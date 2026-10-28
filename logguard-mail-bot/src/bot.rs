//! The bot: logguard's outbox to the admins' mailboxes, each mail encrypted to their
//! OpenPGP keys. Send-only: it reads no mail and takes no orders (those stay on SSH).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::mime::{self, Content, Mail, Sender};
use crate::outbox;
use crate::redact::Pseudonyms;
use crate::seal::{self, Recipients, Signer};
use crate::servers::ServerNames;
use crate::smtp::{Outgoing, SendError};

/// A setting, a key or a login that restarting will not fix; the process exits with 78,
/// which the unit does not restart.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl Refused {
    pub const EXIT_CODE: u8 = 78;
}

pub struct Config {
    pub outbox: PathBuf,
    /// Files waiting longer are deleted unsent.
    pub outbox_max_age: Duration,
    /// Alerts waiting longer are dropped unsent (counted in one mail instead).
    pub alert_max_age: Duration,
    pub from: Sender,
    /// The outer `Subject:` (the real one is encrypted).
    pub outer_subject: String,
    pub recipients: Recipients,
    pub signer: Option<Signer>,
    /// `SANITIZE=on`: alerts and digests with XMPP account names and the servers' own
    /// addresses replaced, as on Telegram. Off by default: the mails are encrypted end to end.
    pub sanitize: Option<Sanitize>,
}

/// What `SANITIZE=on` replaces in alerts and digests (not in files: the weekly report goes
/// out as it is, as on Telegram).
pub struct Sanitize {
    pub names: Pseudonyms,
    pub servers: ServerNames,
}

impl Sanitize {
    pub fn text(&self, text: &str) -> String {
        crate::redact::sanitize(&self.names, &self.servers, text)
    }
}

/// Where the admin finds what the mail server refused.
const ELSEWHERE_ALERT: &str = "Alerts and the digest are also in logguard's actions log on the server (logguard tui --actions).";
const ELSEWHERE_FILE: &str =
    "The abuse report can be made again on the server: logguard abuse-report --since 7d (its README, \"Weekly, to the admin's phone\").";

/// The longest pause after failures; a server refusing everything is tried this often.
const MAX_PAUSE: Duration = Duration::from_secs(30 * 60);

pub struct Bot<O: Outgoing> {
    pub cfg: Config,
    pub out: O,
    /// The Autocrypt header with the bot's key, if it signs.
    autocrypt: Option<String>,
    /// Nothing is sent before this (after a failure).
    not_before: Option<Instant>,
    /// The pause after the next failure: doubles up to [`MAX_PAUSE`], back to 30 s on success.
    pause: Duration,
    /// Warnings logged in the last 10 minutes and when: each is repeated at most that often.
    warned: HashMap<String, Instant>,
    pub sent: u64,
}

fn unix_now() -> u32 {
    chrono::Utc::now().timestamp() as u32
}

/// The inner subject of a file's mail.
pub fn file_subject(name: &str) -> String {
    match name.strip_prefix("abuse-report-").and_then(|r| r.strip_suffix(".txt")) {
        Some(date) => format!("logguard: weekly abuse report {date}"),
        None => format!("logguard: {}", mime::safe_file_name(name)),
    }
}

/// What a file in the outbox becomes: UTF-8 text is the mail's text, anything else attached.
pub fn file_content(name: &str, data: Vec<u8>) -> Content {
    match String::from_utf8(data) {
        Ok(text) => Content::Text(text),
        Err(e) => Content::File { name: name.to_string(), data: e.into_bytes() },
    }
}

impl<O: Outgoing> Bot<O> {
    pub fn new(cfg: Config, out: O) -> Bot<O> {
        let autocrypt = cfg.signer.as_ref().map(|s| mime::autocrypt(&cfg.from.address, &s.public));
        Bot { cfg, out, autocrypt, not_before: None, pause: Duration::from_secs(30), warned: HashMap::new(), sent: 0 }
    }

    fn warn_repeated(&mut self, msg: String) {
        const EVERY: Duration = Duration::from_secs(600);
        self.warned.retain(|_, t| t.elapsed() < EVERY);
        self.warned.entry(msg).or_insert_with_key(|msg| {
            log::warn!("{msg}");
            Instant::now()
        });
    }

    fn throttled(&self) -> bool {
        self.not_before.is_some_and(|t| Instant::now() < t)
    }

    fn hold_off(&mut self, pause: Duration) {
        self.not_before = Some(Instant::now() + pause);
    }

    /// The recipients whose keys are usable now; the others are named in the log. `None`
    /// when nobody's is: the mail waits.
    fn recipients(&mut self) -> Option<Vec<String>> {
        let (ok, not) = self.cfg.recipients.split(unix_now());
        if !not.is_empty() {
            let list: Vec<String> = not.iter().map(|(addr, why)| format!("{addr} ({why})")).collect();
            self.warn_repeated(format!("no mail until their OpenPGP keys are replaced: {}", list.join("; ")));
        }
        (!ok.is_empty()).then_some(ok)
    }

    /// A whole mail: the content with its protected headers, encrypted (and signed), in
    /// its PGP/MIME envelope.
    pub fn compose(&self, subject: &str, content: Content, to: &[String]) -> Result<Vec<u8>, String> {
        let id = mime::message_id(&self.cfg.from.address);
        let mail = Mail { from: &self.cfg.from, to, subject, content, date: chrono::Utc::now(), message_id: &id };
        let armored = seal::seal(mime::inner(&mail), &self.cfg.recipients, to, self.cfg.signer.as_ref(), unix_now())?;
        Ok(mime::outer(&mail, &self.cfg.outer_subject, &armored, self.autocrypt.as_deref()))
    }

    /// Composes and sends; remembers how long to hold off after a failure.
    fn send(&mut self, subject: &str, content: Content, to: &[String]) -> Result<(), SendError> {
        let mail = self.compose(subject, content, to).map_err(SendError::transient)?;
        match self.out.send(&self.cfg.from.address, to, &mail) {
            Ok(()) => {
                self.pause = Duration::from_secs(30);
                self.not_before = None;
                self.sent += 1;
                Ok(())
            }
            Err(e) => {
                self.hold_off(if e.permanent { MAX_PAUSE } else { self.pause });
                self.pause = (self.pause * 2).min(MAX_PAUSE);
                Err(e)
            }
        }
    }

    /// After the server refused `what` for good: whether it refuses that one only. A short
    /// note goes out in its place; if that is refused too, the server refuses everything
    /// (the sender, a recipient) and `what` waits for it to be fixed. A refused login is never
    /// tried again at once (each failure counts towards the server's ban): it waits.
    /// `elsewhere`: where the admin finds it instead.
    fn refused_alone(&mut self, what: &str, e: &SendError, to: &[String], elsewhere: &str) -> bool {
        if !e.permanent {
            return false;
        }
        if e.global {
            self.warn_repeated(format!(
                "the mail server refuses the bot ({e}): check SMTP_USER, the password and SMTP_AUTH; trying again in {} min",
                MAX_PAUSE.as_secs() / 60
            ));
            return false;
        }
        self.not_before = None;
        let note = format!("The mail server refused {what} ({e}), so it was not sent. {elsewhere}");
        match self.send("logguard-mail-bot: a message was refused", Content::Text(note), to) {
            Ok(()) => true,
            Err(e2) if e2.permanent => {
                self.warn_repeated(format!(
                    "the mail server refuses every mail ({e2}): check SMTP_USER, the password, MAIL_FROM and MAIL_TO; trying again in {} min",
                    MAX_PAUSE.as_secs() / 60
                ));
                false
            }
            // out of reach just now: decide on the next try
            Err(_) => false,
        }
    }

    /// logguard's alerts in the outbox, one mail each.
    pub fn deliver_alerts(&mut self, stop: &AtomicBool) {
        if self.throttled() {
            return;
        }
        let dir = self.cfg.outbox.clone();
        let waiting = match outbox::scan_messages(&dir, SystemTime::now()) {
            Ok(w) => w,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return self.warn_repeated(format!("outbox {}: {e}", dir.display())),
        };
        let mut dropped = 0;
        for (path, age) in waiting {
            if stop.load(Ordering::Relaxed) || self.throttled() {
                break;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            if age > self.cfg.alert_max_age {
                if std::fs::remove_file(&path).is_ok() {
                    dropped += 1;
                }
                continue;
            }
            let Some(to) = self.recipients() else { break };
            let sending = outbox::claimed(&path, "sending");
            match std::fs::rename(&path, &sending) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.warn_repeated(format!("outbox: can't take {name}: {e}"));
                    continue;
                }
            }
            let Some((subject, text)) = outbox::read_message(&sending) else {
                log::warn!("outbox: {name} is not an admin message (or larger than 1 MB); deleted");
                let _ = std::fs::remove_file(&sending);
                continue;
            };
            let (subject, text) = match &self.cfg.sanitize {
                Some(s) => (s.text(&subject), s.text(&text)),
                None => (subject, text),
            };
            match self.send(&subject, Content::Text(text), &to) {
                Ok(()) => {
                    log::info!("outbox: alert {name} sent to {}", to.join(", "));
                    if let Err(e) = std::fs::remove_file(&sending) {
                        log::error!("outbox: deleting {} after sending: {e}", sending.display());
                    }
                }
                Err(e) if self.refused_alone("an alert", &e, &to, ELSEWHERE_ALERT) => {
                    log::error!("outbox: alert {name} dropped: the mail server refuses it ({e})");
                    let _ = std::fs::remove_file(&sending);
                }
                Err(e) => {
                    let _ = std::fs::rename(&sending, &path);
                    self.warn_repeated(format!("outbox: alert {name} not sent ({e}); trying again"));
                    break;
                }
            }
        }
        if dropped > 0 {
            let hours = self.cfg.alert_max_age.as_secs() / 3600;
            log::warn!("outbox: {dropped} alert(s) older than {hours} h dropped unsent");
            if let Some(to) = self.recipients() {
                let note = format!(
                    "{dropped} alert(s) waited more than {hours} h and were dropped unsent (the bot was down, or the mail server out of \
                     reach). They are in logguard's actions log on the server."
                );
                let _ = self.send("logguard-mail-bot: alerts dropped", Content::Text(note), &to);
            }
        }
    }

    /// Files in the outbox (the weekly abuse report): a text file as the mail's text, any
    /// other attached. Deletes those that waited too long.
    pub fn deliver_files(&mut self, stop: &AtomicBool) {
        let dir = self.cfg.outbox.clone();
        let pending = match outbox::scan(&dir, self.cfg.outbox_max_age, SystemTime::now()) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return self.warn_repeated(format!("outbox {}: {e}", dir.display())),
        };
        for path in pending.expired {
            let size = std::fs::symlink_metadata(&path).map_or(0, |m| m.len());
            match std::fs::remove_file(&path) {
                Ok(()) => log::warn!(
                    "outbox: {} not sent within {} days (or larger than {} MB), deleted",
                    path.display(),
                    self.cfg.outbox_max_age.as_secs() / 86400,
                    outbox::MAX_FILE >> 20
                ),
                Err(e) => {
                    log::error!("outbox: deleting {}: {e}", path.display());
                    continue;
                }
            }
            // too large to mail: say so (one that waited too long would likely not go out now either)
            if size > outbox::MAX_FILE {
                if let Some(to) = self.recipients() {
                    let name = mime::safe_file_name(&path.file_name().unwrap_or_default().to_string_lossy());
                    let note = format!(
                        "The file {name} ({} MB) was too large to mail (at most {} MB) and was deleted unsent. {ELSEWHERE_FILE}",
                        size >> 20,
                        outbox::MAX_FILE >> 20
                    );
                    let _ = self.send("logguard-mail-bot: a file was too large", Content::Text(note), &to);
                }
            }
        }
        for path in pending.ready {
            if stop.load(Ordering::Relaxed) || self.throttled() {
                return;
            }
            let Some(to) = self.recipients() else { return };
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    self.warn_repeated(format!("outbox: reading {name}: {e}"));
                    continue;
                }
            };
            match self.send(&file_subject(&name), file_content(&name, data), &to) {
                Ok(()) => {
                    log::info!("outbox: {name} sent to {}", to.join(", "));
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("outbox: deleting {} after sending: {e}", path.display());
                    }
                }
                Err(e) if self.refused_alone(&format!("the file {}", mime::safe_file_name(&name)), &e, &to, ELSEWHERE_FILE) => {
                    log::error!("outbox: {name} dropped: the mail server refuses it ({e})");
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => {
                    self.warn_repeated(format!("outbox: {name} not sent ({e}); trying again later"));
                    return;
                }
            }
        }
    }
}

/// Serves the outbox until `stop` is set (SIGTERM, SIGINT).
pub fn run<O: Outgoing>(mut bot: Bot<O>, stop: &AtomicBool) {
    let recovered = outbox::recover(&bot.cfg.outbox);
    if recovered > 0 {
        log::info!("outbox: {recovered} alert(s) left half-sent at the last stop, sending again");
    }
    if !bot.cfg.outbox.is_dir() {
        log::warn!("no outbox {} yet: nothing to deliver until it exists", bot.cfg.outbox.display());
    } else if let Err(e) = outbox::writable(&bot.cfg.outbox) {
        // e.g. an OUTBOX_DIR outside the unit's ReadWritePaths: messages could be read but never taken
        log::error!(
            "the outbox {} is not writable for the bot ({e}): it can't take or delete what logguard puts there",
            bot.cfg.outbox.display()
        );
    }
    // alerts every 5 s, files every minute; the first round now
    let mut last_files: Option<Instant> = None;
    while !stop.load(Ordering::Relaxed) {
        bot.deliver_alerts(stop);
        if last_files.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            bot.deliver_files(stop);
            last_files = Some(Instant::now());
        }
        for _ in 0..10 {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    log::info!("Shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::tests::{keypair, open};

    /// Records mails; refuses as scripted (front first), then accepts.
    #[derive(Default)]
    struct Fake {
        sent: Vec<(Vec<String>, String)>,
        script: Vec<SendError>,
    }

    impl Outgoing for Fake {
        fn send(&mut self, _from: &str, to: &[String], mail: &[u8]) -> Result<(), SendError> {
            if !self.script.is_empty() {
                return Err(self.script.remove(0));
            }
            self.sent.push((to.to_vec(), String::from_utf8(mail.to_vec()).unwrap()));
            Ok(())
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("logguard-mail-bot-bot-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bot(dir: &std::path::Path) -> (Bot<Fake>, pgp::composed::SignedSecretKey) {
        let (secret, public) = keypair("admin@example.org");
        let to = vec!["admin@example.org".to_string()];
        let recipients = Recipients::parse(&public, &to, unix_now(), &mut |w| panic!("{w}")).unwrap();
        let cfg = Config {
            outbox: dir.to_path_buf(),
            outbox_max_age: Duration::from_secs(7 * 86400),
            alert_max_age: Duration::from_secs(24 * 3600),
            from: Sender { name: "logguard".into(), address: "alerts@example.org".into() },
            outer_subject: "...".into(),
            recipients,
            signer: None,
            sanitize: None,
        };
        (Bot::new(cfg, Fake::default()), secret)
    }

    /// The decrypted inner entity of a sent mail.
    fn inner(secret: &pgp::composed::SignedSecretKey, mail: &str) -> String {
        let start = mail.find("-----BEGIN PGP MESSAGE-----").unwrap();
        let end = mail.find("-----END PGP MESSAGE-----").unwrap() + 25;
        String::from_utf8(open(secret, &mail[start..end].replace("\r\n", "\n"))).unwrap()
    }

    fn decoded_body(inner: &str) -> String {
        let body = inner.split_once("\r\n\r\n").unwrap().1;
        String::from_utf8(quoted_printable::decode(body.trim_end(), quoted_printable::ParseMode::Robust).unwrap()).unwrap()
    }

    const ALERT: &str = "To: admin@example.org\nSubject: [xmpp] logguard: system\n\n[xmpp] logguard: system\n\n[High] line → ✓";

    #[test]
    fn alerts_go_out_encrypted_and_leave_the_outbox() {
        let dir = tmp("alerts");
        std::fs::write(dir.join("alert-1.msg"), ALERT).unwrap();
        std::fs::write(dir.join("alert-2.msg"), "garbage").unwrap();
        let (mut b, secret) = bot(&dir);
        b.deliver_alerts(&AtomicBool::new(false));
        assert_eq!(b.out.sent.len(), 1);
        let (to, mail) = &b.out.sent[0];
        assert_eq!(to, &["admin@example.org"]);
        assert!(!mail.contains("logguard: system") && !mail.contains("High"), "nothing in clear");
        let inner = inner(&secret, mail);
        assert!(inner.contains("\r\nSubject: [xmpp] logguard: system\r\n"), "{inner}");
        assert_eq!(decoded_body(&inner), "[xmpp] logguard: system\r\n\r\n[High] line → ✓");
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "sent, and the junk deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitizing_is_optional() {
        let alert = "To: admin\nSubject: [xmpp] logguard: account under attack\n\n\
                     account alice@example.org under attack from 11.23.45.233; peer 11.29.39.236:7946 failing";
        let dir = tmp("sanitize");
        // off (the default): the mail carries the names, encrypted
        std::fs::write(dir.join("alert-1.msg"), alert).unwrap();
        let (mut b, secret) = bot(&dir);
        b.deliver_alerts(&AtomicBool::new(false));
        let plain = decoded_body(&inner(&secret, &b.out.sent[0].1));
        assert!(plain.contains("alice@example.org") && plain.contains("11.29.39.236"), "{plain}");
        // on: as on Telegram; attackers' addresses stay
        std::fs::write(dir.join("alert-2.msg"), alert).unwrap();
        b.cfg.sanitize = Some(Sanitize {
            names: Pseudonyms::new([7; 32], vec!["example.org".into()]),
            servers: ServerNames::parse("xmpp=11.29.39.236,example.org").unwrap(),
        });
        b.deliver_alerts(&AtomicBool::new(false));
        let inner = inner(&secret, &b.out.sent[1].1);
        let text = decoded_body(&inner);
        assert!(!text.contains("alice") && !text.contains("11.29.39.236"), "{text}");
        assert!(text.contains("[acct:") && text.contains("peer xmpp:7946") && text.contains("11.23.45.233"), "{text}");
        assert!(inner.contains("\r\nSubject: [xmpp] logguard: account under attack\r\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_server_out_of_reach_keeps_alerts_waiting() {
        let dir = tmp("transient");
        std::fs::write(dir.join("alert-1.msg"), ALERT).unwrap();
        let (mut b, _) = bot(&dir);
        b.out.script.push(SendError::transient("connection refused"));
        b.deliver_alerts(&AtomicBool::new(false));
        assert!(dir.join("alert-1.msg").exists(), "put back");
        assert!(b.throttled());
        b.deliver_alerts(&AtomicBool::new(false));
        assert!(b.out.sent.is_empty(), "held off");
        b.not_before = None;
        b.deliver_alerts(&AtomicBool::new(false));
        assert_eq!(b.out.sent.len(), 1);
        assert_eq!(b.pause, Duration::from_secs(30), "back to the short pause");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refused_alert_is_dropped_only_if_others_go_through() {
        let dir = tmp("refused");
        std::fs::write(dir.join("alert-1.msg"), ALERT).unwrap();
        std::fs::write(dir.join("alert-2.msg"), ALERT).unwrap();
        let (mut b, secret) = bot(&dir);
        // this one alone: the note goes through, the alert is dropped, the next one sent
        b.out.script.push(SendError::refused("554 5.7.1 rejected as spam"));
        b.deliver_alerts(&AtomicBool::new(false));
        assert_eq!(b.out.sent.len(), 2);
        assert!(decoded_body(&inner(&secret, &b.out.sent[0].1)).contains("554 5.7.1 rejected as spam"));
        assert!(!dir.join("alert-1.msg").exists() && !dir.join("alert-2.msg").exists());

        // everything refused (a wrong password): the alert waits
        std::fs::write(dir.join("alert-3.msg"), ALERT).unwrap();
        let refused = SendError::refused("550 5.1.0 sender rejected");
        b.out.script = vec![refused.clone(), refused];
        b.deliver_alerts(&AtomicBool::new(false));
        assert!(dir.join("alert-3.msg").exists());
        assert!(b.throttled(), "and the bot holds off");
        assert!(b.out.script.is_empty(), "the alert and the note were both tried");

        // a refused login: no note (another failed login), the alert waits
        b.not_before = None;
        let login = SendError { permanent: true, global: true, text: "permanent error (535): 5.7.8 authentication failed".into() };
        b.out.script = vec![login.clone(), login];
        b.deliver_alerts(&AtomicBool::new(false));
        assert_eq!(b.out.script.len(), 1, "one try only");
        assert!(dir.join("alert-3.msg").exists() && b.throttled());

        // the note itself out of reach: the alert waits too
        b.not_before = None;
        b.out.script = vec![SendError::refused("552 too big"), SendError::transient("connection reset")];
        b.deliver_alerts(&AtomicBool::new(false));
        assert!(dir.join("alert-3.msg").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_alerts_are_dropped_with_a_note() {
        let dir = tmp("old");
        std::fs::write(dir.join("alert-1.msg"), ALERT).unwrap();
        let (mut b, secret) = bot(&dir);
        b.cfg.alert_max_age = Duration::ZERO;
        std::thread::sleep(Duration::from_millis(20));
        b.deliver_alerts(&AtomicBool::new(false));
        assert_eq!(b.out.sent.len(), 1);
        assert!(decoded_body(&inner(&secret, &b.out.sent[0].1)).starts_with("1 alert(s) waited more than 0 h"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_are_the_mails_text() {
        let dir = tmp("files");
        let report = "Abuse report\n\nHello, abuse@example.net,\n".repeat(100);
        std::fs::write(dir.join("abuse-report-2026-10-19.txt"), &report).unwrap();
        std::fs::write(dir.join("dump.bin"), [0xffu8, 0, 1]).unwrap();
        std::fs::write(dir.join(".abuse-report-2026-10-26.txt.tmp"), "being written").unwrap();
        let (mut b, secret) = bot(&dir);
        b.deliver_files(&AtomicBool::new(false));
        assert_eq!(b.out.sent.len(), 2);
        let first = inner(&secret, &b.out.sent[0].1);
        assert!(first.contains("\r\nSubject: logguard: weekly abuse report 2026-10-19\r\n"), "{first}");
        assert_eq!(decoded_body(&first), report.replace('\n', "\r\n").trim_end());
        let second = inner(&secret, &b.out.sent[1].1);
        assert!(second.starts_with("Content-Type: multipart/mixed") && second.contains("filename=\"dump.bin\""));
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, [".abuse-report-2026-10-26.txt.tmp"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_too_large_is_deleted_with_a_note() {
        let dir = tmp("large");
        let f = std::fs::File::create(dir.join("abuse-report-2026-10-19.txt")).unwrap();
        f.set_len(outbox::MAX_FILE + 1).unwrap();
        let (mut b, secret) = bot(&dir);
        b.deliver_files(&AtomicBool::new(false));
        assert_eq!(b.out.sent.len(), 1);
        let note = decoded_body(&inner(&secret, &b.out.sent[0].1));
        assert!(note.contains("abuse-report-2026-10-19.txt") && note.contains("too large"), "{note}");
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subjects_of_files() {
        assert_eq!(file_subject("abuse-report-2026-10-19.txt"), "logguard: weekly abuse report 2026-10-19");
        assert_eq!(file_subject("x y.csv"), "logguard: x_y.csv");
    }
}
