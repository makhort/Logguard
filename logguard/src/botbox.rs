//! Admin messages handed to the XMPP admin bot (logguard-xmpp-bot), which sends them OMEMO-encrypted,
//! with ejabberd's plain `send_message` as the fallback.
//!
//! The bot's outbox is a directory both sides share (root:ejabberd 1770, sticky). One file
//! per message, `alert-<time>-<n>.msg`: `To:` and `Subject:` lines, a blank line, the body.
//! It is written under a dot name, given to the bot's user and renamed into place. Then:
//!
//! - the bot claims it by renaming it to `.<name>.sending`, sends it and deletes it; if
//!   sending fails it renames it back. A message for anyone but its admin it renames to
//!   `.<name>.rejected`.
//! - logguard looks every few seconds ([`BotBox::sweep`]). A message the bot hasn't taken
//!   within `grace`, one it rejected, and one stuck in `.sending` (the bot died while sending)
//!   is claimed back by a rename to `.<name>.fallback` and sent the old way, with a line
//!   saying why it isn't encrypted. Renames are atomic, so only one side sends a message
//!   (unless the bot hangs mid-send for over ten minutes and then finishes).
//!
//! The same sweep notices the bot's other files (the weekly abuse report) waiting longer than
//! `stuck_after`, and says so once per file.
//!
//! The Telegram bot (logguard-tg-bot) reads the same format from its own outbox ([`BotBox::without_fallback`]):
//! there logguard takes nothing back, as each message there is a copy of one that goes the
//! XMPP way too. A message logguard-tg-bot hasn't sent within `stuck_after` is named like a file.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::notify::Notice;

/// How long a `.sending` message may sit beyond `grace` before logguard takes it back: the
/// bot's sends (OMEMO key fetches, a reconnect) finish well within this.
const STALLED: Duration = Duration::from_secs(10 * 60);
/// A message whose plain fallback keeps failing is dropped after this long.
const GIVE_UP: Duration = Duration::from_secs(24 * 3600);
/// A dot file still being written after this long is a leftover of a crash.
const TMP_LEFTOVER: Duration = Duration::from_secs(60);

pub const PREFIX: &str = "alert-";
pub const SUFFIX: &str = ".msg";

/// Why a message went out unencrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// Not taken within `grace` (the bot is down, offline or behind).
    NotTaken(Duration),
    /// The bot refused it (a recipient other than its admin).
    Refused,
    /// The bot started sending it and never finished.
    Stalled,
    /// An earlier fallback attempt failed or was interrupted; trying again.
    Retry,
}

impl Why {
    pub fn note(self) -> String {
        match self {
            Why::NotTaken(g) => format!("(Sent unencrypted: the admin bot didn't pick this up within {} min.)", g.as_secs().div_ceil(60)),
            Why::Refused => "(Sent unencrypted: the admin bot only writes to its own admin.)".into(),
            Why::Stalled => "(Sent unencrypted: the admin bot started sending this and didn't finish.)".into(),
            Why::Retry => "(Sent unencrypted: the admin bot didn't send this.)".into(),
        }
    }
}

/// A message logguard took back, to send the old way.
#[derive(Debug, PartialEq)]
pub struct Fallback {
    /// The claimed file (`.<name>.fallback`); delete it once sent.
    pub path: PathBuf,
    pub notice: Notice,
    pub why: Why,
}

/// What a sweep found.
#[derive(Debug, Default, PartialEq)]
pub struct Sweep {
    pub fallback: Vec<Fallback>,
    /// The bot's other files waiting longer than `stuck_after` (name, age), each named once.
    pub stuck: Vec<(String, Duration)>,
}

/// The file's text. Header values are kept on one line.
pub fn render(n: &Notice) -> String {
    let one_line = |s: &str| s.replace(['\r', '\n'], " ");
    format!("To: {}\nSubject: {}\n\n{}", one_line(&n.to), one_line(&n.subject), n.body)
}

/// The message in a file's text, if it is one.
pub fn parse(text: &str) -> Option<Notice> {
    let (head, body) = text.split_once("\n\n")?;
    let (mut to, mut subject) = (None, None);
    for line in head.lines() {
        match line.split_once(": ") {
            Some(("To", v)) => to = Some(v.trim().to_string()),
            Some(("Subject", v)) => subject = Some(v.to_string()),
            _ => return None,
        }
    }
    Some(Notice { to: to.filter(|t| !t.is_empty())?, subject: subject.unwrap_or_default(), body: body.to_string() })
}

/// The message name inside one of the dot names (`.alert-x.msg.sending` → `alert-x.msg`) and
/// the state suffix, or the name itself with an empty state.
fn split_state(name: &str) -> Option<(&str, &str)> {
    if let Some(rest) = name.strip_prefix('.') {
        let (base, state) = rest.rsplit_once('.')?;
        return (base.starts_with(PREFIX) && base.ends_with(SUFFIX)).then_some((base, state));
    }
    (name.starts_with(PREFIX) && name.ends_with(SUFFIX)).then_some((name, ""))
}

/// The uid and gid of a user, from /etc/passwd (`name:x:uid:gid:...`).
pub fn user_ids(passwd: &str, user: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && f[0] == user).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?))).flatten()
    })
}

pub struct BotBox {
    pub dir: PathBuf,
    /// Who the files are given to (the bot's user), if they are given away at all.
    owner: Option<(u32, u32)>,
    grace: Duration,
    stuck_after: Duration,
    /// Messages not taken in time are taken back and sent the usual way (logguard-xmpp-bot), or only
    /// named as stuck (logguard-tg-bot).
    fallback: bool,
    seq: u64,
    /// Stuck files already reported, and fallbacks whose failure was already logged.
    reported: HashSet<String>,
    pub failing: HashSet<PathBuf>,
}

impl BotBox {
    pub fn new(dir: PathBuf, owner: Option<(u32, u32)>, grace: Duration, stuck_after: Duration) -> Self {
        BotBox { dir, owner, grace, stuck_after, fallback: true, seq: 0, reported: HashSet::new(), failing: HashSet::new() }
    }

    /// An outbox without a fallback (logguard-tg-bot's): messages wait there until the bot sends them,
    /// and sweeps only name those waiting longer than `stuck_after`.
    pub fn without_fallback(dir: PathBuf, owner: Option<(u32, u32)>, stuck_after: Duration) -> Self {
        BotBox { fallback: false, ..Self::new(dir, owner, stuck_after, stuck_after) }
    }

    /// Whether the bot's outbox is there (the bot is installed on this server).
    pub fn ready(&self) -> bool {
        self.dir.is_dir()
    }

    /// Puts a message in the outbox for the bot. Returns the file it went to.
    pub fn put(&mut self, n: &Notice, now: SystemTime) -> io::Result<PathBuf> {
        self.seq += 1;
        let t = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        // sorts in sending order: time, then the counter for messages in the same instant
        let name = format!("{PREFIX}{:012}{:09}-{:06}{SUFFIX}", t.as_secs(), t.subsec_nanos(), self.seq % 1_000_000);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let dest = self.dir.join(&name);
        let write = || -> io::Result<()> {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(render(n).as_bytes())?;
            f.sync_all()?;
            if let Some((uid, gid)) = self.owner {
                std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
            }
            fs::rename(&tmp, &dest)
        };
        write().inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        Ok(dest)
    }

    /// Takes back what the bot hasn't sent in time (see the module comment), and finds its
    /// other files waiting too long.
    pub fn sweep(&mut self, now: SystemTime) -> io::Result<Sweep> {
        let mut out = Sweep::default();
        let mut present = HashSet::new();
        let mut entries: Vec<_> = fs::read_dir(&self.dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let Ok(name) = entry.file_name().into_string() else { continue };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
            if !meta.file_type().is_file() {
                continue;
            }
            let age = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).unwrap_or_default();
            let Some((base, state)) = split_state(&name) else {
                // the bot's other files: the weekly report
                if !name.starts_with('.') {
                    present.insert(name.clone());
                    if age > self.stuck_after && self.reported.insert(name.clone()) {
                        out.stuck.push((name, age));
                    }
                }
                continue;
            };
            if !self.fallback {
                match state {
                    // waiting, or left half-sent by a bot that stopped (it puts those back
                    // when it starts again)
                    "" | "sending" => {
                        present.insert(name.clone());
                        if age > self.stuck_after && self.reported.insert(name.clone()) {
                            out.stuck.push((name, age));
                        }
                    }
                    "tmp" if age > TMP_LEFTOVER => {
                        let _ = fs::remove_file(entry.path());
                    }
                    _ => {}
                }
                continue;
            }
            let why = match state {
                "" if age > self.grace => Why::NotTaken(self.grace),
                "rejected" => Why::Refused,
                "sending" if age > self.grace + STALLED => Why::Stalled,
                "fallback" if age > GIVE_UP => {
                    eprintln!("logguard: admin message {base} could not be sent for a day, dropped");
                    let _ = fs::remove_file(entry.path());
                    self.failing.remove(&entry.path());
                    continue;
                }
                "fallback" => Why::Retry,
                "tmp" if age > TMP_LEFTOVER => {
                    let _ = fs::remove_file(entry.path());
                    continue;
                }
                _ => continue,
            };
            let claimed = self.dir.join(format!(".{base}.fallback"));
            if state != "fallback" {
                match fs::rename(entry.path(), &claimed) {
                    Ok(()) => {}
                    // the bot took it in the meantime
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                }
            }
            match fs::read_to_string(&claimed).ok().as_deref().and_then(parse) {
                Some(notice) => out.fallback.push(Fallback { path: claimed, notice, why }),
                None => {
                    eprintln!("logguard: {} is not an admin message, deleted", claimed.display());
                    let _ = fs::remove_file(&claimed);
                }
            }
        }
        // a file sent (or deleted) and later one of the same name is new again
        self.reported.retain(|n| present.contains(n));
        Ok(out)
    }

    /// The text to send in place of the bot: the message and why it isn't encrypted.
    pub fn plain(f: &Fallback) -> Notice {
        Notice { body: format!("{}\n\n{}", f.notice.body, f.why.note()), ..f.notice.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn notice() -> Notice {
        Notice {
            to: "admin@example.org".into(),
            subject: "[xmpp] logguard: system\nx".into(),
            body: "[xmpp] logguard: system\n\nline 1\n\nline 3 → ✓".into(),
        }
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("logguard-botbox-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        v.sort();
        v
    }

    #[test]
    fn file_format_round_trip() {
        let n = notice();
        let text = render(&n);
        assert!(text.starts_with("To: admin@example.org\nSubject: [xmpp] logguard: system x\n\n"), "{text}");
        let back = parse(&text).unwrap();
        assert_eq!(back.to, n.to);
        assert_eq!(back.subject, "[xmpp] logguard: system x", "the subject stays on its line");
        assert_eq!(back.body, n.body, "blank lines in the body survive");
        assert_eq!(parse("no header"), None);
        assert_eq!(parse("From: x\n\nbody"), None);
        assert_eq!(parse("Subject: s\n\nbody"), None, "a recipient is required");
    }

    #[test]
    fn passwd_lookup() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nejabberd:x:998:997::/opt/ejabberd:/bin/sh\nbroken:x:abc:1::/:/bin/false\n";
        assert_eq!(user_ids(passwd, "ejabberd"), Some((998, 997)));
        assert_eq!(user_ids(passwd, "ejabber"), None);
        assert_eq!(user_ids(passwd, "broken"), None);
    }

    #[test]
    fn the_bot_takes_it_or_logguard_takes_it_back() {
        let d = dir("flow");
        let grace = Duration::from_secs(120);
        let mut b = BotBox::new(d.clone(), None, grace, Duration::from_secs(3600));
        let now = SystemTime::now();
        let p1 = b.put(&notice(), now).unwrap();
        let p2 = b.put(&notice(), now).unwrap();
        assert!(p1 < p2, "names sort in sending order");
        assert_eq!(names(&d).len(), 2, "no temporary file left: {:?}", names(&d));
        let mode = fs::metadata(&p1).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // within the grace time nothing happens
        assert_eq!(b.sweep(now + Duration::from_secs(60)).unwrap(), Sweep::default());

        // the bot claims the first, and is still sending it when the grace time is up
        let base1 = p1.file_name().unwrap().to_str().unwrap().to_string();
        fs::rename(&p1, d.join(format!(".{base1}.sending"))).unwrap();
        let s = b.sweep(now + Duration::from_secs(180)).unwrap();
        assert_eq!(s.fallback.len(), 1, "only the untaken one");
        assert_eq!(s.fallback[0].why, Why::NotTaken(grace));
        assert_eq!(s.fallback[0].notice.body, notice().body);
        let plain = BotBox::plain(&s.fallback[0]);
        assert!(plain.body.ends_with("(Sent unencrypted: the admin bot didn't pick this up within 2 min.)"), "{}", plain.body);
        assert!(s.fallback[0].path.file_name().unwrap().to_str().unwrap().ends_with(".msg.fallback"));
        assert!(!p2.exists(), "claimed by rename");

        // a fallback not deleted (sending failed) is tried again
        let s = b.sweep(now + Duration::from_secs(200)).unwrap();
        assert_eq!(s.fallback.iter().map(|f| f.why).collect::<Vec<_>>(), [Why::Retry]);
        fs::remove_file(&s.fallback[0].path).unwrap();

        // a bot that died while sending: taken back 10 minutes after the grace time
        assert!(b.sweep(now + Duration::from_secs(600)).unwrap().fallback.is_empty());
        let s = b.sweep(now + Duration::from_secs(780)).unwrap();
        assert_eq!(s.fallback.iter().map(|f| f.why).collect::<Vec<_>>(), [Why::Stalled]);
        fs::remove_file(&s.fallback[0].path).unwrap();
        assert!(names(&d).is_empty(), "{:?}", names(&d));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn refused_messages_go_out_at_once_and_junk_is_cleared() {
        let d = dir("refused");
        let mut b = BotBox::new(d.clone(), None, Duration::from_secs(120), Duration::from_secs(3600));
        let now = SystemTime::now();
        let p = b.put(&notice(), now).unwrap();
        let base = p.file_name().unwrap().to_str().unwrap().to_string();
        fs::rename(&p, d.join(format!(".{base}.rejected"))).unwrap();
        let s = b.sweep(now).unwrap();
        assert_eq!(s.fallback.iter().map(|f| f.why).collect::<Vec<_>>(), [Why::Refused]);
        fs::remove_file(&s.fallback[0].path).unwrap();

        // a crash leftover, a message without a header, the bot's own dot files
        fs::write(d.join(".alert-1.msg.tmp"), "half").unwrap();
        fs::write(d.join("alert-2.msg"), "garbage").unwrap();
        fs::write(d.join(".abuse-report-2026-10-19.txt.tmp"), "being written").unwrap();
        let s = b.sweep(now + Duration::from_secs(3 * 60)).unwrap();
        assert!(s.fallback.is_empty());
        assert_eq!(names(&d), [".abuse-report-2026-10-19.txt.tmp"], "only what isn't logguard's is left");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn without_fallback_messages_wait_for_the_bot() {
        let d = dir("nofallback");
        let mut b = BotBox::without_fallback(d.clone(), None, Duration::from_secs(3600));
        let now = SystemTime::now();
        let p = b.put(&notice(), now).unwrap();
        let p2 = b.put(&notice(), now).unwrap();
        let base2 = p2.file_name().unwrap().to_str().unwrap().to_string();
        fs::rename(&p2, d.join(format!(".{base2}.sending"))).unwrap();
        fs::write(d.join(".alert-9.msg.tmp"), "half").unwrap();
        assert_eq!(b.sweep(now + Duration::from_secs(600)).unwrap(), Sweep::default(), "nothing taken back after a grace time");
        let s = b.sweep(now + Duration::from_secs(4000)).unwrap();
        assert!(s.fallback.is_empty());
        let sending = format!(".{base2}.sending");
        assert_eq!(
            s.stuck.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            [sending.as_str(), p.file_name().unwrap().to_str().unwrap()],
            "waiting, and left half-sent by a bot that died: each named once"
        );
        assert!(b.sweep(now + Duration::from_secs(5000)).unwrap().stuck.is_empty());
        assert!(p.exists() && d.join(format!(".{base2}.sending")).exists(), "the bot's to send");
        assert!(!d.join(".alert-9.msg.tmp").exists(), "crash leftovers are cleared");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_waiting_report_is_named_once() {
        let d = dir("stuck");
        let mut b = BotBox::new(d.clone(), None, Duration::from_secs(120), Duration::from_secs(3600));
        fs::write(d.join("abuse-report-2026-10-19.txt"), "report").unwrap();
        let now = SystemTime::now();
        assert!(b.sweep(now + Duration::from_secs(1800)).unwrap().stuck.is_empty());
        let s = b.sweep(now + Duration::from_secs(4000)).unwrap();
        assert_eq!(s.stuck.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["abuse-report-2026-10-19.txt"]);
        assert!(s.fallback.is_empty(), "the report itself is the bot's to send");
        assert!(b.sweep(now + Duration::from_secs(5000)).unwrap().stuck.is_empty(), "named once");
        // sent, and next week's waits too long again: named again
        fs::remove_file(d.join("abuse-report-2026-10-19.txt")).unwrap();
        b.sweep(now + Duration::from_secs(5000)).unwrap();
        fs::write(d.join("abuse-report-2026-10-19.txt"), "report").unwrap();
        assert_eq!(b.sweep(now + Duration::from_secs(9000)).unwrap().stuck.len(), 1);
        assert!(d.join("abuse-report-2026-10-19.txt").exists(), "logguard never touches the report");
        let _ = fs::remove_dir_all(&d);
    }
}
