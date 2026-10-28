//! Client mode (`BOT_MODE=client`): a copy bot like logguard-tg-bot or logguard-matrix-bot,
//! for logguard's `[notify] xmpp_outbox`, on any host (a VPN server, a relay node, a desktop)
//! with an account on any XMPP server. It sends logguard's alerts, digests and files to one
//! admin (`ADMIN_JID`, on any server), OMEMO-encrypted. When OMEMO can't reach the admin
//! (`OMEMO=off`, the admin's client publishes no OMEMO device, none of them is trusted, no
//! session can be started), a message or file goes out as a file encrypted to the admin's
//! OpenPGP key (`OPENPGP_KEY`, see [`crate::seal`]), uploaded with HTTP File Upload and sent
//! as a link (XEP-0066), which Conversations shows as a download. Without that key it waits.
//!
//! logguard has no fallback for this outbox: an alert waits until it is sent or older than
//! `ALERT_MAX_HOURS`, a file until it is sent or older than `OUTBOX_MAX_DAYS`. The server sees
//! in clear only the links to the OpenPGP files and short notices saying why messages come as
//! files or wait (each kind at most once a day). The bot answers only its admin, and only
//! `/status`, `/omemo` and `/help`: no ejabberdctl, no state.json, no users.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use tokio_xmpp::jid::Jid;
use tokio_xmpp::minidom::Element;
use tokio_xmpp::parsers::message::{Lang, Message, MessageType};

use super::{chat, no_archive, Role, Session};
use crate::commands::{Reply, Response};
use crate::outbox;
use crate::seal::Recipient;
use crate::{Args, ConfigError, OmemoMode};

const OOB: &str = "jabber:x:oob";
/// Each kind of notice in clear (why messages come as files, or wait) at most this often.
const NOTICE_EVERY: Duration = Duration::from_secs(86400);
/// The same failure is logged again after this.
const WARN_EVERY: Duration = Duration::from_secs(600);

const CLIENT_HELP: &str = "\
This bot sends you logguard's alerts, daily digest and weekly abuse report, OMEMO-encrypted \
(as files encrypted to your OpenPGP key when OMEMO can't reach you). It takes no other commands.
`/status`  what was sent, what waits, the fallback key
`/omemo`   the bot's and your devices' OMEMO fingerprints
`/help`    this text";

/// The name a fallback file goes out under: neutral, with the original's extension (the apps
/// name the decrypted file after it, without `.pgp`).
pub fn sealed_name(kind: &str, original_ext: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> String {
    let ext = original_ext.filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric())).unwrap_or("bin");
    format!("{kind}-{}.{ext}.pgp", now.format("%Y-%m-%d-%H%M%S"))
}

/// A link to an uploaded file as clients show it as an attachment: the body is exactly the
/// URL, repeated in a XEP-0066 element.
fn file_message(to: Jid, url: &str) -> Message {
    let oob = Element::builder("x", OOB).append(Element::builder("url", OOB).append(url)).build();
    Message::new_with_type(MessageType::Chat, Some(to)).with_body(Lang::default(), url.to_owned()).with_payloads(vec![oob, no_archive()])
}

/// What became of one message or file.
#[derive(Debug, PartialEq)]
enum Outcome {
    Sent,
    /// No way to send it now: it stays in the outbox.
    Waits,
}

#[derive(Default)]
struct Stats {
    alerts: u64,
    files: u64,
    fallbacks: u64,
}

pub struct ClientCtx {
    /// The admin's OpenPGP key: the fallback when OMEMO can't reach the admin.
    recipient: Option<Recipient>,
    /// Alerts waiting longer are dropped unsent (counted in one notice instead).
    alert_max_age: Duration,
    omemo: OmemoMode,
    /// Notices in clear, by kind, when last sent.
    notices: HashMap<&'static str, Instant>,
    /// The last warning logged and when: repeated failures are logged every 10 minutes.
    last_warning: Option<(String, Instant)>,
    stats: Stats,
    /// Alerts dropped as too old, not yet told in a notice (that needs the server).
    dropped: u64,
    started: Instant,
}

impl ClientCtx {
    /// Client mode's settings, checked: the bot sends nothing in clear, so `OMEMO=off` needs
    /// an OpenPGP key.
    pub fn new(args: &Args) -> anyhow::Result<ClientCtx> {
        if args.alert_max_hours == 0 || args.outbox_max_days == 0 {
            return Err(ConfigError("ALERT_MAX_HOURS and OUTBOX_MAX_DAYS must be at least 1".into()).into());
        }
        let recipient = match &args.openpgp_key {
            Some(path) => {
                let r =
                    Recipient::load(path, chrono::Utc::now().timestamp() as u32).map_err(|e| ConfigError(format!("OPENPGP_KEY {e}")))?;
                log::info!("the fallback files are encrypted to OpenPGP key {}", r.pretty_fingerprint());
                Some(r)
            }
            None if args.omemo == OmemoMode::Off => {
                return Err(ConfigError("OMEMO=off in client mode needs OPENPGP_KEY: the bot sends nothing in clear".into()).into())
            }
            None => {
                log::warn!("OPENPGP_KEY is not set: when OMEMO can't reach the admin, messages wait instead of going out as OpenPGP files");
                None
            }
        };
        Ok(ClientCtx {
            recipient,
            alert_max_age: Duration::from_secs(u64::from(args.alert_max_hours) * 3600),
            omemo: args.omemo,
            notices: HashMap::new(),
            last_warning: None,
            stats: Stats::default(),
            dropped: 0,
            started: Instant::now(),
        })
    }

    /// One line for the log: what was sent since the start.
    pub fn summary(&self) -> String {
        let s = &self.stats;
        format!("sent {} alert(s) and {} file(s), {} of them as OpenPGP files", s.alerts, s.files, s.fallbacks)
    }

    fn warn_repeated(&mut self, msg: String) {
        if self.last_warning.as_ref().is_some_and(|(m, t)| *m == msg && t.elapsed() < WARN_EVERY) {
            return;
        }
        log::warn!("{msg}");
        self.last_warning = Some((msg, Instant::now()));
    }

    /// The fallback key's state, for `/status`.
    fn key_status(&self, now: u32) -> String {
        match &self.recipient {
            None => "not set (OPENPGP_KEY): messages wait while OMEMO can't reach you".into(),
            Some(r) => match r.check(now) {
                Ok(()) => format!("`{}`", r.pretty_fingerprint()),
                Err(e) => format!("`{}`, unusable: {e}", r.pretty_fingerprint()),
            },
        }
    }
}

fn unix_now() -> u32 {
    chrono::Utc::now().timestamp() as u32
}

impl Session {
    fn client_ctx(&mut self) -> Option<&mut ClientCtx> {
        match &mut self.role {
            Role::Client(c) => Some(c),
            Role::Admin(_) => None,
        }
    }

    fn client_warn(&mut self, msg: String) {
        if let Some(c) = self.client_ctx() {
            c.warn_repeated(msg);
        }
    }

    /// A command from the admin (the only one who gets an answer in client mode).
    pub(super) fn client_command(&self, body: &str) -> Response {
        let text = match body.split_whitespace().next() {
            Some("/status") => self.client_status(),
            _ => CLIENT_HELP.to_string(),
        };
        Response { reply: Reply::from(text), notify_admin: None, attachment: None }
    }

    fn client_status(&self) -> String {
        let Role::Client(ctx) = &self.role else { return String::new() };
        let t = crate::i18n::Language::En.texts();
        let (alerts, files) =
            match (outbox::scan_messages(&self.upload.outbox), outbox::scan(&self.upload.outbox, self.upload.max_age, SystemTime::now())) {
                (Ok(a), Ok(f)) => (a.len().to_string(), f.ready.len().to_string()),
                _ => ("?".into(), "?".into()),
            };
        let omemo = match ctx.omemo {
            OmemoMode::Off => "off",
            OmemoMode::On => "on",
            OmemoMode::Required => "required",
        };
        format!(
            "*logguard-xmpp-bot {}*, client mode, up {}\nSent: {}\nWaiting: {alerts} alert(s), {files} file(s)\nOMEMO: {omemo}\nOpenPGP fallback key: {}",
            env!("CARGO_PKG_VERSION"),
            crate::i18n::duration(t, ctx.started.elapsed().as_secs() as i64),
            ctx.summary().trim_start_matches("sent "),
            ctx.key_status(unix_now())
        )
    }

    /// A short notice to the admin in clear (why messages come as files, or wait), at most
    /// once a day per kind.
    async fn notice(&mut self, kind: &'static str, text: String) {
        let Ok(to) = self.admin_jid.parse::<Jid>() else { return };
        let Some(ctx) = self.client_ctx() else { return };
        if ctx.notices.get(kind).is_some_and(|t| t.elapsed() < NOTICE_EVERY) {
            return;
        }
        ctx.notices.insert(kind, Instant::now());
        self.send(chat(to, Reply::from(format!("logguard-xmpp-bot: {text}")))).await;
    }

    /// `data` as a file encrypted to the admin's OpenPGP key, uploaded and sent as a link;
    /// `Waits` when there is no usable key. `why`: why OMEMO isn't possible.
    async fn send_sealed(&mut self, data: Vec<u8>, name: &str, why: &str) -> Result<Outcome, String> {
        let now = unix_now();
        let Some(ctx) = self.client_ctx() else { return Ok(Outcome::Waits) };
        let sealed = match &ctx.recipient {
            None => Err("OPENPGP_KEY is not set".to_string()),
            Some(r) => r.check(now).map_err(|e| format!("the OpenPGP key {e}")).and_then(|()| r.seal(data, now)),
        };
        let sealed = match sealed {
            Ok(s) => s,
            Err(problem) => {
                let (hours, days) = (ctx.alert_max_age.as_secs() / 3600, self.upload.max_age.as_secs() / 86400);
                self.client_warn(format!("outbox: messages wait: {why}, and {problem}"));
                let text = format!("messages can't be sent: {why}, and {problem} on the server. Alerts wait {hours} h, files {days} days.");
                self.notice("waiting", text).await;
                return Ok(Outcome::Waits);
            }
        };
        let url = self.upload(name, &sealed, "application/pgp-encrypted").await?;
        let to: Jid = self.admin_jid.parse().map_err(|e| format!("ADMIN_JID: {e}"))?;
        self.notice(
            "fallback",
            format!(
                "{why}. Messages come as files encrypted to your OpenPGP key until that changes; open them with OpenKeychain (Android) or iPGMail (iPhone)."
            ),
        )
        .await;
        self.send(file_message(to, &url)).await;
        if let Some(c) = self.client_ctx() {
            c.stats.fallbacks += 1;
        }
        Ok(Outcome::Sent)
    }

    /// Why OMEMO can't reach the admin now, if it can't.
    async fn omemo_blocked(&mut self) -> Option<String> {
        if self.omemo.is_none() {
            return Some("OMEMO is off (OMEMO=off)".into());
        }
        let admin = self.admin_jid.clone();
        self.omemo_targets(&admin, None).await.err()
    }

    /// One alert, OMEMO-encrypted if possible, else as an OpenPGP file.
    async fn client_send_alert(&mut self, text: &str) -> Result<Outcome, String> {
        let admin = self.admin_jid.clone();
        let why = match self.omemo_blocked().await {
            Some(why) => why,
            None => {
                let to: Jid = admin.parse().map_err(|e| format!("ADMIN_JID: {e}"))?;
                match self.send_encrypted(to, &admin, None, &Reply::from(text)).await {
                    Ok(()) => return Ok(Outcome::Sent),
                    Err(e) => e,
                }
            }
        };
        let name = sealed_name("message", Some("txt"), chrono::Utc::now());
        self.send_sealed(text.as_bytes().to_vec(), &name, &why).await
    }

    /// One file, as OMEMO media if possible, else as an OpenPGP file.
    async fn client_send_file(&mut self, name: &str, data: Vec<u8>) -> Result<Outcome, String> {
        let Some(why) = self.omemo_blocked().await else {
            self.send_outbox_file(name, &data).await?;
            return Ok(Outcome::Sent);
        };
        let ext = Path::new(name).extension().and_then(|e| e.to_str());
        self.send_sealed(data, &sealed_name("report", ext, chrono::Utc::now()), &why).await
    }

    /// logguard's alerts in the outbox, to the admin. Each is claimed by renaming it first (as
    /// in admin mode); one that can't go out now, or that the server didn't confirm
    /// ([`Session::delivered`]), is put back. Alerts older than `ALERT_MAX_HOURS` are dropped,
    /// online or not.
    pub(super) async fn client_deliver_alerts(&mut self) {
        let Some(max_age) = self.client_ctx().map(|c| c.alert_max_age) else { return };
        let dir = self.upload.outbox.clone();
        let waiting = match outbox::scan_messages(&dir) {
            Ok(w) => w,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return self.client_warn(format!("outbox {}: {e}", dir.display())),
        };
        let now = SystemTime::now();
        let mut ready = Vec::new();
        for path in waiting {
            let age = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|m| now.duration_since(m).ok());
            if !age.is_some_and(|a| a > max_age) {
                ready.push(path);
            } else if std::fs::remove_file(&path).is_ok() {
                if let Some(c) = self.client_ctx() {
                    c.dropped += 1;
                }
            }
        }
        let dropped = self.client_ctx().map_or(0, |c| c.dropped);
        if (ready.is_empty() && dropped == 0) || !self.server_answers().await {
            return;
        }
        if dropped > 0 {
            if let Some(c) = self.client_ctx() {
                c.dropped = 0;
            }
            let hours = max_age.as_secs() / 3600;
            log::warn!("outbox: {dropped} alert(s) older than {hours} h dropped unsent");
            let text =
                format!("{dropped} alert(s) waited more than {hours} h and were dropped unsent. They are in logguard's actions log.");
            self.notice("dropped", text).await;
        }
        for path in ready {
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let sending = outbox::claimed(&path, "sending");
            match std::fs::rename(&path, &sending) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.client_warn(format!("outbox: can't take {name}: {e}"));
                    continue;
                }
            }
            // the recipient is logguard's ("admin", or its first admin's JID): this bot has one
            let Some((_, text)) = outbox::read_message(&sending) else {
                log::warn!("outbox: {name} is not an admin message (or larger than 1 MB); deleted");
                let _ = std::fs::remove_file(&sending);
                continue;
            };
            match self.client_send_alert(&text).await {
                Ok(Outcome::Sent) if !self.delivered().await => {
                    let _ = std::fs::rename(&sending, &path);
                    self.client_warn(format!("outbox: alert {name} not confirmed by the server; sending it again"));
                    break;
                }
                Ok(Outcome::Sent) => {
                    log::info!("outbox: alert {name} sent");
                    if let Err(e) = std::fs::remove_file(&sending) {
                        log::error!("outbox: deleting {} after sending: {e}", sending.display());
                    }
                    if let Some(c) = self.client_ctx() {
                        c.stats.alerts += 1;
                    }
                }
                Ok(Outcome::Waits) => {
                    let _ = std::fs::rename(&sending, &path);
                    break;
                }
                Err(e) => {
                    let _ = std::fs::rename(&sending, &path);
                    self.client_warn(format!("outbox: alert {name} not sent ({e}); trying again"));
                    break;
                }
            }
        }
    }

    /// Files in the outbox (the weekly abuse report); deletes those that waited too long.
    pub(super) async fn client_deliver_files(&mut self) {
        let dir = self.upload.outbox.clone();
        let pending = match outbox::scan(&dir, self.upload.max_age, SystemTime::now()) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return self.client_warn(format!("outbox {}: {e}", dir.display())),
        };
        for path in pending.expired {
            match std::fs::remove_file(&path) {
                Ok(()) => log::warn!(
                    "outbox: {} not sent within {} days (or too large), deleted",
                    path.display(),
                    self.upload.max_age.as_secs() / 86400
                ),
                Err(e) => log::error!("outbox: deleting {}: {e}", path.display()),
            }
        }
        if pending.ready.is_empty() || !self.server_answers().await {
            return;
        }
        for path in pending.ready {
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    self.client_warn(format!("outbox: reading {name}: {e}"));
                    continue;
                }
            };
            match self.client_send_file(&name, data).await {
                Ok(Outcome::Sent) if !self.delivered().await => {
                    self.client_warn(format!("outbox: {name} not confirmed by the server; sending it again later"));
                    return;
                }
                Ok(Outcome::Sent) => {
                    log::info!("outbox: {name} sent to the admin");
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("outbox: deleting {} after sending: {e}", path.display());
                    }
                    if let Some(c) = self.client_ctx() {
                        c.stats.files += 1;
                    }
                }
                Ok(Outcome::Waits) => return,
                Err(e) => {
                    self.client_warn(format!("outbox: {name} not sent ({e}); trying again later"));
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(extra: &[&str]) -> Args {
        let mut v = vec!["logguard-xmpp-bot", "--mode", "client", "--jid", "bot@example.net", "--admin", "admin@example.org"];
        v.extend_from_slice(extra);
        Args::try_parse_from(v).unwrap()
    }

    #[test]
    fn sealed_files_have_neutral_names() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-19T06:20:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(sealed_name("report", Some("txt"), now), "report-2026-10-19-062000.txt.pgp");
        assert_eq!(sealed_name("message", None, now), "message-2026-10-19-062000.bin.pgp");
        assert_eq!(sealed_name("report", Some("t x"), now), "report-2026-10-19-062000.bin.pgp");
    }

    /// Conversations shows a message as a file when its body is exactly the XEP-0066 URL.
    #[test]
    fn fallback_file_is_a_link_conversations_downloads() {
        let url = "https://upload.example.net/abc/report-2026-10-19-062000.txt.pgp";
        let el: Element = file_message("admin@example.org".parse().unwrap(), url).into();
        assert_eq!(el.get_child("body", "jabber:client").unwrap().text(), url);
        assert_eq!(el.get_child("x", OOB).unwrap().get_child("url", OOB).unwrap().text(), url);
        assert!(el.has_child("no-permanent-store", super::super::HINTS));
        assert!(!el.has_child("encrypted", crate::omemo::NS));
    }

    #[test]
    fn settings_send_nothing_in_clear() {
        let e = ClientCtx::new(&args(&["--omemo", "off"])).err().unwrap();
        assert!(e.is::<ConfigError>() && e.to_string().contains("needs OPENPGP_KEY"), "{e}");
        let ctx = ClientCtx::new(&args(&[])).unwrap();
        assert!(ctx.recipient.is_none());
        assert!(ctx.key_status(unix_now()).contains("messages wait"));
        assert_eq!(ctx.alert_max_age, Duration::from_secs(24 * 3600));
        assert!(ClientCtx::new(&args(&["--alert-max-hours", "0"])).is_err());
        let missing = ClientCtx::new(&args(&["--openpgp-key", "/nonexistent/admin.asc"])).err().unwrap();
        assert!(missing.is::<ConfigError>(), "{missing}");
    }

    #[test]
    fn a_usable_key_is_shown_by_fingerprint() {
        // a v4 key as phones make them: an EdDSA primary, a Curve25519 encryption subkey
        use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder};
        use pgp::ser::Serialize;
        let mut enc = SubkeyParamsBuilder::default();
        enc.key_type(KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("logguard reports <admin@example.org>".into())
            .subkeys(vec![enc.build().unwrap()]);
        let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
        let public = SignedPublicKey::from(secret).to_bytes().unwrap();
        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-client-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.pgp");
        std::fs::write(&path, public).unwrap();
        let ctx = ClientCtx::new(&args(&["--omemo", "off", "--openpgp-key", path.to_str().unwrap()])).unwrap();
        let fp = ctx.recipient.as_ref().unwrap().pretty_fingerprint();
        assert_eq!(ctx.key_status(unix_now()), format!("`{fp}`"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn help_names_every_command() {
        for c in ["/status", "/omemo", "/help"] {
            assert!(CLIENT_HELP.contains(c), "{c}");
        }
    }
}
