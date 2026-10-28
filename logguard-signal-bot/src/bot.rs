//! The bot: logguard's outbox to the admin's Signal account, through signal-cli.
//!
//! Signal encrypts every message end to end; what the bot adds is a check that the other end
//! is still the admin. It pins the safety number with the admin when it first sees it (or
//! takes it from `ADMIN_SAFETY_NUMBER`, as the Signal app shows it). While the safety number is
//! the pinned one, alerts go as Signal messages and files as attachments. When it changes (the
//! admin reinstalled Signal, or someone took over their number), nothing goes out readable to
//! the new identity: messages and files go as attachments encrypted to the admin's OpenPGP key
//! (`OPENPGP_KEY`), or wait without one, until the new safety number is confirmed on the server.
//!
//! The bot doesn't read what people send it: no commands. signal-cli receives (it must, to
//! keep the account working) and the bot drops it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use serde_json::{json, Value};

use crate::outbox;
use crate::redact::Pseudonyms;
use crate::rpc::{Rpc, RpcError};
use crate::seal::Recipient;
use crate::servers::ServerNames;
use crate::state::State;

/// A setting that restarting will not fix; the process exits with 78, which the unit does
/// not restart.
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

/// How long one call to signal-cli may take (a send with a large attachment included).
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// The admin's identity is looked up again after this.
const IDENTITY_FRESH: Duration = Duration::from_secs(60);

pub struct Config {
    /// The admin's phone number (+E.164) or ACI.
    pub admin: String,
    pub outbox: PathBuf,
    /// Files waiting longer are deleted unsent.
    pub outbox_max_age: Duration,
    /// Alerts waiting longer are dropped unsent (counted in one message instead).
    pub alert_max_age: Duration,
    pub state_path: PathBuf,
    /// The safety number with the admin, as set (digits only): it overrides the pin.
    pub admin_safety_number: Option<String>,
    /// The admin's OpenPGP key: the fallback while the safety number isn't the pinned one.
    pub recipient: Option<Recipient>,
    /// `SANITIZE=on`: alerts and digests with XMPP account names and the servers' own
    /// addresses replaced, as on Telegram. Off by default: they are end-to-end encrypted.
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

/// The first message to the admin: it makes the session whose identity the bot then checks.
pub const PROBE: &str = "logguard-signal-bot: connected. logguard's admin messages will come here.";

/// The caption of a fallback file: nothing about what is in it.
pub const FILE_CAPTION: &str = "Encrypted (OpenPGP). Open it with OpenKeychain (Android) or iPGMail (iPhone).";

/// A safety number as digits only (signal-cli and the app group them with blanks).
pub fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// The name a fallback file goes out under: neutral, with the original's extension.
pub fn sealed_name(kind: &str, original_ext: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> String {
    let ext = original_ext.filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric())).unwrap_or("bin");
    format!("{kind}-{}.{ext}.pgp", now.format("%Y-%m-%d-%H%M%S"))
}

/// An attachment as signal-cli takes it inline: a `data:` URI. The name keeps only
/// characters that can't end the URI's parts.
pub fn data_uri(mime: &str, name: &str, data: &[u8]) -> String {
    let name: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    format!("data:{mime};filename={name};base64,{}", base64::engine::general_purpose::STANDARD.encode(data))
}

/// The UTF-16 length of the first line, for a bold subject (`textStyle` counts UTF-16 units).
pub fn subject_len(text: &str) -> usize {
    text.lines().next().unwrap_or_default().encode_utf16().count()
}

/// The admin's identity, as signal-cli knows it.
#[derive(Debug, Clone, PartialEq)]
pub enum Identity {
    /// No session with the admin yet.
    Unknown,
    /// The safety number (digits) and signal-cli's trust level for it.
    Known { safety_number: String, trust: String },
}

/// The admin's current identity from a `listIdentities` result: the newest one for them.
pub fn identity_of(result: &Value, admin: &str) -> Identity {
    let newest = result
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i.get("number").and_then(Value::as_str) == Some(admin) || i.get("uuid").and_then(Value::as_str) == Some(admin))
        .filter(|i| i.get("safetyNumber").and_then(Value::as_str).is_some_and(|s| digits(s).len() == 60))
        .max_by_key(|i| i.get("addedTimestamp").and_then(Value::as_i64).unwrap_or(0));
    match newest {
        Some(i) => Identity::Known {
            safety_number: digits(i["safetyNumber"].as_str().unwrap_or_default()),
            trust: i.get("trustLevel").and_then(Value::as_str).unwrap_or_default().to_string(),
        },
        None => Identity::Unknown,
    }
}

/// Why a send failed.
#[derive(Debug, Clone, PartialEq)]
pub enum SendError {
    /// signal-cli itself: gone, too slow, or an error of its own.
    Rpc(RpcError),
    /// The admin's identity isn't trusted (a changed safety number).
    Identity,
    /// The admin's number isn't on Signal.
    Unregistered,
    /// Signal's rate limit.
    RateLimit,
    /// Signal wants a captcha solved for the bot's account first.
    ProofRequired,
    /// Signal out of reach.
    Network,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SendError::Rpc(e) => write!(f, "{e}"),
            SendError::Identity => f.write_str("the admin's identity isn't trusted (safety number changed)"),
            SendError::Unregistered => f.write_str("the admin's number isn't registered with Signal"),
            SendError::RateLimit => f.write_str("Signal's rate limit"),
            SendError::ProofRequired => {
                f.write_str("Signal wants a captcha for the bot's account (logguard-signal-bot signal-cli submitRateLimitChallenge ...)")
            }
            SendError::Network => f.write_str("Signal out of reach"),
        }
    }
}

/// The outcome of a `send` call: success, or what the first failed recipient result says.
pub fn send_outcome(reply: Result<Value, RpcError>) -> Result<(), SendError> {
    let results = match &reply {
        Ok(v) => v.get("results").cloned(),
        Err(RpcError::Remote { data, .. }) => data.get("response").and_then(|r| r.get("results")).cloned(),
        Err(_) => None,
    };
    for r in results.as_ref().and_then(Value::as_array).into_iter().flatten() {
        match r.get("type").and_then(Value::as_str).unwrap_or("SUCCESS") {
            "SUCCESS" => {}
            "IDENTITY_FAILURE" => return Err(SendError::Identity),
            "UNREGISTERED_FAILURE" => return Err(SendError::Unregistered),
            "RATE_LIMIT_FAILURE" => return Err(SendError::RateLimit),
            "PROOF_REQUIRED_FAILURE" => return Err(SendError::ProofRequired),
            _ => return Err(SendError::Network),
        }
    }
    match reply {
        Ok(_) => Ok(()),
        Err(RpcError::Remote { message, .. }) if message.to_lowercase().contains("untrusted") => Err(SendError::Identity),
        Err(e) => Err(SendError::Rpc(e)),
    }
}

/// How a message can go out right now.
#[derive(Debug, PartialEq)]
pub enum Route {
    /// As a Signal message to the pinned identity (or to the first one seen).
    Signal,
    /// As an OpenPGP file, for this reason.
    Pgp(String),
}

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

pub struct Bot {
    pub rpc: Rpc,
    pub cfg: Config,
    pub state: State,
    stats: Stats,
    /// Nothing is sent before this (rate limited, or after a failure).
    not_before: Option<Instant>,
    last_warning: Option<(String, Instant)>,
    identity: Option<(Instant, Identity)>,
    /// Notices to the admin (why messages come as files), by kind, when last sent.
    notices: BTreeMap<&'static str, Instant>,
    /// Set when signal-cli is gone: the service stops, systemd starts it again.
    pub fatal: Option<String>,
}

impl Bot {
    pub fn new(rpc: Rpc, cfg: Config, mut state: State) -> Bot {
        if let Some(pin) = &cfg.admin_safety_number {
            state.admin_safety_number = Some(pin.clone());
        }
        Bot {
            rpc,
            cfg,
            state,
            stats: Stats::default(),
            not_before: None,
            last_warning: None,
            identity: None,
            notices: BTreeMap::new(),
            fatal: None,
        }
    }

    pub fn save(&self) {
        if let Err(e) = self.state.save(&self.cfg.state_path) {
            log::error!("saving {}: {e}", self.cfg.state_path.display());
        }
    }

    fn warn_repeated(&mut self, msg: String) {
        let again = self.last_warning.as_ref().is_none_or(|(m, t)| *m != msg || t.elapsed() >= Duration::from_secs(600));
        if again {
            log::warn!("{msg}");
            self.last_warning = Some((msg, Instant::now()));
        }
    }

    fn throttled(&self) -> bool {
        self.not_before.is_some_and(|t| Instant::now() < t)
    }

    fn pause(&mut self, d: Duration) {
        self.not_before = Some(Instant::now() + d);
    }

    /// Remembers a failed send: how long to hold off, or that signal-cli is gone.
    fn failed(&mut self, e: &SendError) {
        match e {
            SendError::Rpc(RpcError::Closed) => self.fatal = Some("signal-cli has stopped".into()),
            SendError::Rpc(_) | SendError::Network => self.pause(Duration::from_secs(30)),
            SendError::RateLimit => self.pause(Duration::from_secs(300)),
            SendError::Identity => self.identity = None,
            SendError::ProofRequired | SendError::Unregistered => {
                self.warn_repeated(format!("{e}: messages wait"));
                self.pause(Duration::from_secs(3600));
            }
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.rpc.call(method, params, CALL_TIMEOUT).await
    }

    /// The admin's identity (looked up at most once a minute).
    async fn identity(&mut self) -> Result<Identity, RpcError> {
        if let Some((t, id)) = &self.identity {
            if t.elapsed() < IDENTITY_FRESH {
                return Ok(id.clone());
            }
        }
        let id = match self.call("listIdentities", json!({ "number": self.cfg.admin })).await {
            Ok(v) => identity_of(&v, &self.cfg.admin),
            // signal-cli doesn't know the recipient yet
            Err(RpcError::Remote { .. }) => Identity::Unknown,
            Err(e) => return Err(e),
        };
        self.identity = Some((Instant::now(), id.clone()));
        Ok(id)
    }

    /// How messages can go out now; pins the safety number on first sight. With no session
    /// to the admin yet, a first message without content makes one, so the identity is known
    /// (and checked) before anything else goes out.
    pub async fn route(&mut self) -> Result<Route, SendError> {
        let admin = self.cfg.admin.clone();
        if self.identity().await.map_err(SendError::Rpc)? == Identity::Unknown {
            match self.send(PROBE, 0, None).await {
                Ok(()) | Err(SendError::Identity) => log::info!("first message to {admin} sent"),
                Err(e) => return Err(e),
            }
            self.identity = None;
        }
        let (safety_number, trust) = match self.identity().await.map_err(SendError::Rpc)? {
            Identity::Unknown => return Ok(Route::Pgp(format!("signal-cli knows no identity of {admin}, even after a first message"))),
            Identity::Known { safety_number, trust } => (safety_number, trust),
        };
        match self.state.admin_safety_number.clone() {
            Some(pin) if pin == safety_number => {
                if trust == "UNTRUSTED" {
                    // the identity confirmed on the server (ADMIN_SAFETY_NUMBER): signal-cli too
                    self.call("trust", json!({ "recipient": admin, "verifiedSafetyNumber": safety_number }))
                        .await
                        .map_err(SendError::Rpc)?;
                    log::info!("trusted {admin}'s identity: its safety number is the configured one");
                    self.identity = None;
                }
                Ok(Route::Signal)
            }
            Some(pin) => Ok(Route::Pgp(format!(
                "the safety number with {admin} changed: it was {}, now it is {}. If {admin} reinstalled Signal, compare it in \
                 the app and set ADMIN_SAFETY_NUMBER to it on the server",
                grouped(&pin),
                grouped(&safety_number)
            ))),
            None if trust == "UNTRUSTED" => Ok(Route::Pgp(format!(
                "the safety number with {admin} changed before the bot pinned one; compare it in the app and set \
                 ADMIN_SAFETY_NUMBER={} on the server",
                grouped(&safety_number)
            ))),
            None => {
                log::info!("pinned the safety number with {admin}: {}", grouped(&safety_number));
                self.state.admin_safety_number = Some(safety_number);
                self.save();
                Ok(Route::Signal)
            }
        }
    }

    /// One Signal message to the admin, with an attachment (`data:` URI) if any.
    async fn send(&mut self, text: &str, bold: usize, attachment: Option<String>) -> Result<(), SendError> {
        let mut params = json!({ "recipient": [self.cfg.admin], "message": text });
        if bold > 0 {
            params["textStyle"] = json!([format!("0:{bold}:BOLD")]);
        }
        if let Some(a) = attachment {
            params["attachments"] = json!([a]);
        }
        send_outcome(self.call("send", params).await)
    }

    /// A short message to the admin at most once a day per kind (why messages come as files,
    /// or wait).
    async fn notice(&mut self, kind: &'static str, text: String) {
        if self.notices.get(kind).is_some_and(|t| t.elapsed() < Duration::from_secs(86400)) {
            return;
        }
        match self.send(&format!("logguard-signal-bot: {text}"), 0, None).await {
            Ok(()) => {
                self.notices.insert(kind, Instant::now());
            }
            Err(e) => log::warn!("notice not sent: {e}"),
        }
    }

    /// `data` as an attachment encrypted to the admin's OpenPGP key; `Waits` when there is no
    /// usable key. signal-cli is first told to accept the admin's new identity, which only
    /// ever gets ciphertext then.
    async fn send_sealed(&mut self, data: Vec<u8>, name: &str, why: &str) -> Result<Outcome, SendError> {
        let now = chrono::Utc::now().timestamp() as u32;
        let key_problem = match &self.cfg.recipient {
            None => Some("OPENPGP_KEY is not set".to_string()),
            Some(r) => r.check(now).err().map(|e| format!("the OpenPGP key {e}")),
        };
        if let Some(p) = key_problem {
            self.warn_repeated(format!("outbox: messages wait: {why}, and {p}"));
            return Ok(Outcome::Waits);
        }
        let Some(r) = &self.cfg.recipient else { return Ok(Outcome::Waits) };
        let sealed = match r.seal(data, now) {
            Ok(s) => s,
            Err(e) => {
                self.warn_repeated(format!("outbox: {name} not encrypted: {e}"));
                return Ok(Outcome::Waits);
            }
        };
        self.call("trust", json!({ "recipient": self.cfg.admin, "trustAllKnownKeys": true })).await.map_err(SendError::Rpc)?;
        self.notice("fallback", format!("{why}. Until then messages come as files encrypted to your OpenPGP key.")).await;
        self.send(FILE_CAPTION, 0, Some(data_uri("application/pgp-encrypted", name, &sealed))).await?;
        self.stats.fallbacks += 1;
        Ok(Outcome::Sent)
    }

    async fn send_alert(&mut self, text: &str) -> Result<Outcome, SendError> {
        match self.route().await? {
            Route::Signal => {
                self.send(text, subject_len(text), None).await?;
                Ok(Outcome::Sent)
            }
            Route::Pgp(why) => {
                self.send_sealed(text.as_bytes().to_vec(), &sealed_name("message", Some("txt"), chrono::Utc::now()), &why).await
            }
        }
    }

    async fn send_file(&mut self, name: &str, data: Vec<u8>) -> Result<Outcome, SendError> {
        match self.route().await? {
            Route::Signal => {
                self.send(name, 0, Some(data_uri("text/plain", name, &data))).await?;
                Ok(Outcome::Sent)
            }
            Route::Pgp(why) => {
                let ext = std::path::Path::new(name).extension().and_then(|e| e.to_str());
                self.send_sealed(data, &sealed_name("report", ext, chrono::Utc::now()), &why).await
            }
        }
    }

    /// logguard's alerts in the outbox, to the admin.
    pub async fn deliver_alerts(&mut self) {
        if self.throttled() || self.fatal.is_some() {
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
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            if age > self.cfg.alert_max_age {
                if std::fs::remove_file(&path).is_ok() {
                    dropped += 1;
                }
                continue;
            }
            let sending = outbox::claimed(&path, "sending");
            match std::fs::rename(&path, &sending) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.warn_repeated(format!("outbox: can't take {name}: {e}"));
                    continue;
                }
            }
            let Some(text) = outbox::read_message(&sending) else {
                log::warn!("outbox: {name} is not an admin message (or larger than 1 MB); deleted");
                let _ = std::fs::remove_file(&sending);
                continue;
            };
            let text = match &self.cfg.sanitize {
                Some(s) => s.text(&text),
                None => text,
            };
            match self.send_alert(&text).await {
                Ok(Outcome::Sent) => {
                    log::info!("outbox: alert {name} sent");
                    if let Err(e) = std::fs::remove_file(&sending) {
                        log::error!("outbox: deleting {} after sending: {e}", sending.display());
                    }
                    self.stats.alerts += 1;
                }
                Ok(Outcome::Waits) => {
                    let _ = std::fs::rename(&sending, &path);
                    break;
                }
                // a request signal-cli finds malformed would be refused forever
                Err(SendError::Rpc(RpcError::Remote { code: -32602, message, .. })) => {
                    log::error!("outbox: alert {name} dropped: signal-cli refuses it ({message})");
                    let _ = std::fs::remove_file(&sending);
                }
                Err(e) => {
                    let _ = std::fs::rename(&sending, &path);
                    self.failed(&e);
                    self.warn_repeated(format!("outbox: alert {name} not sent ({e}); trying again"));
                    break;
                }
            }
        }
        if dropped > 0 {
            let hours = self.cfg.alert_max_age.as_secs() / 3600;
            log::warn!("outbox: {dropped} alert(s) older than {hours} h dropped unsent");
            let text = format!(
                "{dropped} alert(s) waited more than {hours} h and were dropped unsent. They are in logguard's actions log on the server."
            );
            self.notice("dropped", text).await;
        }
    }

    /// Files in the outbox (the weekly abuse report); deletes those that waited too long.
    pub async fn deliver_files(&mut self) {
        if self.fatal.is_some() {
            return;
        }
        let dir = self.cfg.outbox.clone();
        let pending = match outbox::scan(&dir, self.cfg.outbox_max_age, SystemTime::now()) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return self.warn_repeated(format!("outbox {}: {e}", dir.display())),
        };
        for path in pending.expired {
            match std::fs::remove_file(&path) {
                Ok(()) => log::warn!(
                    "outbox: {} not sent within {} days (or too large), deleted",
                    path.display(),
                    self.cfg.outbox_max_age.as_secs() / 86400
                ),
                Err(e) => log::error!("outbox: deleting {}: {e}", path.display()),
            }
        }
        for path in pending.ready {
            if self.throttled() {
                return;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    self.warn_repeated(format!("outbox: reading {name}: {e}"));
                    continue;
                }
            };
            match self.send_file(&name, data).await {
                Ok(Outcome::Sent) => {
                    log::info!("outbox: {name} sent");
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("outbox: deleting {} after sending: {e}", path.display());
                    }
                    self.stats.files += 1;
                }
                Ok(Outcome::Waits) => return,
                Err(e) => {
                    self.failed(&e);
                    self.warn_repeated(format!("outbox: {name} not sent ({e}); trying again later"));
                    return;
                }
            }
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "sent {} alert(s) and {} file(s), {} of them as OpenPGP files; ignored {} message(s) to the bot",
            self.stats.alerts,
            self.stats.files,
            self.stats.fallbacks,
            self.rpc.incoming()
        )
    }
}

/// A safety number in groups of five, as the app shows it.
pub fn grouped(digits: &str) -> String {
    let chars: Vec<char> = digits.chars().collect();
    chars.chunks(5).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
}

pub async fn run(mut bot: Bot) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let recovered = outbox::recover(&bot.cfg.outbox);
    if recovered > 0 {
        log::info!("outbox: {recovered} alert(s) left half-sent at the last stop, sending again");
    }
    if !bot.cfg.outbox.is_dir() {
        log::warn!("no outbox {} yet: nothing to deliver until it exists", bot.cfg.outbox.display());
    } else if let Err(e) = outbox::writable(&bot.cfg.outbox) {
        log::error!(
            "the outbox {} is not writable for the bot ({e}): it can't take or delete what logguard puts there",
            bot.cfg.outbox.display()
        );
    }
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut alerts = tokio::time::interval(Duration::from_secs(5));
    alerts.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut files = tokio::time::interval(Duration::from_secs(60));
    files.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            _ = alerts.tick() => bot.deliver_alerts().await,
            _ = files.tick() => bot.deliver_files().await,
            _ = sigterm.recv() => break Ok(()),
            _ = sigint.recv() => break Ok(()),
        }
        if bot.rpc.is_closed() && bot.fatal.is_none() {
            bot.fatal = Some("signal-cli has stopped".into());
        }
        if let Some(f) = bot.fatal.take() {
            break Err(anyhow::anyhow!("{f}"));
        }
    };
    log::info!("Shutting down; {}", bot.summary());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SN: &str = "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890";

    #[test]
    fn identities() {
        let admin = "+491701234567";
        let list = json!([
            { "number": admin, "uuid": "u", "safetyNumber": SN, "trustLevel": "TRUSTED_UNVERIFIED", "addedTimestamp": 1 },
            { "number": admin, "uuid": "u", "safetyNumber": "98765 ".repeat(12), "trustLevel": "UNTRUSTED", "addedTimestamp": 2 },
            { "number": "+15550000000", "safetyNumber": SN, "addedTimestamp": 3 },
        ]);
        assert_eq!(
            identity_of(&list, admin),
            Identity::Known { safety_number: "98765".repeat(12), trust: "UNTRUSTED".into() },
            "the newest"
        );
        assert_eq!(identity_of(&list, "u"), identity_of(&list, admin), "by ACI too");
        assert_eq!(identity_of(&json!([]), admin), Identity::Unknown);
        assert_eq!(identity_of(&json!([{ "number": admin, "safetyNumber": "123" }]), admin), Identity::Unknown, "not a safety number");
        assert_eq!(grouped(&digits(SN)), SN);
    }

    #[test]
    fn send_outcomes() {
        let ok = json!({ "timestamp": 1, "results": [{ "recipientAddress": { "number": "+4917" }, "type": "SUCCESS" }] });
        assert_eq!(send_outcome(Ok(ok)), Ok(()));
        let identity = RpcError::Remote {
            code: -1,
            message: "Failed to send message".into(),
            data: json!({ "response": { "results": [{ "type": "IDENTITY_FAILURE" }] } }),
        };
        assert_eq!(send_outcome(Err(identity)), Err(SendError::Identity));
        assert_eq!(send_outcome(Ok(json!({ "results": [{ "type": "RATE_LIMIT_FAILURE" }] }))), Err(SendError::RateLimit));
        assert_eq!(send_outcome(Ok(json!({ "results": [{ "type": "NETWORK_FAILURE" }] }))), Err(SendError::Network));
        assert_eq!(send_outcome(Err(RpcError::Timeout)), Err(SendError::Rpc(RpcError::Timeout)));
        let untrusted = RpcError::Remote { code: 4, message: "Untrusted Identity for \"+4917\"".into(), data: Value::Null };
        assert_eq!(send_outcome(Err(untrusted)), Err(SendError::Identity));
    }

    #[test]
    fn attachments_and_names() {
        assert_eq!(data_uri("text/plain", "abuse report;x,y.txt", b"hi"), "data:text/plain;filename=abuse_report_x_y.txt;base64,aGk=");
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-19T06:20:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(sealed_name("report", Some("txt"), now), "report-2026-10-19-062000.txt.pgp");
        assert_eq!(subject_len("[xmpp] logguard: system\n\nbody"), 23);
        assert_eq!(subject_len("😀 x"), 4, "UTF-16 units");
        assert!(!FILE_CAPTION.to_lowercase().contains("abuse"));
    }
}
