//! The bot: logguard's outbox to the admin's Telegram chat, and a few read-only commands.
//!
//! One chat only: the admin's private chat with the bot (`ADMIN_CHAT_ID`, the admin's
//! Telegram user id). Messages from anyone else, and from groups the bot was added to, are
//! ignored without an answer. The bot takes no orders for the servers: that stays on SSH.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use crate::api::{self, Api, ApiError, Message, Update, User};
use crate::format::{self, Out};
use crate::outbox;
use crate::redact::Pseudonyms;
use crate::seal::Recipient;
use crate::servers::ServerNames;
use crate::state::{Sent, State};

/// Messages older than this can't be deleted any more (Telegram's limit is 48 hours).
const DELETE_LIMIT_SECS: i64 = 48 * 3600 - 600;

/// A setting or a token that restarting will not fix; the process exits with 78, which
/// the unit does not restart.
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
    /// The admin's Telegram user id, which is also the id of their private chat with the bot.
    pub admin: i64,
    pub outbox: PathBuf,
    /// Files waiting longer are deleted unsent.
    pub outbox_max_age: Duration,
    /// Alerts waiting longer are dropped unsent (counted in one message instead).
    pub alert_max_age: Duration,
    /// Delete the chat's messages this long after they were sent; `None`: keep them.
    pub delete_after: Option<Duration>,
    /// Ask clients not to allow forwarding or saving alerts (files are never protected:
    /// the abuse report is meant to be passed on).
    pub protect: bool,
    pub state_path: PathBuf,
    /// The servers' own addresses and names, replaced by their node ids in alerts.
    pub servers: ServerNames,
    /// The admin's OpenPGP key: files go out encrypted to it, as a whole, or not at all.
    pub recipient: Option<Recipient>,
}

/// The caption of an encrypted file: nothing about what is in it.
pub const FILE_CAPTION: &str = "Encrypted (OpenPGP). Open it with OpenKeychain (Android) or iPGMail (iPhone).";

/// The name a file goes out under: neutral, with the original's extension (the apps name
/// the decrypted file after it, without `.pgp`).
pub fn sealed_name(original: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let ext = std::path::Path::new(original)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("bin");
    format!("report-{}.{ext}.pgp", now.format("%Y-%m-%d"))
}

#[derive(Default)]
struct Stats {
    alerts: u64,
    files: u64,
    last_sent: Option<i64>,
    last_error: Option<(i64, String)>,
}

pub struct Bot {
    pub api: Api,
    pub cfg: Config,
    pub names: Pseudonyms,
    pub state: State,
    /// The bot's own @name.
    pub username: String,
    started: i64,
    stats: Stats,
    /// Nothing is sent before this (Telegram's flood control, or after a failure).
    not_before: Option<Instant>,
    /// Whether the last poll for updates worked.
    polling: bool,
    dirty: bool,
    /// The last warning logged and when: repeated failures are logged every 10 minutes.
    last_warning: Option<(String, Instant)>,
    /// Messages from others since the last log line about them.
    ignored: u64,
    ignored_logged: Option<Instant>,
    /// When the admin was last told that files can't go out (at most daily).
    file_notice: Option<Instant>,
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Whether a message comes from the admin, in their private chat with the bot.
pub fn from_admin(m: &Message, admin: i64) -> bool {
    m.chat.kind == "private" && m.chat.id == admin && m.from.as_ref().is_some_and(|u| u.id == admin && !u.is_bot)
}

pub const COMMANDS: [(&str, &str); 3] = [
    ("status", "delivery state and what waits in the outbox"),
    ("privacy", "what goes through Telegram, what the bot keeps"),
    ("help", "what this bot does"),
];

pub fn help() -> String {
    "logguard's messages to the admin, on Telegram: alerts, the daily digest and the weekly abuse report.\n\n\
     /status  delivery state and what waits in the outbox\n\
     /privacy  what goes through Telegram, and what the bot keeps\n\
     /help  this text\n\n\
     It takes no orders for the servers: those stay on SSH."
        .into()
}

/// Waits for Telegram to accept the token: retries while Telegram can't be reached, gives
/// up at once (exit 78) when it refuses the token.
pub async fn connect(api: &Api) -> anyhow::Result<User> {
    let mut wait = 5;
    loop {
        match api.get_me().await {
            Ok(me) => return Ok(me),
            Err(e) if e.bad_token() => return Err(Refused(format!("Telegram refused the token ({e}): check TELEGRAM_TOKEN")).into()),
            Err(e) => {
                log::warn!("Telegram not reachable ({e}); trying again in {wait} s");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                wait = (wait * 2).min(300);
            }
        }
    }
}

impl Bot {
    pub fn new(api: Api, cfg: Config, names: Pseudonyms, username: String) -> Bot {
        let mut state = State::load(&cfg.state_path);
        // auto-delete turned off: what it would have deleted is no business of the bot any more
        let stale = cfg.delete_after.is_none() && !state.to_delete.is_empty();
        if stale {
            state.to_delete.clear();
        }
        Bot {
            api,
            cfg,
            names,
            state,
            username,
            started: unix_now(),
            stats: Stats::default(),
            not_before: None,
            polling: false,
            last_warning: None,
            ignored: 0,
            ignored_logged: None,
            file_notice: None,
            dirty: stale,
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

    /// Remembers a failed call: what to show in /status, and how long to hold off.
    fn failed(&mut self, e: &ApiError) {
        self.stats.last_error = Some((unix_now(), e.to_string()));
        let pause = match e {
            _ if e.retry_after().is_some() => e.retry_after().unwrap_or_default(),
            // this request will never go through, but the next one may: no pause
            _ if e.permanent() => return,
            ApiError::Transport(_) => Duration::from_secs(30),
            ApiError::Telegram { code: 403, .. } => {
                self.warn_repeated(format!(
                    "Telegram: {e}. Has the admin (ADMIN_CHAT_ID {}) started a chat with the bot (/start)?",
                    self.cfg.admin
                ));
                Duration::from_secs(300)
            }
            ApiError::Telegram { .. } => Duration::from_secs(60),
        };
        self.not_before = Some(Instant::now() + pause);
    }

    fn remember(&mut self, message_id: i64, at: i64) {
        if self.cfg.delete_after.is_some() {
            self.state.to_delete.push(Sent { id: message_id, at });
            self.dirty = true;
        }
    }

    /// Sends the pieces in order; stops at the first failure.
    async fn send(&mut self, outs: &[Out], protect: bool) -> Result<(), ApiError> {
        for o in outs {
            match self.api.send_message(self.cfg.admin, &o.text, &o.entities, protect).await {
                Ok(m) => self.remember(m.message_id, m.date),
                Err(e) => {
                    self.failed(&e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        match self.state.save(&self.cfg.state_path) {
            Ok(()) => self.dirty = false,
            Err(e) => log::error!("saving {}: {e}", self.cfg.state_path.display()),
        }
    }

    pub async fn on_update(&mut self, u: Update) {
        if u.update_id >= self.state.offset {
            self.state.offset = u.update_id + 1;
            self.dirty = true;
        }
        let Some(m) = u.message else { return };
        if matches!(m.chat.kind.as_str(), "group" | "supergroup" | "channel") {
            // someone added the bot to a group: it serves one private chat only
            match self.api.leave_chat(m.chat.id).await {
                Ok(_) => log::info!("left the {} chat {} the bot was added to", m.chat.kind, m.chat.id),
                Err(e) => log::warn!("leaving the {} chat {}: {e}", m.chat.kind, m.chat.id),
            }
        }
        if !from_admin(&m, self.cfg.admin) {
            self.ignored += 1;
            if self.ignored_logged.is_none_or(|t| t.elapsed() >= Duration::from_secs(600)) {
                let who = m.from.as_ref().map_or(0, |u| u.id);
                log::info!(
                    "ignored {} message(s) not from the admin; the latest from Telegram user {who} in a {} chat",
                    self.ignored,
                    m.chat.kind
                );
                self.ignored = 0;
                self.ignored_logged = Some(Instant::now());
            }
            return;
        }
        self.remember(m.message_id, m.date);
        let text = m.text.as_deref().unwrap_or("");
        let command = text.split_whitespace().next().unwrap_or("").split('@').next().unwrap_or("");
        log::info!("admin: {}", if command.starts_with('/') { command } else { "(text)" });
        let reply = self.reply(command);
        if let Err(e) = self.send(&format::plain(&reply), false).await {
            log::warn!("reply to {command} not sent: {e}");
        }
    }

    pub fn reply(&self, command: &str) -> String {
        match command {
            "/start" | "/help" => help(),
            "/status" => self.status(),
            "/privacy" => self.privacy(),
            c if c.starts_with('/') => format!("Unknown command {c}. /help lists the commands."),
            _ => "This bot only delivers logguard's messages; it takes no orders. /help lists its commands.".into(),
        }
    }

    pub fn status(&self) -> String {
        let now = unix_now();
        let mut s =
            format!("logguard-tg-bot {}, @{}, up {}\n", env!("CARGO_PKG_VERSION"), self.username, format::duration(now - self.started));
        s += if self.polling { "Telegram: polling\n" } else { "Telegram: not polling right now\n" };
        s += &format!("Sent since the start: {} alert(s), {} file(s)", self.stats.alerts, self.stats.files);
        if let Some(t) = self.stats.last_sent {
            s += &format!(", the last {} ago", format::duration(now - t));
        }
        s += "\n";
        let sys_now = SystemTime::now();
        let alerts = outbox::scan_messages(&self.cfg.outbox, sys_now).unwrap_or_default();
        let files = outbox::scan(&self.cfg.outbox, self.cfg.outbox_max_age, sys_now).unwrap_or_default();
        s += &format!("Outbox: {} alert(s), {} file(s) waiting", alerts.len(), files.ready.len());
        if let Some(oldest) = alerts.iter().map(|(_, age)| *age).max() {
            s += &format!(", the oldest alert for {}", format::duration(oldest.as_secs() as i64));
        }
        s += "\n";
        s += "Account names: replaced by pseudonyms ([acct:…])\n";
        s += if self.cfg.servers.is_empty() {
            "Server addresses and names: not replaced (SERVER_NAMES is empty)\n"
        } else {
            "Server addresses and names: replaced by node ids\n"
        };
        s += &match &self.cfg.recipient {
            Some(r) => match r.check(now as u32) {
                Ok(()) => format!("Files: encrypted to the OpenPGP key …{}\n", &r.fingerprint[r.fingerprint.len() - 16..]),
                Err(e) => format!("Files: not sent: the OpenPGP key …{}: {e}\n", &r.fingerprint[r.fingerprint.len() - 16..]),
            },
            None => "Files: not sent (no OPENPGP_KEY: they go out encrypted or not at all)\n".into(),
        };
        s += &match self.cfg.delete_after {
            Some(d) => format!("Messages here are deleted after {} h ({} waiting)\n", d.as_secs() / 3600, self.state.to_delete.len()),
            None => "Messages here are kept (DELETE_AFTER_HOURS=0)\n".into(),
        };
        if let Some((t, e)) = &self.stats.last_error {
            s += &format!("Last error, {} ago: {e}\n", format::duration(now - t));
        }
        s
    }

    pub fn privacy(&self) -> String {
        let kept = match self.cfg.delete_after {
            Some(d) => format!("The bot deletes this chat's messages (both sides) after {} hours.", d.as_secs() / 3600),
            None => "They stay in this chat until you delete them.".into(),
        };
        format!(
            "What goes through this bot\n\n\
             • Bots on Telegram are not end-to-end encrypted: Telegram's servers can read what this bot sends, \
             TLS only protects the way there. {kept}\n\
             • It carries logguard's admin alerts and daily digests as messages: attackers' addresses, \
             the servers' state, sanitized log lines. The servers appear only by their node ids (xmpp, vpn, …), \
             not by address or host name.\n\
             • XMPP account names never reach Telegram: each becomes a pseudonym like [acct:1a2b3c], made with \
             a key that stays on the server (`logguard-tg-bot pseudonym <address>` there tells which).\n\
             • The weekly abuse report comes only as a file encrypted, as a whole, to your OpenPGP key: Telegram \
             sees its size and a neutral name, nothing of its content. Open it with OpenKeychain or iPGMail. \
             The server holds only the public key.\n\
             • On the server the bot keeps its log (14 days), its position in Telegram's update queue{}, and \
             outbox files until they are sent (unsent ones {} days at most).\n\
             • Only your Telegram account (id {}) can use it. Messages from others get no answer; the log \
             keeps only a count and the sender's number.\n\
             • It takes no orders for the servers.",
            if self.cfg.delete_after.is_some() { " and the ids of messages to delete" } else { "" },
            self.cfg.outbox_max_age.as_secs() / 86400,
            self.cfg.admin
        )
    }

    /// logguard's alerts in the outbox, to the admin, with account names and the servers'
    /// addresses and names replaced.
    pub async fn deliver_alerts(&mut self) {
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
            let text = crate::redact::sanitize(&self.names, &self.cfg.servers, &text);
            let outcome = match self.send(&format::alert(&text), self.cfg.protect).await {
                Err(e) if e.permanent() => {
                    log::warn!("outbox: Telegram refused alert {name} ({e}); sending it without formatting");
                    self.send(&format::plain(&text), self.cfg.protect).await
                }
                other => other,
            };
            match outcome {
                // the same request would be refused forever, and hold up every alert after it
                Err(e) if e.permanent() => {
                    log::error!("outbox: alert {name} dropped: Telegram refuses it ({e})");
                    let _ = std::fs::remove_file(&sending);
                    let note = format!("An alert was dropped: Telegram refused it ({e}). It is in logguard's actions log on the server.");
                    let _ = self.send(&format::plain(&note), false).await;
                }
                Ok(()) => {
                    log::info!("outbox: alert {name} sent");
                    if let Err(e) = std::fs::remove_file(&sending) {
                        log::error!("outbox: deleting {} after sending: {e}", sending.display());
                    }
                    self.stats.alerts += 1;
                    self.stats.last_sent = Some(unix_now());
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
            let note = format!("{dropped} alert(s) waited more than {hours} h and were dropped unsent (the bot was down, or Telegram out of reach). The XMPP admin bot, if set up, had its own copy.");
            let _ = self.send(&format::plain(&note), false).await;
        }
    }

    /// Files in the outbox (the weekly abuse report), encrypted to the admin's OpenPGP key,
    /// as documents; deletes those that waited too long. Without a key, nothing is sent.
    pub async fn deliver_files(&mut self) {
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
        if pending.ready.is_empty() {
            return;
        }
        if self.cfg.recipient.is_none() {
            let n = pending.ready.len();
            return self.warn_repeated(format!("outbox: {n} file(s) wait: files go out encrypted only, and OPENPGP_KEY is not set"));
        }
        let now = unix_now() as u32;
        if let Some(Err(e)) = self.cfg.recipient.as_ref().map(|r| r.check(now)) {
            let n = pending.ready.len();
            self.warn_repeated(format!("outbox: {n} file(s) wait: OPENPGP_KEY {e}"));
            let days = self.cfg.outbox_max_age.as_secs() / 86400;
            let note = format!("{n} file(s) can't be sent: your OpenPGP key {e}. Install a valid public key as OPENPGP_KEY on the server and restart the bot; files wait {days} days at most.");
            return self.file_notice(note).await;
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
            let sealed = match self.cfg.recipient.as_ref().map(|r| r.seal(data, now)) {
                Some(Ok(s)) => s,
                Some(Err(e)) => {
                    self.warn_repeated(format!("outbox: {name} not sent: {e}"));
                    continue;
                }
                None => return,
            };
            let sent_as = sealed_name(&name, chrono::Utc::now());
            match self.api.send_document(self.cfg.admin, &sent_as, sealed, FILE_CAPTION).await {
                Ok(m) => {
                    log::info!("outbox: {name} sent encrypted as {sent_as}");
                    self.remember(m.message_id, m.date);
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("outbox: deleting {} after sending: {e}", path.display());
                    }
                    self.stats.files += 1;
                    self.stats.last_sent = Some(unix_now());
                }
                // too large, or otherwise refused for good: it would hold up every file after it
                Err(e) if e.permanent() => {
                    log::error!("outbox: {name} dropped: Telegram refuses it ({e})");
                    let _ = std::fs::remove_file(&path);
                    let note = format!("A file was dropped: Telegram refused it ({e}).");
                    let _ = self.send(&format::plain(&note), false).await;
                }
                Err(e) => {
                    self.failed(&e);
                    self.warn_repeated(format!("outbox: {name} not sent ({e}); trying again later"));
                    return;
                }
            }
        }
    }

    /// Tells the admin something about files, at most once a day.
    async fn file_notice(&mut self, note: String) {
        if self.file_notice.is_some_and(|t| t.elapsed() < Duration::from_secs(86400)) || self.throttled() {
            return;
        }
        if self.send(&format::plain(&note), false).await.is_ok() {
            self.file_notice = Some(Instant::now());
        }
    }

    /// Deletes the chat's messages that are `delete_after` old.
    pub async fn delete_old(&mut self) {
        let Some(after) = self.cfg.delete_after else { return };
        let now = unix_now();
        let due: Vec<Sent> = self.state.to_delete.iter().filter(|s| now - s.at >= after.as_secs() as i64).copied().collect();
        let mut too_late = 0;
        for s in due {
            if self.throttled() {
                break;
            }
            if now - s.at < DELETE_LIMIT_SECS {
                match self.api.delete_message(self.cfg.admin, s.id).await {
                    Ok(_) => {}
                    // already gone (deleted in the app), or not deletable: nothing to retry
                    Err(e @ ApiError::Telegram { .. }) if e.retry_after().is_none() => log::info!("message {} not deleted: {e}", s.id),
                    Err(e) => {
                        self.failed(&e);
                        break;
                    }
                }
            } else {
                too_late += 1;
            }
            self.state.to_delete.retain(|x| x.id != s.id);
            self.dirty = true;
        }
        if too_late > 0 {
            log::warn!("{too_late} message(s) were older than Telegram lets bots delete (48 h); delete them in the app");
        }
    }

    fn poll_failed(&mut self, e: &ApiError) {
        self.polling = false;
        self.stats.last_error = Some((unix_now(), e.to_string()));
        if e.conflict() {
            self.warn_repeated(format!(
                "{e}: another program reads this bot's updates (a second logguard-tg-bot, `logguard-tg-bot pair`, or a webhook)"
            ));
        } else {
            self.warn_repeated(format!("polling Telegram: {e}"));
        }
    }
}

enum Polled {
    Updates(Vec<Update>),
    Failed(ApiError),
}

/// Long polling, in its own task so the outbox is served while a poll waits.
async fn poll(api: Api, mut offset: i64, tx: mpsc::Sender<Polled>) {
    let mut failures = 0u32;
    loop {
        match api.get_updates(offset, api::POLL_SECS).await {
            Ok(updates) => {
                failures = 0;
                if let Some(u) = updates.last() {
                    offset = offset.max(u.update_id + 1);
                }
                if tx.send(Polled::Updates(updates)).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                let stop = e.bad_token();
                let wait = e.retry_after().unwrap_or(if e.conflict() {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(5 << failures.min(5))
                });
                failures += 1;
                if tx.send(Polled::Failed(e)).await.is_err() || stop {
                    return;
                }
                tokio::time::sleep(wait).await;
            }
        }
    }
}

pub async fn run(mut bot: Bot) -> anyhow::Result<()> {
    if let Err(e) = bot.api.set_commands(bot.cfg.admin, &COMMANDS).await {
        log::warn!("setting the command menu: {e}");
    }
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

    let (tx, mut rx) = mpsc::channel(4);
    let poller = tokio::spawn(poll(bot.api.clone(), bot.state.offset, tx));
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    // logguard's alerts; the first tick is now
    let mut alerts = tokio::time::interval(Duration::from_secs(5));
    alerts.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // files (the weekly report)
    let mut files = tokio::time::interval(Duration::from_secs(60));
    files.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cleanup = tokio::time::interval(Duration::from_secs(600));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            polled = rx.recv() => match polled {
                Some(Polled::Updates(updates)) => {
                    bot.polling = true;
                    for u in updates {
                        bot.on_update(u).await;
                    }
                }
                Some(Polled::Failed(e)) if e.bad_token() => break Err(Refused(format!("Telegram refused the token ({e}): check TELEGRAM_TOKEN")).into()),
                Some(Polled::Failed(e)) => bot.poll_failed(&e),
                None => break Err(anyhow::anyhow!("the poller stopped")),
            },
            _ = alerts.tick() => bot.deliver_alerts().await,
            _ = files.tick() => bot.deliver_files().await,
            _ = cleanup.tick() => bot.delete_old().await,
            _ = sigterm.recv() => break Ok(()),
            _ = sigint.recv() => break Ok(()),
        }
        bot.save();
    };
    poller.abort();
    bot.save();
    log::info!("Shutting down");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Chat, User};

    fn msg(chat: i64, kind: &str, from: Option<i64>) -> Message {
        Message {
            message_id: 1,
            from: from.map(|id| User { id, is_bot: false, username: None }),
            chat: Chat { id: chat, kind: kind.into() },
            date: 0,
            text: Some("/status".into()),
        }
    }

    #[test]
    fn only_the_admin_in_private() {
        assert!(from_admin(&msg(42, "private", Some(42)), 42));
        assert!(!from_admin(&msg(43, "private", Some(43)), 42), "someone else");
        assert!(!from_admin(&msg(-100, "group", Some(42)), 42), "the admin, but in a group");
        assert!(!from_admin(&msg(42, "group", Some(42)), 42));
        assert!(!from_admin(&msg(42, "private", None), 42), "no sender");
        let mut bot = msg(42, "private", Some(42));
        bot.from.as_mut().unwrap().is_bot = true;
        assert!(!from_admin(&bot, 42));
    }

    #[test]
    fn sealed_files_have_neutral_names() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-19T06:20:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(sealed_name("abuse-report-2026-10-19.txt", now), "report-2026-10-19.txt.pgp");
        assert_eq!(sealed_name("noext", now), "report-2026-10-19.bin.pgp");
        assert_eq!(sealed_name("x.tar.gz", now), "report-2026-10-19.gz.pgp");
        assert_eq!(sealed_name("weird.t x t", now), "report-2026-10-19.bin.pgp");
        assert!(!FILE_CAPTION.to_lowercase().contains("abuse"));
    }

    #[test]
    fn help_names_the_menu() {
        for (c, _) in COMMANDS {
            assert!(help().contains(&format!("/{c} ")), "{c}");
        }
    }
}
