//! The bot: logguard's outbox to the admin's Matrix room, end-to-end encrypted.
//!
//! One room: a direct chat the bot makes with the admin (`ADMIN`), encrypted from its first
//! event. Messages and files go out as Megolm events whose room key reaches only the admin's
//! devices, over Olm. Which devices those are, the homeserver can't decide: with
//! cross-signing, only the devices the admin verified (signed by their self-signing key,
//! under their master key, which the bot pins on first sight or takes from
//! `ADMIN_MASTER_KEY`); without it, every device that signs its own keys, each pinned by id.
//!
//! When end-to-end encryption isn't possible (`E2EE=off`, a changed master key, no verified
//! device, no one-time key to start a session with), a message or file goes out as a file
//! encrypted to the admin's OpenPGP key (`OPENPGP_KEY`) instead; without that key it waits.
//! Nothing is sent to the homeserver in clear but short notices that say so.
//!
//! The bot doesn't read the room (no `/sync`): it takes no commands, and nothing anyone
//! writes there reaches it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};
use tokio::signal::unix::{signal, SignalKind};
use vodozemac::megolm::{GroupSession, SessionConfig as MegolmConfig};
use vodozemac::olm::{Account, Session, SessionConfig as OlmConfig};

use crate::api::{Api, ApiError};
use crate::crypto::{self, Device, MEGOLM, OLM};
use crate::outbox;
use crate::redact::Pseudonyms;
use crate::seal::Recipient;
use crate::servers::ServerNames;
use crate::state::{Login, Outbound, State};

/// A setting or a login that restarting will not fix; the process exits with 78, which the
/// unit does not restart.
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

/// A Megolm session is replaced after this many messages or this long (the spec's defaults),
/// and whenever a device that has its key is no longer trusted.
const ROTATE_MESSAGES: u32 = 100;
const ROTATE_SECS: i64 = 7 * 86400;
/// The admin's device list is asked for again after this.
const KEYS_FRESH: Duration = Duration::from_secs(60);
/// The room (its encryption, the admin's membership) is looked at again after this.
const ROOM_FRESH: Duration = Duration::from_secs(600);
/// An admin who left the room is invited again after this.
const REINVITE_SECS: i64 = 86400;

pub struct Config {
    /// The admin's Matrix user id.
    pub admin: String,
    pub outbox: PathBuf,
    /// Files waiting longer are deleted unsent.
    pub outbox_max_age: Duration,
    /// Alerts waiting longer are dropped unsent (counted in one notice instead).
    pub alert_max_age: Duration,
    pub state_path: PathBuf,
    /// End-to-end encryption on; off sends everything as OpenPGP files.
    pub e2ee: bool,
    /// The admin's master cross-signing key, as set (unpadded base64): it overrides the pin.
    pub admin_master_key: Option<String>,
    /// The admin's OpenPGP key: the fallback when end-to-end encryption isn't possible.
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

/// The body of a fallback file's event: nothing about what is in it.
pub const FILE_CAPTION: &str = "Encrypted (OpenPGP). Open it with OpenKeychain (Android) or iPGMail (iPhone).";

/// An identifier from the homeserver, fit for a log line: printable, at most 80 characters.
pub fn shown(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A fresh transaction id: the homeserver drops a repeated one as a duplicate.
fn txn() -> String {
    format!("lg{}{:016x}", chrono::Utc::now().timestamp_millis(), rand::random::<u64>())
}

/// The name a fallback file goes out under: neutral, with the original's extension (the apps
/// name the decrypted file after it, without `.pgp`).
pub fn sealed_name(kind: &str, original_ext: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> String {
    let ext = original_ext.filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric())).unwrap_or("bin");
    format!("{kind}-{}.{ext}.pgp", now.format("%Y-%m-%d-%H%M%S"))
}

/// How a message can go out right now.
#[derive(Debug)]
pub enum Route {
    /// Megolm, to these devices of the admin.
    E2e(Vec<Device>),
    /// As an OpenPGP file, for this reason.
    Pgp(String),
}

/// What became of one message or file.
#[derive(Debug, PartialEq)]
enum Outcome {
    Sent,
    /// No way to send it now (no route): it stays in the outbox.
    Waits,
}

/// The Megolm session in use, live.
struct Live {
    session: GroupSession,
    created: i64,
    sent: u32,
    shared: BTreeMap<String, String>,
}

#[derive(Default)]
struct Stats {
    alerts: u64,
    files: u64,
    fallbacks: u64,
}

pub struct Bot {
    pub api: Api,
    pub cfg: Config,
    pub state: State,
    pub login: Login,
    account: Account,
    olm: BTreeMap<String, Session>,
    outbound: Option<Live>,
    stats: Stats,
    /// Nothing is sent before this (rate limited, or after a failure).
    not_before: Option<Instant>,
    /// The last warning logged and when: repeated failures are logged every 10 minutes.
    last_warning: Option<(String, Instant)>,
    /// The admin's trusted devices (or why there are none), and when asked.
    keys: Option<(Instant, Result<Vec<Device>, String>)>,
    room_checked: Option<Instant>,
    room_encrypted: bool,
    /// When a room was last made: at most one an hour.
    room_made: Option<Instant>,
    /// Notices in the room (why messages come as files), by kind, when last sent.
    notices: BTreeMap<&'static str, Instant>,
    /// Set when the homeserver no longer knows the access token: the service stops (78).
    pub fatal: Option<String>,
}

impl Bot {
    /// The bot as `login` left it in `state`.
    pub fn new(api: Api, cfg: Config, mut state: State) -> Result<Bot, Refused> {
        let login = state.login.clone().ok_or_else(|| Refused("not logged in: run `logguard-matrix-bot login` first".into()))?;
        let account = state
            .account
            .take()
            .map(Account::from_pickle)
            .ok_or_else(|| Refused("no device keys: run `logguard-matrix-bot login` again".into()))?;
        let olm = std::mem::take(&mut state.olm).into_iter().map(|(k, p)| (k, Session::from_pickle(p))).collect();
        let outbound = state.outbound.take().map(|o| Live {
            session: GroupSession::from_pickle(o.session),
            created: o.created,
            sent: o.sent,
            shared: o.shared,
        });
        if let Some(pin) = &cfg.admin_master_key {
            if state.admin_master.as_ref() != Some(pin) {
                state.admin_master = Some(pin.clone());
            }
        }
        let api = api.with_token(login.access_token.clone());
        let mut bot = Bot {
            api,
            cfg,
            state,
            login,
            account,
            olm,
            outbound,
            stats: Stats::default(),
            not_before: None,
            last_warning: None,
            keys: None,
            room_checked: None,
            room_encrypted: false,
            room_made: None,
            notices: BTreeMap::new(),
            fatal: None,
        };
        bot.save();
        Ok(bot)
    }

    /// The device's Ed25519 key, as clients show it in the list of sessions.
    pub fn fingerprint(&self) -> String {
        self.account.ed25519_key().to_base64()
    }

    /// Writes the state, the live sessions included. A failure is logged: it is retried with
    /// the next change.
    pub fn save(&mut self) {
        self.state.account = Some(self.account.pickle());
        self.state.olm = self.olm.iter().map(|(k, s)| (k.clone(), s.pickle())).collect();
        self.state.outbound = self.outbound.as_ref().map(|o| Outbound {
            session: o.session.pickle(),
            created: o.created,
            sent: o.sent,
            shared: o.shared.clone(),
        });
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

    /// Remembers a failed call: how long to hold off, or that the login is gone.
    fn failed(&mut self, e: &ApiError) {
        if e.unknown_token() {
            self.fatal = Some(format!("the homeserver no longer knows the bot's login ({e}): run `logguard-matrix-bot login` again"));
            return;
        }
        if e.permanent() {
            return;
        }
        let pause = e.retry_after().unwrap_or(match e {
            ApiError::Transport(_) => Duration::from_secs(30),
            ApiError::Matrix { .. } => Duration::from_secs(60),
        });
        self.not_before = Some(Instant::now() + pause);
    }

    /// Checks the login, publishes the device keys if `login` couldn't, and sets up the room.
    pub async fn prepare(&mut self) -> Result<(), ApiError> {
        let me = self.api.whoami().await?;
        if me.user_id != self.login.user_id || me.device_id.as_deref().is_some_and(|d| d != self.login.device_id) {
            self.fatal = Some(format!(
                "the access token belongs to {} (device {}), not to the bot's device: run `logguard-matrix-bot login` again",
                shown(&me.user_id),
                shown(me.device_id.as_deref().unwrap_or("?"))
            ));
            return Ok(());
        }
        if !self.state.keys_published {
            self.publish_keys().await?;
        }
        self.check_room().await
    }

    pub async fn publish_keys(&mut self) -> Result<(), ApiError> {
        let keys = crypto::device_keys(&self.account, &self.login.user_id, &self.login.device_id);
        self.api.upload_keys(&json!({ "device_keys": keys })).await?;
        self.state.keys_published = true;
        self.save();
        log::info!("published the device keys of {}", shown(&self.login.device_id));
        Ok(())
    }

    /// The room with the admin: made (encrypted, the admin invited) when there is none.
    async fn room(&mut self) -> Result<String, ApiError> {
        if let Some(r) = &self.state.room {
            return Ok(r.clone());
        }
        if self.room_made.is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
            return Err(ApiError::Transport("the room was made less than an hour ago and lost again; waiting".into()));
        }
        let body = json!({
            "preset": "private_chat",
            "is_direct": true,
            "invite": [self.cfg.admin],
            "name": "logguard",
            "topic": "logguard's admin messages: alerts, the daily digest, the weekly abuse report",
            "initial_state": [{ "type": "m.room.encryption", "state_key": "", "content": { "algorithm": MEGOLM } }],
        });
        self.room_made = Some(Instant::now());
        let room = self.api.create_room(&body).await?;
        log::info!("made the room {} and invited {}", shown(&room), self.cfg.admin);
        self.state.room = Some(room.clone());
        self.state.invited_at = Some(unix_now());
        // a Megolm session belongs to one room
        self.outbound = None;
        self.room_encrypted = true;
        self.room_checked = Some(Instant::now());
        self.save();
        Ok(room)
    }

    /// Forgets a room the bot is no longer in: the next message makes a new one.
    fn lost_room(&mut self, e: &ApiError) {
        if let Some(room) = self.state.room.take() {
            log::warn!("the room {} is gone for the bot ({e}); a new one will be made", shown(&room));
        }
        self.outbound = None;
        self.room_checked = None;
        self.save();
    }

    /// Looks at the room: still encrypted, and the admin in it (invited again a day after
    /// leaving it).
    pub async fn check_room(&mut self) -> Result<(), ApiError> {
        let room = self.room().await?;
        let encryption = match self.api.state(&room, "m.room.encryption", "").await {
            Ok(e) => e,
            Err(e) if e.not_in_room() => {
                self.lost_room(&e);
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        self.room_encrypted = encryption.as_ref().and_then(|c| c.get("algorithm")).and_then(Value::as_str) == Some(MEGOLM);
        if !self.room_encrypted {
            self.warn_repeated(format!("the room {} isn't encrypted with Megolm: messages go out as OpenPGP files", shown(&room)));
        }
        let member = self.api.state(&room, "m.room.member", &self.cfg.admin).await?;
        let membership = member.as_ref().and_then(|m| m.get("membership")).and_then(Value::as_str).unwrap_or("none").to_string();
        match membership.as_str() {
            "join" | "invite" => {}
            "ban" => self.warn_repeated(format!(
                "{} is banned from the room {}: unban them (or delete state.json's room)",
                self.cfg.admin,
                shown(&room)
            )),
            _ if self.state.invited_at.is_some_and(|t| unix_now() - t < REINVITE_SECS) => {}
            _ => {
                self.api.invite(&room, &self.cfg.admin).await?;
                log::info!("invited {} to the room again (they had left it)", self.cfg.admin);
                self.state.invited_at = Some(unix_now());
                self.save();
            }
        }
        self.room_checked = Some(Instant::now());
        Ok(())
    }

    /// The admin's devices to share room keys with, checked against the pins; or why there
    /// are none. Updates the pins.
    pub fn trusted(&mut self, reply: &Value) -> Result<Vec<Device>, String> {
        let admin = self.cfg.admin.clone();
        let keys = crypto::user_keys(reply, &admin);
        for p in &keys.problems {
            log::warn!("{admin}'s keys: {p}");
        }
        let master = keys.master.map(|k| k.to_base64());
        let cross_signed = match (&self.state.admin_master, &master) {
            (Some(pin), Some(m)) if pin == m => true,
            (Some(pin), Some(m)) => {
                return Err(format!(
                    "{admin}'s master cross-signing key changed: it was {pin}, now it is {m}. If you reset your \
                     cross-signing yourself, set ADMIN_MASTER_KEY={m} in config.env and restart the bot"
                ))
            }
            (Some(pin), None) => {
                return Err(format!("{admin} has no master cross-signing key any more (it was {pin}); set ADMIN_MASTER_KEY to the new one"))
            }
            (None, Some(m)) => {
                log::info!("pinned {admin}'s master cross-signing key {m}: only devices it verifies get the room keys");
                self.state.admin_master = Some(m.clone());
                true
            }
            (None, None) => {
                self.warn_repeated(format!(
                    "{admin} has no cross-signing keys: every device of the account that signs its own keys gets the room keys"
                ));
                false
            }
        };
        let mut out = Vec::new();
        for d in keys.devices {
            if cross_signed && !keys.cross_signed.contains(&d.device_id) {
                continue;
            }
            let ed = d.ed25519.to_base64();
            match self.state.admin_devices.get(&d.device_id) {
                Some(pin) if *pin != ed => {
                    log::warn!("{admin}'s device {} came back with another Ed25519 key: left out", shown(&d.device_id));
                    continue;
                }
                Some(_) => {}
                None => {
                    log::info!("new device of {admin}: {} (Ed25519 {ed})", shown(&d.device_id));
                    self.state.admin_devices.insert(d.device_id.clone(), ed);
                }
            }
            out.push(d);
        }
        if out.is_empty() && cross_signed {
            return Err(format!("none of {admin}'s devices is verified (cross-signed): verify your session in your Matrix client"));
        }
        Ok(out)
    }

    async fn admin_devices(&mut self) -> Result<Result<Vec<Device>, String>, ApiError> {
        if let Some((t, keys)) = &self.keys {
            if t.elapsed() < KEYS_FRESH {
                return Ok(keys.clone());
            }
        }
        let reply = self.api.query_keys(&[&self.cfg.admin]).await?;
        let keys = self.trusted(&reply);
        self.save();
        self.keys = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    /// How messages can go out now.
    pub async fn route(&mut self) -> Result<Route, ApiError> {
        if !self.cfg.e2ee {
            return Ok(Route::Pgp("end-to-end encryption is off (E2EE=off)".into()));
        }
        if self.state.room.is_none() || self.room_checked.is_none_or(|t| t.elapsed() >= ROOM_FRESH) {
            self.check_room().await?;
        }
        if self.state.room.is_none() {
            return Err(ApiError::Transport("no room yet".into()));
        }
        if !self.room_encrypted {
            return Ok(Route::Pgp("the room isn't end-to-end encrypted".into()));
        }
        Ok(match self.admin_devices().await? {
            Err(why) => Route::Pgp(why),
            Ok(d) if d.is_empty() => Route::Pgp(format!("{} has no device that can take room keys", self.cfg.admin)),
            Ok(d) => Route::E2e(d),
        })
    }

    /// Makes sure the room's Megolm session key is on `devices` (a new session when one that
    /// had it is no longer trusted, or the session is old); returns how many have it.
    pub async fn share(&mut self, devices: &[Device]) -> Result<usize, ApiError> {
        let now = unix_now();
        let trusted: BTreeMap<String, String> = devices.iter().map(|d| (d.device_id.clone(), d.curve25519.to_base64())).collect();
        let rotate = match &self.outbound {
            None => true,
            Some(o) => {
                o.sent >= ROTATE_MESSAGES || now - o.created >= ROTATE_SECS || o.shared.iter().any(|(id, k)| trusted.get(id) != Some(k))
            }
        };
        if rotate {
            let session = GroupSession::new(MegolmConfig::version_1());
            log::info!("new Megolm session {}", session.session_id());
            self.outbound = Some(Live { session, created: now, sent: 0, shared: BTreeMap::new() });
            self.save();
        }
        let shared = &self.outbound.as_ref().map(|o| o.shared.clone()).unwrap_or_default();
        let missing: Vec<&Device> = devices.iter().filter(|d| shared.get(&d.device_id) != Some(&d.curve25519.to_base64())).collect();
        if missing.is_empty() {
            return Ok(shared.len());
        }
        let admin = self.cfg.admin.clone();
        let need: Vec<&str> =
            missing.iter().filter(|d| !self.olm.contains_key(&d.curve25519.to_base64())).map(|d| d.device_id.as_str()).collect();
        if !need.is_empty() {
            let reply = self.api.claim_keys(&admin, &need).await?;
            for d in missing.iter().filter(|d| need.contains(&d.device_id.as_str())) {
                let Some(otk) = crypto::claimed_key(&reply, &admin, d) else {
                    self.warn_repeated(format!("{admin}'s device {}: no signed one-time key to start a session with", shown(&d.device_id)));
                    continue;
                };
                match self.account.create_outbound_session(OlmConfig::version_1(), d.curve25519, otk) {
                    Ok(s) => {
                        self.olm.insert(d.curve25519.to_base64(), s);
                    }
                    Err(e) => log::warn!("{admin}'s device {}: no Olm session: {e}", shown(&d.device_id)),
                }
            }
        }
        let room = self.state.room.clone().unwrap_or_default();
        let Some(live) = &self.outbound else { return Ok(0) };
        let (session_id, session_key) = (live.session.session_id(), live.session.session_key().to_base64());
        let mut messages = serde_json::Map::new();
        let mut sent_to = Vec::new();
        for d in &missing {
            let curve = d.curve25519.to_base64();
            let Some(olm) = self.olm.get_mut(&curve) else { continue };
            let payload = json!({
                "type": "m.room_key",
                "content": { "algorithm": MEGOLM, "room_id": room, "session_id": session_id, "session_key": session_key },
                "sender": self.login.user_id,
                "sender_device": self.login.device_id,
                "keys": { "ed25519": self.account.ed25519_key().to_base64() },
                "recipient": admin,
                "recipient_keys": { "ed25519": d.ed25519.to_base64() },
            });
            let message = match olm.encrypt(payload.to_string()) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("{admin}'s device {}: Olm encryption failed: {e}", shown(&d.device_id));
                    continue;
                }
            };
            messages.insert(
                d.device_id.clone(),
                json!({
                    "algorithm": OLM,
                    "sender_key": self.account.curve25519_key().to_base64(),
                    "ciphertext": { curve.clone(): message },
                }),
            );
            sent_to.push((d.device_id.clone(), curve));
        }
        // the Olm ratchets moved: saved before anything leaves
        self.save();
        if !sent_to.is_empty() {
            self.api.send_to_device("m.room.encrypted", &txn(), &json!({ admin.clone(): messages })).await?;
            if let Some(live) = &mut self.outbound {
                for (id, curve) in &sent_to {
                    live.shared.insert(id.clone(), curve.clone());
                }
            }
            log::info!(
                "room key of session {session_id} sent to {}",
                sent_to.iter().map(|(id, _)| shown(id)).collect::<Vec<_>>().join(", ")
            );
            self.save();
        }
        Ok(self.outbound.as_ref().map_or(0, |o| o.shared.keys().filter(|id| trusted.contains_key(*id)).count()))
    }

    /// One `m.room.message` (its `content`) as a Megolm event; the session key must be
    /// shared ([`Bot::share`]).
    async fn send_megolm(&mut self, content: Value) -> Result<(), ApiError> {
        let room = self.state.room.clone().unwrap_or_default();
        let Some(live) = &mut self.outbound else { return Err(ApiError::Transport("no Megolm session".into())) };
        let plaintext = json!({ "type": "m.room.message", "content": content, "room_id": room });
        let message = live.session.encrypt(plaintext.to_string());
        live.sent += 1;
        let event = json!({
            "algorithm": MEGOLM,
            "sender_key": self.account.curve25519_key().to_base64(),
            "device_id": self.login.device_id,
            "session_id": live.session.session_id(),
            "ciphertext": message.to_base64(),
        });
        // the ratchet moved: saved before the message leaves, so no index is used twice
        self.save();
        match self.api.send_event(&room, "m.room.encrypted", &txn(), &event).await {
            Err(e) if e.not_in_room() => {
                self.lost_room(&e);
                Err(e)
            }
            other => other.map(|_| ()),
        }
    }

    /// A short notice in the room, in clear, at most once a day per kind (it says why
    /// messages come as files, or wait).
    async fn notice(&mut self, kind: &'static str, text: String) {
        if self.notices.get(kind).is_some_and(|t| t.elapsed() < Duration::from_secs(86400)) {
            return;
        }
        let Some(room) = self.state.room.clone() else { return };
        let content = json!({ "msgtype": "m.notice", "body": format!("logguard-matrix-bot: {text}") });
        match self.api.send_event(&room, "m.room.message", &txn(), &content).await {
            Ok(_) => {
                self.notices.insert(kind, Instant::now());
            }
            Err(e) => log::warn!("notice not sent: {e}"),
        }
    }

    /// `data` as a file encrypted to the admin's OpenPGP key, in a plain event; `Waits` when
    /// there is no usable key.
    async fn send_sealed(&mut self, data: Vec<u8>, name: &str, why: &str) -> Result<Outcome, ApiError> {
        let now = unix_now() as u32;
        let key_problem = match &self.cfg.recipient {
            None => Some("OPENPGP_KEY is not set".to_string()),
            Some(r) => r.check(now).err().map(|e| format!("the OpenPGP key {e}")),
        };
        if let Some(p) = key_problem {
            self.warn_repeated(format!("outbox: messages wait: {why}, and {p}"));
            let days = self.cfg.outbox_max_age.as_secs() / 86400;
            let text = format!(
                "messages can't be sent: {why}, and {p} on the server. Alerts wait {} h, files {days} days.",
                self.cfg.alert_max_age.as_secs() / 3600
            );
            self.notice("waiting", text).await;
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
        self.notice("fallback", format!("{why}. Messages come as files encrypted to your OpenPGP key until that changes.")).await;
        let room = self.room().await?;
        let size = sealed.len();
        let mxc = self.api.upload(sealed, name, "application/pgp-encrypted").await?;
        let content = json!({
            "msgtype": "m.file",
            "body": FILE_CAPTION,
            "filename": name,
            "url": mxc,
            "info": { "mimetype": "application/pgp-encrypted", "size": size },
        });
        match self.api.send_event(&room, "m.room.message", &txn(), &content).await {
            Err(e) if e.not_in_room() => {
                self.lost_room(&e);
                Err(e)
            }
            Err(e) => Err(e),
            Ok(_) => {
                self.stats.fallbacks += 1;
                Ok(Outcome::Sent)
            }
        }
    }

    /// One alert, end-to-end encrypted if possible, else as an OpenPGP file.
    async fn send_alert(&mut self, text: &str) -> Result<Outcome, ApiError> {
        let why = match self.route().await? {
            Route::E2e(devices) => {
                if self.share(&devices).await? > 0 {
                    self.send_megolm(json!({ "msgtype": "m.text", "body": text })).await?;
                    return Ok(Outcome::Sent);
                }
                format!("none of {}'s trusted devices could get the room key", self.cfg.admin)
            }
            Route::Pgp(why) => why,
        };
        let name = sealed_name("message", Some("txt"), chrono::Utc::now());
        self.send_sealed(text.as_bytes().to_vec(), &name, &why).await
    }

    /// One file, as an encrypted attachment if possible, else as an OpenPGP file.
    async fn send_file(&mut self, name: &str, data: Vec<u8>) -> Result<Outcome, ApiError> {
        let why = match self.route().await? {
            Route::E2e(devices) => {
                if self.share(&devices).await? > 0 {
                    let (ciphertext, mut file) = crypto::encrypt_attachment(&data);
                    // the homeserver sees an encrypted blob under a neutral name
                    file["url"] = Value::String(self.api.upload(ciphertext, "file", "application/octet-stream").await?);
                    let content = json!({
                        "msgtype": "m.file",
                        "body": name,
                        "filename": name,
                        "file": file,
                        "info": { "mimetype": "text/plain", "size": data.len() },
                    });
                    self.send_megolm(content).await?;
                    return Ok(Outcome::Sent);
                }
                format!("none of {}'s trusted devices could get the room key", self.cfg.admin)
            }
            Route::Pgp(why) => why,
        };
        let ext = std::path::Path::new(name).extension().and_then(|e| e.to_str());
        self.send_sealed(data, &sealed_name("report", ext, chrono::Utc::now()), &why).await
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
                // the same request would be refused forever, and hold up every alert after it
                Err(e) if e.permanent() => {
                    log::error!("outbox: alert {name} dropped: the homeserver refuses it ({e})");
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
                Err(e) if e.permanent() => {
                    log::error!("outbox: {name} dropped: the homeserver refuses it ({e})");
                    let _ = std::fs::remove_file(&path);
                    self.notice("file-dropped", format!("a file was dropped: the homeserver refused it ({e}).")).await;
                }
                Err(e) => {
                    self.failed(&e);
                    self.warn_repeated(format!("outbox: {name} not sent ({e}); trying again later"));
                    return;
                }
            }
        }
    }

    /// One line for the log: what was sent since the start.
    pub fn summary(&self) -> String {
        format!("sent {} alert(s) and {} file(s), {} of them as OpenPGP files", self.stats.alerts, self.stats.files, self.stats.fallbacks)
    }
}

/// Waits for the homeserver: retries while it can't be reached, gives up (exit 78) when it
/// no longer knows the login.
pub async fn connect(bot: &mut Bot) -> anyhow::Result<()> {
    let mut wait = 5;
    loop {
        match bot.prepare().await {
            Ok(()) => break,
            Err(e) if e.unknown_token() => {
                bot.failed(&e);
                break;
            }
            Err(e) => {
                log::warn!("homeserver: {e}; trying again in {wait} s");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                wait = (wait * 2).min(300);
            }
        }
    }
    match bot.fatal.take() {
        Some(f) => Err(Refused(f).into()),
        None => Ok(()),
    }
}

pub async fn run(mut bot: Bot) -> anyhow::Result<()> {
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
    let mut room = tokio::time::interval(ROOM_FRESH);
    room.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    room.tick().await; // connect() just looked
    let result = loop {
        tokio::select! {
            _ = alerts.tick() => bot.deliver_alerts().await,
            _ = files.tick() => bot.deliver_files().await,
            _ = room.tick() => {
                if !bot.throttled() {
                    if let Err(e) = bot.check_room().await {
                        bot.failed(&e);
                        bot.warn_repeated(format!("looking at the room: {e}"));
                    }
                }
            }
            _ = sigterm.recv() => break Ok(()),
            _ = sigint.recv() => break Ok(()),
        }
        if let Some(f) = bot.fatal.take() {
            break Err(Refused(f).into());
        }
    };
    bot.save();
    log::info!("Shutting down; {}", bot.summary());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_files_have_neutral_names() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-19T06:20:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(sealed_name("report", Some("txt"), now), "report-2026-10-19-062000.txt.pgp");
        assert_eq!(sealed_name("message", None, now), "message-2026-10-19-062000.bin.pgp");
        assert_eq!(sealed_name("report", Some("t x"), now), "report-2026-10-19-062000.bin.pgp");
        assert!(!FILE_CAPTION.to_lowercase().contains("abuse"));
    }

    #[test]
    fn identifiers_are_shown_safely() {
        assert_eq!(shown("DEV\nINFO - forged"), "DEVINFO - forged");
        assert_eq!(shown(&"x".repeat(200)).len(), 80);
    }
}
