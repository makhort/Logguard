//! `state.json` (mode 0600, the bot's own): its login on the homeserver, its device's Olm
//! account, the Olm sessions to the admin's devices, the current Megolm session of the room,
//! the bot's self-signing key, and the admin's keys as first seen (the pins). No message
//! text, nothing of the outbox.
//!
//! It holds secrets: whoever reads it can read what the bot sends from now on (and, with the
//! Megolm session, the messages of the current session). The server's root can anyway.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vodozemac::megolm::GroupSessionPickle;
use vodozemac::olm::{AccountPickle, SessionPickle};

#[derive(Default, Serialize, Deserialize)]
pub struct State {
    /// Set by `logguard-matrix-bot login`.
    #[serde(default)]
    pub login: Option<Login>,
    /// The device's identity keys (Ed25519, Curve25519).
    #[serde(default)]
    pub account: Option<AccountPickle>,
    /// Whether the homeserver has the device keys.
    #[serde(default)]
    pub keys_published: bool,
    /// The bot account's cross-signing keys: the master key's public half, the self-signing
    /// key that signs the bot's devices (unpadded base64). The master key's secret half isn't
    /// kept.
    #[serde(default)]
    pub master_key: Option<String>,
    #[serde(default)]
    pub self_signing_key: Option<String>,
    /// Whether this device carries the self-signing key's signature on the homeserver.
    #[serde(default)]
    pub device_signed: bool,
    /// The room with the admin, which the bot made.
    #[serde(default)]
    pub room: Option<String>,
    /// When the admin was last invited (Unix time).
    #[serde(default)]
    pub invited_at: Option<i64>,
    /// Olm sessions to the admin's devices, by the device's Curve25519 key.
    #[serde(default)]
    pub olm: BTreeMap<String, SessionPickle>,
    /// The Megolm session the room's messages are encrypted with.
    #[serde(default)]
    pub outbound: Option<Outbound>,
    /// The admin's master cross-signing key as first seen (unless `ADMIN_MASTER_KEY` pins it).
    #[serde(default)]
    pub admin_master: Option<String>,
    /// The Ed25519 key of each of the admin's devices as first seen, by device id: a device
    /// id that comes back with another key is a different device and gets nothing.
    #[serde(default)]
    pub admin_devices: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Login {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Outbound {
    pub session: GroupSessionPickle,
    /// Unix time it was made.
    pub created: i64,
    /// Messages encrypted with it.
    pub sent: u32,
    /// The devices that have its key: device id → their Curve25519 key.
    #[serde(default)]
    pub shared: BTreeMap<String, String>,
}

impl State {
    /// The saved state; none yet is an empty one. A file that can't be read or parsed is an
    /// error: starting afresh would make a new device and lose the pins.
    pub fn load(path: &Path) -> std::io::Result<State> {
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e),
        }
    }

    /// Written to a temporary file and renamed into place: a crash never leaves half a file.
    /// Synced first: a Megolm ratchet must never step back after a restart, or a message
    /// index would be used twice.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec(self)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::megolm::{GroupSession, SessionConfig};
    use vodozemac::olm::Account;

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("logguard-matrix-bot-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        assert!(State::load(&path).unwrap().login.is_none());
        let account = Account::new();
        let group = GroupSession::new(SessionConfig::version_1());
        let s = State {
            login: Some(Login { user_id: "@bot:x".into(), device_id: "D".into(), access_token: "t".into() }),
            account: Some(account.pickle()),
            room: Some("!r:x".into()),
            outbound: Some(Outbound { session: group.pickle(), created: 1, sent: 2, shared: [("P".into(), "k".into())].into() }),
            ..Default::default()
        };
        s.save(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let back = State::load(&path).unwrap();
        assert_eq!(back.login, s.login);
        assert_eq!(Account::from_pickle(back.account.unwrap()).curve25519_key(), account.curve25519_key());
        assert_eq!(GroupSession::from_pickle(back.outbound.unwrap().session).session_id(), group.session_id());
        assert!(!dir.join("state.json.tmp").exists());
        std::fs::write(&path, "{broken").unwrap();
        assert!(State::load(&path).is_err(), "never silently a new device");
        std::fs::write(&path, "{}").unwrap();
        assert!(State::load(&path).unwrap().login.is_none(), "every field has a default");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
