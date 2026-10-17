//! `state.json`: where the bot is in Telegram's update queue, and which messages it still
//! has to delete (`DELETE_AFTER_HOURS`). Nothing else: no message text, no account names.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// The next update to fetch: the ones before are handled (and confirmed to Telegram
    /// with the next poll).
    #[serde(default)]
    pub offset: i64,
    /// Messages in the admin chat, both directions, to delete once old enough.
    #[serde(default)]
    pub to_delete: Vec<Sent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sent {
    pub id: i64,
    /// Unix time.
    pub at: i64,
}

impl State {
    /// The saved state; a missing or unreadable file starts afresh (Telegram then repeats
    /// the updates of the last 24 hours, and the commands are read-only).
    pub fn load(path: &Path) -> State {
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
                log::warn!("{}: {e}; starting afresh", path.display());
                State::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                log::warn!("{}: {e}; starting afresh", path.display());
                State::default()
            }
        }
    }

    /// Written to a temporary file and renamed into place: a crash never leaves half a file.
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

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("logguard-tg-bot-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        assert_eq!(State::load(&path), State::default());
        let s = State { offset: 123, to_delete: vec![Sent { id: 5, at: 1_760_000_000 }] };
        s.save(&path).unwrap();
        assert_eq!(State::load(&path), s);
        assert!(!dir.join("state.json.tmp").exists());
        std::fs::write(&path, "{broken").unwrap();
        assert_eq!(State::load(&path), State::default());
        std::fs::write(&path, "{}").unwrap();
        assert_eq!(State::load(&path), State::default(), "every field has a default");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
