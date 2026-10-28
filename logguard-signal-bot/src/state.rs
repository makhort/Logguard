//! `state.json`: the admin's safety number as first seen (the pin). signal-cli keeps the
//! account's keys and sessions in its own data directory.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// The safety number with the admin when first seen, digits only (unless
    /// `ADMIN_SAFETY_NUMBER` sets it).
    #[serde(default)]
    pub admin_safety_number: Option<String>,
}

impl State {
    /// The saved state; none yet is an empty one. A file that can't be read is an error:
    /// starting afresh would drop the pin.
    pub fn load(path: &Path) -> std::io::Result<State> {
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e),
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
        let dir = std::env::temp_dir().join(format!("logguard-signal-bot-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        assert_eq!(State::load(&path).unwrap(), State::default());
        let s = State { admin_safety_number: Some("1".repeat(60)) };
        s.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), s);
        std::fs::write(&path, "{broken").unwrap();
        assert!(State::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
