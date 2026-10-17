//! Which OMEMO keys the bot trusts: fingerprints pinned in a text file on the server.
//!
//! ```text
//! # jid  fingerprint (as Conversations shows it; spaces and case don't matter)
//! admin@example.org  1a2b3c4d 5e6f7a8b 9c0d1e2f 3a4b5c6d 7e8f9a0b 1c2d3e4f 5a6b7c8d 9e0f1a2b
//! ```
//!
//! A JID with pins is trusted only on those keys. A JID without any is trusted on any
//! key ("blind trust"), like Conversations does before you verify anything, unless the
//! bot runs with `OMEMO_TRUST=pinned`.
//!
//! Whoever can write the file decides whom the bot trusts, so it must be writable by its
//! owner only, and that owner must be root or the bot's user.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Trust {
    Pinned,
    Blind,
    Untrusted,
}

impl Trust {
    pub fn trusted(self) -> bool {
        self != Trust::Untrusted
    }
}

#[derive(Debug, Default)]
pub struct Pins {
    pins: HashMap<String, HashSet<String>>,
    /// The file could not be trusted: nothing is.
    closed: bool,
    /// JIDs without pins are not trusted either.
    strict: bool,
}

/// 64 lowercase hex digits; also takes libsignal's 66 with the 05 type byte.
pub fn normalize(fp: &str) -> Option<String> {
    let hex: String = fp.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
    let hex = match hex.len() {
        66 if hex.starts_with("05") => hex[2..].to_string(),
        _ => hex,
    };
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// Groups of eight, as Conversations displays fingerprints.
pub fn pretty(fp: &str) -> String {
    fp.as_bytes().chunks(8).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
}

impl Pins {
    /// A missing file means no pins. Lines that don't parse are reported and skipped. A
    /// file that can't be read, or that others could have changed, trusts nothing.
    pub fn load(path: &Path, strict: bool) -> Pins {
        let closed = || Pins { closed: true, ..Pins::default() };
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Pins { strict, ..Pins::default() },
            Err(e) => {
                log::error!("{}: {e}; trusting no OMEMO key", path.display());
                return closed();
            }
        };
        // SAFETY: geteuid has no preconditions and cannot fail
        let me = unsafe { libc::geteuid() };
        if meta.mode() & 0o022 != 0 || (meta.uid() != 0 && meta.uid() != me) {
            log::error!(
                "{}: writable by others than its owner, or owned by another user; trusting no OMEMO key. Fix: chown root {0} && chmod 644 {0}",
                path.display()
            );
            return closed();
        }
        match std::fs::read_to_string(path) {
            Ok(text) => Pins { strict, ..Self::parse(&text, &path.display().to_string()) },
            Err(e) => {
                log::error!("{}: {e}; trusting no OMEMO key", path.display());
                closed()
            }
        }
    }

    fn parse(text: &str, name: &str) -> Pins {
        let mut pins: HashMap<String, HashSet<String>> = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((jid, fp)) = line.split_once(char::is_whitespace) else {
                if !line.is_empty() {
                    log::warn!("{name}:{}: expected `<jid> <fingerprint>`", n + 1);
                }
                continue;
            };
            match normalize(fp) {
                Some(fp) => {
                    pins.entry(jid.to_lowercase()).or_default().insert(fp);
                }
                None => log::warn!("{name}:{}: not a fingerprint: {}", n + 1, fp.trim()),
            }
        }
        Pins { pins, ..Pins::default() }
    }

    pub fn check(&self, jid: &str, fingerprint: &str) -> Trust {
        if self.closed {
            return Trust::Untrusted;
        }
        match self.pins.get(jid) {
            None if self.strict => Trust::Untrusted,
            None => Trust::Blind,
            Some(fps) if fps.contains(fingerprint) => Trust::Pinned,
            Some(_) => Trust::Untrusted,
        }
    }

    pub fn has_pins(&self, jid: &str) -> bool {
        self.pins.contains_key(jid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";

    #[test]
    fn parses_conversations_style_fingerprints() {
        let pins = Pins::parse(
            "# comment\n\nAdmin@Example.org 1A2B3C4D 5E6F7A8B 9C0D1E2F 3A4B5C6D 7E8F9A0B 1C2D3E4F 5A6B7C8D 9E0F1A2B # phone\n\
             admin@example.org 05ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n\
             bob@example.org not-hex\n\
             junk\n",
            "t",
        );
        assert_eq!(pins.check("admin@example.org", FP), Trust::Pinned);
        assert_eq!(pins.check("admin@example.org", &"f".repeat(64)), Trust::Pinned);
        assert_eq!(pins.check("admin@example.org", &"0".repeat(64)), Trust::Untrusted);
        assert_eq!(pins.check("carol@example.org", FP), Trust::Blind);
        // a line that didn't parse pins nothing
        assert_eq!(pins.check("bob@example.org", FP), Trust::Blind);
        assert!(pins.has_pins("admin@example.org"));
    }

    #[test]
    fn missing_file_means_blind_trust() {
        let pins = Pins::load(Path::new("/nonexistent/omemo-trust.txt"), false);
        assert_eq!(pins.check("a@b", FP), Trust::Blind);
        let pins = Pins::load(Path::new("/nonexistent/omemo-trust.txt"), true);
        assert_eq!(pins.check("a@b", FP), Trust::Untrusted);
    }

    #[test]
    fn a_file_others_can_write_trusts_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("omemo-trust.txt");
        std::fs::write(&path, format!("a@b {FP}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(Pins::load(&path, false).check("a@b", FP), Trust::Pinned);
        assert_eq!(Pins::load(&path, false).check("c@d", FP), Trust::Blind);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(Pins::load(&path, false).check("a@b", FP), Trust::Untrusted);
        assert_eq!(Pins::load(&path, false).check("c@d", FP), Trust::Untrusted);
    }

    #[test]
    fn pretty_groups() {
        assert_eq!(pretty(FP), "1a2b3c4d 5e6f7a8b 9c0d1e2f 3a4b5c6d 7e8f9a0b 1c2d3e4f 5a6b7c8d 9e0f1a2b");
        assert_eq!(normalize(&pretty(FP)).unwrap(), FP);
    }
}
