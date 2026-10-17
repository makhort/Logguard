//! Files for the admin (the weekly abuse report from logguard), sent as OMEMO media
//! (XEP-0454): encrypted here with AES-256-GCM, uploaded with HTTP File Upload (XEP-0363),
//! and announced in an OMEMO message whose body is the `aesgcm://` URL carrying the key.
//!
//! The outbox is a directory another program (logguard's weekly timer, as root) writes
//! into: under a dot name first, then renamed. Files are deleted once sent, or when they
//! could not be sent within the retention time.
//!
//! logguard's admin alerts come through the same directory as messages, `alert-*.msg`
//! (`To:` and `Subject:` lines, a blank line, the text), sent as OMEMO text. logguard sends
//! one the bot doesn't take within its grace time itself, unencrypted, so the bot claims
//! each by renaming it to `.<name>.sending` first, puts it back if sending fails, and renames
//! one for anyone but the admin to `.<name>.rejected` (logguard's module `botbox` has the
//! other side).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::omemo::crypto::random;

/// Larger files are left alone (and deleted when they expire): a weekly report is ~50 KB.
pub const MAX_FILE: u64 = 20 * 1024 * 1024;

/// What is in the outbox: files to send now (oldest name first), and files older than the
/// retention time, to delete unsent.
#[derive(Debug, Default, PartialEq)]
pub struct Pending {
    pub ready: Vec<PathBuf>,
    pub expired: Vec<PathBuf>,
}

/// logguard's alert messages: `alert-*.msg`.
pub fn is_message(name: &str) -> bool {
    name.starts_with("alert-") && name.ends_with(".msg")
}

/// The name a message has while the bot sends it, or after it refused it.
pub fn claimed(path: &Path, state: &str) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.{state}"))
}

/// The messages waiting (oldest first): regular files only.
pub fn scan_messages(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let is_file = std::fs::symlink_metadata(entry.path()).is_ok_and(|m| m.file_type().is_file());
        if is_file && entry.file_name().to_str().is_some_and(is_message) {
            v.push(entry.path());
        }
    }
    v.sort();
    Ok(v)
}

/// Messages left half-sent by a bot that stopped (`.alert-*.msg.sending`), put back to be
/// sent again. Returns how many.
pub fn recover(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(base) = name.to_str().and_then(|n| n.strip_prefix('.')?.strip_suffix(".sending")) else { continue };
        if is_message(base) && std::fs::rename(entry.path(), dir.join(base)).is_ok() {
            n += 1;
        }
    }
    n
}

/// An alert message: (recipient, text). The subject is the text's first line already.
pub fn parse_message(text: &str) -> Option<(String, String)> {
    let (head, body) = text.split_once("\n\n")?;
    let mut to = None;
    for line in head.lines() {
        match line.split_once(": ") {
            Some(("To", v)) => to = Some(v.trim().to_lowercase()),
            Some(("Subject", _)) => {}
            _ => return None,
        }
    }
    Some((to.filter(|t| !t.is_empty())?, body.to_string()))
}

/// Files to upload: regular files only (no links, no directories), not dot files (still
/// being written) and not alert messages.
pub fn scan(dir: &Path, max_age: Duration, now: SystemTime) -> std::io::Result<Pending> {
    let mut p = Pending::default();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { continue };
        if name.starts_with('.') || is_message(name) || !meta.file_type().is_file() {
            continue;
        }
        let age = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).unwrap_or_default();
        if age > max_age || meta.len() > MAX_FILE {
            p.expired.push(entry.path());
        } else {
            p.ready.push(entry.path());
        }
    }
    p.ready.sort();
    p.expired.sort();
    Ok(p)
}

/// A file encrypted as XEP-0454 says: AES-256-GCM, the 16-byte tag after the ciphertext,
/// a 12-byte IV (the length every client reads; Conversations also takes legacy 16).
pub struct Sealed {
    pub data: Vec<u8>,
    pub iv: [u8; 12],
    pub key: [u8; 32],
}

pub fn seal(plain: &[u8]) -> Sealed {
    let (iv, key) = (random::<12>(), random::<32>());
    let data = Aes256Gcm::new(&key.into()).encrypt(Nonce::from_slice(&iv), plain).expect("AES-GCM encryption of a buffer cannot fail");
    Sealed { data, iv, key }
}

/// The message body for an uploaded file: its HTTPS download URL with the scheme
/// `aesgcm` and the IV and key, in hex, as the fragment. The server never sees the
/// fragment; the body travels OMEMO-encrypted.
pub fn aesgcm_url(get_url: &str, iv: &[u8; 12], key: &[u8; 32]) -> Result<String, String> {
    let url = url::Url::parse(get_url).map_err(|e| format!("upload URL {get_url}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("upload URL {get_url} is not https"));
    }
    if url.fragment().is_some() {
        return Err(format!("upload URL {get_url} already has a fragment"));
    }
    let hex: String = iv.iter().chain(key).map(|b| format!("{b:02x}")).collect();
    // from the parsed URL, not the server's text: the parser trims blanks and lowercases
    // the scheme, so cutting "https" off the raw text could cut the wrong characters
    let normalized = url.as_str();
    Ok(format!("aesgcm{}#{hex}", &normalized["https".len()..]))
}

/// The first lines of a text report ("Abuse report from …", "Period: …"), for the message
/// that comes with the file.
pub fn summary(text: &str) -> String {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).take(2).collect::<Vec<_>>().join("\n").chars().take(400).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(s: &Sealed) -> Vec<u8> {
        Aes256Gcm::new(&s.key.into()).decrypt(Nonce::from_slice(&s.iv), s.data.as_slice()).unwrap()
    }

    #[test]
    fn sealed_files_open_with_the_url_fragment() {
        let report = b"Abuse report from xmpp and vpn\nPeriod: ...\n".repeat(50);
        let s = seal(&report);
        assert_eq!(s.data.len(), report.len() + 16, "ciphertext then 16-byte tag");
        assert_eq!(open(&s), report);
        let mut bad = Sealed { data: s.data.clone(), ..s };
        *bad.data.last_mut().unwrap() ^= 1;
        assert!(Aes256Gcm::new(&bad.key.into()).decrypt(Nonce::from_slice(&bad.iv), bad.data.as_slice()).is_err());
        assert_ne!(seal(&report).key, seal(&report).key, "a new key per file");

        let url = aesgcm_url("https://upload.example.org:5443/upload/ab12/cd34/abuse-report-2026-10-19.txt", &s.iv, &s.key).unwrap();
        let (base, fragment) = url.split_once('#').unwrap();
        assert_eq!(base, "aesgcm://upload.example.org:5443/upload/ab12/cd34/abuse-report-2026-10-19.txt");
        assert_eq!(fragment.len(), 88, "24 hex digits of IV, 64 of key");
        let bytes: Vec<u8> = (0..fragment.len()).step_by(2).map(|i| u8::from_str_radix(&fragment[i..i + 2], 16).unwrap()).collect();
        let back = Sealed { data: s.data.clone(), iv: bytes[..12].try_into().unwrap(), key: bytes[12..].try_into().unwrap() };
        assert_eq!(open(&back), report);
    }

    #[test]
    fn only_https_urls_without_fragment() {
        let (iv, key) = ([1; 12], [2; 32]);
        assert!(aesgcm_url("http://example.org/f.txt", &iv, &key).is_err());
        assert!(aesgcm_url("https://example.org/f.txt#x", &iv, &key).is_err());
        assert!(aesgcm_url("not a url", &iv, &key).is_err());
        assert!(aesgcm_url("https://example.org/f%20g.txt", &iv, &key).unwrap().starts_with("aesgcm://example.org/f%20g.txt#0101"));
        // blanks around it and an upper-case scheme still give a proper aesgcm:// URL
        assert!(aesgcm_url(" HTTPS://Example.org/f.txt\n", &iv, &key).unwrap().starts_with("aesgcm://example.org/f.txt#0101"));
    }

    #[test]
    fn scan_picks_finished_regular_files() {
        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-outbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("abuse-report-2026-10-19.txt"), "b").unwrap();
        std::fs::write(dir.join("abuse-report-2026-10-12.txt"), "a").unwrap();
        std::fs::write(dir.join(".abuse-report-2026-10-26.txt.tmp"), "being written").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link.txt")).unwrap();
        let now = SystemTime::now();
        let p = scan(&dir, Duration::from_secs(7 * 86400), now).unwrap();
        let names = |v: &[PathBuf]| v.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(names(&p.ready), ["abuse-report-2026-10-12.txt", "abuse-report-2026-10-19.txt"]);
        assert!(p.expired.is_empty());
        // eight days later both are past a seven-day retention
        let later = scan(&dir, Duration::from_secs(7 * 86400), now + Duration::from_secs(8 * 86400)).unwrap();
        assert_eq!(names(&later.expired), ["abuse-report-2026-10-12.txt", "abuse-report-2026-10-19.txt"]);
        assert!(later.ready.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn alert_messages() {
        let text = "To: Admin@Example.org\nSubject: [xmpp] logguard: system\n\n[xmpp] logguard: system\n\n[High] line\n\nlast";
        assert_eq!(parse_message(text), Some(("admin@example.org".into(), "[xmpp] logguard: system\n\n[High] line\n\nlast".into())));
        assert_eq!(parse_message("To: a@b\nFrom: x\n\nbody"), None);
        assert_eq!(parse_message("Subject: s\n\nbody"), None);
        assert_eq!(parse_message("no header"), None);

        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-messages-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alert-2.msg"), text).unwrap();
        std::fs::write(dir.join("alert-1.msg"), text).unwrap();
        std::fs::write(dir.join(".alert-0.msg.sending"), text).unwrap();
        std::fs::write(dir.join(".alert-9.msg.fallback"), text).unwrap();
        std::fs::write(dir.join("abuse-report-2026-10-19.txt"), "r").unwrap();
        let names = |v: &[PathBuf]| v.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(names(&scan_messages(&dir).unwrap()), ["alert-1.msg", "alert-2.msg"]);
        assert_eq!(
            names(&scan(&dir, Duration::from_secs(60), SystemTime::now()).unwrap().ready),
            ["abuse-report-2026-10-19.txt"],
            "messages aren't uploads"
        );
        assert_eq!(recover(&dir), 1);
        assert_eq!(names(&scan_messages(&dir).unwrap()), ["alert-0.msg", "alert-1.msg", "alert-2.msg"]);
        assert!(dir.join(".alert-9.msg.fallback").exists(), "logguard's claim stays logguard's");
        assert_eq!(claimed(&dir.join("alert-1.msg"), "sending"), dir.join(".alert-1.msg.sending"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_is_the_report_heading() {
        let text = "Abuse report from xmpp (1.2.3.4) and vpn (5.6.7.8)\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n\nmore";
        assert_eq!(summary(text), "Abuse report from xmpp (1.2.3.4) and vpn (5.6.7.8)\nPeriod: 2026-10-12 to 2026-10-19 UTC.");
        assert_eq!(summary(""), "");
    }
}
