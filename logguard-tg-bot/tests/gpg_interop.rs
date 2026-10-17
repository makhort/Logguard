//! The encrypted files against GnuPG, the reference OpenPGP implementation: keys made by
//! `gpg` (RSA 4096, and Ed25519 with a Curve25519 subkey, as OpenKeychain and iPGMail make
//! them), files sealed by the bot, decrypted by `gpg`. Skipped when `gpg` isn't installed.
//! Runs in a throwaway GNUPGHOME: your own keyring is never touched.

use std::path::{Path, PathBuf};
use std::process::Command;

use logguard_tg_bot::seal::Recipient;

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf").env("GNUPGHOME", &self.0).args(["--kill", "all"]).status();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(tag: &str) -> Home {
    // short: gpg-agent's socket lives in it, and Unix socket paths are limited to ~100 bytes
    let base = if Path::new("/tmp").is_dir() { PathBuf::from("/tmp") } else { std::env::temp_dir() };
    let dir = base.join(format!("logguard-tg-bot-gpg-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    Home(dir)
}

fn gpg(home: &Home, args: &[&str]) -> std::process::Output {
    let out = Command::new("gpg")
        .env("GNUPGHOME", &home.0)
        .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""])
        .args(args)
        .output()
        .expect("running gpg");
    assert!(out.status.success(), "gpg {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out
}

fn have_gpg() -> bool {
    Command::new("gpg").arg("--version").output().is_ok_and(|o| o.status.success())
}

/// Makes a key with `gpg`, exports its public part, seals a report to it and lets `gpg`
/// decrypt it. Returns gpg's packet listing of the sealed file.
fn round_trip(tag: &str, primary: &str, subkey: &str) -> String {
    let h = home(tag);
    let uid = format!("logguard reports {tag} <admin@example.org>");
    gpg(&h, &["--quick-gen-key", &uid, primary, "sign,cert", "never"]);
    let fpr = String::from_utf8(gpg(&h, &["--list-keys", "--with-colons", &uid]).stdout).unwrap();
    let fpr = fpr.lines().find(|l| l.starts_with("fpr:")).unwrap().split(':').nth(9).unwrap().to_string();
    gpg(&h, &["--quick-add-key", &fpr, subkey, "encr", "never"]);
    let public = gpg(&h, &["--armor", "--export", &fpr]).stdout;

    let r = Recipient::parse(&public, chrono::Utc::now().timestamp() as u32).unwrap();
    assert_eq!(r.fingerprint, fpr, "the fingerprint gpg shows");
    let report =
        "Abuse report from xmpp (192.0.2.1) and vpn (192.0.2.2)\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n\nHello, abuse@example.net,\n→ ✓\n"
            .repeat(200);
    let sealed = h.0.join("report.pgp");
    std::fs::write(&sealed, r.seal(report.clone().into_bytes(), chrono::Utc::now().timestamp() as u32).unwrap()).unwrap();
    let out = h.0.join("report.txt");
    let decrypted = gpg(&h, &["--verbose", "--output", out.to_str().unwrap(), "--decrypt", sealed.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), report, "gpg decrypts it unchanged");
    // the packets, and the cipher as the verbose decryption named it
    let listing = gpg(&h, &["--list-packets", sealed.to_str().unwrap()]);
    format!("{}{}", String::from_utf8_lossy(&listing.stdout), String::from_utf8_lossy(&decrypted.stderr))
}

fn check_format(packets: &str) {
    // a v3 PKESK, SEIPD v1 with MDC (what every app reads), AES-256, no name inside
    assert!(packets.contains(":pubkey enc packet: version 3"), "{packets}");
    assert!(packets.contains(":encrypted data packet:\n\tversion: 1\n\t    mdc: 2"), "SEIPD v1 with MDC: {packets}");
    assert!(!packets.to_lowercase().contains("aead"), "not AEAD (SEIPD v2): {packets}");
    assert!(packets.contains("AES256"), "AES-256: {packets}");
    assert!(packets.contains("name=\"\""), "no file name inside: {packets}");
}

#[test]
fn keys_that_expire_stop_being_used() {
    if !have_gpg() {
        return eprintln!("skipped: gpg is not installed");
    }
    let h = home("expiry");
    let uid = "logguard reports expiry <admin@example.org>";
    gpg(&h, &["--quick-gen-key", uid, "ed25519", "sign,cert", "2d"]);
    let fpr = String::from_utf8(gpg(&h, &["--list-keys", "--with-colons", uid]).stdout).unwrap();
    let fpr = fpr.lines().find(|l| l.starts_with("fpr:")).unwrap().split(':').nth(9).unwrap().to_string();
    gpg(&h, &["--quick-add-key", &fpr, "cv25519", "encr", "1d"]);
    let public = gpg(&h, &["--export", &fpr]).stdout;
    let now = chrono::Utc::now().timestamp() as u32;
    let r = Recipient::parse(&public, now).unwrap();
    assert!(r.seal(b"x".to_vec(), now).is_ok());
    // while the bot runs: the subkey first, then the whole key
    let e = r.seal(b"x".to_vec(), now + 86400 + 60).unwrap_err();
    assert!(e.contains("encryption subkeys expired"), "{e}");
    assert!(r.check(now + 2 * 86400 + 60).unwrap_err().contains("the key expired"));
    // and at the start
    assert!(Recipient::parse(&public, now + 2 * 86400 + 60).is_err());
}

/// A key someone else has signed (`gpg --sign-key`, web of trust) is as good as any: the
/// bot looks at the key's own signatures only.
#[test]
fn keys_signed_by_others_are_taken() {
    if !have_gpg() {
        return eprintln!("skipped: gpg is not installed");
    }
    let h = home("signed");
    let fpr = |uid: &str| {
        let out = String::from_utf8(gpg(&h, &["--list-keys", "--with-colons", uid]).stdout).unwrap();
        out.lines().find(|l| l.starts_with("fpr:")).unwrap().split(':').nth(9).unwrap().to_string()
    };
    gpg(&h, &["--quick-gen-key", "Admin <admin@example.org>", "ed25519", "sign,cert", "never"]);
    let admin = fpr("admin@example.org");
    gpg(&h, &["--quick-add-key", &admin, "cv25519", "encr", "never"]);
    gpg(&h, &["--quick-gen-key", "Friend <friend@example.org>", "ed25519", "sign,cert", "never"]);
    let friend = fpr("friend@example.org");
    gpg(&h, &["--local-user", &friend, "--quick-sign-key", &admin]);
    let public = gpg(&h, &["--armor", "--export", &admin]).stdout;
    let r = Recipient::parse(&public, chrono::Utc::now().timestamp() as u32).unwrap();
    assert_eq!(r.fingerprint, admin);
}

#[test]
fn gpg_decrypts_for_an_rsa_key() {
    if !have_gpg() {
        return eprintln!("skipped: gpg is not installed");
    }
    check_format(&round_trip("rsa", "rsa4096", "rsa4096"));
}

#[test]
fn gpg_decrypts_for_a_curve25519_key() {
    if !have_gpg() {
        return eprintln!("skipped: gpg is not installed");
    }
    check_format(&round_trip("cv25519", "ed25519", "cv25519"));
}
