//! The mails against GnuPG, the reference OpenPGP implementation (and what Thunderbird's
//! predecessors, mutt and Apple Mail's GPG Suite use): recipient keys made by `gpg` (RSA
//! 4096, and Ed25519 with a Curve25519 subkey), a mail composed and signed by the bot,
//! decrypted and its signature checked by `gpg`. Skipped when `gpg` isn't installed. Runs in
//! a throwaway GNUPGHOME: your own keyring is never touched.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use logguard_mail_bot::bot::{Bot, Config};
use logguard_mail_bot::mime::{Content, Sender};
use logguard_mail_bot::seal::{Recipients, Signer};
use logguard_mail_bot::smtp::{Outgoing, SendError};

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
    let dir = base.join(format!("lg-mail-gpg-{tag}-{}", std::process::id()));
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

struct Nowhere;

impl Outgoing for Nowhere {
    fn send(&mut self, _: &str, _: &[String], _: &[u8]) -> Result<(), SendError> {
        unreachable!()
    }
}

/// Makes a key with `gpg`, composes a signed mail to it, and lets `gpg` decrypt it and check
/// the signature with the bot's public key. Returns gpg's packet listing and status lines.
fn round_trip(tag: &str, primary: &str, subkey: &str) -> String {
    let h = home(tag);
    let uid = format!("Admin {tag} <admin@example.org>");
    gpg(&h, &["--quick-gen-key", &uid, primary, "sign,cert", "never"]);
    let fpr = String::from_utf8(gpg(&h, &["--list-keys", "--with-colons", &uid]).stdout).unwrap();
    let fpr = fpr.lines().find(|l| l.starts_with("fpr:")).unwrap().split(':').nth(9).unwrap().to_string();
    gpg(&h, &["--quick-add-key", &fpr, subkey, "encr", "never"]);
    let public = gpg(&h, &["--armor", "--export", &fpr]).stdout;

    let to = vec!["admin@example.org".to_string()];
    let now = chrono::Utc::now().timestamp() as u32;
    let recipients = Recipients::parse(&public, &to, now, &mut |w| panic!("{w}")).unwrap();
    assert_eq!(recipients.keys[0].fingerprint, fpr, "the fingerprint gpg shows");
    let (secret, bots_public) = Signer::generate("alerts@example.org").unwrap();
    let signer = Signer::parse(secret.as_bytes()).unwrap();
    let cfg = Config {
        outbox: h.0.join("outbox"),
        outbox_max_age: Duration::from_secs(86400),
        alert_max_age: Duration::from_secs(86400),
        from: Sender { name: "logguard".into(), address: "alerts@example.org".into() },
        outer_subject: "...".into(),
        recipients,
        signer: Some(signer),
        sanitize: None,
    };
    let report = "Abuse report from xmpp (192.0.2.1) and vpn (192.0.2.2)\nHello, abuse@example.net,\n→ ✓\n".repeat(200);
    let mail = Bot::new(cfg, Nowhere).compose("[xmpp] logguard: weekly abuse report", Content::Text(report), &to).unwrap();
    let mail = String::from_utf8(mail).unwrap();
    let start = mail.find("-----BEGIN PGP MESSAGE-----").unwrap();
    let end = mail.find("-----END PGP MESSAGE-----").unwrap() + 25;
    let sealed = h.0.join("mail.asc");
    std::fs::write(&sealed, &mail[start..end]).unwrap();
    std::fs::write(h.0.join("bot.asc"), bots_public).unwrap();
    gpg(&h, &["--import", h.0.join("bot.asc").to_str().unwrap()]);

    let out = h.0.join("inner.eml");
    let decrypted = gpg(&h, &["--verbose", "--status-fd", "2", "--output", out.to_str().unwrap(), "--decrypt", sealed.to_str().unwrap()]);
    let inner = std::fs::read_to_string(&out).unwrap();
    assert!(inner.starts_with("Content-Type: text/plain; charset=\"utf-8\"; protected-headers=\"v1\"\r\n"), "{inner}");
    assert!(inner.contains("\r\nSubject: [xmpp] logguard: weekly abuse report\r\n"));
    let listing = gpg(&h, &["--list-packets", sealed.to_str().unwrap()]);
    format!("{}{}", String::from_utf8_lossy(&listing.stdout), String::from_utf8_lossy(&decrypted.stderr))
}

fn check_format(out: &str) {
    // a v3 PKESK, SEIPD v1 with MDC (what every client reads), AES-256, signed by the bot
    assert!(out.contains(":pubkey enc packet: version 3"), "{out}");
    assert!(out.contains(":encrypted data packet:\n\tversion: 1\n\t    mdc: 2"), "SEIPD v1 with MDC: {out}");
    assert!(!out.to_lowercase().contains("aead"), "not AEAD (SEIPD v2): {out}");
    assert!(out.contains("AES256"), "AES-256: {out}");
    assert!(out.contains("[GNUPG:] GOODSIG ") && out.contains("logguard-mail-bot <alerts@example.org>"), "signed by the bot: {out}");
    assert!(out.contains("[GNUPG:] DECRYPTION_OKAY"), "{out}");
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
    let sigs = String::from_utf8(gpg(&h, &["--list-sigs", &admin]).stdout).unwrap();
    assert!(sigs.contains("Friend <friend@example.org>"), "the friend's signature is on the key: {sigs}");
    let now = chrono::Utc::now().timestamp() as u32;
    let r = Recipients::parse(&public, &["admin@example.org".into()], now, &mut |w| panic!("{w}")).unwrap();
    assert_eq!(r.keys[0].fingerprint, admin);
}

#[test]
fn gpg_reads_mails_to_an_rsa_key() {
    if !have_gpg() {
        return eprintln!("skipped: gpg is not installed");
    }
    check_format(&round_trip("rsa", "rsa4096", "rsa4096"));
}

#[test]
fn gpg_reads_mails_to_a_curve25519_key() {
    if !have_gpg() {
        return eprintln!("skipped: gpg is not installed");
    }
    check_format(&round_trip("cv25519", "ed25519", "cv25519"));
}
