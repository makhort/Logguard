//! The bot against a fake mail server on 127.0.0.1: plain SMTP (as to the local Postfix),
//! STARTTLS and TLS from the start with a certificate of a test CA, PLAIN and LOGIN logins,
//! refusals, and a server that strips STARTTLS. The mails that arrive are decrypted with the
//! recipient's key. The last tests run the binary itself, as systemd would.
//!
//! Needs to bind 127.0.0.1: run outside a sandbox that forbids it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use logguard_mail_bot::bot::{self, Bot, Config};
use logguard_mail_bot::mime::Sender;
use logguard_mail_bot::seal::Recipients;
use logguard_mail_bot::smtp::{self, Auth, Outgoing, Smtp, TlsMode};
use pgp::composed::{ArmorOptions, Deserializable, Message, SignedPublicKey, SignedSecretKey};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Plain,
    StartTls,
    Implicit,
    /// Says nothing of STARTTLS, as a server (or a man in the middle) that strips it.
    Stripped,
}

#[derive(Debug, Clone)]
struct Received {
    from: String,
    to: Vec<String>,
    data: String,
    tls: bool,
    login: Option<String>,
}

struct Server {
    port: u16,
    mails: Arc<Mutex<Vec<Received>>>,
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(b),
            Stream::Tls(s) => s.read(b),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(b),
            Stream::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

fn read_line(s: &mut Stream) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8];
    while !line.ends_with(b"\r\n") {
        if s.read(&mut b).ok()? == 0 {
            return None;
        }
        line.push(b[0]);
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).ok()
}

fn tls(s: TcpStream, cfg: &Arc<rustls::ServerConfig>) -> Stream {
    Stream::Tls(Box::new(rustls::StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), s)))
}

struct Opts {
    mode: Mode,
    tls: Option<Arc<rustls::ServerConfig>>,
    /// user, password: AUTH required.
    login: Option<(&'static str, &'static str)>,
    /// Answers to DATA's end, one per mail, then 250.
    data_replies: Vec<&'static str>,
}

impl Server {
    fn start(opts: Opts) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mails = Arc::new(Mutex::new(Vec::new()));
        let m = mails.clone();
        let opts = Arc::new(Mutex::new(opts));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let (m, opts) = (m.clone(), opts.clone());
                std::thread::spawn(move || session(conn, &opts, &m));
            }
        });
        Server { port, mails }
    }

    fn wait_for(&self, n: usize) -> Vec<Received> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            let m = self.mails.lock().unwrap().clone();
            if m.len() >= n {
                return m;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{n} mail(s) didn't arrive; got {}", self.mails.lock().unwrap().len());
    }
}

fn session(conn: TcpStream, opts: &Mutex<Opts>, mails: &Mutex<Vec<Received>>) {
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (mode, cfg, login) = {
        let o = opts.lock().unwrap();
        (o.mode, o.tls.clone(), o.login)
    };
    let mut s = Some(if mode == Mode::Implicit { tls(conn, cfg.as_ref().unwrap()) } else { Stream::Plain(conn) });
    let say = |s: &mut Option<Stream>, t: &str| {
        let st = s.as_mut().unwrap();
        st.write_all(format!("{t}\r\n").as_bytes()).unwrap();
        st.flush().unwrap();
    };
    say(&mut s, "220 fake.example.org ESMTP");
    let (mut from, mut to, mut authed) = (String::new(), Vec::new(), None::<String>);
    while let Some(line) = read_line(s.as_mut().unwrap()) {
        let upper = line.to_ascii_uppercase();
        let is_tls = matches!(s, Some(Stream::Tls(_)));
        if upper.starts_with("EHLO") {
            let mut caps = vec!["250-fake.example.org", "250-8BITMIME", "250-PIPELINING"];
            if mode == Mode::StartTls && !is_tls {
                caps.push("250-STARTTLS");
            }
            if login.is_some() && (is_tls || mode != Mode::StartTls) {
                caps.push("250-AUTH PLAIN LOGIN");
            }
            caps.push("250 SIZE 10240000");
            say(&mut s, &caps.join("\r\n"));
        } else if upper == "STARTTLS" && mode == Mode::StartTls {
            say(&mut s, "220 go ahead");
            let Some(Stream::Plain(c)) = s.take() else { panic!("STARTTLS twice") };
            s = Some(tls(c, cfg.as_ref().unwrap()));
        } else if let Some(rest) = upper.strip_prefix("AUTH PLAIN") {
            let b64 = if rest.trim().is_empty() {
                say(&mut s, "334 ");
                read_line(s.as_mut().unwrap()).unwrap_or_default()
            } else {
                line[11..].trim().to_string()
            };
            let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
            let parts: Vec<String> = raw.split(|&b| b == 0).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
            let ok = login.is_some_and(|(u, p)| parts.len() == 3 && parts[1] == u && parts[2] == p);
            if ok {
                authed = Some(format!("PLAIN {}", parts[1]));
                say(&mut s, "235 2.7.0 ok");
            } else {
                say(&mut s, "535 5.7.8 authentication failed");
            }
        } else if upper.starts_with("AUTH LOGIN") {
            say(&mut s, "334 VXNlcm5hbWU6");
            let u = read_line(s.as_mut().unwrap()).unwrap_or_default();
            say(&mut s, "334 UGFzc3dvcmQ6");
            let p = read_line(s.as_mut().unwrap()).unwrap_or_default();
            let dec =
                |x: &str| String::from_utf8(base64::engine::general_purpose::STANDARD.decode(x).unwrap_or_default()).unwrap_or_default();
            let (u, p) = (dec(&u), dec(&p));
            if login.is_some_and(|(lu, lp)| lu == u && lp == p) {
                authed = Some(format!("LOGIN {u}"));
                say(&mut s, "235 2.7.0 ok");
            } else {
                say(&mut s, "535 5.7.8 authentication failed");
            }
        } else if upper.starts_with("MAIL FROM:") {
            if login.is_some() && authed.is_none() {
                say(&mut s, "530 5.7.0 authentication required");
                continue;
            }
            from = line[10..].split_whitespace().next().unwrap_or("").trim_matches(['<', '>']).to_string();
            say(&mut s, "250 ok");
        } else if upper.starts_with("RCPT TO:") {
            to.push(line[8..].trim().trim_matches(['<', '>']).to_string());
            say(&mut s, "250 ok");
        } else if upper == "DATA" {
            say(&mut s, "354 go on");
            let mut data = String::new();
            loop {
                let l = read_line(s.as_mut().unwrap()).unwrap();
                if l == "." {
                    break;
                }
                data.push_str(l.strip_prefix('.').unwrap_or(&l));
                data.push_str("\r\n");
            }
            let reply = {
                let mut o = opts.lock().unwrap();
                if o.data_replies.is_empty() {
                    "250 2.0.0 queued"
                } else {
                    o.data_replies.remove(0)
                }
            };
            if reply.starts_with('2') {
                mails.lock().unwrap().push(Received {
                    from: std::mem::take(&mut from),
                    to: std::mem::take(&mut to),
                    data,
                    tls: is_tls,
                    login: authed.clone(),
                });
            }
            say(&mut s, reply);
        } else if upper == "QUIT" {
            say(&mut s, "221 bye");
            return;
        } else if upper == "NOOP" || upper == "RSET" {
            say(&mut s, "250 ok");
        } else {
            say(&mut s, "502 5.5.2 what?");
        }
    }
}

/// A test CA and a certificate for localhost and 127.0.0.1 from it: (server config, CA PEM).
fn test_ca() -> (Arc<rustls::ServerConfig>, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "logguard test CA");
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = rcgen::CertifiedIssuer::self_signed(ca, ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap().signed_by(&leaf_key, &ca).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![leaf.der().clone()], key).unwrap();
    (Arc::new(cfg), ca.pem())
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("logguard-mail-bot-smtp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("outbox")).unwrap();
    d
}

/// The admin's key pair (as made by phones and Thunderbird), the public part in `dir`.
fn admin_key(d: &Path) -> (SignedSecretKey, PathBuf) {
    use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Admin <admin@example.org>".into())
        .subkeys(vec![enc.build().unwrap()]);
    let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
    let path = d.join("admin.asc");
    std::fs::write(&path, SignedPublicKey::from(secret.clone()).to_armored_string(ArmorOptions::default()).unwrap()).unwrap();
    (secret, path)
}

/// The decrypted content of a mail.
fn decrypt(secret: &SignedSecretKey, mail: &str) -> String {
    let start = mail.find("-----BEGIN PGP MESSAGE-----").expect("an encrypted part");
    let end = mail.find("-----END PGP MESSAGE-----").unwrap() + 25;
    let (msg, _) = Message::from_armor(&mail.as_bytes()[start..end]).unwrap();
    let mut msg = msg.decrypt(&"".into(), secret).unwrap();
    String::from_utf8(msg.as_data_vec().unwrap()).unwrap()
}

fn settings(port: u16, tls: TlsMode) -> smtp::Settings {
    smtp::Settings {
        host: "127.0.0.1".into(),
        port,
        tls,
        tls_name: "localhost".into(),
        ca_file: None,
        auth: Auth::Auto,
        user: String::new(),
        password: String::new(),
        helo: "test.example.org".into(),
        timeout: Duration::from_secs(5),
    }
}

fn config(d: &Path, key: &Path) -> Config {
    let to = vec!["admin@example.org".to_string()];
    let recipients = Recipients::load(key, &to, chrono::Utc::now().timestamp() as u32, &mut |w| panic!("{w}")).unwrap();
    Config {
        outbox: d.join("outbox"),
        outbox_max_age: Duration::from_secs(7 * 86400),
        alert_max_age: Duration::from_secs(86400),
        from: Sender { name: "logguard".into(), address: "alerts@example.org".into() },
        outer_subject: "...".into(),
        recipients,
        signer: None,
        sanitize: None,
    }
}

const ALERT: &str =
    "To: admin\nSubject: [vpn] logguard: password guessing blocked\n\n[vpn] logguard: password guessing blocked\n\n11.23.45.233 banned → ✓";

#[test]
fn plain_smtp_to_the_local_server_with_a_login() {
    let server = Server::start(Opts { mode: Mode::Plain, tls: None, login: Some(("alerts", "pw")), data_replies: vec![] });
    let d = dir("plain");
    let (secret, key) = admin_key(&d);
    std::fs::write(d.join("outbox/alert-1.msg"), ALERT).unwrap();
    let s = smtp::Settings { auth: Auth::Plain, user: "alerts".into(), password: "pw".into(), ..settings(server.port, TlsMode::None) };
    let smtp = Smtp::new(&s).unwrap();
    smtp.check().unwrap();
    let mut b = Bot::new(config(&d, &key), smtp);
    b.deliver_alerts(&AtomicBool::new(false));
    let m = &server.wait_for(1)[0];
    assert_eq!(
        (m.from.as_str(), m.to.as_slice(), m.login.as_deref()),
        ("alerts@example.org", &["admin@example.org".to_string()][..], Some("PLAIN alerts"))
    );
    assert!(!m.tls);
    assert!(m.data.contains("\r\nSubject: ...\r\n") && !m.data.contains("11.23.45.233") && !m.data.contains("guessing"));
    let inner = decrypt(&secret, &m.data);
    assert!(inner.contains("Subject: [vpn] logguard: password guessing blocked\r\n"), "{inner}");
    assert!(inner.contains("11.23.45.233 banned =E2=86=92 =E2=9C=93"), "{inner}");
    assert!(!d.join("outbox/alert-1.msg").exists());

    // a wrong password: refused for good, which the service takes as "stop" (exit 78)
    let wrong = smtp::Settings { password: "nope".into(), ..s };
    let e = Smtp::new(&wrong).unwrap().check().unwrap_err();
    assert!(e.permanent && e.text.contains("535"), "{e:?}");
}

#[test]
fn tls_both_ways_with_the_servers_own_ca() {
    let (cfg, ca) = test_ca();
    let d = dir("tls");
    std::fs::write(d.join("ca.pem"), &ca).unwrap();
    let (secret, key) = admin_key(&d);
    for mode in [Mode::StartTls, Mode::Implicit] {
        let server = Server::start(Opts { mode, tls: Some(cfg.clone()), login: Some(("alerts", "pw")), data_replies: vec![] });
        let tls = if mode == Mode::StartTls { TlsMode::StartTls } else { TlsMode::Implicit };
        let s = smtp::Settings {
            ca_file: Some(d.join("ca.pem")),
            auth: Auth::Login,
            user: "alerts".into(),
            password: "pw".into(),
            ..settings(server.port, tls)
        };
        let mut smtp = Smtp::new(&s).unwrap();
        let mail = Bot::new(config(&d, &key), Smtp::new(&s).unwrap())
            .compose("subject", logguard_mail_bot::mime::Content::Text("over TLS".into()), &["admin@example.org".into()])
            .unwrap();
        smtp.send("alerts@example.org", &["admin@example.org".into()], &mail).unwrap();
        let m = &server.wait_for(1)[0];
        assert!(m.tls, "{:?}", tls);
        assert_eq!(m.login.as_deref(), Some("LOGIN alerts"));
        assert!(decrypt(&secret, &m.data).contains("over TLS"));

        // the system's CA store doesn't know the test CA: not sent, and not for good (retried)
        let e = Smtp::new(&smtp::Settings { ca_file: None, ..s.clone() }).unwrap().check().unwrap_err();
        assert!(!e.permanent, "{e:?}");
        // a name the certificate doesn't carry
        let e = Smtp::new(&smtp::Settings { tls_name: "mail.example.org".into(), ..s }).unwrap().check().unwrap_err();
        assert!(!e.permanent, "{e:?}");
    }
}

#[test]
fn a_stripped_starttls_is_never_answered_in_clear() {
    let (cfg, ca) = test_ca();
    let d = dir("stripped");
    std::fs::write(d.join("ca.pem"), &ca).unwrap();
    let server = Server::start(Opts { mode: Mode::Stripped, tls: Some(cfg), login: Some(("alerts", "pw")), data_replies: vec![] });
    let s = smtp::Settings {
        ca_file: Some(d.join("ca.pem")),
        user: "alerts".into(),
        password: "pw".into(),
        ..settings(server.port, TlsMode::StartTls)
    };
    let e = Smtp::new(&s).unwrap().check().unwrap_err();
    assert!(!e.permanent && e.global, "retried, not given up on for good (someone in the way could do this): {e:?}");
    assert!(e.text.contains("STARTTLS"), "{e:?}");
    assert!(server.mails.lock().unwrap().is_empty());
}

#[test]
fn a_mail_the_server_refuses_is_dropped_with_a_note() {
    let server = Server::start(Opts { mode: Mode::Plain, tls: None, login: None, data_replies: vec!["552 5.3.4 message too big"] });
    let d = dir("refused");
    let (secret, key) = admin_key(&d);
    std::fs::write(d.join("outbox/abuse-report-2026-10-19.txt"), "the report\n").unwrap();
    let mut b = Bot::new(config(&d, &key), Smtp::new(&settings(server.port, TlsMode::None)).unwrap());
    b.deliver_files(&AtomicBool::new(false));
    let m = server.wait_for(1);
    assert_eq!(m.len(), 1, "only the note");
    let inner = decrypt(&secret, &m[0].data);
    let body = inner.split_once("\r\n\r\n").unwrap().1;
    let note = String::from_utf8(quoted_printable::decode(body, quoted_printable::ParseMode::Robust).unwrap()).unwrap();
    assert!(note.contains("(552): 5.3.4 message too big)") && note.contains("abuse-report-2026-10-19.txt"), "{note}");
    assert!(note.contains("logguard abuse-report"), "where to get it instead: {note}");
    assert!(!d.join("outbox/abuse-report-2026-10-19.txt").exists());
}

fn binary(d: &Path, port: u16, key: &Path, password: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_logguard-mail-bot"));
    std::fs::write(d.join("password"), format!("{password}\n")).unwrap();
    c.env_clear()
        .env("SMTP_HOST", "127.0.0.1")
        .env("SMTP_PORT", port.to_string())
        .env("SMTP_TLS", "none")
        .env("SMTP_USER", "alerts")
        .env("SMTP_PASSWORD_FILE", d.join("password"))
        .env("MAIL_FROM", "alerts@example.org")
        .env("MAIL_TO", "admin@example.org")
        .env("OPENPGP_KEY", key)
        .env("OUTBOX_DIR", d.join("outbox"))
        .env("LOG_DIR", d.join("log"));
    c
}

#[test]
fn the_service_as_systemd_runs_it() {
    let server = Server::start(Opts { mode: Mode::Plain, tls: None, login: Some(("alerts", "pw")), data_replies: vec![] });
    let d = dir("binary");
    let (secret, key) = admin_key(&d);

    // keygen, then check and a test mail, signed
    let out = binary(&d, server.port, &key, "pw").args(["keygen", "--out"]).arg(d.join("signing.key")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(d.join("signing.key")).unwrap().permissions().mode() & 0o777, 0o600);
    let again = binary(&d, server.port, &key, "pw").args(["keygen", "--out"]).arg(d.join("signing.key")).output().unwrap();
    assert!(!again.status.success(), "never overwritten");
    let check = binary(&d, server.port, &key, "pw").env("SIGNING_KEY", d.join("signing.key")).arg("check").output().unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
    assert!(String::from_utf8_lossy(&check.stdout).contains("encrypted and signed"));
    let test = binary(&d, server.port, &key, "pw").env("SIGNING_KEY", d.join("signing.key")).arg("send-test").output().unwrap();
    assert!(test.status.success(), "{}", String::from_utf8_lossy(&test.stderr));
    let m = &server.wait_for(1)[0];
    assert!(m.data.contains("\r\nAutocrypt: addr=alerts@example.org; prefer-encrypt=mutual; keydata=\r\n "));
    let (msg, _) = Message::from_armor(&m.data.as_bytes()[m.data.find("-----BEGIN PGP MESSAGE-----").unwrap()..]).unwrap();
    let mut msg = msg.decrypt(&"".into(), &secret).unwrap();
    let text = String::from_utf8(msg.as_data_vec().unwrap()).unwrap();
    assert!(text.contains("Subject: [logguard-mail-bot] test"));
    let (bots, _) = SignedPublicKey::from_armor_single(std::fs::File::open(d.join("signing.key.pub.asc")).unwrap()).unwrap();
    msg.verify(&bots.primary_key).expect("signed by the bot");

    // the service: delivers what logguard puts in the outbox, stops cleanly on SIGTERM
    let mut child = binary(&d, server.port, &key, "pw").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    std::fs::write(d.join("outbox/alert-1.msg"), ALERT).unwrap();
    let m = &server.wait_for(2)[1];
    assert!(decrypt(&secret, &m.data).contains("password guessing blocked"));
    let start = Instant::now();
    while d.join("outbox/alert-1.msg").exists() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    Command::new("kill").arg(child.id().to_string()).status().unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let log = std::fs::read_to_string(d.join("log/bot.log")).unwrap();
    assert!(log.contains("alert alert-1.msg sent to admin@example.org") && log.contains("Shutting down"), "{log}");

    // the one-off commands, run as root, never make the pseudonym key the service must own
    let key_path = d.join("pseudonym.key");
    let sanitized = |c: &mut Command| {
        c.env("SANITIZE", "on").env("PSEUDONYM_KEY", &key_path);
    };
    let mut c = binary(&d, server.port, &key, "pw");
    sanitized(&mut c);
    assert!(c.arg("check").output().unwrap().status.success());
    let mut c = binary(&d, server.port, &key, "pw");
    sanitized(&mut c);
    assert!(!c.args(["pseudonym", "alice@example.org"]).output().unwrap().status.success());
    assert!(!key_path.exists());

    // a wrong password stops the service for good (78: systemd doesn't restart it)
    let status = binary(&d, server.port, &key, "wrong").status().unwrap();
    assert_eq!(status.code(), Some(78));
    // and so does a missing key: nothing goes out in clear
    let status = binary(&d, server.port, &key, "pw").env_remove("OPENPGP_KEY").status().unwrap();
    assert_eq!(status.code(), Some(78));
    let status = binary(&d, server.port, &key, "pw").env("SMTP_HOST", "192.0.2.1").status().unwrap();
    assert_eq!(status.code(), Some(78), "no plain SMTP to another host");
}

#[test]
fn run_stops_when_told() {
    let d = dir("stop");
    let (_, key) = admin_key(&d);
    let b = Bot::new(config(&d, &key), Smtp::new(&settings(1, TlsMode::None)).unwrap());
    let stop = AtomicBool::new(true);
    let start = Instant::now();
    bot::run(b, &stop);
    assert!(start.elapsed() < Duration::from_secs(2));
}
