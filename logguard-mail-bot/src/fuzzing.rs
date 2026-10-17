//! What the fuzz targets in `fuzz/` run (`cargo +nightly fuzz run alert_mail`, ...). Each
//! takes input the bot doesn't control: logguard's outbox files (log text attackers wrote
//! into), other files in the outbox, the recipients' key file, the bot's signing key. None of
//! it may panic or hang, and every mail keeps the bot's promises, checked here with rules of
//! their own rather than the code under test:
//!
//! - the mail as it goes out is a well-formed PGP/MIME envelope: all ASCII, CRLF line ends,
//!   lines under 998 characters, exactly the bot's own outer headers (nothing the input could
//!   add or change, the subject `...`), and between the boundaries only the version part and
//!   the armored OpenPGP message;
//! - decrypted with the recipient's key, it is the input: the protected headers are the same
//!   fixed set, the subject one line of what the input said, and the text or file comes back
//!   byte for byte;
//! - with `SANITIZE=on`, no account address and no configured server address or host name is
//!   left in the subject or the text.
//!
//! `tests/fuzz_smoke.rs` runs the same functions on stable, so `cargo test` keeps them working.

use std::net::IpAddr;
use std::sync::OnceLock;

use base64::Engine;
use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;

use crate::bot::{self, Bot, Config, Sanitize};
use crate::mime::{self, Content, Sender};
use crate::outbox;
use crate::redact::{parse_domains, Pseudonyms};
use crate::seal::{self, Recipients, Signer};
use crate::servers::ServerNames;
use crate::smtp::{Outgoing, SendError};

/// The servers of the fuzzed setup (documentation addresses only).
pub const SERVERS: &str = "xmpp=192.0.2.10,2001:db8::10,example.org; vpn=198.51.100.20; tg=203.0.113.30,relay.example.net";
const V4: &[&str] = &["192.0.2.10", "198.51.100.20", "203.0.113.30"];
const V6: &[&str] = &["2001:db8::10"];
const HOSTS: &[&str] = &["example.org", "relay.example.net"];
/// A fixed "now" for the key checks: Unix time in 2026.
pub const NOW: u32 = 1_780_000_000;
/// The recipient of the fuzzed mails.
pub const ADMIN: &str = "admin@example.org";

/// `s` from about `at` bytes on (a character boundary at or before it).
fn from(s: &str, at: usize) -> &str {
    let mut k = at.min(s.len());
    while !s.is_char_boundary(k) {
        k -= 1;
    }
    &s[k..]
}

/// The start of a long text, for an assertion message.
fn short(s: &str) -> String {
    let mut t: String = s.chars().take(300).collect();
    if t.len() < s.len() {
        t.push('…');
    }
    t
}

/// The admin's key pair, made once per process: (secret key, public key file).
fn admin() -> &'static (SignedSecretKey, Vec<u8>) {
    static KEY: OnceLock<(SignedSecretKey, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut enc = SubkeyParamsBuilder::default();
        enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(format!("Admin <{ADMIN}>"))
            .subkeys(vec![enc.build().expect("subkey params")]);
        let secret = params.build().expect("key params").generate(rand08::thread_rng()).expect("a key");
        let public = SignedPublicKey::from(secret.clone()).to_bytes().expect("the public key");
        (secret, public)
    })
}

struct Nowhere;

impl Outgoing for Nowhere {
    fn send(&mut self, _: &str, _: &[String], _: &[u8]) -> Result<(), SendError> {
        Ok(())
    }
}

fn bot(signer: Option<Signer>, sanitize: bool) -> Bot<Nowhere> {
    let now = chrono::Utc::now().timestamp() as u32;
    let recipients = Recipients::parse(&admin().1, &[ADMIN.to_string()], now, &mut |_| {}).expect("the admin's key");
    let sanitize = sanitize.then(|| Sanitize {
        names: Pseudonyms::new([7; 32], parse_domains("example.org")),
        servers: ServerNames::parse(SERVERS).expect("the fuzzed setup"),
    });
    let cfg = Config {
        outbox: "/nonexistent".into(),
        outbox_max_age: std::time::Duration::from_secs(86400),
        alert_max_age: std::time::Duration::from_secs(86400),
        from: Sender { name: "logguard".into(), address: "alerts@example.org".into() },
        outer_subject: mime::PLACEHOLDER_SUBJECT.into(),
        recipients,
        signer,
        sanitize,
    };
    Bot::new(cfg, Nowhere)
}

/// CRLF line ends only, every line under 998 characters (RFC 5322).
fn assert_lines(text: &str, what: &str) {
    let b = text.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        assert!(
            c != b'\r' || b.get(i + 1) == Some(&b'\n'),
            "{what}: a CR alone at byte {i}: {:?}",
            short(from(text, i.saturating_sub(40)))
        );
        assert!(
            c != b'\n' || (i > 0 && b[i - 1] == b'\r'),
            "{what}: an LF alone at byte {i}: {:?}",
            short(from(text, i.saturating_sub(40)))
        );
    }
    for line in text.split("\r\n") {
        assert!(line.len() <= 998, "{what}: a line of {} characters", line.len());
    }
}

/// The header block of a MIME entity: (name, raw value lines), and the body.
fn headers(entity: &str) -> (Vec<(String, Vec<String>)>, &str) {
    let (head, body) = entity.split_once("\r\n\r\n").expect("a blank line after the headers");
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in head.split("\r\n") {
        if let Some(cont) = line.strip_prefix(' ') {
            out.last_mut().expect("a continuation line after a header").1.push(cont.to_string());
        } else {
            let (name, value) = line.split_once(": ").unwrap_or_else(|| panic!("not a header: {line:?}"));
            assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "header name {name:?}");
            out.push((name.to_string(), vec![value.to_string()]));
        }
    }
    (out, body)
}

fn names(h: &[(String, Vec<String>)]) -> Vec<&str> {
    h.iter().map(|(n, _)| n.as_str()).collect()
}

fn value<'a>(h: &'a [(String, Vec<String>)], name: &str) -> &'a [String] {
    &h.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no {name} header")).1
}

/// The boundary in a Content-Type value.
fn boundary_of(content_type: &str) -> String {
    let b = content_type.split("boundary=\"").nth(1).expect("a boundary").split('"').next().expect("a closing quote");
    assert!(b.contains("=_") && b.len() <= 70, "a boundary that can't occur in the parts: {b:?}");
    b.to_string()
}

/// The parts between `--boundary` lines, after the preamble and before the closing one.
fn parts<'a>(body: &'a str, boundary: &str) -> Vec<&'a str> {
    let first = format!("--{boundary}\r\n");
    let start = body.find(&first).expect("a first part");
    assert!(start == 0 || body[..start].ends_with("\r\n"), "a boundary inside a line");
    let rest = body[start + first.len()..].strip_suffix(&format!("\r\n--{boundary}--\r\n")).expect("the closing boundary at the end");
    let v: Vec<&str> = rest.split(&format!("\r\n--{boundary}\r\n")).collect();
    for p in &v {
        assert!(!p.contains(&format!("--{boundary}")), "a boundary inside a part");
    }
    v
}

/// The mail as it goes out: the outer headers and the encrypted part. Returns the armored
/// message.
fn assert_outer(mail: &[u8], signed: bool) -> String {
    let text = std::str::from_utf8(mail).expect("ASCII");
    assert!(text.is_ascii() && !text.contains('\0'), "not plain ASCII");
    assert_lines(text, "outer mail");
    let (h, body) = headers(text);
    let mut expected = vec!["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Auto-Submitted"];
    if signed {
        expected.push("Autocrypt");
    }
    expected.push("Content-Type");
    assert_eq!(names(&h), expected, "exactly the bot's own outer headers");
    assert_eq!(value(&h, "Subject"), [mime::PLACEHOLDER_SUBJECT], "the real subject stays inside");
    assert_eq!(value(&h, "From"), ["\"logguard\" <alerts@example.org>"]);
    assert_eq!(value(&h, "To"), [ADMIN]);
    let ct = value(&h, "Content-Type").join(" ");
    assert!(ct.starts_with("multipart/encrypted; protocol=\"application/pgp-encrypted\";"), "{ct}");
    let b = boundary_of(&ct);
    let p = parts(body, &b);
    assert_eq!(p.len(), 2, "the version part and the encrypted part");
    assert_eq!(
        p[0],
        "Content-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n"
    );
    let (eh, armored) = headers(p[1]);
    assert_eq!(names(&eh), ["Content-Type", "Content-Description", "Content-Disposition"]);
    let armored = armored.strip_suffix("\r\n").expect("a blank line before the boundary");
    assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----\r\n") && armored.ends_with("-----END PGP MESSAGE-----"), "armor");
    for line in armored.split("\r\n").filter(|l| !l.starts_with("-----")) {
        assert!(line.len() <= 76 && line.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c)), "armor line {line:?}");
    }
    armored.replace("\r\n", "\n")
}

/// The decrypted inner entity (and, if signed, the signature checked against `signer`).
fn open(armored: &str, signer: Option<&SignedPublicKey>) -> String {
    let (msg, _) = Message::from_armor(armored.as_bytes()).expect("an armored message");
    let mut msg = msg.decrypt(&"".into(), &admin().0).expect("the admin's key opens it");
    let data = msg.as_data_vec().expect("the content");
    if let Some(k) = signer {
        msg.verify(&k.primary_key).expect("signed by the bot");
    }
    let inner = String::from_utf8(data).expect("the inner entity is text");
    assert!(inner.is_ascii(), "the inner entity is ASCII too (non-ASCII is encoded)");
    assert_lines(&inner, "inner entity");
    inner
}

/// A subject header's value as a reader sees it: one plain line, or RFC 2047 words.
fn decode_subject(lines: &[String]) -> String {
    if !lines[0].starts_with("=?utf-8?b?") {
        assert_eq!(lines.len(), 1, "a plain subject is one line");
        return lines[0].clone();
    }
    let mut bytes = Vec::new();
    for w in lines {
        assert!(w.len() <= 76, "an encoded word longer than a line: {w}");
        let b64 = w.strip_prefix("=?utf-8?b?").and_then(|w| w.strip_suffix("?=")).unwrap_or_else(|| panic!("not an encoded word: {w}"));
        bytes.extend(base64::engine::general_purpose::STANDARD.decode(b64).expect("base64"));
    }
    // each word holds whole characters, as RFC 2047 requires
    String::from_utf8(bytes).expect("UTF-8")
}

/// What the subject must read: the text on one line, no control characters, 200 characters
/// at most, no blanks at the ends.
fn expected_subject(s: &str) -> String {
    let one: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    one.trim().to_string()
}

/// Text as it must come back from quoted-printable: CRLF line ends.
fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

fn qp_decode(body: &str) -> String {
    for line in body.split("\r\n") {
        assert!(line.len() <= 76, "a quoted-printable line of {} characters", line.len());
    }
    let raw = quoted_printable::decode(body, quoted_printable::ParseMode::Strict).expect("valid quoted-printable");
    String::from_utf8(raw).expect("the text was UTF-8")
}

/// The protected headers and the text of a mail's inner entity, checked: (subject, text).
fn assert_inner_text(inner: &str) -> (String, String) {
    let (h, body) = headers(inner);
    assert_eq!(names(&h), ["Content-Type", "Content-Transfer-Encoding", "From", "To", "Subject", "Date", "Message-ID"]);
    assert_eq!(value(&h, "Content-Type"), ["text/plain; charset=\"utf-8\"; protected-headers=\"v1\""]);
    assert_eq!(value(&h, "Content-Transfer-Encoding"), ["quoted-printable"]);
    let body = body.strip_suffix("\r\n").expect("a CRLF after the text");
    (decode_subject(value(&h, "Subject")), qp_decode(body))
}

// --- what SANITIZE promises (the same rules as logguard-tg-bot's fuzzing) ---------------

/// What XMPP forbids in an account's local part (RFC 7622), besides blanks and controls.
fn local_char(c: char) -> bool {
    !c.is_whitespace() && !c.is_control() && !"\"&'/:<>@".contains(c)
}

fn domain_char(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

fn host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// No `local@domain` and no `ejabberd:<name>` is left.
fn assert_no_accounts(out: &str) {
    for (i, _) in out.match_indices('@') {
        let local: String = out[..i].chars().rev().take_while(|&c| local_char(c)).collect::<Vec<_>>().into_iter().rev().collect();
        let name = local.trim_start_matches(['(', '[', '{']);
        let domain: String = out[i + 1..].chars().take_while(|&c| domain_char(c)).collect();
        assert!(
            !(!name.is_empty() && domain.trim_end_matches(['.', '-']).chars().any(char::is_alphanumeric)),
            "an address is left at byte {i}: {:?}",
            short(from(out, i.saturating_sub(40)))
        );
    }
    for (i, m) in out.match_indices("ejabberd:") {
        let rest = &out[i + m.len()..];
        let name: String = rest.chars().take_while(|&c| local_char(c)).collect();
        let name = name.trim_start_matches(['(', '[', '{']).trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
        assert!(
            name.is_empty() || crate::redact::pseudonym_after_openers(rest).is_some(),
            "an ejabberd: name is left at byte {i}: {:?}",
            short(from(out, i))
        );
    }
}

/// The maximal runs of ASCII bytes in `class`.
fn runs(text: &str, class: impl Fn(u8) -> bool) -> Vec<&str> {
    let b = text.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !class(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && class(b[i]) {
            i += 1;
        }
        v.push(&text[start..i]);
    }
    v
}

/// None of the fuzzed setup's server addresses or host names is left.
fn assert_no_servers(out: &str) {
    let v4: Vec<IpAddr> = V4.iter().map(|a| a.parse().expect("an address")).collect();
    let v6: Vec<IpAddr> = V6.iter().map(|a| a.parse().expect("an address")).collect();
    let ours = |c: &str| {
        c.parse::<IpAddr>()
            .ok()
            .map(|ip| match ip {
                IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                v4 => v4,
            })
            .filter(|ip| v6.contains(ip) || v4.contains(ip))
    };
    let check = |run: &str| {
        let whole = run.trim_matches('.');
        if whole.parse::<IpAddr>().is_ok() {
            let tail = whole.rsplit_once(':').map_or("", |(_, t)| t);
            assert!(ours(whole).is_none() && ours(tail).is_none(), "server address in {whole} is left: {:?}", short(out));
            return;
        }
        let b = run.as_bytes();
        let sep = |k: usize| b[k] == b':' || b[k] == b'.';
        for start in (0..b.len()).filter(|&k| k == 0 || sep(k - 1)) {
            for end in (start + 1..=b.len().min(start + 45)).filter(|&k| k == b.len() || sep(k)) {
                assert!(ours(&run[start..end]).is_none(), "server address {} is left: {:?}", &run[start..end], short(out));
            }
        }
    };
    for run in runs(out, |c| c.is_ascii_hexdigit() || c == b':' || c == b'.').into_iter().filter(|r| r.contains(':')) {
        check(run);
    }
    for run in runs(out, |c| c.is_ascii_digit() || c == b'.') {
        check(run);
    }
    let lower = out.to_ascii_lowercase();
    for host in HOSTS {
        for (k, _) in lower.match_indices(host) {
            let before = lower[..k].chars().next_back();
            let mut after = lower[k + host.len()..].chars();
            let (a1, a2) = (after.next(), after.next());
            let whole_left = before.is_none_or(|c| !host_char(c) || c == '.');
            let whole_right = a1.is_none_or(|c| !host_char(c)) && !(a1 == Some('.') && a2.is_some_and(host_char));
            assert!(!(whole_left && whole_right), "host name {host} is left at byte {k}: {:?}", short(from(out, k)));
        }
    }
}

// --- the targets ------------------------------------------------------------------------

/// An outbox file, as logguard writes it (or anything else): the mail the bot makes of it,
/// as it is and with `SANITIZE=on`.
pub fn alert(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let Some((subject, body)) = outbox::parse_message(&text) else { return };
    for sanitize in [false, true] {
        let b = bot(None, sanitize);
        let (subject, body) = match &b.cfg.sanitize {
            Some(s) => (s.text(&subject), s.text(&body)),
            None => (subject.clone(), body.clone()),
        };
        let mail = b.compose(&subject, Content::Text(body.clone()), &[ADMIN.to_string()]).expect("a mail");
        let inner = open(&assert_outer(&mail, false), None);
        let (got_subject, got_body) = assert_inner_text(&inner);
        assert_eq!(got_subject, expected_subject(&subject), "the subject");
        assert_eq!(got_body, crlf(&body), "the text comes back as it was");
        if sanitize {
            // the whole subject: the header keeps 200 characters of it, and a cut through a
            // pseudonym (`ejabberd:[a`) is no name (found by fuzzing); what the header shows
            // is checked to be that start above
            for out in [&subject, &got_body] {
                assert_no_accounts(out);
                assert_no_servers(out);
            }
        }
    }
}

/// Any other file in the outbox: `name`, a NUL byte, the content. Text comes back as the
/// mail's text, anything else as an attachment with a safe name, byte for byte.
pub fn file(data: &[u8]) {
    let (name, content) = match data.iter().position(|&b| b == 0) {
        Some(i) => (String::from_utf8_lossy(&data[..i]).into_owned(), data[i + 1..].to_vec()),
        None => ("abuse-report-2026-10-19.txt".to_string(), data.to_vec()),
    };
    let b = bot(None, false);
    let subject = bot::file_subject(&name);
    let mail = b.compose(&subject, bot::file_content(&name, content.clone()), &[ADMIN.to_string()]).expect("a mail");
    let inner = open(&assert_outer(&mail, false), None);
    match String::from_utf8(content.clone()) {
        Ok(text) => {
            let (s, t) = assert_inner_text(&inner);
            assert_eq!(s, expected_subject(&subject));
            assert_eq!(t, crlf(&text));
        }
        Err(_) => {
            let (h, body) = headers(&inner);
            assert_eq!(names(&h), ["Content-Type", "From", "To", "Subject", "Date", "Message-ID"]);
            let ct = value(&h, "Content-Type").join(" ");
            assert!(ct.starts_with("multipart/mixed;") && ct.ends_with("protected-headers=\"v1\""), "{ct}");
            let p = parts(body, &boundary_of(&ct));
            assert_eq!(p.len(), 2, "a line of text and the file");
            let (th, text) = headers(p[0]);
            assert_eq!(names(&th), ["Content-Type", "Content-Transfer-Encoding"]);
            assert!(qp_decode(text.strip_suffix("\r\n").unwrap_or(text)).starts_with("logguard sent "));
            let (ah, b64) = headers(p[1]);
            assert_eq!(names(&ah), ["Content-Type", "Content-Disposition", "Content-Transfer-Encoding"]);
            let disposition = value(&ah, "Content-Disposition").join("");
            let fname = disposition.strip_prefix("attachment; filename=\"").and_then(|f| f.strip_suffix('"')).expect("a file name");
            assert!(
                !fname.is_empty() && !fname.starts_with('.') && fname.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)),
                "an unsafe file name {fname:?}"
            );
            for line in b64.split("\r\n") {
                assert!(line.len() <= 76, "a base64 line of {}", line.len());
            }
            let got = base64::engine::general_purpose::STANDARD.decode(b64.replace("\r\n", "")).expect("base64");
            assert_eq!(got, content, "the file comes back as it was");
        }
    }
}

/// The recipients' key file: whatever is taken must encrypt to every usable address.
pub fn openpgp_keys(data: &[u8]) {
    let to = ["admin@example.org".to_string(), "ops@example.net".to_string()];
    let Ok(r) = Recipients::parse(data, &to, NOW, &mut |_| {}) else { return };
    let (ok, _) = r.split(NOW);
    assert!(!ok.is_empty(), "taken at NOW, so some address is usable at NOW");
    for k in &r.keys {
        assert_eq!(k.fingerprint.len(), 40, "a v4 fingerprint: {}", k.fingerprint);
        let _ = (seal::pretty(&k.fingerprint), k.short());
    }
    let armored = seal::seal(b"report".to_vec(), &r, &ok, None, NOW).expect("a key that was taken must encrypt");
    assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
    let _ = r.split(u32::MAX);
}

/// The bot's signing key: whatever is taken signs mails that verify, and goes into a
/// well-formed Autocrypt header.
pub fn signing_key(data: &[u8]) {
    let Ok(s) = Signer::parse(data) else { return };
    let (public, _) = SignedPublicKey::from_reader_single(&s.public[..]).expect("its public key parses");
    let header = mime::autocrypt("alerts@example.org", &s.public);
    assert_lines(&header, "Autocrypt header");
    assert!(header.lines().skip(1).all(|l| l.starts_with(' ') && l.len() <= 78), "folded: {header}");
    let b = bot(Some(s), false);
    let mail = b.compose("signed", Content::Text("text".into()), &[ADMIN.to_string()]).expect("a signed mail");
    let inner = open(&assert_outer(&mail, true), Some(&public));
    assert_eq!(assert_inner_text(&inner).1, "text");
}
