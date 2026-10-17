//! The mails, as PGP/MIME (RFC 3156): the whole content, headers included, is one OpenPGP
//! message. What the mail servers on the way see is the envelope and the outer headers:
//! sender, recipients, date, size, and a placeholder subject (`...`).
//!
//! The real subject, sender, recipients and date are repeated inside, as "protected headers"
//! (`protected-headers="v1"`, draft-ietf-lamps-header-protection): Thunderbird, K-9 /
//! Thunderbird for Android, FairEmail and Delta Chat show the inner subject in place of the
//! placeholder. The text is quoted-printable, so any line length and any character are fine.
//!
//! The text in alerts comes partly from attackers (user names they tried, URIs): it never
//! reaches a header unencoded, and its line breaks can't start a header or a MIME part
//! (quoted-printable turns every `=` into `=3D`, and every boundary has `=_` in it).

use base64::Engine;
use chrono::{DateTime, Utc};

/// The sender as the outer and inner `From:` show it.
#[derive(Clone, Debug)]
pub struct Sender {
    /// Plain ASCII without quotes or backslashes (checked by [`valid_name`]).
    pub name: String,
    pub address: String,
}

/// What the mail carries.
#[derive(Clone, Debug, PartialEq)]
pub enum Content {
    /// An alert, the digest, a text report: the mail's text.
    Text(String),
    /// Any other file: attached, with a line of text about it.
    File { name: String, data: Vec<u8> },
}

pub struct Mail<'a> {
    pub from: &'a Sender,
    pub to: &'a [String],
    pub subject: &'a str,
    pub content: Content,
    pub date: DateTime<Utc>,
    pub message_id: &'a str,
}

/// What the outer `Subject:` says by default (Thunderbird's choice; the real one is inside).
pub const PLACEHOLDER_SUBJECT: &str = "...";

/// A display name that needs no encoding: printable ASCII, no quote or backslash.
pub fn valid_name(name: &str) -> bool {
    name.len() <= 64 && name.chars().all(|c| c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ')
}

/// A mail address as headers and the SMTP envelope take it: `local@domain`, printable ASCII,
/// none of the characters that would end or split a header or an address list.
pub fn valid_address(a: &str) -> bool {
    let Some((local, domain)) = a.rsplit_once('@') else { return false };
    !local.is_empty()
        && !domain.is_empty()
        && a.len() <= 254
        && (domain.contains('.') || domain == "localhost")
        && a.chars().all(|c| c.is_ascii_graphic() && !"<>()[]\\,;:\"".contains(c))
        && !local.starts_with('-')
}

fn mailbox(s: &Sender) -> String {
    format!("\"{}\" <{}>", s.name, s.address)
}

/// A boundary that can't occur in base64, armor or quoted-printable text: `=_` is in it.
pub fn boundary(tag: &str) -> String {
    format!("=_{tag}_{:032x}", rand::random::<u128>())
}

/// A Message-ID for the sender's domain: random, nothing about the content or the host.
pub fn message_id(from: &str) -> String {
    let domain = from.rsplit_once('@').map_or("localhost", |(_, d)| d);
    format!("<{:032x}@{domain}>", rand::random::<u128>())
}

/// A header value from text that may hold anything: one line, no control characters, at
/// most 200 characters; non-ASCII as RFC 2047 encoded words (base64, UTF-8), folded.
pub fn header_text(text: &str) -> String {
    let clean: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    let clean = clean.trim();
    // ASCII as it is, unless it holds "=?": a reader would decode that as an encoded word
    // and show something else (found by fuzzing)
    if clean.is_ascii() && !clean.contains("=?") {
        return clean.to_string();
    }
    // whole characters, at most 45 bytes per word: each word stays within 75 characters
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in clean.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(std::mem::take(&mut chunk));
        }
        chunk.push(c);
    }
    words.push(chunk);
    words.iter().map(|w| format!("=?utf-8?b?{}?=", base64::engine::general_purpose::STANDARD.encode(w))).collect::<Vec<_>>().join("\r\n ")
}

/// Text as quoted-printable with CRLF line ends.
fn qp(text: &str) -> String {
    let crlf = text.replace("\r\n", "\n").replace('\n', "\r\n");
    quoted_printable::encode_to_str(crlf)
}

/// Base64 in lines of 76.
fn base64_lines(data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    b64.as_bytes().chunks(76).map(|l| std::str::from_utf8(l).unwrap_or_default()).collect::<Vec<_>>().join("\r\n")
}

/// A file name for the attachment: letters, digits, `.`, `-`, `_` only.
pub fn safe_file_name(name: &str) -> String {
    let n: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || ".-_".contains(c) { c } else { '_' }).take(80).collect();
    let n = n.trim_start_matches('.');
    if n.is_empty() {
        "file".into()
    } else {
        n.to_string()
    }
}

fn common_headers(m: &Mail, subject: &str) -> String {
    format!(
        "From: {}\r\nTo: {}\r\nSubject: {subject}\r\nDate: {}\r\nMessage-ID: {}\r\n",
        mailbox(m.from),
        // one address per line: a header line must stay under 998 characters
        m.to.join(",\r\n "),
        m.date.to_rfc2822(),
        m.message_id
    )
}

/// The MIME entity that gets encrypted: the content with the protected headers.
pub fn inner(m: &Mail) -> Vec<u8> {
    let headers = common_headers(m, &header_text(m.subject));
    let out = match &m.content {
        Content::Text(text) => format!(
            "Content-Type: text/plain; charset=\"utf-8\"; protected-headers=\"v1\"\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n{headers}\r\n{}\r\n",
            qp(text)
        ),
        Content::File { name, data } => {
            let b = boundary("logguard-file");
            let name = safe_file_name(name);
            format!(
                "Content-Type: multipart/mixed; boundary=\"{b}\"; protected-headers=\"v1\"\r\n{headers}\r\n\
                 --{b}\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}\r\n\
                 --{b}\r\nContent-Type: application/octet-stream; name=\"{name}\"\r\n\
                 Content-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n\
                 --{b}--\r\n",
                qp(&format!("logguard sent {name} ({} bytes), attached.", data.len())),
                base64_lines(data)
            )
        }
    };
    out.into_bytes()
}

/// The `Autocrypt:` header (autocrypt.org, Level 1) with the bot's public key: clients that
/// read it learn the key and show the signature as valid.
pub fn autocrypt(address: &str, public_key: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    let lines: Vec<&str> = b64.as_bytes().chunks(76).map(|l| std::str::from_utf8(l).unwrap_or_default()).collect();
    format!("Autocrypt: addr={address}; prefer-encrypt=mutual; keydata=\r\n {}\r\n", lines.join("\r\n "))
}

/// The mail as it goes out: outer headers and the encrypted content (`armored`, an ASCII
/// armored OpenPGP message of [`inner`]). All ASCII, CRLF line ends.
pub fn outer(m: &Mail, outer_subject: &str, armored: &str, autocrypt_header: Option<&str>) -> Vec<u8> {
    let b = boundary("logguard");
    let armored = armored.trim_end().replace("\r\n", "\n").replace('\n', "\r\n");
    format!(
        "{}MIME-Version: 1.0\r\nAuto-Submitted: auto-generated\r\n{}\
         Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n boundary=\"{b}\"\r\n\r\n\
         This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n\
         --{b}\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\r\n\
         --{b}\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Description: OpenPGP encrypted message\r\n\
         Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n{armored}\r\n\r\n--{b}--\r\n",
        common_headers(m, &header_text(outer_subject)),
        autocrypt_header.unwrap_or("")
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Sender {
        Sender { name: "logguard".into(), address: "alerts@example.org".into() }
    }

    fn mail<'a>(from: &'a Sender, to: &'a [String], subject: &'a str, content: Content) -> Mail<'a> {
        let date = DateTime::parse_from_rfc3339("2026-10-19T06:20:00Z").unwrap().with_timezone(&Utc);
        Mail { from, to, subject, content, date, message_id: "<1@example.org>" }
    }

    /// Headers (unfolded) and body of a MIME entity.
    fn split(entity: &str) -> (Vec<(String, String)>, String) {
        let (head, body) = entity.split_once("\r\n\r\n").unwrap();
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in head.split("\r\n") {
            if let Some(rest) = line.strip_prefix(' ') {
                let v = &mut headers.last_mut().unwrap().1;
                v.push_str(if v.ends_with(',') { " " } else { "" });
                v.push_str(rest);
            } else {
                let (k, v) = line.split_once(": ").unwrap();
                headers.push((k.to_string(), v.to_string()));
            }
        }
        (headers, body.to_string())
    }

    #[test]
    fn hostile_text_stays_text() {
        let from = sender();
        let to = vec!["admin@example.org".to_string()];
        // what an attacker can put into an alert: line breaks, a fake header, a fake boundary
        let subject = "[xmpp] logguard: account under attack\r\nBcc: evil@example.net\n";
        let body =
            "Account x\r\nContent-Type: text/html\r\n\r\n--=_logguard_0\r\n.\r\n<script>\n".to_string() + &"long ".repeat(400) + "→ ✓";
        let m = mail(&from, &to, subject, Content::Text(body.clone()));
        let inner = String::from_utf8(inner(&m)).unwrap();
        let (headers, qp_body) = split(&inner);
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["Content-Type", "Content-Transfer-Encoding", "From", "To", "Subject", "Date", "Message-ID"]);
        assert_eq!(headers[4].1, "[xmpp] logguard: account under attack  Bcc: evil@example.net", "one line");
        assert!(headers[0].1.contains("protected-headers=\"v1\""));
        assert!(!qp_body.contains("--=_"), "no boundary-like line survives quoted-printable");
        assert!(qp_body.split("\r\n").all(|l| l.len() <= 76), "short lines");
        let decoded = quoted_printable::decode(qp_body.trim_end(), quoted_printable::ParseMode::Strict).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), body.replace("\r\n", "\n").replace('\n', "\r\n"));
    }

    #[test]
    fn non_ascii_subjects_are_encoded_words() {
        let s = header_text("[xmpp] logguard: Konto zagrożone → ✓ ".repeat(3).as_str());
        assert!(s.is_ascii());
        for line in s.split("\r\n") {
            assert!(line.len() <= 76, "{line}");
        }
        let decoded: String = s
            .split("\r\n ")
            .map(|w| {
                let b64 = w.strip_prefix("=?utf-8?b?").unwrap().strip_suffix("?=").unwrap();
                String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b64).unwrap()).unwrap()
            })
            .collect();
        assert_eq!(decoded, "[xmpp] logguard: Konto zagrożone → ✓ ".repeat(3).trim());
        assert_eq!(header_text("plain"), "plain");
        // text that a reader would decode as an encoded word is encoded itself
        let fake = header_text("=?utf-8?b?ZmFrZQ==?= subject");
        assert!(fake.starts_with("=?utf-8?b?") && !fake.contains("ZmFrZQ==?= "), "{fake}");
        assert_eq!(header_text(&"x".repeat(500)).len(), 200);
    }

    #[test]
    fn the_outer_mail_shows_nothing_of_the_content() {
        let from = sender();
        let to = vec!["a@example.org".to_string(), "b@example.org".to_string()];
        let m = mail(&from, &to, "[vpn] logguard: secret subject", Content::Text("body".into()));
        let armored = "-----BEGIN PGP MESSAGE-----\n\nwcBMA0\n=abcd\n-----END PGP MESSAGE-----\n";
        let ac = autocrypt("alerts@example.org", &[7u8; 200]);
        let out = String::from_utf8(outer(&m, PLACEHOLDER_SUBJECT, armored, Some(&ac))).unwrap();
        assert!(out.is_ascii());
        assert!(!out.contains("secret") && !out.contains("vpn"), "{out}");
        assert!(!out.replace("\r\n", "").contains('\n'), "CRLF only");
        let (headers, body) = split(&out);
        let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("Subject"), "...");
        assert_eq!(get("From"), "\"logguard\" <alerts@example.org>");
        assert_eq!(get("To"), "a@example.org, b@example.org", "folded, one address per line");
        assert!(out.contains("\r\nTo: a@example.org,\r\n b@example.org\r\n"));
        assert_eq!(get("Date"), "Mon, 19 Oct 2026 06:20:00 +0000");
        assert_eq!(get("Auto-Submitted"), "auto-generated");
        let ct = get("Content-Type");
        assert!(ct.starts_with("multipart/encrypted; protocol=\"application/pgp-encrypted\";"), "{ct}");
        let b = ct.split("boundary=\"").nth(1).unwrap().trim_end_matches('"');
        let parts: Vec<&str> = body.split(&format!("--{b}")).collect();
        assert_eq!(parts.len(), 4, "preamble, two parts, the end");
        assert!(parts[1].contains("Content-Type: application/pgp-encrypted") && parts[1].contains("\r\nVersion: 1\r\n"));
        assert!(parts[2].contains("\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMA0\r\n=abcd\r\n-----END PGP MESSAGE-----\r\n"));
        assert_eq!(parts[3], "--\r\n");
        let key = get("Autocrypt");
        assert!(key.starts_with("addr=alerts@example.org; prefer-encrypt=mutual; keydata="), "{key}");
        let data = key.split("keydata=").nth(1).unwrap().replace(' ', "");
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(data).unwrap(), [7u8; 200]);
    }

    #[test]
    fn files_that_are_not_text_are_attached() {
        let from = sender();
        let to = vec!["a@example.org".to_string()];
        let data = vec![0xff, 0x00, 0xfe, b'\n'];
        let m = mail(&from, &to, "s", Content::File { name: "../x y.bin".into(), data: data.clone() });
        let inner = String::from_utf8(inner(&m)).unwrap();
        assert!(inner.starts_with("Content-Type: multipart/mixed; boundary=\"=_logguard-file_"));
        assert!(inner.contains("filename=\"_x_y.bin\""), "{inner}");
        let b64 = inner.split("Content-Transfer-Encoding: base64\r\n\r\n").nth(1).unwrap().split("\r\n").next().unwrap();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(b64).unwrap(), data);
        assert!(inner.ends_with("--\r\n"));
    }

    #[test]
    fn addresses_and_names() {
        assert!(valid_address("alerts@example.org"));
        assert!(valid_address("root@localhost"));
        assert!(!valid_address("a@b"), "a domain with a dot");
        assert!(!valid_address("a b@example.org"));
        assert!(!valid_address("a@example.org>, evil@example.net"));
        assert!(!valid_address("-oX@example.org"));
        assert!(!valid_address("example.org"));
        assert!(valid_name("logguard (xmpp)"));
        assert!(!valid_name("a\"b"));
        assert!(!valid_name("zagrożone"));
        assert!(message_id("alerts@example.org").ends_with("@example.org>"));
        assert_ne!(boundary("x"), boundary("x"));
    }
}
