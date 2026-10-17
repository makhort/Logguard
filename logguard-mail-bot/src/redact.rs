//! Optional here (`SANITIZE=on`): the mails are encrypted end to end, so they may carry
//! account names. With it on, they don't, as on Telegram (this is logguard-tg-bot's code).
//!
//! logguard's admin alerts name accounts (`account alice@example.org registered from …`,
//! `ejabberd:alice@example.org under distributed attack`, ejabberd log lines as evidence).
//! Each becomes a pseudonym, `[acct:1a2b3c]`: the first 24 bits of an HMAC-SHA-256 of the
//! bare address under a key that stays on the server (`pseudonym.key`). The same account
//! gets the same pseudonym in every message, so repeated attacks on one account still show,
//! and only someone with the key can tell which account it is (`logguard-mail-bot pseudonym <jid>` on
//! the server). A plain hash would not do: account names are few and easy to guess.
//!
//! Every address-like `local@domain` in an alert is replaced, with its `/resource`, and so is
//! the name in `ejabberd:<name>` (a bare user name counts as on the first of `XMPP_DOMAINS`).
//! A local part is everything back to a blank or a character XMPP forbids in one
//! (`"&'/:<>@`, RFC 7622 / nodeprep): account names may contain `( ) [ ] { } , ; = |`, so
//! stopping at those would show part of a name. Leading brackets are left outside, so
//! `(alice@x)` and `alice@x` get the same pseudonym. Matching too much only hides more.
//! Files (the weekly abuse report) aren't touched, as on Telegram: only alerts and digests.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct Pseudonyms {
    key: [u8; 32],
    /// Lower case, without leading or trailing dots.
    domains: Vec<String>,
}

/// What can be part of an account name: anything but blanks, control characters and what
/// XMPP forbids in a local part.
fn local_char(c: char) -> bool {
    !c.is_whitespace() && !c.is_control() && !"\"&'/:<>@".contains(c)
}

/// Punctuation left outside a name when it starts it (`(alice@x)`) or ends it (`ejabberd:bob,`).
const OPENERS: &[char] = &['(', '[', '{'];
const CLOSERS: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}'];

fn domain_char(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

/// Where a resource (`/Conversations.x1Yz`) ends in running text.
fn token_end(c: char) -> bool {
    c.is_whitespace() || "\"'<>)]},;".contains(c)
}

/// `[acct:` + 6 hex digits + `]`.
pub const PSEUDONYM_LEN: usize = 13;

/// Whether `s` starts with a pseudonym as [`Pseudonyms::tag`] makes them.
pub fn is_pseudonym(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= PSEUDONYM_LEN && b.starts_with(b"[acct:") && b[6..12].iter().all(u8::is_ascii_hexdigit) && b[12] == b']'
}

/// Where a pseudonym starts in `s` after nothing but opening brackets (a pseudonym starts
/// with one itself), if one does.
pub fn pseudonym_after_openers(s: &str) -> Option<usize> {
    let lead = s.len() - s.trim_start_matches(OPENERS).len();
    (0..=lead).find(|&k| is_pseudonym(&s[k..]))
}

pub fn parse_domains(list: &str) -> Vec<String> {
    list.split([',', ' ']).map(|d| d.trim().trim_matches('.').to_lowercase()).filter(|d| !d.is_empty()).collect()
}

impl Pseudonyms {
    pub fn new(key: [u8; 32], domains: Vec<String>) -> Self {
        Pseudonyms { key, domains }
    }

    /// The key from `path`, which must be there already (the one-off commands, run as root,
    /// must not make a key the service then can't read).
    pub fn load(path: &Path, domains: Vec<String>) -> std::io::Result<Self> {
        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{}: no key yet; the service makes it on its first start with SANITIZE=on", path.display()),
            ));
        }
        Self::load_or_create(path, domains)
    }

    /// The key from `path` (64 hex digits), or a new random one written there (mode 600).
    pub fn load_or_create(path: &Path, domains: Vec<String>) -> std::io::Result<Self> {
        let bad = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {why}", path.display()));
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let hex = text.trim();
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("expected 64 hex digits"));
                }
                let mut key = [0u8; 32];
                for (i, k) in key.iter_mut().enumerate() {
                    *k = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad("expected 64 hex digits"))?;
                }
                Ok(Self::new(key, domains))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key: [u8; 32] = rand::random();
                let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
                f.write_all(format!("{hex}\n").as_bytes())?;
                f.sync_all()?;
                log::info!("new pseudonym key in {}", path.display());
                Ok(Self::new(key, domains))
            }
            Err(e) => Err(e),
        }
    }

    /// The pseudonym of an account (a bare or full JID, or a user name on the first XMPP domain).
    pub fn tag(&self, account: &str) -> String {
        let mut a = account.trim().to_lowercase();
        if let Some(i) = a.find('/') {
            a.truncate(i);
        }
        if !a.contains('@') {
            if let Some(d) = self.domains.first() {
                a = format!("{a}@{d}");
            }
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key length");
        mac.update(a.as_bytes());
        let out = mac.finalize().into_bytes();
        format!("[acct:{:02x}{:02x}{:02x}]", out[0], out[1], out[2])
    }

    /// An admin alert: every address, and `ejabberd:<name>`.
    pub fn alert(&self, text: &str) -> String {
        self.prefixed(&self.addresses(text))
    }

    /// Replaces every `local@domain[/resource]`. Addresses that touch or overlap (`a@b@x.org`,
    /// `a@x.org,b@y.org`, `a@x{@y`) become one pseudonym: nothing between them is left
    /// readable. Each `@` scans back only to the last non-name character and forward only over
    /// its domain, so the work stays linear in the text.
    fn addresses(&self, text: &str) -> String {
        let cs: Vec<(usize, char)> = text.char_indices().collect();
        let at = |k: usize| cs.get(k).map_or(text.len(), |c| c.0);
        // (start, end of the bare address, end with the resource), in characters
        let mut spans: Vec<(usize, usize, usize)> = Vec::new();
        for i in 0..cs.len() {
            // an `@` inside the last address's resource belongs to it already
            if cs[i].1 != '@' || spans.last().is_some_and(|s| i < s.2) {
                continue;
            }
            let mut l = i;
            while l > 0 && local_char(cs[l - 1].1) {
                l -= 1;
            }
            while l < i && OPENERS.contains(&cs[l].1) {
                l += 1;
            }
            let mut r = i + 1;
            while r < cs.len() && domain_char(cs[r].1) {
                r += 1;
            }
            // a full stop or dash after the address is punctuation
            while r > i + 1 && matches!(cs[r - 1].1, '.' | '-') {
                r -= 1;
            }
            if l == i || !text[at(i + 1)..at(r)].chars().any(char::is_alphanumeric) {
                continue;
            }
            let mut end = r;
            if cs.get(end).is_some_and(|c| c.1 == '/') {
                while end < cs.len() && !token_end(cs[end].1) {
                    end += 1;
                }
            }
            match spans.last_mut() {
                Some(last) if l <= last.2 => {
                    last.1 = last.1.max(r);
                    last.2 = last.2.max(end);
                }
                _ => spans.push((l, r, end)),
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut copied = 0; // bytes of `text` already in `out`
        for (l, r, end) in spans {
            out.push_str(&text[copied..at(l)]);
            out.push_str(&self.tag(&text[at(l)..at(r)]));
            copied = at(end);
        }
        out.push_str(&text[copied..]);
        out
    }

    /// Replaces the name in `ejabberd:<name>` (logguard's account label) where it is not an
    /// address (those are pseudonyms by now).
    fn prefixed(&self, text: &str) -> String {
        const PREFIX: &str = "ejabberd:";
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(p) = rest.find(PREFIX) {
            let after = p + PREFIX.len();
            out.push_str(&rest[..after]);
            let tail = &rest[after..];
            // a pseudonym already (an address replaced above), maybe in brackets
            if let Some(k) = pseudonym_after_openers(tail) {
                out.push_str(&tail[..k + PSEUDONYM_LEN]);
                rest = &tail[k + PSEUDONYM_LEN..];
                continue;
            }
            let n = tail.find(|c: char| !local_char(c)).unwrap_or(tail.len());
            let token = &tail[..n];
            // brackets around it stay outside, as for addresses: `ejabberd:(bob)`
            let lead = token.len() - token.trim_start_matches(OPENERS).len();
            let name = token[lead..].trim_end_matches(CLOSERS);
            if !name.is_empty() {
                out.push_str(&token[..lead]);
                out.push_str(&self.tag(name));
                out.push_str(&token[lead + name.len()..]);
            } else {
                out.push_str(token);
            }
            rest = &tail[n..];
        }
        out.push_str(rest);
        out
    }
}

/// An alert with account names and the servers' own addresses and names replaced. The
/// accounts go first (so a pseudonym is the account's, whatever servers it names), then the
/// servers, then the accounts once more: a server replaced by its node id can complete an
/// address (`admin@::ffff:192.0.2.10` becomes `admin@xmpp`; found by fuzzing).
pub fn sanitize(names: &Pseudonyms, servers: &crate::servers::ServerNames, text: &str) -> String {
    names.alert(&servers.replace(&names.alert(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_replaced_cant_complete_an_address() {
        let names = Pseudonyms::new([7; 32], parse_domains("example.org"));
        let servers = crate::servers::ServerNames::parse("xmpp=192.0.2.10").unwrap();
        let out = sanitize(&names, &servers, "admin@::ffff:192.0.2.10 and alice@example.org");
        assert!(!out.contains("admin") && !out.contains("alice"), "{out}");
        assert!(out.ends_with(&format!("and {}", names.tag("alice@example.org"))), "pseudonyms stay the accounts': {out}");
    }

    fn p() -> Pseudonyms {
        Pseudonyms::new([7; 32], parse_domains("example.org, .Example.org."))
    }

    #[test]
    fn same_account_same_pseudonym() {
        let p = p();
        let t = p.tag("alice@example.org");
        assert!(t.starts_with("[acct:") && t.len() == "[acct:123456]".len(), "{t}");
        assert_eq!(p.tag("Alice@example.org/phone"), t, "case and resource don't matter");
        assert_eq!(p.tag("alice"), t, "a bare user name is on the first domain");
        assert_ne!(p.tag("bob@example.org"), t);
        assert_ne!(Pseudonyms::new([8; 32], vec![]).tag("alice@example.org"), t, "keyed");
        assert_eq!(parse_domains("example.org, .Example.org."), ["example.org", "example.org"]);
    }

    #[test]
    fn alerts_lose_every_account_name() {
        let p = p();
        let a = p.tag("alice@example.org");
        let b = p.tag("user5@x");
        let text = "[xmpp] logguard: new registration\n\n\
            [Info] account alice@example.org registered from 1.2.3.4.\n\
            [High] account ejabberd:alice@example.org under distributed attack: ~40 failures from 9 addresses\n\
            ejabberd:user5@x logged in from a new network: Australia - 1.0.0.7\n\
              10-16 12:00:01 Failed c2s SCRAM-SHA-256 authentication for Alice@example.org/Conversations.x1Yz from ::ffff:5.6.7.8\n\
              (user \"alice@example.org\"), <alice@example.org>; ejabberd:bob, ejabberd:carol.\n\
            service ejabberd: restarted; mail to abuse@hetzner.de";
        let out = p.alert(text);
        for name in ["alice", "Alice", "user5", "bob", "carol", "Conversations", "hetzner"] {
            assert!(!out.contains(name), "{name} left in:\n{out}");
        }
        assert!(out.contains(&format!("account {a} registered from 1.2.3.4.")), "{out}");
        assert!(out.contains(&format!("account ejabberd:{a} under")), "{out}");
        assert!(out.contains(&format!("ejabberd:{b} logged in")), "{out}");
        assert!(out.contains(&format!("authentication for {a} from ::ffff:5.6.7.8")), "resource gone: {out}");
        assert!(out.contains(&format!("(user \"{a}\"), <{a}>; ejabberd:{}, ejabberd:{}.", p.tag("bob"), p.tag("carol"))), "{out}");
        assert!(out.contains("service ejabberd: restarted"), "not an account label: {out}");
        assert!(out.starts_with("[xmpp] logguard: new registration\n\n[Info]"));
        assert_eq!(p.alert(&out), out, "pseudonyms stay as they are");
    }

    #[test]
    fn names_with_punctuation_are_hidden_whole() {
        let p = p();
        let tag = |a: &str| p.tag(a);
        let out = p.alert(
            "for bob(1)@example.org from x; a,b@example.org; x=y|z@example.org/res tried; \
             [alice@example.org] (alice@example.org), {alice@example.org}; \
             ejabberd:a,b ejabberd:bob, ejabberd:c(d) and ejabberd:e;f.",
        );
        for name in ["bob(1)", "(1)", "a,b", "x=y", "y|z", "res", "c(d", "e;f"] {
            assert!(!out.contains(name), "{name} left in: {out}");
        }
        assert!(out.contains(&format!("for {} from x; {};", tag("bob(1)@example.org"), tag("a,b@example.org"))), "{out}");
        let a = tag("alice@example.org");
        assert!(out.contains(&format!("[{a}] ({a}), {{{a}}};")), "brackets around stay outside: {out}");
        assert!(out.contains(&format!("ejabberd:{} ejabberd:{}, ", tag("a,b"), tag("bob"))), "{out}");
        assert_eq!(p.alert("x a@b@example.org y"), format!("x {} y", tag("a@b@example.org")), "two @: one pseudonym");
        assert_eq!(p.alert("x a@x{@y z"), format!("x {} z", tag("a@x{@y")), "touching: one pseudonym");
        assert_eq!(p.alert("a@x.org,b@y.org"), tag("a@x.org,b@y.org"));
        // something that only looks like the start of a pseudonym hides nothing after it
        let out = p.alert("ejabberd:[acct: x ejabberd:carol ]");
        assert!(!out.contains("carol"), "{out}");
        assert_eq!(
            p.alert("ejabberd:(bob) ejabberd:((((@1(("),
            format!("ejabberd:({}) ejabberd:((((@1((", tag("bob")),
            "brackets alone are no name"
        );
        // linear: many @ in a row don't rescan the text
        let many = "a@".repeat(50_000) + "example.org";
        let t = std::time::Instant::now();
        assert!(p.alert(&many).starts_with("[acct:"));
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
        assert_eq!(p.alert(&out), out, "pseudonyms stay as they are");
    }

    #[test]
    fn non_ascii_text_survives() {
        let p = p();
        let out = p.alert("Привіт → юзер@example.org ✓ ünïcode@exämple.org.");
        assert_eq!(out, format!("Привіт → {} ✓ {}.", p.tag("юзер@example.org"), p.tag("ünïcode@exämple.org")));
    }

    #[test]
    fn key_file() {
        let dir = std::env::temp_dir().join(format!("logguard-mail-bot-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pseudonym.key");
        let first = Pseudonyms::load_or_create(&path, vec![]).unwrap().tag("alice@x");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Pseudonyms::load_or_create(&path, vec![]).unwrap().tag("alice@x"), first, "the same key next time");
        std::fs::write(&path, "short\n").unwrap();
        assert!(Pseudonyms::load_or_create(&path, vec![]).is_err(), "a broken key is not replaced");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
