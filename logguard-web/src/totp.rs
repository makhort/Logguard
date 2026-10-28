//! Time-based one-time codes (RFC 6238 with HMAC-SHA-1, 6 digits, 30 seconds): the console's
//! second factor, as authenticator apps make them.

use hmac::{Hmac, Mac};

pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, as authenticator apps take secrets.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for b in bytes {
        buf = (buf << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes base32 (case, blanks and padding ignored).
pub fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = ALPHABET.iter().position(|a| *a as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// The code for time step `step` (RFC 4226's HOTP).
pub fn code(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The time step of a code typed at `unix_secs` that matches `typed`, one step of clock
/// difference allowed either way; only steps after `last_used`, so a code works once.
pub fn verify(secret: &[u8], typed: &str, unix_secs: u64, last_used: u64) -> Option<u64> {
    let typed = typed.trim();
    if typed.len() != DIGITS as usize || !typed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = typed.parse().ok()?;
    let now = unix_secs / STEP_SECS;
    let mut found = None;
    // every step is computed, so the time taken says nothing about which one matched
    for step in [now.saturating_sub(1), now, now + 1] {
        if code(secret, step) == want && step > last_used && found.is_none() {
            found = Some(step);
        }
    }
    found
}

fn percent(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// The `otpauth://` link authenticator apps take (as a QR code, or typed).
pub fn uri(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        percent(issuer),
        percent(account),
        base32(secret),
        percent(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_vectors() {
        // RFC 6238 appendix B (SHA-1), last 6 of its 8 digits
        let secret = b"12345678901234567890";
        for (t, want) in [(59u64, 287_082u32), (1_111_111_109, 81_804), (1_234_567_890, 5_924), (2_000_000_000, 279_037)] {
            assert_eq!(code(secret, t / STEP_SECS), want, "T={t}");
        }
        assert_eq!(verify(secret, "287082", 59, 0), Some(1));
        assert_eq!(verify(secret, "287082", 59 + 30, 0), Some(1), "one step late");
        assert_eq!(verify(secret, "287082", 59 + 60, 0), None, "two steps late");
        assert_eq!(verify(secret, "287082", 59, 1), None, "used already");
        assert_eq!(verify(secret, "28708", 59, 0), None);
        assert_eq!(verify(secret, "2870821", 59, 0), None);
        assert_eq!(verify(secret, "+87082", 59, 0), None);
    }

    #[test]
    fn base32_round_trip() {
        assert_eq!(base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(unbase32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap(), b"12345678901234567890");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(unbase32("MY======").unwrap(), b"f");
        assert!(unbase32("A1").is_none());
        assert!(
            uri(b"12345678901234567890", "logguard-web", "admin@xmpp").starts_with("otpauth://totp/logguard-web:admin%40xmpp?secret=GEZD")
        );
    }
}
