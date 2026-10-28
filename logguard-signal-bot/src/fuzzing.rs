//! Entry points for the fuzz targets in `fuzz/` (cargo-fuzz, nightly) and for
//! `tests/fuzz_smoke.rs`, which runs the same functions on stable over the seeds. Each takes
//! arbitrary bytes, as signal-cli or the outbox could hand them over, and panics when an
//! invariant breaks.

use serde_json::Value;

use crate::bot::{self, Identity};
use crate::rpc::{self, Line, RpcError};

const ADMIN: &str = "+491701234567";

/// A line of signal-cli's output, and what the bot makes of it as a reply to `send` and to
/// `listIdentities`: never a panic; a safety number is always 60 digits.
pub fn cli_line(data: &[u8]) {
    let line = String::from_utf8_lossy(data);
    match rpc::parse_line(&line) {
        Line::Reply(_, r) => {
            let _ = bot::send_outcome(r.clone());
            if let Ok(v) = &r {
                if let Identity::Known { safety_number, .. } = bot::identity_of(v, ADMIN) {
                    assert_eq!(safety_number.len(), 60);
                    assert!(safety_number.bytes().all(|b| b.is_ascii_digit()));
                }
            }
            if let Err(RpcError::Remote { message, .. }) = &r {
                assert!(message.chars().count() <= 500);
            }
        }
        Line::Notification(m) => assert!(m.chars().count() <= 40),
        Line::Other => {}
    }
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        let _ = bot::send_outcome(Ok(v));
    }
}

/// An alert file's text as the outbox reads it: never a panic.
pub fn alert_file(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(body) = crate::outbox::parse_message(text) {
            assert!(text.ends_with(&body));
            let _ = bot::subject_len(&body);
        }
    }
}
