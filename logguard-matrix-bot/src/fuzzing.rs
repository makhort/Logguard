//! Entry points for the fuzz targets in `fuzz/` (cargo-fuzz, nightly) and for
//! `tests/fuzz_smoke.rs`, which runs the same functions on stable over the seeds. Each takes
//! arbitrary bytes, as the homeserver or the outbox could hand them over, and panics when an
//! invariant breaks. Under cargo-fuzz vodozemac accepts every signature (its `fuzzing` cfg),
//! so the targets reach past the checks; `crypto`'s tests cover the checks themselves.

use serde_json::Value;

use crate::crypto;

const ADMIN: &str = "@admin:example.org";

/// A `/keys/query` reply (whatever the homeserver says) through the checks: never a panic,
/// and only devices that sign themselves come out, each cross-signed one among them.
pub fn keys_query(data: &[u8]) {
    let Ok(reply) = serde_json::from_slice::<Value>(data) else { return };
    let keys = crypto::user_keys(&reply, ADMIN);
    for d in &keys.devices {
        let raw = &reply["device_keys"][ADMIN][&d.device_id];
        assert!(crypto::verify(raw, ADMIN, &format!("ed25519:{}", d.device_id), &d.ed25519), "a device that doesn't sign itself");
    }
    for id in &keys.cross_signed {
        assert!(keys.devices.iter().any(|d| &d.device_id == id), "cross-signed but not a valid device: {id}");
    }
    if keys.master.is_none() {
        assert!(keys.cross_signed.is_empty(), "cross-signed without a master key");
    }
    for d in &keys.devices {
        let _ = crypto::claimed_key(&reply, ADMIN, d);
    }
}

/// An alert file's text as the outbox reads it: never a panic.
pub fn alert_file(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(body) = crate::outbox::parse_message(text) {
            assert!(text.ends_with(&body));
        }
    }
}

/// An attachment round trip: what goes in comes out, and a flipped byte is caught.
pub fn attachment(data: &[u8]) {
    let (ciphertext, file) = crypto::encrypt_attachment(data);
    assert_eq!(crypto::decrypt_attachment(&ciphertext, &file).as_deref(), Some(data));
    if !ciphertext.is_empty() {
        let mut damaged = ciphertext.clone();
        damaged[data.len() / 2] ^= 0x40;
        assert!(crypto::decrypt_attachment(&damaged, &file).is_none());
    }
}
