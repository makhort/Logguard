//! What the fuzz targets in `fuzz/` run (`cargo +nightly fuzz run omemo_decrypt`, ...). Each
//! takes what another XMPP client controls: the OMEMO messages and bundles of anyone who
//! writes to the bot, and the XML they come in. None of it may panic or hang.
//! `tests/fuzz_smoke.rs` runs the same functions on stable, so `cargo test` keeps them working.

use std::path::PathBuf;

use tokio_xmpp::minidom::Element;
use tokio_xmpp::parsers::legacy_omemo::{Bundle, DeviceList, Encrypted, Header, Key, Payload, IV};

use crate::omemo::crypto::PublicKey;
use crate::omemo::wire::{PreKeyWhisperMessage, WhisperMessage};
use crate::omemo::Omemo;

/// The OMEMO wire format (libsignal's protobuf messages). What parses must serialize back to
/// the same message.
pub fn wire(data: &[u8]) {
    let _ = PublicKey::parse(data);
    if let Ok(m) = WhisperMessage::parse(data) {
        let _ = m.verify_mac(&[7; 32], &m.ratchet_key, &m.ratchet_key);
    }
    if let Ok(m) = PreKeyWhisperMessage::parse(data) {
        assert_eq!(PreKeyWhisperMessage::parse(&m.serialize()).as_ref(), Ok(&m), "serialize(parse(x)) parses differently");
    }
}

/// A bot device, its store in a temporary directory, receiving fuzzed messages.
pub struct Device {
    pub store: Omemo,
    signed_pre_key: u32,
    pre_keys: Vec<u32>,
    dir: PathBuf,
}

impl Device {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "logguard-xmpp-bot-fuzz-{}-{:x}",
            std::process::id(),
            crate::omemo::crypto::random::<8>()[0]
        ));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        let store = Omemo::open(&dir.join("omemo.json"), 1_780_000_000).expect("new OMEMO store");
        let bundle = store.bundle();
        let signed_pre_key = bundle.signed_pre_key_public.as_ref().and_then(|s| s.signed_pre_key_id).unwrap_or(0);
        let pre_keys = bundle.prekeys.map(|p| p.keys.iter().map(|k| k.pre_key_id).collect()).unwrap_or_default();
        Device { store, signed_pre_key, pre_keys, dir }
    }
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn key(bytes: &[u8]) -> PublicKey {
    let mut k = [0u8; 32];
    k[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    PublicKey(k)
}

/// An encrypted message to the bot. The first byte picks the shape: a message as sent, or
/// (odd) a session start built on the device's real prekey ids, so the key agreement runs
/// on fuzzed keys (low-order points, zeros) and a fuzzed first message.
pub fn decrypt(device: &mut Device, data: &[u8]) {
    let Some((&shape, rest)) = data.split_first() else { return };
    let (prekey, key_data) = if shape & 1 == 1 && rest.len() >= 66 && !device.pre_keys.is_empty() {
        let pre_key_id = device.pre_keys[rest[64] as usize % device.pre_keys.len()];
        let inner = WhisperMessage::new(
            &[0; 32],
            key(&rest[..32]),
            u32::from(rest[65]),
            0,
            rest[66..].to_vec(),
            &key(&rest[32..64]),
            &key(&rest[..32]),
        );
        let m = PreKeyWhisperMessage {
            registration_id: 1,
            pre_key_id,
            signed_pre_key_id: device.signed_pre_key,
            base_key: key(&rest[..32]),
            identity_key: key(&rest[32..64]),
            message: inner,
        };
        (true, m.serialize())
    } else {
        (shape & 2 != 0, rest.to_vec())
    };
    let encrypted = Encrypted {
        header: Header {
            sid: 1000 + u32::from(shape >> 2),
            keys: vec![Key { rid: device.store.device_id(), prekey, data: key_data }],
            iv: IV { data: rest.iter().take(12).copied().collect() },
        },
        payload: (shape & 4 != 0).then(|| Payload { data: rest.to_vec() }),
    };
    let _ = device.store.decrypt_if("fuzz@example.org", &encrypted, |_| true);
}

/// XML from another client: an `<encrypted>` message, a device list or a bundle (which the
/// bot also starts a session from), and logguard's outbox messages.
pub fn stanza(device: &mut Device, data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = crate::outbox::parse_message(&text);
    let _ = crate::outbox::summary(&text);
    let Ok(el) = text.parse::<Element>() else { return };
    if let Ok(e) = Encrypted::try_from(el.clone()) {
        let _ = device.store.decrypt_if("fuzz@example.org", &e, |_| true);
    }
    let _ = DeviceList::try_from(el.clone());
    if let Ok(bundle) = Bundle::try_from(el) {
        let _ = Omemo::bundle_identity(&bundle);
        if device.store.start_session("peer@example.org", 7, &bundle).is_ok() {
            let _ = device.store.encrypt("peer@example.org", &[7], Some("reply"));
        }
    }
}
