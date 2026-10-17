//! OMEMO 0.3 (XEP-0384 v0.3, namespace `eu.siacs.conversations.axolotl`), the version
//! Conversations, Gajim, Dino and Monal speak: this device's keys, its sessions with
//! other devices, and the `<encrypted>` element.
//!
//! Written from the X3DH, Double Ratchet and XEdDSA specifications and XEP-0384 v0.3;
//! tests/omemo_oracle checks it against omemo-dr, Gajim's implementation.

pub mod crypto;
pub mod session;
pub mod trust;
pub mod wire;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use tokio_xmpp::parsers::legacy_omemo::{
    Bundle, Encrypted, Header, IdentityKey, Key, Payload, PreKeyPublic, Prekeys, SignedPreKeyPublic, SignedPreKeySignature, IV,
};

use crypto::{KeyPair, PublicKey};
use session::{SessionError, SessionRecord, SessionState, TheirBundle};
use wire::{PreKeyWhisperMessage, WhisperMessage};

pub const NS: &str = "eu.siacs.conversations.axolotl";
pub const DEVICELIST_NODE: &str = "eu.siacs.conversations.axolotl.devicelist";

pub fn bundle_node(device_id: u32) -> String {
    format!("eu.siacs.conversations.axolotl.bundles:{device_id}")
}

/// One-time prekeys published; topped up again below [`MIN_PRE_KEYS`] (Gajim's numbers).
const PRE_KEYS: usize = 100;
const MIN_PRE_KEYS: usize = 80;
/// Signed prekey lifetime, and how long a replaced one still answers late session starts.
const SIGNED_PRE_KEY_ROTATE: i64 = 30 * 86400;
const SIGNED_PRE_KEY_KEEP: i64 = 15 * 86400;
/// Device ids and key ids are 1..=2^31-1.
const MAX_ID: u32 = i32::MAX as u32;

#[derive(Debug)]
pub enum OmemoError {
    /// Our own message (a carbon or MAM copy).
    OwnMessage,
    /// Encrypted for other devices only.
    NotForUs,
    UnknownPreKey(u32),
    UnknownSignedPreKey(u32),
    Session(SessionError),
    Wire(wire::WireError),
    Body(crypto::CryptoError),
    BadBundle(&'static str),
    /// It decrypts, but the sending device's key is not trusted: nothing was saved, so a
    /// session with a trusted key of that device id stays as it was.
    Untrusted {
        device_id: u32,
        identity: PublicKey,
    },
    NoSessions,
    Save(anyhow::Error),
}

impl std::fmt::Display for OmemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OmemoError::OwnMessage => f.write_str("sent by this device"),
            OmemoError::NotForUs => f.write_str("not encrypted for this device"),
            OmemoError::UnknownPreKey(id) => write!(f, "unknown one-time prekey {id} (already used?)"),
            OmemoError::UnknownSignedPreKey(id) => write!(f, "unknown signed prekey {id}"),
            OmemoError::Session(e) => write!(f, "{e}"),
            OmemoError::Wire(e) => write!(f, "{e}"),
            OmemoError::Body(e) => write!(f, "message body: {e}"),
            OmemoError::BadBundle(what) => write!(f, "bad bundle: {what}"),
            OmemoError::Untrusted { identity, .. } => write!(f, "key {} is not trusted", identity.fingerprint()),
            OmemoError::NoSessions => f.write_str("no session with any of the devices"),
            OmemoError::Save(e) => write!(f, "saving OMEMO store: {e:#}"),
        }
    }
}

impl std::error::Error for OmemoError {}

impl From<SessionError> for OmemoError {
    fn from(e: SessionError) -> Self {
        OmemoError::Session(e)
    }
}

impl From<wire::WireError> for OmemoError {
    fn from(e: wire::WireError) -> Self {
        OmemoError::Wire(e)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct SignedPreKey {
    pair: KeyPair,
    signature: Vec<u8>,
    created: i64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Data {
    device_id: u32,
    identity: KeyPair,
    next_pre_key_id: u32,
    pre_keys: BTreeMap<u32, KeyPair>,
    current_signed_pre_key: u32,
    signed_pre_keys: BTreeMap<u32, SignedPreKey>,
    /// When the previous signed prekeys were replaced, by id.
    replaced_signed_pre_keys: BTreeMap<u32, i64>,
    /// bare JID -> device id -> session
    sessions: BTreeMap<String, BTreeMap<u32, SessionRecord>>,
}

/// A decrypted `<encrypted>` element.
#[derive(Debug, PartialEq)]
pub struct Decrypted {
    /// The sending device.
    pub device_id: u32,
    pub identity: PublicKey,
    /// None for a key transport message (it only sets up or advances the session).
    pub body: Option<String>,
    /// The message started a session and used up one of our one-time prekeys: the
    /// bundle should be republished.
    pub used_pre_key: bool,
}

/// This device's OMEMO state, saved (owner-only) after every change.
pub struct Omemo {
    path: PathBuf,
    data: Data,
}

fn random_id() -> u32 {
    (1..=MAX_ID).choose(&mut rand::rng()).expect("non-empty range")
}

fn next_id(id: u32) -> u32 {
    id % MAX_ID + 1
}

impl Omemo {
    /// Loads the store, or creates a new device (new id and identity key) when there is none.
    pub fn open(path: &Path, now: i64) -> Result<Self> {
        let data = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("{}: not a valid OMEMO store", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = KeyPair::generate();
                let spk = Self::new_signed_pre_key(&identity, now);
                let spk_id = random_id();
                Data {
                    device_id: random_id(),
                    identity,
                    next_pre_key_id: 1,
                    pre_keys: BTreeMap::new(),
                    current_signed_pre_key: spk_id,
                    signed_pre_keys: BTreeMap::from([(spk_id, spk)]),
                    replaced_signed_pre_keys: BTreeMap::new(),
                    sessions: BTreeMap::new(),
                }
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut omemo = Omemo { path: path.to_owned(), data };
        omemo.refresh_keys(now)?;
        Ok(omemo)
    }

    fn save(&self) -> Result<(), OmemoError> {
        let json = serde_json::to_vec(&self.data).map_err(|e| OmemoError::Save(e.into()))?;
        crate::state::write_private(&self.path, &json).map_err(OmemoError::Save)
    }

    fn new_signed_pre_key(identity: &KeyPair, now: i64) -> SignedPreKey {
        let pair = KeyPair::generate();
        let signature = identity.sign(&pair.public.serialize()).to_vec();
        SignedPreKey { pair, signature, created: now }
    }

    pub fn device_id(&self) -> u32 {
        self.data.device_id
    }

    pub fn fingerprint(&self) -> String {
        self.data.identity.public.fingerprint()
    }

    /// Tops up the one-time prekeys, rotates the signed prekey once it is 30 days old and
    /// forgets replaced ones after 15 days. True when the bundle changed.
    pub fn refresh_keys(&mut self, now: i64) -> Result<bool, OmemoError> {
        let mut changed = false;
        if self.data.pre_keys.len() < MIN_PRE_KEYS {
            while self.data.pre_keys.len() < PRE_KEYS {
                let id = self.data.next_pre_key_id;
                self.data.next_pre_key_id = next_id(id);
                self.data.pre_keys.insert(id, KeyPair::generate());
            }
            changed = true;
        }
        let current = self.data.current_signed_pre_key;
        // missing (a hand-edited store): replaced like an expired one
        if self.data.signed_pre_keys.get(&current).is_none_or(|k| k.created + SIGNED_PRE_KEY_ROTATE <= now) {
            let id = next_id(current);
            let spk = Self::new_signed_pre_key(&self.data.identity, now);
            self.data.signed_pre_keys.insert(id, spk);
            self.data.current_signed_pre_key = id;
            self.data.replaced_signed_pre_keys.insert(current, now);
            changed = true;
        }
        let expired: Vec<u32> =
            self.data.replaced_signed_pre_keys.iter().filter(|(_, &t)| t + SIGNED_PRE_KEY_KEEP <= now).map(|(&id, _)| id).collect();
        for id in expired {
            self.data.replaced_signed_pre_keys.remove(&id);
            self.data.signed_pre_keys.remove(&id);
            changed = true;
        }
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// The bundle to publish at [`bundle_node`].
    pub fn bundle(&self) -> Bundle {
        let id = self.data.current_signed_pre_key;
        let spk = &self.data.signed_pre_keys[&id];
        Bundle {
            signed_pre_key_public: Some(SignedPreKeyPublic { signed_pre_key_id: Some(id), data: spk.pair.public.serialize().to_vec() }),
            signed_pre_key_signature: Some(SignedPreKeySignature { data: spk.signature.clone() }),
            identity_key: Some(IdentityKey { data: self.data.identity.public.serialize().to_vec() }),
            prekeys: Some(Prekeys {
                keys: self
                    .data
                    .pre_keys
                    .iter()
                    .map(|(&id, k)| PreKeyPublic { pre_key_id: id, data: k.public.serialize().to_vec() })
                    .collect(),
            }),
        }
    }

    /// The identity key in someone's bundle, for the trust decision before
    /// [`Omemo::start_session`].
    pub fn bundle_identity(bundle: &Bundle) -> Result<PublicKey, OmemoError> {
        let ik = bundle.identity_key.as_ref().ok_or(OmemoError::BadBundle("no identity key"))?;
        PublicKey::parse(&ik.data).map_err(|_| OmemoError::BadBundle("identity key"))
    }

    /// Starts a session with `jid`'s device from its bundle, replacing any existing one.
    /// Checks the signed prekey's signature; picks a random one-time prekey.
    pub fn start_session(&mut self, jid: &str, device_id: u32, bundle: &Bundle) -> Result<(), OmemoError> {
        let identity = Self::bundle_identity(bundle)?;
        let spk = bundle.signed_pre_key_public.as_ref().ok_or(OmemoError::BadBundle("no signed prekey"))?;
        let sig = bundle.signed_pre_key_signature.as_ref().ok_or(OmemoError::BadBundle("no signature"))?;
        if !crypto::verify(&identity, &spk.data, &sig.data) {
            return Err(OmemoError::BadBundle("signed prekey signature does not verify"));
        }
        let prekey = bundle
            .prekeys
            .as_ref()
            .and_then(|p| p.keys.iter().filter(|k| (1..=MAX_ID).contains(&k.pre_key_id)).choose(&mut rand::rng()))
            .ok_or(OmemoError::BadBundle("no one-time prekeys"))?;
        let their = TheirBundle {
            identity,
            signed_pre_key_id: spk.signed_pre_key_id.unwrap_or(0),
            signed_pre_key: PublicKey::parse(&spk.data).map_err(|_| OmemoError::BadBundle("signed prekey"))?,
            pre_key_id: prekey.pre_key_id,
            pre_key: PublicKey::parse(&prekey.data).map_err(|_| OmemoError::BadBundle("one-time prekey"))?,
        };
        let state = SessionState::initiate(&self.data.identity, self.data.device_id, &their);
        let devices = self.data.sessions.entry(jid.to_owned()).or_default();
        match devices.get_mut(&device_id) {
            Some(record) => record.replace(state),
            None => {
                devices.insert(device_id, SessionRecord::new(state));
            }
        }
        self.save()
    }

    pub fn has_session(&self, jid: &str, device_id: u32) -> bool {
        self.data.sessions.get(jid).is_some_and(|d| d.contains_key(&device_id))
    }

    /// The identity key of `jid`'s device, as of our session with it.
    pub fn session_identity(&self, jid: &str, device_id: u32) -> Option<PublicKey> {
        Some(self.data.sessions.get(jid)?.get(&device_id)?.current.remote_identity)
    }

    /// Decrypts a message from `jid`, trusting any key.
    #[cfg(test)]
    pub fn decrypt(&mut self, jid: &str, encrypted: &Encrypted) -> Result<Decrypted, OmemoError> {
        self.decrypt_if(jid, encrypted, |_| true)
    }

    /// Decrypts a message from `jid`. The session changes are saved only when it decrypts
    /// and `trusted` accepts the sending device's identity key: an untrusted key never
    /// replaces a session or uses up a prekey.
    pub fn decrypt_if(&mut self, jid: &str, encrypted: &Encrypted, trusted: impl Fn(&PublicKey) -> bool) -> Result<Decrypted, OmemoError> {
        let sid = encrypted.header.sid;
        if sid == self.data.device_id {
            return Err(OmemoError::OwnMessage);
        }
        let key = encrypted.header.keys.iter().find(|k| k.rid == self.data.device_id).ok_or(OmemoError::NotForUs)?;
        let existing = self.data.sessions.get(jid).and_then(|d| d.get(&sid));

        let (record, key_material, used_pre_key) = if key.prekey {
            let msg = PreKeyWhisperMessage::parse(&key.data)?;
            if let Some(mut record) = existing.filter(|r| r.has_base_key(&msg.base_key)).cloned() {
                // a repeat of the message that started this session
                let pt = record.decrypt(&msg.message)?;
                (record, pt, None)
            } else {
                let spk =
                    self.data.signed_pre_keys.get(&msg.signed_pre_key_id).ok_or(OmemoError::UnknownSignedPreKey(msg.signed_pre_key_id))?;
                let otpk = self.data.pre_keys.get(&msg.pre_key_id).ok_or(OmemoError::UnknownPreKey(msg.pre_key_id))?;
                let state = SessionState::respond(&self.data.identity, self.data.device_id, &spk.pair, otpk, &msg);
                let mut record = match existing {
                    Some(r) => {
                        let mut r = r.clone();
                        r.replace(state);
                        r
                    }
                    None => SessionRecord::new(state),
                };
                let pt = record.decrypt(&msg.message)?;
                (record, pt, Some(msg.pre_key_id))
            }
        } else {
            let msg = WhisperMessage::parse(&key.data)?;
            let mut record = existing.cloned().ok_or(SessionError::NoSession)?;
            let pt = record.decrypt(&msg)?;
            (record, pt, None)
        };

        if !trusted(&record.current.remote_identity) {
            return Err(OmemoError::Untrusted { device_id: sid, identity: record.current.remote_identity });
        }
        let body = match &encrypted.payload {
            Some(p) => {
                let pt = crypto::open(&key_material, &encrypted.header.iv.data, &p.data).map_err(OmemoError::Body)?;
                Some(String::from_utf8(pt).map_err(|_| OmemoError::Body(crypto::CryptoError::Ciphertext))?)
            }
            None => None,
        };
        let identity = record.current.remote_identity;
        self.data.sessions.entry(jid.to_owned()).or_default().insert(sid, record);
        if let Some(id) = used_pre_key {
            self.data.pre_keys.remove(&id);
        }
        self.save()?;
        Ok(Decrypted { device_id: sid, identity, body, used_pre_key: used_pre_key.is_some() })
    }

    /// Encrypts `body` (None: a key transport message) for those of `jid`'s devices we
    /// have sessions with. Fails when that is none of them.
    pub fn encrypt(&mut self, jid: &str, devices: &[u32], body: Option<&str>) -> Result<Encrypted, OmemoError> {
        let sealed = crypto::seal(body.unwrap_or("").as_bytes());
        let sessions = self.data.sessions.get_mut(jid).ok_or(OmemoError::NoSessions)?;
        let mut keys = Vec::new();
        for id in devices {
            if let Some(record) = sessions.get_mut(id) {
                let (data, prekey) = record.current.encrypt(&sealed.key_and_tag);
                keys.push(Key { rid: *id, prekey, data });
            }
        }
        if keys.is_empty() {
            return Err(OmemoError::NoSessions);
        }
        // chain keys must never be reused: save before anything is sent
        self.save()?;
        Ok(Encrypted {
            header: Header { sid: self.data.device_id, keys, iv: IV { data: sealed.iv.to_vec() } },
            payload: body.map(|_| Payload { data: sealed.ciphertext }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> Omemo {
        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-omemo-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("omemo.json");
        let _ = std::fs::remove_file(&path);
        Omemo::open(&path, 1_000_000).unwrap()
    }

    #[test]
    fn two_stores_talk_and_survive_a_reload() {
        let mut a = store("a");
        let mut b = store("b");
        let b_id = b.device_id();
        a.start_session("b@x", b_id, &b.bundle()).unwrap();
        let first = a.encrypt("b@x", &[b_id, 999], Some("hello")).unwrap();
        assert_eq!(first.header.keys.len(), 1);
        assert!(first.header.keys[0].prekey);

        let d = b.decrypt("a@x", &first).unwrap();
        assert_eq!(d.body.as_deref(), Some("hello"));
        assert!(d.used_pre_key);
        assert_eq!(d.identity.fingerprint(), a.fingerprint());
        assert_eq!(b.data.pre_keys.len(), PRE_KEYS - 1);
        // the repeat of a session-starting message decrypts no more
        assert!(matches!(b.decrypt("a@x", &first), Err(OmemoError::Session(SessionError::Duplicate))));

        let mut b = Omemo::open(&b.path, 1_000_100).unwrap();
        let reply = b.encrypt("a@x", &[a.device_id()], Some("hi a")).unwrap();
        assert!(!reply.header.keys[0].prekey);
        assert_eq!(a.decrypt("b@x", &reply).unwrap().body.as_deref(), Some("hi a"));

        let next = a.encrypt("b@x", &[b_id], Some("now plain")).unwrap();
        assert!(!next.header.keys[0].prekey, "the reply acknowledged the session");
        assert_eq!(b.decrypt("a@x", &next).unwrap().body.as_deref(), Some("now plain"));

        let kt = a.encrypt("b@x", &[b_id], None).unwrap();
        assert!(kt.payload.is_none());
        assert_eq!(b.decrypt("a@x", &kt).unwrap().body, None);

        let own = b.encrypt("a@x", &[a.device_id()], Some("x")).unwrap();
        assert!(matches!(b.decrypt("a@x", &own), Err(OmemoError::OwnMessage)));
    }

    /// A new session from an untrusted key (same device id) must not replace the trusted one.
    #[test]
    fn untrusted_keys_change_nothing() {
        let mut bot = store("trust-bot");
        let mut alice = store("trust-alice");
        let mut mallory = store("trust-mallory");
        mallory.data.device_id = alice.device_id();
        let (bot_id, good) = (bot.device_id(), alice.fingerprint());
        let only_alice = |k: &PublicKey| k.fingerprint() == good;

        alice.start_session("bot@x", bot_id, &bot.bundle()).unwrap();
        let hello = alice.encrypt("bot@x", &[bot_id], Some("hi")).unwrap();
        assert_eq!(bot.decrypt_if("alice@x", &hello, only_alice).unwrap().body.as_deref(), Some("hi"));
        let prekeys = bot.data.pre_keys.len();

        mallory.start_session("bot@x", bot_id, &bot.bundle()).unwrap();
        let fake = mallory.encrypt("bot@x", &[bot_id], Some("/rstpass admin")).unwrap();
        let err = bot.decrypt_if("alice@x", &fake, only_alice).unwrap_err();
        assert!(matches!(err, OmemoError::Untrusted { identity, .. } if identity.fingerprint() == mallory.fingerprint()));
        assert_eq!(bot.data.pre_keys.len(), prekeys, "no prekey used up");
        assert_eq!(bot.session_identity("alice@x", alice.device_id()).unwrap().fingerprint(), good);
        let reloaded = Omemo::open(&bot.path, 1_000_000).unwrap();
        assert_eq!(reloaded.session_identity("alice@x", alice.device_id()).unwrap().fingerprint(), good, "nothing saved");

        // Alice's session still works both ways
        let next = alice.encrypt("bot@x", &[bot_id], Some("still me")).unwrap();
        assert_eq!(bot.decrypt_if("alice@x", &next, only_alice).unwrap().body.as_deref(), Some("still me"));
    }

    #[test]
    fn bad_bundles_are_refused() {
        let mut a = store("bad-a");
        let b = store("bad-b");
        let mut bundle = b.bundle();
        bundle.signed_pre_key_signature.as_mut().unwrap().data[3] ^= 1;
        assert!(matches!(a.start_session("b@x", 1, &bundle), Err(OmemoError::BadBundle(_))));
        let mut bundle = b.bundle();
        bundle.prekeys = None;
        assert!(matches!(a.start_session("b@x", 1, &bundle), Err(OmemoError::BadBundle(_))));
        assert!(matches!(a.encrypt("b@x", &[1], Some("x")), Err(OmemoError::NoSessions)));
    }

    #[test]
    fn keys_are_topped_up_and_rotated() {
        let mut s = store("rotate");
        let spk = s.data.current_signed_pre_key;
        s.data.pre_keys.retain(|&id, _| id > 30);
        assert!(s.refresh_keys(1_000_000).unwrap());
        assert_eq!(s.data.pre_keys.len(), PRE_KEYS);
        assert!(!s.refresh_keys(1_000_000).unwrap());

        let later = 1_000_000 + SIGNED_PRE_KEY_ROTATE;
        assert!(s.refresh_keys(later).unwrap());
        assert_ne!(s.data.current_signed_pre_key, spk);
        assert!(s.data.signed_pre_keys.contains_key(&spk), "kept for late session starts");
        assert!(s.refresh_keys(later + SIGNED_PRE_KEY_KEEP).unwrap());
        assert!(!s.data.signed_pre_keys.contains_key(&spk));
        assert_eq!(s.data.signed_pre_keys.len(), 1);

        // a store missing its current signed prekey gets a new one instead of a panic
        s.data.signed_pre_keys.clear();
        assert!(s.refresh_keys(later + SIGNED_PRE_KEY_KEEP).unwrap());
        assert!(s.bundle().signed_pre_key_public.is_some());
    }
}

#[cfg(test)]
mod oracle_tests;
