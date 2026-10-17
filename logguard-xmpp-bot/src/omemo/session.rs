//! One device-to-device session: X3DH to set it up (signal.org/docs/specifications/x3dh)
//! and the Double Ratchet (signal.org/docs/specifications/doubleratchet), with the
//! constants of libsignal protocol version 3 that OMEMO 0.3 uses.

use serde::{Deserialize, Serialize};

use super::crypto::{aes256_cbc_decrypt, aes256_cbc_encrypt, hkdf, hmac_sha256, KeyPair, PublicKey};
use super::wire::{PreKeyWhisperMessage, WhisperMessage};

/// How many messages ahead of the chain a message may be (libsignal's limit).
const MAX_SKIP: u32 = 2000;
/// Old receiving chains kept for late messages.
const MAX_RECEIVER_CHAINS: usize = 5;
/// Skipped message keys kept per chain.
const MAX_SKIPPED_KEYS: usize = 2000;

#[derive(Debug, PartialEq)]
pub enum SessionError {
    /// No session with that device.
    NoSession,
    /// A message already decrypted (or whose key was dropped).
    Duplicate,
    TooFarAhead,
    BadMac,
    Decrypt,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            SessionError::NoSession => "no session with this device",
            SessionError::Duplicate => "message already received",
            SessionError::TooFarAhead => "message too far ahead in the chain",
            SessionError::BadMac => "message authentication failed",
            SessionError::Decrypt => "message did not decrypt",
        })
    }
}

impl std::error::Error for SessionError {}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ChainKey {
    key: [u8; 32],
    index: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct MessageKeys {
    cipher: [u8; 32],
    mac: [u8; 32],
    iv: [u8; 16],
    index: u32,
}

impl ChainKey {
    fn message_keys(&self) -> MessageKeys {
        let seed = hmac_sha256(&self.key, &[&[0x01]]);
        let okm: [u8; 80] = hkdf(&[0u8; 32], &seed, b"WhisperMessageKeys");
        MessageKeys {
            cipher: okm[..32].try_into().unwrap(),
            mac: okm[32..64].try_into().unwrap(),
            iv: okm[64..].try_into().unwrap(),
            index: self.index,
        }
    }

    fn next(&self) -> ChainKey {
        ChainKey { key: hmac_sha256(&self.key, &[&[0x02]]), index: self.index + 1 }
    }
}

/// A DH ratchet step: new root key and chain key from the old root key.
fn create_chain(root_key: &[u8; 32], theirs: &PublicKey, ours: &KeyPair) -> ([u8; 32], ChainKey) {
    let okm: [u8; 64] = hkdf(root_key, &ours.agree(theirs), b"WhisperRatchet");
    (okm[..32].try_into().unwrap(), ChainKey { key: okm[32..].try_into().unwrap(), index: 0 })
}

/// Root and first chain key from the X3DH secrets.
fn derive_initial(secrets: &[[u8; 32]; 4]) -> ([u8; 32], ChainKey) {
    let mut ikm = vec![0xFFu8; 32];
    for s in secrets {
        ikm.extend_from_slice(s);
    }
    let okm: [u8; 64] = hkdf(&[0u8; 32], &ikm, b"WhisperText");
    (okm[..32].try_into().unwrap(), ChainKey { key: okm[32..].try_into().unwrap(), index: 0 })
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct ReceiverChain {
    ratchet_key: PublicKey,
    chain_key: ChainKey,
    skipped: Vec<MessageKeys>,
}

/// What a session started by us repeats in every message until the other side answers.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct PendingPreKey {
    pre_key_id: u32,
    signed_pre_key_id: u32,
    base_key: PublicKey,
}

/// The other device's published keys used to start a session.
pub struct TheirBundle {
    pub identity: PublicKey,
    pub signed_pre_key_id: u32,
    pub signed_pre_key: PublicKey,
    pub pre_key_id: u32,
    pub pre_key: PublicKey,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct SessionState {
    local_identity: PublicKey,
    pub remote_identity: PublicKey,
    local_device_id: u32,
    root_key: [u8; 32],
    previous_counter: u32,
    sender_ratchet: KeyPair,
    sender_chain: ChainKey,
    receiver_chains: Vec<ReceiverChain>,
    pending_pre_key: Option<PendingPreKey>,
    /// The base key of the X3DH run that made this session, to recognize repeats of the
    /// same PreKeyWhisperMessage.
    alice_base_key: PublicKey,
}

impl SessionState {
    /// We start the session ("Alice") from the other device's bundle. Its signature has
    /// to be checked by the caller.
    pub fn initiate(our_identity: &KeyPair, our_device_id: u32, their: &TheirBundle) -> Self {
        let base = KeyPair::generate();
        let secrets = [
            our_identity.agree(&their.signed_pre_key),
            base.agree(&their.identity),
            base.agree(&their.signed_pre_key),
            base.agree(&their.pre_key),
        ];
        let (root, chain) = derive_initial(&secrets);
        let sender_ratchet = KeyPair::generate();
        let (root, sender_chain) = create_chain(&root, &their.signed_pre_key, &sender_ratchet);
        SessionState {
            local_identity: our_identity.public,
            remote_identity: their.identity,
            local_device_id: our_device_id,
            root_key: root,
            previous_counter: 0,
            sender_ratchet,
            sender_chain,
            receiver_chains: vec![ReceiverChain { ratchet_key: their.signed_pre_key, chain_key: chain, skipped: Vec::new() }],
            pending_pre_key: Some(PendingPreKey {
                pre_key_id: their.pre_key_id,
                signed_pre_key_id: their.signed_pre_key_id,
                base_key: base.public,
            }),
            alice_base_key: base.public,
        }
    }

    /// The other device started the session ("Bob" side) with a PreKeyWhisperMessage
    /// to our signed prekey and one-time prekey.
    pub fn respond(
        our_identity: &KeyPair,
        our_device_id: u32,
        signed_pre_key: &KeyPair,
        one_time_pre_key: &KeyPair,
        msg: &PreKeyWhisperMessage,
    ) -> Self {
        let secrets = [
            signed_pre_key.agree(&msg.identity_key),
            our_identity.agree(&msg.base_key),
            signed_pre_key.agree(&msg.base_key),
            one_time_pre_key.agree(&msg.base_key),
        ];
        let (root, chain) = derive_initial(&secrets);
        SessionState {
            local_identity: our_identity.public,
            remote_identity: msg.identity_key,
            local_device_id: our_device_id,
            root_key: root,
            previous_counter: 0,
            sender_ratchet: signed_pre_key.clone(),
            sender_chain: chain,
            receiver_chains: Vec::new(),
            pending_pre_key: None,
            alice_base_key: msg.base_key,
        }
    }

    /// Encrypts `plaintext`; true when it is a PreKeyWhisperMessage.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, bool) {
        let keys = self.sender_chain.message_keys();
        let ciphertext = aes256_cbc_encrypt(&keys.cipher, &keys.iv, plaintext);
        let msg = WhisperMessage::new(
            &keys.mac,
            self.sender_ratchet.public,
            keys.index,
            self.previous_counter,
            ciphertext,
            &self.local_identity,
            &self.remote_identity,
        );
        self.sender_chain = self.sender_chain.next();
        match &self.pending_pre_key {
            Some(p) => {
                let pk = PreKeyWhisperMessage {
                    registration_id: self.local_device_id,
                    pre_key_id: p.pre_key_id,
                    signed_pre_key_id: p.signed_pre_key_id,
                    base_key: p.base_key,
                    identity_key: self.local_identity,
                    message: msg,
                };
                (pk.serialize(), true)
            }
            None => (msg.serialized, false),
        }
    }

    /// Decrypts in place; on error the state may be half-updated, so callers decrypt
    /// on a copy (see [`SessionRecord::decrypt`]).
    fn decrypt(&mut self, msg: &WhisperMessage) -> Result<Vec<u8>, SessionError> {
        let chain = self.receiver_chain(&msg.ratchet_key);
        let keys = self.message_keys(chain, msg.counter)?;
        if !msg.verify_mac(&keys.mac, &self.remote_identity, &self.local_identity) {
            return Err(SessionError::BadMac);
        }
        let plaintext = aes256_cbc_decrypt(&keys.cipher, &keys.iv, &msg.ciphertext).map_err(|_| SessionError::Decrypt)?;
        // they answered: the session is set up on their side
        self.pending_pre_key = None;
        Ok(plaintext)
    }

    /// The receiving chain for their ratchet key; a new key means a DH ratchet step.
    fn receiver_chain(&mut self, theirs: &PublicKey) -> usize {
        if let Some(i) = self.receiver_chains.iter().position(|c| &c.ratchet_key == theirs) {
            return i;
        }
        let (root, receiving) = create_chain(&self.root_key, theirs, &self.sender_ratchet);
        let new_ratchet = KeyPair::generate();
        let (root, sending) = create_chain(&root, theirs, &new_ratchet);
        self.root_key = root;
        self.previous_counter = self.sender_chain.index.saturating_sub(1);
        self.sender_ratchet = new_ratchet;
        self.sender_chain = sending;
        self.receiver_chains.push(ReceiverChain { ratchet_key: *theirs, chain_key: receiving, skipped: Vec::new() });
        if self.receiver_chains.len() > MAX_RECEIVER_CHAINS {
            self.receiver_chains.remove(0);
        }
        self.receiver_chains.len() - 1
    }

    fn message_keys(&mut self, chain: usize, counter: u32) -> Result<MessageKeys, SessionError> {
        let c = &mut self.receiver_chains[chain];
        if counter < c.chain_key.index {
            let i = c.skipped.iter().position(|k| k.index == counter).ok_or(SessionError::Duplicate)?;
            return Ok(c.skipped.remove(i));
        }
        if counter - c.chain_key.index > MAX_SKIP {
            return Err(SessionError::TooFarAhead);
        }
        while c.chain_key.index < counter {
            c.skipped.push(c.chain_key.message_keys());
            c.chain_key = c.chain_key.next();
        }
        if c.skipped.len() > MAX_SKIPPED_KEYS {
            let excess = c.skipped.len() - MAX_SKIPPED_KEYS;
            c.skipped.drain(..excess);
        }
        let keys = c.chain_key.message_keys();
        c.chain_key = c.chain_key.next();
        Ok(keys)
    }
}

/// A device's current session and the ones it replaced (a peer may still send on those).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct SessionRecord {
    pub current: SessionState,
    previous: Vec<SessionState>,
}

const MAX_PREVIOUS_STATES: usize = 10;

impl SessionRecord {
    pub fn new(state: SessionState) -> Self {
        SessionRecord { current: state, previous: Vec::new() }
    }

    /// Makes `state` current and keeps the old current one.
    pub fn replace(&mut self, state: SessionState) {
        let old = std::mem::replace(&mut self.current, state);
        self.previous.insert(0, old);
        self.previous.truncate(MAX_PREVIOUS_STATES);
    }

    /// Whether one of the states was set up by the X3DH run with this base key.
    pub fn has_base_key(&self, base_key: &PublicKey) -> bool {
        std::iter::once(&self.current).chain(&self.previous).any(|s| &s.alice_base_key == base_key)
    }

    /// Tries the current state, then the older ones; a state that decrypts becomes
    /// current. Nothing changes when decryption fails.
    pub fn decrypt(&mut self, msg: &WhisperMessage) -> Result<Vec<u8>, SessionError> {
        let mut state = self.current.clone();
        let first_error = match state.decrypt(msg) {
            Ok(pt) => {
                self.current = state;
                return Ok(pt);
            }
            Err(e) => e,
        };
        for i in 0..self.previous.len() {
            let mut state = self.previous[i].clone();
            if let Ok(pt) = state.decrypt(msg) {
                self.previous.remove(i);
                self.replace(state);
                return Ok(pt);
            }
        }
        Err(first_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Device {
        identity: KeyPair,
        spk: KeyPair,
        otpk: KeyPair,
    }

    fn device() -> Device {
        Device { identity: KeyPair::generate(), spk: KeyPair::generate(), otpk: KeyPair::generate() }
    }

    /// Alice starts a session with Bob; Bob answers its first message.
    fn pair() -> (SessionRecord, SessionRecord) {
        let (a, b) = (device(), device());
        let bundle = TheirBundle {
            identity: b.identity.public,
            signed_pre_key_id: 1,
            signed_pre_key: b.spk.public,
            pre_key_id: 7,
            pre_key: b.otpk.public,
        };
        let mut alice = SessionState::initiate(&a.identity, 100, &bundle);
        let (first, prekey) = alice.encrypt(b"hi bob");
        assert!(prekey);
        let pk = PreKeyWhisperMessage::parse(&first).unwrap();
        assert_eq!((pk.registration_id, pk.pre_key_id, pk.signed_pre_key_id), (100, 7, 1));
        let mut bob = SessionRecord::new(SessionState::respond(&b.identity, 200, &b.spk, &b.otpk, &pk));
        assert_eq!(bob.decrypt(&pk.message).unwrap(), b"hi bob");
        (SessionRecord::new(alice), bob)
    }

    fn send(from: &mut SessionRecord, to: &mut SessionRecord, text: &[u8]) -> Result<Vec<u8>, SessionError> {
        let (bytes, _) = from.current.encrypt(text);
        to.decrypt(&WhisperMessage::parse(&bytes).unwrap())
    }

    #[test]
    fn conversation_with_ratchet_turns() {
        let (mut alice, mut bob) = pair();
        assert_eq!(send(&mut bob, &mut alice, b"hello alice").unwrap(), b"hello alice");
        // Alice's next message is a plain WhisperMessage now
        assert!(!alice.current.clone().encrypt(b"x").1);
        for i in 0..5 {
            let t = format!("a{i}");
            assert_eq!(send(&mut alice, &mut bob, t.as_bytes()).unwrap(), t.as_bytes());
            let t = format!("b{i}");
            assert_eq!(send(&mut bob, &mut alice, t.as_bytes()).unwrap(), t.as_bytes());
        }
    }

    #[test]
    fn out_of_order_duplicates_and_tampering() {
        let (mut alice, mut bob) = pair();
        let msgs: Vec<Vec<u8>> = (0..4).map(|i| alice.current.encrypt(format!("m{i}").as_bytes()).0).collect();
        let parse = |b: &Vec<u8>| PreKeyWhisperMessage::parse(b).unwrap().message;
        assert_eq!(bob.decrypt(&parse(&msgs[3])).unwrap(), b"m3");
        assert_eq!(bob.decrypt(&parse(&msgs[1])).unwrap(), b"m1");
        assert_eq!(bob.decrypt(&parse(&msgs[1])), Err(SessionError::Duplicate));
        let mut bad = parse(&msgs[2]);
        let n = bad.serialized.len();
        bad.serialized[n - 1] ^= 1;
        let before = bob.clone();
        assert_eq!(bob.decrypt(&bad), Err(SessionError::BadMac));
        assert_eq!(bob, before, "a failed decryption changes nothing");
        assert_eq!(bob.decrypt(&parse(&msgs[2])).unwrap(), b"m2");
        assert_eq!(bob.decrypt(&parse(&msgs[0])).unwrap(), b"m0");
    }

    #[test]
    fn too_far_ahead() {
        let (mut alice, mut bob) = pair();
        let mut last = Vec::new();
        for _ in 0..=MAX_SKIP + 1 {
            last = alice.current.encrypt(b"x").0;
        }
        let m = PreKeyWhisperMessage::parse(&last).unwrap().message;
        assert_eq!(bob.decrypt(&m), Err(SessionError::TooFarAhead));
    }

    #[test]
    fn previous_state_still_decrypts() {
        let (mut alice, mut bob) = pair();
        let late = alice.current.encrypt(b"late").0;
        // Bob gets a new session (say, Alice reinstalled) ...
        let (mut alice2, bob2) = pair();
        bob.replace(bob2.current.clone());
        let (new, _) = alice2.current.encrypt(b"new");
        assert_eq!(bob.decrypt(&PreKeyWhisperMessage::parse(&new).unwrap().message).unwrap(), b"new");
        // ... and the old session's late message still decrypts.
        let m = PreKeyWhisperMessage::parse(&late).unwrap().message;
        assert_eq!(bob.decrypt(&m).unwrap(), b"late");
    }
}
