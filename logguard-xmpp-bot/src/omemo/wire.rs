//! The two libsignal v3 messages carried in an OMEMO `<key>`:
//!
//! - WhisperMessage: version byte 0x33, protobuf, then the first 8 bytes of
//!   HMAC-SHA256(mac key, sender identity ‖ receiver identity ‖ version ‖ protobuf);
//! - PreKeyWhisperMessage (a session's first messages): version byte 0x33, then a
//!   protobuf holding the key-agreement inputs and a whole WhisperMessage.

use prost::Message;

use super::crypto::{hmac_sha256, hmac_sha256_verify, PublicKey};

pub const VERSION: u8 = 3;
const VERSION_BYTE: u8 = (VERSION << 4) | VERSION;
const MAC_LEN: usize = 8;

#[derive(Clone, PartialEq, Message)]
struct WhisperProto {
    #[prost(bytes = "vec", optional, tag = "1")]
    ratchet_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    previous_counter: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    ciphertext: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct PreKeyWhisperProto {
    #[prost(uint32, optional, tag = "5")]
    registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "1")]
    pre_key_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    signed_pre_key_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    base_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    identity_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    message: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub enum WireError {
    Version(u8),
    Malformed(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WireError::Version(v) => write!(f, "unsupported message version {v}"),
            WireError::Malformed(what) => write!(f, "malformed message: {what}"),
        }
    }
}

impl std::error::Error for WireError {}

fn check_version(bytes: &[u8]) -> Result<(), WireError> {
    match bytes.first() {
        Some(b) if b >> 4 == VERSION => Ok(()),
        Some(b) => Err(WireError::Version(b >> 4)),
        None => Err(WireError::Malformed("empty")),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WhisperMessage {
    pub ratchet_key: PublicKey,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Vec<u8>,
    /// The whole message as sent, MAC included.
    pub serialized: Vec<u8>,
}

impl WhisperMessage {
    pub fn new(
        mac_key: &[u8; 32],
        ratchet_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: Vec<u8>,
        sender_identity: &PublicKey,
        receiver_identity: &PublicKey,
    ) -> Self {
        let proto = WhisperProto {
            ratchet_key: Some(ratchet_key.serialize().to_vec()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(ciphertext.clone()),
        };
        let mut serialized = vec![VERSION_BYTE];
        proto.encode(&mut serialized).expect("Vec grows");
        let mac = hmac_sha256(mac_key, &[&sender_identity.serialize(), &receiver_identity.serialize(), &serialized]);
        serialized.extend_from_slice(&mac[..MAC_LEN]);
        WhisperMessage { ratchet_key, counter, previous_counter, ciphertext, serialized }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        check_version(bytes)?;
        if bytes.len() < 1 + MAC_LEN {
            return Err(WireError::Malformed("too short"));
        }
        let proto = WhisperProto::decode(&bytes[1..bytes.len() - MAC_LEN]).map_err(|_| WireError::Malformed("protobuf"))?;
        let (Some(ratchet_key), Some(ciphertext)) = (proto.ratchet_key, proto.ciphertext) else {
            return Err(WireError::Malformed("incomplete"));
        };
        if ciphertext.is_empty() {
            return Err(WireError::Malformed("incomplete"));
        }
        Ok(WhisperMessage {
            ratchet_key: PublicKey::parse(&ratchet_key).map_err(|_| WireError::Malformed("ratchet key"))?,
            counter: proto.counter.unwrap_or(0),
            previous_counter: proto.previous_counter.unwrap_or(0),
            ciphertext,
            serialized: bytes.to_vec(),
        })
    }

    pub fn verify_mac(&self, mac_key: &[u8; 32], sender_identity: &PublicKey, receiver_identity: &PublicKey) -> bool {
        let (body, mac) = self.serialized.split_at(self.serialized.len() - MAC_LEN);
        hmac_sha256_verify(mac_key, &[&sender_identity.serialize(), &receiver_identity.serialize(), body], mac)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreKeyWhisperMessage {
    /// The sender's device id.
    pub registration_id: u32,
    pub pre_key_id: u32,
    pub signed_pre_key_id: u32,
    pub base_key: PublicKey,
    pub identity_key: PublicKey,
    pub message: WhisperMessage,
}

impl PreKeyWhisperMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let proto = PreKeyWhisperProto {
            registration_id: Some(self.registration_id),
            pre_key_id: Some(self.pre_key_id),
            signed_pre_key_id: Some(self.signed_pre_key_id),
            base_key: Some(self.base_key.serialize().to_vec()),
            identity_key: Some(self.identity_key.serialize().to_vec()),
            message: Some(self.message.serialized.clone()),
        };
        let mut out = vec![VERSION_BYTE];
        proto.encode(&mut out).expect("Vec grows");
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        check_version(bytes)?;
        let proto = PreKeyWhisperProto::decode(&bytes[1..]).map_err(|_| WireError::Malformed("protobuf"))?;
        let (Some(signed_pre_key_id), Some(base_key), Some(identity_key), Some(message)) =
            (proto.signed_pre_key_id, proto.base_key, proto.identity_key, proto.message)
        else {
            return Err(WireError::Malformed("incomplete"));
        };
        // OMEMO always uses a one-time prekey
        let pre_key_id = proto.pre_key_id.filter(|&id| id != 0).ok_or(WireError::Malformed("no one-time prekey"))?;
        Ok(PreKeyWhisperMessage {
            registration_id: proto.registration_id.unwrap_or(0),
            pre_key_id,
            signed_pre_key_id,
            base_key: PublicKey::parse(&base_key).map_err(|_| WireError::Malformed("base key"))?,
            identity_key: PublicKey::parse(&identity_key).map_err(|_| WireError::Malformed("identity key"))?,
            message: WhisperMessage::parse(&message)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{random, KeyPair};
    use super::*;

    #[test]
    fn whisper_round_trip_and_mac() {
        let (a, b) = (KeyPair::generate().public, KeyPair::generate().public);
        let mac_key = random();
        let m = WhisperMessage::new(&mac_key, KeyPair::generate().public, 7, 3, vec![1, 2, 3], &a, &b);
        assert_eq!(m.serialized[0], 0x33);
        let p = WhisperMessage::parse(&m.serialized).unwrap();
        assert_eq!(p, m);
        assert!(p.verify_mac(&mac_key, &a, &b));
        assert!(!p.verify_mac(&mac_key, &b, &a));
        let mut tampered = m.serialized.clone();
        tampered[5] ^= 1;
        assert!(WhisperMessage::parse(&tampered).map_or(true, |t| !t.verify_mac(&mac_key, &a, &b)));
    }

    #[test]
    fn prekey_round_trip() {
        let (a, b) = (KeyPair::generate().public, KeyPair::generate().public);
        let inner = WhisperMessage::new(&random(), KeyPair::generate().public, 0, 0, vec![9; 16], &a, &b);
        let m = PreKeyWhisperMessage {
            registration_id: 1234,
            pre_key_id: 5,
            signed_pre_key_id: 1,
            base_key: KeyPair::generate().public,
            identity_key: a,
            message: inner,
        };
        assert_eq!(PreKeyWhisperMessage::parse(&m.serialize()).unwrap(), m);
    }

    #[test]
    fn rejects_other_versions_and_garbage() {
        assert_eq!(WhisperMessage::parse(&[0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(WireError::Version(4)));
        assert!(WhisperMessage::parse(&[0x33, 1, 2]).is_err());
        assert!(PreKeyWhisperMessage::parse(&[]).is_err());
        assert!(PreKeyWhisperMessage::parse(&[0x33, 0xff, 0xff]).is_err());
    }
}
