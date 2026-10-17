//! The primitives of OMEMO 0.3 (libsignal protocol version 3): Curve25519 keys, XEdDSA
//! signatures, the KDFs and the two AES modes.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use aes_gcm::aes::Aes128;
use aes_gcm::{Aes128Gcm, AesGcm};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{clamp_integer, Scalar};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// libsignal's type byte in front of a serialized Curve25519 public key.
pub const DJB_TYPE: u8 = 0x05;

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    Key,
    Mac,
    Ciphertext,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            CryptoError::Key => "malformed public key",
            CryptoError::Mac => "authentication failed",
            CryptoError::Ciphertext => "malformed ciphertext",
        })
    }
}

impl std::error::Error for CryptoError {}

/// A Curve25519 public key (the Montgomery u-coordinate).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// libsignal's form: 0x05 and the 32 key bytes.
    pub fn serialize(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = DJB_TYPE;
        out[1..].copy_from_slice(&self.0);
        out
    }

    /// Accepts the 33-byte libsignal form and the bare 32 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        match bytes.len() {
            33 if bytes[0] == DJB_TYPE => Ok(PublicKey(bytes[1..].try_into().unwrap())),
            32 => Ok(PublicKey(bytes.try_into().unwrap())),
            _ => Err(CryptoError::Key),
        }
    }

    /// The fingerprint clients show: the key in hex, without the type byte.
    pub fn fingerprint(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    /// Stored clamped, as libsignal does.
    pub private: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::from_private(random())
    }

    pub fn from_private(private: [u8; 32]) -> Self {
        let private = clamp_integer(private);
        KeyPair { public: PublicKey(MontgomeryPoint::mul_base_clamped(private).to_bytes()), private }
    }

    /// X25519.
    pub fn agree(&self, their: &PublicKey) -> [u8; 32] {
        MontgomeryPoint(their.0).mul_clamped(self.private).to_bytes()
    }

    /// XEdDSA signature (signal.org/docs/specifications/xeddsa): an Ed25519 signature
    /// made with this Curve25519 key, its Edwards sign bit forced to 0.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let k = Scalar::from_bytes_mod_order(self.private);
        let point = EdwardsPoint::mul_base(&k).compress();
        // A = kB must have sign bit 0; -k gives the point with the other sign.
        let (a, public) = if point.as_bytes()[31] & 0x80 != 0 {
            let a = -k;
            (a, EdwardsPoint::mul_base(&a).compress())
        } else {
            (k, point)
        };
        let nonce: [u8; 64] = random();
        // r = hash1(a || M || Z), hash1 prefixing 0xFE and 31 × 0xFF
        let mut prefix = [0xFFu8; 32];
        prefix[0] = 0xFE;
        let r = Scalar::from_hash(Sha512::new().chain_update(prefix).chain_update(a.as_bytes()).chain_update(message).chain_update(nonce));
        let big_r = EdwardsPoint::mul_base(&r).compress();
        let h = Scalar::from_hash(Sha512::new().chain_update(big_r.as_bytes()).chain_update(public.as_bytes()).chain_update(message));
        let s = r + h * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(big_r.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }
}

/// Verifies an XEdDSA signature like libsignal's `curve25519_verify`: the Edwards sign
/// bit comes from the top bit of the signature (0 for XEdDSA; older libsignal signers
/// stored the real sign bit there).
pub fn verify(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let mut sig = sig;
    let sign = sig[63] >> 7;
    sig[63] &= 0x7F;
    let Some(edwards) = MontgomeryPoint(key.0).to_edwards(sign) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(edwards.compress().as_bytes()) else {
        return false;
    };
    vk.verify_strict(message, &Signature::from_bytes(&sig)).is_ok()
}

/// HKDF-SHA256.
pub fn hkdf<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).expect("HKDF output length");
    out
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Constant-time check of a truncated HMAC-SHA256.
pub fn hmac_sha256_verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.verify_truncated_left(tag).is_ok()
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    buf.resize(plaintext.len() + 16, 0);
    let n = Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .expect("buffer has room for the padding")
        .len();
    buf.truncate(n);
    buf
}

pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut buf = ciphertext.to_vec();
    let n = Aes256CbcDec::new(key.into(), iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| CryptoError::Ciphertext)?.len();
    buf.truncate(n);
    Ok(buf)
}

/// A message body encrypted with a fresh AES-128-GCM key: the key and tag (32 bytes,
/// what each recipient device gets) and the ciphertext without the tag.
pub struct Sealed {
    pub key_and_tag: [u8; 32],
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn seal(plaintext: &[u8]) -> Sealed {
    let key: [u8; 16] = random();
    let iv: [u8; 12] = random();
    let mut ciphertext = plaintext.to_vec();
    let tag = Aes128Gcm::new(&key.into()).encrypt_in_place_detached(&iv.into(), b"", &mut ciphertext).expect("plaintext within GCM limits");
    let mut key_and_tag = [0u8; 32];
    key_and_tag[..16].copy_from_slice(&key);
    key_and_tag[16..].copy_from_slice(&tag);
    Sealed { key_and_tag, iv, ciphertext }
}

/// Opens a message body. `key` is the 32 bytes of key and tag; older senders transport
/// only the 16-byte key and append the tag to the payload. Old Conversations used a
/// 16-byte IV, current clients 12.
pub fn open(key: &[u8], iv: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (key, tag, data) = match key.len() {
        32.. => (&key[..16], &key[16..32], payload),
        16 if payload.len() >= 16 => (key, &payload[payload.len() - 16..], &payload[..payload.len() - 16]),
        _ => return Err(CryptoError::Ciphertext),
    };
    let mut buf = data.to_vec();
    let tag = GenericArray::from_slice(tag);
    let ok = match iv.len() {
        12 => Aes128Gcm::new(GenericArray::from_slice(key)).decrypt_in_place_detached(GenericArray::from_slice(iv), b"", &mut buf, tag),
        16 => AesGcm::<Aes128, aes_gcm::aead::consts::U16>::new(GenericArray::from_slice(key)).decrypt_in_place_detached(
            GenericArray::from_slice(iv),
            b"",
            &mut buf,
            tag,
        ),
        _ => return Err(CryptoError::Ciphertext),
    };
    ok.map_err(|_| CryptoError::Mac)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn agreement_is_symmetric() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_eq!(a.agree(&b.public), b.agree(&a.public));
    }

    /// RFC 7748, section 6.1.
    #[test]
    fn x25519_rfc7748_vector() {
        let alice = KeyPair::from_private(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().unwrap());
        assert_eq!(alice.public.0.to_vec(), hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        let bob = PublicKey(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").try_into().unwrap());
        assert_eq!(alice.agree(&bob).to_vec(), hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    }

    #[test]
    fn signatures_verify_and_reject_tampering() {
        for _ in 0..32 {
            let k = KeyPair::generate();
            let msg = random::<40>();
            let sig = k.sign(&msg);
            assert_eq!(sig[63] & 0x80, 0);
            assert!(verify(&k.public, &msg, &sig));
            assert!(!verify(&k.public, &msg[1..], &sig));
            let mut bad = sig;
            bad[5] ^= 1;
            assert!(!verify(&k.public, &msg, &bad));
            assert!(!verify(&KeyPair::generate().public, &msg, &sig));
        }
    }

    #[test]
    fn public_key_forms() {
        let k = KeyPair::generate().public;
        assert_eq!(PublicKey::parse(&k.serialize()), Ok(k));
        assert_eq!(PublicKey::parse(&k.0), Ok(k));
        assert!(PublicKey::parse(&k.serialize()[1..32]).is_err());
        let mut wrong_type = k.serialize();
        wrong_type[0] = 0x06;
        assert!(PublicKey::parse(&wrong_type).is_err());
        assert_eq!(k.fingerprint().len(), 64);
    }

    #[test]
    fn cbc_round_trip() {
        let key = random();
        let iv = random();
        for len in [0, 1, 15, 16, 17, 100] {
            let pt = vec![7u8; len];
            let ct = aes256_cbc_encrypt(&key, &iv, &pt);
            assert_eq!(ct.len(), (len / 16 + 1) * 16);
            assert_eq!(aes256_cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
        }
        assert!(aes256_cbc_decrypt(&key, &iv, &[1u8; 15]).is_err());
    }

    #[test]
    fn gcm_seal_open_including_legacy_layout() {
        let s = seal(b"hello");
        assert_eq!(open(&s.key_and_tag, &s.iv, &s.ciphertext).unwrap(), b"hello");
        // legacy: 16-byte key, tag at the end of the payload
        let mut legacy = s.ciphertext.clone();
        legacy.extend_from_slice(&s.key_and_tag[16..]);
        assert_eq!(open(&s.key_and_tag[..16], &s.iv, &legacy).unwrap(), b"hello");
        let mut bad = s.key_and_tag;
        bad[20] ^= 1;
        assert_eq!(open(&bad, &s.iv, &s.ciphertext), Err(CryptoError::Mac));
    }

    #[test]
    fn gcm_with_a_16_byte_iv() {
        let key: [u8; 16] = random();
        let iv: [u8; 16] = random();
        let mut ct = b"old conversations".to_vec();
        let tag = AesGcm::<Aes128, aes_gcm::aead::consts::U16>::new(&key.into())
            .encrypt_in_place_detached(GenericArray::from_slice(&iv), b"", &mut ct)
            .unwrap();
        let mut kt = key.to_vec();
        kt.extend_from_slice(&tag);
        assert_eq!(open(&kt, &iv, &ct).unwrap(), b"old conversations");
    }
}
