//! The fallback when the admin's Signal identity isn't the one the bot pinned (a changed
//! safety number): a message or file goes out as one OpenPGP message to the admin's public key
//! (`OPENPGP_KEY`), as an attachment, which a phone app decrypts (OpenKeychain on Android,
//! iPGMail on iPhone). Nothing of the content goes out in clear: a neutral caption and file name
//! (`message-<time>.txt.pgp`, `report-<time>.txt.pgp`; the apps name the decrypted file after
//! it, without `.pgp`). The literal packet carries no name, as RFC 9580 advises.
//!
//! The format is the one every OpenPGP app reads: a v4 key (RSA, or Curve25519 "legacy"
//! ECDH), the session key in a v3 PKESK packet, the data in a SEIPD v1 packet (with MDC)
//! under AES-256, no compression. Not SEIPD v2 / AEAD nor v6 keys (RFC 9580): OpenKeychain
//! and many others can't read them.
//!
//! Only the public key is on the server: whoever gets into it can't read reports that
//! were already sent.

use std::path::Path;

use pgp::composed::{Deserializable, MessageBuilder, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, KeyVersion};

/// The certificate with only its own signatures on user ids and attributes: rpgp checks
/// every signature there as a self-signature, so one from someone else (a key signed with
/// `gpg --sign-key`, or imported with web-of-trust signatures) would make the whole key look
/// broken. User ids left without a signature of their own are dropped: they aren't bound to
/// the key. Signatures that name no issuer are kept, and checked.
fn own_signatures_only(mut cert: SignedPublicKey) -> SignedPublicKey {
    let fp = cert.primary_key.fingerprint();
    let id = cert.primary_key.legacy_key_id();
    let own = |s: &Signature| {
        let (fps, ids) = (s.issuer_fingerprint(), s.issuer_key_id());
        (fps.is_empty() && ids.is_empty()) || fps.iter().any(|f| **f == fp) || ids.iter().any(|k| **k == id)
    };
    for u in &mut cert.details.users {
        u.signatures.retain(own);
    }
    cert.details.users.retain(|u| !u.signatures.is_empty());
    for a in &mut cert.details.user_attributes {
        a.signatures.retain(own);
    }
    cert.details.user_attributes.retain(|a| !a.signatures.is_empty());
    cert
}

pub struct Recipient {
    cert: SignedPublicKey,
    /// When the key as a whole expires (Unix time), if it does.
    expires: Option<u64>,
    /// The usable encryption subkeys (indices into `public_subkeys`) and when each expires.
    subkeys: Vec<(usize, Option<u64>)>,
    /// The primary key's fingerprint, as the apps show it (40 hex digits).
    pub fingerprint: String,
}

/// The latest signature of `sigs` (by creation time).
fn latest(sigs: &[Signature]) -> Option<&Signature> {
    sigs.iter().max_by_key(|s| s.created().map_or(0, |t| t.as_secs()))
}

/// When a key created at `created` with the expiration in `sig` expires (Unix time), if it does.
fn expiry(created: u32, sig: &Signature) -> Option<u64> {
    let secs = sig.key_expiration_time().map_or(0, |d| std::time::Duration::from(d).as_secs());
    (secs > 0).then(|| u64::from(created) + secs)
}

fn live(expires: Option<u64>, now: u32) -> bool {
    expires.is_none_or(|t| u64::from(now) < t)
}

fn date(t: u64) -> String {
    chrono::DateTime::from_timestamp(t as i64, 0).map_or_else(|| t.to_string(), |d| d.format("%Y-%m-%d %H:%M UTC").to_string())
}

/// Whether the phone apps can encrypt to this algorithm in a v4 key.
fn supported(alg: PublicKeyAlgorithm) -> bool {
    matches!(alg, PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::ECDH)
}

/// A subkey the apps can decrypt with, and when it expires: an encryption subkey of a
/// supported kind, never revoked (whatever the dates), by its latest binding signature.
fn usable(sk: &SignedPublicSubKey) -> Option<Option<u64>> {
    if sk.signatures.iter().any(|s| s.typ() == Some(SignatureType::SubkeyRevocation)) {
        return None;
    }
    let bindings: Vec<Signature> = sk.signatures.iter().filter(|s| s.typ() == Some(SignatureType::SubkeyBinding)).cloned().collect();
    let sig = latest(&bindings)?;
    let flags = sig.key_flags();
    ((flags.encrypt_comms() || flags.encrypt_storage()) && supported(sk.key.algorithm()))
        .then(|| expiry(sk.key.created_at().as_secs(), sig))
}

impl Recipient {
    /// The admin's public key from a file (armored or binary), checked: signatures valid, a v4
    /// key, not revoked or expired, with an encryption subkey the apps can use. `now`: Unix time.
    pub fn load(path: &Path, now: u32) -> Result<Recipient, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&data, now).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(data: &[u8], now: u32) -> Result<Recipient, String> {
        let (cert, _) = SignedPublicKey::from_reader_single(data).map_err(|e| format!("not an OpenPGP public key: {e}"))?;
        let cert = own_signatures_only(cert);
        cert.verify_bindings().map_err(|e| format!("its self-signatures don't verify: {e}"))?;
        if cert.primary_key.version() != KeyVersion::V4 {
            return Err(format!("a {:?} key: phone apps read v4 keys only", cert.primary_key.version()));
        }
        if !cert.details.revocation_signatures.is_empty() {
            return Err("the key is revoked".into());
        }
        let self_sigs: Vec<Signature> = cert
            .details
            .users
            .iter()
            .flat_map(|u| u.signatures.iter().cloned())
            .chain(cert.details.direct_signatures.iter().cloned())
            .collect();
        let expires = latest(&self_sigs).and_then(|s| expiry(cert.primary_key.created_at().as_secs(), s));
        let subkeys: Vec<(usize, Option<u64>)> =
            (0..cert.public_subkeys.len()).filter_map(|i| usable(&cert.public_subkeys[i]).map(|e| (i, e))).collect();
        if subkeys.is_empty() {
            return Err("no valid encryption subkey (RSA or Curve25519)".into());
        }
        let fingerprint = cert.fingerprint().to_string().to_uppercase();
        let r = Recipient { cert, expires, subkeys, fingerprint };
        r.keys_at(now)?;
        Ok(r)
    }

    /// The subkeys to encrypt to at `now`, or why there are none (the key or every
    /// encryption subkey has expired since the start).
    fn keys_at(&self, now: u32) -> Result<Vec<usize>, String> {
        if !live(self.expires, now) {
            return Err(format!("the key expired on {}", date(self.expires.unwrap_or_default())));
        }
        let keys: Vec<usize> = self.subkeys.iter().filter(|(_, e)| live(*e, now)).map(|(i, _)| *i).collect();
        if keys.is_empty() {
            let last = self.subkeys.iter().filter_map(|(_, e)| *e).max().unwrap_or_default();
            return Err(format!("its encryption subkeys expired, the last on {}", date(last)));
        }
        Ok(keys)
    }

    /// Whether files can be encrypted to the key at `now`, and if not, why.
    pub fn check(&self, now: u32) -> Result<(), String> {
        self.keys_at(now).map(|_| ())
    }

    /// `data` as one encrypted OpenPGP message (binary), to the subkeys valid at `now`.
    pub fn seal(&self, data: Vec<u8>, now: u32) -> Result<Vec<u8>, String> {
        let keys = self.keys_at(now)?;
        let rng = rand08::rngs::OsRng;
        let mut builder = MessageBuilder::from_bytes("", data).seipd_v1(rng, SymmetricKeyAlgorithm::AES256);
        for i in keys {
            builder.encrypt_to_key(rng, &self.cert.public_subkeys[i]).map_err(|e| format!("encrypting: {e}"))?;
        }
        builder.to_vec(rng).map_err(|e| format!("encrypting: {e}"))
    }

    /// The fingerprint in groups of four, as OpenKeychain and iPGMail show it.
    pub fn pretty_fingerprint(&self) -> String {
        let chars: Vec<char> = self.fingerprint.chars().collect();
        chars.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pgp::composed::{EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder};
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::ser::Serialize;

    /// A v4 key as phones make them: an EdDSA primary, a Curve25519 encryption subkey.
    pub(crate) fn keypair() -> (SignedSecretKey, Vec<u8>) {
        let mut enc = SubkeyParamsBuilder::default();
        enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("logguard reports <admin@example.org>".into())
            .subkeys(vec![enc.build().unwrap()]);
        let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
        let public = SignedPublicKey::from(secret.clone()).to_bytes().unwrap();
        (secret, public)
    }

    pub(crate) fn open(secret: &SignedSecretKey, sealed: &[u8]) -> Vec<u8> {
        Message::from_bytes(sealed).unwrap().decrypt(&"".into(), secret).unwrap().as_data_vec().unwrap()
    }

    fn now() -> u32 {
        chrono::Utc::now().timestamp() as u32
    }

    #[test]
    fn sealed_files_open_with_the_admins_key_only() {
        let (secret, public) = keypair();
        let r = Recipient::parse(&public, now()).unwrap();
        assert_eq!(r.fingerprint.len(), 40);
        assert_eq!(r.pretty_fingerprint().split(' ').count(), 10);
        let report = b"Abuse report from xmpp (192.0.2.1) and vpn (192.0.2.2)\n".repeat(100);
        let sealed = r.seal(report.clone(), now()).unwrap();
        assert!(!sealed.windows(12).any(|w| w == b"Abuse report"), "nothing in clear");
        // a v3 PKESK packet (tag 1), then a SEIPD v1 packet (tag 18, version 1): what every app reads
        let tag = |b: u8| if b & 0x40 != 0 { b & 0x3f } else { (b >> 2) & 0x0f };
        assert_eq!(tag(sealed[0]), 1);
        assert_eq!(open(&secret, &sealed), report);

        let (other, _) = keypair();
        assert!(Message::from_bytes(&sealed[..]).unwrap().decrypt(&"".into(), &other).is_err(), "another key can't");
        // armored keys (as apps export them) work too
        let armored = SignedPublicKey::from(secret.clone()).to_armored_string(Default::default()).unwrap();
        assert_eq!(Recipient::parse(armored.as_bytes(), now()).unwrap().fingerprint, r.fingerprint);
    }

    #[test]
    fn unusable_keys_are_refused() {
        assert!(Recipient::parse(b"not a key", now()).is_err());
        let (secret, _) = keypair();
        // a certificate without its encryption subkey
        let mut public = SignedPublicKey::from(secret);
        public.public_subkeys.clear();
        let e = Recipient::parse(&public.to_bytes().unwrap(), now()).err().unwrap();
        assert!(e.contains("no valid encryption subkey"), "{e}");
    }
}
