//! Every mail is an OpenPGP message, as a whole: encrypted to the recipients' public keys
//! (`OPENPGP_KEY`), and signed with the bot's own key (`SIGNING_KEY`) if it has one.
//!
//! The format is the one every OpenPGP mail client reads (Thunderbird, K-9/Thunderbird for
//! Android with OpenKeychain, FairEmail, Apple Mail with GPG Suite, mutt with gpg): v4 keys
//! (RSA, or Curve25519 "legacy" ECDH), the session key in v3 PKESK packets, the data in a
//! SEIPD v1 packet (with MDC) under AES-256, no compression. Not SEIPD v2 / AEAD nor v6
//! keys (RFC 9580): many clients can't read them yet.
//!
//! Only public keys of the recipients are on the server: whoever gets into it can't read
//! mails that were already sent. The signing key is the bot's alone: it proves a mail comes
//! from this bot, and is worth nothing for reading anything.

use std::path::Path;

use pgp::composed::{
    ArmorOptions, Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, KeyVersion, Password};

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

/// One recipient's public key, checked.
pub struct Key {
    cert: SignedPublicKey,
    /// When the key as a whole expires (Unix time), if it does.
    expires: Option<u64>,
    /// The usable encryption subkeys (indices into `public_subkeys`) and when each expires.
    subkeys: Vec<(usize, Option<u64>)>,
    /// The primary key's fingerprint, as the apps show it (40 hex digits).
    pub fingerprint: String,
    /// The mail addresses in its user ids, lower case.
    pub addresses: Vec<String>,
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

/// Whether mail clients can encrypt to this algorithm in a v4 key.
fn supported(alg: PublicKeyAlgorithm) -> bool {
    matches!(alg, PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::ECDH)
}

/// A subkey the clients can decrypt with, and when it expires: an encryption subkey of a
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

/// The mail address in a user id: `Name <a@b>` or a bare `a@b`, lower case.
pub fn address_of(uid: &str) -> Option<String> {
    let a = match (uid.rfind('<'), uid.rfind('>')) {
        (Some(s), Some(e)) if s < e => &uid[s + 1..e],
        _ => uid.trim(),
    };
    (a.contains('@') && !a.contains(char::is_whitespace)).then(|| a.to_lowercase())
}

/// A fingerprint in groups of four, as the apps show it.
pub fn pretty(fingerprint: &str) -> String {
    let chars: Vec<char> = fingerprint.chars().collect();
    chars.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
}

impl Key {
    /// A public key, checked: its own signatures valid, a v4 key, not revoked, with an
    /// encryption subkey the clients can use. Whether it has expired is [`Key::usable_at`]'s
    /// question: a key can expire while the bot runs.
    pub fn check(cert: SignedPublicKey) -> Result<Key, String> {
        let cert = own_signatures_only(cert);
        let fingerprint = cert.fingerprint().to_string().to_uppercase();
        let fp = fingerprint.clone();
        let named = move |e: String| format!("key {fp}: {e}");
        cert.verify_bindings().map_err(|e| named(format!("its self-signatures don't verify: {e}")))?;
        if cert.primary_key.version() != KeyVersion::V4 {
            return Err(named(format!("a {:?} key: mail clients read v4 keys", cert.primary_key.version())));
        }
        if !cert.details.revocation_signatures.is_empty() {
            return Err(named("the key is revoked".into()));
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
            return Err(named("no valid encryption subkey (RSA or Curve25519)".into()));
        }
        let addresses = cert.details.users.iter().filter_map(|u| u.id.as_str().and_then(address_of)).collect();
        if cert.details.users.is_empty() {
            return Err(named("no user id signed by the key itself".into()));
        }
        Ok(Key { cert, expires, subkeys, fingerprint, addresses })
    }

    /// The subkeys to encrypt to at `now`, or why there are none (the key or every
    /// encryption subkey has expired since the start).
    fn keys_at(&self, now: u32) -> Result<Vec<&SignedPublicSubKey>, String> {
        if !live(self.expires, now) {
            return Err(format!("the key expired on {}", date(self.expires.unwrap_or_default())));
        }
        let keys: Vec<&SignedPublicSubKey> =
            self.subkeys.iter().filter(|(_, e)| live(*e, now)).map(|(i, _)| &self.cert.public_subkeys[*i]).collect();
        if keys.is_empty() {
            let last = self.subkeys.iter().filter_map(|(_, e)| *e).max().unwrap_or_default();
            return Err(format!("its encryption subkeys expired, the last on {}", date(last)));
        }
        Ok(keys)
    }

    /// Whether mails can be encrypted to the key at `now`, and if not, why.
    pub fn usable_at(&self, now: u32) -> Result<(), String> {
        self.keys_at(now).map(|_| ())
    }

    /// The last 16 hex digits of the fingerprint (the long key id).
    pub fn short(&self) -> &str {
        &self.fingerprint[self.fingerprint.len().saturating_sub(16)..]
    }
}

/// All public keys in `data` (armored or binary, one or several), checked.
pub fn parse_keys(data: &[u8]) -> Result<Vec<Key>, String> {
    let (certs, _) = SignedPublicKey::from_reader_many(data).map_err(|e| format!("not OpenPGP public keys: {e}"))?;
    let mut keys = Vec::new();
    for cert in certs {
        let cert = cert.map_err(|e| format!("not an OpenPGP public key: {e}"))?;
        keys.push(Key::check(cert)?);
    }
    if keys.is_empty() {
        return Err("no OpenPGP public key in it".into());
    }
    Ok(keys)
}

/// Who gets the mails, each with the key their mails are encrypted to.
pub struct Recipients {
    pub keys: Vec<Key>,
    /// (address, index into `keys`), in the order of MAIL_TO.
    pub to: Vec<(String, usize)>,
}

impl Recipients {
    /// The keys in `path` matched to the addresses: by the address in a user id; with a single
    /// key and no match, that key (`warn` says so). Every address needs a key: none gets mail
    /// in clear. A key that has expired only leaves its address out (`warn` says so) until it
    /// is replaced; with no usable key at all at `now`, nothing could be sent: an error.
    pub fn load(path: &Path, to: &[String], now: u32, warn: &mut dyn FnMut(String)) -> Result<Recipients, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&data, to, now, warn).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(data: &[u8], to: &[String], now: u32, warn: &mut dyn FnMut(String)) -> Result<Recipients, String> {
        let keys = parse_keys(data)?;
        let mut pairs = Vec::new();
        for addr in to {
            let lower = addr.to_lowercase();
            let i = match keys.iter().position(|k| k.addresses.contains(&lower)) {
                Some(i) => i,
                None if keys.len() == 1 => {
                    warn(format!(
                        "no user id of key {} names {addr}; mails to it are encrypted to that key anyway (clients may say so)",
                        keys[0].short()
                    ));
                    0
                }
                None => return Err(format!("no key for {addr}: with several keys, each address must be in a user id of one")),
            };
            if !pairs.iter().any(|(a, _): &(String, usize)| a.eq_ignore_ascii_case(addr)) {
                pairs.push((addr.clone(), i));
            }
        }
        let r = Recipients { keys, to: pairs };
        let (ok, not) = r.split(now);
        if ok.is_empty() {
            return Err(not.into_iter().map(|(a, why)| format!("{a}: {why}")).collect::<Vec<_>>().join("; "));
        }
        for (a, why) in not {
            warn(format!("no mail to {a} until its key is replaced: {why}"));
        }
        Ok(r)
    }

    /// The addresses whose keys are usable at `now`, and the others with the reason.
    pub fn split(&self, now: u32) -> (Vec<String>, Vec<(String, String)>) {
        let (mut ok, mut not) = (Vec::new(), Vec::new());
        for (addr, i) in &self.to {
            match self.keys[*i].usable_at(now) {
                Ok(()) => ok.push(addr.clone()),
                Err(e) => not.push((addr.clone(), format!("key {}: {e}", self.keys[*i].short()))),
            }
        }
        (ok, not)
    }

    /// The keys of `addresses` (each once).
    fn keys_for(&self, addresses: &[String]) -> Vec<&Key> {
        let mut idx: Vec<usize> = self.to.iter().filter(|(a, _)| addresses.contains(a)).map(|(_, i)| *i).collect();
        idx.sort_unstable();
        idx.dedup();
        idx.into_iter().map(|i| &self.keys[i]).collect()
    }
}

/// The bot's own key: signs every mail, and goes out in the Autocrypt header so clients
/// learn it and show the signature as valid.
pub struct Signer {
    key: SignedSecretKey,
    pub fingerprint: String,
    /// The public key as clients want it in the Autocrypt header (binary).
    pub public: Vec<u8>,
}

impl Signer {
    pub fn load(path: &Path) -> Result<Signer, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&data).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(data: &[u8]) -> Result<Signer, String> {
        let (key, _) = SignedSecretKey::from_reader_single(data).map_err(|e| format!("not an OpenPGP secret key: {e}"))?;
        key.verify_bindings().map_err(|e| format!("its self-signatures don't verify: {e}"))?;
        if key.primary_key.version() != KeyVersion::V4 {
            return Err("not a v4 key".into());
        }
        // a passphrase would have to sit next to the key on the server: none
        let mut probe = MessageBuilder::from_bytes("", b"probe".to_vec());
        probe.sign(&key.primary_key, Password::empty(), HashAlgorithm::Sha256);
        let signed = probe.to_vec(rand08::rngs::OsRng).map_err(|e| format!("can't sign with it (a key with a passphrase?): {e}"))?;
        // the secret part must match the public one: a damaged file can carry intact
        // self-signatures and still make every mail's signature bad (found by fuzzing)
        let verified = Message::from_bytes(&signed[..]).and_then(|mut m| {
            m.as_data_vec()?;
            m.verify(&key.primary_key.public_key()).map(|_| ())
        });
        verified.map_err(|_| "its secret part doesn't match its public key (a damaged file?)".to_string())?;
        let fingerprint = key.fingerprint().to_string().to_uppercase();
        let public = key.to_public_key().to_bytes().map_err(|e| e.to_string())?;
        Ok(Signer { key, fingerprint, public })
    }

    /// A new key for the bot (`keygen`): Ed25519 to sign, a Curve25519 subkey as Autocrypt
    /// wants one (nothing is ever encrypted to it). Armored secret key, armored public key.
    pub fn generate(address: &str) -> Result<(String, String), String> {
        let mut enc = SubkeyParamsBuilder::default();
        enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(format!("logguard-mail-bot <{address}>"))
            .subkeys(vec![enc.build().map_err(|e| e.to_string())?]);
        let secret = params.build().map_err(|e| e.to_string())?.generate(rand08::rngs::OsRng).map_err(|e| e.to_string())?;
        let armored = secret.to_armored_string(ArmorOptions::default()).map_err(|e| e.to_string())?;
        let public = SignedPublicKey::from(secret).to_armored_string(ArmorOptions::default()).map_err(|e| e.to_string())?;
        Ok((armored, public))
    }
}

/// `data` as one armored OpenPGP message: encrypted to the keys of `addresses` usable at
/// `now`, signed by `signer` if there is one.
pub fn seal(data: Vec<u8>, recipients: &Recipients, addresses: &[String], signer: Option<&Signer>, now: u32) -> Result<String, String> {
    let rng = rand08::rngs::OsRng;
    let mut builder = MessageBuilder::from_bytes("", data).seipd_v1(rng, SymmetricKeyAlgorithm::AES256);
    let keys = recipients.keys_for(addresses);
    if keys.is_empty() {
        return Err("no recipient".into());
    }
    for key in keys {
        for sub in key.keys_at(now)? {
            builder.encrypt_to_key(rng, sub).map_err(|e| format!("encrypting: {e}"))?;
        }
    }
    if let Some(s) = signer {
        builder.sign(&s.key.primary_key, Password::empty(), HashAlgorithm::Sha256);
    }
    builder.to_armored_string(rng, ArmorOptions::default()).map_err(|e| format!("encrypting: {e}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A v4 key as phones and Thunderbird make them: an EdDSA primary, a Curve25519 encryption subkey.
    pub(crate) fn keypair(addr: &str) -> (SignedSecretKey, Vec<u8>) {
        let mut enc = SubkeyParamsBuilder::default();
        enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(format!("Admin <{addr}>"))
            .subkeys(vec![enc.build().unwrap()]);
        let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
        let public = SignedPublicKey::from(secret.clone()).to_bytes().unwrap();
        (secret, public)
    }

    pub(crate) fn open(secret: &SignedSecretKey, armored: &str) -> Vec<u8> {
        let (msg, _) = Message::from_armor(armored.as_bytes()).unwrap();
        let mut msg = msg.decrypt(&"".into(), secret).unwrap();
        msg.as_data_vec().unwrap()
    }

    fn now() -> u32 {
        chrono::Utc::now().timestamp() as u32
    }

    fn no_warning(w: String) {
        panic!("unexpected warning: {w}");
    }

    #[test]
    fn mails_open_with_each_recipients_key_only() {
        let (alice, alice_pub) = keypair("alice@example.org");
        let (bob, bob_pub) = keypair("bob@example.org");
        let ring = [alice_pub.clone(), bob_pub].concat();
        let to = vec!["Bob@Example.org".to_string(), "alice@example.org".to_string()];
        let r = Recipients::parse(&ring, &to, now(), &mut no_warning).unwrap();
        assert_eq!(r.to.iter().map(|(_, i)| *i).collect::<Vec<_>>(), [1, 0], "matched by user id, case aside");
        let text = "[xmpp] logguard: system\n\nsecret line → ✓\n".repeat(50);
        let sealed = seal(text.clone().into_bytes(), &r, &to, None, now()).unwrap();
        assert!(sealed.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(!sealed.contains("secret line"));
        assert_eq!(open(&alice, &sealed), text.as_bytes());
        assert_eq!(open(&bob, &sealed), text.as_bytes());

        // only to bob: alice can't read it
        let only_bob = seal(b"x".to_vec(), &r, &to[..1], None, now()).unwrap();
        let (msg, _) = Message::from_armor(only_bob.as_bytes()).unwrap();
        assert!(msg.decrypt(&"".into(), &alice).is_err());

        // several keys: an address without one is refused
        let e = Recipients::parse(&ring, &["carol@example.org".into()], now(), &mut no_warning).err().unwrap();
        assert!(e.contains("no key for carol@example.org"), "{e}");
        // one key: used for any address, with a warning
        let mut warned = Vec::new();
        let one = Recipients::parse(&alice_pub, &["ops@example.net".into()], now(), &mut |w| warned.push(w)).unwrap();
        assert_eq!(one.to, [("ops@example.net".to_string(), 0)]);
        assert_eq!(warned.len(), 1);
    }

    #[test]
    fn signed_mails_verify_with_the_bots_key() {
        let (admin, admin_pub) = keypair("admin@example.org");
        let (secret, public) = Signer::generate("alerts@example.org").unwrap();
        assert!(public.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let signer = Signer::parse(secret.as_bytes()).unwrap();
        let to = vec!["admin@example.org".to_string()];
        let r = Recipients::parse(&admin_pub, &to, now(), &mut no_warning).unwrap();
        let sealed = seal(b"signed text".to_vec(), &r, &to, Some(&signer), now()).unwrap();
        let (msg, _) = Message::from_armor(sealed.as_bytes()).unwrap();
        let mut msg = msg.decrypt(&"".into(), &admin).unwrap();
        assert_eq!(msg.as_data_vec().unwrap(), b"signed text");
        let (bots, _) = SignedPublicKey::from_armor_single(public.as_bytes()).unwrap();
        msg.verify(&bots.primary_key).expect("the bot's signature verifies");
        // the Autocrypt key: the same public key, binary
        let (from_header, _) = SignedPublicKey::from_reader_single(&signer.public[..]).unwrap();
        assert_eq!(from_header.fingerprint(), bots.fingerprint());
        let k = Key::check(from_header).unwrap();
        assert_eq!(k.addresses, ["alerts@example.org"]);
    }

    #[test]
    fn unusable_keys_are_refused() {
        assert!(parse_keys(b"not a key").is_err());
        let (secret, _) = keypair("a@example.org");
        let mut public = SignedPublicKey::from(secret);
        public.public_subkeys.clear();
        let e = parse_keys(&public.to_bytes().unwrap()).err().unwrap();
        assert!(e.contains("no valid encryption subkey"), "{e}");
        assert!(Signer::parse(&public.to_bytes().unwrap()).is_err(), "a public key can't sign");
    }

    #[test]
    fn signatures_of_others_on_a_key_are_ignored() {
        use pgp::packet::{SignatureConfig, SignatureType};
        let (secret, public) = keypair("admin@example.org");
        let (other, _) = keypair("friend@example.org");
        let (mut cert, _) = SignedPublicKey::from_reader_single(&public[..]).unwrap();
        // the friend certifies the admin's user id, as `gpg --sign-key` does
        let user = cert.details.users[0].clone();
        let mut config = SignatureConfig::from_key(rand08::thread_rng(), &other.primary_key, SignatureType::CertGeneric).unwrap();
        config.hashed_subpackets = vec![
            pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::IssuerFingerprint(other.fingerprint())).unwrap(),
            pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::SignatureCreationTime(pgp::types::Timestamp::now())).unwrap(),
        ];
        let sig = config
            .sign_certification_third_party(&other.primary_key, &Password::empty(), &secret.primary_key, pgp::types::Tag::UserId, &user.id)
            .unwrap();
        cert.details.users[0].signatures.push(sig);
        assert!(cert.verify_bindings().is_err(), "rpgp alone takes it for a broken self-signature");
        let k = Key::check(cert).expect("the key is fine");
        assert_eq!(k.addresses, ["admin@example.org"]);
    }

    #[test]
    fn an_expired_key_leaves_out_its_address_only() {
        let (_, alice) = keypair("alice@example.org");
        let (_, bob) = keypair("bob@example.org");
        let ring = [alice, bob].concat();
        let to = vec!["alice@example.org".to_string(), "bob@example.org".to_string(), "ALICE@example.org".to_string()];
        let r = Recipients::parse(&ring, &to, now(), &mut no_warning).unwrap();
        assert_eq!(r.to.len(), 2, "an address twice is mailed once");
        // pretend alice's key expired
        let mut r = r;
        r.keys[0].expires = Some(u64::from(now()) - 1);
        let (ok, not) = r.split(now());
        assert_eq!(ok, ["bob@example.org"]);
        assert!(not[0].1.contains("the key expired"), "{not:?}");
        r.keys[1].expires = Some(u64::from(now()) - 1);
        assert!(r.split(now()).0.is_empty());
    }

    #[test]
    fn user_id_addresses() {
        assert_eq!(address_of("Admin <Admin@Example.org>").as_deref(), Some("admin@example.org"));
        assert_eq!(address_of("admin@example.org").as_deref(), Some("admin@example.org"));
        assert_eq!(address_of("Just a name"), None);
        assert_eq!(address_of("x <not an address>"), None);
        assert_eq!(pretty("ABCDEF0123456789"), "ABCD EF01 2345 6789");
    }
}
