//! Matrix's key formats around vodozemac: canonical JSON and its Ed25519 signatures, device
//! and cross-signing keys as `/keys/query` returns them, claimed one-time keys, and encrypted
//! attachments (<https://spec.matrix.org/v1.16/client-server-api/#end-to-end-encryption>).
//!
//! Everything the homeserver hands over is checked here before the bot uses it: a device key
//! must carry its own valid signature, a self-signing key its master key's, a cross-signed
//! device the self-signing key's, a one-time key its device's. The homeserver can withhold
//! keys, not forge them.

use std::collections::BTreeSet;

use aes::cipher::{KeyIvInit, StreamCipher};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use vodozemac::olm::Account;
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

pub const OLM: &str = "m.olm.v1.curve25519-aes-sha2";
pub const MEGOLM: &str = "m.megolm.v1.aes-sha2";

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Matrix's canonical JSON of `v` without its `signatures` and `unsigned`: what a signature
/// covers. serde_json's map is ordered by key and writes no blanks, as canonical JSON wants.
pub fn canonical(v: &Value) -> String {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("signatures");
        o.remove("unsigned");
    }
    v.to_string()
}

/// `v` with a signature by `key_id` of `user` added (the other signatures kept).
pub fn signed(v: &Value, user: &str, key_id: &str, sign: impl Fn(&[u8]) -> Ed25519Signature) -> Value {
    let sig = sign(canonical(v).as_bytes()).to_base64();
    let mut out = v.clone();
    out["signatures"][user][key_id] = Value::String(sig);
    out
}

/// Whether `v` carries a valid signature by `key` under `user`'s `key_id`.
pub fn verify(v: &Value, user: &str, key_id: &str, key: &Ed25519PublicKey) -> bool {
    let Some(sig) = v.get("signatures").and_then(|s| s.get(user)).and_then(|s| s.get(key_id)).and_then(Value::as_str) else {
        return false;
    };
    let Ok(sig) = Ed25519Signature::from_base64(sig) else { return false };
    key.verify(canonical(v).as_bytes(), &sig).is_ok()
}

/// The bot's device keys, signed by its device: what `/keys/upload` publishes.
pub fn device_keys(account: &Account, user: &str, device: &str) -> Value {
    let keys = json!({
        "user_id": user,
        "device_id": device,
        "algorithms": [OLM, MEGOLM],
        "keys": {
            format!("curve25519:{device}"): account.curve25519_key().to_base64(),
            format!("ed25519:{device}"): account.ed25519_key().to_base64(),
        },
    });
    signed(&keys, user, &format!("ed25519:{device}"), |m| account.sign(m))
}

/// A device of another user, its keys checked.
#[derive(Debug, Clone)]
pub struct Device {
    pub device_id: String,
    pub ed25519: Ed25519PublicKey,
    pub curve25519: Curve25519PublicKey,
    /// The device keys as published: cross-signatures are checked on them.
    raw: Value,
}

/// `user`'s device `device_id` from a `/keys/query` reply: it must name itself, support Olm
/// and Megolm, and be signed by its own Ed25519 key.
pub fn parse_device(user: &str, device_id: &str, v: &Value) -> Result<Device, String> {
    if v.get("user_id").and_then(Value::as_str) != Some(user) || v.get("device_id").and_then(Value::as_str) != Some(device_id) {
        return Err("names another user or device".into());
    }
    let algorithms: Vec<&str> = v.get("algorithms").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
    if !algorithms.contains(&OLM) || !algorithms.contains(&MEGOLM) {
        return Err("doesn't do Olm and Megolm".into());
    }
    let key = |kind: &str| v.get("keys").and_then(|k| k.get(format!("{kind}:{device_id}"))).and_then(Value::as_str);
    let ed25519 = key("ed25519").and_then(|k| Ed25519PublicKey::from_base64(k).ok()).ok_or("no valid Ed25519 key")?;
    let curve25519 = key("curve25519").and_then(|k| Curve25519PublicKey::from_base64(k).ok()).ok_or("no valid Curve25519 key")?;
    if !verify(v, user, &format!("ed25519:{device_id}"), &ed25519) {
        return Err("its self-signature doesn't verify".into());
    }
    Ok(Device { device_id: device_id.to_string(), ed25519, curve25519, raw: v.clone() })
}

/// A cross-signing key of `user` with `usage` (master, self_signing): the one Ed25519 key it
/// holds.
fn parse_cross_key(user: &str, usage: &str, v: &Value) -> Result<(Ed25519PublicKey, Value), String> {
    if v.get("user_id").and_then(Value::as_str) != Some(user) {
        return Err(format!("the {usage} key names another user"));
    }
    if !v.get("usage").and_then(Value::as_array).is_some_and(|u| u.iter().any(|x| x.as_str() == Some(usage))) {
        return Err(format!("the {usage} key isn't one"));
    }
    let keys = v.get("keys").and_then(Value::as_object).ok_or(format!("the {usage} key has no keys"))?;
    let [(id, key)] = keys.iter().collect::<Vec<_>>()[..] else { return Err(format!("the {usage} key holds more or less than one key")) };
    let key = key.as_str().unwrap_or_default();
    if id.strip_prefix("ed25519:") != Some(key) {
        return Err(format!("the {usage} key's id doesn't match it"));
    }
    let k = Ed25519PublicKey::from_base64(key).map_err(|_| format!("the {usage} key isn't an Ed25519 key"))?;
    Ok((k, v.clone()))
}

/// What `/keys/query` says about one user, checked.
#[derive(Debug, Default)]
pub struct UserKeys {
    /// Their master cross-signing key, if they have one.
    pub master: Option<Ed25519PublicKey>,
    /// Their devices whose own signatures verify.
    pub devices: Vec<Device>,
    /// Which of those their self-signing key (signed by the master key) has signed.
    pub cross_signed: BTreeSet<String>,
    /// What was left out, and why.
    pub problems: Vec<String>,
}

/// `user`'s keys in a `/keys/query` reply.
pub fn user_keys(reply: &Value, user: &str) -> UserKeys {
    let mut out = UserKeys::default();
    if let Some(devices) = reply.get("device_keys").and_then(|d| d.get(user)).and_then(Value::as_object) {
        for (id, v) in devices {
            match parse_device(user, id, v) {
                Ok(d) => out.devices.push(d),
                Err(e) => out.problems.push(format!("device {}: {e}", crate::bot::shown(id))),
            }
        }
    }
    let Some(master) = reply.get("master_keys").and_then(|m| m.get(user)) else { return out };
    let master = match parse_cross_key(user, "master", master) {
        Ok((k, _)) => k,
        Err(e) => {
            out.problems.push(e);
            return out;
        }
    };
    out.master = Some(master);
    let Some(ssk) = reply.get("self_signing_keys").and_then(|m| m.get(user)) else { return out };
    let (ssk, raw) = match parse_cross_key(user, "self_signing", ssk) {
        Ok(k) => k,
        Err(e) => {
            out.problems.push(e);
            return out;
        }
    };
    if !verify(&raw, user, &format!("ed25519:{}", master.to_base64()), &master) {
        out.problems.push("the self-signing key isn't signed by the master key".into());
        return out;
    }
    let ssk_id = format!("ed25519:{}", ssk.to_base64());
    out.cross_signed = out.devices.iter().filter(|d| verify(&d.raw, user, &ssk_id, &ssk)).map(|d| d.device_id.clone()).collect();
    out
}

/// The one-time (or fallback) key claimed for `device`, if it carries the device's signature.
pub fn claimed_key(reply: &Value, user: &str, device: &Device) -> Option<Curve25519PublicKey> {
    let keys = reply.get("one_time_keys")?.get(user)?.get(&device.device_id)?.as_object()?;
    keys.iter().find_map(|(id, v)| {
        if !id.starts_with("signed_curve25519:") || !verify(v, user, &format!("ed25519:{}", device.device_id), &device.ed25519) {
            return None;
        }
        Curve25519PublicKey::from_base64(v.get("key")?.as_str()?).ok()
    })
}

/// The bot account's cross-signing keys as `/keys/device_signing/upload` takes them: the
/// master key, and the self-signing key it signs. (No user-signing key: the bot verifies
/// no one by signature.)
pub fn cross_signing_keys(user: &str, master: &Ed25519SecretKey, self_signing: &Ed25519SecretKey) -> Value {
    let key = |k: &Ed25519SecretKey, usage: &str| {
        let public = k.public_key().to_base64();
        json!({ "user_id": user, "usage": [usage], "keys": { format!("ed25519:{public}"): public } })
    };
    let master_id = format!("ed25519:{}", master.public_key().to_base64());
    json!({
        "master_key": key(master, "master"),
        "self_signing_key": signed(&key(self_signing, "self_signing"), user, &master_id, |m| master.sign(m)),
    })
}

/// The bot's device keys signed by its self-signing key, for `/keys/signatures/upload`.
pub fn device_signature(device_keys: &Value, user: &str, device: &str, self_signing: &Ed25519SecretKey) -> Value {
    let mut keys = device_keys.clone();
    if let Some(o) = keys.as_object_mut() {
        o.remove("signatures");
    }
    let id = format!("ed25519:{}", self_signing.public_key().to_base64());
    json!({ user: { device: signed(&keys, user, &id, |m| self_signing.sign(m)) } })
}

/// `data` encrypted as a Matrix attachment: the ciphertext to upload, and the `file` object
/// for the event (without its `url`): AES-256-CTR under a fresh key, the SHA-256 of the
/// ciphertext.
pub fn encrypt_attachment(data: &[u8]) -> (Vec<u8>, Value) {
    let key: [u8; 32] = rand::random();
    let mut iv = [0u8; 16];
    // the lower 64 bits are the block counter, from zero
    iv[..8].copy_from_slice(&rand::random::<[u8; 8]>());
    let mut out = data.to_vec();
    Aes256Ctr::new(&key.into(), &iv.into()).apply_keystream(&mut out);
    let file = json!({
        "v": "v2",
        "key": { "kty": "oct", "key_ops": ["encrypt", "decrypt"], "alg": "A256CTR", "k": URL_SAFE_NO_PAD.encode(key), "ext": true },
        "iv": STANDARD_NO_PAD.encode(iv),
        "hashes": { "sha256": STANDARD_NO_PAD.encode(Sha256::digest(&out)) },
    });
    (out, file)
}

/// An attachment decrypted with its `file` object (what a client does; for the tests).
pub fn decrypt_attachment(ciphertext: &[u8], file: &Value) -> Option<Vec<u8>> {
    let key: [u8; 32] = URL_SAFE_NO_PAD.decode(file["key"]["k"].as_str()?).ok()?.try_into().ok()?;
    let iv: [u8; 16] = STANDARD_NO_PAD.decode(file["iv"].as_str()?).ok()?.try_into().ok()?;
    let hash = STANDARD_NO_PAD.decode(file["hashes"]["sha256"].as_str()?).ok()?;
    if Sha256::digest(ciphertext).as_slice() != hash {
        return None;
    }
    let mut out = ciphertext.to_vec();
    Aes256Ctr::new(&key.into(), &iv.into()).apply_keystream(&mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "@admin:example.org";

    /// A device as a client publishes it.
    fn device(account: &Account, id: &str) -> Value {
        device_keys(account, USER, id)
    }

    fn reply(devices: &[(&str, Value)], cross: Option<Value>) -> Value {
        let mut r = json!({ "device_keys": { USER: devices.iter().map(|(k, v)| (k.to_string(), v.clone())).collect::<serde_json::Map<String, Value>>() } });
        if let Some(c) = cross {
            r["master_keys"] = json!({ USER: c["master_key"] });
            r["self_signing_keys"] = json!({ USER: c["self_signing_key"] });
        }
        r
    }

    #[test]
    fn canonical_json_and_signatures() {
        let v = json!({ "b": 1, "a": { "y": "é", "x": [1, 2] }, "signatures": { "x": {} }, "unsigned": { "z": 1 } });
        assert_eq!(canonical(&v), r#"{"a":{"x":[1,2],"y":"é"},"b":1}"#);
        let k = Ed25519SecretKey::new();
        let s = signed(&v, USER, "ed25519:K", |m| k.sign(m));
        assert!(verify(&s, USER, "ed25519:K", &k.public_key()));
        assert!(s["unsigned"]["z"] == 1, "unsigned is kept, not signed");
        let mut tampered = s.clone();
        tampered["b"] = json!(2);
        assert!(!verify(&tampered, USER, "ed25519:K", &k.public_key()));
        assert!(!verify(&s, USER, "ed25519:other", &k.public_key()));
        assert!(!verify(&s, "@x:example.org", "ed25519:K", &k.public_key()));
    }

    #[test]
    fn devices_must_sign_themselves() {
        let a = Account::new();
        let good = device(&a, "PHONE");
        let d = parse_device(USER, "PHONE", &good).unwrap();
        assert_eq!(d.curve25519, a.curve25519_key());
        assert!(parse_device(USER, "OTHER", &good).is_err(), "listed under another id");
        assert!(parse_device("@x:example.org", "PHONE", &good).is_err());
        // the homeserver swaps in its own Curve25519 key
        let mut swapped = good.clone();
        swapped["keys"]["curve25519:PHONE"] = json!(Account::new().curve25519_key().to_base64());
        assert!(parse_device(USER, "PHONE", &swapped).unwrap_err().contains("self-signature"));
        let mut no_megolm = good;
        no_megolm["algorithms"] = json!([OLM]);
        assert!(parse_device(USER, "PHONE", &no_megolm).is_err());
    }

    #[test]
    fn cross_signed_devices() {
        let (phone, laptop, fake) = (Account::new(), Account::new(), Account::new());
        let (master, ssk) = (Ed25519SecretKey::new(), Ed25519SecretKey::new());
        let cross = cross_signing_keys(USER, &master, &ssk);
        let phone_keys = device(&phone, "PHONE");
        let signed_phone = &device_signature(&phone_keys, USER, "PHONE", &ssk)[USER]["PHONE"];
        let mut phone_both = phone_keys.clone();
        phone_both["signatures"][USER].as_object_mut().unwrap().extend(signed_phone["signatures"][USER].as_object().unwrap().clone());
        let r = reply(&[("PHONE", phone_both), ("LAPTOP", device(&laptop, "LAPTOP"))], Some(cross.clone()));
        let k = user_keys(&r, USER);
        assert_eq!(k.master, Some(master.public_key()));
        assert_eq!(k.devices.len(), 2);
        assert_eq!(k.cross_signed.iter().collect::<Vec<_>>(), ["PHONE"], "the laptop isn't verified");
        assert!(k.problems.is_empty(), "{:?}", k.problems);

        // a self-signing key the master key didn't sign: nothing counts as cross-signed
        let mut forged = cross.clone();
        forged["self_signing_key"] = cross_signing_keys(USER, &Ed25519SecretKey::new(), &ssk)["self_signing_key"].clone();
        let k = user_keys(&reply(&[("PHONE", device(&phone, "PHONE"))], Some(forged)), USER);
        assert!(k.cross_signed.is_empty());
        assert_eq!(k.problems, ["the self-signing key isn't signed by the master key"]);

        // a device signed by nobody, a broken one, no cross-signing at all
        let mut broken = device(&fake, "FAKE");
        broken["device_id"] = json!("PHONE");
        let k = user_keys(&reply(&[("FAKE", broken), ("LAPTOP", device(&laptop, "LAPTOP"))], None), USER);
        assert_eq!(k.devices.len(), 1);
        assert!(k.master.is_none() && k.cross_signed.is_empty());
        assert_eq!(k.problems.len(), 1);
    }

    #[test]
    fn claimed_keys_need_the_devices_signature() {
        let a = Account::new();
        let d = parse_device(USER, "PHONE", &device(&a, "PHONE")).unwrap();
        let otk = Account::new().curve25519_key().to_base64();
        let key = signed(&json!({ "key": otk }), USER, "ed25519:PHONE", |m| a.sign(m));
        let r = json!({ "one_time_keys": { USER: { "PHONE": { "signed_curve25519:AAAAAQ": key } } } });
        assert_eq!(claimed_key(&r, USER, &d).map(|k| k.to_base64()), Some(otk.clone()));
        let other = signed(&json!({ "key": otk }), USER, "ed25519:PHONE", |m| Account::new().sign(m));
        let r = json!({ "one_time_keys": { USER: { "PHONE": { "signed_curve25519:AAAAAQ": other } } } });
        assert!(claimed_key(&r, USER, &d).is_none(), "signed by another key");
        assert!(claimed_key(&json!({ "one_time_keys": {} }), USER, &d).is_none());
    }

    #[test]
    fn attachments() {
        let data = b"Abuse report\n".repeat(1000);
        let (ct, file) = encrypt_attachment(&data);
        assert_ne!(ct, data);
        assert_eq!(file["key"]["alg"], "A256CTR");
        assert_eq!(STANDARD_NO_PAD.decode(file["iv"].as_str().unwrap()).unwrap()[8..], [0; 8]);
        assert_eq!(decrypt_attachment(&ct, &file).unwrap(), data);
        let mut damaged = ct.clone();
        damaged[5] ^= 1;
        assert!(decrypt_attachment(&damaged, &file).is_none(), "the hash catches it");
        let (ct2, _) = encrypt_attachment(&data);
        assert_ne!(ct, ct2, "a fresh key each time");
    }
}
