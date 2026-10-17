//! Interoperability with omemo-dr (Gajim's OMEMO library) through
//! tests/omemo_oracle/oracle.py. Runs when OMEMO_ORACLE_PYTHON names a Python with
//! omemo-dr installed (scripts/omemo-oracle.sh sets one up); skipped otherwise.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::crypto::{self, KeyPair, PublicKey};
use super::*;

const ORACLE_JID: &str = "oracle@example.org";
const BOT_JID: &str = "bot@example.org";

struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    fn start() -> Option<Oracle> {
        let Ok(python) = std::env::var("OMEMO_ORACLE_PYTHON") else {
            eprintln!("skipped: set OMEMO_ORACLE_PYTHON (scripts/omemo-oracle.sh)");
            return None;
        };
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/omemo_oracle/oracle.py");
        let mut child =
            Command::new(python).args(["-I", script]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("starting the oracle");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Some(Oracle { child, stdin, stdout })
    }

    fn call(&mut self, req: Value) -> Result<Value, String> {
        writeln!(self.stdin, "{req}").unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).expect("oracle reply");
        match reply.get("error") {
            Some(e) => Err(e.as_str().unwrap().to_string()),
            None => Ok(reply["ok"].clone()),
        }
    }

    fn ok(&mut self, req: Value) -> Value {
        let cmd = req["cmd"].clone();
        self.call(req).unwrap_or_else(|e| panic!("oracle {cmd}: {e}"))
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

fn unb64(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}

fn to_json(e: &Encrypted) -> Value {
    json!({
        "sid": e.header.sid,
        "iv": b64(&e.header.iv.data),
        "keys": e.header.keys.iter().map(|k| json!({"rid": k.rid, "data": b64(&k.data), "prekey": k.prekey})).collect::<Vec<_>>(),
        "payload": e.payload.as_ref().map(|p| b64(&p.data)),
    })
}

fn from_json(v: &Value) -> Encrypted {
    Encrypted {
        header: Header {
            sid: v["sid"].as_u64().unwrap() as u32,
            keys: v["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| Key { rid: k["rid"].as_u64().unwrap() as u32, prekey: k["prekey"].as_bool().unwrap(), data: unb64(&k["data"]) })
                .collect(),
            iv: IV { data: unb64(&v["iv"]) },
        },
        payload: (!v["payload"].is_null()).then(|| Payload { data: unb64(&v["payload"]) }),
    }
}

fn bundle_to_json(omemo: &Omemo) -> Value {
    let b = omemo.bundle();
    let spk = b.signed_pre_key_public.unwrap();
    json!({
        "device_id": omemo.device_id(),
        "ik": b64(&b.identity_key.unwrap().data),
        "spk": {"id": spk.signed_pre_key_id.unwrap(), "key": b64(&spk.data)},
        "spk_signature": b64(&b.signed_pre_key_signature.unwrap().data),
        "otpks": b.prekeys.unwrap().keys.iter().map(|k| json!({"id": k.pre_key_id, "key": b64(&k.data)})).collect::<Vec<_>>(),
    })
}

fn bundle_from_json(v: &Value) -> Bundle {
    Bundle {
        signed_pre_key_public: Some(SignedPreKeyPublic {
            signed_pre_key_id: Some(v["spk"]["id"].as_u64().unwrap() as u32),
            data: unb64(&v["spk"]["key"]),
        }),
        signed_pre_key_signature: Some(SignedPreKeySignature { data: unb64(&v["spk_signature"]) }),
        identity_key: Some(IdentityKey { data: unb64(&v["ik"]) }),
        prekeys: Some(Prekeys {
            keys: v["otpks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| PreKeyPublic { pre_key_id: k["id"].as_u64().unwrap() as u32, data: unb64(&k["key"]) })
                .collect(),
        }),
    }
}

fn store(name: &str) -> Omemo {
    let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-oracle-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("omemo.json");
    let _ = std::fs::remove_file(&path);
    Omemo::open(&path, 1_000_000).unwrap()
}

/// Oracle message for the bot -> decrypted by the bot.
fn oracle_to_bot(o: &mut Oracle, bot: &mut Omemo, text: &str) -> Decrypted {
    let m = o.ok(json!({"cmd": "encrypt", "jid": BOT_JID, "text": text}));
    bot.decrypt(ORACLE_JID, &from_json(&m)).unwrap()
}

/// Bot message for the oracle -> decrypted by the oracle.
fn bot_to_oracle(o: &mut Oracle, bot: &mut Omemo, devices: &[u32], text: &str) -> String {
    let e = bot.encrypt(ORACLE_JID, devices, Some(text)).unwrap();
    let r = o.ok(json!({"cmd": "decrypt", "jid": BOT_JID, "message": to_json(&e)}));
    r["text"].as_str().unwrap().to_string()
}

fn oracle_identity(o: &mut Oracle) -> (u32, String) {
    let id = o.ok(json!({"cmd": "identity"}));
    (id["device_id"].as_u64().unwrap() as u32, id["fingerprint"].as_str().unwrap().to_string())
}

#[test]
fn xeddsa_signatures_both_ways() {
    let Some(mut o) = Oracle::start() else { return };
    for i in 0..40 {
        let msg = crypto::random::<33>();
        let k = KeyPair::generate();
        let sig = k.sign(&msg);
        let v = json!({"cmd": "verify_signature", "key": b64(&k.public.serialize()), "message": b64(&msg), "signature": b64(&sig)});
        assert_eq!(o.ok(v), json!(true), "libsignal rejects our signature #{i}");
        let mut bad = sig;
        bad[10] ^= 4;
        let v = json!({"cmd": "verify_signature", "key": b64(&k.public.serialize()), "message": b64(&msg), "signature": b64(&bad)});
        assert_eq!(o.ok(v), json!(false));

        let r = o.ok(json!({"cmd": "sign", "message": b64(&msg)}));
        let key = PublicKey::parse(&unb64(&r["key"])).unwrap();
        assert!(crypto::verify(&key, &msg, &unb64(&r["signature"])), "we reject libsignal's signature #{i}");
        assert!(!crypto::verify(&key, &msg[1..], &unb64(&r["signature"])));
    }
}

#[test]
fn oracle_starts_the_session() {
    let Some(mut o) = Oracle::start() else { return };
    let mut bot = store("o-starts");
    let (oracle_dev, oracle_fp) = oracle_identity(&mut o);
    o.ok(json!({"cmd": "set_devices", "jid": BOT_JID, "devices": [bot.device_id()]}));
    o.ok(json!({"cmd": "build_session", "jid": BOT_JID, "bundle": bundle_to_json(&bot)}));

    // the oracle keeps sending PreKey messages until the bot answers
    for text in ["/help", "/list", "/online"] {
        let d = oracle_to_bot(&mut o, &mut bot, text);
        assert_eq!(d.body.as_deref(), Some(text));
        assert_eq!(d.device_id, oracle_dev);
        assert_eq!(d.identity.fingerprint(), oracle_fp);
    }
    assert_eq!(bot.data.pre_keys.len(), PRE_KEYS - 1, "one session, one prekey");

    assert_eq!(bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "✓ Registered users (2):\n  • admin"), "✓ Registered users (2):\n  • admin");
    for i in 0..10 {
        let t = format!("from oracle {i}");
        assert_eq!(oracle_to_bot(&mut o, &mut bot, &t).body.unwrap(), t);
        if i % 3 == 0 {
            let t = format!("from bot {i}");
            assert_eq!(bot_to_oracle(&mut o, &mut bot, &[oracle_dev], &t), t);
        }
    }
}

#[test]
fn bot_starts_the_session_and_survives_restarts() {
    let Some(mut o) = Oracle::start() else { return };
    let mut bot = store("b-starts");
    let (oracle_dev, _) = oracle_identity(&mut o);
    let bundle = bundle_from_json(&o.ok(json!({"cmd": "bundle"})));
    assert_eq!(Omemo::bundle_identity(&bundle).unwrap().fingerprint(), oracle_identity(&mut o).1);
    bot.start_session(ORACLE_JID, oracle_dev, &bundle).unwrap();
    let before = o.ok(json!({"cmd": "prekey_count"}));

    let e = bot.encrypt(ORACLE_JID, &[oracle_dev], Some("hello from rust")).unwrap();
    assert!(e.header.keys[0].prekey);
    let r = o.ok(json!({"cmd": "decrypt", "jid": BOT_JID, "message": to_json(&e)}));
    assert_eq!(r["text"], "hello from rust");
    assert_eq!(r["fingerprint"].as_str().unwrap(), bot.fingerprint());
    assert_eq!(o.ok(json!({"cmd": "prekey_count"})), json!(before.as_u64().unwrap() - 1));

    o.ok(json!({"cmd": "set_devices", "jid": BOT_JID, "devices": [bot.device_id()]}));
    assert_eq!(oracle_to_bot(&mut o, &mut bot, "ack").body.unwrap(), "ack");
    let mut bot = Omemo::open(&bot.path, 1_000_500).unwrap();
    let e = bot.encrypt(ORACLE_JID, &[oracle_dev], Some("after restart")).unwrap();
    assert!(!e.header.keys[0].prekey);
    assert_eq!(o.ok(json!({"cmd": "decrypt", "jid": BOT_JID, "message": to_json(&e)}))["text"], "after restart");
}

#[test]
fn out_of_order_duplicates_and_key_transport() {
    let Some(mut o) = Oracle::start() else { return };
    let mut bot = store("order");
    let (oracle_dev, _) = oracle_identity(&mut o);
    o.ok(json!({"cmd": "set_devices", "jid": BOT_JID, "devices": [bot.device_id()]}));
    o.ok(json!({"cmd": "build_session", "jid": BOT_JID, "bundle": bundle_to_json(&bot)}));
    assert_eq!(oracle_to_bot(&mut o, &mut bot, "start").body.unwrap(), "start");
    bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "ok");

    let msgs: Vec<Value> = (0..4).map(|i| o.ok(json!({"cmd": "encrypt", "jid": BOT_JID, "text": format!("m{i}")}))).collect();
    for i in [3, 0, 2] {
        assert_eq!(bot.decrypt(ORACLE_JID, &from_json(&msgs[i])).unwrap().body.unwrap(), format!("m{i}"));
    }
    assert!(matches!(bot.decrypt(ORACLE_JID, &from_json(&msgs[3])), Err(OmemoError::Session(session::SessionError::Duplicate))));
    assert_eq!(bot.decrypt(ORACLE_JID, &from_json(&msgs[1])).unwrap().body.unwrap(), "m1");

    let kt = o.ok(json!({"cmd": "key_transport", "jid": BOT_JID, "devices": [bot.device_id()]}));
    assert!(kt["payload"].is_null());
    assert_eq!(bot.decrypt(ORACLE_JID, &from_json(&kt)).unwrap().body, None);

    // and the other way: the oracle accepts our key transport message
    let e = bot.encrypt(ORACLE_JID, &[oracle_dev], None).unwrap();
    let err = o.call(json!({"cmd": "decrypt", "jid": BOT_JID, "message": to_json(&e)})).unwrap_err();
    assert!(err.starts_with("KeyExchangeMessage"), "{err}");
    assert_eq!(bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "still in sync"), "still in sync");

    // tampering is caught on both sides
    let mut bad = from_json(&o.ok(json!({"cmd": "encrypt", "jid": BOT_JID, "text": "x"})));
    bad.payload.as_mut().unwrap().data[0] ^= 1;
    assert!(matches!(bot.decrypt(ORACLE_JID, &bad), Err(OmemoError::Body(_))));
    let mut e = bot.encrypt(ORACLE_JID, &[oracle_dev], Some("y")).unwrap();
    let n = e.header.keys[0].data.len();
    e.header.keys[0].data[n - 1] ^= 1;
    assert!(o.call(json!({"cmd": "decrypt", "jid": BOT_JID, "message": to_json(&e)})).is_err());
}

#[test]
fn oracle_restarts_its_session() {
    let Some(mut o) = Oracle::start() else { return };
    let mut bot = store("restart");
    let (oracle_dev, _) = oracle_identity(&mut o);
    o.ok(json!({"cmd": "set_devices", "jid": BOT_JID, "devices": [bot.device_id()]}));
    o.ok(json!({"cmd": "build_session", "jid": BOT_JID, "bundle": bundle_to_json(&bot)}));
    assert_eq!(oracle_to_bot(&mut o, &mut bot, "one").body.unwrap(), "one");
    bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "ok");
    // the oracle builds a fresh session (as a client does after losing its state)
    o.ok(json!({"cmd": "build_session", "jid": BOT_JID, "bundle": bundle_to_json(&bot)}));
    let d = oracle_to_bot(&mut o, &mut bot, "two");
    assert_eq!(d.body.as_deref(), Some("two"));
    assert!(d.used_pre_key);
    assert_eq!(bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "new session works"), "new session works");
}

/// The bot's healing (as Conversations heals): a new session from the peer's bundle,
/// announced with a key transport message; the peer switches to it.
#[test]
fn bot_rebuilds_a_session_and_the_peer_follows() {
    let Some(mut o) = Oracle::start() else { return };
    let mut bot = store("heal");
    let (oracle_dev, _) = oracle_identity(&mut o);
    o.ok(json!({"cmd": "set_devices", "jid": BOT_JID, "devices": [bot.device_id()]}));
    o.ok(json!({"cmd": "build_session", "jid": BOT_JID, "bundle": bundle_to_json(&bot)}));
    assert_eq!(oracle_to_bot(&mut o, &mut bot, "before").body.unwrap(), "before");
    bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "ok");

    let bundle = bundle_from_json(&o.ok(json!({"cmd": "bundle"})));
    bot.start_session(ORACLE_JID, oracle_dev, &bundle).unwrap();
    let kt = bot.encrypt(ORACLE_JID, &[oracle_dev], None).unwrap();
    assert!(kt.header.keys[0].prekey && kt.payload.is_none());
    let err = o.call(json!({"cmd": "decrypt", "jid": BOT_JID, "message": to_json(&kt)})).unwrap_err();
    assert!(err.starts_with("KeyExchangeMessage"), "{err}");

    let d = oracle_to_bot(&mut o, &mut bot, "after");
    assert_eq!(d.body.as_deref(), Some("after"));
    assert!(!d.used_pre_key);
    assert_eq!(bot_to_oracle(&mut o, &mut bot, &[oracle_dev], "both on the new session"), "both on the new session");
}
