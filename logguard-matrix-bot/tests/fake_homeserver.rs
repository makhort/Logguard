//! The bot against a fake homeserver on 127.0.0.1, with the admin's devices played by
//! vodozemac accounts of their own: what the bot sends must decrypt on the admin's verified
//! devices, and only there; when it can't be end-to-end encrypted, it must come as an
//! OpenPGP file, and nothing of it in clear.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use vodozemac::megolm::{InboundGroupSession, MegolmMessage, SessionConfig as MegolmConfig, SessionKey};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig as OlmConfig};
use vodozemac::{Curve25519PublicKey, Ed25519SecretKey};

use logguard_matrix_bot::api::Api;
use logguard_matrix_bot::bot::{self, Bot, Config, FILE_CAPTION};
use logguard_matrix_bot::crypto;
use logguard_matrix_bot::login;
use logguard_matrix_bot::seal::Recipient;
use logguard_matrix_bot::state::State;
use pgp::composed::{
    EncryptionCaps, KeyType, Message as PgpMessage, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;

const BOT: &str = "@logguard:example.org";
const ADMIN: &str = "@admin:example.org";
const PASSWORD: &str = "correct horse";

/// One request as the fake saw it: method, decoded path segments, body.
#[derive(Debug, Clone)]
struct Request {
    method: String,
    path: Vec<String>,
    body: Vec<u8>,
}

impl Request {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn is(&self, method: &str, prefix: &[&str]) -> bool {
        self.method == method && self.path.len() >= prefix.len() && self.path.iter().zip(prefix).all(|(a, b)| a == b)
    }
}

#[derive(Default)]
struct Fake {
    requests: Mutex<Vec<Request>>,
    /// What `/keys/query` answers for the admin (device_keys, master_keys, ...).
    admin_keys: Mutex<Value>,
    /// The admin's devices, to make one-time keys for `/keys/claim`.
    admin_devices: Mutex<BTreeMap<String, Arc<Mutex<Account>>>>,
    /// The bot's keys as uploaded.
    bot_device: Mutex<Option<Value>>,
    bot_cross: Mutex<Option<Value>>,
    bot_signatures: Mutex<Vec<Value>>,
    media: Mutex<BTreeMap<String, Vec<u8>>>,
    /// The admin's membership in the room.
    membership: Mutex<String>,
    /// The cross-signing upload wants the password (else the first upload goes without, as
    /// MSC3967 has it).
    uia: AtomicBool,
    /// The next whoami answers 401 M_UNKNOWN_TOKEN.
    revoked: AtomicBool,
    /// The next this many room sends answer 429.
    limit: AtomicU32,
    next: AtomicU32,
}

fn segments(path: &str) -> Vec<String> {
    let path = path.split('?').next().unwrap_or_default();
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut out = Vec::new();
            let b = s.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%' && i + 2 < b.len() + 1 {
                    out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            String::from_utf8(out).unwrap()
        })
        .collect()
}

impl Fake {
    fn take(&self) -> Vec<Request> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }

    fn answer(&self, r: &Request) -> (u16, Value) {
        let p: Vec<&str> = r.path.iter().map(String::as_str).collect();
        let body = r.json();
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        match (r.method.as_str(), &p[..]) {
            ("POST", ["_matrix", "client", "v3", "login"]) if body["password"] == PASSWORD => {
                (200, json!({ "user_id": BOT, "access_token": format!("token{id}"), "device_id": format!("BOTDEV{id}") }))
            }
            ("POST", ["_matrix", "client", "v3", "login"]) => (403, json!({ "errcode": "M_FORBIDDEN", "error": "Invalid password" })),
            ("POST", ["_matrix", "client", "v3", "logout"]) => (200, json!({})),
            ("GET", ["_matrix", "client", "v3", "account", "whoami"]) if self.revoked.swap(false, Ordering::SeqCst) => {
                (401, json!({ "errcode": "M_UNKNOWN_TOKEN", "error": "Invalid access token passed." }))
            }
            ("GET", ["_matrix", "client", "v3", "account", "whoami"]) => {
                let dev = self.bot_device.lock().unwrap().as_ref().map(|d| d["device_id"].clone()).unwrap_or(Value::Null);
                (200, json!({ "user_id": BOT, "device_id": dev }))
            }
            ("POST", ["_matrix", "client", "v3", "keys", "upload"]) => {
                *self.bot_device.lock().unwrap() = Some(body["device_keys"].clone());
                (200, json!({ "one_time_key_counts": {} }))
            }
            ("POST", ["_matrix", "client", "v3", "keys", "query"]) => {
                let mut reply = json!({ "device_keys": {}, "master_keys": {}, "self_signing_keys": {} });
                if body["device_keys"].get(ADMIN).is_some() {
                    reply = self.admin_keys.lock().unwrap().clone();
                }
                if body["device_keys"].get(BOT).is_some() {
                    if let Some(c) = self.bot_cross.lock().unwrap().as_ref() {
                        reply["master_keys"][BOT] = c["master_key"].clone();
                        reply["self_signing_keys"][BOT] = c["self_signing_key"].clone();
                    }
                }
                (200, reply)
            }
            ("POST", ["_matrix", "client", "v3", "keys", "claim"]) => {
                let mut keys = serde_json::Map::new();
                for (dev, _) in body["one_time_keys"][ADMIN].as_object().unwrap() {
                    let Some(account) = self.admin_devices.lock().unwrap().get(dev).cloned() else { continue };
                    let mut a = account.lock().unwrap();
                    a.generate_one_time_keys(1);
                    let (key_id, key) = a.one_time_keys().into_iter().next().unwrap();
                    a.mark_keys_as_published();
                    let signed = crypto::signed(&json!({ "key": key.to_base64() }), ADMIN, &format!("ed25519:{dev}"), |m| a.sign(m));
                    keys.insert(dev.clone(), json!({ format!("signed_curve25519:{}", key_id.to_base64()): signed }));
                }
                (200, json!({ "one_time_keys": { ADMIN: keys }, "failures": {} }))
            }
            ("POST", ["_matrix", "client", "v3", "keys", "device_signing", "upload"]) => {
                if self.uia.load(Ordering::SeqCst) && body["auth"]["password"] != PASSWORD {
                    return (401, json!({ "session": "uia1", "flows": [{ "stages": ["m.login.password"] }], "params": {} }));
                }
                assert!(self.uia.load(Ordering::SeqCst) || body.get("auth").is_none());
                assert_eq!(body["auth"]["identifier"]["user"].as_str().is_some(), self.uia.load(Ordering::SeqCst));
                let mut keys = body.clone();
                keys.as_object_mut().unwrap().remove("auth");
                *self.bot_cross.lock().unwrap() = Some(keys);
                (200, json!({}))
            }
            ("POST", ["_matrix", "client", "v3", "keys", "signatures", "upload"]) => {
                self.bot_signatures.lock().unwrap().push(body);
                (200, json!({ "failures": {} }))
            }
            ("POST", ["_matrix", "client", "v3", "createRoom"]) => {
                *self.membership.lock().unwrap() = "invite".into();
                (200, json!({ "room_id": format!("!room{id}:example.org") }))
            }
            ("POST", ["_matrix", "client", "v3", "rooms", _, "invite"]) => {
                *self.membership.lock().unwrap() = "invite".into();
                (200, json!({}))
            }
            ("GET", ["_matrix", "client", "v3", "rooms", _, "state", "m.room.encryption", ..]) => {
                (200, json!({ "algorithm": crypto::MEGOLM }))
            }
            ("GET", ["_matrix", "client", "v3", "rooms", _, "state", "m.room.member", user]) if *user == ADMIN => {
                (200, json!({ "membership": *self.membership.lock().unwrap() }))
            }
            ("PUT", ["_matrix", "client", "v3", "rooms", _, "send", ..]) if self.limit.load(Ordering::SeqCst) > 0 => {
                self.limit.fetch_sub(1, Ordering::SeqCst);
                (429, json!({ "errcode": "M_LIMIT_EXCEEDED", "error": "Too Many Requests", "retry_after_ms": 30000 }))
            }
            ("PUT", ["_matrix", "client", "v3", "rooms", _, "send", ..]) => (200, json!({ "event_id": format!("$ev{id}") })),
            ("PUT", ["_matrix", "client", "v3", "sendToDevice", ..]) => (200, json!({})),
            ("POST", ["_matrix", "media", "v3", "upload"]) => {
                let mxc = format!("mxc://example.org/m{id}");
                self.media.lock().unwrap().insert(mxc.clone(), r.body.clone());
                (200, json!({ "content_uri": mxc }))
            }
            _ => (404, json!({ "errcode": "M_UNRECOGNIZED", "error": format!("{} {}", r.method, r.path.join("/")) })),
        }
    }
}

/// One HTTP/1.1 request (Content-Length body), or None at the end of the connection.
async fn read_request<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut words = line.split_whitespace();
    let (method, path) = (words.next()?.to_string(), words.next()?.to_string());
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        r.read_line(&mut h).await.ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        headers.push((k.trim().to_lowercase(), v.trim().to_string()));
    }
    let mut body = Vec::new();
    if let Some((_, len)) = headers.iter().find(|(k, _)| k == "content-length") {
        body.resize(len.parse().ok()?, 0);
        r.read_exact(&mut body).await.ok()?;
    }
    Some((method, path, headers, body))
}

async fn serve(fake: Arc<Fake>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let fake = fake.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = stream.into_split();
                let mut rd = BufReader::new(rd);
                while let Some((method, path, headers, body)) = read_request(&mut rd).await {
                    let r = Request { method, path: segments(&path), body };
                    let public = r.is("POST", &["_matrix", "client", "v3", "login"]);
                    let auth = headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Bearer token"));
                    assert!(public || auth, "no access token: {r:?}");
                    let (status, reply) = fake.answer(&r);
                    fake.requests.lock().unwrap().push(r);
                    let reply = reply.to_string();
                    let head = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", reply.len());
                    if wr.write_all(head.as_bytes()).await.is_err() || wr.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    url
}

/// The admin: their devices and cross-signing keys, and what their devices decrypt.
struct AdminSide {
    master: Ed25519SecretKey,
    ssk: Ed25519SecretKey,
    devices: BTreeMap<String, Arc<Mutex<Account>>>,
    /// Inbound Olm sessions per device, by the bot's Curve25519 key.
    olm: BTreeMap<String, Vec<Session>>,
    /// Room keys per device, by session id.
    megolm: BTreeMap<String, BTreeMap<String, InboundGroupSession>>,
}

impl AdminSide {
    fn new(devices: &[&str]) -> AdminSide {
        AdminSide {
            master: Ed25519SecretKey::new(),
            ssk: Ed25519SecretKey::new(),
            devices: devices.iter().map(|d| (d.to_string(), Arc::new(Mutex::new(Account::new())))).collect(),
            olm: BTreeMap::new(),
            megolm: BTreeMap::new(),
        }
    }

    /// The `/keys/query` reply: every device, those in `verified` signed by the self-signing
    /// key; cross-signing keys only with `cross`.
    fn keys(&self, verified: &[&str], cross: bool) -> Value {
        let mut devices = serde_json::Map::new();
        for (id, a) in &self.devices {
            let mut keys = crypto::device_keys(&a.lock().unwrap(), ADMIN, id);
            if cross && verified.contains(&id.as_str()) {
                let sig = crypto::device_signature(&keys, ADMIN, id, &self.ssk);
                let ssk_id = format!("ed25519:{}", self.ssk.public_key().to_base64());
                keys["signatures"][ADMIN][&ssk_id] = sig[ADMIN][id]["signatures"][ADMIN][&ssk_id].clone();
            }
            devices.insert(id.clone(), keys);
        }
        let mut reply = json!({ "device_keys": { ADMIN: devices } });
        if cross {
            let c = crypto::cross_signing_keys(ADMIN, &self.master, &self.ssk);
            reply["master_keys"] = json!({ ADMIN: c["master_key"] });
            reply["self_signing_keys"] = json!({ ADMIN: c["self_signing_key"] });
        }
        reply
    }

    fn publish(&self, fake: &Fake, verified: &[&str], cross: bool) {
        *fake.admin_keys.lock().unwrap() = self.keys(verified, cross);
        *fake.admin_devices.lock().unwrap() = self.devices.clone();
    }

    /// The to-device room keys in `requests`, taken in by each device they are for. Returns
    /// which devices got one.
    fn receive_keys(&mut self, requests: &[Request]) -> Vec<String> {
        let mut got = Vec::new();
        for r in requests.iter().filter(|r| r.is("PUT", &["_matrix", "client", "v3", "sendToDevice", "m.room.encrypted"])) {
            for (dev, content) in r.json()["messages"][ADMIN].as_object().unwrap() {
                assert_eq!(content["algorithm"], crypto::OLM);
                let sender = Curve25519PublicKey::from_base64(content["sender_key"].as_str().unwrap()).unwrap();
                let account = self.devices[dev].clone();
                let mut account = account.lock().unwrap();
                let mine = account.curve25519_key().to_base64();
                let message: OlmMessage = serde_json::from_value(content["ciphertext"][&mine].clone()).unwrap();
                let sessions = self.olm.entry(dev.clone()).or_default();
                let plaintext = match sessions.iter_mut().find_map(|s| s.decrypt(&message).ok()) {
                    Some(p) => p,
                    None => {
                        let OlmMessage::PreKey(pre) = &message else { panic!("a normal message without a session") };
                        let created = account.create_inbound_session(OlmConfig::version_1(), sender, pre).unwrap();
                        sessions.push(created.session);
                        created.plaintext
                    }
                };
                let event: Value = serde_json::from_slice(&plaintext).unwrap();
                assert_eq!(event["type"], "m.room_key");
                assert_eq!((event["sender"].as_str(), event["recipient"].as_str()), (Some(BOT), Some(ADMIN)));
                assert_eq!(event["recipient_keys"]["ed25519"], account.ed25519_key().to_base64(), "for this device only");
                let key = SessionKey::from_base64(event["content"]["session_key"].as_str().unwrap()).unwrap();
                let session = InboundGroupSession::new(&key, MegolmConfig::version_1());
                assert_eq!(session.session_id(), event["content"]["session_id"]);
                self.megolm.entry(dev.clone()).or_default().insert(session.session_id(), session);
                got.push(dev.clone());
            }
        }
        got
    }

    /// The room event decrypted on `dev`, if it can.
    fn decrypt(&mut self, dev: &str, event: &Value) -> Option<Value> {
        assert_eq!(event["algorithm"], crypto::MEGOLM);
        let session = self.megolm.get_mut(dev)?.get_mut(event["session_id"].as_str()?)?;
        let message = MegolmMessage::from_base64(event["ciphertext"].as_str()?).ok()?;
        let plain = session.decrypt(&message).ok()?;
        serde_json::from_slice(&plain.plaintext).ok()
    }
}

/// A throwaway OpenPGP key as phones make them (Ed25519, a Curve25519 encryption subkey).
fn pgp_keypair() -> (SignedSecretKey, Vec<u8>) {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("admin <admin@example.org>".into())
        .subkeys(vec![enc.build().unwrap()]);
    let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
    let public = SignedPublicKey::from(secret.clone()).to_bytes().unwrap();
    (secret, public)
}

fn now_secs() -> u32 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32
}

fn alert(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("To: admin@example.org\nSubject: s\n\n{body}")).unwrap();
    path
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("logguard-matrix-bot-fake-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("outbox")).unwrap();
    dir
}

fn config(dir: &Path, recipient: Option<Recipient>) -> Config {
    Config {
        admin: ADMIN.into(),
        outbox: dir.join("outbox"),
        outbox_max_age: Duration::from_secs(7 * 86400),
        alert_max_age: Duration::from_secs(24 * 3600),
        state_path: dir.join("state.json"),
        e2ee: true,
        admin_master_key: None,
        recipient,
        sanitize: None,
    }
}

/// A logged-in bot and its prepared room.
async fn logged_in(fake: &Arc<Fake>, url: &str, dir: &Path, recipient: Option<Recipient>) -> Bot {
    let api = Api::new(url, None).unwrap();
    let state = login::login(&api, &dir.join("state.json"), BOT, PASSWORD, false, &mut |t| panic!("asked: {t}")).await.unwrap();
    let mut bot = Bot::new(api, config(dir, recipient), state).unwrap();
    bot::connect(&mut bot).await.unwrap();
    fake.take();
    bot
}

/// The room events sent, with their type (the `send/<type>` path segment).
fn room_events(requests: &[Request]) -> Vec<(String, Value)> {
    requests
        .iter()
        .filter(|r| r.is("PUT", &["_matrix", "client", "v3", "rooms"]) && r.path[5] == "send")
        .map(|r| (r.path[6].clone(), r.json()))
        .collect()
}

fn no_clear_text(requests: &[Request], words: &[&str]) {
    for r in requests {
        let body = String::from_utf8_lossy(&r.body);
        for w in words {
            assert!(!body.contains(w), "{w} in clear in {} {}: {body}", r.method, r.path.join("/"));
        }
    }
}

#[tokio::test]
async fn login_signs_the_device_and_messages_reach_only_verified_devices() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let dir = tmp("e2e");
    let mut admin = AdminSide::new(&["PHONE", "LAPTOP"]);
    admin.publish(&fake, &["PHONE"], true);

    let mut bot = logged_in(&fake, &url, &dir, None).await;
    // the device signs itself, the master key signs the self-signing key, which signs the device
    let device = fake.bot_device.lock().unwrap().clone().unwrap();
    let dev_id = device["device_id"].as_str().unwrap().to_string();
    let parsed = crypto::parse_device(BOT, &dev_id, &device).unwrap();
    assert_eq!(parsed.ed25519.to_base64(), bot.fingerprint());
    let cross = fake.bot_cross.lock().unwrap().clone().unwrap();
    let sig = fake.bot_signatures.lock().unwrap()[0].clone();
    let mut published = json!({ "device_keys": { BOT: { &dev_id: device.clone() } }, "master_keys": { BOT: cross["master_key"] }, "self_signing_keys": { BOT: cross["self_signing_key"] } });
    let ssk_sig = sig[BOT][&dev_id]["signatures"][BOT].clone();
    published["device_keys"][BOT][&dev_id]["signatures"][BOT].as_object_mut().unwrap().extend(ssk_sig.as_object().unwrap().clone());
    let k = crypto::user_keys(&published, BOT);
    assert!(k.cross_signed.contains(&dev_id), "{:?}", k.problems);
    assert_eq!(bot.state.master_key, k.master.map(|m| m.to_base64()));
    assert!(bot.state.device_signed);

    // the room: made encrypted, the admin invited
    let room = bot.state.room.clone().unwrap();
    assert!(room.starts_with("!room"));

    // an alert: the room key goes to the verified phone only, and the event decrypts there
    let text = "[xmpp] logguard: brute force\n\n[High] 203.0.113.9 banned after 40 failed logins on alice@example.org";
    alert(&dir.join("outbox"), "alert-0001.msg", text);
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(admin.receive_keys(&sent), ["PHONE"], "the unverified laptop gets nothing");
    let events = room_events(&sent);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, "m.room.encrypted");
    let decrypted = admin.decrypt("PHONE", &events[0].1).unwrap();
    assert_eq!(decrypted["type"], "m.room.message");
    assert_eq!(decrypted["room_id"], room.as_str());
    assert_eq!(decrypted["content"]["body"], text);
    assert!(admin.decrypt("LAPTOP", &events[0].1).is_none());
    no_clear_text(&sent, &["brute force", "203.0.113.9", "alice"]);
    assert!(listing(&dir.join("outbox")).is_empty());

    // the weekly report: an encrypted attachment in an encrypted event
    let report = "Abuse report from xmpp (192.0.2.10)\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n\nHello, abuse@isp.example,\n";
    std::fs::write(dir.join("outbox/abuse-report-2026-10-19.txt"), report).unwrap();
    bot.deliver_files().await;
    let sent = fake.take();
    assert!(admin.receive_keys(&sent).is_empty(), "the session's key is there already");
    let events = room_events(&sent);
    let content = admin.decrypt("PHONE", &events[0].1).unwrap()["content"].clone();
    assert_eq!((content["msgtype"].as_str(), content["body"].as_str()), (Some("m.file"), Some("abuse-report-2026-10-19.txt")));
    let blob = fake.media.lock().unwrap()[content["file"]["url"].as_str().unwrap()].clone();
    assert_eq!(crypto::decrypt_attachment(&blob, &content["file"]).unwrap(), report.as_bytes());
    no_clear_text(&sent, &["Abuse", "abuse", "192.0.2.10", "Period"]);

    // the laptop gets verified: it gets the current session's key, nothing else changes
    admin.publish(&fake, &["PHONE", "LAPTOP"], true);
    let mut bot = Bot::new(Api::new(&url, None).unwrap(), config(&dir, None), State::load(&dir.join("state.json")).unwrap()).unwrap();
    alert(&dir.join("outbox"), "alert-0002.msg", "second");
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(admin.receive_keys(&sent), ["LAPTOP"]);
    let events = room_events(&sent);
    assert_eq!(admin.decrypt("LAPTOP", &events[0].1).unwrap()["content"]["body"], "second");
    assert_eq!(admin.decrypt("PHONE", &events[0].1).unwrap()["content"]["body"], "second");

    // the phone is removed: a new session, its key to the laptop only
    let first_session = events[0].1["session_id"].clone();
    admin.devices.remove("PHONE");
    admin.publish(&fake, &["LAPTOP"], true);
    let mut bot = Bot::new(Api::new(&url, None).unwrap(), config(&dir, None), State::load(&dir.join("state.json")).unwrap()).unwrap();
    alert(&dir.join("outbox"), "alert-0003.msg", "third");
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(admin.receive_keys(&sent), ["LAPTOP"]);
    let events = room_events(&sent);
    assert_ne!(events[0].1["session_id"], first_session, "rotated");
    assert!(admin.decrypt("PHONE", &events[0].1).is_none());
    assert_eq!(admin.decrypt("LAPTOP", &events[0].1).unwrap()["content"]["body"], "third");

    // rate limited: the alert stays and waits out retry_after
    fake.limit.store(1, Ordering::SeqCst);
    alert(&dir.join("outbox"), "alert-0004.msg", "fourth");
    bot.deliver_alerts().await;
    assert!(listing(&dir.join("outbox")).contains(&"alert-0004.msg".to_string()));
    fake.take();
    bot.deliver_alerts().await;
    assert!(fake.take().is_empty(), "waiting");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_changed_master_key_means_openpgp_files() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let dir = tmp("fallback");
    let mut admin = AdminSide::new(&["PHONE"]);
    admin.publish(&fake, &["PHONE"], true);
    let (secret, public) = pgp_keypair();
    let recipient = || Some(Recipient::parse(&public, now_secs()).unwrap());
    let mut bot = logged_in(&fake, &url, &dir, recipient()).await;
    alert(&dir.join("outbox"), "alert-0001.msg", "pinned");
    bot.deliver_alerts().await;
    let sent = fake.take();
    admin.receive_keys(&sent);
    let old_master = bot.state.admin_master.clone().unwrap();
    assert_eq!(old_master, admin.master.public_key().to_base64(), "pinned on first sight");

    // someone (the homeserver?) replaces the admin's cross-signing keys and devices
    let mut impostor = AdminSide::new(&["EVIL"]);
    impostor.publish(&fake, &["EVIL"], true);
    // (a bot asks for the keys again after a minute; this one starts afresh from the state)
    let mut bot =
        Bot::new(Api::new(&url, None).unwrap(), config(&dir, recipient()), State::load(&dir.join("state.json")).unwrap()).unwrap();
    let text = "[vpn] logguard: compromise\n\n[Critical] login of root from 198.51.100.7";
    alert(&dir.join("outbox"), "alert-0002.msg", text);
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert!(impostor.receive_keys(&sent).is_empty(), "no room key for the new keys");
    let events = room_events(&sent);
    assert_eq!(events.len(), 2, "a notice, then the file: {events:?}");
    assert_eq!(events[0].1["msgtype"], "m.notice");
    assert!(events[0].1["body"].as_str().unwrap().contains("master cross-signing key changed"));
    let file = &events[1].1;
    assert_eq!(
        (events[1].0.as_str(), file["msgtype"].as_str(), file["body"].as_str()),
        ("m.room.message", Some("m.file"), Some(FILE_CAPTION))
    );
    assert!(file["filename"].as_str().unwrap().starts_with("message-") && file["filename"].as_str().unwrap().ends_with(".txt.pgp"));
    let blob = fake.media.lock().unwrap()[file["url"].as_str().unwrap()].clone();
    let opened = PgpMessage::from_bytes(&blob[..]).unwrap().decrypt(&"".into(), &secret).unwrap().as_data_vec().unwrap();
    assert_eq!(String::from_utf8(opened).unwrap(), text);
    no_clear_text(&sent, &["compromise", "198.51.100.7", "root"]);
    assert_eq!(bot.state.admin_master.as_deref(), Some(old_master.as_str()), "the pin stays");

    // the admin confirms the new key on the server (ADMIN_MASTER_KEY): end to end again
    let cfg = Config { admin_master_key: Some(impostor.master.public_key().to_base64()), ..config(&dir, recipient()) };
    let mut bot = Bot::new(Api::new(&url, None).unwrap(), cfg, State::load(&dir.join("state.json")).unwrap()).unwrap();
    alert(&dir.join("outbox"), "alert-0003.msg", "confirmed");
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(impostor.receive_keys(&sent), ["EVIL"]);
    assert_eq!(impostor.decrypt("EVIL", &room_events(&sent)[0].1).unwrap()["content"]["body"], "confirmed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn without_a_route_messages_wait() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let dir = tmp("wait");
    let admin = AdminSide::new(&["PHONE"]);
    // cross-signing, but the phone isn't verified, and no OpenPGP key
    admin.publish(&fake, &[], true);
    let mut bot = logged_in(&fake, &url, &dir, None).await;
    alert(&dir.join("outbox"), "alert-0001.msg", "secret alert");
    std::fs::write(dir.join("outbox/abuse-report-2026-10-19.txt"), "secret report").unwrap();
    bot.deliver_alerts().await;
    bot.deliver_files().await;
    let sent = fake.take();
    let events = room_events(&sent);
    assert_eq!(events.len(), 1, "one notice only: {events:?}");
    let notice = events[0].1["body"].as_str().unwrap();
    assert!(notice.contains("none of @admin:example.org's devices is verified") && notice.contains("OPENPGP_KEY is not set"), "{notice}");
    no_clear_text(&sent, &["secret"]);
    assert!(!sent.iter().any(|r| r.is("PUT", &["_matrix", "client", "v3", "sendToDevice"])));
    assert_eq!(listing(&dir.join("outbox")), ["abuse-report-2026-10-19.txt", "alert-0001.msg"], "both wait");

    // E2EE=off with a key: files, even to a verified device
    admin.publish(&fake, &["PHONE"], true);
    let (_, public) = pgp_keypair();
    let cfg = Config { e2ee: false, ..config(&dir, Some(Recipient::parse(&public, now_secs()).unwrap())) };
    let mut bot = Bot::new(Api::new(&url, None).unwrap(), cfg, State::load(&dir.join("state.json")).unwrap()).unwrap();
    bot.deliver_alerts().await;
    bot.deliver_files().await;
    let sent = fake.take();
    let events = room_events(&sent);
    let files: Vec<&Value> = events.iter().map(|(_, e)| e).filter(|e| e["msgtype"] == "m.file").collect();
    assert_eq!(files.len(), 2);
    assert!(files[1]["filename"].as_str().unwrap().starts_with("report-"));
    no_clear_text(&sent, &["secret"]);
    assert!(listing(&dir.join("outbox")).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn admin_without_cross_signing_and_login_details() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let dir = tmp("plain");
    fake.uia.store(true, Ordering::SeqCst);
    let mut admin = AdminSide::new(&["PHONE", "TABLET"]);
    admin.publish(&fake, &[], false);
    // the cross-signing upload wants the password: login gives it
    let mut bot = logged_in(&fake, &url, &dir, None).await;
    assert!(bot.state.device_signed);
    alert(&dir.join("outbox"), "alert-0001.msg", "to every device");
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(admin.receive_keys(&sent), ["PHONE", "TABLET"], "no cross-signing: every self-signed device");
    assert_eq!(admin.decrypt("TABLET", &room_events(&sent)[0].1).unwrap()["content"]["body"], "to every device");
    assert_eq!(bot.state.admin_devices.len(), 2, "each pinned by id");

    // a device id that comes back with other keys is left out
    let swapped = Arc::new(Mutex::new(Account::new()));
    admin.devices.insert("TABLET".into(), swapped);
    admin.publish(&fake, &[], false);
    let mut bot = Bot::new(Api::new(&url, None).unwrap(), config(&dir, None), State::load(&dir.join("state.json")).unwrap()).unwrap();
    alert(&dir.join("outbox"), "alert-0002.msg", "phone only");
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(admin.receive_keys(&sent), ["PHONE"], "a new session: the tablet that had the old one is out");
    assert_eq!(admin.decrypt("PHONE", &room_events(&sent)[0].1).unwrap()["content"]["body"], "phone only");

    // logging in again: a new device, the old one logged out, the room and pins kept
    let room = bot.state.room.clone();
    let old_device = bot.login.device_id.clone();
    let state =
        login::login(&Api::new(&url, None).unwrap(), &dir.join("state.json"), BOT, PASSWORD, false, &mut |t| panic!("{t}")).await.unwrap();
    assert_ne!(state.login.as_ref().unwrap().device_id, old_device);
    assert_eq!(state.room, room);
    assert!(state.device_signed, "signed with the self-signing key kept from the first login");
    let reqs = fake.take();
    assert!(reqs.iter().any(|r| r.is("POST", &["_matrix", "client", "v3", "logout"])));
    assert!(
        !reqs.iter().any(|r| r.is("POST", &["_matrix", "client", "v3", "keys", "device_signing", "upload"])),
        "no new cross-signing keys"
    );
    assert!(state.outbound.is_none() && state.olm.is_empty(), "a new device starts without sessions");

    // a wrong password changes nothing
    assert!(login::login(&Api::new(&url, None).unwrap(), &dir.join("state.json"), BOT, "wrong", false, &mut |_| {}).await.is_err());
    assert_eq!(State::load(&dir.join("state.json")).unwrap().login, state.login);
    assert!(!fake.take().iter().any(|r| r.is("POST", &["_matrix", "client", "v3", "logout"])), "the working device stays");

    // a revoked token stops the service (exit 78)
    let mut bot = Bot::new(Api::new(&url, None).unwrap(), config(&dir, None), State::load(&dir.join("state.json")).unwrap()).unwrap();
    fake.revoked.store(true, Ordering::SeqCst);
    let e = bot::connect(&mut bot).await.unwrap_err();
    assert!(e.is::<bot::Refused>() && e.to_string().contains("login"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}
