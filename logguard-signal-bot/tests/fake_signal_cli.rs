//! The bot against a fake signal-cli (JSON-RPC over a pipe, as `signal-cli jsonRpc` speaks
//! it) that keeps the admin's identities and their trust as signal-cli does: what reaches
//! "Signal" from the outbox, the safety number pinned on first sight, and only OpenPGP files
//! once it changes.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use logguard_signal_bot::bot::{Bot, Config, FILE_CAPTION, PROBE};
use logguard_signal_bot::rpc::Rpc;
use logguard_signal_bot::seal::Recipient;
use logguard_signal_bot::state::State;
use pgp::composed::{
    EncryptionCaps, KeyType, Message as PgpMessage, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;

const ADMIN: &str = "+491701234567";
const FIRST: &str = "111112222233333444445555566666777778888899999000001111122222";
const SECOND: &str = "999998888877777666665555544444333332222211111000009999988888";

#[derive(Default)]
struct Fake {
    /// Every request: method and params.
    requests: Vec<(String, Value)>,
    /// The admin's identities as signal-cli lists them.
    identities: Vec<Value>,
    /// The next sends answer with this failure type.
    fail: Option<&'static str>,
}

impl Fake {
    fn current(&mut self) -> Option<&mut Value> {
        self.identities.iter_mut().max_by_key(|i| i["addedTimestamp"].as_i64())
    }

    fn answer(&mut self, method: &str, params: &Value) -> Result<Value, Value> {
        match method {
            "version" => Ok(json!({ "version": "0.13.99" })),
            "listIdentities" => {
                assert_eq!(params["number"], ADMIN);
                Ok(Value::Array(self.identities.clone()))
            }
            "trust" => {
                assert_eq!(params["recipient"], ADMIN);
                let cur = self.current().expect("trust without an identity");
                if params["trustAllKnownKeys"] == true {
                    cur["trustLevel"] = json!("TRUSTED_UNVERIFIED");
                } else if params["verifiedSafetyNumber"] == cur["safetyNumber"].as_str().unwrap().replace(' ', "") {
                    cur["trustLevel"] = json!("TRUSTED_VERIFIED");
                } else {
                    return Err(json!({ "code": -1, "message": "Safety number doesn't match" }));
                }
                Ok(json!({}))
            }
            "send" => {
                assert_eq!(params["recipient"], json!([ADMIN]));
                if self.identities.is_empty() {
                    // the first session: signal-cli trusts on first use
                    self.identities.push(identity(FIRST, "TRUSTED_UNVERIFIED", 1));
                }
                let failure = if self.current().unwrap()["trustLevel"] == "UNTRUSTED" { Some("IDENTITY_FAILURE") } else { self.fail };
                match failure {
                    None => Ok(
                        json!({ "timestamp": 1760000000000u64, "results": [{ "recipientAddress": { "number": ADMIN }, "type": "SUCCESS" }] }),
                    ),
                    Some(t) => Err(
                        json!({ "code": -1, "message": "Failed to send message", "data": { "response": { "results": [{ "type": t }] } } }),
                    ),
                }
            }
            m => Err(json!({ "code": -32601, "message": format!("Method not implemented: {m}") })),
        }
    }
}

fn identity(digits: &str, trust: &str, added: i64) -> Value {
    let grouped: Vec<String> = digits.as_bytes().chunks(5).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    json!({ "number": ADMIN, "uuid": "a1b2c3d4-e5f6-7890-abcd-ef0123456789", "fingerprint": "05 aa", "safetyNumber": grouped.join(" "),
            "scannableSafetyNumber": "x", "trustLevel": trust, "addedTimestamp": added })
}

/// The bot's end of a pipe to the fake, which runs until the bot drops its end.
fn connect(fake: Arc<Mutex<Fake>>) -> Rpc {
    let (bot_side, cli_side) = tokio::io::duplex(1 << 20);
    let (r, w) = tokio::io::split(bot_side);
    let (cr, mut cw) = tokio::io::split(cli_side);
    tokio::spawn(async move {
        let mut lines = BufReader::new(cr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let req: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["jsonrpc"], "2.0");
            let (method, params) = (req["method"].as_str().unwrap().to_string(), req["params"].clone());
            let reply = {
                let mut f = fake.lock().unwrap();
                f.requests.push((method.clone(), params.clone()));
                match f.answer(&method, &params) {
                    Ok(result) => json!({ "jsonrpc": "2.0", "result": result, "id": req["id"] }),
                    Err(error) => json!({ "jsonrpc": "2.0", "error": error, "id": req["id"] }),
                }
            };
            // a message someone sends the bot, which it ignores
            cw.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"receive\",\"params\":{\"envelope\":{\"source\":\"+15550000000\"}}}\n")
                .await
                .unwrap();
            if cw.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                return;
            }
        }
    });
    Rpc::new(r, w)
}

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

fn alert(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), format!("To: admin@example.org\nSubject: s\n\n{body}")).unwrap();
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn config(dir: &Path, recipient: Option<Recipient>) -> Config {
    Config {
        admin: ADMIN.into(),
        outbox: dir.join("outbox"),
        outbox_max_age: Duration::from_secs(7 * 86400),
        alert_max_age: Duration::from_secs(24 * 3600),
        state_path: dir.join("state.json"),
        admin_safety_number: None,
        recipient,
        sanitize: None,
    }
}

/// The `send` requests, and what each carried.
fn sends(fake: &Arc<Mutex<Fake>>) -> Vec<Value> {
    let mut f = fake.lock().unwrap();
    std::mem::take(&mut f.requests).into_iter().filter(|(m, _)| m == "send").map(|(_, p)| p).collect()
}

/// An attachment's data out of its `data:` URI, with its type and name.
fn attachment(uri: &str) -> (String, String, Vec<u8>) {
    let rest = uri.strip_prefix("data:").unwrap();
    let (head, data) = rest.split_once(";base64,").unwrap();
    let (mime, name) = head.split_once(";filename=").unwrap();
    (mime.into(), name.into(), base64::engine::general_purpose::STANDARD.decode(data).unwrap())
}

#[tokio::test]
async fn safety_number_pinned_then_openpgp_after_a_change() {
    let dir = std::env::temp_dir().join(format!("logguard-signal-bot-fake-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("outbox")).unwrap();
    let fake = Arc::new(Mutex::new(Fake::default()));
    let (secret, public) = pgp_keypair();
    let recipient = || Some(Recipient::parse(&public, now_secs()).unwrap());
    let mut bot = Bot::new(connect(fake.clone()), config(&dir, recipient()), State::load(&dir.join("state.json")).unwrap());

    // first contact: a message without content makes the session, its safety number is pinned,
    // then the alert goes, its subject bold
    let text = "[xmpp] logguard: brute force\n\n[High] 203.0.113.9 banned after 40 failed logins";
    alert(&dir.join("outbox"), "alert-0001.msg", text);
    bot.deliver_alerts().await;
    let sent = sends(&fake);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0]["message"], PROBE);
    assert_eq!(sent[1]["message"], text);
    assert_eq!(sent[1]["textStyle"], json!(["0:28:BOLD"]));
    assert_eq!(State::load(&dir.join("state.json")).unwrap().admin_safety_number.as_deref(), Some(FIRST));
    assert!(listing(&dir.join("outbox")).is_empty());

    // the weekly report: an attachment (Signal encrypts it end to end)
    let report = "Abuse report from xmpp (192.0.2.10)\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n";
    std::fs::write(dir.join("outbox/abuse-report-2026-10-19.txt"), report).unwrap();
    bot.deliver_files().await;
    let sent = sends(&fake);
    assert_eq!(sent.len(), 1);
    let (mime, name, data) = attachment(sent[0]["attachments"][0].as_str().unwrap());
    assert_eq!((mime.as_str(), name.as_str(), data.as_slice()), ("text/plain", "abuse-report-2026-10-19.txt", report.as_bytes()));

    // the admin's identity changes (a new phone, or someone else): signal-cli marks it untrusted
    fake.lock().unwrap().identities.push(identity(SECOND, "UNTRUSTED", 2));
    let mut bot = Bot::new(connect(fake.clone()), config(&dir, None), State::load(&dir.join("state.json")).unwrap());
    alert(&dir.join("outbox"), "alert-0002.msg", "[vpn] logguard: compromise\n\nlogin of root from 198.51.100.7");
    bot.deliver_alerts().await;
    assert!(sends(&fake).is_empty(), "no OpenPGP key: it waits, nothing goes to the new identity");
    assert_eq!(listing(&dir.join("outbox")), ["alert-0002.msg"]);

    // with the key: signal-cli is told to accept the new identity, which gets a notice and a
    // file encrypted to the admin's OpenPGP key, nothing readable
    let mut bot = Bot::new(connect(fake.clone()), config(&dir, recipient()), State::load(&dir.join("state.json")).unwrap());
    bot.deliver_alerts().await;
    let requests: Vec<(String, Value)> = fake.lock().unwrap().requests.clone();
    assert!(requests.iter().any(|(m, p)| m == "trust" && p["trustAllKnownKeys"] == true));
    for (_, p) in &requests {
        let s = p.to_string();
        assert!(!s.contains("compromise") && !s.contains("198.51.100.7"), "in clear: {s}");
    }
    let sent = sends(&fake);
    assert_eq!(sent.len(), 2, "{sent:?}");
    let notice = sent[0]["message"].as_str().unwrap();
    assert!(notice.contains("safety number with +491701234567 changed") && notice.contains("ADMIN_SAFETY_NUMBER"), "{notice}");
    assert_eq!(sent[1]["message"], FILE_CAPTION);
    let (mime, name, sealed) = attachment(sent[1]["attachments"][0].as_str().unwrap());
    assert_eq!(mime, "application/pgp-encrypted");
    assert!(name.starts_with("message-") && name.ends_with(".txt.pgp"), "{name}");
    let opened = PgpMessage::from_bytes(&sealed[..]).unwrap().decrypt(&"".into(), &secret).unwrap().as_data_vec().unwrap();
    assert_eq!(String::from_utf8(opened).unwrap(), "[vpn] logguard: compromise\n\nlogin of root from 198.51.100.7");
    assert_eq!(bot.state.admin_safety_number.as_deref(), Some(FIRST), "the pin stays");

    // a report then too goes only as an OpenPGP file
    std::fs::write(dir.join("outbox/abuse-report-2026-10-26.txt"), report).unwrap();
    bot.deliver_files().await;
    let sent = sends(&fake);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["message"], FILE_CAPTION);
    assert!(attachment(sent[0]["attachments"][0].as_str().unwrap()).1.starts_with("report-"));

    // the admin confirms the new safety number on the server: signal-cli verifies it, and
    // alerts go as messages again
    let cfg = Config { admin_safety_number: Some(SECOND.into()), ..config(&dir, recipient()) };
    fake.lock().unwrap().identities.last_mut().unwrap()["trustLevel"] = json!("UNTRUSTED");
    let mut bot = Bot::new(connect(fake.clone()), cfg, State::load(&dir.join("state.json")).unwrap());
    alert(&dir.join("outbox"), "alert-0003.msg", "[vpn] logguard: system\n\nback");
    bot.deliver_alerts().await;
    let requests: Vec<(String, Value)> = fake.lock().unwrap().requests.clone();
    assert!(requests.iter().any(|(m, p)| m == "trust" && p["verifiedSafetyNumber"] == SECOND));
    let sent = sends(&fake);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["message"], "[vpn] logguard: system\n\nback");
    assert_eq!(bot.state.admin_safety_number.as_deref(), Some(SECOND));

    // rate limited: the alert stays, and waits
    fake.lock().unwrap().fail = Some("RATE_LIMIT_FAILURE");
    alert(&dir.join("outbox"), "alert-0004.msg", "limited");
    bot.deliver_alerts().await;
    assert_eq!(sends(&fake).len(), 1);
    assert_eq!(listing(&dir.join("outbox")), ["alert-0004.msg"]);
    fake.lock().unwrap().fail = None;
    bot.deliver_alerts().await;
    assert!(sends(&fake).is_empty(), "waiting out the rate limit");
    assert!(bot.summary().contains("ignored"), "{}", bot.summary());

    // signal-cli goes away: the bot stops (systemd starts both again)
    let (bot_side, cli_side) = tokio::io::duplex(1024);
    drop(cli_side);
    let (r, w) = tokio::io::split(bot_side);
    let rpc = Rpc::new(r, w);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(rpc.is_closed());
    let mut bot = Bot::new(rpc, config(&dir, recipient()), State::load(&dir.join("state.json")).unwrap());
    alert(&dir.join("outbox"), "alert-0005.msg", "lost");
    std::fs::remove_file(dir.join("outbox/alert-0004.msg")).unwrap();
    bot.deliver_alerts().await;
    assert!(bot.fatal.is_some());
    assert!(listing(&dir.join("outbox")).contains(&"alert-0005.msg".to_string()), "kept for the next start");
    let _ = std::fs::remove_dir_all(&dir);
}
