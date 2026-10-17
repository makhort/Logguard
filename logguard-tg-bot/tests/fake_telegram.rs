//! The bot against a fake Bot API server on 127.0.0.1: what reaches "Telegram" from the
//! outbox, with account names replaced, and what stays when Telegram refuses.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use logguard_tg_bot::api::{Api, Chat, Message, Update, User};
use logguard_tg_bot::bot::{Bot, Config, FILE_CAPTION};
use logguard_tg_bot::redact::{parse_domains, Pseudonyms};
use logguard_tg_bot::seal::Recipient;
use logguard_tg_bot::servers::ServerNames;
use pgp::composed::{
    EncryptionCaps, KeyType, Message as PgpMessage, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;

const TOKEN: &str = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";
const ADMIN: i64 = 4242;

#[derive(Debug, Clone)]
struct Request {
    method: String,
    content_type: String,
    body: Vec<u8>,
}

impl Request {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Default)]
struct Fake {
    requests: Mutex<Vec<Request>>,
    /// The next sendMessage gets 429 Too Many Requests.
    flood: AtomicBool,
    /// The next this many sendMessage get 400 Bad Request.
    refuse: AtomicI64,
    next_id: AtomicI64,
}

impl Fake {
    fn take(&self) -> Vec<Request> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }

    fn answer(&self, method: &str) -> (u16, String) {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 100;
        let sent = format!(r#"{{"ok":true,"result":{{"message_id":{id},"chat":{{"id":{ADMIN},"type":"private"}},"date":{now}}}}}"#);
        match method {
            "sendMessage" if self.flood.swap(false, Ordering::SeqCst) => (
                429,
                r#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}"#.into(),
            ),
            "sendMessage" if self.refuse.fetch_sub(1, Ordering::SeqCst) > 0 => {
                (400, r#"{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities"}"#.into())
            }
            "sendMessage" | "sendDocument" => (200, sent),
            "deleteMessage" | "setMyCommands" => (200, r#"{"ok":true,"result":true}"#.into()),
            "getMe" => (200, r#"{"ok":true,"result":{"id":999,"is_bot":true,"first_name":"t","username":"lg_test_bot"}}"#.into()),
            _ => (404, r#"{"ok":false,"error_code":404,"description":"Not Found"}"#.into()),
        }
    }
}

/// One HTTP/1.1 request (Content-Length or chunked body), or None at the end of the connection.
async fn read_request<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let path = line.split_whitespace().nth(1)?.to_string();
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
    let header = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let mut body = Vec::new();
    if let Some(len) = header("content-length") {
        body.resize(len.parse().ok()?, 0);
        r.read_exact(&mut body).await.ok()?;
    } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            let mut size = String::new();
            r.read_line(&mut size).await.ok()?;
            let n = usize::from_str_radix(size.trim(), 16).ok()?;
            let mut chunk = vec![0; n + 2];
            r.read_exact(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    Some((path, headers, body))
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
                while let Some((path, headers, body)) = read_request(&mut rd).await {
                    let method = path.strip_prefix(&format!("/bot{TOKEN}/")).expect("the token in the path").to_string();
                    let content_type = headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.clone()).unwrap_or_default();
                    let (status, reply) = fake.answer(&method);
                    fake.requests.lock().unwrap().push(Request { method, content_type, body });
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

fn now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

/// A throwaway OpenPGP key as phones make them (Ed25519, a Curve25519 encryption subkey).
fn keypair() -> (SignedSecretKey, Vec<u8>) {
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

/// The uploaded file in a multipart/form-data request.
fn document(r: &Request) -> Vec<u8> {
    let boundary = r.content_type.split("boundary=").nth(1).unwrap().trim_matches('"');
    let b = &r.body;
    let find = |needle: &[u8], from: usize| b[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from);
    let part = find(b"name=\"document\"", 0).unwrap();
    let start = find(b"\r\n\r\n", part).unwrap() + 4;
    let end = find(format!("\r\n--{boundary}").as_bytes(), start).unwrap();
    b[start..end].to_vec()
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

#[tokio::test]
async fn outbox_to_telegram() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let dir = std::env::temp_dir().join(format!("logguard-tg-bot-fake-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let outbox = dir.join("outbox");
    std::fs::create_dir_all(&outbox).unwrap();

    let names = Pseudonyms::new([1; 32], parse_domains("example.org"));
    let alice = names.tag("alice@example.org");
    let cfg = Config {
        admin: ADMIN,
        outbox: outbox.clone(),
        outbox_max_age: Duration::from_secs(7 * 86400),
        alert_max_age: Duration::from_secs(24 * 3600),
        delete_after: Some(Duration::from_secs(3600)),
        protect: true,
        state_path: dir.join("state.json"),
        servers: ServerNames::parse("xmpp=11.17.39.236,example.org; vpn=11.25.48.86").unwrap(),
        recipient: None,
    };
    let api = Api::new(&url, TOKEN).unwrap();
    assert_eq!(logguard_tg_bot::bot::connect(&api).await.unwrap().username.as_deref(), Some("lg_test_bot"));
    let mut bot = Bot::new(api, cfg, names, "lg_test_bot".into());
    fake.take();

    // an alert naming an account, and one that waited too long
    alert(
        &outbox,
        "alert-0001.msg",
        "[xmpp] logguard: new registration\n\n[Info] account alice@example.org registered from 1.2.3.4\n  \
         cluster peer 11.25.48.86:7946 failing; nextcloud.example.org:443 5d",
    );
    let old = alert(&outbox, "alert-0000.msg", "[xmpp] logguard: system\n\nold");
    std::fs::File::options().write(true).open(&old).unwrap().set_modified(SystemTime::now() - Duration::from_secs(25 * 3600)).unwrap();
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(sent.len(), 2, "{sent:?}");
    let m = sent[0].json();
    assert_eq!(sent[0].method, "sendMessage");
    assert_eq!(m["chat_id"], ADMIN);
    assert_eq!(
        m["text"],
        format!(
            "[xmpp] logguard: new registration\n\n[Info] account {alice} registered from 1.2.3.4\n  \
             cluster peer vpn:7946 failing; nextcloud.xmpp:443 5d"
        ),
        "account names and the servers' addresses replaced"
    );
    assert_eq!(m["entities"][0]["type"], "bold");
    assert_eq!(m["entities"][1]["type"], "pre");
    assert_eq!(m["protect_content"], true);
    assert_eq!(m["link_preview_options"]["is_disabled"], true);
    assert!(sent[1].json()["text"].as_str().unwrap().starts_with("1 alert(s) waited more than 24 h"), "{:?}", sent[1].json());
    assert!(listing(&outbox).is_empty(), "sent and dropped: {:?}", listing(&outbox));

    // the weekly report: without the admin's OpenPGP key it waits, never sent in clear
    let report =
        "Abuse report from xmpp (11.17.39.236) and vpn\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n\nHello, abuse@hetzner.de,\n1.2.3.4 tried\n";
    std::fs::write(outbox.join("abuse-report-2026-10-19.txt"), report).unwrap();
    std::fs::write(outbox.join(".abuse-report-2026-10-26.txt.tmp"), "being written").unwrap();
    bot.deliver_files().await;
    assert!(fake.take().is_empty());
    assert!(listing(&outbox).contains(&"abuse-report-2026-10-19.txt".to_string()));

    // with it: one encrypted file, a neutral name and caption, nothing of the report in clear
    let (secret, public) = keypair();
    bot.cfg.recipient = Some(Recipient::parse(&public, now_secs() as u32).unwrap());
    bot.deliver_files().await;
    let sent = fake.take();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "sendDocument");
    assert!(sent[0].content_type.starts_with("multipart/form-data"));
    let form = sent[0].text();
    let today = chrono::Utc::now().format("%Y-%m-%d");
    assert!(form.contains(&format!("filename=\"report-{today}.txt.pgp\"")), "{form}");
    assert!(form.contains(FILE_CAPTION), "{form}");
    for clear in ["Abuse", "abuse", "Period", "hetzner", "11.17.39.236", "xmpp (", "1.2.3.4"] {
        assert!(!form.contains(clear), "{clear} in clear: {form}");
    }
    assert!(form.contains(&format!("\r\n{ADMIN}\r\n")), "chat_id: {form}");
    let sealed = document(&sent[0]);
    let opened = PgpMessage::from_bytes(&sealed[..]).unwrap().decrypt(&"".into(), &secret).unwrap().as_data_vec().unwrap();
    assert_eq!(String::from_utf8(opened).unwrap(), report, "the admin's key opens the whole report, unchanged");
    assert_eq!(listing(&outbox), [".abuse-report-2026-10-26.txt.tmp"], "only the unfinished file stays");

    // commands: the admin's are answered, others' ignored
    let update = |id: i64, chat: i64, from: i64, text: &str| Update {
        update_id: id,
        message: Some(Message {
            message_id: id,
            from: Some(User { id: from, is_bot: false, username: None }),
            chat: Chat { id: chat, kind: "private".into() },
            date: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
            text: Some(text.into()),
        }),
    };
    bot.on_update(update(500, 777, 777, "/status")).await;
    assert!(fake.take().is_empty(), "no answer to strangers");
    bot.on_update(update(501, ADMIN, ADMIN, "/status@lg_test_bot")).await;
    let sent = fake.take();
    let status = sent[0].json()["text"].as_str().unwrap().to_string();
    assert!(status.contains("Sent since the start: 1 alert(s), 1 file(s)"), "the note about dropped ones is no alert: {status}");
    assert!(status.contains("Outbox: 0 alert(s), 0 file(s) waiting"), "{status}");
    assert!(sent[0].json().get("protect_content").is_none(), "replies aren't protected");
    assert_eq!(bot.state.offset, 502);

    // an alert Telegram refuses goes again without formatting; one refused for good is
    // dropped with a note, and the alerts after it still go
    alert(&outbox, "alert-0003.msg", "[vpn] logguard: system\n\nrefused once");
    fake.refuse.store(1, Ordering::SeqCst);
    bot.deliver_alerts().await;
    let sent = fake.take();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(sent[0].json().get("entities").is_some() && sent[1].json().get("entities").is_none());
    assert_eq!(sent[1].json()["text"], "[vpn] logguard: system\n\nrefused once");
    alert(&outbox, "alert-0004.msg", "[vpn] logguard: system\n\nrefused for good");
    alert(&outbox, "alert-0005.msg", "[vpn] logguard: system\n\nthe next one");
    fake.refuse.store(2, Ordering::SeqCst);
    bot.deliver_alerts().await;
    let texts: Vec<String> = fake.take().iter().map(|r| r.json()["text"].as_str().unwrap().to_string()).collect();
    assert_eq!(texts.len(), 4, "{texts:?}");
    assert!(texts[2].starts_with("An alert was dropped: Telegram refused it"), "{texts:?}");
    assert_eq!(texts[3], "[vpn] logguard: system\n\nthe next one", "not held up");
    assert!(listing(&outbox).iter().all(|n| n.starts_with(".abuse")), "{:?}", listing(&outbox));
    fake.refuse.store(0, Ordering::SeqCst);

    // flood control: the alert stays and nothing is tried until Telegram's wait is over
    alert(&outbox, "alert-0002.msg", "[vpn] logguard: system\n\nsecond");
    fake.flood.store(true, Ordering::SeqCst);
    bot.deliver_alerts().await;
    assert_eq!(fake.take().len(), 1);
    assert!(listing(&outbox).contains(&"alert-0002.msg".to_string()), "put back: {:?}", listing(&outbox));
    bot.deliver_alerts().await;
    assert!(fake.take().is_empty(), "waiting out retry_after");

    // messages sent and received are deleted once old enough
    let tracked = bot.state.to_delete.len();
    assert!(tracked >= 4, "alert, note, file, command and reply: {tracked}");
    for s in &mut bot.state.to_delete {
        s.at -= 2 * 3600;
    }
    bot.state.to_delete[0].at -= 47 * 3600; // too old to delete
                                            // a new instance (as after a restart) holds no flood wait
    bot.save();
    let state = logguard_tg_bot::state::State::load(&dir.join("state.json"));
    assert_eq!(state.offset, 502);
    let mut bot = Bot::new(
        Api::new(&url, TOKEN).unwrap(),
        Config { delete_after: Some(Duration::from_secs(3600)), ..bot.cfg },
        bot.names,
        "lg_test_bot".into(),
    );
    bot.delete_old().await;
    let deleted = fake.take();
    assert_eq!(deleted.len(), tracked - 1, "all but the one past 48 h");
    assert!(deleted.iter().all(|r| r.method == "deleteMessage" && r.json()["chat_id"] == ADMIN));
    assert!(bot.state.to_delete.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
