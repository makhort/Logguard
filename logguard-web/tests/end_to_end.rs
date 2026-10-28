//! The whole path, as on a cluster: a fake logguard behind its console socket, an agent in
//! front of it, a console asking that agent and an unreachable one over the network, and a
//! browser-like TLS client logging in with a password and a one-time code. Listens on
//! 127.0.0.1 and on a Unix socket: a sandbox without local sockets fails these tests.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use logguard_web::agent::{self, AgentCfg};
use logguard_web::auth::{self, Auth, AuthCfg};
use logguard_web::console::{self, Console, ConsoleCfg};
use logguard_web::fleet::{self, Fleet};
use logguard_web::local::Local;
use logguard_web::netlist::Allow;
use logguard_web::{tls, totp, wire};

/// A snapshot as logguard's console socket answers it (the fields the console reads).
fn snapshot(node: &str, bans: usize) -> String {
    let now = logguard_web::time::now();
    let bans: Vec<String> = (0..bans)
        .map(|i| {
            format!(r#"{{"net":"192.0.2.{i}","since":{},"until":{},"offence":1,"reason":"scan"}}"#, now - i as i64, now + 3_600_000_000)
        })
        .collect();
    format!(
        r#"{{"generated":{now},"started":{},"mode":"enforce","backend":"nftables","tracked_ips":12,"bans":[{}],
            "recent":[{{"ts":{now},"kind":"ban","severity":"high","target":"192.0.2.0","message":"ban 192.0.2.0 for 1h"}}],
            "alerts":[{{"ts":{now},"kind":"alert","severity":"critical","message":"<script>alert(1)</script> on {node}"}}],
            "offenders":[],"accounts":[],"trusted":[],"stats":{{"bans":9,"alerts":1,"records":{{"ssh":5}},"history":[]}},
            "cluster":{{"node_id":"{node}","key_id":"abcdef012345","peers":[]}}}}"#,
        now - 60_000_000,
        bans.join(",")
    )
}

/// logguard's console socket: snapshots, the digest and abuse reports; everything else refused.
fn fake_logguard(path: &Path, snap: String) {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let mut s = s.unwrap();
            let mut cmd = String::new();
            s.read_to_string(&mut cmd).unwrap();
            let reply = match cmd.trim() {
                "" | "snapshot" => snap.clone(),
                "digest" => "logguard daily digest so far".into(),
                "abuse 24h" | "abuse 7d" => serde_json::json!({
                    "host": "h", "addresses": [], "from": 1, "to": 2, "sources": 1,
                    "offenders": [{ "net": "192.0.2.5", "first": 1, "last": 2, "bans": 1, "events": 1, "categories": ["ssh"],
                        "activity": "SSH probing / login attempts", "omitted": 0, "members": [],
                        "evidence": [{ "ts": 1, "text": cmd.trim() }], "asn": 64500, "org": "Example Net" }]
                })
                .to_string(),
                _ => "error: read-only socket".into(),
            };
            s.write_all(reply.as_bytes()).unwrap();
        }
    });
}

struct Setup {
    dir: PathBuf,
    console: SocketAddr,
    cert: Vec<u8>,
    totp: Vec<u8>,
    key: [u8; 32],
    agent: SocketAddr,
}

fn setup(name: &str) -> Setup {
    // short: a Unix socket's path has a length limit (104 bytes on macOS)
    let dir = std::env::temp_dir().join(format!("lgw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = wire::decode_key(&wire::generate_key()).unwrap();

    // the agent's node
    fake_logguard(&dir.join("vpn.sock"), snapshot("vpn", 5000));
    let agent = agent::serve(
        AgentCfg { listen: "127.0.0.1:0".into(), allow: Allow::parse("127.0.0.1").unwrap(), key, node: String::new() },
        Arc::new(Local::new(dir.join("vpn.sock"))),
    )
    .unwrap();

    // the console's node, and a node nobody answers for
    fake_logguard(&dir.join("xmpp.sock"), snapshot("xmpp", 3));
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (cert, tls_key, _) = tls::self_signed(&["127.0.0.1".into()]).unwrap();
    std::fs::write(dir.join("tls.crt"), &cert).unwrap();
    std::fs::write(dir.join("tls.key"), &tls_key).unwrap();
    std::fs::write(dir.join("pw"), auth::hash_password("correct horse battery").unwrap()).unwrap();
    let secret = b"an end to end secret".to_vec();
    std::fs::write(dir.join("totp"), totp::base32(&secret)).unwrap();
    std::fs::write(dir.join("metrics.token"), "metrics-token-0123456789").unwrap();
    let fleet = Arc::new(Fleet::new(
        Some(key),
        Some(Arc::new(Local::new(dir.join("xmpp.sock")))),
        String::new(),
        &[agent.to_string(), dead.to_string()],
        Duration::from_secs(2),
    ));
    // a second admin, with codes of their own
    std::fs::create_dir_all(dir.join("admins")).unwrap();
    std::fs::write(dir.join("admins/ops.password"), auth::hash_password("the ops admin's password").unwrap()).unwrap();
    std::fs::write(dir.join("admins/ops.totp"), totp::base32(b"the ops admin secret")).unwrap();
    let auth = Auth::new(AuthCfg {
        password_file: dir.join("pw"),
        totp_file: Some(dir.join("totp")),
        admins_dir: dir.join("admins"),
        idle: Duration::from_secs(600),
        max: Duration::from_secs(3600),
    });
    auth.check_files().unwrap();
    let cfg = ConsoleCfg {
        listen: "127.0.0.1:0".into(),
        allow: Allow::Any,
        tls: tls::server_config(dir.join("tls.crt"), dir.join("tls.key")).unwrap(),
        metrics_token: Some("metrics-token-0123456789".into()),
        refresh_secs: 2,
        node: "xmpp".into(),
        rdap: false,
    };
    let console = console::serve(Arc::new(Console::new(cfg, auth, fleet))).unwrap();
    let cert_der =
        rustls_pki_types::pem::PemObject::from_pem_slice(cert.as_bytes()).map(|c: rustls_pki_types::CertificateDer| c.to_vec()).unwrap();
    Setup { dir, console, cert: cert_der, totp: secret, key, agent }
}

struct Resp {
    status: u16,
    head: String,
    body: String,
}

/// One HTTPS request, trusting only the console's own certificate.
fn https(s: &Setup, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Resp {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls_pki_types::CertificateDer::from(s.cert.clone())).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(cfg), "127.0.0.1".try_into().unwrap()).unwrap();
    let tcp = TcpStream::connect(s.console).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n", s.console, body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    tls.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Resp { status, head: head.to_string(), body: body.to_string() }
}

fn code(secret: &[u8]) -> String {
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    format!("{:06}", totp::code(secret, unix / totp::STEP_SECS))
}

fn login(s: &Setup) -> String {
    let origin = format!("https://{}", s.console);
    let body = format!(r#"{{"password":"correct horse battery","code":"{}"}}"#, code(&s.totp));
    let r = https(s, "POST", "/api/login", &[("Content-Type", "application/json"), ("Origin", &origin)], &body);
    assert_eq!(r.status, 200, "{}\n{}", r.head, r.body);
    let cookie = r.head.lines().find_map(|l| l.strip_prefix("Set-Cookie: ")).expect("a session cookie");
    assert!(
        cookie.contains("; Secure")
            && cookie.contains("; HttpOnly")
            && cookie.contains("SameSite=Strict")
            && cookie.starts_with("__Host-lgw="),
        "{cookie}"
    );
    cookie.split(';').next().unwrap().to_string()
}

#[test]
fn the_console_shows_the_cluster_to_the_admin_only() {
    let s = setup("e2e");
    // before the login: the page and the session state, nothing else
    let r = https(&s, "GET", "/", &[], "");
    assert_eq!(r.status, 200);
    assert!(r.head.contains("Content-Security-Policy: default-src 'none'; script-src 'self'"), "{}", r.head);
    assert!(r.head.contains("Strict-Transport-Security") && r.head.contains("X-Frame-Options: DENY"));
    assert!(https(&s, "GET", "/api/v1/session", &[], "").body.contains(r#""logged_in":false"#));
    let map = https(&s, "GET", "/world.json", &[], "");
    assert_eq!(map.status, 200, "the map's countries are public data");
    assert!(map.body.contains("Natural Earth") && map.body.contains(r#""UA":[50.45,30.52]"#), "logguard's capitals");
    assert_eq!(https(&s, "GET", "/api/v1/cluster", &[], "").status, 401);
    assert_eq!(https(&s, "GET", "/api/v1/nodes/1", &[], "").status, 401);
    assert_eq!(https(&s, "GET", "/metrics", &[], "").status, 401);

    // wrong logins, and a form posted from another site
    let json = [("Content-Type", "application/json")];
    let r = https(&s, "POST", "/api/login", &json, r#"{"password":"correct horse battery","code":"000000"}"#);
    assert_eq!(r.status, 401, "the password without the code");
    let r = https(&s, "POST", "/api/login", &[("Content-Type", "application/x-www-form-urlencoded")], "password=x");
    assert_eq!(r.status, 415);
    let r = https(&s, "POST", "/api/login", &[("Content-Type", "application/json"), ("Origin", "https://evil.example")], "{}");
    assert_eq!(r.status, 403);

    let cookie = login(&s);
    let auth = [("Cookie", cookie.as_str())];
    let r = https(&s, "GET", "/api/v1/session", &auth, "");
    assert!(r.body.contains(r#""logged_in":true"#) && r.body.contains(r#""user":"admin""#), "{}", r.body);

    // the second admin logs in with their own password and code, not with the first one's
    let origin = format!("https://{}", s.console);
    let json_from = [("Content-Type", "application/json"), ("Origin", origin.as_str())];
    let ops = |pw: &str, secret: &[u8]| format!(r#"{{"user":"ops","password":"{pw}","code":"{}"}}"#, code(secret));
    assert_eq!(https(&s, "POST", "/api/login", &json_from, &ops("correct horse battery", &s.totp)).status, 401);
    let r = https(&s, "POST", "/api/login", &json_from, &ops("the ops admin's password", b"the ops admin secret"));
    assert_eq!(r.status, 200, "{}", r.body);
    let ops_cookie = r.head.lines().find_map(|l| l.strip_prefix("Set-Cookie: ")).unwrap().split(';').next().unwrap().to_string();
    let r = https(&s, "GET", "/api/v1/session", &[("Cookie", ops_cookie.as_str())], "");
    assert!(r.body.contains(r#""user":"ops""#), "{}", r.body);
    assert_eq!(https(&s, "GET", "/api/v1/cluster", &[("Cookie", ops_cookie.as_str())], "").status, 200, "no roles: all of it");
    let r = https(&s, "GET", "/api/v1/cluster", &auth, "");
    assert_eq!(r.status, 200, "{}", r.body);
    let c: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let states: Vec<(String, String)> = c["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["name"].as_str().unwrap().to_string(), n["state"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(states[0], ("xmpp".into(), "ok".into()), "this node, by its cluster name");
    assert_eq!(states[1], ("vpn".into(), "ok".into()), "the agent's node, by the name its logguard uses");
    assert_eq!(states[2].1, "down", "nobody answers there");
    assert_eq!(c["totals"]["bans"], 5003, "every ban is counted...");
    assert_eq!(c["nodes"][1]["bans"], 5000);
    assert_eq!(c["bans"].as_array().unwrap().len(), 3003, "...the newest few thousand listed");
    // the page shows text from the nodes as it is: JSON-escaped here, set as text there
    assert_eq!(c["alerts"][0]["message"].as_str().unwrap().split(" on ").next().unwrap(), "<script>alert(1)</script>");
    assert!(c["attention"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["level"] == "critical" && a["text"].as_str().unwrap().starts_with("no data")));

    // one node in full, its digest, and the metrics
    let r = https(&s, "GET", "/api/v1/nodes/1", &auth, "");
    let n: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(n["snapshot"]["_cut"]["bans"], 5000);
    assert_eq!(n["snapshot"]["mode"], "enforce");
    let r = https(&s, "GET", "/api/v1/nodes/1/digest", &auth, "");
    assert!(r.body.contains("logguard daily digest so far"), "{}", r.body);

    // abuse reports: every node's merged, per provider, or one node's
    let r = https(&s, "GET", "/api/v1/abuse/7d", &auth, "");
    assert_eq!(r.status, 200, "{}", r.body);
    let a: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(a["window"], "7d");
    assert_eq!(a["sources"], 1, "the same source on both nodes is one");
    let p = &a["providers"][0];
    assert_eq!((p["key"].as_str(), p["name"].as_str(), p["bans"].as_u64()), (Some("AS64500"), Some("Example Net"), Some(2)));
    assert_eq!(p["nodes"], serde_json::json!(["vpn", "xmpp"]));
    assert_eq!(p["sources"][0]["evidence"][0]["text"], "abuse 7d");
    assert!(a["nodes"][2]["error"].is_string(), "the dead node says why it is missing");
    let r = https(&s, "GET", "/api/v1/nodes/1/abuse/24h", &auth, "");
    let a: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!((a["window"].as_str(), a["providers"][0]["nodes"].clone()), (Some("24h"), serde_json::json!(["vpn"])), "{}", r.body);
    assert_eq!(a["providers"][0]["sources"][0]["evidence"][0]["text"], "abuse 24h");
    assert_eq!(https(&s, "GET", "/api/v1/abuse/30d", &auth, "").status, 404);

    // the page asks for what its tab shows, and always for what its header needs
    let r = https(&s, "GET", "/api/v1/cluster?only=alerts", &auth, "");
    let c: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert!(c["alerts"].is_array() && c["totals"].is_object() && c["attention"].is_array() && c["nodes"].is_array());
    assert!(c.get("bans").is_none() && c.get("world").is_none(), "{}", r.body.chars().take(300).collect::<String>());

    // one address across the nodes
    let r = https(&s, "GET", "/api/v1/address/192.0.2.0/24", &auth, "");
    assert_eq!(r.status, 200, "{}", r.body);
    let a: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(a["query"], "192.0.2.0/24");
    assert!(!a["bans"].as_array().unwrap().is_empty(), "{}", r.body.chars().take(300).collect::<String>());
    assert_eq!(https(&s, "GET", "/api/v1/address/not-an-address", &auth, "").status, 400);

    // RDAP: this console doesn't look up (rdap: false), so the page is told to ask itself
    let r = https(&s, "GET", "/api/v1/rdap/8.8.8.8", &auth, "");
    assert_eq!(r.status, 502);
    assert!(r.body.contains(r#""fallback":true"#), "{}", r.body);
    let r = https(&s, "GET", "/", &[], "");
    assert!(r.head.contains("connect-src 'self' https://rdap.org https://*.arin.net"), "the page may ask RDAP's servers: {}", r.head);

    // sessions: this admin's, and ending the others (ops's session stays: another admin)
    let r = https(&s, "GET", "/api/v1/sessions", &auth, "");
    assert!(r.body.contains(r#""current":true"#), "{}", r.body);
    let r = https(&s, "GET", "/api/v1/session", &auth, "");
    assert!(r.body.contains(r#""previous":{"#) && r.body.contains(r#""session":{"#), "{}", r.body);
    // (ending one's other sessions is tested in auth.rs: a second login here would reuse the code)
    let r = https(&s, "POST", "/api/v1/sessions/end-others", &[("Cookie", cookie.as_str()), ("Origin", origin.as_str())], "{}");
    assert!(r.body.contains(r#""ended":0"#), "another admin's session isn't one's own: {}", r.body);
    assert_eq!(https(&s, "GET", "/api/v1/cluster", &[("Cookie", ops_cookie.as_str())], "").status, 200);
    assert_eq!(
        https(&s, "POST", "/api/v1/sessions/end-others", &[("Cookie", cookie.as_str()), ("Origin", "https://evil.example")], "{}").status,
        403
    );
    assert_eq!(https(&s, "GET", "/api/v1/nodes/9/abuse/7d", &auth, "").status, 404);
    let r = https(&s, "GET", "/metrics", &[("Authorization", "Bearer metrics-token-0123456789")], "");
    assert_eq!(r.status, 200);
    assert!(
        r.body.contains("logguard_up{node=\"vpn\"} 1")
            && r.body.contains("logguard_active_bans{node=\"vpn\",origin=\"local\",kind=\"address\"} 5000")
            && r.body.contains("logguard_web_logins_total{result=\"ok\"} 2")
            && r.body.contains("logguard_web_logins_total{result=\"failed\"} 2")
            && r.body.contains("logguard_attention{node=\"127.0.0.1"),
        "{}",
        r.body
    );
    assert_eq!(https(&s, "GET", "/metrics", &[("Authorization", "Bearer wrong")], "").status, 401);

    // another site's page can't read the API with the admin's cookie
    assert_eq!(https(&s, "GET", "/api/v1/cluster", &[("Cookie", cookie.as_str()), ("Origin", "https://evil.example")], "").status, 403);
    assert_eq!(https(&s, "GET", "/api/v1/cluster", &[("Cookie", cookie.as_str()), ("Sec-Fetch-Site", "cross-site")], "").status, 403);
    // nothing writes: other methods are refused
    assert_eq!(https(&s, "DELETE", "/api/v1/cluster", &auth, "").status, 404);
    assert_eq!(https(&s, "POST", "/api/v1/cluster", &auth, "").status, 404);

    // logged out: the cookie is worth nothing
    let r = https(&s, "POST", "/api/logout", &auth, "");
    assert!(r.head.contains("Max-Age=0"));
    assert_eq!(https(&s, "GET", "/api/v1/cluster", &auth, "").status, 401);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn agents_answer_the_web_key_only() {
    let s = setup("agent");
    let reply = fleet::fetch(&s.agent.to_string(), &s.key, wire::Want::Snapshot).unwrap();
    assert_eq!(reply.node, "vpn");
    assert!(reply.snapshot.is_some());
    let other = wire::decode_key(&wire::generate_key()).unwrap();
    assert!(fleet::fetch(&s.agent.to_string(), &other, wire::Want::Snapshot).is_err(), "another key gets nothing");
    // a recorded request sent again
    let (frame, _) = wire::request(&s.key, wire::Want::Snapshot, logguard_web::time::now()).unwrap();
    for (i, want_reply) in [(0, true), (1, false)] {
        let mut t = TcpStream::connect(s.agent).unwrap();
        t.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        t.write_all(&frame).unwrap();
        let got = wire::read_frame(&mut t, wire::MAX_REPLY);
        assert_eq!(got.is_ok(), want_reply, "attempt {i}");
    }
    // a stranger speaking HTTP to the agent's port
    let mut t = TcpStream::connect(s.agent).unwrap();
    t.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    t.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let _ = t.read_to_end(&mut buf);
    assert!(buf.is_empty());
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn logins_are_locked_out_after_failures() {
    let s = setup("lockout");
    let json = [("Content-Type", "application/json")];
    for _ in 0..auth::MAX_FAILURES {
        assert_eq!(https(&s, "POST", "/api/login", &json, r#"{"password":"guess","code":"123456"}"#).status, 401);
    }
    let body = format!(r#"{{"password":"correct horse battery","code":"{}"}}"#, code(&s.totp));
    let r = https(&s, "POST", "/api/login", &json, &body);
    assert_eq!(r.status, 429, "locked out, even with the right password and code");
    assert!(r.head.contains("Retry-After"));
    let _ = std::fs::remove_dir_all(&s.dir);
}
