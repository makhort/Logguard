//! The web console: HTTPS (TLS 1.3) for one admin, the page and its JSON API, read only.
//!
//! | path | what |
//! |---|---|
//! | `/` | the page (it asks for the login itself); `/world.json` the Map tab's countries and capitals |
//! | `POST /api/login`, `POST /api/logout` | `{"password": ..., "code": ...}`; a session cookie |
//! | `/api/v1/session` | whether this browser is logged in (the only API path that needs no session) |
//! | `/api/v1/cluster` | everything below in one document (the page's refresh) |
//! | `/api/v1/{overview,attention,alerts,actions,bans,offenders,accounts,world,history}` | parts of it |
//! | `/api/v1/nodes`, `/api/v1/nodes/<id>`, `/api/v1/nodes/<id>/digest` | the nodes; one node's whole snapshot; its digest so far |
//! | `/api/v1/abuse/{24h,7d}`, `/api/v1/nodes/<id>/abuse/{24h,7d}` | the abuse report of every node merged, or of one, per provider |
//! | `/api/v1/address/<address or network>` | what every node says about it |
//! | `/api/v1/rdap/<address>` | its network's abuse mailbox (RDAP); `"fallback": true` when the page should ask itself |
//! | `/api/v1/sessions`, `POST /api/v1/sessions/end-others` | this admin's sessions; end the others |
//! | `/metrics` | Prometheus' text format (a session, or `Authorization: Bearer` with `METRICS_TOKEN_FILE`) |

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::auth::{self, Auth, Login};
use crate::fleet::Fleet;
use crate::http::{self, ReadError, Request, Response};
use crate::netlist::{normalize, Allow};
use crate::say;

const MAX_CONNECTIONS: usize = 64;
/// A browser opens up to six connections to a site.
const MAX_PER_SOURCE: usize = 12;
/// To finish the TLS handshake, then each request (or to wait for the next one).
const HANDSHAKE: Duration = Duration::from_secs(10);
const REQUEST: Duration = Duration::from_secs(30);
const MAX_REQUESTS: usize = 1000;

const INDEX: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const CORE_JS: &str = include_str!("../web/core.js");
const DOM_JS: &str = include_str!("../web/dom.js");
const APP_CSS: &str = include_str!("../web/app.css");
const ICON: &str = include_str!("../web/icon.svg");
/// The Map tab's countries (Natural Earth, public domain) and capitals (logguard's): public data.
const WORLD: &str = include_str!("../web/world.json");

/// `connect-src` names RDAP's servers: when the console can't look up an abuse mailbox, the
/// page asks rdap.org itself, which sends it on to the registry.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self' https://rdap.org https://*.arin.net https://*.ripe.net https://*.apnic.net \
                   https://*.lacnic.net https://*.afrinic.net; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct ConsoleCfg {
    pub listen: String,
    pub allow: Allow,
    pub tls: Arc<rustls::ServerConfig>,
    /// `METRICS_TOKEN_FILE`'s token, for Prometheus.
    pub metrics_token: Option<String>,
    pub refresh_secs: u64,
    /// This node's name, shown on the login page.
    pub node: String,
    /// Whether the console looks up abuse mailboxes itself (`RDAP_LOOKUPS`).
    pub rdap: bool,
}

pub struct Console {
    pub cfg: ConsoleCfg,
    pub auth: Auth,
    pub fleet: Arc<Fleet>,
    pub rdap: crate::rdap::Rdap,
    /// Addresses whose failed TLS handshakes were logged lately (scanners try often).
    tls_logged: Mutex<HashMap<IpAddr, Instant>>,
}

impl Console {
    pub fn new(cfg: ConsoleCfg, auth: Auth, fleet: Arc<Fleet>) -> Self {
        let rdap = crate::rdap::Rdap::new(cfg.rdap);
        Console { cfg, auth, fleet, rdap, tls_logged: Mutex::default() }
    }
}

/// A TCP stream whose reads share one deadline (set per request).
struct Timed {
    s: TcpStream,
    until: Instant,
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "too slow"));
        }
        self.s.set_read_timeout(Some(left))?;
        self.s.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.s.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.s.flush()
    }
}

/// Starts the console's listener thread; returns the address it listens on.
pub fn serve(console: Arc<Console>) -> Result<SocketAddr> {
    let listener = TcpListener::bind(&console.cfg.listen).with_context(|| format!("binding CONSOLE_LISTEN {}", console.cfg.listen))?;
    let addr = listener.local_addr()?;
    let active = Arc::new(AtomicUsize::new(0));
    let per_source: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            let Ok(ip) = s.peer_addr().map(|a| normalize(a.ip())) else { continue };
            if !console.cfg.allow.admits(ip) {
                say!("console: refused connection from {ip}: not in CONSOLE_ALLOW");
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                continue;
            }
            {
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                let n = open.entry(ip).or_default();
                if *n >= MAX_PER_SOURCE {
                    continue;
                }
                *n += 1;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let (console, active, per_source) = (Arc::clone(&console), Arc::clone(&active), Arc::clone(&per_source));
            std::thread::spawn(move || {
                connection(&console, s, ip);
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(n) = open.get_mut(&ip) {
                    *n -= 1;
                    if *n == 0 {
                        open.remove(&ip);
                    }
                }
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(addr)
}

fn connection(console: &Console, s: TcpStream, ip: IpAddr) {
    let _ = s.set_write_timeout(Some(REQUEST));
    let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&console.cfg.tls)) else { return };
    let mut tls = rustls::StreamOwned::new(conn, Timed { s, until: Instant::now() + HANDSHAKE });
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            log_tls_failure(console, ip, &e);
            return;
        }
    }
    let mut reader = BufReader::new(tls);
    for _ in 0..MAX_REQUESTS {
        reader.get_mut().sock.until = Instant::now() + REQUEST;
        let req = match http::read_request(&mut reader) {
            Ok(r) => r,
            Err(ReadError::Closed) | Err(ReadError::Io(_)) => break,
            Err(ReadError::Bad(status, why)) => {
                let _ = http::write_response(reader.get_mut(), headers(Response::error(status, why)), false, false, false);
                break;
            }
        };
        let keep = req.keep_alive;
        let head = req.method == "HEAD";
        let gzip = http::takes_gzip(&req);
        let resp = headers(handle(console, &req, ip));
        if http::write_response(reader.get_mut(), resp, keep, head, gzip).is_err() || !keep {
            break;
        }
    }
    let tls = reader.get_mut();
    tls.conn.send_close_notify();
    let _ = tls.conn.complete_io(&mut tls.sock);
}

fn log_tls_failure(console: &Console, ip: IpAddr, e: &std::io::Error) {
    let mut logged = console.tls_logged.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if logged.len() > 1000 {
        logged.retain(|_, t| now - *t < Duration::from_secs(3600));
    }
    if logged.len() < 1000 && logged.get(&ip).is_none_or(|t| now - *t >= Duration::from_secs(3600)) {
        logged.insert(ip, now);
        say!("console: TLS handshake with {ip} failed: {e}");
    }
}

/// Headers every answer carries: no caching, no framing, no other origins.
fn headers(resp: Response) -> Response {
    resp.with("Content-Security-Policy", CSP)
        .with("Strict-Transport-Security", "max-age=31536000")
        .with("X-Content-Type-Options", "nosniff")
        .with("X-Frame-Options", "DENY")
        .with("Referrer-Policy", "no-referrer")
        .with("Cross-Origin-Opener-Policy", "same-origin")
        .with("Cross-Origin-Resource-Policy", "same-origin")
        .with("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        .with("Cache-Control", "no-store")
}

fn session_token(req: &Request) -> Option<&str> {
    req.header("cookie").and_then(auth::cookie_value)
}

/// The admin logged in with this request's cookie.
fn user(console: &Console, req: &Request) -> Option<String> {
    session_token(req).and_then(|t| console.auth.session(t))
}

fn logged_in(console: &Console, req: &Request) -> bool {
    user(console, req).is_some()
}

/// Byte strings equal, in a time that doesn't depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    use sha2::Digest;
    let (a, b) = (sha2::Sha256::digest(a), sha2::Sha256::digest(b));
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A request a page of this console sent: same origin when the browser says where it came from.
fn same_origin(req: &Request) -> bool {
    if req.header("sec-fetch-site").is_some_and(|s| s == "cross-site" || s == "same-site") {
        return false;
    }
    match (req.header("origin"), req.header("host")) {
        (Some(origin), Some(host)) => origin == format!("https://{host}"),
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn handle(console: &Console, req: &Request, ip: IpAddr) -> Response {
    let read = req.method == "GET" || req.method == "HEAD";
    match (req.method.as_str(), req.path.as_str()) {
        (_, "/" | "/index.html") if read => Response::new(200, "text/html; charset=utf-8", INDEX.into()),
        (_, "/app.js") if read => Response::new(200, "text/javascript; charset=utf-8", APP_JS.into()),
        (_, "/core.js") if read => Response::new(200, "text/javascript; charset=utf-8", CORE_JS.into()),
        (_, "/dom.js") if read => Response::new(200, "text/javascript; charset=utf-8", DOM_JS.into()),
        (_, "/app.css") if read => Response::new(200, "text/css; charset=utf-8", APP_CSS.into()),
        (_, "/icon.svg") if read => Response::new(200, "image/svg+xml", ICON.into()),
        (_, "/world.json") if read => Response::new(200, "application/json", WORLD.into()),
        ("POST", "/api/login") => login(console, req, ip),
        ("POST", "/api/logout") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            if let Some(t) = session_token(req) {
                console.auth.logout(t);
            }
            Response::json(200, &json!({ "ok": true }))
                .with("Set-Cookie", format!("{}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0", auth::COOKIE))
        }
        ("POST", "/api/v1/sessions/end-others") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            match session_token(req).filter(|t| console.auth.session(t).is_some()) {
                Some(t) => Response::json(200, &json!({ "ended": console.auth.end_others(t) })),
                None => Response::error(401, "log in first"),
            }
        }
        (_, "/api/v1/session") if read => {
            let user = user(console, req);
            let about = session_token(req).filter(|_| user.is_some()).and_then(|t| console.auth.about(t));
            Response::json(
                200,
                &json!({
                    "logged_in": user.is_some(),
                    "user": user,
                    "session": about.as_ref().map(|a| &a.0),
                    "previous": about.as_ref().map(|a| &a.1),
                    "totp": console.auth.cfg.totp_file.is_some(),
                    "node": console.cfg.node,
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            )
        }
        (_, "/metrics") if read => {
            let bearer = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).map(str::trim);
            let token_ok = match (&console.cfg.metrics_token, bearer) {
                (Some(want), Some(got)) => same(want.as_bytes(), got.as_bytes()),
                _ => false,
            };
            if !token_ok && !logged_in(console, req) {
                return Response::error(401, "log in, or send the metrics token").with("WWW-Authenticate", "Bearer");
            }
            let nodes = console.fleet.view();
            let ours = crate::metrics::Console {
                logins: std::array::from_fn(|i| console.auth.logins[i].load(std::sync::atomic::Ordering::Relaxed)),
                sessions: console.auth.sessions(),
            };
            let text = crate::metrics::render(&nodes, crate::time::now(), Some(ours));
            Response::new(200, "text/plain; version=0.0.4; charset=utf-8", text.into())
        }
        (_, p) if p.starts_with("/api/v1/") && read => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            if !logged_in(console, req) {
                return Response::error(401, "log in first");
            }
            api(console, req, &p["/api/v1/".len()..])
        }
        (_, "/" | "/index.html" | "/app.js" | "/core.js" | "/dom.js" | "/app.css" | "/icon.svg" | "/world.json" | "/metrics") => {
            Response::error(405, "GET only").with("Allow", "GET, HEAD")
        }
        (_, p) if p.starts_with("/api/") => Response::error(404, "no such API path"),
        (m, p) => {
            if !logged_in(console, req) {
                say!("console: unknown path from {ip}: {m} {}", p.chars().take(200).collect::<String>());
            }
            Response::error(404, "not found")
        }
    }
}

fn login(console: &Console, req: &Request, ip: IpAddr) -> Response {
    if !same_origin(req) {
        return Response::error(403, "not from this console's page");
    }
    if !req.header("content-type").is_some_and(|c| c.split(';').next().is_some_and(|t| t.trim() == "application/json")) {
        return Response::error(415, "JSON only");
    }
    let body: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "not JSON"),
    };
    let user = body.get("user").and_then(Value::as_str).unwrap_or("").trim();
    let password = body.get("password").and_then(Value::as_str).unwrap_or("");
    let code = body.get("code").and_then(Value::as_str).unwrap_or("");
    match console.auth.login(ip, user, password, code) {
        Ok(Login::Ok(token)) => {
            console.auth.set_agent(&token, req.header("user-agent").unwrap_or(""));
            Response::json(200, &json!({ "ok": true }))
                .with("Set-Cookie", format!("{}={token}; Path=/; Secure; HttpOnly; SameSite=Strict", auth::COOKIE))
        }
        Ok(Login::Wrong) => Response::error(401, "wrong account, password or code"),
        Ok(Login::Locked(left)) => {
            Response::error(429, &format!("too many failed logins from this address: wait {} minutes", left.as_secs().div_ceil(60)))
                .with("Retry-After", left.as_secs().to_string())
        }
        Err(e) => {
            say!("console: login impossible: {e:#}");
            Response::error(503, "the console can't check logins: see its log (journalctl -u logguard-web)")
        }
    }
}

fn api(console: &Console, req: &Request, rest: &str) -> Response {
    let now = crate::time::now();
    // the console's own matters first: they don't ask the nodes
    if rest == "sessions" {
        let list = session_token(req).map(|t| console.auth.list(t)).unwrap_or_default();
        return Response::json(200, &json!({ "sessions": list }));
    }
    if let Some(ip) = rest.strip_prefix("rdap/") {
        let Ok(ip) = ip.parse::<IpAddr>() else { return Response::error(400, "not an address") };
        return match console.rdap.lookup(crate::netlist::normalize(ip)) {
            Ok(c) => Response::json(200, &json!({ "abuse": c.abuse, "network": c.network, "via": "console" })),
            // the page asks rdap.org itself then
            Err(e) => Response::json(502, &json!({ "error": e, "fallback": true })),
        };
    }
    let nodes = console.fleet.view();
    if let Some(q) = rest.strip_prefix("address/") {
        return match q.parse::<crate::netlist::Net>() {
            Ok(net) => Response::json(200, &crate::aggregate::address(&nodes, &net)),
            Err(_) => Response::error(400, "not an address or network"),
        };
    }
    let abuse = |want: Option<crate::wire::Want>, only: Option<&str>| match want {
        Some(want) => match console.fleet.abuse(want, only) {
            Ok(r) => Response::json(200, &serde_json::to_value(r).unwrap_or_default()),
            Err(e) => Response::error(404, &format!("{e:#}")),
        },
        None => Response::error(404, "abuse reports are of 24h or 7d"),
    };
    if let Some(window) = rest.strip_prefix("abuse/") {
        return abuse(crate::wire::Want::abuse(window), None);
    }
    if let Some(node) = rest.strip_prefix("nodes/") {
        if let Some((id, window)) = node.split_once("/abuse/") {
            return abuse(crate::wire::Want::abuse(window), Some(id));
        }
        let (id, digest) = match node.strip_suffix("/digest") {
            Some(id) => (id, true),
            None => (node, false),
        };
        let Some(n) = nodes.iter().find(|n| n.id == id) else { return Response::error(404, "no such node") };
        if digest {
            return match console.fleet.digest(&n.id) {
                Ok(text) => Response::json(200, &json!({ "node": n.name, "text": text })),
                Err(e) => Response::error(502, &format!("{e:#}")),
            };
        }
        return Response::json(200, &crate::aggregate::node(n, now));
    }
    let all = crate::aggregate::cluster(&nodes, now, console.cfg.refresh_secs);
    let part = |keys: &[&str]| {
        let mut out = serde_json::Map::new();
        out.insert("generated".into(), all["generated"].clone());
        for k in keys {
            out.insert((*k).into(), all[*k].clone());
        }
        Response::json(200, &Value::Object(out))
    };
    match rest {
        // the page asks for what its tab shows (`?only=alerts,history`), and always for what its
        // header needs
        "cluster" if req.param("only").is_some() => {
            let mut keys = vec!["refresh_secs", "nodes", "totals", "attention"];
            keys.extend(
                req.param("only")
                    .unwrap_or("")
                    .split(',')
                    .filter(|k| ["alerts", "actions", "bans", "offenders", "accounts", "world", "history"].contains(k)),
            );
            part(&keys)
        }
        "cluster" => Response::json(200, &all),
        "overview" => part(&["nodes", "totals", "attention"]),
        "nodes" => part(&["nodes"]),
        "attention" | "alerts" | "actions" | "bans" | "offenders" | "accounts" | "world" | "history" => part(&[rest]),
        _ => Response::error(404, "no such API path"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "POST".into(),
            path: "/api/login".into(),
            query: String::new(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: vec![],
            keep_alive: true,
        }
    }

    #[test]
    fn origins() {
        assert!(same_origin(&req(&[("host", "c.example.org:7948"), ("origin", "https://c.example.org:7948")])));
        assert!(same_origin(&req(&[("host", "c.example.org:7948")])), "no Origin: not a browser's cross-site request");
        assert!(!same_origin(&req(&[("host", "c.example.org:7948"), ("origin", "https://evil.example")])));
        assert!(!same_origin(&req(&[("host", "c.example.org:7948"), ("origin", "http://c.example.org:7948")])));
        assert!(!same_origin(&req(&[("host", "c"), ("sec-fetch-site", "cross-site")])));
        assert!(same_origin(&req(&[("host", "c"), ("sec-fetch-site", "same-origin")])));
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }
}
