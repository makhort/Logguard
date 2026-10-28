//! Abuse mailboxes by RDAP, for the Abuse tab's Mail button: `https://rdap.org/ip/<address>`,
//! which sends each address on to its registry (RIPE, ARIN, APNIC, ...). Asked by the console
//! only when an admin asks, one at a time and at most one a second, each answer kept a day.
//! When the console can't (`RDAP_LOOKUPS=off`, or no way out from its host), the page asks
//! rdap.org itself, from the admin's browser.
//!
//! RDAP data is written by the network's owner, who may be the attacker: only plain e-mail
//! addresses are taken (as logguard's weekly report does), and the network's name is cut to
//! printable text.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use serde_json::Value;

/// Each hop's connection and reads.
const TIMEOUT: Duration = Duration::from_secs(10);
/// rdap.org, then the registry (sometimes a national one after it).
const MAX_REDIRECTS: usize = 4;
/// An RDAP answer is a few kB.
const MAX_BODY: usize = 1 << 20;
const KEEP: Duration = Duration::from_secs(24 * 3600);
const KEEP_FAILED: Duration = Duration::from_secs(300);
const CACHED: usize = 5000;
/// The CA bundles of Debian/Ubuntu, Fedora/RHEL, Alpine and macOS.
const CA_FILES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Contact {
    /// The abuse mailboxes, plain e-mail addresses only, at most 5.
    pub abuse: Vec<String>,
    /// "EXAMPLE-NET, NET-198-51-100-0-1": the network's name and handle.
    pub network: String,
}

fn plain_email(e: &str) -> Option<String> {
    let e = e.trim().to_lowercase();
    let ok = e.len() <= 100
        && e.matches('@').count() == 1
        && !e.starts_with('@')
        && e.contains('.')
        && e.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c));
    ok.then_some(e)
}

fn abuse_emails(v: &Value, out: &mut Vec<String>, depth: usize) {
    if depth > 8 {
        return;
    }
    for e in v.get("entities").and_then(Value::as_array).into_iter().flatten() {
        let abuse = e.get("roles").and_then(Value::as_array).is_some_and(|r| r.iter().any(|x| x.as_str() == Some("abuse")));
        if abuse {
            let items = e.get("vcardArray").and_then(|v| v.get(1)).and_then(Value::as_array);
            for item in items.into_iter().flatten() {
                if item.get(0).and_then(Value::as_str) == Some("email") {
                    if let Some(m) = item.get(3).and_then(Value::as_str).and_then(plain_email) {
                        if !out.contains(&m) {
                            out.push(m);
                        }
                    }
                }
            }
        }
        abuse_emails(e, out, depth + 1);
    }
}

/// The abuse mailboxes and network name in an RDAP answer.
pub fn parse(json: &str) -> Option<Contact> {
    let v: Value = serde_json::from_str(json).ok()?;
    let mut abuse = vec![];
    abuse_emails(&v, &mut abuse, 0);
    abuse.truncate(5);
    let name = v.get("name").and_then(Value::as_str).unwrap_or("");
    let handle = v.get("handle").and_then(Value::as_str).unwrap_or("");
    let network = match (name, handle) {
        ("", h) => h.to_string(),
        (n, "") => n.to_string(),
        (n, h) => format!("{n}, {h}"),
    };
    Some(Contact { abuse, network: network.chars().filter(|c| !c.is_control()).take(100).collect() })
}

/// A host name the console may ask over HTTPS: a name, never an address written out.
fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        && host.bytes().any(|b| b.is_ascii_alphabetic())
}

/// Addresses a registry knows: not private, local, link-local or multicast ones (asking
/// about those would only tell rdap.org about this network).
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_multicast() || a.is_broadcast())
        }
        IpAddr::V6(a) => {
            let first = a.segments()[0];
            !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80)
                && a.to_ipv4_mapped().is_none_or(|v4| public(IpAddr::V4(v4)))
        }
    }
}

fn client() -> Result<Arc<rustls::ClientConfig>> {
    static CFG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CFG.get_or_init(|| {
        let file = CA_FILES.iter().find(|f| std::path::Path::new(f).exists()).ok_or("no CA bundle (ca-certificates not installed?)")?;
        let mut roots = rustls::RootCertStore::empty();
        let certs = CertificateDer::pem_file_iter(file).map_err(|e| format!("{file}: {e}"))?;
        let (added, _) = roots.add_parsable_certificates(certs.flatten());
        if added == 0 {
            return Err(format!("{file}: no certificates"));
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(cfg))
    })
    .clone()
    .map_err(|e| anyhow!(e))
}

/// One GET over HTTPS: (status, Location, body).
fn get(url: &str) -> Result<(u16, Option<String>, Vec<u8>)> {
    let rest = url.strip_prefix("https://").context("only https")?;
    let (hostport, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse::<u16>().expect("checked")),
        _ => (hostport, 443),
    };
    if !host_ok(host) {
        bail!("not a public host name: {host:?}");
    }
    let mut tcp = None;
    let mut last = None;
    // a registry's redirect names the next server: only one on the internet (never this
    // host's network, whatever a Location header says)
    let addrs: Vec<_> = (host, port).to_socket_addrs().with_context(|| format!("resolving {host}"))?.filter(|a| public(a.ip())).collect();
    if addrs.is_empty() {
        bail!("{host} has no public address");
    }
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| anyhow!("connecting to {host}: {}", last.map_or("no address".into(), |e| e.to_string())))?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| anyhow!("{host}: {e}"))?;
    let conn = rustls::ClientConnection::new(client()?, name)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/rdap+json, application/json\r\nUser-Agent: logguard-web/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    tls.write_all(req.as_bytes()).with_context(|| format!("asking {host}"))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY + 64 * 1024 {
                    bail!("{host}: answer larger than 1 MB");
                }
            }
            // servers that close without TLS's goodbye: what came is the answer
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e).with_context(|| format!("reading {host}'s answer")),
        }
    }
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").with_context(|| format!("{host}: no HTTP answer"))?;
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut body = raw[end + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).context("no HTTP status")?;
    let header = |name: &str| {
        head.lines()
            .skip(1)
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
    };
    if header("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked")) {
        body = dechunk(&body).with_context(|| format!("{host}: a broken chunked answer"))?;
    } else if let Some(len) = header("content-length").and_then(|l| l.parse::<usize>().ok()) {
        body.truncate(len);
    }
    Ok((status, header("location"), body))
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n").context("no chunk size")?;
        let size = std::str::from_utf8(&b[..eol])?.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16)?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size || out.len() + size > MAX_BODY {
            bail!("chunk beyond the answer");
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
}

/// Asks rdap.org about `ip`, following it to the registry.
fn ask(ip: IpAddr) -> Result<Contact> {
    let mut url = format!("https://rdap.org/ip/{ip}");
    for _ in 0..=MAX_REDIRECTS {
        let (status, location, body) = get(&url)?;
        match status {
            200 => return parse(&String::from_utf8_lossy(&body)).context("not an RDAP answer"),
            301 | 302 | 303 | 307 | 308 => {
                let next = location.context("a redirect without a Location")?;
                if !next.starts_with("https://") {
                    bail!("redirected away from HTTPS: {}", next.chars().take(100).collect::<String>());
                }
                url = next;
            }
            404 => bail!("no registry knows {ip}"),
            429 => bail!("the registry asks to slow down (429): try again later"),
            s => bail!("the registry answered {s}"),
        }
    }
    bail!("more than {MAX_REDIRECTS} redirects")
}

/// Each address's answer, and when it came.
type Cache = HashMap<IpAddr, (Instant, Result<Contact, String>)>;

/// The console's lookups: one at a time, kept a day.
pub struct Rdap {
    pub enabled: bool,
    cache: Mutex<Cache>,
    /// The last request's time: one a second at most, as rdap.org asks.
    one: Mutex<Option<Instant>>,
}

impl Rdap {
    pub fn new(enabled: bool) -> Self {
        Rdap { enabled, cache: Mutex::default(), one: Mutex::default() }
    }

    pub fn lookup(&self, ip: IpAddr) -> Result<Contact, String> {
        if !self.enabled {
            return Err("this console doesn't look up (RDAP_LOOKUPS=off)".into());
        }
        if !public(ip) {
            return Err(format!("{ip} is not a public address"));
        }
        if let Some((at, r)) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&ip) {
            if at.elapsed() < if r.is_ok() { KEEP } else { KEEP_FAILED } {
                return r.clone();
            }
        }
        let r = {
            let mut one = self.one.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(wait) = one.map(|t| Duration::from_secs(1).saturating_sub(t.elapsed())) {
                std::thread::sleep(wait);
            }
            let r = ask(ip).map_err(|e| format!("{e:#}"));
            *one = Some(Instant::now());
            r
        };
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= CACHED {
            cache.retain(|_, (at, r)| at.elapsed() < if r.is_ok() { KEEP } else { KEEP_FAILED });
            if cache.len() >= CACHED {
                cache.clear();
            }
        }
        cache.insert(ip, (Instant::now(), r.clone()));
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abuse_contact() {
        let json = r#"{"handle":"NET-198-51-100-0-1","name":"EXAMPLE-NET",
            "entities":[{"roles":["registrant"],"entities":[{"roles":["abuse"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["email",{},"text","Abuse@Example.net"]]]}]}]}"#;
        let c = parse(json).unwrap();
        assert_eq!(c.abuse, ["abuse@example.net"]);
        assert_eq!(c.network, "EXAMPLE-NET, NET-198-51-100-0-1");
        // owner-written data: no line breaks or odd characters get through
        let evil = r#"{"name":"X\nTo: someone@else.example","entities":[{"roles":["abuse"],
            "vcardArray":["vcard",[["email",{},"text","a@b.example\nInjected text"],["email",{},"text","ok@isp.example"]]]}]}"#;
        let c = parse(evil).unwrap();
        assert_eq!(c.abuse, ["ok@isp.example"]);
        assert!(!c.network.contains('\n'));
        assert!(parse("not json").is_none());
    }

    #[test]
    fn chunked() {
        assert_eq!(dechunk(b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n").unwrap(), b"hello world");
        assert!(dechunk(b"ff\r\nshort\r\n").is_err());
        assert!(dechunk(b"zz\r\n").is_err());
    }

    #[test]
    fn only_public_addresses() {
        for a in ["10.1.2.3", "192.168.1.1", "127.0.0.1", "169.254.1.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "0.0.0.0"] {
            assert!(!public(a.parse().unwrap()), "{a}");
        }
        for a in ["8.8.8.8", "3fff:120::8888", "::ffff:8.8.8.8"] {
            assert!(public(a.parse().unwrap()), "{a}");
        }
        assert!(host_ok("rdap.arin.net") && host_ok("rdap.db.ripe.net"));
        for bad in ["", "10.0.0.1", "[::1]", "a b", "evil.example/x", &"a".repeat(300)] {
            assert!(!host_ok(bad), "{bad:?}");
        }
        assert!(get("https://10.0.0.1/ip/8.8.8.8").unwrap_err().to_string().contains("not a public host"));
        assert!(get("https://localhost/ip/8.8.8.8").unwrap_err().to_string().contains("no public address"));
        let off = Rdap::new(false);
        assert!(off.lookup("8.8.8.8".parse().unwrap()).unwrap_err().contains("RDAP_LOOKUPS=off"));
        assert!(Rdap::new(true).lookup("10.0.0.1".parse().unwrap()).unwrap_err().contains("not a public"));
    }
}
