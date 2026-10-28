//! ejabberd log parsing with connection correlation.
//!
//! ejabberd logs `(#PID<0.N.0>) Accepted connection [ip]:port -> [ip]:port` and
//! every later line of that connection carries the same Erlang process id, e.g.
//! `(tls|<0.N.0>) Failed to secure c2s connection`. Tracking that id lets us
//! attribute TLS failures, auth results and silent connections to the source IP.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::event::{Event, Signal};
use crate::net::{parse_ip, parse_ip_port};
use crate::record::Record;
use crate::time::{self, Micros};

/// Inbound s2s close reasons that indicate a scanner or bogus peer rather
/// than a real federating server.
const BAD_S2S_MARKERS: &[&str] = &[
    "not well-formed",
    "not-well-formed",
    "syntax error",
    "invalid-namespace",
    "host-unknown",
    "invalid-from",
    "improper-addressing",
    "policy-violation",
    "bad-format",
    "unsupported-stanza-type",
];

const MAX_TRACKED_CONNECTIONS: usize = 50_000;

/// An operational event without a remote address (certificates, ACME), turned into an
/// admin alert by the pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct OpsNote {
    pub key: String,
    pub severity: crate::engine::Severity,
    pub message: String,
    /// A freshly stored certificate (for computing its DANE TLSA record).
    pub new_cert: Option<String>,
}

#[derive(Debug)]
struct Conn {
    ip: IpAddr,
    port: u16,
    opened: Micros,
    resolved: bool,
}

pub struct EjabberdParser {
    c2s_ports: Vec<u16>,
    noauth_grace: Micros,
    conns: HashMap<String, Conn>,
    os_pid: u32,
    pub unattributed: u64,
    /// Lines where ejabberd replaced the client address with `hidden_by_ejabberd`
    /// (`hide_sensitive_log_data: true`), which blinds IP-based detection.
    pub hidden: u64,
    pub ops: Vec<OpsNote>,
}

/// Splits `2026-08-16 21:20:19.107 [info] (tls|<0.1.0>) text` into (erlang pid, text).
fn split_message(msg: &str) -> (Option<&str>, &str) {
    let mut rest = msg;
    if let Some((_, used)) = time::parse_iso_prefix(rest) {
        rest = rest[used..].trim_start();
    }
    if rest.starts_with('[') {
        if let Some(end) = rest.find("] ") {
            rest = &rest[end + 2..];
        }
    }
    let mut pid = None;
    if rest.starts_with('(') {
        if let Some(end) = rest.find(") ") {
            let ctx = &rest[1..end];
            pid = ctx.find('<').and_then(|a| ctx[a + 1..].find('>').map(|b| &ctx[a + 1..a + 1 + b]));
            rest = &rest[end + 2..];
        }
    }
    (pid, rest)
}

/// Returns the IP after the last ` from ` in `s` (ejabberd writes `::ffff:1.2.3.4`).
fn ip_after_from(s: &str) -> Option<IpAddr> {
    let tail = &s[s.rfind(" from ")? + 6..];
    // "from ::ffff:1.2.3.4: reason" - addresses contain ':' but never ": "
    let token = tail.split(": ").next()?.split_whitespace().next()?;
    parse_ip(token)
}

fn jid_after(s: &str, marker: &str) -> Option<String> {
    let tail = &s[s.find(marker)? + marker.len()..];
    let jid = tail.split_whitespace().next()?;
    Some(jid.split('/').next().unwrap_or(jid).trim_end_matches(':').to_string())
}

impl EjabberdParser {
    pub fn new(c2s_ports: Vec<u16>, noauth_grace: Micros) -> Self {
        EjabberdParser { c2s_ports, noauth_grace, conns: HashMap::new(), os_pid: 0, unattributed: 0, hidden: 0, ops: Vec::new() }
    }

    pub fn tracked(&self) -> usize {
        self.conns.len()
    }

    fn resolve(&mut self, pid: Option<&str>) -> Option<(IpAddr, u16)> {
        let conn = self.conns.get_mut(pid?)?;
        conn.resolved = true;
        Some((conn.ip, conn.port))
    }

    pub fn feed(&mut self, rec: &Record, out: &mut Vec<Event>) {
        if rec.pid != 0 && rec.pid != self.os_pid {
            // ejabberd restarted: Erlang process ids are reused, forget them.
            self.conns.clear();
            self.os_pid = rec.pid;
        }
        let ts = rec.ts;
        let (pid, text) = split_message(&rec.msg);
        if text.contains("hidden_by_ejabberd") && (text.starts_with("Accepted") || text.starts_with("Failed c2s")) {
            self.hidden += 1;
            return;
        }

        if let Some(rest) = text.strip_prefix("Accepted connection ") {
            let mut parts = rest.split(" -> ");
            let src = parts.next().and_then(parse_ip_port);
            let dst_port = parts.next().and_then(parse_ip_port).and_then(|(_, p)| p);
            let Some((ip, _)) = src else { return };
            let port = dst_port.unwrap_or(0);
            if self.c2s_ports.contains(&port) {
                if let Some(pid) = pid {
                    if self.conns.len() >= MAX_TRACKED_CONNECTIONS {
                        self.sweep(ts, out);
                    }
                    self.conns.insert(pid.to_string(), Conn { ip, port, opened: ts, resolved: false });
                }
            } else {
                out.push(Event::new(ts, ip, Signal::XmppConn).port(Some(port)).detail(format!("connection to port {port}")));
            }
        } else if text.starts_with("Accepted c2s ") {
            let conn = self.resolve(pid);
            let logged = ip_after_from(text);
            if let (Some(c), Some(l)) = (conn, logged) {
                if c.0 != l {
                    // The connection came from elsewhere than the line claims: a forged line
                    // (e.g. injected through a multi-line log message) must not earn trust.
                    self.unattributed += 1;
                    return;
                }
            }
            let ip = logged.or(conn.map(|c| c.0));
            let port = conn.map(|c| c.1);
            let jid = jid_after(text, "authentication for ");
            // Only a connection seen opening on a client port proves where a login came from.
            // One naming any other process (a web client over BOSH or WebSocket, or a line
            // injected through a multi-line log message) counts for its account, not as trust.
            match ip {
                Some(ip) => out.push(
                    Event::new(ts, ip, Signal::XmppAuthOk)
                        .port(port)
                        .account(jid.as_deref())
                        .detail("c2s authentication accepted")
                        .verified(conn.is_some()),
                ),
                None => self.unattributed += 1,
            }
        } else if text.starts_with("Failed c2s ") {
            let conn = self.resolve(pid);
            let ip = ip_after_from(text).or(conn.map(|c| c.0));
            let jid = jid_after(text, "authentication for ");
            let reason = text.rsplit(": ").next().unwrap_or("");
            match ip {
                Some(ip) => out.push(
                    Event::new(ts, ip, if is_token_mech(text) { Signal::XmppTokenFail } else { Signal::XmppAuthFail })
                        .port(conn.map(|c| c.1))
                        .account(jid.as_deref())
                        .detail(format!("auth failed: {reason}")),
                ),
                None => self.unattributed += 1,
            }
        } else if let Some(reason) = text.strip_prefix("Failed to secure c2s connection: ") {
            match self.resolve(pid) {
                Some((ip, port)) => out.push(Event::new(ts, ip, Signal::XmppTlsFail).port(Some(port)).detail(short_tls_reason(reason))),
                None => self.unattributed += 1,
            }
        } else if let Some(rest) = text.strip_prefix("Closing inbound s2s connection ") {
            let ip = rest.split_whitespace().next().and_then(parse_ip);
            let reason = rest.split_once(": ").map_or("", |(_, r)| r);
            if let Some(ip) = ip {
                if BAD_S2S_MARKERS.iter().any(|m| reason.contains(m)) {
                    out.push(Event::new(ts, ip, Signal::XmppS2sBad).port(Some(5269)).detail(format!("s2s rejected: {reason}")));
                }
            }
        } else if let Some(rest) = text.strip_prefix("The account ") {
            // The account azerty@example.org was registered from IP address ::ffff:11.46.43.85
            if let Some((jid, ip)) = rest.split_once(" was registered from IP address ") {
                if let Some(ip) = parse_ip(ip.trim()) {
                    out.push(Event::new(ts, ip, Signal::XmppRegister).account(Some(jid)).detail(format!("registered account {jid}")));
                }
            }
        } else if let Some(rest) = text.strip_prefix("Storing certificate for ") {
            // Storing certificate for example.org, conference.example.org and 2 more hosts in /opt/.../acme/live/f415...
            if let Some((hosts, path)) = rest.rsplit_once(" in ") {
                self.ops.push(OpsNote {
                    key: format!("cert-stored:{path}"),
                    severity: crate::engine::Severity::Info,
                    message: format!("certificate renewed for {hosts}: {path}"),
                    new_cert: Some(path.to_string()),
                });
            }
        } else if let Some(rest) = text.strip_prefix("Certificate in ") {
            // Certificate in /opt/.../879798... (at line: 1) for conference.example.org, ... will expire in a week
            let path = rest.split(" (at line").next().unwrap_or(rest);
            let tail = rest.split_once(" for ").map_or("", |(_, t)| t);
            let (hosts, when) = ["will expire", "has expired", "is expired"]
                .iter()
                .find_map(|w| tail.find(w).map(|i| (&tail[..i], &tail[i..])))
                .unwrap_or((tail, ""));
            if !when.is_empty() {
                use crate::engine::Severity::*;
                let severity = if when.starts_with("will expire in a week") || when.contains("days") { Warning } else { High };
                self.ops.push(OpsNote {
                    key: format!("cert-expiry:{path}"),
                    severity,
                    message: format!("ejabberd: certificate {path} for {} {when}", hosts.trim()),
                    new_cert: None,
                });
            }
        } else if let Some(rest) = text.strip_prefix("Failed to request certificate for ") {
            // ...: Challenge failed for domain proxy.example.org: ACME server reported: IP: Fetching URL: remote error: ... (error type: tls)
            let domain = rest.split("Challenge failed for domain ").nth(1).and_then(|d| d.split(':').next()).unwrap_or("?");
            let fetched = rest.split("Fetching ").nth(1).and_then(|f| f.split(':').next().zip(f.split_once(": ").map(|x| x.1)));
            let reason = rest.rsplit(": ").next().unwrap_or(rest);
            let detail = match fetched {
                Some(("https", _)) => {
                    "Let's Encrypt was redirected to https and the TLS handshake failed: port 80 must reach ejabberd's acme handler without redirecting".to_string()
                }
                _ if reason.contains("Connection refused") || reason.contains("connection") => {
                    "nothing answered on port 80: Let's Encrypt must reach ejabberd's acme handler there".to_string()
                }
                _ => reason.to_string(),
            };
            self.ops.push(OpsNote {
                key: format!("acme-failed:{domain}"),
                severity: crate::engine::Severity::Warning,
                message: format!("ACME renewal failed for {domain}: {detail}"),
                new_cert: None,
            });
        } else if let Some(rest) = text.strip_prefix("Cannot serve ") {
            if let Some(ip) = rest.rsplit_once(" to ").and_then(|(_, t)| t.split(": ").next()).and_then(parse_ip) {
                out.push(Event::new(ts, ip, Signal::XmppHttpMiss).detail("upload request for missing file"));
            }
        } else if text.starts_with("Opened c2s session")
            || text.starts_with("Resumed session")
            || text.starts_with("Closing c2s")
            || text.starts_with("Enabling push")
            || text.starts_with("Offering STUN")
        {
            // Session activity: the connection got past authentication.
            if let Some(pid) = pid {
                if text.starts_with("Closing c2s") {
                    self.conns.remove(pid);
                } else {
                    self.resolve(Some(pid));
                }
            }
        }
    }

    /// Emits `XmppNoAuth` for client connections that stayed silent past the grace period.
    pub fn sweep(&mut self, now: Micros, out: &mut Vec<Event>) {
        let grace = self.noauth_grace;
        self.conns.retain(|_, c| {
            if now - c.opened < grace {
                return true;
            }
            if !c.resolved {
                out.push(
                    Event::new(c.opened, c.ip, Signal::XmppNoAuth)
                        .port(Some(c.port))
                        .detail(format!("port {} connection without authentication", c.port)),
                );
            }
            false
        });
    }
}

/// FAST tokens (XEP-0484) use `HT-*` SASL mechanisms; a rejection means an expired token.
fn is_token_mech(text: &str) -> bool {
    text.split_whitespace().nth(2).is_some_and(|m| m.starts_with("HT-"))
}

fn short_tls_reason(reason: &str) -> String {
    // "TLS failed: SSL_do_handshake failed: error:0A000102:SSL routines::unsupported protocol"
    let r = reason.rsplit("::").next().unwrap_or(reason);
    format!("TLS failed: {}", r.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Source;

    fn rec(ts_s: i64, msg: &str) -> Record {
        Record { ts: ts_s * time::SEC, source: Source::Ejabberd, pid: 1, msg: msg.to_string(), cursor: None, sender: None }
    }

    fn parser() -> EjabberdParser {
        EjabberdParser::new(vec![5222, 5223], 90 * time::SEC)
    }

    #[test]
    fn tls_failure_attributed_by_pid_not_by_previous_line() {
        let mut p = parser();
        let mut out = vec![];
        p.feed(&rec(0, "2026-08-16 21:53:54.665 [info] (#PID<0.10.0>) Accepted connection [::ffff:11.57.40.218]:38436 -> [::ffff:11.29.39.236]:5223"), &mut out);
        p.feed(
            &rec(
                0,
                "2026-08-16 21:53:54.666 [info] (#PID<0.11.0>) Accepted connection [::ffff:11.48.43.31]:1 -> [::ffff:11.29.39.236]:5223",
            ),
            &mut out,
        );
        p.feed(&rec(1, "2026-08-16 21:53:54.700 [info] (tls|<0.10.0>) Failed to secure c2s connection: TLS failed: SSL_do_handshake failed: error:0A000102:SSL routines::unsupported protocol"), &mut out);
        p.feed(&rec(1, "2026-08-16 21:53:55.000 [info] (tls|<0.11.0>) Accepted c2s SCRAM-SHA-512-PLUS authentication for user2@example.org by mnesia backend from ::ffff:11.48.43.31"), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].signal, Signal::XmppTlsFail);
        assert_eq!(out[0].ip.to_string(), "11.57.40.218");
        assert_eq!(out[0].detail, "TLS failed: unsupported protocol");
        assert_eq!(out[1].signal, Signal::XmppAuthOk);
        assert_eq!(out[1].account.as_deref(), Some("user2@example.org"));
        assert!(out[1].verified, "its connection was seen opening");
        // a login naming a process no client connection was seen for: counted, not verified
        let mut other = vec![];
        p.feed(&rec(2, "2026-08-16 21:53:56.000 [info] (tls|<0.99.0>) Accepted c2s PLAIN authentication for x@example.org by mnesia backend from ::ffff:198.51.100.5"), &mut other);
        assert_eq!((other[0].signal, other[0].verified), (Signal::XmppAuthOk, false));
        out.clear();
        p.sweep(200 * time::SEC, &mut out);
        assert!(out.is_empty(), "resolved connections must not count as silent");
    }

    #[test]
    fn silent_client_connection_and_other_ports() {
        let mut p = parser();
        let mut out = vec![];
        p.feed(&rec(0, "2026-08-21 22:17:26.048 [info] (#PID<0.2334.0>) Accepted connection [::ffff:11.47.253.221]:64606 -> [::ffff:11.29.39.236]:5222"), &mut out);
        p.feed(&rec(0, "2026-08-21 22:17:27.481 [info] (#PID<0.2336.0>) Accepted connection [::ffff:11.47.253.221]:23136 -> [::ffff:11.29.39.236]:5269"), &mut out);
        p.feed(
            &rec(0, "2026-08-16 21:36:25.361 [info] (#PID<0.28907.0>) Accepted connection 11.20.79.110:50735 -> 11.29.39.236:5349"),
            &mut out,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].port, Some(5269));
        assert_eq!(out[1].ip.to_string(), "11.20.79.110");
        out.clear();
        p.sweep(30 * time::SEC, &mut out);
        assert!(out.is_empty());
        p.sweep(91 * time::SEC, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].signal, Signal::XmppNoAuth);
        assert_eq!(p.tracked(), 0);
    }

    #[test]
    fn failed_auth_and_s2s() {
        let mut p = parser();
        let mut out = vec![];
        p.feed(&rec(0, "2026-08-16 21:00:00.000 [info] (tls|<0.5.0>) Failed c2s PLAIN authentication for admin@example.org from ::ffff:9.9.9.9: Invalid username or password"), &mut out);
        p.feed(&rec(0, "2026-08-16 21:35:11.121 [info] Closing inbound s2s connection ::ffff:11.25.26.161 -> example.org: Stream closed by local host: not well-formed (invalid token) (not-well-formed)"), &mut out);
        p.feed(&rec(0, "2026-08-16 21:35:11.121 [info] Closing inbound s2s connection ::ffff:5.5.5.5 -> example.org: Connection failed: connection closed"), &mut out);
        p.feed(
            &rec(0, "2026-08-22 08:56:37.094 [warning] Cannot serve /opt/ejabberd/upload/x/y.jpg to ::ffff:11.43.11.41: No such file"),
            &mut out,
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].signal, Signal::XmppAuthFail);
        assert_eq!(out[0].ip.to_string(), "9.9.9.9");
        assert_eq!(out[0].account.as_deref(), Some("admin@example.org"));
        assert_eq!(out[1].signal, Signal::XmppS2sBad);
        assert_eq!(out[2].signal, Signal::XmppHttpMiss);
    }

    #[test]
    fn month_sample_formats() {
        let mut p = parser();
        let mut out = vec![];
        p.feed(&rec(0, "2026-09-18 15:05:55.227 [warning] (tls|<0.15027.0>) Failed c2s HT-SHA-256-EXPR authentication for user5@example.org from ::ffff:11.40.62.53: Invalid username or password"), &mut out);
        p.feed(
            &rec(0, "2026-09-13 22:36:29.090 [info] The account azerty@example.org was registered from IP address ::ffff:11.46.43.85"),
            &mut out,
        );
        p.feed(
            &rec(0, "2026-09-30 10:00:00.000 [info] (#PID<0.9.0>) Accepted connection hidden_by_ejabberd -> [::ffff:11.29.39.236]:5223"),
            &mut out,
        );
        p.feed(&rec(0, "2026-09-30 10:00:00.100 [info] (tls|<0.9.0>) Accepted c2s HT-SHA-256-EXPR authentication for a@b by mod_auth_fast backend from hidden_by_ejabberd"), &mut out);
        let sigs: Vec<_> = out.iter().map(|e| e.signal).collect();
        assert_eq!(sigs, vec![Signal::XmppTokenFail, Signal::XmppRegister]);
        assert_eq!(out[1].account.as_deref(), Some("azerty@example.org"));
        assert_eq!(p.hidden, 2);
        assert_eq!(p.tracked(), 0);
    }

    #[test]
    fn certificate_events() {
        use crate::engine::Severity;
        let mut p = parser();
        let mut out = vec![];
        p.feed(&rec(0, "2026-10-02 18:12:42.758 [debug] Storing certificate for example.org, conference.example.org and 2 more hosts in /opt/ejabberd/database/ejabberd@localhost/acme/live/f4156bc5a417a6ae18b62e365480e05a42159a2f"), &mut out);
        p.feed(&rec(0, "2026-10-10 01:43:43.687 [warning] Certificate in /opt/ejabberd/database/ejabberd@localhost/acme/live/879798eeaf32b7f23c095b37ac02e426393e2f4f (at line: 1) for conference.example.org, example.org and 3 more hosts will expire in a week"), &mut out);
        p.feed(&rec(0, "2026-10-10 01:43:45.000 [error] Failed to request certificate for conference.example.org, example.org and 3 more hosts: Challenge failed for domain proxy.example.org: ACME server reported: 11.29.39.236: Fetching https://proxy.example.org/.well-known/acme-challenge/Gah: remote error: tls: internal error (error type: tls)"), &mut out);
        p.feed(&rec(0, "2026-10-02 17:56:25.257 [error] Failed to request certificate for example.org: Challenge failed for domain conference.example.org: ACME server reported: 11.29.39.236: Fetching http://conference.example.org/.well-known/acme-challenge/4cl: Connection refused (error type: connection)"), &mut out);
        assert!(out.is_empty(), "no address events");
        assert_eq!(p.ops.len(), 4);
        assert_eq!(
            p.ops[0].new_cert.as_deref(),
            Some("/opt/ejabberd/database/ejabberd@localhost/acme/live/f4156bc5a417a6ae18b62e365480e05a42159a2f")
        );
        assert!(p.ops[0].message.starts_with("certificate renewed for example.org, conference.example.org and 2 more hosts"));
        assert_eq!(p.ops[1].severity, Severity::Warning);
        assert!(
            p.ops[1].message.ends_with("for conference.example.org, example.org and 3 more hosts will expire in a week"),
            "{}",
            p.ops[1].message
        );
        assert!(
            p.ops[2].message.starts_with("ACME renewal failed for proxy.example.org: Let's Encrypt was redirected to https"),
            "{}",
            p.ops[2].message
        );
        assert!(p.ops[3].message.contains("nothing answered on port 80"), "{}", p.ops[3].message);
    }

    #[test]
    fn restart_forgets_erlang_pids() {
        let mut p = parser();
        let mut out = vec![];
        p.feed(
            &rec(0, "2026-08-16 21:00:00.000 [info] (#PID<0.5.0>) Accepted connection [::ffff:1.1.1.1]:1 -> [::ffff:2.2.2.2]:5223"),
            &mut out,
        );
        let mut r = rec(1, "2026-08-16 21:00:01.000 [info] (tls|<0.5.0>) Failed to secure c2s connection: TLS failed: x");
        r.pid = 2;
        p.feed(&r, &mut out);
        assert!(out.is_empty());
        assert_eq!(p.unattributed, 1);
    }
}
