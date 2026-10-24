//! OpenSSH (sshd / sshd-session) message parsing.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::event::{Event, Signal};
use crate::net::{parse_ip, parse_ip_port};
use crate::record::Record;
use crate::time::{Micros, MIN};

/// Remembers which TCP connections already produced an auth-failure event, so
/// the trailing "Connection closed by authenticating user" isn't double-counted.
#[derive(Default)]
pub struct SshParser {
    counted: HashMap<(IpAddr, u16), Micros>,
    /// sshd-session processes that authenticated someone. A close/reset from any other
    /// process is pre-authentication noise even without the `[preauth]` suffix
    /// (e.g. after `kex_exchange_identification` errors).
    authed_pids: HashMap<u32, Micros>,
    /// Addresses whose last attempt was refused by AllowUsers & co (that line has no port).
    not_allowed: HashMap<IpAddr, Micros>,
}

const MAX_AUTHED_PIDS: usize = 10_000;

/// Parses `<user> <ip> port <port>` at the end of a line, before an optional `[preauth]`
/// (user may be absent, e.g. "invalid user  1.2.3.4"). Read from the end: the user name is
/// the client's, may contain spaces, and so may look like an address and a port itself.
fn user_ip_port(s: &str) -> Option<(Option<&str>, IpAddr, Option<u16>)> {
    let s = s.trim_end();
    let s = s.strip_suffix("[preauth]").unwrap_or(s).trim_end();
    let (head, port) = s.rsplit_once(' ')?;
    let (head, word) = head.rsplit_once(' ')?;
    if word != "port" {
        return None;
    }
    let (user, ip) = head.rsplit_once(' ').map_or(("", head), |(u, ip)| (u.trim(), ip));
    Some(((!user.is_empty()).then_some(user), parse_ip(ip)?, port.parse().ok()))
}

/// Parses `<ip> port <port>` at the start of `s`: lines without a user name, where text the
/// client chose (a disconnect message) may follow.
fn ip_port_first(s: &str) -> Option<(IpAddr, Option<u16>)> {
    let mut it = s.split_whitespace();
    let ip = parse_ip(it.next()?)?;
    let port = match it.next() {
        Some("port") => it.next().and_then(|p| p.split(':').next()?.parse().ok()),
        _ => None,
    };
    Some((ip, port))
}

/// Parses `<user> from <ip> port <port>`.
fn user_from_ip(s: &str) -> Option<(&str, IpAddr, Option<u16>)> {
    let (user, rest) = s.rsplit_once(" from ")?;
    let mut it = rest.split_whitespace();
    let ip = parse_ip(it.next()?)?;
    let port = match it.next() {
        Some("port") => it.next().and_then(|p| p.parse().ok()),
        _ => None,
    };
    Some((user.split_whitespace().last().unwrap_or(user), ip, port))
}

impl SshParser {
    fn first_failure(&mut self, ip: IpAddr, port: Option<u16>, ts: Micros) -> bool {
        match port {
            Some(p) => self.counted.insert((ip, p), ts).is_none(),
            None => true,
        }
    }

    pub fn sweep(&mut self, now: Micros) {
        self.counted.retain(|_, ts| now - *ts < 10 * MIN);
        self.not_allowed.retain(|_, ts| now - *ts < 10 * MIN);
        if self.authed_pids.len() > MAX_AUTHED_PIDS {
            self.authed_pids.retain(|_, ts| now - *ts < 7 * 24 * 60 * MIN);
        }
    }

    pub fn feed(&mut self, rec: &Record, out: &mut Vec<Event>) {
        let ts = rec.ts;
        let m = rec.msg.trim();
        let m = m.strip_prefix("error: ").unwrap_or(m);
        let preauth = m.ends_with("[preauth]") || (rec.pid != 0 && !self.authed_pids.contains_key(&rec.pid));
        // Events carry no port: the one in these lines is the client's own (source) port, and
        // `Event::port` is the local one (a whitelisted port must not excuse a client that
        // merely connects from it). It still tells one connection's lines apart.
        let fail = |ip, user: Option<&str>, signal, detail: String| Event::new(ts, ip, signal).account(user).detail(detail);

        if let Some(rest) = m.strip_prefix("Accepted ") {
            // Accepted publickey for alice from 1.2.3.4 port 5555 ssh2: ED25519 SHA256:...
            let method = rest.split_whitespace().next().unwrap_or("?");
            if rec.pid != 0 {
                self.authed_pids.insert(rec.pid, ts);
            }
            // the key after "ssh2: " ("ED25519 SHA256:..."; a certificate adds its ID and CA),
            // read from the end: the user name is the client's
            let (head, key) = match rest.rsplit_once(" ssh2: ") {
                Some((h, k)) if method == "publickey" => (h, Some(k.split(" ID ").next().unwrap_or(k).trim())),
                _ => (rest.trim_end_matches(" ssh2"), None),
            };
            if let Some((user, ip, _)) = head.split_once(" for ").and_then(|(_, r)| user_from_ip(r)) {
                out.push(Event::new(ts, ip, Signal::SshAuthOk).account(Some(user)).detail(format!("accepted {method}")).key(key));
            }
        } else if let Some(rest) = m.strip_prefix("Failed ") {
            // Failed password for [invalid user ]root from 1.2.3.4 port 5555 ssh2
            let method = rest.split_whitespace().next().unwrap_or("?");
            if let Some((_, tail)) = rest.split_once(" for ") {
                if let Some((user, ip, port)) = user_from_ip(tail) {
                    let invalid = tail.starts_with("invalid user ");
                    self.first_failure(ip, port, ts);
                    let sig = if invalid { Signal::SshInvalidUser } else { Signal::SshAuthFail };
                    out.push(fail(ip, Some(user), sig, format!("failed {method} for {user}")));
                }
            }
        } else if let Some(rest) = m.strip_prefix("Invalid user ") {
            if let Some((user, ip, port)) = user_from_ip(rest) {
                self.first_failure(ip, port, ts);
                out.push(fail(ip, Some(user), Signal::SshInvalidUser, format!("invalid user {user}")));
            }
        } else if let Some(rest) = m.strip_prefix("User ").filter(|r| r.contains(" not allowed because ")) {
            // AllowUsers/DenyUsers/AllowGroups: "User root from 1.2.3.4 not allowed because not listed in AllowUsers".
            // No port here; sshd then treats the name as invalid and logs a "closed by invalid user" follow-up.
            if let Some(((user, ip, _), why)) =
                rest.rsplit_once(" not allowed because ").and_then(|(head, why)| Some((user_from_ip(head)?, why)))
            {
                self.not_allowed.insert(ip, ts);
                out.push(fail(ip, Some(user), Signal::SshInvalidUser, format!("user {user} not allowed ({why})")));
            }
        } else if let Some(rest) =
            m.strip_prefix("Connection closed by invalid user ").or_else(|| m.strip_prefix("Disconnected from invalid user "))
        {
            // Follow-up of "Invalid user" / "not allowed": counts only if neither was logged for this connection.
            if let Some((user, ip, port)) = user_ip_port(rest) {
                let after_not_allowed = self.not_allowed.remove(&ip).is_some_and(|t| ts - t < 10 * MIN);
                if self.first_failure(ip, port, ts) && !after_not_allowed {
                    let user = user.unwrap_or("?");
                    out.push(fail(ip, Some(user), Signal::SshInvalidUser, format!("invalid user {user}")));
                }
            }
        } else if let Some(rest) =
            m.strip_prefix("Connection closed by authenticating user ").or_else(|| m.strip_prefix("Disconnected from authenticating user "))
        {
            if let Some((user, ip, port)) = user_ip_port(rest) {
                if self.first_failure(ip, port, ts) {
                    let user = user.unwrap_or("?");
                    out.push(fail(ip, Some(user), Signal::SshAuthFail, format!("gave up authenticating as {user}")));
                }
            }
        } else if m.starts_with("maximum authentication attempts exceeded") || m.starts_with("Disconnecting authenticating user") {
            // "... for [invalid user ]alice from 1.2.3.4 port 5555 ssh2 [preauth]": from the end,
            // as the user name may contain " ssh2" too
            let line = m.strip_suffix("[preauth]").unwrap_or(m).trim_end();
            if let Some((user, ip, _)) = user_from_ip(line.strip_suffix(" ssh2").unwrap_or(line)) {
                out.push(fail(ip, Some(user), Signal::SshAuthFail, "max auth attempts exceeded".to_string()));
            }
        } else if let Some(rest) = m.strip_prefix("drop connection #") {
            // drop connection #0 from [1.2.3.4]:5555 on [5.6.7.8]:22 penalty: failed authentication
            if let Some((ip, _)) = rest.split_whitespace().nth(2).and_then(parse_ip_port) {
                let why = rest.split_once("penalty: ").map_or("", |(_, w)| w);
                out.push(Event::new(ts, ip, Signal::SshPenalty).detail(format!("sshd penalty: {why}")));
            }
        } else if let Some(rest) = m.strip_prefix("srclimit_penalise: ") {
            // srclimit_penalise: ipv4: new 1.2.3.4/32 deferred penalty of 10 seconds for reason: ...
            let addr = rest.split_whitespace().find(|w| w.contains('/')).and_then(|w| w.split('/').next());
            if let Some(ip) = addr.and_then(parse_ip) {
                out.push(Event::new(ts, ip, Signal::SshPenalty).detail("sshd source penalty"));
            }
        } else if let Some(rest) = ["Connection closed by ", "Connection reset by ", "Received disconnect from ", "Disconnected from "]
            .iter()
            .find_map(|p| m.strip_prefix(p))
            .filter(|_| preauth)
        {
            // The "authenticating user" / "invalid user" variants are handled above; here the
            // address comes first (what follows can be the client's disconnect message), and a
            // line naming a user ("Disconnected from user alice ...") is after a login.
            if let Some((ip, _)) = ip_port_first(rest) {
                out.push(Event::new(ts, ip, Signal::SshPreauth).detail("disconnected before authentication"));
            }
        } else if let Some(rest) = m.strip_prefix("Unable to negotiate with ") {
            if let Some(ip) = rest.split_whitespace().next().and_then(parse_ip) {
                out.push(Event::new(ts, ip, Signal::SshPreauth).detail("unable to negotiate"));
            }
        } else if let Some(rest) = m.strip_prefix("banner exchange: Connection from ") {
            if let Some(ip) = rest.split_whitespace().next().and_then(parse_ip) {
                out.push(Event::new(ts, ip, Signal::SshPreauth).detail("invalid banner"));
            }
        } else if let Some(rest) = m
            .strip_prefix("Did not receive identification string from ")
            .or_else(|| m.strip_prefix("Timeout before authentication for connection from "))
            .or_else(|| m.strip_prefix("Timeout before authentication for "))
        {
            if let Some(ip) = rest.split_whitespace().next().and_then(parse_ip) {
                out.push(Event::new(ts, ip, Signal::SshPreauth).detail("no identification / auth timeout"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Source;

    fn run(lines: &[&str]) -> Vec<Event> {
        let mut p = SshParser::default();
        let mut out = vec![];
        for l in lines {
            // pid 0 = unknown process: classification falls back to the `[preauth]` suffix
            let r = Record { ts: 0, source: Source::Ssh, pid: 0, msg: l.to_string(), cursor: None, sender: None };
            p.feed(&r, &mut out);
        }
        out
    }

    #[test]
    fn auth_lines() {
        let ev = run(&[
            "Accepted publickey for user6 from 11.33.48.86 port 50022 ssh2: ED25519 SHA256:abc",
            "Failed password for root from 1.2.3.4 port 40000 ssh2",
            "Connection closed by authenticating user root 1.2.3.4 port 40000 [preauth]",
            "Failed password for invalid user oracle from 1.2.3.5 port 40001 ssh2",
            "Invalid user admin from 1.2.3.6 port 40002",
            "Connection closed by invalid user admin 1.2.3.6 port 40002 [preauth]",
            "Connection closed by authenticating user ubuntu 1.2.3.7 port 40003 [preauth]",
        ]);
        let sigs: Vec<_> = ev.iter().map(|e| (e.signal, e.ip.to_string())).collect();
        assert_eq!(
            sigs,
            vec![
                (Signal::SshAuthOk, "11.33.48.86".into()),
                (Signal::SshAuthFail, "1.2.3.4".into()),
                (Signal::SshInvalidUser, "1.2.3.5".into()),
                (Signal::SshInvalidUser, "1.2.3.6".into()),
                (Signal::SshAuthFail, "1.2.3.7".into()),
            ]
        );
        assert_eq!(ev[0].account.as_deref(), Some("user6"));
        assert_eq!(ev[0].key.as_deref(), Some("ED25519 SHA256:abc"));
        assert_eq!(ev[2].account.as_deref(), Some("oracle"));
        let ev = run(&[
            "Accepted publickey for a b from 1.2.3.4 port 9 ssh2: x from 192.0.2.1 port 1 ssh2: RSA SHA256:real",
            "Accepted publickey for c from 1.2.3.5 port 9 ssh2: ED25519-CERT SHA256:cert ID c@x (serial 7) CA ED25519 SHA256:ca",
            "Accepted password for d from 1.2.3.6 port 9 ssh2",
        ]);
        let got: Vec<(String, Option<&str>)> = ev.iter().map(|e| (e.ip.to_string(), e.key.as_deref())).collect();
        assert_eq!(
            got,
            vec![
                ("192.0.2.1".into(), Some("RSA SHA256:real")),
                ("1.2.3.5".into(), Some("ED25519-CERT SHA256:cert")),
                ("1.2.3.6".into(), None)
            ],
            "a name with \" ssh2: \" in it can't choose the key; a password login has none"
        );
    }

    #[test]
    fn non_preauth_close_classified_by_session_pid() {
        let mut p = SshParser::default();
        let mut out = vec![];
        let mut feed = |pid: u32, msg: &str, out: &mut Vec<Event>| {
            p.feed(&Record { ts: 0, source: Source::Ssh, pid, msg: msg.into(), cursor: None, sender: None }, out)
        };
        feed(10, "error: kex_exchange_identification: read: Connection reset by peer", &mut out);
        feed(10, "Connection reset by 11.24.67.78 port 13822", &mut out);
        feed(11, "Connection closed by 11.8.51.54 port 1", &mut out);
        feed(12, "Accepted publickey for user6 from 11.33.48.86 port 50022 ssh2: ED25519 SHA256:x", &mut out);
        feed(12, "Connection closed by 11.33.48.86 port 50022", &mut out);
        let got: Vec<_> = out.iter().map(|e| (e.signal, e.ip.to_string())).collect();
        assert_eq!(
            got,
            vec![
                (Signal::SshPreauth, "11.24.67.78".into()),
                (Signal::SshPreauth, "11.8.51.54".into()),
                (Signal::SshAuthOk, "11.33.48.86".into()),
            ]
        );
    }

    #[test]
    fn preauth_noise_and_penalties() {
        let ev = run(&[
            "Connection closed by 9.9.9.1 port 1 [preauth]",
            "Received disconnect from 9.9.9.2 port 2:11: Bye Bye [preauth]",
            "Unable to negotiate with 9.9.9.3 port 3: no matching key exchange method found.",
            "banner exchange: Connection from 9.9.9.4 port 4: invalid format",
            "error: kex_exchange_identification: Connection closed by remote host",
            "Connection closed by 11.33.48.86 port 50022",
            "drop connection #0 from [9.9.9.5]:5 on [11.25.39.236]:9843 penalty: failed authentication",
            "srclimit_penalise: ipv4: new 9.9.9.6/32 deferred penalty of 10 seconds for reason: penalty: connections without attempting authentication",
        ]);
        let ips: Vec<_> = ev.iter().map(|e| e.ip.to_string()).collect();
        assert_eq!(ips, vec!["9.9.9.1", "9.9.9.2", "9.9.9.3", "9.9.9.4", "9.9.9.5", "9.9.9.6"]);
        assert_eq!(ev[4].signal, Signal::SshPenalty);
    }

    /// User names are the client's and may contain spaces: whatever they look like, the
    /// address is the connection's, and the port in these lines (the client's) isn't kept.
    #[test]
    fn user_names_never_choose_the_address() {
        let named = "a 192.0.2.99 port 1";
        let ev = run(&[
            &format!("Connection closed by invalid user {named} 198.51.100.7 port 40000 [preauth]"),
            &format!("Disconnected from invalid user {named} 198.51.100.8 port 40001 [preauth]"),
            &format!("Invalid user {named} from 198.51.100.9 port 40002"),
            "maximum authentication attempts exceeded for invalid user b from 192.0.2.99 port 1 ssh2 from 198.51.100.10 port 40003 ssh2 [preauth]",
            "Received disconnect from 198.51.100.11 port 40004:11: x 192.0.2.99 port 3 [preauth]",
            "User c from 192.0.2.99 not allowed because x from 198.51.100.12 not allowed because not listed in AllowUsers",
        ]);
        let ips: Vec<String> = ev.iter().map(|e| e.ip.to_string()).collect();
        assert_eq!(ips, ["198.51.100.7", "198.51.100.8", "198.51.100.9", "198.51.100.10", "198.51.100.11", "198.51.100.12"]);
        assert_eq!(ev[0].account.as_deref(), Some(named), "the whole name is the account");
        assert!(ev.iter().all(|e| e.port.is_none()), "no client port in Event::port (the local port)");
        // the same connection's follow-up still counts once
        let ev = run(&[
            "Invalid user oracle from 198.51.100.20 port 40010",
            "Connection closed by invalid user oracle 198.51.100.20 port 40010 [preauth]",
        ]);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn allow_users_refusals_count_once() {
        let ev = run(&[
            "User root from 11.10.2.3 not allowed because not listed in AllowUsers",
            "Connection closed by invalid user root 11.10.2.3 port 40000 [preauth]",
            "Invalid user oracle from 11.10.2.4 port 40001",
            "Connection closed by invalid user oracle 11.10.2.4 port 40001 [preauth]",
            "Connection closed by invalid user admin 11.10.2.5 port 40002 [preauth]",
        ]);
        let got: Vec<(String, Option<&str>)> = ev.iter().map(|e| (e.ip.to_string(), e.account.as_deref())).collect();
        assert_eq!(
            got,
            vec![("11.10.2.3".into(), Some("root")), ("11.10.2.4".into(), Some("oracle")), ("11.10.2.5".into(), Some("admin"))]
        );
        assert!(ev.iter().all(|e| e.signal == Signal::SshInvalidUser));
        assert_eq!(ev[0].detail, "user root not allowed (not listed in AllowUsers)");
    }
}
