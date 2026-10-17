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

/// Parses `<user> <ip> port <port>` (user may be absent, e.g. "invalid user  1.2.3.4").
fn user_ip_port(s: &str) -> Option<(Option<&str>, IpAddr, Option<u16>)> {
    let words: Vec<&str> = s.split_whitespace().collect();
    let pos = words.iter().position(|w| *w == "port")?;
    let ip = parse_ip(words.get(pos.checked_sub(1)?)?)?;
    let user = if pos >= 2 { Some(words[pos - 2]) } else { None };
    let port = words.get(pos + 1).and_then(|p| p.trim_end_matches(':').parse().ok());
    Some((user, ip, port))
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
        let fail =
            |ip, port, user: Option<&str>, signal, detail: String| Event::new(ts, ip, signal).port(port).account(user).detail(detail);

        if let Some(rest) = m.strip_prefix("Accepted ") {
            // Accepted publickey for alice from 1.2.3.4 port 5555 ssh2: ED25519 SHA256:...
            let method = rest.split_whitespace().next().unwrap_or("?");
            if rec.pid != 0 {
                self.authed_pids.insert(rec.pid, ts);
            }
            if let Some((user, ip, port)) = rest.split_once(" for ").and_then(|(_, r)| user_from_ip(r)) {
                out.push(Event::new(ts, ip, Signal::SshAuthOk).port(port).account(Some(user)).detail(format!("accepted {method}")));
            }
        } else if let Some(rest) = m.strip_prefix("Failed ") {
            // Failed password for [invalid user ]root from 1.2.3.4 port 5555 ssh2
            let method = rest.split_whitespace().next().unwrap_or("?");
            if let Some((_, tail)) = rest.split_once(" for ") {
                if let Some((user, ip, port)) = user_from_ip(tail) {
                    let invalid = tail.starts_with("invalid user ");
                    self.first_failure(ip, port, ts);
                    let sig = if invalid { Signal::SshInvalidUser } else { Signal::SshAuthFail };
                    out.push(fail(ip, port, Some(user), sig, format!("failed {method} for {user}")));
                }
            }
        } else if let Some(rest) = m.strip_prefix("Invalid user ") {
            if let Some((user, ip, port)) = user_from_ip(rest) {
                self.first_failure(ip, port, ts);
                out.push(fail(ip, port, Some(user), Signal::SshInvalidUser, format!("invalid user {user}")));
            }
        } else if let Some(rest) = m.strip_prefix("User ").filter(|r| r.contains(" not allowed because ")) {
            // AllowUsers/DenyUsers/AllowGroups: "User root from 1.2.3.4 not allowed because not listed in AllowUsers".
            // No port here; sshd then treats the name as invalid and logs a "closed by invalid user" follow-up.
            if let Some((user, ip, _)) = rest.split_once(" not allowed").and_then(|(head, _)| user_from_ip(head)) {
                self.not_allowed.insert(ip, ts);
                let why = rest.split_once(" because ").map_or("", |(_, w)| w);
                out.push(fail(ip, None, Some(user), Signal::SshInvalidUser, format!("user {user} not allowed ({why})")));
            }
        } else if let Some(rest) =
            m.strip_prefix("Connection closed by invalid user ").or_else(|| m.strip_prefix("Disconnected from invalid user "))
        {
            // Follow-up of "Invalid user" / "not allowed": counts only if neither was logged for this connection.
            if let Some((user, ip, port)) = user_ip_port(rest) {
                let after_not_allowed = self.not_allowed.remove(&ip).is_some_and(|t| ts - t < 10 * MIN);
                if self.first_failure(ip, port, ts) && !after_not_allowed {
                    let user = user.unwrap_or("?");
                    out.push(fail(ip, port, Some(user), Signal::SshInvalidUser, format!("invalid user {user}")));
                }
            }
        } else if let Some(rest) =
            m.strip_prefix("Connection closed by authenticating user ").or_else(|| m.strip_prefix("Disconnected from authenticating user "))
        {
            if let Some((user, ip, port)) = user_ip_port(rest) {
                if self.first_failure(ip, port, ts) {
                    let user = user.unwrap_or("?");
                    out.push(fail(ip, port, Some(user), Signal::SshAuthFail, format!("gave up authenticating as {user}")));
                }
            }
        } else if m.starts_with("maximum authentication attempts exceeded") || m.starts_with("Disconnecting authenticating user") {
            if let Some((user, ip, port)) = user_from_ip(m.split(" ssh2").next().unwrap_or(m)) {
                out.push(fail(ip, port, Some(user), Signal::SshAuthFail, "max auth attempts exceeded".to_string()));
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
        } else if preauth
            && (m.starts_with("Connection closed by ")
                || m.starts_with("Connection reset by ")
                || m.starts_with("Received disconnect from ")
                || m.starts_with("Disconnected from "))
        {
            // Not "authenticating user" / "invalid user" variants: handled above or follow-ups.
            if m.contains(" invalid user ") {
                return;
            }
            if let Some((_, ip, port)) = user_ip_port(m) {
                out.push(Event::new(ts, ip, Signal::SshPreauth).port(port).detail("disconnected before authentication"));
            } else if let Some(ip) = m.split_whitespace().nth(3).and_then(parse_ip) {
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
            let r = Record { ts: 0, source: Source::Ssh, pid: 0, msg: l.to_string(), cursor: None };
            p.feed(&r, &mut out);
        }
        out
    }

    #[test]
    fn auth_lines() {
        let ev = run(&[
            "Accepted publickey for user6 from 11.25.48.86 port 50022 ssh2: ED25519 SHA256:abc",
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
                (Signal::SshAuthOk, "11.25.48.86".into()),
                (Signal::SshAuthFail, "1.2.3.4".into()),
                (Signal::SshInvalidUser, "1.2.3.5".into()),
                (Signal::SshInvalidUser, "1.2.3.6".into()),
                (Signal::SshAuthFail, "1.2.3.7".into()),
            ]
        );
        assert_eq!(ev[0].account.as_deref(), Some("user6"));
        assert_eq!(ev[2].account.as_deref(), Some("oracle"));
    }

    #[test]
    fn non_preauth_close_classified_by_session_pid() {
        let mut p = SshParser::default();
        let mut out = vec![];
        let mut feed = |pid: u32, msg: &str, out: &mut Vec<Event>| {
            p.feed(&Record { ts: 0, source: Source::Ssh, pid, msg: msg.into(), cursor: None }, out)
        };
        feed(10, "error: kex_exchange_identification: read: Connection reset by peer", &mut out);
        feed(10, "Connection reset by 11.16.67.78 port 13822", &mut out);
        feed(11, "Connection closed by 11.7.51.54 port 1", &mut out);
        feed(12, "Accepted publickey for user6 from 11.25.48.86 port 50022 ssh2: ED25519 SHA256:x", &mut out);
        feed(12, "Connection closed by 11.25.48.86 port 50022", &mut out);
        let got: Vec<_> = out.iter().map(|e| (e.signal, e.ip.to_string())).collect();
        assert_eq!(
            got,
            vec![
                (Signal::SshPreauth, "11.16.67.78".into()),
                (Signal::SshPreauth, "11.7.51.54".into()),
                (Signal::SshAuthOk, "11.25.48.86".into()),
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
            "Connection closed by 11.25.48.86 port 50022",
            "drop connection #0 from [9.9.9.5]:5 on [11.17.39.236]:9843 penalty: failed authentication",
            "srclimit_penalise: ipv4: new 9.9.9.6/32 deferred penalty of 10 seconds for reason: penalty: connections without attempting authentication",
        ]);
        let ips: Vec<_> = ev.iter().map(|e| e.ip.to_string()).collect();
        assert_eq!(ips, vec!["9.9.9.1", "9.9.9.2", "9.9.9.3", "9.9.9.4", "9.9.9.5", "9.9.9.6"]);
        assert_eq!(ev[4].signal, Signal::SshPenalty);
    }

    #[test]
    fn allow_users_refusals_count_once() {
        let ev = run(&[
            "User root from 11.8.2.3 not allowed because not listed in AllowUsers",
            "Connection closed by invalid user root 11.8.2.3 port 40000 [preauth]",
            "Invalid user oracle from 11.8.2.4 port 40001",
            "Connection closed by invalid user oracle 11.8.2.4 port 40001 [preauth]",
            "Connection closed by invalid user admin 11.8.2.5 port 40002 [preauth]",
        ]);
        let got: Vec<(String, Option<&str>)> = ev.iter().map(|e| (e.ip.to_string(), e.account.as_deref())).collect();
        assert_eq!(got, vec![("11.8.2.3".into(), Some("root")), ("11.8.2.4".into(), Some("oracle")), ("11.8.2.5".into(), Some("admin"))]);
        assert!(ev.iter().all(|e| e.signal == Signal::SshInvalidUser));
        assert_eq!(ev[0].detail, "user root not allowed (not listed in AllowUsers)");
    }
}
