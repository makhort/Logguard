//! Optional here (`SANITIZE=on`), as [`crate::redact`]: with it on, the servers' own
//! addresses and host names don't reach the mailbox, as on Telegram (logguard-tg-bot's code).
//!
//! The servers' own addresses and host names never reach Telegram: each becomes the
//! server's node id, as logguard names it (`[xmpp]`, `[vpn]`, `[tg]`). logguard's messages
//! carry them in certificate targets (`example.org:5223`), cluster warnings (`peer
//! 11.29.39.236:7946 failing`), exposure alerts and log lines.
//!
//! `SERVER_NAMES` lists them: `xmpp=11.29.39.236,2001:db8::1,example.org; vpn=11.38.48.86`.
//! An address matches exactly (IPv4-mapped IPv6 too, with or without a port after it); a host
//! name matches with its subdomains, which keep their first labels:
//! `nextcloud.example.org:443` becomes `nextcloud.xmpp:443`. Attackers' addresses, the
//! point of the alerts, stay as they are.

use std::net::IpAddr;

#[derive(Debug, Default)]
pub struct ServerNames {
    addrs: Vec<(IpAddr, String)>,
    /// (lower-case name, node), longest names first.
    hosts: Vec<(String, String)>,
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

impl ServerNames {
    pub fn parse(spec: &str) -> Result<ServerNames, String> {
        let mut s = ServerNames::default();
        for entry in spec.split([';', '\n']).map(str::trim).filter(|e| !e.is_empty()) {
            let (node, items) = entry.split_once('=').ok_or_else(|| format!("'{entry}': expected <node>=<address or name>,..."))?;
            let node = node.trim();
            if node.is_empty() || !node.chars().all(host_char) {
                return Err(format!("'{node}' is not a node id (letters, digits, - and _)"));
            }
            // it takes the place of addresses: hex digits only ("0", "cafe") would join the
            // colons and digits around it into a new address-like run
            if node.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("'{node}': a node id needs a letter other than a to f"));
            }
            for item in items.split([',', ' ']).map(str::trim).filter(|i| !i.is_empty()) {
                if let Ok(ip) = item.trim_matches(['[', ']']).parse::<IpAddr>() {
                    let ip = normalize(ip);
                    if ip.is_unspecified() || ip.is_loopback() {
                        return Err(format!("{item}: not a server's public address"));
                    }
                    s.addrs.push((ip, node.to_string()));
                    continue;
                }
                let name = item.trim_matches('.').to_ascii_lowercase();
                if !name.contains('.') || !name.split('.').all(|l| !l.is_empty() && l.chars().all(host_char)) {
                    return Err(format!("'{item}' is neither an IP address nor a host name"));
                }
                s.hosts.push((name, node.to_string()));
            }
        }
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) =
            s.addrs.iter().map(|(a, _)| a.to_string()).chain(s.hosts.iter().map(|(h, _)| h.clone())).find(|k| !seen.insert(k.clone()))
        {
            return Err(format!("{dup} is listed twice"));
        }
        s.hosts.sort_by_key(|(h, _)| std::cmp::Reverse(h.len()));
        Ok(s)
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty() && self.hosts.is_empty()
    }

    pub fn replace(&self, text: &str) -> String {
        if self.is_empty() {
            return text.to_string();
        }
        // a replacement can free what was glued to it ("192.0.2.1db8::" → "vpndb8::"):
        // again until nothing changes (each pass only takes address characters out)
        let mut cur = self.host_names(&self.addresses(text));
        for _ in 0..8 {
            let next = self.host_names(&self.addresses(&cur));
            if next == cur {
                break;
            }
            cur = next;
        }
        cur
    }

    fn node_of(&self, ip: IpAddr) -> Option<&str> {
        let ip = normalize(ip);
        self.addrs.iter().find(|(a, _)| *a == ip).map(|(_, n)| n.as_str())
    }

    /// The addresses, in runs of address characters: first runs of hex digits, `:` and `.`
    /// with a `:` in them (IPv6, IPv4-mapped too), then runs of digits and dots (IPv4). A run
    /// that is a valid address is that address: replaced if it is ours, or if its last 32 bits
    /// spell ours (`64:ff9b::192.0.2.1`); `2001:db8::7:5` is not `2001:db8::7` with a port.
    /// A run that is no valid address hides each of ours in it between separators: a port
    /// after it (`::ffff:192.0.2.1:7946`), punctuation (`2001:db8::7: refused`,
    /// `2001:db8::7.Then`), junk around it (`dead:192.0.2.1`, `1.192.0.2.1`).
    fn addresses(&self, text: &str) -> String {
        let v6 = replace_runs(text, |c| c.is_ascii_hexdigit() || c == b':' || c == b'.', |run| self.in_run(run, true));
        replace_runs(&v6, |c| c.is_ascii_digit() || c == b'.', |run| self.in_run(run, false))
    }

    /// Ours in one run: (offset, length, node), leftmost and longest first, not overlapping.
    fn in_run(&self, run: &str, v6: bool) -> Vec<(usize, usize, &str)> {
        if v6 && !run.contains(':') {
            return vec![];
        }
        let whole = run.trim_matches('.');
        let lead = run.len() - run.trim_start_matches('.').len();
        if whole.parse::<IpAddr>().is_ok() {
            let tail = whole.rsplit_once(':').map(|(_, t)| t).filter(|t| t.contains('.'));
            return self
                .ip_node(whole)
                .or_else(|| tail.and_then(|t| self.ip_node(t)))
                .map(|n| (lead, whole.len(), n))
                .into_iter()
                .collect();
        }
        // windows between separators, at most as long as the longest address text
        const LONGEST: usize = 45;
        let b = run.as_bytes();
        let sep = |k: usize| b[k] == b':' || b[k] == b'.';
        let mut found = Vec::new();
        let mut start = 0;
        while start < b.len() {
            if start == 0 || sep(start - 1) {
                let limit = (start + LONGEST).min(b.len());
                let hit = (start + 1..=limit)
                    .rev()
                    .filter(|&end| end == b.len() || sep(end))
                    .find_map(|end| self.ip_node(&run[start..end]).map(|n| (end, n)));
                if let Some((end, node)) = hit {
                    found.push((start, end - start, node));
                    start = end;
                    continue;
                }
            }
            start += 1;
        }
        found
    }

    fn ip_node(&self, cand: &str) -> Option<&str> {
        cand.parse::<IpAddr>().ok().and_then(|ip| self.node_of(ip))
    }

    /// The host names, with subdomains: `nextcloud.example.org` → `nextcloud.xmpp`.
    fn host_names(&self, text: &str) -> String {
        let lower = text.to_ascii_lowercase(); // same byte offsets as `text`
        let mut spans: Vec<(usize, usize, &str)> = Vec::new();
        for (host, node) in &self.hosts {
            let mut from = 0;
            while let Some(k) = lower[from..].find(host.as_str()) {
                let (start, end) = (from + k, from + k + host.len());
                from = end;
                let before = lower[..start].chars().next_back();
                let after = lower[end..].chars().next();
                let after2 = lower[end..].chars().nth(1);
                // a whole name (or the end of a subdomain), not part of a longer name
                let left_ok = before.is_none_or(|c| !host_char(c));
                let right_ok = after.is_none_or(|c| !host_char(c)) && !(after == Some('.') && after2.is_some_and(host_char));
                if right_ok && (left_ok || before == Some('.')) && !spans.iter().any(|&(s, e, _)| start < e && s < end) {
                    spans.push((start, end, node));
                }
            }
        }
        spans.sort();
        let mut out = String::with_capacity(text.len());
        let mut copied = 0;
        for (start, end, node) in spans {
            out.push_str(&text[copied..start]);
            out.push_str(node);
            copied = end;
        }
        out.push_str(&text[copied..]);
        out
    }
}

/// Replaces in `text` what `matched` finds in each maximal run of ASCII bytes in `class`:
/// (offset in the run, length, replacement), in order, not overlapping.
fn replace_runs<'a>(text: &str, class: impl Fn(u8) -> bool, matched: impl Fn(&str) -> Vec<(usize, usize, &'a str)>) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut copied) = (0, 0);
    while i < b.len() {
        if !class(b[i]) {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < b.len() && class(b[end]) {
            end += 1;
        }
        // ASCII bytes only, so these are character boundaries
        for (from, len, node) in matched(&text[i..end]) {
            out.push_str(&text[copied..i + from]);
            out.push_str(node);
            copied = i + from + len;
        }
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> ServerNames {
        ServerNames::parse("xmpp=11.29.39.236, 2001:db8::7, example.org; vpn=11.38.48.86\n tg=[2001:db8::9],relay.example.net").unwrap()
    }

    #[test]
    fn own_addresses_and_names_become_node_ids() {
        let n = names();
        let digest = "[xmpp] logguard daily digest\n\n\
            Certificates: example.org:5223 85d, example.org:5222/xmpp 85d, nextcloud.example.org:443 5d\n\
            cluster peer 11.38.48.86:7946 failing: connect: timed out\n\
            Exposed: 0.0.0.0:7946 logguard (from 11.38.48.86.)\n\
            [High] ban 11.38.48.87 for 1h: scan of 11.29.39.236 and [2001:db8::7]:5223, ::ffff:11.29.39.236 too\n\
            log: GET https://nextcloud.example.org/login from 2001:db8::9 via relay.example.net\n\
            hidden too: dead:11.29.39.236 ::ffff:11.29.39.236:7946 2001:db8::7:522333 peer:2001:db8::7 x11.29.39.236y 2001:db8::7: refused\n\
            other addresses: 2001:db8::7:5223 2001:db8::70\n\
            64:ff9b::11.29.39.236 2001:db8::7:ad:11.38.48.86\n\
            2001:db8::7.example.org 1.11.29.39.236 11.29.39.236.5 a:11.29.39.236:11.38.48.86\n\
            not ours: example.org.evil.example, notexample.org, 78.40.199.2366, 11.49.39.236, 10:00:01";
        let out = n.replace(digest);
        assert_eq!(
            out,
            "[xmpp] logguard daily digest\n\n\
            Certificates: xmpp:5223 85d, xmpp:5222/xmpp 85d, nextcloud.xmpp:443 5d\n\
            cluster peer vpn:7946 failing: connect: timed out\n\
            Exposed: 0.0.0.0:7946 logguard (from vpn.)\n\
            [High] ban 11.38.48.87 for 1h: scan of xmpp and [xmpp]:5223, xmpp too\n\
            log: GET https://nextcloud.xmpp/login from tg via tg\n\
            hidden too: dead:xmpp xmpp:7946 xmpp:522333 peer:xmpp xxmppy xmpp: refused\n\
            other addresses: 2001:db8::7:5223 2001:db8::70\n\
            xmpp vpn\n\
            xmpp.xmpp 1.xmpp xmpp.5 a:xmpp:vpn\n\
            not ours: example.org.evil.example, notexample.org, 78.40.199.2366, 11.49.39.236, 10:00:01"
        );
        assert_eq!(ServerNames::default().replace(digest), digest, "nothing configured: unchanged");
    }

    #[test]
    fn bad_lists_are_refused() {
        assert!(ServerNames::parse("").unwrap().is_empty());
        assert!(ServerNames::parse("xmpp").is_err());
        assert!(ServerNames::parse("x y=1.2.3.4").is_err());
        assert!(ServerNames::parse("xmpp=localhost").is_err(), "not a host name with a domain");
        assert!(ServerNames::parse("xmpp=1.2.3.4; vpn=1.2.3.4").is_err(), "twice");
        assert!(ServerNames::parse("xmpp=::ffff:1.2.3.4; vpn=1.2.3.4").is_err(), "the same address");
        for bad in ["0=192.0.2.1", "cafe=192.0.2.1", "x=[::]", "x=0.0.0.0", "x=127.0.0.1", "x=::1", "x=::ffff:127.0.0.1"] {
            assert!(ServerNames::parse(bad).is_err(), "{bad}");
        }
        assert!(ServerNames::parse("node1=192.0.2.1; tg=192.0.2.2").is_ok());
    }

    #[test]
    fn non_ascii_text_survives() {
        let out = names().replace("Привіт → 11.29.39.236 ✓ example.org 😀");
        assert_eq!(out, "Привіт → xmpp ✓ xmpp 😀");
    }
}
