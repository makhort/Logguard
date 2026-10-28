//! IP address and CIDR helpers. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`)
//! are always normalised to plain IPv4 so one host never has two identities.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Parses a bare IP, tolerating surrounding brackets and trailing punctuation.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim_matches(|c: char| c == '[' || c == ']' || c == ',' || c == ';');
    s.parse::<IpAddr>().ok().map(normalize)
}

/// The same networks without overlaps: entries inside another entry are dropped (nftables
/// interval sets reject overlapping elements, e.g. `127.0.0.0/8` together with `127.0.0.1`).
pub fn collapse(nets: &[Net]) -> Vec<Net> {
    let mut sorted: Vec<Net> = nets.to_vec();
    sorted.sort_by_key(|n| (n.is_v4(), n.prefix, n.addr));
    let mut out: Vec<Net> = Vec::new();
    for n in sorted {
        if !out.iter().any(|k| k.is_v4() == n.is_v4() && k.contains_net(&n)) {
            out.push(n);
        }
    }
    out
}

/// Addresses assigned to this host (Linux; empty elsewhere): IPv4 from the kernel's local
/// routing table (`/proc/net/fib_trie`, "/32 host LOCAL"), IPv6 from `/proc/net/if_inet6`.
/// The host's own checks and services connect to its public address too, and must never
/// be scored or banned.
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(trie) = std::fs::read_to_string("/proc/net/fib_trie") {
        out.extend(parse_fib_trie(&trie));
    }
    if let Ok(v6) = std::fs::read_to_string("/proc/net/if_inet6") {
        out.extend(v6.lines().filter_map(|l| u128::from_str_radix(l.split_whitespace().next()?, 16).ok()).map(|a| IpAddr::V6(a.into())));
    }
    out.sort();
    out.dedup();
    out
}

fn parse_fib_trie(text: &str) -> Vec<IpAddr> {
    let mut last = None;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start_matches([' ', '|', '+', '-']).trim();
        if let Ok(ip) = t.parse::<IpAddr>() {
            last = Some(ip);
        } else if t.starts_with("/32 host LOCAL") {
            out.extend(last);
        }
    }
    out
}

/// Whether `s` is a DNS host name (not an address, no port): letters, digits, `-` and `.`.
pub fn valid_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.parse::<IpAddr>().is_err()
        && s.split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Most addresses kept per host name (a name for one home connection has one or two).
const MAX_HOST_ADDRESSES: usize = 16;

/// The addresses host names resolve to, sorted, and what could not be resolved.
pub fn resolve_hosts(hosts: &[String]) -> (Vec<Net>, Vec<String>) {
    use std::net::ToSocketAddrs;
    let (mut nets, mut errors) = (Vec::new(), Vec::new());
    for h in hosts {
        match (h.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let mut mine: Vec<Net> = addrs.map(|a| Net::host(normalize(a.ip()))).collect();
                mine.sort();
                mine.dedup();
                if mine.len() > MAX_HOST_ADDRESSES {
                    errors.push(format!("{h} resolves to {} addresses: only the first {MAX_HOST_ADDRESSES} are used", mine.len()));
                    mine.truncate(MAX_HOST_ADDRESSES);
                }
                nets.extend(mine);
            }
            Err(e) => errors.push(format!("{h}: cannot resolve: {e}")),
        }
    }
    nets.sort();
    nets.dedup();
    (nets, errors)
}

/// Parses `[addr]:port`, `a.b.c.d:port` or a bare address.
pub fn parse_ip_port(s: &str) -> Option<(IpAddr, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return Some((parse_ip(addr)?, port));
    }
    if let Some(ip) = parse_ip(s) {
        return Some((ip, None));
    }
    let (addr, port) = s.rsplit_once(':')?;
    Some((parse_ip(addr)?, port.parse().ok()))
}

/// An address with a prefix length, always stored masked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    pub fn host(ip: IpAddr) -> Self {
        let ip = normalize(ip);
        Net { addr: ip, prefix: max_prefix(&ip) }
    }

    pub fn new(ip: IpAddr, prefix: u8) -> Self {
        let ip = normalize(ip);
        let prefix = prefix.min(max_prefix(&ip));
        Net { addr: mask(ip, prefix), prefix }
    }

    pub fn is_host(&self) -> bool {
        self.prefix == max_prefix(&self.addr)
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.addr
    }

    pub fn contains_net(&self, other: &Net) -> bool {
        other.prefix >= self.prefix && self.contains(other.addr)
    }

    pub fn overlaps(&self, other: &Net) -> bool {
        self.contains_net(other) || other.contains_net(self)
    }

    /// The narrowest network holding both (of the same family): `11.20.59.0/24` and
    /// `11.20.57.7` -> `11.20.56.0/22`.
    pub fn common(&self, other: &Net) -> Net {
        let shared = match (self.addr, other.addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) ^ u32::from(b)).leading_zeros(),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a) ^ u128::from(b)).leading_zeros(),
            _ => 0,
        };
        Net::new(self.addr, (shared as u8).min(self.prefix).min(other.prefix))
    }
}

fn max_prefix(ip: &IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix.min(128))) };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_host() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

impl FromStr for Net {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s.split_once('/') {
            Some((addr, prefix)) => {
                let ip = parse_ip(addr).ok_or_else(|| format!("invalid address in '{s}'"))?;
                let prefix: u8 = prefix.parse().map_err(|_| format!("invalid prefix in '{s}'"))?;
                if prefix > max_prefix(&ip) {
                    return Err(format!("prefix too long in '{s}'"));
                }
                Ok(Net::new(ip, prefix))
            }
            None => parse_ip(s).map(Net::host).ok_or_else(|| format!("invalid address '{s}'")),
        }
    }
}

impl Serialize for Net {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Net {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_addresses_become_v4() {
        assert_eq!(parse_ip("::ffff:1.2.3.4"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(parse_ip_port("[::ffff:11.45.25.27]:59195"), Some(("11.45.25.27".parse().unwrap(), Some(59195))));
        assert_eq!(parse_ip_port("11.20.79.110:50735"), Some(("11.20.79.110".parse().unwrap(), Some(50735))));
        assert_eq!(parse_ip_port("[2001:db8::1]:443").unwrap().1, Some(443));
        assert_eq!(parse_ip_port("2001:db8::1").unwrap().1, None);
    }

    #[test]
    fn subnet_math() {
        let n: Net = "11.48.43.99/24".parse().unwrap();
        assert_eq!(n.to_string(), "11.48.43.0/24");
        assert!(n.contains("11.48.43.31".parse().unwrap()));
        assert!(!n.contains("11.48.44.31".parse().unwrap()));
        assert!(n.contains_net(&"11.48.43.31".parse().unwrap()));
        let v6: Net = "2001:db8:1:2::5/64".parse().unwrap();
        assert_eq!(v6.to_string(), "2001:db8:1:2::/64");
        assert!(!v6.contains("1.2.3.4".parse().unwrap()));
        assert_eq!(Net::host("::ffff:1.2.3.4".parse().unwrap()).to_string(), "1.2.3.4");
    }

    #[test]
    fn common_network() {
        let common = |a: &str, b: &str| a.parse::<Net>().unwrap().common(&b.parse().unwrap()).to_string();
        assert_eq!(common("11.20.59.0/24", "11.20.57.7"), "11.20.56.0/22");
        assert_eq!(common("11.20.59.0/24", "11.20.58.0/24"), "11.20.58.0/23");
        assert_eq!(common("11.20.59.0/24", "11.20.59.9"), "11.20.59.0/24", "already inside");
        assert_eq!(common("11.20.56.0/22", "11.20.0.0/16"), "11.20.0.0/16", "the wider one");
        // (across /16s: addresses the public mirror keeps as they are, see make_public_mirror.zsh)
        assert_eq!(common("5.7.123.0/24", "5.8.1.1"), "5.0.0.0/12");
        assert_eq!(common("8.8.8.8", "8.8.8.8"), "8.8.8.8");
        assert_eq!(common("2001:db8:1::/64", "2001:db8:2::5"), "2001:db8::/46");
    }

    #[test]
    fn host_addresses_from_fib_trie() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     +-- 11.29.39.0/24 2 0 2\n        |-- 11.29.39.0\n           /24 link UNICAST\n        |-- 11.29.39.236\n           /32 host LOCAL\n     |-- 127.0.0.1\n        /32 host LOCAL\n";
        assert_eq!(parse_fib_trie(trie), vec!["11.29.39.236".parse::<IpAddr>().unwrap(), "127.0.0.1".parse().unwrap()]);
    }

    #[test]
    fn host_names() {
        assert!(valid_host_name("home.example.dyndns.org") && valid_host_name("localhost"));
        for bad in ["", "1.2.3.4", "::1", "host:22", "a..b", "-x.org", "a b", "x/y"] {
            assert!(!valid_host_name(bad), "{bad}");
        }
        let (nets, errors) = resolve_hosts(&["localhost".into(), "no-such-host.invalid".into()]);
        assert!(nets.iter().all(|n| n.is_host()));
        assert!(errors.iter().any(|e| e.starts_with("no-such-host.invalid: cannot resolve")), "{errors:?}");
    }

    #[test]
    fn collapse_overlaps() {
        let nets: Vec<Net> = ["127.0.0.0/8", "11.48.43.31", "127.0.0.1", "8.8.8.8", "8.8.8.8", "::1", "2001:db8::/32", "2001:db8::5"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let got: Vec<String> = collapse(&nets).iter().map(|n| n.to_string()).collect();
        assert_eq!(got, vec!["2001:db8::/32", "::1", "127.0.0.0/8", "8.8.8.8", "11.48.43.31"]);
    }
}
