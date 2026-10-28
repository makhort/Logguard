//! Address lists (`CONSOLE_ALLOW`, `AGENT_ALLOW`): addresses and networks in CIDR notation.

use std::net::IpAddr;

use anyhow::{anyhow, bail, Result};

/// IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) as the IPv4 address they are: a dual-stack
/// listener sees IPv4 clients that way.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl std::str::FromStr for Net {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (a, p) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
        let addr: IpAddr = a.trim_matches(['[', ']']).parse().map_err(|_| anyhow!("'{s}' is not an address or network"))?;
        let addr = normalize(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| anyhow!("'{s}': bad prefix length"))?,
        };
        if prefix == 0 {
            bail!("'{s}' is every address: leave the list empty (or \"any\") instead");
        }
        Ok(Net { addr, prefix })
    }
}

impl Net {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX << (32 - u32::from(self.prefix));
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX << (128 - u32::from(self.prefix));
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Who may connect: everyone, or the listed networks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Allow {
    Any,
    Nets(Vec<Net>),
}

impl Allow {
    /// Parses a list separated by commas or blanks; empty or "any" is everyone.
    pub fn parse(list: &str) -> Result<Allow> {
        let items: Vec<&str> = list.split([',', ' ', '\t', '\n', ';']).filter(|s| !s.is_empty()).collect();
        if items.is_empty() || items == ["any"] {
            return Ok(Allow::Any);
        }
        Ok(Allow::Nets(items.iter().map(|s| s.parse()).collect::<Result<_>>()?))
    }

    pub fn admits(&self, ip: IpAddr) -> bool {
        match self {
            Allow::Any => true,
            Allow::Nets(nets) => nets.iter().any(|n| n.contains(ip)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let a = Allow::parse("203.0.113.0/24, 2001:db8::/32 198.51.100.7").unwrap();
        assert!(a.admits(ip("203.0.113.200")));
        assert!(a.admits(ip("::ffff:203.0.113.9")), "IPv4-mapped");
        assert!(a.admits(ip("2001:db8:1::5")));
        assert!(a.admits(ip("198.51.100.7")));
        assert!(!a.admits(ip("198.51.100.8")));
        assert!(!a.admits(ip("2001:db9::1")));
        assert_eq!(Allow::parse("").unwrap(), Allow::Any);
        assert_eq!(Allow::parse(" any ").unwrap(), Allow::Any);
        for bad in ["203.0.113.0/33", "example.org", "0.0.0.0/0", "::/0", "1.2.3.4/x"] {
            assert!(Allow::parse(bad).is_err(), "{bad}");
        }
    }
}
