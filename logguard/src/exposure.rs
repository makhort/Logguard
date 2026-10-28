//! Exposure watch: which sockets are reachable from the internet, and do the
//! firewall rules still match reality?
//!
//! Every interval the daemon reads the listening sockets from `/proc/net/{tcp,udp}{,6}`
//! (no `ss` subprocess), maps them to processes via `/proc/<pid>/fd`, and compares
//! them with `ufw status` (or firewalld's zones, or iptables' INPUT chain). Ports published by Docker show up as `docker-proxy`
//! listeners and are flagged: that traffic bypasses UFW. The engine keeps a baseline
//! and alerts on drift (see `Engine::on_exposure`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::PortSpec;
use crate::engine::is_non_global;
use crate::event::Proto;
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExposureCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Used to read the firewall rules; leave empty on hosts without UFW.
    pub ufw: PathBuf,
    /// Ports never reported (e.g. exposed by design through another path).
    pub ignore: Vec<PortSpec>,
    /// No new/gone alerts this long after logguard starts: after a reboot, services
    /// (Docker containers especially) come up after logguard does.
    pub startup_grace: Dur,
    /// Consecutive scans a new listener must be seen in / a known one missing from.
    pub new_after_scans: u32,
    pub gone_after_scans: u32,
}

impl Default for ExposureCfg {
    fn default() -> Self {
        ExposureCfg {
            enabled: true,
            interval: Dur(60),
            ufw: "/usr/sbin/ufw".into(),
            ignore: vec![],
            startup_grace: Dur(900),
            new_after_scans: 2,
            gone_after_scans: 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ListenerKey {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
}

impl std::fmt::Display for ListenerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = if self.proto == Proto::Udp { "udp" } else { "tcp" };
        match self.addr {
            IpAddr::V6(a) => write!(f, "[{a}]:{}/{p}", self.port),
            IpAddr::V4(a) => write!(f, "{a}:{}/{p}", self.port),
        }
    }
}

/// How reachable a listener is from the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// Bound to loopback / a private address.
    Local,
    /// Public address, but the firewall does not let new connections to the port in.
    Firewalled,
    /// Public and let in by a firewall rule (or policy) from anywhere.
    Allowed,
    /// Published by Docker (`docker-proxy`): reachable whatever the INPUT rules say.
    Docker,
    /// Public, and no firewall the scan can read filters it.
    Unfiltered,
}

impl Exposure {
    pub fn is_exposed(self) -> bool {
        matches!(self, Exposure::Allowed | Exposure::Docker | Exposure::Unfiltered)
    }
}

/// What filters incoming traffic, as the scan found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Firewall {
    /// ufw, active: `ufw status` is read.
    Ufw,
    /// firewalld, running: its zones are read (`firewall-cmd --list-all-zones`, and the ports
    /// of the services they name from firewalld's service files).
    Firewalld,
    /// No active ufw; the filter table's INPUT chain is read (`iptables -S`, `ip6tables -S`).
    Iptables,
    /// No active ufw and no iptables filtering, but nftables chains of their own on the input
    /// hook. Their rules aren't read: listeners on public addresses count as reachable.
    Nftables,
    /// Nothing filters incoming traffic.
    Absent,
}

impl Firewall {
    pub fn name(self) -> &'static str {
        match self {
            Firewall::Ufw => "ufw",
            Firewall::Firewalld => "firewalld",
            Firewall::Iptables => "iptables",
            Firewall::Nftables => "nftables",
            Firewall::Absent => "no firewall",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listener {
    pub key: ListenerKey,
    pub process: String,
    pub exposure: Exposure,
    /// Allowed only through a ufw port *range* (e.g. TURN relay ports 49152:65535):
    /// such sockets come and go with every call, so they never trigger drift alerts.
    #[serde(default)]
    pub dynamic: bool,
    /// The firewall rule letting it in from anywhere, the first that matches as the firewall
    /// applies them: `LIMIT 9843/tcp` (ufw), `ACCEPT 80,443/tcp`, `policy ACCEPT` (iptables).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// That rule, or one before it, only rate-limits: ufw's `LIMIT`, iptables' `limit`,
    /// `hashlimit`, `recent` or `connlimit`.
    #[serde(default)]
    pub limited: bool,
    /// One of logguard's own honeypot listeners (`[ports] honeypot`): exposed on purpose, so
    /// it never makes a new/gone alert.
    #[serde(default)]
    pub honeypot: bool,
}

impl Listener {
    /// How it is reachable under `fw`, naming a rate limit.
    pub fn describe(&self, fw: Firewall) -> String {
        let by = fw.name();
        if self.honeypot {
            return match self.exposure {
                Exposure::Firewalled => format!("honeypot, but blocked by {by}: open it ({})", open_command(fw, self.key.port)),
                Exposure::Local => "honeypot, local only".into(),
                _ => "honeypot: logguard bans whoever connects".into(),
            };
        }
        match (self.exposure, fw) {
            (Exposure::Local, _) => "local only".into(),
            (Exposure::Firewalled, _) if self.rule.is_some() => format!("allowed by {by} from some sources only"),
            (Exposure::Firewalled, _) => format!("blocked by {by}"),
            (Exposure::Allowed, _) if self.limited => format!("allowed by {by}, rate-limited"),
            (Exposure::Allowed, _) => format!("allowed by {by}"),
            (Exposure::Docker, Firewall::Absent) => "published by docker".into(),
            (Exposure::Docker, _) => format!("published by docker, bypasses {by}"),
            (Exposure::Unfiltered, Firewall::Nftables) => "public, nftables rules not read".into(),
            (Exposure::Unfiltered, Firewall::Iptables) => "no ip6tables rules: open over IPv6".into(),
            (Exposure::Unfiltered, _) => "no firewall".into(),
        }
    }
}

/// How to open a TCP port to everyone under `fw`.
fn open_command(fw: Firewall, port: u16) -> String {
    match fw {
        Firewall::Firewalld => format!("firewall-cmd --permanent --add-port={port}/tcp; firewall-cmd --reload"),
        Firewall::Iptables => format!("iptables -I INPUT -p tcp --dport {port} -j ACCEPT"),
        _ => format!("ufw allow {port}/tcp"),
    }
}

impl Listener {
    /// The rule letting it in, or for a docker-published port without one under ufw, what
    /// that means: from the internet Docker's DNAT bypasses ufw, but a container calling the
    /// host's public address (Nextcloud's check of its Talk server) reaches docker-proxy
    /// through INPUT, where ufw drops it.
    pub fn rule_text(&self, fw: Firewall) -> Option<String> {
        match (&self.rule, self.exposure, fw) {
            (None, Exposure::Docker, Firewall::Ufw) => Some("none: containers blocked".into()),
            (rule, ..) => rule.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExposureReport {
    pub scanned: Micros,
    /// None = UFW not installed / not readable.
    pub ufw_active: Option<bool>,
    /// What filters incoming traffic; missing from reports of versions that read only ufw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<Firewall>,
    pub listeners: Vec<Listener>,
    /// UFW rules allowing a single port from anywhere while nothing listens on it publicly.
    pub dead_rules: Vec<String>,
}

impl ExposureReport {
    /// What filters incoming traffic (an older report: ufw if it was active, else nothing).
    pub fn firewall(&self) -> Firewall {
        self.firewall.unwrap_or(if self.ufw_active == Some(true) { Firewall::Ufw } else { Firewall::Absent })
    }

    /// Whether the scan read every firewall it knows of: not so in a report from a version
    /// that read only ufw, where ufw wasn't active (it never looked at iptables).
    pub fn firewall_checked(&self) -> bool {
        self.firewall.is_some() || self.ufw_active == Some(true)
    }

    /// How one of its listeners is reachable (see `Listener::describe`).
    pub fn describe(&self, l: &Listener) -> String {
        match l.exposure {
            Exposure::Unfiltered if !self.firewall_checked() => "public, firewall not checked".into(),
            _ => l.describe(self.firewall()),
        }
    }

    /// "ufw active", "iptables (ufw inactive)", "NO FIREWALL", ...
    pub fn firewall_summary(&self) -> String {
        let ufw = match self.ufw_active {
            Some(false) => " (ufw inactive)",
            _ => "",
        };
        if !self.firewall_checked() {
            return format!("ufw not active{ufw}, iptables not checked: restart the daemon");
        }
        match self.firewall() {
            Firewall::Ufw => "ufw active".into(),
            Firewall::Firewalld => format!("firewalld running{ufw}"),
            Firewall::Iptables => format!("iptables{ufw}"),
            Firewall::Nftables => format!("nftables, rules not read{ufw}"),
            Firewall::Absent => format!("NO FIREWALL{ufw}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UfwRule {
    pub lo: u16,
    pub hi: u16,
    pub proto: Option<Proto>,
    pub label: String,
    /// `LIMIT` rather than `ALLOW`.
    pub limit: bool,
    /// The address or network it lets in from; None: from anywhere.
    pub from: Option<String>,
    /// Every port (of `proto`): a firewalld zone whose target is ACCEPT, or that allows a
    /// whole protocol. Not a port range, whose sockets come and go.
    pub every: bool,
}

impl UfwRule {
    fn matches(&self, port: u16, proto: Proto) -> bool {
        (self.lo..=self.hi).contains(&port) && self.proto.is_none_or(|p| p == proto)
    }
}

// ------------------------------------------------------------------ /proc parsing

/// The kernel prints an address as 32-bit words read in the host's byte order: their bytes in
/// that order are the address (little-endian on x86_64 and ARM, so `0100007F` is 127.0.0.1).
pub(crate) fn parse_hex_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes()))),
        32 => {
            // four 32-bit words, each in host byte order
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            Some(crate::net::normalize(IpAddr::V6(Ipv6Addr::from(bytes))))
        }
        _ => None,
    }
}

/// Parses `/proc/net/{tcp,udp}{,6}`; returns listening/bound sockets with their inode.
pub fn parse_proc_net(text: &str, proto: Proto) -> Vec<(ListenerKey, u64)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let listening = match proto {
            Proto::Tcp => f[3] == "0A",
            // UDP "listeners" are unconnected bound sockets (state 07, remote port 0).
            _ => f[3] == "07" && f[2].ends_with(":0000"),
        };
        if !listening {
            continue;
        }
        let Some((addr, port)) = f[1].split_once(':') else { continue };
        let (Some(addr), Ok(port), Ok(inode)) = (parse_hex_addr(addr), u16::from_str_radix(port, 16), f[9].parse()) else {
            continue;
        };
        out.push((ListenerKey { proto, addr, port }, inode));
    }
    out
}

/// Maps socket inodes to the owning process name (needs root to see every process).
fn socket_owners() -> HashMap<u64, String> {
    let mut owners = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else { return owners };
    for p in procs.flatten() {
        let name = p.file_name();
        let Some(pid) = name.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
        let mut comm = None;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let Some(inode) = target.to_str().and_then(|t| t.strip_prefix("socket:[")).and_then(|t| t.strip_suffix(']')) else {
                continue;
            };
            let Ok(inode) = inode.parse() else { continue };
            let comm = comm.get_or_insert_with(|| {
                // any user names their own processes: no control characters into alerts and `status`
                std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map_or_else(|_| format!("pid {pid}"), |c| crate::event::clean(c.trim(), 64))
            });
            owners.entry(inode).or_insert_with(|| comm.clone());
        }
    }
    owners
}

// ------------------------------------------------------------------ ufw parsing

/// Parses `ufw status` (plain or verbose): returns (active, the rules letting traffic in, from
/// anywhere or from some sources).
pub fn parse_ufw_status(text: &str) -> (bool, Vec<UfwRule>) {
    let active = text.lines().any(|l| l.trim() == "Status: active");
    let mut rules = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        if line.starts_with("--") {
            in_table = true;
            continue;
        }
        if !in_table || line.trim().is_empty() {
            continue;
        }
        let body = line.split(" # ").next().unwrap_or(line);
        let cols: Vec<&str> = body.split("  ").map(str::trim).filter(|c| !c.is_empty()).collect();
        if cols.len() < 3 {
            continue;
        }
        let (to, action, from) = (cols[0], cols[1], cols[2]);
        if !(action.starts_with("ALLOW") || action.starts_with("LIMIT")) {
            continue;
        }
        let from = (!from.starts_with("Anywhere")).then(|| from.trim_end_matches(" (v6)").trim().to_string());
        let to = to.trim_end_matches(" (v6)").trim();
        let (ports, proto) = match to.split_once('/') {
            Some((p, "tcp")) => (p, Some(Proto::Tcp)),
            Some((p, "udp")) => (p, Some(Proto::Udp)),
            Some(_) => continue,
            None => (to, None),
        };
        let (lo, hi) = match ports.split_once(':') {
            Some((a, b)) => (a.parse().ok(), b.parse().ok()),
            None => (ports.parse().ok(), ports.parse().ok()),
        };
        // App profiles ("OpenSSH") and "Anywhere" targets can't be mapped to ports.
        let (Some(lo), Some(hi)) = (lo, hi) else { continue };
        let rule = UfwRule { lo, hi, proto, label: to.to_string(), limit: action.starts_with("LIMIT"), from, every: false };
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    (active, rules)
}

// ------------------------------------------------------------------ firewalld parsing

/// One zone of `firewall-cmd --list-all-zones`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirewalldZone {
    pub name: String,
    /// The default zone: it takes the interfaces no zone names.
    pub default: bool,
    pub target: String,
    pub interfaces: Vec<String>,
    pub sources: Vec<String>,
    pub services: Vec<String>,
    pub ports: Vec<String>,
    pub protocols: Vec<String>,
    pub rich_rules: Vec<String>,
}

/// Parses `firewall-cmd --list-all-zones`: a header line per zone (`public (default, active)`),
/// then indented `key: values` lines; rich rules follow `rich rules:`, one per line.
pub fn parse_firewalld_zones(text: &str) -> Vec<FirewalldZone> {
    let mut zones: Vec<FirewalldZone> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            let (name, flags) = line.split_once(' ').unwrap_or((line, ""));
            zones.push(FirewalldZone { name: name.to_string(), default: flags.contains("default"), ..Default::default() });
            continue;
        }
        let Some(z) = zones.last_mut() else { continue };
        let t = line.trim();
        if t.starts_with("rule ") {
            z.rich_rules.push(t.to_string());
            continue;
        }
        let Some((key, values)) = t.split_once(':') else { continue };
        let values: Vec<String> = values.split_whitespace().map(str::to_string).collect();
        match key {
            "target" => z.target = values.first().cloned().unwrap_or_default(),
            "interfaces" => z.interfaces = values,
            "sources" => z.sources = values,
            "services" => z.services = values,
            "ports" => z.ports = values,
            "protocols" => z.protocols = values,
            _ => {}
        }
    }
    zones
}

/// A port range of firewalld's: `443/tcp`, `60000-61000/udp`.
fn firewalld_port(spec: &str) -> Option<(u16, u16, Option<Proto>)> {
    let (ports, proto) = spec.split_once('/')?;
    let proto = match proto {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        _ => return None, // sctp, dccp: no listeners read
    };
    let (lo, hi) = match ports.split_once('-') {
        Some((a, b)) => (a.parse().ok()?, b.parse().ok()?),
        None => (ports.parse().ok()?, ports.parse().ok()?),
    };
    Some((lo, hi, proto))
}

/// A firewalld service file's ports (`<port protocol="tcp" port="22"/>`) and the services it
/// includes (`<include service="..."/>`).
pub fn parse_firewalld_service(xml: &str) -> (Vec<String>, Vec<String>) {
    let attr = |tag: &str, name: &str| -> Option<String> {
        let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
        Some(tag[start..].split('"').next()?.to_string())
    };
    let (mut ports, mut includes) = (Vec::new(), Vec::new());
    for tag in xml.split('<').skip(1) {
        if let Some(t) = tag.strip_prefix("port ") {
            if let (Some(port), Some(proto)) = (attr(t, "port"), attr(t, "protocol")) {
                ports.push(format!("{port}/{proto}"));
            }
        } else if let Some(t) = tag.strip_prefix("include ") {
            includes.extend(attr(t, "service"));
        }
    }
    (ports, includes)
}

/// The ports of the services the zones name, from firewalld's service files (`/etc` overrides
/// `/usr/lib`), includes followed a few levels deep. A service without a file has none.
fn firewalld_service_ports(zones: &[FirewalldZone], dirs: &[&Path]) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let named: Vec<String> = zones
        .iter()
        .flat_map(|z| z.services.iter().cloned())
        .chain(zones.iter().flat_map(|z| z.rich_rules.iter().filter_map(|r| rich_value(r, "service name"))))
        .collect();
    for name in named {
        if out.contains_key(&name) || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) || name.starts_with('.') {
            continue;
        }
        let mut ports = Vec::new();
        let mut todo = vec![(name.clone(), 0)];
        while let Some((service, depth)) = todo.pop() {
            let Some(xml) = dirs.iter().find_map(|d| std::fs::read_to_string(d.join(format!("{service}.xml"))).ok()) else { continue };
            let (p, includes) = parse_firewalld_service(&xml);
            ports.extend(p);
            if depth < 3 {
                todo.extend(
                    includes
                        .into_iter()
                        .filter(|i| i.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) && !i.starts_with('.'))
                        .map(|i| (i, depth + 1)),
                );
            }
        }
        out.insert(name, ports);
    }
    out
}

/// A rich rule's `key="value"` (e.g. `source address`, `port port`, `service name`).
fn rich_value(rule: &str, key: &str) -> Option<String> {
    let start = rule.find(&format!("{key}=\""))? + key.len() + 2;
    Some(rule[start..].split('"').next()?.to_string())
}

/// The rules letting traffic in under firewalld, as ufw's would be: those of the zones that
/// take traffic from the internet (the default zone, and zones with an interface other than
/// loopback, containers' bridges and tunnels) from anywhere; those of zones bound to sources,
/// and rich rules naming a source, from those sources only. logguard's own zone (banned
/// sources) lets nobody in. Also the single ports opened from anywhere (`ports:`, not
/// services), for dead-rule checks.
pub fn firewalld_rules(zones: &[FirewalldZone], services: &HashMap<String, Vec<String>>) -> (Vec<UfwRule>, Vec<UfwRule>) {
    let (mut rules, mut explicit) = (Vec::new(), Vec::new());
    for z in zones.iter().filter(|z| z.name != crate::enforce::FIREWALLD_ZONE) {
        let public = z.default || z.interfaces.iter().any(|i| !internal_interface(i));
        let from = match (public, z.sources.is_empty()) {
            (true, _) => None,
            (false, false) => Some(z.sources.join(", ")),
            (false, true) => continue, // inactive, or internal interfaces only
        };
        let mut add = |lo, hi, proto, label: String, limit, from: Option<String>, every| {
            let r = UfwRule { lo, hi, proto, label, limit, from, every };
            if !rules.contains(&r) {
                rules.push(r);
            }
        };
        let zone = &z.name;
        if z.target == "ACCEPT" {
            add(1, u16::MAX, None, format!("target ACCEPT ({zone})"), false, from.clone(), true);
        }
        for p in &z.ports {
            if let Some((lo, hi, proto)) = firewalld_port(p) {
                add(lo, hi, proto, format!("{p} ({zone})"), false, from.clone(), false);
                if from.is_none() && lo == hi {
                    explicit.push(UfwRule { lo, hi, proto, label: format!("{p} ({zone})"), limit: false, from: None, every: false });
                }
            }
        }
        for s in &z.services {
            for (lo, hi, proto) in services.get(s).into_iter().flatten().filter_map(|p| firewalld_port(p)) {
                add(lo, hi, proto, format!("{s} ({zone})"), false, from.clone(), false);
            }
        }
        for p in &z.protocols {
            let proto = match p.as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => continue,
            };
            add(1, u16::MAX, Some(proto), format!("protocol {p} ({zone})"), false, from.clone(), true);
        }
        for r in &z.rich_rules {
            // only rules that let traffic in; `source not` = from anywhere but some
            if !r.split_whitespace().any(|w| w == "accept") {
                continue;
            }
            let source = (!r.contains("source not"))
                .then(|| rich_value(r, "source address").or_else(|| rich_value(r, "source ipset").map(|s| format!("ipset {s}"))))
                .flatten();
            let from = source.or_else(|| from.clone());
            let limit = r.contains(" limit value=");
            if let Some(port) = rich_value(r, "port port") {
                let proto = rich_value(r, "protocol").unwrap_or_default();
                if let Some((lo, hi, proto)) = firewalld_port(&format!("{port}/{proto}")) {
                    add(
                        lo,
                        hi,
                        proto,
                        format!("rich rule {port}/{} ({zone})", rich_value(r, "protocol").unwrap_or_default()),
                        limit,
                        from,
                        false,
                    );
                }
            } else if let Some(s) = rich_value(r, "service name") {
                for (lo, hi, proto) in services.get(&s).into_iter().flatten().filter_map(|p| firewalld_port(p)) {
                    add(lo, hi, proto, format!("rich rule {s} ({zone})"), limit, from.clone(), false);
                }
            } else if !r.contains("forward-port") && !r.contains("icmp") {
                add(1, u16::MAX, None, format!("rich rule ({zone})"), limit, from, true);
            }
        }
    }
    (rules, explicit)
}

// ------------------------------------------------------------------ iptables parsing

/// The filter table as `iptables -S` prints it, for hosts without an active ufw: INPUT's
/// policy and every chain's rules, in order.
#[derive(Debug, Default)]
pub struct IptRules {
    input_drops: bool,
    chains: HashMap<String, Vec<IptRule>>,
}

#[derive(Debug, Default)]
struct IptRule {
    /// tcp or udp; None for every protocol.
    proto: Option<Proto>,
    /// ICMP and the like: never a listener's.
    other_proto: bool,
    /// Destination ports and ranges; empty for every port.
    ports: Vec<(u16, u16)>,
    target: String,
    /// `-g`: a chain it goes to doesn't return here.
    goto: bool,
    /// A rate or connection limit (`limit`, `hashlimit`, `recent`, `connlimit`): it acts on
    /// some connection attempts only.
    limit: bool,
    /// Doesn't concern new connections from anywhere to a public address (loopback or a
    /// container/tunnel interface, a connection state other than NEW, source ports,
    /// fragments, odd TCP flags): ignored.
    skip: bool,
    /// Has a match this parser doesn't know: an ACCEPT still counts, a DROP doesn't, so the
    /// exposure is over- rather than under-reported.
    unsure: bool,
    /// Only for these sources (`-s 192.0.2.7/32`, `--match-set peers`): not for new
    /// connections from anywhere, but shown as letting some in.
    from: Option<String>,
}

/// `iptables -S` output (filter table).
pub fn parse_iptables(text: &str) -> IptRules {
    let mut rules = IptRules::default();
    for line in text.lines() {
        let words = shell_words(line);
        match words.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
            ["-P", "INPUT", policy, ..] => rules.input_drops = *policy != "ACCEPT",
            ["-A", chain, ..] => {
                let rule = parse_ipt_rule(&words[2..]);
                rules.chains.entry(chain.to_string()).or_default().push(rule);
            }
            _ => {}
        }
    }
    rules
}

/// Splits a line as a shell would, for the quoted comments `iptables -S` prints.
fn shell_words(line: &str) -> Vec<String> {
    let (mut words, mut word, mut quoted, mut started) = (Vec::new(), String::new(), false, false);
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => (quoted, started) = (!quoted, true),
            '\\' if quoted => word.extend(chars.next()),
            c if c.is_whitespace() && !quoted => {
                if started || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => word.push(c),
        }
    }
    if started || !word.is_empty() {
        words.push(word);
    }
    words
}

/// Loopback and the interfaces of containers, bridges and tunnels: rules about them don't
/// concern connections from the internet.
fn internal_interface(name: &str) -> bool {
    name == "lo"
        || ["docker", "br-", "veth", "virbr", "lxc", "lxd", "cni", "flannel", "cali", "podman", "wg", "tun", "tap", "tailscale", "zt"]
            .iter()
            .any(|p| name.starts_with(p))
}

/// "22", "5000:5100", "80,443,8000:8100" (multiport) -> ranges.
fn port_ranges(text: &str) -> Option<Vec<(u16, u16)>> {
    text.split(',')
        .map(|p| match p.split_once(':') {
            Some((a, b)) => Some((if a.is_empty() { 0 } else { a.parse().ok()? }, if b.is_empty() { u16::MAX } else { b.parse().ok()? })),
            None => p.parse().ok().map(|n| (n, n)),
        })
        .collect()
}

/// The words after `-A <chain>`.
fn parse_ipt_rule(words: &[String]) -> IptRule {
    let mut r = IptRule::default();
    let (mut i, mut negated) = (0, false);
    while i < words.len() {
        let opt = words[i].as_str();
        i += 1;
        if opt == "!" {
            negated = true;
            continue;
        }
        // an option's values: the words up to the next option
        let start = i;
        while i < words.len() && !words[i].starts_with('-') && words[i] != "!" {
            i += 1;
        }
        let value = if i > start { words[start].as_str() } else { "" };
        let neg = std::mem::take(&mut negated);
        match opt {
            "-p" | "--protocol" => match (neg, value) {
                (false, "tcp" | "6") => r.proto = Some(Proto::Tcp),
                (false, "udp" | "17") => r.proto = Some(Proto::Udp),
                (false, "all" | "0") => {}
                (false, _) => r.other_proto = true,
                (true, _) => r.unsure = true,
            },
            "-s" | "--source" | "--src" => {
                if !neg && value.parse::<crate::net::Net>().map_or(true, |n| n.prefix > 0) {
                    r.from = Some(value.trim_end_matches("/32").trim_end_matches("/128").to_string());
                }
            }
            "--match-set" if !neg => r.from = Some(format!("set {value}")),
            // to loopback (a private address may be where a cloud host's public one is NATed to)
            "-d" | "--destination" | "--dst" => {
                if !neg && value.parse::<crate::net::Net>().is_ok_and(|n| n.prefix > 0 && n.addr.is_loopback()) {
                    r.skip = true;
                }
            }
            "-i" | "--in-interface" => {
                if !neg && internal_interface(value) {
                    r.skip = true;
                }
            }
            "--dport" | "--destination-port" | "--dports" | "--destination-ports" | "--ports" => match (neg, port_ranges(value)) {
                (false, Some(p)) => r.ports = p,
                _ => r.unsure = true,
            },
            "--ctstate" | "--state" => {
                if value.split(',').any(|s| s == "NEW") == neg {
                    r.skip = true;
                }
            }
            "--dst-type" => {
                if neg || value != "LOCAL" {
                    r.skip = true;
                }
            }
            "--syn" => r.skip |= neg,
            "--sport" | "--source-port" | "--sports" | "--source-ports" | "--match-set" | "--src-range" | "--src-type" | "--tcp-flags"
            | "-f" | "--fragment" => r.skip = true,
            "-m" | "--match" => r.limit |= matches!(value, "limit" | "hashlimit" | "recent" | "connlimit"),
            "-j" | "--jump" => r.target = value.to_string(),
            "-g" | "--goto" => (r.target, r.goto) = (value.to_string(), true),
            // details of the matches above, or of what a target does
            "-o" | "--out-interface" | "--comment" | "--reject-with" | "--limit" | "--limit-burst" | "--set" | "--update" | "--rcheck"
            | "--remove" | "--seconds" | "--hitcount" | "--name" | "--rsource" | "--rdest" | "--mask" | "--reap" | "--rttl"
            | "--icmp-type" | "--icmpv6-type" => {}
            o if o.starts_with("--hashlimit") || o.starts_with("--connlimit") || o.starts_with("--log") => {}
            _ => r.unsure = true,
        }
    }
    r
}

impl IptRule {
    /// Whether it applies to a new connection from anywhere to `port`.
    fn matches(&self, proto: Proto, port: u16) -> bool {
        self.from.is_none() && self.matches_port(proto, port)
    }

    /// The same, from the sources it names.
    fn matches_port(&self, proto: Proto, port: u16) -> bool {
        !self.skip
            && !self.other_proto
            && self.proto.is_none_or(|p| p == proto)
            && (self.ports.is_empty() || self.ports.iter().any(|(lo, hi)| (*lo..=*hi).contains(&port)))
    }

    fn drops(&self) -> bool {
        matches!(self.target.as_str(), "DROP" | "REJECT")
    }

    /// What it matches: "22/tcp", "80,443/tcp", "tcp"; None for everything.
    fn what(&self) -> Option<String> {
        let proto = match self.proto? {
            Proto::Udp => "udp",
            _ => "tcp",
        };
        let ports: Vec<String> = self.ports.iter().map(|(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}:{hi}") }).collect();
        Some(if ports.is_empty() { proto.to_string() } else { format!("{}/{proto}", ports.join(",")) })
    }

    /// Whether `port` is let in only through a port range (`49152:65535`), as TURN relays are.
    fn by_range(&self, port: u16) -> bool {
        let hit = |single: bool| self.ports.iter().any(|(lo, hi)| (lo == hi) == single && (*lo..=*hi).contains(&port));
        !hit(true) && hit(false)
    }
}

/// How iptables lets a connection in: the rule, a rate limit on the way, through a port range.
#[derive(Debug, PartialEq)]
struct Accepted {
    rule: String,
    limited: bool,
    range: bool,
}

impl IptRules {
    /// Whether these rules filter at all: INPUT drops what no rule accepts, or a rule it
    /// reaches drops new connections from everyone (not only some sources or rates).
    pub fn filters(&self) -> bool {
        self.input_drops || self.reachable().iter().any(|r| r.drops() && r.from.is_none() && !r.skip && !r.limit && !r.unsure)
    }

    /// For a port closed to everyone: the ACCEPT rules it reaches that let some sources in,
    /// as "ACCEPT 7946/tcp from 3 sources".
    fn accepts_some(&self, proto: Proto, port: u16) -> Option<String> {
        let rules: Vec<&IptRule> =
            self.reachable().into_iter().filter(|r| r.target == "ACCEPT" && r.from.is_some() && r.matches_port(proto, port)).collect();
        let what = rules.first()?.what().unwrap_or_else(|| "all".into());
        Some(format!("ACCEPT {what} from {}", sources(rules.iter().filter_map(|r| r.from.as_deref()))))
    }

    /// The rules of INPUT and of every chain it jumps to.
    fn reachable(&self) -> Vec<&IptRule> {
        let (mut chains, mut rules) = (vec!["INPUT"], Vec::new());
        let mut i = 0;
        while i < chains.len() {
            for r in self.chains.get(chains[i]).into_iter().flatten() {
                rules.push(r);
                if self.chains.contains_key(&r.target) && !chains.contains(&r.target.as_str()) {
                    chains.push(&r.target);
                }
            }
            i += 1;
        }
        rules
    }

    /// The rule letting a new connection from anywhere to `port` in ("ACCEPT 22/tcp",
    /// "ACCEPT 22/tcp via ssh-guard", "policy ACCEPT"); None when it is dropped.
    fn accepts(&self, proto: Proto, port: u16) -> Option<Accepted> {
        let mut limited = false;
        match self.walk("INPUT", proto, port, None, 0, &mut limited) {
            Some(verdict) => verdict.map(|(rule, range)| Accepted { rule, limited, range }),
            None if self.input_drops => None,
            None => Some(Accepted { rule: "policy ACCEPT".into(), limited, range: false }),
        }
    }

    /// Some(Some((label, through a range))): accepted; Some(None): dropped; None: through the
    /// chain (RETURN). `outer`: the jump into this chain, for an ACCEPT that matches anything.
    fn walk<'a>(
        &'a self,
        chain: &str,
        proto: Proto,
        port: u16,
        outer: Option<&'a IptRule>,
        depth: u8,
        limited: &mut bool,
    ) -> Option<Option<(String, bool)>> {
        if depth > 10 {
            return None;
        }
        for r in self.chains.get(chain)?.iter().filter(|r| r.matches(proto, port)) {
            // what it matched, or what the jump here did
            let spec = if r.proto.is_some() { Some(r) } else { outer };
            match r.target.as_str() {
                "ACCEPT" => {
                    *limited |= r.limit;
                    let via = if chain == "INPUT" { String::new() } else { format!(" via {chain}") };
                    let what = spec.and_then(IptRule::what).unwrap_or_else(|| "all".into());
                    return Some(Some((format!("ACCEPT {what}{via}"), spec.is_some_and(|s| s.by_range(port)))));
                }
                // drops above a rate only, or on a match not understood
                "DROP" | "REJECT" if r.limit || r.unsure => *limited |= r.limit,
                "DROP" | "REJECT" => return Some(None),
                "RETURN" => return None,
                // a chain of its own; LOG and other targets that don't decide go on
                other => match self.walk(other, proto, port, spec, depth + 1, limited) {
                    Some(verdict) => return Some(verdict),
                    // through a chain gone to: back to whatever called this one
                    None if r.goto => return None,
                    None => {}
                },
            }
        }
        None
    }
}

// ------------------------------------------------------------------ nftables

/// nftables filter chains on the input hook, other than the `filter` tables iptables-nft
/// keeps for iptables (read through iptables): (family, table, chain, drops by default),
/// from `nft -j list chains`.
fn nft_input_chains(json: &str) -> Vec<(String, String, String, bool)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return vec![] };
    let items = v["nftables"].as_array().map(Vec::as_slice).unwrap_or_default();
    items
        .iter()
        .filter_map(|item| {
            let field = |k: &str| item["chain"][k].as_str();
            let (family, table) = (field("family")?, field("table")?);
            if field("hook")? != "input" || field("type")? != "filter" || (matches!(family, "ip" | "ip6") && table == "filter") {
                return None;
            }
            Some((family.to_string(), table.to_string(), field("name")?.to_string(), field("policy") == Some("drop")))
        })
        .collect()
}

/// A table or chain name safe to hand back to nft, which reads its arguments as one command
/// line: a name with blanks, quotes or `;` (or one starting with `-`) is never passed on.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

/// Whether `nft -j list chain ...` output holds a rule.
fn nft_has_rules(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v["nftables"].as_array().map(|items| items.iter().any(|i| i.get("rule").is_some())))
        .unwrap_or(false)
}

// ------------------------------------------------------------------ classification

/// The firewall state a scan read.
#[derive(Clone, Copy, Debug, Default)]
pub struct FirewallView<'a> {
    /// `ufw status`; None without ufw.
    pub ufw: Option<&'a str>,
    /// `iptables -S` and `ip6tables -S` (filter table), read when ufw isn't active.
    pub iptables: Option<&'a str>,
    pub ip6tables: Option<&'a str>,
    /// nftables has filter chains of its own on the input hook that drop or hold rules.
    pub nft_input: bool,
    /// `firewall-cmd --list-all-zones`, when firewalld runs (and ufw isn't active).
    pub firewalld: Option<&'a str>,
    /// The ports of the services firewalld's zones name.
    pub firewalld_services: Option<&'a HashMap<String, Vec<String>>>,
}

/// How reachable a listener is, the rule letting it in, whether a rate limit applies, and
/// whether it is let in only through a port range (`dynamic`).
fn classify(
    key: &ListenerKey,
    process: &str,
    fw: Firewall,
    ufw: &[UfwRule],
    ipt: &[Option<IptRules>; 2],
) -> (Exposure, Option<String>, bool, bool) {
    let public = key.addr.is_unspecified() || !is_non_global(key.addr);
    if !public {
        return (Exposure::Local, None, false, false);
    }
    let action = |r: &UfwRule| format!("{} {}", if r.limit { "LIMIT" } else { "ALLOW" }, r.label);
    let open = |r: &&UfwRule| r.from.is_none() && r.matches(key.port, key.proto);
    if process == "docker-proxy" {
        // bypassing ufw either way, but a rule says it is meant to be reachable
        let rule = ufw.iter().find(open).filter(|_| fw == Firewall::Ufw).map(action);
        return (Exposure::Docker, rule, false, false);
    }
    match fw {
        Firewall::Ufw | Firewall::Firewalld => match ufw.iter().find(open) {
            Some(r) => {
                let hit = |single: bool| ufw.iter().filter(open).any(|r| (r.lo == r.hi || r.every) == single);
                (Exposure::Allowed, Some(action(r)), r.limit, !hit(true) && hit(false))
            }
            None => {
                let some: Vec<&UfwRule> = ufw.iter().filter(|r| r.from.is_some() && r.matches(key.port, key.proto)).collect();
                let rule = some.first().map(|r| format!("{} from {}", action(r), sources(some.iter().filter_map(|r| r.from.as_deref()))));
                (Exposure::Firewalled, rule, false, false)
            }
        },
        Firewall::Iptables => {
            // a socket on [::] takes IPv4 connections too: IPv4 rules (0), then IPv6 rules (1)
            let families: &[usize] = match key.addr {
                IpAddr::V4(_) => &[0],
                IpAddr::V6(a) if a.is_unspecified() => &[0, 1],
                IpAddr::V6(a) if a.to_ipv4_mapped().is_some() => &[0],
                IpAddr::V6(_) => &[1],
            };
            let mut verdict = (Exposure::Firewalled, None, false, false);
            for &f in families {
                match &ipt[f] {
                    Some(rules) => {
                        if let Some(a) = rules.accepts(key.proto, key.port) {
                            let rule = if f == 1 && families.len() > 1 { format!("{} (IPv6)", a.rule) } else { a.rule };
                            return (Exposure::Allowed, Some(rule), a.limited, a.range);
                        }
                    }
                    // no rules for that family (ip6tables missing): nothing filters it
                    None => verdict = (Exposure::Unfiltered, None, false, false),
                }
            }
            if verdict.0 == Exposure::Firewalled {
                verdict.1 = families.iter().find_map(|&f| ipt[f].as_ref()?.accepts_some(key.proto, key.port));
            }
            verdict
        }
        Firewall::Nftables | Firewall::Absent => (Exposure::Unfiltered, None, false, false),
    }
}

/// "11.38.48.86", "3 sources": who some rules let in.
fn sources<'a>(from: impl Iterator<Item = &'a str>) -> String {
    let distinct: std::collections::BTreeSet<&str> = from.collect();
    match distinct.iter().next() {
        Some(one) if distinct.len() == 1 => one.to_string(),
        _ => format!("{} sources", distinct.len()),
    }
}

/// Listeners for display: a socket on every IPv4 address (`0.0.0.0`) and its twin on
/// every IPv6 address (`[::]`) - same port, process and reachability, as Docker and sshd
/// open them - become one `*:443/tcp (v4+v6)` row. Twins that differ stay apart.
pub fn for_display(listeners: &[Listener]) -> Vec<(String, &Listener)> {
    let twin = |l: &Listener| {
        listeners.iter().find(|o| {
            o.key.addr.is_ipv6()
                && o.key.addr.is_unspecified()
                && (o.key.proto, o.key.port) == (l.key.proto, l.key.port)
                && (&o.process, o.exposure, o.dynamic, o.limited) == (&l.process, l.exposure, l.dynamic, l.limited)
        })
    };
    let paired: Vec<&Listener> =
        listeners.iter().filter(|l| l.key.addr.is_ipv4() && l.key.addr.is_unspecified()).filter_map(twin).collect();
    listeners
        .iter()
        .filter(|l| !paired.iter().any(|p| std::ptr::eq(*p, *l)))
        .map(|l| {
            let both = l.key.addr.is_ipv4() && l.key.addr.is_unspecified() && twin(l).is_some();
            let p = if l.key.proto == Proto::Udp { "udp" } else { "tcp" };
            (if both { format!("*:{}/{p} (v4+v6)", l.key.port) } else { l.key.to_string() }, l)
        })
        .collect()
}

/// Builds a report from raw inputs (pure; used by `scan` and the tests). An active ufw is
/// what filters; without one, iptables' INPUT chain if it filters anything; else nftables
/// chains of their own on the input hook; else nothing.
pub fn build_report(
    now: Micros,
    sockets: Vec<(ListenerKey, u64)>,
    owners: &HashMap<u64, String>,
    fw: &FirewallView,
    ignore: &[PortSpec],
) -> ExposureReport {
    let ufw = fw.ufw.map(parse_ufw_status);
    let ipt = [fw.iptables.map(parse_iptables), fw.ip6tables.map(parse_iptables)];
    let no_services = HashMap::new();
    let firewalld = fw.firewalld.map(|t| firewalld_rules(&parse_firewalld_zones(t), fw.firewalld_services.unwrap_or(&no_services)));
    let firewall = match (&ufw, &firewalld) {
        (Some((true, _)), _) => Firewall::Ufw,
        (_, Some(_)) => Firewall::Firewalld,
        _ if ipt.iter().flatten().any(IptRules::filters) => Firewall::Iptables,
        _ if fw.nft_input => Firewall::Nftables,
        _ => Firewall::Absent,
    };
    let (rules, explicit): (&[UfwRule], &[UfwRule]) = match (&ufw, &firewalld) {
        (Some((true, rules)), _) => (rules, rules),
        (_, Some((rules, explicit))) if firewall == Firewall::Firewalld => (rules, explicit),
        _ => (&[], &[]),
    };
    let mut listeners: Vec<Listener> = sockets
        .into_iter()
        .filter(|(k, _)| !ignore.iter().any(|i| i.matches(k.port, k.proto)))
        .map(|(key, inode)| {
            let process = owners.get(&inode).cloned().unwrap_or_else(|| "?".into());
            let (exposure, rule, limited, dynamic) = classify(&key, &process, firewall, rules, &ipt);
            Listener { key, process, exposure, dynamic, rule, limited, honeypot: false }
        })
        .collect();
    listeners.sort_by_key(|l| l.key);
    listeners.dedup_by_key(|l| l.key);

    let mut dead_rules = Vec::new();
    for r in explicit.iter().filter(|r| r.from.is_none() && r.lo == r.hi && !ignore.iter().any(|i| i.port == r.lo)) {
        let served = listeners.iter().any(|l| l.exposure != Exposure::Local && r.matches(l.key.port, l.key.proto));
        if !served && !dead_rules.contains(&r.label) {
            dead_rules.push(r.label.clone());
        }
    }
    ExposureReport { scanned: now, ufw_active: ufw.map(|(a, _)| a), firewall: Some(firewall), listeners, dead_rules }
}

/// `ufw status`, re-run only when ufw's rule or config files change (or every 10 minutes):
/// ufw is a Python program, too heavy to start every scan interval.
fn ufw_status(ufw: &Path) -> Option<String> {
    use std::sync::Mutex;
    use std::time::{Instant, SystemTime};
    type Cache = (Vec<Option<SystemTime>>, Instant, Option<String>);
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    if ufw.as_os_str().is_empty() || !ufw.exists() {
        return None;
    }
    let stamps: Vec<Option<SystemTime>> = ["/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf", "/etc/default/ufw"]
        .iter()
        .map(|f| std::fs::metadata(f).and_then(|m| m.modified()).ok())
        .collect();
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((s, at, text)) = cache.as_ref() {
        if *s == stamps && at.elapsed() < std::time::Duration::from_secs(600) {
            return text.clone();
        }
    }
    let mut cmd = Command::new(ufw);
    cmd.arg("status");
    let out = crate::proc::run(cmd, None, std::time::Duration::from_secs(30)).ok()?;
    let text = out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned());
    *cache = Some((stamps, Instant::now(), text.clone()));
    text
}

/// firewalld's zones and their services' ports, when it runs. firewall-cmd is a Python
/// program talking to firewalld over D-Bus, too heavy to start every scan: re-read every 5
/// minutes, or when a file in /etc/firewalld changes.
fn firewalld_state(firewall_cmd: &Path) -> Option<(String, HashMap<String, Vec<String>>)> {
    use std::sync::Mutex;
    use std::time::{Instant, SystemTime};
    type Cache = (Option<SystemTime>, Instant, Option<(String, HashMap<String, Vec<String>>)>);
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    if firewall_cmd.as_os_str().is_empty() || !firewall_cmd.exists() {
        return None;
    }
    let stamp = ["/etc/firewalld", "/etc/firewalld/zones", "/etc/firewalld/services"]
        .iter()
        .filter_map(|d| std::fs::metadata(d).and_then(|m| m.modified()).ok())
        .max();
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((s, at, state)) = cache.as_ref() {
        if *s == stamp && at.elapsed() < std::time::Duration::from_secs(300) {
            return state.clone();
        }
    }
    // fails (exit 252) while firewalld isn't running
    let state = output_of(firewall_cmd, &["--list-all-zones"]).map(|text| {
        let zones = parse_firewalld_zones(&text);
        let services = firewalld_service_ports(&zones, &[Path::new("/etc/firewalld/services"), Path::new("/usr/lib/firewalld/services")]);
        (text, services)
    });
    *cache = Some((stamp, Instant::now(), state.clone()));
    state
}

/// A command's output, None where the program is missing or fails.
fn output_of(program: &Path, args: &[&str]) -> Option<String> {
    if program.as_os_str().is_empty() || !program.exists() {
        return None;
    }
    let mut cmd = Command::new(program);
    cmd.args(args);
    let out = crate::proc::run(cmd, None, std::time::Duration::from_secs(30)).ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether nftables has filter chains of its own on the input hook that drop by default or
/// hold rules (Debian's stock `inet filter` table, empty and accepting, doesn't count).
fn nft_filters_input(nft: &Path) -> bool {
    let Some(chains) = output_of(nft, &["-j", "list", "chains"]) else { return false };
    nft_input_chains(&chains).iter().any(|(family, table, chain, drops)| {
        // one that can't be listed safely counts as filtering
        *drops
            || ![family, table, chain].iter().all(|n| plain_name(n))
            || output_of(nft, &["-j", "list", "chain", family, table, chain]).is_some_and(|t| nft_has_rules(&t))
    })
}

/// Marks logguard's own listeners on the honeypot ports (another program there is no honeypot).
pub fn mark_honeypots(r: &mut ExposureReport, ports: &[u16]) {
    for l in &mut r.listeners {
        l.honeypot = l.key.proto == Proto::Tcp && ports.contains(&l.key.port) && l.process == "logguard";
    }
}

/// Scans the live system (Linux only), reading the firewall with the programs of `[enforce]`;
/// `honeypots` are logguard's own honeypot ports.
pub fn scan(cfg: &ExposureCfg, tools: &crate::config::EnforceCfg, honeypots: &[u16]) -> Result<ExposureReport> {
    let mut sockets = Vec::new();
    for (file, proto) in [("tcp", Proto::Tcp), ("tcp6", Proto::Tcp), ("udp", Proto::Udp), ("udp6", Proto::Udp)] {
        let path = format!("/proc/net/{file}");
        match std::fs::read_to_string(&path) {
            Ok(text) => sockets.extend(parse_proc_net(&text, proto)),
            Err(e) if file.ends_with('6') => {
                let _ = e; // IPv6 disabled
            }
            Err(e) => return Err(e).with_context(|| format!("reading {path}")),
        }
    }
    let owners = socket_owners();
    let ufw = ufw_status(&cfg.ufw);
    // without an active ufw: firewalld's zones, else iptables' filter table, else nftables
    // chains of their own
    let ufw_active = ufw.as_deref().is_some_and(|t| parse_ufw_status(t).0);
    let firewalld = if ufw_active { None } else { firewalld_state(&tools.firewall_cmd) };
    let (v4, v6) = if ufw_active || firewalld.is_some() {
        (None, None)
    } else {
        (output_of(&tools.iptables, &["-w", "10", "-S"]), output_of(&tools.ip6tables, &["-w", "10", "-S"]))
    };
    let filtering = [&v4, &v6].iter().any(|t| t.as_deref().is_some_and(|t| parse_iptables(t).filters()));
    let fw = FirewallView {
        ufw: ufw.as_deref(),
        iptables: v4.as_deref(),
        ip6tables: v6.as_deref(),
        nft_input: !ufw_active && firewalld.is_none() && !filtering && nft_filters_input(&tools.nft),
        firewalld: firewalld.as_ref().map(|(t, _)| t.as_str()),
        firewalld_services: firewalld.as_ref().map(|(_, s)| s),
    };
    let mut r = build_report(time::now(), sockets, &owners, &fw, &cfg.ignore);
    mark_honeypots(&mut r, honeypots);
    Ok(r)
}

#[cfg(test)]
mod tests {
    #[test]
    // /proc/net fixtures as a little-endian kernel prints them (x86_64, ARM)
    #[cfg(target_endian = "little")]
    fn v4_and_v6_twins_shown_once() {
        let l = |addr: &str, port, proto, process: &str, exposure| Listener {
            key: ListenerKey { proto, addr: addr.parse().unwrap(), port },
            process: process.into(),
            exposure,
            dynamic: false,
            rule: None,
            limited: false,
            honeypot: false,
        };
        let all = vec![
            l("0.0.0.0", 443, Proto::Tcp, "docker-proxy", Exposure::Docker),
            l("::", 443, Proto::Tcp, "docker-proxy", Exposure::Docker),
            l("::", 443, Proto::Udp, "docker-proxy", Exposure::Docker),
            l("0.0.0.0", 22, Proto::Tcp, "sshd", Exposure::Allowed),
            l("::", 22, Proto::Tcp, "sshd", Exposure::Firewalled),
            l("::", 5222, Proto::Tcp, "beam.smp", Exposure::Allowed),
            l("127.0.0.1", 8080, Proto::Tcp, "docker-proxy", Exposure::Local),
        ];
        let names: Vec<String> = for_display(&all).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            ["*:443/tcp (v4+v6)", "[::]:443/udp", "0.0.0.0:22/tcp", "[::]:22/tcp", "[::]:5222/tcp", "127.0.0.1:8080/tcp"],
            "twins merged; a v6 socket without a v4 twin, or one that differs, stays apart"
        );
    }

    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:4651 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 1002 1 0000000000000000 100 0 0 10 0
   2: 00000000:CA6D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 100 0 0 10 0
   3: 0A0200C0:4651 0B6433C6:A1F2 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 100 0 0 10 0
";
    const UDP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000000000000000000000000000:D471 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2001 2 0000000000000000 0
";
    const UFW: &str = "Status: active

To                         Action      From
--                         ------      ----
53/udp                     LIMIT       Anywhere                   # DNS
2222/tcp                  LIMIT       Anywhere                   # SSH
51820/udp                  LIMIT       Anywhere                   # WG VPN
49152:65535/udp            ALLOW       Anywhere                   # relay
5349/tcp                   ALLOW       Anywhere                   # TURNS
OpenSSH                    ALLOW       Anywhere
Anywhere                   DENY        11.35.0.0/16              # blocked
Anywhere                   ALLOW       11.48.43.31
2222/tcp (v6)             LIMIT       Anywhere (v6)              # SSH
";

    #[test]
    fn proc_net_parsing() {
        let tcp = parse_proc_net(TCP, Proto::Tcp);
        let keys: Vec<String> = tcp.iter().map(|(k, _)| k.to_string()).collect();
        assert_eq!(keys, vec!["0.0.0.0:18001/tcp", "127.0.0.53:53/tcp", "0.0.0.0:51821/tcp"]);
        let udp = parse_proc_net(UDP6, Proto::Udp);
        assert_eq!(udp[0].0.to_string(), "[::]:54385/udp");
        assert_eq!(udp[0].1, 2001);
    }

    #[test]
    fn ufw_rules_from_anywhere_only() {
        let (active, rules) = parse_ufw_status(UFW);
        assert!(active);
        let labels: Vec<&str> = rules.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["53/udp", "2222/tcp", "51820/udp", "49152:65535/udp", "5349/tcp"]);
    }

    #[test]
    fn report_flags_docker_dead_rules_and_unfiltered() {
        let key = |addr: &str, port, proto| ListenerKey { addr: addr.parse().unwrap(), port, proto };
        let sockets = vec![
            (key("0.0.0.0", 2222, Proto::Tcp), 1),
            (key("127.0.0.53", 53, Proto::Udp), 2),
            (key("0.0.0.0", 51820, Proto::Udp), 3),
            (key("0.0.0.0", 4369, Proto::Tcp), 4),
            (key("172.17.0.1", 53, Proto::Udp), 5),
            (key("0.0.0.0", 5349, Proto::Tcp), 6),
            (key("0.0.0.0", 50123, Proto::Udp), 7),
        ];
        let owners: HashMap<u64, String> =
            [(1, "sshd"), (2, "systemd-resolve"), (3, "docker-proxy"), (4, "epmd"), (5, "unbound"), (6, "turnserver"), (7, "turnserver")]
                .map(|(i, n)| (i, n.to_string()))
                .into();
        let r = build_report(0, sockets.clone(), &owners, &FirewallView { ufw: Some(UFW), ..Default::default() }, &[]);
        let exp: Vec<(String, Exposure)> = r.listeners.iter().map(|l| (l.key.to_string(), l.exposure)).collect();
        assert!(exp.contains(&("0.0.0.0:2222/tcp".into(), Exposure::Allowed)));
        assert!(exp.contains(&("0.0.0.0:51820/udp".into(), Exposure::Docker)));
        assert!(exp.contains(&("0.0.0.0:4369/tcp".into(), Exposure::Firewalled)));
        assert!(exp.contains(&("127.0.0.53:53/udp".into(), Exposure::Local)));
        assert!(exp.contains(&("172.17.0.1:53/udp".into(), Exposure::Local)), "docker bridge address is private");
        assert_eq!(r.dead_rules, vec!["53/udp"], "only a loopback resolver listens on 53; ranges are never 'dead'");
        let turn = |port| r.listeners.iter().find(|l| l.key.port == port).unwrap();
        assert!(turn(50123).dynamic && turn(50123).exposure == Exposure::Allowed, "TURN relay socket inside the allowed range");
        assert!(!turn(5349).dynamic, "TURNS listener has its own rule");
        assert!(!turn(2222).dynamic);
        // the rule letting each in, and whether it only rate-limits
        let rule = |port| (turn(port).rule.as_deref(), turn(port).limited, turn(port).describe(r.firewall()));
        assert_eq!(rule(2222), (Some("LIMIT 2222/tcp"), true, "allowed by ufw, rate-limited".into()));
        assert_eq!(rule(5349), (Some("ALLOW 5349/tcp"), false, "allowed by ufw".into()));
        assert_eq!(rule(50123), (Some("ALLOW 49152:65535/udp"), false, "allowed by ufw".into()));
        assert_eq!(rule(4369), (None, false, "blocked by ufw".into()));
        assert_eq!(
            rule(51820),
            (Some("LIMIT 51820/udp"), false, "published by docker, bypasses ufw".into()),
            "a rule docker bypasses anyway, but meant"
        );

        let none = build_report(0, sockets, &owners, &FirewallView::default(), &["4369".parse().unwrap()]);
        assert!(none.listeners.iter().all(|l| l.key.port != 4369), "ignored port");
        assert_eq!(none.listeners.iter().find(|l| l.key.port == 2222).unwrap().exposure, Exposure::Unfiltered);
        assert!(none.dead_rules.is_empty());
        assert_eq!(none.firewall(), Firewall::Absent);
        let l = none.listeners.iter().find(|l| l.key.port == 2222).unwrap();
        assert_eq!((l.describe(none.firewall()), none.firewall_summary().as_str()), ("no firewall".into(), "NO FIREWALL"));
    }

    #[test]
    fn rules_for_some_sources_and_docker_ports() {
        // a node with the cluster port open to the peers only, Nextcloud published by docker
        let ufw = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n\
            9847/tcp                   LIMIT IN    Anywhere                   # SSH\n\
            443/tcp                    ALLOW IN    Anywhere                   # Nextcloud\n\
            7946/tcp                   ALLOW IN    11.38.48.86               # logguard cluster\n\
            7946/tcp                   ALLOW IN    11.8.39.73                # logguard cluster\n\
            7946/tcp                   ALLOW IN    11.29.39.236              # logguard cluster\n\
            9847/tcp (v6)              LIMIT IN    Anywhere (v6)              # SSH\n";
        let key = |port, proto| ListenerKey { addr: "0.0.0.0".parse().unwrap(), port, proto };
        let sockets = vec![(key(7946, Proto::Tcp), 1), (key(443, Proto::Tcp), 2), (key(8443, Proto::Tcp), 2), (key(5355, Proto::Tcp), 3)];
        let owners: HashMap<u64, String> =
            [(1, "logguard"), (2, "docker-proxy"), (3, "systemd-resolve")].map(|(i, n)| (i, n.to_string())).into();
        let r = build_report(0, sockets, &owners, &FirewallView { ufw: Some(ufw), ..Default::default() }, &[]);
        let get = |port| {
            let l = r.listeners.iter().find(|l| l.key.port == port).unwrap();
            (l.exposure, l.rule.clone(), r.describe(l))
        };
        assert_eq!(
            get(7946),
            (Exposure::Firewalled, Some("ALLOW 7946/tcp from 3 sources".into()), "allowed by ufw from some sources only".into()),
            "open to the peers, not to the internet: no exposure alerts"
        );
        assert_eq!(get(443), (Exposure::Docker, Some("ALLOW 443/tcp".into()), "published by docker, bypasses ufw".into()));
        assert_eq!(get(8443), (Exposure::Docker, None, "published by docker, bypasses ufw".into()));
        let docker = |port| r.listeners.iter().find(|l| l.key.port == port).unwrap().rule_text(Firewall::Ufw);
        assert_eq!((docker(443).as_deref(), docker(8443).as_deref()), (Some("ALLOW 443/tcp"), Some("none: containers blocked")));
        assert_eq!(get(5355), (Exposure::Firewalled, None, "blocked by ufw".into()));
        assert_eq!(r.dead_rules, ["9847/tcp"], "no sshd in this test; rules for some sources are never dead");
        let one = parse_ufw_status(&ufw.replace("11.8.39.73", "11.38.48.86").replace("11.29.39.236", "11.38.48.86")).1;
        let r = build_report(0, vec![(key(7946, Proto::Tcp), 1)], &owners, &FirewallView { ufw: Some(ufw), ..Default::default() }, &[]);
        assert!(r.listeners[0].rule.as_deref().is_some_and(|x| x.ends_with("3 sources")));
        assert_eq!(sources(one.iter().filter_map(|r| r.from.as_deref())), "11.38.48.86");

        // the same with iptables: an ACCEPT for the peers' set, closed by the policy otherwise
        let ipt = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 7946 -m set --match-set peers src -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n";
        let rules = parse_iptables(ipt);
        assert!(rules.accepts(Proto::Tcp, 7946).is_none());
        assert_eq!(rules.accepts_some(Proto::Tcp, 7946).as_deref(), Some("ACCEPT 7946/tcp from set peers"));
        assert_eq!(rules.accepts_some(Proto::Tcp, 22), None, "open to all: not 'some'");
    }

    // a host with plain iptables (iptables-persistent), no ufw
    const IPTABLES: &str = r#"-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER-USER
-N ssh-guard
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -s 203.0.113.7/32 -j ACCEPT
-A INPUT -i docker0 -j ACCEPT
-A INPUT -m addrtype --dst-type BROADCAST -j DROP
-A INPUT -p tcp -m tcp --dport 22 -j LOG --log-prefix "ssh: "
-A INPUT -p tcp -m tcp --dport 22 -j ssh-guard
-A INPUT -p tcp -m multiport --dports 80,443 -m comment --comment "web \"front\" door" -j ACCEPT
-A INPUT -p udp -m udp --dport 50000:50100 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3306 -j REJECT --reject-with tcp-reset
-A INPUT -p icmp -j ACCEPT
-A ssh-guard -m recent --set --name ssh --mask 255.255.255.255 --rsource
-A ssh-guard -m recent --update --seconds 60 --hitcount 4 --name ssh --mask 255.255.255.255 --rsource -j DROP
-A ssh-guard -j ACCEPT
-A DOCKER-USER -j RETURN
"#;

    #[test]
    fn iptables_rules_read_like_the_kernel() {
        let rules = parse_iptables(IPTABLES);
        assert!(rules.filters());
        let acc = |rule: &str, limited, range| Some(Accepted { rule: rule.into(), limited, range });
        assert_eq!(rules.accepts(Proto::Tcp, 22), acc("ACCEPT 22/tcp via ssh-guard", true, false), "recent: rate-limited");
        assert_eq!(rules.accepts(Proto::Tcp, 443), acc("ACCEPT 80,443/tcp", false, false));
        assert_eq!(rules.accepts(Proto::Udp, 50050), acc("ACCEPT 50000:50100/udp", false, true), "through a range: dynamic");
        assert_eq!(rules.accepts(Proto::Udp, 443), None, "the web rule is tcp only");
        assert_eq!(rules.accepts(Proto::Tcp, 3306), None, "rejected");
        assert_eq!(rules.accepts(Proto::Tcp, 8080), None, "dropped by the policy; source, loopback and docker0 rules don't count");
        assert_eq!(shell_words(r#"-m comment --comment "web \"front\" door" -j ACCEPT"#)[3], r#"web "front" door"#);

        // what only blocks some sources, states or rates isn't a firewall
        let open = parse_iptables(
            "-P INPUT ACCEPT\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n-A INPUT -m conntrack --ctstate INVALID -j DROP\n\
             -A f2b-sshd -s 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable\n-A f2b-sshd -j RETURN\n\
             -A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP\n",
        );
        assert!(!open.filters());
        assert_eq!(open.accepts(Proto::Tcp, 22), acc("policy ACCEPT", false, false));
        // one port closed: the rest open by the policy
        let one = parse_iptables("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 25 -j DROP\n");
        assert!(one.filters());
        assert_eq!((one.accepts(Proto::Tcp, 25), one.accepts(Proto::Tcp, 26)), (None, acc("policy ACCEPT", false, false)));
        // a match this parser doesn't know: the ACCEPT counts, the DROP doesn't
        let odd = parse_iptables(
            "-P INPUT DROP\n-A INPUT -p tcp --dport 8443 -m quota --quota 100 -j ACCEPT\n-A INPUT -p tcp -m u32 --u32 0x1 -j DROP\n",
        );
        assert!(odd.accepts(Proto::Tcp, 8443).is_some());
        assert_eq!(odd.accepts(Proto::Tcp, 9000), None, "the policy drops it");
        // to a private address: where a cloud host's public address is NATed to; loopback isn't
        let nat = parse_iptables(
            "-P INPUT DROP\n-A INPUT -d 127.0.0.0/8 -j ACCEPT\n-A INPUT -d 10.0.0.5/32 -p tcp -m tcp --dport 22 -j ACCEPT\n",
        );
        assert_eq!(nat.accepts(Proto::Tcp, 22), acc("ACCEPT 22/tcp", false, false));
        assert_eq!(nat.accepts(Proto::Tcp, 80), None);
        // -g: what falls through the chain gone to ends at INPUT's policy, unlike -j
        let goto =
            "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -g g22\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A g22 -s 1.2.3.4/32 -j ACCEPT\n";
        assert_eq!(parse_iptables(goto).accepts(Proto::Tcp, 22), None);
        assert!(parse_iptables(&goto.replace("-g g22", "-j g22")).accepts(Proto::Tcp, 22).is_some());
    }

    #[test]
    fn report_with_iptables_or_without_any_firewall() {
        let key = |addr: &str, port, proto| ListenerKey { addr: addr.parse().unwrap(), port, proto };
        let sockets = vec![
            (key("0.0.0.0", 22, Proto::Tcp), 1),
            (key("0.0.0.0", 8080, Proto::Tcp), 2),
            (key("::", 8080, Proto::Tcp), 2),
            (key("3fff:130::1", 9000, Proto::Tcp), 3),
            (key("0.0.0.0", 443, Proto::Tcp), 4),
            (key("127.0.0.1", 3306, Proto::Tcp), 5),
            (key("0.0.0.0", 50050, Proto::Udp), 6),
        ];
        let owners: HashMap<u64, String> = [(1, "sshd"), (2, "app"), (3, "app6"), (4, "docker-proxy"), (5, "mariadbd"), (6, "turnserver")]
            .map(|(i, n)| (i, n.to_string()))
            .into();
        let v6_open = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
        let fw = FirewallView { ufw: Some("Status: inactive\n"), iptables: Some(IPTABLES), ip6tables: Some(v6_open), ..Default::default() };
        let r = build_report(0, sockets.clone(), &owners, &fw, &[]);
        assert_eq!((r.firewall(), r.firewall_summary().as_str()), (Firewall::Iptables, "iptables (ufw inactive)"));
        let get = |addr: &str, port| {
            let l = r.listeners.iter().find(|l| l.key.addr == addr.parse::<IpAddr>().unwrap() && l.key.port == port).unwrap();
            (l.exposure, l.rule.clone(), l.describe(Firewall::Iptables))
        };
        assert_eq!(
            get("0.0.0.0", 22),
            (Exposure::Allowed, Some("ACCEPT 22/tcp via ssh-guard".into()), "allowed by iptables, rate-limited".into())
        );
        // closed to everyone but the address one rule accepts everything from
        let from_one =
            (Exposure::Firewalled, Some("ACCEPT all from 203.0.113.7".into()), "allowed by iptables from some sources only".into());
        assert_eq!(get("0.0.0.0", 8080), from_one);
        // IPv4 is closed, IPv6 isn't filtered at all
        assert_eq!(get("::", 8080), (Exposure::Allowed, Some("policy ACCEPT (IPv6)".into()), "allowed by iptables".into()));
        assert_eq!(get("3fff:130::1", 9000).1.as_deref(), Some("policy ACCEPT"));
        assert_eq!(get("0.0.0.0", 443).2, "published by docker, bypasses iptables");
        let relay = r.listeners.iter().find(|l| l.key.port == 50050).unwrap();
        assert!(relay.dynamic && relay.exposure == Exposure::Allowed, "a relay let in through a port range: no new/gone alerts");
        assert!(!r.listeners.iter().find(|l| l.key.port == 22).unwrap().dynamic);
        assert_eq!(get("127.0.0.1", 3306).0, Exposure::Local);
        assert!(r.dead_rules.is_empty(), "dead rules are ufw's");
        // no ip6tables: IPv6 is open
        let r = build_report(0, sockets.clone(), &owners, &FirewallView { ip6tables: None, ..fw }, &[]);
        let l = r.listeners.iter().find(|l| l.key.port == 9000).unwrap();
        assert_eq!((l.exposure, l.describe(r.firewall())), (Exposure::Unfiltered, "no ip6tables rules: open over IPv6".into()));

        // nothing filters: ufw inactive, iptables accepting everything
        let fw = FirewallView { iptables: Some(v6_open), ip6tables: Some(v6_open), ..fw };
        let r = build_report(0, sockets.clone(), &owners, &fw, &[]);
        assert_eq!((r.firewall(), r.firewall_summary().as_str()), (Firewall::Absent, "NO FIREWALL (ufw inactive)"));
        assert!(r.listeners.iter().filter(|l| l.key.port != 3306).all(|l| l.exposure.is_exposed()));
        assert!(r.firewall_checked());
        // nftables rules of their own: not read, but not "no firewall" either
        let r = build_report(0, sockets, &owners, &FirewallView { nft_input: true, ..fw }, &[]);
        assert_eq!(r.firewall(), Firewall::Nftables);
        assert_eq!(r.listeners[0].describe(Firewall::Nftables), "public, nftables rules not read");

        // a report from before the firewall was named
        let old: ExposureReport = serde_json::from_str(r#"{"scanned":0,"ufw_active":true,"listeners":[],"dead_rules":[]}"#).unwrap();
        assert_eq!(old.firewall(), Firewall::Ufw);
        assert!(old.firewall_checked());
        // ... where ufw wasn't active, it never looked at iptables: no "NO FIREWALL" claim
        let old: ExposureReport = serde_json::from_str(r#"{"scanned":0,"ufw_active":null,"listeners":[],"dead_rules":[]}"#).unwrap();
        assert!(!old.firewall_checked());
        assert_eq!(old.firewall_summary(), "ufw not active, iptables not checked: restart the daemon");
    }

    #[test]
    fn nftables_input_chains() {
        let chains = r#"{"nftables": [{"metainfo": {"version": "1.1.1"}},
            {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "inet", "table": "logguard", "name": "pre", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -300, "policy": "accept"}},
            {"chain": {"family": "inet", "table": "firewalld", "name": "filter_INPUT", "handle": 9, "type": "filter", "hook": "input", "prio": 10, "policy": "drop"}},
            {"chain": {"family": "inet", "table": "firewalld", "name": "filter_IN_public", "handle": 10}}]}"#;
        let found: Vec<(String, String, String, bool)> = nft_input_chains(chains);
        let found: Vec<(&str, &str, &str, bool)> = found.iter().map(|(f, t, c, d)| (f.as_str(), t.as_str(), c.as_str(), *d)).collect();
        assert_eq!(
            found,
            [("inet", "filter", "input", false), ("inet", "firewalld", "filter_INPUT", true)],
            "iptables-nft's own and logguard's left out"
        );
        let empty = r#"{"nftables": [{"metainfo": {}}, {"chain": {"family": "inet", "table": "filter", "name": "input"}}]}"#;
        let ruled = r#"{"nftables": [{"chain": {"name": "input"}}, {"rule": {"family": "inet", "chain": "input", "expr": []}}]}"#;
        assert!(!nft_has_rules(empty) && nft_has_rules(ruled) && !nft_has_rules("not json"));
        // names nft would read as more commands or options are never handed back to it
        assert!(plain_name("filter") && plain_name("filter_IN_public") && plain_name("inet"));
        assert!(!plain_name("x; flush ruleset") && !plain_name("-f") && !plain_name("a b") && !plain_name("") && !plain_name("\"q\""));
    }

    /// `firewall-cmd --list-all-zones` of a Fedora server: the default zone with services,
    /// ports and rich rules, a zone for an internal network, Docker's zone, and logguard's.
    const ZONES: &str = "docker (active)
  target: ACCEPT
  icmp-block-inversion: no
  interfaces: br-1a2b docker0
  sources: 
  services: 
  ports: 
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 

logguard (active)
  target: DROP
  interfaces: 
  sources: ipset:logguard-ban4 ipset:logguard-ban6
  services: 
  ports: 443/tcp
  rich rules: 

public (default, active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources: 
  services: cockpit dhcpv6-client ssh
  ports: 8443/tcp 60000-61000/udp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
\trule family=\"ipv4\" source address=\"198.51.100.7\" port port=\"7946\" protocol=\"tcp\" accept
\trule family=\"ipv4\" port port=\"5222\" protocol=\"tcp\" log prefix=\"xmpp\" accept limit value=\"30/m\"
\trule family=\"ipv4\" source address=\"203.0.113.0/24\" port port=\"25\" protocol=\"tcp\" reject

trusted
  target: ACCEPT
  interfaces: 
  sources: 
  services: 

work (active)
  target: default
  interfaces: 
  sources: 10.0.0.0/8
  services: 
  ports: 6379/tcp
  rich rules: 
";

    #[test]
    fn firewalld_zones_and_services() {
        let zones = parse_firewalld_zones(ZONES);
        assert_eq!(zones.iter().map(|z| z.name.as_str()).collect::<Vec<_>>(), ["docker", "logguard", "public", "trusted", "work"]);
        let public = &zones[2];
        assert!(public.default && !zones[0].default);
        assert_eq!((public.target.as_str(), public.interfaces.as_slice()), ("default", &["eth0".to_string()][..]));
        assert_eq!(public.services, ["cockpit", "dhcpv6-client", "ssh"]);
        assert_eq!(public.ports, ["8443/tcp", "60000-61000/udp"]);
        assert_eq!(public.rich_rules.len(), 3);
        assert_eq!(zones[4].sources, ["10.0.0.0/8"]);

        let (ports, includes) = parse_firewalld_service(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<service>\n  <short>SSH</short>\n  <port protocol=\"tcp\" port=\"22\"/>\n  <include service=\"ssh-extra\"/>\n</service>\n",
        );
        assert_eq!((ports, includes), (vec!["22/tcp".to_string()], vec!["ssh-extra".to_string()]));

        // service files: /etc first, includes followed; unsafe or unknown names have none
        let dir = std::env::temp_dir().join(format!("logguard-fwd-services-{}", std::process::id()));
        let (etc, lib) = (dir.join("etc"), dir.join("lib"));
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("ssh.xml"), "<service><port protocol=\"tcp\" port=\"22\"/></service>").unwrap();
        std::fs::write(etc.join("ssh.xml"), "<service><port protocol=\"tcp\" port=\"2222\"/><include service=\"cockpit\"/></service>")
            .unwrap();
        std::fs::write(lib.join("cockpit.xml"), "<service><port protocol=\"tcp\" port=\"9090\"/></service>").unwrap();
        let mut odd = zones.clone();
        odd[2].services.push("../../etc/passwd".into());
        let services = firewalld_service_ports(&odd, &[&etc, &lib]);
        assert_eq!(services["ssh"], ["2222/tcp", "9090/tcp"]);
        assert_eq!(services["cockpit"], ["9090/tcp"]);
        assert!(services["dhcpv6-client"].is_empty());
        assert!(!services.contains_key("../../etc/passwd"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn firewalld_exposure() {
        let services: HashMap<String, Vec<String>> =
            [("ssh", vec!["22/tcp"]), ("cockpit", vec!["9090/tcp"]), ("dhcpv6-client", vec!["546/udp"])]
                .map(|(n, p)| (n.to_string(), p.into_iter().map(String::from).collect()))
                .into();
        let key = |port, proto| ListenerKey { addr: "0.0.0.0".parse().unwrap(), port, proto };
        let ports = [22, 9090, 5432, 6379, 7946, 5222, 443, 3000];
        let mut sockets: Vec<(ListenerKey, u64)> = ports.iter().map(|&p| (key(p, Proto::Tcp), u64::from(p))).collect();
        sockets.push((key(60123, Proto::Udp), 60123));
        let owners: HashMap<u64, String> =
            sockets.iter().map(|(_, i)| (*i, if *i == 3000 { "docker-proxy".to_string() } else { "x".to_string() })).collect();
        let fw = FirewallView { firewalld: Some(ZONES), firewalld_services: Some(&services), ..Default::default() };
        let r = build_report(0, sockets, &owners, &fw, &[]);
        assert_eq!(r.firewall(), Firewall::Firewalld);
        assert_eq!(r.firewall_summary(), "firewalld running");
        let get = |port: u16| {
            let l = r.listeners.iter().find(|l| l.key.port == port).unwrap();
            (l.exposure, l.rule.clone(), l.limited, l.dynamic)
        };
        assert_eq!(get(22), (Exposure::Allowed, Some("ALLOW ssh (public)".into()), false, false));
        assert_eq!(get(9090), (Exposure::Allowed, Some("ALLOW cockpit (public)".into()), false, false));
        assert_eq!(get(5432), (Exposure::Firewalled, None, false, false), "nothing opens it");
        assert_eq!(get(6379), (Exposure::Firewalled, Some("ALLOW 6379/tcp (work) from 10.0.0.0/8".into()), false, false));
        assert_eq!(get(7946), (Exposure::Firewalled, Some("ALLOW rich rule 7946/tcp (public) from 198.51.100.7".into()), false, false));
        assert_eq!(get(5222), (Exposure::Allowed, Some("LIMIT rich rule 5222/tcp (public)".into()), true, false));
        assert_eq!(get(443).0, Exposure::Firewalled, "logguard's zone lets in only banned sources' whitelisted ports");
        assert_eq!(get(60123), (Exposure::Allowed, Some("ALLOW 60000-61000/udp (public)".into()), false, true), "a range: short-lived");
        assert_eq!(get(3000).0, Exposure::Docker);
        let l = r.listeners.iter().find(|l| l.key.port == 5432).unwrap();
        assert_eq!(r.describe(l), "blocked by firewalld");
        assert_eq!(r.dead_rules, ["8443/tcp (public)"], "a port opened by hand that nothing serves; services never count");
        // Docker's zone (bridges only) doesn't open everything; a public zone with target ACCEPT does
        let open = ZONES.replace("interfaces: br-1a2b docker0", "interfaces: br-1a2b docker0 eth1");
        let r = build_report(0, vec![(key(5432, Proto::Tcp), 1)], &owners, &FirewallView { firewalld: Some(&open), ..fw }, &[]);
        assert_eq!(
            (r.listeners[0].exposure, r.listeners[0].rule.as_deref(), r.listeners[0].dynamic),
            (Exposure::Allowed, Some("ALLOW target ACCEPT (docker)"), false)
        );
        // an active ufw is what filters, even with firewalld's zones read
        let r = build_report(0, vec![(key(22, Proto::Tcp), 1)], &owners, &FirewallView { ufw: Some(UFW), ..fw }, &[]);
        assert_eq!(r.firewall(), Firewall::Ufw);
        // logguard's honeypot behind firewalld: firewalld's command to open it
        let hp = Listener {
            key: key(2222, Proto::Tcp),
            process: "logguard".into(),
            exposure: Exposure::Firewalled,
            dynamic: false,
            rule: None,
            limited: false,
            honeypot: true,
        };
        assert!(hp.describe(Firewall::Firewalld).contains("firewall-cmd --permanent --add-port=2222/tcp"));
    }
}
