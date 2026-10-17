//! Exposure watch: which sockets are reachable from the internet, and do the
//! firewall rules still match reality?
//!
//! Every interval the daemon reads the listening sockets from `/proc/net/{tcp,udp}{,6}`
//! (no `ss` subprocess), maps them to processes via `/proc/<pid>/fd`, and compares
//! them with `ufw status`. Ports published by Docker show up as `docker-proxy`
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
    /// Public address, but UFW does not allow the port.
    Firewalled,
    /// Public and allowed by a UFW rule from anywhere.
    Allowed,
    /// Published by Docker (`docker-proxy`): reachable regardless of UFW.
    Docker,
    /// Public and no active UFW to filter it.
    Unfiltered,
}

impl Exposure {
    pub fn is_exposed(self) -> bool {
        matches!(self, Exposure::Allowed | Exposure::Docker | Exposure::Unfiltered)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Exposure::Local => "local only",
            Exposure::Firewalled => "blocked by ufw",
            Exposure::Allowed => "allowed by ufw",
            Exposure::Docker => "published by docker, bypasses ufw",
            // ufw missing or inactive; iptables rules of your own aren't read
            Exposure::Unfiltered => "no active ufw",
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
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExposureReport {
    pub scanned: Micros,
    /// None = UFW not installed / not readable.
    pub ufw_active: Option<bool>,
    pub listeners: Vec<Listener>,
    /// UFW rules allowing a single port from anywhere while nothing listens on it publicly.
    pub dead_rules: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UfwRule {
    pub lo: u16,
    pub hi: u16,
    pub proto: Option<Proto>,
    pub label: String,
}

impl UfwRule {
    fn matches(&self, port: u16, proto: Proto) -> bool {
        (self.lo..=self.hi).contains(&port) && self.proto.is_none_or(|p| p == proto)
    }
}

// ------------------------------------------------------------------ /proc parsing

fn parse_hex_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(hex, 16).ok()?.swap_bytes()))),
        32 => {
            // four 32-bit words, each in host (little-endian) byte order
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
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
                std::fs::read_to_string(format!("/proc/{pid}/comm")).map_or_else(|_| format!("pid {pid}"), |c| c.trim().to_string())
            });
            owners.entry(inode).or_insert_with(|| comm.clone());
        }
    }
    owners
}

// ------------------------------------------------------------------ ufw parsing

/// Parses `ufw status` (plain or verbose): returns (active, rules allowing traffic from anywhere).
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
        if !(action.starts_with("ALLOW") || action.starts_with("LIMIT")) || !from.starts_with("Anywhere") {
            continue;
        }
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
        let rule = UfwRule { lo, hi, proto, label: to.to_string() };
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    (active, rules)
}

// ------------------------------------------------------------------ classification

pub fn classify(key: &ListenerKey, process: &str, ufw: Option<(bool, &[UfwRule])>) -> Exposure {
    let public = key.addr.is_unspecified() || !is_non_global(key.addr);
    if !public {
        return Exposure::Local;
    }
    if process == "docker-proxy" {
        return Exposure::Docker;
    }
    match ufw {
        Some((true, rules)) if rules.iter().any(|r| r.matches(key.port, key.proto)) => Exposure::Allowed,
        Some((true, _)) => Exposure::Firewalled,
        _ => Exposure::Unfiltered,
    }
}

/// Builds a report from raw inputs (pure; used by `scan` and the tests).
/// Listeners for display: a socket on every IPv4 address (`0.0.0.0`) and its twin on
/// every IPv6 address (`[::]`) - same port, process and reachability, as Docker and sshd
/// open them - become one `*:443/tcp (v4+v6)` row. Twins that differ stay apart.
pub fn for_display(listeners: &[Listener]) -> Vec<(String, &Listener)> {
    let twin = |l: &Listener| {
        listeners.iter().find(|o| {
            o.key.addr.is_ipv6()
                && o.key.addr.is_unspecified()
                && (o.key.proto, o.key.port) == (l.key.proto, l.key.port)
                && (&o.process, o.exposure, o.dynamic) == (&l.process, l.exposure, l.dynamic)
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

pub fn build_report(
    now: Micros,
    sockets: Vec<(ListenerKey, u64)>,
    owners: &HashMap<u64, String>,
    ufw_text: Option<&str>,
    ignore: &[PortSpec],
) -> ExposureReport {
    let ufw = ufw_text.map(parse_ufw_status);
    let mut listeners: Vec<Listener> = sockets
        .into_iter()
        .filter(|(k, _)| !ignore.iter().any(|i| i.matches(k.port, k.proto)))
        .map(|(key, inode)| {
            let process = owners.get(&inode).cloned().unwrap_or_else(|| "?".into());
            let exposure = classify(&key, &process, ufw.as_ref().map(|(a, r)| (*a, r.as_slice())));
            let dynamic = exposure == Exposure::Allowed
                && ufw.as_ref().is_some_and(|(_, rules)| {
                    let hit = |single: bool| rules.iter().any(|r| (r.lo == r.hi) == single && r.matches(key.port, key.proto));
                    !hit(true) && hit(false)
                });
            Listener { key, process, exposure, dynamic }
        })
        .collect();
    listeners.sort_by_key(|l| l.key);
    listeners.dedup_by_key(|l| l.key);

    let mut dead_rules = Vec::new();
    if let Some((true, rules)) = &ufw {
        for r in rules.iter().filter(|r| r.lo == r.hi && !ignore.iter().any(|i| i.port == r.lo)) {
            let served = listeners.iter().any(|l| l.exposure != Exposure::Local && r.matches(l.key.port, l.key.proto));
            if !served && !dead_rules.contains(&r.label) {
                dead_rules.push(r.label.clone());
            }
        }
    }
    ExposureReport { scanned: now, ufw_active: ufw.map(|(a, _)| a), listeners, dead_rules }
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

/// Scans the live system (Linux only).
pub fn scan(cfg: &ExposureCfg) -> Result<ExposureReport> {
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
    Ok(build_report(time::now(), sockets, &owners, ufw.as_deref(), &cfg.ignore))
}

#[cfg(test)]
mod tests {
    #[test]
    fn v4_and_v6_twins_shown_once() {
        let l = |addr: &str, port, proto, process: &str, exposure| Listener {
            key: ListenerKey { proto, addr: addr.parse().unwrap(), port },
            process: process.into(),
            exposure,
            dynamic: false,
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
   3: ECC7284E:4651 0B4B74B0:A1F2 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 100 0 0 10 0
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
Anywhere                   DENY        11.22.0.0/16              # blocked
Anywhere                   ALLOW       11.35.43.31
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
        let r = build_report(0, sockets.clone(), &owners, Some(UFW), &[]);
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

        let none = build_report(0, sockets, &owners, None, &["4369".parse().unwrap()]);
        assert!(none.listeners.iter().all(|l| l.key.port != 4369), "ignored port");
        assert_eq!(none.listeners.iter().find(|l| l.key.port == 2222).unwrap().exposure, Exposure::Unfiltered);
        assert!(none.dead_rules.is_empty());
    }
}
