//! Process watch: what a break-in runs, read from `/proc` every interval.
//!
//! - **Outbound connections:** TCP connections this host opened (to a port not listening
//!   here), by program and remote port. The pairs are learned for `learn`; afterwards a new
//!   one (a miner reaching its pool, a reverse shell, data going somewhere new) is reported
//!   once and becomes normal. A shell or a network tool (`bash`, `nc`, `socat`) talking out,
//!   or anything reaching a port miners and reverse shells use, is always high.
//! - **Programs running from where nothing should run:** `/tmp`, `/var/tmp`, `/dev/shm`,
//!   memory only (`memfd:`), or a program file deleted after start outside the system's
//!   package directories (an upgrade replacing `/usr/sbin/sshd` is the patch status's business).
//!
//! Connections inside containers have network namespaces of their own and aren't seen.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::cronwatch::Finding;
use crate::engine::{is_non_global, Severity};
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Outbound (program, port) pairs seen in this time after the first scan are normal.
    pub learn: Dur,
    /// Remote ports that are always worth a high alert: mining pools, reverse shells.
    pub suspicious_ports: Vec<u16>,
    /// Programs (as `/proc/<pid>/comm` names them) left out of both checks.
    pub ignore_processes: Vec<String>,
    /// Remote ports whose connections aren't watched.
    pub ignore_ports: Vec<u16>,
}

impl Default for ProcCfg {
    fn default() -> Self {
        ProcCfg {
            enabled: true,
            interval: Dur(60),
            learn: Dur(3 * 86_400),
            suspicious_ports: vec![1337, 3333, 4444, 5555, 6666, 7777, 8333, 9999, 14433, 14444, 31337, 45560, 45700],
            ignore_processes: vec![],
            ignore_ports: vec![],
        }
    }
}

impl ProcCfg {
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.interval.0 < 10 {
            bail!("[procwatch] interval must be at least 10s");
        }
        Ok(())
    }
}

/// Programs whose talking out is a reverse shell or a tunnel.
const SHELLS: [&str; 12] = ["sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "nc", "ncat", "netcat", "socat", "telnet"];

/// An outbound TCP connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conn {
    pub process: String,
    pub pid: u32,
    pub uid: u32,
    pub remote: IpAddr,
    pub port: u16,
}

/// A program running from where nothing should run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Odd {
    pub process: String,
    pub pid: u32,
    pub uid: u32,
    pub exe: String,
    pub why: &'static str,
    /// In a mount namespace of its own (a container).
    pub container: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ProcReport {
    pub scanned: Micros,
    /// False where there is no `/proc` (nothing to judge).
    pub available: bool,
    pub outbound: Vec<Conn>,
    pub odd: Vec<Odd>,
}

/// The accepted state, persisted across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcBaseline {
    pub learning_until: Micros,
    #[serde(default)]
    pub armed: bool,
    /// (program, remote port)
    pub pairs: BTreeSet<(String, u16)>,
}

/// Summary for `status` and the dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcView {
    pub scanned: Micros,
    pub learning_until: Micros,
    pub pairs: usize,
    pub outbound: usize,
}

/// Most (program, port) pairs kept: beyond, new ones are still reported, not learned.
const MAX_PAIRS: usize = 2000;
/// Connections read per scan, and new ones reported one by one per scan (a host scanning
/// out gives thousands): the rest are summed up in one more alert.
const MAX_CONNS: usize = 5000;
const MAX_REPORTED: usize = 20;

/// An established or opening TCP connection: (local port, remote address, remote port, inode).
pub type Socket = (u16, IpAddr, u16, u64);

/// Established and opening TCP connections from `/proc/net/tcp{,6}` text, and the ports
/// listening.
pub fn parse_tcp(text: &str) -> (Vec<Socket>, BTreeSet<u16>) {
    let (mut conns, mut listening) = (Vec::new(), BTreeSet::new());
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let local_port = f[1].rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok());
        let Some(lp) = local_port else { continue };
        match f[3] {
            "0A" => {
                listening.insert(lp);
            }
            // ESTABLISHED, SYN_SENT
            "01" | "02" => {
                let Some((addr, port)) = f[2].split_once(':') else { continue };
                let (Some(remote), Ok(rp), Ok(inode)) =
                    (crate::exposure::parse_hex_addr(addr), u16::from_str_radix(port, 16), f[9].parse::<u64>())
                else {
                    continue;
                };
                conns.push((lp, remote, rp, inode));
            }
            _ => {}
        }
    }
    (conns, listening)
}

/// Who owns a socket: (pid, program name, uid).
fn socket_owners(proc: &Path) -> HashMap<u64, (u32, String, u32)> {
    let mut owners = HashMap::new();
    let Ok(procs) = std::fs::read_dir(proc) else { return owners };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
        let mut who: Option<(String, u32)> = None;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let Some(inode) = target.to_str().and_then(|t| t.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok()) else {
                continue;
            };
            let (name, uid) = who.get_or_insert_with(|| (comm(&p.path()), uid_of(&p.path())));
            owners.entry(inode).or_insert_with(|| (pid, name.clone(), *uid));
        }
    }
    owners
}

fn comm(dir: &Path) -> String {
    // any user names their own processes: no control characters into alerts
    std::fs::read_to_string(dir.join("comm")).map_or_else(|_| "?".into(), |c| crate::event::clean(c.trim(), 32))
}

fn uid_of(dir: &Path) -> u32 {
    std::fs::read_to_string(dir.join("status"))
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").and_then(|r| r.split_whitespace().next()?.parse().ok())))
        .unwrap_or(u32::MAX)
}

/// Where packages put programs: a deleted file there was replaced by an upgrade.
const SYSTEM_DIRS: [&str; 7] = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/libx32/"];
const TEMP_DIRS: [&str; 5] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/"];

/// Why a program at `exe` (as `/proc/<pid>/exe` names it) shouldn't run, if it shouldn't.
pub fn odd_exe(exe: &str) -> Option<&'static str> {
    let deleted = exe.ends_with(" (deleted)");
    let path = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    if path.starts_with("/memfd:") {
        // runc runs itself from a sealed memory copy while it starts a container
        return (!path.starts_with("/memfd:runc")).then_some("runs from memory only (memfd), with no file on disk");
    }
    if TEMP_DIRS.iter().any(|d| path.starts_with(d)) {
        return Some(if deleted { "ran from a temporary directory, and its file was deleted" } else { "runs from a temporary directory" });
    }
    if deleted && !SYSTEM_DIRS.iter().any(|d| path.starts_with(d)) {
        return Some("its program file was deleted after it started");
    }
    None
}

fn programs(proc: &Path, ignore: &[String]) -> Vec<Odd> {
    let mut out = Vec::new();
    let own_ns = std::fs::read_link(proc.join("self/ns/mnt")).ok();
    let Ok(rd) = std::fs::read_dir(proc) else { return out };
    for p in rd.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let dir = p.path();
        // kernel threads have no program
        let Ok(exe) = std::fs::read_link(dir.join("exe")) else { continue };
        let exe = crate::event::clean(&exe.display().to_string(), 300);
        let Some(why) = odd_exe(&exe) else { continue };
        let process = comm(&dir);
        if ignore.contains(&process) {
            continue;
        }
        let container = own_ns.is_some() && std::fs::read_link(dir.join("ns/mnt")).ok() != own_ns;
        out.push(Odd { process, pid, uid: uid_of(&dir), exe, why, container });
        if out.len() >= 100 {
            break;
        }
    }
    out
}

/// Reads outbound connections and odd programs from `/proc` (Linux).
pub fn scan(cfg: &ProcCfg) -> ProcReport {
    let proc = Path::new("/proc");
    let mut r = ProcReport { scanned: time::now(), ..Default::default() };
    let Ok(v4) = std::fs::read_to_string(proc.join("net/tcp")) else { return r };
    r.available = true;
    let v6 = std::fs::read_to_string(proc.join("net/tcp6")).unwrap_or_default();
    let (mut conns, mut listening) = parse_tcp(&v4);
    let (c6, l6) = parse_tcp(&v6);
    conns.extend(c6);
    listening.extend(l6);
    let outward: Vec<(IpAddr, u16, u64)> = conns
        .into_iter()
        .filter(|(lp, ip, rp, _)| !listening.contains(lp) && !is_non_global(*ip) && !cfg.ignore_ports.contains(rp))
        .map(|(_, ip, rp, inode)| (ip, rp, inode))
        .collect();
    if !outward.is_empty() {
        let owners = socket_owners(proc);
        let mut seen = std::collections::HashSet::new();
        for (remote, port, inode) in outward {
            let Some((pid, process, uid)) = owners.get(&inode).cloned() else { continue };
            if cfg.ignore_processes.contains(&process) || !seen.insert((process.clone(), remote, port)) {
                continue;
            }
            r.outbound.push(Conn { process, pid, uid, remote, port });
            if r.outbound.len() >= MAX_CONNS {
                break;
            }
        }
    }
    r.odd = programs(proc, &cfg.ignore_processes);
    r
}

/// The local user (not root) a process runs as, if known: the owner of its findings.
fn local_user(uid: u32) -> Option<u32> {
    (uid != 0 && uid != u32::MAX).then_some(uid)
}

/// Compares a scan with the baseline, learns, and says what is new.
pub fn judge(baseline: &mut Option<ProcBaseline>, r: &ProcReport, cfg: &ProcCfg, place: &dyn Fn(IpAddr) -> Option<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    if !r.available {
        return out;
    }
    let now = r.scanned;
    let day = 86_400 * time::SEC;
    let b = baseline.get_or_insert_with(|| ProcBaseline { learning_until: now + cfg.learn.micros(), armed: false, pairs: BTreeSet::new() });
    let learning = now < b.learning_until;
    for o in &r.odd {
        let (severity, inside) = if o.container { (Severity::Warning, " in a container") } else { (Severity::High, "") };
        out.push(Finding {
            key: format!("proc-exe:{}:{}", o.process, o.exe),
            every: day,
            severity,
            message: format!(
                "process {} (pid {}, uid {}){inside} {}: {} - check what it is (ls -l /proc/{}/exe; cat /proc/{}/cmdline)",
                o.process, o.pid, o.uid, o.why, o.exe, o.pid, o.pid
            ),
            evidence: vec![],
            notify: true,
            owner: local_user(o.uid),
        });
    }
    let (mut more, mut more_uids): (Vec<String>, BTreeSet<u32>) = (Vec::new(), BTreeSet::new());
    for c in &r.outbound {
        let shell = SHELLS.contains(&c.process.as_str());
        let odd_port = cfg.suspicious_ports.contains(&c.port);
        let pair = (c.process.clone(), c.port);
        let known = b.pairs.contains(&pair);
        if !shell && !odd_port && (known || learning) {
            if !known && b.pairs.len() < MAX_PAIRS {
                b.pairs.insert(pair);
            }
            continue;
        }
        let reported = out.iter().filter(|f| f.key.starts_with("proc-out:")).count();
        if reported >= MAX_REPORTED {
            if more.len() < 30 {
                more.push(format!("{} (pid {}) to {}:{}", c.process, c.pid, c.remote, c.port));
            }
            more_uids.insert(c.uid);
            if !shell && !odd_port && b.pairs.len() < MAX_PAIRS {
                b.pairs.insert(pair);
            }
            continue;
        }
        let at = place(c.remote).map(|p| format!(" [{p}]")).unwrap_or_default();
        let (severity, why) = match (shell, odd_port) {
            (true, _) => (Severity::High, " - a shell or network tool talking out: a reverse shell?"),
            (_, true) => (Severity::High, " - a port miners and reverse shells use"),
            _ => (Severity::Warning, ""),
        };
        out.push(Finding {
            key: format!("proc-out:{}:{}", c.process, c.port),
            every: if shell || odd_port { 3600 * time::SEC } else { 0 },
            severity,
            message: format!("new outbound connection: {} (pid {}, uid {}) to {}:{}{at}{why}", c.process, c.pid, c.uid, c.remote, c.port),
            evidence: vec![],
            notify: true,
            owner: local_user(c.uid),
        });
        if !shell && !odd_port && b.pairs.len() < MAX_PAIRS {
            b.pairs.insert(pair);
        }
    }
    if !more.is_empty() {
        out.push(Finding {
            key: "proc-out-more".into(),
            every: 3600 * time::SEC,
            severity: Severity::High,
            message: format!("and more new outbound connections in the same minute (a scan from this host?): {}", more.join(", ")),
            evidence: vec![],
            notify: true,
            // one user's own, if they all are
            owner: (more_uids.len() == 1).then(|| more_uids.first().copied().and_then(local_user)).flatten(),
        });
    }
    if !learning && !b.armed {
        b.armed = true;
        out.push(Finding {
            key: "proc-armed".into(),
            every: day,
            severity: Severity::Info,
            message: format!("process watch learned {} outbound (program, port) pairs; new ones are reported from now on", b.pairs.len()),
            evidence: vec![],
            notify: false,
            owner: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0
   1: ECC7284E:0016 0B4B74B0:A1F2 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0
   2: ECC7284E:C350 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0
   3: ECC7284E:C351 0B4B74B0:115C 02 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 100 0 0 10 0
";

    #[test]
    fn outbound_connections_from_proc() {
        let (conns, listening) = parse_tcp(TCP);
        assert_eq!(listening.into_iter().collect::<Vec<_>>(), vec![22]);
        let out: Vec<(u16, String, u16)> = conns.iter().map(|(lp, ip, rp, _)| (*lp, ip.to_string(), *rp)).collect();
        assert_eq!(
            out,
            vec![(22, "11.43.43.11".into(), 41458), (50000, "8.8.8.8".into(), 443), (50001, "11.43.43.11".into(), 4444)],
            "the first is a connection to sshd, not an outbound one"
        );
    }

    #[test]
    fn odd_programs() {
        assert_eq!(odd_exe("/usr/sbin/sshd"), None);
        assert_eq!(odd_exe("/usr/sbin/sshd (deleted)"), None, "replaced by an upgrade");
        assert!(odd_exe("/tmp/.x/kworker").is_some());
        assert!(odd_exe("/dev/shm/a (deleted)").unwrap().contains("deleted"));
        assert!(odd_exe("/memfd:payload (deleted)").unwrap().contains("memfd"));
        assert_eq!(odd_exe("/memfd:runc_cloned:/proc/self/exe (deleted)"), None);
        assert!(odd_exe("/home/eve/miner (deleted)").is_some());
        assert_eq!(odd_exe("/opt/app/bin/app"), None);
    }

    #[test]
    fn learns_then_reports_new_pairs() {
        let h = 3600 * time::SEC;
        let cfg = ProcCfg::default();
        let conn = |process: &str, port| Conn { process: process.into(), pid: 7, uid: 0, remote: "8.8.8.8".parse().unwrap(), port };
        let report = |t: Micros, outbound: Vec<Conn>| ProcReport { scanned: t, available: true, outbound, odd: vec![] };
        let none = |_| None;
        let mut b = None;
        assert!(judge(&mut b, &report(h, vec![conn("curl", 443), conn("beam.smp", 5269)]), &cfg, &none).is_empty(), "learning");
        // a reverse shell is high even while learning
        let f = judge(&mut b, &report(2 * h, vec![conn("bash", 9001)]), &cfg, &none);
        assert!(f.len() == 1 && f[0].severity == Severity::High && f[0].message.contains("reverse shell"), "{f:?}");
        let f = judge(&mut b, &report(80 * h, vec![conn("curl", 443)]), &cfg, &none);
        assert!(f.len() == 1 && f[0].message.contains("learned 2 outbound"), "{f:?}");
        let f = judge(&mut b, &report(81 * h, vec![conn("curl", 443), conn("curl", 8080), conn("xmrig", 3333)]), &cfg, &none);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.starts_with("new outbound connection: curl (pid 7, uid 0) to 8.8.8.8:8080"));
        assert_eq!(f[1].severity, Severity::High);
        assert!(judge(&mut b, &report(82 * h, vec![conn("curl", 8080)]), &cfg, &none).is_empty(), "learned after its alert");
        assert!(judge(&mut None, &ProcReport::default(), &cfg, &none).is_empty(), "no /proc: nothing");
    }

    /// A finding about a process belongs to the local user it runs as (root's to nobody):
    /// the engine limits how many such alerts one user gets sent an hour.
    #[test]
    fn findings_name_the_processes_user() {
        let cfg = ProcCfg::default();
        let odd =
            |uid| Odd { process: "x".into(), pid: 9, uid, exe: "/tmp/x".into(), why: "runs from a temporary directory", container: false };
        let conn = |uid, port| Conn { process: "nc".into(), pid: 9, uid, remote: "8.8.8.8".parse().unwrap(), port };
        let r = ProcReport {
            scanned: time::SEC,
            available: true,
            outbound: vec![conn(1000, 4444), conn(0, 4445)],
            odd: vec![odd(1000), odd(0), odd(u32::MAX)],
        };
        let f = judge(&mut None, &r, &cfg, &|_| None);
        let owners: Vec<Option<u32>> = f.iter().map(|f| f.owner).collect();
        assert_eq!(owners, [Some(1000), None, None, Some(1000), None], "{f:?}");
    }
}
