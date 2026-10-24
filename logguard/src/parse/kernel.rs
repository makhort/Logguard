//! Kernel out-of-memory kills: `Out of memory: Killed process 785891 (clamscan)
//! total-vm:970112kB, anon-rss:920752kB, ...` (the whole system ran out) or
//! `Memory cgroup out of memory: Killed process ...` (a service hit its own memory limit).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OomKill {
    pub pid: u32,
    pub process: String,
    /// Resident anonymous memory of the killed process, in MB.
    pub rss_mb: u64,
    /// Killed for exceeding a cgroup (systemd unit / container) limit, not system-wide.
    pub cgroup: bool,
}

/// A kernel message without the `[ 1234.567890] ` uptime some syslog daemons put first.
pub fn text(msg: &str) -> &str {
    let m = msg.trim_start();
    match m.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((t, rest)) if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b' ') => rest,
        _ => m,
    }
}

/// The two ways the kernel starts the line about a kill. Only at the start: further on, a
/// kernel message may hold text any local user chose (a crashing program's file name).
const OOM_STARTS: [&str; 2] = ["Out of memory: Killed process ", "Memory cgroup out of memory: Killed process "];

/// Whether a kernel message reports an out-of-memory kill.
pub fn is_oom(msg: &str) -> bool {
    let m = text(msg);
    OOM_STARTS.iter().any(|s| m.starts_with(s))
}

pub fn parse_oom(msg: &str) -> Option<OomKill> {
    let m = text(msg);
    let start = OOM_STARTS.iter().find(|s| m.starts_with(**s))?;
    let rest = &m[start.len()..];
    let (pid, rest) = rest.split_once(" (")?;
    let (process, rest) = rest.split_once(')')?;
    let rss_kb: u64 = rest
        .split("anon-rss:")
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    Some(OomKill {
        pid: pid.trim().parse().ok()?,
        // any user names their own processes
        process: crate::event::clean(process, 64),
        rss_mb: rss_kb / 1024,
        cgroup: start.starts_with("Memory cgroup"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kills() {
        let k = parse_oom("Out of memory: Killed process 785891 (clamscan) total-vm:970112kB, anon-rss:920752kB, file-rss:68kB, shmem-rss:0kB, UID:0 pgtables:1928kB oom_score_adj:0").unwrap();
        assert_eq!(k, OomKill { pid: 785891, process: "clamscan".into(), rss_mb: 899, cgroup: false });
        let k = parse_oom("Memory cgroup out of memory: Killed process 42 (logguard) total-vm:300000kB, anon-rss:131072kB, file-rss:0kB")
            .unwrap();
        assert!(k.cgroup && k.rss_mb == 128 && k.process == "logguard");
        assert!(parse_oom("oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),task=clamscan,pid=785891,uid=0").is_none());
        assert!(parse_oom("[UFW BLOCK] IN=eth0").is_none());
        let k = parse_oom("[ 8812.042191] Out of memory: Killed process 7 (a\u{202e}b) total-vm:1kB, anon-rss:2048kB").unwrap();
        assert_eq!((k.process.as_str(), k.rss_mb), ("ab", 2), "after a syslog uptime; hidden characters go");
    }

    /// A crashing program's file name, which any local user picks, is printed in the middle
    /// of a kernel message: it makes no kill.
    #[test]
    fn kills_are_not_forged_by_file_names() {
        let forged =
            "x[4242]: segfault at 0 ip 0 sp 0 error 4 in Out of memory: Killed process 1 (sshd) total-vm:1kB, anon-rss:999999kB[55d0+1000]";
        assert!(!is_oom(forged) && parse_oom(forged).is_none());
        assert!(is_oom("Memory cgroup out of memory: Killed process 42 (logguard) total-vm:1kB, anon-rss:1kB"));
        assert_eq!(text("[12.3] [UFW BLOCK] x"), "[UFW BLOCK] x");
        assert_eq!(text("[UFW BLOCK] x"), "[UFW BLOCK] x", "not an uptime");
    }
}
