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

pub fn parse_oom(msg: &str) -> Option<OomKill> {
    let at = msg.find("out of memory: Killed process ").or_else(|| msg.find("Out of memory: Killed process "))?;
    let rest = &msg[at + "out of memory: Killed process ".len()..];
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
        process: process.chars().filter(|c| !c.is_control()).take(64).collect(),
        rss_mb: rss_kb / 1024,
        cgroup: msg[..at].contains("cgroup"),
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
    }
}
