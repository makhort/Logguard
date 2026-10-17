//! Disk space and memory pressure, read every `interval`: low free space on the
//! filesystems holding the logs and databases, and memory that stays short. An
//! out-of-memory kill is the last step of the latter; this warns before it.
//!
//! Disk space comes from `df -Pk` (POSIX output, no libc binding needed), memory from
//! `/proc/meminfo` and, when the kernel has it, the pressure stall information in
//! `/proc/pressure/memory` (share of time tasks waited for memory).

use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::engine::Severity;
use crate::time::{Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourcesCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Paths whose filesystems to watch (each filesystem once).
    pub disks: Vec<PathBuf>,
    /// Warn below this share of free space (percent), high below `disk_high_percent`.
    pub disk_warn_percent: f64,
    pub disk_high_percent: f64,
    /// Warn when less than this share of memory (percent of MemTotal) stayed available
    /// for `mem_sustain`, or tasks stalled on memory (`full avg300`) at least
    /// `psi_full_percent` of the time.
    pub mem_warn_percent: f64,
    pub mem_sustain: Dur,
    pub psi_full_percent: f64,
    pub df: PathBuf,
}

impl Default for ResourcesCfg {
    fn default() -> Self {
        ResourcesCfg {
            enabled: true,
            interval: Dur(60),
            disks: vec!["/".into()],
            disk_warn_percent: 10.0,
            disk_high_percent: 5.0,
            mem_warn_percent: 10.0,
            mem_sustain: Dur(15 * 60),
            psi_full_percent: 10.0,
            df: "/usr/bin/df".into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Disk {
    pub mount: String,
    /// The configured paths on this filesystem.
    pub paths: Vec<String>,
    pub size_kb: u64,
    pub avail_kb: u64,
}

impl Disk {
    pub fn free_percent(&self) -> f64 {
        if self.size_kb == 0 {
            100.0
        } else {
            100.0 * self.avail_kb as f64 / self.size_kb as f64
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    pub total_kb: u64,
    pub avail_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    /// `/proc/pressure/memory`: `some avg300` and `full avg300` (percent of time).
    pub psi_some: Option<f64>,
    pub psi_full: Option<f64>,
}

impl Memory {
    pub fn avail_percent(&self) -> f64 {
        if self.total_kb == 0 {
            100.0
        } else {
            100.0 * self.avail_kb as f64 / self.total_kb as f64
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub read: Micros,
    pub disks: Vec<Disk>,
    pub memory: Option<Memory>,
    pub errors: Vec<String>,
}

pub fn scan(cfg: &ResourcesCfg, now: Micros) -> Report {
    let mut r = Report { read: now, ..Default::default() };
    if !cfg.disks.is_empty() {
        let mut cmd = Command::new(&cfg.df);
        cmd.arg("-Pk").args(&cfg.disks);
        // a stalled network mount makes df hang for good
        match crate::proc::run(cmd, None, std::time::Duration::from_secs(15)) {
            Ok(out) => {
                r.disks = parse_df(&String::from_utf8_lossy(&out.stdout), &cfg.disks);
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    r.errors.push(format!("df: {}", err.lines().next().unwrap_or("failed").trim()));
                }
            }
            Err(e) => r.errors.push(format!("{}: {e}", cfg.df.display())),
        }
    }
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(text) => {
            let psi = std::fs::read_to_string("/proc/pressure/memory").unwrap_or_default();
            r.memory = Some(parse_memory(&text, &psi));
        }
        Err(e) if cfg!(target_os = "linux") => r.errors.push(format!("/proc/meminfo: {e}")),
        Err(_) => {}
    }
    r
}

/// `df -Pk` lines: `Filesystem 1024-blocks Used Available Capacity Mounted-on`, one per
/// path in order (mount points may contain spaces, so the mount is everything after the
/// fifth column). Paths on the same filesystem are merged.
fn parse_df(out: &str, paths: &[PathBuf]) -> Vec<Disk> {
    let mut disks: Vec<Disk> = Vec::new();
    for (line, path) in out.lines().skip(1).zip(paths) {
        let mut cols = line.split_whitespace();
        let (Some(_fs), Some(size), Some(_used), Some(avail), Some(_cap)) =
            (cols.next(), cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let (Ok(size_kb), Ok(avail_kb)) = (size.parse(), avail.parse()) else { continue };
        let mount = cols.collect::<Vec<_>>().join(" ");
        let path = path.display().to_string();
        match disks.iter_mut().find(|d| d.mount == mount) {
            Some(d) => d.paths.push(path),
            None => disks.push(Disk { mount, paths: vec![path], size_kb, avail_kb }),
        }
    }
    disks
}

fn parse_memory(meminfo: &str, psi: &str) -> Memory {
    let field = |name: &str| {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
            .unwrap_or(0)
    };
    let avg300 = |kind: &str| {
        psi.lines().find_map(|l| l.strip_prefix(kind)?.split_whitespace().find_map(|f| f.strip_prefix("avg300=")?.parse().ok()))
    };
    Memory {
        total_kb: field("MemTotal"),
        avail_kb: field("MemAvailable"),
        swap_total_kb: field("SwapTotal"),
        swap_free_kb: field("SwapFree"),
        psi_some: avg300("some "),
        psi_full: avg300("full "),
    }
}

/// What the scans so far say: alerts as (gate key, gate period, severity, message).
#[derive(Debug, Default)]
pub struct Watch {
    low_memory_since: Option<Micros>,
}

pub type Finding = (String, Micros, Severity, String);

impl Watch {
    pub fn judge(&mut self, r: &Report, cfg: &ResourcesCfg) -> Vec<Finding> {
        const HOURS6: Micros = 6 * 3600 * crate::time::SEC;
        let mut out = Vec::new();
        for d in &r.disks {
            let free = d.free_percent();
            let severity = if free < cfg.disk_high_percent {
                Severity::High
            } else if free < cfg.disk_warn_percent {
                Severity::Warning
            } else {
                continue;
            };
            out.push((
                format!("disk:{}:{severity:?}", d.mount),
                HOURS6,
                severity,
                format!(
                    "low disk space on {} ({}): {:.1}% free, {} MB of {} MB (du -xh --max-depth=2 {} | sort -h | tail)",
                    d.mount,
                    d.paths.join(", "),
                    free,
                    d.avail_kb / 1024,
                    d.size_kb / 1024,
                    d.mount
                ),
            ));
        }
        if let Some(m) = &r.memory {
            let low = m.total_kb > 0 && m.avail_percent() < cfg.mem_warn_percent;
            let since = if low { *self.low_memory_since.get_or_insert(r.read) } else { r.read };
            if !low {
                self.low_memory_since = None;
            }
            let stalled = m.psi_full.is_some_and(|p| p >= cfg.psi_full_percent);
            if (low && r.read - since >= cfg.mem_sustain.micros()) || stalled {
                let swap = if m.swap_total_kb == 0 {
                    "no swap".to_string()
                } else {
                    format!("swap {} of {} MB free", m.swap_free_kb / 1024, m.swap_total_kb / 1024)
                };
                let psi = m.psi_full.map_or(String::new(), |p| format!(", tasks stalled on memory {p:.1}% of the last 5 min"));
                out.push((
                    "memory".into(),
                    HOURS6,
                    Severity::Warning,
                    format!(
                        "memory is short: {} MB of {} MB available ({:.1}%), {swap}{psi} (ps aux --sort=-rss | head)",
                        m.avail_kb / 1024,
                        m.total_kb / 1024,
                        m.avail_percent()
                    ),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DF: &str = "Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/vda1         41152736 38000000   1048576      98% /
/dev/vda1         41152736 38000000   1048576      98% /
/dev/vdb1         10000000  1000000   9000000      10% /srv/my data
";

    #[test]
    fn df_output_merges_paths_per_filesystem() {
        let paths: Vec<PathBuf> = ["/", "/var/log", "/srv/my data/db"].iter().map(PathBuf::from).collect();
        let d = parse_df(DF, &paths);
        assert_eq!(d.len(), 2);
        assert_eq!((d[0].mount.as_str(), d[0].paths.len()), ("/", 2));
        assert_eq!(d[1].mount, "/srv/my data");
        assert!((d[0].free_percent() - 2.548).abs() < 0.01);
    }

    #[test]
    fn meminfo_and_pressure() {
        let m = parse_memory(
            "MemTotal:        2014480 kB\nMemFree:  10 kB\nMemAvailable:     100000 kB\nSwapTotal:  0 kB\nSwapFree: 0 kB\n",
            "some avg10=1.00 avg60=2.00 avg300=3.50 total=1\nfull avg10=0.50 avg60=1.00 avg300=12.25 total=2\n",
        );
        assert_eq!((m.total_kb, m.avail_kb, m.swap_total_kb), (2014480, 100000, 0));
        assert_eq!((m.psi_some, m.psi_full), (Some(3.5), Some(12.25)));
        assert_eq!(parse_memory("MemTotal: 1 kB\n", "").psi_full, None, "kernels without PSI");
    }

    #[test]
    fn alerts_on_low_disk_and_sustained_memory_shortage() {
        let cfg = ResourcesCfg::default();
        let min = 60 * crate::time::SEC;
        let mut w = Watch::default();
        let mem = |avail_kb| Some(Memory { total_kb: 2_000_000, avail_kb, ..Default::default() });
        let disks = parse_df(DF, &["/".into(), "/var/log".into(), "/srv/my data".into()]);
        let f = w.judge(&Report { read: 0, disks, memory: mem(1_000_000), errors: vec![] }, &cfg);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].2, Severity::High);
        assert!(f[0].3.contains("low disk space on / (/, /var/log): 2.5% free"), "{}", f[0].3);
        // memory: short for less than mem_sustain says nothing, then warns
        assert!(w.judge(&Report { read: min, memory: mem(100_000), ..Default::default() }, &cfg).is_empty());
        assert!(w.judge(&Report { read: 10 * min, memory: mem(100_000), ..Default::default() }, &cfg).is_empty());
        let f = w.judge(&Report { read: 16 * min, memory: mem(100_000), ..Default::default() }, &cfg);
        assert!(f[0].3.contains("97 MB of 1953 MB available (5.0%), no swap"), "{}", f[0].3);
        // recovered: the clock starts over
        assert!(w.judge(&Report { read: 17 * min, memory: mem(1_000_000), ..Default::default() }, &cfg).is_empty());
        assert!(w.judge(&Report { read: 18 * min, memory: mem(100_000), ..Default::default() }, &cfg).is_empty());
        // stalls alone are enough
        let stalled = Some(Memory { total_kb: 2_000_000, avail_kb: 1_000_000, psi_full: Some(15.0), ..Default::default() });
        assert_eq!(w.judge(&Report { read: 19 * min, memory: stalled, ..Default::default() }, &cfg).len(), 1);
    }
}
