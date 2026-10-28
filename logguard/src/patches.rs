//! Patch status, for the daily digest and the dashboard: pending updates (security ones by
//! name), a newer kernel installed than the one running, `/run/reboot-required`, and
//! programs still running a program or library an upgrade replaced (they keep the old,
//! possibly vulnerable code until restarted). Read every `interval`; nothing is changed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::PackageManager;
use crate::time::{Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PatchesCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Ask apt which upgrades are pending (`apt-get -s dist-upgrade`, a simulation: nothing
    /// is installed, and apt's lock isn't taken). It loads apt's package cache, some tens of
    /// MB: under systemd it runs in a transient unit of its own (`systemd-run`), so that isn't
    /// charged to logguard's memory limit. With `package_manager = "dnf"`: dnf instead
    /// (`dnf --cacheonly check-update`, the metadata dnf-makecache.timer keeps current).
    pub apt: bool,
    pub apt_get: PathBuf,
    pub dnf: PathBuf,
    pub systemd_run: PathBuf,
    /// The top-level `package_manager` (`Config::share_package_manager`).
    #[serde(skip)]
    pub package_manager: PackageManager,
}

impl Default for PatchesCfg {
    fn default() -> Self {
        PatchesCfg {
            enabled: true,
            interval: Dur(6 * 3600),
            apt: true,
            apt_get: "/usr/bin/apt-get".into(),
            dnf: "/usr/bin/dnf".into(),
            systemd_run: "/usr/bin/systemd-run".into(),
            package_manager: PackageManager::Apt,
        }
    }
}

/// A program still running replaced code.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stale {
    pub process: String,
    pub pids: usize,
    /// One of the replaced files it still uses.
    pub file: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PatchReport {
    pub read: Micros,
    /// Which tool was asked: what the digest says to run.
    #[serde(default)]
    pub manager: PackageManager,
    /// Pending upgrades, when apt was asked.
    #[serde(default)]
    pub upgradable: Option<usize>,
    /// Pending upgrades from a security archive.
    #[serde(default)]
    pub security_count: usize,
    /// Their package names (the first 30).
    #[serde(default)]
    pub security: Vec<String>,
    /// `/run/reboot-required` exists, and the packages in `reboot-required.pkgs`.
    #[serde(default)]
    pub reboot_required: bool,
    #[serde(default)]
    pub reboot_pkgs: Vec<String>,
    #[serde(default)]
    pub running_kernel: Option<String>,
    /// The newest kernel in /boot.
    #[serde(default)]
    pub newest_kernel: Option<String>,
    #[serde(default)]
    pub stale: Vec<Stale>,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl PatchReport {
    /// The newer kernel installed, if the running one is older.
    pub fn kernel_pending(&self) -> Option<&str> {
        match (&self.running_kernel, &self.newest_kernel) {
            (Some(r), Some(n)) if natural_cmp(n, r) == std::cmp::Ordering::Greater => Some(n),
            _ => None,
        }
    }

    /// What needs doing, one line each (empty: up to date).
    pub fn concerns(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.security_count > 0 {
            let names = self.security.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
            let more = if self.security_count > 8 { ", ..." } else { "" };
            out.push(format!("{} security updates pending ({names}{more}): {}", self.security_count, self.manager.upgrade_command()));
        }
        if let Some(k) = self.kernel_pending() {
            out.push(format!("kernel {k} is installed but {} runs: reboot", self.running_kernel.as_deref().unwrap_or("?")));
        } else if self.reboot_required {
            let pkgs = if self.reboot_pkgs.is_empty() { String::new() } else { format!(" (for {})", self.reboot_pkgs.join(", ")) };
            out.push(format!("a reboot is required{pkgs}"));
        }
        if !self.stale.is_empty() {
            let names: Vec<String> = self.stale.iter().take(8).map(|s| s.process.clone()).collect();
            let more = if self.stale.len() > 8 { ", ..." } else { "" };
            out.push(format!(
                "{} programs still run replaced code ({}{more}): restart them (or reboot)",
                self.stale.len(),
                names.join(", ")
            ));
        }
        out
    }

    /// One line for the dashboard and `status`.
    pub fn summary(&self) -> String {
        let mut c = self.concerns();
        if !c.is_empty() {
            // the other updates too, which the concerns don't count
            match self.upgradable {
                Some(n) if n > self.security_count => c.push(format!("{} other updates pending", n - self.security_count)),
                _ => {}
            }
            return c.join("; ");
        }
        match self.upgradable {
            Some(0) | None => "up to date".into(),
            Some(n) => format!("{n} updates pending, none for security"),
        }
    }
}

/// Compares version strings piece by piece, numbers as numbers: `6.12.48+deb13` > `6.12.9+deb13`.
pub fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn pieces(s: &str) -> Vec<(bool, &str)> {
        let mut out = Vec::new();
        let mut start = 0;
        let b = s.as_bytes();
        for i in 1..=b.len() {
            if i == b.len() || b[i].is_ascii_digit() != b[start].is_ascii_digit() {
                out.push((b[start].is_ascii_digit(), &s[start..i]));
                start = i;
            }
        }
        out
    }
    let (pa, pb) = (pieces(a), pieces(b));
    for (x, y) in pa.iter().zip(&pb) {
        let ord = match (x.0, y.0) {
            (true, true) => {
                let (u, v) = (x.1.trim_start_matches('0'), y.1.trim_start_matches('0'));
                u.len().cmp(&v.len()).then_with(|| u.cmp(v))
            }
            _ => x.1.cmp(y.1),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    pa.len().cmp(&pb.len())
}

/// `apt-get -s dist-upgrade` output: the packages it would install (`Inst name [old] (new
/// Origin:release [arch])`) and those of them from a security archive.
pub fn parse_apt_simulation(text: &str) -> (usize, Vec<String>) {
    let mut total = 0;
    let mut security = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Inst ") else { continue };
        total += 1;
        let name = rest.split_whitespace().next().unwrap_or("");
        let origin = rest.split_once('(').map_or("", |(_, o)| o);
        if origin.to_ascii_lowercase().contains("security") {
            security.push(crate::event::clean(name, 64));
        }
    }
    (total, security)
}

/// `dnf check-update` output (dnf 4 and 5): a `name.arch  version  repository` line per
/// pending update, which dnf 4 wraps after a long name; then, after an "Obsoleting packages"
/// heading, the packages replaced, which aren't updates. Names, sorted, each once.
pub fn parse_dnf_check_update(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for l in text.lines() {
        if l.trim_start().to_ascii_lowercase().starts_with("obsoleting") {
            break;
        }
        match lines.last_mut() {
            Some(prev) if l.starts_with(char::is_whitespace) => {
                prev.push(' ');
                prev.push_str(l.trim());
            }
            _ => lines.push(l.to_string()),
        }
    }
    let mut names: Vec<String> = lines
        .iter()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (name, arch) = f.first()?.rsplit_once('.')?;
            (f.len() == 3 && !name.is_empty() && !arch.is_empty() && f[1].chars().next()?.is_ascii_alphanumeric())
                .then(|| crate::event::clean(name, 64))
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The newest kernel among `/boot/vmlinuz-*` names.
pub fn newest_kernel<'a>(names: impl Iterator<Item = &'a str>) -> Option<String> {
    names.filter_map(|n| n.strip_prefix("vmlinuz-")).filter(|v| !v.is_empty()).max_by(|a, b| natural_cmp(a, b)).map(str::to_string)
}

/// Where packages put programs and libraries: replaced files there were upgraded.
const SYSTEM_DIRS: [&str; 7] = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/libx32/"];

fn replaced(path: &str) -> Option<&str> {
    let p = path.strip_suffix(" (deleted)")?;
    SYSTEM_DIRS.iter().any(|d| p.starts_with(d)).then_some(p)
}

/// The replaced program or library a `/proc/<pid>/maps` text (with its `exe` link) uses.
pub fn stale_file(exe: Option<&str>, maps: &str) -> Option<String> {
    if let Some(p) = exe.and_then(replaced) {
        return Some(p.to_string());
    }
    maps.lines()
        .filter_map(|l| l.split_once('/').map(|(_, p)| format!("/{p}")))
        .find_map(|p| replaced(&p).filter(|f| f.contains(".so")).map(str::to_string))
}

/// Programs (by name) still running replaced code, from `/proc`.
fn stale_processes(proc: &Path) -> Vec<Stale> {
    let mut by_name: BTreeMap<String, Stale> = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(proc) else { return vec![] };
    let me = std::process::id().to_string();
    for e in rd.flatten() {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.bytes().all(|b| b.is_ascii_digit()) || pid == me {
            continue;
        }
        let dir = e.path();
        let exe = std::fs::read_link(dir.join("exe")).ok().map(|p| p.display().to_string());
        // the big ones (beam.smp) have a few thousand lines: read at most 4 MB
        let maps = std::fs::File::open(dir.join("maps"))
            .map(|f| {
                let mut s = String::new();
                let _ = std::io::Read::read_to_string(&mut std::io::Read::take(f, 4 << 20), &mut s);
                s
            })
            .unwrap_or_default();
        let Some(file) = stale_file(exe.as_deref(), &maps) else { continue };
        let name = std::fs::read_to_string(dir.join("comm")).map_or_else(|_| format!("pid {pid}"), |c| crate::event::clean(c.trim(), 32));
        let s = by_name.entry(name.clone()).or_insert_with(|| Stale { process: name, pids: 0, file: crate::event::clean(&file, 160) });
        s.pids += 1;
        if by_name.len() >= 50 {
            break;
        }
    }
    by_name.into_values().collect()
}

/// The command apt-get (or dnf) runs as. Run by systemd (`INVOCATION_ID` is set for a
/// service), in a transient unit of its own: apt's package cache (some tens of MB; dnf's
/// metadata, a few hundred) would otherwise count against logguard's memory limit, next to
/// everything else running then. systemd-run passes on the program's exit status.
fn apt_command(cfg: &PatchesCfg, under_systemd: bool) -> Command {
    let (program, memory) = match cfg.package_manager {
        PackageManager::Apt => (&cfg.apt_get, "512M"),
        PackageManager::Dnf => (&cfg.dnf, "1G"),
    };
    if !(under_systemd && cfg.systemd_run.exists()) {
        let mut cmd = Command::new(program);
        cmd.env("LC_ALL", "C");
        return cmd;
    }
    let mut cmd = Command::new(&cfg.systemd_run);
    cmd.args(["--quiet", "--wait", "--pipe", "--collect"])
        .arg(format!("--property=MemoryMax={memory}"))
        .args(["--property=RuntimeMaxSec=110", "--property=Nice=10", "--setenv=LC_ALL=C", "--"])
        .arg(program);
    cmd
}

/// Pending updates from dnf, and the security ones: `check-update` exits 100 when there are
/// some, 0 when none. From the metadata on disk only (`--cacheonly`), like apt's simulation:
/// no download, and dnf's lock isn't taken.
fn dnf_updates(cfg: &PatchesCfg, security: bool) -> Result<Vec<String>, String> {
    let mut cmd = apt_command(cfg, std::env::var_os("INVOCATION_ID").is_some());
    cmd.args(["--cacheonly", "--quiet", "check-update"]);
    if security {
        cmd.arg("--security");
    }
    let out = crate::proc::run(cmd, None, Duration::from_secs(120))?;
    match out.status.code() {
        Some(0 | 100) => Ok(parse_dnf_check_update(&String::from_utf8_lossy(&out.stdout))),
        _ => Err(format!("dnf check-update: {}", crate::event::clean(&out.complaint(), 200))),
    }
}

/// Reads the patch status of this host.
pub fn scan(cfg: &PatchesCfg, now: Micros) -> PatchReport {
    let mut r = PatchReport { read: now, manager: cfg.package_manager, ..Default::default() };
    if cfg.apt && cfg.package_manager == PackageManager::Dnf && cfg.dnf.exists() {
        match dnf_updates(cfg, false) {
            Ok(all) => {
                r.upgradable = Some(all.len());
                if !all.is_empty() {
                    match dnf_updates(cfg, true) {
                        Ok(sec) => {
                            r.security_count = sec.len();
                            r.security = sec.into_iter().take(30).collect();
                        }
                        Err(e) => r.errors.push(e),
                    }
                }
            }
            Err(e) => r.errors.push(e),
        }
    }
    if cfg.apt && cfg.package_manager == PackageManager::Apt && cfg.apt_get.exists() {
        let mut cmd = apt_command(cfg, std::env::var_os("INVOCATION_ID").is_some());
        // a simulation, as any user can run it; no lock, so a running upgrade isn't disturbed
        cmd.args(["-s", "-q", "-o", "Debug::NoLocking=true", "dist-upgrade"]);
        match crate::proc::run(cmd, None, Duration::from_secs(120)) {
            Ok(out) if out.status.success() => {
                let (n, sec) = parse_apt_simulation(&String::from_utf8_lossy(&out.stdout));
                r.upgradable = Some(n);
                r.security_count = sec.len();
                r.security = sec.into_iter().take(30).collect();
            }
            Ok(out) => r.errors.push(format!("apt-get -s: {}", crate::event::clean(&out.complaint(), 200))),
            Err(e) => r.errors.push(e),
        }
    }
    r.reboot_required = Path::new("/run/reboot-required").exists();
    if let Ok(t) = std::fs::read_to_string("/run/reboot-required.pkgs") {
        let mut pkgs: Vec<String> = t.lines().map(|l| crate::event::clean(l.trim(), 64)).filter(|l| !l.is_empty()).collect();
        pkgs.sort();
        pkgs.dedup();
        r.reboot_pkgs = pkgs.into_iter().take(10).collect();
    }
    r.running_kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|k| k.trim().to_string());
    if let Ok(rd) = std::fs::read_dir("/boot") {
        let names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        r.newest_kernel = newest_kernel(names.iter().map(String::as_str));
    }
    r.stale = stale_processes(Path::new("/proc"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        use std::cmp::Ordering::*;
        assert_eq!(natural_cmp("6.12.48+deb13-amd64", "6.12.9+deb13-amd64"), Greater);
        assert_eq!(natural_cmp("6.1.0-26-amd64", "6.1.0-28-amd64"), Less);
        assert_eq!(natural_cmp("5.15.0-125-generic", "5.15.0-125-generic"), Equal);
        assert_eq!(
            newest_kernel(["vmlinuz-6.12.9+deb13-amd64", "config-x", "vmlinuz-6.12.48+deb13-amd64", "vmlinuz-"].into_iter()).as_deref(),
            Some("6.12.48+deb13-amd64")
        );
    }

    #[test]
    fn apt_simulation_and_concerns() {
        let text = "Reading package lists...\nInst libc6 [2.41-11] (2.41-12 Debian-Security:13/stable-security [amd64])\n\
                    Inst tzdata [2025a-4] (2025b-0+deb13u1 Debian:13.2/stable [all])\nConf libc6 (2.41-12 Debian-Security:13/stable-security [amd64])\n";
        assert_eq!(parse_apt_simulation(text), (2, vec!["libc6".to_string()]));
        let r = PatchReport {
            upgradable: Some(2),
            security_count: 1,
            security: vec!["libc6".into()],
            running_kernel: Some("6.12.9+deb13-amd64".into()),
            newest_kernel: Some("6.12.48+deb13-amd64".into()),
            stale: vec![Stale { process: "sshd".into(), pids: 2, file: "/usr/lib/x86_64-linux-gnu/libc.so.6".into() }],
            ..Default::default()
        };
        let c = r.concerns();
        assert_eq!(c.len(), 3, "{c:?}");
        assert!(c[0].starts_with("1 security updates pending (libc6)"));
        assert!(c[1].contains("6.12.48+deb13-amd64 is installed but 6.12.9+deb13-amd64 runs"));
        assert!(c[2].contains("1 programs still run replaced code (sshd)"));
        assert_eq!(PatchReport { upgradable: Some(0), ..Default::default() }.summary(), "up to date");
        assert_eq!(PatchReport { upgradable: Some(3), ..Default::default() }.summary(), "3 updates pending, none for security");
        assert!(r.summary().ends_with("; 1 other updates pending"), "{}", r.summary());
        let kernel = PatchReport {
            upgradable: Some(0),
            running_kernel: Some("7.2.10".into()),
            newest_kernel: Some("7.2.11".into()),
            ..Default::default()
        };
        assert_eq!(kernel.summary(), "kernel 7.2.11 is installed but 7.2.10 runs: reboot", "none pending: not said");
    }

    #[test]
    fn apt_runs_outside_the_service_under_systemd() {
        let cfg = PatchesCfg { systemd_run: "/bin/sh".into(), ..Default::default() };
        let args = |c: &Command| c.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let unit = apt_command(&cfg, true);
        assert_eq!(unit.get_program(), "/bin/sh");
        let a = args(&unit);
        assert!(a.contains(&"--pipe".to_string()) && a.contains(&"--property=MemoryMax=512M".to_string()), "{a:?}");
        assert_eq!(a.last().map(String::as_str), Some("/usr/bin/apt-get"));
        // started by hand, or without systemd-run: apt itself
        assert_eq!(apt_command(&cfg, false).get_program(), "/usr/bin/apt-get");
        let missing = PatchesCfg { systemd_run: "/nonexistent/systemd-run".into(), ..Default::default() };
        assert_eq!(apt_command(&missing, true).get_program(), "/usr/bin/apt-get");
    }

    #[test]
    fn replaced_files_in_proc() {
        let maps = "7f00-7f01 r-xp 00000000 08:01 123 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n\
                    7f02-7f03 rw-s 00000000 00:01 9 /dev/shm/x (deleted)\n";
        assert_eq!(stale_file(Some("/usr/sbin/sshd"), maps).as_deref(), Some("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
        assert_eq!(stale_file(Some("/usr/sbin/sshd (deleted)"), "").as_deref(), Some("/usr/sbin/sshd"));
        assert_eq!(stale_file(Some("/tmp/x (deleted)"), "7f-7f rw-s 0 00:01 9 /dev/shm/y (deleted)\n"), None, "not an upgrade");
        assert_eq!(stale_file(None, "7f-7f r--p 0 08:01 5 /usr/share/locale/x.mo (deleted)\n"), None, "libraries only");
    }

    #[test]
    fn dnf_check_update_output() {
        // dnf 4: a blank line first, a long name wrapped, obsoleted packages at the end
        let dnf4 = "\nopenssl-libs.x86_64                 1:3.2.2-9.fc41           updates\n\
                    kernel-core.x86_64                  6.11.5-300.fc41          updates\n\
                    a-very-long-package-name-indeed.noarch\n                                    2.0-1.fc41               updates\n\
                    openssl-libs.i686                   1:3.2.2-9.fc41           updates\n\
                    Obsoleting Packages\nnew-thing.x86_64  1.0-1.fc41  updates\n    old-thing.x86_64  0.9-1.fc41  @System\n";
        assert_eq!(parse_dnf_check_update(dnf4), ["a-very-long-package-name-indeed", "kernel-core", "openssl-libs"]);
        // dnf 5
        let dnf5 = "Repositories loaded.\nopenssh-server.aarch64 9.8p1-3.fc42 updates\nSecurity: kernel-core-6.11.4-301.fc42.aarch64 is an installed security update\n";
        assert_eq!(parse_dnf_check_update(dnf5), ["openssh-server"]);
        assert!(parse_dnf_check_update("").is_empty());
        let r = PatchReport {
            manager: PackageManager::Dnf,
            upgradable: Some(1),
            security_count: 1,
            security: vec!["openssh-server".into()],
            ..Default::default()
        };
        assert_eq!(r.concerns(), ["1 security updates pending (openssh-server): dnf upgrade"]);
    }

    #[test]
    fn dnf_runs_outside_the_service_too() {
        let cfg = PatchesCfg { systemd_run: "/bin/sh".into(), package_manager: PackageManager::Dnf, ..Default::default() };
        let unit = apt_command(&cfg, true);
        let a: Vec<String> = unit.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert!(a.contains(&"--property=MemoryMax=1G".to_string()), "{a:?}");
        assert_eq!(a.last().map(String::as_str), Some("/usr/bin/dnf"));
        assert_eq!(apt_command(&cfg, false).get_program(), "/usr/bin/dnf");
    }
}
