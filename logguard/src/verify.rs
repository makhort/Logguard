//! Package and set-uid verification, weekly by default.
//!
//! - **Package files:** every program and library a package installed under `dirs` is
//!   hashed and compared with the MD5 dpkg recorded for it (`/var/lib/dpkg/info/*.md5sums`),
//!   like `debsums`. A replaced `/usr/bin/ssh` or `libpam` module is how a rootkit stays
//!   hidden. Files diverted with `dpkg-divert` are left out; a mismatch is checked again
//!   after the pass (an upgrade may have been running).
//! - **Set-uid and set-gid programs** under `suid_roots`: a new one, or a changed one, is how
//!   an intruder keeps root. The list is learned on the first run.
//!
//! The pass reads at most `max_rate_mb` MB a second, so it never competes with the services.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::cronwatch::{Finding, Origin};
use crate::engine::Severity;
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerifyCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Package files under these directories are checked (`/usr/bin` and `/bin`, its alias
    /// on merged-/usr systems, are the same).
    pub dirs: Vec<String>,
    /// ...except under these.
    pub exclude: Vec<String>,
    /// Where set-uid/set-gid programs are looked for (not crossing into `suid_exclude`).
    pub suid_roots: Vec<PathBuf>,
    pub suid_exclude: Vec<PathBuf>,
    /// Read speed cap, MB per second.
    pub max_rate_mb: u64,
    pub dpkg_db: PathBuf,
}

impl Default for VerifyCfg {
    fn default() -> Self {
        VerifyCfg {
            enabled: true,
            interval: Dur(7 * 86_400),
            dirs: ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec"].map(String::from).to_vec(),
            exclude: ["/usr/lib/firmware"].map(String::from).to_vec(),
            suid_roots: ["/usr", "/bin", "/sbin", "/opt", "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/srv", "/etc", "/boot"]
                .map(PathBuf::from)
                .to_vec(),
            suid_exclude: ["/var/lib/docker", "/proc", "/sys"].map(PathBuf::from).to_vec(),
            max_rate_mb: 20,
            dpkg_db: "/var/lib/dpkg".into(),
        }
    }
}

impl VerifyCfg {
    pub fn validate(&self) -> Result<()> {
        if self.max_rate_mb == 0 {
            bail!("[verify] max_rate_mb must be at least 1");
        }
        if self.enabled && self.interval.0 < 3600 {
            bail!("[verify] interval must be at least 1h (a pass reads every package file)");
        }
        Ok(())
    }
}

/// A set-uid or set-gid program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suid {
    pub mode: u32,
    pub uid: u32,
    pub sha256: String,
}

impl Suid {
    fn kind(&self) -> &'static str {
        match (self.mode & 0o4000 != 0, self.mode & 0o2000 != 0) {
            (true, true) => "set-uid and set-gid",
            (true, false) => "set-uid",
            _ => "set-gid",
        }
    }

    fn describe(&self) -> String {
        format!("{}, owner uid {}, mode {:o}", self.kind(), self.uid, self.mode & 0o7777)
    }
}

#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub started: Micros,
    pub finished: Micros,
    /// Package files hashed.
    pub checked: u64,
    /// Package files missing.
    pub missing: u64,
    /// path -> (package, its MD5 now)
    pub mismatched: BTreeMap<String, (String, String)>,
    pub suid: BTreeMap<String, Suid>,
    /// Package origin of the set-uid programs.
    pub origins: BTreeMap<String, Origin>,
    /// Set-uid/set-gid files found beyond what a pass keeps (`MAX_SUID_ROOT`, `MAX_SUID_OTHER`).
    pub suid_overflow: usize,
    pub errors: Vec<String>,
}

/// The accepted state, persisted across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerifyBaseline {
    pub last_run: Micros,
    /// Package files known to differ (path -> MD5 now): reported once.
    pub mismatched: BTreeMap<String, String>,
    pub suid: BTreeMap<String, Suid>,
}

/// Summary for `status` and the dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerifyView {
    pub last_run: Micros,
    pub checked: u64,
    pub mismatched: usize,
    pub suid: usize,
}

/// Paths dpkg-divert moved aside: the file at the original path is someone else's.
fn diversions(db: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(db.join("diversions")).unwrap_or_default();
    text.lines().step_by(3).map(str::to_string).collect()
}

/// A path from an md5sums file (`usr/bin/ls`, or `bin/ls` before merged /usr) as it is under
/// /usr, for matching `dirs`.
fn under_usr(rel: &str) -> String {
    if ["bin/", "sbin/", "lib/", "lib64/", "lib32/", "libx32/"].iter().any(|d| rel.starts_with(d)) {
        format!("/usr/{rel}")
    } else {
        format!("/{rel}")
    }
}

fn wanted(cfg: &VerifyCfg, path: &str) -> bool {
    let inside = |d: &String| path.strip_prefix(d.as_str()).is_some_and(|r| r.starts_with('/'));
    cfg.dirs.iter().any(inside) && !cfg.exclude.iter().any(inside)
}

/// Sleeps as long as reading `bytes` at `rate_mb` MB/s takes, less the time `since` spent.
fn pace(bytes: u64, rate_mb: u64, since: Instant) {
    let due = Duration::from_secs_f64(bytes as f64 / (rate_mb.max(1) as f64 * 1_048_576.0));
    if let Some(rest) = due.checked_sub(since.elapsed()) {
        std::thread::sleep(rest);
    }
}

/// MD5 of a file, without leaving it in the page cache: a pass reads gigabytes, and the cache
/// they'd fill is charged to the service's memory limit (`MemoryHigh` throttles it).
fn md5_uncached(path: &Path) -> std::io::Result<String> {
    use md5::{Digest as _, Md5};
    let mut f = crate::cronwatch::open_regular(path)?;
    let mut h = Md5::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    drop_cache(&f);
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Tells the kernel the file's cached pages aren't needed any more (Linux).
#[cfg(target_os = "linux")]
fn drop_cache(f: &std::fs::File) {
    use std::os::fd::AsRawFd;
    extern "C" {
        fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    }
    const POSIX_FADV_DONTNEED: i32 = 4;
    // SAFETY: an advisory call on a file descriptor this function borrows; no memory is touched.
    unsafe {
        posix_fadvise(f.as_raw_fd(), 0, 0, POSIX_FADV_DONTNEED);
    }
}

#[cfg(not(target_os = "linux"))]
fn drop_cache(_: &std::fs::File) {}

/// The expected MD5 of `rel` in a package's md5sums file.
fn expected_md5(info: &Path, stem: &str, rel: &str) -> Option<String> {
    let f = std::fs::File::open(info.join(format!("{stem}.md5sums"))).ok()?;
    std::io::BufReader::new(f).lines().map_while(Result::ok).find_map(|l| {
        let (md5, r) = l.split_once("  ")?;
        (r == rel).then(|| md5.to_string())
    })
}

/// Checks the package files under `cfg.dirs` against dpkg's checksums.
fn check_packages(cfg: &VerifyCfg, r: &mut VerifyReport, stop: &dyn Fn() -> bool) {
    let info = cfg.dpkg_db.join("info");
    let Ok(rd) = std::fs::read_dir(&info) else { return };
    let diverted = diversions(&cfg.dpkg_db);
    // (path, package file stem, path in md5sums)
    let mut suspects: Vec<(String, String, String)> = Vec::new();
    let mut names: Vec<String> =
        rd.flatten().filter_map(|e| e.file_name().to_str()?.strip_suffix(".md5sums").map(str::to_string)).collect();
    names.sort();
    for stem in names {
        if stop() {
            return;
        }
        let Ok(f) = std::fs::File::open(info.join(format!("{stem}.md5sums"))) else { continue };
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            let Some((want, rel)) = line.split_once("  ") else { continue };
            let usr = under_usr(rel);
            let path = format!("/{rel}");
            if !wanted(cfg, &usr) || diverted.contains(&path) || diverted.contains(&usr) {
                continue;
            }
            // symlinks aren't in md5sums; what dpkg lists there is a regular file
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                r.missing += 1;
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let start = Instant::now();
            match md5_uncached(Path::new(&path)) {
                Ok(have) => {
                    r.checked += 1;
                    if !have.eq_ignore_ascii_case(want) && suspects.len() < MAX_SUSPECTS {
                        suspects.push((path, stem.clone(), rel.to_string()));
                    }
                }
                Err(e) => note_error(r, format!("{path}: {e}")),
            }
            pace(meta.len(), cfg.max_rate_mb, start);
        }
    }
    // An upgrade during the pass changes both the file and its checksum: look again.
    for (path, stem, rel) in suspects {
        let (Some(want), Ok(have)) = (expected_md5(&info, &stem, &rel), md5_uncached(Path::new(&path))) else { continue };
        if !have.eq_ignore_ascii_case(&want) {
            let pkg = stem.split(':').next().unwrap_or(&stem).to_string();
            r.mismatched.insert(path, (pkg, have));
        }
    }
}

/// SHA-256 of the first `max` bytes of a file.
fn sha256_file(path: &Path, max: u64) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = crate::cronwatch::open_regular(path)?.take(max);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Errors kept per pass, and package files rechecked after it: enough to tell what is wrong,
/// bounded whatever a broken system (or dpkg database) looks like.
const MAX_ERRORS: usize = 20;
const MAX_SUSPECTS: usize = 1000;

fn note_error(r: &mut VerifyReport, e: String) {
    if r.errors.len() < MAX_ERRORS {
        r.errors.push(e);
    }
}

/// Most entries visited looking for set-uid programs (a pass over a server's system
/// directories is a few hundred thousand).
const MAX_WALK: usize = 3_000_000;

/// Set-uid/set-gid files kept per pass. Only root makes one owned by root (a system has a few
/// dozen); any user can make thousands of their own in /tmp or their home, which must not
/// fill the daemon's memory, the state file or the admins' chat.
const MAX_SUID_ROOT: usize = 10_000;
const MAX_SUID_OTHER: usize = 1_000;
/// Bytes hashed of one: a root-owned program in full (up to this), a user's own only its start.
const SUID_HASHED_ROOT: u64 = 64 << 20;
const SUID_HASHED_OTHER: u64 = 1 << 20;
/// Changes to set-uid programs named one by one; the rest are listed in one more alert.
const MAX_SUID_REPORTED: usize = 20;

/// Where the host's own file system is seen: the service runs with a private /tmp
/// (`PrivateTmp=yes`), and set-uid files in the real /tmp are the interesting ones. Through
/// init's root (`/proc/1/root`) when it can be read, else as is.
fn host_root() -> Option<PathBuf> {
    let base = PathBuf::from("/proc/1/root");
    base.join("usr").is_dir().then_some(base)
}

/// Set-uid and set-gid regular files under `cfg.suid_roots`.
fn find_suid(cfg: &VerifyCfg, r: &mut VerifyReport, stop: &dyn Fn() -> bool) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let base = host_root();
    let real = |p: &Path| base.as_ref().map_or_else(|| p.to_path_buf(), |b| b.join(p.strip_prefix("/").unwrap_or(p)));
    let shown = |p: &Path| base.as_ref().and_then(|b| p.strip_prefix(b).ok()).map_or_else(|| p.to_path_buf(), |r| Path::new("/").join(r));
    let mut stack: Vec<PathBuf> = cfg.suid_roots.iter().map(|p| real(p)).collect();
    let mut seen_dirs: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut visited = 0usize;
    let mut others = 0usize;
    while let Some(dir) = stack.pop() {
        if visited >= MAX_WALK || stop() {
            note_error(r, format!("set-uid search stopped after {visited} entries"));
            return;
        }
        if cfg.suid_exclude.iter().any(|x| shown(&dir).starts_with(x)) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&dir) else { continue };
        // a directory reached twice (bind mounts) is read once
        if !meta.is_dir() || !seen_dirs.insert((meta.dev(), meta.ino())) {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            visited += 1;
            let Ok(m) = e.metadata() else { continue }; // DirEntry::metadata doesn't follow links
            let path = e.path();
            if m.is_dir() {
                stack.push(path);
            } else if m.is_file() && m.permissions().mode() & 0o6000 != 0 {
                let root = m.uid() == 0;
                if (root && r.suid.len() - others >= MAX_SUID_ROOT) || (!root && others >= MAX_SUID_OTHER) {
                    r.suid_overflow += 1;
                    continue;
                }
                let p = crate::event::clean(&shown(&path).display().to_string(), 500);
                let start = Instant::now();
                match sha256_file(&path, if root { SUID_HASHED_ROOT } else { SUID_HASHED_OTHER }) {
                    Ok(sha256) => {
                        others += usize::from(!root && !r.suid.contains_key(&p));
                        r.suid.insert(p, Suid { mode: m.permissions().mode(), uid: m.uid(), sha256 });
                    }
                    Err(e) => note_error(r, format!("{p}: {e}")),
                }
                pace(m.len().min(if root { SUID_HASHED_ROOT } else { SUID_HASHED_OTHER }), cfg.max_rate_mb, start);
            }
        }
    }
}

/// One pass; `stop` is asked between files (the daemon stopping).
pub fn scan(cfg: &VerifyCfg, stop: &dyn Fn() -> bool) -> VerifyReport {
    let mut r = VerifyReport { started: time::now(), ..Default::default() };
    if !cfg.dpkg_db.as_os_str().is_empty() {
        check_packages(cfg, &mut r, stop);
    }
    find_suid(cfg, &mut r, stop);
    let paths: Vec<String> = r.suid.keys().cloned().collect();
    if !paths.is_empty() && !cfg.dpkg_db.as_os_str().is_empty() {
        let o = crate::cronwatch::dpkg_origins(&cfg.dpkg_db, &paths);
        r.origins = paths.into_iter().map(|p| (p.clone(), o.get(&p).cloned().unwrap_or(Origin::Local))).collect();
    }
    r.finished = time::now();
    r
}

fn listed(items: &[String], max: usize) -> Vec<String> {
    let mut v: Vec<String> = items.iter().take(max).cloned().collect();
    if items.len() > max {
        v.push(format!("... and {} more", items.len() - max));
    }
    v
}

/// Compares a pass with the baseline, updates it, and says what changed.
pub fn judge(baseline: &mut Option<VerifyBaseline>, r: &VerifyReport) -> Vec<Finding> {
    let mut out = Vec::new();
    let finding = |key: String, severity, message: String, evidence: Vec<String>, notify| Finding {
        key,
        every: 0,
        severity,
        message,
        evidence,
        notify,
        owner: None,
    };
    let first = baseline.is_none();
    let b = baseline.get_or_insert_with(Default::default);
    b.last_run = r.finished;
    if !r.errors.is_empty() {
        out.push(finding(
            format!("verify-errors:{}", r.finished),
            Severity::Info,
            format!("package check: some files could not be read ({})", r.errors.join("; ")),
            vec![],
            false,
        ));
    }

    let new_mismatch: Vec<String> = r
        .mismatched
        .iter()
        .filter(|(p, (_, md5))| b.mismatched.get(*p) != Some(md5))
        .map(|(p, (pkg, _))| format!("{p} (package {pkg})"))
        .collect();
    if !new_mismatch.is_empty() {
        let (severity, advice) = if first {
            (Severity::Warning, "first check: changed by hand, or by an intruder")
        } else {
            (Severity::High, "if nobody here changed them, the server may be compromised (reinstall: apt install --reinstall <package>)")
        };
        out.push(finding(
            format!("verify-packages:{}", r.finished),
            severity,
            format!("{} package files differ from what dpkg installed - {advice}", new_mismatch.len()),
            listed(&new_mismatch, 30),
            true,
        ));
    }
    b.mismatched = r.mismatched.iter().map(|(p, (_, md5))| (p.clone(), md5.clone())).collect();

    if r.suid_overflow > 0 {
        out.push(finding(
            format!("suid-overflow:{}", r.finished),
            Severity::High,
            format!(
                "integrity: {} more set-uid/set-gid files than a pass checks ({MAX_SUID_ROOT} owned by root, {MAX_SUID_OTHER} by others) \
                 were left out - who made so many? (find / -xdev -perm /6000 -type f)",
                r.suid_overflow
            ),
            vec![],
            true,
        ));
    }
    if first {
        out.push(finding(
            "verify-learned".into(),
            Severity::Info,
            format!(
                "package check: {} files match dpkg's checksums; {} set-uid/set-gid programs learned, changes are reported from now on",
                r.checked,
                r.suid.len()
            ),
            vec![],
            true,
        ));
        b.suid = r.suid.clone();
        return out;
    }
    let origin = |p: &str| r.origins.get(p).cloned().unwrap_or(Origin::Local);
    let (mut more, mut more_severity) = (Vec::new(), Severity::Warning);
    for (p, s) in &r.suid {
        let message = match b.suid.get(p) {
            None => format!("new {} program {p} (owner uid {}, mode {:o}; {})", s.kind(), s.uid, s.mode & 0o7777, origin_text(&origin(p))),
            Some(old) if old.sha256 != s.sha256 => format!("set-uid program {p} changed ({})", origin_text(&origin(p))),
            Some(old) if old.mode != s.mode || old.uid != s.uid => {
                format!("set-uid program {p} now {} (was {})", s.describe(), old.describe())
            }
            Some(_) => continue,
        };
        let severity = if matches!(origin(p), Origin::Package(_)) { Severity::Warning } else { Severity::High };
        if out.iter().filter(|f| f.key.starts_with("suid:")).count() >= MAX_SUID_REPORTED {
            more.push(message);
            more_severity = more_severity.max(severity);
            continue;
        }
        let advice = if severity == Severity::High { " - if nobody here made it, the server may be compromised" } else { "" };
        out.push(finding(format!("suid:{p}:{}", r.finished), severity, format!("integrity: {message}{advice}"), vec![], true));
    }
    if !more.is_empty() {
        out.push(finding(
            format!("suid-more:{}", r.finished),
            more_severity,
            format!("integrity: {} more set-uid/set-gid programs are new or changed", more.len()),
            listed(&more, 30),
            true,
        ));
    }
    if r.suid_overflow > 0 {
        // an incomplete pass: what it didn't reach isn't gone
        for (p, s) in &r.suid {
            if b.suid.len() < MAX_SUID_ROOT + MAX_SUID_OTHER || b.suid.contains_key(p) {
                b.suid.insert(p.clone(), s.clone());
            }
        }
        return out;
    }
    let gone: Vec<String> = b.suid.keys().filter(|p| !r.suid.contains_key(*p)).cloned().collect();
    if !gone.is_empty() {
        out.push(finding(
            format!("suid-gone:{}", r.finished),
            Severity::Info,
            format!("{} set-uid/set-gid programs are gone (removed packages?)", gone.len()),
            listed(&gone, 20),
            false,
        ));
    }
    b.suid = r.suid.clone();
    out
}

fn origin_text(o: &Origin) -> String {
    match o {
        Origin::Package(p) => format!("installed by package {p}, unmodified"),
        Origin::ModifiedPackage(p) => format!("from package {p}, but modified since installation"),
        Origin::Local => "not from any package".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5(t: &str) -> String {
        use md5::{Digest as _, Md5};
        Md5::digest(t.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn checks_package_files_against_dpkg() {
        let dir = std::env::temp_dir().join(format!("logguard-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (db, root) = (dir.join("db"), dir.join("usr").join("bin"));
        std::fs::create_dir_all(db.join("info")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let rel = |n: &str| root.join(n).display().to_string()[1..].to_string();
        std::fs::write(root.join("good"), "good\n").unwrap();
        std::fs::write(root.join("evil"), "trojan\n").unwrap();
        std::fs::write(root.join("diverted"), "other\n").unwrap();
        std::fs::write(
            db.join("info/coreutils.md5sums"),
            format!(
                "{}  {}\n{}  {}\n{}  {}\n{}  {}\n",
                md5("good\n"),
                rel("good"),
                md5("original\n"),
                rel("evil"),
                md5("original\n"),
                rel("diverted"),
                md5("x\n"),
                rel("gone")
            ),
        )
        .unwrap();
        std::fs::write(db.join("diversions"), format!("/{}\n/{}.distrib\nother\n", rel("diverted"), rel("diverted"))).unwrap();
        let top = dir.display().to_string();
        let cfg = VerifyCfg {
            dirs: vec![top.clone()],
            exclude: vec![],
            suid_roots: vec![dir.clone()],
            suid_exclude: vec![],
            dpkg_db: db.clone(),
            max_rate_mb: 1000,
            ..Default::default()
        };
        // under_usr only rewrites unmerged system paths: the temp dir is matched as it is
        assert!(wanted(&cfg, &format!("{top}/usr/bin/good")));
        let r = scan(&cfg, &|| false);
        assert_eq!((r.checked, r.missing), (2, 1), "{:?}", r.errors);
        assert_eq!(r.mismatched.keys().cloned().collect::<Vec<_>>(), vec![format!("/{}", rel("evil"))]);

        let mut b = None;
        let f = judge(&mut b, &r);
        assert!(f.iter().any(|x| x.severity == Severity::Warning && x.message.starts_with("1 package files differ")), "{f:?}");
        assert!(judge(&mut b, &r).is_empty(), "known mismatches are reported once");

        // a set-uid program appears
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(dir.join("sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(dir.join("sh"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        let r2 = scan(&cfg, &|| false);
        let f = judge(&mut b, &r2);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].message.contains("new set-uid program") && f[0].message.contains("not from any package"), "{}", f[0].message);
        // changed
        std::fs::write(dir.join("sh"), "#!/bin/sh\nid\n").unwrap();
        std::fs::set_permissions(dir.join("sh"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        let f = judge(&mut b, &scan(&cfg, &|| false));
        assert!(f.len() == 1 && f[0].message.contains("changed"), "{f:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Any user can make set-uid files of their own: thousands of them neither fill the
    /// memory and the state nor become one alert each.
    #[test]
    fn a_flood_of_set_uid_files_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("logguard-suid-flood-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = VerifyCfg {
            dirs: vec![],
            suid_roots: vec![dir.clone()],
            suid_exclude: vec![],
            dpkg_db: PathBuf::new(),
            max_rate_mb: 1000,
            ..Default::default()
        };
        let make = |range: std::ops::Range<usize>| {
            for i in range {
                let f = dir.join(format!("s{i:05}"));
                std::fs::write(&f, format!("{i}")).unwrap();
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
            }
        };
        let mut b = None;
        judge(&mut b, &scan(&cfg, &|| false));
        make(0..25);
        let f = judge(&mut b, &scan(&cfg, &|| false));
        assert_eq!(f.iter().filter(|x| x.key.starts_with("suid:")).count(), MAX_SUID_REPORTED, "{f:?}");
        let rest = f.iter().find(|x| x.key.starts_with("suid-more:")).unwrap();
        assert!(rest.message.contains("5 more") && rest.evidence.len() == 5 && rest.notify, "{rest:?}");

        make(25..MAX_SUID_OTHER + 10);
        let r = scan(&cfg, &|| false);
        assert_eq!((r.suid.len(), r.suid_overflow), (MAX_SUID_OTHER, 10));
        let f = judge(&mut b, &r);
        assert!(f.iter().any(|x| x.key.starts_with("suid-overflow:") && x.severity == Severity::High), "{f:?}");
        assert!(f.iter().filter(|x| x.notify).count() <= MAX_SUID_REPORTED + 2, "{} alerts", f.len());
        assert!(!f.iter().any(|x| x.key.starts_with("suid-gone:")), "an incomplete pass reports nothing gone");
        assert!(b.as_ref().unwrap().suid.len() <= MAX_SUID_ROOT + MAX_SUID_OTHER);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merged_usr_paths() {
        assert_eq!(under_usr("bin/ls"), "/usr/bin/ls");
        assert_eq!(under_usr("usr/lib/x.so"), "/usr/lib/x.so");
        let cfg = VerifyCfg::default();
        assert!(wanted(&cfg, "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"));
        assert!(!wanted(&cfg, "/usr/lib/firmware/x.bin"));
        assert!(!wanted(&cfg, "/usr/library/x"), "a prefix of a name is not a directory");
        assert!(!wanted(&cfg, "/usr/share/doc/x"));
    }
}
