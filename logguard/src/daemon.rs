//! The long-running service: follows the journal, detects, enforces, persists
//! state and serves snapshots to the TUI over a Unix socket.

use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::config::Config;
use crate::enforce::Enforcer;
use crate::engine::{Action, PersistedState, Severity};
use crate::notify::Notifier;
use crate::pipeline::Pipeline;
use crate::record::{parse_journal_json, Record};
use crate::replay::format_action;
use crate::time;

enum Msg {
    Rec(Record),
    /// A live record from a non-journal source (Nextcloud), with the name of the log it came
    /// from: held back during catch-up.
    Live(&'static str, Record),
    /// How far a followed log has been read (any line, event or not), about once a minute;
    /// after the records read before it, so it never gets ahead of them.
    Position(&'static str, time::Micros),
    Cursor(String),
    Exposure(Box<crate::exposure::ExposureReport>),
    /// A peer's message, with the address it came from (for `peer_accept`).
    Peer(Box<crate::cluster::Envelope>, Option<std::net::IpAddr>),
    Delivered(usize, Result<(), String>),
    Feeds(Vec<crate::net::Net>, Box<crate::feeds::FeedStatus>),
    /// A `[waf]` refresh: the list, and each ban source's decisions.
    Waf(Box<crate::waf::WafUpdate>),
    /// The cluster peers resolved again, with what could not be resolved.
    PeerNets(Vec<crate::net::Net>, Vec<String>),
    Certs(Vec<crate::digest::CertStatus>),
    /// A (re)loaded geo database, plus download problems to report.
    Geo(Option<Arc<crate::geo::GeoDb>>, Vec<String>),
    /// Release the geo database before a reload (acknowledged), so two copies never
    /// coexist under the service's memory limit.
    GeoRelease(std::sync::mpsc::SyncSender<()>),
    Cron(Box<crate::cronwatch::CronReport>),
    Av(Box<crate::avscan::AvReport>),
    Resources(Box<crate::resources::Report>),
    /// journalctl kept rejecting the saved journal position: what to tell the admins.
    JournalReset(String),
    /// What `journalctl --verify` found wrong (empty: nothing).
    JournalVerify(Vec<String>),
    /// The `[allowlist] hosts` resolved again, with what could not be resolved, and whether
    /// that has gone on long enough to tell the admins (not a lookup at boot before DNS works).
    AllowHosts(Vec<crate::net::Net>, Vec<String>, bool),
    Patches(Box<crate::patches::PatchReport>),
    Verify(Box<crate::verify::VerifyReport>),
    Proc(Box<crate::procwatch::ProcReport>),
    SshAudit(Box<crate::sshaudit::SshAuditReport>),
    /// A completed handshake with a honeypot listener (`[ports] honeypot`), with its time.
    Honeypot(crate::honeypot::Hit, time::Micros),
    /// A line of a log file a pattern of your own reads (`[[patterns]] file`).
    Custom(Record),
    /// A scan of changed files finished (`[antivirus] scan_changed`).
    FileScan(Box<crate::filescan::ScanReport>),
}

/// Most files handed to one scan of changed files; the rest wait for the next.
const MAX_SCAN_BATCH: usize = 200;

/// The journal fields `record::parse_journal_json` reads (journalctl adds the cursor and the
/// time itself). Only these are printed: any local user can log entries with hundreds of
/// fields of their own, which would otherwise come along, each up to 4 KB.
const JOURNAL_FIELDS: &str = "MESSAGE,SYSLOG_IDENTIFIER,SYSLOG_PID,_SYSTEMD_UNIT,_PID,_EXE,_TRANSPORT,_UID";

/// Longest journal line read: with only [`JOURNAL_FIELDS`] (each at most 4 KB, which JSON
/// escaping can make a few times longer) a real one is far shorter.
const MAX_JOURNAL_LINE: u64 = 1 << 20;

pub fn journalctl_args(cfg: &Config, cursor: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["--follow", "--output=json", "--no-pager", "--quiet"].map(String::from).to_vec();
    args.push(format!("--output-fields={JOURNAL_FIELDS}"));
    match cursor {
        Some(c) => args.push(format!("--after-cursor={c}")),
        None => args.push(format!("--since=-{}s", cfg.journal.initial_lookback.0)),
    }
    for (i, m) in cfg.journal_matches().iter().enumerate() {
        if i > 0 {
            args.push("+".into());
        }
        args.push(m.clone());
    }
    args
}

/// Runs journalctl, restarting it from the last seen cursor if it ever exits.
fn reader(cfg: Arc<Config>, mut cursor: Option<String>, tx: SyncSender<Msg>, child_slot: Arc<Mutex<Option<Child>>>, stop: Arc<AtomicBool>) {
    let lookback = cfg.journal.initial_lookback;
    let mut quick_exits = 0;
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let args = journalctl_args(&cfg, cursor.as_deref());
        let spawned = Command::new(&cfg.journal.journalctl).args(&args).stdin(Stdio::null()).stdout(Stdio::piped()).spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                eprintln!("logguard: cannot start {}: {e}", cfg.journal.journalctl.display());
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let stdout = child.stdout.take().expect("piped stdout");
        *child_slot.lock().unwrap() = Some(child);
        let (mut lines, mut buf) = (BufReader::new(stdout), Vec::new());
        loop {
            buf.clear();
            if !matches!(crate::record::read_line_capped(&mut lines, &mut buf, MAX_JOURNAL_LINE), Ok(n) if n > 0) {
                break;
            }
            // a line cut short isn't JSON any more: skipped, as one journalctl can't print
            let (rec, cur) = parse_journal_json(&String::from_utf8_lossy(&buf));
            if let Some(c) = &cur {
                cursor = Some(c.clone());
            }
            let msg = match (rec, cur) {
                (Some(r), _) => Msg::Rec(r),
                (None, Some(c)) => Msg::Cursor(c),
                (None, None) => continue,
            };
            if tx.send(msg).is_err() {
                return;
            }
        }
        if let Some(mut c) = child_slot.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if !stop.load(Ordering::Relaxed) {
            // A saved cursor journald no longer accepts (e.g. its files were vacuumed) makes
            // journalctl exit immediately; don't retry it forever.
            quick_exits = if started.elapsed() < Duration::from_secs(3) { quick_exits + 1 } else { 0 };
            if quick_exits >= 2 && cursor.is_some() {
                eprintln!("logguard: journalctl keeps rejecting the saved position; reading the last {lookback} instead");
                cursor = None;
                quick_exits = 0;
                // Lines between the saved position and the lookback may never be read. Normal
                // after a downtime longer than journald keeps logs; otherwise someone may have
                // removed journal files (evidence).
                let msg = format!(
                    "journald no longer has logguard's saved position in the journal (its files were rotated or vacuumed away, \
                     or deleted): reading the last {lookback} instead, so lines logged in between may never have been read. \
                     Expected after a downtime longer than journald keeps logs; otherwise check who removed journal files \
                     (ls -l /var/log/journal/*; journalctl --verify)"
                );
                if tx.send(Msg::JournalReset(msg)).is_err() {
                    return;
                }
            }
            eprintln!("logguard: journalctl exited, restarting in 5s");
            thread::sleep(Duration::from_secs(5));
        }
    }
}

/// Longest line kept from a followed log: Apache's lines are at most a few KB, and a failed
/// login in nextcloud.log is short. The rest of a longer one is read and dropped, so a line
/// without end can't grow without bound.
const MAX_FOLLOWED_LINE: u64 = 64 * 1024;

/// Follows a command's stdout and stderr line by line (e.g. `docker logs -f`, `tail -F`),
/// restarting it whenever it exits (container recreated, Docker restarted, file missing).
/// `start` is the time of the last line processed before (kept in the state file, see
/// `Engine::followers`): `args` gets the newest line's time before every start, to resume
/// from there, and lines up to it are skipped as already seen.
fn follow(
    name: &'static str,
    program: PathBuf,
    args: impl Fn(time::Micros) -> Vec<String> + Send + 'static,
    start: time::Micros,
    tx: SyncSender<Msg>,
    stop: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let last = Arc::new(std::sync::atomic::AtomicI64::new(start));
        let mut warned = false;
        while !stop.load(Ordering::Relaxed) {
            // Only lines newer than this are new: a resumed program repeats some old ones.
            // (Lines in one run are all taken: several can share a second.)
            let seen = last.load(Ordering::Relaxed);
            let child = Command::new(&program).args(args(seen)).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    if !warned {
                        warned = true;
                        eprintln!("logguard: {name}: cannot run {}: {e}", program.display());
                    }
                    thread::sleep(Duration::from_secs(30));
                    continue;
                }
            };
            // docker logs writes the container's stderr (Apache's error log) to stderr.
            let readers: Vec<_> = [
                child.stdout.take().map(|o| Box::new(o) as Box<dyn Read + Send>),
                child.stderr.take().map(|e| Box::new(e) as Box<dyn Read + Send>),
            ]
            .into_iter()
            .flatten()
            .map(|pipe| {
                let (tx, last) = (tx.clone(), Arc::clone(&last));
                thread::spawn(move || {
                    // Not `lines()`: it stops at the first line that isn't valid UTF-8, and the
                    // child would then block forever on a full pipe.
                    let mut reader = BufReader::new(pipe);
                    let mut buf = Vec::new();
                    let mut reported = seen;
                    while matches!(crate::record::read_line_capped(&mut reader, &mut buf, MAX_FOLLOWED_LINE), Ok(n) if n > 0) {
                        let text = String::from_utf8_lossy(&buf);
                        if let Some(rec) = crate::record::parse_nextcloud_line(&text).filter(|r| r.ts > seen) {
                            last.fetch_max(rec.ts, Ordering::Relaxed);
                            if tx.send(Msg::Live(name, rec)).is_err() {
                                return;
                            }
                        }
                        // Quiet logs (no events for weeks) must still move the position, or a
                        // restart would replay all of it (docker) or skip the gap (tail).
                        if let Some(t) = crate::record::line_time(&text).filter(|t| *t > seen) {
                            last.fetch_max(t, Ordering::Relaxed);
                            if t - reported >= 60 * time::SEC {
                                reported = t;
                                if tx.send(Msg::Position(name, t)).is_err() {
                                    return;
                                }
                            }
                        }
                        buf.clear();
                    }
                })
            })
            .collect();
            for r in readers {
                let _ = r.join();
            }
            let _ = child.wait();
            thread::sleep(Duration::from_secs(10));
        }
    });
}

/// Follows a log file a pattern reads, or auditd's (`tail -F`, from its end: lines written
/// while logguard was down aren't read), as records of `source` stamped when read.
fn follow_file(path: String, source: crate::record::Source, tx: SyncSender<Msg>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut warned = false;
        while !stop.load(Ordering::Relaxed) {
            let child = Command::new("tail")
                .args(["-F", "-n", "0", &path])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    if !warned {
                        warned = true;
                        eprintln!("logguard: {path}: cannot run tail: {e}");
                    }
                    thread::sleep(Duration::from_secs(30));
                    continue;
                }
            };
            let Some(out) = child.stdout.take() else { continue };
            let (mut reader, mut buf) = (BufReader::new(out), Vec::new());
            while matches!(crate::record::read_line_capped(&mut reader, &mut buf, MAX_FOLLOWED_LINE), Ok(n) if n > 0) {
                let msg = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
                buf.clear();
                let sender = (source == crate::record::Source::Custom)
                    .then(|| Box::new(crate::record::Sender { file: Some(path.clone()), ..Default::default() }));
                let rec = Record { ts: time::now(), source, pid: 0, msg, cursor: None, sender };
                if tx.send(Msg::Custom(rec)).is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            thread::sleep(Duration::from_secs(10));
        }
    });
}

/// `journalctl --verify` (with the sealing verification key, when one is set): the files
/// that failed, leaving out the ones journald is writing (checked while they change, they
/// can fail without anything wrong).
fn verify_journal(cfg: &Config) -> Vec<String> {
    let mut cmd = Command::new(&cfg.journal.journalctl);
    cmd.args(["--verify", "--no-pager"]);
    let key = &cfg.journal.verify_key_file;
    if !key.as_os_str().is_empty() {
        match fs::read_to_string(key) {
            Ok(k) if !k.trim().is_empty() => {
                cmd.arg(format!("--verify-key={}", k.trim()));
            }
            Ok(_) => return vec![format!("{} is empty", key.display())],
            Err(e) => return vec![format!("cannot read {}: {e}", key.display())],
        }
    }
    match crate::proc::run(cmd, None, Duration::from_secs(600)) {
        Err(e) => vec![e],
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
            let failed = failed_journal_files(&text);
            if failed.is_empty() && !out.status.success() && !text.contains("PASS") {
                vec![crate::event::clean(&out.complaint(), 300)]
            } else {
                failed
            }
        }
    }
}

/// What to tell the admins about `[journal] verify_key_file`, if it is set. A Forward Secure
/// Sealing verification key is the seed every sealing key derives from (systemd's FSPRG): who
/// holds it can seal edited journal files of any past period too. On this host, it catches
/// only an intruder who doesn't look for it; and journalctl takes it on its command line,
/// which every local user can read (`ps`) while the check runs, unless /proc hides it.
fn verify_key_warning(cfg: &Config, mountinfo: &str) -> Option<String> {
    let key = &cfg.journal.verify_key_file;
    if cfg.journal.verify_every.0 == 0 || key.as_os_str().is_empty() {
        return None;
    }
    let shown = if proc_hides_pids(mountinfo) {
        ""
    } else {
        " It is also on journalctl's command line during each check, where every local user can read it \
         (mount /proc with hidepid=invisible to hide it)."
    };
    Some(format!(
        "[journal] verify_key_file {}: a sealing verification key can seal journal entries too, for any past period, so \
         an intruder with root who reads it can rewrite the journal unnoticed. Kept on this server, the check only \
         catches tampering by someone who doesn't look for the key: keep it elsewhere and verify copies of the \
         journal there for a real guarantee.{shown}",
        key.display()
    ))
}

/// Whether /proc is mounted so that users can't see other users' processes (`hidepid`), from
/// `/proc/self/mountinfo`.
fn proc_hides_pids(mountinfo: &str) -> bool {
    mountinfo.lines().any(|l| {
        // `<id> <parent> <dev> <root> <mount point> <options> ... - <type> <source> <fs options>`
        let (head, tail) = l.split_once(" - ").unwrap_or((l, ""));
        let head: Vec<&str> = head.split_whitespace().collect();
        let opts = [head.get(5).copied(), tail.split_whitespace().nth(2)];
        head.get(4) == Some(&"/proc")
            && opts
                .iter()
                .flatten()
                .flat_map(|o| o.split(','))
                .filter_map(|o| o.strip_prefix("hidepid="))
                .any(|v| !matches!(v, "0" | "off"))
    })
}

/// The `FAIL:` lines of `journalctl --verify` about archived files (names with `@`; the
/// active `system.journal` changes while it is checked).
fn failed_journal_files(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("FAIL: "))
        .filter(|f| f.split_whitespace().next().and_then(|p| p.rsplit('/').next()).is_some_and(|name| name.contains('@')))
        .map(|f| crate::event::clean(f, 300))
        .take(10)
        .collect()
}

/// Sleeps up to `d`, waking early when the daemon stops; false when it did.
fn nap(d: Duration, stop: &AtomicBool) -> bool {
    let until = Instant::now() + d;
    while Instant::now() < until {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        thread::sleep(Duration::from_secs(1).min(until.saturating_duration_since(Instant::now())));
    }
    !stop.load(Ordering::Relaxed)
}

type Control = (String, std::sync::mpsc::Sender<String>);

fn serve_control(path: PathBuf, control: SyncSender<Control>) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    answer(listener, control, |cmd| Ok(cmd.to_string()), None);
    Ok(())
}

/// The console socket (`[console]`, for logguard-web): snapshots, the digest preview and abuse
/// reports only. It is bound after the control socket, whose owner is this process.
fn serve_console(
    cfg: &crate::console::ConsoleCfg,
    control_socket: &Path,
    control: SyncSender<Control>,
    reports: Arc<AbuseReports>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let gid = crate::console::group(cfg)?;
    let me = fs::symlink_metadata(control_socket).context("the control socket is needed first")?.uid();
    let listener = crate::console::bind(cfg, gid, me)?;
    answer(listener, control, console_admit, Some(reports));
    Ok(())
}

/// How long a built abuse report is handed out again (the console asks while its page is open).
const ABUSE_FRESH: Duration = Duration::from_secs(60);
/// Abuse report requests in progress or waiting; more are refused.
const ABUSE_WAITING: usize = 2;

/// The console socket's abuse reports. Reading a week of the actions log takes a moment and
/// needs nothing of the main loop's, so they are built beside it: one at a time, each kept a
/// minute.
struct AbuseReports {
    actions_log: Option<PathBuf>,
    /// The main loop's geo database, for the sources' countries and networks.
    geo: Arc<Mutex<Option<Arc<crate::geo::GeoDb>>>>,
    /// (command, when, answer)
    built: Mutex<Vec<(String, Instant, String)>>,
    waiting: std::sync::atomic::AtomicUsize,
}

impl AbuseReports {
    fn new(actions_log: Option<PathBuf>, geo: Arc<Mutex<Option<Arc<crate::geo::GeoDb>>>>) -> Self {
        AbuseReports { actions_log, geo, built: Mutex::new(vec![]), waiting: Default::default() }
    }

    fn answer(&self, cmd: &str) -> String {
        let Some(since) = crate::console::abuse_window(cmd) else { return format!("error: unknown command '{cmd}'") };
        let Some(path) = &self.actions_log else {
            return "error: actions_log is off in logguard's configuration: no abuse reports".into();
        };
        let mut built = self.built.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, _, text)) = built.iter().find(|(c, at, _)| c == cmd && at.elapsed() < ABUSE_FRESH) {
            return text.clone();
        }
        let addresses = crate::net::local_addresses().into_iter().filter(|a| !crate::engine::is_non_global(*a)).collect();
        let text = match crate::abuse::live(path, since, time::now(), crate::cluster::hostname(), addresses) {
            Ok(mut r) => {
                // under the lock: the main loop releases the database (before a reload) only
                // when no report is using it
                if let Some(db) = self.geo.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                    crate::abuse::locate(&mut r, db);
                }
                serde_json::to_string(&r).unwrap_or_else(|e| format!("error: {e}"))
            }
            Err(e) => format!("error: {e:#}"),
        };
        built.retain(|(c, at, _)| c != cmd && at.elapsed() < ABUSE_FRESH);
        if !text.starts_with("error: ") {
            built.push((cmd.to_string(), Instant::now(), text.clone()));
        }
        text
    }
}

/// What the console socket passes on to the main loop: reading commands only.
fn console_admit(cmd: &str) -> Result<String, String> {
    crate::console::read_only(cmd)
        .map(str::to_string)
        .ok_or_else(|| format!("error: read-only socket: only {} (the control socket has the rest)", crate::console::COMMANDS.join(", ")))
}

/// Answers each connection's command (an empty one asks for the snapshot) through the main
/// loop; `admit` turns it into the command to run, or refuses it with the reply. Abuse
/// reports (the console socket's) are built by `reports`, beside the main loop.
fn answer(
    listener: UnixListener,
    control: SyncSender<Control>,
    admit: fn(&str) -> Result<String, String>,
    reports: Option<Arc<AbuseReports>>,
) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
            // the whole command, however it arrives (a long `allow` note in two pieces): the
            // clients close their side after it; at most 4 KB, and no longer than the timeout
            let mut cmd = Vec::new();
            let _ = (&mut s).take(4096).read_to_end(&mut cmd);
            let cmd = String::from_utf8_lossy(&cmd).trim().to_string();
            let cmd = if cmd.is_empty() { "snapshot".to_string() } else { cmd };
            let cmd = match admit(&cmd) {
                Ok(cmd) => cmd,
                Err(refused) => {
                    let _ = s.write_all(refused.as_bytes());
                    continue;
                }
            };
            if let Some(r) = reports.as_ref().filter(|_| crate::console::abuse_window(&cmd).is_some()) {
                if r.waiting.fetch_add(1, Ordering::SeqCst) >= ABUSE_WAITING {
                    r.waiting.fetch_sub(1, Ordering::SeqCst);
                    let _ = s.write_all(b"error: busy building abuse reports: ask again in a moment");
                    continue;
                }
                let r = Arc::clone(r);
                thread::spawn(move || {
                    let reply = r.answer(&cmd);
                    r.waiting.fetch_sub(1, Ordering::SeqCst);
                    let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
                    let _ = s.write_all(reply.as_bytes());
                });
                continue;
            }
            // Executed by the main loop (it owns all state); the control socket is root-only
            // (0600), the console socket only reads.
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            let reply = match control.send((cmd, reply_tx)) {
                Ok(()) => reply_rx.recv_timeout(Duration::from_secs(15)).unwrap_or_else(|_| "error: daemon did not answer".into()),
                Err(_) => "error: daemon is stopping".into(),
            };
            let _ = s.write_all(reply.as_bytes());
        }
    });
}

/// The saved state; or why it couldn't be used. An unreadable file is kept aside (it would
/// be overwritten at the next save) and the problem reported.
pub fn load_state(path: &Path) -> (Option<PersistedState>, Option<String>) {
    let Ok(bytes) = fs::read(path) else { return (None, None) };
    match crate::engine::decode_state(&bytes) {
        Ok(s) => (Some(s), None),
        Err(e) => {
            let aside = path.with_extension(format!("bad-{}", time::now() / time::SEC));
            let kept = match fs::rename(path, &aside) {
                Ok(()) => format!("kept as {}", aside.display()),
                Err(re) => format!("could not be kept aside: {re}"),
            };
            eprintln!("logguard: unreadable state file {} ({kept}): {e:#}", path.display());
            (None, Some(format!("{e:#}; {kept}")))
        }
    }
}

fn save_state(path: &Path, state: &PersistedState) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    // Addresses, account names and login networks: root only.
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(&crate::engine::encode_state(state)?)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

struct ActionSink {
    log: Option<fs::File>,
    notifier: Notifier,
    /// Some when this node can't deliver admin notifications itself, or relays them
    /// anyway (`[cluster] relay_notices`): they go out as cluster facts to nodes that do.
    relay: Option<Vec<crate::cluster::FactBody>>,
}

impl ActionSink {
    fn new(path: Option<&Path>, notifier: Notifier) -> Self {
        let log = path.and_then(|p| {
            if let Some(dir) = p.parent() {
                let _ = fs::create_dir_all(dir);
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o640)
                .open(p)
                .map_err(|e| eprintln!("logguard: cannot open actions log {}: {e}", p.display()))
                .ok()
        });
        ActionSink { log, notifier, relay: None }
    }

    fn handle(&mut self, enforcer: &Enforcer, engine: &mut crate::engine::Engine, mut a: Action) {
        enforcer.apply(&mut a);
        if a.applied {
            engine.mark_applied(&a);
        }
        // Failures to apply are reported separately; bans that ended before a backlog was
        // processed are simply not applied.
        let tag = if enforcer.kind == crate::enforce::Kind::Shadow && !matches!(a.kind, crate::engine::ActionKind::Alert) {
            "[shadow] "
        } else {
            ""
        };
        println!("{tag}{}", format_action(&a, false));
        if let Some(f) = &mut self.log {
            if let Ok(line) = serde_json::to_string(&a) {
                let _ = writeln!(f, "{line}");
            }
        }
        self.notifier.handle(&a);
        if let (Some(relay), Some(topic)) = (self.relay.as_mut(), a.topic) {
            use crate::engine::Topic;
            if topic == Topic::Digest {
                relay.push(crate::cluster::FactBody::Notice { subject: a.message.clone(), body: a.user_note.clone().unwrap_or_default() });
            } else if topic != Topic::Relayed && crate::notify::NotifyCfg::default().admin_topics.contains(&topic) {
                relay.push(crate::cluster::FactBody::Notice {
                    subject: format!("logguard: {}", crate::notify::topic_name(topic)),
                    body: crate::notify::Planner::admin_body(&a),
                });
            }
        }
    }
}

/// systemd notification protocol (`Type=notify`, `WatchdogSec=`): a datagram to $NOTIFY_SOCKET.
/// A no-op when not started by systemd.
pub fn sd_notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else { return };
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
    if let Some(name) = bytes.strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name) {
                let _ = sock.send_to_addr(state.as_bytes(), &addr);
            }
        }
        let _ = name;
    } else {
        let _ = sock.send_to(state.as_bytes(), &path);
    }
}

/// Processes a line from a followed log and records how far that log has been processed
/// (by the line's own time, before clamping, as `follow` compares it).
fn feed_live(pipe: &mut Pipeline, name: &'static str, mut rec: Record) -> Vec<Action> {
    advance(pipe, name, rec.ts);
    clamp_ts(&mut rec);
    pipe.feed(&rec)
}

fn advance(pipe: &mut Pipeline, name: &str, t: time::Micros) {
    let at = pipe.engine.followers.entry(name.to_string()).or_default();
    *at = (*at).max(t);
}

/// Engine time only moves forward. One record stamped in the future (a wrong hardware clock
/// before time sync at boot) would otherwise expire every ban early and stall scoring until
/// the real clock caught up.
fn clamp_ts(rec: &mut Record) {
    rec.ts = rec.ts.min(time::now() + 60 * time::SEC);
}

/// How often to ping the systemd watchdog: a third of `WatchdogSec`, if one is set for us.
fn watchdog_interval() -> Option<Duration> {
    if std::env::var("WATCHDOG_PID").ok().is_some_and(|p| p.parse() != Ok(std::process::id())) {
        return None;
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec / 3))
}

pub fn run(cfg: Arc<Config>) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    // No terminal is ours: a hangup (from one we opened by mistake as the controlling terminal)
    // must not stop the daemon, as SIGHUP would by default.
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::new(AtomicBool::new(false)))?;

    let now = time::now();
    // Engine time starts at 0 (or the saved time) and is driven by record timestamps
    // while catching up on history, so a backlog isn't scored as one giant burst.
    let mut pipe = Pipeline::new(Arc::clone(&cfg), 0);
    pipe.engine.started = now;
    let mut cursor = None;
    let (state, state_problem) = load_state(&cfg.state_file);
    if let Some(state) = state {
        cursor = state.cursor.clone();
        pipe.engine.restore(state);
        // A state saved under a wrong (future) clock must not pin the engine there.
        pipe.engine.now = pipe.engine.now.min(now);
    }

    let mut cluster = None;
    let mut cluster_problem = None;
    if cfg.cluster.enabled {
        match crate::cluster::Cluster::new(&cfg.cluster) {
            Ok(c) => cluster = Some(c),
            Err(e) => {
                eprintln!("logguard: cluster disabled: {e:#}");
                cluster_problem = Some(format!("{e:#}"));
            }
        }
    }
    let mut peer_nets = cluster.as_ref().map(|c| c.peer_nets()).unwrap_or_default();
    if cluster.is_some() {
        pipe.engine.enable_sharing(peer_nets.clone());
    }
    // The host itself (its checks, Nextcloud or bots reaching it via its public address).
    let own_nets: Vec<crate::net::Net> = crate::net::local_addresses().into_iter().map(crate::net::Net::host).collect();
    pipe.engine.set_own_addresses(own_nets.clone());
    // `[allowlist] hosts`, as last resolved
    let mut host_nets: Vec<crate::net::Net> = Vec::new();
    let never_block: Vec<crate::net::Net> = peer_nets.iter().chain(&own_nets).copied().collect();
    let mut enforcer = Enforcer::new(&cfg, &never_block);
    enforcer.restore(&pipe.engine.active_bans(), now);
    enforcer.restore_allows(&pipe.engine.allowed(), now);
    if !cfg.feeds.enabled {
        // Disabling feeds in the config removes a previously loaded list.
        let _ = enforcer.load_feeds(&[]);
    }
    if !cfg.geoblock.enabled {
        // the same for [geoblock]; when enabled, it loads with the geo database
        let _ = enforcer.load_geoblock(&[]);
    }
    if !cfg.waf.enabled || !cfg.waf.sources.iter().any(|s| s.action == crate::waf::WafAction::List) {
        // and for [waf] lists: what an earlier configuration loaded
        let _ = enforcer.load_waf(&[]);
    }
    eprintln!(
        "logguard: started, mode={:?} backend={} notify={} resume={} active_bans={}",
        cfg.mode,
        enforcer.name(),
        if cfg.notify.enabled { "on" } else { "off" },
        if cursor.is_some() { "cursor" } else { "lookback" },
        pipe.engine.active_bans().len()
    );

    let (tx, rx) = sync_channel::<Msg>(65_536);
    // Operator commands and snapshot requests get their own channel, checked every loop
    // iteration, so a journal backlog never makes the TUI wait.
    let (ctrl_tx, ctrl_rx) = sync_channel::<Control>(16);
    // The geo database the main loop has, for the feeds' ASN lists and the console's abuse
    // reports: used under the lock, so it is released (before a reload) only when nothing uses it.
    let geo_slot: Arc<Mutex<Option<Arc<crate::geo::GeoDb>>>> = Arc::new(Mutex::new(None));
    match serve_control(cfg.socket.clone(), ctrl_tx.clone()) {
        Ok(()) if cfg.console.enabled() => {
            let reports = Arc::new(AbuseReports::new(cfg.actions_log.clone(), Arc::clone(&geo_slot)));
            if let Err(e) = serve_console(&cfg.console, &cfg.socket, ctrl_tx, reports) {
                eprintln!("logguard: console socket disabled: {e:#}");
            }
        }
        Ok(()) => {}
        Err(e) => eprintln!("logguard: control socket disabled (and so the console socket): {e:#}"),
    }
    let protected: Vec<crate::net::Net> = cfg.allowlist.nets.iter().chain(never_block.iter()).copied().collect();
    let feeds_refresh = if cfg.feeds.enabled {
        let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<()>();
        let (tx, fcfg, protected, slot) = (tx.clone(), cfg.feeds.clone(), protected.clone(), Arc::clone(&geo_slot));
        thread::spawn(move || loop {
            let expand = |asns: &std::collections::BTreeSet<u32>| slot.lock().unwrap().as_ref().map(|db| db.networks_of(asns));
            let (nets, status) = crate::feeds::refresh(&fcfg, &protected, &expand);
            if tx.send(Msg::Feeds(nets, Box::new(status))).is_err() {
                return;
            }
            match refresh_rx.recv_timeout(Duration::from_secs(fcfg.refresh.0.max(3600))) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return,
            }
        });
        Some(refresh_tx)
    } else {
        None
    };
    let waf_refresh = if cfg.waf.enabled {
        let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<()>();
        let (tx, wcfg, protected) = (tx.clone(), cfg.waf.clone(), protected.clone());
        thread::spawn(move || loop {
            let update = crate::waf::refresh(&wcfg, &protected, time::now());
            if tx.send(Msg::Waf(Box::new(update))).is_err() {
                return;
            }
            match refresh_rx.recv_timeout(Duration::from_secs(wcfg.refresh.0.max(10))) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return,
            }
        });
        Some(refresh_tx)
    } else {
        None
    };
    if cfg.digest.enabled && !(cfg.digest.certs.is_empty() && cfg.digest.cert_files.is_empty()) {
        let (tx, dcfg, stop) = (tx.clone(), cfg.digest.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut certs: Vec<crate::digest::CertStatus> =
                    dcfg.certs.iter().map(|t| crate::digest::check_cert(&dcfg.openssl, t)).collect();
                let wait = |d: Duration| {
                    let end = std::time::Instant::now() + d;
                    while std::time::Instant::now() < end {
                        if stop.load(Ordering::Relaxed) {
                            return false;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                    true
                };
                crate::digest::recheck_failed(&mut certs, &crate::digest::CERT_RETRY_WAITS, wait, |t| {
                    crate::digest::check_cert(&dcfg.openssl, t)
                });
                for pattern in &dcfg.cert_files {
                    certs.extend(crate::digest::expand_files(pattern).iter().map(|p| crate::digest::check_cert_file(&dcfg.openssl, p)));
                }
                if tx.send(Msg::Certs(certs)).is_err() {
                    return;
                }
                thread::sleep(Duration::from_secs(dcfg.check_certs_every.0.max(600)));
            }
        });
    }
    let mut feed_nets: Vec<crate::net::Net> = Vec::new();
    let mut geo_nets: Vec<crate::net::Net> = Vec::new();
    if cfg.geo.enabled {
        let (tx, gcfg, stop) = (tx.clone(), cfg.geo.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            // Use what's on disk right away; download (weekly) only what is missing or old.
            let mut loaded = false;
            while !stop.load(Ordering::Relaxed) {
                let (done, errors) = crate::geo::refresh(&gcfg, time::now());
                for d in &done {
                    eprintln!("logguard: geo database downloaded: {d}");
                }
                let db = if !loaded || !done.is_empty() {
                    if loaded {
                        let (ack_tx, ack_rx) = sync_channel(1);
                        if tx.send(Msg::GeoRelease(ack_tx)).is_err() {
                            return;
                        }
                        let _ = ack_rx.recv_timeout(Duration::from_secs(60));
                    }
                    match crate::geo::GeoDb::open(&gcfg) {
                        Ok(db) => {
                            eprintln!("logguard: geo database loaded ({})", db.summary);
                            loaded = true;
                            Some(Arc::new(db))
                        }
                        Err(e) => {
                            eprintln!("logguard: geo database: {e:#}");
                            None
                        }
                    }
                } else {
                    None
                };
                if (db.is_some() || !errors.is_empty()) && tx.send(Msg::Geo(db, errors)).is_err() {
                    return;
                }
                thread::sleep(Duration::from_secs(6 * 3600));
            }
        });
    }
    // Where each followed log was left (see `follow`).
    let position = |name: &str| pipe.engine.followers.get(name).copied().unwrap_or(0);
    if cfg.sources.nextcloud_aio {
        let nc = &cfg.nextcloud_aio;
        if !nc.apache_container.is_empty() {
            let container = nc.apache_container.clone();
            follow(
                "nextcloud apache",
                nc.docker.clone(),
                move |last| {
                    // From the last line seen (inclusive: it is skipped, but others of the same
                    // instant aren't); the first time ever, from 10 minutes back.
                    let since = if last > 0 { format!("{}.{:06}", last / time::SEC, last % time::SEC) } else { "10m".into() };
                    ["logs", "--follow", "--timestamps", "--since", &since, &container].map(String::from).to_vec()
                },
                position("nextcloud apache"),
                tx.clone(),
                Arc::clone(&stop),
            );
        }
        if !nc.log_file.as_os_str().is_empty() {
            let path = nc.log_file.display().to_string();
            follow(
                "nextcloud.log",
                "tail".into(),
                // After a restart, re-read the end of the file: what was logged meanwhile is
                // in there, and lines already seen are skipped by time.
                move |last| ["-F", "-n", if last > 0 { "2000" } else { "0" }, &path].map(String::from).to_vec(),
                position("nextcloud.log"),
                tx.clone(),
                Arc::clone(&stop),
            );
        }
    }
    if cfg.exposure.enabled {
        let (tx, ecfg, tools, stop) = (tx.clone(), cfg.exposure.clone(), cfg.enforce.clone(), Arc::clone(&stop));
        // logguard's own honeypot listeners: listed, marked, never alerted about
        let honeypots: Vec<u16> = cfg.ports.honeypot.iter().map(|h| h.port).collect();
        thread::spawn(move || {
            let mut warned = false;
            while !stop.load(Ordering::Relaxed) {
                match crate::exposure::scan(&ecfg, &tools, &honeypots) {
                    Ok(r) => {
                        if tx.send(Msg::Exposure(Box::new(r))).is_err() {
                            return;
                        }
                    }
                    Err(e) if !warned => {
                        warned = true;
                        eprintln!("logguard: exposure scan failed (will keep retrying): {e:#}");
                    }
                    Err(_) => {}
                }
                thread::sleep(Duration::from_secs(ecfg.interval.0.max(10)));
            }
        });
    }
    if cfg.cron.enabled {
        let (tx, ccfg, stop) = (tx.clone(), cfg.cron.clone(), Arc::clone(&stop));
        let expected = crate::cronwatch::expected_path(&cfg.state_file);
        thread::spawn(move || {
            let mut scanner = crate::cronwatch::Scanner::default();
            while !stop.load(Ordering::Relaxed) {
                let mut r = scanner.scan(&ccfg);
                r.expected = crate::cronwatch::load_expected(&expected, r.scanned);
                if tx.send(Msg::Cron(Box::new(r))).is_err() {
                    return;
                }
                thread::sleep(Duration::from_secs(ccfg.interval.0.max(10)));
            }
        });
    }
    if cfg.resources.enabled {
        let (tx, rcfg, stop) = (tx.clone(), cfg.resources.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if tx.send(Msg::Resources(Box::new(crate::resources::scan(&rcfg, time::now())))).is_err() {
                    return;
                }
                thread::sleep(Duration::from_secs(rcfg.interval.0.max(10)));
            }
        });
    }
    if !cfg.allowlist.hosts.is_empty() {
        let (tx, hosts, stop) = (tx.clone(), cfg.allowlist.hosts.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            let mut failing_since: Option<Instant> = None;
            loop {
                let (nets, errors) = crate::net::resolve_hosts(&hosts);
                let failing = !errors.is_empty();
                failing_since = if failing { failing_since.or(Some(Instant::now())) } else { None };
                let report = failing_since.is_some_and(|t| t.elapsed() >= Duration::from_secs(600));
                if tx.send(Msg::AllowHosts(nets, errors, report)).is_err()
                    || !nap(Duration::from_secs(if failing { 60 } else { 600 }), &stop)
                {
                    return;
                }
            }
        });
    }
    if cfg.journal.verify_every.0 > 0 {
        let (tx, c, stop) = (tx.clone(), Arc::clone(&cfg), Arc::clone(&stop));
        thread::spawn(move || {
            // not at boot, with everything else starting
            while nap(Duration::from_secs(900), &stop) {
                if tx.send(Msg::JournalVerify(verify_journal(&c))).is_err()
                    || !nap(Duration::from_secs(c.journal.verify_every.0.saturating_sub(900)), &stop)
                {
                    return;
                }
            }
        });
    }
    if cfg.patches.enabled {
        let (tx, pcfg, stop) = (tx.clone(), cfg.patches.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            while nap(Duration::from_secs(120), &stop) {
                if tx.send(Msg::Patches(Box::new(crate::patches::scan(&pcfg, time::now())))).is_err() {
                    return;
                }
                if !nap(Duration::from_secs(pcfg.interval.0.max(600).saturating_sub(120)), &stop) {
                    return;
                }
            }
        });
    }
    if cfg.verify.enabled {
        let (tx, vcfg, stop) = (tx.clone(), cfg.verify.clone(), Arc::clone(&stop));
        let mut last = pipe.engine.verify_last_run();
        thread::spawn(move || loop {
            // the first pass a quarter of an hour after start (or when the last is due), not at boot
            let due = if last <= 0 { time::now() + 900 * time::SEC } else { last + vcfg.interval.micros() };
            let wait = Duration::from_micros(u64::try_from(due - time::now()).unwrap_or(0)).max(Duration::from_secs(900));
            if !nap(wait, &stop) {
                return;
            }
            let report = crate::verify::scan(&vcfg, &|| stop.load(Ordering::Relaxed));
            if stop.load(Ordering::Relaxed) {
                return; // cut short: not a result
            }
            last = report.finished;
            if tx.send(Msg::Verify(Box::new(report))).is_err() {
                return;
            }
        });
    }
    if cfg.ssh_audit.enabled {
        let (tx, scfg, stop) = (tx.clone(), cfg.ssh_audit.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            // a few minutes after start: sshd may be restarting with logguard (a reboot, an upgrade)
            while nap(Duration::from_secs(300), &stop) {
                if tx.send(Msg::SshAudit(Box::new(crate::sshaudit::scan(&scfg, time::now())))).is_err() {
                    return;
                }
                if !nap(Duration::from_secs(scfg.interval.0.max(600).saturating_sub(300)), &stop) {
                    return;
                }
            }
        });
    }
    if cfg.procwatch.enabled {
        let (tx, pcfg, stop) = (tx.clone(), cfg.procwatch.clone(), Arc::clone(&stop));
        thread::spawn(move || loop {
            let r = crate::procwatch::scan(&pcfg);
            let available = r.available;
            if tx.send(Msg::Proc(Box::new(r))).is_err() || !available || !nap(Duration::from_secs(pcfg.interval.0.max(10)), &stop) {
                return; // (no /proc: nothing to watch)
            }
        });
    }
    let honeypot_errors = if cfg.ports.honeypot.is_empty() {
        vec![]
    } else {
        let tx = tx.clone();
        let ports: Vec<u16> = cfg.ports.honeypot.iter().map(|h| h.port).collect();
        // a flood is dropped rather than queued: each source counts once a minute anyway
        crate::honeypot::start(
            &ports,
            move |hit| !matches!(tx.try_send(Msg::Honeypot(hit, time::now())), Err(std::sync::mpsc::TrySendError::Disconnected(_))),
            Arc::clone(&stop),
        )
    };
    for line in &cfg.app_logs_found {
        eprintln!("logguard: [sources] apps: {line}");
    }
    // one tail per file, however many patterns read it (each line counts once)
    let files: std::collections::BTreeSet<&std::path::PathBuf> = cfg.all_patterns().flat_map(|p| p.files()).collect();
    for f in files {
        follow_file(f.display().to_string(), crate::record::Source::Custom, tx.clone(), Arc::clone(&stop));
    }
    if cfg.sources.audit && !cfg.sources.audit_log.as_os_str().is_empty() {
        follow_file(cfg.sources.audit_log.display().to_string(), crate::record::Source::Audit, tx.clone(), Arc::clone(&stop));
    }
    // Scans of changed files, one batch at a time: the engine queues the files the integrity
    // watches report, the main loop hands them over while no scan runs.
    let scan_tx: Option<SyncSender<Vec<crate::filescan::Job>>> =
        (cfg.antivirus.scan_changed != crate::filescan::Scanners::None).then(|| {
            let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<Vec<crate::filescan::Job>>(1);
            let (tx, av) = (tx.clone(), cfg.antivirus.clone());
            let work = cfg.state_file.parent().map_or_else(|| PathBuf::from("/var/lib/logguard"), Path::to_path_buf);
            thread::spawn(move || {
                while let Ok(jobs) = job_rx.recv() {
                    let report = crate::filescan::scan(&av, jobs, &work, &time::now);
                    if tx.send(Msg::FileScan(Box::new(report))).is_err() {
                        return;
                    }
                }
            });
            job_tx
        });
    let mut scan_busy = false;
    if cfg.antivirus.enabled {
        let (tx, path, stop) = (tx.clone(), cfg.antivirus.log.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            let mut reader = crate::avscan::Reader::default();
            while !stop.load(Ordering::Relaxed) {
                if tx.send(Msg::Av(Box::new(reader.read(&path)))).is_err() {
                    return;
                }
                thread::sleep(Duration::from_secs(60));
            }
        });
    }
    let mut send_jobs: Option<SyncSender<Msg>> = None;
    // One delivery in flight per peer: a dead peer can't pile up queued frames.
    let mut in_flight = vec![false; cluster.as_ref().map_or(0, |c| c.cfg.peers.len())];
    // While catching up on journal history, things that carry wall-clock time must wait,
    // or they'd move the engine clock forward and squash the backlog into one burst.
    let mut deferred_peers: Vec<(crate::cluster::Envelope, Option<std::net::IpAddr>)> = Vec::new();
    let mut deferred_exposure: Option<crate::exposure::ExposureReport> = None;
    let mut deferred_waf: Option<Box<crate::waf::WafUpdate>> = None;
    // what the sets waf4/waf6 hold
    let mut waf_nets: Vec<crate::net::Net> = Vec::new();
    let mut deferred_live: Vec<(&'static str, Record)> = Vec::new();
    let mut deferred_positions: Vec<(&'static str, time::Micros)> = Vec::new();
    let mut deferred_events: Vec<crate::event::Event> = Vec::new();
    let mut deferred_custom: Vec<Record> = Vec::new();
    if let Some(c) = &cluster {
        if !c.cfg.listen.is_empty() {
            let tx = tx.clone();
            let allowed = if c.cfg.allow_only_peers {
                crate::cluster::PeerFilter::peers(peer_nets.clone())
            } else {
                crate::cluster::PeerFilter::Anyone
            };
            // Peers named by host name may move, or not resolve yet at boot: resolve them
            // again (every minute while some fail, else every 10). The listener's filter is
            // updated here; the engine and nftables by the main loop.
            if !c.cfg.peers.iter().all(|p| p.parse::<std::net::SocketAddr>().is_ok()) {
                let (tx, filter, limits, ccfg, stop) = (tx.clone(), allowed.clone(), c.limits.clone(), c.cfg.clone(), Arc::clone(&stop));
                thread::spawn(move || {
                    let mut failing = true;
                    while !stop.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_secs(if failing { 60 } else { 600 }));
                        let (nets, errors) = crate::cluster::resolve_peers(&ccfg.peers);
                        failing = !errors.is_empty();
                        // the limits first: the filter may then admit a limited peer's new address
                        limits.refresh(&ccfg);
                        if !nets.is_empty() {
                            filter.set(nets.clone());
                        }
                        if tx.send(Msg::PeerNets(nets, errors)).is_err() {
                            return;
                        }
                    }
                });
            }
            let (inbox, skew, limits, node_keys) = (c.cfg.inbox.clone(), c.cfg.max_clock_skew, c.limits.clone(), c.node_keys.clone());
            let senders = crate::cluster::Senders::default();
            // A file from a peer is written here, in the connection's thread: it carries no facts.
            let deliver = move |env: crate::cluster::Envelope, from: Option<std::net::IpAddr>| {
                let limit = limits.of(from);
                let own_name = senders.observe(&env.from, from, limit.is_some());
                if env.file.is_none() {
                    return tx.send(Msg::Peer(Box::new(env), from)).is_ok();
                }
                if limit.as_ref().is_some_and(|k| !k.contains(&crate::cluster::FactKind::Files)) {
                    eprintln!("logguard: cluster: file from {} refused: [cluster] peer_accept doesn't allow files from there", env.from);
                    return true;
                }
                // signed by the key pinned for its name ([cluster] nodes): its sender's for sure
                let signed = match crate::cluster::file_signed(&node_keys, &env) {
                    Ok(signed) => signed,
                    Err(why) => {
                        eprintln!(
                            "logguard: cluster: file from '{}' ({}) refused: {why}",
                            crate::event::clean(&env.from, 64),
                            from.map_or("?".into(), |ip| ip.to_string())
                        );
                        return true;
                    }
                };
                if !own_name && !signed {
                    eprintln!(
                        "logguard: cluster: file from '{}' ({}) refused: a peer limited by [cluster] peer_accept sends under its own node name only",
                        crate::event::clean(&env.from, 64),
                        from.map_or("?".into(), |ip| ip.to_string())
                    );
                    return true;
                }
                match crate::cluster::store_file(&inbox, &env, skew, time::now()) {
                    Ok(path) => eprintln!("logguard: cluster: {} sent {}", env.from, path.display()),
                    Err(e) => eprintln!("logguard: cluster: file from {} refused: {e:#}", env.from),
                }
                true
            };
            if let Err(e) = crate::cluster::serve(&c.cfg.listen, c.keys(), allowed, deliver) {
                eprintln!("logguard: cluster listener disabled: {e:#}");
            }
        }
        send_jobs = Some(tx.clone());
        eprintln!(
            "logguard: cluster node '{}' listening on {} with {} peers, key {}{}",
            c.node_id,
            if c.cfg.listen.is_empty() { "-" } else { &c.cfg.listen },
            c.cfg.peers.len(),
            c.view.key_id,
            if c.view.extra_key_ids.is_empty() {
                String::new()
            } else {
                format!(" (rotation: also accepting {})", c.view.extra_key_ids.join(", "))
            }
        );
    }
    let child_slot = Arc::new(Mutex::new(None));
    {
        let (cfg, cursor, child_slot, stop) = (Arc::clone(&cfg), cursor.clone(), Arc::clone(&child_slot), Arc::clone(&stop));
        thread::spawn(move || reader(cfg, cursor, tx, child_slot, stop));
    }

    let mut sink = ActionSink::new(cfg.actions_log.as_deref(), Notifier::new(&cfg.notify, cfg.mode));
    sink.notifier.set_node(cluster.as_ref().map_or_else(crate::cluster::hostname, |c: &crate::cluster::Cluster| c.node_id.clone()));
    // Nodes that can't deliver admin messages relay them; others too with relay_notices.
    let relays = !cfg.notify.enabled || cfg.cluster.relay_notices;
    if cluster.is_some() && relays && cfg.cluster.share.contains(&crate::cluster::FactKind::Notices) {
        sink.relay = Some(Vec::new());
    }
    if let Some(problem) = state_problem {
        let msg = format!(
            "the state file {} was unreadable, logguard started without it: repeat-offender history, trusted addresses, \
             login networks and the cron/file watch baseline are lost (the watch learns again; changes in that time aren't reported). Error: {problem}",
            cfg.state_file.display()
        );
        for a in pipe.engine.system_alert_wall("state-unreadable", 86_400 * time::SEC, Severity::High, msg, time::now()) {
            sink.handle(&enforcer, &mut pipe.engine, a);
        }
    }
    if let Some(problem) = cluster_problem {
        // Running alone would otherwise go unnoticed: no peer-down alert comes from a node
        // that isn't part of the cluster (e.g. a damaged key file after a key rotation).
        let msg =
            format!("[cluster] is enabled but could not start, so this node runs alone (no bans or reports shared or received): {problem}");
        for a in pipe.engine.system_alert_wall("cluster-disabled", 86_400 * time::SEC, Severity::High, msg, time::now()) {
            sink.handle(&enforcer, &mut pipe.engine, a);
        }
    }
    if let Some(err) = enforcer.nft_error.as_ref().filter(|_| cfg.mode == crate::config::Mode::Enforce) {
        let instead = match enforcer.kind {
            crate::enforce::Kind::Ufw => "ufw instead: no rate limits, no blocklist feeds, ufw rules don't expire on their own",
            crate::enforce::Kind::Iptables => "iptables instead: no rate limits, no blocklist feeds, bans end only while logguard runs",
            crate::enforce::Kind::Firewalld => "firewalld instead: no rate limits, no blocklist feeds, bans end only while logguard runs",
            crate::enforce::Kind::Ipset => "ipset instead: no rate limits",
            _ => "nothing (shadow): no bans are applied",
        };
        let msg = format!("nftables setup failed, enforcing with {instead}. Error: {err}");
        for a in pipe.engine.system_alert_wall("nft-setup", 86_400 * time::SEC, Severity::High, msg, time::now()) {
            sink.handle(&enforcer, &mut pipe.engine, a);
        }
    }
    if let Some(err) = enforcer.trip_error.as_ref() {
        let msg = format!(
            "nftables rejected the kernel tripwire rules, so tripwire hits are seen only through UFW's log (about 3 lines a minute); \
             set [ports] kernel_tripwires = false to stop this warning. Error: {err}"
        );
        for a in pipe.engine.system_alert_wall("trip-setup", 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
            sink.handle(&enforcer, &mut pipe.engine, a);
        }
    }
    if let Some(msg) = verify_key_warning(&cfg, &fs::read_to_string("/proc/self/mountinfo").unwrap_or_default()) {
        eprintln!("logguard: {msg}");
        for a in pipe.engine.system_alert_wall("journal-verify-key", 7 * 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
            sink.handle(&enforcer, &mut pipe.engine, a);
        }
    }
    if !honeypot_errors.is_empty() {
        let msg = format!("[ports] honeypot: {}", honeypot_errors.join("; "));
        for a in pipe.engine.system_alert_wall("honeypot", 86_400 * time::SEC, Severity::High, msg, time::now()) {
            sink.handle(&enforcer, &mut pipe.engine, a);
        }
    }
    if pipe.engine.digest.since == 0 {
        pipe.engine.digest.since = now; // first period starts now, not at the epoch
    }
    if pipe.engine.digest_last_sent == 0 {
        pipe.engine.digest_last_sent = now; // first start: wait for the next scheduled time
    }
    let mut last_digest_check = Instant::now();
    let (mut last_tick, mut last_save) = (Instant::now(), Instant::now());
    let mut saved_changes = pipe.engine.changes;
    let mut last_heal = Instant::now();
    let mut last_silence_check = Instant::now();
    let mut last_key_check: Option<Instant> = None;
    let mut resource_watch = crate::resources::Watch::default();
    // The watchdog is fed from this loop, so a hang anywhere in it (a stuck nft or
    // ejabberdctl call, a deadlock) gets the service restarted by systemd.
    let watchdog = watchdog_interval();
    let mut last_watchdog = Instant::now();
    sd_notify("READY=1");
    let mut last_sync = Instant::now();
    // While catching up, periodic work runs on record time (once per record-second, as in
    // replay); once caught up it runs on the wall clock.
    let mut next_record_tick: Option<time::Micros> = None;
    let mut idle_since: Option<Instant> = None;
    let mut caught_up = false;
    while !stop.load(Ordering::Relaxed) {
        while let Ok((cmd, reply)) = ctrl_rx.try_recv() {
            let (text, actions) = control(
                &cmd,
                &mut pipe,
                &cluster,
                &cfg,
                (&feeds_refresh, &waf_refresh),
                &enforcer,
                (&mut feed_nets, &mut waf_nets),
                caught_up,
            );
            for a in actions {
                sink.handle(&enforcer, &mut pipe.engine, a);
            }
            let _ = reply.send(text);
        }
        if caught_up {
            if let Some(r) = deferred_exposure.take() {
                for a in pipe.engine.on_exposure(r, cfg.sources.ufw) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            if let Some(u) = deferred_waf.take() {
                apply_waf(*u, &mut pipe, &cfg, &enforcer, &mut sink, &mut waf_nets);
            }
            for (name, rec) in std::mem::take(&mut deferred_live) {
                for a in feed_live(&mut pipe, name, rec) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            for (name, t) in std::mem::take(&mut deferred_positions) {
                advance(&mut pipe, name, t);
            }
            for ev in std::mem::take(&mut deferred_events) {
                for a in pipe.event(ev) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            for mut rec in std::mem::take(&mut deferred_custom) {
                clamp_ts(&mut rec);
                for a in pipe.feed(&rec) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            for (env, from) in std::mem::take(&mut deferred_peers) {
                if let Some(c) = cluster.as_mut() {
                    for fact in c.ingest(env, from, time::now()) {
                        for a in pipe.engine.apply_peer_fact(&fact, &c.cfg) {
                            sink.handle(&enforcer, &mut pipe.engine, a);
                        }
                    }
                }
            }
        }
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Msg::Rec(mut rec)) => {
                clamp_ts(&mut rec);
                idle_since = None;
                cursor = rec.cursor.clone().or(cursor);
                if !caught_up && rec.ts >= time::now() - 10 * time::SEC {
                    caught_up = true;
                    eprintln!("logguard: caught up with the journal");
                }
                if !caught_up && next_record_tick.is_none_or(|t| rec.ts >= t) {
                    next_record_tick = Some(rec.ts + time::SEC);
                    for a in pipe.tick(rec.ts) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
                for a in pipe.feed(&rec) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::Cursor(c)) => cursor = Some(c),
            Ok(Msg::Live(name, rec)) if !caught_up => {
                if deferred_live.len() < 10_000 {
                    deferred_live.push((name, rec));
                }
            }
            Ok(Msg::Live(name, rec)) => {
                for a in feed_live(&mut pipe, name, rec) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::Position(name, t)) if !caught_up => {
                deferred_positions.retain(|(n, _)| *n != name);
                deferred_positions.push((name, t));
            }
            Ok(Msg::Position(name, t)) => advance(&mut pipe, name, t),
            Ok(Msg::Peer(env, from)) if !caught_up => {
                if deferred_peers.len() < 1000 {
                    deferred_peers.push((*env, from));
                }
            }
            Ok(Msg::Peer(env, from)) => {
                if let Some(c) = cluster.as_mut() {
                    for fact in c.ingest(*env, from, time::now()) {
                        for a in pipe.engine.apply_peer_fact(&fact, &c.cfg) {
                            sink.handle(&enforcer, &mut pipe.engine, a);
                        }
                    }
                }
            }
            Ok(Msg::Delivered(i, result)) => {
                if let Some(f) = in_flight.get_mut(i) {
                    *f = false;
                }
                if let Some(msg) = cluster.as_mut().and_then(|c| c.delivered(i, result, time::now())) {
                    for a in pipe.engine.system_alert_wall(&format!("peer-down-{i}"), 3600 * time::SEC, Severity::Warning, msg, time::now())
                    {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
            }
            Ok(Msg::PeerNets(nets, errors)) => {
                for e in &errors {
                    eprintln!("logguard: {e}");
                }
                // a failed lookup keeps the addresses known so far
                if !nets.is_empty() && nets != peer_nets {
                    eprintln!(
                        "logguard: cluster peers now resolve to {}",
                        nets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
                    );
                    peer_nets = nets;
                    pipe.engine.set_peer_nets(peer_nets.clone());
                    let never_block: Vec<crate::net::Net> = peer_nets.iter().chain(&own_nets).chain(&host_nets).copied().collect();
                    if let Err(e) = enforcer.set_extra_allow(&never_block) {
                        eprintln!("logguard: updating the nftables allowlist with the peers: {e:#}");
                    }
                }
            }
            Ok(Msg::Feeds(nets, mut status)) => {
                match enforcer.load_feeds(&nets) {
                    Ok(applied) => status.applied = applied,
                    Err(e) => status.error = Some(format!("loading into nftables: {e:#}")),
                }
                eprintln!(
                    "logguard: blocklist feeds: {} IPv4 + {} IPv6 networks ({} skipped){}",
                    status.v4,
                    status.v6,
                    status.skipped,
                    if status.applied { "" } else { ", not applied (shadow mode / no nftables)" }
                );
                let problems: Vec<String> = status
                    .sources
                    .iter()
                    .filter_map(|s| s.error.as_ref().map(|e| format!("{}: {e}", s.url)))
                    .chain(status.error.clone())
                    .collect();
                if !problems.is_empty() {
                    let msg = format!("blocklist feed problems: {}", problems.join("; "));
                    for a in pipe.engine.system_alert_wall("feeds", 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
                if status.applied || nets.is_empty() {
                    feed_nets = nets;
                }
                pipe.engine.feeds = Some(*status);
            }
            Ok(Msg::GeoRelease(ack)) => {
                pipe.engine.geo = None;
                *geo_slot.lock().unwrap() = None;
                let _ = ack.send(());
            }
            Ok(Msg::Geo(db, errors)) => {
                if let Some(db) = db {
                    if cfg.geoblock.enabled {
                        let (loaded, status) = apply_geoblock(&db, &cfg.geoblock, &protected, &enforcer);
                        if let Some(nets) = loaded {
                            geo_nets = nets;
                        }
                        if let Some(e) = &status.error {
                            let msg = format!("[geoblock] not loaded: {e}");
                            for a in pipe.engine.system_alert_wall("geoblock", 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
                                sink.handle(&enforcer, &mut pipe.engine, a);
                            }
                        }
                        pipe.engine.geoblock = Some(status);
                    }
                    *geo_slot.lock().unwrap() = Some(Arc::clone(&db));
                    pipe.engine.geo = Some(db);
                    // the ASN lists waited for it
                    if pipe.engine.feeds.as_ref().is_some_and(|f| f.asn_pending) {
                        if let Some(r) = &feeds_refresh {
                            let _ = r.send(());
                        }
                    }
                }
                if !errors.is_empty() {
                    let msg = format!("geo database download failed (labels use the previous copy, if any): {}", errors.join("; "));
                    for a in pipe.engine.system_alert_wall("geo", 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
            }
            Ok(Msg::Certs(certs)) => {
                let now = time::now();
                for msg in crate::digest::stale_served(&certs) {
                    for a in pipe.engine.system_alert_wall(
                        &format!("stale-cert:{}", msg.split(' ').next().unwrap_or("")),
                        86_400 * time::SEC,
                        Severity::Warning,
                        msg,
                        now,
                    ) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
                for c in certs.iter().filter(|c| !c.file) {
                    let msg = c
                        .concern(now, cfg.digest.cert_warn_days)
                        .map(|(sev, what)| (sev, format!("TLS certificate at {} {what}", c.target)));
                    if let Some((sev, msg)) = msg {
                        for a in pipe.engine.system_alert_wall(&format!("cert:{}", c.target), 86_400 * time::SEC, sev, msg, time::now()) {
                            sink.handle(&enforcer, &mut pipe.engine, a);
                        }
                    }
                }
                pipe.engine.certs = certs;
            }
            Ok(Msg::Cron(r)) => {
                for a in pipe.engine.on_cron(&r) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::Av(r)) => {
                for a in pipe.engine.on_av(&r) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::Resources(r)) => {
                for (key, every, severity, msg) in resource_watch.judge(&r, &cfg.resources) {
                    for a in pipe.engine.system_alert_wall(&key, every, severity, msg, r.read) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
                if !r.errors.is_empty() && pipe.engine.resources.is_none() {
                    eprintln!("logguard: resources: {}", r.errors.join("; "));
                }
                pipe.engine.resources = Some(*r);
            }
            // its bans are decided on the wall clock
            Ok(Msg::Waf(u)) if !caught_up => deferred_waf = Some(u),
            Ok(Msg::Waf(u)) => apply_waf(*u, &mut pipe, &cfg, &enforcer, &mut sink, &mut waf_nets),
            Ok(Msg::Exposure(r)) if !caught_up => deferred_exposure = Some(*r),
            Ok(Msg::Exposure(r)) => {
                for a in pipe.engine.on_exposure(*r, cfg.sources.ufw) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::JournalReset(msg)) => {
                for a in pipe.engine.system_alert_wall("journal-reset", 86_400 * time::SEC, Severity::High, msg, time::now()) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::JournalVerify(failed)) => {
                if !failed.is_empty() {
                    let msg = format!(
                        "journalctl --verify failed: {} - journal files damaged{}",
                        failed.join("; "),
                        if cfg.journal.verify_key_file.as_os_str().is_empty() {
                            ""
                        } else {
                            ", or changed after they were sealed (tampering)"
                        }
                    );
                    for a in pipe.engine.system_alert_wall("journal-verify", 86_400 * time::SEC, Severity::High, msg, time::now()) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
            }
            Ok(Msg::AllowHosts(nets, errors, report)) => {
                if report {
                    let msg = format!("[allowlist] hosts: {} (the addresses resolved before stay allowlisted)", errors.join("; "));
                    for a in pipe.engine.system_alert_wall("allow-hosts", 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
                // a failed lookup keeps the addresses known so far
                let mut nets = nets;
                if !errors.is_empty() {
                    nets.extend(host_nets.iter().copied());
                    nets.sort();
                    nets.dedup();
                }
                if nets != host_nets {
                    eprintln!(
                        "logguard: [allowlist] hosts now resolve to {}",
                        nets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
                    );
                    host_nets = nets;
                    for a in pipe.engine.set_allow_hosts(host_nets.clone()) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                    let never_block: Vec<crate::net::Net> = peer_nets.iter().chain(&own_nets).chain(&host_nets).copied().collect();
                    if let Err(e) = enforcer.set_extra_allow(&never_block) {
                        eprintln!("logguard: updating the nftables allowlist with [allowlist] hosts: {e:#}");
                    }
                }
            }
            Ok(Msg::Patches(r)) => pipe.engine.on_patches(*r),
            Ok(Msg::Verify(r)) => {
                for a in pipe.engine.on_verify(&r) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::Proc(r)) => {
                for a in pipe.engine.on_procwatch(&r) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::SshAudit(r)) => {
                for a in pipe.engine.on_ssh_audit(*r) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::FileScan(r)) => {
                scan_busy = false;
                for a in pipe.engine.on_file_scan(&r) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Ok(Msg::Honeypot(hit, ts)) => {
                let ev = crate::event::Event::new(ts, hit.ip, crate::event::Signal::TripwireConnect)
                    .port(Some(hit.port))
                    .detail(format!("connected to honeypot TCP/{}", hit.port));
                if !caught_up {
                    if deferred_events.len() < 10_000 {
                        deferred_events.push(ev);
                    }
                } else {
                    for a in pipe.event(ev) {
                        sink.handle(&enforcer, &mut pipe.engine, a);
                    }
                }
            }
            Ok(Msg::Custom(rec)) if !caught_up => {
                if deferred_custom.len() < 10_000 {
                    deferred_custom.push(rec);
                }
            }
            Ok(Msg::Custom(mut rec)) => {
                clamp_ts(&mut rec);
                for a in pipe.feed(&rec) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let since = *idle_since.get_or_insert_with(Instant::now);
                if !caught_up && since.elapsed() >= Duration::from_secs(2) {
                    caught_up = true;
                    eprintln!("logguard: caught up with the journal (idle)");
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if let (Some(jobs), false) = (&scan_tx, scan_busy) {
            let batch = pipe.engine.take_scans(MAX_SCAN_BATCH);
            if !batch.is_empty() {
                scan_busy = jobs.send(batch).is_ok();
            }
        }
        if caught_up && last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
            for a in pipe.tick(time::now()) {
                sink.handle(&enforcer, &mut pipe.engine, a);
            }
            for (key, msg) in sink.notifier.take_problems() {
                for a in pipe.engine.system_alert_wall(&key, 3600 * time::SEC, Severity::High, msg, time::now()) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
        }
        if let (Some(c), Some(jobs)) = (cluster.as_mut(), &send_jobs) {
            if last_sync.elapsed() >= Duration::from_secs(c.cfg.sync_interval.0.max(1)) {
                last_sync = Instant::now();
                let facts = pipe.engine.take_outbox(c.cfg.min_report_points);
                // Evidence replayed from journal history is not news for the cluster.
                if caught_up {
                    let now = time::now();
                    for f in facts.into_iter().chain(sink.relay.as_mut().map(std::mem::take).unwrap_or_default()) {
                        c.originate(f, now);
                    }
                    // A large sync comes in several frames: one connection thread per peer
                    // sends them in order and reports the first failure.
                    let mut per_peer: std::collections::BTreeMap<usize, Vec<Vec<u8>>> = std::collections::BTreeMap::new();
                    for (i, frame) in c.outgoing(now) {
                        per_peer.entry(i).or_default().push(frame);
                    }
                    for (i, frames) in per_peer {
                        if in_flight[i] {
                            continue; // previous delivery still pending; the next sync resends
                        }
                        in_flight[i] = true;
                        let (tx, addr) = (jobs.clone(), c.cfg.peers[i].clone());
                        thread::spawn(move || {
                            let result = frames.iter().try_for_each(|f| crate::cluster::send_frame(&addr, f));
                            let _ = tx.send(Msg::Delivered(i, result));
                        });
                    }
                }
            }
        }
        if cfg.digest.enabled && caught_up && last_digest_check.elapsed() >= Duration::from_secs(30) {
            last_digest_check = Instant::now();
            let now = time::now();
            if cfg.digest.last_due(now).is_some_and(|due| pipe.engine.digest_last_sent < due) {
                for a in send_digest(&mut pipe, &cluster, &cfg, now) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
        }
        if let Some(every) = watchdog {
            if last_watchdog.elapsed() >= every {
                last_watchdog = Instant::now();
                sd_notify("WATCHDOG=1");
            }
        }
        if caught_up && last_silence_check.elapsed() >= Duration::from_secs(60) {
            last_silence_check = Instant::now();
            for a in pipe.engine.check_silence(time::now()) {
                sink.handle(&enforcer, &mut pipe.engine, a);
            }
        }
        // Hourly; the alert itself repeats at most weekly (its gate is saved with the state).
        if caught_up && last_key_check.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
            last_key_check = Some(Instant::now());
            let now = time::now();
            if let Some(msg) = cluster.as_ref().and_then(|c| c.cfg.rotation_reminder(c.view.key_since, now)) {
                for a in pipe.engine.system_alert_wall("cluster-key-age", 7 * 86_400 * time::SEC, Severity::Warning, msg, now) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
        }
        if last_heal.elapsed() >= Duration::from_secs(30) {
            last_heal = Instant::now();
            // tripwire ports something listens on now (any address, whatever the exposure watch
            // leaves out) aren't logged in the kernel: a service started there isn't a tripwire
            if let Err(e) = enforcer.set_trip_ports(crate::enforce::trip_ports(&cfg, &crate::enforce::served_tcp_ports())) {
                eprintln!("logguard: updating the kernel tripwire ports: {e:#}");
            }
            let missing = !enforcer.table_present();
            if let Some(msg) = missing
                .then(|| enforcer.heal(&pipe.engine.active_bans(), &pipe.engine.allowed(), &feed_nets, &waf_nets, &geo_nets, time::now()))
                .flatten()
            {
                eprintln!("logguard: {msg}");
                for a in pipe.engine.system_alert_wall("nft-heal", 10 * time::MIN, Severity::High, msg, time::now()) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
        }
        // Lossless at any interval: after a crash the journal is replayed from the saved cursor
        // (and bans live on in the kernel), so save only when something worth keeping changed,
        // at most every 10 minutes - and hourly regardless, to bound that replay.
        let since_save = last_save.elapsed();
        if (pipe.engine.changes != saved_changes && since_save >= Duration::from_secs(600)) || since_save >= Duration::from_secs(3600) {
            last_save = Instant::now();
            saved_changes = pipe.engine.changes;
            if let Err(e) = save_state(&cfg.state_file, &pipe.engine.export(cursor.clone())) {
                eprintln!("logguard: saving state: {e:#}");
            }
        }
    }

    eprintln!("logguard: stopping");
    sd_notify("STOPPING=1");
    stop.store(true, Ordering::Relaxed);
    if let Some(mut c) = child_slot.lock().unwrap().take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    save_state(&cfg.state_file, &pipe.engine.export(cursor))?;
    let _ = fs::remove_file(&cfg.socket);
    if cfg.console.enabled() {
        let _ = fs::remove_file(&cfg.console.socket);
    }
    Ok(())
}

/// Applies a `[waf]` refresh: loads the list (when it changed), brings each ban source's bans
/// in line with its decisions, and raises a `system` alert (daily) about sources that fail.
fn apply_waf(
    u: crate::waf::WafUpdate,
    pipe: &mut Pipeline,
    cfg: &Config,
    enforcer: &Enforcer,
    sink: &mut ActionSink,
    waf_nets: &mut Vec<crate::net::Net>,
) {
    let mut status = u.status;
    let was_applied = pipe.engine.waf.as_ref().is_some_and(|w| w.applied);
    status.applied = was_applied;
    match u.list {
        Some(list) if list != *waf_nets || (!was_applied && !list.is_empty()) => match enforcer.load_waf(&list) {
            Ok(applied) => {
                status.applied = applied;
                if applied || list.is_empty() {
                    *waf_nets = list;
                }
            }
            Err(e) => status.error = Some(format!("loading the list into the firewall: {e:#}")),
        },
        Some(_) => {}
        // refused (too many): what is loaded stays
        None => {
            status.list_v4 = waf_nets.iter().filter(|n| n.is_v4()).count();
            status.list_v6 = waf_nets.len() - status.list_v4;
        }
    }
    pipe.engine.now = pipe.engine.now.max(time::now());
    for (name, decisions) in u.bans {
        let Some(src) = cfg.waf.sources.iter().find(|s| s.name == name) else { continue };
        let skipped = match decisions {
            Some(d) => {
                let (actions, skipped) = pipe.engine.waf_sync(src, &d);
                for a in actions {
                    sink.handle(enforcer, &mut pipe.engine, a);
                }
                Some(skipped)
            }
            None => None,
        };
        let banned = pipe.engine.waf_bans(&name).len();
        let last = pipe.engine.waf.as_ref().and_then(|w| w.sources.iter().find(|s| s.name == name)).map(|s| s.skipped);
        if let Some(st) = status.sources.iter_mut().find(|s| s.name == name) {
            st.banned = banned;
            st.skipped = skipped.or(last).unwrap_or(0);
        }
    }
    let problems = status.problems();
    if !problems.is_empty() {
        let msg = format!("[waf] problems: {}", problems.join("; "));
        for a in pipe.engine.system_alert_wall("waf", 86_400 * time::SEC, Severity::Warning, msg, time::now()) {
            sink.handle(enforcer, &mut pipe.engine, a);
        }
    }
    pipe.engine.waf = Some(status);
}

/// `[geoblock]`'s networks from a freshly loaded geo database, loaded into the firewall: the
/// networks now in it (None: refused, the last ones stay), and the status.
fn apply_geoblock(
    db: &crate::geo::GeoDb,
    gcfg: &crate::geo::GeoblockCfg,
    keep: &[crate::net::Net],
    enforcer: &Enforcer,
) -> (Option<Vec<crate::net::Net>>, crate::geo::GeoblockStatus) {
    let nets = db.blocked_networks(gcfg, keep);
    let v4 = nets.iter().filter(|n| n.is_v4()).count();
    let (countries, only_countries) = gcfg.country_codes();
    let mut status = crate::geo::GeoblockStatus {
        computed: time::now(),
        what: gcfg.describe(),
        v4,
        v6: nets.len() - v4,
        countries,
        only_countries,
        asns: gcfg.asns.clone(),
        ..Default::default()
    };
    if nets.len() > gcfg.max_entries {
        status.error = Some(format!("{} networks exceed max_entries {}", nets.len(), gcfg.max_entries));
        return (None, status);
    }
    match enforcer.load_geoblock(&nets) {
        Ok(applied) => status.applied = applied,
        Err(e) => status.error = Some(format!("loading into {}: {e:#}", enforcer.name())),
    }
    eprintln!(
        "logguard: geoblock ({}): {} IPv4 + {} IPv6 networks{}",
        status.what,
        status.v4,
        status.v6,
        if status.applied { String::new() } else { format!(", not applied ({})", enforcer.name()) }
    );
    (status.error.is_none().then_some(nets), status)
}

fn full_snapshot(pipe: &Pipeline, cluster: &Option<crate::cluster::Cluster>) -> crate::engine::Snapshot {
    let mut snap = pipe.snapshot(300);
    snap.cluster = cluster.as_ref().map(|c| c.view.clone());
    snap
}

fn digest_action(subject: String, body: String, now: time::Micros) -> Action {
    Action {
        ts: now,
        kind: crate::engine::ActionKind::Alert,
        severity: Severity::Info,
        target: None,
        until: None,
        message: subject,
        evidence: vec![],
        superseded: vec![],
        applied: false,
        topic: Some(crate::engine::Topic::Digest),
        accounts: vec![],
        user_note: Some(body),
        notice: None,
        category: None,
    }
}

fn send_digest(pipe: &mut Pipeline, cluster: &Option<crate::cluster::Cluster>, cfg: &Config, now: time::Micros) -> Vec<Action> {
    let data = pipe.engine.digest_take(now);
    pipe.engine.digest_last_sent = now;
    let (subject, mut body) = crate::digest::render(&data, &full_snapshot(pipe, cluster), cfg.digest.cert_warn_days);
    body += &crate::geo::attribution(&cfg.geo, pipe.engine.geo.is_some());
    vec![digest_action(subject, body, now)]
}

/// Executes an operator command; returns the reply text and resulting actions.
#[allow(clippy::too_many_arguments)]
fn control(
    cmd: &str,
    pipe: &mut Pipeline,
    cluster: &Option<crate::cluster::Cluster>,
    cfg: &Config,
    (feeds_refresh, waf_refresh): (&Option<std::sync::mpsc::Sender<()>>, &Option<std::sync::mpsc::Sender<()>>),
    enforcer: &Enforcer,
    (feed_nets, waf_nets): (&mut Vec<crate::net::Net>, &mut Vec<crate::net::Net>),
    caught_up: bool,
) -> (String, Vec<Action>) {
    let now = time::now();
    if cmd == "snapshot" {
        let mut snap = full_snapshot(pipe, cluster);
        snap.backend = Some(enforcer.name().into());
        return (serde_json::to_string(&snap).unwrap_or_else(|e| format!("error: {e}")), vec![]);
    }
    if caught_up {
        // during catch-up the engine runs on record time; don't jump it to the wall clock
        pipe.engine.now = pipe.engine.now.max(now);
    }
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let net =
        |i: usize| -> Result<crate::net::Net, String> { words.get(i).ok_or("missing address".to_string())?.parse::<crate::net::Net>() };
    let summarize = |actions: &[Action]| actions.iter().map(|a| a.message.clone()).collect::<Vec<_>>().join("\n");
    match words.as_slice() {
        ["unban", ..] => {
            // a WAF's ban comes back with its next read while the WAF still lists it
            let from_waf: Vec<String> = match net(1) {
                Ok(n) => pipe
                    .engine
                    .active_bans()
                    .iter()
                    .filter(|b| n.contains_net(&b.net) && b.origin.is_none() && b.reason.starts_with("waf "))
                    .map(|b| b.net.to_string())
                    .collect(),
                Err(_) => vec![],
            };
            match net(1).and_then(|n| pipe.engine.operator_unban(n)) {
                Ok(actions) => {
                    let mut text = format!("ok\n{}", summarize(&actions));
                    if !from_waf.is_empty() {
                        text += &format!(
                            "\nnote: {} banned by [waf]: banned again at its next read while the WAF lists it; \
                             delete the decision there, or `logguard allow` it",
                            from_waf.join(", ")
                        );
                    }
                    (text, actions)
                }
                Err(e) => (format!("error: {e}"), vec![]),
            }
        }
        ["allow", _, secs, note @ ..] => {
            let secs: i64 = match secs.parse::<i64>() {
                // capped at a year: also keeps `now + secs` far from overflowing
                Ok(s) if s > 0 => s.min(365 * 86_400),
                _ => return ("error: duration must be a positive number of seconds".into(), vec![]),
            };
            match net(1) {
                Ok(n) => {
                    let note = if note.is_empty() { "operator".to_string() } else { note.join(" ") };
                    let actions = pipe.engine.operator_allow(n, now + secs * time::SEC, note);
                    let mut text = format!("ok\n{}", summarize(&actions));
                    // ufw and firewalld can't let it through a wider ban (an allow rule would open every
                    // port; a zone's sources have no exceptions)
                    let through = matches!(enforcer.kind, crate::enforce::Kind::Ufw | crate::enforce::Kind::Firewalld);
                    if let Some(b) = pipe.engine.covering_ban(&n).filter(|_| through) {
                        text += &format!(
                            "\nnote: with {1} it stays blocked by the ban on {0}: `logguard unban {0}` to let it in",
                            b.net,
                            enforcer.name()
                        );
                    }
                    (text, actions)
                }
                Err(e) => (format!("error: {e}"), vec![]),
            }
        }
        ["ban", _, secs, note @ ..] => {
            let secs: i64 = match secs.parse::<i64>() {
                // capped at a year, like allow
                Ok(s) if s > 0 => s.min(365 * 86_400),
                _ => return ("error: duration must be a positive number of seconds".into(), vec![]),
            };
            let note = if note.is_empty() { "operator".to_string() } else { note.join(" ") };
            match net(1).and_then(|n| pipe.engine.operator_ban(n, pipe.engine.now.max(now) + secs * time::SEC, note)) {
                Ok(actions) => {
                    let mut text = format!("ok\n{}", summarize(&actions));
                    if enforcer.kind == crate::enforce::Kind::Shadow {
                        text += "\nnote: shadow mode: decided and shared, but not applied to this firewall";
                    }
                    (text, actions)
                }
                Err(e) => (format!("error: {e}"), vec![]),
            }
        }
        ["disallow", ..] => match net(1).and_then(|n| pipe.engine.operator_disallow(n)) {
            Ok(actions) => (format!("ok\n{}", summarize(&actions)), actions),
            Err(e) => (format!("error: {e}"), vec![]),
        },
        ["allowed"] => {
            let list: Vec<String> = pipe
                .engine
                .allowed()
                .iter()
                .map(|a| format!("{:<22} {:>9} left  {}", a.net.to_string(), time::fmt_duration(a.until - now), a.note))
                .collect();
            (if list.is_empty() { "operator allowlist is empty".into() } else { list.join("\n") }, vec![])
        }
        ["feeds", "refresh"] => match feeds_refresh {
            Some(tx) => {
                let _ = tx.send(());
                ("ok: refresh started (see `logguard status` in a minute)".into(), vec![])
            }
            None => ("error: [feeds] enabled = false".into(), vec![]),
        },
        ["feeds", "clear"] => match enforcer.load_feeds(&[]) {
            Ok(_) => {
                feed_nets.clear();
                if let Some(f) = pipe.engine.feeds.as_mut() {
                    f.applied = false;
                    f.error = Some("cleared by operator (reloaded at the next refresh; set [feeds] enabled = false to keep it off)".into());
                }
                ("ok: blocklist feed sets emptied".into(), vec![])
            }
            Err(e) => (format!("error: {e:#}"), vec![]),
        },
        ["waf", "refresh"] => match waf_refresh {
            Some(tx) => {
                let _ = tx.send(());
                ("ok: reading the [waf] sources (see `logguard waf` in a minute)".into(), vec![])
            }
            None => ("error: [waf] enabled = false".into(), vec![]),
        },
        ["waf", "clear"] => match enforcer.load_waf(&[]) {
            Ok(_) => {
                waf_nets.clear();
                if let Some(w) = pipe.engine.waf.as_mut() {
                    w.applied = false;
                    w.error = Some("list cleared by operator (loaded again at the next refresh; its bans stay)".into());
                }
                ("ok: [waf] list sets emptied (bans from WAFs stay: `logguard unban` them)".into(), vec![])
            }
            Err(e) => (format!("error: {e:#}"), vec![]),
        },
        ["digest"] => {
            let node = cluster.as_ref().map_or_else(crate::cluster::hostname, |c| c.node_id.clone());
            let (subject, body) =
                crate::digest::render(&pipe.engine.digest_preview(), &full_snapshot(pipe, cluster), cfg.digest.cert_warn_days);
            let body = body + &crate::geo::attribution(&cfg.geo, pipe.engine.geo.is_some());
            (format!("[{node}] {subject}\n\n{body}"), vec![])
        }
        ["digest", "send"] => {
            let actions = send_digest(pipe, cluster, cfg, now);
            ("ok: digest sent".into(), actions)
        }
        _ => (format!("error: unknown command '{cmd}'"), vec![]),
    }
}

/// Sends one control command to a running daemon and returns its reply.
pub fn control_command(socket: &Path, cmd: &str) -> Result<String> {
    let mut s = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("connecting to {} (is logguard running? are you root?)", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(20)))?;
    s.write_all(cmd.as_bytes())?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut body = String::new();
    s.read_to_string(&mut body)?;
    Ok(body)
}

/// Fetches a snapshot from a running daemon.
pub fn fetch_snapshot(socket: &Path) -> Result<String> {
    let mut s = std::os::unix::net::UnixStream::connect(socket).with_context(|| format!("connecting to {}", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(b"snapshot\n")?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut body = String::new();
    s.read_to_string(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waf_updates_become_bans() {
        use crate::waf::{Decision, SourceStatus, WafAction, WafStatus, WafUpdate};
        let cfg = Arc::new(
            Config::from_toml(
                "[waf]\nenabled = true\n[[waf.sources]]\nname = \"crowdsec\"\nformat = \"crowdsec\"\nfile = \"/dev/null\"\n\
                 [[waf.sources]]\nname = \"capi\"\nfile = \"/dev/null\"\naction = \"list\"\n",
            )
            .unwrap(),
        );
        let mut pipe = Pipeline::new(Arc::clone(&cfg), 0);
        let enforcer = Enforcer::shadow();
        let mut sink = ActionSink::new(None, Notifier::new(&cfg.notify, cfg.mode));
        let mut waf_nets = Vec::new();
        let now = time::now();
        let status = |error: Option<&str>| WafStatus {
            refreshed: now,
            sources: vec![
                SourceStatus { name: "crowdsec".into(), action: WafAction::Ban, error: error.map(String::from), ..Default::default() },
                SourceStatus { name: "capi".into(), action: WafAction::List, ..Default::default() },
            ],
            ..Default::default()
        };
        let ip: crate::net::Net = "11.18.9.9".parse().unwrap();
        let decision =
            Decision { net: ip, until: Some(now + 3600 * time::SEC), kind: "ban".into(), origin: "crowdsec".into(), reason: "x".into() };
        let update = WafUpdate {
            status: status(None),
            list: Some(vec!["6.6.6.0/24".parse().unwrap()]),
            bans: vec![("crowdsec".into(), Some(vec![decision]))],
        };
        apply_waf(update, &mut pipe, &cfg, &enforcer, &mut sink, &mut waf_nets);
        assert!(pipe.engine.banned_by(ip.addr).is_some_and(|b| b.reason == "waf crowdsec: x"));
        let w = pipe.engine.waf.clone().unwrap();
        assert_eq!((w.sources[0].banned, w.applied, waf_nets.len()), (1, false, 0), "shadow mode: the list isn't loaded");

        // the WAF can't be read: its ban stays, and the admins hear of it
        let update = WafUpdate { status: status(Some("connection refused")), list: Some(vec![]), bans: vec![("crowdsec".into(), None)] };
        apply_waf(update, &mut pipe, &cfg, &enforcer, &mut sink, &mut waf_nets);
        assert!(pipe.engine.banned_by(ip.addr).is_some());
        assert_eq!(pipe.engine.waf.as_ref().unwrap().sources[0].banned, 1);
        assert!(pipe.snapshot(10).alerts.iter().any(|a| a.message.contains("[waf] problems: crowdsec: connection refused")));

        // it can again, and the decision is gone: so is the ban
        let update = WafUpdate { status: status(None), list: Some(vec![]), bans: vec![("crowdsec".into(), Some(vec![]))] };
        apply_waf(update, &mut pipe, &cfg, &enforcer, &mut sink, &mut waf_nets);
        assert!(pipe.engine.banned_by(ip.addr).is_none());
    }

    #[test]
    fn unreadable_state_is_kept_aside() {
        let dir = std::env::temp_dir().join(format!("logguard-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        assert!(matches!(load_state(&path), (None, None)), "no file yet: nothing to report");
        fs::write(&path, b"\x1f\x8bgarbage").unwrap();
        let (st, problem) = load_state(&path);
        assert!(st.is_none());
        assert!(problem.unwrap().contains("kept as"));
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "the bad file is kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn followed_logs_resume_without_repeats() {
        let line = |t: &str, ip: &str| format!(r#"{{"time":"{t}","remoteAddr":"{ip}","message":"Login failed: x (Remote IP: {ip})"}}"#);
        let old = line("2026-10-12T10:00:00+00:00", "192.0.2.1");
        let new1 = line("2026-10-12T10:00:05+00:00", "192.0.2.2");
        let new2 = line("2026-10-12T10:00:05+00:00", "192.0.2.3"); // same second: still new
                                                                   // no event, but it moves the position (a quiet log must not be replayed from far back)
        let quiet = r#"{"time":"2026-10-12T10:02:00+00:00","remoteAddr":"192.0.2.9","message":"cron job ran"}"#;
        let script = format!("printf '%s\\n%s\\n%s\\n%s\\n' '{old}' '{new1}' '{new2}' '{quiet}'; sleep 5");
        let seen = time::parse_iso_prefix("2026-10-12 10:00:00").unwrap().0;
        let (tx, rx) = sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let got_seen = Arc::new(std::sync::atomic::AtomicI64::new(-1));
        let g = Arc::clone(&got_seen);
        follow(
            "test",
            "sh".into(),
            move |s| {
                g.store(s, Ordering::Relaxed);
                vec!["-c".into(), script.clone()]
            },
            seen,
            tx,
            Arc::clone(&stop),
        );
        let (mut ips, mut positions) = (vec![], vec![]);
        loop {
            match rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Msg::Live(_, r)) => ips.push(r.msg.split("remoteAddr\":\"").nth(1).unwrap().split('"').next().unwrap().to_string()),
                Ok(Msg::Position(_, t)) => positions.push(t),
                _ => break,
            }
        }
        stop.store(true, Ordering::Relaxed);
        assert_eq!(ips, ["192.0.2.2", "192.0.2.3"], "the already-seen line is skipped");
        assert_eq!(got_seen.load(Ordering::Relaxed), seen, "the program was told where to resume");
        assert_eq!(positions, [seen + 120 * time::SEC], "the quiet line moved the position");
        assert_eq!(
            crate::record::line_time("2026-10-12T12:47:39.763221894Z [Mon Oct 12 14:47:39 2026] x"),
            Some(seen + (2 * 3600 + 47 * 60 + 39) * time::SEC + 763_221)
        );
        assert_eq!(crate::record::line_time("[Mon Oct 12 14:47:39 2026] no docker prefix"), None);
    }

    #[test]
    fn followed_lines_are_capped() {
        let long = vec![b'x'; 3 * MAX_FOLLOWED_LINE as usize];
        let input = [b"first\n".as_slice(), &long, b"\nlast\n"].concat();
        let mut r = BufReader::new(input.as_slice());
        let mut lines = vec![];
        let mut buf = Vec::new();
        while crate::record::read_line_capped(&mut r, &mut buf, MAX_FOLLOWED_LINE).unwrap() > 0 {
            lines.push(buf.len());
            buf.clear();
        }
        assert_eq!(lines, [6, MAX_FOLLOWED_LINE as usize, 5], "the long line cut, the next one whole");
    }

    /// A command the client sends in pieces (a long `allow` note) reaches the daemon whole.
    #[test]
    fn control_commands_arrive_whole() {
        let dir = std::env::temp_dir().join(format!("logguard-ctl-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("ctl.sock");
        let (tx, rx) = sync_channel::<Control>(1);
        serve_control(path.clone(), tx).unwrap();
        let cmd = format!("allow 192.0.2.1 60 {}", "x".repeat(2000));
        let client = {
            let (path, cmd) = (path.clone(), cmd.clone());
            thread::spawn(move || {
                let mut s = std::os::unix::net::UnixStream::connect(&path).unwrap();
                let (a, b) = cmd.split_at(100);
                s.write_all(a.as_bytes()).unwrap();
                thread::sleep(Duration::from_millis(100));
                s.write_all(b.as_bytes()).unwrap();
                s.shutdown(std::net::Shutdown::Write).unwrap();
                let mut reply = String::new();
                s.read_to_string(&mut reply).unwrap();
                reply
            })
        };
        let (got, reply) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, cmd);
        reply.send("ok".into()).unwrap();
        assert_eq!(client.join().unwrap(), "ok");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn console_socket_only_reads() {
        let dir = std::env::temp_dir().join(format!("logguard-console-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("console.sock");
        let _ = fs::remove_file(&path);
        let (tx, rx) = sync_channel::<Control>(4);
        let log = dir.join("actions.jsonl");
        let ban = crate::engine::Action {
            ts: time::now() - 3600 * time::SEC,
            kind: crate::engine::ActionKind::Ban,
            severity: Severity::High,
            target: Some("203.0.113.9".parse().unwrap()),
            until: None,
            message: "ban 203.0.113.9 for 1h (offence #1)".into(),
            evidence: vec![format!("{} tripwire block TCP/23", &time::fmt_ts(time::now() - 3600 * time::SEC)[5..19])],
            superseded: vec![],
            applied: true,
            topic: None,
            accounts: vec![],
            user_note: None,
            notice: None,
            category: Some("tripwire".into()),
        };
        fs::write(&log, serde_json::to_string(&ban).unwrap() + "\n").unwrap();
        let reports = Arc::new(AbuseReports::new(Some(log), Arc::default()));
        answer(UnixListener::bind(&path).unwrap(), tx, console_admit, Some(reports));
        let ask = |cmd: &str| {
            let (path, cmd) = (path.clone(), cmd.to_string());
            thread::spawn(move || control_command(&path, &cmd).unwrap())
        };
        for refused in [
            "unban 192.0.2.1",
            "ban 192.0.2.1 60",
            "allow 192.0.2.1 60",
            "disallow 192.0.2.1",
            "feeds clear",
            "waf clear",
            "waf refresh",
            "digest send",
        ] {
            let reply = ask(refused).join().unwrap();
            assert!(reply.starts_with("error: read-only socket"), "{refused}: {reply}");
        }
        assert!(rx.try_recv().is_err(), "nothing refused reaches the main loop");
        for (cmd, want) in [("", "snapshot"), ("snapshot", "snapshot"), ("digest", "digest")] {
            let client = ask(cmd);
            let (got, reply) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(got, want);
            reply.send(format!("answer to {got}")).unwrap();
            assert_eq!(client.join().unwrap(), format!("answer to {want}"));
        }
        // abuse reports are built beside the main loop, from the actions log
        for cmd in ["abuse", "abuse 24h"] {
            let reply = ask(cmd).join().unwrap();
            let v: serde_json::Value = serde_json::from_str(&reply).unwrap_or_else(|e| panic!("{e}: {reply}"));
            assert_eq!(v["offenders"][0]["net"], "203.0.113.9", "{reply}");
            assert!(v["offenders"][0]["evidence"][0]["text"].as_str().unwrap().contains("closed port TCP/23 (Telnet)"), "{reply}");
        }
        assert!(rx.try_recv().is_err(), "abuse reports don't reach the main loop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn notifies_systemd() {
        let dir = std::env::temp_dir().join(format!("logguard-notify-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("notify.sock");
        let _ = fs::remove_file(&path);
        let listener = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        // Only this test touches these variables.
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", &path);
            std::env::set_var("WATCHDOG_USEC", "120000000");
            std::env::remove_var("WATCHDOG_PID");
        }
        sd_notify("READY=1");
        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        assert_eq!(watchdog_interval(), Some(Duration::from_secs(40)));
        unsafe {
            std::env::set_var("WATCHDOG_PID", "1");
        }
        assert_eq!(watchdog_interval(), None, "meant for another process");
        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
            std::env::remove_var("WATCHDOG_USEC");
            std::env::remove_var("WATCHDOG_PID");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_verification_key_warning() {
        let plain = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n";
        let hidden = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,hidepid=invisible\n";
        let off = "22 1 0:21 / /proc rw,relatime shared:12 - proc proc rw,hidepid=0\n";
        assert!(!proc_hides_pids(plain) && proc_hides_pids(hidden) && !proc_hides_pids(off));
        assert!(proc_hides_pids("22 1 0:21 / /proc rw shared:12 - proc proc rw,hidepid=2,gid=4\n"));
        assert!(!proc_hides_pids("40 22 0:5 / /proc/sys rw - proc proc rw,hidepid=invisible\n"), "another mount point");
        let mut cfg = Config::default();
        assert_eq!(verify_key_warning(&cfg, plain), None, "no key set");
        cfg.journal.verify_every = time::Dur(86_400);
        cfg.journal.verify_key_file = "/etc/logguard/journal-verify.key".into();
        let w = verify_key_warning(&cfg, plain).unwrap();
        assert!(w.contains("can seal journal entries too") && w.contains("hidepid=invisible"), "{w}");
        assert!(!verify_key_warning(&cfg, hidden).unwrap().contains("command line"));
    }

    #[test]
    fn journalctl_matches_are_ored() {
        let cfg = Config::default();
        let args = journalctl_args(&cfg, None);
        assert!(args.contains(&"--since=-3600s".to_string()));
        // only the fields parse_journal_json reads
        let fields = args.iter().find_map(|a| a.strip_prefix("--output-fields=")).unwrap();
        for f in ["MESSAGE", "SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_PID", "_EXE", "_TRANSPORT", "_UID"] {
            assert!(fields.split(',').any(|x| x == f), "{f}");
        }
        let tail = &args[args.len() - 19..];
        assert_eq!(tail[0], "_SYSTEMD_UNIT=ejabberd.service");
        assert_eq!(tail[1], "+");
        assert_eq!(tail[8], "_TRANSPORT=kernel");
        assert_eq!(tail[12], "SYSLOG_IDENTIFIER=sudo");
        assert_eq!(
            (tail[14].as_str(), tail[16].as_str(), tail[18].as_str()),
            ("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "_TRANSPORT=audit")
        );
        // with auditd's file, not the journal's copies
        let file = Config::from_toml("[sources]\naudit_log = \"/var/log/audit/audit.log\"").unwrap();
        assert!(!journalctl_args(&file, None).contains(&"_TRANSPORT=audit".to_string()));
        let args = journalctl_args(&cfg, Some("s=1;i=2"));
        assert!(args.contains(&"--after-cursor=s=1;i=2".to_string()));
    }
}
