//! The long-running service: follows the journal, detects, enforces, persists
//! state and serves snapshots to the TUI over a Unix socket.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
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
}

pub fn journalctl_args(cfg: &Config, cursor: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["--follow", "--output=json", "--no-pager", "--quiet"].map(String::from).to_vec();
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
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let (rec, cur) = parse_journal_json(&line);
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
                eprintln!(
                    "logguard: journalctl keeps rejecting the saved position; reading the last {} instead",
                    cfg.journal.initial_lookback
                );
                cursor = None;
                quick_exits = 0;
            }
            eprintln!("logguard: journalctl exited, restarting in 5s");
            thread::sleep(Duration::from_secs(5));
        }
    }
}

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
                    while matches!(reader.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
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

type Control = (String, std::sync::mpsc::Sender<String>);

fn serve_control(path: PathBuf, control: SyncSender<Control>) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
            let mut cmd = [0u8; 1024];
            let n = s.read(&mut cmd).unwrap_or(0);
            let cmd = String::from_utf8_lossy(&cmd[..n]).trim().to_string();
            let cmd = if cmd.is_empty() { "snapshot".to_string() } else { cmd };
            // Executed by the main loop (it owns all state); the socket is root-only (0600).
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            let reply = match control.send((cmd, reply_tx)) {
                Ok(()) => reply_rx.recv_timeout(Duration::from_secs(15)).unwrap_or_else(|_| "error: daemon did not answer".into()),
                Err(_) => "error: daemon is stopping".into(),
            };
            let _ = s.write_all(reply.as_bytes());
        }
    });
    Ok(())
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
    let never_block: Vec<crate::net::Net> = peer_nets.iter().chain(&own_nets).copied().collect();
    let mut enforcer = Enforcer::new(&cfg, &never_block);
    enforcer.restore(&pipe.engine.active_bans(), now);
    enforcer.restore_allows(&pipe.engine.allowed(), now);
    if !cfg.feeds.enabled {
        // Disabling feeds in the config removes a previously loaded list.
        let _ = enforcer.load_feeds(&[]);
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
    if let Err(e) = serve_control(cfg.socket.clone(), ctrl_tx) {
        eprintln!("logguard: control socket disabled: {e:#}");
    }
    let protected: Vec<crate::net::Net> = cfg.allowlist.nets.iter().chain(never_block.iter()).copied().collect();
    let feeds_refresh = if cfg.feeds.enabled {
        let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<()>();
        let (tx, fcfg, protected) = (tx.clone(), cfg.feeds.clone(), protected.clone());
        thread::spawn(move || loop {
            let (nets, status) = crate::feeds::refresh(&fcfg, &protected);
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
    if cfg.digest.enabled && !(cfg.digest.certs.is_empty() && cfg.digest.cert_files.is_empty()) {
        let (tx, dcfg, stop) = (tx.clone(), cfg.digest.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut certs: Vec<crate::digest::CertStatus> =
                    dcfg.certs.iter().map(|t| crate::digest::check_cert(&dcfg.openssl, t)).collect();
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
                    match crate::geo::GeoDb::load(&gcfg.dir) {
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
    if cfg.sources.nextcloud {
        let nc = &cfg.nextcloud;
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
        let (tx, ecfg, stop) = (tx.clone(), cfg.exposure.clone(), Arc::clone(&stop));
        thread::spawn(move || {
            let mut warned = false;
            while !stop.load(Ordering::Relaxed) {
                match crate::exposure::scan(&ecfg) {
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
        thread::spawn(move || {
            let mut scanner = crate::cronwatch::Scanner::default();
            while !stop.load(Ordering::Relaxed) {
                if tx.send(Msg::Cron(Box::new(scanner.scan(&ccfg)))).is_err() {
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
    let mut deferred_live: Vec<(&'static str, Record)> = Vec::new();
    let mut deferred_positions: Vec<(&'static str, time::Micros)> = Vec::new();
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
            let (inbox, skew, limits) = (c.cfg.inbox.clone(), c.cfg.max_clock_skew, c.limits.clone());
            // A file from a peer is written here, in the connection's thread: it carries no facts.
            let deliver = move |env: crate::cluster::Envelope, from: Option<std::net::IpAddr>| {
                if env.file.is_none() {
                    return tx.send(Msg::Peer(Box::new(env), from)).is_ok();
                }
                if limits.of(from).is_some_and(|k| !k.contains(&crate::cluster::FactKind::Files)) {
                    eprintln!("logguard: cluster: file from {} refused: [cluster] peer_accept doesn't allow files from there", env.from);
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
            _ => "nothing (shadow): no bans are applied",
        };
        let msg = format!("nftables setup failed, enforcing with {instead}. Error: {err}");
        for a in pipe.engine.system_alert_wall("nft-setup", 86_400 * time::SEC, Severity::High, msg, time::now()) {
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
            let (text, actions) = control(&cmd, &mut pipe, &cluster, &cfg, &feeds_refresh, &enforcer, &mut feed_nets, caught_up);
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
            for (name, rec) in std::mem::take(&mut deferred_live) {
                for a in feed_live(&mut pipe, name, rec) {
                    sink.handle(&enforcer, &mut pipe.engine, a);
                }
            }
            for (name, t) in std::mem::take(&mut deferred_positions) {
                advance(&mut pipe, name, t);
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
                    let never_block: Vec<crate::net::Net> = peer_nets.iter().chain(&own_nets).copied().collect();
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
                let _ = ack.send(());
            }
            Ok(Msg::Geo(db, errors)) => {
                if let Some(db) = db {
                    pipe.engine.geo = Some(db);
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
            Ok(Msg::Exposure(r)) if !caught_up => deferred_exposure = Some(*r),
            Ok(Msg::Exposure(r)) => {
                for a in pipe.engine.on_exposure(*r, cfg.sources.ufw) {
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
            let missing = !enforcer.table_present();
            if let Some(msg) =
                missing.then(|| enforcer.heal(&pipe.engine.active_bans(), &pipe.engine.allowed(), &feed_nets, time::now())).flatten()
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
    Ok(())
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
    feeds_refresh: &Option<std::sync::mpsc::Sender<()>>,
    enforcer: &Enforcer,
    feed_nets: &mut Vec<crate::net::Net>,
    caught_up: bool,
) -> (String, Vec<Action>) {
    let now = time::now();
    if cmd == "snapshot" {
        return (serde_json::to_string(&full_snapshot(pipe, cluster)).unwrap_or_else(|e| format!("error: {e}")), vec![]);
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
        ["unban", ..] => match net(1).and_then(|n| pipe.engine.operator_unban(n)) {
            Ok(actions) => (format!("ok\n{}", summarize(&actions)), actions),
            Err(e) => (format!("error: {e}"), vec![]),
        },
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
                    (format!("ok\n{}", summarize(&actions)), actions)
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
    fn journalctl_matches_are_ored() {
        let cfg = Config::default();
        let args = journalctl_args(&cfg, None);
        assert!(args.contains(&"--since=-3600s".to_string()));
        let tail = &args[args.len() - 9..];
        assert_eq!(tail[0], "_SYSTEMD_UNIT=ejabberd.service");
        assert_eq!(tail[1], "+");
        assert_eq!(tail[8], "_TRANSPORT=kernel");
        let args = journalctl_args(&cfg, Some("s=1;i=2"));
        assert!(args.contains(&"--after-cursor=s=1;i=2".to_string()));
    }
}
