use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use logguard::config::Config;
use logguard::{config, daemon, enforce, notify, replay, tui};

#[derive(Parser)]
#[command(version = env!("LOGGUARD_VERSION"), about = "Near-realtime behaviour-based protection for SSH, ejabberd and UFW")]
struct Cli {
    /// Configuration file (TOML). Built-in defaults are used when omitted.
    #[arg(short, long, global = true, env = "LOGGUARD_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon: follow the journal, detect, and (in enforce mode) ban.
    Run,
    /// Replay log files offline (journalctl short or JSON output); never touches the firewall.
    Replay {
        files: Vec<PathBuf>,
        /// Year for syslog timestamps without one (default: current year).
        #[arg(long)]
        year: Option<i64>,
        /// Print only the summary, not each decision.
        #[arg(short, long)]
        quiet: bool,
        /// Print the evidence behind each ban.
        #[arg(short, long)]
        verbose: bool,
        /// Write the final snapshot as JSON (viewable with `logguard tui --file`).
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Number of offenders in the summary.
        #[arg(long, default_value_t = 25)]
        top: usize,
        /// Print the XMPP notifications that would be sent (as if in enforce mode). Nothing is sent.
        #[arg(long)]
        notify: bool,
        /// Write the state file the daemon would save at the end.
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Send a test XMPP notification through ejabberdctl (run on the server).
    NotifyTest {
        /// Recipient JID (with --telegram or --mail: the first of [notify] admins, if any, when left out).
        #[arg(required_unless_present_any = ["telegram", "mail"])]
        jid: Option<String>,
        /// Through the admin bot's outbox ([notify] bot_outbox), OMEMO-encrypted, and wait
        /// until the bot has sent it. One it doesn't take, the running daemon sends unencrypted.
        #[arg(long, conflicts_with_all = ["telegram", "mail"])]
        bot: bool,
        /// Only through the Telegram bot's outbox ([notify] tg_outbox), and wait until logguard-tg-bot
        /// has sent it.
        #[arg(long, conflicts_with = "mail")]
        telegram: bool,
        /// Only through the mail bot's outbox ([notify] mail_outbox), and wait until logguard-mail-bot
        /// has sent it.
        #[arg(long)]
        mail: bool,
    },
    /// Interactive dashboard for a running daemon (or a saved snapshot).
    Tui {
        /// Read a snapshot file instead of the daemon socket.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Show the state at the end of decision logs (actions.jsonl, rotated .gz copies, or
        /// several servers' logs, combined), read-only and without the daemon. Places come
        /// from the [geo] database when it is set up on this machine, else from the ban messages.
        #[arg(long, conflicts_with = "file", num_args = 1.., value_name = "FILE")]
        actions: Vec<PathBuf>,
    },
    /// Plain-text summary from the running daemon (no terminal needed).
    Status {
        /// Number of offenders to list.
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Lift a ban (address or network); also clears its score and offence history.
    Unban { net: String },
    /// Never ban an address/network for a while (lifts current bans inside it).
    Allow {
        net: String,
        /// How long, e.g. 12h, 7d.
        #[arg(long = "for", default_value = "7d", value_parser = |s: &str| s.parse::<logguard::time::Dur>())]
        duration: logguard::time::Dur,
        /// Why (shown in the TUI and logs).
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove an operator allowlist entry.
    Disallow { net: String },
    /// List the operator allowlist.
    Allowed,
    /// Blocklist feeds: status, refresh now, or clear (empty the feed sets in one step).
    Feeds {
        #[arg(value_parser = ["status", "refresh", "clear"], default_value = "status")]
        action: String,
    },
    /// Show today's digest so far (or send it now with --send).
    Digest {
        #[arg(long)]
        send: bool,
    },
    /// Country and network owner of addresses, from the offline [geo] database.
    Geo {
        ips: Vec<std::net::IpAddr>,
        /// Download the databases first if they are missing or older than [geo] refresh.
        #[arg(long)]
        download: bool,
    },
    /// What the cron watch sees right now (with package origins), and the antivirus log's
    /// recent scans. Read-only; works without the daemon.
    Integrity {
        /// Number of recent scans to list.
        #[arg(long, default_value_t = 5)]
        scans: usize,
    },
    /// Report of the addresses banned in a time window, with their evidence, for abuse
    /// desks of the networks they come from. Account names and internal scores are withheld.
    AbuseReport {
        /// Time window back from now, e.g. 24h, 7d, 30d.
        #[arg(long, default_value = "7d", value_parser = |s: &str| s.parse::<logguard::time::Dur>())]
        since: logguard::time::Dur,
        /// Only these addresses or networks (repeatable).
        #[arg(long = "ip")]
        ips: Vec<String>,
        /// Leave out sources with less evidence than this (one blocked packet isn't worth a report).
        #[arg(long, default_value_t = 3)]
        min_events: usize,
        /// The most persistent sources only (repeat offenders first).
        #[arg(long, default_value_t = 50)]
        top: usize,
        /// Every source in the window (ignores --top).
        #[arg(long)]
        all: bool,
        /// Look up each network's abuse e-mail address (RDAP via rdap.org; ~1 request per second).
        #[arg(long)]
        contacts: bool,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Write to this file instead of stdout.
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Combine `--json` reports of several servers (one entry per source, each log line
        /// marked with the server it hit) instead of reading this server's log.
        #[arg(long, num_args = 1.., value_name = "REPORT.json")]
        merge: Vec<PathBuf>,
    },
    /// Send a file to the cluster peers once, e.g. this server's weekly JSON abuse report
    /// for the node that merges them. Peers write it to their `[cluster] inbox` as
    /// `<name>-<this node>.json.gz`.
    ClusterSendReport {
        /// What the file is.
        #[arg(long, default_value = "abuse", value_parser = clap::builder::PossibleValuesParser::new(logguard::cluster::PEER_FILES))]
        name: String,
        /// Only to this peer (as written in [cluster] peers); repeat for several. Default: all.
        #[arg(long = "peer", value_name = "HOST:PORT")]
        peers: Vec<String>,
        file: PathBuf,
    },
    /// Generate a new random cluster key (base64) for `[cluster] key`/`key_file`.
    ClusterKeygen,
    /// Fingerprints of the cluster keys this node sends and accepts (the same key gives the
    /// same fingerprint on every node; the key itself isn't shown).
    ClusterKeyId {
        /// A key file instead of the configured keys (e.g. deploy/cluster.key on this machine).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Print the ufw commands that open the cluster port to the configured peers only.
    ClusterUfwRules {
        /// iptables/ip6tables commands instead, for hosts without ufw (add them to your
        /// persistent rules, e.g. /etc/iptables/rules.v4).
        #[arg(long)]
        iptables: bool,
    },
    /// Print the effective configuration (the built-in defaults without --config).
    PrintConfig,
    /// Compare the config file with this version's options: unknown keys, new options and
    /// changed defaults (with --against, the previous binary's `print-config` output).
    ConfigDiff {
        /// Defaults of the previously installed version (`logguard print-config` without --config).
        #[arg(long)]
        against: Option<PathBuf>,
        /// Also list every option not set in the file, and settings equal to the default.
        #[arg(long)]
        all: bool,
    },
    /// Print the nftables ruleset logguard installs in enforce mode.
    PrintNft,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("logguard: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn parse_net(s: &str) -> Result<logguard::net::Net> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn send_control(cfg: &Config, cmd: &str) -> Result<()> {
    let reply = daemon::control_command(&cfg.socket, cmd)?;
    println!("{}", reply.trim_end());
    if reply.starts_with("error:") {
        anyhow::bail!("command failed");
    }
    Ok(())
}

/// Command-line tools end quietly when their output is cut short (`status | head`), like
/// other Unix tools, instead of panicking on a broken pipe. Not for the daemon: it writes to
/// pipes of child processes and must get an error, not a signal, when one has gone.
fn default_sigpipe() {
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIGPIPE: i32 = 13; // Linux and macOS
    const SIG_DFL: usize = 0;
    // SAFETY: restores the default disposition of one signal before any thread is started.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    if !matches!(cli.cmd, Cmd::Run) {
        default_sigpipe();
    }
    if let Cmd::ClusterKeyId { file: Some(f) } = &cli.cmd {
        // No config needed: e.g. the local copy deploy.sh installs.
        let text = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        println!("{}  {}", logguard::cluster::key_id(&logguard::cluster::decode_key(text.trim())?), f.display());
        return Ok(());
    }
    if let Cmd::ConfigDiff { against, all } = &cli.cmd {
        // Before loading: the file may not be valid for this version yet.
        let path = cli.config.as_deref().ok_or_else(|| anyhow::anyhow!("config-diff needs --config <file>"))?;
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let old = against.as_ref().map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))).transpose()?;
        print!("{}", logguard::configdiff::diff(&text, old.as_deref(), &logguard::configdiff::DiffOpts { all: *all })?);
        return Ok(());
    }
    let cfg = Arc::new(Config::load(cli.config.as_deref())?);
    match cli.cmd {
        Cmd::Run => daemon::run(cfg),
        Cmd::Replay { files, year, quiet, verbose, snapshot, top, notify, state } => {
            if files.is_empty() {
                anyhow::bail!("no input files");
            }
            let opts = replay::ReplayOpts { files, year, quiet, verbose, snapshot, top, state };
            let mut ncfg = cfg.notify.clone();
            if ncfg.from.is_empty() {
                ncfg.from = "server".into();
            }
            let mut planner = notify::Planner::new(ncfg, config::Mode::Enforce);
            let mut notices = 0usize;
            let snap = replay::replay(Arc::clone(&cfg), &opts, |a| {
                if !opts.quiet {
                    println!("{}", replay::format_action(a, opts.verbose));
                }
                if notify {
                    for n in planner.plan(a) {
                        notices += 1;
                        println!("    NOTIFY {} | {}\n      {}", n.to, n.subject, n.body.replace('\n', "\n      "));
                    }
                }
            })?;
            if notify {
                println!("\n{notices} notifications would be sent ({} suppressed by the hourly cap)", planner.suppressed);
            }
            replay::print_summary(&snap, opts.top);
            if let Some(path) = &opts.snapshot {
                std::fs::write(path, serde_json::to_vec(&snap)?)?;
                println!("\nsnapshot written to {} (view with: logguard tui --file {})", path.display(), path.display());
            }
            Ok(())
        }
        Cmd::Tui { file, actions } => {
            let source = match file {
                Some(f) => tui::DataSource::File(f),
                None if !actions.is_empty() => {
                    let geo = cfg.geo.enabled.then(|| logguard::geo::GeoDb::load(&cfg.geo.dir).ok()).flatten();
                    tui::DataSource::Actions(actions, geo.map(Arc::new))
                }
                None => tui::DataSource::Socket(cfg.socket.clone()),
            };
            tui::run(source)
        }
        Cmd::NotifyTest { jid, bot, telegram, mail } => {
            let mut ncfg = cfg.notify.clone();
            ncfg.enabled = true;
            ncfg.validate()?;
            if !ncfg.xmpp && !telegram && !mail {
                anyhow::bail!("this node doesn't send XMPP messages ([notify] xmpp = false): use --telegram or --mail");
            }
            let Some(jid) = jid.or_else(|| ncfg.admin_recipients().first().cloned()) else {
                anyhow::bail!("give a JID: [notify] admins is empty")
            };
            let n_to = jid.clone();
            let n = notify::Notice {
                to: jid,
                subject: "logguard test".into(),
                // Two lines, quotes and non-ASCII, like real alerts: ejabberdctl's CTL_OVER_HTTP
                // drops the first two, its /ctl handler garbles the third.
                body: format!("{}\n\"logguard\" line 2 of 2: → ⚠ ✓", logguard::i18n::phrases(ncfg.language_for(&n_to)).test),
            };
            if bot {
                return notify_test_bot(&ncfg, &n);
            }
            if telegram {
                let Some(dir) = ncfg.tg_outbox.clone() else { anyhow::bail!("[notify] tg_outbox is not set") };
                return notify_test_copy(&notify::TG_BOT, dir, &ncfg.tg_user, "tg_user", &n);
            }
            if mail {
                let Some(dir) = ncfg.mail_outbox.clone() else { anyhow::bail!("[notify] mail_outbox is not set") };
                return notify_test_copy(&notify::MAIL_BOT, dir, &ncfg.mail_user, "mail_user", &n);
            }
            notify::send(&ncfg, &n)?;
            println!("sent to {} from {}", n.to, ncfg.from);
            Ok(())
        }
        Cmd::Status { top } => {
            let snap: logguard::engine::Snapshot = serde_json::from_str(&daemon::fetch_snapshot(&cfg.socket)?)?;
            let now = snap.generated;
            println!("mode {:?}, snapshot at {}", snap.mode, logguard::time::fmt_ts(now));
            let lines: Vec<String> = snap
                .last_lines
                .iter()
                .filter(|(s, _)| {
                    cfg.sources.enabled(**s)
                        && !matches!(
                            s,
                            logguard::record::Source::Peer | logguard::record::Source::Kernel | logguard::record::Source::Systemd
                        )
                })
                .map(|(s, t)| format!("{} {} ago", s.name(), logguard::time::fmt_duration(now - t)))
                .collect();
            println!("last log line: {}", if lines.is_empty() { "none yet".into() } else { lines.join(", ") });
            println!("\nactive bans ({}):", snap.bans.len());
            for b in &snap.bans {
                println!(
                    "  {:<22} {:>8} left  #{}  {}",
                    b.net.to_string(),
                    logguard::time::fmt_duration(b.until - now),
                    b.offence,
                    b.reason
                );
            }
            if let Some(c) = &snap.cluster {
                println!(
                    "\ncluster node {} ({} facts known, {} received, {} rejected{}), key {}{}{}:",
                    c.node_id,
                    c.facts_known,
                    c.facts_received,
                    c.rejected,
                    if c.refused_by_limit > 0 { format!(", {} refused by peer_accept", c.refused_by_limit) } else { String::new() },
                    c.key_id,
                    c.key_since.map_or(String::new(), |t| {
                        let days = (now - t) / (86_400 * logguard::time::SEC);
                        let due = cfg.cluster.rotate_after.0 > 0 && now - t >= cfg.cluster.rotate_after.micros();
                        format!(" ({days} days old{})", if due { ", due for rotation" } else { "" })
                    }),
                    if c.extra_key_ids.is_empty() {
                        String::new()
                    } else {
                        format!(", rotation: also accepting {}", c.extra_key_ids.join(", "))
                    }
                );
                for p in &c.peers {
                    let state = match (&p.last_error, p.last_ok) {
                        (Some(e), _) => format!("FAILING: {e}"),
                        (None, Some(t)) => format!("ok, last delivery {}", logguard::time::fmt_ts(t)),
                        _ => "not contacted yet".into(),
                    };
                    println!("  -> {:<28} {state}", p.addr);
                }
                for (node, t) in &c.heard_from {
                    println!("  <- {node:<28} last heard {}", logguard::time::fmt_ts(*t));
                }
            }
            if let Some(r) = &snap.exposure {
                println!(
                    "\nexposed listeners (ufw {}):",
                    match r.ufw_active {
                        Some(true) => "active",
                        Some(false) => "INACTIVE",
                        None => "not found",
                    }
                );
                for (name, l) in logguard::exposure::for_display(&r.listeners).iter().filter(|(_, l)| l.exposure.is_exposed() && !l.dynamic)
                {
                    println!("  {name:<44} {:<16} {}", l.process, l.exposure.describe());
                }
                let dynamic = r.listeners.iter().filter(|l| l.dynamic).count();
                if dynamic > 0 {
                    println!("  + {dynamic} short-lived sockets in allowed port ranges (e.g. TURN relays)");
                }
                for d in &r.dead_rules {
                    println!("  dead ufw rule: {d} (nothing listens)");
                }
            }
            if snap.cron.is_some() || snap.av.is_some() {
                println!("\nhost integrity:");
            }
            if let Some(c) = &snap.cron {
                let state = if c.learning_until > now {
                    format!("learning until {}", logguard::time::fmt_ts(c.learning_until))
                } else {
                    "watching".into()
                };
                println!(
                    "  cron: {state}; {} crontab lines in {} crontabs, {} task files, {} scripts, {} other files",
                    c.lines, c.crontabs, c.tasks, c.scripts, c.files
                );
                for e in &c.errors {
                    println!("  cron: cannot read {e}");
                }
            }
            if let Some(av) = &snap.av {
                match &av.last {
                    Some(s) => println!(
                        "  antivirus: last finished scan {} ({} ago){}, {} infected",
                        logguard::time::fmt_ts(s.end),
                        logguard::time::fmt_duration(now - s.end),
                        s.scanned_files.map(|n| format!(", {n} files")).unwrap_or_default(),
                        s.infections()
                    ),
                    None => println!("  antivirus: no finished scan seen yet in {}", cfg.antivirus.log.display()),
                }
            }
            if let Some(r) = &snap.resources {
                println!("\nresources (read {} ago):", logguard::time::fmt_duration(now - r.read));
                for d in &r.disks {
                    println!(
                        "  disk {:<12} {:>5.1}% free, {} of {} MB ({})",
                        d.mount,
                        d.free_percent(),
                        d.avail_kb / 1024,
                        d.size_kb / 1024,
                        d.paths.join(", ")
                    );
                }
                if let Some(m) = &r.memory {
                    let swap = if m.swap_total_kb == 0 {
                        "no swap".to_string()
                    } else {
                        format!("swap {} of {} MB free", m.swap_free_kb / 1024, m.swap_total_kb / 1024)
                    };
                    let psi = m.psi_full.map_or(String::new(), |p| format!(", stalled {p:.1}% (5 min)"));
                    println!(
                        "  memory            {:>5.1}% available, {} of {} MB, {swap}{psi}",
                        m.avail_percent(),
                        m.avail_kb / 1024,
                        m.total_kb / 1024
                    );
                }
                for e in &r.errors {
                    println!("  cannot read: {e}");
                }
            }
            if !cfg.ratelimit.is_empty() && snap.mode == config::Mode::Enforce {
                println!("\nrate limits (new connections per source address):");
                match enforce::rate_limit_drops(&cfg.enforce.nft, &cfg.enforce.nft_table) {
                    Ok(drops) => {
                        for (i, l) in cfg.ratelimit.iter().enumerate() {
                            let ports: Vec<String> = l.ports.iter().map(|p| p.to_string()).collect();
                            let n = drops.iter().find(|d| d.0 == i).map_or(0, |d| d.1);
                            println!("  {:<24} {:>12} burst {:<4} {n} packets dropped", ports.join(","), l.rate, l.burst);
                        }
                    }
                    Err(e) => println!("  not readable ({e:#}); the ufw fallback has no rate limits"),
                }
            }
            println!("\nrecent alerts:");
            for a in snap.alerts.iter().take(10) {
                println!("  {}", replay::format_action(a, false));
            }
            replay::print_summary(&snap, top);
            Ok(())
        }
        Cmd::Unban { net } => send_control(&cfg, &format!("unban {}", parse_net(&net)?)),
        Cmd::Allow { net, duration, note } => {
            let note = note.unwrap_or_default().replace(['\n', '\r'], " ");
            send_control(&cfg, &format!("allow {} {} {note}", parse_net(&net)?, duration.0))
        }
        Cmd::Disallow { net } => send_control(&cfg, &format!("disallow {}", parse_net(&net)?)),
        Cmd::Allowed => send_control(&cfg, "allowed"),
        Cmd::Feeds { action } if action == "status" => {
            let snap: logguard::engine::Snapshot = serde_json::from_str(&daemon::fetch_snapshot(&cfg.socket)?)?;
            match snap.feeds {
                None if !cfg.feeds.enabled => println!("blocklist feeds are disabled ([feeds] enabled = false)"),
                None => println!("no feed refresh has completed yet"),
                Some(f) => {
                    println!(
                        "{} IPv4 + {} IPv6 networks, {} skipped, refreshed {}, {}",
                        f.v4,
                        f.v6,
                        f.skipped,
                        logguard::time::fmt_ts(f.refreshed),
                        if f.applied { "active in nftables" } else { "NOT applied (shadow mode, ufw backend, or cleared)" }
                    );
                    for s in &f.sources {
                        let state = match (&s.error, s.from_cache) {
                            (Some(e), true) => format!("failed, using cached copy: {e}"),
                            (Some(e), false) => format!("failed: {e}"),
                            _ => "ok".into(),
                        };
                        println!("  {:>6}  {}  {state}", s.entries, s.url);
                    }
                    if let Some(e) = f.error {
                        println!("  note: {e}");
                    }
                }
            }
            Ok(())
        }
        Cmd::Feeds { action } => send_control(&cfg, &format!("feeds {action}")),
        Cmd::Digest { send } => send_control(&cfg, if send { "digest send" } else { "digest" }),
        Cmd::ClusterUfwRules { iptables } => {
            let c = &cfg.cluster;
            if !c.enabled || c.listen.is_empty() {
                return Ok(());
            }
            let port: std::net::SocketAddr = c.listen.parse()?;
            let cluster = logguard::cluster::Cluster::new(c)?;
            for net in cluster.peer_nets() {
                if iptables {
                    let cmd = if net.is_v4() { "iptables" } else { "ip6tables" };
                    println!("{cmd} -I INPUT -p tcp -s {net} --dport {} -j ACCEPT -m comment --comment 'logguard cluster'", port.port());
                } else {
                    println!("ufw allow from {net} to any port {} proto tcp comment 'logguard cluster'", port.port());
                }
            }
            Ok(())
        }
        Cmd::Geo { ips, download } => {
            if download {
                let (done, errors) = logguard::geo::refresh(&cfg.geo, logguard::time::now());
                for d in done {
                    println!("downloaded {d}");
                }
                for e in &errors {
                    eprintln!("download failed: {e}");
                }
            }
            let started = std::time::Instant::now();
            let db = logguard::geo::GeoDb::load(&cfg.geo.dir)?;
            println!("{} ({}, loaded in {:.1?})", cfg.geo.dir.display(), db.summary, started.elapsed());
            for ip in ips {
                println!("{ip:<40} {}", db.label(ip).unwrap_or_else(|| "unknown".into()));
            }
            print!("{}", logguard::geo::attribution(&cfg.geo, true));
            Ok(())
        }
        Cmd::Integrity { scans } => {
            use logguard::cronwatch::{Key, Origin};
            let r = logguard::cronwatch::Scanner::default().scan(&cfg.cron);
            println!("cron watch ({}):", if cfg.cron.enabled { "enabled" } else { "disabled in [cron]" });
            let origin = |p: &str| match r.origins.get(p) {
                Some(Origin::Package(p)) => format!("package {p}"),
                Some(Origin::ModifiedPackage(p)) => format!("package {p}, MODIFIED"),
                Some(Origin::Local) | None => "local".into(),
            };
            for (k, fp) in &r.items {
                match k {
                    Key::Crontab(p) => println!("  crontab {p} ({})", origin(p)),
                    Key::Line(_, l) => println!("      {l}"),
                    Key::Task(p) => println!("  task    {p} ({}) {}", origin(p), fp.chars().take(12).collect::<String>()),
                    Key::Script(p) => {
                        let by = r.script_refs.get(p).map(String::as_str).unwrap_or("");
                        println!("  script  {p} ({}, run from {by}) {}", origin(p), fp.chars().take(12).collect::<String>());
                    }
                    Key::File(p) => println!("  file    {p} ({}) {}", origin(p), fp.chars().take(12).collect::<String>()),
                }
            }
            for e in &r.errors {
                println!("  cannot read {e}");
            }
            println!(
                "\nantivirus log {} ({}):",
                cfg.antivirus.log.display(),
                if cfg.antivirus.enabled { "enabled" } else { "disabled in [antivirus]" }
            );
            let rep = logguard::avscan::Reader::default().read(&cfg.antivirus.log);
            if let Some(e) = &rep.error {
                println!("  {e}");
            }
            let all = rep.scans.unwrap_or_default();
            if all.is_empty() && rep.error.is_none() {
                println!("  no finished scan in the log");
            }
            for s in all.iter().skip(all.len().saturating_sub(scans)) {
                let state = match (s.ok(), s.exit) {
                    (true, _) => "finished".to_string(),
                    (false, Some(c)) => format!("FAILED (exit {c})"),
                    (false, None) => "DID NOT FINISH".to_string(),
                };
                let files = s.scanned_files.map(|n| format!(", {n} files")).unwrap_or_default();
                println!("  {} {state}{files}, {} infected", logguard::time::fmt_ts(s.end), s.infections());
                for i in &s.infected {
                    println!("      {i}");
                }
            }
            Ok(())
        }
        Cmd::AbuseReport { since, ips, min_events, top, all, contacts, json, out, merge } => {
            use logguard::abuse;
            let only = ips.iter().map(|s| parse_net(s)).collect::<Result<Vec<_>>>()?;
            let mut report = if merge.is_empty() {
                let now = logguard::time::now();
                let from = abuse::window_start(now, since);
                let path = cfg.actions_log.clone().context("actions_log is disabled in the config: nothing to report from")?;
                let bans = abuse::load_bans(&path, from)?;
                let offenders = abuse::collect(&bans, &abuse::Filter { only, min_events: 1 });
                let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
                    .map(|h| h.trim().to_string())
                    .unwrap_or_else(|_| "this server".into());
                let addresses = logguard::net::local_addresses().into_iter().filter(|a| !logguard::engine::is_non_global(*a)).collect();
                abuse::Report { servers: vec![abuse::Server { host, addresses }], from, to: now, offenders }
            } else {
                let mut reports = Vec::new();
                for p in &merge {
                    let text = abuse::read_report_file(p)?;
                    reports.push(
                        serde_json::from_str::<abuse::Report>(&text)
                            .with_context(|| format!("{} is not a --json abuse report", p.display()))?,
                    );
                }
                let (mut r, skipped) = abuse::merge(reports);
                for n in skipped {
                    eprintln!("skipped {}: the same report (server and period) is already merged", merge[n].display());
                }
                if !only.is_empty() {
                    r.offenders.retain(|o| only.iter().any(|f| f.contains_net(&o.net) || o.net.contains_net(f)));
                }
                r
            };
            // After merging, so sources seen a little by each server still count in full.
            report.offenders.retain(|o| abuse::events(o) >= min_events.max(1));
            let found = report.offenders.len();
            if !all {
                report.offenders.truncate(top);
            }
            if cfg.geo.enabled {
                if let Ok(db) = logguard::geo::GeoDb::load(&cfg.geo.dir) {
                    for o in report.offenders.iter_mut().filter(|o| o.place.is_none()) {
                        o.place = db.label(o.net.addr);
                    }
                }
            }
            if contacts {
                let missing: Vec<usize> = (0..report.offenders.len()).filter(|i| report.offenders[*i].contact.is_none()).collect();
                let mut todo: Vec<abuse::Offender> = missing.iter().map(|i| report.offenders[*i].clone()).collect();
                // a progress line on a terminal; in the journal (the weekly job) it would be one
                // long "blob" of carriage returns: a summary instead
                use std::io::IsTerminal as _;
                let tty = std::io::stderr().is_terminal();
                let looked_up = todo.len();
                let errors = abuse::add_contacts(&mut todo, &cfg.feeds, |i, n| {
                    if tty {
                        eprint!("\rlooking up abuse contacts {i}/{n} ");
                    }
                });
                if tty {
                    eprintln!();
                } else {
                    eprintln!("looked up abuse contacts of {looked_up} networks");
                }
                for e in errors {
                    eprintln!("abuse contact lookup failed: {e}");
                }
                for (i, o) in missing.into_iter().zip(todo) {
                    report.offenders[i].contact = o.contact;
                }
            }
            let text = if json { serde_json::to_string_pretty(&report)? + "\n" } else { abuse::render_text(&report) };
            match out {
                Some(p) => {
                    std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))?;
                    eprintln!("{} of {found} sources written to {}", report.offenders.len(), p.display());
                }
                None => print!("{text}"),
            }
            if !all && found > report.offenders.len() {
                eprintln!("({} more below the top {top}; --all lists every source)", found - report.offenders.len());
            }
            Ok(())
        }
        Cmd::ClusterKeyId { .. } => {
            let c = &cfg.cluster;
            if !c.enabled {
                anyhow::bail!("[cluster] is not enabled in this configuration");
            }
            let key = c.load_key()?;
            let source = if c.key.is_empty() { c.key_file.display().to_string() } else { "[cluster] key".into() };
            println!("{}  {source}  (sends with it)", logguard::cluster::key_id(&key));
            for (path, k) in c.load_extra_keys()? {
                let note = if k == key { "the same key" } else { "also accepted: key rotation in progress" };
                println!("{}  {}  ({note})", logguard::cluster::key_id(&k), path.display());
            }
            Ok(())
        }
        Cmd::ClusterSendReport { name, peers, file } => {
            if !cfg.cluster.enabled {
                anyhow::bail!("[cluster] is not enabled in this configuration");
            }
            if let Some(p) = peers.iter().find(|p| !cfg.cluster.peers.contains(p)) {
                anyhow::bail!("{p} is not one of [cluster] peers");
            }
            let targets: Vec<&String> = cfg.cluster.peers.iter().filter(|p| peers.is_empty() || peers.contains(p)).collect();
            let content = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let c = logguard::cluster::Cluster::new(&cfg.cluster)?;
            let frame = logguard::cluster::file_frame(c.key(), &c.node_id, &name, &content, logguard::time::now())
                .with_context(|| format!("{} does not fit in one cluster message", file.display()))?;
            let mut failed = 0;
            for peer in &targets {
                match logguard::cluster::send_frame(peer, &frame) {
                    Ok(()) => eprintln!("sent {} ({} bytes, {} on the wire) to {peer}", file.display(), content.len(), frame.len()),
                    Err(e) => {
                        eprintln!("{peer}: {e}");
                        failed += 1;
                    }
                }
            }
            if failed > 0 {
                anyhow::bail!("{failed} of {} peers did not get the file", targets.len());
            }
            Ok(())
        }
        Cmd::ClusterKeygen => {
            println!("{}", logguard::cluster::generate_key());
            Ok(())
        }
        Cmd::PrintConfig => {
            print!("{}", toml::to_string_pretty(&*cfg)?);
            Ok(())
        }
        Cmd::ConfigDiff { .. } => unreachable!("handled before the config is loaded"),
        Cmd::PrintNft => {
            // Exactly what the daemon loads: the allowlist plus cluster peers and this host's
            // own addresses (so `install.sh`'s `nft -c` dry run checks the real thing).
            let mut allow = cfg.allowlist.nets.clone();
            if cfg.cluster.enabled {
                if let Ok(c) = logguard::cluster::Cluster::new(&cfg.cluster) {
                    allow.extend(c.peer_nets());
                }
            }
            allow.extend(logguard::net::local_addresses().into_iter().map(logguard::net::Net::host));
            print!("{}", enforce::nft_setup_script(&cfg.enforce.nft_table, &allow, &cfg.ports.whitelist, &cfg.ratelimit));
            Ok(())
        }
    }
}

/// `notify-test --telegram` and `--mail`: a message through a copy bot's outbox (logguard-tg-bot's,
/// logguard-mail-bot's), waiting for the bot.
fn notify_test_copy(kind: &notify::CopyKind, dir: PathBuf, user: &str, user_key: &str, n: &notify::Notice) -> Result<()> {
    use logguard::botbox::{self, BotBox};
    let unit = kind.unit;
    let owner = std::fs::read_to_string("/etc/passwd").ok().and_then(|p| botbox::user_ids(&p, user));
    anyhow::ensure!(owner.is_some(), "no user {user} ([notify] {user_key}): is {unit} installed?");
    let wait = std::time::Duration::from_secs(60);
    let mut outbox = BotBox::without_fallback(dir, owner, wait);
    anyhow::ensure!(outbox.ready(), "no {unit} outbox {}", outbox.dir.display());
    let path = outbox.put(n, std::time::SystemTime::now())?;
    let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    println!("in {unit}'s outbox: {}", path.display());
    let sending = outbox.dir.join(format!(".{name}.sending"));
    let start = std::time::Instant::now();
    while start.elapsed() < wait {
        if !path.exists() && !sending.exists() {
            println!("{unit} sent it after {:.0?}", start.elapsed());
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    anyhow::bail!("{unit} didn't send it within {wait:?} (its log: /var/log/{unit}/bot.log); it stays in the outbox until {unit} does")
}

/// `notify-test --bot`: a message through the admin bot's outbox, waiting for the bot.
fn notify_test_bot(ncfg: &notify::NotifyCfg, n: &notify::Notice) -> Result<()> {
    use logguard::botbox::{self, BotBox};
    let Some(dir) = ncfg.bot_outbox.clone() else { anyhow::bail!("[notify] bot_outbox is not set") };
    let owner = std::fs::read_to_string("/etc/passwd").ok().and_then(|p| botbox::user_ids(&p, &ncfg.bot_user));
    let grace = std::time::Duration::from_secs(ncfg.bot_grace.0);
    let mut bot = BotBox::new(dir, owner, grace, grace);
    anyhow::ensure!(bot.ready(), "no admin bot outbox {}", bot.dir.display());
    let path = bot.put(n, std::time::SystemTime::now())?;
    let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    println!("in the admin bot's outbox: {}", path.display());
    let start = std::time::Instant::now();
    let state = |s: &str| bot.dir.join(format!(".{name}.{s}"));
    let (sending, rejected, fallback) = (state("sending"), state("rejected"), state("fallback"));
    while start.elapsed() < grace {
        if rejected.exists() {
            anyhow::bail!("the bot refused it: it writes to its own admin (ADMIN_JID) only; the daemon sends it unencrypted");
        }
        if fallback.exists() {
            anyhow::bail!("the bot didn't take it in time; the daemon is sending it unencrypted");
        }
        if !path.exists() && !sending.exists() && !rejected.exists() && !fallback.exists() {
            println!("the bot sent it (OMEMO) after {:.0?}", start.elapsed());
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    anyhow::bail!(
        "the bot didn't send it within {grace:?} (the bot's log: /var/log/logguard-xmpp-bot/bot.log); the running daemon sends it unencrypted"
    )
}
