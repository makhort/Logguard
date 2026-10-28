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
        /// Recipient JID (with --telegram, --mail, --signal, --matrix or --xmpp-client: the first
        /// of [notify] admins, if any, when left out).
        #[arg(required_unless_present_any = ["telegram", "mail", "signal", "matrix", "xmpp_client"])]
        jid: Option<String>,
        /// Through the admin bot's outbox ([notify] bot_outbox), OMEMO-encrypted, and wait
        /// until the bot has sent it. One it doesn't take, the running daemon sends unencrypted.
        #[arg(long, conflicts_with_all = ["telegram", "mail", "signal", "matrix", "xmpp_client"])]
        bot: bool,
        /// Only through the Telegram bot's outbox ([notify] tg_outbox), and wait until logguard-tg-bot
        /// has sent it.
        #[arg(long, conflicts_with_all = ["mail", "signal", "matrix", "xmpp_client"])]
        telegram: bool,
        /// Only through the mail bot's outbox ([notify] mail_outbox), and wait until logguard-mail-bot
        /// has sent it.
        #[arg(long, conflicts_with_all = ["signal", "matrix", "xmpp_client"])]
        mail: bool,
        /// Only through the Signal bot's outbox ([notify] signal_outbox), and wait until
        /// logguard-signal-bot has sent it.
        #[arg(long, conflicts_with_all = ["matrix", "xmpp_client"])]
        signal: bool,
        /// Only through the Matrix bot's outbox ([notify] matrix_outbox), and wait until
        /// logguard-matrix-bot has sent it.
        #[arg(long, conflicts_with = "xmpp_client")]
        matrix: bool,
        /// Only through the XMPP client bot's outbox ([notify] xmpp_outbox), and wait until
        /// logguard-xmpp-bot (BOT_MODE=client) has sent it.
        #[arg(long)]
        xmpp_client: bool,
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
    /// Ban an address or network for a while (shared with the cluster peers like a ban
    /// logguard decided). Refused for protected addresses: this host, peers, allowlists.
    Ban {
        net: String,
        /// How long, e.g. 12h, 7d (365d at most).
        #[arg(long = "for", default_value = "1d", value_parser = |s: &str| s.parse::<logguard::time::Dur>())]
        duration: logguard::time::Dur,
        /// Why (shown in the TUI, logs and the peers' messages).
        #[arg(long)]
        note: Option<String>,
    },
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
    /// Addresses WAFs block ([waf]: CrowdSec, ...): status, read the sources now, or clear
    /// (empty the list sets in one step; bans from WAFs stay).
    Waf {
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
    /// Create this node's own signing key for `[cluster] identity_file` (mode 0600; an existing
    /// file is kept) and print its public key, for `[cluster] nodes` on every node.
    ClusterIdentity {
        /// The key file, e.g. /etc/logguard/node.key.
        #[arg(long)]
        out: PathBuf,
    },
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
        #[arg(long, conflicts_with = "firewalld")]
        iptables: bool,
        /// firewall-cmd commands instead (permanent rich rules in the default zone; then
        /// `firewall-cmd --reload`).
        #[arg(long)]
        firewalld: bool,
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
    PrintNft {
        /// Without the kernel tripwire rules (loaded on their own; logguard runs without them
        /// where they are rejected).
        #[arg(long)]
        no_tripwires: bool,
    },
    /// Announce a watched file's coming content, so the integrity watch logs the change
    /// instead of alerting. Installers run it before they replace logguard's binaries and
    /// units: `logguard expect-change /usr/local/bin/logguard=./logguard`.
    ExpectChange {
        /// `PATH=SOURCE` (PATH will get SOURCE's content), or `PATH` (its content as it is now).
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Audit sshd's settings now (as `sshd -T` gives them) for this host's layout: a plain
    /// VPS, a hosting panel, or a gateway like harden-vps.sh's. Read-only; works without the
    /// daemon; run as root.
    SshAudit {
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Also the notes (info), not only high problems and warnings.
        #[arg(short, long)]
        all: bool,
    },
    /// Run the patterns of your own ([[patterns]]) and those of [sources] apps over log lines
    /// (journal JSON, `journalctl` short output, or a log file's lines) and show what each finds.
    TestPattern {
        files: Vec<PathBuf>,
        /// Only this pattern.
        #[arg(long)]
        pattern: Option<String>,
        /// Print every matching line.
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // In the journal at error priority, so a start that fails (a config error) shows in
            // `journalctl -p warning` next to systemd's "Failed to start", not only at info.
            let level = if stderr_is_journal() { "<3>" } else { "" };
            eprintln!("{level}logguard: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Whether stderr is systemd's journal stream (`JOURNAL_STREAM` names its device and inode),
/// which reads a `<N>` prefix as the line's priority. Not so in a terminal, even one whose
/// shell inherited the variable.
fn stderr_is_journal() -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(want) = std::env::var_os("JOURNAL_STREAM") else { return false };
    let Ok(meta) = std::fs::metadata("/proc/self/fd/2") else { return false };
    want.to_str() == Some(format!("{}:{}", meta.dev(), meta.ino()).as_str())
}

fn parse_net(s: &str) -> Result<logguard::net::Net> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn send_control(cfg: &Config, cmd: &str) -> Result<()> {
    let reply = daemon::control_command(&cfg.socket, cmd)?;
    // notes from peers' allowlist entries: nothing that acts on the terminal
    println!("{}", logguard::event::plain_text(reply.trim_end()));
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
    const SIG_DFL: usize = 0;
    // SAFETY: restores the default disposition of one signal before any thread is started.
    unsafe {
        signal(logguard::sys::SIGPIPE, SIG_DFL);
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
    if let Cmd::ClusterIdentity { out } = &cli.cmd {
        // No config needed: run before [cluster] identity_file names the file.
        let (id, new) = logguard::cluster::Identity::create(out)?;
        let name = cli.config.as_deref().and_then(|p| Config::load(Some(p)).ok()).map(|c| c.cluster.node_name());
        eprintln!("{} {}; pin its public key on every node:", if new { "created" } else { "kept the existing key in" }, out.display());
        println!("{} = \"{}\"", name.unwrap_or_else(logguard::cluster::hostname), id.public());
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
                    let geo = cfg.geo.enabled.then(|| logguard::geo::GeoDb::open(&cfg.geo).ok()).flatten();
                    tui::DataSource::Actions(actions, geo.map(Arc::new))
                }
                None => tui::DataSource::Socket(cfg.socket.clone()),
            };
            tui::run(source, cfg.digest.cert_warn_days)
        }
        Cmd::NotifyTest { jid, bot, telegram, mail, signal, matrix, xmpp_client } => {
            let mut ncfg = cfg.notify.clone();
            ncfg.enabled = true;
            ncfg.validate()?;
            if !ncfg.xmpp && !telegram && !mail && !signal && !matrix && !xmpp_client {
                anyhow::bail!(
                    "this node doesn't send XMPP messages ([notify] xmpp = false): use --telegram, --mail, --signal, --matrix or --xmpp-client"
                );
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
            if signal {
                let Some(dir) = ncfg.signal_outbox.clone() else { anyhow::bail!("[notify] signal_outbox is not set") };
                return notify_test_copy(&notify::SIGNAL_BOT, dir, &ncfg.signal_user, "signal_user", &n);
            }
            if matrix {
                let Some(dir) = ncfg.matrix_outbox.clone() else { anyhow::bail!("[notify] matrix_outbox is not set") };
                return notify_test_copy(&notify::MATRIX_BOT, dir, &ncfg.matrix_user, "matrix_user", &n);
            }
            if xmpp_client {
                let Some(dir) = ncfg.xmpp_outbox.clone() else { anyhow::bail!("[notify] xmpp_outbox is not set") };
                return notify_test_copy(&notify::XMPP_BOT, dir, &ncfg.xmpp_user, "xmpp_user", &n);
            }
            notify::send(&ncfg, &n)?;
            println!("sent to {} from {}", n.to, ncfg.from);
            Ok(())
        }
        Cmd::Status { top } => {
            // text from peers and other programs (ban reasons, node names, process names),
            // shown on a terminal without anything that acts on it
            let safe = |s: &str| logguard::event::clean(s, 1000);
            let snap: logguard::engine::Snapshot = serde_json::from_str(&daemon::fetch_snapshot(&cfg.socket)?)?;
            let now = snap.generated;
            let backend =
                snap.backend.as_ref().filter(|_| snap.mode == config::Mode::Enforce).map(|b| format!(" ({b})")).unwrap_or_default();
            println!("mode {:?}{backend}, snapshot at {}", snap.mode, logguard::time::fmt_ts(now));
            let lines: Vec<String> = snap
                .last_lines
                .iter()
                .filter(|(s, _)| {
                    cfg.sources.enabled(**s)
                        && !matches!(
                            s,
                            logguard::record::Source::Peer
                                | logguard::record::Source::Kernel
                                | logguard::record::Source::Systemd
                                | logguard::record::Source::Privilege
                                | logguard::record::Source::Auth
                                | logguard::record::Source::Audit
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
                    safe(&b.reason)
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
                let signs = if c.identity.is_empty() { "signs nothing".to_string() } else { format!("signs as {}", c.identity) };
                println!(
                    "  node identity: {signs}; {} node keys pinned{}{}",
                    c.pinned,
                    if cfg.cluster.require_signatures { ", others refused" } else { "" },
                    if c.refused_signature > 0 {
                        format!("; {} facts refused for their signature", c.refused_signature)
                    } else {
                        String::new()
                    }
                );
                for p in &c.peers {
                    let state = match (&p.last_error, p.last_ok) {
                        (Some(e), _) => format!("FAILING: {}", safe(e)),
                        (None, Some(t)) => format!("ok, last delivery {}", logguard::time::fmt_ts(t)),
                        _ => "not contacted yet".into(),
                    };
                    println!("  -> {:<28} {state}", p.addr);
                }
                for (node, t) in &c.heard_from {
                    println!("  <- {:<28} last heard {}", safe(node), logguard::time::fmt_ts(*t));
                }
            }
            if let Some(r) = &snap.exposure {
                let fw = r.firewall();
                println!("\nexposed listeners (firewall: {}):", r.firewall_summary());
                if fw == logguard::exposure::Firewall::Absent && r.firewall_checked() {
                    println!("  nothing filters incoming traffic: every listener on a public address is reachable");
                }
                for (name, l) in logguard::exposure::for_display(&r.listeners)
                    .iter()
                    .filter(|(_, l)| l.exposure.is_exposed() && !l.dynamic && !l.honeypot)
                {
                    let rule = l.rule_text(fw).map(|r| format!(" [{r}]")).unwrap_or_default();
                    println!("  {name:<44} {:<16} {}{rule}", safe(&l.process), r.describe(l));
                }
                let honeypots: Vec<String> = logguard::exposure::for_display(&r.listeners)
                    .iter()
                    .filter(|(_, l)| l.honeypot)
                    .map(|(name, l)| format!("{name} ({})", r.describe(l)))
                    .collect();
                if !honeypots.is_empty() {
                    println!("  honeypots: {}", honeypots.join(", "));
                }
                let dynamic = r.listeners.iter().filter(|l| l.dynamic).count();
                if dynamic > 0 {
                    println!("  + {dynamic} short-lived sockets in allowed port ranges (e.g. TURN relays)");
                }
                for d in &r.dead_rules {
                    println!("  dead {} rule: {d} (nothing listens)", fw.name());
                }
            }
            if !snap.allow_hosts.is_empty() {
                let list: Vec<String> = snap.allow_hosts.iter().map(|n| n.to_string()).collect();
                println!("\n[allowlist] hosts resolve to: {}", list.join(", "));
            }
            if snap.cron.is_some() || snap.av.is_some() || snap.verify.is_some() || snap.procwatch.is_some() {
                println!("\nhost integrity:");
            }
            if let Some(v) = &snap.verify {
                println!(
                    "  packages: last check {}, {} files match their packages, {} differ; {} set-uid/set-gid programs",
                    logguard::time::fmt_ts(v.last_run),
                    v.checked,
                    v.mismatched,
                    v.suid
                );
            }
            if let Some(p) = &snap.procwatch {
                let state = if p.learning_until > now {
                    format!("learning until {}", logguard::time::fmt_ts(p.learning_until))
                } else {
                    "watching".into()
                };
                println!("  processes: {state}; {} outbound (program, port) pairs known, {} connections now", p.pairs, p.outbound);
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
            if cfg.geoblock.enabled {
                match &snap.geoblock {
                    None => println!("\ngeoblock ({}): waiting for the [geo] databases", cfg.geoblock.describe()),
                    Some(g) => {
                        let state = match (&g.error, g.applied) {
                            (Some(e), _) => format!("NOT loaded: {}", safe(e)),
                            (None, true) => format!("active in {}", snap.backend.as_deref().unwrap_or("the firewall")),
                            (None, false) => "NOT applied (shadow mode, or a backend without it: ufw, iptables)".into(),
                        };
                        println!(
                            "\ngeoblock ({}): {} IPv4 + {} IPv6 networks, computed {}, {state}",
                            g.what,
                            g.v4,
                            g.v6,
                            logguard::time::fmt_ts(g.computed)
                        );
                    }
                }
            }
            if let Some(p) = &snap.patches {
                println!("\npatches (read {} ago): {}", logguard::time::fmt_duration(now - p.read), safe(&p.summary()));
                for e in &p.errors {
                    println!("  cannot read: {}", safe(e));
                }
            }
            if let Some(a) = &snap.ssh_audit {
                println!("\nssh audit (read {} ago): {}", logguard::time::fmt_duration(now - a.read), safe(&a.summary()));
                for i in a.issues.iter().filter(|i| i.severity >= logguard::engine::Severity::Warning) {
                    println!("  {:?}: {}", i.severity, safe(&i.message));
                }
            }
            if !cfg.ratelimit.is_empty() && snap.mode == config::Mode::Enforce {
                println!("\nrate limits (new connections per source address):");
                // only nftables has them (an older daemon doesn't say which backend it uses)
                let backend = snap.backend.as_deref().filter(|b| *b != "nftables");
                match backend.map_or_else(|| enforce::rate_limit_drops(&cfg.enforce.nft, &cfg.enforce.nft_table).map(Some), |_| Ok(None)) {
                    Ok(None) => println!("  none: [[ratelimit]] needs the nftables backend; this daemon uses {}", backend.unwrap_or("?")),
                    Ok(Some(drops)) => {
                        for (i, l) in cfg.ratelimit.iter().enumerate() {
                            let ports: Vec<String> = l.ports.iter().map(|p| p.to_string()).collect();
                            let n = drops.iter().find(|d| d.0 == i).map_or(0, |d| d.1);
                            println!("  {:<24} {:>12} burst {:<4} {n} packets dropped", ports.join(","), l.rate, l.burst);
                        }
                    }
                    Err(e) => println!("  not readable ({e:#}): only the nftables backend has rate limits"),
                }
            }
            println!("\nrecent alerts:");
            for a in snap.alerts.iter().take(10) {
                println!("  {}", safe(&replay::format_action(a, false)));
            }
            replay::print_summary(&snap, top);
            Ok(())
        }
        Cmd::Unban { net } => send_control(&cfg, &format!("unban {}", parse_net(&net)?)),
        Cmd::Ban { net, duration, note } => {
            let note = note.unwrap_or_default().replace(['\n', '\r'], " ");
            send_control(&cfg, &format!("ban {} {} {note}", parse_net(&net)?, duration.0))
        }
        Cmd::ExpectChange { files } => {
            let mut entries = Vec::new();
            for f in &files {
                let (dest, src) = f.split_once('=').unwrap_or((f, f));
                anyhow::ensure!(dest.starts_with('/'), "{dest}: the watched path must be absolute");
                let fp = logguard::cronwatch::fingerprint(std::path::Path::new(src)).with_context(|| format!("reading {src}"))?;
                entries.push((dest.to_string(), fp));
            }
            let path = logguard::cronwatch::expected_path(&cfg.state_file);
            logguard::cronwatch::record_expected(&path, &entries, logguard::time::now())
                .with_context(|| format!("writing {}", path.display()))?;
            Ok(())
        }
        Cmd::TestPattern { files, pattern, verbose } => {
            let mut out = std::io::stdout().lock();
            let patterns: Vec<_> = cfg.all_patterns().cloned().collect();
            if files.is_empty() {
                logguard::parse::custom::test(&patterns, pattern.as_deref(), std::io::stdin().lock(), verbose, &mut out)?;
            }
            for f in &files {
                let file = std::fs::File::open(f).with_context(|| format!("reading {}", f.display()))?;
                let reader: Box<dyn std::io::BufRead> = if f.extension().is_some_and(|e| e == "gz") {
                    Box::new(std::io::BufReader::new(flate2::read::GzDecoder::new(file)))
                } else {
                    Box::new(std::io::BufReader::new(file))
                };
                use std::io::Write as _;
                writeln!(out, "== {}", f.display())?;
                logguard::parse::custom::test(&patterns, pattern.as_deref(), reader, verbose, &mut out)?;
            }
            Ok(())
        }
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
                        if f.applied {
                            format!("active in {}", snap.backend.as_deref().unwrap_or("the firewall"))
                        } else {
                            "NOT applied (shadow mode, a backend without feeds: firewalld, ufw, iptables; or cleared)".into()
                        }
                    );
                    if f.asns > 0 {
                        let how = if f.asn_pending {
                            "not loaded yet: waiting for the [geo] network database".to_string()
                        } else {
                            format!("{} address blocks", f.asn_networks)
                        };
                        println!("  {} networks (ASNs) listed: {how}", f.asns);
                    }
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
        Cmd::Waf { action } if action == "status" => {
            let snap: logguard::engine::Snapshot = serde_json::from_str(&daemon::fetch_snapshot(&cfg.socket)?)?;
            match snap.waf {
                None if !cfg.waf.enabled => println!("[waf] is disabled (enabled = false)"),
                None => println!("no [waf] refresh has completed yet (the first waits for the journal catch-up)"),
                Some(w) => {
                    println!("refreshed {}", logguard::time::fmt_ts(w.refreshed));
                    for s in &w.sources {
                        let state = match (&s.error, s.from_cache) {
                            (Some(e), true) => format!("failed, using the last good copy: {e}"),
                            (Some(e), false) => format!("failed: {e}"),
                            _ => "ok".into(),
                        };
                        let what = match s.action {
                            logguard::waf::WafAction::Ban => format!("{} bans ({} decisions made none)", s.banned, s.skipped),
                            logguard::waf::WafAction::List => "into the list".into(),
                        };
                        let odd = if s.bad + s.ignored > 0 {
                            format!(", {} not understood, {} left out", s.bad, s.ignored)
                        } else {
                            String::new()
                        };
                        println!("  {:<16} {:>6} decisions, {what}{odd}  {state}", s.name, s.decisions);
                    }
                    if w.sources.iter().any(|s| s.action == logguard::waf::WafAction::List) {
                        println!(
                            "  list: {} IPv4 + {} IPv6 networks, {} skipped, {}",
                            w.list_v4,
                            w.list_v6,
                            w.list_skipped,
                            if w.applied {
                                format!("active in {}", snap.backend.as_deref().unwrap_or("the firewall"))
                            } else {
                                "NOT applied (shadow mode, a backend without lists: firewalld, ufw, iptables; empty, or cleared)".into()
                            }
                        );
                    }
                    if let Some(e) = w.error {
                        println!("  note: {e}");
                    }
                }
            }
            Ok(())
        }
        Cmd::Waf { action } => send_control(&cfg, &format!("waf {action}")),
        Cmd::Digest { send } => send_control(&cfg, if send { "digest send" } else { "digest" }),
        Cmd::ClusterUfwRules { iptables, firewalld } => {
            let c = &cfg.cluster;
            if !c.enabled || c.listen.is_empty() {
                return Ok(());
            }
            let port: std::net::SocketAddr = c.listen.parse()?;
            let cluster = logguard::cluster::Cluster::new(c)?;
            for net in cluster.peer_nets() {
                if firewalld {
                    let family = if net.is_v4() { "ipv4" } else { "ipv6" };
                    println!(
                        "firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" source address=\"{net}\" port port=\"{}\" protocol=\"tcp\" accept'",
                        port.port()
                    );
                } else if iptables {
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
            let db = logguard::geo::GeoDb::open(&cfg.geo)?;
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
                if let Ok(db) = logguard::geo::GeoDb::open(&cfg.geo) {
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
            let frame = logguard::cluster::file_frame(c.key(), c.identity(), &c.node_id, &name, &content, logguard::time::now())
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
        Cmd::ClusterIdentity { .. } => unreachable!("handled before loading the config"),
        Cmd::PrintConfig => {
            print!("{}", toml::to_string_pretty(&*cfg)?);
            Ok(())
        }
        Cmd::ConfigDiff { .. } => unreachable!("handled before the config is loaded"),
        Cmd::SshAudit { json, all } => {
            let r = logguard::sshaudit::scan(&cfg.ssh_audit, logguard::time::now());
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
                return Ok(());
            }
            let safe = |s: &str| logguard::event::plain_text(s);
            println!("ssh audit: {}", safe(&r.summary()));
            if let Some(v) = &r.version {
                println!("  {}", safe(v));
            }
            for e in &r.errors {
                println!("  cannot read: {}", safe(e));
            }
            for i in r.issues.iter().filter(|i| all || i.severity >= logguard::engine::Severity::Warning) {
                let sev = format!("{:?}", i.severity).to_lowercase();
                println!("\n{sev:>7}  {}\n         {}", safe(&i.message), safe(&i.id));
                if !i.fix.is_empty() {
                    println!("    fix  {}", safe(&i.fix));
                }
            }
            let notes = r.issues.iter().filter(|i| i.severity < logguard::engine::Severity::Warning).count();
            if !all && notes > 0 {
                println!("\n(+{notes} notes: --all shows them; [ssh_audit] ignore = [\"id\"] hides any)");
            }
            if !cfg.ssh_audit.enabled {
                println!("\n([ssh_audit] is disabled: the daemon doesn't run this)");
            }
            Ok(())
        }
        Cmd::PrintNft { no_tripwires } => {
            // Exactly what the daemon loads: the allowlist plus cluster peers and this host's
            // own addresses (so `install.sh`'s `nft -c` dry run checks the real thing).
            let mut allow = cfg.allowlist.nets.clone();
            if cfg.cluster.enabled {
                if let Ok(c) = logguard::cluster::Cluster::new(&cfg.cluster) {
                    allow.extend(c.peer_nets());
                }
            }
            allow.extend(logguard::net::local_addresses().into_iter().map(logguard::net::Net::host));
            let trip = cfg.ports.kernel_tripwires.then(|| enforce::Trip {
                ports: enforce::trip_ports(&cfg, &enforce::served_tcp_ports()),
                rate: cfg.ports.kernel_tripwire_rate.clone(),
            });
            print!("{}", enforce::nft_setup_script(&cfg.enforce.nft_table, &allow, &cfg.ports.whitelist, &cfg.ratelimit, trip.as_ref()));
            if let Some(t) = trip.as_ref().filter(|_| !no_tripwires) {
                print!("{}", enforce::nft_trip_rules_script(&cfg.enforce.nft_table, t));
            }
            Ok(())
        }
    }
}

/// `notify-test --telegram`, `--mail`, `--signal`, `--matrix` and `--xmpp-client`: a message
/// through a copy bot's outbox (logguard-tg-bot's, logguard-mail-bot's, logguard-signal-bot's,
/// logguard-matrix-bot's, client-mode logguard-xmpp-bot's), waiting for the bot.
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
            let then = if ncfg.admins.contains(&n.to) {
                "the daemon sends it unencrypted"
            } else {
                "the daemon deletes it (it isn't one of [notify] admins)"
            };
            anyhow::bail!("the bot refused it: it writes to its own admin (ADMIN_JID) only; {then}");
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
