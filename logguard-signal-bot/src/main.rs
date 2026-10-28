use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use logguard_signal_bot::bot::{self, Bot, Refused};
use logguard_signal_bot::cli::{self, CliConfig, SignalCli};
use logguard_signal_bot::logger;
use logguard_signal_bot::redact::{self, Pseudonyms};
use logguard_signal_bot::seal::Recipient;
use logguard_signal_bot::servers::ServerNames;
use logguard_signal_bot::state::State;

/// Signal bot delivering logguard's admin alerts, daily digest and weekly abuse report to one
/// admin through signal-cli, while the safety number with the admin is the pinned one; else
/// as files encrypted to the admin's OpenPGP key.
///
/// Every option can also come from the environment variable named after it, so config.env
/// works as the unit's EnvironmentFile.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// The signal-cli program: its native build, or the Java build's launcher script.
    #[arg(long, env = "SIGNAL_CLI", default_value = "/usr/local/bin/signal-cli", global = true)]
    signal_cli: PathBuf,
    /// signal-cli's data directory: the bot account's keys and sessions (mode 700, the bot's).
    #[arg(long, env = "SIGNAL_CLI_DATA", default_value = "/opt/logguard-signal-bot/signal-cli", global = true)]
    signal_cli_data: PathBuf,
    /// More arguments for `signal-cli jsonRpc`, separated by blanks.
    #[arg(long, env = "SIGNAL_CLI_ARGS", default_value = "--ignore-attachments --ignore-stories", global = true)]
    signal_cli_args: String,
    /// The bot's Signal account: its phone number, +<country><number>.
    #[arg(long, env = "SIGNAL_ACCOUNT", default_value = "", global = true)]
    account: String,
    /// The admin's Signal phone number (+<country><number>) or ACI: the only one the bot
    /// writes to.
    #[arg(long, env = "ADMIN", default_value = "", global = true)]
    admin: String,
    /// The safety number with the admin, as the Signal app shows it (60 digits; blanks
    /// ignored). Unset, the one first seen is pinned in the state file.
    #[arg(long, env = "ADMIN_SAFETY_NUMBER", global = true)]
    admin_safety_number: Option<String>,
    /// The admin's OpenPGP public key (armored or binary, v4: RSA or Curve25519): while the
    /// safety number isn't the pinned one, messages and files go out encrypted to it, as files.
    /// Without it they wait.
    #[arg(long, env = "OPENPGP_KEY", global = true)]
    openpgp_key: Option<PathBuf>,
    /// The bot's state: the pinned safety number.
    #[arg(long, env = "BOT_STATE_PATH", default_value = "/opt/logguard-signal-bot/state.json", global = true)]
    state_path: PathBuf,
    /// logguard's messages and files for the admin (logguard's `[notify] signal_outbox` and the
    /// abuse report's ABUSE_REPORT_SIGNAL_OUTBOX) [default: outbox next to the state file].
    #[arg(long, env = "OUTBOX_DIR", global = true)]
    outbox_dir: Option<PathBuf>,
    /// Days a file may wait to be sent before it is deleted unsent.
    #[arg(long, env = "OUTBOX_MAX_DAYS", default_value_t = 7, global = true)]
    outbox_max_days: u32,
    /// Hours an alert may wait (bot down, Signal out of reach) before it is dropped unsent.
    #[arg(long, env = "ALERT_MAX_HOURS", default_value_t = 24, global = true)]
    alert_max_hours: u32,
    /// Replace XMPP account names (by pseudonyms) and the servers' own addresses and host names
    /// (by node ids) in alerts, as on Telegram. Off by default: they are end-to-end encrypted.
    #[arg(long, env = "SANITIZE", default_value_t = false, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    sanitize: bool,
    /// With SANITIZE: the XMPP domains, separated by commas or blanks.
    #[arg(long, env = "XMPP_DOMAINS", default_value = "", global = true)]
    xmpp_domains: String,
    /// With SANITIZE: the servers' own addresses and host names, replaced by their node ids:
    /// `xmpp=192.0.2.10,example.org; vpn=192.0.2.20` (subdomains included).
    #[arg(long, env = "SERVER_NAMES", default_value = "", global = true)]
    server_names: String,
    /// With SANITIZE: the pseudonym key [default: pseudonym.key next to the state file]; made
    /// on first start.
    #[arg(long, env = "PSEUDONYM_KEY", global = true)]
    pseudonym_key: Option<PathBuf>,
    /// Log to bot.log here (else to stderr).
    #[arg(long, env = "LOG_DIR", default_value = "/var/log/logguard-signal-bot", global = true)]
    log_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run signal-cli with the bot's data directory and account (`register`, `verify`,
    /// `link`, `listIdentities`, ...), as the bot's user, with the service stopped.
    #[command(name = "signal-cli", trailing_var_arg = true, allow_hyphen_values = true)]
    SignalCli {
        #[arg(required = true)]
        args: Vec<String>,
    },
    /// Print the pseudonym of each account as sanitized alerts show it (reads the key file).
    Pseudonym {
        #[arg(required = true)]
        accounts: Vec<String>,
    },
}

impl Args {
    fn state_dir(&self) -> PathBuf {
        self.state_path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
    }

    fn pseudonyms(&self, create: bool) -> Result<Pseudonyms> {
        let domains = redact::parse_domains(&self.xmpp_domains);
        let path = self.pseudonym_key.clone().unwrap_or_else(|| self.state_dir().join("pseudonym.key"));
        let names = if create { Pseudonyms::load_or_create(&path, domains) } else { Pseudonyms::load(&path, domains) };
        names.map_err(|e| Refused(format!("pseudonym key: {e}")).into())
    }

    fn cli(&self) -> Result<CliConfig> {
        if !cli::valid_number(&self.account) {
            bail!(Refused("SIGNAL_ACCOUNT is not set to a phone number (+<country><number>)".into()));
        }
        Ok(CliConfig {
            program: self.signal_cli.clone(),
            data_dir: self.signal_cli_data.clone(),
            account: self.account.clone(),
            extra: self.signal_cli_args.split_whitespace().map(String::from).collect(),
        })
    }

    fn config(&self) -> Result<bot::Config> {
        if !cli::valid_recipient(&self.admin) {
            bail!(Refused("ADMIN is not set to a phone number (+<country><number>) or an ACI".into()));
        }
        if self.admin == self.account {
            bail!(Refused("ADMIN is the bot's own account".into()));
        }
        if self.alert_max_hours == 0 || self.outbox_max_days == 0 {
            bail!(Refused("ALERT_MAX_HOURS and OUTBOX_MAX_DAYS must be at least 1".into()));
        }
        let admin_safety_number = self.admin_safety_number.as_deref().map(bot::digits).filter(|d| !d.is_empty());
        if admin_safety_number.as_ref().is_some_and(|d| d.len() != 60) {
            bail!(Refused("ADMIN_SAFETY_NUMBER: a safety number has 60 digits".into()));
        }
        let recipient = match &self.openpgp_key {
            Some(path) => {
                let r = Recipient::load(path, chrono::Utc::now().timestamp() as u32).map_err(|e| Refused(format!("OPENPGP_KEY {e}")))?;
                log::info!("the fallback files are encrypted to OpenPGP key {}", r.pretty_fingerprint());
                Some(r)
            }
            None => {
                log::warn!("OPENPGP_KEY is not set: while the safety number isn't the pinned one, messages wait instead of going out as OpenPGP files");
                None
            }
        };
        let sanitize = if self.sanitize {
            let servers = ServerNames::parse(&self.server_names).map_err(|e| Refused(format!("SERVER_NAMES: {e}")))?;
            if servers.is_empty() {
                log::warn!("SANITIZE is on but SERVER_NAMES is empty: only XMPP account names are replaced");
            }
            Some(bot::Sanitize { names: self.pseudonyms(true)?, servers })
        } else {
            log::info!("SANITIZE is off: alerts go out as they are (end-to-end encrypted)");
            None
        };
        Ok(bot::Config {
            admin: self.admin.clone(),
            outbox: self.outbox_dir.clone().unwrap_or_else(|| self.state_dir().join("outbox")),
            outbox_max_age: Duration::from_secs(u64::from(self.outbox_max_days) * 86400),
            alert_max_age: Duration::from_secs(u64::from(self.alert_max_hours) * 3600),
            state_path: self.state_path.clone(),
            admin_safety_number,
            recipient,
            sanitize,
        })
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            log::error!("{e:#}");
            if e.is::<Refused>() {
                ExitCode::from(Refused::EXIT_CODE)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = Args::parse();
    match &args.cmd {
        None => logger::init(&args.log_dir),
        Some(_) => logger::init_stderr(),
    }
    match &args.cmd {
        Some(Cmd::Pseudonym { accounts }) => {
            let names = args.pseudonyms(false)?;
            for a in accounts {
                println!("{a} {}", names.tag(a));
            }
            return Ok(ExitCode::SUCCESS);
        }
        Some(Cmd::SignalCli { args: rest }) => {
            // SAFETY: geteuid has no preconditions
            if unsafe { libc::geteuid() } == 0 {
                bail!("run it as the bot's user, so signal-cli's data stays its own:\n  runuser -u logguard-signal-bot -- /opt/logguard-signal-bot/logguard-signal-bot signal-cli ...");
            }
            // `link` makes the account: it has no number yet
            let with_account = rest.first().map(String::as_str) != Some("link");
            let cfg = if with_account {
                args.cli()?
            } else {
                CliConfig {
                    program: args.signal_cli.clone(),
                    data_dir: args.signal_cli_data.clone(),
                    account: String::new(),
                    extra: vec![],
                }
            };
            let status = cli::passthrough(&cfg, rest, with_account)?;
            return Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8));
        }
        None => {}
    }

    let cli_cfg = args.cli()?;
    let cfg = args.config()?;
    cli::check_data_dir(&cli_cfg.data_dir).map_err(|e| Refused(format!("SIGNAL_CLI_DATA {e}")))?;
    let state = State::load(&args.state_path).map_err(|e| Refused(format!("{}: {e}", args.state_path.display())))?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let (signal_cli, rpc) = SignalCli::start(&cli_cfg).await.map_err(|e| Refused(format!("signal-cli didn't start: {e:#}")))?;
        log::info!(
            "logguard-signal-bot {} as {}; admin {}; outbox {}",
            env!("CARGO_PKG_VERSION"),
            cli_cfg.account,
            cfg.admin,
            cfg.outbox.display()
        );
        let result = bot::run(Bot::new(rpc, cfg, state)).await;
        signal_cli.stop().await;
        result
    })?;
    Ok(ExitCode::SUCCESS)
}
