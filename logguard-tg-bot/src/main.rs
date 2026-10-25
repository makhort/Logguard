use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser, Subcommand};

use logguard_tg_bot::api::Api;
use logguard_tg_bot::bot::{self, Bot, Refused};
use logguard_tg_bot::redact::{self, Pseudonyms};
use logguard_tg_bot::{logger, pair};

/// Telegram bot delivering logguard's admin alerts and daily digest to one admin, with XMPP
/// account names and the servers' addresses replaced, and the weekly abuse report as a file
/// encrypted to the admin's OpenPGP key.
///
/// Every option can also come from the environment variable named after it, so config.env
/// works as the unit's EnvironmentFile.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// The bot's token from @BotFather. Prefer the environment variable or --token-file:
    /// a command-line argument is visible to every user in `ps`.
    #[arg(long, env = "TELEGRAM_TOKEN", hide_env_values = true, global = true)]
    token: Option<String>,
    /// File holding the token (trailing newline ignored).
    #[arg(long, env = "TELEGRAM_TOKEN_FILE", conflicts_with = "token", global = true)]
    token_file: Option<PathBuf>,
    /// The admin's Telegram user id (`logguard-tg-bot pair` finds it): the only chat the bot serves.
    #[arg(long, env = "ADMIN_CHAT_ID", global = true)]
    admin_chat_id: Option<i64>,
    /// The Bot API server: Telegram's, or a local one (http allowed on localhost only).
    #[arg(long, env = "TELEGRAM_API_URL", default_value = "https://api.telegram.org", global = true)]
    api_url: String,
    /// The bot's state: its place in Telegram's update queue, messages to delete.
    #[arg(long, env = "BOT_STATE_PATH", default_value = "/opt/logguard-tg-bot/state.json", global = true)]
    state_path: PathBuf,
    /// logguard's messages and files for the admin (logguard's `[notify] tg_outbox` and the
    /// abuse report's ABUSE_REPORT_TG_OUTBOX) [default: outbox next to the state file].
    #[arg(long, env = "OUTBOX_DIR", global = true)]
    outbox_dir: Option<PathBuf>,
    /// Days a file may wait to be sent before it is deleted unsent.
    #[arg(long, env = "OUTBOX_MAX_DAYS", default_value_t = 7, global = true)]
    outbox_max_days: u32,
    /// Hours an alert may wait (bot down, Telegram out of reach) before it is dropped unsent.
    #[arg(long, env = "ALERT_MAX_HOURS", default_value_t = 24, global = true)]
    alert_max_hours: u32,
    /// The XMPP domains, separated by commas or blanks: a bare user name in an alert
    /// (`ejabberd:alice`) is taken as on the first one. Every address in alerts is replaced.
    #[arg(long, env = "XMPP_DOMAINS", default_value = "", global = true)]
    xmpp_domains: String,
    /// The servers' own addresses and host names, replaced by their node ids in alerts:
    /// `xmpp=11.24.39.236,example.org; vpn=11.32.48.86` (subdomains included).
    #[arg(long, env = "SERVER_NAMES", default_value = "", global = true)]
    server_names: String,
    /// The admin's OpenPGP public key (armored or binary, v4: RSA or Curve25519). Files go out
    /// encrypted to it, as a whole; without it they aren't sent.
    #[arg(long, env = "OPENPGP_KEY", global = true)]
    openpgp_key: Option<PathBuf>,
    /// The pseudonym key [default: pseudonym.key next to the state file]; made on first start.
    #[arg(long, env = "PSEUDONYM_KEY", global = true)]
    pseudonym_key: Option<PathBuf>,
    /// Delete the chat's messages (both sides) after this many hours, 1 to 47 (Telegram lets
    /// bots delete for 48 hours); 0 keeps them.
    #[arg(long, env = "DELETE_AFTER_HOURS", default_value_t = 0, global = true)]
    delete_after_hours: u32,
    /// Ask Telegram clients not to allow forwarding or saving alerts (it also blocks copying
    /// an address out of one). Files are never protected.
    #[arg(long, env = "PROTECT_CONTENT", default_value_t = false, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    protect_content: bool,
    /// Log to bot.log here (else to stderr).
    #[arg(long, env = "LOG_DIR", default_value = "/var/log/logguard-tg-bot", global = true)]
    log_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Find the admin's chat id: prints a code to send to the bot, then ADMIN_CHAT_ID=….
    /// Stop the service first: only one program can read the bot's updates.
    Pair {
        #[arg(long, default_value_t = 10)]
        minutes: u64,
    },
    /// Print the pseudonym of each account as alerts show it (reads the key file).
    Pseudonym {
        #[arg(required = true)]
        accounts: Vec<String>,
    },
}

impl Args {
    fn state_dir(&self) -> PathBuf {
        self.state_path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
    }

    fn token(&self) -> Result<String> {
        let token = match &self.token_file {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
            None => self.token.clone().unwrap_or_default(),
        };
        if token.is_empty() {
            return Err(Refused("no token: set TELEGRAM_TOKEN or TELEGRAM_TOKEN_FILE".into()).into());
        }
        Ok(token)
    }

    fn pseudonyms(&self) -> Result<Pseudonyms> {
        let path = self.pseudonym_key.clone().unwrap_or_else(|| self.state_dir().join("pseudonym.key"));
        Pseudonyms::load_or_create(&path, redact::parse_domains(&self.xmpp_domains))
            .map_err(|e| Refused(format!("pseudonym key: {e}")).into())
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
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

fn run() -> Result<()> {
    let matches = Args::command().get_matches();
    let token_on_command_line = matches.value_source("token") == Some(ValueSource::CommandLine);
    let args = Args::from_arg_matches(&matches)?;
    match &args.cmd {
        None => logger::init(&args.log_dir),
        Some(_) => logger::init_stderr(),
    }
    if token_on_command_line {
        log::warn!("--token on the command line is visible in `ps`; use TELEGRAM_TOKEN or --token-file");
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

    if let Some(Cmd::Pseudonym { accounts }) = &args.cmd {
        let names = args.pseudonyms()?;
        for a in accounts {
            println!("{a} {}", names.tag(a));
        }
        return Ok(());
    }
    let api = Api::new(&args.api_url, &args.token()?).map_err(|e| Refused(format!("Telegram API: {e}")))?;
    if let Some(Cmd::Pair { minutes }) = &args.cmd {
        let id = runtime.block_on(pair::pair(&api, Duration::from_secs(minutes * 60)))?;
        println!("\nADMIN_CHAT_ID={id}\nPut that line in config.env and (re)start the service.");
        return Ok(());
    }

    let Some(admin) = args.admin_chat_id.filter(|&id| id > 0) else {
        bail!(Refused("ADMIN_CHAT_ID is not set to a user id (`logguard-tg-bot pair` finds it)".into()));
    };
    if args.delete_after_hours > 47 {
        bail!(Refused("DELETE_AFTER_HOURS: at most 47 (Telegram lets bots delete messages for 48 hours)".into()));
    }
    if args.alert_max_hours == 0 || args.outbox_max_days == 0 {
        bail!(Refused("ALERT_MAX_HOURS and OUTBOX_MAX_DAYS must be at least 1".into()));
    }
    let names = args.pseudonyms()?;
    let servers = logguard_tg_bot::servers::ServerNames::parse(&args.server_names).map_err(|e| Refused(format!("SERVER_NAMES: {e}")))?;
    if servers.is_empty() {
        log::warn!("SERVER_NAMES is not set: the servers' addresses and host names in alerts go to Telegram as they are");
    }
    let recipient = match &args.openpgp_key {
        Some(path) => {
            let r = logguard_tg_bot::seal::Recipient::load(path, chrono::Utc::now().timestamp() as u32)
                .map_err(|e| Refused(format!("OPENPGP_KEY {e}")))?;
            log::info!("files are encrypted to OpenPGP key {}", r.pretty_fingerprint());
            Some(r)
        }
        None => {
            log::warn!("OPENPGP_KEY is not set: files (the weekly abuse report) are not sent, they go out encrypted only");
            None
        }
    };
    let cfg = bot::Config {
        admin,
        outbox: args.outbox_dir.clone().unwrap_or_else(|| args.state_dir().join("outbox")),
        outbox_max_age: Duration::from_secs(u64::from(args.outbox_max_days) * 86400),
        alert_max_age: Duration::from_secs(u64::from(args.alert_max_hours) * 3600),
        delete_after: (args.delete_after_hours > 0).then(|| Duration::from_secs(u64::from(args.delete_after_hours) * 3600)),
        protect: args.protect_content,
        state_path: args.state_path.clone(),
        servers,
        recipient,
    };
    runtime.block_on(async {
        let me = bot::connect(&api).await?;
        let username = me.username.unwrap_or_default();
        if me.id == admin {
            bail!(Refused("ADMIN_CHAT_ID is the bot's own id".into()));
        }
        log::info!("logguard-tg-bot {} as @{username}; admin chat {admin}; outbox {}", env!("CARGO_PKG_VERSION"), cfg.outbox.display());
        bot::run(Bot::new(api, cfg, names, username)).await
    })
}
