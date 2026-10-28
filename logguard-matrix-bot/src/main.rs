use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use logguard_matrix_bot::api::{self, Api};
use logguard_matrix_bot::bot::{self, Bot, Refused};
use logguard_matrix_bot::redact::{self, Pseudonyms};
use logguard_matrix_bot::seal::Recipient;
use logguard_matrix_bot::servers::ServerNames;
use logguard_matrix_bot::state::State;
use logguard_matrix_bot::{logger, login};

/// Matrix bot delivering logguard's admin alerts, daily digest and weekly abuse report to
/// one admin, end-to-end encrypted (Olm/Megolm) to the devices the admin verified; when that
/// isn't possible, as files encrypted to the admin's OpenPGP key.
///
/// Every option can also come from the environment variable named after it, so config.env
/// works as the unit's EnvironmentFile.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// The homeserver's client URL (https; http only to localhost), e.g.
    /// https://matrix-client.matrix.org for matrix.org.
    #[arg(long, env = "MATRIX_HOMESERVER", default_value = "", global = true)]
    homeserver: String,
    /// The bot's account, for `login`: @name:server (or the bare name).
    #[arg(long, env = "MATRIX_USER", default_value = "", global = true)]
    user: String,
    /// The admin's Matrix user id (@name:server): the only one the bot writes to.
    #[arg(long, env = "ADMIN", default_value = "", global = true)]
    admin: String,
    /// The admin's master cross-signing key (unpadded base64, as the bot logs it): only devices
    /// it verifies get the room keys. Unset, the key first seen is pinned in the state file.
    #[arg(long, env = "ADMIN_MASTER_KEY", global = true)]
    admin_master_key: Option<String>,
    /// End-to-end encryption; off sends every message and file as an OpenPGP file.
    #[arg(long, env = "E2EE", default_value_t = true, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    e2ee: bool,
    /// The admin's OpenPGP public key (armored or binary, v4: RSA or Curve25519): messages and
    /// files go out encrypted to it, as files, when end-to-end encryption isn't possible.
    /// Without it they wait.
    #[arg(long, env = "OPENPGP_KEY", global = true)]
    openpgp_key: Option<PathBuf>,
    /// The bot's state: its login, device keys and sessions, the room, the admin's pinned keys.
    #[arg(long, env = "BOT_STATE_PATH", default_value = "/opt/logguard-matrix-bot/state.json", global = true)]
    state_path: PathBuf,
    /// logguard's messages and files for the admin (logguard's `[notify] matrix_outbox` and the
    /// abuse report's ABUSE_REPORT_MATRIX_OUTBOX) [default: outbox next to the state file].
    #[arg(long, env = "OUTBOX_DIR", global = true)]
    outbox_dir: Option<PathBuf>,
    /// Days a file may wait to be sent before it is deleted unsent.
    #[arg(long, env = "OUTBOX_MAX_DAYS", default_value_t = 7, global = true)]
    outbox_max_days: u32,
    /// Hours an alert may wait (bot down, homeserver out of reach) before it is dropped unsent.
    #[arg(long, env = "ALERT_MAX_HOURS", default_value_t = 24, global = true)]
    alert_max_hours: u32,
    /// Replace XMPP account names (by pseudonyms) and the servers' own addresses and host names
    /// (by node ids) in alerts, as on Telegram. Off by default: they are end-to-end encrypted.
    #[arg(long, env = "SANITIZE", default_value_t = false, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    sanitize: bool,
    /// With SANITIZE: the XMPP domains, separated by commas or blanks; a bare user name in an
    /// alert (`ejabberd:alice`) is taken as on the first one.
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
    #[arg(long, env = "LOG_DIR", default_value = "/var/log/logguard-matrix-bot", global = true)]
    log_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Log the bot account in on a new device (the previous one is logged out), publish its
    /// keys and sign it with the account's cross-signing keys (made on the first login).
    /// Run it as the bot's user, with the service stopped; it asks for the password.
    Login {
        /// Read the password from this file instead (first line).
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Replace cross-signing keys the account already has (made in another client).
        #[arg(long)]
        reset_cross_signing: bool,
    },
    /// Print the bot's device, its keys and the admin's pinned keys, from the state file.
    Info,
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

    fn pseudonym_key(&self) -> PathBuf {
        self.pseudonym_key.clone().unwrap_or_else(|| self.state_dir().join("pseudonym.key"))
    }

    fn pseudonyms(&self, create: bool) -> Result<Pseudonyms> {
        let domains = redact::parse_domains(&self.xmpp_domains);
        let path = self.pseudonym_key();
        let names = if create { Pseudonyms::load_or_create(&path, domains) } else { Pseudonyms::load(&path, domains) };
        names.map_err(|e| Refused(format!("pseudonym key: {e}")).into())
    }

    fn sanitize(&self) -> Result<Option<bot::Sanitize>> {
        if !self.sanitize {
            log::info!("SANITIZE is off: alerts go out as they are (encrypted)");
            return Ok(None);
        }
        let servers = ServerNames::parse(&self.server_names).map_err(|e| Refused(format!("SERVER_NAMES: {e}")))?;
        if servers.is_empty() {
            log::warn!("SANITIZE is on but SERVER_NAMES is empty: only XMPP account names are replaced");
        } else {
            log::info!("SANITIZE is on: XMPP account names and the servers' addresses are replaced in alerts");
        }
        Ok(Some(bot::Sanitize { names: self.pseudonyms(true)?, servers }))
    }

    fn api(&self) -> Result<Api> {
        if self.homeserver.is_empty() {
            bail!(Refused("MATRIX_HOMESERVER is not set".into()));
        }
        Api::new(&self.homeserver, None).map_err(|e| Refused(format!("MATRIX_HOMESERVER: {e}")).into())
    }

    fn config(&self) -> Result<bot::Config> {
        if !api::valid_user_id(&self.admin) {
            bail!(Refused("ADMIN is not set to a Matrix user id (@name:server)".into()));
        }
        if self.alert_max_hours == 0 || self.outbox_max_days == 0 {
            bail!(Refused("ALERT_MAX_HOURS and OUTBOX_MAX_DAYS must be at least 1".into()));
        }
        let admin_master_key = self.admin_master_key.clone().filter(|k| !k.trim().is_empty()).map(|k| k.trim().to_string());
        if let Some(k) = &admin_master_key {
            vodozemac::Ed25519PublicKey::from_base64(k).map_err(|_| Refused("ADMIN_MASTER_KEY is not an Ed25519 key in base64".into()))?;
        }
        let recipient = match &self.openpgp_key {
            Some(path) => {
                let r = Recipient::load(path, chrono::Utc::now().timestamp() as u32).map_err(|e| Refused(format!("OPENPGP_KEY {e}")))?;
                log::info!("the fallback files are encrypted to OpenPGP key {}", r.pretty_fingerprint());
                Some(r)
            }
            None if !self.e2ee => bail!(Refused("E2EE=off needs OPENPGP_KEY: the bot sends nothing in clear".into())),
            None => {
                log::warn!("OPENPGP_KEY is not set: when end-to-end encryption isn't possible, messages wait instead of going out as OpenPGP files");
                None
            }
        };
        Ok(bot::Config {
            admin: self.admin.clone(),
            outbox: self.outbox_dir.clone().unwrap_or_else(|| self.state_dir().join("outbox")),
            outbox_max_age: Duration::from_secs(u64::from(self.outbox_max_days) * 86400),
            alert_max_age: Duration::from_secs(u64::from(self.alert_max_hours) * 3600),
            state_path: self.state_path.clone(),
            e2ee: self.e2ee,
            admin_master_key,
            recipient,
            sanitize: self.sanitize()?,
        })
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
    let args = Args::parse();
    match &args.cmd {
        None => logger::init(&args.log_dir),
        Some(_) => logger::init_stderr(),
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    match &args.cmd {
        Some(Cmd::Pseudonym { accounts }) => {
            let names = args.pseudonyms(false)?;
            for a in accounts {
                println!("{a} {}", names.tag(a));
            }
            return Ok(());
        }
        Some(Cmd::Info) => return info(&args),
        Some(Cmd::Login { password_file, reset_cross_signing }) => {
            // SAFETY: geteuid has no preconditions
            if unsafe { libc::geteuid() } == 0 {
                bail!(
                    "run login as the bot's user, so the state file stays its own:\n  runuser -u logguard-matrix-bot -- sh -c 'set -a; . /opt/logguard-matrix-bot/config.env; exec /opt/logguard-matrix-bot/logguard-matrix-bot login'"
                );
            }
            if args.user.is_empty() {
                bail!("MATRIX_USER is not set: the bot's account (@name:server)");
            }
            let password = match password_file {
                Some(p) => std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                None => rpassword::prompt_password(format!("Password of {}: ", args.user))?,
            };
            let api = args.api()?;
            let mut approve = |text: &str| {
                eprintln!("{text}");
                let _ = std::io::stdin().read_line(&mut String::new());
            };
            runtime.block_on(login::login(&api, &args.state_path, &args.user, &password, *reset_cross_signing, &mut approve))?;
            println!();
            return info(&args);
        }
        None => {}
    }

    let api = args.api()?;
    let cfg = args.config()?;
    let state = State::load(&args.state_path).map_err(|e| Refused(format!("{}: {e}", args.state_path.display())))?;
    let mut bot = Bot::new(api, cfg, state)?;
    if bot.login.user_id == bot.cfg.admin {
        bail!(Refused("ADMIN is the bot's own account".into()));
    }
    if !bot.state.device_signed {
        log::warn!(
            "the bot's device isn't signed by the account's cross-signing keys: clients mark its messages as from an unverified device"
        );
    }
    log::info!(
        "logguard-matrix-bot {} as {} (device {}, Ed25519 {}); admin {}; outbox {}",
        env!("CARGO_PKG_VERSION"),
        bot.login.user_id,
        bot.login.device_id,
        bot.fingerprint(),
        bot.cfg.admin,
        bot.cfg.outbox.display()
    );
    runtime.block_on(async {
        bot::connect(&mut bot).await?;
        bot::run(bot).await
    })
}

/// `info`: the state file, for comparing keys with what a client shows.
fn info(args: &Args) -> Result<()> {
    let state = State::load(&args.state_path).with_context(|| format!("reading {}", args.state_path.display()))?;
    let Some(login) = &state.login else {
        println!("Not logged in yet (logguard-matrix-bot login).");
        return Ok(());
    };
    println!("Bot account:        {}", login.user_id);
    println!("Device:             {} (\"{}\")", login.device_id, login::DEVICE_NAME);
    if let Some(a) = state.account {
        let a = vodozemac::olm::Account::from_pickle(a);
        println!("Device Ed25519 key: {}   (the session key clients show)", a.ed25519_key().to_base64());
    }
    println!("Device keys:        {}", if state.keys_published { "published" } else { "not published yet" });
    match &state.master_key {
        Some(m) => {
            println!("Cross-signing:      master key {m}; this device {}", if state.device_signed { "signed" } else { "NOT signed" })
        }
        None => println!("Cross-signing:      none (the device is unverified for clients)"),
    }
    println!("Room:               {}", state.room.as_deref().unwrap_or("not made yet"));
    match &state.admin_master {
        Some(m) => println!("Admin master key:   {m} (pinned)"),
        None => println!("Admin master key:   not seen yet"),
    }
    for (id, key) in &state.admin_devices {
        println!("Admin device:       {id} (Ed25519 {key})");
    }
    if let Some(o) = &state.outbound {
        let age = chrono::Utc::now().timestamp() - o.created;
        println!("Megolm session:     {} message(s), {} h old, key on {} device(s)", o.sent, age / 3600, o.shared.len());
    }
    Ok(())
}
