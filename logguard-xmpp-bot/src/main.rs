mod commands;
mod ctl;
mod i18n;
mod logger;
mod timefmt;
mod xmpp;

use logguard_xmpp_bot::{omemo, outbox, seal, state};

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser};

/// XMPP bot for logguard. As an admin bot (BOT_MODE=admin), on the XMPP server: curated
/// ejabberdctl commands for the admin and users in a chat, and logguard's alerts and reports
/// for the admin. As a client bot (BOT_MODE=client), on any host and XMPP server: only
/// logguard's alerts, digests and reports for the admin, OMEMO-encrypted, else as files
/// encrypted to the admin's OpenPGP key.
///
/// Every option can also come from the environment variable named after it, so the
/// Python bot's config.env works as an EnvironmentFile unchanged.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Args {
    /// admin: the admin bot on the XMPP server (ejabberdctl, commands for the admin and
    /// users); client: a copy bot like logguard-tg-bot, for logguard's [notify] xmpp_outbox.
    #[arg(long, env = "BOT_MODE", value_enum, default_value_t = BotMode::Admin)]
    mode: BotMode,
    /// The bot's JID; a missing resource becomes "bot".
    #[arg(long, env = "BOT_JID")]
    jid: String,
    /// The bot's password. Prefer the environment variable or --password-file:
    /// a command-line argument is visible to every user in `ps`.
    #[arg(long, env = "BOT_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// File holding the bot's password (trailing newline ignored).
    #[arg(long, env = "BOT_PASSWORD_FILE", conflicts_with = "password")]
    password_file: Option<PathBuf>,
    /// Sort name in the bot's vCard.
    #[arg(long, env = "BOT_NAME", default_value = "logguard")]
    name: String,
    /// The admin's bare JID: the only one with the admin commands (admin mode), the only one
    /// the bot writes to (client mode; on any server).
    #[arg(long, env = "ADMIN_JID")]
    admin: String,
    /// Host to connect to (DNS name or IP). TLS is still verified against the JID's domain.
    /// Unset: the JID's domain, through its SRV records (_xmpp-client, or _xmpps-client
    /// with XMPP_TLS=direct).
    #[arg(long, env = "XMPP_SERVER")]
    server: Option<String>,
    /// The XMPP domain the bot manages accounts of (admin mode) [default: the JID's domain].
    #[arg(long, env = "XMPP_DOMAIN")]
    domain: Option<String>,
    /// [default: 5222, or 5223 with XMPP_TLS=direct; with SRV records only when they fail]
    #[arg(long, env = "XMPP_PORT")]
    port: Option<u16>,
    /// direct: TLS from the first byte (ejabberd's 5223); starttls: plain TCP upgraded
    /// to TLS (5222); auto: direct on port 5223, else starttls. Both verify the certificate.
    #[arg(long, env = "XMPP_TLS", value_enum, default_value_t = Tls::Auto)]
    tls: Tls,
    /// Also log in with SCRAM-SHA-1 when the server offers no SCRAM-SHA-256 (Prosody before
    /// 13 offers only SCRAM-SHA-1). Off: such a server is refused.
    #[arg(long, env = "ALLOW_SCRAM_SHA1", default_value_t = false, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new())]
    allow_scram_sha1: bool,
    /// The JSON state file (same format as the Python bot's; admin mode only). Its directory
    /// holds the OMEMO keys, trust pins and outbox by default in both modes.
    #[arg(long, env = "BOT_STATE_PATH", default_value = "/opt/logguard-xmpp-bot/state.json")]
    state_path: PathBuf,
    #[arg(long, env = "ORG_NAME")]
    org_name: Option<String>,
    /// Picture for the bot's avatar (PNG, JPEG, GIF, WebP, BMP or TIFF).
    #[arg(long, env = "AVATAR_PATH")]
    avatar_path: Option<PathBuf>,
    #[arg(long, env = "EJABBERDCTL", default_value = "/usr/sbin/ejabberdctl")]
    ejabberdctl: PathBuf,
    /// ejabberd's SQLite database (`sql_database` in ejabberd.yml), read-only: /export
    /// sends its rows about the user as an encrypted JSON file. Unset: text summary only.
    #[arg(long, env = "EJABBERD_DB")]
    ejabberd_db: Option<PathBuf>,
    #[arg(long, env = "SQLITE3", default_value = "/usr/bin/sqlite3")]
    sqlite3: PathBuf,
    /// Languages of server announcements (/maintenance, /restart, /warn), in order:
    /// EN, FR, GE (or DE), PL, RU, UA (or UK), separated by commas or blanks.
    #[arg(long, env = "ANNOUNCE_LANGUAGES", default_value = "EN,FR,RU,UK")]
    announce_languages: String,
    /// When the bot runs as root, ejabberdctl and openssl run as this user (the one ejabberd
    /// runs as), so the script never has to switch users itself.
    #[arg(long, env = "EJABBERD_USER", default_value = "ejabberd")]
    ejabberd_user: String,
    /// mod_invites' web page, given by /invite [default: https://<domain>:5281/invites].
    #[arg(long, env = "INVITE_URL")]
    invite_url: Option<String>,
    /// OMEMO end-to-end encryption: off; on (encrypted and plain commands); required
    /// (plain commands refused).
    #[arg(long, env = "OMEMO", value_enum, default_value_t = OmemoMode::On)]
    omemo: OmemoMode,
    /// The bot's OMEMO keys and sessions [default: omemo.json next to the state file].
    #[arg(long, env = "OMEMO_STORE")]
    omemo_store: Option<PathBuf>,
    /// Pinned OMEMO keys, `<jid> <fingerprint>` per line [default: omemo-trust.txt next
    /// to the state file]. A JID without pins is trusted on any key.
    #[arg(long, env = "OMEMO_TRUST_FILE")]
    omemo_trust_file: Option<PathBuf>,
    /// blind: a JID without pins is trusted on any key; pinned: only pinned keys are.
    #[arg(long, env = "OMEMO_TRUST", value_enum, default_value_t = OmemoTrust::Blind)]
    omemo_trust: OmemoTrust,
    /// Days the archive, offline messages and push registrations are kept (/privacy;
    /// cleanup_db.sh's MAX_DAYS).
    #[arg(long, env = "RETENTION_MESSAGE_DAYS", default_value_t = 21)]
    retention_message_days: u32,
    /// Days uploaded files are kept (/privacy; mod_http_upload_quota's max_days).
    #[arg(long, env = "RETENTION_FILE_DAYS", default_value_t = 7)]
    retention_file_days: u32,
    /// Largest upload in MB (/privacy; mod_http_upload's max_size).
    #[arg(long, env = "UPLOAD_MAX_MB", default_value_t = 500)]
    upload_max_mb: u32,
    /// Days without a login before an account is deleted (/privacy; USER_EXPIRATION_DAYS).
    #[arg(long, env = "RETENTION_ACCOUNT_DAYS", default_value_t = 90)]
    retention_account_days: u32,
    /// Days before an unused group chat is deleted (/privacy; MUC_UNUSED_DAYS).
    #[arg(long, env = "RETENTION_ROOM_DAYS", default_value_t = 90)]
    retention_room_days: u32,
    /// Days the bot keeps abuse reports (/privacy).
    #[arg(long, env = "ABUSE_REPORT_DAYS", default_value_t = 90)]
    abuse_report_days: u32,
    /// Days security records are kept (/privacy; logguard's actions.jsonl: weekly × 12).
    #[arg(long, env = "SECURITY_RECORD_DAYS", default_value_t = 84)]
    security_record_days: u32,
    /// Files to send to the admin, encrypted (OMEMO media sharing over HTTP File Upload):
    /// logguard's weekly abuse report [default: outbox next to the state file]. Each is
    /// deleted once sent.
    #[arg(long, env = "OUTBOX_DIR")]
    outbox_dir: Option<PathBuf>,
    /// Days an outbox file may wait to be sent (no trusted admin device, upload failing)
    /// before it is deleted unsent.
    #[arg(long, env = "OUTBOX_MAX_DAYS", default_value_t = 7)]
    outbox_max_days: u32,
    /// The HTTP File Upload service (XEP-0363) [default: found with disco on the domain].
    #[arg(long, env = "UPLOAD_SERVICE")]
    upload_service: Option<String>,
    /// Client mode: the admin's OpenPGP public key (armored or binary, v4: RSA or Curve25519).
    /// When OMEMO can't reach the admin, messages and files go out encrypted to it, as files.
    /// Without it they wait.
    #[arg(long, env = "OPENPGP_KEY")]
    openpgp_key: Option<PathBuf>,
    /// Client mode: hours an alert may wait (offline, no way to encrypt it) before it is
    /// dropped unsent.
    #[arg(long, env = "ALERT_MAX_HOURS", default_value_t = 24)]
    alert_max_hours: u32,
    /// Log here as well as to stderr.
    #[arg(long, env = "LOG_DIR", default_value = "/var/log/logguard-xmpp-bot")]
    log_dir: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum BotMode {
    Admin,
    Client,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum OmemoMode {
    Off,
    On,
    Required,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum OmemoTrust {
    Blind,
    Pinned,
}

/// A setting that restarting will not fix; exits with the code the unit doesn't restart.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum Tls {
    Auto,
    Direct,
    Starttls,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e:#}");
            if e.is::<xmpp::LoginRefused>() || e.is::<ConfigError>() {
                ExitCode::from(xmpp::LoginRefused::EXIT_CODE)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result<()> {
    let matches = Args::command().get_matches();
    let password_on_command_line = matches.value_source("password") == Some(ValueSource::CommandLine);
    let mut args = Args::from_arg_matches(&matches)?;

    logger::init(&args.log_dir);
    if password_on_command_line {
        log::warn!("--password on the command line is visible in `ps`; use BOT_PASSWORD or --password-file");
    }
    if let Some(path) = &args.password_file {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        args.password = Some(s.trim_end_matches(['\r', '\n']).to_string());
    }
    if args.password.as_deref().is_none_or(str::is_empty) {
        bail!("no password: give --password-file or set BOT_PASSWORD");
    }

    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(xmpp::run(args))
}
