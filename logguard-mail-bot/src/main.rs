use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser, Subcommand};

use logguard_mail_bot::bot::{self, Bot, Refused};
use logguard_mail_bot::mime::{self, Content, Sender};
use logguard_mail_bot::redact::{self, Pseudonyms};
use logguard_mail_bot::seal::{self, Recipients, Signer};
use logguard_mail_bot::servers::ServerNames;
use logguard_mail_bot::smtp::{self, Outgoing, Smtp};
use logguard_mail_bot::{logger, outbox};

/// Send-only mail bot for logguard: its admin alerts, daily digest and weekly abuse report
/// to the admins' mailboxes, each mail OpenPGP-encrypted as a whole (PGP/MIME, the subject
/// too), through a mail server over SMTP: the local Postfix, or any other with TLS.
///
/// Every option can also come from the environment variable named after it, so config.env
/// works as the unit's EnvironmentFile.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// The mail server: a host name, or an address (127.0.0.1 for the local Postfix).
    #[arg(long, env = "SMTP_HOST", default_value = "127.0.0.1", global = true)]
    smtp_host: String,
    /// The port [default: 465 with tls, 587 with starttls, 25 with none].
    #[arg(long, env = "SMTP_PORT", global = true)]
    smtp_port: Option<u16>,
    /// tls (TLS from the start, "SMTPS"), starttls (required, never falling back to plain), or
    /// none (only to a mail server on this host).
    #[arg(long, env = "SMTP_TLS", default_value = "starttls", global = true)]
    smtp_tls: smtp::TlsMode,
    /// The name the server's certificate must carry [default: SMTP_HOST].
    #[arg(long, env = "SMTP_TLS_NAME", global = true)]
    smtp_tls_name: Option<String>,
    /// Trust only this CA certificate (PEM) for the server, not the system's CA store: for a
    /// server with a certificate of its own CA.
    #[arg(long, env = "SMTP_CA_FILE", global = true)]
    smtp_ca_file: Option<PathBuf>,
    /// auto (PLAIN or LOGIN, whichever the server offers, if SMTP_USER is set), plain, login,
    /// or none.
    #[arg(long, env = "SMTP_AUTH", default_value = "auto", global = true)]
    smtp_auth: smtp::Auth,
    #[arg(long, env = "SMTP_USER", default_value = "", global = true)]
    smtp_user: String,
    /// Prefer SMTP_PASSWORD_FILE: a command-line argument is visible to every user in `ps`.
    #[arg(long, env = "SMTP_PASSWORD", hide_env_values = true, global = true)]
    smtp_password: Option<String>,
    /// File holding the password (trailing newline ignored).
    #[arg(long, env = "SMTP_PASSWORD_FILE", conflicts_with = "smtp_password", global = true)]
    smtp_password_file: Option<PathBuf>,
    /// Seconds to wait for the server at each step.
    #[arg(long, env = "SMTP_TIMEOUT_SECS", default_value_t = 30, global = true)]
    smtp_timeout_secs: u64,
    /// The name given in EHLO [default: MAIL_FROM's domain].
    #[arg(long, env = "HELO_NAME", global = true)]
    helo_name: Option<String>,
    /// The sender address (also the envelope sender: bounces go there).
    #[arg(long, env = "MAIL_FROM", global = true)]
    mail_from: Option<String>,
    /// The sender's display name (plain ASCII).
    #[arg(long, env = "FROM_NAME", default_value = "logguard", global = true)]
    from_name: String,
    /// The recipients, separated by commas or blanks: every mail goes to all of them.
    #[arg(long, env = "MAIL_TO", default_value = "", global = true)]
    mail_to: String,
    /// The recipients' OpenPGP public keys (armored or binary, one file, one or more v4 keys:
    /// RSA or Curve25519). Each recipient's key is the one whose user id has their address
    /// (with a single key: that one). Required: nothing goes out unencrypted.
    #[arg(long, env = "OPENPGP_KEY", global = true)]
    openpgp_key: Option<PathBuf>,
    /// The bot's own secret key (`logguard-mail-bot keygen` makes it): mails are signed with it,
    /// and it goes out in an Autocrypt header. Unset: mails are encrypted, not signed.
    #[arg(long, env = "SIGNING_KEY", global = true)]
    signing_key: Option<PathBuf>,
    /// Replace XMPP account names (by pseudonyms) and the servers' own addresses and host names
    /// (by node ids) in alerts and digests, as logguard-tg-bot does for Telegram. Off by
    /// default: the mails are encrypted end to end. Files (the weekly report) are never changed.
    #[arg(long, env = "SANITIZE", default_value_t = false, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    sanitize: bool,
    /// With SANITIZE: the XMPP domains, separated by commas or blanks; a bare user name in an
    /// alert (`ejabberd:alice`) is taken as on the first one. Every address is replaced anyway.
    #[arg(long, env = "XMPP_DOMAINS", default_value = "", global = true)]
    xmpp_domains: String,
    /// With SANITIZE: the servers' own addresses and host names, replaced by their node ids:
    /// `xmpp=11.25.39.236,example.org; vpn=11.33.48.86` (subdomains included).
    #[arg(long, env = "SERVER_NAMES", default_value = "", global = true)]
    server_names: String,
    /// With SANITIZE: the pseudonym key, made on first start.
    #[arg(long, env = "PSEUDONYM_KEY", default_value = "/opt/logguard-mail-bot/pseudonym.key", global = true)]
    pseudonym_key: PathBuf,
    /// The subject mail servers see (the real one is encrypted inside).
    #[arg(long, env = "OUTER_SUBJECT", default_value = mime::PLACEHOLDER_SUBJECT, global = true)]
    outer_subject: String,
    /// logguard's messages and files for the admins (logguard's `[notify] mail_outbox` and the
    /// abuse report's ABUSE_REPORT_MAIL_OUTBOX).
    #[arg(long, env = "OUTBOX_DIR", default_value = "/opt/logguard-mail-bot/outbox", global = true)]
    outbox_dir: PathBuf,
    /// Days a file may wait to be sent before it is deleted unsent.
    #[arg(long, env = "OUTBOX_MAX_DAYS", default_value_t = 7, global = true)]
    outbox_max_days: u32,
    /// Hours an alert may wait (bot down, mail server out of reach) before it is dropped unsent.
    #[arg(long, env = "ALERT_MAX_HOURS", default_value_t = 24, global = true)]
    alert_max_hours: u32,
    /// Log to bot.log here (else to stderr).
    #[arg(long, env = "LOG_DIR", default_value = "/var/log/logguard-mail-bot", global = true)]
    log_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Check the settings and keys, connect to the mail server and log in; send nothing.
    Check,
    /// Send a test mail now, as the service would (not through the outbox).
    SendTest,
    /// Make the bot's signing key (Ed25519) for MAIL_FROM: the secret key to OUT (mode 0600,
    /// never overwritten), the public key to OUT.pub.asc and stdout.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the pseudonym of each account as sanitized alerts show it (reads the key file).
    Pseudonym {
        #[arg(required = true)]
        accounts: Vec<String>,
    },
}

struct Setup {
    from: Sender,
    to: Vec<String>,
    smtp: smtp::Settings,
}

impl Args {
    fn from(&self) -> Result<Sender> {
        let Some(address) = self.mail_from.clone().filter(|a| !a.is_empty()) else {
            bail!(Refused("MAIL_FROM is not set".into()));
        };
        if !mime::valid_address(&address) {
            bail!(Refused(format!("MAIL_FROM '{address}' is not a plain mail address (local@domain)")));
        }
        if !mime::valid_name(&self.from_name) {
            bail!(Refused("FROM_NAME: plain ASCII without quotes or backslashes, at most 64 characters".into()));
        }
        Ok(Sender { name: self.from_name.clone(), address })
    }

    fn setup(&self) -> Result<Setup> {
        let from = self.from()?;
        let mut to: Vec<String> = Vec::new();
        for a in self.mail_to.split([',', ' ', '\t', '\n', ';']).filter(|a| !a.is_empty()) {
            if !to.iter().any(|t| t.eq_ignore_ascii_case(a)) {
                to.push(a.to_string());
            }
        }
        if to.is_empty() {
            bail!(Refused("MAIL_TO is not set".into()));
        }
        if let Some(bad) = to.iter().find(|a| !mime::valid_address(a)) {
            bail!(Refused(format!("MAIL_TO: '{bad}' is not a plain mail address (local@domain)")));
        }
        let password = match &self.smtp_password_file {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
            None => self.smtp_password.clone().unwrap_or_default(),
        };
        let domain = from.address.rsplit_once('@').map_or("localhost", |(_, d)| d).to_string();
        let smtp = smtp::Settings {
            host: self.smtp_host.clone(),
            port: self.smtp_port.unwrap_or(self.smtp_tls.default_port()),
            tls: self.smtp_tls,
            tls_name: self.smtp_tls_name.clone().unwrap_or_else(|| self.smtp_host.trim_matches(['[', ']']).to_string()),
            ca_file: self.smtp_ca_file.clone(),
            auth: self.smtp_auth,
            user: self.smtp_user.clone(),
            password,
            helo: self.helo_name.clone().unwrap_or(domain),
            timeout: Duration::from_secs(self.smtp_timeout_secs.max(1)),
        };
        smtp.validate().map_err(Refused)?;
        if self.alert_max_hours == 0 || self.outbox_max_days == 0 {
            bail!(Refused("ALERT_MAX_HOURS and OUTBOX_MAX_DAYS must be at least 1".into()));
        }
        if self.outer_subject.trim().is_empty() || !self.outer_subject.is_ascii() || self.outer_subject.chars().any(|c| c.is_control()) {
            bail!(Refused("OUTER_SUBJECT: one line of plain ASCII".into()));
        }
        Ok(Setup { from, to, smtp })
    }

    fn keys(&self, setup: &Setup) -> Result<(Recipients, Option<Signer>)> {
        let Some(path) = &self.openpgp_key else {
            bail!(Refused("OPENPGP_KEY is not set: the bot sends nothing unencrypted".into()));
        };
        let now = chrono::Utc::now().timestamp() as u32;
        let recipients = Recipients::load(path, &setup.to, now, &mut |w| log::warn!("OPENPGP_KEY: {w}"))
            .map_err(|e| Refused(format!("OPENPGP_KEY {e}")))?;
        for (addr, i) in &recipients.to {
            log::info!("mails to {addr} are encrypted to OpenPGP key {}", seal::pretty(&recipients.keys[*i].fingerprint));
        }
        let signer = match &self.signing_key {
            Some(path) => {
                let s = Signer::load(path).map_err(|e| Refused(format!("SIGNING_KEY {e}")))?;
                log::info!("mails are signed with the bot's key {}", seal::pretty(&s.fingerprint));
                Some(s)
            }
            None => {
                log::info!("SIGNING_KEY is not set: mails are encrypted, not signed");
                None
            }
        };
        Ok((recipients, signer))
    }

    /// The pseudonym key; only the service makes a missing one (as its own user).
    fn pseudonyms(&self, create: bool) -> Result<Pseudonyms> {
        let domains = redact::parse_domains(&self.xmpp_domains);
        let names =
            if create { Pseudonyms::load_or_create(&self.pseudonym_key, domains) } else { Pseudonyms::load(&self.pseudonym_key, domains) };
        names.map_err(|e| Refused(format!("pseudonym key: {e}")).into())
    }

    fn sanitize(&self, service: bool) -> Result<Option<bot::Sanitize>> {
        if !self.sanitize || (!service && !self.pseudonym_key.exists()) {
            log::info!("SANITIZE is off: alerts go out as they are (encrypted)");
            return Ok(None);
        }
        let servers = ServerNames::parse(&self.server_names).map_err(|e| Refused(format!("SERVER_NAMES: {e}")))?;
        if servers.is_empty() {
            log::warn!("SANITIZE is on but SERVER_NAMES is empty: only XMPP account names are replaced");
        } else {
            log::info!("SANITIZE is on: XMPP account names and the servers' addresses are replaced in alerts");
        }
        Ok(Some(bot::Sanitize { names: self.pseudonyms(service)?, servers }))
    }

    fn config(&self, setup: &Setup, service: bool) -> Result<bot::Config> {
        let (recipients, signer) = self.keys(setup)?;
        Ok(bot::Config {
            outbox: self.outbox_dir.clone(),
            outbox_max_age: Duration::from_secs(u64::from(self.outbox_max_days) * 86400),
            alert_max_age: Duration::from_secs(u64::from(self.alert_max_hours) * 3600),
            from: setup.from.clone(),
            outer_subject: self.outer_subject.clone(),
            recipients,
            signer,
            sanitize: self.sanitize(service)?,
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

/// Connects and logs in, retrying while the server can't be reached; gives up at once
/// (exit 78) when it refuses the login (retrying could get the address banned there).
fn connect(smtp: &Smtp, settings: &smtp::Settings, stop: &AtomicBool) -> Result<()> {
    let mut wait = 5;
    loop {
        match smtp.check() {
            Ok(()) => return Ok(()),
            Err(e) if e.permanent => {
                bail!(Refused(format!("the mail server {} refuses the bot: {e}", settings.describe())))
            }
            Err(e) => {
                log::warn!("mail server {} not reachable ({e}); trying again in {wait} s", settings.describe());
                for _ in 0..wait {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                wait = (wait * 2).min(300);
            }
        }
    }
}

fn run() -> Result<()> {
    let matches = Args::command().get_matches();
    let password_on_command_line = matches.value_source("smtp_password") == Some(ValueSource::CommandLine);
    let args = Args::from_arg_matches(&matches)?;
    match &args.cmd {
        None => logger::init(&args.log_dir),
        Some(_) => logger::init_stderr(),
    }
    if password_on_command_line {
        log::warn!("--smtp-password on the command line is visible in `ps`; use SMTP_PASSWORD_FILE");
    }
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(Cmd::Keygen { out }) = &args.cmd {
        return keygen(&args, out);
    }
    if let Some(Cmd::Pseudonym { accounts }) = &args.cmd {
        let names = args.pseudonyms(false)?;
        for a in accounts {
            println!("{a} {}", names.tag(a));
        }
        return Ok(());
    }
    let setup = args.setup()?;
    let cfg = args.config(&setup, args.cmd.is_none())?;
    let smtp = Smtp::new(&setup.smtp).map_err(Refused)?;
    match &args.cmd {
        Some(Cmd::Check) => {
            smtp.check().map_err(|e| anyhow::anyhow!("{}: {e}", setup.smtp.describe()))?;
            let (ok, not) = cfg.recipients.split(chrono::Utc::now().timestamp() as u32);
            for (addr, why) in &not {
                println!("NOT usable for {addr}: {why}");
            }
            println!(
                "OK: logged in to {}; mails from {} to {} ({}), outbox {}",
                setup.smtp.describe(),
                setup.from.address,
                ok.join(", "),
                if cfg.signer.is_some() { "encrypted and signed" } else { "encrypted" },
                if outbox::writable(&cfg.outbox).is_ok() {
                    format!("{} writable", cfg.outbox.display())
                } else {
                    format!("{} NOT writable", cfg.outbox.display())
                }
            );
            Ok(())
        }
        Some(Cmd::SendTest) => {
            let mut bot = Bot::new(cfg, smtp);
            let text = "A test from logguard-mail-bot: if you can read this, mails reach you encrypted.\n\
                        \"logguard\" line 2 of 3: → ⚠ ✓\nline 3 of 3."
                .to_string();
            let mail = bot.compose("[logguard-mail-bot] test", Content::Text(text), &setup.to).map_err(|e| anyhow::anyhow!(e))?;
            bot.out.send(&setup.from.address, &setup.to, &mail).map_err(|e| anyhow::anyhow!("{}: {e}", setup.smtp.describe()))?;
            println!("sent to {} ({} bytes) through {}", setup.to.join(", "), mail.len(), setup.smtp.describe());
            Ok(())
        }
        Some(Cmd::Keygen { .. } | Cmd::Pseudonym { .. }) => unreachable!(),
        None => {
            let stop = Arc::new(AtomicBool::new(false));
            for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                signal_hook::flag::register(sig, Arc::clone(&stop))?;
            }
            connect(&smtp, &setup.smtp, &stop)?;
            log::info!(
                "logguard-mail-bot {}: from {} to {} through {}; outbox {}",
                env!("CARGO_PKG_VERSION"),
                setup.from.address,
                setup.to.join(", "),
                setup.smtp.describe(),
                cfg.outbox.display()
            );
            bot::run(Bot::new(cfg, smtp), &stop);
            Ok(())
        }
    }
}

fn keygen(args: &Args, out: &std::path::Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let from = args.from()?;
    let (secret, public) = Signer::generate(&from.address).map_err(|e| anyhow::anyhow!("making the key: {e}"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .with_context(|| format!("{} (an existing key is never overwritten)", out.display()))?;
    f.write_all(secret.as_bytes())?;
    f.sync_all()?;
    let public_path = PathBuf::from(format!("{}.pub.asc", out.display()));
    std::fs::write(&public_path, &public).with_context(|| format!("writing {}", public_path.display()))?;
    let s = Signer::parse(secret.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;
    print!("{public}");
    eprintln!(
        "\nThe bot's key {} for {}: secret key in {}, public key in {}.\nSet SIGNING_KEY={} in config.env. Clients that read Autocrypt headers \
         learn the key from the first mail; others: import the public key above.",
        seal::pretty(&s.fingerprint),
        from.address,
        out.display(),
        public_path.display(),
        out.display()
    );
    Ok(())
}
