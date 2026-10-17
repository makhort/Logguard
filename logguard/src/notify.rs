//! XMPP notifications via ejabberd's HTTP API on loopback (`api`), its CTL_OVER_HTTP
//! socket (`ctl_socket`), or `ejabberdctl send_message`.
//!
//! The affected user gets a plain-language warning (password guessing against
//! their account, an address banned for trying their password, a suspicious
//! login); admins get a copy of important decisions. Messages are rate-limited
//! per recipient/topic/account and globally, and sent from a background thread
//! so a slow `ejabberdctl` never stalls detection.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::botbox::BotBox;
use crate::config::Mode;
use crate::engine::{Action, ActionKind, Topic};
use crate::i18n::{self, Lang};
use crate::time::{Dur, Micros, SEC};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyCfg {
    pub enabled: bool,
    /// Deliver over XMPP (ejabberd on this host). false on a node without ejabberd that only
    /// hands admin messages to the Telegram bot (`tg_outbox`) or the mail bot (`mail_outbox`):
    /// no users' warnings, no `from` or `admins` needed.
    pub xmpp: bool,
    pub ejabberdctl: PathBuf,
    /// A loopback ejabberd listener serving `/api` (mod_http_api), e.g. `127.0.0.1:5285`.
    /// Preferred: the only way that is both cheap and keeps any text intact.
    pub api: Option<SocketAddr>,
    /// Account `api` calls authenticate as (HTTP Basic), e.g. `logguard@example.org`, so
    /// ejabberd can grant `send_message` to that account alone instead of to every local
    /// process. Empty: no authentication.
    pub api_user: String,
    /// File holding `api_user`'s password (root-only, mode 0600; trailing newline ignored).
    pub api_password_file: PathBuf,
    /// ejabberd's CTL_OVER_HTTP Unix socket (absolute path), used when `api` isn't set.
    /// Better than `ejabberdctl`, whose CTL_OVER_HTTP mode doesn't escape arguments (ejabberd
    /// rejects any message with a line break or a quote), but ejabberd's `/ctl` handler
    /// still garbles non-ASCII text.
    pub ctl_socket: Option<PathBuf>,
    /// Sender JID: the server domain (e.g. `example.org`). Not the XMPP bot's account: users
    /// must not get notifications in their chat with the bot, which only answers commands.
    pub from: String,
    /// `chat` is shown by every client and stored for offline users; `headline` often isn't.
    pub message_type: String,
    /// XMPP accounts that get admin messages. Empty with `tg_outbox` or `mail_outbox`: admin
    /// messages go to those bots only, while users are still warned over XMPP.
    pub admins: Vec<String>,
    pub admin_topics: Vec<Topic>,
    pub user_topics: Vec<Topic>,
    /// Warn users while in shadow mode too (admins are always notified).
    pub users_in_shadow: bool,
    /// Minimum gap between messages with the same recipient, topic and account.
    pub cooldown: Dur,
    /// Cap per hour: on all messages to users together, and on admin messages per topic.
    pub max_per_hour: usize,
    /// Language of messages to users: en, fr, de, pl, ru or uk. Admin messages are always English.
    pub language: Lang,
    /// Per-account language, keyed by user name (`alice`) or full JID (`alice@example.org`).
    pub languages: BTreeMap<String, Lang>,
    /// The XMPP admin bot's outbox (logguard-xmpp-bot's `OUTBOX_DIR`, e.g. `/opt/logguard-xmpp-bot/outbox`).
    /// Messages to `admins` go there, and the bot sends them OMEMO-encrypted; one it hasn't
    /// taken within `bot_grace` goes out the usual way, saying so. Unset: not used.
    pub bot_outbox: Option<PathBuf>,
    /// The user the bot runs as, who gets the files (the outbox is sticky).
    pub bot_user: String,
    pub bot_grace: Dur,
    /// Warn when another file in the outbox (the weekly abuse report) waits longer than this.
    pub bot_stuck_after: Dur,
    /// The Telegram admin bot's outbox (logguard-tg-bot's `OUTBOX_DIR`, e.g. `/opt/logguard-tg-bot/outbox`).
    /// Optional; unset, nothing goes to Telegram. Set, a copy of every message to the first of
    /// `admins` goes there as well (every admin message when `admins` is empty or `xmpp` is
    /// false), and logguard-tg-bot sends it to the admin's Telegram chat with XMPP account names
    /// replaced by pseudonyms. The XMPP way is unchanged. There is no fallback for the copy:
    /// it waits until logguard-tg-bot sends it, and the admins are warned (the XMPP way, else as a
    /// system alert) when copies wait longer than `bot_stuck_after`.
    pub tg_outbox: Option<PathBuf>,
    /// The user logguard-tg-bot runs as, who gets the files.
    pub tg_user: String,
    /// The mail bot's outbox (logguard-mail-bot's `OUTBOX_DIR`, e.g. `/opt/logguard-mail-bot/outbox`).
    /// Optional, and like `tg_outbox` in every way: a copy of every message to the first of
    /// `admins` (every admin message when `admins` is empty or `xmpp` is false), which
    /// logguard-mail-bot mails OpenPGP-encrypted to its recipients. No fallback; the admins are
    /// warned when copies wait longer than `bot_stuck_after`.
    pub mail_outbox: Option<PathBuf>,
    /// The user logguard-mail-bot runs as, who gets the files.
    pub mail_user: String,
}

impl Default for NotifyCfg {
    fn default() -> Self {
        NotifyCfg {
            enabled: false,
            xmpp: true,
            ejabberdctl: "/usr/sbin/ejabberdctl".into(),
            api: None,
            api_user: String::new(),
            api_password_file: PathBuf::new(),
            ctl_socket: None,
            from: String::new(),
            message_type: "chat".into(),
            admins: vec![],
            admin_topics: vec![
                Topic::AccountAttack,
                Topic::BruteForce,
                Topic::Compromise,
                Topic::Registration,
                Topic::FalsePositive,
                Topic::Protected,
                Topic::System,
                Topic::Exposure,
                Topic::Integrity,
            ],
            user_topics: vec![Topic::AccountAttack, Topic::BruteForce, Topic::Compromise],
            users_in_shadow: false,
            cooldown: Dur(6 * 3600),
            max_per_hour: 30,
            language: Lang::En,
            languages: BTreeMap::new(),
            bot_outbox: None,
            bot_user: "ejabberd".into(),
            bot_grace: Dur(120),
            bot_stuck_after: Dur(3600),
            tg_outbox: None,
            tg_user: "logguard-tg-bot".into(),
            mail_outbox: None,
            mail_user: "logguard-mail-bot".into(),
        }
    }
}

fn valid_jid(j: &str) -> bool {
    !j.is_empty() && j.len() <= 256 && !j.starts_with('-') && !j.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl NotifyCfg {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !self.xmpp {
            if !self.has_copy_bots() {
                bail!("notify.xmpp = false needs notify.tg_outbox or notify.mail_outbox: nothing else would deliver admin messages");
            }
            if self.bot_outbox.is_some() {
                bail!("notify.bot_outbox is the XMPP bot's: not with notify.xmpp = false");
            }
        } else if !valid_jid(&self.from) {
            bail!("notify.from must be a JID (e.g. the server domain) when notifications are enabled");
        }
        if let Some(bad) = self.admins.iter().find(|j| !valid_jid(j) || !j.contains('@')) {
            bail!("notify.admins: invalid JID '{bad}'");
        }
        if self.api.is_some_and(|a| !a.ip().is_loopback()) {
            bail!("notify.api must be a loopback address (plain HTTP, no password)");
        }
        if self.api_user.is_empty() != self.api_password_file.as_os_str().is_empty() {
            bail!("notify.api_user and notify.api_password_file go together");
        }
        if !self.api_user.is_empty() && (!valid_jid(&self.api_user) || !self.api_user.contains('@')) {
            bail!("notify.api_user must be an account JID (e.g. logguard@example.org)");
        }
        if self.ctl_socket.as_ref().is_some_and(|p| !p.is_absolute()) {
            bail!("notify.ctl_socket must be an absolute path");
        }
        if !["chat", "normal", "headline"].contains(&self.message_type.as_str()) {
            bail!("notify.message_type must be chat, normal or headline");
        }
        if self.bot_outbox.as_ref().is_some_and(|p| !p.is_absolute()) {
            bail!("notify.bot_outbox must be an absolute path");
        }
        if self.tg_outbox.as_ref().is_some_and(|p| !p.is_absolute()) {
            bail!("notify.tg_outbox must be an absolute path");
        }
        if self.mail_outbox.as_ref().is_some_and(|p| !p.is_absolute()) {
            bail!("notify.mail_outbox must be an absolute path");
        }
        let outboxes: Vec<&PathBuf> = [&self.bot_outbox, &self.tg_outbox, &self.mail_outbox].into_iter().flatten().collect();
        if outboxes.iter().enumerate().any(|(i, a)| outboxes[..i].contains(a)) {
            bail!("notify.bot_outbox, tg_outbox and mail_outbox must differ: each bot empties its own");
        }
        if self.bot_outbox.is_some() && self.admins.is_empty() {
            bail!("notify.bot_outbox needs notify.admins: the XMPP bot only writes to an admin");
        }
        if self.bot_grace.0 < 10 {
            bail!("notify.bot_grace must be at least 10s (the bot looks every few seconds)");
        }
        if let Some(bad) = self.languages.keys().find(|k| k.trim().is_empty() || k.contains(char::is_whitespace)) {
            bail!("[notify.languages]: '{bad}' is not a user name or JID");
        }
        Ok(())
    }

    /// Who admin messages are addressed to: `admins`, or only [`ADMIN_BOTS`] (the copy bots'
    /// admins) with `xmpp = false` or no `admins` but a copy bot, or nobody.
    pub fn admin_recipients(&self) -> Vec<String> {
        if self.admins_over_xmpp() {
            self.admins.clone()
        } else if self.has_copy_bots() {
            vec![ADMIN_BOTS.into()]
        } else {
            vec![]
        }
    }

    /// Whether a bot gets a copy of admin messages (logguard-tg-bot, logguard-mail-bot).
    pub fn has_copy_bots(&self) -> bool {
        self.tg_outbox.is_some() || self.mail_outbox.is_some()
    }

    /// The copy bots set up here: what each is, its outbox, and the user it runs as.
    pub fn copy_bots(&self) -> Vec<(&'static CopyKind, PathBuf, String)> {
        [(&TG_BOT, &self.tg_outbox, &self.tg_user), (&MAIL_BOT, &self.mail_outbox, &self.mail_user)]
            .into_iter()
            .filter_map(|(k, dir, user)| dir.clone().map(|d| (k, d, user.clone())))
            .collect()
    }

    /// Whether admin messages (and warnings about the bots) can go out over XMPP.
    pub fn admins_over_xmpp(&self) -> bool {
        self.xmpp && !self.admins.is_empty()
    }

    /// The language for a recipient: by full JID, then by user name, else `language`.
    pub fn language_for(&self, jid: &str) -> Lang {
        let jid = jid.to_lowercase();
        let user = jid.split('@').next().unwrap_or(&jid);
        self.languages
            .iter()
            .find(|(k, _)| k.to_lowercase() == jid)
            .or_else(|| self.languages.iter().find(|(k, _)| !k.contains('@') && k.to_lowercase() == user))
            .map_or(self.language, |(_, l)| *l)
    }
}

/// The recipient of admin messages that go to the copy bots only (`xmpp = false`, or no
/// `admins`): they write to their own admins, whatever the `To:` says.
pub const ADMIN_BOTS: &str = "admin";

/// A bot that gets a copy of the first admin's messages and only sends them on.
#[derive(Debug, PartialEq, Eq)]
pub struct CopyKind {
    /// How warnings name it.
    pub name: &'static str,
    /// Its systemd unit and log directory name.
    pub unit: &'static str,
    /// What to look at when it sits on messages.
    pub hint: &'static str,
    /// The wall key of the system alert about it.
    pub stuck_key: &'static str,
}

pub const TG_BOT: CopyKind = CopyKind {
    name: "The Telegram bot (logguard-tg-bot)",
    unit: "logguard-tg-bot",
    hint: "Telegram out of reach, or the token revoked?",
    stuck_key: "logguard-tg-bot-stuck",
};

pub const MAIL_BOT: CopyKind = CopyKind {
    name: "The mail bot (logguard-mail-bot)",
    unit: "logguard-mail-bot",
    hint: "The mail server out of reach or refusing the login, or a recipient's OpenPGP key expired?",
    stuck_key: "logguard-mail-bot-stuck",
};

/// A copy bot's outbox, as the sending thread keeps it.
pub struct CopyBot {
    pub kind: &'static CopyKind,
    pub outbox: BotBox,
    /// When the admins were last warned about it.
    last_warning: Option<Instant>,
}

impl CopyBot {
    pub fn new(kind: &'static CopyKind, outbox: BotBox) -> CopyBot {
        CopyBot { kind, outbox, last_warning: None }
    }

    /// The outbox of a configured copy bot, its files given to `user` (from /etc/passwd).
    pub fn open(kind: &'static CopyKind, dir: PathBuf, user: &str, stuck_after: Duration) -> CopyBot {
        let owner = std::fs::read_to_string("/etc/passwd").ok().and_then(|p| crate::botbox::user_ids(&p, user));
        if owner.is_none() {
            eprintln!("logguard: no user {user} for {}'s files; it won't be able to take them", kind.unit);
        }
        CopyBot::new(kind, BotBox::without_fallback(dir, owner, stuck_after))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub to: String,
    pub subject: String,
    pub body: String,
}

pub fn topic_name(t: Topic) -> &'static str {
    match t {
        Topic::AccountAttack => "account under attack",
        Topic::BruteForce => "password guessing blocked",
        Topic::Compromise => "suspicious login",
        Topic::NewNetwork => "new login location",
        Topic::Registration => "new registration",
        Topic::FalsePositive => "possible false positive",
        Topic::Protected => "protected address misbehaving",
        Topic::System => "system",
        Topic::Exposure => "exposure change",
        Topic::Integrity => "host integrity",
        Topic::Digest => "daily digest",
        Topic::Relayed => "relayed",
    }
}

/// Decides which messages an action produces. Pure apart from rate-limit state.
pub struct Planner {
    cfg: NotifyCfg,
    mode: Mode,
    last: HashMap<(String, Topic, String), Micros>,
    /// Send times in the last hour: users share one budget, admins have one per topic.
    /// Messages to users (and account alerts) are triggered by attacker-chosen account
    /// names, so a flood of them must never silence e.g. system or compromise alerts.
    sent_users: VecDeque<Micros>,
    sent_admins: HashMap<Topic, VecDeque<Micros>>,
    pub suppressed: u64,
    /// This server's name (the cluster node id, else the host name): admin messages from
    /// several servers reach the same chat, so each says where it comes from.
    pub node: Option<String>,
}

impl Planner {
    pub fn new(cfg: NotifyCfg, mode: Mode) -> Self {
        Planner { cfg, mode, last: HashMap::new(), sent_users: VecDeque::new(), sent_admins: HashMap::new(), suppressed: 0, node: None }
    }

    fn allow(&mut self, to: &str, topic: Topic, account: &str, now: Micros, admin: bool) -> bool {
        // A distributed-attack alert and the bans it causes are one incident for the user.
        let topic = if topic == Topic::BruteForce { Topic::AccountAttack } else { topic };
        let key = (to.to_string(), topic, account.to_string());
        if self.last.get(&key).is_some_and(|t| now - t < self.cfg.cooldown.micros()) {
            return false;
        }
        let sent = if admin { self.sent_admins.entry(topic).or_default() } else { &mut self.sent_users };
        while sent.front().is_some_and(|t| now - t >= 3600 * SEC) {
            sent.pop_front();
        }
        if sent.len() >= self.cfg.max_per_hour {
            self.suppressed += 1;
            return false;
        }
        sent.push_back(now);
        self.last.insert(key, now);
        if self.last.len() > 10_000 {
            let cooldown = self.cfg.cooldown.micros();
            self.last.retain(|_, t| now - *t < cooldown);
        }
        true
    }

    /// The message to one user (`acct` qualified, `jid` bare), in their language.
    fn user_body(&self, a: &Action, topic: Topic, acct: &str, jid: &str, lang: Lang) -> String {
        let p = i18n::phrases(lang);
        let mut body = format!("{} {jid}\n\n", p.header);
        match &a.notice {
            Some(n) => body += &i18n::note(n, lang, Some(acct)),
            None => body += a.user_note.as_deref().unwrap_or(&a.message),
        }
        if matches!(topic, Topic::AccountAttack | Topic::BruteForce) {
            if self.mode == Mode::Enforce {
                body += &format!("\n\n{}", p.blocks);
                if let (true, Some(until)) = (a.kind == ActionKind::Ban && a.applied, a.until) {
                    body += &format!(" {}", p.blocked_for.replace("{dur}", &i18n::duration(lang, until - a.ts)));
                }
            }
            body += &format!("\n{}", p.advice);
        }
        body += &format!("\n\n{}", p.footer);
        body
    }

    pub fn admin_body(a: &Action) -> String {
        let mut body = format!("[{:?}] {}", a.severity, a.message).replace("[Critical]", "[CRITICAL]");
        for e in a.evidence.iter().take(5) {
            body += &format!("\n  {e}");
        }
        if !a.applied && a.kind == ActionKind::Ban {
            body += "\n(not applied to the firewall)";
        }
        body
    }

    pub fn plan(&mut self, a: &Action) -> Vec<Notice> {
        let Some(topic) = a.topic else { return vec![] };
        let mut out = Vec::new();

        // users are XMPP accounts: warned over XMPP only
        let users_ok = self.cfg.xmpp && (self.mode == Mode::Enforce || self.cfg.users_in_shadow);
        if users_ok && self.cfg.user_topics.contains(&topic) {
            for acct in &a.accounts {
                // Only XMPP accounts can receive XMPP messages.
                let Some(jid) = acct.strip_prefix("ejabberd:") else { continue };
                if !valid_jid(jid) || !jid.contains('@') {
                    continue;
                }
                if self.allow(jid, topic, acct, a.ts, false) {
                    let lang = self.cfg.language_for(jid);
                    out.push(Notice {
                        to: jid.to_string(),
                        subject: i18n::subject(topic, lang),
                        body: self.user_body(a, topic, acct, jid, lang),
                    });
                }
            }
        }

        // Digests and relayed notifications are enabled explicitly ([digest], cluster
        // `notices`), so they bypass admin_topics; each relayed message is rate-limited on its own.
        let explicit = matches!(topic, Topic::Digest | Topic::Relayed);
        if explicit || self.cfg.admin_topics.contains(&topic) {
            // What makes two admin messages "the same" for the cooldown: the accounts involved,
            // or else the message itself (system/exposure alerts have no account; the engine
            // already rate-limits each of those by its own key). A relayed message's subject
            // only names its server and topic ("[vpn] logguard: password guessing blocked"):
            // its text tells them apart, kept as a hash (digests run to kilobytes).
            let account = if topic == Topic::Relayed {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                (&a.message, &a.user_note).hash(&mut h);
                format!("{}#{:016x}", a.message, h.finish())
            } else if explicit || a.accounts.is_empty() {
                a.message.clone()
            } else {
                a.accounts.join(",")
            };
            let (mut subject, body) = if explicit {
                (a.message.clone(), a.user_note.clone().unwrap_or_default())
            } else {
                (format!("logguard: {}", topic_name(topic)), Self::admin_body(a))
            };
            // relayed messages carry their origin already ("[vpn] ...")
            if let Some(node) = self.node.as_ref().filter(|_| topic != Topic::Relayed) {
                subject = format!("[{node}] {subject}");
            }
            // XMPP clients (Conversations, Monal) don't show a message's subject: repeat it,
            // with the server's name, as the first line
            let body = format!("{subject}\n\n{body}");
            let admins = self.cfg.admin_recipients();
            for admin in admins {
                if self.allow(&admin, topic, &account, a.ts, true) {
                    out.push(Notice { to: admin, subject: subject.clone(), body: body.clone() });
                }
            }
        }
        out
    }
}

pub fn send(cfg: &NotifyCfg, n: &Notice) -> Result<()> {
    if let Some(addr) = cfg.api {
        return send_api(addr, cfg, n).with_context(|| format!("send_message to {} via http://{addr}/api", n.to));
    }
    if let Some(sock) = &cfg.ctl_socket {
        return send_ctl(sock, cfg, n).with_context(|| format!("send_message to {} via {}", n.to, sock.display()));
    }
    let mut cmd = Command::new(&cfg.ejabberdctl);
    cmd.args(["send_message", &cfg.message_type, &cfg.from, &n.to, &n.subject, &n.body]);
    let out =
        crate::proc::run(cmd, None, Duration::from_secs(20)).map_err(|e| anyhow::anyhow!("ejabberdctl send_message to {}: {e}", n.to))?;
    if !out.status.success() {
        bail!("ejabberdctl send_message to {} failed ({}): {}", n.to, out.status, out.complaint());
    }
    Ok(())
}

/// Sends a message through ejabberd's REST API (mod_http_api), which keeps any text intact.
/// The API needs a TCP listener: over a Unix socket it rejects every call, as it can't
/// determine the caller's address.
fn send_api(addr: SocketAddr, cfg: &NotifyCfg, n: &Notice) -> Result<()> {
    let body = serde_json::json!({
        "type": cfg.message_type, "from": cfg.from, "to": n.to, "subject": n.subject, "body": n.body,
    });
    let auth = api_auth(cfg)?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).context("connecting")?;
    let (http, head, reply) = post(stream, &domain_of(&cfg.from), "/api/send_message", &body.to_string(), auth.as_deref())?;
    // A command that fails without raising an error still answers 200, with 1 instead of 0.
    match (http.as_str(), reply.as_str()) {
        ("200", "0") => Ok(()),
        ("200", r) => bail!("command failed: {r}"),
        _ => bail!("HTTP {http}: {}", if reply.is_empty() { head.lines().next().unwrap_or("") } else { &reply }),
    }
}

/// Sends a message over the CTL_OVER_HTTP socket's `/ctl` handler, as `ejabberdctl` does but
/// with the arguments encoded as proper JSON. ejabberd answers 200 with the command's exit
/// code in a `status-code` header. The handler splits each argument into bytes and encodes
/// them again, so anything beyond ASCII arrives garbled ("→" as "â" and two control characters).
fn send_ctl(sock: &Path, cfg: &NotifyCfg, n: &Notice) -> Result<()> {
    let args = ["send_message", &cfg.message_type, &cfg.from, &n.to, &n.subject, &n.body];
    let stream = UnixStream::connect(sock).context("connecting")?;
    let (http, head, reply) = post(stream, &domain_of(&cfg.from), "/ctl/send_message", &serde_json::to_string(&args)?, None)?;
    let code =
        head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("status-code")).map(|(_, v)| v.trim()));
    match (http.as_str(), code) {
        ("200", Some("0") | None) => {
            if !n.body.is_ascii() || !n.subject.is_ascii() {
                eprintln!("logguard: non-ASCII text sent through ejabberd's /ctl handler arrives garbled; set [notify] api (README, \"XMPP notifications\")");
            }
            Ok(())
        }
        ("200", Some(c)) => bail!("command failed (status {c}): {reply}"),
        _ => bail!("HTTP {http}: {}", if reply.is_empty() { head.lines().next().unwrap_or("") } else { &reply }),
    }
}

/// The `Authorization` header value for `api` calls, if `api_user` is set. The password is
/// read for every message, so changing the file needs no restart.
fn api_auth(cfg: &NotifyCfg) -> Result<Option<String>> {
    use base64::Engine as _;
    if cfg.api_user.is_empty() {
        return Ok(None);
    }
    let path = &cfg.api_password_file;
    let password = std::fs::read_to_string(path).with_context(|| format!("reading notify.api_password_file {}", path.display()))?;
    let password = password.trim_end_matches(['\r', '\n']);
    if password.is_empty() || password.contains(['\r', '\n']) {
        bail!("{}: expected the password on one line", path.display());
    }
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{password}", cfg.api_user));
    Ok(Some(format!("Basic {token}")))
}

/// The XMPP domain of a JID (`bot@example.org/res` → `example.org`): ejabberd picks the
/// virtual host from the HTTP `Host` header.
fn domain_of(jid: &str) -> String {
    let bare = jid.split('/').next().unwrap_or(jid);
    bare.rsplit('@').next().unwrap_or(bare).to_string()
}

/// One HTTP POST: (status, response head, trimmed body).
fn post<S: Read + Write + Timeouts>(
    mut stream: S,
    host: &str,
    path: &str,
    body: &str,
    auth: Option<&str>,
) -> Result<(String, String, String)> {
    stream.timeouts(Duration::from_secs(20))?;
    let auth = auth.map(|a| format!("Authorization: {a}\r\n")).unwrap_or_default();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Type: application/json\r\nAccept: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let resp = read_reply(&mut stream).context("reading the reply")?;
    let resp = String::from_utf8_lossy(&resp);
    let (head, reply) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let http = head.split_whitespace().nth(1).unwrap_or("?").to_string();
    Ok((http, head.to_string(), reply.trim().to_string()))
}

trait Timeouts {
    fn timeouts(&self, d: Duration) -> std::io::Result<()>;
}

impl Timeouts for TcpStream {
    fn timeouts(&self, d: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(d))?;
        self.set_write_timeout(Some(d))
    }
}

impl Timeouts for UnixStream {
    fn timeouts(&self, d: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(d))?;
        self.set_write_timeout(Some(d))
    }
}

/// An HTTP reply, up to 64 KB: until the connection closes or, if the server keeps it
/// open, until `Content-Length` bytes of body have arrived. Gives up after 30 s in total, so
/// a reply trickling in can't hold the sender thread (each read also has its own timeout).
fn read_reply(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while buf.len() < 64 * 1024 {
        if Instant::now() > deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "reply took longer than 30 s"));
        }
        let n = r.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]);
            let len = head.lines().find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
            });
            if len.is_some_and(|len| buf.len() >= end + 4 + len) {
                break;
            }
        }
    }
    Ok(buf)
}

/// How often the bot's outbox is checked for messages to take back.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// Sends the usual way (`api`, `ctl_socket` or `ejabberdctl`), logging the outcome.
fn send_logged(cfg: &NotifyCfg, n: &Notice, how: &str) -> bool {
    match send(cfg, n) {
        Ok(()) => {
            eprintln!("logguard: notified {}{how}: {}", n.to, n.subject);
            true
        }
        Err(e) => {
            eprintln!("logguard: {e:#}");
            false
        }
    }
}

/// A copy of a message to the first admin for each copy bot set up (but `except`).
fn copy_to_bots(cfg: &NotifyCfg, copies: &mut [CopyBot], n: &Notice, except: Option<usize>) {
    if cfg.admin_recipients().first() != Some(&n.to) {
        return;
    }
    for (_, c) in copies.iter_mut().enumerate().filter(|(i, _)| Some(*i) != except) {
        if !c.outbox.ready() {
            eprintln!("logguard: {}'s outbox {} is missing; {} not sent there", c.kind.unit, c.outbox.dir.display(), n.subject);
            continue;
        }
        match c.outbox.put(n, SystemTime::now()) {
            Ok(path) => eprintln!("logguard: copy for {}: {} ({})", c.kind.unit, n.subject, path.display()),
            Err(e) => eprintln!("logguard: couldn't hand {} to {}: {e}", n.subject, c.kind.unit),
        }
    }
}

/// One message from the queue: a copy for each copy bot (if set up), then to the XMPP bot's
/// outbox if it is for an admin and the bot is there, else (or if that fails) the usual way.
fn deliver(cfg: &NotifyCfg, bot: Option<&mut BotBox>, copies: &mut [CopyBot], n: Notice) {
    deliver_except(cfg, bot, copies, n, None)
}

/// [`deliver`], leaving out copy bot `except` (the one a warning is about).
fn deliver_except(cfg: &NotifyCfg, bot: Option<&mut BotBox>, copies: &mut [CopyBot], n: Notice, except: Option<usize>) {
    copy_to_bots(cfg, copies, &n, except);
    if !cfg.xmpp || n.to == ADMIN_BOTS {
        return;
    }
    let Some(bot) = bot.filter(|_| cfg.admins.contains(&n.to)) else {
        send_logged(cfg, &n, "");
        return;
    };
    let why = if bot.ready() {
        match bot.put(&n, SystemTime::now()) {
            Ok(path) => return eprintln!("logguard: handed to the admin bot for {}: {} ({})", n.to, n.subject, path.display()),
            Err(e) => format!("couldn't hand it to the admin bot: {e}"),
        }
    } else {
        format!("the admin bot's outbox {} is missing", bot.dir.display())
    };
    eprintln!("logguard: {why}; sending unencrypted");
    let n = Notice { body: format!("{}\n\n(Sent unencrypted: {why}.)", n.body), ..n };
    send_logged(cfg, &n, " (unencrypted)");
}

/// Takes back what the bot hasn't sent in time and sends it the usual way; warns the admins
/// about other files the bot has been sitting on.
fn sweep(cfg: &NotifyCfg, bot: &mut BotBox, copies: &mut [CopyBot], node: &OnceLock<String>) {
    if !bot.ready() {
        return;
    }
    let found = match bot.sweep(SystemTime::now()) {
        Ok(f) => f,
        Err(e) => return eprintln!("logguard: admin bot outbox {}: {e}", bot.dir.display()),
    };
    for f in found.fallback {
        let n = BotBox::plain(&f);
        // a failure is logged once, not on every retry
        let sent = if bot.failing.contains(&f.path) {
            send(cfg, &n).is_ok()
        } else {
            send_logged(cfg, &n, &format!(" (unencrypted: {:?})", f.why))
        };
        if sent {
            let _ = std::fs::remove_file(&f.path);
            bot.failing.remove(&f.path);
        } else {
            bot.failing.insert(f.path);
        }
    }
    for (name, age) in found.stuck {
        let subject = match node.get() {
            Some(node) => format!("[{node}] logguard: {}", topic_name(Topic::System)),
            None => format!("logguard: {}", topic_name(Topic::System)),
        };
        let body = format!(
            "{subject}\n\n[High] The admin bot has had {name} in its outbox for {} without sending it. \
             Check the bot's log: no trusted admin device, or the upload failing?",
            crate::time::fmt_duration(age.as_secs() as i64 * SEC)
        );
        eprintln!("logguard: {name} waits in the admin bot's outbox");
        for admin in &cfg.admins {
            deliver(cfg, Some(bot), copies, Notice { to: admin.clone(), subject: subject.clone(), body: body.clone() });
        }
    }
}

/// Warns the admins when copy bot `i` leaves messages or files in its outbox longer than
/// `bot_stuck_after`: at most once per that time, however many wait. The warning goes the
/// XMPP way and to the other copy bots. A node without XMPP admins hands it to the daemon
/// instead (`problems`, with the system alert's wall key), which raises it as a system alert
/// (journal, actions log, the other copy bots), so `[cluster] relay_notices` takes it to a node
/// that delivers over XMPP.
fn sweep_copy(
    cfg: &NotifyCfg,
    copies: &mut [CopyBot],
    i: usize,
    bot: Option<&mut BotBox>,
    node: &OnceLock<String>,
    problems: &Mutex<Vec<(String, String)>>,
) {
    let c = &mut copies[i];
    if !c.outbox.ready() {
        return;
    }
    let found = match c.outbox.sweep(SystemTime::now()) {
        Ok(f) => f,
        Err(e) => return eprintln!("logguard: {} outbox {}: {e}", c.kind.unit, c.outbox.dir.display()),
    };
    let Some(oldest) = found.stuck.iter().map(|(_, age)| *age).max() else { return };
    eprintln!("logguard: {} file(s) wait in {}'s outbox", found.stuck.len(), c.kind.unit);
    if c.last_warning.is_some_and(|t| t.elapsed() < Duration::from_secs(cfg.bot_stuck_after.0)) {
        return;
    }
    c.last_warning = Some(Instant::now());
    let subject = match node.get() {
        Some(node) => format!("[{node}] logguard: {}", topic_name(Topic::System)),
        None => format!("logguard: {}", topic_name(Topic::System)),
    };
    let problem = format!(
        "{} has left {} message(s) or file(s) in its outbox {} unsent, the oldest for {}. \
         Is it running (systemctl status {unit}, /var/log/{unit}/bot.log)? {}",
        c.kind.name,
        found.stuck.len(),
        c.outbox.dir.display(),
        crate::time::fmt_duration(oldest.as_secs() as i64 * SEC),
        c.kind.hint,
        unit = c.kind.unit,
    );
    if !cfg.admins_over_xmpp() {
        if let Ok(mut p) = problems.lock() {
            p.push((c.kind.stuck_key.to_string(), problem));
        }
        return;
    }
    let body = format!("{subject}\n\n[High] {problem}");
    let mut bot = bot;
    for admin in &cfg.admins {
        deliver_except(
            cfg,
            bot.as_deref_mut(),
            copies,
            Notice { to: admin.clone(), subject: subject.clone(), body: body.clone() },
            Some(i),
        );
    }
}

/// Plans in the caller's thread, sends in a background thread.
pub struct Notifier {
    planner: Planner,
    tx: Option<SyncSender<Notice>>,
    node: Arc<OnceLock<String>>,
    /// Problems with delivery the daemon should raise as system alerts, with their wall
    /// keys (see [`sweep_copy`]).
    problems: Arc<Mutex<Vec<(String, String)>>>,
}

impl Notifier {
    pub fn new(cfg: &NotifyCfg, mode: Mode) -> Self {
        let node = Arc::new(OnceLock::new());
        let problems = Arc::new(Mutex::new(Vec::new()));
        let tx = cfg.enabled.then(|| {
            let (tx, rx) = sync_channel::<Notice>(256);
            let cfg = cfg.clone();
            let node = node.clone();
            let problems = problems.clone();
            thread::spawn(move || {
                let mut bot = cfg.bot_outbox.clone().map(|dir| {
                    let owner = std::fs::read_to_string("/etc/passwd").ok().and_then(|p| crate::botbox::user_ids(&p, &cfg.bot_user));
                    if owner.is_none() {
                        eprintln!("logguard: no user {} for the admin bot's files; the bot won't be able to take them", cfg.bot_user);
                    }
                    BotBox::new(dir, owner, Duration::from_secs(cfg.bot_grace.0), Duration::from_secs(cfg.bot_stuck_after.0))
                });
                let stuck_after = Duration::from_secs(cfg.bot_stuck_after.0);
                let mut copies: Vec<CopyBot> =
                    cfg.copy_bots().into_iter().map(|(kind, dir, user)| CopyBot::open(kind, dir, &user, stuck_after)).collect();
                let mut last_sweep: Option<Instant> = None;
                loop {
                    match rx.recv_timeout(SWEEP_EVERY) {
                        Ok(n) => deliver(&cfg, bot.as_mut(), &mut copies, n),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    if last_sweep.is_none_or(|t| t.elapsed() >= SWEEP_EVERY) {
                        if let Some(bot) = bot.as_mut() {
                            sweep(&cfg, bot, &mut copies, &node);
                        }
                        for i in 0..copies.len() {
                            sweep_copy(&cfg, &mut copies, i, bot.as_mut(), &node, &problems);
                        }
                        last_sweep = Some(Instant::now());
                    }
                }
            });
            tx
        });
        Notifier { planner: Planner::new(cfg.clone(), mode), tx, node, problems }
    }

    /// Delivery problems to raise as system alerts, each with its wall key (taken: each is
    /// returned once).
    pub fn take_problems(&self) -> Vec<(String, String)> {
        self.problems.lock().map(|mut p| std::mem::take(&mut *p)).unwrap_or_default()
    }

    /// Names this server in admin messages.
    pub fn set_node(&mut self, node: String) {
        let _ = self.node.set(node.clone());
        self.planner.node = Some(node);
    }

    pub fn handle(&mut self, a: &Action) {
        let Some(tx) = &self.tx else { return };
        for mut n in self.planner.plan(a) {
            // log text (user names attackers tried, URIs) reaches the message: nothing that
            // could make it display other than it reads
            n.subject = crate::event::plain_text(&n.subject);
            n.body = crate::event::plain_text(&n.body);
            if let Err(TrySendError::Full(n)) = tx.try_send(n) {
                eprintln!("logguard: notification queue full, dropping message to {}", n.to);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Severity;

    /// A one-request-per-connection HTTP server: checks each request line and Host, records
    /// the JSON bodies, and replies as scripted (keeping the connection open, so the client
    /// must stop at Content-Length).
    fn fake_server<L: Send + 'static>(
        accept: impl Fn(&L) -> Box<dyn ReadWrite> + Send + 'static,
        listener: L,
        script: Vec<(&'static str, &'static str, &'static str, &'static str)>,
    ) -> thread::JoinHandle<Vec<serde_json::Value>> {
        thread::spawn(move || {
            let mut bodies = Vec::new();
            for (line, status, header, reply) in script {
                let mut s = accept(&listener);
                let req = String::from_utf8(read_reply(&mut s).unwrap()).unwrap();
                let (head, body) = req.split_once("\r\n\r\n").unwrap();
                assert!(head.starts_with(line), "{head}");
                assert!(head.contains("\r\nHost: example.org\r\n"), "{head}");
                bodies.push(serde_json::from_str::<serde_json::Value>(body).unwrap());
                write!(s, "HTTP/1.1 {status}\r\n{header}Content-Length: {}\r\n\r\n{reply}", reply.len()).unwrap();
                thread::sleep(Duration::from_millis(300));
            }
            bodies
        })
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    const TEXT: &str = "line 1 → ⚠ Привіт\n\"two\" \\ end";

    #[test]
    fn api_sends_named_fields() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = fake_server(
            |l: &std::net::TcpListener| Box::new(l.accept().unwrap().0),
            listener,
            vec![
                ("POST /api/send_message ", "200 OK", "", "0"),
                ("POST /api/send_message ", "403 Forbidden", "", "{\"status\":\"error\"}"),
                ("POST /api/send_message ", "200 OK", "", "1"),
            ],
        );
        let ncfg = NotifyCfg { api: Some(addr), from: "bot@example.org/x".into(), ..cfg() };
        let n = Notice { to: "admin@example.org".into(), subject: "s".into(), body: TEXT.into() };
        send(&ncfg, &n).unwrap();
        let err = format!("{:#}", send(&ncfg, &n).unwrap_err());
        assert!(err.contains("HTTP 403"), "{err}");
        let err = format!("{:#}", send(&ncfg, &n).unwrap_err());
        assert!(err.contains("command failed: 1"), "200 with 1 is a failure: {err}");
        let bodies = server.join().unwrap();
        assert_eq!(
            bodies[0],
            serde_json::json!({"type": "chat", "from": "bot@example.org/x", "to": "admin@example.org", "subject": "s", "body": TEXT})
        );
        assert!(NotifyCfg { api: Some("10.0.0.1:5285".parse().unwrap()), ..cfg() }.validate().is_err(), "loopback only");
    }

    #[test]
    fn api_authenticates_as_its_account() {
        let dir = std::env::temp_dir().join(format!("lg-apiauth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pw = dir.join("pw");
        std::fs::write(&pw, "s3cret:x\n").unwrap();
        let ncfg = NotifyCfg { api_user: "logguard@example.org".into(), api_password_file: pw.clone(), ..cfg() };
        ncfg.validate().unwrap();
        // base64("logguard@example.org:s3cret:x")
        assert_eq!(api_auth(&ncfg).unwrap().as_deref(), Some("Basic bG9nZ3VhcmRAZXhhbXBsZS5vcmc6czNjcmV0Ong="));
        assert_eq!(api_auth(&cfg()).unwrap(), None);
        std::fs::write(&pw, "two\nlines\n").unwrap();
        assert!(api_auth(&ncfg).is_err());
        assert!(api_auth(&NotifyCfg { api_password_file: dir.join("missing"), ..ncfg.clone() }).is_err());
        assert!(NotifyCfg { api_password_file: PathBuf::new(), ..ncfg.clone() }.validate().is_err(), "both or neither");
        assert!(NotifyCfg { api_user: "logguard".into(), ..ncfg }.validate().is_err(), "a JID");
        // the header goes out with the request
        let mut wire: Vec<u8> = Vec::new();
        struct Pipe<'a>(&'a mut Vec<u8>, &'a [u8]);
        impl Read for Pipe<'_> {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.1.read(b)
            }
        }
        impl Write for Pipe<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Timeouts for Pipe<'_> {
            fn timeouts(&self, _: Duration) -> std::io::Result<()> {
                Ok(())
            }
        }
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n0";
        let (http, _, reply) = post(Pipe(&mut wire, answer), "example.org", "/api/send_message", "{}", Some("Basic abc")).unwrap();
        assert_eq!((http.as_str(), reply.as_str()), ("200", "0"));
        assert!(String::from_utf8(wire).unwrap().contains("\r\nAuthorization: Basic abc\r\n"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ctl_socket_sends_valid_json_and_reads_status() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("lg-ctl-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("ctl.sock");
        let _ = std::fs::remove_file(&sock);
        let server = fake_server(
            |l: &UnixListener| Box::new(l.accept().unwrap().0),
            UnixListener::bind(&sock).unwrap(),
            vec![
                ("POST /ctl/send_message ", "200 OK", "status-code: 0\r\n", ""),
                ("POST /ctl/send_message ", "200 OK", "status-code: 1\r\n", "Error: no such user\n"),
            ],
        );
        let ncfg = NotifyCfg { ctl_socket: Some(sock.clone()), ..cfg() };
        let n = Notice { to: "admin@example.org".into(), subject: "s".into(), body: TEXT.into() };
        send(&ncfg, &n).unwrap();
        let err = format!("{:#}", send(&ncfg, &n).unwrap_err());
        assert!(err.contains("status 1"), "{err}");
        let bodies = server.join().unwrap();
        assert_eq!(bodies[0], serde_json::json!(["send_message", "chat", "example.org", "admin@example.org", "s", TEXT]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admin_messages_go_to_the_bot_users_never() {
        let dir = std::env::temp_dir().join(format!("logguard-notify-bot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // the usual way can't work here, so whatever isn't in the outbox wasn't put there
        let ncfg = NotifyCfg { ejabberdctl: "/nonexistent/ejabberdctl".into(), bot_outbox: Some(dir.clone()), ..cfg() };
        ncfg.validate().unwrap();
        let mut bot = BotBox::new(dir.clone(), None, Duration::from_secs(120), Duration::from_secs(3600));
        let to = |jid: &str| Notice { to: jid.into(), subject: "s".into(), body: "b".into() };
        deliver(&ncfg, Some(&mut bot), &mut [], to("admin@example.org"));
        deliver(&ncfg, Some(&mut bot), &mut [], to("alice@example.org"));
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(files.len(), 1, "{files:?}");
        let n = crate::botbox::parse(&std::fs::read_to_string(&files[0]).unwrap()).unwrap();
        assert_eq!(n.to, "admin@example.org");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(NotifyCfg { bot_outbox: Some("outbox".into()), ..cfg() }.validate().is_err(), "absolute path");
        assert!(NotifyCfg { bot_grace: Dur(1), ..cfg() }.validate().is_err());
    }

    #[test]
    fn telegram_gets_a_copy_of_the_first_admins_messages() {
        let dir = std::env::temp_dir().join(format!("logguard-notify-tg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (xmpp, telegram) = (dir.join("xmpp"), dir.join("telegram"));
        std::fs::create_dir_all(&xmpp).unwrap();
        std::fs::create_dir_all(&telegram).unwrap();
        let ncfg = NotifyCfg {
            ejabberdctl: "/nonexistent/ejabberdctl".into(),
            admins: vec!["admin@example.org".into(), "second@example.org".into()],
            bot_outbox: Some(xmpp.clone()),
            tg_outbox: Some(telegram.clone()),
            ..cfg()
        };
        ncfg.validate().unwrap();
        let mut bot = BotBox::new(xmpp.clone(), None, Duration::from_secs(120), Duration::from_secs(3600));
        let mut tg = [CopyBot::new(&TG_BOT, BotBox::without_fallback(telegram.clone(), None, Duration::from_secs(3600)))];
        let to = |jid: &str| Notice { to: jid.into(), subject: "s".into(), body: "b".into() };
        // the planner makes one message per admin: Telegram gets one copy; users' warnings none
        for jid in ["admin@example.org", "second@example.org", "alice@example.org"] {
            deliver(&ncfg, Some(&mut bot), &mut tg, to(jid));
        }
        let count = |d: &Path| std::fs::read_dir(d).unwrap().count();
        assert_eq!((count(&xmpp), count(&telegram)), (2, 1));
        // without the XMPP bot too
        deliver(&ncfg, None, &mut tg, to("admin@example.org"));
        assert_eq!(count(&telegram), 2);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(NotifyCfg::default().tg_outbox.is_none(), "off unless set");
        assert!(NotifyCfg { tg_outbox: Some("outbox".into()), ..cfg() }.validate().is_err(), "absolute path");
        assert!(
            NotifyCfg { bot_outbox: Some("/opt/logguard-xmpp-bot/outbox".into()), admins: vec![], ..cfg() }.validate().is_err(),
            "needs an admin"
        );
        let parsed: NotifyCfg = toml::from_str("enabled = true\nfrom = \"x.org\"\nadmins = [\"a@x.org\"]").unwrap();
        assert_eq!((parsed.tg_outbox, parsed.tg_user.as_str()), (None, "logguard-tg-bot"), "older configs parse unchanged");
        assert_eq!((parsed.mail_outbox, parsed.mail_user.as_str()), (None, "logguard-mail-bot"));
    }

    fn cfg() -> NotifyCfg {
        NotifyCfg { enabled: true, from: "example.org".into(), admins: vec!["admin@example.org".into()], ..Default::default() }
    }

    fn attack(ts_s: i64, accounts: &[&str]) -> Action {
        Action {
            ts: ts_s * SEC,
            kind: ActionKind::Alert,
            severity: Severity::High,
            target: None,
            until: None,
            message: "account ejabberd:bob@example.org under distributed attack".into(),
            evidence: vec![],
            superseded: vec![],
            applied: false,
            topic: Some(Topic::AccountAttack),
            accounts: accounts.iter().map(|s| s.to_string()).collect(),
            user_note: Some("Your account is the target of a password-guessing attack.".into()),
            notice: None,
            category: None,
        }
    }

    #[test]
    fn telegram_only_node() {
        let dir = std::env::temp_dir().join(format!("logguard-notify-tgonly-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // no from, no admins, no ejabberd
        let ncfg = NotifyCfg { enabled: true, xmpp: false, tg_outbox: Some(dir.clone()), ..Default::default() };
        ncfg.validate().unwrap();
        assert_eq!(ncfg.admin_recipients(), [ADMIN_BOTS]);
        let mut p = Planner::new(ncfg.clone(), Mode::Enforce);
        let n = p.plan(&attack(0, &["ejabberd:bob@example.org"]));
        assert_eq!(n.iter().map(|n| n.to.as_str()).collect::<Vec<_>>(), [ADMIN_BOTS], "no user warning without XMPP");
        let mut tg = [CopyBot::new(&TG_BOT, BotBox::without_fallback(dir.clone(), None, Duration::from_secs(3600)))];
        deliver(&ncfg, None, &mut tg, n[0].clone());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "to Telegram, and nothing tried over XMPP");

        // a stuck bot is handed to the daemon, not sent anywhere
        let problems = Mutex::new(Vec::new());
        let file = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        std::fs::File::options().write(true).open(&file).unwrap().set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        sweep_copy(&ncfg, &mut tg, 0, None, &OnceLock::new(), &problems);
        let p = problems.lock().unwrap().clone();
        assert!(p.len() == 1 && p[0].1.starts_with("The Telegram bot (logguard-tg-bot) has left 1 message(s)"), "{p:?}");
        assert_eq!(p[0].0, "logguard-tg-bot-stuck");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(NotifyCfg { tg_outbox: None, ..ncfg.clone() }.validate().is_err(), "nothing would deliver");
        assert!(NotifyCfg { bot_outbox: Some("/opt/logguard-xmpp-bot/outbox".into()), ..ncfg.clone() }.validate().is_err());
        assert!(NotifyCfg::default().xmpp, "XMPP unless turned off");
    }

    /// An XMPP server whose admin reads alerts on Telegram only: users are still warned over
    /// XMPP, admin messages never go out over XMPP.
    #[test]
    fn telegram_admin_xmpp_users() {
        let dir = std::env::temp_dir().join(format!("logguard-notify-tgadmin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        api.set_nonblocking(true).unwrap();
        let ncfg = NotifyCfg { api: Some(api.local_addr().unwrap()), admins: vec![], tg_outbox: Some(dir.clone()), ..cfg() };
        ncfg.validate().unwrap();
        assert_eq!(ncfg.admin_recipients(), [ADMIN_BOTS]);
        assert!(!ncfg.admins_over_xmpp());
        let mut p = Planner::new(ncfg.clone(), Mode::Enforce);
        let n = p.plan(&attack(0, &["ejabberd:bob@example.org"]));
        assert_eq!(n.iter().map(|n| n.to.as_str()).collect::<Vec<_>>(), ["bob@example.org", ADMIN_BOTS]);
        let mut tg = [CopyBot::new(&TG_BOT, BotBox::without_fallback(dir.clone(), None, Duration::from_secs(3600)))];
        deliver(&ncfg, None, &mut tg, n[1].clone());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "to Telegram");
        assert!(api.accept().is_err(), "and nothing over XMPP");
        // a stuck Telegram bot can't be reported to an XMPP admin: the daemon raises it
        let file = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        std::fs::File::options().write(true).open(&file).unwrap().set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        let problems = Mutex::new(Vec::new());
        sweep_copy(&ncfg, &mut tg, 0, None, &OnceLock::new(), &problems);
        assert_eq!(problems.lock().unwrap().len(), 1);
        assert!(api.accept().is_err());
        let _ = std::fs::remove_dir_all(&dir);
        // users only: no admins and no Telegram
        assert!(NotifyCfg { admins: vec![], ..cfg() }.admin_recipients().is_empty());
    }

    /// The mail bot is a copy bot like the Telegram one: alone on a node without XMPP, or
    /// next to it, each gets its copy, and one that sits on its messages is reported to the
    /// admins (over XMPP, and to the other copy bot), never into its own outbox.
    #[test]
    fn mail_bot_copies() {
        let dir = std::env::temp_dir().join(format!("logguard-notify-mail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mail, telegram) = (dir.join("mail"), dir.join("tg"));
        std::fs::create_dir_all(&mail).unwrap();
        std::fs::create_dir_all(&telegram).unwrap();
        let count = |d: &Path| std::fs::read_dir(d).unwrap().count();
        let open = |d: &Path, k| CopyBot::new(k, BotBox::without_fallback(d.to_path_buf(), None, Duration::from_secs(3600)));

        // mail only, no ejabberd
        let only = NotifyCfg { enabled: true, xmpp: false, mail_outbox: Some(mail.clone()), ..Default::default() };
        only.validate().unwrap();
        assert_eq!(only.admin_recipients(), [ADMIN_BOTS]);
        assert_eq!(
            only.copy_bots().iter().map(|(k, d, u)| (k.unit, d.clone(), u.as_str())).collect::<Vec<_>>(),
            [("logguard-mail-bot", mail.clone(), "logguard-mail-bot")]
        );
        let mut copies = [open(&mail, &MAIL_BOT)];
        deliver(&only, None, &mut copies, Notice { to: ADMIN_BOTS.into(), subject: "s".into(), body: "b".into() });
        assert_eq!(count(&mail), 1);
        let text = std::fs::read_to_string(std::fs::read_dir(&mail).unwrap().next().unwrap().unwrap().path()).unwrap();
        assert!(text.starts_with("To: admin\nSubject: s\n\n"), "{text}");

        // both, on an XMPP server with an admin there too; the API isn't reachable, so only
        // the outboxes show what was handed on
        let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = api.local_addr().unwrap();
        drop(api);
        let both = NotifyCfg { api: Some(addr), tg_outbox: Some(telegram.clone()), mail_outbox: Some(mail.clone()), ..cfg() };
        both.validate().unwrap();
        assert_eq!(both.copy_bots().len(), 2);
        let mut copies = [open(&telegram, &TG_BOT), open(&mail, &MAIL_BOT)];
        deliver(&both, None, &mut copies, Notice { to: "admin@example.org".into(), subject: "s".into(), body: "b".into() });
        assert_eq!((count(&telegram), count(&mail)), (1, 2));
        // the Telegram bot sits on its message: the warning reaches the mail bot, not Telegram
        let file = std::fs::read_dir(&telegram).unwrap().next().unwrap().unwrap().path();
        std::fs::File::options().write(true).open(&file).unwrap().set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        let problems = Mutex::new(Vec::new());
        sweep_copy(&both, &mut copies, 0, None, &OnceLock::new(), &problems);
        assert!(problems.lock().unwrap().is_empty(), "XMPP admins are told directly");
        assert_eq!((count(&telegram), count(&mail)), (1, 3));
        let newest = std::fs::read_dir(&mail).unwrap().map(|e| e.unwrap().path()).max().unwrap();
        assert!(std::fs::read_to_string(newest).unwrap().contains("The Telegram bot (logguard-tg-bot) has left 1 message(s)"));
        sweep_copy(&both, &mut copies, 0, None, &OnceLock::new(), &problems);
        assert_eq!(count(&mail), 3, "once per bot_stuck_after");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(NotifyCfg { mail_outbox: Some("outbox".into()), ..cfg() }.validate().is_err(), "absolute path");
        assert!(
            NotifyCfg { tg_outbox: Some(mail.clone()), mail_outbox: Some(mail.clone()), ..cfg() }.validate().is_err(),
            "one outbox each"
        );
        assert!(NotifyCfg { bot_outbox: Some(mail.clone()), mail_outbox: Some(mail.clone()), ..cfg() }.validate().is_err());
        assert!(NotifyCfg { bot_outbox: Some(telegram.clone()), tg_outbox: Some(telegram.clone()), ..cfg() }.validate().is_err());
        assert!(NotifyCfg { mail_outbox: None, ..only }.validate().is_err(), "nothing would deliver");
    }

    #[test]
    fn user_and_admin_get_messages_with_cooldown() {
        let mut p = Planner::new(cfg(), Mode::Enforce);
        let n = p.plan(&attack(0, &["ejabberd:bob@example.org"]));
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].to, "bob@example.org");
        assert!(n[0].body.contains("password-guessing attack"));
        assert!(n[0].body.contains("blocks the attacking addresses"));
        assert_eq!(n[1].to, "admin@example.org");
        assert!(p.plan(&attack(60, &["ejabberd:bob@example.org"])).is_empty(), "cooldown");
        assert_eq!(p.plan(&attack(7 * 3600, &["ejabberd:bob@example.org"])).len(), 2);
        let mut ban = attack(7 * 3600 + 5, &["ejabberd:bob@example.org"]);
        ban.kind = ActionKind::Ban;
        ban.topic = Some(Topic::BruteForce);
        assert!(
            !p.plan(&ban).iter().any(|n| n.to == "bob@example.org"),
            "a ban right after the attack alert is the same incident for the user"
        );
    }

    #[test]
    fn shadow_mode_only_admins_and_ssh_accounts_never_messaged() {
        let mut p = Planner::new(cfg(), Mode::Shadow);
        let n = p.plan(&attack(0, &["ejabberd:bob@example.org"]));
        assert_eq!(n.iter().map(|n| n.to.as_str()).collect::<Vec<_>>(), vec!["admin@example.org"]);
        let mut p = Planner::new(cfg(), Mode::Enforce);
        let n = p.plan(&attack(0, &["ssh:root"]));
        assert_eq!(n.iter().map(|n| n.to.as_str()).collect::<Vec<_>>(), vec!["admin@example.org"]);
    }

    #[test]
    fn admin_messages_name_their_server_in_the_body() {
        let mut p = Planner::new(cfg(), Mode::Enforce);
        p.node = Some("xmpp".into());
        let mut digest = attack(0, &[]);
        (digest.topic, digest.message, digest.user_note) = (Some(Topic::Digest), "logguard daily digest".into(), Some("Bans: 3".into()));
        let n = p.plan(&digest);
        assert_eq!(n[0].subject, "[xmpp] logguard daily digest");
        assert_eq!(n[0].body, "[xmpp] logguard daily digest\n\nBans: 3", "chat clients don't show the subject");
        // relayed from vpn: tagged by the engine already, not tagged again
        let mut relayed = digest.clone();
        (relayed.topic, relayed.message) = (Some(Topic::Relayed), "[vpn] logguard daily digest".into());
        let n = p.plan(&relayed);
        assert!(n[0].body.starts_with("[vpn] logguard daily digest\n\n"), "{}", n[0].body);
        let n = p.plan(&attack(0, &["ejabberd:bob@example.org"]));
        let admin = n.iter().find(|n| n.to == "admin@example.org").unwrap();
        assert!(admin.body.starts_with("[xmpp] logguard: "), "{}", admin.body);
    }

    #[test]
    fn relayed_messages_are_told_apart_by_their_text() {
        let mut p = Planner::new(cfg(), Mode::Enforce);
        let relayed = |ts_s: i64, body: &str| Action {
            topic: Some(Topic::Relayed),
            message: "[vpn] logguard: password guessing blocked".into(),
            user_note: Some(body.into()),
            ..attack(ts_s, &[])
        };
        assert_eq!(p.plan(&relayed(0, "[High] ban 11.13.45.233 for 1h")).len(), 1);
        assert_eq!(p.plan(&relayed(10, "[High] ban 11.21.63.115 for 1h")).len(), 1, "another ban from the same server");
        assert!(p.plan(&relayed(20, "[High] ban 11.21.63.115 for 1h")).is_empty(), "the same one again: cooldown");
    }

    #[test]
    fn global_cap() {
        let mut c = cfg();
        c.max_per_hour = 3;
        c.admins.clear();
        let mut p = Planner::new(c, Mode::Enforce);
        let total: usize = (0..10).map(|i| p.plan(&attack(i, &[&format!("ejabberd:u{i}@x.org")])).len()).sum();
        assert_eq!(total, 3);
        assert_eq!(p.suppressed, 7);
    }

    #[test]
    fn admin_alerts_without_accounts_are_distinct_and_have_their_own_budget() {
        let mut c = cfg();
        c.max_per_hour = 3;
        let mut p = Planner::new(c, Mode::Enforce);
        let sys = |ts_s: i64, msg: &str| Action {
            topic: Some(Topic::System),
            accounts: vec![],
            message: msg.into(),
            user_note: None,
            notice: None,
            ..attack(ts_s, &[])
        };
        // an attacker spraying made-up account names uses up the user budget...
        for i in 0..10 {
            p.plan(&attack(i, &[&format!("ejabberd:u{i}@example.org")]));
        }
        // ...but different system alerts still reach the admin
        assert_eq!(p.plan(&sys(20, "no ufw log lines for 2h")).len(), 1);
        assert_eq!(p.plan(&sys(30, "nftables table rebuilt")).len(), 1);
        assert!(p.plan(&sys(40, "nftables table rebuilt")).is_empty(), "same message: cooldown");
    }

    #[test]
    fn messages_in_each_users_language() {
        let mut c = cfg();
        c.languages =
            [("bob".to_string(), Lang::Ru), ("Carol@example.org".to_string(), Lang::Uk), ("dave@other.org".to_string(), Lang::Fr)]
                .into_iter()
                .collect();
        assert_eq!(c.language_for("bob@example.org"), Lang::Ru, "by user name");
        assert_eq!(c.language_for("carol@example.org"), Lang::Uk, "by JID, case-insensitive");
        assert_eq!(c.language_for("dave@example.org"), Lang::En, "a JID key is exact");
        assert_eq!(c.language_for("alice@example.org"), Lang::En, "default");
        let mut p = Planner::new(c, Mode::Enforce);
        let mut ban = attack(0, &["ejabberd:alice@example.org", "ejabberd:bob@example.org"]);
        ban.kind = ActionKind::Ban;
        ban.applied = true;
        ban.until = Some(6 * 3600 * SEC);
        ban.topic = Some(Topic::BruteForce);
        ban.notice = Some(i18n::UserNotice::BruteForce {
            ip: "11.8.2.3".parse().unwrap(),
            attempts: [("ejabberd:alice@example.org".to_string(), 2), ("ejabberd:bob@example.org".to_string(), 5)].into_iter().collect(),
        });
        let n = p.plan(&ban);
        let to = |who: &str| n.iter().find(|n| n.to == who).unwrap();
        let bob = to("bob@example.org");
        assert_eq!(bob.subject, "⚠️ Уведомление о безопасности: подбор пароля заблокирован");
        assert!(bob.body.starts_with("Уведомление о безопасности для bob@example.org"), "{}", bob.body);
        assert!(bob.body.contains("С адреса 11.8.2.3: 5 неудачных попыток входа"), "{}", bob.body);
        assert!(bob.body.contains("Этот адрес заблокирован на 6 часов."), "{}", bob.body);
        assert!(!bob.body.contains("alice"), "never another user's account: {}", bob.body);
        let alice = to("alice@example.org");
        assert!(alice.body.contains("2 failed login attempts on alice@example.org came from 11.8.2.3."), "{}", alice.body);
        assert!(alice.body.contains("This address is blocked for 6 hours."), "{}", alice.body);
        assert!(to("admin@example.org").body.contains("\n\n[High]"), "admins: English as before");
    }

    #[test]
    fn language_config() {
        let cfg = crate::config::Config::from_toml(
            "[notify]\nlanguage = \"english\"\n[notify.languages]\nuser5 = \"uk\"\n\"user2@example.org\" = \"ru\"\nbob = \"fr\"",
        )
        .unwrap();
        assert_eq!(cfg.notify.language, Lang::En);
        assert_eq!(cfg.notify.language_for("user5@example.org"), Lang::Uk);
        assert!(crate::config::Config::from_toml("[notify]\nlanguage = \"es\"").is_err(), "unsupported language");
        assert_eq!(crate::config::Config::from_toml("[notify]\nlanguage = \"deutsch\"").unwrap().notify.language, Lang::De);
    }

    #[test]
    fn validation() {
        assert!(cfg().validate().is_ok());
        assert!(NotifyCfg { from: String::new(), ..cfg() }.validate().is_err());
        assert!(NotifyCfg { admins: vec!["-x".into()], ..cfg() }.validate().is_err());
        assert!(NotifyCfg::default().validate().is_ok(), "disabled needs nothing");
    }
}
