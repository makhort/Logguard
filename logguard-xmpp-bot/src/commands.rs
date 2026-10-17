//! The chat commands. Everything here is transport-free: a sender and a text in, a reply
//! out, so the whole command set is testable against a fake ejabberd.

use chrono::{DateTime, Utc};
use rand::distr::{Alphanumeric, SampleString};

use crate::ctl::Ejabberd;
use crate::i18n::{Language, Texts};
use crate::state::State;
use crate::timefmt::{elapsed_time, format_maintenance_times, relative_time, utc_to_local_times};

/// A chat reply. Every message of the bot is sent with a no-archive hint.
#[derive(Debug, PartialEq)]
pub struct Reply {
    pub text: String,
    /// Holds a password or a reset link: sent unencrypted, it must not wait in the
    /// server's offline storage either.
    pub secret: bool,
}

impl Reply {
    fn secret(text: String) -> Self {
        Reply { text, secret: true }
    }
}

impl From<String> for Reply {
    fn from(text: String) -> Self {
        Reply { text, secret: false }
    }
}

impl From<&str> for Reply {
    fn from(text: &str) -> Self {
        text.to_string().into()
    }
}

/// A file for the sender, after the reply: sent OMEMO-encrypted (XEP-0454) or not at all.
#[derive(Debug, PartialEq)]
pub struct Attachment {
    pub filename: String,
    pub data: Vec<u8>,
}

/// What a command produces besides its reply.
#[derive(Default)]
struct Extra {
    notify_admin: Option<String>,
    attachment: Option<Attachment>,
}

#[derive(Debug, PartialEq)]
pub struct Response {
    pub reply: Reply,
    /// Also tell the admin this.
    pub notify_admin: Option<String>,
    pub attachment: Option<Attachment>,
}

const INVALID_USERNAME: &str = "✗ Invalid username.";

const ADMIN_HELP: &str = "\
*Accounts*
`/add <username>` — register user with a generated password
`/remove <username>` — delete user
`/chpass <username> <new_password>` — change password
`/rstpass <username>` — reset password to a generated one
`/resetlink <username>` — link where the user sets a new password
`/list` — list registered users
`/seen <username>` — last time online
`/sessions <username>` — devices, IP addresses, clients
`/roster <username>` — contacts and subscription states
`/storage <username>` — archived and offline message counts

*Invitations*
`/invites` — open invitation and reset links
`/invite` — where users invite others

*Bot access*
`/allow <username> [language]` — allow access to bot; language of its replies: EN (default), FR, GE, PL, RU or UA
`/deny <username>` — deny access to bot
`/allowed` — list users with access to bot

*Bans and spam*
`/ban <username> [reason]` — ban user
`/unban <username>` — unban user
`/banned` — list banned accounts
`/baninfo <username>` — reason and date of a ban
`/kick <username> [resource]` — disconnect a user, or one device
`/unban_ip <address>` — lift a fail2ban IP ban
`/spam_domains` — list blocked domains
`/block_domain <domain>` — block a domain
`/unblock_domain <domain>` — unblock a domain

*Server*
`/status` — uptime and user counts
`/online` — list connected users
`/certs` — TLS certificates
`/reload_config confirm` — reload ejabberd.yml
`/restart <minutes> confirm` — announce, wait, restart ejabberd

*Announcements*
`/maintenance <from> <to>` — notify all users about server maintenance
`/warn <message>` — warn all users
`/announce <all|online> <subject> <message>` — make announcement
`/get_motd` — get current message of the day
`/set_motd <subject> <message>` — set or update current message of the day
`/del_motd` — delete current message of the day
`/dt_conv <dt>` — convert UTC datetime to simplified localized string

*Cleanup*
`/purge_mam <days> confirm` — delete archived messages older than that
`/purge_offline <days> confirm` — delete offline messages older than that
`/purge_status` — progress of both purges
`/purge_bot_chats confirm` — delete all archived chats with the bot

*Other*
`/privacy` — how long the server keeps data
`/omemo` — show OMEMO fingerprints
`/help` — show this help";

/// 16 random letters and digits in groups of four: `aB3d-9xYz-...`.
pub fn generate_password() -> String {
    let raw = Alphanumeric.sample_string(&mut rand::rng(), 16);
    let groups: Vec<&str> = (0..16).step_by(4).map(|i| &raw[i..i + 4]).collect();
    groups.join("-")
}

fn is_valid_username(u: &str) -> bool {
    (3..=64).contains(&u.chars().count()) && u.chars().all(|c| c.is_alphanumeric() || ".-_".contains(c))
}

/// The username in `john` or `john@any.domain` as ejabberd stores it: nodeprep'd
/// (lowercase, compatibility forms folded: `Admin` and `ａｄｍｉｎ` are `admin`).
fn normalize_username(arg: &str) -> Option<String> {
    let node = tokio_xmpp::jid::NodePart::new(local_part(arg)).ok()?;
    is_valid_username(node.as_str()).then(|| node.as_str().to_string())
}

/// The local part of `john` or `john@any.domain`.
fn local_part(arg: &str) -> &str {
    arg.split('@').next().unwrap_or(arg)
}

/// One item per line in a preformatted block (XEP-0393 Message Styling): monospace in
/// Conversations, and usernames like `a_b_c` are not taken for italics.
fn bullet_list<S: AsRef<str>>(items: &[S]) -> String {
    let lines: Vec<String> = items.iter().map(|u| format!("• {}", u.as_ref())).collect();
    format!("```\n{}\n```", lines.join("\n"))
}

/// `Usage:` and `Example:` lines of a usage reply (in any language) get their command in
/// a monospace span.
fn style_usage(text: String) -> String {
    let is_label = |l: &str| Language::ALL.iter().any(|lang| [lang.texts().usage, lang.texts().example].contains(&l));
    if !text.split_once(": ").is_some_and(|(first, _)| is_label(first)) {
        return text;
    }
    text.lines()
        .map(|l| match l.split_once(": ") {
            Some((label, cmd)) if is_label(label) && cmd.starts_with('/') => format!("{label}: `{cmd}`"),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn unix(now: DateTime<Utc>) -> f64 {
    now.timestamp_millis() as f64 / 1000.0
}

/// How long the server keeps data, in days, for /privacy: what the daily cleanup
/// (cleanup_db.sh) and ejabberd's config enforce.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    /// Archive (MAM), offline messages, push registrations.
    pub messages: u32,
    /// HTTP uploads (mod_http_upload_quota's max_days).
    pub files: u32,
    /// Largest upload, in MB (mod_http_upload's max_size).
    pub max_file_mb: u32,
    /// Accounts without a login.
    pub accounts: u32,
    /// Unused group chats.
    pub rooms: u32,
    /// Abuse reports kept by the bot.
    pub reports: u32,
    /// Security records: logguard's decisions (actions.jsonl).
    pub security: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention { messages: 21, files: 7, max_file_mb: 500, accounts: 90, rooms: 90, reports: 90, security: 84 }
    }
}

pub struct Bot<E> {
    pub domain: String,
    pub retention: Retention,
    /// mod_invites' web page, where users sign in and create invitations.
    pub invite_url: String,
    /// Bare JID, lowercase.
    pub admin_jid: String,
    /// The bot's own bare JID, lowercase.
    pub bot_jid: String,
    pub state: State,
    pub ctl: E,
    /// The languages of server announcements (/maintenance, /restart, /warn), in order.
    pub announce_languages: Vec<Language>,
}

impl<E: Ejabberd> Bot<E> {
    /// The admin, or someone the admin allowed.
    pub fn may_use(&self, sender: &str) -> bool {
        sender == self.admin_jid || self.state.can_access_bot(sender)
    }

    /// The language the bot uses with `sender`: English for the admin, otherwise the one
    /// set with /allow.
    pub fn language_of(&self, sender: &str) -> Language {
        if sender == self.admin_jid {
            return Language::En;
        }
        self.state.language(local_part(sender)).and_then(Language::parse).unwrap_or_default()
    }

    /// Handles one chat message from `sender` (a lowercase bare JID). `None`: ignore it,
    /// the sender may not use the bot.
    #[cfg(test)]
    pub async fn process(&mut self, sender: &str, text: &str, now: DateTime<Utc>) -> Option<Response> {
        self.process_from(sender, None, text, now).await
    }

    /// [`Bot::process`] for a message from `sender`'s `device` (the resource), which
    /// /devices marks as the current one.
    pub async fn process_from(&mut self, sender: &str, device: Option<&str>, text: &str, now: DateTime<Utc>) -> Option<Response> {
        if !self.may_use(sender) {
            return None;
        }
        let is_admin = sender == self.admin_jid;
        let mut extra = Extra::default();
        let mut reply = self.dispatch(sender, device, is_admin, text, now, &mut extra).await;
        reply.text = style_usage(reply.text);
        Some(Response { reply, notify_admin: extra.notify_admin, attachment: extra.attachment })
    }

    async fn dispatch(
        &mut self,
        sender: &str,
        device: Option<&str>,
        is_admin: bool,
        text: &str,
        now: DateTime<Utc>,
        extra: &mut Extra,
    ) -> Reply {
        let t = self.language_of(sender).texts();
        let Some(line) = text.strip_prefix('/') else {
            return t.not_a_command.into();
        };
        let Some(parts) = shlex::split(line.trim()) else {
            return t.parse_error.into();
        };
        let Some((cmd, args)) = parts.split_first() else {
            return t.no_command.into();
        };
        let cmd = cmd.to_lowercase();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let who = local_part(sender);

        match (cmd.as_str(), is_admin) {
            ("help", true) => ADMIN_HELP.into(),
            ("help", false) => t.help.replace("{admin}", &self.admin_jid).into(),
            // "create": what users typed before; they get the same answer
            ("invite" | "create", _) => self.invite(t),
            ("privacy", _) => self.privacy(&args, t),
            ("resetlink", false) => self.own_reset_link(who, &args, t).await,
            ("devices", false) => self.devices(who, device, &args, t).await,
            ("logout", false) => self.logout(who, device, &args, t).await,
            ("storage", false) => self.own_storage(who, &args, t).await,
            ("delete_history", false) => self.delete_history(who, &args, t).await,
            ("lang", false) => self.set_own_language(who, &args, t),
            ("motd", false) => self.motd(&args, t).await,
            ("export", false) => self.export(who, &args, t, now, &mut extra.attachment).await,
            ("abuse", false) => self.abuse_user(who, &args, now, &mut extra.notify_admin, t).await,
            (_, false) => t.unknown_command.replace("{cmd}", &cmd).into(),
            ("add", _) => self.add(&args).await,
            ("remove", _) => self.remove(&args).await,
            ("ban", _) => self.ban(&args).await,
            ("unban", _) => self.unban(&args).await,
            ("allow", _) => self.allow(&args).await,
            ("deny", _) => self.deny(&args).await,
            ("chpass", _) => self.chpass(&args).await,
            ("rstpass", _) => self.rstpass(&args).await,
            ("list", _) => self.list(&args).await,
            ("banned", _) => self.banned(&args).await,
            ("allowed", _) => self.allowed(&args),
            ("online", _) => self.online(&args).await,
            ("seen", _) => self.seen(&args, now).await,
            ("dt_conv", _) => dt_conv(&args, now, &self.announce_languages),
            ("maintenance", _) => self.maintenance(&args, now).await,
            ("warn", _) => self.warn(&args).await,
            ("announce", _) => self.announce(&args).await,
            ("get_motd", _) => self.get_motd(&args).await,
            ("set_motd", _) => self.set_motd(&args).await,
            ("del_motd", _) => self.del_motd(&args).await,
            ("status", _) => self.status(&args).await,
            ("certs", _) => self.certs(&args, now).await,
            ("sessions", _) => self.sessions(&args).await,
            ("roster", _) => self.roster(&args).await,
            ("storage", _) => self.storage(&args).await,
            ("baninfo", _) => self.baninfo(&args).await,
            ("kick", _) => self.kick(&args).await,
            ("unban_ip", _) => self.unban_ip(&args).await,
            ("resetlink", _) => self.resetlink(&args).await,
            ("invites", _) => self.invites(&args).await,
            ("spam_domains", _) => self.spam_domains(&args).await,
            ("block_domain", _) => self.block_domain(&args, true).await,
            ("unblock_domain", _) => self.block_domain(&args, false).await,
            ("purge_mam", _) => self.purge_mam(&args).await,
            ("purge_offline", _) => self.purge_offline(&args).await,
            ("purge_status", _) => self.purge_status(&args).await,
            ("purge_bot_chats", _) => self.purge_bot_chats(&args).await,
            ("restart", _) => self.restart(&args).await,
            ("reload_config", _) => self.reload_config(&args).await,
            _ => format!("Unknown command: '{cmd}'. Type '/help'.").into(),
        }
    }

    /// Daily: forgets what the bot holds about accounts that no longer exist (ejabberd's
    /// own cleanup deletes inactive ones without telling the bot) and abuse reports older
    /// than [`Retention::reports`] days.
    pub async fn prune_state(&mut self, now: DateTime<Utc>) {
        let users: std::collections::HashSet<String> = match self.ctl.run(&["registered_users", &self.domain]).await {
            Ok(out) => out.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty()).collect(),
            Err(e) => return log::warn!("state cleanup skipped: listing users: {e}"),
        };
        // a broken or partial listing must not wipe the state: the bot's own account is
        // always there
        if !users.contains(local_part(&self.bot_jid)) {
            return log::warn!("state cleanup skipped: the user list ({} names) lacks the bot's own account", users.len());
        }
        let max_age = f64::from(self.retention.reports) * 86400.0;
        match self.state.prune(|u| users.contains(u), &self.domain, unix(now), max_age) {
            Ok(p) if p == crate::state::Pruned::default() => {}
            Ok(p) => log::info!(
                "state cleanup: {} entries of deleted accounts, {} old or orphaned reports, {} bot accesses removed",
                p.entries,
                p.reports,
                p.allowed
            ),
            Err(e) => log::error!("state cleanup: {e:#}"),
        }
    }

    async fn account_exists(&self, username: &str) -> bool {
        self.ctl.run(&["check_account", username, &self.domain]).await.is_ok()
    }

    /// The username in `arg` (normalized), if it is well-formed and the account exists
    /// (or, with `exists == false`, does not exist yet).
    async fn username(&self, arg: &str, exists: bool) -> Result<String, Reply> {
        match normalize_username(arg) {
            Some(u) if self.account_exists(&u).await == exists => Ok(u),
            _ => Err(INVALID_USERNAME.into()),
        }
    }

    /// Refuses to `what` the admin's or the bot's own account.
    fn guard(&self, u: &str, what: &str) -> Result<(), Reply> {
        let jid = format!("{u}@{}", self.domain);
        let whose = if jid == self.admin_jid {
            "the admin's account"
        } else if jid == self.bot_jid {
            "the bot's own account"
        } else {
            return Ok(());
        };
        Err(format!("✗ Can not {what} '{u}': {whose}.").into())
    }

    /// An existing, unprotected account (see [`Bot::guard`]).
    async fn target(&self, arg: &str, what: &str) -> Result<String, Reply> {
        let u = self.username(arg, true).await?;
        self.guard(&u, what)?;
        Ok(u)
    }

    async fn register(&self, username: &str) -> Result<String, String> {
        let password = generate_password();
        self.ctl.run(&["register", username, &self.domain, &password]).await?;
        Ok(password)
    }

    fn registered(&self, username: &str, password: &str) -> Reply {
        Reply::secret(format!("✓ User '{username}' registered.\nLogin: `{username}@{}`\nPassword: `{password}`", self.domain))
    }

    fn saved(r: anyhow::Result<()>, ok: Reply) -> Reply {
        match r {
            Ok(()) => ok,
            Err(e) => {
                log::error!("saving state: {e:#}");
                format!("✗ Failed to save bot state: {e:#}").into()
            }
        }
    }

    async fn add(&mut self, args: &[&str]) -> Reply {
        let [arg] = args else { return "Usage: /add <username>\nExample: /add john".into() };
        let u = match self.username(arg, false).await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.register(&u).await {
            Ok(password) => self.registered(&u, &password),
            Err(e) => format!("✗ Failed to register user: {e}").into(),
        }
    }

    async fn remove(&mut self, args: &[&str]) -> Reply {
        let [arg] = args else { return "Usage: /remove <username>\nExample: /remove john".into() };
        let u = match self.target(arg, "remove").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.ctl.run(&["unregister", &u, &self.domain]).await {
            Ok(_) => {
                // a new account of the same name must not inherit bot access
                let jid = format!("{u}@{}", self.domain);
                let saved = self.state.remove_user(&u).and_then(|()| self.state.deny_bot_access(&jid));
                Self::saved(saved, format!("✓ User '{u}' removed.").into())
            }
            Err(e) => format!("✗ Failed to remove user: {e}").into(),
        }
    }

    /// Users invite others on mod_invites' web page, which checks their password.
    fn privacy(&self, args: &[&str], t: &Texts) -> Reply {
        if !args.is_empty() {
            return format!("{}: /privacy", t.usage).into();
        }
        let r = self.retention;
        t.privacy
            .replace("{domain}", &self.domain)
            .replace("{messages}", &r.messages.to_string())
            .replace("{files}", &r.files.to_string())
            .replace("{quota}", &r.max_file_mb.to_string())
            .replace("{accounts}", &r.accounts.to_string())
            .replace("{rooms}", &r.rooms.to_string())
            .replace("{reports}", &r.reports.to_string())
            .replace("{security}", &r.security.to_string())
            .into()
    }

    fn invite(&self, t: &Texts) -> Reply {
        t.invite.replace("{url}", &self.invite_url).into()
    }

    async fn ban(&mut self, args: &[&str]) -> Reply {
        let Some(arg) = args.first() else {
            return "Usage: /ban <username> [reason]\nExample: /ban john 'Spam account'".into();
        };
        let u = match self.target(arg, "ban").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let reason = args.get(1).copied().unwrap_or("Blocked by admin");
        match self.ctl.run(&["ban_account", &u, &self.domain, reason]).await {
            Ok(_) => Self::saved(self.state.reset_abuse_reports(&u), format!("✓ User '{u}' banned.\nReason: {reason}").into()),
            Err(e) => format!("✗ Failed to ban user: {e}").into(),
        }
    }

    async fn unban(&mut self, args: &[&str]) -> Reply {
        let [arg] = args else { return "Usage: /unban <username>\nExample: /unban john".into() };
        let u = match self.target(arg, "unban").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.ctl.run(&["unban_account", &u, &self.domain]).await {
            Ok(_) => Self::saved(self.state.reset_abuse_reports(&u), format!("✓ User '{u}' unbanned.").into()),
            Err(e) => format!("✗ Failed to unban user: {e}").into(),
        }
    }

    async fn allow(&mut self, args: &[&str]) -> Reply {
        let (arg, code) = match args {
            [arg] => (arg, None),
            [arg, code] => (arg, Some(*code)),
            _ => return "Usage: /allow <username> [language]\nExample: /allow john\nExample: /allow john FR".into(),
        };
        let lang = match code.map(Language::parse) {
            None => None,
            Some(Some(l)) => Some(l),
            Some(None) => return crate::i18n::EN.unknown_language.into(),
        };
        let u = match self.target(arg, "change bot access of").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let jid = format!("{u}@{}", self.domain);
        let mut saved = self.state.allow_bot_access(&jid);
        if let (Ok(()), Some(l)) = (&saved, lang) {
            saved = self.state.set_language(&u, l.code());
        }
        let lang = self.language_of(&jid).code();
        Self::saved(saved, format!("✓ User '{u}' now has access to bot (language: {lang}).").into())
    }

    async fn deny(&mut self, args: &[&str]) -> Reply {
        let Some(arg) = args.first() else { return "Usage: /deny <username>\nExample: /deny john".into() };
        let u = match self.target(arg, "change bot access of").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let jid = format!("{u}@{}", self.domain);
        Self::saved(self.state.deny_bot_access(&jid), format!("✓ User '{u}' will not have access to bot.").into())
    }

    fn allowed(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /allowed".into();
        }
        let users: Vec<String> =
            self.state.users_with_bot_access().iter().map(|j| format!("{} ({})", local_part(j), self.language_of(j).code())).collect();
        format!("✓ Users with access to bot ({}):\n{}", users.len(), bullet_list(&users)).into()
    }

    async fn abuse_user(&mut self, who: &str, args: &[&str], now: DateTime<Utc>, notify_admin: &mut Option<String>, t: &Texts) -> Reply {
        let Some(arg) = args.first() else {
            return format!("{}: /abuse {}\n{}: /abuse {}", t.usage, t.abuse_args, t.example, t.abuse_example).into();
        };
        let default_reason = format!("Blocked by {who}");
        let reason = args.get(1).copied().unwrap_or(&default_reason);
        let Ok(u) = self.username(arg, true).await else {
            return t.invalid_username.into();
        };
        if self.guard(&u, "report").is_err() {
            return t.cannot_report.replace("{user}", &u).into();
        }
        match self.state.push_abuse_user(who, &u, reason, unix(now)) {
            Ok(None) => t.report_once.into(),
            Ok(Some(is_abuser)) => {
                if is_abuser {
                    let reports = self.state.reporters_for_abuser(&u);
                    let lines: Vec<String> = reports.iter().map(|(r, ts)| format!("{r} {}", relative_time(*ts, unix(now)))).collect();
                    *notify_admin =
                        Some(format!("User {u} is reported as abuser {} times.\nReporters:\n{}", reports.len(), bullet_list(&lines)));
                }
                t.report_accepted.into()
            }
            Err(e) => {
                // the error names server paths: only for the log
                log::error!("saving state: {e:#}");
                t.report_failed.into()
            }
        }
    }

    async fn chpass(&mut self, args: &[&str]) -> Reply {
        let [arg, new_password] = args else {
            return "Usage: /chpass <username> <new_password>\nExample: /chpass john NewPass123".into();
        };
        let u = match self.target(arg, "change the password of").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.ctl.run(&["change_password", &u, &self.domain, new_password]).await {
            Ok(_) => format!("✓ Password changed for '{u}'.").into(),
            Err(e) => format!("✗ Failed to change password: {e}").into(),
        }
    }

    async fn rstpass(&mut self, args: &[&str]) -> Reply {
        let [arg] = args else { return "Usage: /rstpass <username>\nExample: /rstpass john".into() };
        let u = match self.target(arg, "reset the password of").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let password = generate_password();
        match self.ctl.run(&["change_password", &u, &self.domain, &password]).await {
            Ok(_) => Reply::secret(format!("✓ Password reset for '{u}'.\nNew password: `{password}`")),
            Err(e) => format!("✗ Failed to reset password: {e}").into(),
        }
    }

    async fn list(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /list".into();
        }
        match self.ctl.run(&["registered_users", &self.domain]).await {
            Err(e) => format!("✗ Failed to list users: {e}").into(),
            Ok(out) => {
                let users: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
                if users.is_empty() {
                    format!("No registered users on '{}'.", self.domain).into()
                } else {
                    format!("✓ Registered users ({}):\n{}", users.len(), bullet_list(&users)).into()
                }
            }
        }
    }

    async fn banned(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /banned".into();
        }
        match self.ctl.run(&["list_banned", &self.domain]).await {
            Err(e) => format!("✗ Failed to list banned accounts: {e}").into(),
            Ok(out) => {
                let items: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
                if items.is_empty() {
                    format!("No banned accounts on '{}'.", self.domain).into()
                } else {
                    format!("✓ Banned accounts ({}):\n{}", items.len(), bullet_list(&items)).into()
                }
            }
        }
    }

    async fn online(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /online".into();
        }
        let out = match self.ctl.run(&["connected_users_info"]).await {
            Ok(out) => out,
            Err(e) => return format!("✗ Failed to list connected users: {e}").into(),
        };
        // jid, connection, ip, port, priority, node, uptime (s), status, resource, text
        let selected: Vec<String> = out
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .filter(|f| f.len() >= 8 && f[7].eq_ignore_ascii_case("available"))
            .map(|f| {
                let uptime = f[6].parse().map(elapsed_time).unwrap_or_else(|_| f[6].to_string());
                format!("• {}\n  [{}]{}:{}\n  {uptime}", f[0], f[1], f[2], f[3])
            })
            .collect();
        if selected.is_empty() {
            format!("Noone online on '{}'.", self.domain).into()
        } else {
            format!("✓ Connected users ({}):\n```\n{}\n```", selected.len(), selected.join("\n")).into()
        }
    }

    async fn seen(&self, args: &[&str], now: DateTime<Utc>) -> Reply {
        let Some(arg) = args.first() else { return "Usage: /seen <username>\nExample: /seen john".into() };
        let u = match self.username(arg, true).await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let out = match self.ctl.run(&["get_last", &u, &self.domain]).await {
            Ok(out) => out,
            Err(e) => return format!("✗ Failed to get last online timestamp: {e}").into(),
        };
        let ts = out.split_whitespace().next().unwrap_or("");
        match DateTime::parse_from_rfc3339(ts) {
            Ok(dt) => format!("✓ Last seen: {}.", relative_time(unix(dt.into()), unix(now))).into(),
            Err(_) => format!("✗ Unexpected get_last output: {out}").into(),
        }
    }

    async fn announce_all(&self, subject: &str, message: &str) -> Reply {
        match self.ctl.run(&["announce_send_all", &self.domain, subject, message]).await {
            Ok(_) => "✓ Done.".into(),
            Err(e) => format!("✗ Failed to make announcement: {e}").into(),
        }
    }

    async fn maintenance(&self, args: &[&str], now: DateTime<Utc>) -> Reply {
        let [from, to] = args else {
            return "Usage: /maintenance <from> <to>\n\
                    Example: /maintenance '01/02/2026 01:00:00' '01/02/2026 02:00:00'\n\
                    Example: /maintenance 'Sun 01:00' 'Sun 02:00'\n\
                    Example: /maintenance 'Monday 01:00' 'Monday 02:00'"
                .into();
        };
        let ranges = match format_maintenance_times(from, to, now, &self.announce_languages) {
            Ok(r) => r,
            Err(e) => return format!("✗ Failed to parse/format datetime: {e}").into(),
        };
        let mut ranges = ranges.into_iter();
        let message = self.multilingual(|t| t.maintenance_notice.replace("{range}", &ranges.next().unwrap_or_default()), "\n\n");
        self.announce_all(&self.subject("🛠️", |t| t.maintenance_subject), &message).await
    }

    async fn warn(&self, args: &[&str]) -> Reply {
        if args.is_empty() {
            return "Usage: /warn <message>\nExample: /warn 'Please update your client to the latest version.'".into();
        }
        self.announce_all(&self.subject("⚠️", |t| t.warning_subject), &args.join(" ")).await
    }

    /// One paragraph per announcement language: its flag, then `text` in it.
    fn multilingual(&self, mut text: impl FnMut(&Texts) -> String, separator: &str) -> String {
        self.announce_languages.iter().map(|l| format!("{} {}", l.texts().flag, text(l.texts()))).collect::<Vec<_>>().join(separator)
    }

    /// An announcement's subject in every announcement language: "📢 🛠️ Server maintenance / …".
    fn subject(&self, icon: &str, words: fn(&Texts) -> &'static str) -> String {
        let words: Vec<&str> = self.announce_languages.iter().map(|l| words(l.texts())).collect();
        format!("📢 {icon} {}", words.join(" / "))
    }

    async fn announce(&self, args: &[&str]) -> Reply {
        let target = args.first().map(|a| a.to_lowercase());
        let (Some(target @ ("all" | "online")), true) = (target.as_deref(), args.len() >= 3) else {
            return "Usage: /announce <all|online> <subject> <message>\n\
                    Example: /announce online 'Test' 'Some message.'"
                .into();
        };
        let command = format!("announce_send_{target}");
        let message = args[2..].join(" ");
        match self.ctl.run(&[&command, &self.domain, args[1], &message]).await {
            Ok(_) => "✓ Done.".into(),
            Err(e) => format!("✗ Failed to make announcement: {e}").into(),
        }
    }

    async fn get_motd(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /get_motd".into();
        }
        match self.ctl.run(&["announce_motd_get", &self.domain]).await {
            Ok(out) if out.trim().is_empty() => "''".into(),
            Ok(out) => out.trim().to_string().into(),
            Err(e) => format!("✗ Failed to get message of the day: {e}").into(),
        }
    }

    async fn set_motd(&self, args: &[&str]) -> Reply {
        if args.len() < 2 {
            return "Usage: /set_motd <subject> <message>\nExample: /set_motd Welcome 'Welcome to our XMPP server!'".into();
        }
        let current = match self.ctl.run(&["announce_motd_get", &self.domain]).await {
            Ok(out) => out,
            Err(e) => return format!("✗ Failed to check for current message of the day: {e}").into(),
        };
        let command = if current.trim().is_empty() { "announce_motd_set_online" } else { "announce_motd_update" };
        let message = args[1..].join(" ");
        match self.ctl.run(&[command, &self.domain, args[0], &message]).await {
            Ok(_) => "✓ Done.".into(),
            Err(e) => format!("✗ Failed to set message of the day: {e}").into(),
        }
    }

    async fn del_motd(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /del_motd".into();
        }
        match self.ctl.run(&["announce_motd_delete", &self.domain]).await {
            Ok(_) => "✓ Done.".into(),
            Err(e) => format!("✗ Failed to delete current message of the day: {e}").into(),
        }
    }
}

fn dt_conv(args: &[&str], now: DateTime<Utc>, langs: &[Language]) -> Reply {
    let Some(raw) = args.first() else {
        return "Usage: /dt_conv <dt>\n\
                Example: /dt_conv '01/02/2026 01:00:00'\n\
                Example: /dt_conv 'Sun 01:00'\n\
                Example: /dt_conv 'Monday 01:00'"
            .into();
    };
    match utc_to_local_times(raw, now, langs) {
        Ok(times) => langs.iter().zip(times).map(|(l, t)| format!("{} {t}", l.texts().flag)).collect::<Vec<_>>().join("\n").into(),
        Err(e) => format!("✗ Failed to parse/format datetime: {e}").into(),
    }
}

mod export;
mod server;
mod user;

#[cfg(test)]
mod tests;
