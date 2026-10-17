//! Admin commands around ejabberd itself: status, sessions, bans, spam domains,
//! maintenance. Commands that change or delete data want a final `confirm`.

use std::net::IpAddr;

use chrono::{DateTime, NaiveDateTime, Utc};

use super::{bullet_list, local_part, Bot, Reply, Texts};
use crate::ctl::Ejabberd;
use crate::timefmt::elapsed_time;

/// Longer ejabberdctl output is cut, to keep a chat message readable.
const MAX_OUTPUT: usize = 3500;
/// What the batch purges delete per round, and per minute at most.
const PURGE_BATCH: &str = "1000";
const PURGE_RATE: &str = "10000";

/// ejabberdctl output as a preformatted block under a title.
fn block(title: &str, out: &str) -> Reply {
    let out = out.trim().replace("```", "'''");
    if out.is_empty() {
        return format!("✓ {title}: none.").into();
    }
    let mut text: String = out.chars().take(MAX_OUTPUT).collect();
    if text.len() < out.len() {
        text.push_str("\n… (cut)");
    }
    format!("✓ {title}:\n```\n{text}\n```").into()
}

fn failed(what: &str, e: String) -> Reply {
    format!("✗ Failed to {what}: {e}").into()
}

/// Days for the purges: a whole number from 1 to 36500.
fn days(arg: &str) -> Option<u32> {
    arg.parse().ok().filter(|d| (1..=36500).contains(d))
}

/// `<value> confirm`: the value if the confirmation is there.
fn confirmed<'a>(args: &[&'a str]) -> Option<&'a str> {
    match args {
        [value, "confirm"] => Some(value),
        _ => None,
    }
}

fn is_domain(d: &str) -> bool {
    d.contains('.')
        && d.len() <= 253
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// An IP address, optionally with a prefix length (`unban_ip` takes networks).
fn is_ip_or_network(a: &str) -> bool {
    match a.split_once('/') {
        Some((ip, len)) => match (ip.parse::<IpAddr>(), len.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(l)) => l <= 32,
            (Ok(IpAddr::V6(_)), Ok(l)) => l <= 128,
            _ => false,
        },
        None => a.parse::<IpAddr>().is_ok(),
    }
}

/// `list_certificates` lines (domain, file, used) grouped by file: (file, domains, used).
fn parse_certificates(out: &str) -> Vec<(String, Vec<String>, bool)> {
    let mut certs: Vec<(String, Vec<String>, bool)> = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let [domain, file, used] = f[..] else { continue };
        match certs.iter_mut().find(|c| c.0 == file) {
            Some(c) => c.1.push(domain.to_string()),
            None => certs.push((file.to_string(), vec![domain.to_string()], used == "true")),
        }
    }
    certs
}

/// `notAfter=Jan 10 17:29:37 2027 GMT`
fn parse_not_after(s: &str) -> Result<DateTime<Utc>, String> {
    let v = s.trim().strip_prefix("notAfter=").unwrap_or(s.trim());
    let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
    NaiveDateTime::parse_from_str(&v, "%b %d %H:%M:%S %Y GMT").map(|t| t.and_utc()).map_err(|_| format!("unexpected date {v:?}"))
}

/// `::ffff:1.2.3.4` is an IPv4 client on a dual-stack listener.
pub(super) fn plain_ip(ip: &str) -> &str {
    ip.strip_prefix("::ffff:").unwrap_or(ip)
}

/// `user_sessions_info` lines: connection, ip, port, priority, node, uptime, status,
/// resource, status text.
fn format_sessions(out: &str) -> Option<Vec<String>> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 8 {
                return None;
            }
            let uptime = f[5].parse().map(elapsed_time).unwrap_or_else(|_| f[5].to_string());
            let text = f.get(8).map(|t| t.trim()).filter(|t| !t.is_empty()).map(|t| format!(", \"{t}\"")).unwrap_or_default();
            Some(format!("{} ({}{text})\n  {}:{} {}, {uptime}", f[7], f[6], plain_ip(f[1]), f[2], f[0]))
        })
        .collect()
}

/// `get_roster` lines: jid, nick, subscription, pending, groups.
fn format_roster(out: &str) -> Option<Vec<String>> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 4 {
                return None;
            }
            let mut s = f[0].to_string();
            if !f[1].is_empty() {
                s.push_str(&format!(" ({})", f[1]));
            }
            s.push_str(&format!(" — {}", f[2]));
            if !matches!(f[3], "none" | "undefined" | "") {
                s.push_str(&format!(", pending {}", f[3]));
            }
            if let Some(g) = f.get(4).map(|g| g.trim()).filter(|g| !g.is_empty()) {
                s.push_str(&format!(" [{g}]"));
            }
            Some(s)
        })
        .collect()
}

/// `get_ban_details` lines: name, value.
fn format_ban_details(out: &str) -> String {
    out.lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(name, value)| {
            let label = match name {
                "reason" => "Reason",
                "bandate" => "Banned",
                "lastdate" => "Last login",
                "lastreason" => "Last disconnect",
                other => other,
            };
            let value = match DateTime::parse_from_rfc3339(value) {
                Ok(t) => t.with_timezone(&Utc).format("%Y-%m-%d %H:%M UTC").to_string(),
                Err(_) => value.to_string(),
            };
            format!("{label}: {value}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `list_invites` lines: token, valid, created_at, expires, type, inviter, invitee,
/// account_name, token_uri, landing_page.
fn format_invites(out: &str) -> Option<Vec<String>> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 10 {
                return None;
            }
            let state = if f[1] == "true" { "valid" } else { "expired or used" };
            let kind = match f[4] {
                "reset_token" => format!("Password reset for '{}'", f[7]),
                "account_only" | "account_subscription" => match f[7] {
                    "" => "Account invitation".to_string(),
                    name => format!("Account invitation for '{name}'"),
                },
                "roster_only" => "Contact invitation".to_string(),
                other => other.to_string(),
            };
            let by = if f[5].is_empty() || f[5].starts_with('@') { String::new() } else { format!(" by {}", f[5]) };
            let used = if f[6].is_empty() { String::new() } else { format!(", used by {}", f[6]) };
            Some(format!("• {kind}{by}: {state}, expires {}{used}\n{}", f[3], f[9]))
        })
        .collect()
}

impl<E: Ejabberd> Bot<E> {
    /// The username in `args` (exactly one, of an existing account), or the reply to send.
    async fn one_user(&self, args: &[&str], usage: &str) -> Result<String, Reply> {
        let [arg] = args else { return Err(usage.into()) };
        self.username(arg, true).await
    }

    pub(super) async fn status(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /status".into();
        }
        let status = match self.ctl.run(&["status"]).await {
            Ok(s) => s,
            Err(e) => return failed("get the server status", e),
        };
        let stat = |name: &'static str| async move { self.ctl.run(&["stats", name]).await.ok().and_then(|v| v.trim().parse::<i64>().ok()) };
        let uptime = stat("uptimeseconds").await.map(elapsed_time).unwrap_or_else(|| "?".into());
        let registered = stat("registeredusers").await.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
        let online = stat("onlineusers").await.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
        format!("✓ {}\nUptime: {uptime}\nRegistered users: {registered}\nOnline sessions: {online}", status.trim()).into()
    }

    pub(super) async fn certs(&self, args: &[&str], now: DateTime<Utc>) -> Reply {
        if !args.is_empty() {
            return "Usage: /certs".into();
        }
        let out = match self.ctl.run(&["list_certificates"]).await {
            Ok(out) => out,
            Err(e) => return failed("list certificates", e),
        };
        let certs = parse_certificates(&out);
        if certs.is_empty() {
            return block("Certificates", &out);
        }
        let mut lines = Vec::new();
        for (file, domains, used) in certs {
            let expiry = match self.ctl.cert_end_date(&file).await.and_then(|d| parse_not_after(&d)) {
                Ok(t) => {
                    let days = (t - now).num_days();
                    let warn = if days < 21 { "⚠️ " } else { "" };
                    format!("{warn}expires {} ({days} days)", t.format("%Y-%m-%d"))
                }
                Err(e) => format!("expiry unknown: {e}"),
            };
            let used = if used { "" } else { ", not in use" };
            lines.push(format!("• {}\n  {expiry}{used}", domains.join(", ")));
        }
        format!("✓ Certificates:\n```\n{}\n```", lines.join("\n")).into()
    }

    pub(super) async fn sessions(&self, args: &[&str]) -> Reply {
        let u = match self.one_user(args, "Usage: /sessions <username>\nExample: /sessions john").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.ctl.run(&["user_sessions_info", &u, &self.domain]).await {
            Ok(out) if out.trim().is_empty() => format!("✓ '{u}' is not connected.").into(),
            Ok(out) => match format_sessions(&out) {
                Some(lines) => format!("✓ Sessions of '{u}' ({}):\n{}", lines.len(), bullet_list(&lines)).into(),
                None => block(&format!("Sessions of '{u}'"), &out),
            },
            Err(e) => failed("get sessions", e),
        }
    }

    pub(super) async fn roster(&self, args: &[&str]) -> Reply {
        let u = match self.one_user(args, "Usage: /roster <username>\nExample: /roster john").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.ctl.run(&["get_roster", &u, &self.domain]).await {
            Ok(out) if out.trim().is_empty() => format!("✓ '{u}' has no contacts.").into(),
            Ok(out) => match format_roster(&out) {
                Some(lines) => format!("✓ Contacts of '{u}' ({}):\n{}", lines.len(), bullet_list(&lines)).into(),
                None => block(&format!("Roster of '{u}'"), &out),
            },
            Err(e) => failed("get the roster", e),
        }
    }

    pub(super) async fn storage(&self, args: &[&str]) -> Reply {
        let u = match self.one_user(args, "Usage: /storage <username>\nExample: /storage john").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let mam = self.ctl.run(&["get_mam_count", &u, &self.domain]).await;
        let offline = self.ctl.run(&["get_offline_count", &u, &self.domain]).await;
        let show = |r: Result<String, String>| r.map(|s| s.trim().to_string()).unwrap_or_else(|e| format!("? ({e})"));
        format!("✓ '{u}': {} archived messages, {} offline messages.", show(mam), show(offline)).into()
    }

    pub(super) async fn baninfo(&self, args: &[&str]) -> Reply {
        let u = match self.one_user(args, "Usage: /baninfo <username>\nExample: /baninfo john").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match self.ctl.run(&["get_ban_details", &u, &self.domain]).await {
            Ok(out) if out.trim().is_empty() => format!("✓ '{u}' is not banned.").into(),
            Ok(out) => format!("✓ Ban of '{u}':\n{}", format_ban_details(&out)).into(),
            Err(e) => failed("get ban details", e),
        }
    }

    pub(super) async fn kick(&self, args: &[&str]) -> Reply {
        let usage = "Usage: /kick <username> [resource]\nExample: /kick john\nExample: /kick john phone";
        let (arg, resource) = match args {
            [arg] => (arg, None),
            [arg, resource] => (arg, Some(*resource)),
            _ => return usage.into(),
        };
        let u = match self.target(arg, "kick").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        match resource {
            None => match self.ctl.run(&["kick_user", &u, &self.domain]).await {
                // "Kicked sessions: 2"
                Ok(out) => {
                    let n = out.trim().rsplit(' ').next().unwrap_or("?").to_string();
                    format!("✓ '{u}': {n} session(s) disconnected.").into()
                }
                Err(e) => failed("kick the user", e),
            },
            Some(r) => match self.ctl.run(&["kick_session", &u, &self.domain, r, "Disconnected by the admin"]).await {
                Ok(_) => format!("✓ '{u}/{r}' disconnected.").into(),
                Err(e) => failed("kick the session", e),
            },
        }
    }

    pub(super) async fn unban_ip(&self, args: &[&str]) -> Reply {
        let [address] = args else {
            return "Usage: /unban_ip <address>\nExample: /unban_ip 203.0.113.7\nExample: /unban_ip 203.0.113.0/24".into();
        };
        if !is_ip_or_network(address) {
            return "✗ Not an IP address or network.".into();
        }
        // the number of unbanned addresses; negative on error
        match self.ctl.run(&["unban_ip", address]).await.map(|o| o.trim().parse::<i64>()) {
            Ok(Ok(n)) if n >= 0 => format!("✓ fail2ban: {n} banned address(es) in {address} lifted.").into(),
            Ok(Ok(n)) => format!("✗ fail2ban reported an error ({n}).").into(),
            Ok(Err(_)) => "✗ Unexpected unban_ip output.".into(),
            Err(e) => failed("unban the address", e),
        }
    }

    /// A single-use mod_invites link where `u` sets a new password: the web page, and
    /// the xmpp: URI for clients that handle it, after `intro` and `xmpp_label`.
    async fn reset_link(&self, u: &str, intro: &str, xmpp_label: &str) -> Result<Reply, String> {
        let out = self.ctl.run(&["generate_reset_token", u, &self.domain]).await?;
        let words: Vec<&str> = out.split_whitespace().collect();
        let web = words.iter().find(|w| w.starts_with("https://"));
        let xmpp = words.iter().find(|w| w.starts_with("xmpp:"));
        let text = match (web, xmpp) {
            (Some(web), xmpp) => {
                let mut text = format!("{intro}\n{web}");
                if let Some(x) = xmpp {
                    text.push_str(&format!("\n{xmpp_label}\n{x}"));
                }
                text
            }
            // not the expected output: as it is
            _ => format!("{intro}\n```\n{}\n```", out.trim().replace("```", "'''")),
        };
        Ok(Reply::secret(text))
    }

    pub(super) async fn resetlink(&self, args: &[&str]) -> Reply {
        let [arg] = args else { return "Usage: /resetlink <username>\nExample: /resetlink john".into() };
        let u = match self.target(arg, "reset the password of").await {
            Ok(u) => u,
            Err(r) => return r,
        };
        let intro = format!("✓ Password reset link for '{u}' (single use; valid for the invitation lifetime, 5 days by default):");
        self.reset_link(&u, &intro, "For XMPP clients that support it:").await.unwrap_or_else(|e| failed("create a reset link", e))
    }

    /// `/resetlink` of a user: for their own account only.
    pub(super) async fn own_reset_link(&self, who: &str, args: &[&str], t: &Texts) -> Reply {
        if !args.is_empty() {
            return format!("{}: /resetlink", t.usage).into();
        }
        if self.guard(who, "reset the password of").is_err() {
            return t.reset_link_failed.into();
        }
        match self.reset_link(who, t.reset_link, t.reset_link_xmpp).await {
            Ok(r) => r,
            Err(e) => {
                // ejabberd's errors are for the admin
                log::error!("reset link for {who}: {e}");
                t.reset_link_failed.into()
            }
        }
    }

    pub(super) async fn invites(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /invites".into();
        }
        match self.ctl.run(&["list_invites", &self.domain]).await {
            Ok(out) if out.trim().is_empty() => "✓ No invitations or reset links.".into(),
            Ok(out) => match format_invites(&out) {
                // links stay outside the block, so they can be tapped
                Some(items) => format!("✓ Invitations and reset links ({}):\n\n{}", items.len(), items.join("\n\n")).into(),
                None => block("Invitations and reset links", &out),
            },
            Err(e) => failed("list invites", e),
        }
    }

    pub(super) async fn spam_domains(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /spam_domains".into();
        }
        match self.ctl.run(&["get_blocked_domains", &self.domain]).await {
            Ok(out) => {
                let items: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                if items.is_empty() {
                    "✓ No blocked domains.".into()
                } else {
                    format!("✓ Blocked domains ({}):\n{}", items.len(), bullet_list(&items)).into()
                }
            }
            Err(e) => failed("list blocked domains", e),
        }
    }

    pub(super) async fn block_domain(&self, args: &[&str], block: bool) -> Reply {
        let name = if block { "block_domain" } else { "unblock_domain" };
        let [domain] = args else {
            return format!("Usage: /{name} <domain>\nExample: /{name} spam.example").into();
        };
        let domain = domain.to_lowercase();
        if !is_domain(&domain) {
            return "✗ Not a domain name.".into();
        }
        if domain == self.domain {
            return "✗ Can not block this server's own domain.".into();
        }
        let command = if block { "add_blocked_domain" } else { "remove_blocked_domain" };
        match self.ctl.run(&[command, &self.domain, &domain]).await {
            Ok(_) => format!("✓ '{domain}' {}.", if block { "blocked" } else { "unblocked" }).into(),
            Err(e) => failed(if block { "block the domain" } else { "unblock the domain" }, e),
        }
    }

    pub(super) async fn purge_mam(&self, args: &[&str]) -> Reply {
        let usage = "Usage: /purge_mam <days> confirm\nExample: /purge_mam 365 confirm";
        let Some(d) = confirmed(args).and_then(days) else {
            return match args.first().and_then(|a| days(a)) {
                Some(d) => {
                    format!(
                        "This deletes every user's and every group chat's archived messages older than {d} days. To proceed:\n`/purge_mam {d} confirm`"
                    )
                    .into()
                }
                None => usage.into(),
            };
        };
        let d = d.to_string();
        match self.ctl.run(&["delete_old_mam_messages_batch", &self.domain, "all", &d, PURGE_BATCH, PURGE_RATE]).await {
            Ok(out) => format!("✓ Started: {}\nProgress: /purge_status", out.trim()).into(),
            Err(e) => failed("start the purge", e),
        }
    }

    pub(super) async fn purge_offline(&self, args: &[&str]) -> Reply {
        let usage = "Usage: /purge_offline <days> confirm\nExample: /purge_offline 90 confirm";
        let Some(d) = confirmed(args).and_then(days) else {
            return match args.first().and_then(|a| days(a)) {
                Some(d) => {
                    format!("This deletes undelivered offline messages older than {d} days. To proceed:\n`/purge_offline {d} confirm`")
                        .into()
                }
                None => usage.into(),
            };
        };
        let d = d.to_string();
        match self.ctl.run(&["delete_old_messages_batch", &self.domain, &d, PURGE_BATCH, PURGE_RATE]).await {
            Ok(out) => format!("✓ Started: {}\nProgress: /purge_status", out.trim()).into(),
            Err(e) => failed("start the purge", e),
        }
    }

    pub(super) async fn purge_status(&self, args: &[&str]) -> Reply {
        if !args.is_empty() {
            return "Usage: /purge_status".into();
        }
        let show = |r: Result<String, String>| match r {
            Ok(s) => s.trim().to_string(),
            Err(e) => format!("? ({e})"),
        };
        let mam = show(self.ctl.run(&["delete_old_mam_messages_status", &self.domain]).await);
        let offline = show(self.ctl.run(&["delete_old_messages_status", &self.domain]).await);
        format!("✓ Archive purge: {mam}\nOffline purge: {offline}").into()
    }

    /// The bot's own archive, and every user's archived chats with the bot.
    pub(super) async fn purge_bot_chats(&self, args: &[&str]) -> Reply {
        if args != ["confirm"] {
            return "This deletes the bot's message archive and every user's archived chats with the bot. To proceed:\n`/purge_bot_chats confirm`"
                .into();
        }
        let users = match self.ctl.run(&["registered_users", &self.domain]).await {
            Ok(out) => out.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect::<Vec<_>>(),
            Err(e) => return failed("list users", e),
        };
        let bot_user = local_part(&self.bot_jid).to_string();
        let mut failures = Vec::new();
        if let Err(e) = self.ctl.run(&["remove_mam_for_user", &bot_user, &self.domain]).await {
            failures.push(format!("{bot_user}: {e}"));
        }
        for u in users.iter().filter(|u| **u != bot_user) {
            if let Err(e) = self.ctl.run(&["remove_mam_for_user_with_peer", u, &self.domain, &self.bot_jid]).await {
                failures.push(format!("{u}: {e}"));
            }
        }
        if failures.is_empty() {
            format!("✓ Archived chats with the bot deleted ({} users and the bot).", users.len().saturating_sub(1)).into()
        } else {
            format!("✗ Some archives were not cleaned:\n{}", bullet_list(&failures)).into()
        }
    }

    /// `restart_kindly` waits out the delay before restarting, so it runs in the
    /// background: it stops accepting new logins at once, announces, waits, restarts.
    pub(super) async fn restart(&self, args: &[&str]) -> Reply {
        let usage = "Usage: /restart <minutes> confirm\nExample: /restart 5 confirm";
        let Some(minutes) = confirmed(args).and_then(|m| m.parse::<u32>().ok()).filter(|m| (1..=60).contains(m)) else {
            return match args.first().and_then(|a| a.parse::<u32>().ok()).filter(|m| (1..=60).contains(m)) {
                Some(m) => format!(
                    "This stops new logins now, tells everyone online, and restarts ejabberd in {m} min. To proceed:\n`/restart {m} confirm`"
                )
                .into(),
                None => usage.into(),
            };
        };
        let announcement = self.multilingual(|t| t.restart_notice.replace("{minutes}", &minutes.to_string()), "\n");
        if let Err(e) = self.ctl.start_restart(&["restart_kindly", &(minutes * 60).to_string(), &announcement]).await {
            return failed("schedule the restart", e);
        }
        format!("✓ Restart in {minutes} min: new logins are refused from now, users are told. The bot reconnects after the restart.").into()
    }

    pub(super) async fn reload_config(&self, args: &[&str]) -> Reply {
        if args != ["confirm"] {
            return "This reloads ejabberd.yml; a broken file can take services down. To proceed:\n`/reload_config confirm`".into();
        }
        match self.ctl.run(&["reload_config"]).await {
            Ok(_) => "✓ Configuration reloaded.".into(),
            Err(e) => failed("reload the configuration", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_checks() {
        assert_eq!(days("365"), Some(365));
        assert_eq!(days("0"), None);
        assert_eq!(days("-1"), None);
        assert_eq!(days("x"), None);
        assert_eq!(confirmed(&["30", "confirm"]), Some("30"));
        assert_eq!(confirmed(&["30"]), None);
        assert_eq!(confirmed(&["30", "yes"]), None);
        assert!(is_domain("spam.example"));
        assert!(is_domain("a-b.c.example"));
        assert!(!is_domain("localhost"));
        assert!(!is_domain("bad_domain.example"));
        assert!(!is_domain("x..example"));
        assert!(is_ip_or_network("203.0.113.7"));
        assert!(is_ip_or_network("203.0.113.0/24"));
        assert!(is_ip_or_network("2001:db8::1"));
        assert!(is_ip_or_network("2001:db8::/32"));
        assert!(!is_ip_or_network("203.0.113.0/33"));
        assert!(!is_ip_or_network("example.org"));
    }

    #[test]
    fn blocks_are_cut_and_cannot_be_escaped() {
        assert_eq!(block("X", " \n").text, "✓ X: none.");
        assert_eq!(block("X", "a\n```\nb").text, "✓ X:\n```\na\n'''\nb\n```");
        let long = "y".repeat(MAX_OUTPUT + 10);
        assert!(block("X", &long).text.ends_with("… (cut)\n```"));
    }
}
