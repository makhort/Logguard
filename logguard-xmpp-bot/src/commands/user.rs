//! Commands of ordinary users about their own account: devices, archive, language,
//! message of the day. Their only target is the sender's account, and ejabberd's error
//! texts (server paths and the like) go to the log, not to the user.

use chrono::{DateTime, Utc};

use serde_json::json;

use super::server::plain_ip;
use super::{bullet_list, Attachment, Bot, Reply, Texts};
use crate::ctl::Ejabberd;
use crate::i18n::{duration, Language};

/// The vCard fields /export reads: `get_vcard` name, or `get_vcard2` name and subname.
const VCARD_FIELDS: [(&str, Option<&str>); 7] =
    [("FN", None), ("NICKNAME", None), ("BDAY", None), ("URL", None), ("DESC", None), ("EMAIL", Some("USERID")), ("TEL", Some("NUMBER"))];

/// A section of /export: its title, then the items as a list, or `none`.
fn section<S: AsRef<str>>(title: &str, items: &[S], none: &str) -> String {
    let title = title.replace("{n}", &items.len().to_string());
    if items.is_empty() {
        format!("{title}\n{none}")
    } else {
        let items: Vec<String> = items.iter().map(|i| i.as_ref().replace("```", "'''")).collect();
        format!("{title}\n{}", bullet_list(&items))
    }
}

fn day(ts: f64) -> String {
    DateTime::from_timestamp(ts as i64, 0).map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or_default()
}

/// `list_invites` lines (token, valid, created, expires, type, inviter, invitee, account,
/// uri, landing page) of invitations `jid` created, without their tokens, and without the
/// accounts they created: those are other people's data.
fn invites_by(out: &str, jid: &str, t: &Texts) -> Vec<String> {
    out.lines()
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .filter(|f| f.len() >= 10 && f[5] == jid && f[4] != "reset_token")
        .map(|f| {
            let state = if !f[6].is_empty() {
                t.invite_used.to_string()
            } else if f[1] == "true" {
                t.invite_open.to_string()
            } else {
                t.invite_expired.to_string()
            };
            let date = |s: &str| s.get(..10).unwrap_or(s).to_string();
            format!("{} → {}: {state}", date(f[2]), date(f[3]))
        })
        .collect()
}

/// One connected device of a user.
#[derive(Debug, PartialEq)]
struct Device {
    resource: String,
    ip: String,
    uptime: Option<i64>,
}

/// `user_sessions_info` lines (connection, ip, port, priority, node, uptime, status,
/// resource, status text), sorted by device name so the numbers stay put.
fn parse_devices(out: &str) -> Vec<Device> {
    let mut devices: Vec<Device> = out
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            (f.len() >= 8).then(|| Device { resource: f[7].to_string(), ip: plain_ip(f[1]).to_string(), uptime: f[5].parse().ok() })
        })
        .collect();
    devices.sort_by(|a, b| a.resource.cmp(&b.resource));
    devices
}

/// `arg` as a number from /devices (1-based) or a device name.
fn pick<'a>(devices: &'a [Device], arg: &str) -> Option<&'a Device> {
    match arg.parse::<usize>() {
        Ok(n) if arg.bytes().all(|b| b.is_ascii_digit()) => n.checked_sub(1).and_then(|i| devices.get(i)),
        _ => devices.iter().find(|d| d.resource == arg),
    }
}

impl<E: Ejabberd> Bot<E> {
    /// The sender's sessions, or the reply when they can't be listed.
    async fn own_devices(&self, who: &str, t: &Texts) -> Result<Vec<Device>, Reply> {
        match self.ctl.run(&["user_sessions_info", who, &self.domain]).await {
            Ok(out) => Ok(parse_devices(&out)),
            Err(e) => {
                log::error!("devices of {who}: {e}");
                Err(t.failed.into())
            }
        }
    }

    /// Numbered, the one the command came from marked, with a reminder to check them.
    pub(super) async fn devices(&self, who: &str, current: Option<&str>, args: &[&str], t: &Texts) -> Reply {
        if !args.is_empty() {
            return format!("{}: /devices", t.usage).into();
        }
        let devices = match self.own_devices(who, t).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        if devices.is_empty() {
            return t.devices_none.into();
        }
        let lines: Vec<String> = devices
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let this = if current == Some(d.resource.as_str()) { format!(" ({})", t.this_device) } else { String::new() };
                let online = d.uptime.map(|s| format!(", {}", t.online_for.replace("{time}", &duration(t, s)))).unwrap_or_default();
                format!("{}. {}{this}\n   {}{online}", i + 1, d.resource, d.ip)
            })
            .collect();
        let title = t.devices_title.replace("{n}", &devices.len().to_string());
        format!("{title}\n```\n{}\n```\n{}", lines.join("\n").replace("```", "'''"), t.devices_footer).into()
    }

    /// By number (from /devices) or device name. The device the command comes from only
    /// with `confirm`: its client logs in again, but that is rarely what was meant.
    pub(super) async fn logout(&self, who: &str, current: Option<&str>, args: &[&str], t: &Texts) -> Reply {
        let (arg, confirmed) = match args {
            [arg] => (*arg, false),
            [arg, "confirm"] => (*arg, true),
            _ => return format!("{}: /logout {}\n{}: /logout 2", t.usage, t.logout_args, t.example).into(),
        };
        let devices = match self.own_devices(who, t).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let Some(device) = pick(&devices, arg) else {
            return t.no_such_device.into();
        };
        if current == Some(device.resource.as_str()) && !confirmed {
            return t.logout_current.replace("{device}", &device.resource).replace("{arg}", arg).into();
        }
        match self.ctl.run(&["kick_session", who, &self.domain, &device.resource, "Disconnected by the account owner"]).await {
            Ok(_) => t.logout_done.replace("{device}", &device.resource).into(),
            Err(e) => {
                log::error!("logout of {who}/{}: {e}", device.resource);
                t.failed.into()
            }
        }
    }

    pub(super) async fn own_storage(&self, who: &str, args: &[&str], t: &Texts) -> Reply {
        if !args.is_empty() {
            return format!("{}: /storage", t.usage).into();
        }
        let mam = self.ctl.run(&["get_mam_count", who, &self.domain]).await;
        let offline = self.ctl.run(&["get_offline_count", who, &self.domain]).await;
        match (mam, offline) {
            (Ok(m), Ok(o)) => t.storage.replace("{mam}", m.trim()).replace("{offline}", o.trim()).into(),
            (Err(e), _) | (_, Err(e)) => {
                log::error!("storage of {who}: {e}");
                t.failed.into()
            }
        }
    }

    /// The sender's whole MAM archive, after `confirm`.
    pub(super) async fn delete_history(&self, who: &str, args: &[&str], t: &Texts) -> Reply {
        if args != ["confirm"] {
            return t.delete_history_ask.into();
        }
        match self.ctl.run(&["remove_mam_for_user", who, &self.domain]).await {
            Ok(_) => {
                log::info!("{who} deleted their message archive");
                t.history_deleted.into()
            }
            Err(e) => {
                log::error!("deleting the archive of {who}: {e}");
                t.failed.into()
            }
        }
    }

    /// Sets the sender's language; the answer comes in the new one.
    pub(super) fn set_own_language(&mut self, who: &str, args: &[&str], t: &Texts) -> Reply {
        let [code] = args else {
            return format!("{}: /lang <EN|FR|GE|PL|RU|UA>\n{}: /lang FR", t.usage, t.example).into();
        };
        let Some(lang) = Language::parse(code) else {
            return t.unknown_language.into();
        };
        match self.state.set_language(who, lang.code()) {
            Ok(()) => lang.texts().lang_set.into(),
            Err(e) => {
                log::error!("saving state: {e:#}");
                t.failed.into()
            }
        }
    }

    /// ejabberdctl for /export: a failure is logged, and the export goes on without it.
    async fn logged(&self, who: &str, args: &[&str]) -> Result<String, String> {
        let r = self.ctl.run(args).await;
        if let Err(e) = &r {
            log::warn!("export for {who}: {}: {e}", args[0]);
        }
        r
    }

    /// What the server and the bot hold about the sender (GDPR art. 15): a summary as the
    /// reply, as far as ejabberdctl can read it per user, and, with the database set
    /// (EJABBERD_DB), everything about the sender's own account as a JSON file (see
    /// [`super::export`]: only the sender's data).
    pub(super) async fn export(
        &self,
        who: &str,
        args: &[&str],
        t: &Texts,
        now: DateTime<Utc>,
        attachment: &mut Option<Attachment>,
    ) -> Reply {
        if !args.is_empty() {
            return format!("{}: /export", t.usage).into();
        }
        let d = self.domain.as_str();
        let jid = format!("{who}@{d}");
        let mut parts = vec![t
            .export_title
            .replace("{domain}", d)
            .replace("{jid}", &jid)
            .replace("{date}", &now.format("%Y-%m-%d %H:%M UTC").to_string())];

        let last = match self.logged(who, &["get_last", who, d]).await {
            Ok(out) => {
                let mut f = out.split('\t');
                let (ts, status) = (f.next().unwrap_or("").trim(), f.next().unwrap_or("").trim());
                if status.eq_ignore_ascii_case("online") {
                    t.export_online.to_string()
                } else {
                    DateTime::parse_from_rfc3339(ts)
                        .map(|x| x.with_timezone(&Utc).format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_else(|_| out.trim().to_string())
                }
            }
            Err(_) => "?".into(),
        };
        parts.push(format!("{}\n{}", t.export_account, t.export_last.replace("{time}", &last)));

        // missing fields are errors for ejabberd: simply left out
        let values = futures::future::join_all(VCARD_FIELDS.iter().map(|&(name, sub)| async move {
            let r = match sub {
                None => self.ctl.run(&["get_vcard", who, d, name]).await,
                Some(sub) => self.ctl.run(&["get_vcard2", who, d, name, sub]).await,
            };
            r.ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
        }))
        .await;
        let profile: Vec<String> = t.vcard_labels.iter().zip(values).filter_map(|(label, v)| v.map(|v| format!("{label}: {v}"))).collect();
        parts.push(section(t.export_profile, &profile, t.export_none));

        let contacts: Vec<String> = self
            .logged(who, &["get_roster", who, d])
            .await
            .unwrap_or_default()
            .lines()
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .filter(|f| !f[0].trim().is_empty())
            .map(|f| match f.get(1).map(|n| n.trim()).filter(|n| !n.is_empty()) {
                Some(nick) => format!("{} ({nick})", f[0]),
                None => f[0].to_string(),
            })
            .collect();
        parts.push(section(t.export_contacts, &contacts, t.export_none));

        let rooms: Vec<String> = self
            .logged(who, &["get_user_rooms", who, d])
            .await
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        parts.push(section(t.export_rooms, &rooms, t.export_none));

        let sessions = self.logged(who, &["user_sessions_info", who, d]).await.map(|out| parse_devices(&out)).unwrap_or_default();
        let devices: Vec<String> = sessions.iter().map(|dev| format!("{}, {}", dev.resource, dev.ip)).collect();
        parts.push(section(t.export_devices, &devices, t.export_none));

        let count = |r: Result<String, String>| r.map(|s| s.trim().to_string()).unwrap_or_else(|_| "?".into());
        let mam = count(self.logged(who, &["get_mam_count", who, d]).await);
        let offline = count(self.logged(who, &["get_offline_count", who, d]).await);
        parts.push(format!("{}\n{}", t.export_messages, t.storage.replace("{mam}", &mam).replace("{offline}", &offline)));

        let invites = invites_by(&self.logged(who, &["list_invites", d]).await.unwrap_or_default(), &jid, t);
        parts.push(section(t.export_invites, &invites, t.export_none));

        let reports: Vec<String> =
            self.state.reports_by(who).into_iter().map(|(user, ts, reason)| format!("{user}, {}: {reason}", day(ts))).collect();
        let mut bot = format!("{}\n{}", t.export_bot, t.export_language.replace("{lang}", self.language_of(&jid).code()));
        bot.push('\n');
        bot.push_str(&section(t.export_reports_by, &reports, t.export_none));
        bot.push('\n');
        bot.push_str(&t.export_reports_about.replace("{n}", &self.state.reporters_for_abuser(who).len().to_string()));
        parts.push(bot);

        let r = self.retention;
        parts.push(t.export_footer.replace("{messages}", &r.messages.to_string()).replace("{files}", &r.files.to_string()));

        if self.ctl.has_db() && super::export::plain_username(who) {
            let reports: Vec<_> = self
                .state
                .reports_by(who)
                .into_iter()
                .map(|(user, ts, reason)| json!({ "account": user, "date": day(ts), "reason": reason }))
                .collect();
            let file = json!({
                "format": "logguard-xmpp-bot export 1",
                "account": jid,
                "created": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "about": "What the server holds about this account, and only about it. Columns are ejabberd's own; times are UTC. \
                          Messages sent OMEMO-encrypted are stored encrypted: only your devices can read them.",
                "retention_days": {
                    "messages": r.messages, "files": r.files, "unused_accounts": r.accounts, "unused_group_chats": r.rooms,
                },
                "not_included": [
                    "password hashes, login and invitation tokens, push registration secrets",
                    "group chat archives and member lists (they are the rooms', with other people's messages)",
                    "who subscribed to your published items, and which accounts your invitations created",
                    "files you uploaded (linked in your chats)",
                    "server logs",
                ],
                "connected_devices": sessions.iter().map(|dev| json!({ "device": dev.resource, "address": dev.ip })).collect::<Vec<_>>(),
                "group_chats_joined": rooms,
                "bot": {
                    "language": self.language_of(&jid).code(),
                    "abuse_reports_by_you": reports,
                    "reports_about_you": self.state.reporters_for_abuser(who).len(),
                },
                "database": super::export::database_sections(&self.ctl, who, d).await,
            });
            match serde_json::to_vec_pretty(&file) {
                Ok(data) => *attachment = Some(Attachment { filename: format!("export-{who}-{}.json", now.format("%Y-%m-%d")), data }),
                Err(e) => log::error!("export for {who}: {e}"),
            }
        }
        Reply::secret(parts.join("\n\n"))
    }

    pub(super) async fn motd(&self, args: &[&str], t: &Texts) -> Reply {
        if !args.is_empty() {
            return format!("{}: /motd", t.usage).into();
        }
        match self.ctl.run(&["announce_motd_get", &self.domain]).await {
            Ok(out) if out.trim().is_empty() => t.motd_none.into(),
            Ok(out) => out.trim().to_string().into(),
            Err(e) => {
                log::error!("motd: {e}");
                t.failed.into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_are_sorted_and_picked_by_number_or_name() {
        let out = "c2s_tls\t::ffff:203.0.113.41\t54794\t0\tejabberd@localhost\t2272\taway\tphone\t\n\
                   c2s_tls\t2001:db8::7\t40000\t0\tejabberd@localhost\t90000\tavailable\tdesktop\t\n";
        let d = parse_devices(out);
        assert_eq!(d.iter().map(|d| d.resource.as_str()).collect::<Vec<_>>(), ["desktop", "phone"]);
        assert_eq!(d[1].ip, "203.0.113.41");
        assert_eq!(pick(&d, "2").unwrap().resource, "phone");
        assert_eq!(pick(&d, "desktop").unwrap().resource, "desktop");
        assert!(pick(&d, "0").is_none());
        assert!(pick(&d, "3").is_none());
        assert!(pick(&d, "Desktop").is_none());
    }
}
