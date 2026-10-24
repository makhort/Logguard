use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use chrono::TimeZone;

use super::*;

const ADMIN: &str = "admin@example.org";
const ALICE: &str = "alice@example.org";

/// ejabberd as far as the commands see it: accounts plus canned command outputs.
#[derive(Default)]
struct Fake {
    accounts: RefCell<HashSet<String>>,
    outputs: HashMap<&'static str, Result<String, String>>,
    calls: RefCell<Vec<Vec<String>>>,
    /// A real SQLite file for query_db (read with the sqlite3 tool, as on the server).
    db: Option<std::path::PathBuf>,
}

impl Ejabberd for Fake {
    async fn query_db(&self, sql: &str) -> Result<String, String> {
        let ctl = crate::ctl::Ejabberdctl { path: "/bin/false".into(), run_as: None, db: self.db.clone(), sqlite3: "sqlite3".into() };
        ctl.query_db(sql).await
    }

    fn has_db(&self) -> bool {
        self.db.is_some()
    }

    async fn cert_end_date(&self, file: &str) -> Result<String, String> {
        self.calls.borrow_mut().push(vec!["openssl".into(), file.into()]);
        self.outputs.get("openssl").cloned().unwrap_or(Err("no such file".into()))
    }

    async fn start_restart(&self, args: &[&str]) -> Result<(), String> {
        self.calls.borrow_mut().push(args.iter().map(|s| s.to_string()).collect());
        self.outputs.get("restart_kindly").cloned().unwrap_or(Ok(String::new())).map(drop)
    }

    async fn run(&self, args: &[&str]) -> Result<String, String> {
        self.calls.borrow_mut().push(args.iter().map(|s| s.to_string()).collect());
        let mut accounts = self.accounts.borrow_mut();
        match args {
            ["check_account", u, "example.org"] => {
                if accounts.contains(*u) {
                    Ok(String::new())
                } else {
                    Err("no such account".into())
                }
            }
            ["register", u, "example.org", _] => {
                if let Some(r) = self.outputs.get("register") {
                    return r.clone();
                }
                accounts.insert(u.to_string());
                Ok(String::new())
            }
            ["unregister", u, "example.org"] => {
                accounts.remove(*u);
                Ok(String::new())
            }
            [cmd, ..] => self.outputs.get(cmd).cloned().unwrap_or(Ok(String::new())),
            [] => unreachable!(),
        }
    }
}

fn bot(name: &str, accounts: &[&str]) -> Bot<Fake> {
    let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-cmd-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let _ = std::fs::remove_file(&path);
    let ctl = Fake::default();
    ctl.accounts.borrow_mut().extend(accounts.iter().map(|s| s.to_string()));
    Bot {
        domain: "example.org".into(),
        retention: Retention::default(),
        invite_url: "https://example.org:5281/invites".into(),
        admin_jid: ADMIN.into(),
        bot_jid: "bot@example.org".into(),
        state: State::load(&path).unwrap(),
        ctl,
        announce_languages: crate::i18n::parse_languages("EN,FR,RU,UK").unwrap(),
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 13, 12, 0, 0).unwrap()
}

async fn say(bot: &mut Bot<Fake>, from: &str, text: &str) -> Option<String> {
    bot.process(from, text, now()).await.map(|r| r.reply.text)
}

fn last_call(bot: &Bot<Fake>) -> Vec<String> {
    bot.ctl.calls.borrow().last().cloned().unwrap()
}

#[tokio::test]
async fn strangers_are_ignored_and_parsing_errors_answered() {
    let mut b = bot("access", &["alice"]);
    assert_eq!(say(&mut b, ALICE, "/help").await, None);
    assert_eq!(say(&mut b, "admin@evil.org", "/help").await, None);
    assert_eq!(say(&mut b, ADMIN, "help").await.unwrap(), "Commands must start with '/'. Type '/help'.");
    assert_eq!(say(&mut b, ADMIN, "/").await.unwrap(), "No command specified. Type '/help'.");
    assert_eq!(say(&mut b, ADMIN, "/ban 'x").await.unwrap(), "Command parsing error: No closing quotation");
    assert_eq!(say(&mut b, ADMIN, "/nope").await.unwrap(), "Unknown command: 'nope'. Type '/help'.");
    assert!(say(&mut b, ADMIN, "/HELP").await.unwrap().starts_with("*Accounts*\n`/add <username>` — register user"));
}

#[tokio::test]
async fn admin_and_user_command_sets_are_separate() {
    let mut b = bot("sets", &["alice"]);
    assert_eq!(say(&mut b, ADMIN, "/allow alice").await.unwrap(), "✓ User 'alice' now has access to bot (language: EN).");
    assert_eq!(say(&mut b, ALICE, "/add bob").await.unwrap(), "Unknown command: 'add'. Type '/help'.");
    assert!(say(&mut b, ALICE, "/help").await.unwrap().starts_with("`/invite` — invite someone"));
    assert_eq!(say(&mut b, ADMIN, "/allowed").await.unwrap(), "✓ Users with access to bot (1):\n```\n• alice (EN)\n```");
    assert_eq!(say(&mut b, ADMIN, "/deny alice@example.org").await.unwrap(), "✓ User 'alice' will not have access to bot.");
    assert_eq!(say(&mut b, ALICE, "/help").await, None);
}

#[tokio::test]
async fn add_registers_with_a_generated_password() {
    let mut b = bot("add", &["admin", "alice"]);
    let r = b.process(ADMIN, "/add bob@elsewhere.net", now()).await.unwrap().reply;
    let call = last_call(&b);
    assert_eq!(call[..3], ["register", "bob", "example.org"]);
    assert_eq!(r.text, format!("✓ User 'bob' registered.\nLogin: `bob@example.org`\nPassword: `{}`", call[3]));

    assert_eq!(say(&mut b, ADMIN, "/add alice").await.unwrap(), INVALID_USERNAME);
    assert_eq!(say(&mut b, ADMIN, "/add a!").await.unwrap(), INVALID_USERNAME);
    assert_eq!(say(&mut b, ADMIN, "/add").await.unwrap(), "Usage: `/add <username>`\nExample: `/add john`");
    assert!(r.secret, "a password: not into offline storage when unencrypted");
    assert_eq!(say(&mut b, ADMIN, "/remove admin").await.unwrap(), "✗ Can not remove 'admin': the admin's account.");
    assert_eq!(say(&mut b, ADMIN, "/remove bob").await.unwrap(), "✓ User 'bob' removed.");
    assert_eq!(say(&mut b, ADMIN, "/remove bob").await.unwrap(), INVALID_USERNAME);
}

/// An account that exists is named however ejabberd let it be named (two letters, a `+`):
/// the bot's own rule is only for the accounts /add creates.
#[tokio::test]
async fn existing_accounts_go_by_ejabberds_rules() {
    let mut b = bot("short-names", &["an", "jean+paul"]);
    assert_eq!(say(&mut b, ADMIN, "/allow an").await.unwrap(), "✓ User 'an' now has access to bot (language: EN).");
    assert_eq!(say(&mut b, ADMIN, "/deny AN@example.org").await.unwrap(), "✓ User 'an' will not have access to bot.");
    assert_eq!(say(&mut b, ADMIN, "/allow jean+paul").await.unwrap(), "✓ User 'jean+paul' now has access to bot (language: EN).");
    assert_eq!(say(&mut b, ADMIN, "/remove an").await.unwrap(), "✓ User 'an' removed.");
    assert_eq!(say(&mut b, ADMIN, "/allow an").await.unwrap(), INVALID_USERNAME, "gone");
    assert_eq!(say(&mut b, ADMIN, "/add jo").await.unwrap(), INVALID_USERNAME, "a new account: the bot's rule");
    // what ejabberd's names never hold, and so never reaches ejabberdctl
    for bad in ["", "a\"b", "a'b", "a b", "a/b", "a:b", "a<b", "a&b", "a\nb"] {
        assert_eq!(normalize_username(bad), None, "{bad:?}");
    }
}

#[test]
fn passwords_and_usernames() {
    let p = generate_password();
    assert_eq!(p.len(), 19);
    assert!(p.split('-').all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_alphanumeric())));
    assert_ne!(p, generate_password());
    assert!(is_valid_username("jo.hn_doe-1"));
    assert!(is_valid_username("иван"));
    assert!(!is_valid_username("jo"));
    assert!(!is_valid_username("john doe"));
    assert!(!is_valid_username(&"a".repeat(65)));
}

#[tokio::test]
async fn users_invite_on_the_web_page() {
    let mut b = bot("invite", &["alice"]);
    b.state.allow_bot_access(ALICE).unwrap();
    for cmd in ["/invite", "/create bob"] {
        let r = say(&mut b, ALICE, cmd).await.unwrap();
        assert!(r.starts_with("To invite someone, open\nhttps://example.org:5281/invites\n"), "{cmd}: {r}");
    }
    assert!(!b.ctl.calls.borrow().iter().any(|c| c[0] == "register"), "nothing registered");
}

/// ejabberd keeps usernames nodeprep'd: `Admin` and `ａｄｍｉｎ` are the admin.
#[tokio::test]
async fn protected_accounts_cannot_be_reached_by_other_spellings() {
    let mut b = bot("protected", &["admin", "bot", "alice"]);
    for cmd in ["/remove Admin", "/remove ａｄｍｉｎ", "/ban ADMIN", "/rstpass Admin@example.org", "/kick Admin", "/resetlink Admin"] {
        let r = say(&mut b, ADMIN, cmd).await.unwrap();
        assert!(r.ends_with("'admin': the admin's account."), "{cmd}: {r}");
    }
    for cmd in ["/chpass bot x", "/rstpass Bot", "/remove bot", "/ban bot", "/kick bot", "/resetlink bot", "/deny bot"] {
        let r = say(&mut b, ADMIN, cmd).await.unwrap();
        assert!(r.ends_with("'bot': the bot's own account."), "{cmd}: {r}");
    }
    assert!(!b.ctl.calls.borrow().iter().any(|c| c[0] != "check_account"), "only lookups ran");

    // names are stored and compared as ejabberd has them
    assert_eq!(say(&mut b, ADMIN, "/allow Alice").await.unwrap(), "✓ User 'alice' now has access to bot (language: EN).");
    assert!(b.may_use(ALICE));
    assert_eq!(say(&mut b, ADMIN, "/deny ALICE").await.unwrap(), "✓ User 'alice' will not have access to bot.");
    assert!(!b.may_use(ALICE));
}

#[tokio::test]
async fn removed_users_lose_bot_access() {
    let mut b = bot("removed", &["alice"]);
    assert_eq!(say(&mut b, ADMIN, "/allow alice").await.unwrap(), "✓ User 'alice' now has access to bot (language: EN).");
    assert_eq!(say(&mut b, ADMIN, "/remove alice").await.unwrap(), "✓ User 'alice' removed.");
    // a new account of the same name starts without it
    b.ctl.accounts.borrow_mut().insert("alice".into());
    assert!(!b.may_use(ALICE));
}

#[tokio::test]
async fn five_abuse_reports_alert_the_admin_and_a_ban_clears_them() {
    let reporters = ["r1", "r2", "r3", "r4", "r5"];
    let mut b = bot("abuse", &["eve", "r1", "r2", "r3", "r4", "r5"]);
    for (i, r) in reporters.iter().enumerate() {
        let jid = format!("{r}@example.org");
        b.state.allow_bot_access(&jid).unwrap();
        let resp = b.process(&jid, "/abuse eve 'spam bot'", now()).await.unwrap();
        assert_eq!(resp.reply.text, "✓ Your abuse report is accepted.");
        assert_eq!(resp.notify_admin.is_some(), i == 4);
        if i == 4 {
            assert_eq!(
                resp.notify_admin.unwrap(),
                "User eve is reported as abuser 5 times.\nReporters:\n```\n• r1 just now\n• r2 just now\n• r3 just now\n• r4 just now\n• r5 just now\n```"

            );
        }
    }
    assert_eq!(say(&mut b, "r1@example.org", "/abuse eve").await.unwrap(), "✗ You can report the same user only once.");
    // a reason is kept on one line, and at most MAX_REASON characters of it
    b.ctl.accounts.borrow_mut().insert("mallory".into());
    let long = format!("/abuse mallory 'line one\nline two {}'", "x".repeat(1000));
    assert_eq!(say(&mut b, "r1@example.org", &long).await.unwrap(), "✓ Your abuse report is accepted.");
    let (_, _, reason) = b.state.reports_by("r1").into_iter().find(|(u, _, _)| *u == "mallory").unwrap();
    assert!(reason.starts_with("line one line two x") && reason.chars().count() == MAX_REASON, "{reason:?}");
    assert_eq!(say(&mut b, "r1@example.org", "/abuse admin").await.unwrap(), INVALID_USERNAME);
    b.ctl.accounts.borrow_mut().insert("admin".into());
    assert_eq!(say(&mut b, "r1@example.org", "/abuse admin").await.unwrap(), "✗ 'admin' can not be reported.");

    assert_eq!(say(&mut b, ADMIN, "/ban eve").await.unwrap(), "✓ User 'eve' banned.\nReason: Blocked by admin");
    assert_eq!(last_call(&b), ["ban_account", "eve", "example.org", "Blocked by admin"]);
    assert!(b.state.reporters_for_abuser("eve").is_empty());
}

#[tokio::test]
async fn ejabberd_failures_are_reported() {
    let mut b = bot("fail", &["alice"]);
    b.ctl.outputs.insert("ban_account", Err("Command timed out".into()));
    assert_eq!(say(&mut b, ADMIN, "/ban alice").await.unwrap(), "✗ Failed to ban user: Command timed out");
    b.ctl.outputs.insert("registered_users", Err("node down".into()));
    assert_eq!(say(&mut b, ADMIN, "/list").await.unwrap(), "✗ Failed to list users: node down");
}

#[tokio::test]
async fn password_commands() {
    let mut b = bot("pass", &["alice"]);
    assert_eq!(say(&mut b, ADMIN, "/chpass alice 'n3w pass'").await.unwrap(), "✓ Password changed for 'alice'.");
    assert_eq!(last_call(&b), ["change_password", "alice", "example.org", "n3w pass"]);
    let r = b.process(ADMIN, "/rstpass alice", now()).await.unwrap().reply;
    assert_eq!(r.text, format!("✓ Password reset for 'alice'.\nNew password: `{}`", last_call(&b)[3]));
}

#[tokio::test]
async fn listings() {
    let mut b = bot("lists", &["alice"]);
    b.ctl.outputs.insert("registered_users", Ok("admin\nalice\n\n".into()));
    assert_eq!(say(&mut b, ADMIN, "/list").await.unwrap(), "✓ Registered users (2):\n```\n• admin\n• alice\n```");
    assert_eq!(say(&mut b, ADMIN, "/banned").await.unwrap(), "No banned accounts on 'example.org'.");
    b.ctl.outputs.insert(
        "connected_users_info",
        Ok("alice@example.org/phone c2s_tls 1.2.3.4 5555 0 ejabberd@node 3700 available phone\n\
            bob@example.org/pc c2s_tls 5.6.7.8 6666 0 ejabberd@node 10 away pc"
            .into()),
    );
    assert_eq!(
        say(&mut b, ADMIN, "/online").await.unwrap(),
        "✓ Connected users (1):\n```\n• alice@example.org/phone\n  [c2s_tls]1.2.3.4:5555\n  1 hour\n```"
    );
    b.ctl.outputs.insert("get_last", Ok("2026-10-13T09:00:00Z\tLogged out".into()));
    assert_eq!(say(&mut b, ADMIN, "/seen alice").await.unwrap(), "✓ Last seen: 3 hours ago.");
    b.ctl.outputs.insert("get_last", Ok("garbage".into()));
    assert_eq!(say(&mut b, ADMIN, "/seen alice").await.unwrap(), "✗ Unexpected get_last output: garbage");
}

#[tokio::test]
async fn announcements_and_motd() {
    let mut b = bot("announce", &[]);
    assert_eq!(say(&mut b, ADMIN, "/warn update   your client").await.unwrap(), "✓ Done.");
    assert_eq!(
        last_call(&b),
        [
            "announce_send_all",
            "example.org",
            "📢 ⚠️ Important update / Mise à jour importante / Важное сообщение / Важливе повідомлення",
            "update your client"
        ]
    );
    assert_eq!(say(&mut b, ADMIN, "/announce ONLINE Hi 'all of' you").await.unwrap(), "✓ Done.");
    assert_eq!(last_call(&b), ["announce_send_online", "example.org", "Hi", "all of you"]);
    assert!(say(&mut b, ADMIN, "/announce later Hi you").await.unwrap().starts_with("Usage: `/announce"));

    assert_eq!(say(&mut b, ADMIN, "/maintenance 'Tue 13:00' 'Tue 14:00'").await.unwrap(), "✓ Done.");
    let call = last_call(&b);
    assert_eq!(call[2], "📢 🛠️ Server maintenance / Maintenance du serveur / Технические работы / Технічні роботи");
    // 13:00 UTC on 13 October: London is on summer time, Paris too, Moscow +3, Kyiv summer +3
    assert_eq!(
        call[3],
        "🇬🇧 The server will be down for maintenance from Today 14:00 to Today 15:00 (BST).\n\n\
         🇫🇷 Le serveur sera indisponible pour maintenance de Aujourd'hui 15h00 à Aujourd'hui 16h00 (CEST).\n\n\
         🇷🇺 Сервер будет недоступен в связи с техническими работами с Сегодня 16:00 по Сегодня 17:00 (MSK).\n\n\
         🇺🇦 Сервер буде недоступний у зв'язку з технічними роботами з Сьогодні 16:00 по Сьогодні 17:00 (EEST)."
    );
    assert_eq!(
        say(&mut b, ADMIN, "/dt_conv 'Tue 13:00'").await.unwrap(),
        "🇬🇧 Today 14:00 (BST)\n🇫🇷 Aujourd'hui 15h00 (CEST)\n🇷🇺 Сегодня 16:00 (MSK)\n🇺🇦 Сьогодні 16:00 (EEST)"
    );

    // other languages, in the configured order
    b.announce_languages = crate::i18n::parse_languages("PL, DE").unwrap();
    say(&mut b, ADMIN, "/maintenance 'Tue 13:00' 'Tue 14:00'").await.unwrap();
    let call = last_call(&b);
    assert_eq!(call[2], "📢 🛠️ Prace konserwacyjne / Serverwartung");
    assert_eq!(
        call[3],
        "🇵🇱 Serwer będzie niedostępny z powodu prac konserwacyjnych od Dziś 15:00 do Dziś 16:00 (CEST).\n\n\
         🇩🇪 Der Server ist wegen Wartungsarbeiten nicht erreichbar, von Heute 15:00 bis Heute 16:00 (CEST)."
    );
    b.announce_languages = crate::i18n::parse_languages("EN,FR,RU,UK").unwrap();
    assert!(say(&mut b, ADMIN, "/maintenance 'Tue 13:00'").await.unwrap().starts_with("Usage: `/maintenance"));
    assert_eq!(
        say(&mut b, ADMIN, "/dt_conv 'Someday 01:00'").await.unwrap(),
        "✗ Failed to parse/format datetime: Invalid day of week: Someday"
    );

    assert_eq!(say(&mut b, ADMIN, "/get_motd").await.unwrap(), "''");
    assert_eq!(say(&mut b, ADMIN, "/set_motd Welcome 'to the' server").await.unwrap(), "✓ Done.");
    assert_eq!(last_call(&b), ["announce_motd_set_online", "example.org", "Welcome", "to the server"]);
    b.ctl.outputs.insert("announce_motd_get", Ok("Welcome\nto the server".into()));
    assert_eq!(say(&mut b, ADMIN, "/set_motd New text").await.unwrap(), "✓ Done.");
    assert_eq!(last_call(&b)[0], "announce_motd_update");
}

#[test]
fn usage_lines_get_monospace_commands() {
    assert_eq!(
        style_usage("Usage: /ban <username> [reason]\nExample: /ban john 'Spam account'".into()),
        "Usage: `/ban <username> [reason]`\nExample: `/ban john 'Spam account'`"
    );
    // only usage messages are touched (a MOTD may have such lines too)
    assert_eq!(style_usage("✓ Done.\nExample: x".into()), "✓ Done.\nExample: x");
    assert_eq!(style_usage("Welcome\nUsage: rules".into()), "Welcome\nUsage: rules");
}

#[tokio::test]
async fn usage_of_every_command_is_styled() {
    let mut b = bot("usage", &[]);
    for cmd in ["/resetlink a b", "/maintenance x", "/dt_conv", "/set_motd x", "/warn"] {
        let r = say(&mut b, ADMIN, cmd).await.unwrap();
        assert!(r.lines().all(|l| !l.starts_with("Usage: /") && !l.starts_with("Example: /")), "{cmd}: {r}");
        assert!(r.starts_with("Usage: `/"), "{cmd}: {r}");
    }
}

#[tokio::test]
async fn help_has_sections_and_every_command_is_dispatched() {
    let mut b = bot("help", &[]);
    let help = say(&mut b, ADMIN, "/help").await.unwrap();
    for section in ["*Accounts*", "*Invitations*", "*Bot access*", "*Bans and spam*", "*Server*", "*Announcements*", "*Cleanup*", "*Other*"]
    {
        assert!(help.contains(section), "{section}");
    }
    // every command in the help is known to the dispatcher
    for line in help.lines().filter(|l| l.starts_with("`/")) {
        let cmd = line[1..].split([' ', '`']).next().unwrap();
        if cmd == "/omemo" {
            continue; // handled by the XMPP layer
        }
        let r = say(&mut b, ADMIN, cmd).await.unwrap();
        assert!(!r.starts_with("Unknown command"), "{cmd}: {r}");
    }
}

#[tokio::test]
async fn status_and_storage() {
    let mut b = bot("status", &["alice"]);
    b.ctl.outputs.insert("status", Ok("The node ejabberd@localhost is started with status: started\nejabberd 26.09 is running".into()));
    b.ctl.outputs.insert("stats", Ok("90061".into()));
    let r = say(&mut b, ADMIN, "/status").await.unwrap();
    assert!(r.starts_with("✓ The node ejabberd@localhost is started"), "{r}");
    assert!(r.contains("Uptime: 1 day"), "{r}");
    b.ctl.outputs.insert("get_mam_count", Ok("795\n".into()));
    b.ctl.outputs.insert("get_offline_count", Ok("6".into()));
    assert_eq!(say(&mut b, ADMIN, "/storage alice").await.unwrap(), "✓ 'alice': 795 archived messages, 6 offline messages.");
    assert_eq!(last_call(&b), ["get_offline_count", "alice", "example.org"]);
    assert_eq!(say(&mut b, ADMIN, "/storage nobody").await.unwrap(), INVALID_USERNAME);
}

// Outputs below are ejabberd 26.09's, from example.org (IP address changed).
#[tokio::test]
async fn certificates_with_expiry() {
    let mut b = bot("certs", &[]);
    let file = "/opt/ejabberd/database/ejabberd@localhost/acme/live/f4156bc5a417a6ae18b62e365480e05a42159a2f";
    b.ctl.outputs.insert(
        "list_certificates",
        Ok(format!(
            "conference.example.org\t{file}\ttrue\nexample.org\t{file}\ttrue\npubsub.example.org\t{file}\ttrue\nupload.example.org\t{file}\ttrue\n"
        )),
    );
    b.ctl.outputs.insert("openssl", Ok("notAfter=Jan 10 17:29:37 2027 GMT".into()));
    assert_eq!(
        say(&mut b, ADMIN, "/certs").await.unwrap(),
        "✓ Certificates:\n```\n• conference.example.org, example.org, pubsub.example.org, upload.example.org\n  \
         expires 2027-01-10 (89 days)\n```"
    );
    assert_eq!(b.ctl.calls.borrow().iter().filter(|c| c[0] == "openssl").count(), 1, "one file, one check");
    // soon: a warning; unreadable: said so
    b.ctl.outputs.insert("openssl", Ok("notAfter=Oct 20  9:00:00 2026 GMT".into()));
    assert!(say(&mut b, ADMIN, "/certs").await.unwrap().contains("⚠️ expires 2026-10-20 (6 days)"));
    b.ctl.outputs.insert("openssl", Err("Could not open file".into()));
    assert!(say(&mut b, ADMIN, "/certs").await.unwrap().contains("expiry unknown: Could not open file"));
    b.ctl.outputs.insert("list_certificates", Ok(String::new()));
    assert_eq!(say(&mut b, ADMIN, "/certs").await.unwrap(), "✓ Certificates: none.");
}

#[tokio::test]
async fn sessions_roster_and_bans() {
    let mut b = bot("sessions", &["admin", "eve"]);
    b.ctl.outputs.insert(
        "user_sessions_info",
        Ok("c2s_tls\t::ffff:203.0.113.41\t54794\t0\tejabberd@localhost\t2272\taway\tConversations.bFjbnK4rPN\t\n".into()),
    );
    assert_eq!(
        say(&mut b, ADMIN, "/sessions admin").await.unwrap(),
        "✓ Sessions of 'admin' (1):\n```\n• Conversations.bFjbnK4rPN (away)\n  203.0.113.41:54794 c2s_tls, 37 minutes\n```"
    );
    b.ctl.outputs.insert("user_sessions_info", Ok(String::new()));
    assert_eq!(say(&mut b, ADMIN, "/sessions admin").await.unwrap(), "✓ 'admin' is not connected.");

    b.ctl.outputs.insert("get_roster", Ok("bot@example.org\t\tboth\tundefined\t\nbob@example.org\tBob\tnone\tout\tFriends\n".into()));
    assert_eq!(
        say(&mut b, ADMIN, "/roster admin").await.unwrap(),
        "✓ Contacts of 'admin' (2):\n```\n• bot@example.org — both\n• bob@example.org (Bob) — none, pending out [Friends]\n```"
    );

    b.ctl.outputs.insert("get_ban_details", Ok(String::new()));
    assert_eq!(say(&mut b, ADMIN, "/baninfo admin").await.unwrap(), "✓ 'admin' is not banned.");
    b.ctl.outputs.insert(
        "get_ban_details",
        Ok("reason\tSpamming other users\nbandate\t2024-04-22T09:16:47.975312Z\nlastdate\t2024-04-22T08:39:12Z\nlastreason\tConnection reset by peer\n".into()),
    );
    assert_eq!(
        say(&mut b, ADMIN, "/baninfo eve").await.unwrap(),
        "✓ Ban of 'eve':\nReason: Spamming other users\nBanned: 2024-04-22 09:16 UTC\nLast login: 2024-04-22 08:39 UTC\nLast disconnect: Connection reset by peer"
    );
}

#[tokio::test]
async fn invites_listing() {
    let mut b = bot("invites", &[]);
    assert_eq!(say(&mut b, ADMIN, "/invites").await.unwrap(), "✓ No invitations or reset links.");
    b.ctl.outputs.insert(
        "list_invites",
        Ok("T1\ttrue\t2026-10-13T20:00:00Z\t2026-10-18T20:00:00Z\treset_token\t@example.org\t\talice\txmpp:alice@example.org?register;preauth=T1\thttps://example.org:5281/invites/T1\n\
            T2\tfalse\t2026-10-01T10:00:00Z\t2026-10-06T10:00:00Z\taccount_only\tuser5@example.org\tbob@example.org\t\txmpp:example.org?register;preauth=T2\thttps://example.org:5281/invites/T2\n"
            .into()),
    );
    assert_eq!(
        say(&mut b, ADMIN, "/invites").await.unwrap(),
        "✓ Invitations and reset links (2):\n\n\
         • Password reset for 'alice': valid, expires 2026-10-18T20:00:00Z\nhttps://example.org:5281/invites/T1\n\n\
         • Account invitation by user5@example.org: expired or used, expires 2026-10-06T10:00:00Z, used by bob@example.org\nhttps://example.org:5281/invites/T2"
    );
}

#[tokio::test]
async fn kick_and_unban_ip() {
    let mut b = bot("kick", &["alice", "admin"]);
    b.ctl.outputs.insert("kick_user", Ok("Kicked sessions: 2".into()));
    assert_eq!(say(&mut b, ADMIN, "/kick alice").await.unwrap(), "✓ 'alice': 2 session(s) disconnected.");
    assert_eq!(say(&mut b, ADMIN, "/kick alice phone").await.unwrap(), "✓ 'alice/phone' disconnected.");
    assert_eq!(last_call(&b), ["kick_session", "alice", "example.org", "phone", "Disconnected by the admin"]);
    assert_eq!(say(&mut b, ADMIN, "/kick admin").await.unwrap(), "✗ Can not kick 'admin': the admin's account.");
    b.ctl.outputs.insert("unban_ip", Ok("3".into()));
    assert_eq!(say(&mut b, ADMIN, "/unban_ip 203.0.113.0/24").await.unwrap(), "✓ fail2ban: 3 banned address(es) in 203.0.113.0/24 lifted.");
    b.ctl.outputs.insert("unban_ip", Ok("-1".into()));
    assert_eq!(say(&mut b, ADMIN, "/unban_ip 203.0.113.7").await.unwrap(), "✗ fail2ban reported an error (-1).");
    assert_eq!(say(&mut b, ADMIN, "/unban_ip evil.example").await.unwrap(), "✗ Not an IP address or network.");
}

#[tokio::test]
async fn reset_link() {
    let mut b = bot("reset", &["alice", "admin"]);
    b.ctl
        .outputs
        .insert("generate_reset_token", Ok("xmpp:alice@example.org?register;preauth=TOKEN\thttps://example.org:5281/invites/TOKEN".into()));
    let r = b.process(ADMIN, "/resetlink alice", now()).await.unwrap().reply;
    assert!(r.text.contains("\nhttps://example.org:5281/invites/TOKEN\n"), "{}", r.text);
    assert!(r.text.ends_with("\nxmpp:alice@example.org?register;preauth=TOKEN"), "{}", r.text);
    assert!(r.secret);
    assert_eq!(say(&mut b, ADMIN, "/resetlink admin").await.unwrap(), "✗ Can not reset the password of 'admin': the admin's account.");
    assert!(say(&mut b, ADMIN, "/resetlink").await.unwrap().starts_with("Usage: `/resetlink <username>`"));

    // users: their own account only, whatever they type
    b.state.allow_bot_access(ALICE).unwrap();
    let r = b.process(ALICE, "/resetlink", now()).await.unwrap().reply;
    assert!(r.text.starts_with("✓ Link to set a new password for your account"), "{}", r.text);
    assert!(r.secret);
    assert_eq!(last_call(&b), ["generate_reset_token", "alice", "example.org"]);
    assert!(say(&mut b, ALICE, "/resetlink bob").await.unwrap().starts_with("Usage: `/resetlink`"));
    // ejabberd's error text is not shown to users
    b.ctl.outputs.insert("generate_reset_token", Err("/opt/ejabberd/x: failed".into()));
    assert_eq!(say(&mut b, ALICE, "/resetlink").await.unwrap(), "✗ Could not create a reset link. Please ask the admin.");
}

#[tokio::test]
async fn spam_domains() {
    let mut b = bot("spam", &[]);
    assert_eq!(say(&mut b, ADMIN, "/spam_domains").await.unwrap(), "✓ No blocked domains.");
    assert_eq!(say(&mut b, ADMIN, "/block_domain Spam.Example").await.unwrap(), "✓ 'spam.example' blocked.");
    assert_eq!(last_call(&b), ["add_blocked_domain", "example.org", "spam.example"]);
    assert_eq!(say(&mut b, ADMIN, "/unblock_domain spam.example").await.unwrap(), "✓ 'spam.example' unblocked.");
    assert_eq!(say(&mut b, ADMIN, "/block_domain example.org").await.unwrap(), "✗ Can not block this server's own domain.");
    assert_eq!(say(&mut b, ADMIN, "/block_domain nodot").await.unwrap(), "✗ Not a domain name.");
}

#[tokio::test]
async fn destructive_commands_want_confirm() {
    let mut b = bot("confirm", &[]);
    let calls_before = b.ctl.calls.borrow().len();
    for cmd in ["/purge_mam 365", "/purge_offline 90", "/restart 5", "/reload_config", "/purge_bot_chats"] {
        let r = say(&mut b, ADMIN, cmd).await.unwrap();
        assert!(r.contains("To proceed:"), "{cmd}: {r}");
    }
    assert_eq!(b.ctl.calls.borrow().len(), calls_before, "nothing ran without confirm");
    assert!(say(&mut b, ADMIN, "/purge_mam 0 confirm").await.unwrap().starts_with("Usage: `/purge_mam"));
    assert!(say(&mut b, ADMIN, "/restart 99 confirm").await.unwrap().starts_with("Usage: `/restart"));

    b.ctl.outputs.insert("delete_old_mam_messages_batch", Ok("Removal of 120 messages in progress".into()));
    let r = say(&mut b, ADMIN, "/purge_mam 365 confirm").await.unwrap();
    assert_eq!(r, "✓ Started: Removal of 120 messages in progress\nProgress: /purge_status");
    assert_eq!(last_call(&b), ["delete_old_mam_messages_batch", "example.org", "all", "365", "1000", "10000"]);
    say(&mut b, ADMIN, "/purge_offline 90 confirm").await.unwrap();
    assert_eq!(last_call(&b), ["delete_old_messages_batch", "example.org", "90", "1000", "10000"]);

    let r = say(&mut b, ADMIN, "/restart 5 confirm").await.unwrap();
    assert!(r.starts_with("✓ Restart in 5 min"), "{r}");
    let call = last_call(&b);
    assert_eq!(call[..2], ["restart_kindly", "300"]);
    assert_eq!(
        call[2],
        "🇬🇧 The server will restart in 5 min, for about a minute.\n\
         🇫🇷 Le serveur redémarrera dans 5 min, pour environ une minute.\n\
         🇷🇺 Сервер перезапустится через 5 мин, примерно на минуту.\n\
         🇺🇦 Сервер перезапуститься через 5 хв, приблизно на хвилину."
    );
    b.ctl.outputs.insert("restart_kindly", Err("a restart is already pending".into()));
    assert_eq!(say(&mut b, ADMIN, "/restart 5 confirm").await.unwrap(), "✗ Failed to schedule the restart: a restart is already pending");
}

#[tokio::test]
async fn purge_bot_chats_cleans_both_sides() {
    let mut b = bot("botchats", &[]);
    b.ctl.outputs.insert("registered_users", Ok("admin\nalice\nbot\n".into()));
    let r = say(&mut b, ADMIN, "/purge_bot_chats confirm").await.unwrap();
    assert_eq!(r, "✓ Archived chats with the bot deleted (2 users and the bot).");
    let calls = b.ctl.calls.borrow();
    let mam: Vec<&Vec<String>> = calls.iter().filter(|c| c[0].starts_with("remove_mam")).collect();
    assert_eq!(mam[0], &["remove_mam_for_user", "bot", "example.org"]);
    assert_eq!(mam[1], &["remove_mam_for_user_with_peer", "admin", "example.org", "bot@example.org"]);
    assert_eq!(mam[2], &["remove_mam_for_user_with_peer", "alice", "example.org", "bot@example.org"]);
    assert_eq!(mam.len(), 3);
}

#[tokio::test]
async fn users_cannot_run_admin_commands() {
    let mut b = bot("nonadmin", &["alice"]);
    b.state.allow_bot_access(ALICE).unwrap();
    for cmd in ["/status", "/kick alice", "/purge_mam 1 confirm", "/restart 1 confirm", "/add bob", "/remove alice"] {
        assert!(say(&mut b, ALICE, cmd).await.unwrap().starts_with("Unknown command"), "{cmd}");
    }
}

#[tokio::test]
async fn users_get_replies_in_their_language() {
    let mut b = bot("lang", &["alice", "bob"]);
    assert_eq!(say(&mut b, ADMIN, "/allow alice fr").await.unwrap(), "✓ User 'alice' now has access to bot (language: FR).");
    assert_eq!(say(&mut b, ADMIN, "/allow bob xx").await.unwrap(), "✗ Unknown language. Use one of: EN, FR, GE, PL, RU, UA.");
    assert_eq!(say(&mut b, ADMIN, "/allow bob de").await.unwrap(), "✗ Unknown language. Use one of: EN, FR, GE, PL, RU, UA.");
    assert!(!b.may_use("bob@example.org"), "nothing allowed on a bad language");
    assert_eq!(say(&mut b, ADMIN, "/allow bob Ua").await.unwrap(), "✓ User 'bob' now has access to bot (language: UA).");
    assert_eq!(say(&mut b, ADMIN, "/allowed").await.unwrap(), "✓ Users with access to bot (2):\n```\n• alice (FR)\n• bob (UA)\n```");
    // /allow again without a language keeps it
    assert_eq!(say(&mut b, ADMIN, "/allow alice").await.unwrap(), "✓ User 'alice' now has access to bot (language: FR).");

    assert!(say(&mut b, ALICE, "/help").await.unwrap().starts_with("`/invite` — inviter quelqu'un"));
    assert_eq!(say(&mut b, ALICE, "/nope").await.unwrap(), "Commande inconnue : 'nope'. Tapez '/help'.");
    assert_eq!(say(&mut b, ALICE, "hello").await.unwrap(), "Les commandes doivent commencer par '/'. Tapez '/help'.");
    assert!(say(&mut b, ALICE, "/invite").await.unwrap().starts_with("Pour inviter quelqu'un, ouvrez\nhttps://example.org:5281/invites\n"));
    // usage lines styled in any language, commands untranslated
    assert_eq!(
        say(&mut b, "bob@example.org", "/abuse").await.unwrap(),
        "Використання: `/abuse <користувач> [причина]`\nПриклад: `/abuse john 'Спам-акаунт'`"
    );
    assert_eq!(say(&mut b, "bob@example.org", "/abuse nobody").await.unwrap(), "✗ Неправильне ім'я користувача.");
    assert_eq!(say(&mut b, "bob@example.org", "/abuse alice").await.unwrap(), "✓ Вашу скаргу прийнято.");

    b.ctl
        .outputs
        .insert("generate_reset_token", Ok("xmpp:alice@example.org?register;preauth=T\thttps://example.org:5281/invites/T".into()));
    let r = say(&mut b, ALICE, "/resetlink").await.unwrap();
    assert!(r.starts_with("✓ Lien pour définir un nouveau mot de passe"), "{r}");
    assert!(r.contains("\nPour les clients XMPP qui le prennent en charge :\nxmpp:"), "{r}");

    // the admin stays in English
    assert_eq!(say(&mut b, ADMIN, "/nope").await.unwrap(), "Unknown command: 'nope'. Type '/help'.");
    assert_eq!(b.language_of(ADMIN), Language::En);
}

#[tokio::test]
async fn users_see_and_disconnect_their_devices() {
    let mut b = bot("devices", &["alice"]);
    b.state.allow_bot_access(ALICE).unwrap();
    b.ctl.outputs.insert(
        "user_sessions_info",
        Ok("c2s_tls\t::ffff:203.0.113.41\t54794\t0\tejabberd@localhost\t2272\taway\tphone\t\n\
            c2s_tls\t2001:db8::7\t40000\t0\tejabberd@localhost\t180000\tavailable\tdesktop\t\n"
            .into()),
    );
    let r = b.process_from(ALICE, Some("phone"), "/devices", now()).await.unwrap().reply.text;
    assert_eq!(
        r,
        "Your connected devices (2):\n```\n1. desktop\n   2001:db8::7, online for 2 d\n2. phone (this device)\n   203.0.113.41, online for 37 min\n```\n\
         Check this list now and then. If you don't recognise a device, disconnect it with `/logout <number>` and set a new password \
         with `/resetlink`: otherwise it connects again with the saved password."
    );
    assert_eq!(last_call(&b), ["user_sessions_info", "alice", "example.org"], "only the sender's own sessions");

    // by number or by name
    assert!(say(&mut b, ALICE, "/logout 1").await.unwrap().starts_with("✓ Disconnected: desktop."));
    assert_eq!(last_call(&b), ["kick_session", "alice", "example.org", "desktop", "Disconnected by the account owner"]);
    // the device the command comes from: only with confirm
    let r = b.process_from(ALICE, Some("phone"), "/logout 2", now()).await.unwrap().reply.text;
    assert_eq!(r, "phone is the device you are writing from. To disconnect it anyway:\n`/logout 2 confirm`");
    assert_eq!(last_call(&b)[0], "user_sessions_info", "not disconnected");
    let r = b.process_from(ALICE, Some("phone"), "/logout 2 confirm", now()).await.unwrap().reply.text;
    assert!(r.starts_with("✓ Disconnected: phone."), "{r}");
    assert!(say(&mut b, ALICE, "/logout phone").await.unwrap().starts_with("✓ Disconnected: phone."));
    assert_eq!(say(&mut b, ALICE, "/logout 3").await.unwrap(), "✗ No such device. Send /devices for the list.");
    assert_eq!(say(&mut b, ALICE, "/logout").await.unwrap(), "Usage: `/logout <number|device>`\nExample: `/logout 2`");

    b.ctl.outputs.insert("user_sessions_info", Err("/opt/ejabberd: node down".into()));
    assert_eq!(say(&mut b, ALICE, "/devices").await.unwrap(), "✗ That didn't work. Please ask the admin.");
}

#[tokio::test]
async fn users_manage_their_archive_language_and_read_the_motd() {
    let mut b = bot("userown", &["alice"]);
    b.state.allow_bot_access(ALICE).unwrap();
    b.ctl.outputs.insert("get_mam_count", Ok("795\n".into()));
    b.ctl.outputs.insert("get_offline_count", Ok("6".into()));
    assert_eq!(say(&mut b, ALICE, "/storage").await.unwrap(), "Messages in your server archive: 795\nMessages waiting for delivery: 6");
    assert_eq!(last_call(&b), ["get_offline_count", "alice", "example.org"]);

    let calls = b.ctl.calls.borrow().len();
    assert!(say(&mut b, ALICE, "/delete_history").await.unwrap().contains("`/delete_history confirm`"));
    assert_eq!(b.ctl.calls.borrow().len(), calls, "nothing deleted without confirm");
    assert_eq!(say(&mut b, ALICE, "/delete_history confirm").await.unwrap(), "✓ Your message archive on the server is deleted.");
    assert_eq!(last_call(&b), ["remove_mam_for_user", "alice", "example.org"]);

    assert_eq!(say(&mut b, ALICE, "/motd").await.unwrap(), "No message of the day.");
    b.ctl.outputs.insert("announce_motd_get", Ok("Maintenance on Sunday".into()));
    assert_eq!(say(&mut b, ALICE, "/motd").await.unwrap(), "Maintenance on Sunday");

    assert_eq!(say(&mut b, ALICE, "/lang xx").await.unwrap(), "✗ Unknown language. Use one of: EN, FR, GE, PL, RU, UA.");
    assert_eq!(say(&mut b, ALICE, "/lang ru").await.unwrap(), "✓ Язык: русский.");
    assert_eq!(say(&mut b, ALICE, "/motd x").await.unwrap(), "Использование: `/motd`");
    assert_eq!(say(&mut b, ADMIN, "/allowed").await.unwrap(), "✓ Users with access to bot (1):\n```\n• alice (RU)\n```");
}

#[tokio::test]
async fn user_help_names_the_admin_and_every_command_is_dispatched() {
    let mut b = bot("userhelp", &["alice"]);
    b.state.allow_bot_access(ALICE).unwrap();
    for lang in Language::ALL {
        b.state.set_language("alice", lang.code()).unwrap();
        let help = say(&mut b, ALICE, "/help").await.unwrap();
        assert!(help.ends_with(&format!(" {ADMIN}")), "{lang:?}: {help}");
        for line in help.lines().filter(|l| l.starts_with("`/")) {
            let cmd = line[1..].split([' ', '`']).next().unwrap();
            if cmd == "/omemo" {
                continue; // handled by the XMPP layer
            }
            let r = say(&mut b, ALICE, cmd).await.unwrap();
            assert!(r != lang.texts().unknown_command.replace("{cmd}", &cmd[1..]), "{lang:?} {cmd}: {r}");
        }
    }
}

#[tokio::test]
async fn privacy_policy_for_everyone_in_their_language() {
    let mut b = bot("privacy", &["alice"]);
    let r = say(&mut b, ADMIN, "/privacy").await.unwrap();
    assert!(r.starts_with("*Privacy and data retention on example.org*"), "{r}");
    assert!(r.contains("Archived messages (also in group chats) are deleted after 21 days."), "{r}");
    assert!(r.contains("Uploaded files (pictures, voice messages, …; up to 500 MB each) are deleted after 7 days."), "{r}");
    assert!(!r.contains('{'), "every placeholder filled: {r}");
    assert!(r.contains("\n  https://en.wikipedia.org/wiki/OMEMO\n"), "{r}");
    assert!(r.contains("never their content, and is deleted after 14 days at the latest."), "{r}");
    assert!(
        r.contains(
            "*Logs and security*\n• Server logs (logins, IP addresses) are deleted after 14 days at the latest.\n• Security records"
        ),
        "{r}"
    );
    assert!(r.contains("are kept up to 84 days.\n• Both are used only for security: to protect your account"), "{r}");
    assert!(r.contains("against attacks.\n• Once a week the administrator gets an encrypted report of the blocked addresses"), "{r}");
    assert!(r.contains("The server holds it only encrypted, for at most 7 days.\n\n*This bot*"), "{r}");
    b.retention.accounts = 30;
    b.state.allow_bot_access(ALICE).unwrap();
    b.state.set_language("alice", "UA").unwrap();
    let r = say(&mut b, ALICE, "/privacy").await.unwrap();
    assert!(r.contains("Обліковий запис, яким не користувалися 30 дн."), "{r}");
    assert!(r.contains("https://uk.wikipedia.org/wiki/SCRAM") && r.contains("https://uk.wikipedia.org/wiki/OMEMO"), "{r}");
    assert!(r.contains("не довше 7 дн.\n\n*Цей бот*"), "{r}");
    assert!(!r.contains('{'), "{r}");
}

#[tokio::test]
async fn daily_state_cleanup_needs_a_trustworthy_user_list() {
    let mut b = bot("prune", &["alice"]);
    b.state.allow_bot_access(ALICE).unwrap();
    b.state.allow_bot_access("gone@example.org").unwrap();
    // a listing without the bot's own account (broken or partial): nothing is touched
    b.ctl.outputs.insert("registered_users", Ok("alice\n".into()));
    b.prune_state(now()).await;
    assert!(b.may_use("gone@example.org"));
    b.ctl.outputs.insert("registered_users", Err("node down".into()));
    b.prune_state(now()).await;
    assert!(b.may_use("gone@example.org"));

    b.ctl.outputs.insert("registered_users", Ok("admin\nalice\nbot\n".into()));
    b.prune_state(now()).await;
    assert!(!b.may_use("gone@example.org"));
    assert!(b.may_use(ALICE));
}

#[tokio::test]
async fn users_export_what_the_server_and_the_bot_hold_about_them() {
    let mut b = bot("export", &["alice", "eve"]);
    b.state.allow_bot_access(ALICE).unwrap();
    b.state.push_abuse_user("alice", "eve", "spam", 1_760_000_000.0).unwrap();
    b.state.push_abuse_user("eve", "alice", "revenge", 1_760_000_000.0).unwrap();
    b.ctl.outputs.insert("get_last", Ok("2026-10-13T09:00:00Z\tLogged out".into()));
    b.ctl.outputs.insert("get_vcard", Ok("Alice A.".into()));
    b.ctl.outputs.insert("get_vcard2", Err("no vcard field".into()));
    b.ctl.outputs.insert("get_roster", Ok("bob@example.org\tBob\tboth\tnone\t\ncarol@example.org\t\tto\tnone\t\n".into()));
    b.ctl.outputs.insert("get_user_rooms", Ok("friends@conference.example.org\n".into()));
    b.ctl.outputs.insert("user_sessions_info", Ok("c2s_tls\t::ffff:203.0.113.41\t1\t0\tn\t60\tavailable\tphone\t\n".into()));
    b.ctl.outputs.insert("get_mam_count", Ok("795".into()));
    b.ctl.outputs.insert("get_offline_count", Ok("6".into()));
    b.ctl.outputs.insert(
        "list_invites",
        Ok("SECRET1\tfalse\t2026-10-01T10:00:00Z\t2026-10-06T10:00:00Z\taccount_only\talice@example.org\tdan@example.org\t\tx\thttps://x/SECRET1\n\
            SECRET2\ttrue\t2026-10-12T10:00:00Z\t2026-10-17T10:00:00Z\taccount_only\tsomeone@example.org\t\t\tx\thttps://x/SECRET2\n"
            .into()),
    );
    let r = b.process(ALICE, "/export", now()).await.unwrap().reply;
    assert!(r.secret);
    let text = r.text;
    for part in [
        "*Your data on example.org*\nalice@example.org, as of 2026-10-13 12:00 UTC",
        "Last login or logout: 2026-10-13 09:00 UTC",
        "• Full name: Alice A.",
        "• bob@example.org (Bob)\n• carol@example.org",
        "• friends@conference.example.org",
        "• phone, 203.0.113.41",
        "Messages in your server archive: 795",
        "*Invitations you created (1)*\n```\n• 2026-10-01 → 2026-10-06: used",
        "Language: EN",
        "Your abuse reports (1):\n```\n• eve",
        "• eve, 2025-10-09: spam",
        "Reports about you: 1",
        "Not included: the messages themselves",
    ] {
        assert!(text.contains(part), "missing {part:?} in:\n{text}");
    }
    assert!(!text.contains("SECRET"), "no invitation tokens");
    assert!(!text.contains("dan@example.org"), "not who used an invitation: someone else's account");
    assert!(!text.contains("revenge"), "nothing about who reported the user");
    assert!(!text.contains("Email"), "missing vCard fields are left out");
    let calls = b.ctl.calls.borrow();
    assert!(
        calls.iter().filter(|c| c.len() > 1 && c[0] != "list_invites").all(|c| c[1] == "alice"),
        "only the sender's account: {calls:?}"
    );
}

/// The tables /export reads, with the columns of ejabberd 26.09's single-host SQLite schema.
const EXPORT_SCHEMA: &str = "
CREATE TABLE users (username text, type smallint, password text, serverkey text, salt text, iterationcount integer, created_at timestamp, \"primary\" text);
CREATE TABLE last (username text, seconds text, state text);
CREATE TABLE rosterusers (username text, jid text, nick text, subscription text, ask text, askmessage text, server text, subscribe text, type text, approved text, created_at timestamp);
CREATE TABLE rostergroups (username text, jid text, grp text);
CREATE TABLE vcard (username text, vcard text, created_at timestamp);
CREATE TABLE private_storage (username text, namespace text, data text, created_at timestamp);
CREATE TABLE privacy_list (username text, name text, id integer primary key, created_at timestamp);
CREATE TABLE privacy_list_data (id integer, t text, value text, action text, ord numeric, match_all boolean, match_iq boolean, match_message boolean, match_presence_in boolean, match_presence_out boolean);
CREATE TABLE privacy_default_list (username text, name text);
CREATE TABLE archive_prefs (username text, def text, always text, never text, created_at timestamp);
CREATE TABLE archive (username text, timestamp bigint, peer text, bare_peer text, xml text, txt text, id integer primary key, kind text, nick text, origin_id text, created_at timestamp);
CREATE TABLE spool (username text, xml text, seq integer primary key, created_at timestamp);
CREATE TABLE push_session (username text, timestamp bigint, service text, node text, xml text);
CREATE TABLE pubsub_node (host text, node text, parent text, plugin text, nodeid integer primary key);
CREATE TABLE pubsub_node_option (nodeid bigint, name text, val text);
CREATE TABLE pubsub_item (nodeid bigint, itemid text, publisher text, creation varchar(32), modification varchar(32), payload text);
CREATE TABLE pubsub_state (nodeid bigint, jid text, affiliation character(1), subscriptions text, stateid integer primary key);
CREATE TABLE muc_registered (jid text, host text, nick text, created_at timestamp);
CREATE TABLE muc_room_subscribers (room text, host text, jid text, nick text, nodes text, created_at timestamp);
CREATE TABLE invite_token (token text, username text, invitee text, created_at timestamp, expires timestamp, type character(1), account_name text);
CREATE TABLE auth_fast_tokens (username text, server_host text, ua text, type character(1), token text, created_at timestamp, expires timestamp);
CREATE TABLE sr_user (jid text, grp text, created_at timestamp);
CREATE TABLE motd (username text, xml text, created_at timestamp);
";

/// Rows of the sender `a_ice` and of others, among them `abice`, whom `LIKE 'a_ice'` would
/// match. Everything marked LEAK must stay out of a_ice's file.
const EXPORT_ROWS: &str = "
INSERT INTO users VALUES ('a_ice', 3, 'LEAK-hash', 'LEAK-serverkey', 'LEAK-salt', 4096, '2026-09-01 10:00:00', ''), ('abice', 3, 'LEAK-abice', 'x', 'x', 4096, '2026-09-01', '');
INSERT INTO last VALUES ('a_ice', '1760000000', 'Away'), ('abice', '1', 'LEAK-abice-status');
INSERT INTO rosterusers VALUES ('a_ice', 'bob@example.org', 'Bob', 'B', 'N', 'LEAK-askmessage', 'N', '', 'item', 'N', '2026-09-02'),
  ('abice', 'LEAK-abice-contact@example.org', '', 'B', 'N', '', 'N', '', 'item', 'N', '2026-09-02');
INSERT INTO rostergroups VALUES ('a_ice', 'bob@example.org', 'Friends'), ('abice', 'x@example.org', 'LEAK-abice-group');
INSERT INTO vcard VALUES ('a_ice', '<vCard><FN>Alice Own</FN></vCard>', '2026-09-03'), ('abice', '<vCard><FN>LEAK-abice-name</FN></vCard>', '2026-09-03');
INSERT INTO private_storage VALUES ('a_ice', 'storage:bookmarks', '<storage/>', '2026-09-03'), ('abice', 'x', 'LEAK-abice-private', '2026-09-03');
INSERT INTO privacy_list VALUES ('a_ice', 'mine', 1, '2026-09-04'), ('abice', 'LEAK-abice-list', 2, '2026-09-04');
INSERT INTO privacy_list_data VALUES (1, 'j', 'spam@example.net', 'd', 1, 0, 0, 1, 0, 0), (2, 'j', 'LEAK-abice-rule', 'd', 1, 0, 0, 1, 0, 0);
INSERT INTO privacy_default_list VALUES ('a_ice', 'mine'), ('abice', 'LEAK-abice-default');
INSERT INTO archive_prefs VALUES ('a_ice', 'always', '[]', '[]', '2026-09-05'), ('abice', 'LEAK-abice-prefs', '[]', '[]', '2026-09-05');
INSERT INTO archive (username, timestamp, peer, bare_peer, xml, txt, kind, nick, origin_id) VALUES
  ('a_ice', 1760000000000000, 'bob@example.org/phone', 'bob@example.org', '<message><body>hello from bob</body></message>', 'hello from bob', 'chat', '', 'o1'),
  ('abice', 1760000000000000, 'x@example.org', 'x@example.org', '<message><body>LEAK-abice-message</body></message>', 'LEAK-abice-message', 'chat', '', 'o2'),
  ('room@conference.example.org', 1760000000000000, 'room@conference.example.org/a_ice', 'room@conference.example.org',
   '<message><body>LEAK-room-message</body></message>', 'LEAK-room-message', 'groupchat', 'a_ice', 'o3');
INSERT INTO spool (username, xml, created_at) VALUES ('a_ice', '<message>waiting</message>', '2026-10-12'), ('abice', '<message>LEAK-abice-offline</message>', '2026-10-12');
INSERT INTO push_session VALUES ('a_ice', 1760000000000000, 'push.example.net', 'node1', '<x>LEAK-push-secret</x>'), ('abice', 1, 'LEAK-abice-push', 'n', '');
INSERT INTO pubsub_node VALUES ('a_ice@example.org', 'urn:xmpp:avatar:metadata', '', 'pep', 1), ('abice@example.org', 'LEAK-abice-node', '', 'pep', 2),
  ('bob@example.org', 'urn:xmpp:avatar:metadata', '', 'pep', 3);
INSERT INTO pubsub_node_option VALUES (1, 'access_model', 'open'), (2, 'LEAK-abice-option', 'x');
INSERT INTO pubsub_item VALUES (1, 'av1', 'a_ice@example.org/phone', '1760000000', '1760000000', '<metadata>own avatar</metadata>'),
  (1, 'evil', 'LEAK-other-publisher@example.org', '1', '1', '<x>LEAK-foreign-item</x>'), (2, 'i', 'abice@example.org', '1', '1', '<x>LEAK-abice-item</x>');
INSERT INTO pubsub_state (nodeid, jid, affiliation, subscriptions) VALUES (3, 'a_ice@example.org', 'n', 's'),
  (1, 'LEAK-subscriber@example.org', 'n', 's'), (2, 'abice@example.org', 'o', '');
INSERT INTO muc_registered VALUES ('a_ice@example.org', 'conference.example.org', 'ally', '2026-09-06'), ('abice@example.org', 'conference.example.org', 'LEAK-abice-nick', '2026-09-06');
INSERT INTO muc_room_subscribers VALUES ('room', 'conference.example.org', 'a_ice@example.org', 'ally', 'urn:xmpp:mucsub:nodes:messages', '2026-09-06'),
  ('room', 'conference.example.org', 'LEAK-member@example.org', 'LEAK-member-nick', '', '2026-09-06');
INSERT INTO invite_token VALUES ('LEAK-token', 'a_ice', 'LEAK-invitee@example.org', '2026-10-01', '2026-10-06', 'R', 'LEAK-reserved-name'),
  ('LEAK-token2', 'abice', '', '2026-10-01', '2026-10-06', 'R', '');
INSERT INTO auth_fast_tokens VALUES ('a_ice', 'example.org', 'Conversations 2.20', 'c', 'LEAK-fast-token', '2026-10-10', '2026-10-17'),
  ('abice', 'example.org', 'LEAK-abice-client', 'c', 'x', '2026-10-10', '2026-10-17');
INSERT INTO sr_user VALUES ('a_ice@example.org', 'staff', '2026-09-07'), ('abice@example.org', 'LEAK-abice-sr', '2026-09-07');
INSERT INTO motd VALUES ('a_ice', '', '2026-09-08'), ('abice', 'LEAK-abice-motd', '2026-09-08');
";

#[tokio::test]
async fn export_file_holds_the_senders_data_and_nothing_else() {
    let mut b = bot("export-file", &["a_ice", "abice"]);
    let dir = std::env::current_dir().unwrap().join("target").join(format!("export-db-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("ejabberd.db");
    let made = std::process::Command::new("sqlite3").arg(&db).arg(format!("{EXPORT_SCHEMA}{EXPORT_ROWS}")).status();
    if !made.is_ok_and(|s| s.success()) {
        eprintln!("no sqlite3 here, skipping");
        return;
    }
    b.ctl.db = Some(db);
    b.state.allow_bot_access("a_ice@example.org").unwrap();
    let r = b.process("a_ice@example.org", "/export", now()).await.unwrap();
    let file = r.attachment.expect("a file with the database set");
    assert_eq!(file.filename, "export-a_ice-2026-10-13.json");
    let text = String::from_utf8(file.data.clone()).unwrap();
    assert!(!text.contains("LEAK"), "someone else's data or a secret in the export:\n{text}");
    assert!(!text.contains("abice"), "nothing about the other account:\n{text}");

    let v: serde_json::Value = serde_json::from_slice(&file.data).unwrap();
    let db = &v["database"];
    let count = |s: &str| db[s].as_array().unwrap_or_else(|| panic!("{s}: {}", db[s])).len();
    for (section, n) in [
        ("account", 1),
        ("last_activity", 1),
        ("contacts", 1),
        ("contact_groups", 1),
        ("vcard", 1),
        ("private_storage", 1),
        ("privacy_lists", 1),
        ("default_privacy_list", 1),
        ("archive_settings", 1),
        ("archived_messages", 1),
        ("offline_messages", 1),
        ("push_registrations", 1),
        ("pep_nodes", 1),
        ("pep_node_options", 1),
        ("pep_items", 1),
        ("pubsub_subscriptions", 1),
        ("room_nicknames", 1),
        ("room_subscriptions", 1),
        ("invitations_created", 1),
        ("login_tokens", 1),
        ("shared_roster_groups", 1),
        ("message_of_the_day_seen", 1),
    ] {
        assert_eq!(count(section), n, "{section}: {}", db[section]);
    }
    assert_eq!(db["archived_messages"][0]["text"], "hello from bob");
    assert_eq!(db["archived_messages"][0]["time"], "2025-10-09T08:53:20.000Z");
    assert_eq!(db["invitations_created"][0]["used"], 1);
    assert_eq!(db["login_tokens"][0]["client"], "Conversations 2.20");
    assert_eq!(db["pubsub_subscriptions"][0]["host"], "bob@example.org", "the sender's own subscription");
    assert!(db["contacts"][0].get("askmessage").is_none());
    assert!(db["account"][0].get("password").is_none() && db["account"][0].get("salt").is_none());
    assert!(db.as_object().unwrap().values().flat_map(|s| s.as_array().unwrap()).all(|row| row.get("owner").is_none()));
    assert_eq!(v["account"], "a_ice@example.org");

    // without the database: the text summary only
    b.ctl.db = None;
    assert!(b.process("a_ice@example.org", "/export", now()).await.unwrap().attachment.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
