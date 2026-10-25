//! The deployment layouts logguard must protect a server in, run end to end: the real daemon
//! with a fake `journalctl` (attacks as journal JSON, stamped now) and a fake `nft` that
//! records the rulesets it is given, with and without the XMPP bot's, the Telegram bot's and
//! the mail bot's outboxes, and with cluster peers on 127.0.0.1. Each layout must put the attackers into the
//! firewall within seconds, and deliver admin and user messages where that layout says:
//!
//! | layout | bots | peers |
//! |---|---|---|
//! | 1 | none | none |
//! | 2 | none | yes (a VPN server) |
//! | 3 | logguard-xmpp-bot | none |
//! | 4 | logguard-xmpp-bot | yes |
//! | 5 | logguard-tg-bot | none |
//! | 6 | logguard-tg-bot | yes (on the XMPP server, or on a relay node of its own) |
//! | 7 | logguard-xmpp-bot and logguard-tg-bot | none |
//! | 8 | logguard-mail-bot | none |
//! | 9 | logguard-mail-bot | yes (on a relay node of its own) |
//! | 10 | all three | none |
//!
//! XMPP messages go to a fake ejabberd HTTP API (`[notify] api`), which records them.
//! Needs to bind 127.0.0.1 (cluster and API): run outside a sandbox that forbids it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const ATTACKER_SSH: &str = "11.20.45.233";
const ATTACKER_XMPP: &str = "11.46.50.7";
const ATTACKER_VPN: &str = "11.28.63.115";
const USER: &str = "bob@example.org";
const ADMIN: &str = "admin@example.org";
const KEY: &str = "Zm9yIHRlc3RzIG9ubHk6IGEgMzItYnl0ZSBrZXkhISE=";
/// No such account: the outbox files stay root's (they would go to the bot's user).
const NO_USER: &str = "logguard-test-nobody";
const WAIT: Duration = Duration::from_secs(40);

/// Journal lines for an SSH attack: three unknown user names (40 points each, ban at 100).
fn ssh_attack(ip: &str) -> Vec<String> {
    (1..=3).map(|i| journal("sshd-session", "", &format!("Invalid user probe{i} from {ip} port {}", 40_000 + i))).collect()
}

/// Journal lines for password guessing on an XMPP account that has logged in before (only
/// real accounts are warned): five failures (25 points each; four decay to just under 100).
fn xmpp_attack(ip: &str, jid: &str) -> Vec<String> {
    let ts = logguard::time::fmt_ts(logguard::time::now());
    let line = |msg: String| journal("ejabberd", "ejabberd.service", &format!("{ts}.000 {msg}"));
    let login =
        line(format!("[info] (tls|<0.4000.0>) Accepted c2s SCRAM-SHA-256 authentication for {jid} by sql backend from ::ffff:11.42.43.31"));
    let failures = (1..=5).map(|i| {
        line(format!(
            "[warning] (tls|<0.{}.0>) Failed c2s SCRAM-SHA-256 authentication for {jid} from ::ffff:{ip}: Invalid username or password",
            5000 + i
        ))
    });
    std::iter::once(login).chain(failures).collect()
}

fn journal(ident: &str, unit: &str, msg: &str) -> String {
    let now = logguard::time::now();
    let mut e = serde_json::json!({
        "__CURSOR": format!("c-{now}-{}", msg.len()),
        "__REALTIME_TIMESTAMP": now.to_string(),
        "SYSLOG_IDENTIFIER": ident,
        "_PID": "4242",
        "_UID": "0",
        "MESSAGE": msg,
    });
    if !unit.is_empty() {
        e["_SYSTEMD_UNIT"] = unit.into();
    }
    e.to_string()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// ejabberd's HTTP API (`/api/send_message`): records (to, body) and answers success.
#[derive(Clone)]
struct FakeApi {
    addr: String,
    sent: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeApi {
    fn start() -> FakeApi {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let log = sent.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // headers, then Content-Length bytes of body
                let body = loop {
                    let Ok(n) = s.read(&mut chunk) else { break None };
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>()))
                            .and_then(Result::ok)
                            .unwrap_or(0);
                        if body.len() >= len {
                            break Some(body.to_string());
                        }
                    }
                };
                if let Some(json) = body.and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok()) {
                    let field = |k: &str| json[k].as_str().unwrap_or_default().to_string();
                    log.lock().unwrap().push((field("to"), field("body")));
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n0");
            }
        });
        FakeApi { addr, sent }
    }

    fn to(&self, jid: &str) -> Vec<String> {
        self.sent.lock().unwrap().iter().filter(|(to, _)| to == jid).map(|(_, b)| b.clone()).collect()
    }

    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

/// One logguard daemon in a directory of its own.
struct Node {
    name: String,
    dir: PathBuf,
    child: Option<Child>,
}

impl Node {
    /// Starts `logguard run` in enforce mode with nftables (the fake `nft`), the journal lines
    /// `lines` and `extra` appended to the configuration.
    fn start(name: &str, extra: &str, lines: &[String]) -> Node {
        let dir = node_dir(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("outbox-xmpp")).unwrap();
        std::fs::create_dir_all(dir.join("outbox-tg")).unwrap();
        std::fs::create_dir_all(dir.join("outbox-mail")).unwrap();
        std::fs::write(dir.join("journal.jsonl"), lines.join("\n") + "\n").unwrap();
        let d = dir.display();
        script(&dir.join("journalctl"), &format!("#!/bin/sh\ncat '{d}/journal.jsonl'\nexec sleep 300\n"));
        script(&dir.join("nft"), &format!("#!/bin/sh\nif [ \"$1\" = -f ]; then cat >> '{d}/nft.log'; fi\nexit 0\n"));
        let config = format!(
            r#"mode = "enforce"
state_file = "{d}/state.json"
socket = "{d}/s.sock"
actions_log = "{d}/actions.jsonl"
[journal]
journalctl = "{d}/journalctl"
[enforce]
backend = "nft"
nft = "{d}/nft"
[exposure]
enabled = false
[cron]
enabled = false
[resources]
enabled = false
{extra}"#
        );
        std::fs::write(dir.join("logguard.toml"), &config).unwrap();
        let log = std::fs::File::create(dir.join("daemon.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_logguard"))
            .args(["--config", &dir.join("logguard.toml").to_string_lossy(), "run"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        Node { name: name.into(), dir, child: Some(child) }
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.dir.join(file)).unwrap_or_default()
    }

    /// Whether the firewall was told to drop `ip`.
    fn blocks(&self, ip: &str) -> bool {
        self.read("nft.log").lines().any(|l| l.starts_with("add element") && l.contains(&format!("{{ {ip} ")))
    }

    /// The messages in a bot's outbox (`xmpp`, `tg` or `mail`), as their full text.
    fn messages(&self, which: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.dir.join(format!("outbox-{which}")))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("alert-"))
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        out.sort();
        out
    }

    fn wait_until(&self, what: &str, cond: impl Fn() -> bool) {
        let start = Instant::now();
        while !cond() {
            if start.elapsed() > WAIT {
                panic!("{}: {what} didn't happen within {WAIT:?}\n--- daemon log:\n{}", self.name, self.read("daemon.log"));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // SIGTERM: the daemon stops its journalctl (the fake one's sleep) too
            let _ = Command::new("kill").arg(child.id().to_string()).status();
            let start = Instant::now();
            while child.try_wait().ok().flatten().is_none() && start.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        if !thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn node_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("lgl-{}-{name}", std::process::id()))
}

/// A node's outbox for the XMPP bot (`xmpp`), the Telegram bot (`tg`) or the mail bot (`mail`).
fn outbox(name: &str, which: &str) -> String {
    node_dir(name).join(format!("outbox-{which}")).display().to_string()
}

fn script(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `[notify]` of an XMPP server: messages through the (fake) ejabberd API, plus `more`.
fn xmpp_notify(api: &FakeApi, more: &str) -> String {
    format!("[notify]\nenabled = true\napi = \"{}\"\nfrom = \"example.org\"\nadmins = [\"{ADMIN}\"]\n{more}\n", api.addr)
}

/// `[cluster]` of a node at 127.0.0.1:`port` with `peers`, sending every second.
fn cluster(node: &str, port: u16, peers: &[u16], more: &str) -> String {
    let peers: Vec<String> = peers.iter().map(|p| format!("\"127.0.0.1:{p}\"")).collect();
    format!(
        "[cluster]\nenabled = true\nnode_id = \"{node}\"\nlisten = \"127.0.0.1:{port}\"\npeers = [{}]\nkey = \"{KEY}\"\nsync_interval = \"1s\"\n{more}\n",
        peers.join(", ")
    )
}

/// A server without ejabberd (the VPN server): SSH and the firewall only, no messages of its own.
const VPN: &str = "[sources]\nejabberd = false\n[notify]\nenabled = false\n";

fn attacks_on_xmpp_server() -> Vec<String> {
    ssh_attack(ATTACKER_SSH).into_iter().chain(xmpp_attack(ATTACKER_XMPP, USER)).collect()
}

fn user_warned(api: &FakeApi) -> bool {
    api.to(USER).iter().any(|b| b.contains(ATTACKER_XMPP))
}

#[test]
fn layout1_no_bots_no_peers() {
    // an XMPP server: admin and user messages over XMPP, unencrypted
    let api = FakeApi::start();
    let xmpp = Node::start("1-xmpp", &xmpp_notify(&api, ""), &attacks_on_xmpp_server());
    // a server with nothing to tell anyone: protection alone
    let bare = Node::start("1-bare", VPN, &ssh_attack(ATTACKER_SSH));
    xmpp.wait_until("both attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    bare.wait_until("the attacker blocked", || bare.blocks(ATTACKER_SSH));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    xmpp.wait_until("the admin told over XMPP", || api.to(ADMIN).iter().any(|b| b.contains(ATTACKER_SSH)));
    // the ban reaches nft before the actions log: wait for it rather than read once
    bare.wait_until("the ban in the actions log", || bare.read("actions.jsonl").contains(&format!("\"target\":\"{ATTACKER_SSH}\"")));
}

#[test]
fn layout2_no_bots_with_peers() {
    let api = FakeApi::start();
    let (pa, pb) = (free_port(), free_port());
    let xmpp = Node::start("2-xmpp", &(xmpp_notify(&api, "") + &cluster("xmpp", pa, &[pb], "")), &attacks_on_xmpp_server());
    let vpn = Node::start("2-vpn", &(VPN.to_string() + &cluster("vpn", pb, &[pa], "")), &ssh_attack(ATTACKER_VPN));
    // each blocks its own attackers, and the other's through the cluster
    xmpp.wait_until("own attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    vpn.wait_until("own attacker blocked", || vpn.blocks(ATTACKER_VPN));
    vpn.wait_until("the XMPP server's attackers blocked", || vpn.blocks(ATTACKER_SSH) && vpn.blocks(ATTACKER_XMPP));
    xmpp.wait_until("the VPN server's attacker blocked", || xmpp.blocks(ATTACKER_VPN));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    // the VPN server's alerts reach the admin through the XMPP server
    xmpp.wait_until("the VPN server's alert relayed", || api.to(ADMIN).iter().any(|b| b.starts_with("[vpn] ") && b.contains(ATTACKER_VPN)));
}

#[test]
fn layout3_xmpp_bot_no_peers() {
    let api = FakeApi::start();
    let notify = xmpp_notify(&api, &format!("bot_outbox = \"{}\"\nbot_user = \"{NO_USER}\"", outbox("3-xmpp", "xmpp")));
    let xmpp = Node::start("3-xmpp", &notify, &attacks_on_xmpp_server());
    xmpp.wait_until("both attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    xmpp.wait_until("admin alerts in the XMPP bot's outbox", || {
        let m = xmpp.messages("xmpp");
        m.iter().any(|t| t.contains(ATTACKER_SSH)) && m.iter().all(|t| t.starts_with(&format!("To: {ADMIN}\n")))
    });
    assert!(api.to(ADMIN).is_empty(), "admin messages only through the bot (OMEMO)");
    assert!(xmpp.messages("tg").is_empty());
}

#[test]
fn layout4_xmpp_bot_with_peers() {
    let api = FakeApi::start();
    let (pa, pb) = (free_port(), free_port());
    let notify = xmpp_notify(&api, &format!("bot_outbox = \"{}\"\nbot_user = \"{NO_USER}\"", outbox("4-xmpp", "xmpp")));
    let xmpp = Node::start("4-xmpp", &(notify + &cluster("xmpp", pa, &[pb], "")), &attacks_on_xmpp_server());
    let vpn = Node::start("4-vpn", &(VPN.to_string() + &cluster("vpn", pb, &[pa], "")), &ssh_attack(ATTACKER_VPN));
    vpn.wait_until("all attackers blocked", || [ATTACKER_VPN, ATTACKER_SSH, ATTACKER_XMPP].iter().all(|ip| vpn.blocks(ip)));
    xmpp.wait_until("all attackers blocked", || [ATTACKER_VPN, ATTACKER_SSH, ATTACKER_XMPP].iter().all(|ip| xmpp.blocks(ip)));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    xmpp.wait_until("own and relayed alerts in the bot's outbox", || {
        let m = xmpp.messages("xmpp");
        m.iter().any(|t| t.contains(ATTACKER_SSH)) && m.iter().any(|t| t.contains("[vpn] ") && t.contains(ATTACKER_VPN))
    });
    assert!(api.to(ADMIN).is_empty(), "admin messages only through the bot (OMEMO)");
}

#[test]
fn layout5_tg_bot_no_peers() {
    // a server without ejabberd: admin messages to Telegram only
    let notify = format!(
        "[sources]\nejabberd = false\n[notify]\nenabled = true\nxmpp = false\ntg_outbox = \"{}\"\ntg_user = \"{NO_USER}\"\n",
        outbox("5-tg", "tg")
    );
    let tg = Node::start("5-tg", &notify, &ssh_attack(ATTACKER_SSH));
    tg.wait_until("the attacker blocked", || tg.blocks(ATTACKER_SSH));
    tg.wait_until("the alert in the Telegram bot's outbox", || {
        tg.messages("tg").iter().any(|t| t.starts_with("To: admin\n") && t.contains(ATTACKER_SSH))
    });
}

#[test]
fn layout6_tg_bot_with_peers() {
    // a) logguard-tg-bot on the XMPP server, the admin on Telegram only (no [notify] admins), users
    //    still warned over XMPP; a VPN server as peer
    let api = FakeApi::start();
    let (pa, pb) = (free_port(), free_port());
    let notify = format!(
        "[notify]\nenabled = true\napi = \"{}\"\nfrom = \"example.org\"\ntg_outbox = \"{}\"\ntg_user = \"{NO_USER}\"\n",
        api.addr,
        outbox("6a-xmpp", "tg")
    );
    let xmpp = Node::start("6a-xmpp", &(notify + &cluster("xmpp", pa, &[pb], "")), &attacks_on_xmpp_server());
    let vpn = Node::start("6a-vpn", &(VPN.to_string() + &cluster("vpn", pb, &[pa], "")), &ssh_attack(ATTACKER_VPN));
    xmpp.wait_until("all attackers blocked", || [ATTACKER_VPN, ATTACKER_SSH, ATTACKER_XMPP].iter().all(|ip| xmpp.blocks(ip)));
    vpn.wait_until("all attackers blocked", || [ATTACKER_VPN, ATTACKER_SSH, ATTACKER_XMPP].iter().all(|ip| vpn.blocks(ip)));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    xmpp.wait_until("own and relayed alerts in the Telegram bot's outbox", || {
        let m = xmpp.messages("tg");
        m.iter().any(|t| t.contains(ATTACKER_XMPP)) && m.iter().any(|t| t.contains("[vpn] ") && t.contains(ATTACKER_VPN))
    });
    assert!(api.sent.lock().unwrap().iter().all(|(to, _)| to == USER), "nothing but users' warnings over XMPP");

    // b) logguard-tg-bot on a relay node of its own (deploy/logguard-tg.toml): the XMPP server relays
    //    its admin messages there and takes only notices and files from it
    let api = FakeApi::start();
    let (px, pt) = (free_port(), free_port());
    let limit = format!("relay_notices = true\npeer_accept = {{ \"127.0.0.1:{pt}\" = [\"notices\", \"files\"] }}");
    let xmpp = Node::start("6b-xmpp", &(xmpp_notify(&api, "") + &cluster("xmpp", px, &[pt], &limit)), &attacks_on_xmpp_server());
    let notify = format!(
        "[sources]\nejabberd = false\n[notify]\nenabled = true\nxmpp = false\ntg_outbox = \"{}\"\ntg_user = \"{NO_USER}\"\n",
        outbox("6b-tg", "tg")
    );
    let tg = Node::start("6b-tg", &(notify + &cluster("tg", pt, &[px], "relay_notices = true")), &ssh_attack(ATTACKER_VPN));
    tg.wait_until("own and the XMPP server's attackers blocked", || {
        [ATTACKER_VPN, ATTACKER_SSH, ATTACKER_XMPP].iter().all(|ip| tg.blocks(ip))
    });
    xmpp.wait_until("own attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    tg.wait_until("own and relayed alerts in the Telegram bot's outbox", || {
        let m = tg.messages("tg");
        m.iter().any(|t| t.contains(ATTACKER_VPN)) && m.iter().any(|t| t.contains("[xmpp] ") && t.contains(ATTACKER_XMPP))
    });
    xmpp.wait_until("the relay node's alert reaches the XMPP admin", || {
        api.to(ADMIN).iter().any(|b| b.starts_with("[tg] ") && b.contains(ATTACKER_VPN))
    });
    // peer_accept: the relay node's ban doesn't apply on the XMPP server
    thread::sleep(Duration::from_secs(3));
    assert!(!xmpp.blocks(ATTACKER_VPN), "the relay node may hand the XMPP server notices only");
}

#[test]
fn layout7_both_bots() {
    let api = FakeApi::start();
    let notify = xmpp_notify(
        &api,
        &format!(
            "bot_outbox = \"{}\"\nbot_user = \"{NO_USER}\"\ntg_outbox = \"{}\"\ntg_user = \"{NO_USER}\"",
            outbox("7-xmpp", "xmpp"),
            outbox("7-xmpp", "tg")
        ),
    );
    let xmpp = Node::start("7-xmpp", &notify, &attacks_on_xmpp_server());
    xmpp.wait_until("both attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    xmpp.wait_until("the alerts in both bots' outboxes", || {
        let has = |which| xmpp.messages(which).iter().any(|t| t.starts_with(&format!("To: {ADMIN}\n")) && t.contains(ATTACKER_SSH));
        has("xmpp") && has("tg")
    });
    assert!(api.to(ADMIN).is_empty(), "admin messages only through the bots");
    assert!(api.count() >= 1);
}

/// A node without ejabberd whose admin messages go to the mail bot only.
fn mail_node(name: &str) -> String {
    format!(
        "[sources]\nejabberd = false\n[notify]\nenabled = true\nxmpp = false\nmail_outbox = \"{}\"\nmail_user = \"{NO_USER}\"\n",
        outbox(name, "mail")
    )
}

#[test]
fn layout8_mail_bot_no_peers() {
    let mail = Node::start("8-mail", &mail_node("8-mail"), &ssh_attack(ATTACKER_SSH));
    mail.wait_until("the attacker blocked", || mail.blocks(ATTACKER_SSH));
    mail.wait_until("the alert in the mail bot's outbox", || {
        mail.messages("mail").iter().any(|t| t.starts_with("To: admin\n") && t.contains(ATTACKER_SSH))
    });
    assert!(mail.messages("tg").is_empty() && mail.messages("xmpp").is_empty());
}

#[test]
fn layout9_mail_bot_with_peers() {
    // logguard-mail-bot on a relay node of its own: the XMPP server relays its admin messages
    // there and takes only notices and files from it, as from a Telegram relay node
    let api = FakeApi::start();
    let (px, pm) = (free_port(), free_port());
    let limit = format!("relay_notices = true\npeer_accept = {{ \"127.0.0.1:{pm}\" = [\"notices\", \"files\"] }}");
    let xmpp = Node::start("9-xmpp", &(xmpp_notify(&api, "") + &cluster("xmpp", px, &[pm], &limit)), &attacks_on_xmpp_server());
    let mail =
        Node::start("9-mail", &(mail_node("9-mail") + &cluster("mail", pm, &[px], "relay_notices = true")), &ssh_attack(ATTACKER_VPN));
    mail.wait_until("own and the XMPP server's attackers blocked", || {
        [ATTACKER_VPN, ATTACKER_SSH, ATTACKER_XMPP].iter().all(|ip| mail.blocks(ip))
    });
    xmpp.wait_until("own attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    mail.wait_until("own and relayed alerts in the mail bot's outbox", || {
        let m = mail.messages("mail");
        m.iter().any(|t| t.contains(ATTACKER_VPN)) && m.iter().any(|t| t.contains("[xmpp] ") && t.contains(ATTACKER_XMPP))
    });
    xmpp.wait_until("the relay node's alert reaches the XMPP admin", || {
        api.to(ADMIN).iter().any(|b| b.starts_with("[mail] ") && b.contains(ATTACKER_VPN))
    });
    thread::sleep(Duration::from_secs(3));
    assert!(!xmpp.blocks(ATTACKER_VPN), "the relay node may hand the XMPP server notices only");
}

#[test]
fn layout10_all_three_bots() {
    let api = FakeApi::start();
    let notify = xmpp_notify(
        &api,
        &format!(
            "bot_outbox = \"{}\"\nbot_user = \"{NO_USER}\"\ntg_outbox = \"{}\"\ntg_user = \"{NO_USER}\"\nmail_outbox = \"{}\"\nmail_user = \"{NO_USER}\"",
            outbox("10-xmpp", "xmpp"),
            outbox("10-xmpp", "tg"),
            outbox("10-xmpp", "mail")
        ),
    );
    let xmpp = Node::start("10-xmpp", &notify, &attacks_on_xmpp_server());
    xmpp.wait_until("both attackers blocked", || xmpp.blocks(ATTACKER_SSH) && xmpp.blocks(ATTACKER_XMPP));
    xmpp.wait_until("the user warned over XMPP", || user_warned(&api));
    xmpp.wait_until("the alerts in all three bots' outboxes", || {
        let has = |which| xmpp.messages(which).iter().any(|t| t.starts_with(&format!("To: {ADMIN}\n")) && t.contains(ATTACKER_SSH));
        has("xmpp") && has("tg") && has("mail")
    });
    assert!(api.to(ADMIN).is_empty(), "admin messages only through the bots");
}
