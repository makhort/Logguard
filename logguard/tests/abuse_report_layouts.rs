//! `deploy/logguard-abuse-report.sh` in each deployment layout (see tests/layouts.rs): which
//! role `auto` picks, where the weekly report ends up, and that a server without peers
//! doesn't wait for any. A fake `logguard` answers `print-config` with the real effective
//! configuration and records the reports and sends it is asked for.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Case {
    dir: PathBuf,
}

impl Case {
    /// A directory with the fake logguard, outboxes for both bots and an inbox, and the
    /// effective configuration of `toml` (`{dir}` replaced by the directory).
    fn new(name: &str, toml: &str) -> Case {
        let dir = std::env::temp_dir().join(format!("lgar-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["outbox-xmpp", "outbox-tg", "outbox-mail", "inbox", "work"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let me = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap().trim().to_string();
        let toml = toml.replace("{dir}", &dir.display().to_string()).replace("{me}", &me);
        std::fs::write(dir.join("logguard.toml"), &toml).unwrap();
        let effective = Command::new(env!("CARGO_BIN_EXE_logguard"))
            .args(["--config", &dir.join("logguard.toml").to_string_lossy(), "print-config"])
            .output()
            .unwrap();
        assert!(effective.status.success(), "{}", String::from_utf8_lossy(&effective.stderr));
        std::fs::write(dir.join("effective.toml"), effective.stdout).unwrap();
        let d = dir.display();
        let fake = format!(
            r#"#!/bin/sh
shift 2
cmd=$1; shift
case $cmd in
print-config) cat '{d}/effective.toml' ;;
abuse-report)
    out=; args=
    while [ $# -gt 0 ]; do
        if [ "$1" = -o ]; then out=$2; shift; else args="$args $1"; fi
        shift
    done
    echo "abuse-report$args" > "$out" ;;
cluster-send-report) echo "$*" >> '{d}/sent' ;;
*) echo "unexpected: $cmd" >&2; exit 1 ;;
esac
"#
        );
        std::fs::write(dir.join("logguard"), fake).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("logguard"), std::fs::Permissions::from_mode(0o755)).unwrap();
        Case { dir }
    }

    /// Runs the script (no waiting: 0 minutes for peers and the merged report).
    fn run(&self) -> (bool, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/logguard-abuse-report.sh");
        let out = Command::new("bash")
            .arg(script)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("LOGGUARD", self.dir.join("logguard"))
            .env("LOGGUARD_CONFIG", self.dir.join("logguard.toml"))
            .env("ABUSE_REPORT_WORKDIR", self.dir.join("work"))
            .env("ABUSE_REPORT_WAIT_MIN", "0")
            .env("ABUSE_REPORT_RELAY_WAIT_MIN", "0")
            .env("ABUSE_REPORT_CONTACTS", "no")
            .output()
            .unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// The reports in a bot's outbox (`xmpp`, `tg` or `mail`).
    fn reports(&self, which: &str) -> Vec<String> {
        std::fs::read_dir(self.dir.join(format!("outbox-{which}")))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("abuse-report-"))
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect()
    }

    fn sent(&self) -> String {
        std::fs::read_to_string(self.dir.join("sent")).unwrap_or_default()
    }

    /// A file a peer sent (`abuse-<node>.json.gz` or `abuse-report-<node>.txt.gz`), gzipped.
    fn peer_file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.join("inbox").join(name);
        let mut gz = flate2::write::GzEncoder::new(std::fs::File::create(&path).unwrap(), flate2::Compression::default());
        gz.write_all(text.as_bytes()).unwrap();
        gz.finish().unwrap();
        path
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

const XMPP_BOT: &str = "bot_outbox = \"{dir}/outbox-xmpp\"\nbot_user = \"{me}\"\n";
const TG_BOT: &str = "tg_outbox = \"{dir}/outbox-tg\"\ntg_user = \"{me}\"\n";
const MAIL_BOT: &str = "mail_outbox = \"{dir}/outbox-mail\"\nmail_user = \"{me}\"\n";
const CLUSTER: &str = "[cluster]\nenabled = true\nkey = \"Zm9yIHRlc3RzIG9ubHk6IGEgMzItYnl0ZSBrZXkhISE=\"\npeers = [\"192.0.2.1:7946\"]\ninbox = \"{dir}/inbox\"\n";
const NO_PEERS: &str = "[cluster]\ninbox = \"{dir}/inbox\"\n";

fn xmpp_server(bots: &str, cluster: &str) -> String {
    format!("[notify]\nenabled = true\nfrom = \"example.org\"\nadmins = [\"admin@example.org\"]\n{bots}{cluster}")
}

fn tg_node(cluster: &str) -> String {
    format!("[sources]\nejabberd = false\n[notify]\nenabled = true\nxmpp = false\n{TG_BOT}{cluster}")
}

#[test]
fn layout1_no_bots_no_peers_off() {
    // no bot_outbox: the default one (/opt/logguard-xmpp-bot/outbox) doesn't exist here
    let c = Case::new("1", &xmpp_server("", NO_PEERS));
    let (ok, out) = c.run();
    assert!(ok && out.contains("nothing to do"), "{out}");
}

#[test]
fn layout2_no_bots_with_peers_sends() {
    let c = Case::new("2", &format!("[notify]\nenabled = false\n{CLUSTER}"));
    let stale = c.peer_file("abuse-xmpp.json.gz", "{}");
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(c.sent().starts_with("--name abuse "), "{}", c.sent());
    assert!(!stale.exists(), "nobody merges here: a peer's report isn't kept");
}

#[test]
fn layout3_xmpp_bot_no_peers_merges_at_once() {
    let c = Case::new("3", &xmpp_server(XMPP_BOT, NO_PEERS));
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(!out.contains("WARNING"), "no peers to wait for or warn about: {out}");
    let r = c.reports("xmpp");
    assert!(r.len() == 1 && r[0].starts_with("abuse-report --merge ") && !r[0].contains(".json.gz"), "{r:?}");
    assert!(c.reports("tg").is_empty() && c.sent().is_empty());
}

#[test]
fn layout4_xmpp_bot_with_peers_merges_theirs() {
    let c = Case::new("4", &xmpp_server(XMPP_BOT, CLUSTER));
    let vpn = c.peer_file("abuse-vpn.json.gz", "{}");
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    let r = c.reports("xmpp");
    assert!(r.len() == 1 && r[0].contains("abuse-vpn.json.gz"), "{r:?}");
    assert!(!vpn.exists(), "merged, then deleted");
    assert!(c.sent().is_empty(), "the merging server sends nothing");
}

#[test]
fn layout5_tg_bot_no_peers_merges_for_telegram() {
    let c = Case::new("5", &tg_node(NO_PEERS));
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(!out.contains("WARNING"), "{out}");
    assert_eq!(c.reports("tg").len(), 1);
    assert!(c.reports("xmpp").is_empty());
}

#[test]
fn layout6_tg_bot_with_peers() {
    // a relay node whose merging peer (the XMPP server) forwarded the merged report
    let c = Case::new("6-relay", &tg_node(CLUSTER));
    let merged = c.peer_file("abuse-report-xmpp.txt.gz", "merged on the XMPP server\n");
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(c.sent().starts_with("--name abuse "), "own report to the peers: {}", c.sent());
    assert_eq!(c.reports("tg"), ["merged on the XMPP server\n"]);
    assert!(!merged.exists());

    // no merging peer (a VPN server only): merges here after the wait
    let c = Case::new("6-alone", &tg_node(CLUSTER));
    let vpn = c.peer_file("abuse-vpn.json.gz", "{}");
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(out.contains("merging here"), "{out}");
    let r = c.reports("tg");
    assert!(r.len() == 1 && r[0].contains("abuse-vpn.json.gz"), "{r:?}");
    assert!(!vpn.exists());

    // logguard-tg-bot on the XMPP server (no admins: Telegram only), with a peer
    let c = Case::new("6-xmpp", &format!("[notify]\nenabled = true\nfrom = \"example.org\"\n{TG_BOT}{CLUSTER}"));
    c.peer_file("abuse-vpn.json.gz", "{}");
    std::fs::remove_dir_all(c.dir.join("outbox-xmpp")).unwrap();
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    let r = c.reports("tg");
    assert!(r.len() == 1 && r[0].contains("abuse-vpn.json.gz"), "{r:?}");
}

#[test]
fn layout7_both_bots_get_the_report() {
    let c = Case::new("7", &xmpp_server(&format!("{XMPP_BOT}{TG_BOT}"), NO_PEERS));
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert_eq!((c.reports("xmpp").len(), c.reports("tg").len()), (1, 1));
}

fn mail_node(cluster: &str) -> String {
    format!("[sources]\nejabberd = false\n[notify]\nenabled = true\nxmpp = false\n{MAIL_BOT}{cluster}")
}

#[test]
fn layout8_mail_bot_no_peers_merges_for_mail() {
    let c = Case::new("8", &mail_node(NO_PEERS));
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(!out.contains("WARNING"), "{out}");
    assert_eq!(c.reports("mail").len(), 1);
    assert!(c.reports("xmpp").is_empty() && c.reports("tg").is_empty());
}

#[test]
fn layout9_mail_bot_with_peers_relays() {
    let c = Case::new("9-relay", &mail_node(CLUSTER));
    c.peer_file("abuse-report-xmpp.txt.gz", "merged on the XMPP server\n");
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert!(c.sent().starts_with("--name abuse "), "own report to the peers: {}", c.sent());
    assert_eq!(c.reports("mail"), ["merged on the XMPP server\n"]);
}

#[test]
fn layout10_all_three_bots_get_the_report() {
    let c = Case::new("10", &xmpp_server(&format!("{XMPP_BOT}{TG_BOT}{MAIL_BOT}"), NO_PEERS));
    let (ok, out) = c.run();
    assert!(ok, "{out}");
    assert_eq!((c.reports("xmpp").len(), c.reports("tg").len(), c.reports("mail").len()), (1, 1, 1));
}

#[test]
fn send_or_relay_without_peers_is_refused() {
    let c = Case::new("refuse", &xmpp_server("", NO_PEERS));
    let out = Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/logguard-abuse-report.sh"))
        .env("LOGGUARD", c.dir.join("logguard"))
        .env("LOGGUARD_CONFIG", c.dir.join("logguard.toml"))
        .env("ABUSE_REPORT_ROLE", "send")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
}
