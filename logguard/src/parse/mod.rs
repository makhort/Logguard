//! Turns raw records into security events.

pub mod apps;
pub mod auth;
pub mod custom;
pub mod ejabberd;
pub mod kernel;
pub mod nextcloud;
pub mod privilege;
pub mod ssh;
pub mod systemd;
pub mod ufw;

use crate::config::Config;
use crate::event::{Event, Signal};
use crate::record::{Record, Source};
use crate::time::Micros;

pub struct Parsers {
    pub ejabberd: ejabberd::EjabberdParser,
    pub ssh: ssh::SshParser,
    pub custom: custom::Patterns,
    /// What each pattern for its sender made of the last `Source::Custom` line: for the
    /// dashboard's per-pattern statistics.
    pub pattern_seen: Vec<(String, custom::Outcome)>,
    sources: crate::config::SourcesCfg,
    ports: crate::config::PortsCfg,
    canary: crate::config::CanaryCfg,
    /// The built-in patterns of Nextcloud's and ownCloud's failed logins in use: their
    /// accounts are checked against `[canary] nextcloud` too.
    cloud_logins: Vec<String>,
    /// PAM services whose failed logins an app source of `[sources] apps` scores already.
    auth_scored_elsewhere: Vec<&'static str>,
    /// Recent tripwire hits: the same blocked SYN may be logged by UFW and by logguard's own
    /// nftables rule (`[ports] kernel_tripwires`), and must count once.
    trips: std::collections::HashMap<(std::net::IpAddr, u16), Micros>,
}

/// Bound on remembered tripwire hits (spoofed SYNs can name any source).
const MAX_TRIPS: usize = 4096;
/// Two lines about the same SYN arrive within a moment of each other.
const TRIP_TWIN: Micros = 2 * crate::time::SEC;

impl Parsers {
    pub fn new(cfg: &Config) -> Self {
        Parsers {
            ejabberd: ejabberd::EjabberdParser::new(cfg.xmpp.c2s_ports.clone(), cfg.xmpp.noauth_grace.micros()),
            ssh: ssh::SshParser::default(),
            custom: custom::Patterns::new(cfg.all_patterns()),
            pattern_seen: Vec::new(),
            sources: cfg.sources.clone(),
            ports: cfg.ports.clone(),
            canary: cfg.canary.clone(),
            cloud_logins: cfg
                .app_patterns
                .iter()
                .filter(|p| matches!(p.name.as_str(), "nextcloud_auth" | "owncloud_auth"))
                .map(|p| p.name.clone())
                .collect(),
            auth_scored_elsewhere: cfg
                .sources
                .apps
                .iter()
                .flat_map(|a| match a.as_str() {
                    "dovecot" => &["dovecot"][..],
                    "postfix" => &["smtp", "smtps", "submission"][..],
                    _ => &[][..],
                })
                .copied()
                .collect(),
            trips: Default::default(),
        }
    }

    pub fn feed(&mut self, rec: &Record, out: &mut Vec<Event>) {
        if !self.sources.enabled(rec.source) {
            return;
        }
        let start = out.len();
        match rec.source {
            Source::Ejabberd => self.ejabberd.feed(rec, out),
            Source::Ssh => self.ssh.feed(rec, out),
            Source::Ufw => ufw::feed(rec, out),
            Source::Nextcloud => nextcloud::feed(rec, out),
            Source::Custom => self.pattern_seen = self.custom.feed(rec, out).into_iter().map(|(name, o)| (name.to_string(), o)).collect(),
            Source::Auth => self.auth(rec, out),
            // out-of-memory kills, service failures, su/sudo and the audit log become alerts
            // in the pipeline; peer evidence arrives as cluster facts
            Source::Peer | Source::Kernel | Source::Systemd | Source::Privilege | Source::Audit => {}
        }
        self.drop_whitelisted(out, start);
        for e in &mut out[start..] {
            if e.signal == Signal::FwBlock && self.ports.tripwired(e.port, e.proto) {
                e.signal = Signal::FwTripwire;
                e.detail = format!("tripwire {}", e.detail);
            }
            self.mark_canary(e);
        }
        self.drop_trip_twins(out, start);
    }

    /// A failed login PAM logged from an address on the internet, at a service no other
    /// parser reads.
    fn auth(&self, rec: &Record, out: &mut Vec<Event>) {
        let ident = rec.sender.as_ref().and_then(|s| s.ident.as_deref()).unwrap_or("");
        let Some(auth::Auth::Failure(f)) = auth::pam(ident, &rec.msg) else { return };
        let auth::Rhost::Addr(ip) = f.rhost else { return };
        if self.auth_scored_elsewhere.contains(&f.service.as_str()) {
            return;
        }
        let account = format!("{}:{}", f.service, f.user);
        let detail = format!("failed {} password for {}", f.service, f.user);
        out.push(Event::new(rec.ts, ip, Signal::PamAuthFail).account(Some(&account)).detail(detail));
    }

    /// Drops a tripwire hit logged a second time (by UFW and by logguard's own rule).
    fn drop_trip_twins(&mut self, out: &mut Vec<Event>, start: usize) {
        if !out[start..].iter().any(|e| e.signal == Signal::FwTripwire) {
            return;
        }
        let fresh = out.split_off(start);
        for e in fresh {
            if let (Signal::FwTripwire, Some(port)) = (e.signal, e.port) {
                let key = (e.ip, port);
                if self.trips.get(&key).is_some_and(|t| (e.ts - t).abs() < TRIP_TWIN) {
                    continue;
                }
                if self.trips.len() >= MAX_TRIPS {
                    let ts = e.ts;
                    self.trips.retain(|_, t| (ts - *t).abs() < TRIP_TWIN);
                }
                if self.trips.len() < MAX_TRIPS {
                    self.trips.insert(key, e.ts);
                }
            }
            out.push(e);
        }
    }

    /// Login attempts (and XMPP registrations) on canary accounts become `*_canary` events;
    /// a *successful* login to one too, so it never earns the address any trust.
    fn mark_canary(&self, e: &mut Event) {
        // Nextcloud's and ownCloud's failed logins from the apps' patterns:
        // `nextcloud_auth:admin`, ownCloud's quoted `owncloud_auth:'admin'`
        if e.signal == Signal::CustomFailure {
            let Some((pattern, user)) = e.account.as_deref().and_then(|a| a.split_once(':')) else { return };
            let user = user.trim_matches('\'');
            if self.cloud_logins.iter().any(|p| p == pattern) && self.canary.is_canary(Source::Nextcloud, user) {
                e.detail = format!("login attempt on canary account {user}");
                e.signal = Signal::NcCanary;
                e.points = None; // the canary's weight, not the pattern's
            }
            return;
        }
        let candidate =
            e.signal.is_auth_failure() || e.signal.is_success() || matches!(e.signal, Signal::XmppRegister | Signal::XmppTokenFail);
        let Some(acct) = e.account.as_deref().filter(|_| candidate) else { return };
        if !self.canary.is_canary(e.signal.source(), acct) {
            return;
        }
        let what = if e.signal.is_success() {
            crate::event::CANARY_LOGIN.to_string()
        } else if e.signal == Signal::XmppRegister {
            "registration of canary account".to_string()
        } else {
            "login attempt on canary account".to_string()
        };
        e.detail = format!("{what} {acct}");
        e.signal = match e.signal.source() {
            Source::Ejabberd => Signal::XmppCanary,
            Source::Ssh => Signal::SshCanary,
            _ => Signal::NcCanary,
        };
    }

    pub fn sweep(&mut self, now: Micros, out: &mut Vec<Event>) {
        let start = out.len();
        self.ejabberd.sweep(now, out);
        self.ssh.sweep(now);
        self.trips.retain(|_, t| now - *t < TRIP_TWIN);
        self.drop_whitelisted(out, start);
    }

    /// Whitelisted ports (e.g. a VPN and its panel) are legitimate by definition.
    fn drop_whitelisted(&self, out: &mut Vec<Event>, start: usize) {
        if self.ports.whitelist.is_empty() {
            return;
        }
        let fresh = out.split_off(start);
        out.extend(fresh.into_iter().filter(|e| !self.ports.whitelisted(e.port, e.proto)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_sources_and_whitelisted_ports() {
        let cfg = Config::from_toml("[sources]\nejabberd = false\n[ports]\nwhitelist = [\"51820/udp\", \"51821/tcp\"]").unwrap();
        let mut p = Parsers::new(&cfg);
        let mut out = vec![Event::new(0, "9.9.9.9".parse().unwrap(), crate::event::Signal::FwBlock)];
        let ufw = |dpt: u16, proto: &str| Record {
            ts: 0,
            source: Source::Ufw,
            pid: 0,
            msg: format!("[UFW BLOCK] IN=ens3 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO={proto} SPT=1 DPT={dpt}"),
            cursor: None,
            sender: None,
        };
        for (port, proto) in [(51820, "UDP"), (51821, "TCP"), (51820, "TCP"), (22, "TCP")] {
            p.feed(&ufw(port, proto), &mut out);
        }
        p.feed(
            &Record {
                ts: 0,
                source: Source::Ejabberd,
                pid: 1,
                msg: "2026-01-01 00:00:00.000 [info] (#PID<0.1.0>) Accepted connection 1.2.3.4:1 -> 5.6.7.8:5269".into(),
                cursor: None,
                sender: None,
            },
            &mut out,
        );
        let ports: Vec<_> = out.iter().map(|e| e.port).collect();
        assert_eq!(ports, vec![None, Some(51820), Some(22)], "earlier events untouched; whitelisted and ejabberd dropped");
        p.feed(&ufw(23, "TCP"), &mut out);
        p.feed(&ufw(23, "UDP"), &mut out);
        let last: Vec<_> = out[3..].iter().map(|e| (e.signal, e.detail.clone())).collect();
        assert_eq!(last[0], (crate::event::Signal::FwTripwire, "tripwire block TCP/23".into()));
        assert_eq!(last[1].0, crate::event::Signal::FwBlock, "default tripwires are TCP only");
    }

    #[test]
    fn canary_accounts() {
        let cfg = Config::from_toml(
            r#"
            [canary]
            xmpp = ["test", "Info@example.org"]
            ssh = ["*"]
            except = ["gw7f3a", "admin"]
            "#,
        )
        .unwrap();
        let mut p = Parsers::new(&cfg);
        let mut out = vec![];
        let ssh = |msg: &str| Record { ts: 0, source: Source::Ssh, pid: 0, msg: msg.into(), cursor: None, sender: None };
        let xmpp = |msg: &str| Record {
            ts: 0,
            source: Source::Ejabberd,
            pid: 1,
            msg: format!("2026-10-11 10:00:00.000 [info] (tls|<0.5.0>) {msg}"),
            cursor: None,
            sender: None,
        };
        p.feed(&ssh("Invalid user ubuntu from 1.2.3.4 port 5555"), &mut out);
        p.feed(&ssh("User root from 1.2.3.5 not allowed because not listed in AllowUsers"), &mut out);
        p.feed(&ssh("Connection closed by authenticating user gw7f3a 1.2.3.6 port 5556 [preauth]"), &mut out);
        p.feed(&ssh("Accepted publickey for gw7f3a from 1.2.3.6 port 5557 ssh2: ED25519 SHA256:x"), &mut out);
        p.feed(&xmpp("Failed c2s PLAIN authentication for TEST@example.org from ::ffff:9.9.9.9: Invalid username or password"), &mut out);
        p.feed(&xmpp("Failed c2s PLAIN authentication for info@example.org from ::ffff:9.9.9.8: Invalid username or password"), &mut out);
        p.feed(&xmpp("Failed c2s PLAIN authentication for admin@example.org from ::ffff:9.9.9.7: Invalid username or password"), &mut out);
        p.feed(&xmpp("Failed c2s PLAIN authentication for info@other.org from ::ffff:9.9.9.6: Invalid username or password"), &mut out);
        p.feed(&xmpp("Accepted c2s PLAIN authentication for test@example.org by mnesia backend from ::ffff:9.9.9.5"), &mut out);
        let got: Vec<(Signal, String)> = out.iter().map(|e| (e.signal, e.ip.to_string())).collect();
        use Signal::*;
        assert_eq!(
            got,
            vec![
                (SshCanary, "1.2.3.4".into()),
                (SshCanary, "1.2.3.5".into()),
                (SshAuthFail, "1.2.3.6".into()),
                (SshAuthOk, "1.2.3.6".into()),
                (XmppCanary, "9.9.9.9".into()),
                (XmppCanary, "9.9.9.8".into()),
                (XmppAuthFail, "9.9.9.7".into()),
                (XmppAuthFail, "9.9.9.6".into()),
                (XmppCanary, "9.9.9.5".into()),
            ]
        );
        assert!(out[8].detail.starts_with(crate::event::CANARY_LOGIN));
        assert!(Config::from_toml("[canary]\nssh = [\"*\"]").is_err(), "wildcard without except");
        assert!(Config::from_toml("[canary]\nxmpp = [\"*\"]\nexcept = [\"a\"]").is_err());
    }

    /// `[canary] nextcloud` covers the apps' Nextcloud and ownCloud logins too.
    #[test]
    fn canary_accounts_of_the_cloud_apps() {
        let cfg = Config::from_toml(
            "[sources]\napps = [\"nextcloud\", \"owncloud\"]\n[sources.app_logs]\nnextcloud = \"/srv/nc.log\"\nowncloud = \"/srv/oc.log\"\n\
             [canary]\nnextcloud = [\"test\", \"Guest\"]\nexcept = [\"admin\"]",
        )
        .unwrap();
        let mut p = Parsers::new(&cfg);
        let line = |file: &str, ip: &str, msg: &str| Record {
            ts: 0,
            source: Source::Custom,
            pid: 0,
            msg: format!(
                r#"{{"reqId":"a","level":2,"time":"2026-10-26T10:00:00+00:00","remoteAddr":"{ip}","user":"--","app":"core","method":"POST","url":"/login","message":"{msg}"}}"#
            ),
            cursor: None,
            sender: Some(Box::new(crate::record::Sender { file: Some(file.into()), ..Default::default() })),
        };
        let mut out = vec![];
        p.feed(&line("/srv/nc.log", "203.0.113.1", "Login failed: test (Remote IP: 203.0.113.1)"), &mut out);
        p.feed(&line("/srv/oc.log", "203.0.113.2", "Login failed: 'guest' (Remote IP: '203.0.113.2')"), &mut out);
        p.feed(&line("/srv/nc.log", "203.0.113.3", "Login failed: alice (Remote IP: 203.0.113.3)"), &mut out);
        p.feed(&line("/srv/oc.log", "203.0.113.4", "Login failed: 'admin' (Remote IP: '203.0.113.4')"), &mut out);
        let got: Vec<(Signal, Option<f64>, String)> = out.iter().map(|e| (e.signal, e.points, e.detail.clone())).collect();
        assert_eq!(got[0], (Signal::NcCanary, None, "login attempt on canary account test".into()));
        assert_eq!((got[1].0, got[1].2.as_str()), (Signal::NcCanary, "login attempt on canary account guest"), "ownCloud's quotes");
        assert_eq!((got[2].0, got[2].1), (Signal::CustomFailure, Some(25.0)), "not a canary");
        assert_eq!(got[3].0, Signal::CustomFailure, "except");
        assert_eq!(cfg.weight(Signal::NcCanary), 100.0, "one attempt bans");

        // a pattern of your own with the same name, the app not in use: left alone
        let mine = Config::from_toml(
            "[canary]\nnextcloud = [\"test\"]\n[[patterns]]\nname = \"nextcloud_auth\"\nfile = \"/srv/nc.log\"\nregex = '\"remoteAddr\":\"(?P<ip>[0-9.]+)\".*Login failed: (?P<user>\\S+)'",
        )
        .unwrap();
        let mut p = Parsers::new(&mine);
        let mut out = vec![];
        p.feed(&line("/srv/nc.log", "203.0.113.1", "Login failed: test (Remote IP: 203.0.113.1)"), &mut out);
        assert_eq!(out[0].signal, Signal::CustomFailure);
    }

    /// Log lines carry attacker-controlled text: no input may panic a parser (a panic aborts
    /// the daemon). Random splices of real message fragments, multi-byte characters and
    /// truncations, through every record format and parser, and on into the engine.
    #[test]
    fn hostile_lines_never_panic() {
        const FRAGMENTS: &[&str] = &[
            "2026-10-11 10:00:00.000 ",
            "2026-10-11T10:00:00",
            "[info] ",
            "[warning] ",
            "(tls|<0.5.0>) ",
            "(#PID<0.9.0>) ",
            "(",
            ") ",
            "<",
            ">",
            "Accepted connection ",
            "1.2.3.4:5",
            "::ffff:",
            "[2001:db8::1]:443",
            " -> ",
            "5.6.7.8:5222",
            "Accepted c2s PLAIN authentication for ",
            "Failed c2s PLAIN authentication for ",
            "a@b",
            " from ",
            ": ",
            "Failed to secure c2s connection: ",
            "Closing inbound s2s connection ",
            "Certificate in ",
            " for ",
            "will expire",
            "Storing certificate ",
            "Invalid user ",
            "User ",
            " not allowed because ",
            "Connection closed by invalid user ",
            "Connection closed by authenticating user ",
            " port ",
            "65536",
            "99999999999999999999",
            "[preauth]",
            "Failed password for ",
            "drop connection #",
            "srclimit_penalise: ",
            "[UFW BLOCK] ",
            "[UFW ",
            "]",
            "SRC=",
            "DPT=",
            "PROTO=TCP ",
            "[client",
            "[client: ",
            "client denied by server configuration: ",
            "AH10244",
            "invalid URI path (",
            "{",
            "}",
            "\"remoteAddr\":\"9.9.9.9\"",
            "pam_unix(",
            "login:auth): ",
            "authentication failure; logname= uid=0 euid=0 tty=",
            " rhost=",
            " ruser=",
            " user=",
            "type=USER_AUTH msg=audit(1.2:3): ",
            "USER_LOGIN ",
            "SYSCALL ",
            "msg='",
            "acct=",
            "726F6F74",
            "\"",
            "'",
            "\u{1d}AUID=",
            "key=",
            "add '",
            "' to group '",
            "new user: name=",
            "change user '",
            "\"message\":\"Login failed: x (Remote IP: 1.1.1.1)\"",
            "Login failed",
            "\"",
            ",",
            "é",
            "日本",
            "\u{0}",
            "\t",
            "\n",
            " ",
            "-",
            ":",
            ".",
            "/",
            "%",
            "\u{202e}",
            "🦀",
        ];
        let cfg =
            Config::from_toml("[sources]\nnextcloud_aio = true\n[canary]\nxmpp = [\"test\"]\nssh = [\"*\"]\nexcept = [\"gw\"]").unwrap();
        let mut parsers = Parsers::new(&cfg);
        let mut engine = crate::engine::Engine::new(std::sync::Arc::new(cfg.clone()), 0);
        let mut years = crate::record::YearGuess::new(2026);
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..15_000 {
            let mut line = String::new();
            for _ in 0..(next() % 12) {
                line += FRAGMENTS[(next() % FRAGMENTS.len() as u64) as usize];
            }
            // truncate at a random char boundary
            let cut = (next() as usize) % (line.len() + 1);
            let cut = (0..=cut).rev().find(|&i| line.is_char_boundary(i)).unwrap_or(0);
            let line = &line[..cut];
            let mut out = Vec::new();
            for source in [Source::Ejabberd, Source::Ssh, Source::Ufw, Source::Nextcloud, Source::Auth] {
                let rec = Record { ts: round, source, pid: (next() % 3) as u32, msg: line.to_string(), cursor: None, sender: None };
                parsers.feed(&rec, &mut out);
            }
            for ident in ["login", "useradd", "usermod", "gpasswd", "passwd"] {
                let _ = auth::pam(ident, line);
            }
            let _ = auth::audit(line, &["*".to_string()]);
            let _ = crate::record::parse_syslog_line(line, &mut years);
            let _ = crate::record::parse_journal_json(line);
            if let Some(rec) = crate::record::parse_nextcloud_line(line) {
                parsers.feed(&rec, &mut out);
            }
            parsers.sweep(round, &mut out);
            for e in &out {
                engine.on_event(e);
            }
        }
    }
}
