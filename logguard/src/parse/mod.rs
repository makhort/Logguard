//! Turns raw records into security events.

pub mod ejabberd;
pub mod kernel;
pub mod nextcloud;
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
    sources: crate::config::SourcesCfg,
    ports: crate::config::PortsCfg,
    canary: crate::config::CanaryCfg,
}

impl Parsers {
    pub fn new(cfg: &Config) -> Self {
        Parsers {
            ejabberd: ejabberd::EjabberdParser::new(cfg.xmpp.c2s_ports.clone(), cfg.xmpp.noauth_grace.micros()),
            ssh: ssh::SshParser::default(),
            sources: cfg.sources.clone(),
            ports: cfg.ports.clone(),
            canary: cfg.canary.clone(),
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
            // out-of-memory kills become operational alerts in the pipeline, not events
            // service failures become operational alerts in the pipeline too
            Source::Peer | Source::Kernel | Source::Systemd => {} // peer evidence arrives as cluster facts
        }
        self.drop_whitelisted(out, start);
        for e in &mut out[start..] {
            if e.signal == Signal::FwBlock && self.ports.tripwired(e.port, e.proto) {
                e.signal = Signal::FwTripwire;
                e.detail = format!("tripwire {}", e.detail);
            }
            self.mark_canary(e);
        }
    }

    /// Login attempts (and XMPP registrations) on canary accounts become `*_canary` events;
    /// a *successful* login to one too, so it never earns the address any trust.
    fn mark_canary(&self, e: &mut Event) {
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
        let ssh = |msg: &str| Record { ts: 0, source: Source::Ssh, pid: 0, msg: msg.into(), cursor: None };
        let xmpp = |msg: &str| Record {
            ts: 0,
            source: Source::Ejabberd,
            pid: 1,
            msg: format!("2026-10-11 10:00:00.000 [info] (tls|<0.5.0>) {msg}"),
            cursor: None,
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
        let cfg = Config::from_toml("[sources]\nnextcloud = true\n[canary]\nxmpp = [\"test\"]\nssh = [\"*\"]\nexcept = [\"gw\"]").unwrap();
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
            for source in [Source::Ejabberd, Source::Ssh, Source::Ufw, Source::Nextcloud] {
                let rec = Record { ts: round, source, pid: (next() % 3) as u32, msg: line.to_string(), cursor: None };
                parsers.feed(&rec, &mut out);
            }
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
