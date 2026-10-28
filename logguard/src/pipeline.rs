//! Records → parsers → engine. Shared by the daemon and offline replay so
//! both make identical decisions for identical input.

use std::sync::Arc;

use crate::config::Config;
use crate::engine::{Action, Engine, Severity, Snapshot};
use crate::event::Event;
use crate::parse::Parsers;
use crate::record::Record;
use crate::time::Micros;

pub struct Pipeline {
    pub cfg: Arc<Config>,
    pub parsers: Parsers,
    pub engine: Engine,
    events: Vec<Event>,
    hidden_seen: u64,
    /// The last unclean exit status of each watched service, for its failure alert.
    exits: std::collections::HashMap<String, String>,
    /// Watched services that failed, waiting `service_restart_grace` to see whether they
    /// are started again: (when, what failed).
    failed: std::collections::HashMap<String, (Micros, String)>,
}

impl Pipeline {
    pub fn new(cfg: Arc<Config>, now: Micros) -> Self {
        Pipeline {
            parsers: Parsers::new(&cfg),
            engine: Engine::new(Arc::clone(&cfg), now),
            cfg,
            events: Vec::new(),
            hidden_seen: 0,
            exits: Default::default(),
            failed: Default::default(),
        }
    }

    /// The kernel killed a process for lack of memory. A scheduled virus scan dying this way
    /// is also reported by `[antivirus]`, so it's a warning; anything else (ejabberd, a
    /// database, logguard itself) is high.
    fn oom_alert(&mut self, k: &crate::parse::kernel::OomKill) -> Vec<Action> {
        use crate::engine::Severity;
        let scanner = matches!(k.process.as_str(), "clamscan" | "clamdscan" | "clamd");
        let severity = if scanner { Severity::Warning } else { Severity::High };
        let message = if k.cgroup {
            format!(
                "out of memory: the kernel killed {} (pid {}, {} MB) for exceeding its service/container memory limit (MemoryMax / docker --memory)",
                k.process, k.pid, k.rss_mb
            )
        } else {
            format!(
                "out of memory: the kernel killed {} (pid {}, {} MB) because the server ran out of RAM - add swap or memory, or find what grew (free -m; ps aux --sort=-rss | head)",
                k.process, k.pid, k.rss_mb
            )
        };
        self.engine.system_alert(&format!("oom:{}:{}", k.process, k.pid), 3600 * crate::time::SEC, severity, message)
    }

    /// A watched service ended unsuccessfully and nobody started it again (High: it is
    /// down), or systemd gave up restarting it. A failure systemd recovers from on its own
    /// (`Restart=`) says nothing. One alert per service and hour.
    fn service_alert(&mut self, msg: &str, ts: Micros) -> Vec<Action> {
        use crate::parse::systemd::UnitEvent;
        let Some((unit, event)) = crate::parse::systemd::parse(msg) else { return vec![] };
        match event {
            UnitEvent::Exited { status } => {
                self.exits.insert(unit, status);
                vec![]
            }
            UnitEvent::Failed { result } => {
                let status = self.exits.remove(&unit).map_or(String::new(), |s| format!(", exit status {s}"));
                self.failed.insert(unit, (ts, format!("{result}{status}")));
                vec![]
            }
            UnitEvent::Restarting | UnitEvent::Starting => {
                self.failed.remove(&unit);
                vec![]
            }
            UnitEvent::GaveUp => {
                self.failed.remove(&unit);
                let message = format!(
                    "service {unit} keeps failing: systemd stopped restarting it (systemctl reset-failed {unit}; systemctl start {unit})"
                );
                self.engine.system_alert(&format!("service:{unit}:gave-up"), 3600 * crate::time::SEC, Severity::High, message)
            }
        }
    }

    /// Failed services the grace time has passed for, without a restart: down.
    fn services_down(&mut self, now: Micros) -> Vec<Action> {
        let grace = self.cfg.sources.service_restart_grace.micros();
        let due: Vec<String> = self.failed.iter().filter(|(_, (at, _))| now - at >= grace).map(|(u, _)| u.clone()).collect();
        let mut out = Vec::new();
        for unit in due {
            let Some((_, what)) = self.failed.remove(&unit) else { continue };
            let message = format!(
                "service {unit} failed ({what}) and was not restarted: it is down. systemctl status {unit}; journalctl -u {unit} -n 30"
            );
            out.extend(self.engine.system_alert(&format!("service:{unit}:failed"), 3600 * crate::time::SEC, Severity::High, message));
        }
        out
    }

    pub fn feed(&mut self, rec: &Record) -> Vec<Action> {
        if !self.cfg.sources.enabled(rec.source) {
            return Vec::new();
        }
        // with auditd's file, the journal's copies of its records would count twice
        if rec.source == crate::record::Source::Audit && rec.cursor.is_some() && !self.cfg.sources.audit_log.as_os_str().is_empty() {
            return Vec::new();
        }
        // syslog exports carry systemd's lines about every unit; only the watched ones count
        if rec.source == crate::record::Source::Systemd
            && crate::parse::systemd::parse(&rec.msg).is_none_or(|(unit, _)| !self.cfg.sources.services.contains(&unit))
        {
            return Vec::new();
        }
        // lines no built-in parser reads: only those a pattern of your own finds something in
        if rec.source == crate::record::Source::Custom {
            if self.parsers.custom.is_empty() {
                return Vec::new();
            }
            self.parsers.feed(rec, &mut self.events);
            for (name, outcome) in std::mem::take(&mut self.parsers.pattern_seen) {
                self.engine.count_pattern(&name, rec.ts, outcome, &rec.msg);
            }
            if self.events.is_empty() {
                return Vec::new();
            }
            self.engine.count_record(rec.source, rec.ts);
            self.engine.now = self.engine.now.max(rec.ts);
            return self.drain();
        }
        self.engine.count_record(rec.source, rec.ts);
        // Lines that only produce ops notes (certificates) must still advance time.
        self.engine.now = self.engine.now.max(rec.ts);
        self.parsers.feed(rec, &mut self.events);
        let mut actions = self.drain();
        if let Some(k) = (rec.source == crate::record::Source::Kernel).then(|| crate::parse::kernel::parse_oom(&rec.msg)).flatten() {
            actions.extend(self.oom_alert(&k));
        }
        if rec.source == crate::record::Source::Systemd {
            actions.extend(self.service_alert(&rec.msg, rec.ts));
        }
        if rec.source == crate::record::Source::Privilege {
            let ident = rec.sender.as_ref().and_then(|s| s.ident.as_deref()).unwrap_or_else(|| crate::parse::privilege::ident_of(&rec.msg));
            if let Some(sw) = crate::parse::privilege::parse(ident, &rec.msg) {
                actions.extend(self.engine.on_privilege(&sw, rec.ts));
            }
        }
        let auth = match rec.source {
            crate::record::Source::Auth => {
                crate::parse::auth::pam(rec.sender.as_ref().and_then(|s| s.ident.as_deref()).unwrap_or(""), &rec.msg)
            }
            // sshd's own lockouts (its other PAM lines say what sshd's say)
            crate::record::Source::Ssh
                if self.cfg.sources.pam && (rec.msg.starts_with("pam_faillock(") || rec.msg.starts_with("pam_tally")) =>
            {
                crate::parse::auth::pam("sshd", &rec.msg)
            }
            crate::record::Source::Audit => crate::parse::auth::audit(&rec.msg, &self.cfg.sources.audit_keys),
            _ => None,
        };
        if let Some(a) = auth {
            actions.extend(self.engine.on_auth(&a, rec.ts));
        }
        actions.extend(self.services_down(rec.ts));
        for note in std::mem::take(&mut self.parsers.ejabberd.ops) {
            // log text (paths, host names, ACME's reasons): nothing that displays otherwise
            let mut message = crate::event::clean(&note.message, 500);
            let mut severity = note.severity;
            if note.key.starts_with("cert-expiry:") {
                // ejabberd also warns about old certificates still lying in acme/live. If every
                // certificate actually served is fine for 14+ days, this one isn't in use.
                // (judged by each certificate's own lifetime: Nextcloud's 6-day ones are fine too)
                let now = self.engine.now;
                let served: Vec<&crate::digest::CertStatus> =
                    self.engine.certs.iter().filter(|c| !c.file && c.not_after.is_some()).collect();
                if !served.is_empty() && served.iter().all(|c| c.expiry_concern(now, self.cfg.digest.cert_warn_days).is_none()) {
                    severity = crate::engine::Severity::Info;
                    let until = served.iter().filter_map(|c| c.not_after).min().unwrap_or_default();
                    message += &format!(
                        " - not in use (served certificates are valid until {}), safe to delete",
                        &crate::time::fmt_ts(until)[..10]
                    );
                }
            }
            // The path comes from a log line: only hash real certificate files (a few KB; this
            // runs on the main loop, so nothing openssl would take long over).
            let certificate_file = |p: &String| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() <= 1 << 20);
            if let Some(path) = note.new_cert.as_ref().filter(|p| p.starts_with('/') && !p.contains("/../") && certificate_file(p)) {
                // Only meaningful live (the file exists on this host); harmless in replays.
                if let Some(hash) = crate::digest::tlsa_311(&self.cfg.digest.openssl, path) {
                    message += &format!(". New DANE TLSA record: 3 1 1 {hash} - publish it (next to the old one) before switching");
                }
            }
            let every = if note.key.starts_with("acme-failed") { 6 * 3600 } else { 86_400 } * crate::time::SEC;
            actions.extend(self.engine.system_alert(&note.key, every, severity, message));
        }
        let hidden = self.parsers.ejabberd.hidden;
        if hidden > self.hidden_seen {
            self.hidden_seen = hidden;
            actions.extend(self.engine.system_alert(
                "hidden-ips",
                86_400 * crate::time::SEC,
                Severity::High,
                "ejabberd is hiding client addresses (hidden_by_ejabberd): XMPP detection is blind. Set `hide_sensitive_log_data: false` in ejabberd.yml".into(),
            ));
        }
        actions
    }

    /// An event observed outside the logs (a honeypot listener's connection), as if parsed.
    pub fn event(&mut self, ev: Event) -> Vec<Action> {
        self.engine.count_record(ev.signal.source(), ev.ts);
        self.engine.on_event(&ev)
    }

    pub fn tick(&mut self, now: Micros) -> Vec<Action> {
        self.parsers.sweep(now, &mut self.events);
        let mut actions = self.drain();
        actions.extend(self.services_down(now));
        actions.extend(self.engine.tick(now));
        actions
    }

    fn drain(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        for ev in std::mem::take(&mut self.events) {
            actions.extend(self.engine.on_event(&ev));
        }
        actions
    }

    pub fn snapshot(&self, max_offenders: usize) -> Snapshot {
        let mut s = self.engine.snapshot(self.parsers.ejabberd.tracked(), max_offenders);
        s.stats.unattributed = self.parsers.ejabberd.unattributed;
        s.stats.hidden_ips = self.parsers.ejabberd.hidden;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::CertStatus;
    use crate::record::Source;

    #[test]
    fn expiry_warning_for_unused_old_certificate_is_downgraded() {
        let mut p = Pipeline::new(Arc::new(Config::default()), 0);
        let day = 86_400 * crate::time::SEC;
        let now = 20_000 * day;
        let warn = |p: &mut Pipeline, ts| {
            p.feed(&Record {
                ts,
                source: Source::Ejabberd,
                pid: 1,
                msg: "2026-10-10 01:43:43.687 [warning] Certificate in /acme/live/879798 (at line: 1) for conference.example.org, example.org and 3 more hosts will expire in a week".into(),
                cursor: None,
                sender: None,
            })
        };
        // no certificate data yet: stays a warning
        let a = warn(&mut p, now);
        assert_eq!(a[0].severity, crate::engine::Severity::Warning);
        // the served certificate (f4156bc...) is valid for 80 more days: the warned one is unused
        p.engine.certs = vec![CertStatus { target: "example.org:5223".into(), not_after: Some(now + 80 * day), ..Default::default() }];
        let a = warn(&mut p, now + 2 * day);
        assert_eq!(a[0].severity, crate::engine::Severity::Info);
        assert!(a[0].message.contains("not in use"), "{}", a[0].message);
    }

    use crate::engine::{Severity, Topic};

    /// PAM and the audit log: a failed console login alerts once though PAM and the audit
    /// log both report it; a brute force on an FTP server is scored like SSH's; the journal's
    /// audit records don't count twice when auditd's file is read.
    #[test]
    fn pam_and_audit_lines() {
        use crate::record::Sender;
        let cfg = Config::from_toml("[sources]\naudit_keys = [\"identity\"]").unwrap();
        let mut p = Pipeline::new(Arc::new(cfg), 0);
        let pam = |s: i64, ident: &str, msg: &str| Record {
            ts: s * crate::time::SEC,
            source: Source::Auth,
            pid: 1,
            msg: msg.into(),
            cursor: Some("c".into()),
            sender: Some(Box::new(Sender { ident: Some(ident.into()), ..Default::default() })),
        };
        let audit = |s: i64, msg: &str| Record {
            ts: s * crate::time::SEC,
            source: Source::Audit,
            pid: 0,
            msg: msg.into(),
            cursor: Some("c".into()),
            sender: None,
        };
        let alerts = |a: &[Action]| {
            a.iter().filter(|a| a.kind == crate::engine::ActionKind::Alert).map(|a| (a.severity, a.message.clone())).collect::<Vec<_>>()
        };
        let console = "pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=root";
        let a = alerts(&p.feed(&pam(10, "login", console)));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, Severity::High);
        assert_eq!(a[0].1, "login as root on tty1 failed (login) - if it wasn't you, someone is trying root's password");
        let twin = "USER_AUTH pid=1 uid=0 auid=4294967295 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/bin/login\" hostname=? addr=? terminal=/dev/tty1 res=failed'";
        assert!(alerts(&p.feed(&audit(10, twin))).is_empty(), "the same failure");
        assert!(alerts(&p.feed(&pam(20, "login", console))).is_empty(), "counted into the next alert");
        let a = alerts(&p.feed(&pam(20 + 11 * 60, "login", console)));
        assert!(a[0].1.contains("(login), 3 failures in 11m10s"), "{a:?}");

        // polkit: per user who asked, whatever account they try
        let polkit = |user: &str| {
            format!("pam_unix(polkit-1:auth): authentication failure; logname= uid=1000 euid=0 tty= ruser=eve rhost= user={user}")
        };
        assert_eq!(alerts(&p.feed(&pam(1000, "polkit-agent-helper-1", &polkit("root")))).len(), 1);
        assert!(alerts(&p.feed(&pam(1002, "polkit-agent-helper-1", &polkit("gateway")))).is_empty());

        // FTP from the internet: scored, five strikes, no alert per failure
        let ftp = "pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=admin rhost=203.0.113.9  user=admin";
        let mut bans = 0;
        for s in 0..5 {
            let a = p.feed(&pam(2000 + s, "vsftpd", ftp));
            assert!(alerts(&a).iter().all(|(sev, m)| *sev != Severity::High || m.contains("ban")), "{a:?}");
            bans += a.iter().filter(|a| a.kind == crate::engine::ActionKind::Ban).count();
        }
        assert_eq!(bans, 1);
        assert_eq!(p.engine.export(None).bans.len(), 1);
        // abuse reports quote the evidence without the account
        let quoted = crate::abuse::sanitize("failed vsftpd password for admin").unwrap();
        assert!(!quoted.contains("admin") && quoted.contains("vsftpd"), "{quoted}");

        // account changes, auditd, rule keys
        let a = alerts(&p.feed(&pam(3000, "usermod", "add 'eve' to group 'sudo'")));
        assert_eq!(a[0].0, Severity::High);
        let grp =
            "GRP_MGMT pid=1 uid=0 auid=1000 msg='op=add-user-to-group grp=\"sudo\" acct=\"eve\" exe=\"/usr/sbin/usermod\" res=success'";
        assert!(alerts(&p.feed(&audit(3000, grp))).is_empty(), "the same change");
        let a = alerts(&p.feed(&audit(3100, "CONFIG_CHANGE op=set audit_enabled=0 old=1 auid=1000 ses=2 res=1")));
        assert_eq!(a[0].0, Severity::High);
        let sys =
            "SYSCALL arch=c000003e syscall=257 success=yes auid=1000 uid=0 tty=pts0 comm=\"vim\" exe=\"/usr/bin/vim\" key=\"identity\"";
        assert_eq!(alerts(&p.feed(&audit(3200, sys)))[0].0, Severity::Warning);

        // auditd's file: the journal's copies are left out
        let file = Arc::new(Config::from_toml("[sources]\naudit_log = \"/var/log/audit/audit.log\"").unwrap());
        let mut q = Pipeline::new(file, 0);
        let off = "CONFIG_CHANGE op=set audit_enabled=0 old=1 auid=1000 ses=2 res=1";
        assert!(q.feed(&audit(10, off)).is_empty());
        let from_file = Record { cursor: None, ..audit(10, &format!("type=CONFIG_CHANGE msg=audit(1.2:3): {}", &off[14..])) };
        assert_eq!(alerts(&q.feed(&from_file)).len(), 1);
        // pam = false, audit = false
        let mut off_cfg = Pipeline::new(Arc::new(Config::from_toml("[sources]\npam = false\naudit = false").unwrap()), 0);
        assert!(off_cfg.feed(&pam(10, "login", console)).is_empty() && off_cfg.feed(&audit(10, twin)).is_empty());
    }

    /// A built-in app source (`[sources] apps`): an nginx error log's lines, as `tail -F`
    /// delivers them, through the engine to a ban.
    #[test]
    fn app_lines_ban() {
        let cfg = Config::from_toml("[sources]\napps = [\"nginx\"]\n[sources.app_logs]\nnginx_error = \"/srv/log/error.log\"").unwrap();
        let mut p = Pipeline::new(Arc::new(cfg), 0);
        let line = |s: u32, user: &str| {
            crate::record::Record {
            ts: i64::from(s) * crate::time::SEC,
            source: Source::Custom,
            pid: 0,
            msg: format!("2026/10/25 10:00:0{s} [error] 9#9: *{s} user \"{user}\": password mismatch, client: 198.51.100.8, server: x, request: \"GET / HTTP/1.1\""),
            cursor: None,
            sender: Some(Box::new(crate::record::Sender { file: Some("/srv/log/error.log".into()), ..Default::default() })),
        }
        };
        let bans = |a: &[crate::engine::Action]| a.iter().filter(|a| a.kind == crate::engine::ActionKind::Ban).count();
        for s in 1..5 {
            assert_eq!(bans(&p.feed(&line(s, "admin"))), 0, "25 points each");
        }
        assert_eq!(bans(&p.feed(&line(5, "root"))), 1, "five strikes");
        let snap = p.snapshot(50);
        let auth = snap.patterns.iter().find(|v| v.stats.name == "nginx_auth").unwrap();
        assert_eq!((auth.from.as_str(), auth.stats.matches), ("file /srv/log/error.log", 5));
        // another file's line isn't nginx's
        let mut other = line(6, "x");
        other.sender = Some(Box::new(crate::record::Sender { file: Some("/var/log/other.log".into()), ..Default::default() }));
        assert!(p.feed(&other).is_empty());
    }

    #[test]
    fn privilege_and_custom_lines() {
        let cfg = Config::from_toml(
            "[[patterns]]\nname = \"web\"\nidentifier = \"nginx\"\nuid = 33\nkind = \"probe\"\nweight = 60\nregex = '^(?P<ip>\\S+) .*GET /\\.env'",
        )
        .unwrap();
        let mut p = Pipeline::new(Arc::new(cfg), 0);
        let mut y = crate::record::YearGuess::new(2026);
        let mut feed = |p: &mut Pipeline, line: &str| p.feed(&crate::record::parse_syslog_line(line, &mut y).unwrap());
        let a = feed(&mut p, "Oct 24 10:00:00 h su[77]: FAILED SU (to root) gateway on pts/0");
        assert_eq!((a.len(), a[0].severity, a[0].topic), (1, Severity::High, Some(Topic::Compromise)));
        assert!(a[0].message.starts_with("su to root failed for gateway on pts/0"), "{}", a[0].message);
        let a = feed(&mut p, "Oct 24 10:00:20 h su[78]: (to root) gateway on pts/0");
        assert!(a[0].message.contains("succeeded after 1 failed attempts"), "{}", a[0].message);
        let a = feed(&mut p, "Oct 24 11:00:00 h su[79]: (to root) gateway on pts/0");
        assert_eq!((a[0].severity, a[0].topic), (Severity::Info, None), "the admin's own way in: logged, not sent");
        // a line of a pattern of your own; other lines of no parser are dropped uncounted
        let a = feed(&mut p, "Oct 24 11:00:01 h nginx[5]: 198.51.100.7 - - \"GET /.env HTTP/1.1\" 404");
        assert!(a.is_empty(), "60 points: no ban yet");
        let a = feed(&mut p, "Oct 24 11:00:02 h nginx[5]: 198.51.100.7 - - \"GET /.env.bak HTTP/1.1\" 404");
        assert_eq!(a.iter().filter(|a| a.kind == crate::engine::ActionKind::Ban).count(), 1, "{a:?}");
        assert_eq!(a[0].category.as_deref(), Some("custom"));
        assert!(feed(&mut p, "Oct 24 11:00:03 h cron[6]: (root) CMD (x)").is_empty());
        assert_eq!(p.engine.stats.records.get(&Source::Custom), Some(&2));
        // a match whose group ip holds no address: counted for the Patterns tab only
        assert!(feed(&mut p, "Oct 24 11:00:04 h nginx[5]: unknown - - \"GET /.env HTTP/1.1\" 404").is_empty());
        assert_eq!(p.engine.stats.records.get(&Source::Custom), Some(&2));
        let snap = p.snapshot(50);
        let st = &snap.patterns[0].stats;
        assert_eq!((st.name.as_str(), st.matches, st.no_address, snap.patterns[0].addresses), ("web", 2, 1, 1));
        assert_eq!(st.lines, 3, "lines from nginx's uid, matched or not");
        assert_eq!((st.ips[0].ip.to_string(), st.ips[0].lines), ("198.51.100.7".to_string(), 2));
        assert!(st.no_address_lines[0].1.starts_with("unknown - - "), "{:?}", st.no_address_lines);

        // kept across restarts, for the patterns still configured
        let saved = p.engine.export(None);
        let mut again = Pipeline::new(Arc::clone(&p.cfg), 0);
        again.engine.restore(saved.clone());
        assert_eq!(again.snapshot(50).patterns[0].stats, *st);
        let mut other = Pipeline::new(Arc::new(Config::default()), 0);
        other.engine.restore(saved);
        assert!(other.snapshot(50).patterns.is_empty() && other.engine.export(None).patterns.is_empty());
    }

    #[test]
    fn oom_kills_become_system_alerts() {
        let mut p = Pipeline::new(std::sync::Arc::new(crate::config::Config::default()), 0);
        let rec = |pid: u32, name: &str| Record {
            ts: 1_000 * crate::time::SEC,
            source: Source::Kernel,
            pid: 0,
            msg: format!("Out of memory: Killed process {pid} ({name}) total-vm:970112kB, anon-rss:920752kB, file-rss:68kB"),
            cursor: None,
            sender: None,
        };
        let a = p.feed(&rec(1, "clamscan"));
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].severity, a[0].topic), (Severity::Warning, Some(Topic::System)));
        assert!(a[0].message.contains("killed clamscan (pid 1, 899 MB)"), "{}", a[0].message);
        let a = p.feed(&rec(2, "beam.smp"));
        assert_eq!(a[0].severity, Severity::High);
        assert!(p.feed(&rec(2, "beam.smp")).is_empty(), "the same kill read twice is one alert");
    }

    #[test]
    fn watched_service_failures_alert() {
        let mut cfg = crate::config::Config::default();
        cfg.sources.services = vec!["logguard-xmpp-bot.service".into()];
        let mut p = Pipeline::new(std::sync::Arc::new(cfg), 0);
        let mut y = crate::record::YearGuess::new(2026);
        let t0 = crate::time::parse_syslog("Oct", "14", "10:00:00", 2026).unwrap();
        let mut feed = |p: &mut Pipeline, line: &str| p.feed(&crate::record::parse_syslog_line(line, &mut y).unwrap());
        let min = 60 * crate::time::SEC;

        // exit 78 and RestartPreventExitStatus: no restart follows, so after the grace time it's down
        assert!(feed(
            &mut p,
            "Oct 14 10:00:00 h systemd[1]: logguard-xmpp-bot.service: Main process exited, code=exited, status=78/CONFIG"
        )
        .is_empty());
        assert!(feed(&mut p, "Oct 14 10:00:00 h systemd[1]: logguard-xmpp-bot.service: Failed with result 'exit-code'.").is_empty());
        assert!(p.tick(t0 + min).is_empty(), "still within the grace time");
        let a = p.tick(t0 + 2 * min);
        assert_eq!((a.len(), a[0].severity, a[0].topic), (1, Severity::High, Some(Topic::System)));
        assert!(
            a[0].message.contains("logguard-xmpp-bot.service failed (exit-code, exit status 78/CONFIG) and was not restarted"),
            "{}",
            a[0].message
        );
        assert!(p.tick(t0 + 3 * min).is_empty(), "reported once");

        // any other unclean end that systemd restarts on its own: nothing
        feed(&mut p, "Oct 14 11:00:00 h systemd[1]: logguard-xmpp-bot.service: Main process exited, code=killed, status=9/KILL");
        feed(&mut p, "Oct 14 11:00:00 h systemd[1]: logguard-xmpp-bot.service: Failed with result 'signal'.");
        assert!(feed(&mut p, "Oct 14 11:00:05 h systemd[1]: logguard-xmpp-bot.service: Scheduled restart job, restart counter is at 1.")
            .is_empty());
        assert!(p.tick(t0 + 70 * min).is_empty(), "restarted by systemd");
        // ...or that someone starts again by hand within the grace time
        feed(&mut p, "Oct 14 12:00:00 h systemd[1]: logguard-xmpp-bot.service: Failed with result 'exit-code'.");
        feed(&mut p, "Oct 14 12:01:00 h systemd[1]: Starting logguard-xmpp-bot.service - XMPP Admin Chatbot Service...");
        assert!(p.tick(t0 + 130 * min).is_empty());

        // a crash of a one-shot job (no Restart=): down, whatever the exit code
        let mut cfg = crate::config::Config::default();
        cfg.sources.services = vec!["logguard-abuse-report.service".into()];
        let mut p = Pipeline::new(std::sync::Arc::new(cfg), 0);
        feed(&mut p, "Oct 14 13:00:00 h systemd[1]: logguard-abuse-report.service: Main process exited, code=exited, status=1/FAILURE");
        feed(&mut p, "Oct 14 13:00:00 h systemd[1]: logguard-abuse-report.service: Failed with result 'exit-code'.");
        let a = p.tick(t0 + 182 * min);
        assert!(a[0].message.contains("exit status 1/FAILURE"), "{a:?}");

        // systemd giving up: at once
        let mut cfg = crate::config::Config::default();
        cfg.sources.services = vec!["logguard-xmpp-bot.service".into()];
        let mut p = Pipeline::new(std::sync::Arc::new(cfg), 0);
        feed(&mut p, "Oct 14 14:00:00 h systemd[1]: logguard-xmpp-bot.service: Failed with result 'exit-code'.");
        let a = feed(&mut p, "Oct 14 14:00:01 h systemd[1]: logguard-xmpp-bot.service: Start request repeated too quickly.");
        assert!(a[0].message.contains("stopped restarting"), "{}", a[0].message);
        assert!(p.tick(t0 + 250 * min).is_empty(), "not reported twice");
        // services not listed are ignored
        feed(&mut p, "Oct 14 15:00:00 h systemd[1]: cron.service: Failed with result 'exit-code'.");
        assert!(p.tick(t0 + 400 * min).is_empty());
    }
}
