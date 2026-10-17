//! Raw log records from either journald JSON (`journalctl -o json`) or
//! classic syslog text (`journalctl` short output, as in the sample logs).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::time::{self, Micros};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Ejabberd,
    Ssh,
    Ufw,
    /// Evidence reported by other logguard nodes in the cluster.
    Peer,
    /// Nextcloud (AIO): Apache error log via `docker logs`, logins via nextcloud.log.
    Nextcloud,
    /// Kernel messages other than UFW's: out-of-memory kills.
    Kernel,
    /// systemd's messages about the services in `[sources] services` (failures).
    Systemd,
}

impl Source {
    pub const ALL: [Source; 7] =
        [Source::Ejabberd, Source::Ssh, Source::Ufw, Source::Nextcloud, Source::Kernel, Source::Systemd, Source::Peer];

    pub fn name(self) -> &'static str {
        match self {
            Source::Ejabberd => "ejabberd",
            Source::Ssh => "ssh",
            Source::Ufw => "ufw",
            Source::Peer => "peer",
            Source::Nextcloud => "nextcloud",
            Source::Kernel => "kernel",
            Source::Systemd => "systemd",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Record {
    pub ts: Micros,
    pub source: Source,
    /// OS process id of the logging process (used to detect ejabberd restarts).
    pub pid: u32,
    pub msg: String,
    /// journald cursor, when the record came from the journal.
    pub cursor: Option<String>,
}

fn classify(ident: &str, unit: &str, msg: &str) -> Option<Source> {
    if ident.starts_with("ejabberd") || unit.starts_with("ejabberd") {
        Some(Source::Ejabberd)
    } else if ident == "sshd" || ident == "sshd-session" || ident == "sshd-auth" {
        Some(Source::Ssh)
    } else if ident == "kernel" && crate::parse::ufw::is_firewall_log(msg) {
        Some(Source::Ufw)
    } else if ident == "kernel" && (msg.contains("out of memory: Killed process") || msg.contains("Out of memory: Killed process")) {
        Some(Source::Kernel)
    } else if ident == "systemd" && crate::parse::systemd::parse(msg).is_some() {
        Some(Source::Systemd)
    } else {
        None
    }
}

/// ejabberd prefixes every message with its own millisecond ISO timestamp; prefer it.
fn refine_ts(source: Source, ts: Micros, msg: &str) -> Micros {
    if source == Source::Ejabberd {
        if let Some((iso, _)) = time::parse_iso_prefix(msg) {
            return iso;
        }
    }
    ts
}

/// Infers the year for syslog timestamps that lack one, handling Dec→Jan rollover.
#[derive(Debug)]
pub struct YearGuess {
    pub year: i64,
    last_month: u32,
}

impl YearGuess {
    pub fn new(year: i64) -> Self {
        YearGuess { year, last_month: 0 }
    }

    fn observe(&mut self, month: u32) -> i64 {
        if self.last_month >= 11 && month <= 2 {
            self.year += 1;
        }
        self.last_month = month;
        self.year
    }

    fn sync(&mut self, ts: Micros) {
        self.year = time::year_of(ts);
    }
}

/// Parses `Aug 16 21:20:19 host ident[pid]: message` (or an ISO-8601 first field).
pub fn parse_syslog_line(line: &str, years: &mut YearGuess) -> Option<Record> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (ts, rest) = if let Some((ts, used)) = time::parse_iso_prefix(line) {
        let rest = line[used..].trim_start_matches(|c: char| c != ' ');
        (ts, rest.trim_start())
    } else {
        let mut it = line.splitn(4, ' ').filter(|s| !s.is_empty());
        let (mon, day) = (it.next()?, it.next()?);
        // splitn on single spaces leaves day padding ("Aug  5") as an empty field; re-split.
        let tail = line.get(mon.len()..)?.trim_start();
        let tail = tail.get(day.len()..)?.trim_start();
        let (clock, rest) = tail.split_once(' ')?;
        let month = time::month_from_abbr(mon)?;
        let year = years.observe(month);
        (time::parse_syslog(mon, day, clock, year)?, rest)
    };
    let (_host, rest) = rest.split_once(' ')?;
    let (tag, msg) = rest.split_once(": ")?;
    let (ident, pid) = match tag.split_once('[') {
        Some((ident, pid)) => (ident, pid.trim_end_matches(']').parse().unwrap_or(0)),
        None => (tag, 0),
    };
    let source = classify(ident, "", msg)?;
    let ts = refine_ts(source, ts, msg);
    if source == Source::Ejabberd {
        years.sync(ts);
    }
    Some(Record { ts, source, pid, msg: msg.to_string(), cursor: None })
}

fn field_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        // journald emits non-UTF-8 payloads as byte arrays
        Value::Array(bytes) => {
            let raw: Vec<u8> = bytes.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect();
            Some(String::from_utf8_lossy(&raw).into_owned())
        }
        _ => None,
    }
}

#[derive(Deserialize)]
struct JournalEntry {
    #[serde(rename = "MESSAGE")]
    message: Option<Value>,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime: Option<String>,
    #[serde(rename = "__CURSOR")]
    cursor: Option<String>,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    ident: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    unit: Option<String>,
    #[serde(rename = "_PID")]
    pid: Option<String>,
    #[serde(rename = "SYSLOG_PID")]
    syslog_pid: Option<String>,
    /// Trusted fields (set by journald, not by the sender).
    #[serde(rename = "_EXE")]
    exe: Option<String>,
    #[serde(rename = "_TRANSPORT")]
    transport: Option<String>,
    #[serde(rename = "_UID")]
    uid: Option<String>,
}

/// Whether the sender really is what the (sender-chosen) syslog identifier claims: any
/// local user can `logger -t sshd "Invalid user x from <someone else's address>"` to get
/// that address banned. journald records `_EXE` only if the sender is still running when
/// the line arrives (short-lived sshd-session processes often aren't, and neither is a
/// `logger` that exits at once); `_UID` comes from the socket and is always there: sshd's
/// lines about connection attempts are logged as root. Fields missing (exports) are accepted.
fn genuine(source: Source, e: &JournalEntry) -> bool {
    match source {
        Source::Ssh => match e.exe.as_deref() {
            Some(x) => x.rsplit('/').next().is_some_and(|b| b.starts_with("sshd")),
            None => e.uid.as_deref().is_none_or(|u| u == "0"),
        },
        Source::Ufw | Source::Kernel => e.transport.as_deref().is_none_or(|t| t == "kernel"),
        // the system manager, not a user's `systemd --user` or `logger -t systemd`
        Source::Systemd => e.pid.as_deref().is_none_or(|p| p == "1"),
        _ => true,
    }
}

/// The time of any followed Nextcloud line, event or not: `docker logs --timestamps`' prefix
/// (UTC), or the `"time"` of a nextcloud.log JSON line. Used to remember how far a log was read.
pub fn line_time(line: &str) -> Option<Micros> {
    time::parse_iso_prefix(line)
        .map(|(t, _)| t)
        .or_else(|| line.trim_start().starts_with('{').then(|| line.split("\"time\":\"").nth(1).and_then(time::parse_iso_offset)).flatten())
}

/// Parses a Nextcloud line: Apache's error log (`[Sat Oct 03 11:06:44 2026] [error] ...`),
/// optionally prefixed by `docker logs --timestamps` (RFC 3339, UTC), or a JSON line of
/// nextcloud.log (`{"time":"2026-10-11T19:16:24+00:00","remoteAddr":...}`).
pub fn parse_nextcloud_line(line: &str) -> Option<Record> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (prefix_ts, rest) = match time::parse_iso_prefix(line) {
        Some((ts, used)) => (Some(ts), line[used..].trim_start_matches('Z').trim_start()),
        None => (None, line),
    };
    let ts = if rest.starts_with('{') {
        // nextcloud.log lines can carry multi-KB stack traces; only failed logins matter,
        // so skip everything else before copying or parsing it (Caddy JSON included).
        if !rest.contains("Login failed") || !rest.contains("\"remoteAddr\"") {
            return None;
        }
        let t = rest.split("\"time\":\"").nth(1).and_then(time::parse_iso_offset);
        prefix_ts.or(t)?
    } else {
        // [Sat Oct 03 11:06:44 2026] or [Fri Oct 02 15:53:01.527478 2026]
        let inner = rest.strip_prefix('[')?;
        let head = &inner[..inner.find(']')?];
        let f: Vec<&str> = head.split_whitespace().collect();
        let apache = if f.len() == 5 { time::parse_syslog(f[1], f[2], f[3], f[4].parse().ok()?) } else { None };
        prefix_ts.or(apache)?
    };
    Some(Record { ts, source: Source::Nextcloud, pid: 0, msg: rest.to_string(), cursor: None })
}

/// Parses one line of `journalctl -o json`. Returns the cursor even for
/// records we don't care about, so checkpointing still advances.
pub fn parse_journal_json(line: &str) -> (Option<Record>, Option<String>) {
    let Ok(e) = serde_json::from_str::<JournalEntry>(line) else {
        return (None, None);
    };
    let cursor = e.cursor.clone();
    let Some(msg) = e.message.as_ref().and_then(field_str) else {
        return (None, cursor);
    };
    let ident = e.ident.as_deref().unwrap_or("");
    let unit = e.unit.as_deref().unwrap_or("");
    let Some(source) = classify(ident, unit, &msg).filter(|s| genuine(*s, &e)) else {
        return (None, cursor);
    };
    let ts = e.realtime.as_deref().and_then(|t| t.parse().ok()).unwrap_or_else(time::now);
    let pid = e.pid.as_deref().or(e.syslog_pid.as_deref()).and_then(|p| p.parse().ok()).unwrap_or(0);
    let rec = Record { ts, source, pid, msg, cursor: cursor.clone() };
    (Some(rec), cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_ejabberd_line_uses_inner_iso_timestamp() {
        let mut y = YearGuess::new(2020);
        let r = parse_syslog_line(
            "Aug 16 21:20:19 example.org ejabberdctl[26427]: 2026-08-16 21:20:19.107 [info] (#PID<0.28856.0>) Accepted connection [::ffff:11.32.25.27]:59195 -> [::ffff:11.17.39.236]:5223",
            &mut y,
        )
        .unwrap();
        assert_eq!(r.source, Source::Ejabberd);
        assert_eq!(r.pid, 26427);
        assert_eq!(time::fmt_ts(r.ts), "2026-08-16 21:20:19");
        assert_eq!(y.year, 2026);
        assert!(r.msg.starts_with("2026-08-16"));
    }

    #[test]
    fn syslog_padded_day_and_kernel_ufw() {
        let mut y = YearGuess::new(2026);
        let r = parse_syslog_line(
            "Aug  5 18:41:52 example.org kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=1.2.3.4 DST=5.6.7.8 LEN=40 TOS=0x00 PREC=0x00 TTL=240 ID=1 PROTO=TCP SPT=1 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0",
            &mut y,
        )
        .unwrap();
        assert_eq!(r.source, Source::Ufw);
        assert_eq!(time::fmt_ts(r.ts), "2026-08-05 18:41:52");
        assert!(parse_syslog_line("Aug 20 23:10:53 host systemd[1]: Stopping x", &mut y).is_none());
        let oom = "Oct 03 02:39:53 example.org kernel: Out of memory: Killed process 785891 (clamscan) total-vm:970112kB, anon-rss:920752kB, file-rss:68kB, shmem-rss:0kB, UID:0 pgtables:1928kB oom_score_adj:0";
        assert_eq!(parse_syslog_line(oom, &mut y).unwrap().source, Source::Kernel);
        assert!(parse_syslog_line("Oct 03 02:39:53 h kernel: oom-kill:constraint=CONSTRAINT_NONE,task=clamscan", &mut y).is_none());
    }

    #[test]
    fn journal_json() {
        let line = r#"{"__CURSOR":"s=abc","__REALTIME_TIMESTAMP":"1786000000000000","SYSLOG_IDENTIFIER":"sshd-session","_PID":"77","MESSAGE":"Invalid user admin from 1.2.3.4 port 5555"}"#;
        let (rec, cur) = parse_journal_json(line);
        let rec = rec.unwrap();
        assert_eq!(rec.source, Source::Ssh);
        assert_eq!(rec.pid, 77);
        assert_eq!(cur.as_deref(), Some("s=abc"));
        let other = r#"{"__CURSOR":"s=def","SYSLOG_IDENTIFIER":"cron","MESSAGE":"x"}"#;
        let (rec, cur) = parse_journal_json(other);
        assert!(rec.is_none());
        assert_eq!(cur.as_deref(), Some("s=def"));
        let forged = r#"{"SYSLOG_IDENTIFIER":"sshd","_EXE":"/usr/bin/logger","_TRANSPORT":"syslog","MESSAGE":"Invalid user admin from 1.2.3.4 port 5555"}"#;
        assert!(parse_journal_json(forged).0.is_none());
        let real = r#"{"SYSLOG_IDENTIFIER":"sshd-session","_EXE":"/usr/lib/openssh/sshd-session","MESSAGE":"Invalid user admin from 1.2.3.4 port 5555"}"#;
        assert!(parse_journal_json(real).0.is_some());
        // the sender exited before journald looked: judged by the user it ran as
        let exited = r#"{"SYSLOG_IDENTIFIER":"sshd","_UID":"1000","MESSAGE":"Invalid user admin from 1.2.3.4 port 5555"}"#;
        assert!(parse_journal_json(exited).0.is_none());
        let exited_root = r#"{"SYSLOG_IDENTIFIER":"sshd-session","_UID":"0","MESSAGE":"Invalid user admin from 1.2.3.4 port 5555"}"#;
        assert!(parse_journal_json(exited_root).0.is_some());
        let fake_ufw = r#"{"SYSLOG_IDENTIFIER":"kernel","_TRANSPORT":"syslog","MESSAGE":"[UFW BLOCK] IN=eth0 SRC=1.2.3.4"}"#;
        assert!(parse_journal_json(fake_ufw).0.is_none());
        let bytes = r#"{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":[73,110,118,97,108,105,100]}"#;
        assert_eq!(parse_journal_json(bytes).0.unwrap().msg, "Invalid");
    }
}
