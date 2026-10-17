//! Antivirus results: reads the log of scheduled ClamAV scans and tells the admin about
//! infected files, scans that died (killed for memory, typically) and scans that stopped
//! happening altogether.
//!
//! Understands plain `clamscan`/`clamdscan --stdout` output (the summary block with its
//! `End Date:`), and the markers that the shipped `logguard-avscan` script wraps around
//! each run, which add the exit code:
//!
//! ```text
//! logguard-avscan start 2026-10-12T02:30:01Z
//! /tmp/x: Eicar-Signature FOUND
//! ----------- SCAN SUMMARY -----------
//! ...
//! End Date:   2026:10:12 02:31:17
//! logguard-avscan end 2026-10-12T02:31:17Z exit=1
//! ```
//!
//! Dates without a zone (clamscan's own) are read as UTC, the server's time zone.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cronwatch::Finding;
use crate::engine::Severity;
use crate::time::{self, Dur, Micros, SEC};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AvCfg {
    pub enabled: bool,
    /// The scan results (stdout and stderr of clamscan/clamdscan, appended per run).
    pub log: PathBuf,
    /// Warn when no scan has finished for this long ("0s" = never).
    pub stale_after: Dur,
}

impl Default for AvCfg {
    fn default() -> Self {
        AvCfg { enabled: false, log: "/var/log/logguard/avscan.log".into(), stale_after: Dur(36 * 3600) }
    }
}

/// One scan run, as far as the log tells.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Scan {
    pub start: Option<Micros>,
    pub end: Micros,
    /// `path: Signature` of each infected file (capped).
    pub infected: Vec<String>,
    /// `Infected files:` from the summary (it can exceed the listed ones).
    pub infected_count: u64,
    pub scanned_files: Option<u64>,
    pub errors: u64,
    /// The scan's exit code, when the logguard-avscan markers are present.
    pub exit: Option<i32>,
    /// The summary block was written: the scanner ran to the end.
    pub completed: bool,
    pub db_outdated: bool,
}

impl Scan {
    pub fn infections(&self) -> u64 {
        self.infected_count.max(self.infected.len() as u64)
    }

    /// Finished: a summary and no exit code worse than "some files could not be read".
    pub fn ok(&self) -> bool {
        self.completed && self.exit.is_none_or(|e| (0..=2).contains(&e))
    }
}

const MAX_LISTED: usize = 200;

/// `2026:10:02 02:31:17` (clamscan) or ISO-8601 (`2026-10-12T02:31:17Z`).
fn parse_date(s: &str) -> Option<Micros> {
    let s = s.trim();
    if let Some((t, _)) = time::parse_iso_prefix(s) {
        return Some(t);
    }
    let iso = s.get(..10)?.replace(':', "-") + s.get(10..)?;
    time::parse_iso_prefix(&iso).map(|(t, _)| t)
}

fn number(s: &str) -> Option<u64> {
    s.split_whitespace().next()?.parse().ok()
}

/// Splits a scan log into runs, oldest first. A run still in progress is left out.
pub fn parse(text: &str) -> Vec<Scan> {
    let mut out = Vec::new();
    let mut cur = Scan::default();
    let mut marked = false; // inside a logguard-avscan start/end pair
    let mut started = false; // anything seen for `cur`
    for line in text.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("logguard-avscan start ") {
            let ts = parse_date(rest);
            if started && marked {
                // The previous run never wrote its end marker: the script itself was killed.
                cur.end = cur.end.max(ts.unwrap_or(0)).max(cur.start.unwrap_or(0));
                cur.completed = false;
                out.push(std::mem::take(&mut cur));
            }
            cur = Scan { start: ts, ..Default::default() };
            (marked, started) = (true, true);
        } else if let Some(rest) = line.strip_prefix("logguard-avscan end ").filter(|_| marked) {
            // (an end without a start is a forged line, or the run was already closed)
            let mut words = rest.split_whitespace();
            let ts = words.next().and_then(parse_date);
            cur.exit = words.find_map(|w| w.strip_prefix("exit=")).and_then(|c| c.parse().ok());
            cur.end = ts.unwrap_or(cur.end);
            if cur.end > 0 {
                out.push(std::mem::take(&mut cur));
            }
            (marked, started) = (false, false);
        } else if let Some(d) = line.strip_prefix("Start Date:") {
            cur.start = cur.start.or(parse_date(d));
            started = true;
        } else if let Some(d) = line.strip_prefix("End Date:") {
            // Only printed in the summary, so it proves the scan completed even when the
            // summary's head was cut off (by the read window, or a truncated log).
            cur.end = parse_date(d).unwrap_or(0);
            cur.completed = true;
            if !marked && cur.end > 0 {
                out.push(std::mem::take(&mut cur));
                started = false;
            }
        } else if line.contains("----------- SCAN SUMMARY -----------") {
            cur.completed = true;
            started = true;
        } else if let Some(n) = line.strip_prefix("Infected files:") {
            cur.infected_count = number(n).unwrap_or(0);
        } else if let Some(n) = line.strip_prefix("Scanned files:") {
            cur.scanned_files = number(n);
        } else if let Some(n) = line.strip_prefix("Total errors:") {
            cur.errors = number(n).unwrap_or(0);
        } else if line.contains("virus database is older than") || line.contains("This version of the ClamAV engine is outdated") {
            cur.db_outdated |= line.contains("database");
            started = true;
        } else if let Some(hit) = line.strip_suffix(" FOUND").filter(|l| l.contains(": ")) {
            if cur.infected.len() < MAX_LISTED {
                cur.infected.push(hit.chars().filter(|c| !c.is_control()).take(500).collect());
            }
            started = true;
        }
    }
    out
}

/// What the daemon remembers between reads (persisted).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AvState {
    /// End of the newest run already reported.
    pub reported: Micros,
    /// End of the newest run that finished properly.
    pub completed: Micros,
    /// That run, for `logguard status`.
    #[serde(default)]
    pub last: Option<Scan>,
}

/// One read of the scan log.
#[derive(Clone, Debug, Default)]
pub struct AvReport {
    pub read: Micros,
    /// None when the log hasn't changed since the previous read.
    pub scans: Option<Vec<Scan>>,
    pub error: Option<String>,
}

/// Reads the scan log when it changed (only its last 4 MB: older runs are long reported).
#[derive(Default)]
pub struct Reader {
    seen: Option<(u64, std::time::SystemTime)>,
}

impl Reader {
    pub fn read(&mut self, path: &Path) -> AvReport {
        let mut r = AvReport { read: time::now(), ..Default::default() };
        let res = (|| -> std::io::Result<Option<String>> {
            let mut f = std::fs::File::open(path)?;
            let meta = f.metadata()?;
            let stamp = (meta.len(), meta.modified()?);
            if self.seen == Some(stamp) {
                return Ok(None);
            }
            let skip = meta.len().saturating_sub(4 << 20);
            f.seek(SeekFrom::Start(skip))?;
            let mut buf = Vec::new();
            f.take(4 << 20).read_to_end(&mut buf)?;
            self.seen = Some(stamp);
            Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
        })();
        match res {
            Ok(text) => r.scans = text.map(|t| parse(&t)),
            Err(e) => {
                self.seen = None;
                r.error = Some(format!("{}: {e}", path.display()));
            }
        }
        r
    }
}

fn exit_meaning(code: i32) -> &'static str {
    match code {
        2 => "errors",
        50..=59 => "database or engine problem",
        62 => "cannot initialise logger",
        137 => "killed, probably out of memory",
        143 => "terminated",
        _ => "error",
    }
}

/// Reports new scan results and missing scans; `started` is when the daemon started.
pub fn judge(st: &mut AvState, r: &AvReport, cfg: &AvCfg, started: Micros) -> Vec<Finding> {
    let mut out = Vec::new();
    let now = r.read;
    let day = 86_400 * SEC;
    if let Some(scans) = &r.scans {
        // The log also holds file names, which can contain line breaks: a crafted name could
        // fake a run dated in the future, which would make every real run look old news.
        let (scans, forged): (Vec<&Scan>, Vec<&Scan>) = scans.iter().partition(|s| s.end <= now + 3600 * SEC);
        if let Some(f) = forged.first() {
            out.push(Finding {
                key: "av-future".into(),
                every: day,
                severity: Severity::High,
                message: format!(
                    "the virus scan log contains a run dated {} (in the future); ignored. A file name with line breaks can forge log lines - check the log",
                    time::fmt_ts(f.end)
                ),
                evidence: vec![],
                notify: true,
            });
        }
        if st.reported == 0 {
            // First read ever: only the newest run is news; older ones only tell when
            // the last good scan was.
            st.completed = scans.iter().filter(|s| s.ok()).map(|s| s.end).max().unwrap_or(0);
            st.last = scans.iter().filter(|s| s.ok()).max_by_key(|s| s.end).map(|s| (*s).clone());
            if let [.., older, newest] = scans[..] {
                st.reported = older.end.min(newest.end - 1);
            }
        }
        let reported = st.reported;
        for s in scans.iter().filter(|s| s.end > reported) {
            let when = time::fmt_ts(s.end);
            if s.infections() > 0 {
                let n = s.infections();
                out.push(Finding {
                    key: format!("av-infected:{}", s.end),
                    every: 0,
                    severity: Severity::Critical,
                    message: format!(
                        "virus scan finished {when}: {n} infected file{} found - check and quarantine them; the server may be compromised",
                        if n == 1 { "" } else { "s" }
                    ),
                    evidence: s.infected.clone(),
                    notify: true,
                });
            }
            if !s.ok() {
                let why = match s.exit {
                    Some(c) => format!("exit code {c}: {}", exit_meaning(c)),
                    None => "no summary written: the scanner was killed (out of memory?) or crashed".into(),
                };
                out.push(Finding {
                    key: format!("av-failed:{}", s.end),
                    every: 0,
                    severity: Severity::High,
                    message: format!("virus scan started {} did not finish ({why})", s.start.map_or(when.clone(), time::fmt_ts)),
                    evidence: vec![],
                    notify: true,
                });
            } else if s.infections() == 0 {
                let files = s.scanned_files.map(|n| format!("{n} files, ")).unwrap_or_default();
                let took = s.start.map(|b| format!(" in {}", time::fmt_duration(s.end - b))).unwrap_or_default();
                let errors = if s.errors > 0 { format!(", {} unreadable", s.errors) } else { String::new() };
                out.push(Finding {
                    key: format!("av-clean:{}", s.end),
                    every: 0,
                    severity: Severity::Info,
                    message: format!("virus scan finished {when}{took}: {files}nothing found{errors}"),
                    evidence: vec![],
                    notify: false,
                });
            }
            if s.db_outdated {
                out.push(Finding {
                    key: "av-db-old".into(),
                    every: day,
                    severity: Severity::Warning,
                    message: "ClamAV's virus database is older than 7 days - is freshclam (clamav-freshclam.service) running?".into(),
                    evidence: vec![],
                    notify: true,
                });
            }
            st.reported = st.reported.max(s.end);
            if s.ok() && s.end >= st.completed {
                st.completed = s.end;
                st.last = Some((*s).clone());
            }
        }
    }
    if let Some(e) = &r.error {
        if now - started >= cfg.stale_after.micros() || st.completed > 0 {
            out.push(Finding {
                key: "av-log".into(),
                every: day,
                severity: Severity::Warning,
                message: format!("cannot read the virus scan log {e}"),
                evidence: vec![],
                notify: true,
            });
        }
    }
    let stale = cfg.stale_after.micros();
    if stale > 0 {
        let message = if st.completed > 0 && now - st.completed >= stale {
            Some(format!(
                "no virus scan has finished since {} ({} ago) - check the scan's timer/cron job and its memory (journalctl -k | grep -i oom)",
                time::fmt_ts(st.completed),
                time::fmt_duration(now - st.completed)
            ))
        } else if st.completed == 0 && started > 0 && now - started >= stale {
            Some(format!(
                "no finished virus scan in {} since logguard started {} ago - is a scan scheduled?",
                cfg.log.display(),
                time::fmt_duration(now - started)
            ))
        } else {
            None
        };
        if let Some(message) = message {
            out.push(Finding { key: "av-stale".into(), every: day, severity: Severity::Warning, message, evidence: vec![], notify: true });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &str = "\
Data read: 123.68 MB (ratio 1.80:1)
Time: 56.156 sec (0 m 56 s)
Start Date: 2026:09:04 02:30:01
End Date:   2026:09:04 02:30:56

----------- SCAN SUMMARY -----------
Known viruses: 3628035
Engine version: 1.4.3
Scanned directories: 248
Scanned files: 2813
Infected files: 0
Data scanned: 234.42 MB
Time: 54.339 sec (0 m 54 s)
Start Date: 2026:09:05 02:30:01
End Date:   2026:09:05 02:30:58
/opt/app/x.php: Php.Webshell-1 FOUND

----------- SCAN SUMMARY -----------
Scanned files: 2810
Infected files: 1
Start Date: 2026:10:02 02:30:01
End Date:   2026:10:02 02:31:17
";

    #[test]
    fn parses_plain_clamscan_output() {
        let s = parse(LEGACY);
        assert_eq!(s.len(), 3);
        assert_eq!(time::fmt_ts(s[1].end), "2026-09-05 02:30:58");
        assert_eq!(s[1].scanned_files, Some(2813));
        assert!(s[1].ok() && s[1].infections() == 0);
        assert_eq!(s[2].infected, ["/opt/app/x.php: Php.Webshell-1"]);
        assert_eq!(s[2].infections(), 1);
        assert_eq!(time::fmt_ts(s[2].start.unwrap()), "2026-10-02 02:30:01");
    }

    #[test]
    fn parses_markers_and_killed_runs() {
        let text = "\
logguard-avscan start 2026-10-10T02:30:01Z
logguard-avscan end 2026-10-10T02:30:40Z exit=137
logguard-avscan start 2026-10-11T02:30:01Z
LibClamAV Warning: *** The virus database is older than 7 days! ***
logguard-avscan start 2026-10-12T02:30:01Z
/tmp/eicar.com: Eicar-Test-Signature FOUND
----------- SCAN SUMMARY -----------
Infected files: 1
Total errors: 3
End Date:   2026:10:12 02:31:00
logguard-avscan end 2026-10-12T02:31:01Z exit=1
logguard-avscan start 2026-10-13T02:30:01Z
";
        let s = parse(text);
        assert_eq!(s.len(), 3, "{s:?}");
        assert_eq!(s[0].exit, Some(137));
        assert!(!s[0].ok());
        assert!(!s[1].ok() && s[1].exit.is_none() && s[1].db_outdated, "{:?}", s[1]);
        assert_eq!(time::fmt_ts(s[1].end), "2026-10-12 02:30:01");
        assert!(s[2].ok() && s[2].exit == Some(1) && s[2].errors == 3);
        assert_eq!(time::fmt_ts(s[2].end), "2026-10-12 02:31:01");
    }

    #[test]
    fn reports_news_once_and_staleness() {
        let cfg = AvCfg { enabled: true, ..Default::default() };
        let mut st = AvState::default();
        let at = |s: &str| parse_date(s).unwrap();
        let rep = |read: Micros, text: Option<&str>| AvReport { read, scans: text.map(parse), error: None };

        // First read: the newest run (with a finding) is reported, older ones are not;
        // the last good scan was 10 days ago.
        let f = judge(&mut st, &rep(at("2026-10-12T12:00:00Z"), Some(LEGACY)), &cfg, at("2026-10-12T11:00:00Z"));
        let crit: Vec<_> = f.iter().filter(|x| x.severity == Severity::Critical).collect();
        assert_eq!(crit.len(), 1, "{f:?}");
        assert_eq!(crit[0].evidence, ["/opt/app/x.php: Php.Webshell-1"]);
        assert!(f.iter().any(|x| x.key == "av-stale" && x.message.contains("since 2026-10-02 02:31:17")), "{f:?}");
        assert!(!f.iter().any(|x| x.key.starts_with("av-clean")), "old clean runs are history");

        // Unchanged log: only the staleness check runs.
        let f = judge(&mut st, &rep(at("2026-10-12T12:01:00Z"), None), &cfg, 0);
        assert_eq!(f.iter().map(|x| x.key.as_str()).collect::<Vec<_>>(), ["av-stale"]);

        // A new clean scan: logged, not notified, and no longer stale.
        let more = format!("{LEGACY}----------- SCAN SUMMARY -----------\nScanned files: 9\nInfected files: 0\nStart Date: 2026:10:13 02:30:01\nEnd Date:   2026:10:13 02:31:00\n");
        let f = judge(&mut st, &rep(at("2026-10-13T03:00:00Z"), Some(&more)), &cfg, 0);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(!f[0].notify && f[0].message.contains("in 59s: 9 files, nothing found"), "{}", f[0].message);
        assert!(judge(&mut st, &rep(at("2026-10-13T04:00:00Z"), Some(&more)), &cfg, 0).is_empty());
        assert_eq!(st.last.as_ref().unwrap().scanned_files, Some(9));
    }

    #[test]
    fn forged_future_run_is_ignored() {
        let cfg = AvCfg { enabled: true, ..Default::default() };
        let mut st = AvState::default();
        // clamscan prints an infected file's name as is; this one carries a fake summary.
        let text = "logguard-avscan start 2026-10-12T02:30:00Z\n/tmp/a\nEnd Date:   2099:01:01 00:00:00\nlogguard-avscan end 2099-01-01T00:00:00Z exit=0\nx: Eicar-Test-Signature FOUND\n\
                    Infected files: 1\nEnd Date:   2026:10:12 02:31:00\nlogguard-avscan end 2026-10-12T02:31:00Z exit=1\n";
        let now = parse_date("2026-10-12T03:00:00Z").unwrap();
        let f = judge(&mut st, &AvReport { read: now, scans: Some(parse(text)), error: None }, &cfg, now);
        assert!(f.iter().any(|x| x.key == "av-future"), "{f:?}");
        assert!(f.iter().any(|x| x.severity == Severity::Critical), "the real summary still counts the infection: {f:?}");
        assert!(st.reported < now && st.completed < now);
    }

    #[test]
    fn no_scan_at_all() {
        let cfg = AvCfg { enabled: true, ..Default::default() };
        let mut st = AvState::default();
        let missing = AvReport { read: 40 * 3600 * SEC, scans: None, error: Some("/var/log/x: No such file".into()) };
        assert!(judge(&mut st, &AvReport { read: 3600 * SEC, ..missing.clone() }, &cfg, SEC).is_empty(), "grace after start");
        let f = judge(&mut st, &missing, &cfg, SEC);
        assert!(f.iter().any(|x| x.key == "av-log") && f.iter().any(|x| x.key == "av-stale"), "{f:?}");
    }
}
