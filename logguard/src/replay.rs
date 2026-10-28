//! Offline replay of log files through the exact pipeline the daemon uses.
//! Accepts `journalctl` short output (as in `sample_data/logs/weekly.log`) and
//! `journalctl -o json`, auto-detected per line. Never touches the firewall.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::config::Config;
use crate::engine::{Action, ActionKind, Snapshot};
use crate::pipeline::Pipeline;
use crate::record::{parse_journal_json, parse_syslog_line, YearGuess};
use crate::time::{self, Micros, SEC};

pub struct ReplayOpts {
    pub files: Vec<PathBuf>,
    pub year: Option<i64>,
    pub quiet: bool,
    pub verbose: bool,
    pub snapshot: Option<PathBuf>,
    pub top: usize,
    /// Write the state the daemon would persist at the end (to inspect or seed a daemon).
    pub state: Option<PathBuf>,
}

/// Feeds every line of `reader` through `pipe`, ticking on record time.
pub fn feed_reader(pipe: &mut Pipeline, reader: impl BufRead, years: &mut YearGuess, mut on_action: impl FnMut(&Action)) -> Result<Micros> {
    let mut next_tick: Option<Micros> = None;
    let mut last = 0;
    for line in reader.lines() {
        let line = line?;
        let rec = if line.starts_with('{') { parse_journal_json(&line).0 } else { parse_syslog_line(&line, years) };
        let Some(rec) = rec else { continue };
        if next_tick.is_none_or(|t| rec.ts >= t) {
            pipe.tick(rec.ts).iter().for_each(&mut on_action);
            next_tick = Some(rec.ts + SEC);
        }
        pipe.feed(&rec).iter().for_each(&mut on_action);
        last = last.max(rec.ts);
    }
    Ok(last)
}

/// Lazily parsed records of one input file.
struct FileRecords {
    lines: std::io::Lines<BufReader<File>>,
    years: YearGuess,
}

impl Iterator for FileRecords {
    type Item = Result<crate::record::Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match self.lines.next()? {
                Ok(l) => l,
                Err(e) => return Some(Err(e.into())),
            };
            let rec = if line.starts_with('{') { parse_journal_json(&line).0 } else { parse_syslog_line(&line, &mut self.years) };
            if let Some(rec) = rec.or_else(|| crate::record::parse_nextcloud_line(&line)) {
                return Some(Ok(rec));
            }
        }
    }
}

/// Replays files and returns the final snapshot plus every action taken.
/// Several files (e.g. separate ejabberd, sshd and ufw exports) are merged by
/// timestamp so the engine sees one chronological stream.
/// Decisions go to `on_action` as they happen (they aren't kept: a flood produces hundreds of thousands).
pub fn replay(cfg: Arc<Config>, opts: &ReplayOpts, mut on_action: impl FnMut(&Action)) -> Result<Snapshot> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let year = opts.year.unwrap_or_else(|| time::year_of(time::now()));
    let mut sources = Vec::new();
    for path in &opts.files {
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        sources.push(FileRecords { lines: BufReader::new(f).lines(), years: YearGuess::new(year) });
    }
    // Min-heap on (timestamp, file index, sequence) - each file is (nearly) sorted already.
    let mut heads = BinaryHeap::new();
    let mut pending = Vec::new();
    for (i, src) in sources.iter_mut().enumerate() {
        if let Some(rec) = src.next().transpose()? {
            heads.push(Reverse((rec.ts, i)));
            pending.push(Some(rec));
        } else {
            pending.push(None);
        }
    }

    let mut pipe = Pipeline::new(Arc::clone(&cfg), 0);
    if cfg.geo.enabled {
        // Labels from an already downloaded database; replay never downloads.
        match crate::geo::GeoDb::open(&cfg.geo) {
            Ok(db) => pipe.engine.geo = Some(Arc::new(db)),
            Err(e) => eprintln!("logguard: no place labels: {e:#}"),
        }
    }
    let (mut next_tick, mut last): (Option<Micros>, Micros) = (None, 0);
    while let Some(Reverse((_, i))) = heads.pop() {
        let rec = pending[i].take().expect("head present");
        if let Some(next) = sources[i].next().transpose()? {
            heads.push(Reverse((next.ts, i)));
            pending[i] = Some(next);
        }
        if next_tick.is_none_or(|t| rec.ts >= t) {
            for a in pipe.tick(rec.ts) {
                on_action(&a);
            }
            next_tick = Some(rec.ts + SEC);
        }
        for a in pipe.feed(&rec) {
            on_action(&a);
        }
        last = last.max(rec.ts);
    }
    // Flush connections still waiting for authentication; bans stay active.
    for a in pipe.tick(last + cfg.xmpp.noauth_grace.micros() + SEC) {
        on_action(&a);
    }
    if let Some(path) = &opts.state {
        std::fs::write(path, crate::engine::encode_state(&pipe.engine.export(None))?)?;
    }
    Ok(pipe.snapshot(opts.top.max(300)))
}

pub fn format_action(a: &Action, verbose: bool) -> String {
    let kind = match a.kind {
        ActionKind::Ban => "BAN",
        ActionKind::Unban => "UNBAN",
        ActionKind::Alert => "ALERT",
        ActionKind::Allow => "ALLOW",
        ActionKind::Disallow => "UNALLOW",
    };
    let sev = format!("{:?}", a.severity).to_lowercase();
    let mut s = format!("{} {kind:<5} {sev:<8} {}", time::fmt_ts(a.ts), a.message);
    if verbose {
        for e in &a.evidence {
            s += &format!("\n{:>36}{e}", "");
        }
    }
    s
}

pub fn print_summary(snap: &Snapshot, top: usize) {
    let st = &snap.stats;
    println!("\n== Summary ==");
    let records: Vec<String> = st.records.iter().map(|(s, n)| format!("{}={n}", s.name())).collect();
    println!("records:  {}", records.join("  "));
    let events: Vec<String> = st.events.iter().map(|(s, n)| format!("{}={n}", s.name())).collect();
    println!("events:   {}", events.join("  "));
    println!(
        "decisions: {} bans, {} alerts; {} bans active at end; {} unattributed ejabberd lines",
        st.bans,
        st.alerts,
        snap.bans.len(),
        st.unattributed
    );
    println!("\n{:<40} {:>7} {:>6} {:>6} {:>6}  {:<22} signals", "address", "danger%", "fast", "slow", "peak", "status");
    for v in snap.offenders.iter().take(top) {
        let status = match (&v.banned_by, &v.protected) {
            (Some(net), _) => format!("banned ({net})"),
            (None, Some(p)) => p.clone(),
            _ => String::new(),
        };
        let mut counts: Vec<(&crate::event::Signal, &u64)> = v.counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));
        let sig: Vec<String> = counts.iter().take(4).map(|(s, n)| format!("{}x{}", n, s.name())).collect();
        println!(
            "{:<40} {:>7.0} {:>6.0} {:>6.0} {:>6.0}  {:<22} {}",
            v.ip.to_string(),
            v.danger,
            v.fast,
            v.slow,
            v.peak,
            status,
            sig.join(" ")
        );
        if let Some(g) = &v.geo {
            println!("{:<40} {g}", "");
        }
    }
}
