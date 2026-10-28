//! Patterns of your own (`[[patterns]]`): a regular expression over the lines of a systemd
//! unit (journal) or of a log file, naming the client address (and maybe the account) in
//! groups `ip` and `user`. A matching line becomes an event with the pattern's points, so a
//! new service needs no new release:
//!
//! ```toml
//! [[patterns]]
//! name = "postfix_sasl"
//! unit = "postfix@-.service"
//! regex = 'warning: [^\[]*\[(?P<ip>[0-9A-Fa-f.:]+)\]: SASL \S+ authentication failed'
//! kind = "failure"
//! weight = 25
//! ```
//!
//! The `regex` crate matches in linear time, so no line an attacker shapes can make a pattern
//! take long (no catastrophic backtracking). Journal lines count only from the sender the
//! pattern names by journald's own fields (`unit`, `uid`): any local user can log lines with
//! any `SYSLOG_IDENTIFIER`.

use std::io::BufRead;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::event::{Event, Signal};
use crate::net::parse_ip;
use crate::record::{Record, Sender};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    /// A failed login: counted per account (distributed guessing, a login right after).
    Failure,
    /// Hostile, without a login (a probe for secrets, a refused request).
    Probe,
    /// A successful login: its address is trusted for this kind of line, like a login to
    /// XMPP or SSH, and its account's failures before it raise a compromise alert.
    Success,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternCfg {
    /// Shown in events and alerts; letters, digits, `_` and `-`.
    pub name: String,
    /// Journal: lines of this systemd unit (`_SYSTEMD_UNIT`, exactly), e.g. `postfix@-.service`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unit: String,
    /// Journal: lines with this `SYSLOG_IDENTIFIER` (any process can claim one: needs `uid`
    /// too, unless `unit` is set).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identifier: String,
    /// Journal: only lines logged by this user id (`_UID`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Instead of the journal: a log file, followed from its end (`tail -F`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// More files of the same kind (the built-in sources' logs, `parse::apps`).
    #[serde(skip)]
    pub extra_files: Vec<PathBuf>,
    /// Must have a group `ip` (the client address); `user` (the account) is optional.
    pub regex: String,
    #[serde(default = "default_kind")]
    pub kind: PatternKind,
    /// Points per matching line (ignored for `success`).
    #[serde(default = "default_weight")]
    pub weight: f64,
    /// The local port the service listens on, for the dashboard's port statistics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

fn default_kind() -> PatternKind {
    PatternKind::Failure
}

fn default_weight() -> f64 {
    25.0
}

/// Compiled programs larger than this are refused: a pattern is a configuration line, and
/// one that compiles to megabytes is a mistake.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Longest piece of a matched line kept as evidence.
const EVIDENCE_LEN: usize = 120;

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A journal field value as journalctl takes it in a match (`FIELD=value`).
fn field_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '+' || c == '=')
}

impl PatternCfg {
    fn compile(&self) -> Result<Regex> {
        let re = regex::RegexBuilder::new(&self.regex)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .with_context(|| format!("[[patterns]] {}: regex", self.name))?;
        if !re.capture_names().flatten().any(|n| n == "ip") {
            bail!("[[patterns]] {}: the regex needs a group named ip, e.g. (?P<ip>[0-9a-fA-F.:]+)", self.name);
        }
        Ok(re)
    }

    pub fn validate(&self) -> Result<()> {
        if !name_ok(&self.name) {
            bail!("[[patterns]] name '{}' must be 1-32 letters, digits, '_' or '-'", self.name);
        }
        let n = &self.name;
        let journal = !self.unit.is_empty() || !self.identifier.is_empty();
        match (&self.file, journal) {
            (Some(_), true) => bail!("[[patterns]] {n}: either a file or journal lines (unit, identifier), not both"),
            (None, false) => bail!("[[patterns]] {n}: name the lines: unit = \"...\" (journal) or file = \"/var/log/...\""),
            (Some(f), false) if !f.is_absolute() => bail!("[[patterns]] {n}: file must be an absolute path"),
            (Some(_), false) if self.uid.is_some() => bail!("[[patterns]] {n}: uid is for journal lines only"),
            _ => {}
        }
        if journal && self.unit.is_empty() && self.uid.is_none() {
            bail!(
                "[[patterns]] {n}: any local user can log lines with any identifier: name the sender's systemd unit \
                 (unit = \"...\") or its user id (uid = ...) too"
            );
        }
        if [&self.unit, &self.identifier].iter().any(|v| !v.is_empty() && !field_ok(v)) {
            bail!("[[patterns]] {n}: unit and identifier may not contain spaces, '=' or '+'");
        }
        if !self.weight.is_finite() || !(0.0..=1000.0).contains(&self.weight) {
            bail!("[[patterns]] {n}: weight must be within 0 and 1000");
        }
        self.compile().map(|_| ())
    }

    /// The log files it reads (none: journal lines).
    pub fn files(&self) -> impl Iterator<Item = &PathBuf> {
        self.file.iter().chain(&self.extra_files)
    }

    /// The journalctl match that brings this pattern's lines (none for a file).
    pub fn journal_match(&self) -> Option<String> {
        if self.file.is_some() {
            None
        } else if !self.unit.is_empty() {
            Some(format!("_SYSTEMD_UNIT={}", self.unit))
        } else {
            Some(format!("SYSLOG_IDENTIFIER={}", self.identifier))
        }
    }

    /// Whether a line from `s` is for this pattern. Journal lines are judged by journald's own
    /// fields; an export without them (`journalctl -o json` of a copy, syslog text) is taken by
    /// its identifier, as the built-in parsers take theirs.
    fn applies(&self, s: &Sender) -> bool {
        if self.file.is_some() {
            return s.file.as_deref().is_some_and(|got| self.files().any(|f| f.to_str() == Some(got)));
        }
        if s.file.is_some() {
            return false;
        }
        let ident_ok = self.identifier.is_empty() || s.ident.as_deref() == Some(self.identifier.as_str());
        // (a kernel message has none of the sender fields, but its transport)
        let export = s.unit.is_none() && s.exe.is_none() && s.uid.is_none() && s.transport.is_none();
        if export {
            return ident_ok;
        }
        let unit_ok = self.unit.is_empty() || s.unit.as_deref() == Some(self.unit.as_str());
        let uid_ok = self.uid.is_none_or(|u| s.uid.as_deref().and_then(|x| x.parse::<u32>().ok()) == Some(u));
        ident_ok && unit_ok && uid_ok
    }

    fn signal(&self) -> Signal {
        match self.kind {
            PatternKind::Failure => Signal::CustomFailure,
            PatternKind::Probe => Signal::CustomProbe,
            PatternKind::Success => Signal::CustomSuccess,
        }
    }
}

/// What a pattern found in one line.
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    pub ip: std::net::IpAddr,
    pub user: Option<String>,
    /// The matched text, cut to `EVIDENCE_LEN`, with the account (group `user`) left out: it
    /// is evidence, which abuse reports for other networks quote.
    pub text: String,
}

struct Compiled {
    cfg: PatternCfg,
    re: Regex,
}

impl Compiled {
    /// The address (and account) the line names, if the pattern matches it. Some(None): it
    /// matches, but group `ip` holds no address.
    fn find(&self, line: &str) -> Option<Option<Found>> {
        let caps = self.re.captures(line)?;
        let ip = caps.name("ip").and_then(|m| parse_ip(m.as_str()));
        let user = caps.name("user").filter(|u| !u.as_str().is_empty());
        let text = match (caps.get(0), user) {
            (Some(all), Some(u)) => format!("{}[account]{}", &line[all.start()..u.start()], &line[u.end()..all.end()]),
            (all, _) => all.map_or("", |m| m.as_str()).to_string(),
        };
        let text = crate::event::clean(&text, EVIDENCE_LEN);
        Some(ip.map(|ip| Found { ip, user: user.map(|u| u.as_str().to_string()), text }))
    }
}

/// The configured patterns, compiled.
#[derive(Default)]
pub struct Patterns {
    list: Vec<Compiled>,
}

impl Patterns {
    /// Compiles `[[patterns]]` and the built-in ones (validated with the configuration already).
    pub fn new<'a>(cfgs: impl IntoIterator<Item = &'a PatternCfg>) -> Self {
        let list = cfgs.into_iter().filter_map(|c| c.compile().ok().map(|re| Compiled { cfg: c.clone(), re })).collect();
        Patterns { list }
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Events for a line no built-in parser reads: the first pattern that is for its sender
    /// and finds an address in it. Returns what each pattern for its sender made of it.
    pub fn feed(&self, rec: &Record, out: &mut Vec<Event>) -> Vec<(&str, Outcome)> {
        let Some(sender) = rec.sender.as_deref() else { return Vec::new() };
        let mut seen = Vec::new();
        let mut won = false;
        for p in self.list.iter().filter(|p| p.cfg.applies(sender)) {
            let c = &p.cfg;
            let outcome = match (won, p.find(&rec.msg)) {
                (false, Some(Some(f))) => {
                    won = true;
                    let points = (c.kind != PatternKind::Success).then_some(c.weight);
                    // accounts of different patterns are different accounts
                    let account = f.user.as_ref().map(|u| format!("{}:{u}", c.name));
                    out.push(
                        Event::new(rec.ts, f.ip, c.signal())
                            .port(c.port)
                            .points(points)
                            .account(account.as_deref())
                            .detail(format!("{}: {}", c.name, f.text)),
                    );
                    Outcome::Address(f.ip)
                }
                (false, Some(None)) if !seen.iter().any(|(_, o)| *o == Outcome::NoAddress) => Outcome::NoAddress,
                _ => Outcome::Read,
            };
            seen.push((c.name.as_str(), outcome));
        }
        // a line another pattern found an address in is that pattern's
        if won {
            for (_, o) in &mut seen {
                if *o == Outcome::NoAddress {
                    *o = Outcome::Read;
                }
            }
        }
        seen
    }
}

/// What a pattern made of a line from its sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not matched (or another pattern took it).
    Read,
    /// Matched, naming this address in group `ip`.
    Address(std::net::IpAddr),
    /// Matched, but group `ip` held no address.
    NoAddress,
}

/// Addresses kept per pattern for the dashboard: the busiest, so a flood of one-off
/// addresses can't grow the state.
pub(crate) const MAX_PATTERN_IPS: usize = 200;
/// Lines without an address kept per pattern, newest last.
pub(crate) const MAX_NO_ADDRESS_LINES: usize = 5;
/// An address not seen for this long leaves a pattern's list.
const PATTERN_IP_TTL: crate::time::Micros = 30 * 86_400 * crate::time::SEC;

/// One address a pattern found: its lines, and the latest one's time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpHits {
    pub ip: std::net::IpAddr,
    pub lines: u64,
    pub last: crate::time::Micros,
}

/// What one pattern has found since `since`, for the dashboard's Patterns tab (kept in the
/// state file).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternStats {
    pub name: String,
    /// The first line read from the pattern's unit or file (0: none yet).
    pub since: crate::time::Micros,
    /// Lines read from its unit or file, matched or not, and the latest one's time: none
    /// means the service isn't there or logs elsewhere (a wrong unit name or path).
    pub lines: u64,
    pub last_line: Option<crate::time::Micros>,
    /// Lines matched with an address in group `ip`.
    pub matches: u64,
    pub last: Option<crate::time::Micros>,
    /// Lines matched without an address in group `ip` (the pattern needs a fix), and the
    /// latest of them (time, cleaned text), newest last.
    pub no_address: u64,
    pub no_address_lines: Vec<(crate::time::Micros, String)>,
    /// The busiest addresses, at most `MAX_PATTERN_IPS`, in no order.
    pub ips: Vec<IpHits>,
}

impl PatternStats {
    pub fn new(name: &str) -> Self {
        PatternStats { name: name.to_string(), ..Default::default() }
    }

    /// Counts one line from the pattern's sender, and what the pattern made of it (a line
    /// matched without an address is kept).
    pub fn count(&mut self, ts: crate::time::Micros, outcome: Outcome, line: &str) {
        if self.since == 0 {
            self.since = ts;
        }
        self.lines += 1;
        self.last_line = Some(self.last_line.map_or(ts, |l| l.max(ts)));
        let ip = match outcome {
            Outcome::Read => return,
            Outcome::Address(ip) => ip,
            Outcome::NoAddress => {
                self.no_address += 1;
                if self.no_address_lines.len() >= MAX_NO_ADDRESS_LINES {
                    self.no_address_lines.remove(0);
                }
                self.no_address_lines.push((ts, crate::event::clean(line, 200)));
                return;
            }
        };
        self.matches += 1;
        self.last = Some(self.last.map_or(ts, |l| l.max(ts)));
        if let Some(h) = self.ips.iter_mut().find(|h| h.ip == ip) {
            h.lines += 1;
            h.last = h.last.max(ts);
            return;
        }
        if self.ips.len() >= MAX_PATTERN_IPS {
            // the quietest, and of those the longest unseen, makes room
            let quietest = self.ips.iter().enumerate().min_by_key(|(_, h)| (h.lines, h.last)).map(|(i, _)| i);
            if let Some(i) = quietest {
                self.ips.swap_remove(i);
            }
        }
        self.ips.push(IpHits { ip, lines: 1, last: ts });
    }

    /// Forgets addresses not seen for `PATTERN_IP_TTL`.
    pub fn prune(&mut self, now: crate::time::Micros) {
        self.ips.retain(|h| now - h.last < PATTERN_IP_TTL);
    }

    /// The `n` busiest addresses, busiest first (then the latest seen).
    pub fn top(&self, n: usize) -> Vec<IpHits> {
        let mut v = self.ips.clone();
        v.sort_by(|a, b| b.lines.cmp(&a.lines).then(b.last.cmp(&a.last)).then(a.ip.cmp(&b.ip)));
        v.truncate(n);
        v
    }
}

/// A pattern as the dashboard shows it: how it is configured, and what it found.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatternView {
    pub kind: PatternKind,
    /// "unit postfix@-.service", "file /var/log/app.log"
    pub from: String,
    pub weight: f64,
    #[serde(default)]
    pub port: Option<u16>,
    /// With `ips` cut to the busiest few, busiest first.
    pub stats: PatternStats,
    /// Addresses tracked in all (`stats.ips` holds only the busiest).
    pub addresses: usize,
}

impl PatternCfg {
    /// Where its lines come from, for the dashboard.
    pub fn from(&self) -> String {
        match (&self.file, self.unit.is_empty()) {
            (Some(f), _) if self.extra_files.is_empty() => format!("file {}", f.display()),
            (Some(f), _) => format!("file {} and {} more", f.display(), self.extra_files.len()),
            (None, false) if !self.identifier.is_empty() => format!("unit {}, identifier {}", self.unit, self.identifier),
            (None, false) => format!("unit {}", self.unit),
            (None, true) => format!("identifier {}, uid {}", self.identifier, self.uid.map_or("-".into(), |u| u.to_string())),
        }
    }
}

/// Per pattern: lines matched, addresses and accounts found; for `logguard test-pattern`.
#[derive(Default)]
struct Tally {
    matched: u64,
    no_address: u64,
    by_ip: std::collections::BTreeMap<std::net::IpAddr, (u64, std::collections::BTreeSet<String>)>,
}

/// `logguard test-pattern`: runs the patterns (or the one named) over log lines (journal JSON,
/// `journalctl` short output, or plain lines of a log file) and writes what each found. The
/// sender checks are left out: they need the live journal.
pub fn test(cfgs: &[PatternCfg], only: Option<&str>, input: impl BufRead, verbose: bool, out: &mut dyn std::io::Write) -> Result<u64> {
    let chosen: Vec<&PatternCfg> = cfgs.iter().filter(|c| only.is_none_or(|n| c.name == n)).collect();
    if chosen.is_empty() {
        match only {
            Some(n) => bail!("no pattern named '{n}' in [[patterns]] or [sources] apps"),
            None => bail!("no [[patterns]] and no [sources] apps in the configuration"),
        }
    }
    let compiled: Vec<Compiled> = chosen.iter().map(|c| Ok(Compiled { cfg: (*c).clone(), re: c.compile()? })).collect::<Result<_>>()?;
    let mut tallies: Vec<Tally> = compiled.iter().map(|_| Tally::default()).collect();
    let (mut lines, mut missed) = (0u64, 0u64);
    let mut years = crate::record::YearGuess::new(crate::time::year_of(crate::time::now()));
    let mut buf = Vec::new();
    let mut reader = input;
    while crate::record::read_line_capped(&mut reader, &mut buf, 1 << 20)? > 0 {
        let raw = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
        buf.clear();
        lines += 1;
        // the message of a journal entry or syslog line, else the whole line (a log file's)
        let msg = if raw.starts_with('{') {
            crate::record::parse_journal_json(&raw).0.map(|r| r.msg)
        } else {
            crate::record::parse_syslog_line(&raw, &mut years).map(|r| r.msg)
        }
        .unwrap_or_else(|| raw.clone());
        let mut hit = false;
        for (p, t) in compiled.iter().zip(&mut tallies) {
            match p.find(&msg) {
                Some(Some(f)) => {
                    hit = true;
                    t.matched += 1;
                    let e = t.by_ip.entry(f.ip).or_default();
                    e.0 += 1;
                    if let Some(u) = &f.user {
                        if e.1.len() < 10 {
                            e.1.insert(crate::event::clean(u, 64));
                        }
                    }
                    if verbose {
                        let user = f.user.as_deref().map(|u| format!(" user={}", crate::event::clean(u, 64))).unwrap_or_default();
                        writeln!(out, "{}: ip={}{user}  {}", p.cfg.name, f.ip, crate::event::clean(&msg, 200))?;
                    }
                }
                Some(None) => {
                    hit = true;
                    t.no_address += 1;
                    if verbose {
                        writeln!(out, "{}: NO ADDRESS in group ip  {}", p.cfg.name, crate::event::clean(&msg, 200))?;
                    }
                }
                None => {}
            }
        }
        missed += u64::from(!hit);
    }
    for (p, t) in compiled.iter().zip(&tallies) {
        let c = &p.cfg;
        let from = match &c.file {
            Some(_) => c.from(),
            None if !c.unit.is_empty() => format!("journal, unit {}", c.unit),
            None => format!("journal, identifier {}", c.identifier),
        };
        let points = if c.kind == PatternKind::Success { "a login".to_string() } else { format!("{} points each", c.weight) };
        writeln!(
            out,
            "\npattern {} ({from}; {:?}, {points}): {} of {lines} lines matched, {} addresses",
            c.name,
            c.kind,
            t.matched,
            t.by_ip.len()
        )?;
        if t.no_address > 0 {
            writeln!(out, "  {} more matched, but group ip held no address", t.no_address)?;
        }
        let mut top: Vec<(&std::net::IpAddr, &(u64, std::collections::BTreeSet<String>))> = t.by_ip.iter().collect();
        top.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
        for (ip, (n, users)) in top.iter().take(20) {
            let users = if users.is_empty() {
                String::new()
            } else {
                format!("  accounts: {}", users.iter().cloned().collect::<Vec<_>>().join(", "))
            };
            writeln!(out, "  {ip:<40} {n:>6}x{users}")?;
        }
        if top.len() > 20 {
            writeln!(out, "  ... and {} more addresses", top.len() - 20)?;
        }
    }
    writeln!(out, "\n{missed} of {lines} lines matched no pattern")?;
    Ok(tallies.iter().map(|t| t.matched).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> PatternCfg {
        toml::from_str(toml).unwrap()
    }

    const POSTFIX: &str = r#"
        name = "postfix_sasl"
        unit = "postfix@-.service"
        regex = 'warning: [^\[]*\[(?P<ip>[0-9A-Fa-f.:]+)\]: SASL \S+ authentication failed(: [^,]*, sasl_username=(?P<user>\S+))?'
        port = 587
    "#;

    fn journal_rec(msg: &str, s: Sender) -> Record {
        Record { ts: 5, source: crate::record::Source::Custom, pid: 1, msg: msg.into(), cursor: None, sender: Some(Box::new(s)) }
    }

    #[test]
    fn validation() {
        cfg(POSTFIX).validate().unwrap();
        let bad = |extra: &str| cfg(&format!("name = \"x\"\nregex = '(?P<ip>\\S+)'\n{extra}")).validate().unwrap_err().to_string();
        assert!(bad("identifier = \"postfix/smtpd\"").contains("any local user"), "an identifier alone can be forged");
        assert!(bad("").contains("name the lines"));
        assert!(bad("file = \"log\"").contains("absolute"));
        assert!(bad("file = \"/var/log/x\"\nunit = \"x.service\"").contains("not both"));
        assert!(bad("unit = \"a b\"").contains("spaces"));
        assert!(bad("unit = \"x.service\"\nweight = -1.0").contains("weight"));
        let no_group = cfg("name = \"x\"\nunit = \"x.service\"\nregex = 'failed from (\\S+)'").validate().unwrap_err().to_string();
        assert!(no_group.contains("group named ip"), "{no_group}");
        let broken = cfg("name = \"x\"\nunit = \"x.service\"\nregex = '(?P<ip>'").validate().unwrap_err();
        assert!(format!("{broken:#}").contains("regex"), "{broken:#}");
        cfg("name = \"x\"\nidentifier = \"dovecot\"\nuid = 0\nregex = '(?P<ip>\\S+)'").validate().unwrap();
        assert_eq!(cfg(POSTFIX).journal_match().as_deref(), Some("_SYSTEMD_UNIT=postfix@-.service"));
    }

    #[test]
    fn matches_only_from_the_named_sender() {
        let p = Patterns::new(&[cfg(POSTFIX)]);
        let line = "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=alice";
        let unit = |u: &str, uid: &str| Sender {
            ident: Some("postfix/smtpd".into()),
            unit: Some(u.into()),
            uid: Some(uid.into()),
            ..Default::default()
        };
        let mut out = vec![];
        p.feed(&journal_rec(line, unit("postfix@-.service", "104")), &mut out);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!((e.signal, e.ip.to_string(), e.points, e.port), (Signal::CustomFailure, "203.0.113.5".into(), Some(25.0), Some(587)));
        assert_eq!(e.account.as_deref(), Some("postfix_sasl:alice"));
        assert!(e.detail.starts_with("postfix_sasl: warning: unknown[203.0.113.5]"), "{}", e.detail);
        // evidence, quoted in abuse reports to other networks: without the account
        assert!(e.detail.ends_with("sasl_username=[account]") && !e.detail.contains("alice"), "{}", e.detail);
        let report = crate::abuse::sanitize(&e.detail).unwrap();
        assert!(!report.contains("alice"), "{report}");
        // a user's own process claiming to be postfix: not counted
        let mut out = vec![];
        p.feed(&journal_rec(line, unit("session-3.scope", "1000")), &mut out);
        assert!(out.is_empty());
        // nor a kernel message, which has no sender fields but its transport
        p.feed(
            &journal_rec(line, Sender { ident: Some("kernel".into()), transport: Some("kernel".into()), ..Default::default() }),
            &mut out,
        );
        assert!(out.is_empty());
        // an export without journald's fields is taken by what it says
        p.feed(&journal_rec(line, Sender { ident: Some("postfix/smtpd".into()), ..Default::default() }), &mut out);
        assert_eq!(out.len(), 1);
        // a file pattern reads its file's lines only
        let f =
            Patterns::new(&[cfg("name = \"web\"\nfile = \"/var/log/web.log\"\nkind = \"probe\"\nregex = '^(?P<ip>\\S+) .*GET /\\.env'")]);
        let web = "198.51.100.7 - - [24/Oct/2026:10:00:00 +0000] \"GET /.env HTTP/1.1\" 404";
        let mut out = vec![];
        f.feed(&journal_rec(web, Sender { file: Some("/var/log/other.log".into()), ..Default::default() }), &mut out);
        f.feed(&journal_rec(web, Sender { ident: Some("x".into()), ..Default::default() }), &mut out);
        assert!(out.is_empty());
        f.feed(&journal_rec(web, Sender { file: Some("/var/log/web.log".into()), ..Default::default() }), &mut out);
        assert_eq!((out[0].signal, out[0].account.as_deref()), (Signal::CustomProbe, None));
        // no address in group ip: no event
        let mut out = vec![];
        f.feed(&journal_rec("not-an-ip GET /.env", Sender { file: Some("/var/log/web.log".into()), ..Default::default() }), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn feed_names_the_pattern_even_without_an_address() {
        let cfg: PatternCfg =
            toml::from_str("name = \"app\"\nfile = \"/var/log/app.log\"\nregex = 'login failed for \\S+ from (?P<ip>\\S+)'").unwrap();
        let p = Patterns::new(&[cfg]);
        let rec = |msg: &str| Record {
            ts: 1,
            source: crate::record::Source::Custom,
            pid: 0,
            msg: msg.into(),
            cursor: None,
            sender: Some(Box::new(Sender { file: Some("/var/log/app.log".into()), ..Default::default() })),
        };
        let mut out = vec![];
        let seen = p.feed(&rec("login failed for bob from 203.0.113.9"), &mut out);
        assert_eq!(seen, [("app", Outcome::Address("203.0.113.9".parse().unwrap()))]);
        assert_eq!(out.len(), 1);
        let seen = p.feed(&rec("login failed for bob from unknown"), &mut out);
        assert_eq!((seen, out.len()), (vec![("app", Outcome::NoAddress)], 1), "matched, no address: no event");
        assert_eq!(p.feed(&rec("something else"), &mut out), [("app", Outcome::Read)], "read, for the line count");
    }

    #[test]
    fn stats_keep_the_busiest_addresses() {
        let ip = |i: u32| std::net::IpAddr::from(std::net::Ipv4Addr::from(0xc633_6400 + i));
        let mut st = PatternStats::new("app");
        st.count(5, Outcome::Read, "not for the pattern");
        for i in 0..7 {
            st.count(10 + i, Outcome::NoAddress, &format!("line {i}\n\u{1b}[31m"));
        }
        assert_eq!((st.since, st.lines, st.last_line, st.no_address, st.matches), (5, 8, Some(16), 7, 0));
        assert_eq!(st.no_address_lines.len(), MAX_NO_ADDRESS_LINES);
        assert_eq!(st.no_address_lines.last().map(|(t, _)| *t), Some(16), "newest last");
        assert!(!st.no_address_lines[0].1.contains('\u{1b}'), "control characters removed");

        for i in 0..MAX_PATTERN_IPS as u32 {
            st.count(100 + i64::from(i), Outcome::Address(ip(i)), "");
            st.count(100 + i64::from(i), Outcome::Address(ip(i)), "");
        }
        assert_eq!((st.matches, st.ips.len(), st.last), (400, MAX_PATTERN_IPS, Some(299)));
        st.count(1000, Outcome::Address(ip(500)), "");
        assert_eq!(st.ips.len(), MAX_PATTERN_IPS);
        assert!(st.ips.iter().any(|h| h.ip == ip(500)), "a new address gets in");
        assert!(!st.ips.iter().any(|h| h.ip == ip(0)), "in place of the quietest, longest unseen");
        st.count(1001, Outcome::Address(ip(501)), "");
        assert!(!st.ips.iter().any(|h| h.ip == ip(500)) && st.ips.iter().any(|h| h.ip == ip(1)), "one-off addresses churn");
        st.count(1002, Outcome::Address(ip(7)), "");
        let top = st.top(2);
        assert_eq!((top[0].ip, top[0].lines, top[1].lines), (ip(7), 3, 2));
        st.prune(150 + PATTERN_IP_TTL);
        assert!(st.ips.iter().all(|h| h.last >= 151), "unseen for 30 days: forgotten");
    }

    #[test]
    fn test_command_reports_per_pattern() {
        let input =
            "Oct 24 10:00:00 mx postfix/smtpd[11]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x, sasl_username=bob\n\
                     Oct 24 10:00:01 mx postfix/smtpd[11]: connect from unknown[203.0.113.5]\n\
                     plain line\n";
        let mut out = Vec::new();
        let n = test(&[cfg(POSTFIX)], None, input.as_bytes(), true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(n, 1);
        assert!(text.contains("postfix_sasl: ip=203.0.113.5 user=bob"), "{text}");
        assert!(text.contains("1 of 3 lines matched, 1 addresses"), "{text}");
        assert!(text.contains("accounts: bob"), "{text}");
        assert!(text.contains("2 of 3 lines matched no pattern"), "{text}");
        assert!(test(&[cfg(POSTFIX)], Some("nope"), "".as_bytes(), false, &mut Vec::new()).is_err());
    }
}
