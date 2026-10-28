//! Abuse reports: the addresses banned in a time window, with the evidence behind each ban,
//! formatted for the network owner's abuse desk.
//!
//! Built from the actions log (`actions.jsonl` and its rotated copies), so it covers
//! everything decided in the window, not just what the daemon still remembers. What would
//! help an attacker or expose users is left out: account names (except non-existent ones
//! that attackers tried), decoy-account names, internal scores, and bans that other cluster
//! nodes decided (their evidence is in their own report).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::engine::{Action, ActionKind};
use crate::net::Net;
use crate::time::{self, Micros, SEC};

/// One reported address (or network), with what it did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offender {
    pub net: Net,
    pub first: Micros,
    pub last: Micros,
    pub bans: u32,
    /// What the bans were for (tripwire, port scan, ssh, xmpp, web, canary, ...).
    pub categories: BTreeSet<String>,
    /// Sanitised evidence, oldest first.
    pub evidence: Vec<Line>,
    /// Evidence lines beyond the ones kept (the console's live report keeps a few per source).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted: usize,
    /// For a network ban: the addresses in it that took part.
    pub members: Vec<IpAddr>,
    pub place: Option<String>,
    pub contact: Option<Contact>,
}

/// One evidence line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Line {
    pub ts: Micros,
    /// Which of our servers saw it (set when reports of several servers are merged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub text: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Contact {
    pub abuse: Vec<String>,
    pub network: String,
}

/// The actions log and its rotated copies (`.1`, `.2.gz`, ...) touched since `from`.
fn log_files(path: &Path, from: Micros) -> Vec<PathBuf> {
    let mut out = vec![];
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else { return out };
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let rotated = n.strip_prefix(name).is_some_and(|rest| rest.is_empty() || rest.starts_with('.'));
            let recent = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .is_none_or(|d| d.as_micros() as Micros >= from);
            if rotated && recent {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// Ban actions taken since `from`, from the actions log and its rotated (gzip) copies.
pub fn load_bans(path: &Path, from: Micros) -> Result<Vec<Action>> {
    let mut out = Vec::new();
    for_each_ban(path, from, |a| out.push(a))?;
    out.sort_by_key(|a| a.ts);
    Ok(out)
}

/// Each ban action taken since `from`, as it is read (in no particular order): a week of a
/// busy server's bans is never all in memory at once.
pub fn for_each_ban(path: &Path, from: Micros, mut f: impl FnMut(Action)) -> Result<()> {
    let files = log_files(path, from);
    if files.is_empty() {
        anyhow::bail!("no actions log at {} (see `actions_log` in the config)", path.display());
    }
    for file in files {
        let opened = std::fs::File::open(&file).with_context(|| format!("opening {}", file.display()))?;
        let reader: Box<dyn Read> =
            if file.extension().is_some_and(|e| e == "gz") { Box::new(flate2::read::GzDecoder::new(opened)) } else { Box::new(opened) };
        // a damaged (rotated, compressed) file still yields what it has up to the damage
        let _ = crate::record::for_each_action_line(reader, |line| {
            if !line.contains("\"ban\"") {
                return;
            }
            if let Ok(a) = serde_json::from_str::<Action>(line) {
                if a.kind == ActionKind::Ban && a.ts >= from && a.target.is_some() {
                    f(a);
                }
            }
        });
    }
    Ok(())
}

/// An evidence line (`10-12 14:03:11 invalid user oracle`) with private details withheld;
/// None for lines that aren't evidence of this host (other nodes' reports).
pub fn sanitize(text: &str) -> Option<String> {
    // A network ban's lines name the member first: "192.0.2.9 failed password for alice".
    if let Some((ip, rest)) = text.split_once(' ').filter(|(ip, _)| ip.parse::<IpAddr>().is_ok()) {
        return sanitize(rest).map(|r| format!("{ip} {r}"));
    }
    if text.starts_with("peer ") {
        return None;
    }
    let cut = |s: &str, at: &str| s.find(at).map(|i| s[..i].to_string());
    let t = if text.contains("canary account") {
        if text.starts_with(crate::event::CANARY_LOGIN) {
            "logged in to a decoy account (credentials that are never used legitimately)".to_string()
        } else if text.starts_with("registration of") {
            "tried to register a decoy account name".to_string()
        } else {
            "login attempt on a decoy account (password guessing)".to_string()
        }
    } else if let Some(rest) = text.strip_prefix("failed ") {
        // "failed password for alice" / "failed publickey for invalid user bob"
        match rest.split_once(" for invalid user ") {
            Some((method, user)) => format!("failed {method} login as non-existent user {user}"),
            None => format!("failed {} login (account name withheld)", rest.split(" for ").next().unwrap_or(rest)),
        }
    } else if text.starts_with("user ") && text.contains(" not allowed") {
        "login attempt as a user that may not log in (name withheld)".to_string()
    } else if text.starts_with("gave up authenticating as ") {
        "gave up authenticating (account name withheld)".to_string()
    } else if text.starts_with("nextcloud login failed for ") {
        "failed Nextcloud login (account name withheld)".to_string()
    } else if text.starts_with("registered account ") {
        "registered an account".to_string()
    } else if let Some(c) = cut(text, " (+") {
        c // never show internal points
    } else {
        text.to_string()
    };
    // Anything still looking like an account or e-mail address.
    let t: Vec<String> = t.split(' ').map(|w| if w.contains('@') { "[account]".to_string() } else { w.to_string() }).collect();
    Some(t.join(" ").chars().filter(|c| !c.is_control()).take(300).collect())
}

/// `10-12 14:03:11 text` with the year of the ban it belongs to (December lines in a
/// January ban are from the year before).
fn evidence_time(line: &str, ban_ts: Micros) -> Option<(Micros, &str)> {
    let (date, rest) = line.split_once(' ')?;
    let (clock, text) = rest.split_once(' ')?;
    let (month, _) = date.split_once('-')?;
    let ban_year = time::year_of(ban_ts);
    let ban_month: u32 = time::fmt_ts(ban_ts)[5..7].parse().ok()?;
    let year = if month.parse::<u32>().ok()? > ban_month { ban_year - 1 } else { ban_year };
    let (t, _) = time::parse_iso_prefix(&format!("{year}-{date} {clock}"))?;
    Some((t, text))
}

pub struct Filter {
    /// Only these addresses / networks (empty = all).
    pub only: Vec<Net>,
    /// Leave out offenders with fewer evidence lines (a single blocked packet isn't worth a report).
    pub min_events: usize,
}

/// Groups the bans by target, keeping this host's own evidence only.
pub fn collect(bans: &[Action], filter: &Filter) -> Vec<Offender> {
    let mut c = Collector::new(filter, usize::MAX, usize::MAX);
    for a in bans {
        c.add(a);
    }
    c.finish()
}

/// [`collect`] one ban at a time.
pub struct Collector<'a> {
    filter: &'a Filter,
    /// Evidence lines kept per source; the rest are counted in `omitted`.
    max_evidence: usize,
    /// Sources kept; bans of further ones are only counted in `beyond`.
    max_sources: usize,
    by: BTreeMap<Net, Offender>,
    /// Sources not kept (see `max_sources`).
    pub beyond: usize,
}

impl<'a> Collector<'a> {
    pub fn new(filter: &'a Filter, max_evidence: usize, max_sources: usize) -> Self {
        Collector { filter, max_evidence, max_sources, by: BTreeMap::new(), beyond: 0 }
    }

    pub fn add(&mut self, a: &Action) {
        let Some(net) = a.target else { return };
        if !self.by.contains_key(&net) && self.by.len() >= self.max_sources {
            self.beyond += 1;
            return;
        }
        // Peer bans carry another node's evidence; a reinstated ban (put back when a network
        // ban covering it expired) is no new activity.
        if matches!(a.category.as_deref(), Some("from peers" | "reinstated")) || a.message.contains("(from peer ") {
            return;
        }
        let only = &self.filter.only;
        if !only.is_empty() && !only.iter().any(|f| f.contains_net(&net) || net.contains_net(f)) {
            return;
        }
        let o = self.by.entry(net).or_insert_with(|| Offender {
            net,
            first: a.ts,
            last: a.ts,
            bans: 0,
            categories: BTreeSet::new(),
            evidence: vec![],
            omitted: 0,
            members: vec![],
            place: None,
            contact: None,
        });
        o.bans += 1;
        o.last = o.last.max(a.ts);
        if let Some(c) = &a.category {
            o.categories.insert(c.clone());
        }
        for e in &a.evidence {
            if let Ok(ip) = e.trim().parse::<IpAddr>() {
                if !o.members.contains(&ip) {
                    o.members.push(ip);
                }
                continue;
            }
            if let Some((t, text)) = evidence_time(e, a.ts) {
                if let Some(text) = sanitize(text) {
                    o.first = o.first.min(t);
                    let line = Line { ts: t, server: None, text };
                    if o.evidence.len() >= self.max_evidence {
                        o.omitted += 1;
                    } else if !o.evidence.contains(&line) {
                        o.evidence.push(line);
                    }
                }
            }
        }
    }

    pub fn finish(self) -> Vec<Offender> {
        // A network's members carry their own evidence from their own bans.
        let member_events: BTreeMap<IpAddr, usize> =
            self.by.values().filter(|o| o.net.is_host()).map(|o| (o.net.addr, o.evidence.len() + o.omitted)).collect();
        let min = self.filter.min_events.max(1);
        let mut out: Vec<Offender> = self
            .by
            .into_values()
            .filter(|o| {
                o.evidence.len() + o.omitted + o.members.iter().map(|m| member_events.get(m).copied().unwrap_or(1)).sum::<usize>() >= min
            })
            .collect();
        for o in &mut out {
            o.evidence.sort();
            o.members.sort();
            // "Seen" is when the activity happened, not when bans were decided.
            if let (Some(f), Some(l)) = (o.evidence.first(), o.evidence.last()) {
                (o.first, o.last) = (f.ts, l.ts);
            }
        }
        rank(&mut out);
        out
    }
}

pub(crate) fn service_of(proto: &str, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        ("TCP", 21) => "FTP",
        ("TCP", 22) => "SSH",
        ("TCP", 23) | ("TCP", 2323) => "Telnet",
        ("TCP", 25) => "SMTP",
        ("TCP", 80) => "Web HTTP",
        ("TCP", 110) => "POP3",
        ("TCP", 135) => "MS RPC",
        ("TCP", 139) => "NetBIOS",
        ("TCP", 143) => "IMAP",
        ("TCP", 389) => "LDAP",
        ("TCP", 443) => "Web HTTPS",
        ("UDP", 443) => "Web QUIC",
        ("TCP", 445) => "SMB",
        ("TCP", 465) => "SMTPS",
        ("TCP", 587) => "SMTP submission",
        ("TCP", 993) => "IMAPS",
        ("TCP", 995) => "POP3S",
        ("TCP", 1433) => "MS SQL",
        ("TCP", 1521) => "Oracle DB",
        ("TCP", 1723) => "PPTP",
        ("TCP", 2375) | ("TCP", 2376) => "Docker API",
        ("TCP", 3306) => "MySQL",
        ("TCP", 3389) => "RDP",
        ("UDP", 3478) | ("TCP", 3478) => "STUN/TURN",
        ("TCP", 5349) | ("UDP", 5349) => "TURN over TLS",
        ("TCP", 5432) => "PostgreSQL",
        ("TCP", 5900) | ("TCP", 5901) => "VNC",
        ("TCP", 5985) | ("TCP", 5986) => "WinRM",
        ("TCP", 6379) => "Redis",
        ("TCP", 7547) => "TR-069",
        ("TCP", 8000) | ("TCP", 8080) | ("TCP", 8888) => "Web HTTP alt",
        ("TCP", 8291) => "MikroTik Winbox",
        ("TCP", 8443) => "Web HTTPS alt",
        ("TCP", 9200) => "Elasticsearch",
        ("TCP", 11211) => "Memcached",
        ("TCP", 27017) => "MongoDB",
        ("TCP", 34567) => "DVR (Xiongmai)",
        ("UDP", 161) => "SNMP",
        ("UDP", 5060) | ("TCP", 5060) => "SIP",
        _ => return None,
    })
}

/// One sentence per kind of activity, for the summary line.
/// What kinds of activity the evidence itself shows, for bans without a usable category
/// (reinstated bans, or ones logged by older versions).
fn inferred_categories(o: &Offender) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for l in &o.evidence {
        let t = l.text.split_once(' ').filter(|(ip, _)| ip.parse::<IpAddr>().is_ok()).map_or(l.text.as_str(), |(_, rest)| rest);
        let c = if t.starts_with("tripwire block ") {
            "tripwire"
        } else if t.starts_with("block ") || t.starts_with("port scan:") {
            "port scan"
        } else if t.contains("decoy account") {
            "canary"
        } else if t.contains(" login") || t.starts_with("invalid user") || t.contains("authenticat") || t.starts_with("sshd ") {
            "ssh"
        } else if t.starts_with("TLS failed") || t.contains("XMPP") || t.starts_with("s2s ") || t.contains("without authentication") {
            "xmpp"
        } else {
            continue;
        };
        out.insert(c.to_string());
    }
    if !o.members.is_empty() {
        out.insert("subnet".into());
    }
    out
}

fn describe(o: &Offender) -> String {
    const KNOWN: [&str; 9] = ["tripwire", "port scan", "ssh", "xmpp", "web", "canary", "distributed probing", "subnet", "cluster evidence"];
    let categories = if o.categories.iter().any(|c| KNOWN.contains(&c.as_str())) { o.categories.clone() } else { inferred_categories(o) };
    let mut parts = Vec::new();
    for c in &categories {
        let p = match c.as_str() {
            "tripwire" => {
                let mut ports: Vec<String> = o
                    .evidence
                    .iter()
                    .filter_map(|l| l.text.strip_prefix("tripwire block "))
                    .map(|pp| {
                        let (proto, port) = pp.split_once('/').unwrap_or(("", pp));
                        match port.parse().ok().and_then(|n| service_of(proto, n)) {
                            Some(s) => format!("{pp} ({s})"),
                            None => pp.to_string(),
                        }
                    })
                    .collect();
                ports.sort();
                ports.dedup();
                format!("connections to closed ports of commonly attacked services: {}", ports.join(", "))
            }
            "port scan" => "port scanning (connection attempts to many closed ports)".into(),
            "ssh" => "SSH probing / login attempts".into(),
            "xmpp" => "probing the XMPP (chat) service: failed TLS handshakes, connections without authentication, failed logins".into(),
            "web" => "web vulnerability scanning / failed Nextcloud logins".into(),
            "canary" => "login attempts with decoy credentials (password guessing)".into(),
            "distributed probing" | "subnet" => "coordinated probing from several addresses of this network".into(),
            "cluster evidence" => "activity also seen by our other servers".into(),
            "reinstated" => continue,
            other => other.to_string(),
        };
        parts.push(p);
    }
    if parts.is_empty() {
        "malicious activity".into()
    } else {
        parts.join("; ")
    }
}

/// Evidence in words an abuse desk understands: "tripwire block TCP/5900" becomes
/// "connection attempt to closed port TCP/5900 (VNC)".
fn plain(text: &str) -> String {
    let (who, rest) = match text.split_once(' ') {
        Some((ip, rest)) if ip.parse::<IpAddr>().is_ok() => (format!("{ip} "), rest),
        _ => (String::new(), text),
    };
    let Some(pp) = rest.strip_prefix("tripwire block ").or_else(|| rest.strip_prefix("block ")) else { return text.to_string() };
    let (proto, port) = pp.split_once('/').unwrap_or(("", pp));
    let svc = port.parse().ok().and_then(|n| service_of(proto, n)).map(|s| format!(" ({s})")).unwrap_or_default();
    format!("{who}connection attempt to closed port {pp}{svc}")
}

fn ts(t: Micros) -> String {
    format!("{} UTC", time::fmt_ts(t))
}

/// A server whose logs a report is built from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    /// Public addresses: the destination of the attacks.
    pub addresses: Vec<IpAddr>,
}

impl Server {
    /// How evidence lines name this server: its first public IPv4 address, else its name.
    fn tag(&self) -> String {
        self.addresses.iter().find(|a| a.is_ipv4()).or(self.addresses.first()).map_or(self.host.clone(), |a| a.to_string())
    }
}

/// A complete report; `--json` writes this, `--merge` combines several.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub servers: Vec<Server>,
    pub from: Micros,
    pub to: Micros,
    pub offenders: Vec<Offender>,
}

/// Largest report read (decompressed). A week's JSON report of a busy server is a few MB; a
/// peer's file is at most one cluster frame (1 MB), which gzip could inflate a thousandfold.
pub const MAX_REPORT: u64 = 64 << 20;

/// A `--json` report file, plain or gzip-compressed (as `cluster-send-report` delivers it).
pub fn read_report_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut raw = Vec::new();
    file.take(MAX_REPORT + 1).read_to_end(&mut raw).with_context(|| format!("reading {}", path.display()))?;
    let raw = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut text = Vec::new();
        flate2::read::GzDecoder::new(raw.as_slice())
            .take(MAX_REPORT + 1)
            .read_to_end(&mut text)
            .with_context(|| format!("decompressing {}", path.display()))?;
        text
    } else {
        raw
    };
    if raw.len() as u64 > MAX_REPORT {
        anyhow::bail!("{} is larger than {} MB: not a report", path.display(), MAX_REPORT >> 20);
    }
    String::from_utf8(raw).with_context(|| format!("{} is not UTF-8", path.display()))
}

/// What a peer's report may say about an offender, made safe: abuse contacts as plain e-mail
/// addresses only (as from RDAP), and no hidden characters in its text.
fn tidy(o: &mut Offender) {
    use crate::event::clean;
    if let Some(c) = o.contact.as_mut() {
        c.abuse = c.abuse.iter().filter_map(|e| plain_email(e)).take(5).collect();
        c.network = clean(&c.network, 100);
    }
    o.place = o.place.as_deref().map(|p| clean(p, 160));
    o.categories = o.categories.iter().map(|c| clean(c, 40)).collect();
    for l in &mut o.evidence {
        l.text = clean(&l.text, 300);
        l.server = l.server.as_deref().map(|s| clean(s, 100));
    }
}

/// Combines the reports of several servers: one entry per source, evidence lines marked
/// with the server that saw them. A report identical in server and period to one already
/// merged (the same file given twice) is skipped, as it would double every count; its
/// position is returned.
pub fn merge(reports: Vec<Report>) -> (Report, Vec<usize>) {
    let mut by: BTreeMap<Net, Offender> = BTreeMap::new();
    let mut servers: Vec<Server> = vec![];
    let mut skipped = vec![];
    let (mut from, mut to) = (Micros::MAX, 0);
    let mut seen: Vec<String> = vec![];
    for (n, r) in reports.into_iter().enumerate() {
        let id = serde_json::to_string(&(&r.servers, r.from, r.to)).unwrap_or_default();
        if seen.contains(&id) {
            skipped.push(n);
            continue;
        }
        seen.push(id);
        from = from.min(r.from);
        to = to.max(r.to);
        let tag = r.servers.first().map(Server::tag).map(|t| crate::event::clean(&t, 100));
        servers.extend(r.servers.into_iter().map(|s| Server { host: crate::event::clean(&s.host, 100), ..s }));
        for mut o in r.offenders {
            tidy(&mut o);
            for l in &mut o.evidence {
                l.server = l.server.take().or_else(|| tag.clone());
            }
            match by.get_mut(&o.net) {
                None => {
                    by.insert(o.net, o);
                }
                Some(m) => {
                    m.first = m.first.min(o.first);
                    m.last = m.last.max(o.last);
                    m.bans += o.bans;
                    m.categories.extend(o.categories);
                    // duplicates go below, sorted: a peer's report may hold a million lines
                    m.evidence.extend(o.evidence);
                    m.omitted += o.omitted;
                    m.members.extend(o.members);
                    m.place = m.place.take().or(o.place);
                    m.contact = m.contact.take().or(o.contact);
                }
            }
        }
    }
    let mut offenders: Vec<Offender> = by.into_values().collect();
    for o in &mut offenders {
        o.evidence.sort();
        o.evidence.dedup();
        o.members.sort();
        o.members.dedup();
    }
    rank(&mut offenders);
    (Report { servers, from: if from == Micros::MAX { 0 } else { from }, to, offenders }, skipped)
}

/// Most persistent first: repeated bans, then the amount of evidence.
pub fn rank(list: &mut [Offender]) {
    list.sort_by_key(|o| std::cmp::Reverse((o.bans, events(o))));
}

/// Evidence lines (and network members) behind an entry.
pub fn events(o: &Offender) -> usize {
    o.evidence.len() + o.omitted + o.members.len()
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

const MAX_LINES: usize = 25;

/// Plain text, grouped by abuse contact when known (one section per e-mail to send).
pub fn render_text(r: &Report) -> String {
    // merged reports come from peers, and carry RDAP and geo text: nothing hidden in it
    crate::event::plain_text(&render_text_raw(r))
}

fn render_text_raw(r: &Report) -> String {
    let offenders = &r.offenders;
    let mut s = String::new();
    let servers: Vec<String> = r
        .servers
        .iter()
        .map(|sv| {
            let addrs: Vec<String> = sv.addresses.iter().map(|a| a.to_string()).collect();
            format!("{} ({})", sv.host, if addrs.is_empty() { "-".into() } else { addrs.join(", ") })
        })
        .collect();
    s += &format!("Abuse report from {}\n", servers.join(" and "));
    s += &format!("Period: {} to {}. All times are UTC.\n", ts(r.from), ts(r.to));
    s += &format!(
        "{} source{} below, each flagged by our intrusion detection for the activity shown.\n",
        offenders.len(),
        if offenders.len() == 1 { "" } else { "s" }
    );
    s += "Evidence is taken from our server logs (firewall and the attacked services). Account names are withheld.\n";

    let mut groups: BTreeMap<String, Vec<&Offender>> = BTreeMap::new();
    for o in offenders {
        let key = match &o.contact {
            Some(c) if !c.abuse.is_empty() => c.abuse.join(", "),
            _ => String::new(),
        };
        groups.entry(key).or_default().push(o);
    }
    for (contact, list) in &groups {
        s += "\n==========================================================================\n";
        if contact.is_empty() {
            s += "Abuse contact: unknown (run with --contacts, or look up the network owner)\n";
        } else {
            let net = list.iter().find_map(|o| o.contact.as_ref().map(|c| c.network.clone())).unwrap_or_default();
            s += &format!("To: {contact}{}\n", if net.is_empty() { String::new() } else { format!("   (network: {net})") });
            s += "\nHello,\n\nthe following address(es) in your network attacked our server. Please investigate and stop\nthe abuse; the log excerpts below are in UTC.\n";
        }
        for o in list {
            s += "\n--------------------------------------------------------------------------\n";
            s += &format!("Source: {}{}\n", o.net, o.place.as_ref().map(|p| format!("   [{p}]")).unwrap_or_default());
            s += &format!("Seen: {} - {} ({} incident{})\n", ts(o.first), ts(o.last), o.bans, if o.bans == 1 { "" } else { "s" });
            s += &format!("Activity: {}\n", describe(o));
            if !o.members.is_empty() {
                let m: Vec<String> = o.members.iter().map(|m| m.to_string()).collect();
                s += &format!("Addresses involved: {}\n", m.join(", "));
            }
            if !o.evidence.is_empty() {
                s += "Log excerpt:\n";
                for l in o.evidence.iter().take(MAX_LINES) {
                    let to = l.server.as_ref().map(|sv| format!("(to {sv}) ")).unwrap_or_default();
                    s += &format!("  {}  {to}{}\n", ts(l.ts), plain(&l.text));
                }
                let more = o.evidence.len().saturating_sub(MAX_LINES) + o.omitted;
                if more > 0 {
                    s += &format!("  ... and {more} more\n");
                }
            }
        }
    }
    s
}

// ------------------------------------------------------------------ the console's live report

/// Sources in the console's live report, the most persistent first.
pub const LIVE_SOURCES: usize = 1000;
/// Log lines per source in it (as many as the text report quotes).
pub const LIVE_LINES: usize = MAX_LINES;
/// Sources read for it before the ranking: the report is built inside the daemon, whose
/// memory is limited (its unit's `MemoryMax`), and a week of a flood's bans would exceed it;
/// bans of further sources are only counted. (The weekly report, built in a process of its
/// own, has no such cap.)
pub const LIVE_MAX_SOURCES: usize = 20_000;

/// This server's abuse report as it stands, for logguard-web (`abuse 24h` / `abuse 7d` on
/// the console socket): every source of the window, its activity in words, its network from
/// the geo database ([`locate`]) and its first log lines worded for an abuse desk. No abuse
/// mailboxes: those take RDAP lookups, which the weekly report makes.
#[derive(Clone, Debug, Serialize)]
pub struct Live {
    pub host: String,
    pub addresses: Vec<IpAddr>,
    pub from: Micros,
    pub to: Micros,
    /// Sources in the window, also those beyond [`LIVE_SOURCES`].
    pub sources: usize,
    pub offenders: Vec<LiveSource>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LiveSource {
    pub net: Net,
    pub first: Micros,
    pub last: Micros,
    pub bans: u32,
    /// Log lines and network members behind it.
    pub events: usize,
    pub categories: BTreeSet<String>,
    /// What it did, as the text report says it.
    pub activity: String,
    pub evidence: Vec<Line>,
    /// Log lines beyond those in `evidence`.
    pub omitted: usize,
    pub members: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// Builds the live report of the `since` window up to `now` from the actions log at `path`.
pub fn live(path: &Path, since: crate::time::Dur, now: Micros, host: String, addresses: Vec<IpAddr>) -> Result<Live> {
    let from = window_start(now, since);
    let filter = Filter { only: vec![], min_events: 1 };
    // a few more lines than shown, for the ranking; a port scan's thousands only counted
    let mut c = Collector::new(&filter, 4 * LIVE_LINES, LIVE_MAX_SOURCES);
    for_each_ban(path, from, |a| c.add(&a))?;
    let beyond = c.beyond;
    let all = c.finish();
    let sources = all.len() + beyond;
    let offenders = all
        .into_iter()
        .take(LIVE_SOURCES)
        .map(|o| {
            let shown = o.evidence.len().min(LIVE_LINES);
            LiveSource {
                net: o.net,
                first: o.first,
                last: o.last,
                bans: o.bans,
                events: events(&o),
                activity: describe(&o),
                evidence: o.evidence[..shown].iter().map(|l| Line { ts: l.ts, server: None, text: plain(&l.text) }).collect(),
                omitted: o.evidence.len() - shown + o.omitted,
                members: o.members.iter().take(100).copied().collect(),
                categories: o.categories,
                country: None,
                country_name: None,
                asn: None,
                org: None,
            }
        })
        .collect();
    Ok(Live { host, addresses, from, to: now, sources, offenders })
}

/// Fills in each source's country and network.
pub fn locate(r: &mut Live, db: &crate::geo::GeoDb) {
    for o in &mut r.offenders {
        let g = db.lookup(o.net.addr);
        o.country = g.country.map(|c| String::from_utf8_lossy(&c).into_owned());
        o.country_name = g.country_name().map(str::to_string);
        o.asn = g.asn;
        o.org = g.org;
    }
}

// ------------------------------------------------------------------ abuse contacts (RDAP)

/// RDAP data is written by the network's owner, who may be the attacker: only plain
/// e-mail addresses are taken, so nothing can be smuggled into the report.
fn plain_email(e: &str) -> Option<String> {
    let e = e.trim().to_lowercase();
    let ok = e.len() <= 100
        && e.matches('@').count() == 1
        && !e.starts_with('@')
        && e.contains('.')
        && e.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c));
    ok.then_some(e)
}

fn vcard_emails(entity: &serde_json::Value) -> Vec<String> {
    let mut out = vec![];
    if let Some(items) = entity.get("vcardArray").and_then(|v| v.get(1)).and_then(|v| v.as_array()) {
        for item in items {
            if item.get(0).and_then(|v| v.as_str()) == Some("email") {
                if let Some(e) = item.get(3).and_then(|v| v.as_str()).and_then(plain_email) {
                    out.push(e);
                }
            }
        }
    }
    out
}

fn abuse_emails(v: &serde_json::Value, out: &mut Vec<String>) {
    for e in v.get("entities").and_then(|e| e.as_array()).into_iter().flatten() {
        let abuse = e.get("roles").and_then(|r| r.as_array()).is_some_and(|r| r.iter().any(|x| x.as_str() == Some("abuse")));
        if abuse {
            for m in vcard_emails(e) {
                if !out.contains(&m) {
                    out.push(m);
                }
            }
        }
        abuse_emails(e, out);
    }
}

/// The abuse mailbox and network name from an RDAP response (`rdap.org/ip/<addr>`).
pub fn parse_rdap(json: &str) -> Option<(Contact, Option<(IpAddr, IpAddr)>)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut abuse = vec![];
    abuse_emails(&v, &mut abuse);
    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let handle = v.get("handle").and_then(|n| n.as_str()).unwrap_or("");
    let network: String = match (name, handle) {
        ("", h) => h.to_string(),
        (n, "") => n.to_string(),
        (n, h) => format!("{n}, {h}"),
    }
    .chars()
    .filter(|c| !c.is_control())
    .take(100)
    .collect();
    abuse.truncate(5);
    let range = (|| {
        let a = v.get("startAddress")?.as_str()?.parse().ok()?;
        let b = v.get("endAddress")?.as_str()?.parse().ok()?;
        Some((a, b))
    })();
    Some((Contact { abuse, network }, range))
}

/// Looks up abuse contacts (one RDAP request per network, ~1 per second).
pub fn add_contacts(offenders: &mut [Offender], cfg: &crate::feeds::FeedsCfg, progress: impl Fn(usize, usize)) -> Vec<String> {
    let mut known: Vec<((IpAddr, IpAddr), Contact)> = vec![];
    let mut errors = vec![];
    let total = offenders.len();
    for (i, o) in offenders.iter_mut().enumerate() {
        let ip = o.net.addr;
        if let Some((_, c)) = known.iter().find(|((a, b), _)| *a <= ip && ip <= *b) {
            o.contact = Some(c.clone());
            continue;
        }
        progress(i + 1, total);
        match crate::feeds::download(cfg, &format!("https://rdap.org/ip/{ip}")) {
            Ok(json) => match parse_rdap(&json) {
                Some((c, range)) => {
                    // Reuse the answer for other addresses only within a plausible allocation
                    // that contains this one: a forged answer claiming the whole internet
                    // would otherwise receive every other attacker's evidence.
                    if let Some(r) = range.filter(|(a, b)| plausible_range(*a, *b) && *a <= ip && ip <= *b) {
                        known.push((r, c.clone()));
                    }
                    o.contact = Some(c);
                }
                None => errors.push(format!("{ip}: unreadable RDAP answer")),
            },
            Err(e) => errors.push(format!("{ip}: {e:#}")),
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    errors
}

/// At most a /8 (IPv4) or /32 (IPv6), the largest blocks registries hand out.
fn plausible_range(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(b).checked_sub(u32::from(a)).is_some_and(|n| n < 1 << 24),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(b).checked_sub(u128::from(a)).is_some_and(|n| n < 1 << 96),
        _ => false,
    }
}

pub fn window_start(now: Micros, since: crate::time::Dur) -> Micros {
    now.saturating_sub((since.0 as Micros).saturating_mul(SEC))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Severity;

    #[test]
    fn report_files_plain_or_gzip() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("lg-abuse-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let json = r#"{"servers":[],"from":1,"to":2,"offenders":[]}"#;
        std::fs::write(dir.join("a.json"), json).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(json.as_bytes()).unwrap();
        std::fs::write(dir.join("b.json.gz"), gz.finish().unwrap()).unwrap();
        for f in ["a.json", "b.json.gz"] {
            let r: Report = serde_json::from_str(&read_report_file(&dir.join(f)).unwrap()).unwrap();
            assert_eq!((r.from, r.to), (1, 2), "{f}");
        }
        // a small file that inflates beyond any report is refused, not read into memory
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![b' '; 1 << 20];
        for _ in 0..=(MAX_REPORT >> 20) {
            gz.write_all(&zeros).unwrap();
        }
        let big = gz.finish().unwrap();
        assert!(big.len() < 1 << 20, "fits in a cluster frame: {} bytes", big.len());
        std::fs::write(dir.join("big.json.gz"), big).unwrap();
        assert!(read_report_file(&dir.join("big.json.gz")).unwrap_err().to_string().contains("larger than"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer's report is checked like an RDAP answer: its abuse contacts must be plain
    /// e-mail addresses, its text has no hidden characters.
    #[test]
    fn merged_peer_reports_are_tidied() {
        let mut o = collect(
            &[ban("2026-10-10 08:00:00", "198.51.100.7", "ssh", &["10-10 07:59:58 invalid user oracle"])],
            &Filter { only: vec![], min_events: 1 },
        )
        .remove(0);
        o.contact = Some(Contact { abuse: vec!["x@y.example\nInjected".into(), "abuse@isp.example".into()], network: "N\u{1b}[2J".into() });
        o.place = Some("Somewhere\u{202e}".into());
        let r = Report { servers: vec![Server { host: "vpn\u{7}".into(), addresses: vec![] }], from: 0, to: 1, offenders: vec![o] };
        let (m, _) = merge(vec![r]);
        let c = m.offenders[0].contact.as_ref().unwrap();
        assert_eq!(c.abuse, ["abuse@isp.example"]);
        assert_eq!(c.network, "N[2J");
        assert_eq!(m.offenders[0].place.as_deref(), Some("Somewhere"));
        assert_eq!(m.servers[0].host, "vpn");
    }

    fn ban(ts: &str, target: &str, category: &str, evidence: &[&str]) -> Action {
        Action {
            ts: time::parse_iso_prefix(ts).unwrap().0,
            kind: ActionKind::Ban,
            severity: Severity::High,
            target: Some(target.parse().unwrap()),
            until: None,
            message: format!("ban {target} for 1h (offence #1): burst score fast=100 slow=100"),
            evidence: evidence.iter().map(|e| e.to_string()).collect(),
            superseded: vec![],
            applied: true,
            topic: None,
            accounts: vec!["ejabberd:alice@example.org".into()],
            user_note: None,
            notice: None,
            category: Some(category.into()),
        }
    }

    #[test]
    fn private_details_are_withheld() {
        assert_eq!(sanitize("failed password for alice").unwrap(), "failed password login (account name withheld)");
        assert_eq!(sanitize("failed password for invalid user oracle").unwrap(), "failed password login as non-existent user oracle");
        assert_eq!(sanitize("invalid user oracle").unwrap(), "invalid user oracle");
        assert!(!sanitize("login attempt on canary account postmaster").unwrap().contains("postmaster"));
        assert!(!sanitize("LOGGED IN to canary account test").unwrap().contains("test"));
        assert!(!sanitize("user root not allowed (not listed in AllowUsers)").unwrap().contains("root"));
        assert!(!sanitize("nextcloud login failed for bob").unwrap().contains("bob"));
        assert_eq!(sanitize("registered account eve@example.org").unwrap(), "registered an account");
        assert_eq!(sanitize("auth failed: user x@example.org unknown").unwrap(), "auth failed: user [account] unknown");
        assert_eq!(sanitize("peer vpn: 3x ssh_invalid_user (+60)"), None);
        assert_eq!(sanitize("tripwire block TCP/23").unwrap(), "tripwire block TCP/23");
        // network-ban lines start with the member address
        assert_eq!(sanitize("192.0.2.9 failed password for alice").unwrap(), "192.0.2.9 failed password login (account name withheld)");
        assert_eq!(sanitize("192.0.2.9 peer vpn: 3x ssh_invalid_user (+60)"), None);
        assert!(!sanitize("2001:db8::1 nextcloud login failed for bob").unwrap().contains("bob"));
    }

    #[test]
    fn groups_bans_and_formats_a_report() {
        let bans = vec![
            ban(
                "2026-10-10 08:00:00",
                "198.51.100.7",
                "ssh",
                &["10-10 07:59:58 invalid user oracle", "10-10 08:00:00 failed password for gateway"],
            ),
            ban("2026-10-11 09:00:00", "198.51.100.7", "tripwire", &["10-11 09:00:00 tripwire block TCP/3389"]),
            ban("2026-10-11 10:00:00", "203.0.113.5", "tripwire", &["10-11 10:00:00 tripwire block TCP/23"]),
            ban("2026-10-11 11:00:00", "192.0.2.0/24", "x", &["192.0.2.9", "192.0.2.10"]),
            ban("2026-10-11 12:00:00", "192.0.2.9", "port scan", &["10-11 11:58:00 block TCP/8080", "10-11 11:59:00 block TCP/8081"]),
            Action {
                message: "ban 100.64.0.1 for 1h (from peer vpn): x".into(),
                ..ban("2026-10-11 13:00:00", "198.18.0.1", "from peers", &[])
            },
        ];
        let all = collect(&bans, &Filter { only: vec![], min_events: 1 });
        assert_eq!(all.len(), 4, "peer bans are left out");
        assert_eq!(all[0].net.to_string(), "198.51.100.7", "repeat offender first");
        assert_eq!(all[0].bans, 2);
        assert_eq!(all[0].evidence.len(), 3);
        let net = all.iter().find(|o| !o.net.is_host()).unwrap();
        assert_eq!(net.members.len(), 2);

        let worth = collect(&bans, &Filter { only: vec![], min_events: 3 });
        assert!(!worth.iter().any(|o| o.net.to_string() == "203.0.113.5"), "a single blocked packet isn't reported");
        let only = collect(&bans, &Filter { only: vec!["192.0.2.0/24".parse().unwrap()], min_events: 1 });
        assert_eq!(only.len(), 2);

        let mut list = collect(&bans, &Filter { only: vec![], min_events: 1 });
        list[0].contact = Some(Contact { abuse: vec!["abuse@isp.example".into()], network: "ISP-NET".into() });
        let server = Server { host: "example.org".into(), addresses: vec!["192.0.2.1".parse().unwrap()] };
        let report = Report { servers: vec![server], from: 0, to: bans[5].ts, offenders: list };
        let text = render_text(&report);
        assert!(text.contains("To: abuse@isp.example   (network: ISP-NET)"), "{text}");
        assert!(text.contains("2026-10-10 07:59:58 UTC  invalid user oracle"), "{text}");
        assert!(text.contains("TCP/3389 (RDP)"), "{text}");
        assert!(text.contains("UTC  connection attempt to closed port TCP/3389 (RDP)"), "{text}");
        assert_eq!(plain("192.0.2.9 block TCP/4444"), "192.0.2.9 connection attempt to closed port TCP/4444");
        assert_eq!(plain("192.0.2.9 block TCP/8080"), "192.0.2.9 connection attempt to closed port TCP/8080 (Web HTTP alt)");

        // a ban without a usable category is described from its evidence
        let old = collect(
            &[ban(
                "2026-10-11 15:39:20",
                "11.39.61.51",
                "",
                &["10-11 15:34:44 block TCP/46468", "10-11 15:39:20 port scan: 16 closed ports"],
            )],
            &Filter { only: vec![], min_events: 1 },
        );
        assert_eq!(describe(&old[0]), "port scanning (connection attempts to many closed ports)");
        // a reinstated ban is no new incident, and "Seen" ends with the last activity
        let twice = collect(
            &[
                ban(
                    "2026-10-12 13:03:28",
                    "11.7.32.8",
                    "port scan",
                    &["10-12 12:55:13 block TCP/9794", "10-12 13:03:28 port scan: 8 closed ports"],
                ),
                ban("2026-10-12 16:24:29", "11.7.32.8", "reinstated", &[]),
            ],
            &Filter { only: vec![], min_events: 1 },
        );
        assert_eq!(twice[0].bans, 1);
        assert_eq!(time::fmt_ts(twice[0].last), "2026-10-12 13:03:28");
        for secret in ["gateway", "alice", "fast=", "score", "peer"] {
            assert!(!text.contains(secret), "{secret} leaked:\n{text}");
        }
    }

    #[test]
    fn merges_reports_of_two_servers() {
        let a = vec![ban("2026-10-10 08:00:00", "198.51.100.7", "ssh", &["10-10 07:59:58 invalid user oracle"])];
        let b = vec![
            ban("2026-10-11 09:00:00", "198.51.100.7", "tripwire", &["10-11 09:00:00 tripwire block TCP/23"]),
            ban("2026-10-11 10:00:00", "203.0.113.5", "tripwire", &["10-11 10:00:00 tripwire block TCP/3389"]),
        ];
        let f = Filter { only: vec![], min_events: 1 };
        let report = |host: &str, addr: &str, bans: &[Action]| Report {
            servers: vec![Server { host: host.into(), addresses: vec![addr.parse().unwrap()] }],
            from: bans[0].ts,
            to: bans[bans.len() - 1].ts,
            offenders: collect(bans, &f),
        };
        // through JSON, as the files are exchanged between servers
        let json = |r: Report| serde_json::from_str::<Report>(&serde_json::to_string(&r).unwrap()).unwrap();
        let (m, skipped) = merge(vec![
            json(report("xmpp.example", "192.0.2.1", &a)),
            json(report("vpn", "192.0.2.2", &b)),
            json(report("vpn", "192.0.2.2", &b)),
        ]);
        assert_eq!(skipped, [2], "the same server's report twice is skipped");
        assert_eq!(m.servers.len(), 2);
        assert_eq!(m.offenders.len(), 2);
        let both = &m.offenders[0];
        assert_eq!((both.net.to_string().as_str(), both.bans), ("198.51.100.7", 2));
        assert_eq!(both.categories.len(), 2);
        let text = render_text(&m);
        assert!(text.contains("Abuse report from xmpp.example (192.0.2.1) and vpn (192.0.2.2)"), "{text}");
        assert!(text.contains("2026-10-10 07:59:58 UTC  (to 192.0.2.1) invalid user oracle"), "{text}");
        assert!(text.contains("2026-10-11 09:00:00 UTC  (to 192.0.2.2) connection attempt to closed port TCP/23 (Telnet)"), "{text}");
    }

    /// The console's live report: the window, this server's own bans, a few lines per source.
    #[test]
    fn live_report() {
        let dir = std::env::temp_dir().join(format!("lg-abuse-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("actions.jsonl");
        let now = time::parse_iso_prefix("2026-10-28 12:00:00").unwrap().0;
        let scan: Vec<String> = (0..200).map(|i| format!("10-28 10:{:02}:{:02} tripwire block TCP/{}", i / 60, i % 60, 1000 + i)).collect();
        let scan: Vec<&str> = scan.iter().map(String::as_str).collect();
        let mut bans = [
            ban("2026-10-28 11:00:00", "198.51.100.7", "tripwire", &scan),
            ban("2026-10-25 09:00:00", "192.0.2.5", "ssh", &["10-25 08:59:00 failed password for alice"]),
            ban("2026-10-28 11:30:00", "192.0.2.6", "from peers", &["10-28 11:29:00 invalid user oracle"]),
        ];
        bans[0].message = "ban 198.51.100.7 for 1h".into();
        let text: String = bans.iter().map(|a| serde_json::to_string(a).unwrap() + "\n").collect();
        std::fs::write(&log, text).unwrap();

        let day = live(&log, "24h".parse().unwrap(), now, "h".into(), vec![]).unwrap();
        assert_eq!(day.sources, 1, "the week's ban and the peer's are not in the day's");
        let o = &day.offenders[0];
        assert_eq!(o.net.to_string(), "198.51.100.7");
        assert_eq!((o.evidence.len(), o.omitted, o.events), (LIVE_LINES, 200 - LIVE_LINES, 200));
        assert_eq!(o.evidence[0].text, "connection attempt to closed port TCP/1000");
        assert!(o.activity.starts_with("connections to closed ports"), "{}", o.activity);

        let week = live(&log, "7d".parse().unwrap(), now, "h".into(), vec![]).unwrap();
        assert_eq!(week.sources, 2);
        let ssh = week.offenders.iter().find(|o| o.net.to_string() == "192.0.2.5").unwrap();
        assert_eq!(ssh.evidence[0].text, "failed password login (account name withheld)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The live report keeps a bounded number of sources (it is built inside the daemon's
    /// memory limit); the rest are counted, not kept.
    #[test]
    fn live_report_sources_are_capped() {
        let filter = Filter { only: vec![], min_events: 1 };
        let mut c = Collector::new(&filter, LIVE_LINES, 2);
        for (i, ip) in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.1"].iter().enumerate() {
            c.add(&ban(&format!("2026-10-28 10:0{i}:00"), ip, "ssh", &["10-28 09:59:00 failed password for alice"]));
        }
        assert_eq!(c.beyond, 1, "the third source is counted only");
        let kept = c.finish();
        assert_eq!(kept.iter().map(|o| o.net.to_string()).collect::<Vec<_>>(), ["192.0.2.1", "192.0.2.2"]);
        assert_eq!(kept[0].bans, 2, "a kept source's later bans still count");
    }

    /// A peer's report (up to 64 MB unpacked) merges in a moment, whatever it holds.
    #[test]
    fn large_peer_reports_merge_quickly() {
        let off = |n: u32| Offender {
            net: "198.51.100.7".parse().unwrap(),
            first: 0,
            last: 1,
            bans: 1,
            categories: BTreeSet::new(),
            evidence: (0..n).map(|i| Line { ts: Micros::from(i), server: None, text: "block TCP/23".into() }).collect(),
            omitted: 0,
            members: (0..n).map(|i| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i))).collect(),
            place: None,
            contact: None,
        };
        let report =
            |host: &str, o| Report { servers: vec![Server { host: host.into(), addresses: vec![] }], from: 0, to: 1, offenders: vec![o] };
        let start = std::time::Instant::now();
        let (m, _) = merge(vec![report("a", off(100_000)), report("b", off(100_000))]);
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
        let o = &m.offenders[0];
        assert_eq!(o.members.len(), 100_000, "each address once");
        assert_eq!(o.evidence.len(), 200_000, "each server's lines");
    }

    #[test]
    fn evidence_from_december_in_a_january_ban() {
        let jan = time::parse_iso_prefix("2027-01-01 00:00:10").unwrap().0;
        let (t, text) = evidence_time("12-31 23:59:59 block TCP/23", jan).unwrap();
        assert_eq!(time::fmt_ts(t), "2026-12-31 23:59:59");
        assert_eq!(text, "block TCP/23");
    }

    #[test]
    fn rdap_abuse_contact() {
        let json = r#"{"handle":"NET-198-51-100-0-1","name":"EXAMPLE-NET","startAddress":"198.51.100.0","endAddress":"198.51.100.255",
            "entities":[{"roles":["registrant"],"entities":[{"roles":["abuse"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["email",{},"text","Abuse@Example.net"]]]}]}]}"#;
        let (c, range) = parse_rdap(json).unwrap();
        assert_eq!(c.abuse, ["abuse@example.net"]);
        assert_eq!(c.network, "EXAMPLE-NET, NET-198-51-100-0-1");
        assert_eq!(range.unwrap().1.to_string(), "198.51.100.255");

        // owner-written data: no line breaks or odd characters reach the report
        let evil = r#"{"name":"X\nTo: someone@else.example","entities":[{"roles":["abuse"],
            "vcardArray":["vcard",[["email",{},"text","a@b.example\nInjected text"],["email",{},"text","ok@isp.example"]]]}]}"#;
        let (c, _) = parse_rdap(evil).unwrap();
        assert_eq!(c.abuse, ["ok@isp.example"]);
        assert!(!c.network.contains('\n'));
        assert!(!plausible_range("0.0.0.0".parse().unwrap(), "255.255.255.255".parse().unwrap()));
        assert!(plausible_range("198.51.100.0".parse().unwrap(), "198.51.100.255".parse().unwrap()));
    }
}
