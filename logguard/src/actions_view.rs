//! `logguard tui --actions <file>...`: the state at the end of decision logs (`actions.jsonl`,
//! plain or gzipped; several servers' logs, or rotated copies, combine), for the dashboard.
//! Nothing is replayed or re-scored: bans and unbans are applied in order, and the totals and
//! per-country figures are counted from the logs. Scores, accounts and the exposure scan
//! aren't in the logs, so those tabs stay hidden.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::engine::{Action, ActionKind, Ban, CountryDetail, PlaceStats, Snapshot, Stats, WorldView};
use crate::geo::{Geo, GeoDb};
use crate::net::Net;
use crate::time::Micros;

/// What the log covers, for the Overview tab.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogSummary {
    /// The log files, comma-separated.
    pub file: String,
    pub files: usize,
    /// Decisions counted once although logged twice: the same line in two files, or a ban
    /// received from a peer whose own log, with its ban, is among the files.
    #[serde(default)]
    pub duplicates: u64,
    pub from: Micros,
    pub to: Micros,
    pub decisions: u64,
    /// Lines that aren't decisions of this version (skipped).
    pub unreadable: u64,
    /// Bans decided by this server.
    pub bans_local: u32,
    /// Bans received from cluster peers, per peer.
    pub bans_peer: BTreeMap<String, u32>,
    /// Bans put back when a covering network ban ended.
    pub reinstated: u32,
    pub unbans: u32,
    pub alerts: u32,
    /// Bans decided here, per cause.
    pub categories: BTreeMap<String, u32>,
    /// Bans per hour, oldest first, over the last 30 days of the log at most.
    pub bans_per_hour: Vec<u64>,
    /// Whether the geo database was used (else places come from the ban messages).
    pub geo_db: bool,
    /// Bans per UTC day over the whole log, oldest first, days without bans included.
    #[serde(default)]
    pub bans_per_day: Vec<DayBans>,
    /// Bans per week (Monday to Sunday, UTC), oldest first.
    #[serde(default)]
    pub weeks: Vec<WeekTrend>,
}

/// Bans on one UTC day (days since 1970-01-01): decided by the servers, received from peers.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DayBans {
    pub day: i64,
    pub local: u32,
    pub peer: u32,
}

/// One week of bans and where they came from, to see whether a tuning change cut the
/// noise or let more through.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WeekTrend {
    /// The Monday, in days since 1970-01-01.
    pub start_day: i64,
    pub bans: u32,
    /// Distinct addresses and networks banned.
    pub sources: u32,
    /// The countries and networks most bans went to, most first.
    pub countries: Vec<(String, u32)>,
    pub networks: Vec<(String, u32)>,
}

const DAY: Micros = 86_400 * crate::time::SEC;
const WEEK_TOP: usize = 3;

/// The Monday of a day's week (1970-01-01 was a Thursday).
fn week_of(day: i64) -> i64 {
    day - (day + 3).rem_euclid(7)
}

/// Per-day and per-week ban counts, places labelled by `place`.
fn trends(bans: &[(Micros, Net, bool)], place: impl Fn(&Net) -> Geo) -> (Vec<DayBans>, Vec<WeekTrend>) {
    let (Some(first), Some(last)) = (bans.first(), bans.last()) else { return (vec![], vec![]) };
    let first_day = first.0.div_euclid(DAY);
    let mut days: Vec<DayBans> = (first_day..=last.0.div_euclid(DAY)).map(|day| DayBans { day, ..Default::default() }).collect();
    // per Monday: bans, sources, bans per country, bans per network
    type Week = (u32, HashSet<Net>, HashMap<String, u32>, HashMap<String, u32>);
    let mut weeks: BTreeMap<i64, Week> = BTreeMap::new();
    for (ts, net, peer) in bans {
        let day = ts.div_euclid(DAY);
        let d = &mut days[(day - first_day) as usize];
        if *peer {
            d.peer += 1;
        } else {
            d.local += 1;
        }
        let w = weeks.entry(week_of(day)).or_default();
        w.0 += 1;
        w.1.insert(*net);
        let g = place(net);
        *w.2.entry(g.country_name().unwrap_or("unknown").to_string()).or_default() += 1;
        *w.3.entry(Geo { country: None, ..g }.label().unwrap_or_else(|| "unknown".into())).or_default() += 1;
    }
    let top = |m: HashMap<String, u32>| {
        let mut v: Vec<(String, u32)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(WEEK_TOP);
        v
    };
    let weeks = weeks
        .into_iter()
        .map(|(start_day, (bans, sources, countries, networks))| WeekTrend {
            start_day,
            bans,
            sources: sources.len() as u32,
            countries: top(countries),
            networks: top(networks),
        })
        .collect();
    (days, weeks)
}

const RECENT: usize = 500;
const ISPS: usize = 100;
const COUNTRY_ISPS: usize = 50;
const PORTS: usize = 40;
const HOUR: Micros = 3600 * crate::time::SEC;

/// Reads the logs and builds the snapshot the dashboard shows.
pub fn load(paths: &[PathBuf], geo: Option<&GeoDb>) -> Result<Snapshot> {
    let mut unreadable = 0;
    let files = paths.iter().map(|p| read_log(p, &mut unreadable)).collect::<Result<Vec<_>>>()?;
    let mut snap = build(files, geo);
    if let Some(sum) = snap.actions_log.as_mut() {
        sum.file = paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ");
        sum.unreadable = unreadable;
    }
    Ok(snap)
}

fn read_log(path: &Path, unreadable: &mut u64) -> Result<Vec<Action>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader: Box<dyn Read> =
        if path.extension().is_some_and(|e| e == "gz") { Box::new(flate2::read::GzDecoder::new(file)) } else { Box::new(file) };
    let mut actions = Vec::new();
    crate::record::for_each_action_line(reader, |line| {
        if line.trim().is_empty() {
            return;
        }
        match serde_json::from_str::<Action>(line) {
            Ok(a) => actions.push(a),
            Err(_) => *unreadable += 1,
        }
    })
    .with_context(|| format!("reading {}", path.display()))?;
    Ok(actions)
}

/// How far apart a peer's own ban and the copy another node logged may be (the copy is
/// logged when the fact arrives, normally within seconds).
const PEER_COPY_WINDOW: Micros = 300 * crate::time::SEC;

/// Bans and unbans of one log applied in order: what was still banned at its end.
fn active_at_end(actions: &[Action]) -> HashMap<Net, Ban> {
    let mut active: HashMap<Net, Ban> = HashMap::new();
    for a in actions {
        let Some(net) = a.target else { continue };
        match a.kind {
            ActionKind::Ban => {
                for old in &a.superseded {
                    active.remove(old);
                }
                let offence = a
                    .message
                    .split_once("(offence #")
                    .and_then(|(_, r)| r.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok())
                    .unwrap_or(1);
                let reason = a.message.split_once("): ").map_or(a.message.as_str(), |(_, r)| r).to_string();
                let until = a.until.unwrap_or(a.ts + HOUR);
                let origin = peer_of(&a.message).map(String::from);
                active.insert(net, Ban { net, since: a.ts, until, offence, reason, origin, inner: vec![] });
            }
            ActionKind::Unban => {
                active.remove(&net);
            }
            _ => {}
        }
    }
    active
}

/// "(from peer vpn)" -> "vpn"
fn peer_of(message: &str) -> Option<&str> {
    let rest = message.split_once("(from peer ")?.1;
    Some(rest.split_once(')')?.0)
}

/// "ban 1.2.3.4 [Germany / Hetzner Online GmbH (AS24940)] for 1h ..." -> the place.
fn label_of(message: &str) -> Option<Geo> {
    let start = message.find(" [")? + 2;
    let inner = &message[start..start + message[start..].find(']')?];
    let (country, net) = match inner.split_once(" / ") {
        Some((c, n)) => (Some(c), Some(n)),
        None if inner.ends_with(')') => (None, Some(inner)),
        None => (Some(inner), None),
    };
    let (org, asn) = match net.and_then(|n| n.rsplit_once(" (AS")) {
        Some((org, asn)) => (Some(org.to_string()), asn.trim_end_matches(')').parse().ok()),
        None => (net.map(String::from), None),
    };
    let country = country.and_then(crate::geo::country_code);
    (country.is_some() || asn.is_some()).then_some(Geo { country, asn, org })
}

/// "10-12 10:48:27 tripwire block TCP/23" (or a network member's "1.2.3.4 block UDP/53") -> 23
fn port_of(evidence: &str) -> Option<u16> {
    let (_, rest) = evidence.split_once(" block ")?;
    let (proto, port) = rest.split_once('/')?;
    if proto != "TCP" && proto != "UDP" {
        return None;
    }
    port.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

fn build(mut files: Vec<Vec<Action>>, geo: Option<&GeoDb>) -> Snapshot {
    for f in &mut files {
        f.sort_by_key(|a| a.ts);
    }
    // Still banned at the end: per log (an unban in one log never ends another's ban), then
    // one entry per address or network, the server's own ban before a peer's copy.
    let mut active: HashMap<Net, Ban> = HashMap::new();
    for f in &files {
        for (net, b) in active_at_end(f) {
            let better = active.get(&net).is_none_or(|cur| (b.origin.is_none(), b.until) > (cur.origin.is_none(), cur.until));
            if better {
                active.insert(net, b);
            }
        }
    }
    // Every ban decided on a server itself, per address, to spot peers' copies of it.
    let mut own_bans: HashMap<Net, Vec<(usize, Micros)>> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        for a in f.iter().filter(|a| a.kind == ActionKind::Ban && peer_of(&a.message).is_none()) {
            if let Some(net) = a.target {
                own_bans.entry(net).or_default().push((i, a.ts));
            }
        }
    }
    let n_files = files.len();
    let mut actions: Vec<(usize, Action)> = files.into_iter().enumerate().flat_map(|(i, f)| f.into_iter().map(move |a| (i, a))).collect();
    actions.sort_by_key(|(_, a)| a.ts);
    let total = actions.len();
    let mut seen: HashSet<(Micros, String, Option<Net>, String)> = HashSet::new();
    let actions: Vec<Action> = actions
        .into_iter()
        .filter(|(i, a)| {
            let copy = a.kind == ActionKind::Ban
                && peer_of(&a.message).is_some()
                && a.target
                    .and_then(|n| own_bans.get(&n))
                    .is_some_and(|v| v.iter().any(|(j, t)| j != i && (a.ts - t).abs() <= PEER_COPY_WINDOW));
            !copy && seen.insert((a.ts, format!("{:?}", a.kind), a.target, a.message.clone()))
        })
        .map(|(_, a)| a)
        .collect();

    // Some alerts carry no time (0): they don't define the period.
    let from = actions.iter().map(|a| a.ts).find(|t| *t > 0).unwrap_or(0);
    let to = actions.last().map_or(0, |a| a.ts);
    // the hourly chart covers the last 30 days at most, however long the log
    let hours_from = from.max(to - 30 * 24 * HOUR);
    let mut sum = LogSummary {
        from,
        to,
        files: n_files,
        decisions: actions.len() as u64,
        duplicates: (total - actions.len()) as u64,
        geo_db: geo.is_some(),
        ..Default::default()
    };
    let mut stats = Stats::default();
    let mut labels: HashMap<Net, Geo> = HashMap::new();
    // every source banned in the period: events seen by the servers, local ports probed
    let mut sources: BTreeMap<Net, (u64, Vec<u16>)> = BTreeMap::new();
    let mut applied = false;
    // (time, target, from a peer) of every ban but reinstated ones, for the trends
    let mut timeline: Vec<(Micros, Net, bool)> = Vec::new();

    for a in &actions {
        match a.kind {
            ActionKind::Ban => {
                let Some(net) = a.target else { continue };
                stats.bans += 1;
                applied |= a.applied;
                if a.ts >= hours_from {
                    let hour = ((a.ts - hours_from) / HOUR) as usize;
                    if sum.bans_per_hour.len() <= hour {
                        sum.bans_per_hour.resize(hour + 1, 0);
                    }
                    sum.bans_per_hour[hour] += 1;
                }
                let peer = peer_of(&a.message);
                if a.ts > 0 && a.category.as_deref() != Some("reinstated") {
                    timeline.push((a.ts, net, peer.is_some()));
                }
                match (peer, a.category.as_deref()) {
                    (Some(p), _) => *sum.bans_peer.entry(p.to_string()).or_default() += 1,
                    (None, Some("reinstated")) => sum.reinstated += 1,
                    (None, c) => {
                        sum.bans_local += 1;
                        *sum.categories.entry(c.unwrap_or("other").to_string()).or_default() += 1;
                    }
                }
                if let Some(g) = label_of(&a.message) {
                    labels.insert(net, g);
                }
                let src = sources.entry(net).or_default();
                if peer.is_none() {
                    src.0 += a.evidence.len() as u64;
                    src.1.extend(a.evidence.iter().filter_map(|e| port_of(e)));
                }
            }
            ActionKind::Unban => sum.unbans += 1,
            ActionKind::Alert => sum.alerts += 1,
            ActionKind::Allow | ActionKind::Disallow => {}
        }
    }
    stats.alerts = u64::from(sum.alerts);
    let mut bans: Vec<Ban> = active.into_values().filter(|b| b.until > to).collect();
    bans.sort_by_key(|b| std::cmp::Reverse(b.since));

    // The database where it knows the address; the ban message's label fills the gaps.
    let place = |net: &Net| {
        let label = labels.get(net).cloned().unwrap_or_default();
        match geo.map(|db| db.lookup(net.addr)) {
            Some(g) => Geo { country: g.country.or(label.country), asn: g.asn.or(label.asn), org: g.org.or(label.org) },
            None => label,
        }
    };
    (sum.bans_per_day, sum.weeks) = trends(&timeline, place);
    let world = world(&bans, &sources, place, geo.is_some() || !labels.is_empty());

    let recent: Vec<Action> = actions.iter().rev().take(RECENT).cloned().collect();
    let alerts: Vec<Action> = actions.iter().rev().filter(|a| a.kind == ActionKind::Alert).take(RECENT).cloned().collect();
    Snapshot {
        generated: to,
        started: from,
        mode: if applied { crate::config::Mode::Enforce } else { crate::config::Mode::Shadow },
        fast_threshold: 0.0,
        slow_threshold: 0.0,
        stats,
        tracked_ips: sources.len(),
        tracked_connections: 0,
        offenders: vec![],
        bans,
        recent,
        alerts,
        accounts: vec![],
        trusted: vec![],
        exposure: None,
        cluster: None,
        allowed: vec![],
        feeds: None,
        certs: vec![],
        last_lines: BTreeMap::new(),
        cron: None,
        av: None,
        resources: None,
        world,
        port_names: vec![],
        actions_log: Some(sum),
        patches: None,
        verify: None,
        procwatch: None,
        allow_hosts: vec![],
        patterns: vec![],
    }
}

/// Per country and network: active bans at the end, sources banned during the period
/// ("offenders"), their evidence lines ("events"), and the ports they probed.
fn world(bans: &[Ban], sources: &BTreeMap<Net, (u64, Vec<u16>)>, place: impl Fn(&Net) -> Geo, located: bool) -> WorldView {
    let mut countries: HashMap<[u8; 2], PlaceStats> = HashMap::new();
    let mut isps: HashMap<u32, PlaceStats> = HashMap::new();
    let mut country_isps: HashMap<([u8; 2], u32), PlaceStats> = HashMap::new();
    let mut ports: HashMap<u16, u64> = HashMap::new();
    let mut country_ports: HashMap<[u8; 2], HashMap<u16, u64>> = HashMap::new();
    let mut unlocated = 0;
    let mut add = |g: &Geo, bans: u32, offenders: u32, events: u64| {
        let bump = |e: &mut PlaceStats| {
            e.bans += bans;
            e.offenders += offenders;
            e.events += events;
        };
        let cc = g.country.map(|c| String::from_utf8_lossy(&c).into_owned()).unwrap_or_default();
        let isp = |asn: u32| PlaceStats {
            key: format!("AS{asn}"),
            name: g.org.clone().unwrap_or_default(),
            country: cc.clone(),
            ..Default::default()
        };
        match g.country {
            Some(c) => {
                bump(countries.entry(c).or_insert_with(|| PlaceStats {
                    key: cc.clone(),
                    name: crate::geo::country_name(&c).to_string(),
                    ..Default::default()
                }));
                if let Some(asn) = g.asn {
                    bump(country_isps.entry((c, asn)).or_insert_with(|| isp(asn)));
                }
            }
            // sources only: a banned source is counted once, not also for its ban
            None => unlocated += offenders,
        }
        if let Some(asn) = g.asn {
            bump(isps.entry(asn).or_insert_with(|| isp(asn)));
        }
    };
    for b in bans {
        add(&place(&b.net), 1, 0, 0);
    }
    for (net, (events, probed)) in sources {
        let g = place(net);
        add(&g, 0, 1, *events);
        for p in probed {
            *ports.entry(*p).or_default() += 1;
            if let Some(c) = g.country {
                *country_ports.entry(c).or_default().entry(*p).or_default() += 1;
            }
        }
    }
    let top_ports = |hits: &HashMap<u16, u64>| {
        let mut v: Vec<(u16, u64)> = hits.iter().map(|(p, n)| (*p, *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(PORTS);
        v
    };
    let worst = |a: &PlaceStats, b: &PlaceStats| {
        b.bans.cmp(&a.bans).then(b.offenders.cmp(&a.offenders)).then(b.events.cmp(&a.events)).then(a.key.cmp(&b.key))
    };
    let mut countries: Vec<PlaceStats> = countries.into_values().collect();
    countries.sort_by(|a, b| b.offenders.cmp(&a.offenders).then(b.bans.cmp(&a.bans)).then(b.events.cmp(&a.events)).then(a.key.cmp(&b.key)));
    let mut isps: Vec<PlaceStats> = isps.into_values().collect();
    isps.sort_by(worst);
    isps.truncate(ISPS);
    let mut by_country: BTreeMap<String, CountryDetail> = BTreeMap::new();
    for ((c, _), stats) in country_isps {
        by_country.entry(String::from_utf8_lossy(&c).into_owned()).or_default().isps.push(stats);
    }
    for d in by_country.values_mut() {
        d.isps.sort_by(worst);
        d.isps.truncate(COUNTRY_ISPS);
    }
    for (c, hits) in &country_ports {
        by_country.entry(String::from_utf8_lossy(c).into_owned()).or_default().ports = top_ports(hits);
    }
    WorldView { geo: located, countries, isps, ports: top_ports(&ports), logged_in: BTreeMap::new(), unlocated, by_country }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(json: &str) -> Action {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn final_state_from_decisions() {
        let h = HOUR;
        let actions = vec![
            line(&format!(
                r#"{{"ts":{},"kind":"ban","severity":"high","target":"5.9.1.1","until":{},"message":"ban 5.9.1.1 [Germany / Hetzner Online GmbH (AS24940)] for 1h (offence #2): burst score fast=100 [1x fw_tripwire]","evidence":["10-12 10:00:00 tripwire block TCP/23"],"applied":true,"category":"tripwire"}}"#,
                h,
                3 * h
            )),
            line(&format!(
                r#"{{"ts":{},"kind":"ban","severity":"high","target":"1.0.0.1","until":{},"message":"ban 1.0.0.1 for 59m (from peer vpn): burst score fast=100 [1x fw_tripwire]","evidence":["10-12 10:00:00 peer vpn: 1x fw_tripwire"],"applied":true,"category":"from peers"}}"#,
                h + 1,
                2 * h
            )),
            line(&format!(
                r#"{{"ts":{},"kind":"ban","severity":"high","target":"11.35.1.1","until":{},"message":"ban 11.35.1.1 [Finland / Hetzner Online GmbH (AS24940)] for 1h (offence #1): x","evidence":["10-12 10:01:00 block UDP/3389","10-12 10:01:01 block TCP/3389"],"applied":true,"category":"port scan"}}"#,
                h + 2,
                9 * h
            )),
            line(&format!(r#"{{"ts":{},"kind":"unban","severity":"info","target":"11.35.1.1","message":"unban"}}"#, 2 * h)),
            line(&format!(r#"{{"ts":{},"kind":"alert","severity":"warning","message":"something"}}"#, 2 * h + 5)),
            line(r#"{"ts":0,"kind":"alert","severity":"warning","message":"no time"}"#),
        ];
        let s = build(vec![actions], None);
        let sum = s.actions_log.as_ref().unwrap();
        assert_eq!((sum.bans_local, sum.bans_peer.get("vpn").copied(), sum.unbans, sum.alerts), (2, Some(1), 1, 2));
        assert_eq!(sum.categories, BTreeMap::from([("port scan".into(), 1), ("tripwire".into(), 1)]));
        assert_eq!(sum.bans_per_hour, vec![3]);
        assert_eq!((sum.from, sum.to), (h, 2 * h + 5), "an alert without a time doesn't start the period");
        // at the end (2h+5): 1.0.0.1 expired at 2h, 11.35.1.1 was lifted, 5.9.1.1 lasts until 3h
        let active: Vec<String> = s.bans.iter().map(|b| b.net.to_string()).collect();
        assert_eq!(active, ["5.9.1.1"]);
        assert_eq!((s.bans[0].offence, s.bans[0].reason.as_str()), (2, "burst score fast=100 [1x fw_tripwire]"));
        assert_eq!(s.mode, crate::config::Mode::Enforce);
        // places from the ban messages; the peer ban has no label
        let w = &s.world;
        let c: Vec<(&str, u32, u32, u64)> = w.countries.iter().map(|c| (c.key.as_str(), c.bans, c.offenders, c.events)).collect();
        assert_eq!(c, [("DE", 1, 1, 1), ("FI", 0, 1, 2)]);
        assert_eq!(w.unlocated, 1);
        assert_eq!(w.ports, [(3389, 2), (23, 1)], "TCP and UDP together; peer evidence isn't ours");
        assert_eq!(w.by_country["FI"].ports, [(3389, 2)]);
        assert_eq!((w.isps[0].key.as_str(), w.isps[0].offenders), ("AS24940", 2));
        assert_eq!(s.recent[0].kind, ActionKind::Alert, "newest first");

        // a long log: the hourly chart keeps the last 30 days
        let old = line(
            r#"{"ts":3600000000,"kind":"ban","severity":"high","target":"9.9.9.9","until":3600000001,"message":"ban 9.9.9.9 for 1s (offence #1): x","applied":true}"#,
        );
        let new = line(&format!(
            r#"{{"ts":{},"kind":"ban","severity":"high","target":"9.9.9.8","until":{},"message":"ban 9.9.9.8 for 1h (offence #1): x","applied":true}}"#,
            400 * 24 * h,
            401 * 24 * h
        ));
        let s = build(vec![vec![old, new]], None);
        assert_eq!(s.actions_log.unwrap().bans_per_hour.len(), 30 * 24 + 1);
    }

    #[test]
    fn logs_of_two_servers_combined() {
        let h = HOUR;
        let ban = |ts: Micros, net: &str, until: Micros, msg: &str| {
            line(&format!(
                r#"{{"ts":{ts},"kind":"ban","severity":"high","target":"{net}","until":{until},"message":"{msg}","applied":true}}"#
            ))
        };
        let unban = |ts: Micros, net: &str| {
            line(&format!(r#"{{"ts":{ts},"kind":"unban","severity":"info","target":"{net}","message":"unban {net}"}}"#))
        };
        // vpn bans 9.9.9.9 for 6h; xmpp receives it 2s later but its copy is capped at 1h
        let vpn = vec![
            ban(h, "9.9.9.9", 7 * h, "ban 9.9.9.9 for 6h (offence #2): x"),
            ban(h + 9, "8.8.8.8", 2 * h, "ban 8.8.8.8 for 1h (offence #1): y"),
        ];
        let xmpp = vec![
            ban(h + 2, "9.9.9.9", 2 * h, "ban 9.9.9.9 for 59m (from peer vpn): x"),
            unban(2 * h, "9.9.9.9"),
            ban(h + 3, "7.7.7.7", 9 * h, "ban 7.7.7.7 for 8h (offence #3): z"),
            // a peer ban whose origin log isn't among the files stays
            ban(h + 4, "6.6.6.6", 9 * h, "ban 6.6.6.6 for 8h (from peer nc): w"),
        ];
        let s = build(vec![xmpp, vpn.clone()], None);
        let sum = s.actions_log.as_ref().unwrap();
        assert_eq!((sum.files, sum.duplicates, sum.bans_local), (2, 1, 3), "xmpp's copy of the vpn ban counted once");
        assert_eq!(sum.bans_peer, BTreeMap::from([("nc".into(), 1)]));
        // ends at 2h+? : the last decision is xmpp's unban at 2h. 9.9.9.9: the copy ended, vpn's own ban lasts.
        let mut active: Vec<(String, Option<String>)> = s.bans.iter().map(|b| (b.net.to_string(), b.origin.clone())).collect();
        active.sort();
        assert_eq!(active, [("6.6.6.6".into(), Some("nc".into())), ("7.7.7.7".into(), None), ("9.9.9.9".into(), None)]);
        // the same file twice: every line counted once
        let twice = build(vec![vpn.clone(), vpn], None);
        assert_eq!(twice.actions_log.as_ref().map(|s| (s.decisions, s.duplicates, s.bans_local)), Some((2, 2, 2)));
    }

    #[test]
    fn trends_per_day_and_week() {
        let day = DAY;
        // 2026-10-12 is a Monday
        let monday = crate::time::days_from_civil(2026, 10, 12) * day;
        assert_eq!(week_of(monday / day), monday / day);
        assert_eq!(week_of(monday / day + 6), monday / day, "Sunday");
        let ban = |ts: Micros, net: &str, msg: &str| {
            line(&format!(
                r#"{{"ts":{ts},"kind":"ban","severity":"high","target":"{net}","until":{},"message":"{msg}","applied":true}}"#,
                ts + HOUR
            ))
        };
        let actions = vec![
            ban(monday - day, "1.0.0.1", "ban 1.0.0.1 [Germany / Hetzner Online GmbH (AS24940)] for 1h (offence #1): x"),
            ban(monday + HOUR, "1.0.0.2", "ban 1.0.0.2 [Germany / Hetzner Online GmbH (AS24940)] for 1h (offence #1): x"),
            ban(monday + 2 * HOUR, "1.0.0.2", "ban 1.0.0.2 [Germany / Hetzner Online GmbH (AS24940)] for 1h (offence #2): x"),
            ban(monday + 3 * day, "2.0.0.1", "ban 2.0.0.1 [France / OVH SAS (AS16276)] for 1h (from peer vpn): y"),
        ];
        let s = build(vec![actions], None);
        let sum = s.actions_log.unwrap();
        let days: Vec<(u32, u32)> = sum.bans_per_day.iter().map(|d| (d.local, d.peer)).collect();
        assert_eq!(days, [(1, 0), (2, 0), (0, 0), (0, 0), (0, 1)], "Sunday, then Monday to Thursday");
        assert_eq!(sum.weeks.len(), 2);
        let w = &sum.weeks[1];
        assert_eq!((w.start_day, w.bans, w.sources), (monday / day, 3, 2));
        assert_eq!(w.countries, [("Germany".to_string(), 2), ("France".to_string(), 1)]);
        assert_eq!(w.networks[0], ("Hetzner Online GmbH (AS24940)".to_string(), 2));
    }

    #[test]
    fn labels_and_ports_parsed() {
        let g = label_of("ban 1.2.3.4 [United States / Microsoft Corporation (AS8075)] for 1h").unwrap();
        assert_eq!((g.country, g.asn, g.org.as_deref()), (Some(*b"US"), Some(8075), Some("Microsoft Corporation")));
        assert_eq!(label_of("ban 1.2.3.4 for 1h (offence #1): x [1x fw_block]"), None, "signal list isn't a place");
        assert_eq!(port_of("10-12 10:48:27 tripwire block TCP/23"), Some(23));
        assert_eq!(port_of("1.2.3.4 10-12 10:48:27 block UDP/53"), Some(53));
        assert_eq!(port_of("10-12 10:48:27 port scan: 16 closed ports"), None);
        assert_eq!(peer_of("ban x for 59m (from peer vpn): y"), Some("vpn"));
    }
}
