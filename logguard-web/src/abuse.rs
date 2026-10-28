//! Abuse reports in the console. Each node's logguard builds its own (`abuse 24h` / `abuse 7d`
//! on its console socket): its bans of the window with their evidence, worded for an abuse
//! desk, each source with its country and network from the geo database. Here they are
//! checked, merged across the nodes (one entry per source, each log line marked with the node
//! it hit) and split per provider: one entry per network owner (by AS number, else by name),
//! as an abuse desk gets one mail.
//!
//! What a node sends is shown as text only; still, long or odd strings are cut here.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::time::Micros;

/// Sources taken from one node (logguard sends its 1000 most persistent).
const MAX_SOURCES: usize = 1000;
/// Log lines kept per source (as many as the weekly text report quotes).
const MAX_LINES: usize = 25;
/// Network members listed per source.
const MAX_MEMBERS: usize = 100;

#[derive(Deserialize)]
struct NodeReport {
    /// The server's public addresses: where the attacks went.
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    from: Micros,
    #[serde(default)]
    to: Micros,
    /// Sources in the window, also those beyond the ones sent.
    #[serde(default)]
    sources: usize,
    #[serde(default)]
    offenders: Vec<Source>,
}

/// One source: an address or network that was banned in the window.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Source {
    pub net: String,
    #[serde(default)]
    pub first: Micros,
    #[serde(default)]
    pub last: Micros,
    #[serde(default)]
    pub bans: u64,
    /// Log lines and network members behind it.
    #[serde(default)]
    pub events: u64,
    #[serde(default)]
    pub categories: BTreeSet<String>,
    /// What it did, in words for an abuse desk.
    #[serde(default)]
    pub activity: String,
    #[serde(default)]
    pub evidence: Vec<Line>,
    /// Log lines beyond those in `evidence`.
    #[serde(default)]
    pub omitted: u64,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// The nodes that banned it.
    #[serde(default)]
    pub nodes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Line {
    pub ts: Micros,
    /// The node whose logs it is from.
    #[serde(default)]
    pub server: Option<String>,
    /// That node's public address (its first IPv4 one): the text for an abuse desk names the
    /// attacked server by it, never by the node's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub text: String,
}

/// One node's report, checked.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub from: Micros,
    pub to: Micros,
    /// Sources in the window, also those the node didn't send.
    pub total: usize,
    pub sources: Vec<Source>,
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// An address or network as logguard writes it, or None.
fn net_ok(n: &str) -> bool {
    (2..=43).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_hexdigit() || b".:/".contains(&b))
}

/// Reads node `node`'s report (logguard's JSON), marking its log lines with the node's name.
pub fn parse(text: &str, node: &str) -> Result<Parsed> {
    let r: NodeReport = serde_json::from_str(text).context("not an abuse report")?;
    let node = clean(node, 64);
    let addresses: Vec<&String> = r.addresses.iter().filter(|a| net_ok(a) && !a.contains('/')).collect();
    let to = addresses.iter().find(|a| !a.contains(':')).or(addresses.first()).map(|a| a.to_string());
    let mut sources = Vec::new();
    for mut s in r.offenders.into_iter().take(MAX_SOURCES) {
        if !net_ok(&s.net) {
            continue;
        }
        s.activity = clean(&s.activity, 1000);
        s.categories = s.categories.iter().take(20).map(|c| clean(c, 40)).collect();
        if s.evidence.len() > MAX_LINES {
            s.omitted = s.omitted.saturating_add((s.evidence.len() - MAX_LINES) as u64);
            s.evidence.truncate(MAX_LINES);
        }
        for l in &mut s.evidence {
            l.text = clean(&l.text, 300);
            l.server = Some(node.clone());
            l.to = to.clone();
        }
        s.members.retain(|m| net_ok(m));
        s.members.truncate(MAX_MEMBERS);
        s.country = s.country.filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()));
        s.country_name = s.country_name.map(|c| clean(&c, 60));
        s.org = s.org.map(|o| clean(&o, 100)).filter(|o| !o.is_empty());
        s.nodes = vec![node.clone()];
        sources.push(s);
    }
    Ok(Parsed { from: r.from, to: r.to, total: r.sources.max(sources.len()), sources })
}

/// One node's part in a report.
#[derive(Clone, Debug, Serialize)]
pub struct NodePart {
    pub id: String,
    pub name: String,
    /// Sources in the window on it.
    pub sources: usize,
    /// Sources it didn't send (beyond its most persistent ones).
    pub beyond: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A network owner and the sources in its networks.
#[derive(Clone, Debug, Serialize)]
pub struct Provider {
    /// "AS16276", else "org:<name>", else "unknown".
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// The network's owner as the geo database names it; None when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// (code, name) of its sources' countries.
    pub countries: Vec<(String, String)>,
    pub bans: u64,
    pub events: u64,
    pub first: Micros,
    pub last: Micros,
    pub nodes: Vec<String>,
    pub sources: Vec<Source>,
}

/// The report the page shows: per provider, the nodes' sources merged.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub window: String,
    pub from: Micros,
    pub to: Micros,
    pub generated: Micros,
    pub nodes: Vec<NodePart>,
    /// Distinct sources.
    pub sources: usize,
    pub providers: Vec<Provider>,
}

/// Merges the nodes' reports (`parts`: each node's id, name and its report or why there is
/// none) and splits the sources per provider, most bans first.
pub fn merge(window: &str, parts: Vec<(String, String, Result<Parsed, String>)>, now: Micros) -> Report {
    let mut nodes = Vec::new();
    let mut by: BTreeMap<String, Source> = BTreeMap::new();
    let (mut from, mut to) = (Micros::MAX, 0);
    for (id, name, part) in parts {
        let p = match part {
            Ok(p) => p,
            Err(e) => {
                nodes.push(NodePart { id, name, sources: 0, beyond: 0, error: Some(e) });
                continue;
            }
        };
        nodes.push(NodePart { id, name, sources: p.total, beyond: p.total.saturating_sub(p.sources.len()), error: None });
        from = from.min(p.from);
        to = to.max(p.to);
        for s in p.sources {
            match by.get_mut(&s.net) {
                None => {
                    by.insert(s.net.clone(), s);
                }
                Some(m) => add(m, s),
            }
        }
    }
    let total = by.len();
    let mut groups: BTreeMap<String, Provider> = BTreeMap::new();
    for s in by.into_values() {
        let key = match (s.asn, &s.org) {
            (Some(n), _) => format!("AS{n}"),
            (None, Some(o)) => format!("org:{o}"),
            (None, None) => "unknown".into(),
        };
        let p = groups.entry(key.clone()).or_insert_with(|| Provider {
            key,
            asn: s.asn,
            name: None,
            countries: vec![],
            bans: 0,
            events: 0,
            first: s.first,
            last: s.last,
            nodes: vec![],
            sources: vec![],
        });
        if p.name.is_none() {
            p.name = s.org.clone();
        }
        if let (Some(c), Some(n)) = (&s.country, &s.country_name) {
            if !p.countries.iter().any(|(k, _)| k == c) {
                p.countries.push((c.clone(), n.clone()));
            }
        }
        p.bans = p.bans.saturating_add(s.bans);
        p.events = p.events.saturating_add(s.events);
        p.first = p.first.min(s.first);
        p.last = p.last.max(s.last);
        for n in &s.nodes {
            if !p.nodes.contains(n) {
                p.nodes.push(n.clone());
            }
        }
        p.sources.push(s);
    }
    let mut providers: Vec<Provider> = groups.into_values().collect();
    for p in &mut providers {
        p.sources.sort_by_key(|s| std::cmp::Reverse((s.bans, s.events)));
        p.countries.sort();
        p.nodes.sort();
    }
    providers.sort_by_key(|p| std::cmp::Reverse((p.bans, p.events, p.sources.len())));
    Report { window: window.into(), from: if from == Micros::MAX { 0 } else { from }, to, generated: now, nodes, sources: total, providers }
}

/// Adds another node's view of the same source.
fn add(m: &mut Source, s: Source) {
    m.first = m.first.min(s.first);
    m.last = m.last.max(s.last);
    m.bans = m.bans.saturating_add(s.bans);
    m.events = m.events.saturating_add(s.events);
    m.omitted = m.omitted.saturating_add(s.omitted);
    m.categories.extend(s.categories);
    // the nodes may word it differently: each part once
    for part in s.activity.split("; ") {
        if !part.is_empty() && !m.activity.split("; ").any(|p| p == part) {
            if !m.activity.is_empty() {
                m.activity.push_str("; ");
            }
            m.activity.push_str(part);
        }
    }
    m.evidence.extend(s.evidence);
    m.evidence.sort();
    m.evidence.dedup();
    if m.evidence.len() > MAX_LINES {
        m.omitted = m.omitted.saturating_add((m.evidence.len() - MAX_LINES) as u64);
        m.evidence.truncate(MAX_LINES);
    }
    for x in s.members {
        if m.members.len() < MAX_MEMBERS && !m.members.contains(&x) {
            m.members.push(x);
        }
    }
    m.members.sort();
    m.country = m.country.take().or(s.country);
    m.country_name = m.country_name.take().or(s.country_name);
    m.asn = m.asn.or(s.asn);
    m.org = m.org.take().or(s.org);
    for n in s.nodes {
        if !m.nodes.contains(&n) {
            m.nodes.push(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report(sources: serde_json::Value) -> String {
        json!({ "host": "h", "addresses": ["2001:db8::1", "192.0.2.1"], "from": 10, "to": 20, "sources": 3, "offenders": sources })
            .to_string()
    }

    #[test]
    fn merges_and_splits_per_provider() {
        let a = report(json!([
            { "net": "192.0.2.5", "first": 11, "last": 12, "bans": 2, "events": 3, "categories": ["ssh"], "activity": "SSH probing / login attempts",
              "evidence": [{ "ts": 11, "text": "failed password login (account name withheld)" }], "omitted": 2, "members": [],
              "country": "FR", "country_name": "France", "asn": 16276, "org": "OVH SAS" },
            { "net": "198.51.100.0/24", "first": 12, "last": 13, "bans": 1, "events": 4, "activity": "coordinated probing",
              "evidence": [], "members": ["198.51.100.1", "198.51.100.2"], "country": "FR", "country_name": "France", "asn": 16276, "org": "OVH SAS" },
            { "net": "203.0.113.9", "first": 14, "last": 14, "bans": 1, "events": 1, "activity": "port scanning", "evidence": [] }
        ]));
        let b = report(json!([
            { "net": "192.0.2.5", "first": 9, "last": 15, "bans": 1, "events": 1, "categories": ["tripwire"], "activity": "connections to closed ports",
              "evidence": [{ "ts": 9, "text": "connection attempt to closed port TCP/23 (Telnet)" }], "asn": 16276, "org": "OVH SAS" },
            { "net": "not an address <b>", "bans": 99 }
        ]));
        let parts = vec![
            ("0".to_string(), "xmpp".to_string(), parse(&a, "xmpp").map_err(|e| e.to_string())),
            ("1".to_string(), "vpn".to_string(), parse(&b, "vpn").map_err(|e| e.to_string())),
            ("2".to_string(), "tg".to_string(), Err("connecting: refused".to_string())),
        ];
        let r = merge("7d", parts, 30);
        assert_eq!(r.sources, 3, "the same source on two nodes once; the bad one left out");
        assert_eq!(r.nodes[2].error.as_deref(), Some("connecting: refused"));
        assert_eq!((r.from, r.to), (10, 20));
        let ovh = &r.providers[0];
        assert_eq!((ovh.key.as_str(), ovh.name.as_deref(), ovh.bans, ovh.sources.len()), ("AS16276", Some("OVH SAS"), 4, 2));
        assert_eq!(ovh.countries, [("FR".to_string(), "France".to_string())]);
        assert_eq!(ovh.nodes, ["vpn", "xmpp"]);
        let both = &ovh.sources[0];
        assert_eq!((both.net.as_str(), both.bans, both.first, both.last, both.omitted), ("192.0.2.5", 3, 9, 15, 2));
        assert_eq!(both.activity, "SSH probing / login attempts; connections to closed ports");
        assert_eq!(both.evidence[0].server.as_deref(), Some("vpn"), "oldest first, marked with its node");
        assert_eq!(both.evidence[1].server.as_deref(), Some("xmpp"));
        assert_eq!(both.evidence[1].to.as_deref(), Some("192.0.2.1"), "the attacked server by its public IPv4 address");
        assert_eq!(r.providers[1].key, "unknown");
        assert_eq!(r.providers[1].name, None);
    }

    #[test]
    fn hostile_reports_are_cut() {
        let lines: Vec<serde_json::Value> = (0..500).map(|i| json!({ "ts": i, "text": format!("line {i}\u{1b}[31m") })).collect();
        let r = report(json!([{ "net": "192.0.2.5", "bans": u64::MAX, "events": u64::MAX, "omitted": u64::MAX, "evidence": lines,
            "org": "x".repeat(5000), "country": "zz", "activity": "a\u{0}b" }]));
        let p = parse(&r, "n\nx").unwrap();
        let s = &p.sources[0];
        assert_eq!((s.evidence.len(), s.omitted), (MAX_LINES, u64::MAX));
        assert!(!s.evidence[0].text.contains('\u{1b}'));
        assert_eq!(s.org.as_ref().unwrap().len(), 100);
        assert_eq!((s.country.as_deref(), s.activity.as_str(), s.nodes[0].as_str()), (None, "ab", "nx"));
        let twice = vec![("0".into(), "a".into(), Ok(p.clone())), ("1".into(), "b".into(), Ok(p))];
        let m = merge("24h", twice, 0);
        assert_eq!(m.providers[0].bans, u64::MAX, "no overflow");
        assert!(parse("busy", "n").is_err() && parse("\"x\"", "n").is_err());
    }
}
