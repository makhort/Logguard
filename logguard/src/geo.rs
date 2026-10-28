//! Offline IP -> country and network owner ("Germany / Hetzner Online GmbH (AS24940)").
//!
//! Everything is looked up in memory from database files downloaded once a week, so no
//! address ever leaves the server. Default source: DB-IP's free "lite" databases
//! (CC BY 4.0, monthly, no account; https://db-ip.com): country per address range
//! (geolocated, not just where the network is registered) and the owning network (ASN
//! and organisation name). iptoasn.com's `ip2asn-*.tsv.gz` (public domain) is accepted
//! as the network database too; it carries registry handles instead of company names.

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::net::Net;
use crate::time::Dur;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoCfg {
    pub enabled: bool,
    /// `{month}` is replaced by the current `YYYY-MM` (the previous month if that isn't out yet).
    /// Empty = don't use that database.
    pub country_url: String,
    pub asn_url: String,
    /// Downloaded databases are kept here (`country.gz`, `asn.gz`) and reused after restarts.
    pub dir: PathBuf,
    pub refresh: Dur,
    /// Download command; the URL is appended and the file is read from its stdout.
    pub fetch: Vec<String>,
    /// Networks the database places in the wrong country, pinned to the right one: e.g.
    /// `"198.51.100.0/24" = "GE"` (an ISO code, or a name like "Georgia"). The most specific
    /// network wins. Places in alerts, bans, accounts' countries and the counters use it;
    /// `[geoblock]` doesn't (its lists come from the database as it is).
    pub places: std::collections::BTreeMap<String, String>,
}

impl GeoCfg {
    pub fn validate(&self) -> Result<()> {
        for (net, country) in &self.places {
            net.parse::<Net>().map_err(|e| anyhow::anyhow!("[geo] places: '{net}': {e}"))?;
            if parse_country(country).is_none() {
                bail!("[geo] places: '{country}' is not a country (an ISO code like \"GE\", or a name like \"Georgia\")");
            }
        }
        Ok(())
    }

    /// `places`, parsed (validated at load), most specific first.
    fn pinned(&self) -> Vec<(Net, [u8; 2])> {
        let mut v: Vec<(Net, [u8; 2])> =
            self.places.iter().filter_map(|(n, c)| Some((n.parse::<Net>().ok()?, parse_country(c)?))).collect();
        v.sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix));
        v
    }
}

impl Default for GeoCfg {
    fn default() -> Self {
        GeoCfg {
            enabled: false,
            country_url: "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz".into(),
            asn_url: "https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz".into(),
            dir: "/var/lib/logguard/geo".into(),
            refresh: Dur(7 * 86_400),
            // a redirect may not leave https
            fetch: ["curl", "-fsSL", "--proto-redir", "=https", "--max-time", "300", "--retry", "2", "--max-filesize", "200000000"]
                .map(String::from)
                .to_vec(),
            places: std::collections::BTreeMap::new(),
        }
    }
}

/// Dropping whole countries or networks (ASNs) by the same databases (`[geoblock]`): their
/// address ranges, from what is loaded already, go into sets of their own in the firewall,
/// next to the blocklist feeds. Lite databases misplace some addresses; this is coarse.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoblockCfg {
    pub enabled: bool,
    /// Countries whose addresses are dropped: ISO codes ("CN") or names as logguard spells
    /// them ("China").
    pub countries: Vec<String>,
    /// Drop every other country's addresses: only these (and addresses the database places
    /// nowhere) can reach the server. Together with `countries`, both apply.
    pub only_countries: Vec<String>,
    /// Networks (AS numbers) whose addresses are dropped, from the network database.
    pub asns: Vec<u32>,
    /// Refuse to load more networks than this (each is a set element in the kernel).
    pub max_entries: usize,
}

impl Default for GeoblockCfg {
    fn default() -> Self {
        GeoblockCfg { enabled: false, countries: vec![], only_countries: vec![], asns: vec![], max_entries: 200_000 }
    }
}

impl GeoblockCfg {
    pub fn validate(&self, geo: &GeoCfg) -> Result<()> {
        for c in self.countries.iter().chain(&self.only_countries) {
            if parse_country(c).is_none() {
                bail!("[geoblock]: '{c}' is not a country (an ISO code like \"CN\", or a name like \"China\")");
            }
        }
        if !self.enabled {
            return Ok(());
        }
        if self.countries.is_empty() && self.only_countries.is_empty() && self.asns.is_empty() {
            bail!("[geoblock] is enabled but lists no countries, only_countries or asns");
        }
        if !geo.enabled {
            bail!("[geoblock] needs the [geo] databases: [geo] enabled = true");
        }
        if (!self.countries.is_empty() || !self.only_countries.is_empty()) && geo.country_url.is_empty() {
            bail!("[geoblock] countries need the [geo] country database (country_url)");
        }
        if !self.asns.is_empty() && geo.asn_url.is_empty() {
            bail!("[geoblock] asns need the [geo] network database (asn_url)");
        }
        if let Some(c) = self.only_countries.iter().find(|c| self.countries.iter().any(|b| parse_country(b) == parse_country(c))) {
            bail!("[geoblock]: '{c}' is both blocked (countries) and the only one let in (only_countries)");
        }
        Ok(())
    }

    fn codes(list: &[String]) -> std::collections::BTreeSet<[u8; 2]> {
        list.iter().filter_map(|c| parse_country(c)).collect()
    }

    /// The ISO codes of `countries` and of `only_countries`, sorted.
    pub fn country_codes(&self) -> (Vec<String>, Vec<String>) {
        let codes = |list: &[String]| Self::codes(list).iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect();
        (codes(&self.countries), codes(&self.only_countries))
    }

    /// "CN, RU; all but UA; 2 networks" for status lines.
    pub fn describe(&self) -> String {
        let show = |set: std::collections::BTreeSet<[u8; 2]>| {
            set.iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(", ")
        };
        let mut parts = Vec::new();
        if !self.countries.is_empty() {
            parts.push(show(Self::codes(&self.countries)));
        }
        if !self.only_countries.is_empty() {
            parts.push(format!("all but {}", show(Self::codes(&self.only_countries))));
        }
        if !self.asns.is_empty() {
            parts.push(format!("{} networks (ASNs)", self.asns.len()));
        }
        parts.join("; ")
    }
}

/// What `[geoblock]` loaded, for status and the dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GeoblockStatus {
    pub computed: crate::time::Micros,
    /// `GeoblockCfg::describe`.
    pub what: String,
    pub v4: usize,
    pub v6: usize,
    /// In the firewall (false in shadow mode, with a backend without it, or on error).
    pub applied: bool,
    pub error: Option<String>,
    /// The blocked countries' ISO codes (`countries`), and those of `only_countries` (every
    /// other country is blocked), for the web console's map. Older daemons leave them out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_countries: Vec<String>,
    /// The blocked networks' AS numbers (`asns`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asns: Vec<u32>,
}

/// An ISO code ("cn", "CN") or a name as `country_name` spells it ("China"), any case.
pub fn parse_country(s: &str) -> Option<[u8; 2]> {
    let s = s.trim();
    COUNTRIES.split('|').find_map(|e| {
        let (code, name) = e.split_once(' ')?;
        (code.len() == 2 && (code.eq_ignore_ascii_case(s) || name.eq_ignore_ascii_case(s)))
            .then(|| [code.as_bytes()[0], code.as_bytes()[1]])
    })
}

/// Sorted, merged intervals (touching ones join).
fn merge_intervals(mut v: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    v.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(v.len());
    for (lo, hi) in v {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// Intervals that come sorted by start (a database's ranges), merged as they come: only the
/// merged ones are kept, not every range (all but one country is most of the database).
fn merge_sorted(sorted: impl Iterator<Item = (u128, u128)>) -> Vec<(u128, u128)> {
    let mut out: Vec<(u128, u128)> = Vec::new();
    for (lo, hi) in sorted {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// `keep` (merged) cut out of `from` (merged).
fn subtract_intervals(from: Vec<(u128, u128)>, keep: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut out = Vec::new();
    let mut k = 0;
    for (mut lo, hi) in from {
        while k < keep.len() && keep[k].1 < lo {
            k += 1;
        }
        let mut j = k;
        while lo <= hi {
            match keep.get(j) {
                Some(&(klo, khi)) if klo <= hi => {
                    if klo > lo {
                        out.push((lo, klo - 1));
                    }
                    match khi.checked_add(1) {
                        Some(next) if khi < hi => lo = next,
                        _ => break,
                    }
                    j += 1;
                }
                _ => {
                    out.push((lo, hi));
                    break;
                }
            }
        }
    }
    out
}

/// A network as an interval of the databases' keys: IPv4 addresses, or IPv6 /64s (a
/// network inside one /64 keeps all of it).
fn key_interval(n: &Net) -> (bool, u128, u128) {
    match n.addr {
        IpAddr::V4(a) => {
            let lo = u32::from(a);
            (false, u128::from(lo), u128::from(lo | u32::MAX.checked_shr(u32::from(n.prefix)).unwrap_or(0)))
        }
        IpAddr::V6(a) => {
            let lo = (u128::from(a) >> 64) as u64;
            (true, u128::from(lo), u128::from(lo | u64::MAX.checked_shr(u32::from(n.prefix.min(64))).unwrap_or(0)))
        }
    }
}

/// What is known about one address.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Geo {
    pub country: Option<[u8; 2]>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

impl Geo {
    pub fn country_name(&self) -> Option<&'static str> {
        self.country.map(|c| country_name(&c))
    }

    /// "Germany / Hetzner Online GmbH (AS24940)", or whichever half is known.
    pub fn label(&self) -> Option<String> {
        let net = match (&self.org, self.asn) {
            (Some(o), Some(n)) => Some(format!("{o} (AS{n})")),
            (None, Some(n)) => Some(format!("AS{n}")),
            (Some(o), None) => Some(o.clone()),
            (None, None) => None,
        };
        match (self.country_name(), net) {
            (Some(c), Some(n)) => Some(format!("{c} / {n}")),
            (Some(c), None) => Some(c.to_string()),
            (None, n) => n,
        }
    }
}

/// Sorted, non-overlapping ranges. IPv6 is kept at /64 granularity (the upper 64 bits),
/// which halves memory; no database distinguishes locations inside a /64.
#[derive(Default)]
struct Ranges<K, V> {
    v: Vec<(K, K, V)>,
}

impl<K: Ord + Copy, V: PartialEq + Copy> Ranges<K, V> {
    fn push(&mut self, start: K, end: K, val: V, adjacent: impl Fn(K, K) -> bool) {
        if let Some(last) = self.v.last_mut() {
            // Neighbouring ranges with the same value merge (e.g. a country's consecutive blocks).
            if last.2 == val && adjacent(last.1, start) {
                last.1 = last.1.max(end);
                return;
            }
        }
        self.v.push((start, end, val));
    }

    fn finish(&mut self) {
        self.v.sort_unstable_by_key(|r| r.0);
        self.v.shrink_to_fit();
    }

    fn get(&self, k: K) -> Option<V> {
        let i = self.v.partition_point(|r| r.0 <= k).checked_sub(1)?;
        let r = self.v[i];
        (k <= r.1).then_some(r.2)
    }

    /// The values of the ranges overlapping `lo..=hi` (ranges don't overlap each other, so
    /// their ends are sorted too).
    fn within(&self, lo: K, hi: K) -> impl Iterator<Item = V> + '_ {
        let i = self.v.partition_point(|r| r.1 < lo);
        self.v[i..].iter().take_while(move |r| r.0 <= hi).map(|r| r.2)
    }
}

/// (country, asn, org index into `orgs`)
type AsVal = ([u8; 2], u32, u32);

#[derive(Default)]
pub struct GeoDb {
    cc4: Ranges<u32, [u8; 2]>,
    cc6: Ranges<u64, [u8; 2]>,
    as4: Ranges<u32, AsVal>,
    as6: Ranges<u64, AsVal>,
    orgs: Vec<String>,
    /// `[geo] places`: networks pinned to a country, most specific first.
    places: Vec<(Net, [u8; 2])>,
    /// e.g. "country: 712345 ranges, network: 498765 ranges"
    pub summary: String,
}

const NO_CC: [u8; 2] = *b"--";
/// Longest organisation name kept (the longest real ones are about 100 characters).
const MAX_ORG_LEN: usize = 120;

fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

enum Key {
    V4(u32, u32),
    V6(u64, u64),
}

fn key(start: &str, end: &str) -> Option<Key> {
    match (start.trim().parse::<IpAddr>().ok()?, end.trim().parse::<IpAddr>().ok()?) {
        (IpAddr::V4(a), IpAddr::V4(b)) => Some(Key::V4(a.into(), b.into())),
        (IpAddr::V6(a), IpAddr::V6(b)) => Some(Key::V6((u128::from(a) >> 64) as u64, (u128::from(b) >> 64) as u64)),
        _ => None,
    }
}

fn cc(s: &str) -> Option<[u8; 2]> {
    let b = s.trim().as_bytes();
    (b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic) && s.trim() != "ZZ")
        .then(|| [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

/// iptoasn descriptions start with the registry handle: "GTELECOM-AS-AP Gtelecom Pty Ltd".
fn tidy_org(desc: &str) -> &str {
    let desc = desc.trim();
    match desc.split_once(' ') {
        Some((handle, rest))
            if !rest.trim().is_empty() && handle.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_') =>
        {
            rest.trim()
        }
        _ => desc,
    }
}

impl GeoDb {
    /// Loads the databases in `[geo] dir` and pins its `places`.
    pub fn open(cfg: &GeoCfg) -> Result<GeoDb> {
        let mut db = GeoDb::load(&cfg.dir)?;
        db.places = cfg.pinned();
        if !db.places.is_empty() {
            db.summary += &format!(", {} networks pinned by [geo] places", db.places.len());
        }
        Ok(db)
    }

    /// Loads whichever of `<dir>/country.gz` and `<dir>/asn.gz` exist.
    pub fn load(dir: &Path) -> Result<GeoDb> {
        let mut db = GeoDb::default();
        let mut parts = Vec::new();
        for (name, is_country) in [("country.gz", true), ("asn.gz", false)] {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            let file = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
            let n = db
                .read(BufReader::new(flate2::read::GzDecoder::new(file)), is_country)
                .with_context(|| format!("reading {}", path.display()))?;
            parts.push(format!("{} {n} ranges", if is_country { "country" } else { "network" }));
        }
        if parts.is_empty() {
            bail!("no geo database in {} yet", dir.display());
        }
        db.summary = parts.join(", ");
        Ok(db)
    }

    /// Reads one database (CSV or iptoasn TSV); returns the number of ranges kept.
    pub fn read(&mut self, r: impl BufRead, is_country: bool) -> Result<usize> {
        self.read_within(r, is_country, MAX_RANGES, MAX_ORGS)
    }

    fn read_within(&mut self, r: impl BufRead, is_country: bool, max_ranges: usize, max_orgs: usize) -> Result<usize> {
        let mut org_ids: std::collections::HashMap<String, u32> =
            self.orgs.iter().enumerate().map(|(i, o)| (o.clone(), i as u32)).collect();
        let mut lines = 0usize;
        let mut too_big = false;
        for_each_line(r, |line| {
            if too_big {
                return;
            }
            let f: Vec<String> = if line.contains('\t') { line.split('\t').map(String::from).collect() } else { split_csv(line) };
            let Some(k) = f.get(1).and_then(|end| key(&f[0], end)) else { return };
            lines += 1;
            if lines > max_ranges || self.orgs.len() > max_orgs {
                too_big = true;
                return;
            }
            if is_country {
                // DB-IP: start,end,CC (iptoasn ip2country: start,end,CC)
                let Some(c) = f.get(2).and_then(|c| cc(c)) else { return };
                match k {
                    Key::V4(a, b) => self.cc4.push(a, b, c, |e, s| e.checked_add(1) == Some(s)),
                    Key::V6(a, b) => self.cc6.push(a, b, c, |e, s| e.checked_add(1) == Some(s)),
                }
            } else {
                // DB-IP: start,end,asn,org; iptoasn: start,end,asn,cc,description
                let Some(asn) = f.get(2).and_then(|n| n.trim().parse::<u32>().ok()).filter(|n| *n > 0) else { return };
                let (country, org) =
                    if f.len() >= 5 { (cc(&f[3]).unwrap_or(NO_CC), tidy_org(&f[4])) } else { (NO_CC, f.get(3).map_or("", |s| s.trim())) };
                // Downloaded text that reaches terminals (TUI), XMPP messages and the digest.
                let org = crate::event::clean(org, MAX_ORG_LEN);
                let org = org.as_str();
                let id = match org_ids.get(org) {
                    Some(id) => *id,
                    None => {
                        let id = self.orgs.len() as u32;
                        self.orgs.push(org.to_string());
                        org_ids.insert(org.to_string(), id);
                        id
                    }
                };
                let v = (country, asn, id);
                match k {
                    Key::V4(a, b) => self.as4.push(a, b, v, |e, s| e.checked_add(1) == Some(s)),
                    Key::V6(a, b) => self.as6.push(a, b, v, |e, s| e.checked_add(1) == Some(s)),
                }
            }
        })?;
        if too_big {
            bail!("more than {max_ranges} ranges or {max_orgs} network names: not a geo database (it would not fit in memory)");
        }
        if lines == 0 {
            bail!("no address ranges found (not a DB-IP CSV or iptoasn TSV file?)");
        }
        self.orgs.shrink_to_fit();
        let n = if is_country {
            self.cc4.finish();
            self.cc6.finish();
            self.cc4.v.len() + self.cc6.v.len()
        } else {
            self.as4.finish();
            self.as6.finish();
            self.as4.v.len() + self.as6.v.len()
        };
        Ok(n)
    }

    pub fn lookup(&self, ip: IpAddr) -> Geo {
        let (country, net) = match ip {
            IpAddr::V4(a) => {
                let k = u32::from(a);
                (self.cc4.get(k), self.as4.get(k))
            }
            IpAddr::V6(a) => {
                let k = (u128::from(a) >> 64) as u64;
                (self.cc6.get(k), self.as6.get(k))
            }
        };
        // A pinned network first; then the geolocated country; the network's registration
        // country is a fallback.
        let pinned = self.places.iter().find(|(n, _)| n.contains(ip)).map(|(_, c)| *c);
        let country = pinned.or(country).or(net.map(|n| n.0).filter(|c| *c != NO_CC));
        Geo { country, asn: net.map(|n| n.1), org: net.and_then(|n| self.orgs.get(n.2 as usize)).filter(|o| !o.is_empty()).cloned() }
    }

    pub fn label(&self, ip: IpAddr) -> Option<String> {
        self.lookup(ip).label()
    }

    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let k = match ip {
            IpAddr::V4(a) => self.as4.get(u32::from(a)),
            IpAddr::V6(a) => self.as6.get((u128::from(a) >> 64) as u64),
        };
        k.map(|v| v.1)
    }

    /// The networks (as CIDRs) the network database gives these ASNs.
    pub fn networks_of(&self, asns: &std::collections::BTreeSet<u32>) -> Vec<Net> {
        let mut out = Vec::new();
        for (lo, hi, v) in &self.as4.v {
            if asns.contains(&v.1) {
                for (a, p) in cidrs(u128::from(*lo), u128::from(*hi), 32) {
                    out.push(Net::new(IpAddr::V4((a as u32).into()), p));
                }
            }
        }
        for (lo, hi, v) in &self.as6.v {
            if asns.contains(&v.1) {
                // kept per /64: the upper 64 bits
                for (a, p) in cidrs(u128::from(*lo), u128::from(*hi), 64) {
                    out.push(Net::new(IpAddr::V6((a << 64).into()), p));
                }
            }
        }
        out
    }

    /// The networks `[geoblock]` drops: the country ranges of `countries` (with
    /// `only_countries`, of every other country) and the network ranges of `asns`, merged,
    /// less `keep` (allowlisted networks, this host, the cluster peers) and special-purpose
    /// ranges, cut out exactly; as few CIDRs as cover the rest.
    pub fn blocked_networks(&self, cfg: &GeoblockCfg, keep: &[Net]) -> Vec<Net> {
        let (block, only) = (GeoblockCfg::codes(&cfg.countries), GeoblockCfg::codes(&cfg.only_countries));
        let blocked = |c: &[u8; 2]| block.contains(c) || (!only.is_empty() && !only.contains(c));
        let asns: std::collections::BTreeSet<u32> = cfg.asns.iter().copied().collect();
        let bogons: Vec<Net> = crate::feeds::BOGONS.iter().map(|b| b.parse().expect("valid bogon")).collect();
        let mut out = Vec::new();
        for v6 in [false, true] {
            // each database's ranges are sorted and apart: merged while read, then together
            let (countries, networks) = if v6 {
                (
                    merge_sorted(self.cc6.v.iter().filter(|r| blocked(&r.2)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                    merge_sorted(self.as6.v.iter().filter(|r| asns.contains(&r.2 .1)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                )
            } else {
                (
                    merge_sorted(self.cc4.v.iter().filter(|r| blocked(&r.2)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                    merge_sorted(self.as4.v.iter().filter(|r| asns.contains(&r.2 .1)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                )
            };
            let ranges = if networks.is_empty() { countries } else { merge_intervals([countries, networks].concat()) };
            let holes: Vec<(u128, u128)> =
                keep.iter().chain(&bogons).map(key_interval).filter(|(is6, ..)| *is6 == v6).map(|(_, lo, hi)| (lo, hi)).collect();
            for (lo, hi) in subtract_intervals(ranges, &merge_intervals(holes)) {
                if v6 {
                    out.extend(cidrs(lo, hi, 64).into_iter().map(|(a, p)| Net::new(IpAddr::V6((a << 64).into()), p)));
                } else {
                    out.extend(cidrs(lo, hi, 32).into_iter().map(|(a, p)| Net::new(IpAddr::V4((a as u32).into()), p)));
                }
            }
        }
        out
    }

    /// Whether the addresses of `net` the network database knows all belong to one network
    /// (ASN): a ban on it then can't reach another provider's customers. True without that
    /// database.
    pub fn one_network(&self, net: &Net) -> bool {
        fn same(mut asns: impl Iterator<Item = u32>) -> bool {
            let first = asns.next();
            asns.all(|a| Some(a) == first)
        }
        match net.addr {
            IpAddr::V4(a) => {
                let lo = u32::from(a);
                same(self.as4.within(lo, lo | u32::MAX.checked_shr(u32::from(net.prefix)).unwrap_or(0)).map(|v| v.1))
            }
            IpAddr::V6(a) => {
                let lo = (u128::from(a) >> 64) as u64;
                same(self.as6.within(lo, lo | u64::MAX.checked_shr(u32::from(net.prefix)).unwrap_or(0)).map(|v| v.1))
            }
        }
    }
}

/// The CIDR blocks covering `lo..=hi` in a `bits`-bit address space: (start, prefix length).
fn cidrs(mut lo: u128, hi: u128, bits: u32) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    while lo <= hi {
        let align = if lo == 0 { bits } else { lo.trailing_zeros().min(bits) };
        let span = hi - lo + 1;
        let fits = 127 - span.leading_zeros().min(127); // floor(log2(span)), span >= 1
        let size = align.min(fits);
        out.push((lo, (bits - size) as u8));
        match lo.checked_add(1u128 << size) {
            Some(next) => lo = next,
            None => break,
        }
    }
    out
}

/// Database lines are short and DB-IP's files have ~1-2 million of them: anything far
/// beyond is a broken or hostile download, which must not exhaust the service's memory.
const MAX_LINE: usize = 4096;
const MAX_LINES: usize = 10_000_000;
/// What is kept of one database is bounded too, within the service's memory limit: DB-IP's
/// lite databases hold about 0.5-0.7 million ranges each, and ~80,000 network names.
const MAX_RANGES: usize = 2_000_000;
const MAX_ORGS: usize = 300_000;

/// Calls `f` for each line, bounded in line length and count.
fn for_each_line(mut r: impl BufRead, mut f: impl FnMut(&str)) -> Result<()> {
    let mut buf = Vec::new();
    for _ in 0..MAX_LINES {
        buf.clear();
        let n = std::io::Read::take(&mut r, MAX_LINE as u64 + 1).read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_LINE && buf.last() != Some(&b'\n') {
            bail!("line longer than {MAX_LINE} bytes: not a geo database");
        }
        f(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']));
    }
    bail!("more than {MAX_LINES} lines: not a geo database")
}

/// Number of usable ranges in a database, as `GeoDb::read` would load them; an error for
/// one too big to load (more than `max_ranges` ranges or `max_orgs` network names).
fn count_ranges(r: impl BufRead, is_country: bool) -> Result<usize> {
    count_ranges_within(r, is_country, MAX_RANGES, MAX_ORGS)
}

fn count_ranges_within(r: impl BufRead, is_country: bool, max_ranges: usize, max_orgs: usize) -> Result<usize> {
    use std::hash::{Hash, Hasher};
    let mut n = 0;
    // names by hash: a few MB at most, and nothing kept of a hostile file's text
    let mut orgs = std::collections::HashSet::new();
    for_each_line(r, |line| {
        let f: Vec<String> = if line.contains('\t') { line.split('\t').map(String::from).collect() } else { split_csv(line) };
        let ok = f.get(1).and_then(|end| key(&f[0], end)).is_some()
            && if is_country {
                f.get(2).and_then(|c| cc(c)).is_some()
            } else {
                f.get(2).and_then(|a| a.trim().parse::<u32>().ok()).is_some_and(|a| a > 0)
            };
        if ok && !is_country && orgs.len() <= max_orgs {
            let org = if f.len() >= 5 { tidy_org(&f[4]) } else { f.get(3).map_or("", |s| s.trim()) };
            let mut h = std::collections::hash_map::DefaultHasher::new();
            org.hash(&mut h);
            orgs.insert(h.finish());
        }
        n += usize::from(ok);
    })?;
    if n > max_ranges || orgs.len() > max_orgs {
        bail!(
            "{n} ranges and {} network names, more than {max_ranges} and {max_orgs}: not a geo database (it would not fit in memory)",
            orgs.len()
        );
    }
    Ok(n)
}

/// Current and previous `YYYY-MM` (UTC).
fn months(now: crate::time::Micros) -> [String; 2] {
    let (y, m, _) = crate::time::civil_from_days(now.div_euclid(86_400 * crate::time::SEC));
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")]
}

/// Largest compressed database accepted (DB-IP's are ~5-10 MB).
const MAX_DOWNLOAD: u64 = 200 << 20;

/// Downloads the databases that are missing or older than `refresh`. Each download is
/// checked (it must decompress and parse) before it replaces the previous copy.
/// Returns what was downloaded, and the problems met.
pub fn refresh(cfg: &GeoCfg, now: crate::time::Micros) -> (Vec<String>, Vec<String>) {
    let (mut done, mut errors) = (Vec::new(), Vec::new());
    let _ = std::fs::create_dir_all(&cfg.dir);
    for (url, name, is_country) in [(&cfg.country_url, "country.gz", true), (&cfg.asn_url, "asn.gz", false)] {
        if url.is_empty() {
            let _ = std::fs::remove_file(cfg.dir.join(name));
            continue;
        }
        let path = cfg.dir.join(name);
        let age = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a.as_secs() < cfg.refresh.0) {
            continue;
        }
        let mut last_err = None;
        for month in months(now) {
            let u = url.replace("{month}", &month);
            // Streamed to a file and validated from there while decompressing: neither the
            // download nor a second database is ever held in memory (MemoryMax=128M).
            let tmp = path.with_extension("tmp");
            let result = (|| -> Result<usize> {
                let mut file = std::fs::File::create(&tmp)?;
                crate::feeds::fetch_into(&cfg.fetch, &u, &mut file, MAX_DOWNLOAD)?;
                file.sync_all()?;
                let gz = flate2::read::GzDecoder::new(std::fs::File::open(&tmp)?);
                let n = count_ranges(BufReader::new(gz), is_country).context("checking the download")?;
                if n < 1000 {
                    bail!("only {n} ranges");
                }
                std::fs::rename(&tmp, &path)?;
                Ok(n)
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            match result {
                Ok(n) => {
                    done.push(format!("{u} ({n} ranges)"));
                    last_err = None;
                    break;
                }
                Err(e) => last_err = Some(format!("{u}: {e:#}")),
            }
            if !url.contains("{month}") {
                break;
            }
        }
        errors.extend(last_err);
    }
    (done, errors)
}

/// Credit line required by DB-IP's CC BY 4.0 licence, for texts that show its data.
pub fn attribution(cfg: &GeoCfg, loaded: bool) -> String {
    let dbip = [&cfg.country_url, &cfg.asn_url].iter().any(|u| u.contains("db-ip.com"));
    if loaded && dbip {
        "\nIP locations: DB-IP.com (CC BY 4.0)\n".into()
    } else {
        String::new()
    }
}

/// English short names of ISO 3166-1 alpha-2 codes.
pub fn country_name(code: &[u8; 2]) -> &'static str {
    let code = std::str::from_utf8(code).unwrap_or("??");
    COUNTRIES.split('|').find_map(|e| e.strip_prefix(code).and_then(|n| n.strip_prefix(' '))).unwrap_or(match code {
        "EU" => "European Union",
        "AP" => "Asia/Pacific",
        _ => "unknown country",
    })
}

/// The code of a country as `country_name` spells it ("Germany" -> DE).
pub fn country_code(name: &str) -> Option<[u8; 2]> {
    COUNTRIES.split('|').find_map(|e| {
        let (code, n) = e.split_once(' ')?;
        (n == name && code.len() == 2).then(|| [code.as_bytes()[0], code.as_bytes()[1]])
    })
}

const COUNTRIES: &str = "AD Andorra|AE United Arab Emirates|AF Afghanistan|AG Antigua and Barbuda|AI Anguilla|AL Albania|AM Armenia|\
AO Angola|AQ Antarctica|AR Argentina|AS American Samoa|AT Austria|AU Australia|AW Aruba|AX Åland Islands|AZ Azerbaijan|\
BA Bosnia and Herzegovina|BB Barbados|BD Bangladesh|BE Belgium|BF Burkina Faso|BG Bulgaria|BH Bahrain|BI Burundi|BJ Benin|\
BL Saint Barthélemy|BM Bermuda|BN Brunei|BO Bolivia|BQ Caribbean Netherlands|BR Brazil|BS Bahamas|BT Bhutan|BV Bouvet Island|\
BW Botswana|BY Belarus|BZ Belize|CA Canada|CC Cocos Islands|CD DR Congo|CF Central African Republic|CG Congo|CH Switzerland|\
CI Côte d'Ivoire|CK Cook Islands|CL Chile|CM Cameroon|CN China|CO Colombia|CR Costa Rica|CU Cuba|CV Cape Verde|CW Curaçao|\
CX Christmas Island|CY Cyprus|CZ Czechia|DE Germany|DJ Djibouti|DK Denmark|DM Dominica|DO Dominican Republic|DZ Algeria|\
EC Ecuador|EE Estonia|EG Egypt|EH Western Sahara|ER Eritrea|ES Spain|ET Ethiopia|FI Finland|FJ Fiji|FK Falkland Islands|\
FM Micronesia|FO Faroe Islands|FR France|GA Gabon|GB United Kingdom|GD Grenada|GE Georgia|GF French Guiana|GG Guernsey|GH Ghana|\
GI Gibraltar|GL Greenland|GM Gambia|GN Guinea|GP Guadeloupe|GQ Equatorial Guinea|GR Greece|GS South Georgia|GT Guatemala|GU Guam|\
GW Guinea-Bissau|GY Guyana|HK Hong Kong|HM Heard and McDonald Islands|HN Honduras|HR Croatia|HT Haiti|HU Hungary|ID Indonesia|\
IE Ireland|IL Israel|IM Isle of Man|IN India|IO British Indian Ocean Territory|IQ Iraq|IR Iran|IS Iceland|IT Italy|JE Jersey|\
JM Jamaica|JO Jordan|JP Japan|KE Kenya|KG Kyrgyzstan|KH Cambodia|KI Kiribati|KM Comoros|KN Saint Kitts and Nevis|KP North Korea|\
KR South Korea|KW Kuwait|KY Cayman Islands|KZ Kazakhstan|LA Laos|LB Lebanon|LC Saint Lucia|LI Liechtenstein|LK Sri Lanka|\
LR Liberia|LS Lesotho|LT Lithuania|LU Luxembourg|LV Latvia|LY Libya|MA Morocco|MC Monaco|MD Moldova|ME Montenegro|\
MF Saint Martin|MG Madagascar|MH Marshall Islands|MK North Macedonia|ML Mali|MM Myanmar|MN Mongolia|MO Macao|\
MP Northern Mariana Islands|MQ Martinique|MR Mauritania|MS Montserrat|MT Malta|MU Mauritius|MV Maldives|MW Malawi|MX Mexico|\
MY Malaysia|MZ Mozambique|NA Namibia|NC New Caledonia|NE Niger|NF Norfolk Island|NG Nigeria|NI Nicaragua|NL Netherlands|\
NO Norway|NP Nepal|NR Nauru|NU Niue|NZ New Zealand|OM Oman|PA Panama|PE Peru|PF French Polynesia|PG Papua New Guinea|\
PH Philippines|PK Pakistan|PL Poland|PM Saint Pierre and Miquelon|PN Pitcairn|PR Puerto Rico|PS Palestine|PT Portugal|PW Palau|\
PY Paraguay|QA Qatar|RE Réunion|RO Romania|RS Serbia|RU Russia|RW Rwanda|SA Saudi Arabia|SB Solomon Islands|SC Seychelles|\
SD Sudan|SE Sweden|SG Singapore|SH Saint Helena|SI Slovenia|SJ Svalbard and Jan Mayen|SK Slovakia|SL Sierra Leone|SM San Marino|\
SN Senegal|SO Somalia|SR Suriname|SS South Sudan|ST São Tomé and Príncipe|SV El Salvador|SX Sint Maarten|SY Syria|SZ Eswatini|\
TC Turks and Caicos Islands|TD Chad|TF French Southern Territories|TG Togo|TH Thailand|TJ Tajikistan|TK Tokelau|TL Timor-Leste|\
TM Turkmenistan|TN Tunisia|TO Tonga|TR Türkiye|TT Trinidad and Tobago|TV Tuvalu|TW Taiwan|TZ Tanzania|UA Ukraine|UG Uganda|\
UM US Minor Outlying Islands|US United States|UY Uruguay|UZ Uzbekistan|VA Vatican City|VC Saint Vincent and the Grenadines|\
VE Venezuela|VG British Virgin Islands|VI US Virgin Islands|VN Vietnam|VU Vanuatu|WF Wallis and Futuna|WS Samoa|XK Kosovo|\
YE Yemen|YT Mayotte|ZA South Africa|ZM Zambia|ZW Zimbabwe";

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn ranges_as_cidrs() {
        let c = |lo: u128, hi: u128, bits| super::cidrs(lo, hi, bits);
        assert_eq!(c(0, u128::from(u32::MAX), 32), vec![(0, 0)]);
        // 10.0.0.0 - 10.0.2.255: a /23 and a /24
        let ten = 10u128 << 24;
        assert_eq!(c(ten, ten + 767, 32), vec![(ten, 23), (ten + 512, 24)]);
        assert_eq!(c(5, 5, 32), vec![(5, 32)]);
        assert_eq!(c(1, 6, 32), vec![(1, 32), (2, 31), (4, 31), (6, 32)]);
        assert_eq!(c(u128::from(u64::MAX) - 1, u128::from(u64::MAX), 64), vec![(u128::from(u64::MAX) - 1, 63)]);
    }

    use super::*;

    #[test]
    fn hostile_files_are_rejected() {
        let long = format!("1.0.0.0,1.0.0.255,{}\n", "A".repeat(10_000));
        assert!(count_ranges(long.as_bytes(), true).unwrap_err().to_string().contains("line longer"));
        let ok = "1.0.0.0,1.0.0.255,AU\r\n1.0.1.0,1.0.1.255,CN\n";
        assert_eq!(count_ranges(ok.as_bytes(), true).unwrap(), 2);
        // more ranges or network names than fit in memory: refused when downloaded and when loaded
        let asn: String = (0..20u32).map(|i| format!("1.0.{i}.0,1.0.{i}.255,{},\"Org {i}\"\n", 64500 + i)).collect();
        assert_eq!(count_ranges_within(asn.as_bytes(), false, 20, 20).unwrap(), 20);
        assert!(count_ranges_within(asn.as_bytes(), false, 19, 20).unwrap_err().to_string().contains("not fit in memory"));
        assert!(count_ranges_within(asn.as_bytes(), false, 20, 19).unwrap_err().to_string().contains("not fit in memory"));
        assert!(GeoDb::default().read_within(asn.as_bytes(), false, 19, 20).is_err());
        assert!(GeoDb::default().read_within(asn.as_bytes(), false, 20, 10).is_err());
        assert!(GeoDb::default().read_within(asn.as_bytes(), false, 20, 20).is_ok());
    }

    pub(crate) fn sample() -> GeoDb {
        let mut db = GeoDb::default();
        let country = "0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n5.9.0.0,5.9.127.255,DE\n5.9.128.0,5.9.255.255,DE\n\
                       11.41.0.0,11.41.255.255,FI\n3fff:130::,3fff:130:ffff:ffff:ffff:ffff:ffff:ffff,DE\n";
        let asn = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n5.9.0.0,5.9.255.255,24940,\"Hetzner Online GmbH\"\n\
                   11.41.0.0,11.41.255.255,24940,\"Hetzner Online GmbH\"\n3fff:130::,3fff:130:ffff:ffff:ffff:ffff:ffff:ffff,24940,\"Hetzner Online GmbH\"\n";
        assert_eq!(db.read(country.as_bytes(), true).unwrap(), 4, "ZZ dropped, adjacent DE blocks merged");
        assert_eq!(db.read(asn.as_bytes(), false).unwrap(), 4);
        db
    }

    #[test]
    fn lookups_and_labels() {
        let db = sample();
        let l = |ip: &str| db.label(ip.parse().unwrap());
        assert_eq!(l("5.9.200.1").as_deref(), Some("Germany / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("11.41.3.4").as_deref(), Some("Finland / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("1.0.0.1").as_deref(), Some("Australia / Cloudflare, Inc. (AS13335)"));
        assert_eq!(l("3fff:130:1:2::3").as_deref(), Some("Germany / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("1.0.1.1"), None);
        assert_eq!(l("0.1.2.3"), None);
        assert_eq!(db.asn("11.41.3.4".parse().unwrap()), Some(24940));
    }

    #[test]
    fn places_pin_misplaced_networks() {
        let cfg = GeoCfg {
            places: [("5.9.0.0/16", "GE"), ("5.9.1.0/24", "Armenia"), ("3fff:130:1::/48", "ge")]
                .map(|(n, c)| (n.to_string(), c.to_string()))
                .into(),
            ..Default::default()
        };
        cfg.validate().unwrap();
        let mut db = sample();
        db.places = cfg.pinned();
        let l = |ip: &str| db.label(ip.parse().unwrap());
        assert_eq!(l("5.9.200.1").as_deref(), Some("Georgia / Hetzner Online GmbH (AS24940)"), "the owner stays");
        assert_eq!(l("5.9.1.7").as_deref(), Some("Armenia / Hetzner Online GmbH (AS24940)"), "the most specific wins");
        assert_eq!(l("3fff:130:1:2::3").as_deref(), Some("Georgia / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("11.41.3.4").as_deref(), Some("Finland / Hetzner Online GmbH (AS24940)"), "others as the database says");
        assert_eq!(l("1.0.1.1"), None);

        let bad = |n: &str, c: &str| GeoCfg { places: [(n.to_string(), c.to_string())].into(), ..Default::default() }.validate();
        assert!(bad("5.9.0.0/16", "Atlantis").unwrap_err().to_string().contains("not a country"));
        assert!(bad("5.9.0.0/33", "GE").is_err());
        assert!(bad("example.org", "GE").is_err());
    }

    #[test]
    fn one_network() {
        let mut db = GeoDb::default();
        let asn = "11.20.56.0,11.20.57.255,64501,\"Other\"\n11.20.58.0,11.20.59.127,64500,\"Provider\"\n\
                   11.20.59.128,11.20.63.255,64500,\"Provider (DE)\"\n3fff:130::,3fff:130:0:ffff:ffff:ffff:ffff:ffff,24940,\"H\"\n\
                   3fff:130:1::,3fff:130:1:ffff:ffff:ffff:ffff:ffff,64502,\"V\"\n";
        db.read(asn.as_bytes(), false).unwrap();
        let one = |n: &str| db.one_network(&n.parse().unwrap());
        assert!(one("11.20.58.0/23") && one("11.20.60.0/22"), "one ASN over several ranges");
        assert!(!one("11.20.56.0/22") && !one("11.20.0.0/16"), "two providers");
        assert!(one("11.20.57.7") && one("11.21.0.0/16"), "unknown addresses don't count");
        assert!(one("3fff:130::/48") && one("3fff:130:0:5::/64") && !one("3fff:130::/47"));
        assert!(GeoDb::default().one_network(&"11.20.0.0/16".parse().unwrap()), "no network database");
    }

    #[test]
    fn networks_of_asns() {
        let db = sample();
        let nets: Vec<String> = db.networks_of(&[24940].into_iter().collect()).iter().map(|n| n.to_string()).collect();
        assert_eq!(nets, ["5.9.0.0/16", "11.41.0.0/16", "3fff:130::/32"]);
        assert!(db.networks_of(&[64999].into_iter().collect()).is_empty());
    }

    #[test]
    fn org_names_are_cleaned() {
        let mut db = GeoDb::default();
        let asn =
            format!("1.0.0.0,1.0.0.255,13335,\"Evil\x1b]0;pwned\x07 Corp\u{9b}31m\"\n2.0.0.0,2.0.0.255,64500,\"{}\"\n", "x".repeat(500));
        db.read(asn.as_bytes(), false).unwrap();
        assert_eq!(db.label("1.0.0.1".parse().unwrap()).as_deref(), Some("Evil]0;pwned Corp31m (AS13335)"));
        let long = db.lookup("2.0.0.1".parse().unwrap()).org.unwrap();
        assert_eq!(long.chars().count(), MAX_ORG_LEN + 1, "capped, with an ellipsis");
    }

    #[test]
    fn iptoasn_format() {
        let mut db = GeoDb::default();
        let tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
                   1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd\n";
        assert_eq!(db.read(tsv.as_bytes(), false).unwrap(), 2, "unrouted ranges skipped");
        let g = db.lookup("1.0.5.5".parse().unwrap());
        assert_eq!(g.label().as_deref(), Some("Australia / Gtelecom Pty Ltd (AS38803)"), "registration country as fallback");
        assert_eq!(db.label("1.0.0.9".parse().unwrap()).as_deref(), Some("United States / CLOUDFLARENET (AS13335)"));
        assert!(db.read("garbage\n".as_bytes(), true).is_err());
        assert_eq!(count_ranges(tsv.as_bytes(), false).unwrap(), 2);
        assert_eq!(count_ranges("1.0.0.0,1.0.0.255,AU\nx,y,z\n".as_bytes(), true).unwrap(), 1);
    }

    #[test]
    fn helpers() {
        assert_eq!(
            split_csv(r#"1.0.0.0,1.0.0.255,13335,"Cloudflare, ""Inc."""#),
            vec!["1.0.0.0", "1.0.0.255", "13335", "Cloudflare, \"Inc.\""]
        );
        assert_eq!(country_name(b"DE"), "Germany");
        assert_eq!(country_name(b"ZW"), "Zimbabwe");
        assert_eq!(country_name(b"AD"), "Andorra");
        assert_eq!(country_name(b"QQ"), "unknown country");
        // 2026-01-15: current and previous month
        assert_eq!(months(20_468 * 86_400 * crate::time::SEC), ["2026-01".to_string(), "2025-12".to_string()]);
    }

    #[test]
    fn countries_by_code_or_name() {
        assert_eq!(parse_country("CN"), Some(*b"CN"));
        assert_eq!(parse_country(" cn "), Some(*b"CN"));
        assert_eq!(parse_country("china"), Some(*b"CN"));
        assert_eq!(parse_country("Côte d'Ivoire"), Some(*b"CI"));
        assert_eq!(parse_country("XX"), None);
        assert_eq!(parse_country("Chin"), None);
    }

    #[test]
    fn intervals() {
        assert_eq!(merge_intervals(vec![(5, 9), (1, 3), (4, 4), (12, 20), (15, 16)]), [(1, 9), (12, 20)], "touching ones join");
        assert_eq!(subtract_intervals(vec![(1, 20)], &[(5, 6), (10, 10), (20, 30)]), [(1, 4), (7, 9), (11, 19)]);
        assert_eq!(subtract_intervals(vec![(1, 4), (8, 9)], &[(0, 100)]), []);
        assert_eq!(subtract_intervals(vec![(1, 4), (8, 9)], &[(5, 7)]), [(1, 4), (8, 9)]);
        assert_eq!(subtract_intervals(vec![(0, u128::MAX)], &[(u128::MAX, u128::MAX)]), [(0, u128::MAX - 1)]);
    }

    #[test]
    fn geoblock_networks() {
        let mut db = GeoDb::default();
        let country = "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n1.0.4.0,1.0.7.255,CN\n1.0.8.0,1.0.15.255,CN\n\
                       1.0.16.0,1.0.16.255,JP\n10.0.0.0,10.255.255.255,CN\n\
                       3fff:110::,3fff:110:ffff:ffff:ffff:ffff:ffff:ffff,CN\n3fff:100::,3fff:100:ffff:ffff:ffff:ffff:ffff:ffff,JP\n";
        let asn = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n1.0.16.0,1.0.16.255,2497,\"IIJ\"\n";
        db.read(country.as_bytes(), true).unwrap();
        db.read(asn.as_bytes(), false).unwrap();
        let cfg = |countries: &[&str], only: &[&str], asns: &[u32]| GeoblockCfg {
            enabled: true,
            countries: countries.iter().map(|c| c.to_string()).collect(),
            only_countries: only.iter().map(|c| c.to_string()).collect(),
            asns: asns.to_vec(),
            ..Default::default()
        };
        let names = |nets: Vec<Net>| nets.iter().map(Net::to_string).collect::<Vec<_>>();
        // CN's three adjacent ranges as few CIDRs; 10/8 is private and never blocked; IPv6 per /64
        assert_eq!(
            names(db.blocked_networks(&cfg(&["China"], &[], &[]), &[])),
            ["1.0.1.0/24", "1.0.2.0/23", "1.0.4.0/22", "1.0.8.0/21", "3fff:110::/32"]
        );
        // a protected address inside is cut out exactly, not the whole block
        let kept = db.blocked_networks(&cfg(&["CN"], &[], &[]), &["1.0.2.5".parse().unwrap(), "3fff:110:0:7::1".parse().unwrap()]);
        assert!(kept.iter().all(|n| !n.contains("1.0.2.5".parse().unwrap())), "{kept:?}");
        for still in ["1.0.2.4", "1.0.2.6", "1.0.1.1", "1.0.15.255"] {
            assert!(kept.iter().any(|n| n.contains(still.parse().unwrap())), "{still}: {kept:?}");
        }
        assert!(kept.iter().all(|n| !n.contains("3fff:110:0:7::abcd".parse().unwrap())), "its whole /64 is kept");
        assert!(kept.iter().any(|n| n.contains("3fff:110:0:8::1".parse().unwrap())));
        // all but AU: CN and JP, and the ranges in between merge into larger blocks
        assert_eq!(
            names(db.blocked_networks(&cfg(&[], &["AU"], &[]), &[])),
            ["1.0.1.0/24", "1.0.2.0/23", "1.0.4.0/22", "1.0.8.0/21", "1.0.16.0/24", "3fff:100::/32", "3fff:110::/32"]
        );
        // networks by ASN, together with countries
        assert_eq!(names(db.blocked_networks(&cfg(&[], &[], &[13335]), &[])), ["1.0.0.0/24"]);
        assert_eq!(names(db.blocked_networks(&cfg(&["JP"], &[], &[13335]), &[])), ["1.0.0.0/24", "1.0.16.0/24", "3fff:100::/32"]);
        assert!(db.blocked_networks(&cfg(&[], &[], &[64999]), &[]).is_empty());
        assert_eq!(cfg(&["China", "ru"], &["UA"], &[1, 2]).describe(), "CN, RU; all but UA; 2 networks (ASNs)");
        // for the web console's map: codes, whatever the spelling
        assert_eq!(
            cfg(&["ru", "China", "CN"], &["Ukraine"], &[]).country_codes(),
            (vec!["CN".to_string(), "RU".into()], vec!["UA".to_string()])
        );
    }

    #[test]
    fn geoblock_config() {
        let geo = GeoCfg { enabled: true, ..Default::default() };
        let c = |toml: &str| toml::from_str::<GeoblockCfg>(toml).unwrap();
        assert!(c("enabled = true\ncountries = [\"CN\", \"Russia\"]").validate(&geo).is_ok());
        assert!(c("countries = [\"Narnia\"]").validate(&geo).unwrap_err().to_string().contains("Narnia"), "checked even while disabled");
        assert!(c("enabled = true").validate(&geo).is_err(), "nothing listed");
        assert!(c("enabled = true\nasns = [13335]").validate(&GeoCfg::default()).is_err(), "[geo] off");
        assert!(c("enabled = true\nasns = [13335]").validate(&GeoCfg { asn_url: String::new(), ..geo.clone() }).is_err());
        assert!(c("enabled = true\ncountries = [\"CN\"]\nonly_countries = [\"china\"]").validate(&geo).is_err(), "both");
        assert_eq!(GeoblockCfg::default().max_entries, 200_000);
    }

    /// Sizes on the real databases (`LOGGUARD_GEO_DIR=<dir with country.gz, asn.gz>
    /// cargo test --release real_geoblock_sizes -- --ignored --nocapture`). With `LOAD_ONLY=1`
    /// it stops after loading: the peak memory of both runs (`/usr/bin/time -l` on the test
    /// binary) tells the computation's share from the database's.
    #[test]
    #[ignore]
    fn real_geoblock_sizes() {
        let dir = std::env::var("LOGGUARD_GEO_DIR").expect("LOGGUARD_GEO_DIR");
        let db = GeoDb::load(Path::new(&dir)).unwrap();
        println!("{}", db.summary);
        if std::env::var_os("LOAD_ONLY").is_some() {
            return;
        }
        let cases: [(&[&str], &[&str], &[u32]); 6] = [
            (&["CN"], &[], &[]),
            (&["RU"], &[], &[]),
            (&["US"], &[], &[]),
            (&["CN", "RU", "IR", "KP"], &[], &[]),
            (&[], &["UA"], &[]),
            (&[], &[], &[13335, 16509]),
        ];
        for (countries, only, asns) in cases {
            let cfg = GeoblockCfg {
                enabled: true,
                countries: countries.iter().map(|c| c.to_string()).collect(),
                only_countries: only.iter().map(|c| c.to_string()).collect(),
                asns: asns.to_vec(),
                ..Default::default()
            };
            let start = std::time::Instant::now();
            let nets = db.blocked_networks(&cfg, &[]);
            let v4 = nets.iter().filter(|n| n.is_v4()).count();
            println!("{:<40} {v4:>7} IPv4 + {:>6} IPv6 networks in {:?}", cfg.describe(), nets.len() - v4, start.elapsed());
        }
    }
}
