//! Behaviour-based detection.
//!
//! Every remote address carries two exponentially decaying scores: a *fast*
//! one (minutes) that catches bursts and a *slow* one (hours) that catches
//! low-and-slow probing. Events add configurable weights; crossing either
//! threshold bans the address unless it is allowlisted or recently
//! authenticated, in which case an alert is raised instead. A periodic pass
//! aggregates bad addresses into subnet bans, and per-account tracking spots
//! distributed password guessing and logins from unusual networks.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cluster::{ClusterCfg, Fact, FactBody};
use crate::config::{Config, Mode};
use crate::event::{Event, Signal};
use crate::exposure::{ExposureReport, Firewall, ListenerKey};
use crate::i18n::UserNotice;
use crate::net::Net;
use crate::record::Source;
use crate::time::{fmt_ts, Micros, MIN};

const RECENT_ACTIONS: usize = 500;
const PERSISTED_ACTIONS: usize = 100;
/// Alerts are kept apart from `recent` too, so a flood of bans can't push them out.
const RECENT_ALERTS: usize = 50;
const MAX_DIGEST_POINTS: usize = 50_000;
const EVIDENCE_PER_IP: usize = 8;
const HISTORY_MINUTES: usize = 180;
/// Hourly figures kept for the web console's longer charts: 7 days (since the start).
const HISTORY_HOURS: usize = 7 * 24;
/// Accounts tracked for failed logins (names are attacker-chosen) and known to log in.
const MAX_ACCOUNTS: usize = 50_000;
/// Addresses remembered per attacked account: enough to see a distributed attack, bounded
/// so a large botnet can't make every failure scan a huge list.
const MAX_ACCOUNT_IPS: usize = 1000;
/// Alert rate-limit entries kept besides the system ones (see `Engine::gc`).
const MAX_ALERT_GATE: usize = 50_000;
/// Integrity alerts about one local user's own files and processes sent per hour (see
/// `Engine::findings`).
const USER_ALERTS_PER_HOUR: usize = 5;
/// Files of one local user's own sent to the scan of changed files per hour: each scan may
/// load a scanner's gigabyte of signatures, and any account can change its files every minute.
const USER_SCANS_PER_HOUR: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Ban,
    Unban,
    Alert,
    /// Operator allowlist entry added (accepted before any drop until `until`).
    Allow,
    /// Operator allowlist entry removed or expired.
    Disallow,
}

/// What an alert or ban is about; drives who gets notified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topic {
    /// Password guessing against one account from several addresses.
    AccountAttack,
    /// An address was banned after failed logins against specific accounts.
    BruteForce,
    /// Successful login right after suspicious activity from the same address.
    Compromise,
    NewNetwork,
    Registration,
    FalsePositive,
    /// A protected (allowlisted/trusted) address crossed the ban threshold.
    Protected,
    /// Operational problems, e.g. ejabberd hiding client addresses.
    System,
    /// A service became (un)reachable from the internet, or a firewall rule is dead.
    Exposure,
    /// Changed cron jobs / timers, antivirus findings: signs of a compromised host.
    Integrity,
    /// The daily summary.
    Digest,
    /// An admin notification relayed from another cluster node.
    Relayed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    pub ts: Micros,
    pub kind: ActionKind,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Net>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Micros>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Narrower bans replaced by this (subnet) ban.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded: Vec<Net>,
    /// Whether the firewall was actually changed (false in shadow mode).
    #[serde(default)]
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<Topic>,
    /// Affected accounts, qualified by source: `ejabberd:alice@example.org`, `ssh:root`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<String>,
    /// Plain-language explanation for the affected user (no internal scores), in English.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_note: Option<String>,
    /// The same as facts, rendered in each recipient's language when notifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<UserNotice>,
    /// What caused a ban (tripwire, port scan, ssh, ...), for the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// An address/network the operator allowlisted for a while.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperAllow {
    pub net: Net,
    pub until: Micros,
    pub note: String,
}

/// Counters for the daily digest (reset whenever one is produced).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DigestStats {
    pub since: Micros,
    pub bans_by_category: BTreeMap<String, u32>,
    pub alerts_by_topic: BTreeMap<String, u32>,
    /// Warning-or-worse alerts, newest last (capped).
    pub attention: Vec<String>,
    pub events_base: BTreeMap<Signal, u64>,
    #[serde(skip)]
    pub points: HashMap<IpAddr, f64>,
}

/// One digest period, ready for rendering.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DigestData {
    pub since: Micros,
    pub until: Micros,
    pub bans_by_category: BTreeMap<String, u32>,
    pub alerts_by_topic: BTreeMap<String, u32>,
    pub attention: Vec<String>,
    pub events: BTreeMap<Signal, u64>,
    /// Address, points, covering ban, place.
    pub top: Vec<(IpAddr, f64, Option<Net>, Option<String>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ban {
    pub net: Net,
    pub since: Micros,
    pub until: Micros,
    pub offence: u32,
    pub reason: String,
    /// Cluster node the ban came from; None = decided here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Narrower bans this (subnet) ban replaced that last longer than it: nftables can't hold
    /// overlapping elements, so they are set aside and reinstated when this one ends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inner: Vec<Ban>,
}

/// What the subnet bans among some bans cover, to show how far they reach.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SubnetCoverage {
    pub subnets: usize,
    /// IPv4 addresses in them (an IPv6 /64 alone holds 2^64).
    pub v4_addresses: u64,
    pub widest_v4: Option<u8>,
}

pub fn subnet_coverage(bans: &[Ban]) -> SubnetCoverage {
    let mut c = SubnetCoverage::default();
    for n in bans.iter().map(|b| b.net).filter(|n| !n.is_host()) {
        c.subnets += 1;
        if n.is_v4() {
            c.v4_addresses += 1u64 << (32 - u32::from(n.prefix.min(32)));
            c.widest_v4 = Some(c.widest_v4.map_or(n.prefix, |w| w.min(n.prefix)));
        }
    }
    c
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Offender {
    pub count: u32,
    pub last_ban: Micros,
}

/// Stored as `[count, last_ban_seconds]`: thousands of these make up most of the state file.
impl Serialize for Offender {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.count, self.last_ban.div_euclid(crate::time::SEC)).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Offender {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Compact(u32, i64),
            /// state files written before the compact form
            Full {
                count: u32,
                last_ban: Micros,
            },
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Compact(count, secs) => Offender { count, last_ban: secs * crate::time::SEC },
            Raw::Full { count, last_ban } => Offender { count, last_ban },
        })
    }
}

/// Scores need no more than two decimals on disk.
fn round2<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64((v * 100.0).round() / 100.0)
}

/// Events per signal. An address has only a few kinds, so a small vector: a B-tree map
/// costs ~120 bytes per address, and floods track hundreds of thousands of them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counts(Vec<(Signal, u32)>);

impl Counts {
    pub fn bump(&mut self, s: Signal) {
        match self.0.iter_mut().find(|(k, _)| *k == s) {
            Some(e) => e.1 = e.1.saturating_add(1),
            None => self.0.push((s, 1)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (Signal, u64)> + '_ {
        self.0.iter().map(|(s, n)| (*s, u64::from(*n)))
    }

    pub fn to_map(&self) -> BTreeMap<Signal, u64> {
        self.iter().collect()
    }
}

/// Persisted as a map, like the B-tree map it replaced.
impl Serialize for Counts {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.iter())
    }
}

impl<'de> Deserialize<'de> for Counts {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let m = BTreeMap::<Signal, u64>::deserialize(d)?;
        Ok(Counts(m.into_iter().map(|(s, n)| (s, u32::try_from(n).unwrap_or(u32::MAX))).collect()))
    }
}

/// The latest `EVIDENCE_PER_IP` evidence lines, newline-separated in one allocation.
#[derive(Clone, Debug, Default)]
pub struct Evidence(String);

impl Evidence {
    fn push(&mut self, line: &str) {
        if self.0.lines().count() >= EVIDENCE_PER_IP {
            match self.0.find('\n') {
                Some(i) => drop(self.0.drain(..=i)),
                None => self.0.clear(),
            }
        }
        if !self.0.is_empty() {
            self.0.push('\n');
        }
        self.0.extend(line.chars().map(|c| if c == '\n' { ' ' } else { c }));
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.0.lines()
    }
}

#[derive(Clone, Debug, Default)]
struct Probe {
    xmpp_ports: Vec<(u16, Micros)>,
    fw_ports: Vec<(u16, Micros)>,
    spread_fired: Option<Micros>,
    scan_fired: Option<Micros>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IpState {
    #[serde(serialize_with = "round2")]
    pub fast: f64,
    #[serde(serialize_with = "round2")]
    pub slow: f64,
    pub updated: Micros,
    pub first_seen: Micros,
    pub last_seen: Micros,
    #[serde(serialize_with = "round2")]
    pub peak: f64,
    pub counts: Counts,
    /// Not persisted: it's most of the state file's size and only shown in the TUI.
    #[serde(skip)]
    pub evidence: Evidence,
    /// Failed logins per targeted account (qualified), for notifying the account owner.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub targeted: BTreeMap<String, u32>,
    /// Port-probing bookkeeping, allocated only for addresses that touch ports.
    #[serde(skip)]
    probe: Option<Box<Probe>>,
    /// Local points not yet reported to the cluster.
    #[serde(skip)]
    report_points: f64,
}

/// Most files waiting for the scan of changed files; more are dropped (a flood of changes is
/// news enough).
const MAX_SCAN_QUEUE: usize = 1000;

/// Whether `uid` may have one more of `limit` things an hour (and counts it if so).
fn hourly_budget(used: &mut HashMap<u32, VecDeque<Micros>>, uid: u32, now: Micros, limit: usize) -> bool {
    let hour = 3600 * crate::time::SEC;
    if used.len() >= 1000 && !used.contains_key(&uid) {
        used.retain(|_, times| times.back().is_some_and(|t| now - t < hour));
    }
    let times = used.entry(uid).or_default();
    while times.front().is_some_and(|t| now - t >= hour) {
        times.pop_front();
    }
    if times.len() >= limit {
        return false;
    }
    times.push_back(now);
    true
}

/// Digest category of a ban, from the dominant signal.
fn category_of(s: Signal) -> &'static str {
    match s {
        Signal::FwTripwire | Signal::TripwireConnect => "tripwire",
        s if s.is_canary() => "canary",
        Signal::FwBlock | Signal::FwLimit => "port scan",
        Signal::PeerReport => "cluster evidence",
        s if s.source() == Source::Ssh => "ssh",
        s if s.source() == Source::Ejabberd => "xmpp",
        s if s.source() == Source::Nextcloud => "web",
        s if s.source() == Source::Custom => "custom",
        s if s.source() == Source::Auth => "pam",
        _ => "other",
    }
}

/// Whether these offences are all blocked packets, whose source address is easily forged
/// (a peer's report is not, nor a completed handshake with a honeypot listener).
fn firewall_only(offences: impl Iterator<Item = Signal>) -> bool {
    let mut any = false;
    offences.inspect(|_| any = true).all(|s| s.source() == Source::Ufw && s != Signal::TripwireConnect) && any
}

/// Private, loopback, link-local, CGNAT, multicast and unspecified addresses: local
/// containers (e.g. Docker bridges) or spoofed bogons, never worth banning.
pub fn is_non_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || o[0] == 0
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

fn decay(v: f64, dt: Micros, half_life: Micros) -> f64 {
    if dt <= 0 || v == 0.0 {
        v
    } else {
        v * 0.5_f64.powf(dt as f64 / half_life as f64)
    }
}

impl IpState {
    fn scores_at(&self, now: Micros, cfg: &Config) -> (f64, f64) {
        let dt = now - self.updated;
        (decay(self.fast, dt, cfg.scoring.fast_half_life.micros()), decay(self.slow, dt, cfg.scoring.slow_half_life.micros()))
    }

    fn advance(&mut self, now: Micros, cfg: &Config) {
        (self.fast, self.slow) = self.scores_at(now, cfg);
        self.updated = self.updated.max(now);
    }

    fn add(&mut self, points: f64) {
        self.fast += points;
        self.slow += points;
        self.peak = self.peak.max(self.fast);
    }

    fn note(&mut self, ts: Micros, text: &str) {
        self.evidence.push(&format!("{} {}", &fmt_ts(ts)[5..], text));
    }

    fn auth_failures(&self) -> u64 {
        self.counts.iter().filter(|(s, _)| s.is_auth_failure()).map(|(_, n)| n).sum()
    }
}

/// Records `port` and returns the number of distinct ports seen within `window`.
fn distinct_ports(ports: &mut Vec<(u16, Micros)>, port: u16, now: Micros, window: Micros) -> usize {
    ports.retain(|(_, t)| now - *t < window);
    match ports.iter_mut().find(|(p, _)| *p == port) {
        Some(entry) => entry.1 = now,
        None => ports.push((port, now)),
    }
    ports.len()
}

#[derive(Clone, Debug, Default)]
struct AccountState {
    score: f64,
    updated: Micros,
    ips: HashMap<IpAddr, Micros>,
    alerted: Option<Micros>,
    under_attack_until: Micros,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MinuteBucket {
    pub minute: Micros,
    /// Events per source (`Source as usize`).
    pub events: Vec<u32>,
    pub bans: u32,
}

impl MinuteBucket {
    fn count(&mut self, source: Source) {
        let i = source as usize;
        if self.events.len() <= i {
            self.events.resize(i + 1, 0);
        }
        self.events[i] = self.events[i].saturating_add(1);
    }
}

/// The SSH keys an account has logged in with.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SshKeys {
    /// When the first was seen: keys are learned silently for `learning_period` after it.
    pub since: Micros,
    pub keys: BTreeSet<String>,
}

/// Keys remembered per account, and accounts with keys.
const MAX_KEYS: usize = 32;
const MAX_KEY_ACCOUNTS: usize = 1000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub records: BTreeMap<Source, u64>,
    pub events: BTreeMap<Signal, u64>,
    pub unattributed: u64,
    #[serde(default)]
    pub hidden_ips: u64,
    pub bans: u64,
    pub alerts: u64,
    pub history: VecDeque<MinuteBucket>,
    /// Events and bans per hour, the last [`HISTORY_HOURS`] (since the start).
    #[serde(default)]
    pub hours: VecDeque<HourBucket>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HourBucket {
    pub hour: Micros,
    pub events: u64,
    pub bans: u64,
}

impl Stats {
    fn hour(&mut self, ts: Micros) -> Option<&mut HourBucket> {
        let hour = ts - ts.rem_euclid(60 * MIN);
        if self.hours.back().is_none_or(|b| hour > b.hour) {
            if self.hours.len() == HISTORY_HOURS {
                self.hours.pop_front();
            }
            self.hours.push_back(HourBucket { hour, ..Default::default() });
            return self.hours.back_mut();
        }
        self.hours.iter_mut().rev().find(|b| b.hour == hour)
    }

    fn bucket(&mut self, ts: Micros) -> Option<&mut MinuteBucket> {
        let minute = ts - ts.rem_euclid(MIN);
        if self.history.back().is_none_or(|b| minute > b.minute) {
            if self.history.len() == HISTORY_MINUTES {
                self.history.pop_front();
            }
            self.history.push_back(MinuteBucket { minute, ..Default::default() });
            return self.history.back_mut();
        }
        self.history.iter_mut().rev().find(|b| b.minute == minute)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpView {
    pub ip: IpAddr,
    pub fast: f64,
    pub slow: f64,
    /// Highest of fast/threshold and slow/threshold, as a percentage.
    pub danger: f64,
    pub peak: f64,
    pub first_seen: Micros,
    pub last_seen: Micros,
    pub counts: BTreeMap<Signal, u64>,
    pub evidence: Vec<String>,
    pub banned_by: Option<Net>,
    pub banned_until: Option<Micros>,
    pub protected: Option<String>,
    /// "Germany / Hetzner Online GmbH (AS24940)" when a geo database is loaded.
    #[serde(default)]
    pub geo: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountView {
    pub account: String,
    pub failures: f64,
    pub ips: usize,
    pub under_attack: bool,
}

/// Everything the TUI and reports need, serialised as one JSON document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    /// logguard's version.
    #[serde(default)]
    pub version: String,
    pub generated: Micros,
    pub started: Micros,
    pub mode: Mode,
    pub fast_threshold: f64,
    pub slow_threshold: f64,
    pub stats: Stats,
    pub tracked_ips: usize,
    /// Client connections still inside the `noauth_grace` window (not yet logged in or flagged).
    pub tracked_connections: usize,
    pub offenders: Vec<IpView>,
    pub bans: Vec<Ban>,
    pub recent: Vec<Action>,
    /// The latest alerts, newest first, however many other actions came after them.
    #[serde(default)]
    pub alerts: Vec<Action>,
    pub accounts: Vec<AccountView>,
    pub trusted: Vec<(IpAddr, Micros)>,
    #[serde(default)]
    pub exposure: Option<ExposureReport>,
    #[serde(default)]
    pub cluster: Option<crate::cluster::ClusterView>,
    #[serde(default)]
    pub allowed: Vec<OperAllow>,
    #[serde(default)]
    pub feeds: Option<crate::feeds::FeedStatus>,
    /// What `[waf]` loaded last.
    #[serde(default)]
    pub waf: Option<crate::waf::WafStatus>,
    /// What `[geoblock]` loaded last (countries and networks dropped).
    #[serde(default)]
    pub geoblock: Option<crate::geo::GeoblockStatus>,
    #[serde(default)]
    pub certs: Vec<crate::digest::CertStatus>,
    /// Time of the newest line per log source.
    #[serde(default)]
    pub last_lines: BTreeMap<Source, Micros>,
    #[serde(default)]
    pub cron: Option<crate::cronwatch::CronView>,
    /// Present when `[antivirus]` is enabled.
    #[serde(default)]
    pub av: Option<crate::avscan::AvState>,
    /// The latest disk and memory reading, when `[resources]` is enabled.
    #[serde(default)]
    pub resources: Option<crate::resources::Report>,
    #[serde(default)]
    pub world: WorldView,
    /// Names for local ports from the daemon's configuration (`Config::port_names`).
    #[serde(default)]
    pub port_names: Vec<(u16, String)>,
    /// Set when the snapshot was built from a decision log (`tui --actions`), not the daemon.
    #[serde(default)]
    pub actions_log: Option<crate::actions_view::LogSummary>,
    /// The latest patch status, when `[patches]` is enabled.
    #[serde(default)]
    pub patches: Option<crate::patches::PatchReport>,
    /// The last package and set-uid check (`[verify]`).
    #[serde(default)]
    pub verify: Option<crate::verify::VerifyView>,
    /// Outbound connections learned (`[procwatch]`).
    #[serde(default)]
    pub procwatch: Option<crate::procwatch::ProcView>,
    /// The latest SSH hardening audit (`[ssh_audit]`).
    #[serde(default)]
    pub ssh_audit: Option<crate::sshaudit::SshAuditReport>,
    /// Addresses the `[allowlist] hosts` names resolve to now.
    #[serde(default)]
    pub allow_hosts: Vec<Net>,
    /// The `[[patterns]]` entries and what each found.
    #[serde(default)]
    pub patterns: Vec<crate::parse::custom::PatternView>,
    /// The firewall backend the daemon enforces with (`Enforcer::name`: "nftables",
    /// "firewalld", ...); missing from snapshots of older daemons and decision logs.
    #[serde(default)]
    pub backend: Option<String>,
}

/// Where the trouble comes from, for the Countries and Map tabs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorldView {
    /// Whether a geo database is loaded; without one only `ports` is filled.
    pub geo: bool,
    /// Every country with an active ban or a tracked offender, worst first.
    pub countries: Vec<PlaceStats>,
    /// Networks (ASNs), worst first, capped.
    pub isps: Vec<PlaceStats>,
    /// Events per local port (TCP and UDP together) since start, busiest first, capped.
    pub ports: Vec<(u16, u64)>,
    /// Addresses that logged in during the last hour, per country code.
    pub logged_in: BTreeMap<String, u32>,
    /// Offenders (sources) whose country is unknown.
    pub unlocated: u32,
    /// Networks and ports of each country in `countries`, keyed by country code.
    #[serde(default)]
    pub by_country: BTreeMap<String, CountryDetail>,
}

/// Events per local port, kept across restarts and halved once a day, so the Countries tab
/// shows recent activity: an event from a week ago weighs 1/128 of one from today.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PortCounts {
    /// When the counters were last halved.
    pub halved: Micros,
    pub all: Vec<(u16, u64)>,
    pub by_country: BTreeMap<String, Vec<(u16, u64)>>,
}

/// What the Countries tab shows for one selected country.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CountryDetail {
    /// Networks with this country's figures only (a network spanning countries is listed
    /// under each), worst first, capped.
    pub isps: Vec<PlaceStats>,
    /// Events per local port from this country since start, busiest first, capped.
    pub ports: Vec<(u16, u64)>,
}

/// Bans, offenders and their events for one country or network.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PlaceStats {
    /// Country code (countries) or "AS1234" (networks).
    pub key: String,
    /// Country name, or the network's organisation.
    pub name: String,
    /// The network's country code (networks only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    /// Active bans (an address or a subnet each).
    pub bans: u32,
    /// Tracked addresses with a score, banned or not.
    pub offenders: u32,
    pub events: u64,
}

const WORLD_ISPS: usize = 100;
const WORLD_PORTS: usize = 40;
const COUNTRY_ISPS: usize = 50;
/// Distinct ports counted per country: forged UDP can name any port from any country,
/// so this bounds the memory (about 75,000 counters at most); only the top 40 are shown.
const COUNTRY_PORTS: usize = 300;
/// Busiest addresses per pattern in a snapshot.
const PATTERN_TOP_IPS: usize = 20;

/// Persisted across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    pub version: u32,
    pub saved: Micros,
    pub cursor: Option<String>,
    pub bans: Vec<Ban>,
    pub offenders: Vec<(Net, Offender)>,
    /// Written empty: logins of older versions, whatever the service.
    pub trusted: Vec<(IpAddr, Micros)>,
    /// When an address last logged in, per service.
    #[serde(default)]
    pub trusted_by: Vec<(IpAddr, Source, Micros)>,
    pub account_nets: BTreeMap<String, BTreeSet<Net>>,
    #[serde(default)]
    pub account_first_seen: BTreeMap<String, Micros>,
    #[serde(default)]
    pub account_asns: BTreeMap<String, BTreeSet<u32>>,
    pub ips: Vec<(IpAddr, IpState)>,
    #[serde(default)]
    pub recent: Vec<Action>,
    #[serde(default)]
    pub alerts: Vec<Action>,
    /// Exposed listeners accepted as normal (learned on the first scan).
    #[serde(default)]
    pub exposure_baseline: Option<Vec<(ListenerKey, String)>>,
    /// The firewall that baseline was learned under (None: by a version reading only ufw).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure_firewall: Option<crate::exposure::Firewall>,
    #[serde(default)]
    pub allowed: Vec<OperAllow>,
    #[serde(default)]
    pub digest: Option<DigestStats>,
    #[serde(default)]
    pub digest_last_sent: Micros,
    /// Alert rate-limit state, so daily alerts aren't repeated after every restart.
    #[serde(default)]
    pub alert_gate: Vec<(String, Micros)>,
    /// Accepted cron jobs / timers (None until the first scan).
    #[serde(default)]
    pub cron: Option<crate::cronwatch::Baseline>,
    #[serde(default)]
    pub av: crate::avscan::AvState,
    /// Time of the last line read from each followed log (Nextcloud), to resume there.
    #[serde(default)]
    pub followers: BTreeMap<String, Micros>,
    /// Probed-port counters of the Countries tab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<PortCounts>,
    /// SSH keys per account (`ssh:alice`), for new-key alerts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ssh_keys: BTreeMap<String, SshKeys>,
    /// Package and set-uid check results accepted (None until the first pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<crate::verify::VerifyBaseline>,
    /// Outbound connections learned (None until the first scan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procwatch: Option<crate::procwatch::ProcBaseline>,
    /// What the SSH audit reported (None until the first reading).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_audit: Option<crate::sshaudit::SshAuditBaseline>,
    /// What each `[[patterns]]` entry found, for the Patterns tab.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<crate::parse::custom::PatternStats>,
}

/// The state file's bytes: gzip-compressed JSON (`zcat state.json | jq` to read it).
pub fn encode_state(st: &PersistedState) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    serde_json::to_writer(&mut gz, st)?;
    gz.flush()?;
    gz.finish()
}

/// Reads a state file written by `encode_state`, or the plain JSON of older versions.
pub fn decode_state(bytes: &[u8]) -> anyhow::Result<PersistedState> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        Ok(serde_json::from_reader(flate2::read::GzDecoder::new(bytes))?)
    } else {
        Ok(serde_json::from_slice(bytes)?)
    }
}

pub struct Engine {
    cfg: Arc<Config>,
    pub now: Micros,
    pub started: Micros,
    /// Boxed: the table then holds pointers, so its empty slots (up to half of it) stay small.
    ips: HashMap<IpAddr, Box<IpState>>,
    accounts: HashMap<String, AccountState>,
    bans: HashMap<Net, Ban>,
    ban_prefixes: BTreeSet<(bool, u8)>,
    offenders: HashMap<Net, Offender>,
    /// When each address last logged in, per service: trust shields it from that service's
    /// own noise and typos only (see [`Engine::trust_covers`]).
    trusted: HashMap<IpAddr, BTreeMap<Source, Micros>>,
    account_nets: HashMap<String, BTreeSet<Net>>,
    account_first_seen: HashMap<String, Micros>,
    alert_gate: HashMap<String, Micros>,
    recent: VecDeque<Action>,
    alerts: VecDeque<Action>,
    /// None until the first exposure scan has been learned.
    exposure_baseline: Option<BTreeMap<ListenerKey, (String, u32)>>,
    /// The firewall the baseline was learned under.
    exposure_firewall: Option<crate::exposure::Firewall>,
    exposure_pending: BTreeMap<ListenerKey, u32>,
    /// Consecutive scans each ufw rule has had nothing listening behind it.
    dead_pending: BTreeMap<String, u32>,
    exposure_last: Option<ExposureReport>,
    /// Cluster: facts produced here, drained by the daemon (None = sharing disabled).
    outbox: Option<Vec<FactBody>>,
    peer_nets: Vec<Net>,
    /// This host's own addresses.
    own_nets: Vec<Net>,
    allowed: BTreeMap<Net, OperAllow>,
    pub digest: DigestStats,
    pub digest_last_sent: Micros,
    pub feeds: Option<crate::feeds::FeedStatus>,
    pub waf: Option<crate::waf::WafStatus>,
    /// What `[geoblock]` loaded last.
    pub geoblock: Option<crate::geo::GeoblockStatus>,
    pub certs: Vec<crate::digest::CertStatus>,
    /// Set by the daemon after each `[resources]` reading.
    pub resources: Option<crate::resources::Report>,
    pub stats: Stats,
    last_subnet_eval: Micros,
    last_gc: Micros,
    silence: SilenceState,
    /// Bumped whenever something worth persisting happens (bans, alerts, trust, new
    /// account networks); the daemon saves state only when it moved.
    pub changes: u64,
    /// Offline country/network database, when loaded (`[geo]`).
    pub geo: Option<Arc<crate::geo::GeoDb>>,
    /// Networks (ASNs) each account has logged in from: a new /16 of a known provider is no news.
    account_asns: HashMap<String, BTreeSet<u32>>,
    cron: Option<crate::cronwatch::Baseline>,
    cron_view: Option<crate::cronwatch::CronView>,
    av: crate::avscan::AvState,
    /// See `PersistedState::followers`; kept up to date by the daemon.
    pub followers: BTreeMap<String, Micros>,
    /// Events per local port from unprotected addresses since start, for the TUI.
    port_hits: HashMap<u16, u64>,
    /// The same per country (with a geo database), at most `COUNTRY_PORTS` ports each.
    port_hits_cc: HashMap<[u8; 2], HashMap<u16, u64>>,
    /// When the port counters were last halved (daily).
    ports_halved: Micros,
    /// Addresses `[allowlist] hosts` resolve to: allowlisted like `[allowlist] nets`.
    allow_hosts: Vec<Net>,
    /// Each SSH account's latest login (address, time), named in su/sudo alerts.
    last_ssh: HashMap<String, (IpAddr, Micros)>,
    ssh_keys: HashMap<String, SshKeys>,
    /// Failed su/sudo attempts per user: (count, first, last).
    priv_fails: HashMap<String, (u32, Micros, Micros)>,
    /// The same for failed logins PAM or the audit log report here (per service and who or
    /// where): count, first, last.
    auth_fails: HashMap<String, (u32, Micros, Micros)>,
    /// When integrity alerts about each local user's own things were sent, the last hour.
    user_alerts: HashMap<u32, VecDeque<Micros>>,
    /// The same for each local user's files sent to the scan of changed files.
    user_scans: HashMap<u32, VecDeque<Micros>>,
    /// Set by the daemon after each `[patches]` reading.
    pub patches: Option<crate::patches::PatchReport>,
    verify: Option<crate::verify::VerifyBaseline>,
    verify_view: Option<crate::verify::VerifyView>,
    procwatch: Option<crate::procwatch::ProcBaseline>,
    proc_view: Option<crate::procwatch::ProcView>,
    ssh_audit: Option<crate::sshaudit::SshAuditBaseline>,
    ssh_audit_last: Option<crate::sshaudit::SshAuditReport>,
    /// Files the integrity watches reported new or changed, waiting for their scan
    /// (`[antivirus] scan_changed`). Not kept across restarts.
    scan_queue: Vec<crate::filescan::Job>,
    /// One per `[[patterns]]` entry, in the configuration's order, then the built-in ones.
    pattern_stats: Vec<crate::parse::custom::PatternStats>,
}

/// Per-source liveness, for "this log went quiet" alerts.
#[derive(Default)]
struct SilenceState {
    last_line: BTreeMap<Source, Micros>,
    last_event: BTreeMap<Source, Micros>,
    lines_since_event: BTreeMap<Source, u64>,
    quiet: BTreeSet<Source>,
    blind: BTreeSet<Source>,
    /// Logs of `[silence.apps]` reported quiet.
    quiet_apps: BTreeSet<String>,
}

impl Engine {
    pub fn new(cfg: Arc<Config>, now: Micros) -> Self {
        let mut e = Engine {
            cfg,
            now,
            started: now,
            ips: HashMap::new(),
            accounts: HashMap::new(),
            bans: HashMap::new(),
            ban_prefixes: BTreeSet::new(),
            offenders: HashMap::new(),
            trusted: HashMap::new(),
            account_nets: HashMap::new(),
            account_first_seen: HashMap::new(),
            alert_gate: HashMap::new(),
            recent: VecDeque::new(),
            alerts: VecDeque::new(),
            exposure_baseline: None,
            exposure_firewall: None,
            exposure_pending: BTreeMap::new(),
            dead_pending: BTreeMap::new(),
            exposure_last: None,
            outbox: None,
            peer_nets: vec![],
            own_nets: vec![],
            allowed: BTreeMap::new(),
            digest: DigestStats { since: now, ..Default::default() },
            digest_last_sent: 0,
            feeds: None,
            waf: None,
            geoblock: None,
            certs: vec![],
            resources: None,
            stats: Stats::default(),
            last_subnet_eval: now,
            last_gc: now,
            silence: SilenceState::default(),
            changes: 0,
            geo: None,
            account_asns: HashMap::new(),
            cron: None,
            cron_view: None,
            av: Default::default(),
            followers: BTreeMap::new(),
            port_hits: HashMap::new(),
            port_hits_cc: HashMap::new(),
            ports_halved: now,
            allow_hosts: vec![],
            last_ssh: HashMap::new(),
            ssh_keys: HashMap::new(),
            priv_fails: HashMap::new(),
            auth_fails: HashMap::new(),
            scan_queue: Vec::new(),
            user_alerts: HashMap::new(),
            user_scans: HashMap::new(),
            patches: None,
            verify: None,
            verify_view: None,
            procwatch: None,
            proc_view: None,
            ssh_audit: None,
            ssh_audit_last: None,
            pattern_stats: Vec::new(),
        };
        e.set_pattern_stats(Vec::new());
        e
    }

    /// Statistics for each configured pattern: the saved ones by name, new ones empty; those
    /// of patterns no longer configured are dropped.
    fn set_pattern_stats(&mut self, mut saved: Vec<crate::parse::custom::PatternStats>) {
        self.pattern_stats = self
            .cfg
            .all_patterns()
            .map(|p| match saved.iter().position(|s| s.name == p.name) {
                Some(i) => saved.swap_remove(i),
                None => crate::parse::custom::PatternStats::new(&p.name),
            })
            .collect();
    }

    /// Counts a line from pattern `name`'s sender, and what the pattern made of it.
    pub fn count_pattern(&mut self, name: &str, ts: Micros, outcome: crate::parse::custom::Outcome, line: &str) {
        if let Some(st) = self.pattern_stats.iter_mut().find(|s| s.name == name) {
            st.count(ts, outcome, line);
        }
    }

    /// The accounts (qualified, `ejabberd:alice@example.org`) that have logged in successfully at
    /// some point; user notifications go only to those.
    fn notifiable(&self, accounts: Vec<String>) -> Vec<String> {
        accounts.into_iter().filter(|a| self.account_first_seen.contains_key(a)).collect()
    }

    /// Allowlist entries wider than anything logguard bans itself (default /16, IPv6 /32): a
    /// peer sending one is broken or compromised, and a /1 entry would be a disaster.
    fn too_wide(&self, net: &Net) -> bool {
        let sc = &self.cfg.subnets;
        net.prefix < if net.is_v4() { sc.v4_wide_prefix.min(16) } else { sc.v6_prefix.min(32) }
    }

    /// Bans wider than this node's own: `v4_wide_prefix` (`v4_prefix` without growth), IPv6
    /// `v6_prefix`. Bans kept narrow here stay narrow whatever the peers decide.
    fn wider_than_own_bans(&self, net: &Net) -> bool {
        let sc = &self.cfg.subnets;
        net.prefix
            < match (net.is_v4(), sc.wide_enabled) {
                (true, true) => sc.v4_wide_prefix,
                (true, false) => sc.v4_prefix,
                (false, true) => sc.v6_wide_prefix,
                (false, false) => sc.v6_prefix,
            }
    }

    /// "Germany / Hetzner Online GmbH (AS24940)", if a geo database is loaded and knows the address.
    pub fn place(&self, ip: IpAddr) -> Option<String> {
        self.geo.as_ref()?.label(ip)
    }

    /// `ip` followed by its place in parentheses, when known.
    fn ip_place(&self, ip: IpAddr) -> String {
        match self.place(ip) {
            Some(p) => format!("{ip} ({p})"),
            None => ip.to_string(),
        }
    }

    pub fn count_record(&mut self, source: Source, ts: Micros) {
        *self.stats.records.entry(source).or_default() += 1;
        let last = self.silence.last_line.entry(source).or_default();
        *last = (*last).max(ts);
        *self.silence.lines_since_event.entry(source).or_default() += 1;
    }

    /// Alerts about enabled sources that stopped logging, or that log without any line
    /// naming an address. Live daemon only (`started` = wall-clock start): silence is
    /// measured from the later of the last line and the daemon start, so host downtime
    /// and history replayed at startup never count.
    pub fn check_silence(&mut self, now: Micros) -> Vec<Action> {
        let mut out = Vec::new();
        let cfg = Arc::clone(&self.cfg);
        let sc = &cfg.silence;
        if !sc.enabled || self.started <= 0 {
            return out;
        }
        self.now = self.now.max(now);
        for src in [Source::Ejabberd, Source::Ssh, Source::Ufw, Source::Nextcloud] {
            if !cfg.sources.enabled(src) {
                continue;
            }
            let name = src.name();
            let quiet = sc.quiet_after(src).micros();
            let last = self.silence.last_line.get(&src).copied();
            let since = last.unwrap_or(0).max(self.started);
            if quiet > 0 && now - since >= quiet {
                self.silence.quiet.insert(src);
                let seen = match last {
                    Some(t) => format!("last one at {}", fmt_ts(t)),
                    None => "none since logguard started".into(),
                };
                let hint = match src {
                    Source::Ufw => "is UFW logging on (`ufw logging low`) and is the kernel log reaching journald?",
                    Source::Ejabberd => "is ejabberd running, and is it still the ejabberd.service unit logging to the journal?",
                    Source::Ssh => "is sshd running and logging to the journal?",
                    _ => "is the container running and is [nextcloud] log_file still right?",
                };
                let msg = format!(
                    "no {name} log lines for {} ({seen}): detection for it is blind - {hint}",
                    crate::time::fmt_duration(now - since)
                );
                out.extend(self.system_alert(&format!("silent:{name}"), 86_400 * crate::time::SEC, Severity::Warning, msg));
            } else if quiet > 0 && self.silence.quiet.remove(&src) {
                out.extend(self.system_alert(
                    &format!("silent-back:{name}"),
                    MIN,
                    Severity::Info,
                    format!("{name} log lines are arriving again"),
                ));
            }

            let lines = self.silence.lines_since_event.get(&src).copied().unwrap_or(0);
            let last_event = self.silence.last_event.get(&src).copied().unwrap_or(0).max(self.started);
            let blind_after = sc.blind_after.micros();
            if blind_after > 0 && lines >= sc.blind_lines && now - last_event >= blind_after {
                self.silence.blind.insert(src);
                let msg = format!(
                    "{lines} {name} log lines in the last {} but none could be tied to a client address: \
                     addresses hidden (ejabberd `hide_sensitive_log_data`), or a log format change logguard doesn't understand",
                    crate::time::fmt_duration(now - last_event)
                );
                out.extend(self.system_alert(&format!("blind:{name}"), 86_400 * crate::time::SEC, Severity::Warning, msg));
            } else if lines < sc.blind_lines && self.silence.blind.remove(&src) {
                out.extend(self.system_alert(
                    &format!("blind-back:{name}"),
                    MIN,
                    Severity::Info,
                    format!("{name} log lines name client addresses again"),
                ));
            }
        }
        out.extend(self.check_quiet_apps(now));
        out
    }

    /// `[silence.apps]`: a log of an app (`nginx_access`) with no line for its time. Its
    /// lines are counted by its first pattern, which reads every line of it.
    fn check_quiet_apps(&mut self, now: Micros) -> Vec<Action> {
        let mut out = Vec::new();
        let cfg = Arc::clone(&self.cfg);
        for (log, quiet) in &cfg.silence.apps {
            let Some((app, stream)) = crate::parse::apps::stream(log) else { continue };
            let Some(first) = stream.rules.first() else { continue };
            let Some(pattern) = cfg.app_patterns.iter().find(|p| p.name == first.name) else { continue };
            let last = self.pattern_stats.iter().find(|s| s.name == first.name).and_then(|s| s.last_line);
            let since = last.unwrap_or(0).max(self.started);
            let quiet = quiet.micros();
            if quiet > 0 && now - since >= quiet {
                self.silence.quiet_apps.insert(log.clone());
                let seen = match last {
                    Some(t) => format!("last one at {}", fmt_ts(t)),
                    None => "none since logguard started".into(),
                };
                let msg = format!(
                    "no lines in the {} {} for {} ({seen}): its built-in patterns see nothing - is {} running, and does it still log to {}?",
                    app.about,
                    stream.about,
                    crate::time::fmt_duration(now - since),
                    app.name,
                    pattern.from()
                );
                out.extend(self.system_alert(&format!("silent:app:{log}"), 86_400 * crate::time::SEC, Severity::Warning, msg));
            } else if quiet > 0 && self.silence.quiet_apps.remove(log) {
                let msg = format!("lines in the {} {} are arriving again", app.about, stream.about);
                out.extend(self.system_alert(&format!("silent-back:app:{log}"), MIN, Severity::Info, msg));
            }
        }
        out
    }

    // ---------------------------------------------------------------- queries

    /// Marks this host's own addresses: never scored, banned or reported.
    pub fn set_own_addresses(&mut self, nets: Vec<Net>) {
        self.own_nets = nets;
    }

    /// `system_alert` for things observed on the wall clock (certificate checks, downloads,
    /// peers): while a backlog is replayed the engine clock lags (or is still 0 at startup),
    /// and the alert must carry the real time.
    pub fn system_alert_wall(&mut self, key: &str, every: Micros, severity: Severity, message: String, wall: Micros) -> Vec<Action> {
        let engine_time = self.now;
        self.now = self.now.max(wall);
        let out = self.system_alert(key, every, severity, message);
        self.now = engine_time;
        out
    }

    /// A cron scan: new or changed jobs after the learn period (see `cronwatch`).
    pub fn on_cron(&mut self, r: &crate::cronwatch::CronReport) -> Vec<Action> {
        let before = self.cron.as_ref().map(|b| (b.items.clone(), b.armed));
        let findings = crate::cronwatch::judge(&mut self.cron, r, self.cfg.cron.learn);
        self.cron_view = self.cron.as_ref().map(|b| crate::cronwatch::CronView::of(r, b));
        if before != self.cron.as_ref().map(|b| (b.items.clone(), b.armed)) {
            self.changes += 1; // the baseline moved: save it
        }
        self.findings(findings, r.scanned)
    }

    /// A read of the antivirus scan log (see `avscan`).
    pub fn on_av(&mut self, r: &crate::avscan::AvReport) -> Vec<Action> {
        let before = (self.av.reported, self.av.completed);
        let findings = crate::avscan::judge(&mut self.av, r, &self.cfg.antivirus, self.started);
        if before != (self.av.reported, self.av.completed) {
            self.changes += 1;
        }
        self.findings(findings, r.read)
    }

    /// Host-integrity findings become alerts on the wall clock; those not meant for the
    /// admins (routine results, changes accepted while learning) are only logged. So are those
    /// about a local user's own crontab, scripts, files and processes beyond
    /// `USER_ALERTS_PER_HOUR` an hour (one more alert says so): any account can change those
    /// every minute, and must not use up the hour's messages about the host's integrity.
    fn findings(&mut self, findings: Vec<crate::cronwatch::Finding>, wall: Micros) -> Vec<Action> {
        let engine_time = self.now;
        self.now = self.now.max(wall);
        let mut out = Vec::new();
        let mut held: BTreeMap<u32, Severity> = BTreeMap::new();
        for f in findings {
            if f.every > 0 {
                if self.alert_gate.get(&f.key).is_some_and(|t| self.now - t < f.every) {
                    continue;
                }
                self.alert_gate.insert(f.key, self.now);
            }
            // the files it names go to the scan of changed files (a user's own, a few an hour)
            if self.cfg.antivirus.scan_changed != crate::filescan::Scanners::None {
                let why = crate::event::clean(&f.message, 100);
                for path in f.files {
                    if self.scan_queue.len() >= MAX_SCAN_QUEUE || self.scan_queue.iter().any(|j| j.path == path) {
                        continue;
                    }
                    if f.owner.is_some_and(|uid| !hourly_budget(&mut self.user_scans, uid, self.now, USER_SCANS_PER_HOUR)) {
                        break;
                    }
                    self.scan_queue.push(crate::filescan::Job { path, why: why.clone(), owner: f.owner });
                }
            }
            let mut message = f.message;
            let mut notify = f.notify;
            if let Some(uid) = f.owner.filter(|_| notify) {
                if !self.user_alert_allowed(uid) {
                    notify = false;
                    message += &format!(" [only logged: uid {uid} had its {USER_ALERTS_PER_HOUR} alerts this hour]");
                    let worst = held.entry(uid).or_insert(f.severity);
                    *worst = (*worst).max(f.severity);
                }
            }
            let a = Action {
                ts: self.now,
                kind: ActionKind::Alert,
                severity: f.severity,
                target: None,
                until: None,
                message,
                evidence: f.evidence,
                superseded: vec![],
                applied: false,
                topic: notify.then_some(Topic::Integrity),
                accounts: vec![],
                user_note: None,
                notice: None,
                category: None,
            };
            self.push_action(a, &mut out);
        }
        for (uid, severity) in held {
            let who = std::fs::read_to_string("/etc/passwd")
                .ok()
                .and_then(|p| crate::botbox::user_name(&p, uid))
                .map_or(format!("uid {uid}"), |n| format!("{n} (uid {uid})"));
            self.alert_about(
                format!("user-flood:{uid}"),
                3600 * crate::time::SEC,
                severity,
                None,
                format!(
                    "integrity: more than {USER_ALERTS_PER_HOUR} alerts this hour about the own crontab, scripts, files or processes \
                     of {who}: the rest of this hour's are only logged (logguard tui, Alerts tab; the actions log)"
                ),
                Some(Topic::Integrity),
                vec![],
                None,
                &mut out,
            );
        }
        self.now = engine_time;
        out
    }

    /// Whether one more integrity alert about local user `uid`'s own things may go to the
    /// admins this hour (and counts it if so).
    fn user_alert_allowed(&mut self, uid: u32) -> bool {
        hourly_budget(&mut self.user_alerts, uid, self.now, USER_ALERTS_PER_HOUR)
    }

    /// Raises an operational alert (not tied to an address), rate-limited per key.
    pub fn system_alert(&mut self, key: &str, every: Micros, severity: Severity, message: String) -> Vec<Action> {
        let mut out = Vec::new();
        self.alert_about(format!("system:{key}"), every, severity, None, message, Some(Topic::System), vec![], None, &mut out);
        out
    }

    fn allowlisted(&self, ip: IpAddr) -> bool {
        self.cfg.allowlist.nets.iter().any(|n| n.contains(ip))
    }

    /// Whether `ip` logged in to `source` within `trust_ttl`.
    fn trusted_for(&self, ip: IpAddr, source: Source) -> bool {
        self.cfg.allowlist.trust_authenticated
            && self.trusted.get(&ip).and_then(|m| m.get(&source)).is_some_and(|t| self.now - t < self.cfg.allowlist.trust_ttl.micros())
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.cfg.allowlist.trust_authenticated
            && self.trusted.get(&ip).is_some_and(|m| m.values().any(|t| self.now - t < self.cfg.allowlist.trust_ttl.micros()))
    }

    /// Whether a trusted `ip`'s offences all come from services it logged in to: a login
    /// excuses that service's typos and reconnects, never canary names, other services or
    /// peers' reports. Blocked packets (tripwire ports included) are excused by any recent
    /// login: one forged SYN carries any source address.
    fn trust_covers(&self, ip: IpAddr, st: &IpState) -> bool {
        let mut offences = st.counts.iter().filter(|(s, n)| *n > 0 && !s.is_success()).peekable();
        offences.peek().is_some()
            && offences.all(|(s, _)| {
                if s.source() == Source::Ufw {
                    self.is_trusted(ip)
                } else {
                    !s.is_canary() && self.trusted_for(ip, s.source())
                }
            })
    }

    /// Why an address must never be banned, whatever it did, if it must not (trust from a
    /// login is not part of it: see [`Engine::shield`]).
    fn hard_protection(&self, ip: IpAddr) -> Option<&'static str> {
        if is_non_global(ip) {
            Some("private/non-routable")
        } else if self.own_nets.iter().any(|n| n.contains(ip)) {
            Some("this host")
        } else if self.peer_nets.iter().any(|n| n.contains(ip)) {
            Some("cluster peer")
        } else if self.allowed.values().any(|a| a.until > self.now && a.net.contains(ip)) {
            Some("operator allowlist")
        } else if self.allowlisted(ip) {
            Some("allowlisted")
        } else if self.allow_hosts.iter().any(|n| n.contains(ip)) {
            Some("allowlisted host name")
        } else {
            None
        }
    }

    /// What protects `ip` (shown in views): [`Engine::hard_protection`], or a recent login.
    pub fn protection(&self, ip: IpAddr) -> Option<&'static str> {
        self.hard_protection(ip).or_else(|| self.is_trusted(ip).then_some("recently authenticated"))
    }

    /// Why `ip` must not be banned for what it did (`st`), if it must not.
    fn shield(&self, ip: IpAddr, st: &IpState) -> Option<&'static str> {
        self.hard_protection(ip).or_else(|| self.trust_covers(ip, st).then_some("recently authenticated"))
    }

    fn net_protected(&self, net: &Net) -> bool {
        self.cfg.allowlist.nets.iter().any(|n| n.overlaps(net))
            || self.peer_nets.iter().any(|n| n.overlaps(net))
            || self.own_nets.iter().any(|n| n.overlaps(net))
            || self.allow_hosts.iter().any(|n| n.overlaps(net))
            || self.allowed.values().any(|a| a.until > self.now && a.net.overlaps(net))
            // a user's login keeps their neighbours' subnet from being banned wholesale, but
            // never shields the address itself (host bans are decided by `shield`)
            || (!net.is_host() && self.trusted.keys().any(|ip| net.contains(*ip) && self.is_trusted(*ip)))
    }

    /// The active ban covering `net` (itself or any wider prefix), if any.
    pub fn covering_ban(&self, net: &Net) -> Option<&Ban> {
        self.ban_prefixes
            .iter()
            .filter(|(v4, p)| *v4 == net.is_v4() && *p <= net.prefix)
            .find_map(|(_, p)| self.bans.get(&Net::new(net.addr, *p)))
    }

    pub fn banned_by(&self, ip: IpAddr) -> Option<&Ban> {
        self.covering_ban(&Net::host(ip))
    }

    // ---------------------------------------------------------------- actions

    /// Records that the firewall applied an action. Recent actions are kept when they are
    /// decided, before the enforcer runs, so without this the dashboard would show every
    /// ban as a shadow one.
    pub fn mark_applied(&mut self, a: &Action) {
        if let Some(r) = self
            .recent
            .iter_mut()
            .rev()
            .find(|r| !r.applied && r.ts == a.ts && r.kind == a.kind && r.target == a.target && r.message == a.message)
        {
            r.applied = true;
        }
    }

    fn push_action(&mut self, a: Action, out: &mut Vec<Action>) {
        self.changes += 1;
        match a.kind {
            ActionKind::Ban => {
                self.stats.bans += 1;
                if let Some(b) = self.stats.bucket(a.ts) {
                    b.bans += 1;
                }
                if let Some(h) = self.stats.hour(a.ts) {
                    h.bans += 1;
                }
                let cat = a.category.clone().unwrap_or_else(|| "other".into());
                *self.digest.bans_by_category.entry(cat).or_default() += 1;
            }
            ActionKind::Alert => {
                self.stats.alerts += 1;
                if !matches!(a.topic, Some(Topic::Digest | Topic::Relayed)) {
                    let topic = a.topic.map_or("other".to_string(), |t| format!("{t:?}").to_lowercase());
                    *self.digest.alerts_by_topic.entry(topic).or_default() += 1;
                    if a.severity >= Severity::Warning && self.digest.attention.len() < 100 {
                        self.digest.attention.push(format!("{} {}", &fmt_ts(a.ts)[5..16], a.message));
                    }
                }
            }
            ActionKind::Unban | ActionKind::Allow | ActionKind::Disallow => {}
        }
        if self.recent.len() == RECENT_ACTIONS {
            self.recent.pop_front();
        }
        self.recent.push_back(a.clone());
        if a.kind == ActionKind::Alert {
            if self.alerts.len() == RECENT_ALERTS {
                self.alerts.pop_front();
            }
            self.alerts.push_back(a.clone());
        }
        out.push(a);
    }

    /// Raises an alert at most once per `every` for the same key.
    #[allow(clippy::too_many_arguments)]
    fn alert_about(
        &mut self,
        key: String,
        every: Micros,
        severity: Severity,
        target: Option<Net>,
        message: String,
        topic: Option<Topic>,
        accounts: Vec<String>,
        notice: Option<UserNotice>,
        out: &mut Vec<Action>,
    ) {
        if self.alert_gate.get(&key).is_some_and(|t| self.now - t < every) {
            return;
        }
        self.alert_gate.insert(key, self.now);
        let a = Action {
            ts: self.now,
            kind: ActionKind::Alert,
            severity,
            target,
            until: None,
            message,
            evidence: vec![],
            superseded: vec![],
            applied: false,
            topic,
            accounts,
            user_note: notice.as_ref().map(|n| crate::i18n::note(n, crate::i18n::Lang::En, None)),
            notice,
            category: None,
        };
        self.push_action(a, out);
    }

    /// `forgeable`: the evidence is firewall logs only (see [`FactBody::Ban`]).
    fn ban(&mut self, net: Net, reason: String, evidence: Vec<String>, category: &str, forgeable: bool, out: &mut Vec<Action>) {
        let now = self.now;
        let ladder = &self.cfg.bans.ladder;
        let forgive = self.cfg.bans.forgive_after.micros();
        let off = self.offenders.entry(net).or_default();
        if now - off.last_ban > forgive {
            off.count = 0;
        }
        let dur = ladder[(off.count as usize).min(ladder.len() - 1)];
        off.count += 1;
        off.last_ban = now;
        let offence = off.count;
        let until = now + dur.micros();
        if let Some(ob) = self.outbox.as_mut() {
            ob.push(FactBody::Ban { net, until, reason: reason.clone(), forgeable });
        }
        let place = self.place(net.addr).map(|p| format!(" [{p}]")).unwrap_or_default();
        let message = format!("ban {net}{place} for {dur} (offence #{offence}): {reason}");
        self.insert_ban(net, until, offence, reason, None, message, evidence, category, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_ban(
        &mut self,
        net: Net,
        until: Micros,
        offence: u32,
        reason: String,
        origin: Option<String>,
        message: String,
        evidence: Vec<String>,
        category: &str,
        out: &mut Vec<Action>,
    ) {
        let now = self.now;
        let superseded: Vec<Net> =
            if net.is_host() { vec![] } else { self.bans.keys().filter(|b| **b != net && net.contains_net(b)).copied().collect() };
        let mut inner = Vec::new();
        for s in &superseded {
            if let Some(mut b) = self.bans.remove(s) {
                inner.append(&mut b.inner);
                if b.until > until {
                    inner.push(b);
                }
            }
        }
        inner.retain(|b| b.until > until);
        self.bans.insert(net, Ban { net, since: now, until, offence, reason, origin, inner });
        self.ban_prefixes.insert((net.is_v4(), net.prefix));

        let severity = if net.is_host() { Severity::High } else { Severity::Critical };
        let a = Action {
            ts: now,
            kind: ActionKind::Ban,
            severity,
            target: Some(net),
            until: Some(until),
            message,
            evidence,
            superseded,
            applied: false,
            topic: None,
            accounts: vec![],
            user_note: None,
            notice: None,
            category: Some(category.to_string()),
        };
        self.push_action(a, out);
    }

    fn unban(&mut self, net: Net, why: &str, severity: Severity, out: &mut Vec<Action>) {
        if self.bans.remove(&net).is_none() {
            return;
        }
        let a = Action {
            ts: self.now,
            kind: ActionKind::Unban,
            severity,
            target: Some(net),
            until: None,
            message: format!("unban {net}: {why}"),
            evidence: vec![],
            superseded: vec![],
            applied: false,
            topic: None,
            accounts: vec![],
            user_note: None,
            notice: None,
            category: None,
        };
        self.push_action(a, out);
    }

    // ---------------------------------------------------------------- events

    pub fn on_event(&mut self, ev: &Event) -> Vec<Action> {
        let mut out = Vec::new();
        self.now = self.now.max(ev.ts);
        *self.stats.events.entry(ev.signal).or_default() += 1;
        let src = ev.signal.source();
        self.silence.last_event.insert(src, self.now);
        self.silence.lines_since_event.insert(src, 0);
        if let Some(b) = self.stats.bucket(ev.ts) {
            b.count(src);
        }
        if let Some(h) = self.stats.hour(ev.ts) {
            h.events += 1;
        }
        if self.ips.len() >= self.cfg.scoring.max_tracked_ips {
            self.gc(true);
        }

        if ev.signal.is_success() {
            self.on_success(ev, &mut out);
            return out;
        }

        // A login to this service excuses its background noise; one to another service doesn't.
        // Blocked packets are excused by any recent login: their source address is forged with
        // a single SYN, or is a carrier NAT the user shares.
        let protected = self.hard_protection(ev.ip).is_some()
            || self.trusted_for(ev.ip, ev.signal.source())
            || (ev.signal.source() == Source::Ufw && self.is_trusted(ev.ip));
        let cfg = Arc::clone(&self.cfg);
        // a pattern of your own sets its own points
        let mut points = ev.points.unwrap_or_else(|| cfg.weight(ev.signal));
        if is_non_global(ev.ip) {
            return out;
        }
        if let (false, Some(port)) = (protected, ev.port) {
            *self.port_hits.entry(port).or_default() += 1;
            if let Some(cc) = self.geo.as_ref().and_then(|g| g.lookup(ev.ip).country) {
                let ports = self.port_hits_cc.entry(cc).or_default();
                // Spoofed UDP can name any port: bound the map, keep counting known ones.
                if ports.len() < COUNTRY_PORTS || ports.contains_key(&port) {
                    *ports.entry(port).or_default() += 1;
                }
            }
        }
        if protected
            && matches!(
                ev.signal,
                Signal::XmppConn
                    | Signal::XmppNoAuth
                    | Signal::XmppHttpMiss
                    | Signal::XmppTokenFail
                    | Signal::SshPreauth
                    | Signal::FwBlock
                    | Signal::FwTripwire
                    | Signal::TripwireConnect
            )
        {
            // Background noise from your own devices is expected; only real failures count.
            points = 0.0;
        }
        if ev.signal.is_canary() && ev.detail.starts_with(crate::event::CANARY_LOGIN) {
            // Somebody actually got into an account that must not exist / be used.
            self.alert_about(
                format!("canary-login:{}", ev.ip),
                MIN,
                Severity::Critical,
                Some(Net::host(ev.ip)),
                format!("{} from {} - check whether the account exists and lock it", ev.detail, ev.ip),
                Some(Topic::Compromise),
                vec![],
                None,
                &mut out,
            );
        }
        if ev.signal == Signal::XmppRegister {
            let acct = ev.account.clone().unwrap_or_default();
            self.alert_about(
                format!("register:{acct}"),
                MIN,
                Severity::Info,
                Some(Net::host(ev.ip)),
                format!("account {acct} registered from {}", ev.ip),
                Some(Topic::Registration),
                vec![format!("ejabberd:{acct}")],
                None,
                &mut out,
            );
        }
        if ev.signal.is_auth_failure() {
            if let Some(acct) = &ev.account {
                points *= self.track_account(ev, acct, &mut out);
            }
        }

        let now = self.now;
        let st = self.ips.entry(ev.ip).or_insert_with(|| Box::new(IpState { first_seen: ev.ts, updated: now, ..Default::default() }));
        st.advance(now, &cfg);
        st.counts.bump(ev.signal);
        st.last_seen = st.last_seen.max(ev.ts);
        if points > 0.0 {
            st.note(ev.ts, &ev.detail);
        }
        if let (true, Some(acct)) = (ev.signal.is_auth_failure(), &ev.account) {
            let key = format!("{}:{acct}", ev.signal.source().name());
            if st.targeted.len() < 32 || st.targeted.contains_key(&key) {
                *st.targeted.entry(key).or_default() += 1;
            }
        }

        let window = cfg.scoring.spread_window.micros();
        let mut bonus = 0.0;
        if let (Some(port), false) = (ev.port, protected) {
            if ev.signal.source() == Source::Ejabberd {
                let probe = st.probe.get_or_insert_with(Default::default);
                let n = distinct_ports(&mut probe.xmpp_ports, port, now, window);
                if n >= cfg.scoring.port_spread_ports && probe.spread_fired.is_none_or(|t| now - t >= window) {
                    probe.spread_fired = Some(now);
                    bonus += cfg.scoring.port_spread_bonus;
                    let ports: Vec<String> = probe.xmpp_ports.iter().map(|(p, _)| p.to_string()).collect();
                    st.note(ev.ts, &format!("probed XMPP ports {}", ports.join(",")));
                }
            } else if ev.signal.source() == Source::Ufw {
                let probe = st.probe.get_or_insert_with(Default::default);
                let n = distinct_ports(&mut probe.fw_ports, port, now, window);
                if n >= cfg.scoring.fw_scan_ports && probe.scan_fired.is_none_or(|t| now - t >= window) {
                    probe.scan_fired = Some(now);
                    bonus += cfg.scoring.fw_scan_bonus;
                    st.note(ev.ts, &format!("port scan: {n} closed ports"));
                }
            }
        }
        st.add(points + bonus);
        // What protection excuses here isn't for peers to ban on either.
        if !protected {
            st.report_points += points + bonus;
        }
        if points + bonus > 0.0 {
            *self.digest.points.entry(ev.ip).or_default() += points + bonus;
        }
        self.check_threshold(ev.ip, &mut out);
        out
    }

    // ---------------------------------------------------------------- cluster

    /// Starts collecting facts for the cluster; `peers` are never banned.
    pub fn enable_sharing(&mut self, peers: Vec<Net>) {
        self.outbox = Some(Vec::new());
        self.peer_nets = peers;
    }

    /// The peers' addresses after they were resolved again.
    pub fn set_peer_nets(&mut self, peers: Vec<Net>) {
        self.peer_nets = peers;
    }

    /// Facts produced since the last call; addresses this node scored at least
    /// `min_report_points` for since their last report are included as reports.
    pub fn take_outbox(&mut self, min_report_points: f64) -> Vec<FactBody> {
        let Some(mut facts) = self.outbox.take() else { return vec![] };
        let mut reports = Vec::new();
        for (ip, st) in self.ips.iter_mut() {
            if st.report_points >= min_report_points {
                let mut c: Vec<(Signal, u64)> = st.counts.iter().filter(|(s, _)| !s.is_success() && *s != Signal::PeerReport).collect();
                c.sort_by_key(|x| std::cmp::Reverse(x.1));
                let signals = c.iter().take(3).map(|(s, n)| format!("{n}x {}", s.name())).collect::<Vec<_>>().join(", ");
                let forgeable = firewall_only(c.iter().map(|(s, _)| *s));
                reports.push(FactBody::Report { ip: *ip, points: (st.report_points * 10.0).round() / 10.0, signals, forgeable });
                st.report_points = 0.0;
            }
        }
        facts.extend(reports.into_iter().filter(|r| matches!(r, FactBody::Report { ip, .. } if self.hard_protection(*ip).is_none())));
        self.outbox = Some(Vec::new());
        facts
    }

    /// Applies a fact learned from another node. Local protections always win.
    pub fn apply_peer_fact(&mut self, fact: &Fact, ccfg: &ClusterCfg) -> Vec<Action> {
        let mut out = Vec::new();
        // Peer timestamps never move our clock beyond the wall clock.
        let now = self.now.max(fact.created.min(crate::time::now()));
        self.now = now;
        let origin = &fact.origin;
        match &fact.body {
            FactBody::Ban { net, until, reason, forgeable } => {
                if self.wider_than_own_bans(net) {
                    return out;
                }
                let until = (*until).min(now + ccfg.max_remote_ban.micros());
                // (a forged packet there must not lock out someone who logged in here)
                let protected = self.net_protected(net)
                    || (net.is_host() && (self.hard_protection(net.addr).is_some() || (*forgeable && self.is_trusted(net.addr))));
                if until <= now || protected || self.covering_ban(net).is_some() {
                    return out;
                }
                let message = format!("ban {net} for {} (from peer {origin}): {reason}", crate::time::fmt_duration(until - now));
                self.insert_ban(
                    *net,
                    until,
                    0,
                    format!("peer {origin}: {reason}"),
                    Some(origin.clone()),
                    message,
                    vec![],
                    "from peers",
                    &mut out,
                );
            }
            FactBody::Unban { net, reason } => {
                self.unban(*net, &format!("lifted by peer {origin}: {reason}"), Severity::Info, &mut out);
            }
            FactBody::Report { ip, points, signals, forgeable } => {
                // NaN is rejected too; one report can't add more than a ban's worth.
                // (`min` would turn NaN into the threshold, so check first)
                let points = points * ccfg.report_factor;
                if points.is_nan() || points <= 0.0 || self.hard_protection(*ip).is_some() || (*forgeable && self.is_trusted(*ip)) {
                    return out;
                }
                let points = points.min(self.cfg.scoring.fast_threshold);
                let cfg = Arc::clone(&self.cfg);
                *self.stats.events.entry(Signal::PeerReport).or_default() += 1;
                if let Some(b) = self.stats.bucket(now) {
                    b.count(Source::Peer);
                }
                if let Some(h) = self.stats.hour(now) {
                    h.events += 1;
                }
                let st = self.ips.entry(*ip).or_insert_with(|| Box::new(IpState { first_seen: now, updated: now, ..Default::default() }));
                st.advance(now, &cfg);
                st.counts.bump(Signal::PeerReport);
                st.last_seen = st.last_seen.max(now);
                st.note(now, &format!("peer {origin}: {signals} (+{points:.0})"));
                st.add(points);
                self.check_threshold(*ip, &mut out);
            }
            // Sent by older nodes. Not accepted: a login on another server says nothing about
            // what an address does here, and would shield it from bans on every service.
            FactBody::Trust { .. } => {}
            FactBody::Allow { net, until, note } => {
                if self.too_wide(net) {
                    return out;
                }
                let until = (*until).min(now + ccfg.max_remote_ban.micros());
                if until <= now {
                    self.remove_allow(*net, &format!("revoked by peer {origin}"), &mut out);
                } else {
                    self.add_allow(*net, until, format!("peer {origin}: {note}"), &mut out);
                }
            }
            FactBody::Notice { subject, body } => {
                let a = Action {
                    ts: now,
                    kind: ActionKind::Alert,
                    severity: Severity::Info,
                    target: None,
                    until: None,
                    message: format!("[{origin}] {subject}"),
                    evidence: vec![],
                    superseded: vec![],
                    applied: false,
                    topic: Some(Topic::Relayed),
                    accounts: vec![],
                    user_note: Some(body.clone()),
                    notice: None,
                    category: None,
                };
                self.push_action(a, &mut out);
            }
        }
        out
    }

    // ---------------------------------------------------------------- operator

    fn add_allow(&mut self, net: Net, until: Micros, note: String, out: &mut Vec<Action>) {
        let lifted: Vec<Net> = self.bans.keys().filter(|b| net.contains_net(b)).copied().collect();
        for b in lifted {
            self.unban(b, &format!("allowlisted: {note}"), Severity::Info, out);
        }
        self.forget(&net);
        self.allowed.insert(net, OperAllow { net, until, note: note.clone() });
        let a = Action {
            ts: self.now,
            kind: ActionKind::Allow,
            severity: Severity::Info,
            target: Some(net),
            until: Some(until),
            message: format!("allow {net} for {}: {note}", crate::time::fmt_duration(until - self.now)),
            evidence: vec![],
            superseded: vec![],
            applied: false,
            topic: None,
            accounts: vec![],
            user_note: None,
            notice: None,
            category: None,
        };
        self.push_action(a, out);
    }

    fn remove_allow(&mut self, net: Net, why: &str, out: &mut Vec<Action>) -> bool {
        if self.allowed.remove(&net).is_none() {
            return false;
        }
        let a = Action {
            ts: self.now,
            kind: ActionKind::Disallow,
            severity: Severity::Info,
            target: Some(net),
            until: None,
            message: format!("allowlist entry {net} removed: {why}"),
            evidence: vec![],
            superseded: vec![],
            applied: false,
            topic: None,
            accounts: vec![],
            user_note: None,
            notice: None,
            category: None,
        };
        self.push_action(a, out);
        true
    }

    /// Clears scores and offence history inside `net`, so an operator decision sticks.
    fn forget(&mut self, net: &Net) {
        for (ip, st) in self.ips.iter_mut() {
            if net.contains(*ip) {
                st.fast = 0.0;
                st.slow = 0.0;
                st.report_points = 0.0;
            }
        }
        self.offenders.retain(|n, _| !net.contains_net(n));
    }

    /// `logguard unban`: lifts the ban on exactly `net` (or every ban inside it).
    pub fn operator_unban(&mut self, net: Net) -> Result<Vec<Action>, String> {
        let mut out = Vec::new();
        let targets: Vec<Net> =
            if self.bans.contains_key(&net) { vec![net] } else { self.bans.keys().filter(|b| net.contains_net(b)).copied().collect() };
        if targets.is_empty() {
            return Err(match self.covering_ban(&net) {
                Some(b) => format!("{net} is covered by the ban on {}; unban that, or allowlist {net}", b.net),
                None => format!("no active ban for {net}"),
            });
        }
        for t in targets {
            self.unban(t, "operator", Severity::Info, &mut out);
        }
        self.forget(&net);
        if let Some(ob) = self.outbox.as_mut() {
            ob.push(FactBody::Unban { net, reason: "operator".into() });
        }
        Ok(out)
    }

    /// `logguard allow`: never ban `net` until `until`; lifts current bans inside it.
    pub fn operator_allow(&mut self, net: Net, until: Micros, note: String) -> Vec<Action> {
        let mut out = Vec::new();
        self.add_allow(net, until, note.clone(), &mut out);
        if let Some(ob) = self.outbox.as_mut() {
            ob.push(FactBody::Allow { net, until, note });
        }
        out
    }

    /// `logguard disallow`: removes an operator allowlist entry.
    pub fn operator_disallow(&mut self, net: Net) -> Result<Vec<Action>, String> {
        let mut out = Vec::new();
        if !self.remove_allow(net, "operator", &mut out) {
            return Err(format!("{net} is not on the operator allowlist"));
        }
        if let Some(ob) = self.outbox.as_mut() {
            ob.push(FactBody::Allow { net, until: self.now, note: "revoked".into() });
        }
        Ok(out)
    }

    pub fn allowed(&self) -> Vec<OperAllow> {
        self.allowed.values().cloned().collect()
    }

    /// `logguard ban`: bans `net` until `until`, shared with the peers like a ban decided here.
    /// Refused for protected addresses (this host, peers, allowlists) and networks wider than
    /// logguard bans itself.
    pub fn operator_ban(&mut self, net: Net, until: Micros, note: String) -> Result<Vec<Action>, String> {
        let mut out = Vec::new();
        let now = self.now;
        if self.wider_than_own_bans(&net) {
            return Err(format!("{net} is wider than logguard's own bans: use a blocklist feed ([feeds]) for that"));
        }
        let why = if net.is_host() {
            self.hard_protection(net.addr)
        } else {
            self.net_protected(&net).then_some("protected: an allowlisted, peer, own or recently logged-in address is inside")
        };
        if let Some(why) = why {
            return Err(format!("{net} is {why}; not banned (an operator allowlist entry: `logguard disallow` it first)"));
        }
        if let Some(b) = self.covering_ban(&net).filter(|b| b.net != net) {
            return Err(format!("{net} is inside the ban on {} already", b.net));
        }
        // nftables keeps an element's timeout when it is added again: lift the old ban first
        if self.bans.contains_key(&net) {
            self.unban(net, "replaced by an operator ban", Severity::Info, &mut out);
        }
        let forgive = self.cfg.bans.forgive_after.micros();
        let off = self.offenders.entry(net).or_default();
        if now - off.last_ban > forgive {
            off.count = 0;
        }
        off.count += 1;
        off.last_ban = now;
        let offence = off.count;
        let reason = format!("operator: {note}");
        if let Some(ob) = self.outbox.as_mut() {
            ob.push(FactBody::Ban { net, until, reason: reason.clone(), forgeable: false });
        }
        let place = self.place(net.addr).map(|p| format!(" [{p}]")).unwrap_or_default();
        let message = format!("ban {net}{place} for {} (operator): {note}", crate::time::fmt_duration(until - now));
        self.insert_ban(net, until, offence, reason, None, message, vec![], "operator", &mut out);
        Ok(out)
    }

    /// The bans `[waf]` source `source` holds now (decided here, not relayed by peers).
    pub fn waf_bans(&self, source: &str) -> Vec<Net> {
        let prefix = crate::waf::reason_prefix(source);
        self.bans.values().filter(|b| b.origin.is_none() && b.reason.starts_with(&prefix)).map(|b| b.net).collect()
    }

    /// Makes the bans of an `action = "ban"` source what its `decisions` are now: a ban for
    /// each, as long as it lasts (`[waf] default_ban` if it doesn't say, `max_ban` at most),
    /// lifted when the source drops it. Protected as an operator ban is, and recent logins
    /// too: a WAF's mistake about an address must not lock out someone who just logged in.
    /// Returns the actions and how many decisions made no ban (protected, too wide).
    pub fn waf_sync(&mut self, src: &crate::waf::WafSource, decisions: &[crate::waf::Decision]) -> (Vec<Action>, usize) {
        let mut out = Vec::new();
        let now = self.now;
        let name = &src.name;
        let (default_ban, max_ban) = (self.cfg.waf.default_ban.micros(), self.cfg.waf.max_ban.micros());
        let current: Vec<crate::waf::Decision> = decisions.iter().filter(|d| d.until.is_none_or(|u| u > now)).cloned().collect();
        let wanted = crate::waf::by_net(&current);
        for net in self.waf_bans(name).into_iter().filter(|n| !wanted.contains_key(n)) {
            let why = format!("lifted by waf {name}");
            self.unban(net, &why, Severity::Info, &mut out);
            if let Some(ob) = self.outbox.as_mut().filter(|_| src.share) {
                ob.push(FactBody::Unban { net, reason: why });
            }
        }
        let mut skipped = 0;
        for (net, d) in wanted {
            let until = d.until.unwrap_or(now + default_ban).min(now + max_ban);
            if until <= now {
                continue;
            }
            // Blocked for long enough already (by this ban, or a wider one). An end moves by
            // seconds between reads, and a list without durations asks for `default_ban` from
            // now each time: renewed only once less than half of it is left.
            if let Some(b) = self.covering_ban(&net) {
                if b.until - now >= (until - now) / 2 {
                    continue;
                }
                if b.net != net {
                    continue; // inside a wider ban ending sooner: banned on its own after it
                }
            }
            let protected = if net.is_host() { self.protection(net.addr).is_some() } else { self.net_protected(&net) };
            if protected || self.wider_than_own_bans(&net) {
                skipped += 1;
                continue;
            }
            // nftables keeps an element's timeout when it is added again: lift the old ban first
            if self.bans.contains_key(&net) {
                self.unban(net, &format!("renewed by waf {name}"), Severity::Info, &mut out);
            }
            let forgive = self.cfg.bans.forgive_after.micros();
            let off = self.offenders.entry(net).or_default();
            if now - off.last_ban > forgive {
                off.count = 0;
            }
            off.count += 1;
            off.last_ban = now;
            let offence = off.count;
            let why = if d.reason.is_empty() { "decision".to_string() } else { d.reason.clone() };
            let reason = format!("{}{why}", crate::waf::reason_prefix(name));
            if let Some(ob) = self.outbox.as_mut().filter(|_| src.share) {
                ob.push(FactBody::Ban { net, until, reason: reason.clone(), forgeable: false });
            }
            let place = self.place(net.addr).map(|p| format!(" [{p}]")).unwrap_or_default();
            let message = format!("ban {net}{place} for {} (waf {name}): {why}", crate::time::fmt_duration(until - now));
            let evidence = [&d.kind, &d.origin]
                .iter()
                .any(|s| !s.is_empty())
                .then(|| format!("{name} decision: type {}, origin {}", d.kind, d.origin))
                .into_iter()
                .collect();
            self.insert_ban(net, until, offence, reason, None, message, evidence, "waf", &mut out);
        }
        (out, skipped)
    }

    /// The addresses `[allowlist] hosts` resolve to now. A newly allowlisted address's ban is
    /// lifted and its score forgotten, as for `logguard allow`.
    pub fn set_allow_hosts(&mut self, nets: Vec<Net>) -> Vec<Action> {
        let mut out = Vec::new();
        let added: Vec<Net> = nets.iter().filter(|n| !self.allow_hosts.contains(n)).copied().collect();
        self.allow_hosts = nets;
        for n in added {
            let lifted: Vec<Net> = self.bans.keys().filter(|b| n.contains_net(b)).copied().collect();
            for b in lifted {
                self.unban(b, "allowlisted host name", Severity::Info, &mut out);
            }
            self.forget(&n);
        }
        out
    }

    /// A public-key SSH login: a key the account never used before is reported, after the
    /// account's keys were learned for `learning_period`.
    fn check_ssh_key(&mut self, who: &str, key: &str, ev: &Event, out: &mut Vec<Action>) {
        let now = self.now;
        if !self.ssh_keys.contains_key(who) && self.ssh_keys.len() >= MAX_KEY_ACCOUNTS {
            return;
        }
        let learn = self.cfg.accounts.learning_period.micros();
        let known = self.ssh_keys.entry(who.to_string()).or_insert_with(|| SshKeys { since: now, keys: BTreeSet::new() });
        if known.keys.contains(key) {
            return;
        }
        let learning = now - known.since < learn;
        if known.keys.len() < MAX_KEYS {
            known.keys.insert(key.to_string());
            self.changes += 1;
        }
        if learning {
            return;
        }
        let n = self.ssh_keys.get(who).map_or(0, |k| k.keys.len());
        self.alert_about(
            format!("newkey:{who}:{key}"),
            86_400 * crate::time::SEC,
            Severity::High,
            Some(Net::host(ev.ip)),
            format!(
                "{who} logged in from {} with an SSH key it never used before ({key}; {n} keys known now) - if nobody here added \
                 one, its authorized_keys may have been changed",
                self.ip_place(ev.ip)
            ),
            Some(Topic::Compromise),
            vec![who.to_string()],
            None,
            out,
        );
    }

    /// An `su` or `sudo` line: a failure is high (someone has the account and tries for the
    /// target), a success right after failures a warning, any other success only logged.
    /// Failures count, and alert, per user, whatever the target: any local user can try every
    /// account there is (or a made-up one, see `parse::privilege`), and must not be able to
    /// use up the hourly messages about compromises that way.
    pub fn on_privilege(&mut self, sw: &crate::parse::privilege::Switch, ts: Micros) -> Vec<Action> {
        let mut out = Vec::new();
        self.now = self.now.max(ts);
        let now = self.now;
        let window = 30 * MIN;
        let key = sw.user.clone();
        let from = match self.last_ssh.get(&sw.user) {
            Some((ip, t)) => format!(" ({}'s last SSH login: {}, {} ago)", sw.user, self.ip_place(*ip), crate::time::fmt_duration(now - t)),
            None => String::new(),
        };
        let tty = if sw.tty.is_empty() { String::new() } else { format!(" on {}", sw.tty) };
        let what = sw.what.as_deref().map(|w| format!(" ({w})")).unwrap_or_default();
        let (tool, user, target) = (sw.tool, &sw.user, &sw.target);
        if !sw.ok {
            if self.priv_fails.len() >= 1000 {
                self.priv_fails.retain(|_, f| now - f.2 < window);
            }
            let f = self.priv_fails.entry(key.clone()).or_insert((0, now, now));
            if now - f.2 >= window {
                *f = (0, now, now);
            }
            f.0 += 1;
            f.2 = now;
            let times = if f.0 > 1 { format!(", {} failures in {}", f.0, crate::time::fmt_duration(now - f.1)) } else { String::new() };
            self.alert_about(
                format!("priv-fail:{key}"),
                10 * MIN,
                Severity::High,
                None,
                format!(
                    "{tool} to {target} failed for {user}{tty}{what}{times}{from} - if it wasn't you, someone has {user}'s login \
                     and is trying for {target}"
                ),
                Some(Topic::Compromise),
                vec![],
                None,
                &mut out,
            );
            return out;
        }
        match self.priv_fails.remove(&key).filter(|f| now - f.2 < window) {
            Some((n, _, _)) => self.alert_about(
                format!("priv-after:{key}"),
                MIN,
                Severity::Warning,
                None,
                format!("{tool} to {target} by {user}{tty} succeeded after {n} failed attempts{from}"),
                Some(Topic::Compromise),
                vec![],
                None,
                &mut out,
            ),
            // the admin's own way in: on record (dashboard, actions log), not a message
            None => self.alert_about(
                format!("priv-ok:{key}"),
                0,
                Severity::Info,
                None,
                format!("{tool} to {target} by {user}{tty}{what}{from}"),
                None,
                vec![],
                None,
                &mut out,
            ),
        }
        out
    }

    /// A PAM, account tool or audit line (see `parse::auth`). A failed login at the console,
    /// a desktop, polkit or the web console is high, like a failed `su`; elsewhere on record
    /// only, unless it came from the internet, where its event scores the address instead.
    /// Failures count per service and who asked (polkit's user) or where (the terminal): a
    /// local user trying every account there is can't use up the hour's messages.
    pub fn on_auth(&mut self, a: &crate::parse::auth::Auth, ts: Micros) -> Vec<Action> {
        use crate::parse::auth::{Auth, Rhost};
        let mut out = Vec::new();
        self.now = self.now.max(ts);
        let now = self.now;
        let f = match a {
            Auth::Notice(n) => {
                let topic = (n.severity > Severity::Info).then_some(n.topic);
                self.alert_about(format!("auth:{}", n.key), n.every, n.severity, None, n.message.clone(), topic, vec![], None, &mut out);
                return out;
            }
            Auth::Failure(f) => f,
        };
        let place = match &f.rhost {
            Rhost::Addr(ip) if !is_non_global(*ip) => return out,
            Rhost::Addr(ip) => format!(" from {ip}"),
            Rhost::Name(h) => format!(" from {h}"),
            Rhost::Unclear => " from an unclear address (the line names more than one remote host)".into(),
            Rhost::Local if f.tty.is_empty() => String::new(),
            Rhost::Local => format!(" on {}", f.tty),
        };
        let who = [&f.ruser, &f.tty].into_iter().find(|w| !w.is_empty()).map_or("-", |w| w.as_str());
        let key = format!("{}:{who}", f.service);
        let window = 30 * MIN;
        if self.auth_fails.len() >= 1000 {
            self.auth_fails.retain(|_, c| now - c.2 < window);
        }
        let c = self.auth_fails.entry(key.clone()).or_insert((0, now, now));
        // PAM's line and the audit record of the same failure come within a moment
        if c.0 > 0 && now - c.2 < crate::time::SEC {
            return out;
        }
        if now - c.2 >= window {
            *c = (0, now, now);
        }
        c.0 += 1;
        c.2 = now;
        let times = if c.0 > 1 { format!(", {} failures in {}", c.0, crate::time::fmt_duration(now - c.1)) } else { String::new() };
        let asked = if f.ruser.is_empty() { String::new() } else { format!(" for {}", f.ruser) };
        let last = match self.last_ssh.get(&f.ruser) {
            Some((ip, t)) => format!(" ({}'s last SSH login: {}, {} ago)", f.ruser, self.ip_place(*ip), crate::time::fmt_duration(now - t)),
            None => String::new(),
        };
        let (service, user) = (&f.service, &f.user);
        let message = format!("login as {user}{place} failed ({service}){asked}{times}{last}");
        if crate::parse::auth::console_service(service) {
            let message = format!("{message} - if it wasn't you, someone is trying {user}'s password");
            self.alert_about(
                format!("auth-fail:{key}"),
                10 * MIN,
                Severity::High,
                None,
                message,
                Some(Topic::Compromise),
                vec![],
                None,
                &mut out,
            );
        } else {
            self.alert_about(format!("auth-fail:{key}"), 10 * MIN, Severity::Info, None, message, None, vec![], None, &mut out);
        }
        out
    }

    /// Up to `max` files waiting for the scan of changed files, oldest first.
    pub fn take_scans(&mut self, max: usize) -> Vec<crate::filescan::Job> {
        let n = max.min(self.scan_queue.len());
        self.scan_queue.drain(..n).collect()
    }

    /// A scan of changed files (see `filescan`): an alert for each infected file, a warning
    /// when a scanner failed, and the scan itself on record.
    pub fn on_file_scan(&mut self, r: &crate::filescan::ScanReport) -> Vec<Action> {
        let day = 86_400 * crate::time::SEC;
        let finding = |key: String, every, severity, message: String, evidence: Vec<String>, notify, owner| crate::cronwatch::Finding {
            key,
            every,
            severity,
            message,
            evidence,
            notify,
            owner,
            files: vec![],
        };
        let mut found = Vec::new();
        for f in r.infected() {
            found.push(finding(
                format!("scan-hit:{}:{}", f.path, f.hits.join(",")),
                day,
                Severity::High,
                format!(
                    "malware in {}: {} (it was scanned because: {}) - if nobody here put it there, the server may be compromised: \
                     move it aside, and find out how it got there",
                    f.path,
                    f.hits.join("; "),
                    f.why
                ),
                f.hits.clone(),
                true,
                // a user's own file: their alert budget (a flood of test signatures is theirs)
                f.owner,
            ));
        }
        for e in &r.errors {
            let short: String = e.chars().take(60).collect();
            found.push(finding(
                format!("scan-error:{short}"),
                day,
                Severity::Warning,
                format!("scan of changed files: {e}"),
                vec![],
                true,
                None,
            ));
        }
        let infected = r.infected().count();
        let skipped = r.files.iter().filter(|f| f.hits.is_empty() && f.note.is_some()).count();
        let scanned = r.files.len() - r.files.iter().filter(|f| f.note.as_deref().is_some_and(|n| n.starts_with("not scanned"))).count();
        let with = if r.scanners.is_empty() { String::new() } else { format!(" with {}", r.scanners) };
        let result = match (infected, skipped) {
            (0, 0) => "nothing found".to_string(),
            (0, s) => format!("nothing found, {s} not scanned or unreadable"),
            (i, 0) => format!("{i} infected"),
            (i, s) => format!("{i} infected, {s} not scanned or unreadable"),
        };
        let evidence = r
            .files
            .iter()
            .take(50)
            .map(|f| match (&f.hits[..], &f.note) {
                ([], None) => format!("{}: clean", f.path),
                ([], Some(n)) => format!("{}: {n}", f.path),
                (h, _) => format!("{}: {}", f.path, h.join("; ")),
            })
            .collect();
        found.push(finding(
            format!("scan:{}", r.finished),
            0,
            Severity::Info,
            format!("scanned {scanned} of {} changed files{with}: {result}", r.files.len()),
            evidence,
            false,
            None,
        ));
        self.findings(found, r.finished)
    }

    /// The latest `[patches]` reading (shown in the digest and the dashboard).
    pub fn on_patches(&mut self, r: crate::patches::PatchReport) {
        self.patches = Some(r);
    }

    /// When the last package and set-uid check finished (0: never), for scheduling the next.
    pub fn verify_last_run(&self) -> Micros {
        self.verify.as_ref().map_or(0, |b| b.last_run)
    }

    /// A package and set-uid check (see `verify`).
    pub fn on_verify(&mut self, r: &crate::verify::VerifyReport) -> Vec<Action> {
        let findings = crate::verify::judge(&mut self.verify, r);
        self.verify_view = Some(crate::verify::VerifyView {
            last_run: r.finished,
            checked: r.checked,
            mismatched: r.mismatched.len(),
            suid: r.suid.len(),
        });
        self.changes += 1;
        self.findings(findings, r.finished)
    }

    /// An SSH hardening audit (see `sshaudit`).
    pub fn on_ssh_audit(&mut self, r: crate::sshaudit::SshAuditReport) -> Vec<Action> {
        let before = self.ssh_audit.clone();
        let findings = crate::sshaudit::judge(&mut self.ssh_audit, &r, &self.cfg.ssh_audit);
        if before != self.ssh_audit {
            self.changes += 1;
        }
        let wall = r.read;
        self.ssh_audit_last = Some(r);
        self.findings(findings, wall)
    }

    /// A process watch scan (see `procwatch`).
    pub fn on_procwatch(&mut self, r: &crate::procwatch::ProcReport) -> Vec<Action> {
        let geo = self.geo.clone();
        let place = move |ip: IpAddr| geo.as_ref().and_then(|g| g.label(ip));
        let state = |b: &Option<crate::procwatch::ProcBaseline>| b.as_ref().map(|b| (b.pairs.len(), b.armed));
        let before = state(&self.procwatch);
        let findings = crate::procwatch::judge(&mut self.procwatch, r, &self.cfg.procwatch, &place);
        if state(&self.procwatch) != before {
            self.changes += 1;
        }
        if r.available {
            self.proc_view = self.procwatch.as_ref().map(|b| crate::procwatch::ProcView {
                scanned: r.scanned,
                learning_until: b.learning_until,
                pairs: b.pairs.len(),
                outbound: r.outbound.len(),
            });
        }
        self.findings(findings, r.scanned)
    }

    /// Closes the current digest period and starts a new one.
    pub fn digest_take(&mut self, now: Micros) -> DigestData {
        self.now = self.now.max(now);
        let data = self.digest_preview();
        self.digest = DigestStats { since: self.now, events_base: self.stats.events.clone(), ..Default::default() };
        data
    }

    /// The digest of the current period so far, without closing it.
    pub fn digest_preview(&self) -> DigestData {
        let d = self.digest.clone();
        let events = self
            .stats
            .events
            .iter()
            .map(|(s, n)| (*s, n.saturating_sub(d.events_base.get(s).copied().unwrap_or(0))))
            .filter(|(_, n)| *n > 0)
            .collect();
        let mut top: Vec<(IpAddr, f64)> = d.points.into_iter().collect();
        top.sort_by(|a, b| b.1.total_cmp(&a.1));
        top.truncate(10);
        DigestData {
            since: d.since,
            until: self.now,
            bans_by_category: d.bans_by_category,
            alerts_by_topic: d.alerts_by_topic,
            attention: d.attention,
            events,
            top: top.into_iter().map(|(ip, p)| (ip, p, self.banned_by(ip).map(|b| b.net), self.place(ip))).collect(),
        }
    }

    /// Returns the weight multiplier for a failure against `acct`.
    fn track_account(&mut self, ev: &Event, acct: &str, out: &mut Vec<Action>) -> f64 {
        let now = self.now;
        let cfg = Arc::clone(&self.cfg);
        let half = cfg.accounts.half_life.micros();
        let key = format!("{}:{acct}", ev.signal.source().name());
        if self.accounts.len() >= MAX_ACCOUNTS && !self.accounts.contains_key(&key) {
            return 1.0; // a spray of random names: per-address scoring still applies
        }
        let st = self.accounts.entry(key.clone()).or_default();
        st.score = decay(st.score, now - st.updated, half) + 1.0;
        st.updated = now;
        st.ips.retain(|_, t| now - *t < 2 * half); // at most MAX_ACCOUNT_IPS entries
        if st.ips.len() < MAX_ACCOUNT_IPS || st.ips.contains_key(&ev.ip) {
            st.ips.insert(ev.ip, now);
        }
        let (score, n_ips) = (st.score, st.ips.len());
        if score >= cfg.accounts.alert_failures && n_ips >= cfg.accounts.min_ips && st.alerted.is_none_or(|t| now - t >= half) {
            st.alerted = Some(now);
            st.under_attack_until = now + 2 * half;
            let note = UserNotice::AccountAttack { failures: score.round() as u32, addresses: n_ips };
            self.alert_about(
                format!("account:{key}"),
                half,
                Severity::High,
                None,
                format!("account {key} under distributed attack: ~{score:.0} failures from {n_ips} addresses"),
                Some(Topic::AccountAttack),
                self.notifiable(vec![key.clone()]),
                Some(note),
                out,
            );
        }
        let st = &self.accounts[&key];
        if now < st.under_attack_until {
            cfg.accounts.under_attack_multiplier
        } else {
            1.0
        }
    }

    fn on_success(&mut self, ev: &Event, out: &mut Vec<Action>) {
        let cfg = Arc::clone(&self.cfg);
        let now = self.now;
        let acct = ev.account.clone().unwrap_or_else(|| "?".into());
        let who = format!("{}:{acct}", ev.signal.source().name());

        if let Some(st) = self.ips.get_mut(&ev.ip) {
            st.advance(now, &cfg);
            st.counts.bump(ev.signal);
            st.last_seen = st.last_seen.max(ev.ts);
            let fast = st.fast;
            if fast >= cfg.scoring.compromise_score
                && st.auth_failures() > 0
                && self.hard_protection(ev.ip).is_none()
                && !self.trusted_for(ev.ip, ev.signal.source())
            {
                let note = UserNotice::Compromise { ip: ev.ip, place: self.place(ev.ip), at: ev.ts };
                self.alert_about(
                    format!("compromise:{}:{who}", ev.ip),
                    30 * MIN,
                    Severity::Critical,
                    Some(Net::host(ev.ip)),
                    format!(
                        "{who} logged in from {} right after suspicious activity (score {fast:.0}) - possible compromise",
                        self.ip_place(ev.ip)
                    ),
                    Some(Topic::Compromise),
                    vec![who.clone()],
                    Some(note),
                    out,
                );
            }
        }

        if let Some(ban) = self.banned_by(ev.ip).cloned() {
            // In shadow mode this is a would-be false positive: lifted, here and at the peers.
            // In enforce mode a banned address can't connect (unless through a whitelisted port,
            // or a ban the firewall didn't take), and a line saying it logged in may be forged:
            // the ban stays and the operator decides.
            let lift = ban.net.is_host() && ev.verified && cfg.mode == crate::config::Mode::Shadow;
            let what =
                if lift { "likely false positive, lifting ban" } else { "ban kept: `logguard unban` it if this is a false positive" };
            self.alert_about(
                format!("fp:{}", ev.ip),
                MIN,
                Severity::Warning,
                Some(ban.net),
                format!("{who} authenticated from banned address {} (ban: {}) - {what}", ev.ip, ban.reason),
                Some(Topic::FalsePositive),
                vec![who.clone()],
                None,
                out,
            );
            if lift {
                self.unban(ban.net, "successful authentication", Severity::Warning, out);
                if let Some(ob) = self.outbox.as_mut() {
                    ob.push(FactBody::Unban { net: ban.net, reason: format!("{who} authenticated from it") });
                }
            }
        }

        // Accounts seen logging in are real: only they get security notices (an attacker can
        // fail logins against any made-up name on the domain).
        let first_seen = match ev.account {
            Some(_) if self.account_first_seen.len() < MAX_ACCOUNTS => *self.account_first_seen.entry(who.clone()).or_insert(now),
            _ => self.account_first_seen.get(&who).copied().unwrap_or(now),
        };
        // (only for the accounts kept above: their networks and providers are bounded alike)
        if cfg.accounts.new_network_alerts
            && ev.account.is_some()
            && !cfg.accounts.new_network_ignore.contains(&acct)
            && self.account_first_seen.contains_key(&who)
        {
            let net = Net::new(ev.ip, if ev.ip.is_ipv4() { 16 } else { 48 });
            let learning = now - first_seen < cfg.accounts.learning_period.micros();
            let nets = self.account_nets.entry(who.clone()).or_default();
            let fresh = !nets.contains(&net);
            if fresh && nets.len() < 256 {
                nets.insert(net);
                self.changes += 1;
            }
            // With a geo database, the provider decides: mobile carriers and VPN services hand
            // out addresses from many /16s, and a new one of a known provider is no news.
            let asn = self.geo.as_ref().and_then(|g| g.asn(ev.ip));
            let known_provider = asn.is_some_and(|a| {
                let asns = self.account_asns.entry(who.clone()).or_default();
                let known = asns.contains(&a);
                if asns.len() < 64 {
                    asns.insert(a);
                }
                known
            });
            if fresh && !learning && !known_provider {
                let place = self.place(ev.ip);
                let note = UserNotice::NewLogin { ip: ev.ip, place: place.clone(), network: net, at: ev.ts };
                let message = match &place {
                    Some(p) => format!("{who} logged in from a new network: {p} - {} ({net})", ev.ip),
                    None => format!("{who} logged in from a new network {net} ({})", ev.ip),
                };
                self.alert_about(
                    format!("newnet:{who}:{net}"),
                    86_400 * crate::time::SEC,
                    Severity::Info,
                    Some(Net::host(ev.ip)),
                    message,
                    Some(Topic::NewNetwork),
                    vec![who.clone()],
                    Some(note),
                    out,
                );
            }
        }

        if ev.signal == Signal::SshAuthOk && ev.verified {
            if let Some(user) = &ev.account {
                if self.last_ssh.len() < MAX_KEY_ACCOUNTS || self.last_ssh.contains_key(user) {
                    self.last_ssh.insert(user.clone(), (ev.ip, ev.ts));
                }
            }
            if let (Some(key), true) = (&ev.key, cfg.accounts.new_key_alerts) {
                self.check_ssh_key(&who, key, ev, out);
            }
        }

        if cfg.allowlist.trust_authenticated && ev.verified {
            // Only for this service, and never shared with peers (see `apply_peer_fact`).
            let previous = self.trusted.entry(ev.ip).or_default().insert(ev.signal.source(), now);
            // Refreshing a trust that is less than an hour old isn't worth a save.
            if previous.is_none_or(|t| now - t >= 3600 * crate::time::SEC) {
                self.changes += 1;
            }
        }
    }

    fn check_threshold(&mut self, ip: IpAddr, out: &mut Vec<Action>) {
        let cfg = Arc::clone(&self.cfg);
        let Some(st) = self.ips.get(&ip) else { return };
        let (fast, slow) = (st.fast, st.slow);
        let burst = fast >= cfg.scoring.fast_threshold;
        if !burst && slow < cfg.scoring.slow_threshold {
            return;
        }
        if self.banned_by(ip).is_some() {
            return;
        }
        let kind = if burst { "burst" } else { "sustained" };
        let mut counts: Vec<(Signal, u64)> = st.counts.iter().filter(|(s, _)| !s.is_success()).collect();
        counts.sort_by_key(|c| std::cmp::Reverse(c.1));
        let summary: Vec<String> = counts.iter().take(4).map(|(s, n)| format!("{n}x {}", s.name())).collect();
        let reason = format!("{kind} score fast={fast:.0} slow={slow:.0} [{}]", summary.join(", "));
        let evidence: Vec<String> = st.evidence.lines().map(String::from).collect();
        if let Some(why) = self.shield(ip, st) {
            self.alert_about(
                format!("protected:{ip}"),
                60 * MIN,
                Severity::Warning,
                Some(Net::host(ip)),
                format!("{ip} is {why} but crossed the ban threshold: {reason}"),
                Some(Topic::Protected),
                st.targeted.keys().cloned().collect(),
                None,
                out,
            );
            return;
        }
        let targeted: Vec<(String, u32)> = st.targeted.iter().map(|(k, n)| (k.clone(), *n)).collect();
        let category = counts.first().map_or("other", |(s, _)| category_of(*s));
        let forgeable = firewall_only(counts.iter().map(|(s, _)| *s));
        self.ban(Net::host(ip), reason, evidence, category, forgeable, out);
        if !targeted.is_empty() {
            if let Some(a) = out.last_mut().filter(|a| a.kind == ActionKind::Ban) {
                a.topic = Some(Topic::BruteForce);
                let notice = UserNotice::BruteForce { ip, attempts: targeted.iter().cloned().collect() };
                a.user_note = Some(crate::i18n::note(&notice, crate::i18n::Lang::En, None));
                a.notice = Some(notice);
                a.accounts = self.notifiable(targeted.into_iter().map(|(k, _)| k).collect());
                if let Some(r) = self.recent.back_mut() {
                    *r = a.clone();
                }
            }
        }
    }

    // ---------------------------------------------------------------- exposure

    /// Compares an exposure scan with the learned baseline. New exposed listeners must be
    /// seen in 2 consecutive scans and vanished ones missing from 3 before alerting, so
    /// service restarts don't flap.
    pub fn on_exposure(&mut self, report: ExposureReport, ufw_expected: bool) -> Vec<Action> {
        let mut out = Vec::new();
        self.now = self.now.max(report.scanned);
        let day = 86_400 * crate::time::SEC;
        // After a (re)start, services may still be coming up: watch, but don't judge yet.
        // `started` is 0 in replays and tests, where there is no grace period.
        let ecfg = &self.cfg.exposure;
        if self.started > 0 && report.scanned - self.started < ecfg.startup_grace.micros() {
            self.exposure_last = Some(report);
            return out;
        }
        let (new_after, gone_after) = (ecfg.new_after_scans.max(1), ecfg.gone_after_scans.max(1));
        let exposed: BTreeMap<ListenerKey, String> = report
            .listeners
            .iter()
            .filter(|l| l.exposure.is_exposed() && !l.dynamic && !l.honeypot)
            .map(|l| (l.key, l.process.clone()))
            .collect();
        let fw = report.firewall();
        let describe = |k: &ListenerKey| report.listeners.iter().find(|l| l.key == *k).map_or(String::new(), |l| l.describe(fw));

        // ufw switched off with nothing else filtering (iptables rules of their own are read too)
        if ufw_expected && report.ufw_active == Some(false) && fw == Firewall::Absent {
            self.alert_about(
                "ufw-inactive".into(),
                day,
                Severity::High,
                None,
                "ufw is inactive: every listening port is reachable".into(),
                Some(Topic::Exposure),
                vec![],
                None,
                &mut out,
            );
        }
        // Like a gone listener, a rule is only dead after `gone_after` scans in a row: while
        // containers are recreated their published ports vanish for a minute or two.
        self.dead_pending.retain(|r, _| report.dead_rules.contains(r));
        for rule in &report.dead_rules {
            let scans = self.dead_pending.entry(rule.clone()).or_default();
            *scans += 1;
            if *scans < gone_after {
                continue;
            }
            self.alert_about(
                format!("deadrule:{rule}"),
                day,
                Severity::Warning,
                None,
                format!(
                    "{} allows {rule} from anywhere, but nothing listens on it publicly - remove the rule or it exposes whatever binds there next",
                    fw.name()
                ),
                Some(Topic::Exposure),
                vec![],
                None,
                &mut out,
            );
        }

        // A baseline learned under another firewall counts other listeners as exposed: learn
        // it again rather than report what the change hid or opened as gone or new. One from
        // a version that read only ufw saw an active ufw, or nothing.
        let learned_under = self.exposure_firewall.unwrap_or(if fw == Firewall::Iptables { Firewall::Absent } else { fw });
        let relearn = self.exposure_baseline.is_some() && learned_under != fw;
        if relearn {
            self.exposure_baseline = None;
            self.exposure_pending.clear();
        }
        self.exposure_firewall = Some(fw);
        match self.exposure_baseline.as_mut() {
            None => {
                let list: Vec<String> = exposed.iter().map(|(k, p)| format!("{k} ({p})")).collect();
                self.exposure_baseline = Some(exposed.iter().map(|(k, p)| (*k, (p.clone(), 0))).collect());
                let (key, why) = if relearn {
                    ("exposure-relearned", format!(" (learned again: the firewall is now {})", fw.name()))
                } else {
                    ("exposure-learned", String::new())
                };
                self.alert_about(
                    key.into(),
                    day,
                    Severity::Info,
                    None,
                    format!("exposure baseline learned{why}: {} exposed listeners: {}", list.len(), list.join(", ")),
                    Some(Topic::Exposure),
                    vec![],
                    None,
                    &mut out,
                );
            }
            Some(baseline) => {
                let mut new_ones = Vec::new();
                for (k, p) in &exposed {
                    if baseline.contains_key(k) {
                        continue;
                    }
                    let seen = self.exposure_pending.entry(*k).or_default();
                    *seen += 1;
                    if *seen >= new_after {
                        new_ones.push((*k, p.clone()));
                    }
                }
                self.exposure_pending.retain(|k, _| exposed.contains_key(k) && !new_ones.iter().any(|(n, _)| n == k));
                let mut gone = Vec::new();
                for (k, (p, misses)) in baseline.iter_mut() {
                    if exposed.contains_key(k) {
                        *misses = 0;
                    } else {
                        *misses += 1;
                        if *misses >= gone_after {
                            gone.push((*k, p.clone()));
                        }
                    }
                }
                for (k, p) in &new_ones {
                    baseline.insert(*k, (p.clone(), 0));
                }
                for (k, _) in &gone {
                    baseline.remove(k);
                }
                for (k, p) in new_ones {
                    let how = describe(&k);
                    self.alert_about(
                        format!("newlistener:{k}"),
                        MIN,
                        Severity::Warning,
                        None,
                        format!("new internet-facing listener {k} ({p}, {how})"),
                        Some(Topic::Exposure),
                        vec![],
                        None,
                        &mut out,
                    );
                }
                for (k, p) in gone {
                    self.alert_about(
                        format!("gonelistener:{k}"),
                        MIN,
                        Severity::Warning,
                        None,
                        format!("internet-facing listener {k} ({p}) is gone - service stopped?"),
                        Some(Topic::Exposure),
                        vec![],
                        None,
                        &mut out,
                    );
                }
            }
        }
        self.exposure_last = Some(report);
        out
    }

    // ---------------------------------------------------------------- periodic

    /// Expires bans, aggregates subnets and collects garbage. Call about once a second.
    pub fn tick(&mut self, now: Micros) -> Vec<Action> {
        let mut out = Vec::new();
        self.now = self.now.max(now);
        self.halve_ports();
        let expired: Vec<Net> = self.bans.values().filter(|b| b.until <= self.now).map(|b| b.net).collect();
        for net in expired {
            let inner = self.bans.get_mut(&net).map(|b| std::mem::take(&mut b.inner)).unwrap_or_default();
            self.unban(net, "ban expired", Severity::Info, &mut out);
            let now = self.now;
            for b in inner.into_iter().filter(|b| b.until > now) {
                // Still inside another (wider) ban: wait for that one to end too.
                if let Some(cover) = self.covering_ban(&b.net).map(|c| c.net) {
                    if let Some(c) = self.bans.get_mut(&cover).filter(|c| c.until < b.until) {
                        c.inner.push(b);
                    }
                    continue;
                }
                let message =
                    format!("ban {} for {} more: reinstated after subnet ban {net} ended", b.net, crate::time::fmt_duration(b.until - now));
                self.insert_ban(b.net, b.until, b.offence, b.reason, b.origin, message, vec![], "reinstated", &mut out);
            }
        }
        let lapsed: Vec<Net> = self.allowed.values().filter(|a| a.until <= self.now).map(|a| a.net).collect();
        for net in lapsed {
            self.remove_allow(net, "expired", &mut out);
        }
        if self.cfg.subnets.enabled && self.now - self.last_subnet_eval >= self.cfg.subnets.evaluate_every.micros() {
            self.last_subnet_eval = self.now;
            self.evaluate_subnets(&mut out);
        }
        if self.now - self.last_gc >= 5 * MIN {
            self.last_gc = self.now;
            self.gc(false);
        }
        out
    }

    fn evaluate_subnets(&mut self, out: &mut Vec<Action>) {
        let cfg = Arc::clone(&self.cfg);
        let sc = &cfg.subnets;

        #[derive(Default)]
        struct Group {
            bad: Vec<IpAddr>,
            contributors: usize,
            score: f64,
            /// (slow score, address) of every contributor, for the ban's evidence.
            members: Vec<(f64, IpAddr)>,
        }
        let mut narrow: BTreeMap<Net, Group> = BTreeMap::new();
        for (ip, st) in &self.ips {
            // Scores only decay, so the stored value bounds the current one: skip the powf.
            if st.slow < 5.0 {
                continue;
            }
            let (_, slow) = st.scores_at(self.now, &cfg);
            if slow < 5.0 || self.shield(*ip, st).is_some() {
                continue;
            }
            let prefix = if ip.is_ipv4() { sc.v4_prefix } else { sc.v6_prefix };
            let g = narrow.entry(Net::new(*ip, prefix)).or_default();
            g.contributors += 1;
            g.score += slow;
            g.members.push((slow, *ip));
            if slow >= sc.suspect_score || self.bans.contains_key(&Net::host(*ip)) {
                g.bad.push(*ip);
            }
        }

        for (net, g) in narrow {
            let concentrated = g.bad.len() >= sc.min_bad_ips;
            let distributed = g.contributors >= sc.min_contributors && g.score >= sc.score_sum_threshold;
            if !(concentrated || distributed) || self.covering_ban(&net).is_some() || self.net_protected(&net) {
                continue;
            }
            let reason = if concentrated {
                format!("{} bad addresses in subnet", g.bad.len())
            } else {
                format!("distributed probing: {} addresses, combined score {:.0}", g.contributors, g.score)
            };
            let mut sample: Vec<String> = g.bad.iter().map(|ip| ip.to_string()).collect();
            sample.sort();
            // the worst members' latest lines
            let mut members = g.members.clone();
            members.sort_by(|a, b| b.0.total_cmp(&a.0));
            sample.extend(self.members_evidence(members.iter().take(10).map(|m| m.1)));
            self.ban(net, reason, sample, "subnet", false, out);
        }
        if sc.wide_enabled {
            self.grow_subnet_bans(out);
        }
    }

    /// Widens subnet bans step by step instead of jumping from `v4_prefix` straight to
    /// `v4_wide_prefix`: a ban grows to the narrowest network that also holds the nearest
    /// other ban (an address or a subnet) at most `wide_max_step` prefix bits wider, then
    /// again from there. An attacking range is followed as it shows up, while the rest of
    /// the provider's /16 (other customers, VPN exits) stays reachable. IPv6 bans grow the
    /// same way from `v6_prefix` up to `v6_wide_prefix`, `wide_max_step_v6` bits at a time.
    fn grow_subnet_bans(&mut self, out: &mut Vec<Action>) {
        let cfg = Arc::clone(&self.cfg);
        let sc = &cfg.subnets;
        for v4 in [true, false] {
            let (narrow, wide, step) = if v4 {
                (sc.v4_prefix, sc.v4_wide_prefix, sc.wide_max_step)
            } else {
                (sc.v6_prefix, sc.v6_wide_prefix, sc.wide_max_step_v6)
            };
            if wide >= narrow {
                continue;
            }
            let widest = |n: &Net| Net::new(n.addr, wide);
            // A ban never grows past its widest network, so only the bans there matter to it.
            let mut nearby: BTreeMap<Net, Vec<Net>> = BTreeMap::new();
            for n in self.bans.keys().filter(|n| n.is_v4() == v4) {
                nearby.entry(widest(n)).or_default().push(*n);
            }
            let mut seeds: Vec<Net> =
                self.bans.keys().filter(|n| n.is_v4() == v4 && !n.is_host() && (wide + 1..=narrow).contains(&n.prefix)).copied().collect();
            seeds.sort();
            for seed in seeds {
                // gone: taken in by an earlier seed's growth
                let Some(bans) = nearby.get_mut(&widest(&seed)).filter(|b| b.contains(&seed)) else { continue };
                let mut grown = seed;
                loop {
                    let reach = grown.prefix.saturating_sub(step).max(wide);
                    let next = bans
                        .iter()
                        .filter(|b| !grown.contains_net(b))
                        .map(|b| grown.common(b))
                        .filter(|n| n.prefix >= reach)
                        .max_by_key(|n| n.prefix);
                    // a protected address or another provider (ASN) in the narrowest step is in
                    // every wider one too
                    match next {
                        Some(n) if !self.net_protected(&n) && self.geo.as_ref().is_none_or(|g| g.one_network(&n)) => grown = n,
                        _ => break,
                    }
                }
                if grown == seed {
                    continue;
                }
                let mut taken: Vec<Net> = bans.iter().filter(|b| grown.contains_net(b) && **b != seed).copied().collect();
                taken.sort();
                bans.retain(|b| !grown.contains_net(b));
                bans.push(grown);
                let mut shown: Vec<String> = taken.iter().take(5).map(|n| n.to_string()).collect();
                if taken.len() > 5 {
                    shown.push(format!("{} more", taken.len() - 5));
                }
                let reason = format!("grown from {seed}, banned nearby: {}", shown.join(", "));
                let mut evidence: Vec<String> = taken.iter().map(|n| n.to_string()).collect();
                evidence.extend(self.members_evidence(taken.iter().filter(|n| n.is_host()).take(10).map(|n| n.addr)));
                self.ban(grown, reason, evidence, "subnet", false, out);
            }
        }
    }

    /// The latest lines of what these addresses did, so the actions log keeps proof for a
    /// network ban too: "10-11 05:03:08 11.54.29.77 block TCP/23".
    fn members_evidence(&self, ips: impl Iterator<Item = IpAddr>) -> Vec<String> {
        let mut out = Vec::new();
        for ip in ips {
            if let Some(st) = self.ips.get(&ip) {
                let lines: Vec<&str> = st.evidence.lines().collect();
                for l in &lines[lines.len().saturating_sub(3)..] {
                    if let Some((stamp, text)) = l.split_at_checked(14) {
                        out.push(format!("{stamp} {ip}{text}"));
                    }
                }
            }
        }
        out
    }

    fn gc(&mut self, pressure: bool) {
        let cfg = Arc::clone(&self.cfg);
        let now = self.now;
        let idle = if pressure { 10 * MIN } else { (2 * cfg.scoring.slow_half_life.micros()).max(86_400 * crate::time::SEC) };
        let min_slow = if pressure { 10.0 } else { 1.0 };
        let banned: BTreeSet<IpAddr> = self.bans.keys().filter(|n| n.is_host()).map(|n| n.addr).collect();
        // Cheapest checks first; a stored score below the bound can't have grown since.
        self.ips.retain(|ip, st| {
            now - st.last_seen < idle || banned.contains(ip) || (st.slow >= min_slow && st.scores_at(now, &cfg).1 >= min_slow)
        });
        let keep = cfg.scoring.max_tracked_ips * 8 / 10;
        if pressure && self.ips.len() > keep {
            // Still too many (e.g. a flood of spoofed UFW sources): evict the least suspicious
            // addresses, banned ones last, down to `keep` - always, so the next event can't
            // trigger another full pass. An evicted banned address stays banned; only its
            // score and evidence go.
            let mut by_score: Vec<(bool, f64, IpAddr)> = self.ips.iter().map(|(ip, st)| (banned.contains(ip), st.slow, *ip)).collect();
            let excess = self.ips.len() - keep;
            let order = |a: &(bool, f64, IpAddr), b: &(bool, f64, IpAddr)| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1));
            if excess < by_score.len() {
                by_score.select_nth_unstable_by(excess, order);
            }
            for (_, _, ip) in by_score.into_iter().take(excess) {
                self.ips.remove(&ip);
            }
        }
        let ips = &self.ips;
        self.digest.points.retain(|ip, _| ips.contains_key(ip));
        if self.digest.points.len() > MAX_DIGEST_POINTS {
            self.digest.points.clear();
        }
        let ttl = cfg.allowlist.trust_ttl.micros();
        self.trusted.retain(|_, by| {
            by.retain(|_, t| now - *t < ttl);
            !by.is_empty()
        });
        let ahalf = cfg.accounts.half_life.micros();
        self.accounts.retain(|_, a| now - a.updated < 6 * ahalf || now < a.under_attack_until);
        self.priv_fails.retain(|_, f| now - f.2 < 30 * MIN);
        // System alerts (a few dozen fixed keys) may be gated for up to a week (the cluster
        // key reminder); the rest (per address or account) for a day at most.
        let day = 86_400 * crate::time::SEC;
        self.alert_gate.retain(|k, t| now - *t < if k.starts_with("system:") { 8 * day } else { day });
        // The other keys name what users and attackers vary (programs, files, accounts): a
        // flood of them must not fill the memory or the state file. The oldest go first.
        let mut times: Vec<Micros> = self.alert_gate.iter().filter(|(k, _)| !k.starts_with("system:")).map(|(_, t)| *t).collect();
        if times.len() > MAX_ALERT_GATE {
            let cut = times.len() - MAX_ALERT_GATE;
            let keep_from = *times.select_nth_unstable(cut).1;
            self.alert_gate.retain(|k, t| k.starts_with("system:") || *t >= keep_from);
        }
        let forgive = cfg.bans.forgive_after.micros();
        let bans = &self.bans;
        self.offenders.retain(|net, o| now - o.last_ban < forgive || bans.contains_key(net));
    }

    // ---------------------------------------------------------------- views

    pub fn active_bans(&self) -> Vec<Ban> {
        let mut v: Vec<Ban> = self.bans.values().cloned().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.since));
        v
    }

    pub fn snapshot(&self, tracked_connections: usize, max_offenders: usize) -> Snapshot {
        let cfg = &self.cfg;
        // Rank every address cheaply, then build full views (cloned evidence) only for the top N.
        let mut ranked: Vec<(f64, Micros, IpAddr, f64, f64)> = self
            .ips
            .iter()
            .map(|(ip, st)| {
                let (fast, slow) = st.scores_at(self.now, cfg);
                let danger = 100.0 * (fast / cfg.scoring.fast_threshold).max(slow / cfg.scoring.slow_threshold);
                (danger, st.last_seen, *ip, fast, slow)
            })
            .collect();
        let order = |a: &(f64, Micros, IpAddr, f64, f64), b: &(f64, Micros, IpAddr, f64, f64)| b.0.total_cmp(&a.0).then(b.1.cmp(&a.1));
        if ranked.len() > max_offenders && max_offenders > 0 {
            ranked.select_nth_unstable_by(max_offenders - 1, order);
            ranked.truncate(max_offenders);
        }
        ranked.sort_by(order);
        ranked.truncate(max_offenders);
        let offenders: Vec<IpView> = ranked
            .into_iter()
            .map(|(danger, _, ip, fast, slow)| {
                let st = &self.ips[&ip];
                let ip = &ip;
                let ban = self.banned_by(*ip);
                IpView {
                    ip: *ip,
                    fast,
                    slow,
                    danger,
                    peak: st.peak,
                    first_seen: st.first_seen,
                    last_seen: st.last_seen,
                    counts: st.counts.to_map(),
                    evidence: st.evidence.lines().map(String::from).collect(),
                    banned_by: ban.map(|b| b.net),
                    banned_until: ban.map(|b| b.until),
                    protected: self.protection(*ip).map(str::to_string),
                    geo: self.place(*ip),
                }
            })
            .collect();

        let half = cfg.accounts.half_life.micros();
        let mut accounts: Vec<AccountView> = self
            .accounts
            .iter()
            .map(|(k, a)| AccountView {
                account: k.clone(),
                failures: decay(a.score, self.now - a.updated, half),
                ips: a.ips.len(),
                under_attack: self.now < a.under_attack_until,
            })
            .collect();
        accounts.sort_by(|a, b| b.failures.total_cmp(&a.failures));
        accounts.truncate(50);

        let mut trusted: Vec<(IpAddr, Micros)> = self.trusted.iter().filter_map(|(ip, by)| by.values().max().map(|t| (*ip, *t))).collect();
        trusted.sort_by_key(|t| std::cmp::Reverse(t.1));

        Snapshot {
            version: env!("CARGO_PKG_VERSION").into(),
            generated: self.now,
            started: self.started,
            mode: cfg.mode,
            fast_threshold: cfg.scoring.fast_threshold,
            slow_threshold: cfg.scoring.slow_threshold,
            stats: self.stats.clone(),
            tracked_ips: self.ips.len(),
            tracked_connections,
            offenders,
            bans: self.active_bans(),
            recent: self.recent.iter().rev().cloned().collect(),
            alerts: self.alerts.iter().rev().cloned().collect(),
            accounts,
            trusted,
            exposure: self.exposure_last.clone(),
            cluster: None,
            allowed: self.allowed.values().cloned().collect(),
            feeds: self.feeds.clone(),
            waf: self.waf.clone(),
            geoblock: self.geoblock.clone(),
            certs: self.certs.clone(),
            last_lines: self.silence.last_line.clone(),
            cron: self.cron_view.clone(),
            av: cfg.antivirus.enabled.then(|| self.av.clone()),
            resources: self.resources.clone(),
            world: self.world(),
            port_names: cfg.port_names(),
            actions_log: None,
            patches: self.patches.clone(),
            verify: self.verify_view.clone().or_else(|| {
                self.verify.as_ref().map(|b| crate::verify::VerifyView {
                    last_run: b.last_run,
                    checked: b.checked,
                    mismatched: b.mismatched.len(),
                    suid: b.suid.len(),
                })
            }),
            procwatch: self.proc_view.clone(),
            ssh_audit: self.ssh_audit_last.clone(),
            allow_hosts: self.allow_hosts.clone(),
            backend: None,
            patterns: cfg
                .all_patterns()
                .zip(&self.pattern_stats)
                .map(|(p, st)| crate::parse::custom::PatternView {
                    kind: p.kind,
                    from: p.from(),
                    weight: p.weight,
                    port: p.port,
                    stats: crate::parse::custom::PatternStats { ips: st.top(PATTERN_TOP_IPS), ..st.clone() },
                    addresses: st.ips.len(),
                })
                .collect(),
        }
    }

    /// Halves the port counters once per day elapsed (dropping those that reach 0), so the
    /// statistics follow current activity and survive restarts without growing forever.
    fn halve_ports(&mut self) {
        const DAY: Micros = 86_400 * crate::time::SEC;
        if self.ports_halved > self.now + DAY {
            // saved under a clock that was ahead: restart the daily rhythm from now
            self.ports_halved = self.now;
        }
        if self.now - self.ports_halved < DAY {
            return;
        }
        let days = ((self.now - self.ports_halved) / DAY).min(64) as u32;
        self.ports_halved = self.now;
        let halve = |m: &mut HashMap<u16, u64>| {
            for n in m.values_mut() {
                *n = n.checked_shr(days).unwrap_or(0);
            }
            m.retain(|_, n| *n > 0);
        };
        halve(&mut self.port_hits);
        for m in self.port_hits_cc.values_mut() {
            halve(m);
        }
        self.port_hits_cc.retain(|_, m| !m.is_empty());
        for st in &mut self.pattern_stats {
            st.prune(self.now);
        }
    }

    fn world(&self) -> WorldView {
        let top_ports = |hits: &HashMap<u16, u64>| {
            let mut ports: Vec<(u16, u64)> = hits.iter().map(|(p, n)| (*p, *n)).collect();
            ports.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            ports.truncate(WORLD_PORTS);
            ports
        };
        let ports = top_ports(&self.port_hits);
        let Some(geo) = &self.geo else { return WorldView { ports, ..Default::default() } };

        let mut countries: HashMap<[u8; 2], PlaceStats> = HashMap::new();
        let mut isps: HashMap<u32, PlaceStats> = HashMap::new();
        let mut country_isps: HashMap<([u8; 2], u32), PlaceStats> = HashMap::new();
        let mut unlocated = 0;
        let mut add = |g: crate::geo::Geo, bans: u32, offenders: u32, events: u64| {
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
        for b in self.bans.values() {
            add(geo.lookup(b.net.addr), 1, 0, 0);
        }
        for (ip, st) in &self.ips {
            if self.protection(*ip).is_none() {
                add(geo.lookup(*ip), 0, 1, st.counts.iter().map(|(_, n)| n).sum());
            }
        }
        let worst = |a: &PlaceStats, b: &PlaceStats| {
            b.bans.cmp(&a.bans).then(b.offenders.cmp(&a.offenders)).then(b.events.cmp(&a.events)).then(a.key.cmp(&b.key))
        };
        // Countries: most offenders first.
        let mut countries: Vec<PlaceStats> = countries.into_values().collect();
        countries
            .sort_by(|a, b| b.offenders.cmp(&a.offenders).then(b.bans.cmp(&a.bans)).then(b.events.cmp(&a.events)).then(a.key.cmp(&b.key)));
        let mut isps: Vec<PlaceStats> = isps.into_values().collect();
        isps.sort_by(worst);
        isps.truncate(WORLD_ISPS);

        let mut by_country: BTreeMap<String, CountryDetail> = BTreeMap::new();
        for ((cc, _), stats) in country_isps {
            by_country.entry(String::from_utf8_lossy(&cc).into_owned()).or_default().isps.push(stats);
        }
        for d in by_country.values_mut() {
            d.isps.sort_by(worst);
            d.isps.truncate(COUNTRY_ISPS);
        }
        for c in &countries {
            let cc = [c.key.as_bytes()[0], c.key.as_bytes()[1]];
            if let Some(hits) = self.port_hits_cc.get(&cc) {
                by_country.entry(c.key.clone()).or_default().ports = top_ports(hits);
            }
        }

        let mut logged_in: BTreeMap<String, u32> = BTreeMap::new();
        for (ip, by) in &self.trusted {
            if by.values().any(|t| self.now - t < 3600 * crate::time::SEC) {
                if let Some(c) = geo.lookup(*ip).country {
                    *logged_in.entry(String::from_utf8_lossy(&c).into_owned()).or_default() += 1;
                }
            }
        }
        WorldView { geo: true, countries, isps, ports, logged_in, unlocated, by_country }
    }

    // ---------------------------------------------------------------- persistence

    pub fn export(&self, cursor: Option<String>) -> PersistedState {
        PersistedState {
            version: 2,
            saved: self.now,
            cursor,
            bans: self.active_bans(),
            offenders: self.offenders.iter().map(|(n, o)| (*n, o.clone())).collect(),
            trusted: vec![],
            trusted_by: self.trusted.iter().flat_map(|(ip, by)| by.iter().map(|(s, t)| (*ip, *s, *t))).collect(),
            account_nets: self.account_nets.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            account_first_seen: self.account_first_seen.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            account_asns: self.account_asns.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            ips: self
                .ips
                .iter()
                .filter(|(_, st)| st.scores_at(self.now, &self.cfg).1 >= 5.0)
                .map(|(ip, st)| (*ip, (**st).clone()))
                .collect(),
            recent: self.recent.iter().skip(self.recent.len().saturating_sub(PERSISTED_ACTIONS)).cloned().collect(),
            alerts: self.alerts.iter().cloned().collect(),
            allowed: self.allowed.values().cloned().collect(),
            digest: Some(self.digest.clone()),
            digest_last_sent: self.digest_last_sent,
            alert_gate: self.alert_gate.iter().map(|(k, t)| (k.clone(), *t)).collect(),
            exposure_baseline: self.exposure_baseline.as_ref().map(|b| b.iter().map(|(k, (p, _))| (*k, p.clone())).collect()),
            exposure_firewall: self.exposure_firewall,
            cron: self.cron.clone(),
            av: self.av.clone(),
            followers: self.followers.clone(),
            ports: Some(PortCounts {
                halved: self.ports_halved,
                all: self.port_hits.iter().map(|(p, n)| (*p, *n)).collect(),
                by_country: self
                    .port_hits_cc
                    .iter()
                    .map(|(c, m)| (String::from_utf8_lossy(c).into_owned(), m.iter().map(|(p, n)| (*p, *n)).collect()))
                    .collect(),
            }),
            ssh_keys: self.ssh_keys.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            verify: self.verify.clone(),
            procwatch: self.procwatch.clone(),
            ssh_audit: self.ssh_audit.clone(),
            patterns: self.pattern_stats.iter().filter(|s| s.since > 0).cloned().collect(),
        }
    }

    pub fn restore(&mut self, st: PersistedState) {
        for b in st.bans {
            self.ban_prefixes.insert((b.net.is_v4(), b.net.prefix));
            self.bans.insert(b.net, b);
        }
        self.offenders = st.offenders.into_iter().collect();
        // `trusted` (older versions) didn't say which service a login was for: dropped.
        for (ip, source, t) in st.trusted_by {
            self.trusted.entry(ip).or_default().insert(source, t);
        }
        self.account_nets = st.account_nets.into_iter().collect();
        self.account_first_seen = st.account_first_seen.into_iter().collect();
        self.account_asns = st.account_asns.into_iter().collect();
        self.ips = st.ips.into_iter().map(|(ip, s)| (ip, Box::new(s))).collect();
        // State saved before alerts had their own list: take them from the recent actions.
        self.alerts = if st.alerts.is_empty() {
            st.recent.iter().filter(|a| a.kind == ActionKind::Alert).cloned().collect()
        } else {
            st.alerts.into_iter().collect()
        };
        self.recent = st.recent.into_iter().collect();
        self.exposure_baseline = st.exposure_baseline.map(|b| b.into_iter().map(|(k, p)| (k, (p, 0))).collect());
        self.exposure_firewall = st.exposure_firewall;
        self.allowed = st.allowed.into_iter().map(|a| (a.net, a)).collect();
        if let Some(d) = st.digest {
            self.digest = d;
        }
        self.digest_last_sent = st.digest_last_sent;
        self.alert_gate = st.alert_gate.into_iter().collect();
        self.cron = st.cron;
        self.av = st.av;
        self.followers = st.followers;
        if let Some(p) = st.ports {
            self.ports_halved = p.halved;
            self.port_hits = p.all.into_iter().collect();
            self.port_hits_cc.clear();
            for (cc, ports) in p.by_country {
                let &[a, b] = cc.as_bytes() else { continue };
                if !(a.is_ascii_uppercase() && b.is_ascii_uppercase()) {
                    continue; // only country codes: bounds the map like when counting
                }
                // the same bound as when counting (the file may have been edited)
                self.port_hits_cc.insert([a, b], ports.into_iter().take(COUNTRY_PORTS).collect());
            }
        }
        self.ssh_keys = st.ssh_keys.into_iter().take(MAX_KEY_ACCOUNTS).collect();
        self.verify = st.verify;
        self.procwatch = st.procwatch;
        self.ssh_audit = st.ssh_audit;
        self.set_pattern_stats(
            st.patterns
                .into_iter()
                .map(|mut p| {
                    // the same bounds as when counting (the file may have been edited)
                    p.ips.truncate(crate::parse::custom::MAX_PATTERN_IPS);
                    p.no_address_lines.truncate(crate::parse::custom::MAX_NO_ADDRESS_LINES);
                    p
                })
                .collect(),
        );
        self.now = self.now.max(st.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hourly_history() {
        let mut s = Stats::default();
        for h in 0..(HISTORY_HOURS as i64 + 5) {
            s.hour(h * 60 * MIN + 5).unwrap().events += 1;
        }
        assert_eq!(s.hours.len(), HISTORY_HOURS, "7 days kept");
        assert_eq!(s.hours.front().unwrap().hour, 5 * 60 * MIN);
        s.hour(10 * 60 * MIN + 1).unwrap().bans += 1;
        assert_eq!(s.hours.iter().find(|b| b.hour == 10 * 60 * MIN).unwrap().bans, 1, "a late event finds its hour");
        assert!(s.hour(MIN).is_none(), "one older than the week is dropped");
    }
    use crate::time::SEC;

    fn engine() -> Engine {
        let mut cfg = Config::default();
        cfg.allowlist.nets.push("11.48.43.31".parse().unwrap());
        Engine::new(Arc::new(cfg), 0)
    }

    fn ev(t: i64, ip: &str, s: Signal) -> Event {
        Event::new(t * SEC, ip.parse().unwrap(), s).port(Some(5223)).detail("x")
    }

    fn bans(actions: &[Action]) -> Vec<String> {
        actions.iter().filter(|a| a.kind == ActionKind::Ban).map(|a| a.target.unwrap().to_string()).collect()
    }

    /// `[silence.apps]`: an app's log with no line for its time, counted by its first pattern.
    #[test]
    fn quiet_app_logs() {
        let h = 3600 * SEC;
        let cfg = Config::from_toml(
            "[sources]\napps = [\"nextcloud\", \"owncloud\"]\n[sources.app_logs]\nnextcloud = \"/srv/nc.log\"\nowncloud = \"/srv/oc.log\"\n\
             [silence.apps]\nnextcloud = \"7d\"",
        )
        .unwrap();
        let mut e = Engine::new(Arc::new(cfg), 0);
        e.started = 100 * h;
        let quiet = |a: Vec<Action>| a.into_iter().filter(|a| a.message.contains("nextcloud.log")).map(|a| a.message).collect::<Vec<_>>();
        e.count_pattern("nextcloud_auth", 101 * h, crate::parse::custom::Outcome::Read, "x");
        assert!(quiet(e.check_silence(101 * h + 7 * 24 * h - SEC)).is_empty());
        let m = quiet(e.check_silence(101 * h + 7 * 24 * h));
        assert_eq!(m.len(), 1);
        assert!(m[0].starts_with("no lines in the Nextcloud without AIO") && m[0].contains("file /srv/nc.log"), "{m:?}");
        assert!(quiet(e.check_silence(101 * h + 7 * 24 * h + h)).is_empty(), "once a day");
        e.count_pattern("nextcloud_auth", 300 * h, crate::parse::custom::Outcome::Read, "x");
        let back: Vec<String> = e.check_silence(300 * h).into_iter().map(|a| a.message).collect();
        assert!(back.iter().any(|m| m.starts_with("lines in the Nextcloud without AIO") && m.ends_with("are arriving again")), "{back:?}");
        // owncloud has none set: never
        assert!(e.check_silence(5000 * h).iter().all(|a| !a.message.contains("ownCloud")));
        let err = |t: &str| Config::from_toml(t).unwrap_err().to_string();
        assert!(err("[silence.apps]\nnginx = \"1h\"").contains("unknown log"));
        assert!(err("[silence.apps]\nnginx_access = \"1h\"").contains("isn't in [sources] apps"));
    }

    /// Files the integrity watches report are queued for the scan of changed files, once; a
    /// scan's infected files are high alerts, its failures warnings, the scan itself on record.
    #[test]
    fn changed_files_are_scanned_and_infections_alert() {
        use crate::filescan::{FileResult, ScanReport};
        let finding = |key: &str, files: &[&str]| crate::cronwatch::Finding {
            key: key.into(),
            every: 0,
            severity: Severity::High,
            message: format!("cron: {key} changed"),
            evidence: vec![],
            notify: true,
            owner: None,
            files: files.iter().map(|f| f.to_string()).collect(),
        };
        let off = Engine::new(Arc::new(Config::default()), 0);
        let mut off = off;
        off.findings(vec![finding("a", &["/tmp/x"])], 10 * SEC);
        assert!(off.take_scans(10).is_empty(), "scan_changed = none: nothing queued");

        let cfg = Config::from_toml("[antivirus]\nscan_changed = \"clamav\"").unwrap();
        let mut e = Engine::new(Arc::new(cfg), 0);
        e.findings(vec![finding("a", &["/tmp/x", "/opt/y"]), finding("b", &["/tmp/x"])], 10 * SEC);
        let jobs = e.take_scans(10);
        assert_eq!(jobs.iter().map(|j| j.path.as_str()).collect::<Vec<_>>(), ["/tmp/x", "/opt/y"], "each file once");
        assert_eq!(jobs[0].why, "cron: a changed");
        assert!(e.take_scans(10).is_empty());

        let report = ScanReport {
            started: 20 * SEC,
            finished: 30 * SEC,
            scanners: "ClamAV (clamd)".into(),
            files: vec![
                FileResult {
                    path: "/tmp/x".into(),
                    why: "cron: a changed".into(),
                    hits: vec!["ClamAV: Unix.Trojan.Mirai-1".into()],
                    ..Default::default()
                },
                FileResult { path: "/opt/y".into(), why: "cron: a changed".into(), ..Default::default() },
                FileResult {
                    path: "/opt/z".into(),
                    why: "x".into(),
                    note: Some("not scanned: no longer there".into()),
                    ..Default::default()
                },
            ],
            errors: vec!["YARA (1 rule file) failed: syntax error".into()],
        };
        let a = e.on_file_scan(&report);
        let hit = a.iter().find(|a| a.severity == Severity::High).unwrap();
        assert_eq!(hit.topic, Some(Topic::Integrity));
        assert!(
            hit.message.starts_with("malware in /tmp/x: ClamAV: Unix.Trojan.Mirai-1 (it was scanned because: cron: a changed)"),
            "{}",
            hit.message
        );
        let warn = a.iter().find(|a| a.severity == Severity::Warning).unwrap();
        assert!(warn.message.contains("syntax error") && warn.topic == Some(Topic::Integrity));
        let rec = a.iter().find(|a| a.severity == Severity::Info).unwrap();
        assert_eq!(rec.message, "scanned 2 of 3 changed files with ClamAV (clamd): 1 infected, 1 not scanned or unreadable");
        assert_eq!(rec.topic, None, "on record, not sent");
        assert_eq!(rec.evidence, ["/tmp/x: ClamAV: Unix.Trojan.Mirai-1", "/opt/y: clean", "/opt/z: not scanned: no longer there"]);
        assert!(e.on_file_scan(&report).iter().all(|a| a.severity == Severity::Info), "the same hit and error: once a day");
    }

    /// A local user's own changed files: at most `USER_SCANS_PER_HOUR` scanned an hour (each
    /// scan may load a gigabyte of signatures), and what the scans find in them shares the
    /// user's alert budget, so a pile of test signatures can't flood the admins.
    #[test]
    fn a_users_own_files_have_a_scan_and_alert_budget() {
        use crate::filescan::{FileResult, ScanReport};
        let cfg = Config::from_toml("[antivirus]\nscan_changed = \"clamav\"").unwrap();
        let mut e = Engine::new(Arc::new(cfg), 0);
        let h = 3600 * SEC;
        let finding = |i: usize, owner: Option<u32>| crate::cronwatch::Finding {
            key: format!("cron:{i}"),
            every: 0,
            severity: Severity::High,
            message: "cron: changed".into(),
            evidence: vec![],
            notify: false,
            owner,
            files: vec![format!("/home/eve/s{i}"), format!("/home/eve/t{i}")],
        };
        e.findings((0..20).map(|i| finding(i, Some(1000))).collect(), 10 * h);
        e.findings((100..120).map(|i| finding(i, None)).collect(), 10 * h);
        let jobs = e.take_scans(1000);
        assert_eq!(jobs.iter().filter(|j| j.owner == Some(1000)).count(), USER_SCANS_PER_HOUR);
        assert_eq!(jobs.iter().filter(|j| j.owner.is_none()).count(), 40, "root's: no budget");
        e.findings(vec![finding(50, Some(1000))], 11 * h + MIN);
        assert_eq!(e.take_scans(10).len(), 2, "an hour on");

        let report = ScanReport {
            finished: 12 * h,
            files: (0..10)
                .map(|i| FileResult {
                    path: format!("/home/eve/s{i}"),
                    why: "cron".into(),
                    hits: vec!["ClamAV: Eicar-Signature".into()],
                    owner: Some(1000),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let a = e.on_file_scan(&report);
        let sent = a.iter().filter(|a| a.topic == Some(Topic::Integrity)).count();
        assert_eq!(sent, USER_ALERTS_PER_HOUR + 1, "five alerts and the note that the rest are only logged: {a:?}");
        assert_eq!(a.iter().filter(|a| a.message.starts_with("malware in")).count(), 10, "all on record");
    }

    #[test]
    fn quiet_and_blind_sources() {
        let h = 3600 * SEC;
        let mut cfg = Config::default();
        cfg.sources.ejabberd = false;
        let mut e = Engine::new(Arc::new(cfg), 0);
        assert!(e.check_silence(10 * h).is_empty(), "replay (no wall-clock start): never");
        e.started = 100 * h;
        e.count_record(Source::Ufw, 100 * h);
        e.count_record(Source::Ssh, 100 * h);
        assert!(e.check_silence(101 * h).is_empty());
        let msgs = |a: Vec<Action>| a.into_iter().map(|a| a.message).collect::<Vec<_>>();
        let m = msgs(e.check_silence(102 * h + SEC));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].starts_with("no ufw log lines for 2h"), "{m:?}");
        assert!(e.check_silence(103 * h).is_empty(), "repeated at most daily");
        e.count_record(Source::Ufw, 103 * h);
        assert_eq!(msgs(e.check_silence(103 * h + SEC)), vec!["ufw log lines are arriving again"]);
        // ssh: lines keep coming (own logins, reloads...) but none names an address
        for i in 0..300 {
            e.count_record(Source::Ssh, 103 * h + i * SEC);
            e.on_event(&Event::new(103 * h + i * 60 * SEC, "11.13.1.2".parse().unwrap(), Signal::FwBlock));
            e.count_record(Source::Ufw, 103 * h + i * 60 * SEC);
        }
        let m = msgs(e.check_silence(106 * h + SEC));
        assert!(m.iter().any(|m| m.starts_with("301 ssh log lines in the last 6h")), "{m:?}");
        e.on_event(&ev(106 * 3600 + 2, "11.13.1.1", Signal::SshPreauth));
        e.count_record(Source::Ssh, 106 * h + 2 * SEC);
        assert_eq!(msgs(e.check_silence(106 * h + 3 * SEC)), vec!["ssh log lines name client addresses again"]);
    }

    #[test]
    fn world_view_by_country_network_and_port() {
        let mut e = engine();
        assert!(!e.snapshot(0, 10).world.geo);
        e.geo = Some(Arc::new(crate::geo::tests::sample()));
        e.on_event(&ev(1, "5.9.1.1", Signal::FwTripwire).port(Some(23))); // DE, banned
        e.on_event(&ev(2, "11.41.1.1", Signal::FwBlock).port(Some(3389))); // FI, tracked
        e.on_event(&ev(3, "11.41.1.1", Signal::FwBlock).port(Some(3389)));
        e.on_event(&ev(4, "8.8.8.8", Signal::FwBlock).port(Some(22))); // no geo data
        e.on_event(&ev(5, "1.0.0.5", Signal::XmppAuthOk)); // AU user
        let w = e.snapshot(0, 10).world;
        assert!(w.geo);
        let c: Vec<(&str, u32, u32, u64)> = w.countries.iter().map(|c| (c.key.as_str(), c.bans, c.offenders, c.events)).collect();
        assert_eq!(c, vec![("DE", 1, 1, 1), ("FI", 0, 1, 2)], "worst first; the user isn't an offender");
        assert_eq!(w.countries[0].name, "Germany");
        assert_eq!(w.unlocated, 1);
        assert_eq!(
            (w.isps[0].key.as_str(), w.isps[0].name.as_str(), w.isps[0].bans, w.isps[0].offenders),
            ("AS24940", "Hetzner Online GmbH", 1, 2)
        );
        assert_eq!(w.ports, vec![(3389, 2), (22, 1), (23, 1)]);
        assert_eq!(w.logged_in, BTreeMap::from([("AU".to_string(), 1)]));
        // per country: only that country's ports and its share of a network
        assert_eq!(w.by_country["DE"].ports, vec![(23, 1)]);
        assert_eq!(w.by_country["FI"].ports, vec![(3389, 2)]);
        let fi = &w.by_country["FI"].isps;
        assert_eq!((fi.len(), fi[0].key.as_str(), fi[0].country.as_str(), fi[0].bans, fi[0].offenders), (1, "AS24940", "FI", 0, 1));
        // kept across a restart, halved once a day
        let mut e2 = engine();
        e2.geo = e.geo.clone();
        e2.restore(e.export(None));
        let w2 = e2.snapshot(0, 10).world;
        assert_eq!(w2.ports, vec![(3389, 2), (22, 1), (23, 1)]);
        assert_eq!(w2.by_country["DE"].ports, vec![(23, 1)], "the banned source's country is still listed");
        let day_after = e2.ports_halved + 86_400 * SEC;
        e2.tick(day_after - 1);
        assert_eq!(e2.snapshot(0, 10).world.ports.len(), 3, "not yet a day");
        e2.tick(day_after);
        let w2 = e2.snapshot(0, 10).world;
        assert_eq!(w2.ports, vec![(3389, 1)], "halved; counters reaching 0 are dropped");
        assert!(w2.by_country.get("DE").is_none_or(|d| d.ports.is_empty()));
        // most offenders first, whatever the bans
        e.on_event(&ev(6, "11.41.1.2", Signal::FwBlock).port(Some(3389)));
        let w = e.snapshot(0, 10).world;
        assert_eq!(w.countries.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), ["FI", "DE"]);
    }

    #[test]
    fn applied_actions_are_marked_in_recent() {
        let mut e = engine();
        let mut a = e.on_event(&ev(5, "8.8.4.4", Signal::FwTripwire).port(Some(23)));
        let ban = a.iter_mut().find(|a| a.kind == ActionKind::Ban).unwrap();
        assert!(!e.snapshot(0, 10).recent[0].applied, "recorded before the enforcer runs");
        ban.applied = true;
        e.mark_applied(ban);
        assert!(e.snapshot(0, 10).recent[0].applied);
    }

    #[test]
    fn alerts_outlive_a_flood_of_bans() {
        let mut e = engine();
        let mut out = vec![];
        let action = |ts, kind, message: &str| Action {
            ts,
            kind,
            severity: Severity::Warning,
            target: None,
            until: None,
            message: message.into(),
            evidence: vec![],
            superseded: vec![],
            applied: false,
            topic: None,
            accounts: vec![],
            user_note: None,
            notice: None,
            category: None,
        };
        e.push_action(action(1, ActionKind::Alert, "early alert"), &mut out);
        for i in 0..RECENT_ACTIONS as Micros {
            e.push_action(action(2 + i, ActionKind::Ban, "ban"), &mut out);
        }
        let s = e.snapshot(0, 10);
        assert!(s.recent.iter().all(|a| a.kind == ActionKind::Ban), "pushed out of the recent actions");
        assert_eq!(s.alerts.iter().map(|a| a.message.as_str()).collect::<Vec<_>>(), ["early alert"]);
        // kept across a restart
        let mut e2 = engine();
        e2.restore(e.export(None));
        assert_eq!(e2.snapshot(0, 10).alerts.len(), 1);
    }

    #[test]
    fn canary_bans_at_first_attempt_and_login_is_critical() {
        let mut e = engine();
        let a = e.on_event(&ev(1, "11.18.9.9", Signal::SshCanary).account(Some("ubuntu")));
        assert_eq!(bans(&a), vec!["11.18.9.9"]);
        assert_eq!(a[0].category.as_deref(), Some("canary"));
        assert!(a.iter().all(|a| a.accounts.is_empty()), "nobody to notify about a canary account");
        let login = Event::new(2 * SEC, "11.18.9.8".parse().unwrap(), Signal::XmppCanary)
            .detail(format!("{} test@x.org", crate::event::CANARY_LOGIN));
        let a = e.on_event(&login);
        assert!(a.iter().any(|a| a.severity == Severity::Critical && a.topic == Some(Topic::Compromise)), "{a:?}");
        assert!(e.protection("11.18.9.8".parse().unwrap()).is_none(), "a canary login earns no trust");
        // your own (allowlisted) address mistyping a name: alert, no ban
        let a = e.on_event(&ev(3, "11.48.43.31", Signal::SshCanary).account(Some("root")));
        assert!(bans(&a).is_empty());
        assert!(a.iter().any(|a| a.topic == Some(Topic::Protected)));
    }

    #[test]
    fn dead_rule_survives_a_container_restart_without_alert() {
        let mut e = engine();
        let report = |t: i64, dead: &[&str]| ExposureReport {
            scanned: t * 60 * SEC,
            ufw_active: Some(true),
            firewall: None,
            listeners: vec![],
            dead_rules: dead.iter().map(|d| d.to_string()).collect(),
        };
        let dead = |a: Vec<Action>| a.iter().filter(|a| a.message.contains("ufw allows")).count();
        e.on_exposure(report(0, &[]), true);
        // Nextcloud containers recreated: 443 and 3478 have no listener for two scans
        assert_eq!(dead(e.on_exposure(report(1, &["443/tcp", "3478/udp"]), true)), 0);
        assert_eq!(dead(e.on_exposure(report(2, &["443/tcp", "3478/udp"]), true)), 0);
        assert_eq!(dead(e.on_exposure(report(3, &[]), true)), 0);
        // a rule that stays dead is reported on the 5th scan in a row, once
        for t in 4..8 {
            assert_eq!(dead(e.on_exposure(report(t, &["5350/tcp"]), true)), 0);
        }
        assert_eq!(dead(e.on_exposure(report(8, &["5350/tcp"]), true)), 1);
        assert_eq!(dead(e.on_exposure(report(9, &["5350/tcp"]), true)), 0);
    }

    #[test]
    fn exposure_baseline_learned_again_when_the_firewall_changes() {
        use crate::event::Proto;
        use crate::exposure::{Exposure, Firewall, Listener};
        let l = |port: u16, exposure| Listener {
            key: ListenerKey { proto: Proto::Tcp, addr: "0.0.0.0".parse().unwrap(), port },
            process: "p".into(),
            exposure,
            dynamic: false,
            rule: None,
            limited: false,
            honeypot: false,
        };
        let report = |t: i64, fw: Option<Firewall>, ufw: Option<bool>, ls: Vec<Listener>| ExposureReport {
            scanned: t * 60 * SEC,
            ufw_active: ufw,
            firewall: fw,
            listeners: ls,
            dead_rules: vec![],
        };
        let msgs = |a: Vec<Action>| a.into_iter().map(|a| a.message).collect::<Vec<_>>();
        // no firewall: everything public is exposed
        let mut e = engine();
        let open = || vec![l(22, Exposure::Unfiltered), l(8080, Exposure::Unfiltered)];
        let m = msgs(e.on_exposure(report(0, Some(Firewall::Absent), None, open()), true));
        assert!(m[0].starts_with("exposure baseline learned: 2 exposed"), "{m:?}");
        // iptables rules now read: 8080 is blocked, which is no "gone" listener
        let filtered = || vec![l(22, Exposure::Allowed), l(8080, Exposure::Firewalled)];
        let m = msgs(e.on_exposure(report(1, Some(Firewall::Iptables), None, filtered()), true));
        assert_eq!(m, ["exposure baseline learned (learned again: the firewall is now iptables): 1 exposed listeners: 0.0.0.0:22/tcp (p)"]);
        for t in 2..12 {
            assert!(msgs(e.on_exposure(report(t, Some(Firewall::Iptables), None, filtered()), true)).is_empty(), "scan {t}");
        }
        // the state file keeps what the baseline was learned under
        let mut back = engine();
        back.restore(decode_state(&encode_state(&e.export(None)).unwrap()).unwrap());
        assert!(msgs(back.on_exposure(report(12, Some(Firewall::Iptables), None, filtered()), true)).is_empty());

        // a baseline from a version that read only ufw: still good under ufw, learned again
        // once iptables is read where there was no ufw
        let mut old = engine();
        old.exposure_baseline = Some(BTreeMap::from([(l(22, Exposure::Allowed).key, ("p".to_string(), 0))]));
        assert!(msgs(old.on_exposure(report(0, Some(Firewall::Ufw), Some(true), vec![l(22, Exposure::Allowed)]), true)).is_empty());
        let mut old = engine();
        old.exposure_baseline = Some(BTreeMap::from([(l(8080, Exposure::Unfiltered).key, ("p".to_string(), 0))]));
        let m = msgs(old.on_exposure(report(0, Some(Firewall::Iptables), None, filtered()), true));
        assert!(m[0].contains("learned again: the firewall is now iptables"), "{m:?}");
    }

    #[test]
    fn exposure_drift() {
        use crate::event::Proto;
        use crate::exposure::{Exposure, Listener};
        let mut e = engine();
        let l = |port: u16, exposure| Listener {
            key: ListenerKey { proto: Proto::Tcp, addr: "0.0.0.0".parse().unwrap(), port },
            process: "p".into(),
            exposure,
            dynamic: false,
            rule: None,
            limited: false,
            honeypot: false,
        };
        let report = |t: i64, ls: Vec<Listener>, dead: Vec<&str>| ExposureReport {
            scanned: t * 60 * SEC,
            ufw_active: Some(true),
            firewall: None,
            listeners: ls,
            dead_rules: dead.into_iter().map(String::from).collect(),
        };
        let msgs = |a: Vec<Action>| a.into_iter().map(|a| a.message).collect::<Vec<_>>();

        let first = msgs(e.on_exposure(report(0, vec![l(22, Exposure::Allowed), l(4369, Exposure::Firewalled)], vec![]), true));
        assert_eq!(first.len(), 1);
        assert!(first[0].contains("baseline learned: 1 exposed"), "{first:?}");

        let panel = || l(51821, Exposure::Docker);
        assert!(msgs(e.on_exposure(report(1, vec![l(22, Exposure::Allowed), panel()], vec![]), true)).is_empty(), "needs 2 scans");
        let m = msgs(e.on_exposure(report(2, vec![l(22, Exposure::Allowed), panel()], vec!["53/udp"]), true));
        assert!(m.iter().any(|m| m.contains("new internet-facing listener 0.0.0.0:51821/tcp (p, published by docker")), "{m:?}");
        assert!(!m.iter().any(|m| m.contains("ufw allows 53/udp")), "a dead rule needs 5 scans in a row");
        assert!(msgs(e.on_exposure(report(3, vec![l(22, Exposure::Allowed), panel()], vec!["53/udp"]), true)).is_empty(), "alerted once");

        // sshd restarting briefly is not "gone"; staying away for 5 scans is.
        assert!(msgs(e.on_exposure(report(4, vec![panel()], vec![]), true)).is_empty());
        assert!(msgs(e.on_exposure(report(5, vec![l(22, Exposure::Allowed), panel()], vec![]), true)).is_empty());
        for t in 6..10 {
            assert!(msgs(e.on_exposure(report(t, vec![l(22, Exposure::Allowed)], vec![]), true)).is_empty());
        }
        let m = msgs(e.on_exposure(report(10, vec![l(22, Exposure::Allowed)], vec![]), true));
        assert_eq!(m, vec!["internet-facing listener 0.0.0.0:51821/tcp (p) is gone - service stopped?"]);

        // logguard's own honeypot listeners are exposed on purpose: never alerted either
        let trap = |port| Listener { honeypot: true, ..l(port, Exposure::Allowed) };
        for t in 0..2 {
            let r = report(10 + t, vec![l(22, Exposure::Allowed), trap(2323)], vec![]);
            assert!(!msgs(e.on_exposure(r, true)).iter().any(|m| m.contains("2323")));
        }

        // TURN relay sockets in an allowed range come and go with calls: never alerted.
        let relay = |port| Listener { dynamic: true, ..l(port, Exposure::Allowed) };
        assert!(msgs(e.on_exposure(report(11, vec![l(22, Exposure::Allowed), relay(50001)], vec![]), true)).is_empty());
        assert!(msgs(e.on_exposure(report(12, vec![l(22, Exposure::Allowed), relay(50001), relay(61000)], vec![]), true)).is_empty());
        for t in 13..17 {
            assert!(msgs(e.on_exposure(report(t, vec![l(22, Exposure::Allowed)], vec![]), true)).is_empty());
        }

        // after a restart: nothing is judged during the startup grace period
        let mut booting = engine();
        booting.started = 100 * 60 * SEC;
        booting.exposure_baseline = Some(BTreeMap::from([(l(22, Exposure::Allowed).key, ("sshd".to_string(), 0))]));
        for t in 101..110 {
            assert!(msgs(booting.on_exposure(report(t, vec![], vec!["443/tcp"]), true)).is_empty(), "grace at minute {t}");
        }

        let st = e.export(None);
        let mut e2 = engine();
        e2.restore(serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap());
        assert!(msgs(e2.on_exposure(report(17, vec![l(22, Exposure::Allowed)], vec![]), true)).is_empty(), "baseline survives restart");
    }

    /// A tripwire hit's source address may be forged: a ban or report on blocked packets alone
    /// says so, and isn't applied to an address that logged in at the receiving node lately.
    #[test]
    fn forgeable_peer_evidence_spares_logged_in_users() {
        use crate::cluster::{ClusterCfg, Fact};
        let mut origin = engine();
        origin.enable_sharing(vec![]);
        origin.on_event(&ev(1, "7.7.7.1", Signal::FwTripwire).port(Some(23)));
        for i in 0..3 {
            origin.on_event(&ev(2 + i, "7.7.7.2", Signal::SshInvalidUser).account(Some("oracle")));
        }
        let facts = origin.take_outbox(10.0);
        let forgeable = |ip: &str| {
            facts
                .iter()
                .filter_map(|f| match f {
                    FactBody::Ban { net, forgeable, .. } if net.to_string() == ip => Some(("ban", *forgeable)),
                    FactBody::Report { ip: i, forgeable, .. } if i.to_string() == ip => Some(("report", *forgeable)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(forgeable("7.7.7.1"), [("ban", true), ("report", true)], "{facts:?}");
        assert_eq!(forgeable("7.7.7.2"), [("ban", false), ("report", false)], "{facts:?}");

        let ccfg = ClusterCfg::default();
        let mut here = engine();
        for ip in ["7.7.7.1", "7.7.7.2"] {
            here.on_event(&Event::new(0, ip.parse().unwrap(), Signal::XmppAuthOk).account(Some("a@x.org")));
        }
        let mut seq = 0;
        let mut apply = |e: &mut Engine, body: &FactBody| {
            seq += 1;
            e.apply_peer_fact(
                &Fact { origin: "vpn".into(), seq, created: 10 * SEC, hops: 1, body: body.clone(), sig: String::new() },
                &ccfg,
            )
        };
        let mut all = vec![];
        for f in &facts {
            all.extend(apply(&mut here, f));
        }
        assert_eq!(bans(&all), ["7.7.7.2"], "only the one on evidence that can't be forged");
        assert!(here.ips.get(&"7.7.7.1".parse().unwrap()).is_none_or(|s| s.slow == 0.0), "the report was left out");
        // someone who hasn't logged in here is banned on it as before
        let mut fresh = engine();
        let all: Vec<Action> = facts.iter().flat_map(|f| apply(&mut fresh, f)).collect();
        assert_eq!(bans(&all), ["7.7.7.1", "7.7.7.2"]);
    }

    /// Peer bans never reach wider than this node bans itself.
    #[test]
    fn peer_bans_no_wider_than_own() {
        use crate::cluster::{ClusterCfg, Fact};
        let ccfg = ClusterCfg::default();
        let mut seq = 0;
        let mut ban = |e: &mut Engine, net: &str| {
            seq += 1;
            let body = FactBody::Ban { net: net.parse().unwrap(), until: 3600 * SEC, reason: "x".into(), forgeable: false };
            bans(&e.apply_peer_fact(&Fact { origin: "vpn".into(), seq, created: SEC, hops: 1, body, sig: String::new() }, &ccfg))
        };
        let mut cfg = Config::default();
        cfg.subnets.v4_wide_prefix = 20;
        let mut e = Engine::new(Arc::new(cfg), 0);
        assert!(ban(&mut e, "11.13.0.0/16").is_empty() && ban(&mut e, "11.14.0.0/19").is_empty());
        assert_eq!(ban(&mut e, "11.15.0.0/20"), ["11.15.0.0/20"]);
        // without growth: /24 at most; IPv6 /64
        let mut cfg = Config::default();
        cfg.subnets.wide_enabled = false;
        let mut e = Engine::new(Arc::new(cfg), 0);
        assert!(ban(&mut e, "11.16.0.0/23").is_empty() && ban(&mut e, "3fff:130::/48").is_empty());
        assert_eq!(ban(&mut e, "11.16.0.0/24"), ["11.16.0.0/24"]);
    }

    #[test]
    fn cluster_facts() {
        use crate::cluster::{ClusterCfg, Fact, FactBody};
        let ccfg = ClusterCfg::default();
        let fact = |body| Fact { origin: "vpn".into(), seq: 1, created: 1000 * SEC, hops: 1, body, sig: String::new() };
        let mut e = engine();
        e.enable_sharing(vec!["11.38.48.86".parse().unwrap()]);
        e.now = 1000 * SEC;

        // remote ban: applied, capped to max_remote_ban, tagged with its origin, not re-shared as ours
        let a = e.apply_peer_fact(
            &fact(FactBody::Ban { net: "1.2.3.4".parse().unwrap(), until: 999_999 * SEC, reason: "scan".into(), forgeable: false }),
            &ccfg,
        );
        assert!(a[0].message.contains("(from peer vpn)"), "{}", a[0].message);
        let b = e.banned_by("1.2.3.4".parse().unwrap()).unwrap().clone();
        assert_eq!(b.origin.as_deref(), Some("vpn"));
        assert_eq!(b.until, 1000 * SEC + 86_400 * SEC);
        assert!(e.take_outbox(10.0).is_empty());

        // protected addresses: home (allowlist) and cluster peers are never banned by peers
        for ip in ["11.48.43.31", "11.38.48.86"] {
            assert!(e
                .apply_peer_fact(
                    &fact(FactBody::Ban { net: ip.parse().unwrap(), until: 2000 * SEC, reason: "x".into(), forgeable: false }),
                    &ccfg
                )
                .is_empty());
        }

        // reports add up across nodes at report_factor (0.5): 2 reports of 120 points = ban
        let rep = |seq, pts| Fact {
            seq,
            ..fact(FactBody::Report { ip: "5.5.5.5".parse().unwrap(), points: pts, signals: "tripwire".into(), forgeable: false })
        };
        assert!(e.apply_peer_fact(&rep(2, 120.0), &ccfg).is_empty());
        let a = e.apply_peer_fact(&rep(3, 120.0), &ccfg);
        assert_eq!(bans(&a), vec!["5.5.5.5"]);
        let out = e.take_outbox(10.0);
        assert!(out.iter().any(|f| matches!(f, FactBody::Ban { net, .. } if net.to_string() == "5.5.5.5")), "local decision is shared");
        assert!(!out.iter().any(|f| matches!(f, FactBody::Report { .. })), "peer points are never re-reported");

        // local evidence produces a report; logins are neither shared nor accepted from peers
        e.on_event(&ev(1001, "6.6.6.6", Signal::XmppTlsFail));
        e.on_event(&Event::new(1001 * SEC, "6.6.6.7".parse().unwrap(), Signal::XmppAuthOk).account(Some("a@b")));
        let out = e.take_outbox(10.0);
        assert!(out.iter().any(|f| matches!(f, FactBody::Report { ip, points, .. } if ip.to_string() == "6.6.6.6" && *points == 40.0)));
        assert!(!out.iter().any(|f| matches!(f, FactBody::Trust { .. })), "{out:?}");
        e.apply_peer_fact(&fact(FactBody::Trust { ip: "7.7.7.7".parse().unwrap() }), &ccfg);
        assert_eq!(e.protection("7.7.7.7".parse().unwrap()), None);
        // a peer's reports count against an address that logged in here
        let rep7 = |seq| Fact {
            seq,
            ..fact(FactBody::Report { ip: "6.6.6.7".parse().unwrap(), points: 200.0, signals: "x".into(), forgeable: false })
        };
        let mut a = e.apply_peer_fact(&rep7(10), &ccfg);
        a.extend(e.apply_peer_fact(&rep7(11), &ccfg));
        assert_eq!(bans(&a), vec!["6.6.6.7"]);

        // unban from a peer lifts the ban
        let a = e.apply_peer_fact(&fact(FactBody::Unban { net: "1.2.3.4".parse().unwrap(), reason: "fp".into() }), &ccfg);
        assert_eq!(a[0].kind, ActionKind::Unban);
        // a broken or compromised peer: absurdly wide networks and non-numbers are ignored
        for wide in ["0.0.0.0/1", "10.0.0.0/8", "2000::/3"] {
            let net: Net = wide.parse().unwrap();
            assert!(e
                .apply_peer_fact(&fact(FactBody::Ban { net, until: 2000 * SEC, reason: "x".into(), forgeable: false }), &ccfg)
                .is_empty());
            assert!(e.apply_peer_fact(&fact(FactBody::Allow { net, until: 2000 * SEC, note: "x".into() }), &ccfg).is_empty());
        }
        let nan = Fact {
            seq: 4,
            ..fact(FactBody::Report { ip: "5.5.5.6".parse().unwrap(), points: f64::NAN, signals: "x".into(), forgeable: false })
        };
        assert!(e.apply_peer_fact(&nan, &ccfg).is_empty());
        assert!(!e.ips.contains_key(&"5.5.5.6".parse().unwrap()), "nothing recorded");
        let huge = Fact {
            seq: 5,
            ..fact(FactBody::Report { ip: "5.5.5.7".parse().unwrap(), points: 1e300, signals: "x".into(), forgeable: false })
        };
        e.apply_peer_fact(&huge, &ccfg);
        assert_eq!(e.ips[&"5.5.5.7".parse().unwrap()].fast, 100.0, "capped at one threshold");
        assert!(
            e.apply_peer_fact(
                &fact(FactBody::Ban { net: "11.13.0.0/16".parse().unwrap(), until: 2000 * SEC, reason: "x".into(), forgeable: false }),
                &ccfg
            )
            .len()
                == 1
        );
    }

    #[test]
    fn operator_controls() {
        let mut e = engine();
        e.enable_sharing(vec![]);
        for i in 0..3 {
            e.on_event(&ev(i, "9.9.9.9", Signal::XmppTlsFail));
        }
        assert!(e.banned_by("9.9.9.9".parse().unwrap()).is_some());
        let a = e.operator_unban("9.9.9.9".parse().unwrap()).unwrap();
        assert_eq!(a[0].kind, ActionKind::Unban);
        // score was reset: one more failure doesn't re-ban immediately, and the offence count restarted
        assert!(bans(&e.on_event(&ev(10, "9.9.9.9", Signal::XmppTlsFail))).is_empty());
        let again: Vec<Action> = (11..13).flat_map(|i| e.on_event(&ev(i, "9.9.9.9", Signal::XmppTlsFail))).collect();
        assert!(again.iter().any(|a| a.message.contains("offence #1")), "{again:?}");
        assert!(e.take_outbox(1000.0).iter().any(|f| matches!(f, FactBody::Unban { .. })), "shared with the cluster");

        // unbanning a host inside a banned subnet explains what to do
        e.operator_unban("9.9.9.9".parse().unwrap()).unwrap();
        e.apply_peer_fact(
            &Fact {
                origin: "x".into(),
                seq: 1,
                created: 20 * SEC,
                hops: 1,
                body: FactBody::Ban { net: "11.18.0.0/24".parse().unwrap(), until: 9000 * SEC, reason: "r".into(), forgeable: false },
                sig: String::new(),
            },
            &ClusterCfg::default(),
        );
        let err = e.operator_unban("11.18.0.7".parse().unwrap()).unwrap_err();
        assert!(err.contains("covered by the ban on 11.18.0.0/24"), "{err}");
        assert!(e.operator_unban("8.8.4.4".parse().unwrap()).unwrap_err().contains("no active ban"));

        // allowlisting lifts bans inside it, protects, and expires
        let a = e.operator_allow("11.18.0.0/24".parse().unwrap(), 100 * SEC, "office".into());
        assert_eq!(a.iter().map(|a| a.kind).collect::<Vec<_>>(), vec![ActionKind::Unban, ActionKind::Allow]);
        assert_eq!(e.protection("11.18.0.7".parse().unwrap()), Some("operator allowlist"));
        let tripped: Vec<Action> = (0..5).flat_map(|i| e.on_event(&ev(30 + i, "11.18.0.7", Signal::XmppTlsFail))).collect();
        assert!(bans(&tripped).is_empty());
        let expired = e.tick(200 * SEC);
        assert!(expired.iter().any(|a| a.kind == ActionKind::Disallow));
        assert!(e.protection("11.18.0.7".parse().unwrap()).is_none());
        assert!(e.operator_disallow("11.18.0.0/24".parse().unwrap()).is_err());
    }

    #[test]
    fn digest_counts_bans_by_cause() {
        let mut e = engine();
        for i in 0..3 {
            e.on_event(&ev(i, "9.9.9.9", Signal::XmppTlsFail));
        }
        e.on_event(&ev(5, "8.8.4.4", Signal::FwTripwire).port(Some(23)));
        let d = e.digest_take(60 * SEC);
        assert_eq!(d.bans_by_category.get("xmpp"), Some(&1));
        assert_eq!(d.bans_by_category.get("tripwire"), Some(&1));
        assert_eq!(d.top[0].0.to_string(), "9.9.9.9");
        assert!(d.top[0].2.is_some(), "banned");
        assert_eq!(d.events.get(&Signal::XmppTlsFail), Some(&3));
        let next = e.digest_take(120 * SEC);
        assert!(next.bans_by_category.is_empty() && next.events.is_empty(), "period was reset");
    }

    #[test]
    fn flood_eviction_keeps_suspicious_addresses() {
        let mut e = engine();
        // fill past the cap with harmless one-packet sources, all seen "just now"
        let max = e.cfg.scoring.max_tracked_ips;
        for i in 0..(max as u32 + 10) {
            let ip = std::net::Ipv4Addr::from(0x2d00_0000 + i);
            e.ips.insert(IpAddr::V4(ip), Box::new(IpState { slow: 1.0, last_seen: 0, ..Default::default() }));
        }
        let bad: IpAddr = "8.8.4.4".parse().unwrap();
        e.ips.insert(bad, Box::new(IpState { slow: 200.0, fast: 50.0, ..Default::default() }));
        let t = std::time::Instant::now();
        e.on_event(&ev(1, "9.9.9.9", Signal::FwBlock).port(Some(1)));
        assert!(e.ips.len() <= max * 8 / 10 + 2, "evicted to 80%: {}", e.ips.len());
        assert!(e.ips.contains_key(&bad), "the suspicious address survives");
        // banned addresses alone exceeding the cap must not make every event a full pass
        let mut e = engine();
        let max = e.cfg.scoring.max_tracked_ips;
        for i in 0..(max as u32 + 10) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x2e00_0000 + i));
            e.ips.insert(ip, Box::new(IpState { slow: 300.0, last_seen: 0, ..Default::default() }));
            e.bans.insert(
                Net::host(ip),
                Ban { net: Net::host(ip), since: 0, until: i64::MAX / 2, offence: 1, reason: String::new(), origin: None, inner: vec![] },
            );
        }
        e.ban_prefixes.insert((true, 32));
        e.on_event(&ev(1, "9.9.9.8", Signal::FwBlock).port(Some(1)));
        assert!(e.ips.len() <= max * 8 / 10 + 2, "banned addresses evicted too: {}", e.ips.len());
        assert_eq!(e.bans.len(), max + 10, "their bans stay");
        // the next events don't trigger another full pass
        for i in 2..1000 {
            e.on_event(&ev(i, "9.9.9.9", Signal::FwBlock).port(Some(1)));
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn snapshot_top_n_and_persistence_is_lean() {
        let mut e = engine();
        for host in 1..=50u8 {
            e.on_event(&ev(i64::from(host), &format!("11.13.1.{host}"), Signal::XmppConn).port(Some(5269)));
        }
        for i in 0..3 {
            e.on_event(&ev(100 + i, "9.9.9.9", Signal::XmppTlsFail));
        }
        let snap = e.snapshot(0, 5);
        assert_eq!(snap.offenders.len(), 5);
        assert_eq!(snap.offenders[0].ip.to_string(), "9.9.9.9");
        assert!(snap.offenders.windows(2).all(|w| w[0].danger >= w[1].danger));
        assert!(!snap.offenders[0].evidence.is_empty());
        let json = serde_json::to_string(&e.export(None)).unwrap();
        assert!(!json.contains("TLS failed"), "evidence is not persisted");
        let back: PersistedState = serde_json::from_str(&json).unwrap();
        assert!(back.alert_gate.is_empty() || back.alert_gate.iter().all(|(k, _)| !k.is_empty()));
    }

    #[test]
    fn private_addresses_are_ignored() {
        let mut e = engine();
        let mut all = vec![];
        for i in 0..50 {
            all.extend(e.on_event(&ev(i, "172.18.0.8", Signal::FwBlock).port(Some(443 + i as u16))));
            all.extend(e.on_event(&ev(i, "10.101.0.1", Signal::XmppTlsFail)));
        }
        assert!(all.is_empty());
        assert!(e.snapshot(0, 10).offenders.is_empty());
    }

    #[test]
    fn three_tls_failures_ban() {
        let mut e = engine();
        assert!(e.on_event(&ev(0, "11.57.40.218", Signal::XmppTlsFail)).is_empty());
        assert!(e.on_event(&ev(5, "11.57.40.218", Signal::XmppTlsFail)).is_empty());
        let a = e.on_event(&ev(9, "11.57.40.218", Signal::XmppTlsFail));
        assert_eq!(bans(&a), vec!["11.57.40.218"]);
        assert_eq!(a[0].until, Some(9 * SEC + 3600 * SEC));
        // no duplicate ban while active
        assert!(e.on_event(&ev(10, "11.57.40.218", Signal::XmppTlsFail)).is_empty());
    }

    #[test]
    fn low_and_slow_caught_by_sustained_score() {
        let mut e = engine();
        let mut banned_at = None;
        for i in 0..12 {
            let a = e.on_event(&ev(i * 1800, "9.9.9.9", Signal::XmppTlsFail));
            if !bans(&a).is_empty() && banned_at.is_none() {
                assert!(a[0].message.contains("sustained"), "{}", a[0].message);
                banned_at = Some(i);
            }
        }
        // One TLS failure every 30 min never trips the fast score, but 6 of them in 2.5h do trip the slow one.
        assert_eq!(banned_at, Some(5));
    }

    #[test]
    fn allowlisted_and_trusted_never_banned() {
        let mut e = engine();
        let mut all = vec![];
        for i in 0..10 {
            all.extend(e.on_event(&ev(i, "11.48.43.31", Signal::XmppTlsFail)));
        }
        assert!(bans(&all).is_empty());
        assert!(all.iter().any(|a| a.kind == ActionKind::Alert));

        let ok = Event::new(20 * SEC, "5.5.5.5".parse().unwrap(), Signal::SshAuthOk).account(Some("user6"));
        e.on_event(&ok);
        let mut all = vec![];
        for i in 0..10 {
            all.extend(e.on_event(&ev(30 + i, "5.5.5.5", Signal::SshAuthFail)));
        }
        assert!(bans(&all).is_empty());
    }

    /// A login shields an address from its own service's typos only.
    #[test]
    fn trust_from_a_login_is_per_service() {
        let login = |e: &mut Engine, ip: &str, t: i64| {
            e.on_event(&Event::new(t * SEC, ip.parse().unwrap(), Signal::XmppAuthOk).account(Some("alice@x.org")));
        };
        // XMPP typos from a logged-in address: alert, no ban
        let mut e = engine();
        login(&mut e, "5.5.5.1", 0);
        let mut all = vec![];
        for i in 0..10 {
            all.extend(e.on_event(&ev(10 + i, "5.5.5.1", Signal::XmppAuthFail).account(Some("alice@x.org"))));
        }
        assert!(bans(&all).is_empty() && all.iter().any(|a| a.topic == Some(Topic::Protected)), "{all:?}");
        // SSH guessing from it: banned like anyone else
        let mut all = vec![];
        for i in 0..10 {
            all.extend(e.on_event(&ev(30 + i, "5.5.5.1", Signal::SshInvalidUser).account(Some("oracle"))));
        }
        assert_eq!(bans(&all), vec!["5.5.5.1"]);
        // a canary name, even on the same service
        let mut e = engine();
        e.enable_sharing(vec![]);
        login(&mut e, "5.5.5.2", 0);
        login(&mut e, "5.5.5.3", 0);
        assert_eq!(bans(&e.on_event(&ev(5, "5.5.5.2", Signal::XmppCanary).account(Some("test@x.org")))), vec!["5.5.5.2"]);
        // but not blocked packets, a tripwire port or a scan included: one forged SYN would
        // lock the user out (and they may share a carrier NAT); nor are they reported to peers
        let mut all = e.on_event(&ev(5, "5.5.5.3", Signal::FwTripwire).port(Some(23)));
        for port in 1000..1020 {
            all.extend(e.on_event(&ev(6, "5.5.5.3", Signal::FwBlock).port(Some(port))));
        }
        assert!(bans(&all).is_empty(), "{all:?}");
        let facts = e.take_outbox(1.0);
        assert!(!facts.iter().any(|f| format!("{f:?}").contains("5.5.5.3")), "{facts:?}");
        assert!(matches!(&facts[..], [FactBody::Ban { forgeable: false, .. }]), "the canary ban is shared: {facts:?}");
        // trust ends trust_ttl (24 h by default) after the last login
        let mut e = engine();
        login(&mut e, "5.5.5.4", 0);
        let day = 86_400;
        let mut all = vec![];
        for i in 0..10 {
            all.extend(e.on_event(&ev(day + 10 + i, "5.5.5.4", Signal::XmppAuthFail).account(Some("alice@x.org"))));
        }
        assert_eq!(bans(&all), vec!["5.5.5.4"]);
    }

    #[test]
    fn login_trust_survives_a_restart_per_service() {
        let mut e = engine();
        e.on_event(&Event::new(0, "5.5.5.9".parse().unwrap(), Signal::SshAuthOk).account(Some("user6")));
        let st = e.export(None);
        assert!(st.trusted.is_empty());
        let json = serde_json::to_string(&st).unwrap();
        let mut back = engine();
        back.restore(serde_json::from_str(&json).unwrap());
        let ip = "5.5.5.9".parse().unwrap();
        assert!(back.trusted_for(ip, Source::Ssh) && !back.trusted_for(ip, Source::Ejabberd));
        // a state file of an older version: its logins (service unknown) are dropped
        let mut old: serde_json::Value = serde_json::from_str(&json).unwrap();
        old["trusted"] = serde_json::json!([["5.5.5.9", 0]]);
        old.as_object_mut().unwrap().remove("trusted_by");
        let mut back = engine();
        back.restore(serde_json::from_value(old).unwrap());
        assert_eq!(back.protection(ip), None);
    }

    #[test]
    fn port_spread_scanner() {
        let mut e = engine();
        let ip = "11.47.253.221";
        let mut all = vec![];
        for (i, port) in [5222u16, 5269, 5280, 5443].iter().enumerate() {
            all.extend(e.on_event(&ev(i as i64, ip, Signal::XmppConn).port(Some(*port))));
        }
        for i in 0..4 {
            all.extend(e.on_event(&ev(10 + i, ip, Signal::XmppNoAuth).port(Some(5222))));
        }
        assert_eq!(bans(&all), vec![ip]);
    }

    #[test]
    fn escalation_ladder_and_expiry() {
        let mut e = engine();
        let ip = "8.8.4.4";
        let burst = |e: &mut Engine, t0: i64| {
            let mut v = vec![];
            for i in 0..3 {
                v.extend(e.on_event(&ev(t0 + i, ip, Signal::XmppTlsFail)));
            }
            v
        };
        let first = burst(&mut e, 0);
        assert_eq!(first[0].until, Some((2 + 3600) * SEC));
        let expired = e.tick(4000 * SEC);
        assert!(expired.iter().any(|a| a.kind == ActionKind::Unban));
        let second = burst(&mut e, 20_000);
        let b = second.iter().find(|a| a.kind == ActionKind::Ban).unwrap();
        assert_eq!(b.until, Some((20_002 + 6 * 3600) * SEC), "second offence gets the next ladder step");
    }

    #[test]
    fn subnet_aggregation_respects_trust() {
        let mut e = engine();
        let mut all = vec![];
        for host in [10, 11, 12] {
            for i in 0..3 {
                all.extend(e.on_event(&ev(i, &format!("11.20.59.{host}"), Signal::XmppTlsFail)));
            }
        }
        all.extend(e.tick(120 * SEC));
        let b = bans(&all);
        assert!(b.contains(&"11.20.59.0/24".to_string()));
        let sub = all.iter().find(|a| a.target.map(|t| t.prefix) == Some(24)).unwrap();
        assert_eq!(sub.superseded.len(), 3, "host bans inside the subnet are replaced");
        assert!(e.banned_by("11.20.59.200".parse().unwrap()).is_some());

        // A subnet that contains a trusted address is never banned wholesale.
        let mut e = engine();
        e.on_event(&Event::new(0, "11.26.44.5".parse().unwrap(), Signal::XmppAuthOk).account(Some("a@b")));
        let mut all = vec![];
        for host in [10, 11, 12] {
            for i in 0..3 {
                all.extend(e.on_event(&ev(i + 1, &format!("11.26.44.{host}"), Signal::XmppTlsFail)));
            }
        }
        all.extend(e.tick(120 * SEC));
        assert!(!bans(&all).iter().any(|b| b.contains('/')));
    }

    #[test]
    fn distributed_subnet_probing() {
        let mut e = engine();
        let mut all = vec![];
        for host in 1..=6 {
            all.extend(e.on_event(&ev(host, &format!("11.37.48.{host}"), Signal::XmppTlsFail)));
        }
        assert!(bans(&all).is_empty(), "one probe per address is not a ban on its own");
        all.extend(e.tick(120 * SEC));
        assert_eq!(bans(&all), vec!["11.37.48.0/24"]);
    }

    /// Three failed TLS handshakes within 3 s: a host ban.
    fn attack(e: &mut Engine, t: i64, ip: &str) {
        for i in 0..3 {
            e.on_event(&ev(t + i, ip, Signal::XmppTlsFail));
        }
    }

    #[test]
    fn subnet_bans_grow_step_by_step() {
        // (across /19s and /16s: addresses the public mirror keeps as they are, see make_public_mirror.zsh)
        let mut e = engine();
        for host in [10, 11, 12] {
            attack(&mut e, 0, &format!("5.8.123.{host}"));
        }
        assert_eq!(bans(&e.tick(120 * SEC)), vec!["5.8.123.0/24"], "the first subnet ban is a /24");

        // 5 prefix bits away (common network /19): more than one step, so it stays a host ban
        attack(&mut e, 200, "5.8.100.5");
        assert!(bans(&e.tick(300 * SEC)).is_empty());

        // in the same /22: the ban grows to the /22 and takes both in
        attack(&mut e, 400, "5.8.121.7");
        let a = e.tick(500 * SEC);
        assert_eq!(bans(&a), vec!["5.8.120.0/22"]);
        let grown = a.iter().find(|a| a.kind == ActionKind::Ban).unwrap();
        assert_eq!(grown.superseded.len(), 2, "{:?}", grown.superseded);
        assert!(grown.message.contains("grown from 5.8.123.0/24, banned nearby: 5.8.121.7"), "{}", grown.message);
        assert!(grown.evidence.iter().any(|l| l.contains(" 5.8.121.7 ")), "what it did: {:?}", grown.evidence);
        assert_eq!(e.banned_by("5.8.122.200".parse().unwrap()).unwrap().net.to_string(), "5.8.120.0/22");
        assert!(e.banned_by("5.8.124.1".parse().unwrap()).is_none(), "the rest of the /16 stays reachable");

        // /22 -> /20 (5.8.113.1), which brings 5.8.100.5 within one step: /19, as one ban
        attack(&mut e, 600, "5.8.113.1");
        let a = e.tick(700 * SEC);
        assert_eq!(bans(&a), vec!["5.8.96.0/19"]);
        let grown = a.iter().find(|a| a.kind == ActionKind::Ban).unwrap();
        assert!(grown.message.contains("grown from 5.8.120.0/22, banned nearby: 5.8.100.5, 5.8.113.1"), "{}", grown.message);

        // never past v4_wide_prefix (/16), never into the next /16
        attack(&mut e, 800, "5.8.200.1");
        attack(&mut e, 800, "5.9.0.1");
        assert!(bans(&e.tick(900 * SEC)).is_empty(), "3 bits from the /19: too far");
        attack(&mut e, 1000, "5.8.64.9");
        assert_eq!(bans(&e.tick(1100 * SEC)), vec!["5.8.0.0/16"], "/18, then 5.8.200.1 is one step away");
        assert_eq!(e.banned_by("5.9.0.1".parse().unwrap()).unwrap().net.to_string(), "5.9.0.1");
        assert!(bans(&e.tick(1200 * SEC)).is_empty());
        let cover = subnet_coverage(&e.export(None).bans);
        assert_eq!(cover, SubnetCoverage { subnets: 1, v4_addresses: 65_536, widest_v4: Some(16) });
    }

    #[test]
    fn subnet_growth_limits() {
        let seed = |e: &mut Engine| {
            for host in [10, 11, 12] {
                attack(e, 0, &format!("11.20.59.{host}"));
            }
            assert_eq!(bans(&e.tick(120 * SEC)), vec!["11.20.59.0/24"]);
        };
        // a user who logged in from the next /24 keeps it out of the ban
        let mut e = engine();
        e.on_event(&Event::new(0, "11.20.58.50".parse().unwrap(), Signal::XmppAuthOk).account(Some("a@b")));
        seed(&mut e);
        attack(&mut e, 200, "11.20.57.7");
        assert!(bans(&e.tick(300 * SEC)).is_empty());

        // two banned /24s side by side make exactly their /23
        let mut e = engine();
        seed(&mut e);
        for host in [20, 21, 22] {
            attack(&mut e, 200, &format!("11.20.58.{host}"));
        }
        assert_eq!(bans(&e.tick(300 * SEC)), vec!["11.20.58.0/24", "11.20.58.0/23"]);

        // with a network database: never into another provider's addresses
        let mut e = engine();
        let mut db = crate::geo::GeoDb::default();
        db.read("11.20.56.0,11.20.57.255,64501,\"Other\"\n11.20.58.0,11.20.63.255,64500,\"Provider\"\n".as_bytes(), false).unwrap();
        e.geo = Some(Arc::new(db));
        seed(&mut e);
        attack(&mut e, 200, "11.20.57.7");
        attack(&mut e, 200, "11.20.58.9");
        assert_eq!(bans(&e.tick(300 * SEC)), vec!["11.20.58.0/23"], "the /22 would hold AS64501's 11.20.56.0/23");

        // a larger step: one ban anywhere within it is enough (here 5 bits, /24 -> /19)
        let mut cfg = Config::default();
        cfg.subnets.wide_max_step = 8;
        let mut e = Engine::new(Arc::new(cfg), 0);
        seed(&mut e);
        attack(&mut e, 200, "11.20.36.5");
        assert_eq!(bans(&e.tick(300 * SEC)), vec!["11.20.32.0/19"]);

        // growth off: /24 bans stay /24
        let mut cfg = Config::default();
        cfg.subnets.wide_enabled = false;
        let mut e = Engine::new(Arc::new(cfg), 0);
        seed(&mut e);
        attack(&mut e, 200, "11.20.57.7");
        assert!(bans(&e.tick(300 * SEC)).is_empty());

        // IPv6 /64 bans grow too, 4 bits at a time, up to /48
        let mut e = engine();
        for host in 1..=3 {
            attack(&mut e, 0, &format!("3fff:130:1:2::{host}"));
        }
        assert_eq!(bans(&e.tick(120 * SEC)), vec!["3fff:130:1:2::/64"]);
        attack(&mut e, 200, "3fff:130:1:3::1");
        assert_eq!(bans(&e.tick(300 * SEC)), vec!["3fff:130:1:2::/63"], "the narrowest network with the nearest ban");
        attack(&mut e, 400, "3fff:130:1:ff::1");
        assert!(bans(&e.tick(500 * SEC)).is_empty(), "8 bits away: more than 4 at a time");
        attack(&mut e, 600, "3fff:130:1:8::1");
        assert_eq!(bans(&e.tick(700 * SEC)), vec!["3fff:130:1::/56"], "through the /60 on to the far one, in one go");
        attack(&mut e, 800, "3fff:130:2::1");
        assert!(bans(&e.tick(900 * SEC)).is_empty(), "another /48: never past v6_wide_prefix");
        // ...and not at all with v6_wide_prefix = v6_prefix
        let mut cfg = Config::default();
        cfg.subnets.v6_wide_prefix = 64;
        let mut e = Engine::new(Arc::new(cfg), 0);
        for host in 1..=3 {
            attack(&mut e, 0, &format!("3fff:130:1:2::{host}"));
        }
        assert_eq!(bans(&e.tick(120 * SEC)), vec!["3fff:130:1:2::/64"]);
        attack(&mut e, 200, "3fff:130:1:3::1");
        assert!(bans(&e.tick(300 * SEC)).is_empty());
    }

    #[test]
    fn new_network_alert_after_learning() {
        let mut e = engine();
        let ok = |t: i64, ip: &str| Event::new(t * SEC, ip.parse().unwrap(), Signal::XmppAuthOk).account(Some("admin@x"));
        let mut all = e.on_event(&ok(0, "1.1.1.1"));
        all.extend(e.on_event(&ok(60, "2.2.2.2")));
        assert!(all.is_empty(), "networks are learned silently at first");
        let a = e.on_event(&ok(8 * 86_400, "3.3.3.3"));
        assert!(a.iter().any(|a| a.message.contains("new network 3.3.0.0/16")));
        assert!(e.on_event(&ok(8 * 86_400 + 5, "2.2.2.9")).is_empty(), "known network");
        // accounts beyond MAX_ACCOUNTS are not tracked: their networks aren't kept either
        e.account_first_seen.extend((0..MAX_ACCOUNTS).map(|i| (format!("ejabberd:u{i}@x"), 0)));
        e.on_event(&Event::new(9 * 86_400 * SEC, "4.4.4.4".parse().unwrap(), Signal::XmppAuthOk).account(Some("new@x")));
        assert!(!e.account_nets.contains_key("ejabberd:new@x") && !e.account_asns.contains_key("ejabberd:new@x"));
    }

    #[test]
    fn own_address_is_never_scored_and_wall_alerts_have_real_time() {
        let mut e = engine();
        e.set_own_addresses(vec!["11.29.39.236".parse().unwrap()]);
        for i in 0..20 {
            assert!(bans(&e.on_event(&ev(i, "11.29.39.236", Signal::XmppNoAuth))).is_empty());
        }
        assert_eq!(e.protection("11.29.39.236".parse().unwrap()), Some("this host"));
        assert!(e.ips.get(&"11.29.39.236".parse().unwrap()).is_none_or(|s| s.slow == 0.0), "its own checks score nothing");
        // engine clock still at the start (no log line yet): the alert gets the wall-clock time
        let mut e = engine();
        let a = e.system_alert_wall("cert:x", 86_400 * SEC, Severity::High, "expires".into(), 1_791_806_149 * SEC);
        assert_eq!(a[0].ts, 1_791_806_149 * SEC);
        assert_eq!(e.now, 0, "engine time itself is untouched");
    }

    #[test]
    fn longer_bans_outlive_a_shorter_subnet_ban() {
        let mut e = engine();
        let mut out = vec![];
        let long: Net = "11.18.9.9".parse().unwrap();
        e.insert_ban(long, 30 * 86_400 * SEC, 5, "repeat".into(), None, "m".into(), vec![], "x", &mut out);
        let short: Net = "11.18.9.0/24".parse().unwrap();
        e.insert_ban(short, 3600 * SEC, 1, "subnet".into(), None, "m".into(), vec![], "x", &mut out);
        assert_eq!(out[1].superseded, vec![long], "nftables needs the host element gone first");
        assert!(e.banned_by("11.18.9.9".parse().unwrap()).is_some_and(|b| b.net == short));
        let a = e.tick(3601 * SEC);
        let kinds: Vec<(ActionKind, String)> = a.iter().map(|a| (a.kind, a.target.unwrap().to_string())).collect();
        assert_eq!(kinds, vec![(ActionKind::Unban, "11.18.9.0/24".into()), (ActionKind::Ban, "11.18.9.9".into())]);
        assert_eq!(a[1].until, Some(30 * 86_400 * SEC), "same end as before");
        assert!(e.export(None).bans.iter().all(|b| b.inner.is_empty()));
    }

    #[test]
    fn unknown_accounts_get_no_user_notices() {
        let mut e = engine();
        let ok = Event::new(0, "1.1.1.1".parse().unwrap(), Signal::XmppAuthOk).account(Some("bob@x.org"));
        e.on_event(&ok);
        let mut all = vec![];
        for (i, acct) in ["bob@x.org", "nosuchuser@x.org"].iter().enumerate() {
            for j in 0..25 {
                let ip = format!("45.{i}.{}.{j}", j % 5);
                all.extend(e.on_event(&ev(100 + j, &ip, Signal::XmppAuthFail).account(Some(acct))));
            }
        }
        let attacks: Vec<&Action> = all.iter().filter(|a| a.topic == Some(Topic::AccountAttack)).collect();
        assert_eq!(attacks.len(), 2, "both reported to admins");
        assert_eq!(attacks[0].accounts, vec!["ejabberd:bob@x.org"]);
        assert!(attacks[1].accounts.is_empty() && attacks[1].message.contains("nosuchuser"), "no notice to a made-up account");
    }

    #[test]
    fn state_file_compact_gzip_and_old_format() {
        let mut e = engine();
        e.on_event(&ev(5, "8.8.4.4", Signal::FwTripwire).port(Some(23)));
        let st = e.export(Some("c1".into()));
        let bytes = encode_state(&st).unwrap();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
        let back = decode_state(&bytes).unwrap();
        assert_eq!(back.offenders, st.offenders);
        assert_eq!(back.cursor.as_deref(), Some("c1"));
        let json = serde_json::to_string(&st).unwrap();
        assert!(json.contains(r#"[["8.8.4.4",[1,5]]]"#), "{json}");
        // written by earlier versions: plain JSON, offenders as objects in microseconds
        let old = json.replace(r#"[["8.8.4.4",[1,5]]]"#, r#"[["8.8.4.4",{"count":1,"last_ban":5000000}]]"#);
        assert_eq!(decode_state(old.as_bytes()).unwrap().offenders, st.offenders);
    }

    #[test]
    fn new_network_with_geo_database() {
        let mut e = engine();
        e.geo = Some(Arc::new(crate::geo::tests::sample()));
        let ok = |t: i64, ip: &str| Event::new(t * SEC, ip.parse().unwrap(), Signal::XmppAuthOk).account(Some("user5@x"));
        assert!(e.on_event(&ok(0, "5.9.1.1")).is_empty(), "learning");
        // a different /16 (and country) of the same provider: no news
        assert!(e.on_event(&ok(8 * 86_400, "11.41.1.1")).is_empty());
        let a = e.on_event(&ok(8 * 86_400 + 60, "1.0.0.7"));
        assert_eq!(
            a[0].message,
            "ejabberd:user5@x logged in from a new network: Australia / Cloudflare, Inc. (AS13335) - 1.0.0.7 (1.0.0.0/16)"
        );
        assert!(a[0]
            .user_note
            .as_deref()
            .unwrap()
            .starts_with("New login to your account from Australia / Cloudflare, Inc. (AS13335), address 1.0.0.7 at"));
        let st = e.export(None);
        assert_eq!(st.account_asns["ejabberd:user5@x"].len(), 2);
    }

    #[test]
    fn distributed_account_attack_and_compromise() {
        let mut e = engine();
        let mut all = vec![];
        for i in 0..25 {
            let ip = format!("45.{}.0.{}", i % 7, i);
            all.extend(e.on_event(&ev(i, &ip, Signal::XmppAuthFail).account(Some("admin@example.org"))));
        }
        assert!(all.iter().any(|a| a.kind == ActionKind::Alert && a.message.contains("distributed attack")));

        let mut e = engine();
        let mut all = vec![];
        all.extend(e.on_event(&ev(0, "7.7.7.7", Signal::XmppAuthFail).account(Some("bob@x"))));
        all.extend(e.on_event(&ev(1, "7.7.7.7", Signal::XmppAuthFail).account(Some("bob@x"))));
        all.extend(e.on_event(&ev(2, "7.7.7.7", Signal::XmppAuthFail).account(Some("bob@x"))));
        all.extend(e.on_event(&Event::new(3 * SEC, "7.7.7.7".parse().unwrap(), Signal::XmppAuthOk).account(Some("bob@x"))));
        assert!(all.iter().any(|a| a.severity == Severity::Critical && a.message.contains("possible compromise")));
    }

    #[test]
    fn shadow_false_positive_is_lifted() {
        let mut e = engine();
        for i in 0..3 {
            e.on_event(&ev(i, "3.3.3.3", Signal::XmppTlsFail));
        }
        assert!(e.banned_by("3.3.3.3".parse().unwrap()).is_some());
        let a = e.on_event(&Event::new(10 * SEC, "3.3.3.3".parse().unwrap(), Signal::XmppAuthOk).account(Some("c@d")));
        assert!(a.iter().any(|a| a.kind == ActionKind::Unban));
        assert!(e.banned_by("3.3.3.3".parse().unwrap()).is_none());
    }

    /// A weekly alert stays weekly: garbage collection keeps its gate.
    #[test]
    fn weekly_system_alerts_stay_weekly() {
        let mut e = engine();
        let day = 86_400 * SEC;
        let week = 7 * day;
        let remind = |e: &mut Engine, t| e.system_alert_wall("cluster-key-age", week, Severity::Warning, "rotate".into(), t);
        assert_eq!(remind(&mut e, day).len(), 1);
        e.tick(3 * day); // collects garbage
        assert!(remind(&mut e, 3 * day).is_empty(), "two days later");
        assert_eq!(remind(&mut e, day + week).len(), 1, "a week later");
    }

    /// A login can only lift a ban in shadow mode, and only one tied to its connection; an
    /// unverified one earns no trust either.
    #[test]
    fn logins_lift_no_bans_in_enforce_mode_and_unverified_ones_earn_no_trust() {
        let ip: IpAddr = "3.3.3.3".parse().unwrap();
        let login = |verified| Event::new(10 * SEC, ip, Signal::XmppAuthOk).account(Some("c@d")).verified(verified);
        let banned = |mode| {
            let mut e = Engine::new(Arc::new(Config { mode, ..Default::default() }), 0);
            e.enable_sharing(vec![]);
            for i in 0..3 {
                e.on_event(&ev(i, "3.3.3.3", Signal::XmppTlsFail));
            }
            let _ = e.take_outbox(f64::MAX);
            e
        };
        let mut e = banned(crate::config::Mode::Enforce);
        let a = e.on_event(&login(true));
        assert!(a.iter().all(|a| a.kind != ActionKind::Unban), "enforce: the ban stays");
        assert!(a.iter().any(|a| a.topic == Some(Topic::FalsePositive) && a.message.contains("ban kept")));
        assert!(e.banned_by(ip).is_some());
        assert!(!e.take_outbox(f64::MAX).iter().any(|f| matches!(f, FactBody::Unban { .. })), "nothing lifted at the peers");

        let mut e = banned(crate::config::Mode::Shadow);
        e.on_event(&login(false));
        assert!(e.banned_by(ip).is_some(), "an unverified login lifts nothing");
        assert!(!e.trusted_for(ip, Source::Ejabberd), "and earns no trust");
        e.on_event(&login(true));
        assert!(e.banned_by(ip).is_none());
        assert!(e.trusted_for(ip, Source::Ejabberd));
    }

    #[test]
    fn persistence_roundtrip() {
        let mut e = engine();
        for i in 0..3 {
            e.on_event(&ev(i, "4.4.4.4", Signal::XmppTlsFail));
        }
        let json = serde_json::to_string(&e.export(Some("c1".into()))).unwrap();
        let st: PersistedState = serde_json::from_str(&json).unwrap();
        let mut e2 = engine();
        e2.restore(st);
        assert!(e2.banned_by("4.4.4.4".parse().unwrap()).is_some());
    }

    #[test]
    fn integrity_findings_go_to_admins_and_survive_restarts() {
        use crate::cronwatch::{CronReport, Key};
        let mut e = engine();
        let h = 3600 * SEC;
        let mut items = BTreeMap::from([(Key::Crontab("/etc/crontab".into()), String::new())]);
        let report = |t: Micros, items: &BTreeMap<Key, String>| CronReport { scanned: t, items: items.clone(), ..Default::default() };
        let a = e.on_cron(&report(h, &items));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].topic, Some(Topic::Integrity));
        assert_eq!(a[0].ts, h, "wall-clock time, not the (lagging) engine clock");

        // a change while learning is logged without a topic: nobody is notified
        items.insert(Key::Line("/etc/crontab".into(), "* * * * * root /tmp/x".into()), String::new());
        let a = e.on_cron(&report(2 * h, &items));
        assert!(a.len() == 1 && a[0].topic.is_none() && a[0].severity == Severity::Info, "{a:?}");

        // the baseline survives a restart; after the learn period a change is news
        let mut e2 = engine();
        e2.restore(e.export(None));
        assert!(e2.on_cron(&report(30 * h, &items)).iter().all(|a| a.severity == Severity::Info));
        items.insert(Key::Line("/etc/crontab".into(), "@reboot root /opt/y".into()), String::new());
        let a = e2.on_cron(&report(31 * h, &items));
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].severity, a[0].topic), (Severity::High, Some(Topic::Integrity)));
        assert_eq!(a[0].evidence, ["+ `@reboot root /opt/y`"]);
        assert!(crate::notify::NotifyCfg::default().admin_topics.contains(&Topic::Integrity));
    }

    #[test]
    fn ssh_audit_alerts_once_and_survives_restarts() {
        use crate::sshaudit::{Issue, SshAuditReport};
        let h = 3600 * SEC;
        let report = |t: Micros, pw: &str| SshAuditReport {
            read: t,
            installed: true,
            layout: "standard".into(),
            issues: if pw == "yes" {
                vec![Issue {
                    id: "password-auth".into(),
                    severity: Severity::Warning,
                    message: "sshd accepts passwords".into(),
                    fix: "x".into(),
                }]
            } else {
                vec![]
            },
            settings: BTreeMap::from([("passwordauthentication".into(), pw.into())]),
            ..Default::default()
        };
        let mut e = engine();
        let a = e.on_ssh_audit(report(h, "no"));
        assert!(a.len() == 1 && a[0].topic.is_none(), "nothing wrong: only logged: {a:?}");
        assert!(e.snapshot(0, 0).ssh_audit.is_some());

        let mut e2 = engine();
        e2.restore(e.export(None));
        let a = e2.on_ssh_audit(report(2 * h, "yes"));
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!((a[0].severity, a[0].topic), (Severity::Warning, Some(Topic::Integrity)));
        assert!(a[0].evidence.iter().any(|e| e == "changed: passwordauthentication: no -> yes"), "{:?}", a[0].evidence);
        assert!(e2.on_ssh_audit(report(3 * h, "yes")).is_empty(), "told once");
    }

    #[test]
    fn operator_bans() {
        let mut e = engine();
        e.enable_sharing(vec!["203.0.113.9".parse().unwrap()]);
        e.now = 100 * SEC;
        let net: Net = "11.18.9.9".parse().unwrap();
        let a = e.operator_ban(net, 100 * SEC + 7 * 86_400 * SEC, "scanner".into()).unwrap();
        assert_eq!(bans(&a), vec!["11.18.9.9"]);
        assert!(a[0].message.contains("for 7d00h (operator): scanner"), "{}", a[0].message);
        assert_eq!(a[0].category.as_deref(), Some("operator"));
        let shared = e.take_outbox(1000.0);
        assert!(matches!(&shared[..], [FactBody::Ban { forgeable: false, .. }]), "shared, as evidence a peer applies: {shared:?}");
        // again: the old ban goes first (nftables would keep its timeout)
        let a = e.operator_ban(net, 200 * SEC, "shorter".into()).unwrap();
        assert_eq!(a.iter().map(|a| a.kind).collect::<Vec<_>>(), vec![ActionKind::Unban, ActionKind::Ban]);
        // refused: protected addresses, ones inside a wider ban, networks wider than own bans
        for (target, why) in [("11.48.43.31", "allowlisted"), ("203.0.113.9", "cluster peer"), ("10.0.0.1", "private")] {
            let err = e.operator_ban(target.parse().unwrap(), 300 * SEC, "x".into()).unwrap_err();
            assert!(err.contains(why), "{target}: {err}");
        }
        assert!(e.operator_ban("11.48.43.0/24".parse().unwrap(), 300 * SEC, "x".into()).unwrap_err().contains("protected"));
        assert!(e.operator_ban("11.12.0.0/12".parse().unwrap(), 300 * SEC, "x".into()).unwrap_err().contains("wider"));
        e.operator_ban("11.18.9.0/24".parse().unwrap(), 300 * SEC, "range".into()).unwrap();
        assert!(e
            .operator_ban("11.18.9.7".parse().unwrap(), 300 * SEC, "x".into())
            .unwrap_err()
            .contains("inside the ban on 11.18.9.0/24"));
    }

    #[test]
    fn waf_bans_follow_their_source() {
        use crate::waf::{Decision, WafSource};
        let mut e = engine();
        e.enable_sharing(vec![]);
        e.now = 100 * SEC;
        let d = |net: &str, until: Option<Micros>, reason: &str| Decision {
            net: net.parse().unwrap(),
            until,
            kind: "ban".into(),
            origin: "crowdsec".into(),
            reason: reason.into(),
        };
        let src = WafSource { name: "crowdsec".into(), ..Default::default() };
        let ten_hours = Some(100 * SEC + 10 * 3600 * SEC);
        let mut decisions = vec![
            d("11.18.9.9", ten_hours, "crowdsecurity/http-probing"),
            d("198.51.100.0/24", None, ""),
            d("11.48.43.31", ten_hours, "allowlisted"),
            d("11.12.0.0/12", ten_hours, "too wide"),
            d("11.18.9.9", Some(200 * SEC), "a shorter one for the same address"),
        ];
        let (a, skipped) = e.waf_sync(&src, &decisions);
        assert_eq!((bans(&a), skipped), (vec!["11.18.9.9".to_string(), "198.51.100.0/24".into()], 2));
        assert!(a[0].message.contains("for 10h00m (waf crowdsec): crowdsecurity/http-probing"), "{}", a[0].message);
        assert_eq!((a[0].category.as_deref(), a[0].evidence.len()), (Some("waf"), 1));
        assert_eq!(a[1].until, Some(100 * SEC + 4 * 3600 * SEC), "[waf] default_ban without a duration");
        assert_eq!(e.banned_by("11.18.9.9".parse().unwrap()).unwrap().reason, "waf crowdsec: crowdsecurity/http-probing");
        assert_eq!(e.waf_bans("crowdsec").len(), 2);
        assert!(e.waf_bans("other").is_empty());
        assert_eq!(e.take_outbox(1000.0).iter().filter(|f| matches!(f, FactBody::Ban { forgeable: false, .. })).count(), 2);

        // read again a minute later: nothing to do
        e.now += 60 * SEC;
        assert!(e.waf_sync(&src, &decisions).0.is_empty());
        // two hours on, the plain list's 4 h ban has less than half left: renewed
        e.now += 2 * 3600 * SEC;
        let a = e.waf_sync(&src, &decisions).0;
        assert_eq!(
            a.iter().map(|a| (a.kind, a.target.unwrap().to_string())).collect::<Vec<_>>(),
            [(ActionKind::Unban, "198.51.100.0/24".to_string()), (ActionKind::Ban, "198.51.100.0/24".into())]
        );

        // the WAF drops a decision: its ban is lifted, here and at the peers
        decisions.remove(0);
        let _ = e.take_outbox(1000.0);
        let a = e.waf_sync(&src, &decisions).0;
        assert_eq!(a.len(), 1);
        assert!(a[0].kind == ActionKind::Unban && a[0].message.contains("lifted by waf crowdsec"), "{a:?}");
        assert!(matches!(&e.take_outbox(1000.0)[..], [FactBody::Unban { .. }]));
        // a ban logguard decided itself is never the WAF's to lift
        e.on_event(&ev(e.now / SEC, "11.18.9.10", Signal::SshCanary).account(Some("root")));
        assert!(e.banned_by("11.18.9.10".parse().unwrap()).is_some());
        assert!(e.waf_sync(&src, &decisions).0.is_empty());
        assert!(e.banned_by("11.18.9.10".parse().unwrap()).is_some());

        // not shared: nothing for the peers; a recent login protects the address
        let quiet = WafSource { name: "local".into(), share: false, ..Default::default() };
        let _ = e.take_outbox(1000.0);
        let now = e.now;
        e.on_event(&Event::new(now, "5.5.5.9".parse().unwrap(), Signal::SshAuthOk).account(Some("user6")));
        let (a, skipped) = e.waf_sync(&quiet, &[d("11.18.9.20", None, "x"), d("5.5.5.9", None, "a user's address")]);
        assert_eq!((bans(&a), skipped), (vec!["11.18.9.20".to_string()], 1));
        assert!(e.take_outbox(1000.0).is_empty());
    }

    #[test]
    fn allowlisted_host_names() {
        let mut e = engine();
        let ip = "198.51.100.20";
        e.on_event(&ev(1, ip, Signal::SshCanary).account(Some("root")));
        assert!(e.banned_by(ip.parse().unwrap()).is_some());
        // the home connection's name now resolves to it: unbanned, and never banned again
        let a = e.set_allow_hosts(vec![ip.parse().unwrap()]);
        assert!(a.iter().any(|a| a.kind == ActionKind::Unban && a.message.contains("allowlisted host name")), "{a:?}");
        assert_eq!(e.protection(ip.parse().unwrap()), Some("allowlisted host name"));
        let a = e.on_event(&ev(2, ip, Signal::SshCanary).account(Some("root")));
        assert!(bans(&a).is_empty() && a.iter().any(|a| a.topic == Some(Topic::Protected)));
        // the name moved on: the old address is an address like any other
        e.set_allow_hosts(vec!["198.51.100.21".parse().unwrap()]);
        assert_eq!(e.protection(ip.parse().unwrap()), None);
        assert!(e.snapshot(0, 10).allow_hosts == vec!["198.51.100.21".parse::<Net>().unwrap()]);
    }

    #[test]
    fn new_ssh_keys_after_learning() {
        let mut e = engine();
        let login =
            |t: i64, key: &str| Event::new(t * SEC, "198.51.100.30".parse().unwrap(), Signal::SshAuthOk).account(Some("gw")).key(Some(key));
        assert!(e.on_event(&login(0, "ED25519 SHA256:aaa")).is_empty());
        assert!(e.on_event(&login(86_400, "ED25519 SHA256:bbb")).is_empty(), "learned during the first week");
        assert!(e.on_event(&login(8 * 86_400, "ED25519 SHA256:aaa")).is_empty());
        let a = e.on_event(&login(9 * 86_400, "RSA SHA256:evil"));
        assert_eq!((a.len(), a[0].severity, a[0].topic), (1, Severity::High, Some(Topic::Compromise)));
        assert!(a[0].message.contains("ssh:gw logged in from 198.51.100.30 with an SSH key it never used before (RSA SHA256:evil"));
        assert!(e.on_event(&login(9 * 86_400 + 60, "RSA SHA256:evil")).is_empty(), "known from now on");
        // kept across a restart
        let mut back = engine();
        back.restore(decode_state(&encode_state(&e.export(None)).unwrap()).unwrap());
        assert!(back.on_event(&login(10 * 86_400, "RSA SHA256:evil")).is_empty());
        // su names the account's last SSH login
        let sw = crate::parse::privilege::parse("su", "FAILED SU (to root) gw on pts/0").unwrap();
        let a = back.on_privilege(&sw, 10 * 86_400 * SEC + 5 * SEC);
        assert!(a[0].message.contains("(gw's last SSH login: 198.51.100.30, 5s ago)"), "{}", a[0].message);
    }

    #[test]
    fn alert_gate_is_bounded() {
        let mut e = engine();
        e.now = 1000 * SEC;
        e.alert_gate.insert("system:cluster-key-age".into(), 0);
        for i in 0..MAX_ALERT_GATE as i64 + 500 {
            e.alert_gate.insert(format!("proc-exe:x{i}:/tmp/x{i}"), i);
        }
        e.gc(false);
        assert_eq!(e.alert_gate.len(), MAX_ALERT_GATE + 1);
        assert!(e.alert_gate.contains_key("system:cluster-key-age"), "system keys stay");
        assert!(!e.alert_gate.contains_key("proc-exe:x0:/tmp/x0") && e.alert_gate.contains_key("proc-exe:x50499:/tmp/x50499"));
    }

    /// One local user changing their own crontab, scripts or processes every minute gets
    /// `USER_ALERTS_PER_HOUR` alerts to the admins an hour, and one saying the rest are only
    /// logged; changes only root can make are never held back.
    #[test]
    fn a_users_own_changes_have_an_hourly_budget() {
        let mut e = engine();
        let h = 3600 * SEC;
        let finding = |i: usize, owner: Option<u32>| crate::cronwatch::Finding {
            key: format!("cron:/var/spool/cron/crontabs/eve:{i}"),
            every: 0,
            severity: Severity::High,
            message: format!("cron: crontab changed #{i}"),
            evidence: vec![],
            notify: true,
            owner,
            files: vec![],
        };
        let sent = |a: &[Action]| a.iter().filter(|a| a.topic == Some(Topic::Integrity)).count();
        let mut a = Vec::new();
        for i in 0..8 {
            a.extend(e.findings(vec![finding(i, Some(1000))], 10 * h + i as i64 * MIN));
        }
        assert_eq!(a.len(), 9, "every change on record, and the notice: {a:?}");
        assert_eq!(sent(&a), USER_ALERTS_PER_HOUR + 1);
        let notice = a.iter().find(|a| a.message.contains("only logged (")).unwrap();
        assert!(notice.message.contains("uid 1000") && notice.topic == Some(Topic::Integrity), "{}", notice.message);
        let held: Vec<&Action> = a.iter().filter(|a| a.topic.is_none()).collect();
        assert_eq!(held.len(), 3);
        assert!(held[0].message.ends_with("[only logged: uid 1000 had its 5 alerts this hour]"), "{}", held[0].message);
        // another user, and root's own changes, are not held back by it
        assert_eq!(sent(&e.findings(vec![finding(20, Some(1001))], 10 * h + 9 * MIN)), 1);
        assert_eq!(sent(&e.findings((30..40).map(|i| finding(i, None)).collect(), 10 * h + 10 * MIN)), 10);
        // an hour on, the user's alerts go out again
        assert_eq!(sent(&e.findings(vec![finding(50, Some(1000))], 11 * h + 5 * MIN)), 1);
    }

    /// A local user trying every account there is gets one alert per 10 minutes, not one
    /// per account: the hourly messages about compromises stay for the rest.
    #[test]
    fn privilege_failures_alert_per_user() {
        let mut e = engine();
        let fail = |target: &str| crate::parse::privilege::parse("su", &format!("FAILED SU (to {target}) eve on pts/1")).unwrap();
        let mut alerts = 0;
        for (i, target) in ["root", "daemon", "bin", "sys", "www-data", "ejabberd"].iter().enumerate() {
            alerts += e.on_privilege(&fail(target), (100 + i as i64) * SEC).len();
        }
        assert_eq!(alerts, 1);
        let a = e.on_privilege(&fail("root"), 100 * SEC + 11 * MIN);
        assert!(a[0].message.contains("7 failures in 11m"), "{}", a[0].message);
        let ok = crate::parse::privilege::parse("su", "(to daemon) eve on pts/1").unwrap();
        let a = e.on_privilege(&ok, 100 * SEC + 12 * MIN);
        assert!(a[0].severity == Severity::Warning && a[0].message.contains("after 7 failed attempts"), "{}", a[0].message);
    }

    #[test]
    fn honeypot_hits_are_not_forgeable() {
        let mut e = engine();
        e.enable_sharing(vec![]);
        let a = e.on_event(&ev(1, "11.17.8.8", Signal::TripwireConnect).port(Some(2323)));
        assert_eq!(bans(&a), vec!["11.17.8.8"]);
        assert_eq!(a[0].category.as_deref(), Some("tripwire"));
        let facts = e.take_outbox(10.0);
        assert!(
            facts.iter().all(|f| matches!(f, FactBody::Ban { forgeable: false, .. } | FactBody::Report { forgeable: false, .. })),
            "a completed handshake names its sender: {facts:?}"
        );
        // a logged-in address (a carrier NAT neighbour) is still excused, as for blocked SYNs
        let user = "11.17.8.9";
        e.on_event(&ev(2, user, Signal::SshAuthOk).account(Some("gw")));
        assert!(bans(&e.on_event(&ev(3, user, Signal::TripwireConnect).port(Some(2323)))).is_empty());
    }
}
