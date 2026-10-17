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
use crate::exposure::{ExposureReport, ListenerKey};
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
/// Accounts tracked for failed logins (names are attacker-chosen) and known to log in.
const MAX_ACCOUNTS: usize = 50_000;
/// Addresses remembered per attacked account: enough to see a distributed attack, bounded
/// so a large botnet can't make every failure scan a huge list.
const MAX_ACCOUNT_IPS: usize = 1000;

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

/// Digest category of a ban, from the dominant signal.
fn category_of(s: Signal) -> &'static str {
    match s {
        Signal::FwTripwire => "tripwire",
        s if s.is_canary() => "canary",
        Signal::FwBlock | Signal::FwLimit => "port scan",
        Signal::PeerReport => "cluster evidence",
        s if s.source() == Source::Ssh => "ssh",
        s if s.source() == Source::Ejabberd => "xmpp",
        s if s.source() == Source::Nextcloud => "web",
        _ => "other",
    }
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
    pub events: [u32; 5],
    pub bans: u32,
}

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
}

impl Stats {
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
}

/// Per-source liveness, for "this log went quiet" alerts.
#[derive(Default)]
struct SilenceState {
    last_line: BTreeMap<Source, Micros>,
    last_event: BTreeMap<Source, Micros>,
    lines_since_event: BTreeMap<Source, u64>,
    quiet: BTreeSet<Source>,
    blind: BTreeSet<Source>,
}

impl Engine {
    pub fn new(cfg: Arc<Config>, now: Micros) -> Self {
        Engine {
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
        }
    }

    /// The accounts (qualified, `ejabberd:alice@example.org`) that have logged in successfully at
    /// some point; user notifications go only to those.
    fn notifiable(&self, accounts: Vec<String>) -> Vec<String> {
        accounts.into_iter().filter(|a| self.account_first_seen.contains_key(a)).collect()
    }

    /// Networks wider than anything logguard bans itself (default /16, IPv6 /32): a peer
    /// sending one is broken or compromised, and a /1 ban or allowlist entry would be a disaster.
    fn too_wide(&self, net: &Net) -> bool {
        let sc = &self.cfg.subnets;
        net.prefix < if net.is_v4() { sc.v4_wide_prefix.min(16) } else { sc.v6_prefix.min(32) }
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
    /// admins (routine results, changes accepted while learning) are only logged.
    fn findings(&mut self, findings: Vec<crate::cronwatch::Finding>, wall: Micros) -> Vec<Action> {
        let engine_time = self.now;
        self.now = self.now.max(wall);
        let mut out = Vec::new();
        for f in findings {
            if f.every > 0 {
                if self.alert_gate.get(&f.key).is_some_and(|t| self.now - t < f.every) {
                    continue;
                }
                self.alert_gate.insert(f.key, self.now);
            }
            let a = Action {
                ts: self.now,
                kind: ActionKind::Alert,
                severity: f.severity,
                target: None,
                until: None,
                message: f.message,
                evidence: f.evidence,
                superseded: vec![],
                applied: false,
                topic: f.notify.then_some(Topic::Integrity),
                accounts: vec![],
                user_note: None,
                notice: None,
                category: None,
            };
            self.push_action(a, &mut out);
        }
        self.now = engine_time;
        out
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
    /// excuses that service's typos and reconnects, never canary names, tripwire ports,
    /// other services or peers' reports.
    fn trust_covers(&self, ip: IpAddr, st: &IpState) -> bool {
        let mut offences = st.counts.iter().filter(|(s, n)| *n > 0 && !s.is_success()).peekable();
        offences.peek().is_some() && offences.all(|(s, _)| !s.is_canary() && s != Signal::FwTripwire && self.trusted_for(ip, s.source()))
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

    fn ban(&mut self, net: Net, reason: String, evidence: Vec<String>, category: &str, out: &mut Vec<Action>) {
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
            ob.push(FactBody::Ban { net, until, reason: reason.clone() });
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
        let src_idx = ev.signal.source() as usize;
        if let Some(b) = self.stats.bucket(ev.ts) {
            b.events[src_idx] += 1;
        }
        if self.ips.len() >= self.cfg.scoring.max_tracked_ips {
            self.gc(true);
        }

        if ev.signal.is_success() {
            self.on_success(ev, &mut out);
            return out;
        }

        // a login to this service excuses its background noise; one to another service doesn't
        let protected = self.hard_protection(ev.ip).is_some() || self.trusted_for(ev.ip, ev.signal.source());
        let cfg = Arc::clone(&self.cfg);
        let mut points = cfg.weight(ev.signal);
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
        st.report_points += points + bonus;
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
                reports.push(FactBody::Report { ip: *ip, points: (st.report_points * 10.0).round() / 10.0, signals });
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
            FactBody::Ban { net, until, reason } => {
                if self.too_wide(net) {
                    return out;
                }
                let until = (*until).min(now + ccfg.max_remote_ban.micros());
                let protected = self.net_protected(net) || (net.is_host() && self.hard_protection(net.addr).is_some());
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
            FactBody::Report { ip, points, signals } => {
                // NaN is rejected too; one report can't add more than a ban's worth.
                // (`min` would turn NaN into the threshold, so check first)
                let points = points * ccfg.report_factor;
                if points.is_nan() || points <= 0.0 || self.hard_protection(*ip).is_some() {
                    return out;
                }
                let points = points.min(self.cfg.scoring.fast_threshold);
                let cfg = Arc::clone(&self.cfg);
                *self.stats.events.entry(Signal::PeerReport).or_default() += 1;
                if let Some(b) = self.stats.bucket(now) {
                    b.events[Source::Peer as usize] += 1;
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
            // In enforce mode a banned host can't get here; in shadow mode this is a would-be false positive.
            self.alert_about(
                format!("fp:{}", ev.ip),
                MIN,
                Severity::Warning,
                Some(ban.net),
                format!("{who} authenticated from banned address {} (ban: {}) - likely false positive, lifting ban", ev.ip, ban.reason),
                Some(Topic::FalsePositive),
                vec![who.clone()],
                None,
                out,
            );
            if ban.net.is_host() {
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
        if cfg.accounts.new_network_alerts && ev.account.is_some() && !cfg.accounts.new_network_ignore.contains(&acct) {
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

        if cfg.allowlist.trust_authenticated {
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
        self.ban(Net::host(ip), reason, evidence, category, out);
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
        let exposed: BTreeMap<ListenerKey, String> =
            report.listeners.iter().filter(|l| l.exposure.is_exposed() && !l.dynamic).map(|l| (l.key, l.process.clone())).collect();
        let describe = |k: &ListenerKey| report.listeners.iter().find(|l| l.key == *k).map_or("", |l| l.exposure.describe()).to_string();

        if ufw_expected && report.ufw_active == Some(false) {
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
                format!("ufw allows {rule} from anywhere, but nothing listens on it publicly - remove the rule or it exposes whatever binds there next"),
                Some(Topic::Exposure),
                vec![],
                None,
                &mut out,
            );
        }

        match self.exposure_baseline.as_mut() {
            None => {
                let list: Vec<String> = exposed.iter().map(|(k, p)| format!("{k} ({p})")).collect();
                self.exposure_baseline = Some(exposed.iter().map(|(k, p)| (*k, (p.clone(), 0))).collect());
                self.alert_about(
                    "exposure-learned".into(),
                    day,
                    Severity::Info,
                    None,
                    format!("exposure baseline learned: {} exposed listeners: {}", list.len(), list.join(", ")),
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

        let mut wide: BTreeMap<Net, (usize, BTreeSet<Net>)> = BTreeMap::new();
        for (net, g) in &narrow {
            if net.is_v4() && sc.wide_enabled && !g.bad.is_empty() {
                let w = wide.entry(Net::new(net.addr, sc.v4_wide_prefix)).or_default();
                w.0 += g.bad.len();
                w.1.insert(*net);
            }
        }
        for (net, (count, subnets)) in wide {
            if count >= sc.wide_min_bad_ips
                && subnets.len() >= sc.wide_min_subnets
                && self.covering_ban(&net).is_none()
                && !self.net_protected(&net)
            {
                let reason = format!("{count} bad addresses across {} /{} subnets", subnets.len(), sc.v4_prefix);
                let evidence = subnets.iter().map(|n| n.to_string()).collect();
                self.ban(net, reason, evidence, "subnet", out);
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
            // What the members did (the latest lines of the worst ones), so the actions log
            // keeps proof for a network ban too: "10-11 05:03:08 11.40.29.77 block TCP/23".
            let mut members = g.members.clone();
            members.sort_by(|a, b| b.0.total_cmp(&a.0));
            for (_, ip) in members.iter().take(10) {
                if let Some(st) = self.ips.get(ip) {
                    let lines: Vec<&str> = st.evidence.lines().collect();
                    for l in &lines[lines.len().saturating_sub(3)..] {
                        if let Some((stamp, text)) = l.split_at_checked(14) {
                            sample.push(format!("{stamp} {ip}{text}"));
                        }
                    }
                }
            }
            self.ban(net, reason, sample, "subnet", out);
        }
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
        self.alert_gate.retain(|_, t| now - *t < 86_400 * crate::time::SEC);
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
            certs: self.certs.clone(),
            last_lines: self.silence.last_line.clone(),
            cron: self.cron_view.clone(),
            av: cfg.antivirus.enabled.then(|| self.av.clone()),
            resources: self.resources.clone(),
            world: self.world(),
            port_names: cfg.port_names(),
            actions_log: None,
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
        self.now = self.now.max(st.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::SEC;

    fn engine() -> Engine {
        let mut cfg = Config::default();
        cfg.allowlist.nets.push("11.35.43.31".parse().unwrap());
        Engine::new(Arc::new(cfg), 0)
    }

    fn ev(t: i64, ip: &str, s: Signal) -> Event {
        Event::new(t * SEC, ip.parse().unwrap(), s).port(Some(5223)).detail("x")
    }

    fn bans(actions: &[Action]) -> Vec<String> {
        actions.iter().filter(|a| a.kind == ActionKind::Ban).map(|a| a.target.unwrap().to_string()).collect()
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
            e.on_event(&Event::new(103 * h + i * 60 * SEC, "11.8.1.2".parse().unwrap(), Signal::FwBlock));
            e.count_record(Source::Ufw, 103 * h + i * 60 * SEC);
        }
        let m = msgs(e.check_silence(106 * h + SEC));
        assert!(m.iter().any(|m| m.starts_with("301 ssh log lines in the last 6h")), "{m:?}");
        e.on_event(&ev(106 * 3600 + 2, "11.8.1.1", Signal::SshPreauth));
        e.count_record(Source::Ssh, 106 * h + 2 * SEC);
        assert_eq!(msgs(e.check_silence(106 * h + 3 * SEC)), vec!["ssh log lines name client addresses again"]);
    }

    #[test]
    fn world_view_by_country_network_and_port() {
        let mut e = engine();
        assert!(!e.snapshot(0, 10).world.geo);
        e.geo = Some(Arc::new(crate::geo::tests::sample()));
        e.on_event(&ev(1, "5.9.1.1", Signal::FwTripwire).port(Some(23))); // DE, banned
        e.on_event(&ev(2, "11.28.1.1", Signal::FwBlock).port(Some(3389))); // FI, tracked
        e.on_event(&ev(3, "11.28.1.1", Signal::FwBlock).port(Some(3389)));
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
        e.on_event(&ev(6, "11.28.1.2", Signal::FwBlock).port(Some(3389)));
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
        let a = e.on_event(&ev(1, "11.9.9.9", Signal::SshCanary).account(Some("ubuntu")));
        assert_eq!(bans(&a), vec!["11.9.9.9"]);
        assert_eq!(a[0].category.as_deref(), Some("canary"));
        assert!(a.iter().all(|a| a.accounts.is_empty()), "nobody to notify about a canary account");
        let login = Event::new(2 * SEC, "11.9.9.8".parse().unwrap(), Signal::XmppCanary)
            .detail(format!("{} test@x.org", crate::event::CANARY_LOGIN));
        let a = e.on_event(&login);
        assert!(a.iter().any(|a| a.severity == Severity::Critical && a.topic == Some(Topic::Compromise)), "{a:?}");
        assert!(e.protection("11.9.9.8".parse().unwrap()).is_none(), "a canary login earns no trust");
        // your own (allowlisted) address mistyping a name: alert, no ban
        let a = e.on_event(&ev(3, "11.35.43.31", Signal::SshCanary).account(Some("root")));
        assert!(bans(&a).is_empty());
        assert!(a.iter().any(|a| a.topic == Some(Topic::Protected)));
    }

    #[test]
    fn dead_rule_survives_a_container_restart_without_alert() {
        let mut e = engine();
        let report = |t: i64, dead: &[&str]| ExposureReport {
            scanned: t * 60 * SEC,
            ufw_active: Some(true),
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
    fn exposure_drift() {
        use crate::event::Proto;
        use crate::exposure::{Exposure, Listener};
        let mut e = engine();
        let l = |port: u16, exposure| Listener {
            key: ListenerKey { proto: Proto::Tcp, addr: "0.0.0.0".parse().unwrap(), port },
            process: "p".into(),
            exposure,
            dynamic: false,
        };
        let report = |t: i64, ls: Vec<Listener>, dead: Vec<&str>| ExposureReport {
            scanned: t * 60 * SEC,
            ufw_active: Some(true),
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

    #[test]
    fn cluster_facts() {
        use crate::cluster::{ClusterCfg, Fact, FactBody};
        let ccfg = ClusterCfg::default();
        let fact = |body| Fact { origin: "vpn".into(), seq: 1, created: 1000 * SEC, hops: 1, body };
        let mut e = engine();
        e.enable_sharing(vec!["11.25.48.86".parse().unwrap()]);
        e.now = 1000 * SEC;

        // remote ban: applied, capped to max_remote_ban, tagged with its origin, not re-shared as ours
        let a =
            e.apply_peer_fact(&fact(FactBody::Ban { net: "1.2.3.4".parse().unwrap(), until: 999_999 * SEC, reason: "scan".into() }), &ccfg);
        assert!(a[0].message.contains("(from peer vpn)"), "{}", a[0].message);
        let b = e.banned_by("1.2.3.4".parse().unwrap()).unwrap().clone();
        assert_eq!(b.origin.as_deref(), Some("vpn"));
        assert_eq!(b.until, 1000 * SEC + 86_400 * SEC);
        assert!(e.take_outbox(10.0).is_empty());

        // protected addresses: home (allowlist) and cluster peers are never banned by peers
        for ip in ["11.35.43.31", "11.25.48.86"] {
            assert!(e
                .apply_peer_fact(&fact(FactBody::Ban { net: ip.parse().unwrap(), until: 2000 * SEC, reason: "x".into() }), &ccfg)
                .is_empty());
        }

        // reports add up across nodes at report_factor (0.5): 2 reports of 120 points = ban
        let rep =
            |seq, pts| Fact { seq, ..fact(FactBody::Report { ip: "5.5.5.5".parse().unwrap(), points: pts, signals: "tripwire".into() }) };
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
        let rep7 = |seq| Fact { seq, ..fact(FactBody::Report { ip: "6.6.6.7".parse().unwrap(), points: 200.0, signals: "x".into() }) };
        let mut a = e.apply_peer_fact(&rep7(10), &ccfg);
        a.extend(e.apply_peer_fact(&rep7(11), &ccfg));
        assert_eq!(bans(&a), vec!["6.6.6.7"]);

        // unban from a peer lifts the ban
        let a = e.apply_peer_fact(&fact(FactBody::Unban { net: "1.2.3.4".parse().unwrap(), reason: "fp".into() }), &ccfg);
        assert_eq!(a[0].kind, ActionKind::Unban);
        // a broken or compromised peer: absurdly wide networks and non-numbers are ignored
        for wide in ["0.0.0.0/1", "10.0.0.0/8", "2000::/3"] {
            let net: Net = wide.parse().unwrap();
            assert!(e.apply_peer_fact(&fact(FactBody::Ban { net, until: 2000 * SEC, reason: "x".into() }), &ccfg).is_empty());
            assert!(e.apply_peer_fact(&fact(FactBody::Allow { net, until: 2000 * SEC, note: "x".into() }), &ccfg).is_empty());
        }
        let nan = Fact { seq: 4, ..fact(FactBody::Report { ip: "5.5.5.6".parse().unwrap(), points: f64::NAN, signals: "x".into() }) };
        assert!(e.apply_peer_fact(&nan, &ccfg).is_empty());
        assert!(!e.ips.contains_key(&"5.5.5.6".parse().unwrap()), "nothing recorded");
        let huge = Fact { seq: 5, ..fact(FactBody::Report { ip: "5.5.5.7".parse().unwrap(), points: 1e300, signals: "x".into() }) };
        e.apply_peer_fact(&huge, &ccfg);
        assert_eq!(e.ips[&"5.5.5.7".parse().unwrap()].fast, 100.0, "capped at one threshold");
        assert!(
            e.apply_peer_fact(&fact(FactBody::Ban { net: "11.8.0.0/16".parse().unwrap(), until: 2000 * SEC, reason: "x".into() }), &ccfg)
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
                body: FactBody::Ban { net: "11.9.0.0/24".parse().unwrap(), until: 9000 * SEC, reason: "r".into() },
            },
            &ClusterCfg::default(),
        );
        let err = e.operator_unban("11.9.0.7".parse().unwrap()).unwrap_err();
        assert!(err.contains("covered by the ban on 11.9.0.0/24"), "{err}");
        assert!(e.operator_unban("8.8.4.4".parse().unwrap()).unwrap_err().contains("no active ban"));

        // allowlisting lifts bans inside it, protects, and expires
        let a = e.operator_allow("11.9.0.0/24".parse().unwrap(), 100 * SEC, "office".into());
        assert_eq!(a.iter().map(|a| a.kind).collect::<Vec<_>>(), vec![ActionKind::Unban, ActionKind::Allow]);
        assert_eq!(e.protection("11.9.0.7".parse().unwrap()), Some("operator allowlist"));
        let tripped: Vec<Action> = (0..5).flat_map(|i| e.on_event(&ev(30 + i, "11.9.0.7", Signal::XmppTlsFail))).collect();
        assert!(bans(&tripped).is_empty());
        let expired = e.tick(200 * SEC);
        assert!(expired.iter().any(|a| a.kind == ActionKind::Disallow));
        assert!(e.protection("11.9.0.7".parse().unwrap()).is_none());
        assert!(e.operator_disallow("11.9.0.0/24".parse().unwrap()).is_err());
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
            e.on_event(&ev(i64::from(host), &format!("11.8.1.{host}"), Signal::XmppConn).port(Some(5269)));
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
        assert!(e.on_event(&ev(0, "11.42.40.218", Signal::XmppTlsFail)).is_empty());
        assert!(e.on_event(&ev(5, "11.42.40.218", Signal::XmppTlsFail)).is_empty());
        let a = e.on_event(&ev(9, "11.42.40.218", Signal::XmppTlsFail));
        assert_eq!(bans(&a), vec!["11.42.40.218"]);
        assert_eq!(a[0].until, Some(9 * SEC + 3600 * SEC));
        // no duplicate ban while active
        assert!(e.on_event(&ev(10, "11.42.40.218", Signal::XmppTlsFail)).is_empty());
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
            all.extend(e.on_event(&ev(i, "11.35.43.31", Signal::XmppTlsFail)));
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
        // a canary name or a tripwire port, even on the same service
        let mut e = engine();
        login(&mut e, "5.5.5.2", 0);
        login(&mut e, "5.5.5.3", 0);
        assert_eq!(bans(&e.on_event(&ev(5, "5.5.5.2", Signal::XmppCanary).account(Some("test@x.org")))), vec!["5.5.5.2"]);
        assert_eq!(bans(&e.on_event(&ev(5, "5.5.5.3", Signal::FwTripwire).port(Some(23)))), vec!["5.5.5.3"]);
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
        let ip = "11.34.253.221";
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
                all.extend(e.on_event(&ev(i, &format!("11.11.59.{host}"), Signal::XmppTlsFail)));
            }
        }
        all.extend(e.tick(120 * SEC));
        let b = bans(&all);
        assert!(b.contains(&"11.11.59.0/24".to_string()));
        let sub = all.iter().find(|a| a.target.map(|t| t.prefix) == Some(24)).unwrap();
        assert_eq!(sub.superseded.len(), 3, "host bans inside the subnet are replaced");
        assert!(e.banned_by("11.11.59.200".parse().unwrap()).is_some());

        // A subnet that contains a trusted address is never banned wholesale.
        let mut e = engine();
        e.on_event(&Event::new(0, "11.16.44.5".parse().unwrap(), Signal::XmppAuthOk).account(Some("a@b")));
        let mut all = vec![];
        for host in [10, 11, 12] {
            for i in 0..3 {
                all.extend(e.on_event(&ev(i + 1, &format!("11.16.44.{host}"), Signal::XmppTlsFail)));
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
            all.extend(e.on_event(&ev(host, &format!("11.24.48.{host}"), Signal::XmppTlsFail)));
        }
        assert!(bans(&all).is_empty(), "one probe per address is not a ban on its own");
        all.extend(e.tick(120 * SEC));
        assert_eq!(bans(&all), vec!["11.24.48.0/24"]);
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
    }

    #[test]
    fn own_address_is_never_scored_and_wall_alerts_have_real_time() {
        let mut e = engine();
        e.set_own_addresses(vec!["11.17.39.236".parse().unwrap()]);
        for i in 0..20 {
            assert!(bans(&e.on_event(&ev(i, "11.17.39.236", Signal::XmppNoAuth))).is_empty());
        }
        assert_eq!(e.protection("11.17.39.236".parse().unwrap()), Some("this host"));
        assert!(e.ips.get(&"11.17.39.236".parse().unwrap()).is_none_or(|s| s.slow == 0.0), "its own checks score nothing");
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
        let long: Net = "11.9.9.9".parse().unwrap();
        e.insert_ban(long, 30 * 86_400 * SEC, 5, "repeat".into(), None, "m".into(), vec![], "x", &mut out);
        let short: Net = "11.9.9.0/24".parse().unwrap();
        e.insert_ban(short, 3600 * SEC, 1, "subnet".into(), None, "m".into(), vec![], "x", &mut out);
        assert_eq!(out[1].superseded, vec![long], "nftables needs the host element gone first");
        assert!(e.banned_by("11.9.9.9".parse().unwrap()).is_some_and(|b| b.net == short));
        let a = e.tick(3601 * SEC);
        let kinds: Vec<(ActionKind, String)> = a.iter().map(|a| (a.kind, a.target.unwrap().to_string())).collect();
        assert_eq!(kinds, vec![(ActionKind::Unban, "11.9.9.0/24".into()), (ActionKind::Ban, "11.9.9.9".into())]);
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
        assert!(e.on_event(&ok(8 * 86_400, "11.28.1.1")).is_empty());
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
}
