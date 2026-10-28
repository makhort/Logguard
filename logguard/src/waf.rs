//! Decisions of WAFs and other security apps that publish the addresses they block (`[waf]`):
//! CrowdSec's local API, `cscli` output and blocklist mirror, or any JSON, CSV or line-based
//! list. A WAF sees attacks inside web requests that no log line here shows; logguard then
//! enforces its verdicts at the firewall, for every port, and with a cluster on every node.
//!
//! Each `[[waf.sources]]` entry is read (a URL with `curl`, a file, or a command's output),
//! parsed by its `format` into decisions (an address or network, until when, why), filtered
//! by decision type and origin, and then either
//! - `action = "ban"`: each decision becomes a logguard ban for as long as it lasts, under
//!   the protections of an operator ban (allowlists, peers, this host, recent logins), in the
//!   TUI and digest, shared with the cluster, and lifted when the WAF drops the decision; or
//! - `action = "list"`: the networks go into the separate sets `waf4`/`waf6`, replaced in one
//!   step like the blocklist feeds (for thousands of entries: CrowdSec's community blocklist).
//!
//! A source that can't be read keeps what it had: its bans run out on their own, its list
//! entries when their decisions end (the last good copy is cached with absolute end times).
//!
//! New formats: the generic `json`, `csv` and `regex` formats map an app's fields by name,
//! so most apps need no code. One that does is one more [`Format`] variant whose parser
//! returns [`Fields`] for each entry, through [`Parsed::add`].

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::net::Net;
use crate::time::{self, Dur, Micros, SEC};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// One address or network per line; `#` and `;` start comments (CrowdSec's blocklist
    /// mirror, fail2ban or any WAF exporting a plain list).
    #[default]
    Plain,
    /// Whatever CrowdSec gives out, told apart by its shape: the local API's decisions
    /// (`/v1/decisions`, `/v1/decisions/stream?startup=true`), `cscli decisions list -o json`
    /// (alerts holding decisions), `-o raw` (CSV), or the blocklist mirror's plain list.
    Crowdsec,
    /// JSON (or JSON lines): the entries at `items`, their fields named by the `*_field` settings.
    Json,
    /// Delimited text: fields by header name, or by column number (from 1).
    Csv,
    /// Text of any kind: every match of `pattern` on a line, its named groups (`ip`, and
    /// optionally `duration`, `until`, `type`, `origin`, `reason`) the fields.
    Regex,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafAction {
    /// A logguard ban per decision (dozens to thousands: a WAF's own detections).
    #[default]
    Ban,
    /// Into the sets `waf4`/`waf6` (blocklists of many thousands; nftables and ipset only).
    List,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafSource {
    /// Names its bans (`waf <name>: <reason>`) and its cache file: letters, digits, `_`, `-`.
    pub name: String,
    pub format: Format,
    /// Where the decisions are: one of `url` (fetched with `[waf] fetch`), `file`, `command`.
    pub url: String,
    pub file: Option<PathBuf>,
    /// A program and its arguments (no shell), e.g. `["cscli", "decisions", "list", "-o", "json"]`.
    pub command: Vec<String>,
    /// A file holding the API key sent with `url` (CrowdSec: `cscli bouncers add logguard`).
    /// Given to curl on its stdin, never on its command line.
    pub api_key_file: Option<PathBuf>,
    /// The header carrying it; for a bearer token, `Authorization` with `Bearer <token>` in the file.
    pub api_key_header: String,
    pub action: WafAction,
    /// Decision types to block (CrowdSec: `ban`; `captcha` and `throttle` are for the HTTP
    /// layer). Empty: all. Entries without a type (plain lists) always count.
    pub types: Vec<String>,
    /// Only decisions of these origins (CrowdSec: `crowdsec`, `cscli`, `CAPI`, `lists`, ...).
    /// Empty: all.
    pub origins: Vec<String>,
    /// `action = "ban"`: share the bans with the cluster (as `logguard ban` does).
    pub share: bool,
    /// `action = "ban"`: more decisions than this is a broken or misdirected source: its bans
    /// are left as they are.
    pub max_bans: usize,
    /// `json`: the dotted path to the entries (empty: the document, or its top-level array).
    /// Arrays on the way are walked into: `decisions` finds every decision in a list of alerts.
    pub items: String,
    /// `json` and `csv`: the fields of an entry (dotted paths in JSON; header names, or
    /// column numbers from 1, in CSV). Empty: not given. `duration` is CrowdSec's `4h0m0s`, a
    /// number of seconds or `90s`/`12h`/`7d`; `until` a Unix time or an ISO 8601 date.
    pub ip_field: String,
    pub duration_field: String,
    pub until_field: String,
    pub type_field: String,
    pub origin_field: String,
    pub reason_field: String,
    /// `csv`: the field separator (one character), and whether the first line names the columns.
    pub delimiter: String,
    pub header: bool,
    /// `regex`: matched against each line.
    pub pattern: String,
}

impl Default for WafSource {
    fn default() -> Self {
        WafSource {
            name: String::new(),
            format: Format::Plain,
            url: String::new(),
            file: None,
            command: vec![],
            api_key_file: None,
            api_key_header: "X-Api-Key".into(),
            action: WafAction::Ban,
            types: vec!["ban".into()],
            origins: vec![],
            share: true,
            max_bans: 10_000,
            items: String::new(),
            ip_field: "ip".into(),
            duration_field: String::new(),
            until_field: String::new(),
            type_field: String::new(),
            origin_field: String::new(),
            reason_field: String::new(),
            delimiter: ",".into(),
            header: true,
            pattern: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafCfg {
    pub enabled: bool,
    /// How often every source is read (10 s at least).
    pub refresh: Dur,
    /// The last good decisions of every source; used while it can't be read.
    pub cache_dir: PathBuf,
    /// Download command for `url` sources; the URL is appended. Output must go to stdout.
    pub fetch: Vec<String>,
    /// The longest ban a decision becomes (a WAF's permanent decisions included).
    pub max_ban: Dur,
    /// How long a decision that doesn't say lasts as a ban (renewed while it is listed).
    pub default_ban: Dur,
    /// `action = "list"`: as in `[feeds]`, for all such sources together.
    pub max_entries: usize,
    pub min_prefix_v4: u8,
    pub min_prefix_v6: u8,
    pub sources: Vec<WafSource>,
}

impl Default for WafCfg {
    fn default() -> Self {
        WafCfg {
            enabled: false,
            refresh: Dur(60),
            cache_dir: "/var/lib/logguard/waf".into(),
            // a local API is usually plain http on 127.0.0.1; a redirect may only go to https
            fetch: ["curl", "-fsS", "--proto", "=http,https", "--proto-redir", "=https", "--max-time", "30", "--max-filesize", "16000000"]
                .map(String::from)
                .to_vec(),
            max_ban: Dur(7 * 86_400),
            default_ban: Dur(4 * 3600),
            max_entries: 100_000,
            min_prefix_v4: 12,
            min_prefix_v6: 24,
            sources: vec![],
        }
    }
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The host of an `http://` or `https://` URL, without brackets or port.
fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    }
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || crate::net::parse_ip(host).is_some_and(|ip| ip.is_loopback())
}

impl WafCfg {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.sources.is_empty() {
            bail!("[waf] enabled = true needs at least one [[waf.sources]]");
        }
        if self.refresh.0 < 10 {
            bail!("[waf] refresh must be 10s or more");
        }
        if self.default_ban.0 == 0 || self.max_ban.0 == 0 {
            bail!("[waf] default_ban and max_ban must be more than 0");
        }
        let mut names = std::collections::BTreeSet::new();
        for s in &self.sources {
            s.validate(&self.fetch)?;
            if !names.insert(s.name.as_str()) {
                bail!("[[waf.sources]]: two sources are named '{}'", s.name);
            }
        }
        Ok(())
    }
}

impl WafSource {
    fn validate(&self, fetch: &[String]) -> Result<()> {
        if !name_ok(&self.name) {
            bail!("[[waf.sources]] name '{}' must be 1-32 letters, digits, '_' or '-'", self.name);
        }
        let n = &self.name;
        let places = usize::from(!self.url.is_empty()) + usize::from(self.file.is_some()) + usize::from(!self.command.is_empty());
        if places != 1 {
            bail!("[[waf.sources]] {n}: give exactly one of url, file or command");
        }
        if !self.url.is_empty() {
            if !(self.url.starts_with("http://") || self.url.starts_with("https://"))
                || self.url.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                bail!("[[waf.sources]] {n}: url must be an http:// or https:// URL without spaces");
            }
            if fetch.is_empty() {
                bail!("[waf] fetch is empty");
            }
        }
        if self.file.as_ref().is_some_and(|f| !f.is_absolute()) {
            bail!("[[waf.sources]] {n}: file must be an absolute path");
        }
        if self.api_key_file.is_some() {
            if self.url.is_empty() {
                bail!("[[waf.sources]] {n}: api_key_file goes with a url");
            }
            if !fetch.first().is_some_and(|p| p == "curl" || p.ends_with("/curl")) {
                bail!("[[waf.sources]] {n}: api_key_file needs curl as [waf] fetch (the key goes to it as `-H @-`)");
            }
            if self.api_key_header.is_empty() || !self.api_key_header.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                bail!("[[waf.sources]] {n}: api_key_header must be a header name (letters, digits, '-')");
            }
            if self.url.starts_with("http://") && !is_loopback(url_host(&self.url)) {
                bail!("[[waf.sources]] {n}: the API key would cross the network in clear text: use https:// for {}", url_host(&self.url));
            }
        }
        // a stream without startup=true gives what changed since the last pull only: every
        // decision not repeated would look lifted
        if self.format == Format::Crowdsec && self.url.contains("/decisions/stream") && !self.url.contains("startup=true") {
            bail!("[[waf.sources]] {n}: the decisions stream lists only changes; add ?startup=true (the full list each time) or use /v1/decisions");
        }
        if self.format == Format::Regex {
            let re = compile(&self.pattern).with_context(|| format!("[[waf.sources]] {n}: pattern"))?;
            if !re.capture_names().flatten().any(|g| g == "ip") {
                bail!("[[waf.sources]] {n}: the pattern needs a group named ip, e.g. (?P<ip>[0-9a-fA-F.:/]+)");
            }
        } else if !self.pattern.is_empty() {
            bail!("[[waf.sources]] {n}: pattern is for format = \"regex\"");
        }
        if self.format == Format::Csv && self.delimiter.chars().count() != 1 {
            bail!("[[waf.sources]] {n}: delimiter must be one character");
        }
        if matches!(self.format, Format::Json | Format::Csv) && self.ip_field.is_empty() {
            bail!("[[waf.sources]] {n}: ip_field names the field with the address");
        }
        let has_origin = match self.format {
            Format::Plain => false,
            Format::Crowdsec => true,
            Format::Json | Format::Csv => !self.origin_field.is_empty(),
            Format::Regex => self.pattern.contains("?P<origin>") || self.pattern.contains("?<origin>"),
        };
        if !self.origins.is_empty() && !has_origin {
            bail!("[[waf.sources]] {n}: origins filters on an origin this format doesn't give (origin_field, or a group named origin)");
        }
        if self.max_bans == 0 {
            bail!("[[waf.sources]] {n}: max_bans must be at least 1");
        }
        Ok(())
    }
}

/// Linear-time, like `[[patterns]]`: no hostile line can make it backtrack.
fn compile(pattern: &str) -> Result<regex::Regex> {
    Ok(regex::RegexBuilder::new(pattern).size_limit(1 << 20).build()?)
}

/// One address or network a source wants blocked.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub net: Net,
    /// When it ends; None: while it is listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Micros>,
    /// Its type (`ban`, `captcha`, ...), origin and reason (a scenario, a rule), if given.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// One entry as a format reads it, before it is checked.
#[derive(Debug, Default)]
pub struct Fields {
    pub ip: Option<String>,
    /// CrowdSec's scope: `Ip` and `Range` are addresses; `Country`, `AS`, `Username` aren't.
    pub scope: Option<String>,
    pub duration: Option<String>,
    pub until: Option<String>,
    pub kind: String,
    pub origin: String,
    pub reason: String,
    pub simulated: bool,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub decisions: Vec<Decision>,
    /// Entries not understood: no address, an address that isn't one, a bad duration.
    pub bad: usize,
    /// Left out on purpose: other scopes, simulated, already over, filtered by type or origin.
    pub ignored: usize,
}

/// Log text shown in bans and alerts and sent to peers: no control characters, 100 at most.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(100).collect::<String>().trim().to_string()
}

impl Parsed {
    pub fn add(&mut self, f: Fields, now: Micros) {
        let present = |s: &Option<String>| s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        if f.simulated {
            self.ignored += 1;
            return;
        }
        if let Some(scope) = present(&f.scope) {
            if !scope.eq_ignore_ascii_case("ip") && !scope.eq_ignore_ascii_case("range") {
                self.ignored += 1;
                return;
            }
        }
        let Some(net) = present(&f.ip).and_then(|ip| ip.trim_matches('"').parse::<Net>().ok()) else {
            self.bad += 1;
            return;
        };
        // a duration is relative, so it doesn't depend on the WAF host's clock
        let until = match (present(&f.duration), present(&f.until)) {
            (Some(d), _) => parse_duration(&d).map(|d| now.saturating_add(d)),
            (None, Some(u)) => parse_until(&u),
            (None, None) => Some(Micros::MAX),
        };
        let Some(until) = until else {
            self.bad += 1;
            return;
        };
        if until <= now {
            self.ignored += 1;
            return;
        }
        let until = (until != Micros::MAX).then_some(until);
        self.decisions.push(Decision { net, until, kind: clean(&f.kind), origin: clean(&f.origin), reason: clean(&f.reason) });
    }
}

/// A Go duration as CrowdSec writes it (`3h59m56.9s`, `-1m`, `300ms`), a number of seconds,
/// or `7d`: microseconds, negative for one already over.
pub fn parse_duration(s: &str) -> Option<Micros> {
    let s = s.trim();
    let cap = 100.0 * 365.0 * 86_400.0 * SEC as f64;
    if let Ok(secs) = s.parse::<f64>() {
        return secs.is_finite().then(|| (secs * SEC as f64).clamp(-cap, cap) as Micros);
    }
    let (neg, mut rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total = 0.0f64;
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        let n: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let unit_len = rest.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(rest.len());
        let unit = match &rest[..unit_len] {
            "ns" => 1e-3,
            "us" | "µs" | "μs" => 1.0,
            "ms" => 1e3,
            "s" => 1e6,
            "m" => 6e7,
            "h" => 3.6e9,
            "d" => 8.64e10,
            "w" => 6.048e11,
            _ => return None,
        };
        total += n * unit;
        rest = &rest[unit_len..];
    }
    let total = total.min(cap);
    Some(if neg { -total } else { total } as Micros)
}

/// A Unix time (seconds, or milliseconds when that large) or an ISO 8601 date.
pub fn parse_until(s: &str) -> Option<Micros> {
    let s = s.trim();
    match s.parse::<f64>() {
        Ok(n) if n.is_finite() && n > 0.0 => {
            let secs = if n > 1e11 { n / 1000.0 } else { n };
            Some((secs.min(4e9) * SEC as f64) as Micros)
        }
        Ok(_) => None,
        Err(_) => time::parse_iso_offset(s),
    }
}

/// Parses what a source gave out. An error (not JSON where JSON was expected, lines none of
/// which hold an address) means it said nothing usable: what it had is kept.
pub fn parse(src: &WafSource, text: &str, now: Micros) -> Result<Parsed> {
    let mut p = Parsed::default();
    match src.format {
        Format::Plain => parse_plain(text, now, &mut p)?,
        Format::Crowdsec => parse_crowdsec(text, now, &mut p)?,
        Format::Json => {
            let doc = parse_json_doc(text)?;
            for item in select(&doc, &src.items) {
                p.add(json_fields(item, src), now);
            }
        }
        Format::Csv => parse_csv(src, text, now, &mut p)?,
        Format::Regex => {
            let re = compile(&src.pattern)?;
            let group = |c: &regex::Captures, g: &str| c.name(g).map(|m| m.as_str().to_string());
            // every match on a line: a whole list may be on one (`[{'sshd': ['192.0.2.1', ...]}]`)
            for c in text.lines().flat_map(|line| re.captures_iter(line)) {
                p.add(
                    Fields {
                        ip: group(&c, "ip"),
                        duration: group(&c, "duration"),
                        until: group(&c, "until"),
                        kind: group(&c, "type").unwrap_or_default(),
                        origin: group(&c, "origin").unwrap_or_default(),
                        reason: group(&c, "reason").unwrap_or_default(),
                        ..Default::default()
                    },
                    now,
                );
            }
        }
    }
    Ok(p)
}

fn parse_plain(text: &str, now: Micros, p: &mut Parsed) -> Result<()> {
    let mut lines = 0;
    for line in text.lines() {
        let token = line.split(['#', ';']).next().unwrap_or("").split_whitespace().next().unwrap_or("");
        if token.is_empty() {
            continue;
        }
        lines += 1;
        p.add(Fields { ip: Some(token.to_string()), ..Default::default() }, now);
    }
    // an HTML error page or a login form served with status 200 must not empty the list
    if lines > 0 && p.decisions.is_empty() && p.ignored == 0 {
        bail!("none of its {lines} lines is an address: not a list of addresses?");
    }
    Ok(())
}

/// A JSON document, or JSON lines (one value per line) as an array.
fn parse_json_doc(text: &str) -> Result<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => Ok(v),
        Err(e) => {
            let lines: Option<Vec<Value>> = text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).ok()).collect();
            match lines {
                Some(v) if v.len() > 1 => Ok(Value::Array(v)),
                _ => Err(e).context("not JSON"),
            }
        }
    }
}

/// The values at a dotted `path` under `v` (empty: `v`), walking into arrays on the way;
/// an array found at the end gives its elements.
fn select<'a>(v: &'a Value, path: &str) -> Vec<&'a Value> {
    fn spread(v: &Value) -> Vec<&Value> {
        match v {
            Value::Array(a) => a.iter().collect(),
            Value::Null => vec![],
            v => vec![v],
        }
    }
    let mut cur = vec![v];
    for key in path.split('.').filter(|k| !k.is_empty()) {
        cur = cur.into_iter().flat_map(spread).filter_map(|x| x.get(key)).collect();
    }
    cur.into_iter().flat_map(spread).collect()
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn json_field(item: &Value, path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let mut cur = item;
    for key in path.split('.') {
        cur = cur.get(key)?;
    }
    scalar(cur)
}

fn json_fields(item: &Value, src: &WafSource) -> Fields {
    if let Value::String(s) = item {
        // a list of addresses: ["192.0.2.1", "198.51.100.0/24"]
        return Fields { ip: Some(s.clone()), ..Default::default() };
    }
    let get = |path: &str| json_field(item, path);
    Fields {
        ip: get(&src.ip_field),
        duration: get(&src.duration_field),
        until: get(&src.until_field),
        kind: get(&src.type_field).unwrap_or_default(),
        origin: get(&src.origin_field).unwrap_or_default(),
        reason: get(&src.reason_field).unwrap_or_default(),
        ..Default::default()
    }
}

/// CrowdSec's decision object (the local API's, or one inside an alert of `cscli ... -o json`).
fn crowdsec_fields(d: &Value) -> Fields {
    let get = |k: &str| d.get(k).and_then(scalar);
    Fields {
        ip: get("value"),
        scope: get("scope"),
        duration: get("duration"),
        until: get("until"),
        kind: get("type").unwrap_or_default(),
        origin: get("origin").unwrap_or_default(),
        reason: get("scenario").unwrap_or_default(),
        simulated: d.get("simulated").and_then(Value::as_bool).unwrap_or(false),
    }
}

fn parse_crowdsec(text: &str, now: Micros, p: &mut Parsed) -> Result<()> {
    let t = text.trim_start();
    if t.is_empty() {
        return Ok(()); // `cscli` prints nothing (or `null`) without decisions
    }
    if !(t.starts_with('[') || t.starts_with('{') || t.starts_with("null")) {
        // `cscli decisions list -o raw`: id,source,ip,reason,action,country,as,events_count,expiration,simulated,alert_id
        let first = t.lines().next().unwrap_or("");
        if first.starts_with("id,") && first.contains(",ip,") {
            return parse_crowdsec_raw(t, now, p);
        }
        return parse_plain(t, now, p); // the blocklist mirror
    }
    let doc: Value = serde_json::from_str(t).context("not JSON")?;
    let decisions: Vec<&Value> = match &doc {
        Value::Null => vec![],
        // the stream (with startup=true: everything active); `deleted` is what ended since
        Value::Object(o) if o.contains_key("new") || o.contains_key("deleted") => select(&doc, "new"),
        Value::Array(items) => {
            items.iter().flat_map(|i| if i.get("decisions").is_some() { select(i, "decisions") } else { vec![i] }).collect()
        }
        _ => bail!("not a CrowdSec answer: an object without decisions"),
    };
    for d in decisions {
        p.add(crowdsec_fields(d), now);
    }
    Ok(())
}

fn parse_crowdsec_raw(text: &str, now: Micros, p: &mut Parsed) -> Result<()> {
    let mut lines = text.lines();
    let header = csv_split(lines.next().unwrap_or(""), ',');
    let col = |name: &str| header.iter().position(|h| h.trim() == name);
    let ip = col("ip").context("cscli raw output without an ip column")?;
    let (source, reason, action, expiration, simulated) =
        (col("source"), col("reason"), col("action"), col("expiration"), col("simulated"));
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let row = csv_split(line, ',');
        let at = |i: Option<usize>| i.and_then(|i| row.get(i)).map(|s| s.trim().to_string());
        // `Ip:192.0.2.1`, `Range:198.51.100.0/24`, `Country:XX` (an IPv6 address holds ':' too)
        let (scope, value) = match at(Some(ip)) {
            Some(v) => match v.split_once(':') {
                Some((s, rest)) if s.chars().all(|c| c.is_ascii_alphabetic()) && !s.is_empty() => {
                    (Some(s.to_string()), Some(rest.to_string()))
                }
                _ => (None, Some(v)),
            },
            None => (None, None),
        };
        p.add(
            Fields {
                ip: value,
                scope,
                duration: at(expiration),
                kind: at(action).unwrap_or_default(),
                origin: at(source).unwrap_or_default(),
                reason: at(reason).unwrap_or_default(),
                simulated: at(simulated).is_some_and(|s| s == "true"),
                ..Default::default()
            },
            now,
        );
    }
    Ok(())
}

/// One line of delimited text; `"..."` quotes a field (`""` inside is a quote).
fn csv_split(line: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            c if c == delim && !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn parse_csv(src: &WafSource, text: &str, now: Micros, p: &mut Parsed) -> Result<()> {
    let delim = src.delimiter.chars().next().unwrap_or(',');
    let mut lines = text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
    let header = if src.header { csv_split(lines.next().unwrap_or(""), delim) } else { vec![] };
    let col = |spec: &str| -> Result<Option<usize>> {
        if spec.is_empty() {
            return Ok(None);
        }
        if let Some(i) = header.iter().position(|h| h.trim().eq_ignore_ascii_case(spec)) {
            return Ok(Some(i));
        }
        match spec.parse::<usize>() {
            Ok(n) if n > 0 => Ok(Some(n - 1)),
            _ => bail!("no column '{spec}' in the header"),
        }
    };
    let cols = [&src.ip_field, &src.duration_field, &src.until_field, &src.type_field, &src.origin_field, &src.reason_field]
        .map(|f| col(f))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let mut rows = 0;
    for line in lines {
        rows += 1;
        let row = csv_split(line, delim);
        let at = |i: Option<usize>| i.and_then(|i| row.get(i)).map(|s| s.trim().to_string());
        p.add(
            Fields {
                ip: at(cols[0]),
                duration: at(cols[1]),
                until: at(cols[2]),
                kind: at(cols[3]).unwrap_or_default(),
                origin: at(cols[4]).unwrap_or_default(),
                reason: at(cols[5]).unwrap_or_default(),
                ..Default::default()
            },
            now,
        );
    }
    if rows > 0 && p.decisions.is_empty() && p.ignored == 0 {
        bail!("none of its {rows} rows holds an address in column '{}'", src.ip_field);
    }
    Ok(())
}

/// Keeps the decisions of the types and origins asked for.
pub fn filter(src: &WafSource, p: &mut Parsed) {
    let any = |list: &[String], v: &str| list.iter().any(|x| x.eq_ignore_ascii_case(v));
    let before = p.decisions.len();
    p.decisions.retain(|d| {
        (src.types.is_empty() || d.kind.is_empty() || any(&src.types, &d.kind)) && (src.origins.is_empty() || any(&src.origins, &d.origin))
    });
    p.ignored += before - p.decisions.len();
}

/// The start of the reason of the bans a source made: how they are told from others.
pub fn reason_prefix(source: &str) -> String {
    format!("waf {source}: ")
}

/// Longest a `command` source may run.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// What the source gives out now.
pub fn read_source(cfg: &WafCfg, src: &WafSource) -> Result<String> {
    let max = crate::feeds::MAX_DOWNLOAD;
    let bytes = if let Some(path) = &src.file {
        let f = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
        let mut buf = Vec::new();
        f.take(max + 1).read_to_end(&mut buf).with_context(|| format!("reading {}", path.display()))?;
        buf
    } else if let Some((prog, args)) = src.command.split_first() {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(args);
        let out = crate::proc::run(cmd, None, COMMAND_TIMEOUT).map_err(anyhow::Error::msg)?;
        if !out.status.success() {
            bail!("{prog} failed ({}): {}", out.status, out.complaint());
        }
        out.stdout
    } else {
        let mut cmd = cfg.fetch.clone();
        let mut header = None;
        if let Some(path) = &src.api_key_file {
            header = Some(api_key_header(path, &src.api_key_header)?);
            cmd.extend(["-H".to_string(), "@-".to_string()]);
        }
        let mut buf = Vec::new();
        crate::feeds::fetch_into_with(&cmd, &src.url, header.as_deref().map(str::as_bytes), &mut buf, max)?;
        buf
    };
    if bytes.len() as u64 > max {
        bail!("larger than {} MB", max >> 20);
    }
    Ok(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// `<header>: <key>` for curl's `-H @-`, from a key file only root can read.
fn api_key_header(path: &Path, header: &str) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).with_context(|| format!("api_key_file {}", path.display()))?;
    if meta.mode() & 0o077 != 0 {
        bail!("api_key_file {} can be read by other users: chmod 600 it", path.display());
    }
    let key = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = key.trim();
    if key.is_empty() || key.chars().any(|c| c.is_control()) {
        bail!("api_key_file {} must hold the key on one line", path.display());
    }
    Ok(format!("{header}: {key}\n"))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceStatus {
    pub name: String,
    pub action: WafAction,
    /// Decisions it holds now (after the type and origin filters).
    pub decisions: usize,
    /// Entries not understood, and left out (other scopes, simulated, other types or origins).
    pub bad: usize,
    pub ignored: usize,
    /// It could not be read now: its last good decisions apply (`action = "list"`), or its
    /// bans are left as they are (`action = "ban"`).
    pub from_cache: bool,
    pub error: Option<String>,
    /// `action = "ban"`: the bans it holds now, and decisions that made none (a protected
    /// address, wider than logguard's own bans).
    #[serde(default)]
    pub banned: usize,
    #[serde(default)]
    pub skipped: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WafStatus {
    pub refreshed: Micros,
    pub sources: Vec<SourceStatus>,
    /// The sets `waf4`/`waf6` (`action = "list"`), and the networks dropped as bogons,
    /// protected or too wide.
    pub list_v4: usize,
    pub list_v6: usize,
    pub list_skipped: usize,
    /// The list is in the firewall (not in shadow mode, nor with firewalld, ufw or iptables).
    pub applied: bool,
    pub error: Option<String>,
}

impl WafStatus {
    /// `source: problem` for every source that has one, then the list's.
    pub fn problems(&self) -> Vec<String> {
        self.sources.iter().filter_map(|s| s.error.as_ref().map(|e| format!("{}: {e}", s.name))).chain(self.error.clone()).collect()
    }
}

/// One refresh of every source, for the daemon to apply.
#[derive(Debug, Default)]
pub struct WafUpdate {
    pub status: WafStatus,
    /// What the `action = "list"` sources hold, sanitised and de-nested; None: leave the sets
    /// as they are (too many networks).
    pub list: Option<Vec<Net>>,
    /// Each `action = "ban"` source's decisions; None when it can't be read now (its bans stay).
    pub bans: Vec<(String, Option<Vec<Decision>>)>,
}

#[derive(Serialize, Deserialize)]
struct Cached {
    fetched: Micros,
    decisions: Vec<Decision>,
}

fn cache_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

fn write_cache(dir: &Path, name: &str, c: &Cached) {
    let path = cache_path(dir, name);
    let tmp = path.with_extension("json.tmp");
    if let Ok(text) = serde_json::to_string(c) {
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Reads, parses and filters one source; falls back to its cached decisions (those not over
/// yet) when it can't be read. Returns the decisions, whether they are fresh, and its status.
pub fn load_source(cfg: &WafCfg, src: &WafSource, now: Micros) -> (Vec<Decision>, bool, SourceStatus) {
    let mut st = SourceStatus { name: src.name.clone(), action: src.action, ..Default::default() };
    let parsed = read_source(cfg, src).and_then(|text| parse(src, &text, now));
    let (decisions, fresh) = match parsed {
        Ok(mut p) => {
            filter(src, &mut p);
            (st.bad, st.ignored) = (p.bad, p.ignored);
            write_cache(&cfg.cache_dir, &src.name, &Cached { fetched: now, decisions: p.decisions.clone() });
            (p.decisions, true)
        }
        Err(e) => {
            st.error = Some(format!("{e:#}"));
            st.from_cache = true;
            let cached: Option<Cached> =
                std::fs::read_to_string(cache_path(&cfg.cache_dir, &src.name)).ok().and_then(|t| serde_json::from_str(&t).ok());
            let mut d = cached.map(|c| c.decisions).unwrap_or_default();
            d.retain(|d| d.until.is_none_or(|u| u > now));
            (d, false)
        }
    };
    st.decisions = decisions.len();
    (decisions, fresh, st)
}

/// Reads every source. `protected` (allowlists, peers, this host) never goes into the list.
pub fn refresh(cfg: &WafCfg, protected: &[Net], now: Micros) -> WafUpdate {
    let _ = std::fs::create_dir_all(&cfg.cache_dir);
    let mut u = WafUpdate { status: WafStatus { refreshed: now, ..Default::default() }, ..Default::default() };
    let mut list = Vec::new();
    for src in &cfg.sources {
        let (decisions, fresh, mut st) = load_source(cfg, src, now);
        match src.action {
            WafAction::List => list.extend(decisions.iter().map(|d| d.net)),
            WafAction::Ban => {
                let too_many = decisions.len() > src.max_bans;
                if too_many {
                    st.error = Some(format!(
                        "{} decisions exceed max_bans {}: its bans are left as they are (action = \"list\" is for blocklists)",
                        decisions.len(),
                        src.max_bans
                    ));
                }
                u.bans.push((src.name.clone(), (fresh && !too_many).then_some(decisions)));
            }
        }
        u.status.sources.push(st);
    }
    let (kept, skipped) = crate::feeds::sanitize(list, protected, cfg.min_prefix_v4, cfg.min_prefix_v6);
    let nets = crate::feeds::aggregate(kept);
    u.status.list_skipped = skipped;
    if nets.len() > cfg.max_entries {
        u.status.error = Some(format!("{} networks exceed [waf] max_entries {}: the list loaded last stays", nets.len(), cfg.max_entries));
    } else {
        u.status.list_v4 = nets.iter().filter(|n| n.is_v4()).count();
        u.status.list_v6 = nets.len() - u.status.list_v4;
        u.list = Some(nets);
    }
    u
}

/// The decisions of one source by network, the longest-lasting one of each.
pub fn by_net(decisions: &[Decision]) -> BTreeMap<Net, &Decision> {
    let mut m: BTreeMap<Net, &Decision> = BTreeMap::new();
    for d in decisions {
        let longer = |old: &Decision| match (old.until, d.until) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(a), Some(b)) => b > a,
        };
        if m.get(&d.net).is_none_or(|old| longer(old)) {
            m.insert(d.net, d);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Micros = 1_790_000_000 * SEC;

    fn src(format: Format) -> WafSource {
        WafSource { name: "t".into(), format, file: Some("/dev/null".into()), ..Default::default() }
    }

    fn nets(p: &Parsed) -> Vec<String> {
        p.decisions.iter().map(|d| d.net.to_string()).collect()
    }

    #[test]
    fn go_durations_and_dates() {
        assert_eq!(parse_duration("3h59m56.5s"), Some((3 * 3600 + 59 * 60) * SEC + 56_500_000));
        assert_eq!(parse_duration("-1m30s"), Some(-90 * SEC));
        assert_eq!(parse_duration("300ms"), Some(300_000));
        assert_eq!(parse_duration("1.5h"), Some(5400 * SEC));
        assert_eq!(parse_duration("7d"), Some(7 * 86_400 * SEC));
        assert_eq!(parse_duration("3600"), Some(3600 * SEC));
        assert_eq!(parse_duration("2µs"), Some(2));
        for bad in ["", "h", "4x", "1h-2m", "-"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        assert!(parse_duration("99999999h").unwrap() <= 100 * 365 * 86_400 * SEC);
        assert_eq!(parse_until("1790000000"), Some(NOW));
        assert_eq!(parse_until("1790000000000"), Some(NOW), "milliseconds");
        assert_eq!(parse_until("2026-10-27T10:00:00Z"), time::parse_iso_offset("2026-10-27 10:00:00"));
        assert_eq!(parse_until("soon"), None);
    }

    #[test]
    fn crowdsec_local_api() {
        // GET /v1/decisions (a bouncer's view)
        let lapi = r#"[
          {"duration":"3h59m56.919518355s","id":1,"origin":"crowdsec","scenario":"crowdsecurity/http-probing","scope":"Ip","type":"ban","value":"192.0.2.10","uuid":"a"},
          {"duration":"23h50m","id":2,"origin":"cscli","scenario":"manual 'ban' from 'x'","scope":"Range","type":"ban","value":"198.51.100.0/24"},
          {"duration":"1h","id":3,"origin":"crowdsec","scenario":"crowdsecurity/http-crawl","scope":"Ip","type":"captcha","value":"192.0.2.11"},
          {"duration":"1h","id":4,"origin":"cscli","scenario":"geo","scope":"Country","type":"ban","value":"XX"},
          {"duration":"-2s","id":5,"origin":"crowdsec","scenario":"old","scope":"Ip","type":"ban","value":"192.0.2.12"},
          {"duration":"4h","id":6,"origin":"crowdsec","scenario":"s","scope":"Ip","type":"ban","value":"not-an-ip"},
          {"duration":"4h","id":7,"origin":"CAPI","scenario":"crowdsecurity/ssh-bf","scope":"ip","type":"ban","value":"2001:db8::7","simulated":true}
        ]"#;
        let s = src(Format::Crowdsec);
        let mut p = parse(&s, lapi, NOW).unwrap();
        assert_eq!(nets(&p), ["192.0.2.10", "198.51.100.0/24", "192.0.2.11"]);
        assert_eq!((p.bad, p.ignored), (1, 3), "the country, the ended and the simulated one are left out");
        let d = &p.decisions[0];
        assert_eq!((d.kind.as_str(), d.origin.as_str(), d.reason.as_str()), ("ban", "crowdsec", "crowdsecurity/http-probing"));
        assert_eq!(d.until, Some(NOW + (3 * 3600 + 59 * 60 + 56) * SEC + 919_518));
        filter(&s, &mut p);
        assert_eq!(nets(&p), ["192.0.2.10", "198.51.100.0/24"], "captcha is for the HTTP layer");
        let s = WafSource { origins: vec!["CrowdSec".into()], ..s };
        filter(&s, &mut p);
        assert_eq!(nets(&p), ["192.0.2.10"]);

        // none: `null`, and the stream with startup=true
        assert!(parse(&src(Format::Crowdsec), "null", NOW).unwrap().decisions.is_empty());
        let stream =
            r#"{"deleted":null,"new":[{"duration":"4h","origin":"CAPI","scenario":"x","scope":"Ip","type":"ban","value":"203.0.113.9"}]}"#;
        assert_eq!(nets(&parse(&src(Format::Crowdsec), stream, NOW).unwrap()), ["203.0.113.9"]);
        assert!(parse(&src(Format::Crowdsec), r#"{"deleted":[],"new":null}"#, NOW).unwrap().decisions.is_empty());
        assert!(parse(&src(Format::Crowdsec), r#"{"message":"access forbidden"}"#, NOW).is_err());
        assert!(parse(&src(Format::Crowdsec), "[{\"value\":", NOW).is_err(), "cut short");
    }

    #[test]
    fn crowdsec_cscli_outputs() {
        // `cscli decisions list -o json`: alerts, each with its decisions
        let alerts = r#"[{"id":12,"scenario":"crowdsecurity/appsec-vpatch","source":{"ip":"192.0.2.20","scope":"Ip","value":"192.0.2.20"},
            "decisions":[{"duration":"3h58m","origin":"crowdsec","scenario":"crowdsecurity/appsec-vpatch","scope":"Ip","type":"ban","value":"192.0.2.20","simulated":false}]},
            {"id":13,"decisions":[{"duration":"1h","origin":"cscli","scenario":"manual","scope":"Ip","type":"ban","value":"192.0.2.21"},
                                  {"duration":"1h","origin":"cscli","scenario":"manual","scope":"Ip","type":"ban","value":"192.0.2.22"}]}]"#;
        let p = parse(&src(Format::Crowdsec), alerts, NOW).unwrap();
        assert_eq!(nets(&p), ["192.0.2.20", "192.0.2.21", "192.0.2.22"]);
        assert_eq!(p.decisions[0].reason, "crowdsecurity/appsec-vpatch");

        // `-o raw`
        let raw = "id,source,ip,reason,action,country,as,events_count,expiration,simulated,alert_id\n\
                   1,crowdsec,Ip:192.0.2.30,crowdsecurity/http-bad-user-agent,ban,XX,64500 Example,2,3h59m1s,false,5\n\
                   2,cscli,Ip:2001:db8::30,\"manual, with a comma\",ban,,,1,23h0m0s,false,6\n\
                   3,cscli,Range:198.51.100.0/24,manual,ban,,,1,1h0m0s,true,7\n\
                   4,cscli,Country:XX,manual,ban,,,1,1h0m0s,false,8\n";
        let p = parse(&src(Format::Crowdsec), raw, NOW).unwrap();
        assert_eq!(nets(&p), ["192.0.2.30", "2001:db8::30"]);
        assert_eq!(p.decisions[1].reason, "manual, with a comma");
        assert_eq!((p.decisions[1].origin.as_str(), p.ignored), ("cscli", 2));

        // the blocklist mirror's plain text
        let p = parse(&src(Format::Crowdsec), "192.0.2.40\n198.51.100.0/24\n", NOW).unwrap();
        assert_eq!((nets(&p), p.decisions[0].until), (vec!["192.0.2.40".to_string(), "198.51.100.0/24".into()], None));
    }

    #[test]
    fn plain_lists_and_error_pages() {
        let p = parse(&src(Format::Plain), "# fail2ban\n192.0.2.1\n198.51.100.0/24 ; note\n\n2001:db8::1 # x\nbogus\n", NOW).unwrap();
        assert_eq!((nets(&p).len(), p.bad), (3, 1));
        assert!(parse(&src(Format::Plain), "# empty list\n", NOW).unwrap().decisions.is_empty(), "an empty list is one");
        let err = parse(&src(Format::Plain), "<html>\n<body>Sign in</body>\n</html>\n", NOW).unwrap_err().to_string();
        assert!(err.contains("not a list"), "{err}");
    }

    #[test]
    fn generic_json() {
        // e.g. an IP list API: {"result":[{"ip":...,"comment":...}]}
        let doc = r#"{"success":true,"result":[{"ip":"192.0.2.50","comment":"waf rule 942100","expires_on":"2026-10-27T12:00:00Z"},
                      {"ip":"198.51.100.0/24","comment":"bot fight","meta":{"kind":"block"}}]}"#;
        let s = WafSource {
            items: "result".into(),
            reason_field: "comment".into(),
            until_field: "expires_on".into(),
            type_field: "meta.kind".into(),
            types: vec!["block".into()],
            ..src(Format::Json)
        };
        let mut p = parse(&s, doc, time::parse_iso_offset("2026-10-27T10:00:00Z").unwrap()).unwrap();
        filter(&s, &mut p);
        assert_eq!(nets(&p), ["192.0.2.50", "198.51.100.0/24"], "no type: kept");
        assert_eq!(p.decisions[0].until, time::parse_iso_offset("2026-10-27T12:00:00Z"));
        assert_eq!(p.decisions[1].reason, "bot fight");
        // an array of strings, JSON lines, numbers as durations
        assert_eq!(nets(&parse(&src(Format::Json), r#"["192.0.2.60","2001:db8::/48"]"#, NOW).unwrap()).len(), 2);
        let s = WafSource { duration_field: "ttl".into(), ip_field: "addr".into(), ..src(Format::Json) };
        let p = parse(&s, "{\"addr\":\"192.0.2.61\",\"ttl\":600}\n{\"addr\":\"192.0.2.62\",\"ttl\":\"10m\"}\n", NOW).unwrap();
        assert_eq!(p.decisions.iter().map(|d| d.until).collect::<Vec<_>>(), [Some(NOW + 600 * SEC); 2]);
        assert!(parse(&src(Format::Json), "<html>", NOW).is_err());
    }

    #[test]
    fn generic_csv_and_regex() {
        let s = WafSource { ip_field: "client".into(), reason_field: "4".into(), duration_field: "TTL".into(), ..src(Format::Csv) };
        let text = "time,client,ttl,rule\n1,192.0.2.70,3600,sqli\n2,\"198.51.100.0/24\",60,\"xss, reflected\"\n";
        let p = parse(&s, text, NOW).unwrap();
        assert_eq!(nets(&p), ["192.0.2.70", "198.51.100.0/24"]);
        assert_eq!((p.decisions[1].reason.as_str(), p.decisions[1].until), ("xss, reflected", Some(NOW + 60 * SEC)));
        let s = WafSource { header: false, delimiter: ";".into(), ip_field: "2".into(), ..src(Format::Csv) };
        assert_eq!(nets(&parse(&s, "x;192.0.2.71\n", NOW).unwrap()), ["192.0.2.71"]);
        let s = WafSource { ip_field: "nope".into(), ..src(Format::Csv) };
        assert!(parse(&s, "a,b\n1,2\n", NOW).is_err());

        // e.g. a WAF's own log of what it banned
        let s = WafSource { pattern: r"ban ip=(?P<ip>\S+) for=(?P<duration>\S+) rule=(?P<reason>\S+)".into(), ..src(Format::Regex) };
        s.validate(&WafCfg::default().fetch).unwrap();
        let p = parse(&s, "10:00 ban ip=192.0.2.80 for=1h rule=920350\n10:01 unrelated\n10:02 ban ip=x for=1h rule=1\n", NOW).unwrap();
        assert_eq!((nets(&p), p.bad), (vec!["192.0.2.80".to_string()], 1));
        assert_eq!(p.decisions[0].reason, "920350");
        // `fail2ban-client banned`: every jail's addresses on one line
        let s = WafSource { pattern: "'(?P<ip>[0-9a-fA-F.:]+)'".into(), ..src(Format::Regex) };
        let p = parse(&s, "[{'sshd': ['192.0.2.1', '2001:db8::2']}, {'dead': []}]\n", NOW).unwrap();
        assert_eq!((nets(&p), p.bad), (vec!["192.0.2.1".to_string(), "2001:db8::2".into()], 1));
    }

    #[test]
    fn reasons_are_cleaned() {
        let text = r#"[{"duration":"1h","scope":"Ip","type":"ban","value":"192.0.2.90","scenario":"a\u001b[31m\nb"}]"#;
        let p = parse(&src(Format::Crowdsec), text, NOW).unwrap();
        assert_eq!(p.decisions[0].reason, "a[31mb");
    }

    #[test]
    fn validation() {
        let fetch = WafCfg::default().fetch;
        let ok = |s: WafSource| s.validate(&fetch);
        let base = WafSource {
            name: "crowdsec".into(),
            format: Format::Crowdsec,
            url: "http://127.0.0.1:8080/v1/decisions".into(),
            ..Default::default()
        };
        ok(base.clone()).unwrap();
        ok(WafSource { api_key_file: Some("/etc/logguard/crowdsec.key".into()), ..base.clone() }).unwrap();
        let err = |s: WafSource| ok(s).unwrap_err().to_string();
        assert!(err(WafSource { name: "a b".into(), ..base.clone() }).contains("name"));
        assert!(err(WafSource { file: Some("/x".into()), ..base.clone() }).contains("exactly one"));
        assert!(err(WafSource { url: String::new(), ..base.clone() }).contains("exactly one"));
        assert!(err(WafSource { url: "ftp://x/".into(), ..base.clone() }).contains("http"));
        assert!(err(WafSource { url: "http://127.0.0.1:8080/v1/decisions/stream".into(), ..base.clone() }).contains("startup=true"));
        ok(WafSource { url: "http://127.0.0.1:8080/v1/decisions/stream?startup=true".into(), ..base.clone() }).unwrap();
        let remote = WafSource { url: "http://waf.example:8080/v1/decisions".into(), api_key_file: Some("/k".into()), ..base.clone() };
        assert!(err(remote.clone()).contains("clear text"));
        ok(WafSource { url: "https://waf.example:8080/v1/decisions".into(), ..remote.clone() }).unwrap();
        ok(WafSource { url: "http://[::1]:8080/v1/decisions".into(), ..remote.clone() }).unwrap();
        assert!(err(WafSource { url: "http://localhost.evil.example/".into(), ..remote }).contains("clear text"));
        assert!(
            err(WafSource { api_key_header: "X-Api-Key: x".into(), api_key_file: Some("/k".into()), ..base.clone() }).contains("header")
        );
        let wget = vec!["wget".to_string()];
        assert!(WafSource { api_key_file: Some("/k".into()), ..base.clone() }.validate(&wget).unwrap_err().to_string().contains("curl"));
        let plain = WafSource { format: Format::Plain, origins: vec!["crowdsec".into()], ..base.clone() };
        assert!(err(plain).contains("origin"));
        assert!(err(WafSource { format: Format::Regex, pattern: "(?P<addr>.*)".into(), ..base.clone() }).contains("group named ip"));
        assert!(err(WafSource { format: Format::Csv, delimiter: "::".into(), ..base.clone() }).contains("delimiter"));
        assert!(err(WafSource { file: Some("relative".into()), url: String::new(), ..base.clone() }).contains("absolute"));

        let cfg = |sources| WafCfg { enabled: true, sources, ..Default::default() };
        assert!(cfg(vec![]).validate().is_err());
        assert!(cfg(vec![base.clone(), base.clone()]).validate().unwrap_err().to_string().contains("two sources"));
        cfg(vec![base]).validate().unwrap();
    }

    #[test]
    fn hosts_of_urls() {
        assert_eq!(url_host("http://127.0.0.1:8080/v1"), "127.0.0.1");
        assert_eq!(url_host("https://user:pw@waf.example/x"), "waf.example");
        assert_eq!(url_host("http://[::1]:8080/"), "::1");
        assert_eq!(url_host("http://localhost?x=1"), "localhost");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("logguard-waf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn refresh_lists_bans_and_the_cache() {
        let dir = temp_dir("refresh");
        let decisions = dir.join("decisions.json");
        let blocklist = dir.join("blocklist.txt");
        std::fs::write(
            &decisions,
            r#"[{"duration":"1h","origin":"crowdsec","scenario":"crowdsecurity/http-probing","scope":"Ip","type":"ban","value":"192.0.2.10"},
                {"duration":"10m","origin":"crowdsec","scenario":"s","scope":"Ip","type":"ban","value":"192.0.2.11"}]"#,
        )
        .unwrap();
        std::fs::write(&blocklist, "6.6.6.0/24\n6.6.6.7\n10.0.0.0/8\n11.3.10.7\n2.0.0.0/8\n").unwrap();
        let cfg = WafCfg {
            enabled: true,
            cache_dir: dir.join("cache"),
            sources: vec![
                WafSource { name: "crowdsec".into(), format: Format::Crowdsec, file: Some(decisions.clone()), ..Default::default() },
                WafSource { name: "capi".into(), file: Some(blocklist.clone()), action: WafAction::List, ..Default::default() },
            ],
            ..Default::default()
        };
        cfg.validate().unwrap();
        let protected: Vec<Net> = vec!["11.3.10.7".parse().unwrap()];
        let u = refresh(&cfg, &protected, NOW);
        let list: Vec<String> = u.list.as_ref().unwrap().iter().map(|n| n.to_string()).collect();
        assert_eq!(list, ["6.6.6.0/24"], "nested, bogon, protected and too wide left out");
        assert_eq!((u.status.list_v4, u.status.list_skipped), (1, 3));
        assert_eq!(u.bans.len(), 1);
        assert_eq!(u.bans[0].1.as_ref().unwrap().len(), 2);
        assert!(u.status.problems().is_empty(), "{:?}", u.status);

        // the WAF can't be read: its bans are left alone, the list keeps what hasn't ended
        std::fs::remove_file(&decisions).unwrap();
        std::fs::write(&blocklist, "<html>").unwrap();
        let u = refresh(&cfg, &protected, NOW + 30 * time::MIN);
        assert!(u.bans[0].1.is_none());
        assert_eq!(u.list.as_ref().unwrap().len(), 1, "from the cache");
        let st = &u.status.sources;
        assert!(st.iter().all(|s| s.from_cache && s.error.is_some()), "{st:?}");
        assert_eq!(st[0].decisions, 1, "the 10-minute decision is over");
        assert_eq!(u.status.problems().len(), 2);

        // more than max_bans: left as they are
        std::fs::write(&decisions, r#"[{"duration":"1h","scope":"Ip","type":"ban","value":"192.0.2.10"},{"duration":"1h","scope":"Ip","type":"ban","value":"192.0.2.12"}]"#).unwrap();
        let mut small = cfg.clone();
        small.sources[0].max_bans = 1;
        assert!(refresh(&small, &protected, NOW).bans[0].1.is_none());
        let mut tiny = cfg.clone();
        tiny.max_entries = 0;
        std::fs::write(&blocklist, "6.6.6.0/24\n").unwrap();
        let u = refresh(&tiny, &protected, NOW);
        assert!(u.list.is_none() && u.status.error.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn commands_and_api_keys() {
        let dir = temp_dir("cmd");
        let cfg = WafCfg { cache_dir: dir.clone(), ..Default::default() };
        let s = WafSource { name: "c".into(), command: vec!["sh".into(), "-c".into(), "echo 192.0.2.1".into()], ..Default::default() };
        assert_eq!(read_source(&cfg, &s).unwrap(), "192.0.2.1\n");
        let s = WafSource { command: vec!["sh".into(), "-c".into(), "echo no >&2; exit 3".into()], ..s };
        assert!(read_source(&cfg, &s).unwrap_err().to_string().contains("no"));

        // the key reaches curl's stdin, not its command line
        use std::os::unix::fs::PermissionsExt;
        let key = dir.join("key");
        std::fs::write(&key, "s3cret\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let fake_curl = vec!["sh".to_string(), "-c".into(), r#"echo "args: $*"; cat"#.into(), "curl".into()];
        let cfg = WafCfg { fetch: fake_curl, ..cfg };
        let s = WafSource {
            name: "k".into(),
            url: "http://127.0.0.1:8080/v1/decisions".into(),
            api_key_file: Some(key.clone()),
            ..Default::default()
        };
        assert!(read_source(&cfg, &s).unwrap_err().to_string().contains("chmod 600"));
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out = read_source(&cfg, &s).unwrap();
        assert_eq!(out, "args: -H @- http://127.0.0.1:8080/v1/decisions\nX-Api-Key: s3cret\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn longest_decision_per_network() {
        let d = |net: &str, until: Option<Micros>| Decision {
            net: net.parse().unwrap(),
            until,
            kind: String::new(),
            origin: String::new(),
            reason: String::new(),
        };
        let all =
            [d("192.0.2.1", Some(10)), d("192.0.2.1", Some(30)), d("192.0.2.1", Some(20)), d("192.0.2.2", Some(5)), d("192.0.2.2", None)];
        let m = by_net(&all);
        assert_eq!(m.values().map(|d| d.until).collect::<Vec<_>>(), [Some(30), None]);
    }
}
