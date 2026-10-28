//! `/metrics`: what the console shows, for Prometheus (and Grafana, or alerting rules of your
//! own), in Prometheus' text format, `text/plain; version=0.0.4`
//! (<https://prometheus.io/docs/instrumenting/exposition_formats/>). Prometheus 3 also knows a
//! version 1.0.0, whose only addition is quoted UTF-8 metric and label names; these names are
//! all of the classic characters, so 0.0.4 suits every version of Prometheus and the tools that
//! read its format. Every series of a node carries its `node` label; the console's own
//! (`logguard_web_…`) carry none.
//!
//! No series names an attacker's address or an account: those are personal data, and one
//! series each would grow without bound. Countries, networks (ASNs), ports, peers, certificates
//! and mounts are bounded by logguard's own caps.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde_json::Value;

use crate::fleet::Node;
use crate::snapshot::Snapshot;
use crate::time::{Micros, SEC};

/// The console's own figures.
#[derive(Clone, Copy, Debug, Default)]
pub struct Console {
    /// Logins since start: succeeded, failed, refused while locked out.
    pub logins: [u64; 3],
    pub sessions: usize,
}

/// A label value in quotes, escaped as the format wants.
fn label(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Family {
    kind: &'static str,
    help: &'static str,
    samples: Vec<String>,
    /// The label sets written: the format wants each once (a service on both 0.0.0.0:22
    /// and [::]:22 is one public listener).
    seen: std::collections::HashSet<String>,
}

/// A value as Go's `ParseFloat` reads it, which the format asks for.
fn fmt_value(v: f64) -> String {
    match v {
        v if v.is_nan() => "NaN".into(),
        v if v == f64::INFINITY => "+Inf".into(),
        v if v == f64::NEG_INFINITY => "-Inf".into(),
        v => format!("{v}"),
    }
}

/// HELP text escaped as the format wants: backslash and line feed.
fn help_text(h: &str) -> String {
    h.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Samples gathered in any order, written grouped by family (the format requires it), in the
/// order the families first came.
#[derive(Default)]
struct Out {
    order: Vec<&'static str>,
    families: HashMap<&'static str, Family>,
}

impl Out {
    fn put(&mut self, name: &'static str, kind: &'static str, help: &'static str, labels: &[(&str, &str)], value: f64) {
        let fam = self.families.entry(name).or_insert_with(|| {
            self.order.push(name);
            Family { kind, help, samples: Vec::new(), seen: Default::default() }
        });
        let labels: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={}", label(v))).collect();
        let labels = labels.join(",");
        if !fam.seen.insert(labels.clone()) {
            return;
        }
        let value = fmt_value(value);
        fam.samples.push(if labels.is_empty() { format!("{name} {value}") } else { format!("{name}{{{labels}}} {value}") });
    }

    fn text(self) -> String {
        let mut out = String::new();
        for name in self.order {
            let f = &self.families[name];
            let _ = writeln!(out, "# HELP {name} {}\n# TYPE {name} {}", help_text(f.help), f.kind);
            for s in &f.samples {
                out.push_str(s);
                out.push('\n');
            }
        }
        out
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64)
}

fn secs(t: f64) -> f64 {
    t / SEC as f64
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn items(v: Option<&Value>) -> impl Iterator<Item = &Value> {
    v.and_then(Value::as_array).into_iter().flatten()
}

fn set(v: Option<&Value>) -> bool {
    v.is_some_and(|x| !x.is_null())
}

/// One node's series, each labelled with the node.
struct NodeOut<'a> {
    out: &'a mut Out,
    node: &'a str,
}

impl NodeOut<'_> {
    fn gauge(&mut self, name: &'static str, help: &'static str, labels: &[(&str, &str)], value: f64) {
        self.put(name, "gauge", help, labels, value);
    }

    fn counter(&mut self, name: &'static str, help: &'static str, labels: &[(&str, &str)], value: Option<f64>) {
        if let Some(v) = value {
            self.put(name, "counter", help, labels, v);
        }
    }

    fn put(&mut self, name: &'static str, kind: &'static str, help: &'static str, labels: &[(&str, &str)], value: f64) {
        let mut all: Vec<(&str, &str)> = vec![("node", self.node)];
        all.extend_from_slice(labels);
        self.out.put(name, kind, help, &all, value);
    }

    /// A gauge from a number in the snapshot, when it is there.
    fn maybe(&mut self, name: &'static str, help: &'static str, labels: &[(&str, &str)], value: Option<f64>) {
        if let Some(v) = value {
            self.gauge(name, help, labels, v);
        }
    }

    /// 1 or 0 from a yes/no in the snapshot, when it is there.
    fn flag(&mut self, name: &'static str, help: &'static str, value: Option<&Value>) {
        if let Some(b) = value.and_then(Value::as_bool) {
            self.gauge(name, help, &[], if b { 1.0 } else { 0.0 });
        }
    }
}

const LEVELS: [&str; 4] = ["critical", "high", "warning", "info"];

/// Prometheus' text for `nodes`, and the console's own figures.
pub fn render(nodes: &[Node], now: Micros, console: Option<Console>) -> String {
    let mut out = Out::default();
    for n in nodes {
        let mut o = NodeOut { out: &mut out, node: &n.name };
        let up = if crate::aggregate::state(n) == "ok" { 1.0 } else { 0.0 };
        o.gauge("logguard_up", "1 when the console read the node's data in its latest attempt.", &[], up);
        if let Some(t) = n.fetched {
            o.gauge("logguard_data_age_seconds", "Age of the node's latest data.", &[], secs((now - t) as f64));
        }
        if let Some(ms) = n.latency_ms {
            o.gauge("logguard_fetch_duration_seconds", "How long the node took to answer the console.", &[], ms as f64 / 1000.0);
        }
        if let Some(v) = &n.version {
            o.gauge("logguard_web_agent_info", "The node's logguard-web version (agents only).", &[("version", v)], 1.0);
        }
        let problems = crate::aggregate::problems(n, now);
        for level in LEVELS {
            let count = problems.iter().filter(|(l, _)| *l == level).count();
            let help = "Things that need the admin's attention, as the console's overview lists them.";
            o.gauge("logguard_attention", help, &[("level", level)], count as f64);
        }
        if let Some(s) = &n.snapshot {
            snapshot(&mut o, s, now);
        }
    }
    if let Some(c) = console {
        let help = "Console logins since it started: succeeded, failed, refused while the address was locked out.";
        for (i, result) in ["ok", "failed", "locked_out"].into_iter().enumerate() {
            out.put("logguard_web_logins_total", "counter", help, &[("result", result)], c.logins[i] as f64);
        }
        out.put("logguard_web_sessions", "gauge", "Console sessions open.", &[], c.sessions as f64);
        out.put("logguard_web_nodes", "gauge", "Nodes the console shows.", &[], nodes.len() as f64);
    }
    out.text()
}

fn snapshot(o: &mut NodeOut, s: &Snapshot, now: Micros) {
    let get = |k: &str| s.value.get(k).filter(|x| !x.is_null());
    engine(o, s, now);
    if let Some(w) = get("world") {
        places(o, w);
    }
    blocking(o, get("geoblock"), get("feeds"));
    if let Some(w) = get("waf") {
        waf(o, w);
    }
    if let Some(c) = get("cluster") {
        cluster(o, c);
    }
    host(o, get("certs"), get("resources"), get("patches"));
    integrity(o, get("av").and_then(|a| a.get("last")).filter(|l| !l.is_null()), get("verify"), get("cron"), get("procwatch"));
    if let Some(x) = get("exposure") {
        exposure(o, x);
    }
    patterns(o, get("patterns"));
}

/// logguard itself: mode, scores, bans, alerts, events, accounts.
fn engine(o: &mut NodeOut, s: &Snapshot, now: Micros) {
    let get = |k: &str| s.value.get(k).filter(|x| !x.is_null());
    let mode = get("mode").and_then(Value::as_str).unwrap_or("");
    let backend = get("backend").and_then(Value::as_str).unwrap_or("");
    o.gauge("logguard_info", "logguard's mode and firewall backend.", &[("mode", mode), ("backend", backend)], 1.0);
    o.gauge("logguard_enforcing", "1 in enforce mode, 0 in shadow mode.", &[], if mode == "enforce" { 1.0 } else { 0.0 });
    o.maybe("logguard_started_timestamp_seconds", "When logguard started.", &[], num(get("started")).map(secs));
    o.maybe("logguard_snapshot_timestamp_seconds", "When logguard made the data the console has.", &[], num(get("generated")).map(secs));
    o.maybe("logguard_tracked_addresses", "Addresses with a score.", &[], num(get("tracked_ips")));
    o.maybe("logguard_tracked_connections", "Client connections still in their grace time.", &[], num(get("tracked_connections")));
    for (window, key) in [("fast", "fast_threshold"), ("slow", "slow_threshold")] {
        o.maybe("logguard_ban_threshold", "Points that make a ban.", &[("window", window)], num(get(key)).filter(|t| *t > 0.0));
    }
    o.gauge(
        "logguard_offenders",
        "Addresses listed as offenders (logguard lists the worst few hundred).",
        &[],
        s.len_of("offenders") as f64,
    );

    let help = "Bans in force, by where they were decided (local, or the peer) and what they cover.";
    for ((origin, kind), count) in &s.bans {
        o.gauge("logguard_active_bans", help, &[("origin", origin), ("kind", kind)], *count as f64);
    }
    let stats = get("stats");
    let stat = |k: &str| num(stats.and_then(|st| st.get(k)));
    o.counter("logguard_bans_total", "Bans decided since logguard started.", &[], stat("bans"));
    o.counter("logguard_alerts_total", "Alerts since logguard started.", &[], stat("alerts"));
    o.counter("logguard_unattributed_lines_total", "Lines of interest no address could be found for.", &[], stat("unattributed"));
    o.counter("logguard_hidden_addresses_total", "Lines where a service hid the client's address.", &[], stat("hidden_ips"));
    for (source, n) in stats.and_then(|st| st.get("records")).and_then(Value::as_object).into_iter().flatten() {
        o.counter("logguard_records_total", "Log lines read since logguard started, per source.", &[("source", source)], n.as_f64());
    }
    for (signal, n) in stats.and_then(|st| st.get("events")).and_then(Value::as_object).into_iter().flatten() {
        o.counter("logguard_events_total", "Events since logguard started, per signal.", &[("signal", signal)], n.as_f64());
    }
    if let Some(history) = stats.and_then(|st| st.get("history")).and_then(Value::as_array) {
        let generated = num(get("generated")).map_or(now, |g| g as Micros);
        let (mut events, mut bans) = (0.0, 0.0);
        for b in
            history.iter().filter(|b| b.get("minute").and_then(Value::as_i64).is_some_and(|m| m >= generated.saturating_sub(3600 * SEC)))
        {
            events += items(b.get("events")).filter_map(Value::as_f64).sum::<f64>();
            bans += num(b.get("bans")).unwrap_or(0.0);
        }
        o.gauge("logguard_events_last_hour", "Events in the last hour.", &[], events);
        o.gauge("logguard_bans_last_hour", "Bans in the last hour.", &[], bans);
    }
    for severity in LEVELS {
        let recent = |a: &&Value| text(a, "severity") == severity && num(a.get("ts")).is_some_and(|t| t as Micros >= now - 86_400 * SEC);
        let n = items(get("alerts")).filter(recent).count();
        let help = "Alerts in the last 24 hours, by severity (of the newest few hundred).";
        o.gauge("logguard_alerts_last_day", help, &[("severity", severity)], n as f64);
    }
    for (source, t) in get("last_lines").and_then(Value::as_object).into_iter().flatten() {
        o.maybe(
            "logguard_last_line_timestamp_seconds",
            "Time of the newest line per log source.",
            &[("source", source)],
            t.as_f64().map(secs),
        );
    }

    let accounts: Vec<&Value> = items(get("accounts")).collect();
    let attacked = accounts.iter().filter(|a| a.get("under_attack").and_then(Value::as_bool) == Some(true)).count();
    o.gauge("logguard_accounts_with_failures", "Accounts with failed logins (the worst hundred).", &[], accounts.len() as f64);
    o.gauge("logguard_accounts_under_attack", "Accounts under a distributed password attack.", &[], attacked as f64);
    o.gauge("logguard_trusted_addresses", "Addresses trusted after a login.", &[], s.len_of("trusted") as f64);
    o.gauge("logguard_operator_allowlist_entries", "Entries of the operator allowlist (logguard allow).", &[], s.len_of("allowed") as f64);
}

/// Countries, networks, ports and logins (`world`).
fn places(o: &mut NodeOut, w: &Value) {
    o.maybe("logguard_offenders_unlocated", "Offenders whose country is unknown.", &[], num(w.get("unlocated")));
    for c in items(w.get("countries")) {
        let cc = [("country", text(c, "key"))];
        o.maybe("logguard_country_active_bans", "Bans in force per country.", &cc, num(c.get("bans")));
        o.maybe("logguard_country_offenders", "Offenders per country.", &cc, num(c.get("offenders")));
        o.maybe("logguard_country_events", "Events per country.", &cc, num(c.get("events")));
    }
    for i in items(w.get("isps")) {
        let labels = [("asn", text(i, "key")), ("name", text(i, "name")), ("country", text(i, "country"))];
        o.maybe("logguard_network_active_bans", "Bans in force per network (ASN), the worst ones.", &labels, num(i.get("bans")));
        o.maybe("logguard_network_offenders", "Offenders per network (ASN), the worst ones.", &labels, num(i.get("offenders")));
        o.maybe("logguard_network_events", "Events per network (ASN), the worst ones.", &labels, num(i.get("events")));
    }
    for p in items(w.get("ports")) {
        if let (Some(port), Some(n)) = (num(p.get(0)), num(p.get(1))) {
            o.gauge("logguard_port_events", "Events per local port, halved every day.", &[("port", &port.to_string())], n);
        }
    }
    for (cc, n) in w.get("logged_in").and_then(Value::as_object).into_iter().flatten() {
        let help = "Addresses that logged in during the last hour, per country.";
        o.gauge("logguard_logged_in_addresses", help, &[("country", cc)], n.as_f64().unwrap_or(0.0));
    }
}

/// `[geoblock]` and the blocklist feeds.
fn blocking(o: &mut NodeOut, geoblock: Option<&Value>, feeds: Option<&Value>) {
    if let Some(g) = geoblock {
        for fam in ["v4", "v6"] {
            o.maybe("logguard_geoblock_networks", "Networks [geoblock] blocks.", &[("family", fam)], num(g.get(fam)));
        }
        o.flag("logguard_geoblock_applied", "1 when [geoblock]'s networks are in the firewall.", g.get("applied"));
        o.gauge("logguard_geoblock_error", "1 when [geoblock] couldn't be loaded.", &[], if set(g.get("error")) { 1.0 } else { 0.0 });
        o.gauge("logguard_geoblock_asns", "Networks (AS numbers) [geoblock] blocks.", &[], items(g.get("asns")).count() as f64);
        for (list, key) in [("blocked", "countries"), ("only", "only_countries")] {
            for cc in items(g.get(key)).filter_map(Value::as_str) {
                let help = "Countries [geoblock] names: blocked, or the only ones let in.";
                o.gauge("logguard_geoblock_country", help, &[("country", cc), ("list", list)], 1.0);
            }
        }
    }
    if let Some(f) = feeds {
        for fam in ["v4", "v6"] {
            o.maybe("logguard_feed_networks", "Networks loaded from the blocklist feeds.", &[("family", fam)], num(f.get(fam)));
        }
        o.flag("logguard_feed_applied", "1 when the feeds' networks are in the firewall.", f.get("applied"));
        o.gauge("logguard_feed_error", "1 when the latest feed refresh failed.", &[], if set(f.get("error")) { 1.0 } else { 0.0 });
        o.maybe("logguard_feed_refreshed_timestamp_seconds", "When the feeds were refreshed.", &[], num(f.get("refreshed")).map(secs));
        o.maybe("logguard_feed_skipped_entries", "Feed entries left out (private, too wide, protected).", &[], num(f.get("skipped")));
        o.maybe("logguard_feed_asns", "Networks (ASNs) the feeds list.", &[], num(f.get("asns")));
        for src in items(f.get("sources")) {
            let url = [("url", text(src, "url"))];
            o.maybe("logguard_feed_source_entries", "Entries per feed.", &url, num(src.get("entries")));
            let help = "1 when a feed couldn't be fetched (its cached copy is used).";
            o.gauge("logguard_feed_source_error", help, &url, if set(src.get("error")) { 1.0 } else { 0.0 });
        }
    }
}

/// `[waf]`: what WAFs (CrowdSec, ...) gave out, and what it became.
fn waf(o: &mut NodeOut, w: &Value) {
    let lists = items(w.get("sources")).any(|s| text(s, "action") == "list");
    if lists {
        for (fam, key) in [("v4", "list_v4"), ("v6", "list_v6")] {
            o.maybe("logguard_waf_list_networks", "Networks in the [waf] list sets.", &[("family", fam)], num(w.get(key)));
        }
        o.flag("logguard_waf_list_applied", "1 when the [waf] list is in the firewall.", w.get("applied"));
    }
    o.maybe("logguard_waf_refreshed_timestamp_seconds", "When the [waf] sources were read.", &[], num(w.get("refreshed")).map(secs));
    for src in items(w.get("sources")) {
        let name = [("source", text(src, "name"))];
        o.maybe("logguard_waf_source_decisions", "Decisions a [waf] source holds.", &name, num(src.get("decisions")));
        if text(src, "action") == "ban" {
            o.maybe("logguard_waf_source_bans", "Bans a [waf] source holds.", &name, num(src.get("banned")));
            let help = "Decisions of a [waf] source that made no ban (protected, too wide).";
            o.maybe("logguard_waf_source_skipped", help, &name, num(src.get("skipped")));
        }
        let help = "1 when a [waf] source couldn't be read (its last good decisions apply).";
        o.gauge("logguard_waf_source_error", help, &name, if set(src.get("error")) { 1.0 } else { 0.0 });
    }
}

fn cluster(o: &mut NodeOut, c: &Value) {
    let help = "The node's cluster name and key fingerprint (the same key everywhere).";
    o.gauge("logguard_cluster_info", help, &[("node_id", text(c, "node_id")), ("key_id", text(c, "key_id"))], 1.0);
    let help = "When the cluster key file was installed or rotated.";
    o.maybe("logguard_cluster_key_installed_timestamp_seconds", help, &[], num(c.get("key_since")).map(secs));
    let help = "Extra cluster keys accepted (a rotation in progress).";
    o.gauge("logguard_cluster_rotation_keys", help, &[], items(c.get("extra_key_ids")).count() as f64);
    for p in items(c.get("peers")) {
        let peer = [("peer", text(p, "addr"))];
        let ok = !set(p.get("failing_since")) && set(p.get("last_ok"));
        o.gauge(
            "logguard_cluster_peer_up",
            "1 when the node's latest delivery to a cluster peer worked.",
            &peer,
            if ok { 1.0 } else { 0.0 },
        );
        let help = "The latest delivery to a peer that worked.";
        o.maybe("logguard_cluster_peer_last_ok_timestamp_seconds", help, &peer, num(p.get("last_ok")).map(secs));
        let help = "Since when deliveries to a peer fail.";
        o.maybe("logguard_cluster_peer_failing_since_timestamp_seconds", help, &peer, num(p.get("failing_since")).map(secs));
    }
    for (from, t) in c.get("heard_from").and_then(Value::as_object).into_iter().flatten() {
        let help = "The latest message from another node.";
        o.maybe("logguard_cluster_heard_from_timestamp_seconds", help, &[("from", from)], t.as_f64().map(secs));
    }
    o.maybe("logguard_cluster_facts_known", "Cluster facts the node holds.", &[], num(c.get("facts_known")));
    o.counter("logguard_cluster_facts_received_total", "Cluster facts received.", &[], num(c.get("facts_received")));
    o.counter("logguard_cluster_facts_sent_total", "Cluster facts sent.", &[], num(c.get("facts_sent")));
    o.counter("logguard_cluster_rejected_total", "Cluster messages or facts refused.", &[], num(c.get("rejected")));
    let help = "Facts a limited peer may not hand the node (peer_accept).";
    o.counter("logguard_cluster_refused_by_limit_total", help, &[], num(c.get("refused_by_limit")));
}

/// Certificates, disks and memory, updates.
fn host(o: &mut NodeOut, certs: Option<&Value>, resources: Option<&Value>, patches: Option<&Value>) {
    for c in items(certs) {
        let target = [("target", text(c, "target"))];
        o.maybe(
            "logguard_cert_expiry_timestamp_seconds",
            "When a watched certificate expires.",
            &target,
            num(c.get("not_after")).map(secs),
        );
        o.maybe(
            "logguard_cert_start_timestamp_seconds",
            "When a watched certificate became valid.",
            &target,
            num(c.get("not_before")).map(secs),
        );
        let help = "When a watched certificate was last checked.";
        o.maybe("logguard_cert_checked_timestamp_seconds", help, &target, num(c.get("checked")).map(secs));
        o.gauge(
            "logguard_cert_error",
            "1 when a watched certificate couldn't be read.",
            &target,
            if set(c.get("error")) { 1.0 } else { 0.0 },
        );
        let help = "1 when a live certificate doesn't name its host.";
        o.gauge("logguard_cert_wrong_name", help, &target, if set(c.get("wrong_name")) { 1.0 } else { 0.0 });
    }
    if let Some(r) = resources {
        for d in items(r.get("disks")) {
            let mount = [("mount", text(d, "mount"))];
            let (size, avail) = (num(d.get("size_kb")), num(d.get("avail_kb")));
            o.maybe("logguard_disk_size_bytes", "Size of a watched filesystem.", &mount, size.map(|k| k * 1024.0));
            o.maybe("logguard_disk_available_bytes", "Free space of a watched filesystem.", &mount, avail.map(|k| k * 1024.0));
            let ratio = size.zip(avail).filter(|(s, _)| *s > 0.0).map(|(s, a)| a / s);
            o.maybe("logguard_disk_free_ratio", "Free share of a watched filesystem.", &mount, ratio);
        }
        if let Some(m) = r.get("memory").filter(|m| !m.is_null()) {
            let (total, avail) = (num(m.get("total_kb")), num(m.get("avail_kb")));
            o.maybe("logguard_memory_total_bytes", "Memory.", &[], total.map(|k| k * 1024.0));
            o.maybe("logguard_memory_available_bytes", "Memory available.", &[], avail.map(|k| k * 1024.0));
            let ratio = total.zip(avail).filter(|(t, _)| *t > 0.0).map(|(t, a)| a / t);
            o.maybe("logguard_memory_available_ratio", "Available share of the memory.", &[], ratio);
            o.maybe("logguard_swap_total_bytes", "Swap.", &[], num(m.get("swap_total_kb")).map(|k| k * 1024.0));
            o.maybe("logguard_swap_free_bytes", "Swap free.", &[], num(m.get("swap_free_kb")).map(|k| k * 1024.0));
            for (kind, key) in [("some", "psi_some"), ("full", "psi_full")] {
                let help = "Share of time tasks stalled on memory (/proc/pressure/memory, 5 minutes).";
                o.maybe("logguard_memory_pressure_ratio", help, &[("kind", kind)], num(m.get(key)).map(|p| p / 100.0));
            }
        }
    }
    if let Some(p) = patches {
        o.maybe("logguard_updates_pending", "Pending package updates.", &[], num(p.get("upgradable")));
        o.maybe("logguard_security_updates", "Pending security updates.", &[], num(p.get("security_count")));
        o.flag("logguard_reboot_required", "1 when the system asks for a reboot.", p.get("reboot_required"));
        if let (Some(run), Some(new)) = (p.get("running_kernel").and_then(Value::as_str), p.get("newest_kernel").and_then(Value::as_str)) {
            let help = "1 when a newer kernel is installed than the one running.";
            o.gauge("logguard_kernel_outdated", help, &[], if run != new { 1.0 } else { 0.0 });
        }
        let help = "Programs still running replaced libraries.";
        o.gauge("logguard_processes_using_replaced_files", help, &[], items(p.get("stale")).count() as f64);
        o.maybe("logguard_updates_checked_timestamp_seconds", "When updates were last checked.", &[], num(p.get("read")).map(secs));
    }
}

/// The antivirus' latest scan, the package check, the cron watch, the process watch.
fn integrity(o: &mut NodeOut, av: Option<&Value>, verify: Option<&Value>, cron: Option<&Value>, procwatch: Option<&Value>) {
    if let Some(last) = av {
        o.maybe("logguard_av_infected_files", "Infected files the latest antivirus scan found.", &[], num(last.get("infected_count")));
        o.maybe("logguard_av_scanned_files", "Files the latest antivirus scan read.", &[], num(last.get("scanned_files")));
        o.maybe("logguard_av_errors", "Errors in the latest antivirus scan.", &[], num(last.get("errors")));
        o.flag("logguard_av_signatures_outdated", "1 when the antivirus signatures are outdated.", last.get("db_outdated"));
        o.flag("logguard_av_scan_completed", "1 when the latest antivirus scan ran to the end.", last.get("completed"));
        o.maybe("logguard_av_last_scan_timestamp_seconds", "When the latest antivirus scan ended.", &[], num(last.get("end")).map(secs));
    }
    if let Some(v) = verify {
        o.maybe("logguard_verify_checked_files", "Package files checked against their checksums.", &[], num(v.get("checked")));
        o.maybe("logguard_verify_mismatched_files", "Package files that differ from their checksums.", &[], num(v.get("mismatched")));
        o.maybe("logguard_verify_setuid_programs", "Set-uid programs.", &[], num(v.get("suid")));
        let help = "When package files were last checked.";
        o.maybe("logguard_verify_last_run_timestamp_seconds", help, &[], num(v.get("last_run")).map(secs));
    }
    if let Some(c) = cron {
        o.maybe("logguard_cron_tasks", "Cron jobs and timers watched.", &[], num(c.get("tasks")));
        o.maybe("logguard_cron_scripts", "Scripts they run, watched.", &[], num(c.get("scripts")));
        o.maybe("logguard_cron_files", "Files watched by the cron watch.", &[], num(c.get("files")));
        o.gauge("logguard_cron_errors", "Problems the cron watch reports.", &[], items(c.get("errors")).count() as f64);
        o.maybe("logguard_cron_scanned_timestamp_seconds", "When the cron watch last looked.", &[], num(c.get("scanned")).map(secs));
    }
    if let Some(p) = procwatch {
        o.maybe("logguard_procwatch_pairs", "Program and destination pairs learned.", &[], num(p.get("pairs")));
        o.maybe("logguard_procwatch_outbound", "Outbound connections seen in the latest scan.", &[], num(p.get("outbound")));
    }
}

/// Listening services and the firewall's view of them.
fn exposure(o: &mut NodeOut, x: &Value) {
    let mut by: Vec<(&str, usize)> = Vec::new();
    for l in items(x.get("listeners")) {
        let exposure = text(l, "exposure");
        match by.iter_mut().find(|(e, _)| *e == exposure) {
            Some((_, n)) => *n += 1,
            None => by.push((exposure, 1)),
        }
        // reachable from the internet; a port range's sockets come and go with every call
        if matches!(exposure, "allowed" | "unfiltered" | "docker") && l.get("dynamic").and_then(Value::as_bool) != Some(true) {
            let k = l.get("key");
            let port = k.and_then(|k| num(k.get("port"))).map(|p| p.to_string()).unwrap_or_default();
            let proto = k.map_or("", |k| text(k, "proto"));
            let labels = [("proto", proto), ("port", port.as_str()), ("process", text(l, "process"))];
            o.gauge("logguard_public_listener", "Services reachable from the internet.", &labels, 1.0);
        }
    }
    for (exposure, n) in by {
        o.gauge("logguard_listeners", "Listening sockets, by how reachable they are.", &[("exposure", exposure)], n as f64);
    }
    let help = "Firewall rules opening ports nothing listens on.";
    o.gauge("logguard_firewall_dead_rules", help, &[], items(x.get("dead_rules")).count() as f64);
    o.flag("logguard_ufw_active", "1 when ufw is active.", x.get("ufw_active"));
}

/// `[[patterns]]` and the built-in ones of `[sources] apps`.
fn patterns(o: &mut NodeOut, patterns: Option<&Value>) {
    for p in items(patterns) {
        let Some(st) = p.get("stats") else { continue };
        let name = text(st, "name");
        if name.is_empty() {
            continue;
        }
        let labels = [("pattern", name), ("kind", text(p, "kind"))];
        o.counter("logguard_pattern_lines_total", "Lines a pattern read from its unit or file.", &labels, num(st.get("lines")));
        o.counter("logguard_pattern_matches_total", "Lines a pattern matched with an address.", &labels, num(st.get("matches")));
        let help = "Lines a pattern matched without an address (it needs a fix).";
        o.counter("logguard_pattern_unaddressed_total", help, &labels, num(st.get("no_address")));
        o.maybe("logguard_pattern_addresses", "Addresses a pattern tracks.", &labels, num(p.get("addresses")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::Node;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn values_and_escapes() {
        assert_eq!(
            (fmt_value(f64::INFINITY), fmt_value(f64::NEG_INFINITY), fmt_value(f64::NAN)),
            ("+Inf".into(), "-Inf".into(), "NaN".into())
        );
        assert_eq!((fmt_value(0.5), fmt_value(3.0), fmt_value(1e21)), ("0.5".into(), "3".into(), "1000000000000000000000".into()));
        assert_eq!(help_text("a\\b\nc"), "a\\\\b\\nc");
        assert_eq!(label("C:\\DIR\nx\"y\u{7}"), "\"C:\\\\DIR\\nx\\\"y\"");
    }

    #[test]
    fn text_format() {
        let snap = json!({"mode": "enforce", "backend": "nftables", "bans": [{"net": "192.0.2.1"}, {"net": "198.51.100.0/24", "origin": "vpn"}], "tracked_ips": 7,
                          "stats": {"bans": 3, "records": {"ssh": 10, "ufw": 5}},
                          "alerts": [{"ts": 9 * SEC, "severity": "high"}],
                          "world": {"countries": [{"key": "CN", "bans": 2, "offenders": 3, "events": 4}], "ports": [[23, 7]], "logged_in": {"DE": 1}},
                          "geoblock": {"v4": 10, "v6": 1, "applied": true, "countries": ["RU"]},
                          "cluster": {"node_id": "xmpp", "key_id": "abc", "peers": [{"addr": "vpn\"x:7946", "last_ok": 5}]},
                          "exposure": {"listeners": [{"key": {"proto": "tcp", "addr": "0.0.0.0", "port": 22}, "process": "sshd", "exposure": "allowed"},
                                                     {"key": {"proto": "tcp", "addr": "::", "port": 22}, "process": "sshd", "exposure": "allowed"}], "dead_rules": []},
                          "patterns": [{"kind": "probe", "from": "unit x", "weight": 40, "stats": {"name": "nginx_probe", "lines": 9, "matches": 2, "no_address": 0}, "addresses": 1}]});
        let s = crate::snapshot::trim(&snap.to_string()).unwrap();
        let nodes = [
            Node {
                id: "0".into(),
                name: "xmpp".into(),
                addr: "local".into(),
                snapshot: Some(Arc::new(s)),
                fetched: Some(0),
                ..Default::default()
            },
            Node { id: "1".into(), name: "vpn".into(), addr: "vpn:7949".into(), error: Some("down".into()), ..Default::default() },
        ];
        let text = render(&nodes, 10 * SEC, Some(Console { logins: [2, 5, 1], sessions: 1 }));
        let has = |line: &str| assert!(text.lines().any(|l| l == line), "{line} missing from:\n{text}");
        assert!(text.contains("# TYPE logguard_up gauge\nlogguard_up{node=\"xmpp\"} 1\nlogguard_up{node=\"vpn\"} 0\n"), "{text}");
        has("logguard_active_bans{node=\"xmpp\",origin=\"local\",kind=\"address\"} 1");
        has("logguard_active_bans{node=\"xmpp\",origin=\"vpn\",kind=\"network\"} 1");
        has("logguard_records_total{node=\"xmpp\",source=\"ssh\"} 10");
        has("logguard_cluster_peer_up{node=\"xmpp\",peer=\"vpn\\\"x:7946\"} 1");
        has("logguard_data_age_seconds{node=\"xmpp\"} 10");
        has("logguard_country_active_bans{node=\"xmpp\",country=\"CN\"} 2");
        has("logguard_port_events{node=\"xmpp\",port=\"23\"} 7");
        has("logguard_logged_in_addresses{node=\"xmpp\",country=\"DE\"} 1");
        has("logguard_geoblock_country{node=\"xmpp\",country=\"RU\",list=\"blocked\"} 1");
        has("logguard_alerts_last_day{node=\"xmpp\",severity=\"high\"} 1");
        has("logguard_public_listener{node=\"xmpp\",proto=\"tcp\",port=\"22\",process=\"sshd\"} 1");
        has("logguard_pattern_matches_total{node=\"xmpp\",pattern=\"nginx_probe\",kind=\"probe\"} 2");
        has("logguard_attention{node=\"vpn\",level=\"critical\"} 1");
        has("logguard_web_logins_total{result=\"failed\"} 5");
        has("logguard_web_nodes 2");
        // a service on 0.0.0.0:22 and [::]:22 is one series
        assert_eq!(text.matches("logguard_public_listener{node=\"xmpp\",proto=\"tcp\",port=\"22\"").count(), 1, "{text}");
        // each family declared once, its samples together
        let mut declared = std::collections::HashSet::new();
        assert!(
            text.lines().filter_map(|l| l.strip_prefix("# TYPE ")).all(|l| declared.insert(l.split(' ').next().unwrap())),
            "a family declared twice"
        );
        let mut seen = std::collections::HashSet::new();
        let mut current = "";
        for l in text.lines().filter(|l| !l.starts_with('#')) {
            let name = l.split(['{', ' ']).next().unwrap();
            if name != current {
                assert!(seen.insert(name), "{name}'s samples are not together");
                current = name;
            }
        }
    }
}
