//! Daily digest for admins, and TLS certificate expiry checks.
//!
//! Certificates are checked against the live endpoints with the `openssl` CLI
//! (`s_client`, with `-starttls xmpp` for client ports), so expiry of whatever is
//! actually served is caught - including failed ACME renewals.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::engine::{DigestData, Snapshot};
use crate::time::{self, fmt_duration, fmt_ts, Dur, Micros, SEC};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DigestCfg {
    pub enabled: bool,
    /// Time of day (UTC) to send the digest, `HH:MM`.
    pub at: String,
    /// TLS endpoints to check: `host:port`, or `host:port/xmpp` (STARTTLS) etc.
    pub certs: Vec<String>,
    /// Certificate files on disk (`*` wildcards allowed in the file name), e.g. ejabberd's
    /// `acme/live/*`. If one covering an endpoint's host expires later than the certificate
    /// actually served there, you're told to point the server at it and reload.
    pub cert_files: Vec<String>,
    /// Alert (and highlight in the digest) when a certificate expires within this many days.
    pub cert_warn_days: i64,
    pub check_certs_every: Dur,
    pub openssl: PathBuf,
}

impl Default for DigestCfg {
    fn default() -> Self {
        DigestCfg {
            enabled: false,
            at: "07:00".into(),
            certs: vec![],
            cert_files: vec![],
            cert_warn_days: 21,
            check_certs_every: Dur(6 * 3600),
            openssl: "/usr/bin/openssl".into(),
        }
    }
}

impl DigestCfg {
    /// Minutes after midnight UTC.
    pub fn minute_of_day(&self) -> Option<i64> {
        let (h, m) = self.at.split_once(':')?;
        let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
        ((0..24).contains(&h) && (0..60).contains(&m)).then_some(h * 60 + m)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.enabled && self.minute_of_day().is_none() {
            anyhow::bail!("[digest] at must be HH:MM (UTC), got '{}'", self.at);
        }
        if let Some(bad) = self.certs.iter().find(|c| c.split('/').next().is_none_or(|hp| hp.rsplit_once(':').is_none())) {
            anyhow::bail!("[digest] cert endpoint '{bad}' must be host:port[/starttls-protocol]");
        }
        Ok(())
    }

    /// The most recent scheduled time at or before `now`.
    pub fn last_due(&self, now: Micros) -> Option<Micros> {
        let day = 86_400 * SEC;
        let midnight = now - now.rem_euclid(day);
        let due = midnight + self.minute_of_day()? * 60 * SEC;
        Some(if due <= now { due } else { due - day })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CertStatus {
    pub target: String,
    pub checked: Micros,
    pub not_after: Option<Micros>,
    /// Start of validity: with it, short-lived certificates (Let's Encrypt's 6-day profile,
    /// requested by recent Caddy) aren't mistaken for ones about to lapse.
    #[serde(default)]
    pub not_before: Option<Micros>,
    pub error: Option<String>,
    /// DNS names (subjectAltName) the certificate covers.
    #[serde(default)]
    pub names: Vec<String>,
    /// A file on disk rather than a live endpoint.
    #[serde(default)]
    pub file: bool,
    /// A live endpoint's certificate doesn't name the host it was fetched for (the chain
    /// of trust is not checked).
    #[serde(default)]
    pub wrong_name: Option<String>,
}

impl CertStatus {
    pub fn days_left(&self, now: Micros) -> Option<i64> {
        self.not_after.map(|t| (t - now).div_euclid(86_400 * SEC))
    }

    /// Whether the expiry needs attention: within `warn_days`, but never before a third of
    /// the certificate's lifetime is left (renewals normally happen around half way), and
    /// high within 7 days or a sixth of the lifetime.
    pub fn expiry_concern(&self, now: Micros, warn_days: i64) -> Option<crate::engine::Severity> {
        use crate::engine::Severity;
        let day = 86_400 * SEC;
        let not_after = self.not_after?;
        let left = not_after - now;
        let lifetime = self.not_before.map(|b| not_after - b).filter(|l| *l > 0).unwrap_or(90 * day);
        if left <= (7 * day).min(lifetime / 6) {
            Some(Severity::High)
        } else if left <= (warn_days * day).min(lifetime / 3) {
            Some(Severity::Warning)
        } else {
            None
        }
    }

    /// What is wrong with the certificate, worst first: (severity, text after "certificate at
    /// <target> "). None when nothing needs attention.
    pub fn concern(&self, now: Micros, warn_days: i64) -> Option<(crate::engine::Severity, String)> {
        use crate::engine::Severity;
        if let Some(w) = &self.wrong_name {
            return Some((Severity::High, w.clone()));
        }
        match (self.expiry_concern(now, warn_days), &self.error) {
            (Some(sev), _) => Some((sev, self.expiry_text(now))),
            (None, Some(e)) if self.not_after.is_none() => Some((Severity::Warning, format!("could not be checked: {e}"))),
            _ => None,
        }
    }

    /// "expires in 1d04h00m (2026-10-16 07:04:33)"
    pub fn expiry_text(&self, now: Micros) -> String {
        let t = self.not_after.unwrap_or(0);
        if t <= now {
            format!("expired {} ago ({})", fmt_duration(now - t), fmt_ts(t))
        } else {
            format!("expires in {} ({})", fmt_duration(t - now), fmt_ts(t))
        }
    }
}

/// Parses `DNS:a.example, DNS:b.example` lines from `openssl x509 -ext subjectAltName`.
pub fn parse_san(text: &str) -> Vec<String> {
    text.split([',', '\n']).filter_map(|p| p.trim().strip_prefix("DNS:")).map(|n| n.trim().to_ascii_lowercase()).collect()
}

/// Why a certificate with these subjectAltName `names` is wrong for `host`, if it is (an
/// IP address as host isn't checked).
pub fn name_problem(names: &[String], host: &str) -> Option<String> {
    if host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() || names.iter().any(|n| name_covers(n, host)) {
        return None;
    }
    Some(if names.is_empty() {
        format!("names no host (no subjectAltName), not {host}")
    } else {
        let shown: Vec<&str> = names.iter().take(5).map(String::as_str).collect();
        format!("is for {}, not {host}", shown.join(", "))
    })
}

fn name_covers(pattern: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(base) => host.split_once('.').is_some_and(|(_, rest)| rest == base),
        None => pattern == host,
    }
}

pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((pre, rest)) => {
            name.starts_with(pre)
                && (0..=name.len() - pre.len())
                    .any(|i| name.is_char_boundary(pre.len() + i) && wildcard_match(rest, &name[pre.len() + i..]))
        }
    }
}

/// Expands `*` in the last path component.
pub fn expand_files(pattern: &str) -> Vec<PathBuf> {
    let path = PathBuf::from(pattern);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else { return vec![] };
    if !name.contains('*') {
        return if path.is_file() { vec![path] } else { vec![] };
    }
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_file() && e.file_name().to_str().is_some_and(|n| wildcard_match(name, n)))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Endpoints serving a certificate that expires earlier than a newer one on disk for the
/// same host - i.e. a renewed certificate that the server hasn't been pointed at / reloaded.
pub fn stale_served(certs: &[CertStatus]) -> Vec<String> {
    let mut out = Vec::new();
    for ep in certs.iter().filter(|c| !c.file) {
        let (Some(served), Some(host)) = (ep.not_after, ep.target.split('/').next().and_then(|hp| hp.rsplit_once(':')).map(|(h, _)| h))
        else {
            continue;
        };
        let newest = certs
            .iter()
            .filter(|f| f.file && f.names.iter().any(|n| name_covers(n, host)))
            .filter_map(|f| f.not_after.map(|t| (t, &f.target)))
            .max();
        if let Some((t, path)) = newest {
            if t > served + 86_400 * SEC {
                out.push(format!(
                    "{} serves a certificate expiring {}, but {path} (expires {}) is newer: point the server at it and reload",
                    ep.target,
                    &fmt_ts(served)[..10],
                    &fmt_ts(t)[..10]
                ));
            }
        }
    }
    out
}

/// Parses openssl's `notAfter=Jan  9 12:00:00 2027 GMT`.
pub fn parse_not_after(text: &str) -> Option<Micros> {
    parse_openssl_date(text, "notAfter=")
}

fn parse_openssl_date(text: &str, key: &str) -> Option<Micros> {
    let v = text.lines().find_map(|l| l.trim().strip_prefix(key))?;
    let f: Vec<&str> = v.split_whitespace().collect();
    if f.len() < 4 {
        return None;
    }
    time::parse_syslog(f[0], f[1], f[2], f[3].parse().ok()?)
}

fn run_with_timeout(cmd: Command, input: Option<&[u8]>, limit: Duration) -> Result<Vec<u8>, String> {
    // stdout whatever the exit status: s_client exits non-zero after printing the chain
    crate::proc::run(cmd, input, limit).map(|o| o.stdout)
}

/// Fetches the certificate served at `target` and reads its expiry.
pub fn check_cert(openssl: &PathBuf, target: &str) -> CertStatus {
    let mut st = CertStatus { target: target.into(), checked: time::now(), ..Default::default() };
    let (hostport, starttls) = target.split_once('/').map_or((target, None), |(h, p)| (h, Some(p)));
    let host = hostport.rsplit_once(':').map_or(hostport, |(h, _)| h);
    let mut cmd = Command::new(openssl);
    cmd.args(["s_client", "-connect", hostport, "-servername", host]);
    if let Some(proto) = starttls {
        cmd.args(["-starttls", proto]);
        if proto == "xmpp" {
            cmd.args(["-xmpphost", host]);
        }
    }
    let pem = match run_with_timeout(cmd, None, Duration::from_secs(20)) {
        Ok(out) if String::from_utf8_lossy(&out).contains("BEGIN CERTIFICATE") => out,
        Ok(_) => {
            st.error = Some("no certificate received".into());
            return st;
        }
        Err(e) => {
            st.error = Some(e);
            return st;
        }
    };
    read_x509(openssl, None, Some(&pem), &mut st);
    // With -starttls xmpp, `host` is the XMPP domain the certificate must cover.
    if st.error.is_none() {
        st.wrong_name = name_problem(&st.names, host);
    }
    st
}

fn read_x509(openssl: &PathBuf, file: Option<&std::path::Path>, pem: Option<&[u8]>, st: &mut CertStatus) {
    let mut x509 = Command::new(openssl);
    x509.args(["x509", "-noout", "-startdate", "-enddate", "-text"]);
    if let Some(f) = file {
        x509.arg("-in").arg(f);
    }
    match run_with_timeout(x509, pem, Duration::from_secs(10)) {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out);
            st.names = parse_san(&text);
            st.not_before = parse_openssl_date(&text, "notBefore=");
            match parse_not_after(&text) {
                Some(t) => st.not_after = Some(t),
                None => st.error = Some("could not read expiry".into()),
            }
        }
        Err(e) => st.error = Some(e),
    }
}

/// DANE TLSA `3 1 1` value (SHA-256 of the SubjectPublicKeyInfo) of the first certificate
/// in `path`, as `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256` would give.
pub fn tlsa_311(openssl: &PathBuf, path: &str) -> Option<String> {
    let mut x509 = Command::new(openssl);
    x509.args(["x509", "-pubkey", "-noout", "-in", path]);
    let pubkey = run_with_timeout(x509, None, Duration::from_secs(10)).ok().filter(|o| !o.is_empty())?;
    let mut pkey = Command::new(openssl);
    pkey.args(["pkey", "-pubin", "-outform", "der"]);
    let der = run_with_timeout(pkey, Some(&pubkey), Duration::from_secs(10)).ok().filter(|o| !o.is_empty())?;
    let mut dgst = Command::new(openssl);
    dgst.args(["dgst", "-sha256", "-r"]);
    let out = run_with_timeout(dgst, Some(&der), Duration::from_secs(10)).ok()?;
    let hex = String::from_utf8_lossy(&out).split_whitespace().next()?.to_ascii_lowercase();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// Reads a certificate file's expiry and names.
pub fn check_cert_file(openssl: &PathBuf, path: &std::path::Path) -> CertStatus {
    let mut st = CertStatus { target: path.display().to_string(), checked: time::now(), file: true, ..Default::default() };
    read_x509(openssl, Some(path), None, &mut st);
    st
}

/// Renders the digest as (subject, plain-text body). The notifier names the server in
/// the subject (`[xmpp] logguard daily digest`), and a relaying peer adds its own name.
pub fn render(d: &DigestData, s: &Snapshot, warn_days: i64) -> (String, String) {
    let (subject, body) = render_raw(d, s, warn_days);
    (crate::event::plain_text(&subject), crate::event::plain_text(&body))
}

fn render_raw(d: &DigestData, s: &Snapshot, warn_days: i64) -> (String, String) {
    let now = d.until;
    let mut b = String::new();
    let mut attention: Vec<String> = Vec::new();

    // certificates first: they're the thing most likely to need action
    attention.extend(stale_served(&s.certs));
    for c in s.certs.iter().filter(|c| !c.file) {
        if let Some((_, what)) = c.concern(now, warn_days) {
            attention.push(format!("certificate {} {what}", c.target));
        }
    }
    if let Some(c) = &s.cluster {
        for p in c.peers.iter().filter(|p| p.last_error.is_some()) {
            attention.push(format!("cluster peer {} failing: {}", p.addr, p.last_error.clone().unwrap_or_default()));
        }
    }
    if let Some(f) = &s.feeds {
        for src in f.sources.iter().filter(|x| x.error.is_some()) {
            attention.push(format!(
                "feed {} failed{}: {}",
                src.url,
                if src.from_cache { " (using cached copy)" } else { "" },
                src.error.clone().unwrap_or_default()
            ));
        }
    }
    if let Some(r) = &s.exposure {
        for dead in &r.dead_rules {
            attention.push(format!("dead ufw rule {dead} (nothing listens)"));
        }
    }
    attention.extend(d.attention.iter().rev().take(15).cloned());

    let total_bans: u32 = d.bans_by_category.values().sum();
    b += &format!("Period {} → {} UTC ({})\n", &fmt_ts(d.since)[..16], &fmt_ts(now)[..16], fmt_duration(now - d.since));
    b += &format!("Mode: {:?}. Active bans now: {}.\n", s.mode, s.bans.len());

    b += "\n⚠ Needs attention:\n";
    if attention.is_empty() {
        b += "  nothing\n";
    }
    for a in &attention {
        b += &format!("  • {a}\n");
    }

    b += &format!("\nBans ({total_bans}):\n");
    let mut cats: Vec<(&String, &u32)> = d.bans_by_category.iter().collect();
    cats.sort_by_key(|c| std::cmp::Reverse(*c.1));
    for (cat, n) in cats {
        b += &format!("  {n:>5}  {cat}\n");
    }

    if !d.top.is_empty() {
        b += "\nTop offenders:\n";
        for (ip, pts, ban, place) in d.top.iter().take(10) {
            let state = ban.map_or(String::new(), |n| format!("  banned ({n})"));
            let place = place.as_ref().map_or(String::new(), |p| format!("  {p}"));
            b += &format!("  {:<22} {:>6.0} pts{state}{place}\n", ip.to_string(), pts);
        }
    }

    let alerts: Vec<String> = d.alerts_by_topic.iter().map(|(t, n)| format!("{t} {n}")).collect();
    if !alerts.is_empty() {
        b += &format!("\nAlerts: {}\n", alerts.join(", "));
    }
    let ev: u64 = d.events.values().sum();
    let mut top_ev: Vec<(&crate::event::Signal, &u64)> = d.events.iter().collect();
    top_ev.sort_by_key(|e| std::cmp::Reverse(*e.1));
    b += &format!("Events: {ev} ({})\n", top_ev.iter().take(5).map(|(s, n)| format!("{} {n}", s.name())).collect::<Vec<_>>().join(", "));

    if let Some(r) = &s.exposure {
        // "443 docker-proxy" once, whatever sockets (IPv4, IPv6, TCP, UDP) serve it
        let mut exposed: Vec<String> =
            r.listeners.iter().filter(|l| l.exposure.is_exposed() && !l.dynamic).map(|l| format!("{} {}", l.key.port, l.process)).collect();
        let mut seen = std::collections::HashSet::new();
        exposed.retain(|e| seen.insert(e.clone()));
        b += &format!("\nExposed: {}\n", if exposed.is_empty() { "nothing".into() } else { exposed.join(", ") });
    }
    if s.certs.iter().any(|c| !c.file) {
        let certs: Vec<String> = s
            .certs
            .iter()
            .filter(|c| !c.file)
            .map(|c| match c.days_left(now) {
                Some(d) => format!("{} {d}d", c.target),
                None => format!("{} ?", c.target),
            })
            .collect();
        b += &format!("Certificates: {}\n", certs.join(", "));
    }
    if let Some(c) = &s.cluster {
        let ok = c.peers.iter().filter(|p| p.last_error.is_none() && p.last_ok.is_some()).count();
        b += &format!("Cluster: {ok}/{} peers ok, {} facts received\n", c.peers.len(), c.facts_received);
    }
    if let Some(f) = &s.feeds {
        b += &format!("Blocklists: {} networks{}\n", f.v4 + f.v6, if f.applied { "" } else { " (not applied)" });
    }
    if !s.allowed.is_empty() {
        b += &format!("Operator allowlist: {} entries\n", s.allowed.len());
    }

    let flag = if attention.is_empty() { "" } else { "⚠ " };
    (format!("{flag}logguard daily digest"), b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssl_date_and_schedule() {
        let t = parse_not_after("notAfter=Jan  9 12:00:00 2027 GMT\n").unwrap();
        assert_eq!(fmt_ts(t), "2027-01-09 12:00:00");
        let cfg = DigestCfg { enabled: true, at: "07:30".into(), ..Default::default() };
        cfg.validate().unwrap();
        let day = 86_400 * SEC;
        let now = 100 * day + 8 * 3600 * SEC;
        assert_eq!(cfg.last_due(now), Some(100 * day + 7 * 3600 * SEC + 30 * 60 * SEC));
        let early = 100 * day + 6 * 3600 * SEC;
        assert_eq!(cfg.last_due(early), Some(99 * day + 7 * 3600 * SEC + 30 * 60 * SEC));
        assert!(DigestCfg { at: "25:00".into(), ..cfg.clone() }.validate().is_err());
        assert!(DigestCfg { certs: vec!["nohost".into()], ..cfg }.validate().is_err());
    }

    #[test]
    fn renewed_but_not_served() {
        let day = 86_400 * SEC;
        let ep = |target: &str, t: i64| CertStatus { target: target.into(), not_after: Some(t * day), ..Default::default() };
        let file = |path: &str, t: i64, names: &[&str]| CertStatus {
            target: path.into(),
            not_after: Some(t * day),
            names: names.iter().map(|n| n.to_string()).collect(),
            file: true,
            ..Default::default()
        };
        let certs = vec![
            ep("example.org:5223", 100),
            ep("upload.example.org:443", 100),
            file("/acme/live/old", 100, &["example.org", "conference.example.org"]),
            file("/acme/live/new", 190, &["example.org", "conference.example.org"]),
        ];
        let stale = stale_served(&certs);
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert!(stale[0].starts_with("example.org:5223 serves") && stale[0].contains("/acme/live/new"));
        assert!(name_covers("*.example.org", "upload.example.org") && !name_covers("*.example.org", "example.org"));
        let names = vec!["example.org".to_string(), "*.example.org".to_string()];
        assert_eq!(name_problem(&names, "example.org"), None);
        assert_eq!(name_problem(&names, "Upload.example.org"), None);
        assert_eq!(name_problem(&names, "nextcloud.example.net").unwrap(), "is for example.org, *.example.org, not nextcloud.example.net");
        assert!(name_problem(&[], "example.org").unwrap().contains("no subjectAltName"));
        assert_eq!(name_problem(&[], "203.0.113.5"), None, "addresses aren't names");
        let mut c = CertStatus { target: "x:443".into(), not_after: Some(100 * 86_400 * SEC), ..Default::default() };
        assert_eq!(c.concern(0, 21), None);
        c.wrong_name = Some("is for a.example, not x".into());
        assert_eq!(c.concern(0, 21).unwrap().0, crate::engine::Severity::High);
        assert_eq!(
            parse_san("X509v3 Subject Alternative Name: \n    DNS:example.org, DNS:Conference.example.org\n"),
            vec!["example.org", "conference.example.org"]
        );
        assert!(wildcard_match("*", "879798abc") && wildcard_match("*.pem", "a.pem") && !wildcard_match("*.pem", "a.key"));
    }

    #[test]
    fn short_lived_certificates_are_judged_by_their_lifetime() {
        use crate::engine::Severity;
        let t = |m: &str, d: &str, c: &str| time::parse_syslog(m, d, c, 2026).unwrap();
        // Let's Encrypt 6-day profile, as served by Nextcloud AIO's Caddy (issuer YE1)
        let c = CertStatus {
            target: "nextcloud.example.org:443".into(),
            not_before: Some(t("Oct", "9", "15:04:34")),
            not_after: Some(t("Oct", "16", "07:04:33")),
            ..Default::default()
        };
        assert_eq!(c.expiry_concern(t("Oct", "12", "12:30:00"), 21), None, "3.8 days of 6.7 left: just renewed");
        assert_eq!(c.expiry_concern(t("Oct", "14", "06:00:00"), 21), Some(Severity::Warning), "~49 h left: renewal is late");
        assert_eq!(c.expiry_concern(t("Oct", "15", "08:00:00"), 21), Some(Severity::High), "~23 h left");
        assert!(c.expiry_text(t("Oct", "15", "08:00:00")).starts_with("expires in 23h04m"));
        // 90-day certificates: as before (21 days, high under 7)
        let long =
            CertStatus { not_before: Some(t("Sep", "1", "00:00:00")), not_after: Some(t("Nov", "30", "00:00:00")), ..Default::default() };
        assert_eq!(long.expiry_concern(t("Nov", "1", "00:00:00"), 21), None);
        assert_eq!(long.expiry_concern(t("Nov", "10", "00:00:00"), 21), Some(Severity::Warning));
        assert_eq!(long.expiry_concern(t("Nov", "25", "00:00:00"), 21), Some(Severity::High));
        assert_eq!(parse_openssl_date("notBefore=Oct  9 15:04:34 2026 GMT\nnotAfter=Oct 16 07:04:33 2026 GMT", "notBefore="), c.not_before);
    }
}
