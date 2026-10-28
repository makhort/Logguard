//! Public blocklist feeds (Spamhaus DROP, FireHOL level1, ...).
//!
//! Lists are downloaded with `curl` (or `wget`) - shelling out keeps the binary free of
//! a TLS stack - cached on disk, sanitised (private/bogon ranges, overly wide prefixes
//! and anything overlapping the allowlist or cluster peers are dropped), de-nested and
//! loaded into the separate nftables sets `feed4`/`feed6` in one atomic transaction.
//! `logguard feeds clear` (or `enabled = false`) empties them in one step without
//! touching logguard's own bans.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::net::Net;
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeedsCfg {
    pub enabled: bool,
    pub urls: Vec<String>,
    pub refresh: Dur,
    /// Last good copy of every list; used when a download fails.
    pub cache_dir: PathBuf,
    /// Download command; the URL is appended. Output must go to stdout.
    pub fetch: Vec<String>,
    /// Refuse to load more than this many networks (protects against a broken feed).
    pub max_entries: usize,
    /// Never load networks wider than these prefixes: one bad entry must not drop a
    /// whole provider's (or country's) addresses before any other rule is looked at.
    pub min_prefix_v4: u8,
    pub min_prefix_v6: u8,
    /// Refuse a refresh covering more than this many times the address space of the last
    /// accepted one (plus a /16, or 2^16 IPv6 /64s); the last accepted list stays loaded.
    /// 0 = no check. After an intended change (a new feed), delete
    /// `<cache_dir>/accepted.txt` once.
    pub max_growth: f64,
    /// Lists of networks (ASNs) to block wholesale, e.g. Spamhaus ASN-DROP
    /// (`https://www.spamhaus.org/drop/asndrop.json`): their addresses come from the `[geo]`
    /// network database and are loaded with the other feeds, under the same limits.
    pub asn_urls: Vec<String>,
}

impl Default for FeedsCfg {
    fn default() -> Self {
        FeedsCfg {
            enabled: false,
            urls: vec![
                "https://www.spamhaus.org/drop/drop.txt".into(),
                "https://www.spamhaus.org/drop/dropv6.txt".into(),
                "https://iplists.firehol.org/files/firehol_level1.netset".into(),
            ],
            refresh: Dur(86_400),
            cache_dir: "/var/lib/logguard/feeds".into(),
            // a redirect may not leave https (a feed or RDAP answer from anyone on the way)
            fetch: ["curl", "-fsSL", "--proto-redir", "=https", "--max-time", "60", "--retry", "2", "--max-filesize", "50000000"]
                .map(String::from)
                .to_vec(),
            max_entries: 100_000,
            min_prefix_v4: 12,
            min_prefix_v6: 24,
            max_growth: 2.0,
            asn_urls: vec![],
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceStatus {
    pub url: String,
    pub entries: usize,
    pub from_cache: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FeedStatus {
    pub refreshed: Micros,
    pub v4: usize,
    pub v6: usize,
    /// Entries dropped as private/bogon, too wide, or overlapping protected addresses.
    pub skipped: usize,
    pub sources: Vec<SourceStatus>,
    /// Loaded into nftables (false in shadow mode, with the ufw backend, or on error).
    pub applied: bool,
    pub error: Option<String>,
    /// Networks (ASNs) listed by `asn_urls`, and the address blocks they came to.
    #[serde(default)]
    pub asns: usize,
    #[serde(default)]
    pub asn_networks: usize,
    /// The ASN lists were left out: no `[geo]` network database loaded yet (a refresh
    /// follows once it is).
    #[serde(default)]
    pub asn_pending: bool,
}

/// Special-purpose ranges that must never be blocked (FireHOL level1 lists several).
pub(crate) const BOGONS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/8",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
];

/// Parses plain CIDR lists, Spamhaus `cidr ; SBL...` lines and Spamhaus JSON lines.
pub fn parse_feed(text: &str) -> Vec<Net> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let token = if line.starts_with('{') {
            // {"cidr":"11.1.16.0/20","sblid":"SBL256894","rir":"apnic"}
            line.split("\"cidr\":\"").nth(1).and_then(|r| r.split('"').next()).unwrap_or("")
        } else {
            line.split(['#', ';']).next().unwrap_or("").split_whitespace().next().unwrap_or("")
        };
        if let Ok(net) = token.parse::<Net>() {
            out.push(net);
        }
    }
    out
}

/// Parses ASN lists: Spamhaus ASN-DROP JSON lines (`{"asn":6939,...}`), `AS6939 ; ...` text,
/// or one number per line.
pub fn parse_asns(text: &str) -> std::collections::BTreeSet<u32> {
    let mut out = std::collections::BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        let token = if line.starts_with('{') {
            line.split("\"asn\":").nth(1).map(|r| r.trim_start().trim_start_matches('"')).unwrap_or("")
        } else {
            line.split(['#', ';']).next().unwrap_or("").trim()
        };
        let digits: String = token.trim_start_matches(['A', 'S', 'a', 's']).chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse::<u32>() {
            if n > 0 {
                out.insert(n);
            }
        }
    }
    out
}

/// Drops dangerous entries; returns (kept, skipped).
pub fn sanitize(nets: Vec<Net>, protected: &[Net], min_v4: u8, min_v6: u8) -> (Vec<Net>, usize) {
    let bogons: Vec<Net> = BOGONS.iter().map(|b| b.parse().expect("valid bogon")).collect();
    let total = nets.len();
    let kept: Vec<Net> = nets
        .into_iter()
        .filter(|n| n.prefix >= if n.is_v4() { min_v4 } else { min_v6 })
        .filter(|n| !bogons.iter().any(|b| b.overlaps(n)))
        .filter(|n| !protected.iter().any(|p| p.overlaps(n)))
        .collect();
    let skipped = total - kept.len();
    (kept, skipped)
}

/// Sorts and removes networks contained in others (nftables interval sets reject overlaps).
pub fn aggregate(mut nets: Vec<Net>) -> Vec<Net> {
    nets.sort_by_key(|n| (n.is_v4(), n.addr, n.prefix));
    let mut out: Vec<Net> = Vec::with_capacity(nets.len());
    for n in nets {
        // CIDRs are nested or disjoint: after sorting, a container precedes what it contains.
        if out.last().is_some_and(|last| last.contains_net(&n)) {
            continue;
        }
        out.push(n);
    }
    out
}

fn cache_path(dir: &Path, url: &str) -> PathBuf {
    let name: String = url.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
    dir.join(format!("{name}.txt"))
}

/// Largest blocklist (or RDAP answer) accepted: the lists in use are well under 1 MB, and
/// the download is held in memory, inside the service's memory limit.
pub const MAX_DOWNLOAD: u64 = 16 << 20;

/// Runs a fetch command (`curl ... <url>`), streaming its output into `out` and stopping
/// at `max` bytes, so a huge or endless answer can't exhaust memory or disk.
pub fn fetch_into(cmd: &[String], url: &str, out: &mut dyn std::io::Write, max: u64) -> Result<u64> {
    fetch_into_with(cmd, url, None, out, max)
}

/// `fetch_into`, writing `input` to the command's stdin: a secret header for `curl -H @-`,
/// which other local users can't read there as they can a command line.
pub fn fetch_into_with(cmd: &[String], url: &str, input: Option<&[u8]>, out: &mut dyn std::io::Write, max: u64) -> Result<u64> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    let (prog, args) = cmd.split_first().context("empty fetch command")?;
    // In a process group of its own, so the whole tree can be stopped: a wrapper (`sh -c`,
    // which dash forks from instead of exec'ing) leaves children that hold the pipes open.
    let mut child = Command::new(prog)
        .args(args)
        .arg(url)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .with_context(|| format!("running {prog}"))?;
    let group = child.id();
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(&data);
        });
    }
    // Drained separately (only the start kept), so a chatty program can't block on it.
    let mut err_pipe = child.stderr.take().context("stderr")?;
    let errors = std::thread::spawn(move || {
        let mut head = Vec::new();
        let _ = err_pipe.by_ref().take(4096).read_to_end(&mut head);
        let _ = std::io::copy(&mut err_pipe, &mut std::io::sink());
        head
    });
    let mut stdout = child.stdout.take().context("stdout")?;
    let copied = std::io::copy(&mut stdout.by_ref().take(max + 1), out);
    // Too big, or the output can't be written (disk full): stop the program, which would
    // otherwise block forever on its full pipe.
    if copied.as_ref().map_or(true, |n| *n > max) {
        drop(stdout);
        kill_group(group);
        let _ = child.wait();
        let _ = errors.join();
        return match copied {
            Ok(_) => Err(anyhow::anyhow!("{url}: larger than {} MB", max >> 20)),
            Err(e) => Err(e).context("storing the download"),
        };
    }
    drop(stdout);
    let status = child.wait()?;
    // Something it left behind still holds stderr open, and the reader would wait for it:
    // stop that too. (The group then still has members, so its id is still theirs.)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !errors.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !errors.is_finished() {
        kill_group(group);
    }
    let err = errors.join().unwrap_or_default();
    let n = copied?;
    if !status.success() {
        bail!("{prog} failed ({status}): {}", String::from_utf8_lossy(&err).trim());
    }
    Ok(n)
}

/// SIGKILL to every process in the group `fetch_into` started. Only while the group's id can't
/// have been reused: its leader not yet reaped, or members still holding its pipes.
fn kill_group(group: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let Ok(pgid) = i32::try_from(group) else { return };
    // SAFETY: kill(2) takes plain integers and touches no memory; a negative pid names a
    // process group, here the one of a child we started (see above).
    unsafe {
        kill(-pgid, crate::sys::SIGKILL);
    }
}

/// Fetches a URL with the configured command (curl, falling back to wget), at most `MAX_DOWNLOAD` bytes.
pub fn download(cfg: &FeedsCfg, url: &str) -> Result<String> {
    let run = |cmd: &[String]| -> Result<String> {
        let mut buf = Vec::new();
        fetch_into(cmd, url, &mut buf, MAX_DOWNLOAD)?;
        Ok(String::from_utf8(buf).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
    };
    match run(&cfg.fetch) {
        Ok(t) => Ok(t),
        // curl missing on a minimal install: try wget with the default command only.
        Err(e) if cfg.fetch.first().is_some_and(|p| p == "curl") => {
            run(&["wget", "-q", "-T", "60", "-O", "-"].map(String::from)).map_err(|w| e.context(format!("wget fallback: {w:#}")))
        }
        Err(e) => Err(e),
    }
}

/// Addresses covered: IPv4 addresses, and IPv6 /64 networks.
pub fn space(nets: &[Net]) -> (u128, u128) {
    let mut s = (0u128, 0u128);
    for n in nets {
        if n.is_v4() {
            s.0 += 1u128 << (32 - u32::from(n.prefix.min(32)));
        } else {
            s.1 += 1u128 << (64 - u32::from(n.prefix.min(64)));
        }
    }
    s
}

/// Why `new` is suspiciously larger than the last accepted list `old`, if it is.
pub fn growth_problem(old: &[Net], new: &[Net], max_growth: f64) -> Option<String> {
    if max_growth <= 0.0 || old.is_empty() {
        return None;
    }
    let ((o4, o6), (n4, n6)) = (space(old), space(new));
    let limit = |o: u128| (o as f64 * max_growth) + 65_536.0;
    if n4 as f64 > limit(o4) {
        return Some(format!(
            "the lists now cover {n4} IPv4 addresses, {:.1}x the {o4} of the last accepted load",
            n4 as f64 / o4.max(1) as f64
        ));
    }
    if n6 as f64 > limit(o6) {
        return Some(format!(
            "the lists now cover {n6} IPv6 /64s, {:.1}x the {o6} of the last accepted load",
            n6 as f64 / o6.max(1) as f64
        ));
    }
    None
}

/// The last accepted (loaded) list, one network per line.
fn accepted_path(dir: &Path) -> PathBuf {
    dir.join("accepted.txt")
}

/// What a list was built from (its URLs), written at the top of `accepted.txt`: a list from
/// other sources is an intended change, which the growth check doesn't refuse.
fn sources_id(urls: &[String], asn_urls: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(urls.join("\n"));
    if !asn_urls.is_empty() {
        h.update("\n--asn--\n");
        h.update(asn_urls.join("\n"));
    }
    h.finalize().iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Downloads a list, falling back to the cached copy; `parse` says whether it holds anything.
fn fetch_list(cfg: &FeedsCfg, url: &str, holds: impl Fn(&str) -> bool) -> (Option<String>, SourceStatus) {
    let cache = cache_path(&cfg.cache_dir, url);
    let mut src = SourceStatus { url: url.to_string(), ..Default::default() };
    let text = match download(cfg, url) {
        Ok(t) if holds(&t) => {
            let _ = std::fs::write(&cache, &t);
            Some(t)
        }
        result => {
            src.error = Some(match result {
                Ok(_) => "downloaded list contains no networks".into(),
                Err(e) => format!("{e:#}"),
            });
            src.from_cache = true;
            std::fs::read_to_string(&cache).ok()
        }
    };
    (text, src)
}

/// Downloads (or reads cached) lists and returns the networks to load. A result that is
/// too big (`max_entries`) or grew too much (`max_growth`) is refused: the last accepted
/// list is returned instead, with the reason in the status.
///
/// `expand` gives the networks of the ASNs `asn_urls` list (from the `[geo]` network
/// database); None while no database is loaded: the ASN lists are left out then.
pub fn refresh(
    cfg: &FeedsCfg,
    protected: &[Net],
    expand: &dyn Fn(&std::collections::BTreeSet<u32>) -> Option<Vec<Net>>,
) -> (Vec<Net>, FeedStatus) {
    let mut status = FeedStatus { refreshed: time::now(), ..Default::default() };
    let _ = std::fs::create_dir_all(&cfg.cache_dir);
    let mut all = Vec::new();
    for url in &cfg.urls {
        let (text, mut src) = fetch_list(cfg, url, |t| !parse_feed(t).is_empty());
        let nets = text.map(|t| parse_feed(&t)).unwrap_or_default();
        src.entries = nets.len();
        all.extend(nets);
        status.sources.push(src);
    }
    let mut asns = std::collections::BTreeSet::new();
    for url in &cfg.asn_urls {
        let (text, mut src) = fetch_list(cfg, url, |t| !parse_asns(t).is_empty());
        let listed = text.map(|t| parse_asns(&t)).unwrap_or_default();
        src.entries = listed.len();
        asns.extend(listed);
        status.sources.push(src);
    }
    let mut sources = (cfg.urls.clone(), cfg.asn_urls.clone());
    if !asns.is_empty() {
        status.asns = asns.len();
        match expand(&asns) {
            Some(nets) => {
                status.asn_networks = nets.len();
                all.extend(nets);
            }
            None => {
                // not expanded: the list is what the plain feeds make, for the growth check too
                sources.1.clear();
                status.asn_pending = true;
            }
        }
    }
    let (kept, skipped) = sanitize(all, protected, cfg.min_prefix_v4, cfg.min_prefix_v6);
    let nets = aggregate(kept);
    status.skipped = skipped;
    let accepted_text = std::fs::read_to_string(accepted_path(&cfg.cache_dir)).unwrap_or_default();
    let id = sources_id(&sources.0, &sources.1);
    // a list of older versions has no id: it came from the plain feeds
    let accepted_id = accepted_text
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("# sources "))
        .map_or_else(|| sources_id(&cfg.urls, &[]), |s| s.trim().to_string());
    let accepted = parse_feed(&accepted_text);
    // the protected list may have changed since: apply it to the old list too
    let accepted = aggregate(sanitize(accepted, protected, cfg.min_prefix_v4, cfg.min_prefix_v6).0);
    let refused = if nets.len() > cfg.max_entries {
        Some(format!("{} networks exceed max_entries {}", nets.len(), cfg.max_entries))
    } else if accepted_id != id {
        None // other lists than last time: an intended change
    } else {
        growth_problem(&accepted, &nets, cfg.max_growth)
    };
    let nets = match refused {
        Some(why) => {
            status.error = Some(format!(
                "{why}; not loaded, keeping the last accepted list ({} networks). If intended, delete {}",
                accepted.len(),
                accepted_path(&cfg.cache_dir).display()
            ));
            accepted
        }
        None => {
            let text: String = std::iter::once(format!("# sources {id}\n")).chain(nets.iter().map(|n| format!("{n}\n"))).collect();
            let _ = std::fs::write(accepted_path(&cfg.cache_dir), text);
            nets
        }
    };
    status.v4 = nets.iter().filter(|n| n.is_v4()).count();
    status.v6 = nets.len() - status.v4;
    (nets, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloads_are_capped() {
        let cmd = |script: &str| ["sh", "-c", script, "sh"].map(String::from).to_vec();
        let mut buf = Vec::new();
        assert_eq!(fetch_into(&cmd("yes | head -c 5000"), "http://x", &mut buf, 10_000).unwrap(), 5000);
        let mut buf = Vec::new();
        let err = fetch_into(&cmd("yes"), "http://x", &mut buf, 1 << 20).unwrap_err().to_string();
        assert!(err.contains("larger than 1 MB"), "{err}");
        assert!(buf.len() <= (1 << 20) + 1, "stopped at the cap");
        let err = fetch_into(&cmd("echo nope >&2; exit 22"), "http://x", &mut Vec::new(), 10).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");
    }

    #[test]
    fn stops_what_the_command_started() {
        let cmd = |script: &str| ["sh", "-c", script, "sh"].map(String::from).to_vec();
        let start = std::time::Instant::now();
        // `yes` as a child of the shell (as dash runs `sh -c yes`): killing the shell alone
        // left it blocked on the full pipe, holding stderr open, and fetch_into waiting forever
        let err = fetch_into(&cmd("yes; true"), "http://x", &mut Vec::new(), 1 << 16).unwrap_err().to_string();
        assert!(err.contains("larger than"), "{err}");
        // a background process left holding stderr after the command is done
        let mut buf = Vec::new();
        assert_eq!(fetch_into(&cmd("sleep 60 > /dev/null & echo ok"), "http://x", &mut buf, 100).unwrap(), 3);
        assert!(start.elapsed() < std::time::Duration::from_secs(20), "{:?}", start.elapsed());
    }

    #[test]
    fn parses_spamhaus_firehol_and_json() {
        let spamhaus = "; Spamhaus DROP List 2026/10/11\n; Last-Modified: x\n11.1.16.0/20 ; SBL256894\n11.2.32.0/22 ; SBL459831\n";
        let firehol = "#\n# firehol_level1\n#\n0.0.0.0/8\n11.1.16.0/20\n10.0.0.0/8\n11.3.10.0/23\n224.0.0.0/3\n";
        let json = "{\"cidr\":\"11.19.56.0/22\",\"sblid\":\"SBL1\",\"rir\":\"ripencc\"}\n{\"type\":\"metadata\",\"timestamp\":1}\n";
        let v6 = "3fff:140::/29 ; SBL300728\n";
        let all: Vec<Net> = [spamhaus, firehol, json, v6].iter().flat_map(|t| parse_feed(t)).collect();
        assert_eq!(all.len(), 9);

        let protected: Vec<Net> = vec!["11.3.10.7".parse().unwrap()];
        let (kept, skipped) = sanitize(all, &protected, 8, 19);
        assert_eq!(skipped, 4, "0/8, 10/8, 224/3 and the protected 11.3.10.0/23");
        let merged = aggregate(kept);
        let s: Vec<String> = merged.iter().map(|n| n.to_string()).collect();
        assert_eq!(s, vec!["3fff:140::/29", "11.1.16.0/20", "11.2.32.0/22", "11.19.56.0/22"]);
    }

    #[test]
    fn asn_lists() {
        let json = "{\"asn\":6939,\"rir\":\"arin\",\"domain\":\"he.net\"}\n{\"type\":\"metadata\",\"timestamp\":1}\n";
        let text = "; Spamhaus ASN-DROP\nAS64500 ; RU | X\n64501\nas64502\n0\nnot a number\n";
        let all: Vec<u32> = parse_asns(json).into_iter().chain(parse_asns(text)).collect();
        assert_eq!(all, vec![6939, 64500, 64501, 64502]);

        let dir = std::env::temp_dir().join(format!("logguard-feeds-asn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = FeedsCfg {
            cache_dir: dir.clone(),
            urls: vec!["https://invalid.example/l".into()],
            asn_urls: vec!["https://invalid.example/asn".into()],
            fetch: vec!["false".into()],
            ..Default::default()
        };
        // (wider than a /16: addresses the public mirror keeps as they are, see make_public_mirror.zsh)
        std::fs::write(cache_path(&dir, &cfg.urls[0]), "1.2.16.0/20\n").unwrap();
        std::fs::write(cache_path(&dir, &cfg.asn_urls[0]), "AS64500\n").unwrap();
        // no network database yet: the plain feeds only, and why
        let (nets, st) = refresh(&cfg, &[], &|_| None);
        assert_eq!((nets.len(), st.asns, st.asn_pending, st.error.as_deref()), (1, 1, true, None));
        // with it: the ASN's networks too, accepted although they are far more than the
        // last list (other sources: an intended change)
        let expand = |asns: &std::collections::BTreeSet<u32>| -> Option<Vec<Net>> {
            Some(asns.iter().map(|_| "100.64.0.0/10".parse().unwrap()).chain(["6.0.0.0/12".parse().unwrap()]).collect())
        };
        let (nets, st) = refresh(&cfg, &[], &expand);
        let s: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
        assert_eq!(s, ["1.2.16.0/20", "6.0.0.0/12"], "the bogon is dropped as always: {st:?}");
        assert_eq!((st.asn_networks, st.error), (2, None));
        assert!(std::fs::read_to_string(dir.join("accepted.txt")).unwrap().starts_with("# sources "));
        // the same sources again: the growth check applies
        let (_, st) = refresh(&cfg, &[], &expand);
        assert_eq!(st.error, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aggregate_removes_nested() {
        let nets: Vec<Net> =
            ["11.35.0.0/16", "11.35.53.0/24", "11.35.53.7", "11.31.62.0/24", "11.31.0.0/16"].iter().map(|n| n.parse().unwrap()).collect();
        let s: Vec<String> = aggregate(nets).iter().map(|n| n.to_string()).collect();
        assert_eq!(s, vec!["11.31.0.0/16", "11.35.0.0/16"]);
    }

    #[test]
    fn failing_download_falls_back_to_cache() {
        let dir = std::env::temp_dir().join(format!("logguard-feeds-{}", std::process::id()));
        let cfg = FeedsCfg {
            cache_dir: dir.clone(),
            urls: vec!["https://invalid.example/list".into()],
            fetch: vec!["false".into()],
            ..Default::default()
        };
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(cache_path(&dir, &cfg.urls[0]), "11.1.16.0/20\n").unwrap();
        let (nets, st) = refresh(&cfg, &[], &|_| None);
        assert_eq!(nets.len(), 1);
        assert!(st.sources[0].from_cache && st.sources[0].error.is_some());
        let cfg = FeedsCfg { max_entries: 0, ..cfg };
        let (nets, st) = refresh(&cfg, &[], &|_| None);
        assert_eq!(nets.len(), 1, "max_entries guard: the last accepted list stays");
        assert!(st.error.as_deref().is_some_and(|e| e.contains("max_entries")), "{st:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_feed_that_suddenly_covers_much_more_is_refused() {
        let dir = std::env::temp_dir().join(format!("logguard-feeds-growth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = FeedsCfg {
            cache_dir: dir.clone(),
            urls: vec!["https://invalid.example/l".into()],
            fetch: vec!["false".into()],
            ..Default::default()
        };
        let list = |text: &str| std::fs::write(cache_path(&dir, &cfg.urls[0]), text).unwrap();
        list("11.1.16.0/20\n11.2.32.0/22\n");
        assert_eq!(refresh(&cfg, &[], &|_| None).0.len(), 2, "first load: no baseline");
        // one new /12 is ~250x the space: refused, the accepted list stays
        list("11.1.16.0/20\n11.2.32.0/22\n100.0.0.0/12\n");
        let (nets, st) = refresh(&cfg, &[], &|_| None);
        assert_eq!(nets.len(), 2);
        assert!(st.error.as_deref().is_some_and(|e| e.contains("IPv4 addresses")), "{st:?}");
        // a few more small networks are normal growth
        list("11.1.16.0/20\n11.2.32.0/22\n11.3.10.0/23\n11.19.56.0/22\n");
        let (nets, st) = refresh(&cfg, &[], &|_| None);
        assert_eq!((nets.len(), st.error), (4, None));
        // wider than the floor (/12): never loaded
        list("11.1.16.0/20\n64.0.0.0/8\n");
        assert!(!refresh(&cfg, &[], &|_| None).0.iter().any(|n| n.prefix == 8));
        // max_growth = 0: no check
        list("11.1.16.0/20\n100.0.0.0/12\n");
        assert_eq!(refresh(&FeedsCfg { max_growth: 0.0, ..cfg.clone() }, &[], &|_| None).0.len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
