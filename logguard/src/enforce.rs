//! Firewall enforcement.
//!
//! Preferred: an nftables table of our own, hooked at prerouting (raw priority, i.e.
//! before UFW's input chains *and* before Docker's DNAT, so ports published by
//! `docker run -p` are covered too), with
//! timed sets (`flags interval, timeout`) so bans expire in the kernel even if
//! the daemon is down. Fallback: `ufw prepend deny`, which places the rule
//! above UFW's ALLOW rules (plain `ufw deny` appends after them and never
//! matches traffic to allowed ports). For hosts with plain iptables (e.g. with
//! iptables-persistent) instead of ufw: two chains of our own in the raw table, see
//! [`iptables_static_rules`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::config::{Backend, Config, Mode, PortSpec, RateLimitCfg};
use crate::engine::{Action, ActionKind, Ban};
use crate::event::Proto;
use crate::net::Net;
use crate::time::{Micros, SEC};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Shadow,
    Nft,
    Ufw,
    Iptables,
}

pub struct Enforcer {
    pub kind: Kind,
    /// Why nftables couldn't be set up, when the ufw fallback (or shadow) is in use instead.
    pub nft_error: Option<String>,
    nft: PathBuf,
    ufw: PathBuf,
    iptables: PathBuf,
    ip6tables: PathBuf,
    /// iptables chain names: static rules, and bans with operator allows.
    chain: String,
    table: String,
    setup: String,
    /// What `setup` is made of, to rebuild it when the cluster peers' addresses change.
    allow: Vec<Net>,
    /// Runtime-protected networks (cluster peers), for rebuilding the iptables chain.
    extra_allow: Vec<Net>,
    open_ports: Vec<PortSpec>,
    limits: Vec<RateLimitCfg>,
}

fn set_name(net: &Net) -> &'static str {
    if net.is_v4() {
        "ban4"
    } else {
        "ban6"
    }
}

/// The ports of a port list per protocol name (`tcp`, `udp`), sorted, without empty ones.
fn ports_by_proto(ports: &[PortSpec]) -> Vec<(&'static str, Vec<u16>)> {
    let mut out = Vec::new();
    for (proto, name) in [(Proto::Tcp, "tcp"), (Proto::Udp, "udp")] {
        let mut list: Vec<u16> = ports.iter().filter(|p| p.proto.is_none_or(|q| q == proto)).map(|p| p.port).collect();
        list.sort_unstable();
        list.dedup();
        if !list.is_empty() {
            out.push((name, list));
        }
    }
    out
}

/// `tcp dport { 5222, 5223 }`-style matches for a port list, one per protocol.
fn dport_matches(ports: &[PortSpec]) -> Vec<String> {
    ports_by_proto(ports)
        .into_iter()
        .map(|(name, list)| {
            let list: Vec<String> = list.iter().map(u16::to_string).collect();
            format!("{name} dport {{ {} }}", list.join(", "))
        })
        .collect()
}

/// One iptables (false) or ip6tables (true) call: the arguments after `-w 10 -t raw`.
pub type IptCmd = (bool, Vec<String>);

fn ipt(v6: bool, args: &[&str]) -> IptCmd {
    (v6, args.iter().map(|a| a.to_string()).collect())
}

/// The iptables backend's static rules, for both address families. Two chains of our own
/// in the raw table, jumped to from the top of PREROUTING (like the nftables table: before
/// conntrack, the filter chains and Docker's DNAT):
/// - `<chain>`: allowlisted sources and whitelisted ports `RETURN` (skip what follows), then
///   a jump to `<chain>-ban`. Rebuilt whenever the allowlist changes.
/// - `<chain>-ban`: operator allows (`RETURN`, inserted at the top), then bans (`DROP`,
///   appended). logguard adds and removes these one by one; they don't expire in the kernel.
///
/// `RETURN`, not `ACCEPT`, so other rules in the raw table (Docker's) still apply.
pub fn iptables_static_rules(chain: &str, allow: &[Net], open_ports: &[PortSpec]) -> Vec<IptCmd> {
    let allow = crate::net::collapse(allow);
    let ban_chain = format!("{chain}-ban");
    let mut out = Vec::new();
    for v6 in [false, true] {
        out.push(ipt(v6, &["-F", chain]));
        for net in allow.iter().filter(|n| n.is_v4() != v6) {
            out.push(ipt(v6, &["-A", chain, "-s", &net.to_string(), "-j", "RETURN"]));
        }
        for (proto, list) in ports_by_proto(open_ports) {
            // multiport takes at most 15 ports per rule
            for chunk in list.chunks(15) {
                let ports: Vec<String> = chunk.iter().map(u16::to_string).collect();
                out.push(ipt(v6, &["-A", chain, "-p", proto, "-m", "multiport", "--dports", &ports.join(","), "-j", "RETURN"]));
            }
        }
        out.push(ipt(v6, &["-A", chain, "-j", &ban_chain]));
    }
    out
}

/// A ban rule in `<chain>-ban`; `verb` is `-A` (add), `-D` (delete) or `-C` (check).
pub fn iptables_ban_rule(chain: &str, net: &Net, verb: &str) -> IptCmd {
    ipt(!net.is_v4(), &[verb, &format!("{chain}-ban"), "-s", &net.to_string(), "-j", "DROP"])
}

/// An operator allow in `<chain>-ban`, above the bans; `verb` is `-I` (add), `-D` or `-C`.
pub fn iptables_allow_rule(chain: &str, net: &Net, verb: &str) -> IptCmd {
    let (ban_chain, source) = (format!("{chain}-ban"), net.to_string());
    let at_top: &[&str] = if verb == "-I" { &["1"] } else { &[] };
    let args: Vec<&str> = [verb, &ban_chain].into_iter().chain(at_top.iter().copied()).chain(["-s", &source, "-j", "RETURN"]).collect();
    ipt(!net.is_v4(), &args)
}

/// Longest an nft or ufw call may take (a feed load is one big transaction); the main loop
/// waits for it, and the systemd watchdog (2 min) must not fire.
const FIREWALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Comment tagging the rules of `[[ratelimit]]` entry `i` (used to read their counters back).
const RL_COMMENT: &str = "logguard ratelimit";

/// Idempotent setup: creates the table, sets and chains, and (re)loads the allowlist,
/// whitelisted ports and rate limits. Existing ban elements survive a restart.
///
/// Two base chains: `pre` (priority raw: before conntrack and Docker's DNAT) drops banned
/// and blocklisted sources; `rl` (priority mangle: after conntrack, still before DNAT, so
/// it sees the original port of Docker-published services) limits new connections per source.
pub fn nft_setup_script(table: &str, allow: &[Net], open_ports: &[PortSpec], limits: &[RateLimitCfg]) -> String {
    let allow = crate::net::collapse(allow);
    let (a4, a6): (Vec<&Net>, Vec<&Net>) = allow.iter().partition(|n| n.is_v4());
    // Per-source limiter state lives in dynamic sets. Declarations never change (a set can't
    // be redeclared with other properties), and they're flushed so new rates apply at once.
    let rl_sets: String = (0..limits.len())
        .flat_map(|i| [(i, 4, "ipv4_addr"), (i, 6, "ipv6_addr")])
        .map(|(i, v, ty)| format!("\tset rl{i}_{v} {{ type {ty}; flags dynamic, timeout; size 65536; timeout 2h; }}\n"))
        .collect();
    let mut s = format!(
        "table inet {table} {{\n\
         \tset ban4 {{ type ipv4_addr; flags interval, timeout; }}\n\
         \tset ban6 {{ type ipv6_addr; flags interval, timeout; }}\n\
         \tset allow4 {{ type ipv4_addr; flags interval; }}\n\
         \tset allow6 {{ type ipv6_addr; flags interval; }}\n\
         \tset oper4 {{ type ipv4_addr; flags interval, timeout; }}\n\
         \tset oper6 {{ type ipv6_addr; flags interval, timeout; }}\n\
         \tset feed4 {{ type ipv4_addr; flags interval; }}\n\
         \tset feed6 {{ type ipv6_addr; flags interval; }}\n\
         {rl_sets}\
         \tchain pre {{ type filter hook prerouting priority raw; policy accept; }}\n\
         \tchain rl {{ type filter hook prerouting priority mangle; policy accept; }}\n\
         }}\n\
         flush chain inet {table} pre\n\
         flush chain inet {table} rl\n\
         flush set inet {table} allow4\n\
         flush set inet {table} allow6\n"
    );
    for (set, nets) in [("allow4", &a4), ("allow6", &a6)] {
        if !nets.is_empty() {
            let list: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            s += &format!("add element inet {table} {set} {{ {} }}\n", list.join(", "));
        }
    }
    s += &format!(
        "add rule inet {table} pre ip saddr @allow4 accept\n\
         add rule inet {table} pre ip6 saddr @allow6 accept\n\
         add rule inet {table} pre ip saddr @oper4 accept\n\
         add rule inet {table} pre ip6 saddr @oper6 accept\n"
    );
    for m in dport_matches(open_ports) {
        s += &format!("add rule inet {table} pre {m} accept\n");
    }
    s += &format!(
        "add rule inet {table} pre ip saddr @feed4 counter drop\n\
         add rule inet {table} pre ip6 saddr @feed6 counter drop\n\
         add rule inet {table} pre ip saddr @ban4 counter drop\n\
         add rule inet {table} pre ip6 saddr @ban6 counter drop\n"
    );
    if !limits.is_empty() {
        for set in ["allow4", "oper4"] {
            s += &format!("add rule inet {table} rl ip saddr @{set} accept\n");
        }
        for set in ["allow6", "oper6"] {
            s += &format!("add rule inet {table} rl ip6 saddr @{set} accept\n");
        }
    }
    for (i, l) in limits.iter().enumerate() {
        s += &format!("flush set inet {table} rl{i}_4\nflush set inet {table} rl{i}_6\n");
        let limit = format!("limit rate over {} burst {} packets", l.rate, l.burst);
        for m in dport_matches(&l.ports) {
            for (v, addr) in [(4, "ip saddr"), (6, "ip6 saddr")] {
                s += &format!(
                    "add rule inet {table} rl {m} ct state new update @rl{i}_{v} {{ {addr} {limit} }} counter drop comment \"{RL_COMMENT} {i}\"\n"
                );
            }
        }
    }
    s
}

/// Packets dropped per `[[ratelimit]]` entry so far, from the live ruleset (index, packets).
pub fn rate_limit_drops(nft: &std::path::Path, table: &str) -> Result<Vec<(usize, u64)>> {
    let mut cmd = Command::new(nft);
    cmd.args(["list", "chain", "inet", table, "rl"]);
    let out = crate::proc::run(cmd, None, FIREWALL_TIMEOUT).map_err(anyhow::Error::msg)?;
    if !out.status.success() {
        bail!("nft: {}", out.complaint());
    }
    Ok(parse_rate_limit_drops(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_rate_limit_drops(listing: &str) -> Vec<(usize, u64)> {
    let mut drops: BTreeMap<usize, u64> = BTreeMap::new();
    for line in listing.lines() {
        let idx = line.split_once(&format!("comment \"{RL_COMMENT} ")).and_then(|(_, r)| r.trim_end_matches('"').parse::<usize>().ok());
        let packets = line.split_once("counter packets ").and_then(|(_, r)| r.split_whitespace().next()?.parse::<u64>().ok());
        if let (Some(i), Some(p)) = (idx, packets) {
            *drops.entry(i).or_default() += p;
        }
    }
    drops.into_iter().collect()
}

/// Replaces the blocklist-feed sets atomically (one nft transaction).
pub fn nft_feeds_script(table: &str, nets: &[Net]) -> String {
    let mut s = format!("flush set inet {table} feed4\nflush set inet {table} feed6\n");
    for (set, v4) in [("feed4", true), ("feed6", false)] {
        let list: Vec<String> = nets.iter().filter(|n| n.is_v4() == v4).map(|n| n.to_string()).collect();
        for chunk in list.chunks(2000) {
            s += &format!("add element inet {table} {set} {{ {} }}\n", chunk.join(", "));
        }
    }
    s
}

pub fn nft_allow_script(table: &str, net: &Net, timeout_secs: i64) -> String {
    let set = if net.is_v4() { "oper4" } else { "oper6" };
    format!("add element inet {table} {set} {{ {net} timeout {}s }}\n", timeout_secs.max(1))
}

pub fn nft_add_script(table: &str, net: &Net, timeout_secs: i64) -> String {
    format!("add element inet {table} {} {{ {net} timeout {}s }}\n", set_name(net), timeout_secs.max(1))
}

pub fn nft_delete_script(table: &str, net: &Net) -> String {
    format!("delete element inet {table} {} {{ {net} }}\n", set_name(net))
}

impl Enforcer {
    pub fn shadow() -> Self {
        Enforcer {
            kind: Kind::Shadow,
            nft_error: None,
            nft: PathBuf::new(),
            ufw: PathBuf::new(),
            iptables: PathBuf::new(),
            ip6tables: PathBuf::new(),
            chain: String::new(),
            table: String::new(),
            setup: String::new(),
            allow: vec![],
            extra_allow: vec![],
            open_ports: vec![],
            limits: vec![],
        }
    }

    /// Picks and initialises a backend. Never fails: falls back to shadow with a warning.
    /// `extra_allow` adds runtime-protected networks (cluster peers) to the allowlist.
    pub fn new(cfg: &Config, extra_allow: &[Net]) -> Self {
        let mut e = Enforcer {
            kind: Kind::Shadow,
            nft_error: None,
            nft: cfg.enforce.nft.clone(),
            ufw: cfg.enforce.ufw.clone(),
            iptables: cfg.enforce.iptables.clone(),
            ip6tables: cfg.enforce.ip6tables.clone(),
            chain: cfg.enforce.iptables_chain.clone(),
            table: cfg.enforce.nft_table.clone(),
            setup: String::new(),
            allow: cfg.allowlist.nets.clone(),
            extra_allow: extra_allow.to_vec(),
            open_ports: cfg.ports.whitelist.clone(),
            limits: cfg.ratelimit.clone(),
        };
        e.setup = e.setup_script(extra_allow);
        if cfg.mode == Mode::Shadow {
            return e;
        }
        let try_nft = matches!(cfg.enforce.backend, Backend::Auto | Backend::Nft);
        let try_ufw = matches!(cfg.enforce.backend, Backend::Auto | Backend::Ufw);
        let try_ipt = matches!(cfg.enforce.backend, Backend::Auto | Backend::Iptables);
        if try_nft {
            match e.run_nft(&e.setup) {
                Ok(()) => {
                    e.kind = Kind::Nft;
                    return e;
                }
                Err(err) => {
                    eprintln!("logguard: nftables setup failed: {err:#}");
                    e.nft_error = Some(format!("{err:#}"));
                }
            }
        }
        // auto: ufw only where it is installed, so a host with plain iptables gets iptables
        if try_ufw && (cfg.enforce.backend == Backend::Ufw || e.ufw.exists()) {
            match e.run_ufw(&["status"]) {
                Ok(()) => {
                    if !cfg.ratelimit.is_empty() {
                        eprintln!("logguard: WARNING [[ratelimit]] needs nftables; not applied with the ufw fallback");
                    }
                    if !cfg.ports.whitelist.is_empty() {
                        eprintln!(
                            "logguard: WARNING ufw fallback cannot keep whitelisted ports open for banned addresses, \
                             and does not affect ports published by Docker"
                        );
                    }
                    e.kind = Kind::Ufw;
                    return e;
                }
                Err(err) => eprintln!("logguard: ufw unavailable: {err:#}"),
            }
        }
        if try_ipt {
            match e.ipt_setup(true, extra_allow) {
                Ok(()) => {
                    if !cfg.ratelimit.is_empty() {
                        eprintln!("logguard: WARNING [[ratelimit]] needs nftables; not applied with iptables");
                    }
                    e.kind = Kind::Iptables;
                    return e;
                }
                Err(err) => eprintln!("logguard: iptables setup failed: {err:#}"),
            }
        }
        eprintln!("logguard: WARNING no usable firewall backend, running in shadow mode");
        e
    }

    /// The nftables setup with the configured allowlist plus `extra_allow`.
    fn setup_script(&self, extra_allow: &[Net]) -> String {
        nft_setup_script(&self.table, &self.allowlist(extra_allow), &self.open_ports, &self.limits)
    }

    /// New runtime-protected networks (cluster peers re-resolved): the allowlist sets are
    /// reloaded; bans, feeds and operator entries stay. Rate-limit counters start over.
    pub fn set_extra_allow(&mut self, extra_allow: &[Net]) -> Result<()> {
        self.setup = self.setup_script(extra_allow);
        self.extra_allow = extra_allow.to_vec();
        match self.kind {
            Kind::Nft => self.run_nft(&self.setup),
            Kind::Iptables => self.ipt_setup(false, extra_allow),
            Kind::Ufw | Kind::Shadow => Ok(()),
        }
    }

    /// The configured allowlist plus `extra_allow`.
    fn allowlist(&self, extra_allow: &[Net]) -> Vec<Net> {
        let mut allow = self.allow.clone();
        for n in extra_allow {
            if !allow.contains(n) {
                allow.push(*n);
            }
        }
        allow
    }

    fn run_ipt(&self, (v6, args): &IptCmd) -> Result<()> {
        let mut cmd = Command::new(if *v6 { &self.ip6tables } else { &self.iptables });
        cmd.args(["-w", "10", "-t", "raw"]).args(args);
        let out = crate::proc::run(cmd, None, FIREWALL_TIMEOUT).map_err(anyhow::Error::msg)?;
        if !out.status.success() {
            bail!("{} {}: {}", if *v6 { "ip6tables" } else { "iptables" }, args.join(" "), out.complaint());
        }
        Ok(())
    }

    /// Creates logguard's chains (if missing) and loads the static rules; `fresh` also
    /// empties the ban chain, to be refilled from the saved state. The jump from PREROUTING
    /// goes in last, so traffic never meets a half-built chain.
    fn ipt_setup(&self, fresh: bool, extra_allow: &[Net]) -> Result<()> {
        let ban_chain = format!("{}-ban", self.chain);
        for v6 in [false, true] {
            for c in [&self.chain, &ban_chain] {
                // "Chain already exists" is fine
                let _ = self.run_ipt(&ipt(v6, &["-N", c]));
            }
            if fresh {
                self.run_ipt(&ipt(v6, &["-F", &ban_chain]))?;
            }
        }
        for cmd in iptables_static_rules(&self.chain, &self.allowlist(extra_allow), &self.open_ports) {
            self.run_ipt(&cmd)?;
        }
        for v6 in [false, true] {
            if self.run_ipt(&ipt(v6, &["-C", "PREROUTING", "-j", &self.chain])).is_err() {
                self.run_ipt(&ipt(v6, &["-I", "PREROUTING", "1", "-j", &self.chain]))?;
            }
        }
        Ok(())
    }

    /// Adds a rule unless it is there already (`add` is `cmd` with `-A`/`-I`).
    fn ipt_ensure(&self, check: IptCmd, add: IptCmd) -> Result<()> {
        if self.run_ipt(&check).is_ok() {
            return Ok(());
        }
        self.run_ipt(&add)
    }

    /// Deletes a rule if it is there.
    fn ipt_drop(&self, check: IptCmd, delete: IptCmd) -> Result<()> {
        if self.run_ipt(&check).is_err() {
            return Ok(());
        }
        self.run_ipt(&delete)
    }

    pub fn name(&self) -> &'static str {
        match self.kind {
            Kind::Shadow => "shadow",
            Kind::Nft => "nftables",
            Kind::Ufw => "ufw",
            Kind::Iptables => "iptables",
        }
    }

    fn run_nft(&self, script: &str) -> Result<()> {
        let mut cmd = Command::new(&self.nft);
        cmd.args(["-f", "-"]);
        let out = crate::proc::run(cmd, Some(script.as_bytes()), FIREWALL_TIMEOUT).map_err(anyhow::Error::msg)?;
        if !out.status.success() {
            bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    fn run_ufw(&self, args: &[&str]) -> Result<()> {
        let mut cmd = Command::new(&self.ufw);
        cmd.args(args);
        let out = crate::proc::run(cmd, None, FIREWALL_TIMEOUT).map_err(anyhow::Error::msg)?;
        if !out.status.success() {
            bail!("ufw {}: {}", args.join(" "), out.complaint());
        }
        Ok(())
    }

    fn add(&self, net: &Net, until: Micros, now: Micros, reason: &str) -> Result<()> {
        match self.kind {
            Kind::Shadow => Ok(()),
            Kind::Nft => self.run_nft(&nft_add_script(&self.table, net, (until - now) / SEC)),
            Kind::Ufw => {
                let comment: String =
                    format!("logguard {reason}").chars().filter(|c| c.is_ascii_alphanumeric() || " ._:/=-".contains(*c)).take(60).collect();
                self.run_ufw(&["prepend", "deny", "from", &net.to_string(), "comment", &comment])
            }
            Kind::Iptables => self.ipt_ensure(iptables_ban_rule(&self.chain, net, "-C"), iptables_ban_rule(&self.chain, net, "-A")),
        }
    }

    fn remove(&self, net: &Net) -> Result<()> {
        match self.kind {
            Kind::Shadow => Ok(()),
            Kind::Nft => self.run_nft(&nft_delete_script(&self.table, net)),
            Kind::Ufw => self.run_ufw(&["delete", "deny", "from", &net.to_string()]),
            Kind::Iptables => self.ipt_drop(iptables_ban_rule(&self.chain, net, "-C"), iptables_ban_rule(&self.chain, net, "-D")),
        }
    }

    /// Applies a ban/unban decision; sets `applied` on success.
    pub fn apply(&self, a: &mut Action) {
        if self.kind == Kind::Shadow {
            return;
        }
        let Some(net) = a.target else { return };
        let result = match a.kind {
            ActionKind::Ban => {
                for old in &a.superseded {
                    // Already-expired elements make delete fail; that's fine.
                    let _ = self.remove(old);
                }
                // While catching up on history, a.ts lies in the past: the kernel gets only the
                // time actually left, and a ban that has already ended isn't added at all.
                let now = crate::time::now().max(a.ts);
                let until = a.until.unwrap_or(a.ts + 3600 * SEC);
                if until <= now {
                    return;
                }
                self.add(&net, until, now, &a.message)
            }
            ActionKind::Unban => self.remove(&net).or_else(|e| {
                // For nft the kernel may already have expired the element.
                if self.kind == Kind::Nft {
                    Ok(())
                } else {
                    Err(e)
                }
            }),
            ActionKind::Allow => match self.kind {
                Kind::Nft => self.run_nft(&nft_allow_script(&self.table, &net, (a.until.unwrap_or(a.ts) - a.ts) / SEC)),
                Kind::Ufw => self.run_ufw(&["prepend", "allow", "from", &net.to_string(), "comment", "logguard operator allow"]),
                Kind::Iptables => {
                    self.ipt_ensure(iptables_allow_rule(&self.chain, &net, "-C"), iptables_allow_rule(&self.chain, &net, "-I"))
                }
                Kind::Shadow => Ok(()),
            },
            ActionKind::Disallow => match self.kind {
                Kind::Nft => {
                    let set = if net.is_v4() { "oper4" } else { "oper6" };
                    // Already gone if the kernel timed it out.
                    let _ = self.run_nft(&format!("delete element inet {} {set} {{ {net} }}\n", self.table));
                    Ok(())
                }
                Kind::Ufw => self.run_ufw(&["delete", "allow", "from", &net.to_string()]),
                Kind::Iptables => self.ipt_drop(iptables_allow_rule(&self.chain, &net, "-C"), iptables_allow_rule(&self.chain, &net, "-D")),
                Kind::Shadow => Ok(()),
            },
            ActionKind::Alert => return,
        };
        match result {
            Ok(()) => a.applied = true,
            Err(e) => eprintln!("logguard: failed to apply '{}': {e:#}", a.message),
        }
    }

    /// Verifies the nftables table still exists (e.g. `systemctl restart nftables` runs
    /// `flush ruleset`) and rebuilds it with all active bans if not. Returns what happened.
    /// Whether our nftables chain still exists (always true for other backends).
    pub fn table_present(&self) -> bool {
        if self.kind == Kind::Iptables {
            // the jump from PREROUTING and, at the end of our chain, the one to the bans
            let ban_chain = format!("{}-ban", self.chain);
            return [false, true].into_iter().all(|v6| {
                self.run_ipt(&ipt(v6, &["-C", "PREROUTING", "-j", &self.chain])).is_ok()
                    && self.run_ipt(&ipt(v6, &["-C", &self.chain, "-j", &ban_chain])).is_ok()
            });
        }
        if self.kind != Kind::Nft {
            return true;
        }
        let mut cmd = Command::new(&self.nft);
        cmd.args(["list", "chain", "inet", &self.table, "pre"]);
        // a timed-out check says "present": rebuilding on a busy kernel would make it worse
        crate::proc::run(cmd, None, FIREWALL_TIMEOUT).map_or(true, |o| o.status.success())
    }

    /// Rebuilds a missing table with all active bans, allowlist entries and feeds.
    pub fn heal(&self, bans: &[Ban], allows: &[crate::engine::OperAllow], feeds: &[Net], now: Micros) -> Option<String> {
        if self.table_present() {
            return None;
        }
        if self.kind == Kind::Iptables {
            return Some(match self.ipt_setup(true, &self.extra_allow) {
                Ok(()) => {
                    self.restore(bans, now);
                    self.restore_allows(allows, now);
                    format!(
                        "iptables chain {} in the raw table had been removed or emptied (e.g. a firewall reload); rebuilt it and restored {} bans",
                        self.chain,
                        bans.iter().filter(|b| b.until > now).count()
                    )
                }
                Err(e) => format!("iptables chain {} is missing and could not be rebuilt: {e:#}", self.chain),
            });
        }
        Some(match self.run_nft(&self.setup) {
            Ok(()) => {
                self.restore(bans, now);
                self.restore_allows(allows, now);
                if !feeds.is_empty() {
                    let _ = self.load_feeds(feeds);
                }
                format!(
                    "nftables table inet {} had been removed (e.g. `nft flush ruleset` / nftables restart); rebuilt it and restored {} bans",
                    self.table,
                    bans.iter().filter(|b| b.until > now).count()
                )
            }
            Err(e) => format!("nftables table inet {} is missing and could not be rebuilt: {e:#}", self.table),
        })
    }

    /// Loads blocklist feeds (nftables only). Returns whether they are now active.
    pub fn load_feeds(&self, nets: &[Net]) -> Result<bool> {
        match self.kind {
            Kind::Nft => self.run_nft(&nft_feeds_script(&self.table, nets)).map(|()| !nets.is_empty()),
            Kind::Ufw | Kind::Iptables | Kind::Shadow => Ok(false),
        }
    }

    /// Re-adds operator allowlist entries from saved state.
    pub fn restore_allows(&self, allows: &[crate::engine::OperAllow], now: Micros) {
        if self.kind == Kind::Iptables {
            for a in allows.iter().filter(|a| a.until > now) {
                let (check, add) = (iptables_allow_rule(&self.chain, &a.net, "-C"), iptables_allow_rule(&self.chain, &a.net, "-I"));
                if let Err(e) = self.ipt_ensure(check, add) {
                    eprintln!("logguard: restoring allowlist entry {}: {e:#}", a.net);
                }
            }
            return;
        }
        let items: Vec<(String, String)> = allows
            .iter()
            .filter(|a| a.until > now)
            .map(|a| (a.net.to_string(), nft_allow_script(&self.table, &a.net, (a.until - now) / SEC)))
            .collect();
        self.run_batch("allowlist entry", items);
    }

    /// Runs many one-line nft commands in one transaction; if that fails (e.g. one
    /// conflicting element), falls back to one by one so the rest still apply.
    fn run_batch(&self, what: &str, items: Vec<(String, String)>) {
        if self.kind != Kind::Nft || items.is_empty() {
            return;
        }
        for chunk in items.chunks(1000) {
            let script: String = chunk.iter().map(|(_, line)| line.as_str()).collect();
            if self.run_nft(&script).is_ok() {
                continue;
            }
            for (name, line) in chunk {
                if let Err(e) = self.run_nft(line) {
                    eprintln!("logguard: restoring {what} {name}: {e:#}");
                }
            }
        }
    }

    /// Re-adds bans from saved state (nft sets don't survive a reboot).
    pub fn restore(&self, bans: &[Ban], now: Micros) {
        if self.kind == Kind::Iptables {
            for b in bans.iter().filter(|b| b.until > now) {
                if let Err(e) = self.add(&b.net, b.until, now, "") {
                    eprintln!("logguard: restoring ban {}: {e:#}", b.net);
                }
            }
            return;
        }
        let items: Vec<(String, String)> = bans
            .iter()
            .filter(|b| b.until > now)
            .map(|b| (b.net.to_string(), nft_add_script(&self.table, &b.net, (b.until - now) / SEC)))
            .collect();
        self.run_batch("ban", items);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts() {
        let allow: Vec<Net> = vec!["11.35.43.31".parse().unwrap(), "2001:db8::/32".parse().unwrap()];
        let ports: Vec<PortSpec> = ["51820/udp", "51821/tcp", "443"].iter().map(|p| p.parse().unwrap()).collect();
        let s = nft_setup_script("logguard", &allow, &ports, &[]);
        assert!(s.contains("hook prerouting priority raw"));
        assert!(s.contains("add rule inet logguard pre tcp dport { 443, 51821 } accept"));
        assert!(s.contains("add rule inet logguard pre udp dport { 443, 51820 } accept"));
        let accept = s.find("dport").unwrap();
        assert!(accept < s.find("@ban4 counter drop").unwrap(), "whitelisted ports are accepted before bans drop");
        assert!(!nft_setup_script("t", &[], &[], &[]).contains("dport"));
        // order: allowlists accept, then feeds drop, then bans drop
        let pos = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(pos("@oper4 accept") < pos("@feed4 counter drop"));
        assert!(pos("@feed4 counter drop") < pos("@ban4 counter drop"));
        let feeds = nft_feeds_script("logguard", &["11.1.16.0/20".parse().unwrap(), "3fff:110::/29".parse().unwrap()]);
        assert_eq!(
            feeds,
            "flush set inet logguard feed4\nflush set inet logguard feed6\nadd element inet logguard feed4 { 11.1.16.0/20 }\nadd element inet logguard feed6 { 3fff:110::/29 }\n"
        );
        assert_eq!(nft_allow_script("t", &"8.8.8.8".parse().unwrap(), 60), "add element inet t oper4 { 8.8.8.8 timeout 60s }\n");
        assert!(s.contains("add element inet logguard allow4 { 11.35.43.31 }"));
        assert!(s.contains("add element inet logguard allow6 { 2001:db8::/32 }"));
        // the host's own 127.0.0.1 next to the configured 127.0.0.0/8 must not break the set
        let overlapping: Vec<Net> = ["127.0.0.0/8", "127.0.0.1", "11.35.43.31"].iter().map(|n| n.parse().unwrap()).collect();
        assert!(nft_setup_script("t", &overlapping, &[], &[]).contains("add element inet t allow4 { 127.0.0.0/8, 11.35.43.31 }"));
        let net: Net = "11.11.59.0/24".parse().unwrap();
        assert_eq!(nft_add_script("logguard", &net, 3600), "add element inet logguard ban4 { 11.11.59.0/24 timeout 3600s }\n");
        let v6: Net = "2001:db8::1".parse().unwrap();
        assert_eq!(nft_delete_script("t", &v6), "delete element inet t ban6 { 2001:db8::1 }\n");
    }

    #[test]
    fn iptables_rules() {
        let allow: Vec<Net> = ["11.35.43.31", "127.0.0.0/8", "127.0.0.1", "2001:db8::/32"].iter().map(|n| n.parse().unwrap()).collect();
        let ports: Vec<PortSpec> = ["51820/udp", "443"].iter().map(|p| p.parse().unwrap()).collect();
        let lines: Vec<String> = iptables_static_rules("logguard", &allow, &ports)
            .iter()
            .map(|(v6, args)| format!("{} {}", if *v6 { "ip6tables" } else { "iptables" }, args.join(" ")))
            .collect();
        assert_eq!(
            lines,
            [
                "iptables -F logguard",
                "iptables -A logguard -s 127.0.0.0/8 -j RETURN",
                "iptables -A logguard -s 11.35.43.31 -j RETURN",
                "iptables -A logguard -p tcp -m multiport --dports 443 -j RETURN",
                "iptables -A logguard -p udp -m multiport --dports 443,51820 -j RETURN",
                "iptables -A logguard -j logguard-ban",
                "ip6tables -F logguard",
                "ip6tables -A logguard -s 2001:db8::/32 -j RETURN",
                "ip6tables -A logguard -p tcp -m multiport --dports 443 -j RETURN",
                "ip6tables -A logguard -p udp -m multiport --dports 443,51820 -j RETURN",
                "ip6tables -A logguard -j logguard-ban",
            ]
        );
        // multiport takes 15 ports per rule
        let many: Vec<PortSpec> = (1..=20).map(|p| format!("{p}/tcp").parse().unwrap()).collect();
        let rules = iptables_static_rules("c", &[], &many);
        assert_eq!(rules.iter().filter(|(v6, a)| !v6 && a.contains(&"multiport".to_string())).count(), 2);

        let v4: Net = "11.11.59.0/24".parse().unwrap();
        let v6: Net = "2001:db8::1".parse().unwrap();
        assert_eq!(
            iptables_ban_rule("logguard", &v4, "-A"),
            (false, ["-A", "logguard-ban", "-s", "11.11.59.0/24", "-j", "DROP"].iter().map(|s| s.to_string()).collect())
        );
        assert!(iptables_ban_rule("logguard", &v6, "-D").0, "IPv6 goes to ip6tables");
        let top = iptables_allow_rule("logguard", &v4, "-I").1;
        assert_eq!(top, ["-I", "logguard-ban", "1", "-s", "11.11.59.0/24", "-j", "RETURN"], "operator allows above the bans");
        assert_eq!(iptables_allow_rule("logguard", &v4, "-D").1, ["-D", "logguard-ban", "-s", "11.11.59.0/24", "-j", "RETURN"]);
    }

    #[test]
    fn rate_limits() {
        let limits = vec![
            RateLimitCfg { ports: vec!["5222/tcp".parse().unwrap(), "5223/tcp".parse().unwrap()], rate: "30/minute".into(), burst: 30 },
            RateLimitCfg { ports: vec!["3478".parse().unwrap()], rate: "10/second".into(), burst: 10 },
        ];
        let s = nft_setup_script("t", &[], &[], &limits);
        assert!(s.contains("chain rl { type filter hook prerouting priority mangle; policy accept; }"));
        assert!(s.contains("set rl1_6 { type ipv6_addr; flags dynamic, timeout; size 65536; timeout 2h; }"));
        assert!(s.contains(
            "add rule inet t rl tcp dport { 5222, 5223 } ct state new update @rl0_4 { ip saddr limit rate over 30/minute burst 30 packets } counter drop comment \"logguard ratelimit 0\"\n"
        ));
        assert!(s.contains(
            "add rule inet t rl udp dport { 3478 } ct state new update @rl1_6 { ip6 saddr limit rate over 10/second burst 10 packets }"
        ));
        let pos = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(pos("rl ip saddr @allow4 accept") < pos("update @rl0_4"), "allowlisted sources are exempt");
        // no limits: the chain still exists (and is flushed), but has no rules
        let none = nft_setup_script("t", &[], &[], &[]);
        assert!(none.contains("flush chain inet t rl") && !none.contains("add rule inet t rl"));

        let listing = r#"table inet logguard {
	chain rl {
		type filter hook prerouting priority mangle; policy accept;
		ip saddr @allow4 accept
		tcp dport { 5222, 5223 } ct state new update @rl0_4 { ip saddr limit rate over 30/minute burst 30 packets } counter packets 12 bytes 720 drop comment "logguard ratelimit 0"
		tcp dport { 5222, 5223 } ct state new update @rl0_6 { ip6 saddr limit rate over 30/minute burst 30 packets } counter packets 3 bytes 240 drop comment "logguard ratelimit 0"
		udp dport 3478 ct state new update @rl1_4 { ip saddr limit rate over 10/second burst 10 packets } counter packets 0 bytes 0 drop comment "logguard ratelimit 1"
	}
}"#;
        assert_eq!(parse_rate_limit_drops(listing), vec![(0, 15), (1, 0)]);
    }
}
