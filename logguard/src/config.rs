//! Configuration (TOML). Every field has a default, so an empty file is valid;
//! `logguard print-config` dumps the effective configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::event::{Proto, Signal};
use crate::net::Net;
use crate::record::Source;
use crate::time::Dur;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Detect and log what would be done; never touch the firewall.
    Shadow,
    Enforce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// nftables, falling back to firewalld (where it runs), UFW, then iptables, if nftables
    /// can't be set up.
    Auto,
    Nft,
    /// firewalld's own objects (Fedora, RHEL): ipsets bound to a drop zone of logguard's.
    Firewalld,
    Ufw,
    /// iptables and ip6tables (legacy or nf_tables flavour; works next to
    /// iptables-persistent): a chain of our own in the mangle table's PREROUTING.
    Iptables,
    /// iptables chains as with `iptables`, matching ipset sets: bans expire in the kernel and
    /// blocklist feeds work, with one rule however many addresses.
    Ipset,
}

/// The host's package manager: whose database the package checks read (`[cron]` origins,
/// `[verify]`) and which tool lists pending updates (`[patches]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    /// dpkg and apt: Debian, Ubuntu.
    #[default]
    #[serde(alias = "dpkg")]
    Apt,
    /// rpm and dnf: Fedora, RHEL and its rebuilds (AlmaLinux, Rocky).
    #[serde(alias = "rpm")]
    Dnf,
}

impl PackageManager {
    /// The package database, as alerts name it.
    pub fn db(self) -> &'static str {
        match self {
            PackageManager::Apt => "dpkg",
            PackageManager::Dnf => "rpm",
        }
    }

    pub fn upgrade_command(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt upgrade",
            PackageManager::Dnf => "dnf upgrade",
        }
    }

    pub fn reinstall_command(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt install --reinstall <package>",
            PackageManager::Dnf => "dnf reinstall <package>",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    /// "apt" (dpkg's database) or "dnf" (rpm's).
    pub package_manager: PackageManager,
    pub sources: SourcesCfg,
    pub ports: PortsCfg,
    pub state_file: PathBuf,
    pub socket: PathBuf,
    /// JSON-lines audit log of every ban/unban/alert decision.
    pub actions_log: Option<PathBuf>,
    pub journal: JournalCfg,
    pub allowlist: AllowCfg,
    pub xmpp: XmppCfg,
    pub scoring: ScoringCfg,
    pub accounts: AccountCfg,
    pub subnets: SubnetCfg,
    pub bans: BanCfg,
    pub enforce: EnforceCfg,
    pub notify: crate::notify::NotifyCfg,
    pub exposure: crate::exposure::ExposureCfg,
    pub cluster: crate::cluster::ClusterCfg,
    /// The read-only socket for logguard-web, the web console.
    pub console: crate::console::ConsoleCfg,
    /// Where Nextcloud AIO's logs are (`[nextcloud_aio]`; `[nextcloud]` until 2026-10-26).
    #[serde(alias = "nextcloud")]
    pub nextcloud_aio: NextcloudCfg,
    pub feeds: crate::feeds::FeedsCfg,
    /// Addresses WAFs and other security apps block (CrowdSec, ...), enforced here.
    pub waf: crate::waf::WafCfg,
    pub digest: crate::digest::DigestCfg,
    pub canary: CanaryCfg,
    pub silence: SilenceCfg,
    /// Per-source connection rate limits in the kernel (nftables only).
    pub ratelimit: Vec<RateLimitCfg>,
    /// Offline country / network-owner labels for addresses.
    pub geo: crate::geo::GeoCfg,
    /// Whole countries or networks (ASNs) dropped, by the `[geo]` databases.
    pub geoblock: crate::geo::GeoblockCfg,
    /// New or changed cron jobs, systemd timers and the scripts they run.
    pub cron: crate::cronwatch::CronCfg,
    /// Results of scheduled ClamAV scans.
    pub antivirus: crate::avscan::AvCfg,
    /// Low disk space and sustained memory shortage.
    pub resources: crate::resources::ResourcesCfg,
    /// Pending updates, a newer kernel than the running one, services still running replaced
    /// libraries: in the daily digest.
    pub patches: crate::patches::PatchesCfg,
    /// Package binaries checked against dpkg's checksums, and the set-uid programs (weekly).
    pub verify: crate::verify::VerifyCfg,
    /// New outbound connections and programs running from temporary or deleted files.
    pub procwatch: crate::procwatch::ProcCfg,
    /// sshd's effective settings checked against good practice and this host's layout
    /// (plain VPS, hosting panel, or a harden-vps.sh-style gateway).
    pub ssh_audit: crate::sshaudit::SshAuditCfg,
    /// Log lines of your own to score (`[[patterns]]`).
    pub patterns: Vec<crate::parse::custom::PatternCfg>,
    /// The built-in patterns of `[sources] apps`, where their logs are on this host.
    #[serde(skip)]
    pub app_patterns: Vec<crate::parse::custom::PatternCfg>,
    /// Where each of their logs is, one line each, for the daemon's start.
    #[serde(skip)]
    pub app_logs_found: Vec<String>,
}

/// Which logs to analyse. Disable ejabberd on hosts without an XMPP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SourcesCfg {
    pub ejabberd: bool,
    pub ssh: bool,
    pub ufw: bool,
    /// Nextcloud AIO: probes in Apache's error log and failed logins (see `[nextcloud_aio]`). A
    /// Nextcloud without AIO is an app (`apps = ["nextcloud"]`). Called `nextcloud` until
    /// 2026-10-26, which is still read.
    #[serde(alias = "nextcloud")]
    pub nextcloud_aio: bool,
    /// Alert when the kernel kills a process for lack of memory (from the kernel log).
    pub oom: bool,
    /// `su` and `sudo`: failed attempts (someone holds an account's key or password) and
    /// switches after them, as alerts.
    pub privilege: bool,
    /// PAM and the account tools: failed logins at the console, a desktop, polkit or Cockpit
    /// (alerts), failed logins from the internet at services without a parser of their own
    /// (scored), locked accounts, changed passwords, new accounts and admin group members.
    pub pam: bool,
    /// The audit log (the journal's audit records, or `audit_log`): the same changes as
    /// the kernel records them, auditd stopped or auditing switched off, and `audit_keys`.
    pub audit: bool,
    /// auditd's log file, instead of the journal's audit records (for a journald with
    /// `Audit=no`); empty: the journal.
    pub audit_log: PathBuf,
    /// Audit rule keys (`auditctl -k identity`) to alert about when one of their rules
    /// fires; `"*"` for every key.
    pub audit_keys: Vec<String>,
    /// systemd services to alert about when they fail (any unsuccessful end: a non-zero
    /// exit, a signal, a timeout, ...) and are not started again within
    /// `service_restart_grace`, or when systemd gives up restarting them. E.g.
    /// `["logguard-xmpp-bot.service"]` (exit 78 there: a wrong password or setting).
    pub services: Vec<String>,
    /// How long after a failure systemd (`Restart=`, after `RestartSec`) or anyone else may
    /// start the service again before it counts as down.
    pub service_restart_grace: Dur,
    /// Built-in sources for common services (`parse::apps`): "apache", "nginx", "haproxy",
    /// "prosody", "nextcloud" (without AIO), "owncloud" (10), "mysql" (MariaDB too),
    /// "postgresql", "mongodb", "redis" (Valkey, KeyDB too), "postfix", "dovecot".
    pub apps: Vec<String>,
    /// Where an app's log is when not in the usual places: `nginx_access = ["/srv/a.log"]`
    /// (absolute paths, `*` in a file name) or `mysql = "mariadb.service"` (its journal).
    pub app_logs: BTreeMap<String, crate::parse::apps::Logs>,
    /// Points of a built-in pattern instead of its default: `nginx_limit = 0`.
    pub app_weights: BTreeMap<String, f64>,
}

impl Default for SourcesCfg {
    fn default() -> Self {
        SourcesCfg {
            ejabberd: true,
            ssh: true,
            ufw: true,
            nextcloud_aio: false,
            oom: true,
            privilege: true,
            pam: true,
            audit: true,
            audit_log: PathBuf::new(),
            audit_keys: vec![],
            services: vec![],
            service_restart_grace: Dur(120),
            apps: vec![],
            app_logs: BTreeMap::new(),
            app_weights: BTreeMap::new(),
        }
    }
}

impl SourcesCfg {
    pub fn enabled(&self, s: Source) -> bool {
        match s {
            Source::Ejabberd => self.ejabberd,
            Source::Ssh => self.ssh,
            Source::Ufw => self.ufw,
            Source::Peer => true,
            Source::Nextcloud => self.nextcloud_aio,
            Source::Kernel => self.oom,
            Source::Systemd => !self.services.is_empty(),
            Source::Privilege => self.privilege,
            Source::Auth => self.pam,
            Source::Audit => self.audit,
            // only lines a pattern of your own matches count (`parse::custom`)
            Source::Custom => true,
        }
    }
}

/// A local port, optionally restricted to one protocol: `51820/udp`, `51821/tcp`, `443`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortSpec {
    pub port: u16,
    /// `None` = TCP and UDP.
    pub proto: Option<Proto>,
}

impl PortSpec {
    pub fn matches(&self, port: u16, proto: Proto) -> bool {
        self.port == port && self.proto.is_none_or(|p| p == proto)
    }
}

impl std::str::FromStr for PortSpec {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (port, proto) = s.trim().split_once('/').map_or((s.trim(), None), |(p, q)| (p, Some(q)));
        let port: u16 = port.parse().map_err(|_| format!("invalid port in '{s}'"))?;
        let proto = match proto.map(str::to_ascii_lowercase).as_deref() {
            None => None,
            Some("tcp") => Some(Proto::Tcp),
            Some("udp") => Some(Proto::Udp),
            Some(other) => return Err(format!("unknown protocol '{other}' in '{s}' (tcp or udp)")),
        };
        Ok(PortSpec { port, proto })
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.proto {
            Some(Proto::Tcp) => write!(f, "{}/tcp", self.port),
            Some(Proto::Udp) => write!(f, "{}/udp", self.port),
            _ => write!(f, "{}", self.port),
        }
    }
}

impl Serialize for PortSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u16),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(port) => Ok(PortSpec { port, proto: None }),
            Raw::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortsCfg {
    /// Traffic to these local ports is never scored, and in enforce mode never blocked,
    /// even from banned addresses (e.g. a WireGuard port and its admin panel).
    pub whitelist: Vec<PortSpec>,
    /// Ports nobody legitimate connects to: a single UFW-blocked packet to one scores
    /// `fw_tripwire` (default 100 = immediate ban). Only blocked traffic is logged by UFW,
    /// so a port you actually serve can never trip. Prefer TCP: UDP senders are trivially spoofed.
    pub tripwire: Vec<PortSpec>,
    /// Names for local ports in the dashboard's port histogram, e.g.
    /// `{ "51820/udp" = "WireGuard", 8443 = "Nextcloud AIO" }`. They come before the
    /// names taken from the rest of the config (`[xmpp] c2s_ports`, the cluster port)
    /// and the built-in ones (Telnet, RDP, ...).
    pub names: BTreeMap<String, String>,
    /// Log the first new TCP connection per source (every 10 minutes) to a tripwire port
    /// nothing listens on from logguard's own nftables table, at up to
    /// `kernel_tripwire_rate`, instead of relying on UFW's log, which keeps about 3 lines a
    /// minute for the whole host. nftables backend in enforce mode only.
    pub kernel_tripwires: bool,
    /// `<n>/second`, `<n>/minute` or `<n>/hour`, for the whole host.
    pub kernel_tripwire_rate: String,
    /// Ports logguard listens on itself and closes every connection at once: a completed
    /// handshake can't come from a forged address, so it scores `tripwire_connect` (default
    /// 100). With any set, a blocked SYN to a tripwire port scores 50 by default
    /// (`fw_tripwire`). TCP only; open them in the firewall (`ufw allow 2323/tcp`).
    pub honeypot: Vec<PortSpec>,
}

/// Commonly attacked services neither server runs: remote access (FTP, Telnet, Windows RPC/SMB/
/// RDP/WinRM, VNC, PPTP, router management), mail (SMTP, submission, POP3, IMAP; the domains'
/// MX records point elsewhere, so no mail server delivers here), directories, databases and caches.
pub const DEFAULT_TRIPWIRE: [&str; 32] = [
    "21/tcp",
    "23/tcp",
    "25/tcp",
    "110/tcp",
    "135/tcp",
    "139/tcp",
    "143/tcp",
    "389/tcp",
    "445/tcp",
    "465/tcp",
    "587/tcp",
    "993/tcp",
    "995/tcp",
    "1433/tcp",
    "1521/tcp",
    "1723/tcp",
    "2323/tcp",
    "2375/tcp",
    "2376/tcp",
    "3306/tcp",
    "3389/tcp",
    "5432/tcp",
    "5900/tcp",
    "5901/tcp",
    "5985/tcp",
    "5986/tcp",
    "6379/tcp",
    "7547/tcp",
    "8291/tcp",
    "9200/tcp",
    "11211/tcp",
    "27017/tcp",
];

impl Default for PortsCfg {
    fn default() -> Self {
        let tripwire = DEFAULT_TRIPWIRE.iter().map(|p| p.parse().expect("valid default")).collect();
        PortsCfg {
            whitelist: vec![],
            tripwire,
            names: BTreeMap::new(),
            kernel_tripwires: true,
            kernel_tripwire_rate: "60/minute".into(),
            honeypot: vec![],
        }
    }
}

impl PortsCfg {
    pub fn whitelisted(&self, port: Option<u16>, proto: Proto) -> bool {
        port.is_some_and(|p| self.whitelist.iter().any(|w| w.matches(p, proto)))
    }

    pub fn tripwired(&self, port: Option<u16>, proto: Proto) -> bool {
        port.is_some_and(|p| self.tripwire.iter().any(|w| w.matches(p, proto)))
    }
}

/// Canary accounts: names attackers guess but nobody legitimate uses. A login attempt on
/// one scores `*_canary` (default 100 = immediate ban), the account-level tripwire.
/// Names are matched case-insensitively; never list an account that is really used.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CanaryCfg {
    /// XMPP: a local part (`test`, any domain) or a full JID (`test@example.org`).
    /// Failed logins and in-band registrations of these names both trip.
    pub xmpp: Vec<String>,
    /// SSH user names; `"*"` = every name not listed in `except` (for key-only servers
    /// that admit exactly one user).
    pub ssh: Vec<String>,
    /// Nextcloud and ownCloud login names: for Nextcloud AIO (`[sources] nextcloud_aio`)
    /// and the apps "nextcloud" and "owncloud".
    pub nextcloud: Vec<String>,
    /// Names that are never canaries, whatever the lists above say (your real accounts).
    pub except: Vec<String>,
}

impl CanaryCfg {
    fn listed(list: &[String], name: &str, except: &[String]) -> bool {
        let name = name.trim().to_lowercase();
        let local = name.split('@').next().unwrap_or(&name);
        let excepted = except.iter().any(|e| {
            let e = e.to_lowercase();
            e == name || (!e.contains('@') && e == local)
        });
        !excepted
            && list.iter().any(|c| {
                let c = c.to_lowercase();
                c == "*" || c == name || (!c.contains('@') && c == local)
            })
    }

    /// Whether a login name on `source` is a canary.
    pub fn is_canary(&self, source: Source, name: &str) -> bool {
        let list = match source {
            Source::Ejabberd => &self.xmpp,
            Source::Ssh => &self.ssh,
            Source::Nextcloud => &self.nextcloud,
            Source::Ufw
            | Source::Peer
            | Source::Kernel
            | Source::Systemd
            | Source::Privilege
            | Source::Auth
            | Source::Audit
            | Source::Custom => return false,
        };
        !list.is_empty() && Self::listed(list, name, &self.except)
    }

    pub fn validate(&self) -> Result<()> {
        if self.xmpp.iter().chain(&self.nextcloud).any(|n| n.trim() == "*") {
            bail!("[canary]: \"*\" is only allowed for ssh");
        }
        if self.ssh.iter().any(|n| n == "*") && self.except.is_empty() {
            bail!("[canary] ssh = [\"*\"] needs your real SSH user name(s) in `except`");
        }
        Ok(())
    }
}

/// Alerts when a log source goes quiet, so "no attacks" can't be confused with "not seeing logs".
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SilenceCfg {
    pub enabled: bool,
    /// Alert when an enabled source produced no lines for this long; "0s" = never.
    /// Defaults from a month of real traffic: UFW and ejabberd were never quiet for
    /// 3 hours except during an outage, sshd sometimes was for a whole day.
    pub ejabberd: Dur,
    pub ssh: Dur,
    pub ufw: Dur,
    /// Nextcloud AIO (`nextcloud` until 2026-10-26).
    #[serde(alias = "nextcloud")]
    pub nextcloud_aio: Dur,
    /// Alert when a source keeps logging (at least `blind_lines` lines) but none of it
    /// could be tied to an address for this long: e.g. ejabberd hiding client IPs or
    /// a changed log format.
    pub blind_after: Dur,
    pub blind_lines: u64,
    /// Logs of `[sources] apps` (their keys in `[sources.app_logs]`) to alert about when no
    /// line arrives for this long: `nginx_access = "2h"`, `nextcloud = "7d"`. None by
    /// default: how long a healthy one can stay quiet depends on the service.
    pub apps: BTreeMap<String, Dur>,
}

impl Default for SilenceCfg {
    fn default() -> Self {
        SilenceCfg {
            enabled: true,
            ejabberd: Dur(6 * 3600),
            ssh: Dur(2 * 86_400),
            ufw: Dur(2 * 3600),
            nextcloud_aio: Dur(0),
            blind_after: Dur(6 * 3600),
            blind_lines: 200,
            apps: BTreeMap::new(),
        }
    }
}

impl SilenceCfg {
    pub fn quiet_after(&self, s: Source) -> Dur {
        match s {
            Source::Ejabberd => self.ejabberd,
            Source::Ssh => self.ssh,
            Source::Ufw => self.ufw,
            Source::Nextcloud => self.nextcloud_aio,
            Source::Peer | Source::Kernel | Source::Systemd | Source::Privilege | Source::Auth | Source::Audit | Source::Custom => Dur(0),
        }
    }
}

/// A kernel rate limit: new connections per source address to `ports`, e.g.
/// `{ ports = ["5222/tcp", "5223/tcp"], rate = "30/minute", burst = 30 }`.
/// Applies from the first packet, before any score reacts, and also to Docker-published
/// ports (UFW's `limit` rules don't). Allowlisted addresses are exempt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitCfg {
    pub ports: Vec<PortSpec>,
    /// `<n>/second`, `<n>/minute` or `<n>/hour`.
    pub rate: String,
    /// Extra connections allowed in a burst above the rate.
    #[serde(default = "default_burst")]
    pub burst: u32,
}

fn default_burst() -> u32 {
    10
}

impl RateLimitCfg {
    pub fn validate(&self) -> Result<()> {
        if !crate::enforce::valid_rate(&self.rate) {
            bail!("[[ratelimit]] rate '{}' must look like 30/minute (second, minute or hour)", self.rate);
        }
        if self.ports.is_empty() {
            bail!("[[ratelimit]] needs at least one port");
        }
        Ok(())
    }
}

/// Where Nextcloud AIO's logs are read from (`[nextcloud_aio]`, only with `[sources]
/// nextcloud_aio = true`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NextcloudCfg {
    pub docker: PathBuf,
    /// Container whose `docker logs` carry Apache's error log; empty = don't read it.
    pub apache_container: String,
    /// nextcloud.log (JSON lines, failed logins); empty = don't read it.
    pub log_file: PathBuf,
}

impl Default for NextcloudCfg {
    fn default() -> Self {
        NextcloudCfg {
            docker: "/usr/bin/docker".into(),
            apache_container: "nextcloud-aio-apache".into(),
            // `occ log:file` reports /var/www/html/data/nextcloud.log inside the container;
            // AIO mounts /var/www/html from the nextcloud_aio_nextcloud volume.
            log_file: "/var/lib/docker/volumes/nextcloud_aio_nextcloud/_data/data/nextcloud.log".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JournalCfg {
    pub journalctl: PathBuf,
    /// journalctl match expressions, OR-ed together. Empty (the default) = derived from `[sources]`.
    pub matches: Vec<String>,
    /// How far back to read when there is no saved cursor.
    pub initial_lookback: Dur,
    /// Run `journalctl --verify` this often ("0s" = never) and raise a high alert when it
    /// fails: damaged journal files, or with `verify_key` (Forward Secure Sealing, see
    /// `journalctl --setup-keys`) entries changed after they were sealed.
    pub verify_every: Dur,
    /// File holding the verification key `journalctl --setup-keys` printed (root only). Every
    /// sealing key derives from it, so whoever reads it can seal edited entries: on this
    /// host it catches only an intruder who doesn't look for it (see the README).
    pub verify_key_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowCfg {
    /// Addresses/networks that are never banned (your home, VPN, push servers...).
    pub nets: Vec<Net>,
    /// Host names whose addresses are allowlisted too (a home connection with a dynamic DNS
    /// name), resolved again every 10 minutes (every minute while one fails).
    pub hosts: Vec<String>,
    /// An address that logged in successfully (XMPP, SSH) isn't banned for that service's
    /// noise and typos for `trust_ttl` (each login renews it), nor for blocked packets on any
    /// port (their source address is easily forged). It stays bannable for canary names,
    /// other services and peers' reports, and is never shared.
    pub trust_authenticated: bool,
    pub trust_ttl: Dur,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XmppCfg {
    /// Client ports where a connection is expected to authenticate.
    pub c2s_ports: Vec<u16>,
    /// A client connection with no auth/TLS/session activity after this is "silent".
    pub noauth_grace: Dur,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScoringCfg {
    /// Short-term score: catches bursts. Ban when it reaches `fast_threshold`.
    pub fast_half_life: Dur,
    pub fast_threshold: f64,
    /// Long-term score: catches low-and-slow attackers.
    pub slow_half_life: Dur,
    pub slow_threshold: f64,
    /// Points added per event; entries override the built-in defaults individually.
    pub weights: BTreeMap<Signal, f64>,
    /// Bonus when one address touches this many distinct XMPP ports within `spread_window`.
    pub port_spread_ports: usize,
    pub port_spread_bonus: f64,
    pub spread_window: Dur,
    /// Bonus when UFW drops traffic from one address to this many distinct ports.
    pub fw_scan_ports: usize,
    pub fw_scan_bonus: f64,
    /// Alert when an address with at least this fast score then logs in successfully.
    pub compromise_score: f64,
    /// Addresses tracked at once (~600 bytes each). When full, the least suspicious 20% are
    /// dropped. A month of real traffic peaked at ~4,200 addresses in two days; 50,000 keeps
    /// a flood within the service's memory limit.
    pub max_tracked_ips: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountCfg {
    pub half_life: Dur,
    /// Alert when an account's decayed failure count reaches this from >= `min_ips` addresses.
    pub alert_failures: f64,
    pub min_ips: usize,
    /// Weight multiplier for failures against an account that is under attack.
    pub under_attack_multiplier: f64,
    /// Alert when an account logs in from a network never seen before...
    pub new_network_alerts: bool,
    /// ...once the account has been observed for this long (networks are learned silently before).
    pub learning_period: Dur,
    /// Accounts (JIDs or SSH user names) that roam across VPN exits; no new-network alerts for them.
    pub new_network_ignore: Vec<String>,
    /// Alert when an SSH account logs in with a key it never used before (keys are learned
    /// silently for `learning_period` after the first one is seen).
    pub new_key_alerts: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubnetCfg {
    pub enabled: bool,
    pub evaluate_every: Dur,
    /// An address counts as "bad" for aggregation if banned or its slow score is at least this.
    pub suspect_score: f64,
    /// The first (narrowest) subnet ban.
    pub v4_prefix: u8,
    pub v6_prefix: u8,
    pub min_bad_ips: usize,
    /// Distributed scanning: ban when at least `min_contributors` addresses in a subnet
    /// (each with slow score >= 5) together reach `score_sum_threshold`.
    pub min_contributors: usize,
    pub score_sum_threshold: f64,
    /// An IPv4 subnet ban grows to the narrowest network that also holds the next banned
    /// address or subnet nearby, up to `v4_wide_prefix`...
    pub wide_enabled: bool,
    pub v4_wide_prefix: u8,
    /// ...by at most this many prefix bits at a time (2: four times the addresses, /24 ->
    /// /22), so one ban far away can't turn a /24 into a /17.
    pub wide_max_step: u8,
    /// IPv6 subnet bans grow the same way, from `v6_prefix` up to this ("64", equal to
    /// `v6_prefix`, = no growth)...
    pub v6_wide_prefix: u8,
    /// ...by at most this many bits at a time (4: providers hand out /64s, /60s, /56s, /48s).
    pub wide_max_step_v6: u8,
    /// Retired with the single /24 -> /16 step: still accepted so older files load, ignored.
    #[serde(skip_serializing)]
    pub wide_min_bad_ips: Option<usize>,
    #[serde(skip_serializing)]
    pub wide_min_subnets: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BanCfg {
    /// Ban duration for the 1st, 2nd, ... offence; the last entry repeats.
    pub ladder: Vec<Dur>,
    /// Offence counter resets after this long without a new ban.
    pub forgive_after: Dur,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforceCfg {
    pub backend: Backend,
    pub nft: PathBuf,
    pub nft_table: String,
    pub ufw: PathBuf,
    pub iptables: PathBuf,
    pub ip6tables: PathBuf,
    /// Name of logguard's chains in the mangle table (`<name>` and `<name>-ban`), and with
    /// the ipset backend the start of its sets' names (`<name>-ban4`, `<name>-feed6`, ...).
    pub iptables_chain: String,
    pub firewall_cmd: PathBuf,
    pub ipset: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Shadow,
            package_manager: PackageManager::Apt,
            sources: SourcesCfg::default(),
            ports: PortsCfg::default(),
            state_file: "/var/lib/logguard/state.json".into(),
            socket: "/run/logguard/logguard.sock".into(),
            actions_log: Some("/var/log/logguard/actions.jsonl".into()),
            journal: JournalCfg::default(),
            allowlist: AllowCfg::default(),
            xmpp: XmppCfg::default(),
            scoring: ScoringCfg::default(),
            accounts: AccountCfg::default(),
            subnets: SubnetCfg::default(),
            bans: BanCfg::default(),
            enforce: EnforceCfg::default(),
            notify: crate::notify::NotifyCfg::default(),
            exposure: crate::exposure::ExposureCfg::default(),
            cluster: crate::cluster::ClusterCfg::default(),
            console: crate::console::ConsoleCfg::default(),
            nextcloud_aio: NextcloudCfg::default(),
            feeds: crate::feeds::FeedsCfg::default(),
            waf: crate::waf::WafCfg::default(),
            digest: crate::digest::DigestCfg::default(),
            canary: CanaryCfg::default(),
            silence: SilenceCfg::default(),
            ratelimit: vec![],
            geo: crate::geo::GeoCfg::default(),
            geoblock: crate::geo::GeoblockCfg::default(),
            cron: crate::cronwatch::CronCfg::default(),
            antivirus: crate::avscan::AvCfg::default(),
            resources: crate::resources::ResourcesCfg::default(),
            patches: crate::patches::PatchesCfg::default(),
            verify: crate::verify::VerifyCfg::default(),
            procwatch: crate::procwatch::ProcCfg::default(),
            ssh_audit: crate::sshaudit::SshAuditCfg::default(),
            patterns: vec![],
            app_patterns: vec![],
            app_logs_found: vec![],
        }
    }
}

impl Default for JournalCfg {
    fn default() -> Self {
        JournalCfg {
            journalctl: "/usr/bin/journalctl".into(),
            matches: vec![],
            initial_lookback: Dur(3600),
            verify_every: Dur(0),
            verify_key_file: PathBuf::new(),
        }
    }
}

impl Default for AllowCfg {
    fn default() -> Self {
        let nets = ["127.0.0.0/8", "::1"].iter().map(|s| s.parse().expect("valid default")).collect();
        AllowCfg { nets, hosts: vec![], trust_authenticated: true, trust_ttl: Dur(86_400) }
    }
}

impl Default for XmppCfg {
    fn default() -> Self {
        XmppCfg { c2s_ports: vec![5222, 5223], noauth_grace: Dur(90) }
    }
}

impl Default for ScoringCfg {
    fn default() -> Self {
        use Signal::*;
        let weights = [
            // "Three strikes within ~5 minutes" needs 40 with a 10 min half-life
            // (34 only banned if all three came within ~25 s); "five strikes" needs 25.
            (XmppTlsFail, 40.0),
            (XmppAuthFail, 25.0),
            (XmppNoAuth, 10.0),
            (XmppConn, 2.0),
            (XmppS2sBad, 25.0),
            (XmppHttpMiss, 4.0),
            (XmppTokenFail, 5.0),
            (XmppRegister, 15.0),
            (SshAuthFail, 25.0),
            (SshInvalidUser, 40.0),
            (SshPreauth, 8.0),
            (SshPenalty, 25.0),
            (FwBlock, 1.0),
            (FwLimit, 20.0),
            (FwTripwire, 100.0),
            (WebProbe, 40.0),
            (NcAuthFail, 25.0),
            (PamAuthFail, 25.0),
            (XmppCanary, 100.0),
            (SshCanary, 100.0),
            (NcCanary, 100.0),
            (TripwireConnect, 100.0),
            // the patterns of your own set their points (`[[patterns]] weight`)
            (CustomFailure, 0.0),
            (CustomProbe, 0.0),
            (CustomSuccess, 0.0),
        ]
        .into_iter()
        .collect();
        ScoringCfg {
            fast_half_life: Dur(600),
            fast_threshold: 100.0,
            slow_half_life: Dur(12 * 3600),
            slow_threshold: 200.0,
            weights,
            port_spread_ports: 3,
            port_spread_bonus: 60.0,
            spread_window: Dur(600),
            fw_scan_ports: 8,
            fw_scan_bonus: 60.0,
            compromise_score: 40.0,
            max_tracked_ips: 50_000,
        }
    }
}

impl Default for AccountCfg {
    fn default() -> Self {
        AccountCfg {
            half_life: Dur(3600),
            alert_failures: 20.0,
            min_ips: 3,
            under_attack_multiplier: 2.0,
            new_network_alerts: true,
            learning_period: Dur(7 * 86_400),
            new_network_ignore: vec![],
            new_key_alerts: true,
        }
    }
}

impl Default for SubnetCfg {
    fn default() -> Self {
        SubnetCfg {
            enabled: true,
            evaluate_every: Dur(60),
            suspect_score: 50.0,
            v4_prefix: 24,
            v6_prefix: 64,
            min_bad_ips: 3,
            min_contributors: 5,
            score_sum_threshold: 100.0,
            wide_enabled: true,
            v4_wide_prefix: 16,
            wide_max_step: 2,
            v6_wide_prefix: 48,
            wide_max_step_v6: 4,
            wide_min_bad_ips: None,
            wide_min_subnets: None,
        }
    }
}

impl Default for BanCfg {
    fn default() -> Self {
        BanCfg { ladder: vec![Dur(3600), Dur(6 * 3600), Dur(86_400), Dur(7 * 86_400), Dur(30 * 86_400)], forgive_after: Dur(30 * 86_400) }
    }
}

impl Default for EnforceCfg {
    fn default() -> Self {
        EnforceCfg {
            backend: Backend::Auto,
            nft: "/usr/sbin/nft".into(),
            nft_table: "logguard".into(),
            ufw: "/usr/sbin/ufw".into(),
            iptables: "/usr/sbin/iptables".into(),
            ip6tables: "/usr/sbin/ip6tables".into(),
            iptables_chain: "logguard".into(),
            firewall_cmd: "/usr/bin/firewall-cmd".into(),
            ipset: "/usr/sbin/ipset".into(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Config> {
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
                Config::from_toml(&text).with_context(|| format!("loading {}", p.display()))
            }
            None => Ok(Config::default()),
        }
    }

    /// Parses TOML; weights given in `[scoring.weights]` override the defaults individually.
    pub fn from_toml(text: &str) -> Result<Config> {
        let mut cfg: Config = toml::from_str(text)?;
        // With handshake-checked tripwires, a blocked SYN (whose source may be forged) is
        // only half the evidence, unless the file says otherwise.
        let raw: toml::Table = toml::from_str(text)?;
        let set = raw.get("scoring").and_then(|s| s.get("weights")).and_then(|w| w.get(Signal::FwTripwire.name())).is_some();
        if !cfg.ports.honeypot.is_empty() && !set {
            cfg.scoring.weights.insert(Signal::FwTripwire, 50.0);
        }
        for (signal, w) in ScoringCfg::default().weights {
            cfg.scoring.weights.entry(signal).or_insert(w);
        }
        cfg.share_package_manager();
        (cfg.app_patterns, cfg.app_logs_found) = crate::parse::apps::expand(&cfg.sources, &crate::parse::apps::System)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Hands `package_manager` to the sections that use it (their copies aren't read from the file).
    pub fn share_package_manager(&mut self) {
        self.cron.package_manager = self.package_manager;
        self.verify.package_manager = self.package_manager;
        self.patches.package_manager = self.package_manager;
    }

    /// The journalctl matches to follow: explicit ones, or those of the enabled sources.
    pub fn journal_matches(&self) -> Vec<String> {
        if !self.journal.matches.is_empty() {
            return self.journal.matches.clone();
        }
        let mut m: Vec<String> = Vec::new();
        if self.sources.ejabberd {
            m.push("_SYSTEMD_UNIT=ejabberd.service".into());
        }
        if self.sources.ssh {
            m.extend(["sshd", "sshd-session", "sshd-auth"].map(|i| format!("SYSLOG_IDENTIFIER={i}")));
        }
        if self.sources.ufw || self.sources.oom {
            m.push("_TRANSPORT=kernel".into());
        }
        // systemd (PID 1) tags its messages about a unit with UNIT=
        m.extend(self.sources.services.iter().map(|s| format!("UNIT={s}")));
        if self.sources.privilege {
            m.extend(["su", "sudo"].map(|i| format!("SYSLOG_IDENTIFIER={i}")));
        }
        // PAM logs as authpriv (10), the account tools as auth (4), whatever the program
        if self.sources.pam {
            m.extend(["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"].map(String::from));
        }
        if self.sources.audit && self.sources.audit_log.as_os_str().is_empty() {
            m.push("_TRANSPORT=audit".into());
        }
        for p in self.all_patterns() {
            if let Some(j) = p.journal_match() {
                if !m.contains(&j) {
                    m.push(j);
                }
            }
        }
        m
    }

    /// Names for local ports from this configuration, most specific first: `[ports] names`,
    /// then the XMPP client ports and the cluster port. One per port number (the dashboard
    /// counts TCP and UDP together).
    pub fn port_names(&self) -> Vec<(u16, String)> {
        let mut out: Vec<(u16, String)> = Vec::new();
        let mut add = |port: u16, name: &str| {
            if !out.iter().any(|(p, _)| *p == port) {
                out.push((port, name.to_string()));
            }
        };
        for (spec, name) in &self.ports.names {
            if let Ok(s) = spec.parse::<PortSpec>() {
                add(s.port, name);
            }
        }
        if self.sources.ejabberd {
            for p in &self.xmpp.c2s_ports {
                add(*p, "XMPP client");
            }
        }
        if self.cluster.enabled {
            if let Some(port) = self.cluster.listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()) {
                add(port, "logguard cluster");
            }
        }
        out
    }

    pub fn validate(&self) -> Result<()> {
        if let Some((spec, e)) = self.ports.names.keys().find_map(|k| k.parse::<PortSpec>().err().map(|e| (k, e))) {
            bail!("[ports] names: '{spec}': {e}");
        }
        if let Some(t) = self.ports.tripwire.iter().find(|t| self.ports.whitelist.iter().any(|w| w.port == t.port)) {
            bail!("[ports]: {t} is both whitelisted and a tripwire");
        }
        if let Some(s) = self.sources.services.iter().find(|s| !s.contains('.') || s.contains(|c: char| c.is_whitespace() || c == '=')) {
            bail!("[sources] services: '{s}' must be a full unit name, e.g. \"logguard-xmpp-bot.service\"");
        }
        for log in self.silence.apps.keys() {
            match crate::parse::apps::stream(log) {
                None => bail!("[silence.apps]: unknown log '{log}' (the keys of [sources.app_logs])"),
                Some((app, _)) if !self.sources.apps.iter().any(|a| a == app.name) => {
                    bail!("[silence.apps] {log}: '{}' isn't in [sources] apps", app.name)
                }
                _ => {}
            }
        }
        if !self.sources.audit_log.as_os_str().is_empty() && !self.sources.audit_log.is_absolute() {
            bail!("[sources] audit_log must be an absolute path, e.g. \"/var/log/audit/audit.log\"");
        }
        if let Some(k) = self
            .sources
            .audit_keys
            .iter()
            .find(|k| k.is_empty() || k.len() > 31 || k.contains(|c: char| c.is_whitespace() || c.is_control()))
        {
            bail!("[sources] audit_keys: '{k}' is no audit rule key (1-31 characters, no spaces)");
        }
        if !(self.sources.ejabberd || self.sources.ssh || self.sources.ufw) {
            bail!("[sources]: enable at least one of ejabberd, ssh, ufw");
        }
        if self.notify.enabled && self.notify.xmpp && !self.sources.ejabberd {
            bail!("notify needs ejabberd (ejabberdctl) on this host; disable [notify], enable sources.ejabberd, or set [notify] xmpp = false with a copy bot (tg_outbox, mail_outbox, signal_outbox, matrix_outbox or xmpp_outbox)");
        }
        let s = &self.scoring;
        if s.fast_threshold <= 0.0 || s.slow_threshold <= 0.0 {
            bail!("scoring thresholds must be positive");
        }
        if s.max_tracked_ips < 1000 {
            bail!("scoring.max_tracked_ips must be at least 1000");
        }
        if s.fast_half_life.0 == 0 || s.slow_half_life.0 == 0 || self.accounts.half_life.0 == 0 {
            bail!("half-lives must be non-zero");
        }
        if self.bans.ladder.is_empty() {
            bail!("bans.ladder must not be empty");
        }
        if !(8..=32).contains(&self.subnets.v4_prefix) || !(8..=32).contains(&self.subnets.v4_wide_prefix) {
            bail!("IPv4 subnet prefixes must be within 8..=32");
        }
        if self.subnets.v4_wide_prefix >= self.subnets.v4_prefix {
            bail!("subnets.v4_wide_prefix must be shorter than v4_prefix");
        }
        if self.subnets.wide_max_step == 0 {
            bail!("subnets.wide_max_step must be at least 1");
        }
        if !(16..=128).contains(&self.subnets.v6_prefix) {
            bail!("subnets.v6_prefix must be within 16..=128");
        }
        if !(16..=self.subnets.v6_prefix).contains(&self.subnets.v6_wide_prefix) {
            bail!("subnets.v6_wide_prefix must be within 16 and v6_prefix ({})", self.subnets.v6_prefix);
        }
        if self.subnets.wide_max_step_v6 == 0 {
            bail!("subnets.wide_max_step_v6 must be at least 1");
        }
        if let Some(h) = self.allowlist.hosts.iter().find(|h| !crate::net::valid_host_name(h)) {
            bail!("[allowlist] hosts: '{h}' is not a host name (no port, no address)");
        }
        if !crate::enforce::valid_rate(&self.ports.kernel_tripwire_rate) {
            bail!("[ports] kernel_tripwire_rate '{}' must look like 60/minute (second, minute or hour)", self.ports.kernel_tripwire_rate);
        }
        if let Some(h) = self.ports.honeypot.iter().find(|h| h.proto == Some(Proto::Udp)) {
            bail!("[ports] honeypot: {h}: TCP only (a UDP sender's address is never checked)");
        }
        if let Some(h) = self.ports.honeypot.iter().find(|h| self.ports.whitelist.iter().any(|w| w.port == h.port)) {
            bail!("[ports]: {h} is both whitelisted and a honeypot");
        }
        if self.feeds.enabled && !self.feeds.asn_urls.is_empty() && (!self.geo.enabled || self.geo.asn_url.is_empty()) {
            bail!("[feeds] asn_urls needs the network database: [geo] enabled = true with an asn_url");
        }
        self.waf.validate()?;
        let mut names = std::collections::BTreeSet::new();
        for p in &self.patterns {
            p.validate()?;
            if self.app_patterns.iter().any(|a| a.name == p.name) {
                bail!("[[patterns]]: '{}' is the name of a built-in pattern of [sources] apps: name yours differently", p.name);
            }
            if !names.insert(p.name.as_str()) {
                bail!("[[patterns]]: two patterns are named '{}'", p.name);
            }
        }
        for p in &self.app_patterns {
            p.validate()?;
        }
        self.notify.validate()?;
        self.cluster.validate()?;
        self.console.validate(&self.socket)?;
        self.digest.validate()?;
        self.canary.validate()?;
        for r in &self.ratelimit {
            r.validate()?;
        }
        self.procwatch.validate()?;
        self.antivirus.validate_scans()?;
        self.verify.validate()?;
        self.geo.validate()?;
        self.geoblock.validate(&self.geo)?;
        if !self.enforce.nft_table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            bail!("enforce.nft_table must be alphanumeric");
        }
        let chain = &self.enforce.iptables_chain;
        if chain.is_empty() || chain.len() > 24 || !chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            bail!("enforce.iptables_chain must be 1-24 letters, digits, '_' or '-' (iptables allows 28 with the -ban suffix)");
        }
        Ok(())
    }

    /// The patterns of your own, then the built-in ones of `[sources] apps`: a line goes to
    /// the first that finds an address in it.
    pub fn all_patterns(&self) -> impl Iterator<Item = &crate::parse::custom::PatternCfg> {
        self.patterns.iter().chain(&self.app_patterns)
    }

    pub fn weight(&self, s: Signal) -> f64 {
        self.scoring.weights.get(&s).copied().unwrap_or(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip_through_toml() {
        let text = toml::to_string_pretty(&Config::default()).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        back.validate().unwrap();
        assert_eq!(back.weight(Signal::XmppTlsFail), 40.0);
    }

    #[test]
    fn port_names_from_config() {
        let cfg = Config::from_toml(
            r#"
            [ports]
            names = { "51820/udp" = "WireGuard", 5223 = "XMPP direct TLS" }
            [cluster]
            enabled = true
            key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            listen = "0.0.0.0:7946"
            "#,
        )
        .unwrap();
        let names = cfg.port_names();
        let name = |port| names.iter().find(|(p, _)| *p == port).map(|(_, n)| n.as_str());
        assert_eq!(name(51820), Some("WireGuard"));
        assert_eq!(name(5223), Some("XMPP direct TLS"), "[ports] names come first");
        assert_eq!(name(5222), Some("XMPP client"));
        assert_eq!(name(7946), Some("logguard cluster"));
        assert!(Config::from_toml("[ports]\nnames = { \"x/tcp\" = \"y\" }").is_err());
    }

    /// The desktop profile: watches the machine, leaves the firewall alone, and takes what a
    /// desktop does (new apps talking, AppImages, snapd's units) without hiding programs by name.
    #[test]
    fn desktop_profile() {
        let cfg = Config::from_toml(include_str!("../deploy/logguard-desktop.toml")).unwrap();
        assert_eq!(cfg.mode, Mode::Shadow);
        assert!(!cfg.notify.enabled && !cfg.cluster.enabled && !cfg.feeds.enabled && !cfg.exposure.enabled && !cfg.silence.enabled);
        assert!(cfg.cron.enabled && cfg.verify.enabled && cfg.procwatch.enabled && cfg.sources.pam && cfg.sources.privilege);
        assert!(!cfg.procwatch.new_outbound && cfg.procwatch.allow_appimages);
        assert!(cfg.procwatch.ignore_processes.is_empty(), "nothing by name");
        assert!(cfg.cron.exclude.iter().all(|p| p.contains("/snap")) && !cfg.cron.exclude.is_empty());
        assert!(!cfg.cron.files.is_empty(), "the default watched files stay");
        assert_eq!(cfg.cluster.node_id, "desktop", "upgrades find the template");

        // its notes for the XMPP client bot, followed, give a valid config with that copy bot only
        let template = include_str!("../deploy/logguard-desktop.toml");
        let with_bot = template
            .replace("enabled = false\n#xmpp = false", "enabled = true\nxmpp = false")
            .replace("#xmpp_outbox", "xmpp_outbox")
            .replace("#xmpp_user", "xmpp_user");
        let cfg = Config::from_toml(&with_bot).unwrap();
        assert!(cfg.notify.enabled && !cfg.notify.xmpp);
        let bots: Vec<&str> = cfg.notify.copy_bots().iter().map(|(k, _, _)| k.unit).collect();
        assert_eq!(bots, ["logguard-xmpp-bot"]);
    }

    #[test]
    fn vpn_host_config() {
        let cfg = Config::from_toml(
            r#"
            [sources]
            ejabberd = false
            [ports]
            whitelist = ["51820/udp", "51821/tcp", 8443]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.journal_matches(),
            vec![
                "SYSLOG_IDENTIFIER=sshd",
                "SYSLOG_IDENTIFIER=sshd-session",
                "SYSLOG_IDENTIFIER=sshd-auth",
                "_TRANSPORT=kernel",
                "SYSLOG_IDENTIFIER=su",
                "SYSLOG_IDENTIFIER=sudo",
                "SYSLOG_FACILITY=4",
                "SYSLOG_FACILITY=10",
                "_TRANSPORT=audit"
            ]
        );
        assert!(cfg.ports.whitelisted(Some(51820), Proto::Udp));
        assert!(!cfg.ports.whitelisted(Some(51820), Proto::Tcp));
        assert!(cfg.ports.whitelisted(Some(8443), Proto::Udp));
        assert!(!cfg.ports.whitelisted(None, Proto::Tcp));
        assert_eq!(cfg.ports.whitelist[0].to_string(), "51820/udp");
        assert!(Config::from_toml("[ports]\nwhitelist = [\"51820/sctp\"]").is_err());
        assert!(Config::from_toml("[sources]\nejabberd = false\nssh = false\nufw = false").is_err());
        assert_eq!(Config::from_toml("[enforce]\nbackend = \"firewalld\"").unwrap().enforce.backend, Backend::Firewalld);
        assert_eq!(Config::from_toml("[enforce]\nbackend = \"ipset\"").unwrap().enforce.backend, Backend::Ipset);
        let ipt = Config::from_toml("[enforce]\nbackend = \"iptables\"\niptables_chain = \"lg-raw\"").unwrap();
        assert_eq!((ipt.enforce.backend, ipt.enforce.iptables_chain.as_str()), (Backend::Iptables, "lg-raw"));
        assert!(Config::from_toml("[enforce]\niptables_chain = \"a b\"").is_err());
        assert!(Config::from_toml("[enforce]\niptables_chain = \"a-name-much-too-long-for-xt\"").is_err());
        assert!(Config::from_toml("[sources]\nejabberd = false\n[notify]\nenabled = true\nfrom = \"x.org\"").is_err());
        assert_eq!(Config::default().journal_matches().len(), 10);
        // a pattern of your own adds its unit; one already followed isn't added twice
        let p = Config::from_toml("[sources]\nprivilege = false\n[[patterns]]\nname = \"x\"\nunit = \"postfix@-.service\"\nregex = '(?P<ip>\\S+)'\n[[patterns]]\nname = \"y\"\nunit = \"postfix@-.service\"\nregex = 'a(?P<ip>\\S+)'").unwrap();
        assert_eq!(p.journal_matches().last().map(String::as_str), Some("_SYSTEMD_UNIT=postfix@-.service"));
        assert_eq!(p.journal_matches().len(), 9);
        assert!(Config::from_toml("[[patterns]]\nname = \"x\"\nunit = \"a.service\"\nregex = '(?P<ip>\\S+)'\n[[patterns]]\nname = \"x\"\nunit = \"b.service\"\nregex = '(?P<ip>\\S+)'").is_err(), "names are unique");
        // [sources] nextcloud_aio, called nextcloud before
        assert!(Config::from_toml("[sources]\nnextcloud = true").unwrap().sources.nextcloud_aio);
        assert!(Config::from_toml("[sources]\nnextcloud_aio = true").unwrap().sources.nextcloud_aio);
        assert!(Config::from_toml("[sources]\nnextcloud = true\nnextcloud_aio = true").is_err(), "one name only");
        assert!(toml::to_string(&Config::default()).unwrap().contains("nextcloud_aio = false"), "print-config: the new name");
        // [nextcloud] and [silence] nextcloud, now nextcloud_aio
        let old = Config::from_toml("[nextcloud]\napache_container = \"x\"\n[silence]\nnextcloud = \"1h\"").unwrap();
        assert_eq!((old.nextcloud_aio.apache_container.as_str(), old.silence.nextcloud_aio.0), ("x", 3600));
        assert!(Config::from_toml("[nextcloud]\ndocker = \"/a\"\n[nextcloud_aio]\ndocker = \"/b\"").is_err(), "one name only");
        let printed = toml::to_string(&Config::default()).unwrap();
        assert!(printed.contains("[nextcloud_aio]") && !printed.contains("[nextcloud]"), "{printed}");
        let apps = Config::from_toml(
            "[sources]\napps = [\"mysql\"]\n[sources.app_logs]\nmysql = \"mariadb.service\"\n[sources.app_weights]\nmysql_preauth = 0",
        )
        .unwrap();
        let names: Vec<&str> = apps.all_patterns().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["mysql_auth", "mysql_preauth"]);
        assert!(apps.journal_matches().contains(&"_SYSTEMD_UNIT=mariadb.service".to_string()));
        let mine = "[[patterns]]\nname = \"nginx_auth\"\nunit = \"a.service\"\nregex = '(?P<ip>\\S+)'";
        Config::from_toml(mine).expect("nginx isn't in [sources] apps: the name is free");
        let clash = Config::from_toml(&format!("[sources]\napps = [\"nginx\"]\n{mine}")).unwrap_err();
        assert!(clash.to_string().contains("built-in pattern"), "{clash}");
        assert!(Config::from_toml("[sources]\napps = [\"iis\"]").is_err());
        // honeypots: a blocked SYN to a tripwire port is half the evidence then, unless set
        assert_eq!(Config::from_toml("[ports]\nhoneypot = [2323]").unwrap().weight(Signal::FwTripwire), 50.0);
        assert_eq!(
            Config::from_toml("[ports]\nhoneypot = [2323]\n[scoring.weights]\nfw_tripwire = 80").unwrap().weight(Signal::FwTripwire),
            80.0
        );
        assert_eq!(Config::default().weight(Signal::FwTripwire), 100.0);
        assert!(Config::from_toml("[ports]\nhoneypot = [\"161/udp\"]").is_err());
        assert!(Config::from_toml("[allowlist]\nhosts = [\"home.example.org:22\"]").is_err());
        assert!(Config::from_toml("[ports]\nkernel_tripwire_rate = \"fast\"").is_err());
        assert!(Config::from_toml("[subnets]\nv6_wide_prefix = 72").is_err());
        assert!(Config::from_toml("[feeds]\nenabled = true\nasn_urls = [\"https://x/asn\"]").is_err(), "needs [geo]");
        assert!(Config::from_toml("[waf]\nenabled = true").is_err(), "needs a source");
    }

    #[test]
    fn waf_sources() {
        let cfg = Config::from_toml(
            r#"
            [waf]
            enabled = true
            [[waf.sources]]
            name = "crowdsec"
            format = "crowdsec"
            url = "http://127.0.0.1:8080/v1/decisions?type=ban&origins=crowdsec,cscli"
            api_key_file = "/etc/logguard/crowdsec-bouncer.key"
            [[waf.sources]]
            name = "capi"
            format = "crowdsec"
            command = ["cscli", "decisions", "list", "-a", "--origin", "CAPI", "-o", "raw"]
            action = "list"
            [[waf.sources]]
            name = "edge"
            format = "json"
            file = "/var/lib/edge/blocked.json"
            items = "result"
            reason_field = "comment"
            "#,
        )
        .unwrap();
        let names: Vec<(&str, crate::waf::WafAction)> = cfg.waf.sources.iter().map(|s| (s.name.as_str(), s.action)).collect();
        use crate::waf::WafAction::{Ban, List};
        assert_eq!(names, [("crowdsec", Ban), ("capi", List), ("edge", Ban)]);
        assert_eq!(cfg.waf.sources[0].api_key_header, "X-Api-Key");
        assert!(
            Config::from_toml("[waf]\nenabled = true\n[[waf.sources]]\nname = \"x\"\nfile = \"/x\"\nformt = \"json\"").is_err(),
            "a typo"
        );
    }

    #[test]
    fn partial_file() {
        let cfg = Config::from_toml(
            r#"
            mode = "enforce"
            [allowlist]
            nets = ["11.48.43.31", "11.38.48.86/32"]
            [scoring.weights]
            fw_block = 0.5
            "#,
        )
        .unwrap();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert_eq!(cfg.allowlist.nets.len(), 2);
        assert!(cfg.allowlist.trust_authenticated);
        assert_eq!(cfg.weight(Signal::FwBlock), 0.5);
        assert_eq!(cfg.weight(Signal::XmppTlsFail), 40.0, "unlisted weights keep their defaults");
        assert!(Config::from_toml("bogus = 1").is_err());
    }

    #[test]
    fn retired_subnet_options_still_load() {
        let cfg = Config::from_toml("[subnets]\nwide_min_bad_ips = 12\nwide_min_subnets = 4\n").unwrap();
        assert_eq!(cfg.subnets.wide_max_step, 2);
        assert!(!toml::to_string(&cfg).unwrap().contains("wide_min"), "print-config leaves them out");
        assert!(Config::from_toml("[subnets]\nwide_max_step = 0\n").is_err());
    }

    #[test]
    fn package_manager() {
        let cfg = Config::from_toml("package_manager = \"dnf\"\n").unwrap();
        assert_eq!(cfg.package_manager, PackageManager::Dnf);
        assert_eq!(
            (cfg.cron.package_manager, cfg.verify.package_manager, cfg.patches.package_manager),
            (PackageManager::Dnf, PackageManager::Dnf, PackageManager::Dnf)
        );
        assert_eq!(Config::from_toml("package_manager = \"rpm\"\n").unwrap().package_manager, PackageManager::Dnf);
        assert_eq!(Config::from_toml("package_manager = \"dpkg\"\n").unwrap().package_manager, PackageManager::Apt);
        assert_eq!(Config::from_toml("").unwrap().verify.package_manager, PackageManager::Apt, "apt by default");
        assert!(Config::from_toml("package_manager = \"pacman\"\n").is_err());
        assert!(toml::to_string(&cfg).unwrap().starts_with("mode = \"shadow\"\npackage_manager = \"dnf\"\n"), "print-config shows it once");
        assert!(Config::from_toml("[verify]\npackage_manager = \"dnf\"\n").is_err(), "top-level only");
    }
}
