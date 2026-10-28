//! SSH hardening audit: how sshd is really configured, checked against good practice and
//! against the layout this host uses. The effective settings come from `sshd -T` (with `-C`
//! for root and the gateway users, so `Match` blocks count, as seen from an internet address);
//! the config files are parsed too, to say which file a setting comes from (cloud images'
//! `50-cloud-init.conf` turning passwords back on is the classic).
//!
//! Layouts:
//! - a plain VPS: keys, maybe root with a key; passwords are the risk;
//! - a hosting panel (cPanel/WHM, Plesk, DirectAdmin, ...): the same checks, with the panel's
//!   own place to change them;
//! - a gateway (`harden-vps.sh`, or set up the same way by hand): one key-only user whose
//!   sessions are forced into a su/sftp wrapper, `su` limited by pam_wheel to a group, keys in
//!   root-owned files, no root login. Each of those pieces is checked.
//!
//! Read every `interval`; nothing is changed. New problems and changed settings are alerts
//! (see `judge`); the digest, `status` and the TUI show what is still open, and
//! `logguard ssh-audit` prints everything with how to fix it.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cronwatch::Finding;
use crate::engine::Severity;
use crate::time::{self, Dur, Micros};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// A gateway when sshd's settings say so (a ForceCommand for the allowed users, or
    /// AllowUsers with `su` limited to `su_group`), else a plain host.
    #[default]
    Auto,
    Standard,
    /// The gateway checks always; missing pieces of the layout are problems.
    Gateway,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshAuditCfg {
    pub enabled: bool,
    pub interval: Dur,
    pub sshd: PathBuf,
    /// The main config file (passed to `sshd -T -f`, and read for where settings come from).
    pub config: PathBuf,
    pub profile: Profile,
    /// The gateway users; empty: those AllowUsers and `su_group` name whose sessions sshd
    /// forces into a command.
    pub gateway_users: Vec<String>,
    /// The group pam_wheel lets `su` to root on a gateway (harden-vps.sh: gw-su). The group
    /// pam_wheel names in /etc/pam.d/su is used when it names another.
    pub su_group: String,
    /// Problems never reported, by id (`logguard ssh-audit` shows them), e.g. "x11-forwarding";
    /// an id covers its forms for one user or file too ("gateway-home" covers "gateway-home:alice").
    pub ignore: Vec<String>,
    /// High problems still open are reminded this often ("0s": only in the digest).
    pub remind: Dur,
    pub passwd: PathBuf,
    pub shadow: PathBuf,
    pub group: PathBuf,
    pub pam_su: PathBuf,
}

impl Default for SshAuditCfg {
    fn default() -> Self {
        SshAuditCfg {
            enabled: true,
            interval: Dur(3600),
            sshd: "/usr/sbin/sshd".into(),
            config: "/etc/ssh/sshd_config".into(),
            profile: Profile::Auto,
            gateway_users: vec![],
            su_group: "gw-su".into(),
            ignore: vec![],
            remind: Dur(7 * 86_400),
            passwd: "/etc/passwd".into(),
            shadow: "/etc/shadow".into(),
            group: "/etc/group".into(),
            pam_su: "/etc/pam.d/su".into(),
        }
    }
}

/// Effective settings: keyword (lower case) -> values. Keywords sshd accumulates (Port,
/// AllowUsers, HostKey, ...) have one value per item; the others one value, all its words.
pub type Settings = BTreeMap<String, Vec<String>>;

/// Keywords whose lines add up instead of the first one winning.
const ACCUMULATING: [&str; 11] = [
    "port",
    "listenaddress",
    "hostkey",
    "hostcertificate",
    "allowusers",
    "denyusers",
    "allowgroups",
    "denygroups",
    "acceptenv",
    "subsystem",
    "include",
];

/// OpenSSH's defaults (9.x) for what is checked, for when `sshd -T` can't run.
const DEFAULTS: [(&str, &str); 27] = [
    ("port", "22"),
    ("permitrootlogin", "prohibit-password"),
    ("passwordauthentication", "yes"),
    ("kbdinteractiveauthentication", "yes"),
    ("usepam", "no"),
    ("pubkeyauthentication", "yes"),
    ("authenticationmethods", "any"),
    ("permitemptypasswords", "no"),
    ("hostbasedauthentication", "no"),
    ("ignorerhosts", "yes"),
    ("strictmodes", "yes"),
    ("loglevel", "INFO"),
    ("maxauthtries", "6"),
    ("logingracetime", "120"),
    ("x11forwarding", "no"),
    ("allowtcpforwarding", "yes"),
    ("allowagentforwarding", "yes"),
    ("allowstreamlocalforwarding", "yes"),
    ("gatewayports", "no"),
    ("permittunnel", "no"),
    ("permituserenvironment", "no"),
    ("permitopen", "any"),
    ("permitlisten", "any"),
    ("forcecommand", "none"),
    ("authorizedkeysfile", ".ssh/authorized_keys .ssh/authorized_keys2"),
    ("authorizedkeyscommand", "none"),
    ("permittty", "yes"),
];

/// The settings whose changes are reported (`judge`), besides the gateway users' own.
const WATCHED: [&str; 26] = [
    "port",
    "listenaddress",
    "permitrootlogin",
    "passwordauthentication",
    "kbdinteractiveauthentication",
    "usepam",
    "pubkeyauthentication",
    "authenticationmethods",
    "permitemptypasswords",
    "hostbasedauthentication",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
    "authorizedkeysfile",
    "authorizedkeyscommand",
    "strictmodes",
    "loglevel",
    "allowtcpforwarding",
    "gatewayports",
    "permittunnel",
    "x11forwarding",
    "permituserenvironment",
    "ciphers",
    "macs",
    "kexalgorithms",
];

/// What a gateway user's own session settings are watched for.
const WATCHED_PER_USER: [&str; 6] =
    ["forcecommand", "authenticationmethods", "allowtcpforwarding", "permitopen", "permitlisten", "x11forwarding"];

/// A test address (TEST-NET-3) for `sshd -T -C`: what a login from the internet gets, not one
/// from a `Match Address` block for the LAN.
const INTERNET_ADDR: &str = "203.0.113.1";

/// Users asked about with `sshd -T -C` at most (root, then the gateway candidates).
const MAX_USERS: usize = 10;
/// Accounts whose key files are checked at most.
const MAX_ACCOUNTS: usize = 300;

/// `sshd -T` output: `keyword value...` lines.
pub fn parse_settings(text: &str) -> Settings {
    let mut s = Settings::new();
    for line in text.lines() {
        let Some((k, v)) = line.trim().split_once(' ') else { continue };
        let k = k.to_ascii_lowercase();
        let v = v.trim();
        if ACCUMULATING.contains(&k.as_str()) {
            s.entry(k).or_default().extend(v.split_whitespace().map(str::to_string));
        } else {
            s.entry(k).or_default().push(v.to_string());
        }
    }
    s
}

fn first<'a>(s: &'a Settings, key: &str) -> &'a str {
    s.get(key).and_then(|v| v.first()).map_or_else(|| default_of(key), String::as_str)
}

fn default_of(key: &str) -> &'static str {
    DEFAULTS.iter().find(|(k, _)| *k == key).map_or("", |(_, v)| v)
}

fn yes(s: &Settings, key: &str) -> bool {
    first(s, key).eq_ignore_ascii_case("yes")
}

fn list<'a>(s: &'a Settings, key: &str) -> &'a [String] {
    s.get(key).map_or(&[], Vec::as_slice)
}

/// Keyboard-interactive authentication, under its old name too (OpenSSH before 8.7).
fn kbd_interactive(s: &Settings) -> bool {
    let key = if s.contains_key("kbdinteractiveauthentication") || !s.contains_key("challengeresponseauthentication") {
        "kbdinteractiveauthentication"
    } else {
        "challengeresponseauthentication"
    };
    yes(s, key) && yes(s, "usepam")
}

/// The AuthenticationMethods lists (None: "any", every method alone).
fn method_lists(s: &Settings) -> Option<Vec<Vec<String>>> {
    let v = first(s, "authenticationmethods");
    if v.is_empty() || v.eq_ignore_ascii_case("any") {
        return None;
    }
    Some(v.split_whitespace().map(|l| l.split(',').map(|m| m.to_ascii_lowercase()).collect()).collect())
}

/// Whether a password (or PAM's password prompt) is enough to log in, without a key.
pub fn password_alone(s: &Settings) -> bool {
    let pw = yes(s, "passwordauthentication");
    let kbd = kbd_interactive(s);
    if !(pw || kbd) {
        return false;
    }
    match method_lists(s) {
        None => true,
        Some(lists) => lists.iter().any(|l| {
            !l.iter().any(|m| m == "publickey")
                && l.iter().any(|m| (pw && m == "password") || (kbd && m.starts_with("keyboard-interactive")))
        }),
    }
}

/// Whether keys can log in at all.
fn keys_allowed(s: &Settings) -> bool {
    yes(s, "pubkeyauthentication") && method_lists(s).is_none_or(|l| l.iter().any(|l| l.iter().any(|m| m == "publickey")))
}

/// Root's PermitRootLogin, normalised: "yes", "prohibit-password", "forced-commands-only", "no".
fn root_login(s: &Settings) -> &'static str {
    match first(s, "permitrootlogin").to_ascii_lowercase().as_str() {
        "yes" => "yes",
        "no" => "no",
        "forced-commands-only" => "forced-commands-only",
        _ => "prohibit-password",
    }
}

/// `*` and `?` glob, as sshd matches user and group names.
pub fn glob(pattern: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), s.as_bytes())
}

/// A pattern list item for users: `user` or `user@host` (the host part can't be judged here:
/// it may match, so it counts). `!pattern` negates.
fn user_pattern_matches(pattern: &str, user: &str) -> bool {
    let p = pattern.split_once('@').map_or(pattern, |(u, _)| u);
    glob(p, user)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Password {
    /// A password hash: the account can log in with it.
    Set,
    /// `!`, `*`, or `!` in front of a hash.
    Locked,
    /// No password at all.
    Empty,
    /// /etc/shadow couldn't be read.
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub password: Password,
}

impl Account {
    fn login_shell(&self) -> bool {
        let s = self.shell.as_str();
        !(s.is_empty()
            || s.ends_with("/nologin")
            || s.ends_with("/false")
            || s.ends_with("/sync")
            || s.ends_with("/halt")
            || s.ends_with("/shutdown"))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Group {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub fn parse_passwd(passwd: &str, shadow: Option<&str>) -> Vec<Account> {
    let mut pw: BTreeMap<&str, Password> = BTreeMap::new();
    for l in shadow.unwrap_or("").lines() {
        let mut f = l.split(':');
        let (Some(name), Some(hash)) = (f.next(), f.next()) else { continue };
        let state = if hash.is_empty() {
            Password::Empty
        } else if hash.starts_with('!') || hash.starts_with('*') {
            Password::Locked
        } else {
            Password::Set
        };
        pw.insert(name, state);
    }
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 || f[0].is_empty() || f[0].starts_with('+') || f[0].starts_with('-') {
                return None;
            }
            let password = match (f[1], shadow) {
                // the hash in /etc/passwd itself (no shadow), or "x": see shadow
                ("", _) => Password::Empty,
                ("x", Some(_)) => pw.get(f[0]).cloned().unwrap_or(Password::Locked),
                ("x", None) => Password::Unknown,
                (h, _) if h.starts_with('!') || h.starts_with('*') => Password::Locked,
                _ => Password::Set,
            };
            Some(Account {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: f[5].to_string(),
                shell: f[6].to_string(),
                password,
            })
        })
        .collect()
}

pub fn parse_groups(text: &str) -> Vec<Group> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 || f[0].is_empty() {
                return None;
            }
            Some(Group {
                name: f[0].to_string(),
                gid: f[2].parse().ok()?,
                members: f[3].split(',').map(str::trim).filter(|m| !m.is_empty()).map(str::to_string).collect(),
            })
        })
        .collect()
}

/// Where a setting is written: the value and `file:line`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub value: String,
    pub at: String,
}

/// A `Match` block's settings.
#[derive(Clone, Debug, Default)]
pub struct MatchBlock {
    pub criteria: String,
    pub lines: Vec<(String, String)>,
}

/// The config files as sshd reads them: global lines in order (first wins, Include in place),
/// and the Match blocks.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    /// keyword -> every global line setting it, in the order sshd reads them.
    pub origins: BTreeMap<String, Vec<Origin>>,
    pub matches: Vec<MatchBlock>,
    /// Every file read (the main one, then the included ones).
    pub files: Vec<String>,
    pub errors: Vec<String>,
}

/// `keyword args` or `keyword=args`, without comments; None for empty and comment lines.
fn split_line(line: &str) -> Option<(String, String)> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let cut = l.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(l.len());
    let key = l[..cut].to_ascii_lowercase();
    let mut rest = l[cut..].trim_start();
    rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    // a word starting with # ends the line (sshd's argv_split)
    let words: Vec<&str> = rest.split_whitespace().take_while(|w| !w.starts_with('#')).collect();
    Some((key, words.join(" ").replace('"', "")))
}

/// Files an Include pattern names, sorted like glob(3) (`*` and `?` in the last component).
fn include_files(pattern: &str, base: &Path) -> Vec<PathBuf> {
    let p = if pattern.starts_with('/') { PathBuf::from(pattern) } else { base.join(pattern) };
    let (Some(dir), Some(name)) = (p.parent(), p.file_name().map(|n| n.to_string_lossy().into_owned())) else { return vec![] };
    if !name.contains(['*', '?']) {
        return if p.is_file() { vec![p] } else { vec![] };
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            !n.starts_with('.') && glob(&name, &n)
        })
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    out.sort();
    out
}

/// Parses sshd's config files from `main`.
pub fn parse_config(main: &Path) -> Parsed {
    let mut out = Parsed::default();
    let base = main.parent().unwrap_or(Path::new("/etc/ssh")).to_path_buf();
    read_config_file(main, &base, None, 0, &mut out);
    out
}

/// One file's lines, into `out`; `in_match`: the Match block an Include stood in.
fn read_config_file(path: &Path, base: &Path, in_match: Option<usize>, depth: usize, out: &mut Parsed) {
    let name = path.display().to_string();
    if depth > 16 || out.files.len() >= 200 {
        out.errors.push(format!("{name}: too many nested Include files"));
        return;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            out.errors.push(format!("{name}: {e}"));
            return;
        }
    };
    out.files.push(name.clone());
    parse_config_text(&text, &name, base, in_match, depth, out);
}

fn parse_config_text(text: &str, name: &str, base: &Path, in_match: Option<usize>, depth: usize, out: &mut Parsed) {
    // a Match block ends with the next Match or the end of the file
    let mut block = in_match;
    for (n, line) in text.lines().enumerate() {
        let Some((key, value)) = split_line(line) else { continue };
        match key.as_str() {
            "match" => {
                if value.eq_ignore_ascii_case("all") {
                    block = in_match;
                } else {
                    out.matches.push(MatchBlock { criteria: value, lines: vec![] });
                    block = Some(out.matches.len() - 1);
                }
            }
            "include" => {
                for pattern in value.split_whitespace() {
                    for f in include_files(pattern, base) {
                        read_config_file(&f, base, block, depth + 1, out);
                    }
                }
            }
            _ => match block {
                Some(i) => out.matches[i].lines.push((key, value)),
                None => out.origins.entry(key).or_default().push(Origin { value, at: format!("{name}:{}", n + 1) }),
            },
        }
    }
}

impl Parsed {
    /// Settings from the files alone, over OpenSSH's defaults (when `sshd -T` can't run).
    pub fn effective(&self) -> Settings {
        let mut s: Settings = DEFAULTS.iter().map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect();
        for (k, lines) in &self.origins {
            set_from_lines(&mut s, k, lines.iter().map(|o| o.value.as_str()));
        }
        s
    }

    /// The same with the Match blocks a user's login from the internet would get: those
    /// matching on `User` (and `Group`) only; others can't be judged from the files.
    pub fn effective_for(&self, user: &str, groups: &[String]) -> Settings {
        let mut s = self.effective();
        let mut set: BTreeSet<String> = BTreeSet::new();
        for m in &self.matches {
            if !match_applies(&m.criteria, user, groups) {
                continue;
            }
            for (k, v) in &m.lines {
                // within Match, the first line for a keyword wins too
                if set.insert(k.clone()) {
                    s.remove(k);
                    set_from_lines(&mut s, k, std::iter::once(v.as_str()));
                }
            }
        }
        s
    }

    /// The global value lines of a keyword that come after the one that wins, with another
    /// value: what someone wrote but sshd ignores.
    pub fn shadowed(&self, key: &str) -> Vec<&Origin> {
        let Some(lines) = self.origins.get(key) else { return vec![] };
        if ACCUMULATING.contains(&key) || lines.is_empty() {
            return vec![];
        }
        lines[1..].iter().filter(|o| !o.value.eq_ignore_ascii_case(&lines[0].value)).collect()
    }

    pub fn origin(&self, key: &str) -> Option<&Origin> {
        self.origins.get(key).and_then(|l| l.first())
    }
}

fn set_from_lines<'a>(s: &mut Settings, key: &str, mut lines: impl Iterator<Item = &'a str>) {
    if ACCUMULATING.contains(&key) {
        let v: Vec<String> = lines.flat_map(str::split_whitespace).map(str::to_string).collect();
        s.insert(key.to_string(), v);
    } else if let Some(v) = lines.next() {
        // sshd -T spells it so
        let v = if key == "permitrootlogin" && v.eq_ignore_ascii_case("without-password") { "prohibit-password" } else { v };
        s.insert(key.to_string(), vec![v.to_string()]);
    }
}

/// Whether `Match <criteria>` applies to a login of `user` from the internet; only User and
/// Group criteria are known here, anything else doesn't apply.
fn match_applies(criteria: &str, user: &str, groups: &[String]) -> bool {
    let words: Vec<&str> = criteria.split_whitespace().collect();
    if !words.len().is_multiple_of(2) || words.is_empty() {
        return false;
    }
    words.chunks(2).all(|c| {
        let patterns: Vec<&str> = c[1].split(',').collect();
        let hit = |name: &str| {
            let mut ok = false;
            for p in &patterns {
                if let Some(neg) = p.strip_prefix('!') {
                    if glob(neg, name) {
                        return false;
                    }
                } else if glob(p, name) {
                    ok = true;
                }
            }
            ok
        };
        match c[0].to_ascii_lowercase().as_str() {
            "user" => hit(user),
            "group" => groups.iter().any(|g| hit(g)),
            _ => false,
        }
    })
}

/// A file's owner and mode, as checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub uid: u32,
    pub gid: u32,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    pub dir: bool,
}

impl FileInfo {
    fn of(path: &str) -> Option<FileInfo> {
        let m = std::fs::metadata(path).ok()?;
        Some(FileInfo { uid: m.uid(), gid: m.gid(), mode: m.mode() & 0o7777, dir: m.is_dir() })
    }
}

/// A host key: its file, algorithm and (RSA) size.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostKey {
    pub path: String,
    pub algorithm: String,
    pub bits: Option<u32>,
}

/// An RSA public key's size from a `.pub` line (`ssh-rsa AAAA... comment`): the modulus's
/// length in the key blob (string "ssh-rsa", mpint e, mpint n).
pub fn rsa_bits(pub_line: &str) -> Option<u32> {
    use base64::Engine as _;
    fn field<'a>(b: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(b.get(*at..*at + 4)?.try_into().ok()?) as usize;
        let f = b.get(*at + 4..(*at + 4).checked_add(len)?)?;
        *at += 4 + len;
        Some(f)
    }
    let blob = pub_line.split_whitespace().nth(1)?;
    let b = base64::engine::general_purpose::STANDARD.decode(blob).ok()?;
    let mut at = 0usize;
    if field(&b, &mut at)? != b"ssh-rsa" {
        return None;
    }
    let _e = field(&b, &mut at)?;
    let n = field(&b, &mut at)?;
    let n = &n[n.iter().position(|&x| x != 0)?..];
    let lead = 8 - n[0].leading_zeros();
    Some((n.len() as u32 - 1) * 8 + lead)
}

/// Everything read from the host; `audit` judges it.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub installed: bool,
    pub version: Option<String>,
    /// `sshd -T` worked: the settings are sshd's own, not read from the files.
    pub exact: bool,
    pub global: Settings,
    /// Per user, with Match blocks (`sshd -T -C`, or the files' User/Group blocks).
    pub per_user: BTreeMap<String, Settings>,
    pub parsed: Parsed,
    pub accounts: Vec<Account>,
    pub groups: Vec<Group>,
    /// /etc/pam.d/su.
    pub pam_su: Option<String>,
    pub files: BTreeMap<String, FileInfo>,
    /// Contents of the gateway users' wrappers and key files.
    pub texts: BTreeMap<String, String>,
    pub host_keys: Vec<HostKey>,
    pub panel: Option<&'static str>,
    /// cloud-init is installed (`/etc/cloud/cloud.cfg.d`): it may write its sshd file again.
    pub cloud_init: bool,
    /// harden-vps.sh's rollback timers still armed (not committed).
    pub rollback_timers: Vec<String>,
    /// harden-vps.sh's backups (`/root/ssh-harden-*`).
    pub backups: Vec<String>,
    pub errors: Vec<String>,
}

impl Facts {
    fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.name == name)
    }

    /// Group names of an account (its primary group and those listing it).
    fn groups_of(&self, a: &Account) -> Vec<String> {
        let mut out: Vec<String> =
            self.groups.iter().filter(|g| g.gid == a.gid || g.members.contains(&a.name)).map(|g| g.name.clone()).collect();
        out.dedup();
        out
    }

    fn settings_for(&self, user: &str) -> &Settings {
        self.per_user.get(user).unwrap_or(&self.global)
    }

    /// Whether sshd lets `a` log in at all (AllowUsers/DenyUsers/AllowGroups/DenyGroups).
    fn allowed(&self, a: &Account) -> bool {
        let s = self.settings_for(&a.name);
        let groups = self.groups_of(a);
        if list(s, "denyusers").iter().any(|p| user_pattern_matches(p, &a.name)) {
            return false;
        }
        let allow = list(s, "allowusers");
        if !allow.is_empty() && !allow.iter().any(|p| user_pattern_matches(p, &a.name)) {
            return false;
        }
        if list(s, "denygroups").iter().any(|p| groups.iter().any(|g| glob(p, g))) {
            return false;
        }
        let allow_g = list(s, "allowgroups");
        allow_g.is_empty() || allow_g.iter().any(|p| groups.iter().any(|g| glob(p, g)))
    }

    /// The gateway users: the configured ones, else AllowUsers' plain names and the su
    /// group's members whose sessions get a ForceCommand.
    fn gateway_users(&self, cfg: &SshAuditCfg, su_group: &str) -> Vec<String> {
        if !cfg.gateway_users.is_empty() {
            return cfg.gateway_users.clone();
        }
        gateway_candidates(&self.global, &self.groups, su_group)
            .into_iter()
            .filter(|u| self.per_user.get(u).is_some_and(|s| !first(s, "forcecommand").eq_ignore_ascii_case("none")))
            .collect()
    }
}

/// AllowUsers' plain names (no patterns) and the su group's members.
fn gateway_candidates(global: &Settings, groups: &[Group], su_group: &str) -> Vec<String> {
    let mut out: Vec<String> = list(global, "allowusers")
        .iter()
        .map(|p| p.split_once('@').map_or(p.as_str(), |(u, _)| u).to_string())
        .filter(|u| !u.contains(['*', '?', '!']) && u != "root")
        .collect();
    if let Some(g) = groups.iter().find(|g| g.name == su_group) {
        out.extend(g.members.iter().cloned());
    }
    let mut seen = BTreeSet::new();
    out.retain(|u| seen.insert(u.clone()));
    out
}

/// pam_wheel in /etc/pam.d/su: an active `auth` line, and the group it names (None: the
/// default, wheel or gid 0).
pub fn pam_wheel(pam_su: &str) -> Option<Option<String>> {
    pam_su.lines().find_map(|l| {
        let l = l.trim();
        if l.starts_with('#') {
            return None;
        }
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.first() != Some(&"auth") || !w.iter().any(|x| x.ends_with("pam_wheel.so")) {
            return None;
        }
        // "trust" lets the group su without a password; "deny" inverts it: neither limits su
        if w.iter().any(|x| *x == "trust" || *x == "deny") {
            return None;
        }
        Some(w.iter().find_map(|x| x.strip_prefix("group=")).map(str::to_string))
    })
}

/// The key files sshd reads for an account (`AuthorizedKeysFile`, expanded).
fn key_files(s: &Settings, a: &Account) -> Vec<String> {
    let v = first(s, "authorizedkeysfile");
    if v.eq_ignore_ascii_case("none") {
        return vec![];
    }
    v.split_whitespace()
        .map(|f| {
            let f = f
                .replace("%%", "\u{0}")
                .replace("%h", &a.home)
                .replace("%u", &a.name)
                .replace("%U", &a.uid.to_string())
                .replace('\u{0}', "%");
            if f.starts_with('/') {
                f
            } else {
                format!("{}/{f}", a.home.trim_end_matches('/'))
            }
        })
        .collect()
}

/// The program a ForceCommand runs (None: internal-sftp, or nothing to check).
fn forced_program(cmd: &str) -> Option<&str> {
    let p = cmd.split_whitespace().next()?;
    (p.starts_with('/')).then_some(p)
}

/// Hosting panels, by a file each installs, and where they change sshd's settings.
const PANELS: [(&str, &str); 9] = [
    ("/usr/local/cpanel/version", "cPanel/WHM"),
    ("/usr/local/psa/version", "Plesk"),
    ("/usr/local/directadmin/directadmin", "DirectAdmin"),
    ("/usr/local/hestia/bin/v-list-sys-info", "HestiaCP"),
    ("/usr/local/vesta/bin/v-list-sys-info", "VestaCP"),
    ("/usr/local/CyberCP", "CyberPanel"),
    ("/www/server/panel/class", "aaPanel"),
    ("/usr/local/ispconfig/server", "ISPConfig"),
    ("/etc/webmin/miniserv.conf", "Webmin"),
];

fn panel_advice(panel: Option<&str>) -> String {
    match panel {
        Some("cPanel/WHM") => {
            " In WHM: Security Center > SSH Password Authorization Tweak turns passwords off; Manage root's SSH Keys adds the key first."
                .into()
        }
        Some("Plesk") => " Plesk leaves sshd_config to you: add root's key, then change the file.".into(),
        Some(p) => format!(" {p} may rewrite sshd_config: check its SSH settings too."),
        None => String::new(),
    }
}

/// A problem found, with how to fix it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    /// Stable: what `ignore` names, and what alerts are keyed by (`id` or `id:user`/`id:file`).
    pub id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(default)]
    pub fix: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SshAuditReport {
    pub read: Micros,
    /// sshd is installed (nothing to check otherwise).
    pub installed: bool,
    #[serde(default)]
    pub version: Option<String>,
    /// "standard", "gateway (user)", with the panel when there is one.
    #[serde(default)]
    pub layout: String,
    /// The settings are read from the files, not from `sshd -T` (it failed).
    #[serde(default)]
    pub approximate: bool,
    #[serde(default)]
    pub issues: Vec<Issue>,
    /// The watched settings, for reporting changes.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl SshAuditReport {
    fn count(&self, s: Severity) -> usize {
        self.issues.iter().filter(|i| i.severity == s).count()
    }

    /// One line for the dashboard, `status` and the digest.
    pub fn summary(&self) -> String {
        if !self.installed {
            return "sshd is not installed".into();
        }
        let mut parts = Vec::new();
        for (s, one) in [(Severity::High, "high"), (Severity::Warning, "warning"), (Severity::Info, "note")] {
            match self.count(s) {
                0 => {}
                1 => parts.push(format!("1 {one}")),
                n => parts.push(format!("{n} {one}s")),
            }
        }
        let found = if parts.is_empty() { "no problems".to_string() } else { parts.join(", ") };
        let approx = if self.approximate { ", read from the files (sshd -T failed)" } else { "" };
        format!("{}: {found}{approx}", self.layout)
    }

    /// The problems to act on (high and warnings), one line each, for the digest.
    pub fn concerns(&self) -> Vec<String> {
        self.issues.iter().filter(|i| i.severity >= Severity::Warning).map(|i| format!("ssh: {}", i.message)).collect()
    }

    pub fn worst(&self) -> Option<Severity> {
        self.issues.iter().map(|i| i.severity).max()
    }
}

/// Builds issues; `ignore`d ids are left out at the end.
struct Out {
    issues: Vec<Issue>,
}

impl Out {
    fn add(&mut self, id: impl Into<String>, severity: Severity, message: String, fix: impl Into<String>) {
        self.issues.push(Issue { id: id.into(), severity, message, fix: fix.into() });
    }
}

/// ", set in file:line" for a keyword's winning line (with the lines it overrides), or
/// ", the default". A value written otherwise than sshd shows it (`10m` for 600 seconds) is
/// quoted, so the line can be found: ", written `10m` in file:line".
fn from_where(f: &Facts, key: &str) -> String {
    match f.parsed.origin(key) {
        Some(o) => {
            let shadowed: Vec<String> = f.parsed.shadowed(key).iter().map(|o| format!("{} at {}", o.value, o.at)).collect();
            let ignored = if shadowed.is_empty() { String::new() } else { format!("; ignored: {}", shadowed.join(", ")) };
            let effective = first(&f.global, key);
            if o.value.eq_ignore_ascii_case(effective) {
                format!(", set in {}{ignored}", o.at)
            } else {
                format!(", written `{}` in {}{ignored}", o.value, o.at)
            }
        }
        None => ", the default".into(),
    }
}

/// The fix for a setting cloud-init wrote, when that is where it comes from.
fn cloud_init_note(f: &Facts, key: &str) -> &'static str {
    match f.parsed.origin(key) {
        Some(o) if (o.at.contains("cloud-init") || o.at.contains("cloudimg")) && f.cloud_init => {
            " cloud-init wrote that file and may write it again: delete it and set `ssh_pwauth: false` in /etc/cloud/cloud.cfg.d/99-no-passwords.cfg."
        }
        Some(o) if o.at.contains("cloud-init") || o.at.contains("cloudimg") => {
            " The image's cloud-init wrote that file; cloud-init isn't installed here, so deleting the file is enough."
        }
        _ => "",
    }
}

/// Why a file is too open: not owned by an allowed uid, or writable by group (other than
/// root's) or everyone.
fn loose(fi: &FileInfo, owners: &[u32]) -> Option<String> {
    if !owners.contains(&fi.uid) {
        return Some(format!("owned by uid {}", fi.uid));
    }
    if fi.mode & 0o002 != 0 {
        return Some("writable by everyone".into());
    }
    if fi.mode & 0o020 != 0 && fi.gid != 0 {
        return Some(format!("writable by group {}", fi.gid));
    }
    None
}

const WEAK_CIPHERS: [&str; 5] = ["cbc", "3des", "arcfour", "blowfish", "cast128"];
const WEAK_MACS: [&str; 4] = ["md5", "-96", "ripemd", "umac-32"];
const WEAK_KEX: [&str; 4] = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "gss-"];

fn weak<'a>(s: &'a Settings, key: &str, bad: &[&str]) -> Vec<&'a str> {
    let v = first(s, key);
    v.split(',')
        .filter(|a| {
            let a = a.to_ascii_lowercase();
            bad.iter().any(|b| a.contains(b)) && !(key == "kexalgorithms" && a.starts_with("gss-") && !a.contains("sha1"))
        })
        .collect()
}

/// Judges the facts: the problems, the layout, and the watched settings.
pub fn audit(f: &Facts, cfg: &SshAuditCfg, now: Micros) -> SshAuditReport {
    let mut r = SshAuditReport {
        read: now,
        installed: f.installed,
        version: f.version.clone(),
        approximate: f.installed && !f.exact,
        errors: f.errors.clone(),
        ..Default::default()
    };
    if !f.installed {
        r.layout = "no sshd".into();
        return r;
    }
    let su_group = match f.pam_su.as_deref().and_then(pam_wheel) {
        Some(Some(g)) => g,
        _ => cfg.su_group.clone(),
    };
    let gw_users = f.gateway_users(cfg, &su_group);
    let gateway = match cfg.profile {
        Profile::Gateway => true,
        Profile::Standard => false,
        Profile::Auto => {
            !gw_users.is_empty()
                || (!list(&f.global, "allowusers").is_empty()
                    && root_login(f.settings_for("root")) == "no"
                    && f.pam_su.as_deref().and_then(pam_wheel).is_some()
                    && f.groups.iter().any(|g| g.name == su_group))
        }
    };
    let users: Vec<String> = match (gateway, gw_users.is_empty()) {
        (false, _) => vec![],
        (true, true) => gateway_candidates(&f.global, &f.groups, &su_group).into_iter().filter(|u| f.account(u).is_some()).collect(),
        (true, false) => gw_users,
    };
    let mut out = Out { issues: vec![] };
    general_checks(f, gateway, &users, &mut out);
    if gateway {
        gateway_checks(f, &users, &su_group, &mut out);
        r.layout = match users.len() {
            0 => "gateway (no gateway user found)".into(),
            1 => format!("gateway ({})", users[0]),
            n => format!("gateway ({n} users)"),
        };
        for u in &users {
            let s = f.settings_for(u);
            for k in WATCHED_PER_USER {
                r.settings.insert(format!("{u}:{k}"), list(s, k).join(" "));
            }
        }
        r.settings
            .insert("pam_wheel".into(), f.pam_su.as_deref().and_then(pam_wheel).map_or("off".into(), |g| g.unwrap_or("wheel".into())));
        let members = f.groups.iter().find(|g| g.name == su_group).map(|g| g.members.join(",")).unwrap_or_default();
        r.settings.insert(format!("group {su_group}"), members);
    } else {
        r.layout = "standard".into();
    }
    if let Some(p) = f.panel {
        r.layout += &format!(", {p}");
    }
    for k in WATCHED {
        let v = match f.global.get(k) {
            Some(v) => v.join(" "),
            None => default_of(k).to_string(),
        };
        r.settings.insert(k.to_string(), v);
    }
    let ignored = |id: &str| cfg.ignore.iter().any(|i| id == i || id.strip_prefix(i.as_str()).is_some_and(|rest| rest.starts_with(':')));
    out.issues.retain(|i| !ignored(&i.id));
    out.issues.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| b.severity.cmp(&a.severity)));
    out.issues.dedup_by(|a, b| a.id == b.id);
    out.issues.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    r.issues = out.issues;
    r
}

/// Checks for every layout; `gateway_users`' key files are the gateway checks' business.
fn general_checks(f: &Facts, gateway: bool, gateway_users: &[String], out: &mut Out) {
    let g = &f.global;
    let panel = panel_advice(f.panel);
    let root = f.account("root");
    let root_s = f.settings_for("root");
    let root_allowed = root.is_some_and(|a| f.allowed(a));
    let rl = root_login(root_s);

    // root
    if root_allowed && rl == "yes" && password_alone(root_s) && root.is_some_and(|a| a.password != Password::Locked) {
        out.add(
            "root-password",
            Severity::High,
            format!("root can log in with a password from the internet (PermitRootLogin yes{})", from_where(f, "permitrootlogin")),
            format!(
                "add a key for root (or an admin user), then `PermitRootLogin prohibit-password` (or `no`) and `PasswordAuthentication no`.{panel}"
            ),
        );
    } else if root_allowed && rl == "yes" && !gateway {
        out.add(
            "root-login",
            Severity::Info,
            "PermitRootLogin yes: only keys work now, but turning passwords on would let root in with one".into(),
            "`PermitRootLogin prohibit-password`",
        );
    }

    // passwords
    let pw_accounts: Vec<&str> = f
        .accounts
        .iter()
        .filter(|a| matches!(a.password, Password::Set | Password::Empty) && f.allowed(a) && password_alone(f.settings_for(&a.name)))
        .filter(|a| a.name != "root" || rl == "yes")
        .map(|a| a.name.as_str())
        .collect();
    if password_alone(g) {
        let key = if yes(g, "passwordauthentication") { "passwordauthentication" } else { "kbdinteractiveauthentication" };
        let unknown = f.accounts.iter().any(|a| a.password == Password::Unknown);
        let who = if pw_accounts.is_empty() && unknown {
            "which accounts have one isn't known (/etc/shadow unreadable: run as root)".to_string()
        } else if pw_accounts.is_empty() {
            "no account that may log in has a password now".to_string()
        } else {
            let more = if pw_accounts.len() > 10 { ", ..." } else { "" };
            format!("accounts with a password: {}{more}", pw_accounts.iter().take(10).copied().collect::<Vec<_>>().join(", "))
        };
        let how = if key == "passwordauthentication" {
            "PasswordAuthentication yes".to_string()
        } else {
            "KbdInteractiveAuthentication with UsePAM: PAM asks for the password".to_string()
        };
        let severity = if gateway {
            Severity::High
        } else if pw_accounts.is_empty() && !unknown {
            Severity::Info
        } else {
            Severity::Warning
        };
        out.add(
            "password-auth",
            severity,
            format!("sshd accepts passwords ({how}{}); {who}", from_where(f, key)),
            format!(
                "with keys in place: `PasswordAuthentication no` and `KbdInteractiveAuthentication no` (or `AuthenticationMethods publickey`).{}{panel}",
                cloud_init_note(f, key)
            ),
        );
    }
    if yes(g, "permitemptypasswords") {
        let empty: Vec<&str> =
            f.accounts.iter().filter(|a| a.password == Password::Empty && f.allowed(a)).map(|a| a.name.as_str()).collect();
        let (severity, who) = if empty.is_empty() || !password_alone(g) {
            (Severity::Warning, String::new())
        } else {
            (Severity::High, format!(": {} can log in without any password", empty.join(", ")))
        };
        out.add(
            "empty-passwords",
            severity,
            format!("PermitEmptyPasswords yes{}{who}", from_where(f, "permitemptypasswords")),
            "`PermitEmptyPasswords no`",
        );
    }
    for a in f.accounts.iter().filter(|a| a.uid == 0 && a.name != "root") {
        out.add(
            format!("uid0:{}", a.name),
            Severity::High,
            format!("account {} has uid 0: it is root under another name", a.name),
            "remove it (`userdel`) unless you made it on purpose",
        );
    }

    // logging: logguard reads sshd's failed logins
    let level = first(g, "loglevel").to_ascii_uppercase();
    if matches!(level.as_str(), "QUIET" | "FATAL" | "ERROR") {
        out.add(
            "log-level",
            Severity::Warning,
            format!("LogLevel {level}{}: sshd doesn't log failed logins, logguard can't see or ban them", from_where(f, "loglevel")),
            "`LogLevel VERBOSE` (or INFO)",
        );
    }
    if first(g, "strictmodes").eq_ignore_ascii_case("no") {
        out.add(
            "strict-modes",
            Severity::Warning,
            format!("StrictModes no{}: sshd uses key files that others can write", from_where(f, "strictmodes")),
            "`StrictModes yes`",
        );
    }
    if first(g, "maxauthtries").parse::<u32>().is_ok_and(|n| n > 6) {
        out.add(
            "max-auth-tries",
            Severity::Info,
            format!("MaxAuthTries {}{}: many guesses per connection", first(g, "maxauthtries"), from_where(f, "maxauthtries")),
            "`MaxAuthTries 3`",
        );
    }
    if first(g, "logingracetime").parse::<u32>().is_ok_and(|n| n == 0 || n > 300) {
        out.add(
            "login-grace",
            Severity::Info,
            format!(
                "LoginGraceTime {}s{}: unauthenticated connections are held long",
                first(g, "logingracetime"),
                from_where(f, "logingracetime")
            ),
            "`LoginGraceTime 30s`",
        );
    }
    if yes(g, "hostbasedauthentication") || first(g, "ignorerhosts").eq_ignore_ascii_case("no") {
        out.add(
            "host-based",
            Severity::Warning,
            "host-based authentication or .rhosts files are trusted".into(),
            "`HostbasedAuthentication no` and `IgnoreRhosts yes`",
        );
    }
    if !first(g, "permituserenvironment").eq_ignore_ascii_case("no") {
        out.add(
            "user-environment",
            Severity::Warning,
            "PermitUserEnvironment: users' ~/.ssh/environment can set LD_PRELOAD and the like for sshd's children".into(),
            "`PermitUserEnvironment no`",
        );
    }
    if !gateway {
        let gp = first(g, "gatewayports");
        if !gp.eq_ignore_ascii_case("no") {
            out.add(
                "gateway-ports",
                Severity::Warning,
                format!("GatewayPorts {gp}: remote forwards can listen on public addresses"),
                "`GatewayPorts no`",
            );
        }
        if yes(g, "x11forwarding") {
            out.add(
                "x11-forwarding",
                Severity::Info,
                format!("X11Forwarding yes{}: rarely needed on a server", from_where(f, "x11forwarding")),
                "`X11Forwarding no`",
            );
        }
        if !first(g, "permittunnel").eq_ignore_ascii_case("no") {
            out.add("permit-tunnel", Severity::Info, "PermitTunnel: users can open tun/tap devices".into(), "`PermitTunnel no`");
        }
    }
    if !first(g, "authorizedkeyscommand").eq_ignore_ascii_case("none") {
        out.add(
            "keys-command",
            Severity::Info,
            format!("keys also come from AuthorizedKeysCommand {}", first(g, "authorizedkeyscommand")),
            "make sure that program and what it reads are root's only",
        );
    }

    // crypto
    for (id, key, bad, what) in [
        ("weak-ciphers", "ciphers", &WEAK_CIPHERS[..], "ciphers"),
        ("weak-macs", "macs", &WEAK_MACS[..], "MACs"),
        ("weak-kex", "kexalgorithms", &WEAK_KEX[..], "key exchanges"),
    ] {
        let w = weak(g, key, bad);
        if !w.is_empty() {
            out.add(
                id,
                Severity::Warning,
                format!("weak {what} allowed: {}", w.join(", ")),
                format!("remove them from {} (or the line, for OpenSSH's defaults)", key),
            );
        }
    }
    for k in &f.host_keys {
        match (k.algorithm.as_str(), k.bits) {
            ("ssh-dss", _) => out.add(
                format!("host-key-dsa:{}", k.path),
                Severity::Warning,
                format!("DSA host key {} (broken; OpenSSH 9.8 dropped it)", k.path),
                "remove its HostKey line",
            ),
            ("ssh-rsa", Some(b)) if b < 2048 => out.add(
                format!("host-key-size:{}", k.path),
                Severity::Warning,
                format!("RSA host key {} has {b} bits", k.path),
                "a new one: `ssh-keygen -t rsa -b 4096 -f` it, or use the ed25519 key only",
            ),
            _ => {}
        }
    }

    // files: the config, the host keys, the key files
    let ssh_keys_gid = f.groups.iter().find(|g| g.name == "ssh_keys").map(|g| g.gid);
    for path in f.parsed.files.iter().map(String::as_str).chain(["/etc/ssh", "/etc/ssh/sshd_config.d"]) {
        if let Some(why) = f.files.get(path).and_then(|fi| loose(fi, &[0])) {
            out.add(
                format!("config-perms:{path}"),
                Severity::High,
                format!("{path} is {why}: whoever can write it decides who logs in"),
                format!("`chown root:root {path}; chmod go-w {path}`"),
            );
        }
    }
    for path in list(g, "hostkey") {
        let Some(fi) = f.files.get(path.as_str()) else { continue };
        let group_ok = fi.mode & 0o070 == 0 || (Some(fi.gid) == ssh_keys_gid && fi.mode & 0o030 == 0);
        if fi.uid != 0 || fi.mode & 0o007 != 0 || !group_ok {
            let severity = if fi.mode & 0o004 != 0 || fi.uid != 0 { Severity::High } else { Severity::Warning };
            out.add(
                format!("host-key-perms:{path}"),
                severity,
                format!(
                    "host key {path} is readable by others (mode {:o}, uid {}): whoever reads it can pose as this server",
                    fi.mode, fi.uid
                ),
                format!("`chown root:root {path}; chmod 600 {path}` (then new host keys: it may have been copied)"),
            );
        }
    }
    let mut checked = 0;
    for a in &f.accounts {
        if checked >= MAX_ACCOUNTS {
            break;
        }
        if !(a.login_shell() || a.uid == 0) || !f.allowed(a) || !keys_allowed(f.settings_for(&a.name)) {
            continue;
        }
        if (a.name == "root" && rl == "no") || gateway_users.contains(&a.name) {
            continue;
        }
        checked += 1;
        let s = f.settings_for(&a.name);
        let strict = !first(s, "strictmodes").eq_ignore_ascii_case("no");
        for path in key_files(s, a) {
            let Some(fi) = f.files.get(&path) else { continue };
            let parent = Path::new(&path).parent().map(|p| p.display().to_string()).unwrap_or_default();
            let checks = [(path.as_str(), Some(fi)), (parent.as_str(), f.files.get(&parent))];
            for (p, info) in checks {
                let Some(why) = info.and_then(|i| loose(i, &[0, a.uid])) else { continue };
                // with StrictModes sshd refuses such files: then it's a broken login, not a hole
                let severity = if !strict || a.uid == 0 { Severity::High } else { Severity::Warning };
                out.add(
                    format!("key-file-perms:{p}"),
                    severity,
                    format!("{p} ({}'s keys) is {why}: others can add keys to log in as {}", a.name, a.name),
                    format!("`chmod go-w {p}`"),
                );
            }
        }
    }

    // harden-vps.sh's leftovers
    for t in &f.rollback_timers {
        out.add(
            format!("rollback-armed:{t}"),
            Severity::Warning,
            format!("harden-vps.sh's rollback timer {t} is armed: the old sshd config comes back when it fires"),
            format!("if the new login works: `systemctl stop {t}`; else let it roll back and run harden-vps.sh again"),
        );
    }
    for b in &f.backups {
        if f.files.get(b).is_some_and(|fi| fi.uid != 0 || fi.mode & 0o077 != 0) {
            out.add(
                format!("backup-perms:{b}"),
                Severity::Warning,
                format!("{b} (harden-vps.sh's backup of the old sshd config) is readable by others"),
                format!("`chmod 700 {b}`, or delete it once the new login has worked for a while"),
            );
        }
    }
}

fn gateway_checks(f: &Facts, users: &[String], su_group: &str, out: &mut Out) {
    let g = &f.global;
    if users.is_empty() {
        out.add(
            "gateway-users",
            Severity::High,
            "profile is gateway, but AllowUsers names no gateway user and none has a ForceCommand".into(),
            "set [ssh_audit] gateway_users, or AllowUsers and a `Match User` block with the ForceCommand",
        );
    }
    let root_s = f.settings_for("root");
    if f.account("root").is_some_and(|a| f.allowed(a)) && root_login(root_s) != "no" {
        out.add(
            "gateway-root-login",
            Severity::High,
            format!(
                "root may log in directly (PermitRootLogin {}{}), around the gateway",
                root_login(root_s),
                from_where(f, "permitrootlogin")
            ),
            "`PermitRootLogin no`",
        );
    }
    let allow = list(g, "allowusers");
    if allow.is_empty() && list(g, "allowgroups").is_empty() {
        out.add(
            "gateway-allowusers",
            Severity::High,
            "no AllowUsers: every account with a key (or a password) can log in, not only the gateway".into(),
            format!("`AllowUsers {}`", users.join(" ")),
        );
    } else {
        let others: Vec<&str> = f
            .accounts
            .iter()
            .filter(|a| a.name != "root" && !users.contains(&a.name) && f.allowed(a) && a.login_shell())
            .map(|a| a.name.as_str())
            .collect();
        if !others.is_empty() {
            out.add(
                "gateway-other-users",
                Severity::Warning,
                format!("besides the gateway, sshd lets in: {}", others.join(", ")),
                "AllowUsers with the gateway user(s) only",
            );
        }
    }
    match f.pam_su.as_deref().map(pam_wheel) {
        None => {}
        Some(None) => out.add(
            "gateway-pam-wheel",
            Severity::High,
            "su isn't limited by pam_wheel: any account that learns root's password can become root".into(),
            format!("in /etc/pam.d/su after pam_rootok: `auth required pam_wheel.so group={su_group}`"),
        ),
        Some(Some(_)) => {}
    }
    let su = f.groups.iter().find(|x| x.name == su_group);
    match su {
        None if f.pam_su.as_deref().and_then(pam_wheel).is_some_and(|g| g.is_some()) => out.add(
            "gateway-su-group",
            Severity::High,
            format!("pam_wheel names group {su_group}, which doesn't exist: nobody can su to root"),
            format!("`groupadd {su_group}; usermod -aG {su_group} <gateway user>`"),
        ),
        Some(grp) => {
            let extra: Vec<&str> = grp.members.iter().filter(|m| !users.contains(m)).map(String::as_str).collect();
            if !extra.is_empty() {
                out.add(
                    "gateway-su-members",
                    Severity::Warning,
                    format!("group {su_group} (may su to root) also has: {}", extra.join(", ")),
                    format!("`gpasswd -d <user> {su_group}` unless intended"),
                );
            }
        }
        None => {}
    }
    if f.account("root").is_some_and(|a| a.password == Password::Locked) {
        out.add(
            "gateway-root-password",
            Severity::Warning,
            "root has no password: the su stage can't work, the gateway leads nowhere".into(),
            "`passwd root` (a long random one, in your password manager)",
        );
    }

    let sudo_groups: Vec<&Group> = f.groups.iter().filter(|x| matches!(x.name.as_str(), "sudo" | "wheel" | "admin")).collect();
    for u in users {
        let Some(a) = f.account(u) else {
            out.add(
                format!("gateway-user:{u}"),
                Severity::Warning,
                format!("gateway user {u} doesn't exist"),
                "fix gateway_users or AllowUsers",
            );
            continue;
        };
        let s = f.settings_for(u);
        if password_alone(s) {
            out.add(
                format!("gateway-passwords:{u}"),
                Severity::High,
                format!("{u} can log in with a password, not only a key"),
                "`AuthenticationMethods publickey`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`",
            );
        }
        if a.password == Password::Set || a.password == Password::Empty {
            out.add(
                format!("gateway-user-password:{u}"),
                Severity::Warning,
                format!("gateway user {u} has a password (harden-vps.sh locks it)"),
                format!("`usermod -p '*' {u}`"),
            );
        }
        if sudo_groups.iter().any(|x| x.members.contains(u) || x.gid == a.gid) {
            out.add(
                format!("gateway-sudo:{u}"),
                Severity::High,
                format!("gateway user {u} is in a sudo group: a stolen key is root without the su stage"),
                format!("`gpasswd -d {u} sudo` (or wheel)"),
            );
        }
        let fc = first(s, "forcecommand");
        if fc.eq_ignore_ascii_case("none") {
            out.add(
                format!("gateway-forcecommand:{u}"),
                Severity::High,
                format!("{u}'s sessions aren't forced into the wrapper: a key gives a full shell"),
                format!("`Match User {u}` with `ForceCommand /usr/local/bin/gateway-shell`"),
            );
        } else if let Some(prog) = forced_program(fc) {
            match f.files.get(prog) {
                None => out.add(
                    format!("gateway-wrapper:{u}"),
                    Severity::High,
                    format!("{u}'s ForceCommand {prog} doesn't exist: every login fails"),
                    "reinstall the wrapper (harden-vps.sh step 6)",
                ),
                Some(fi) => {
                    let dir = Path::new(prog).parent().map(|d| d.display().to_string()).unwrap_or_default();
                    for (p, info) in [(prog, Some(fi)), (dir.as_str(), f.files.get(&dir))] {
                        if let Some(why) = info.and_then(|i| loose(i, &[0])) {
                            out.add(
                                format!("gateway-wrapper-perms:{p}"),
                                Severity::High,
                                format!("{p} ({u}'s forced command) is {why}: whoever changes it gets {u}'s logins"),
                                format!("`chown root:root {p}; chmod go-w {p}`"),
                            );
                        }
                    }
                    if let Some(text) = f.texts.get(prog) {
                        let execs: Vec<&str> = text
                            .lines()
                            .map(str::trim)
                            .filter(|l| !l.starts_with('#'))
                            .filter_map(|l| l.split_once("exec ").map(|(_, rest)| rest.split_whitespace().next().unwrap_or("")))
                            .filter(|p| !(p.ends_with("/su") || p.ends_with("sftp-server") || p.is_empty()))
                            .collect();
                        if !execs.is_empty() {
                            out.add(
                                format!("gateway-wrapper-exec:{u}"),
                                Severity::Warning,
                                format!("{prog} runs more than su and sftp: {}", execs.join(", ")),
                                "only `exec /bin/su - root` and the sftp server",
                            );
                        }
                    }
                }
            }
        }
        if !keys_allowed(s) {
            out.add(
                format!("gateway-no-keys:{u}"),
                Severity::Warning,
                format!("{u} can't log in with a key"),
                "`PubkeyAuthentication yes`",
            );
        }
        for path in key_files(s, a) {
            let in_home = path.starts_with(&format!("{}/", a.home.trim_end_matches('/')));
            let Some(fi) = f.files.get(&path) else { continue };
            if in_home || fi.uid == a.uid {
                out.add(
                    format!("gateway-keys-owner:{u}"),
                    Severity::Warning,
                    format!("{u}'s keys are in {path}, which {u} can change: one stolen key adds others"),
                    "`AuthorizedKeysFile /etc/ssh/authorized_keys/%u`, root-owned, mode 644",
                );
            } else if let Some(why) = loose(fi, &[0]) {
                out.add(
                    format!("gateway-keys-perms:{path}"),
                    Severity::High,
                    format!("{path} ({u}'s keys) is {why}"),
                    format!("`chown root:root {path}; chmod 644 {path}`"),
                );
            }
            if let Some(text) = f.texts.get(&path) {
                let keys: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
                let unrestricted =
                    keys.iter().filter(|l| !l.split_whitespace().next().is_some_and(|o| o.split(',').any(|x| x == "restrict"))).count();
                if unrestricted > 0 {
                    out.add(
                        format!("gateway-key-options:{u}"),
                        Severity::Warning,
                        format!("{unrestricted} of {u}'s keys in {path} have no `restrict` option"),
                        "start each line with `restrict,pty` (plus `port-forwarding,permitopen=\"127.0.0.1:PORT\"` for tunnels)",
                    );
                }
            }
        }
        let fwd = first(s, "allowtcpforwarding").to_ascii_lowercase();
        let open = first(s, "permitopen").to_ascii_lowercase();
        if matches!(fwd.as_str(), "yes" | "all" | "remote") {
            out.add(
                format!("gateway-forwarding:{u}"),
                Severity::Warning,
                format!("{u} may forward ports both ways (AllowTcpForwarding {fwd})"),
                "`AllowTcpForwarding local` with `PermitOpen 127.0.0.1:PORT`, or `no`",
            );
        } else if fwd == "local"
            && (open == "any" || open.split_whitespace().any(|t| !t.starts_with("127.0.0.1:") && !t.starts_with("localhost:")))
        {
            out.add(
                format!("gateway-permitopen:{u}"),
                Severity::Warning,
                format!("{u}'s tunnels may reach other hosts (PermitOpen {open})"),
                "`PermitOpen 127.0.0.1:PORT ...` for the panels it needs",
            );
        }
        let mut extras = Vec::new();
        if yes(s, "x11forwarding") {
            extras.push("X11Forwarding");
        }
        if yes(s, "allowagentforwarding") {
            extras.push("AllowAgentForwarding");
        }
        if !first(s, "allowstreamlocalforwarding").eq_ignore_ascii_case("no") {
            extras.push("AllowStreamLocalForwarding");
        }
        if !first(s, "permittunnel").eq_ignore_ascii_case("no") {
            extras.push("PermitTunnel");
        }
        if !first(s, "gatewayports").eq_ignore_ascii_case("no") {
            extras.push("GatewayPorts");
        }
        if !extras.is_empty() {
            out.add(
                format!("gateway-extras:{u}"),
                Severity::Warning,
                format!("{u} may also use {}", extras.join(", ")),
                format!("{} no", extras.join(" no, ")),
            );
        }
        // the home: root's, only ~/xfer writable
        if let Some(home) = f.files.get(&a.home) {
            let writable = home.uid == a.uid || home.mode & 0o002 != 0 || (home.mode & 0o020 != 0 && home.gid == a.gid);
            if writable {
                out.add(
                    format!("gateway-home:{u}"),
                    Severity::Warning,
                    format!("{u} can write its home {}: it can plant ~/.ssh and dotfiles", a.home),
                    format!("`chown root:{u} {h}; chmod 750 {h}` with only {h}/xfer {u}'s own", h = a.home),
                );
            }
        }
    }
    let ports = list(g, "port");
    if ports.iter().all(|p| p == "22") {
        out.add(
            "gateway-port",
            Severity::Info,
            "sshd listens on port 22 (bots try it all day)".into(),
            "another port, as harden-vps.sh -p does",
        );
    }
}

/// `sshd -T` (with `-C spec`), run as it is.
fn sshd_settings(cfg: &SshAuditCfg, spec: Option<&str>) -> Result<Settings, String> {
    let mut cmd = Command::new(&cfg.sshd);
    cmd.arg("-T").arg("-f").arg(&cfg.config).env("LC_ALL", "C");
    if let Some(s) = spec {
        cmd.arg("-C").arg(s);
    }
    let out = crate::proc::run(cmd, None, Duration::from_secs(20))?;
    if !out.status.success() {
        return Err(format!("{} -T: {}", cfg.sshd.display(), crate::event::clean(&out.complaint(), 200)));
    }
    let s = parse_settings(&String::from_utf8_lossy(&out.stdout));
    if s.is_empty() {
        return Err(format!("{} -T printed no settings", cfg.sshd.display()));
    }
    Ok(s)
}

/// The OpenSSH version: `sshd -V` (older versions print it with their usage).
fn sshd_version(cfg: &SshAuditCfg) -> Option<String> {
    let mut cmd = Command::new(&cfg.sshd);
    cmd.arg("-V");
    let out = crate::proc::run(cmd, None, Duration::from_secs(10)).ok()?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stderr), String::from_utf8_lossy(&out.stdout));
    text.split_whitespace().find(|w| w.starts_with("OpenSSH_")).map(|w| crate::event::clean(w.trim_end_matches(','), 40))
}

fn read_small(path: &str) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(f, 256 << 10), &mut s).ok()?;
    Some(s)
}

/// Reads everything `audit` needs from this host.
pub fn collect(cfg: &SshAuditCfg) -> Facts {
    let mut f = Facts { installed: cfg.sshd.exists(), ..Default::default() };
    if !f.installed {
        return f;
    }
    f.version = sshd_version(cfg);
    f.parsed = parse_config(&cfg.config);
    f.errors.extend(f.parsed.errors.iter().cloned());
    match sshd_settings(cfg, None) {
        Ok(s) => {
            f.global = s;
            f.exact = true;
        }
        Err(e) => {
            f.errors.push(e);
            f.global = f.parsed.effective();
        }
    }
    let passwd = std::fs::read_to_string(&cfg.passwd).unwrap_or_default();
    let shadow = std::fs::read_to_string(&cfg.shadow).ok();
    if shadow.is_none() {
        f.errors.push(format!("{}: unreadable (run as root): passwords not judged", cfg.shadow.display()));
    }
    f.accounts = parse_passwd(&passwd, shadow.as_deref());
    f.groups = parse_groups(&std::fs::read_to_string(&cfg.group).unwrap_or_default());
    f.pam_su = std::fs::read_to_string(&cfg.pam_su).ok();

    let su_group = match f.pam_su.as_deref().and_then(pam_wheel) {
        Some(Some(g)) => g,
        _ => cfg.su_group.clone(),
    };
    let mut users = vec!["root".to_string()];
    users.extend(cfg.gateway_users.iter().cloned());
    users.extend(gateway_candidates(&f.global, &f.groups, &su_group));
    let mut seen = BTreeSet::new();
    users.retain(|u| seen.insert(u.clone()));
    for u in users.into_iter().take(MAX_USERS) {
        let Some(a) = f.account(&u).cloned() else { continue };
        let s = if f.exact {
            match sshd_settings(cfg, Some(&format!("user={u},host=unknown.invalid,addr={INTERNET_ADDR}"))) {
                Ok(s) => s,
                Err(e) => {
                    f.errors.push(format!("for {u}: {e}"));
                    continue;
                }
            }
        } else {
            let groups = f.groups_of(&a);
            f.parsed.effective_for(&u, &groups)
        };
        f.per_user.insert(u, s);
    }

    // files to check
    let mut paths: Vec<String> = f.parsed.files.clone();
    paths.extend(["/etc/ssh".to_string(), "/etc/ssh/sshd_config.d".to_string()]);
    for k in list(&f.global, "hostkey") {
        paths.push(k.clone());
        if let Some(line) = read_small(&format!("{k}.pub")) {
            let algorithm = line.split_whitespace().next().unwrap_or("").to_string();
            let bits = if algorithm == "ssh-rsa" { rsa_bits(&line) } else { None };
            f.host_keys.push(HostKey { path: k.clone(), algorithm, bits });
        }
    }
    let gw = f.gateway_users(cfg, &su_group);
    let gw_or_candidates =
        if gw.is_empty() && cfg.profile != Profile::Standard { gateway_candidates(&f.global, &f.groups, &su_group) } else { gw };
    let mut texts = BTreeMap::new();
    for a in f.accounts.iter().filter(|a| a.login_shell() || a.uid == 0).take(MAX_ACCOUNTS) {
        for p in key_files(f.settings_for(&a.name), a) {
            if let Some(dir) = Path::new(&p).parent() {
                paths.push(dir.display().to_string());
            }
            if gw_or_candidates.contains(&a.name) {
                if let Some(t) = read_small(&p) {
                    texts.insert(p.clone(), t);
                }
            }
            paths.push(p);
        }
    }
    for u in &gw_or_candidates {
        let Some(a) = f.account(u) else { continue };
        paths.push(a.home.clone());
        if let Some(prog) = forced_program(first(f.settings_for(u), "forcecommand")) {
            paths.push(prog.to_string());
            if let Some(dir) = Path::new(prog).parent() {
                paths.push(dir.display().to_string());
            }
            if let Some(t) = read_small(prog) {
                texts.insert(prog.to_string(), t);
            }
        }
    }
    f.texts = texts;
    if let Ok(rd) = std::fs::read_dir("/root") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("ssh-harden-") {
                let p = format!("/root/{n}");
                paths.push(p.clone());
                f.backups.push(p);
            }
        }
        f.backups.sort();
    }
    if let Ok(rd) = std::fs::read_dir("/run/systemd/transient") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("ssh-harden-rollback-") && n.ends_with(".timer") {
                f.rollback_timers.push(crate::event::clean(&n, 80));
            }
        }
        f.rollback_timers.sort();
    }
    for p in paths {
        if let Some(fi) = FileInfo::of(&p) {
            f.files.insert(p, fi);
        }
    }
    f.panel = PANELS.iter().find(|(p, _)| Path::new(p).exists()).map(|(_, name)| *name);
    f.cloud_init = Path::new("/etc/cloud/cloud.cfg.d").is_dir();
    f
}

/// Reads and judges this host.
pub fn scan(cfg: &SshAuditCfg, now: Micros) -> SshAuditReport {
    audit(&collect(cfg), cfg, now)
}

/// What was reported before: open problems and the watched settings.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SshAuditBaseline {
    pub issues: BTreeMap<String, Severity>,
    pub settings: BTreeMap<String, String>,
    /// When open high problems were last told (the first report, or a reminder).
    #[serde(default)]
    pub reminded: Micros,
}

fn line(i: &Issue) -> String {
    let sev = match i.severity {
        Severity::Info => "note",
        Severity::Warning => "warning",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    };
    if i.fix.is_empty() {
        format!("{sev}: {}", i.message)
    } else {
        format!("{sev}: {} - fix: {}", i.message, i.fix)
    }
}

/// Compares a reading with what was reported before, and says what to tell the admins: all
/// problems at the first reading; then new (or worse) ones with the settings that changed,
/// changed settings alone, fixed problems, and open high ones again every `remind`.
pub fn judge(baseline: &mut Option<SshAuditBaseline>, r: &SshAuditReport, cfg: &SshAuditCfg) -> Vec<Finding> {
    let now = r.read;
    let finding = |key: String, severity, message: String, evidence: Vec<String>, notify| Finding {
        key,
        every: 0,
        severity,
        message,
        evidence,
        notify,
        owner: None,
        files: vec![],
    };
    let mut out = Vec::new();
    if !r.errors.is_empty() {
        out.push(Finding {
            every: 86_400 * time::SEC,
            ..finding(
                "ssh-audit-errors".into(),
                if r.approximate { Severity::Warning } else { Severity::Info },
                format!("SSH audit: {}", r.errors.join("; ")),
                vec![],
                r.approximate,
            )
        });
    }
    if !r.installed {
        *baseline = None;
        return out;
    }
    let issues: BTreeMap<String, &Issue> = r.issues.iter().map(|i| (i.id.clone(), i)).collect();
    let high: Vec<&Issue> = r.issues.iter().filter(|i| i.severity >= Severity::High).collect();
    let Some(b) = baseline.as_mut() else {
        let worst = r.worst().unwrap_or(Severity::Info);
        let shown: Vec<&Issue> = r.issues.iter().filter(|i| i.severity >= Severity::Warning).collect();
        let message = if shown.is_empty() {
            format!("SSH audit ({}): no problems", r.layout)
        } else {
            format!("SSH audit ({}): {}", r.layout, shown.iter().map(|i| i.message.as_str()).take(3).collect::<Vec<_>>().join("; "))
        };
        out.push(finding(format!("ssh-audit-first:{now}"), worst, message, r.issues.iter().map(line).collect(), !shown.is_empty()));
        *baseline = Some(SshAuditBaseline {
            issues: r.issues.iter().map(|i| (i.id.clone(), i.severity)).collect(),
            settings: r.settings.clone(),
            reminded: now,
        });
        return out;
    };

    let changes: Vec<String> = r
        .settings
        .iter()
        .filter_map(|(k, v)| match b.settings.get(k) {
            Some(old) if old != v => Some(format!("{k}: {} -> {}", shown(old), shown(v))),
            None if !b.settings.is_empty() && !v.is_empty() => Some(format!("{k}: {}", shown(v))),
            _ => None,
        })
        .chain(b.settings.keys().filter(|k| !r.settings.contains_key(*k)).map(|k| format!("{k}: gone")))
        .collect();
    let new: Vec<&Issue> = r.issues.iter().filter(|i| b.issues.get(&i.id).is_none_or(|old| *old < i.severity)).collect();
    let fixed: Vec<&String> = b.issues.keys().filter(|id| !issues.contains_key(*id)).collect();
    let changed = |c: &[String]| c.iter().map(|c| format!("changed: {c}")).collect::<Vec<_>>();

    if !new.is_empty() {
        let worst = new.iter().map(|i| i.severity).max().unwrap_or(Severity::Info);
        let mut evidence: Vec<String> = new.iter().map(|i| line(i)).collect();
        evidence.extend(changed(&changes));
        let what = new.iter().map(|i| i.message.as_str()).take(3).collect::<Vec<_>>().join("; ");
        let n = if new.len() == 1 { "new problem".to_string() } else { format!("{} new problems", new.len()) };
        out.push(finding(format!("ssh-audit-new:{now}"), worst, format!("SSH audit: {n}: {what}"), evidence, worst >= Severity::Warning));
    } else if !changes.is_empty() && fixed.is_empty() {
        out.push(finding(
            format!("ssh-audit-changed:{now}"),
            Severity::Info,
            format!("sshd settings changed, no new problems: {}", changes.iter().take(4).cloned().collect::<Vec<_>>().join("; ")),
            changed(&changes),
            true,
        ));
    }
    if !fixed.is_empty() {
        let names: Vec<&str> = fixed.iter().map(|s| s.as_str()).collect();
        out.push(finding(
            format!("ssh-audit-fixed:{now}"),
            Severity::Info,
            format!("SSH audit: fixed: {}", names.join(", ")),
            if new.is_empty() { changed(&changes) } else { vec![] },
            b.issues.iter().any(|(id, s)| fixed.contains(&id) && *s >= Severity::Warning),
        ));
    }
    let remind = cfg.remind.micros();
    if remind > 0 && !high.is_empty() && new.is_empty() && now - b.reminded >= remind {
        out.push(finding(
            format!("ssh-audit-remind:{now}"),
            Severity::High,
            format!("SSH audit: still open: {}", high.iter().map(|i| i.message.as_str()).take(3).collect::<Vec<_>>().join("; ")),
            high.iter().map(|i| line(i)).collect(),
            true,
        ));
        b.reminded = now;
    }
    if !new.is_empty() && new.iter().any(|i| i.severity >= Severity::High) {
        b.reminded = now;
    }
    b.issues = r.issues.iter().map(|i| (i.id.clone(), i.severity)).collect();
    b.settings = r.settings.clone();
    out
}

fn shown(v: &str) -> &str {
    if v.is_empty() {
        "(none)"
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Micros = 1_800_000_000 * time::SEC;

    /// A fresh Debian 13 cloud image as most VPS providers hand it out: root with a password,
    /// cloud-init turning passwords on in front of sshd_config's own "no".
    fn cloud_vps() -> Facts {
        let mut parsed = Parsed::default();
        parse_config_text(
            "PasswordAuthentication yes\n",
            "/etc/ssh/sshd_config.d/50-cloud-init.conf",
            Path::new("/etc/ssh"),
            None,
            0,
            &mut parsed,
        );
        parse_config_text(
            "Include /nonexistent/*.conf\nPermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\n",
            "/etc/ssh/sshd_config",
            Path::new("/etc/ssh"),
            None,
            0,
            &mut parsed,
        );
        let global = parse_settings(
            "port 22\npermitrootlogin yes\npasswordauthentication yes\nkbdinteractiveauthentication no\nusepam yes\n\
             pubkeyauthentication yes\nauthenticationmethods any\nx11forwarding yes\nloglevel INFO\nstrictmodes yes\n\
             permituserenvironment no\ngatewayports no\npermittunnel no\nhostkey /etc/ssh/ssh_host_ed25519_key\n\
             authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n",
        );
        Facts {
            installed: true,
            exact: true,
            per_user: BTreeMap::from([("root".into(), global.clone())]),
            global,
            parsed,
            accounts: parse_passwd(
                "root:x:0:0:root:/root:/bin/bash\ndebian:x:1000:1000::/home/debian:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
                Some("root:$y$j9T$abc:20000::::::\ndebian:$y$j9T$def:20000::::::\nwww-data:*:20000::::::\n"),
            ),
            groups: parse_groups("root:x:0:\nsudo:x:27:debian\ndebian:x:1000:\n"),
            files: BTreeMap::from([
                ("/etc/ssh".into(), FileInfo { uid: 0, gid: 0, mode: 0o755, dir: true }),
                ("/etc/ssh/ssh_host_ed25519_key".into(), FileInfo { uid: 0, gid: 0, mode: 0o600, dir: false }),
                ("/root/.ssh/authorized_keys".into(), FileInfo { uid: 0, gid: 0, mode: 0o600, dir: false }),
            ]),
            cloud_init: true,
            ..Default::default()
        }
    }

    /// A host after harden-vps.sh: the gateway user's settings come from `sshd -T -C`.
    fn gateway_host() -> Facts {
        let gw = "gabc";
        let global = parse_settings(&format!(
            "port 2222\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\nusepam no\n\
             pubkeyauthentication yes\nauthenticationmethods publickey\nallowusers {gw}\nloglevel VERBOSE\n\
             authorizedkeysfile /etc/ssh/authorized_keys/%u\nhostkey /etc/ssh/ssh_host_ed25519_key\nstrictmodes yes\n\
             allowtcpforwarding no\nallowagentforwarding no\nallowstreamlocalforwarding no\nx11forwarding no\n\
             permittunnel no\ngatewayports no\npermituserenvironment no\nforcecommand none\npermitopen none\n"
        ));
        let mut user = global.clone();
        user.insert("forcecommand".into(), vec!["/usr/local/bin/gateway-shell".into()]);
        user.insert("allowtcpforwarding".into(), vec!["local".into()]);
        user.insert("permitopen".into(), vec!["127.0.0.1:8080 127.0.0.1:51821".into()]);
        user.insert("permitlisten".into(), vec!["none".into()]);
        let file = |uid, gid, mode, dir| FileInfo { uid, gid, mode, dir };
        Facts {
            installed: true,
            exact: true,
            per_user: BTreeMap::from([("root".into(), global.clone()), (gw.into(), user)]),
            global,
            accounts: parse_passwd(
                &format!(
                    "root:x:0:0:root:/root:/bin/bash\n{gw}:x:1001:1001::/home/{gw}:/bin/sh\ndebian:x:1000:1000::/home/debian:/bin/bash\n"
                ),
                Some(&format!("root:$y$j9T$abc:20000::::::\n{gw}:*:20000::::::\ndebian:!:20000::::::\n")),
            ),
            groups: parse_groups(&format!("root:x:0:\nsudo:x:27:debian\n{gw}:x:1001:\ngw-su:x:1002:{gw}\n")),
            pam_su: Some("auth       sufficient pam_rootok.so\nauth       required   pam_wheel.so group=gw-su\n".into()),
            files: BTreeMap::from([
                ("/etc/ssh".into(), file(0, 0, 0o755, true)),
                ("/etc/ssh/ssh_host_ed25519_key".into(), file(0, 0, 0o600, false)),
                ("/etc/ssh/authorized_keys".into(), file(0, 0, 0o755, true)),
                (format!("/etc/ssh/authorized_keys/{gw}"), file(0, 0, 0o644, false)),
                ("/usr/local/bin".into(), file(0, 0, 0o755, true)),
                ("/usr/local/bin/gateway-shell".into(), file(0, 0, 0o755, false)),
                (format!("/home/{gw}"), file(0, 1001, 0o750, true)),
            ]),
            texts: BTreeMap::from([
                (
                    "/usr/local/bin/gateway-shell".into(),
                    "#!/bin/sh\ncase \"$SSH_ORIGINAL_COMMAND\" in\n\"\") exec /bin/su - root ;;\n\
                     \"/usr/lib/openssh/sftp-server\") exec /usr/lib/openssh/sftp-server -l INFO -f AUTH -d %d/xfer ;;\nesac\n"
                        .into(),
                ),
                (
                    format!("/etc/ssh/authorized_keys/{gw}"),
                    "restrict,pty,port-forwarding,permitopen=\"127.0.0.1:8080\" ssh-ed25519 AAAAC3Nza me\n".into(),
                ),
            ]),
            ..Default::default()
        }
    }

    fn ids(r: &SshAuditReport) -> Vec<(&str, Severity)> {
        r.issues.iter().map(|i| (i.id.as_str(), i.severity)).collect()
    }

    #[test]
    fn cloud_vps_with_root_passwords() {
        let r = audit(&cloud_vps(), &SshAuditCfg::default(), T);
        assert_eq!(r.layout, "standard");
        assert_eq!(ids(&r), [("root-password", Severity::High), ("password-auth", Severity::Warning), ("x11-forwarding", Severity::Info)]);
        let pw = &r.issues[1];
        assert!(pw.message.contains("set in /etc/ssh/sshd_config.d/50-cloud-init.conf:1"), "{}", pw.message);
        assert!(pw.message.contains("ignored: no at /etc/ssh/sshd_config:3"), "the file's own `no` loses: {}", pw.message);
        assert!(pw.message.contains("accounts with a password: root, debian"), "{}", pw.message);
        assert!(pw.fix.contains("ssh_pwauth: false"), "{}", pw.fix);
        assert_eq!(r.summary(), "standard: 1 high, 1 warning, 1 note");
        assert_eq!(r.concerns().len(), 2);

        // keys only, root with a key: nothing worse than notes
        let mut f = cloud_vps();
        for s in [&mut f.global, f.per_user.get_mut("root").unwrap()] {
            s.insert("passwordauthentication".into(), vec!["no".into()]);
            s.insert("permitrootlogin".into(), vec!["without-password".into()]);
        }
        let r = audit(&f, &SshAuditCfg::default(), T);
        assert_eq!(ids(&r), [("x11-forwarding", Severity::Info)]);
        // ignored by id
        let cfg = SshAuditCfg { ignore: vec!["x11-forwarding".into()], ..Default::default() };
        assert!(audit(&f, &cfg, T).issues.is_empty());
    }

    #[test]
    fn messages_point_at_the_line_to_change() {
        // the image left cloud-init's file, but cloud-init itself isn't installed
        let mut f = cloud_vps();
        f.cloud_init = false;
        let r = audit(&f, &SshAuditCfg::default(), T);
        let pw = r.issues.iter().find(|i| i.id == "password-auth").unwrap();
        assert!(!pw.fix.contains("ssh_pwauth") && pw.fix.contains("deleting the file is enough"), "{}", pw.fix);

        // sshd shows seconds; the file says `10m`: the message quotes the file
        let mut f = cloud_vps();
        parse_config_text("LoginGraceTime 10m\n", "/etc/ssh/sshd_config.d/10-mine.conf", Path::new("/etc/ssh"), None, 0, &mut f.parsed);
        f.global.insert("logingracetime".into(), vec!["600".into()]);
        let r = audit(&f, &SshAuditCfg::default(), T);
        let grace = r.issues.iter().find(|i| i.id == "login-grace").unwrap();
        assert_eq!(
            grace.message,
            "LoginGraceTime 600s, written `10m` in /etc/ssh/sshd_config.d/10-mine.conf:1: unauthenticated connections are held long"
        );
        let x11 = r.issues.iter().find(|i| i.id == "x11-forwarding").unwrap();
        assert_eq!(x11.message, "X11Forwarding yes, set in /etc/ssh/sshd_config:6: rarely needed on a server");
    }

    #[test]
    fn passwords_with_a_key_first_are_two_factors() {
        let mut s = parse_settings("passwordauthentication yes\nkbdinteractiveauthentication yes\nusepam yes\n");
        assert!(password_alone(&s));
        s.insert("authenticationmethods".into(), vec!["publickey,keyboard-interactive:pam publickey,password".into()]);
        assert!(!password_alone(&s), "a key first, then the password or a PAM prompt");
        s.insert("authenticationmethods".into(), vec!["publickey password".into()]);
        assert!(password_alone(&s), "either alone");
        // PAM's prompt counts only with UsePAM
        let kbd = parse_settings("passwordauthentication no\nkbdinteractiveauthentication yes\nusepam no\n");
        assert!(!password_alone(&kbd));
        let old = parse_settings("passwordauthentication no\nchallengeresponseauthentication yes\nusepam yes\n");
        assert!(password_alone(&old), "OpenSSH before 8.7");
    }

    #[test]
    fn hardened_gateway_is_clean() {
        let f = gateway_host();
        let r = audit(&f, &SshAuditCfg::default(), T);
        assert_eq!(r.layout, "gateway (gabc)");
        assert!(r.issues.is_empty(), "{:?}", ids(&r));
        assert_eq!(r.settings.get("gabc:forcecommand").map(String::as_str), Some("/usr/local/bin/gateway-shell"));
        assert_eq!(r.settings.get("pam_wheel").map(String::as_str), Some("gw-su"));
        assert_eq!(r.summary(), "gateway (gabc): no problems");
    }

    #[test]
    fn broken_gateway_pieces() {
        let mut f = gateway_host();
        let gw = "gabc";
        // a manual edit dropped the Match block, someone made the keys file group-writable,
        // the su limit went, and the user owns its home
        f.per_user.get_mut(gw).unwrap().insert("forcecommand".into(), vec!["none".into()]);
        f.files.insert(format!("/etc/ssh/authorized_keys/{gw}"), FileInfo { uid: 0, gid: 1001, mode: 0o664, dir: false });
        f.pam_su = Some("auth sufficient pam_rootok.so\n# auth required pam_wheel.so group=gw-su\n".into());
        f.files.insert(format!("/home/{gw}"), FileInfo { uid: 1001, gid: 1001, mode: 0o755, dir: true });
        f.texts.insert(format!("/etc/ssh/authorized_keys/{gw}"), "ssh-ed25519 AAAAC3Nza laptop\n".into());
        // the profile is said: no ForceCommand left to detect it by
        let cfg = SshAuditCfg { profile: Profile::Gateway, ..Default::default() };
        let r = audit(&f, &cfg, T);
        let got = ids(&r);
        for want in [
            ("gateway-forcecommand:gabc", Severity::High),
            ("gateway-keys-perms:/etc/ssh/authorized_keys/gabc", Severity::High),
            ("gateway-pam-wheel", Severity::High),
            ("gateway-home:gabc", Severity::Warning),
            ("gateway-key-options:gabc", Severity::Warning),
        ] {
            assert!(got.contains(&want), "{want:?} missing from {got:?}");
        }
        assert_eq!(r.layout, "gateway (gabc)", "AllowUsers' user");

        // auto-detected from the ForceCommand; root with a key and passwords turned on again
        let mut f = gateway_host();
        for s in f.per_user.values_mut().chain([&mut f.global]) {
            s.insert("allowusers".into(), vec![gw.into(), "root".into()]);
            s.insert("permitrootlogin".into(), vec!["without-password".into()]);
            s.insert("passwordauthentication".into(), vec!["yes".into()]);
            s.insert("authenticationmethods".into(), vec!["any".into()]);
        }
        let r = audit(&f, &SshAuditCfg::default(), T);
        let got = ids(&r);
        assert!(got.contains(&("gateway-root-login", Severity::High)), "{got:?}");
        assert!(got.contains(&("gateway-passwords:gabc", Severity::High)), "{got:?}");
        assert!(got.contains(&("password-auth", Severity::High)), "passwords on a gateway are high: {got:?}");
        assert!(!got.iter().any(|(id, _)| *id == "root-password"), "root's password can't be used: prohibit-password");

        // the wrapper runs a shell, and an extra user can log in
        let mut f = gateway_host();
        f.texts.insert("/usr/local/bin/gateway-shell".into(), "#!/bin/sh\nexec /bin/bash -l\n".into());
        f.global.insert("allowusers".into(), vec![gw.into(), "debian".into()]);
        let r = audit(&f, &SshAuditCfg::default(), T);
        let got = ids(&r);
        assert!(got.contains(&("gateway-wrapper-exec:gabc", Severity::Warning)), "{got:?}");
        assert!(got.contains(&("gateway-other-users", Severity::Warning)), "{got:?}");
    }

    #[test]
    fn standard_profile_skips_the_gateway() {
        let cfg = SshAuditCfg { profile: Profile::Standard, ..Default::default() };
        let r = audit(&gateway_host(), &cfg, T);
        assert_eq!(r.layout, "standard");
        assert!(r.issues.iter().all(|i| !i.id.starts_with("gateway")), "{:?}", ids(&r));
    }

    #[test]
    fn files_writable_by_others() {
        let mut f = cloud_vps();
        f.parsed.files = vec!["/etc/ssh/sshd_config".into()];
        f.files.insert("/etc/ssh/sshd_config".into(), FileInfo { uid: 0, gid: 1000, mode: 0o664, dir: false });
        f.files.insert("/etc/ssh/ssh_host_ed25519_key".into(), FileInfo { uid: 0, gid: 0, mode: 0o644, dir: false });
        f.files.insert("/home/debian/.ssh".into(), FileInfo { uid: 1000, gid: 1000, mode: 0o777, dir: true });
        f.files.insert("/home/debian/.ssh/authorized_keys".into(), FileInfo { uid: 1000, gid: 1000, mode: 0o600, dir: false });
        let r = audit(&f, &SshAuditCfg::default(), T);
        let got = ids(&r);
        assert!(got.contains(&("config-perms:/etc/ssh/sshd_config", Severity::High)), "{got:?}");
        assert!(got.contains(&("host-key-perms:/etc/ssh/ssh_host_ed25519_key", Severity::High)), "{got:?}");
        assert!(got.contains(&("key-file-perms:/home/debian/.ssh", Severity::Warning)), "StrictModes refuses it: {got:?}");
        // Fedora's host keys: group ssh_keys may read them
        let mut f = cloud_vps();
        f.groups.push(Group { name: "ssh_keys".into(), gid: 996, members: vec![] });
        f.files.insert("/etc/ssh/ssh_host_ed25519_key".into(), FileInfo { uid: 0, gid: 996, mode: 0o640, dir: false });
        assert!(!ids(&audit(&f, &SshAuditCfg::default(), T)).iter().any(|(id, _)| id.starts_with("host-key-perms")));
    }

    #[test]
    fn panels_and_weak_crypto() {
        let mut f = cloud_vps();
        f.panel = Some("cPanel/WHM");
        f.global.insert("ciphers".into(), vec!["aes128-ctr,aes256-cbc,3des-cbc".into()]);
        f.global.insert("macs".into(), vec!["hmac-sha2-256-etm@openssh.com,hmac-md5".into()]);
        f.global.insert("kexalgorithms".into(), vec!["curve25519-sha256,diffie-hellman-group1-sha1,gss-curve25519-sha256-".into()]);
        f.host_keys = vec![HostKey { path: "/etc/ssh/ssh_host_dsa_key".into(), algorithm: "ssh-dss".into(), bits: None }];
        let r = audit(&f, &SshAuditCfg::default(), T);
        assert_eq!(r.layout, "standard, cPanel/WHM");
        assert!(r.issues[0].fix.contains("SSH Password Authorization Tweak"), "{}", r.issues[0].fix);
        let msg = |id: &str| r.issues.iter().find(|i| i.id == id).map(|i| i.message.clone()).unwrap_or_default();
        assert_eq!(msg("weak-ciphers"), "weak ciphers allowed: aes256-cbc, 3des-cbc");
        assert_eq!(msg("weak-macs"), "weak MACs allowed: hmac-md5");
        assert_eq!(msg("weak-kex"), "weak key exchanges allowed: diffie-hellman-group1-sha1");
        assert!(msg("host-key-dsa:/etc/ssh/ssh_host_dsa_key").starts_with("DSA host key"));
    }

    #[test]
    fn config_files_include_and_match() {
        let dir = std::env::temp_dir().join(format!("logguard-sshaudit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sshd_config.d")).unwrap();
        std::fs::write(dir.join("sshd_config.d/50-cloud-init.conf"), "PasswordAuthentication yes\n").unwrap();
        std::fs::write(dir.join("sshd_config.d/10-mine.conf"), "Port 2222\nPort=2223 # second\n").unwrap();
        std::fs::write(dir.join("sshd_config.d/.hidden.conf"), "PermitRootLogin yes\n").unwrap();
        std::fs::write(
            dir.join("sshd_config"),
            "Include sshd_config.d/*.conf\nPermitRootLogin no\nPasswordAuthentication no\nAllowUsers gw alice@10.0.0.*\n\
             Match User gw\n    ForceCommand /usr/local/bin/gateway-shell\n    AllowTcpForwarding local\n\
             Match Address 10.0.0.0/8\n    PasswordAuthentication yes\n",
        )
        .unwrap();
        let p = parse_config(&dir.join("sshd_config"));
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert_eq!(p.files.len(), 3, "the hidden file is skipped: {:?}", p.files);
        let s = p.effective();
        assert_eq!(list(&s, "port"), ["2222", "2223"]);
        assert_eq!(first(&s, "passwordauthentication"), "yes", "the include comes first");
        assert_eq!(first(&s, "permitrootlogin"), "no");
        assert_eq!(list(&s, "allowusers"), ["gw", "alice@10.0.0.*"]);
        assert_eq!(first(&s, "forcecommand"), "none", "Match lines aren't global");
        assert_eq!(p.shadowed("passwordauthentication").len(), 1);
        let gw = p.effective_for("gw", &[]);
        assert_eq!(first(&gw, "forcecommand"), "/usr/local/bin/gateway-shell");
        assert_eq!(first(&gw, "allowtcpforwarding"), "local");
        assert_eq!(first(&p.effective_for("alice", &[]), "forcecommand"), "none");
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(split_line("  Ciphers=aes256-gcm@openssh.com"), Some(("ciphers".into(), "aes256-gcm@openssh.com".into())));
        assert_eq!(split_line("# PermitRootLogin yes"), None);
        assert!(match_applies("User gw,ops Group staff", "ops", &["staff".into()]));
        assert!(!match_applies("User *,!gw", "gw", &[]));
        assert!(!match_applies("Address 10.0.0.0/8", "gw", &[]), "unknown criteria never apply");
    }

    #[test]
    fn who_may_log_in() {
        let mut f = cloud_vps();
        f.global.insert("allowusers".into(), vec!["deb*@203.0.113.*".into()]);
        let root = f.account("root").unwrap().clone();
        let debian = f.account("debian").unwrap().clone();
        f.per_user.clear();
        assert!(!f.allowed(&root) && f.allowed(&debian));
        f.global.insert("denygroups".into(), vec!["sudo".into()]);
        assert!(!f.allowed(&debian));
        assert!(glob("g*x?", "gabcxy") && !glob("g*x?", "gabcx"));
    }

    #[test]
    fn rsa_key_size_from_the_blob() {
        use base64::Engine as _;
        let mut blob = Vec::new();
        let mut put = |b: &[u8]| {
            blob.extend((b.len() as u32).to_be_bytes());
            blob.extend(b);
        };
        put(b"ssh-rsa");
        put(&[1, 0, 1]);
        let mut n = vec![0u8];
        n.extend(std::iter::repeat_n(0xffu8, 128)); // 1024 bits, with mpint's sign byte
        put(&n);
        let line = format!("ssh-rsa {} host", base64::engine::general_purpose::STANDARD.encode(&blob));
        assert_eq!(rsa_bits(&line), Some(1024));
        assert_eq!(rsa_bits("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x"), None);
    }

    #[test]
    fn accounts_and_pam() {
        let a = parse_passwd(
            "a:x:1:1::/h:/bin/sh\nb:x:2:2::/h:/bin/sh\nc:x:3:3::/h:/bin/sh\nd::4:4::/h:/bin/sh\n+nis::::::\n",
            Some("a:$6$x:1\nb:!$6$x:1\nc::1\n"),
        );
        let pw: Vec<Password> = a.iter().map(|a| a.password.clone()).collect();
        assert_eq!(pw, [Password::Set, Password::Locked, Password::Empty, Password::Empty]);
        assert_eq!(parse_passwd("a:x:1:1::/h:/bin/sh\n", None)[0].password, Password::Unknown);
        assert_eq!(pam_wheel("auth required pam_wheel.so group=gw-su\n"), Some(Some("gw-su".into())));
        assert_eq!(pam_wheel("auth required pam_wheel.so use_uid\n"), Some(None));
        assert_eq!(pam_wheel("# auth required pam_wheel.so\nauth sufficient pam_wheel.so trust\n"), None, "trust doesn't limit su");
    }

    fn report(issues: &[(&str, Severity)], settings: &[(&str, &str)], at: Micros) -> SshAuditReport {
        SshAuditReport {
            read: at,
            installed: true,
            layout: "standard".into(),
            issues: issues
                .iter()
                .map(|(id, s)| Issue { id: id.to_string(), severity: *s, message: format!("{id} msg"), fix: "do x".into() })
                .collect(),
            settings: settings.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn alerts_new_changed_fixed_and_reminders() {
        let cfg = SshAuditCfg::default();
        let mut b = None;
        // first reading: everything once
        let f = judge(
            &mut b,
            &report(&[("password-auth", Severity::Warning), ("x11-forwarding", Severity::Info)], &[("passwordauthentication", "yes")], T),
            &cfg,
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].notify && f[0].severity == Severity::Warning && f[0].evidence.len() == 2, "{f:?}");
        assert!(f[0].evidence[0].starts_with("warning: password-auth msg - fix: do x"));
        // the same again: quiet
        assert!(judge(
            &mut b,
            &report(
                &[("password-auth", Severity::Warning), ("x11-forwarding", Severity::Info)],
                &[("passwordauthentication", "yes")],
                T + 1
            ),
            &cfg
        )
        .is_empty());
        // root's passwords turned on: the new problem, with the change
        let r = report(
            &[("root-password", Severity::High), ("password-auth", Severity::Warning)],
            &[("passwordauthentication", "yes"), ("permitrootlogin", "yes")],
            T + 2,
        );
        let f = judge(&mut b, &r, &cfg);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].message, "SSH audit: new problem: root-password msg");
        assert!(f[0].evidence.iter().any(|e| e == "changed: permitrootlogin: yes"), "{:?}", f[0].evidence);
        assert_eq!(f[1].message, "SSH audit: fixed: x11-forwarding");
        assert!(!f[1].notify, "a note fixed isn't worth a message");
        // a week later, still open: reminded
        let later = T + 2 + cfg.remind.micros();
        let f = judge(
            &mut b,
            &report(
                &[("root-password", Severity::High), ("password-auth", Severity::Warning)],
                &[("passwordauthentication", "yes"), ("permitrootlogin", "yes")],
                later,
            ),
            &cfg,
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("SSH audit: still open: root-password msg"));
        // fixed, settings back
        let f = judge(&mut b, &report(&[], &[("passwordauthentication", "no"), ("permitrootlogin", "prohibit-password")], later + 1), &cfg);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("fixed: password-auth, root-password") && f[0].notify);
        // a setting changes without a new problem
        let f = judge(&mut b, &report(&[], &[("passwordauthentication", "no"), ("permitrootlogin", "no")], later + 2), &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "sshd settings changed, no new problems: permitrootlogin: prohibit-password -> no");
        // sshd removed: nothing to watch
        let gone = SshAuditReport { read: later + 3, ..Default::default() };
        assert!(judge(&mut b, &gone, &cfg).is_empty() && b.is_none());
    }

    #[test]
    fn errors_say_the_reading_is_approximate() {
        let mut b = None;
        let mut r = report(&[], &[], T);
        r.approximate = true;
        r.errors = vec!["/usr/sbin/sshd -T: Missing privilege separation directory: /run/sshd".into()];
        let f = judge(&mut b, &r, &SshAuditCfg::default());
        assert_eq!(f[0].key, "ssh-audit-errors");
        assert!(f[0].notify && f[0].every > 0 && f[0].severity == Severity::Warning);
        assert_eq!(f[1].message, "SSH audit (standard): no problems");
        assert!(!f[1].notify);
    }
}
