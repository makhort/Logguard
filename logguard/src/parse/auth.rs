//! PAM, the account tools (shadow-utils) and the audit log: logins that failed where no
//! other parser looks (the console, a desktop, polkit, Cockpit, FTP, ...), accounts locked
//! after failures, changed passwords, new accounts and admin group members, and the audit
//! system itself stopped or switched off.
//!
//! Lines carry names someone typed (the user name at a login prompt, a client's FTP user):
//! a field is taken only where the program writes it, and a line naming more than one
//! remote host names none for sure.

use std::net::IpAddr;

use crate::engine::{Severity, Topic};
use crate::time::{Micros, MIN};

/// A failed password check.
#[derive(Clone, Debug, PartialEq)]
pub struct Failure {
    /// The PAM service (`login`, `gdm-password`, `polkit-1`), or the audited program.
    pub service: String,
    /// The account tried (typed by whoever tried it).
    pub user: String,
    pub rhost: Rhost,
    /// The terminal, when the line names one (`tty1`, `:0`).
    pub tty: String,
    /// The local user who asked (polkit's `ruser`), when the line names one.
    pub ruser: String,
}

/// Where a failed login came from.
#[derive(Clone, Debug, PartialEq)]
pub enum Rhost {
    /// Not from the network (no remote host).
    Local,
    Addr(IpAddr),
    /// A host name (the service looked the address up).
    Name(String),
    /// The line names more than one remote host: a name typed into it holds one.
    Unclear,
}

/// Something to tell, as it is.
#[derive(Clone, Debug, PartialEq)]
pub struct Notice {
    /// Alerts with the same key within `every` are one (a PAM line and the audit record of
    /// the same change).
    pub key: String,
    pub every: Micros,
    pub severity: Severity,
    pub topic: Topic,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Auth {
    Failure(Failure),
    Notice(Notice),
}

fn clean(s: &str) -> String {
    crate::event::clean(s.trim(), 64)
}

/// The account tools; their lines are about accounts only root may change.
const SHADOW_TOOLS: [&str; 10] =
    ["useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod", "gpasswd", "newusers", "chage", "passwd"];

/// PAM services whose failed logins are someone at this machine (a console, a desktop and
/// its screen locker, polkit asking for root's password, the web console): an alert each.
const CONSOLE: [&str; 17] = [
    "login",
    "remote",
    "gdm-password",
    "gdm-autologin",
    "gdm-fingerprint",
    "gdm-smartcard",
    "lightdm",
    "lightdm-autologin",
    "sddm",
    "sddm-autologin",
    "xrdp-sesman",
    "kde",
    "xscreensaver",
    "i3lock",
    "swaylock",
    "polkit-1",
    "cockpit",
];

/// PAM services other parsers read, or that never ask anyone for a password.
const ELSEWHERE: [&str; 11] =
    ["sshd", "su", "su-l", "sudo", "sudo-i", "cron", "crond", "systemd-user", "runuser", "runuser-l", "unix_chkpwd"];

/// Groups whose members are admins, or can become root.
const ADMIN_GROUPS: [&str; 11] = ["root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "incus-admin", "libvirt", "disk", "shadow"];

pub fn console_service(service: &str) -> bool {
    CONSOLE.contains(&service)
}

/// Whether a line belongs to [`pam`]: a PAM module's, or an account tool's.
pub fn is_auth_line(ident: &str, msg: &str) -> bool {
    SHADOW_TOOLS.contains(&ident) || pam_head(msg).is_some()
}

/// `pam_unix(login:auth): rest` -> (module, service, kind, rest).
fn pam_head(msg: &str) -> Option<(&str, &str, &str, &str)> {
    let (module, rest) = msg.trim_start().split_once('(')?;
    let name = module.strip_prefix("pam_")?;
    if name.is_empty() || name.len() > 32 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let (inside, rest) = rest.split_once("): ")?;
    let (service, kind) = inside.rsplit_once(':')?;
    Some((module, service, kind, rest))
}

/// The value of ` key=` (up to the next space) in a PAM line; `None` when it isn't there.
fn pam_value<'a>(rest: &'a str, key: &str) -> Option<&'a str> {
    let i = rest.find(key)?;
    Some(rest[i + key.len()..].split(' ').next().unwrap_or(""))
}

/// `authentication failure; logname=x uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=root`.
/// The user name comes last and may hold anything: of several ` rhost=`, none counts.
fn pam_failure(service: &str, rest: &str) -> Failure {
    let rhost = match rest.matches(" rhost=").count() {
        0 => Rhost::Local,
        1 => match pam_value(rest, " rhost=").unwrap_or("") {
            "" => Rhost::Local,
            h => crate::net::parse_ip(h).map_or_else(|| Rhost::Name(clean(h)), Rhost::Addr),
        },
        _ => Rhost::Unclear,
    };
    // the user after the (one) remote host; the name may hold spaces
    let tail = rest.find(" rhost=").map_or(rest, |i| &rest[i..]);
    let user = tail.find(" user=").map_or("", |i| &tail[i + 6..]);
    let user = if user.trim().is_empty() { "unknown".to_string() } else { clean(user) };
    let one = |key: &str| if rest.matches(key).count() == 1 { pam_value(rest, key).unwrap_or("") } else { "" };
    Failure { service: clean(service), user, rhost, tty: clean(one(" tty=").trim_start_matches("/dev/")), ruser: clean(one(" ruser=")) }
}

fn notice(key: String, every: Micros, severity: Severity, topic: Topic, message: String) -> Option<Auth> {
    Some(Auth::Notice(Notice { key, every, severity, topic, message }))
}

/// A PAM module's line, or an account tool's (`ident`: the program that logged it).
pub fn pam(ident: &str, msg: &str) -> Option<Auth> {
    let Some((module, service, kind, rest)) = pam_head(msg) else {
        return SHADOW_TOOLS.contains(&ident).then(|| shadow(ident, msg.trim())).flatten();
    };
    let svc = clean(service);
    match (kind, rest) {
        ("auth", r) if r.starts_with("authentication failure;") && !ELSEWHERE.contains(&service) => {
            Some(Auth::Failure(pam_failure(service, r)))
        }
        // pam_access: "access denied for user `alice' from `203.0.113.5'" (the host is last)
        ("account", r) if r.starts_with("access denied for user ") && !ELSEWHERE.contains(&service) => {
            let (who, from) = r.rsplit_once(" from `")?;
            let from = from.strip_suffix('\'').unwrap_or(from);
            let user = who.trim_start_matches("access denied for user ").trim_matches(['`', '\'']);
            let rhost = crate::net::parse_ip(from).map_or_else(|| Rhost::Name(clean(from)), Rhost::Addr);
            Some(Auth::Failure(Failure { service: svc, user: clean(user), rhost, tty: String::new(), ruser: String::new() }))
        }
        // pam_faillock, pam_tally2: the account is locked for a while
        (_, r) if r.starts_with("Consecutive login failures for user ") || (module == "pam_tally2" && r.contains(" tally ")) => {
            let user = r.trim_start_matches("Consecutive login failures for user ").trim_start_matches("user ");
            let user = user.split_whitespace().next().unwrap_or("?");
            let message = format!("account {} locked after repeated failed logins ({module}, {svc})", clean(user));
            notice(format!("auth-locked:{svc}"), 10 * MIN, Severity::Warning, Topic::Compromise, message)
        }
        ("chauthtok", r) if r.starts_with("password changed for ") => password(r.trim_start_matches("password changed for "), &svc),
        ("session", r) if r.starts_with("session opened for user ") && console_service(service) => {
            let user = r.trim_start_matches("session opened for user ");
            let user = clean(user.split(['(', ' ']).next().unwrap_or(user));
            // the web console is a login like SSH's: on record only
            let severity = if service == "cockpit" { Severity::Info } else { Severity::Warning };
            let topic = Topic::Compromise;
            notice(format!("auth-login:{user}"), MIN, severity, topic, format!("{user} logged in at the console or a desktop ({svc})"))
        }
        _ => None,
    }
}

/// A changed password: root's at once, another account's once an hour (any user can change
/// their own with `passwd` every minute).
fn password(user: &str, by: &str) -> Option<Auth> {
    let user = clean(user);
    let (severity, every) = if user == "root" { (Severity::High, MIN) } else { (Severity::Warning, 60 * MIN) };
    notice(format!("password:{user}"), every, severity, Topic::Integrity, format!("password of {user} changed ({by})"))
}

/// A new account: high for a person's (UID 1000 and up, or a login shell) and for a second
/// UID 0; one a package makes for itself is on record only.
fn new_user(name: &str, uid: Option<u32>, shell: &str, by: &str) -> Option<Auth> {
    let login_shell = !shell.is_empty() && !shell.ends_with("nologin") && !shell.ends_with("/false");
    let severity = match uid {
        Some(0) => Severity::High,
        Some(u) if u >= 1000 => Severity::High,
        _ if login_shell => Severity::High,
        _ => Severity::Info,
    };
    let uid_text = match uid {
        Some(0) => " with UID 0 (a second root)".to_string(),
        Some(u) => format!(" (UID {u})"),
        None => String::new(),
    };
    let shell = if shell.is_empty() { String::new() } else { format!(", shell {}", clean(shell)) };
    notice(format!("new-user:{name}"), MIN, severity, Topic::Integrity, format!("new account {name}{uid_text}{shell} ({by})"))
}

fn group_member(user: &str, group: &str, by: &str) -> Option<Auth> {
    let (user, group) = (clean(user), clean(group));
    let admin = ADMIN_GROUPS.contains(&group.as_str());
    let severity = if admin { Severity::High } else { Severity::Info };
    let why = if admin { " - its members are admins or can become root" } else { "" };
    notice(format!("group:{user}:{group}"), MIN, severity, Topic::Integrity, format!("{user} added to group {group} ({by}){why}"))
}

/// `'name'` -> name.
fn quoted(s: &str) -> Option<&str> {
    s.strip_prefix('\'')?.split_once('\'').map(|(q, _)| q)
}

/// An account tool's own line.
fn shadow(tool: &str, m: &str) -> Option<Auth> {
    let fields = |s: &str| -> Vec<(String, String)> {
        s.split(", ").filter_map(|f| f.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect()
    };
    let get = |f: &[(String, String)], k: &str| f.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let info = |key: String, message: String| notice(key, MIN, Severity::Info, Topic::Integrity, message);
    if let Some(r) = m.strip_prefix("new user: ") {
        let f = fields(r);
        return new_user(&clean(&get(&f, "name")), get(&f, "UID").parse().ok(), &get(&f, "shell"), tool);
    }
    if let Some(r) = m.strip_prefix("new group: ").or_else(|| m.strip_prefix("group added to /etc/group: ")) {
        let name = clean(&get(&fields(r), "name"));
        return info(format!("new-group:{name}"), format!("new group {name} ({tool})"));
    }
    if m.starts_with("group added to /etc/gshadow: ") {
        return None; // the line before said it
    }
    // useradd -G, usermod -aG: "add 'x' to group 'sudo'", "add 'x' to shadow group 'sudo'"
    if let Some(r) = m.strip_prefix("add ") {
        let user = quoted(r)?;
        let rest = r[user.len() + 2..].trim_start();
        let rest = rest.strip_prefix("to shadow group ").or_else(|| rest.strip_prefix("to group "))?;
        return group_member(user, quoted(rest)?, tool);
    }
    // gpasswd: "user x added by root to group sudo"
    if let Some((user, rest)) = m.strip_prefix("user ").and_then(|r| r.split_once(" added by ")) {
        let group = rest.rsplit_once(" to group ")?.1;
        return group_member(user, group, tool);
    }
    if let Some(r) = m.strip_prefix("delete user ") {
        let name = clean(quoted(r)?);
        return notice(format!("del-user:{name}"), MIN, Severity::Warning, Topic::Integrity, format!("account {name} deleted ({tool})"));
    }
    if let Some(r) = m.strip_prefix("change user ") {
        let raw = quoted(r)?;
        let name = clean(raw);
        let rest = r[raw.len() + 2..].trim_start();
        // "UID from '1001' to '0'"
        if let Some(r) = rest.strip_prefix("UID from ") {
            let to = r.rsplit_once(" to ").and_then(|(_, t)| quoted(t)).unwrap_or("?");
            let (severity, why) = if to == "0" { (Severity::High, " - a second root") } else { (Severity::Warning, "") };
            return notice(format!("uid:{name}"), MIN, severity, Topic::Integrity, format!("UID of {name} changed to {to} ({tool}){why}"));
        }
        if rest == "password" {
            return password(&name, tool);
        }
        if let Some(r) = rest.strip_prefix("shell from ") {
            let (from, to) = r.split_once(" to ")?;
            let (from, to) = (quoted(from).unwrap_or(from), quoted(to).unwrap_or(to));
            let opens = (from.ends_with("nologin") || from.ends_with("/false")) && !(to.ends_with("nologin") || to.ends_with("/false"));
            let severity = if opens { Severity::High } else { Severity::Info };
            let why = if opens { " - the account can log in now" } else { "" };
            let message = format!("shell of {name} changed from {} to {} ({tool}){why}", clean(from), clean(to));
            return notice(format!("shell:{name}"), MIN, severity, Topic::Integrity, message);
        }
    }
    // shadow's passwd: "password for 'x' changed by 'root'"
    if let Some(r) = m.strip_prefix("password for ") {
        let name = quoted(r)?;
        if r.contains(" changed by ") {
            return password(name, tool);
        }
    }
    // anything else they say: on record
    let line = crate::event::clean(m, 160);
    info(format!("account:{tool}:{line}"), format!("account change ({tool}): {line}"))
}

/// Names of the audit record types read here, by number (in kernel messages, and with
/// `log_format = RAW` when auditd can't name them).
fn type_name(n: u32) -> Option<&'static str> {
    Some(match n {
        1100 => "USER_AUTH",
        1102 => "USER_MGMT",
        1108 => "USER_CHAUTHTOK",
        1112 => "USER_LOGIN",
        1114 => "ADD_USER",
        1115 => "DEL_USER",
        1116 => "ADD_GROUP",
        1117 => "DEL_GROUP",
        1131 => "SERVICE_STOP",
        1132 => "GRP_MGMT",
        1201 => "DAEMON_END",
        1202 => "DAEMON_ABORT",
        1300 => "SYSCALL",
        1305 => "CONFIG_CHANGE",
        2100 => "ANOM_LOGIN_FAILURES",
        _ => return None,
    })
}

/// The type and the fields of an audit record: `type=USER_AUTH msg=audit(1.2:3): ...`
/// (audit.log), `USER_AUTH pid=...` (the journal), `audit: type=1100 audit(1.2:3): ...`
/// (the kernel's log, without auditd). The names auditd adds (`log_format = ENRICHED`) come
/// after a group separator.
fn audit_record(msg: &str) -> Option<(&str, &str, &str)> {
    let m = msg.trim_start();
    let m = m.strip_prefix("audit: ").unwrap_or(m);
    let (ty, rest) = m.strip_prefix("type=").unwrap_or(m).split_once(' ')?;
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix("msg=audit(").or_else(|| rest.strip_prefix("audit(")) {
        Some(r) => r.split_once("): ")?.1,
        None => rest,
    };
    let ty = match ty.parse::<u32>() {
        Ok(n) => type_name(n)?,
        Err(_) if !ty.is_empty() && ty.chars().all(|c| c.is_ascii_uppercase() || c == '_') => ty,
        Err(_) => return None,
    };
    let (fields, names) = rest.split_once('\u{1d}').unwrap_or((rest, ""));
    Some((ty, fields, names))
}

/// A field of an audit record: the first `key=` at the start, after a space or after `msg='`,
/// outside a quoted value. Values with spaces, double quotes or other odd bytes are written
/// in hex by the audit library (`acct=726F6F7420`): decoded here. Others are quoted as they
/// are, a `'` included: the account typed at a login prompt (`acct="'addr=203.0.113.9'"`) or a
/// program's name (`comm="'key=x'"`) can't hold a field of its own. `?` and `(null)` are no
/// value.
fn audit_field(body: &str, key: &str) -> Option<String> {
    let start = field_start(body, key)?;
    let v = &body[start..];
    let raw = match v.strip_prefix('"') {
        Some(q) => q.split('"').next().unwrap_or("").to_string(),
        None => {
            let t = v.split([' ', '\'']).next().unwrap_or("");
            match hex(t) {
                Some(decoded) => decoded,
                None => t.to_string(),
            }
        }
    };
    (!matches!(raw.as_str(), "" | "?" | "(null)")).then_some(raw)
}

/// Where the value of [`audit_field`]'s `key` starts.
fn field_start(body: &str, key: &str) -> Option<usize> {
    let pat = format!("{key}=");
    let b = body.as_bytes();
    let mut quoted = false;
    for i in 0..b.len() {
        if b[i] == b'"' {
            quoted = !quoted;
            continue;
        }
        let at_field = i == 0 || b[i - 1] == b' ' || (b[i - 1] == b'\'' && body[..i - 1].ends_with("msg="));
        if !quoted && at_field && body[i..].starts_with(&pat) {
            return Some(i + pat.len());
        }
    }
    None
}

/// Hex text as the audit library writes it (an even number of hex digits).
fn hex(t: &str) -> Option<String> {
    if t.len() < 2 || !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) || t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok()).collect();
    Some(String::from_utf8_lossy(&bytes?).into_owned())
}

/// `op=` holds spaces (`op=adding user id=1001`): up to the next field.
fn audit_op(body: &str) -> String {
    let Some(i) = field_start(body, "op") else { return String::new() };
    let words: Vec<&str> = body[i..].split(' ').take_while(|w| !w.contains('=')).collect();
    clean(words.join(" ").trim_end_matches('\''))
}

/// The person behind a record: `auid` (who logged in, whatever they became), with its name
/// when auditd added it.
fn audit_who(body: &str, names: &str) -> String {
    match audit_field(body, "auid").as_deref() {
        None | Some("4294967295") | Some("-1") | Some("unset") => String::new(),
        Some(n) => match audit_field(names, "AUID") {
            Some(name) => format!(" by {} (auid {n})", clean(&name)),
            None => format!(" by auid {}", clean(n)),
        },
    }
}

fn base(exe: &str) -> &str {
    exe.rsplit('/').next().unwrap_or(exe)
}

/// An audit record. `keys`: the rule keys (`-k`) to alert on, `"*"` for any.
pub fn audit(msg: &str, keys: &[String]) -> Option<Auth> {
    let (ty, body, names) = audit_record(msg)?;
    let f = |k: &str| audit_field(body, k);
    let exe = f("exe").unwrap_or_default();
    let by = match base(&exe) {
        "" => String::new(),
        b => clean(b),
    };
    let acct = f("acct").map(|a| clean(&a));
    let who = audit_who(body, names);
    let failed = f("res").is_some_and(|r| r == "failed" || r == "0");
    match ty {
        "USER_AUTH" | "USER_LOGIN" if failed => {
            if matches!(by.as_str(), "sshd" | "sshd-session" | "sshd-auth" | "su" | "sudo") {
                return None;
            }
            let rhost = match f("addr").or_else(|| f("hostname")) {
                None => Rhost::Local,
                Some(a) => crate::net::parse_ip(&a).map_or_else(|| Rhost::Name(clean(&a)), Rhost::Addr),
            };
            let user = acct.or_else(|| f("id").map(|i| format!("uid {}", clean(&i)))).unwrap_or_else(|| "unknown".into());
            let tty = clean(f("terminal").unwrap_or_default().trim_start_matches("/dev/"));
            Some(Auth::Failure(Failure { service: by, user, rhost, tty, ruser: String::new() }))
        }
        "USER_LOGIN" => {
            let tty = f("terminal").unwrap_or_default();
            let tty = tty.trim_start_matches("/dev/");
            let console = tty.starts_with("tty") || tty.starts_with(':') || tty == "console";
            if !console || matches!(by.as_str(), "sshd" | "sshd-session") {
                return None;
            }
            let user = acct.or_else(|| f("id").map(|i| format!("uid {}", clean(&i))))?;
            let message = format!("{user} logged in at the console or a desktop ({by} on {})", clean(tty));
            notice(format!("auth-login:{user}"), MIN, Severity::Warning, Topic::Compromise, message)
        }
        "USER_CHAUTHTOK" if !failed => password(&acct.or_else(|| f("id").map(|i| format!("uid {i}")))?, &format!("{by}{who}")),
        "ADD_USER" if !failed => {
            let uid = f("id").and_then(|i| i.parse().ok());
            let name = acct.or_else(|| uid.map(|u: u32| format!("uid {u}")))?;
            new_user(&name, uid, "", &format!("{by}{who}"))
        }
        "DEL_USER" if !failed => {
            let name = acct.or_else(|| f("id").map(|i| format!("uid {}", clean(&i))))?;
            notice(format!("del-user:{name}"), MIN, Severity::Warning, Topic::Integrity, format!("account {name} deleted ({by}{who})"))
        }
        "ADD_GROUP" | "DEL_GROUP" if !failed => {
            let name = acct.or_else(|| f("id").map(|i| format!("gid {}", clean(&i))))?;
            let (key, what) = if ty == "ADD_GROUP" { ("new-group", "new group") } else { ("del-group", "group deleted:") };
            notice(format!("{key}:{name}"), MIN, Severity::Info, Topic::Integrity, format!("{what} {name} ({by}{who})"))
        }
        "USER_MGMT" | "GRP_MGMT" if !failed => {
            let op = audit_op(body);
            let group = f("grp").map(|g| clean(&g));
            let name = acct.unwrap_or_else(|| "?".into());
            match group {
                Some(g) if op.contains("add") || op.contains("member") => group_member(&name, &g, &format!("{by}{who}")),
                _ => notice(
                    format!("account:{ty}:{name}:{op}"),
                    MIN,
                    Severity::Info,
                    Topic::Integrity,
                    format!("account change: {op} {name} ({by}{who})"),
                ),
            }
        }
        "ANOM_LOGIN_FAILURES" => {
            let name = acct.or_else(|| f("id").map(|i| format!("uid {}", clean(&i)))).unwrap_or_else(|| "?".into());
            let message = format!("account {name} locked after repeated failed logins ({by})");
            notice(format!("auth-locked:{by}"), 10 * MIN, Severity::Warning, Topic::Compromise, message)
        }
        "SERVICE_STOP" if f("unit").as_deref() == Some("auditd") => notice(
            "audit-stop".into(),
            10 * MIN,
            Severity::Warning,
            Topic::Integrity,
            format!("auditd stopped{who}: the audit log records nothing until it runs again"),
        ),
        "DAEMON_END" => notice(
            "audit-stop".into(),
            10 * MIN,
            Severity::Warning,
            Topic::Integrity,
            format!("auditd stopped{who}: the audit log records nothing until it runs again"),
        ),
        "DAEMON_ABORT" => notice(
            "audit-abort".into(),
            10 * MIN,
            Severity::High,
            Topic::Integrity,
            format!("auditd aborted ({}): the audit log records nothing until it runs again", clean(&audit_op(body))),
        ),
        "CONFIG_CHANGE" if f("audit_enabled").as_deref() == Some("0") && f("old").as_deref() != Some("0") => notice(
            "audit-off".into(),
            10 * MIN,
            Severity::High,
            Topic::Integrity,
            format!("auditing switched off (auditctl -e 0){who}: the kernel records nothing until it is switched on again"),
        ),
        "SYSCALL" => {
            let key = f("key")?;
            if !keys.iter().any(|k| k == "*" || *k == key) {
                return None;
            }
            let key = clean(&key);
            let comm = clean(&f("comm").unwrap_or_default());
            let uid = f("uid").map(|u| format!(" as uid {}", clean(&u))).unwrap_or_default();
            let tty = f("tty").filter(|t| t != "(none)").map(|t| format!(" on {}", clean(&t))).unwrap_or_default();
            let ok = match f("success").as_deref() {
                Some("no") => ", refused",
                _ => "",
            };
            let exe = if exe.is_empty() { String::new() } else { format!(" ({})", crate::event::clean(&exe, 120)) };
            let message = format!("audit rule {key}: {comm}{exe}{uid}{who}{tty}{ok}");
            notice(format!("audit-key:{key}"), 10 * MIN, Severity::Warning, Topic::Integrity, message)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(a: Option<Auth>) -> Failure {
        match a {
            Some(Auth::Failure(f)) => f,
            other => panic!("not a failure: {other:?}"),
        }
    }

    fn notice_of(a: Option<Auth>) -> Notice {
        match a {
            Some(Auth::Notice(n)) => n,
            other => panic!("not a notice: {other:?}"),
        }
    }

    #[test]
    fn pam_failures() {
        let f = failure(pam(
            "login",
            "pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=root",
        ));
        assert_eq!((f.service.as_str(), f.user.as_str(), &f.rhost, f.tty.as_str()), ("login", "root", &Rhost::Local, "tty1"));
        let f = failure(pam(
            "polkit-agent-helper-1",
            "pam_unix(polkit-1:auth): authentication failure; logname= uid=1000 euid=0 tty= ruser=eve rhost= user=root",
        ));
        assert_eq!((f.service.as_str(), f.ruser.as_str(), f.user.as_str()), ("polkit-1", "eve", "root"));
        let f = failure(pam(
            "vsftpd",
            "pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=admin rhost=203.0.113.5",
        ));
        assert_eq!((&f.rhost, f.user.as_str()), (&Rhost::Addr("203.0.113.5".parse().unwrap()), "unknown"), "no user=: an unknown one");
        let f = failure(pam(
            "cockpit-session",
            "pam_unix(cockpit:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=::ffff:198.51.100.4 user=admin",
        ));
        assert_eq!(f.rhost, Rhost::Addr("198.51.100.4".parse().unwrap()));
        let f = failure(pam("x", "pam_sss(x:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=host.example user=bob"));
        assert_eq!(f.rhost, Rhost::Name("host.example".into()));
        // a typed name naming another host: none for sure
        let f = failure(pam("vsftpd", "pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=x rhost=203.0.113.5  user=x rhost=198.51.100.1"));
        assert_eq!(f.rhost, Rhost::Unclear);
        let f = failure(pam("vsftpd", "pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=x rhost=198.51.100.1 rhost=203.0.113.5 user=x"));
        assert_eq!(f.rhost, Rhost::Unclear);
        // a name with spaces: all of it, cleaned
        let f = failure(pam(
            "login",
            "pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=tty2 ruser= rhost= user=no such\u{1b}[2J user",
        ));
        assert_eq!(f.user, "no such[2J user");
        let f = failure(pam("vsftpd", "pam_access(vsftpd:account): access denied for user `alice' from `203.0.113.7'"));
        assert_eq!((f.user.as_str(), &f.rhost), ("alice", &Rhost::Addr("203.0.113.7".parse().unwrap())));
        let f = failure(pam("vsftpd", "pam_access(vsftpd:account): access denied for user `x' from `198.51.100.1' from `203.0.113.7'"));
        assert_eq!(f.rhost, Rhost::Addr("203.0.113.7".parse().unwrap()), "the host is last");
        // other parsers' services, sessions of no interest, other lines
        assert!(pam(
            "sudo",
            "pam_unix(sudo:auth): authentication failure; logname=eve uid=1001 euid=0 tty=/dev/pts/3 ruser=eve rhost=  user=eve"
        )
        .is_none());
        assert!(pam("CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)").is_none());
        assert!(pam("systemd", "pam_unix(systemd-user:session): session opened for user gateway(uid=1000) by (uid=0)").is_none());
        assert!(pam("login", "pam_unix(login:auth): check pass; user unknown").is_none());
        assert!(pam("x", "pam_unix login failed").is_none() && pam("x", "pam_(x:auth): authentication failure;").is_none());
    }

    #[test]
    fn pam_notices() {
        let n = notice_of(pam("login", "pam_unix(login:session): session opened for user root(uid=0) by LOGIN(uid=0)"));
        assert_eq!((n.key.as_str(), n.severity), ("auth-login:root", Severity::Warning));
        assert_eq!(n.message, "root logged in at the console or a desktop (login)");
        let n = notice_of(pam("cockpit-session", "pam_unix(cockpit:session): session opened for user admin by (uid=0)"));
        assert_eq!((n.key.as_str(), n.severity), ("auth-login:admin", Severity::Info));
        let n = notice_of(pam("sshd", "pam_faillock(sshd:auth): Consecutive login failures for user root account temporarily locked"));
        assert_eq!((n.key.as_str(), n.severity), ("auth-locked:sshd", Severity::Warning));
        assert!(n.message.starts_with("account root locked"), "{}", n.message);
        let n = notice_of(pam("login", "pam_tally2(login:auth): user root (0) tally 4, deny 3"));
        assert!(n.message.starts_with("account root locked"), "{}", n.message);
        let n = notice_of(pam("passwd", "pam_unix(passwd:chauthtok): password changed for root"));
        assert_eq!((n.key.as_str(), n.severity, n.topic), ("password:root", Severity::High, Topic::Integrity));
        assert_eq!(n.every, MIN);
        let n = notice_of(pam("chpasswd", "pam_unix(chpasswd:chauthtok): password changed for alice"));
        assert_eq!((n.severity, n.every), (Severity::Warning, 60 * MIN), "a user's own: hourly");
    }

    #[test]
    fn account_tools() {
        let n = notice_of(pam("useradd", "new user: name=eve, UID=1001, GID=1001, home=/home/eve, shell=/bin/bash, from=/dev/pts/0"));
        assert_eq!((n.key.as_str(), n.severity), ("new-user:eve", Severity::High));
        assert_eq!(n.message, "new account eve (UID 1001), shell /bin/bash (useradd)");
        let n = notice_of(pam("useradd", "new user: name=toor, UID=0, GID=0, home=/root, shell=/bin/sh, from=none"));
        assert!(n.message.contains("UID 0 (a second root)") && n.severity == Severity::High);
        let n =
            notice_of(pam("useradd", "new user: name=_chrony, UID=104, GID=111, home=/var/lib/chrony, shell=/usr/sbin/nologin, from=none"));
        assert_eq!(n.severity, Severity::Info, "a package's own account");
        let n = notice_of(pam("usermod", "add 'eve' to group 'sudo'"));
        assert_eq!((n.key.as_str(), n.severity), ("group:eve:sudo", Severity::High));
        assert!(n.message.contains("can become root"));
        let n = notice_of(pam("usermod", "add 'eve' to shadow group 'sudo'"));
        assert_eq!(n.key, "group:eve:sudo", "the same alert");
        assert_eq!(notice_of(pam("useradd", "add 'eve' to group 'audio'")).severity, Severity::Info);
        let n = notice_of(pam("gpasswd", "user eve added by root to group docker"));
        assert_eq!((n.key.as_str(), n.severity), ("group:eve:docker", Severity::High));
        let n = notice_of(pam("usermod", "change user 'eve' UID from '1001' to '0'"));
        assert_eq!((n.key.as_str(), n.severity), ("uid:eve", Severity::High));
        let n = notice_of(pam("usermod", "change user 'www-data' shell from '/usr/sbin/nologin' to '/bin/bash'"));
        assert_eq!((n.severity, n.message.contains("can log in now")), (Severity::High, true));
        assert_eq!(notice_of(pam("usermod", "change user 'root' password")).key, "password:root");
        assert_eq!(notice_of(pam("passwd", "password for 'root' changed by 'root'")).severity, Severity::High);
        assert_eq!(notice_of(pam("userdel", "delete user 'eve'")).severity, Severity::Warning);
        assert_eq!(notice_of(pam("groupadd", "group added to /etc/group: name=docker, GID=999")).key, "new-group:docker");
        assert!(pam("groupadd", "group added to /etc/gshadow: name=docker").is_none());
        assert_eq!(notice_of(pam("userdel", "removed group 'eve' owned by 'eve'")).severity, Severity::Info);
        assert!(is_auth_line("useradd", "x") && is_auth_line("cockpit-session", "pam_unix(cockpit:auth): x") && !is_auth_line("cron", "x"));
    }

    #[test]
    fn audit_records() {
        let keys = vec!["identity".to_string()];
        // audit.log (enriched), the journal, the kernel's log without auditd
        let file = "type=USER_AUTH msg=audit(1729900000.123:456): pid=1234 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct=\"root\" exe=\"/usr/bin/login\" hostname=? addr=? terminal=/dev/tty1 res=failed'\u{1d}UID=\"root\" AUID=\"unset\"";
        let f = failure(audit(file, &keys));
        assert_eq!((f.service.as_str(), f.user.as_str(), &f.rhost, f.tty.as_str()), ("login", "root", &Rhost::Local, "tty1"));
        let journal = "USER_AUTH pid=99 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct=\"admin\" exe=\"/usr/libexec/cockpit-session\" hostname=203.0.113.5 addr=203.0.113.5 terminal=? res=failed'";
        assert_eq!(failure(audit(journal, &keys)).rhost, Rhost::Addr("203.0.113.5".parse().unwrap()));
        let kernel = "audit: type=1100 audit(1729900000.123:456): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct=\"root\" exe=\"/usr/bin/login\" hostname=? addr=? terminal=tty2 res=failed'";
        assert_eq!(failure(audit(kernel, &keys)).tty, "tty2");
        // a name with odd bytes is written in hex
        let hexed = "USER_AUTH pid=1 uid=0 msg='op=PAM:authentication acct=726F6F7420782061646472 exe=\"/usr/bin/login\" addr=? terminal=tty1 res=failed'";
        assert_eq!(failure(audit(hexed, &keys)).user, "root x addr");
        // sshd's and su's are read elsewhere; successes aren't failures
        assert!(audit("USER_AUTH pid=1 uid=0 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" addr=203.0.113.5 terminal=ssh res=failed'", &keys).is_none());
        assert!(audit(
            "USER_AUTH pid=1 uid=0 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/bin/login\" addr=? terminal=tty1 res=success'",
            &keys
        )
        .is_none());

        let n = notice_of(audit("USER_LOGIN pid=1 uid=0 auid=0 ses=3 msg='op=login id=0 exe=\"/usr/bin/login\" hostname=? addr=? terminal=/dev/tty1 res=success'", &keys));
        assert_eq!((n.key.as_str(), n.severity), ("auth-login:uid 0", Severity::Warning));
        let n = notice_of(audit("USER_LOGIN pid=1 uid=0 auid=0 msg='op=login acct=\"root\" exe=\"/usr/sbin/gdm-session-worker\" addr=? terminal=:0 res=success'", &keys));
        assert_eq!(n.key, "auth-login:root", "the same alert as PAM's session line");
        assert!(audit(
            "USER_LOGIN pid=1 uid=0 msg='op=login acct=\"root\" exe=\"/usr/sbin/sshd\" addr=203.0.113.5 terminal=ssh res=success'",
            &keys
        )
        .is_none());

        let n = notice_of(audit("type=USER_CHAUTHTOK msg=audit(1.2:3): pid=1 uid=0 auid=1000 ses=2 msg='op=PAM:chauthtok grantors=pam_unix acct=\"root\" exe=\"/usr/bin/passwd\" hostname=? addr=? terminal=pts/0 res=success'\u{1d}UID=\"root\" AUID=\"gateway\"", &keys));
        assert_eq!((n.key.as_str(), n.severity), ("password:root", Severity::High));
        assert_eq!(n.message, "password of root changed (passwd by gateway (auid 1000))");
        let n = notice_of(audit("ADD_USER pid=1 uid=0 auid=1000 ses=2 msg='op=adding user id=1001 exe=\"/usr/sbin/useradd\" hostname=h addr=? terminal=pts/0 res=success'", &keys));
        assert_eq!((n.severity, n.key.as_str()), (Severity::High, "new-user:uid 1001"));
        let n = notice_of(audit(
            "ADD_USER pid=1 uid=0 auid=1000 msg='op=adding user acct=\"eve\" id=1001 exe=\"/usr/sbin/useradd\" res=success'",
            &keys,
        ));
        assert_eq!(n.key, "new-user:eve", "the same alert as useradd's line");
        let n = notice_of(audit(
            "GRP_MGMT pid=1 uid=0 auid=1000 msg='op=add-user-to-group grp=\"sudo\" acct=\"eve\" exe=\"/usr/sbin/usermod\" res=success'",
            &keys,
        ));
        assert_eq!((n.key.as_str(), n.severity), ("group:eve:sudo", Severity::High));
        let n = notice_of(audit(
            "ANOM_LOGIN_FAILURES pid=1 uid=0 auid=4294967295 msg='pam_faillock uid=0 exe=\"/usr/bin/login\" res=success'",
            &keys,
        ));
        assert_eq!(n.key, "auth-locked:login");

        let n = notice_of(audit("SERVICE_STOP pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=auditd comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'", &keys));
        assert_eq!((n.key.as_str(), n.severity), ("audit-stop", Severity::Warning));
        assert!(audit("SERVICE_STOP pid=1 uid=0 msg='unit=cron comm=\"systemd\" res=success'", &keys).is_none());
        assert_eq!(
            notice_of(audit("type=DAEMON_END msg=audit(1.2:3): op=terminate auid=1000 uid=0 ses=2 pid=1 res=success", &keys)).key,
            "audit-stop"
        );
        assert_eq!(
            notice_of(audit("type=DAEMON_ABORT msg=audit(1.2:3): op=disk-full auid=4294967295 pid=1 res=failed", &keys)).severity,
            Severity::High
        );
        let n =
            notice_of(audit("audit: type=1305 audit(1.2:3): op=set audit_enabled=0 old=1 auid=1000 ses=2 subj=unconfined res=1", &keys));
        assert_eq!((n.key.as_str(), n.severity), ("audit-off", Severity::High));
        assert_eq!(
            n.message,
            "auditing switched off (auditctl -e 0) by auid 1000: the kernel records nothing until it is switched on again"
        );
        assert!(audit("CONFIG_CHANGE op=set audit_enabled=1 old=0 auid=1000 res=1", &keys).is_none());

        let sys = "type=SYSCALL msg=audit(1.2:3): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c ppid=1 pid=2 auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=2 comm=\"vim\" exe=\"/usr/bin/vim.basic\" subj=unconfined key=\"identity\"\u{1d}AUID=\"gateway\" UID=\"root\"";
        let n = notice_of(audit(sys, &keys));
        assert_eq!(n.message, "audit rule identity: vim (/usr/bin/vim.basic) as uid 0 by gateway (auid 1000) on pts0");
        assert!(audit(sys, &[]).is_none(), "keys not asked for");
        assert!(audit(&sys.replace("key=\"identity\"", "key=(null)"), &["*".to_string()]).is_none());
        // a program named to look like a field: comm is hex when odd
        let odd = "SYSCALL arch=c000003e success=yes auid=1000 uid=1000 comm=6B65793D226964656E7469747922 exe=\"/tmp/x\" key=\"logins\"";
        let n = notice_of(audit(odd, &["*".to_string()]));
        assert!(n.message.starts_with("audit rule logins: key=\"identity\" (/tmp/x)"), "{}", n.message);
        // ...but a ' isn't odd to the audit library: a program named 'key=x' (or a path holding
        // it) neither hides the rule's real key nor fakes another
        let named = "SYSCALL arch=c000003e success=yes auid=1000 uid=1000 comm=\"'key=nope'\" exe=\"/tmp/'key=nope'\" key=\"identity\"";
        let n = notice_of(audit(named, &keys));
        assert!(n.message.starts_with("audit rule identity: 'key=nope' (/tmp/'key=nope')"), "{}", n.message);
        let faked = "SYSCALL arch=c000003e success=yes auid=1000 uid=1000 comm=\"'key=identity'\" exe=\"/tmp/x\" key=\"noisy\"";
        assert!(audit(faked, &keys).is_none(), "the rule that matched is noisy, not identity");
        // an account typed at a login prompt can't name the address
        let typed = "USER_AUTH pid=1 uid=0 msg='op=PAM:authentication acct=\"'addr=8.8.8.8'\" exe=\"/usr/sbin/vsftpd\" hostname=203.0.113.7 addr=203.0.113.7 terminal=ftp res=failed'";
        let f = failure(audit(typed, &keys));
        assert_eq!((f.user.as_str(), &f.rhost), ("'addr=8.8.8.8'", &Rhost::Addr("203.0.113.7".parse().unwrap())));
        // not audit records
        assert!(audit("audit: type=1100[1234]: segfault at 0", &keys).is_none());
        assert!(audit("hello world", &keys).is_none() && audit("", &keys).is_none());
    }
}
