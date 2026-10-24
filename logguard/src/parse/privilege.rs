//! `su` and `sudo` lines: who became whom, and who failed to. On a server where root is
//! reached through one SSH account and `su`, a failed `su` means someone holds that account's
//! key and is trying the root password.

/// One switch of user, or a failed attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switch {
    pub ok: bool,
    /// `su` or `sudo`.
    pub tool: &'static str,
    /// Who ran it.
    pub user: String,
    /// Whom they became (or tried to).
    pub target: String,
    /// The terminal, when the line names one (`pts/0`).
    pub tty: String,
    /// What sudo ran, or why it refused.
    pub what: Option<String>,
}

fn clean(s: &str) -> String {
    crate::event::clean(s.trim(), 64)
}

/// `(to root) gateway on pts/0` (util-linux), after `FAILED SU ` for a failure.
fn util_linux_su(rest: &str, ok: bool) -> Option<Switch> {
    let rest = rest.strip_prefix("(to ")?;
    let (target, rest) = rest.split_once(") ")?;
    let (user, tty) = rest.rsplit_once(" on ").unwrap_or((rest, ""));
    // "on none": no terminal (su run by a script, or without one)
    let tty = if tty == "none" { "" } else { tty };
    Some(Switch { ok, tool: "su", user: clean(user), target: clean(target), tty: clean(tty), what: None })
}

/// `+ pts/0 gateway:root` / `- pts/0 gateway:root` (shadow's su).
fn shadow_su(m: &str) -> Option<Switch> {
    let (sign, rest) = m.split_at_checked(2)?;
    let ok = match sign {
        "+ " => true,
        "- " => false,
        _ => return None,
    };
    let (tty, who) = rest.split_once(' ')?;
    let (user, target) = who.trim().split_once(':')?;
    if user.is_empty() || target.is_empty() || user.contains(' ') || target.contains(' ') {
        return None;
    }
    Some(Switch { ok, tool: "su", user: clean(user), target: clean(target), tty: clean(tty), what: None })
}

/// `gateway : TTY=pts/0 ; PWD=/home/gateway ; USER=root ; COMMAND=/bin/bash`, with
/// `3 incorrect password attempts ; ` or `user NOT in sudoers ; ` after the colon for a refusal.
/// The user chooses the directory (`PWD`, before `USER=`) and the command (last), either of
/// which may hold ` ; USER=...` or ` ; COMMAND=...`: a line with more than one `USER=` names
/// no target for sure, and the command is everything from the first `COMMAND=` after the
/// target on, so a fake one can't hide the real one.
fn sudo_line(m: &str) -> Option<Switch> {
    let (user, rest) = m.split_once(" : ")?;
    let fields: Vec<&str> = rest.split(" ; ").collect();
    let get = |k: &str| fields.iter().find_map(|f| f.strip_prefix(k)).map(str::trim);
    let targets: Vec<usize> = (0..fields.len()).filter(|i| fields[*i].starts_with("USER=")).collect();
    let (target, from) = match targets.as_slice() {
        [] => ("root", 0),
        [i] => (fields[*i]["USER=".len()..].trim(), *i),
        _ => ("?", 0),
    };
    // sudo writes the terminal before the directory: the first one is sudo's
    let tty = get("TTY=").unwrap_or("");
    let command = (from..fields.len()).find(|i| fields[*i].starts_with("COMMAND=")).map(|i| fields[i..].join(" ; "));
    let command = command.as_deref().map(|c| c["COMMAND=".len()..].trim());
    let refusal = fields.first().filter(|f| !f.contains('=')).map(|f| f.trim());
    // an odd line is shown at more length, so whatever was hidden in it shows
    let shown = if targets.len() == 1 { 120 } else { 400 };
    let (ok, what) = match refusal {
        Some(r) => (false, Some(clean(r))),
        None => (true, command.map(|c| crate::event::clean(c, shown))),
    };
    if user.trim().is_empty() || user.contains(' ') {
        return None;
    }
    Some(Switch { ok, tool: "sudo", user: clean(user), target: clean(target), tty: clean(tty), what })
}

/// `pam_unix(sudo:auth): authentication failure; logname=gateway uid=1000 ... user=gateway`:
/// one wrong password (sudo's own summary line comes only when it gives up).
fn sudo_pam_failure(m: &str) -> Option<Switch> {
    let rest = m.strip_prefix("pam_unix(sudo:auth): authentication failure;")?;
    let field = |k: &str| rest.split_whitespace().find_map(|w| w.strip_prefix(k)).filter(|v| !v.is_empty());
    let user = field("ruser=").or_else(|| field("logname="))?;
    let tty = field("tty=").unwrap_or("").trim_start_matches("/dev/");
    Some(Switch { ok: false, tool: "sudo", user: clean(user), target: "root".into(), tty: clean(tty), what: Some("wrong password".into()) })
}

/// Parses a line logged as `su` or `sudo` (`ident`). PAM's session lines repeat what the
/// program's own line says, and are skipped.
pub fn parse(ident: &str, msg: &str) -> Option<Switch> {
    let m = msg.trim();
    match ident {
        "su" => match m.strip_prefix("FAILED SU ") {
            Some(rest) => util_linux_su(rest, false),
            None => util_linux_su(m, true).or_else(|| shadow_su(m)),
        },
        "sudo" => sudo_pam_failure(m).or_else(|| (!m.starts_with("pam_")).then(|| sudo_line(m)).flatten()),
        _ => None,
    }
}

/// The identifier a `Source::Privilege` record was logged under: su's lines name a target in
/// parentheses or a `user:target` pair, sudo's carry `USER=` or `sudo:auth`.
pub fn ident_of(msg: &str) -> &'static str {
    if msg.contains("sudo:auth") || msg.contains(" ; USER=") || msg.contains("incorrect password attempt") || msg.contains("NOT in sudoers")
    {
        "sudo"
    } else {
        "su"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn su_and_sudo_lines() {
        let s = parse("su", "FAILED SU (to root) gateway on pts/0").unwrap();
        assert_eq!((s.ok, s.user.as_str(), s.target.as_str(), s.tty.as_str()), (false, "gateway", "root", "pts/0"));
        let s = parse("su", "(to root) gateway on pts/1").unwrap();
        assert!(s.ok && s.tty == "pts/1");
        assert_eq!(parse("su", "FAILED SU (to root) gateway on none").map(|s| s.tty), Some(String::new()), "no terminal");
        assert_eq!(parse("su", "- pts/2 eve:root").map(|s| (s.ok, s.user)), Some((false, "eve".into())));
        assert_eq!(parse("su", "+ pts/2 eve:root").map(|s| s.ok), Some(true));
        assert!(parse("su", "pam_unix(su-l:session): session opened for user root(uid=0) by gateway(uid=1000)").is_none());
        assert!(parse("su", "pam_unix(su-l:auth): authentication failure; logname=gateway uid=1000").is_none(), "FAILED SU says it");

        let s = parse("sudo", "gateway : TTY=pts/0 ; PWD=/home/gateway ; USER=root ; COMMAND=/usr/bin/systemctl restart x").unwrap();
        assert_eq!((s.ok, s.target.as_str(), s.what.as_deref()), (true, "root", Some("/usr/bin/systemctl restart x")));
        let s = parse("sudo", "eve : 3 incorrect password attempts ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh").unwrap();
        assert_eq!((s.ok, s.user.as_str(), s.what.as_deref()), (false, "eve", Some("3 incorrect password attempts")));
        let s = parse("sudo", "eve : user NOT in sudoers ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh").unwrap();
        assert!(!s.ok && s.what.as_deref() == Some("user NOT in sudoers"));
        let s = parse(
            "sudo",
            "pam_unix(sudo:auth): authentication failure; logname=eve uid=1001 euid=0 tty=/dev/pts/3 ruser=eve rhost=  user=eve",
        )
        .unwrap();
        assert_eq!((s.ok, s.user.as_str(), s.tty.as_str()), (false, "eve", "pts/3"));
        assert!(parse("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by eve(uid=1001)").is_none());
        assert!(parse("sudo", "unrelated").is_none());
        assert_eq!(ident_of("eve : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"), "sudo");
        assert_eq!(ident_of("FAILED SU (to root) gateway on pts/0"), "su");
    }

    /// The directory sudo runs in and its command are the user's choice: they can't name
    /// another target, or hide the command that ran.
    #[test]
    fn sudo_fields_the_user_chooses() {
        let s = parse("sudo", "eve : 3 incorrect password attempts ; TTY=pts/3 ; PWD=/tmp/a ; USER=nobody ; USER=root ; COMMAND=/bin/sh")
            .unwrap();
        assert_eq!((s.ok, s.target.as_str()), (false, "?"), "two USER= fields: no target for sure");
        let s = parse("sudo", "eve : TTY=pts/3 ; PWD=/tmp/b ; COMMAND=/usr/bin/ls ; USER=root ; COMMAND=/bin/bash -i").unwrap();
        assert_eq!((s.target.as_str(), s.what.as_deref()), ("root", Some("/bin/bash -i")), "the command after the target");
        let s = parse("sudo", "eve : TTY=pts/3 ; PWD=/tmp/c ; USER=nobody ; COMMAND=/usr/bin/ls ; USER=root ; COMMAND=/bin/bash").unwrap();
        assert_eq!(
            (s.target.as_str(), s.what.as_deref()),
            ("?", Some("/usr/bin/ls ; USER=root ; COMMAND=/bin/bash")),
            "the real command stays in view"
        );
        let s = parse("sudo", "eve : TTY=pts/3 ; PWD=/srv ; USER=root ; COMMAND=/bin/sh -c a ; COMMAND=b").unwrap();
        assert_eq!(s.what.as_deref(), Some("/bin/sh -c a ; COMMAND=b"), "the command's own arguments");
        let s = parse("sudo", "eve : TTY=pts/3 ; PWD=/home/eve ; USER=www-data ; COMMAND=/usr/bin/id").unwrap();
        assert_eq!((s.target.as_str(), s.what.as_deref()), ("www-data", Some("/usr/bin/id")));
    }

    #[test]
    fn hostile_names_are_cleaned() {
        let s = parse("su", "FAILED SU (to root) ga\u{1b}[2Jteway on pts/0").unwrap();
        assert_eq!(s.user, "ga[2Jteway");
        assert!(parse("su", "(to ").is_none() && parse("su", "+ ").is_none() && parse("sudo", " : ").is_none());
    }
}
