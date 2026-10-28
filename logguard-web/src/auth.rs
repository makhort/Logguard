//! The admins: each a password (Argon2id, `logguard-web passwd`) and, unless switched off, a
//! code from an authenticator app (`logguard-web totp-setup`). The first is "admin"
//! (`PASSWORD_FILE`, `TOTP_FILE`); others are made the same way with `--user <name>`, their
//! files in `ADMINS_DIR` (`<name>.password`, `<name>.totp`). All may do the same: there are
//! no roles. A login opens a session kept in memory (a restart ends them all) and named by a
//! random cookie; removing an account's files ends its sessions at their next request.
//!
//! Guessing is slowed three ways: Argon2's cost (one check at a time), a lockout of the
//! address after [`MAX_FAILURES`] failures, and logguard itself, which reads the failures
//! from the journal and bans the address (`[sources] apps = ["logguard-web"]`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine as _;
use sha2::Digest;

use crate::say;
use crate::time::Micros;
use serde::Serialize;

/// The session cookie: `__Host-` makes browsers keep it to this host, over HTTPS, path `/`.
pub const COOKIE: &str = "__Host-lgw";
/// Failures from one address within [`WINDOW`] before it is locked out for [`WINDOW`].
pub const MAX_FAILURES: u32 = 5;
pub const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Sessions at once: a few browsers of each admin...
const MAX_SESSIONS: usize = 8;
/// ...and of all of them.
const MAX_ALL_SESSIONS: usize = 64;
/// The first admin's name: its files are `PASSWORD_FILE` and `TOTP_FILE`.
pub const MAIN: &str = "admin";
/// Addresses whose failures are remembered.
const MAX_TRACKED: usize = 10_000;
pub const MIN_PASSWORD: usize = 12;

#[derive(Clone, Debug)]
pub struct AuthCfg {
    /// The first admin's ("admin") password hash.
    pub password_file: PathBuf,
    /// Its TOTP secret's file; None: password only for every admin (`TOTP=off`).
    pub totp_file: Option<PathBuf>,
    /// The other admins' files: `<name>.password` and `<name>.totp`.
    pub admins_dir: PathBuf,
    /// A session ends after this long without a request...
    pub idle: Duration,
    /// ...and this long after the login, whatever.
    pub max: Duration,
}

struct Session {
    user: String,
    created: Instant,
    last: Instant,
    /// The same, as wall-clock times for the page.
    created_at: Micros,
    last_at: Micros,
    ip: IpAddr,
    /// The browser, as it says (shown to its admin, to tell sessions apart).
    agent: String,
    /// The admin's login before this one, and the failures since (shown once after the login).
    previous: LoginRecord,
}

/// An admin's last good login and the failed attempts since, since the console started (it
/// writes nothing, so a restart forgets them).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct LoginRecord {
    pub at: Option<Micros>,
    pub ip: Option<IpAddr>,
    pub failed_since: u32,
}

/// One session, as the page shows it to its admin.
#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    /// A short name for it (from its digest: nothing to log in with).
    pub id: String,
    pub user: String,
    pub ip: IpAddr,
    pub agent: String,
    pub created: Micros,
    pub last: Micros,
    /// When it ends however busy (`SESSION_MAX_HOURS` after the login).
    pub ends: Micros,
    /// Minutes without a request that end it.
    pub idle_secs: u64,
    pub current: bool,
}

#[derive(Default)]
struct Failures {
    count: u32,
    first: Option<Instant>,
    locked_until: Option<Instant>,
}

pub struct Auth {
    pub cfg: AuthCfg,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// Each admin's logins since the start.
    records: Mutex<HashMap<String, LoginRecord>>,
    failures: Mutex<HashMap<IpAddr, Failures>>,
    /// Each admin's newest TOTP time step used: each code works once.
    last_step: Mutex<HashMap<String, u64>>,
    /// One Argon2 check at a time (each takes ~19 MB and tens of milliseconds).
    checking: Mutex<()>,
    /// Logins since start: succeeded, failed, refused while locked out (for /metrics).
    pub logins: [AtomicU64; 3],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Login {
    /// The new session's cookie value.
    Ok(String),
    Wrong,
    /// Locked out for this long.
    Locked(Duration),
}

fn digest(token: &str) -> [u8; 32] {
    sha2::Sha256::digest(token.as_bytes()).into()
}

/// The session cookie's value in a `Cookie` header.
pub fn cookie_value(header: &str) -> Option<&str> {
    header.split(';').find_map(|c| c.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

/// Hashes a new password for the password file (Argon2id, the crate's recommended cost).
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    crate::wire::getrandom(&mut salt)?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| anyhow::anyhow!("hashing: {e}"))?.to_string())
}

/// An admin's name: 1-32 lowercase letters, digits, `_` and `-`, starting with a letter.
pub fn user_ok(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A hash no password matches, for logins to accounts that don't exist: they cost the same
/// Argon2 check, so the time taken tells nothing.
fn nobody() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("no account has this password").unwrap_or_default())
}

/// Makes the hash for logins to accounts that don't exist, so the first such login takes
/// no longer than the others (run at start).
pub fn warm() {
    nobody();
}

/// One admin's files.
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub name: String,
    pub password_file: PathBuf,
    /// None with `TOTP=off`.
    pub totp_file: Option<PathBuf>,
}

/// Reads a secret file: a single line.
pub fn read_secret(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text.trim().to_string())
}

impl Auth {
    pub fn new(cfg: AuthCfg) -> Self {
        Auth {
            cfg,
            sessions: Mutex::default(),
            records: Mutex::default(),
            failures: Mutex::default(),
            last_step: Mutex::default(),
            checking: Mutex::new(()),
            logins: Default::default(),
        }
    }

    /// The files of admin `name` (whether they exist or not); None for a name that can't be one.
    pub fn account(&self, name: &str) -> Option<Account> {
        if name == MAIN {
            return Some(Account {
                name: MAIN.into(),
                password_file: self.cfg.password_file.clone(),
                totp_file: self.cfg.totp_file.clone(),
            });
        }
        user_ok(name).then(|| Account {
            name: name.into(),
            password_file: self.cfg.admins_dir.join(format!("{name}.password")),
            totp_file: self.cfg.totp_file.as_ref().map(|_| self.cfg.admins_dir.join(format!("{name}.totp"))),
        })
    }

    /// Every admin: "admin", then those in `ADMINS_DIR` (by their password files), by name.
    pub fn accounts(&self) -> Vec<Account> {
        let mut names: Vec<String> = std::fs::read_dir(&self.cfg.admins_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".password").map(str::to_string))
            .filter(|n| n != MAIN && user_ok(n))
            .collect();
        names.sort();
        std::iter::once(MAIN.to_string()).chain(names).filter_map(|n| self.account(&n)).collect()
    }

    /// Checks that an admin's password (and TOTP) files can be read and hold what they should.
    pub fn check_account(&self, a: &Account) -> Result<()> {
        let user = if a.name == MAIN { String::new() } else { format!(" --user {}", a.name) };
        let hash = read_secret(&a.password_file)?;
        PasswordHash::new(&hash).map_err(|e| {
            anyhow::anyhow!("{}: not a password hash ({e}): set it with `logguard-web passwd{user}`", a.password_file.display())
        })?;
        if let Some(f) = &a.totp_file {
            let secret = read_secret(f).ok().and_then(|t| crate::totp::unbase32(&t)).filter(|s| s.len() >= 16);
            if secret.is_none() {
                bail!("{}: no TOTP secret: make one with `logguard-web totp-setup{user}`", f.display());
            }
        }
        Ok(())
    }

    /// Checks the first admin's files: without them the console doesn't start. (Another
    /// admin's broken files only keep that admin out: see [`Auth::accounts`].)
    pub fn check_files(&self) -> Result<()> {
        self.check_account(&self.account(MAIN).expect("the first admin"))
    }

    /// Whether `ip` is locked out now, and for how long still.
    fn locked(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.get(&ip).and_then(|f| f.locked_until).filter(|u| *u > now).map(|u| u - now)
    }

    fn failed(&self, ip: IpAddr, now: Instant) {
        let mut all = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if all.len() >= MAX_TRACKED {
            all.retain(|_, f| f.locked_until.is_some_and(|u| u > now) || f.first.is_some_and(|t| now - t < WINDOW));
            if all.len() >= MAX_TRACKED {
                // a flood from many addresses: logguard bans them; forget the oldest here
                all.retain(|_, f| f.locked_until.is_some_and(|u| u > now));
            }
        }
        let f = all.entry(ip).or_default();
        if f.first.is_none_or(|t| now - t >= WINDOW) {
            *f = Failures { count: 0, first: Some(now), locked_until: f.locked_until };
        }
        f.count += 1;
        if f.count >= MAX_FAILURES {
            f.locked_until = Some(now + WINDOW);
            f.count = 0;
            f.first = None;
        }
    }

    /// A login attempt from `ip` as admin `user` (empty: "admin"). Every attempt costs the
    /// same Argon2 check, however it fails, also for an account that doesn't exist.
    pub fn login(&self, ip: IpAddr, user: &str, password: &str, code: &str) -> Result<Login> {
        let now = Instant::now();
        if let Some(left) = self.locked(ip, now) {
            self.logins[2].fetch_add(1, Ordering::Relaxed);
            say!("login refused from {ip}: locked out for {}s more after {MAX_FAILURES} failures", left.as_secs());
            return Ok(Login::Locked(left));
        }
        let user = if user.is_empty() { MAIN } else { user };
        // the main admin's files must be there (the console doesn't start without them);
        // another admin's may be missing: then nobody's hash is checked
        let account = self.account(user).filter(|a| a.name == MAIN || a.password_file.exists());
        let hash = match &account {
            Some(a) => read_secret(&a.password_file)?,
            None => nobody().to_string(),
        };
        let parsed = PasswordHash::new(&hash)
            .map_err(|e| anyhow::anyhow!("{}'s password file: {e}", account.as_ref().map_or("?", |a| a.name.as_str())))?;
        let password_ok = {
            let _one = self.checking.lock().unwrap_or_else(|e| e.into_inner());
            password.len() <= 1024 && Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
        } && account.is_some();
        let code_ok = match (&account, &self.cfg.totp_file) {
            (_, None) => Ok(()),
            (None, Some(_)) => Err("no such account"),
            (Some(a), Some(_)) => {
                let f = a.totp_file.as_ref().expect("TOTP is on");
                match read_secret(f).ok().and_then(|t| crate::totp::unbase32(&t)) {
                    None => Err("no TOTP secret for this account yet (totp-setup)"),
                    Some(secret) => {
                        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                        let mut last = self.last_step.lock().unwrap_or_else(|e| e.into_inner());
                        let used = last.get(&a.name).copied().unwrap_or(0);
                        match crate::totp::verify(&secret, code, unix, used) {
                            Some(step) if password_ok => {
                                last.insert(a.name.clone(), step);
                                Ok(())
                            }
                            Some(_) => Ok(()),
                            None if crate::totp::verify(&secret, code, unix, 0).is_some() => Err("code already used"),
                            None => Err("wrong code"),
                        }
                    }
                }
            }
        };
        // the name as tried, if it can be one (nothing else a stranger typed reaches the log)
        let who = account.as_ref().map_or_else(|| "an unknown account".to_string(), |a| format!("account {}", a.name));
        match (password_ok, code_ok) {
            (true, Ok(())) => {
                let user = account.expect("checked").name;
                self.failures.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
                let previous = {
                    let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
                    let r = records.entry(user.clone()).or_default();
                    std::mem::replace(r, LoginRecord { at: Some(crate::time::now()), ip: Some(ip), failed_since: 0 })
                };
                let token = self.open_session(&user, ip, previous, now)?;
                self.logins[0].fetch_add(1, Ordering::Relaxed);
                say!("login from {ip} as {user}");
                Ok(Login::Ok(token))
            }
            (pw, code) => {
                let why = match (pw, code) {
                    (false, Err(_)) => "wrong password and code",
                    (false, Ok(())) => "wrong password",
                    (true, Err(why)) => why,
                    (true, Ok(())) => unreachable!(),
                };
                say!("login failed from {ip}: {why} ({who})");
                if let Some(a) = &account {
                    let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
                    if records.len() < 1000 || records.contains_key(&a.name) {
                        let r = records.entry(a.name.clone()).or_default();
                        r.failed_since = r.failed_since.saturating_add(1);
                    }
                }
                self.logins[1].fetch_add(1, Ordering::Relaxed);
                self.failed(ip, now);
                Ok(Login::Wrong)
            }
        }
    }

    fn open_session(&self, user: &str, ip: IpAddr, previous: LoginRecord, now: Instant) -> Result<String> {
        let mut raw = [0u8; 32];
        crate::wire::getrandom(&mut raw)?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, now);
        // the least recently used goes: of this admin's, else of all
        let theirs = sessions.values().filter(|s| s.user == user).count();
        if theirs >= MAX_SESSIONS || sessions.len() >= MAX_ALL_SESSIONS {
            let mine = theirs >= MAX_SESSIONS;
            if let Some(oldest) = sessions.iter().filter(|(_, s)| !mine || s.user == user).min_by_key(|(_, s)| s.last).map(|(k, _)| *k) {
                sessions.remove(&oldest);
            }
        }
        let at = crate::time::now();
        sessions.insert(
            digest(&token),
            Session { user: user.to_string(), created: now, last: now, created_at: at, last_at: at, ip, agent: String::new(), previous },
        );
        Ok(token)
    }

    fn expire(&self, sessions: &mut HashMap<[u8; 32], Session>, now: Instant) {
        sessions.retain(|_, s| now - s.last < self.cfg.idle && now - s.created < self.cfg.max);
    }

    /// The admin whose live session `token` names; it counts as activity. A session of an
    /// admin whose password file was removed ends here.
    pub fn session(&self, token: &str) -> Option<String> {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, now);
        let key = digest(token);
        let user = sessions.get(&key)?.user.clone();
        if user != MAIN && !self.account(&user).is_some_and(|a| a.password_file.exists()) {
            sessions.remove(&key);
            say!("session of {user} ended: the account is gone");
            return None;
        }
        let s = sessions.get_mut(&key)?;
        s.last = now;
        s.last_at = crate::time::now();
        Some(user)
    }

    fn view(&self, key: &[u8; 32], s: &Session, current: bool) -> SessionView {
        SessionView {
            id: key[..4].iter().map(|b| format!("{b:02x}")).collect(),
            user: s.user.clone(),
            ip: s.ip,
            agent: s.agent.clone(),
            created: s.created_at,
            last: s.last_at,
            ends: s.created_at.saturating_add(self.cfg.max.as_micros() as Micros),
            idle_secs: self.cfg.idle.as_secs(),
            current,
        }
    }

    /// Notes the browser of the session `token` (its User-Agent, cut short).
    pub fn set_agent(&self, token: &str, agent: &str) {
        if let Some(s) = self.sessions.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&digest(token)) {
            s.agent = agent.chars().filter(|c| !c.is_control()).take(160).collect();
        }
    }

    /// The session `token`, and its admin's login before it.
    pub fn about(&self, token: &str) -> Option<(SessionView, LoginRecord)> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, Instant::now());
        let key = digest(token);
        let s = sessions.get(&key)?;
        Some((self.view(&key, s, true), s.previous.clone()))
    }

    /// The sessions of the admin of `token`, newest first.
    pub fn list(&self, token: &str) -> Vec<SessionView> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, Instant::now());
        let me = digest(token);
        let Some(user) = sessions.get(&me).map(|s| s.user.clone()) else { return vec![] };
        let mut out: Vec<SessionView> = sessions.iter().filter(|(_, s)| s.user == user).map(|(k, s)| self.view(k, s, *k == me)).collect();
        out.sort_by_key(|v| std::cmp::Reverse(v.created));
        out
    }

    /// Ends the other sessions of the admin of `token`; how many.
    pub fn end_others(&self, token: &str) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let me = digest(token);
        let Some(user) = sessions.get(&me).map(|s| s.user.clone()) else { return 0 };
        let before = sessions.len();
        sessions.retain(|k, s| *k == me || s.user != user);
        let ended = before - sessions.len();
        if ended > 0 {
            say!("{user} ended {ended} other session(s)");
        }
        ended
    }

    /// Sessions open now.
    pub fn sessions(&self) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, Instant::now());
        sessions.len()
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&digest(token));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(test: &str, totp: bool) -> (Auth, PathBuf, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("lgw-auth-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pw"), hash_password("correct horse battery").unwrap()).unwrap();
        let secret = b"0123456789abcdefghij".to_vec();
        std::fs::write(dir.join("totp"), crate::totp::base32(&secret)).unwrap();
        let cfg = AuthCfg {
            password_file: dir.join("pw"),
            totp_file: totp.then(|| dir.join("totp")),
            admins_dir: dir.join("admins"),
            idle: Duration::from_secs(60),
            max: Duration::from_secs(3600),
        };
        let auth = Auth::new(cfg);
        auth.check_files().unwrap();
        (auth, dir, secret)
    }

    fn now_code(secret: &[u8]) -> String {
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        format!("{:06}", crate::totp::code(secret, unix / crate::totp::STEP_SECS))
    }

    #[test]
    fn password_and_code() {
        let (auth, dir, secret) = setup("both", true);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(auth.login(ip, "", "correct horse battery", "000000").unwrap(), Login::Wrong);
        let code = now_code(&secret);
        assert_eq!(auth.login(ip, "", "wrong", &code).unwrap(), Login::Wrong, "the code alone isn't enough");
        let Login::Ok(token) = auth.login(ip, "", "correct horse battery", &code).unwrap() else { panic!("login failed") };
        assert_eq!(auth.session(&token).as_deref(), Some("admin"));
        assert!(auth.session("forged").is_none());
        assert_eq!(auth.login(ip, "", "correct horse battery", &code).unwrap(), Login::Wrong, "a code works once");
        auth.logout(&token);
        assert!(auth.session(&token).is_none());
        assert_eq!(cookie_value(&format!("a=b; {COOKIE}={token}; c=d")), Some(token.as_str()));
        assert_eq!(cookie_value("__Host-lgwx=1"), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn several_admins() {
        let (auth, dir, secret) = setup("admins", true);
        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        std::fs::create_dir_all(dir.join("admins")).unwrap();
        std::fs::write(dir.join("admins/alice.password"), hash_password("alice's long password").unwrap()).unwrap();
        let alice_secret = b"alice-0123456789-abc".to_vec();
        // her password is set, her TOTP secret not yet: she can't log in, the console runs
        assert!(auth.check_files().is_ok());
        let alice = auth.account("alice").unwrap();
        assert!(auth.check_account(&alice).unwrap_err().to_string().contains("totp-setup --user alice"));
        assert_eq!(auth.login(ip, "alice", "alice's long password", &now_code(&alice_secret)).unwrap(), Login::Wrong);
        std::fs::write(dir.join("admins/alice.totp"), crate::totp::base32(&alice_secret)).unwrap();
        assert_eq!(auth.accounts().iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["admin", "alice"]);

        // her code with the admin's password, the admin's code with hers: no
        assert_eq!(auth.login(ip, "alice", "correct horse battery", &now_code(&alice_secret)).unwrap(), Login::Wrong);
        assert_eq!(auth.login(ip, "alice", "alice's long password", &now_code(&secret)).unwrap(), Login::Wrong);
        let Login::Ok(t) = auth.login(ip, "alice", "alice's long password", &now_code(&alice_secret)).unwrap() else { panic!() };
        assert_eq!(auth.session(&t).as_deref(), Some("alice"));
        // each admin's codes are used up separately
        let Login::Ok(a) = auth.login(ip, "admin", "correct horse battery", &now_code(&secret)).unwrap() else { panic!() };
        assert_eq!(auth.session(&a).as_deref(), Some("admin"));

        // accounts that don't exist, or can't: refused alike
        for user in ["bob", "Alice", "../pw", "admin/../x", &"a".repeat(40)] {
            assert_eq!(
                auth.login("192.0.2.6".parse().unwrap(), user, "correct horse battery", &now_code(&secret)).unwrap(),
                Login::Wrong,
                "{user}"
            );
        }
        // her files removed: her session ends, the admin's stays
        std::fs::remove_file(dir.join("admins/alice.password")).unwrap();
        assert!(auth.session(&t).is_none());
        assert_eq!(auth.session(&a).as_deref(), Some("admin"));
        assert!(auth.account("admin2").is_some() && auth.account("2x").is_none() && auth.account("a.b").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sessions_and_last_login() {
        let (auth, dir, _) = setup("seen", false);
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.7".parse().unwrap(), "192.0.2.8".parse().unwrap());
        let Login::Ok(first) = auth.login(a, "", "correct horse battery", "").unwrap() else { panic!() };
        assert_eq!(auth.about(&first).unwrap().1, LoginRecord::default(), "the first login since the start");
        assert_eq!(auth.login(b, "admin", "wrong", "").unwrap(), Login::Wrong);
        let Login::Ok(second) = auth.login(b, "", "correct horse battery", "").unwrap() else { panic!() };
        auth.set_agent(&second, "Firefox\n<b>");
        let (me, prev) = auth.about(&second).unwrap();
        assert_eq!((prev.ip, prev.failed_since), (Some(a), 1), "the login before, and the failure since");
        assert_eq!((me.ip, me.agent.as_str(), me.current), (b, "Firefox<b>", true));
        assert_eq!(auth.list(&second).len(), 2);
        assert_eq!(auth.end_others(&second), 1);
        assert!(auth.session(&first).is_none() && auth.session(&second).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lockout() {
        let (auth, dir, _) = setup("lockout", false);
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert_eq!(auth.login(ip, "admin", "nope", "").unwrap(), Login::Wrong);
        }
        assert!(matches!(auth.login(ip, "", "correct horse battery", "").unwrap(), Login::Locked(_)), "even the right password");
        let other: IpAddr = "192.0.2.3".parse().unwrap();
        assert!(matches!(auth.login(other, "admin", "correct horse battery", "").unwrap(), Login::Ok(_)), "other addresses aren't");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sessions_end() {
        let (mut auth, dir, _) = setup("end", false);
        auth.cfg.idle = Duration::from_millis(50);
        let ip: IpAddr = "192.0.2.4".parse().unwrap();
        let Login::Ok(token) = auth.login(ip, "", "correct horse battery", "").unwrap() else { panic!() };
        assert!(auth.session(&token).is_some());
        std::thread::sleep(Duration::from_millis(80));
        assert!(auth.session(&token).is_none(), "idle too long");
        for _ in 0..MAX_SESSIONS + 2 {
            auth.login(ip, "", "correct horse battery", "").unwrap();
        }
        assert!(auth.sessions.lock().unwrap().len() <= MAX_SESSIONS);
        let _ = std::fs::remove_dir_all(dir);
    }
}
