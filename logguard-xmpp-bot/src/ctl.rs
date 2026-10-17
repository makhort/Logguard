//! Running ejabberdctl.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(10);
/// systemd unit of a running `/restart`: one at a time, and it outlives bot restarts.
const RESTART_UNIT: &str = "logguard-xmpp-bot-restart-kindly";

/// What the commands need from ejabberd; tests substitute a fake.
pub trait Ejabberd {
    /// Ok(stdout) on exit status 0, otherwise Err(stderr, or stdout, or the status).
    async fn run(&self, args: &[&str]) -> Result<String, String>;

    /// Starts `restart_kindly`, which waits out its delay, without waiting for it. Err
    /// when it could not be started, e.g. because one is already pending.
    async fn start_restart(&self, args: &[&str]) -> Result<(), String>;

    /// `notAfter=Jan 10 17:29:37 2027 GMT` of a PEM certificate file (`openssl x509
    /// -enddate`): `list_certificates` does not say when certificates expire.
    async fn cert_end_date(&self, file: &str) -> Result<String, String>;

    /// The rows of a query on ejabberd's SQLite database, opened read-only, as a JSON
    /// array (`[]` for none). For /export: ejabberdctl can't read archived messages.
    async fn query_db(&self, sql: &str) -> Result<String, String>;

    /// Whether [`Ejabberd::query_db`] has a database to read.
    fn has_db(&self) -> bool;
}

/// The account ejabberdctl runs as. A bot running as root runs it as that user directly,
/// so ejabberdctl never switches users itself: some versions of the script do that with
/// `su -c`, whose shell would split and expand the arguments (passwords, announcements).
#[derive(Debug, Clone, PartialEq)]
pub struct RunAs {
    pub name: String,
    uid: u32,
    gid: u32,
    /// Primary and supplementary groups, as `su` would set them.
    groups: Vec<u32>,
    home: PathBuf,
}

impl RunAs {
    /// `name` from /etc/passwd and /etc/group.
    pub fn lookup(name: &str) -> Result<RunAs, String> {
        let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
        Self::parse(name, &read("/etc/passwd")?, &read("/etc/group")?)
    }

    fn parse(name: &str, passwd: &str, group: &str) -> Result<RunAs, String> {
        let f = passwd
            .lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.len() >= 7 && f[0] == name)
            .ok_or_else(|| format!("no user '{name}' in /etc/passwd"))?;
        let (Ok(uid), Ok(gid)) = (f[2].parse::<u32>(), f[3].parse::<u32>()) else {
            return Err(format!("/etc/passwd: bad ids for '{name}'"));
        };
        if uid == 0 {
            return Err(format!("'{name}' is root"));
        }
        let mut groups = vec![gid];
        for g in group.lines().map(|l| l.split(':').collect::<Vec<_>>()) {
            if g.len() >= 4 && g[3].split(',').any(|m| m == name) {
                if let Ok(id) = g[2].parse::<u32>() {
                    if !groups.contains(&id) {
                        groups.push(id);
                    }
                }
            }
        }
        let home = PathBuf::from(f[5]);
        let home = if home.is_dir() { home } else { PathBuf::from("/") };
        Ok(RunAs { name: name.to_string(), uid, gid, groups, home })
    }
}

pub fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail
    unsafe { libc::geteuid() == 0 }
}

/// Whether some process runs `restart_kindly` (one started by an earlier run of the bot
/// too): ejabberdctl passes its arguments on, down to the Erlang node it starts.
fn restart_running() -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else { return false };
    dir.flatten().any(|e| std::fs::read(e.path().join("cmdline")).is_ok_and(|c| c.split(|&b| b == 0).any(|a| a == b"restart_kindly")))
}

/// Between fork and exec: only plain system calls, no allocation. The directory change
/// comes last, as the user: the unit leaves root no right to enter others' directories
/// (/opt/ejabberd is 0700).
fn drop_privileges(uid: u32, gid: u32, groups: &[u32], home: &CString) -> io::Result<()> {
    // SAFETY: plain system calls on valid pointers
    unsafe {
        if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0
            || libc::setgid(gid) != 0
            || libc::setuid(uid) != 0
            || libc::chdir(home.as_ptr()) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub struct Ejabberdctl {
    pub path: PathBuf,
    /// Set when the bot runs as root.
    pub run_as: Option<RunAs>,
    /// ejabberd's SQLite database (`sql_database` in ejabberd.yml), if set.
    pub db: Option<PathBuf>,
    pub sqlite3: PathBuf,
}

/// stdout of a finished command, or the reason it failed.
async fn output(mut cmd: Command, name: &str) -> Result<String, String> {
    // the timeout drops the future; take the process down with it
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true).spawn().map_err(|e| format!("{name}: {e}"))?;
    let out = match tokio::time::timeout(TIMEOUT, child.wait_with_output()).await {
        Ok(r) => r.map_err(|e| e.to_string())?,
        Err(_) => return Err("Command timed out".to_string()),
    };
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    // ejabberdctl over HTTP (CTL_OVER_HTTP) exits 0 even when curl fails: nothing on
    // stdout and curl's complaint on stderr is a failure, not an empty answer
    if out.status.success() && !(stdout.is_empty() && !stderr.is_empty()) {
        Ok(stdout)
    } else if !stderr.is_empty() {
        Err(stderr)
    } else if !stdout.is_empty() {
        Err(stdout)
    } else {
        Err(format!("{name} exited with {}", out.status))
    }
}

impl Ejabberdctl {
    /// Whether ejabberdctl can be run at all (its `help` exits 0).
    pub async fn check(&self) -> Result<(), String> {
        self.run(&["help"]).await.map(drop)
    }

    /// `program` without the bot's secrets in its environment, as [`RunAs`] if set.
    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.stdin(Stdio::null()).env_remove("BOT_PASSWORD");
        if let Some(r) = &self.run_as {
            cmd.env("HOME", &r.home).env("USER", &r.name).env("LOGNAME", &r.name);
            let (uid, gid, groups) = (r.uid, r.gid, r.groups.clone());
            let home = CString::new(r.home.as_os_str().as_bytes()).unwrap_or_else(|_| c"/".to_owned());
            // SAFETY: drop_privileges only makes system calls (async-signal-safe)
            unsafe {
                cmd.pre_exec(move || drop_privileges(uid, gid, &groups, &home));
            }
        }
        cmd
    }
}

impl Ejabberd for Ejabberdctl {
    async fn cert_end_date(&self, file: &str) -> Result<String, String> {
        let mut cmd = self.command("openssl");
        cmd.args(["x509", "-noout", "-enddate", "-in", file]);
        output(cmd, "openssl").await
    }

    /// Run as root: in a transient systemd unit, which survives restarts of the bot, and
    /// of which a second one can't start while one is pending. Otherwise (the bot runs as
    /// the ejabberd user) a background process, refused while another one runs.
    async fn start_restart(&self, args: &[&str]) -> Result<(), String> {
        if running_as_root() && Path::new("/run/systemd/system").is_dir() {
            let mut cmd = Command::new("systemd-run");
            cmd.stdin(Stdio::null()).env_remove("BOT_PASSWORD");
            cmd.args(["--quiet", "--collect", "--unit", RESTART_UNIT]);
            if let Some(r) = &self.run_as {
                cmd.arg(format!("--uid={}", r.name));
            }
            cmd.arg("--").arg(&self.path).args(args);
            return match output(cmd, "systemd-run").await {
                Ok(_) => Ok(()),
                Err(e) if e.contains("already") => Err(format!("a restart is already pending (journalctl -u {RESTART_UNIT})")),
                Err(e) => Err(e),
            };
        }
        if restart_running() {
            return Err("a restart is already pending".into());
        }
        // its own process group and no pipes to the bot: it outlives a restart of the bot
        // (the unit has KillMode=process) without dying of a broken pipe
        let mut cmd = self.command(&self.path);
        cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
        let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", self.path.display()))?;
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) if status.success() => log::info!("ejabberdctl restart_kindly: done"),
                Ok(status) => log::error!("ejabberdctl restart_kindly: {status}"),
                Err(e) => log::error!("ejabberdctl restart_kindly: {e}"),
            }
        });
        Ok(())
    }

    async fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut cmd = self.command(&self.path);
        cmd.args(args);
        output(cmd, "ejabberdctl").await
    }

    fn has_db(&self) -> bool {
        self.db.is_some()
    }

    /// `sqlite3 -readonly -json`, waiting up to 5 s for ejabberd's write locks.
    async fn query_db(&self, sql: &str) -> Result<String, String> {
        let db = self.db.as_ref().ok_or("EJABBERD_DB is not set")?;
        let mut cmd = self.command(&self.sqlite3);
        cmd.args(["-readonly", "-json", "-batch", "-bail", "-cmd", ".timeout 5000"]).arg(db).arg(sql);
        let out = output(cmd, "sqlite3").await?;
        // no rows: no output at all
        Ok(if out.is_empty() { "[]".into() } else { out })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                          ejabberd:x:998:997:ejabberd:/nonexistent-home:/bin/sh\n\
                          bot:x:1000:1000::/home/bot:/bin/sh\n";
    const GROUP: &str = "root:x:0:\nssl-cert:x:110:postgres,ejabberd\nejabberd:x:997:\nadm:x:4:syslog\n";

    #[test]
    fn looks_up_the_ejabberd_user() {
        let r = RunAs::parse("ejabberd", PASSWD, GROUP).unwrap();
        assert_eq!((r.uid, r.gid), (998, 997));
        assert_eq!(r.groups, [997, 110]);
        assert_eq!(r.home, PathBuf::from("/"), "missing home: /");
        assert!(RunAs::parse("root", PASSWD, GROUP).unwrap_err().contains("root"));
        assert!(RunAs::parse("nobody", PASSWD, GROUP).is_err());
    }

    #[tokio::test]
    async fn outputs_and_failures() {
        let ctl = Ejabberdctl { path: "/bin/sh".into(), run_as: None, db: None, sqlite3: "sqlite3".into() };
        assert_eq!(ctl.run(&["-c", "echo ' hi '"]).await, Ok("hi".into()));
        assert_eq!(ctl.run(&["-c", "echo oops >&2; exit 3"]).await, Err("oops".into()));
        assert!(ctl.run(&["-c", "exit 4"]).await.unwrap_err().contains("exited with"));
        // exit 0, no output, an error message: an error
        assert_eq!(
            ctl.run(&["-c", "echo 'curl: (52) Empty reply from server' >&2"]).await,
            Err("curl: (52) Empty reply from server".into())
        );
        assert_eq!(ctl.run(&["-c", "echo ok; echo note >&2"]).await, Ok("ok".into()));
        // arguments arrive unsplit, and the bot's password is not passed on
        assert_eq!(ctl.run(&["-c", "printf '%s|' \"$@\"", "sh", "a b", "$HOME;x"]).await, Ok("a b|$HOME;x|".into()));
        std::env::set_var("BOT_PASSWORD", "secret");
        let ctl = Ejabberdctl { path: "/usr/bin/env".into(), run_as: None, db: None, sqlite3: "sqlite3".into() };
        assert!(!ctl.run(&[]).await.unwrap().contains("BOT_PASSWORD="));
    }

    #[tokio::test]
    async fn database_queries_are_read_only_json() {
        let Ok(dir) = std::env::current_dir().map(|d| d.join("target").join(format!("ctl-db-{}", std::process::id()))) else { return };
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let sh = Ejabberdctl { path: "/bin/sh".into(), run_as: None, db: None, sqlite3: "sqlite3".into() };
        if sh
            .run(&[
                "-c",
                &format!(
                    "sqlite3 '{}' \"CREATE TABLE last (username text, seconds text); INSERT INTO last VALUES ('alice', '17');\"",
                    db.display()
                ),
            ])
            .await
            .is_err()
        {
            eprintln!("no sqlite3 here, skipping");
            return;
        }
        let ctl = Ejabberdctl { db: Some(db.clone()), ..sh };
        let rows: serde_json::Value = serde_json::from_str(&ctl.query_db("SELECT username, seconds FROM last").await.unwrap()).unwrap();
        assert_eq!(rows, serde_json::json!([{"username": "alice", "seconds": "17"}]));
        assert_eq!(ctl.query_db("SELECT * FROM last WHERE 0").await.unwrap(), "[]");
        assert!(ctl.query_db("DELETE FROM last").await.is_err(), "read-only");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
