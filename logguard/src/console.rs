//! The read-only socket for logguard-web, the web console (`[console]`).
//!
//! The control socket (`socket`) is root's: it bans, unbans and allows. logguard-web runs as
//! a user of its own and must never be able to do that, so it gets a socket of its own that
//! only answers [`COMMANDS`]: the dashboard's snapshot, today's digest so far and the abuse
//! report of the last day or week (built from the actions log, without RDAP lookups). Anything
//! else is refused before it reaches the daemon's main loop.
//!
//! ```toml
//! [console]
//! socket = "/run/logguard-console/console.sock"
//! group = "logguard-web"
//! ```
//!
//! The socket's directory is logguard's (root's, mode 0750, group `group`), so the group may
//! connect but nobody else may put anything there; the socket is mode 0660, root and `group`.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleCfg {
    /// Where logguard-web reads this node's snapshots; empty = no console socket.
    pub socket: PathBuf,
    /// The group that may read them (logguard-web's own).
    pub group: String,
}

impl Default for ConsoleCfg {
    fn default() -> Self {
        ConsoleCfg { socket: PathBuf::new(), group: "logguard-web".into() }
    }
}

/// What the console socket answers: the snapshot (also for an empty request), today's digest
/// so far and the abuse report of the last 24 hours or 7 days (`abuse` alone: 7 days). All
/// only read.
pub const COMMANDS: &[&str] = &["snapshot", "digest", "abuse 24h", "abuse 7d"];

/// The command a request on the console socket stands for, or None when it may not be asked
/// there.
pub fn read_only(cmd: &str) -> Option<&'static str> {
    let cmd = cmd.split_whitespace().collect::<Vec<_>>().join(" ");
    match cmd.as_str() {
        "" => Some("snapshot"),
        "abuse" => Some("abuse 7d"),
        _ => COMMANDS.iter().find(|c| **c == cmd).copied(),
    }
}

/// The window of an abuse report command from [`read_only`].
pub fn abuse_window(cmd: &str) -> Option<crate::time::Dur> {
    match cmd {
        "abuse 24h" => Some(crate::time::Dur(86_400)),
        "abuse 7d" => Some(crate::time::Dur(7 * 86_400)),
        _ => None,
    }
}

impl ConsoleCfg {
    pub fn enabled(&self) -> bool {
        !self.socket.as_os_str().is_empty()
    }

    /// Checks the settings against the control socket's path.
    pub fn validate(&self, control_socket: &Path) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let dir_name = self.socket.parent().and_then(|d| d.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !self.socket.is_absolute() || self.socket.file_name().is_none() {
            bail!("[console] socket must be an absolute path, e.g. \"/run/logguard-console/console.sock\"");
        }
        // logguard makes the directory its own and opens it to the group: never one that
        // holds anything else (/run, /etc), so it must be one of logguard's
        if !dir_name.starts_with("logguard") {
            bail!("[console] socket: put it in a directory of its own whose name starts with \"logguard\", e.g. \"/run/logguard-console/console.sock\"");
        }
        if self.socket.parent() == control_socket.parent() {
            bail!("[console] socket: not in the control socket's directory (root's only): use another one, e.g. \"/run/logguard-console/console.sock\"");
        }
        let name_ok = |n: &str| {
            (1..=32).contains(&n.len())
                && n.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        };
        if !name_ok(&self.group) {
            bail!("[console] group: '{}' is not a group name", self.group);
        }
        Ok(())
    }
}

/// The id of group `name`, from /etc/group (`name:x:gid:members`).
pub fn group_id(etc_group: &str, name: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[0] == name).then(|| f[2].parse().ok()).flatten()
    })
}

/// Binds the console socket. `me` is this process's uid (the owner of the control socket it
/// just bound), so a directory someone else made beforehand is refused, not adopted.
pub fn bind(cfg: &ConsoleCfg, gid: u32, me: u32) -> Result<UnixListener> {
    let dir = cfg.socket.parent().context("[console] socket has no directory")?;
    match fs::symlink_metadata(dir) {
        Ok(m) if !m.is_dir() => bail!("{} is not a directory", dir.display()),
        Ok(m) if m.uid() != me => bail!("{} belongs to uid {}, not to logguard: remove it", dir.display(), m.uid()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    }
    std::os::unix::fs::chown(dir, None, Some(gid)).with_context(|| format!("giving {} to group {gid}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
    let _ = fs::remove_file(&cfg.socket);
    let listener = UnixListener::bind(&cfg.socket).with_context(|| format!("binding {}", cfg.socket.display()))?;
    std::os::unix::fs::chown(&cfg.socket, None, Some(gid))?;
    fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// The console socket's group id, or why there is none.
pub fn group(cfg: &ConsoleCfg) -> Result<u32> {
    let etc = fs::read_to_string("/etc/group").context("reading /etc/group")?;
    group_id(&etc, &cfg.group).with_context(|| format!("[console] group '{}' doesn't exist (install logguard-web first)", cfg.group))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reading_commands() {
        assert_eq!(read_only(""), Some("snapshot"));
        assert_eq!(read_only("snapshot\n"), Some("snapshot"));
        assert_eq!(read_only("digest"), Some("digest"));
        assert_eq!(read_only("abuse"), Some("abuse 7d"));
        assert_eq!(read_only(" abuse  24h\n"), Some("abuse 24h"));
        assert_eq!(read_only("abuse 7d"), Some("abuse 7d"));
        assert_eq!(abuse_window("abuse 24h").map(|d| d.0), Some(86_400));
        assert_eq!(abuse_window("digest").map(|d| d.0), None);
        for cmd in [
            "abuse 30d",
            "abuse 7d x",
            "abuse --contacts",
            "unban 203.0.113.5",
            "ban 203.0.113.5 60",
            "allow 203.0.113.5 60",
            "digest send",
            "feeds clear",
            "waf clear",
            "disallow x",
            "snapshotx",
        ] {
            assert_eq!(read_only(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn settings() {
        let control = Path::new("/run/logguard/logguard.sock");
        let cfg = |socket: &str, group: &str| ConsoleCfg { socket: socket.into(), group: group.into() };
        assert!(ConsoleCfg::default().validate(control).is_ok(), "off by default");
        assert!(cfg("/run/logguard-console/console.sock", "logguard-web").validate(control).is_ok());
        for bad in
            ["relative/console.sock", "/run/console.sock", "/etc/console.sock", "/run/logguard/console.sock", "/run/logguard-console/"]
        {
            assert!(cfg(bad, "logguard-web").validate(control).is_err(), "{bad}");
        }
        for bad in ["", "Web", "a b", "x:y", "0abc"] {
            assert!(cfg("/run/logguard-console/c.sock", bad).validate(control).is_err(), "{bad:?}");
        }
        assert_eq!(group_id("root:x:0:\nlogguard-web:x:998:\nweb:x:5:a,b\n", "logguard-web"), Some(998));
        assert_eq!(group_id("logguard-webx:x:7:\n", "logguard-web"), None);
    }

    #[test]
    fn socket_for_the_group_only() {
        use std::os::unix::fs::MetadataExt;
        let base = std::env::temp_dir().join(format!("lg-console-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let me = fs::metadata(&base).unwrap().uid();
        let gid = fs::metadata(&base).unwrap().gid();
        let cfg = ConsoleCfg { socket: base.join("logguard-console/console.sock"), group: "x".into() };
        let bound = match bind(&cfg, gid, me) {
            Ok(l) => l,
            // a sandbox without local sockets
            Err(e) if format!("{e:#}").contains("Operation not permitted") => return,
            Err(e) => panic!("{e:#}"),
        };
        let dir = fs::metadata(base.join("logguard-console")).unwrap();
        assert_eq!(dir.permissions().mode() & 0o7777, 0o750);
        assert_eq!(fs::metadata(&cfg.socket).unwrap().permissions().mode() & 0o777, 0o660);
        drop(bound);
        // again over the old socket (a restart)
        bind(&cfg, gid, me).unwrap();
        // a directory of someone else's is refused
        assert!(format!("{:#}", bind(&cfg, gid, me + 1).unwrap_err()).contains("not to logguard"));
        let _ = fs::remove_dir_all(&base);
    }
}
