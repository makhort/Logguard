//! signal-cli as the bot's child process: `signal-cli --config <dir> -a <account> jsonRpc`,
//! talked to over its stdin and stdout ([`crate::rpc`]). Its stderr (its own log) goes to the
//! bot's log, a line at a time. When the bot stops, signal-cli is stopped with it; when
//! signal-cli stops, the bot does too, and systemd starts both again.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::rpc::{Rpc, RpcError};

/// How signal-cli is started.
#[derive(Debug, Clone)]
pub struct CliConfig {
    /// The signal-cli program (the native build, or the Java one's launcher script).
    pub program: PathBuf,
    /// Its data directory (`--config`): the account's keys and sessions.
    pub data_dir: PathBuf,
    /// The bot's Signal account, `+<country><number>`.
    pub account: String,
    /// More arguments for `jsonRpc` (as `--ignore-attachments --ignore-stories`).
    pub extra: Vec<String>,
}

impl CliConfig {
    /// The arguments before the subcommand: data directory, account, and trust on first use
    /// (the bot's own pin of the admin's safety number sits on top).
    pub fn global_args(&self) -> Vec<String> {
        vec![
            "--config".into(),
            self.data_dir.display().to_string(),
            "-a".into(),
            self.account.clone(),
            "--trust-new-identities".into(),
            "on-first-use".into(),
        ]
    }
}

/// Whether `s` is an E.164 phone number as Signal accounts have them.
pub fn valid_number(s: &str) -> bool {
    s.strip_prefix('+').is_some_and(|d| (7..=15).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()) && !d.starts_with('0'))
}

/// Whether `s` names a Signal recipient signal-cli takes: a phone number, or an account's
/// ACI (a UUID).
pub fn valid_recipient(s: &str) -> bool {
    let uuid =
        s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() });
    valid_number(s) || uuid
}

/// signal-cli, running (the [`Rpc`] to talk to it is returned beside it).
pub struct SignalCli {
    child: Child,
}

impl SignalCli {
    /// Starts signal-cli and waits until it answers (its JVM, if any, takes a few seconds).
    /// If it exits first (an account not registered, a bad option), the error carries the
    /// last lines it wrote.
    pub async fn start(cfg: &CliConfig) -> anyhow::Result<(SignalCli, Rpc)> {
        let mut cmd = Command::new(&cfg.program);
        cmd.args(cfg.global_args()).arg("jsonRpc").args(&cfg.extra);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!("starting {}: {e}", cfg.program.display()))?;
        let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
            anyhow::bail!("signal-cli's pipes");
        };
        let tail = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let t = tail.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line: String = line.chars().take(500).collect();
                if line.contains("ERROR") || line.contains("WARN") {
                    log::warn!("signal-cli: {line}");
                } else {
                    log::info!("signal-cli: {line}");
                }
                if let Ok(mut t) = t.lock() {
                    t.push(line);
                    let n = t.len();
                    if n > 5 {
                        t.drain(..n - 5);
                    }
                }
            }
        });
        let (cli, rpc) = (SignalCli { child }, Rpc::new(stdout, stdin));
        match rpc.call("version", json!({}), Duration::from_secs(120)).await {
            Ok(v) => {
                log::info!("signal-cli {} for {}", v.get("version").and_then(Value::as_str).unwrap_or("?"), cfg.account);
                Ok((cli, rpc))
            }
            Err(RpcError::Remote { .. }) => Ok((cli, rpc)), // an old signal-cli without `version`: it runs
            Err(e) => {
                tokio::time::sleep(Duration::from_millis(300)).await; // the last stderr lines
                let said = tail.lock().map(|t| t.join(" | ")).unwrap_or_default();
                Err(anyhow::anyhow!("{e}: {said}"))
            }
        }
    }

    /// Stops signal-cli: its input closed (the [`Rpc`] dropped before), it exits on its own;
    /// else it is killed after 10 s.
    pub async fn stop(mut self) {
        if tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await.is_err() {
            let _ = self.child.kill().await;
        }
    }
}

/// `logguard-signal-bot signal-cli ARGS...`: signal-cli with the bot's data directory and
/// account, for registering, linking and verifying by hand. Returns its exit status.
pub fn passthrough(cfg: &CliConfig, args: &[String], with_account: bool) -> std::io::Result<std::process::ExitStatus> {
    let mut global = cfg.global_args();
    if !with_account {
        global.drain(2..4);
    }
    std::process::Command::new(&cfg.program).args(global).args(args).status()
}

/// The data directory exists and is the bot's own (signal-cli keeps the account's keys there).
pub fn check_data_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!("{} is open to others (mode {:o}): chmod 700", dir.display(), meta.permissions().mode() & 0o777));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipients() {
        assert!(valid_number("+491701234567"));
        assert!(!valid_number("491701234567") && !valid_number("+0123456789") && !valid_number("+49 170") && !valid_number("+12"));
        assert!(valid_recipient("+491701234567"));
        assert!(valid_recipient("a1b2c3d4-e5f6-7890-abcd-ef0123456789"));
        assert!(!valid_recipient("a1b2c3d4-e5f6-7890-abcd-ef012345678"));
        assert!(!valid_recipient("--config"));
    }

    #[test]
    fn arguments() {
        let cfg = CliConfig {
            program: "/usr/local/bin/signal-cli".into(),
            data_dir: "/opt/logguard-signal-bot/signal-cli".into(),
            account: "+491701234567".into(),
            extra: vec![],
        };
        assert_eq!(
            cfg.global_args(),
            ["--config", "/opt/logguard-signal-bot/signal-cli", "-a", "+491701234567", "--trust-new-identities", "on-first-use"]
        );
    }

    #[tokio::test]
    async fn a_program_that_exits_at_once_says_why() {
        let dir = std::env::temp_dir().join(format!("logguard-signal-bot-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("signal-cli");
        std::fs::write(&script, "#!/bin/sh\necho 'ERROR App - User +491701234567 is not registered.' >&2\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = CliConfig { program: script, data_dir: dir.clone(), account: "+491701234567".into(), extra: vec![] };
        let e = SignalCli::start(&cfg).await.err().unwrap().to_string();
        assert!(e.contains("not registered"), "{e}");
        assert!(check_data_dir(&dir).is_err(), "a temp dir is usually 755");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_data_dir(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
