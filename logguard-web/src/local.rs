//! This node's logguard, through its console socket (`[console] socket`): a read-only socket
//! that answers `snapshot`, `digest` and `abuse 24h` / `abuse 7d` and refuses everything else
//! (logguard's `src/console.rs`).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::snapshot::{self, Snapshot};
use crate::wire::Want;

/// The largest answer read: logguard's snapshot with every active ban of a flood.
const MAX_ANSWER: u64 = 64 << 20;

/// Asks logguard `cmd` and returns its answer.
pub fn ask(socket: &Path, cmd: &str) -> Result<String> {
    ask_within(socket, cmd, Duration::from_secs(20))
}

/// Building an abuse report reads a week of logguard's actions log.
pub const ABUSE_TIMEOUT: Duration = Duration::from_secs(90);

fn ask_within(socket: &Path, cmd: &str, timeout: Duration) -> Result<String> {
    let mut s = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {} (is logguard running, with [console] socket set?)", socket.display()))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(cmd.as_bytes())?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    s.take(MAX_ANSWER + 1).read_to_string(&mut answer).context("reading logguard's answer")?;
    if answer.len() as u64 > MAX_ANSWER {
        bail!("logguard's answer is larger than {} MB", MAX_ANSWER >> 20);
    }
    if let Some(e) = answer.strip_prefix("error: ") {
        bail!("logguard: {}", e.trim());
    }
    Ok(answer)
}

/// This node's logguard, with the latest snapshot kept a few seconds: several consoles (or
/// a console and an agent) asking at once ask logguard once.
pub struct Local {
    pub socket: PathBuf,
    cache: Mutex<Option<(Instant, Arc<Snapshot>)>>,
}

const FRESH: Duration = Duration::from_secs(3);

impl Local {
    pub fn new(socket: PathBuf) -> Self {
        Local { socket, cache: Mutex::new(None) }
    }

    pub fn snapshot(&self) -> Result<Arc<Snapshot>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, s)) = cache.as_ref() {
            if at.elapsed() < FRESH {
                return Ok(Arc::clone(s));
            }
        }
        let s = Arc::new(snapshot::trim(&ask(&self.socket, "snapshot")?)?);
        *cache = Some((Instant::now(), Arc::clone(&s)));
        Ok(s)
    }

    pub fn digest(&self) -> Result<String> {
        let text = ask(&self.socket, "digest")?;
        Ok(text.chars().take(256 * 1024).collect())
    }

    /// The abuse report `want` (JSON as logguard writes it; logguard keeps it a minute).
    pub fn abuse(&self, want: Want) -> Result<String> {
        let window = want.window().context("not an abuse report")?;
        let text = ask_within(&self.socket, &format!("abuse {window}"), ABUSE_TIMEOUT)?;
        if text.contains("read-only socket") {
            bail!("this node's logguard is older: update it for abuse reports");
        }
        Ok(text)
    }

    pub fn get(&self, want: Want) -> Result<Answer> {
        Ok(match want {
            Want::Snapshot => Answer::Snapshot(self.snapshot()?),
            Want::Digest => Answer::Digest(self.digest()?),
            Want::Abuse24h | Want::Abuse7d => Answer::Abuse(self.abuse(want)?),
        })
    }
}

pub enum Answer {
    Snapshot(Arc<Snapshot>),
    Digest(String),
    Abuse(String),
}

/// The node name logguard uses in the cluster, if it is in one.
pub fn cluster_name(s: &Snapshot) -> Option<String> {
    s.value.get("cluster")?.get("node_id")?.as_str().map(str::to_string).filter(|n| crate::node_name_ok(n))
}
