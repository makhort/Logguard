//! The agent: answers the consoles' requests for this node's data (`AGENT_LISTEN`), one
//! sealed request and one sealed reply per connection (see `wire`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::value::RawValue;

use crate::local::{Answer, Local};
use crate::netlist::{normalize, Allow};
use crate::say;
use crate::time::{self, Micros};
use crate::wire::{self, Reply, Want};

/// Connections served at once, and from one address: consoles ask every few seconds.
const MAX_CONNECTIONS: usize = 8;
const MAX_PER_SOURCE: usize = 2;
/// Whole-request deadline: a slow sender can't hold a slot.
const READ_DEADLINE: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct AgentCfg {
    pub listen: String,
    pub allow: Allow,
    pub key: [u8; 32],
    /// `NODE_NAME`; empty: logguard's cluster name, else the host name.
    pub node: String,
}

/// Request ids seen within the clock skew window: a recorded request sent again is refused
/// (its reply couldn't be read anyway: it is sealed to the console's fresh key).
#[derive(Default)]
struct Seen {
    order: VecDeque<(Micros, String)>,
    ids: HashSet<String>,
}

impl Seen {
    /// False when `id` was seen before.
    fn insert(&mut self, id: &str, now: Micros) -> bool {
        while self.order.front().is_some_and(|(t, _)| *t < now - wire::MAX_SKEW || self.order.len() > 50_000) {
            let (_, old) = self.order.pop_front().expect("not empty");
            self.ids.remove(&old);
        }
        if !self.ids.insert(id.to_string()) {
            return false;
        }
        self.order.push_back((now, id.to_string()));
        true
    }
}

/// The name this node goes by in the consoles.
pub fn node_name(configured: &str, local: &Local) -> String {
    if !configured.is_empty() {
        return configured.to_string();
    }
    local.snapshot().ok().and_then(|s| crate::local::cluster_name(&s)).unwrap_or_else(crate::hostname)
}

struct Shared {
    cfg: AgentCfg,
    local: Arc<Local>,
    seen: Mutex<Seen>,
}

/// Starts the agent's listener thread.
pub fn serve(cfg: AgentCfg, local: Arc<Local>) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(&cfg.listen).with_context(|| format!("binding AGENT_LISTEN {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let shared = Arc::new(Shared { cfg, local, seen: Mutex::default() });
    let active = Arc::new(AtomicUsize::new(0));
    let per_source: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            let Ok(ip) = s.peer_addr().map(|a| normalize(a.ip())) else { continue };
            if !shared.cfg.allow.admits(ip) {
                say!("agent: refused connection from {ip}: not in AGENT_ALLOW");
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                continue;
            }
            {
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                let n = open.entry(ip).or_default();
                if *n >= MAX_PER_SOURCE {
                    continue;
                }
                *n += 1;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let (shared, active, per_source) = (Arc::clone(&shared), Arc::clone(&active), Arc::clone(&per_source));
            std::thread::spawn(move || {
                if let Err(e) = answer(&shared, s, ip) {
                    say!("agent: rejected request from {ip}: {e:#}");
                }
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(n) = open.get_mut(&ip) {
                    *n -= 1;
                    if *n == 0 {
                        open.remove(&ip);
                    }
                }
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(addr)
}

/// One overall deadline for every read of a connection.
pub struct Deadline<'a> {
    pub s: &'a mut TcpStream,
    pub until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "request not received in time"));
        }
        self.s.set_read_timeout(Some(left))?;
        self.s.read(buf)
    }
}

fn answer(shared: &Shared, mut s: TcpStream, _ip: IpAddr) -> Result<()> {
    let body = wire::read_frame(&mut Deadline { s: &mut s, until: Instant::now() + READ_DEADLINE }, wire::MAX_REQUEST)?;
    let now = time::now();
    let asked = wire::open_request(&shared.cfg.key, &body, now)?;
    if !shared.seen.lock().unwrap_or_else(|e| e.into_inner()).insert(&asked.req.id, now) {
        bail!("a request sent before (replayed)");
    }
    let mut reply = Reply {
        v: 1,
        node: node_name(&shared.cfg.node, &shared.local),
        sent: time::now(),
        version: env!("CARGO_PKG_VERSION").into(),
        error: None,
        snapshot: None,
        digest: None,
        abuse: None,
        can: Want::ALL.iter().map(|w| w.name().to_string()).collect(),
    };
    match shared.local.get(asked.req.want) {
        Ok(Answer::Snapshot(snap)) => reply.snapshot = Some(RawValue::from_string(serde_json::to_string(&snap.to_value())?)?),
        Ok(Answer::Digest(text)) => reply.digest = Some(text),
        Ok(Answer::Abuse(json)) => match RawValue::from_string(json) {
            Ok(raw) => reply.abuse = Some(raw),
            Err(e) => reply.error = Some(format!("logguard's abuse report is not JSON: {e}")),
        },
        Err(e) => reply.error = Some(format!("{e:#}")),
    }
    reply.sent = time::now();
    let frame = wire::seal_reply(&shared.cfg.key, &asked, &reply)?;
    s.set_write_timeout(Some(WRITE_TIMEOUT))?;
    s.write_all(&frame).context("sending the reply")?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replays_are_refused() {
        let mut seen = Seen::default();
        assert!(seen.insert("a", 0));
        assert!(!seen.insert("a", 1));
        assert!(seen.insert("b", 1));
        // forgotten once out of the window (then the request is too old anyway)
        assert!(seen.insert("a", wire::MAX_SKEW * 3));
    }
}
