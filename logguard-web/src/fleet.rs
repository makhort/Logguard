//! The console's view of the cluster: this node's logguard through its socket, the other
//! nodes through their agents (`NODES`). Asked only while someone looks (the console's pages,
//! a Prometheus scrape), at most every `REFRESH_SECS`: an idle console sends nothing.

use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::abuse::{self, Parsed};
use crate::local::Local;
use crate::snapshot::{self, Snapshot};
use crate::time::{self, Micros};
use crate::wire::{self, Reply, Want};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// For the whole reply: a large snapshot over a slow link.
const REPLY_DEADLINE: Duration = Duration::from_secs(30);
/// How long a page waits for a round of asking before it shows what is there (the slow
/// nodes' news comes with the next refresh).
const WAIT: Duration = Duration::from_secs(4);
/// The first round, when there is nothing to show yet.
const FIRST_WAIT: Duration = Duration::from_secs(12);
/// For an abuse report: the agent's logguard reads a week of its actions log first.
const ABUSE_DEADLINE: Duration = Duration::from_secs(120);
/// A node that keeps failing is asked less often: twice the wait after each failure, up to this.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A node's abuse report is asked again after this long (logguard keeps it a minute too).
const ABUSE_FRESH: Duration = Duration::from_secs(60);

/// One node as the console last saw it.
#[derive(Clone, Debug, Default)]
pub struct Node {
    /// Stable within this configuration: "0" this node, "1".. the entries of `NODES`.
    pub id: String,
    /// "local" or the agent's `host:port`.
    pub addr: String,
    /// The name the node goes by (its logguard's cluster name); the address until known.
    pub name: String,
    /// The latest data that came, even if later attempts failed.
    pub snapshot: Option<Arc<Snapshot>>,
    /// When that data came.
    pub fetched: Option<Micros>,
    /// The latest attempt's error; None when it succeeded.
    pub error: Option<String>,
    /// Since when every attempt failed.
    pub failing_since: Option<Micros>,
    pub latency_ms: Option<u64>,
    /// The node's logguard-web version (agents only).
    pub version: Option<String>,
    /// Whether its agent answers abuse reports; None until it answered.
    pub can_abuse: Option<bool>,
    /// Failed attempts in a row, and when to try again (sooner rounds skip it).
    pub fails: u32,
    pub retry_at: Option<Instant>,
}

impl Node {
    pub fn is_local(&self) -> bool {
        self.addr == "local"
    }
}

struct Inner {
    nodes: Vec<Node>,
    round_started: Option<Instant>,
    running: bool,
    rounds: u64,
}

pub struct Fleet {
    key: Option<[u8; 32]>,
    local: Option<Arc<Local>>,
    local_name: String,
    refresh: Duration,
    inner: Mutex<Inner>,
    done: Condvar,
    /// Each node's latest abuse reports: (address, which) → (when, report).
    abuse: Mutex<HashMap<(String, Want), (Instant, Parsed)>>,
}

/// A node name as an agent may send it.
pub fn name_ok(n: &str) -> bool {
    crate::node_name_ok(n)
}

impl Fleet {
    /// `local`: this node's logguard (None on a console without one); `remotes`: the agents.
    pub fn new(key: Option<[u8; 32]>, local: Option<Arc<Local>>, local_name: String, remotes: &[String], refresh: Duration) -> Self {
        let mut nodes = Vec::new();
        if local.is_some() {
            let name = if local_name.is_empty() { crate::hostname() } else { local_name.clone() };
            nodes.push(Node { id: "0".into(), addr: "local".into(), name, ..Default::default() });
        }
        for (i, addr) in remotes.iter().enumerate() {
            nodes.push(Node { id: (i + 1).to_string(), addr: addr.clone(), name: addr.clone(), ..Default::default() });
        }
        Fleet {
            key,
            local,
            local_name,
            refresh,
            inner: Mutex::new(Inner { nodes, round_started: None, running: false, rounds: 0 }),
            done: Condvar::new(),
            abuse: Mutex::default(),
        }
    }

    /// Every node, asked again first if the data is older than the refresh interval.
    pub fn view(self: &Arc<Self>) -> Vec<Node> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let stale = inner.round_started.is_none_or(|t| t.elapsed() >= self.refresh);
        if stale && !inner.running {
            inner.running = true;
            inner.round_started = Some(Instant::now());
            let fleet = Arc::clone(self);
            std::thread::spawn(move || fleet.round());
        }
        if inner.running {
            let wait = if inner.rounds == 0 { FIRST_WAIT } else { WAIT };
            inner = self.done.wait_timeout_while(inner, wait, |i| i.running).unwrap_or_else(|e| e.into_inner()).0;
        }
        dedupe_names(inner.nodes.clone())
    }

    /// Asks every node at once; each node's answer is kept as it comes.
    fn round(self: Arc<Self>) {
        let targets: Vec<(usize, String)> = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            inner.nodes.iter().enumerate().filter(|(_, n)| n.retry_at.is_none_or(|t| t <= now)).map(|(i, n)| (i, n.addr.clone())).collect()
        };
        let backoff = |fails: u32| self.refresh.saturating_mul(1 << fails.min(6)).min(MAX_BACKOFF);
        std::thread::scope(|scope| {
            for (i, addr) in targets {
                let fleet = &self;
                scope.spawn(move || {
                    let started = Instant::now();
                    let got = fleet.ask(&addr, Want::Snapshot);
                    let latency = started.elapsed().as_millis() as u64;
                    let now = time::now();
                    let mut inner = fleet.inner.lock().unwrap_or_else(|e| e.into_inner());
                    let node = &mut inner.nodes[i];
                    let answered = matches!(got, Ok(Got { snapshot: Some(_), error: None, .. }));
                    node.fails = if answered { 0 } else { node.fails.saturating_add(1) };
                    node.retry_at = (!answered && node.fails > 1).then(|| Instant::now() + backoff(node.fails - 1));
                    match got {
                        Ok(Got { name, snapshot: Some(s), version, error: None, can, .. }) => {
                            node.can_abuse = Some(node.is_local() || can.iter().any(|c| c == Want::Abuse7d.name()));
                            node.name = name;
                            node.snapshot = Some(s);
                            node.fetched = Some(now);
                            node.error = None;
                            node.failing_since = None;
                            node.latency_ms = Some(latency);
                            node.version = version;
                        }
                        Ok(Got { name, error, version, can, .. }) => {
                            // the agent answered, but its logguard didn't
                            node.can_abuse = Some(node.is_local() || can.iter().any(|c| c == Want::Abuse7d.name()));
                            node.name = name;
                            node.version = version;
                            node.latency_ms = Some(latency);
                            node.error = Some(error.unwrap_or_else(|| "no data".into()));
                            node.failing_since.get_or_insert(now);
                        }
                        Err(e) => {
                            node.error = Some(format!("{e:#}"));
                            node.failing_since.get_or_insert(now);
                        }
                    }
                });
            }
        });
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.running = false;
        inner.rounds += 1;
        self.done.notify_all();
    }

    fn ask(&self, addr: &str, want: Want) -> Result<Got> {
        if addr == "local" {
            let local = self.local.as_ref().context("no local logguard")?;
            return Ok(match want {
                Want::Snapshot => {
                    let s = local.snapshot()?;
                    let name = if self.local_name.is_empty() {
                        crate::local::cluster_name(&s).unwrap_or_else(crate::hostname)
                    } else {
                        self.local_name.clone()
                    };
                    Got { name, snapshot: Some(s), ..Default::default() }
                }
                Want::Digest => Got { digest: Some(local.digest()?), ..Default::default() },
                Want::Abuse24h | Want::Abuse7d => Got { abuse: Some(local.abuse(want)?), ..Default::default() },
            });
        }
        let key = self.key.as_ref().context("no web key")?;
        let reply = fetch(addr, key, want)?;
        let name = if name_ok(&reply.node) { reply.node.clone() } else { addr.to_string() };
        let snapshot = match &reply.snapshot {
            Some(raw) => Some(Arc::new(snapshot::trim(raw.get())?)),
            None => None,
        };
        Ok(Got {
            name,
            snapshot,
            digest: reply.digest,
            abuse: reply.abuse.map(|r| r.get().to_string()),
            version: Some(reply.version.chars().take(40).collect()),
            error: reply.error,
            can: reply.can.into_iter().take(20).collect(),
        })
    }

    /// Today's digest so far from node `id`.
    pub fn digest(&self, id: &str) -> Result<String> {
        let addr = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.nodes.iter().find(|n| n.id == id).map(|n| n.addr.clone()).ok_or_else(|| anyhow!("no node {id}"))?
        };
        let got = self.ask(&addr, Want::Digest)?;
        match (got.digest, got.error) {
            (Some(d), _) => Ok(d),
            (None, Some(e)) => bail!("{e}"),
            (None, None) => bail!("no digest"),
        }
    }

    /// The abuse report `want` of node `only` (else of every node, merged), split per provider.
    pub fn abuse(&self, want: Want, only: Option<&str>) -> Result<abuse::Report> {
        let window = want.window().context("not an abuse report")?;
        let nodes: Vec<Node> = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            dedupe_names(inner.nodes.clone()).into_iter().filter(|n| only.is_none_or(|id| n.id == id)).collect()
        };
        if let (Some(id), true) = (only, nodes.is_empty()) {
            bail!("no node {id}");
        }
        let parts = std::thread::scope(|scope| {
            let asked: Vec<_> = nodes.iter().map(|n| scope.spawn(move || self.abuse_of(n, want))).collect();
            nodes
                .iter()
                .zip(asked)
                .map(|(n, a)| (n.id.clone(), n.name.clone(), a.join().unwrap_or_else(|_| Err("failed".into()))))
                .collect()
        });
        Ok(abuse::merge(window, parts, time::now()))
    }

    fn abuse_of(&self, n: &Node, want: Want) -> Result<Parsed, String> {
        if n.retry_at.is_some_and(|t| t > Instant::now()) {
            return Err(format!("not answering: {}", n.error.as_deref().unwrap_or("down")));
        }
        match n.can_abuse {
            Some(true) => {}
            Some(false) => return Err("its logguard-web is older: update it for abuse reports".into()),
            None => return Err(n.error.clone().map_or_else(|| "not asked yet".into(), |e| format!("no answer yet: {e}"))),
        }
        let key = (n.addr.clone(), want);
        if let Some((at, p)) = self.abuse.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            if at.elapsed() < ABUSE_FRESH {
                return Ok(p.clone());
            }
        }
        let got = self.ask(&n.addr, want).map_err(|e| format!("{e:#}"))?;
        let parsed = match (got.abuse, got.error) {
            (Some(text), _) => abuse::parse(&text, &n.name).map_err(|e| format!("{e:#}"))?,
            (None, Some(e)) => return Err(e),
            (None, None) => return Err("no abuse report in the answer".into()),
        };
        let mut cache = self.abuse.lock().unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (at, _)| at.elapsed() < ABUSE_FRESH);
        cache.insert(key, (Instant::now(), parsed.clone()));
        Ok(parsed)
    }
}

#[derive(Default)]
struct Got {
    name: String,
    snapshot: Option<Arc<Snapshot>>,
    digest: Option<String>,
    abuse: Option<String>,
    version: Option<String>,
    error: Option<String>,
    /// What the agent answers ([`Want::name`]).
    can: Vec<String>,
}

/// Two nodes that call themselves the same get their address added.
fn dedupe_names(mut nodes: Vec<Node>) -> Vec<Node> {
    let names: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
    for n in &mut nodes {
        if names.iter().filter(|x| **x == n.name).count() > 1 {
            n.name = format!("{} ({})", n.name, n.addr);
        }
    }
    nodes
}

/// One exchange with the agent at `addr`.
pub fn fetch(addr: &str, key: &[u8; 32], want: Want) -> Result<Reply> {
    let target =
        addr.to_socket_addrs().with_context(|| format!("resolving {addr}"))?.next().ok_or_else(|| anyhow!("{addr}: no address"))?;
    let mut s = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT).with_context(|| format!("connecting to {addr}"))?;
    s.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    let (frame, pending) = wire::request(key, want, time::now())?;
    use std::io::Write;
    s.write_all(&frame).context("sending the request")?;
    let deadline = if want.window().is_some() { ABUSE_DEADLINE } else { REPLY_DEADLINE };
    let body = wire::read_frame(&mut crate::agent::Deadline { s: &mut s, until: Instant::now() + deadline }, wire::MAX_REPLY)
        .with_context(|| format!("reading {addr}'s reply"))?;
    wire::open_reply(key, pending, &body, time::now()).with_context(|| format!("{addr}'s reply"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dead_node_is_asked_less_often() {
        // nothing listens on port 1: refused at once
        let fleet = Arc::new(Fleet::new(Some([1; 32]), None, String::new(), &["127.0.0.1:1".into()], Duration::from_secs(10)));
        let node = |f: &Fleet| f.inner.lock().unwrap().nodes[0].clone();
        Arc::clone(&fleet).round();
        assert_eq!((node(&fleet).fails, node(&fleet).retry_at), (1, None), "one failure: asked again next round");
        Arc::clone(&fleet).round();
        let wait = node(&fleet).retry_at.expect("waits now") - Instant::now();
        assert!(wait > Duration::from_secs(15) && wait <= Duration::from_secs(20), "{wait:?}");
        Arc::clone(&fleet).round();
        assert_eq!(node(&fleet).fails, 2, "not asked before then");
        assert!(fleet.abuse_of(&node(&fleet), Want::Abuse7d).unwrap_err().starts_with("not answering"));
    }
}
