//! Cluster mode: logguard nodes share attack information directly over TCP,
//! with no VPN or other infrastructure required.
//!
//! **What is shared** ("facts"): bans and unbans, per-address suspicion reports
//! (points this node scored for an address since the last sync), and addresses
//! that authenticated successfully (trust). Each fact has a globally unique id
//! `(origin node, sequence)`; nodes apply each fact once and forward it to their own
//! peers up to `max_hops`, so full meshes, chains and stars all work without loops.
//!
//! **Security**: every message is encrypted and authenticated with
//! XChaCha20-Poly1305 under a pre-shared 256-bit cluster key (random 192-bit nonce per
//! message). Anyone without the key can neither read nor inject facts. Messages older
//! than `max_clock_skew` are rejected (replays are idempotent anyway, as facts are
//! de-duplicated). All members are equally trusted: protect the key like a root password,
//! except peers named in `peer_accept`: what arrives over a connection from such a peer's
//! address (its own facts and those it forwards) is limited to the kinds listed there. The
//! limit goes by the connection's source address, not the node name in the message, which
//! any key holder can write; so it needs `allow_only_peers`.
//!
//! **Wire format**: `"LGC1"` | u32 big-endian length | 24-byte nonce | ciphertext of a
//! JSON `Envelope`. One envelope per TCP connection; no reply.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::net::Net;
use crate::time::{self, Dur, Micros, SEC};

const MAGIC: &[u8; 4] = b"LGC1";
const AAD: &[u8] = b"logguard-cluster-v1";
/// Largest accepted frame. Senders split their facts into chunks of `CHUNK` bytes, so even
/// a full sync of `MAX_KNOWN` facts never needs more; and at most `MAX_CONNECTIONS` frames
/// (each also decrypted into a copy) fit easily in the service's memory limit.
const MAX_FRAME: usize = 1 << 20;
const CHUNK: usize = 512 * 1024;
const MAX_CONNECTIONS: usize = 8;
/// Whole-frame deadline per connection: a slow sender can't hold a connection slot open.
const READ_DEADLINE: Duration = Duration::from_secs(30);
/// Facts remembered at once (bans with long timeouts accumulate).
const MAX_KNOWN: usize = 200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    Bans,
    Unbans,
    Reports,
    /// Trusted addresses and operator allowlist entries.
    Trust,
    /// Admin notifications relayed to a node that delivers them (XMPP, or Telegram).
    Notices,
    /// Files sent with `logguard cluster-send-report` (abuse reports). Not a fact: only
    /// `peer_accept` lists it; other peers' files are taken whenever `inbox` is set.
    Files,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterCfg {
    pub enabled: bool,
    /// Unique name of this node; defaults to the host name.
    pub node_id: String,
    /// Address to accept peers on; empty = send-only node.
    pub listen: String,
    /// Other nodes, `host:port`. Partial lists work: facts are forwarded.
    pub peers: Vec<String>,
    /// Base64 cluster key (`logguard cluster-keygen`). Prefer `key_file`.
    pub key: String,
    /// File containing the base64 key (mode 0600). During a key rotation, keys in
    /// `<key_file>.next` and `<key_file>.prev` are accepted from peers too (messages are always
    /// sent with this one), so nodes can switch one at a time (README, "Rotating the key").
    pub key_file: PathBuf,
    /// Remind the admins, once a week, to rotate a key file older than this (0 = never).
    /// Its age is the file's modification time: when it was installed or last rotated.
    pub rotate_after: Dur,
    pub sync_interval: Dur,
    /// Resend everything this often, so restarted peers catch up.
    pub full_sync_every: Dur,
    /// What this node sends its peers: its own facts and the ones it forwards.
    pub share: Vec<FactKind>,
    pub accept: Vec<FactKind>,
    /// Bans learned from peers last at most this long here.
    pub max_remote_ban: Dur,
    /// Peer-reported points count this much here (0 disables, 1 = like local evidence).
    pub report_factor: f64,
    /// Report an address once this node scored at least this many points for it.
    pub min_report_points: f64,
    pub max_hops: u8,
    pub max_clock_skew: Dur,
    /// Accept connections only from the addresses `peers` resolve to.
    pub allow_only_peers: bool,
    /// Where files from peers (`logguard cluster-send-report`, e.g. a weekly abuse
    /// report) are written; empty = refuse them.
    pub inbox: PathBuf,
    /// What some peers may hand this node, by the peer as written in `peers`, e.g.
    /// `{ "203.0.113.9:7946" = ["notices", "files"] }` for a node that only relays to
    /// Telegram: it can't ban, unban, report or trust anything here, even if it is broken
    /// into. Peers not listed: `accept`. Needs `allow_only_peers`.
    pub peer_accept: BTreeMap<String, Vec<FactKind>>,
    /// Relay this node's admin notifications to the peers even though it delivers them
    /// itself ([notify] enabled), e.g. to a node that forwards them to Telegram. Without
    /// it, only nodes with [notify] off relay theirs.
    pub relay_notices: bool,
}

impl Default for ClusterCfg {
    fn default() -> Self {
        let all = vec![FactKind::Bans, FactKind::Unbans, FactKind::Reports, FactKind::Trust, FactKind::Notices];
        ClusterCfg {
            enabled: false,
            node_id: String::new(),
            listen: "0.0.0.0:7946".into(),
            peers: vec![],
            key: String::new(),
            key_file: PathBuf::new(),
            rotate_after: Dur(180 * 86_400),
            sync_interval: Dur(10),
            full_sync_every: Dur(600),
            share: all.clone(),
            accept: all,
            max_remote_ban: Dur(86_400),
            report_factor: 0.5,
            min_report_points: 10.0,
            max_hops: 3,
            max_clock_skew: Dur(300),
            allow_only_peers: true,
            inbox: PathBuf::from("/var/lib/logguard/inbox"),
            peer_accept: BTreeMap::new(),
            relay_notices: false,
        }
    }
}

pub fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "logguard".into())
}

impl ClusterCfg {
    pub fn node_name(&self) -> String {
        if self.node_id.is_empty() {
            hostname()
        } else {
            self.node_id.clone()
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.key.is_empty() && self.key_file.as_os_str().is_empty() {
            bail!("[cluster] needs `key` or `key_file` (generate one with `logguard cluster-keygen`)");
        }
        if !self.key.is_empty() {
            decode_key(&self.key)?;
        }
        if !self.listen.is_empty() {
            self.listen.parse::<SocketAddr>().map_err(|_| anyhow!("[cluster] listen must be ip:port, got '{}'", self.listen))?;
        }
        if let Some(p) = self.peers.iter().find(|p| p.rsplit_once(':').is_none_or(|(_, port)| port.parse::<u16>().is_err())) {
            bail!("[cluster] peer '{p}' must be host:port");
        }
        if !(0.0..=1.0).contains(&self.report_factor) {
            bail!("[cluster] report_factor must be within 0..=1");
        }
        if self.node_name().chars().any(|c| c.is_whitespace() || c.is_control()) {
            bail!("[cluster] node_id must not contain whitespace");
        }
        if let Some(p) = self.peer_accept.keys().find(|p| !self.peers.contains(p)) {
            bail!("[cluster] peer_accept: '{p}' is not one of the peers (write it as in `peers`)");
        }
        if !self.peer_accept.is_empty() && !self.allow_only_peers {
            bail!("[cluster] peer_accept needs allow_only_peers = true: the limit goes by the connection's address");
        }
        Ok(())
    }

    pub fn load_key(&self) -> Result<[u8; 32]> {
        if !self.key.is_empty() {
            return decode_key(&self.key);
        }
        let text = std::fs::read_to_string(&self.key_file).with_context(|| format!("reading {}", self.key_file.display()))?;
        decode_key(text.trim())
    }

    /// When the key file was installed or last rotated (its modification time); None for a
    /// key written inline in the config.
    pub fn key_since(&self) -> Option<Micros> {
        if !self.key.is_empty() {
            return None;
        }
        let modified = std::fs::metadata(&self.key_file).and_then(|m| m.modified()).ok()?;
        modified.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_micros() as Micros)
    }

    /// The weekly reminder to rotate the key, once it is older than `rotate_after`.
    pub fn rotation_reminder(&self, since: Option<Micros>, now: Micros) -> Option<String> {
        let since = since?;
        let age = now - since;
        (self.rotate_after.0 > 0 && age >= self.rotate_after.micros()).then(|| {
            format!(
                "the cluster key {} is {} days old (rotate after {}): rotate it with deploy/rotate-cluster-key.sh start|switch|finish",
                self.key_file.display(),
                age / (86_400 * SEC),
                self.rotate_after
            )
        })
    }

    /// Keys accepted from peers besides the main one, during a rotation: `<key_file>.next`
    /// and `<key_file>.prev` when present, with their file names. A file that exists but
    /// holds no valid key is an error, so a botched rotation step stops the daemon loudly.
    pub fn load_extra_keys(&self) -> Result<Vec<(PathBuf, [u8; 32])>> {
        if !self.key.is_empty() || self.key_file.as_os_str().is_empty() {
            return Ok(vec![]);
        }
        let mut out = vec![];
        for ext in ["next", "prev"] {
            let mut name = self.key_file.clone().into_os_string();
            name.push(format!(".{ext}"));
            let path = PathBuf::from(name);
            match std::fs::read_to_string(&path) {
                Ok(text) => out.push((path.clone(), decode_key(text.trim()).with_context(|| format!("in {}", path.display()))?)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            }
        }
        Ok(out)
    }
}

/// A key's public fingerprint (SHA-256, first 6 bytes in hex): equal on every node that
/// has the same key, and revealing nothing about it.
pub fn key_id(key: &[u8; 32]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(key)[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// A key as `cluster-keygen` writes it (base64 of 32 bytes).
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).context("cluster key is not valid base64")?;
    raw.try_into().map_err(|_| anyhow!("cluster key must be exactly 32 bytes (use `logguard cluster-keygen`)"))
}

pub fn generate_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(XChaCha20Poly1305::generate_key(&mut OsRng))
}

// ------------------------------------------------------------------ facts

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactBody {
    Ban {
        net: Net,
        until: Micros,
        reason: String,
    },
    Unban {
        net: Net,
        reason: String,
    },
    Report {
        ip: IpAddr,
        points: f64,
        signals: String,
    },
    Trust {
        ip: IpAddr,
    },
    /// Operator allowlist entry; `until` in the past revokes it.
    Allow {
        net: Net,
        until: Micros,
        note: String,
    },
    Notice {
        subject: String,
        body: String,
    },
}

impl FactBody {
    pub fn kind(&self) -> FactKind {
        match self {
            FactBody::Ban { .. } => FactKind::Bans,
            FactBody::Unban { .. } => FactKind::Unbans,
            FactBody::Report { .. } => FactKind::Reports,
            FactBody::Trust { .. } | FactBody::Allow { .. } => FactKind::Trust,
            FactBody::Notice { .. } => FactKind::Notices,
        }
    }

    fn expires(&self, created: Micros) -> Micros {
        let after = |secs: i64| created.saturating_add(secs * SEC);
        match self {
            FactBody::Ban { until, .. } => *until,
            FactBody::Unban { .. } => after(86_400),
            FactBody::Report { .. } => after(3600),
            FactBody::Trust { .. } => after(14 * 86_400),
            FactBody::Allow { until, .. } => (*until).max(after(3600)),
            FactBody::Notice { .. } => after(3600),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub origin: String,
    pub seq: u64,
    pub created: Micros,
    pub hops: u8,
    #[serde(flatten)]
    pub body: FactBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    pub from: String,
    pub sent: Micros,
    pub facts: Vec<Fact>,
    /// A file sent once to the direct peers (`logguard cluster-send-report`). Not a fact:
    /// it is neither kept, forwarded nor resent. Older nodes ignore the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PeerFile>,
}

/// Names of the files peers may send, and so of the files written to `[cluster] inbox`:
/// a node's own abuse report (JSON, for merging), and a merged one (text, for a node
/// that hands it to a bot without merging itself).
pub const PEER_FILES: &[&str] = &["abuse", "abuse-report"];

/// The inbox file a peer's file is written to: `abuse-<node>.json.gz`, `abuse-report-<node>.txt.gz`.
pub fn inbox_name(name: &str, node: &str) -> String {
    let ext = if name == "abuse-report" { "txt" } else { "json" };
    format!("{name}-{node}.{ext}.gz")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerFile {
    /// What it is: one of [`PEER_FILES`].
    pub name: String,
    /// The content, gzip-compressed, in base64.
    pub gz: String,
}

/// A frame carrying `content` as the file `name` (gzip-compressed: a week's JSON abuse
/// report shrinks ~10x, and a frame holds at most 1 MB).
pub fn file_frame(key: &[u8; 32], from: &str, name: &str, content: &[u8], now: Micros) -> Result<Vec<u8>> {
    if !PEER_FILES.contains(&name) {
        bail!("unknown file name '{name}' (known: {})", PEER_FILES.join(", "));
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(content)?;
    let gz = base64::engine::general_purpose::STANDARD.encode(gz.finish()?);
    let env = Envelope { v: 1, from: from.into(), sent: now, facts: vec![], file: Some(PeerFile { name: name.into(), gz }) };
    seal(key, &env)
}

/// Writes a peer's file to `dir` as [`inbox_name`] (mode 0600, replacing the
/// previous one atomically) and returns its path. The content is only checked to be gzip:
/// nothing here parses it.
pub fn store_file(dir: &Path, env: &Envelope, max_skew: Dur, now: Micros) -> Result<PathBuf> {
    let file = env.file.as_ref().context("no file in the message")?;
    if dir.as_os_str().is_empty() {
        bail!("[cluster] inbox is empty: files from peers are refused");
    }
    if env.sent.abs_diff(now) > max_skew.micros().unsigned_abs() {
        bail!("sent at {}, beyond max_clock_skew", time::fmt_ts(env.sent));
    }
    if !PEER_FILES.contains(&file.name.as_str()) {
        bail!("unknown file name '{}'", file.name.chars().take(40).collect::<String>());
    }
    let node_ok =
        |n: &str| (1..=64).contains(&n.len()) && !n.starts_with('.') && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !node_ok(&env.from) {
        bail!("node name unfit for a file name");
    }
    let gz = base64::engine::general_purpose::STANDARD.decode(&file.gz).context("file content is not base64")?;
    if !gz.starts_with(&[0x1f, 0x8b]) {
        bail!("file content is not gzip");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join(inbox_name(&file.name, &env.from));
    let tmp = dir.join(format!(".{}-{}.tmp", file.name, env.from));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(&gz)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

// ------------------------------------------------------------------ crypto / framing

pub fn seal(key: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plain = serde_json::to_vec(env)?;
    let ct = cipher.encrypt(&nonce, Payload { msg: &plain, aad: AAD }).map_err(|_| anyhow!("encryption failed"))?;
    if 24 + ct.len() > MAX_FRAME {
        bail!("message too large for one frame ({} bytes)", 24 + ct.len());
    }
    let mut frame = Vec::with_capacity(8 + 24 + ct.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&((24 + ct.len()) as u32).to_be_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ct);
    Ok(frame)
}

/// Opens a frame with whichever of `keys` it was sealed with.
pub fn open_any(keys: &[[u8; 32]], body: &[u8]) -> Result<Envelope> {
    let mut last = anyhow!("no cluster key");
    for k in keys {
        match open(k, body) {
            Ok(env) => return Ok(env),
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub fn open(key: &[u8; 32], body: &[u8]) -> Result<Envelope> {
    if body.len() < 24 + 16 {
        bail!("frame too short");
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&body[..24]);
    let plain = cipher
        .decrypt(nonce, Payload { msg: &body[24..], aad: AAD })
        .map_err(|_| anyhow!("authentication failed (wrong cluster key or tampered message)"))?;
    let env: Envelope = serde_json::from_slice(&plain).context("decoding envelope")?;
    if env.v != 1 {
        bail!("unsupported protocol version {}", env.v);
    }
    Ok(env)
}

/// Applies one overall deadline to all reads of a TCP stream.
struct Deadline<'a> {
    s: &'a mut TcpStream,
    until: std::time::Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "frame not received in time"));
        }
        self.s.set_read_timeout(Some(left))?;
        self.s.read(buf)
    }
}

fn read_frame(s: &mut impl Read) -> Result<Vec<u8>> {
    let mut head = [0u8; 8];
    s.read_exact(&mut head)?;
    if &head[..4] != MAGIC {
        bail!("not a logguard cluster connection");
    }
    let len = u32::from_be_bytes(head[4..].try_into().expect("4 bytes")) as usize;
    if len > MAX_FRAME {
        bail!("frame too large ({len} bytes)");
    }
    // Grow with the data actually received: a peer can't make us reserve memory by
    // merely claiming a large frame.
    let mut body = Vec::with_capacity(len.min(64 * 1024));
    s.take(len as u64).read_to_end(&mut body)?;
    if body.len() != len {
        bail!("truncated frame ({} of {len} bytes)", body.len());
    }
    Ok(body)
}

// ------------------------------------------------------------------ state

#[derive(Clone, Debug)]
struct Stored {
    fact: Fact,
    expires: Micros,
    learned: Micros,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerView {
    pub addr: String,
    pub last_ok: Option<Micros>,
    pub last_error: Option<String>,
    pub failing_since: Option<Micros>,
    #[serde(skip)]
    watermark: Micros,
    #[serde(skip)]
    last_full: Micros,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClusterView {
    pub node_id: String,
    pub listen: String,
    pub peers: Vec<PeerView>,
    /// Nodes we heard from (directly), with the time of their last message.
    pub heard_from: BTreeMap<String, Micros>,
    pub facts_known: usize,
    pub facts_received: u64,
    pub facts_sent: u64,
    pub rejected: u64,
    /// Facts a limited peer may not hand this node (`peer_accept`).
    #[serde(default)]
    pub refused_by_limit: u64,
    /// Fingerprint of the key messages are sent with.
    #[serde(default)]
    pub key_id: String,
    /// Fingerprints of the other keys accepted (during a rotation).
    #[serde(default)]
    pub extra_key_ids: Vec<String>,
    /// When the key file was installed or last rotated.
    #[serde(default)]
    pub key_since: Option<Micros>,
}

pub struct Cluster {
    pub cfg: ClusterCfg,
    pub node_id: String,
    key: [u8; 32],
    /// Also accepted from peers (key rotation).
    extra_keys: Vec<[u8; 32]>,
    last_seq: u64,
    known: HashMap<(String, u64), Stored>,
    pub view: ClusterView,
    /// `peer_accept` by address, shared with the listener (files are taken there).
    pub limits: PeerLimits,
    /// (sender, kind) pairs already logged as refused.
    refused_logged: std::collections::HashSet<(String, FactKind)>,
}

impl Cluster {
    pub fn new(cfg: &ClusterCfg) -> Result<Self> {
        let key = cfg.load_key()?;
        let extra: Vec<[u8; 32]> = cfg.load_extra_keys()?.into_iter().map(|(_, k)| k).filter(|k| *k != key).collect();
        let node_id = cfg.node_name();
        let peers = cfg.peers.iter().map(|p| PeerView { addr: p.clone(), ..Default::default() }).collect();
        Ok(Cluster {
            cfg: cfg.clone(),
            view: ClusterView {
                node_id: node_id.clone(),
                listen: cfg.listen.clone(),
                peers,
                key_id: key_id(&key),
                extra_key_ids: extra.iter().map(key_id).collect(),
                key_since: cfg.key_since(),
                ..Default::default()
            },
            node_id,
            key,
            extra_keys: extra,
            last_seq: 0,
            known: HashMap::new(),
            limits: PeerLimits::new(cfg),
            refused_logged: Default::default(),
        })
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Every key accepted from peers: the main one first.
    pub fn keys(&self) -> Vec<[u8; 32]> {
        std::iter::once(self.key).chain(self.extra_keys.iter().copied()).collect()
    }

    /// Resolves peers to addresses; they are never banned (and accepted by nftables).
    pub fn peer_nets(&self) -> Vec<Net> {
        let (nets, errors) = resolve_peers(&self.cfg.peers);
        for e in errors {
            eprintln!("logguard: {e}");
        }
        nets
    }

    /// Records a fact produced by this node. Sequence numbers are time-based, so they stay
    /// unique across restarts without persistence.
    pub fn originate(&mut self, body: FactBody, now: Micros) {
        if !self.cfg.share.contains(&body.kind()) {
            return;
        }
        let seq = self.last_seq.saturating_add(1).max(time::now().max(now) as u64);
        self.last_seq = seq;
        let fact = Fact { origin: self.node_id.clone(), seq, created: now, hops: 0, body };
        let expires = fact.body.expires(now);
        self.known.insert((fact.origin.clone(), seq), Stored { fact, expires, learned: now });
    }

    /// Validates an incoming envelope (that came from the address `from`) and returns the
    /// facts this node hasn't seen yet.
    pub fn ingest(&mut self, env: Envelope, from: Option<IpAddr>, now: Micros) -> Vec<Fact> {
        let skew = self.cfg.max_clock_skew.micros();
        if env.from == self.node_id || env.sent.abs_diff(now) > skew.unsigned_abs() {
            self.view.rejected += 1;
            return vec![];
        }
        self.view.heard_from.insert(env.from.clone(), now);
        let limit = self.limits.of(from);
        let mut fresh = Vec::new();
        for mut f in env.facts {
            let id = (f.origin.clone(), f.seq);
            if f.origin == self.node_id || self.known.contains_key(&id) {
                continue;
            }
            let kind = f.body.kind();
            if limit.as_ref().is_some_and(|l| !l.contains(&kind)) {
                self.view.refused_by_limit += 1;
                if self.refused_logged.len() < 100 && self.refused_logged.insert((env.from.clone(), kind)) {
                    eprintln!(
                        "logguard: cluster: {kind:?} from '{}' ({}) refused: [cluster] peer_accept doesn't allow it from there",
                        env.from,
                        from.map_or("?".into(), |ip| ip.to_string())
                    );
                }
                continue;
            }
            let expires = f.body.expires(f.created);
            if f.hops >= self.cfg.max_hops || expires <= now || f.created > now + skew || !self.cfg.accept.contains(&f.body.kind()) {
                continue;
            }
            if self.known.len() >= MAX_KNOWN {
                self.view.rejected += 1;
                continue;
            }
            f.hops += 1;
            self.known.insert(id, Stored { fact: f.clone(), expires, learned: now });
            fresh.push(f);
        }
        self.view.facts_received += fresh.len() as u64;
        fresh
    }

    /// Builds one envelope per peer: new facts since the last send, or everything on a
    /// full sync. Empty envelopes double as heartbeats.
    pub fn outgoing(&mut self, now: Micros) -> Vec<(usize, Vec<u8>)> {
        self.known.retain(|_, s| s.expires > now);
        self.view.facts_known = self.known.len();
        let full_every = self.cfg.full_sync_every.micros();
        let mut out = Vec::new();
        for i in 0..self.view.peers.len() {
            let peer = &mut self.view.peers[i];
            let full = now - peer.last_full >= full_every;
            let since = if full { Micros::MIN } else { peer.watermark };
            let share = &self.cfg.share;
            let facts: Vec<Fact> = self
                .known
                .values()
                .filter(|s| s.learned > since && s.fact.hops < self.cfg.max_hops && share.contains(&s.fact.body.kind()))
                .map(|s| s.fact.clone())
                .collect();
            if full {
                peer.last_full = now;
            }
            peer.watermark = now;
            self.view.facts_sent += facts.len() as u64;
            // One frame per CHUNK bytes of facts (an empty one still says "alive").
            let mut chunks: Vec<Vec<Fact>> = vec![vec![]];
            let mut size = 0;
            for f in facts {
                let n = serde_json::to_vec(&f).map_or(0, |v| v.len()) + 1;
                if size + n > CHUNK && !chunks.last().is_some_and(|c| c.is_empty()) {
                    chunks.push(vec![]);
                    size = 0;
                }
                size += n;
                chunks.last_mut().expect("never empty").push(f);
            }
            for facts in chunks {
                let env = Envelope { v: 1, from: self.node_id.clone(), sent: time::now(), facts, file: None };
                match seal(&self.key, &env) {
                    Ok(frame) => out.push((i, frame)),
                    Err(e) => eprintln!("logguard: cluster: {e:#}"),
                }
            }
        }
        out
    }

    /// Records a delivery result. A failed delivery forces a full resend next time.
    /// Returns an alert message when a peer has been unreachable for 5 minutes.
    pub fn delivered(&mut self, peer: usize, result: Result<(), String>, now: Micros) -> Option<String> {
        let p = self.view.peers.get_mut(peer)?;
        match result {
            Ok(()) => {
                p.last_ok = Some(now);
                p.last_error = None;
                p.failing_since = None;
                None
            }
            Err(e) => {
                p.last_full = Micros::MIN / 2;
                p.last_error = Some(e.clone());
                let since = *p.failing_since.get_or_insert(now);
                (now - since >= 5 * time::MIN).then(|| format!("cluster peer {} unreachable since {}: {e}", p.addr, time::fmt_ts(since)))
            }
        }
    }
}

/// The addresses `peers` (`host:port`) resolve to, sorted, and what could not be resolved.
pub fn resolve_peers(peers: &[String]) -> (Vec<Net>, Vec<String>) {
    let (mut nets, mut errors) = (Vec::new(), Vec::new());
    for p in peers {
        match p.to_socket_addrs() {
            Ok(addrs) => nets.extend(addrs.map(|a| Net::host(crate::net::normalize(a.ip())))),
            Err(e) => errors.push(format!("cluster peer {p}: cannot resolve: {e}")),
        }
    }
    nets.sort();
    nets.dedup();
    (nets, errors)
}

// ------------------------------------------------------------------ network threads

/// `peer_accept` by the addresses the limited peers resolve to, shared between the
/// listener's threads (files) and the main loop (facts).
#[derive(Clone, Debug, Default)]
pub struct PeerLimits(Arc<RwLock<Vec<Limit>>>);

/// A limited peer (as in `peers`), one of its addresses, and what it may hand over.
type Limit = (String, Net, Vec<FactKind>);

impl PeerLimits {
    pub fn new(cfg: &ClusterCfg) -> Self {
        let limits = PeerLimits::default();
        limits.refresh(cfg);
        limits
    }

    /// Resolves the limited peers again. A peer that doesn't resolve keeps its old
    /// addresses: the listener may still admit them.
    pub fn refresh(&self, cfg: &ClusterCfg) {
        let mut list = self.0.write().unwrap_or_else(|e| e.into_inner());
        for (peer, kinds) in &cfg.peer_accept {
            let (nets, errors) = resolve_peers(std::slice::from_ref(peer));
            if !errors.is_empty() || nets.is_empty() {
                continue;
            }
            list.retain(|(p, _, _)| p != peer);
            list.extend(nets.into_iter().map(|n| (peer.clone(), n, kinds.clone())));
        }
    }

    /// What a connection from `ip` may deliver: `None` when it isn't limited. An address
    /// of several limited peers gets what any of them may.
    pub fn of(&self, ip: Option<IpAddr>) -> Option<Vec<FactKind>> {
        let list = self.0.read().unwrap_or_else(|e| e.into_inner());
        if list.is_empty() {
            return None;
        }
        let Some(ip) = ip.map(crate::net::normalize) else { return Some(vec![]) };
        let mut kinds: Option<Vec<FactKind>> = None;
        for (_, _, k) in list.iter().filter(|(_, n, _)| n.contains(ip)) {
            kinds.get_or_insert_with(Vec::new).extend(k.iter().copied());
        }
        kinds
    }
}

/// Who may connect to the cluster listener.
#[derive(Clone, Debug)]
pub enum PeerFilter {
    /// Anyone (`allow_only_peers = false`, for NATed peers): the key still decides.
    Anyone,
    /// The addresses the peers resolve to, kept current by the daemon. While none resolved
    /// (DNS down at boot), every connection is refused: never "anyone" by accident.
    Peers(Arc<RwLock<Vec<Net>>>),
}

impl PeerFilter {
    pub fn peers(nets: Vec<Net>) -> Self {
        PeerFilter::Peers(Arc::new(RwLock::new(nets)))
    }

    /// Replaces the peers' addresses (no-op for `Anyone`).
    pub fn set(&self, nets: Vec<Net>) {
        if let PeerFilter::Peers(list) = self {
            *list.write().unwrap_or_else(|e| e.into_inner()) = nets;
        }
    }

    fn admits(&self, ip: Option<IpAddr>) -> bool {
        match self {
            PeerFilter::Anyone => true,
            PeerFilter::Peers(list) => ip.is_some_and(|ip| list.read().unwrap_or_else(|e| e.into_inner()).iter().any(|n| n.contains(ip))),
        }
    }
}

/// Accepts peer connections; authenticated envelopes are passed to `deliver`.
/// Connections `allowed` doesn't admit are dropped unread.
pub fn serve(
    listen: &str,
    keys: Vec<[u8; 32]>,
    allowed: PeerFilter,
    deliver: impl Fn(Envelope, Option<IpAddr>) -> bool + Send + Sync + 'static,
) -> Result<()> {
    let keys = Arc::new(keys);
    let listener = TcpListener::bind(listen).with_context(|| format!("binding cluster listener {listen}"))?;
    let deliver = Arc::new(deliver);
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        let mut logged = std::collections::HashSet::new();
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let from = s.peer_addr().map(|a| crate::net::normalize(a.ip())).ok();
            if !allowed.admits(from) {
                if let Some(ip) = from.filter(|_| logged.len() < 1000) {
                    if logged.insert(ip) {
                        eprintln!("logguard: cluster: refused connection from {ip} (not a configured peer; set allow_only_peers = false if it is NATed)");
                    }
                }
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                continue; // dropped: too many concurrent peers/probes
            }
            active.fetch_add(1, Ordering::Relaxed);
            let (deliver, active, keys) = (Arc::clone(&deliver), Arc::clone(&active), Arc::clone(&keys));
            std::thread::spawn(move || {
                let peer = s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
                let mut r = Deadline { s: &mut s, until: std::time::Instant::now() + READ_DEADLINE };
                match read_frame(&mut r).and_then(|body| open_any(&keys, &body)) {
                    Ok(env) => {
                        deliver(env, from);
                    }
                    Err(e) => eprintln!("logguard: cluster: rejected connection from {peer}: {e:#}"),
                }
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(())
}

/// Delivers one frame to `addr` (connect + write, 5 s timeouts).
pub fn send_frame(addr: &str, frame: &[u8]) -> Result<(), String> {
    let target = addr.to_socket_addrs().map_err(|e| format!("resolve: {e}"))?.next().ok_or_else(|| "no address".to_string())?;
    let mut s = TcpStream::connect_timeout(&target, Duration::from_secs(5)).map_err(|e| format!("connect: {e}"))?;
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    s.write_all(frame).map_err(|e| format!("send: {e}"))?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_reminder_after_rotate_after() {
        let day = 86_400 * SEC;
        let cfg = ClusterCfg { key_file: "/etc/logguard/cluster.key".into(), ..Default::default() };
        assert_eq!(cfg.rotation_reminder(Some(0), 179 * day), None, "not yet 180 days");
        let msg = cfg.rotation_reminder(Some(0), 200 * day).unwrap();
        assert!(msg.contains("200 days old (rotate after 180d)"), "{msg}");
        assert_eq!(cfg.rotation_reminder(None, 200 * day), None, "inline key: age unknown");
        let never = ClusterCfg { rotate_after: Dur(0), ..cfg.clone() };
        assert_eq!(never.rotation_reminder(Some(0), 1000 * day), None);
        // the key file's modification time
        let d = std::env::temp_dir().join(format!("lg-keyage-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("k"), "x").unwrap();
        let since = ClusterCfg { key_file: d.join("k"), ..Default::default() }.key_since().unwrap();
        assert!((time::now() - since).abs() < 60 * SEC);
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn cluster(name: &str, key: &str, peers: Vec<String>) -> Cluster {
        let cfg = ClusterCfg { enabled: true, node_id: name.into(), key: key.into(), peers, ..Default::default() };
        cfg.validate().unwrap();
        Cluster::new(&cfg).unwrap()
    }

    fn ban(net: &str, until_s: i64) -> FactBody {
        FactBody::Ban { net: net.parse().unwrap(), until: until_s * SEC, reason: "scan".into() }
    }

    #[test]
    fn key_rotation_without_a_gap() {
        let dir = std::env::temp_dir().join(format!("lg-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (old, new) = (generate_key(), generate_key());
        let node = |name: &str, main: &str, extra: &[(&str, &str)]| {
            let d = dir.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("cluster.key"), format!("{main}\n")).unwrap();
            for (ext, k) in extra {
                std::fs::write(d.join(format!("cluster.key.{ext}")), k).unwrap();
            }
            let cfg = ClusterCfg { enabled: true, node_id: name.into(), key_file: d.join("cluster.key"), ..Default::default() };
            Cluster::new(&cfg).unwrap()
        };
        let env = Envelope { v: 1, from: "x".into(), sent: 0, facts: vec![], file: None };
        let talks = |a: &Cluster, b: &Cluster| {
            let frame = seal(a.key(), &env).unwrap();
            open_any(&b.keys(), &frame[8..]).is_ok()
        };
        // before: both on the old key
        let (a0, b0) = (node("a0", &old, &[]), node("b0", &old, &[]));
        assert!(talks(&a0, &b0) && a0.view.extra_key_ids.is_empty());
        // start done on a only, then on both: the new key is accepted, still sent with the old
        let a1 = node("a1", &old, &[("next", &new)]);
        assert!(talks(&a1, &b0) && talks(&b0, &a1));
        let b1 = node("b1", &old, &[("next", &new)]);
        // switch done on a only: a sends with the new key, b (with .next) reads it, and back
        let a2 = node("a2", &new, &[("prev", &old)]);
        assert!(talks(&a2, &b1) && talks(&b1, &a2));
        assert_eq!(a2.view.key_id, key_id(&decode_key(&new).unwrap()));
        assert_eq!(a2.view.extra_key_ids, vec![key_id(&decode_key(&old).unwrap())]);
        // switch done on both, then finish on a only
        let b2 = node("b2", &new, &[("prev", &old)]);
        let a3 = node("a3", &new, &[]);
        assert!(talks(&a3, &b2) && talks(&b2, &a3) && talks(&a2, &b2));
        // a node left on the old key alone can't read the new one: why `start` goes first
        assert!(!talks(&a3, &b0));
        // a damaged rotation file is an error, not silently ignored
        let d = dir.join("bad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cluster.key"), &old).unwrap();
        std::fs::write(d.join("cluster.key.next"), "not a key").unwrap();
        let cfg = ClusterCfg { enabled: true, key_file: d.join("cluster.key"), ..Default::default() };
        assert!(Cluster::new(&cfg).is_err());
        // the same key in .prev and main isn't listed twice
        assert!(node("same", &new, &[("prev", &new)]).keys().len() == 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_open_and_tamper() {
        let key = decode_key(&generate_key()).unwrap();
        let env = Envelope { v: 1, from: "a".into(), sent: 5, facts: vec![], file: None };
        let frame = seal(&key, &env).unwrap();
        let body = read_frame(&mut frame.as_slice()).unwrap();
        assert_eq!(open(&key, &body).unwrap().from, "a");
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, &bad).unwrap_err().to_string().contains("authentication failed"));
        let other = decode_key(&generate_key()).unwrap();
        assert!(open(&other, &body).is_err(), "wrong key");
        assert!(read_frame(&mut &b"GET / HTTP/1.1\r\n"[..]).is_err());
    }

    #[test]
    fn peer_file_is_stored_once_checked() {
        use std::io::Read as _;
        use std::os::unix::fs::PermissionsExt;
        let key = decode_key(&generate_key()).unwrap();
        let now = time::now();
        let skew = Dur(300);
        let dir = std::env::temp_dir().join(format!("lg-inbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let report = br#"{"servers":[],"from":0,"to":1,"offenders":[]}"#.repeat(1000);
        let frame = file_frame(&key, "vpn", "abuse", &report, now).unwrap();
        assert!(frame.len() < report.len() / 4, "compressed: {} bytes", frame.len());
        let env = open(&key, &read_frame(&mut frame.as_slice()).unwrap()).unwrap();
        assert!(env.facts.is_empty());
        let path = store_file(&dir, &env, skew, now).unwrap();
        assert_eq!(path, dir.join("abuse-vpn.json.gz"));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let mut back = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap()).read_to_end(&mut back).unwrap();
        assert_eq!(back, report);
        // a newer one replaces it; no temporary file is left behind
        let env2 = open(&key, &read_frame(&mut file_frame(&key, "vpn", "abuse", b"{}", now).unwrap().as_slice()).unwrap()).unwrap();
        store_file(&dir, &env2, skew, now).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        assert!(file_frame(&key, "vpn", "passwd", b"x", now).is_err(), "only known names are sent");
        let refused = |e: &Envelope, dir: &Path| store_file(dir, e, skew, now).unwrap_err().to_string();
        assert!(refused(&env, Path::new("")).contains("refused"));
        let stale = Envelope { sent: now - 3600 * SEC, ..env.clone() };
        assert!(refused(&stale, &dir).contains("max_clock_skew"));
        for from in ["../etc", ".hidden", "a/b", ""] {
            assert!(refused(&Envelope { from: from.into(), ..env.clone() }, &dir).contains("node name"), "{from}");
        }
        let mut other = env.clone();
        other.file.as_mut().unwrap().name = "../../root/.ssh/authorized_keys".into();
        assert!(refused(&other, &dir).contains("unknown file name"));
        let mut plain = env.clone();
        plain.file.as_mut().unwrap().gz = base64::engine::general_purpose::STANDARD.encode(b"not gzip");
        assert!(refused(&plain, &dir).contains("not gzip"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nodes without the `file` field (older versions) still read such a message: as a
    /// heartbeat without facts.
    #[test]
    fn peer_file_is_ignored_by_older_nodes() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldEnvelope {
            v: u8,
            from: String,
            sent: Micros,
            facts: Vec<Fact>,
        }
        let key = decode_key(&generate_key()).unwrap();
        let frame = file_frame(&key, "vpn", "abuse", b"{}", 7).unwrap();
        let body = read_frame(&mut frame.as_slice()).unwrap();
        let plain =
            XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: AAD }).unwrap();
        let old: OldEnvelope = serde_json::from_slice(&plain).unwrap();
        assert!(old.facts.is_empty());
        let without: Envelope = serde_json::from_str(r#"{"v":1,"from":"a","sent":1,"facts":[]}"#).unwrap();
        assert!(without.file.is_none());
    }

    #[test]
    fn mesh_forwarding_dedup_and_hop_limit() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["b:1".into()]);
        let mut b = cluster("b", &k, vec!["c:1".into()]);
        let mut c = cluster("c", &k, vec!["a:1".into()]);
        a.originate(ban("1.2.3.4", now / SEC + 3600), now);

        let deliver = |from: &mut Cluster, to: &mut Cluster| -> Vec<Fact> {
            let frames = from.outgoing(now);
            let body = read_frame(&mut frames[0].1.as_slice()).unwrap();
            to.ingest(open(from.key(), &body).unwrap(), None, now)
        };
        let got_b = deliver(&mut a, &mut b);
        assert_eq!(got_b.len(), 1);
        assert_eq!(got_b[0].hops, 1);
        let got_c = deliver(&mut b, &mut c);
        assert_eq!(got_c.len(), 1, "b forwards a's fact to c");
        assert_eq!(got_c[0].hops, 2);
        assert!(deliver(&mut c, &mut a).is_empty(), "origin ignores its own fact coming back");
        // incremental: nothing new for b
        assert!(deliver(&mut a, &mut b).is_empty());
        let mut far = cluster("d", &k, vec![]);
        let mut env = Envelope { v: 1, from: "c".into(), sent: now, facts: got_c.clone(), file: None };
        env.facts[0].hops = 3;
        assert!(far.ingest(env, None, now).is_empty(), "hop limit");
    }

    #[test]
    fn limited_peers_hand_over_only_what_they_may() {
        let now = time::now();
        let key = generate_key();
        let mut tg = cluster("tg", &key, vec!["127.0.0.1:7946".into()]);
        let mut xmpp = cluster("xmpp", &key, vec!["127.0.0.2:7946".into(), "127.0.0.3:7946".into()]);
        xmpp.cfg.peer_accept.insert("127.0.0.3:7946".into(), vec![FactKind::Notices, FactKind::Files]);
        xmpp.cfg.validate().unwrap();
        xmpp.limits = PeerLimits::new(&xmpp.cfg);
        tg.originate(ban("10.9.9.9", now / SEC + 3600), now);
        tg.originate(FactBody::Trust { ip: "10.8.8.8".parse().unwrap() }, now);
        tg.originate(FactBody::Notice { subject: "s".into(), body: "b".into() }, now);
        let (_, frame) = tg.outgoing(now).remove(0);
        let env = || open(tg.key(), &frame[8..]).unwrap();
        // from the limited peer's address: only the notice
        let got = xmpp.ingest(env(), Some("127.0.0.3".parse().unwrap()), now);
        assert_eq!(got.iter().map(|f| f.body.kind()).collect::<Vec<_>>(), [FactKind::Notices]);
        assert_eq!(xmpp.view.refused_by_limit, 2);
        // the same message from another peer's address (or as IPv4-mapped IPv6) is judged by that
        let mut other = cluster("xmpp", &key, vec!["127.0.0.2:7946".into(), "127.0.0.3:7946".into()]);
        other.cfg.peer_accept = xmpp.cfg.peer_accept.clone();
        other.limits = PeerLimits::new(&other.cfg);
        assert_eq!(other.ingest(env(), Some("::ffff:127.0.0.3".parse().unwrap()), now).len(), 1);
        assert_eq!(other.ingest(env(), Some("127.0.0.2".parse().unwrap()), now).len(), 2, "the rest, unlimited");
        assert_eq!(other.limits.of(None), Some(vec![]), "no address: nothing");
        assert_eq!(other.limits.of(Some("127.0.0.2".parse().unwrap())), None);
        assert_eq!(PeerLimits::new(&ClusterCfg::default()).of(None), None, "no limits configured");
        // a node sharing only notices doesn't pass the others' bans on either
        let mut relay = cluster("tg", &key, vec!["127.0.0.1:7946".into()]);
        relay.cfg.share = vec![FactKind::Notices];
        let mut from_xmpp = cluster("xmpp", &key, vec!["127.0.0.1:7946".into()]);
        from_xmpp.originate(ban("10.7.7.7", now / SEC + 3600), now);
        from_xmpp.originate(FactBody::Notice { subject: "s".into(), body: "b".into() }, now);
        let (_, f) = from_xmpp.outgoing(now).remove(0);
        assert_eq!(relay.ingest(open(from_xmpp.key(), &f[8..]).unwrap(), None, now).len(), 2, "it takes both");
        let (_, f) = relay.outgoing(now + SEC).remove(0);
        let passed: Vec<FactKind> = open(relay.key(), &f[8..]).unwrap().facts.iter().map(|f| f.body.kind()).collect();
        assert_eq!(passed, [FactKind::Notices]);
        // the limit goes by address: it needs the listener to admit only peers
        let mut bad = xmpp.cfg.clone();
        bad.allow_only_peers = false;
        assert!(bad.validate().is_err());
        bad = xmpp.cfg.clone();
        bad.peer_accept.insert("127.0.0.9:7946".into(), vec![]);
        assert!(bad.validate().is_err(), "not a peer");
    }

    #[test]
    fn rejects_stale_and_unaccepted() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec![]);
        let fact = |body| Fact { origin: "x".into(), seq: 1, created: now, hops: 0, body };
        let stale =
            Envelope { v: 1, from: "x".into(), sent: now - 3600 * SEC, facts: vec![fact(ban("9.9.9.9", now / SEC + 60))], file: None };
        assert!(a.ingest(stale, None, now).is_empty());
        assert_eq!(a.view.rejected, 1);
        a.cfg.accept = vec![FactKind::Bans];
        let env = Envelope {
            v: 1,
            from: "x".into(),
            sent: now,
            facts: vec![fact(FactBody::Trust { ip: "9.9.9.9".parse().unwrap() })],
            file: None,
        };
        assert!(a.ingest(env, None, now).is_empty(), "trust not accepted");
        let expired =
            Envelope { v: 1, from: "x".into(), sent: now, facts: vec![Fact { seq: 2, ..fact(ban("9.9.9.9", now / SEC - 1)) }], file: None };
        assert!(a.ingest(expired, None, now).is_empty());
    }

    #[test]
    fn over_real_tcp() {
        let k = generate_key();
        let key = decode_key(&k).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        serve(&addr, vec![key], PeerFilter::peers(vec!["127.0.0.1".parse().unwrap()]), move |env, _| tx.send(env).is_ok()).unwrap();
        let now = time::now();
        let mut a = cluster("a", &k, vec![addr.clone()]);
        a.originate(FactBody::Report { ip: "5.6.7.8".parse().unwrap(), points: 40.0, signals: "3x fw_tripwire".into() }, now);
        let frames = a.outgoing(now);
        send_frame(&addr, &frames[0].1).unwrap();
        let env = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(env.from, "a");
        assert!(matches!(env.facts[0].body, FactBody::Report { points, .. } if points == 40.0));
        assert!(send_frame("127.0.0.1:1", b"x").is_err());
        assert!(a.delivered(0, Err("connect: refused".into()), now).is_none());
        assert!(a.delivered(0, Err("connect: refused".into()), now + 6 * time::MIN).unwrap().contains("unreachable"));
    }

    #[test]
    fn listener_refuses_strangers_and_lazy_reads() {
        let k = generate_key();
        let key = decode_key(&k).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let filter = PeerFilter::peers(vec!["192.0.2.1".parse().unwrap()]);
        serve(&addr, vec![key], filter.clone(), move |env, _| tx.send(env).is_ok()).unwrap();
        let mut a = cluster("a", &k, vec![addr.clone()]);
        a.originate(FactBody::Trust { ip: "5.6.7.8".parse().unwrap() }, time::now());
        let frames = a.outgoing(time::now());
        let _ = send_frame(&addr, &frames[0].1);
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "localhost is not a configured peer");
        // no peer resolved: nobody gets in (not everybody)
        filter.set(vec![]);
        let _ = send_frame(&addr, &frames[0].1);
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "an empty peer list refuses everyone");
        // re-resolved to this address: accepted
        filter.set(vec!["127.0.0.1".parse().unwrap()]);
        send_frame(&addr, &frames[0].1).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());

        // a header claiming 1 MB but delivering 3 bytes is rejected without allocating 1 MB
        let mut frame = b"LGC1".to_vec();
        frame.extend_from_slice(&(MAX_FRAME as u32).to_be_bytes());
        frame.extend_from_slice(b"abc");
        let err = read_frame(&mut frame.as_slice()).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn full_sync_is_split_into_frames() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["b:1".into(), "c:1".into()]);
        let mut b = cluster("b", &k, vec![]);
        for i in 0..20_000u32 {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            a.originate(FactBody::Ban { net: Net::host(ip.into()), until: now + 3600 * SEC, reason: "x".repeat(60) }, now);
        }
        let frames = a.outgoing(now);
        let to_b: Vec<&Vec<u8>> = frames.iter().filter(|(i, _)| *i == 0).map(|(_, f)| f).collect();
        assert!(to_b.len() > 1, "split: {} frame(s)", to_b.len());
        assert_eq!(frames.iter().filter(|(i, _)| *i == 1).count(), to_b.len(), "every peer gets every chunk");
        let mut got = 0;
        for f in to_b {
            assert!(f.len() <= 8 + MAX_FRAME);
            let body = read_frame(&mut f.as_slice()).unwrap();
            got += b.ingest(open(a.key(), &body).unwrap(), None, now).len();
        }
        assert_eq!(got, 20_000);
    }

    #[test]
    fn config_validation() {
        let ok = ClusterCfg { enabled: true, key: generate_key(), peers: vec!["vpn.example.org:7946".into()], ..Default::default() };
        assert!(ok.validate().is_ok());
        assert!(ClusterCfg { key: String::new(), ..ok.clone() }.validate().is_err());
        assert!(ClusterCfg { key: "c2hvcnQ=".into(), ..ok.clone() }.validate().is_err(), "short key");
        assert!(ClusterCfg { peers: vec!["nohost".into()], ..ok.clone() }.validate().is_err());
        assert!(ClusterCfg { listen: "7946".into(), ..ok }.validate().is_err());
    }
}
