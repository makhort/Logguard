//! How a console asks another node's agent for its data, over TCP.
//!
//! **Keys**: every node holds the *web key* (32 random bytes, `logguard-web keygen`), never
//! logguard's cluster key. The cluster key makes bans, unbans and trust on every node; a web
//! console holding it could forge them if it were ever broken into. The web key only reads.
//!
//! **Request** (console → agent): `"LGW1"` | u32 big-endian length | 24-byte nonce |
//! XChaCha20-Poly1305 under the web key (associated data [`REQUEST_AAD`]) of a JSON
//! [`Request`]: what it wants, when it was sent, a random id and a fresh X25519 public key.
//! Nothing in it is secret; the key proves the console holds the web key.
//!
//! **Reply** (agent → console, same connection): `"LGW1"` | u32 length | the agent's fresh
//! X25519 public key (32 bytes) | 24-byte nonce | XChaCha20-Poly1305 of the gzip-compressed
//! JSON [`Reply`] under HKDF-SHA-256(salt = web key, ikm = X25519 of the two fresh keys,
//! info = [`REPLY_INFO`] | request id | both public keys). Only a holder of the web key can
//! derive it (so the console knows the reply is an agent's, made for this very request), and
//! once both sides dropped their fresh secrets nobody can, not even with the web key: a
//! recording of the traffic stays unreadable if the web key leaks later (forward secrecy).
//!
//! One request and one reply per connection.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::time::{self, Micros, SEC};

const MAGIC: &[u8; 4] = b"LGW1";
pub const REQUEST_AAD: &[u8] = b"logguard-web-request-v1";
pub const REPLY_INFO: &[u8] = b"logguard-web-reply-v1";
/// A request is a few hundred bytes.
pub const MAX_REQUEST: usize = 4096;
/// A reply holds one node's snapshot, compressed (the snapshot's long lists are capped
/// before, see `snapshot::trim`).
pub const MAX_REPLY: usize = 16 << 20;
/// And uncompressed.
pub const MAX_REPLY_PLAIN: usize = 64 << 20;
/// Requests and replies older or newer than this are refused.
pub const MAX_SKEW: Micros = 300 * SEC;

/// What a console may ask an agent for: all only read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Want {
    /// logguard's snapshot (what its dashboard shows), with long lists capped.
    Snapshot,
    /// Today's digest so far (text).
    Digest,
    /// The abuse report of the last 24 hours (JSON, logguard's `abuse 24h`).
    #[serde(rename = "abuse_24h")]
    Abuse24h,
    /// And of the last 7 days.
    #[serde(rename = "abuse_7d")]
    Abuse7d,
}

impl Want {
    /// Everything an agent of this version answers, as [`Reply::can`] lists it. Older agents
    /// list nothing: they are asked for snapshots and digests only (an agent refuses a
    /// request it can't read, and logguard bans who sends too many of those).
    pub const ALL: [Want; 4] = [Want::Snapshot, Want::Digest, Want::Abuse24h, Want::Abuse7d];

    /// The abuse report of a window as the API names it ("24h", "7d").
    pub fn abuse(window: &str) -> Option<Want> {
        match window {
            "24h" => Some(Want::Abuse24h),
            "7d" => Some(Want::Abuse7d),
            _ => None,
        }
    }

    /// The window of an abuse report.
    pub fn window(self) -> Option<&'static str> {
        match self {
            Want::Abuse24h => Some("24h"),
            Want::Abuse7d => Some("7d"),
            _ => None,
        }
    }

    /// As [`Reply::can`] and the request name it.
    pub fn name(self) -> &'static str {
        match self {
            Want::Snapshot => "snapshot",
            Want::Digest => "digest",
            Want::Abuse24h => "abuse_24h",
            Want::Abuse7d => "abuse_7d",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u8,
    pub sent: Micros,
    /// 16 random bytes in hex: binds the reply to this request.
    pub id: String,
    /// The console's fresh X25519 public key (base64).
    pub epk: String,
    pub want: Want,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reply {
    pub v: u8,
    /// The agent's node name.
    pub node: String,
    pub sent: Micros,
    /// The agent's logguard-web version.
    pub version: String,
    /// Why there is no data (logguard not running, no console socket).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Box<RawValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// An abuse report (logguard's JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse: Option<Box<RawValue>>,
    /// What this agent answers ([`Want::name`]); empty from agents before abuse reports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub can: Vec<String>,
}

/// A web key as `keygen` writes it (base64 of 32 bytes).
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).context("the web key is not valid base64")?;
    raw.try_into().map_err(|_| anyhow!("the web key must be exactly 32 bytes (make one with `logguard-web keygen`)"))
}

pub fn generate_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(XChaCha20Poly1305::generate_key(&mut OsRng))
}

/// A key's public fingerprint (SHA-256, first 6 bytes in hex): the same on every node with the
/// same key, revealing nothing about it. Compare it with `logguard-web key-id` on each node.
pub fn key_id(key: &[u8; 32]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(key)[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Reads one frame's body, at most `max` bytes; memory grows with the bytes received, not with
/// the length a peer claims.
pub fn read_frame(r: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 8];
    r.read_exact(&mut head).context("reading the frame header")?;
    if &head[..4] != MAGIC {
        bail!("not a logguard-web connection");
    }
    let len = u32::from_be_bytes(head[4..].try_into().expect("4 bytes")) as usize;
    if len > max {
        bail!("frame too large ({len} bytes, at most {max})");
    }
    let mut body = Vec::with_capacity(len.min(64 * 1024));
    r.take(len as u64).read_to_end(&mut body)?;
    if body.len() != len {
        bail!("truncated frame ({} of {len} bytes)", body.len());
    }
    Ok(body)
}

/// A console's side of one exchange: its fresh secret, until the reply comes.
pub struct Pending {
    secret: EphemeralSecret,
    epk: [u8; 32],
    id: String,
}

/// Builds a request frame for `want`.
pub fn request(key: &[u8; 32], want: Want, now: Micros) -> Result<(Vec<u8>, Pending)> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&secret).to_bytes();
    let mut id = [0u8; 16];
    getrandom(&mut id)?;
    let id = hex(&id);
    let req = Request { v: 1, sent: now, id: id.clone(), epk: base64::engine::general_purpose::STANDARD.encode(epk), want };
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct =
        cipher.encrypt(&nonce, Payload { msg: &serde_json::to_vec(&req)?, aad: REQUEST_AAD }).map_err(|_| anyhow!("encryption failed"))?;
    let mut body = nonce.to_vec();
    body.extend_from_slice(&ct);
    Ok((frame(&body), Pending { secret, epk, id }))
}

/// An agent's view of a request: checked, with what it needs to answer.
#[derive(Debug)]
pub struct Asked {
    pub req: Request,
    epk: [u8; 32],
}

/// Opens a request frame's body (see [`read_frame`]) and checks it is fresh.
pub fn open_request(key: &[u8; 32], body: &[u8], now: Micros) -> Result<Asked> {
    if body.len() < 24 + 16 {
        bail!("request too short");
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: REQUEST_AAD })
        .map_err(|_| anyhow!("authentication failed (another web key, or not a console)"))?;
    let req: Request = serde_json::from_slice(&plain).context("decoding the request")?;
    if req.v != 1 {
        bail!("unsupported request version {}", req.v);
    }
    if req.sent.abs_diff(now) > MAX_SKEW.unsigned_abs() {
        bail!("request sent at {}: clocks more than 5 minutes apart, or a replay", time::fmt_ts(req.sent));
    }
    if req.id.len() != 32 || !req.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("bad request id");
    }
    let epk: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&req.epk)
        .ok()
        .and_then(|k| k.try_into().ok())
        .context("bad public key in the request")?;
    Ok(Asked { req, epk })
}

fn reply_key(key: &[u8; 32], shared: &[u8; 32], id: &str, console_pk: &[u8; 32], agent_pk: &[u8; 32]) -> [u8; 32] {
    let mut info = REPLY_INFO.to_vec();
    info.extend_from_slice(id.as_bytes());
    info.extend_from_slice(console_pk);
    info.extend_from_slice(agent_pk);
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(key), shared).expand(&info, &mut out).expect("32 bytes is a valid length");
    out
}

/// Seals the reply to `asked` (the reply's JSON, compressed).
pub fn seal_reply(key: &[u8; 32], asked: &Asked, reply: &Reply) -> Result<Vec<u8>> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let agent_pk = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(asked.epk));
    if !shared.was_contributory() {
        bail!("the console's public key is a low-order point");
    }
    let k = reply_key(key, shared.as_bytes(), &asked.req.id, &asked.epk, &agent_pk);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    serde_json::to_writer(&mut gz, reply)?;
    let plain = gz.finish()?;
    let cipher = XChaCha20Poly1305::new((&k).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, Payload { msg: &plain, aad: REPLY_INFO }).map_err(|_| anyhow!("encryption failed"))?;
    if 32 + 24 + ct.len() > MAX_REPLY {
        bail!("reply too large ({} bytes compressed)", ct.len());
    }
    let mut body = agent_pk.to_vec();
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    Ok(frame(&body))
}

/// Opens the agent's reply to `pending` (a frame body) and checks it is fresh.
pub fn open_reply(key: &[u8; 32], pending: Pending, body: &[u8], now: Micros) -> Result<Reply> {
    if body.len() < 32 + 24 + 16 {
        bail!("reply too short");
    }
    let agent_pk: [u8; 32] = body[..32].try_into().expect("32 bytes");
    let shared = pending.secret.diffie_hellman(&PublicKey::from(agent_pk));
    if !shared.was_contributory() {
        bail!("the agent's public key is a low-order point");
    }
    let k = reply_key(key, shared.as_bytes(), &pending.id, &pending.epk, &agent_pk);
    let cipher = XChaCha20Poly1305::new((&k).into());
    let gz = cipher
        .decrypt(XNonce::from_slice(&body[32..56]), Payload { msg: &body[56..], aad: REPLY_INFO })
        .map_err(|_| anyhow!("authentication failed (another web key, or not this request's reply)"))?;
    let mut plain = Vec::new();
    flate2::read::GzDecoder::new(gz.as_slice()).take(MAX_REPLY_PLAIN as u64 + 1).read_to_end(&mut plain).context("decompressing")?;
    if plain.len() > MAX_REPLY_PLAIN {
        bail!("reply larger than {} MB uncompressed", MAX_REPLY_PLAIN >> 20);
    }
    let reply: Reply = serde_json::from_slice(&plain).context("decoding the reply")?;
    if reply.v != 1 {
        bail!("unsupported reply version {}", reply.v);
    }
    if reply.sent.abs_diff(now) > MAX_SKEW.unsigned_abs() {
        bail!("reply sent at {}: clocks more than 5 minutes apart", time::fmt_ts(reply.sent));
    }
    Ok(reply)
}

/// Sends `frame` on `s` and reads the reply frame's body.
pub fn exchange<S: Read + Write>(s: &mut S, frame: &[u8], max: usize) -> Result<Vec<u8>> {
    s.write_all(frame).context("sending")?;
    s.flush()?;
    read_frame(s, max)
}

pub fn getrandom(buf: &mut [u8]) -> Result<()> {
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.try_fill_bytes(buf).map_err(|e| anyhow!("no randomness from the system: {e}"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(node: &str, now: Micros) -> Reply {
        Reply {
            v: 1,
            node: node.into(),
            sent: now,
            version: "test".into(),
            error: None,
            snapshot: Some(RawValue::from_string(r#"{"mode":"enforce"}"#.into()).unwrap()),
            digest: None,
            abuse: None,
            can: vec![],
        }
    }

    #[test]
    fn round_trip() {
        let key = decode_key(&generate_key()).unwrap();
        let now = time::now();
        let (req, pending) = request(&key, Want::Snapshot, now).unwrap();
        let body = read_frame(&mut req.as_slice(), MAX_REQUEST).unwrap();
        let asked = open_request(&key, &body, now).unwrap();
        assert_eq!(asked.req.want, Want::Snapshot);
        let rep = seal_reply(&key, &asked, &reply("vpn", now)).unwrap();
        let body = read_frame(&mut rep.as_slice(), MAX_REPLY).unwrap();
        let got = open_reply(&key, pending, &body, now).unwrap();
        assert_eq!(got.node, "vpn");
        assert_eq!(got.snapshot.unwrap().get(), r#"{"mode":"enforce"}"#);
    }

    #[test]
    fn refused() {
        let key = decode_key(&generate_key()).unwrap();
        let other = decode_key(&generate_key()).unwrap();
        let now = time::now();
        let (req, _) = request(&key, Want::Digest, now).unwrap();
        let body = read_frame(&mut req.as_slice(), MAX_REQUEST).unwrap();
        assert!(open_request(&other, &body, now).is_err(), "another web key");
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open_request(&key, &bad, now).is_err(), "tampered");
        assert!(open_request(&key, &body, now + 301 * SEC).unwrap_err().to_string().contains("replay"), "old");

        // a reply can't be read with the web key alone (forward secrecy), nor by another request
        let asked = open_request(&key, &body, now).unwrap();
        let rep = seal_reply(&key, &asked, &reply("x", now)).unwrap();
        let rep_body = read_frame(&mut rep.as_slice(), MAX_REPLY).unwrap();
        let (_, other_pending) = request(&key, Want::Digest, now).unwrap();
        assert!(open_reply(&key, other_pending, &rep_body, now).is_err(), "another request's reply");
        // a request reflected back as a reply
        let (_, pending) = request(&key, Want::Digest, now).unwrap();
        assert!(open_reply(&key, pending, &body, now).is_err());
        // a stale reply
        let (req2, pending2) = request(&key, Want::Digest, now).unwrap();
        let asked2 = open_request(&key, &read_frame(&mut req2.as_slice(), MAX_REQUEST).unwrap(), now).unwrap();
        let old = seal_reply(&key, &asked2, &reply("x", now - 400 * SEC)).unwrap();
        let old = read_frame(&mut old.as_slice(), MAX_REPLY).unwrap();
        assert!(open_reply(&key, pending2, &old, now).is_err());

        assert!(read_frame(&mut &b"GET / HTTP/1.1\r\n"[..], MAX_REQUEST).is_err());
        let mut big = MAGIC.to_vec();
        big.extend_from_slice(&(MAX_REQUEST as u32 + 1).to_be_bytes());
        assert!(read_frame(&mut big.as_slice(), MAX_REQUEST).unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn low_order_key_refused() {
        let key = decode_key(&generate_key()).unwrap();
        let now = time::now();
        let req = Request {
            v: 1,
            sent: now,
            id: "0".repeat(32),
            epk: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            want: Want::Snapshot,
        };
        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut body = nonce.to_vec();
        body.extend(cipher.encrypt(&nonce, Payload { msg: &serde_json::to_vec(&req).unwrap(), aad: REQUEST_AAD }).unwrap());
        let asked = open_request(&key, &body, now).unwrap();
        assert!(seal_reply(&key, &asked, &reply("x", now)).unwrap_err().to_string().contains("low-order"));
    }

    #[test]
    fn keys() {
        assert!(decode_key("not base64!").is_err());
        assert!(decode_key(&base64::engine::general_purpose::STANDARD.encode([1u8; 31])).is_err());
        let k = decode_key(&generate_key()).unwrap();
        assert_eq!(key_id(&k).len(), 12);
        assert_eq!(key_id(&k), key_id(&k));
    }
}
