//! JSON-RPC 2.0 with signal-cli, one JSON object per line (`signal-cli jsonRpc` on its stdin
//! and stdout; `man signal-cli-jsonrpc`). Requests carry ids; replies are matched to them.
//! What signal-cli sends on its own (`receive` notifications: messages people send the bot)
//! is counted and dropped: the bot reads nothing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

/// A line longer than this from signal-cli is not one of its replies: the connection is
/// dropped. (A reply is a few KB; an incoming message with a large text more.)
pub const MAX_LINE: usize = 4 << 20;

/// Why a call failed.
#[derive(Debug, Clone, PartialEq)]
pub enum RpcError {
    /// signal-cli answered with an error (`data` may hold the per-recipient results).
    Remote { code: i64, message: String, data: Value },
    /// No answer in time.
    Timeout,
    /// signal-cli is gone (exited, or closed its output).
    Closed,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RpcError::Remote { code, message, .. } => write!(f, "signal-cli error {code}: {message}"),
            RpcError::Timeout => f.write_str("signal-cli didn't answer in time"),
            RpcError::Closed => f.write_str("signal-cli has stopped"),
        }
    }
}

impl std::error::Error for RpcError {}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, RpcError>>>>>;

pub struct Rpc {
    writer: tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>,
    pending: Pending,
    next: AtomicU64,
    /// Notifications from signal-cli (messages to the bot) since the start.
    incoming: Arc<AtomicU64>,
    /// Set once the reading side has ended.
    closed: Arc<std::sync::atomic::AtomicBool>,
}

/// What one line from signal-cli is.
#[derive(Debug, PartialEq)]
pub enum Line {
    /// The reply to request `id`.
    Reply(u64, Result<Value, RpcError>),
    /// Something signal-cli sends on its own (`receive`, ...).
    Notification(String),
    /// Not JSON-RPC.
    Other,
}

/// Reads one line of signal-cli's output.
pub fn parse_line(line: &str) -> Line {
    let Ok(v) = serde_json::from_str::<Value>(line) else { return Line::Other };
    if let Some(id) = v.get("id").and_then(Value::as_u64) {
        if let Some(e) = v.get("error") {
            let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message: String = e.get("message").and_then(Value::as_str).unwrap_or_default().chars().take(500).collect();
            return Line::Reply(id, Err(RpcError::Remote { code, message, data: e.get("data").cloned().unwrap_or(Value::Null) }));
        }
        return Line::Reply(id, Ok(v.get("result").cloned().unwrap_or(Value::Null)));
    }
    match v.get("method").and_then(Value::as_str) {
        Some(m) => Line::Notification(m.chars().take(40).collect()),
        None => Line::Other,
    }
}

impl Rpc {
    /// Talks to signal-cli over `reader` (its stdout) and `writer` (its stdin); spawns the task
    /// that reads its replies.
    pub fn new<R, W>(reader: R, writer: W) -> Rpc
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let pending: Pending = Arc::default();
        let incoming = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (p, inc, cl) = (pending.clone(), incoming.clone(), closed.clone());
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match (&mut lines).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if buf.len() > MAX_LINE => {
                        log::error!("signal-cli wrote a line longer than {} MB; dropping the connection", MAX_LINE >> 20);
                        break;
                    }
                    Ok(_) => {}
                }
                match parse_line(&String::from_utf8_lossy(&buf)) {
                    Line::Reply(id, r) => {
                        if let Some(tx) = p.lock().ok().and_then(|mut m| m.remove(&id)) {
                            let _ = tx.send(r);
                        }
                    }
                    Line::Notification(_) => {
                        inc.fetch_add(1, Ordering::Relaxed);
                    }
                    Line::Other => {}
                }
            }
            cl.store(true, Ordering::SeqCst);
            // every call still waiting learns that signal-cli is gone
            if let Ok(mut m) = p.lock() {
                for (_, tx) in m.drain() {
                    let _ = tx.send(Err(RpcError::Closed));
                }
            }
        });
        Rpc { writer: tokio::sync::Mutex::new(Box::new(writer)), pending, next: AtomicU64::new(1), incoming, closed }
    }

    /// Calls `method`; waits at most `timeout` for the reply.
    pub async fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        if self.is_closed() {
            return Err(RpcError::Closed);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut m) = self.pending.lock() {
            m.insert(id, tx);
        }
        let mut line = json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": id }).to_string();
        line.push('\n');
        let written = {
            let mut w = self.writer.lock().await;
            match w.write_all(line.as_bytes()).await {
                Ok(()) => w.flush().await,
                Err(e) => Err(e),
            }
        };
        if written.is_err() {
            self.forget(id);
            return Err(RpcError::Closed);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(RpcError::Closed),
            Err(_) => {
                self.forget(id);
                Err(RpcError::Timeout)
            }
        }
    }

    fn forget(&self, id: u64) {
        if let Ok(mut m) = self.pending.lock() {
            m.remove(&id);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Messages people sent the bot since the start (ignored).
    pub fn incoming(&self) -> u64 {
        self.incoming.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        assert_eq!(
            parse_line(r#"{"jsonrpc":"2.0","result":{"version":"0.13.4"},"id":3}"#),
            Line::Reply(3, Ok(json!({"version":"0.13.4"})))
        );
        let Line::Reply(4, Err(RpcError::Remote { code, message, data })) = parse_line(
            r#"{"jsonrpc":"2.0","error":{"code":-1,"message":"Failed to send message","data":{"response":{"results":[]}}},"id":4}"#,
        ) else {
            panic!()
        };
        assert_eq!((code, message.as_str()), (-1, "Failed to send message"));
        assert!(data["response"]["results"].is_array());
        assert_eq!(parse_line(r#"{"jsonrpc":"2.0","method":"receive","params":{"envelope":{}}}"#), Line::Notification("receive".into()));
        assert_eq!(parse_line("INFO something"), Line::Other);
        assert_eq!(parse_line(r#"{"jsonrpc":"2.0","result":1,"id":"x"}"#), Line::Other, "ids are ours: numbers");
    }

    #[tokio::test]
    async fn calls_are_matched_to_replies() {
        let (bot_side, cli_side) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(bot_side);
        let rpc = Rpc::new(r, w);
        let (cr, mut cw) = tokio::io::split(cli_side);
        let fake = tokio::spawn(async move {
            let mut lines = BufReader::new(cr).lines();
            let a: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            let b: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            // a notification in between, then the replies in reverse order
            cw.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"receive\",\"params\":{}}\n").await.unwrap();
            for v in [&b, &a] {
                let reply = json!({ "jsonrpc": "2.0", "result": { "echo": v["method"] }, "id": v["id"] });
                cw.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            }
            lines.next_line().await.unwrap(); // the call that times out
            drop(cw);
        });
        let t = Duration::from_secs(5);
        let (x, y) = tokio::join!(rpc.call("version", json!({}), t), rpc.call("listIdentities", json!({}), t));
        assert_eq!(x.unwrap()["echo"], "version");
        assert_eq!(y.unwrap()["echo"], "listIdentities");
        assert_eq!(rpc.incoming(), 1);
        assert_eq!(rpc.call("send", json!({}), Duration::from_secs(5)).await, Err(RpcError::Closed), "signal-cli went away");
        fake.await.unwrap();
        assert!(rpc.is_closed());
        assert_eq!(rpc.call("send", json!({}), t).await, Err(RpcError::Closed));
    }
}
