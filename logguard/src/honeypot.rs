//! Tripwire listeners (`[ports] honeypot`): logguard accepts TCP connections on ports nobody
//! legitimate uses and closes each at once, without reading a byte. A connection is only
//! accepted after the TCP handshake, which a forged source address can't complete (the
//! server's SYN-ACK goes to the real owner of the address), so unlike a blocked SYN in the
//! firewall log, a hit here names its sender for certain.

use std::collections::HashMap;
use std::net::{IpAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// One completed handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub ip: IpAddr,
    pub port: u16,
}

/// A source is reported once a minute per port, however often it connects.
const REPEAT_AFTER: Duration = Duration::from_secs(60);
/// Sources remembered per port for that (real addresses only, but a botnet has many).
const MAX_SOURCES: usize = 10_000;

/// Binds `port` on every address: IPv6 with IPv4 mapped where the system allows, else IPv4,
/// and IPv4 as well where IPv6 sockets don't take it (`net.ipv6.bindv6only = 1`).
fn bind(port: u16) -> std::io::Result<Vec<TcpListener>> {
    let mut out = Vec::new();
    let v6 = TcpListener::bind(("::", port));
    if let Ok(l) = v6 {
        out.push(l);
    }
    match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => out.push(l),
        // taken by the dual-stack IPv6 socket above: fine
        Err(e) if out.is_empty() => return Err(e),
        Err(_) => {}
    }
    Ok(out)
}

fn serve(listener: TcpListener, port: u16, on_hit: Arc<dyn Fn(Hit) -> bool + Send + Sync>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut seen: HashMap<IpAddr, Instant> = HashMap::new();
        for stream in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(s) = stream else {
                // e.g. out of file descriptors: don't spin
                thread::sleep(Duration::from_millis(100));
                continue;
            };
            let peer = s.peer_addr().ok().map(|a| crate::net::normalize(a.ip()));
            drop(s); // closed before anything else: nothing is read, nothing is sent
            let Some(ip) = peer else { continue };
            let now = Instant::now();
            if seen.get(&ip).is_some_and(|t| now.duration_since(*t) < REPEAT_AFTER) {
                continue;
            }
            if seen.len() >= MAX_SOURCES {
                seen.retain(|_, t| now.duration_since(*t) < REPEAT_AFTER);
            }
            if seen.len() < MAX_SOURCES {
                seen.insert(ip, now);
            }
            if !on_hit(Hit { ip, port }) {
                return;
            }
        }
    });
}

/// Starts a listener for each port; `on_hit` is called from their threads (false stops it).
/// Returns the ports that could not be opened, with why.
pub fn start(ports: &[u16], on_hit: impl Fn(Hit) -> bool + Send + Sync + 'static, stop: Arc<AtomicBool>) -> Vec<String> {
    let on_hit: Arc<dyn Fn(Hit) -> bool + Send + Sync> = Arc::new(on_hit);
    let mut errors = Vec::new();
    for &port in ports {
        match bind(port) {
            Ok(listeners) => {
                for l in listeners {
                    serve(l, port, Arc::clone(&on_hit), Arc::clone(&stop));
                }
            }
            Err(e) => errors.push(format!("honeypot port {port}/tcp: cannot listen: {e}")),
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs to bind 127.0.0.1 (run outside a sandbox that forbids it).
    #[test]
    fn a_connection_is_a_hit_once_a_minute() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        for _ in 0..3 {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            // closed by the other side without a word
            let mut buf = [0u8; 8];
            assert_eq!(std::io::Read::read(&mut s, &mut buf).unwrap_or(0), 0);
        }
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit, Hit { ip: "127.0.0.1".parse().unwrap(), port });
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "repeats within a minute are one hit");
        let taken = start(&[port], |_| true, Arc::new(AtomicBool::new(false)));
        assert!(taken[0].contains("cannot listen"), "{taken:?}");
    }
}
