//! Entry points for the fuzz targets in `fuzz/` (and `tests/fuzz_smoke.rs`, which runs them
//! over their seeds on stable Rust): the parsers that see what a stranger sends.

use std::sync::OnceLock;

/// An HTTP request as a client sends it, before any login.
pub fn http_request(data: &[u8]) {
    let mut r = std::io::BufReader::new(data);
    for _ in 0..4 {
        if crate::http::read_request(&mut r).is_err() {
            break;
        }
    }
}

fn key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| [7u8; 32])
}

/// A request frame as it reaches an agent, from anyone who may connect.
pub fn agent_request(data: &[u8]) {
    if let Ok(body) = crate::wire::read_frame(&mut &data[..], crate::wire::MAX_REQUEST) {
        let _ = crate::wire::open_request(key(), &body, crate::time::now());
    }
    let _ = crate::wire::open_request(key(), data, crate::time::now());
}

/// A snapshot as an agent (any holder of the web key) or logguard sends it.
pub fn snapshot(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(s) = crate::snapshot::trim(text) {
            let node =
                crate::fleet::Node { id: "1".into(), name: "x".into(), snapshot: Some(std::sync::Arc::new(s)), ..Default::default() };
            let nodes = [node];
            let _ = crate::aggregate::cluster(&nodes, crate::time::now(), 10);
            let _ = crate::metrics::render(&nodes, crate::time::now(), None);
        }
    }
}

/// An abuse report as an agent (any holder of the web key) or logguard sends it: read, merged
/// with itself (two nodes saw the same) and split per provider.
pub fn abuse_report(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(p) = crate::abuse::parse(text, "x") {
            let parts = vec![("0".into(), "a".into(), Ok(p.clone())), ("1".into(), "b".into(), Ok(p))];
            let _ = serde_json::to_string(&crate::abuse::merge("7d", parts, crate::time::now()));
        }
    }
}
