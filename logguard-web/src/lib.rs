//! logguard-web as a library: the binary (`main.rs`) only reads the settings; the tests in
//! `tests/` run an agent and a console against a fake logguard, and the fuzz targets in
//! `fuzz/` reach the parsers through [`fuzzing`].

pub mod abuse;
pub mod agent;
pub mod aggregate;
pub mod auth;
pub mod console;
pub mod envfile;
pub mod fleet;
pub mod fuzzing;
pub mod http;
pub mod local;
pub mod log;
pub mod metrics;
pub mod netlist;
pub mod rdap;
pub mod snapshot;
pub mod time;
pub mod tls;
pub mod totp;
pub mod wire;

/// This machine's host name.
pub fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| node_name_ok(s))
        .unwrap_or_else(|| "logguard".into())
}

/// A node name as the console shows it: 1-64 letters, digits, dots, dashes, underscores.
pub fn node_name_ok(n: &str) -> bool {
    (1..=64).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
