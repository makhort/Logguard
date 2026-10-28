//! The fuzz targets (`fuzz/`, nightly) on stable: their seed files plus a few thousand
//! mutations of them, so `cargo test` catches a panic (an overflow, an index out of range)
//! without libFuzzer. The real search runs with `cargo +nightly fuzz run …`.

use std::path::PathBuf;

use logguard_web::fuzzing;

fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds").join(target);
    let mut out: Vec<Vec<u8>> = std::fs::read_dir(&dir).unwrap().map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect();
    assert!(!out.is_empty(), "no seeds in {}", dir.display());
    out.sort();
    out
}

/// Deterministic mutations: bytes flipped, set to edge values, cut, repeated.
fn mutations(seed: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ seed.len() as u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut m = seed.to_vec();
        if m.is_empty() {
            m.push(0);
        }
        match next() % 5 {
            0 => {
                let i = next() as usize % m.len();
                m[i] ^= 1 << (next() % 8);
            }
            1 => {
                let i = next() as usize % m.len();
                m[i] = [0u8, 0xff, b'"', b'-', b'9', b'\n', b'['][next() as usize % 7];
            }
            2 => m.truncate(next() as usize % m.len()),
            3 => {
                let i = next() as usize % m.len();
                let piece = m[i..].to_vec();
                m.extend_from_slice(&piece);
            }
            _ => {
                let i = next() as usize % m.len();
                m.insert(i, b"0123456789-e.,:{}[]\" "[next() as usize % 21]);
            }
        }
        out.push(m);
    }
    out
}

fn run(target: &str, f: fn(&[u8]), per_seed: usize) {
    for seed in seeds(target) {
        f(&seed);
        for m in mutations(&seed, per_seed) {
            f(&m);
        }
    }
}

#[test]
fn http_request() {
    run("http_request", fuzzing::http_request, 3000);
}

#[test]
fn agent_request() {
    run("agent_request", fuzzing::agent_request, 1000);
}

#[test]
fn snapshot() {
    run("snapshot", fuzzing::snapshot, 1500);
}

#[test]
fn abuse_report() {
    run("abuse_report", fuzzing::abuse_report, 1500);
}
