//! The fuzz targets (`fuzz/`, nightly) on stable: realistic inputs and the seed files, plus a
//! few thousand mutations of them, so `cargo test` catches a panic or a broken promise
//! without libFuzzer. The real search runs with `cargo +nightly fuzz run …`.
//! `LOGGUARD_SIGNAL_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` refreshes `fuzz/seeds/` from
//! the inputs below.

use std::path::PathBuf;

use logguard_signal_bot::fuzzing;

/// (target, input) pairs like the real ones.
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("cli_line", br#"{"jsonrpc":"2.0","result":{"timestamp":1760000000000,"results":[{"recipientAddress":{"uuid":"a1b2c3d4-e5f6-7890-abcd-ef0123456789","number":"+491701234567"},"type":"SUCCESS"}]},"id":7}"#.to_vec()),
        ("cli_line", br#"{"jsonrpc":"2.0","error":{"code":-1,"message":"Failed to send message","data":{"response":{"timestamp":1,"results":[{"recipientAddress":{"number":"+491701234567"},"type":"IDENTITY_FAILURE","token":null}]}}},"id":8}"#.to_vec()),
        ("cli_line", br#"{"jsonrpc":"2.0","result":[{"number":"+491701234567","uuid":"a1b2c3d4-e5f6-7890-abcd-ef0123456789","fingerprint":"05 1a 2b","safetyNumber":"12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890","scannableSafetyNumber":"CiQK","trustLevel":"UNTRUSTED","addedTimestamp":1760000000000}],"id":9}"#.to_vec()),
        ("cli_line", br#"{"jsonrpc":"2.0","method":"receive","params":{"envelope":{"source":"+15550000000","sourceNumber":"+15550000000","timestamp":1,"dataMessage":{"message":"/status"}},"account":"+491700000000"}}"#.to_vec()),
        ("cli_line", b"INFO  SignalAccount - Config file is in use by another instance, waiting\xe2\x80\xa6".to_vec()),
        ("alert_file", b"To: admin\nSubject: [xmpp] logguard: system\n\n[xmpp] logguard: system\n\n[High] line \xf0\x9f\x98\x80".to_vec()),
        ("alert_file", b"To: \nSubject: s\n\nbody\xff".to_vec()),
    ]
}

fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds").join(target);
    let mut v: Vec<Vec<u8>> =
        std::fs::read_dir(dir).map(|d| d.map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect()).unwrap_or_default();
    v.sort();
    v
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Bytes that matter to the parsers: JSON structure, signal-cli's fields and values.
const INTERESTING: &[&[u8]] = &[
    b"\"",
    b"{",
    b"}",
    b"[",
    b"]",
    b":",
    b",",
    b"null",
    b"\"id\":",
    b"\"error\":",
    b"\"results\":",
    b"IDENTITY_FAILURE",
    b"UNTRUSTED",
    b"+491701234567",
    b"12345 ",
    b"\\u0000",
    b"\n\n",
    b"\xff",
    b"0",
];

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..1 + rng.below(6) {
        let at = rng.below(out.len() + 1);
        match rng.below(5) {
            0 if !out.is_empty() => {
                let i = at.min(out.len() - 1);
                out[i] = rng.next() as u8;
            }
            1 if at < out.len() => {
                let end = (at + rng.below(8)).min(out.len());
                out.drain(at..end);
            }
            2 => {
                let piece = INTERESTING[rng.below(INTERESTING.len())];
                out.splice(at..at, piece.iter().copied());
            }
            3 if at < out.len() => {
                let end = (at + rng.below(16)).min(out.len());
                let piece = out[at..end].repeat(1 + rng.below(8));
                out.splice(at..at, piece);
            }
            _ => out.truncate(at),
        }
    }
    out
}

#[test]
fn targets_survive_inputs_and_mutations() {
    let inputs = inputs();
    if std::env::var_os("LOGGUARD_SIGNAL_BOT_WRITE_SEEDS").is_some() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
        for (i, (target, data)) in inputs.iter().enumerate() {
            std::fs::create_dir_all(root.join(target)).unwrap();
            std::fs::write(root.join(target).join(format!("generated-{i}")), data).unwrap();
        }
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for target in ["cli_line", "alert_file"] {
        let mut all: Vec<Vec<u8>> = inputs.iter().filter(|(t, _)| *t == target).map(|(_, d)| d.clone()).collect();
        all.extend(seeds(target));
        let run = |data: &[u8]| {
            let call = || match target {
                "cli_line" => fuzzing::cli_line(data),
                _ => fuzzing::alert_file(data),
            };
            // a failing input is kept, to replay: cargo +nightly fuzz run <target> <file>
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)) {
                let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("target/fuzz-smoke-{target}.bin"));
                let _ = std::fs::write(&path, data);
                eprintln!("the failing input is in {}", path.display());
                std::panic::resume_unwind(e);
            }
        };
        for i in &all {
            run(i);
        }
        for _ in 0..3000 {
            let pick = rng.below(all.len());
            let m = mutate(&mut rng, &all[pick]);
            run(&m);
        }
    }
}
