//! The fuzz targets (`fuzz/`, nightly) on stable: realistic inputs and the seed files, plus a
//! few thousand mutations of them, so `cargo test` catches a panic or a broken promise
//! without libFuzzer. The real search runs with `cargo +nightly fuzz run …`.
//! `LOGGUARD_MATRIX_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` refreshes `fuzz/seeds/` from
//! the inputs below (the keys are new and throwaway every time).

use std::path::PathBuf;

use logguard_matrix_bot::{crypto, fuzzing};
use serde_json::json;
use vodozemac::olm::Account;
use vodozemac::Ed25519SecretKey;

const ADMIN: &str = "@admin:example.org";

/// A `/keys/query` reply as a homeserver gives it: two devices, one cross-signed, plus a
/// claimed one-time key.
fn keys_reply() -> Vec<u8> {
    let (phone, laptop) = (Account::new(), Account::new());
    let (master, ssk) = (Ed25519SecretKey::new(), Ed25519SecretKey::new());
    let cross = crypto::cross_signing_keys(ADMIN, &master, &ssk);
    let mut phone_keys = crypto::device_keys(&phone, ADMIN, "PHONE");
    let sig = crypto::device_signature(&phone_keys, ADMIN, "PHONE", &ssk);
    let id = format!("ed25519:{}", ssk.public_key().to_base64());
    phone_keys["signatures"][ADMIN][&id] = sig[ADMIN]["PHONE"]["signatures"][ADMIN][&id].clone();
    let otk = crypto::signed(&json!({ "key": Account::new().curve25519_key().to_base64() }), ADMIN, "ed25519:PHONE", |m| phone.sign(m));
    json!({
        "device_keys": { ADMIN: { "PHONE": phone_keys, "LAPTOP": crypto::device_keys(&laptop, ADMIN, "LAPTOP") } },
        "master_keys": { ADMIN: cross["master_key"] },
        "self_signing_keys": { ADMIN: cross["self_signing_key"] },
        "one_time_keys": { ADMIN: { "PHONE": { "signed_curve25519:AAAAAQ": otk } } },
        "failures": {},
    })
    .to_string()
    .into_bytes()
}

/// (target, input) pairs like the real ones.
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("keys_query", keys_reply()),
        ("keys_query", br#"{"device_keys":{"@admin:example.org":{"X":{"user_id":"@admin:example.org","device_id":"X","algorithms":[],"keys":{}}}}}"#.to_vec()),
        ("keys_query", br#"{"master_keys":{"@admin:example.org":{"user_id":"@admin:example.org","usage":["master"],"keys":{"ed25519:a":"a","ed25519:b":"b"}}}}"#.to_vec()),
        ("alert_file", b"To: admin\nSubject: [xmpp] logguard: system\n\n[xmpp] logguard: system\n\n[High] line".to_vec()),
        ("alert_file", b"To: \nSubject: s\n\nbody\xff".to_vec()),
        ("attachment", b"Abuse report from xmpp (192.0.2.10)\n".repeat(50)),
        ("attachment", Vec::new()),
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

/// Bytes that matter to the parsers: JSON structure, key ids, identifiers.
const INTERESTING: &[&[u8]] = &[
    b"\"",
    b"{",
    b"}",
    b"[",
    b"]",
    b":",
    b",",
    b"null",
    b"ed25519:",
    b"curve25519:",
    b"signed_curve25519:",
    b"@admin:example.org",
    b"PHONE",
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
    if std::env::var_os("LOGGUARD_MATRIX_BOT_WRITE_SEEDS").is_some() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
        for (i, (target, data)) in inputs.iter().enumerate() {
            std::fs::create_dir_all(root.join(target)).unwrap();
            std::fs::write(root.join(target).join(format!("generated-{i}")), data).unwrap();
        }
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for target in ["keys_query", "alert_file", "attachment"] {
        let mut all: Vec<Vec<u8>> = inputs.iter().filter(|(t, _)| *t == target).map(|(_, d)| d.clone()).collect();
        all.extend(seeds(target));
        let run = |data: &[u8]| {
            let call = || match target {
                "keys_query" => fuzzing::keys_query(data),
                "alert_file" => fuzzing::alert_file(data),
                _ => fuzzing::attachment(data),
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
