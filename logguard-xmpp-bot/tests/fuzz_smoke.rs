//! The fuzz targets (`fuzz/`, nightly) on stable: real OMEMO traffic between two throwaway
//! devices and the seed files, plus a few thousand mutations of them, so `cargo test`
//! catches a panic without libFuzzer. The real search runs with `cargo +nightly fuzz run …`.
//! `LOGGUARD_XMPP_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` refreshes `fuzz/seeds/` from the
//! generated traffic (new random keys every time; nothing secret).

use std::path::PathBuf;

use logguard_xmpp_bot::fuzzing::{self, Device};
use tokio_xmpp::minidom::Element;

/// (target, input) pairs: a session start and a follow-up message, as wire bytes and as XML,
/// and a bundle.
fn traffic() -> Vec<(&'static str, Vec<u8>)> {
    let (mut alice, mut bot) = (Device::new(), Device::new());
    let bundle = bot.store.bundle();
    let bot_id = bot.store.device_id();
    alice.store.start_session("bot@example.org", bot_id, &bundle).unwrap();
    let first = alice.store.encrypt("bot@example.org", &[bot_id], Some("/help")).unwrap();
    bot.store.decrypt_if("alice@example.org", &first, |_| true).unwrap();
    let reply = bot.store.encrypt("alice@example.org", &[first.header.sid], Some("ok")).unwrap();
    let mut v = vec![
        ("omemo_wire", first.header.keys[0].data.clone()),
        ("omemo_wire", reply.header.keys[0].data.clone()),
        ("omemo_stanza", String::from(&Element::from(first.clone())).into_bytes()),
        ("omemo_stanza", String::from(&Element::from(bundle)).into_bytes()),
        ("omemo_stanza", b"To: admin@example.org\nSubject: s\n\n[xmpp] logguard: system\n\nline".to_vec()),
    ];
    // the decrypt target: shape byte, then what it builds the message from
    let mut session_start = vec![1u8];
    session_start.extend_from_slice(&first.header.keys[0].data);
    v.push(("omemo_decrypt", session_start));
    let mut as_sent = vec![2u8];
    as_sent.extend_from_slice(&first.header.keys[0].data);
    v.push(("omemo_decrypt", as_sent));
    v
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
                let byte = [0x00, 0x05, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x22, 0x2a, 0x33, 0x80, 0xff][rng.below(12)];
                out.insert(at, byte);
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
fn omemo_targets_survive_traffic_and_mutations() {
    let traffic = traffic();
    if std::env::var_os("LOGGUARD_XMPP_BOT_WRITE_SEEDS").is_some() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
        for (i, (target, data)) in traffic.iter().enumerate() {
            std::fs::create_dir_all(root.join(target)).unwrap();
            std::fs::write(root.join(target).join(format!("generated-{i}")), data).unwrap();
        }
    }
    let mut device = Device::new();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for target in ["omemo_wire", "omemo_decrypt", "omemo_stanza"] {
        let mut inputs: Vec<Vec<u8>> = traffic.iter().filter(|(t, _)| *t == target).map(|(_, d)| d.clone()).collect();
        inputs.extend(seeds(target));
        let run = |device: &mut Device, data: &[u8]| match target {
            "omemo_wire" => fuzzing::wire(data),
            "omemo_decrypt" => fuzzing::decrypt(device, data),
            _ => fuzzing::stanza(device, data),
        };
        for i in &inputs {
            run(&mut device, i);
        }
        for _ in 0..1000 {
            let pick = rng.below(inputs.len());
            let m = mutate(&mut rng, &inputs[pick]);
            run(&mut device, &m);
        }
    }
}
