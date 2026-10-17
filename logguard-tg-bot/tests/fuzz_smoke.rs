//! The fuzz targets (`fuzz/`, nightly) on stable: realistic inputs and the seed files, plus a
//! few thousand mutations of them, so `cargo test` catches a panic or a broken promise
//! without libFuzzer. The real search runs with `cargo +nightly fuzz run …`.
//! `LOGGUARD_TG_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` refreshes `fuzz/seeds/` from the inputs
//! below (the keys are new and throwaway every time; documentation addresses only).

use std::path::PathBuf;

use logguard_tg_bot::fuzzing;
use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;

/// An outbox message as logguard's botbox writes it.
fn message(subject: &str, body: &str) -> Vec<u8> {
    format!("To: telegram\nSubject: {subject}\n\n{subject}\n\n{body}").into_bytes()
}

fn public_key(primary: KeyType, encryption: KeyType) -> SignedPublicKey {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(encryption).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("fuzz <admin@example.org>".into())
        .subkeys(vec![enc.build().unwrap()]);
    SignedPublicKey::from(params.build().unwrap().generate(rand08::thread_rng()).unwrap())
}

/// (target, input) pairs like the real ones.
fn inputs(with_rsa: bool) -> Vec<(&'static str, Vec<u8>)> {
    let digest = "Period 2026-10-16 07:05 → 2026-10-17 07:05 UTC (1d)\nMode: Enforce. Active bans now: 3.\n\nAttention:\n  \
        • certificate example.org:5223 expires in 5d\n  • cluster peer 198.51.100.20:7946 failing: connect: timed out\n\nBans (2):\n  \
        2  ssh_canary\n  10.1.2.3  40 pts  banned (2)  Germany / Example (AS64496)\n\nExposed: 22 sshd, [2001:db8::10]:5223 ejabberd\n\
        Certificates: example.org:5223 85d, nextcloud.example.org:443 5d";
    let mut v = vec![
        ("alert_text", message("[xmpp] logguard daily digest", digest)),
        (
            "alert_text",
            message(
                "[xmpp] logguard: account under attack",
                "[High] account ejabberd:alice@example.org under distributed attack: ~40 failures from 9 addresses\n  \
                 10-16 12:00:01 auth failed: Failed c2s SCRAM-SHA-256 authentication for Bob(1)@Example.org/Conversations.x1 from ::ffff:192.0.2.10",
            ),
        ),
        ("alert_text", message("[vpn] logguard: new registration", "[Info] account [a,b]@example.org registered from 203.0.113.30:443; ejabberd:carol, ejabberd:x=y")),
        ("alert_text", message("[tg] logguard: system", "Привіт → юзер@example.org ✓ 😀\r\n\u{1b}[31mred\u{0}\ttab relay.example.net.")),
        ("alert_text", message("[xmpp] logguard daily digest", &"  1234  192.0.2.99  12 pts  dead:192.0.2.10 😀\n".repeat(300))),
        ("alert_text", b"To: telegram\nSubject: s\n\n".to_vec()),
        ("alert_text", b"not a message at all @ ejabberd: 2001:db8::10:5223".to_vec()),
        (
            "telegram_reply",
            br#"{"ok":true,"result":[{"update_id":20,"message":{"message_id":5,"from":{"id":42,"is_bot":false,"first_name":"A"},"chat":{"id":42,"type":"private"},"date":1760000000,"text":"/start 0011aabbccddeeff"}},{"update_id":21,"my_chat_member":{}},{"update_id":"x"}]}"#.to_vec(),
        ),
        ("telegram_reply", br#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}"#.to_vec()),
        ("telegram_reply", br#"{"ok":true,"result":{"message_id":9,"chat":{"id":42,"type":"private"},"date":1760000000}}"#.to_vec()),
        ("telegram_reply", br#"{"ok":true,"result":{"id":999,"is_bot":true,"first_name":"t","username":"lg_bot"}}"#.to_vec()),
        ("telegram_reply", br#"{"offset":502,"to_delete":[{"id":5,"at":1760000000}]}"#.to_vec()),
        ("server_names", format!("{}\0{digest}", fuzzing::SERVERS).into_bytes()),
        ("server_names", b"a=[::ffff:192.0.2.1], 2001:db8::1 ;b=x.example; tg=tg.example.com\0x.tg.example.com 192.0.2.1:80 [2001:db8::1]:5222".to_vec()),
    ];
    let ed = public_key(KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy));
    v.push(("openpgp_key", ed.to_bytes().unwrap()));
    v.push(("openpgp_key", ed.to_armored_string(Default::default()).unwrap().into_bytes()));
    if with_rsa {
        // slow to make in a debug build: only when writing the seeds
        v.push(("openpgp_key", public_key(KeyType::Rsa(2048), KeyType::Rsa(2048)).to_bytes().unwrap()));
    }
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

/// Bytes that matter to the parsers: separators, brackets, address and JSON characters.
const INTERESTING: &[&[u8]] = &[
    b"@",
    b":",
    b".",
    b"[",
    b"]",
    b"(",
    b",",
    b"/",
    b"\n\n",
    b"\r",
    b"\0",
    b"\xff",
    b"\xf0\x9f\x98\x80",
    b"ejabberd:",
    b"[acct:",
    b"example.org",
    b"192.0.2.10",
    b"::ffff:",
    b"2001:db8::10",
    b"\"",
    b"{",
    b"}",
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
    let write = std::env::var_os("LOGGUARD_TG_BOT_WRITE_SEEDS").is_some();
    let inputs = inputs(write);
    if write {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
        for (i, (target, data)) in inputs.iter().enumerate() {
            std::fs::create_dir_all(root.join(target)).unwrap();
            std::fs::write(root.join(target).join(format!("generated-{i}")), data).unwrap();
        }
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for target in ["alert_text", "telegram_reply", "openpgp_key", "server_names"] {
        let mut all: Vec<Vec<u8>> = inputs.iter().filter(|(t, _)| *t == target).map(|(_, d)| d.clone()).collect();
        all.extend(seeds(target));
        let run = |data: &[u8]| {
            let call = || match target {
                "alert_text" => fuzzing::alert(data),
                "telegram_reply" => fuzzing::telegram_reply(data),
                "openpgp_key" => fuzzing::openpgp_key(data),
                _ => fuzzing::server_names(data),
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
        // keys are slow to parse and encrypt to in a debug build: fewer of those
        let rounds = if target == "openpgp_key" { 300 } else { 3000 };
        for _ in 0..rounds {
            let pick = rng.below(all.len());
            let m = mutate(&mut rng, &all[pick]);
            run(&m);
        }
    }
}
