//! The fuzz targets (`fuzz/`, nightly) on stable: realistic inputs and the seed files, plus a
//! few thousand mutations of them, so `cargo test` catches a panic or a broken promise
//! without libFuzzer. The real search runs with `cargo +nightly fuzz run …`.
//! `LOGGUARD_MAIL_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` refreshes `fuzz/seeds/` from the
//! inputs below (the keys are new and throwaway every time; documentation addresses only).

use std::path::PathBuf;

use logguard_mail_bot::fuzzing;
use logguard_mail_bot::seal::Signer;
use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;

/// An outbox message as logguard's botbox writes it.
fn message(to: &str, subject: &str, body: &str) -> Vec<u8> {
    format!("To: {to}\nSubject: {subject}\n\n{subject}\n\n{body}").into_bytes()
}

fn public_key(uid: &str, primary: KeyType, encryption: KeyType) -> SignedPublicKey {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(encryption).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(uid.into())
        .subkeys(vec![enc.build().unwrap()]);
    SignedPublicKey::from(params.build().unwrap().generate(rand08::thread_rng()).unwrap())
}

/// (target, input) pairs like the real ones.
fn inputs(with_rsa: bool) -> Vec<(&'static str, Vec<u8>)> {
    let digest = "Period 2026-10-16 07:05 → 2026-10-17 07:05 UTC (1d)\nMode: Enforce. Active bans now: 3.\n\nAttention:\n  \
        • certificate example.org:5223 expires in 5d\n  • cluster peer 198.51.100.20:7946 failing: connect: timed out\n\nBans (2):\n  \
        10.1.2.3  40 pts  banned (2)  Germany / Example (AS64496)\n\nExposed: 22 sshd, [2001:db8::10]:5223 ejabberd\n\
        Certificates: example.org:5223 85d, nextcloud.example.org:443 5d";
    let report = "Abuse report from xmpp (192.0.2.10) and vpn (198.51.100.20)\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n\n\
        Hello, abuse@example.net,\n\n2026-10-18T11:00:01Z  11.20.45.233  sshd  Invalid user probe1\n"
        .repeat(20);
    let mut v = vec![
        ("alert_mail", message("admin", "[xmpp] logguard daily digest", digest)),
        (
            "alert_mail",
            message(
                "admin@example.org",
                "[xmpp] logguard: account under attack",
                "[High] account ejabberd:alice@example.org under distributed attack: ~40 failures from 9 addresses\n  \
                 10-16 12:00:01 auth failed: Failed c2s SCRAM-SHA-256 authentication for Bob(1)@Example.org/Conversations.x1 from ::ffff:192.0.2.10",
            ),
        ),
        // what attackers can put in: line breaks, header and boundary look-alikes, dots, "From "
        (
            "alert_mail",
            message(
                "admin",
                "[vpn] logguard: new registration",
                "account x@example.org\r\nBcc: evil@example.net\r\n\r\n--=_logguard_0\r\nContent-Type: text/html\r\n.\r\n..\nFrom me\n=?utf-8?b?QQ==?=\n=3D",
            ),
        ),
        ("alert_mail", message("admin", &"[tg] logguard: Konto zagrożone → юзер ✓ 😀 ".repeat(12), "Привіт\r\u{1b}[31mred\u{0}\ttab relay.example.net.")),
        ("alert_mail", message("admin", "[xmpp] logguard daily digest", &format!("{}{}", "x".repeat(2000), " trailing   \n".repeat(50)))),
        ("alert_mail", b"To: admin\n\nno subject: the first line is\nsecond".to_vec()),
        ("alert_mail", b"To: admin\nSubject: s\n\n".to_vec()),
        ("file_mail", format!("abuse-report-2026-10-19.txt\0{report}").into_bytes()),
        ("file_mail", b"dump.bin\0\xff\x00\xfe\r\n--=_logguard-file_0\r\n".to_vec()),
        ("file_mail", b"../.. evil \"name\".bin\0\x80".to_vec()),
        ("file_mail", b"\0".to_vec()),
        ("file_mail", "report.txt\0line\r\nline\rline\n\u{0}".as_bytes().to_vec()),
    ];
    let admin = public_key("Admin <admin@example.org>", KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy));
    let ops = public_key("Ops <ops@example.net>", KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy));
    let other = public_key("Someone <someone@example.com>", KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy));
    v.push(("openpgp_keys", admin.to_bytes().unwrap()));
    v.push(("openpgp_keys", [admin.to_bytes().unwrap(), ops.to_bytes().unwrap()].concat()));
    v.push((
        "openpgp_keys",
        format!("{}{}", admin.to_armored_string(Default::default()).unwrap(), ops.to_armored_string(Default::default()).unwrap())
            .into_bytes(),
    ));
    v.push(("openpgp_keys", other.to_bytes().unwrap()));
    let (secret, public) = Signer::generate("alerts@example.org").unwrap();
    v.push(("signing_key", secret.into_bytes()));
    v.push(("signing_key", public.into_bytes()));
    if with_rsa {
        // slow to make in a debug build: only when writing the seeds
        v.push(("openpgp_keys", public_key("Admin <admin@example.org>", KeyType::Rsa(2048), KeyType::Rsa(2048)).to_bytes().unwrap()));
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

/// Bytes that matter to the parsers and the MIME layout.
const INTERESTING: &[&[u8]] = &[
    b"@",
    b":",
    b".",
    b"\r\n",
    b"\n\n",
    b"\r",
    b"\0",
    b"\xff",
    b"\xf0\x9f\x98\x80",
    b"=",
    b"=_",
    b"--",
    b"\r\n.\r\n",
    b"Subject: ",
    b"To: ",
    b"ejabberd:",
    b"example.org",
    b"192.0.2.10",
    b"2001:db8::10",
    b"=?utf-8?b?",
    b" ",
    b"\t",
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
    let write = std::env::var_os("LOGGUARD_MAIL_BOT_WRITE_SEEDS").is_some();
    let inputs = inputs(write);
    if write {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
        for (i, (target, data)) in inputs.iter().enumerate() {
            std::fs::create_dir_all(root.join(target)).unwrap();
            std::fs::write(root.join(target).join(format!("generated-{i}")), data).unwrap();
        }
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for target in ["alert_mail", "file_mail", "openpgp_keys", "signing_key"] {
        let mut all: Vec<Vec<u8>> = inputs.iter().filter(|(t, _)| *t == target).map(|(_, d)| d.clone()).collect();
        all.extend(seeds(target));
        let run = |data: &[u8]| {
            let call = || match target {
                "alert_mail" => fuzzing::alert(data),
                "file_mail" => fuzzing::file(data),
                "openpgp_keys" => fuzzing::openpgp_keys(data),
                _ => fuzzing::signing_key(data),
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
        // every round encrypts and decrypts (and keys are slow in a debug build): fewer rounds
        let rounds = match target {
            "alert_mail" | "file_mail" => 1500,
            _ => 300,
        };
        for _ in 0..rounds {
            let pick = rng.below(all.len());
            let m = mutate(&mut rng, &all[pick]);
            run(&m);
        }
    }
}
