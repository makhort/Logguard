# logguard

Behaviour-based intrusion prevention for a small self-hosted server family: an XMPP server
(ejabberd) with Nextcloud, a WireGuard VPN host and a Telegram relay node. Everything is
written in Rust and runs as single static binaries on Linux (x86_64, musl).

**logguard** follows the systemd journal (ejabberd, sshd, UFW/kernel, Nextcloud AIO), scores
every remote address by what it does, and bans attackers in nftables, ufw or iptables within
seconds. Nodes can share bans and suspicion reports over an encrypted cluster link. Three
optional bots carry logguard's admin alerts, daily digest and weekly abuse report to the
admins. They only carry messages: protection never depends on them.

```
        ┌──────────── server ─────────────┐        cluster (XChaCha20-Poly1305, TCP 7946)
journal ─► logguard ─► nftables/ufw/iptables ◄──────────────► logguard on other nodes
            │  outboxes (files)
            ├─► logguard-xmpp-bot ─► XMPP, OMEMO-encrypted
            ├─► logguard-tg-bot   ─► Telegram (pseudonymized, files OpenPGP-encrypted)
            └─► logguard-mail-bot ─► SMTP, PGP/MIME-encrypted
```

## Crates

Each directory is its own Cargo project with a README that covers setup, settings and design
in detail.

| crate | what it does |
|---|---|
| [`logguard`](logguard/README.md) | The daemon and its CLI/TUI: log parsers, the scoring and ban engine, firewall backends, cluster, exposure/cron/antivirus watches, blocklist feeds, daily digest, weekly abuse reports. |
| [`logguard-xmpp-bot`](logguard-xmpp-bot/README.md) | XMPP admin bot: curated `ejabberdctl` commands in chat, plus logguard's admin messages over OMEMO. SCRAM-SHA-256-PLUS login, direct TLS. |
| [`logguard-tg-bot`](logguard-tg-bot/README.md) | Telegram transport for logguard's admin messages. Account names become pseudonyms and servers appear only by node id. Reports go out as OpenPGP-encrypted files. |
| [`logguard-mail-bot`](logguard-mail-bot/README.md) | Send-only SMTP bot that mails logguard's admin messages, each OpenPGP-encrypted as a whole (subject included). |

The supported combinations of bots and cluster peers are described in logguard's README,
"Deployment layouts". `logguard/tests/layouts.rs` runs each layout end to end.

## Build and test

You need Rust stable and the `x86_64-unknown-linux-musl` target. The bots also need the
`llvm-tools` component. Each crate builds and tests on its own:

```bash
cd logguard            # or logguard-xmpp-bot, logguard-tg-bot, logguard-mail-bot
./scripts/ci.sh        # fmt, clippy -D warnings, tests, cargo audit, static musl build
```

The static Linux binary also builds from macOS without a C cross toolchain (see each crate's
`.cargo/config.toml`). Some tests listen on 127.0.0.1, so they need a machine or sandbox that
allows local sockets. `.github/workflows/` runs the same `ci.sh` per crate on GitHub Actions
and uploads the static binaries.

Each crate has `fuzz/` targets for cargo-fuzz (nightly). `tests/fuzz_smoke.rs` runs the same
targets on stable over their seeds.

## Deployment

Each crate has a `deploy/` directory: a `deploy.sh` that runs `ci.sh`, builds the binary and
copies everything to a host over SSH, and an `install.sh` to run there as root. It also holds
the systemd units, logrotate files and config templates. logguard ships three config
templates: `logguard.toml` (XMPP server), `logguard-standalone.toml` (a host with SSH and UFW
only, e.g. a VPN server) and `logguard-tg.toml` (Telegram relay node).

The templates use placeholder names and addresses (`example.org`, documentation ranges).
Replace them, and the allowlist entries, with your own before deploying. Start in
`mode = "shadow"`, review the decisions, then switch to `"enforce"`.


## License

[MIT](LICENSE).

## Authorship

This project was co-authored by Claude Opus 5.5 (Anthropic) in Claude Code: the design,
the code, the tests and the documentation were written in collaboration with the model.
