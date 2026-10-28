# logguard

Behaviour-based intrusion prevention for a small self-hosted server family: an XMPP server
(ejabberd) with Nextcloud, a WireGuard VPN host and a Telegram relay node. Everything is
written in Rust and runs as single static binaries on Linux (musl; x86_64, aarch64 and 32-bit ARMv7 with hardware floating point).

**logguard** follows the systemd journal (ejabberd, sshd, the UFW or firewalld kernel log,
Nextcloud AIO), scores every remote address by what it does, and bans attackers in nftables,
firewalld, ufw, iptables or ipset within seconds. It can also drop whole countries or networks
(ASNs), by the offline geo database it already uses for labels. Nodes can share bans and suspicion reports over an encrypted cluster link. Five
optional bots carry logguard's admin alerts, daily digest and weekly abuse report to the
admins, and an optional web console shows the whole cluster to its admins, read only. They only
carry messages and show data: protection never depends on them.

```
        ┌──────────── server ─────────────┐        cluster (XChaCha20-Poly1305, TCP 7946)
journal ─► logguard ─► nftables/firewalld/ufw/iptables/ipset ◄─► logguard on other nodes
            │  outboxes (files)
            ├─► logguard-xmpp-bot ─► XMPP, OMEMO-encrypted (client mode: else OpenPGP files)
            ├─► logguard-tg-bot     ─► Telegram (pseudonymized, files OpenPGP-encrypted)
            ├─► logguard-mail-bot   ─► SMTP, PGP/MIME-encrypted
            ├─► logguard-signal-bot ─► Signal through signal-cli (else OpenPGP files)
            └─► logguard-matrix-bot ─► Matrix, Olm/Megolm-encrypted (else OpenPGP files)
            │  read-only console socket
            └─► logguard-web (agent) ◄─ web key, TCP 7949 ─ logguard-web (console) ─► HTTPS ─► the admin's browser
```

How logguard compares with fail2ban, sshguard, CrowdSec, CSF, Wazuh and OSSEC, the host
integrity and monitoring tools, and commercial products, with pros and cons per category and
feature: [COMPARISON.md](COMPARISON.md).

## Contents

1. [Crates](#crates)
2. [Build and test](#build-and-test)
3. [Deployment](#deployment)
4. [Private repository only](#private-repository-only)
5. [License](#license)
6. [Authorship](#authorship)

## Crates

Each directory is its own Cargo project with a README that covers setup, settings and design
in detail.

| crate | what it does |
|---|---|
| [`logguard`](logguard/README.md) | The daemon and its CLI/TUI: log parsers, the scoring and ban engine, firewall backends, cluster, exposure/cron/antivirus watches, package checks (dpkg or rpm), blocklist feeds, country and network blocking, daily digest, weekly abuse reports. |
| [`logguard-xmpp-bot`](logguard-xmpp-bot/README.md) | XMPP bot in two modes. Admin (on the XMPP server): curated `ejabberdctl` commands in chat, plus logguard's admin messages over OMEMO. Client (`BOT_MODE=client`, any host and XMPP server, e.g. a desktop): send-only, logguard's admin messages over OMEMO, else as OpenPGP-encrypted files. SCRAM-SHA-256-PLUS login. |
| [`logguard-tg-bot`](logguard-tg-bot/README.md) | Telegram transport for logguard's admin messages. Account names become pseudonyms and servers appear only by node id. Reports go out as OpenPGP-encrypted files. |
| [`logguard-mail-bot`](logguard-mail-bot/README.md) | Send-only SMTP bot that mails logguard's admin messages, each OpenPGP-encrypted as a whole (subject included). |
| [`logguard-signal-bot`](logguard-signal-bot/README.md) | Send-only Signal bot over signal-cli (installed separately): logguard's admin messages while the safety number with the admin is the pinned one, else as OpenPGP-encrypted files. |
| [`logguard-web`](logguard-web/README.md) | Read-only web console for the whole cluster: an agent on every node hands its logguard's data (through a read-only socket) to the console, sealed with a web key of its own (never the cluster key) and forward-secret; the console shows bans, alerts, offenders, places and every node's health and every node's abuse report split per network owner, ready to mail, over HTTPS (TLS 1.3) to its admins (one or a few, all equal), each with a password and a one-time code, plus `/metrics` for Prometheus. It also runs alone on a host without logguard, as an aggregator. |
| [`logguard-matrix-bot`](logguard-matrix-bot/README.md) | Send-only Matrix client: logguard's admin messages end-to-end encrypted (Olm/Megolm, vodozemac) to the devices the admin verified, else as OpenPGP-encrypted files. |

The supported combinations of bots and cluster peers are described in logguard's README,
"Deployment layouts". `logguard/tests/layouts.rs` runs each layout end to end.

## Build and test

You need Rust stable and the `x86_64-unknown-linux-musl` target (for ARM also `aarch64-unknown-linux-musl`,
`armv7-unknown-linux-musleabihf`; `TARGET=<target> ./scripts/ci.sh` builds one). The bots and logguard-web also need the
`llvm-tools` component. Each crate builds and tests on its own:

```bash
cd logguard            # or logguard-xmpp-bot, logguard-tg-bot, logguard-mail-bot, logguard-signal-bot, logguard-matrix-bot, logguard-web
./scripts/ci.sh        # fmt, clippy -D warnings, tests, cargo audit, static musl build
./scripts/bundle.sh    # the release bundle (zip); ./scripts/package.sh: the .deb and .rpm (both take --target TRIPLE)
```

`package.sh` needs `cargo install cargo-deb cargo-generate-rpm --locked` once; they write the
packages without dpkg or rpm, so the packages build on macOS too.

The static Linux binary also builds from macOS without a C cross toolchain (see each crate's
`.cargo/config.toml`). Some tests listen on 127.0.0.1, so they need a machine or sandbox that
allows local sockets. `.github/workflows/` runs the same `ci.sh` per crate on GitHub Actions
and uploads the bundles: the tests on x86_64 and on GitHub's arm64 runners, the 32-bit ARM
binary cross-built, linted for its target and started under qemu.

Each crate has `fuzz/` targets for cargo-fuzz (nightly). `tests/fuzz_smoke.rs` runs the same
targets on stable over their seeds.

## Deployment

**From a release bundle** (no Rust needed): one zip per crate and architecture,
`<crate>-<version>-<commit>-<arch>.zip`, `<arch>` one of `x86_64-linux-musl`,
`aarch64-linux-musl` (arm64) and `armv7-linux-musleabihf` (32-bit ARMv7, hard-float). It holds the static binary, the systemd
units, logrotate files and config templates, `SHA256SUMS`, and an `install.sh`. Unzip it on
the server and run `sudo ./install.sh` (the first run of each puts a config in place to edit,
then you run it again). Each crate's README has a section "Install from a release bundle",
with how to download and verify one.

**From a package** (Debian, Ubuntu and their derivatives; Fedora, RHEL and its rebuilds): the same
releases carry `<crate>_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`) and
`<crate>-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`), the same static binary and
deploy files for the package manager: `sudo apt install ./<file>.deb` or `sudo dnf install
./<file>.rpm`. logguard goes to `/usr/bin` with its units in `/usr/lib/systemd/system` and the
templates in `/usr/share/logguard/templates`; the bots and logguard-web stay in `/opt/<crate>`.
Nothing starts on its own: the first install puts the config template in place to edit, then
you enable the service. An upgrade keeps the config (asking, when a terminal is there, whether
to replace it with the new template) and restarts a running service when its config is valid.
The packages also install over a bundle or `deploy.sh` install and take it over, keeping its
config, keys and state. Rollback is installing the previous version's package; there is no apt
or dnf repository. Each crate's README has a section "Install from a package".

**Releases:** a version is a tag `<crate>-v<version>` (`logguard-v0.4.0`,
`logguard-xmpp-bot-v0.4.0`, ...), with the version in that crate's `Cargo.toml`
(`./scripts/bundle.sh --check-tag TAG` checks it). Pushing the tag runs that crate's workflow,
which refuses a tag that doesn't match, tests, builds and installs the bundles and packages as
on every commit (the `.deb` on the runner, over the bundle's install; the `.rpm` in a Fedora
container), then attaches them to the GitHub Release of the tag, each with its `.sha256` and
(in a public repository) a signed build provenance attestation, `.sigstore.json`, that
`gh attestation verify` checks. Every CI run, tagged or not, also keeps its zip, `.deb` and
`.rpm` as workflow artifacts.

**Fedora and RHEL:** logguard's `package_manager = "dnf"` (its `-dnf` config templates, the
`.rpm`'s default on a host with dnf) reads rpm's database and asks dnf for pending updates
instead of dpkg and apt; with firewalld as the firewall. Tried on a Fedora 44 server, step by step in
[logguard/TESTING-fedora.md](logguard/TESTING-fedora.md); the results are in logguard's README,
"Verified on the servers".

**From a checkout:** each crate has a `deploy/` directory: a `deploy.sh` that runs `ci.sh`,
builds the binary and copies everything to a host over SSH, and an `install.sh` to run there
as root. It also holds the systemd units, logrotate files and config templates.
`scripts/bundle.sh` builds the release bundle locally. logguard ships three config
templates: `logguard.toml` (XMPP server), `logguard-standalone.toml` (a host with SSH and UFW
only, e.g. a VPN server) and `logguard-tg.toml` (Telegram relay node).

The templates use placeholder names and addresses (`example.org`, documentation ranges).
Replace them, and the allowlist entries, with your own before deploying. Start in
`mode = "shadow"`, review the decisions, then switch to `"enforce"`.

**SSH hardening:** `hardening/harden-vps.sh`, run from your laptop, turns SSH on a VPS
(Debian/Ubuntu or Fedora/RHEL-like) into the gateway layout logguard's SSH audit checks: one
key-only user forced into `su` or sftp, keys in a root-owned file, `su` limited by pam_wheel.
It takes over a server hardened partly by hand too (`-g` keeps its user, `--su` works without
root login or sudo). It tests the new login before it commits and rolls back otherwise;
`hardening/harden-vps.sh --help` lists the options.


## License

[MIT](LICENSE).

## Authorship

This project was co-authored by Claude Opus 5.5 (Anthropic) in Claude Code: the design,
the code, the tests and the documentation were written in collaboration with the model.
