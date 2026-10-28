# logguard-matrix-bot

A Matrix bot that brings logguard's admin messages to the admin's Matrix account: the alerts,
the daily digest and the weekly abuse report, **end-to-end encrypted** (Olm and Megolm, as
Element, FluffyChat and other clients do it). When end-to-end encryption to the admin isn't
possible, a message goes out as a file encrypted to the admin's OpenPGP key instead, or waits.
It does for Matrix what `logguard-tg-bot` does for Telegram on logguard's side, through the
same kind of outbox, and nothing else:

- **A client only.** It logs in to an existing homeserver (matrix.org or your own) with an
  account of its own. No homeserver runs here, nothing listens.
- **Send only.** It doesn't read the room (no `/sync`): no commands, and nothing anyone writes
  there reaches it. The servers are managed over SSH.
- **No link to ejabberd.** It runs as its own user `logguard-matrix-bot`, which can't read
  ejabberd's files.

logguard feeds it only when `[notify] matrix_outbox` is set. Without it, nothing changes. It
can run next to the other bots, on any node: on the relay node (logguard's
`deploy/logguard-tg.toml`), the XMPP server never connects to the homeserver.

## Contents

1. [What it sends](#what-it-sends)
2. [End-to-end encryption, and who gets the keys](#end-to-end-encryption-and-who-gets-the-keys)
3. [When end-to-end encryption isn't possible](#when-end-to-end-encryption-isnt-possible)
4. [How logguard and the bot meet](#how-logguard-and-the-bot-meet)
5. [Install from a release bundle](#install-from-a-release-bundle)
6. [Install from a package](#install-from-a-package)
7. [Setup](#setup)
8. [Settings](#settings)
9. [Retention and what the bot keeps](#retention-and-what-the-bot-keeps)
10. [Why not matrix-sdk](#why-not-matrix-sdk)
11. [Build and test](#build-and-test)

## What it sends

| From logguard | In the room |
|---|---|
| alerts, the daily digest | a text message, Megolm-encrypted |
| the weekly abuse report | an encrypted attachment (AES-256-CTR, its key inside the Megolm-encrypted event) |
| either, when end-to-end encryption isn't possible | a file `message-<time>.txt.pgp` / `report-<time>.txt.pgp` encrypted to `OPENPGP_KEY`, with a neutral caption, and once a day a short notice saying why |

The homeserver sees that the bot sent something to the room, when, and how large: never what.
With `SANITIZE=yes` alerts and digests also lose XMPP account names (they become
pseudonyms) and the servers' addresses (node ids), as on Telegram; off by default, since they
are end-to-end encrypted (`logguard-matrix-bot pseudonym <jid>` tells which account a pseudonym is).

## End-to-end encryption, and who gets the keys

The bot is a Matrix device of its own (`logguard-matrix-bot login` makes it). It makes a direct
chat with the admin (`ADMIN`), encrypted from its first event, and invites them. For each
message it:

1. asks the homeserver for the admin's devices and cross-signing keys, and checks every
   signature itself (`src/crypto.rs`): a device must sign its own keys; with cross-signing,
   the admin's self-signing key must carry their master key's signature and the device the
   self-signing key's. The homeserver can withhold keys, not forge them.
2. decides which devices are the admin's:
   - **with cross-signing** (the usual case: every current client sets it up): only the
     devices the admin verified, under the admin's **master key**, which the bot pins the
     first time it sees it (or takes from `ADMIN_MASTER_KEY`). A changed master key, as
     after a reset of your cross-signing or a homeserver handing out keys of its own, gets
     nothing: messages come as OpenPGP files until you set `ADMIN_MASTER_KEY` to the new key
     (the bot logs it, and so does its notice) and restart the bot.
   - **without cross-signing:** every device that signs its own keys, each pinned by device
     id on first sight (a device id that comes back with other keys gets nothing). The bot
     logs a warning: anyone who controls the homeserver could add a device then.
3. shares the room's Megolm session key with those devices over Olm (a one-time key claimed
   for each, checked against the device's signature), and sends the message as a Megolm
   event. A new session is made after 100 messages, after a week, and whenever a device that
   had the key is no longer trusted (removed, or unverified), so it can't read what follows.

The bot's own device is signed by the bot account's cross-signing keys (made at the first
`login`), so clients show its messages as from a device its owner verified rather than with a
red warning. You can also verify the bot user in your client; the bot doesn't need it.

The Olm and Megolm code is [vodozemac](https://github.com/matrix-org/vodozemac) (matrix.org's
pure-Rust implementation, Apache-2.0, audited); the rest (key checks, sharing, the client API
calls) is in this crate. `state.json` keeps the device's keys, the sessions and the pins
(mode 0600); a Megolm ratchet is saved before each message leaves, so no message index is
ever used twice.

## When end-to-end encryption isn't possible

- `E2EE=no`;
- the admin's master key changed or vanished (above);
- with cross-signing, none of the admin's devices is verified;
- no device could take the room key (no one-time key to start an Olm session with);
- the room isn't encrypted (it always is, unless someone with power in it changed that).

Then a message or file goes out as one OpenPGP message to `OPENPGP_KEY` (v4, RSA or
Curve25519, SEIPD v1 with AES-256: what OpenKeychain on Android and iPGMail on iPhone read),
uploaded as a file in a plain event, with a notice at most once a day saying why. Without
`OPENPGP_KEY` messages wait in the outbox (alerts for `ALERT_MAX_HOURS`, files for
`OUTBOX_MAX_DAYS`), and the notice says that instead. Nothing goes to the homeserver in clear
but these notices, which name keys, never content. logguard warns the admins over its other
ways when copies wait longer than `bot_stuck_after`.

## How logguard and the bot meet

They share one directory, `/opt/logguard-matrix-bot/outbox` (root:logguard-matrix-bot 1770,
sticky), in logguard-xmpp-bot's file format (`src/outbox.rs`, logguard's `src/botbox.rs`):

1. logguard writes a copy of each message to the first of `[notify] admins` (every admin
   message when `admins` is empty or `xmpp = false`) as `alert-<time>-<n>.msg`, gives the
   file to `matrix_user`, and renames it into place.
2. The bot looks every 5 seconds, claims a message by renaming it to `.<name>.sending`, sends
   it and deletes it. If sending fails it renames it back and tries again (after the
   homeserver's `retry_after_ms`, or 30 s). A half-sent one is put back at the next start.
3. There is no plain-text fallback on logguard's side: copies wait until the bot sends them.
4. `logguard-abuse-report.sh` puts the weekly report into this outbox too when
   `[notify] matrix_outbox` (or `ABUSE_REPORT_MATRIX_OUTBOX`) is set. The bot looks every
   minute.

Check it as root: `logguard -c /etc/logguard/logguard.toml notify-test --matrix` puts a test in
the outbox and waits until the bot has sent it.

## Install from a release bundle

As for the other crates (see logguard-tg-bot's README, "Install from a release bundle"): the
tag is `logguard-matrix-bot-v<version>`, the zip `logguard-matrix-bot-<version>-<commit>-<arch>.zip`;
unzip it on the server and run `sudo ./install.sh`. The first install doesn't start the bot:
continue with step 3 below.

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `logguard-matrix-bot_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) and `logguard-matrix-bot-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"` or `"*.rpm*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once; neither needs dpkg or rpm, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). The package is for one host at a time: there is no apt or dnf repository.

```bash
sudo apt install ./logguard-matrix-bot_0.2.0-1_amd64.deb     # Fedora, RHEL:  sudo dnf install ./logguard-matrix-bot-0.2.0-1.x86_64.rpm
sudoedit /opt/logguard-matrix-bot/config.env                 # the first install put the template there
sudo systemctl enable --now logguard-matrix-bot
```

The package puts the same files in the same places as `install.sh` (`/opt/logguard-matrix-bot` with the binary and `config.env.example`, the user `logguard-matrix-bot`, `/var/log/logguard-matrix-bot`, the logrotate rule), except the unit, which is in `/usr/lib/systemd/system`. Its post-install step does what `install.sh` does apart from copying files: the user, `config.env` from the template the first time, the owners and modes, the outbox and the log directory; and it prints what is left to do ("Setup": the homeserver and accounts, your OpenPGP key, then `login` as the bot's user (the install prints the command)). `dpkg-reconfigure logguard-matrix-bot` (rpm: `dnf reinstall ./logguard-matrix-bot-*.rpm`) runs that step again, e.g. after copying a key there. `apt remove logguard-matrix-bot` (`dnf remove`) stops the bot and keeps `/opt/logguard-matrix-bot`; `apt purge logguard-matrix-bot` removes it with the state and keys (rpm: by hand).

**Nothing starts on its own.** The first install puts the template in place and prints what to fill in; you enable the service once it is filled in. An upgrade keeps the config and restarts the service only if it was running and the config is filled in. **Over a bundle or `deploy.sh` install** the package takes over: the config, state and keys stay; the bundle's unit in `/etc/systemd/system` (it would shadow the package's) and its rollback files go, and the service is enabled again on the package's unit if it was (logguard's integrity watch reports the removed unit as a warning once). **Replacing the config:** when a terminal is there, the install asks whether to replace the config with the new template (the old one kept with the suffix `.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `LOGGUARD_PACKAGE_CONFIG=replace` (or `keep`) answers without asking: `sudo LOGGUARD_PACKAGE_CONFIG=replace apt install ./<file>.deb`. **Rollback** is installing the previous version's package (`apt install ./<old>.deb --allow-downgrades`, `dnf downgrade ./<old>.rpm`): there is no `.prev` file.

## Setup

1. **An account for the bot** on a homeserver, made in any client (not your own account).
   Note its user id (`@logguard:example.org`) and password. Your own client should have
   cross-signing set up (current Element, Element X, FluffyChat do it by default) and your
   devices verified.
2. **Deploy** from the Mac (runs `scripts/ci.sh` first, builds the static binary):
   ```bash
   ./deploy/deploy.sh          # to the relay node "tg"; name another host as the argument
   ```
   The first install creates the user, `/opt/logguard-matrix-bot` and `config.env`.
3. **Fill in `config.env`** as root: `MATRIX_HOMESERVER`, `MATRIX_USER`, `ADMIN`, and your
   OpenPGP public key as `OPENPGP_KEY` (`/opt/logguard-matrix-bot/admin.asc`, root:logguard-matrix-bot
   640), then log the bot in, as its own user (it asks for the password, which it doesn't keep):
   ```bash
   runuser -u logguard-matrix-bot -- sh -c 'set -a; . /opt/logguard-matrix-bot/config.env; exec /opt/logguard-matrix-bot/logguard-matrix-bot login'
   ```
   It prints the bot's device and keys (`logguard-matrix-bot info` again later). If the
   account already has cross-signing keys from another client, `login --reset-cross-signing`
   replaces them; a homeserver behind Matrix Authentication Service then asks you to approve
   the reset in the account's web page (the bot prints the link). Run `bash install.sh` again
   (or `systemctl enable --now logguard-matrix-bot`).
4. **Accept the invitation** in your client. The first message pins your master key; check
   it in the bot's log (`pinned ... master cross-signing key`) against your client's, or set
   `ADMIN_MASTER_KEY` before the first message.
5. **Tell logguard**, in `[notify]` of `/etc/logguard/logguard.toml` (deploy a logguard that
   knows the key first):
   ```toml
   matrix_outbox = "/opt/logguard-matrix-bot/outbox"
   matrix_user = "logguard-matrix-bot"
   ```
   then `systemctl restart logguard` and `logguard ... notify-test --matrix`. Adding
   `logguard-matrix-bot.service` to logguard's `[sources] services` gets an alert when it fails.

`install.sh rollback` goes back to the previous binary and unit. The host needs outgoing HTTPS
to the homeserver; the homeserver sees the host's address.

## Settings

All in `config.env` (`deploy/config.env.example` has each with a comment; `--help` lists the
matching flags):

| Variable | Default | |
|---|---|---|
| `MATRIX_HOMESERVER` | | the client URL, https (http only to localhost) |
| `MATRIX_USER` | | the bot's account, for `login` |
| `ADMIN` | | your user id: the only one the bot writes to |
| `ADMIN_MASTER_KEY` | (pinned on first sight) | your master cross-signing key |
| `E2EE` | yes | no: everything as OpenPGP files |
| `OPENPGP_KEY` | | your OpenPGP public key, for the fallback; without it messages wait |
| `SANITIZE` | no | yes: pseudonyms and node ids in alerts (`XMPP_DOMAINS`, `SERVER_NAMES`, `PSEUDONYM_KEY`) |
| `ALERT_MAX_HOURS` | 24 | older alerts are dropped unsent |
| `OUTBOX_MAX_DAYS` | 7 | older files are deleted unsent |
| `BOT_STATE_PATH` | `/opt/logguard-matrix-bot/state.json` | |
| `OUTBOX_DIR` | `outbox` next to the state | |
| `LOG_DIR` | `/var/log/logguard-matrix-bot` | `bot.log`, 14 days |

Exit status 78 (a setting is wrong, no login yet, or the homeserver no longer knows the
login: a device deleted in a client, a password change that logged out every device) is not
restarted by the unit: run `login` again, then start it.

## Retention and what the bot keeps

- **On the homeserver:** the room's events (encrypted) and uploads (encrypted) stay as long
  as the homeserver keeps them; delete the room in your client to drop them for you.
- **On the server:** `bot.log` (14 days), `state.json` (login token, device keys, Olm and
  Megolm sessions, the bot's self-signing key, your pinned keys: no message text), with
  `SANITIZE` the pseudonym key, and outbox files until they are sent or expire. Whoever reads
  `state.json` (root) could read what the bot sends while the current Megolm session lasts.

| Path | Owner | Mode |
|---|---|---|
| `/opt/logguard-matrix-bot/` | root:logguard-matrix-bot | 1770 (sticky) |
| `config.env`, `OPENPGP_KEY` | root:logguard-matrix-bot | 640 |
| `state.json`, `pseudonym.key` | logguard-matrix-bot | 600 |
| `outbox/` | root:logguard-matrix-bot | 1770; files logguard-matrix-bot 600 |
| `/var/log/logguard-matrix-bot/`, `bot.log` | logguard-matrix-bot | 700, 600 |

The unit drops every capability, makes the file system read-only except its two directories,
allows only IPv4 and IPv6 sockets, and denies writable-executable memory.

## Why not matrix-sdk

matrix-rust-sdk's crypto needs a persistent store, and its only native one is SQLite (C code),
which would end the static musl build from macOS without a C cross toolchain; it would also
bring a sync loop and room state the bot doesn't need. The bot uses the same audited Olm and
Megolm (vodozemac) and does the few steps of a send-only device itself (`src/api.rs`, `crypto.rs`, `bot.rs`, `login.rs`: under 2000 lines with their tests).

## Build and test

```bash
./scripts/ci.sh            # fmt, clippy, tests, cargo audit, static Linux binary
```

The static build needs `rustup target add x86_64-unknown-linux-musl` (or the ARM targets) and
`rustup component add llvm-tools`, as the other crates. `tests/fake_homeserver.rs` runs the
bot against a fake homeserver on 127.0.0.1 whose admin devices are vodozemac accounts of their
own: `login` (device keys that verify, cross-signing keys, the device signed by them, the
password step when the homeserver asks), the room made encrypted with the admin invited, an
alert and the report that decrypt on the verified phone and not on the unverified laptop
(nothing of them in any request), a newly verified device getting the current key, a removed
one forcing a new session, rate limiting, a changed master key giving OpenPGP files that the
admin's key opens (and `ADMIN_MASTER_KEY` bringing end-to-end back), messages that wait without
any route, `E2EE=no`, an admin without cross-signing, a device id with new keys left out, a
second `login` keeping the room and pins, a wrong password leaving the working device alone,
and a revoked token stopping the bot.

**Not yet tried against a real homeserver or client.** The formats follow the spec and what
the fake checks; whether Element and Element X decrypt and show the messages without
warnings is still to be seen.

**Fuzzing.** `fuzz/` has cargo-fuzz targets (code in `src/fuzzing.rs`): `keys_query` (the
homeserver's key replies: only self-signed devices come out, cross-signed ones only under a
master key), `alert_file` (outbox files), `attachment` (encrypt and decrypt, damage caught).
Under cargo-fuzz vodozemac accepts every signature (its `fuzzing` cfg), so the targets reach
past the checks; the signature checks themselves are in `src/crypto.rs`'s tests.
`tests/fuzz_smoke.rs` runs the targets on stable over realistic inputs, `fuzz/seeds/` and
thousands of mutations (`LOGGUARD_MATRIX_BOT_WRITE_SEEDS=1` regenerates the seeds).

```bash
cargo +nightly fuzz run keys_query fuzz/corpus/keys_query fuzz/seeds/keys_query -- -max_total_time=600
```
