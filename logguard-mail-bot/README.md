# logguard-mail-bot

A send-only mail bot for [logguard](../logguard/README.md): it mails logguard's admin alerts,
the daily digest and the weekly abuse report to the admins, each mail **OpenPGP-encrypted as
a whole**, subject included. It goes out through a mail server over SMTP: the local Postfix,
or any other server with TLS. It reads no mail and takes no orders; the servers stay managed
over SSH.

It is the third copy bot next to logguard-xmpp-bot (OMEMO) and logguard-tg-bot (Telegram), and
works like logguard-tg-bot: logguard puts a copy of every admin message in its outbox, the bot
sends it and deletes it. It can run on any logguard node, alone or next to the other bots, or
on a relay node of its own (as logguard-tg-bot does, `deploy/logguard-tg.toml` in logguard).

## What a mail looks like

Every mail is PGP/MIME (RFC 3156): `multipart/encrypted`, one OpenPGP message holding the
whole content. Mail servers on the way, and the mailbox provider, see only:

- the envelope and the outer headers: `From`, `To`, `Date`, `Message-ID` (random), the size,
  and the subject `...` (`OUTER_SUBJECT`);
- `Auto-Submitted: auto-generated` (no auto-replies), and, if the bot signs, an `Autocrypt`
  header with the bot's public key.

Inside, encrypted: the real subject (`[vpn] logguard: password guessing blocked`) and the
headers again as "protected headers" (`protected-headers="v1"`), which Thunderbird, K-9 /
Thunderbird for Android, FairEmail and Delta Chat show in place of `...`, then the text,
quoted-printable (any line length, any character). Text from attackers in alerts (user names
they tried, URIs) never reaches a header unencoded and can't start a MIME part.

- **Alerts and the digest**: one mail each, the message's text as the mail's text.
- **The weekly abuse report**: the report as the mail's text (it is text). A file that isn't
  UTF-8 text would be attached instead.

The OpenPGP format is the one every client reads: v4 keys (RSA, or Ed25519/Curve25519), a v3
PKESK per recipient key, SEIPD v1 with MDC under AES-256, no compression (not AEAD / v6, which
many clients can't read yet). `tests/gpg_interop.rs` has GnuPG decrypt the mails and check the
signature, for RSA and Curve25519 keys.

## Keys

- **`OPENPGP_KEY`** (required): the recipients' public keys, in one file (armored or binary,
  one or more keys). Each address in `MAIL_TO` gets the key whose user id names it; with a single
  key, that key serves every address (logged as a warning when the user id differs). An address
  without a key stops the bot at the start (exit 78): nothing goes out in clear. A key that has
  expired, at the start or later: that recipient gets nothing (logged every 10 minutes) until
  the key is replaced; with no usable key at all the bot doesn't start, and when the last one
  expires while it runs, messages wait and logguard warns about them after `bot_stuck_after`.
  Only the key's own signatures count: certifications by others (`gpg --sign-key`, web of
  trust) are ignored, not taken for broken self-signatures.
- **`SIGNING_KEY`** (optional): the bot's own key, made once with `logguard-mail-bot keygen`
  (Ed25519, no passphrase: it would sit next to the key anyway). Every mail is then signed, and
  the public key goes out in the `Autocrypt` header (autocrypt.org Level 1), so clients that read
  it (Thunderbird, K-9/FairEmail, Delta Chat) learn it from the first mail and show the signature
  as valid. Others: import `signing.key.pub.asc`. The key proves a mail comes from the bot; it
  can't read anything.

Only public keys of the recipients are on the server: whoever gets into it can't read mails
already sent.

## Sanitizing (optional)

The mails are encrypted end to end, so by default alerts and digests go out as they are, with
XMPP account names and the servers' own addresses. `SANITIZE=on` replaces them exactly as
logguard-tg-bot does for Telegram (the same code, `src/redact.rs` and `src/servers.rs`):

- every XMPP address (`alice@example.org`, `ejabberd:alice`) becomes a pseudonym
  `[acct:1a2b3c]`, an HMAC under `PSEUDONYM_KEY` (made on the first start, the bot's, 600);
  `logguard-mail-bot pseudonym alice@example.org` on the server tells which is which;
- the servers' own addresses and host names in `SERVER_NAMES` become their node ids
  (`nextcloud.example.org:443` → `nextcloud.xmpp:443`); attackers' addresses stay.

The weekly abuse report is never changed (as on Telegram). The Telegram bot sanitizes always.

## The mail server

| | `SMTP_TLS` | port | login |
|---|---|---|---|
| the local Postfix | `none` (only allowed to 127.0.0.1, ::1, localhost) | 25 | usually `SMTP_AUTH=none` |
| a provider or another server | `tls` (TLS from the start) or `starttls` (required: never falls back to plain) | 465 / 587 | `SMTP_AUTH=auto` (PLAIN or LOGIN, whichever is offered), `plain`, `login` |

The server's certificate is checked against the system's CAs (`/etc/ssl/certs`) and
`SMTP_TLS_NAME` (default: `SMTP_HOST`), or only against `SMTP_CA_FILE` (a server with a
certificate of its own CA). A login is never sent over plain SMTP to another host: that
setting is refused. The password goes in `SMTP_PASSWORD_FILE` (root:logguard-mail-bot 640).

What the server says decides what happens:

- **Out of reach, 4xx, TLS failing:** the message waits; the bot tries again after 30 s,
  doubling up to 30 minutes. Alerts older than `ALERT_MAX_HOURS` (24) are dropped and counted
  in one mail; files after `OUTBOX_MAX_DAYS` (7).
- **5xx for one mail** (too large, rejected as spam): the bot sends a short note in its place
  saying what was refused and where to find it (logguard's actions log, or how to make the
  report again). If the note goes through, the refused mail is dropped.
- **5xx for every mail** (the sender or a recipient refused): the note fails too, the message
  waits, and the bot tries every 30 minutes.
- **A refused login** (530, 534, 535, 538): no note is tried (it would be one more failed
  login towards the server's ban); the message waits, retried every 30 minutes. At the start
  it stops the bot with exit 78, which systemd doesn't restart.
- **No STARTTLS offered** where `SMTP_TLS=starttls`: nothing is sent, not even the login, and
  the bot keeps retrying with backoff rather than giving up for good (someone in the way may be
  stripping it, and must not be able to stop the bot).

The bot opens one connection per mail (a few a day).

## How logguard and the bot meet

The outbox (`/opt/logguard-mail-bot/outbox`, root:logguard-mail-bot 1770, sticky) has the format
of the other bots: `alert-*.msg` with `To:` and `Subject:` lines, a blank line and the text,
written under a dot name and renamed into place, owned by the bot's user. The bot claims one by
renaming it to `.<name>.sending`, sends it, deletes it; if sending fails it renames it back
(and on the next start it puts back what a stop left half-sent). The weekly report is any
other regular file. logguard (`[notify] mail_outbox`, `mail_user`) puts a copy of every
message for the first admin there (every admin message on a node with `xmpp = false` or no
`admins`), and the abuse report job puts the report there. logguard warns the admins (over
XMPP and to the Telegram bot, else as a system alert) when the bot leaves something unsent
longer than `bot_stuck_after`.

## Install from a release bundle

Instead of `deploy.sh` (below), without a Rust toolchain: every version tag `logguard-mail-bot-v<version>` gets its bundle, `logguard-mail-bot-<version>-<commit>-x86_64-linux-musl.zip`, as an asset of the tag's GitHub Release (see "Releases" in the [repository README](../README.md#deployment)); CI also keeps one for every commit as a workflow artifact (they expire and need a GitHub login), and `scripts/bundle.sh` builds it locally. It holds the static binary, the unit, `config.env.example`, `SHA256SUMS` and `install.sh`.

**Download and verify** (on your machine, then copy the zip over, or on the server): take the zip from the GitHub Release of the version's tag, with the [GitHub CLI](https://cli.github.com/) or from the Release's page:

```bash
gh release download logguard-mail-bot-v0.2.0 --repo OWNER/REPO    # the zip, its .sha256 and .sigstore.json
sha256sum -c logguard-mail-bot-*.zip.sha256                         # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify logguard-mail-bot-*.zip --repo OWNER/REPO --source-ref refs/tags/logguard-mail-bot-v0.2.0
```

`gh attestation verify` (after `gh auth login`) checks the signed build provenance: that this repository's CI built exactly this zip from that tag. With `--bundle logguard-mail-bot-*.zip.sigstore.json` it checks the attestation attached to the Release instead of fetching it from GitHub. Only a public repository's releases have one (GitHub offers attestations for private repositories only with Enterprise Cloud).

On the server (`apt install unzip` if needed):

```bash
unzip logguard-mail-bot-*-x86_64-linux-musl.zip && cd logguard-mail-bot-*-x86_64-linux-musl
sudo ./install.sh          # install or upgrade; the first time also /opt/logguard-mail-bot/config.env
sudo ./install.sh rollback # back to the previous version
```

The first install, as with `deploy.sh`, doesn't start the bot until `config.env` is filled in (then run it again). `install.sh` checks every file against `SHA256SUMS` in a copy only root can write, then runs the same installer as `deploy.sh` (`./install.sh --check` only checks the files).

## Setup

On your Mac:

```bash
./deploy/deploy.sh vpn
```

It runs `scripts/ci.sh`, builds the static binary, copies it with the unit and `install.sh`
to the server and prints the command to paste into a root shell there. The first install
creates the user `logguard-mail-bot`, `/opt/logguard-mail-bot/config.env` from
`config.env.example`, and doesn't start the bot until it's filled in. Then, as root:

1. Fill in `config.env`: `MAIL_FROM`, `MAIL_TO`, the mail server.
2. Copy the recipients' public keys to `/opt/logguard-mail-bot/recipients.asc` (Thunderbird:
   Account settings → End-to-end encryption → OpenPGP Key Manager → File → Export; or
   `gpg --armor --export you@example.org`), and the SMTP password to `smtp-password`.
3. Optionally, the signing key:
   `set -a; . /opt/logguard-mail-bot/config.env; set +a; /opt/logguard-mail-bot/logguard-mail-bot keygen --out /opt/logguard-mail-bot/signing.key`
   and `SIGNING_KEY=/opt/logguard-mail-bot/signing.key` in config.env.
4. `bash /opt/logguard-mail-bot/install.sh` again (it sets owners and modes of the keys and files), then:

```bash
set -a; . /opt/logguard-mail-bot/config.env; set +a
/opt/logguard-mail-bot/logguard-mail-bot check        # connects, logs in, sends nothing
/opt/logguard-mail-bot/logguard-mail-bot send-test    # one test mail
systemctl enable --now logguard-mail-bot
```

5. In `[notify]` of `/etc/logguard/logguard.toml`: `mail_outbox = "/opt/logguard-mail-bot/outbox"`
   and `mail_user = "logguard-mail-bot"`, restart logguard, and
   `logguard -c /etc/logguard/logguard.toml notify-test --mail`.

For SPF/DKIM, `MAIL_FROM` should be an address the mail server may send as; otherwise the
mails may land in spam. `install.sh rollback` goes back to the previous binary and unit.

## Settings

Every option is also an environment variable (config.env is the unit's `EnvironmentFile`);
`logguard-mail-bot --help` lists them with their defaults. `deploy/config.env.example` explains
each one.

## Retention and what the bot keeps

- Outbox files until they are sent (alerts 24 h at most, files 7 days).
- Its log, `/var/log/logguard-mail-bot/bot.log` (owner only): what was sent to whom, and the
  mail server's answers; rotated weekly, no line older than 14 days. No message text.
- Nothing else: no state file. With `SANITIZE=on`, the pseudonym key. The service makes it on
  its first start; the one-off commands (`check`, `send-test`, `pseudonym`), run as root, never
  do, so it stays the bot's.

## Build and test

```bash
./scripts/ci.sh
```

Format, clippy, the tests, `cargo audit`, and the static `x86_64-unknown-linux-musl` binary.
`tests/fake_smtp.rs` runs the bot against a fake mail server on 127.0.0.1 (plain, STARTTLS and
TLS with a test CA, PLAIN and LOGIN, a server that strips STARTTLS, refusals) and runs the
binary as systemd would; it needs to bind 127.0.0.1. `tests/gpg_interop.rs` needs `gpg`
(skips without it). SMTP is `lettre` (blocking, rustls with ring: no OpenSSL), OpenPGP is
rpgp, both pure Rust.

**Fuzzing.** What comes from outside (logguard's outbox files with attackers' log text in
them, other files there, the recipients' key file, the signing key) goes through four
cargo-fuzz targets (code in `src/fuzzing.rs`). Besides no panics, each checks the promises
with rules of its own:
- `alert_mail`: an outbox file to the finished mail, with `SANITIZE` off and on. The mail is
  all ASCII with CRLF line ends and lines under 998 characters; it has exactly the bot's own
  outer headers (subject `...`) and, between the boundaries, only the version part and the
  armored message. Decrypted, it has the fixed protected headers, the subject on one line, and
  the text back unchanged; with `SANITIZE=on`, no account address and no server address or
  host name of the fuzzed setup is left.
- `file_mail`: a file (`name`, NUL, content): text as the mail's text, anything else attached
  under a safe name, back byte for byte.
- `openpgp_keys`: the key file; whatever is taken must encrypt to every usable address.
- `signing_key`: whatever is taken signs mails that verify, in a well-formed Autocrypt header.

`tests/fuzz_smoke.rs` runs them on stable on realistic inputs, the seeds in `fuzz/seeds/` and a
few thousand mutations, so `cargo test` keeps them working; a failing input is saved as
`target/fuzz-smoke-<target>.bin` (`LOGGUARD_MAIL_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke`
regenerates the seeds; the keys in them, the signing key's secret part too, are throwaway).
The real search needs nightly:

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked   # once
cargo +nightly fuzz run alert_mail fuzz/corpus/alert_mail fuzz/seeds/alert_mail -- -dict=fuzz/alert_mail.dict -max_len=8192 -max_total_time=600
```

New inputs collect in `fuzz/corpus/`, crashes in `fuzz/artifacts/` (both git-ignored). The
`regression-*` seeds are inputs the first runs (2026-10-17) failed on, all fixed: a subject
holding `=?utf-8?b?…?=` went into the header as it was, so mail clients would have shown it
decoded, as other text (now encoded); a damaged signing key whose secret part no longer
matched its public part was taken, and every mail would have carried a bad signature (now
refused at the start); with `SANITIZE=on`, a server address replaced by its node id completed
an address (`admin@::ffff:192.0.2.10` → `admin@xmpp`; fixed in logguard-tg-bot too). One was the
oracle's: a pseudonym cut by the 200-character subject limit.

**Tested on a server (2026-10-20):** a Debian VPS deployed with `deploy.sh`, the unit running.
`check`, `send-test`, logguard's `notify-test --mail` (picked up from the outbox and sent
within seconds) and a digest (`digest --send`) through a provider (`SMTP_TLS=tls`, port 465, LOGIN) to a SimpleLogin alias
forwarding to Proton Mail; GnuPG on a Mac decrypts the mails and shows the bot's signature as
good. Proton re-armors the encrypted part and exports it quoted-printable with
CRLF line ends, which turns every `=` in the armor (the base64 padding and the checksum line)
into `=3D` and makes gpg report a CRC error or a malformed CRC. Undo that before decrypting a
mail exported from Proton (only there: base64 itself never holds `=3D`, apart from a checksum
that happens to start with `3D`):

```bash
sed 's/=3D/=/g' mail.eml | gpg --decrypt
```

**Not yet verified:** opening the mails in Thunderbird, K-9 or FairEmail.
