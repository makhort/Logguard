# logguard-tg-bot

A Telegram bot that brings logguard's admin messages to the admin's Telegram chat: the
alerts, the daily digest (both servers'; the VPN server's arrive through the cluster) and
the weekly abuse report. It does for Telegram what `logguard-xmpp-bot` does for XMPP on logguard's side,
through the same kind of outbox, and nothing else:

- **No link to ejabberd.** No ejabberdctl, no database, no XMPP login. It runs as its own
  user `logguard-tg-bot`, which isn't in the `ejabberd` group and can't read ejabberd's files.
- **No XMPP account data, and no server addresses, on Telegram.** Telegram's servers can
  read everything a bot sends (bots get no end-to-end encryption). So in alerts and digests
  account names become pseudonyms and the servers appear only by their node ids (below), and
  the abuse report goes only as a file encrypted to the admin's OpenPGP key. logguard-xmpp-bot's user commands (`/invite`, `/devices`,
  `/export`, ...) and admin commands (`/list`, `/sessions`, ...) are not here.
- **No orders for the servers.** Its commands only show its own state; the servers are
  managed over SSH.

Both bots can run side by side. logguard feeds logguard-tg-bot only when `[notify] tg_outbox` is set.
Without it, nothing changes.

**Where it runs.** On a small VPS of its own that joins the logguard cluster (the *Telegram
relay node*, logguard's `deploy/logguard-tg.toml`), so the XMPP server never connects to
Telegram: the XMPP and VPN nodes relay their admin messages to it over the encrypted cluster
link, and may limit what it hands them to notices (it can't ban or allowlist anything there).
logguard's README, "A Telegram relay node", has the cluster side. It can also run on the XMPP
server itself: then that server talks to Telegram.

## What it sends

| From logguard | In Telegram |
|---|---|
| an alert or the digest (`alert-*.msg` in the outbox) | a message, account names and server addresses replaced: the subject (server and topic) in bold, the text as a monospace block; long ones split into several messages |
| the weekly abuse report (`abuse-report-<date>.txt`), or any other file | `report-<date>.txt.pgp`: the whole file encrypted to `OPENPGP_KEY`, with a fixed caption that says nothing about it. Without a key, files aren't sent |
| alerts older than `ALERT_MAX_HOURS` (24) when the bot gets to them | dropped, and one message says how many |
| an alert Telegram refuses (400 Bad Request) | sent again without formatting; refused again, dropped with a note, so it can't hold up the alerts after it |

Commands, from the admin only: `/status` (uptime, what was sent, what waits in the outbox,
the last error), `/privacy` (what goes through Telegram and what the bot keeps), `/help`.
The bot sets them as its command menu in the admin's chat only. Messages from anyone else
get no answer, and a group or channel someone adds the bot to, it leaves. The log only counts
them, with the latest sender's numeric id, at most every 10 minutes.

## Account names become pseudonyms

logguard's admin alerts name XMPP accounts (`account alice@example.org registered from …`,
`ejabberd:alice@… under distributed attack`, ejabberd log lines as evidence). logguard-tg-bot replaces
each with `[acct:1a2b3c]`: the first 24 bits of an HMAC-SHA-256 of the bare address (lower
case, resource dropped) under `pseudonym.key`, a random key made on the first start. It never
leaves the server.

- The same account always gets the same pseudonym, so repeated attacks on one account still show.
- Without the key, nobody can tell which account it is, Telegram included. A plain hash would
  not do: account names are few and easy to guess.
- On the server, `logguard-tg-bot pseudonym alice@example.org` prints an account's pseudonym (as root
  or `logguard-tg-bot`, with the same `PSEUDONYM_KEY`).
- **Every address-like `local@domain` in an alert is replaced** (with its `/resource`), and so is
  `ejabberd:<name>` (a bare user name counts as on the first of `XMPP_DOMAINS`). Alerts never
  need an e-mail address.
- **A name is everything back to a blank** or a character XMPP forbids in account names
  (`"&'/:<>@`). Account names may contain `( ) [ ] { } , ; = |`, so `bob(1)@example.org`
  and `a,b@…` are hidden whole; brackets in front stay outside (`(alice@…)` and `alice@…` get
  the same pseudonym). Matching too much only hides more.
- Files are not touched: they go out encrypted as a whole (below).

## The servers appear by their node ids

`SERVER_NAMES` lists each server's own addresses and host names under its node id (logguard's
`[cluster] node_id`): `xmpp=11.17.39.236,example.org; vpn=11.25.48.86; tg=203.0.113.10`.
In alerts and digests, after the account names:

- an address becomes the node id: `cluster peer 11.25.48.86:7946 failing` → `cluster peer
  vpn:7946 failing`. IPv4 matches as any run of digits and dots, wherever it is (`dead:…`,
  `::ffff:…:7946`); IPv6 as a run of hex digits and colons that is the address (brackets and
  IPv4-mapped too), or, when the run is no valid address, starts with it before a colon
  (`…: refused`, a port). A run that is another valid address stays: attackers' addresses,
  also `2001:db8::7:5` next to a server's `2001:db8::7`;
- a host name becomes the node id, subdomains keeping their first labels:
  `example.org:5223` → `xmpp:5223`, `nextcloud.example.org:443` → `nextcloud.xmpp:443`.
  `notexample.org` and `example.org.example.net` are left alone.

List every public IPv4 and IPv6 address of each server. Loopback and unspecified addresses
(`127.0.0.1`, `::`, `0.0.0.0`) are refused: they are no server's address and appear in many
lines. A node id needs a letter other than a to f (`xmpp`, `vpn`, `tg`, `node1`): one of hex
digits only would join the colons and digits around it into a new address. Without `SERVER_NAMES` the bot warns
at startup and sends the names as they are. The subjects say which server already (`[xmpp]`).

What does go to Telegram: attackers' addresses, ports, countries and networks; ban decisions;
the servers' state (exposure, certificates, cluster) under their node ids; sanitized log lines
with account names and server names replaced. A "suspicious login" alert also carries the
login's address. That is the point of the alert, but if it was the account owner, it is their
address.

## Files go out encrypted, as a whole

The weekly abuse report (or any file logguard puts in the outbox) is sent only as one
OpenPGP message encrypted to the admin's public key (`OPENPGP_KEY`), never in clear, not even
in part: the caption is a fixed line saying how to open it, the name is
`report-<date>.<ext>.pgp`. Telegram sees a file of some size, and that it is OpenPGP.

- **Apps.** Android: [OpenKeychain](https://www.openkeychain.org) (F-Droid, Google Play; in
  maintenance mode, still working). iPhone: [iPGMail](https://apps.apple.com/app/ipgmail/id430780873)
  (paid, updated in 2026). In Telegram, open the file's menu → Share (or Save to Files) → the app;
  it asks for the key's passphrase and shows or saves `report-<date>.txt`.
- **The key.** Create it in that app (on the phone, so the secret key never leaves it), or
  use one you have. A v4 key with an RSA (3072 or 4096 bits) or Curve25519 encryption subkey
  works everywhere; RSA is the safe choice if you switch between Android and iPhone apps.
  Export the **public** key as a file (both apps can share or export it from the key's
  page), copy it to the server and install it as root:
  `install -o root -g logguard-tg-bot -m 640 admin.asc /opt/logguard-tg-bot/admin.asc`, then restart the bot. Its
  log (and `/status`) shows the fingerprint: compare it with the one the app shows.
- **The format.** What these apps and GnuPG read: a v3 PKESK packet for each encryption subkey,
  a SEIPD v1 packet (with MDC) under AES-256, no compression, no file name inside (RFC 9580
  advises none). Not SEIPD v2 / AEAD or v6 keys: OpenKeychain can't read them. The bot uses
  [rPGP](https://github.com/rpgp/rpgp) (pure Rust, MIT/Apache). `tests/gpg_interop.rs`
  checks every file decrypts with GnuPG, for RSA-4096 and Curve25519 keys made by `gpg`.
- **Checks at startup.** The key must parse, its self-signatures verify, and it must be a v4
  key, not revoked or expired, with an encryption subkey of those kinds that was never revoked.
  Signatures by other keys (`gpg --sign-key`, web of trust) are ignored, not taken for broken
  self-signatures (until 2026-10-17 they stopped the bot).
  Otherwise the bot stops (exit 78) instead of running without a key. Without `OPENPGP_KEY` it
  runs, and files wait, unsent, until they expire after `OUTBOX_MAX_DAYS`.
- **And at every file.** A key (or subkey) that expires while the bot runs is no longer used:
  files wait, `/status` says why, and the chat gets a note at most once a day.
- A file Telegram refuses for good (400 Bad Request, 413 too large) is dropped with a note in
  the chat.
- Only the public key is on the server: whoever gets into it can't read reports sent before.
  The report itself still names the servers' addresses, for the abuse desks; that stays inside
  the encryption.

Deleting a key gives every account a new pseudonym; old messages then no longer match.

## How logguard and the bot meet

They share one directory, `/opt/logguard-tg-bot/outbox` (root:logguard-tg-bot 1770, sticky), and logguard-xmpp-bot's file
format (see `src/outbox.rs` and logguard's `src/botbox.rs`):

1. logguard's notifier writes a copy of each message to the first of `[notify] admins` (on
   the relay node, `[notify] xmpp = false`, or with `admins` empty: every admin message, its
   own and the relayed ones, and then only here) as `alert-<time>-<n>.msg` (`To:` and `Subject:` lines, a blank line, the text). It writes under
   a dot name first, gives the file to `tg_user`, and renames it into place. This copy is in
   addition to the XMPP way, which is unchanged.
2. The bot looks every 5 seconds. It claims a message by renaming it to `.<name>.sending`,
   sends it and deletes it. If sending fails, it renames the file back and tries again (after
   Telegram's `retry_after`, or after 30 s). A message left in `.sending` by a stop is put
   back at the next start. Messages over 1 MB (logguard's are a few KB) are deleted unread. At
   startup the bot checks it can write the outbox (an `OUTBOX_DIR` outside the unit's
   `ReadWritePaths` can't be), and says so in its log if not.
3. Unlike the XMPP bot's outbox, logguard takes nothing back: there is no plain-text fallback
   for a copy. When copies wait longer than `bot_stuck_after` (1h), also ones a bot that died
   left half-sent (`.sending`), logguard warns the admins
   the XMPP way, at most once per hour (with no XMPP admins: as a system alert in its journal,
   relayed to peers with `relay_notices`).
4. `logguard-abuse-report.sh` (`merge` role: on the XMPP server, or any server with logguard-tg-bot)
   puts the weekly report into every outbox it knows: logguard-xmpp-bot's, and logguard-tg-bot's when logguard's
   `[notify] tg_outbox` (or `ABUSE_REPORT_TG_OUTBOX`) is set. On the relay node (role `relay`)
   it waits for the report the XMPP server merged and forwarded (`ABUSE_REPORT_FORWARD_TO`
   there) and puts that in logguard-tg-bot's outbox; if none comes, it merges itself. The bot
   looks every minute, sends the report encrypted and deletes it. A report not sent
   within `OUTBOX_MAX_DAYS` (7) is deleted unsent.

Check it as root: `logguard -c /etc/logguard/logguard.toml notify-test --telegram` puts a test
in the outbox and waits until logguard-tg-bot has sent it.

## Install from a release bundle

Instead of `deploy.sh` (step 2 below), without a Rust toolchain: every version tag `logguard-tg-bot-v<version>` gets its bundle, `logguard-tg-bot-<version>-<commit>-x86_64-linux-musl.zip`, as an asset of the tag's GitHub Release (see "Releases" in the [repository README](../README.md#deployment)); CI also keeps one for every commit as a workflow artifact (they expire and need a GitHub login), and `scripts/bundle.sh` builds it locally. It holds the static binary, the unit, `config.env.example`, `SHA256SUMS` and `install.sh`.

**Download and verify** (on your machine, then copy the zip over, or on the server): take the zip from the GitHub Release of the version's tag, with the [GitHub CLI](https://cli.github.com/) or from the Release's page:

```bash
gh release download logguard-tg-bot-v0.1.0 --repo OWNER/REPO    # the zip, its .sha256 and .sigstore.json
sha256sum -c logguard-tg-bot-*.zip.sha256                         # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify logguard-tg-bot-*.zip --repo OWNER/REPO --source-ref refs/tags/logguard-tg-bot-v0.1.0
```

`gh attestation verify` (after `gh auth login`) checks the signed build provenance: that this repository's CI built exactly this zip from that tag. With `--bundle logguard-tg-bot-*.zip.sigstore.json` it checks the attestation attached to the Release instead of fetching it from GitHub. Only a public repository's releases have one (GitHub offers attestations for private repositories only with Enterprise Cloud).

On the server (`apt install unzip` if needed):

```bash
unzip logguard-tg-bot-*-x86_64-linux-musl.zip && cd logguard-tg-bot-*-x86_64-linux-musl
sudo ./install.sh          # install or upgrade; the first time also /opt/logguard-tg-bot/config.env
sudo ./install.sh rollback # back to the previous version
```

The first install, as with `deploy.sh`, doesn't start the bot while the token and admin id are placeholders: continue with step 3. `install.sh` checks every file against `SHA256SUMS` in a copy only root can write, then runs the same installer as `deploy.sh` (`./install.sh --check` only checks the files).

## Setup

1. **Create the bot** with [@BotFather](https://t.me/BotFather): `/newbot`, then
   `/setjoingroups` → Disable (it serves one private chat). Keep the token secret.
2. **Deploy** from the Mac (builds a static Linux binary, runs `scripts/ci.sh` first), to the
   relay node: first logguard (`../logguard/deploy/deploy.sh tg deploy/logguard-tg.toml`, after
   setting the peers and `peer_accept` on the other nodes), then the bot:
   ```bash
   ./deploy/deploy.sh          # copies to tg:/tmp/logguard-tg-bot-deploy, prints the root command ("xmpp" as argument for the XMPP server)
   ```
   The first install creates the `logguard-tg-bot` user, `/opt/logguard-tg-bot` and `config.env` (from
   `deploy/config.env.example`, every option with a reasonable value). It doesn't start the
   bot while the token and admin id are placeholders.
3. **Fill in `config.env`** as root: put the token in `TELEGRAM_TOKEN`. Then find your user id:
   ```bash
   set -a; . /opt/logguard-tg-bot/config.env; set +a; /opt/logguard-tg-bot/logguard-tg-bot pair
   ```
   It prints a link and a code. Open the link (or send `/start <code>` to the bot) from your
   Telegram account, and it prints `ADMIN_CHAT_ID=…`. Put that in `config.env`, check
   `SERVER_NAMES`, install your OpenPGP public key as `OPENPGP_KEY` (above), then
   `systemctl enable --now logguard-tg-bot` (or run `install.sh` again). `pair` reads the bot's updates
   itself, so the service must be stopped meanwhile.
4. **Tell logguard** (optional, off by default; `logguard-tg.toml` has it already). In
   `[notify]` of `/etc/logguard/logguard.toml` (a logguard with `tg_outbox` support must be
   deployed first: older ones reject the key):
   ```toml
   tg_outbox = "/opt/logguard-tg-bot/outbox"
   tg_user = "logguard-tg-bot"
   ```
   The weekly abuse report job reads `tg_outbox` from there too. On a server with ejabberd,
   leaving `admins` empty sends admin messages to Telegram only (users are still warned over
   XMPP). For a relay node, in `/etc/default/logguard-abuse-report`:
   `ABUSE_REPORT_SEND_TO=<xmpp>:7946` there, and on the XMPP server
   `ABUSE_REPORT_PEERS="vpn tg"` and `ABUSE_REPORT_FORWARD_TO=<tg>:7946`.
   Then `systemctl restart logguard` and run the `notify-test --telegram` check above. Adding
   `logguard-tg-bot.service` to logguard's `[sources] services` gets an alert when the bot fails.

`install.sh rollback` goes back to the previous binary and unit (kept while the running
version runs cleanly).

**Renamed from `tgbot` (2026-10-17).** The bot was `tgbot`, installed as `/opt/tgbot/tgbot`,
run by `tgbot.service` as the user `tgbot`, logging to `/var/log/tgbot`. The first
`install.sh` of the new name moves an old install over on its own, before installing:

- stops and disables `tgbot.service`, removes it and `/etc/logrotate.d/tgbot` (local changes
  in `tgbot.service.d/` move to `logguard-tg-bot.service.d/`);
- renames the user and group `tgbot` to `logguard-tg-bot` (same ids, so every file stays
  theirs);
- moves `/opt/tgbot` to `/opt/logguard-tg-bot` and `/var/log/tgbot` to
  `/var/log/logguard-tg-bot`: the state (Telegram's queue position, messages to delete), the
  pseudonym key (so every account keeps its pseudonym), `OPENPGP_KEY`, the outbox and the log
  carry over;
- rewrites the old paths in `config.env` (the previous file stays as `config.env.pre-rename`)
  and adds `BOT_STATE_PATH` and `LOG_DIR` if they were missing;
- keeps the old binary as `logguard-tg-bot.prev` if it ran cleanly, so `rollback` works right
  after the move (with the new unit and paths; the old unit is not kept);
- in `/etc/logguard/logguard.toml` and `/etc/default/logguard-abuse-report`, replaces
  `/opt/tgbot`, `tg_user = "tgbot"`, `"tgbot.service"` and `ABUSE_REPORT_TG_OWNER=tgbot` (each
  changed file stays as `<file>.pre-rename-<time>`), checks that logguard accepts the config
  (else puts it back and says what to change by hand) and restarts logguard.

Deploy the current logguard first (its abuse report unit may write only to the new outbox
paths, and its `tg_user` default is now `logguard-tg-bot`); `install.sh` warns while the
installed abuse report unit names only the old ones. Running it again changes nothing more;
if both `/opt/tgbot` and `/opt/logguard-tg-bot` exist, it stops and asks you to keep one.
The bot's token and chat stay the same; Telegram doesn't see the rename.

Telegram sees the address of the host logguard-tg-bot runs on; in the messages the servers appear by
their node ids only, as far as `SERVER_NAMES` lists them. The host needs outgoing HTTPS to `api.telegram.org`. `TELEGRAM_API_URL` can point to a
local Bot API server instead (plain HTTP only on localhost).

## Settings

All in `config.env` (`deploy/config.env.example` has each with a reasonable value and a
comment; `logguard-tg-bot --help` lists the matching flags):

| Variable | Default | |
|---|---|---|
| `TELEGRAM_TOKEN` / `TELEGRAM_TOKEN_FILE` | | from @BotFather; one of the two |
| `ADMIN_CHAT_ID` | | your Telegram user id (`logguard-tg-bot pair`) |
| `TELEGRAM_API_URL` | `https://api.telegram.org` | |
| `XMPP_DOMAINS` | | a bare user name in an alert counts as on the first one |
| `SERVER_NAMES` | | `node=address,...,name; ...`: replaced by the node id in alerts |
| `OPENPGP_KEY` | | the admin's OpenPGP public key; files go out encrypted to it, or not at all |
| `DELETE_AFTER_HOURS` | 0 (keep) | 1–47: the bot deletes the chat's messages, both sides, after that long |
| `PROTECT_CONTENT` | no | yes: clients don't allow forwarding, saving or copying alerts |
| `ALERT_MAX_HOURS` | 24 | older alerts are dropped unsent |
| `OUTBOX_MAX_DAYS` | 7 | older files are deleted unsent |
| `BOT_STATE_PATH` | `/opt/logguard-tg-bot/state.json` | |
| `OUTBOX_DIR` | `outbox` next to the state | |
| `PSEUDONYM_KEY` | `pseudonym.key` next to the state | |
| `LOG_DIR` | `/var/log/logguard-tg-bot` | `bot.log`, 14 days |

Exit status 78 (Telegram refused the token, or a setting is wrong) is not restarted by the
unit. Fix `config.env` and start it again. A token revoked while the bot runs stops it the
same way.

## Retention and what the bot keeps

- **On Telegram:** messages stay in the chat until deleted. With `DELETE_AFTER_HOURS`, the bot
  deletes its own and your messages in the chat after that long. Telegram allows bots this
  only within 48 hours, so messages from a longer downtime have to be deleted in the app.
  `/privacy` says which applies.
- **On the server:** `bot.log` (14 days: weekly rotation, one old copy), `state.json` (the
  next update id and, with auto-delete, message ids and times: no text), `pseudonym.key`,
  and outbox files until they are sent (or expire). Nothing the bot sends is written
  anywhere else on the server.

| Path | Owner | Mode |
|---|---|---|
| `/opt/logguard-tg-bot/` | root:logguard-tg-bot | 1770 (sticky) |
| `config.env` (the token), `OPENPGP_KEY` | root:logguard-tg-bot | 640 |
| `state.json`, `pseudonym.key` | logguard-tg-bot | 600 |
| `outbox/` | root:logguard-tg-bot | 1770; files logguard-tg-bot 600 |
| `/var/log/logguard-tg-bot/`, `bot.log` | logguard-tg-bot | 700, 600 |

The unit drops every capability, makes the whole file system read-only except `/opt/logguard-tg-bot`
and `/var/log/logguard-tg-bot`, allows only IPv4 and IPv6 sockets, and denies writable-executable memory.

## Why not a Telegram crate

The suggested `telegram-rs-2` (0.1.2) served as a reference for the API's shape but is not a
dependency:
- it has no `sendDocument`, and its `Message` lacks `from` and `date`;
- its reqwest uses the default TLS (OpenSSL), which breaks the static musl build;
- its errors carry reqwest's URL, which holds the token, into logs;
- it pulls in a proc-macro crate from the same single author (runs at build time), with a few
  dozen downloads in all.

`src/api.rs` calls the half dozen methods it needs directly, over reqwest with rustls and
ring (like logguard-xmpp-bot's TLS). It checks the token's shape before it goes into a URL and strips
URLs from errors. Formatting goes as entities, never Markdown or HTML, so nothing in a log
line can change how a message displays.

## Build and test

```bash
./scripts/ci.sh            # fmt, clippy, tests, cargo audit, static Linux binary
```

The static build needs `rustup target add x86_64-unknown-linux-musl` and
`rustup component add llvm-tools` (see `.cargo/config.toml`, the same as logguard-xmpp-bot's).
`tests/fake_telegram.rs` runs the delivery code against a fake Bot API server on 127.0.0.1:
an alert with account names and server addresses replaced, the report held back without a
key and then sent encrypted (nothing of it in the request, the admin's key opens it), flood
control (429 `retry_after`), strangers ignored, the state across a restart, auto-delete and
its 48-hour limit. `tests/gpg_interop.rs` decrypts the files with GnuPG when `gpg` is
installed (`brew install gnupg`), in a throwaway `GNUPGHOME`, and checks keys that expire.
Not yet tried against the real Telegram or on a phone.

**Fuzzing.** What comes from outside (logguard's outbox files with attackers' log text in
them, Telegram's replies, the key file, `SERVER_NAMES`) goes through four cargo-fuzz targets
(code in `src/fuzzing.rs`):
- `alert_text`: an outbox file through the whole way to Telegram. Besides no panics, it
  checks the promises with rules of its own: no `name@domain` and no `ejabberd:<name>` left,
  no configured server address or host name left, nothing left to replace on a second pass,
  and every message as Telegram takes it unchanged (1 to 4096 UTF-16 units, no blanks at the
  ends, no control characters, entities inside the text and not splitting a UTF-16 pair).
- `telegram_reply`: Bot API replies (updates, errors, sent messages) and `state.json`; no
  update with an id may be lost.
- `openpgp_key`: the key file; whatever is taken as a key must encrypt, with nothing in clear.
- `server_names`: a `SERVER_NAMES` value and a text (split at the first NUL byte).

`tests/fuzz_smoke.rs` runs them on stable on realistic inputs, the seeds in `fuzz/seeds/` and
a few thousand mutations, so `cargo test` keeps them working; a failing input is saved as
`target/fuzz-smoke-<target>.bin` (`LOGGUARD_TG_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke`
regenerates the seeds; the keys in them are new and throwaway). The real search needs nightly:

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked   # once
cargo +nightly fuzz run alert_text fuzz/corpus/alert_text fuzz/seeds/alert_text -- -dict=fuzz/alert_text.dict -max_total_time=600
```

New inputs collect in `fuzz/corpus/`, crashes in `fuzz/artifacts/` (both git-ignored). The
`regression-*` seeds are inputs the first runs (2026-10-17) failed on, all fixed: a server
address inside a longer run (`dead:…`, `…:ad:192.0.2.10`, `2001:db8::10.example…`), an
address with junk after a colon, two addresses touching (`a@x{@y`), an `ejabberd:[acct:` that
wasn't a pseudonym hiding the name after it, brackets alone taken for an `ejabberd:` name, a hex-only node id rebuilding an address, an address glued to another
(`198.51.100.20db8::`, now replaced until nothing changes), a long subject cut on a blank. The smoke test found the first of these within a second.
Later the same day, logguard-mail-bot's fuzzing of the same code found a server address that,
replaced by its node id, completed an address (`admin@::ffff:192.0.2.10` → `admin@xmpp`): the
account pass now runs again after the server pass (`regression-server-makes-address`).
