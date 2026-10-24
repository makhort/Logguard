# logguard-xmpp-bot

The Rust rewrite of the Python XMPP admin bot (`/opt/xmpp-bot/bot8.py`, before the rename below): the same
chat commands over `ejabberdctl`, the same `state.json`, the same `config.env`.

## What changed from the Python bot

- **Login: SCRAM-SHA-256-PLUS** (SCRAM-SHA-256 bound to the TLS 1.3 session) instead of
  DIGEST-MD5. At startup the bot refuses a server that doesn't offer SCRAM-SHA-256, so it never
  falls back to SCRAM-SHA-1 or PLAIN. If the server rejects the channel binding, the bot logs a
  warning and uses plain SCRAM-SHA-256. ejabberd logs
  `Accepted c2s SCRAM-SHA-256-PLUS authentication for bot@...`.
- **TLS certificates are verified** against the JID's domain, also when connecting to
  `127.0.0.1`. xmpppy didn't verify them.
- **Wrong password: the bot stops** (exit 78, which the unit does not restart) instead of
  retrying until mod_fail2ban bans the address. That holds at startup and also when the
  password changes while the bot runs: after 3 failed logins in a row it stops.
- **The bot runs as the `ejabberd` user**, the one ejabberd itself runs as, with no root and
  no capabilities. ejabberdctl then works for it directly, without switching users. The
  bot's password is removed from the environment of the commands it runs. (Run as root
  instead, it starts ejabberdctl and openssl as `EJABBERD_USER`.)
- **Usernames are normalized as ejabberd does** (nodeprep): `Admin`, `ADMIN` and `ａｄｍｉｎ`
  are all `admin`. The admin's and the bot's own accounts can't be removed, banned, kicked,
  given a new password or reset link, or reported. `/remove` also takes the user off the bot
  allowlist, so a new account of the same name starts without bot access.
- **Late commands are not run.** A command that reaches the bot more than 2 minutes after it
  was sent (held in offline storage while the bot was down) gets "Not run: … send it again"
  instead. A message delivered twice (same id) runs once.
- **The password is no longer on the command line**: the bot reads `BOT_PASSWORD` (and every
  other setting) from the environment, i.e. straight from `config.env`.
- **Nothing the bot sends is archived.** Every message it sends (replies, errors, alerts,
  OMEMO key messages) carries a XEP-0334 `<no-permanent-store/>` hint. mod_mam
  (`default: always`) then archives it on neither side, while offline storage still delivers
  it. The bot also sets its own account's archive preference to `never` (XEP-0313). What a
  user sends to the bot still lands in that user's archive; `/purge_bot_chats confirm`
  deletes it, along with the bot's whole archive.
- Messages are accepted only from exactly the bot's domain (the Python suffix test also let
  through domains like `evilexample.org`, although only listed JIDs could run commands).
- **User commands**, all about the sender's own account only:
  - `/invite` points to mod_invites' web page (`INVITE_URL`, default
    `https://<domain>:5281/invites`), where users sign in and create invitations; it
    replaces `/create`, which still answers with the same text.
  - `/resetlink`: a reset link for their own account.
  - `/devices`: their connected devices, numbered, with address and time online; the one
    they write from is marked. A footer reminds them to check the list and to disconnect
    an unknown device with `/logout` and set a new password with `/resetlink`.
  - `/logout <number|device>`: disconnects one of their devices, by its number in
    `/devices` or its name. The device the command comes from only with `confirm`.
  - `/storage`: how many of their messages the server archive holds and how many wait
    for delivery.
  - `/delete_history confirm`: deletes their whole message archive on the server.
  - `/motd`: the current message of the day.
  - `/lang <EN|FR|GE|PL|RU|UA>`: the language of the bot's replies.
  - `/export`: what the server and the bot hold about the user (GDPR art. 15): last
    login, profile, contacts, group chats, devices, message counts, invitations they
    created (without tokens, and without who used them), their language and abuse
    reports, and how many reports there are about them (not by whom). The whole-server
    XEP-0227 export (`export_piefxis`) is not used: it writes everyone's data, password
    hashes included, to disk.

    With `EJABBERD_DB` set (ejabberd's `sql_database`), the full copy follows as a JSON
    file (GDPR art. 15 and 20), sent like the weekly report: encrypted (OMEMO media,
    XEP-0454), to the device that asked and the user's other trusted devices, in an
    OMEMO-encrypted chat only (a plain chat gets a note instead). It holds every row of
    ejabberd's database about the account: account (hash types, not hashes), last
    activity, contacts and groups, vCard, private storage, privacy lists, archive
    settings, the archived messages themselves, offline messages, push registrations
    (not their secrets), published items (PEP) and their settings, own pubsub
    subscriptions, room nicknames and subscriptions, invitations created, login
    tokens' client names (not the tokens), shared roster groups; plus connected
    devices, joined rooms and what the bot holds.

    **Only the user's own data.** `sqlite3 -readonly` reads the database. Every query
    matches the account exactly (`=`, never `LIKE`, whose `_` and `%` would match other
    names), and every row is checked again in the bot before it goes into the file: a
    row owned by anyone else is dropped and logged. Left out on purpose: group chat
    archives and member lists (other people's messages and accounts), who subscribed to
    the user's published items, the accounts the user's invitations created, a contact's
    subscription request text, and every secret. A test (`commands/tests.rs`) builds a
    SQLite database with the user, a look-alike account `LIKE` would match, a group
    chat and a foreign publisher, and checks the file holds none of them.
  - `/privacy` (also for the admin): how long the server keeps data. The archive,
    offline messages and push registrations go after `RETENTION_MESSAGE_DAYS` (21),
    uploads (at most `UPLOAD_MAX_MB`, 500, each) after `RETENTION_FILE_DAYS` (7),
    accounts without a login after `RETENTION_ACCOUNT_DAYS` (90), unused group chats
    after `RETENTION_ROOM_DAYS` (90). Keep them in step with `cleanup_db.sh` and
    `mod_http_upload(_quota)`. It also covers passwords (SCRAM hashes), OMEMO, server logs
    and what the bot itself keeps.
  - `/help` ends with the admin's address (`ADMIN_JID`) for questions.

  ejabberd's error texts go to the bot's log, not to users.

  At startup and then daily, the bot drops from `state.json` what it holds about accounts
  that no longer exist (the daily `cleanup_db.sh` deletes inactive ones without telling
  it), reports about or by them, and abuse reports older than `ABUSE_REPORT_DAYS` (90).
  It skips this when ejabberd's user list lacks the bot's own account, so a failed
  listing can't wipe the state. `/getlim`, `/setlim` and
  `/invited` (the old `/create` quota) are gone; old entries stay in `state.json`.
- **Replies to users in their language.** `/allow <username> [language]` sets it, and users can change it with `/lang`: `EN`
  (default), `FR`, `GE` (German), `PL` (Polish), `RU` or `UA` (Ukrainian), in any case. Everything the bot
  says to that user is translated: help, errors, usage lines, `/invite`, `/resetlink`,
  `/abuse`, OMEMO messages and `/omemo`. Command names stay English. The admin's replies
  stay English. `/allowed` shows each user's language. It is kept in `state.json` (a
  `lang` field older versions ignore).
- **Server announcements in the configured languages.** `/maintenance`, `/restart` and
  the subject of `/warn` are written in every language of `ANNOUNCE_LANGUAGES`, in that
  order (default `EN,FR,RU,UK`; `GE`/`DE`, `PL` and `UA`/`UK` work too), one paragraph per
  language with its flag. Times are given in each language's time zone, named as it is
  then (`BST` or `GMT` for English, `CET`/`CEST` for French, German and Polish, `MSK`, `EET`/
  `EEST` for Ukrainian): `/maintenance 'Sun 01:00' 'Sun 02:00'` gives "from Sun 02:00 to
  Sun 03:00 (BST)" and so on. `/dt_conv` shows a time the same way. The text of `/warn`
  itself is the admin's, as typed.
- **Delivery and read receipts.** Commands that ask for them get a XEP-0184 receipt and a
  XEP-0333 "displayed" marker, so Conversations shows them as delivered and read. The bot
  answers disco#info and puts XEP-0115 caps in its presence, so clients know it supports
  both.
- `state.json` is written to a temporary file and then renamed into place, so a crash never
  leaves a truncated file. The format is unchanged, so you can roll back.
- Pings, disco#info and roster pushes are answered; other IQ requests get
  `service-unavailable`.
- Passwords and reset links sent unencrypted carry `<no-store/>` too, so they never wait in
  the server's offline storage. With `OMEMO=required` they are always encrypted.
- **More admin commands**, grouped by section in `/help`: `/status`, `/certs`,
  `/sessions`, `/roster`, `/storage`, `/baninfo`, `/kick`, `/unban_ip` (fail2ban),
  `/resetlink` (a `mod_invites` page where the user sets a new password), `/invites`,
  `/spam_domains`, `/block_domain`, `/unblock_domain`. These ask for a final `confirm`:
  `/purge_mam`, `/purge_offline` (ejabberd's batch purges; `/purge_status` shows progress),
  `/purge_bot_chats`, `/restart` (`restart_kindly`: refuses new logins, announces in the
  `ANNOUNCE_LANGUAGES`, waits, restarts) and `/reload_config`. Shutdown, backups, modules and mass
  deletion stay in the root shell.
- Replies use Message Styling (XEP-0393), which Conversations renders and other clients
  show as plain text: generated logins and passwords, commands in `/help` and usage lines,
  and OMEMO fingerprints in monospace; listings (`/list`, `/online`, …) in a preformatted
  block. Server announcements (`/maintenance`, `/warn`, `/announce`, MOTD) stay plain.
- **The avatar shows in Conversations.** Besides the vCard photo, the bot publishes the
  avatar with XEP-0084 (PEP, open access), which is the only kind Conversations shows for
  contacts; it uses vCard photos only for servers. It also approves subscription requests
  from the admin and allowed users, and asks them for theirs in return: ejabberd sends a
  contact's PEP items (the avatar) when that contact's presence reaches the publisher, so it
  takes a subscription in both directions. At startup, and right after `/allow`, it makes
  the subscription mutual with the admin and every allowed user, also those who never added
  the bot as a contact. Conversations shows such a user the bot's request once; accept it.
  Other subscription requests stay unanswered.

## OMEMO

The bot speaks OMEMO 0.3 (`eu.siacs.conversations.axolotl`, what Conversations, Gajim, Dino
and Monal use), implemented in `src/omemo/` from the X3DH, Double Ratchet and XEdDSA
specifications and XEP-0384 v0.3.

- On login it publishes its device list (only its own device) and its key bundle, with open
  access. It republishes the bundle when a one-time key gets used, and rotates the signed key
  every 30 days.
- An encrypted command gets an encrypted reply, sent to the sender's trusted devices, with the
  same no-archive hint as every other message of the bot.
- `OMEMO=on` (the default) also accepts unencrypted commands. `OMEMO=required` refuses them,
  except `/omemo`. `OMEMO=off` turns OMEMO off entirely.
- `/omemo` shows the bot's fingerprint and your devices' fingerprints with their trust state.
  Compare the bot's fingerprint with the one in Conversations (contact details) and with the
  `OMEMO on: device …, fingerprint …` line in the bot's log.

**Trust.** Keys are pinned in `omemo-trust.txt` next to `state.json` (`OMEMO_TRUST_FILE`),
one `<jid> <fingerprint>` per line, as Conversations shows the fingerprint (spaces and case
don't matter). A JID with pinned keys is served only on those keys: an unknown device gets
its fingerprint back and no command runs. A JID without pins is trusted on any key, as
Conversations does before you verify anything, unless `OMEMO_TRUST=pinned`, which trusts
pinned keys only. The bot warns in its log while the admin has no pin. The file must be
owned by root (or the bot's user) and writable by its owner only; otherwise the bot trusts no
key at all and says so in its log. Because pinning needs root on the server, a stolen admin password alone cannot run
commands once your devices are pinned. The file is re-read on every message, so no restart
is needed.

**Keys.** `omemo.json` next to `state.json` (`OMEMO_STORE`, mode 600) holds the bot's
identity key and sessions. Deleting it gives the bot a new device and key, which clients
then have to trust again. Never restore an old copy: its ratchet state has already been
used.

**Tests.** `./scripts/omemo-oracle.sh` sets up omemo-dr, Gajim's OMEMO library, in a venv
under `target/` and runs `src/omemo/oracle_tests.rs` against it. The tests cover signatures
in both directions, sessions started by either side, many messages each way, out-of-order
and duplicate messages, key transport messages, tampering, a peer rebuilding its session,
and the bot restarting. Once the venv exists, `ci.sh` runs these tests too. omemo-dr is
GPL-3.0 and only runs at test time; none of its code is in the bot.

**Reminder: OMEMO 2.** The bot speaks only OMEMO 0.3. The current XEP-0384 is OMEMO 2
(`urn:xmpp:omemo:2`: a different wire format, XEP-0420 stanza content encryption, and the
whole stanza encrypted instead of just the body), and clients are moving to it. When
Conversations, which the admin uses, ships it, add OMEMO 2 next to 0.3: publish both device
lists and bundles, and answer each device in the version it uses. Don't switch from one
to the other; that would cut off clients that still speak only one. Then test both versions
against an oracle as for 0.3.

## Alerts from logguard

logguard's messages to the admin (alerts and the daily digest) come through the bot, OMEMO-
encrypted like everything else it sends, instead of from ejabberd's `send_message` in plain
text (which `mod_mam` would also archive). logguard's `[notify] bot_outbox` points at the
bot's outbox. Each message is a file there, `alert-*.msg`. The bot looks every 5 seconds,
claims a message by renaming it to `.<name>.sending`, sends it to the admin's trusted
devices and deletes it.

- **logguard falls back to plain text.** A message the bot hasn't taken within logguard's
  `bot_grace` (2 minutes) goes out the old way, with a last line saying why it isn't
  encrypted. That happens when the bot is down or offline, OMEMO is off, no admin device is
  trusted, or sending failed (the bot then puts the file back).
- **Admin only.** The bot sends only messages addressed to `ADMIN_JID`. It renames a message
  for anyone else to `.<name>.rejected`, and logguard sends that one itself right away.
  Users' warnings never go through the bot.
- If the bot stops while sending, it puts the message back at its next start (or logguard
  takes it after 10 more minutes).
- logguard also warns the admin (the same way) when another file waits in the outbox longer
  than `bot_stuck_after` (1 hour), i.e. a weekly report the bot can't send.

Check it as root on the XMPP server: `logguard -c /etc/logguard/logguard.toml notify-test
--bot admin@example.org` waits until the bot has sent the test message, and says so.

## Weekly abuse report

Every Monday at 06:00 UTC the admin gets logguard's abuse report for both servers as an
encrypted file: a line saying what it is (servers, period), then the file itself, which
Conversations and Monal show as a downloadable attachment.

**How it gets there.** logguard and the bot stay separate programs; they meet only in a
directory.
1. `logguard-abuse-report.timer` runs on both servers at the same time (logguard's
   `deploy/logguard-abuse-report.sh`). Each server writes its own JSON report (`abuse-report
   --since 7d --json --all --min-events 1`).
2. The VPN server sends its report to the XMPP server over the cluster link
   (`logguard cluster-send-report`: the same XChaCha20-Poly1305 key and port as the shared
   bans, nothing new opened), where logguard writes it to `/var/lib/logguard/inbox/`.
3. The XMPP server merges both (`abuse-report --merge … --contacts`: the RDAP lookups,
   `--min-events 3` and `--top 50` apply to the merged report) into the text report with one
   "Hello, …" section per abuse mailbox, and puts it in the bot's outbox,
   `/opt/logguard-xmpp-bot/outbox/abuse-report-<date>.txt`, owned by the bot.
4. The bot checks the outbox every 5 minutes and right after login. It encrypts each file
   with AES-256-GCM (a new random key and 12-byte IV per file), uploads the ciphertext with
   HTTP File Upload (XEP-0363) and sends the admin an OMEMO message whose body is the
   download URL as `aesgcm://…#<IV><key>` (OMEMO media sharing, XEP-0454). Then it deletes
   the file.

**Why encrypted end to end.** The TLS certificate comes from Let's Encrypt, which is fine
for transport, but the server (and anyone with access to its disk or backups) would
otherwise hold a readable copy of the upload. With XEP-0454 the server only ever stores
ciphertext, and the key exists only inside the OMEMO message, encrypted for the admin's
trusted devices. The bot never sends a report in plain text, whatever `OMEMO` says: with no
trusted admin device the file waits and is retried. No XEP-0066 `<x xmlns='jabber:x:oob'>`
is added, since it would travel in clear. PEP/pubsub is involved only as it already is, for
the OMEMO device list and bundles; the report itself does not use pubsub.

**Needs on the server:** `mod_http_upload` with the bot allowed to upload (the default
`access: local` is enough). The bot finds the service with disco on the domain; set
`UPLOAD_SERVICE` (e.g. `upload.example.org`) to skip that. The upload is an HTTPS PUT to
the slot URL, verified against the system's root certificates.

**Retention (GDPR).** The report holds attackers' addresses and sanitized log lines; account
names are withheld. It is derived from logguard's security records, kept 84 days anyway
(`SECURITY_RECORD_DAYS`), and adds no copy that outlives them:
- the work files on both servers live in a private directory under `/run` (memory), deleted
  when the job ends;
- the VPN report in the XMPP server's inbox is deleted once merged; an unmerged one after 7
  days;
- the outbox file is deleted as soon as it is sent; an unsent one after `OUTBOX_MAX_DAYS`
  (7), with a warning in the bot's log;
- the upload is ciphertext only and goes after `RETENTION_FILE_DAYS` (7,
  `mod_http_upload_quota`);
- the two messages carry the no-archive hint like everything the bot sends: not in MAM,
  only in offline storage until delivered.

The admin's devices keep what they downloaded; delete the chat or file there when the
abuse desks have been written to. `/privacy` says, in every language, that the admin gets
this weekly encrypted report without account names and that the server holds it only
encrypted for at most `RETENTION_FILE_DAYS` days. The legal basis is the legitimate
interest in network and information security (GDPR art. 6(1)(f), recital 49).

**Check it** without waiting for Monday, as root on both servers (the VPN server first):
`systemctl start logguard-abuse-report`, then `journalctl -u logguard-abuse-report` and the
bot's log (`outbox: … sent to the admin (OMEMO media)`).

## Install from a release bundle

Without a Rust toolchain: every version tag `logguard-xmpp-bot-v<version>` gets its bundle, `logguard-xmpp-bot-<version>-<commit>-x86_64-linux-musl.zip`, as an asset of the tag's GitHub Release (see "Releases" in the [repository README](../README.md#deployment)); CI also keeps one for every commit as a workflow artifact (they expire and need a GitHub login), and `scripts/bundle.sh` builds it locally. It holds the static binary, the unit and logrotate files, `config.env.example`, `SHA256SUMS` and `install.sh`.

**Download and verify** (on your machine, then copy the zip over, or on the server): take the zip from the GitHub Release of the version's tag, with the [GitHub CLI](https://cli.github.com/) or from the Release's page:

```bash
gh release download logguard-xmpp-bot-v0.2.0 --repo OWNER/REPO    # the zip, its .sha256 and .sigstore.json
sha256sum -c logguard-xmpp-bot-*.zip.sha256                         # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify logguard-xmpp-bot-*.zip --repo OWNER/REPO --source-ref refs/tags/logguard-xmpp-bot-v0.2.0
```

`gh attestation verify` (after `gh auth login`) checks the signed build provenance: that this repository's CI built exactly this zip from that tag. With `--bundle logguard-xmpp-bot-*.zip.sigstore.json` it checks the attestation attached to the Release instead of fetching it from GitHub. Only a public repository's releases have one (GitHub offers attestations for private repositories only with Enterprise Cloud).

On the XMPP server (`apt install unzip` if needed):

```bash
unzip logguard-xmpp-bot-*-x86_64-linux-musl.zip && cd logguard-xmpp-bot-*-x86_64-linux-musl
sudo ./install.sh          # first time: only /opt/logguard-xmpp-bot/config.env, from the template
sudoedit /opt/logguard-xmpp-bot/config.env                     # the bot's account, ADMIN_JID, XMPP_DOMAIN ("Settings")
sudo ./install.sh          # installs and starts the bot; later: upgrades it
sudo ./install.sh rollback # back to the previous version
```

It refuses to install while `config.env` still holds `REPLACE…` placeholders. It checks every file against `SHA256SUMS` in a copy only root can write, then runs the same `install.sh` as `deploy.sh` below (`./install.sh --check` only checks the files). An existing `/opt/xmpp-bot` (the bot's old name) is moved over as with `deploy.sh`.

## Build, test, deploy

```bash
./scripts/ci.sh            # fmt, clippy, tests, cargo audit, static Linux binary
./deploy/deploy.sh         # ci.sh, then copies (over SFTP only) to a fresh xmpp:/tmp/logguard-xmpp-bot-deploy.XXXX
```

The static Linux build needs `rustup target add x86_64-unknown-linux-musl` and
`rustup component add llvm-tools` (see `.cargo/config.toml`).

Then paste the command `deploy.sh` prints into a root shell on the server: it checks the
files and runs `install.sh` (installs /opt/logguard-xmpp-bot/logguard-xmpp-bot and the unit,
restarts). To go back to the previous binary and unit:

```bash
bash /opt/logguard-xmpp-bot/install.sh rollback
```

**Renamed from `xmppbot` (2026-10-17).** The bot was `xmppbot`, installed as
`/opt/xmpp-bot/xmppbot`, run by `xmpp-bot.service`, logging to `/var/log/xmpp-bot`. The
first `install.sh` of the new name moves an old install over on its own, before installing:

- stops and disables `xmpp-bot.service`, removes it and `/etc/logrotate.d/xmpp-bot`
  (local changes in `xmpp-bot.service.d/` move to `logguard-xmpp-bot.service.d/`);
- moves `/opt/xmpp-bot` to `/opt/logguard-xmpp-bot` and `/var/log/xmpp-bot` to
  `/var/log/logguard-xmpp-bot`, with owners and modes: `state.json`, the OMEMO keys and trust
  pins, the avatar, the outbox and the log carry over, so the XMPP account, the OMEMO device
  and the admins' pinned fingerprint stay the same;
- rewrites the old paths in `config.env` (the previous file stays as `config.env.pre-rename`)
  and adds `LOG_DIR` if it was missing;
- keeps the old binary as `logguard-xmpp-bot.prev` if it ran cleanly, so `rollback` works
  right after the move (with the new unit and paths; the old unit is not kept);
- in `/etc/logguard/logguard.toml` and `/etc/default/logguard-abuse-report`, replaces
  `/opt/xmpp-bot` and `"xmpp-bot.service"` (each changed file stays as
  `<file>.pre-rename-<time>`), checks that logguard accepts the config (else puts it back and
  says what to change by hand) and restarts logguard.

Deploy the current logguard first: its `logguard-abuse-report.service` may write only to the
new outbox paths, and `install.sh` warns while the installed one names only the old ones.
logguard's integrity check reports the changed units in `/etc/systemd/system` once; that is
this move. Running `install.sh` again changes nothing more; if both `/opt/xmpp-bot` and
`/opt/logguard-xmpp-bot` exist, it stops and asks you to keep one.

**Fuzzing.** The OMEMO code and the outbox format live in the crate's library (`src/lib.rs`),
which the binary uses too, so `fuzz/` can reach them. There are three cargo-fuzz targets
(code in `src/fuzzing.rs`):
- `omemo_wire`: libsignal's protobuf messages inside OMEMO keys. Whatever parses must
  serialize back to the same message.
- `omemo_decrypt`: encrypted messages to a bot device, including session starts on its real
  prekey ids with fuzzed keys (zeros, low-order points) and a fuzzed first message.
- `omemo_stanza`: XML from other clients (`<encrypted>`, device lists, bundles the bot
  starts sessions from) and logguard's outbox messages.

`tests/fuzz_smoke.rs` runs them on stable, over real traffic between two throwaway devices,
the seeds in `fuzz/seeds/` and fixed mutations, so `cargo test` keeps them working
(`LOGGUARD_XMPP_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` regenerates the seeds; the keys in them
are throwaway). The real search needs nightly:

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked   # once
cargo +nightly fuzz run omemo_decrypt fuzz/corpus/omemo_decrypt fuzz/seeds/omemo_decrypt -- -max_total_time=600
```

New inputs collect in `fuzz/corpus/`, crashes in `fuzz/artifacts/` (both git-ignored). The
first runs (2026-10-16, 90 s per target, 240,000 to 750,000 inputs each) found nothing.

ejabberd's database holds only SCRAM-SHA-256 and SCRAM-SHA-512 hashes (the bot needs
SHA-256). The one-off script that migrated the plain-text passwords
(`ejabberd_scram_migration.py`) ran on 2026-10 and was retired with its backups; it is in
the git history.

`install.sh` keeps the previous binary and unit (`logguard-xmpp-bot.prev`, `logguard-xmpp-bot.service.prev`)
for `rollback` (only while the running version runs cleanly), backs up `state.json`,
installs a logrotate rule for `/var/log/logguard-xmpp-bot/bot.log` (weekly, one old copy: 14 days
at most, as `/privacy` says; older copies are deleted). The bot logs only there, not to
systemd's journal, which would keep the lines longer (`tail -f /var/log/logguard-xmpp-bot/bot.log`
instead of `journalctl -u logguard-xmpp-bot`; the journal still has systemd's own start/stop lines
and anything printed before the log opens). It also installs `ejabberd-logs`, a logrotate
rule keeping ejabberd's own log files 14 days at most (weekly, one old copy, `reopen_log`
afterwards), unless another rule already covers `/opt/ejabberd/logs`, and reminds you to
set `log_rotate_size: infinity` in `ejabberd.yml` so ejabberd stops rotating by size. With
journald limited to 14 days (`MaxRetentionSec=14day`, `MaxFileSec=1day`), `/privacy` can
say server logs are deleted after 14 days at the latest. It also checks that ejabberd's unit runs
as `ejabberd`, and shows the bot's log and ejabberd's record of the login. The Python bot
can't come back: it only logs in with DIGEST-MD5 or PLAIN, which the server no longer
offers.

It warns when `CTL_OVER_HTTP` is set in `/opt/ejabberd/conf/ejabberdctl.cfg`. In that
mode `ejabberdctl` sends its arguments to ejabberd as JSON without escaping them, so line
breaks and quotes (announcements, passwords) break commands, and replies with non-ASCII text
(a Cyrillic nickname in a roster) come back empty. The bot needs the classic mode; turning
it off doesn't affect ejabberd's socket itself, which other tools may use directly.

It also sets owners and modes, so the bot can change only what it has to:

| Path | Owner | Mode |
|---|---|---|
| `/opt/logguard-xmpp-bot/` | root:ejabberd | 1770 (sticky: the bot can't replace root's files) |
| `config.env` (holds the password), `omemo-trust.txt`, the avatar | root:ejabberd | 640 |
| `state.json`, `omemo.json` | ejabberd | 600 |
| `/var/log/logguard-xmpp-bot/`, `bot.log` | ejabberd | 700, 600 |
| `outbox/` (the weekly report waiting to be sent) | root:ejabberd | 1770; files ejabberd 600 |

After editing `omemo-trust.txt` as root, keep it `root:ejabberd 640`; the bot trusts no key
while others than root can write it.

The unit drops every capability, keeps `/usr` and `/etc` read-only, and has
`KillMode=process`, so a pending `/restart` (ejabberdctl `restart_kindly` waiting out its
delay) carries on when the bot restarts; a second one is refused while it runs.

## Settings

The variables in the existing `config.env`: `BOT_JID`, `BOT_PASSWORD`, `BOT_NAME`, `ADMIN_JID`,
`XMPP_SERVER`, `XMPP_DOMAIN`, `XMPP_PORT`, `BOT_STATE_PATH`, `ORG_NAME`, `AVATAR_PATH`,
`LOG_DIR`. Optional extras: `OMEMO` (`on`, `required`, `off`), `OMEMO_STORE`,
`OMEMO_TRUST_FILE`, `OMEMO_TRUST` (`blind`, `pinned`), `XMPP_TLS` (`auto`, `direct` or
`starttls`; auto means direct TLS on port 5223, as xmpppy did), `BOT_PASSWORD_FILE`,
`EJABBERDCTL`, `EJABBERD_USER`, `EJABBERD_DB` (ejabberd's SQLite file, for /export's
JSON file; e.g. `/opt/ejabberd/database/example.org.v2.db`), `SQLITE3`
(`/usr/bin/sqlite3`, package `sqlite3`), `INVITE_URL`, `RETENTION_MESSAGE_DAYS`,
`RETENTION_FILE_DAYS`, `UPLOAD_MAX_MB`, `RETENTION_ACCOUNT_DAYS`, `RETENTION_ROOM_DAYS`,
`ABUSE_REPORT_DAYS`, `SECURITY_RECORD_DAYS` (84: logguard's `actions.jsonl`, weekly × 12),
`ANNOUNCE_LANGUAGES` (`EN,FR,RU,UK`), `OUTBOX_DIR` (default `outbox` next to the state file), `OUTBOX_MAX_DAYS` (7),
`UPLOAD_SERVICE`. `logguard-xmpp-bot --help` lists the
matching command-line flags.
