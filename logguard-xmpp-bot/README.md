# logguard-xmpp-bot

An XMPP bot for logguard, in one of two modes (`BOT_MODE` in `config.env`):

- **admin** (the default): the Rust rewrite of the Python XMPP admin bot (`/opt/xmpp-bot/bot8.py`,
  before the rename below), on the XMPP server itself: the same chat commands over `ejabberdctl`
  for the admin and users, the same `state.json`, the same `config.env`, plus logguard's alerts
  and weekly report for the admin (logguard's `[notify] bot_outbox`, with logguard's plain-text
  fallback). Most of this README is about it.
- **client**: a copy bot like logguard-tg-bot or logguard-matrix-bot, on any host (a VPN server,
  a relay node, a desktop with logguard's desktop profile) with an account on any XMPP server. It
  only sends logguard's alerts, daily digest and weekly abuse report to its admin, OMEMO-encrypted,
  and as files encrypted to the admin's OpenPGP key when OMEMO can't reach the admin (logguard's
  `[notify] xmpp_outbox`). No ejabberd, no commands but `/status`, `/omemo` and `/help`. See
  "Client mode" below.

Both share the login (SCRAM-SHA-256-PLUS, certificates verified, stop on a wrong password), the
OMEMO code and trust pins, the no-archive hints and the outbox format.

## Contents

1. [What changed from the Python bot](#what-changed-from-the-python-bot)
2. [OMEMO](#omemo)
3. [Alerts from logguard](#alerts-from-logguard)
4. [Weekly abuse report](#weekly-abuse-report)
5. [Client mode](#client-mode)
6. [Connection drops (sleep, Wi-Fi, server restarts)](#connection-drops-sleep-wi-fi-server-restarts)
7. [Install from a release bundle](#install-from-a-release-bundle)
8. [Install from a package](#install-from-a-package)
9. [Build, test, deploy](#build-test-deploy)
10. [Settings](#settings)

## What changed from the Python bot

- **Login: SCRAM-SHA-256-PLUS** (SCRAM-SHA-256 bound to the TLS 1.3 session) instead of
  DIGEST-MD5. At startup the bot refuses a server that doesn't offer SCRAM-SHA-256, so it never
  falls back to SCRAM-SHA-1 or PLAIN. If the server rejects the channel binding, the bot logs a
  warning and uses plain SCRAM-SHA-256. ejabberd logs
  `Accepted c2s SCRAM-SHA-256-PLUS authentication for bot@...`.
- **TLS certificates are verified** against the JID's domain, also when connecting to
  `127.0.0.1`. xmpppy didn't verify them.
- **Wrong password: the bot stops** (exit 78, which the unit does not restart) instead of
  retrying until mod_fail2ban (or logguard) bans the address. That holds at startup and also
  when the password changes while the bot runs: it stops after the second failed login (see
  "Connection drops").
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

## Client mode

`BOT_MODE=client` (template: `deploy/config-client.env.example`) makes the bot a copy bot for
logguard's `[notify] xmpp_outbox`, as logguard-tg-bot is for `tg_outbox`: for a host without
ejabberd, such as the VPN server, a relay node, or a Linux desktop with logguard's desktop profile
(`deploy/logguard-desktop.toml` in logguard names the lines).

- **Any XMPP server, for the bot and the admin.** The bot needs an account of its own anywhere
  (a public server will do) and writes only to `ADMIN_JID`, on whatever server that is. Without
  `XMPP_SERVER` it connects to the JID's domain through its SRV records (`_xmpp-client._tcp`, or
  `_xmpps-client._tcp` with `XMPP_TLS=direct`), falling back to port 5222 (5223); the
  certificate is verified against the JID's domain either way. The login is the admin bot's:
  SCRAM-SHA-256(-PLUS) only, and exit 78 when the server offers nothing else or the password is
  wrong. Prosody before 13 offers only SCRAM-SHA-1: `ALLOW_SCRAM_SHA1=yes` accepts it (never PLAIN).
- **OMEMO first.** Alerts go out as OMEMO messages, files (the weekly abuse report) as OMEMO media
  (XEP-0454) through the bot's server's HTTP File Upload, to the admin's trusted devices, exactly
  as in admin mode: trust pins in `omemo-trust.txt`, blind trust while there are none (or
  `OMEMO_TRUST=pinned`).
- **OpenPGP when OMEMO can't reach the admin**: `OMEMO=off`, the admin's client publishes no OMEMO
  device, none of the admin's devices is trusted (not pinned under `OMEMO_TRUST=pinned`, or no key
  bundle), or encrypting fails. The message or file is then encrypted to the admin's OpenPGP key
  (`OPENPGP_KEY`: a v4 RSA or Curve25519 key, as OpenKeychain and iPGMail export it; the same code
  as logguard-matrix-bot's), uploaded under a neutral name (`message-<time>.txt.pgp`,
  `report-<time>.txt.pgp`) and sent as a link (body and XEP-0066 `<x xmlns='jabber:x:oob'>`), which
  Conversations shows as a download; open it with OpenKeychain (Android) or iPGMail (iPhone).
  Without `OPENPGP_KEY` such messages wait. `OMEMO=off` without `OPENPGP_KEY` is refused at the
  start (exit 78): the bot sends nothing in clear.
- **In clear the server sees only** the links to the OpenPGP files (their content is encrypted)
  and short notices, each kind at most once a day: why messages come as files now ("none of
  admin@…'s 2 OMEMO device(s) is trusted and reachable …"), why they wait, how many alerts were
  dropped. Every message carries the no-archive hint, as in admin mode.
- **No fallback on logguard's side**, as for the other copy bots: an alert waits in the outbox until
  it is sent or older than `ALERT_MAX_HOURS` (24; then dropped, and one notice says how many),
  a file until `OUTBOX_MAX_DAYS` (7). logguard warns when copies wait longer than its
  `bot_stuck_after`. The bot accepts any `To:` in the outbox: it has one admin.
- **It answers only its admin**, plain or OMEMO: `/status` (what was sent since the start, what
  waits, OMEMO, the fallback key's fingerprint), `/omemo` (fingerprints, as in admin mode) and
  `/help`. Anyone else gets no answer and no presence. It asks the admin for a mutual
  subscription at every start, as the admin bot does; accept it once.
- **No ejabberdctl, no state.json, no users.** `BOT_STATE_PATH`'s directory holds the OMEMO keys,
  the pins and the outbox. The admin-mode settings (`EJABBERDCTL`, `EJABBERD_DB`, `INVITE_URL`,
  the retention days, `ANNOUNCE_LANGUAGES`) are ignored.

**Install** from the release bundle on the host, as root: `./install.sh --client` puts the client
template in place as `/opt/logguard-xmpp-bot/config.env` (root-only until the bot is installed);
fill in `BOT_JID`, `BOT_PASSWORD`, `ADMIN_JID`, copy your OpenPGP public key to
`/opt/logguard-xmpp-bot/admin.asc` (or comment `OPENPGP_KEY` out), then run `./install.sh`
again. Because the config says `BOT_MODE=client`, `install.sh` creates the system user
`logguard-xmpp-bot` and installs `logguard-xmpp-bot-client.service` as `logguard-xmpp-bot.service` (the
package keeps it under its own name: `systemctl enable --now logguard-xmpp-bot-client`):
no ejabberd group, `ProtectSystem=strict`, `MemoryDenyWriteExecute` (no Erlang VM to start
here). It skips every ejabberd step. Then, in logguard's `[notify]`:

```toml
enabled = true
xmpp = false                                # no ejabberd on this host
xmpp_outbox = "/opt/logguard-xmpp-bot/outbox"
xmpp_user = "logguard-xmpp-bot"
```

and `systemctl restart logguard`, `logguard -c /etc/logguard/logguard.toml notify-test
--xmpp-client`. The weekly abuse report job finds the outbox there too.

Switching an existing install between the modes: change `BOT_MODE` and run `install.sh`; it
moves the files to the other mode's user. The OMEMO device stays the same if the bot's account
does. One logguard-xmpp-bot per host: logguard refuses `bot_outbox` and `xmpp_outbox` together.

## Connection drops (sleep, Wi-Fi, server restarts)

tokio-xmpp reconnects by itself, forever (backing off from 1 to 30 s), finds the server again
through DNS each time, and resumes the session (XEP-0198) when the server still holds it. Three
things it doesn't do are covered by the bot (since 2026-10-26, both modes):

- **Nothing in the outbox is lost.** tokio-xmpp counts a stanza as sent once it is in the
  socket's buffer, also on a connection that died unnoticed (a laptop that just woke up), and
  drops what the server hadn't acknowledged when it can't resume the session (the server keeps
  it 5 minutes on ejabberd's default). It reports no disconnection either. So before sending
  outbox items the bot pings its server (XEP-0199) and waits if there is no answer (asking again
  after 30 s at the earliest); after each alert or file it pings again and deletes the file only
  if the answer came on the same session. Otherwise the file stays and goes out again later: an
  alert may arrive twice, never not at all. Every send waits at most 30 s, so the bot keeps
  answering stop signals while the connection is down.
- **A dead connection is noticed sooner in client mode:** after 60 s of silence the bot asks
  the server for a sign of life and gives up on the connection 15 s later (tokio-xmpp's tight
  timeouts; admin mode, on localhost, keeps 5 + 5 minutes). Its timers stop while the machine
  sleeps, so on a laptop that is 75 s after waking up at most.
- **Failed reconnects can't get the bot banned, and a flaky network can't stop it.** The server
  may be guarded by mod_fail2ban (5 failed logins) and by logguard: a failed login is 25 points
  there, a connection without login 10, a failed TLS handshake 40; logguard bans at 100 points of
  a score halving every 10 minutes, or 200 of one halving every 12 hours. A connection that
  reached the server but didn't get the session online is followed by a wait of 2, 5, then 10
  minutes (30 after six such attempts, 60 after twelve), which keeps even failed TLS handshakes
  under both scores; attempts that never reach the server (no network, DNS down, connection
  refused) aren't counted. Before the next attempt, the bot checks the login on a connection of
  its own: only a rejected password (or no SCRAM-SHA-256) stops it, after two failed logins in
  all, whereas a network that went away during the login just means trying again. The usual
  reconnect after a sleep or a Wi-Fi change reaches the server and comes online at once, so it
  never waits.
- **The bot's account must be a real one, not a logguard canary.** logguard's `[canary] xmpp`
  names (its shipped list: `test`, `info`, `support`, `user`, `guest`, `demo`, `xmpp`, `jabber`,
  ...) are account-level tripwires: one failed login bans the address at once (100 points), and
  every login is a critical alert. The spacing above can't help there. The bot warns at the
  start when its name is on the shipped list; `install.sh` checks the list of the logguard on
  the same host and refuses such an account in admin mode (warns in client mode, whose server is
  usually elsewhere). The cure is another account, or the name in `[canary] except` on the
  server.
- **No network at the start** (a laptop that boots offline): the login check at startup waits and
  tries again (5 s, doubling to 5 minutes) instead of exiting. The client unit therefore doesn't
  pull in `network-online.target`, which slows booting on desktops.

After a long sleep, logguard on the same machine may report once that the bot left a message
unsent for hours: it measures the wait by the wall clock, which went on during the sleep.

## Install from a release bundle

Without a Rust toolchain: every version tag `logguard-xmpp-bot-v<version>` gets its bundle, `logguard-xmpp-bot-<version>-<commit>-<arch>.zip` for each architecture (`x86_64-linux-musl`, `aarch64-linux-musl` for arm64, `armv7-linux-musleabihf` for 32-bit ARMv7 with hardware floating point), as an asset of the tag's GitHub Release (see "Releases" in the [repository README](../README.md#deployment)); CI also keeps one for every commit as a workflow artifact (they expire and need a GitHub login), and `scripts/bundle.sh` builds it locally. It holds the static binary, the unit and logrotate files, `config.env.example`, `SHA256SUMS` and `install.sh`.

**Download and verify** (on your machine, then copy the zip over, or on the server): take the zip for the server's architecture (`uname -m`: `x86_64`, `aarch64`, or `armv7l` for armv7) from the GitHub Release of the version's tag, with the [GitHub CLI](https://cli.github.com/) or from the [Releases page](https://github.com/makhort/Logguard/releases) (each crate's releases are tagged `logguard-xmpp-bot-v<version>`):

```bash
arch=x86_64-linux-musl     # the server's: aarch64-linux-musl (arm64), armv7-linux-musleabihf (32-bit ARM)
gh release download logguard-xmpp-bot-v0.4.0 --repo makhort/Logguard --pattern "*-$arch.zip*"   # the zip, its .sha256 and .sigstore.json
sha256sum -c logguard-xmpp-bot-*-$arch.zip.sha256              # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify logguard-xmpp-bot-*-$arch.zip --repo makhort/Logguard --source-ref refs/tags/logguard-xmpp-bot-v0.4.0
```

`gh attestation verify` (after `gh auth login`) checks the signed build provenance: that this repository's CI built exactly this zip from that tag. With `--bundle logguard-xmpp-bot-*-$arch.zip.sigstore.json` it checks the attestation attached to the Release instead of fetching it from GitHub. Only a public repository's releases have one (GitHub offers attestations for private repositories only with Enterprise Cloud).

On the XMPP server (`apt install unzip` or `dnf install unzip` if needed):

```bash
arch=x86_64-linux-musl     # as above: aarch64-linux-musl, armv7-linux-musleabihf on ARM
unzip logguard-xmpp-bot-*-$arch.zip && cd logguard-xmpp-bot-*-$arch
sudo ./install.sh          # first time: only /opt/logguard-xmpp-bot/config.env, from the template
sudoedit /opt/logguard-xmpp-bot/config.env                     # the bot's account, ADMIN_JID, XMPP_DOMAIN ("Settings")
sudo ./install.sh          # installs and starts the bot; later: upgrades it
sudo ./install.sh rollback # back to the previous version
```

It refuses to install while `config.env` still holds `REPLACE…` placeholders. It checks every file against `SHA256SUMS` in a copy only root can write, then runs the same `install.sh` as `deploy.sh` below (`./install.sh --check` only checks the files). An existing `/opt/xmpp-bot` (the bot's old name) is moved over as with `deploy.sh`.

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `logguard-xmpp-bot_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) and `logguard-xmpp-bot-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"` or `"*.rpm*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once; neither needs dpkg or rpm, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). The package is for one host at a time: there is no apt or dnf repository.

```bash
sudo apt install ./logguard-xmpp-bot_0.4.0-1_amd64.deb     # Fedora, RHEL:  sudo dnf install ./logguard-xmpp-bot-0.4.0-1.x86_64.rpm
sudoedit /opt/logguard-xmpp-bot/config.env                  # the first install put the template there ("Settings")
sudo systemctl enable --now logguard-xmpp-bot               # admin mode; client mode:  logguard-xmpp-bot-client
```

The package puts the same files in the same places as `install.sh` (`/opt/logguard-xmpp-bot` with the binary and both templates, `/var/log/logguard-xmpp-bot`), with two units in `/usr/lib/systemd/system`: `logguard-xmpp-bot.service` for the admin bot (as the user ejabberd, on the XMPP server) and `logguard-xmpp-bot-client.service` for the client bot (`BOT_MODE=client`, its own user `logguard-xmpp-bot`, any host); you enable the one for the mode in `config.env`. The first install takes the admin template where the user `ejabberd` exists and the client template elsewhere. The post-install step does what `install.sh` does apart from copying files: the client mode's user, `config.env` the first time, the owners and modes for the mode's user, the outbox and the log directory, the logrotate rules for the mode (`/etc/logrotate.d/logguard-xmpp-bot`, and in admin mode `ejabberd-logs`, written from the copies in `/usr/share/logguard-xmpp-bot`), and the canary and `CTL_OVER_HTTP` checks as warnings. It refuses nothing: with `BOT_MODE=admin` and no user `ejabberd` it only says so. Switching modes: change `BOT_MODE`, run `dpkg-reconfigure logguard-xmpp-bot` (rpm: `dnf reinstall ./logguard-xmpp-bot-*.rpm`), then disable one unit and enable the other. In logguard's `[sources] services`, the client bot is `logguard-xmpp-bot-client.service`. `apt remove` stops the bot and keeps `/opt/logguard-xmpp-bot`; `apt purge` removes it with the state, OMEMO keys and pins, and the logrotate rules it wrote (rpm: by hand).

**Nothing starts on its own.** The first install puts the template in place and prints what to fill in; you enable the service once it is filled in. An upgrade keeps the config and restarts the service only if it was running and the config is filled in. **Over a bundle or `deploy.sh` install** the package takes over: the config, state and keys stay; the bundle's unit in `/etc/systemd/system` (it would shadow the package's) and its rollback files go, and the service is enabled again on the package's unit if it was (logguard's integrity watch reports the removed unit as a warning once). **Replacing the config:** when a terminal is there, the install asks whether to replace the config with the new template (the old one kept with the suffix `.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `LOGGUARD_PACKAGE_CONFIG=replace` (or `keep`) answers without asking: `sudo LOGGUARD_PACKAGE_CONFIG=replace apt install ./<file>.deb`. **Rollback** is installing the previous version's package (`apt install ./<old>.deb --allow-downgrades`, `dnf downgrade ./<old>.rpm`): there is no `.prev` file. A bundle's client-mode install ran under the admin unit's name; the takeover enables `logguard-xmpp-bot-client.service` instead.

## Build, test, deploy

```bash
./scripts/ci.sh            # fmt, clippy, tests, cargo audit, static Linux binary
./deploy/deploy.sh         # ci.sh, then copies (over SFTP only) to a fresh xmpp:/tmp/logguard-xmpp-bot-deploy.XXXX
```

The static Linux build needs `rustup target add x86_64-unknown-linux-musl` (for ARM: `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`, built with `TARGET=... ./deploy/deploy.sh`) and
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

`BOT_MODE` (`admin`, the default, or `client`). Since 2026-10-26 `XMPP_SERVER` (unset: the JID's
domain through SRV records), `XMPP_DOMAIN` (unset: the JID's domain), `XMPP_PORT` (unset: 5222,
or 5223 with `XMPP_TLS=direct`), `BOT_NAME` (`logguard`) and `BOT_STATE_PATH`
(`/opt/logguard-xmpp-bot/state.json`) have defaults, and `ALLOW_SCRAM_SHA1` (no) is new; client
mode adds `OPENPGP_KEY` and `ALERT_MAX_HOURS` (24) and uses the OMEMO, upload and outbox settings
below.

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
