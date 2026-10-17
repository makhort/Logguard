# logguard

A Rust daemon that replaces the cron-driven `log_analyzer.py`. It follows the systemd journal for **ejabberd** (optional), **sshd** and **UFW** in near-realtime, scores each remote address by its behaviour, and bans attackers through **nftables**, **ufw** or **iptables** (see "Firewall backends"). It is a single static binary of about 6 MB.

```
journalctl -f -o json ──► parsers ──► events ──► engine ──► decisions ──► nftables / ufw / iptables
 (cursor-resumed)         ejabberd PID correlation   decaying scores       ban ladder, expiry
                          ssh / ufw                  subnet + account      actions.jsonl, journal
                                                     analysis              snapshot socket ──► TUI
```

## Requirements

The binary is static (musl): no Rust, libc version or packages are needed to run it. What it
works with on the host:

| what | needed for | notes |
|---|---|---|
| Linux, x86_64, systemd | everything | runs as a `Type=notify` unit; tested on Debian 13 (kernel 6.12) and Ubuntu 22.04 (kernel 5.15) |
| `journalctl` (systemd-journald) | all log input | follows the journal as JSON; journald must keep the logs of sshd, the kernel and ejabberd |
| **one firewall backend** | enforce mode | `nft` (the default; nft 1.0 on kernel 5.15 and Debian 13's on 6.12 are verified), or `ufw`, or `iptables` + `ip6tables` (legacy or nf_tables flavour, with the `raw` table and `multiport`). Shadow mode needs none. |
| `nft` | rate limits, blocklist feeds | only the nftables backend has them |
| firewall logging | firewall signals (port scans, tripwires) | `ufw logging low`, or with plain iptables a LOG rule with the prefix `[LOGGUARD BLOCK] ` (see "Firewall backends") |
| `ufw` | exposure watch's firewall view | without ufw, listeners are still watched but not checked against firewall rules |
| `ejabberdctl`, or ejabberd's HTTP API on loopback | XMPP notifications | see "XMPP notifications"; reading ejabberd's log needs nothing extra |
| `openssl` | certificate checks in the daily digest | |
| `curl` | blocklist feeds, geo database downloads | |
| `docker` | the Nextcloud AIO source | reads `docker logs -f` of the Apache container |
| `df` | disk space watch | coreutils |
| ClamAV (`clamscan`/`clamdscan`) | the `logguard-avscan` timer | optional |
| the XMPP admin bot (`logguard-xmpp-bot`) | encrypted admin messages | optional, `[notify] bot_outbox` |
| the Telegram admin bot (`logguard-tg-bot`) | a copy of admin messages on Telegram | optional, `[notify] tg_outbox` |
| the mail bot (`logguard-mail-bot`) | a copy of admin messages by mail, OpenPGP-encrypted | optional, `[notify] mail_outbox` |

To build: Rust (stable) with the `x86_64-unknown-linux-musl` target; `deploy/deploy.sh` builds on a Mac.

## Deployment layouts

Protection never depends on the bots or on other servers: each server reads its own logs,
decides and bans in its own firewall, in real time. The bots only carry messages, and peers
only add what the others saw. These layouts are each run end to end by `tests/layouts.rs` (the
real daemon with a stand-in `journalctl` and `nft`, peers on 127.0.0.1): every one bans SSH and
XMPP attackers in the firewall within seconds and delivers messages as below.
`tests/abuse_report_layouts.rs` runs the weekly abuse report job in the same layouts.

| bots on the server | cluster peers | `[notify]` | `[cluster]` | admin messages | users' warnings | weekly abuse report (auto role) |
|---|---|---|---|---|---|---|
| none | none | off, or `enabled` with `api`/`ejabberdctl` on an XMPP server | off | over XMPP, unencrypted; or none | over XMPP (XMPP server) | `off` |
| none | yes (e.g. the VPN server) | the same; off on a server without ejabberd | on | over XMPP from the server with ejabberd; the others relay theirs there | over XMPP | `send` everywhere: nobody to merge |
| logguard-xmpp-bot | none | `bot_outbox` | off | OMEMO through logguard-xmpp-bot | over XMPP | `merge` at once, to logguard-xmpp-bot |
| logguard-xmpp-bot | yes | `bot_outbox` | on | OMEMO through logguard-xmpp-bot, the peers' relayed too | over XMPP | `merge` here, `send` on the peers |
| logguard-tg-bot | none | `xmpp = false` + `tg_outbox` (no ejabberd), or `tg_outbox` with no `admins` (with ejabberd) | off | Telegram only | over XMPP where ejabberd runs | `merge` at once, to logguard-tg-bot |
| logguard-tg-bot | yes | the same, or the relay node (`deploy/logguard-tg.toml`) | on, `relay_notices` on the nodes that deliver themselves | Telegram, the peers' relayed too (and over XMPP from an XMPP server that relays to the relay node) | over XMPP | `merge` on the logguard-tg-bot server, or `relay` on the relay node (merges itself when no merged report arrives) |
| both | none (peers work as above) | `bot_outbox` + `tg_outbox` + `admins` | off | OMEMO through logguard-xmpp-bot and a copy on Telegram | over XMPP | `merge`, to both bots |
| logguard-mail-bot | none | `xmpp = false` + `mail_outbox` (no ejabberd), or `mail_outbox` with no `admins` (with ejabberd) | off | by mail only, OpenPGP-encrypted | over XMPP where ejabberd runs | `merge` at once, to logguard-mail-bot |
| logguard-mail-bot | yes | the same, or a relay node of its own (as `deploy/logguard-tg.toml`, with `mail_outbox`) | on, `relay_notices` on the nodes that deliver themselves | by mail, the peers' relayed too | over XMPP | as logguard-tg-bot: `merge` on its server, or `relay` on a relay node |
| all three | none (peers work as above) | `bot_outbox` + `tg_outbox` + `mail_outbox` + `admins` | off | OMEMO through logguard-xmpp-bot, a copy on Telegram and one by mail | over XMPP | `merge`, to all three |

- **Users** are XMPP accounts: they are warned over XMPP by the server their account is on,
  whatever bots run. Telegram and mail never get users' warnings (and Telegram never their
  account names, logguard-tg-bot's README; by mail only with logguard-mail-bot's `SANITIZE=off`,
  its default, inside the encrypted mail).
- **Admin messages on Telegram (or by mail) only, on an XMPP server:** set `tg_outbox` (or
  `mail_outbox`, or both) and leave `admins` empty. Users are still warned over XMPP; a bot that
  stops sending is then reported as a system alert (journal, actions log, the other copy bot,
  and relayed to peers with `relay_notices`).
- **A server that delivers nothing itself** (`[notify]` off) relays its admin messages to its
  peers when the cluster is on; otherwise they are in its journal and actions log only.
- **The abuse report job** finds the bots' outboxes from `[notify] bot_outbox`, `tg_outbox` and `mail_outbox`
  (`/etc/default/logguard-abuse-report` can override them), merges at once on a server without
  peers, and refuses `send`/`relay` there.

## Firewall backends

`[enforce] backend` picks how bans are applied. `auto` (the default) tries nftables first, then ufw if it is installed, then iptables. If none works, logguard stays in shadow mode and says why. A fallback after nftables failed raises a high `system` alert.

| | `nft` | `ufw` | `iptables` |
|---|---|---|---|
| where | own table `inet logguard`, prerouting at raw priority | `ufw prepend deny` rules | own chains `logguard` and `logguard-ban` in the raw table, jumped to from the top of `PREROUTING` |
| before Docker's published ports | yes | no | yes |
| bans end | in the kernel (set timeouts), also while logguard is down | when logguard removes the rule | when logguard removes the rule |
| whitelisted ports stay open for banned addresses | yes | no | yes |
| rate limits, blocklist feeds | yes | no | no |
| self-healing | table rebuilt within 30 s | – | chains rebuilt within 30 s |

**iptables** is meant for hosts that manage their firewall with plain iptables, e.g. with `iptables-persistent` (`netfilter-persistent`), instead of ufw. logguard never touches your own rules or chains; it only adds its two chains to the raw table and one jump at the top of the raw `PREROUTING` chain, for IPv4 (`iptables`) and IPv6 (`ip6tables`):

- `logguard`: allowlisted networks and whitelisted ports `RETURN`, then a jump to `logguard-ban`. Rebuilt when the allowlist changes.
- `logguard-ban`: operator allows (`RETURN`) at the top, then one `DROP` rule per ban.

Allowed traffic `RETURN`s rather than `ACCEPT`s, so other rules in the raw table (Docker's) still apply. At start logguard empties `logguard-ban` and re-adds the bans and allows that are still active from its state file. So if `netfilter-persistent save` stored them while logguard ran, a reboot or `netfilter-persistent reload` restoring stale bans does no harm: they're replaced as soon as logguard starts. If a reload removes the chains or the jump, logguard rebuilds them within 30 s (high `system` alert). Bans don't expire in the kernel: one stays until logguard (running) lifts it. Paths and the chain name are set in `[enforce]` (`iptables`, `ip6tables`, `iptables_chain`).

For firewall signals, iptables must log what it drops, with the prefix logguard reads (`[sources] ufw` covers these lines too). Add it as the last rules of `INPUT`, before its DROP policy or final DROP rule, and save it with your other rules:

```bash
iptables  -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[LOGGUARD BLOCK] '
ip6tables -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[LOGGUARD BLOCK] '
```

For the cluster port, `logguard cluster-ufw-rules --iptables` prints the rules that open it to the peers only; `install.sh` shows them when there is no ufw.

## How decisions are made

Each address has two exponentially decaying scores:

| score | half-life | threshold | catches |
|---|---|---|---|
| fast | 10 min | 100 | bursts: 3 TLS failures, 5 SSH password failures, a port sweep |
| slow | 12 h | 200 | low-and-slow probing, e.g. one TLS failure every 30 min |

Events add points:

| signal | weight | source |
|---|---|---|
| `xmpp_tls_fail` | 40 | TLS handshake failure (old protocol, no shared cipher), attributed to an IP via the Erlang PID |
| `xmpp_auth_fail` | 25 | failed SASL login |
| `xmpp_no_auth` | 10 | 5222/5223 connection that never authenticated within 90 s |
| `xmpp_conn` | 2 | connection to 5269/5280/5443/5349… |
| `xmpp_s2s_bad` | 25 | inbound s2s rejected: not-well-formed, syntax error, host-unknown… |
| `xmpp_http_miss` | 4 | request for a missing upload file |
| `xmpp_token_fail` | 5 | rejected FAST token (`HT-*`): almost always a legitimate client with an expired token |
| `xmpp_register` | 15 | in-band account registration (each also raises an info alert) |
| `ssh_auth_fail` / `ssh_invalid_user` | 25 / 40 | failed password, gave up authenticating / unknown user |
| `ssh_preauth` | 8 | disconnected before auth, failed key exchange, banner garbage (a close/reset from an sshd-session that never authenticated counts too, even without `[preauth]`) |
| `ssh_penalty` | 25 | OpenSSH PerSourcePenalties fired |
| `fw_block` / `fw_limit` | 1 / 20 | UFW BLOCK / UFW LIMIT BLOCK |
| `fw_tripwire` | 100 | UFW BLOCK on a `[ports] tripwire` port (telnet, mail, RDP, VNC, SMB, databases, ...): one hit = ban |
| `peer_report` | reported points × 0.5 | suspicion reported by another cluster node |
| `web_probe` | 40 | Nextcloud: request for secrets refused (`/config/.env`, `aws.yml`, `secrets.yml`…) or path traversal (`/../.env`) |
| `nc_auth_fail` | 25 | Nextcloud: failed login |

Weights are calibrated against the 10-minute half-life: **40** means three strikes within about 5 minutes ban; **25** means five strikes within about 5 minutes. With 34, three strikes only added up when all came within about 25 seconds, so a scanner pausing 30 s between requests was never banned.

Bonuses: **+60** when one address touches **3 or more XMPP ports** within 10 min (port spread), and **+60** when UFW drops it on **8 or more distinct ports** (port scan).

**Protection.** Private, loopback, link-local and CGNAT addresses are ignored entirely; for example, a Docker container hitting the host's public IP is blocked by UFW about once a minute. Allowlisted addresses, and addresses that **authenticated successfully** within the last 14 days, are never banned. Noise signals from them score 0. Real failures still raise an alert. A subnet containing a protected address is never banned.

**Subnets.** Every 60 s a /24 (or IPv6 /64) is banned in either of two cases:
- 3 or more of its addresses are individually bad (concentrated attack).
- 5 or more addresses together reach a summed score of 100 (distributed scanning, e.g. `11.24.48.0/24` probing once per IP).

A /16 is banned when 12 or more bad addresses spread over 4 or more /24s.

**Ban ladder.** Bans last 1h → 6h → 1d → 7d → 30d per repeat offence. The offence counter resets after 30 days without a new ban.

**Accounts.** Alerts are raised for:
- Distributed password guessing against one account: about 20 failures from 3 or more IPs within an hour.
- A login right after suspicious activity from the same IP: **critical**, possible compromise.
- A login from a new /16, after a 7-day learning period.

**Shadow-mode self-check.** If a "banned" address later logs in successfully, a *likely false positive* alert is raised and the ban is lifted.

## Hosts without ejabberd (e.g. the wg-easy VPN server)

```bash
./deploy/deploy.sh vpn deploy/logguard-standalone.toml      # ssh alias "vpn"; then on that host: sudo /tmp/logguard-deploy/install.sh
```

[`deploy/logguard-standalone.toml`](deploy/logguard-standalone.toml) sets three things:
- `[sources] ejabberd = false`: the journal filter and the pipeline skip ejabberd entirely.
- `[ports] whitelist = ["51820/udp"]`: wg-easy's `WG_PORT`. The panel (`PORT=51821`) is no longer published, so it is not whitelisted.
- `notify.enabled = false`: there is no `ejabberdctl` on that host.

Whitelisted ports (`PORT/udp`, `PORT/tcp`, or a bare `PORT` for both) work as follows:
- **Never scored:** UFW blocks or other events on them don't count towards a ban.
- **Never blocked in enforce mode:** an `accept` for them precedes the ban drop, so even a banned address can still reach them.

**Docker:** ports published with `docker run -p` bypass UFW and the host INPUT chain. logguard therefore hooks nftables at **prerouting** (raw priority, before Docker's DNAT), so bans do cover Docker-published ports. The iptables backend covers them the same way (raw `PREROUTING`). The ufw fallback can't do this, and it can't keep whitelisted ports open either; logguard warns about this at startup.

**The wg-easy panel:** the WireGuard port is safe to whitelist, because it silently ignores unauthenticated packets. The admin panel is not: whitelisting it lets banned scanners keep trying its login page. Prefer not exposing it at all. Drop `--publish 0.0.0.0:51821:51821/tcp` and open `http://10.8.0.1:51821` while connected to the VPN: the panel listens inside the container, which owns the WireGuard interface. Alternatively publish it as `127.0.0.1:51821:51821/tcp` and use an SSH tunnel. Then remove `51821/tcp` from the whitelist.

## Nextcloud (AIO)

`[sources] nextcloud = true` reads two things, with no change to Docker or AIO:
- **`docker logs --follow --timestamps nextcloud-aio-apache`.** Apache's error log shows every refused request with the client IP. It's restarted automatically when the container is recreated (AIO updates, reboots), resuming after the last line seen.
- **`tail -F` of `nextcloud.log`** (`/var/lib/docker/volumes/nextcloud_aio_nextcloud/_data/data/nextcloud.log`; `occ log:file` shows the path inside the container) for `Login failed: user (Remote IP: …)`. This is the same file AIO's own fail2ban container reads; failures count per account like XMPP and SSH ones.
- **Restarts lose nothing:** the time of the last line read from each of the two is kept in the state file. After a restart, `docker logs` resumes from that moment and `nextcloud.log` is re-read from its last 2,000 lines; lines already seen are skipped by their timestamps. Login names from these logs are attacker-chosen: control characters are removed before they reach alerts or a terminal.

On the Oct 2–11 Apache log this bans each Google-Cloud `.env`/`aws.yml`/`config.js` prober on its third request. The daily `11.29.52.117` escalates 1h → 6h → 1d → 7d. Docker-published ports bypass UFW, but logguard's nftables chain sits in prerouting, so these bans apply to Nextcloud too.

## Tripwire ports

Nobody legitimate connects to telnet, mail, RDP or database ports on these servers, so one blocked attempt is proof of scanning. The defaults are 32 services neither server runs; each showed up 100-10,000 times in the Sep-Oct month of UFW blocks:

```toml
[ports]
tripwire = [
    "21/tcp", "23/tcp", "2323/tcp",                      # FTP, Telnet
    "25/tcp", "465/tcp", "587/tcp",                      # SMTP, SMTPS, submission (no MX points here)
    "110/tcp", "995/tcp", "143/tcp", "993/tcp",          # POP3(S), IMAP(S)
    "135/tcp", "139/tcp", "445/tcp", "3389/tcp", "5985/tcp", "5986/tcp", # Windows RPC, NetBIOS, SMB, RDP, WinRM
    "5900/tcp", "5901/tcp", "1723/tcp", "7547/tcp", "8291/tcp", # VNC, PPTP, TR-069, MikroTik Winbox
    "389/tcp", "2375/tcp", "2376/tcp",                   # LDAP, Docker API
    "1433/tcp", "1521/tcp", "3306/tcp", "5432/tcp", "27017/tcp", # MS SQL, Oracle, MySQL, PostgreSQL, MongoDB
    "6379/tcp", "9200/tcp", "11211/tcp",                 # Redis, Elasticsearch, Memcached
]
```

- **Ports you serve can't trip.** UFW only logs *blocked* packets, so a port that is open on the host never produces a tripwire event.
- **Mail ports only while no mail is delivered here.** `example.org`'s MX records point to Proton, so no legitimate mail server connects to port 25. Take 25 out for a domain whose mail *is* meant to come to this host but isn't served yet, and for a domain without MX records whose A record is this host: mail servers then deliver to the A record (implicit MX), bounces of forged mail included. A running Postfix opens its ports and can't trip anyway.
- **Defaults are TCP only.** UDP sender addresses are trivially forged, and a forged tripwire hit would ban an innocent address.
- **Impact on the Sep–Oct month:** 13,480 tripwire hits, mostly telnet, banned about 7,500 scanners for an hour on first contact, instead of letting them probe further. Port 23 alone was 9,807 of the month's 142k UFW blocks.

## Canary accounts

Account names attackers guess but nobody here uses are tripwires too. One login attempt on one is an immediate ban:

```toml
[canary]
xmpp = ["test", "info", "support", "root", "administrator", "webmaster", "guest", "demo"]
ssh = ["*"]                              # key-only server with a single user: every other name is a probe
except = ["admin", "<gateway user>"]     # real accounts are never canaries, whatever the lists say
```

- **No accounts to create.** ejabberd logs `Failed c2s … authentication for test@…: Invalid username or password` for a non-existent account exactly as for a wrong password, and sshd logs `Invalid user` / `User root from … not allowed because not listed in AllowUsers`. If in-band registration is open, a registration of a canary name also trips. The account would still be created, though, so keep registration closed or create the canary accounts yourself with long random passwords to reserve the names.
- **A successful login** to a canary (e.g. an account you forgot existed) is a **critical** `compromise` alert, and the address earns no trust.
- **Your own mistakes** (a typo from an allowlisted address, or from one that recently logged in to the same service) raise a "protected address" alert instead of a ban. A login never excuses a canary name or a tripwire port.
- **Trust from a login is per service** (`[allowlist] trust_ttl`, default 24 h after the last login): an XMPP login excuses that address's XMPP reconnects and typos, not SSH guessing, port scans or peers' reports, so one account (or a shared carrier NAT) can't shield an attacker. It is not shared with cluster peers.
- **Nextcloud:** don't list `admin`. It's AIO's initial admin account.
- **Expect few hits.** In the Sep–Oct month nobody guessed SSH user names at all, and all 8 failed XMPP logins were real users with expired tokens. Canaries are cheap insurance for the day someone starts.

## Exposure watch

Every `[exposure] interval` (60 s), the daemon:
1. reads listening sockets straight from `/proc/net/{tcp,udp}{,6}` (no `ss` subprocess) and maps them to processes through `/proc/<pid>/fd`;
2. compares them with the ufw rules that allow traffic **from anywhere** (`ufw status`);
3. classifies every listener:

| state | meaning |
|---|---|
| local only | bound to loopback or a private address (e.g. `127.0.0.53:53`, the Docker bridge) |
| blocked by ufw | public address, but no ufw rule allows it (e.g. Erlang's `epmd`) |
| allowed by ufw | public and allowed: really exposed |
| published by docker | `docker-proxy` listener: reachable **regardless of ufw** |
| no active firewall | public and ufw inactive or missing |

The first scan is learned silently as the baseline (one info alert lists it). After that it alerts, under the `exposure` notification topic:
- **New internet-facing listener:** e.g. an admin panel published on `0.0.0.0` by accident. It must be seen in 2 consecutive scans.
- **Listener gone:** a service stopped or crashed. It must be missing from 3 consecutive scans, so restarts don't flap.
- **Dead firewall rule:** ufw allows a single port from anywhere, but nothing listens on it publicly. That's exactly the 53/udp, 853/udp and 51821/tcp rules found by hand on the VPN host.

**Port ranges** such as the TURN/STUN relay ranges (`49152:65535/udp` and `/tcp`) are never reported as dead. Sockets opened inside them are marked *dynamic*: TURN servers open one per call participant, and Linux client sockets use that range too. They're listed in the TUI but never trigger new/gone alerts. Listeners with their own single-port rule, like TURNS on `5349/tcp`, are still tracked normally.
- **ufw inactive.**

Use `[exposure] ignore = ["5000/tcp"]` for ports that are exposed by design through another path. The TUI's **Exposure** tab (6) and `logguard status` show the current table.

**Weekly reboot / apt upgrades:** for `startup_grace` (15 min) after logguard starts, no new/gone listener alerts are raised, because Docker containers come up after logguard. A listener must be missing from `gone_after_scans` (5) consecutive scans before it's reported as gone, so a service restarted by an upgrade doesn't trigger alerts.

If Docker's userland proxy is disabled (`"userland-proxy": false`), published ports have no `docker-proxy` listener. Their ufw ALLOW rules would then be reported as dead; add those ports to `ignore`.

## Cron watch

Scheduled tasks are the classic way for an intruder to stay on a server after a reboot or a password change. Every `[cron] interval` (1 min) logguard reads:
- **crontabs:** `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d/*`, and every user's crontab in `/var/spool/cron/crontabs/` (what `crontab -l` shows). Each task line counts on its own; comments don't, so the header `crontab -e` rewrites is ignored. `VAR=value` lines count too, because changing `PATH` changes what runs;
- **run-parts directories:** `/etc/cron.{hourly,daily,weekly,monthly,yearly}`. Each file is a task, fingerprinted by content (SHA-256);
- **enabled systemd timers** in `/etc/systemd/system/timers.target.wants/`, cron's modern sibling;
- **scripts that crontab lines run,** e.g. `/usr/local/bin/av_scan.sh`, `bash /opt/job.sh` or `cd /opt/app && ./run.sh`, also behind `sudo -u`, `flock`, `timeout`, `env`, `nice`/`ionice`. Redirect targets, arguments and inline code (`sh -c '...'`) are not scripts. Programs in the system's package directories (`/usr/bin`, `/usr/lib`, ...) are skipped;
- **other files** (`[cron] files`), the usual ways back in besides cron: `authorized_keys` of root and every user in `/home`, `/etc/sudoers(.d)`, `/etc/passwd`, `/etc/shadow`, `/etc/group`, `sshd_config(.d)`, `/etc/ld.so.preload`, `/etc/rc.local`, `/etc/profile.d/*`, and systemd units (`/etc/systemd/system/*`, enabled ones in `*.wants/`, and drop-in overrides in `*.d/*.conf`, which can replace a service's `ExecStart`). Only fingerprints are kept, never contents (so no password hashes in alerts or the state file). Masked units (symlinks to `/dev/null`) are recorded as such. Files of a pattern added later (or by the upgrade that introduced file watching) are learned silently, and files of a removed pattern are forgotten instead of reported as removed.

Editor swap files, `.dpkg-old` leftovers and dotfiles (`.placeholder`) are ignored; cron and run-parts don't run them either. Any user can write their own crontab, so its lines are stripped of control characters, lines are capped at 1,000 characters, and a crontab of more than 500 lines is watched as one fingerprint. Programs it names are only opened if they are regular files (a named pipe would otherwise hang the scan).

**Learn period:** everything present during the first `learn` (1 day) is accepted. Changes in that time are only written to the actions log. After that, every change is reported once under the `integrity` admin topic and becomes the new normal:

| change | severity |
|---|---|
| new or changed task, crontab line or script | high, with "the server may be compromised" if nobody here made it |
| the same, but the file is a package's and identical to what it installed (the MD5 dpkg recorded) | warning, "installed by package man-db, unmodified" |
| a task or line removed (e.g. someone disabling the virus scan) | warning |

Package lookups read dpkg's database (`/var/lib/dpkg/info/*.list`, `*.md5sums`, `status`) line by line, and only for files that changed. Running `dpkg-query -S` / `dpkg --verify` instead would load every package's file list and hash whole packages, all counted against logguard's memory limit.

New and changed lines are listed in the alert (`+ ...` / `- ...`). So your own edits produce a message too, which confirms the watch works. `logguard integrity` prints everything that is watched, with package origins.

## Antivirus (ClamAV) results

With `[antivirus] enabled = true`, logguard reads the log of scheduled ClamAV scans (checked every minute) and reports, under the `integrity` topic:
- **infected files** (critical): each `path: Signature FOUND` is listed;
- **a scan that didn't finish** (high): no summary written, or an exit code beyond 2. Exit 137 means it was killed, usually out of memory (`clamscan` loads ~1-1.5 GB of signatures);
- **no finished scan for `stale_after`** (warning, daily, 36 h by default): the timer/cron job stopped running or keeps dying;
- **signatures older than 7 days** (warning): freshclam isn't working.

Clean scans are only logged ("virus scan finished ...: 2813 files, nothing found"), and `logguard status` shows the last one. Only runs newer than the last reported one count. On the first read of an existing log, only its newest run is news.

`install.sh` ships the scan as **`logguard-avscan.timer`** (daily at 02:30 ± 10 min; `Persistent=true` catches up after a reboot). It runs `/usr/local/sbin/logguard-avscan`, which:
- uses clamdscan when clamav-daemon runs, otherwise clamscan;
- runs at nice 19 with idle I/O, and with `OOMScoreAdjust=900`, so if memory runs out the scan dies (and is reported) rather than ejabberd or a database;
- wraps each run in marker lines with UTC times and the exit code.

Scan paths and excludes are in `/etc/default/logguard-avscan`. The timer is enabled only when `[antivirus]` is enabled and ClamAV is installed. Plain `clamscan --stdout` output appended by your own job also works: point `log` at it (dates are read as UTC).

## Abuse reports

`logguard abuse-report` turns the bans of a time window into a report for the abuse desks of the networks they came from. It works without the daemon: it reads `actions.jsonl` and its rotated copies, including the gzipped ones.

```bash
logguard -c /etc/logguard/logguard.toml abuse-report                          # last 7 days, top 50 sources
logguard -c /etc/logguard/logguard.toml abuse-report --since 30d --contacts -o /root/abuse.txt
logguard -c /etc/logguard/logguard.toml abuse-report --ip 11.40.36.0/24 --json
```

- **Per source:** first and last time seen, the number of incidents, the activity in plain words ("connection attempts to closed ports of commonly attacked services: TCP/23 (Telnet)", "SSH probing / login attempts"), and up to 25 log lines with full UTC timestamps. With `[geo]` on, it also gives the country and network owner. A network ban lists the addresses involved and what each did. Bans from now on keep the latest evidence lines of a network's worst members; older network bans recorded only the member addresses.
- **Order:** repeat offenders come first. `--min-events 3` (the default) leaves out sources with less evidence, such as a single blocked packet. `--top 50` is the default; `--all` lists every source.
- **`--contacts`:** looks up each network's abuse mailbox via RDAP (`rdap.org`, which forwards to the right registry). It makes about one request per second, with one request covering a whole network. The report is then grouped into one section per mailbox, each starting with a short "Hello, ..." ready to paste into an e-mail.
- **Withheld:** account names, except non-existent ones the attacker tried (`invalid user oracle`); the names of decoy (canary) accounts; internal scores; and bans received from other cluster nodes. Those other nodes have the evidence, so run the report there too, or merge the reports (below).

**One report for both servers.** Each server only has its own evidence; a peer's report is just counts and points. To combine them, export a JSON report on each server without filtering, then merge on one of them:

```bash
# on the VPN host
logguard -c /etc/logguard/logguard.toml abuse-report --json --all --min-events 1 -o /root/abuse-vpn.json
# copy it to the XMPP server, export there too, then merge
logguard -c /etc/logguard/logguard.toml abuse-report --json --all --min-events 1 -o /root/abuse-xmpp.json
logguard -c /etc/logguard/logguard.toml abuse-report --merge /root/abuse-xmpp.json /root/abuse-vpn.json --contacts -o /root/abuse.txt
```

The merged report has one entry per source: incidents are added up, and every log line says which server it hit (`(to 11.25.48.86) connection attempt to closed port TCP/23 (Telnet)`). `--min-events`, `--top`, `--ip` and `--contacts` apply after merging, so a source seen a little on each server still counts in full. The same report given twice (same server and period) is skipped with a warning instead of doubling every count.

**Weekly, to the admin's phone.** `logguard-abuse-report.timer` (Mondays 06:00 UTC, installed and enabled by `install.sh`) does the above on its own: the VPN server sends its JSON report to its cluster peers with `logguard cluster-send-report` (gzip-compressed, one message over the encrypted cluster link, never stored or forwarded as a fact; the peer writes it to `[cluster] inbox`, default `/var/lib/logguard/inbox`, mode 0600, and never parses it), and the XMPP server waits for it (up to 15 minutes), merges it with its own and puts the text report in the admin bot's outbox. The bot sends it to the admin as an OMEMO-encrypted file (logguard-xmpp-bot's README, "Weekly abuse report"); logguard-tg-bot, as a file encrypted to the admin's OpenPGP key. `ABUSE_REPORT_ROLE=auto` in `/etc/default/logguard-abuse-report` picks the role: `relay` on a Telegram relay node (below), else `merge` where a bot's outbox exists (`[notify] bot_outbox`, else `/opt/logguard-xmpp-bot/outbox`, and `[notify] tg_outbox`), else `send` when there are cluster peers, else `off`; `off` also turns the timer off. A server without peers merges at once (just its own report). Nothing stays behind: work files are in `/run` and removed on exit, the peer's report is deleted once merged (an unmerged one after 7 days; on a `send` node, which never merges, at its next run), and the bot deletes the outbox file once sent. A missing peer report is named in the job's output (`journalctl -u logguard-abuse-report`) and the report then covers the servers it has; add `logguard-abuse-report.service` to `[sources] services` to be told when the job fails.

```bash
systemctl start logguard-abuse-report      # now, as root: on the VPN server first, then the XMPP server
logguard cluster-send-report /root/abuse-vpn.json   # by hand: to the peers' inbox as abuse-<node>.json.gz
```

`--merge` reads these gzip files directly.

Times are UTC throughout, which is what abuse desks expect. The report doesn't say whether the firewall actually blocked anything, so it is also accurate for a server in shadow mode.

## Self-healing firewall table

On Debian and Ubuntu, `/etc/nftables.conf` begins with `flush ruleset`. Any `systemctl restart nftables`, or a package upgrade that triggers one, silently deletes logguard's table and every ban. In enforce mode the daemon checks for the table every 30 s. If it's gone, it recreates it, re-adds all active bans with their remaining time, and raises a **high** `system` alert.

## Kernel rate limits

`[[ratelimit]]` entries cap **new connections per source address** in the kernel, from the first packet, before any score reacts:

```toml
[[ratelimit]]
ports = ["5222/tcp", "5223/tcp"]
rate = "30/minute"        # n/second, n/minute or n/hour
burst = 30
```

They live in a second chain, `rl`, at prerouting priority *mangle*. That's after conntrack, so only new connections count, and still before Docker's DNAT, so Docker-published ports are limited too; UFW's `limit` rules never see those. Allowlisted and operator-allowed addresses are exempt. Per-source state lives in dynamic sets (`rl0_4`, `rl0_6`, …), and `logguard status` shows how many packets each entry dropped. Enforce mode with nftables only; the ufw and iptables backends ignore them. `install.sh` dry-runs the full ruleset with `nft -c` against the kernel.

## Quiet sources and the systemd watchdog

logguard can't tell "no attacks" from "not seeing logs" by scores alone, so `[silence]` raises a `system` warning when an enabled source:
- **logs nothing** for its threshold (defaults `ufw = "2h"`, `ejabberd = "6h"`, `ssh = "2d"`, Nextcloud off). Measured on the Sep–Oct month: UFW and ejabberd were never quiet for 3 h outside an outage; sshd often was for a day. Typical causes: `ufw logging off`, ejabberd stopped, or a unit renamed. An info alert follows when lines return.
- **logs, but no line can be tied to an address** for `blind_after` (6 h, at least `blind_lines` = 200 lines). This catches ejabberd's `hide_sensitive_log_data` (5 days in that month) or a log format logguard no longer understands.

Silence is measured from the later of the last line and the daemon's start, so a reboot or a stopped service never counts as silence. The checks run in the live daemon only, not in `replay`.

**Out-of-memory kills** (`[sources] oom = true`, the default): when the kernel kills a process for lack of memory (`Out of memory: Killed process 785891 (clamscan) ... anon-rss:920752kB`), a `system` alert names the process and its size. It's high, or a warning for a virus scanner, which `[antivirus]` reports as well. A kill for exceeding a unit's or container's own limit (`Memory cgroup out of memory`, e.g. logguard's `MemoryMax`) is told apart. On a 2 GB host without swap, the nightly clamscan was killed this way every day for weeks without anyone noticing.

**Disk and memory** (`[resources]`, on by default): every minute logguard reads `df -Pk` for the `disks` paths (each filesystem once; default `/`) and `/proc/meminfo` plus `/proc/pressure/memory`. A filesystem under 10% free raises a warning, under 5% a high alert; memory gets a warning when less than 10% stayed available for 15 minutes, or when tasks spent 10% of the last 5 minutes stalled waiting for memory (pressure stall information). Each alert repeats at most every 6 hours. `status` shows the latest reading. This comes before the out-of-memory kills below: on a host without swap, a shortage that lasts is the warning sign.

**Failed services** (`[sources] services = ["logguard-xmpp-bot.service"]`, empty by default): logguard also follows systemd's own messages about these units (journal match `UNIT=<name>`, accepted only from PID 1) and raises a high `system` alert when one ends unsuccessfully (a non-zero exit status, a signal, a timeout, a watchdog kill, ...) and is not started again within `service_restart_grace` (default 2 minutes; keep it longer than the units' `RestartSec`): `service logguard-xmpp-bot.service failed (exit-code, exit status 78/CONFIG) and was not restarted: it is down` (for the bot, a wrong password or setting, after which `RestartPreventExitStatus=78` keeps it down). A failure that systemd recovers from on its own (`Restart=`: "Scheduled restart job"), or that someone starts again in that time, says nothing. When systemd gives up restarting a unit (`Start request repeated too quickly`), the alert comes at once. Each at most once an hour per service. Clean stops and restarts (`systemctl restart`) say nothing. Restart loops that systemd never gives up on are not reported.

The unit is `Type=notify` with `WatchdogSec=2min`. logguard reports `READY=1` and pings the watchdog from its main loop, so if that loop ever hangs (a stuck `nft` or `ejabberdctl` call, a deadlock), systemd restarts it. `logguard status` shows the age of the last line per source.

## Cluster: sharing attack information between servers

Every logguard node can exchange what it learns with the others directly over TCP. No VPN or other infrastructure is needed, and nodes can be on different providers.

**What is shared ("facts"):**

| fact | effect on the receiving node |
|---|---|
| `bans` | the address/subnet is banned here too for the origin's duration, capped at `max_remote_ban`, tagged `from peer <node>` |
| `unbans` | a ban lifted at the origin (e.g. a false positive: a banned address then logged in) is lifted here too |
| `reports` | points a node scored for an address since its last sync, counted here × `report_factor` (0.5). An address that probes every server a little still adds up to a ban |
| `trust` | operator allowlist entries (`logguard allow`). Login trust is no longer shared: older nodes still send it, and it is ignored |

**Rules that keep it safe:**
- **Only peers may connect** (`allow_only_peers`, default on): connections from any address the `peers` don't resolve to are dropped unread. Peers named by host name are resolved again every 10 minutes (every minute while a lookup fails), and the listener, the engine and the nftables allowlist follow. While no peer resolves at all, every connection is refused, never accepted.
- **Local protections always win.** Allowlisted, private and cluster-peer addresses are never banned by peer facts. Peers are added to the nftables allowlist automatically.
- **Evidence is never echoed back.** Peer-reported points are not re-reported. A ban a node decides itself, based partly on peer reports, is shared as that node's own decision.
- **History stays local.** A node starts sharing only after catching up with its journal, so replayed history isn't broadcast as fresh evidence.

**How it works:**
- Every fact has a unique id (origin node, time-based sequence). Nodes apply each fact once and forward it to their own peers up to `max_hops` (3), so full meshes, chains (A↔B↔C) and stars all work, without loops or double counting. `share` is what a node sends: its own facts and the ones it forwards.
- Every `sync_interval` (10 s) each node sends its peers the facts learned since the last send. Every `full_sync_every` (10 min), or after a failed delivery, it resends everything, so restarted or temporarily unreachable nodes catch up. Empty messages double as heartbeats.
- A peer that stays unreachable for 5 minutes raises a `system` alert, at most hourly.

**Security:**
- Each message is one TCP connection carrying `"LGC1"`, a length, a random 192-bit nonce, and a ciphertext. It is encrypted and authenticated with **XChaCha20-Poly1305** under a shared 256-bit key, using pure-Rust crypto.
- Without the key, nobody can read or inject facts. Tampered, foreign or garbage connections are rejected and logged.
- Messages whose timestamp is more than `max_clock_skew` (5 min) off are rejected, so nodes need roughly correct clocks (systemd-timesyncd is enough). **Time zones don't matter:** all timestamps are Unix time (UTC), and the daemon reads journald's UTC timestamps. Times shown in the TUI, `status` and the logs are UTC. Replaying a recent message is harmless, because facts are de-duplicated.
- **Every key holder is fully trusted.** A compromised node can ban or trust addresses on the others. `max_remote_ban` bounds how long its bans last there: the built-in default is 1 day, while the templates use 30 days, because both nodes are yours. A capped peer ban isn't renewed while the origin's longer ban continues; the address is then banned again only on local evidence. Peer bans and allowlist entries wider than this node ever bans itself (/16, IPv6 /32) are ignored, a peer's suspicion report adds at most one ban threshold of points, and each connection must deliver its message within 30 s. Protect `/etc/logguard/cluster.key` like a root password, and rotate it if it may have leaked (see below).
- **Except peers you limit** (`peer_accept`): `peer_accept = { "203.0.113.10:7946" = ["notices", "files"] }` lets what arrives from that peer's address be notices and `cluster-send-report` files only, whoever's facts they are (its own or forwarded); the rest is dropped, counted in `logguard status` and logged once per kind. The limit goes by the connection's source address, not the node name in the message, which any key holder can write, so it needs `allow_only_peers` (the default). Use it for a node that is more exposed than the rest, such as the Telegram relay node below: broken into, it still holds the key (it can read every fact), but can't ban, unban or allowlist anything on the others.
- At most 8 concurrent incoming connections, 30 s per message, 1 MB per message: even 8 messages at once (each also decrypted into a copy) stay far inside the memory limit. A large sync (a full resend of thousands of bans) is split into messages of at most 512 KB, sent in order over one connection thread per peer. Run the same version on all nodes: an older node's large full sync can exceed the new 1 MB limit.

**Setup** (what the deploy scripts do for you):
1. `deploy.sh` generates `deploy/cluster.key` once on your Mac (`logguard cluster-keygen`, mode 0600, git-ignored) and ships it to every node. `install.sh` installs it as `/etc/logguard/cluster.key` unless one exists.
2. In each node's `[cluster]`: `enabled = true`, a unique `node_id`, `listen = "0.0.0.0:7946"`, and `peers` = the other nodes' `ip:7946`.
3. `install.sh` runs `logguard cluster-ufw-rules`, which opens 7946/tcp **only for the configured peers** (`ufw allow from <peer> to any port 7946 proto tcp`).

Check it with `logguard status` (per-peer delivery status and nodes heard from) or the TUI's overview (`Cluster: xmpp - 1/1 peers ok`). Bans from peers show `(from peer vpn)` in their message, and `origin` in `actions.jsonl`.

**Rotating the key** (`deploy/rotate-cluster-key.sh` on your Mac). Swapping the key on one node and then the next would leave a gap in which the two can't read each other, and facts sent in it are lost: a sender can't tell. So logguard also accepts the keys in `<key_file>.next` and `<key_file>.prev` from peers, while always sending with `key_file`, and the rotation goes in three rounds, each done on every node before the next. Like `deploy.sh`, the script only copies files (the step's script, and for `start` the new key) into a private `/tmp/logguard-rotate` on each node; you then run the step as root there, the way you run `install.sh` (no sudo needed):

```bash
./deploy/rotate-cluster-key.sh start  xmpp vpn    # then as root on each node: bash /tmp/logguard-rotate/rotate.sh start
                                                  #   new key -> /etc/logguard/cluster.key.next (accepted, not used yet)
./deploy/rotate-cluster-key.sh switch xmpp vpn    # ... rotate.sh switch: sends with the new key; old one -> cluster.key.prev
./deploy/rotate-cluster-key.sh finish xmpp vpn    # ... rotate.sh finish: cluster.key.prev removed, only the new key works
```

Each root step restarts logguard, prints the node's key fingerprints (`logguard cluster-key-id`: the first bytes of the key's SHA-256, equal for equal keys, revealing nothing about it) and ends with `OK: the new key (…) is in place.`, or a warning if the node holds a different key. `logguard status` and the daemon's startup line show the fingerprints too, with "rotation: also accepting …" while a `.next`/`.prev` file exists. Steps can be repeated (stage and run a step again for a node where it failed), and run in the wrong order they stop with a message. The key copy in `/tmp/logguard-rotate` is deleted when the step runs, whatever its outcome; until then it is readable by the SSH user, as `deploy.sh`'s copy is. `deploy/cluster.key` on your Mac becomes the new key when `finish` is staged, so `deploy.sh` installs the current key on new nodes. A `.next`/`.prev` file without a valid key stops the cluster on that node with a High alert instead of being ignored. Rotation needs the key in `key_file`, not inline as `key`.

**Key age.** `logguard status` shows how old the key file is (its modification time: when `install.sh` or `rotate.sh switch` put it there), and once it is older than `[cluster] rotate_after` (default `180d`, `0` turns it off) every node sends a Warning once a week until the key is rotated.

**Single server:** `[cluster]` is off by default (`enabled = false`). Then no key is needed, nothing listens on 7946, no peer alerts exist, and logguard behaves exactly as without the feature.

`listen = ""` makes a send-only node, for a host that can't accept incoming connections. It still pushes its facts to the others, but it only learns from nodes it can reach and receives nothing back.

### A Telegram relay node

To get admin messages on Telegram without the XMPP server ever connecting to Telegram, run logguard-tg-bot on a separate small VPS that joins the cluster (`deploy/logguard-tg.toml`, node id `tg`):

- **On the relay node:** `[notify] xmpp = false` with `tg_outbox`: no ejabberd, no users' warnings; every admin message (its own and the relayed ones) goes to logguard-tg-bot, which sends it with XMPP account names replaced by pseudonyms. `share = ["notices"]` and `relay_notices = true`: its own alerts and digest also go to the XMPP admin, and it passes nothing else on. It accepts the others' bans for its own firewall. `[sources] services = ["logguard-tg-bot.service"]` makes a failed bot a system alert, and a bot that leaves messages unsent past `bot_stuck_after` raises one too; both reach the XMPP admin through the relay.
- **On the XMPP node:** the relay node in `peers`, `peer_accept = { "<tg>:7946" = ["notices", "files"] }`, and `relay_notices = true`: its admin messages still go out over XMPP (and logguard-xmpp-bot) as before, and as notices to the relay node.
- **On the VPN node:** the relay node in `peers` and `peer_accept = { "<tg>:7946" = ["notices"] }`. It relays its admin messages already (`[notify]` is off there).
- **The weekly abuse report:** the relay node's timer runs in role `relay` (auto picks it with `xmpp = false` and cluster peers): it sends its own JSON report to the XMPP node (`ABUSE_REPORT_SEND_TO`), waits for the merged text report (`ABUSE_REPORT_RELAY_WAIT_MIN`, 60) and puts it in logguard-tg-bot's outbox (`[notify] tg_outbox`). If none arrives (a cluster without an XMPP server, or its `ABUSE_REPORT_FORWARD_TO` unset), it merges its own and the peers' reports itself; set `ABUSE_REPORT_ROLE=merge` there to skip the wait. On the XMPP node, `ABUSE_REPORT_PEERS="vpn tg"` waits for its report, and `ABUSE_REPORT_FORWARD_TO="<tg>:7946"` sends the merged text there (`cluster-send-report --name abuse-report --peer …`, written to the relay node's inbox as `abuse-report-xmpp.txt.gz`, deleted once handed over).

Telegram then sees the relay node's address only. In the alerts and digests logguard-tg-bot replaces the servers' own addresses and host names (certificate targets, peer addresses in cluster warnings) with their node ids (`SERVER_NAMES`), and the abuse report, which names the servers' addresses for the abuse desks, goes only as a file encrypted to the admin's OpenPGP key (logguard-tg-bot's README).

Relayed notices live an hour: if the relay node is down longer, what was relayed meanwhile doesn't reach Telegram (it still reached the XMPP admin). Deploy logguard with these settings to every node before you set them: older versions reject unknown keys.

## Operator controls: unban and temporary allowlist

```bash
logguard unban 11.12.51.11                       # or a subnet: logguard unban 11.12.51.0/24
logguard allow 203.0.113.7 --for 7d --note "temporary access"
logguard allowed                                  # list entries with time left
logguard disallow 203.0.113.7
```

In the TUI, on the **Offenders** or **Bans** tab: `u` unbans the selected entry (after a `y/n` confirmation), and `a` asks for a number of days to allowlist it. The Bans tab lists the operator allowlist under the bans.

- **Unban** lifts the ban and also clears that address's score and offence history, so it isn't re-banned the next second, and a later ban starts again at 1 hour. Unbanning an address inside a banned subnet is refused with a hint: unban the subnet, or allowlist the address.
- **Allow** lifts every ban inside the network and protects it until it expires: never scored into a ban, never banned by peers. In nftables it goes into the `oper4`/`oper6` sets with a kernel timeout, accepted before feeds and bans, so it works even for an address inside a banned subnet.
- **Cluster:** both are shared, so peers follow the operator's decision. Peer allowlist entries are capped at `max_remote_ban`.

All commands talk to the daemon over `/run/logguard/logguard.sock`, which is root-only, so use `sudo`.

## Blocklist feeds (optional)

```toml
[feeds]
enabled = true
urls = ["https://www.spamhaus.org/drop/drop.txt", "https://www.spamhaus.org/drop/dropv6.txt",
        "https://iplists.firehol.org/files/firehol_level1.netset"]
refresh = "24h"
```

- **Download:** every `refresh` period, with `curl` (falling back to `wget`). Shelling out keeps the binary free of a TLS library. The last good copy of each list is cached in `cache_dir`, so a failed download keeps the previous list instead of emptying it. Failures raise a daily warning.
- **Formats:** plain CIDR lists, Spamhaus `cidr ; SBL…` lines and Spamhaus JSON lines.
- **Sanitising:** private and bogon ranges are dropped; FireHOL level1 lists `10.0.0.0/8`, `127.0.0.0/8` and `172.16.0.0/12`, which would break loopback and Docker. So are prefixes wider than /8 (IPv4) or /19 (IPv6), and anything overlapping your allowlist or cluster peers. Nested entries are merged.
- **Loading:** into the separate nftables sets `feed4`/`feed6`, in one atomic transaction, after the allowlist accepts and before logguard's own bans. A feed can never block your allowlisted addresses, peers or operator allowlist. More than `max_entries` (100,000) networks is treated as a broken feed, and a refresh covering more than `max_growth` (2) times the address space of the last accepted load (plus a /16) is refused too: the last accepted list (`<cache_dir>/accepted.txt`) stays loaded, and a `system` alert says why. After an intended change (a new feed URL), delete that file once. Networks wider than `min_prefix_v4` (/12) or `min_prefix_v6` (/24) are never loaded: one bad entry must not drop a whole provider at the raw prerouting hook, where only the static allowlist, peers and operator entries are exempt.
- **One-step removal:** `logguard feeds clear` empties the sets immediately (until the next refresh); `[feeds] enabled = false` plus a restart keeps them empty. logguard's own bans are untouched either way.
- `logguard feeds` shows per-list status. Feeds are only *applied* with the nftables backend in enforce mode; in shadow mode they're downloaded and counted only.

## Daily digest (optional)

```toml
[digest]
enabled = true
at = "07:00"                       # UTC
certs = ["example.org:5223", "example.org:5222/xmpp", "nextcloud.example.org:443"]
cert_warn_days = 21
```

One XMPP message to the `[notify] admins` each day, flagged with ⚠ in the subject when something needs attention. It covers:
- **Needs attention:** certificates expiring within `cert_warn_days` or failing to check, failing cluster peers, failing feeds, dead ufw rules, and the period's warning-or-worse alerts.
- **Bans by cause:** tripwire, port scan, ssh, xmpp, subnet, from peers, cluster evidence.
- **Top offenders** with their current ban, alert counts by topic, and event counts.
- **Exposure, certificates, cluster, feeds and the operator allowlist.**

**Certificates** are checked every 6 h against the live endpoints with `openssl s_client` (`/xmpp` = STARTTLS on 5222), so a failed ACME renewal is caught before clients see it. An expiring certificate also raises its own alert: **warning** under 21 days, **high** under 7.

`cert_files` (e.g. `["/opt/ejabberd/database/ejabberd@localhost/acme/live/*"]`, `*` allowed in the file name) adds the certificates on disk. If one of them covers an endpoint's hostname and expires more than a day later than the certificate actually served there, logguard warns: *renewed, but not in use: point `certfiles` at it and reload*. That's exactly the manual step after each renewal being missed. Old certificates left on disk are ignored.

**ejabberd's own certificate log lines** become admin alerts as they happen (`system` topic, so the VPN node relays them too):

| ejabberd logs | alert |
|---|---|
| `Storing certificate for … in PATH` (debug level) | info: *certificate renewed*, with the new **DANE TLSA `3 1 1`** value (SHA-256 of the public key, via `openssl x509 -pubkey \| openssl pkey -pubin -outform der`) |
| `Certificate in PATH … will expire in a week` / `has expired` | warning / high |
| `Failed to request certificate … Challenge failed for domain D …` | warning, with the cause: *nothing answered on port 80*, or *redirected to https* (port 80 must reach ejabberd's ACME handler without a redirect) |

With DANE, a renewal can change the key, so the safe order is:
1. A *certificate renewed* alert arrives, carrying the new `3 1 1` value.
2. Publish that TLSA record next to the old one.
3. Wait for the DNS TTL to pass.
4. Point `certfiles` at the new file and reload ejabberd.
5. The *renewed, but not in use* check stops warning once the switch is done.

If ejabberd's log level is lowered below `debug`, the "Storing certificate" line disappears. The `cert_files` disk check still notices the new file.

`logguard digest` previews today's digest so far; `logguard digest --send` sends it now. After a restart the period continues; the first period after installation starts at installation.

**Hosts without ejabberd** (the VPN node): `[notify]` is off there, so with the cluster on and `notices` in `share`, the digest and all admin-topic alerts are relayed as cluster facts. The XMPP node delivers them to its admins, prefixed with the origin node (`[vpn] logguard daily digest`); its own admin messages carry its name the same way (`[xmpp] logguard daily digest`, `[xmpp] logguard: system`). XMPP clients such as Conversations and Monal don't show a message's subject, so every admin message repeats it, with that tag, as the body's first line. Relayed messages bypass `admin_topics` and are rate-limited per message.

## Readable places (offline geo database)

With `[geo] enabled = true`, addresses are labelled "Germany / Hetzner Online GmbH (AS24940)" in new-login alerts and their user notices, ban messages, compromise alerts, the TUI's Offenders tab (*where* column and details), `status`, `replay` and the digest's top offenders. `logguard geo [--download] <ip>...` looks addresses up by hand.

The TUI's **Countries** tab (7) lists the countries with active bans or tracked offenders, most offenders first, under an *All countries* row. The port histogram (local ports probed, TCP and UDP together, from addresses that aren't allowlisted or trusted; the counts are kept in the state file across restarts and halved once a day, so a probe from a week ago weighs 1/128 of one from today) and the network (ASN) list follow the selected row: select Germany and both show only Germany's traffic, a network present in several countries counting only its addresses there. The histogram for *All countries* works without `[geo]`. Ports are named from the daemon's configuration first (`[ports] names = { "51820/udp" = "WireGuard" }`, then `[xmpp] c2s_ports` as "XMPP client" and the cluster port as "logguard cluster"), then from a built-in list of well-known services (Telnet, RDP, Web HTTPS, STUN/TURN, ...); `tui --actions` has no daemon configuration, so it uses only the built-in names. The **Map** tab (8) draws active bans as red triangles and addresses that logged in during the last hour as green circles, both growing with the count, at each country's capital (`z` zooms on Europe, where capitals crowd together, and back): the free databases name countries, not towns (db-ip's city database would need several times logguard's memory budget). A subnet ban counts once, located by its first address.

- **Nothing leaves the server per lookup.** Two databases are downloaded weekly into `/var/lib/logguard/geo/`, and lookups happen in memory:
  - [DB-IP](https://db-ip.com) **IP to Country Lite** (~4.5 MB gzipped). The country is geolocated per address range, not just where the network is registered, which matters for VPN exits and cloud regions.
  - DB-IP **IP to ASN Lite** (~7 MB). It gives the network owner's real name, e.g. "Cloudflare, Inc.".

  Both are free, need no account, are updated monthly, and are licensed CC BY 4.0, so the digest carries the credit line "IP locations: DB-IP.com". [iptoasn.com](https://iptoasn.com)'s `ip2asn-combined.tsv.gz` (public domain, 9 MB) also works for `asn_url`; it names networks by registry handle ("HETZNER-AS").
- **Cost:** about 1.2 million ranges load in under a second and take about 40 MB of memory. IPv6 is kept at /64 granularity.
- **New-login alerts by provider:** an account's networks are still learned per /16, but a login from a new /16 of a provider (ASN) the account already used is no news. Mobile carriers and VPN services hand out addresses from many /16s, so this removes most of the noise for your VPN users.
- **Failures:** each download must decompress and parse before it replaces the previous copy. A failed refresh raises a daily warning and keeps the old data, and without any database the labels simply don't appear.

## XMPP notifications

logguard warns the affected user, and admins, over XMPP with `ejabberdctl send_message chat <from> <to> <subject> <body>` (`mod_admin_extra`). It doesn't use `announce_send_all`, which would message everyone. Configure it in `[notify]`:

| topic | user | admins | when |
|---|---|---|---|
| `account_attack` | ✓ | ✓ | about 20 failed logins on one account from 3+ addresses within an hour |
| `brute_force` | ✓ | ✓ | an address is banned after failed logins on that account |
| `compromise` | ✓ | ✓ | a successful login right after failures/suspicious activity from the same address |
| `new_network` | opt-in | – | a login from a /16 never seen for that account (after the 7-day learning period) |
| `registration`, `false_positive`, `protected`, `system` | – | ✓ | new account, a banned address that later logged in, an allowlisted/trusted address crossing the threshold, ejabberd hiding IPs |
| `exposure`, `integrity` | – | ✓ | listeners/firewall drift; new or changed cron jobs, infected files, failed or missing virus scans |

- **Shadow mode:** only admins are messaged (`users_in_shadow = false`).
- **Rate limits:** one message per recipient, incident and account every 6 h; an attack alert and the bans it triggers count as one incident. Admin alerts without an account (system, exposure) are de-duplicated by their message. At most `max_per_hour` (30) messages per hour to users in total, and the same again for admins **per topic**, so a flood of account alerts can't silence system or compromise alerts.
- **Languages:** users get their messages in English, French, German, Polish, Russian or Ukrainian. `[notify] language = "en"` sets the default, and `[notify.languages]` overrides it per account, by user name (`alice = "uk"`) or full JID (`"alice@example.org" = "ru"`). Names like `"russian"` work too. Plural forms and ban durations are translated as well ("заблокирован на 6 часов"); place names from `[geo]` stay in English, and admin messages are always English. `notify-test <jid>` sends the test message in that account's language.
- **Only the recipient's own account is mentioned.** When one address attacked several accounts, each user's message names only their own.
- **Only real accounts are warned.** User notices go only to accounts logguard has seen log in successfully. An attacker failing logins against made-up names on your domain can't make the server message them or use up the hourly budget; admins still get the alert.
- **Sending:** happens in a background thread with a 20 s timeout per `ejabberdctl` call, so a slow ejabberd never delays detection.
- **Use `CTL_OVER_HTTP` (ejabberd 25.03 and later).** By default every `ejabberdctl` call starts a second Erlang VM: tens of MB and about half a second each, counted against logguard's memory limit. With `CTL_OVER_HTTP`, `ejabberdctl` sends each command over a local Unix socket using `curl` instead (measured on the XMPP server: 0.15 s, a few MB). Add a listener to the existing `listen:` list, and an entry under the existing `api_permissions:` section (YAML keeps only one copy of a repeated key, so don't start a second one):
  ```yaml
  listen:
    -
      port: "unix:ctl_over_http.sock"
      module: ejabberd_http
      tag: "ctl_over_http"
      unix_socket:
        mode: '0600'          # the ejabberd user and root only
      request_handlers:
        /ctl: ejabberd_ctl
  api_permissions:
    "console commands over http":
      from:
        - tag: "ctl_over_http"
      who: all
      what: "*"
  ```
  Then set `CTL_OVER_HTTP=ctl_over_http.sock` in `ejabberdctl.cfg`, restart ejabberd, and check that `time ejabberdctl status` answers in well under a second. `curl` must be installed.
- **…but send logguard's messages through ejabberd's HTTP API.** `ejabberdctl` over that socket loses messages and garbles text, so logguard doesn't use it for messages:
  - It puts its arguments into JSON without escaping them, so ejabberd rejects every message with a line break or a quote (`HTTP handler crashed: exception error: {invalid_byte,10}` in ejabberd.log), which is nearly every alert and the digest. `ejabberdctl` still exits successfully, so logguard logged them as "notified".
  - ejabberd's `/ctl` handler re-encodes each argument byte by byte, so anything beyond ASCII arrives garbled ("→" as "â" and two boxes; Cyrillic and emoji alike), whoever sends it.
  - The REST API (`mod_http_api`) keeps text intact, but only over TCP: on the Unix socket it answers every call with `400 Bad Request`.

  So add a listener on loopback that serves only `/api`, with a permission that allows only `send_message`:
  ```yaml
  listen:
    -
      port: 5285
      ip: "127.0.0.1"
      module: ejabberd_http
      tag: "logguard_api"
      request_handlers:
        /api: mod_http_api
  api_permissions:
    "logguard notifications":
      from:
        - tag: "logguard_api"
      who: all
      what: send_message
  ```
  and set `api = "127.0.0.1:5285"` in `[notify]`. Every local process can reach that port, so it can send messages as the server, or as any account, and nothing else. **Better: let only a dedicated account call it.** Create `logguard@example.org` with a long random password, put the password in `/etc/logguard/xmpp-api.password` (root, mode 0600), set `api_user = "logguard@example.org"` and `api_password_file = "/etc/logguard/xmpp-api.password"` in `[notify]` (logguard then sends HTTP Basic authentication), and grant the command to that account instead of to `all`:
  ```yaml
  api_permissions:
    "logguard notifications":
      from:
        - tag: "logguard_api"
      who:
        user: "logguard@example.org"
      what: send_message
  ```
  The `from` parameter of `send_message` is still free, so whoever holds that password can send as any JID; the file is root's only. If an existing `api_permissions` entry for `mod_http_api` allows the `loopback` ACL (the stock "http access" one does), it grants local processes *every* command on this listener too; remove `loopback` from it unless something relies on it. Without `api`, logguard can use `ctl_socket = "/absolute/path/ctl_over_http.sock"` (posts proper JSON to `/ctl`: line breaks and quotes work, non-ASCII is garbled and logged as a warning), else `ejabberdctl`. `notify-test` sends two lines with quotes and arrows, so all of this is visible in a test.
- **Only XMPP accounts are messaged.** SSH incidents go to admins only.
- **Admin messages encrypted through the admin bot.** With `bot_outbox` set (the XMPP
  server's `/opt/logguard-xmpp-bot/outbox`), messages to `admins` (alerts and the digest) go to the XMPP
  admin bot (`logguard-xmpp-bot`), which sends them OMEMO-encrypted and keeps them out of the server's
  archive. logguard puts each message in the outbox as a file (`alert-*.msg`, given to
  `bot_user`) and looks every 10 s. A message the bot hasn't taken within `bot_grace` (2m),
  one it refused (addressed to someone other than its admin), and one it started sending and
  never finished is claimed back and sent the usual way above, unencrypted, with a last line
  saying why. If the outbox is missing, messages go the usual way at once. Users' warnings
  always go the usual way. logguard also tells the admins when another file waits in the
  outbox longer than `bot_stuck_after` (1h), i.e. a weekly abuse report the bot can't send.
  `notify-test --bot <admin>` sends a test through the bot and waits for it. The bot's side
  is in logguard-xmpp-bot's README, "Alerts from logguard". The VPN host has no bot: its alerts reach
  the XMPP server through the cluster and go out from there.
- **A copy on Telegram (optional).** With `tg_outbox` set (logguard-tg-bot's `/opt/logguard-tg-bot/outbox`; unset
  by default, and then nothing goes to Telegram), every message to the first of `admins`
  (alerts, the digest, relayed VPN alerts, the bot warnings below) is also put in the Telegram
  bot's outbox, in the same file format and given to `tg_user` (`logguard-tg-bot`). logguard-tg-bot sends it to the
  admin's Telegram chat with XMPP account names replaced by pseudonyms. The XMPP way is
  unchanged, so there is no fallback for the copy: it waits until logguard-tg-bot sends it (logguard-tg-bot drops
  alerts older than a day). When copies wait longer than `bot_stuck_after`, logguard tells the
  admins the XMPP way, at most once per `bot_stuck_after`. Users' warnings never go there.
  `notify-test --telegram` puts a test there and waits up to a minute for logguard-tg-bot. The weekly
  abuse report goes there too (the job reads `tg_outbox`). The bot's side is in logguard-tg-bot's README.
- **A copy by mail (optional).** `mail_outbox` (logguard-mail-bot's `/opt/logguard-mail-bot/outbox`) and
  `mail_user` (`logguard-mail-bot`) work exactly like `tg_outbox` and `tg_user`, next to them or
  instead: every message to the first of `admins` (all admin messages with `admins` empty or
  `xmpp = false`) goes there too, and logguard-mail-bot mails it through the local Postfix or any
  SMTP server, the whole mail (subject included) OpenPGP-encrypted to the recipients' keys. No
  fallback; a mail bot that sits on copies longer than `bot_stuck_after` is reported over XMPP
  and to the Telegram bot (and the other way round). `notify-test --mail` puts a test there and
  waits up to a minute. The weekly abuse report goes there too. The bot's side is in
  logguard-mail-bot's README.
- **Admin messages on Telegram only.** With `tg_outbox` and `admins` empty, admin messages go
  to logguard-tg-bot only and never over XMPP, while users are still warned over XMPP. A Telegram bot
  that leaves messages unsent is then raised as a system alert instead (journal, actions log,
  peers with `relay_notices`). Without ejabberd on the server, use `xmpp = false` instead.

```bash
logguard -c /etc/logguard/logguard.toml notify-test you@example.org     # on the server: one real test message
logguard -c /etc/logguard/logguard.toml notify-test --bot admin@example.org   # the same through the admin bot (OMEMO)
logguard -c /etc/logguard/logguard.toml notify-test --telegram                 # a test through the Telegram bot (logguard-tg-bot)
logguard -c /etc/logguard/logguard.toml notify-test --mail                     # a test through the mail bot (logguard-mail-bot)
logguard -c logguard.toml replay --notify week.json                        # preview what would be sent (sends nothing)
```

On the Sep–Oct month this would have sent 6 admin messages and no user messages; no account was attacked that month.

## Commands

```bash
logguard -c /etc/logguard/logguard.toml run            # the daemon (systemd runs this)
sudo logguard -c /etc/logguard/logguard.toml tui       # live dashboard over the Unix socket
logguard replay --year 2026 weekly.log                 # offline: same pipeline, never touches the firewall
logguard replay -v --snapshot snap.json *.log          # with evidence; then: logguard tui --file snap.json
logguard tui --actions actions.jsonl* [vpn.jsonl ...]  # the state at the end of decision logs (read-only)
logguard print-config                                  # effective configuration (all defaults)
logguard config-diff [--against old-defaults.toml] [--all]   # what an upgrade means for your config file
logguard geo [--download] <ip>...                      # country / network owner from the offline database
logguard integrity                                     # watched cron jobs/timers/scripts, recent virus scans
logguard abuse-report [--since 7d] [--contacts] [-o file]   # evidence per attacker, for abuse desks
logguard cluster-send-report <file>                         # a JSON abuse report to the peers' inbox
logguard replay --state state.json *.log               # also write the state file the daemon would keep
logguard print-nft                                     # ruleset installed in enforce mode
logguard status                                        # plain-text summary: bans, cluster, exposure, offenders
logguard unban <ip|net> / allow <ip|net> --for 7d / disallow <ip|net> / allowed
logguard feeds [status|refresh|clear]                  # blocklist feeds
logguard digest [--send]                               # preview / send the daily digest
logguard cluster-keygen                                # new random cluster key
logguard cluster-key-id [--file deploy/cluster.key]    # fingerprints of the keys in use (compare nodes)
logguard cluster-ufw-rules                             # ufw commands opening the cluster port to peers only
```

`replay` accepts `journalctl` short output and `journalctl -o json`. To test new rules against real traffic first:

```bash
journalctl -u ejabberd -u ssh -k --since -7d -o json > week.json && logguard -c /etc/logguard/logguard.toml replay week.json
```

TUI keys: `1-8`/`Tab` switch tabs (Overview, Offenders, Bans, Events, Accounts, Exposure, Countries, Map) · `↑↓` select · `Enter` shows an address's evidence · `u` unban · `a` allowlist for N days · `s` cycles the minimum severity · `z` zooms the map on Europe · `PgUp`/`PgDn` scroll the networks on the Countries tab · `p` pauses · `q` quits.

`tui --actions <file>...` reads decision logs (`/var/log/logguard/actions.jsonl` and its rotated `.gz` copies, also ones copied to another machine, or the logs of several servers together) without the daemon and shows the state at their end: the bans still active then, the decisions, and per country and network the active bans, the sources banned during the period, their evidence lines and the ports in them. Nothing is re-scored. The tabs are Overview (period, bans per cause, from which peer, bans per hour), Bans, Events, Countries, Map and Trends; scores, accounts and the exposure scan aren't in the log. **Trends** (6) shows bans per day over the whole log (as many recent days as fit) and a table of weeks (Monday to Sunday, UTC), newest first: bans, the change from the week before, distinct sources, and the three countries and networks most bans went to. Use it after a tuning change, e.g. a new `slow_threshold`, to see whether it cut the noise or let more through; merge rotated copies (`actions.jsonl*`) to cover more weeks. Places come from the `[geo]` database when it's set up on that machine, else from the ban messages, which name the place only for bans decided on that server (bans from peers stay "unlocated"). Given several logs, a decision logged twice counts once: the same line in two files, or a ban received from a peer whose own log, with the original ban, is among the files (within 5 minutes). What's still banned at the end is worked out per log, so an unban in one log never ends another server's ban.

## Rollout

1. **Deploy in shadow mode** (the default), next to the existing cron jobs:
   ```bash
   ./deploy/deploy.sh                      # on the Mac: tests, builds the static binary, copies to host "xmpp"
   sudo /tmp/logguard-deploy/install.sh    # on the server
   ```
   UFW logging must be on for firewall signals (`ufw logging low`).
2. **Review for 1–2 weeks** using `logguard tui` and `/var/log/logguard/actions.jsonl`. Look for "likely false positive" and "crossed the ban threshold" (protected-address) alerts, and tune weights in `/etc/logguard/logguard.toml`.
3. **Enforce:** set `mode = "enforce"` and run `systemctl restart logguard`. Then check:
   ```bash
   nft list table inet logguard            # rules + ban sets with remaining timeouts
   ```
   The table hooks at prerouting `priority raw`, so it runs **before** UFW's chains and Docker's DNAT; your ALLOW rules can no longer shadow the bans. Allowlisted networks get an explicit accept in that table too.
   Rollback: set `mode = "shadow"`, restart, then `nft delete table inet logguard`.
4. **Retire the Python pipeline:** remove `/etc/cron.d/log_analyzer` and `/etc/cron.d/daily_log_analyzer`. Keep `daily_cleanup` (ejabberd DB maintenance). Done on both servers in 2026-10; the Python files are gone from this repo too (see the git history).
5. **Delete, never reorder, the old auto-generated UFW deny rules** (`blocked_*`, `ejabberd_*`). They sit below the ALLOW rules, so they never matched traffic to open ports: in Sep–Oct 2026, 4,438 XMPP connections and 106 SSH sessions came from addresses they "deny". Several of them also cover your own users. In that month, people logged in from `11.31.15.0/24`, `11.37.62.0/24`, `11.41.62.0/24`, `11.14.47.0/24`, and `11.23.56.0/24`. Making those rules effective would lock those users out.

## Restarts, reboots and upgrades

**Upgrading:** `install.sh` keeps your `/etc/logguard/logguard.toml` and saves the new template next to it as `logguard.toml.new`. Before replacing the binary, it saves the old version's defaults (`print-config` without a config file). After installing, it runs:

```bash
logguard -c /etc/logguard/logguard.toml config-diff --against <old defaults>
```

That lists unknown options (typos, or removed ones; the daemon refuses to start with them), **new options** with their defaults, **changed defaults** (marked as unaffected if your file sets the option), and whether the file is valid. Run it by hand any time; without `--against` it lists the sections your file doesn't set, and `--all` lists every option.

**The bots' new names (2026-10-17):** `xmppbot` is now `logguard-xmpp-bot` (`/opt/logguard-xmpp-bot`, `logguard-xmpp-bot.service`) and `tgbot` is `logguard-tg-bot` (`/opt/logguard-tg-bot`, `logguard-tg-bot.service`, user `logguard-tg-bot`, the new default of `tg_user`). Deploy this logguard first (its abuse report unit may write to the new outboxes), then each bot: the bot's `install.sh` moves its old install over and rewrites the old outbox paths, `tg_user` and unit names in `logguard.toml` and `/etc/default/logguard-abuse-report` (keeping a copy of each), then restarts logguard. The bots' READMEs have the details.

**Rolling back:** the replaced binary is kept as `/usr/local/bin/logguard.prev`. `logguard --version` shows the git commit a binary was built from (plus ", modified" for uncommitted changes), and `git checkout <commit> && ./deploy/deploy.sh` rebuilds any earlier version.

After a reboot logguard re-applies everything that lives only in the kernel: active bans, operator allowlist entries and blocklist feeds. It resumes the journal from its saved position. If journald no longer accepts that position, for example because old journal files were vacuumed, it falls back to `initial_lookback` instead of retrying forever. Events from history are scored on their own timestamps, and anything carrying wall-clock time (exposure scans, cluster messages, Nextcloud's live logs) waits until the backlog is processed.

## Memory

The unit runs with `MemoryHigh=112M` and `MemoryMax=128M` (child processes included). Measured peaks:

| scenario | logguard | with `[geo]` |
|---|---|---|
| a month of real traffic (Sep–Oct, ~210k records) | ~10 MB | ~50 MB |
| synthetic flood: 280,000 sources, no bans | ~37 MB | ~66 MB |
| synthetic flood: 450,000 sources, 222,700 bans in 42 h | ~80 MB | ~115 MB |

The floods are far beyond what's possible from UFW: its log rules are rate-limited to about 3 lines a minute (the real month had 141,772, which is exactly that). Per-address state is about 600 bytes, and `[scoring] max_tracked_ips` (50,000) bounds it. The real month peaked at about 4,200 addresses over two days. When the cap is reached, the least suspicious 20% are dropped (banned ones last, and they stay banned). The geo database is released before a weekly reload, so two copies never coexist. If memory is ever tight, `[geo] enabled = false` saves 30–40 MB.

## Files

| path | purpose |
|---|---|
| `/etc/logguard/logguard.toml` | configuration (`deploy/logguard.toml` is the annotated template) |
| `/var/lib/logguard/state.json` | journal cursor, bans, repeat offenders, trusted IPs, per-account networks and providers. Gzip-compressed JSON (`zcat state.json \| jq .`; older plain-JSON files are still read). Saved at most every 10 min when something changed, hourly otherwise, and on stop. After a crash the journal is replayed from the saved cursor, and bans live on in the kernel, so nothing is lost. After the Sep–Oct month the file was 95 KB (539 KB before), which is at most ~14 MB of writes a day instead of ~150 MB. An unreadable file is renamed to `state.bad-<time>` (not overwritten), and a high `system` alert says what was lost |
| `/var/lib/logguard/geo/` | offline country and network databases (`[geo]`) |
| `/var/log/logguard/actions.jsonl` | audit log of every ban, unban and alert (rotated weekly by `/etc/logrotate.d/logguard`, 12 weeks kept) |
| `/run/logguard/logguard.sock` | snapshot socket for the TUI (root only) |
| `/etc/logguard/cluster.key` | shared cluster key (mode 0600; same file on every node) |
| `/var/lib/logguard/feeds/` | last good copy of each blocklist feed |
| `/usr/local/sbin/logguard-avscan`, `/etc/systemd/system/logguard-avscan.{service,timer}` | the daily ClamAV scan (`[antivirus]`); settings in `/etc/default/logguard-avscan` |
| `/var/log/logguard/avscan.log` | scan results read by logguard (rotated monthly) |
| `/usr/local/sbin/logguard-abuse-report`, `/etc/systemd/system/logguard-abuse-report.{service,timer}` | the weekly abuse report for the admin bot; settings in `/etc/default/logguard-abuse-report` |
| `/var/lib/logguard/inbox/` | reports peers sent with `cluster-send-report` (mode 0700; deleted once merged) |

## Development

The project is a git repository. `scripts/ci.sh` runs what CI runs: `cargo fmt --check`, clippy with warnings as errors, the tests, `cargo audit` (fails on known vulnerabilities, unsound code and yanked versions of dependencies; unmaintained ones are only reported; offline it uses the advisory database already on disk), the static musl build, and a parse check of both config templates. `deploy/deploy.sh` runs it before every deployment, `scripts/install-hooks.sh` makes every `git push` that touches `logguard/` run it, and `.github/workflows/logguard.yml` runs it on GitHub.

```bash
./scripts/ci.sh                                             # all checks (~1 min); LOGGUARD_SKIP_AUDIT=1 skips cargo audit
cargo test                                                  # tests only
cargo build --release --target x86_64-unknown-linux-musl    # static Linux binary from macOS (rust-lld, see .cargo/config.toml)
cargo install cargo-audit --locked                          # once, for the dependency check
./scripts/install-hooks.sh                                  # once: git push runs ci.sh (skip: git push --no-verify)
```

**Fuzzing.** `fuzz/` holds a cargo-fuzz target, `records`. It feeds arbitrary input in every log format logguard reads (journal JSON, syslog lines, Nextcloud's JSON log) through the parsers and the decision engine, then lets a day pass for their timers. Attackers shape those lines (user names, request paths, banners), so nothing in them may panic, hang or grow without bound. The target's code is `src/fuzzing.rs`. `tests/fuzz_smoke.rs` runs it on stable over the seeds in `fuzz/seeds/records/` (made-up lines with documentation addresses) and 3,000 fixed mutations, so `cargo test` and `ci.sh` keep it working. The real search needs nightly:

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked   # once
cargo +nightly fuzz run records fuzz/corpus/records fuzz/seeds/records -- -dict=fuzz/records.dict -max_total_time=600 -max_len=8192
```

New inputs collect in `fuzz/corpus/` and crashes in `fuzz/artifacts/` (both git-ignored; replay a crash with `cargo +nightly fuzz run records <file>`). Don't seed it from the month of real logs: the corpus would hold real addresses. The first run (2026-10-16: 630,000 inputs in 2 minutes) found nothing.

## Validation

`tests/layouts.rs` runs the daemon itself in each deployment layout ("Deployment layouts"):
the logguard binary with a stand-in `journalctl` (attacks stamped now), a stand-in `nft`
recording every ruleset, a stand-in ejabberd API, the bots' outboxes and peers on 127.0.0.1.
It needs to bind 127.0.0.1 (a sandbox that forbids it fails these tests). It found that every
relayed alert of the same kind after the first was dropped for 6 hours (`[vpn] logguard:
password guessing blocked` for one attacker, then nothing for the next); fixed 2026-10-17.

Replays of the servers' own logs (kept out of this repository) showed:

- **One week of ejabberd logs (August).**
- **One month of all three sources (Sep 11 – Oct 11), about 210k records.** This replays in about 1 s and produces 185 bans of 93 distinct targets: 54 subnets, and hosts whose main trigger was UFW port scanning (83) or XMPP TLS/silent-connection probing. None of those targets ever authenticated successfully, and no user address was banned. The only failed logins that month were 8 expired FAST tokens from real users.

Formats seen in the real logs and handled:
- OpenSSH 10 `sshd-session` lines.
- `kex_exchange_identification` resets without `[preauth]`.
- ejabberd `hidden_by_ejabberd`. This triggers a **high** alert, because client IPs were hidden from Sep 27 to Oct 2 (`hide_sensitive_log_data`), which blinds XMPP detection.
- FAST (`mod_auth_fast`) and SQL-backend logins.
- In-band registrations.
- UFW TCP/UDP/ICMP/GRE blocks, including from Docker bridges.

## Verified on the servers

Both nodes have been running live in enforce mode: the VPN host (Ubuntu 22.04, kernel 5.15) and, since mid-October 2026 after a shadow-mode period, the XMPP server (Debian 13, kernel 6.12).

- **Live journald input** on both hosts: follow, resume from the saved cursor after restarts, and per-source "last log line" ages in `logguard status`.
- **Blocking** on both hosts. On the VPN host (nftables 1.0): table, sets, timeouts and the restore of shadow-mode bans. That includes allowlists with overlapping entries, which used to make the setup fall back to ufw.
- **Self-healing table rebuild** on the VPN host: after `nft delete table inet logguard`, the table came back within 30 s with all its sets and chains (bans, allowlists, operator allows, blocklist feeds, rate limits). Every active ban was re-added with its remaining time, and a high `system` alert reached the admin.
- **Kernel rate limits** on the VPN host: the `rl` chain loads, and `status` reads its drop counters.
- **Cluster** between the two servers: delivery in both directions, the same ban list on both nodes, and repeat offences escalating across nodes. For example, an SSH canary prober was banned on one node and the ban escalated on the other.
- **Exposure watch** with real `/proc/net` and `ufw status`: Docker-published ports are recognised as bypassing ufw, and dead-rule alerts are debounced while containers are recreated.
- **Certificate checks** with `openssl`, including Let's Encrypt's 6-day certificates on the Nextcloud endpoint (judged by their own lifetime).
- **Geo database** downloads (DB-IP lite) and readable places in bans and alerts.
- **Blocklist feeds** on both hosts: Spamhaus DROP (v4 and v6) and FireHOL level 1 download, about 4,700 networks after dropping overlaps, and are active in nftables. The 13 skipped entries are private or reserved ranges (FireHOL lists e.g. `10.0.0.0/8`), networks wider than `min_prefix_v4`/`v6`, and anything overlapping this host, a cluster peer or the allowlist.
- **Operator controls** over the control socket: an `allow` / `allowed` / `disallow` round trip (`unban` uses the same path).
- **Admin notifications** to the XMPP admin account: system, exposure and integrity alerts, the daily digest, and the VPN node's alerts relayed through the cluster.
- **Admin messages through the bot** (`bot_outbox`) on the XMPP server: they reach the admin OMEMO-encrypted, while users' warnings still come from ejabberd in plain text.
- **Cron watch, antivirus results and out-of-memory alerts**: the learn period, change alerts with dpkg origins, the `logguard-avscan` timer, and kernel OOM kills (which uncovered weeks of clamscan being killed for memory, and freshclam being disabled).
- **SSH canary accounts**: real probers trying canary names on the VPN host were banned.
- **Watchdog:** both units run as `Type=notify` with `WatchdogSec=2min`, without watchdog restarts.

## Not yet verified

- **Users' own notifications** (in their language), which are only sent in enforce mode: the XMPP server enforces since mid-October 2026, but none has been confirmed reaching a user yet. `notify-test <jid>` covers delivery and translation.
- **The Telegram copy** (`tg_outbox`, Telegram-only admins, `notify-test --telegram`) and **the Telegram relay node** (`xmpp = false`, `relay_notices`, `peer_accept`, abuse report role `relay`): new in 2026-10, covered by tests on the Mac only (`tests/layouts.rs` runs the daemon in every layout; the report hand-off runs the script with a stand-in logguard). The real `nft` and journald are not part of those runs.
- **The mail copy** (`mail_outbox`, logguard-mail-bot): new on 2026-10-17, covered by tests on the Mac only (the layouts above; the bot against a fake mail server and GnuPG). Not yet sent through a real mail server or opened in Thunderbird, K-9 or FairEmail.
- **The bot fallback:** a message the bot doesn't take (bot stopped, no trusted admin device) going out unencrypted after `bot_grace` is covered by tests on the Mac only.
- **The iptables backend** (`backend = "iptables"`): covered by tests of the rules it builds, not yet run on a host.
- **SSH password guessing:** SSH is key-only on both hosts, so `ssh_auth_fail` is covered only by synthetic tests (`ssh_invalid_user` and canary probes do occur for real).
- **Spoofing:** UFW-only evidence (blocked packets) can carry spoofed source addresses. Weights are kept low, and allowlisted, trusted and private addresses can never be banned.
