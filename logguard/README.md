# logguard

A Rust daemon that replaces the cron-driven `log_analyzer.py`. It follows the systemd journal for **ejabberd** (optional), **sshd** and the firewall's log (**UFW**, **firewalld**) in near-realtime, scores each remote address by its behaviour, and bans attackers through **nftables**, **firewalld**, **ufw**, **iptables** or **ipset** (see "Firewall backends"), and can drop whole countries or networks by the same offline database it labels addresses with. Apache, nginx, HAProxy, Prosody, Nextcloud, ownCloud, MySQL/MariaDB, PostgreSQL, MongoDB, Redis/Valkey, Postfix and Dovecot have built-in sources ("Built-in sources for common services"), other services count through patterns of your own ("Patterns of your own"). Besides attackers it watches the host: `su` and `sudo`, scheduled tasks and other ways back in, package files and set-uid programs, outbound connections and odd processes, patch status, listeners and firewall rules. It is a single static binary of about 8 MB.

```
journalctl -f -o json ──► parsers ──► events ──► engine ──► decisions ──► nftables / ufw / iptables
 (cursor-resumed)         ejabberd PID correlation   decaying scores       ban ladder, expiry
                          ssh / ufw                  subnet + account      actions.jsonl, journal
                                                     analysis              snapshot socket ──► TUI
```

## Contents

1. [Requirements](#requirements)
2. [Deployment layouts](#deployment-layouts)
3. [Firewall backends](#firewall-backends)
4. [How decisions are made](#how-decisions-are-made)
5. [Hosts without ejabberd (e.g. the wg-easy VPN server)](#hosts-without-ejabberd-eg-the-wg-easy-vpn-server)
6. [Nextcloud (AIO)](#nextcloud-aio)
7. [Built-in sources for common services](#built-in-sources-for-common-services)
8. [Patterns of your own](#patterns-of-your-own)
9. [Tripwire ports](#tripwire-ports)
10. [Kernel tripwires](#kernel-tripwires)
11. [Honeypot ports](#honeypot-ports)
12. [Canary accounts](#canary-accounts)
13. [su and sudo](#su-and-sudo)
14. [PAM, account changes and auditd](#pam-account-changes-and-auditd)
15. [Desktops and laptops](#desktops-and-laptops)
16. [Exposure watch](#exposure-watch)
17. [Cron watch](#cron-watch)
18. [Antivirus: ClamAV's scheduled scans, and scans of changed files](#antivirus-clamavs-scheduled-scans-and-scans-of-changed-files)
   - [Scans of changed files](#scans-of-changed-files)
19. [Package and set-uid check](#package-and-set-uid-check)
20. [Process watch](#process-watch)
21. [Patch status](#patch-status)
22. [SSH audit](#ssh-audit)
23. [Abuse reports](#abuse-reports)
24. [Self-healing firewall table](#self-healing-firewall-table)
25. [Kernel rate limits](#kernel-rate-limits)
26. [Quiet sources and the systemd watchdog](#quiet-sources-and-the-systemd-watchdog)
27. [Cluster: sharing attack information between servers](#cluster-sharing-attack-information-between-servers)
   - [Node identities](#node-identities)
   - [A Telegram relay node](#a-telegram-relay-node)
28. [Web console (logguard-web)](#web-console-logguard-web)
29. [Blocklist feeds (optional)](#blocklist-feeds-optional)
30. [WAF decisions: CrowdSec and others (optional)](#waf-decisions-crowdsec-and-others-optional)
31. [Blocking countries and networks (optional)](#blocking-countries-and-networks-optional)
32. [Daily digest (optional)](#daily-digest-optional)
33. [Readable places (offline geo database)](#readable-places-offline-geo-database)
34. [XMPP notifications](#xmpp-notifications)
35. [Commands](#commands)
36. [Install from a release bundle](#install-from-a-release-bundle)
37. [Install from a package](#install-from-a-package)
38. [Rollout](#rollout)
39. [Restarts, reboots and upgrades](#restarts-reboots-and-upgrades)
40. [Memory](#memory)
41. [Files](#files)
42. [Development](#development)
43. [Validation](#validation)
44. [Verified on the servers](#verified-on-the-servers)
   - [On a Fedora test server (2026-10-25)](#on-a-fedora-test-server-2026-10-25)
44. [Not yet verified](#not-yet-verified)

## Requirements

The binary is static (musl): no Rust, libc version or packages are needed to run it. What it
works with on the host:

| what | needed for | notes |
|---|---|---|
| Linux on x86_64, aarch64 (arm64) or 32-bit ARMv7 with hardware floating point, systemd | everything | runs as a `Type=notify` unit; tested on Debian 13 (kernel 6.12) and Ubuntu 22.04 (kernel 5.15), and briefly on Fedora 44 (kernel 7.2), all x86_64. The ARM binaries pass CI (the tests natively on aarch64; armv7 is linted and started under qemu) but haven't run on an ARM server yet |
| `journalctl` (systemd-journald) | all log input | follows the journal as JSON; journald must keep the logs of sshd, the kernel and ejabberd. Lines count only from their real senders, by journald's own fields: sshd's from root, ejabberd's from a unit named `ejabberd*`, the kernel's and systemd's (PID 1) |
| **one firewall backend** | enforce mode | `nft` (the default; nft 1.0 on kernel 5.15 and Debian 13's on 6.12 are verified), or `firewall-cmd` (firewalld running; policies from 0.9), or `ufw`, or `iptables` + `ip6tables` (legacy or nf_tables flavour, with the `mangle` table, `conntrack` and `multiport`), the latter with `ipset` too for the ipset backend. Shadow mode needs none. |
| `nft` | rate limits, blocklist feeds, `[waf]` lists | only the nftables backend has rate limits; feeds and `[waf]` lists also with ipset (`[waf]` bans work with every backend) |
| firewall logging | firewall signals (port scans, tripwires) | `ufw logging low`, or `firewall-cmd --set-log-denied=unicast`, or with plain iptables a LOG rule with the prefix `[LOGGUARD BLOCK] ` (see "Firewall backends") |
| `ufw`, else `firewall-cmd`, else `iptables` + `ip6tables` | exposure watch's firewall view | without an active ufw, firewalld's zones (`firewall-cmd --list-all-zones`, every 5 minutes), else the filter table's `INPUT` chain (`iptables -S`); nftables rulesets of their own are noticed but not read; with no firewall at all, listeners are still watched and the TUI says so in red |
| `ejabberdctl`, or ejabberd's HTTP API on loopback | XMPP notifications | see "XMPP notifications"; reading ejabberd's log needs nothing extra |
| `openssl` | certificate checks in the daily digest | |
| `curl` | blocklist feeds, geo database downloads, `[waf]` sources read from a URL | 7.55 or later for `[waf] api_key_file` (`-H @-`) |
| `docker` | the Nextcloud AIO source | reads `docker logs -f` of the Apache container |
| `df` | disk space watch | coreutils |
| `apt-get`, or `dnf` | patch status (`[patches]`) | apt: a simulation (`-s`) only (Debian, Ubuntu); dnf: `--cacheonly check-update` (Fedora, RHEL), with `package_manager = "dnf"` |
| dpkg's database, or `rpm` | package origins of changed files, the weekly package check | `package_manager`: `"apt"` (the default) reads `/var/lib/dpkg`, `"dnf"` asks `rpm -q` |
| `sshd` | the SSH audit (`[ssh_audit]`) | `sshd -T` (and `-C` per user) prints the effective settings; without it, they are read from the files |
| `tail` | log files of `[[patterns]]` and `[sources] apps`, auditd's file (`audit_log`) | coreutils |
| auditd, or journald's audit socket | the audit log's alerts (`[sources] audit`) | optional; journald reads audit records where its audit socket runs, `audit_log` names auditd's file instead |
| nftables `fib` and dynamic sets | kernel tripwires (`[ports] kernel_tripwires`) | in Debian's and Ubuntu's kernels; where missing, logguard runs without them and says so |
| ClamAV (`clamscan`/`clamdscan`) | the `logguard-avscan` timer; `[antivirus] scan_changed` "clamav"/"both" | optional |
| YARA (`yara` 4.1 or later) and rules | `[antivirus] scan_changed` "yara"/"both" | optional; `systemd-run` (systemd 235 or later) runs the scanners outside logguard's memory limit |
| the XMPP admin bot (`logguard-xmpp-bot`) | encrypted admin messages | optional, `[notify] bot_outbox` |
| the XMPP client bot (`logguard-xmpp-bot` with `BOT_MODE=client`) | a copy of admin messages over XMPP, OMEMO-encrypted, from an account on any server; no ejabberd needed (a VPN server, a relay node, a desktop) | optional, `[notify] xmpp_outbox` |
| the Telegram admin bot (`logguard-tg-bot`) | a copy of admin messages on Telegram | optional, `[notify] tg_outbox` |
| the mail bot (`logguard-mail-bot`) | a copy of admin messages by mail, OpenPGP-encrypted | optional, `[notify] mail_outbox` |
| the Signal bot (`logguard-signal-bot`, with signal-cli) | a copy of admin messages on Signal | optional, `[notify] signal_outbox` |
| the Matrix bot (`logguard-matrix-bot`) | a copy of admin messages on Matrix, end-to-end encrypted | optional, `[notify] matrix_outbox` |

To build: Rust (stable) with the `x86_64-unknown-linux-musl` target (`aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf` for ARM); `deploy/deploy.sh` builds on a Mac.

**Fedora and RHEL:** set `package_manager = "dnf"` (top of the config, before any section), or start from a `-dnf` template (`logguard-dnf.toml`, `logguard-standalone-dnf.toml`, `logguard-tg-dnf.toml`; `scripts/dnf-templates.sh` writes them from the others). Package lookups then ask rpm, pending updates dnf. Tried on a Fedora 44 server ("Verified on the servers"). Fedora has no ufw (firewalld instead): use the nft backend, and `[sources] ufw` sees no firewall lines unless something logs them with ufw's prefix.

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
| logguard-xmpp-bot, logguard-tg-bot, logguard-mail-bot | none (peers work as above) | `bot_outbox` + `tg_outbox` + `mail_outbox` + `admins` | off | OMEMO through logguard-xmpp-bot, a copy on Telegram and one by mail | over XMPP | `merge`, to all three |
| logguard-signal-bot | none | `xmpp = false` + `signal_outbox` (no ejabberd), or `signal_outbox` with no `admins` (with ejabberd) | off | on Signal only (OpenPGP files while the admin's safety number isn't the pinned one) | over XMPP where ejabberd runs | `merge` at once, to logguard-signal-bot |
| logguard-matrix-bot | yes | the same with `matrix_outbox`, or a relay node of its own (as `deploy/logguard-tg.toml`) | on, `relay_notices` on the nodes that deliver themselves | on Matrix, end-to-end encrypted (OpenPGP files when that isn't possible), the peers' relayed too | over XMPP | as logguard-tg-bot: `merge` on its server, or `relay` on a relay node |
| all five | none (peers work as above) | `bot_outbox` + `tg_outbox` + `mail_outbox` + `signal_outbox` + `matrix_outbox` + `admins` | off | OMEMO through logguard-xmpp-bot and a copy through each of the others | over XMPP | `merge`, to all five |
| logguard-xmpp-bot in client mode (a desktop, a lone server) | none | `xmpp = false` + `xmpp_outbox` (no ejabberd) | off | over XMPP from the bot's account on any server, OMEMO-encrypted (OpenPGP files when OMEMO can't reach the admin) | none (no XMPP server here) | `merge` at once, to the client bot |
| logguard-xmpp-bot in client mode | yes | the same, or a relay node of its own (as `deploy/logguard-tg.toml`, with `xmpp_outbox`) | on, `relay_notices` on the nodes that deliver themselves | as above, the peers' relayed too | over XMPP | as logguard-tg-bot: `merge` on its server, or `relay` on a relay node |

- **Users** are XMPP accounts: they are warned over XMPP by the server their account is on,
  whatever bots run. Telegram, mail, Signal and Matrix never get users' warnings (and Telegram
  never their account names, logguard-tg-bot's README; the mail, Signal and Matrix bots only
  with `SANITIZE=off`, their default, end-to-end encrypted).
- **Admin messages through copy bots only, on an XMPP server:** set `tg_outbox`, `mail_outbox`,
  `signal_outbox` or `matrix_outbox` (any of them together) and leave `admins` empty. (Not
  `xmpp_outbox`: logguard-xmpp-bot runs once per host, and on an XMPP server it is the admin bot,
  `bot_outbox`; logguard refuses both.) Users are
  still warned over XMPP; a bot that stops sending is then reported as a system alert (journal,
  actions log, the other copy bots, and relayed to peers with `relay_notices`).
- **A server that delivers nothing itself** (`[notify]` off) relays its admin messages to its
  peers when the cluster is on; otherwise they are in its journal and actions log only.
- **The abuse report job** finds the bots' outboxes from `[notify] bot_outbox`, `tg_outbox`, `mail_outbox`, `signal_outbox`, `matrix_outbox` and `xmpp_outbox`
  (`/etc/default/logguard-abuse-report` can override them), merges at once on a server without
  peers, and refuses `send`/`relay` there. With `xmpp_outbox` set, `/opt/logguard-xmpp-bot/outbox`
  is the client bot's and no longer the admin bot's default.

## Firewall backends

`[enforce] backend` picks how bans are applied. `auto` (the default) tries nftables first, then firewalld if it runs, then ufw if it is installed, then iptables (`ipset` only when named). If none works, logguard stays in shadow mode and says why. A fallback after nftables failed raises a high `system` alert.

| | `nft` | `firewalld` | `ufw` | `iptables` | `ipset` |
|---|---|---|---|---|---|
| where | own table `inet logguard`, prerouting right after connection tracking | ipsets `logguard-ban4`/`-ban6`, the sources of a zone `logguard` with target `DROP` | `ufw prepend deny` rules | own chains `logguard` and `logguard-ban` in the mangle table, jumped to from the top of `PREROUTING` | the same chains, matching ipset sets `logguard-ban4`/`-ban6`, `logguard-feed4`/`-feed6`, `logguard-waf4`/`-waf6` |
| before Docker's published ports | yes | yes, with a policy `logguard-fwd` (firewalld 0.9 and later) | no | yes | yes |
| bans end | in the kernel (set timeouts), also while logguard is down | when logguard removes the entry | when logguard removes the rule | when logguard removes the rule | in the kernel (ipset timeouts, up to 24 days; longer ones when logguard lifts them) |
| whitelisted ports stay open for banned addresses | yes | yes (the zone's ports) | no | yes | yes |
| rate limits | yes | no | no | no | no |
| blocklist feeds | yes | no | no | no | yes |
| many bans | one set lookup | one set lookup | one rule each | one rule each | one set lookup |
| self-healing | table rebuilt within 30 s | entries restored within 30 s of a reload | – | chains rebuilt within 30 s | chains and sets rebuilt within 30 s |

No backend drops replies to connections the server opened itself. A banned address can be forged (one SYN to a tripwire port names any source), and the server must not lose its DNS resolver, mail relay, update mirrors or federated XMPP servers that way. nftables and iptables therefore drop after connection tracking, which tells replies apart; ufw's own rules accept them before logguard's. Versions before 2026-10-24 dropped earlier (nftables chain `pre` at raw priority, iptables chains in the raw table), replies included; at its first start, this version removes those.

**iptables** is meant for hosts that manage their firewall with plain iptables, e.g. with `iptables-persistent` (`netfilter-persistent`), instead of ufw. logguard never touches your own rules or chains; it only adds its two chains to the mangle table and one jump at the top of the mangle `PREROUTING` chain, for IPv4 (`iptables`) and IPv6 (`ip6tables`):

- `logguard`: allowlisted networks, whitelisted ports and replies to the server's own connections `RETURN`, then a jump to `logguard-ban`. Rebuilt when the allowlist changes.
- `logguard-ban`: operator allows (`RETURN`) at the top, then one `DROP` rule per ban.

Allowed traffic `RETURN`s rather than `ACCEPT`s, so other rules in the mangle table still apply. At start logguard empties `logguard-ban` and re-adds the bans and allows that are still active from its state file. So if `netfilter-persistent save` stored them while logguard ran, a reboot or `netfilter-persistent reload` restoring stale bans does no harm: they're replaced as soon as logguard starts. If a reload removes the chains or the jump, logguard rebuilds them within 30 s (high `system` alert). Bans don't expire in the kernel: one stays until logguard (running) lifts it. Paths and the chain name are set in `[enforce]` (`iptables`, `ip6tables`, `iptables_chain`).

For firewall signals, iptables must log what it drops, with the prefix logguard reads (`[sources] ufw` covers these lines too). Add it as the last rules of `INPUT`, before its DROP policy or final DROP rule, and save it with your other rules:

```bash
iptables  -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[LOGGUARD BLOCK] '
ip6tables -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[LOGGUARD BLOCK] '
```

For the cluster port, `logguard cluster-ufw-rules --iptables` prints the rules that open it to the peers only; `install.sh` shows them when there is no ufw.

**firewalld** (Fedora, RHEL and its rebuilds) keeps its own objects, so `firewall-cmd --list-all-zones` shows what logguard does. At its first start logguard adds to firewalld's permanent configuration (firewalld makes ipsets and zones nowhere else) and reloads it once:

- ipsets `logguard-ban4` and `logguard-ban6` (`hash:net`), the sources of a zone `logguard` whose target is `DROP`. A source-bound zone comes before the interfaces' zones, so firewalld drops everything from a banned network, except the zone's ports (`[ports] whitelist`, kept in step at each start) and replies to the server's own connections (firewalld accepts established traffic before any zone).
- a policy `logguard-fwd` from that zone to `ANY`, target `DROP`: their forwarded traffic too (ports published by Docker or Podman). firewalld before 0.9 has no policies: logguard says so and goes on without it.
- an ipset `logguard-alive` no rule uses, holding one entry (192.0.2.1).

The bans themselves are runtime entries (`firewall-cmd --ipset=logguard-ban4 --add-entry=...`), never permanent: at start logguard empties the sets and re-adds the active bans from its state file, so nothing of a ban outlives logguard. `firewall-cmd --reload` or a firewalld restart forgets them, the sentinel entry with them: within 30 s logguard notices and re-adds them (high `system` alert). An operator allow lifts the bans inside it, as with ufw, but can't open a gap in a wider ban (a zone's sources have no exceptions). No rate limits, blocklist feeds or kernel tripwires (nftables only). With nftables, `auto` still prefers its own table, which works next to firewalld's; name `firewalld` to have firewalld hold everything. Its log lines: `firewall-cmd --set-log-denied=unicast` makes firewalld log what its zones reject or drop (`filter_IN_public_REJECT: ...`), which `[sources] ufw` reads as firewall signals, like UFW's (not those of the `logguard` zone: its sources are banned already). `install.sh` opens the cluster port to the peers with permanent rich rules (`cluster-ufw-rules --firewalld` prints them) and says when denied packets aren't logged.

**ipset** is the iptables backend for many bans: the same chains and allow rules, but `logguard-ban` matches its ipset sets (bans, feeds, `[waf]` lists, `[geoblock]`; IPv4 and IPv6), one rule each, instead of one rule per ban. Bans carry their time in the kernel (`ipset add ... timeout`), so they end while logguard is down too; a ban longer than ipset's limit (2,147,483 s, about 24 days) goes in without one and logguard lifts it. Blocklist feeds load into `logguard-feed4`/`-feed6`, `[waf]` lists into `logguard-waf4`/`-waf6`. At start the ban sets are emptied and refilled from the state file. Needs `ipset` and the `xt_set` match; the set names start with `iptables_chain`.

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
| `fw_block` / `fw_limit` | 1 / 20 | UFW BLOCK / UFW LIMIT BLOCK: kernel lines that start with the prefix and go on with `IN=... OUT=...`, as only the packet logger writes them (other kernel lines start with a name any user picks, such as a crashing program's) |
| `fw_tripwire` | 100 | UFW BLOCK on a `[ports] tripwire` port (telnet, mail, RDP, VNC, SMB, databases, ...), or the same SYN logged by logguard's own rule ("Kernel tripwires"): one hit = ban. 50 when `[ports] honeypot` is set |
| `tripwire_connect` | 100 | a completed TCP handshake with a `[ports] honeypot` listener ("Honeypot ports"): its source isn't forged |
| `peer_report` | reported points × 0.5 | suspicion reported by another cluster node |
| `web_probe` | 40 | Nextcloud: request for secrets refused (`/config/.env`, `aws.yml`, `secrets.yml`…) or path traversal (`/../.env`) |
| `nc_auth_fail` | 25 | Nextcloud: failed login |
| `pam_auth_fail` | 25 | a failed login PAM logs from an address on the internet, at a service with no parser of its own (vsftpd, Cockpit, ...; "PAM, account changes and auditd") |
| `custom_failure` / `custom_probe` | the pattern's `weight` | a line a pattern of your own or a built-in one of `[sources] apps` matched ("Patterns of your own", "Built-in sources for common services"); `custom_success` is a login |

Weights are calibrated against the 10-minute half-life: **40** means three strikes within about 5 minutes ban; **25** means five strikes within about 5 minutes. With 34, three strikes only added up when all came within about 25 seconds, so a scanner pausing 30 s between requests was never banned.

Bonuses: **+60** when one address touches **3 or more XMPP ports** within 10 min (port spread), and **+60** when UFW drops it on **8 or more distinct ports** (port scan).

**Protection.** Private, loopback, link-local and CGNAT addresses are ignored entirely; for example, a Docker container hitting the host's public IP is blocked by UFW about once a minute. Allowlisted addresses are never banned. Addresses that **authenticated successfully** within `trust_ttl` (24 h) aren't banned for that service's noise and typos, nor for blocked packets on any port (see "Canary accounts"). Noise signals from them score 0. Real failures still raise an alert. A subnet containing a protected address is never banned.

**Subnets.** Every 60 s a /24 (or IPv6 /64) is banned in either of two cases:
- 3 or more of its addresses are individually bad (concentrated attack).
- 5 or more addresses together reach a summed score of 100 (distributed scanning, e.g. `11.37.48.0/24` probing once per IP).

A banned /24 then grows step by step, up to a /16 (`v4_wide_prefix`). It grows to the narrowest network that also holds the next ban nearby, either an address or another subnet, and at most 2 prefix bits at a time (`wide_max_step`). For example, `11.20.59.0/24` plus a banned `11.20.57.7` becomes `11.20.56.0/22`, and that /22 grows to a /20 with the next ban inside the /20. An address 5 bits away (`11.20.36.5`, common network /19) stays a host ban until the range has grown close enough. Growth stops before any network with a protected address. With the `[geo]` network database loaded, it also stops before a network that holds another provider's (ASN's) addresses. The rest of a cloud provider's /16 stays reachable: other customers, VPN exits. The TUI's status and the daily digest show how many addresses the subnet bans cover, and the widest one. This replaces the earlier single step from 12 bad addresses over 4 /24s straight to the whole /16. `wide_min_bad_ips` and `wide_min_subnets` are still accepted in old config files, but they are ignored, and `config-diff` lists them.

IPv6 /64 bans grow the same way, up to `v6_wide_prefix` (/48), `wide_max_step_v6` (4) bits at a time: providers hand out /64s, /60s, /56s and /48s, and an attacker rotating through a /56 shows up as /64 after /64. `3fff:130:1:2::/64` plus a ban in `3fff:130:1:3::/64` becomes `3fff:130:1:2::/63`; a ban in `3fff:130:1:8::/64` then takes it to the /60. `v6_wide_prefix = 64` keeps IPv6 bans at /64. A peer's IPv6 ban wider than this node's own widest is ignored, as for IPv4.

**Ban ladder.** Bans last 1h → 6h → 1d → 7d → 30d per repeat offence. The offence counter resets after 30 days without a new ban.

**Accounts.** Alerts are raised for:
- Distributed password guessing against one account: about 20 failures from 3 or more IPs within an hour.
- A login right after suspicious activity from the same IP: **critical**, possible compromise.
- A login from a new /16, after a 7-day learning period.
- An SSH login with a key the account never used before (**high**): the key is in sshd's `Accepted publickey ... ssh2: ED25519 SHA256:...` line. Each account's keys are learned silently for `learning_period` (7 days) after the first one is seen, then a new one is reported once and becomes known. If nobody added a key, the account's `authorized_keys` was changed (the cron watch reports that file too). `[accounts] new_key_alerts = false` turns it off.

**Shadow-mode self-check.** If a "banned" address later logs in successfully, a *likely false positive* alert is raised and, in shadow mode, the ban is lifted (here and at the peers). In enforce mode a banned address can't connect, so a login line naming one is suspect: the alert says so and the ban stays (`logguard unban` it if it is a false positive).

## Hosts without ejabberd (e.g. the wg-easy VPN server)

```bash
./deploy/deploy.sh vpn deploy/logguard-standalone.toml      # ssh alias "vpn"; then paste the printed command into a root shell there
```

[`deploy/logguard-standalone.toml`](deploy/logguard-standalone.toml) sets three things:
- `[sources] ejabberd = false`: the journal filter and the pipeline skip ejabberd entirely.
- `[ports] whitelist = ["51820/udp"]`: wg-easy's `WG_PORT`. The panel (`PORT=51821`) is no longer published, so it is not whitelisted.
- `notify.enabled = false`: there is no `ejabberdctl` on that host.

Whitelisted ports (`PORT/udp`, `PORT/tcp`, or a bare `PORT` for both) work as follows:
- **Never scored:** UFW blocks or other events on them don't count towards a ban.
- **Never blocked in enforce mode:** an `accept` for them precedes the ban drop, so even a banned address can still reach them.

**Docker:** ports published with `docker run -p` bypass UFW and the host INPUT chain. logguard therefore hooks nftables at **prerouting** (right after connection tracking, before Docker's DNAT), so bans do cover Docker-published ports. The iptables backend covers them the same way (mangle `PREROUTING`). The ufw fallback can't do this, and it can't keep whitelisted ports open either; logguard warns about this at startup.

**The wg-easy panel:** the WireGuard port is safe to whitelist, because it silently ignores unauthenticated packets. The admin panel is not: whitelisting it lets banned scanners keep trying its login page. Prefer not exposing it at all. Drop `--publish 0.0.0.0:51821:51821/tcp` and open `http://10.8.0.1:51821` while connected to the VPN: the panel listens inside the container, which owns the WireGuard interface. Alternatively publish it as `127.0.0.1:51821:51821/tcp` and use an SSH tunnel. Then remove `51821/tcp` from the whitelist.

## Nextcloud (AIO)

For a Nextcloud without AIO (distribution packages, the snap, your own web server) and for ownCloud 10, use `[sources] apps = ["nextcloud"]` or `["owncloud"]` instead ("Built-in sources for common services").

`[sources] nextcloud_aio = true` reads two things, with no change to Docker or AIO (until 2026-10-26 the option was called `nextcloud`, and its section `[nextcloud_aio]` was `[nextcloud]`; both old names still work, and `config-diff` points them out):
- **`docker logs --follow --timestamps nextcloud-aio-apache`.** Apache's error log shows every refused request with the client IP. It's restarted automatically when the container is recreated (AIO updates, reboots), resuming after the last line seen.
- **`tail -F` of `nextcloud.log`** (`/var/lib/docker/volumes/nextcloud_aio_nextcloud/_data/data/nextcloud.log`; `occ log:file` shows the path inside the container) for `Login failed: user (Remote IP: …)`. This is the same file AIO's own fail2ban container reads; failures count per account like XMPP and SSH ones.
- **Restarts lose nothing:** the time of the last line read from each of the two is kept in the state file. After a restart, `docker logs` resumes from that moment and `nextcloud.log` is re-read from its last 2,000 lines; lines already seen are skipped by their timestamps. Login names from these logs are attacker-chosen: control characters are removed before they reach alerts or a terminal.

On the Oct 2–11 Apache log this bans each Google-Cloud `.env`/`aws.yml`/`config.js` prober on its third request. The daily `11.42.52.117` escalates 1h → 6h → 1d → 7d. Docker-published ports bypass UFW, but logguard's nftables chain sits in prerouting, so these bans apply to Nextcloud too.

## Built-in sources for common services

Web servers, a load balancer, Prosody, Nextcloud and ownCloud, databases, in-memory stores, mail and logguard's own web console need no patterns of your own: name them in `[sources] apps` and logguard reads their logs with built-in patterns (`src/parse/apps.rs`, each tested against real and forged lines):

```toml
[sources]
apps = ["nginx", "postgresql", "redis"]

[sources.app_logs]           # only for a log that isn't in the usual places
nginx_access = ["/srv/www/logs/access.log", "/srv/www/logs/api-access.log"]   # absolute paths, * in a file name
postgresql = "postgresql@17-main.service"                                       # or a unit: its journal

[sources.app_weights]        # points of a built-in pattern, if not its default
nginx_limit = 0
nginx_survey = 100           # ban internet survey scanners at once
```

| app | log (key in `app_logs`), where it is looked for | patterns: what counts, points |
|---|---|---|
| `apache` (httpd 2.2 and 2.4) | `apache_access`: `/var/log/apache2/*access.log`, `/var/log/httpd/*access_log`; `apache_error`: `*error.log`, `*error_log` there | `apache_probe` 40: requests for secrets and exploits (below); `apache_proxy` 20: absolute URLs and `CONNECT` (open-proxy tests); `apache_scanner` 40 / `apache_survey` 20: user agents of attack tools / survey scanners (below); `apache_auth` 25: Basic auth wrong password or unknown user (AH01617/AH01618); `apache_traversal` 40 (AH10244); `apache_badreq` 10: invalid method, URI too long, no Host; `apache_denied` 20: refused by `Require` (AH01630/AH01797) |
| `nginx` | `nginx_access`: `/var/log/nginx/*access.log`; `nginx_error`: `/var/log/nginx/*error.log` | `nginx_probe`, `nginx_proxy`, `nginx_scanner`, `nginx_survey` as for Apache; `nginx_auth` 25: `auth_basic` password mismatch, unknown user; `nginx_denied` 20: `deny`; `nginx_limit` 8: `limit_req`/`limit_conn` rejections |
| `haproxy` | `haproxy`: `/var/log/haproxy.log`, else `haproxy.service` | `haproxy_probe` 40 (`option httplog`); `haproxy_denied` 20: termination state `PR`/`PT` (`http-request deny`, tarpit, bad request); `haproxy_tls` 10: TLS handshake failures |
| `prosody` | `prosody`: `/var/log/prosody/prosody.log`, else `prosody.service` | `prosody_auth` 25: failed logins, as [mod_log_auth](https://modules.prosody.im/mod_log_auth) logs them (enable it: Prosody itself logs no address) |
| `mysql` (MySQL, MariaDB, Percona) | `mysql`: `/var/log/mysql/error.log`, `/var/log/mysqld.log`, `/var/log/mariadb/mariadb.log`, else the journal of `mariadb.service`, `mysql.service` or `mysqld.service` | `mysql_auth` 25: `Access denied for user`; `mysql_preauth` 8: connections closed before authenticating. Needs `skip_name_resolve = ON` (else the log names hosts, not addresses); MySQL 8 also `log_error_verbosity = 3` (MariaDB logs them by default) |
| `postgresql` | `postgresql`: `/var/log/postgresql/postgresql-*.log`, `/var/lib/pgsql/data/log/postgresql-*.log`, else `postgresql.service` | `postgresql_auth` / `postgresql_role` 25: wrong password, unknown role; `postgresql_hba` 25: no `pg_hba.conf` entry; `postgresql_preauth` 8: broken startup packets, failed TLS. Needs the client in the prefix right after the pid: `log_line_prefix = '%m [%p] %h %q%u@%d '`, and English messages (`lc_messages = 'C'`) |
| `mongodb` (4.4 and later) | `mongodb`: `/var/log/mongodb/mongod.log`, else `mongod.service` | `mongodb_auth`, `mongodb_auth_v6` 25: failed authentication (both message forms) |
| `redis` (Redis, Valkey, KeyDB) | `redis`: `/var/log/redis/redis-server.log`, `redis.log`, the Valkey and KeyDB ones, else their units | `redis_attack` 40: HTTP sent to the Redis port ("Possible SECURITY ATTACK"); `redis_tls` 10: failed TLS handshakes. Redis doesn't log failed `AUTH` (only `ACL LOG` shows them): keep it off the internet |
| `nextcloud` (without AIO: packages, the snap, your own web server) | `nextcloud`: `nextcloud.log` in `/var/www/nextcloud/data/`, `/var/www/html/nextcloud/data/`, `/var/www/html/data/`, `/srv/nextcloud/data/`, the snap's `/var/snap/nextcloud/current/logs/`, `/var/log/nextcloud/`, `/var/log/` (`occ log:file` shows yours) | `nextcloud_auth` 25: `Login failed`; `nextcloud_bruteforce` 40: its own brute-force protection slowing an address down (logged at `loglevel` 1 and below). Its web server's probes come from `apache` or `nginx` (the snap's Apache logs are among the places `apache` looks). Behind a reverse proxy, set `trusted_proxies`, or every line names the proxy. Names in `[canary] nextcloud` are canaries. Not together with `[sources] nextcloud_aio`: both read the same failed logins |
| `owncloud` (ownCloud 10) | `owncloud`: `owncloud.log` in `/var/www/owncloud/data/`, `/var/www/html/owncloud/data/`, `/var/www/html/data/`, the Docker image's `/mnt/data/files/`, `/var/log/owncloud/` | `owncloud_auth` 25: `Login failed`; names in `[canary] nextcloud` are canaries. Not ownCloud Infinite Scale (oCIS), whose log is another |
| `postfix` | `postfix`: the journal of `postfix@-.service` or `postfix.service`, else `/var/log/mail.log`, `/var/log/maillog` | `postfix_sasl` 25: SASL login failures; `postfix_relay` 25: relay attempts |
| `dovecot` | `dovecot`: the journal of `dovecot.service`, else the mail log | `dovecot_auth` 25: IMAP/POP3/ManageSieve logins that failed |
| `logguard-web` (the web console, below) | `logguard_web`: the journal of `logguard-web.service` | `logguard_web_login` 25: failed console logins (wrong password or one-time code), and attempts while the address is locked out; `logguard_web_probe` 40: probes (as for Apache) for paths the console doesn't have; `logguard_web_refused` 20: connections from outside `CONSOLE_ALLOW`/`AGENT_ALLOW`; `logguard_web_agent` 20: requests to an agent without the web key |

- **Where:** a log with several files in the usual place (Apache's and nginx's per-site `example.org-access.log`) is followed in all of them, up to 16, found when logguard starts. Without one, the installed unit's journal is read. Postfix and Dovecot prefer the journal: `/var/log/mail.log` is written by syslog, where any local user can log lines in Postfix's name, while journald names the real sender. HAProxy usually logs only to `/var/log/haproxy.log` (from a chroot), which has the same weakness: if local users aren't trusted, send its log to the journal and set `haproxy = "haproxy.service"`. At start, logguard's journal says where it reads each log (`[sources] apps: nginx access log: ...`), and the Patterns tab shows each built-in pattern with its lines: none means the log isn't where logguard looks.
- **Probes** are requests no legitimate client sends: secrets (`/.env`, `/.git/`, `/.aws/`, `/.ssh/`, `.htpasswd`, `wp-config.php`, `id_rsa`, `docker-compose.yml`), path traversal (`../`, `%2e%2e`, `..;/`), well-known exploits (Log4Shell `${jndi:`, PHPUnit's `eval-stdin.php`, router and IIS worms such as `cmd.exe`, `root.exe`, Code Red's `.ida?`, FrontPage's `_vti_aut`, awstats' `configdir=`, `wget+http` in a URL). Not `wp-login.php`, `xmlrpc.php` or `/phpmyadmin/`: a site may have them. Tested on two Honeynet Project honeypots' Apache logs (SotM 34 and the 2005 honeynet bundle, [log-sharing.dreamhosters.com](https://log-sharing.dreamhosters.com/)): every match was an attack.
- **Scanners by user agent** (from [nginx-hardening's list](https://github.com/trumb/nginx-hardening)): attack tools (nuclei, nikto, sqlmap, gobuster, ffuf, wpscan, masscan, zgrab, nmap, LeakIX, ...) score 40; internet survey scanners (Censys, Shodan, Palo Alto Expanse, BitSight, ...) 20, as they only map. HTTP libraries (`okhttp`, `curl`, `python-requests`, `Go-http-client`) aren't on it: Android XMPP clients upload with okhttp, monitoring uses curl. Scan your own server only from an allowlisted address.
- **Forged addresses:** these logs carry text the client chose (user names, paths, headers). Each pattern takes the address only from where the service writes it: the first field of an access log line, after fixed fields only the service fills (nginx's `client:`, Apache's `[client ...]`, PostgreSQL's prefix, Nextcloud's and ownCloud's `remoteAddr`), or at the end of the line (MySQL, Prosody, Dovecot's last `rip=`). Prosody's message must also start right after its source and level, so a client's text ending another message (a stream error's) can't pass for one. A Basic auth user name can't hold a `:`, a JSON value can't hold an unescaped `"`, and PostgreSQL starts the lines of a message with a tab. The tests try made-up user names, paths and headers naming other addresses.
- **Behind a proxy or CDN** the web server's logs show the proxy's address, not the client's: logguard would score the proxy. Private and loopback addresses are ignored anyway; for a CDN's public ones, log the real client (nginx `real_ip_header`, Apache `mod_remoteip`) or allowlist the CDN's networks.
- **Docker:** a container logging to stdout reaches none of these files. Mount its log directory on the host and name the files in `app_logs`. Or use Docker's `journald` log driver and set the logs to `"docker.service"` (dockerd writes them, access and error lines alike): then every container's lines are read, so only where all containers are yours.
- All built-in patterns are probes or failures (none trusts an address after a login). Their events are `custom_probe` and `custom_failure`, their accounts `<pattern>:<user>`, as for the patterns of your own; `logguard test-pattern` runs them too (`--pattern nginx_probe`). A pattern of your own may not take the name of a built-in pattern of an app in `apps`; yours are tried first.

## Patterns of your own

A service logguard has no parser for counts through `[[patterns]]`: a regular expression over the lines of a systemd unit (journal) or of a log file, with the client address in a group named `ip` and, optionally, the account in `user`:

Postfix is built in (above); its SASL failures as a pattern of your own would be:

```toml
[[patterns]]
name = "smtp_sasl"
unit = "postfix@-.service"     # journal lines of this unit; or identifier + uid; or file = "/var/log/..."
regex = 'warning: [^\[]*\[(?P<ip>[0-9A-Fa-f.:]+)\]: SASL \S+ authentication failed(: [^,]*, sasl_username=(?P<user>\S+))?'
kind = "failure"               # failure, probe or success
weight = 25                    # points per line (not for success)
port = 587                     # optional: the local port, for the dashboard's statistics
```

- **Kinds:** `failure` is a failed login (`custom_failure`): counted per account, so distributed guessing and a login right after failures are noticed as for XMPP and SSH. `probe` (`custom_probe`) is hostile without a login. `success` (`custom_success`) is a login: its address is trusted for these lines (all patterns' lines together) like a login to XMPP or SSH.
- **Whose lines:** any local user can log lines with any `SYSLOG_IDENTIFIER`, so a journal pattern names its sender by journald's own fields: `unit` (`_SYSTEMD_UNIT`, exactly), or `identifier` together with `uid` (`_UID`). Lines the built-in parsers read (ejabberd, sshd, the kernel's firewall lines) don't reach the patterns. A `file` is followed from its end (`tail -F`): lines written while logguard is down aren't read. The first pattern that is for a line's sender and finds an address in it wins.
- **Safe with any line:** the `regex` crate matches in linear time, whatever an attacker puts into a line (no catastrophic backtracking); a pattern compiling to more than 1 MB is refused. But it is matched anywhere in a line, and lines carry text attackers choose (user names, URLs): anchor it (`^`, or the text the service writes right before the address) so that a made-up user name can't put someone else's address into group `ip`. Accounts are kept as `<pattern>:<user>` and get no user notifications (only XMPP accounts do); the evidence kept for a ban (which abuse reports quote) shows `[account]` in place of group `user`.
- **On the dashboard:** the TUI's Patterns tab (key `0`) shows what each pattern found since logguard started counting: lines read from its unit or file (none: the service isn't installed, or the unit name or path is wrong, and the tab says so), matched lines, the last match, the busiest addresses with their bans, and the lines it matched without finding an address (a regex that needs a fix: they score nothing). The counts are kept in the state file; up to 200 addresses per pattern are kept (the busiest, and none unseen for 30 days). `port` only labels the lines for the Countries tab's port statistics: logguard opens no port for a pattern.
- **Try it first:** `logguard -c /etc/logguard/logguard.toml test-pattern --pattern smtp_sasl /var/log/mail.log` (journal JSON, `journalctl` short output, a log file's lines, `.gz` too; stdin without a file) prints, per pattern, how many lines it matched, the addresses and accounts it found, and the lines with no address in group `ip`; `-v` prints every match. The sender checks need the live journal and are left out there.

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
- **Defaults are TCP only.** A UDP packet with a forged sender is trivial to send, and a forged tripwire hit bans an innocent address. TCP is no real protection either: UFW logs the very first SYN, before any handshake, and that SYN can carry any source address too. So a tripwire hit never bans an address that logged in within `trust_ttl` (see below), and bans never drop replies to the server's own connections ("Firewall backends").
- **Impact on the Sep–Oct month:** 13,480 tripwire hits, mostly telnet, banned about 7,500 scanners for an hour on first contact, instead of letting them probe further. Port 23 alone was 9,807 of the month's 142k UFW blocks.

## Kernel tripwires

UFW logs blocked packets at most about 3 lines a minute for the whole host (`ufw logging low`: `--limit 3/min`), so most scans never reach logguard: the Sep–Oct month's 141,772 UFW lines are exactly that limit. With `[ports] kernel_tripwires = true` (the default) and the nftables backend in enforce mode, logguard's own table logs tripwire hits itself:

- **What:** a new TCP connection (`ct state new`) to this host (`fib daddr type local`: not what it forwards, such as a VPN server's clients reaching mail servers elsewhere) on a TCP tripwire port nothing listens on. A port something listens on (on an address other than loopback: a local exim on 127.0.0.1:25 leaves port 25 closed from outside) is taken out, checked every 30 seconds: a mail server started on 25 later stops it within that time. Honeypot ports are taken out too. With Docker's userland proxy disabled (`"userland-proxy": false`), a published port has no listener: keep such ports out of `tripwire`.
- **How much:** the first such connection per source address every 10 minutes (dynamic sets `tripseen4`/`tripseen6`), at most `kernel_tripwire_rate` (`60/minute`) for the whole host. A flood of forged SYNs from random addresses can't produce more than that.
- **Where:** in the `bans` chain after the drops (banned, blocklisted and allowlisted sources aren't logged), with the prefix `[LOGGUARD BLOCK] ` UFW-format lines are read with, so a hit is a `fw_tripwire` event like UFW's. When UFW logs the same SYN too, it counts once. Its source address may be forged just the same, and is judged the same way: never against an address that logged in within `trust_ttl`, and shared with peers as forgeable evidence.
- **Needs** `[sources] ufw` (the kernel log), and an nft and kernel with `fib` and dynamic sets (Debian 13, Ubuntu 22.04). The rules are loaded on their own after the table: where they are rejected, logguard runs without them and raises a warning; `install.sh` says so in its dry run (`print-nft` prints them, `print-nft --no-tripwires` leaves them out). Not with the ufw or iptables backends, nor in shadow mode.

## Honeypot ports

A blocked SYN names any source address its sender wants, and a forged tripwire hit can get an outsider banned for an hour (see "Not yet verified", "Spoofing"). `[ports] honeypot = ["2323/tcp", "5900/tcp"]` makes logguard listen on those ports itself and close every connection at once, without reading or sending a byte. A connection is only accepted after the TCP handshake, which a forged address can't complete (the SYN-ACK goes to the real owner), so a hit scores `tripwire_connect` (100, a ban) and is shared with peers as evidence they apply even to their own logged-in users. Scanners that complete connections (Mirai and its kind on 23/2323, `nmap -sT`) are caught for certain; SYN scanners (masscan, zmap) never complete one and still show up only as blocked SYNs.

- With any honeypot port set, `fw_tripwire` (a blocked SYN to a tripwire port) scores **50** instead of 100 unless `[scoring.weights]` sets it: two such hits within minutes ban, one doesn't.
- Open the ports in the firewall (`ufw allow 2323/tcp`), and leave them out of `tripwire` (a port with a listener can't trip anyway). TCP only. A port something else listens on is reported at startup (high `system` alert) and skipped.
- A logged-in address (a carrier NAT neighbour) is still excused, as for blocked SYNs. Each source counts once a minute per port, and a banned one can't connect any more.
- The Exposure tab lists them as honeypots (magenta; red when the firewall blocks one: it catches nothing then), `logguard status` and the digest name them, and they never make a new or gone listener alert.

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
- **Your own mistakes** (a typo from an allowlisted address, or from one that recently logged in to the same service) raise a "protected address" alert instead of a ban. A login never excuses a canary name. It does excuse blocked packets from that address, tripwire ports and port scans included, whatever service it logged in to: one forged SYN names any source address, and a carrier NAT may share one with others.
- **Trust from a login is per service** (`[allowlist] trust_ttl`, default 24 h after the last login): an XMPP login excuses that address's XMPP reconnects and typos, not SSH guessing or peers' reports, so one account (or a shared carrier NAT) can't shield an attacker. It is not shared with cluster peers, and what it excuses isn't reported to them either. A peer's ban or report that rests on blocked packets alone isn't applied to an address that logged in here within `trust_ttl`. An XMPP login earns trust only on a client connection logguard saw open (5222/5223): one it can't tie to its connection (a web client over BOSH or WebSocket, or a forged log line) counts for the account and its alerts, but protects nothing.
- **Nextcloud and ownCloud:** `nextcloud = [...]` covers Nextcloud AIO and the apps `nextcloud` and `owncloud` (`[sources] apps`), whose failed logins become `nc_canary` (100 points) like AIO's. Don't list `admin`: it's AIO's initial admin account, and often ownCloud's.
- **Expect few hits.** In the Sep–Oct month nobody guessed SSH user names at all, and all 8 failed XMPP logins were real users with expired tokens. Canaries are cheap insurance for the day someone starts.

## su and sudo

`[sources] privilege = true` (the default) follows `su` and `sudo` (journal identifiers `su`, `sudo`; only from `/usr/bin/su` and `/usr/bin/sudo`, or as root: any user can log a line tagged `su`):

| line | alert |
|---|---|
| `FAILED SU (to root) gateway on pts/0`, `gateway : 3 incorrect password attempts ; ...`, `pam_unix(sudo:auth): authentication failure`, `user NOT in sudoers` | **high**, `compromise` topic: if it wasn't you, someone has that account and is trying for root. Repeats by the same user within 10 minutes, whatever account they try, are counted into the next one (one user trying every account can't use up the hour's messages). sudo's line holds the directory and command the user chose: one with two `USER=` names the target `?` |
| a switch within 30 minutes after failures | warning: `su to root by gateway succeeded after 2 failed attempts` |
| any other switch | info, on record (TUI, actions log), not sent |

Each alert names the account's latest SSH login, with its place: `(gateway's last SSH login: 11.48.43.31 (Ukraine / ...), 2m ago)`. Where root is reached only through one SSH account and `su`, a failed `su` is the moment someone holding that account's key tries the second factor. The Sep–Oct month's export of sshd's unit had 5 failed and 26 successful `su` to root.

## PAM, account changes and auditd

`[sources] pam = true` and `audit = true` (the defaults) report what logins and account changes leave in PAM's, the account tools' and the audit log's lines (`src/parse/auth.rs`):

| line | what happens |
|---|---|
| a failed login at the console, a desktop or its screen locker, polkit (`pkexec`, `run0`) or the web console (Cockpit): `pam_unix(login:auth): authentication failure; ... tty=/dev/tty1 ... user=root`, audit `USER_AUTH ... res=failed` | **high**, `compromise` topic: `login as root on tty1 failed (login) - if it wasn't you, someone is trying root's password`. Counted per service and who asked (polkit's user) or where (the terminal), one message per 10 minutes, the next one with the count; PAM's line and its audit record are one failure |
| a failed login PAM logs from an address on the internet, at a service with no parser of its own (vsftpd, Cockpit, xrdp, ...) | `pam_auth_fail`, 25 points: five strikes ban, as for SSH. Its account is `<service>:<user>` |
| the same from no address or a private one, at any other service | info, on record only |
| `session opened` at the console or a desktop, audit `USER_LOGIN` on a `tty` | warning: `root logged in at the console or a desktop (login)` (Cockpit's: info) |
| `pam_faillock`/`pam_tally2` locked an account, audit `ANOM_LOGIN_FAILURES` | warning: `account root locked after repeated failed logins` |
| a changed password (`pam_unix(passwd:chauthtok): password changed for root`, `usermod -p`, audit `USER_CHAUTHTOK`) | **high** for root (one per minute), warning for others (one per account and hour: any user can change their own password every minute), `integrity` topic |
| a new account (`useradd`, audit `ADD_USER`) | **high** for a person's account (UID 1000 and up, or a login shell) and for a second UID 0; a package's own system account is on record only |
| added to an admin group (`root`, `sudo`, `wheel`, `admin`, `adm`, `docker`, `lxd`, `incus-admin`, `libvirt`, `disk`, `shadow`) by `useradd -G`, `usermod -aG`, `gpasswd`, audit `GRP_MGMT` | **high**: its members are admins or can become root; other groups on record only |
| a UID changed to 0, a shell changed from `nologin` to one that logs in | **high**; other changes of the account tools: info, or warning for a deleted account |
| auditd stopped (audit `SERVICE_STOP unit=auditd`, `DAEMON_END`) / aborted / auditing switched off (`auditctl -e 0`: `CONFIG_CHANGE audit_enabled=0`) | warning / **high** / **high**: nothing is recorded until it runs again |
| a rule of yours fired whose key is in `audit_keys` (`-w /etc/shadow -p wa -k identity`, `audit_keys = ["identity"]`, `"*"` for any key) | warning: `audit rule identity: vim (/usr/bin/vim.basic) as uid 0 by gateway (auid 1000) on pts0`, one per key per 10 minutes. Fields are read only where the record has them, never from inside a quoted value: a program named `'key=x'`, or an account typed as `'addr=203.0.113.9'`, can't hide a rule's key or name another address |

- **Whose lines:** any local user can log a line saying `pam_unix(login:auth): authentication failure` or tagged `useradd`. PAM's and the account tools' lines count only from programs running as root, or from the set-uid programs the system installs (`passwd`, `chsh`, `chfn`, `newgrp`, `gpasswd`, `pkexec`, polkit's helper, `run0`). Audit records come only from the kernel and from programs allowed to write them (`CAP_AUDIT_WRITE`): journald's own (`_TRANSPORT=audit`), the kernel's log, or auditd's file. sshd's, su's and sudo's lines stay with their own parsers (sshd's lockouts are read here too).
- **Typed names:** the user name of a failed login is whatever someone typed, and comes last in PAM's line: a line naming more than one ` rhost=` names no address (`from an unclear address`), and scores nothing. The audit library writes odd names in hex (`acct=726F6F7420...`), which are decoded and cleaned.
- **Where:** PAM's and the account tools' lines through journalctl matches on their syslog facilities (`SYSLOG_FACILITY=10` authpriv, `4` auth); audit records through `_TRANSPORT=audit`. Where journald doesn't read the audit log (`Audit=no`, or journald's audit socket off), set `audit_log = "/var/log/audit/audit.log"`: logguard then follows auditd's file instead, the journal's copies are left out, and `auditd`'s own stop and abort records are there too. Without auditd, the kernel writes audit records to its own log, which logguard reads with `ufw` or `oom` on.
- **Not scored twice:** failed logins at Dovecot (`dovecot`) and Postfix's SASL (`smtp`, `smtps`, `submission`) through PAM aren't scored when that app is in `[sources] apps`, which scores its own lines.
- Alerts that PAM's line and the audit record both make (the same failure, password, account or group change) are one alert: they share a key, and the second within a minute says nothing.

## Desktops and laptops

logguard is made for servers, but half of it watches the machine itself, and that half is as useful on a Linux desktop: [`deploy/logguard-desktop.toml`](deploy/logguard-desktop.toml) (`sudo ./install.sh --template desktop`; Fedora: `desktop-dnf`) turns it on and leaves the firewall alone. Behind a home router nothing reaches a desktop from the internet, so there is nobody to score or ban.

- **On:** new or changed crontabs, timers and their scripts, SSH keys, sudoers, PAM, systemd units, `/usr/local/bin` ("Cron watch"); package programs and libraries against the package database, new set-uid programs ("Package and set-uid check"); programs running from `/tmp`, `/dev/shm`, memory or a deleted file, and shells or network tools talking out ("Process watch"); failed `su`, `sudo`, polkit and console or screen-lock logins, new accounts and admins, changed passwords ("su and sudo", "PAM, account changes and auditd"); pending security updates; low disk space and memory. With ClamAV or YARA installed, `[antivirus] scan_changed` scans every changed file ("Scans of changed files").
- **Off:** blocking (`mode = "shadow"`), blocklist feeds, the cluster, the exposure watch (desktop apps open and close listeners all day), quiet-log warnings (a laptop sleeps), the digest.
- **SSH reachable from the internet** (a forwarded port, a public address): then it is a server for that port. Set `mode = "enforce"`, add your SSH names' canaries and the SSH rate limit from `logguard-standalone.toml`, and allowlist where you log in from.
- **Messages:** alerts are in the journal (`journalctl -u logguard`), the actions log and `logguard tui`. For a message on your phone, a copy bot (XMPP client bot, Telegram, mail, Signal, Matrix) with `[notify] xmpp = false` ("Deployment layouts"; `deploy/logguard-desktop.toml` names the XMPP client bot's lines). A failed `sudo` is a high alert even when it is your own typo: it says "if it wasn't you".

What a desktop does differently, and how the profile takes it:

| on a desktop | would be | the profile |
|---|---|---|
| every new app, game or update opens new outbound connections | a warning for each new (program, port) pair | `[procwatch] new_outbound = false`: only shells and network tools talking out, and the ports miners and reverse shells use (always high) |
| AppImages run from `/tmp/.mount_*` | "runs from a temporary directory" (high) | `allow_appimages = true`: not when the program is on the FUSE mount the AppImage made; a program in a directory merely named so still is |
| a Snap or Flatpak app updated while it runs runs from a deleted file | "its program file was deleted" | `/snap` and Flatpak's `/app` count like `/usr` (on servers too) |
| snapd writes units and timers (`snap-*.mount`, `snap.*.service`) at every refresh | a high integrity alert each time | `[cron] exclude` leaves `snap-*` and `snap.*` in `/etc/systemd/system` out. An intruder can hide a unit by naming it so: without snaps, delete those lines |
| browsers talk to hundreds of servers | the usual advice is to ignore them by name | nothing by name: `ignore_processes` would also let a dropper that calls itself `firefox` run from `/tmp` unreported. Their connections are covered by `new_outbound = false` |

Flatpak's and Snap's own files (`/var/lib/flatpak`, `/snap`) are outside what the package check and the set-uid search read. `ignore_ports` (remote ports a game uses, say) never hides a shell's or network tool's connection: a reverse shell on port 443 is still one.

## Exposure watch

Every `[exposure] interval` (60 s), the daemon:
1. reads listening sockets straight from `/proc/net/{tcp,udp}{,6}` (no `ss` subprocess) and maps them to processes through `/proc/<pid>/fd`;
2. reads what filters incoming traffic, and the rules that let traffic in **from anywhere**:
   - **ufw**, when it is active (`ufw status`);
   - else **firewalld**, when it runs: its zones (`firewall-cmd --list-all-zones`, re-read every 5 minutes or when a file in `/etc/firewalld` changes, as firewall-cmd is a Python program talking over D-Bus), with the ports of the services they name read from firewalld's own service files (`/etc/firewalld/services`, then `/usr/lib/firewalld/services`; includes followed). The default zone and zones with an interface other than loopback, container bridges and tunnels let in from anywhere: their `ports`, `services`, `protocols` (every port of one), a target of `ACCEPT` (every port), and rich rules that `accept` (with `limit value=`: rate-limited). Zones bound to sources, and rich rules naming a source, let in from those only. logguard's own zone holds banned sources and opens nothing;
   - else **iptables**: the filter table's `INPUT` chain for IPv4 and IPv6 (`iptables -S`, `ip6tables -S`, the programs set in `[enforce]`), followed like the kernel does: rules in order, jumps into chains of their own, the chain's policy. Rules for some sources only (`-s`, `--match-set`), for loopback or container/tunnel interfaces, for states other than NEW, and for source ports don't count; `limit`, `hashlimit`, `recent` and `connlimit` rules mark the port as rate-limited. A match it doesn't know makes an ACCEPT count and a DROP not, so exposure is over- rather than under-reported. iptables counts as a firewall only if `INPUT` drops by default or something it reaches drops for everyone: fail2ban's per-address rejects alone don't make one. A socket on `[::]` takes IPv4 connections too, so it is reachable when either family lets it in (e.g. `policy ACCEPT (IPv6)` when only IPv4 is filtered);
   - else **nftables** chains of their own on the input hook (other than the `filter` tables iptables-nft keeps for iptables) that drop by default or hold rules: they're noticed, not read, and public listeners are shown as reachable;
   - else **no firewall**: the TUI's Exposure tab says so in a red box above the list, its tab and the Overview's Health panel show it, `logguard status` and the daily digest say it too;
3. classifies every listener:

| state | meaning |
|---|---|
| local only | bound to loopback or a private address (e.g. `127.0.0.53:53`, the Docker bridge) |
| blocked by ufw / firewalld / iptables | public address, but the firewall doesn't let new connections in (e.g. Erlang's `epmd`) |
| allowed by ufw / firewalld / iptables from some sources only | closed to the internet, open to the addresses some rules name (`ALLOW 7946/tcp from 3 sources`: the cluster port, open to the peers; firewalld: `ALLOW 6379/tcp (work) from 10.0.0.0/8`); not exposed, so no new/gone alerts |
| allowed by ufw / firewalld / iptables | public and let in: really exposed |
| allowed by ufw / firewalld / iptables, rate-limited | let in by a ufw `LIMIT` rule (an address opening 6 connections in 30 seconds is dropped), a firewalld rich rule with `limit value=`, or by iptables past a `limit`, `hashlimit`, `recent` or `connlimit` rule |
| published by docker | `docker-proxy` listener: reachable **regardless of ufw or the INPUT chain**; the tab shows the ufw rule allowing it, or *none: containers blocked* when there is none: connections from the internet are DNATed by Docker before ufw sees them, but a container calling the host's public address (Nextcloud's admin check of its Talk server, or anything using the public domain name) reaches `docker-proxy` through the INPUT chain, which ufw then blocks — the check hangs and fails |
| no firewall | public, and nothing filters incoming traffic |
| honeypot | one of logguard's own `[ports] honeypot` listeners: exposed on purpose, never alerted about; "blocked by ufw" means it catches nothing |
| public, nftables rules not read | public, and nftables rules of their own decide |

The first scan is learned silently as the baseline (one info alert lists it). After that it alerts, under the `exposure` notification topic:
- **New internet-facing listener:** e.g. an admin panel published on `0.0.0.0` by accident. It must be seen in 2 consecutive scans.
- **Listener gone:** a service stopped or crashed. It must be missing from 3 consecutive scans, so restarts don't flap.
- **Dead firewall rule:** ufw allows a single port from anywhere, but nothing listens on it publicly (with firewalld: a single port in a zone's `ports`, not a service: Fedora's `dhcpv6-client` would always count). That's exactly the 53/udp, 853/udp and 51821/tcp rules found by hand on the VPN host.

**Port ranges** such as the TURN/STUN relay ranges (`49152:65535/udp` and `/tcp`) are never reported as dead. Sockets opened inside them are marked *dynamic*: TURN servers open one per call participant, and Linux client sockets use that range too. They're listed in the TUI but never trigger new/gone alerts. Listeners with their own single-port rule, like TURNS on `5349/tcp`, are still tracked normally.
- **ufw inactive**, with nothing else filtering (iptables rules of your own count).

When what filters changes (ufw enabled or disabled, firewalld started or stopped, or iptables or firewalld rules read for the first time after an upgrade), the baseline is learned again, with one info alert, rather than every listener the change hid or opened reported as gone or new. A report from a daemon older than the iptables reading shows *firewall not checked* rather than *no firewall* until the daemon is restarted.

Use `[exposure] ignore = ["5000/tcp"]` for ports that are exposed by design through another path. The TUI's **Exposure** tab (6) and `logguard status` show the current table; the tab also names the firewall rule letting each listener in, the first that matches as the firewall applies them (ufw's `ALLOW 5222:5223/tcp`, `LIMIT 9843/tcp`; firewalld's `ALLOW ssh (public)`, `LIMIT rich rule 5222/tcp (public)`, `ALLOW target ACCEPT (trusted)`; iptables' `ACCEPT 80,443/tcp`, `ACCEPT 22/tcp via ssh-guard`, `policy ACCEPT`). Dead rules are ufw's and firewalld's only.

**Weekly reboot / apt upgrades:** for `startup_grace` (15 min) after logguard starts, no new/gone listener alerts are raised, because Docker containers come up after logguard. A listener must be missing from `gone_after_scans` (5) consecutive scans before it's reported as gone, so a service restarted by an upgrade doesn't trigger alerts.

If Docker's userland proxy is disabled (`"userland-proxy": false`), published ports have no `docker-proxy` listener. Their ufw ALLOW rules would then be reported as dead; add those ports to `ignore`.

## Cron watch

Scheduled tasks are the classic way for an intruder to stay on a server after a reboot or a password change. Every `[cron] interval` (1 min) logguard reads:
- **crontabs:** `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d/*`, and every user's crontab in `/var/spool/cron/crontabs/` (what `crontab -l` shows). Each task line counts on its own; comments don't, so the header `crontab -e` rewrites is ignored. `VAR=value` lines count too, because changing `PATH` changes what runs;
- **run-parts directories:** `/etc/cron.{hourly,daily,weekly,monthly,yearly}`. Each file is a task, fingerprinted by content (SHA-256);
- **enabled systemd timers** in `/etc/systemd/system/timers.target.wants/`, cron's modern sibling;
- **scripts that crontab lines run,** e.g. `/usr/local/bin/av_scan.sh`, `bash /opt/job.sh` or `cd /opt/app && ./run.sh`, also behind `sudo -u`, `flock`, `timeout`, `env`, `nice`/`ionice`. Redirect targets, arguments and inline code (`sh -c '...'`) are not scripts. Programs in the system's package directories (`/usr/bin`, `/usr/lib`, ...) are skipped;
- **other files** (`[cron] files`), the usual ways back in besides cron: `authorized_keys` of root and every user in `/home`, and `/etc/ssh/authorized_keys/*` (`AuthorizedKeysFile /etc/ssh/authorized_keys/%u`, as on the hardened hosts), `/etc/sudoers(.d)`, `/etc/passwd`, `/etc/shadow`, `/etc/group`, `sshd_config(.d)`, PAM (`/etc/pam.d/*`: one line there lets anyone in), apt's hooks (`/etc/apt/apt.conf.d/*`, `DPkg::Post-Invoke` runs as root at every package change) and dnf's actions (`/etc/dnf/plugins/post-transaction-actions.d/*`, `/etc/dnf/libdnf5-plugins/actions.d/*`), `/etc/update-motd.d/*` (run as root at every login), `/etc/ld.so.preload`, `/etc/ld.so.conf.d/*`, `/etc/rc.local`, `/etc/profile.d/*`, `/etc/environment`, `/etc/bash.bashrc`, root's `.bashrc` and `.profile`, module loading and device rules (`/etc/modules-load.d/*`, `/etc/modprobe.d/*`, `/etc/udev/rules.d/*`), `/etc/init.d/*`, programs installed by hand (`/usr/local/bin/*`, `/usr/local/sbin/*`: the SSH gateway's shell, logguard itself), and systemd units (`/etc/systemd/system/*`, enabled ones in `*.wants/`, and drop-in overrides in `*.d/*.conf`, which can replace a service's `ExecStart`). Only fingerprints are kept, never contents (so no password hashes in alerts or the state file). A file root owns is hashed whole (up to 1 GB, so a change deep inside a large program shows); anyone else's only its first 16 MB, plus its size, as its owner could make it huge and change it every minute. Masked units (symlinks to `/dev/null`) are recorded as such. **Installers announce their files:** `logguard expect-change PATH=SOURCE...` records the content PATH is about to get (in `expected-changes` next to the state file, kept 7 days), and a change to exactly that content is logged as info instead of alerted. `install.sh` does this for logguard's binaries, scripts and units before it replaces them, and the bots' and logguard-web's installers for their units, and for `/etc/passwd`, `/etc/shadow`, `/etc/group` and `/etc/gshadow` right after they create (or rename) their system user (`expect-change PATH`: its content as it is now); any other content still raises the usual alert. Files of a pattern added later (or by the upgrade that introduced file watching) are learned silently, and files of a removed pattern are forgotten instead of reported as removed. A file two patterns reach under different names is watched once, under the first pattern's: on Fedora 42 and later `/usr/local/sbin` is a link to `/usr/local/bin`, and logguard's binary would otherwise be two alerts at every upgrade, the second unannounced.

Editor swap files, `.dpkg-old` leftovers and dotfiles (`.placeholder`) are ignored; cron and run-parts don't run them either. Any user can write their own crontab, so its lines are stripped of control characters, lines are capped at 1,000 characters, and a crontab of more than 500 lines is watched as one fingerprint. Programs it names are only opened if they are regular files (a named pipe would otherwise hang the scan).

**Learn period:** everything present during the first `learn` (1 day) is accepted. Changes in that time are only written to the actions log. After that, every change is reported once under the `integrity` admin topic and becomes the new normal:

| change | severity |
|---|---|
| new or changed task, crontab line or script | high, with "the server may be compromised" if nobody here made it |
| the same, but the file is a package's and identical to what it installed (the MD5 dpkg recorded, or rpm's digest) | warning, "installed by package man-db, unmodified" |
| a task or line removed (e.g. someone disabling the virus scan) | warning |

**A user's own changes have an hourly budget:** a change any local account could have made (it owns the file, the link to it, or a directory above it: its crontab, its scripts, its `authorized_keys`) counts against that account. After 5 such alerts in an hour, the rest of the hour's are only logged (the TUI's Alerts tab, the actions log), and one more alert says so; so one account changing its crontab every minute can't use up the hour's `integrity` messages. What only root can change is never held back. Process watch alerts share the same budget, by the user a process runs as.

Package lookups read dpkg's database (`/var/lib/dpkg/info/*.list`, `*.md5sums`, `status`) line by line, and only for files that changed. Running `dpkg-query -S` / `dpkg --verify` instead would load every package's file list and hash whole packages, all counted against logguard's memory limit. With `package_manager = "dnf"`, rpm's database (SQLite, not text) is asked instead: `rpm -qf` for the owners of the changed files, then `rpm -q` for those packages' file digests; `%config` files count as dpkg's conffiles do.

New and changed lines are listed in the alert (`+ ...` / `- ...`). So your own edits produce a message too, which confirms the watch works. `logguard integrity` prints everything that is watched, with package origins.

## Antivirus: ClamAV's scheduled scans, and scans of changed files

With `[antivirus] enabled = true`, logguard reads the log of scheduled ClamAV scans (checked every minute) and reports, under the `integrity` topic:
- **infected files** (critical): each `path: Signature FOUND` is listed;
- **a scan that didn't finish** (high): no summary written, or an exit code beyond 2. Exit 137 means it was killed, usually out of memory (`clamscan` loads ~1-1.5 GB of signatures);
- **no finished scan for `stale_after`** (warning, daily, 36 h by default): the timer/cron job stopped running or keeps dying;
- **signatures older than 7 days** (warning): freshclam isn't working.

Clean scans are only logged ("virus scan finished ...: 2813 files, nothing found"), and `logguard status` shows the last one. Only runs newer than the last reported one count. On the first read of an existing log, only its newest run is news.

`install.sh` ships the scan as **`logguard-avscan.timer`** (daily at 02:30 ± 10 min; `Persistent=true` catches up after a reboot). It runs `/usr/local/sbin/logguard-avscan`, which:
- uses clamdscan when clamav-daemon runs, otherwise clamscan;
- runs at nice 19 with idle I/O, and with `OOMScoreAdjust=900`, so if memory runs out the scan dies (and is reported) rather than ejabberd or a database;
- wraps each run in marker lines with UTC times and the exit code, and indents the scanner's output, so a file name with line breaks can't forge a marker.

Scan paths and excludes are in `/etc/default/logguard-avscan`. The timer is enabled only when `[antivirus]` is enabled and ClamAV is installed. Plain `clamscan --stdout` output appended by your own job also works: point `log` at it (dates are read as UTC).

### Scans of changed files

`[antivirus] scan_changed` scans every file the integrity watches report new or changed, right after the report, with `"clamav"`, `"yara"` or `"both"` (`"none"`, the default: no scans). Independent of `enabled` (the scheduled scans' log):

```toml
[antivirus]
scan_changed = "both"
yara_rules = ["/etc/logguard/yara"]   # .yar/.yara files, directories of them, or one compiled .yarc
```

- **What is scanned:** new or changed crontabs, scheduled tasks and the scripts they run (a script that comes with a new crontab line too), files of `[cron] files` (SSH keys, sudoers, systemd units, `/usr/local/bin`, ...), package files that differ from what the package manager installed, new or changed set-uid programs, and programs running from a temporary or deleted file (as they run: `/proc/<pid>/exe`). Not what logguard's own installer announced. A file reported again (a change every minute) is scanned again; up to 200 files go to one scan, up to 1,000 wait (more are dropped), and the queue isn't kept across restarts. A local user's own files (their crontab and the scripts its new lines run, files they can change, their processes) go to at most 20 scans an hour: any account can change its files every minute, and each scan may load a gigabyte of signatures.
- **What it reports:** each infected file is a **high** `integrity` alert, `malware in /tmp/.x/kworker: ClamAV: Unix.Trojan.Mirai-1; YARA: SUSP_ELF_Miner (it was scanned because: process kworker (pid 4242, ...) runs from a temporary directory ...)`, once a day for the same file and finding. One in a local user's own file counts against that user's hourly budget of 5 alerts (see "Cron watch"), so a pile of test signatures can't flood the admins; every hit stays on record. A scanner that fails (not installed, rules that don't compile, out of time) is a warning, once a day. Each scan is on record (TUI, actions log), not sent: `scanned 3 of 3 changed files with ClamAV (clamd) and YARA (2 rule files): nothing found`, with every file's result.
- **ClamAV:** while clamd runs (its socket `clamd_socket`, `/run/clamav/clamd.ctl`; Fedora's is `/run/clamd.scan/clamd.sock`), files go to it with `clamdscan --fdpass`: clamd keeps its signatures loaded, and reads root's files through the descriptors logguard passes. Otherwise `clamscan` runs, loading its signatures for each scan (1-1.5 GB, half a minute and more).
- **YARA:** `yara --scan-list` with every rule file, each in a namespace of its own (the same rule name in two files is no error), or one compiled file (`yarac rules.yar rules.yarc`, then `yara_rules = ["/etc/logguard/rules.yarc"]`: much faster with large rule sets). Rule sets decide the alerts: start with a curated one (e.g. YARA Forge's core set), not every community rule (some flag admin tools). YARA rules also work inside ClamAV: `.yar` files in ClamAV's database directory (`/var/lib/clamav`) are used by clamscan and clamd, a hit reads `YARA.Rule_Name.UNOFFICIAL` (ClamAV supports part of YARA: no modules).
- **Memory:** logguard's unit is limited to 128 MB, which `clamscan` and large YARA rule sets exceed. They run as a transient service of their own (`systemd_run`, `/usr/bin/systemd-run --wait --pipe`), with `MemoryMax=scan_memory` (2G), `RuntimeMaxSec=scan_timeout` (30 min), nice 10 and idle I/O; `systemd_run = ""` runs them inside logguard's limit (small YARA rule sets only). clamdscan itself needs little.
- **Hostile names:** only regular files are scanned, up to `scan_max_mb` (100 MB): not devices (`/dev/zero`, `/dev/random`, `/dev/urandom`, or links to them, whose reads never end), named pipes or sockets. Each file is checked again right before each scanner reads it, so one swapped for such a link while ClamAV ran isn't handed to YARA. The scanners open the files by name themselves, so a swap in the moment between the check and their reading can't be ruled out: `scan_timeout` then ends the scan, reported as a failed scanner. Names with control characters are not scanned (they would break the scanners' file lists; the scan's record says so). Results are matched to the names logguard asked about, so a file named `x: Eicar FOUND` can't report another one.

## Package and set-uid check

Weekly (`[verify] interval`, the first pass a quarter of an hour after the first start), logguard checks what a rootkit replaces:

- **Package files:** every program and library a package installed under `dirs` (`/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`, and their pre-merged-/usr aliases; not `/usr/lib/firmware`) is hashed and compared with the MD5 dpkg recorded (`/var/lib/dpkg/info/*.md5sums`), like `debsums`. With `package_manager = "dnf"`: with the digest rpm recorded (SHA-256 on current Fedora and RHEL), like `rpm -Va`, asking `rpm -q` 25 packages at a time so rpm's lock is never held for long; `%config` and `%ghost` files are left out, and a file two architectures' packages share (i686 and x86_64) may match either. Files moved aside with `dpkg-divert` are left out, and a mismatch is checked again after the pass (an upgrade may have run meanwhile). New mismatches are **high** ("reinstall: `apt install --reinstall <package>`", or `dnf reinstall <package>`); the first pass reports what it finds as a warning, once.
- **Set-uid and set-gid programs** under `suid_roots` (`/usr`, `/opt`, `/home`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/srv`, `/etc`, `/boot`; not `/var/lib/docker`), seen through init's root (`/proc/1/root`), since the service's own `/tmp` is private: learned on the first pass, then a new or changed one is **high** (a warning if dpkg installed it unmodified), a removed one only logged. Any user can make set-uid files of their own: a pass keeps at most 10,000 owned by root and 1,000 owned by others (hashing only the first MB of those), names at most 20 changes one by one and the rest in one more alert, and says (**high**) how many it left out.
- **Cost:** it reads at most `max_rate_mb` (20) MB a second, and drops what it read from the page cache, which would otherwise count against the service's memory limit. A server's package files are a few GB: some minutes a week.

`logguard status` and the TUI's Health panel show the last pass.

## Process watch

Every `[procwatch] interval` (60 s), from `/proc`:

- **Outbound connections:** TCP connections this host opened (to a port not listening here, to a public address), by program and remote port: `curl` to 443, `beam.smp` to 5269 (federation). The pairs are learned for `learn` (3 days); after that a new pair is a warning, once, and becomes normal. A shell or network tool talking out (`bash`, `sh`, `nc`, `socat`, `telnet`: a reverse shell) and any connection to a port miners and reverse shells use (`suspicious_ports`: 3333, 4444, 14444, ...) are **high**, always. Connections inside containers have network namespaces of their own and aren't seen.
- **Programs running from where nothing should run:** `/tmp`, `/var/tmp`, `/dev/shm`, memory only (`memfd:`, except runc starting a container), or a program file deleted after start outside the package directories (an upgrade replacing `/usr/sbin/sshd` is the patch status's business). **High**, a warning for a process in a container; once a day per program.
- `ignore_processes` and `ignore_ports` leave programs (by `/proc/<pid>/comm` name) and remote ports out.
- A process that doesn't run as root counts against its user's hourly budget of 5 alerts, shared with their own crontab and files (see "Cron watch"): the rest of the hour's are only logged, and one more alert says so.

## Patch status

Every `[patches] interval` (6 h): pending upgrades (`apt-get -s dist-upgrade`, a simulation that takes no lock, run in a transient unit of its own with `systemd-run` so apt's cache isn't charged to logguard's memory limit; security ones by name), a newer kernel in `/boot` than the one running, `/run/reboot-required`, and programs still running a library or program an upgrade replaced (from `/proc/*/maps`: they keep the old code until restarted). What needs doing goes into the daily digest's "Needs attention" (`3 security updates pending (openssl, libssl3, ...): apt upgrade`, `kernel 6.12.48+deb13-amd64 is installed but 6.12.9+deb13-amd64 runs: reboot`), and `logguard status` and the TUI's Health panel show it. No alerts of its own. `apt = false` skips apt. Started without systemd (by hand), logguard runs apt itself. With `package_manager = "dnf"`, dnf instead: `dnf --cacheonly --quiet check-update`, then with `--security` (exit status 100: updates pending), from the metadata `dnf-makecache.timer` keeps current, in a transient unit with `MemoryMax=1G` (dnf's metadata is larger than apt's cache); `apt = false` skips it too. Fedora has no `/run/reboot-required`: there the newer kernel in `/boot` and the stale programs say it.

## SSH audit

Every `[ssh_audit] interval` (1 h, the first five minutes after start) sshd's settings are checked as sshd itself applies them: `sshd -T` for the global ones, and `sshd -T -C user=...,addr=203.0.113.1` for root and the gateway users, so `Match` blocks count as they do for a login from the internet (a `Match Address` for the LAN doesn't excuse the internet). The config files are parsed too, `Include`s in order, to say which file each setting comes from and which lines it overrides: the classic is a cloud image's `sshd_config.d/50-cloud-init.conf` saying `PasswordAuthentication yes` in front of `sshd_config`'s own `no` (the message names both lines, and the fix says to set `ssh_pwauth: false` for cloud-init, which would otherwise write the file again). When `sshd -T` fails (no host keys readable, a broken config), the settings come from the files over OpenSSH's defaults and the report says so. Nothing is changed. It reads the files, as sshd will at its next start or reload, not the running daemon: an edit counts as soon as it is saved, so run `sshd -t && systemctl reload ssh` (`sshd` on Fedora) before trusting a clean report. A setting written otherwise than sshd shows it is quoted with its line ("LoginGraceTime 600s, written `10m` in ..."), and cloud-init's own setting is suggested only where cloud-init is installed.

The layout is detected (`profile = "auto"`), or set:

- **standard** (most VPSs): root with a password from the internet (high), passwords accepted at all, naming the accounts that have one (a warning; a note when no allowed account has a password), PAM's keyboard-interactive password prompt counts too, a key first (`AuthenticationMethods publickey,password`) doesn't; `PermitEmptyPasswords`, a second uid-0 account, `LogLevel` too low for logguard to see failed logins, `StrictModes no`, host-based logins, `PermitUserEnvironment`, `GatewayPorts`, weak ciphers, MACs and key exchanges, DSA and short RSA host keys, host keys readable by others (Fedora's `ssh_keys` group is fine), config files and `/etc/ssh` writable by anyone but root, and every allowed account's key files and `.ssh` directories writable by others (high for root, or with `StrictModes no`). Notes, not alerts: `X11Forwarding`, `PermitTunnel`, `MaxAuthTries` above 6, a long `LoginGraceTime`, `PermitRootLogin yes` while only keys work, an `AuthorizedKeysCommand`.
- **hosting panels** (cPanel/WHM, Plesk, DirectAdmin, HestiaCP, VestaCP, CyberPanel, aaPanel, ISPConfig, Webmin; found by a file each installs): the same checks, and the fixes say where the panel changes them (cPanel: WHM's SSH Password Authorization Tweak, after adding root's key).
- **gateway** (`hardening/harden-vps.sh`, or the same set up by hand): detected when a user AllowUsers or the `su_group` names has a `ForceCommand`, or AllowUsers is set with no root login and pam_wheel limiting `su` to an existing `su_group`. On top of the standard checks, each piece of the layout: no root login at all, no passwords (high, not a warning), AllowUsers set and naming no one else, each gateway user's sessions forced into the wrapper, the wrapper root's and not writable by others (nor its directory), running nothing but `su` and the sftp server, the user's keys in a root-owned file outside its home, each key line starting with `restrict`, port forwarding only local and only to `127.0.0.1` (`PermitOpen`), no agent, X11, socket or tun forwarding, a home the user can't write (only `~/xfer`), a locked password, not in a sudo group, pam_wheel in `/etc/pam.d/su` (the group it names, which must exist and have no other members), root with a password (or the su stage leads nowhere), port 22 (a note). harden-vps.sh's leftovers too: a rollback timer still armed (`ssh-harden-rollback-*.timer`: the old config comes back when it fires) and backups in `/root/ssh-harden-*` readable by others.

The first reading tells everything at once (an alert when there is a warning or worse; only logged otherwise). Then a new or worse problem is an alert (host integrity topic), with the watched settings that changed since (`changed: passwordauthentication: no -> yes`); settings that change without a new problem, and problems fixed, are one info message; high problems still open are told again every `remind` (7 days). The daily digest lists the open warnings and high problems under "Needs attention" and the summary as `SSH: gateway (gabc...): no problems`; `logguard status` and the TUI's Health panel show the summary. `logguard ssh-audit` (as root, without the daemon) prints every problem with its id and fix (`--all` with the notes, `--json` for scripts); `ignore = ["x11-forwarding", "gateway-port"]` hides problems by id (an id covers its per-user and per-file forms). Changes to the files themselves (sshd_config, key files, the wrapper) are the cron watch's alerts, as before.

## Abuse reports

`logguard abuse-report` turns the bans of a time window into a report for the abuse desks of the networks they came from. It works without the daemon: it reads `actions.jsonl` and its rotated copies, including the gzipped ones.

```bash
logguard -c /etc/logguard/logguard.toml abuse-report                          # last 7 days, top 50 sources
logguard -c /etc/logguard/logguard.toml abuse-report --since 30d --contacts -o /root/abuse.txt
logguard -c /etc/logguard/logguard.toml abuse-report --ip 11.54.36.0/24 --json
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

The merged report has one entry per source: incidents are added up, and every log line says which server it hit (`(to 11.38.48.86) connection attempt to closed port TCP/23 (Telnet)`). `--min-events`, `--top`, `--ip` and `--contacts` apply after merging, so a source seen a little on each server still counts in full. The same report given twice (same server and period) is skipped with a warning instead of doubling every count.

**Weekly, to the admin's phone.** `logguard-abuse-report.timer` (Mondays 06:00 UTC, installed and enabled by `install.sh`) does the above on its own: the VPN server sends its JSON report to its cluster peers with `logguard cluster-send-report` (gzip-compressed, one message over the encrypted cluster link, never stored or forwarded as a fact; the peer writes it to `[cluster] inbox`, default `/var/lib/logguard/inbox`, mode 0600, and never parses it), and the XMPP server waits for it (up to 15 minutes), merges it with its own and puts the text report in the admin bot's outbox. The bot sends it to the admin as an OMEMO-encrypted file (logguard-xmpp-bot's README, "Weekly abuse report"); logguard-tg-bot, as a file encrypted to the admin's OpenPGP key. `ABUSE_REPORT_ROLE=auto` in `/etc/default/logguard-abuse-report` picks the role: `relay` on a Telegram relay node (below), else `merge` where a bot's outbox exists (`[notify] bot_outbox`, else `/opt/logguard-xmpp-bot/outbox`, and `[notify] tg_outbox`), else `send` when there are cluster peers, else `off`; `off` also turns the timer off. A server without peers merges at once (just its own report). Nothing stays behind: work files are in `/run` and removed on exit, the peer's report is deleted once merged (an unmerged one after 7 days; on a `send` node, which never merges, at its next run), and the bot deletes the outbox file once sent. A missing peer report is named in the job's output (`journalctl -u logguard-abuse-report`) and the report then covers the servers it has; add `logguard-abuse-report.service` to `[sources] services` to be told when the job fails.

```bash
systemctl start logguard-abuse-report      # now, as root: on the VPN server first, then the XMPP server
logguard cluster-send-report /root/abuse-vpn.json   # by hand: to the peers' inbox as abuse-<node>.json.gz
```

`--merge` reads these gzip files directly.

Times are UTC throughout, which is what abuse desks expect. The report doesn't say whether the firewall actually blocked anything, so it is also accurate for a server in shadow mode.

## Self-healing firewall table

(This is about nftables; the iptables, ipset and firewalld backends heal the same way: see "Firewall backends".) On Debian and Ubuntu, `/etc/nftables.conf` begins with `flush ruleset`. Any `systemctl restart nftables`, or a package upgrade that triggers one, silently deletes logguard's table and every ban. In enforce mode the daemon checks for the table every 30 s. If it's gone, it recreates it, re-adds all active bans with their remaining time, and raises a **high** `system` alert.

## Kernel rate limits

`[[ratelimit]]` entries cap **new connections per source address** in the kernel, from the first packet, before any score reacts:

```toml
[[ratelimit]]
ports = ["5222/tcp", "5223/tcp"]
rate = "30/minute"        # n/second, n/minute or n/hour
burst = 30
```

They live in a second chain, `rl`, at prerouting priority *mangle*. That's after conntrack, so only new connections count, and still before Docker's DNAT, so Docker-published ports are limited too; UFW's `limit` rules never see those. Allowlisted and operator-allowed addresses are exempt, and so are private, CGNAT, loopback and link-local sources (Docker containers calling the host's own published ports, VPN clients): logguard never bans those either. Per-source state lives in dynamic sets (`rl0_4`, `rl0_6`, …), and `logguard status` shows how many packets each entry dropped. Enforce mode with nftables only; the ufw and iptables backends ignore them. `install.sh` dry-runs the full ruleset with `nft -c` against the kernel.

## Quiet sources and the systemd watchdog

logguard can't tell "no attacks" from "not seeing logs" by scores alone, so `[silence]` raises a `system` warning when an enabled source:
- **logs nothing** for its threshold (defaults `ufw = "2h"`, `ejabberd = "6h"`, `ssh = "2d"`, Nextcloud AIO off: `nextcloud_aio`, called `nextcloud` until 2026-10-26). Measured on the Sep–Oct month: UFW and ejabberd were never quiet for 3 h outside an outage; sshd often was for a day. Typical causes: `ufw logging off`, ejabberd stopped, or a unit renamed. An info alert follows when lines return.
- **an app's log** (`[sources] apps`) **logs nothing** for its time in `[silence.apps]`, by its key in `[sources.app_logs]`: `nginx_access = "2h"`, `nextcloud = "7d"`. None by default: a busy site's access log is never quiet for hours, while `nextcloud.log` at the default `loglevel` holds only warnings and errors and can be quiet for days. Counted by the log's first pattern, which reads all its lines (the Patterns tab shows them too).
- **logs, but no line can be tied to an address** for `blind_after` (6 h, at least `blind_lines` = 200 lines). This catches ejabberd's `hide_sensitive_log_data` (5 days in that month) or a log format logguard no longer understands.

Silence is measured from the later of the last line and the daemon's start, so a reboot or a stopped service never counts as silence. The checks run in the live daemon only, not in `replay`.

**Out-of-memory kills** (`[sources] oom = true`, the default): when the kernel kills a process for lack of memory (`Out of memory: Killed process 785891 (clamscan) ... anon-rss:920752kB`), a `system` alert names the process and its size. It's high, or a warning for a virus scanner, which `[antivirus]` reports as well. A kill for exceeding a unit's or container's own limit (`Memory cgroup out of memory`, e.g. logguard's `MemoryMax`) is told apart. On a 2 GB host without swap, the nightly clamscan was killed this way every day for weeks without anyone noticing.

**Disk and memory** (`[resources]`, on by default): every minute logguard reads `df -Pk` for the `disks` paths (each filesystem once; default `/`) and `/proc/meminfo` plus `/proc/pressure/memory`. A filesystem under 10% free raises a warning, under 5% a high alert; memory gets a warning when less than 10% stayed available for 15 minutes, or when tasks spent 10% of the last 5 minutes stalled waiting for memory (pressure stall information). Each alert repeats at most every 6 hours. `status` shows the latest reading. This comes before the out-of-memory kills below: on a host without swap, a shortage that lasts is the warning sign.

**Failed services** (`[sources] services = ["logguard-xmpp-bot.service"]`, empty by default): logguard also follows systemd's own messages about these units (journal match `UNIT=<name>`, accepted only from PID 1) and raises a high `system` alert when one ends unsuccessfully (a non-zero exit status, a signal, a timeout, a watchdog kill, ...) and is not started again within `service_restart_grace` (default 2 minutes; keep it longer than the units' `RestartSec`): `service logguard-xmpp-bot.service failed (exit-code, exit status 78/CONFIG) and was not restarted: it is down` (for the bot, a wrong password or setting, after which `RestartPreventExitStatus=78` keeps it down). A failure that systemd recovers from on its own (`Restart=`: "Scheduled restart job"), or that someone starts again in that time, says nothing. When systemd gives up restarting a unit (`Start request repeated too quickly`), the alert comes at once. Each at most once an hour per service. Clean stops and restarts (`systemctl restart`) say nothing. Restart loops that systemd never gives up on are not reported.

**Journal integrity.** When journald no longer has the position logguard saved (journal files vacuumed, rotated away or deleted while lines were unread), logguard reads the last `initial_lookback` instead and raises a **high** `system` alert: expected after a downtime longer than journald keeps logs, otherwise someone may have removed evidence. `[journal] verify_every` (off by default) runs `journalctl --verify` and raises a high alert when an archived journal file fails: damaged, or, with `verify_key_file` (the verification key `journalctl --setup-keys` printed, for Forward Secure Sealing), changed after it was sealed. Files journald is still writing are left out (checked while they change, they can fail without anything wrong). Know what the key gives away: journald derives every sealing key from the verification key, so whoever reads it can seal edited entries of any past period too. Kept in `verify_key_file` on the server itself, it catches only an intruder who doesn't look for it; for a real guarantee keep the key elsewhere and verify copies of the journal there (`journalctl --verify --verify-key=... --file=...`). journalctl also takes it on its command line, where every local user can read it (`ps`) while the check runs, unless /proc is mounted with `hidepid=invisible`. logguard says so in a warning when it starts with the key set (at most once a week).

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
- **Without node identities, every key holder is fully trusted.** A compromised node can ban or trust addresses on the others, under any node's name (with identities, under its own only: below). `max_remote_ban` bounds how long its bans last there: the built-in default is 1 day, while the templates use 30 days, because both nodes are yours. A capped peer ban isn't renewed while the origin's longer ban continues; the address is then banned again only on local evidence. Peer bans wider than this node bans itself (`v4_wide_prefix`, or `v4_prefix` without growth; IPv6 `v6_prefix`) and allowlist entries wider than /16 (IPv6 /32) are ignored. A peer's suspicion report adds at most one ban threshold of points, relayed notices take at most 2 MB of memory at once (16 KB each), and each connection must deliver its message within 30 s. Protect `/etc/logguard/cluster.key` like a root password, and rotate it if it may have leaked (see below).
- **Except peers you limit** (`peer_accept`): `peer_accept = { "203.0.113.10:7946" = ["notices", "files"] }` lets what arrives from that peer's address be notices and `cluster-send-report` files only, whoever's facts they are (its own or forwarded); the rest is dropped, counted in `logguard status` and logged once per kind. The limit goes by the connection's source address, not the node name in the message, which any key holder can write, so it needs `allow_only_peers` (the default). Use it for a node that is more exposed than the rest, such as the Telegram relay node below: broken into, it still holds the key (it can read every fact), but can't ban, unban or allowlist anything on the others. Its files are written under the node name it first used, never one an unlimited peer uses, so it can't replace another node's weekly report.
- **Node identities** (optional, below): each node signs the facts it originates and the files it sends with an Ed25519 key of its own, and the others take a node's facts only with its signature. A broken-into node, or anyone who stole the cluster key, can then speak only for itself, not for the others; and a node is dropped by deleting its public key, without a new cluster key.
- At most 8 concurrent incoming connections, 30 s per message, 1 MB per message, 32 files in the inbox (a report merged later is read up to 64 MB unpacked): even 8 messages at once (each also decrypted into a copy) stay far inside the memory limit. A large sync (a full resend of thousands of bans) is split into messages of at most 512 KB, sent in order over one connection thread per peer. Run the same version on all nodes: an older node's large full sync can exceed the new 1 MB limit.

**Setup** (what the deploy scripts do for you):
1. `deploy.sh` generates `deploy/cluster.key` once on your Mac (`logguard cluster-keygen`, mode 0600, git-ignored) and ships it to every node. `install.sh` installs it as `/etc/logguard/cluster.key` unless one exists.
2. In each node's `[cluster]`: `enabled = true`, a unique `node_id`, `listen = "0.0.0.0:7946"`, and `peers` = the other nodes' `ip:7946`.
3. `install.sh` runs `logguard cluster-ufw-rules`, which opens 7946/tcp **only for the configured peers** (`ufw allow from <peer> to any port 7946 proto tcp`).

Check it with `logguard status` (per-peer delivery status and nodes heard from) or the TUI's overview (`Cluster: node1 - 1/1 peers ok`). Bans from peers show `(from peer vpn)` in their message, and `origin` in `actions.jsonl`.

### Node identities

With one shared key, the node name on a fact is only a claim: any key holder can write any name. Node identities make it a proof. Each node gets a signing key of its own, and every node pins the others' public keys:

```bash
logguard cluster-identity --out /etc/logguard/node.key   # on each node, as root: creates the key (0600), prints its line
```

```toml
[cluster]
identity_file = "/etc/logguard/node.key"
nodes = { node1 = "6h0w…=", vpn = "pQ3k…=", tg = "Zf1c…=" }   # the same on every node
require_signatures = true
```

- **What is signed:** each fact by the node it comes from, over its origin, sequence number, time and content (Ed25519, pure Rust). The signature travels with the fact when other nodes forward it (the hop count is outside it, as forwarders change it), and with full resyncs. `cluster-send-report` files are signed by their sender, over its name, the time sent, the file name and content. The shared key still encrypts and authenticates every message, as before.
- **What is checked:** a fact whose origin has a key in `nodes` is taken only with a valid signature from that key; otherwise it is dropped, counted in `logguard status` ("facts refused for their signature") and logged once per origin. A file under a pinned name must be signed by it, and then needs none of the `peer_accept` name rules above: it is that node's report, whichever peer it comes through. With `require_signatures = true`, facts and files from nodes not in `nodes` are refused too; without it, they are taken unchecked, as before (`nodes` then protects the pinned names only: a node broken into could still invent a new name).
- **Dropping a node:** delete its line in `nodes` on the others (with `require_signatures`) and restart them. Its facts and files are refused from then on, though it still has the cluster key: it can still read what the others share, and send heartbeats. Rotate the cluster key too (below) when that matters, or when the node is still in `peers`.
- **Rolling it out:** older versions ignore the signatures and still read every message, but leave them out when they forward a fact. So first update every node; then set `identity_file` on each (signing only: nothing is refused yet); then add `nodes` everywhere; and set `require_signatures` last. A node's own entry in `nodes` must match its `identity_file` (logguard refuses to start otherwise), so one `nodes` list fits every node.
- **A new key for one node:** `cluster-identity --out` a new file, put its public key in `nodes` on the others, then point `identity_file` at it and restart the node. Its facts sent in between are refused, and resent with the new signature only if it originates them again.
- **What it doesn't cover:** the node name on a heartbeat (`logguard status`'s "nodes heard from") is still a claim; and a node can still be trusted with what it says itself, within the limits above (`max_remote_ban`, `peer_accept`).

**Rotating the key** (`deploy/rotate-cluster-key.sh` on your Mac). Swapping the key on one node and then the next would leave a gap in which the two can't read each other, and facts sent in it are lost: a sender can't tell. So logguard also accepts the keys in `<key_file>.next` and `<key_file>.prev` from peers, while always sending with `key_file`, and the rotation goes in three rounds, each done on every node before the next. Like `deploy.sh`, the script only copies files (the step's script, and for `start` the new key) into a private, freshly created `/tmp/logguard-rotate.XXXX` on each node (over SFTP only, so hardened hosts whose SSH user may run no remote command work too); you then paste the printed command into a root shell there, as with `deploy.sh`: it copies the files into a private directory of root's, checks them against hashes computed on your Mac (so the SSH user can't swap the script root runs), and runs the step (no sudo needed):

```bash
./deploy/rotate-cluster-key.sh start  node1 vpn   # then paste the printed command into a root shell on each node
                                                  #   new key -> /etc/logguard/cluster.key.next (accepted, not used yet)
./deploy/rotate-cluster-key.sh switch node1 vpn   # ... rotate.sh switch: sends with the new key; old one -> cluster.key.prev
./deploy/rotate-cluster-key.sh finish node1 vpn   # ... rotate.sh finish: cluster.key.prev removed, only the new key works
```

Each root step restarts logguard, prints the node's key fingerprints (`logguard cluster-key-id`: the first bytes of the key's SHA-256, equal for equal keys, revealing nothing about it) and ends with `OK: the new key (…) is in place.`, or a warning if the node holds a different key. `logguard status` and the daemon's startup line show the fingerprints too, with "rotation: also accepting …" while a `.next`/`.prev` file exists. Steps can be repeated (stage and run a step again for a node where it failed), and run in the wrong order they stop with a message. The key copies (`/tmp/logguard-rotate.XXXX` and root's) are deleted when the step runs, whatever its outcome; until then it is readable by the SSH user, as `deploy.sh`'s copy is. `deploy/cluster.key` on your Mac becomes the new key when `finish` is staged, so `deploy.sh` installs the current key on new nodes. A `.next`/`.prev` file without a valid key stops the cluster on that node with a High alert instead of being ignored. Rotation needs the key in `key_file`, not inline as `key`. With node identities (above), removing one node from the cluster no longer needs it: deleting its key in `nodes` is enough to refuse what it says. Rotate the cluster key when the node left may still read the cluster's messages and that matters, or after a leak; node keys (`identity_file`) are not touched by the rotation.

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

## Web console (logguard-web)

[logguard-web](../logguard-web/README.md) shows the whole cluster on one HTTPS page for its admins (one or several, all equal): every node's bans, alerts, decisions, offenders, places, peers, certificates, disks and updates, with what needs attention first, every node's abuse report of the last day or week split per network owner (each part ready to mail), and `/metrics` for Prometheus. It only reads. It is a program of its own, under a user of its own, and never holds the cluster key: each node's logguard-web (its *agent*) hands that node's data to the console, sealed with a separate *web key* that can't make a ban. logguard's part is one read-only socket:

```toml
[console]
socket = "/run/logguard-console/console.sock"
group = "logguard-web"         # logguard-web's group: it may connect

[sources]
apps = ["logguard-web"]        # ban addresses that guess the console's password or probe it
```

- The socket answers `snapshot` (what the dashboard shows), `digest` (today's so far) and `abuse 24h` / `abuse 7d` (`abuse` alone: 7d); `unban`, `ban`, `allow`, `feeds clear`, `digest send` and every other command get `error: read-only socket` without reaching the daemon. The control socket stays root's.
- An abuse report is `abuse-report`'s, live: this node's own bans of the window from the actions log (also its rotated copies), each source's activity in the report's words, its country and network from `[geo]`, its first 25 log lines worded for an abuse desk, and how many more. At most the 1000 most persistent sources, ranked among the first 20,000 the window holds (it is built inside the daemon's memory limit; a flood's further sources are only counted); no RDAP lookups (the weekly report makes those). It is built beside the main loop (reading a week of the log takes a moment and holds up nothing), one at a time, two requests waiting at most, and handed out again for a minute. With `actions_log` off there is none.
- logguard makes the socket's directory its own at start (root, mode 0750, the group above; a directory someone else made is refused), the socket mode 0660. The directory's name must start with `logguard` and not be the control socket's.
- Without the group (logguard-web not installed) the console socket stays off and logguard says so at start; everything else runs as before.
- The snapshot carries logguard's `version` and, in `stats.hours`, events and bans per hour over the last 7 days (since logguard started: they aren't saved), for the console's longer charts and its table of differences between nodes.
- The snapshot's `geoblock` names the countries `[geoblock]` blocks (`countries`, `only_countries`, as ISO codes) and its AS numbers, so the console's map hatches them.


```bash
logguard unban 11.22.51.11                       # or a subnet: logguard unban 11.22.51.0/24
logguard ban 198.51.100.7 --for 30d --note "mail scanner"   # or a subnet; 1d by default
logguard allow 203.0.113.7 --for 7d --note "temporary access"
logguard allowed                                  # list entries with time left
logguard disallow 203.0.113.7
```

In the TUI, on the **Offenders**, **Bans**, **Events** (a ban decision) or **Alerts** tab (an alert about an address): `u` unbans the selected entry (after a `y` confirmation), `b` asks for a number of days to ban it (1 unless you type another number), and `a` asks for a number of days to allowlist it (7 unless you type another number, 365 at most as the daemon keeps them; the end date is shown); the command goes to the daemon in the background and its answer shows in the footer. The Bans tab lists the operator allowlist under the bans. A saved snapshot or a decision log is read-only: both keys say so instead.

- **Ban** bans an address or network until the time given (365 days at most), as if logguard had decided it: in the firewall, the actions log, and shared with the peers (who apply it like any peer ban, capped at their `max_remote_ban`). It counts as an offence, so a later automatic ban of it starts higher on the ladder. Refused for this host, cluster peers, allowlisted addresses and host names, operator allowlist entries (`logguard disallow` it first), a network with any of those or a recently logged-in address inside, an address inside a banned network, and networks wider than logguard's own widest ban (use a blocklist feed for those). Banning an address already banned replaces that ban. In shadow mode it is decided and shared, not applied, and the reply says so.
- **Unban** lifts the ban and also clears that address's score and offence history, so it isn't re-banned the next second, and a later ban starts again at 1 hour. Unbanning an address inside a banned subnet is refused with a hint: unban the subnet, or allowlist the address.
- **Allow** lifts every ban inside the network and protects it until it expires: never scored into a ban, never banned by peers. In nftables it goes into the `oper4`/`oper6` sets with a kernel timeout, accepted before feeds and bans, so it works even for an address inside a banned subnet. With the ufw backend nothing is added to ufw (an `allow from` rule would open every port to that network, past your own rules): an address inside a banned subnet stays blocked until that subnet is unbanned, and `logguard allow` says so.
- **Cluster:** both are shared, so peers follow the operator's decision. Peer allowlist entries are capped at `max_remote_ban`.

All commands talk to the daemon over `/run/logguard/logguard.sock`, which is root-only, so use `sudo`.

**Allowlisted host names.** `[allowlist] hosts = ["home.example.dyndns.org"]` allowlists what the names resolve to, like `nets`: never scored into a ban, never banned by peers, accepted before the drops in nftables (and iptables). They are resolved at start and every 10 minutes (every minute while one fails, keeping the addresses known so far; a warning says which name fails). A newly listed address's ban is lifted and its score forgotten; an address the name no longer resolves to is an address like any other. Whoever controls the name's DNS controls the entry, so use a name whose DNS is yours. `logguard status` shows what they resolve to.

## Blocklist feeds (optional)

```toml
[feeds]
enabled = true
urls = ["https://www.spamhaus.org/drop/drop.txt", "https://www.spamhaus.org/drop/dropv6.txt",
        "https://iplists.firehol.org/files/firehol_level1.netset"]
refresh = "24h"
```

- **Download:** every `refresh` period, with `curl` (falling back to `wget`). Shelling out keeps the binary free of a TLS library. A redirect must stay on https (`--proto-redir =https` in the default `fetch`, also used for geo databases and abuse contacts; add it to a `fetch` of your own). The last good copy of each list is cached in `cache_dir`, so a failed download keeps the previous list instead of emptying it. Failures raise a daily warning.
- **Formats:** plain CIDR lists, Spamhaus `cidr ; SBL…` lines and Spamhaus JSON lines.
- **Sanitising:** private and bogon ranges are dropped; FireHOL level1 lists `10.0.0.0/8`, `127.0.0.0/8` and `172.16.0.0/12`, which would break loopback and Docker. So are prefixes wider than /8 (IPv4) or /19 (IPv6), and anything overlapping your allowlist or cluster peers. Nested entries are merged.
- **Loading:** into the separate nftables sets `feed4`/`feed6` (ipset: `<iptables_chain>-feed4`/`-feed6`), in one atomic transaction (lists of up to 10,000 networks; a longer one is emptied, then filled 10,000 at a time), after the allowlist accepts and before logguard's own bans. A feed can never block your allowlisted addresses, peers or operator allowlist. More than `max_entries` (100,000) networks is treated as a broken feed, and a refresh covering more than `max_growth` (2) times the address space of the last accepted load (plus a /16) is refused too: the last accepted list (`<cache_dir>/accepted.txt`) stays loaded, and a `system` alert says why. After an intended change (a new feed URL), delete that file once. Networks wider than `min_prefix_v4` (/12) or `min_prefix_v6` (/24) are never loaded: one bad entry must not drop a whole provider at the prerouting hook, where only the static allowlist, peers and operator entries are exempt.
- **Whole networks (ASNs):** `asn_urls = ["https://www.spamhaus.org/drop/asndrop.json"]` (Spamhaus ASN-DROP: hijacked and criminal networks; JSON lines, `AS64500 ; ...` text or plain numbers) adds every address block the `[geo]` network database gives those ASNs, under the same limits as the other lists (`min_prefix_*`, `max_entries`, protected addresses). It needs `[geo]` with an `asn_url`; until the database is loaded the ASN lists are left out (`logguard feeds` says so) and a refresh follows once it is. A list built from other URLs than the last accepted one (`accepted.txt` records which) is an intended change, which the growth check doesn't refuse.
- **One-step removal:** `logguard feeds clear` empties the sets immediately (until the next refresh); `[feeds] enabled = false` plus a restart keeps them empty. logguard's own bans are untouched either way.
- `logguard feeds` shows per-list status. Feeds are only *applied* with the nftables or ipset backend in enforce mode; in shadow mode they're downloaded and counted only.

## WAF decisions: CrowdSec and others (optional)

logguard reads what it sees in logs; a WAF sees inside web requests (SQL injection, path traversal, a CVE probe in a header) that no log line here shows. `[waf]` closes that gap the other way round: the WAF decides, logguard blocks the address at the firewall, for every port and not only the web server's, and with a cluster on every node. CrowdSec's formats are built in; any other app that gives out the addresses it blocks works through a generic format.

```toml
[waf]
enabled = true
refresh = "1m"

[[waf.sources]]                     # CrowdSec's own detections (its AppSec WAF, scenarios, cscli)
name = "crowdsec"
format = "crowdsec"
url = "http://127.0.0.1:8080/v1/decisions?type=ban&origins=crowdsec,cscli"
api_key_file = "/etc/logguard/crowdsec-bouncer.key"     # from `cscli bouncers add logguard`; chmod 600
action = "ban"

[[waf.sources]]                     # CrowdSec's community blocklist: tens of thousands of addresses
name = "crowdsec-capi"
format = "crowdsec"
url = "http://127.0.0.1:8080/v1/decisions?type=ban&origins=CAPI,lists"
api_key_file = "/etc/logguard/crowdsec-bouncer.key"
action = "list"
```

- **Where from:** one of `url` (read with `[waf] fetch`, curl), `file` (a file another program writes) or `command` (a program and its arguments, no shell, 60 s at most). `api_key_file` sends its key in the header `api_key_header` (`X-Api-Key`, CrowdSec's; `Authorization` with `Bearer <token>` in the file for a token). curl gets it on its stdin (`-H @-`), never on its command line, where any local user could read it; a key file other users can read is refused, and so is a key sent over plain http to anything but loopback.
- **Formats** (`format`):
  - `crowdsec`: told apart by shape: the local API's decisions (`/v1/decisions`, or `/v1/decisions/stream?startup=true`: without `startup=true` the stream lists only changes, and is refused), `cscli decisions list -o json` (alerts holding decisions) and `-o raw` (CSV), or the blocklist mirror's plain list. Only the `Ip` and `Range` scopes are addresses (`Country`, `AS`, `Username` are left out), simulated decisions are left out, and durations (`3h59m56s`) are taken as relative, so the CrowdSec host's clock doesn't matter.
  - `plain`: one address or network per line, `#` and `;` comments (fail2ban, a blocklist file, anything exported as a list).
  - `json`: the entries at the dotted path `items` (arrays on the way are walked into: `decisions` finds every decision in a list of alerts; JSON lines work too), their fields named by `ip_field` (default `ip`), `duration_field`, `until_field`, `type_field`, `origin_field`, `reason_field`, as dotted paths. A list of strings is a list of addresses.
  - `csv`: the same fields by header name or column number (from 1); `delimiter`, `header`.
  - `regex`: every match of `pattern` on a line, with the groups `ip`, `duration`, `until`, `type`, `origin`, `reason` (linear-time, like `[[patterns]]`). E.g. `fail2ban-client banned` (`[{'sshd': ['192.0.2.1', ...]}]`) with `pattern = "'(?P<ip>[0-9a-fA-F.:]+)'"`.
  - A duration is a Go duration, a number of seconds or `90s`/`12h`/`7d`; `until` is a Unix time (seconds or milliseconds) or an ISO 8601 date. Without either, a decision lasts while it is listed. Any other app is one more format: a `Format` variant in `src/waf.rs` whose parser hands each entry's fields to `Parsed::add`, which checks them the same way for every format.
- **Filters:** `types` (default `["ban"]`: `captcha` and `throttle` are for an HTTP-layer bouncer; entries without a type always count) and `origins` (CrowdSec: `crowdsec`, `cscli`, `CAPI`, `lists`, `console`; empty: all).
- **`action = "ban"`** (for a WAF's own detections, up to `max_bans`, 10,000, per source): each decision becomes a logguard ban for as long as it lasts (`default_ban`, 4 h, when it doesn't say, renewed while listed; `max_ban`, 7 d, at most), with the reason `waf <name>: <scenario>`, category `waf` in the digest, in the TUI and the actions log, and shared with the cluster (`share = false` keeps it here). It is refused like an operator ban for allowlisted, peer and own addresses, networks wider than logguard's own bans, and also for an address someone logged in from lately: a WAF's false positive must not lock out a user. When the WAF drops the decision (`cscli decisions delete`), the ban is lifted, here and at the peers. A source that can't be read leaves its bans alone: they end on their own, in the kernel. `logguard unban` lasts only until the next read while the WAF still lists the address: delete the decision there, or `logguard allow` it. These bans work with every backend.
- **`action = "list"`** (for blocklists): the networks of all such sources go into the sets `waf4`/`waf6` (ipset: `<iptables_chain>-waf4`/`-waf6`), after the feeds' and before logguard's bans, sanitised as the feeds are (bogons, protected addresses, wider than `min_prefix_v4`/`_v6`, more than `max_entries` in all) and replaced in one step when they change. nftables and ipset only. `logguard waf clear` empties them until the next read.
- **Failures:** a source that can't be read, or gives out something that isn't a list (an HTML login page served with status 200, JSON cut short), keeps its last good decisions (`cache_dir`, with absolute end times: list entries still end when their decisions do). A `system` warning says so, once a day; `logguard waf`, the TUI, the digest and logguard-web show each source's state, and logguard-web's metrics have `logguard_waf_source_error`.
- **Timing:** decisions are read every `refresh` (1 min); a new ban is in the firewall within that. The first read waits until logguard has caught up with the journal.

## Blocking countries and networks (optional)

```toml
[geoblock]
enabled = true
countries = ["CN", "Russia"]     # ISO codes or names
only_countries = []              # e.g. ["UA", "DE"]: every other country is dropped
asns = [64500]                   # networks by AS number
```

- **Source:** the `[geo]` databases logguard has loaded anyway (DB-IP's lite country and network databases), so there is nothing to download and no second database in memory. The list is computed when they load (at start and after the weekly refresh) and loaded into the firewall; only its sets hold it afterwards. Computing it costs about 1 MB beyond the databases themselves, the United States included (the ranges are merged while they are read, measured with the test `real_geoblock_sizes`), and it goes into the firewall 10,000 networks per command, so the commands for a whole list are never in memory at once. The lite data places some addresses in the wrong country, and a network's addresses can move between monthly releases: this is coarse, not a curated list.
- **What is dropped:** the addresses the country database places in `countries`; with `only_countries`, those it places in any other country (addresses it places nowhere stay reachable); and the address blocks the network database gives `asns`. All three can be combined. Unknown country names or codes are refused at start (`logguard print-config` checks), and so is a country both blocked and the only one let in.
- **Never dropped:** the allowlist, this host's addresses, the cluster peers (as configured at start) and private or special-purpose ranges are cut out exactly, not by leaving out a whole block (an IPv6 address keeps its whole /64, the databases' granularity). Neighbouring ranges merge before they become CIDRs. With DB-IP's lite databases of autumn 2026 (computed in a few milliseconds): China is 15,040 networks (8,331 IPv4 + 6,709 IPv6), Russia 22,983, China, Russia, Iran and North Korea together 41,152, everything but Ukraine 27,690 (the other countries' neighbouring ranges merge), the United States 251,826. More than `max_entries` (200,000; raise it for the United States) is refused with a warning, and what was loaded before stays.
- **Where:** nftables: the sets `geo4`/`geo6`, dropped after the allowlist, operator allows, whitelisted ports and replies to the host's own connections, before the feeds and bans. ipset: `<iptables_chain>-geo4`/`-geo6`, one rule each. firewalld: the ipsets `logguard-geo4`/`-geo6`, sources of logguard's zone (whitelisted ports stay open; on a change only the difference is sent, and after a reload they come back with the bans). firewalld takes thousands of entries slowly while logguard waits, so it takes at most 50,000 networks: for more, use the nftables or ipset backend. Not with ufw or plain iptables; in shadow mode it is computed only.
- **Effects:** dropped traffic never reaches the firewall's log, so blocked countries make no events, bans or alerts. Cluster peers don't share it (each node has its own `[geoblock]`).
- `logguard status` shows what is loaded (`geoblock (CN): 8331 IPv4 + 6709 IPv6 networks, computed ..., active in nftables`), or why not. `enabled = false` and a restart empty the sets again.

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

**Certificates** are checked every 6 h against the live endpoints with `openssl s_client` (`/xmpp` = STARTTLS on 5222), so a failed ACME renewal is caught before clients see it. An expiring certificate also raises its own alert: **warning** under 21 days, **high** under 7. An endpoint that gives no certificate is checked again after 1, 2 and 4 minutes before it is reported, so a service still starting after a reboot raises no alert.

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
- **Wrong countries:** the lite data places some networks where they are registered, not where they are used (a server in Georgia on addresses registered in Latin America shows as Brazil). `[geo] places = { "198.51.100.0/24" = "GE" }` pins such networks to the right country (an ISO code or a name; the most specific network wins), ahead of the database: in labels, accounts' countries and the counters. `[geoblock]` keeps the database's own ranges.
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
- **A copy on Signal or Matrix (optional).** `signal_outbox`/`signal_user`
  (`/opt/logguard-signal-bot/outbox`, `logguard-signal-bot`) and `matrix_outbox`/`matrix_user`
  (`/opt/logguard-matrix-bot/outbox`, `logguard-matrix-bot`) work exactly like `tg_outbox`, next to
  the others or instead. logguard-signal-bot sends through signal-cli while the safety number
  with the admin is the one it pinned; logguard-matrix-bot sends Olm/Megolm-encrypted to the
  devices the admin verified. Both send OpenPGP files instead when that isn't possible (or keep
  the copies waiting without an OpenPGP key). A bot that sits on copies longer than
  `bot_stuck_after` is reported over XMPP and to the other copy bots. `notify-test --signal` and
  `--matrix` put a test there and wait up to a minute. The weekly abuse report goes there too.
  The bots' sides are in their READMEs.
- **A copy over XMPP from a host without ejabberd (optional).** `xmpp_outbox`/`xmpp_user`
  (`/opt/logguard-xmpp-bot/outbox`, `logguard-xmpp-bot`) work exactly like `tg_outbox`, for
  logguard-xmpp-bot in client mode (`BOT_MODE=client`): with an account on any XMPP server it
  sends the admin (any server too) OMEMO-encrypted messages and files, and OpenPGP files when
  OMEMO can't reach the admin (or keeps them waiting without an OpenPGP key). For a VPN server,
  a relay node or the desktop profile (`deploy/logguard-desktop.toml` names the lines). Not with
  `bot_outbox`: one logguard-xmpp-bot per host. `notify-test --xmpp-client` puts a test there and
  waits up to a minute. The bot's side is in logguard-xmpp-bot's README ("Client mode").
- **Admin messages on Telegram only.** With `tg_outbox` and `admins` empty, admin messages go
  to logguard-tg-bot only and never over XMPP, while users are still warned over XMPP. A Telegram bot
  that leaves messages unsent is then raised as a system alert instead (journal, actions log,
  peers with `relay_notices`). Without ejabberd on the server, use `xmpp = false` instead.

```bash
logguard -c /etc/logguard/logguard.toml notify-test you@example.org     # on the server: one real test message
logguard -c /etc/logguard/logguard.toml notify-test --bot admin@example.org   # the same through the admin bot (OMEMO)
logguard -c /etc/logguard/logguard.toml notify-test --telegram                 # a test through the Telegram bot (logguard-tg-bot)
logguard -c /etc/logguard/logguard.toml notify-test --mail                     # a test through the mail bot (logguard-mail-bot)
logguard -c /etc/logguard/logguard.toml notify-test --signal                   # a test through the Signal bot (logguard-signal-bot)
logguard -c /etc/logguard/logguard.toml notify-test --matrix                   # a test through the Matrix bot (logguard-matrix-bot)
logguard -c /etc/logguard/logguard.toml notify-test --xmpp-client              # a test through the XMPP client bot (logguard-xmpp-bot, BOT_MODE=client)
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
sudo logguard ssh-audit [--all] [--json]               # sshd's settings against this host's layout, with fixes
logguard abuse-report [--since 7d] [--contacts] [-o file]   # evidence per attacker, for abuse desks
logguard cluster-send-report <file>                         # a JSON abuse report to the peers' inbox
logguard replay --state state.json *.log               # also write the state file the daemon would keep
logguard print-nft [--no-tripwires]                    # ruleset installed in enforce mode
logguard status                                        # plain-text summary: bans, cluster, exposure, offenders
logguard unban <ip|net> / ban <ip|net> --for 1d / allow <ip|net> --for 7d / disallow <ip|net> / allowed
logguard test-pattern [--pattern NAME] [-v] <file>...  # what the [[patterns]] find in log lines
logguard expect-change PATH=SOURCE...                  # announce a watched file's new content (installers)
logguard feeds [status|refresh|clear]                  # blocklist feeds
logguard waf [status|refresh|clear]                    # decisions of WAFs: CrowdSec, ...
logguard digest [--send]                               # preview / send the daily digest
logguard cluster-keygen                                # new random cluster key
logguard cluster-identity --out /etc/logguard/node.key # this node's signing key; prints its line for [cluster] nodes
logguard cluster-key-id [--file deploy/cluster.key]    # fingerprints of the keys in use (compare nodes)
logguard cluster-ufw-rules                             # ufw commands opening the cluster port to peers only
```

`replay` accepts `journalctl` short output and `journalctl -o json`. To test new rules against real traffic first:

```bash
journalctl -u ejabberd -u ssh -k --since -7d -o json > week.json && logguard -c /etc/logguard/logguard.toml replay week.json
```

TUI keys (`?` shows them all; the footer shows the ones that work on the current tab): `1-9`/`Tab`/`←→` switch tabs (Overview, Offenders, Bans, Events, Accounts, Exposure, Countries, Map, Alerts, and `0` Patterns when `[[patterns]]` are configured) · `↑↓` select · `PgUp`/`PgDn`/`Home`/`End` page, first, last · `Enter` opens the details of the selected address, ban, decision or alert under the list (evidence, whole message, tracked addresses in a banned subnet; `↑↓` move on to the next row) · `/` filters the rows by any text in them (an address, a country, a signal; `↑↓` pick a row while it is typed, `Enter` keeps it, `Esc` clears it) · `o` sorts Offenders (danger, last seen, address) and Bans (newest, time left, address) · `s` cycles the minimum severity on Events and Alerts · `t` cycles the topic on Alerts · `u` unban · `b` ban for N days · `a` allowlist for N days · `z` zooms the map on Europe · `PgUp`/`PgDn` scroll the networks on the Countries tab · `p` pauses · `r` refreshes now · `q` or `Ctrl-C` quits (`Esc` doesn't). The cursor stays on the same address when a refresh re-sorts a list. The Overview's **Health** panel shows the cluster peers, blocklist feeds, certificates, disk and memory, the last virus scan and the cron watch, coloured by how they are doing; the footer shows the node, the mode (`ENFORCE`/`SHADOW`) and how fresh the data is (red when the daemon stopped answering). Snapshots load in the background, so the keys never wait for a busy daemon. In an 80-column terminal, less important columns (fast/slow scores, place, signals) are left out before addresses are cut, and the tab bar glues each number to its name (`4Events`). **Alerts** (9) lists the latest 50 alerts, newest first, however many bans came after them (the Events tab keeps the last 500 decisions, mostly bans, so on a busy day an alert scrolls out of it within hours): time, severity, topic (suspicious login, account under attack, exposure change, host integrity, system, ...), the accounts concerned and the message; its details add whether the address is still banned, the note sent to the user and the evidence. The tab bar and the Overview count the high and critical alerts of the last 24 hours in red. **Patterns** (0, only with `[[patterns]]` configured) lists each pattern with its kind, lines read from its unit or file, matched lines, last match, addresses, the lines it matched without an address in group `ip`, its port and where its lines come from; for the selected one it shows the 20 busiest addresses (lines, last seen, banned or how dangerous now) and the latest 5 lines without an address.

`tui --actions <file>...` reads decision logs (`/var/log/logguard/actions.jsonl` and its rotated `.gz` copies, also ones copied to another machine, or the logs of several servers together) without the daemon and shows the state at their end: the bans still active then, the decisions, and per country and network the active bans, the sources banned during the period, their evidence lines and the ports in them. Nothing is re-scored. The tabs are Overview (period, bans per cause, from which peer, bans per hour), Bans, Events, Countries, Map, Trends and Alerts (the log's latest 500); scores, accounts and the exposure scan aren't in the log. **Trends** (6) shows bans per day over the whole log (as many recent days as fit) and a table of weeks (Monday to Sunday, UTC), newest first: bans, the change from the week before, distinct sources, and the three countries and networks most bans went to. Use it after a tuning change, e.g. a new `slow_threshold`, to see whether it cut the noise or let more through; merge rotated copies (`actions.jsonl*`) to cover more weeks. Places come from the `[geo]` database when it's set up on that machine, else from the ban messages, which name the place only for bans decided on that server (bans from peers stay "unlocated"). Given several logs, a decision logged twice counts once: the same line in two files, or a ban received from a peer whose own log, with the original ban, is among the files (within 5 minutes). What's still banned at the end is worked out per log, so an unban in one log never ends another server's ban.

## Install from a release bundle

Without a Rust toolchain: every version tag `logguard-v<version>` gets its bundle, `logguard-<version>-<commit>-<arch>.zip` for each architecture (`x86_64-linux-musl`, `aarch64-linux-musl` for arm64, `armv7-linux-musleabihf` for 32-bit ARMv7 with hardware floating point), as an asset of the tag's GitHub Release (see "Releases" in the [repository README](../README.md#deployment)); CI also keeps one for every commit as a workflow artifact (they expire and need a GitHub login), and `scripts/bundle.sh` builds it locally. It holds the static binary, everything `deploy.sh` copies to a server, the config templates in `configs/`, `SHA256SUMS`, and `install.sh`.

**Download and verify** (on your machine, then copy the zip over, or on the server): take the zip for the server's architecture (`uname -m`: `x86_64`, `aarch64`, or `armv7l` for armv7) from the GitHub Release of the version's tag, with the [GitHub CLI](https://cli.github.com/) or from the [Releases page](https://github.com/makhort/Logguard/releases) (each crate's releases are tagged `logguard-v<version>`):

```bash
arch=x86_64-linux-musl     # the server's: aarch64-linux-musl (arm64), armv7-linux-musleabihf (32-bit ARM)
gh release download logguard-v0.4.0 --repo makhort/Logguard --pattern "*-$arch.zip*"   # the zip, its .sha256 and .sigstore.json
sha256sum -c logguard-*-$arch.zip.sha256              # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify logguard-*-$arch.zip --repo makhort/Logguard --source-ref refs/tags/logguard-v0.4.0
```

`gh attestation verify` (after `gh auth login`) checks the signed build provenance: that this repository's CI built exactly this zip from that tag. With `--bundle logguard-*-$arch.zip.sigstore.json` it checks the attestation attached to the Release instead of fetching it from GitHub. Only a public repository's releases have one (GitHub offers attestations for private repositories only with Enterprise Cloud).

On the server (`unzip` comes with `apt install unzip`, or `dnf install unzip`):

```bash
arch=x86_64-linux-musl     # as above: aarch64-linux-musl, armv7-linux-musleabihf on ARM
unzip logguard-*-$arch.zip && cd logguard-*-$arch
sudo ./install.sh --template logguard-standalone.toml   # a new server: only puts /etc/logguard/logguard.toml in place (Fedora: logguard-standalone-dnf.toml)
sudoedit /etc/logguard/logguard.toml             # allowlist, [notify], [cluster] node_id and peers, ...
sudo ./install.sh                                # installs and starts logguard (in shadow mode)
```

- **Templates** (`configs/`, `--template` takes the file name, or the short one: `tg` for `logguard-tg.toml`): `logguard.toml` for an XMPP server (the default), `logguard-standalone.toml` for a host with SSH and UFW only, `logguard-desktop.toml` for a Linux desktop or laptop (`--template desktop`; "Desktops and laptops"), `logguard-tg.toml` for the Telegram relay node; each with a `-dnf` variant for Fedora and RHEL (`vpn-dnf` for `logguard-standalone-dnf.toml`; `logguard-dnf.toml` is the default on a host with dnf and no apt). A finished config can go in at once: `sudo ./install.sh --config my.toml`.
- **Upgrades:** run `sudo ./install.sh` from the new bundle. Your config stays; the matching template (by `[cluster] node_id` and `package_manager`) lands next to it as `logguard.toml.new`, and `config-diff` shows what the new version changes. The previous binary stays as `/usr/local/bin/logguard.prev`.
- **Cluster key:** the first node whose config has `[cluster] enabled` gets a new `/etc/logguard/cluster.key`. Copy it to the others (as root, mode 0600) and install them with `sudo ./install.sh --cluster-key FILE`.
- **What it checks:** root, Linux, systemd, and that the bundle's binary runs here (the bundle's `TARGET` names its architecture). It copies the bundle into a directory only root can write and checks every file against `SHA256SUMS` there, so a non-root owner of the unzipped files can't swap them in between; then it runs the same `install.sh` as `deploy.sh` (below). `./install.sh --check` only checks the files. `SHA256SUMS` catches damaged files, not a forged bundle: that is what the attestation (above) is for.

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `logguard_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) and `logguard-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"` or `"*.rpm*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once; neither needs dpkg or rpm, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). The package is for one host at a time: there is no apt or dnf repository.

```bash
sudo apt install ./logguard_0.4.0-1_amd64.deb      # Debian, Ubuntu; Fedora, RHEL:  sudo dnf install ./logguard-0.4.0-1.x86_64.rpm
sudoedit /etc/logguard/logguard.toml               # a new host: the template is in place, nothing runs yet
sudo logguard -c /etc/logguard/logguard.toml print-config > /dev/null && sudo systemctl enable --now logguard logguard-abuse-report.timer
```

- **Paths:** `/usr/bin/logguard` (the bundle: `/usr/local/bin`), `/usr/bin/logguard-avscan` and `/usr/bin/logguard-abuse-report`, the units and timers in `/usr/lib/systemd/system`, the config templates in `/usr/share/logguard/templates` (`logguard.toml`, `-vpn`, `-tg`, `-desktop`, each with a `-dnf` variant: on a new host copy another one over `/etc/logguard/logguard.toml`). `/etc/logguard`, `/etc/default/logguard-avscan`, `/etc/default/logguard-abuse-report` and `/etc/logrotate.d/logguard` are the same as the bundle's; the last three are the package's config files (dpkg asks about them on an upgrade only if you changed them; rpm keeps yours and saves the new one as `.rpmnew`).
- **Nothing starts on its own.** A new host gets the template (`logguard-dnf.toml` where dnf is the package manager, else `logguard.toml`) as `/etc/logguard/logguard.toml`: its names and addresses are examples, so logguard isn't enabled or started until you run the lines above. The timers are yours to enable too (`logguard-abuse-report.timer`; `logguard-avscan.timer` with `[antivirus]`); once enabled they stay enabled across upgrades.
- **Upgrades:** the config stays; the matching template (by `[cluster] node_id` and `package_manager`, as `install.sh` picks it) lands next to it as `logguard.toml.new`, and `config-diff` against the previous version's defaults is printed. logguard is restarted only if it was running and the config is valid for the new version (`print-config` accepts it); otherwise it keeps running the previous version and the install says what to fix. The cluster port is opened for the peers as `install.sh` does (ufw, or firewalld's rich rules; plain iptables rules are only printed).
- **Over a bundle or `deploy.sh` install:** the package takes it over. The bundle's binaries under `/usr/local` (`logguard`, `logguard.prev`, the two helper scripts) and its units in `/etc/systemd/system` (they would shadow the package's) are removed, what was enabled is enabled again on the package's units, and the config, the cluster key, the state and the timer settings stay; then logguard is restarted if it was running. The integrity watch reports each removed file as a warning once (`/usr/local/bin` and `/etc/systemd/system` are watched by content; the new paths are the package manager's, covered by the weekly package check).
- **Replacing the config:** when a terminal is there, the install asks whether to replace the config with this version's template (the old one kept as `logguard.toml.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `LOGGUARD_PACKAGE_CONFIG=replace` (or `keep`) answers without asking: `sudo LOGGUARD_PACKAGE_CONFIG=replace apt install ./logguard_*.deb`. After a replacement logguard keeps running with the old config until you edit the new one and restart it.
- **Rollback, removal:** rollback is installing the previous version's package (`apt install ./logguard_<old>.deb --allow-downgrades`, `dnf downgrade ./logguard-<old>.rpm`); there is no `logguard.prev`. `apt remove logguard` (`dnf remove`) stops and disables the service and timers and keeps `/etc/logguard`, `/var/lib/logguard` and `/var/log/logguard`; `apt purge logguard` removes them too, cluster key and state included (rpm has no purge: delete them by hand). `dpkg-reconfigure logguard` (rpm: `dnf reinstall ./logguard-*.rpm`) runs the post-install step again.

## Rollout

1. **Deploy in shadow mode** (the default), next to the existing cron jobs:
   ```bash
   ./deploy/deploy.sh                      # on the Mac: tests, builds the static binary, copies to the ssh host given (or deploy.sh's default)
   # then paste the command it prints into a root shell on the server
   ```
   UFW logging must be on for firewall signals (`ufw logging low`).
2. **Review for 1–2 weeks** using `logguard tui` and `/var/log/logguard/actions.jsonl`. Look for "likely false positive" and "crossed the ban threshold" (protected-address) alerts, and tune weights in `/etc/logguard/logguard.toml`.
3. **Enforce:** set `mode = "enforce"` and run `systemctl restart logguard`. Then check:
   ```bash
   nft list table inet logguard            # rules + ban sets with remaining timeouts
   ```
   The table hooks at prerouting right after connection tracking (`priority mangle - 1`), so it runs **before** UFW's chains and Docker's DNAT; your ALLOW rules can no longer shadow the bans. Allowlisted networks get an explicit accept in that table too, and so do replies to the server's own connections.
   Rollback: set `mode = "shadow"`, restart, then `nft delete table inet logguard`.
4. **Retire the Python pipeline:** remove `/etc/cron.d/log_analyzer` and `/etc/cron.d/daily_log_analyzer`. Keep `daily_cleanup` (ejabberd DB maintenance). Done on both servers in 2026-10; the Python files are gone from this repo too (see the git history).
5. **Delete, never reorder, the old auto-generated UFW deny rules** (`blocked_*`, `ejabberd_*`). They sit below the ALLOW rules, so they never matched traffic to open ports: in Sep–Oct 2026, 4,438 XMPP connections and 106 SSH sessions came from addresses they "deny". Several of them also cover your own users. In that month, people logged in from `11.44.15.0/24`, `11.50.62.0/24`, `11.56.62.0/24`, `11.24.47.0/24`, and `11.36.56.0/24`. Making those rules effective would lock those users out.

## Restarts, reboots and upgrades

**Upgrading:** `install.sh` keeps your `/etc/logguard/logguard.toml` and saves the new template next to it as `logguard.toml.new`. Before replacing the binary, it saves the old version's defaults (`print-config` without a config file). After installing, it runs:

```bash
logguard -c /etc/logguard/logguard.toml config-diff --against <old defaults>
```

That lists unknown options (typos, or removed ones; the daemon refuses to start with them), **new options** with their defaults, **changed defaults** (marked as unaffected if your file sets the option), and whether the file is valid. Run it by hand any time; without `--against` it lists the sections your file doesn't set, and `--all` lists every option.

**The bots' new names (2026-10-17):** `xmppbot` is now `logguard-xmpp-bot` (`/opt/logguard-xmpp-bot`, `logguard-xmpp-bot.service`) and `tgbot` is `logguard-tg-bot` (`/opt/logguard-tg-bot`, `logguard-tg-bot.service`, user `logguard-tg-bot`, the new default of `tg_user`). Deploy this logguard first (its abuse report unit may write to the new outboxes), then each bot: the bot's `install.sh` moves its old install over and rewrites the old outbox paths, `tg_user` and unit names in `logguard.toml` and `/etc/default/logguard-abuse-report` (keeping a copy of each), then restarts logguard. The bots' READMEs have the details.

**Rolling back:** the replaced binary is kept as `/usr/local/bin/logguard.prev` (a package install: the previous version's package instead, "Install from a package"). `logguard --version` shows the git commit a binary was built from (plus ", modified" for uncommitted changes), and `git checkout <commit> && ./deploy/deploy.sh` rebuilds any earlier version.

After a reboot logguard re-applies everything that lives only in the kernel: active bans, operator allowlist entries and blocklist feeds. It resumes the journal from its saved position. If journald no longer accepts that position, for example because old journal files were vacuumed, it falls back to `initial_lookback` instead of retrying forever. Events from history are scored on their own timestamps, and anything carrying wall-clock time (exposure scans, cluster messages, Nextcloud's live logs) waits until the backlog is processed.

## Memory

The unit runs with `MemoryHigh=112M` and `MemoryMax=128M` (child processes included). Measured peaks:

| scenario | logguard | with `[geo]` |
|---|---|---|
| a month of real traffic (Sep–Oct, ~210k records) | ~10 MB | ~50 MB |
| synthetic flood: 280,000 sources, no bans | ~37 MB | ~66 MB |
| synthetic flood: 450,000 sources, 222,700 bans in 42 h | ~80 MB | ~115 MB |

The patch status's `apt-get -s` (or `dnf check-update`) runs in a transient unit of its own (`systemd-run`), outside this limit; the weekly package check drops what it reads from the page cache as it goes. `systemctl status logguard` shows a peak that includes page cache (journal and geo files read at start), which the kernel reclaims under the limit rather than killing anything.

The floods are far beyond what's possible from UFW: its log rules are rate-limited to about 3 lines a minute (the real month had 141,772, which is exactly that). Per-address state is about 600 bytes, and `[scoring] max_tracked_ips` (50,000) bounds it. The real month peaked at about 4,200 addresses over two days. When the cap is reached, the least suspicious 20% are dropped (banned ones last, and they stay banned). The geo database is released before a weekly reload, so two copies never coexist. If memory is ever tight, `[geo] enabled = false` saves 30–40 MB.

## Files

| path | purpose |
|---|---|
| `/etc/logguard/logguard.toml` | configuration (`deploy/logguard.toml` is the annotated template; the package keeps the templates in `/usr/share/logguard/templates`) |
| `/var/lib/logguard/state.json` | journal cursor, bans, repeat offenders, trusted IPs, per-account networks, providers and SSH keys, the cron/file, package, set-uid and outbound-connection baselines. Gzip-compressed JSON (`zcat state.json \| jq .`; older plain-JSON files are still read). Saved at most every 10 min when something changed, hourly otherwise, and on stop. After a crash the journal is replayed from the saved cursor, and bans live on in the kernel, so nothing is lost. After the Sep–Oct month the file was 95 KB (539 KB before), which is at most ~14 MB of writes a day instead of ~150 MB. An unreadable file is renamed to `state.bad-<time>` (not overwritten), and a high `system` alert says what was lost |
| `/var/lib/logguard/geo/` | offline country and network databases (`[geo]`) |
| `/var/log/logguard/actions.jsonl` | audit log of every ban, unban and alert (rotated weekly by `/etc/logrotate.d/logguard`, 12 weeks kept) |
| `/run/logguard/logguard.sock` | snapshot socket for the TUI (root only) |
| `/run/logguard-console/console.sock` | read-only snapshots for logguard-web (`[console]`; root and its group) |
| `/etc/logguard/cluster.key` | shared cluster key (mode 0600; same file on every node) |
| `/var/lib/logguard/feeds/` | last good copy of each blocklist feed |
| `/usr/local/sbin/logguard-avscan`, `/etc/systemd/system/logguard-avscan.{service,timer}` (the package: `/usr/bin/logguard-avscan`, `/usr/lib/systemd/system/`) | the daily ClamAV scan (`[antivirus]`); settings in `/etc/default/logguard-avscan` |
| `/var/log/logguard/avscan.log` | scan results read by logguard (rotated monthly) |
| `/usr/local/sbin/logguard-abuse-report`, `/etc/systemd/system/logguard-abuse-report.{service,timer}` (the package: `/usr/bin/logguard-abuse-report`, `/usr/lib/systemd/system/`) | the weekly abuse report for the admin bot; settings in `/etc/default/logguard-abuse-report` |
| `/var/lib/logguard/inbox/` | reports peers sent with `cluster-send-report` (mode 0700; deleted once merged) |

## Development

The project is a git repository. `scripts/ci.sh` runs what CI runs: `cargo fmt --check`, clippy with warnings as errors, the tests, `cargo audit` (fails on known vulnerabilities, unsound code and yanked versions of dependencies; unmaintained ones are only reported; offline it uses the advisory database already on disk), the static musl build, and a parse check of both config templates. `deploy/deploy.sh` runs it before every deployment, `scripts/install-hooks.sh` makes every `git push` that touches `logguard/` run it, and `.github/workflows/logguard.yml` runs it on GitHub.

```bash
./scripts/ci.sh                                             # all checks (~1 min); LOGGUARD_SKIP_AUDIT=1 skips cargo audit
cargo test                                                  # tests only
cargo build --release --target x86_64-unknown-linux-musl    # static Linux binary from macOS (rust-lld, see .cargo/config.toml)
cargo build --release --target aarch64-unknown-linux-musl   # the same for arm64; armv7-unknown-linux-musleabihf for 32-bit ARM
TARGET=aarch64-unknown-linux-musl ./deploy/deploy.sh ...    # deploy to an arm64 server (ci.sh builds $TARGET)
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
- **`su` alerts** on the XMPP server: `su` from the SSH gateway user to root, and between root and the `ejabberd` account (the database cleanup script), each with the account's last SSH login and its place. (Neither server has `sudo`.)
- **The package and set-uid check with dpkg**: no file differs from its package's checksums, 17 set-uid programs. **The patch status with `apt-get -s`** after an upgrade: the old kernel still running.
- **Watchdog:** both units run as `Type=notify` with `WatchdogSec=2min`, without watchdog restarts.
- **The SSH audit on the VPN host** (2026-10-28, OpenSSH 8.9p1, a provider's cloud image with password and key logins): `ssh-audit` found root's password login from the internet (high), passwords accepted, with the setting traced to cloud-init's `sshd_config.d/50-cloud-init.conf:1` in front of `sshd_config`'s own `PasswordAuthentication no` (named as ignored), and two notes (`LoginGraceTime 600`, `X11Forwarding yes`). After the fixes it suggested (and a reload), it found no problems, and the daemon's next reading logged them as fixed. The run showed two messages to improve, since changed: the fix named a cloud-init setting on a host where the image's cloud-init wasn't installed, and `LoginGraceTime` was shown in seconds while the file said `10m`. The edited `sshd_config` also went through the scan of changed files with ClamAV (`clamscan`, nothing found).
- **On another node of the cluster (2026-10-27),** upgraded to 0.3.0 (`09951df`) in enforce mode with nftables: IPv4 bans drop traffic, including subnet bans grown from a /24 to a /22; IPv6 bans work there too, including /64 subnet bans (`8 bad addresses in subnet`, distributed probing), with the addresses inside shown as banned. The process watch learned 3 outbound (program, port) pairs and then kept watching. The exposure watch caught both directions of a port change: a new listener (`new internet-facing listener 0.0.0.0:7948/tcp (logguard-web, allowed by ufw)`) and an allow rule with nothing behind it (`ufw allows 7949/tcp from anywhere, but nothing listens on it publicly`). `logguard ssh-audit` as root against its harden-vps.sh gateway (OpenSSH 10.0p2): `sshd -T` and `sshd -T -C` per user worked, the gateway user was detected, and no problems were found. The daemon's own first reading came 5 minutes after the restart, as an info alert that was only logged (`SSH audit (gateway (...)): no problems`), and `status` showed it under "ssh audit".

### On a Fedora test server (2026-10-25)

A Fedora Cloud VPS for one evening, following [TESTING-fedora.md](TESTING-fedora.md): Fedora 44, x86_64, kernel 7.2.10, firewalld 2.4.4 (nftables underneath), rpm 6.0.2 and dnf5, NetworkManager, SELinux disabled by the provider's image. Installed from the x86_64 release bundle with the `logguard-standalone-dnf.toml` template, real scanners on the public address, and a VPN as the probe (exits in Brazil, the Netherlands and Argentina). Verified:

- **Install from a bundle** on a new server: the template first, then the install (the bundle's binary checked to run here); upgrades from later bundles kept the config.
- **firewalld's log lines** (`firewall-cmd --set-log-denied=unicast`): `filter_IN_public_REJECT` lines became port-scan and tripwire signals; real scanners were banned on their first tripwire hit, in shadow and in enforce mode.
- **The exposure watch reading firewalld's zones:** sshd `allowed by firewalld [ALLOW ssh (public)]`; a test server blocked, then allowed after `--add-port`, then a dead rule once it stopped; a rich rule for one address shown as allowed from some sources only; the baseline after the startup grace and a "listener gone" alert.
- **rpm and dnf** (`package_manager = "dnf"`): package origins in the cron watch (`package pam`, `package openssh-server`; `/etc/pam.d/sudo` flagged MODIFIED and back); the package check matched 7,472 files against rpm's digests and learned 14 set-uid programs, and a byte appended to `/usr/bin/tree` raised the high alert with `dnf reinstall` as the fix; the patch status ran `dnf check-update` and saw the newer installed kernel (7.2.11 while 7.2.10 ran) and 9 programs on replaced libraries.
- **The firewalld backend:** logguard's ipsets, its zone (target DROP) and the forwarding policy made with one reload; bans restored at start; an operator ban dropped the probe (its SYNs logged as `filter_IN_logguard_DROP` and not counted again), and it connected again after `unban`; bans lifted on time, as firewalld's entries don't expire; after `firewall-cmd --reload` and after `systemctl restart firewalld`, all bans back within 30 s, with the high alert.
- **nftables next to firewalld:** logguard's table, its sets with kernel timeouts and the kernel tripwire rules loaded on kernel 7.2; `firewall-cmd --reload` left the table untouched (firewalld 2.4 removes only its own).
- **The ipset backend:** the sets and their rules for IPv4 and IPv6, a ban with its kernel timeout, blocklist feeds loaded into `logguard-feed4` (with the ASN-DROP networks), and the chain rebuilt within 30 s after `iptables -t mangle -F logguard`.
- **Honeypot ports:** 22 and 23 set as honeypots, tried with `nc` from the VPN's exit nodes.
- **Blocking by country** (ipset backend): Brazil and the Netherlands came to 32,358 IPv4 and 104,957 IPv6 networks, loaded a second after the geo database; exits in both countries timed out with no ban made, one in Argentina connected; `enabled = false` emptied the sets.
- **Memory:** 47-59 MB peak, under the unit's 128 MB. With Brazil and the Netherlands blocked it peaked at 80 MB; the list is now computed and loaded in a fraction of that (see "Blocking countries and networks"), not yet measured on a server.
- **Found and fixed on the way:** a bundle could carry an older binary under a newer commit's name (`bundle.sh` reused what was built); `status` asked nftables for rate limits under other backends; a failed start (a `[verify] interval` under 1h) logged its reason only at info priority; the package count read 0 after a restart; the feeds status named nftables under ipset; a first install warned it couldn't announce its files; the patch status left out the other pending updates when something needed attention; and `/usr/local/sbin` (a link to `/usr/local/bin` on Fedora 42 and later) made every upgrade two integrity changes.

## Not yet verified

- **Users' own notifications** (in their language), which are only sent in enforce mode: the XMPP server enforces since mid-October 2026, but none has been confirmed reaching a user yet. `notify-test <jid>` covers delivery and translation.
- **The Telegram copy** (`tg_outbox`, Telegram-only admins, `notify-test --telegram`) and **the Telegram relay node** (`xmpp = false`, `relay_notices`, `peer_accept`, abuse report role `relay`): new in 2026-10, covered by tests on the Mac only (`tests/layouts.rs` runs the daemon in every layout; the report hand-off runs the script with a stand-in logguard). The real `nft` and journald are not part of those runs.
- **The mail copy** (`mail_outbox`, logguard-mail-bot): new on 2026-10-17, covered by tests on the Mac (the layouts above; the bot against a fake mail server and GnuPG). Since 2026-10-20 it also runs on a server: `notify-test --mail` went through the outbox and a real mail server, and GnuPG decrypted it and verified the bot's signature. Opening the mails in Thunderbird, K-9 or FairEmail is not verified yet, and neither are real alerts or the weekly report by mail (a digest, `digest --send`, arrived and verified).
- **The Signal and Matrix copies** (`signal_outbox`, `matrix_outbox`, logguard-signal-bot and logguard-matrix-bot): new on 2026-10-25, covered by tests on the Mac only (the layouts above; the Matrix bot against a fake homeserver whose admin devices decrypt with vodozemac, the Signal bot against a fake signal-cli). Not yet tried with a real homeserver, Element, signal-cli or Signal account.
- **The XMPP client bot** (`xmpp_outbox`, logguard-xmpp-bot with `BOT_MODE=client`): new on 2026-10-26, covered by tests on the Mac only (layouts 14 and 15 above, and the bot's unit tests: its settings, the OpenPGP fallback's key and file names, the link it sends). Its OMEMO is the admin bot's, which works with Conversations; the client mode itself, SRV lookup, a server other than ejabberd, `ALLOW_SCRAM_SHA1` and the OpenPGP files in a real client are not yet tried.
- **Node identities** (`[cluster] identity_file`, `nodes`, `require_signatures`, `cluster-identity`): new on 2026-10-27, covered by unit tests on the Mac only (forged origins, forwarding and full syncs, dropped and unsigned nodes, signed files, older nodes reading signed messages). Since 2026-10-28 all four nodes of the authors' cluster sign their facts and pin the other three's keys with `require_signatures = true` (`logguard status`: "3 node keys pinned, others refused"), and bans flow between them as before. Not yet seen: a fact actually refused for its signature, a node dropped from `nodes`, and a cluster where older versions forward signed facts.
- **`[waf]`** (CrowdSec and other WAFs' decisions): new on 2026-10-27, covered by tests on the Mac only, against CrowdSec's documented answers (the local API's decisions and stream, `cscli decisions list -o json` and `-o raw`, the blocklist mirror) and made-up JSON, CSV and regex sources; not yet run against a real CrowdSec, nor its `waf4`/`waf6` sets loaded on a host.
- **The bot fallback:** a message the bot doesn't take (bot stopped, no trusted admin device) going out unencrypted after `bot_grace` is covered by tests on the Mac only.
- **The iptables backend** (`backend = "iptables"`): covered by tests of the rules it builds, not yet run on a host (the ipset backend, which shares its chains, has).
- **Left out of the Fedora run** (see above): IPv6 bans and blocks (the probe had no IPv6); the firewalld policy for forwarded traffic with containers (none ran); blocking by country with the nftables and firewalld backends (ipset only); the smaller memory of blocking by country (`e18df66`) and the merged-`sbin` fix (`692d3ac`), both after the run; SELinux in enforcing mode (the image had it disabled); a host where `/run/reboot-required` doesn't exist and a security update is pending (none was).
- **The ARM builds** (arm64, and 32-bit ARMv7 with hardware floating point): built for every commit, the tests run natively on GitHub's arm64 runners, the ARMv7 binary started under qemu; not yet run on an ARM server.
- **RHEL and its rebuilds** (AlmaLinux, Rocky): the same rpm, dnf and firewalld as Fedora, but older versions of each; only Fedora 44 was tried.
- **Bans after connection tracking** (nftables chain `bans`, iptables in the mangle table; new on 2026-10-24) and the removal of the old raw-priority chain at the first start: covered by tests of the rules they build. On Fedora (above) the nftables `bans` chain and the ipset backend's chains in the mangle table loaded and dropped the probe; that was a new install, so the removal of the old chains didn't run. On another node of the cluster (see "Verified on the servers"), the nftables `bans` chain drops IPv4 bans since the 0.3.0 upgrade; whether the old chain was removed there wasn't checked. The server's own traffic to a banned address gets its replies: from that node, `ping` reached two addresses banned there while their bans ran, so the replies pass the `bans` chain as part of a connection the server opened; a third didn't answer from anywhere (a Mac outside the cluster too), so that host ignores pings. A TCP connection out works too: `curl` from the node to a banned address's web server got its answer (`308 Permanent Redirect`, Caddy) with the ban 40 minutes from its end.
- **PAM, account changes and auditd** (`[sources] pam`, `audit`, new on 2026-10-26): tested against lines in PAM's, shadow-utils' and the audit log's formats, forged senders and typed names. On hosts so far only account changes: logguard-web's installer creating its user and group was reported (`new account logguard-web (UID ...), shell /usr/sbin/nologin (useradd)`); PAM failures and auditd alerts not yet. The journal's form of audit records (`USER_AUTH pid=...`, identifier `audit`) is read in all three forms auditd, journald and the kernel write, but which one a given journald writes hasn't been checked.
- **The web console** (`[console]` socket, logguard-web, the `logguard-web` app; new on 2026-10-26): covered by tests on the Mac (the read-only socket refusing every other command; logguard-web's agent, console and TLS login end to end against a fake logguard; the app's patterns against its lines) and a manual run there with real decision logs. Since 2026-10-27 the console runs on one node of the cluster (`CONSOLE_LISTEN=0.0.0.0:7948`, no agent: it reads that node's logguard through the console socket), under systemd's sandboxing, reached from a browser without a tunnel, with the self-signed certificate; on 2026-10-28 the agents of the other three nodes joined it, and the console showed all four nodes' alerts and bans. A node's console socket appears only if logguard starts after logguard-web's install created its group: two nodes needed `systemctl restart logguard` for that. The first install found that the installers' new system user raised high alerts for `/etc/passwd`, `/etc/shadow` and `/etc/group`; the agent's install on the VPN host, with the fix, logged them as announced. `logguard-web check` then failed on an `AGENT_ALLOW` list with blanks, sourced in a shell as the docs said: the commands now read `config.env` themselves, as systemd does.
- **The built-in sources for common services** (`[sources] apps`, new on 2026-10-25): the patterns are tested against lines in each service's documented format and against forged ones, and the Apache ones against two honeypots' real logs (2004/2005, Apache 2.0); on that node of the cluster (2026-10-27) the `logguard-web` patterns read the live journal of `logguard-web.service` (the Patterns tab counts its lines) but have matched nothing yet, as no login failed; not yet run on a host with any of the other services, and none of the formats of current versions has been checked against a real log there.
- **Added on 2026-10-24, covered by tests on the Mac only** (unit tests, the month replay, the layouts with a stand-in `nft`), not yet run on a host:
  - kernel tripwires (the nft rules with `fib` and dynamic sets: `install.sh`'s dry run checks them against the kernel; on Fedora's kernel 7.2 they loaded, but no hit was told apart from firewalld's own log lines);
  - `sudo` alerts (neither server has `sudo`; `su` ran, above) and new-SSH-key alerts;
  - the operator ban's TUI key (the `ban` command ran on Fedora), allowlisted host names;
  - patterns of your own on a live journal, the journal position alert and `journalctl --verify`.
- **The SSH audit** (`[ssh_audit]`, `ssh-audit`; new on 2026-10-27): covered by unit tests on the Mac (a cloud image's settings, a harden-vps.sh gateway and its broken pieces, Include and Match parsing, the alerts over time). `ssh-audit` and the daemon's first reading ran on one harden-vps.sh gateway (above) and found nothing; on the VPN host's cloud image (above) it found root's password login and cloud-init's override. On the VPN host the next reading logged the fixes (`fixed: login-grace, root-login, x11-forwarding`, with the changed settings as evidence). Not yet seen: an alert for a new problem or a weakened setting, the TUI's SSH line, a gateway with something wrong, Fedora's OpenSSH, and cPanel's and Plesk's layouts.
- **SSH password guessing:** SSH is key-only on both hosts, so `ssh_auth_fail` is covered only by synthetic tests (`ssh_invalid_user` and canary probes do occur for real).
- **Spoofing:** UFW-only evidence (blocked packets) can carry forged source addresses, TCP tripwire hits included. A forged hit can't ban an address that logged in within `trust_ttl` (nor through a peer), and bans never drop replies to the server's own connections. It can still ban other addresses for an hour, and a subnet that holds no protected address, so an attacker who forges packets can block outsiders from reaching this server. Bans of a forged source cost the attacker nothing. Honeypot ports ("Honeypot ports") rule them out for the connections they take, and lower a blocked SYN to half a ban.
