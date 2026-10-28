# logguard compared

**How logguard compares with the open-source and commercial tools you might use instead:
a briefing for teams thinking about adopting it.**

The state is as of 2026-10-28: logguard 0.3.0 and its web console, logguard-web 0.1.0 (commit
`01e37a6`), compared with the releases and documentation of the other tools as of 2026-10-25. Feature claims about logguard come from its
[README](logguard/README.md) and code. Claims about the other tools come from their documentation,
release pages and advisories (see [Sources](#20-method-and-sources)). Products change, so check a
tool's current documentation before you decide on one detail.

Legend for the tables: **✓** built in · **◐** partly, or by your own configuration or script ·
**–** not available.

## Contents

1. [logguard in one minute](#1-logguard-in-one-minute)
2. [Who it is for, and who it is not for](#2-who-it-is-for-and-who-it-is-not-for)
3. [The field](#3-the-field)
4. [Attack detection and banning](#4-attack-detection-and-banning)
5. [Firewall enforcement](#5-firewall-enforcement)
6. [Sharing and threat intelligence](#6-sharing-and-threat-intelligence)
7. [Host integrity and intrusion detection](#7-host-integrity-and-intrusion-detection)
8. [Exposure, patches and certificates](#8-exposure-patches-and-certificates)
9. [Operations health](#9-operations-health)
10. [Alerts and the people who get them](#10-alerts-and-the-people-who-get-them)
11. [Day-to-day operation](#11-day-to-day-operation)
12. [Footprint, platforms and supply chain](#12-footprint-platforms-and-supply-chain)
13. [Commercial offerings: what money buys](#13-commercial-offerings-what-money-buys)
14. [Scorecard](#14-scorecard)
15. [What logguard does not do (yet)](#15-what-logguard-does-not-do-yet)
16. [Evidence so far](#16-evidence-so-far)
17. [Which tool for which situation](#17-which-tool-for-which-situation)
18. [Good companions](#18-good-companions)
19. [Trying it](#19-trying-it)
20. [Method and sources](#20-method-and-sources)

---

## 1. logguard in one minute

logguard is one static Rust binary for a self-hosted Linux server. It does what usually takes
four or five separate tools:

- It **bans attackers** in the kernel firewall seconds after they show themselves.
- It **watches the host** for the ways intruders stay in.
- It **notices when its own view goes dark**: a log source that stops, a firewall that was
  flushed, a scan that was killed.
- It **tells the admins** over end-to-end-encrypted channels, and warns the users whose
  accounts are under attack.
- It **shows the whole cluster** on one read-only HTTPS page, and to Prometheus (logguard-web,
  optional).

Several servers share what they see over an encrypted peer-to-peer link. There is no central
server and no vendor in between: the web console only asks the nodes, with a key of its own
that can't make a ban.

```
journal ─► logguard ─► nftables / firewalld / ufw / iptables / ipset  ◄── encrypted cluster link ──►  logguard on other nodes
             │
             ├─► logguard-xmpp-bot ─► XMPP, OMEMO-encrypted
             ├─► logguard-tg-bot     ─► Telegram, pseudonymized, files OpenPGP-encrypted
             ├─► logguard-mail-bot   ─► e-mail, PGP/MIME-encrypted
             ├─► logguard-signal-bot ─► Signal (signal-cli), else OpenPGP files
             ├─► logguard-matrix-bot ─► Matrix, Olm/Megolm-encrypted, else OpenPGP files
             └─► logguard-web (read-only socket) ─► the cluster on one HTTPS page, /metrics for Prometheus
```

**What one install covers, and what you would otherwise run:**

| logguard part | usually done with |
|---|---|
| scoring and banning, subnet bans, tripwires, honeypots, canary accounts; built-in sources for common web, database and mail servers | fail2ban, sshguard, CrowdSec |
| country and network (ASN) blocking | CSF `CC_DENY`, ipset scripts with a GeoIP list |
| ban sharing between your servers, blocklist feeds | CrowdSec, CSF cluster, ipset scripts |
| a WAF's decisions (CrowdSec, or any app with a list) enforced at the firewall | CrowdSec's firewall bouncer |
| cron and persistence watch, package and set-uid check (dpkg or rpm), process watch | AIDE, debsums, `rpm -Va`, rkhunter, Wazuh FIM |
| listeners compared with firewall rules, dead rules, Docker bypass | Lynis, external port scans, by hand |
| patch status (apt or dnf), certificate checks | apticron, dnf-automatic, needrestart, an uptime or certificate monitor |
| SSH hardening audit (sshd's effective settings, key file permissions, a su/sftp gateway's layout) | Lynis, ssh-audit, Wazuh SCA |
| quiet log sources, OOM kills, disk, memory, failed units | Monit, Netdata, Prometheus |
| daily digest, weekly abuse report | Logwatch, AbuseIPDB scripts |
| a read-only web console for the cluster, a REST API, Prometheus metrics | Grafana with exporters, the CrowdSec Console, Wazuh's dashboard |

**Key numbers** (measured, from the README):

- **~8 MB** static binary with no runtime dependencies (the optional web console is another ~3 MB).
- **~10 MB RAM** for a real month of traffic (~50 MB with the offline geo database). The hard
  limit is 128 MB, and it held in a synthetic flood of 450,000 sources.
- A real month of logs (~210,000 records) replays through the full engine in **about one
  second**: 185 bans of 93 targets. No address that ever logged in was banned.
- Tripwire ports banned **about 7,500 scanners on first contact** in that month.

---

## 2. Who it is for, and who it is not for

**A good fit:**

- One to about ten Linux servers you run yourself: Debian or Ubuntu, or Fedora and RHEL with
  dnf and firewalld; x86_64 (ARM builds are new, see below); systemd.
- SSH, XMPP (ejabberd), Nextcloud and WireGuard hosts, and the common web, database and mail
  servers through built-in patterns (Apache, nginx, HAProxy, Prosody, MySQL/MariaDB, PostgreSQL,
  MongoDB, Redis/Valkey, Postfix, Dovecot, ownCloud). Other services count through regex
  patterns of your own.
- Admins who want alerts on their phone, encrypted, with nothing about their users or attackers
  sent to a vendor.
- Small machines: it is built to stay within a 128 MB memory limit next to the services it
  protects.
- Linux desktops and laptops, with a profile of their own (new: not yet run on one).

**Not a good fit today:**

- **Fleets** of dozens of hosts or more that need fleet management, roles, several users and
  compliance reports. logguard's web console shows a handful of nodes to a few equal admins, read only.
  Look at Wazuh, the CrowdSec Console or a commercial EDR.
- **Web-application-heavy hosts** that need a WAF, captchas or CDN integration. logguard can
  enforce a WAF's decisions at the firewall (`[waf]`, with CrowdSec's formats built in), but it
  inspects no HTTP request itself and answers none: run CrowdSec AppSec, ModSecurity or Coraza
  for the detection, and a CDN or an HTTP bouncer for captchas.
- **Other platforms:** Windows, macOS, BSD, Linux without systemd. ARM bundles (arm64 and
  32-bit ARMv7) are built and tested in CI but haven't run on an ARM server yet. Fedora has been
  tried on one test server; RHEL and its rebuilds not yet.
- **Organisations that need a vendor:** a support SLA, certified compliance evidence, or a
  24/7 security operations team.

---

## 3. The field

**Ban managers and intrusion-prevention tools**, compared in sections 4 to 12:

| tool | kind | license | language | model | state in Oct 2026 |
|---|---|---|---|---|---|
| **logguard** | ban manager and host watch | MIT | Rust | decaying scores per address across all services, own nftables table (or firewalld, ipset, ufw, iptables), peer-to-peer cluster | 0.3.0, new in Oct 2026 |
| **fail2ban** | ban manager | GPL-2.0 | Python | "jails": a regex filter and a firewall action per service | 1.1.0 is what distributions ship |
| **sshguard** | ban manager | BSD-style | C | built-in attack parser, a score per address | 2.5.1 (2025) |
| **reaction** | ban manager | AGPL-3.0 | – | streams, regex and actions; a smaller, newer fail2ban alternative | 2.x |
| **CrowdSec** | collaborative IPS | MIT (engine); console is SaaS | Go | parsers and scenarios, a local API, separate "bouncers", a crowd-sourced blocklist | 1.7 released; docs on the 1.8 line |
| **CSF / LFD** | firewall front end and login-failure daemon | GPL-3.0 since v15 | Perl | iptables rules, bans, port-scan, process and file checks; hosting-panel UIs | ConfigServer closed in Aug 2025; community forks (and, reportedly, cPanel's) |
| **Wazuh** | XDR / SIEM platform, a fork of OSSEC | GPL-2.0 | C, Python; OpenSearch-based indexer | agents, a manager, an indexer and a dashboard; FIM, SCA, CVE detection, active response | 4.14.x; 5.0 in beta |
| **OSSEC** | host intrusion detection | GPL-2.0 | C | agent and manager, log rules, FIM, rootcheck, active response | 4.x, maintained by Atomicorp |

**Host, posture and monitoring tools**, compared in sections 7 to 9:

- File integrity: AIDE, Samhain, debsums.
- Rootkit scanners: rkhunter, chkrootkit.
- Kernel-event monitoring: auditd, Falco, Tetragon.
- Host state as SQL: osquery.
- Hardening audit: Lynis.
- Patching: unattended-upgrades, needrestart.
- Health and uptime: Monit, Netdata, Prometheus with Alertmanager, Uptime Kuma, blackbox_exporter.
- Log digests: Logwatch, logcheck.

**Commercial offerings** are compared in [section 13](#13-commercial-offerings-what-money-buys).

---

## 4. Attack detection and banning

> **Bottom line:** for the services it knows, logguard detects more, and is more careful about
> false positives, than the generic tools. For any other service, the others ship far larger
> rule libraries.

| feature | logguard | fail2ban | sshguard | CrowdSec | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| built-in parsers | ◐ sshd, ejabberd, kernel log (UFW, firewalld, iptables), Nextcloud, su/sudo, PAM, audit log, and 13 common services (web, proxy, database, mail) | ✓ dozens of filters | ◐ SSH and common mail/FTP daemons | ✓ hub of parsers and scenarios | ✓ thousands of rules | ✓ hosting stack |
| patterns of your own | ✓ | ✓ | – compiled in | ✓ | ✓ | ✓ |
| one score per address across all services | ✓ | ◐ per jail, plus `recidive` | ✓ | ◐ per scenario | ◐ correlation rules | ◐ per trigger |
| low-and-slow probing over hours | ✓ 12 h score | ◐ long `findtime` | ◐ | ◐ | ◐ | ◐ |
| escalating ban times | ✓ 1 h to 30 d | ✓ `bantime.increment` | ✓ | ◐ profile expressions | ✓ `repeated_offenders` | ✓ `LF_PERMBLOCK` |
| subnet bans | ✓ grow from /24 towards /16 | – | ◐ fixed prefix | ◐ range-scoped scenarios | – | ◐ `LF_NETBLOCK`, fixed |
| port scans and tripwire ports | ✓ | ◐ own filter | – | ✓ | ◐ | ✓ |
| honeypot listeners (handshake proves the source) | ✓ | – | – | – | – | – |
| canary account names | ✓ | ◐ own filter | – | ◐ own scenario | ◐ own rule | – |
| per-account alerts (distributed guessing, login after failures, new network, new SSH key) | ✓ | – | – | ◐ | ◐ success after failures | ◐ `LF_DISTATTACK` |
| a recent login protects an address | ✓ per service | ◐ `ignorecommand` script | – | – | – | – |
| dry-run mode | ✓ shadow mode | ◐ dummy action | – | ✓ simulation | ✓ alert-only by default | ✓ `TESTING` |
| replay old logs through the same engine | ✓ | ◐ `fail2ban-regex` tests filters | – | ✓ replay mode | ◐ `wazuh-logtest` | – |
| XMPP server attacks | ✓ deep | ◐ own filter | – | ◐ own parser | ◐ own decoder | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Parsers** | Deep parsers for what it knows. An ejabberd TLS failure is tied to its address through the Erlang PID. OpenSSH 10's `sshd-session` lines are handled. A line counts only from its real sender, by journald's own fields, so a local user can't log a fake sshd line to get someone banned. `[sources] apps` adds built-in patterns for Apache, nginx, HAProxy, Prosody, MySQL/MariaDB, PostgreSQL, MongoDB, Redis/Valkey, Nextcloud, ownCloud, Postfix, Dovecot and its own web console, each taking the address only from where the service writes it, so a client can't get another address banned through a user name or path. | The built-in services are tested against documented and forged log lines, and Apache's against two honeypots' logs, but not yet run on a host with them. FTP and everything else need `[[patterns]]`. fail2ban, CrowdSec and Wazuh ship ready filters for hundreds of services. |
| **Own patterns** | Linear-time regex, so no catastrophic backtracking on hostile lines. The sender is pinned by unit, or by identifier and uid. `test-pattern` and a TUI tab show the lines read, matched, and matched without an address. | A pattern is a regex, a kind and a weight. There are no multi-line or stateful scenarios like CrowdSec's leaky buckets or Wazuh's composite rules. |
| **Scoring** | Two decaying scores (10 min and 12 h half-life) add up every signal from every service. A scanner that touches SSH, XMPP and closed ports a little each still reaches a ban. Weights are calibrated on a real month of logs. | One model for everything: tuning means weights and thresholds, not per-service rules. At first it is less obvious than fail2ban's "N failures in T minutes". |
| **Escalation** | 1 h → 6 h → 1 d → 7 d → 30 d per repeat offence. Offences are shared, so a repeat attacker escalates on every node of the cluster. | fail2ban, sshguard and CSF escalate too, and CSF offers permanent bans. Only the cluster-wide counter is new here. |
| **Subnet bans** | Starts at /24 (IPv6 /64) and grows towards /16 (/48) only as nearby bans appear, at most 2 bits a step. It never covers a protected address. With the geo database, it never grows into another provider's network. | The provider boundary needs the `[geo]` ASN database. A stricter policy, such as blocking a whole network or country now, needs feeds. CSF blocks countries out of the box. |
| **Tripwires and honeypots** | One SYN to an unused telnet, RDP or database port bans. Kernel tripwires log these hits from logguard's own nftables rules, so UFW's log limit (about 3 lines a minute) doesn't hide scans. Honeypot ports complete the TCP handshake, so their evidence can't be forged. | A blocked SYN can carry a forged source address. logguard limits the damage: such evidence never bans an address that logged in recently, replies always pass, and with honeypots set it is worth half a ban. A spoofer can still get outsiders banned for an hour. |
| **Canary accounts** | No accounts to create. On a key-only host, `ssh = ["*"]` makes every unknown user name a ban. A successful login to a canary is a critical alert. | fail2ban, CrowdSec and Wazuh can do this with a filter of your own. logguard just has it built in. |
| **Account protection** | Distributed guessing against one account from several addresses; a login right after failures (possible compromise); a login from a new network or provider for that account; a login with a never-seen SSH key. | Covers XMPP, SSH, Nextcloud, the built-in services and your patterns only. Wazuh covers far more authentication sources (PAM, Windows, cloud services). |
| **False positives** | Shadow mode lifts its own "bans" when the address later logs in, and says so. An address that logged in recently isn't banned for that service's typos and reconnects. Private, CGNAT, loopback and link-local addresses are never banned. | Login trust is a heuristic. An attacker behind the same carrier NAT as a user gets the same excuse for that service's noise; real failures still raise an alert. |
| **Testing** | `replay` runs journal exports through the whole pipeline without touching the firewall, and opens the result in the TUI. | CrowdSec's replay mode and `cscli explain` are as capable, and better documented for writing new scenarios. |

---

## 5. Firewall enforcement

> **Bottom line:** logguard's enforcement takes the most care not to break the server itself
> (Docker, flushed rulesets, replies, oversized feeds). It covers the Linux firewalls (nftables,
> firewalld, ipset, ufw, iptables) but no BSD or Windows ones, and CrowdSec reaches the HTTP
> layer and CDNs.

| feature | logguard | fail2ban | sshguard | CrowdSec bouncer | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| firewall backends | ◐ nftables, firewalld, ipset, ufw, iptables (Linux only) | ✓ iptables, nftables, firewalld, ufw, pf, ipfw, … | ✓ iptables, ipset, nftables, firewalld, pf, ipfw | ✓ nftables, iptables/ipset, pf, Windows | ◐ iptables, firewalld, pf, Windows | ◐ iptables |
| bans expire in the kernel, even while the daemon is down | ✓ nft and ipset timeouts | ◐ some ipset actions | – | ✓ | – | – |
| Docker-published ports covered without extra setup | ✓ | ◐ `DOCKER-USER` chain by config | ◐ | ◐ `DOCKER-USER` or forward hook by config | ◐ | ◐ `DOCKER` option |
| per-source connection rate limits in the kernel | ✓ | – | – | – | – | ✓ `CONNLIMIT`, `PORTFLOOD` |
| public blocklists loaded into the firewall | ✓ with sanity limits | – | – | ✓ console blocklists | – | ✓ `csf.blocklists` |
| country blocking | ✓ offline DB-IP Lite, plus networks by ASN | – | – | ◐ paid lists or own profiles | – | ✓ `CC_DENY` |
| HTTP-level responses (403, captcha, CDN) | – | ◐ Cloudflare action | – | ✓ nginx, Traefik, HAProxy, Cloudflare, … | – | – |
| a WAF's or IPS's decisions blocked at the firewall | ✓ `[waf]`: CrowdSec built in; JSON, CSV, regex, plain lists for others | ◐ an action script of your own | – | ✓ what a bouncer does | ◐ active response scripts | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Where bans sit** | Its own nftables table at prerouting, right after connection tracking. It runs before ufw's chains and before Docker's DNAT, so your own ALLOW rules can't shadow a ban, and Docker ports are covered without touching `DOCKER-USER`. It never edits your rules. On Fedora and RHEL it can keep everything in firewalld instead: its own ipsets, a drop zone and a forwarding policy, visible with `firewall-cmd`. The ipset backend is iptables with one set lookup however many bans. | Linux only: no pf, ipfw or Windows. The ufw fallback loses Docker coverage, rate limits and feeds; the firewalld backend has no rate limits or feeds, and its entries end only while logguard runs. The firewalld, ipset and nftables backends ran on a Fedora 44 test server; the plain iptables backend has not yet run on a real host. |
| **Expiry** | Ban timeouts live in the kernel: if logguard stops, bans still end on time. After a reboot it re-applies what is still active. | CrowdSec's firewall bouncer works the same way. |
| **Self-healing** | Debian's and Ubuntu's `nftables.conf` starts with `flush ruleset`, so a restart of nftables deletes every ban. logguard notices within 30 s, rebuilds every set and chain, re-adds the bans with their remaining time, and raises a high alert. The same after `firewall-cmd --reload` or a firewalld restart, and after its iptables chains are flushed (both seen on the Fedora server). | fail2ban restores its chains too, but only at its next ban action. |
| **Replies to the server's own connections** | Bans drop after connection tracking, so replies always pass: DNS, mail relay, update mirrors, federated XMPP servers. A forged packet that gets such an address banned can't cut the server off. | New since 2026-10-24. The chains dropped a test client on the Fedora server, and on a production server both pings and a TCP connection to addresses banned there got their replies. |
| **Rate limits** | Per-source `[[ratelimit]]` entries in the kernel, from the first packet, Docker ports included. `status` shows their drop counters. | nftables backend only (`status` says so under the others). CSF has richer flood controls (SYN floods, per-port and per-connection limits). |
| **Feeds** | Downloads with `curl` (the binary has no TLS library) and keeps the last good copy. It drops bogons, prefixes wider than /12, and anything overlapping your allowlist or peers. A refresh that suddenly covers far more address space is refused. | A few public lists (Spamhaus DROP and ASN-DROP, FireHOL); no curated commercial lists. nftables and ipset backends only. CrowdSec's blocklists are larger and updated more often. |
| **Countries and networks** | `[geoblock]` drops whole countries (or all but some) and networks by AS number, from the DB-IP Lite databases it already holds for labels: no download, no second database, about 1 MB while the list is computed. Protected addresses are cut out exactly. China is about 15,000 networks, everything but one country about 28,000. On the Fedora server two blocked countries timed out and a third connected. | DB-IP Lite misplaces some addresses and is refreshed monthly: coarse, not a curated list. ufw and plain iptables can't hold it; firewalld takes at most 50,000 networks. CSF's `CC_DENY` and `CC_ALLOW` have been doing this for years, with per-port variants. |
| **HTTP layer** | `[waf]` blocks what a WAF decides at the firewall, for every port and, as bans, on every cluster node: CrowdSec's local API, `cscli` output and blocklist mirror are read as they are, any other app through JSON, CSV, regex or plain-list formats. Its decisions get the protections of an operator ban (allowlists, peers, recent logins), are lifted when the WAF drops them, and large blocklists go into sets of their own. | No WAF of its own, and no HTTP-level response: a banned visitor just times out. No captcha, no ban at the CDN or edge. CrowdSec's remediation components and WAF cover that layer. `[waf]` is new on 2026-10-27: tested against CrowdSec's documented formats, not yet run against a real CrowdSec. |

---

## 6. Sharing and threat intelligence

> **Bottom line:** logguard shares well among your own servers and keeps every observation
> private. It has no crowd-sourced intelligence, which is CrowdSec's main strength.

| feature | logguard | fail2ban | sshguard | CrowdSec | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| bans shared between your own servers | ✓ peer to peer, encrypted | – scripts | – | ✓ through one central local API | ✓ through the manager | ✓ `LF_CLUSTER` |
| suspicion below the ban threshold adds up across servers | ✓ | – | – | – | ✓ the manager sees all events | – |
| works without a central server | ✓ mesh, chain or star | – | – | – | – | ✓ |
| crowd-sourced global blocklist | – | ◐ AbuseIPDB actions | – | ✓ | – | ◐ third-party lists |
| nothing about attackers leaves your servers by default | ✓ | ✓ | ✓ | – signals go to CrowdSec unless turned off | ✓ self-hosted | ✓ |
| reports to the attackers' abuse desks | ✓ weekly, with evidence and contacts | ◐ `complain` and AbuseIPDB actions | – | – | – | – |
| offline country and network labels | ✓ | – | – | ✓ | ✓ | ✓ |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Cluster** | XChaCha20-Poly1305 under a shared key, and only peers may connect. Facts are de-duplicated and forwarded up to 3 hops. Suspicion is shared too, so an address that probes every server a little still adds up to a ban. A limited peer (`peer_accept`) can send messages but never ban anything. Optional node identities: each node signs its own facts and files with an Ed25519 key of its own, pinned on the others, so a broken-into node (or a stolen cluster key) speaks only for itself, and a node is dropped by deleting its key, without a new cluster key. Key rotation is staged in three rounds, without a gap. | Without node identities, every unlimited key holder is fully trusted: a broken-into node can ban on the others under any name, for at most `max_remote_ban`. With them, it can still ban for itself, and still read what the others share until the cluster key is rotated. Keys are pinned by hand in each node's config, with no PKI or enrollment. Node identities are new on 2026-10-27, and run on four servers, each pinning the other three and requiring signatures. It is sized for a handful of nodes, with no fleet management. |
| **Threat intelligence** | Your data stays yours: no vendor sees your attackers or your users. The static feeds (Spamhaus, FireHOL) need no account. | No network effect. CrowdSec blocks addresses that attacked thousands of other servers before they reach yours; logguard knows only what your own nodes saw. |
| **Abuse reports** | A weekly report grouped by abuse mailbox (looked up with RDAP), each attacker with UTC log lines and account names withheld. Reports from several nodes are merged, and the result reaches the admin encrypted. The web console shows the last day's or week's at any time, merged across the nodes, one entry per network owner, each copied or saved as the e-mail to its abuse desk. | You send the mails yourself: logguard never mails third parties, by design. There is no AbuseIPDB integration. |
| **Geo** | DB-IP Lite: about 1.2 million ranges in ~40 MB, looked up in memory, with no request per lookup. Used in alerts, to limit subnet growth, to learn each account's providers, and to block countries and networks. | Countries and networks only, no cities; DB-IP Lite accuracy: on the authors' servers, a VPN exit in Vienna (M247) shows as Czechia. |

---

## 7. Host integrity and intrusion detection

> **Bottom line:** logguard covers the practical "how would someone stay in?" checklist on
> Debian and Ubuntu with no extra tools. It is not a kernel-level runtime sensor and not a
> compliance-grade FIM.

| feature | logguard | Wazuh | AIDE | rkhunter, debsums | Falco, Tetragon | osquery |
|---|---|---|---|---|---|---|
| persistence points watched out of the box (cron, timers, units, SSH keys, PAM, sudoers, `ld.so.preload`, apt and dnf hooks, ...) | ✓ every minute | ◐ default directories, 12 h scans; real time by config | ◐ distribution config, typically daily | ◐ some startup files | ✓ rules, real time | ◐ tables, scheduled queries |
| changed lines shown in the alert | ✓ | ✓ `report_changes` | – | – | – | – |
| package files told apart from foreign ones (dpkg or rpm origin) | ✓ | – | – | ✓ debsums | – | ◐ `deb_packages`, `rpm_packages` |
| package files checked against dpkg's or rpm's hashes | ✓ weekly | – | ◐ own baseline | ✓ debsums | – | – |
| set-uid program inventory | ✓ | ◐ rootcheck | ◐ baseline | ◐ | ◐ rules | ✓ `suid_bin` |
| outbound connections and reverse shells | ◐ checked every 60 s | ◐ command monitoring | – | – | ✓ syscall events | ◐ snapshots |
| programs running from `/tmp`, from memory or from deleted files | ✓ checked every 60 s | ◐ rootcheck | – | ◐ | ✓ | ◐ by query |
| failed su and sudo | ✓ | ✓ | – | – | – | – |
| PAM failures (console, polkit, Cockpit), account changes, auditd stopped | ✓ | ✓ | – | – | ◐ rules | ◐ by query |
| a login with a never-seen SSH key | ✓ | – | – | – | – | – |
| malware signatures | ◐ ClamAV results; changed files scanned with ClamAV or YARA | ◐ ClamAV, YARA, VirusTotal integrations | – | ◐ rootkit signatures | – | – |
| real-time kernel events | – | ◐ who-data through auditd | – | – | ✓ eBPF | ◐ evented tables |
| events copied off the host as they happen | ◐ alerts only, through bots and peers | ✓ | ◐ Samhain's server | – | ◐ falcosidekick | ◐ fleet server |
| signs of journal tampering (lost position, sealed-journal check) | ✓ | – | – | – | – | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Persistence watch** | It knows where intruders hide, including the scripts crontab lines run (also behind `sudo -u`, `flock`, `timeout`). It keeps fingerprints only, never contents, so no password hashes in alerts or state. Alert severity knows whether dpkg or rpm installed the file unchanged. A file reached under two names (Fedora's merged `/usr/local/sbin`) is watched once. Installers announce their changes (`expect-change`) so upgrades don't alert. One local account can raise at most 5 alerts an hour, so it can't flood the channel. | It checks every minute: a change undone within a minute is missed. Falco and Tetragon see the write itself, and which process made it. The list of places is fixed, plus your own `[cron] files`; AIDE and Wazuh FIM cover any directory tree. |
| **Package and set-uid check** | A debsums-like check (or `rpm -Va`-like, with each package's own digest algorithm) plus a set-uid inventory. It reads at most 20 MB/s and drops what it read from the page cache, so it stays within the 128 MB unit. Diverted files, rpm's `%config` files and upgrades in progress are handled. On the Fedora server it matched 7,472 files and caught a tampered binary; with dpkg on a production server no file differed, with 17 set-uid programs listed. | Once a week. A root attacker who also rewrites the package database defeats it, as with debsums. |
| **Process watch** | A baseline of outbound connections per program and port. A shell or network tool talking out, or a miner or reverse-shell port, is always high. Programs from `/tmp`, from memory (`memfd`) or from deleted files are reported. | A snapshot every 60 s misses short-lived connections, and connections inside containers aren't seen. eBPF tools are much stronger here. |
| **Privilege and keys** | Failed su and sudo, each with the account's last SSH login and its place (su seen on the XMPP server; neither server has sudo). New-SSH-key alerts start after a learning period. PAM failures of the programs no other parser reads (the console, desktops, polkit, Cockpit, FTP), account changes (`useradd`, `usermod`, `passwd`, groups), auditd stopping, and authentication failures in the audit log. | Wazuh's ruleset covers far more event types, and Windows and cloud logins. The PAM and audit alerts are new: account changes (a new account and group) have been reported on hosts, PAM failures and auditd alerts not yet. |
| **Malware** | Turns ClamAV's runs into alerts: infected files, scans killed for memory, stale signatures, missing runs. It ships a scan timer that runs at low priority and dies first when memory runs out. Files its watches see change can be scanned at once with ClamAV, YARA or both, outside logguard's memory limit, and are checked again just before the scanner reads them. | No scanning engine of its own: ClamAV or YARA must be installed. The changed-file scans are new: ClamAV's have run on a host (a changed `sshd_config`, clean), YARA's only with a stand-in scanner. |
| **Tamper resistance** | Alerts leave the host at once (encrypted bots, peers). A lost journal position and failed `journalctl --verify` checks are reported. Peers report a node that stops answering for 5 minutes. | The raw evidence stays on the host. A root attacker can stop logguard: the systemd watchdog restarts a hung daemon, not a deliberately stopped one. EDRs add tamper protection, and Wazuh ships every event off the host. |

---

## 8. Exposure, patches and certificates

> **Bottom line:** logguard explains, port by port, what the internet can reach and why, and
> catches certificate mistakes other monitors miss. It audits sshd, and alerts when its settings
> weaken. Use Wazuh or Lynis for CVE matching and whole-host hardening benchmarks, and
> unattended-upgrades to apply updates.

| feature | logguard | Wazuh | Lynis | unattended-upgrades, needrestart | Uptime Kuma, blackbox_exporter | external scan (nmap, Shodan) |
|---|---|---|---|---|---|---|
| each listener compared with the firewall rule that lets it in | ✓ ufw, firewalld zones, iptables, docker-proxy | ◐ port inventory | ◐ once per run | – | – | ◐ outside view |
| Docker ports that bypass ufw | ✓ | – | – | – | – | ◐ seen as open |
| alerts: new public listener, listener gone, dead allow rule, no firewall | ✓ | ◐ listening-port change rule | – | – | ◐ port down | – |
| pending security updates, reboot needed, processes on replaced libraries | ✓ in the digest | ✓ | ◐ | ✓ installs and restarts | – | – |
| CVE matching | – | ✓ | ◐ | – | – | ◐ service versions |
| SSH hardening audit, with alerts when settings weaken | ✓ sshd only | ✓ SCA | ◐ once per run | – | – | ◐ algorithms only |
| hardening benchmark (CIS style), sysctls | – | ✓ SCA | ✓ | – | – | – |
| live certificate expiry, STARTTLS included | ✓ | – | – | – | ✓ | ◐ |
| "renewed but not in use", DANE TLSA value at each renewal | ✓ | – | – | – | – | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Exposure** | Reads the listeners from `/proc` and follows the firewall's own logic: rules in order, jumps, policies, rate limits. The TUI names the rule that lets each port in. It flags Docker-published ports, which ufw doesn't filter, and allow rules for ports nothing listens on: the kind of dead rules that were found by hand on the authors' hosts before. Under firewalld it reads the zones (services, ports, rich rules, source-bound zones). | A view from the host only: a provider's own firewall in front of it is not seen. nftables rulesets of your own are noticed but not read. An external scan remains the ground truth. |
| **Patches** | A simulated `apt-get`, or `dnf check-update` from the cached metadata (no lock taken either way), in a unit of its own; a newer installed kernel than the running one; programs still running replaced libraries. All of it is in the daily digest. | Reports only: it doesn't apply updates (use unattended-upgrades or dnf-automatic). No CVE database. apt and dnf only. |
| **Certificates** | Live endpoints every 6 h, XMPP STARTTLS included, plus the certificates on disk. It warns when a renewed certificate isn't served yet, explains ejabberd's ACME failures, and gives the new DANE `3 1 1` value at each renewal. This matters more since Let's Encrypt stopped sending expiry e-mails in June 2025. | Checked from the host itself, so DNS or routing problems elsewhere are not seen. |
| **Hardening** | sshd's settings as `sshd -T` applies them (Match blocks included), checked against the host's layout: a plain VPS, a hosting panel, or a key-only gateway user forced into a su/sftp wrapper. It names the file each setting comes from (cloud-init's override) and alerts when a setting weakens. | sshd only: no sysctls, no other services, no CIS benchmark or score. Run Lynis or Wazuh SCA for the rest of the host. |

---

## 9. Operations health

> **Bottom line:** logguard covers the alerts a small server needs, and knows when its own
> view has gone dark. It is not a metrics system, but its web console hands what it sees to
> Prometheus.

| feature | logguard | Monit | Netdata | Prometheus, Alertmanager | Logwatch, logcheck |
|---|---|---|---|---|---|
| a log source goes quiet, or stops naming addresses | ✓ | ◐ file timestamps | – | ◐ `absent()` on your own metrics | – |
| OOM kills, with process and size | ✓ | – | ✓ | ◐ a counter only | ◐ in the daily mail |
| disk space, memory pressure (PSI) | ✓ | ✓ | ✓ | ✓ | – |
| failed systemd units that are not restarted | ✓ | ✓ | ✓ | ✓ | – |
| restarts services itself | – | ✓ | – | – | – |
| daily digest | ✓ security and health | – | – | – | ✓ |
| graphs and history | ◐ TUI trends, web console charts (3 hours to 7 days), Prometheus export | ◐ M/Monit | ✓ | ✓ with Grafana | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Silence** | Tells "no attacks" from "not seeing logs", with thresholds measured per source on a real month. It also notices lines that arrive but name no address (ejabberd's `hide_sensitive_log_data`, a changed log format). | For its own sources only. |
| **Resources** | OOM kills (they revealed weeks of a nightly ClamAV scan being killed), disk under 10 % and 5 %, memory availability and pressure stalls, failed units after a restart grace period. | Basic: no per-process graphs, and history only through Prometheus (logguard-web's `/metrics`). Netdata and Prometheus are far richer. |
| **Digest** | One message a day per server, marked ⚠ when something needs attention: certificates, peers, feeds, dead rules, patches, top offenders. | A fixed format, with no report builder. |

---

## 10. Alerts and the people who get them

> **Bottom line:** no other tool here encrypts alerts end to end, pseudonymizes them for an
> untrusted channel, or warns the user whose account is attacked. In exchange, logguard offers
> five channels where the others offer dozens.

| feature | logguard | fail2ban | CrowdSec | Wazuh | commercial EDR, SIEM |
|---|---|---|---|---|---|
| admin channels | ◐ XMPP, Telegram, e-mail, Signal, Matrix | ◐ e-mail, scripts | ✓ Slack, e-mail, webhooks, Splunk, Elastic, Sentinel, … | ✓ e-mail, Slack, PagerDuty, custom | ✓ |
| end-to-end encryption | ✓ OMEMO, Signal, Olm/Megolm, OpenPGP | – | – | – | – |
| pseudonymized copies for an untrusted channel | ✓ Telegram | – | – | – | – |
| warns the attacked user, in their language | ✓ XMPP accounts, 6 languages | – | – | – | – |
| budgets per topic, so a flood can't hide a critical alert | ✓ | – | ◐ grouping | ◐ e-mails per hour | ✓ |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Channels** | XMPP through the admin bot, OMEMO-encrypted and kept out of the server's archive, or from any host through any XMPP server with the bot's client mode (OMEMO, else OpenPGP files). Telegram, with account names pseudonymized and servers named only by node id. E-mail, OpenPGP-encrypted as a whole, subject included. Signal (through signal-cli) while the admin's safety number is the pinned one, and Matrix, Olm/Megolm-encrypted to the devices the admin verified; both send OpenPGP files instead when they can't reach that identity. Any mix of the five. | No Slack, Teams, ntfy, webhooks or PagerDuty. A new channel means a new bot. The Signal bot needs signal-cli (Java on ARM) installed beside it. The Signal and Matrix bots and the XMPP bot's client mode are new and untried against the real services. |
| **Privacy** | Built for operators who take GDPR seriously: nothing about users goes to a vendor, Telegram never sees account names, and reports travel as encrypted files. | Encryption takes setup (OMEMO device trust, OpenPGP keys). If the XMPP bot doesn't take a message within 2 minutes, it goes out over plain XMPP, saying why. |
| **Users** | Account holders learn when their account is attacked: password guessing, a possible compromise, and (opt-in) a login from a new network. No other tool here does this. | XMPP accounts only: Nextcloud and SSH users aren't messaged. |
| **Noise control** | One message per incident and account every 6 h, hourly caps per topic for admins, hourly budgets per local user for host changes. Alerts relayed from peers are tagged with the node's name. A bot that stops sending is itself reported over the other channels. | Fixed policies: routing is less flexible than Alertmanager's or CrowdSec's profiles. |

---

## 11. Day-to-day operation

> **Bottom line:** a capable terminal UI on each node, a read-only web console for the whole
> cluster with a REST API and Prometheus metrics, and careful upgrade tooling. Nothing changes
> from the web: bans and settings stay on the servers, behind SSH.

| feature | logguard | fail2ban | sshguard | CrowdSec | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| live dashboard | ✓ terminal UI, web console | – | – | ◐ `cscli`; web console (SaaS) | ✓ web | ✓ panel UI |
| web UI and fleet view | ◐ read only, a few equal admins, a handful of nodes | – | – | ✓ | ✓ | ◐ per server |
| ban, unban, temporary allow | ✓ CLI and TUI, shared with peers | ✓ | – | ✓ | ◐ API | ✓ |
| pattern tester | ✓ `test-pattern` | ✓ `fail2ban-regex` | – | ✓ `cscli explain` | ✓ `wazuh-logtest` | – |
| REST API | ◐ read only | – | – | ✓ local API | ✓ | – |
| metrics for Prometheus | ✓ through the web console | ◐ community exporters | – | ✓ | ◐ API | – |
| community, Q&A, third-party guides | ◐ one detailed README | ✓ | ◐ | ✓ | ✓ | ◐ forks |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **TUI** | Works over SSH in an 80-column terminal. Up to 10 tabs: offenders with evidence, bans, decisions, accounts, exposure, countries with port histograms, a world map, alerts and patterns. Ban, unban and allow with a confirmation. It also reads saved decision logs of several servers offline. | One node at a time (the web console shows them all); no roles, no multi-tenant view. |
| **Tooling** | `status`, `replay`, `print-nft`, `notify-test` for each channel, a digest preview. `config-diff` runs after every upgrade and lists new options, changed defaults and unknown keys. The installer dry-runs the nftables ruleset against the kernel first. | No OpenTelemetry export, and no API that changes anything: the control socket is root-only, and the web console reads through a separate read-only socket. |
| **Web console** | logguard-web shows every node's bans, alerts, decisions, offenders, countries and networks, peers, certificates, disks and updates on one HTTPS page, with what needs attention first, activity charts and a world map (bans at capitals, countries `[geoblock]` blocks hatched). It only reads: it holds a web key of its own, never the cluster key, and reaches logguard through a read-only socket. TLS 1.3, a password and a one-time code, sessions in memory; failed logins are locked out and banned by logguard itself. About 110 Prometheus metric families for Grafana and alert rules. Asked only while someone looks. | One admin, no roles or several users, no history of its own. A self-signed certificate unless you give it one. New on 2026-10-26: since 2026-10-28 one console shows the authors' four servers, three of them through their agents. The CrowdSec Console and Wazuh's dashboard manage fleets and keep history. |
| **Docs** | One README that explains every default, often with the measurement behind it. | One long document: no website, no forum or chat. Some answers are only in the code. |

---

## 12. Footprint, platforms and supply chain

> **Bottom line:** the smallest and most self-contained option here after sshguard, written
> in a memory-safe language. It runs on fewer platforms, is packaged in fewer ways, and has
> the shortest track record.

| feature | logguard | fail2ban | sshguard | CrowdSec | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| runtime | static binary, ~8 MB (web console ~3 MB more) | Python 3 | C | Go: engine and bouncer | C agent; manager; OpenSearch-based indexer; dashboard | Perl |
| memory | ~10 MB for a real month, ~50 MB with geo; capped at 128 MB | moderate | a few MB | moderate | light agent; the indexer needs ≥ 4 GB RAM (8 GB in the 5.0 beta) | moderate |
| memory-safe language | ✓ | ✓ | – | ✓ | – C agent | ✓ |
| platforms | Linux with systemd: x86_64, arm64, 32-bit ARMv7 | Linux, BSD | Linux, BSD, macOS | Linux, FreeBSD, Windows, containers, Kubernetes | Linux, Windows, macOS and more | Linux |
| ARM builds | ◐ arm64 and ARMv7 bundles, tested in CI only | ✓ | ✓ | ✓ | ✓ | ✓ |
| distribution packages or apt repository | ◐ `.deb` and `.rpm` from the releases (no repository), or a zip bundle with `install.sh` | ✓ | ✓ | ✓ vendor repositories | ✓ vendor repositories | ◐ forks |
| signed releases | ✓ build provenance (Sigstore), `SHA256SUMS` | ✓ distribution-signed | ✓ distribution-signed | ✓ signed repositories | ✓ signed repositories | ◐ |
| license | MIT | GPL-2.0 | BSD-style | MIT (engine) | GPL-2.0 | GPL-3.0 |
| in use since | October 2026 | 2004 | the 2000s | 2020 | 2015 | about two decades, until 2025 |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Footprint** | Fits a 1 GB VPS next to the services it protects. The memory limit is backed by flood tests, per-address state is capped (`max_tracked_ips`), and the apt or dnf query runs in a unit of its own, outside the limit. Country blocking costs about 1 MB while its list is computed; the list itself sits in the kernel's sets. | – |
| **Platforms** | The static musl binary needs no matching libc: the same file runs on Debian 13, Ubuntu 22.04 and Fedora 44. Package checks with dpkg or rpm, patches with apt or dnf. Bundles for arm64 and 32-bit ARMv7 (hard-float), from the same CI. | Linux with systemd only. The ARM bundles haven't run on an ARM server yet; RHEL and its rebuilds are untried. |
| **Supply chain** | Few dependencies, and `cargo audit` on every CI run. No TLS library in the binary: `curl` does the downloads. The parsers are fuzzed (cargo-fuzz, plus a smoke run in every `cargo test`). Log text never reaches a shell: firewall changes are built from parsed addresses and fed to `nft -f -`. That class of bug is real elsewhere: fail2ban's CVE-2021-32749 (the `mail-whois` action), Wazuh's CVE-2026-54085 (active response scripts, fixed in 4.14.7). Six internal security reviews in October 2026, each finding fixed with a test. | No independent third-party audit yet, and no distribution maintainers reviewing its packages. A project this young has no CVE history to judge it by. |

---

## 13. Commercial offerings: what money buys

| offering | what it adds | pricing model | better than logguard at | worse than logguard at |
|---|---|---|---|---|
| **CrowdSec** Console Premium, Platinum Blocklists, CTI API | curated and industry blocklists, longer alert history, fleet console, support | per enrolled engine (Premium); Platinum Blocklists from about $1,900/month; IP reputation API from $49/month; support add-ons $1,000/month (vendor page, Oct 2026) | network effect, fleet management, HTTP layer | observations shared with the vendor; cost grows with engines; no host-integrity checks |
| **Wazuh Cloud** and Wazuh support | hosted manager and indexer, retention, support | subscription by number of agents and retention | compliance dashboards (PCI DSS, GDPR, HIPAA, NIST 800-53), CVE detection, many operating systems | a heavy stack, data off-site; its active response is basic next to logguard's ban engine |
| **Atomic Enterprise OSSEC** (Atomicorp) | OSSEC with a management console, compliance reports, curated rules | per node, by quote | support, compliance | proprietary and heavier |
| **Imunify360** (CloudLinux), **BitNinja** | all-in-one suites for web-hosting servers: WAF, IDS/IPS, malware scanning, reputation networks | per server per month | cPanel and Plesk web hosting, PHP malware cleanup | built for shared web hosting, not XMPP or VPN nodes; proprietary |
| **EDR / XDR**: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Servers, Elastic Defend | kernel or eBPF sensors, behaviour detection, threat hunting, optional 24/7 managed response | per endpoint per year, by quote | runtime visibility, tamper protection, malware, incident response, every common OS | cost for a few servers; telemetry goes to the vendor's cloud (GDPR processor terms); a vendor-updated kernel-level agent is a risk of its own (the July 2024 CrowdStrike outage); not built for log-driven IP banning |
| **SIEM**: Splunk, Datadog Cloud SIEM, Microsoft Sentinel, Elastic | central search, correlation and retention across all systems | by data volume ingested | correlation across systems, long retention, investigations | cost grows with log volume; they detect but don't prevent: something on the host still has to ban |
| **Tripwire Enterprise** (Fortra) | compliance-grade FIM and configuration management | per node, by quote | audit evidence, policy libraries | price and weight for a few VPS |

**What commercial products do better:**

- Support with an SLA, and someone to call during an incident.
- Compliance evidence and certifications that auditors and insurers accept.
- Threat research teams, and intelligence from millions of endpoints.
- Every common OS, fleets of thousands, central consoles with roles.
- Kernel-level visibility and tamper protection.

**What they do worse, for a small self-hosted setup:**

- A recurring cost per host that can exceed the cost of the servers.
- Security telemetry, including your users' addresses, leaves your servers.
- Vendor lock-in, agent weight, and agents that need constant connectivity.
- Most of them still don't ban an SSH or XMPP brute-forcer in the host firewall within seconds.

---

## 14. Scorecard

Our judgment for a setup of 1 to 10 self-hosted Linux servers.
●●● strong · ●●○ good · ●○○ basic · ○○○ not covered.

| category | logguard | fail2ban | sshguard | CrowdSec (free) | Wazuh | CSF/LFD | commercial EDR |
|---|---|---|---|---|---|---|---|
| detection and banning, for the services logguard knows | ●●● | ●●○ | ●○○ | ●●● | ●●○ | ●●○ | ●○○ |
| detection breadth, for any other service | ●○○ | ●●● | ●○○ | ●●● | ●●● | ●●○ | ●●○ |
| firewall enforcement | ●●● | ●●○ | ●●○ | ●●● | ●○○ | ●●● | ●○○ |
| sharing within your own servers | ●●● | ○○○ | ○○○ | ●●● | ●●● | ●●○ | ●●● |
| global threat intelligence | ●○○ | ●○○ | ○○○ | ●●● | ●○○ | ●●○ | ●●● |
| host integrity | ●●○ | ○○○ | ○○○ | ○○○ | ●●● | ●○○ | ●●● |
| exposure, patches, certificates | ●●○ | ○○○ | ○○○ | ○○○ | ●●● | ●○○ | ●●○ |
| operations health | ●●○ | ○○○ | ○○○ | ●○○ | ●○○ | ●○○ | ●○○ |
| alert privacy | ●●● | ●○○ | ○○○ | ●○○ | ●○○ | ●○○ | ●○○ |
| choice of alert channels | ●○○ | ●○○ | ○○○ | ●●● | ●●● | ●○○ | ●●● |
| day-to-day UI | ●●○ | ●○○ | ○○○ | ●●● | ●●● | ●●○ | ●●● |
| footprint | ●●● | ●●○ | ●●● | ●●○ | ●○○ | ●●○ | ●○○ |
| platforms and packaging | ●○○ | ●●● | ●●● | ●●● | ●●● | ●●○ | ●●● |
| maturity and community | ●○○ | ●●● | ●●○ | ●●● | ●●● | ●●○ | ●●● |
| cost | free | free | free | free; paid tiers | free; paid cloud | free | per host, by quote |

---

## 15. What logguard does not do (yet)

Know these before you adopt it:

- **No HTTP layer of its own:** no WAF, captcha or CDN integration. It can enforce a WAF's
  decisions at the firewall (`[waf]`: CrowdSec, or any app that gives out a list).
- **A limited set of built-in sources:** sshd, ejabberd, the kernel log, Nextcloud, su and sudo,
  PAM and the audit log, and 13 common services (web servers, HAProxy, Prosody, databases,
  Redis, mail, ownCloud), the latter tested against log lines but not yet on a host. Everything
  else needs regex patterns of your own.
- **One platform family:** Linux with systemd and journald. Debian, Ubuntu and Fedora have run
  it; ARM builds exist but haven't run on an ARM server.
- **A read-only web console only:** logguard-web shows the cluster to a few admins, with a REST
  API and Prometheus metrics, but nothing can be changed from it (by design), every admin may see
  everything (no roles), and it is new.
- **No crowd-sourced intelligence.** It has static public feeds, and country blocking from a free
  database that misplaces some addresses.
- **Host watches poll**, every minute or once a week; they don't see kernel events. There is no
  tamper protection against root.
- **No CVE matching, hardening benchmark or compliance reports** (the hardening audit covers sshd only).
- **Five alert channels:** XMPP, Telegram, e-mail, Signal and Matrix.
- **No package repository:** `.deb` and `.rpm` files from the releases, installed one by one (`apt install ./file.deb`), or a release zip with `install.sh`; nothing to `apt upgrade` from.
- **Young:** version 0.4.0, running on the authors' own servers only, written by one maintainer
  in collaboration with an AI model (see the [README](README.md#authorship)). It has had internal
  security reviews, but no independent audit.
- **Covered by tests, not yet run on a host** (the README's
  [Not yet verified](logguard/README.md#not-yet-verified)): the plain iptables backend, sudo (the servers have none) and new-SSH-key
  alerts, patterns on a live journal, the Telegram relay
  node, the ARM builds, and what came in October's last days: the built-in sources for common
  services, PAM failures and audit alerts, scans of changed files with YARA (ClamAV's have run on a host), the desktop profile, the XMPP bot's
  client mode, and `[waf]` against a real CrowdSec. Users' own warnings work in tests but have not yet been confirmed
  reaching a user.
- **Forged sources:** evidence that rests only on blocked packets can name a forged source.
  logguard limits the harm, but someone who forges packets can still get outsiders banned for
  an hour.

---

## 16. Evidence so far

**In production.** Four servers run in enforce mode. The first two were a VPN host (Ubuntu 22.04,
kernel 5.15) and an XMPP and Nextcloud server (Debian 13, kernel 6.12), the latter since
mid-October 2026 after a shadow-mode period; two more joined in late October. Verified there:

- live journal input;
- bans in nftables, with timeouts;
- the table rebuilt within 30 s after it was deleted;
- kernel rate limits;
- the cluster in both directions, with repeat offences escalating across nodes;
- the exposure watch, with Docker ports recognised;
- certificate checks;
- the geo database;
- blocklist feeds;
- operator controls;
- encrypted admin messages through the XMPP bot;
- the cron watch and antivirus results;
- OOM alerts;
- SSH canary bans;
- `su` alerts, with the account's last SSH login and its place;
- the package and set-uid check with dpkg (no file differs, 17 set-uid programs) and the patch
  status with apt (the old kernel still running after an upgrade);
- the systemd watchdog.

**Added on 2026-10-27 and 2026-10-28, on the four servers:**

- bans after connection tracking: IPv4 and IPv6 bans, subnet bans growing from a /24 to a /22,
  and the servers' own pings and TCP connections to banned addresses getting their replies;
- node identities: every node signs its facts, pins the other three's keys and requires
  signatures;
- the web console showing all four nodes, three of them through their agents;
- the SSH audit: a hardened gateway found clean; on a cloud image, root's password login and
  cloud-init's override of `PasswordAuthentication` found, then logged as fixed;
- the process watch (a new outbound connection reported), and the exposure watch reporting a
  new listener and an allow rule with nothing behind it;
- a changed file scanned with ClamAV;
- account changes reported, and an installer's new system user logged as announced.

These runs found six problems, all fixed the same day: two misleading SSH audit messages, an
installer's new user raising high alerts, the web console's `check` misreading lists with
blanks, an empty console socket setting refused, and no way to correct a country the geo
database gets wrong (now `[geo] places`).

**On a Fedora 44 test server** (one evening, 2026-10-25, x86_64, firewalld 2.4.4, rpm 6 and
dnf5, real scanners and a VPN as the test client), following
[TESTING-fedora.md](logguard/TESTING-fedora.md):

- install from the release bundle with a `-dnf` template;
- firewalld's denied-packet log as a signal source: real scanners banned on their first
  tripwire hit;
- honeypot ports 22 and 23, tried with `nc` from the VPN's exits;
- the exposure watch reading firewalld's zones, rich rules and dead rules included;
- rpm origins, the package check (7,472 files; a tampered binary caught) and the dnf patch
  status (the newer kernel waiting for a reboot);
- the firewalld, nftables and ipset backends: bans, expiry, operator ban and unban, recovery
  within 30 s after `firewall-cmd --reload`, a firewalld restart or flushed chains;
- country blocking: two countries' 137,000 networks loaded, test clients there timed out and
  one elsewhere connected.

The run found nine bugs (a bundle could carry an older binary, two misleading `status` lines,
a failed start logged too quietly, a merged `/usr/sbin` doubling integrity alerts, and more),
all fixed the same day.

([Verified on the servers](logguard/README.md#verified-on-the-servers) has the details.)

**On a real month of logs** (Sep 11 to Oct 11, 2026, about 210,000 records from ejabberd, sshd
and UFW):

- 185 bans of 93 targets. None of them ever authenticated, and no user's address was banned.
- 13,480 tripwire hits banned about 7,500 scanners on first contact.
- The OOM alerts revealed a nightly virus scan that had been killed for weeks, and a disabled
  signature updater.
- The old setup's generated UFW deny rules sat below the ALLOW rules, so they never matched:
  4,438 XMPP connections and 106 SSH sessions came from addresses they were meant to block. This
  is why logguard's bans sit in their own table, ahead of everything else.

**In tests:**

- About 340 tests in logguard, about 220 more in the bots, and 30 in the web console (an agent
  and a console against a stand-in logguard, logged into over TLS like a browser). The firewalld, ipset and rpm
  code is also tested against stand-in `firewall-cmd`, `ipset`, `iptables` and `rpm` programs.
- `tests/layouts.rs` runs the real daemon in each of the 15 supported layouts of bots and peers,
  end to end.
- The parsers are fuzzed.
- CI runs clippy with warnings as errors, `cargo audit`, and static musl builds for every
  commit: the tests on x86_64 and arm64, the ARMv7 binary started under qemu.

---

## 17. Which tool for which situation

| if you ... | consider |
|---|---|
| run 1 to 10 self-hosted Linux VPS (SSH, XMPP, Nextcloud, WireGuard) and want one small tool with encrypted alerts and nothing sent to a vendor | **logguard** |
| want to drop whole countries cheaply, from an offline database, with the rest of logguard | **logguard** `[geoblock]`; for per-port country rules, **CSF** |
| want a few servers on one read-only web page and in Prometheus, without a SaaS console | **logguard** with **logguard-web** |
| mostly need SSH brute-force protection on any Unix, with minimal setup | **sshguard** or **fail2ban** |
| protect many different services and want ready-made filters | **fail2ban** or **CrowdSec** |
| run web applications and want a WAF, crowd intelligence and proxy or CDN integration | **CrowdSec** with AppSec |
| need compliance reports, CVE detection and one console for dozens of hosts on several operating systems | **Wazuh**, self-hosted or Cloud |
| run cPanel or DirectAdmin shared hosting | a **CSF** fork, or **Imunify360** |
| need runtime visibility into containers and Kubernetes | **Falco** or **Tetragon** |
| need a vendor, a 24/7 security operations team, or must meet insurance requirements | a commercial **EDR / MDR** |

---

## 18. Good companions

logguard works well next to:

- **unattended-upgrades** or **dnf-automatic**, to install what logguard's patch status
  reports.
- **An external uptime and certificate monitor**, which sees the host from outside, even when it
  is down. Cluster peers already report a node that stops answering for 5 minutes.
- **A WAF for web applications:** Coraza or ModSecurity, or CrowdSec AppSec with an HTTP-level
  bouncer only. Keep one ban manager per host: running fail2ban or CrowdSec's firewall bouncer
  next to logguard bans twice and splits the evidence between them.
- **Lynis**, for a periodic hardening audit.
- **Falco or Tetragon**, where containers matter.
- **ClamAV**, whose results logguard reads and reports.
- **An off-host log archive** (systemd-journal-remote, rsyslog) and backups, for forensics.

---

## 19. Trying it

1. **Check the requirements:** Linux with systemd (x86_64; ARM builds untried on servers), and
   one of nftables (recommended), firewalld, ufw, iptables or ipset
   ([Requirements](logguard/README.md#requirements)).
2. **Download a release bundle** and verify its checksum and build provenance
   ([Install from a release bundle](logguard/README.md#install-from-a-release-bundle)).
3. **Install with a template:** `logguard.toml` for an XMPP server, `logguard-standalone.toml` for a
   host with SSH and UFW only, `logguard-tg.toml` for a Telegram relay node; each has a `-dnf`
   variant for Fedora and RHEL.
4. **Run in shadow mode** (the default) for one to two weeks: it decides, but bans nothing. Watch
   `logguard tui`, and look for "likely false positive" alerts. You can replay a week of your
   journal first:
   ```bash
   journalctl -u ssh -k --since -7d -o json > week.json && logguard -c /etc/logguard/logguard.toml replay week.json
   ```
5. **Enforce:** set `mode = "enforce"`, restart, and check `nft list table inet logguard` (or
   `firewall-cmd --info-zone=logguard`). To roll back, switch to shadow mode and delete the table
   ([Rollout](logguard/README.md#rollout)).
6. **Add more** when you want it: cluster peers, the bots, the web console
   ([logguard-web](logguard-web/README.md)), blocklist feeds, country blocking, honeypot ports,
   built-in sources and patterns for your other services.

---

## 20. Method and sources

The logguard facts and numbers come from its READMEs and code at commit `01e37a6`; the
measurements are the ones those READMEs report, the Fedora run included. The other tools were assessed from their
documentation, release pages and advisories as of 2026-10-25. "✓" and "◐" mean what a tool
offers out of the box or as a documented option, not everything a custom script could add. The
scorecard is a judgment for small self-hosted setups, and others may weigh it differently.

- CrowdSec: [pricing](https://www.crowdsec.net/pricing),
  [Security Engine docs (1.8)](https://docs.crowdsec.net/docs/v1.8/intro),
  [AppSec (1.7)](https://docs.crowdsec.net/docs/v1.7/appsec/intro),
  [community blocklist](https://doc.crowdsec.net/docs/next/central_api/community_blocklist),
  [1.7 release notes, summarised](https://linuxiac.com/crowdsec-1-7-intrusion-detection-and-prevention-system-released/)
- fail2ban: [Alpine package (1.1.0, 2026)](https://pkgs.alpinelinux.org/package/edge/main/x86/fail2ban),
  [CVE-2021-32749](https://nvd.nist.gov/vuln/detail/CVE-2021-32749)
- sshguard: [Fedora packages (2.5.1, nftables backend)](https://packages.fedoraproject.org/pkgs/sshguard/sshguard-nftables/)
- reaction: [announcement (LinuxFr)](https://linuxfr.org/news/reaction-remplacant-de-fail2ban),
  [OpenBSD package](https://www.openbsdhandbook.com/packages/current/sysutils/reaction/)
- CSF/LFD: [the ConfigServer shutdown](https://blog.centminmod.com/2025/09/04/2921/configserver-csf-firewall-shutdown-on-august-31-2025/),
  [running CSF after the shutdown](https://linuxblog.io/configserver-firewall-csf-after-shutdown/),
  [a community fork](https://github.com/AfazTech/csf)
- Wazuh: [indexer requirements](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/),
  [5.0 beta requirements](https://documentation.wazuh.com/5.0-beta/installation-guide/wazuh-indexer/index.html),
  [active response (5.0 beta)](https://documentation.wazuh.com/5.0-beta/user-manual/capabilities/active-response/index.html),
  [CVE-2026-54085](https://app.opencve.io/cve/CVE-2026-54085)
- OSSEC: [project overview](https://www.ossec.net/docs/about.html),
  [Wikipedia](https://en.wikipedia.org/wiki/OSSEC),
  [Atomic Enterprise OSSEC](https://marketplace.redhat.com/en-us/products/atomic-workload-protection)
- Let's Encrypt: [ending expiration e-mails](https://letsencrypt.org/2025/01/22/ending-expiration-emails/),
  [the service has ended](https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended/)
- logguard: [README](logguard/README.md), [repository README](README.md), the
  [web console's README](logguard-web/README.md), and each bot's README
  ([XMPP](logguard-xmpp-bot/README.md), [Telegram](logguard-tg-bot/README.md),
  [mail](logguard-mail-bot/README.md), [Signal](logguard-signal-bot/README.md),
  [Matrix](logguard-matrix-bot/README.md))
