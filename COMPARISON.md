# logguard compared

**How logguard compares with the open-source and commercial tools you might use instead:
a briefing for teams thinking about adopting it.**

The state is as of 2026-10-25: logguard 0.2.0 (commit `26a575c`), compared with the releases and
documentation of the other tools at that date. Feature claims about logguard come from its
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

Several servers share what they see over an encrypted peer-to-peer link. There is no central
server and no vendor in between.

```
journal ─► logguard ─► nftables / ufw / iptables  ◄── encrypted cluster link ──►  logguard on other nodes
             │
             ├─► logguard-xmpp-bot ─► XMPP, OMEMO-encrypted
             ├─► logguard-tg-bot   ─► Telegram, pseudonymized, files OpenPGP-encrypted
             └─► logguard-mail-bot ─► e-mail, PGP/MIME-encrypted
```

**What one install covers, and what you would otherwise run:**

| logguard part | usually done with |
|---|---|
| scoring and banning, subnet bans, tripwires, honeypots, canary accounts | fail2ban, sshguard, CrowdSec |
| ban sharing between your servers, blocklist feeds | CrowdSec, CSF cluster, ipset scripts |
| cron and persistence watch, package and set-uid check, process watch | AIDE, debsums, rkhunter, Wazuh FIM |
| listeners compared with firewall rules, dead rules, Docker bypass | Lynis, external port scans, by hand |
| patch status, certificate checks | apticron, needrestart, an uptime or certificate monitor |
| quiet log sources, OOM kills, disk, memory, failed units | Monit, Netdata, Prometheus |
| daily digest, weekly abuse report | Logwatch, AbuseIPDB scripts |

**Key numbers** (measured, from the README):

- **~8 MB** static binary with no runtime dependencies.
- **~10 MB RAM** for a real month of traffic (~50 MB with the offline geo database). The hard
  limit is 128 MB, and it held in a synthetic flood of 450,000 sources.
- A real month of logs (~210,000 records) replays through the full engine in **about one
  second**: 185 bans of 93 targets. No address that ever logged in was banned.
- Tripwire ports banned **about 7,500 scanners on first contact** in that month.

---

## 2. Who it is for, and who it is not for

**A good fit:**

- One to about ten Linux servers you run yourself: Debian or Ubuntu, x86_64, systemd.
- SSH, XMPP (ejabberd), Nextcloud AIO and WireGuard hosts. Other services count through
  regex patterns of your own.
- Admins who want alerts on their phone, encrypted, with nothing about their users or attackers
  sent to a vendor.
- Small machines: it is built to stay within a 128 MB memory limit next to the services it
  protects.

**Not a good fit today:**

- **Fleets** of dozens of hosts or more that need a central web console, roles and compliance
  reports. Look at Wazuh, the CrowdSec Console or a commercial EDR.
- **Web-application-heavy hosts** that need a WAF, captchas or CDN integration. Look at CrowdSec
  AppSec, ModSecurity or Coraza, or a CDN.
- **Other platforms:** Windows, macOS, BSD, ARM, Linux without systemd. RPM distributions run
  the core, but the package and patch checks need dpkg and apt.
- **Organisations that need a vendor:** a support SLA, certified compliance evidence, or a
  24/7 security operations team.

---

## 3. The field

**Ban managers and intrusion-prevention tools**, compared in sections 4 to 12:

| tool | kind | license | language | model | state in Oct 2026 |
|---|---|---|---|---|---|
| **logguard** | ban manager and host watch | MIT | Rust | decaying scores per address across all services, own nftables table, peer-to-peer cluster | 0.2.0, new in Oct 2026 |
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
| built-in parsers | ◐ sshd, ejabberd, kernel/UFW, Nextcloud AIO, su/sudo | ✓ dozens of filters | ◐ SSH and common mail/FTP daemons | ✓ hub of parsers and scenarios | ✓ thousands of rules | ✓ hosting stack |
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
| **Parsers** | Deep parsers for what it knows. An ejabberd TLS failure is tied to its address through the Erlang PID. OpenSSH 10's `sshd-session` lines are handled. A line counts only from its real sender, by journald's own fields, so a local user can't log a fake sshd line to get someone banned. | Five built-in sources. Web servers, mail, FTP and databases need `[[patterns]]`. fail2ban, CrowdSec and Wazuh ship ready filters for hundreds of services. |
| **Own patterns** | Linear-time regex, so no catastrophic backtracking on hostile lines. The sender is pinned by unit, or by identifier and uid. `test-pattern` and a TUI tab show the lines read, matched, and matched without an address. | A pattern is a regex, a kind and a weight. There are no multi-line or stateful scenarios like CrowdSec's leaky buckets or Wazuh's composite rules. |
| **Scoring** | Two decaying scores (10 min and 12 h half-life) add up every signal from every service. A scanner that touches SSH, XMPP and closed ports a little each still reaches a ban. Weights are calibrated on a real month of logs. | One model for everything: tuning means weights and thresholds, not per-service rules. At first it is less obvious than fail2ban's "N failures in T minutes". |
| **Escalation** | 1 h → 6 h → 1 d → 7 d → 30 d per repeat offence. Offences are shared, so a repeat attacker escalates on every node of the cluster. | fail2ban, sshguard and CSF escalate too, and CSF offers permanent bans. Only the cluster-wide counter is new here. |
| **Subnet bans** | Starts at /24 (IPv6 /64) and grows towards /16 (/48) only as nearby bans appear, at most 2 bits a step. It never covers a protected address. With the geo database, it never grows into another provider's network. | The provider boundary needs the `[geo]` ASN database. A stricter policy, such as blocking a whole network or country now, needs feeds. CSF blocks countries out of the box. |
| **Tripwires and honeypots** | One SYN to an unused telnet, RDP or database port bans. Kernel tripwires log these hits from logguard's own nftables rules, so UFW's log limit (about 3 lines a minute) doesn't hide scans. Honeypot ports complete the TCP handshake, so their evidence can't be forged. | A blocked SYN can carry a forged source address. logguard limits the damage: such evidence never bans an address that logged in recently, replies always pass, and with honeypots set it is worth half a ban. A spoofer can still get outsiders banned for an hour. |
| **Canary accounts** | No accounts to create. On a key-only host, `ssh = ["*"]` makes every unknown user name a ban. A successful login to a canary is a critical alert. | fail2ban, CrowdSec and Wazuh can do this with a filter of your own. logguard just has it built in. |
| **Account protection** | Distributed guessing against one account from several addresses; a login right after failures (possible compromise); a login from a new network or provider for that account; a login with a never-seen SSH key. | Covers XMPP, SSH, Nextcloud and your patterns only. Wazuh covers far more authentication sources (PAM, Windows, cloud services). |
| **False positives** | Shadow mode lifts its own "bans" when the address later logs in, and says so. An address that logged in recently isn't banned for that service's typos and reconnects. Private, CGNAT, loopback and link-local addresses are never banned. | Login trust is a heuristic. An attacker behind the same carrier NAT as a user gets the same excuse for that service's noise; real failures still raise an alert. |
| **Testing** | `replay` runs journal exports through the whole pipeline without touching the firewall, and opens the result in the TUI. | CrowdSec's replay mode and `cscli explain` are as capable, and better documented for writing new scenarios. |

---

## 5. Firewall enforcement

> **Bottom line:** logguard's enforcement takes the most care not to break the server itself
> (Docker, flushed rulesets, replies, oversized feeds). fail2ban and CrowdSec support more
> firewalls, and CrowdSec reaches the HTTP layer and CDNs.

| feature | logguard | fail2ban | sshguard | CrowdSec bouncer | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| firewall backends | ◐ nftables, ufw, iptables | ✓ iptables, nftables, firewalld, ufw, pf, ipfw, … | ✓ iptables, ipset, nftables, firewalld, pf, ipfw | ✓ nftables, iptables/ipset, pf, Windows | ◐ iptables, firewalld, pf, Windows | ◐ iptables |
| bans expire in the kernel, even while the daemon is down | ✓ nft set timeouts | ◐ some ipset actions | – | ✓ | – | – |
| Docker-published ports covered without extra setup | ✓ | ◐ `DOCKER-USER` chain by config | ◐ | ◐ `DOCKER-USER` or forward hook by config | ◐ | ◐ `DOCKER` option |
| per-source connection rate limits in the kernel | ✓ | – | – | – | – | ✓ `CONNLIMIT`, `PORTFLOOD` |
| public blocklists loaded into the firewall | ✓ with sanity limits | – | – | ✓ console blocklists | – | ✓ `csf.blocklists` |
| country blocking | – | – | – | ◐ paid lists or own profiles | – | ✓ `CC_DENY` |
| HTTP-level responses (403, captcha, CDN) | – | ◐ Cloudflare action | – | ✓ nginx, Traefik, HAProxy, Cloudflare, … | – | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Where bans sit** | Its own nftables table at prerouting, right after connection tracking. It runs before ufw's chains and before Docker's DNAT, so your own ALLOW rules can't shadow a ban, and Docker ports are covered without touching `DOCKER-USER`. It never edits your rules. | Three Linux backends only: no firewalld, pf or Windows. The ufw fallback loses Docker coverage, rate limits and feeds. The iptables backend has not yet run on a real host. |
| **Expiry** | Ban timeouts live in the kernel: if logguard stops, bans still end on time. After a reboot it re-applies what is still active. | CrowdSec's firewall bouncer works the same way. |
| **Self-healing** | Debian's and Ubuntu's `nftables.conf` starts with `flush ruleset`, so a restart of nftables deletes every ban. logguard notices within 30 s, rebuilds every set and chain, re-adds the bans with their remaining time, and raises a high alert. | fail2ban restores its chains too, but only at its next ban action. |
| **Replies to the server's own connections** | Bans drop after connection tracking, so replies always pass: DNS, mail relay, update mirrors, federated XMPP servers. A forged packet that gets such an address banned can't cut the server off. | New since 2026-10-24. The rules are tested, and `install.sh` checks them against the kernel with `nft -c`, but they have not yet run on a host. |
| **Rate limits** | Per-source `[[ratelimit]]` entries in the kernel, from the first packet, Docker ports included. `status` shows their drop counters. | nftables backend only. CSF has richer flood controls (SYN floods, per-port and per-connection limits). |
| **Feeds** | Downloads with `curl` (the binary has no TLS library) and keeps the last good copy. It drops bogons, prefixes wider than /12, and anything overlapping your allowlist or peers. A refresh that suddenly covers far more address space is refused. | A few public lists (Spamhaus DROP and ASN-DROP, FireHOL); no curated commercial lists, no country lists. CrowdSec's blocklists are larger and updated more often. |
| **HTTP layer** | – | No HTTP-level response: a banned visitor just times out. No captcha, no ban at the CDN or edge. CrowdSec's remediation components and WAF cover that layer. |

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
| **Cluster** | XChaCha20-Poly1305 under a shared key, and only peers may connect. Facts are de-duplicated and forwarded up to 3 hops. Suspicion is shared too, so an address that probes every server a little still adds up to a ban. A limited peer (`peer_accept`) can send messages but never ban anything. Key rotation is staged in three rounds, without a gap. | Every unlimited key holder is fully trusted: a broken-into node can ban on the others, for at most `max_remote_ban`. It uses one shared key, with no per-node keys or PKI. It is sized for a handful of nodes, with no fleet management. |
| **Threat intelligence** | Your data stays yours: no vendor sees your attackers or your users. The static feeds (Spamhaus, FireHOL) need no account. | No network effect. CrowdSec blocks addresses that attacked thousands of other servers before they reach yours; logguard knows only what your own nodes saw. |
| **Abuse reports** | A weekly report grouped by abuse mailbox (looked up with RDAP), each attacker with UTC log lines and account names withheld. Reports from several nodes are merged, and the result reaches the admin encrypted. | You send the mails yourself: logguard never mails third parties, by design. There is no AbuseIPDB integration. |
| **Geo** | DB-IP Lite: about 1.2 million ranges in ~40 MB, looked up in memory, with no request per lookup. Used in alerts, to limit subnet growth, and to learn each account's providers. | Countries and networks only, no cities; DB-IP Lite accuracy. |

---

## 7. Host integrity and intrusion detection

> **Bottom line:** logguard covers the practical "how would someone stay in?" checklist on
> Debian and Ubuntu with no extra tools. It is not a kernel-level runtime sensor and not a
> compliance-grade FIM.

| feature | logguard | Wazuh | AIDE | rkhunter, debsums | Falco, Tetragon | osquery |
|---|---|---|---|---|---|---|
| persistence points watched out of the box (cron, timers, units, SSH keys, PAM, sudoers, `ld.so.preload`, apt hooks, ...) | ✓ every minute | ◐ default directories, 12 h scans; real time by config | ◐ distribution config, typically daily | ◐ some startup files | ✓ rules, real time | ◐ tables, scheduled queries |
| changed lines shown in the alert | ✓ | ✓ `report_changes` | – | – | – | – |
| package files told apart from foreign ones (dpkg origin) | ✓ | – | – | ✓ debsums | – | ◐ `deb_packages` |
| package files checked against dpkg's hashes | ✓ weekly | – | ◐ own baseline | ✓ debsums | – | – |
| set-uid program inventory | ✓ | ◐ rootcheck | ◐ baseline | ◐ | ◐ rules | ✓ `suid_bin` |
| outbound connections and reverse shells | ◐ checked every 60 s | ◐ command monitoring | – | – | ✓ syscall events | ◐ snapshots |
| programs running from `/tmp`, from memory or from deleted files | ✓ checked every 60 s | ◐ rootcheck | – | ◐ | ✓ | ◐ by query |
| failed su and sudo | ✓ | ✓ | – | – | – | – |
| a login with a never-seen SSH key | ✓ | – | – | – | – | – |
| malware signatures | ◐ reads ClamAV results | ◐ ClamAV, YARA, VirusTotal integrations | – | ◐ rootkit signatures | – | – |
| real-time kernel events | – | ◐ who-data through auditd | – | – | ✓ eBPF | ◐ evented tables |
| events copied off the host as they happen | ◐ alerts only, through bots and peers | ✓ | ◐ Samhain's server | – | ◐ falcosidekick | ◐ fleet server |
| signs of journal tampering (lost position, sealed-journal check) | ✓ | – | – | – | – | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Persistence watch** | It knows where intruders hide, including the scripts crontab lines run (also behind `sudo -u`, `flock`, `timeout`). It keeps fingerprints only, never contents, so no password hashes in alerts or state. Alert severity knows whether dpkg installed the file unchanged. Installers announce their changes (`expect-change`) so upgrades don't alert. One local account can raise at most 5 alerts an hour, so it can't flood the channel. | It checks every minute: a change undone within a minute is missed. Falco and Tetragon see the write itself, and which process made it. The list of places is fixed, plus your own `[cron] files`; AIDE and Wazuh FIM cover any directory tree. |
| **Package and set-uid check** | A debsums-like check plus a set-uid inventory. It reads at most 20 MB/s and drops what it read from the page cache, so it stays within the 128 MB unit. Diverted files and upgrades in progress are handled. | dpkg only, no RPM, once a week. A root attacker who also rewrites dpkg's hash lists defeats it, as with debsums. Not yet run on a host. |
| **Process watch** | A baseline of outbound connections per program and port. A shell or network tool talking out, or a miner or reverse-shell port, is always high. Programs from `/tmp`, from memory (`memfd`) or from deleted files are reported. | A snapshot every 60 s misses short-lived connections, and connections inside containers aren't seen. eBPF tools are much stronger here. |
| **Privilege and keys** | Failed su and sudo, each with the account's last SSH login and its place. New-SSH-key alerts start after a learning period. | Wazuh's ruleset covers far more authentication events (PAM, auditd). |
| **Malware** | Turns ClamAV's runs into alerts: infected files, scans killed for memory, stale signatures, missing runs. It ships a scan timer that runs at low priority and dies first when memory runs out. | No scanning engine or YARA of its own. |
| **Tamper resistance** | Alerts leave the host at once (encrypted bots, peers). A lost journal position and failed `journalctl --verify` checks are reported. Peers report a node that stops answering for 5 minutes. | The raw evidence stays on the host. A root attacker can stop logguard: the systemd watchdog restarts a hung daemon, not a deliberately stopped one. EDRs add tamper protection, and Wazuh ships every event off the host. |

---

## 8. Exposure, patches and certificates

> **Bottom line:** logguard explains, port by port, what the internet can reach and why, and
> catches certificate mistakes other monitors miss. Use Wazuh or Lynis for CVE matching and
> hardening benchmarks, and unattended-upgrades to apply updates.

| feature | logguard | Wazuh | Lynis | unattended-upgrades, needrestart | Uptime Kuma, blackbox_exporter | external scan (nmap, Shodan) |
|---|---|---|---|---|---|---|
| each listener compared with the firewall rule that lets it in | ✓ ufw, iptables, docker-proxy | ◐ port inventory | ◐ once per run | – | – | ◐ outside view |
| Docker ports that bypass ufw | ✓ | – | – | – | – | ◐ seen as open |
| alerts: new public listener, listener gone, dead allow rule, no firewall | ✓ | ◐ listening-port change rule | – | – | ◐ port down | – |
| pending security updates, reboot needed, processes on replaced libraries | ✓ in the digest | ✓ | ◐ | ✓ installs and restarts | – | – |
| CVE matching | – | ✓ | ◐ | – | – | ◐ service versions |
| hardening benchmark (CIS style) | – | ✓ SCA | ✓ | – | – | – |
| live certificate expiry, STARTTLS included | ✓ | – | – | – | ✓ | ◐ |
| "renewed but not in use", DANE TLSA value at each renewal | ✓ | – | – | – | – | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Exposure** | Reads the listeners from `/proc` and follows the firewall's own logic: rules in order, jumps, policies, rate limits. The TUI names the rule that lets each port in. It flags Docker-published ports, which ufw doesn't filter, and allow rules for ports nothing listens on: the kind of dead rules that were found by hand on the authors' hosts before. | A view from the host only: a provider's own firewall in front of it is not seen. nftables rulesets of your own are noticed but not read. An external scan remains the ground truth. |
| **Patches** | A simulated `apt-get` (no lock taken) in a unit of its own, a newer installed kernel than the running one, and programs still running replaced libraries. All of it is in the daily digest. | Reports only: it doesn't apply updates (use unattended-upgrades). No CVE database. Debian and Ubuntu only. |
| **Certificates** | Live endpoints every 6 h, XMPP STARTTLS included, plus the certificates on disk. It warns when a renewed certificate isn't served yet, explains ejabberd's ACME failures, and gives the new DANE `3 1 1` value at each renewal. This matters more since Let's Encrypt stopped sending expiry e-mails in June 2025. | Checked from the host itself, so DNS or routing problems elsewhere are not seen. |
| **Hardening** | – | No audit of configuration (sshd settings, sysctls, file permissions). Run Lynis or Wazuh SCA for that. |

---

## 9. Operations health

> **Bottom line:** logguard covers the alerts a small server needs, and knows when its own
> view has gone dark. It is not a metrics system.

| feature | logguard | Monit | Netdata | Prometheus, Alertmanager | Logwatch, logcheck |
|---|---|---|---|---|---|
| a log source goes quiet, or stops naming addresses | ✓ | ◐ file timestamps | – | ◐ `absent()` on your own metrics | – |
| OOM kills, with process and size | ✓ | – | ✓ | ◐ a counter only | ◐ in the daily mail |
| disk space, memory pressure (PSI) | ✓ | ✓ | ✓ | ✓ | – |
| failed systemd units that are not restarted | ✓ | ✓ | ✓ | ✓ | – |
| restarts services itself | – | ✓ | – | – | – |
| daily digest | ✓ security and health | – | – | – | ✓ |
| graphs and history | ◐ TUI trends | ◐ M/Monit | ✓ | ✓ with Grafana | – |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Silence** | Tells "no attacks" from "not seeing logs", with thresholds measured per source on a real month. It also notices lines that arrive but name no address (ejabberd's `hide_sensitive_log_data`, a changed log format). | For its own sources only. |
| **Resources** | OOM kills (they revealed weeks of a nightly ClamAV scan being killed), disk under 10 % and 5 %, memory availability and pressure stalls, failed units after a restart grace period. | Basic: no metrics history and no per-process graphs. Netdata and Prometheus are far richer. |
| **Digest** | One message a day per server, marked ⚠ when something needs attention: certificates, peers, feeds, dead rules, patches, top offenders. | A fixed format, with no report builder. |

---

## 10. Alerts and the people who get them

> **Bottom line:** no other tool here encrypts alerts end to end, pseudonymizes them for an
> untrusted channel, or warns the user whose account is attacked. In exchange, logguard offers
> three channels where the others offer dozens.

| feature | logguard | fail2ban | CrowdSec | Wazuh | commercial EDR, SIEM |
|---|---|---|---|---|---|
| admin channels | ◐ XMPP, Telegram, e-mail | ◐ e-mail, scripts | ✓ Slack, e-mail, webhooks, Splunk, Elastic, Sentinel, … | ✓ e-mail, Slack, PagerDuty, custom | ✓ |
| end-to-end encryption | ✓ OMEMO, OpenPGP | – | – | – | – |
| pseudonymized copies for an untrusted channel | ✓ Telegram | – | – | – | – |
| warns the attacked user, in their language | ✓ XMPP accounts, 6 languages | – | – | – | – |
| budgets per topic, so a flood can't hide a critical alert | ✓ | – | ◐ grouping | ◐ e-mails per hour | ✓ |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Channels** | XMPP through the admin bot, OMEMO-encrypted and kept out of the server's archive. Telegram, with account names pseudonymized and servers named only by node id. E-mail, OpenPGP-encrypted as a whole, subject included. Any mix of the three. | No Slack, Teams, Matrix, Signal, ntfy, webhooks or PagerDuty. A new channel means a new bot. |
| **Privacy** | Built for operators who take GDPR seriously: nothing about users goes to a vendor, Telegram never sees account names, and reports travel as encrypted files. | Encryption takes setup (OMEMO device trust, OpenPGP keys). If the XMPP bot doesn't take a message within 2 minutes, it goes out over plain XMPP, saying why. |
| **Users** | Account holders learn when their account is attacked: password guessing, a possible compromise, and (opt-in) a login from a new network. No other tool here does this. | XMPP accounts only: Nextcloud and SSH users aren't messaged. |
| **Noise control** | One message per incident and account every 6 h, hourly caps per topic for admins, hourly budgets per local user for host changes. Alerts relayed from peers are tagged with the node's name. A bot that stops sending is itself reported over the other channels. | Fixed policies: routing is less flexible than Alertmanager's or CrowdSec's profiles. |

---

## 11. Day-to-day operation

> **Bottom line:** a capable terminal UI and careful upgrade tooling, but no web console, no
> API and no metrics export.

| feature | logguard | fail2ban | sshguard | CrowdSec | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| live dashboard | ✓ terminal UI | – | – | ◐ `cscli`; web console (SaaS) | ✓ web | ✓ panel UI |
| web UI and fleet view | – | – | – | ✓ | ✓ | ◐ per server |
| ban, unban, temporary allow | ✓ CLI and TUI, shared with peers | ✓ | – | ✓ | ◐ API | ✓ |
| pattern tester | ✓ `test-pattern` | ✓ `fail2ban-regex` | – | ✓ `cscli explain` | ✓ `wazuh-logtest` | – |
| metrics for Prometheus | – | ◐ community exporters | – | ✓ | ◐ API | – |
| community, Q&A, third-party guides | ◐ one detailed README | ✓ | ◐ | ✓ | ✓ | ◐ forks |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **TUI** | Works over SSH in an 80-column terminal. Up to 10 tabs: offenders with evidence, bans, decisions, accounts, exposure, countries with port histograms, a world map, alerts and patterns. Ban, unban and allow with a confirmation. It also reads saved decision logs of several servers offline. | One node at a time; no web console, no roles, no multi-tenant view. |
| **Tooling** | `status`, `replay`, `print-nft`, `notify-test` for each channel, a digest preview. `config-diff` runs after every upgrade and lists new options, changed defaults and unknown keys. The installer dry-runs the nftables ruleset against the kernel first. | No Prometheus or OpenTelemetry export, and no REST API: the control socket is a root-only Unix socket. |
| **Docs** | One README that explains every default, often with the measurement behind it. | One long document: no website, no forum or chat. Some answers are only in the code. |

---

## 12. Footprint, platforms and supply chain

> **Bottom line:** the smallest and most self-contained option here after sshguard, written
> in a memory-safe language. It runs on fewer platforms, is packaged in fewer ways, and has
> the shortest track record.

| feature | logguard | fail2ban | sshguard | CrowdSec | Wazuh | CSF/LFD |
|---|---|---|---|---|---|---|
| runtime | static binary, ~8 MB | Python 3 | C | Go: engine and bouncer | C agent; manager; OpenSearch-based indexer; dashboard | Perl |
| memory | ~10 MB for a real month, ~50 MB with geo; capped at 128 MB | moderate | a few MB | moderate | light agent; the indexer needs ≥ 4 GB RAM (8 GB in the 5.0 beta) | moderate |
| memory-safe language | ✓ | ✓ | – | ✓ | – C agent | ✓ |
| platforms | Linux x86_64 with systemd | Linux, BSD | Linux, BSD, macOS | Linux, FreeBSD, Windows, containers, Kubernetes | Linux, Windows, macOS and more | Linux |
| ARM builds | – | ✓ | ✓ | ✓ | ✓ | ✓ |
| distribution packages or apt repository | – zip bundle and `install.sh` | ✓ | ✓ | ✓ vendor repositories | ✓ vendor repositories | ◐ forks |
| signed releases | ✓ build provenance (Sigstore), `SHA256SUMS` | ✓ distribution-signed | ✓ distribution-signed | ✓ signed repositories | ✓ signed repositories | ◐ |
| license | MIT | GPL-2.0 | BSD-style | MIT (engine) | GPL-2.0 | GPL-3.0 |
| in use since | October 2026 | 2004 | the 2000s | 2020 | 2015 | about two decades, until 2025 |

| feature | pros (logguard) | cons (logguard), and who does better |
|---|---|---|
| **Footprint** | Fits a 1 GB VPS next to the services it protects. The memory limit is backed by flood tests, per-address state is capped (`max_tracked_ips`), and the apt simulation runs in a unit of its own, outside the limit. | – |
| **Platforms** | The static musl binary needs no matching libc: the same file runs on Debian 13 and Ubuntu 22.04. | x86_64 Linux with systemd only; the dpkg and apt checks need Debian or Ubuntu; no ARM build (Raspberry Pi, Graviton, Ampere). |
| **Supply chain** | Few dependencies, and `cargo audit` on every CI run. No TLS library in the binary: `curl` does the downloads. The parsers are fuzzed (cargo-fuzz, plus a smoke run in every `cargo test`). Log text never reaches a shell: firewall changes are built from parsed addresses and fed to `nft -f -`. That class of bug is real elsewhere: fail2ban's CVE-2021-32749 (the `mail-whois` action), Wazuh's CVE-2026-54085 (active response scripts, fixed in 4.14.7). Five internal security reviews in October 2026, each finding fixed with a test. | No independent third-party audit yet, and no distribution maintainers reviewing its packages. A project this young has no CVE history to judge it by. |

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
| sharing within your own servers | ●●○ | ○○○ | ○○○ | ●●● | ●●● | ●●○ | ●●● |
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

- **No HTTP layer:** no WAF, captcha or CDN integration.
- **Five built-in sources:** sshd, ejabberd, the kernel and UFW, Nextcloud AIO, su and sudo.
  Everything else needs regex patterns of your own.
- **One platform:** Linux on x86_64 with systemd and journald. The package and patch checks need
  dpkg and apt. No ARM build.
- **No web console, REST API or metrics export.** It has a TUI and a CLI on each node.
- **No crowd-sourced intelligence and no country blocking.** It has static public feeds only.
- **Host watches poll**, every minute or once a week; they don't see kernel events. There is no
  tamper protection against root.
- **No CVE matching, hardening benchmark or compliance reports.**
- **Three alert channels:** XMPP, Telegram and e-mail.
- **No distribution packages:** a release zip with `install.sh`.
- **Young:** version 0.2.0, running on the authors' own servers only, written by one maintainer
  in collaboration with an AI model (see the [README](README.md#authorship)). It has had internal
  security reviews, but no independent audit.
- **Covered by tests, not yet run on a host** (the README's
  [Not yet verified](logguard/README.md#not-yet-verified)): the iptables backend, bans after
  connection tracking, kernel tripwires and honeypots, su/sudo and new-SSH-key alerts, the
  package and set-uid check, the process watch, the patch status, ASN-DROP feeds, IPv6 subnet
  growth, patterns on a live journal, the Telegram relay node. Users' own warnings work in tests
  but have not yet been confirmed reaching a user.
- **Forged sources:** evidence that rests only on blocked packets can name a forged source.
  logguard limits the harm, but someone who forges packets can still get outsiders banned for
  an hour.

---

## 16. Evidence so far

**In production.** Two servers run in enforce mode: a VPN host (Ubuntu 22.04, kernel 5.15) and
an XMPP and Nextcloud server (Debian 13, kernel 6.12), the latter since mid-October 2026 after a
shadow-mode period. Verified there:

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
- the systemd watchdog.

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

- About 270 tests in logguard, and about 150 more in the bots.
- `tests/layouts.rs` runs the real daemon in each of the 10 supported layouts of bots and peers,
  end to end.
- The parsers are fuzzed.
- CI runs clippy with warnings as errors, `cargo audit`, and a static musl build for every
  commit.

---

## 17. Which tool for which situation

| if you ... | consider |
|---|---|
| run 1 to 10 self-hosted Linux VPS (SSH, XMPP, Nextcloud, WireGuard) and want one small tool with encrypted alerts and nothing sent to a vendor | **logguard** |
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

- **unattended-upgrades**, to install what logguard's patch status reports.
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

1. **Check the requirements:** Linux on x86_64, systemd, and one of nftables (recommended), ufw
   or iptables ([Requirements](logguard/README.md#requirements)).
2. **Download a release bundle** and verify its checksum and build provenance
   ([Install from a release bundle](logguard/README.md#install-from-a-release-bundle)).
3. **Install with a template:** `logguard.toml` for an XMPP server, `logguard-standalone.toml` for a
   host with SSH and UFW only, `logguard-tg.toml` for a Telegram relay node.
4. **Run in shadow mode** (the default) for one to two weeks: it decides, but bans nothing. Watch
   `logguard tui`, and look for "likely false positive" alerts. You can replay a week of your
   journal first:
   ```bash
   journalctl -u ssh -k --since -7d -o json > week.json && logguard -c /etc/logguard/logguard.toml replay week.json
   ```
5. **Enforce:** set `mode = "enforce"`, restart, and check `nft list table inet logguard`. To
   roll back, switch to shadow mode and delete the table
   ([Rollout](logguard/README.md#rollout)).
6. **Add more** when you want it: cluster peers, the bots, blocklist feeds, honeypot ports,
   patterns for your other services.

---

## 20. Method and sources

The logguard facts and numbers come from its READMEs and code at commit `48198d4`; the
measurements are the ones those READMEs report. The other tools were assessed from their
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
- logguard: [README](logguard/README.md), [repository README](README.md), and each bot's README
  ([XMPP](logguard-xmpp-bot/README.md), [Telegram](logguard-tg-bot/README.md),
  [mail](logguard-mail-bot/README.md))
