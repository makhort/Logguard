# logguard-web

A read-only web console for a logguard cluster: every node's bans, alerts, decisions,
offenders, countries and networks, cluster peers, certificates, disks, updates and integrity
checks on one HTTPS page, with what needs attention first, and every node's abuse report of the
last day or week, split per network owner and ready to mail. For one admin or a few, all equal.
`/metrics` gives the same in Prometheus' format for Grafana.

It **only reads**. Nothing in it can ban, unban, allow or change a setting: those stay on the
servers, over SSH, as `logguard unban …` and the TUI.

```
 every node                                              the console's node
 ┌────────────────────────────────────┐                  ┌──────────────────────────────────────────┐
 │ logguard ── console socket ──► agent│ ◄── TCP 7949 ───│ console ── HTTPS 7948 (TLS 1.3) ──► browser│
 │ (root)      read-only, 0660   logguard-web             logguard-web       password + one-time code │
 └────────────────────────────────────┘   request sealed │ + its own node's logguard (socket)        │
                                          with the web    └──────────────────────────────────────────┘
                                          key; reply under
                                          a fresh X25519 key
```

One binary, two roles, each switched on by a setting: the **agent** (`AGENT_LISTEN`, on every
node) hands its node's logguard data to the consoles; the **console** (`CONSOLE_LISTEN`, on the
node or nodes you choose) asks the agents in `NODES` and its own logguard, and serves the page.

## Contents

1. [Security design](#security-design)
2. [Setup](#setup)
3. [Settings (`/opt/logguard-web/config.env`)](#settings-optlogguard-webconfigenv)
4. [Commands](#commands)
5. [The page](#the-page)
6. [API](#api)
   - [Prometheus and Grafana](#prometheus-and-grafana)
7. [Files](#files)
8. [Install from a release bundle](#install-from-a-release-bundle)
9. [Install from a package](#install-from-a-package)
10. [Development](#development)
11. [Not yet verified](#not-yet-verified)

## Security design

**Its own key, never the cluster key.** logguard's cluster key lets its holder ban, unban,
allowlist and trust addresses on every node. A web console is the part of a system most exposed
to the network, so it must not hold that key: the agents and the console share a separate
**web key** (32 random bytes, `logguard-web keygen`), and a stolen web key reads status data,
nothing more. It cannot forge cluster facts, and the console can't ask an agent for anything but
reading (`snapshot`, `digest`, `abuse_24h`, `abuse_7d`). An agent says what it answers; the console
asks older agents for snapshots and digests only (an agent refuses a request it can't read, and
logguard bans an address that sends many of those).

**The agent protocol** (`src/wire.rs`), one request and one reply per TCP connection:

- The request is sealed with XChaCha20-Poly1305 under the web key (as the cluster's messages
  are), with its time (refused beyond 5 minutes of clock difference), a random id (refused if
  seen again) and a fresh X25519 public key.
- The reply is sealed under a key derived (HKDF-SHA-256) from a second fresh X25519 key and the
  console's, with the web key as salt and the request id and both public keys bound in. Only a
  holder of the web key can make or read it, it answers that one request only, and **once both
  fresh keys are gone nobody can read a recorded reply, even with the web key** (forward
  secrecy). The cluster's own link doesn't have that; snapshots name accounts and addresses.
- Frames are bounded (4 KB requests, 16 MB compressed replies, 64 MB uncompressed); an agent
  takes 8 connections at once, 2 per address, 10 seconds for a whole request, and only from
  `AGENT_ALLOW`. Memory follows what is kept: long lists (every active ban of a flood) are cut
  to their newest few thousand while parsing, their full lengths kept.

**The console:**

- **HTTPS, TLS 1.3 only** (rustls with ring), with a self-signed certificate made at install
  (compare its fingerprint with the browser's once) or a Let's Encrypt one (read again when it
  changes). Older clients (TLS 1.2 only) are refused.
- **Admins, two factors each:** `admin` and any others you add, all equal (no roles). Each has a
  password (Argon2id, `passwd [--user NAME]`) and a one-time code from an authenticator app (TOTP,
  RFC 6238, `totp-setup [--user NAME]` shows a QR code); each code works once, and only for its
  admin. `TOTP=off` leaves the passwords alone. Every attempt costs the same Argon2 check (one at a
  time), whichever factor is wrong and also for an account that doesn't exist, and the answer
  doesn't say which. Five failures from an address within 15 minutes lock it out for 15 minutes,
  and logguard bans it (below).
- **Sessions** live in memory (a restart ends them), named by a random 256-bit cookie
  `__Host-lgw` (Secure, HttpOnly, SameSite=Strict); 30 idle minutes or 12 hours end one, and so
  does removing its admin (`remove-admin`), at its next request. 8 per admin, 64 in all. An admin
  sees their own sessions (address, browser, times) and can end the others; after a login the page
  says when that admin last logged in, from where, and how many failed attempts at the account came
  since (kept in memory too: a restart forgets them, the journal keeps every login).
- **Read only**, and only for this site's pages: the API answers GET; login and logout take
  JSON (a form from another site can't send it) and check `Origin`; requests another site's page
  makes (`Origin`, `Sec-Fetch-Site`) are refused.
- **The page** is a few files compiled into the binary (`web/`: `app.js` the views, `dom.js`
  building and patching the page, `core.js` what it works out), no libraries, nothing from other
  hosts. `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; ...`,
  no inline script, no framing, `no-store`; `connect-src` adds RDAP's servers (rdap.org and the
  five registries) for the abuse-mailbox lookup below. Everything a node sends (log lines, account names, a
  peer's notices) goes into the page as text (`textContent`), never as HTML.
- **A small HTTP parser** of its own (`src/http.rs`): no chunked bodies, no proxy requests, no
  folded headers, one Host and one Content-Length, 16 KB of headers, 8 KB bodies; anything else is
  refused and the connection closed. 64 connections at once, 12 per address, 30 seconds per request.
  `CONSOLE_ALLOW` drops other addresses before TLS.

**Privilege separation.** logguard runs as root; logguard-web as its own system user, under a
sandboxed unit (`ProtectSystem=strict`, no capabilities, `MemoryDenyWriteExecute`, 128 MB at
most), writing nothing. It reaches logguard only through logguard's **console socket**
(`[console]` in logguard.toml): root's directory, mode 0750, group `logguard-web`, which answers
`snapshot`, `digest` and `abuse 24h` / `abuse 7d` and refuses every other command before the daemon
sees it. The control socket, the cluster key and logguard's state stay root's.

**What a break-in would give.** The console broken into: everything the page shows, read only;
the web key. An agent's node broken into: the web key, and with it the power to show the console
false data (what a node reports is displayed, never acted on: the console has nothing to act
with). Neither gives a ban, an unban or the cluster key.

**logguard watches it.** logguard-web writes to the journal: `login failed from <address>: …`
(with the account tried, if it can be one: nothing else a stranger types reaches the log),
`console: unknown path from <address>: GET /.env`, refused connections, agent requests without the
web key. With `[sources] apps = ["logguard-web"]` logguard scores them (25 points a failed login,
40 a probe for secrets, 20 a refused connection) and bans the address like any other attacker,
on every node through the cluster.

## Setup

On every node of the cluster (the console's too):

1. Install it (from a release bundle, below, or `./deploy/deploy.sh <host>` from a checkout). The
   first run puts `/opt/logguard-web/config.env` in place and creates the user `logguard-web`.
2. The **web key**, once, on one node, then the same file to every other node's
   `/opt/logguard-web/web.key`:
   ```bash
   /opt/logguard-web/logguard-web keygen --out /opt/logguard-web/web.key
   /opt/logguard-web/logguard-web key-id     # the same fingerprint on every node
   ```
3. logguard's console socket, in `/etc/logguard/logguard.toml`, then `systemctl restart logguard`:
   ```toml
   [console]
   socket = "/run/logguard-console/console.sock"
   group = "logguard-web"
   ```
   And in `[sources]`, `apps = ["logguard-web"]` (with your other apps) to ban password guessers.
4. In `config.env`: `AGENT_LISTEN=0.0.0.0:7949`, and `AGENT_ALLOW` the console node's address.
   Open the port to that address only:
   `ufw allow from 203.0.113.10 to any port 7949 proto tcp` (firewalld:
   `firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 source address=203.0.113.10 port port=7949 protocol=tcp accept'`).
   The console's own node needs no agent: the console reads that node's logguard through
   `LOGGUARD_SOCKET`, so `AGENT_LISTEN` stays empty there and 7949 needs no rule.

On the console's node, also:

5. In `config.env`: `CONSOLE_LISTEN`, and `NODES` the other nodes' agents
   (`vpn.example.org:7949, 198.51.100.20:7949`). Either:
   - `CONSOLE_LISTEN=127.0.0.1:7948`, reached through SSH:
     `ssh -L 7948:127.0.0.1:7948 <host>`, then `https://127.0.0.1:7948` (a hardened SSH gateway
     needs `PermitOpen 127.0.0.1:7948` for its user); or
   - `CONSOLE_LISTEN=0.0.0.0:7948` with `CONSOLE_ALLOW` the networks you work from, and the port
     opened to them in the firewall. logguard's exposure watch reports the new listener once.
6. The admin's login:
   ```bash
   /opt/logguard-web/logguard-web passwd        # asked twice, not shown; 12 characters at least
   /opt/logguard-web/logguard-web totp-setup    # scan the QR code with Aegis, 2FAS, FreeOTP, ...
   ```
   More admins, the same way, each with their own password and codes (they log in with their name
   in "Account"; `admin` is the default):
   ```bash
   /opt/logguard-web/logguard-web passwd --user alice
   /opt/logguard-web/logguard-web totp-setup --user alice   # alice scans it with her own app
   /opt/logguard-web/logguard-web admins                    # who can log in
   /opt/logguard-web/logguard-web remove-admin alice        # her sessions end at once
   ```
   No restart needed: the console reads the files at each login.
7. `bash /opt/logguard-web/install.sh` again (a package install: `dpkg-reconfigure logguard-web`, or
   `dnf reinstall` the rpm; it starts nothing, so finish with `systemctl enable --now logguard-web`): it sets the files' owners and modes, makes the
   self-signed certificate if there is none, and starts the service once nothing is missing
   (until then it lists what is). Check it:
   ```bash
   /opt/logguard-web/logguard-web check     # reads config.env itself, as the unit does
   ```
   `check` reads every file and asks this node's logguard and every agent in `NODES` once.
8. Open the console. The browser warns about the self-signed certificate once: compare the
   SHA-256 fingerprint it shows with `logguard-web fingerprint` (install.sh prints it too) before
   you accept it.

**A console without logguard** (a host that only aggregates the nodes and serves the page):
`LOGGUARD_SOCKET=`, `CONSOLE_LISTEN` and `NODES`, no agent, and skip step 3. Every node shown is
then an agent's. One thing is missing there: with no logguard on that host, nothing bans password
guessers at its console from the journal; the lockout above still applies, so keep `CONSOLE_ALLOW`
narrow (or the console on 127.0.0.1 behind SSH). Two consoles: both in each agent's
`AGENT_ALLOW`. A node without the console: `CONSOLE_LISTEN=` (the default).

## Settings (`/opt/logguard-web/config.env`)

| variable | default | meaning |
|---|---|---|
| `NODE_NAME` | logguard's `[cluster] node_id`, else the host name | this node's name in the console |
| `LOGGUARD_SOCKET` | `/run/logguard-console/console.sock` | logguard's `[console] socket`; empty without logguard |
| `WEB_KEY_FILE` | `/opt/logguard-web/web.key` | the web key, the same on every node |
| `AGENT_LISTEN` | empty (no agent) | where the consoles ask for this node's data, e.g. `0.0.0.0:7949` |
| `AGENT_ALLOW` | required with an agent | the consoles' addresses or networks; `any`: the web key alone decides |
| `CONSOLE_LISTEN` | empty (no console) | where the console serves HTTPS, e.g. `127.0.0.1:7948` |
| `CONSOLE_ALLOW` | empty: every address | addresses or networks that may reach the login page |
| `NODES` | empty | the other nodes' agents, `host:port`, separated by commas or blanks |
| `TLS_CERT`, `TLS_KEY` | `/opt/logguard-web/tls.crt`, `tls.key` | PEM certificate chain and key; read again when they change |
| `RDAP_LOOKUPS` | `on` | the console looks up abuse mailboxes (rdap.org, HTTPS with the system's CA bundle) when an admin asks; `off`, or when it can't get out, the admin's browser asks rdap.org itself |
| `PASSWORD_FILE` | `/opt/logguard-web/admin.password` | `admin`'s Argon2id hash (`passwd`) |
| `TOTP`, `TOTP_FILE` | `on`, `/opt/logguard-web/admin.totp` | one-time codes for every admin (`off`: passwords only); `admin`'s secret (`totp-setup`) |
| `ADMINS_DIR` | `/opt/logguard-web/admins` | the other admins: `<name>.password`, `<name>.totp` (`passwd --user`, `totp-setup --user`) |
| `METRICS_TOKEN_FILE` | unset | a token that reads `/metrics` without a login (Prometheus) |
| `REFRESH_SECS` | 10 | how old the nodes' data may get while a page is open |
| `SESSION_IDLE_MINUTES`, `SESSION_MAX_HOURS` | 30, 12 | when a session ends |

The console asks the nodes only while someone looks (a page open, a Prometheus scrape): an
idle console sends nothing. A slow node's answer shows with the next refresh; one that doesn't
answer shows as down, with the reason and its last data, and is asked less and less often (twice
the wait after each failure, up to a minute) until it answers again. The page asks for what its
tab shows (`/api/v1/cluster?only=...`), not the whole cluster document every time.

## Commands

```
logguard-web                  run (the unit does)
logguard-web check            settings, files, this node's logguard and every agent, once
logguard-web keygen [--out F] a new web key (or metrics token); F mode 0640, never overwritten
logguard-web key-id           the web key's fingerprint
logguard-web gen-cert --name console.example.org --name 203.0.113.10 [--force]
logguard-web fingerprint      the certificate's SHA-256 fingerprint, as browsers show it
logguard-web passwd [--user NAME] [--stdin]       an admin's password (a new NAME: a new admin)
logguard-web totp-setup [--user NAME] [--force]   their one-time codes' secret, as a QR code
logguard-web admins                               the admins, and whether each can log in
logguard-web remove-admin NAME                    remove one (not admin): files gone, sessions end
```

## The page

- **Overview:** nodes up, active bans (and how many distinct addresses), bans and events in the
  last hour, alerts in 24 hours, tracked addresses; **Needs attention** (a node without data, a
  failing cluster peer, differing cluster keys, shadow mode, a certificate running out, a full
  disk, security updates, infected files, changed package files, feed errors...); events and
  bans per minute over three hours, per node (also as a table); a card per node.
- **Alerts, Activity** (every decision), **Bans** (per node, or one row per address with the
  nodes that ban it), **Offenders** (scores, evidence, accounts with failed logins), **World**
  (countries, networks and ports, all nodes added up; pick a country, or search for one, and the
  networks and ports are that country's): filters, sorting, details on click.
- **Map:** the TUI's map, drawn properly. Countries from Natural Earth (public domain) in the Equal
  Earth projection, the whole world or Europe. ▲ at each country's capital, sized by its active
  bans, offenders or events (the geo databases name only the country, so a capital is as precise
  as it gets); ● where addresses logged in during the last hour; countries `[geoblock]` blocks
  hatched, with the nodes that block them and whether it is in force. Hover for the figures; a
  click opens the country on World. `web/world.json` is made by `scripts/world-map.py`.
- **An address's page** (`#/address/<address or network>`; every address or network shown is a
  link, also inside log lines and messages): the bans covering it on every node, its scores, the
  decisions and alerts naming it, whether a node trusts or allows it, its entry in the last week's
  abuse report, and who runs its network (RDAP).
- **Abuse:** every node's abuse report merged, for the last 24 hours or the last 7 days (each
  button shows how many networks it has), one row per network owner (by AS number, else by name):
  its countries, sources, bans, log lines, the nodes that banned them and when last seen. A click
  opens its sources: what each did, in the words of the weekly report, and its first log lines
  marked with the node they hit. **Copy** puts that network's part on the clipboard as an e-mail
  to its abuse desk ("Hello, the following addresses in your network ... attacked our servers"),
  **.txt** saves it as a file, **Mail** looks up the network's abuse mailbox (RDAP) and opens the
  e-mail in your mail program, addressed and with a subject (a report too long for a mail link goes
  in part, the rest saved as a .txt to attach). The text names the attacked servers by their public
  address, never by the nodes' names. The mailbox lookup: the console asks rdap.org (one a second,
  kept a day, following a registry's redirects only to public host names); if it can't (`RDAP_LOOKUPS=off`, no way out from its host) the page asks rdap.org
  itself, which then learns the address asked about and the admin's address. Only plain e-mail
  addresses are taken from RDAP (the network's owner writes it, and may be the attacker). **Mark
  mailed** remembers a network as reported (in this browser), shown on its row; "Hide those already
  mailed" leaves out its sources for 30 days. **CSV**: one line per source. Sources with fewer than
  3 log lines are left out unless you ask, as in the weekly report. Each node builds its report from its actions log when asked (logguard keeps
  it a minute, the console too); the page asks again every 5 minutes or on "Again".
- **A node's page:** logguard's mode and figures, log sources, the cluster as that node sees it
  (peers, facts, key), certificates, disk and memory, updates, cron, antivirus and package checks,
  listening services, blocklists, the allowlists, patterns, today's digest so far, that node's
  abuse report (as on Abuse), and its whole snapshot as JSON.

- **Overview** also has the activity charts over 3 hours (per minute), 24 hours or 7 days (per
  hour, from logguard's hourly figures since its start), and **Nodes side by side**: each node's
  logguard and logguard-web versions, mode, firewall, thresholds, cluster key and which watches are
  on, the cells that differ from most nodes marked.
- **Your account** (your name in the header): this session, the login before it, your sessions
  with "Log out the others", and this browser's settings.
- **Every table** of the Alerts, Activity, Bans and Offenders tabs exports as CSV or JSON (the rows
  as filtered, all of them). CSV cells that would start a spreadsheet formula (`=`, `+`, `-`, `@`)
  get a `'` first: log lines and network names come from strangers.

The page refreshes in place: only what changed is redrawn, so the scroll position, rows opened,
text selected and the focus stay, and charts and the map are redrawn only when their data
changes. While text in the page is selected, refreshes wait ("held" in the header) so it can be
copied. A tab left in the background asks again when shown; data older than three refreshes shows
in red in the header; the tab's title counts what needs attention (high or critical). Filters and
settings (not searches) are remembered in the browser. `/` jumps to the page's search box.
A tab's filters are in its address (`#/alerts?level=high&q=ssh`), so a link shows another admin
the same. 🔔 in the header turns on browser notifications of new critical problems while a console
tab is open; ◐ picks light, dark or the system's colours. On a phone, tables turn into cards.

## API

JSON over HTTPS, GET, with the session cookie (log in with `POST /api/login`
`{"user": "admin", "password": "...", "code": "123456"}`, `Content-Type: application/json`;
without `user`: admin).

| path | |
|---|---|
| `/api/v1/session` | `{"logged_in": …, "user": …, "totp": …, "node": …}` (needs no session) |
| `/world.json` | the Map tab's countries and capitals (public data, needs no session) |
| `/api/v1/cluster` | everything below in one document; `?only=alerts,history` only those parts (and `nodes`, `totals`, `attention`, `refresh_secs`) |
| `/api/v1/overview` | `nodes`, `totals`, `attention` |
| `/api/v1/{attention,alerts,actions,bans,offenders,accounts,world,history,nodes}` | one part; list entries carry `node` and `node_id`; `world` also has `by_country` (each country's networks and ports), `geoblock` (what each node blocks) and `port_names` |
| `/api/v1/nodes/<id>` | one node: its summary, what needs attention, its whole snapshot (`_cut` gives the full length of lists cut short) |
| `/api/v1/nodes/<id>/digest` | `{"text": …}`: that node's digest so far |
| `/api/v1/abuse/{24h,7d}` | every node's abuse report merged: `nodes` (each with `sources`, or `error`), `sources`, `providers` (`key`, `asn`, `name`, `countries`, `bans`, `events`, `first`, `last`, `nodes`, `sources` with `activity`, `evidence`, `omitted`, `members`) |
| `/api/v1/nodes/<id>/abuse/{24h,7d}` | the same for one node |
| `/api/v1/address/<address or network>` | `bans`, `actions`, `offenders`, `trusted`, `allowed` naming it or overlapping it, each with its node |
| `/api/v1/rdap/<address>` | `{"abuse": [...], "network": ...}`; 502 with `"fallback": true` when the console can't look up |
| `/api/v1/sessions` | this admin's sessions; `POST /api/v1/sessions/end-others` ends the others |
| `/metrics` | Prometheus' text format |

Times are microseconds since 1970 (UTC), as in logguard. Node ids are `0` for this node and
`1`, `2`, ... for the entries of `NODES`.

### Prometheus and Grafana

```bash
/opt/logguard-web/logguard-web keygen --out /opt/logguard-web/metrics.token   # then METRICS_TOKEN_FILE=... and restart
```

```yaml
scrape_configs:
  - job_name: logguard
    scheme: https
    scrape_interval: 60s
    authorization: { credentials_file: /etc/prometheus/logguard.token }
    tls_config: { ca_file: /etc/prometheus/logguard-web.crt }   # the self-signed certificate
    static_configs: [{ targets: ["console.example.org:7948"] }]
```

Everything the console shows, per node (`node` label), in about 110 families:

| area | series |
|---|---|
| the console's view | `logguard_up`, `logguard_data_age_seconds`, `logguard_fetch_duration_seconds`, `logguard_web_agent_info{version}`, `logguard_attention{level}` (the overview's "needs attention", for alert rules) |
| logguard | `logguard_info{mode,backend}`, `logguard_enforcing`, `logguard_started_timestamp_seconds`, `logguard_snapshot_timestamp_seconds`, `logguard_tracked_addresses`, `logguard_tracked_connections`, `logguard_ban_threshold{window}`, `logguard_offenders`, `logguard_last_line_timestamp_seconds{source}` |
| bans, alerts, events | `logguard_active_bans{origin,kind}` (every ban counted: `origin` local or the peer that decided it, `kind` address or network), `logguard_bans_total`, `logguard_alerts_total`, `logguard_bans_last_hour`, `logguard_events_last_hour`, `logguard_alerts_last_day{severity}`, `logguard_records_total{source}`, `logguard_events_total{signal}`, `logguard_unattributed_lines_total`, `logguard_hidden_addresses_total` |
| accounts and trust | `logguard_accounts_with_failures`, `logguard_accounts_under_attack`, `logguard_trusted_addresses`, `logguard_operator_allowlist_entries` |
| places | `logguard_country_{active_bans,offenders,events}{country}`, `logguard_network_{active_bans,offenders,events}{asn,name,country}`, `logguard_port_events{port}`, `logguard_logged_in_addresses{country}`, `logguard_offenders_unlocated` |
| blocking | `logguard_geoblock_networks{family}`, `logguard_geoblock_applied`, `logguard_geoblock_error`, `logguard_geoblock_asns`, `logguard_geoblock_country{country,list}`, `logguard_feed_networks{family}`, `logguard_feed_applied`, `logguard_feed_error`, `logguard_feed_refreshed_timestamp_seconds`, `logguard_feed_skipped_entries`, `logguard_feed_asns`, `logguard_feed_source_{entries,error}{url}` |
| cluster | `logguard_cluster_info{node_id,key_id}`, `logguard_cluster_key_installed_timestamp_seconds`, `logguard_cluster_rotation_keys`, `logguard_cluster_peer_up{peer}`, `logguard_cluster_peer_last_ok_timestamp_seconds{peer}`, `logguard_cluster_peer_failing_since_timestamp_seconds{peer}`, `logguard_cluster_heard_from_timestamp_seconds{from}`, `logguard_cluster_facts_known`, `logguard_cluster_facts_{received,sent}_total`, `logguard_cluster_rejected_total`, `logguard_cluster_refused_by_limit_total` |
| host | `logguard_cert_{expiry,start,checked}_timestamp_seconds{target}`, `logguard_cert_error{target}`, `logguard_cert_wrong_name{target}`, `logguard_disk_{size,available}_bytes{mount}`, `logguard_disk_free_ratio{mount}`, `logguard_memory_{total,available}_bytes`, `logguard_memory_available_ratio`, `logguard_swap_{total,free}_bytes`, `logguard_memory_pressure_ratio{kind}`, `logguard_updates_pending`, `logguard_security_updates`, `logguard_reboot_required`, `logguard_kernel_outdated`, `logguard_processes_using_replaced_files`, `logguard_updates_checked_timestamp_seconds` |
| integrity | `logguard_av_{infected_files,scanned_files,errors}`, `logguard_av_signatures_outdated`, `logguard_av_scan_completed`, `logguard_av_last_scan_timestamp_seconds`, `logguard_verify_{checked_files,mismatched_files,setuid_programs}`, `logguard_verify_last_run_timestamp_seconds`, `logguard_cron_{tasks,scripts,files,errors}`, `logguard_cron_scanned_timestamp_seconds`, `logguard_procwatch_{pairs,outbound}` |
| exposure | `logguard_listeners{exposure}`, `logguard_public_listener{proto,port,process}`, `logguard_firewall_dead_rules`, `logguard_ufw_active` |
| patterns | `logguard_pattern_{lines,matches,unaddressed}_total{pattern,kind}`, `logguard_pattern_addresses{pattern,kind}` |
| the console | `logguard_web_logins_total{result}` (ok, failed, locked_out), `logguard_web_sessions`, `logguard_web_nodes` |

No series names an attacker's address or an account (personal data, and unbounded); countries,
networks, ports, peers and the rest are bounded by logguard's own caps. A family appears when the
node has that part (`[feeds]`, `[antivirus]`, ... switched on). Rules to start from:
`logguard_up == 0`, `logguard_attention{level=~"critical|high"} > 0`,
`logguard_cluster_peer_up == 0`, `increase(logguard_web_logins_total{result="failed"}[15m]) > 3`,
`logguard_cert_expiry_timestamp_seconds - time() < 7 * 86400`.

## Files

| path | owner, mode | |
|---|---|---|
| `/opt/logguard-web/logguard-web` | root 0755 | the binary (`.prev`: the rollback one) |
| `/opt/logguard-web/config.env` | root:logguard-web 0640 | settings |
| `/opt/logguard-web/web.key` | root:logguard-web 0640 | the web key |
| `/opt/logguard-web/tls.crt`, `tls.key` | 0644, root:logguard-web 0640 | the console's certificate |
| `/opt/logguard-web/admin.password`, `admin.totp` | root:logguard-web 0640 | `admin`'s login |
| `/opt/logguard-web/admins/` | root:logguard-web 0750, files 0640 | the other admins' logins |
| `/etc/systemd/system/logguard-web.service` | root 0644 | the unit |
| `/run/logguard-console/console.sock` | root:logguard-web 0660 | logguard's console socket (logguard makes it) |

Logs: `journalctl -u logguard-web`.

## Install from a release bundle

Every version tag `logguard-web-v<version>` gets its bundle, `logguard-web-<version>-<commit>-<arch>.zip`
for each architecture (`x86_64-linux-musl`, `aarch64-linux-musl` for arm64,
`armv7-linux-musleabihf` for 32-bit ARMv7), as an asset of the tag's GitHub Release (see
"Releases" in the [repository README](../README.md#deployment)). Take the one for the server's
architecture (`uname -m`) and check it:

```bash
arch=x86_64-linux-musl     # the server's: aarch64-linux-musl (arm64), armv7-linux-musleabihf (32-bit ARM)
gh release download logguard-web-v0.2.0 --repo makhort/Logguard --pattern "*-$arch.zip*"   # the zip, its .sha256 and .sigstore.json
sha256sum -c logguard-web-*-$arch.zip.sha256          # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify logguard-web-*-$arch.zip --repo makhort/Logguard --source-ref refs/tags/logguard-web-v0.2.0
```

Then on the server:

```bash
unzip logguard-web-*-$arch.zip && cd logguard-web-*-$arch
sudo ./install.sh            # or as root; again after editing config.env
sudo ./install.sh rollback   # back to the previous version
```

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `logguard-web_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) and `logguard-web-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"` or `"*.rpm*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once; neither needs dpkg or rpm, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). The package is for one host at a time: there is no apt or dnf repository.

```bash
sudo apt install ./logguard-web_0.2.0-1_amd64.deb     # Fedora, RHEL:  sudo dnf install ./logguard-web-0.2.0-1.x86_64.rpm
sudoedit /opt/logguard-web/config.env                 # the first install put the template there; then the keys, password, codes ("Setup")
sudo dpkg-reconfigure logguard-web                    # rpm: sudo dnf reinstall ./logguard-web-*.rpm  (step 7: owners, modes, the certificate)
/opt/logguard-web/logguard-web check && sudo systemctl enable --now logguard-web
```

The package puts the same files in the same places as `install.sh` (`/opt/logguard-web` with the binary and `config.env.example`, the user `logguard-web`), except the unit, which is in `/usr/lib/systemd/system`. Its post-install step does what `install.sh` does apart from copying files: the user, `config.env` from the template the first time, the owners and modes, the self-signed certificate once `CONSOLE_LISTEN` is set; and it lists what is still missing (the to-do list of "Setup"). `dpkg-reconfigure logguard-web` (rpm: `dnf reinstall`) runs that step again, as "`bash install.sh` again" does for the bundle. `apt remove logguard-web` (`dnf remove`) stops the service and keeps `/opt/logguard-web`; `apt purge` removes it with the keys, password and certificate (rpm: by hand).

**Nothing starts on its own.** The first install puts the template in place and prints what to fill in; you enable the service once it is filled in. An upgrade keeps the config and restarts the service only if it was running and the config is filled in. **Over a bundle or `deploy.sh` install** the package takes over: the config, state and keys stay; the bundle's unit in `/etc/systemd/system` (it would shadow the package's) and its rollback files go, and the service is enabled again on the package's unit if it was (logguard's integrity watch reports the removed unit as a warning once). **Replacing the config:** when a terminal is there, the install asks whether to replace the config with the new template (the old one kept with the suffix `.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `LOGGUARD_PACKAGE_CONFIG=replace` (or `keep`) answers without asking: `sudo LOGGUARD_PACKAGE_CONFIG=replace apt install ./<file>.deb`. **Rollback** is installing the previous version's package (`apt install ./<old>.deb --allow-downgrades`, `dnf downgrade ./<old>.rpm`): there is no `.prev` file.

## Development

```bash
./scripts/ci.sh              # fmt, clippy -D warnings, tests, cargo audit, static musl build
./deploy/deploy.sh <host>    # ci.sh, then the files over SFTP and the command for a root shell
```

`node --test web/tests/` (in `ci.sh` when Node is installed) tests the page's patching against a
small fake DOM, and the abuse e-mail, mail links, RDAP parsing, CSV, address links and link
filters. `tests/end_to_end.rs` runs an agent and a console against a fake logguard socket and logs in
over TLS like a browser (it listens on 127.0.0.1 and a Unix socket). The fuzz targets in
`fuzz/` (`cargo +nightly fuzz run http_request`, `agent_request`, `snapshot`, `abuse_report`) cover what strangers
and key holders send; `tests/fuzz_smoke.rs` runs them over their seeds on stable.

## Not yet verified

New on 2026-10-26: covered by the tests above and a run on the Mac against snapshots made from
real decision logs, through real TLS and the agent protocol; the page looked at in a browser
through a plain-HTTP preview (with the console's API behind it), in light and dark, at desktop and
phone width. Not yet run on a server: the unit's sandboxing, logguard's real console socket,
`install.sh`, a browser trusting the self-signed certificate, a Let's Encrypt certificate's
reload, Prometheus scraping it, and the ARM builds.

New on 2026-10-28: abuse reports (built by logguard from a copy of real actions logs, merged from
two fake nodes through a real agent), per-provider Copy and .txt, several admins (also against a
console without logguard), the in-place refresh and the rest of the page's changes, all on the Mac
as above. Not yet on a server: logguard building a week's report under its unit's memory limit,
agents of mixed versions, and a second admin's authenticator app.

Later on 2026-10-28: the address page, Mail with RDAP (the console's lookup and the browser's
fallback both asked rdap.org for real addresses from the Mac), mailed marks, CSV/JSON exports,
links with filters, sessions, the 7-day charts, the table of differences, the phone layout and the
theme, in the same setup. Not yet: a mail program opened by Mail (the link was checked in tests),
browser notifications firing, RDAP from a server's sandboxed unit.
