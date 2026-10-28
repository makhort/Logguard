# Testing logguard on Fedora (Fedora Cloud on a VPS)

A first run of what is new for Fedora and RHEL, none of which has run on a real host yet:
`package_manager = "dnf"` (rpm package checks, dnf patch status), the `-dnf` config templates,
the **firewalld** backend, firewalld's denied-packet log lines, the exposure watch reading
firewalld's zones, the optional **ipset** backend, and on an arm64 VPS the **aarch64** build.

Each step says what to run and what you should see. Note what differs (paste the output) and
send it back: that is the test result.

**Placeholders:** `VPS_IP` is the server's public address, `ADMIN_IP` the address you connect
from (`curl -s https://ifconfig.me` on your machine), `PROBE_IP` the probe's (the same command
there), `SSH_PORT` the server's SSH port (22 unless
you changed it). Commands run on the VPS as root (`sudo -i`) unless they say "on the Mac" or
"on the probe".

**You need:**
- the VPS, with your SSH key, and the provider's web console in case you lock yourself out;
- a **probe**: a second machine with another public address that never logs in to the VPS (a
  phone hotspot, or another VPS). It plays the attacker. Your own address is allowlisted, so
  it can't.
- about 2 hours, mostly waiting (the package check starts 15 minutes after logguard).

Shortcut used below:

```bash
lg() { logguard -c /etc/logguard/logguard.toml "$@"; }
```

## 1. Prepare the VPS

1. Note the system:
   ```bash
   cat /etc/fedora-release; uname -m; getenforce
   ```
   `uname -m` picks the bundle: `x86_64`, or `aarch64` (arm64). SELinux is `Enforcing` on stock
   Fedora (keep it); some providers' images disable it: note which.

2. Fedora Cloud images come **without firewalld**. Install it, open SSH *before* starting it,
   and have it log what it refuses (logguard reads those lines):
   ```bash
   dnf install -y firewalld unzip
   firewall-offline-cmd --add-service=ssh                 # port 22
   firewall-offline-cmd --add-port=SSH_PORT/tcp           # only if SSH isn't on 22
   systemctl enable --now firewalld
   firewall-cmd --set-log-denied=unicast
   firewall-cmd --state; firewall-cmd --get-default-zone; firewall-cmd --list-all
   ```
   Expect `running`, `public`, and `ssh` among the services. **Open a second SSH session now**
   and keep it open until the end: it survives a firewall mistake.

3. dnf's metadata cache (the patch status reads only what is cached, like dnf-makecache.timer leaves it):
   ```bash
   dnf makecache
   systemctl is-enabled dnf-makecache.timer
   ```

4. Time (cluster and journal timestamps need it): `timedatectl` should say `System clock synchronized: yes`.

## 2. Build and copy the bundle (on the Mac)

```bash
cd ~/DomainAndServer/log_analysis_final_rewrite/logguard
git status --short                       # empty: the bundle takes only committed files
./scripts/bundle.sh                                      # x86_64 VPS
./scripts/bundle.sh --target aarch64-unknown-linux-musl  # arm64 VPS (instead)
scp target/bundle/logguard-*-<arch>.zip fedora@VPS_IP:   # <arch>: x86_64-linux-musl or aarch64-linux-musl
```

(Fedora Cloud's user is `fedora`; use yours if the provider made another.)

(Or the package instead of the bundle: `./scripts/package.sh` (`--target aarch64-unknown-linux-musl`
for arm64) writes `target/package/logguard-0.4.0-1.<arch>.rpm`; `scp` it over and on the VPS
`dnf install ./logguard-0.4.0-1.<arch>.rpm`, then `cp /usr/share/logguard/templates/logguard-standalone-dnf.toml
/etc/logguard/logguard.toml` instead of `install.sh --template`, and `systemctl enable --now logguard
logguard-abuse-report.timer` instead of the second `install.sh`. logguard is then `/usr/bin/logguard`;
the steps below read the same otherwise.)

## 3. Install in shadow mode

```bash
cd ~fedora && unzip -q logguard-*.zip && cd logguard-*-linux-musl
./install.sh --check                                  # Bundle OK: logguard 0.4.0 (...)
cat TARGET                                            # the architecture it was built for
./install.sh --template logguard-standalone-dnf.toml
```

Expect: *New server: /etc/logguard/logguard.toml is the template logguard-standalone-dnf.toml now*.

**Edit the config** before installing (`sudoedit /etc/logguard/logguard.toml`): the template is
the VPN host's, with its addresses and ports.

| where | change to |
|---|---|
| top | `package_manager = "dnf"` stays; `mode = "shadow"` stays for now |
| `[ports]` | `whitelist = []`, `names = {}` (no WireGuard here) |
| `[[ratelimit]]` | the SSH one: `ports = ["SSH_PORT/tcp"]`; delete the WireGuard block, all four lines (one without ports is refused) |
| `[allowlist] nets` | replace `11.48.43.31` with `"ADMIN_IP",`: **your own address, never banned**. Without it, enforce mode can lock you out (keep `127.0.0.0/8` and `::1`) |
| `[cluster]` | `enabled = false` |
| `[verify]` | add `interval = "1h"` (a second pass within the test; 7 days by default; 1h is the shortest: a shorter one stops logguard from starting) |

Then:

```bash
files/logguard --config /etc/logguard/logguard.toml print-config > /dev/null && echo config ok   # the bundle's binary: not installed yet
./install.sh
```

Expect, in install.sh's output: *Config OK*, *nftables ruleset OK (dry run)*, no NOTE about
firewalld's denied packets (step 1.2 turned it on), and at the end the service running.

```bash
systemctl is-active logguard
journalctl -u logguard -b | grep 'logguard: started'
```

Expect `active`, and `mode=Shadow backend=shadow` (shadow mode applies nothing yet).

**Check the installer's choice of template** (a quick side test): `ls configs/` shows three
`-dnf` files; `grep ^package_manager configs/*.toml` shows `dnf` in exactly those.

## 4. Shadow mode: what logguard reads

Give it 3 minutes, then:

```bash
lg status
```

Note the whole output. Check in it:

1. **Exposure (firewalld's zones):** the firewall line says `firewalld running`, not
   `nftables, rules not read`. sshd is `allowed by firewalld` with `[ALLOW ssh (public)]`
   (or `[ALLOW SSH_PORT/tcp (public)]`).
2. **Patch status (dnf):** a patches line: `up to date`, `N updates pending, none for security`,
   or what needs doing (`N security updates pending (...): dnf upgrade`, a newer kernel than the
   running one, programs still running replaced code), then `N other updates pending`. Compare with
   `dnf --cacheonly --quiet check-update --security`. An error here (e.g.
   `dnf check-update: ...`) is a finding: paste it.
3. **Firewall signals:** a public VPS gets scanned within minutes. Check firewalld logs them,
   and logguard counts them:
   ```bash
   journalctl -k -g 'filter_IN_public_REJECT' -n 3 --no-pager
   journalctl -u logguard -b | grep '\[shadow\]' | tail -n 5
   ```
   Expect kernel lines `filter_IN_public_REJECT: IN=eth0 OUT= ... SRC=...`, and after a while
   would-be bans of scanners, tagged `[shadow]` (also in `/var/log/logguard/actions.jsonl`).

**Exposure, step by step** (python3 comes with Fedora):

`lg status` lists only exposed listeners; the TUI's Exposure tab (`lg tui`, key `6`, `q` to
quit) lists all of them, blocked ones too.

```bash
python3 -m http.server 8080 --bind 0.0.0.0 > /dev/null 2>&1 &
sleep 70; lg status | grep 8080            # nothing: not exposed
lg tui                                     # tab 6: 0.0.0.0:8080/tcp  python3  blocked by firewalld
firewall-cmd --add-port=8080/tcp
```

firewalld's zones are re-read every 5 minutes (sooner when a file in /etc/firewalld changes;
this runtime change touches none), so:

```bash
sleep 300; lg status | grep 8080           # 0.0.0.0:8080/tcp  python3  allowed by firewalld [ALLOW 8080/tcp (public)]
kill %1
sleep 70; lg status | grep -i dead         # dead firewalld rule: 8080/tcp (public) (nothing listens)
firewall-cmd --remove-port=8080/tcp
```

A source-only rule:

```bash
firewall-cmd --add-rich-rule='rule family="ipv4" source address="ADMIN_IP" port port="8081" protocol="tcp" accept'
python3 -m http.server 8081 --bind 0.0.0.0 > /dev/null 2>&1 &
sleep 360; lg tui                          # tab 6: 8081 allowed by firewalld from some sources only,
                                           # rule "ALLOW rich rule 8081/tcp (public) from ADMIN_IP"
kill %1
firewall-cmd --remove-rich-rule='rule family="ipv4" source address="ADMIN_IP" port port="8081" protocol="tcp" accept'
```

**Package origins (rpm):**

```bash
lg integrity | head -40
```

Expect watched files with their rpm package (`package pam` for `/etc/pam.d/*`,
`package openssh-server` for `sshd_config`), and files of your own
(e.g. `/etc/sudoers.d/90-cloud-init-users`, if your image has it) as `local`. Then a modified one:

```bash
cp -a /etc/pam.d/sudo /root/pam-sudo.bak
echo '# logguard test' >> /etc/pam.d/sudo
lg integrity | grep pam.d/sudo             # package sudo, MODIFIED
cp -a /root/pam-sudo.bak /etc/pam.d/sudo
```

## 5. Enforce with the firewalld backend

First check your own address is allowlisted: `grep -A3 '^nets' /etc/logguard/logguard.toml`
must show `ADMIN_IP`. Then edit the config: `mode = "enforce"`, and in `[enforce]`
`backend = "firewalld"`. Then:

```bash
systemctl restart logguard
journalctl -u logguard -b | grep -E 'started|firewalld' | tail -n 5
```

Expect `mode=Enforce backend=firewalld`, and no *firewalld unavailable* line. The first start
reloads firewalld once (it creates logguard's ipsets and zone in firewalld's permanent
configuration). Your second SSH session must still be alive.

**logguard's firewalld objects:**

```bash
firewall-cmd --get-ipsets                         # logguard-alive logguard-ban4 logguard-ban6
firewall-cmd --info-zone=logguard                 # target: DROP, sources: ipset:logguard-ban4 ipset:logguard-ban6
firewall-cmd --info-policy=logguard-fwd           # ingress-zones: logguard, egress-zones: ANY, target: DROP
firewall-cmd --ipset=logguard-alive --get-entries # 192.0.2.1
firewall-cmd --permanent --list-all --zone=public # unchanged by logguard
```

**An operator ban** of the probe (documentation addresses like 192.0.2.x are refused: logguard
never bans non-routable addresses):

```bash
lg ban PROBE_IP --for 10m --note test
firewall-cmd --ipset=logguard-ban4 --get-entries  # PROBE_IP (plus any bans logguard decided)
```

On the probe, `nc -vz -w 3 VPS_IP 22` now times out. Then:

```bash
lg unban PROBE_IP
firewall-cmd --ipset=logguard-ban4 --get-entries  # PROBE_IP gone; the probe connects again
```

**A real ban, from the probe** (on the probe, which has never logged in):

```bash
nc -vz -w 3 VPS_IP 22      # on the probe: succeeds (or "open") before
nc -vz -w 3 VPS_IP 23      # on the probe: a tripwire port; refused or times out
sleep 5
nc -vz -w 3 VPS_IP 22      # on the probe: now times out: banned
```

On the VPS:

```bash
tail -n 3 /var/log/logguard/actions.jsonl          # a ban of the probe's address, tripwire 23/tcp
firewall-cmd --ipset=logguard-ban4 --get-entries   # the probe's address
journalctl -k -g filter_IN_logguard -n 3 --no-pager  # (only if logged) these are not counted again
```

(If the probe's first `nc ... 22` was itself refused, sshd listens elsewhere: use `SSH_PORT`.)

**Healing after a firewalld reload:**

```bash
firewall-cmd --reload
firewall-cmd --ipset=logguard-ban4 --get-entries   # empty: firewalld forgot them
sleep 40
firewall-cmd --ipset=logguard-ban4 --get-entries   # the probe's address is back
grep -c 'firewalld forgot' /var/log/logguard/actions.jsonl   # 1 (a high "system" alert)
```

Do the same with `systemctl restart firewalld`.

**Exposure under enforce:** `lg status` still says `firewalld running`; the `logguard` zone
must not make anything look open (its whitelist ports are for banned sources only).

**Lift the probe's ban:** `lg unban PROBE_IP`, and `nc -vz -w 3 VPS_IP 22` from the probe works again.

## 6. Enforce with nftables next to firewalld (`backend = "auto"`)

`auto` prefers logguard's own nftables table, which runs next to firewalld's tables.

```bash
sed -i 's/^backend = "firewalld"/backend = "auto"/' /etc/logguard/logguard.toml
systemctl restart logguard
journalctl -u logguard -b | grep started | tail -n 1     # backend=nftables
nft list table inet logguard | head -30                  # chain bans, sets ban4/ban6, the tripwire rules
```

From the probe: `nc -vz -w 3 VPS_IP 3389` (another tripwire), then port 22 times out; the
probe's address is in `nft list set inet logguard ban4`. Then:

```bash
firewall-cmd --reload; sleep 40
nft list set inet logguard ban4            # still there (firewalld leaves other tables alone),
                                           # or rebuilt within 30 s with a "nftables table ... had been removed" alert
lg unban PROBE_IP
```

Note which of the two happened: it says whether this firewalld version flushes foreign tables.

The firewalld objects from step 5 stay in firewalld's permanent configuration, unused (their
sets are emptied): `firewall-cmd --ipset=logguard-ban4 --get-entries` is empty.

## 7. Package check (rpm)

The first pass runs 15 minutes after logguard's start (step 6's restart counts). Then:

```bash
lg status | grep packages     # packages: last check ..., N files match their packages, 0 differ; M set-uid/set-gid programs
grep -E 'match rpm|differ from what rpm' /var/log/logguard/actions.jsonl
```

Expect *package check: N files match rpm's checksums* (N in the tens of thousands), and few or
no differences (a difference now is a finding: paste it, and `rpm -Vf <that file>`).

Now tamper with a package's program, after the first pass:

```bash
dnf install -y tree
cp /usr/bin/tree /root/tree.bak
printf '\n' >> /usr/bin/tree
rpm -Vf /usr/bin/tree          # S.5...... /usr/bin/tree: rpm sees it too
```

At the next pass (`[verify] interval = "1h"`): a **high** alert *1 package files differ from what
rpm installed - ... (reinstall: dnf reinstall <package>)* in the actions log and `lg status`
(`1 differ`). Restore: `dnf reinstall -y tree`.

## 8. Optional: the ipset backend

```bash
dnf install -y ipset iptables-nft
sed -i 's/^backend = "auto"/backend = "ipset"/' /etc/logguard/logguard.toml
systemctl restart logguard
journalctl -u logguard -b | grep started | tail -n 1   # backend=ipset
ipset list -n                                          # logguard-ban4 logguard-ban6 logguard-feed4 logguard-feed6
iptables -t mangle -S logguard-ban                     # -m set --match-set logguard-feed4 src -j DROP, then ban4
ip6tables -t mangle -S logguard-ban
lg ban PROBE_IP --for 10m --note test
ipset list logguard-ban4 | grep PROBE_IP               # PROBE_IP timeout 59x: the kernel ends it
lg unban PROBE_IP
lg feeds status                                        # feeds load into logguard-feed4/6 (not with firewalld)
ipset list logguard-feed4 | head -12
```

From the probe, the tripwire test of step 5 once more (ban, port 22 times out, `ipset list logguard-ban4`
has its address, `lg unban PROBE_IP`). Then `iptables -t mangle -F logguard` (as a firewall reload
would) and within 40 s `iptables -t mangle -S logguard` has its rules back.

Back to the default afterwards: `backend = "auto"`, restart.

## 8b. Optional: block by country

Pick the country of a VPN exit you can use as the probe: `lg geo PROBE_IP` names it (the
earlier probe exits were `Brazil`, code `BR`). Add to the config, with any backend of the steps
above (not shadow mode):

```toml
[geoblock]
enabled = true
countries = ["BR"]
```

```bash
systemctl restart logguard; sleep 10
journalctl -u logguard -b | grep geoblock               # geoblock (BR): N IPv4 + M IPv6 networks
lg status | grep geoblock                               # ..., active in <backend>
nft list set inet logguard geo4 | head                  # nftables
ipset list logguard-geo4 | head                         # ipset
firewall-cmd --ipset=logguard-geo4 --get-entries | wc -l  # firewalld (the first load takes a while)
```

From the probe exit: `nc -vz -w 3 VPS_IP 22` times out, with no ban in `lg status`
(the country is dropped before anything is logged). From your usual exit (another country) it
connects. `lg geo PROBE_IP` and the networks above should agree. Then `enabled = false`, restart,
and the set is empty again.

## 9. Things to check throughout

```bash
journalctl -u logguard -b -p warning --no-pager | tail -n 30   # logguard's own warnings and errors
ausearch -m avc -ts today 2> /dev/null | tail                  # SELinux denials (should be none)
systemctl show logguard -p MemoryPeak                          # under the unit's 128M limit
```

## 10. Send back

- `cat /etc/fedora-release; uname -m; firewall-cmd --version`
- `lg status` from step 4 and after step 7
- the expected-vs-seen differences, step by step (and any errors above)
- `journalctl -u logguard -b --no-pager | grep -v '\[shadow\]' | tail -n 50`

## Clean up (if the VPS is only for this test)

```bash
systemctl disable --now logguard
firewall-cmd --permanent --delete-policy=logguard-fwd
firewall-cmd --permanent --delete-zone=logguard
for s in logguard-ban4 logguard-ban6 logguard-alive; do firewall-cmd --permanent --delete-ipset=$s; done
systemctl reboot     # logguard's nftables table, iptables chains and ipset sets live until a reboot only
```
