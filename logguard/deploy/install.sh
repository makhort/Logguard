#!/bin/bash
# Installs logguard on the server. Run as root from the directory containing
# the logguard binary, logguard.toml and logguard.service.
# Leaves the existing Python cron jobs untouched (run both side by side while in shadow mode).
set -euo pipefail
cd "$(dirname "$0")"

# Defaults of the version being replaced, so config-diff can tell new options and
# changed defaults apart (print-config without a config file prints the defaults).
old_defaults=""
if [ -x /usr/local/bin/logguard ]; then
    old_defaults=$(mktemp)
    trap 'rm -f "$old_defaults"' EXIT
    env -u LOGGUARD_CONFIG /usr/local/bin/logguard print-config > "$old_defaults" 2>/dev/null || old_defaults=""
fi

# The files below are in the integrity watch: announce their new content first, so the
# running daemon logs these changes instead of raising "may be compromised" alerts.
if [ -f /etc/logguard/logguard.toml ]; then
    sysd=/etc/systemd/system
    prev=""
    [ -x /usr/local/bin/logguard ] && prev=/usr/local/bin/logguard.prev=/usr/local/bin/logguard
    ./logguard --config /etc/logguard/logguard.toml expect-change \
        /usr/local/bin/logguard=logguard \
        $prev \
        $sysd/logguard.service=logguard.service \
        $sysd/multi-user.target.wants/logguard.service=logguard.service \
        /usr/local/sbin/logguard-avscan=logguard-avscan.sh \
        /usr/local/sbin/logguard-abuse-report=logguard-abuse-report.sh \
        $sysd/logguard-avscan.service=logguard-avscan.service \
        $sysd/logguard-avscan.timer=logguard-avscan.timer \
        $sysd/timers.target.wants/logguard-avscan.timer=logguard-avscan.timer \
        $sysd/logguard-abuse-report.service=logguard-abuse-report.service \
        $sysd/logguard-abuse-report.timer=logguard-abuse-report.timer \
        $sysd/timers.target.wants/logguard-abuse-report.timer=logguard-abuse-report.timer \
        || echo "WARNING: could not announce the new files: expect integrity alerts for them"
fi

# Keep the replaced binary: roll back with  mv /usr/local/bin/logguard.prev /usr/local/bin/logguard
if [ -x /usr/local/bin/logguard ]; then
    cp -p /usr/local/bin/logguard /usr/local/bin/logguard.prev
fi
install -m 0755 logguard /usr/local/bin/logguard
echo "Installed $(/usr/local/bin/logguard --version)"
install -d -m 0755 /etc/logguard
if [ -f /etc/logguard/logguard.toml ]; then
    install -m 0600 logguard.toml /etc/logguard/logguard.toml.new
    echo "Kept existing /etc/logguard/logguard.toml (new template saved as logguard.toml.new)"
    echo
    echo "=== logguard config-diff: what this upgrade means for your config ==="
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml config-diff ${old_defaults:+--against "$old_defaults"}
    echo "======================================================================"
    echo
else
    install -m 0600 logguard.toml /etc/logguard/logguard.toml
fi
install -m 0644 logguard.service /etc/systemd/system/logguard.service
install -m 0644 logguard.logrotate /etc/logrotate.d/logguard
# Scheduled ClamAV scan for [antivirus]: always installed, enabled below only when configured.
install -m 0755 logguard-avscan.sh /usr/local/sbin/logguard-avscan
install -m 0644 logguard-avscan.service logguard-avscan.timer /etc/systemd/system/
if [ ! -f /etc/default/logguard-avscan ]; then
    install -m 0644 logguard-avscan.default /etc/default/logguard-avscan
fi
# Weekly abuse report for the admin bot: enabled below unless ABUSE_REPORT_ROLE=off.
install -m 0755 logguard-abuse-report.sh /usr/local/sbin/logguard-abuse-report
install -m 0644 logguard-abuse-report.service logguard-abuse-report.timer /etc/systemd/system/
if [ ! -f /etc/default/logguard-abuse-report ]; then
    install -m 0644 logguard-abuse-report.default /etc/default/logguard-abuse-report
fi
if [ -f cluster.key ] && [ ! -f /etc/logguard/cluster.key ]; then
    install -m 0600 cluster.key /etc/logguard/cluster.key
    echo "Installed cluster key /etc/logguard/cluster.key"
fi

/usr/local/bin/logguard --config /etc/logguard/logguard.toml print-config > /dev/null
echo "Config OK"

# Dry run of the nftables ruleset against this kernel (checks rate-limit support too).
if command -v nft > /dev/null; then
    if /usr/local/bin/logguard --config /etc/logguard/logguard.toml print-nft | nft -c -f -; then
        echo "nftables ruleset OK (dry run)"
    elif /usr/local/bin/logguard --config /etc/logguard/logguard.toml print-nft --no-tripwires | nft -c -f - 2> /dev/null; then
        echo "WARNING: this kernel/nft rejects the kernel tripwire rules ([ports] kernel_tripwires); logguard runs without them"
    else
        echo "WARNING: this kernel/nft rejects the ruleset above; logguard would fall back to ufw or iptables"
    fi
fi

if command -v ufw > /dev/null; then
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml cluster-ufw-rules | while read -r rule; do
        echo "+ $rule"
        eval "$rule"
    done
    if ! ufw status verbose | grep -q '^Logging: on'; then
        echo "NOTE: UFW logging is off; enable it for firewall-based detection:  ufw logging low"
    fi
else
    # Plain iptables (e.g. iptables-persistent): the rules are yours, so only suggest them.
    rules=$(/usr/local/bin/logguard --config /etc/logguard/logguard.toml cluster-ufw-rules --iptables)
    if [ -n "$rules" ]; then
        echo "NOTE: no ufw; open the cluster port to the peers in your iptables rules (and save them):"
        echo "$rules" | sed 's/^/    /'
    fi
    echo "NOTE: for firewall-based detection, log dropped packets with the prefix logguard reads, as the"
    echo "      last rules of INPUT (before its DROP policy or final DROP rule), e.g.:"
    echo "    iptables  -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[LOGGUARD BLOCK] '"
    echo "    ip6tables -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[LOGGUARD BLOCK] '"
fi

systemctl daemon-reload
# Enabled before logguard (re)starts, so a first cron-watch baseline includes the timer.
setting() {
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml print-config \
        | awk -v sec="[$1]" -v key="$2" '/^\[/ { s = ($0 == sec) } s && $1 == key { gsub(/"/, "", $3); print $3 }'
}
if [ "$(setting antivirus enabled)" = true ]; then
    if command -v clamscan > /dev/null || command -v clamdscan > /dev/null; then
        systemctl enable --now logguard-avscan.timer
        echo "Virus scan: logguard-avscan.timer enabled ($(systemctl show -P TimersCalendar logguard-avscan.timer | grep -o 'OnCalendar=[^;]*' || true))"
        if [ "$(setting antivirus log)" != /var/log/logguard/avscan.log ] && ! grep -q '^AVSCAN_LOG=' /etc/default/logguard-avscan; then
            echo "NOTE: [antivirus] log is not the scan script's log; set AVSCAN_LOG in /etc/default/logguard-avscan"
        fi
        if { crontab -l 2> /dev/null; cat /etc/crontab /etc/cron.d/* 2> /dev/null; } | grep -v '^\s*#' | grep -qE 'clamscan|clamdscan|av_?scan'; then
            echo "NOTE: a cron job runs a virus scan too; remove it (crontab -e) so two scans don't run"
            echo "      (each clamscan loads ~1-1.5 GB of signatures) - logguard-avscan.timer replaces it"
        fi
    else
        echo "WARNING: [antivirus] is enabled but ClamAV is not installed:  apt install clamav clamav-freshclam"
    fi
elif systemctl is-enabled --quiet logguard-avscan.timer 2> /dev/null; then
    systemctl disable --now logguard-avscan.timer
    echo "Virus scan: logguard-avscan.timer disabled ([antivirus] enabled = false)"
fi

abuse_role=$( (set +u; . /etc/default/logguard-abuse-report; echo "${ABUSE_REPORT_ROLE:-auto}") )
if [ "$abuse_role" = off ]; then
    if systemctl is-enabled --quiet logguard-abuse-report.timer 2> /dev/null; then
        systemctl disable --now logguard-abuse-report.timer
        echo "Abuse report: logguard-abuse-report.timer disabled (ABUSE_REPORT_ROLE=off)"
    fi
else
    systemctl enable --now logguard-abuse-report.timer
    echo "Abuse report: weekly, ABUSE_REPORT_ROLE=$abuse_role (/etc/default/logguard-abuse-report);" \
        "try it now with  systemctl start logguard-abuse-report"
fi

# Files written by older versions were world-readable (addresses, account names; the config
# holds users' addresses and JIDs).
chmod 0600 /var/lib/logguard/state.json /etc/logguard/logguard.toml /etc/logguard/logguard.toml.new 2>/dev/null || true
chmod 0640 /var/log/logguard/actions.jsonl* 2>/dev/null || true

systemctl daemon-reload
systemctl enable logguard.service
systemctl restart logguard.service
sleep 2
systemctl --no-pager --lines=15 status logguard.service || true
echo
echo "Dashboard:   sudo logguard -c /etc/logguard/logguard.toml tui"
echo "Decisions:   journalctl -u logguard -f    or    tail -f /var/log/logguard/actions.jsonl"
