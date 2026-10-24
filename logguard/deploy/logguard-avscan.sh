#!/bin/bash
# Scheduled ClamAV scan whose results logguard reports ([antivirus] in logguard.toml):
# infected files, scans that die (e.g. killed for memory) and scans that stop happening.
# Run daily by logguard-avscan.timer; settings in /etc/default/logguard-avscan.
#
# Each run is appended to the log between two marker lines carrying UTC times and the
# scanner's exit code (0 clean, 1 infected files found, 2 some files unreadable):
#   logguard-avscan start 2026-10-12T02:30:01Z
#   ...clamscan output (only infected files, then the summary)...
#   logguard-avscan end 2026-10-12T02:31:17Z exit=0
set -u

PATHS=${AVSCAN_PATHS:-"/etc /opt /root /home /srv /usr/local /var/www /var/spool/cron /tmp /var/tmp /dev/shm"}
# Directory regexes clamscan skips (clamdscan uses ExcludePath in clamd.conf instead).
EXCLUDE=${AVSCAN_EXCLUDE:-}
LOG=${AVSCAN_LOG:-/var/log/logguard/avscan.log}
# auto: clamdscan when clamav-daemon is running (no signature loading), else clamscan.
SCANNER=${AVSCAN_SCANNER:-auto}

mkdir -p "$(dirname "$LOG")"
targets=()
for p in $PATHS; do
    [ -e "$p" ] && targets+=("$p")
done
if [ "$SCANNER" = auto ]; then
    if command -v clamdscan > /dev/null && systemctl is-active --quiet clamav-daemon; then
        SCANNER=clamdscan
    else
        SCANNER=clamscan
    fi
fi
args=(--infected --stdout)
if [ "$SCANNER" = clamdscan ]; then
    args+=(--multiscan --fdpass)
else
    args+=(--recursive)
    # the unit's writable temporary directory (the rest of the system is read-only there)
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && args+=("--tempdir=$TMPDIR")
    # Regexes, not file patterns: split on spaces, but never expand `*` against files.
    set -f
    for x in $EXCLUDE; do
        args+=("--exclude-dir=$x")
    done
    set +f
fi

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
echo "logguard-avscan start $(now)" >> "$LOG"
if command -v "$SCANNER" > /dev/null; then
    # TZ=UTC: the summary's Start/End Date lines are then in UTC too. Indented, so no line of
    # the output (a file name with line breaks in it) can pass for one of the markers.
    TZ=UTC "$SCANNER" "${args[@]}" "${targets[@]}" 2>&1 | sed -u 's/^/  /' >> "$LOG"
    rc=${PIPESTATUS[0]}
else
    echo "logguard-avscan: $SCANNER not found (apt install clamav clamav-freshclam)" >> "$LOG"
    rc=127
fi
echo "logguard-avscan end $(now) exit=$rc" >> "$LOG"
exit "$rc"
