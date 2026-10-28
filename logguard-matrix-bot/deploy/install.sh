#!/bin/bash
# Installs the bot. Run as root from the directory holding logguard-matrix-bot,
# logguard-matrix-bot.service, logguard-matrix-bot.logrotate and config.env.example (deploy.sh copies them there).
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/logguard-matrix-bot for that)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/logguard-matrix-bot
UNIT=/etc/systemd/system/logguard-matrix-bot.service
BOT=logguard-matrix-bot

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    local start=$1
    sleep 5
    echo
    journalctl -u $BOT --since "$start" --no-pager -o cat | tail -n 5
    echo
    LD=$(grep -E '^LOG_DIR=' "$DIR/config.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'")
    tail -n 10 "${LD:-/var/log/$BOT}/bot.log" 2>/dev/null || true
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/$BOT.prev" ] || { echo "no $DIR/$BOT.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/$BOT.prev" "$DIR/$BOT"
    [ -f "$DIR/$BOT.service.prev" ] && install -m 0644 "$DIR/$BOT.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart $BOT
    show_start "$start"
    systemctl --no-pager status $BOT | head -5
    exit 0
fi

# logguard's integrity watch covers the account files: announce what useradd (or a rename)
# wrote, so it is logged instead of raised as a high alert.
announce_accounts() {
    [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ] || return 0
    local f files=()
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do [ -f "$f" ] && files+=("$f"); done
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml expect-change "${files[@]}" 2> /dev/null || true
}

# A system user of its own, without a home or a shell.
if ! id "$BOT" > /dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$BOT"
    echo "created the system user $BOT"
    announce_accounts
fi

mkdir -p "$DIR"
first=no
if [ ! -f "$DIR/config.env" ]; then
    install -m 0640 -o root -g "$BOT" config.env.example "$DIR/config.env"
    first=yes
fi

setting() { # the value of $1 in config.env, quotes removed
    grep -E "^$1=" "$DIR/config.env" | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true
}

# Owners and modes. The directory is sticky: the bot may replace its own files (the state
# is written to a temporary file and renamed), but not root's ones.
#   config.env, OPENPGP_KEY              root:logguard-matrix-bot 640  (the bot reads them)
#   state.json, pseudonym.key            logguard-matrix-bot 600       (the bot writes them)
#   logguard-matrix-bot, install.sh      root
chown root:"$BOT" "$DIR"
chmod 1770 "$DIR"
chown root:"$BOT" "$DIR/config.env"
chmod 640 "$DIR/config.env"
SP=$(setting BOT_STATE_PATH); SP=${SP:-$DIR/state.json}
KEY=$(setting PSEUDONYM_KEY); KEY=${KEY:-$(dirname "$SP")/pseudonym.key}
# the admin's OpenPGP public key: root's, the bot only reads it
PGPKEY=$(setting OPENPGP_KEY)
if [ -n "$PGPKEY" ] && [ -f "$PGPKEY" ]; then
    chown root:"$BOT" "$PGPKEY"
    chmod 640 "$PGPKEY"
elif [ -n "$PGPKEY" ]; then
    echo "WARNING: OPENPGP_KEY=$PGPKEY does not exist, so the bot won't start. Export your public"
    echo "  key from OpenKeychain or iPGMail and copy it there (root:$BOT 640), or comment OPENPGP_KEY out."
fi
for f in "$SP" "$KEY"; do
    if [ -f "$f" ]; then
        chown "$BOT:$BOT" "$f"
        chmod 600 "$f"
    fi
done
# leftovers of an interrupted write, possibly root's: the bot could not replace them
rm -f "${DIR:?}"/*.tmp
LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-/var/log/$BOT}
mkdir -p "$LOGDIR"
chown "$BOT:$BOT" "$LOGDIR"
chmod 700 "$LOGDIR"
if [ -f "$LOGDIR/bot.log" ]; then
    chown "$BOT:$BOT" "$LOGDIR/bot.log"
    chmod 600 "$LOGDIR/bot.log"
fi

# Outbox: logguard (root) writes alerts and the weekly report here and hands each file to
# the bot, which sends and deletes it. Sticky like $DIR.
OUTBOX=$(setting OUTBOX_DIR); OUTBOX=${OUTBOX:-$(dirname "$SP")/outbox}
mkdir -p "$OUTBOX"
chown root:"$BOT" "$OUTBOX"
chmod 1770 "$OUTBOX"

# The running version becomes the rollback target, unless it is failing (restarting).
if systemctl is-active -q $BOT && [ "$(systemctl show -p NRestarts --value $BOT)" = 0 ]; then
    [ -x "$DIR/$BOT" ] && cp -p "$DIR/$BOT" "$DIR/$BOT.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/$BOT.service.prev"
elif [ -f "$UNIT" ]; then
    echo "$BOT is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 $BOT "$DIR/$BOT"
echo "Installed $("$DIR/$BOT" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
# logguard's integrity watch covers the unit: announce its new content (logged, not alerted).
if [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ]; then
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml expect-change "$UNIT=$BOT.service" \
        "/etc/systemd/system/multi-user.target.wants/$BOT.service=$BOT.service" 2> /dev/null || true
fi
install -m 0644 $BOT.service "$UNIT"
install -m 0644 $BOT.logrotate /etc/logrotate.d/$BOT
install -o root -g root -m 0644 config.env.example "$DIR/config.env.example"
systemctl daemon-reload

# not filled in yet: empty, or still config.env.example's placeholders
placeholder() { local v; v=$(setting "$1"); [ -z "$v" ] || [[ "$v" == *REPLACE* ]] || [ "$v" = https://matrix.example.org ]; }
if placeholder MATRIX_HOMESERVER || placeholder MATRIX_USER || placeholder ADMIN; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template."
    echo "Not started: $DIR/config.env needs MATRIX_HOMESERVER, MATRIX_USER and ADMIN. Then run this again."
    exit 0
fi
if [ ! -f "$SP" ] || ! grep -q '"access_token"' "$SP"; then
    echo "Not started: the bot isn't logged in yet. With the service stopped, as root:"
    echo "  runuser -u $BOT -- sh -c 'set -a; . $DIR/config.env; exec $DIR/$BOT login'"
    echo "It asks for the bot account's password, then: systemctl enable --now $BOT"
    exit 0
fi

start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable -q $BOT
systemctl restart $BOT
show_start "$start"
if ! systemctl is-active -q $BOT; then
    echo "FAILED: $BOT is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
echo "OK: $BOT is running. Accept its invitation in your Matrix client."
# logguard feeds the bot only when its config says so (off by default)
LG=/etc/logguard/logguard.toml
if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*matrix_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
    echo "logguard doesn't write to this outbox yet. In [notify] of $LG set"
    echo "  matrix_outbox = \"$OUTBOX\""
    echo "  matrix_user = \"$BOT\""
    echo "(the weekly abuse report job reads it from there too)"
    echo "then: systemctl restart logguard, and test: logguard -c $LG notify-test --matrix"
fi
