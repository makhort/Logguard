#!/bin/bash
# Installs the bot. Run as root from the directory holding logguard-mail-bot,
# logguard-mail-bot.service, logguard-mail-bot.logrotate and config.env.example (deploy.sh copies them there).
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/logguard-mail-bot for that)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/logguard-mail-bot
UNIT=/etc/systemd/system/logguard-mail-bot.service
BOT=logguard-mail-bot

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    local start=$1
    sleep 5
    echo
    journalctl -u logguard-mail-bot --since "$start" --no-pager -o cat | tail -n 5
    echo
    LD=$(grep -E '^LOG_DIR=' "$DIR/config.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'")
    tail -n 10 "${LD:-/var/log/logguard-mail-bot}/bot.log" 2>/dev/null || true
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/logguard-mail-bot.prev" ] || { echo "no $DIR/logguard-mail-bot.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/logguard-mail-bot.prev" "$DIR/logguard-mail-bot"
    [ -f "$DIR/logguard-mail-bot.service.prev" ] && install -m 0644 "$DIR/logguard-mail-bot.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart logguard-mail-bot
    show_start "$start"
    systemctl --no-pager status logguard-mail-bot | head -5
    exit 0
fi

# A system user of its own, without a home or a shell.
if ! id "$BOT" > /dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$BOT"
    echo "created the system user $BOT"
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

# Owners and modes. The directory is sticky: the bot may delete its own files in the
# outbox, but not root's ones here.
#   config.env, OPENPGP_KEY, SMTP_PASSWORD_FILE, SMTP_CA_FILE   root:logguard-mail-bot 640 (the bot reads them)
#   SIGNING_KEY, PSEUDONYM_KEY                                 logguard-mail-bot 600 (the bot's secrets)
#   logguard-mail-bot, install.sh                              root
chown root:"$BOT" "$DIR"
chmod 1770 "$DIR"
chown root:"$BOT" "$DIR/config.env"
chmod 640 "$DIR/config.env"
for var in OPENPGP_KEY SMTP_PASSWORD_FILE SMTP_CA_FILE; do
    f=$(setting "$var")
    [ -n "$f" ] || continue
    if [ -f "$f" ]; then
        chown root:"$BOT" "$f"
        chmod 640 "$f"
    else
        echo "WARNING: $var=$f does not exist, so the bot won't start (or comment $var out)."
    fi
done
# SANITIZE's pseudonym key: the bot's, made by it on the first start (or by a `check` as root)
PK=$(setting PSEUDONYM_KEY); PK=${PK:-$DIR/pseudonym.key}
if [ -f "$PK" ]; then
    chown "$BOT:$BOT" "$PK"
    chmod 600 "$PK"
fi
SK=$(setting SIGNING_KEY)
if [ -n "$SK" ] && [ -f "$SK" ]; then
    chown "$BOT:$BOT" "$SK"
    chmod 600 "$SK"
elif [ -n "$SK" ]; then
    echo "WARNING: SIGNING_KEY=$SK does not exist, so the bot won't start (make it with keygen, or comment it out)."
fi
LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-/var/log/logguard-mail-bot}
mkdir -p "$LOGDIR"
chown "$BOT:$BOT" "$LOGDIR"
chmod 700 "$LOGDIR"
if [ -f "$LOGDIR/bot.log" ]; then
    chown "$BOT:$BOT" "$LOGDIR/bot.log"
    chmod 600 "$LOGDIR/bot.log"
fi

# Outbox: logguard (root) writes alerts and the weekly report here and hands each file to
# the bot, which sends and deletes it. Sticky like $DIR.
OUTBOX=$(setting OUTBOX_DIR); OUTBOX=${OUTBOX:-$DIR/outbox}
mkdir -p "$OUTBOX"
chown root:"$BOT" "$OUTBOX"
chmod 1770 "$OUTBOX"

# The running version becomes the rollback target, unless it is failing (restarting).
if systemctl is-active -q logguard-mail-bot && [ "$(systemctl show -p NRestarts --value logguard-mail-bot)" = 0 ]; then
    [ -x "$DIR/logguard-mail-bot" ] && cp -p "$DIR/logguard-mail-bot" "$DIR/logguard-mail-bot.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/logguard-mail-bot.service.prev"
elif [ -f "$UNIT" ]; then
    echo "logguard-mail-bot is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 logguard-mail-bot "$DIR/logguard-mail-bot"
echo "Installed $("$DIR/logguard-mail-bot" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
# logguard's integrity watch covers the unit: announce its new content (logged, not alerted).
if [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ]; then
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml expect-change "$UNIT=logguard-mail-bot.service" \
        "/etc/systemd/system/multi-user.target.wants/logguard-mail-bot.service=logguard-mail-bot.service" 2> /dev/null || true
fi
install -m 0644 logguard-mail-bot.service "$UNIT"
install -m 0644 logguard-mail-bot.logrotate /etc/logrotate.d/logguard-mail-bot
install -o root -g root -m 0644 config.env.example "$DIR/config.env.example"
systemctl daemon-reload

# not filled in yet: still config.env.example's placeholders, or no key
FROM=$(setting MAIL_FROM)
TO=$(setting MAIL_TO)
KEY=$(setting OPENPGP_KEY)
if [[ -z "$FROM" || "$FROM" == REPLACE* || -z "$TO" || "$TO" == REPLACE* || "$(setting SMTP_USER)" == REPLACE* || -z "$KEY" || ! -f "$KEY" ]]; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template."
    echo "Not started: fill in $DIR/config.env (MAIL_FROM, MAIL_TO, the mail server), then:"
    echo "  1. copy the recipients' OpenPGP public keys to ${KEY:-$DIR/recipients.asc}, and the SMTP password"
    echo "     (if any) to its SMTP_PASSWORD_FILE; then run this script again to set their owners and modes"
    echo "  2. set -a; . $DIR/config.env; set +a; $DIR/logguard-mail-bot check       # logs in, sends nothing"
    echo "     $DIR/logguard-mail-bot send-test                                     # a test mail"
    echo "  3. systemctl enable --now logguard-mail-bot"
    exit 0
fi

start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable -q logguard-mail-bot
systemctl restart logguard-mail-bot
show_start "$start"
if ! systemctl is-active -q logguard-mail-bot; then
    echo "FAILED: logguard-mail-bot is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
echo "OK: logguard-mail-bot is running."
# logguard feeds the bot only when its config says so (off by default)
LG=/etc/logguard/logguard.toml
if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*mail_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
    echo "logguard doesn't write to this outbox yet. In [notify] of $LG set"
    echo "  mail_outbox = \"$OUTBOX\""
    echo "  mail_user = \"$BOT\""
    echo "(the weekly abuse report job reads it from there too)"
    echo "then: systemctl restart logguard, and test: logguard -c $LG notify-test --mail"
fi
