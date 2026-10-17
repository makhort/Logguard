#!/bin/bash
# Installs the bot. Run as root from the directory holding logguard-tg-bot,
# logguard-tg-bot.service, logguard-tg-bot.logrotate and config.env.example (deploy.sh copies them there).
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/logguard-tg-bot for that)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/logguard-tg-bot
UNIT=/etc/systemd/system/logguard-tg-bot.service
BOT=logguard-tg-bot

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    local start=$1
    sleep 5
    echo
    journalctl -u logguard-tg-bot --since "$start" --no-pager -o cat | tail -n 5
    echo
    LD=$(grep -E '^LOG_DIR=' "$DIR/config.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'")
    tail -n 10 "${LD:-/var/log/logguard-tg-bot}/bot.log" 2>/dev/null || true
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/logguard-tg-bot.prev" ] || { echo "no $DIR/logguard-tg-bot.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/logguard-tg-bot.prev" "$DIR/logguard-tg-bot"
    [ -f "$DIR/logguard-tg-bot.service.prev" ] && install -m 0644 "$DIR/logguard-tg-bot.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart logguard-tg-bot
    show_start "$start"
    systemctl --no-pager status logguard-tg-bot | head -5
    exit 0
fi

# From the old names: up to 2026-10-17 the bot was /opt/tgbot/tgbot, run by tgbot.service as
# the user tgbot, logging to /var/log/tgbot. Moved over once, keeping its state (the place
# in Telegram's queue, messages to delete), pseudonym key, outbox and log; the old unit and
# logrotate rule go. logguard's settings naming the old outbox, user or unit are updated too
# (a copy of each file stays next to it) and logguard restarted. Safe to run again.
OLD_DIR=/opt/tgbot
OLD_UNIT=/etc/systemd/system/tgbot.service
OLD_BOT=tgbot
migrated=no
migrate_old_names() {
    [ -e "$OLD_DIR" ] || [ -e "$OLD_UNIT" ] || id "$OLD_BOT" > /dev/null 2>&1 || return 0
    if [ -e "$OLD_DIR" ] && [ -e "$DIR" ]; then
        echo "both $OLD_DIR and $DIR exist: keep one (move what you need into $DIR, remove $OLD_DIR), then run this again" >&2
        exit 1
    fi
    echo "Renaming tgbot to $BOT (directory, unit, user, log directory)"
    local clean=no
    if systemctl is-active -q tgbot && [ "$(systemctl show -p NRestarts --value tgbot)" = 0 ]; then
        clean=yes
    fi
    systemctl disable -q --now tgbot 2> /dev/null || true
    # the user and group keep their ids, so every file stays theirs
    if id "$OLD_BOT" > /dev/null 2>&1 && ! id "$BOT" > /dev/null 2>&1; then
        usermod -l "$BOT" "$OLD_BOT"
        groupmod -n "$BOT" "$OLD_BOT"
    fi
    if [ -d "$OLD_DIR" ]; then
        mv "$OLD_DIR" "$DIR"
        rm -f "$DIR/tgbot.service.prev" # names the old paths: no rollback target any more
        # the running version becomes the rollback target, as on every install
        if [ "$clean" = yes ] && [ -f "$DIR/tgbot" ]; then
            mv "$DIR/tgbot" "$DIR/$BOT.prev"
            rm -f "$DIR/tgbot.prev"
        elif [ -f "$DIR/tgbot.prev" ]; then
            mv "$DIR/tgbot.prev" "$DIR/$BOT.prev"
        fi
        rm -f "$DIR/tgbot"
        if [ -f "$DIR/config.env" ]; then
            cp -p "$DIR/config.env" "$DIR/config.env.pre-rename"
            sed -i -E 's#/opt/tgbot\b#/opt/logguard-tg-bot#g; s#/var/log/tgbot\b#/var/log/logguard-tg-bot#g; s#/etc/logrotate\.d/tgbot\b#/etc/logrotate.d/logguard-tg-bot#g' "$DIR/config.env"
            # the old binary (the rollback target) would fall back to the old paths
            grep -qE '^BOT_STATE_PATH=' "$DIR/config.env" || echo "BOT_STATE_PATH=$DIR/state.json" >> "$DIR/config.env"
            grep -qE '^LOG_DIR=' "$DIR/config.env" || echo "LOG_DIR=/var/log/logguard-tg-bot" >> "$DIR/config.env"
        fi
    fi
    if [ -d /var/log/tgbot ] && [ ! -e /var/log/logguard-tg-bot ]; then
        mv /var/log/tgbot /var/log/logguard-tg-bot
    fi
    rm -f /etc/logrotate.d/tgbot
    # local changes (systemctl edit tgbot) carry over
    if [ -d "$OLD_UNIT.d" ] && [ ! -e "$UNIT.d" ]; then
        mv "$OLD_UNIT.d" "$UNIT.d"
    fi
    rm -f "$OLD_UNIT"
    systemctl daemon-reload
    systemctl reset-failed tgbot 2> /dev/null || true
    migrate_logguard \
        's#/opt/tgbot\b#/opt/logguard-tg-bot#g; s#"tgbot\.service"#"logguard-tg-bot.service"#g; s#^([[:space:]]*tg_user[[:space:]]*=[[:space:]]*)"tgbot"#\1"logguard-tg-bot"#; s#^([[:space:]]*\#?ABUSE_REPORT_TG_OWNER=)tgbot\b#\1logguard-tg-bot#'
    migrated=yes
}

# logguard's settings: $1 (sed -E) applied to its config and the abuse report job's, each
# changed one kept as <file>.pre-rename-<time>. A config logguard then refuses goes back.
migrate_logguard() {
    local f bak changed=no
    for f in /etc/logguard/logguard.toml /etc/default/logguard-abuse-report; do
        [ -f "$f" ] || continue
        bak="$f.pre-rename-$(date +%Y%m%d-%H%M%S)"
        cp -p "$f" "$bak"
        sed -i -E "$1" "$f"
        if cmp -s "$f" "$bak"; then
            rm -f "$bak"
            continue
        fi
        echo "updated $f (before: $bak)"
        if [ "$f" = /etc/logguard/logguard.toml ]; then
            if [ -x /usr/local/bin/logguard ] && ! /usr/local/bin/logguard --config "$f" print-config > /dev/null; then
                echo "WARNING: logguard refuses the updated $f; restored it. Update it by hand:" >&2
                echo "  /opt/tgbot -> $DIR, tg_user \"tgbot\" -> \"$BOT\", \"tgbot.service\" -> \"$BOT.service\"" >&2
                cp -p "$bak" "$f"
                continue
            fi
            changed=yes
        fi
    done
    if [ "$changed" = yes ] && systemctl is-active -q logguard; then
        systemctl restart logguard
        echo "restarted logguard (it writes to $DIR/outbox now)"
    fi
    if [ -f /etc/systemd/system/logguard-abuse-report.service ] \
        && ! grep -q "$DIR/outbox" /etc/systemd/system/logguard-abuse-report.service; then
        echo "WARNING: logguard-abuse-report.service still names only the old outbox: deploy the"
        echo "  current logguard too, or the weekly abuse report can't reach $DIR/outbox"
    fi
}

migrate_old_names

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

# Owners and modes. The directory is sticky: the bot may replace its own files (the state
# is written to a temporary file and renamed), but not root's ones.
#   config.env (the token), OPENPGP_KEY   root:logguard-tg-bot 640  (the bot reads them)
#   state.json, pseudonym.key            logguard-tg-bot 600       (the bot writes them)
#   logguard-tg-bot, install.sh          root
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
LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-/var/log/logguard-tg-bot}
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
if [ "$migrated" = yes ]; then
    : # the version running under the old name became it above
elif systemctl is-active -q logguard-tg-bot && [ "$(systemctl show -p NRestarts --value logguard-tg-bot)" = 0 ]; then
    [ -x "$DIR/logguard-tg-bot" ] && cp -p "$DIR/logguard-tg-bot" "$DIR/logguard-tg-bot.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/logguard-tg-bot.service.prev"
elif [ -f "$UNIT" ]; then
    echo "logguard-tg-bot is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 logguard-tg-bot "$DIR/logguard-tg-bot"
echo "Installed $("$DIR/logguard-tg-bot" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
install -m 0644 logguard-tg-bot.service "$UNIT"
install -m 0644 logguard-tg-bot.logrotate /etc/logrotate.d/logguard-tg-bot
install -o root -g root -m 0644 config.env.example "$DIR/config.env.example"
systemctl daemon-reload

# not filled in yet: empty, or still config.env.example's placeholders
TOKEN=$(setting TELEGRAM_TOKEN)
[ -n "$(setting TELEGRAM_TOKEN_FILE)" ] && TOKEN=file
ADMIN=$(setting ADMIN_CHAT_ID)
if [ -z "$TOKEN" ] || [[ "$TOKEN" == REPLACE* ]] || [ -z "$ADMIN" ] || [ "$ADMIN" = 0 ]; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template."
    echo "Not started: $DIR/config.env needs TELEGRAM_TOKEN and ADMIN_CHAT_ID. Then:"
    echo "  1. put the token from @BotFather in TELEGRAM_TOKEN"
    echo "  2. set -a; . $DIR/config.env; set +a; $DIR/logguard-tg-bot pair     # prints ADMIN_CHAT_ID=..."
    echo "  3. put that line in config.env, then: systemctl enable --now logguard-tg-bot"
    exit 0
fi

start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable -q logguard-tg-bot
systemctl restart logguard-tg-bot
show_start "$start"
if ! systemctl is-active -q logguard-tg-bot; then
    echo "FAILED: logguard-tg-bot is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
echo "OK: logguard-tg-bot is running. Send /status to the bot to check."
# logguard feeds the bot only when its config says so (off by default)
LG=/etc/logguard/logguard.toml
if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*tg_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
    echo "logguard doesn't write to this outbox yet. In [notify] of $LG set"
    echo "  tg_outbox = \"$OUTBOX\""
    echo "  tg_user = \"$BOT\""
    echo "(the weekly abuse report job reads it from there too)"
    echo "then: systemctl restart logguard, and test: logguard -c $LG notify-test --telegram"
fi
