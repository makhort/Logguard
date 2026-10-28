#!/bin/bash
# Installs the bot. Run as root from the directory holding logguard-xmpp-bot,
# logguard-xmpp-bot.service, logguard-xmpp-bot-client.service and logguard-xmpp-bot.logrotate
# (deploy.sh copies them there). BOT_MODE in config.env picks the kind: admin (default) runs
# as the user ejabberd runs as, on the XMPP server; client runs as its own user
# logguard-xmpp-bot, anywhere, with the client unit.
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/logguard-xmpp-bot for that)
#
# (The Python bot can't come back: it only logs in with DIGEST-MD5 or PLAIN, which the
# server no longer offers.)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/logguard-xmpp-bot
UNIT=/etc/systemd/system/logguard-xmpp-bot.service

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    local start=$1
    sleep 5
    echo
    journalctl -u logguard-xmpp-bot --since "$start" --no-pager -o cat | tail -n 5
    echo
    LD=$(grep -E '^LOG_DIR=' "$DIR/config.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'")
    tail -n 15 "${LD:-/var/log/logguard-xmpp-bot}/bot.log" 2>/dev/null || true
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/logguard-xmpp-bot.prev" ] || { echo "no $DIR/logguard-xmpp-bot.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/logguard-xmpp-bot.prev" "$DIR/logguard-xmpp-bot"
    [ -f "$DIR/logguard-xmpp-bot.service.prev" ] && install -m 0644 "$DIR/logguard-xmpp-bot.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart logguard-xmpp-bot
    show_start "$start"
    systemctl --no-pager status logguard-xmpp-bot | head -5
    exit 0
fi

# From the old names: up to 2026-10-17 the bot was /opt/xmpp-bot/xmppbot, run by
# xmpp-bot.service, logging to /var/log/xmpp-bot. Moved over once, keeping its state, OMEMO
# keys and trust pins, avatar, outbox and log; the old unit and logrotate rule go. logguard's
# settings naming the old outbox or unit are updated too (a copy of each file stays next to
# it) and logguard restarted. The XMPP account and OMEMO device stay the same. Safe to run
# again.
OLD_DIR=/opt/xmpp-bot
OLD_UNIT=/etc/systemd/system/xmpp-bot.service
migrated=no
migrate_old_names() {
    [ -e "$OLD_DIR" ] || [ -e "$OLD_UNIT" ] || return 0
    if [ -e "$OLD_DIR" ] && [ -e "$DIR" ]; then
        echo "both $OLD_DIR and $DIR exist: keep one (move what you need into $DIR, remove $OLD_DIR), then run this again" >&2
        exit 1
    fi
    echo "Renaming xmpp-bot to logguard-xmpp-bot (directory, unit, log directory)"
    local clean=no
    if systemctl is-active -q xmpp-bot && [ "$(systemctl show -p NRestarts --value xmpp-bot)" = 0 ]; then
        clean=yes
    fi
    systemctl disable -q --now xmpp-bot 2> /dev/null || true
    if [ -d "$OLD_DIR" ]; then
        mv "$OLD_DIR" "$DIR"
        rm -f "$DIR/xmpp-bot.service.prev" # names the old paths: no rollback target any more
        # the running version becomes the rollback target, as on every install
        if [ "$clean" = yes ] && [ -f "$DIR/xmppbot" ]; then
            mv "$DIR/xmppbot" "$DIR/logguard-xmpp-bot.prev"
            rm -f "$DIR/xmppbot.prev"
        elif [ -f "$DIR/xmppbot.prev" ]; then
            mv "$DIR/xmppbot.prev" "$DIR/logguard-xmpp-bot.prev"
        fi
        rm -f "$DIR/xmppbot"
        if [ -f "$DIR/config.env" ]; then
            cp -p "$DIR/config.env" "$DIR/config.env.pre-rename"
            sed -i -E 's#/opt/xmpp-bot\b#/opt/logguard-xmpp-bot#g; s#/var/log/xmpp-bot\b#/var/log/logguard-xmpp-bot#g' "$DIR/config.env"
            # the old binary (the rollback target) would fall back to the old log directory
            grep -qE '^LOG_DIR=' "$DIR/config.env" || echo "LOG_DIR=/var/log/logguard-xmpp-bot" >> "$DIR/config.env"
        fi
    fi
    if [ -d /var/log/xmpp-bot ] && [ ! -e /var/log/logguard-xmpp-bot ]; then
        mv /var/log/xmpp-bot /var/log/logguard-xmpp-bot
    fi
    rm -f /etc/logrotate.d/xmpp-bot
    # local changes (systemctl edit xmpp-bot) carry over
    if [ -d "$OLD_UNIT.d" ] && [ ! -e "$UNIT.d" ]; then
        mv "$OLD_UNIT.d" "$UNIT.d"
    fi
    rm -f "$OLD_UNIT"
    systemctl daemon-reload
    systemctl reset-failed xmpp-bot 2> /dev/null || true
    migrate_logguard 's#/opt/xmpp-bot\b#/opt/logguard-xmpp-bot#g; s#"xmpp-bot\.service"#"logguard-xmpp-bot.service"#g'
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
                echo "  /opt/xmpp-bot -> $DIR, \"xmpp-bot.service\" -> \"logguard-xmpp-bot.service\"" >&2
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

[ -f "$DIR/config.env" ] || { echo "$DIR/config.env missing" >&2; exit 1; }

setting() { # the value of $1 in config.env, quotes removed
    grep -E "^$1=" "$DIR/config.env" | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true
}

MODE=$(setting BOT_MODE); MODE=${MODE:-admin}

# logguard's [canary] xmpp names (or `except`, with $1 = except) on this host, lower case, one
# per line: from its effective config, where arrays span several lines.
canary_list() {
    [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ] || return 0
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml print-config 2> /dev/null | awk -v key="${1:-xmpp}" '
        /^\[/ { sec = $0; inlist = 0 }
        sec == "[canary]" && $1 == key && $2 == "=" { inlist = 1 }
        inlist {
            line = $0
            while (match(line, /"[^"]*"/)) { print tolower(substr(line, RSTART + 1, RLENGTH - 2)); line = substr(line, RSTART + RLENGTH) }
            if ($0 ~ /\]/) inlist = 0
        }'
}
# Whether the bot's account is a canary there: listed by name or full JID, not excepted.
bot_is_canary() {
    local jid local_part
    jid=$(setting BOT_JID | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')
    local_part=${jid%%@*}
    [ -n "$jid" ] || return 1
    canary_list except | grep -qxF -e "$jid" -e "$local_part" && return 1
    canary_list xmpp | grep -qxF -e "$jid" -e "$local_part"
}
if bot_is_canary; then
    # A canary is an account-level tripwire: one failed login = immediate ban of the address,
    # every login = a critical alert.
    if [ "$MODE" = admin ]; then
        echo "BOT_JID $(setting BOT_JID) is a [canary] xmpp name in /etc/logguard/logguard.toml: every login of" >&2
        echo "  the bot would be a critical alert, and one failed login would ban it. Use another account, or" >&2
        echo "  add the name to [canary] except there (then: systemctl restart logguard)." >&2
        exit 1
    fi
    echo "WARNING: BOT_JID $(setting BOT_JID) is a [canary] xmpp name in this host's logguard config; if the bot's"
    echo "  XMPP server runs logguard with the same list, every login is a critical alert there and one failed"
    echo "  login bans this address. Use another account, or add it to [canary] except on that server."
fi
case $MODE in
    admin) UNIT_SRC=logguard-xmpp-bot.service ;;
    client) UNIT_SRC=logguard-xmpp-bot-client.service ;;
    *) echo "BOT_MODE must be admin or client, not '$MODE'" >&2; exit 1 ;;
esac

# logguard's integrity watch covers the account files: announce what useradd (or a rename)
# wrote, so it is logged instead of raised as a high alert.
announce_accounts() {
    [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ] || return 0
    local f files=()
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do [ -f "$f" ] && files+=("$f"); done
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml expect-change "${files[@]}" 2> /dev/null || true
}

if [ "$MODE" = client ]; then
    # A system user of its own, without a home or a shell: no ejabberd here.
    BOT=logguard-xmpp-bot
    if ! id "$BOT" > /dev/null 2>&1; then
        useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$BOT"
        echo "created the system user $BOT"
        announce_accounts
    fi
    # the admin's OpenPGP public key: root's, the bot only reads it
    PGPKEY=$(setting OPENPGP_KEY)
    if [ -n "$PGPKEY" ] && [ -f "$PGPKEY" ]; then
        chown root:"$BOT" "$PGPKEY"
        chmod 640 "$PGPKEY"
    elif [ -n "$PGPKEY" ]; then
        echo "WARNING: OPENPGP_KEY=$PGPKEY does not exist, so the bot won't start. Export your public"
        echo "  key from OpenKeychain or iPGMail and copy it there (root:$BOT 640), or comment OPENPGP_KEY out."
    fi
else
# The bot runs as the user ejabberd runs as (the unit says User=ejabberd), so that
# ejabberdctl works for it without root.
BOT=ejabberd
HAVE=$(systemctl show -p User --value ejabberd 2>/dev/null || true)
id "$BOT" >/dev/null 2>&1 || { echo "no user '$BOT'" >&2; exit 1; }
if [ -n "$HAVE" ] && [ "$HAVE" != "$BOT" ]; then
    echo "ejabberd runs as '$HAVE', but logguard-xmpp-bot.service runs the bot as '$BOT'" >&2
    exit 1
fi

# ejabberdctl's CTL_OVER_HTTP mode (ejabberdctl.cfg) puts arguments into JSON unescaped:
# line breaks and quotes (announcements, passwords) break commands, and replies with
# non-ASCII text come back empty. The bot needs the classic mode.
CTLCFG=/opt/ejabberd/conf/ejabberdctl.cfg
if grep -qE '^[[:space:]]*CTL_OVER_HTTP=[^[:space:]]' "$CTLCFG" 2>/dev/null; then
    echo "WARNING: CTL_OVER_HTTP is on in $CTLCFG: /maintenance, /restart, multi-line"
    echo "  announcements and replies with non-ASCII text will fail. To turn it off:"
    echo "  sed -i 's/^CTL_OVER_HTTP=/#CTL_OVER_HTTP=/' $CTLCFG"
fi

# /export's JSON file reads ejabberd's database with the sqlite3 tool.
if [ -n "$(setting EJABBERD_DB)" ]; then
    command -v sqlite3 > /dev/null || echo "WARNING: EJABBERD_DB is set but sqlite3 is missing (apt install sqlite3, or dnf install sqlite): /export sends no file"
else
    echo "note: /export sends its full JSON file only with EJABBERD_DB set in config.env, e.g."
    echo "  EJABBERD_DB=/opt/ejabberd/database/example.org.v2.db"
fi
fi

# Owners and modes. The directory is sticky: the bot may replace its own files (state and
# OMEMO keys are written to a temporary file and renamed), but not root's ones. $BOT is
# ejabberd in admin mode, logguard-xmpp-bot in client mode.
#   config.env (the password), omemo-trust.txt, avatar, OPENPGP_KEY
#                                         root:$BOT 640  (the bot reads them)
#   state.json, omemo.json                $BOT 600       (the bot writes them)
#   logguard-xmpp-bot, backups            root
chown root:"$BOT" "$DIR"
chmod 1770 "$DIR"
chown root:"$BOT" "$DIR/config.env"
chmod 640 "$DIR/config.env"
for f in "$DIR/omemo-trust.txt" "$(setting AVATAR_PATH)"; do
    if [ -n "$f" ] && [ -f "$f" ]; then
        chown root:"$BOT" "$f"
        chmod 640 "$f"
    fi
done
for f in "$(setting BOT_STATE_PATH)" "$DIR/state.json" "$DIR/omemo.json" "$(setting OMEMO_STORE)"; do
    if [ -n "$f" ] && [ -f "$f" ]; then
        chown "$BOT:$BOT" "$f"
        chmod 600 "$f"
    fi
done
# leftovers of an interrupted write, possibly root's: the bot could not replace them
rm -f "$DIR"/*.tmp
LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-/var/log/logguard-xmpp-bot}
mkdir -p "$LOGDIR"
chown "$BOT:$BOT" "$LOGDIR"
chmod 700 "$LOGDIR"
# copies from the older, longer rotation (8 weeks): /privacy promises 14 days at most
rm -f "$LOGDIR"/bot.log.[2-9]* "$LOGDIR"/bot.log.1.gz
if [ -f "$LOGDIR/bot.log" ]; then
    chown "$BOT:$BOT" "$LOGDIR/bot.log"
    chmod 600 "$LOGDIR/bot.log"
fi

# Outbox: files for the admin (logguard's weekly abuse report, written by root and handed to
# the bot, which sends them encrypted and deletes them). Sticky like $DIR.
SP=$(setting BOT_STATE_PATH)
OUTBOX=$(setting OUTBOX_DIR); OUTBOX=${OUTBOX:-$(dirname "${SP:-$DIR/state.json}")/outbox}
mkdir -p "$OUTBOX"
chown root:"$BOT" "$OUTBOX"
chmod 1770 "$OUTBOX"
# files waiting there from the other mode's user: the bot could not delete them once sent
find "$OUTBOX" -maxdepth 1 -type f ! -user "$BOT" -exec chown "$BOT:$BOT" {} +
if [ "$MODE" = admin ] && [ "$OUTBOX" != /opt/logguard-xmpp-bot/outbox ]; then
    echo "note: the outbox is $OUTBOX; set ABUSE_REPORT_OUTBOX=$OUTBOX in /etc/default/logguard-abuse-report"
fi

if [ "$MODE" = admin ]; then
    cp -p "$DIR/state.json" "$DIR/state.json.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    chown root:root "$DIR"/state.json.bak-* 2>/dev/null || true
fi
# The running version becomes the rollback target, unless it is failing (restarting).
if [ "$migrated" = yes ]; then
    : # the version running under the old name became it above
elif systemctl is-active -q logguard-xmpp-bot && [ "$(systemctl show -p NRestarts --value logguard-xmpp-bot)" = 0 ]; then
    [ -x "$DIR/logguard-xmpp-bot" ] && cp -p "$DIR/logguard-xmpp-bot" "$DIR/logguard-xmpp-bot.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/logguard-xmpp-bot.service.prev"
else
    echo "logguard-xmpp-bot is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 logguard-xmpp-bot "$DIR/logguard-xmpp-bot"
echo "Installed $("$DIR/logguard-xmpp-bot" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
# logguard's integrity watch covers the unit: announce its new content (logged, not alerted).
if [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ]; then
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml expect-change "$UNIT=logguard-xmpp-bot.service" \
        "/etc/systemd/system/multi-user.target.wants/logguard-xmpp-bot.service=logguard-xmpp-bot.service" 2> /dev/null || true
fi
install -m 0644 "$UNIT_SRC" "$UNIT"
sed "s/^\([[:space:]]*su\) ejabberd ejabberd\$/\1 $BOT $BOT/" logguard-xmpp-bot.logrotate > /etc/logrotate.d/logguard-xmpp-bot
chmod 0644 /etc/logrotate.d/logguard-xmpp-bot
# ejabberd's own log files, 14 days at most like the rest (/privacy). Not when another
# rule already covers them: logrotate refuses duplicate entries.
if [ "$MODE" = client ]; then
    : # no ejabberd here
elif grep -lqs '/opt/ejabberd/logs' /etc/logrotate.d/* 2>/dev/null && ! [ -f /etc/logrotate.d/ejabberd-logs ]; then
    echo "WARNING: another logrotate rule covers /opt/ejabberd/logs; ejabberd-logs not installed:"
    grep -ls '/opt/ejabberd/logs' /etc/logrotate.d/*
else
    install -m 0644 ejabberd-logs.logrotate /etc/logrotate.d/ejabberd-logs
fi
if [ "$MODE" = admin ] && ! grep -qE '^log_rotate_size:[[:space:]]*infinity' /opt/ejabberd/conf/ejabberd.yml 2>/dev/null; then
    echo "note: ejabberd rotates its logs by size itself; for 14 days at most, set"
    echo "  log_rotate_size: infinity   in /opt/ejabberd/conf/ejabberd.yml (logrotate does it then)"
fi
systemctl daemon-reload

# enabled here: a unit renamed from xmpp-bot.service is not yet
systemctl enable -q logguard-xmpp-bot
start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart logguard-xmpp-bot
show_start "$start"
if [ "$MODE" = client ] && systemctl is-active -q logguard-xmpp-bot; then
    echo "OK: logguard-xmpp-bot is running in client mode. Accept its subscription request in your"
    echo "client, and send it /status."
    # logguard feeds the bot only when its config says so (off by default)
    LG=/etc/logguard/logguard.toml
    if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*xmpp_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
        echo "logguard doesn't write to this outbox yet. In [notify] of $LG set"
        echo "  xmpp_outbox = \"$OUTBOX\""
        echo "  xmpp_user = \"$BOT\""
        echo "(the weekly abuse report job reads it from there too)"
        echo "then: systemctl restart logguard, and test: logguard -c $LG notify-test --xmpp"
    fi
elif systemctl is-active -q logguard-xmpp-bot; then
    echo "OK: logguard-xmpp-bot is running. Send /help from Conversations to check."
    if [ ! -s "$DIR/omemo-trust.txt" ] && ! grep -qi '^OMEMO=off' "$DIR/config.env"; then
        echo "OMEMO: no keys pinned yet, so any device of an allowed user is trusted. To pin yours,"
        echo "send /omemo to the bot, then add '<your jid> <fingerprint>' lines to $DIR/omemo-trust.txt"
        echo "(as root; then: chown root:$BOT $DIR/omemo-trust.txt && chmod 640 $DIR/omemo-trust.txt)"
    fi
    echo "ejabberd's side of the login:"
    grep -h "Accepted c2s .* authentication for bot@" /opt/ejabberd/logs/ejabberd.log 2>/dev/null | tail -n 1 || true
else
    echo "FAILED: logguard-xmpp-bot is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
