#!/bin/bash
# Weekly abuse report, delivered encrypted by the XMPP admin bot (logguard-xmpp-bot) and, optionally,
# on Telegram by logguard-tg-bot, by mail by logguard-mail-bot, on Signal by logguard-signal-bot, on
# Matrix by logguard-matrix-bot and over XMPP by logguard-xmpp-bot in client mode. Run by
# logguard-abuse-report.timer; settings in /etc/default/logguard-abuse-report.
#
# Every server exports its own report (JSON, every source: --min-events, --top and the
# RDAP --contacts lookups only make sense after merging). Then, by ABUSE_REPORT_ROLE:
#   send   sends it to the cluster peers (logguard cluster-send-report), which keep it in
#          [cluster] inbox: the VPN server
#   merge  merges it with the peers' reports from the inbox (none on a server without
#          cluster peers) and puts the text report in each bot's outbox: logguard-xmpp-bot uploads it
#          encrypted (OMEMO media sharing) and sends it to the admin, logguard-tg-bot and
#          logguard-mail-bot send it encrypted to the admins' OpenPGP keys, logguard-signal-bot,
#          logguard-matrix-bot and the XMPP client bot end-to-end encrypted (else to the
#          OpenPGP key). With
#          ABUSE_REPORT_FORWARD_TO the text report goes to those peers (a relay node). The
#          XMPP server, or any server with a bot
#   relay  sends it to the peers like send, then waits for the merged text report from the
#          merging peer (its ABUSE_REPORT_FORWARD_TO) and puts it in the copy bots' outboxes
#          (Telegram, mail, Signal, Matrix, XMPP client). If none arrives in time (no merging peer), it
#          merges here instead. A node with [notify] xmpp = false that only runs copy bots
#   auto   relay on a node with [notify] xmpp = false and cluster peers, else merge where a
#          bot's outbox exists, else send if there are cluster peers, else off (default)
#   off    nothing
# The bots' outboxes come from logguard's [notify] bot_outbox, tg_outbox, mail_outbox, signal_outbox,
# matrix_outbox and xmpp_outbox (bot_outbox else /opt/logguard-xmpp-bot/outbox, unless xmpp_outbox
# is set: the client bot's is there), unless ABUSE_REPORT_OUTBOX / _TG_OUTBOX / _MAIL_OUTBOX /
# _SIGNAL_OUTBOX / _MATRIX_OUTBOX / _XMPP_OUTBOX say otherwise.
# No copy stays behind here: the work files are in a private directory under /run (tmpfs)
# that is removed on exit; peers' reports are deleted once merged or relayed (on a send
# node, at its next run; or after 8 days); the bot deletes the outbox file once it is sent.
set -euo pipefail

ROLE=${ABUSE_REPORT_ROLE:-auto}
CONFIG=${LOGGUARD_CONFIG:-/etc/logguard/logguard.toml}
SINCE=${ABUSE_REPORT_SINCE:-7d}

LOGGUARD=${LOGGUARD:-/usr/local/bin/logguard}
lg() { "$LOGGUARD" --config "$CONFIG" "$@"; }
effective=$(lg print-config)
setting() { # [section] key from the effective config
    printf '%s\n' "$effective" | awk -v sec="[$1]" -v key="$2" '/^\[/ { s = ($0 == sec) } s && $1 == key { gsub(/"/, "", $3); print $3 }'
}
# Whether this node has cluster peers to send to and hear from.
peered=no
if [ "$(setting cluster enabled)" = true ] \
    && ! printf '%s\n' "$effective" | awk '/^\[/ { s = ($0 == "[cluster]") } s && $0 == "peers = []" { f = 1 } END { exit !f }'; then
    peered=yes
fi

# The XMPP client bot's outbox and user (logguard-xmpp-bot, BOT_MODE=client): logguard's [notify]
# xmpp_outbox and xmpp_user. Empty: no client bot.
XMPP_OUTBOX=${ABUSE_REPORT_XMPP_OUTBOX-$(setting notify xmpp_outbox)}
XMPP_OWNER=${ABUSE_REPORT_XMPP_OWNER:-$(setting notify xmpp_user)}
XMPP_OWNER=${XMPP_OWNER:-logguard-xmpp-bot}
# The XMPP admin bot's outbox and user (logguard-xmpp-bot): logguard's [notify] bot_outbox and
# bot_user. Its default path is the client bot's too: not taken when there is one.
OUTBOX=${ABUSE_REPORT_OUTBOX:-$(setting notify bot_outbox)}
if [ -z "$XMPP_OUTBOX" ]; then
    OUTBOX=${OUTBOX:-/opt/logguard-xmpp-bot/outbox}
fi
OWNER=${ABUSE_REPORT_OWNER:-$(setting notify bot_user)}
OWNER=${OWNER:-ejabberd}
# The Telegram bot's outbox and user (logguard-tg-bot): logguard's [notify] tg_outbox and tg_user.
# Empty: no copy for Telegram.
TG_OUTBOX=${ABUSE_REPORT_TG_OUTBOX-$(setting notify tg_outbox)}
TG_OWNER=${ABUSE_REPORT_TG_OWNER:-$(setting notify tg_user)}
TG_OWNER=${TG_OWNER:-logguard-tg-bot}
# The mail bot's outbox and user (logguard-mail-bot): logguard's [notify] mail_outbox and mail_user.
# Empty: no copy by mail.
MAIL_OUTBOX=${ABUSE_REPORT_MAIL_OUTBOX-$(setting notify mail_outbox)}
MAIL_OWNER=${ABUSE_REPORT_MAIL_OWNER:-$(setting notify mail_user)}
MAIL_OWNER=${MAIL_OWNER:-logguard-mail-bot}
# The Signal bot's outbox and user (logguard-signal-bot): logguard's [notify] signal_outbox and
# signal_user. Empty: no copy on Signal.
SIGNAL_OUTBOX=${ABUSE_REPORT_SIGNAL_OUTBOX-$(setting notify signal_outbox)}
SIGNAL_OWNER=${ABUSE_REPORT_SIGNAL_OWNER:-$(setting notify signal_user)}
SIGNAL_OWNER=${SIGNAL_OWNER:-logguard-signal-bot}
# The Matrix bot's outbox and user (logguard-matrix-bot): logguard's [notify] matrix_outbox and
# matrix_user. Empty: no copy on Matrix.
MATRIX_OUTBOX=${ABUSE_REPORT_MATRIX_OUTBOX-$(setting notify matrix_outbox)}
MATRIX_OWNER=${ABUSE_REPORT_MATRIX_OWNER:-$(setting notify matrix_user)}
MATRIX_OWNER=${MATRIX_OWNER:-logguard-matrix-bot}
# send, relay: the peers (host:port as in [cluster] peers) to send this server's report to.
# Empty: all of them.
SEND_TO=${ABUSE_REPORT_SEND_TO:-}
# merge: peers (host:port as in [cluster] peers) that get the merged text report: Telegram
# relay nodes. Empty: none.
FORWARD_TO=${ABUSE_REPORT_FORWARD_TO:-}
# merge: node ids whose reports to wait for (e.g. "vpn"; they send at the same time).
# Empty: wait for the first one to arrive.
PEERS=${ABUSE_REPORT_PEERS:-}
WAIT_MIN=${ABUSE_REPORT_WAIT_MIN:-15}
# relay: how long to wait for the merged report (the merging node waits WAIT_MIN for its
# peers, then looks up the abuse mailboxes).
RELAY_WAIT_MIN=${ABUSE_REPORT_RELAY_WAIT_MIN:-60}
# merge: look up each network's abuse mailbox (RDAP via rdap.org, ~1 request per second).
CONTACTS=${ABUSE_REPORT_CONTACTS:-yes}
# relay: the largest merged report handed on (unpacked); a week's report is far smaller, and
# a peer's file (one cluster message, 1 MB) could unpack a thousandfold into /run.
MAX_REPORT_BYTES=$((64 << 20))

if [ "$ROLE" = auto ]; then
    if [ "$(setting notify xmpp)" = false ] && [ "$peered" = yes ]; then
        ROLE=relay
    elif [ -d "$OUTBOX" ] || { [ -n "$TG_OUTBOX" ] && [ -d "$TG_OUTBOX" ]; } \
        || { [ -n "$MAIL_OUTBOX" ] && [ -d "$MAIL_OUTBOX" ]; } \
        || { [ -n "$SIGNAL_OUTBOX" ] && [ -d "$SIGNAL_OUTBOX" ]; } \
        || { [ -n "$MATRIX_OUTBOX" ] && [ -d "$MATRIX_OUTBOX" ]; } \
        || { [ -n "$XMPP_OUTBOX" ] && [ -d "$XMPP_OUTBOX" ]; }; then
        ROLE=merge
    elif [ "$peered" = yes ]; then
        ROLE=send
    else
        ROLE=off
    fi
fi
case $ROLE in
    off)
        echo "ABUSE_REPORT_ROLE=off: nothing to do"
        exit 0
        ;;
    send | relay)
        if [ "$peered" = no ]; then
            echo "ABUSE_REPORT_ROLE=$ROLE needs [cluster] peers; use merge (a bot here) or off" >&2
            exit 2
        fi
        ;;
    merge) ;;
    *)
        echo "ABUSE_REPORT_ROLE must be auto, send, merge, relay or off, not '$ROLE'" >&2
        exit 2
        ;;
esac

if [ "$ROLE" = merge ] && [ -n "$FORWARD_TO" ] && [ "$peered" = no ]; then
    echo "WARNING: ABUSE_REPORT_FORWARD_TO is set but [cluster] has no peers; not forwarding"
    FORWARD_TO=
fi

# The bots' outboxes, as dir:owner.
outboxes=()
if [ "$ROLE" = merge ] && [ -n "$OUTBOX" ] && [ -d "$OUTBOX" ]; then
    outboxes+=("$OUTBOX:$OWNER")
fi
if [ "$ROLE" != send ] && [ -n "$TG_OUTBOX" ]; then
    if [ -d "$TG_OUTBOX" ]; then
        outboxes+=("$TG_OUTBOX:$TG_OWNER")
    else
        echo "WARNING: no Telegram bot outbox $TG_OUTBOX ([notify] tg_outbox or ABUSE_REPORT_TG_OUTBOX); no copy for Telegram"
    fi
fi
if [ "$ROLE" != send ] && [ -n "$MAIL_OUTBOX" ]; then
    if [ -d "$MAIL_OUTBOX" ]; then
        outboxes+=("$MAIL_OUTBOX:$MAIL_OWNER")
    else
        echo "WARNING: no mail bot outbox $MAIL_OUTBOX ([notify] mail_outbox or ABUSE_REPORT_MAIL_OUTBOX); no copy by mail"
    fi
fi
if [ "$ROLE" != send ] && [ -n "$SIGNAL_OUTBOX" ]; then
    if [ -d "$SIGNAL_OUTBOX" ]; then
        outboxes+=("$SIGNAL_OUTBOX:$SIGNAL_OWNER")
    else
        echo "WARNING: no Signal bot outbox $SIGNAL_OUTBOX ([notify] signal_outbox or ABUSE_REPORT_SIGNAL_OUTBOX); no copy on Signal"
    fi
fi
if [ "$ROLE" != send ] && [ -n "$MATRIX_OUTBOX" ]; then
    if [ -d "$MATRIX_OUTBOX" ]; then
        outboxes+=("$MATRIX_OUTBOX:$MATRIX_OWNER")
    else
        echo "WARNING: no Matrix bot outbox $MATRIX_OUTBOX ([notify] matrix_outbox or ABUSE_REPORT_MATRIX_OUTBOX); no copy on Matrix"
    fi
fi
if [ "$ROLE" != send ] && [ -n "$XMPP_OUTBOX" ]; then
    if [ -d "$XMPP_OUTBOX" ]; then
        outboxes+=("$XMPP_OUTBOX:$XMPP_OWNER")
    else
        echo "WARNING: no XMPP client bot outbox $XMPP_OUTBOX ([notify] xmpp_outbox or ABUSE_REPORT_XMPP_OUTBOX); no copy over XMPP"
    fi
fi
if [ "$ROLE" = relay ] && [ "${#outboxes[@]}" = 0 ]; then
    echo "relay: set [notify] tg_outbox, mail_outbox, signal_outbox, matrix_outbox or xmpp_outbox (or ABUSE_REPORT_TG_OUTBOX / _MAIL_OUTBOX / _SIGNAL_OUTBOX / _MATRIX_OUTBOX / _XMPP_OUTBOX) to the bot's outbox, and install the bot" >&2
    exit 1
fi
if [ "$ROLE" = merge ] && [ "${#outboxes[@]}" = 0 ] && [ -z "$FORWARD_TO" ]; then
    echo "no bot outbox: ${OUTBOX:-the XMPP admin bot outbox} is missing and there is no copy bot outbox (install a bot first, or set [notify] bot_outbox / tg_outbox / mail_outbox / signal_outbox / matrix_outbox / xmpp_outbox)" >&2
    exit 1
fi

umask 077
work=$(mktemp -d "${ABUSE_REPORT_WORKDIR:-/run}/logguard-abuse.XXXXXX")
trap 'rm -rf "${work:?}"' EXIT
lg abuse-report --since "$SINCE" --json --all --min-events 1 -o "$work/own.json"

INBOX=$(setting cluster inbox)
INBOX=${INBOX:-/var/lib/logguard/inbox}
fresh() { [ -n "$(find "$1" -maxdepth 0 -mmin -120 2> /dev/null)" ]; }
if [ -d "$INBOX" ]; then
    # Reports that were never merged or relayed (this job failed or was off) are not kept;
    # nor on a send node, which never merges: what peers sent there since its last run.
    age=(-mtime +7)
    [ "$ROLE" = send ] && age=()
    find "$INBOX" -maxdepth 1 -type f \( -name 'abuse-*.json.gz' -o -name 'abuse-report-*.txt.gz' \) ${age[@]+"${age[@]}"} -print -delete
fi

if [ "$ROLE" != merge ]; then
    targets=()
    for p in $SEND_TO; do targets+=(--peer "$p"); done
    lg cluster-send-report --name abuse ${targets[@]+"${targets[@]}"} "$work/own.json"
    [ "$ROLE" = send ] && exit 0
fi

# Into each outbox under a dot name first (the bots skip those), owned by the bot so it can
# delete the file once sent (the directory is sticky), then renamed into place.
deliver() { # report file, what it says about its origin
    local dir owner name
    name="abuse-report-$(date -u +%Y-%m-%d).txt"
    for entry in ${outboxes[@]+"${outboxes[@]}"}; do
        dir=${entry%:*}
        owner=${entry##*:}
        # Mode first, owner last: `install -o` chowns before it chmods, and a file root no longer
        # owns can't be chmodded without CAP_FOWNER, which the unit doesn't keep (CAP_CHOWN only).
        rm -f "${dir:?}/.$name.tmp"
        install -m 0600 "$1" "$dir/.$name.tmp"
        chown "$owner:" "$dir/.$name.tmp"
        mv -f "$dir/.$name.tmp" "$dir/$name"
        echo "report for the bot: $dir/$name ($(wc -c < "$dir/$name" | tr -d " ") bytes, $2)"
    done
}

# Merges this server's report with the peers' fresh ones from the inbox (deleting those)
# and delivers it.
merge_here() { # what to say about it, besides the number of peer reports
    local f peers=() contacts=()
    for f in "$INBOX"/abuse-*.json.gz; do
        if [ -f "$f" ] && fresh "$f"; then
            peers+=("$f")
        elif [ -f "$f" ]; then
            echo "left out $f: older than 2 hours (not this week's)"
        fi
    done
    [ "$CONTACTS" = no ] || contacts=(--contacts)
    lg abuse-report --merge "$work/own.json" ${peers[@]+"${peers[@]}"} ${contacts[@]+"${contacts[@]}"} -o "$work/report.txt"
    rm -f ${peers[@]+"${peers[@]}"}
    deliver "$work/report.txt" "${#peers[@]} peer reports merged$1"
}

if [ "$ROLE" = relay ]; then
    merged() {
        local f
        for f in "$INBOX"/abuse-report-*.txt.gz; do
            [ -f "$f" ] && fresh "$f" && echo "$f" && return 0
        done
        return 1
    }
    deadline=$((SECONDS + RELAY_WAIT_MIN * 60))
    until merged > /dev/null || [ "$SECONDS" -ge "$deadline" ]; do
        sleep 30
    done
    report=$(merged) || report=
    if [ -n "$report" ]; then
        if gzip -dc "$report" | head -c "$MAX_REPORT_BYTES" > "$work/report.txt" \
            && [ "$(wc -c < "$work/report.txt")" -lt "$MAX_REPORT_BYTES" ]; then
            deliver "$work/report.txt" "merged on $(basename "$report" .txt.gz | sed 's/^abuse-report-//')"
            rm -f "$report"
            # the peers' own reports were merged there
            find "$INBOX" -maxdepth 1 -type f -name 'abuse-*.json.gz' -delete 2> /dev/null || true
            exit 0
        fi
        echo "WARNING: $report is damaged or larger than $((MAX_REPORT_BYTES >> 20)) MB unpacked; merging here instead"
        rm -f "$report"
    else
        # No merging peer (no XMPP server in this cluster), or it failed: merge here.
        echo "WARNING: no merged report arrived within $RELAY_WAIT_MIN minutes (no merging peer, or its" \
            "ABUSE_REPORT_FORWARD_TO isn't set); merging here (ABUSE_REPORT_ROLE=merge skips the wait)"
    fi
    merge_here ", merged here"
    exit 0
fi

if [ "$peered" = no ]; then
    # a server on its own: nothing to wait for
    merge_here ""
    exit 0
fi

# merge: the peers send at the same time: wait for the ones named, or for the first one.
arrived() {
    local p f
    if [ -n "$PEERS" ]; then
        for p in $PEERS; do
            fresh "$INBOX/abuse-$p.json.gz" || return 1
        done
        return 0
    fi
    for f in "$INBOX"/abuse-*.json.gz; do
        [ -f "$f" ] && fresh "$f" && return 0
    done
    return 1
}
deadline=$((SECONDS + WAIT_MIN * 60))
until arrived || [ "$SECONDS" -ge "$deadline" ]; do
    sleep 30
done
for p in $PEERS; do
    fresh "$INBOX/abuse-$p.json.gz" || echo "WARNING: no report from $p this week; the report covers the other servers only"
done
arrived || [ -n "$PEERS" ] || echo "WARNING: no peer report arrived within $WAIT_MIN minutes; the report covers this server only"

merge_here ""
if [ -n "$FORWARD_TO" ]; then
    targets=()
    for p in $FORWARD_TO; do targets+=(--peer "$p"); done
    lg cluster-send-report --name abuse-report "${targets[@]}" "$work/report.txt"
fi
