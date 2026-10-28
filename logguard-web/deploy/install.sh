#!/bin/bash
# Installs logguard-web. Run as root from the directory holding logguard-web,
# logguard-web.service and config.env.example (deploy.sh copies them there).
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/logguard-web for that)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/logguard-web
UNIT=/etc/systemd/system/logguard-web.service
WEB=logguard-web

show_start() { # its first lines in the journal
    local start=$1
    sleep 3
    echo
    journalctl -u logguard-web --since "$start" --no-pager -o cat | tail -n 8
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/logguard-web.prev" ] || { echo "no $DIR/logguard-web.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/logguard-web.prev" "$DIR/logguard-web"
    [ -f "$DIR/logguard-web.service.prev" ] && install -m 0644 "$DIR/logguard-web.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart logguard-web
    show_start "$start"
    systemctl --no-pager status logguard-web | head -5
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

# A system user of its own, without a home or a shell. logguard's [console] socket is given
# to its group.
if ! id "$WEB" > /dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$WEB"
    echo "created the system user $WEB"
    announce_accounts
fi

mkdir -p "$DIR"
first=no
if [ ! -f "$DIR/config.env" ]; then
    install -m 0640 -o root -g "$WEB" config.env.example "$DIR/config.env"
    first=yes
fi

setting() { # the value of $1 in config.env, quotes removed
    grep -E "^$1=" "$DIR/config.env" | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true
}

# Owners and modes: everything root's, the service may only read (it writes nothing).
#   /opt/logguard-web                                        root:logguard-web 750
#   config.env, the web key, the TLS key, password, TOTP,
#   metrics token, the other admins' files                   root:logguard-web 640
#   ADMINS_DIR (the other admins)                            root:logguard-web 750
#   the certificate                                          root:logguard-web 644
chown root:"$WEB" "$DIR"
chmod 750 "$DIR"
chown root:"$WEB" "$DIR/config.env"
chmod 640 "$DIR/config.env"
KEY=$(setting WEB_KEY_FILE); KEY=${KEY:-$DIR/web.key}
CERT=$(setting TLS_CERT); CERT=${CERT:-$DIR/tls.crt}
TLSKEY=$(setting TLS_KEY); TLSKEY=${TLSKEY:-$DIR/tls.key}
PW=$(setting PASSWORD_FILE); PW=${PW:-$DIR/admin.password}
TOTPF=$(setting TOTP_FILE); TOTPF=${TOTPF:-$DIR/admin.totp}
METRICS=$(setting METRICS_TOKEN_FILE)
ADMINS=$(setting ADMINS_DIR); ADMINS=${ADMINS:-$DIR/admins}
if [ -d "$ADMINS" ] && [ "${ADMINS%/*}" = "$DIR" ]; then
    chown root:"$WEB" "$ADMINS"
    chmod 750 "$ADMINS"
    find "$ADMINS" -maxdepth 1 -type f \( -name '*.password' -o -name '*.totp' \) -exec chown root:"$WEB" {} + -exec chmod 640 {} +
fi
for f in "$KEY" "$TLSKEY" "$PW" "$TOTPF" "$METRICS"; do
    # files elsewhere (a Let's Encrypt key) keep their owners: the group must be able to read them
    if [ -n "$f" ] && [ -f "$f" ] && [ "${f%/*}" = "$DIR" ]; then
        chown root:"$WEB" "$f"
        chmod 640 "$f"
    fi
done
if [ -f "$CERT" ] && [ "${CERT%/*}" = "$DIR" ]; then
    chown root:"$WEB" "$CERT"
    chmod 644 "$CERT"
fi

# The running version becomes the rollback target, unless it is failing (restarting).
if systemctl is-active -q logguard-web && [ "$(systemctl show -p NRestarts --value logguard-web)" = 0 ]; then
    [ -x "$DIR/logguard-web" ] && cp -p "$DIR/logguard-web" "$DIR/logguard-web.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/logguard-web.service.prev"
elif [ -f "$UNIT" ]; then
    echo "logguard-web is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 logguard-web "$DIR/logguard-web"
echo "Installed $("$DIR/logguard-web" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
# logguard's integrity watch covers the unit: announce its new content (logged, not alerted).
if [ -x /usr/local/bin/logguard ] && [ -f /etc/logguard/logguard.toml ]; then
    /usr/local/bin/logguard --config /etc/logguard/logguard.toml expect-change "$UNIT=logguard-web.service" \
        "/etc/systemd/system/multi-user.target.wants/logguard-web.service=logguard-web.service" 2> /dev/null || true
fi
install -m 0644 logguard-web.service "$UNIT"
install -o root -g root -m 0644 config.env.example "$DIR/config.env.example"
systemctl daemon-reload

# The console's certificate: a self-signed one for this host's names, the first time.
CONSOLE=$(setting CONSOLE_LISTEN)
if [ -n "$CONSOLE" ] && [ ! -f "$CERT" ] && [ ! -f "$TLSKEY" ] && [ "${CERT%/*}" = "$DIR" ]; then
    names=(--name "$(hostname -f 2> /dev/null || hostname)")
    for ip in $(hostname -I 2> /dev/null); do names+=(--name "$ip"); done
    "$DIR/logguard-web" --tls-cert "$CERT" --tls-key "$TLSKEY" gen-cert "${names[@]}"
    chown root:"$WEB" "$CERT" "$TLSKEY"
    chmod 644 "$CERT"
    chmod 640 "$TLSKEY"
fi

# Not ready yet: placeholders, or a file the settings need
todo=()
AGENT=$(setting AGENT_LISTEN)
ALLOW=$(setting AGENT_ALLOW)
NODES=$(setting NODES)
[ -z "$AGENT" ] && [ -z "$CONSOLE" ] && todo+=("set AGENT_LISTEN (every node) and/or CONSOLE_LISTEN (the console's node) in $DIR/config.env")
[ -n "$AGENT" ] && [[ -z "$ALLOW" || "$ALLOW" == REPLACE* ]] && todo+=("set AGENT_ALLOW in $DIR/config.env: the console's address (or \"any\")")
if [ -n "$AGENT" ] || [ -n "$NODES" ]; then
    [ -f "$KEY" ] || todo+=("the web key: on ONE node  $DIR/logguard-web keygen --out $KEY  then copy that file to every other node's $KEY (not the cluster key)")
fi
if [ -n "$CONSOLE" ]; then
    [ -f "$PW" ] || todo+=("the admin's password:  $DIR/logguard-web passwd")
    if [ "$(setting TOTP)" != off ] && [ ! -f "$TOTPF" ]; then
        todo+=("the one-time codes:  $DIR/logguard-web totp-setup   (scan the QR code with an authenticator app)")
    fi
fi
LG=/etc/logguard/logguard.toml
SOCK=$(setting LOGGUARD_SOCKET)
if [ -n "$SOCK" ] && [ -f "$LG" ] && ! grep -qE "^[[:space:]]*socket[[:space:]]*=[[:space:]]*\"$SOCK\"" "$LG"; then
    todo+=("logguard's console socket: in $LG add
       [console]
       socket = \"$SOCK\"
       group = \"$WEB\"
     then: systemctl restart logguard")
fi
if [ ${#todo[@]} -gt 0 ]; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template."
    echo "Not started yet. To do:"
    for t in "${todo[@]}"; do echo "  - $t"; done
    echo "Then run this script again (it sets the files' owners and modes and starts logguard-web),"
    echo "and check it:  $DIR/logguard-web check"
    exit 0
fi

start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable -q logguard-web
systemctl restart logguard-web
show_start "$start"
if ! systemctl is-active -q logguard-web; then
    echo "FAILED: logguard-web is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
echo "OK: logguard-web is running."
[ -n "$CONSOLE" ] && [ -f "$CERT" ] && echo "Console: https://$CONSOLE  (certificate $("$DIR/logguard-web" --tls-cert "$CERT" fingerprint))"
if [ -f "$LG" ] && ! grep -qE 'apps[[:space:]]*=.*"logguard-web"' "$LG"; then
    echo "logguard can ban addresses that guess the console's password or probe it: in [sources] of $LG"
    echo "add \"logguard-web\" to apps (apps = [\"logguard-web\"]), then: systemctl restart logguard"
fi
