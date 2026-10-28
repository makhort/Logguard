#!/usr/bin/env bash
#
# harden-vps.sh: harden SSH on a clean VPS running Debian/Ubuntu (apt) or Fedora,
# RHEL, AlmaLinux, Rocky and the like (dnf). Run it from your laptop.
#
# Over the VPS's current root login it:
#   0. upgrades all packages and installs what's missing: the firewall (ufw on apt,
#      firewalld on dnf; whichever is already active wins), openssh-sftp-server,
#      SELinux's semanage
#   1. sets a random root password (the second stage: `su - root`)
#   2. creates a random gateway user, the only user allowed to log in
#      (or, with -g, adopts the user an earlier hardening by hand left)
#   3. gives it a root-owned home with a single writable folder, ~/xfer
#   4. installs your public key in /etc/ssh/authorized_keys/<user>
#   5. lets only the gateway user `su` to root (pam_wheel, group gw-su)
#   6. installs the allowlist wrapper (su / sftp only)
#   7. moves conflicting files out of /etc/ssh/sshd_config.d
#   8. writes sshd_config (new port, pubkey only, allowed tunnels only)
#   9. with SELinux on: labels the new port ssh_port_t and relabels the new files
#  10. opens the needed ports in the firewall
#  11. validates and applies the config
# Then it tests the new login from here (sftp, refused commands, su to root)
# and only after that commits (12: closes the old port; for an adopted user, moves
# its old ~/.ssh keys to the backup, locks its password, takes it out of sudo groups).
# If anything fails or you press Ctrl-C, the old sshd config is restored at once; if
# the server can't be reached, a timer on the server restores it after ROLLBACK_MINUTES.
#
# A server hardened partly by hand (root login off, no sudo, root only by `su` from a
# user with keys in ~/.ssh): --su copies the server part over sftp as that user, you
# run it in your `su - root` session (one pasted line), and commit there later. With
# -g the same user stays the gateway user; root's password stays as it is.
#
# Examples:
#   ./harden-vps.sh -i 203.0.113.10 -k ~/.ssh/id_vps1_gateway.pub -p 2222 \
#       -n vps1 --aio=18080 --wg=18521
# A Fedora/Rocky/Alma cloud image without root login (its user needs passwordless sudo):
#   ./harden-vps.sh -i 203.0.113.11 -k ~/.ssh/id_vps2_gateway.pub -p 2222 -u fedora
# Partly hardened by hand, SSH on 2222, user "admin" with su:
#   ./harden-vps.sh -i 203.0.113.12 -k ~/.ssh/id_vps3.pub -P 2222 -p 2222 \
#       -u admin -g admin --su

set -euo pipefail

# ---- Settings -----------------------------------------------------------------
SSH_PORT=22                 # SSH port of the VPS now (-P)
SSH_LOGIN_USER=root         # who can log in there now (-u; non-root needs passwordless sudo or --su)
ROLLBACK_MINUTES=10         # server restores the old sshd config unless committed in time
SU_ROLLBACK_MINUTES=20      # the same with --su (two sessions where you type the root password)
GW_NAME_LEN=24              # random part of the gateway user name ("g" + 24 chars, max 31)
ROOT_PW_BYTES=35            # root password = openssl rand -base64 ROOT_PW_BYTES

AIO_PANEL_PORT=8080         # Nextcloud AIO admin page on the server (--aio)
WG_PANEL_PORT=51821          # WireGuard panel on the server (--wg)
SSH_FW_COMMENT="SSH"                         # ufw comment for the new SSH port
OLD_SSH_FW_COMMENT="SSH (temporary)"         # ufw comment for SSH_PORT until commit
# Public ports opened in the firewall: one "port/proto  comment" per line
# (firewalld has no comments; they are only printed).
AIO_PUBLIC_PORTS="
80/tcp      Nextcloud HTTP
443/tcp     Nextcloud HTTPS
443/udp     Nextcloud HTTP/3
3478/tcp    Nextcloud Talk
3478/udp    Nextcloud Talk"                  # opened with --aio
WG_PUBLIC_PORTS="
51820/udp   WireGuard"                       # opened with --wg
EXTRA_PUBLIC_PORTS=""                        # always opened, e.g. "25/tcp  Mail"
# --------------------------------------------------------------------------------

ports_of() { awk 'NF { print $1 }' <<<"$1" | paste -sd ' ' -; }

usage() {
    cat <<EOF
usage: ${0##*/} -i IP -k PUBKEY -p NEW_PORT [-P PORT] [-n NAME] [-u USER] [--su]
                [-g USER [--keep-keys]] [--aio[=LOCAL]] [--wg[=LOCAL]] [-t SRC:DEST]...
                [--no-firewall] [--dry-run]

  -i IP          the VPS's IP address
  -k PUBKEY      public key for the gateway user, e.g. ~/.ssh/id_vps1_gateway.pub
  -p NEW_PORT    SSH port to switch to (may be the current one)
  -P PORT        SSH port now (default $SSH_PORT)
  -n NAME        alias for ~/.ssh/config (default: vps-<ip>)
  -u USER        who logs in now (default $SSH_LOGIN_USER); not root: needs passwordless
                 sudo, e.g. fedora, rocky or almalinux on cloud images, or --su
  --su           USER has no sudo, root comes from su: copy the server part over sftp
                 and run it in your su session; commit there too. Root's password stays
  -g USER        make this existing user the gateway user instead of a new random one
                 (e.g. the one an earlier hardening by hand set up); its ~/.ssh keys go
                 to the backup at commit, only PUBKEY is installed
  --keep-keys    with -g: also install its other ~/.ssh keys, each restricted like PUBKEY
  --aio[=LOCAL]  tunnel to Nextcloud AIO admin: server port $AIO_PANEL_PORT -> local LOCAL
                 (default $AIO_PANEL_PORT); also opens $(ports_of "$AIO_PUBLIC_PORTS")
  --wg[=LOCAL]   tunnel to the WireGuard panel: server port $WG_PANEL_PORT -> local LOCAL
                 (default $WG_PANEL_PORT); also opens $(ports_of "$WG_PUBLIC_PORTS")
  -t SRC:DEST    any other tunnel: server port SRC -> local port DEST (repeatable)
  --no-firewall  don't install or configure the firewall (ufw, or firewalld on dnf)
  --dry-run      print the server script and the ssh config; change nothing
EOF
}

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }
ok()   { printf '    ok  %s\n' "$*"; }
is_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 )); }

T_SRC=() T_DEST=() T_URL=()
add_tunnel() {  # server_port local_port [url_scheme]
    local src=$1 dest=$2 scheme=$3 i
    is_port "$src"  || die "bad server port: $src"
    is_port "$dest" || die "bad local port: $dest"
    for ((i = 0; i < ${#T_DEST[@]}; i++)); do
        [[ ${T_DEST[i]} != "$dest" ]] || die "local port $dest is used twice"
    done
    T_SRC+=("$src")
    T_DEST+=("$dest")
    T_URL+=("${scheme:+$scheme://}localhost:$dest")
}

# ---- Arguments ------------------------------------------------------------------
IP="" PUB="" NEW_PORT="" NAME="" FIREWALL=1 DRY_RUN=0 PUBLIC_PORTS=$EXTRA_PUBLIC_PORTS
GW_ADOPT="" KEEP_KEYS=0 SU_MODE=0
while (( $# )); do
    case $1 in
        -i|-k|-p|-P|-n|-u|-g|-t)
            (( $# >= 2 )) || die "$1 needs a value"
            case $1 in
                -i) IP=$2 ;;
                -k) PUB=$2 ;;
                -p) NEW_PORT=$2 ;;
                -P) SSH_PORT=$2 ;;
                -n) NAME=$2 ;;
                -u) SSH_LOGIN_USER=$2 ;;
                -g) GW_ADOPT=$2 ;;
                -t) [[ $2 =~ ^([0-9]+):([0-9]+)$ ]] || die "-t wants SRC:DEST, got: $2"
                    add_tunnel "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "" ;;
            esac
            shift 2 ;;
        --aio|--aio=*)
            v=${1#--aio}; v=${v#=}
            add_tunnel "$AIO_PANEL_PORT" "${v:-$AIO_PANEL_PORT}" https
            PUBLIC_PORTS+=$'\n'"$AIO_PUBLIC_PORTS"
            shift ;;
        --wg|--wg=*)
            v=${1#--wg}; v=${v#=}
            add_tunnel "$WG_PANEL_PORT" "${v:-$WG_PANEL_PORT}" http
            PUBLIC_PORTS+=$'\n'"$WG_PUBLIC_PORTS"
            shift ;;
        --no-firewall) FIREWALL=0; shift ;;
        --keep-keys) KEEP_KEYS=1; shift ;;
        --su) SU_MODE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

[[ -n $IP && -n $PUB && -n $NEW_PORT ]] || { usage >&2; exit 1; }
[[ $IP =~ ^[A-Za-z0-9.:-]+$ ]] || die "bad IP: $IP"
is_port "$NEW_PORT" || die "bad port: $NEW_PORT"
is_port "$SSH_PORT" || die "bad SSH_PORT: $SSH_PORT"
NAME=${NAME:-vps-${IP//[.:]/-}}
[[ $NAME =~ ^[A-Za-z0-9._-]+$ ]] || die "bad name: $NAME"
USER_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$'   # hex names (an id) start with a digit
[[ $SSH_LOGIN_USER =~ $USER_RE ]] || die "bad user: $SSH_LOGIN_USER"
if [[ -n $GW_ADOPT ]]; then
    [[ $GW_ADOPT =~ $USER_RE && $GW_ADOPT != root ]] || die "bad gateway user: $GW_ADOPT"
fi
(( !KEEP_KEYS )) || [[ -n $GW_ADOPT ]] || die "--keep-keys goes with -g"
(( !SU_MODE )) || [[ $SSH_LOGIN_USER != root ]] || die "--su needs -u, the user that runs su"

PUB=${PUB/#\~/$HOME}
[[ -f $PUB ]] || die "no such file: $PUB"
PUB="$(cd "$(dirname "$PUB")" && pwd)/$(basename "$PUB")"
PUBKEY=$(grep -m1 -E '^(ssh-|ecdsa-|sk-)' "$PUB") || die "$PUB is not a public key (pass the .pub file)"
ssh-keygen -l -f "$PUB" >/dev/null 2>&1 || die "not a valid public key: $PUB"
# The private key next to it, or the .pub itself (works for agent-held and FIDO keys).
if [[ $PUB == *.pub && -f ${PUB%.pub} ]]; then KEY_ID=${PUB%.pub}; else KEY_ID=$PUB; fi

# ---- Generated values -------------------------------------------------------------
rand_alnum() { LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c "$1" || true; }
ADOPT=0
if [[ -n $GW_ADOPT ]]; then
    ADOPT=1 GW_USER=$GW_ADOPT
else
    GW_USER="g$(rand_alnum "$GW_NAME_LEN")"
    (( ${#GW_USER} == GW_NAME_LEN + 1 )) || die "could not generate the user name"
fi
ROOT_PW="" STAGE=""
if (( SU_MODE )); then
    ROLLBACK_MINUTES=$SU_ROLLBACK_MINUTES
    STAGE=$(rand_alnum 16)
    (( ${#STAGE} == 16 )) || die "could not generate the upload folder name"
    STAGE=/tmp/ssh-harden.$STAGE         # the login user's upload folder (--su)
else
    ROOT_PW=$(openssl rand -base64 "$ROOT_PW_BYTES" | tr -d '\n')
    [[ -n $ROOT_PW ]] || die "could not generate the root password"
fi
TS=$(date +%Y%m%d-%H%M%S)
B=/root/ssh-harden-$TS               # backup, rollback and commit scripts on the server
UNIT=ssh-harden-rollback-$TS         # systemd timer that rolls back

PERMIT_OPEN="" KEY_OPTS="restrict,pty"
if (( ${#T_SRC[@]} )); then
    KEY_OPTS+=",port-forwarding"
    for ((i = 0; i < ${#T_SRC[@]}; i++)); do
        [[ " $PERMIT_OPEN " == *" 127.0.0.1:${T_SRC[i]} "* ]] && continue
        PERMIT_OPEN+="${PERMIT_OPEN:+ }127.0.0.1:${T_SRC[i]}"
        KEY_OPTS+=",permitopen=\"127.0.0.1:${T_SRC[i]}\""
    done
fi
SUDO=""
if [[ $SSH_LOGIN_USER != root ]] && (( !SU_MODE )); then SUDO="sudo -n "; fi

# ---- Server script (steps 1-8, 10, 11) --------------------------------------------
build_remote() {
    printf '%s=%q\n' \
        GW_USER "$GW_USER" ROOT_PW "$ROOT_PW" PUBKEY "$PUBKEY" KEY_OPTS "$KEY_OPTS" \
        NEW_PORT "$NEW_PORT" SSH_PORT "$SSH_PORT" PERMIT_OPEN "$PERMIT_OPEN" \
        FIREWALL "$FIREWALL" PUBLIC_PORTS "$PUBLIC_PORTS" \
        SSH_FW_COMMENT "$SSH_FW_COMMENT" OLD_SSH_FW_COMMENT "$OLD_SSH_FW_COMMENT" \
        ROLLBACK_MINUTES "$ROLLBACK_MINUTES" B "$B" UNIT "$UNIT" \
        GW_ADOPT "$ADOPT" KEEP_KEYS "$KEEP_KEYS" STAGE "$STAGE"
    cat <<'REMOTE'
set -euo pipefail

# Everything is inside main so bash reads the whole script before running any
# of it; nothing below can swallow the rest of the script from stdin.
main() {
    exec </dev/null
    export DEBIAN_FRONTEND=noninteractive
    local WRAPPER=/usr/local/bin/gateway-shell f p cmt want T FWD
    local PKG SFTP USEPAM LOGFAC INCLUDES SELINUX=0 FW=none ZONE="" REBOOT=0 newest

    say()  { printf '    [server] %s\n' "$*"; }
    fail() { printf '    [server] ERROR: %s\n' "$*" >&2; exit 1; }
    restore() { /bin/sh "$B/rollback.sh" "$B" >/dev/null 2>&1 || true; }
    restart_ssh() {
        systemctl daemon-reload
        if systemctl is-active --quiet ssh.socket; then
            # Ubuntu 22.10+: the listening port comes from ssh.socket.
            # Existing sessions survive (KillMode=process).
            systemctl stop ssh.service || true
            systemctl restart ssh.socket
        elif systemctl cat ssh.service >/dev/null 2>&1; then
            systemctl restart ssh.service       # Debian/Ubuntu
        else
            systemctl restart sshd.service      # Fedora/RHEL
        fi
    }

    # ---- Checks
    [ "$(id -u)" -eq 0 ] || fail "must run as root"
    local H G
    if [ "$GW_ADOPT" = 1 ]; then
        id "$GW_USER" >/dev/null 2>&1 || fail "user $GW_USER doesn't exist"
        [ "$(id -u "$GW_USER")" -ne 0 ] || fail "$GW_USER is root"
        H=$(getent passwd "$GW_USER" | cut -d: -f6)
        case $H in
            /|"") fail "$GW_USER has no home of its own" ;;
            *"'"*) fail "$GW_USER's home has a quote in its name: $H" ;;
        esac
        if [ ! -d "$H" ] || [ -L "$H" ]; then fail "$GW_USER's home $H is not a directory"; fi
    else
        if id "$GW_USER" >/dev/null 2>&1; then fail "user $GW_USER already exists"; fi
        H=/home/$GW_USER
    fi
    if [ -f /etc/debian_version ] && command -v apt-get >/dev/null; then
        PKG=apt SFTP=/usr/lib/openssh/sftp-server USEPAM=no LOGFAC=AUTH
    elif command -v dnf >/dev/null; then
        # Fedora/RHEL don't support "UsePAM no" (their sshd_config says so): it skips
        # pam_selinux, pam_loginuid (audit) and pam_systemd. With pubkey-only auth PAM
        # runs only its account and session stacks. AUTHPRIV keeps sshd's log in
        # /var/log/secure, as their stock config does.
        PKG=dnf SFTP=/usr/libexec/openssh/sftp-server USEPAM=yes LOGFAC=AUTHPRIV
    else
        fail "only Debian/Ubuntu (apt) and Fedora/RHEL-like (dnf) systems are supported"
    fi
    command -v systemd-run >/dev/null || fail "systemd is required"
    command -v sshd >/dev/null || fail "openssh-server is not installed"
    [ -x /bin/su ] || fail "/bin/su not found"
    if [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = 1 ]; then
        fail "FIPS mode is on: sshd can't use the ed25519 host key this script relies on"
    fi
    if systemctl is-active --quiet sshd.socket; then
        # Fedora's socket unit has its own ListenStream, which the new Port doesn't change.
        fail "sshd.socket is active; switch to sshd.service first (systemctl disable --now sshd.socket; systemctl enable --now sshd.service)"
    fi
    [ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
    if command -v selinuxenabled >/dev/null && selinuxenabled; then SELINUX=1; fi
    if [ "$FIREWALL" = 1 ]; then
        # Never run two firewalls: an active one wins, else the family's usual one.
        if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then FW=ufw
        elif systemctl is-active --quiet firewalld; then FW=firewalld
        elif [ "$PKG" = apt ]; then FW=ufw
        else FW=firewalld
        fi
    fi

    # ---- Packages: full upgrade, then what's missing (before anything is changed).
    local pkgs=""
    say "upgrading packages (this can take a few minutes)"
    if [ "$PKG" = apt ]; then
        # Keep existing config files on upgrade; restart services without asking (Ubuntu needrestart).
        export NEEDRESTART_MODE=a
        local apt_opts="-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
        apt-get update -qq || fail "apt-get update failed"
        # shellcheck disable=SC2086
        {
            apt-get upgrade $apt_opts &&
            apt-get dist-upgrade $apt_opts &&
            apt-get autoremove $apt_opts
        } >/dev/null || fail "package upgrade failed"
        [ -x "$SFTP" ] || pkgs="$pkgs openssh-sftp-server"
    else
        # rpm keeps changed config files itself (new ones land in *.rpmnew).
        {
            dnf -y -q upgrade --refresh &&
            dnf -y -q autoremove
        } >/dev/null || fail "package upgrade failed"
    fi
    if [ "$FW" = ufw ] && ! command -v ufw >/dev/null; then pkgs="$pkgs ufw"; fi
    if [ "$FW" = firewalld ] && ! command -v firewall-cmd >/dev/null; then pkgs="$pkgs firewalld"; fi
    if [ "$SELINUX" = 1 ] && ! command -v semanage >/dev/null; then pkgs="$pkgs policycoreutils-python-utils"; fi
    if [ -n "$pkgs" ]; then
        say "installing$pkgs"
        if [ "$PKG" = apt ]; then
            # shellcheck disable=SC2086
            apt-get install $apt_opts $pkgs >/dev/null || fail "could not install$pkgs"
        else
            # shellcheck disable=SC2086
            dnf -y -q install $pkgs >/dev/null || fail "could not install$pkgs"
        fi
    fi
    [ -x "$SFTP" ] || fail "no sftp server at $SFTP"
    case $FW in
        ufw) command -v ufw >/dev/null || fail "ufw is not available" ;;
        firewalld) command -v firewall-cmd >/dev/null || fail "firewalld is not available" ;;
    esac
    if [ "$SELINUX" = 1 ]; then command -v semanage >/dev/null || fail "semanage is not available"; fi

    # ---- Backup and rollback script
    say "backup in $B"
    mkdir -m 0700 "$B" "$B/sshd_config.d"
    cp -a /etc/ssh/sshd_config "$B/sshd_config"
    cp -a /etc/pam.d/su "$B/pam-su"
    printf "GW_USER='%s' GW_HOME='%s' GW_ADOPT='%s' UNIT='%s'\n" "$GW_USER" "$H" "$GW_ADOPT" "$UNIT" >"$B/state"
    if [ "$GW_ADOPT" = 1 ]; then
        printf "GW_SHELL='%s' GW_OWNER='%s' GW_MODE='%s'\n" "$(getent passwd "$GW_USER" | cut -d: -f7)" \
            "$(stat -c %u:%g "$H")" "$(stat -c %a "$H")" >>"$B/state"
        if [ -f "/etc/ssh/authorized_keys/$GW_USER" ]; then
            cp -a "/etc/ssh/authorized_keys/$GW_USER" "$B/authorized_keys"
        fi
    fi
    cat >"$B/rollback.sh" <<'EOF'
#!/bin/sh
# Restores the sshd and su config saved by harden-vps.sh. Usage: rollback.sh BACKUP_DIR
B=$1
. "$B/state"
cp -a "$B/sshd_config" /etc/ssh/sshd_config
for f in "$B"/sshd_config.d/*.conf; do
    [ -e "$f" ] && cp -a "$f" /etc/ssh/sshd_config.d/
done
cp -a "$B/pam-su" /etc/pam.d/su
if [ "$GW_ADOPT" = 1 ]; then
    # the adopted user's shell, home and key file as they were
    [ -z "$GW_SHELL" ] || usermod -s "$GW_SHELL" "$GW_USER"
    chown "$GW_OWNER" "$GW_HOME" && chmod "$GW_MODE" "$GW_HOME"
    [ ! -f "$B/authorized_keys" ] || cp -a "$B/authorized_keys" "/etc/ssh/authorized_keys/$GW_USER"
fi
systemctl daemon-reload
if systemctl is-active --quiet ssh.socket; then
    systemctl stop ssh.service || true
    systemctl restart ssh.socket
elif systemctl cat ssh.service >/dev/null 2>&1; then
    systemctl restart ssh.service
else
    systemctl restart sshd.service
fi
logger -t ssh "restored sshd config from $B"
EOF
    chmod 0700 "$B/rollback.sh"
    # Run by the local side (or by hand with --su) once the new login works. Whatever an
    # old login could still need waits for it: the adopted user's old keys, password and
    # sudo groups. commit-fw.sh (step 10) closes the old port.
    cat >"$B/commit.sh" <<'EOF'
#!/bin/sh
# Keeps the sshd config written by harden-vps.sh. Usage: commit.sh BACKUP_DIR [--mark]
B=$1
. "$B/state"
if systemctl is-active --quiet "$UNIT.timer"; then
    systemctl stop "$UNIT.timer"
else
    echo "too late: the rollback timer fired and the old sshd config is back" >&2
    exit 1
fi
[ ! -f "$B/commit-fw.sh" ] || . "$B/commit-fw.sh"
# gw-su: this gateway user only
for u in $(getent group gw-su | cut -d: -f4 | tr , ' '); do
    [ "$u" = "$GW_USER" ] || gpasswd -d "$u" gw-su >/dev/null
done
if [ "$GW_ADOPT" = 1 ]; then
    # Its old keys (sshd no longer reads them) to the backup. The home is root's now, so
    # ~/.ssh can't be swapped for a link any more; check it wasn't one before.
    if [ -d "$GW_HOME/.ssh" ] && [ ! -L "$GW_HOME/.ssh" ]; then
        mkdir -p "$B/home-ssh"
        for f in "$GW_HOME/.ssh/authorized_keys" "$GW_HOME/.ssh/authorized_keys2"; do
            if [ -e "$f" ] || [ -L "$f" ]; then mv "$f" "$B/home-ssh/"; fi
        done
    fi
    usermod -p '*' "$GW_USER"
    for g in sudo wheel admin; do
        if id -nG "$GW_USER" | tr ' ' '\n' | grep -qx "$g"; then gpasswd -d "$GW_USER" "$g" >/dev/null; fi
    done
fi
logger -t ssh "harden-vps.sh: sshd config committed ($B)"
echo "committed"
# --mark: tell the local side, which reads ~/xfer as the gateway user (mkdir follows no link)
if [ "${2-}" = --mark ]; then mkdir "$GW_HOME/xfer/.ssh-harden-committed"; fi
EOF
    chmod 0700 "$B/commit.sh"
    : >"$B/commit-fw.sh"

    # ---- 1. Root password (--su: root's password stays, it's how you got here)
    if [ -n "$ROOT_PW" ]; then
        say "setting the root password"
        printf 'root:%s\n' "$ROOT_PW" | chpasswd
    else
        say "keeping the root password"
    fi

    # ---- 2. Gateway user
    if [ "$GW_ADOPT" = 1 ]; then
        # /bin/sh runs the forced wrapper without reading any of the user's dotfiles
        # (bash started by sshd reads ~/.bashrc even for a command).
        say "adopting user $GW_USER (home $H)"
        usermod -s /bin/sh "$GW_USER"
    else
        say "creating user $GW_USER"
        useradd -M -U -d "$H" -s /bin/sh "$GW_USER"
        usermod -p '*' "$GW_USER"
    fi
    G=$(id -gn "$GW_USER")

    # ---- 3. Home: owned by root, one writable folder. An adopted home becomes root's
    # first, so the user can't swap ~/xfer for a link while it is checked.
    if [ "$GW_ADOPT" = 1 ]; then
        chown root:"$G" "$H"
        chmod 0750 "$H"
        if [ -L "$H/xfer" ] || { [ -e "$H/xfer" ] && [ ! -d "$H/xfer" ]; }; then
            mv "$H/xfer" "$B/home-xfer"
            say "moved $H/xfer (not a directory) to $B/home-xfer"
        fi
    else
        install -d -o root -g "$G" -m 0750 "$H"
    fi
    install -d -o "$GW_USER" -g "$G" -m 0700 "$H/xfer"

    # ---- 4. Authorized keys: root's file, every line restricted
    install -d -o root -g root -m 0755 /etc/ssh/authorized_keys
    {
        printf '%s %s\n' "$KEY_OPTS" "$PUBKEY"
        if [ "$KEEP_KEYS" = 1 ]; then
            set --
            for f in "$H/.ssh/authorized_keys" "$H/.ssh/authorized_keys2"; do
                if [ -f "$f" ] && [ ! -L "$f" ]; then set -- "$@" "$f"; fi
            done
            # type and key only: old options (no restrict) and comments are dropped
            if [ $# -gt 0 ]; then
                awk -v opts="$KEY_OPTS" -v skip="$(printf '%s\n' "$PUBKEY" | awk '{ print $2 }')" '
                    /^[[:space:]]*(#|$)/ { next }
                    { for (i = 1; i < NF; i++)
                        if ($i ~ /^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$/ && $(i + 1) ~ /^AAAA/) {
                            if ($(i + 1) != skip && !seen[$(i + 1)]++) print opts, $i, $(i + 1)
                            break
                        } }' "$@"
            fi
        fi
    } >"/etc/ssh/authorized_keys/$GW_USER"
    chown root:root "/etc/ssh/authorized_keys/$GW_USER"
    chmod 0644 "/etc/ssh/authorized_keys/$GW_USER"
    say "$(grep -c . "/etc/ssh/authorized_keys/$GW_USER") key(s) in /etc/ssh/authorized_keys/$GW_USER"

    # ---- 5. Only the gateway user may su to root
    getent group gw-su >/dev/null || { say "creating group gw-su"; groupadd gw-su; }
    usermod -aG gw-su "$GW_USER"
    # Other active pam_wheel lines (set up by hand for wheel or sudo) would add their own
    # group's demand, or skip the password (trust): only gw-su's stays.
    sed -i -E '/^[[:space:]]*auth[[:space:]].*pam_wheel\.so/{/group=gw-su/!s/^/#harden-vps.sh# /;}' /etc/pam.d/su
    # use_uid: check who runs su, not the utmp login name (getlogin), which not every
    # system keeps.
    grep -qE '^auth.*pam_wheel\.so.* group=gw-su' /etc/pam.d/su ||
        sed -i '/pam_rootok.so/a auth       required   pam_wheel.so use_uid group=gw-su' /etc/pam.d/su
    grep -qE '^auth.*pam_wheel\.so.* group=gw-su' /etc/pam.d/su || fail "could not add pam_wheel to /etc/pam.d/su"

    # ---- 6. Wrapper (sftp clients send the Subsystem path as the command)
    cat >"$WRAPPER" <<EOF
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
src=\${SSH_CLIENT%% *}

case "\${SSH_ORIGINAL_COMMAND-}" in
    "")
        logger -t ssh -p authpriv.notice "su attempt from \$src"
        exec /bin/su - root
        ;;
    "$SFTP")
        logger -t ssh -p authpriv.notice "sftp from \$src"
        exec $SFTP -l INFO -f $LOGFAC -d %d/xfer
        ;;
    *)
        logger -t ssh -p authpriv.warning "denied from \$src: \$SSH_ORIGINAL_COMMAND"
        echo "Not permitted." >&2
        exit 1
        ;;
esac
EOF
    chown root:root "$WRAPPER"
    chmod 0755 "$WRAPPER"

    # ---- 7. Move conflicting files out of sshd_config.d (first value wins)
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [ -e "$f" ] || continue
        if grep -qiE '^[[:space:]]*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|AuthenticationMethods|AuthorizedKeysFile|UsePAM|AllowUsers|AllowGroups|DenyUsers|DenyGroups|ForceCommand|Match|AllowTcpForwarding|PermitOpen)[[:space:]]' "$f"; then
            mv "$f" "$B/sshd_config.d/"
            say "moved $f to $B/sshd_config.d/"
        fi
    done
    # Fedora/RHEL: the system-wide crypto policy comes in by an Include in
    # 50-redhat.conf (moved above for UsePAM) or 40-redhat-crypto-policies.conf.
    INCLUDES="Include /etc/ssh/sshd_config.d/*.conf"
    if [ -f /etc/crypto-policies/back-ends/opensshserver.config ] &&
        ! grep -qs crypto-policies /etc/ssh/sshd_config.d/*.conf; then
        INCLUDES="$INCLUDES
Include /etc/crypto-policies/back-ends/opensshserver.config"
    fi

    # ---- 8. sshd_config
    if [ -n "$PERMIT_OPEN" ]; then
        FWD="    AllowTcpForwarding local
    PermitOpen $PERMIT_OPEN
    PermitListen none"
    else
        FWD="    AllowTcpForwarding no
    PermitOpen none
    PermitListen none"
    fi
    cat >/etc/ssh/sshd_config <<EOF
# Written by harden-vps.sh; original in $B
$INCLUDES

Port $NEW_PORT
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility $LOGFAC
LogLevel VERBOSE

LoginGraceTime 30s
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60

AllowUsers $GW_USER
AuthenticationMethods publickey
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/authorized_keys/%u
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
UsePAM $USEPAM

ClientAliveInterval 300
ClientAliveCountMax 2

AllowAgentForwarding no
AllowStreamLocalForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no
PermitUserRC no
PermitUserEnvironment no
PrintMotd no

Subsystem sftp $SFTP

Match User $GW_USER
    ForceCommand $WRAPPER
    PermitTTY yes
$FWD
EOF

    # ---- 9. SELinux: sshd may only bind ports labelled ssh_port_t; new files get
    # the labels their paths call for (not their parent directory's).
    if [ "$SELINUX" = 1 ]; then
        if ! semanage port -l | awk -v p="$NEW_PORT" '
                $1 == "ssh_port_t" && $2 == "tcp" { for (i = 3; i <= NF; i++) { sub(",", "", $i); if ($i == p) f = 1 } }
                END { exit !f }'; then
            say "SELinux: labelling port $NEW_PORT/tcp ssh_port_t"
            # -m when the port already has another type (e.g. 8080, http_cache_port_t)
            semanage port -a -t ssh_port_t -p tcp "$NEW_PORT" 2>/dev/null ||
                semanage port -m -t ssh_port_t -p tcp "$NEW_PORT" || {
                restore
                fail "could not label port $NEW_PORT for sshd; old config restored"
            }
        fi
        restorecon -R /etc/ssh/authorized_keys "$H" "$WRAPPER"
    fi

    # ---- 11a. Validate before touching the running sshd
    install -d -m 0755 /run/sshd
    if ! sshd -t; then
        restore
        fail "sshd -t rejected the new config; old config restored"
    fi
    T=$(sshd -T -C "user=$GW_USER,host=test,addr=127.0.0.1")
    for want in "port $NEW_PORT" "permitrootlogin no" "passwordauthentication no" \
                "authenticationmethods publickey" "allowusers $GW_USER" \
                "authorizedkeysfile /etc/ssh/authorized_keys/%u" "forcecommand $WRAPPER"; do
        if ! grep -qix -- "$want" <<<"$T"; then
            restore
            fail "effective config lacks '$want' (overridden by another file?); old config restored"
        fi
    done
    say "config valid"

    # ---- 10. Firewall (the current port stays open until commit.sh runs
    # commit-fw.sh)
    fw_each() {  # runs fw_allow port/proto comment for every port to open
        fw_allow "$SSH_PORT/tcp" "$OLD_SSH_FW_COMMENT"
        fw_allow "$NEW_PORT/tcp" "$SSH_FW_COMMENT"
        while read -r p cmt; do
            if [ -n "$p" ]; then fw_allow "$p" "${cmt:-$p}"; fi
        done <<EOF
$PUBLIC_PORTS
EOF
    }
    case $FW in
    ufw)
        fw_allow() {
            say "ufw: allow $1  # $2"
            ufw allow "$1" comment "$2" >/dev/null
        }
        fw_each
        ufw --force enable >/dev/null
        if [ "$NEW_PORT" != "$SSH_PORT" ]; then
            # Delete with the same comment; fall back to the plain rule if it's still listed.
            cat >"$B/commit-fw.sh" <<EOF
ufw delete allow $SSH_PORT/tcp comment '$OLD_SSH_FW_COMMENT' >/dev/null 2>&1
if ufw status | grep -q '^$SSH_PORT/tcp '; then ufw delete allow $SSH_PORT/tcp >/dev/null; fi
EOF
        fi
        ;;
    firewalld)
        if ! systemctl is-active --quiet firewalld; then
            # Open the ports before the first start, so it never blocks them.
            ZONE=$(firewall-offline-cmd --get-default-zone)
            fw_allow() { firewall-offline-cmd -q --zone="$ZONE" --add-port="$1" >/dev/null 2>&1 || true; }
            fw_each
            say "starting firewalld"
            systemctl enable --now firewalld >/dev/null 2>&1 || fail "could not start firewalld"
        fi
        # The zone of the interface with the default route, else the default zone.
        p=$(ip route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
        ZONE=""
        if [ -n "$p" ]; then ZONE=$(firewall-cmd --get-zone-of-interface="$p" 2>/dev/null) || ZONE=""; fi
        [ -n "$ZONE" ] || ZONE=$(firewall-cmd --get-default-zone)
        fw_allow() {
            say "firewalld ($ZONE): allow $1  # $2"
            firewall-cmd -q --zone="$ZONE" --add-port="$1" &&
                firewall-cmd -q --permanent --zone="$ZONE" --add-port="$1" ||
                fail "firewall-cmd could not open $1"
        }
        fw_each
        if [ "$NEW_PORT" != "$SSH_PORT" ]; then
            {
                printf 'firewall-cmd -q --zone=%s --remove-port=%s/tcp\n' "$ZONE" "$SSH_PORT"
                printf 'firewall-cmd -q --permanent --zone=%s --remove-port=%s/tcp\n' "$ZONE" "$SSH_PORT"
            } >"$B/commit-fw.sh"
        fi
        if [ "$NEW_PORT" != 22 ] && firewall-cmd -q --zone="$ZONE" --query-service=ssh; then
            # The stock zones open the ssh service (22), which nothing listens on after commit.
            {
                printf 'firewall-cmd -q --zone=%s --remove-service=ssh\n' "$ZONE"
                printf 'firewall-cmd -q --permanent --zone=%s --remove-service=ssh\n' "$ZONE"
            } >>"$B/commit-fw.sh"
        fi
        if firewall-cmd -q --zone="$ZONE" --query-service=cockpit; then
            say "NOTE: zone $ZONE opens Cockpit (9090/tcp); to close it:"
            say "      firewall-cmd --permanent --zone=$ZONE --remove-service=cockpit; firewall-cmd --reload"
        fi
        ;;
    esac

    # ---- 11b. Arm the rollback timer, then apply
    systemd-run --quiet --unit="$UNIT" --on-active="${ROLLBACK_MINUTES}min" \
        /bin/sh "$B/rollback.sh" "$B"
    say "rollback armed: old config returns in $ROLLBACK_MINUTES min unless committed"
    restart_ssh
    sleep 2
    if [ -z "$(ss -Htln "sport = :$NEW_PORT")" ]; then
        systemctl stop "$UNIT.timer" || true
        restore
        fail "sshd is not listening on $NEW_PORT; old config restored"
    fi
    say "sshd listens on $NEW_PORT"
    [ ! -f /var/run/reboot-required ] || REBOOT=1
    # dnf has no flag file: a newer kernel than the running one needs a reboot.
    if [ "$PKG" = dnf ] &&
        newest=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-core 2>/dev/null | sort -V | tail -n 1) &&
        [ -n "$newest" ] && [ "$newest" != "$(uname -r)" ]; then
        REBOOT=1
    fi
    if [ "$REBOOT" = 1 ]; then
        say "NOTE: the upgrade needs a reboot; do it after this script finishes (su - root, reboot)"
    fi
    # --su: tell the local side, which reads the staging folder over sftp
    if [ -n "$STAGE" ]; then mkdir "$STAGE/ok" 2>/dev/null || true; fi
}

main
REMOTE
}

# ---- ~/.ssh/config lines ------------------------------------------------------------
print_config() {
    local idf=$KEY_ID i
    if [[ $idf == "$HOME"/* ]]; then idf="~/${idf#"$HOME"/}"; fi
    if (( ${#T_SRC[@]} )); then
        cat <<'EOF'
# Shared by all *-tunnel aliases (add once; SessionType needs OpenSSH 8.7+):
Host *-tunnel
    SessionType none
    ExitOnForwardFailure yes
    ServerAliveInterval 60

EOF
    fi
    printf '# --- VPS %s ---\n' "$NAME"
    if (( ${#T_SRC[@]} )); then
        printf 'Host %s-tunnel\n' "$NAME"
        for ((i = 0; i < ${#T_SRC[@]}; i++)); do
            printf '    LocalForward 127.0.0.1:%s 127.0.0.1:%s\n' "${T_DEST[i]}" "${T_SRC[i]}"
        done
        printf '\nHost %s %s-tunnel\n' "$NAME" "$NAME"
    else
        printf 'Host %s\n' "$NAME"
    fi
    printf '    HostName %s\n    Port %s\n    User %s\n    IdentityFile %s\n    IdentitiesOnly yes\n' \
        "$IP" "$NEW_PORT" "$GW_USER" "$idf"
}

if (( DRY_RUN )); then
    info "Server script${ROOT_PW:+ (contains the new root password)}"
    build_remote
    info "SSH config"
    print_config
    exit 0
fi

for c in ssh sftp ssh-keygen openssl; do
    command -v "$c" >/dev/null || die "$c not found"
done

# ---- Connections ----------------------------------------------------------------------
CTL_DIR=$(mktemp -d /tmp/harden.XXXXXX)
ROOT_CTL=$CTL_DIR/root
GW_CTL=$CTL_DIR/gw
ARMED=0 COMMITTED=0

rssh() { ssh -o ControlPath="$ROOT_CTL" -p "$SSH_PORT" "$SSH_LOGIN_USER@$IP" "$@"; }
rrun() { printf '%s\n' "$1" | rssh "${SUDO}sh -s"; }
rsftp() { sftp -q -b - -o ControlPath="$ROOT_CTL" -P "$SSH_PORT" "$SSH_LOGIN_USER@$IP"; }
gssh() { ssh -o ControlPath="$GW_CTL" -p "$NEW_PORT" -o IdentitiesOnly=yes -i "$KEY_ID" "$@"; }
gsftp() { sftp -q -b - -o ControlPath="$GW_CTL" -P "$NEW_PORT" "$GW_USER@$IP"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | awk '{ print $1 }'; }
rollback_now() {
    rrun "systemctl stop $UNIT.timer 2>/dev/null; [ -f $B/rollback.sh ] && /bin/sh $B/rollback.sh $B"
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if (( ARMED && !COMMITTED )); then
        printf '\n==> Not committed: restoring the old sshd config on the server\n' >&2
        if (( SU_MODE )); then
            printf '    it restores itself within %s minutes of the setup; now, as root: /bin/sh %s/rollback.sh %s\n' \
                "$ROLLBACK_MINUTES" "$B" "$B" >&2
        elif rollback_now >/dev/null 2>&1; then
            printf '    restored; %s login on port %s works as before\n' "$SSH_LOGIN_USER" "$SSH_PORT" >&2
        else
            printf '    could not reach the server; it restores itself within %s minutes\n' "$ROLLBACK_MINUTES" >&2
        fi
    fi
    if [[ -n $STAGE && -S $ROOT_CTL ]]; then
        printf -- '-rm %s/server.sh\n-rmdir %s/ok\n-rmdir %s\n' "$STAGE" "$STAGE" "$STAGE" | rsftp >/dev/null 2>&1 || true
    fi
    ssh -o ControlPath="$GW_CTL" -O exit "$GW_USER@$IP" 2>/dev/null || true
    ssh -o ControlPath="$ROOT_CTL" -O exit "$SSH_LOGIN_USER@$IP" 2>/dev/null || true
    rm -rf "$CTL_DIR"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

info "Connecting to $SSH_LOGIN_USER@$IP:$SSH_PORT (this session stays open until the end)"
ssh -o ControlMaster=yes -o ControlPath="$ROOT_CTL" -o ControlPersist=no -fN \
    -p "$SSH_PORT" "$SSH_LOGIN_USER@$IP" || die "cannot log in to $SSH_LOGIN_USER@$IP:$SSH_PORT"

info "Configuring the server"
if (( SU_MODE )); then
    # Over sftp only (the login may refuse commands); you run it as root. It is copied to
    # root's own folder and checked there, so the login user can't change what root runs.
    build_remote >"$CTL_DIR/server.sh"
    printf 'mkdir %s\nchmod 700 %s\nput %s %s/server.sh\n' "$STAGE" "$STAGE" "$CTL_DIR/server.sh" "$STAGE" |
        rsftp >/dev/null || die "could not upload over sftp as $SSH_LOGIN_USER (--su needs sftp)"
    R=/root/ssh-harden-$TS.sh
    cat <<EOF
    Uploaded to $STAGE/server.sh. Log in below and become root (su - root, unless the
    login does it). At the root prompt, paste this line and wait for "sshd listens on":

        cp $STAGE/server.sh $R && echo '$(sha256 <"$CTL_DIR/server.sh")  $R' | sha256sum -c --quiet && bash $R; rm -f $R

    Then type: exit (twice if you used su yourself)

EOF
    ssh -t -o ControlPath="$ROOT_CTL" -p "$SSH_PORT" "$SSH_LOGIN_USER@$IP" || true
    printf 'rmdir %s/ok\n' "$STAGE" | rsftp >/dev/null 2>&1 ||
        die "the server part didn't finish (its output above says why); if it armed the rollback, the old config returns within $ROLLBACK_MINUTES minutes"
    ARMED=1
    ok "server part done; rollback armed for $ROLLBACK_MINUTES minutes"
    printf 'get /etc/ssh/ssh_host_ed25519_key.pub %s/hostkey\n' "$CTL_DIR" | rsftp >/dev/null 2>&1 || true
    HOSTKEY=$(awk '{ print $1, $2 }' "$CTL_DIR/hostkey" 2>/dev/null || true)
else
    ARMED=1
    build_remote | rssh "${SUDO}bash -s" || die "server setup failed"
    HOSTKEY=$(rssh cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1, $2}')
fi

# The host key comes over the authenticated session, so it can be trusted for the new
# port without a fingerprint prompt.
[[ $HOSTKEY == "ssh-ed25519 "* ]] || die "could not read the server's ed25519 host key"
KH_HOST=$IP
[[ $NEW_PORT == 22 ]] || KH_HOST="[$IP]:$NEW_PORT"
[[ -d ~/.ssh ]] || mkdir -m 0700 ~/.ssh
if ! ssh-keygen -F "$KH_HOST" 2>/dev/null | grep -qF "${HOSTKEY#ssh-ed25519 }"; then
    [[ $NEW_PORT == 22 || $NEW_PORT == "$SSH_PORT" ]] || ssh-keygen -R "$KH_HOST" >/dev/null 2>&1 || true
    printf '%s %s\n' "$KH_HOST" "$HOSTKEY" >>~/.ssh/known_hosts
fi

info "Logging in as $GW_USER on port $NEW_PORT (enter your key passphrase if asked)"
gssh -o ControlMaster=yes -o ControlPersist=no -fN "$GW_USER@$IP" ||
    die "key login as $GW_USER failed"
ok "key login works"

out=$(printf 'pwd\n' | gsftp 2>&1) || die "sftp failed: $out"
[[ $out == *"/xfer"* ]] || die "sftp started in the wrong directory: $out"
ok "sftp/scp works and starts in ~/xfer"

rc=0; out=$(gssh "$GW_USER@$IP" id 2>&1) || rc=$?
[[ $rc == 1 && $out == *"Not permitted."* ]] || die "remote commands are not refused (exit $rc): $out"
ok "remote commands are refused"

rc=0; out=$(ssh -p "$NEW_PORT" -o ControlPath=none -o BatchMode=yes -o PubkeyAuthentication=no \
    "$GW_USER@$IP" true 2>&1) || rc=$?
[[ $rc == 255 && $out == *"Permission denied (publickey)"* ]] || die "server offers more than public key auth: $out"
ok "only public key authentication is offered"

rc=0; out=$(ssh -p "$NEW_PORT" -o ControlPath=none -o BatchMode=yes "root@$IP" true 2>&1) || rc=$?
[[ $rc == 255 && $out == *"Permission denied"* ]] || die "root login is not refused: $out"
ok "root login is refused"

if (( SU_MODE )); then
    cat <<EOF

==> Second stage: su to root, and commit
    At the 'Password:' prompt, enter root's password (unchanged). At the root prompt,
    run this line, then type: exit

        sh $B/commit.sh $B --mark
EOF
else
    cat <<EOF

==> Second stage: su to root
    Root password (save it in your password manager NOW):

        $ROOT_PW

    At the 'Password:' prompt, paste it. At the root prompt, type: exit
EOF
fi
for attempt in 1 2 3; do
    rc=0; gssh -t "$GW_USER@$IP" || rc=$?
    (( rc == 0 )) && break
    printf '    su exited with %s (wrong password?)\n' "$rc"
done
(( rc == 0 )) || die "su to root did not succeed"
ok "su to root works"

info "Committing"
if (( SU_MODE )); then
    printf 'rmdir .ssh-harden-committed\n' | gsftp >/dev/null 2>&1 ||
        die "not committed: as root, run  sh $B/commit.sh $B  before the rollback timer fires"
else
    rrun "/bin/sh $B/commit.sh $B" >/dev/null ||
        die "the rollback timer already fired (over $ROLLBACK_MINUTES min); run the script again"
fi
COMMITTED=1
ok "rollback timer cancelled"
if (( FIREWALL )) && [[ $NEW_PORT != "$SSH_PORT" ]]; then ok "port $SSH_PORT closed in the firewall"; fi
if (( ADOPT )); then ok "$GW_USER: old ~/.ssh keys moved to $B/home-ssh, password locked, out of sudo groups"; fi

info "Done"
cat <<EOF
    Gateway user:   $GW_USER
    Root password:  ${ROOT_PW:-unchanged}
    Server backup:  $B
EOF
for ((i = 0; i < ${#T_URL[@]}; i++)); do
    printf '    Tunnel:         %s  (server port %s)\n' "${T_URL[i]}" "${T_SRC[i]}"
done

info "Add to ~/.ssh/config"
print_config
