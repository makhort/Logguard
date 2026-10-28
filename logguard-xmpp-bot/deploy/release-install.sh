#!/bin/bash
# Installs or upgrades logguard-xmpp-bot from this release bundle: the admin bot on the XMPP
# server (ejabberd installed), or the client bot (BOT_MODE=client) on any host. Unzip it
# there, then as root:
#
#   ./install.sh             install, or upgrade (the running version becomes the rollback one)
#   ./install.sh --client    the same; on the first install, with the client mode's template
#   ./install.sh rollback    back to the previous version
#   ./install.sh --check     only check the bundle's files (needs no root)
#
# The first install puts files/config.env.example (with --client: files/config-client.env.example)
# in place as /opt/logguard-xmpp-bot/config.env and stops: fill it in (the bot's account, the
# admin, ...), then run this again (README.md, "Settings", "Client mode").
# It copies the bundle to a directory only root can write, checks every file against
# SHA256SUMS there, and runs files/install.sh from it, as deploy/deploy.sh does over SSH.
set -euo pipefail

DIR=/opt/logguard-xmpp-bot

usage() { sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; }
die() { echo "install.sh: $*" >&2; exit 1; }

template=files/config.env.example
if [ "${1:-}" = --client ]; then
    template=files/config-client.env.example
    shift
fi
case ${1:-} in
    "" | rollback | --check) ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
cd "$(dirname "$0")"
command -v sha256sum > /dev/null || die "sha256sum is missing (coreutils)"
if [ "${1:-}" = --check ]; then
    sha256sum -c --quiet --strict SHA256SUMS || die "files don't match SHA256SUMS: a damaged or altered bundle"
    echo "Bundle OK"
    exit 0
fi
[ "$(id -u)" = 0 ] || die "run as root:  sudo ./install.sh"
[ "$(uname -s)" = Linux ] || die "this bundle is for Linux"
command -v systemctl > /dev/null || die "the bot runs as a systemd service: no systemctl here"

# The unzipped files may belong to another user, who could swap them while this runs:
# a copy only root can write, checked there, is what gets installed.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
while read -r _ f; do
    # SHA256SUMS comes from the same untrusted directory: plain relative names only
    [[ $f =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)?$ ]] || die "odd name in SHA256SUMS: $f"
    mkdir -p "$work/$(dirname "$f")"
    cp -p -- "$f" "$work/$f"
done < SHA256SUMS
cp SHA256SUMS "$work/"
cd "$work"
sha256sum -c --quiet --strict SHA256SUMS || die "files don't match SHA256SUMS: a damaged or altered bundle"
# One bundle per architecture (TARGET: x86_64, aarch64 or armv7 hard-float): its program must run here.
files/logguard-xmpp-bot --version > /dev/null 2>&1 || die "this bundle is for $(cat TARGET); this machine is $(uname -m): use its own bundle"

if [ "${1:-}" != rollback ]; then
    # (/opt/xmpp-bot: the bot's old name; files/install.sh moves it over, config.env included)
    if [ ! -f "$DIR/config.env" ] && [ ! -e /opt/xmpp-bot ]; then
        if [ "$template" = files/config.env.example ] && ! id ejabberd > /dev/null 2>&1; then
            die "no user 'ejabberd': the admin bot runs on the XMPP server, as the user ejabberd runs as. For the client bot (any host): ./install.sh --client"
        fi
        # root's until files/install.sh gives the bot's user (by BOT_MODE) read access
        mkdir -p "$DIR"
        chmod 0700 "$DIR"
        install -m 0600 -o root -g root "$template" "$DIR/config.env"
        echo "New $DIR/config.env from the template; the bot isn't installed yet."
        echo "Fill it in (BOT_JID, BOT_PASSWORD, ADMIN_JID, ...), then run this again."
        exit 0
    fi
    if [ -f "$DIR/config.env" ] && grep -qE '^[A-Z_]+=REPLACE' "$DIR/config.env"; then
        die "$DIR/config.env still has placeholders: $(grep -oE '^[A-Z_]+=REPLACE' "$DIR/config.env" | cut -d= -f1 | xargs)"
    fi
fi

bash files/install.sh "$@"
