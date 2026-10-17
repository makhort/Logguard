#!/bin/bash
# Installs or upgrades logguard from this release bundle. Unzip it on the server, then as root:
#
#   ./install.sh                       upgrade; or, on a new server, put the config template
#                                      in place (/etc/logguard/logguard.toml) to edit first
#   ./install.sh --template NAME       the template a new server starts from: one of configs/
#                                      (logguard.toml: XMPP server, the default; logguard-standalone.toml:
#                                      SSH and UFW only; logguard-tg.toml: Telegram relay node)
#   ./install.sh --config FILE         a new server's finished config: installs it at once
#   ./install.sh --cluster-key FILE    the cluster key of the other nodes (their
#                                      /etc/logguard/cluster.key), for a node joining them
#   ./install.sh --check               only check the bundle's files (needs no root)
#
# It copies the bundle to a directory only root can write, checks every file against
# SHA256SUMS there, and runs files/install.sh from it, as deploy/deploy.sh does over SSH: the
# binary to /usr/local/bin (the previous one stays as logguard.prev), the units, timers and
# logrotate rule, the config check (and on upgrades config-diff against the new template),
# the cluster port in ufw for the peers, and the service restarted.
# A config with [cluster] enabled and no key on this server yet gets a new key: copy
# /etc/logguard/cluster.key to the other nodes (--cluster-key there).
set -euo pipefail

CONF=/etc/logguard/logguard.toml
KEY=/etc/logguard/cluster.key

usage() { sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; }
die() { echo "install.sh: $*" >&2; exit 1; }
abs() { case $1 in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac; }

template="" config="" cluster_key="" check=no
while [ $# -gt 0 ]; do
    case $1 in
        --template) [ $# -ge 2 ] || die "--template needs a name"; template=$2; shift 2 ;;
        --config) [ $# -ge 2 ] || die "--config needs a file"; config=$(abs "$2"); shift 2 ;;
        --cluster-key) [ $# -ge 2 ] || die "--cluster-key needs a file"; cluster_key=$(abs "$2"); shift 2 ;;
        --check) check=yes; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[ -z "$config" ] || [ -f "$config" ] || die "no file $config"
[ -z "$cluster_key" ] || [ -f "$cluster_key" ] || die "no file $cluster_key"
cd "$(dirname "$0")"

command -v sha256sum > /dev/null || die "sha256sum is missing (coreutils)"
if [ "$check" = yes ]; then
    sha256sum -c --quiet --strict SHA256SUMS || die "files don't match SHA256SUMS: a damaged or altered bundle"
    echo "Bundle OK: $(files/logguard --version 2> /dev/null || echo logguard)"
    exit 0
fi
[ "$(id -u)" = 0 ] || die "run as root:  sudo ./install.sh"
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die "this bundle is for Linux on x86_64"
command -v systemctl > /dev/null || die "logguard runs as a systemd service: no systemctl here"

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
bin=$work/files/logguard

setting() { # the value of $2 in section [$1] of config $3, as logguard reads it
    "$bin" --config "$3" print-config \
        | awk -v sec="[$1]" -v key="$2" '/^\[/ { s = ($0 == sec) } s && $1 == key { gsub(/"/, "", $3); print $3 }'
}
template_named() {
    local t
    for t in "configs/$1" "configs/$1.toml" "configs/logguard-$1.toml"; do
        [ -f "$t" ] && { echo "$t"; return; }
    done
    die "no template '$1' in configs/: $(cd configs && echo *)"
}

# The template: named, or the one for this server's node id (upgrades), or logguard.toml.
if [ -n "$template" ]; then
    tpl=$(template_named "$template")
else
    tpl=configs/logguard.toml
    if [ -f "$CONF" ]; then
        node=$(setting cluster node_id "$CONF" 2> /dev/null || true)
        for t in configs/*.toml; do
            if [ -n "$node" ] && [ "$(setting cluster node_id "$t")" = "$node" ]; then tpl=$t; fi
        done
    fi
fi

if [ -f "$CONF" ]; then
    # files/install.sh keeps it, saves the template next to it as logguard.toml.new and
    # shows what the upgrade changes (config-diff)
    [ -z "$config" ] || echo "note: keeping the existing $CONF; $config is saved as logguard.toml.new"
    staged=${config:-$tpl}
    effective=$CONF
elif [ -n "$config" ]; then
    staged=$config
    effective=$config
else
    install -d -m 0755 /etc/logguard
    install -m 0644 "$tpl" "$CONF"
    "$bin" --config "$CONF" print-config > /dev/null
    echo "New server: $CONF is the template ${tpl#configs/} now; nothing else is installed yet."
    echo "Edit it for this server: [allowlist] (your own addresses), [notify], [cluster] (node_id,"
    echo "peers; or enabled = false), [digest] certs, ... It starts in mode = \"shadow\" (decides and"
    echo "logs, bans nothing). Then run this again:  sudo ./install.sh"
    echo "(a node joining others:  sudo ./install.sh --cluster-key FILE, their /etc/logguard/cluster.key)"
    exit 0
fi
"$bin" --config "$staged" print-config > /dev/null || die "$staged: not a valid config (above)"
cp "$staged" files/logguard.toml

generated=no
if [ -f "$KEY" ]; then
    if [ -n "$cluster_key" ] && ! cmp -s "$cluster_key" "$KEY"; then
        echo "note: keeping the existing $KEY (not $cluster_key); to change keys on every node,"
        echo "      see README.md, \"Rotating the key\""
    fi
elif [ -n "$cluster_key" ]; then
    install -m 0600 "$cluster_key" files/cluster.key
elif [ "$(setting cluster enabled "$effective")" = true ]; then
    (umask 077; "$bin" cluster-keygen > files/cluster.key)
    generated=yes
fi

bash files/install.sh

if [ "$generated" = yes ]; then
    echo
    echo "New cluster key: $KEY. Every node needs the same one: copy it to the other nodes"
    echo "(as root, mode 0600) and install there with  sudo ./install.sh --cluster-key FILE"
fi
