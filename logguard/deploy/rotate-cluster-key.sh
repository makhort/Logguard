#!/bin/bash
# Replaces the cluster key on every node without a moment in which two nodes can't read
# each other: logguard also accepts the keys in <key_file>.next and <key_file>.prev.
# Three rounds, each finished on every node before the next:
#
#   ./deploy/rotate-cluster-key.sh start  xmpp vpn   # new key as <key_file>.next everywhere
#   ./deploy/rotate-cluster-key.sh switch xmpp vpn   # send with it; the old one becomes .prev
#   ./deploy/rotate-cluster-key.sh finish xmpp vpn   # drop the old key
#
# Like deploy.sh, this only copies files (ssh host aliases, default: xmpp vpn) to a fresh
# /tmp/logguard-rotate.XXXX on each node; then paste the printed command into a root shell
# on each node (it checks the files, runs the step and restarts logguard).
set -euo pipefail
cd "$(dirname "$0")/.."

step=${1:-}
shift || true
hosts=("$@")
[ ${#hosts[@]} -gt 0 ] || hosts=(xmpp vpn)
case "$step" in
    start | switch | finish) ;;
    *)
        sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac

key=deploy/cluster.key
logguard() { cargo run --quiet --release -- "$@"; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
if [ "$step" = start ]; then
    if [ ! -f "$key.next" ]; then
        (umask 077 && logguard cluster-keygen > "$key.next.tmp" && mv "$key.next.tmp" "$key.next")
        echo "New key: $key.next (git-ignored)"
    fi
    cp "$key.next" "$stage/new.key"
    chmod 600 "$stage/new.key"
fi
# The fingerprint each node must end up with: the new key (still .next here until 'finish').
if [ -f "$key.next" ]; then
    expect=$(logguard cluster-key-id --file "$key.next" | cut -d' ' -f1)
else
    expect=$(logguard cluster-key-id --file "$key" | cut -d' ' -f1)
fi

# Run on the node as root, from the private directory it was copied into.
cat > "$stage/rotate.sh" <<'REMOTE'
set -euo pipefail
step=${1:-}
expect=@EXPECT@
dir=$(cd "$(dirname "$0")" && pwd)
# the key copy goes, whatever happens (stage the step again to retry)
trap 'rm -rf "$dir"' EXIT
if [ "$(id -u)" != 0 ]; then
    echo "run this as root (it installs the key and restarts logguard)" >&2
    exit 1
fi
cfg=/etc/logguard/logguard.toml
kf=$(logguard -c "$cfg" print-config | awk '/^\[/ { s = ($0 == "[cluster]") } s && $1 == "key_file" { gsub(/"/, "", $3); print $3 }')
if [ -z "$kf" ]; then
    echo "no [cluster] key_file in $cfg (rotation needs the key in a file)" >&2
    exit 1
fi
case "$step" in
    start)
        [ -f "$dir/new.key" ] || { echo "no new key next to this script: stage 'start' again" >&2; exit 1; }
        install -m 600 -o root -g root "$dir/new.key" "$kf.next"
        ;;
    switch)
        if [ -f "$kf.next" ]; then
            cp -p "$kf" "$kf.prev"
            mv "$kf.next" "$kf"
        elif [ -f "$kf.prev" ]; then
            echo "already switched here"
            step=none
        else
            echo "no $kf.next - run 'start' on this node first" >&2
            exit 1
        fi
        ;;
    finish)
        if [ -f "$kf.next" ]; then
            echo "$kf.next is still there - run 'switch' on this node first" >&2
            exit 1
        fi
        rm -f "$kf.prev"
        ;;
    *)
        echo "usage: bash $0 start|switch|finish" >&2
        exit 2
        ;;
esac
if [ "$step" != none ]; then
    systemctl restart logguard
    sleep 2
    systemctl is-active --quiet logguard || { echo "logguard did not start: journalctl -u logguard -n 30" >&2; exit 1; }
fi
ids=$(logguard -c "$cfg" cluster-key-id)
echo "$ids"
if printf '%s\n' "$ids" | grep -q "^$expect "; then
    echo "OK: the new key ($expect) is in place."
else
    echo "WARNING: the new key ($expect) is not among the keys above." >&2
    exit 1
fi
REMOTE
sed -i.bak "s/@EXPECT@/$expect/" "$stage/rotate.sh" && rm "$stage/rotate.sh.bak"

# The staging directory belongs to the SSH user, who could swap the script (run as root) or
# the key between the copy and the root shell: root copies it into a private directory and
# checks every file against these hashes, pasted into the root shell, as with deploy.sh.
(cd "$stage" && shasum -a 256 -- * > SHA256SUMS)
MANIFEST=$(shasum -a 256 "$stage/SHA256SUMS" | cut -d' ' -f1)

cmds=()
for h in "${hosts[@]}"; do
    # private, freshly created: it holds the key. SFTP
    # alone, as in deploy.sh: a hardened host's SSH user may run no other remote command.
    remote=/tmp/logguard-rotate.$(openssl rand -hex 8)
    {
        echo "mkdir $remote"
        echo "chmod 700 $remote"
        for f in "$stage"/*; do echo "put \"$f\" $remote/"; done
    } | sftp -q -o BatchMode=no -b - "$h" >/dev/null
    echo "Copied to $h:$remote"
    cmds+=("$h:" "d=\$(mktemp -d /root/logguard-rotate.XXXXXX) && cp -R $remote/. \"\$d\" && cd \"\$d\" && echo '$MANIFEST  SHA256SUMS' | sha256sum -c --quiet && sha256sum -c --quiet --strict SHA256SUMS && bash rotate.sh $step; cd /; rm -rf \"\$d\" $remote" "")
done
echo
echo "Now paste into a root shell on each node:"
printf '%s\n' "${cmds[@]}"
echo "Each node should end with 'OK: the new key ($expect) is in place.'"
case "$step" in
    start) echo "Then, once every node is done:  $0 switch ${hosts[*]}" ;;
    switch) echo "Then, once every node is done:  $0 finish ${hosts[*]}" ;;
    finish)
        if [ -f "$key.next" ]; then
            mv "$key.next" "$key"
            echo "Local $key is the new key now: deploy.sh installs it on new nodes."
        fi
        ;;
esac
