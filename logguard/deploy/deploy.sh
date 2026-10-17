#!/bin/zsh
# Builds a static Linux binary on this Mac and copies it with the deploy files
# to the server (ssh host alias "xmpp", as in the old deploy.sh). Then it prints the command
# to paste into a root shell there: it verifies the files and runs install.sh from a
# root-only copy.
#
#   ./deploy/deploy.sh                                   # XMPP server, deploy/logguard.toml
#   ./deploy/deploy.sh vpn deploy/logguard-standalone.toml      # wg-easy host (ssh alias "vpn")
#   ./deploy/deploy.sh tg deploy/logguard-tg.toml        # Telegram relay node (ssh alias "tg")
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${1:-xmpp}
CONFIG=${2:-deploy/logguard.toml}
TARGET=x86_64-unknown-linux-musl

if [ -n "$(git status --porcelain --untracked-files=no -- . 2>/dev/null)" ]; then
    echo "NOTE: deploying uncommitted changes (the binary's --version will say 'modified')"
fi
./scripts/ci.sh

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "target/$TARGET/release/logguard" deploy/logguard.service deploy/logguard.logrotate deploy/install.sh "$STAGE/"
cp deploy/logguard-avscan.sh deploy/logguard-avscan.service deploy/logguard-avscan.timer deploy/logguard-avscan.default "$STAGE/"
cp deploy/logguard-abuse-report.sh deploy/logguard-abuse-report.service deploy/logguard-abuse-report.timer deploy/logguard-abuse-report.default "$STAGE/"
cp "$CONFIG" "$STAGE/logguard.toml"
# One cluster key shared by all nodes: generated once here, never committed.
if [ ! -f deploy/cluster.key ]; then
    (umask 077; "target/$TARGET/release/logguard" cluster-keygen > deploy/cluster.key 2>/dev/null \
        || cargo run --quiet --release -- cluster-keygen > deploy/cluster.key)
    echo "Generated deploy/cluster.key (keep it secret; it is copied to every node)"
fi
cp deploy/cluster.key "$STAGE/cluster.key"
chmod 600 "$STAGE/cluster.key"
chmod +x "$STAGE/install.sh"

# The staging directory belongs to the SSH user, who could swap files between the copy and
# the root shell: root copies it into a private directory first and checks every file
# against the hashes computed here (pasted into the root shell, so they don't come from
# the server), runs install.sh from there, and removes both copies (the cluster key too).
(cd "$STAGE" && shasum -a 256 -- * > SHA256SUMS)
MANIFEST=$(shasum -a 256 "$STAGE/SHA256SUMS" | cut -d' ' -f1)

# Private, freshly created directory: install.sh runs from it as root, so nobody else may
# have created it beforehand (in sticky /tmp, rm then fails and the deploy stops).
ssh "$HOST" 'rm -rf /tmp/logguard-deploy && mkdir -m 700 /tmp/logguard-deploy'
scp -q "$STAGE"/* "$HOST":/tmp/logguard-deploy/
echo "Copied to $HOST:/tmp/logguard-deploy (config: $CONFIG). Now paste this into a root shell there:"
echo
echo "d=\$(mktemp -d /root/logguard-deploy.XXXXXX) && cp -R /tmp/logguard-deploy/. \"\$d\" && cd \"\$d\" && echo '$MANIFEST  SHA256SUMS' | sha256sum -c --quiet && sha256sum -c --quiet --strict SHA256SUMS && bash install.sh; cd /; rm -rf \"\$d\" /tmp/logguard-deploy"
