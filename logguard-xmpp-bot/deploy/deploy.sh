#!/bin/zsh
# Builds the static Linux binary on this Mac and copies it with the unit and install.sh
# to the XMPP server (ssh alias "xmpp"). Then it prints the command to paste into a root
# shell there: it verifies the files and runs install.sh from a root-only copy.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${1:-xmpp}
TARGET=x86_64-unknown-linux-musl

./scripts/ci.sh

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "target/$TARGET/release/logguard-xmpp-bot" deploy/logguard-xmpp-bot.service deploy/logguard-xmpp-bot.logrotate deploy/ejabberd-logs.logrotate deploy/install.sh "$STAGE/"

# The staging directory belongs to the SSH user, who could swap files between the copy and
# the root shell: root copies it into a private directory first and checks every file
# against the hashes computed here (pasted into the root shell, so they don't come from
# the server), runs install.sh from there, and removes both copies (the cluster key too).
(cd "$STAGE" && shasum -a 256 -- * > SHA256SUMS)
MANIFEST=$(shasum -a 256 "$STAGE/SHA256SUMS" | cut -d' ' -f1)

# Private, freshly created directory: install.sh runs from it as root, so nobody else may
# have created it beforehand (in sticky /tmp, rm then fails and the deploy stops).
ssh "$HOST" 'rm -rf /tmp/logguard-xmpp-bot-deploy && mkdir -m 700 /tmp/logguard-xmpp-bot-deploy'
scp -q "$STAGE"/* "$HOST":/tmp/logguard-xmpp-bot-deploy/
echo "Copied to $HOST:/tmp/logguard-xmpp-bot-deploy. Now paste this into a root shell there:"
echo
echo "d=\$(mktemp -d /root/logguard-xmpp-bot-deploy.XXXXXX) && cp -R /tmp/logguard-xmpp-bot-deploy/. \"\$d\" && cd \"\$d\" && echo '$MANIFEST  SHA256SUMS' | sha256sum -c --quiet && sha256sum -c --quiet --strict SHA256SUMS && bash install.sh; cd /; rm -rf \"\$d\" /tmp/logguard-xmpp-bot-deploy"
