#!/bin/zsh
# Builds the static Linux binary on this Mac and copies it with the unit and install.sh
# to a node of the logguard cluster (by default the relay node, ssh alias "tg"; or name
# another host, e.g. "xmpp"), where logguard writes the bot's outbox. Then it prints the command to paste into a root shell
# there: it verifies the files and runs install.sh from a root-only copy.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${1:-tg}
# An ARM server: TARGET=aarch64-unknown-linux-musl (or armv7-unknown-linux-musleabihf) ./deploy/deploy.sh ...
export TARGET=${TARGET:-x86_64-unknown-linux-musl}   # ci.sh builds it

./scripts/ci.sh

STAGE=$(mktemp -d)
trap 'rm -rf "${STAGE:?}"' EXIT
cp "target/$TARGET/release/logguard-matrix-bot" deploy/logguard-matrix-bot.service deploy/logguard-matrix-bot.logrotate deploy/config.env.example deploy/install.sh "$STAGE/"

# The staging directory belongs to the SSH user, who could swap files between the copy and
# the root shell: root copies it into a private directory first and checks every file
# against the hashes computed here (pasted into the root shell, so they don't come from
# the server), runs install.sh from there, and removes both copies.
(cd "$STAGE" && shasum -a 256 -- * > SHA256SUMS)
MANIFEST=$(shasum -a 256 "$STAGE/SHA256SUMS" | cut -d' ' -f1)

# Private, freshly created directory: install.sh runs from it as root, so nobody else may
# have created it beforehand. Uploaded over SFTP alone, since a hardened host's SSH user may
# run no other remote command: sftp's mkdir fails on an existing name and batch mode stops
# at the first failed command. BatchMode=no (first value wins) keeps the passphrase prompt.
REMOTE=/tmp/logguard-matrix-bot-deploy.$(openssl rand -hex 8)
{
    echo "mkdir $REMOTE"
    echo "chmod 700 $REMOTE"
    for f in "$STAGE"/*; do echo "put \"$f\" $REMOTE/"; done
} | sftp -q -o BatchMode=no -b - "$HOST" >/dev/null
echo "Copied to $HOST:$REMOTE. Now paste this into a root shell there:"
echo
echo "d=\$(mktemp -d /root/logguard-matrix-bot-deploy.XXXXXX) && cp -R $REMOTE/. \"\$d\" && cd \"\$d\" && echo '$MANIFEST  SHA256SUMS' | sha256sum -c --quiet && sha256sum -c --quiet --strict SHA256SUMS && bash install.sh; cd /; rm -rf \"\${d:?}\" $REMOTE"
