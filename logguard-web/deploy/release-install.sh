#!/bin/bash
# Installs or upgrades logguard-web from this release bundle. Unzip it on the server,
# then as root:
#
#   ./install.sh             install, or upgrade (the running version becomes the rollback one)
#   ./install.sh rollback    back to the previous version
#   ./install.sh --check     only check the bundle's files (needs no root)
#
# The first install puts config.env.example in place as /opt/logguard-web/config.env and
# doesn't start logguard-web until it is filled in: edit it, then run this again (README.md, "Setup").
# It copies the bundle to a directory only root can write, checks every file against
# SHA256SUMS there, and runs files/install.sh from it, as deploy/deploy.sh does over SSH.
set -euo pipefail

usage() { sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; }
die() { echo "install.sh: $*" >&2; exit 1; }

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
command -v systemctl > /dev/null || die "logguard-web runs as a systemd service: no systemctl here"

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
files/logguard-web --version > /dev/null 2>&1 || die "this bundle is for $(cat TARGET); this machine is $(uname -m): use its own bundle"

bash files/install.sh "$@"
