#!/bin/bash
# Writes the dnf variants of the config templates, deploy/<name>-dnf.toml from each
# deploy/<name>.toml: the same settings for a Fedora or RHEL host (package_manager = "dnf",
# rpm's database, dnf's tools). Edit the template, then run this.
#
#   ./scripts/dnf-templates.sh           writes them
#   ./scripts/dnf-templates.sh --check   only says (and fails) if one is out of date (ci.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

check=no
case $#:${1:-} in
    0:) ;;
    1:--check) check=yes ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

variant() { # the dnf variant of template $1, on stdout
    local name=${1##*/}
    printf '# The variant of %s for Fedora and RHEL (dnf), written from it by\n# scripts/dnf-templates.sh: edit that file, then run the script.\n' "$name"
    perl -pe '
        s/^package_manager = "apt"$/package_manager = "dnf"/;
        s/^dpkg_db = .*$/rpm = "\/usr\/bin\/rpm"            # asked which package owns a changed file (rpm -qf)/;
        s/\(MD5 recorded by dpkg\)/(digest recorded by rpm)/;
        s/apt install clamav clamav-freshclam/dnf install clamav clamav-update/;
        s/\(apt-get -s, a simulation,$/(dnf --cacheonly check-update,/;
        s/^apt = true$/apt = true                 # here: dnf (package_manager)/;
        s/hashed against dpkg\x27s checksums \(like debsums;/hashed against rpm\x27s digests (like rpm -Va;/;
    ' "$1"
}

stale=0
for t in deploy/*.toml; do
    case $t in *-dnf.toml) continue ;; esac
    v=${t%.toml}-dnf.toml
    if [ "$check" = yes ]; then
        if ! variant "$t" | cmp -s - "$v"; then
            echo "$v is out of date: ./scripts/dnf-templates.sh" >&2
            stale=1
        fi
    else
        variant "$t" > "$v"
        echo "wrote $v"
    fi
done
exit $stale
