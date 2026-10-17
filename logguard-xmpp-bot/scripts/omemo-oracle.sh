#!/bin/bash
# Interoperability tests of the bot's OMEMO against omemo-dr, Gajim's OMEMO library
# (tests/omemo_oracle/oracle.py). The first run creates a Python venv in target/ and
# installs omemo-dr there (needs Python >= 3.10 and a C compiler); ci.sh runs these
# tests whenever that venv works.
#
#   ./scripts/omemo-oracle.sh            set up if needed, then test
#   ./scripts/omemo-oracle.sh --check    only say (exit status) whether the venv works
#   PYTHON=python3.12 ./scripts/omemo-oracle.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=target/omemo-oracle
OMEMO_DR_VERSION=1.2.0

# A venv that exists isn't enough: a cache restore of target/ (GitHub's rust-cache) or a new
# system Python can leave bin/python without omemo-dr, or with another version of it.
works() {
    [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -I -c "
import sys, importlib.metadata, omemo_dr
sys.exit(importlib.metadata.version('omemo-dr') != '$OMEMO_DR_VERSION')" 2> /dev/null
}

if [ "${1:-}" = --check ]; then
    works
    exit
fi

if ! works; then
    py=${PYTHON:-}
    if [ -z "$py" ]; then
        for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
            if command -v "$c" > /dev/null && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
                py=$c
                break
            fi
        done
    fi
    [ -n "$py" ] || { echo "need Python >= 3.10 (set PYTHON=...)" >&2; exit 1; }
    rm -rf "$VENV"
    "$py" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet "omemo-dr==$OMEMO_DR_VERSION"
    works || { echo "omemo-dr $OMEMO_DR_VERSION doesn't import in $VENV" >&2; exit 1; }
fi

OMEMO_ORACLE_PYTHON="$PWD/$VENV/bin/python" cargo test --quiet omemo::oracle_tests -- --test-threads 4
