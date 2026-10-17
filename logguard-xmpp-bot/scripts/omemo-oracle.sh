#!/bin/bash
# Interoperability tests of the bot's OMEMO against omemo-dr, Gajim's OMEMO library
# (tests/omemo_oracle/oracle.py). The first run creates a Python venv in target/ and
# installs omemo-dr there (needs Python >= 3.10 and a C compiler); ci.sh runs these
# tests whenever that venv exists.
#
#   ./scripts/omemo-oracle.sh            set up if needed, then test
#   PYTHON=python3.12 ./scripts/omemo-oracle.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=target/omemo-oracle
OMEMO_DR_VERSION=1.2.0

if [ ! -x "$VENV/bin/python" ]; then
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
    "$py" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet "omemo-dr==$OMEMO_DR_VERSION"
fi

OMEMO_ORACLE_PYTHON="$PWD/$VENV/bin/python" cargo test --quiet omemo::oracle_tests -- --test-threads 4
