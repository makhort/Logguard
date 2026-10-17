#!/bin/bash
# The checks to pass before deploying (deploy/deploy.sh runs them first).
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "format"
cargo fmt --check
step "clippy"
cargo clippy --all-targets --quiet -- -D warnings
step "tests"
cargo test --quiet
step "OMEMO interoperability with omemo-dr"
if [ -x target/omemo-oracle/bin/python ]; then
    ./scripts/omemo-oracle.sh
else
    echo "skipped: run ./scripts/omemo-oracle.sh once to set up the omemo-dr oracle"
fi
step "dependency advisories (cargo audit)"
if [ "${LOGGUARD_XMPP_BOT_SKIP_AUDIT:-}" = 1 ]; then
    echo "skipped (LOGGUARD_XMPP_BOT_SKIP_AUDIT=1)"
elif ! cargo audit --version > /dev/null 2>&1; then
    echo "cargo-audit is not installed:  cargo install cargo-audit --locked   (or LOGGUARD_XMPP_BOT_SKIP_AUDIT=1)" >&2
    exit 1
elif ! cargo audit --quiet --deny unsound --deny yanked > /dev/null 2>&1; then
    if cargo audit --quiet --no-fetch --stale --deny unsound --deny yanked; then
        echo "note: advisory database not updated (offline?); checked against the copy on disk"
    else
        exit 1
    fi
fi
step "static Linux binary"
cargo build --release --quiet --target x86_64-unknown-linux-musl
ls -l target/x86_64-unknown-linux-musl/release/logguard-xmpp-bot
