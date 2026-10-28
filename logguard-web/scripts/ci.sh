#!/bin/bash
# The checks to pass before deploying (deploy/deploy.sh runs them first).
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "format"
cargo fmt --check
step "clippy"
cargo clippy --all-targets --quiet -- -D warnings
step "tests (tests/end_to_end.rs listens on 127.0.0.1 and on a Unix socket)"
cargo test --quiet
step "the page's tests (node --test web/tests: the patching, the abuse e-mail, CSV, links)"
if command -v node > /dev/null; then
    # the files, not the directory: Node 22's --test takes patterns, not directories
    node --test web/tests/*.test.mjs
else
    echo "node is not installed: skipped (any Node 20 or newer runs them)"
fi
step "dependency advisories (cargo audit)"
if [ "${LOGGUARD_WEB_SKIP_AUDIT:-}" = 1 ]; then
    echo "skipped (LOGGUARD_WEB_SKIP_AUDIT=1)"
elif ! cargo audit --version > /dev/null 2>&1; then
    echo "cargo-audit is not installed:  cargo install cargo-audit --locked   (or LOGGUARD_WEB_SKIP_AUDIT=1)" >&2
    exit 1
elif ! cargo audit --quiet --deny unsound --deny yanked > /dev/null 2>&1; then
    if cargo audit --quiet --no-fetch --stale --deny unsound --deny yanked; then
        echo "note: advisory database not updated (offline?); checked against the copy on disk"
    else
        exit 1
    fi
fi
step "static Linux binary"
# TARGET=aarch64-unknown-linux-musl or armv7-unknown-linux-musleabihf builds for ARM instead
TARGET=${TARGET:-x86_64-unknown-linux-musl}
cargo build --release --quiet --target "$TARGET"
ls -l target/$TARGET/release/logguard-web
