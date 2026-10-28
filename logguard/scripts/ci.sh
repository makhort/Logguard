#!/bin/bash
# The checks CI runs; run locally before deploying:  ./scripts/ci.sh
# deploy/deploy.sh runs it first; scripts/install-hooks.sh makes `git push` run it too.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "format"
cargo fmt --check
step "clippy"
cargo clippy --all-targets --quiet -- -D warnings
step "tests"
cargo test --quiet
step "dependency advisories (cargo audit)"
# Fails on known vulnerabilities, unsound code and yanked versions; unmaintained crates are
# only reported. Offline, the advisory database already on disk is used.
# LOGGUARD_SKIP_AUDIT=1 skips this step (e.g. no cargo-audit on this machine).
if [ "${LOGGUARD_SKIP_AUDIT:-}" = 1 ]; then
    echo "skipped (LOGGUARD_SKIP_AUDIT=1)"
elif ! cargo audit --version > /dev/null 2>&1; then
    echo "cargo-audit is not installed:  cargo install cargo-audit --locked   (or LOGGUARD_SKIP_AUDIT=1)" >&2
    exit 1
elif ! cargo audit --quiet --deny unsound --deny yanked > /dev/null 2>&1; then
    # a finding or no network: the run against the copy on disk shows which
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
bin=target/$TARGET/release/logguard
ls -l "$bin"
step "bundled configs parse"
for c in deploy/*.toml; do
    cargo run --quiet -- --config "$c" print-config > /dev/null && echo "ok  $c"
done
step "dnf template variants up to date"
./scripts/dnf-templates.sh --check && echo ok
