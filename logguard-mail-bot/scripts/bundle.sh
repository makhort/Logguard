#!/bin/bash
# Builds the release bundle: target/bundle/<name>-<version>-<commit>-<arch>.zip, <arch> one of
# x86_64-linux-musl, aarch64-linux-musl, armv7-linux-musleabihf (32-bit ARM, hard-float).
# An admin unzips it on the server and runs  sudo ./install.sh  (README, "Install from a
# release bundle"). CI builds and publishes one per architecture after ci.sh.
#
#   ./scripts/bundle.sh                   bundles the static x86_64 binary (cargo builds it, or finds
#                                         the one ci.sh built up to date)
#   ./scripts/bundle.sh --target TRIPLE   the same for another target: aarch64-unknown-linux-musl,
#                                         armv7-unknown-linux-musleabihf (or x86_64-unknown-linux-musl)
#   ./scripts/bundle.sh --check-tag TAG   only checks that TAG is <name>-v<version> of Cargo.toml
#                                         (CI runs it for a tag push, before it publishes a Release)
#
# Inside, in one directory of the same name:
#   install.sh    deploy/release-install.sh: checks the files, then runs files/install.sh
#   files/        what deploy/deploy.sh copies to a server: the binary and deploy/'s files
#   configs/      deploy/*.toml, the config templates (if the crate has any)
#   TARGET        the Rust target the binary is built for (install.sh names it if it can't run)
#   README.md, LICENSE, SHA256SUMS
# Only files git tracks go in, so deploy/config.env and keys (git-ignored) never do.
# (The same script in every crate.)
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
NAME=$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$NAME" ] && [ -n "$VERSION" ] || { echo "no name or version in Cargo.toml" >&2; exit 1; }
case $#:${1:-} in
    0:) ;;
    2:--target)
        case $2 in
            x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | armv7-unknown-linux-musleabihf) TARGET=$2 ;;
            *) echo "unsupported target $2" >&2; exit 2 ;;
        esac ;;
    2:--check-tag)
        [ "$2" = "$NAME-v$VERSION" ] && exit 0
        echo "tag $2 doesn't match Cargo.toml: version $VERSION is tagged $NAME-v$VERSION" >&2
        exit 1 ;;
    *) echo "usage: $0 [--target TRIPLE | --check-tag TAG]" >&2; exit 2 ;;
esac
BIN=target/$TARGET/release/$NAME
# Always asked: a binary built before the last commit (or edit) would go out under this
# commit's name. Nothing to do when ci.sh just built it.
cargo build --release --quiet --target "$TARGET"
COMMIT=$(git rev-parse --short=8 HEAD 2> /dev/null || true)
BASE=$NAME-$VERSION${COMMIT:+-$COMMIT}-${TARGET/-unknown/}
OUT=target/bundle
STAGE=$OUT/$BASE

if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    deploy=$(git ls-files deploy)
else
    deploy=$(find deploy -type f ! -name config.env ! -name '*.key*' ! -path '*/.*' | sort)
fi

# older bundles of this architecture go; the other architectures' stay
rm -rf "$STAGE" "$OUT"/*-"${TARGET/-unknown/}".zip
mkdir -p "$STAGE/files"
install -m 0755 "$BIN" "$STAGE/files/$NAME"
for f in $deploy; do
    case $f in
        # run on the admin's machine, or the bundle's own install.sh
        deploy/deploy.sh | deploy/rotate-cluster-key.sh | deploy/release-install.sh) ;;
        deploy/*.toml) mkdir -p "$STAGE/configs" && cp -p "$f" "$STAGE/configs/" ;;
        deploy/pkg/*) ;;   # the packages' maintainer scripts (scripts/package.sh)
        deploy/*/*) echo "unexpected subdirectory in deploy/: $f" >&2; exit 1 ;;
        *) cp -p "$f" "$STAGE/files/" ;;
    esac
done
install -m 0755 deploy/release-install.sh "$STAGE/install.sh"
echo "$TARGET" > "$STAGE/TARGET"
chmod 0755 "$STAGE/files/install.sh"
cp README.md "$STAGE/"
if [ -f ../LICENSE ]; then cp ../LICENSE "$STAGE/"; fi

# Everything deploy.sh copies to a server must be in files/ too.
for f in $(perl -nle 'print $1 while m{(?<![\w./-])(deploy/\w[\w.-]*)}g' deploy/deploy.sh | sort -u); do
    case $f in deploy/deploy.sh | deploy/cluster.key | deploy/*.toml) continue ;; esac
    [ -f "$STAGE/files/${f#deploy/}" ] || { echo "$f (deploy.sh copies it) is not in the bundle" >&2; exit 1; }
done
# And everything the bundle's install.sh takes from files/ (a new file git doesn't track yet isn't).
for f in $(perl -nle 'print $1 while m{(?<![\w./-])(files/\w[\w.-]*)}g' deploy/release-install.sh | sort -u); do
    case $f in files/cluster.key | files/*.toml) continue ;; esac   # it writes those itself
    [ -f "$STAGE/$f" ] || { echo "$f (release-install.sh uses it) is not in the bundle: git add it?" >&2; exit 1; }
done

sha256() { if command -v sha256sum > /dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$STAGE" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do sha256 "$f"; done > SHA256SUMS)
(cd "$OUT" && zip -qr -X "$BASE.zip" "$BASE")
rm -rf "$STAGE"
echo "$OUT/$BASE.zip"
