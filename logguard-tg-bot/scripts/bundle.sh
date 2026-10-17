#!/bin/bash
# Builds the release bundle: target/bundle/<name>-<version>-<commit>-x86_64-linux-musl.zip.
# An admin unzips it on the server and runs  sudo ./install.sh  (README, "Install from a
# release bundle"). CI builds and publishes it after ci.sh.
#
#   ./scripts/bundle.sh                   bundles the static binary ci.sh built (builds it if missing)
#   ./scripts/bundle.sh --check-tag TAG   only checks that TAG is <name>-v<version> of Cargo.toml
#                                         (CI runs it for a tag push, before it publishes a Release)
#
# Inside, in one directory of the same name:
#   install.sh    deploy/release-install.sh: checks the files, then runs files/install.sh
#   files/        what deploy/deploy.sh copies to a server: the binary and deploy/'s files
#   configs/      deploy/*.toml, the config templates (if the crate has any)
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
    2:--check-tag)
        [ "$2" = "$NAME-v$VERSION" ] && exit 0
        echo "tag $2 doesn't match Cargo.toml: version $VERSION is tagged $NAME-v$VERSION" >&2
        exit 1 ;;
    *) echo "usage: $0 [--check-tag TAG]" >&2; exit 2 ;;
esac
BIN=target/$TARGET/release/$NAME
[ -x "$BIN" ] || cargo build --release --quiet --target $TARGET
COMMIT=$(git rev-parse --short=8 HEAD 2> /dev/null || true)
BASE=$NAME-$VERSION${COMMIT:+-$COMMIT}-x86_64-linux-musl
OUT=target/bundle
STAGE=$OUT/$BASE

if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    deploy=$(git ls-files deploy)
else
    deploy=$(find deploy -type f ! -name config.env ! -name '*.key*' ! -path '*/.*' | sort)
fi

rm -rf "$OUT"
mkdir -p "$STAGE/files"
install -m 0755 "$BIN" "$STAGE/files/$NAME"
for f in $deploy; do
    case $f in
        # run on the admin's machine, or the bundle's own install.sh
        deploy/deploy.sh | deploy/rotate-cluster-key.sh | deploy/release-install.sh) ;;
        deploy/*.toml) mkdir -p "$STAGE/configs" && cp -p "$f" "$STAGE/configs/" ;;
        deploy/*/*) echo "unexpected subdirectory in deploy/: $f" >&2; exit 1 ;;
        *) cp -p "$f" "$STAGE/files/" ;;
    esac
done
install -m 0755 deploy/release-install.sh "$STAGE/install.sh"
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
