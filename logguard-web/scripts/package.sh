#!/bin/bash
# Builds the distribution packages for one architecture, in target/package/:
#   <name>_<version>-1_<deb arch>.deb     Debian, Ubuntu and their derivatives (dpkg, apt)
#   <name>-<version>-1.<rpm arch>.rpm     Fedora, RHEL and its rebuilds (rpm, dnf)
# each with its .sha256. An admin installs one with  apt install ./<file>.deb  or
# dnf install ./<file>.rpm  (README, "Install from a package"). CI builds and publishes them
# after ci.sh, next to the release bundle (scripts/bundle.sh).
#
#   ./scripts/package.sh                   the static x86_64 binary (cargo builds it, or finds the
#                                          one ci.sh built up to date): amd64 .deb, x86_64 .rpm
#   ./scripts/package.sh --target TRIPLE   aarch64-unknown-linux-musl (arm64 .deb, aarch64 .rpm) or
#                                          armv7-unknown-linux-musleabihf (armhf .deb, armv7hl .rpm)
#
# cargo-deb and cargo-generate-rpm write them (cargo install cargo-deb cargo-generate-rpm
# --locked); neither needs dpkg or rpm, so this runs on macOS too. What goes in is listed in
# Cargo.toml, [package.metadata.deb] and [package.metadata.generate-rpm]: the binary, the deploy
# files this script stages in target/package/stage/ (deploy/'s files with the package's paths:
# /usr/bin for /usr/local/bin and /usr/local/sbin), the maintainer scripts in deploy/pkg/
# (dpkg's preinst, postinst, prerm and postrm; the same files are rpm's %pre, %post, %preun and
# %postun), README.md and LICENSE. Only files git tracks go in, so deploy/config.env and keys
# (git-ignored) never do. (The same script in every crate.)
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
NAME=$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$NAME" ] && [ -n "$VERSION" ] || { echo "no name or version in Cargo.toml" >&2; exit 1; }
case $#:${1:-} in
    0:) ;;
    2:--target) TARGET=$2 ;;
    *) echo "usage: $0 [--target TRIPLE]" >&2; exit 2 ;;
esac
case $TARGET in
    x86_64-unknown-linux-musl) DEB_ARCH=amd64 RPM_ARCH=x86_64 ;;
    aarch64-unknown-linux-musl) DEB_ARCH=arm64 RPM_ARCH=aarch64 ;;
    armv7-unknown-linux-musleabihf) DEB_ARCH=armhf RPM_ARCH=armv7hl ;;
    *) echo "unsupported target $TARGET" >&2; exit 2 ;;
esac
for tool in cargo-deb cargo-generate-rpm; do
    command -v $tool > /dev/null || { echo "$tool is not installed:  cargo install cargo-deb cargo-generate-rpm --locked" >&2; exit 1; }
done

# Always asked: a binary built before the last commit (or edit) would go out under this
# version. Nothing to do when ci.sh just built it.
cargo build --release --quiet --target "$TARGET"
BIN=target/$TARGET/release/$NAME
[ -x "$BIN" ] || { echo "no $BIN" >&2; exit 1; }
OUT=target/package
STAGE=$OUT/stage
# The packages' files get the last commit's time, so the same commit packs the same bytes.
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2> /dev/null || date +%s)

if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    deploy=$(git ls-files deploy)
else
    deploy=$(find deploy -type f ! -name config.env ! -name '*.key*' ! -path '*/.*' | sort)
fi

# deploy/'s files as the package installs them. The bundle's install.sh puts logguard in
# /usr/local/bin and its helper scripts in /usr/local/sbin (the admin's directories); a
# package's place is /usr/bin, so the units and scripts that name those paths are rewritten.
# Nothing else changes; a file without those paths is copied as it is.
rm -rf "$STAGE"
mkdir -p "$STAGE"
for f in $deploy; do
    case $f in
        # run on the admin's machine, from a bundle, or by hand: not packaged
        deploy/deploy.sh | deploy/release-install.sh | deploy/install.sh | deploy/rotate-cluster-key.sh) continue ;;
        deploy/pkg/*) continue ;;   # the maintainer scripts: Cargo.toml names them where they are
        deploy/*/*) echo "unexpected subdirectory in deploy/: $f" >&2; exit 1 ;;
    esac
    perl -pe 's{/usr/local/bin/logguard\b}{/usr/bin/logguard}g; s{/usr/local/sbin/(logguard-[a-z-]+)}{/usr/bin/$1}g' "$f" > "$STAGE/${f#deploy/}"
    chmod --reference="$f" "$STAGE/${f#deploy/}" 2> /dev/null || chmod "$(stat -f %Lp "$f")" "$STAGE/${f#deploy/}"
    # Every staged file must be in both packages: a new file in deploy/ needs a line in each
    # metadata table (by name, or by its extension's wildcard, e.g. stage/*.toml).
    base=${f#deploy/}
    for table in metadata.deb metadata.generate-rpm; do
        awk -v t="[package.$table]" '/^\[/ { s = ($0 == t) } s' Cargo.toml | grep -qF -e "stage/$base" -e "stage/*.${base##*.}" \
            || { echo "$f is not in Cargo.toml's [package.$table] assets (or excluded here)" >&2; exit 1; }
    done
done
for s in postinst prerm postrm; do
    [ -f deploy/pkg/$s ] || { echo "deploy/pkg/$s is missing" >&2; exit 1; }
done
for s in deploy/pkg/*; do bash -n "$s"; done
[ -f ../LICENSE ] && cp ../LICENSE "$STAGE/LICENSE"

# older packages of this architecture go; the other architectures' stay
rm -f "$OUT"/*_"$DEB_ARCH".deb "$OUT"/*_"$DEB_ARCH".deb.sha256 "$OUT"/*."$RPM_ARCH".rpm "$OUT"/*."$RPM_ARCH".rpm.sha256
DEB=$OUT/${NAME}_${VERSION}-1_${DEB_ARCH}.deb
RPM=$OUT/${NAME}-${VERSION}-1.${RPM_ARCH}.rpm
# The binaries are already stripped (profile.release) and built: cargo-deb must not build or
# strip (it would look for a cross strip). The rpm's architecture is named: cargo-generate-rpm
# would call 32-bit ARM "armv7", which is not what rpm calls it.
cargo deb --quiet --no-build --no-strip --target "$TARGET" --output "$DEB"
cargo generate-rpm --target "$TARGET" --arch "$RPM_ARCH" --auto-req disabled --output "$RPM" > /dev/null
[ -f "$DEB" ] && [ -f "$RPM" ] || { echo "the packages were not written" >&2; exit 1; }

# What went in, from the packages themselves: with dpkg and rpm (Linux), else with ar and
# tar (macOS); the rpm's payload needs rpm2cpio, so only its header is checked there.
list_deb() {
    if command -v dpkg-deb > /dev/null; then dpkg-deb -c "$1" | awk '{ print $6 }'
    else ar p "$1" data.tar.xz 2> /dev/null | tar -tJf - ; fi | sed 's|^\./||; s|^/||' | grep -v '/$' | sort
}
echo "$DEB:"
list_deb "$DEB" | sed 's/^/    /'
expected=$(awk '/^\[package.metadata.deb\]/ { s = 1; next } /^\[/ { s = 0 } s' Cargo.toml \
    | perl -ne 'print "$1\n" if /^\s*\["[^"]*",\s*"([^"]*)",/' | sed 's|^/||' | { grep -v '/$' || true; } | sort -u)
missing=$(comm -23 <(printf '%s\n' "$expected" | sed '/^$/d') <(list_deb "$DEB"))
[ -z "$missing" ] || { printf 'not in the .deb:\n%s\n' "$missing" >&2; exit 1; }
if command -v rpm > /dev/null; then
    echo "$RPM:"
    rpm -qpl --nosignature "$RPM" 2> /dev/null | sed 's/^/    /'
    rpm -qp --nosignature --scripts "$RPM" > /dev/null 2>&1
fi
sha256() { if command -v sha256sum > /dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$OUT" && sha256 "${DEB##*/}" > "${DEB##*/}.sha256" && sha256 "${RPM##*/}" > "${RPM##*/}.sha256")
rm -rf "$STAGE"
echo "$DEB"
echo "$RPM"
