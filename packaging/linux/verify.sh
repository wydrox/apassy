#!/usr/bin/env bash
# Check the Linux node packages of build.sh on a CI runner (plan S2-S3, units L2 and L3).
#
# Usage: packaging/linux/verify.sh --dist DIR --arch x86_64|aarch64 [--containers]
#
# On this machine (Ubuntu with sudo and systemd): the checksums; the .deb installs, and
# `apassy --version` and `apassy-team --version` print the relay crate's version;
# `systemd-analyze verify` accepts the packaged unit and the unit of `apassy up
# --print-unit` with an encrypted key (LoadCredentialEncrypted=); the .deb removes
# cleanly; install.sh installs the tarball from a file:// directory. With --containers
# (Docker), the .deb installs and the tarball runs in Debian 11 (glibc 2.31, the oldest
# supported) and Debian 12 too. It changes nothing outside a temporary directory except
# the .deb, which it installs and removes again.
set -euo pipefail

die() {
    printf 'verify.sh: %s\n' "$*" >&2
    exit 1
}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)

dist=
arch=
containers=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dist) dist=${2:?--dist needs a directory}; shift 2 ;;
        --arch) arch=${2:?--arch needs a value}; shift 2 ;;
        --containers) containers=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$dist" ] && [ -n "$arch" ] || die 'usage: verify.sh --dist DIR --arch x86_64|aarch64 [--containers]'
case "$arch" in
    x86_64) deb_arch=amd64 ;;
    aarch64) deb_arch=arm64 ;;
    *) die "the architecture is x86_64 or aarch64, not $arch" ;;
esac
[ "$(uname -m)" = "$arch" ] || die "this machine is $(uname -m), not $arch"
dist=$(cd "$dist" && pwd)
version=$(awk -F '"' '/^version = / {print $2; exit}' "$root/crates/apassy-relay/Cargo.toml")
tarball="apassy-$version-linux-$arch.tar.gz"
deb="apassy_${version}_${deb_arch}.deb"
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-verify.XXXXXXXX")
installed=0
cleanup() {
    if [ "$installed" = 1 ]; then
        sudo dpkg -r apassy >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

echo "== checksums"
(cd "$dist" && sha256sum -c "SHA256SUMS-node-$arch")
[ "$(wc -l < "$dist/SHA256SUMS-node-$arch")" -eq 2 ] || die 'SHA256SUMS-node has not two lines'

echo "== dpkg-deb --info and --contents"
dpkg-deb --info "$dist/$deb"
dpkg-deb --contents "$dist/$deb"
[ "$(dpkg-deb --field "$dist/$deb" Package)" = apassy ] || die 'the package is not apassy'
[ "$(dpkg-deb --field "$dist/$deb" Version)" = "$version" ] || die 'the package version differs'

echo "== the .deb on this machine"
sudo dpkg -i "$dist/$deb"
installed=1
[ "$(/usr/bin/apassy --version)" = "apassy $version" ] || die 'apassy --version differs'
[ "$(/usr/bin/apassy-team --version)" = "apassy-team $version" ] || die 'apassy-team --version differs'
/usr/bin/apassy help >/dev/null
systemd-analyze verify --man=no /usr/lib/systemd/user/apassy-node.service
node="$work/node"
install -d -m 0700 "$node"
install -m 0600 /dev/null "$node/master.key.cred"
mkdir "$work/unit"
/usr/bin/apassy up --print-unit --data-dir "$node" > "$work/unit/apassy-node.service"
cat "$work/unit/apassy-node.service"
grep -qx "LoadCredentialEncrypted=apassy-node-key:$node/master.key.cred" "$work/unit/apassy-node.service" ||
    die 'the unit of an encrypted key has no LoadCredentialEncrypted= line'
grep -qx "ExecStart=/usr/bin/apassy serve --data-dir $node" "$work/unit/apassy-node.service" ||
    die 'the unit does not run /usr/bin/apassy serve'
systemd-analyze verify --man=no "$work/unit/apassy-node.service"
sudo dpkg -r apassy
installed=0
[ ! -e /usr/bin/apassy ] || die 'dpkg -r left /usr/bin/apassy'

echo "== install.sh from a file:// directory"
mkdir -p "$work/site/dl" "$work/home"
cp "$dist/$tarball" "$work/site/dl/"
grep -F "  $tarball" "$dist/SHA256SUMS-node-$arch" > "$work/site/dl/SHA256SUMS"
HOME="$work/home" APASSY_RELAY_URL="file://$work/site" APASSY_INSTALL_DIR="$work/bin" \
    sh "$root/crates/apassy-relay/deploy/worker/public/install.sh"
[ "$("$work/bin/apassy" --version)" = "apassy $version" ] || die 'the installed apassy differs'
[ "$("$work/bin/apassy-team" --version 2>/dev/null)" = "apassy-team $version" ] ||
    die 'the installed apassy-team shim differs'
# A second run replaces the installation in place.
HOME="$work/home" APASSY_RELAY_URL="file://$work/site" APASSY_INSTALL_DIR="$work/bin" \
    sh "$root/crates/apassy-relay/deploy/worker/public/install.sh" >/dev/null

if [ "$containers" = 1 ]; then
    for image in debian:11-slim debian:12-slim; do
        echo "== $image"
        docker run --rm --network none -v "$dist:/dist:ro" -e VERSION="$version" \
            -e DEB="$deb" -e TARBALL="$tarball" "$image" sh -euc '
                dpkg -i "/dist/$DEB"
                test "$(apassy --version)" = "apassy $VERSION"
                test "$(apassy-team --version)" = "apassy-team $VERSION"
                mkdir /tmp/t
                tar -xzf "/dist/$TARBALL" -C /tmp/t
                test "$(/tmp/t/apassy-$VERSION-linux-'"$arch"'/apassy --version)" = "apassy $VERSION"
                dpkg -r apassy
            '
    done
fi
echo "verify.sh: the packages of $version for $arch pass."
