#!/usr/bin/env bash
# Install/check/remove vault packages on a disposable Ubuntu CI runner.
# Usage: verify-vault.sh --dist DIR --arch x86_64|aarch64 [--containers]
#
# On this machine: the checksums, the deb fields, apt install, the version, the files
# and their owners, the refusal of piped owner input, removal, and install.sh from a
# file:// directory (tar, twice). With --containers (Docker, Xvfb, xwininfo), in
# minimal Debian 12 and 13 and Ubuntu 22.04 and 24.04 containers: `apt-get install
# --no-install-recommends` of the deb resolves its dependencies, both executables load
# (`ldd -r`: no missing library or symbol version), the tarball's apassy runs, and the
# window starts on an Xvfb display of this machine and maps a window named Apassy.
# It verifies package mechanics and that the window starts, not a browser.
set -euo pipefail
fail() { printf 'verify-vault.sh: %s\n' "$*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
dist='' arch='' containers=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dist) dist=${2:?}; shift 2 ;;
        --arch) arch=${2:?}; shift 2 ;;
        --containers) containers=1; shift ;;
        *) fail "unknown argument: $1" ;;
    esac
done
if [ -z "$dist" ] || [ -z "$arch" ]; then
    fail 'usage: verify-vault.sh --dist DIR --arch x86_64|aarch64 [--containers]'
fi
[ "$(uname -m)" = "$arch" ] || fail 'verification must run on the selected architecture'
case "$arch" in x86_64) deb_arch=amd64 ;; aarch64) deb_arch=arm64 ;; *) fail 'unsupported architecture' ;; esac
dist=$(cd "$dist" && pwd)
version=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$root/release-versions.json")
deb="$dist/apassy-vault_${version}_${deb_arch}.deb"
tarball="apassy-vault-$version-linux-$arch.tar.gz"
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-vault-verify.XXXXXXXX")
installed=0
tar_installed=0
container=''
xvfb=''
cleanup() {
    if [ -n "$container" ]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
    if [ -n "$xvfb" ]; then kill "$xvfb" 2>/dev/null || true; fi
    if [ "$installed" = 1 ]; then sudo dpkg -r apassy-vault >/dev/null 2>&1 || true; fi
    if [ "$tar_installed" = 1 ]; then
        sudo rm -f /usr/bin/apassy /usr/bin/apassy-team /usr/lib/apassy/apassy-browser-host \
            /usr/share/applications/cc.wyderka.apassy.desktop /usr/share/polkit-1/actions/com.wydrox.apassy.policy
        sudo rm -rf /usr/share/apassy/native-messaging-hosts /usr/share/apassy/browser-extension /usr/share/doc/apassy-vault
    fi
    rm -rf "$work"
}
trap cleanup EXIT
# Refuse a pre-existing installation: this verifier is only for disposable CI.
if [ -e /usr/bin/apassy ] || [ -e /usr/lib/apassy/apassy-browser-host ]; then
    fail 'existing Apassy installation'
fi
(cd "$dist" && sha256sum -c "SHA256SUMS-vault-$arch")
[ "$(wc -l < "$dist/SHA256SUMS-vault-$arch")" -eq 2 ] || fail 'expected exactly two package checksums'
[ "$(dpkg-deb --field "$deb" Package)" = apassy-vault ] || fail 'wrong package name'
[ "$(dpkg-deb --field "$deb" Architecture)" = "$deb_arch" ] || fail 'wrong package architecture'
[ "$(dpkg-deb --field "$deb" Version)" = "$version" ] || fail 'wrong package version'
sudo apt-get install -y "$deb"
installed=1
[ "$(/usr/bin/apassy --version)" = "apassy $version" ] || fail 'installed version differs'
[ -x /usr/lib/apassy/apassy-browser-host ] || fail 'missing browser host'
for browser in google-chrome chromium; do
    [ -f "/usr/share/apassy/native-messaging-hosts/$browser/com.wydrox.apassy.json" ] || fail 'missing native manifest template'
done
[ -f /usr/share/apassy/browser-extension/manifest.json ] || fail 'missing extension'
[ -f /usr/share/polkit-1/actions/com.wydrox.apassy.policy ] || fail 'missing polkit action'
[ -z "$(find /usr/lib/apassy /usr/share/apassy/browser-extension -perm /022 -print -quit)" ] || fail 'writable package files'
[ -z "$(find /usr/lib/apassy /usr/share/apassy/browser-extension ! -uid 0 -print -quit)" ] || fail 'non-root package files'
# Owner commands must refuse pipes rather than reading a passphrase from stdin.
if /usr/bin/apassy owner create "$work/headless.db" </dev/null >"$work/owner.log" 2>&1; then
    fail 'owner create unexpectedly accepted non-interactive input'
fi
[ ! -e "$work/headless.db" ] || fail 'non-interactive owner command created a vault'
sudo dpkg -r apassy-vault
installed=0
[ ! -e /usr/bin/apassy ] || fail 'deb removal left the executable'
mkdir -p "$work/site/dl"
cp "$dist/$tarball" "$work/site/dl/"
grep -F "  $tarball" "$dist/SHA256SUMS-vault-$arch" > "$work/site/dl/SHA256SUMS"
tar_installed=1
sudo env APASSY_COMPONENT=vault APASSY_VAULT_FORMAT=tar APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL="file://$work/site" \
    sh "$root/crates/apassy-relay/deploy/worker/public/install.sh"
[ "$(/usr/bin/apassy --version)" = "apassy $version" ] || fail 'tar installed version differs'
[ -x /usr/lib/apassy/apassy-browser-host ] || fail 'tar missing browser host'
# Updating the tar installation repeats all secure directory checks.
sudo env APASSY_COMPONENT=vault APASSY_VAULT_FORMAT=tar APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL="file://$work/site" \
    sh "$root/crates/apassy-relay/deploy/worker/public/install.sh"
if [ "$containers" = 0 ]; then
    printf 'verify-vault.sh: package mechanics passed for %s (%s); desktop/browser runtime NOT_RUN.\n' "$version" "$arch"
    exit 0
fi

# The supported distributions, each as a minimal container. The window connects to an
# Xvfb display of this machine, so the container holds only the package's dependencies.
for tool in docker Xvfb xwininfo; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
display=0
for image in debian:12-slim debian:13-slim ubuntu:22.04 ubuntu:24.04; do
    display=$((display + 1))
    echo "== $image"
    Xvfb ":9$display" -ac -nolisten tcp -screen 0 1280x800x24 >"$work/xvfb-$display.log" 2>&1 &
    xvfb=$!
    for _ in $(seq 50); do [ -S "/tmp/.X11-unix/X9$display" ] && break; sleep 0.2; done
    [ -S "/tmp/.X11-unix/X9$display" ] || fail "Xvfb :9$display did not start"
    container="apassy-vault-verify-$display"
    docker run -d --name "$container" -v "$dist:/dist:ro" -v /tmp/.X11-unix:/tmp/.X11-unix \
        "$image" sleep infinity >/dev/null
    docker exec -e DEBIAN_FRONTEND=noninteractive -e VERSION="$version" -e DEB="${deb##*/}" \
        -e TARBALL="$tarball" -e ARCH="$arch" "$container" sh -euc '
            . /etc/os-release; echo "$PRETTY_NAME, $(ldd --version | head -n 1)"
            apt-get update -q >/dev/null
            cp "/dist/$DEB" /tmp/
            apt-get install -y -q --no-install-recommends "/tmp/$DEB" >/tmp/apt.log || { cat /tmp/apt.log; exit 1; }
            test "$(apassy --version)" = "apassy $VERSION"
            for executable in /usr/bin/apassy /usr/lib/apassy/apassy-browser-host; do
                if ldd -r "$executable" 2>&1 | grep "not found"; then exit 1; fi
            done
            mkdir /tmp/t
            tar -xzf "/dist/$TARBALL" -C /tmp/t
            test "$(/tmp/t/apassy-vault-$VERSION-linux-$ARCH/usr/bin/apassy --version)" = "apassy $VERSION"
            useradd -m apassy-verify
        '
    docker exec -d -u apassy-verify -e DISPLAY=":9$display" -e HOME=/home/apassy-verify "$container" \
        sh -c 'exec /usr/bin/apassy >/tmp/window.log 2>&1'
    shown=''
    for _ in $(seq 60); do
        shown=$(xwininfo -root -tree -display ":9$display" | grep -F '"Apassy"' || true)
        [ -n "$shown" ] && break
        sleep 0.5
    done
    sleep 3
    # Minimal images have no pgrep: the window must still run after the wait.
    if [ -z "$shown" ] || ! docker exec "$container" sh -c 'grep -qx apassy /proc/[0-9]*/comm 2>/dev/null'; then
        docker exec "$container" cat /tmp/window.log || true
        fail "the window did not start in $image"
    fi
    echo "window: $shown"
    docker rm -f "$container" >/dev/null
    container=''
    kill "$xvfb"
    wait "$xvfb" 2>/dev/null || true
    xvfb=''
done
printf 'verify-vault.sh: package mechanics and the window passed for %s (%s) in Debian 12, 13 and Ubuntu 22.04, 24.04; browser runtime NOT_RUN.\n' "$version" "$arch"
