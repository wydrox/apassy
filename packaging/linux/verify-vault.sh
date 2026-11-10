#!/usr/bin/env bash
# Install/check/remove vault packages on a disposable Ubuntu CI runner.
# This verifies package mechanics, not a rendered desktop or real browser.
set -euo pipefail
fail() { printf 'verify-vault.sh: %s\n' "$*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
dist='' arch=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dist) dist=${2:?}; shift 2 ;;
        --arch) arch=${2:?}; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[ -n "$dist" ] && [ -n "$arch" ] || fail 'usage: verify-vault.sh --dist DIR --arch x86_64|aarch64'
[ "$(uname -m)" = "$arch" ] || fail 'verification must run on the selected architecture'
case "$arch" in x86_64) deb_arch=amd64 ;; aarch64) deb_arch=arm64 ;; *) fail 'unsupported architecture' ;; esac
dist=$(cd "$dist" && pwd)
version=$(awk -F '"' '/^version = / {print $2; exit}' "$root/crates/apassy-app/Cargo.toml")
deb="$dist/apassy-vault_${version}_${deb_arch}.deb"
tarball="apassy-vault-$version-linux-$arch.tar.gz"
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-vault-verify.XXXXXXXX")
installed=0
tar_installed=0
cleanup() {
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
[ ! -e /usr/bin/apassy ] && [ ! -e /usr/lib/apassy/apassy-browser-host ] || fail 'existing Apassy installation'
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
sudo env APASSY_COMPONENT=vault APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL="file://$work/site" \
    sh "$root/crates/apassy-relay/deploy/worker/public/install.sh"
[ "$(/usr/bin/apassy --version)" = "apassy $version" ] || fail 'tar installed version differs'
[ -x /usr/lib/apassy/apassy-browser-host ] || fail 'tar missing browser host'
# Updating the tar installation repeats all secure directory checks.
sudo env APASSY_COMPONENT=vault APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL="file://$work/site" \
    sh "$root/crates/apassy-relay/deploy/worker/public/install.sh"
printf 'verify-vault.sh: package mechanics passed for %s (%s); desktop/browser runtime NOT_RUN.\n' "$version" "$arch"
