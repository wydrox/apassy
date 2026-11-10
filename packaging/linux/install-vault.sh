#!/bin/sh
# Install an extracted, checksum-verified vault tarball into its trusted /usr layout.
set -eu
fail() { printf 'install-vault.sh: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Run as root after verifying the archive checksum.'
[ "$(uname -s)" = Linux ] || fail 'Linux is required.'
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Browser authentication trusts only this root-owned prefix. Do not support a
# per-user prefix or follow a symlink into a user-controlled directory.
for path in /usr /usr/bin /usr/lib /usr/share /usr/lib/apassy /usr/share/apassy \
    /usr/share/apassy/browser-extension /usr/share/apassy/native-messaging-hosts \
    /usr/share/apassy/native-messaging-hosts/google-chrome /usr/share/apassy/native-messaging-hosts/chromium /usr/share/applications /usr/share/doc \
    /usr/share/doc/apassy-vault /usr/share/polkit-1 /usr/share/polkit-1/actions; do
    [ ! -L "$path" ] || fail "Refusing symbolic-link directory: $path"
    if [ -e "$path" ]; then
        [ -d "$path" ] || fail "Not a directory: $path"
        [ "$(stat -c %u "$path")" = 0 ] || fail "Not root-owned: $path"
        [ "$(find "$path" -maxdepth 0 -perm /022 -print)" = '' ] || fail "Writable by another user: $path"
    fi
done
for path in /usr/bin/apassy /usr/bin/apassy-team /usr/lib/apassy/apassy-browser-host \
    /usr/share/applications/cc.wyderka.apassy.desktop /usr/share/polkit-1/actions/com.wydrox.apassy.policy; do
    [ ! -L "$path" ] || fail "Refusing symbolic-link target: $path"
    [ ! -d "$path" ] || fail "Not a regular executable target: $path"
done
# Reject unsafe entries even when called independently of the download installer.
[ -z "$(find "$here/usr" ! -type d ! -type f -print -quit)" ] || fail 'Archive contains a link or special file.'
# Copy only directories managed by this package; never recurse into existing links.
for destination in /usr/share/apassy/browser-extension /usr/share/apassy/native-messaging-hosts /usr/share/doc/apassy-vault; do
    [ ! -e "$destination" ] || [ -z "$(find "$destination" -type l -print -quit)" ] || fail "Existing symbolic link in $destination"
done
install -d -m 0755 /usr/lib/apassy /usr/share/apassy/browser-extension /usr/share/doc/apassy-vault /usr/share/applications /usr/share/polkit-1/actions /usr/share/apassy/native-messaging-hosts
install -m 0755 "$here/usr/bin/apassy" /usr/bin/apassy
install -m 0755 "$here/usr/bin/apassy-team" /usr/bin/apassy-team
install -m 0755 "$here/usr/lib/apassy/apassy-browser-host" /usr/lib/apassy/apassy-browser-host
cp -R "$here/usr/share/apassy/browser-extension/." /usr/share/apassy/browser-extension/
cp -R "$here/usr/share/apassy/native-messaging-hosts/." /usr/share/apassy/native-messaging-hosts/
cp -R "$here/usr/share/doc/apassy-vault/." /usr/share/doc/apassy-vault/
install -m 0644 "$here/usr/share/applications/cc.wyderka.apassy.desktop" /usr/share/applications/cc.wyderka.apassy.desktop
install -m 0644 "$here/usr/share/polkit-1/actions/com.wydrox.apassy.policy" /usr/share/polkit-1/actions/com.wydrox.apassy.policy
chown -R 0:0 /usr/lib/apassy /usr/share/apassy/browser-extension /usr/share/apassy/native-messaging-hosts /usr/share/doc/apassy-vault
chmod -R u=rwX,go=rX /usr/lib/apassy /usr/share/apassy/browser-extension /usr/share/apassy/native-messaging-hosts /usr/share/doc/apassy-vault
printf '%s\n' 'Installed Linux vault. Run apassy as your desktop user; enable the browser extension from that account.'
