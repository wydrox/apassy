#!/bin/sh
# Install apassy-team after a SHA-256 check against dl/SHA256SUMS.
# APASSY_RELAY_URL: download origin (default: https://apassy-relay.wyderka.cc).
#   A file:// URL can point to a local directory for tests.
# APASSY_INSTALL_DIR: target directory (default: $HOME/.local/bin).
# APASSY_INSTALL_AS_ROOT: set to 1 to permit installation as root.
set -eu

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

if [ "$(id -u)" = 0 ] && [ "${APASSY_INSTALL_AS_ROOT:-0}" != 1 ]; then
    fail 'Do not run as root. Set APASSY_INSTALL_AS_ROOT=1 to permit root.'
fi

system=$(uname -s)
case "$system" in
    Darwin) os=darwin; checksum_tool=shasum ;;
    Linux) os=linux; checksum_tool=sha256sum ;;
    *) fail "The operating system is not supported: $system" ;;
esac
machine=$(uname -m)
case "$machine" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=x86_64 ;;
    *) fail "The architecture is not supported: $machine" ;;
esac

if command -v curl >/dev/null 2>&1; then
    downloader=curl
elif command -v wget >/dev/null 2>&1; then
    downloader=wget
else
    fail 'Install curl or wget first.'
fi
command -v "$checksum_tool" >/dev/null 2>&1 || fail "Install $checksum_tool first."

base=${APASSY_RELAY_URL:-https://apassy-relay.wyderka.cc}
base=${base%/}
target=${APASSY_INSTALL_DIR:-"$HOME/.local/bin"}
case "$target" in
    /*) ;;
    *) target="$(pwd)/$target" ;;
esac
filename="apassy-team-$os-$arch"
stage=
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-install.XXXXXXXX") || fail 'Cannot make the temporary directory.'
cleanup() {
    if [ -n "$stage" ]; then
        rm -f "$stage"
    fi
    rm -rf "$work"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

download() {
    if [ "$downloader" = curl ]; then
        curl -fsSL -- "$1" > "$2"
    else
        # wget does not accept file:// URLs. Read local test files directly.
        case "$1" in
            file:///*) cat "${1#file://}" > "$2" ;;
            *) wget -qO- -- "$1" > "$2" ;;
        esac
    fi
}

download "$base/dl/SHA256SUMS" "$work/SHA256SUMS" || fail 'Cannot download SHA256SUMS.'
# Accept the exact filename in the standard text or binary checksum format.
# Refuse missing entries, duplicate entries, and invalid SHA-256 values.
expected=$(awk -v name="$filename" '
    $2 == name || $2 == "*" name {
        count++
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) bad = 1
        hash = tolower($1)
    }
    END {
        if (count != 1 || bad) exit 1
        print hash
    }
' "$work/SHA256SUMS") || fail "SHA256SUMS has no single valid entry for $filename."

download "$base/dl/$filename" "$work/$filename" || fail "Cannot download $filename."
if [ "$os" = darwin ]; then
    checksum=$(shasum -a 256 "$work/$filename") || fail 'Cannot calculate SHA-256.'
else
    checksum=$(sha256sum "$work/$filename") || fail 'Cannot calculate SHA-256.'
fi
actual=${checksum%% *}
[ "$actual" = "$expected" ] || fail "The SHA-256 check failed for $filename."

mkdir -p "$target" || fail "Cannot make the target directory: $target"
installed="$target/apassy-team"
[ ! -d "$installed" ] || fail "The target is a directory: $installed"
stage=$(mktemp "$target/.apassy-team.XXXXXXXX") || fail 'Cannot make the temporary installation file.'
cp "$work/$filename" "$stage" || fail 'Cannot copy apassy-team.'
chmod 0755 "$stage" || fail 'Cannot set the file mode.'
mv -f "$stage" "$installed" || fail 'Cannot install apassy-team.'
stage=

printf 'Installed: %s\n' "$installed"
"$installed" --version
case ":${PATH:-}:" in
    *":$target:"*) ;;
    *)
        # Single quotes protect spaces, shell variables, and command text.
        quoted_target=$(printf '%s' "$target" | sed "s/'/'\\\\''/g")
        printf 'Add the directory to PATH with this command:\n'
        printf "export PATH='%s':\"\$PATH\"\n" "$quoted_target"
        ;;
esac
