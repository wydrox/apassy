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

case "$os-$arch" in
    darwin-arm64|linux-x86_64) ;;
    *) fail "Unsupported platform: $system/$machine. Supported platforms: macOS arm64 and Linux x86_64." ;;
esac

if command -v curl >/dev/null 2>&1; then
    downloader=curl
elif command -v wget >/dev/null 2>&1; then
    downloader=wget
    if command -v timeout >/dev/null 2>&1; then
        download_timeout=timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        download_timeout=gtimeout
    else
        fail 'Install curl, or provide timeout with wget for bounded downloads.'
    fi
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
        curl -fsSL --connect-timeout 10 --max-time 120 -- "$1" > "$2"
    else
        # wget does not accept file:// URLs. Read local test files directly.
        case "$1" in
            file:///*) cat "${1#file://}" > "$2" ;;
            *) "$download_timeout" --kill-after=5 120 wget -qO- --timeout=30 --tries=2 -- "$1" > "$2" ;;
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
# Validate the executable before touching a previous installation.
staged_version=$("$stage" --version) || fail 'The staged executable cannot run on this platform; the previous installation is unchanged.'
version_lines=$(printf '%s\n' "$staged_version" | wc -l)
[ "$version_lines" -eq 1 ] || fail 'The staged executable returned multiple version lines; the previous installation is unchanged.'
printf '%s\n' "$staged_version" | LC_ALL=C grep -Eq '^apassy-team [0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$' || fail 'The staged executable returned an invalid version; the previous installation is unchanged.'
mv -f "$stage" "$installed" || fail 'Cannot install apassy-team.'
stage=

printf 'Installed: %s\n' "$installed"
printf '%s\n' "$staged_version"
case ":${PATH:-}:" in
    *":$target:"*) ;;
    *)
        # Single quotes protect spaces, shell variables, and command text.
        quoted_target=$(printf '%s' "$target" | sed "s/'/'\\\\''/g")
        printf 'Add the directory to PATH with this command:\n'
        printf "export PATH='%s':\"\$PATH\"\n" "$quoted_target"
        ;;
esac

# Replacing the file does not replace a running process. Reinstall each saved
# team's service to restart it and migrate an old single service if necessary.
printf '%s\n' 'Running hosts keep their old executable until restarted.' >&2
config_dir=${XDG_CONFIG_HOME:-"$HOME/.config"}
for service in "$HOME"/Library/LaunchAgents/com.wydrox.apassy.team-host*.plist "$config_dir"/systemd/user/apassy-team-host*.service; do
    [ -f "$service" ] || continue
    name=${service##*/}
    case "$name" in
        com.wydrox.apassy.team-host.t_*.plist) team=${name#com.wydrox.apassy.team-host.}; team=${team%.plist} ;;
        apassy-team-host-t_*.service) team=${name#apassy-team-host-}; team=${team%.service} ;;
        *) printf '%s\n' 'Legacy host service found: use apassy-team --team TEAM_ID host install to migrate and restart its team.' >&2; continue ;;
    esac
    printf '%s\n' "$team" | LC_ALL=C grep -Eq '^t_[a-z2-7]{10}$' || continue
    printf 'Restart: apassy-team --team %s host install\n' "$team" >&2
    printf 'Check: apassy-team --team %s host status\n' "$team" >&2
done
printf '%s\n' 'For any foreground host, stop it and start it again. Check apassy-team --version and each team with apassy-team --team TEAM_ID host status.' >&2
