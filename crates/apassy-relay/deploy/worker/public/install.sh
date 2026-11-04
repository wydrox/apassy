#!/bin/sh
# Install after a SHA-256 check against dl/SHA256SUMS.
# - Linux (x86_64, aarch64): the Apassy node `apassy` and the `apassy-team` shim (which
#   runs `apassy team`) from apassy-<version>-linux-<arch>.tar.gz. Then run `apassy up`.
# - macOS (arm64): the team CLI apassy-team. On a Mac the node runs inside the app.
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
    darwin-arm64|linux-x86_64|linux-arm64) ;;
    *) fail "Unsupported platform: $system/$machine. Supported platforms: macOS arm64, Linux x86_64, and Linux aarch64." ;;
esac
if [ "$os" = linux ]; then
    command -v tar >/dev/null 2>&1 || fail 'Install tar first.'
    command -v gzip >/dev/null 2>&1 || fail 'Install gzip first.'
fi

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
stage=
stage_shim=
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-install.XXXXXXXX") || fail 'Cannot make the temporary directory.'
cleanup() {
    if [ -n "$stage" ]; then
        rm -f "$stage"
    fi
    if [ -n "$stage_shim" ]; then
        rm -f "$stage_shim"
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
if [ "$os" = linux ]; then
    # The node tarball: exactly one apassy-<x.y.z>-linux-<arch>.tar.gz in SHA256SUMS.
    case "$arch" in
        arm64) node_arch=aarch64 ;;
        *) node_arch=x86_64 ;;
    esac
    filename=$(awk -v arch="$node_arch" '
        {
            name = $2
            sub(/^\*/, "", name)
            if (name ~ ("^apassy-[0-9]+\\.[0-9]+\\.[0-9]+-linux-" arch "\\.tar\\.gz$")) {
                count++
                found = name
            }
        }
        END {
            if (count != 1) exit 1
            print found
        }
    ' "$work/SHA256SUMS") || fail "SHA256SUMS has no single node package for Linux $node_arch."
    package_version=${filename#apassy-}
    package_version=${package_version%-linux-"$node_arch".tar.gz}
else
    filename="apassy-team-$os-$arch"
fi
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
if [ "$os" = linux ]; then
    # Only the two programs leave the archive, after a check of its entries: one
    # directory of that name, no absolute path, no `..`, no link.
    top=${filename%.tar.gz}
    tar -tzf "$work/$filename" > "$work/entries" || fail "Cannot read $filename."
    awk -v top="$top" '
        $0 != top && $0 != top "/" && index($0, top "/") != 1 { bad = 1 }
        $0 ~ /(^|\/)\.\.(\/|$)/ { bad = 1 }
        END { exit bad ? 1 : 0 }
    ' "$work/entries" || fail "$filename has entries outside $top/."
    tar -tvzf "$work/$filename" | awk '$1 ~ /^[lhcbp]/ { bad = 1 } END { exit bad ? 1 : 0 }' ||
        fail "$filename has a link or a special file."
    mkdir "$work/unpacked" || fail 'Cannot make the unpack directory.'
    tar -xzf "$work/$filename" -C "$work/unpacked" "$top/apassy" "$top/apassy-team" ||
        fail "Cannot unpack $filename."
    program=apassy
    source="$work/unpacked/$top/apassy"
    version_pattern="^apassy $package_version\$"
else
    program=apassy-team
    source="$work/$filename"
    version_pattern='^apassy-team [0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$'
fi
installed="$target/$program"
[ ! -d "$installed" ] || fail "The target is a directory: $installed"
stage=$(mktemp "$target/.$program.XXXXXXXX") || fail 'Cannot make the temporary installation file.'
cp "$source" "$stage" || fail "Cannot copy $program."
chmod 0755 "$stage" || fail 'Cannot set the file mode.'
# Validate the executable before touching a previous installation.
staged_version=$("$stage" --version) || fail 'The staged executable cannot run on this platform; the previous installation is unchanged.'
version_lines=$(printf '%s\n' "$staged_version" | wc -l)
[ "$version_lines" -eq 1 ] || fail 'The staged executable returned multiple version lines; the previous installation is unchanged.'
printf '%s\n' "$staged_version" | LC_ALL=C grep -Eq "$version_pattern" || fail 'The staged executable returned an invalid version; the previous installation is unchanged.'
if [ "$os" = linux ]; then
    shim="$target/apassy-team"
    [ ! -d "$shim" ] || fail "The target is a directory: $shim"
    stage_shim=$(mktemp "$target/.apassy-team.XXXXXXXX") || fail 'Cannot make the temporary installation file.'
    cp "$work/unpacked/$top/apassy-team" "$stage_shim" || fail 'Cannot copy the apassy-team shim.'
    chmod 0755 "$stage_shim" || fail 'Cannot set the file mode.'
fi
mv -f "$stage" "$installed" || fail "Cannot install $program."
stage=
if [ -n "$stage_shim" ]; then
    # apassy-team becomes the shim that runs `apassy team` in the same directory.
    mv -f "$stage_shim" "$target/apassy-team" || fail 'Cannot install the apassy-team shim.'
    stage_shim=
fi

printf 'Installed: %s\n' "$installed"
printf '%s\n' "$staged_version"
if [ "$os" = linux ]; then
    printf 'Installed: %s (it runs apassy team)\n' "$target/apassy-team"
fi
case ":${PATH:-}:" in
    *":$target:"*) ;;
    *)
        # Single quotes protect spaces, shell variables, and command text.
        quoted_target=$(printf '%s' "$target" | sed "s/'/'\\\\''/g")
        printf 'Add the directory to PATH with this command:\n'
        printf "export PATH='%s':\"\$PATH\"\n" "$quoted_target"
        ;;
esac

config_dir=${XDG_CONFIG_HOME:-"$HOME/.config"}
if [ "$os" = linux ]; then
    if [ -f "$config_dir/systemd/user/apassy-node.service" ]; then
        printf '%s\n' 'The node keeps its old executable until it restarts: systemctl --user restart apassy-node.service' >&2
    else
        printf '%s\n' 'Next: apassy up (it starts the node as a systemd user service and prints a pairing link).' >&2
    fi
    team_command='apassy team'
else
    team_command='apassy-team'
fi
# Replacing the file does not replace a running process. Reinstall each saved
# team's service to restart it and migrate an old single service if necessary.
printf '%s\n' 'Running hosts keep their old executable until restarted.' >&2
for service in "$HOME"/Library/LaunchAgents/com.wydrox.apassy.team-host*.plist "$config_dir"/systemd/user/apassy-team-host*.service; do
    [ -f "$service" ] || continue
    name=${service##*/}
    case "$name" in
        com.wydrox.apassy.team-host.t_*.plist) team=${name#com.wydrox.apassy.team-host.}; team=${team%.plist} ;;
        apassy-team-host-t_*.service) team=${name#apassy-team-host-}; team=${team%.service} ;;
        *) printf 'Legacy host service found: use %s --team TEAM_ID host install to migrate and restart its team.\n' "$team_command" >&2; continue ;;
    esac
    printf '%s\n' "$team" | LC_ALL=C grep -Eq '^t_[a-z2-7]{10}$' || continue
    printf 'Restart: %s --team %s host install\n' "$team_command" "$team" >&2
    printf 'Check: %s --team %s host status\n' "$team_command" "$team" >&2
done
printf 'For any foreground host, stop it and start it again. Check %s --version and each team with %s --team TEAM_ID host status.\n' "$team_command" "$team_command" >&2
