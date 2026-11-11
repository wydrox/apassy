#!/bin/sh
# Install after a SHA-256 check against dl/SHA256SUMS.
# - Linux (x86_64, aarch64): the Apassy node `apassy` and the `apassy-team` shim (which
#   runs `apassy team`) from apassy-<version>-linux-<arch>.tar.gz. Then run `apassy up`.
# - macOS (arm64): the team CLI apassy-team. On a Mac the node runs inside the app.
# APASSY_COMPONENT: node (default) or vault. Vault installs the desktop, owner CLI
#   and browser host into fixed root-owned /usr paths; requires explicit root opt-in.
#   It supports Debian 12 or later and Ubuntu 22.04 or later, x86_64 and aarch64.
# APASSY_VAULT_FORMAT: deb (default where apt-get and dpkg-deb exist; apt installs the
#   dependencies) or tar (install-vault.sh; install the dependencies yourself).
# APASSY_ALLOW_UNSUPPORTED: set to 1 to install the vault on another glibc 2.31+
#   distribution, untested.
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

component=${APASSY_COMPONENT:-node}
case "$component" in node|vault) ;; *) fail 'APASSY_COMPONENT must be node or vault.' ;; esac
if [ "$component" = vault ]; then
    if [ "$(id -u)" != 0 ] || [ "${APASSY_INSTALL_AS_ROOT:-0}" != 1 ]; then
        fail 'Vault installation requires root and APASSY_INSTALL_AS_ROOT=1. Prefer the .deb package.'
    fi
    [ -z "${APASSY_INSTALL_DIR:-}" ] || fail 'Vault uses fixed /usr paths; do not set APASSY_INSTALL_DIR.'
    format=${APASSY_VAULT_FORMAT:-}
    case "$format" in ''|deb|tar) ;; *) fail 'APASSY_VAULT_FORMAT must be deb or tar.' ;; esac
fi

system=$(uname -s)
case "$system" in
    Darwin) os=darwin; checksum_tool=shasum ;;
    Linux) os=linux; checksum_tool=sha256sum ;;
    *) fail "The operating system is not supported: $system" ;;
esac
[ "$component" != vault ] || [ "$os" = linux ] || fail 'The vault package is Linux-only.'
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

# The vault packages are built on glibc 2.31 and tested on these distributions
# (docs/operations/release.md, "Linux vault packages"). Refuse the rest before any
# download, with the reason.
supported_vault='Debian 12 or later and Ubuntu 22.04 or later'
if [ "$component" = vault ]; then
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
    case "$libc" in
        'glibc '*) libc=${libc#glibc } ;;
        *) fail "The vault package needs glibc 2.31 or later; this system has no GNU C library (musl?). Supported: $supported_vault." ;;
    esac
    libc_major=${libc%%.*}
    libc_minor=${libc#*.}
    libc_minor=${libc_minor%%.*}
    case "$libc_major.$libc_minor" in
        *[!0-9.]*|.*|*.) fail "Cannot read the glibc version: $libc" ;;
    esac
    if [ "$libc_major" -lt 2 ] || { [ "$libc_major" -eq 2 ] && [ "$libc_minor" -lt 31 ]; }; then
        fail "The vault package needs glibc 2.31 or later; this system has $libc. Supported: $supported_vault."
    fi
    # Read os-release as data, never as a script. APASSY_OS_RELEASE is for tests.
    os_release=${APASSY_OS_RELEASE:-/etc/os-release}
    [ -r "$os_release" ] || os_release=/usr/lib/os-release
    os_field() {
        [ -r "$os_release" ] || return 0
        sed -n "s/^$1=//p" "$os_release" | head -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
    }
    distro_id=$(os_field ID)
    distro_version=$(os_field VERSION_ID)
    distro_name=$(os_field PRETTY_NAME)
    distro_major=${distro_version%%.*}
    distro_minor=${distro_version#"$distro_major"}
    distro_minor=${distro_minor#.}
    distro_minor=${distro_minor%%.*}
    supported=0
    case "$distro_id:$distro_major" in
        debian:*[!0-9]*|ubuntu:*[!0-9]*|debian:|ubuntu:) ;;
        debian:*) [ "$distro_major" -ge 12 ] && supported=1 ;;
        ubuntu:*)
            if [ "$distro_major" -gt 22 ] || { [ "$distro_major" -eq 22 ] && [ "${distro_minor:-0}" -ge 4 ] 2>/dev/null; }; then
                supported=1
            fi
            ;;
    esac
    if [ "$supported" != 1 ]; then
        [ "${APASSY_ALLOW_UNSUPPORTED:-0}" = 1 ] ||
            fail "The vault package supports $supported_vault; this system is ${distro_name:-unknown}. Set APASSY_ALLOW_UNSUPPORTED=1 to try it anyway (untested)."
        printf '%s\n' "Warning: ${distro_name:-this distribution} is not tested; APASSY_ALLOW_UNSUPPORTED=1." >&2
    fi
    if [ -z "$format" ]; then
        if command -v apt-get >/dev/null 2>&1 && command -v dpkg-deb >/dev/null 2>&1; then format=deb; else format=tar; fi
    fi
    if [ "$format" = deb ]; then
        command -v apt-get >/dev/null 2>&1 || fail 'APASSY_VAULT_FORMAT=deb needs apt-get; use APASSY_VAULT_FORMAT=tar.'
        command -v dpkg-deb >/dev/null 2>&1 || fail 'APASSY_VAULT_FORMAT=deb needs dpkg-deb; use APASSY_VAULT_FORMAT=tar.'
    fi
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
    case "$arch" in
        arm64) deb_arch=arm64 ;;
        *) deb_arch=amd64 ;;
    esac
    package_prefix=apassy
    pattern="^apassy-[0-9]+\\.[0-9]+\\.[0-9]+-linux-$node_arch\\.tar\\.gz\$"
    if [ "$component" = vault ]; then
        package_prefix=apassy-vault
        pattern="^apassy-vault-[0-9]+\\.[0-9]+\\.[0-9]+-linux-$node_arch\\.tar\\.gz\$"
        if [ "$format" = deb ]; then pattern="^apassy-vault_[0-9]+\\.[0-9]+\\.[0-9]+_$deb_arch\\.deb\$"; fi
    fi
    filename=$(awk -v pattern="$pattern" '
        {
            name = $2
            sub(/^\*/, "", name)
            if (name ~ pattern) {
                count++
                found = name
            }
        }
        END {
            if (count != 1) exit 1
            print found
        }
    ' "$work/SHA256SUMS") || fail "SHA256SUMS has no single requested package for Linux $node_arch."
    if [ "$component" = vault ] && [ "$format" = deb ]; then
        package_version=${filename#apassy-vault_}
        package_version=${package_version%_"$deb_arch".deb}
    else
        package_version=${filename#"$package_prefix"-}
        package_version=${package_version%-linux-"$node_arch".tar.gz}
    fi
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

if [ "$component" = vault ] && [ "$format" = deb ]; then
    # dpkg checks the C library and apt installs the dependencies of the package.
    for field in "Package apassy-vault" "Version $package_version" "Architecture $deb_arch"; do
        key=${field%% *}
        value=$(dpkg-deb --field "$work/$filename" "$key") || fail "Cannot read $filename."
        [ "$value" = "${field#* }" ] || fail "$filename has $key $value, not ${field#* }."
    done
    chmod 0755 "$work"
    chmod 0644 "$work/$filename"
    DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-noninteractive} apt-get install -y "$work/$filename" ||
        fail "apt-get cannot install $filename."
    actual_version=$(/usr/bin/apassy --version) || fail 'The installed vault cannot run.'
    [ "$actual_version" = "apassy $package_version" ] || fail 'The installed vault version differs from its package.'
    printf '%s\n' "$actual_version"
    exit 0
fi
if [ "$component" = vault ]; then
    top=${filename%.tar.gz}
    tar -tzf "$work/$filename" > "$work/entries" || fail "Cannot read $filename."
    awk -v top="$top" '
        $0 != top && $0 != top "/" && index($0, top "/") != 1 { bad = 1 }
        $0 ~ /(^|\/)\.\.(\/|$)/ { bad = 1 }
        END { exit bad ? 1 : 0 }
    ' "$work/entries" || fail "$filename has entries outside its package directory."
    tar -tvzf "$work/$filename" | awk '$1 !~ /^[-d]/ { bad = 1 } END { exit bad ? 1 : 0 }' ||
        fail "$filename has a link or a special file."
    mkdir "$work/unpacked"
    tar -xzf "$work/$filename" -C "$work/unpacked" || fail "Cannot unpack $filename."
    actual_version=$("$work/unpacked/$top/usr/bin/apassy" --version) || fail 'Vault executable cannot run.'
    [ "$actual_version" = "apassy $package_version" ] || fail 'Vault version differs from its filename.'
    sh "$work/unpacked/$top/install-vault.sh" || fail 'Cannot install the vault package.'
    printf '%s\n' "$actual_version"
    exit 0
fi

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
