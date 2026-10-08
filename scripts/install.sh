#!/bin/bash
# Install Apassy on this Mac from source, with one command:
#
#   /bin/bash -c "$(curl -fsSL https://apassy.wyderka.cc/install.sh)"
#
# The site serves this file (site/src/pages/install.sh.ts). Until the signed and
# notarized download is published, it is the way to install Apassy. It:
#
#   1. checks the Mac: macOS 15 or later on Apple silicon, git and Swift (Xcode or
#      the Command Line Tools), rustup, and an "Apple Development" signing identity;
#   2. clones the newest release of https://github.com/wydrox/apassy, or updates the
#      clone, in ~/Library/Caches/apassy/src;
#   3. runs scripts/build-app.sh of that release: it builds the app, signs it with
#      your identity, and runs its checks;
#   4. installs the app as /Applications/Apassy.app, where the agent sandbox
#      protects it.
#
# You sign this build; Apple does not notarize it, and it does not update itself.
# Run the command again for a new release. The script never uses sudo, and it asks
# before it replaces an app. The whole file downloads before it runs: each step is a
# function, and the last line calls main.
#
# Usage: install.sh [--check] [--yes]
#   --check   Check the Mac and stop. Nothing is cloned, built, or installed.
#   --yes     Answer yes to each question, for a run without a terminal.
#
#   /bin/bash -c "$(curl -fsSL https://apassy.wyderka.cc/install.sh)" install.sh --check
#
# Environment:
#   APASSY_VERSION        the release tag, for example v0.3.0. Default: the newest.
#   APASSY_SRC            the clone. Default: ~/Library/Caches/apassy/src.
#   APASSY_SIGN_IDENTITY  the SHA-1 or the name of the signing identity, when you
#                         have more than one.
#   APASSY_INSTALL_DIR    the folder of the app. Default: /Applications. The agent
#                         sandbox protects only /Applications/Apassy.app.
set -euo pipefail

REPO_URL="https://github.com/wydrox/apassy"
DOCS_URL="$REPO_URL/blob/main/docs/operations/daily-use.md"
MIN_MACOS=15
# A release build needs about 1.5 GB (the clone and target/), and some room to spare.
MIN_FREE_GB=3

if [ -t 1 ]; then
  BOLD=$'\033[1m' DIM=$'\033[2m' RED=$'\033[31m' GREEN=$'\033[32m' YELLOW=$'\033[33m' RESET=$'\033[0m'
else
  BOLD="" DIM="" RED="" GREEN="" YELLOW="" RESET=""
fi

step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
ok() { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
note() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail() {
  printf '\n%sapassy install: %s%s\n' "$RED" "$*" "$RESET" >&2
  exit 1
}

# problem MESSAGE HINT...: report a missing requirement. --check lists each one;
# an install stops at the first.
PROBLEMS=0
problem() {
  local message="$1"
  shift
  printf '  %s✗%s %s\n' "$RED" "$RESET" "$message"
  local hint
  for hint in "$@"; do printf '    %s%s%s\n' "$DIM" "$hint" "$RESET"; done
  PROBLEMS=$((PROBLEMS + 1))
  [ "$CHECK_ONLY" = "1" ] || fail "$message"
}

has_tty() { (: </dev/tty) 2>/dev/null; }

# ask QUESTION: 0 for yes. Questions read the terminal, because the script itself
# can come on standard input.
ask() {
  [ "$ASSUME_YES" = "1" ] && return 0
  has_tty || fail "$1 Run the command again with --yes to answer yes."
  local answer=""
  printf '%s [y/N] ' "$1" >/dev/tty
  read -r answer </dev/tty || true
  case "$answer" in y | Y | yes | Yes | YES) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------- checks

check_mac() {
  step "Check this Mac"
  if [ "$(uname -s)" != "Darwin" ]; then
    fail "this installer is for macOS. Apassy builds on Linux, but its app for Linux is not published yet: the isolation of agents uses macOS Seatbelt. See $REPO_URL#install."
  fi

  local version major
  version="$(sw_vers -productVersion)"
  major="${version%%.*}"
  if [ "$major" -ge "$MIN_MACOS" ] 2>/dev/null; then
    ok "macOS $version"
  else
    problem "macOS $version: Apassy needs macOS $MIN_MACOS or later."
  fi

  if [ "$(sysctl -in hw.optional.arm64 2>/dev/null || echo 0)" != "1" ]; then
    problem "an Intel Mac: Apassy needs Apple silicon."
  elif [ "$(uname -m)" != "arm64" ]; then
    problem "this shell runs under Rosetta." "Open a Terminal that runs natively (not under Rosetta) and run the command again."
  else
    ok "Apple silicon"
  fi

  if xcode-select -p >/dev/null 2>&1 && xcrun --find swiftc >/dev/null 2>&1 &&
    xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1 && xcrun --find git >/dev/null 2>&1; then
    ok "Swift and git ($(xcode-select -p))"
  else
    problem "no Swift compiler or git." "Install Xcode from the App Store, or run: xcode-select --install" \
      "With Xcode installed, open it once to accept its license, then run the command again."
  fi

  # rustup reads rust-toolchain.toml of the release and installs its Rust.
  # shellcheck source=/dev/null
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
  if command -v rustup >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    if rustup show 2>/dev/null | grep -qi '^default host: aarch64-apple-darwin'; then
      ok "rustup $(rustup --version 2>/dev/null | awk '{print $2; exit}')"
    else
      problem "rustup builds for Intel (x86_64), not Apple silicon." "Run: rustup set default-host aarch64-apple-darwin"
    fi
  else
    problem "no rustup." "Install it from https://rustup.rs:" \
      "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" \
      "Then open a new Terminal and run the command again."
  fi

  check_identity

  local free_kb
  free_kb="$(df -Pk "$HOME" 2>/dev/null | awk 'NR == 2 {print $4}')" || free_kb=""
  if [ "${free_kb:-0}" -ge $((MIN_FREE_GB * 1024 * 1024)) ]; then
    ok "$((free_kb / 1024 / 1024)) GB free"
  else
    problem "less than $MIN_FREE_GB GB free on the disk of your home folder." "The build needs about 1.5 GB. Free some space and run the command again."
  fi

  check_existing
}

# The build signs with an "Apple Development" identity (scripts/build-app.sh).
# A free Apple Account in Xcode gives one.
IDENTITY=""
IDENTITY_NAME=""
check_identity() {
  local identities matches count
  identities="$(security find-identity -v -p codesigning 2>/dev/null || true)"
  if [ -n "${APASSY_SIGN_IDENTITY:-}" ]; then
    matches="$(printf '%s\n' "$identities" | grep -F -- "$APASSY_SIGN_IDENTITY" | grep -E '^ *[0-9]+\) [0-9A-F]{40} "' || true)"
  else
    matches="$(printf '%s\n' "$identities" | grep '"Apple Development: ' || true)"
  fi
  count="$(printf '%s' "$matches" | grep -c . || true)"

  if [ "$count" = "0" ]; then
    if [ -n "${APASSY_SIGN_IDENTITY:-}" ]; then
      problem "no signing identity matches APASSY_SIGN_IDENTITY." "security find-identity -v -p codesigning lists the identities."
    else
      problem "no \"Apple Development\" signing identity." \
        "Open Xcode > Settings > Accounts and add your Apple Account (a free one works)." \
        "Select your team, click Manage Certificates…, click +, and choose Apple Development."
    fi
    return
  fi
  if [ "$count" != "1" ]; then
    printf '  %s!%s %s signing identities:\n' "$YELLOW" "$RESET" "$count"
    # Numbered by position in this list, the number that the question reads.
    printf '%s\n' "$matches" | awk -F'"' '{ split($1, f, " "); printf "      %d) %s  %s\n", NR, $2, f[2] }'
    if [ "$CHECK_ONLY" = "1" ] || ! has_tty || [ "$ASSUME_YES" = "1" ]; then
      problem "more than one identity." "Choose one: APASSY_SIGN_IDENTITY=<SHA-1> before the command."
      return
    fi
    local choice=""
    printf '    Use which one? [1-%s] ' "$count" >/dev/tty
    read -r choice </dev/tty || true
    [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$count" ] || fail "no identity was chosen."
    matches="$(printf '%s\n' "$matches" | sed -n "${choice}p")"
  fi
  IDENTITY="$(printf '%s\n' "$matches" | awk '{print $2}')"
  IDENTITY_NAME="$(printf '%s\n' "$matches" | sed -E 's/^[^"]*"(.*)"$/\1/')"
  ok "signing identity: $IDENTITY_NAME"
}

INSTALL_DIR="${APASSY_INSTALL_DIR:-/Applications}"
APP="$INSTALL_DIR/Apassy.app"

# The kind of app at $APP: "none", "notarized" (a Developer ID download), or
# "local" (a build from source).
app_kind() {
  if [ ! -e "$APP" ]; then
    echo none
  elif spctl --assess --type exec "$APP" >/dev/null 2>&1; then
    echo notarized
  else
    echo local
  fi
}

app_version() {
  /usr/bin/defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "?"
}

check_existing() {
  if [ "$INSTALL_DIR" != "/Applications" ]; then
    note "the app goes to $APP. The agent sandbox protects only /Applications/Apassy.app."
  fi
  if [ -e "$INSTALL_DIR" ] && [ ! -w "$INSTALL_DIR" ]; then
    problem "you cannot write $INSTALL_DIR." "Use an administrator account, or set APASSY_INSTALL_DIR."
  fi
  if running_app; then
    note "Apassy is running. Quit it before the install step at the end."
  fi
  case "$(app_kind)" in
    none) ok "no Apassy in $INSTALL_DIR yet" ;;
    notarized) note "$APP is the notarized Apassy $(app_version). The script asks before it replaces it." ;;
    *) ok "$APP $(app_version), built from source, will be replaced" ;;
  esac
}

# Ask about an app that the install replaces before the build, so each question
# comes first and the long part runs without you.
confirm_replace() {
  case "$(app_kind)" in
    notarized)
      ask "Replace the notarized Apassy $(app_version) in $INSTALL_DIR with a build from source? Your build does not update itself." ||
        fail "nothing was changed."
      ;;
    local)
      ask "Replace Apassy $(app_version) in $INSTALL_DIR with the newest release?" || fail "nothing was changed."
      ;;
  esac
}

# ---------------------------------------------------------------- source

SRC="${APASSY_SRC:-$HOME/Library/Caches/apassy/src}"
TAG=""

newest_release() {
  git ls-remote --tags --refs --sort=-v:refname "$REPO_URL" 'v*' |
    awk -F/ '{print $NF}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1
}

fetch_source() {
  step "Get the source"
  TAG="${APASSY_VERSION:-}"
  if [ -z "$TAG" ]; then
    TAG="$(newest_release)" || true
    [ -n "$TAG" ] || fail "cannot read the releases of $REPO_URL (git says why above). Check the network and run the command again."
  fi
  [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "APASSY_VERSION must be a release tag such as v0.3.0, not \"$TAG\"."

  if [ -d "$SRC/.git" ]; then
    # The stored URL: a url.<base>.insteadOf rewrite changes only what get-url shows.
    [ "$(git -C "$SRC" config --get remote.origin.url 2>/dev/null)" = "$REPO_URL" ] ||
      fail "$SRC is not a clone of $REPO_URL. Remove it, or set APASSY_SRC."
    git -C "$SRC" fetch --quiet --depth 1 origin "+refs/tags/$TAG:refs/tags/$TAG" ||
      fail "cannot fetch $TAG from $REPO_URL."
  else
    [ ! -e "$SRC" ] || fail "$SRC exists and is not a clone. Remove it, or set APASSY_SRC."
    mkdir -p "$(dirname "$SRC")"
    git clone --quiet --depth 1 --branch "$TAG" "$REPO_URL" "$SRC" || fail "cannot clone $REPO_URL."
  fi
  # A detached checkout of the tag. target/ stays, so a later release builds faster.
  git -C "$SRC" -c advice.detachedHead=false checkout --quiet --force "refs/tags/$TAG"
  ok "$TAG ($(git -C "$SRC" rev-parse --short HEAD)) in $SRC"
}

# ---------------------------------------------------------------- build

build_app() {
  step "Install the Rust toolchain of $TAG"
  local channel
  channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$SRC/rust-toolchain.toml")"
  [ -n "$channel" ] || fail "rust-toolchain.toml of $TAG names no channel."
  rustup toolchain install "$channel" --profile minimal --component clippy --component rustfmt ||
    fail "rustup cannot install Rust $channel. Check the network and run the command again."
  # rustup's cargo and rustc first on PATH: another cargo (Homebrew) would ignore
  # rust-toolchain.toml.
  PATH="$(dirname "$(command -v rustup)"):$PATH"
  export PATH
  local rustc_version
  rustc_version="$(cd "$SRC" && rustc --version 2>/dev/null)" || rustc_version=""
  case "$rustc_version" in
    "rustc $channel "*) ok "Rust $channel" ;;
    *) fail "the build would use \"${rustc_version:-no rustc}\" from $(command -v rustc || echo "nowhere"), not Rust $channel of rustup." ;;
  esac

  step "Build, sign, and check Apassy $TAG (this takes a few minutes)"
  (cd "$SRC" && APASSY_SIGN_IDENTITY="$IDENTITY" scripts/build-app.sh) ||
    fail "the build failed. The lines above say why. The clone stays in $SRC."
  [ -d "$SRC/target/Apassy.app" ] || fail "the build made no target/Apassy.app."
}

# ---------------------------------------------------------------- install

# The swap in install_app, for the cleanup: a stop in the middle (Ctrl-C, an error)
# removes the half copy and puts the old app back.
SWAP_NEW=""
SWAP_OLD=""
cleanup() {
  if [ -n "$SWAP_NEW" ]; then rm -rf "$SWAP_NEW"; fi
  if [ -n "$SWAP_OLD" ] && [ -e "$SWAP_OLD" ] && [ ! -e "$APP" ]; then
    mv "$SWAP_OLD" "$APP" && printf '  The old app is back in %s.\n' "$APP" >&2
  fi
}

# The main program of the app, of this user. apassy-mcp, which agent hosts start
# from the same folder, keeps running and is not the app.
running_app() {
  pgrep -U "$(id -u)" -f "^$APP/Contents/MacOS/apassy( |\$)" >/dev/null 2>&1
}

install_app() {
  step "Install $APP"
  while running_app; do
    has_tty && [ "$ASSUME_YES" != "1" ] || fail "Apassy is running. Quit it, then run the command again."
    printf '  Apassy is running. Quit it (Apassy > Quit), then press Return. ' >/dev/tty
    read -r _ </dev/tty || true
  done

  mkdir -p "$INSTALL_DIR"
  local new="$INSTALL_DIR/.Apassy.app.new.$$" old="$INSTALL_DIR/.Apassy.app.old.$$"
  rm -rf "$new" "$old"
  SWAP_NEW="$new"
  ditto "$SRC/target/Apassy.app" "$new" || fail "cannot copy the app to $INSTALL_DIR."
  codesign --verify --deep --strict "$new" 2>/dev/null ||
    fail "the copy in $INSTALL_DIR does not pass codesign --verify. Nothing was replaced."
  if [ -e "$APP" ]; then
    SWAP_OLD="$old"
    mv "$APP" "$old" || fail "cannot move the old app aside. Nothing was replaced."
  fi
  mv "$new" "$APP" || fail "cannot put the new app in place."
  SWAP_NEW=""
  SWAP_OLD=""
  rm -rf "$old" 2>/dev/null || note "cannot remove $old. Move it to the Trash in Finder."
  ok "Apassy $(app_version) in $APP"
}

finish() {
  printf '\n%sApassy %s is installed.%s\n\n' "$BOLD" "$TAG" "$RESET"
  printf '  Open it:   open -a Apassy\n'
  printf '  CLI tools: %s/Contents/MacOS/{apassy,apassy-mcp,apassy-hook,apassy-sandbox,apassy-browser-host}\n' "$APP"
  printf '  CLI setup: %s/blob/main/docs/operations/cli.md#1-install\n' "$REPO_URL"
  printf '  The installer does not change your PATH or shell files.\n'
  printf '  Next:      %s\n' "$DOCS_URL"
  printf '  Update:    run the same command again. This build is yours: it does not update itself.\n'
  printf '  Signed by: %s. Apple did not notarize it; it runs because you built it.\n' "$IDENTITY_NAME"
  printf '  Source:    %s (target/ keeps the build for faster updates)\n' "$SRC"
}

# ---------------------------------------------------------------- main

CHECK_ONLY=0
ASSUME_YES=0

main() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      --check) CHECK_ONLY=1 ;;
      --yes | -y) ASSUME_YES=1 ;;
      -h | --help)
        sed -n '2,35p' "${BASH_SOURCE[0]:-}" 2>/dev/null || echo "See $REPO_URL/blob/main/scripts/install.sh"
        return 0
        ;;
      *) fail "unknown option: $arg (use --check or --yes)" ;;
    esac
  done

  trap cleanup EXIT
  trap 'exit 130' INT TERM
  printf '%sApassy installer%s: builds Apassy from source on this Mac.\n' "$BOLD" "$RESET"
  check_mac
  if [ "$CHECK_ONLY" = "1" ]; then
    if [ "$PROBLEMS" = "0" ]; then
      printf '\n%sThis Mac can build Apassy.%s Run the command without --check to install.\n' "$GREEN" "$RESET"
      return 0
    fi
    printf '\n%s%s thing(s) to fix before Apassy can build.%s\n' "$RED" "$PROBLEMS" "$RESET"
    return 1
  fi
  confirm_replace
  fetch_source
  build_app
  install_app
  finish
}

main "$@"
