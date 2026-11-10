# Linux vault and browser passkeys

ADR [0045](../adr/0045-linux-vault-passkeys.md) extends the existing
[node-only Linux package](linux-node.md) with a SQLCipher vault, an egui desktop,
interactive owner commands and browser passkeys. The implementation targets
x86_64 and aarch64 on Ubuntu and Debian. CI produces architecture-specific
artifacts; this change does not publish a release or add a public download.

## Build and install

Build on Linux with the repository's pinned Rust toolchain:

```sh
cargo build --release --locked -p apassy-app -p apassy \
  --features apassy-app/window,apassy-app/node,apassy-app/owner \
  --bin apassy-app --bin apassy-browser-host
packaging/linux/build-vault.sh --binary target/release/apassy-app \
  --host target/release/apassy-browser-host --arch x86_64 --out dist
```

Use `--arch aarch64` on an arm64 machine. The packager rejects mismatched ELF
architectures and records the build's required glibc version, source commit,
SHA-256 checksums and Debian dependencies. Desktop artifacts use the build
runner's glibc baseline. The older node-only download retains its glibc 2.31
contract; do not infer that compatibility for desktop artifacts.

Verify `SHA256SUMS-vault-<arch>` from the CI artifact, then install:

```sh
sha256sum -c SHA256SUMS-vault-x86_64
sudo apt install ./apassy-vault_<version>_amd64.deb
```

Use `arm64` for the Debian package on aarch64. The `apassy-vault` package conflicts
with and replaces the node-only `apassy` package because both install
`/usr/bin/apassy`. Vault packages keep the node command interface. No daemon
starts during installation. The tar archive includes a root-only installer for
the same fixed `/usr` layout; install its dependencies first using the package
record. Tar installation is not tracked by dpkg.

The existing relay `install.sh` keeps node installation as its default.
`APASSY_COMPONENT=vault APASSY_INSTALL_AS_ROOT=1` selects a vault archive only
when the download origin's `dl/SHA256SUMS` contains exactly one matching vault
archive. It refuses a custom installation directory and needs root. This is
installer support for future publication, not a claim that a released archive
is available. For CI artifact qualification use a local `file://` origin.

## Owner use without a desktop

A passphrase is sufficient; no session bus, keyring, screen lock or biometric
reader is required. Run as the owner in an interactive terminal:

```sh
apassy owner create /path/to/vault.db
apassy owner list /path/to/vault.db
apassy owner backup /path/to/vault.db /path/to/backup.db
apassy owner change-passphrase /path/to/vault.db
apassy owner shell /path/to/vault.db
```

The commands read secrets from the terminal, without echo. Do not place a
passphrase in command arguments, environment variables or logs. Headless owner
commands refuse non-interactive input. Keep vault and backup files private.

Secret Service is optional: install `libsecret-tools` and explicitly opt in
with `apassy owner keyring-enable /path/to/vault.db`. Other same-user clients
can retrieve an item from an unlocked keyring. Use `keyring-disable` to remove
that convenience. Do not treat an unlocked keyring as user presence.

The optional polkit action `com.wydrox.apassy.owner-presence` requests `auth_self`
without retained authorization. `pkcheck` needs a session authentication agent;
its PAM stack may support fprintd. Failure, cancellation or missing support must
refuse the operation, with passphrase confirmation available. No biometric-only
path is required to unlock the vault.

## Desktop and browser

Run `apassy` as your desktop user. Secret and TOTP clipboard Copy is currently
unsupported on Linux; Show and browser fill remain available. Prefer Wayland: X11 clients can intercept
input. The package installs the desktop entry and the browser extension assets.
Use Apassy's browser extension installation flow from the desktop account.
Chrome stable and Chromium native manifests point to the trusted root-owned
`/usr/lib/apassy/apassy-browser-host`, with extension assets under
`/usr/share/apassy/browser-extension`. Root-owned native manifest templates for
each browser ship under `/usr/share/apassy/native-messaging-hosts/`; the owner
installation flow writes the per-user registration. A writable per-user binary prefix is
refused. The manifests are per user under these browser directories:

- `~/.config/google-chrome/NativeMessagingHosts/com.wydrox.apassy.json`
- `~/.config/chromium/NativeMessagingHosts/com.wydrox.apassy.json`

Browser authentication verifies kernel peer credentials, process ancestry and
root-owned executable paths. Unknown browser builds, writable executables,
mismatched users and stale process identities are refused. Origin, RP ID,
challenge, pending approval and user verification remain part of the shared
passkey flow. These checks are defense in depth; root and a compromised process
of the same user remain outside the software vault's protection. Linux does not
provide the macOS code-signing, Secure Enclave or Touch ID boundary.

## Screen lock, sleep and inactivity

The desktop observes the session over D-Bus (zbus, the client that the desktop
already links) and applies the macOS rules: "Lock after inactivity" locks the
vault, and the "How often to ask" window ends, at screen lock, sleep, user switch
and session end. Sources:

- systemd-logind on the system bus. The session is found by `XDG_SESSION_ID`,
  else logind's `auto` session, and must belong to this user. Its `Lock` and
  `Unlock` signals and `LockedHint`, `Active` and `State` changes; the manager's
  `PrepareForSleep` and `SessionRemoved`. A `delay` sleep inhibitor gives Apassy
  up to 2 seconds to lock before the system sleeps.
- `org.freedesktop.ScreenSaver` or `org.gnome.ScreenSaver` on the session bus:
  `ActiveChanged` and `GetActive`.
- The clocks: a suspend gap (`CLOCK_BOOTTIME` ran, `CLOCK_MONOTONIC` did not)
  counts as a sleep, also with no bus. Without the inhibitor the vault locks at
  the wake, before any other work.

Inactivity always counts input in the Apassy window; agent requests never reset
it. When the desktop maintains logind's idle hint (`IdleSinceHint` was set; GNOME
and KDE do), the vault also stays open while the hint says the session is active,
so work in other apps keeps it open. Without that hint, only input in Apassy counts.

Settings > Security names the missing sources. Full: a logind session, logind sleep
signals and a screen saver service. Partial (for example a minimal window manager
without a screen saver service): reuse works and ends at each lock and sleep that
Apassy sees; a locker that reports to neither source is not seen. None (no session
bus and no logind session: a container, SSH, a bare X server): approval reuse is
off, every sensitive action needs a fresh check, and you lock manually; the
inactivity time and the clock's sleep detection still apply. Each reuse also reads
the lock state again; any error, timeout or lost stream ends the window and keeps
reuse off until Apassy restarts. "How often to ask" and "Lock after inactivity" are
stored per device in `device-policy.json` in the data directory (mode 0600, this
user, no symlink); a damaged or too open file means "Every time" and "Never".
Headless owner commands can use the same rule without the desktop
(`apassy::native::session_lock::SessionLock`, and with the `session-bus` feature
`apassy::native::linux::session_bus::SessionObserver`).

## Verification evidence

The Linux vault CI matrix builds x86_64 and aarch64 app/host binaries, exercises
Linux browser identity refusal cases and the shared synthetic WebAuthn
registration/assertion test with signature verification, independently verifies real vault create/get and persistence with the synthetic RP,
then builds and checks
the deb and tar packages and the installer. It uses no real accounts.

A passing synthetic test proves the tested wire and cryptographic cases only.
Package installation does not prove rendered desktop operation, keyring/polkit
integration on a real session, or Chrome/Chromium passkey creation and sign-in.
Those need separate runtime qualification on both architectures, using synthetic
RP accounts and explicit approval/refusal, lock/unlock and cancellation checks.
For manual browser qualification, start the synthetic RP with
`cd extension-tests && npm run passkey-rp:start` and use its printed localhost
URL. Open Chrome stable or Chromium normally from the desktop, enable the
packaged extension, and open that URL. Complete create and sign-in with explicit
owner approval; the RP independently verifies registration and assertion. Repeat
with cancellation, refusal, locked vault and a restarted session. Do not launch
with automation or extension loading switches, and do not weaken caller checks
to make a test pass. Record the browser version, architecture, session type,
package commit and RP verification result separately for each run.

No release is complete until the six product components have been published
and read back at one shared new version under the release rules.
