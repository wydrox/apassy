# Linux vault and browser passkeys

ADR [0045](../adr/0045-linux-vault-passkeys.md) extends the existing
[node-only Linux package](linux-node.md) with a SQLCipher vault, an egui desktop,
interactive owner commands and browser passkeys. The implementation targets
x86_64 and aarch64 on Ubuntu and Debian. CI produces architecture-specific
artifacts; this change does not publish a release or add a public download.
The CI desktop artifacts depend on `libc6 (>= 2.39)`: Ubuntu 24.04 or later and
Debian 13 or later. Ubuntu 22.04 and Debian 12 refuse the package. The runtime
acceptance record is
[docs/reviews/linux-acceptance-2026-11.md](../reviews/linux-acceptance-2026-11.md); its
re-runnable kit is `packaging/linux/acceptance/`.

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
can retrieve an item from an unlocked keyring. Only `apassy owner unlock-keyring
/path/to/vault.db` reads that item; it opens the same terminal session as
`apassy owner unlock`. The desktop window does not read it. Use `keyring-disable`
to remove that convenience. Do not treat an unlocked keyring as user presence.

The optional polkit action `com.wydrox.apassy.owner-presence` requests `auth_self`
without retained authorization. `pkcheck` needs a session authentication agent;
its PAM stack may support fprintd. A desktop's agent serves the whole session. In
a text session, run `pkttyagent --process "$(pgrep -xo apassy)"` in another
terminal of the same user: `pkttyagent` without `--process` serves only its own
parent process. `allow_active` needs a local, active seat session; from an SSH
session polkit answers "Not authorized" without a prompt. Failure, cancellation
or missing support must refuse the operation, with passphrase confirmation
available. No biometric-only path is required to unlock the vault.

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

Run `apassy setup browser --browser chrome` (or `chromium`) once: without
`--browser` it writes nothing for a browser that has not created its profile
yet. Then, in the browser, turn on Developer mode on `chrome://extensions`, choose
Load unpacked and select `/usr/share/apassy/browser-extension`; its manifest key
gives it the ID `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih`. Observed browser limits
(2026-11-10):

- Ubuntu ships Chromium only as a snap. The snap cannot see
  `/usr/lib/apassy` or `/usr/share/apassy`, reads its manifests from
  `~/snap/chromium/common/chromium`, and runs from a `/snap` path that the caller
  check refuses. Use Google Chrome on Ubuntu.
- Debian's `chromium` package adds `--load-extension=…` to every start
  (`/etc/chromium.d/extensions`). Apassy refuses a browser started with that
  switch, so passkeys, fill and save are refused in Debian's Chromium as packaged.

Browser authentication verifies kernel peer credentials, process ancestry and
root-owned executable paths. Unknown browser builds, writable executables,
mismatched users and stale process identities are refused. Origin, RP ID,
challenge, pending approval and user verification remain part of the shared
passkey flow. These checks are defense in depth; root and a compromised process
of the same user remain outside the software vault's protection. Linux does not
provide the macOS code-signing, Secure Enclave or Touch ID boundary.

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
