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

### Browser and agents without a desktop: `apassy owner serve`

`apassy owner serve /path/to/vault.db` unlocks the vault in the terminal and then
serves the browser native host (passkey create and sign-in, fill, save) and agents
(runs with secrets, access requests, bouncer questions) until `lock` or `quit`, the
end of the terminal, or the inactivity time. Each request shows its facts in the
terminal and needs a typed `approve` and the vault passphrase (or `approve polkit`);
`deny` refuses. No check is reused for a second request. It refuses to start
without a terminal on stdin and stdout, and while the desktop app or another `owner serve` runs for the same data
directory. Do not run it from a systemd unit, cron or a pipe. To keep it running over
SSH, start it in tmux or screen and attach to approve:

```sh
tmux new -s apassy 'apassy owner serve /path/to/vault.db'   # detach: Ctrl-b d
tmux attach -t apassy                                        # to approve a request
screen -S apassy apassy owner serve /path/to/vault.db        # or with screen
```

While it waits detached, a request times out after 215 s (browser) or 5 minutes
(agents) unless you attach and answer. Headless, these do not work: agent fills of the
browser, browser debugging permission, "approve and remember" and project answers, the
owner command line of `owner.sock` (`apassy items …`), iPhone approvals, sync and the
node of the desktop.

When it locks by itself:

- The inactivity time: `--idle-minutes N` (1 to 1440) when given, else "Lock after
  inactivity" of the device settings when it names a time (15 minutes, 1 hour,
  4 hours), else 15 minutes. "Never" and "When the screen locks or the computer
  sleeps" keep the 15 minutes. Only a line typed in this terminal resets it; agent
  and browser requests do not. The time counts on the sleep-inclusive clock, so the
  time that the computer slept counts. While the desktop's logind idle hint says the
  session is active (you work in another app of that session), it does not lock.
- With "When the screen locks or the computer sleeps": also at a screen lock, a
  sleep, a user switch and the end of the login session. The desktop package reads
  them over D-Bus, as the desktop does (below). A build without D-Bus (the headless
  test build `--no-default-features --features node,owner`) sees a sleep only after
  the wake, from the clocks, and sees no screen lock.
- A damaged, foreign or too open `device-policy.json` gives 15 minutes (or
  `--idle-minutes`) and the screen-lock rule, and the service says so at the start.

The service locks the vault, stops both sockets, ends each waiting run and cancels
each waiting browser request, and prints why.

SIGTERM, SIGHUP and SIGINT (Ctrl-C) end the process at once with their default
action; the service installs no signal handler (the crate forbids `unsafe`). The
vault key exists only in the process memory, so it leaves with the process (no core
file); the vault file needs no lock step. The kernel closes the sockets and frees
`owner.lock`; waiting agent runs and browser requests fail with a closed connection,
and the next start removes the stale socket files. A signal at a passphrase prompt
leaves the terminal echo off: type `stty echo` (or `reset`).

## Desktop and browser

Run `apassy` as your desktop user. Prefer Wayland: X11 clients can intercept
input.

Clipboard Copy of secrets and TOTP codes (src/desktop/clipboard/linux.rs) has the
macOS guarantees. Apassy owns the clipboard itself and serves the value to each
paste with `x-kde-passwordManagerHint: secret`, which Klipper, CopyQ and
wl-clipboard/cliphist honour. When another app copies, Apassy stops serving the
value and never touches that clipboard again. After the clear time, on lock,
vault switch and quit, it replaces only its own copy with an empty one: GNOME's
Mutter keeps and restores the last text clipboard and ignores the hint, so a
plain release would bring the value back. The session decides the mechanism:
Wayland uses ext-data-control-v1 or wlr-data-control (wlroots compositors, KWin);
a compositor without them (GNOME on Wayland) uses the X11 clipboard through
XWayland, which Mutter bridges to Wayland apps; an X11 session uses X11. With no
display, or Wayland without data-control and without XWayland,
Copy stays disabled, its hover names the reason, and Show and browser fill
remain. Every client of the session can read the clipboard while Apassy owns it,
and a clipboard manager that ignores the hint can keep the value. Values above
64 KiB are refused. Headless owner commands never write the clipboard.

The package installs the desktop entry and the browser extension assets.
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

## Screen lock, sleep and inactivity

The desktop observes the session over D-Bus (zbus, the client that the desktop
already links) and applies the macOS rules: "Lock after inactivity" locks the
vault, and the "How often to ask" window ends, at screen lock, sleep, user switch
and session end.

"How often to ask" works as on macOS: after the passphrase or system authentication
(polkit), Apassy does not ask again for the owner's own manual actions until the time
is up; the actions that always ask on macOS ask again here too. The window opens only
while Apassy observes the screen lock (a logind session or a screen saver service).
Every approval of an agent run or a browser request still names that one pending
operation, and its proof works for it only. `apassy owner serve` never reuses a check.
Sources:

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
user, no symlink); a damaged or too open file means "Every time" and "Never" in the
desktop. The file is a plain file of your user: another process of the same user can
change it, for example to a longer window. That is outside the Linux boundary (ADR
0045: same-user processes are not protected), unlike the macOS keychain item.
`apassy owner serve` uses the same rule (`apassy::native::session_lock::SessionLock`,
and in the desktop package `apassy::native::linux::session_bus::SessionObserver`).

## Verification evidence

The Linux vault CI matrix builds x86_64 and aarch64 app/host binaries, exercises
Linux browser identity refusal cases and the shared synthetic WebAuthn
registration/assertion test with signature verification, independently verifies real vault create/get and persistence with the synthetic RP,
then builds and checks
the deb and tar packages and the installer. It uses no real accounts. The same job
runs the clipboard ownership against a real X server (Xvfb) and a headless wlroots
compositor (sway, wlr-data-control) with wl-clipboard as the other client, the
screen lock and sleep observer against private dbus-daemons with fake
systemd-logind and screen saver services, and `apassy owner serve` on a
pseudo-terminal in the build without the window. These are synthetic servers: they
do not prove GNOME, KDE or a real logind.

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
