# Linux vault packages

These packages implement ADR 0045. They are CI artifacts until a separately
approved release publishes and verifies them. Existing node downloads do not
contain the vault desktop or browser host.

The `apassy-vault` package includes the egui desktop, interactive owner commands,
Chrome stable/Chromium native messaging host and extension, plus optional polkit
policy. It replaces the node-only `apassy` package; node commands stay available.
Install with `sudo apt install ./apassy-vault_<version>_<amd64|arm64>.deb`.
The package starts no process and does not enable any keyring integration.

The tar archive has a fixed `/usr` tree and an `install-vault.sh` installer.
Verify the checksum from the same CI artifact, extract to a private directory,
then run `sudo sh ./apassy-vault-<version>-linux-<arch>/install-vault.sh`.
A per-user installation cannot meet the browser executable ownership checks.
Use the deb when possible: tar installs do not register files with dpkg, and the
operator must install the dependencies recorded in `release-vault-linux-*.json`.
The desktop glibc requirement is recorded per artifact; the node's glibc 2.31
compatibility promise does not extend to these desktop builds.

Run `apassy` from your desktop session. A Wayland session is preferred; X11 can
expose keyboard input to other clients. Secret and TOTP Copy works where Apassy can
own and clear its own clipboard copy: Wayland with ext-data-control-v1 or
wlr-data-control, X11, or XWayland (GNOME). Apassy marks the copy with
`x-kde-passwordManagerHint` and replaces only its own copy with an empty one after
the clear time, on lock and on quit. Elsewhere Copy is disabled with the reason;
use Show or browser fill. A clipboard manager that ignores the hint can keep a copy. Configure the browser from that user
account, using Apassy's extension installation flow. Browser manifests point to
`/usr/lib/apassy/apassy-browser-host`; extension assets live in
`/usr/share/apassy/browser-extension`. Native manifest templates for both browsers
are in `/usr/share/apassy/native-messaging-hosts/`. Chrome stable and Chromium use their own
`NativeMessagingHosts/com.wydrox.apassy.json` under `~/.config`.

Passphrase unlock remains the default. Headless owner commands require a real
interactive terminal, and do not require a session bus, desktop, screen lock,
biometric device or keyring. See `docs/operations/linux-vault.md` in the source
for commands and the verification boundary. Optional Secret Service needs
`secret-tool` (`libsecret-tools`) and explicit opt-in. Other clients running as
the same user can retrieve an item from an unlocked keyring. Optional presence
uses `pkcheck` and the packaged `com.wydrox.apassy.owner-presence` policy with
`auth_self`, without cached authorization. Missing, refused or cancelled
presence must not count as approval; passphrase confirmation stays available.

The desktop locks the vault and ends the "How often to ask" window at screen lock,
sleep, user switch and session end, from systemd-logind and screen saver D-Bus
signals, and after the inactivity time (input in Apassy; the desktop's idle hint
when it keeps one). Settings > Security lists the signals that this session lacks.
Without a logind session and without a screen saver service, approval reuse stays
off and you lock the vault manually. Both settings are stored per device in
`~/.local/share/apassy/device-policy.json`.

Without a desktop, `apassy owner serve /path/to/vault.db` hosts the browser and
agent services after a terminal unlock; every request waits for a typed `approve` and
the passphrase in that terminal. Run it in tmux or screen, never from a systemd unit:
it refuses non-interactive input, and the package ships no unit for it.

The vault is a software vault. Root and compromised processes of the same user
are outside its protection. Linux kernel peer credentials and verified process
ancestry improve browser authentication, but do not provide macOS code signing,
Secure Enclave or Touch ID. Use a separate account for untrusted coding agents.

Package inspection and synthetic passkey signature tests do not establish a real
browser or desktop acceptance result. Never use real accounts for qualification.
