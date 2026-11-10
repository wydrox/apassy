# ADR 0041 — The Apassy window on Linux

Date: 2026-11-03.
Status: PROPOSED; built under the owner's instruction of 2026-11-03 unless the owner changes it.
ADR 0037 stage 8 names this work: "Linux window". ADR 0037 §2 says: "A Linux window comes later,
from the same egui UI." The isolation of agents on Linux is a separate plan,
[implementation-plan-s5-env-0011.md](../design/implementation-plan-s5-env-0011.md) (ADR 0011). This
ADR does not decide it. No release or publication is authorized by this ADR.
Plan: [implementation plan, stage 8](../design/implementation-plan-s8.md), track L.

## Context

- Stage 3 makes Linux a headless node: `apassy serve` as a systemd user service, `up`, `pair`,
  `status`, `doctor`, and `.tar.gz` and `.deb` packages (plan 0037, units 3A to 3F). Linux has no
  window.
- The Mac window is eframe (egui): about 96,000 lines in `src/desktop`. It already compiles on
  Linux. CI runs clippy with all features on ubuntu-24.04, and
  `cargo check --features desktop --bin apassy`. In the lock file, winit has its X11 and Wayland back
  ends, and accesskit has its AT-SPI back end (`accesskit_unix`, with zbus 5).
- The macOS-only parts are few. They sit behind `cfg(target_os = "macos")` or in the Swift helpers:

| Part | macOS | Where | Linux today |
| --- | --- | --- | --- |
| Owner check | Touch ID in the Swift helper (LocalAuthentication), in the Apassy panel of ADR 0038 | `src/native/mod.rs`, `src/desktop/owner_check.rs` | No helper: the passphrase only |
| Unlock without the passphrase | The passphrase in the data-protection Keychain behind Touch ID (`.biometryCurrentSet`) | `src/desktop/unlock.rs`, `native/ApassyKeychain` | None |
| Node master key | A Keychain item behind Touch ID, else a 0600 file | `src/node/master_key.rs` (`KeyStore`) | The 0600 file |
| Notifications | `ApassyNotify.app`, fixed templates | `src/desktop/notify.rs` | None |
| Menu | muda, the menu bar | `src/desktop/native_menu.rs` | None |
| Updates | The signed `latest.json` updater | `src/desktop/update` (`SUPPORTED = cfg!(target_os = "macos")`) | Off |
| Browser caller check | The signed Swift guard, code signatures | `src/browser/caller.rs` | Refused (fail closed) |
| Clock for idle time and the owner-check window | Darwin's `CLOCK_MONOTONIC`, which counts sleep | `src/desktop/auto_lock.rs:110`, `src/broker/approvals/owner_window.rs:66` | `Instant`: Linux `CLOCK_MONOTONIC`, which stops during suspend |
| Run sandbox | Seatbelt | `src/broker/proxy/mod.rs:523` | None (the s5 plan) |

- The owner's agents run as the owner's user. On macOS, the Keychain ACL and code signatures keep
  them away from the unlock key and the owner proof. Linux has no such boundary between programs of
  one user. Most of what follows comes from this fact.

## Options for the window

| | A. The same egui/eframe code | B. GTK 4 (gtk-rs, libadwaita) | C. A web UI on loopback |
| --- | --- | --- | --- |
| Code | The Mac UI, and a small Linux platform layer | A second UI for every view | A second UI in HTML and JavaScript, and an HTTP API for every owner action |
| Drift from the Mac | None: one UI | Every feature twice | Every feature twice |
| Look | Apassy's own, as on the Mac | GNOME | A browser tab |
| Owner channel | A window of the Apassy process | The same | A loopback port that every local program, agents included, can reach. Each request needs its own login and defenses against CSRF and DNS rebinding. Agents drive browsers (CDP), so the owner's page is in their reach |
| Headless servers | No (the node stays headless, stage 3) | No | Through an SSH tunnel |

## Decision

### 1. The window is the same egui code (option A)

- One UI for macOS and Linux: eframe with the glow renderer, on Wayland and X11. A Linux target
  dependency names the `wayland` and `x11` features of eframe, so the build does not depend on what
  another crate turns on.
- A platform layer, `src/desktop/platform/`, has one trait for each service: the owner check, the
  unlock key store, notifications, idle time and screen lock, and updates. macOS implements it with
  the Swift helpers, as today. Linux implements it as below. After this, no view calls
  `NativeHelper` directly.
- On Linux the menu is in the window. The Mac keeps its muda menu bar.
- Settings hides the rows that do not exist on Linux: Touch ID unlock, iCloud, automatic updates,
  and the browser extension. The Linux rows say what Linux uses.

### 2. One node per user: the window is the node

- As on the Mac, the window process runs the node in its backend (ADR 0037 §2). There is no new
  owner API between a window and a service.
- A lock file in the data directory allows one node per user. When the window starts and the
  `apassy` user service (stage 3) holds the node, the window stops the service through systemd
  (`StopUnit` on the user manager, over D-Bus), waits for the lock, and runs the node. When the
  window quits, it starts the service again if the service is enabled.
- The window and the service open the same node files with the same key source (stage 3). The
  handover copies nothing.
- Quitting the window locks the vaults. The service then serves its locked roles again (sync home,
  pairing peer). A team host needs `apassy unlock` again (plan 0037, 3C). The handover stops the
  node for a few seconds.
- No tray icon: GNOME has no tray without an extension. Closing the window quits it, and the service
  takes over.
- A second start says "Apassy is already open" and exits.

### 3. The owner check

| Check | What it is | What can fake it | Use |
| --- | --- | --- | --- |
| polkit, `auth_self` | Apassy asks polkitd (system bus) about the action `com.wydrox.apassy.owner-presence` for its own process. The desktop's polkit agent asks for the login password, or for a finger when the system has fingerprint login (PAM with pam_fprintd) | A program of the user cannot answer polkitd without the password or the finger. On X11 it can read the typed password | Offered in each check ("Use system authentication"), when the owner chooses it. Amended 2026-11-10: not the default (ADR 0045) |
| fprintd directly | Apassy claims the reader and asks `net.reactivated.Fprint` for a match | It gives only a match signal inside Apassy. Another program can hold the reader. There is no system dialog | Not used: polkit already uses fprintd through PAM |
| The vault passphrase | Typed in Apassy's window | Knowledge of the vault passphrase | The default, always available. The only check without polkit (tarball without the action, no polkit agent) |

- The polkit action has `allow_active` = `auth_self`, `allow_inactive` = `no`, and `allow_any` = `no`.
  It has no `auth_self_keep`, so polkit keeps no answer of its own. ADR 0030's global "How often to
  ask" applies on top, as on the Mac.
- The owner proofs of the broker stay bound to the exact action and session (ADR 0030). The method
  is a new `CheckMethod::System`, shown as "your Linux login".
- The polkit dialog shows the fixed message of the action. Apassy's window shows the purpose next
  to it, from fixed Rust templates (as in ADR 0038). No agent or website text goes to polkit.
- Cancel in Apassy cancels the polkit request (`CancelCheckAuthorization`).
- Amended 2026-11-10 (ADR 0045, Linux acceptance): there is no "Check with" setting. Every
  owner check in the window shows the passphrase field, which is the default, and the link "Use
  system authentication", which starts the polkit check for that one request; the owner chooses
  in each check. A polkit check that fails, is cancelled or is not installed approves nothing,
  and the passphrase stays available. `apassy owner serve` offers the same choice as `approve`
  (passphrase) or `approve polkit`.
- On Linux the owner-check window and the idle time use `CLOCK_BOOTTIME`, so a suspend counts as
  time, as on the Mac.

### 4. Unlock and secret storage

- **The vault opens with its passphrase on Linux.** There is no equivalent of "Unlock with Touch
  ID" in this ADR.
- **Secret Service does not keep the passphrase.** This covers gnome-keyring, KWallet, and every
  libsecret client. An unlocked login keyring gives its items to every program of the user that
  asks over D-Bus, and the owner's agents are such programs. The Mac Keychain item needs Touch ID
  and Apassy's signature. Secret Service has neither.
- **Later, with a condition:** "Remember the passphrase in the login keyring" becomes possible when
  the isolation of the s5 plan keeps agents off the session bus, or filters `org.freedesktop.secrets`.
  A program outside the sandbox can still read it, and the setting says so. It is off by default. It
  uses the Secret Service D-Bus API through zbus, not the libsecret C library.
- **The node master key** is kept as stage 3 decides (systemd credentials or a 0600 file). The
  window uses the same `KeyStore`, so the service and the window open the same node.
- **A TPM** seals to the machine, not to the owner's presence: any program of the user can ask
  systemd to open a user credential. A TPM protects a stolen disk, not against agents. Stage 3 may
  use it for the node key. It is not used for the vault passphrase.

### 5. Process hardening

- The window process sets `PR_SET_DUMPABLE` to 0 and the core size limit to 0. Then a program of the
  same user cannot attach a debugger or read `/proc/<pid>/mem`, whatever the Yama setting.
- On X11 any program of the session can read keystrokes and draw over windows. Settings › Security
  shows "On X11, other programs can read what you type. Use a Wayland session." `apassy doctor`
  reports the session type.

### 6. Notifications, clipboard, idle time, and screen lock

- Notifications use the freedesktop Notifications API (D-Bus), with the fixed templates of the Mac
  notifier (goal item N2). A click raises the window on Requests.
- The clipboard is arboard on Wayland and X11. A copy has the password-manager hint
  (`x-kde-passwordManagerHint`), so clipboard managers skip it, and it is cleared after the time
  in Settings. A clipboard manager that ignores the hint keeps a copy; Settings says so.
- Screen lock: logind's `Lock` signal and `LockedHint` lock the vault, as the Mac's screen lock does.
  Idle time: logind's `IdleHint` where the desktop sets it; else the window's own input time.

### 7. Packaging

| Format | Decision | Why |
| --- | --- | --- |
| `.deb` | Yes. Two packages, for x86_64 and aarch64: `apassy` (CLI and node, stage 3) and `apassy-desktop` (the window `/usr/bin/apassy-desktop`, the desktop entry `com.wydrox.Apassy.desktop`, the icons, the AppStream metadata, and the polkit action) | A server installs only `apassy` and gets no GUI libraries. The polkit action needs a root install |
| `.tar.gz` | Yes, with the window too. Without the polkit action, the owner check is the passphrase; `apassy doctor` shows how to install the action | Other distributions |
| Flatpak | No | Its sandbox blocks what Apassy does. The node and the broker serve programs outside it (agents, the browser host, the systemd service). A Flatpak cannot install a polkit action. The isolation of s5 cannot run nested inside it, and `flatpak-spawn --host` would undo the sandbox |
| Snap, AppImage, RPM | Not now | RPM when users ask. Snap and AppImage have the Flatpak problems or no polkit action |

- `apassy-desktop` depends on `apassy` of the same version. Both are the Linux component of one
  release. The Linux window is not a seventh component (AGENTS.md).
- Updates: the window reads the release feed and shows "Apassy <version> is available" with the
  download link. It never replaces its own files, because a package manager owns them. A signed apt
  repository is a later step.
- Each package has a SHA-256 checksum and a GitHub build attestation, as in stage 3. GitHub's Linux
  runners build both architectures, on the oldest glibc that stage 3 supports.

### 8. What the Linux window does not change

- Local agents on Linux: the s5 plan decides how they run. This ADR adds no agent path.
- The browser extension on Linux: without a caller check the host refuses guarded commands, as it
  does today. A Linux caller check comes after s5.

## What this does not protect

- **Programs of the owner's user.** Without the isolation of s5, an agent of the same user can change
  what starts next: a user override of the systemd unit, a desktop entry in
  `~/.local/share/applications`, a `PATH` entry, or the session environment. Then the next "Apassy"
  is not Apassy. The packaged binary in `/usr/bin` belongs to root, but the start path belongs to the
  user. This is why s5 exists.
- **X11.** Keystrokes and the screen of the session are open to every program in it.
- **The polkit dialog** accepts the login password. A person who knows it can approve.
- **Memory.** As on the Mac: best-effort erase.

## Consequences

- Linux gets the full owner UI: vaults, devices, pairing, Decisions, Activity, and teams on the
  node.
- The Mac code gets a platform layer. The Mac's behavior does not change.
- A new direct dependency on Linux: zbus (already in the lock through accesskit). No GTK and no
  libsecret.
- The release check and AGENTS.md name the two Linux packages. CI builds the window on Linux.
- Support grows by Linux desktops. The acceptance covers GNOME and KDE Plasma on Wayland, and one X11
  session.
- Known limit of the Linux sandbox of s5 (judge finding L5, 2026-11-03): the sandbox has no seccomp
  filter, so a run can open an `AF_VSOCK` socket. A network namespace does not cover vsock: on a
  virtual machine with a vsock device, a run can reach the hypervisor host past its network rule. The
  run still holds only placeholders. Follow-up: a seccomp filter for `socket(AF_VSOCK)` in the sandbox
  of a run (s5 plan, X1).

## Open decisions

The recommendation of each row is what the plan builds unless the owner changes it.

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | Toolkit | The same egui/eframe code (option A). |
| D2 | Process model | The window is the node, with a handover to and from the user service. |
| D3 | Owner check | The passphrase by default; polkit `auth_self` on request in each check (amended 2026-11-10, ADR 0045). No direct fprintd. |
| D4 | Keep the passphrase | Not now. The login keyring only after s5 keeps agents off the session bus. |
| D5 | Packages | `.deb` (two packages) and `.tar.gz`. No Flatpak. |
| D6 | Tray | None now. |
| D7 | Updates | A notice with the download link. An apt repository later. |
