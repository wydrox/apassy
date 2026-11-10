# L7: Mac wording on Linux (2026-11-10)

Unit L7 of the Linux work (ADR 0041, ADR 0045): a Linux user reads no text written for a
Mac, and sees no Mac-only feature or shortcut. The defect was R3 of
[the acceptance record](../../linux-acceptance-2026-11.md).

- [inventory.md](inventory.md): every changed text, with its macOS text (unchanged) and its
  Linux text.
- The guard: `src/desktop/ui/wording_tests.rs` renders every main view, the welcome,
  open-a-synced-vault and locked screens, a credential, the new-credential sheet, and
  each Settings section (hidden rows shown) of a Linux build with the fixture vault. It
  fails on "Touch ID", "Keychain", "Finder", "Dock", "iCloud", "Apassy.app",
  "System Settings", "macOS", "Notification Center", "⌘", "⌥", "⌃", and on the word
  "Mac", in painted text and in AccessKit names. Its sibling on macOS checks the Mac
  words, written literally.
- The words: macros in `src/wording.rs` (`computer!`, `shortcut!`, `app_package!`, …),
  usable in `concat!`; `wording::tests` pins each macOS and each Linux value.

## Decisions

### Class a: this computer and its owner check

"this Mac", "your Mac", "another Mac", "other Macs", "each Mac", "the Macs" become
"this computer", "your computer", … on Linux (`computer!`, `computers!`, and the `_cap`
forms at the start of a sentence). The device-kind label of a desktop in Devices
(`Kind::Mac`, also used for Linux desktops and nodes) is "Computer" on Linux.
"Touch ID" as the owner check is `touch_id!` / `owner_check!` (the passphrase or
system authentication). Another computer of the vault "answers after Touch ID on it"
becomes "after an owner check on it" (it may be a Mac or a Linux computer).
`apassy status` and `apassy doctor` show an "Owner check" row on Linux instead of
"Touch ID".

### Class b: features Linux does not have

| Mac text | Linux | Where |
| --- | --- | --- |
| "macOS can ask for permission to use iCloud Drive …" | not shown | open a synced vault |
| "Help with iCloud" and its text (Finder, iCloud Drive) | not shown | open a synced vault |
| "Check for a macOS permission request or a file download" | "Check for a stopped sync service or a file download" | sync time-out |
| "⌘H stays the macOS shortcut for "Hide Apassy" …" | not shown | Settings › Updates › Keyboard shortcuts |
| Notifications: "Not running · They start with the broker" | "Not available · Apassy on Linux shows no desktop notifications yet. Questions wait in Decisions." | Settings › Devices |
| "Updates are available only for the macOS app. On Linux, build the new version from the source." | "Apassy does not update itself on Linux: your package manager owns its files. To update, run the installer from apassy-relay.wyderka.cc/install.sh again, or download the new package from apassy-relay.wyderka.cc/dl/ and install it with apt." | Settings › Updates |
| "Delete it in Finder." | "Delete it in your file manager." | import |
| "Reinstall (the complete) Apassy.app (package)" | "Reinstall (the complete) Apassy (package)" | agent setup, Settings › Tools, `apassy doctor`, `apassy setup` |
| "open Apassy.app" | "open Apassy" | `apassy` errors, `apassy doctor` |
| "Use the apassy program inside (the running) Apassy.app" | "the apassy program of the Apassy package (/usr/bin/apassy)" / "of the same package version as the running window" | `apassy setup`, `apassy doctor` |
| "Start {host} in the Apassy sandbox on macOS with the command below." and the `apassy-sandbox -- …` command | "Start {host} with the command below. On Linux it runs as your user: the Apassy sandbox is macOS only." and `MCP_TOOL_TIMEOUT=660000 claude` / `codex` | Agents › connect, after setup (`apassy-sandbox` answers "the Seatbelt launcher runs only on macOS" on Linux and is not in the package) |
| `apassy setup` help: "Apassy.app includes the MCP server, prompt hook, and sandbox." and the sandbox start lines | "The Apassy package includes the MCP server and the prompt hook." and the plain start lines | `apassy setup --help` |
| "the window is in the Dock. Quit Apassy to stop them." | "the window is minimized. Press Ctrl+Q to quit Apassy and stop them." | closing the window while the node serves cloud agents |

Already hidden on Linux before L7 (checked): Touch ID unlock and its rows (no keychain
helper, `unlock.setting` stays `None`), "Show in Finder" (`cfg!(target_os = "macos")`),
"How often to ask for Touch ID" (Linux: "How often to ask"), the Touch ID owner-check
button (Linux: "Use system authentication").

Not reachable on Linux, left unchanged: the iCloud download states (`SyncError::NotDownloaded`
comes from the macOS cloud probe), "iCloud Drive" as a location label (a macOS path),
the macOS notification prompts and System Settings buttons (the notifier needs the
macOS helper), the macOS AutoFill and passkey-sheet requests, the Touch ID helper errors,
the updater (`SUPPORTED = cfg!(target_os = "macos")`).

### Class c: another device that really is a Mac or an iPhone

Kept: "iPhone", "Apple Watch", "Face ID", "an Allow there needs Face ID or Touch ID"
(the other devices), and device names such as "Mac mini (office)". The guard's
allow-list for "Mac" on Linux screens is empty: no rendered Linux screen needs one.

## Shortcuts of the Linux window

egui maps ⌘ (`Modifiers::COMMAND`) to Ctrl on Linux.

| Linux | macOS | Action | Note |
| --- | --- | --- | --- |
| Ctrl+1 … Ctrl+5 | ⌘1 … ⌘5 | All credentials, Overview, Decisions, Agents, Logs | |
| Ctrl+, | ⌘, | Settings | GNOME's Preferences key |
| Alt+Left (and Ctrl+[) | ⌘[ | Back to the list | Alt+Left is Back in GNOME and KDE |
| Ctrl+N | ⌘N | New credential | |
| Ctrl+F | ⌘F | Search credentials | |
| Ctrl+L | ⌘L | Lock the vault | as KeePassXC |
| F9 | ⌃⌘S | Hide or show the sidebar | was Ctrl+S on Linux, which means Save; F9 is the side-pane key of Nautilus, Dolphin, gedit |
| Return, Ctrl+S | Return, ⌘S | Default action of the open sheet (Save) | |
| Ctrl+Shift+H | ⌘⇧H | Show or hide the secret values | |
| Ctrl+Shift+M, Ctrl+Z, Ctrl+A | ⇧⌘M, ⌘Z, ⌘A | Move, undo a move, select all (folders, list) | |
| Ctrl+W | (menu) ⌘W | Close the window (minimizes while the node serves cloud agents) | new on Linux |
| Ctrl+Q | (menu) ⌘Q | Quit Apassy | new on Linux: Linux has no menu bar, so there was no way to quit while the node ran |
| Tab, Shift+Tab; arrows; Space; Page Up/Down, Home, End; Esc | same (⇧Tab) | focus, scroll, close | |

F10 (GNOME's menu key) is not bound: the Linux window has no menu.

## Screenshots

See the files in this folder (`*.png`), taken under Xvfb with openbox at 1600×1000 from a
debug build of this branch, with a synthetic vault.
