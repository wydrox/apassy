# Changelog

All notable changes to Apassy. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/). The site shows this file at <https://apassy.wyderka.cc/changelog>.

## [Unreleased]

### Changed

- The browser extension is in the Chrome Web Store: <https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih>. "Connect" in Settings > General > Browser extension opens its page in the browser, so the install is "Add to Chrome" in place of Developer mode. `apassy setup browser` and the site point there too. Settings no longer shows the extension folder: the folder in Apassy.app still works with Developer mode, and `apassy setup browser` prints its path.

## [0.3.5] - 2026-10-09

### Added

- A browser extension for Helium, Chrome, Chromium, Brave, Edge, Arc, and Vivaldi. It fills the username and the password of a login on its website. Each fill asks for Touch ID or the passphrase in Apassy. Agents never get the password ([ADR 0021](docs/adr/0021-browser-extension.md), [browser](docs/operations/browser.md)).
- "Save this login" in the extension saves the login that you typed on a page, after Touch ID or the passphrase.
- "New password" in the extension makes a login with a new password from Apassy and fills it into a sign-up form. The password is in the vault before the page gets it, and never on the pasteboard.
- Settings > General > Browser extension connects a browser with one click: it writes the host manifest, opens the extensions page, and shows the extension folder. `apassy setup browser` does the same from a terminal.
- Logins have a Website field. The 1Password import puts the first address of a login there.
- The item history shows each fill in the browser, with the site.

### Security

- The agent profile denies a write to every `NativeMessagingHosts` folder. A browser starts the program of such a manifest outside the sandbox, so a planted manifest could replace the host of an installed extension.
- The agent profile denies a change of `Preferences`, `Secure Preferences`, and `Local State` of the Chromium browsers, and a new or renamed profile folder, so an agent cannot point an installed extension at its own code.

### Changed

- CI runs test groups and release builds in parallel. Release uses the verified binaries from the same successful CI run.

## [0.3.4] - 2026-10-07

Vault sync through the Apassy relay, a background sync worker, bouncer start modes in Settings, and fixes in the window and the owner command line.

### Added

- Settings > Agents > Broker and bouncer can start the local model: with Apassy, when a run needs it (it stops after 10, 30, or 60 idle minutes), managed outside Apassy (the default), or off. It shows the state, the model version, and what is missing, with "Start now", "Stop", and "Open log". The setting is `bouncer.json` in the data folder.
- Settings > Agents > Broker and bouncer has "Install the model" while the Laya environment is missing. It runs the `uv` commands of the bouncer guide on a background thread, shows the step, can stop, and writes `~/Library/Logs/Apassy/bouncer-install.log`. Without `uv` it says "Install uv first: brew install uv".
- "Install the model" also downloads the pinned Laya base weights ("Downloading the model weights", `tools/basemodel/fetch_weights.py`); without them a first start says "Starting (downloading the model weights, first start only)" and a run waits up to 45 seconds, then waits for you with the reason. A failed weights download keeps the installed environment, starts the server in "With Apassy", and offers the download again; the Python steps write no `__pycache__` into the app bundle. "Start now" is hidden while a start would fail, and `apassy decisions export` lines have an optional `model_version`.
- Settings shows a note with the remove commands for a LaunchAgent that runs `tools/basemodel/start.sh` with a missing `APASSY_BASE_MODEL`, or while Apassy starts the model itself. Apassy does not change the LaunchAgent.
- `scripts/build-app.sh` without `APASSY_BASE_MODEL` ships the checkpoint in `$APASSY_LAYA_DIR/models` when it exists and matches the manifest, and prints which model it ships. A checkpoint that does not match gives a warning and an app without a model, so `scripts/install.sh` does not fail. GitHub Actions does not use this checkpoint.
- Vault sync through the Apassy relay, stage 1. In Settings > General > Sync, the menu of a vault has "Apassy relay" after the detected folders. Its sheet takes the relay address, the team code from the operator, and the name of this Mac, or a link from another Mac for a vault that is on the relay already. A vault on the relay has "Add a Mac…" (a link that works once for 10 minutes, the same two safety words on both Macs, and Confirm behind Touch ID or the passphrase), "Devices…" (list and remove), and "Sync now", and statuses such as "Saved to the relay." and "Relay not reachable. Apassy syncs when it is back." "Use a vault from another Mac" has the source "Apassy relay": paste the link, compare the words, then type the passphrase. Turning relay sync off keeps the copy on the relay; the last Mac can also delete it. Every relay call that you start runs in the background, so the window stays responsive and shows what runs. "Cancel" or a quit on a Mac that joins cancels its link on the relay. Picking a folder for a relay vault asks first, and this Mac leaves the relay team; the message says what stays on the relay. A damaged relay copy has "Replace with this Mac's vault…", behind a sheet. Settings shows "Received by <Mac>" from the receipts that the other Macs send. A relay copy that this Mac refuses (an older copy after the relay came back from a backup, or a history without this Mac's last change) has "Use the relay copy…", which merges it and keeps the device, also for the last Mac of a team; a copy under another passphrase then asks for that passphrase only to open the copy: the vault keeps the passphrase of this Mac, and the merged vault goes up under it. A failed pull is tried again 5 seconds later, then 10, 20, 40, and 60. A lock, "Turn off", and a quit end every relay call at once, also while it connects. The window does not wait for a relay call, except at a lock with a change that waits: the push before the lock waits at most 10 seconds. "Turn off" needs the vault unlocked, since the key of this Mac for the relay is in the vault. A folder sync stays on until relay sync is on. See `docs/operations/sync.md`, section 17, [ADR 0022](docs/adr/0022-relay-sync.md) (accepted for stage 1), and the wire contract `docs/contracts/relay-sync-v1.md`.
- `apassy completions zsh|bash|fish` prints a shell completion script for the commands, subcommands, and main options. It is made from the tables of `apassy help`. Where no subcommand fits, as for the file of `apassy import`, the shell completes file names.
- `apassy import FILE --bind` binds the variables of the added credentials with one owner check: the key of a `.env` line, or a 1Password or Bitwarden title that is a variable name already. The window lists each credential and its variable with the count, and Touch ID names the count. Invalid names, names that another credential uses, and credentials without a secret value are refused, and a line under the table says why for each credential. With `--json`, the answer is one document, also when a variable is not bound. A cancel binds nothing. Without `--bind`, nothing changes.

### Changed

- Vault schema 16 adds the local table `relay_device` (the key of this Mac for the relay). It is never part of a sync copy. A vault that 0.3.3 opened no longer opens in 0.3.2. See Upgrade notes.
- Folder sync runs on a background thread. It merges and pushes also while the window is hidden, minimized, or covered.
- Settings has five tabs: General, Security, Agents, Notifications, and About.
- The sidebar shows the open vault with its sync state and a lock button, the shortcuts on hover, and expired agent tokens. ⌃⌘S hides it.
- Credentials of a new vault show "Get started", the steps to the first agent request.
- The page column keeps its reading width in a wide window, and lists show relative times.
- The app remembers a hidden sidebar and "Hide" of the Get started list (per vault) across restarts, in `ui.json` in the data folder.
- Relay sync: "Remove" in "Devices…" asks first ("Remove <Mac> from the relay?"), and Cancel is the default for the keyboard.
- Relay sync: after Confirm, "Add a Mac…" shows only the result and "Done", not the used link.
- Relay sync: the team code field is masked, and its text goes after each try.
- Relay sync: "Join from another Mac" for a vault whose relay copy has another passphrase asks for the passphrase of the copy, and the vault takes it, as on your other Macs; the step stays on the screen while the merge runs.

### Fixed

- Return on the Create screen moves to the next field instead of to "Back".
- A path typed in "Use a vault from another Mac" is picked when it is complete, not after the first character.
- The first text field of a new sheet takes the focus after a click.
- Relay sync: a Mac that another Mac removed shows "Removed from the relay" at once and signs in to the relay only once every 15 minutes, so it syncs again by itself after the relay was suspended; to sync again after a removal, turn relay sync off, then join again with a link from another Mac.
- Relay sync: "Turn off" on a Mac that the relay refused asks the relay to remove its device instead of trusting the earlier refusal.
- Relay sync: a failed sign-in token no longer shows "Removed from the relay".
- Relay sync: "Devices…" shows a current "last seen" for each Mac that syncs (the relay writes it at most once a minute per device).
- Return or Space in a destructive alert that was opened with the pointer pressed its destructive button: Delete, Revoke, Reset pairing, Discard, and Remove or Turn off for the relay. They press Cancel (Keep editing in Discard changes) now, as in an alert opened with the keyboard.
- A quick click on "Confirm…" (press and release in one frame, as a tap on a trackpad) could open the owner check behind "Add a Mac…": the window dimmed, the typed passphrase went nowhere, and Return closed the check with "Type the passphrase.". A sheet that opens over another sheet is now on top.
- "Confirm" with an empty passphrase field in an owner check closed the check, and the action that waited for it was lost. The check now stays open and says "Type the passphrase.", as after a wrong passphrase.
- Relay sync: a Mac that another Mac removed still showed "Sync now", "Add a Mac…", and "Devices…", and their sheets offered "Check again", "New link", and "Refresh", which all failed at once. Settings now shows only the sync menu for that vault, with the line that says to turn relay sync off, and the sheets show why without those buttons.
- In "Use a vault from another Mac", a click on a file did not give the focus to the passphrase field, and a click on "Apassy relay" did not give it to the link field, so the owner had to click the field first. egui gave the focus up at that click; the field now takes it in the next frame.
- The demo build without the vault feature (`cargo check --features desktop --bin apassy`) compiles again, and CI checks it.

### Security

- A run that names a host session no longer takes the hook prompt of another session without a flag. Such a prompt now has `hook_ambiguous`, so the owner decides.
- Relay edge: the Worker refuses a request body with a malformed or too large declared length before the relay reads it (400 `invalid_request`, 413 `payload_too_large`; snapshot pushes up to 64 MiB, the agent proxy up to 8 MiB, every other route up to 128 KiB), and limits snapshot pushes to 60 a minute per IP address. This needs a Worker deploy (see `docs/operations/release.md`, "Relay first").

### Upgrade notes

- **Vault schema 16.** The first unlock in 0.3.3 migrates the vault, and 0.3.2 refuses it afterwards (`verify_user_version` in `src/vault/mod.rs`). Back up the vault before the first unlock if you may go back. Macs that sync one vault through a folder or through the relay must all update: a merge needs the same schema on both sides (`src/vault/merge.rs`, the check of an attached copy), so a Mac on 0.3.2 refuses a copy that a 0.3.3 Mac wrote, and the reverse.
- **Relay sync needs a relay with SPEC section 24 deployed** (schema 4 team files, the sync endpoints, and the Worker of the same release). The first start of that relay migrates each team file and keeps `teams/<id>.db.pre-v4`; an older relay image cannot open them. Deploy the relay before you publish the app: `docs/operations/release.md`, "Relay first".

## [0.3.2] - 2026-10-05

Clearer setup on a second Mac, sync recovery, and complete command-line tools in the app bundle.

### Added

- A guided flow to find and open an existing vault from iCloud Drive or another sync folder.
- Setup choices for Claude Code, Codex, and the CLI after a synced vault opens. Agents and grants stay local to each Mac.
- A persistent conflict review with links between retained copies and the current credential.
- Native file panels for vault, import, backup, and sync paths.
- The iPhone companion source, with QR pairing, device removal, and owner approval for runs. Its listener is off by default. Device trust stays local to each Mac.
- Source files for the promotional videos.
- Design records for the local bouncer, shared-vault relay, and relay accounts.

### Fixed

- A wrong vault passphrase preserves the selected file and returns focus to the passphrase field.
- Anonymous cloud snapshots use private file permissions on macOS and Linux.
- Cloud folder checks have bounded waits. Retry detects newly available folders and preserves the selected file.
- Sync status distinguishes a local folder write from receipt on another Mac.
- CLI setup distinguishes configuration from a verified connection. The tool installer checks executable files.
- The app bundle includes `apassy-hook`, `apassy-sandbox`, and the agent profile. Build checks verify those files.
- Keyboard actions, edit cancellation, CLI help, and error output are clearer.

### Changed

- Vault schema 15 adds local companion settings, certificates, and paired devices. Migration keeps schemas 13 and 14. A restore or adoption clears device trust.
- Updated site build dependencies. The dependency audit reports no known vulnerabilities.

### Release status

- This release publishes source code. A signed and notarized download still requires the Apple and Cloudflare release credentials.

## [0.3.1] - 2026-10-01

The owner command line, keyboard use, and the install from source.

### Added

- **Install from source with one command.** `/bin/bash -c "$(curl -fsSL https://apassy.wyderka.cc/install.sh)"` checks the Mac, clones the newest release, builds, signs, and checks it with `scripts/build-app.sh`, and installs it in Applications. It asks before it replaces an app and never uses sudo; `--check` only checks the Mac. On the site, "Coming soon for macOS" opens a note with the command until the signed download is published ([`scripts/install.sh`](scripts/install.sh)).
- **Owner command line.** `apassy` with a command talks to the running window over a new owner socket: credentials (list, show, add, edit, archive, delete, history, agent settings), import of `.env` files and of 1Password and Bitwarden CSV exports, agents (register, rotate, revoke, see all, token lifetime), grants and rules, access requests, runs that wait, remembered patterns, activity, the decision export, backup, and the passphrase change. `apassy login` opens a session after Touch ID or the passphrase in the window; it ends after 30 idle minutes, at a lock, and when another vault opens. Every grant, approval, token, and agent setting still asks for its own owner check in the window, which says that the command line asked. The command line never shows a secret value, never takes one as an argument, and never unlocks or restores ([command line](docs/operations/cli.md), [ADR 0017](docs/adr/0017-owner-command-line.md), [wire](docs/contracts/owner-cli-v1.md)).
- **`apassy setup claude|codex`.** Registers an agent and writes the MCP server and the prompt hook. The token is in two wrapper scripts with mode 0700, not in a host file.
- **`apassy doctor`.** Checks the window, the vault, the broker, the session, the programs, the data directory, and the agent hosts, with a fix for each problem.
- **Settings > Command line.** The owner socket and the open sessions, with "End all sessions".
- **Keyboard use.** The focus follows the owner: a sheet takes the focus when it opens and gives it back when it closes; a destructive alert starts on Cancel; the page scrolls to the focused control; after a navigation or a control that goes away, the first control of the page takes the focus. Return does the default action of a sheet. New shortcuts: ⌘1 to ⌘4 and ⌘, for the views, ⌘[ for back, ⌘L to lock, Page Up, Page Down, Home, and End to scroll, and Esc to close an error message. A menu choice with the keyboard closes the menu. The arrows of a segmented picker no longer move the focus. The focus ring is 2 points of solid accent on every control. VoiceOver gets a name for every icon-only button, row, tag, picker, and custom detail field.

### Fixed

- A copy without a Developer ID signature, such as a build from source, no longer downloads new versions every 6 hours only to refuse them. It shows the version and the download page, and the installer updates it ([updates](docs/operations/updates.md)).

### Security

- **The agent profile denies the Unix sockets of the data directory.** The file rule did not stop a `connect()` to a socket there. Now only the broker socket is open to agents, and the owner socket is closed. `apassy-sandbox` removes `APASSY_SESSION` from the agent environment.

## [0.3.0] - 2026-09-28

Several vaults, sync between your Macs, import from 1Password, and automatic updates.

### Added

- **Several vaults.** Each vault is its own encrypted file with its own passphrase, credentials, agents, rules, and learning data. One vault is open at a time, and agents reach only the open vault. The name of the open vault at the top of the sidebar switches to another vault. A switch locks the open vault and ends each run that waits for you. Settings > Vaults renames a vault or removes it from the list; the file stays ([several vaults](docs/operations/multiple-vaults.md), [ADR 0013](docs/adr/0013-multiple-vaults.md)).
- **Sync through a folder.** As with an Obsidian vault, a vault can sync through iCloud Drive or through any folder that Dropbox, Google Drive, OneDrive, or Syncthing keeps in step. Settings > Vaults > Sync, or the Create screen, turns it on; it is off by default. Your other Macs add the vault with "Open a synced vault…".
  - Changes merge one credential at a time, after each unlock, every 30 seconds, a few seconds after a change, and before each lock and quit. You type no passphrase for it.
  - When the same credential changed on two Macs, the newer version wins, and the other stays as an archived conflict copy. An old copy changes nothing.
  - The credentials and their settings sync. Agents, tokens, grants, rules, activity, and learning data stay on each Mac and are never in the synced file: each Mac registers its own agents.
  - The vault that Apassy works on stays a local file, and SQLite never writes in the synced folder. The synced file is encrypted with the vault passphrase ([sync](docs/operations/sync.md), [ADR 0014](docs/adr/0014-icloud-sync.md)).
- **Import from 1Password.** Settings > Import reads a 1PUX or CSV export and shows each item before anything is added. API credentials, SSH keys, databases, and servers are selected first; logins, passwords, and notes are not. A secret never goes into a title, notes, or tags. No agent gets access to an imported credential. After the import, Apassy offers to delete the export file ([import from 1Password](docs/operations/import-1password.md)).
- **Rule pack validator.** `apassy-packs validate` loads a rule pack or a provider file as the broker does, and names the reason when it does not load. JSON Schemas in `packs/schema/` describe both formats, and CI checks each file with both ([rule packs](docs/operations/rule-packs.md), [CONTRIBUTING.md](CONTRIBUTING.md)).
- **Licenses and policies.** The code and the documents are Apache-2.0. The rule packs, the provider files, and their schemas are CC0-1.0. [SECURITY.md](SECURITY.md) says how to report a vulnerability.
- **Automatic updates.** The app checks for a new version shortly after the start and every 6 hours, downloads it, and installs it at "Restart now" or at the next quit. Only a higher version number updates the app: another build of the same version does not. It installs only an app with the size and SHA-256 of `latest.json`, signed with a Developer ID of the same team, and notarized by Apple. Settings > Updates turns the check and the automatic install off ([updates](docs/operations/updates.md), [ADR 0015](docs/adr/0015-automatic-updates.md)).

### Changed

- The vault schema is version 14: a vault ID, and an ID, a change count, and deletion marks for each synced record. A vault of an earlier version migrates at unlock.
- `apassy-sandbox` denies agents each vault in the vault list, the iCloud Drive folder of Apassy, the synced file of each vault in another folder, and the list itself. It refuses to start when the vault list is damaged, because a damaged list can hide a vault outside the data folder.
- An agent with a token of another vault gets a message that says the owner may have another vault open. The message names no vault.
- The result of a run, a connector call, and a local training goes only to the vault where it started, also when you switch vaults during it.
- An edit of a credential keeps its tags.
- Release builds record their commit and build time in the program and in `Info.plist`.

### Security

- The updater checks the new app again just before it replaces the installed app, and puts the old app back when the replacement fails.
- A synced copy is read only as a local copy, and it must pass the checks of a restore and a content digest before it merges. So a copy made of pages from different versions is refused.

## [0.2.1] - 2026-09-28

Apassy builds and passes its tests on Linux. The app for Linux is not published yet: the isolation of agents uses macOS Seatbelt, and Linux needs its own version first.

### Added

- **Linux build.** Apassy, the broker, the run proxy, and the desktop app build on Linux, and the tests pass there. On Linux, the files of Apassy are in `$XDG_DATA_HOME/apassy`, or `~/.local/share/apassy`. On macOS, they stay in `~/Library/Application Support/Apassy`.
- **Linux in CI.** CI runs Clippy, the tests, and the doc tests on Linux too.

### Changed

- On Linux, `apassy-sandbox` says that it runs only on macOS. The Seatbelt tests and the tests of the Swift helpers run only on macOS.
- The run proxy test uses Node only when it reads `HTTPS_PROXY`. Node before 22.21 ignores it and connects directly.
- CI runs once for each update of a pull request and once for each push to `main`, not for each push to another branch or a tag. A newer push to a pull request cancels its older run. A change only in `site/` or `design/` runs no CI.

## [0.2.0] - 2026-09-28

The first public release: a signed app for macOS, a website, and everything since the alpha.

### Added

- **Download.** A signed and notarized `Apassy.dmg` at [apassy.wyderka.cc](https://apassy.wyderka.cc). Each push to `main` that passes CI publishes a new build ([release](docs/operations/release.md)).
- **App icon.** The Apassy mark in the Dock, on notifications, and on the Touch ID prompt.
- **New desktop interface.** A sidebar with Credentials, Agents, Activity, Learning, and Settings. Each credential has a history and can be archived ([ADR 0011](docs/adr/0011-run-proxy-placeholders.md)).
- **Placeholders.** A variable can hold a placeholder instead of the value. The run then goes through a proxy of Apassy, which puts the real value into HTTPS requests to the hosts of that credential only. On macOS, the process can connect only to that proxy ([ADR 0011](docs/adr/0011-run-proxy-placeholders.md)).
- **Access requests.** An agent can see the names of all credentials, without values, and ask you for access. One grant can cover several credentials, in one folder or in any folder ([ADR 0012](docs/adr/0012-agent-visibility-and-access-requests.md)).
- **Base model.** The bouncer uses `apassy-base-v1`, a local Laya model with decision heads trained on synthetic commands. It starts at login ([base model](docs/operations/base-model.md)).
- **Learning.** A decision log, "Approve and remember" patterns, threshold calibration, and a Learning view with the ask rate of the last 14 days. A local fine-tune runs in shadow mode before it can replace the model ([learning](docs/operations/learning.md)).
- **Rule packs.** 64 packs describe tools as data: migrations and ORMs, clouds and platforms, databases, containers, Kubernetes, Terraform, and secret managers. A local pack can only add restrictions ([rule packs](docs/operations/rule-packs.md)).
- **Declarations.** Each credential can say its project, environment, risk, scope, and whether its actions can be undone. Apassy suggests a declaration and knows the hosts of common providers ([declarations](docs/operations/declarations.md)).
- **Host hooks.** `apassy-hook` gives the bouncer the real request of the user in Claude Code and Codex, and checks it against the transcript ([host hooks](docs/operations/host-hooks.md)).
- **Owner checks and notifications.** Each owner action needs a fresh Touch ID or passphrase check. Notifications come from `ApassyNotify.app`, and the inbox keeps each event ([native app](docs/operations/native-app.md), [notifications](docs/operations/notifications.md)).
- **Agent isolation.** `apassy-sandbox` starts Claude Code and Codex in a Seatbelt profile. The profile denies the vault, the backups, the model, the app bundle, and the ways to start a program outside the sandbox ([isolation](docs/operations/isolation.md)).
- **Vault lifecycle.** Passphrase change, agent token expiry and rotation, a settings review after a restore, and migration from each earlier schema.

### Changed

- A run with a production credential always waits for you.
- The bouncer policy is v7. On the blind held-out set v4 (226 cases, 3 runs), no violation and no critical case ran without the owner, and 91 of 120 normal cases (76%) ran without a prompt ([held-out v4](docs/evaluation/heldout-v4.md)).

### Security

- Key memory hardening: secrets and tokens are zeroized, SQLCipher memory security is on, core dumps are off, and each program has the hardened runtime without debug or injection entitlements ([key-memory review](docs/reviews/key-memory.md)).
- rustls 0.23.45 for RUSTSEC-2026-0285, and `cargo audit` in CI.

## [0.1.0] - 2026-09-25

The alpha. It was not published.

### Added

- The Rust foundation and an encrypted vault: one SQLCipher file with a master passphrase ([ADR 0003](docs/adr/0003-passphrase-vault.md)).
- The owner views of the desktop app.
- The agent path: a local broker, the MCP adapter `apassy-mcp`, and connectors over HTTPS ([ADR 0004](docs/adr/0004-agent-path-first.md), [ADR 0005](docs/adr/0005-connector-tls.md)).
- Secrets for agent processes with owner approval: the socket never returns a secret value ([ADR 0006](docs/adr/0006-process-secrets.md)).
- Plain-language rules and a local bouncer on Laya ([ADR 0007](docs/adr/0007-rules-and-local-bouncer.md)).

[Unreleased]: https://github.com/wydrox/apassy/compare/v0.3.5...HEAD
[0.3.5]: https://github.com/wydrox/apassy/releases/tag/v0.3.5
[0.3.4]: https://github.com/wydrox/apassy/releases/tag/v0.3.4
[0.3.2]: https://github.com/wydrox/apassy/releases/tag/0.3.2
[0.3.1]: https://github.com/wydrox/apassy/releases/tag/v0.3.1
[0.3.0]: https://github.com/wydrox/apassy/releases/tag/v0.3.0
[0.2.1]: https://github.com/wydrox/apassy/releases/tag/v0.2.1
[0.2.0]: https://github.com/wydrox/apassy/releases/tag/v0.2.0
[0.1.0]: https://github.com/wydrox/apassy/commits/a2f860a
