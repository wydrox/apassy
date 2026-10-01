# Changelog

All notable changes to Apassy. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/). The site shows this file at <https://apassy.wyderka.cc/changelog>.

## [Unreleased]

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

[Unreleased]: https://github.com/wydrox/apassy/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/wydrox/apassy/releases/tag/v0.3.0
[0.2.1]: https://github.com/wydrox/apassy/releases/tag/v0.2.1
[0.2.0]: https://github.com/wydrox/apassy/releases/tag/v0.2.0
[0.1.0]: https://github.com/wydrox/apassy/commits/a2f860a
