# Changelog

All notable changes to Apassy. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/). The site shows this file at <https://apassy.wyderka.cc/changelog>.

## [0.2.1] - 2026-09-28

Apassy builds and passes its tests on Linux. The app for Linux is not published yet: the isolation of agents uses macOS Seatbelt, and Linux needs its own version first.

### Added

- **Linux build.** Apassy, the broker, the run proxy, and the desktop app build on Linux, and the tests pass there. On Linux, the files of Apassy are in `$XDG_DATA_HOME/apassy`, or `~/.local/share/apassy`. On macOS, they stay in `~/Library/Application Support/Apassy`.
- **Linux in CI.** CI runs Clippy, the tests, and the doc tests on Linux too.

### Changed

- On Linux, `apassy-sandbox` says that it runs only on macOS. The Seatbelt tests and the tests of the Swift helpers run only on macOS.
- The run proxy test uses Node only when it reads `HTTPS_PROXY`. Node before 22.21 ignores it and connects directly.

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

[0.2.1]: https://github.com/wydrox/apassy/releases/tag/v0.2.1
[0.2.0]: https://github.com/wydrox/apassy/releases/tag/v0.2.0
[0.1.0]: https://github.com/wydrox/apassy/commits/a2f860a
