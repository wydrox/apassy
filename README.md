# apassy

A credential manager for you and your agents.

Store passwords, API keys, SSH keys, database logins, and other credentials.
Write plain-language rules for who can use them, when, where, and for what purpose.
A bouncer checks agent requests, permits normal use, pauses uncertain requests, blocks forbidden use, and alerts you when needed.

## Status

The owner approved the revised MVP plan and implementation with Grok subagents on 2026-09-16.
P0 includes a synthetic owner walkthrough and filesystem checks. P1 includes Rust contracts, a native desktop demo, tests, and CI configuration.
The owner selected macOS desktop with eframe/egui, then SQLCipher with a master passphrase for an experimental vault backend.
The `vault` feature stores items in SQLCipher. With both `desktop` and `vault` enabled, the owner vault and item views use that file. Rules, agents, and activity stay in-memory fixtures. There is no broker.
See the [vault contract](docs/contracts/vault-v1.md) and [passphrase decision](docs/adr/0003-passphrase-vault.md) for scope and limits.
Real service contracts, production key handling, storage acceptance, and full agent isolation remain open. This is not a secure credential manager yet.
The descriptions above are product goals, not implemented features or verified security guarantees.
See [vault verification](docs/operations/vault-verification.md) and the earlier [foundation results](docs/operations/foundation-verification.md) for passing checks and remaining limits.

## Run the desktop demo

Run `cargo run --locked --features desktop,vault --bin apassy` for the owner vault file.
The vault view creates, opens, unlocks, and backs up an encrypted file. Item details can add, edit, search, delete, and reveal values. Do not put real credentials in it.
Rules, agents, and activity stay demo fixtures. “Reset demo” does not wipe the vault file.
Run `cargo run --locked --features desktop --bin apassy` for the older in-memory demo. “Open vault” there is not owner authentication.
Run `cargo run --locked --features desktop,vault --bin apassy -- --smoke-test` for a model check without a window.
See [desktop development](docs/operations/desktop-development.md), [Rust contracts](docs/contracts/rust-v1.md), and [development checks](docs/operations/checks.md).

## Try the synthetic walkthrough

Run `python3 -m http.server 8765 --bind 127.0.0.1 --directory design/walkthrough`.
Open `http://127.0.0.1:8765/`. Use demo data only. Press Ctrl-C to stop the server.
This browser prototype is not the selected desktop app or an encrypted vault.
See [walkthrough instructions](design/walkthrough/README.md).

## Design

- [Product Vision v1](docs/product-vision-v1.md): the product, everyday use, and MVP scope.
- [Product concept](docs/concept.md): how credentials, plain-language rules, and the bouncer work together.
- [Product Infra v1](docs/product-infra-v1.md): the Rust architecture, trust boundaries, and open technical decisions.
- [MVP plan](docs/mvp-plan.md): implementation phases, scoped Grok tasks, and acceptance checks.
