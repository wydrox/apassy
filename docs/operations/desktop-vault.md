# Desktop vault integration

Date: 2026-09-23.
Status: owner vault and item views call the experimental passphrase vault when both `desktop` and `vault` are enabled.
This is not MVP acceptance, P2b, or permission to store real credentials.

## What is connected

The Vault view can create a file, open an existing file, unlock, lock, back up, and restore.
The Item details view can add, edit, search, delete, and reveal items in all five credential categories.
Search uses title, notes, project, and service. It does not match secret field values.
A blank secret on edit keeps the stored value. A stale revision is rejected.
Lock and a failed unlock clear revealed values from the desktop session.
Rules, agents, and activity stay on the in-memory demo model. Reset demo does not delete the vault file.
A `--features desktop` build without `vault` keeps the older demo vault.

## Checks on 2026-09-23

Host: macOS, arm64. Rust: 1.97.0. Commands from the repository root.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS. 97 tests: three egui drawing, one payload-counter, 14 contracts, 29 desktop model, five owner-vault, 12 SQLCipher probes, 28 vault lifecycle, five passphrase/redaction tests. |
| `cargo test --offline --locked --features vault --doc` | PASS. Six compile-fail checks. |
| `cargo test --offline --locked --features desktop --lib --test desktop_model` | PASS. Three drawing tests and 29 model tests. |
| `cargo run --locked --offline --features desktop,vault --bin apassy -- --smoke-test` | PASS. No window. Includes one synthetic vault round trip. |

## What this does not prove

- Real-secret use, memory erasure, swap, or crash-dump handling.
- Native-window visual QA, keyboard use, or accessibility.
- Authenticated owner transport. The passphrase field is process memory, not an owner channel.
- Agent sessions, rules, approvals, audit, or outbox records.
- Crash-safe directory persistence, rekey, or lost-passphrase recovery.
- Product isolation or a license review of bundled SQLCipher and OpenSSL.
