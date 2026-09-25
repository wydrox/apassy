# Foundation verification

Date: 2026-09-16.
Host: macOS, arm64. Rust toolchain: 1.97.0.
Scope: P0 fixtures and the partial P1 Rust desktop foundation.
This is not MVP acceptance or permission to use real credentials.

## Final local results

All commands below exited with code 0.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS. No format differences. |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | PASS. No warnings. |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS. 58 tests: 3 egui drawing, 14 contracts, 29 desktop model, 12 SQLCipher. No failures or skips. |
| `cargo run --locked --offline --features desktop --bin apassy -- --smoke-test` | PASS. `smoke-test: desktop model check passed. This check does not open a window.` |
| `node --check design/walkthrough/app.mjs` | PASS. Syntax check. |
| `node --test design/walkthrough/model.test.mjs` | PASS. 33 tests. No failures or skips. |
| `python3 tests/isolation/test_fixture_boundary.py` | PASS. Nine tests. `Real-secret gate: BLOCKED. This fixture is not product isolation evidence.` |
| `git diff --check` | PASS. No whitespace errors. |

The parent also ran focused checks before the combined suite:

- `cargo test --locked --offline --test contracts`: 14 passed.
- `cargo clippy --locked --offline --features storage-probe --test contracts --test sqlcipher_probe -- -D warnings`: passed.
- `cargo test --locked --offline --features desktop --lib --test desktop_model`: three drawing tests and 29 model tests passed.
- `cargo test --locked --offline --features storage-probe --test contracts --test sqlcipher_probe -- --test-threads=1 --nocapture`: the 12 SQLCipher tests passed. The contract task was still in progress at this earlier check.

## SQLCipher observations

The runtime reported:

- Version: `4.14.0 community`
- Provider: `openssl`
- Page size: 4096 bytes
- KDF iterations: 256000
- HMAC algorithm: `HMAC_SHA512`
- KDF algorithm: `PBKDF2_HMAC_SHA512`
- HMAC enabled: 1
- Plaintext header size: 0

The tests check wrong and missing keys, encrypted artifacts, coordinated transactions, rollback, reopen, a closed encrypted copy, and corruption.
The transaction changes a usage counter and pins the active policy version. It does not advance that version per operation.
See [ADR 0002](../adr/0002-encrypted-state-probe.md) for the scope and remaining limits.

## Repairs during verification

Earlier failing checks are not counted as passes:

- SQLCipher initially failed to compile because a match moved an integrity-check string. A borrow corrected that error.
- Nine probe cases then failed because numeric PRAGMAs returned text. A strict integer-or-integer-text decoder corrected the test helper.
- The journal case then failed because its update wrote the existing value. A distinct canary now forces a real write.
- The journal must be nonempty during the transaction. The scan covers old and new canaries, and rollback must restore the old note.
- Desktop approval originally left the current decision and alert at `Wait`. The repair updates current state and preserves the first decision and activity history.
- Clippy found style errors in source and tests. The final run passed without suppression attributes.

Three Grok sessions ran separate tasks in parallel. Some bounded runs reached their turn limits after partial edits.
Follow-up runs and parent corrections completed the current changes. The parent inspected the edits and ran the checks independently.
Worker exit code 0 was not used as test evidence.

## Dependency inventory

`cargo metadata --offline --locked --all-features --format-version 1 > target/cargo-metadata.json` passed.
The declared-license inventory contains 353 packages, including the workspace package.
The local files are `target/cargo-metadata.json` and `target/cargo-license-inventory.txt`.
This inventory is not a bundled-native-code license review or a vulnerability review.

## Not verified or implemented

- Native-window visual QA, keyboard interaction, accessibility, and egui ID-clash diagnostics
- A remote CI run, installation package, or release build
- Production key handling, authenticated unlock, memory erasure, or a product backup and restore procedure
- A production vault connected to the desktop
- The contract validator connected to a broker or authenticated owner channel
- Complete agent isolation, including memory, clipboard, automation, and IPC
- Real connector services, live rule interpretation, Jev access, or model evaluation
- Native notification delivery or a durable approval inbox
- Full source, license, and vulnerability review of bundled SQLCipher and OpenSSL

The desktop still uses in-memory synthetic fixtures. Headless drawing is not a native-window visual test.
These results predate the `vault` feature. The owner later selected [SQLCipher with a master passphrase](../adr/0003-passphrase-vault.md).
The checks above do not verify that later backend. P0 and MVP remain incomplete.
No commit, push, publication, or deployment occurred.
