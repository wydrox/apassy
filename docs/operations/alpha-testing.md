# Alpha testing — owner vault

Date: 2026-09-25. Branch: `alpha/owner-vault`.
Scope: the owner vault and item views only. Rules, agents, and activity are in-memory demo data.
Use synthetic values only. This alpha is not approved for real credentials.

## Build and run

```
cargo build --release --locked --features desktop,vault --bin apassy
./target/release/apassy
```

Headless check: `./target/release/apassy --smoke-test`.
File paths are typed into text fields. A relative path resolves from the directory where you started the app.
Use absolute paths in a throwaway folder, for example `/tmp/apassy-alpha/vault.db`.
The passphrase must have at least 12 bytes.

## Checks on 2026-09-25

Host: macOS arm64. All commands exited with 0.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS, 97 tests |
| `cargo test --offline --locked --features vault --doc` | PASS, 6 compile-fail checks |
| `cargo build --release --offline --locked --features desktop,vault --bin apassy` | PASS, 14 MB binary |
| `./target/release/apassy --smoke-test` | PASS |

The native window opened (title "Apassy", 1280×868). No automated visual walkthrough was done.

## Manual test list

Mark each row PASS / FAIL and add a note.

### Vault file

1. Create a new vault at an absolute path with a passphrase of 12 or more characters.
2. Try to create with a passphrase shorter than 12 characters. Expect a clear refusal.
3. Try to create at a path that already exists. Expect a refusal, and the file must stay unchanged.
4. Lock, then unlock with the correct passphrase.
5. Unlock with a wrong passphrase. Expect a refusal, and no revealed values.
6. Quit the app, start it again, and open the existing file.

### Items (repeat for all five categories)

7. Add an item with name, notes, project, service, and a secret value.
8. Edit the name. Leave the secret field blank and save. The old secret must stay.
9. Edit the secret to a new value and reveal it. The new value must show.
10. Search by name, notes, project, and service. All must match.
11. Search by part of a secret value. There must be no match.
12. Delete the item. It must not come back after lock/unlock or restart.

### Reveal, lock, clipboard

13. Reveal a value, then lock. The revealed value must disappear.
14. Use Copy. By design the app does not write to the clipboard. Check that the clipboard is unchanged and that the message says so.

### Backup and restore

15. Back up to a new absolute path.
16. Change or delete items, then restore the backup to a new destination path. The restored vault must hold the backup state.
17. Try to restore onto an existing file. Expect a refusal, and the backup must stay unchanged.
18. Delete the vault file while the app is closed, then open the path. Expect a clear error.

### General

19. "Reset demo" must not delete the vault file.
20. Resize the window and use the keyboard only (Tab, Enter, Esc). Note what you cannot reach.
21. Note error messages that are unclear, and any crash with the steps to reproduce it.

## Known limits

- No real secrets. Memory erasure, swap, and crash-dump handling are not verified.
- No agent sessions, rules, approvals, connectors, or notifications.
- No file picker. Paths are typed.
- No rekey and no recovery from a lost passphrase.
- No packaged app, code signing, or update path. SQLCipher and OpenSSL license review is not done.
