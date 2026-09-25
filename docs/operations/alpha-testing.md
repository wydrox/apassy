# Alpha test — owner vault

Date: 2026-09-25. Branch: `alpha/owner-vault`.
Scope: the owner vault and the item views only. Rules, agents, and activity use demo data in memory.
Use only synthetic values. Do not put real credentials in this alpha.

## Build and start the app

```
cargo build --release --locked --features desktop,vault --bin apassy
./target/release/apassy
```

To do a check without a window, use `./target/release/apassy --smoke-test`.

You type each file path into a text field. The app has no file dialog.
A relative path starts from the directory where you started the app. Use absolute paths in a test directory, for example `/tmp/apassy-alpha/vault.db`.
The passphrase must have a minimum of 12 bytes.

## Checks on 2026-09-25

Host: macOS arm64. All commands gave exit code 0.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS, 97 tests |
| `cargo test --offline --locked --features vault --doc` | PASS, 6 compile-fail checks |
| `cargo build --release --offline --locked --features desktop,vault --bin apassy` | PASS, 14 MB binary |
| `./target/release/apassy --smoke-test` | PASS |

## Manual test list and results of the GUI run

On 2026-09-25, a script operated the release build in the native window. The script used synthetic mouse and keyboard events and window screenshots.
The test directory was `/tmp/apassy-alpha/`. The API key and Login categories were in the test. The SSH key, Database, and Custom categories were not in the test.

| # | Test | Result |
| --- | --- | --- |
| 1 | Create a vault at an absolute path with a passphrase of 12 or more characters. | PASS. The file mode is `0600`. The file has no SQLite header. |
| 2 | Try to create a vault with a passphrase of less than 12 characters. | PASS. The app refused and made no file. See finding F1. |
| 3 | Try to create a vault at a path that exists. | PASS. The app refused. The SHA-1 of the file did not change. |
| 4 | Lock the vault. Then, unlock it with the correct passphrase. | PASS |
| 5 | Unlock the vault with an incorrect passphrase. | PASS. The message is "the key is wrong or the vault is corrupt". |
| 6 | Close the app. Start it again and open the vault file. | PASS. The item and its revision were in the file. |
| 7 | Add an item with a name, notes, project, service, and secret value. | PASS for API key and Login. The form shows the correct fields for each category. |
| 8 | Change the name. Keep the secret field empty and save. | PASS. The old secret stayed in the item. See finding F4. |
| 9 | Change the secret and reveal it. | NOT DONE |
| 10 | Search by the name, notes, project, and service. | PASS. All four searches found the item. |
| 11 | Search for a part of a secret value. | PASS. The search found no item. |
| 12 | Delete the item. | PASS. The app asks for a confirmation before it deletes the item. |
| 13 | Reveal a value. Then, lock the vault. | PASS. The app hid the item details. |
| 14 | Examine the copy function. | NOT APPLICABLE. The app has no copy control. |
| 15 | Make a backup to a new absolute path. | PASS. After the backup, the app locks the vault. |
| 16 | Change the items. Then, restore the backup to a new path. | PASS. The restored vault had the state of the backup. |
| 17 | Try to restore the backup onto a file that exists. | PASS. The app refused. The SHA-1 of the two files did not change. |
| 18 | Open a path that does not exist. | PASS. The message is "the item or vault was not found". The app made no file. |
| 19 | Click "Reset demo". | PASS. The vault files stayed. The vault stayed unlocked. |
| 20 | Change the window size. Use only the keyboard. | NOT DONE |
| 21 | Record unclear messages and crashes. | No crash. See the findings. |

## Findings

Status on 2026-09-25 after the fixes. A second GUI run on a new vault examined each fix.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | If the passphrase was too short, the message was "the input is invalid". | FIXED. The message is now "The passphrase must have a minimum of 12 characters." |
| F2 | Medium | In `desktop,vault` mode, the banner and the sidebar showed "Storage is not connected" and "Encryption is not present". | FIXED. The banner and the sidebar show the encrypted vault file. They also show that rules, agents, and activity stay in memory. |
| F3 | Low | The text fields were almost white on a light background. | FIXED. Text fields have a white fill and a visible border. |
| F4 | Low | A save with no changes increased the revision number. | FIXED. The app shows "There are no changes to save." The revision does not change. |
| F5 | Low | After an unlock, the item list was below the visible area. | FIXED. After an unlock, the search, the item list, and "Add item" come first. The file and backup controls are in a folded section below them. |
| F6 | Low | The warning below a revealed value seemed cut at the right edge. | NOT A DEFECT. The screenshot crop cut the text. The second run showed the full text. |
| F7 | Low | Error messages started with a lowercase letter. | FIXED. The desktop shows a full sentence for each vault error. `VaultError` text did not change. |
| F8 | Low | The search hint did not mention notes. | FIXED. The hint is "Name, project, service, or notes". |

After the fixes, all commands in "Checks on 2026-09-25" gave exit code 0. The test count is 99. Two new tests are in `tests/owner_vault.rs`.

## Known limits

- Do not use the alpha for production secrets. There is no test of memory erasure, swap, or crash dumps.
- The alpha has no agent sessions, rules, approvals, connectors, or notifications.
- The app has no file dialog. You must type each path.
- The app cannot change the passphrase. If you do not know the passphrase, you cannot open the vault.
- The alpha has no app package, code signature, or update procedure. There is no license review of the bundled SQLCipher and OpenSSL.
