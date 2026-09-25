# Experimental vault verification

Date: 2026-09-16.
Host: macOS, arm64. Rust: 1.97.0.
Scope: the `vault` backend, synthetic lifecycle tests, and Rust feature integration.
This is not MVP acceptance or permission to use real credentials.

## Implemented scope

The backend stores all five credential categories in SQLCipher. It supports validated edits, revisions, metadata search, explicit reveal, lock, and encrypted backup and restore.
Create, open, and restore return locked instances. A failed unlock closes the previous connection and changes its epoch when entropy is available.
Detail Debug output redacts notes. Payload-size validation counts bytes without another complete plaintext JSON buffer.
Backup closes its source before the copy and leaves it locked on success or failure.
A persistent adjacent `.lock` file coordinates backend instances. This lock is advisory, not an agent security boundary.

The master passphrase is required for unlock and restore. This phase has no Keychain unlock or lost-passphrase bypass.
NUL bytes and the leading `x'` or `X'` syntax are refused. SQLCipher can interpret the latter as a raw key instead of a passphrase.
Database and backup names cannot use reserved lock or SQLite companion suffixes. Existing destination companions are not overwritten.
Restore refuses sources with journal, WAL, or SHM files. It accepts a closed single-file backup, not a live SQLite snapshot.

See the [API contract](../contracts/vault-v1.md) and [passphrase decision](../adr/0003-passphrase-vault.md).

## Local checks

All commands in this table exited with code 0 after the repairs below.

| Command | Result |
| --- | --- |
| `cargo test --locked --offline --features vault --lib --test vault_lifecycle --test vault_passphrase -- --test-threads=1` | PASS. One payload-counter test, 28 lifecycle tests, and five passphrase/redaction tests. No failures or skips. |
| `cargo clippy --offline --locked --features vault --all-targets -- -D warnings` | PASS. No warnings. |
| `cargo fmt --all -- --check` | PASS. No format differences. |
| `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` | PASS. No warnings. |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS. 92 tests: three egui drawing, one payload-counter, 14 contracts, 29 desktop model, 12 SQLCipher probes, 28 vault lifecycle, five passphrase/redaction tests. No failures or skips. |
| `cargo test --offline --locked --features vault --doc` | PASS. Six compile-failure checks. |
| `cargo run --locked --offline --features desktop,vault --bin apassy -- --smoke-test` | PASS. `smoke-test: desktop model check passed. This check does not open a window.` |

The six compile-failure checks cover absent public serialization for `SecretValue`, `Field`, `ItemDraft`, and `Vault`, absent `Vault: Clone`, and private connection access.
They do not prevent a caller from deliberately printing a revealed value.

The lifecycle tests cover passphrase bounds, all categories across reopen, literal metadata search, revision conflicts, invalid input, deletion, epochs, and encrypted copies.
They also cover wrong keys, later-page corruption, unsupported schemas, symlinks, hardlinks, lock retention, mode 0600, and special SQLite filenames.
A child test process checks relative paths and a later working-directory change without changing the main test process directory.
The file-conflict regressions check preservation of existing SQLite companions and refusal of reserved names.
Tests also check epoch changes on refused unlock, note redaction, destination reservation before key validation, and exact JSON byte counting.
Writable sessions set and verify `secure_delete=ON`. This check does not prove physical erasure or removal from earlier copies.
All stored credentials, passphrases, and canaries are synthetic and temporary.

The final `git diff --check` and separate checks of 38 untracked files passed. The changed documentation had 23 valid local file links.
The CI YAML parser check passed and found the vault doc-test step. These checks did not validate link anchors or run CI remotely.

## Repairs and earlier failures

Earlier failures are not counted as passes:

- The first lifecycle run exited 101: all 18 tests failed during create. A direct database file lock blocked SQLCipher writes.
- A separate runtime probe confirmed `DatabaseBusy`. The implementation now retains a persistent sidecar lock instead of locking the database itself.
- Review found mutable categories, ASCII-only search, incomplete schema checks, and an early backup error that could leave the source unlocked. These paths were corrected.
- A runtime probe confirmed that `cipher_integrity_check` returns no rows for a healthy file and an HMAC error row for a damaged page. The backend rejects any returned row.
- The raw-key regression exited 101 because the backend accepted a raw-key-shaped passphrase. Creation, unlock, and restore now reject that syntax and NUL bytes.
- An interrupted Grok test edit duplicated six tests and their helper. The parent removed only the duplicate after rustfmt proved the two blocks equivalent.
- Clippy exited 101 for three single-pattern matches in tests. Assertions replaced those matches without suppressing warnings.
- A new file-conflict test exited 101 because SQLite removed an unrelated file at the proposed journal path. Destination checks and reserved filenames now prevent that case.
- The previous test process handle was unavailable after interruption. No matching process remained. The parent ran the focused tests again instead of assuming a pass.

Grok produced the backend and independent test changes in separate scopes. Some bounded runs ended at their turn limits.
A report-only follow-up acknowledged the duplicate. Parent checks, not worker exit codes, establish the test results above.
Claude Code completed a separate read-only review. It reported no permission denials and did not change files or run checks.
New tests reproduced two findings: a refused unlock kept the previous epoch, and detail Debug output exposed notes. Both tests failed before the repairs.
The parent corrected both paths and replaced the temporary plaintext JSON payload with a bounded byte counter.
The parent also reserved restore destinations before key validation, verified `secure_delete=ON`, and simplified the numeric decoder.
A documentation finding used an older contract revision. The parent checked the current path rules and added the backup-source error rule.
These changes do not prove memory erasure or removal of data from old backups. The final repairs were verified by the parent, not re-reviewed by Claude Code.

## Remaining limits

- Rules, agents, and activity still use synthetic in-memory fixtures. The owner vault and item views can open an encrypted file when both `desktop` and `vault` are enabled. See [desktop vault integration](desktop-vault.md).
- The APIs are trusted-process internals, not authenticated owner or agent endpoints.
- Process memory, swap, crash dumps, and key-memory handling need further review. Redacted Debug is not memory erasure.
- Advisory locks and path checks do not stop arbitrary same-user clients or hostile filesystem races.
- Completed copies do not prove crash-safe directory persistence. Rekey, migration, recovery UX, and lost-passphrase handling remain future work.
- Durable agent sessions, rules, approvals, audit, and outbox records are not part of this backend. Epochs alone do not prove restored authority invalidation.
- Native-window QA, live connectors, model evaluations, product isolation, and bundled-native-code security and license review remain open.
- The CI workflow is configured but was not run remotely. No commit, push, publication, or deployment occurred.

The older [foundation results](foundation-verification.md) predate the vault feature. Browser and Python fixtures were not changed in this vault phase.
