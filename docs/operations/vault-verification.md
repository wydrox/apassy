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

- Agents, grants, rules, declarations, and agent activity are in the vault (schema versions 2 to 6). The Rules screen stays a demo. The owner vault and item views open an encrypted file when both `desktop` and `vault` are enabled. See [desktop vault integration](desktop-vault.md).
- The APIs are trusted-process internals, not authenticated owner or agent endpoints.
- Process memory, swap, crash dumps, and key-memory handling need further review. Redacted Debug is not memory erasure.
- Advisory locks and path checks do not stop arbitrary same-user clients or hostile filesystem races.
- Completed copies do not prove crash-safe directory persistence. Lost-passphrase handling remains future work. The rekey, the migration, and the restore review are in the section below.
- Native-window QA, live connectors, model evaluations, product isolation, and bundled-native-code security and license review remain open.
- The CI workflow is configured but was not run remotely. No commit, push, publication, or deployment occurred.

The older [foundation results](foundation-verification.md) predate the vault feature. Browser and Python fixtures were not changed in this vault phase.

## Goal items V3 to V6, P1, and P2 (2026-09-26)

Host: macOS 27.0, arm64. Rust: 1.97.0. Schema version: 6. Bouncer policy: `apassy-bouncer-v3`.
Scope: [the goal](../goal.md), items V3, V4, V5, V6 (section 2) and P1, P2 (section 5). All data is synthetic.

### Checks

All commands ran from the repository root and exited with code 0.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS. No warnings. |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | PASS. No warnings. |
| `cargo test --locked --features desktop,vault` | PASS. 167 tests and 6 doc tests. 5 tests are ignored: they need network access or a running `laya-serve`. |
| `cargo test --locked --all-features --all-targets -- --test-threads=1` | PASS. 179 tests, 5 ignored, as above. |
| `cargo test --locked --features storage-probe --test sqlcipher_probe` | PASS. 12 tests. |
| `cargo run --locked --features desktop,vault --bin apassy -- --smoke-test` | PASS. `smoke-test: owner vault round trip passed.` |

### Evidence for each item

| Item | Tests |
| --- | --- |
| V3. Startup is locked. Lock and restart end waiting runs and unused approvals. | `startup_is_locked`, `lock_ends_waiting_runs`, `approval_before_lock_is_not_valid_after_unlock`, `restart_ends_waiting_runs_and_old_approvals`, `revoke_or_lock_during_approval_stops_the_run` (`tests/agent_run.rs`). `invalidate_all_ends_waiting_runs`, `invalidate_all_voids_an_unused_approval`, `invalid_session_ends_the_wait`, `a_new_queue_does_not_reuse_ids` (`src/broker/approvals.rs`). |
| V4. Backup and restore. A restore revokes all agents. The owner reviews before an agent runs. | `restore_needs_owner_review_before_runs` (`tests/agent_run.rs`), `restored_connector_waits_for_the_owner_review`, `delete_item_removes_links_and_restore_revokes_agents` (`tests/agent_path.rs`), `restore_lists_items_for_review_until_the_owner_confirms` (`tests/owner_vault.rs`), `restored_item_shows_the_review_and_confirm_action` (`src/desktop/ui.rs`), `restore_migrates_an_old_backup` (`tests/vault_migration.rs`). Procedure: [backup and restore](backup-restore.md). |
| V5. Passphrase change. The old passphrase fails and the data stays. | `change_passphrase_rekeys_and_keeps_the_data`, `failed_passphrase_change_keeps_the_old_passphrase`, `wal_mode_file_changes_passphrase_without_a_wal_file` (`tests/vault_passphrase.rs`), `owner_changes_the_passphrase_with_a_repeat` (`tests/owner_vault.rs`), `passphrase_card_asks_for_the_new_passphrase_two_times` (`src/desktop/ui.rs`). |
| V6. Migration from each earlier schema version. | `unlock_migrates_each_earlier_schema_version_to_the_current_one`, `a_failed_migration_keeps_the_old_version_and_data`, `restore_migrates_an_old_backup` (`tests/vault_migration.rs`). |
| P1. Token expiry, lifetime, and rotation. | `tokens_expire_and_rotation_replaces_them`, `mcp_adapter_explains_an_expired_token` (`tests/agent_path.rs`), `owner_changes_token_lifetime_and_rotates_a_token` (`tests/owner_vault.rs`), `agents_view_shows_token_expiry_and_rotation` (`src/desktop/ui.rs`), `expired_token_gives_the_user_a_next_step` (`src/agent/mcp.rs`). |
| P2. A production run always waits for the owner. | `production_always_asks_the_owner` (`src/broker/bouncer.rs`), `production_declaration_always_waits_for_the_owner` (`tests/bouncer_rules.rs`). |

### What the tests show

- V3: the broker refuses every request before the owner unlocks. A lock ends a waiting run within about 100 ms, also when nobody calls `invalidate_all`. An approval that the broker did not use before a lock and an unlock gives `approval_invalidated`, and the command does not run. A stop of the broker ends the waiting run. After a restart, the vault is locked, and the old run ID matches no run in the new queue.
- V4: a restore revokes every agent, removes every grant and rule, and marks each item with a declaration, an environment variable, or a connector. A run or a connector call with a marked item gives `review_required` until the owner confirms. The model is not asked.
- V5: after the change, the old passphrase gives `WrongKeyOrCorrupt`, the new passphrase opens the file, and items and agents stay. The file does not open with `kdf_iter` 64000 or with `cipher_compatibility` 3. A backup from before the change opens only with the old passphrase. No journal, WAL, or SHM file stays.
- V6: files of versions 1 to 5 are built from frozen copies of the historical schema SQL, with data of each version. After unlock, each file is at version 6 and all data is present. A version 3 grant in "allow" mode becomes "bouncer" mode. A failed migration leaves the file at version 5 with its data.
- V6, schema 7 (2026-09-26): the test also builds a version 6 file with a rotated token, a changed token lifetime, and a waiting restore review. After unlock, each file of versions 1 to 6 is at version 7, all data is present, and the decision log and the pattern list work. `a_failed_migration_from_version_6_keeps_the_old_version_and_data` shows that a failed step from 6 to 7 leaves the file at version 6. See [learning](learning.md).
- V6, schema 8 (2026-09-26): the test also builds a version 7 file with a decision log entry, a blocked pattern, and a calibration. After unlock, each file of versions 1 to 7 is at version 8, all data is present, and the declaration provider and the suggestion record work. `a_failed_migration_from_version_7_keeps_the_old_version_and_data` shows that a failed step from 7 to 8 leaves the file at version 7. See [declarations](declarations.md).
- P1: a token works for 30 days after its issue time by default. The owner can set 1 to 365 days. The lifetime applies to every token from its issue time. An expired token gives `token_expired`, and the activity log names the agent. A rotation stops the old token at once and keeps the grants. `apassy-mcp` tells the user to rotate the token.
- P2: a production declaration waits for the owner for known safe commands, read-only commands, and a model answer that is fully certain. The broker does not call the model for such a run. The owner can still approve the run.

### Findings and repairs

Earlier failures are not counted as passes:

- The first passphrase-change test with a second SQLite reader failed. SQLCipher 4.x `sqlite3_rekey_v2` returns success also when the commit of the rekey fails. The pragma answered "ok", the file kept the old key, and a rollback journal stayed. The repair takes the exclusive lock once before the rekey and verifies the change with a new connection. Now the reader case gives `Busy` before a page changes, and no journal stays.
- The first weaker-settings check placed `PRAGMA kdf_iter` before `PRAGMA key`. SQLCipher ignores cipher settings before the key, so the check passed for the wrong reason. The test now sets the weaker settings after the key.
- The first run of the lock test after the V3 change gave `approval_invalidated` or `vault_locked` in random order. A locked vault after an approval now always gives `approval_invalidated`.

### Limits of this evidence

- A reader of another SQLite client can start between the exclusive-lock check and the commit of the rekey. The verification then finds the failure, and the vault stays locked with the old passphrase. No test forces this timing.
- The rekey journal and old backups keep pages with the old key. Free disk blocks and snapshots can keep them too.
- A migration from version 1 to 5 uses the registration time as the issue time of each token. A token older than 30 days is expired after the migration.
- The connector path (`reporting-api-v0`) has no bouncer and no owner approval. The production rule applies to process runs. Connectors stay synthetic (ADR 0010).
- The GUI actions have headless egui drawing tests and model tests. There was no native-window QA of the new cards.
