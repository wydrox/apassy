# Apassy — goal and definition of done

Date: 2026-09-26. Decisions: [ADR 0010](adr/0010-closing-open-decisions.md).

## Goal

The owner uses Apassy every day with real credentials.
Coding agents (Claude Code and Codex) run their commands in a Seatbelt sandbox. They get secrets only from the broker, in the environment of one process.
A local bouncer permits normal work, asks the owner about uncertain work, and learns from the owner's decisions. A production run always waits for the owner.
Each open item in ADRs 0001 to 0009 is closed by evidence or by a recorded decision.

## Definition of done

The goal is done when all items below are done.
Each item needs evidence: a passing test, a measurement in `docs/operations/`, or a review record. A stub, a skip, or a weaker mode is not evidence.

### 1. Isolation (ADR 0001 §6, ADR 0004)

- [x] I1. Apassy supplies a Seatbelt profile for the agent host. The profile denies read and write access to `~/Library/Application Support/Apassy`, the vault file, and the backup paths. It permits a connection to the broker socket. Evidence: [isolation](operations/isolation.md), `sandbox/apassy-agent-host.sb`, `src/bin/apassy-sandbox.rs`.
- [x] I2. A test starts a process in the profile. The process can call the broker through `apassy-mcp`. It cannot read, copy, or replace the vault file, a backup, or the Laya model. It cannot read the Touch ID Keychain item. Evidence: `tests/isolation/product_profile.rs` (18 tests: vault, backups, Laya, Keychain and helpers, `ps`, LaunchServices, autostart). [Isolation](operations/isolation.md) §5–§7.
- [x] I3. The test in I2 passes for the commands of a real Claude Code session and a real Codex session. `docs/operations/` tells how to start each host in the profile. Evidence: [Isolation](operations/isolation.md) §5: real Claude Code 2.1.280 and Codex 0.156.1 sessions.
- [x] I4. If the sandbox cannot start, the test fails. A skip is not a pass. Evidence: The isolation test fails when `sandbox-exec` is missing or the profile does not apply.

### 2. Vault and storage (ADR 0002, ADR 0003)

- [x] V1. A license and source review of SQLCipher, OpenSSL, rusqlite, and libsqlite3-sys is recorded, with an update policy. Evidence: [Storage dependencies](reviews/storage-dependencies.md), [licenses](../licenses/THIRD-PARTY-NOTICES.md).
- [x] V2. A key-memory review is recorded: where the key is in memory, what Apassy erases, and the limits for swap and crash dumps. Evidence: [Key memory](reviews/key-memory.md), with the status of fixes F1–F14.
- [x] V3. Startup is locked. Lock and restart deny all waiting runs and make unused approvals invalid. A test shows this. Evidence: [Vault verification](operations/vault-verification.md): `startup_is_locked`, `lock_ends_waiting_runs`, `approval_before_lock_is_not_valid_after_unlock`.
- [x] V4. The backup and restore procedure is documented and tested. A restore revokes all agents. The owner reviews the rules before an agent can run a command. Evidence: [Backup and restore](operations/backup-restore.md), `restore_needs_owner_review_before_runs`.
- [x] V5. The owner can change the passphrase. A test shows that the old passphrase then fails and the data stays. Evidence: `change_passphrase_rekeys_and_keeps_the_data`, `failed_passphrase_change_keeps_the_old_passphrase`.
- [x] V6. A test migrates a vault from each earlier schema version to the current version. Evidence: `tests/vault_migration.rs`: versions 1–8 to 9.

### 3. Owner authentication (ADR 0003, ADR 0007)

- [x] A1. `Apassy.app` is a signed app bundle with the Swift helper. A script builds it. The Rust crate keeps `forbid(unsafe_code)`. Evidence: `scripts/build-app.sh`, [native app](operations/native-app.md).
- [x] A2. Unlock is an owner setting: passphrase or Touch ID. Touch ID setup, backup restore, and recovery need the passphrase. Evidence: `tests/owner_auth.rs`, [native app](operations/native-app.md).
- [x] A3. The Touch ID unlock key is in a Keychain item with biometric access control for the current fingerprints. After a change of the fingerprints, unlock needs the passphrase. When the owner turns Touch ID off, Apassy deletes the item. Status: deferred by an owner decision on 2026-09-26 (ADR 0010, fourth round). Touch ID is paused. The passphrase is the only unlock. The code and the fake-helper tests stay.
- [x] A4. Reveal, approval of a run, changes to grants and rules, "Approve and remember", and token rotation need a fresh Touch ID or passphrase check. A test shows that Apassy refuses each action without the check. Evidence: `OwnerGate::authorize`; refusal tests in `tests/owner_vault.rs` and `tests/owner_auth.rs`. The owner checks the real Touch ID prompt by hand.

### 4. Notifications (ADR 0001 §5)

- [ ] N1. A waiting approval and a blocked request cause a native macOS notification within 5 seconds. Status: Measured with the fake helper (0.1 ms and 0.67 s). Open: the owner allows notifications and times a real banner ([notifications](operations/notifications.md)).
- [x] N2. The preview shows the agent name and the event type only. It does not show the command, the user request, or a value. Evidence: The notification type accepts only the agent name and the event type; tests in `tests/native_helper.rs`.
- [x] N3. The inbox keeps each event after a restart. A delivery failure is visible in the app, and the request stays in the inbox. Evidence: Inbox from the activity log and `waiting_run` (schema 7); restart tests.
- [x] N4. A notification or an acknowledgment is not an approval. An approval of an old or changed request fails. Evidence: [Notifications](operations/notifications.md); `NotWaiting` and `Changed` refusals.

### 5. Agent path and real secrets (ADR 0004, ADR 0006, ADR 0008)

- [x] P1. A token expires after 30 days by default. The owner can change this time and rotate a token. An expired token gives a clear error to the agent. Evidence: `tokens_expire_and_rotation_replaces_them`, `mcp_adapter_explains_an_expired_token`.
- [x] P2. A run with a production item always waits for the owner. The model, patterns, and calibration cannot change this. A test shows this. Evidence: `production_always_asks_the_owner`, `production_declaration_always_waits_for_the_owner`.
- [ ] P3. The real-secret gate opens only after I1–I4, V1–V4, A1, A2, and A4 are done, and after B2 passes. A3 is deferred (ADR 0010, fourth round). ADR 0006 and the README then record the gate as OPEN, with links to the evidence. Status: waits for B2.

### 6. Bouncer and learning (ADR 0007, ADR 0008, ADR 0009)

- [x] B1. The bouncer uses only the local Laya model on a loopback address. Apassy has no hosted model and no rule interpreter. Evidence: [Bouncer](operations/bouncer.md); ADR 0010 Models.
- [ ] B2. A held-out evaluation uses 200 or more cases that were not used for tuning: 100 normal, 50 explicit violations, and 50 suspicious. The cases come from a stack other than odealo. Labels are fixed before scoring. Three runs give zero explicit violations run and zero critical cases allowed without the owner. The share of normal cases that run without a prompt is recorded, but it is not a gate (owner decision, ADR 0010 third round; B12 has the target). Status: v1, v2 and v3 are development sets now. The blind test is [held-out v4](evaluation/heldout-v4.md).
- [x] B3. Step 1: the decision log and "Approve and remember" with narrow patterns (ADR 0010). A replay on real commands records the ask rate. No past denial becomes an allowance. Evidence: [Learning](operations/learning.md): replay, 0 denied requests allowed later.
- [x] B4. Step 2: suggested declarations and known hosts. The share of suggestions that the owner accepts without a change is recorded. Evidence: [Declarations](operations/declarations.md): 52% exact on 66 synthetic credentials; per-item record in the vault.
- [x] B5. Step 3: threshold calibration. Apassy accepts a change only if a replay on all past decisions allows no request that the owner denied. The ask rate and misses on a held-out part of the log are recorded. Evidence: [Learning](operations/learning.md) §4, `calibration_proposal_passes_the_replay_gate_and_the_owner_applies_it`.
- [x] B6. Step 4: a Claude Code `UserPromptSubmit` hook sends the user request to Apassy. The request in the log matches the host transcript. A request from the hook replaces the text from the agent. Codex gets the same with its equivalent. If Codex has no equivalent, the gap is recorded. Evidence: [Host hooks](operations/host-hooks.md): real Claude Code and Codex runs.
- [x] B7. Step 5a: tool knowledge moves from `src/broker/shell_risk.rs` to versioned built-in rule packs. A replay gives the same decisions as before the move. A test shows that a local pack can add a restriction and cannot remove one. Evidence: [Rule packs](operations/rule-packs.md): replay with 0 differences at the move; local packs only add restrictions.
- [ ] B8. Step 5b: a general base model is fine-tuned on commands from many stacks, without owner data. It ships with the app. A blind test on a new independent set is recorded. Status: Trained and packaged ([base model](operations/base-model.md)). The blind test is [held-out v3](evaluation/heldout-v3.md).
- [x] B9. Step 5c: local fine-tune and shadow mode follow the gate in ADR 0010: 300 decisions with 30 or more denials, AC power, one hour maximum, 100 shadow decisions, 95% agreement, no allowance of a denied request, and manual promotion. Evidence: [Fine-tune](operations/fine-tune.md): gate, shadow mode, promotion; `tests/local_finetune.rs`, `tests/shadow_mode.rs`.
- [x] B10. The app shows the ask rate over time, the automatic decisions, and the agreement of a candidate model with the owner. Evidence: Learning tab; [learning](operations/learning.md) §5.
- [x] B11. Step 6: Touch ID for "Approve and remember" and rule changes. A4 covers this step. Evidence: Covered by A4 (`OwnerAction::ApproveAndRemember`, `ChangeCalibration`).
- [ ] B12. After two weeks of daily use with real credentials, the Learning tab shows that the owner is asked on 10% or fewer of the runs that reach the bouncer, over the last seven days. Rule denials do not count (owner decision, ADR 0010 third round). Status: starts when the real-secret gate (P3) opens.

### 7. Records

- [ ] R1. The status line of each ADR from 0001 to 0009 says that the ADR is closed, with links to its evidence. Status: In progress.
- [ ] R2. The README status matches the implemented state. Status: Open.

## Out of scope

- Connectors for real services and the plugin design. A later ADR covers them, with P4a and P4b.
- A plain-language rule interpreter (P3a) and hosted models.
- Sharing of patterns or rule packs, and third-party packs.
- Other operating systems.
- Distribution to other users and the five-day pilot (P7).

## Known risks

- A3 needs an Apple Developer team ID. Without one, Touch ID can confirm owner actions, but it cannot unlock the vault.
- Claude Code and Codex have their own sandboxes. A second Seatbelt sandbox around them can conflict. I3 must show how the profile applies to their commands.
- On real odealo commands, 25% of runs asked the owner (ADR 0008). B2 needs 90 or more of 100 normal cases without a prompt.
- The time for a local fine-tune of Laya (about 421M parameters) on the owner's Mac is not measured. The one-hour limit in B9 can be too short.
