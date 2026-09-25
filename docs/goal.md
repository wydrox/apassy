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

- [ ] I1. Apassy supplies a Seatbelt profile for the agent host. The profile denies read and write access to `~/Library/Application Support/Apassy`, the vault file, and the backup paths. It permits a connection to the broker socket.
- [ ] I2. A test starts a process in the profile. The process can call the broker through `apassy-mcp`. It cannot read, copy, or replace the vault file, a backup, or the Laya model. It cannot read the Touch ID Keychain item.
- [ ] I3. The test in I2 passes for the commands of a real Claude Code session and a real Codex session. `docs/operations/` tells how to start each host in the profile.
- [ ] I4. If the sandbox cannot start, the test fails. A skip is not a pass.

### 2. Vault and storage (ADR 0002, ADR 0003)

- [ ] V1. A license and source review of SQLCipher, OpenSSL, rusqlite, and libsqlite3-sys is recorded, with an update policy.
- [ ] V2. A key-memory review is recorded: where the key is in memory, what Apassy erases, and the limits for swap and crash dumps.
- [ ] V3. Startup is locked. Lock and restart deny all waiting runs and make unused approvals invalid. A test shows this.
- [ ] V4. The backup and restore procedure is documented and tested. A restore revokes all agents. The owner reviews the rules before an agent can run a command.
- [ ] V5. The owner can change the passphrase. A test shows that the old passphrase then fails and the data stays.
- [ ] V6. A test migrates a vault from each earlier schema version to the current version.

### 3. Owner authentication (ADR 0003, ADR 0007)

- [ ] A1. `Apassy.app` is a signed app bundle with the Swift helper. A script builds it. The Rust crate keeps `forbid(unsafe_code)`.
- [ ] A2. Unlock is an owner setting: passphrase or Touch ID. Touch ID setup, backup restore, and recovery need the passphrase.
- [ ] A3. The Touch ID unlock key is in a Keychain item with biometric access control for the current fingerprints. After a change of the fingerprints, unlock needs the passphrase. When the owner turns Touch ID off, Apassy deletes the item.
- [ ] A4. Reveal, approval of a run, changes to grants and rules, "Approve and remember", and token rotation need a fresh Touch ID or passphrase check. A test shows that Apassy refuses each action without the check.

### 4. Notifications (ADR 0001 §5)

- [ ] N1. A waiting approval and a blocked request cause a native macOS notification within 5 seconds.
- [ ] N2. The preview shows the agent name and the event type only. It does not show the command, the user request, or a value.
- [ ] N3. The inbox keeps each event after a restart. A delivery failure is visible in the app, and the request stays in the inbox.
- [ ] N4. A notification or an acknowledgment is not an approval. An approval of an old or changed request fails.

### 5. Agent path and real secrets (ADR 0004, ADR 0006, ADR 0008)

- [ ] P1. A token expires after 30 days by default. The owner can change this time and rotate a token. An expired token gives a clear error to the agent.
- [ ] P2. A run with a production item always waits for the owner. The model, patterns, and calibration cannot change this. A test shows this.
- [ ] P3. The real-secret gate opens only after I1–I4, V1–V4, and A1–A4 are done. ADR 0006 and the README then record the gate as OPEN, with links to the evidence.

### 6. Bouncer and learning (ADR 0007, ADR 0008, ADR 0009)

- [ ] B1. The bouncer uses only the local Laya model on a loopback address. Apassy has no hosted model and no rule interpreter.
- [ ] B2. A held-out evaluation uses 200 or more cases that were not used for tuning: 100 normal, 50 explicit violations, and 50 suspicious. The cases come from a stack other than odealo. Labels are fixed before scoring. Three runs give: zero explicit violations run, zero critical cases are allowed without the owner, and 90 or more of 100 normal cases run without a prompt.
- [ ] B3. Step 1: the decision log and "Approve and remember" with narrow patterns (ADR 0010). A replay on real commands records the ask rate. No past denial becomes an allowance.
- [ ] B4. Step 2: suggested declarations and known hosts. The share of suggestions that the owner accepts without a change is recorded.
- [ ] B5. Step 3: threshold calibration. Apassy accepts a change only if a replay on all past decisions allows no request that the owner denied. The ask rate and misses on a held-out part of the log are recorded.
- [ ] B6. Step 4: a Claude Code `UserPromptSubmit` hook sends the user request to Apassy. The request in the log matches the host transcript. A request from the hook replaces the text from the agent. Codex gets the same with its equivalent. If Codex has no equivalent, the gap is recorded.
- [ ] B7. Step 5a: tool knowledge moves from `src/broker/shell_risk.rs` to versioned built-in rule packs. A replay gives the same decisions as before the move. A test shows that a local pack can add a restriction and cannot remove one.
- [ ] B8. Step 5b: a general base model is fine-tuned on commands from many stacks, without owner data. It ships with the app. A blind test on a new independent set is recorded.
- [ ] B9. Step 5c: local fine-tune and shadow mode follow the gate in ADR 0010: 300 decisions with 30 or more denials, AC power, one hour maximum, 100 shadow decisions, 95% agreement, no allowance of a denied request, and manual promotion.
- [ ] B10. The app shows the ask rate over time, the automatic decisions, and the agreement of a candidate model with the owner.
- [ ] B11. Step 6: Touch ID for "Approve and remember" and rule changes. A4 covers this step.

### 7. Records

- [ ] R1. The status line of each ADR from 0001 to 0009 says that the ADR is closed, with links to its evidence.
- [ ] R2. The README status matches the implemented state.

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
