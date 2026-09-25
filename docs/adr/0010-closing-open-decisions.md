# ADR 0010 — Decisions that close the open ADRs

Date: 2026-09-26.
Status: owner selected these options on 2026-09-26. The goal and its definition of done are in [goal.md](../goal.md).

## Context

ADRs 0001 to 0009 have open questions. Each ADR from 0004 to 0009 says that the real-secret gate stays BLOCKED.
On 2026-09-26, the owner answered a questionnaire about these questions. Each question had a recommended option.

## Decisions

### Scope

The goal closes each open item in ADRs 0001 to 0009. [goal.md](../goal.md) lists the items and the evidence for each item.

### Isolation (ADR 0001 §6, ADR 0004)

- Apassy supplies a macOS Seatbelt profile for the agent host.
- The profile denies read and write access to the Apassy data directory (`~/Library/Application Support/Apassy`), the vault file, and the backup paths. The data directory holds the broker socket and the Laya model.
- The profile permits a connection to the broker socket.
- Claude Code and Codex run their agent commands in this profile.

### Real secrets (ADR 0006)

- The owner accepts the risks in ADR 0006 ("What this mode does not protect") for all environments.
- This acceptance starts when the goal items for isolation, storage, and owner authentication are done. Until then, the real-secret gate stays BLOCKED.
- A run with an item that has a production declaration always waits for the owner. The model, remembered patterns, and threshold calibration cannot change this. This changes step 5 of the decision order in ADR 0008.

### Vault storage and unlock (ADR 0002, ADR 0003)

- The owner accepts one SQLCipher database as the store for real use. The license review and the key-memory review in the goal are conditions.
- Unlock is an owner setting: passphrase or Touch ID.
- The master passphrase stays the root key. Touch ID setup, backup restore, and recovery need the passphrase. A lost passphrase can still make the data unrecoverable.
- With Touch ID, the unlock key is in a Keychain item with biometric access control for the current fingerprints. After a change of the fingerprints, the owner unlocks with the passphrase. When the owner turns Touch ID off, Apassy deletes the item.
- This changes ADR 0003, which had no Keychain unlock.

### Touch ID (ADR 0007)

- A small Swift helper in the signed `Apassy.app` calls LocalAuthentication and the Keychain. The Rust crate keeps `forbid(unsafe_code)`.
- These owner actions need a fresh Touch ID or passphrase check: unlock (when the owner selects Touch ID), reveal, approval of a run, changes to grants and rules, "Approve and remember", and token rotation.

### Notifications (ADR 0001 §5)

- Apassy uses native macOS notifications from the signed `Apassy.app`, and the durable inbox in the app.
- A notification only tells the owner about an event. The owner approves in the app.
- A preview shows the agent name and the event type. It does not show the command, the user request, or a value.

### Agent tokens (ADR 0004)

- A token expires. The default is 30 days. The owner can rotate a token in the app. A restore still revokes all agents.
- The socket controls stay the directory mode `0700` and the token. The broker does not check the peer process. The agent can start `apassy-mcp` itself, so a check of the peer program adds little protection.

### Connectors (ADR 0001 §4, ADR 0004)

- Process mode (ADR 0006) is the only path for real secrets in this goal.
- There are no new connectors. A later ADR will define connectors as plugins. P4a and P4b move to that ADR.
- The synthetic connector `reporting-api-v0` stays for tests.
- ADR 0001 §4 closes by this scope change. Rule packs cover the tools in the owner's stack.

### Models (ADR 0001 §7)

- Local only. Laya runs on the owner's computer as the bouncer. Apassy uses no hosted model.
- There is no rule interpreter. The owner instruction stays a question to the model (ADR 0007). The plain-language interpreter of P3a is out of scope.

### Remembered patterns (ADR 0009)

- The program and its subcommand stay fixed. Apassy generalizes arguments by type only: a file in the project, a number, or a quoted string.
- A pattern runs without a prompt after 3 approvals. One denial blocks it.
- An unused pattern expires after 30 days.
- A pattern applies to one agent, one project, and one item.

### Rule packs (ADR 0009)

- Built-in packs are versioned data files in the signed app. Only an app release changes them.
- The owner can add local packs. A local pack can only add restrictions. It cannot mark a command as safe.
- Patterns, examples, and packs do not leave the computer. There is no sharing.

### Local fine-tune (ADR 0009)

- Training starts only after 300 owner decisions, with 30 or more denials.
- Training runs only on AC power, for a maximum of one hour.
- A new version runs in shadow mode for 100 new decisions.
- The owner promotes the version manually. Promotion needs 95% or more agreement with the owner and no allowance of a request that the owner denied.

## Result for the earlier ADRs

| ADR | Result |
| --- | --- |
| 0001 | §1 to §7 are decided. P0 is complete when the isolation items of the goal pass. |
| 0002 | The direction is accepted. The reviews in the goal are conditions for real use. |
| 0003 | Touch ID unlock is an owner setting. The passphrase stays the root key. |
| 0004 | Token life is decided. There is no peer check. P4a moves to the plugin ADR. |
| 0005 | No change. |
| 0006 | The owner accepts the risks for all environments, with the production rule above. |
| 0007 | The Touch ID stage uses the Swift helper. |
| 0008 | A production declaration always waits for the owner. |
| 0009 | The open questions are decided. All six steps are in the goal. |

## Limits

- The real-secret gate stays BLOCKED until the goal marks its gate items done.
- A Keychain item with biometric access control needs code signing with an Apple Developer team ID. Without one, Touch ID can confirm owner actions, but it cannot unlock the vault.
- Apple marks `sandbox-exec` as deprecated. If a macOS release removes it, isolation needs a new ADR.
- Seatbelt does not protect memory, the clipboard, or processes outside the profile.
