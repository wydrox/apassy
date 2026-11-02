# Global owner window implementation — 2026-11-02

All `OwnerAction` variants are eligible through `LocalWindowSource::LocalOwner`.
Browser and AutoFill sources retain transport-specific action checks. Actual
passphrase input remains required for passphrase change and enabling Touch ID
unlock; neither is an `OwnerAction` that can substitute a proof for that input.

## Removed fresh-check exclusions

- Access consent (`AllowAccessOnce`, `GrantAccessRequest`).
- Backup, decision export, agent/setup-agent registration.
- Frequency changes; reveal, CLI code, UI show/copy code and ordinary secret copy.
- Passkey creation and removal (password fill/save/update/create, OTP fill and
  passkey get were already covered for trusted browser/system requests).
- Remembered approvals, ApproveAndEvaluate, first-use grants, project approvals,
  production allowances, exceptions and remembered-answer changes.
- Grants, catalog visibility, rules and item environment/declaration changes.
- Token rotation/connect/lifetime, calibration and model promotion/rollback.
- CLI session opening and variable bindings.
- iPhone pairing/removal, sync-device confirmation, local remote-question
  answers and relay-question setup.

Allow Once and question Development already reused after exact local clicks.
Their question-liveness checks remain. No automatic agent decision was added.

## Extension and native-host audit

| Path | Before | After |
| --- | --- | --- |
| Password fill | Trusted gesture + signed host marker reused | Same shared window |
| Save | Trusted popup/inline save gesture reused | Same shared window |
| Update | Save worker supplies trusted gesture; exact revision reused | Same shared window |
| New password | Trusted create gesture reused | Same shared window |
| One-time code fill | Trusted gesture reused; seed never returned | Same shared window |
| Passkey get | Isolated bridge user activation; get-only gesture forwarded; reused | Same shared window, UP/UV retained |
| Passkey create | Bridge attested activation, background discarded gesture for create; gate excluded creation | Forward activation for create; browser and AutoFill gates admit exact creation proof |
| Multiple passkey accounts | Selection required before authorization | Selection still required, then window consulted |
| Legacy host/extension without provenance | Fresh check | Fresh check; no fabricated provenance |
| Verify browser | Native host codesign/caller/guard and app peer checks, no Touch ID pairing step | Same caller checks; no new Touch ID |
| Device pairing | Local owner dialog always fresh | Global local-controller window |

The extension has no independent biometric cache or timer. `background.js` uses
capability negotiation for gesture compatibility. `relay.rs` stamps the host
marker only after the guarded caller check. The app independently validates the
peer and live ticket before reuse. System AutoFill uses its live ticket. There is
no separate extension/browser biometric pairing command.

## Validation handoff

Only rustfmt and `git diff --check` are run by this implementation worker.
Compilation, tests, lint, Swift checks, scripts and device execution are not run.
Recommended CI commands (top-level validation owner):

```sh
cargo test --offline --locked --all-features owner_window
cargo test --offline --locked --all-features owner_session
cargo test --offline --locked --all-features owner_lifecycle
cargo test --offline --locked --all-features cli_code
cargo clippy --offline --locked --all-features --all-targets -- -D warnings
xcrun --sdk macosx swiftc -typecheck -swift-version 5 -warnings-as-errors native/ApassyHelper/*.swift
```

Also run the existing full CI suite and extension tests. Signed synthetic-vault
acceptance must cover unlock → first fill, repeated create/get, delayed helpers,
lock/unlock while the helper is suspended, display sleep, system sleep, switching
users, timeout, helper exit/restart, revealing secrets and production decisions.
