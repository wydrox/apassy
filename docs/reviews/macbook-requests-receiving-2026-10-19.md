# MacBook Requests receiving investigation

## Reported device state

Rafał reported that an agent request from the Mac mini appeared on his iPhone,
but not in the MacBook Requests list. He confirmed that the same vault was open
and unlocked on both Macs. He subsequently selected **relay questions disabled
or MacBook not joined** in Settings → Devices. This explains why the MacBook
was not eligible to receive those requests. No live device registration, vault
contents, or credential values were inspected or changed during this work.

The existing supported setup is to create an **Add an iPhone or a Mac…** link
under Settings → Devices on the joined Mac mini, turn on **Send questions
through the relay** on the MacBook, and use that link to join the existing
questions team. The owner verifies matching safety words and confirms joining
on the other Mac; local Touch ID or passphrase checks remain required. A shared
unlocked vault does not itself authorize another Mac to receive questions.
After joining, use a fresh request because the original may have expired.

## Separate reproducible defect

Source inspection found that the desktop receiver advanced its delta cursor
past a sealed question it could not yet read. A later key or trusted-device sync
did not re-read that unchanged record. This is independent of the reported
MacBook enrollment state and is not claimed as its live root cause.

The synthetic key-sync regression failed before the fix: after successful sync,
the original request remained absent in the same unlocked session. The installed
Mac mini app metadata was read-only verified as 0.5.5, commit
`46e088dc69cc0d0d77dfad4849984867bd136d44`; its receiver used the affected path.
No installed app was replaced or launched for this investigation.

## Correction

- Retain bounded sealed unreadable records and retry with current vault keys and
  trusted-device rows, including empty deltas and transient fetch failures.
- Scope receiver state to vault path, unlock epoch and team, with generation
  guards against stale in-flight responses after receiver reset.
- Remove terminal and expired records; preserve the original decryption, trust
  validation and fresh owner-approval requirements.
- Keep a retry cursor when the pending buffer is full, so deferred records are
  not permanently skipped.
- Show one contextual receiving problem in Requests and suppress misleading
  “Nothing needs you” / “All clear” messages during that failure.

## Verification

Tests use synthetic vaults and a loopback fake relay. They do not establish live
MacBook reception, Touch ID,
macOS notifications or APNs behavior. This change has not been deployed; it is
not another 0.5.5 macOS release. The already published internal iOS test build
and all component versions remain unchanged.

Executed with shared `CARGO_TARGET_DIR=/Users/rafalw/Dev/apassy/target`, two build
jobs, and the existing `/tmp/apassy-flow-ux-build.toml` toolchain workaround:

- `cargo test --offline --locked --features vault --test it relay_questions:: -- --nocapture`:
  **23 passed**, including the four new key-sync, trust-sync, settlement and lock
  regressions. Recovered requests still reject approval without owner proof.
- `cargo test --offline --locked --features vault --lib questions::worker::receive_tests::`:
  **1 passed**, proving cursor retention and eventual admission after a full
  pending buffer. This unit test intentionally exercises a stronger bound than
  the real relay's open-question quota; fake relay quotas were not relaxed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo clippy --offline --locked --all-features --all-targets -- -D warnings`:
  passed, including compilation checks for the desktop UI and test targets.
- Independent read-only review: two initial findings (overflow cursor loss and
  an overly short test polling deadline) corrected and re-reviewed; no remaining
  concrete findings. Delayed responses concurrent with device disable/removal
  and visual rendering were source-reviewed, not separately exercised live.

The vault-only unit-test build reports an existing unused desktop-only test
helper, `insert_remote_for_test`; it is not a failure. The full desktop-feature
Clippy check passed without warnings. No signed macOS artifact was built or
published for this correction.
