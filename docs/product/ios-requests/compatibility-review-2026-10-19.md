# Requests 0.5.5 internal build: compatibility gate

This is the historical review of build 29873206. The replacement implementation
and its current verification/distribution status are tracked in
[the forward-update report](history-compatibility-fix-2026-10-19.md).

**Decision: the user's no-regression condition is not met by build 29873206.**
The build remains available in internal TestFlight; this review did not expire,
remove, replace or redistribute it. Further publication is paused. Its earlier
`VALID` / `IN_BETA_TESTING` status proves delivery, not compatibility acceptance.

Reviewed source: `bc08deadcef6fbf7ee427ee3f9533028fc8ac5c0`, against stable 0.5.5
`46e088dc69cc0d0d77dfad4849984867bd136d44`. Two independent read-only agents reviewed
wire/authorization compatibility and upgrade/history safety. The parent verified
artifacts, current TestFlight state and the focused synthetic reproduction below.

## Confirmed regression: question-key rotation

**P2 availability defect; blocks this conditional acceptance.** Once this iPhone
has a saved request journal, rotation of the vault's question key makes the journal
unreadable to the new key. Valid new requests then fail before sending an answer.
Removing another trusted device is one normal trigger for this key rotation.

- `ios/ApassyCore/src/core/request_history.rs:317` rejects a different `key_id`.
- `ios/ApassyCore/src/core/questions.rs:1945` loads that journal for every answer
  and propagates `history_unavailable`, including for Deny.
- `src/vault/questions.rs:219` rotates the question key on trusted-device removal.

The synthetic probe uses the existing questions-flow harness: attach a test iPhone,
observe an old-key request, rotate the key while keeping that iPhone registered,
simulate receiving the updated vault, then answer a valid new-key request. It runs
the same case with history disabled and enabled:

| Mode | Result | Answers received by fake relay |
| --- | --- | --- |
| History disabled (control) | `ok: true`, Deny sent | 1 |
| History enabled (shipping app path) | `history_unavailable` | 0 |

The assertion that enabling history must preserve the valid post-rotation answer
**failed**, Cargo exit 101: 0 passed, 1 failed, 12 unrelated tests filtered out.
The prior broad passing suites did not exercise this combination; the existing
rotation tests use history-disabled setup.

This is a reproducible functional regression, not evidence of a secret leak,
unauthenticated grant, broken wire protocol or corrupted vault. Clearing history
is the current recovery message, but deleting history is not an acceptable silent
upgrade strategy and was not performed.

Reproduction artifacts are local, synthetic-only:
`/tmp/apassy-requests-testflight-20261019/requests_compatibility_probe.rs`,
`compatibility-rotation-probe.log` and `compatibility-rotation-probe-result.json`.
The temporary test file was removed from `ios/ApassyCore/tests` after execution;
production source and the original tests remain unchanged.

## Compatibility verified

- Root desktop/shared protocol, extension, relay envelope contract and iOS
  `questions/envelope.rs` have no diff from the baseline. Endpoint paths, v1 payload
  fields, signing strings, encryption and AAD are unchanged. Relay 0.5.5 source
  accepts the same answer envelope. No coordinated component bump is required by
  these wire changes because there are none.
- All six source versions match 0.5.5, checked with Python 3.12 and the separate
  relay checkout. This is a source check, not a new six-component live audit.
- Exported old/new IPA bundle IDs, marketing versions, minimum iOS version, URL
  configuration, background modes and Face ID purpose match. Build numbers differ:
  29870390 -> 29873206. All generated Xcode build configurations are identical.
- App and AutoFill archive entitlements are identical. The signed exported new IPA
  previously passed strict signature checks and has production APNs configuration.
- Existing vault, pairing, Keychain and settings formats were not migrated by this
  delta. History is a separate encrypted `request-history/<vault-id>.json` file.
  Older source does not use that journal; actual on-device rollback is untested.
- Public macOS `latest.json` still advertises 0.5.5 at baseline `46e088d`; the relay
  health endpoint returned `ok` (it does not expose its running version there).

## Other risks requiring targeted checks before a replacement build

These are static-review findings, not additional reproduced failures:

1. A definitive POST rejection (for example 429 before relay acceptance) can leave
   the persisted answer intent blocking a different/new attempt. Existing tests
   cover a lost reply after acceptance, not this rejection path.
2. A journal read/write error with persistence enabled fails closed and can block
   valid answers; failed journal deletion can also interrupt vault removal.
3. If native history initialization/backup-exclusion verification fails on a later
   launch, persistence is disabled and retained duplicate-intent guards are ignored.
   Existing owner authentication/signature checks still apply, but the new
   cross-restart guard guarantee is lost. Test this enabled-to-disabled transition.

Fixing these must preserve owner authentication, exact vault/request binding,
encrypted metadata, backup exclusion and protection against conflicting answers.
Do not solve the regression by silently deleting history or disabling its guards.

## Distribution and physical-device boundary

Authenticated readback at 07:04:35 UTC confirmed 0.5.5 (29873206) is still `VALID` /
`IN_BETA_TESTING`. The only group is internal **Apassy**, with one member (Rafał),
and no public link. The previous 0.5.5 (29870390) remains available and unexpired.
Neither installed build nor on-device automatic-update settings were inspected.

The same bundle identifier means installation updates the existing app and uses
its data; "internal TestFlight" is not a separate sandboxed test app. A new build
number alone is supported by TestFlight but cannot guarantee absence of behavioral
regressions. No real vault, Keychain content, live request or device was modified
for this review.

Do not recommend installing 29873206 as satisfying the user's condition. A corrected
build needs the rotation/rejection/fallback checks first, then a fresh signed build
and explicit device acceptance for Face ID, APNs and the actual upgrade path. The
choice to stop the already-distributed build remains separate; this review did not
silently expire it.
