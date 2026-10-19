# Requests: safe forward update for internal TestFlight 0.5.5

## Scope and authorization

This work follows the failures recorded in [the compatibility gate](compatibility-review-2026-10-19.md). It is an internal iOS test build with a new build number, not a new six-component release. Rafał explicitly accepted a safe forward update without preserving compatibility with the older Requests beta's local history format. Marketing versions remain 0.5.5.

The compact headers are already committed in `b029f6d`: Requests and Search have no large heading; Vault names its active vault; child screens use inline navigation titles. Waiting and History retain their shared native list presentation.

## Changes

- History encryption uses an independent, per-vault device-local key, retrieved through a native C callback. The key never enters JSON config or relay payloads. Keychain storage is non-synchronizing and `WhenUnlockedThisDeviceOnly`.
- Existing v1 history migrates atomically while its matching question key is available. Temporary migration failures retain at most one history-only key in the authenticated context; relay authorization always uses current keys. Lock, suspend and removal discard the retained material.
- Missing keys, unreadable journals and unavailable storage preserve ciphertext and block guarded answers. The native app cannot silently disable durable guards after a failed history-directory initialization.
- A fresh, definitively rejected 429 POST releases only its own intent. A rejected retry cannot release an earlier ambiguous delivery. Unknown outcomes retain the guard. Answer POSTs avoid automatic 503 retries; the generic relay client is unchanged.
- Sends are serialized per vault/request, then revalidate context. Clearing unreadable or pending history is refused. The UI hides unavailable clear actions and replaces raw error codes with concise status messages.
- Swift integration tests inject an in-memory key backend; they do not access the host's Keychain.

## Compatibility boundaries

Vault schema, answer signatures, endpoints, relay wire envelopes, component marketing versions and iOS deployment/toolchain settings are unchanged. The shared relay library gains an answer-specific transport method used by this iOS path; existing generic callers keep their behavior. AutoFill does not enable history or invoke its key provider.

The old Requests beta cannot read v2 history. If a legacy key was already lost before upgrade, the fix cannot recover it: ciphertext stays intact and the app reports the blocked history. Likewise, a lock/process exit before a failed legacy migration can be retried discards its in-memory old key. This is deliberately fail-closed; no reset or silent guard bypass is provided. Arbitrary journal I/O failures can still block answers or vault removal. Unreferenced device-local keys are retained after journal removal; removal does not claim cryptographic erasure.

## Verification ledger

All executable fixtures use synthetic vaults, fake relay services on loopback, and fake key storage. No real vault, device, installed app or host Keychain data was changed.

| Evidence | Result |
| --- | --- |
| Swift model suite | 414 tests passed |
| Rust core unit suite | 57 tests passed, including 9 history storage tests and migration-key authority isolation |
| Existing Rust questions flow | 12 tests passed |
| New rotation, rejection and initialization regressions | 5 passed; the fake 429 response now declares Retry-After: 1 instead of invoking the real 60-second default |
| Native Swift–C–Rust integration and fake key store | 84 VaultKit and 46 Core integration tests passed; final two-vault restart check passed again after compiler-warning cleanup |
| Final formatting, lint and version consistency | `cargo fmt --all -- --check`, Clippy (`apassy-core --lib --tests`, warnings denied), `git diff --check`, and Python 3.12 six-source-version check passed |
| Signed archive and TestFlight processing/group readback | Passed: 0.5.5 (29873951), `VALID`, `IN_BETA_TESTING`, present in the internal Apassy group |

Independent review found a transient migration-key loss issue; the implementation now retains history-only migration material for retry in the live authorized context. Follow-up review found no remaining P0/P1 or new security issue. Review alone is not runtime or physical-device acceptance.

## Physical-device acceptance

After the verified build is available to Rafał, test Face ID approval/cancellation, lock and background transitions, production APNs delivery/opening, and updating the existing app with its history intact. Also check key persistence through restart and question-key rotation on a synthetic test vault. Simulator, fake Keychain and code-signing evidence do not establish those device behaviors.

## Delivered build

Authenticated readback at **2026-10-19 19:28:26 UTC** confirmed **0.5.5 (29873951)** is `VALID`, unexpired and `IN_BETA_TESTING`. The build is listed in the internal **Apassy** group (`6b2b208b-6786-4736-857d-93a769afa99f`), whose membership includes Rafał. No new invitation is required. Test notes were saved in `en-GB` and read back exactly. External beta submission was not requested or performed.

- Build / delivery ID: `fa49eaaa-bb52-4c5e-8518-ee705c96f274`.
- Embedded source commit in both app and AutoFill: `0c917d1852136643c084208b5c4d7e1fd325ac77`, pushed on `product/ios-requests`.
- IPA: 16,218,140 bytes; SHA-256 `2e2d05f91438e5f79d4b1cec7bd2afce3cfe316633adac3795cff001c53715be`.
- Both exported bundles passed strict code-signature verification, have build 29873951 / marketing version 0.5.5 / minimum iOS 26.0, and disable debugging. The main app has production APNs; app groups, Keychain groups and distribution profiles were verified.
- Apple validation and the single upload both succeeded with no errors. The uploaded bytes were hash-checked against the verified IPA before transfer.

[Machine-readable verification](history-compatibility-verification-2026-10-19.json) records test counts, log hashes, artifact metadata and provider readback. Availability to the tester does not prove installation or the physical-device checks above. No previous TestFlight build was expired. No other component was republished, and all six source marketing versions remain 0.5.5.
