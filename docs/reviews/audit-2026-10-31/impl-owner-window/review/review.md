# PR 32 independent security review

Scope: head 6010e1a9, merged with main 153fcc42, then reviewed/fixed on feat/owner-check-window. Owner instructions override the earlier audit's narrower proposed exclusions. No merge or ready action is authorized/performed. All runtime fixtures use synthetic data.

## Confirmed defects and fixes

| Severity | Location | Attack/evidence | Fix |
|---|---|---|---|
| P2 | src/broker/approvals.rs, ApprovalQueue::approve | A proof for the exact waiting run but epoch [18;32] settles a question belonging to [17;32]. New regression FAILED before the fix (Ok vs Changed), see epoch-before.log. | Compare every real question's epoch and proof freshness while holding the queue mutex. |
| P2 | src/desktop/owner_store/browser.rs, save_login/create_login | Source proof: the old code consumed/dropped its proof and unlocked the vault, then generated/built and reacquired the vault through add(). Revocation, expiry or session replacement in this gap was not revalidated at mutation. | Retain proof through preparation and validate the exact action/epoch immediately before add(), under the same vault mutex. Controller tests cover save/create/update/code plus cross-origin refusal. |
| P2 | src/broker/approvals/owner_window.rs, Monotonic::now | Rust Instant on Darwin uses CLOCK_UPTIME_RAW, which stops in sleep. A paused observer could make its pre-sleep heartbeat look current before queued OS events run. | Sleep-inclusive CLOCK_MONOTONIC via the existing safe rustix API; injected suspension and production-clock source tests. |
| P3 | src/desktop/ui/settings.rs, security_section | Original screenshot uses raw egui ComboBox instead of the Bouncer picker. | Same kit::picker, 200-point width, form field accessibility label; screenshots retaken and inspected. |
| Verification gap | .github/workflows/ci.yml | No extension job existed on main or the PR. | Node models plus existing Playwright suite on macOS CI with checksum-pinned Helium 0.20.3.1; no local Playwright. |

Clock sources: [Rust Instant](https://doc.rust-lang.org/std/time/struct.Instant.html), [Apple clock_gettime manual source](https://github.com/apple-oss-distributions/Libc/blob/main/gen/clock_gettime.3), [Apple clock implementation](https://github.com/apple-oss-distributions/Libc/blob/main/gen/clock_gettime.c). This is an API/source proof, not a physical sleep test.

## Attack matrix and evidence boundaries

1. Scope: OwnerRequest::action is exhaustive. LocalWindowSource::permits is the sole reuse allowlist (nine proof variants, with Browser/AutoFill splitting SignPasskey by origin). OwnerProof is non-Clone and compares full OwnerAction equality, epoch, proof lifetime and window fence. Reuse call sites are start_local_owner and tests; there is no socket field that becomes LocalWindowSource. Expanded controller tests reject wrong item, web origin, system request/action, vault epoch, post-revocation proof and passkey-create reuse. Store methods consume exact proofs. The old pre-mutation save/create gap is fixed.
2. Agents: only decisions::apply(Answer::Once) calls allow_once_clicked. The queue remains pending until that explicit in-app answer, and a second run needs its own click. MCP/broker/hook do not reach reuse_local. The owner CLI uses Step::Check -> ask_owner, which always starts a fresh check; it cannot spend the shared window. Completing a fresh owner check in the app can seed the window; a protocol request alone cannot. Remote/Companion/RemoteAction use signed fresh-answer checks and never seed; answering a remote question is explicitly excluded from local seeding. Allow production, project grants, remember, grant-and-evaluate and all durable actions are excluded.
3. Browser: popup ownerAction and inline choose each have one isTrusted secret-action gate, with trustedGesture added after the gate. Worker routing checks browser-supplied extension ID/URL/document/frame/origin and offered item; no externally_connectable route exists. Passkey bridge checks isolated-world transient user activation rather than page-declared trust. Seven native commands are caller guarded in the host. The new host refuses caller-supplied host provenance and only adds its marker after the signed-browser parent check. The app independently checks the signed host/socket peer and browser chain whenever both flags request reuse. Missing gesture or host marker stays fresh; direct forged flags fail peer validation. Browser guard rejects debug/load-extension switches. Node sender/navigation models and host tests cover these cases; production caller acceptance remains unverified. Trusted browser automation is an explicitly documented residual limit, not physical-human proof.
4. Storage: effective policy is never read from ui.json, vault data or a wire setter. Policy lives in the signed keychain helper's Data Protection Keychain access group, synchronizable=false, WhenUnlockedThisDeviceOnly, version 1. requireApassyParent precedes every helper dispatch. Arbitrary same-user code lacks the access-group entitlement and cannot use the helper directly. save_owner_frequency consumes ChangeOwnerFrequency(old,new), checks current epoch/policy, clears to EveryTime before the async write and verifies exact readback. Parser/transport failures and missing/corrupt/unknown policy fail closed. Native transport mocks establish error handling; actual protected-keychain roundtrips/entitlement enforcement are not claimed.
5. Lifecycle: native observers revoke on screen lock, workspace system/display sleep and session resignation; every heartbeat also requires positive CGSession console/login and explicit IOConsoleLocked=false. Events are sequenced, capped, and health-bounded at two seconds. EOF, malformed/gapped streams, observer death and stale health fail closed; the helper is killed/reaped on drop. Mac sleep-inclusive time fences overdue heartbeats even before a sleep event is read. Vault lock/switch/rekey/backup/restore, app shutdown, failed/cancelled checks and setting change revoke. Generation checks prevent late authentication/unlock from reseeding. Tests inject these boundaries; no physical lock, sleep, user-switch or owner biometric prompt was performed.
6. Passkeys: only exact SignPasskey proofs reach vault signing, with rp_id, item, credential_id, client_data_hash, request ID and browser origin (or macOS source) bound. UP/UV are verified in the real synthetic-vault assertion test. Creation/removal are absent from every reuse allowlist. Missing window/gesture takes fresh auth. Real AuthenticationServices/device acceptance remains unverified.
7. UI: original light screenshot inspected; replacement uses the same picker widget as Start the model, including accessible row label. Tour and screenshot evidence are isolated from the owner's app and settings. The tour explicitly routes every native-helper/notifier/credential-bridge override to nonexistent review-only paths, so it cannot touch the owner's Keychain or show Touch ID. All six final PNGs are inspected directly or proven byte-identical to the inspected light counterparts (screenshot-hashes.json). The kit is light-only; a dark system-appearance run does not prove a dark theme.
8. CI: local Node only; extension Playwright is CI-only. All local Cargo commands use /Users/rafalw/Dev/.target-review32, CARGO_INCREMENTAL=0 and disabled dev/test debuginfo. Free space checked before every build (minimum threshold 6 GB). Full test/clippy results, screenshots, final main/head and CI status recorded below after validation.

## Complete scope inventory

Reproduce counts with the JSON inventory alongside this report, or extract the enum body and top-level four-space variant declarations from the two source files. The nine eligible variants are an allowlist, never a rule to skip validation of targets. A fresh check on an otherwise sensitive local action may seed a window, but its proof cannot consume one. Unlock is separately always fresh and can seed. Restore checks the supplied backup passphrase and leaves its result locked. Purely stricter actions with no owner proof retain their existing behavior.

### OwnerRequest: 53 variants

| Variant | Window consumption |
|---|---|
| `FillLogin` | Covered only through its source-specific local route |
| `UpdateLogin` | Covered only through its source-specific local route |
| `SaveLogin` | Covered only through its source-specific local route |
| `CreateLogin` | Covered only through its source-specific local route |
| `FillCode` | Covered only through its source-specific local route |
| `SignPasskey` | Covered only through its source-specific local route |
| `SystemFillLogin` | Covered only through its source-specific local route |
| `SystemFillCode` | Covered only through its source-specific local route |
| `ApproveRun` | Covered only through its source-specific local route |
| `BackupVault` | No reuse; fresh owner check when authentication is required |
| `ExportDecisions` | No reuse; fresh owner check when authentication is required |
| `RegisterAgent` | No reuse; fresh owner check when authentication is required |
| `ChangeOwnerFrequency` | No reuse; fresh owner check when authentication is required |
| `Reveal` | No reuse; fresh owner check when authentication is required |
| `ShowCode` | No reuse; fresh owner check when authentication is required |
| `CopyCode` | No reuse; fresh owner check when authentication is required |
| `CopyField` | No reuse; fresh owner check when authentication is required |
| `CreatePasskey` | No reuse; fresh owner check when authentication is required |
| `RemovePasskey` | No reuse; fresh owner check when authentication is required |
| `ApproveAndRemember` | No reuse; fresh owner check when authentication is required |
| `ApproveAndEvaluate` | No reuse; fresh owner check when authentication is required |
| `ApproveInProject` | No reuse; fresh owner check when authentication is required |
| `AllowProduction` | No reuse; fresh owner check when authentication is required |
| `CorrectEnvironment` | No reuse; fresh owner check when authentication is required |
| `AnswerSuggestion` | No reuse; fresh owner check when authentication is required |
| `ApplyCalibration` | No reuse; fresh owner check when authentication is required |
| `PromoteModel` | No reuse; fresh owner check when authentication is required |
| `RollbackModel` | No reuse; fresh owner check when authentication is required |
| `AllowOperation` | No reuse; fresh owner check when authentication is required |
| `SetProcessAccess` | No reuse; fresh owner check when authentication is required |
| `GrantMany` | No reuse; fresh owner check when authentication is required |
| `ShowAllCredentials` | No reuse; fresh owner check when authentication is required |
| `GrantRequest` | No reuse; fresh owner check when authentication is required |
| `SaveRule` | No reuse; fresh owner check when authentication is required |
| `SaveDeclaration` | No reuse; fresh owner check when authentication is required |
| `SaveVariable` | No reuse; fresh owner check when authentication is required |
| `ConfirmVariable` | No reuse; fresh owner check when authentication is required |
| `SaveConnector` | No reuse; fresh owner check when authentication is required |
| `ConfirmReview` | No reuse; fresh owner check when authentication is required |
| `Unarchive` | No reuse; fresh owner check when authentication is required |
| `SetEnvironment` | No reuse; fresh owner check when authentication is required |
| `AlwaysAskOff` | No reuse; fresh owner check when authentication is required |
| `RemoveAgentException` | No reuse; fresh owner check when authentication is required |
| `RotateToken` | No reuse; fresh owner check when authentication is required |
| `ConnectAgent` | No reuse; fresh owner check when authentication is required |
| `SetTokenLifetime` | No reuse; fresh owner check when authentication is required |
| `OpenCliSession` | No reuse; fresh owner check when authentication is required |
| `BindVariables` | No reuse; fresh owner check when authentication is required |
| `PairCompanion` | No reuse; fresh owner check when authentication is required |
| `ConfirmSyncDevice` | No reuse; fresh owner check when authentication is required |
| `ConfirmQuestionsDevice` | No reuse; fresh owner check when authentication is required |
| `EnableRelayQuestions` | No reuse; fresh owner check when authentication is required |
| `AnswerRemoteQuestion` | No reuse; fresh owner check when authentication is required |

### OwnerAction: 44 variants

| Variant | Window consumption |
|---|---|
| `FillLogin` | Covered only through its source-specific local route |
| `UpdateLogin` | Covered only through its source-specific local route |
| `SaveLogin` | Covered only through its source-specific local route |
| `CreateLogin` | Covered only through its source-specific local route |
| `FillCode` | Covered only through its source-specific local route |
| `SignPasskey` | Covered only through its source-specific local route |
| `FillSystemLogin` | Covered only through its source-specific local route |
| `FillSystemCode` | Covered only through its source-specific local route |
| `ApproveRun` | Covered only through its source-specific local route |
| `BackupVault` | No reuse; fresh owner check when authentication is required |
| `ExportDecisions` | No reuse; fresh owner check when authentication is required |
| `RegisterAgent` | No reuse; fresh owner check when authentication is required |
| `ChangeOwnerFrequency` | No reuse; fresh owner check when authentication is required |
| `Reveal` | No reuse; fresh owner check when authentication is required |
| `ShowCode` | No reuse; fresh owner check when authentication is required |
| `CopyCode` | No reuse; fresh owner check when authentication is required |
| `CopyField` | No reuse; fresh owner check when authentication is required |
| `RemovePasskey` | No reuse; fresh owner check when authentication is required |
| `CreatePasskey` | No reuse; fresh owner check when authentication is required |
| `ApproveAndRemember` | No reuse; fresh owner check when authentication is required |
| `ApproveAndEvaluate` | No reuse; fresh owner check when authentication is required |
| `ApproveAndGrant` | No reuse; fresh owner check when authentication is required |
| `ApproveInProject` | No reuse; fresh owner check when authentication is required |
| `AllowProduction` | No reuse; fresh owner check when authentication is required |
| `RemoveAgentException` | No reuse; fresh owner check when authentication is required |
| `RemoveOwnerAnswer` | No reuse; fresh owner check when authentication is required |
| `ChangeGrant` | No reuse; fresh owner check when authentication is required |
| `ChangeGrants` | No reuse; fresh owner check when authentication is required |
| `ShowAllCredentials` | No reuse; fresh owner check when authentication is required |
| `ChangeRule` | No reuse; fresh owner check when authentication is required |
| `ChangeItemRules` | No reuse; fresh owner check when authentication is required |
| `RotateToken` | No reuse; fresh owner check when authentication is required |
| `ConnectAgent` | No reuse; fresh owner check when authentication is required |
| `ChangeTokenLifetime` | No reuse; fresh owner check when authentication is required |
| `ChangeCalibration` | No reuse; fresh owner check when authentication is required |
| `PromoteModel` | No reuse; fresh owner check when authentication is required |
| `RollbackModel` | No reuse; fresh owner check when authentication is required |
| `OpenCliSession` | No reuse; fresh owner check when authentication is required |
| `BindVariables` | No reuse; fresh owner check when authentication is required |
| `BindVariable` | No reuse; fresh owner check when authentication is required |
| `PairCompanion` | No reuse; fresh owner check when authentication is required |
| `ConfirmSyncDevice` | No reuse; fresh owner check when authentication is required |
| `AnswerRemoteQuestion` | No reuse; fresh owner check when authentication is required |
| `EnableRelayQuestions` | No reuse; fresh owner check when authentication is required |

Proof types: OwnerProof authorizes one exact action and is consumed; WindowProof is an internal generation/deadline/epoch fence; OwnerDeliveryFence is cloneable read-only delivery validation and cannot authorize or mint a proof. OwnerCheck sources are TouchId, Passphrase, Companion, Remote and RemoteAction; only the first two can seed after successful fresh local verification, except setting changes and remote-question answers.

Audit-map coverage: M01 unlock fresh+seed; M02 lifecycle revokes; M03-M05 show/copy/OTP reveal stay fresh; M06-M10 routine browser password/code work is eligible; M11-M15 passkey/AutoFill paths are classified by assertion versus create/remove; M16 Allow once needs an exact app click; M17-M38 all durable, policy, pairing and remote paths stay fresh or keep their existing stricter no-auth behavior; M39 backup/export now fresh, restore fresh passphrase+locked result. The full enum inventory above removes ambiguity from grouped audit rows.

## CI defects found and fixed

CI run 41211222760 (6b51ef78) identified 13 non-desktop lint errors in the apassy dependency of apassy-core. Desktop-only reuse/delivery/lifecycle APIs are now conditionally compiled for desktop, with test-only access retained for clock tests; no warning suppression or mobile product source changes. The exact core Clippy command passes locally after the fix.

The newly added CI extension job first ran 92 Playwright tests: 73 passed, 17 failed, 2 signed/real-host checks skipped. Its strict mock host did not recognize trusted_gesture, and three popup heading selectors also matched the hidden Settings heading. The mock now validates the optional boolean, actual UI-trigger request goldens assert true, and heading assertions are scoped to main. Barrier unit tests exercise both legacy and gesture-bearing requests. Node models now pass 227 tests. Playwright remains CI-only. Completed-job log excerpts are in ci-extension-failed.log and ci-macos-failed.log; gh run view --log-failed was unavailable while the aggregate run was active, so the GitHub job-log API was used.

## Validation receipt

Final local head: `a555d194ff392810eef63c7117cf66396ed2bec5`. Main merged through `153fcc42a0fe61c0bbde95288340e1294485f80b`; final fetch/merge was already up to date. No conflicts remain, working tree is clean, and PR 32 stays draft and unmerged.

- Root full run (at 6b51ef78): `cargo test --offline --locked --all-features -- --test-threads=1` — **1,961 passed, 0 failed, 19 pre-existing ignored**, including 6 doc tests. This run precedes only the non-desktop cfg/lint and test-fixture fixes; no all-features product behavior changed afterwards.
- Final owner checks: same Cargo environment, `cargo test --offline --locked --all-features --lib owner_ -- --test-threads=1` — **94 passed**.
- Root Clippy: `cargo clippy --offline --locked --all-features --all-targets -- -D warnings` — **PASS** locally at 6b51ef78; final-head Linux CI also passes the same all-target lint.
- Final core: `cargo clippy --offline --locked -p apassy-core --all-targets -- -D warnings` — **PASS**; `cargo test --offline --locked -p apassy-core -- --test-threads=1` — **152 passed, 0 failed, 0 ignored**.
- Final extension Node models — **227 passed**; design models **33 passed**; Python isolation fixture **9 passed**. These are fixture/model checks, not signed production/native acceptance.
- `cargo fmt --all -- --check` and `git diff --check` — **PASS**.
- Screenshot paths: `light/settings-security.png`, `light/settings-security-picker.png`, `light/settings-bouncer.png` and the corresponding three `dark/` paths, all under this report's directory. Security/picker/Bouncer light captures were viewed; dark Security was viewed, and all three dark captures have exactly the same hashes as their inspected light counterparts. No clipping; all six choices visible; kit picker matches Bouncer.
- Build directory `/Users/rafalw/Dev/.target-review32` and this worktree's temporary `extension-tests/node_modules` were deleted. `df` measured **2,380,800 KiB** recovery (about **2.27 GiB**), from 11,667,008 to 14,047,808 KiB available on the Data volume. See cleanup.json. Task-started screenshot processes stopped; no manual browser was started.
- Latest CI: [run 41212071481](https://github.com/wydrox/apassy/actions/runs/41212071481), **PENDING** at receipt. Prior failures have corrective commits; the new extension Playwright rerun and queued macOS jobs still require completion. No final green claim is made.

Machine-readable details: validation.json, pr-final.json, scope-inventory.json, screenshot-binary.json and screenshot-hashes.json. Protected-keychain round trips, signed host/peer acceptance, actual Touch ID counts, physical lock/sleep/user-switch transitions and AuthenticationServices device acceptance remain **UNVERIFIED**, requiring a signed isolated build and synthetic-vault device checks. No owner data, owner Keychain items, running Apassy app, LaunchAgents, Touch ID prompts, Docker, or local Playwright were used.
