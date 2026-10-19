# Native Requests implementation

Latest UI correction: [compact headers and the active-vault selector](compact-headers-2026-10-19.md)
(2026-10-19; native verification, not a new TestFlight build).
The earlier [Waiting / History consistency correction](uniform-ui-2026-10-19.md) remains documented separately.

Branch: `product/ios-requests`, based on `46e088dc69cc0d0d77dfad4849984867bd136d44`.
User authorized implementation after accepting A as a wireframe. Versions remain 0.5.5; this work is not a release.

On 2026-10-19 the user additionally authorized committing this branch and delivering a new TestFlight build for Rafał. The earlier verification below remains the implementation-stage record. See the [physical-device test plan](device-test-plan.md); upload, processing and tester availability require separate delivery evidence.
The user explicitly selected an internal TestFlight **0.5.5** build with a new build number, without starting a new coordinated six-component release. This does not change the shared marketing versions or the release policy.

Delivery is complete: **0.5.5 (29873206)** is `VALID` / `IN_BETA_TESTING` and available to Rafał's internal group. See the separate [TestFlight delivery evidence](testflight-delivery-2026-10-19.md). Physical-device acceptance remains pending.

The later [compatibility review](compatibility-review-2026-10-19.md) found and reproduced a regression after question-key rotation. Build 29873206 does not meet the user's conditional no-regression acceptance; further publication is paused. The earlier test results below remain historical, incomplete coverage.

## Delivered behavior

- Native Waiting / History navigation, system lists, segmented controls, menus, search and sheets. Liquid Glass is used through system navigation and controls; content rows are readable system surfaces.
- Routine, current, fully described non-production Read requests have Deny / Allow Once. Unknown, elevated, production and local command requests retain Review. Grants still require the existing owner signature, followed by an immutable-request recheck. Denial never grants authority.
- Separate row navigation and action targets, stable submitted rows, explicit Done, accessible text labels and action stacking at accessibility text sizes. Empty states show a useful next action; no empty Suggestions category or passive Mac-only copy.
- History search, All / Allowed / Denied filters, date groups and read-only details. A selected answer, attempted POST, relay acceptance, authoritative decision and execution are separate facts. No confirmed outcome is inferred from delivery or timeout.
- Per-vault encrypted metadata journal: 30 days from first observation and at most 1,000 records. Private atomic files; native backup exclusion verified before enabling persistence. No command, arguments, prompt, full project path or secret value is persisted.
- Lock removes decrypted records and search state. Vault removal deletes its journal. Key mismatch/corruption is explicit and recoverable by Clear History. Live unresolved attempts are preserved until expiry even across clock changes; capacity refuses another answer before POST if no durable guard can fit. Clearing cannot remove a live duplicate-answer guard.

History covers **relay vault requests observed on this iPhone**. The UI states this coverage. Wi-Fi companion Activity remains separate: its wire contract has no verified vault binding, and selecting a vault or matching a Mac display name cannot supply one. Complete cross-device history is not implemented.

## Work ownership

Four scoped implementation/review agents worked on native UI (swiftui-pro/apple-design), action models, encrypted history and independent security review. Parent owned Session APIs, root preview wiring, integration, Xcode project, UI tests and documentation. Each source file had one editor at a time. Main alone ran builds.

Independent review found and resolved: lock during authentication restoring rows; lock during POST losing delivery intent; own persisted attempt blocking exact retry; attempted state falsely claiming delivery; pairing identity crossing a detail route; unavailable journal lacking Clear; and capacity eviction of a still-live answer guard. Final visual review also removed duplicate History menus and required an explicitly known vault ID/name for a quick Allow Once. Missing scope retains Deny / Review. Final source review found no remaining P0/P1 in the reviewed delta.

## Verification

| Evidence | Result | Boundary |
| --- | --- | --- |
| `swift test --package-path ios/ApassyCompanion/ModelTests` | 414 tests passed, 36 suites | In-memory models and scripted transport; no real Face ID or relay |
| `cargo --config /tmp/apassy-flow-ux-build.toml test -p apassy-core --lib request_history` | 5 passed | Synthetic temporary encrypted stores, corruption/key mismatch, retention, capacity, deletion |
| `cargo --config /tmp/apassy-flow-ux-build.toml test -p apassy-core --test questions_flow` | 12 passed | Fake relay/keys, actual core protocol; restart/lock/removal, intent, no POST at full pending capacity |
| `cargo … clippy --offline --locked -p apassy-core --lib -- -D warnings` | Passed | Changed core library; shared target, two jobs, incremental output disabled |
| `cargo fmt --all -- --check` | Passed | Workspace Rust formatting |
| `APASSY_CORE_PROFILE=dev scripts/build-ios-core.sh sim mac` | Final source Simulator/macOS slices and fake-Mac helper built | Uses shared target; task-local strip workaround for Xcode 27 |
| `swift test --package-path ios/ApassyVaultKit --filter RequestHistoryTests` | 5 passed | Swift decoding, hidden locked rows, preview clearing and explicit vault scope |
| `xcodebuild … -jobs 1 ARCHS=arm64 … build-for-testing` | TEST BUILD SUCCEEDED, no warnings/errors | App + AutoFill + UI runner; iOS 26 deployment preserved, Xcode 27; unsigned Simulator build |
| Native UI tests | 7 distinct scenarios passed across focused runs; affected actions/history/accessibility checks rerun after final edits | Dedicated synthetic iPhone 17e Simulator, iOS 27 |
| `git diff --check` | Passed during integration | Formatting only |

All tests use synthetic data. The Simulator uses ephemeral in-memory answer keys for explicit preview launches, without creating Keychain items. Original dirty checkouts and unrelated concurrent work remain untouched.

The HTML/browser evidence in verify-report.md is historical proposal evidence. It is not native acceptance. Real-device Face ID/Secure Enclave, APNs cold launches/delivery, VoiceOver task testing and customer comprehension tasks remain separate acceptance checks. No TestFlight upload, signing, publication, commit or push was performed during the original implementation stage; the later authorized commit and delivery are documented separately above.

Build-resource note: the first native attempt was superseded to constrain architectures; a later attempt hit disk exhaustion. Final build passed after removing only this task’s generated incremental/test caches and using one build job. Unrelated caches/source/processes were preserved.

UI-test maintenance: initial selectors assumed separate accessibility text for native labeled values and eagerly materialized off-screen List rows. These were corrected to use actual native accessibility labels and scroll to lazy rows. A later largest-text run overshot both stacked actions with full-screen flings; its screen recording confirmed the controls were present. The test now uses bounded short drags. Full device accessibility acceptance is not inferred from these checks.

## Native screenshots

These are actual screenshots from the isolated synthetic Simulator, separate from the HTML proposal images:

[Screenshot gallery](native-preview.html) · [Machine-readable evidence and source hashes](native-verification.json).

- [Waiting and list actions, light](screenshots/native-waiting-light.png)
- [Waiting and list actions, dark](screenshots/native-waiting-dark.png)
- [History with one options menu](screenshots/native-history.png)
- [Confirmed history detail](screenshots/native-history-detail.png)
- [Unconfirmed history detail](screenshots/native-history-unconfirmed.png)
- [Sent answer awaiting confirmation](screenshots/native-sent-unconfirmed.png)
- [Largest accessibility text](screenshots/native-accessibility-text.png)

Waiting was visually checked in light and dark appearance, including a fresh dark launch. The gallery was previewed at 728 px and 360 px with no console errors. Source hashes match the tested state. The final clean native build is recorded in `/tmp/apassy-requests-native-closed-build.log`.
