# Requests A: internal TestFlight delivery

**Available to Rafał: Apassy 0.5.5 (29873206).** App Store Connect readback on
2026-10-19 at 07:00:59 UTC (09:00:59 CEST) confirmed `VALID`,
`IN_BETA_TESTING`, the build's membership in the internal **Apassy** group,
and Rafał's existing membership in that group. No invitation was needed or sent.
The existing tester state is `INSTALLED`; this does **not** establish that Rafał
has installed this new build on his iPhone.

The user explicitly selected a new internal TestFlight build at 0.5.5. This is
not a new coordinated six-component release. Marketing versions remain 0.5.5;
the public website, macOS, Linux, extension and relay were not republished.

## Source and artifact

| Item | Verified value |
| --- | --- |
| Branch | `product/ios-requests` |
| Source commit embedded in app and AutoFill | `bc08deadcef6fbf7ee427ee3f9533028fc8ac5c0` |
| Marketing version / build | `0.5.5` / `29873206` |
| App Store Connect app | `6820438429` / `com.wydrox.apassy.companion` |
| Build ID and upload delivery UUID | `f74a714f-3e79-4adb-9b51-8ebe426583db` |
| IPA | `target/ios/export/ApassyCompanion.ipa`, 16,116,418 bytes |
| SHA-256 | `6b4b41d09b2491f2fd79e27c86e62c9c4eae1c363ea96a7888dd583ed5581091` |
| Internal group | `Apassy`, `6b2b208b-6786-4736-857d-93a769afa99f` |
| What to Test | `en-GB`, saved and independently read back |

The archive was built from a clean source commit with the Release Rust core,
Xcode 27 and the existing iOS 26 deployment target. The exported app and AutoFill
extension passed strict signature verification and matched the source commit,
version, build, team, bundle IDs, App Groups and shared Keychain access group.
Both use Apple Distribution/App Store profiles, with debugging disabled. The
main app has the production APNs entitlement. These checks establish signing and
configuration, not delivery of a push notification or successful Face ID use.

Apple's validation completed without errors. The exact verified IPA was uploaded
once; upload returned success and the delivery UUID above. Subsequent authenticated
readback confirmed processing, internal distribution, tester access and test notes.
The external beta state remains `READY_FOR_BETA_SUBMISSION`; no external beta or
App Store submission was performed.

## Checks completed on 2026-10-19

| Command / check | Result |
| --- | --- |
| `swift test --package-path ios/ApassyCompanion/ModelTests` | 414 tests in 36 suites passed |
| `swift test --package-path ios/ApassyVaultKit --filter RequestHistoryTests` | 5 passed |
| `cargo --config /tmp/apassy-flow-ux-build.toml test --offline --locked -p apassy-core --lib request_history` | 5 passed |
| `cargo --config /tmp/apassy-flow-ux-build.toml test --offline --locked -p apassy-core --test questions_flow` | 12 passed |
| `cargo --config /tmp/apassy-flow-ux-build.toml clippy --offline --locked -p apassy-core --lib -- -D warnings` | Passed |
| `cargo fmt --all -- --check` | Passed |
| `python3.12 scripts/check-release-versions.py --relay-checkout /Users/rafalw/Dev/apassy-relay-release-055 --require-relay` | All six source versions match 0.5.5 |
| Release-version checker unit tests | 8 passed |
| Independent SwiftUI/security source review | No P0/P1 findings in reviewed delta; 37 source hashes match the implementation evidence |
| Signed device Release archive/export, IPA inspection and Apple validation | Passed |
| Git whitespace checks | Passed |

Builds used the shared Cargo target, two jobs and a task-local strip workaround
for Xcode 27. No original dirty source checkout was modified. Signing used the
existing installed distribution identity; no real vault data was accessed.

The seven native Simulator scenarios and screenshots in the
[implementation report](implementation-report.md) remain earlier implementation
evidence. They were not repeated as physical-device tests in this delivery.

## Device acceptance still required

Install **0.5.5 (29873206)** from TestFlight, then follow the
[physical-device checklist](device-test-plan.md) using synthetic credentials in a
test vault. In particular, verify real **Face ID** approval, cancellation and
interrupted authentication, and **APNs** foreground/background/cold launch,
generic payloads and routing back to Waiting. Live relay uncertainty, history
behavior and physical VoiceOver/largest-text flows also need device acceptance.

No physical-device installation, Face ID or APNs acceptance is claimed.

[Machine-readable delivery evidence](testflight-delivery-2026-10-19.json).
