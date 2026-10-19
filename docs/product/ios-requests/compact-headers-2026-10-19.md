# Compact iOS headers and vault selector

Date: 2026-10-19. Branch: `product/ios-requests`. Parent: `f5b9efc`.

The user approved removing redundant Requests/Search headings, naming the active
vault with a selector, and using small contextual titles on child screens.
Three scoped agents implemented Requests, Vault/Search and child titles, using
`swiftui-pro` and `apple-design`. An independent source review found no P0/P1/P2
issues. Main integrated and ran the native checks.

## Behavior

- Requests: compact native action bar, stationary Waiting / History picker, shared
  list. Settings, Devices and History options remain available; approval logic is
  unchanged.
- Vault: the active vault name opens a native menu in the compact navigation bar,
  with native toolbar sizing. The selected vault is marked and disabled. Other choices call the existing
  `VaultModel.select`, which locks and clears credential state before selection;
  the normal unlock screen handles authentication. Add another vault enters the
  existing setup flow.
- Search: native search field without a repeated heading or introductory empty
  state. No-results feedback, results and standard detail navigation remain.
- Folders, favorites, categories, details, settings, licenses, Agent Access and
  forms use inline contextual titles. Native Back, Cancel and Done are preserved.
  Credential details keep a compact service/type/risk summary without repeating
  the credential name as a large hero.

The policy is recorded in `ios/README.md`. No versions, deployment/toolchain
settings, core, models, wire contracts or authentication implementations changed.

## Verification

The unsigned native `build-for-testing` passed. Eleven distinct UI scenarios passed
across scoped runs, with two additional successful dark-mode checks. Coverage includes
Waiting/History geometry, request actions/review/history search, large text, native
vault selection through lock/unlock, folder/form navigation, search isolation and
returning from details with the query preserved. Updated details contain one title.

Earlier broad runs include the selector failures below; those runs are not reported
as entirely passing. The final selector run passed 2/2, and the final dark run passed
2/2. Requests and unchanged navigation checks retain their scoped passing evidence.

The Waiting/History top 300 pixels are identical in each theme. Main and an independent
agent inspected the native originals. The gallery passed browser checks at 728 and
360 pixels without overflow or console errors. Evidence contains 31 source hashes,
18 native screenshots, commands, individual results and known limitations:

- [Native screenshot gallery](compact-headers-preview.html)
- [Machine-readable verification](compact-headers-verification-2026-10-19.json)

Only synthetic in-memory preview data was used, on a dedicated iPhone 17e iOS 27
Simulator. The 13 recorded core/VaultKit source hashes still match the earlier build;
Rust/model suites were not rerun for these UI-only edits. This is not physical-device
or production acceptance. The task simulator was shut down/deleted and the preserved
device XCFramework restored. No real vault, Keychain content or installed app changed.

The first build hit disk exhaustion. Only generated staging/diagnostics from
superseded failed Requests tests were removed after checking their failure logs;
final results, source, screenshots and signed archives/IPA were retained. The
subsequent native build passed. Initial UI checks exposed identifier propagation
from an unnecessary root accessibility identifier; it was removed while preserving
the established picker identifier, and affected checks were rerun.

### Native selector sizing

The initial title menu reported only text bounds. A native `Menu` in the principal
position provides an identifiable toolbar control. On the tested iOS 27 runtime,
its native host is 36 points high. Probes 21 points above/below its center did not
open it. Explicit 44-point label sizing, plain styling, ideal sizing and a layout
wrapper did not expand that host; those ineffective overrides were removed.

The final label fills the 36-point native host and checks the actual
control edges and Apple's 28-point minimum, rather than claiming a 44-point target.
Apple distinguishes a 44-point default from a 28-point minimum for iOS controls
in its [Accessibility guidance](https://developer.apple.com/design/human-interface-guidelines/accessibility#Mobility),
verified against its published Markdown on 2026-10-19. The larger preferred target
was not achieved in this title host; physical-device ease of targeting remains
a device check. This is a deliberate acceptance of the system control, not a
passing result for the earlier stricter probes.

## Distribution

These headers are included in internal TestFlight **0.5.5 (29873951)**, from commit
`0c917d1`, confirmed `VALID` / `IN_BETA_TESTING` for Rafał's Apassy group. The earlier
build 29873206 does not contain this change. The history key-rotation gate was
addressed and tested in the [forward-update report](history-compatibility-fix-2026-10-19.md).
Face ID, APNs, physical VoiceOver use and the actual upgrade path require separate
device acceptance; TestFlight availability is not an on-device result.
