# Requests: consistent Waiting and History UI

Date: 2026-10-19. Branch: `product/ios-requests`. Parent commit: `badf2cf`.
This is the UI correction requested after the earlier implementation and beta delivery.
The cancelled native-UI worker was replaced with scoped implementation and independent
review agents using `swiftui-pro` and `apple-design`; the parent integrated and tested.

## Change

Both destinations now use shared native list, row-summary and disclosure components:
large Requests title, stationary segmented picker, inset grouped surfaces, 16-point
horizontal row insets, matching typography and spacing. System toolbars/navigation
provide Liquid Glass; content retains readable system backgrounds.

History search is available through its options menu in a native search sheet; filters
and per-vault clearing remain in that menu. Search/filter state survives switching
between Waiting and History. Active search retains the sheet's Done action. History
still groups entries by day and displays outcome/time; Waiting retains its current
request context, expiry and guarded actions. No approval, authentication or history
persistence behavior was changed.

History no longer labels a record Development merely because its production-approval
flag is false. That flag does not encode a reliable environment. The unsupported
label was removed from both its row and detail; current Waiting cards retain their
actual environment context.

## Verification

- Final unsigned native `build-for-testing`: passed, no build warnings/errors.
- Final selected native suite: **7 tests passed, 0 failed** (122.651 seconds):
  accessibility XXXL action reachability and 44-point targets; search retention;
  history filter/search/read-only detail/clear; guarded routine versus production
  actions; fixed title/picker geometry; locked-vault entry; no-connection entry.
- Light appearance: original-resolution native screenshots independently reviewed.
  Waiting and History use the same header and picker geometry, row typography and
  system surfaces. Waiting actions and History outcome metadata remain distinct.
- Dark appearance: the same native geometry test passed again (13.753 seconds);
  original screenshots visually checked in both destinations.
- `git diff --check`: passed.

Final build log: `/tmp/apassy-requests-uniform-ui-20261019/native-search-build.log`.
Final UI results: `/tmp/apassy-requests-uniform-ui-20261019/ui-final.xcresult`.
[Source hashes and test commands](uniform-ui-verification-2026-10-19.json).

Screenshots: [Waiting](screenshots/uniform-waiting-light-2026-10-19.png),
[History](screenshots/uniform-history-light-2026-10-19.png),
[largest text](screenshots/uniform-accessibility-2026-10-19.png),
[read-only detail](screenshots/uniform-history-detail-2026-10-19.png).
Dark screenshots: [Waiting](screenshots/uniform-waiting-dark-2026-10-19.png),
[History](screenshots/uniform-history-dark-2026-10-19.png).
Historical screenshot files and verification records were preserved.

The initial run found that native active search hid Done. The UI now explicitly uses
`searchPresentationToolbarBehavior(.avoidHidingContent)`; the final suite reruns the
search and navigation flows. This API supports the unchanged iOS 26 target.

Core and VaultKit were not rebuilt or modified: all 13 source hashes in the prior
native verification record still match. The existing matching Simulator static
library was repackaged for this UI build. This is UI evidence, not a new core pass.
A dedicated iPhone 17e Simulator on iOS 27 uses synthetic in-memory preview data only.
No real vault, Keychain content, connected phone or live request was accessed.
The dedicated Simulator was shut down and deleted after testing. The pre-existing
device XCFramework was restored; signed beta archives and IPAs were preserved.

## Distribution boundary

No build was uploaded or distributed for this correction. Shared versions remain
0.5.5. The previously published internal build 29873206 does not contain these UI
changes and remains subject to the [compatibility gate](compatibility-review-2026-10-19.md).
In particular, the reproduced question-key rotation failure is not fixed by this
presentation-only change. Physical Face ID, APNs and the actual upgrade path still
require device acceptance after the core gate is resolved.
