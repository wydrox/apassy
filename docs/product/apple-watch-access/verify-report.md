# Verify report: Apple Watch access requests

Date: 2026-11-03. Build: `feat/apple-watch-access`, the watchOS 27 Simulator (Apple Watch Series 12, 46 mm). Synthetic
data only (`-ApassyWatchPreview <state>`; the answer states also with `-ApassyWatchScrollToEnd YES`).
Screenshots: [screenshots/](screenshots/). **Simulator only**: nothing was checked on a physical
Apple Watch (see "Pending").

## Spec conformance (flow-spec.md)

| Screen | Result |
| --- | --- |
| S1 Connect, failed reason, Removed | Pass: copy as specified, a status label with no spinner, and the reassurance line |
| S3 Check the words | Pass: 2×3 numbered words, one column at accessibility sizes, Cancel in the toolbar |
| S5 Connected | Pass: a green checkmark, the scope sentence, prominent Done. When the Mac wrote no answer key, the "Update Apassy on your Mac" line takes the place of the Allow line (fixed in review) |
| A1 Requests, empty | Pass: agent, credential, Mac, "Production" as text, a static "Until" time, and `ContentUnavailableView` |
| A2 Request | Pass after fix: facts first. Allow once (prominent) and Deny (destructive, the same height) come after the facts, with the one-attempt footnote and Exact identities |
| A2 Deny only | Pass: the reason ("does not specify the action or the hosts") and Deny only |
| A2 Sent / Not confirmed / Expired | Pass: the buttons are disabled, not removed (Always On HIG) |
| A4 Allowed / Denied | Pass: the outcome, "Answered on This watch", and Done |
| W This watch | Pass: the vault, the Macs that can ask, the Allow rule, and Remove with a confirmation |

## Findings and fixes (Stage 5 → owning stage)

| # | Finding | Source | Severity | Stage | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Every open request showed **Expired** with both buttons off: `TimelineView(.explicit)` passed the future expiry as the first date | Simulator screenshot (`detail-end`), swiftui-pro review | P0 | 4 | Fixed: the timeline only triggers a redraw; the phase uses the real time; a test was added |
| 2 | Text touched the screen edges (no watchOS margins) | apple-design review of the screenshots | P1 | 3 | Fixed: `.scenePadding(.horizontal)` |
| 3 | Cancel during "Connecting…" left a live join | swiftui-pro review | P1 | 4 | Fixed: an in-flight start finishes before the cancel; test |
| 4 | No reopen after background → inactive → active (a false empty list) | swiftui-pro review | P1 | 4 | Fixed: `reopenWhenActive`, a synchronous background clear; test |
| 5 | The transport reported `connect` after bytes were sent | swiftui-pro review | P1 | 4 | Fixed |
| 6 | The iPhone mixed `NavigationLink(destination:)` into a value-based stack | swiftui-pro review | P1 | 4 | Fixed: `Page.addAppleWatch` |
| 7 | U+2028 and U+2029 in agent text were not escaped (watch and iPhone) | swiftui-pro review | P2 | 4 | Fixed in one shared function; tests |
| 8 | Status lines were not redacted in Always On | swiftui-pro review | P2 | 4 | Fixed: `.privacySensitive()` |
| 9 | A Deny on another request was ignored during a wrist check | swiftui-pro review | P2 | 4 | Fixed; test |
| 10 | `LAContext` and keychain calls ran during view updates; extra long polls started on wrist flicks; the row expiry lagged; the body limit was larger than the core's | swiftui-pro review | P2 | 4 | Fixed |
| 11 | "Apple Watch (Apple Watch)" on the Mac for a generic watch name | swiftui-pro review | P2 | 4 | Fixed: `device_link::watch_label`; test |

## Accessibility

- **Dynamic Type at Accessibility XXXL** (launch argument `-UIPreferredContentSizeCategoryName`; the watchOS
  runtime does not support `simctl ui content_size`): the text wraps, the words fall back to one
  column, and nothing is truncated.
- **Never color alone:** "Production" is a text label, and the outcomes have text and a symbol.
- **Buttons:** full width, the system height.
- **No custom motion.** One haptic, the same for both outcomes.
- **Not run on the Simulator:** a VoiceOver walkthrough and Always On redaction. Both are listed for the
  physical acceptance.

## Ethics re-check (built UI)

- No preselected answer, no countdown, no notification action.
- Deny is never behind authentication and is as large as Allow once.
- The success feedback is the same for Allowed and Denied.
- The expiry is static, neutral text.

## Validation (top-level, `heavy-check`)

- **Swift:**
  - ApassyVaultKit: 127 + 46 tests;
  - ApassyCompanionKit: 174;
  - ModelTests: 427.
- **xcodebuild:**
  - ApassyWatch for watchOS Simulator and device (arm64 only);
  - ApassyCompanion for iOS Simulator and device (embeds `Watch/ApassyWatch.app`).

## Pending (physical Apple Watch)

1. The Secure Enclave key (`.privateKeyUsage` + `.userPresence`, `WhenPasscodeSetThisDeviceOnly`) signs
   with a context evaluated by `.deviceOwnerAuthenticationWithWristDetection`, with no second prompt.
2. A tap on the mirrored iPhone notification opens the watch app on Requests.
3. LTE or Wi‑Fi with the iPhone away: list, answer, settle.
4. Always On redaction and a VoiceOver walkthrough.
5. A real connection with a Mac on this branch (safety words, Touch ID, handoff).
