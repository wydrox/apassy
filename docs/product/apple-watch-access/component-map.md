# Component map: Apple Watch access requests

Status: implemented. This is the companion to [flow-spec.md](flow-spec.md). The master-product template is adapted to native watchOS
SwiftUI components: there is no shadcn or Tailwind registry for a watch app. Read with master-product,
apple-design and swiftui-pro.

## Navigation

| Spec element | Native component | Reason |
| --- | --- | --- |
| One stack, no tabs (IA) | `NavigationStack(path:)` with typed `WatchRoute` and `navigationDestination(for:)` | The HIG asks to "minimize the depth of hierarchy". The scene owns the path, and the background clears it, so a notification tap returns to Requests |
| Setup replaces the root | A root `switch` on the model's screen (connect / words / connected / requests) | No back stack into a finished setup |
| This watch (W) | A `.sheet` with its own `NavigationStack` (for the title), opened by a toolbar `Button("This watch", systemImage: "gearshape")` | Settings are secondary; the toolbar corner keeps them out of the content |
| Exact identities (L3) | `NavigationLink(value: WatchRoute.identities)` at the end of A2 | Progressive disclosure, after the answers |

## Screens

| Spec | Component | Notes |
| --- | --- | --- |
| S1 Connect, S3 Words, S5 Connected | `ScrollView` + `VStack(alignment: .leading)` + `.scenePadding(.horizontal)` | System margins of watchOS; the text wraps; no spinner, just a status label with an SF Symbol |
| S3 words | Two-column `Grid` of numbered words; one column at accessibility sizes | Chunking 2×3; VoiceOver reads "Word 1, amber" |
| A1 Requests | `List` of rows (`RequestRow`), `.privacySensitive()` | A row is one accessibility element. "Production" is text, not a color alone |
| A1 empty / A2 unavailable | `ContentUnavailableView` | A system empty state |
| A2 facts | `ScrollView` + `VStack`, `FactView` (caption + body), monospaced hosts, `Text(verbatim:)` of escaped agent text, `.privacySensitive()` | Nothing truncated: `.fixedSize(horizontal: false, vertical: true)` |
| A2 answers | `Button("Allow once")` `.borderedProminent` and `Button("Deny", role: .destructive)` `.bordered`, full width, the same height, separated | HIG buttons.md › watchOS: full-width buttons for primary actions, the same height in a vertical stack |
| A2/A4 status and result | `Text` lines plus `Label` with `checkmark.circle.fill` / `xmark.circle`, `.privacySensitive()` | The result takes the place of the buttons |
| Expiry | `TimelineView(.explicit(deadlines))` used as a redraw trigger only | No countdown; the buttons turn unavailable at the real expiry |
| Confirmed answer | `.sensoryFeedback(.success, trigger:)` | The same haptic for Allowed and Denied (ethics gate) |
| Remove this watch | `Button(role: .destructive)` + `.confirmationDialog` | The one irreversible local action gets a warning and a Cancel |
| iPhone S2 | `NavigationLink(value: Page.addAppleWatch)` in Settings › Devices → `AddAppleWatchView` with the existing `CodeScannerPanel` | Reuses the iPhone scanner; the link is held in memory for one send |

## Not a component: platform behavior used

- **`scenePhase`.** The background cancels the signing and clears the requests. When the app is active again it reopens.
- **Wrist down (Always On).** `.privacySensitive()` redacts the facts and the status lines.
- **WatchConnectivity.** `WCSession.sendMessage` from the iPhone, while the watch app is in the foreground.
