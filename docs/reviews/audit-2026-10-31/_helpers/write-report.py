from pathlib import Path
p=Path('/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31')
rows=[
('01-app-closed','App not running','P2','Recovery works, but a single sentence and Open Apassy sit above two much larger settings blocks; no visual state heading.'),
('02-locked','Vault locked','P2','Almost indistinguishable from app closed. No lock treatment, account context, or in-place refresh after unlock.'),
('03-no-vault','No vault open','P2','Correct instruction, weak hierarchy; settings dominate the recovery task.'),
('04-empty','No matches','P2','Leads with editing the built-in Website field instead of saving or creating a login. Jargon and no contextual illustration.'),
('05-one-match','One match','P2','Fill is an unlabeled account row; Update login is a separate outlined button, visually competing with the intended action.'),
('06-many-matches','Many matches','P2','Update buttons repeat between rows; no section label, count, filter, or account marks. Excess vertical scanning.'),
('07-long-labels','Long title and username','P2','Both identifying lines ellipsize without a visible disclosure or tooltip. Similar accounts become hard to distinguish.'),
('08-error','Native timeout','P2','Error is an isolated red sentence, without Retry or connection recovery. Site/settings remain visible without resolving the error.'),
('09-host-missing','Host missing / not connected','P2','Settings navigation plus Terminal command makes onboarding look technical. No single Connect action; two unrelated settings remain underneath.'),
('10-popup-waiting','Popup waiting','P2','Only a paragraph changes. Chosen account disappears; no status heading or Show Apassy action. Settings remain active during approval.'),
('11-popup-success','Popup filled','P2','Success uses the same visual treatment as waiting. No account recap or positive status treatment; settings still dominate.'),
('12-popup-cancelled','Popup cancelled','P2','Cancellation is styled as a red failure. Full action list returns but no concise contextual recovery.'),
('13-save-missing-password','Save without typed password','P2','Disabled Save plus red text; no shortcut back to the selected field. Error recovery depends on closing/reopening.'),
('14-save-form','Save form','P2','Title/Username labels are clear, but no heading and no explicit approval expectation adjacent to Save. Low-contrast input boundaries.'),
('15-generator-new-login','Generator / new login','P2','Creation intent and account metadata are mixed without heading. Approval requirement is missing from the explanatory hint; no password preview is correct.'),
('16-inline-menu','Inline matches','P2','Single-line title—username rows all have the same weight as Show all and Dismiss. Large explanatory preamble delays account scanning; no brand icon.'),
('17-inline-keyboard-focus','Inline keyboard focus','P3','Alt+Down enters the menu and focus is visible. Shortcut is undiscoverable; primary/secondary actions share one focus sequence.'),
('18-inline-waiting','Inline waiting','P2','Loses account/site identity; still displays Show all accounts, which is inert while busy. No Show Apassy action during approval.'),
('19-inline-success','Inline filled','P2','Success panel persists over page controls, including the submit area; no clear completion treatment or automatic unobtrusive collapse.'),
('20-inline-empty','Inline empty','P2','No Save/Create action. Website-field instruction plus Show all loop gives little useful recovery.'),
('21-inline-locked','Inline locked','P2','Open Apassy is available, but visually equal to Show all and Dismiss; state and recovery do not stand out.'),
('22-inline-failure','Inline timeout','P2','Failure looks like neutral body copy and offers Show all rather than a precise Retry/reconnect action.'),
('23-inline-cancel-choice','Inline pre-cancel account choice','P2','Same hierarchy defects as 16; retained as the starting step of the cancellation flow.'),
('24-inline-cancelled','Inline cancellation result','P2','Account selection vanishes and unrelated Show all remains. No account-specific Try again action.'),
('25-inline-long-label','Inline long title/username','P2','overflow-wrap:anywhere splits the undifferentiated title/username string into a paragraph; poor account recognition.'),
('26-inline-many','Inline 12 accounts','P2','Whole panel scrolls, pushing recovery/dismiss controls below the viewport; no count or sticky header/footer.'),
('27-inline-small-viewport','Inline 390×420','P2','55vh panel shows only a few rows; controls scroll away. Fixed 200px placement estimate does not measure actual panel height.'),
('28-github','GitHub live login','P2','Menu overlays the login form when suggestions are available; no field affordance. Closed shadow isolation preserves typography. No credentials entered.'),
('29-google','Google live username step','P1','Menu covers Forgot email, help content and part of Next. Its width/height and hierarchy compete with Google’s own card.'),
('30-vercel','Vercel live login','P1','Menu covers Continue with Email and multiple SSO methods. It is wider than the email field, with no compact field affordance.'),
('31-long-host','Long hostname fixture','P2','Header ellipsizes the distinguishing hostname suffix; body wraps it awkwardly. This is an explicit renderState fixture, not a navigated real domain.'),
('32-redesign','Proposed design study','Design','Seven paired light/dark studies; all 14 panels fit at 940px without horizontal overflow. Separates settings, account choice and approval. Prototype controls use synthetic metadata only.'),
('33-enabled-settings','Passkeys/suggestions enabled','P2','Enabled explanations still take two full blocks. Suggestions initial copy is generic despite enabled state; use a compact settings entry.'),
('34-update-confirm','Update confirmation','P2','Update and Back touch visually: inline controls lack a shared gap wrapper. Explanation has no heading; selected account is embedded in prose.'),
('35-unsupported-page','Unsupported / blank page','P2','Plain message treatment does not explain a useful next step. Capture uses toolbar action on about:blank.'),
('36-mac-reference','Mac app design reference','Reference','Existing app-v2 mockup captured in Helium for comparison: neutral surfaces, grouped details, account marks, compact native type, 6–12px radii. Dark capture is the same light-only reference.')]
intro='''# Apassy extension appearance and interaction audit

2026-10-31 · Product-design audit · Source `6759f32022e6435ecb60aaba7fdd5d04e4c83e36` · Extension 0.5.7

The extension has sound basic controls and explicit approval copy, but its hierarchy resembles a settings utility more than a focused password-manager surface. The most disruptive issue is the inline panel covering the site’s next action. The redesign prioritizes recognizable accounts, a compact settings entry and an explicit approval state.

## Scope and evidence

Fetched origin and reset `audit/extension-look` to origin/main as requested. No extension/product code edits, Rust builds, commits, pushes or PRs. Only audit artifacts were written under this directory, aside from the explicitly requested Git fetch/checkout metadata. The extension was loaded from the requested worktree, unchanged. Used only a new Helium process on CDP port 9342, with a disposable profile and a profile-local `com.wydrox.apassy` manifest pointing to the repository mock host. A deny manifest simulated missing-host state without falling back to the owner's host. No owner profile, running app or vault was accessed.

Small Node scripts use native WebSocket CDP; no browser automation library or Playwright tests were used. Fixture server imports `extension-tests/support/pages.mjs`; account data is synthetic. Real-site checks only focused empty fields. The scratch profile's optional host access was granted via its own extension permissions API (following profile-local developerPrivate host settings); production manifest was unchanged. Failed setup captures were replaced, not accepted as evidence.

Screenshots use prefers-color-scheme light/dark. Page captures set deviceScaleFactor 2. Actual toolbar popups reject CDP metrics overrides, so Helium was launched with `--force-device-scale-factor=2`; popup images are 680px wide for a 340 CSS px popup. Mock-host delays simulate approval; this proves browser presentation, not native Touch ID, production host correctness or passkey cryptography. The contract allows owner passphrase fallback; every fill/save/create/update must still require an owner check. No vault password was displayed or inspected.

Read `docs/adr/0021-browser-extension.md`, `docs/operations/browser.md`, `extension/README.md`, `docs/design/app-v2-mockup.html`, current extension sources, fixture wiring, and `src/desktop/ui/kit.rs`. Store assets in `design/store/chrome-web-store/` were inventoried; they are marketing material, not evidence of current behavior. Product rules take precedence where older ADR descriptions lag PR #23.

## State inventory

1. Connection: asking/loading, host missing, app not running, no vault, locked vault, unsupported/no page, connection error. Captured representative stable states; transient loading text is source-confirmed, not a separately accepted capture.
2. Popup accounts: zero, one, many, long labels; focused row; fill waiting, success, cancellation/error; per-account update confirmation. Source also supports one-time-code action when `hasTotp` is true (not supplied by this basic mock host; not captured).
3. Popup save: page read, title/username form, missing page password, validation, waiting, success, duplicate/error. Form, missing password and generic fill waiting/results captured; save-specific pending/result variants use different copy and were not all executed. No post-submit capture exists.
4. Popup generator/new login: one combined form, length 12–64 and symbols, metadata validation, no new-password field, owner waiting, saved-and-filled, saved-but-not-filled, failure. Form captured; full create outcome matrix remains source-reviewed only. There is no local password generator or password preview.
5. Search: no popup search UI. Inline filtering follows typed username prefix, plus Show all accounts. No global vault search is exposed.
6. Inline: automatic focus menu; fetching, matches, empty, locked/app recovery, timeout, chosen-account approval waiting, success and cancellation. Long-label, 12-account and small-viewport stress captures included. No field icon currently exists.
7. Save/update banner after submit: absent from shipped extension; update is a popup action only. The redesign banner is a new feature proposal, not a captured current state.
8. Passkeys: popup off/on settings and permission request; no extension-drawn passkey chooser/waiting/error UI. `passkey-page.js`/`passkey-bridge.js` relay requests; owner prompts live in the Mac app, unsupported/preflight failures can fall back to browser UI, later failures return to the site. Native prompt/fallback screens were not captured: the basic mock host does not provide real passkeys, and the owner app/profile was explicitly excluded. Passkey settings on/off are captured; native acceptance remains unverified.
9. Options page: none in the manifest or tree. Settings are currently two popup footer sections.

## Screenshot findings

P1 = high-impact obstruction of a login task; P2 = material usability/visual defect; P3 = polish/discoverability. These are design severities, not a security vulnerability rating. Every link below points to an original current-run screenshot. Each row applies to both themes except the explicitly light-only reference. Files are in `ext-look/`; theme pairs are linked separately.

| Step/state | Severity | Concrete finding | Light | Dark |
|---|---|---|---|---|
'''
for key,state,severity,note in rows:
 intro+=f'| {key[:2]} · {state} | {severity} | {note} | [PNG](ext-look/{key}-light.png) | [PNG](ext-look/{key}-dark.png) |\n'
intro+='''
## Accessibility, keyboard, and page integration

Sampled actual CSS colors, using WCAG relative luminance: muted text `#5b6670` on white **5.87:1**; dark muted `#9aa5b0` on `#141c23` **6.87:1**; white primary label on `#0061d6` **5.71:1**; error text light **5.80:1**, dark **6.83:1**. These text pairs pass AA normal-text contrast. Input/secondary borders `#e3e7eb` on white **1.24:1**, dark `#2b3640` on `#141c23` **1.40:1**: below 3:1 where the boundary is needed to identify the control (notably text fields). Do not call the whole UI WCAG compliant on this evidence. Separators do not independently need 3:1.

Popup focus-visible rings are explicit and visible; list Up/Down traversal is implemented. Inline Alt+Down enters the first button and focus was captured. Its Arrow/Home/End/Escape handlers are source-confirmed; complete keyboard traversal and screen-reader behavior were not separately qualified. Enter-only CDP dispatch without native key codes did not reliably activate a row; accepted fill captures use trusted CDP mouse events into the closed shadow tree. This is an automation limitation, not evidence of a broken Enter handler. No screen-reader, 200% text zoom or forced-colors acceptance run was performed. Popup success removes the focused account without an obvious next focus destination. Save/generator forms have labels; validation uses a general message rather than field-linked errors.

Closed shadow root protects internal typography/buttons against ordinary site selectors. The document-level host, viewport geometry and stacking still need protection: `z-index:2147483647` cannot outrank top-layer dialogs, and a page can still style/remove its host. Positioning clamps using an assumed 200px height instead of actual menu bounds, never flips based on measured space, and assumes a 348px horizontal envelope. This is a source-confirmed geometry risk; the small-viewport capture confirms internal scrolling, not every possible clipping failure. Transforms on document ancestors, native autofill collisions, top-layer dialogs, and hostile host CSS were not exhaustively tested.

Google and Vercel screenshots demonstrate working isolated rendering and concrete overlap, not authenticated compatibility. GitHub was loaded and refocused after content registration; no real credentials were typed or submitted on any external site. Capture details and DOM summaries are local artifacts, not claims about all future versions of these sites.

## Redesign specification

**Layout.** Use a 360px popup with a stable compact header, current site, 16px content inset, 58px account rows, one actions row and a 40px connection/settings footer. Keep settings out of every task body. Search only the metadata of accounts already matched to the current origin; label it “Find an account for this site.” No cross-origin account fill. Keep the list scrollable independently from its header/footer. Empty and locked views get a state title, one primary recovery action and one concise supporting sentence.

**Tokens.** Follow Mac neutral surfaces and system type: `-apple-system, BlinkMacSystemFont, system-ui`; base 13/1.45, metadata 12, section labels 11 semibold, state titles 17–18. Spacing 4/8/12/16/24. Controls radius 7–8, panels 12. Light canvas `#f6f6f7`, surface white, label `#1d1d1f`, secondary `#63636b`; dark canvas `#19191b`, surface `#242426`, text `#f5f5f7`, secondary `#b5b5bd`. Blue action `#0066d6` light; dark `#80b8ff` with dark label. Interactive borders `#85858e`, distinct from decorative separators. Focus outline 2px with 3px offset. No remote fonts/favicon fetches. Keep existing Apassy icon assets; site marks can be local initials with stable neutral tiles. Avoid emoji for security/status indicators. Current icon is legible at 20px; lack of consistent account marks is the larger issue.

**Components.** Shared account row: local mark, title and username on separate lines, explicit Fill affordance, secondary update action in a detail/review view. Long names use two-line constrained metadata or a deliberate disclosure; expose the full hostname and username in an accessible expanded view. Shared state panel, field, action group, connection indicator and notice styles. Inline menu 320–360px, account section scrolls with fixed controls, anchored to the active field; an accessible 24px field button is a new addition, placed without covering page reveal/validation controls. Retain Alt+Down/Escape and document them subtly. Use consistent semantics and return focus to the invoking field. A menu should dismiss outside and after success without stealing site focus.

**States and copy.** “Your vault is locked” / “Open Apassy”; “No logins for github.com” / “Save this login”; “Check Touch ID on your Mac” with site, chosen account, passphrase fallback, “Nothing has been filled yet” and “Show Apassy.” Do not invent a cancellation API: only add Cancel after end-to-end request cancellation is implemented; until then dismissing a panel must not imply cancellation. Success: “Login filled. Continue on this page.” Cancellation is neutral, failure uses a specific recovery and does not automatically retry. Generator says “Approve on your Mac. Apassy saves the password before filling this page.” Never render, copy, generate, or prefill a vault password in a popup or page before approval. No preview password exists in this mockup.

**Save/update offer.** New proposal after an observed submit: site and username, “Save this login in Apassy?” / Not now / Save login. Existing matching username changes offer to “Update this login?” with explicit chosen item. Both require owner approval. A banner must not assert sign-in succeeded from submit alone. Review/revalidate document, origin, selected form and typed secret immediately before the save request; navigation and uncertainty must fail closed. This needs security/product review because current code has no after-submit capture lifecycle. Do not persist a pending plaintext password in page DOM or browser storage.

**Motion.** 100–120ms hover/focus and optional opacity transition only; honor reduced motion. No pulsing approval button or fake progress percentage. Keep state region dimensions stable during async work and announce only meaningful changes via a polite status region.

## Mockup and verification

[Open the self-contained HTML study](extension-redesign-mockup.html). Seven rows each show light and dark: popup matches, empty, locked, generator/new login, inline menu on a sample login, proposed save offer and Touch ID waiting. [Full Helium capture](ext-look/32-redesign-light.png). The file has no remote dependencies or passwords, and embeds the existing 32px icon. CSP allows its single script by hash; no inline event handlers or eval. A production MV3 page must move this behavior into packaged external JS under its existing `script-src 'self'` policy. The study is a design board, not production extension code; the inline example is not injected into a real site and production implementation must preserve the closed shadow root.

Verified in Helium: 14 panels, no horizontal panel overflow at 940px; local account filtering reduces two rows to one for Work; Fill/Save/Open/Generate show explicit demo notices; generator uses native length validation without generating a password; dismiss and field-button reopening are wired. Actual Mac integration is intentionally absent. Full-page capture inspected for spacing, clipping, paired theme treatment and hierarchy. Light/dark emulation produces the same board because each column owns its theme. Narrow viewports reflow the board's spacing; 360px production popup size still needs extension acceptance.

## Implementation notes and risks

| File | Proposed work / reuse |
|---|---|
| `extension/popup.html` | Keep packaged assets/CSP; structured status/header/footer and a compact settings route within popup. No options page required. |
| `extension/popup.css` | Replace duplicated visual hierarchy with shared tokens, interactive-border contrast, fixed action/footer layout, bounded account scrolling and state panels. |
| `extension/popup.js` | Reuse metadata-only replies, view-generation guard, busy guard, clampLength, form values and Escape recovery. Add local match filter, account context during pending, explicit focus restoration and field-linked validation. Separate update review from primary fill. |
| `extension/login-suggestions.js` | Preserve closed shadow and trusted account choice; replace text-only rows, add local icon, measured flip/shift positioning, bounded account scroll, status variants and dismissal rules. Reset host-critical styles carefully; do not treat shadow DOM as a security boundary. |
| `extension/login-target.js` | Reuse form/field capture and document-bound token; field icon must follow eligible fields and observe geometry/removal without altering their values or ownership. |
| `extension/login-worker.js` | Preserve origin/document checks, feature generation, user-choice binding and stale-target refusal. New save-offer lifecycle needs a separate bounded design and origin revalidation, not generic form scraping. |
| `extension/background.js`, `fill.js` | Reuse native messaging, owner checks, ephemeral handling and fill result shapes. A visual redesign should not weaken approved flow or cache secrets. Add cancellation only if protocol support is real. |
| `extension/passkey-bridge.js`, `passkey-page.js` | Preserve strict passkey routing and fallback. No passkey UI rewrite required by this proposal. Native app owner prompts remain outside extension code. |
| `extension/manifest.json`, `icons/` | Existing MV3 CSP and packaged icons are sufficient; no framework, bundler, remote font or new broad required host permission. |
| `extension-tests/` | Later implementation acceptance should cover geometry, focus restoration, long metadata, owner rejection/timeout/navigation, and metadata-only UI. This audit ran no Playwright. |

Risks: duplicate or misclassified post-submit offers; orphaned approval after a popup closes; navigation while awaiting owner approval; accidental metadata/secret logging; icon collision with site controls; menus above/below modal top layers; list filtering hiding the only relevant account; browser permission prompt closing popup; 50-account performance and localization. Keep security invariants independently tested. No live native owner check, cryptographic passkey qualification or authenticated real-site login is claimed here.

## Completion boundary

This is a broad visual audit with the unexecuted subvariants explicitly recorded in the inventory, not exhaustive native/end-to-end acceptance of every protocol outcome. No nonexistent UI was fabricated as current evidence. The redesign is reviewable in one HTML file; implementing it and native passkey prompt review remain separate work.
'''
(p/'extension-look.md').write_text(intro)
print('wrote',p/'extension-look.md')
