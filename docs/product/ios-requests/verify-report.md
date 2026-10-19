# Historical HTML verification

This report records the prototype stage. The later native implementation and checks are in [implementation-report.md](implementation-report.md). Older “not implemented” statements below describe that stage, not the current branch.

# Requests prototype verification

Date: 2026-10-17. Source baseline: `46e088dc69cc0d0d77dfad4849984867bd136d44`.
Scope: three HTML proposals and documentation. No SwiftUI source, build, release, account or real vault changes.

## Evidence boundaries

| Evidence | Completed | What it proves |
| --- | --- | --- |
| Source audit | DecisionsView, QuestionsModel, relay cache, companion activity and authorization models | Current source structure and data limitations; not observed device behavior |
| Independent agents | Source/flow specialist and UX critique specialist | Separate review of hierarchy, journey and prototype semantics |
| Interactive browser | T3 preview against local static files; 18 checks passed | Synthetic prototype behavior only |
| Layout matrix | 3 concepts × 15 state presets × 2 text sizes × 4 widths = 360 variants | No horizontal page/checked-content overflow; tested in-app controls at least 44×44 CSS pixels |
| Visual review | A waiting/history, B journal, C vault inboxes; light and forced dark CSS previews | Proposal appearance, not native rendering |
| Contrast | 14 representative light/dark text pairs ≥4.5:1; minimum 4.76:1 | Listed HTML color pairs only; not a complete accessibility audit |
| Native / device / customer | Not run | No claim about Face ID, production transport, push, persistent journal, VoiceOver or customer outcomes |

Structured results: [verification-results.json](verification-results.json). Viewport widths: 320, 390, 728 and 1440 CSS pixels. “Larger text” enlarges row/fact/body text; it does not emulate all Dynamic Type categories or browser zoom. The 360-state grid uses the 15 selectable states; detail and authentication were covered by interaction checks, not every grid permutation.

## Interaction checks

1. A prior request's delayed confirmation cannot replace another request's authentication screen.
2. The original request still receives its correct journal confirmation.
3. Broader-permission copy derives from the selected request's action/project/environment.
4–6. All three concepts hide locked Work journal records.
7. Locked vault is never described as an empty queue.
8. Global badge retains the other known actionable request when a vault is selected.
9. Searching an empty journal produces a no-results state without an exception.
10. Combined history includes both accessible vaults.
11. Mac-only access request remains deny-only.
12. Its denial records the access-request identity and preserves ordinary pending requests.
13. An unconfirmed answer remains discoverable after Done.
14. Offline detail disables a new grant.
15. Expired unanswered request leaves Waiting and gains an expired journal record.
16. Review new request displays the changed synthetic snapshot.
17. Reset cancels outstanding simulated callbacks.
18. No uncaught JavaScript errors during the interaction run.

Tests used DOM button clicks and waited for actual demo timers in T3's browser. They did not call native authentication or Apassy APIs. No external scripts, services or storage are used by the HTML.

## Review findings resolved

The independent critique found seven issues: hardcoded broader scope, locked-vault history leakage, callbacks tied to mutable selection, wrong identity for access denial, false empty claims for unknown scopes, empty-search failure, and a vault-local count used as the app badge. All were corrected. A follow-up found the visible receipt still needed a request-and-answer identity guard; that was corrected and tested with the exact p1 → Back → p2 authentication race.

Layout measurement caught a Retry target narrower than 44px; the minimum button width was corrected. Expired and changed presets were also corrected to remove the old actionable row and show an updated snapshot respectively.

## Screenshots and rendering

Saved viewport screenshots: [A waiting](screenshots/a-waiting.png), [A history](screenshots/a-history.png), [A unconfirmed](screenshots/a-unconfirmed.png), [A empty](screenshots/a-empty.png), [A offline](screenshots/a-offline.png), [B journal](screenshots/b-journal.png), [C vault inboxes](screenshots/c-vault-inboxes.png). These are viewport captures, not exhaustive full-page captures of every state.

The original `html_preview` at 728px reported 1014px content height and no console errors. Its dark appearance injects thread colors without changing the OS media query. For a diagnostic dark preview, the existing dark CSS block was forced on and the screenshot background matched the injected thread background. The delivered files retain OS-selected dark styling and a transparent outer background. This is not native dark-mode acceptance.

## Remaining decisions and checks

- A with list actions is now accepted as the wireframe. Native Liquid Glass appearance and behavior still require implementation and verification.
- Resolve journal retention, backup/deletion and key lifecycle. A 30-day default is only an open proposal.
- First history iteration covers requests seen on this iPhone. Complete cross-device history requires an API/correlation contract.
- Preserve all current server-offered answer choices in production. The prototype only demonstrates once, deny and broader-scope review.
- Validate VoiceOver, Dynamic Type, increased contrast, Reduce Motion/Transparency, real safe areas, push routing and authentication on native builds with synthetic fixtures.
- Run neutral customer tasks for scope understanding, refusal, unconfirmed recovery and history retrieval. The proposed scorecard and emotional journey are design judgments, not measured results.

The IA direction is accepted. The requested proposal and mockups are complete; no production implementation or release is claimed. Native acceptance must include the Liquid Glass requirements recorded in visual-direction.md.

## List-action revision verification

The user requested actions from the list. A separate read-only specialist reviewed the proposal; its five requirements (visible scope, separate targets, accessible refusal, stable row position and immutable identity) were incorporated. Native approval policies are unchanged because no app code was edited.

19 additional T3 browser checks passed: eligible actions; production Review/Deny; no nested buttons; list authentication before submission; cancellation/focus; inline sending; sent versus confirmed; matching inline receipt; no repeated grant after confirmation; explicit receipt dismissal; denial without authentication; next-row position through sending/confirmation; correct denial identity; offline action availability; changed snapshot rejection after authentication; freshness loss rejection; Review navigation; read-only History; no JavaScript errors.

Re-ran the 360 layout variants after adding controls: no horizontal overflow or tested control below 44×44 CSS pixels. The new 728px light preview is 1068px tall with no console errors. Earlier screenshots are retained as original-version evidence except refreshed A waiting and A offline; `a-list-confirmed.png` captures the new inline receipt. New behavior is synthetic browser evidence only.
