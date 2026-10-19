> Implementation update: A is implemented on `product/ios-requests`. This document preserves the design mapping; current native evidence and limitations are in [implementation-report.md](implementation-report.md).

# Component map: iOS Requests

Status: **A with list actions accepted as wireframe · native Liquid Glass required**. Companion to [flow-spec.md](flow-spec.md).
Target: existing native SwiftUI app; HTML is a synthetic comparison artifact. No dependencies or app changes.
The master-product template is adapted to native Apple components. shadcn/Tailwind registry installation is not applicable.
Read skills: master-product, uxled-psychology, swiftui-pro and apple-design. No native build or runtime verification was performed.

## 1. Navigation and IA

| Spec element | Native component / behavior | Reason and boundary |
| --- | --- | --- |
| Existing Vault / Requests / Search destinations | Existing `TabView` and `Tab` selection | Stable app navigation, badge counts known actionable queue rows only. |
| A: Waiting / History | `Picker("View", selection:)` with `.segmented` above `List` | Two stable destinations; Recognition Over Recall. Retain each view's state. |
| B: one journal | `List` with Needs your answer / Today sections | Chunk active tasks first; See all History opens full history. |
| C: vault inboxes | `List` + `NavigationLink(value:)` to vault, then segmented picker | Visibility boundaries explicit; show Locked/Unavailable instead of false zero. |
| Request and history detail | `NavigationStack(path:)`, typed routes, one `navigationDestination(for:)` per type | Stable request identity; no conflicting destination-style links. |
| Combined history | Route with explicit scope `.allAccessibleVaults` | Avoid the prototype's display string “All vaults” as a data filter sentinel. |
| Settings / devices | `ToolbarItem`, labeled `Button` or `Menu` | Setup discoverable without persistent daily-screen paragraphs. |
| Connect / passphrase | Existing native sheets and pairing flows | Preserve relay and Wi-Fi connection semantics, safety words and cancellation. |
| Generic push routing | Scene-owned tab/path state, RootModel intent → refreshed Waiting | Never deep-link an unidentified notification to a guessed request. |

Implementation reference: `DecisionsView.swift:50–115` already uses typed paths, NavigationStack, sheets and generic-push list routing.
Keep navigation owned by the scene; shared data models own request state, not coupled window selection.

## 2. Waiting list

| Spec element | Native composition / properties | Behavior |
| --- | --- | --- |
| Queue | `List` / `Section` / `ForEach` with stable source-qualified IDs | Existing conservative relay/local dedupe; no duplicate row on refresh. |
| Row | `NavigationLink(value:)` + `Label`, semantic `Text` styles | Credential first; agent/project next; vault context when relevant. |
| Production | `Label("Production", systemImage: …)` with semantic warning tint | Text/symbol plus color; no red-dot-only meaning. |
| Real deadline | Existing `TimelineView`, monospaced digits | VoiceOver summary avoids disruptive every-second announcements. |
| Count | Existing tab `.badge` from known active actionable data | Locked/unavailable inventory is unknown; do not imply completeness. |
| Refresh | `.refreshable` plus visible Retry on failure | Per-source freshness; do not clear good data after an unrelated vault failure. |
| Loading | `ProgressView("Loading requests…")` | Native substitute for HTML skeleton; distinguish first load from background refresh. |
| Empty | `ContentUnavailableView` with “No requests waiting”, optional View History action | One clear ending, no redundant empty categories. |
| Offline / error | Accessible inline status in list header/section with Retry | Real last-success timestamp; state exactly which scope is stale. |
| Locked | Existing `FaceIDLockedRow` / `LockedVaultRow` and explicit Unlock | No automatic biometric prompt; protected names/metadata follow vault policy. |
| Partial result | Inline per-vault “Work unavailable” row | Keep available requests and truthful scope coverage. |

Source: `DecisionsView.swift:130–194,319–413`; `SessionModel.swift:74–84` preserves last-known inbox data with connection state.
The proposed queue must retain access requests even when Suggestions and empty placeholders leave the daily list.

## 3. Request detail and authorization

| Spec element | Native component / props | Required semantics |
| --- | --- | --- |
| Credential / requester | Semantic title + subheadline, flexible vertical layout | No single-line clipping of the only meaningful credential or agent distinction. |
| Facts | `LabeledContent` in `Section` | Action, Project, Environment, Access and expiry remain scannable. |
| Command | Existing `DecisionCommand`; selectable monospaced text | Full authoritative command available in the live request; never stored by default in history. |
| Why / risk | `Section`, body + secondary text | Risk stays visible at decision time; no suggestion that agent prose is authoritative proof. |
| Supporting context | `DisclosureGroup("Request details")` | Cwd, variables' names, vault/source/device and user/agent context as available. |
| Action area | Existing `DecisionBar` in `.safeAreaInset(edge: .bottom)` | One-handed reach, safe areas, scroll content never hidden behind controls. |
| Allow Once / Deny | `Button`, existing `.decisionButton` roles | Exact offered answer; 44pt targets; Deny equally reachable. |
| More answers | Labeled `Menu` or typed scope-review destination | Preserve offered choices. Broader grant must name scope before executing. |
| Production grant | Exact “Allow production: {Action} in {Project}” label + explicit production/all-agents facts | Never shorten it to a project-only grant label. |
| Project grant | “Allow {Action} in {Project}”; remembered for all agents in project | Distinguish scope from Allow Once and production grant. |
| Environment correction | Per-item Development / Production choices | Retain unconfirmed-item identity and server-offered validity. |
| Agent restrictions | Not for this agent / Always ask for this agent / Disconnect | Retain existing meanings, destructive role where appropriate; no new Face ID requirement. |
| Authentication | Existing `PreparedAnswer` / signer → native owner authentication | No fake custom Face ID sheet in app; HTML simulation is visibly labeled. |
| Biometry cancelled | Return to same detail, preserve request and scope | No delivery or terminal success record for cancelled authentication. |
| Changed request | Existing `RunSnapshot`, inline notice and “I have read the new version” | Rereview changed digest; preserve `AnswerGuard` when detail changes. |
| Access request | Read-only facts + Done / Deny; Mac guidance | Phone cannot allow; no reused Allow Once control. |

Source invariants: `QuestionsModel.swift:60–115,569–629`; `Questions.swift:390–397`; `RunDetailView.swift:75–81,255–305`; `RunRow.swift:101–142`.
The HTML broader-grant screen illustrates scope only; no broader permission is sent by the demo.
Do not drop existing Allow and Remember for local runs when `PendingRun.remember` is present.

## 4. Receipts and history

| State / element | Native composition | Truth requirement |
| --- | --- | --- |
| Sending | `ProgressView` + disabled affected actions | Prevent duplicates; cancel navigation must not fabricate cancellation of an accepted answer. |
| Answer sent | Neutral `Label` + “Waiting for Mac” | Relay acceptance remains separate from Mac settlement. |
| Not confirmed | Neutral status, Check Again / Done | Remains nonterminal after deadline when an answer was sent. |
| Allowed once / Denied | Existing `DecisionOutcomeBar` or equivalent accessible status | Match authoritative outcome and exact scope, provenance and time. |
| Expired | Read-only neutral outcome | Unanswered deadline expiry only; do not infer expired authorization outcome from transport timeout. |
| Changed / replaced | Neutral outcome + Review new request | Link verified replacement identity; no resubmission of old signature. |
| Missing / unreadable | `ContentUnavailableView` + actionable refresh/sync/unlock guidance | No fabricated title, outcome or authorization affordance. |
| History list | `List`, date `Section`s, immutable journal row IDs | Date grouping uses locale/time zone; stable ordering and explicit first/last observed timestamps. |
| Search | `.searchable(text:prompt: "Search history")` | Search decrypted accessible scope only; clear query; protect index on lock. |
| Filters | `Picker` or native filter `Menu`: All / Allowed / Denied | All retains unknown, expired and unconfirmed states. More filters can follow actual needs. |
| Coverage | Secondary text “Seen on this iPhone” | Scope remains visible; label does not imply complete history on other devices. |
| No history / no search result | `ContentUnavailableView` / `.search` | Separate “No history yet” from “No matching requests”. |
| History detail | `List`, `LabeledContent`, state `Label` | Read-only facts; explicit Confirmation and Execution “Not reported”; redacted fields “Not saved”. |
| Historical scope | Enum-backed display, source-specific provenance | An answered-on-other-device observation can be saved, but cannot imply full cross-device coverage. |

Current inputs: relay `RemoteQuestion`/`QuestionSettle`; separate `ActivityEntry` is not a ready-made unified journal.
Current Recent retention: `ios/ApassyCore/src/core/questions.rs:68–69,1652–1655` (600 seconds).
Current Mac activity: last 50, `ActivityView.swift:4`; in-memory only, `SessionModel.swift:5–6`; lacks correlation fields, `WireModels.swift:211–228`.

## 5. Data ownership, persistence and gaps

- Existing `@MainActor @Observable` QuestionsModel and SessionModel retain their authorization and transport responsibilities.
- Proposed journal store is separate, encrypted per vault and restricted to metadata of requests seen here; no plaintext disk logs or analytics payloads.
- Persist requested/selected scope separately from confirmed outcome. A sent answer can later be replaced by a different authoritative result.
- Source identity is vault+qid for relay; paired-device+run ID+digest for companion. Title/time similarity is not sufficient correlation.
- Phase 1 is phone-observed journal coverage. Phase 2 requires a stable cross-device/API contract, permission scope, pagination, authoritative replay and correlation.
- 30-day retention is only an open proposal. Default, deletion, backup, key lifecycle and migration decisions remain unresolved.
- Lock purges decrypted rows/search index; vault removal purges that vault's journal. Reopen requires authorized vault access.
- Local activity can be presented as an explicitly labeled separate source; never double-count it as a matched decision without a proven key.
- Full command arguments, environment values, secret values and free-text prompts are not saved by default; historical detail can say Not saved.
- A native journal is new application work. This artifact creates no store, migration, API, entitlement or retention setting.

## 6. Accessibility and responsive behavior acceptance

| Check | Acceptance criterion |
| --- | --- |
| Type | Semantic fonts and full Dynamic Type; largest accessibility size stacks facts/actions without losing scope or commands. |
| Targets | At least 44×44pt practical hit regions; clear spacing between opposite decisions. |
| VoiceOver | Row reads credential, agent/project, environment, real deadline/status; icons do not duplicate labels. |
| Status changes | Announce significant sending/confirmation/changed transitions once; avoid timer spam and unexpected focus jumps. |
| Color | Semantic colors, labels/icons alongside status; light/dark/increased contrast all readable. |
| Layout | Small iPhone, landscape, iPad multitasking and changing window widths expose the same functionality. |
| Motion | Reduce Motion respects state transitions; Reduce Transparency keeps action area readable. |
| Focus | Back restores list/selection/search; modal dismissal restores trigger; sheets do not cover a push-selected list indefinitely. |
| Navigation | Preserve existing native back and detail tab-bar rules; no additional nested TabView. |

HIG read: `writing.md › Getting started` (“Check each word…”), `lists-and-tables.md › Content` (succinct rows), `feedback.md › Best practices` (status in context), plus foundations.
SwiftUI-pro references read: navigation, data and design. These principles guide this proposal; no native conformance result is claimed.

## 7. Future implementation checks — all not run

1. Queue fixtures: relay/local same run dedupes; renamed Mac stays conservative; expired/answered relay rows leave Waiting; access requests remain visible and deny-only.
2. AnswerBar contract matrix: every offered once/project/production/correction/restriction choice preserves enum, item, environment, label and signer policy.
3. Authentication: cancel does not send; changed biometrics follows existing recovery; wrong-vault key cannot sign; Deny remains free of a new biometric requirement.
4. Repeated taps and navigation: one prepared answer/post sequence; current retry uses the same signed answer within its validity; tap guard survives replacement routes.
5. Relay state: accepted POST is neutral; matching authoritative settle confirms; missing settle stays unknown after expiry; replacement does not inherit approval.
6. Local snapshot: digest change disables approval until rereview; disappeared run says decided-or-timeout; local success does not claim execution.
7. Notifications: warm/cold/locked launches refresh Waiting, never select a guessed request or trigger unlock; preserve an early open intent until callbacks are attached.
8. Journal: encrypted storage/key isolation, lock/remove purges, idempotent upsert, replacement links, retention clock, corrupt/missing records, no secrets/raw commands in disk output.
9. Scope: no leaked locked-vault search matches or counts; partial refresh does not erase good data; journal coverage label never implies unseen cross-device events.
10. History: All retains unknown/unconfirmed; filters/search/date groups and back state work; source events lacking correlation are not falsely merged.
11. Native UI: VoiceOver, largest Dynamic Type, dark/increased contrast, Reduce Motion/Transparency and responsive sizes pass complete review→decision→history tasks.
12. Measure comprehension/retrieval/error recovery with synthetic participants; do not optimize approval rate or use live secrets in the study.

## 8. Completion boundary

Changed artifacts only: this map and the flow spec. No native build, app launch, model/UI tests, vault reads, provider calls, commits or push.
HTML browser checks are the main agent's responsibility and prove only proposal behavior; they cannot validate these native acceptance criteria.
A with list actions is the accepted IA direction. Journal retention/key lifecycle remain unresolved; native implementation and release are not completed by these artifacts.

## 9. List-action revision

Use a row `VStack` with an independent `NavigationLink` for details and sibling explicit `Button` controls for Deny / Allow Once or Deny / Review. Apply appropriate native button styles so List row activation does not trigger the other controls. Add named accessibility actions as supplementary access, not a replacement for visible buttons. Keep 44pt targets and stack controls at accessibility text sizes.

Use a typed request/snapshot identifier for the action, never a list index or mutable selected row. Share the existing answer preparation, expiry/snapshot checks, owner authentication, tap guard and submission path. Auth cancellation restores row focus and position. Keep the result in the original slot until explicit dismissal; update a source-qualified journal record idempotently. A list button is a new entry point, not a new authorization policy.

Native tests to add when implementing: action/navigation separation; eligible vs Review-only matrix; validity changes during owner authentication; duplicate taps; stable row positions; denial without new Face ID; matching receipt after navigation; VoiceOver named actions and largest Dynamic Type. Optional `.swipeActions(allowsFullSwipe: false)` must not execute an authorization on a full swipe. These native tests were not run for this HTML revision.

## 10. Native Liquid Glass

Use standard navigation, tab, toolbar, picker, search and sheet components before custom material work. Repeated list actions are ordinary native buttons inside readable List content; their container is not a glass card. Preserve independent navigation/action targets and avoid prominent glass on every row.

For a necessary custom floating control, use supported native glass APIs and group adjacent glass controls only when they form one functional unit. Do not add a glass effect to a standard component that already supplies it. Reuse existing semantic app styles only after checking their material/layer fit; existing use elsewhere is not proof of conformance.

Review the implementation against [the visual requirements](visual-direction.md#native-liquid-glass-requirement). Verify scrolling under native bars, safe areas, accessibility material settings and focus restoration on an actual native build. Keep the repository's existing deployment/toolchain settings.
