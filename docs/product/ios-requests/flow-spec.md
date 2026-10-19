# Flow spec: iOS Requests

Status: **A with list actions accepted as wireframe · native Liquid Glass required**. Mode: Improve, Audit → Design.
Baseline: `46e088dc69cc0d0d77dfad4849984867bd136d44`. No application implementation is authorized by this document.
The [HTML comparison](index.html) uses synthetic data and simulated authentication, transport, unlock and confirmation.
This is a source audit and design judgment, not a device observation or security implementation review.

## 0. Context and intended outcome

- User: a vault owner interrupted by an agent, often rushed and uncertain about the consequences.
- Job: “See what needs my decision, understand its scope, then find what happened later.”
- Entry: Requests tab, badge, generic push, or return from an earlier unconfirmed answer.
- User success: an informed allow or deny, accurate confirmation, and a discoverable record.
- Product success: fewer misunderstood scopes and support questions; faster retrieval of known outcomes.
- Conflict: maximizing approvals or speed could weaken review. Informed refusal and time spent reading count as success.
- Constraint: retain relay and local-companion authorization, Face ID requirements, snapshot checks and per-vault access boundaries.
- Assumption: English app copy follows the existing app; explanations in the proposal do not add permanent screen paragraphs.

## 1. Source audit → changes

Paths below are repository-relative; line numbers refer to the baseline above.

| Finding and evidence | Impact / principle | Proposed change |
| --- | --- | --- |
| `ios/ApassyCompanion/Sources/Views/Decisions/DecisionsView.swift:138` always creates Waiting, Requests (:165), Suggestions (:179). | P1, Cognitive Load: repeated empty categories compete with the real task. | One active queue; omit empty categories and move setup to its flow. |
| `DecisionsView.swift:242–259` repeats “Nothing waits” and explanatory setup/normal-state prose. | P2, Information hierarchy: an idle screen requires unnecessary reading. | “No requests waiting”; optional “View History”. |
| `DecisionsView.swift:180–187` shows Recent only when relay questions leave Waiting. | P1, Recognition Over Recall: history appears conditionally. | Stable History destination with clear coverage label. |
| `ios/ApassyCore/src/core/questions.rs:68–69,1652–1655` retains ended relay records for 600 seconds. Contexts drop on lock/suspend/process end (:20–26). | P1, Memory: Recent is transient, not a persistent journal. | Propose a separate encrypted journal; do not relabel the cache as complete History. |
| `ios/ApassyCompanion/Sources/Views/Main/ActivityView.swift:4` shows newest 50 Mac log entries; `ApprovalsView.swift:33–65` puts Activity inside the Mac companion view. | P1, Discoverability: another history scope is hidden behind Devices → Mac on Wi-Fi. | Define separate provenance and coverage; do not silently merge records. |
| `ios/ApassyCompanion/Sources/Models/SessionModel.swift:5–6,64–66` keeps inbox/activity only in memory. `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/WireModels.swift:211–228` has no qid/vault correlation field. | P1, Meaning: no reliable complete cross-source history contract. | Source-qualified identities; phase 2 API for cross-device history. |
| `ios/ApassyCompanion/Sources/Models/QuestionsModel.swift:691–706` distinguishes sent from confirmed. | Keep, Feedback Loop: relay delivery is not authorization outcome. | “Answer sent” → “Waiting for Mac”; never optimistic “Allowed”. |
| `ios/ApassyCompanion/Sources/Views/Main/RunRow.swift:101–142` permits only Deny for access requests. | Keep, Mental Model: types have different powers. | Explicit “Review access on Mac”; do not add phone approval. |
| `ios/ApassyCompanion/Sources/Models/Decisions.swift:86–124,153–173` deduplicates open relay/local runs conservatively. | Keep: a matching name is weaker than stable source identity. | Preserve current queue rules; require stronger correlation for durable history. |

Priority: remove idle-screen noise; expose honest history coverage; preserve outcome truth; clarify grant scope; verify resilience/accessibility.
Quick copy/order changes are separable from the structural journal and must not imply it already exists.

## 2. IA alternatives and recommendation

| Option | Structure | Best fit / cost |
| --- | --- | --- |
| **A · Waiting / History — recommended** | Requests → segmented Waiting / History; detail on row tap; settings in toolbar. | Daily approvals stay quiet; past decisions need one explicit tap. |
| B · One journal | Needs your answer first; Today below; Search History / See all History. | Frequent reviewers gain context; more content on the daily screen. |
| C · Vault inboxes | Work / Personal → Waiting / History; History across vaults. | Many-vault owners gain boundaries; single-vault users pay an extra step. |

Ranked tasks: review waiting request; inspect previous decision; recover connectivity/unlock; connect a device.
L1: credential, action, agent/project, vault, environment and genuine deadline; a meaningful command is visible before a list grant. L2: full scope, command and reason. L3: cwd, source/device, extra context and broader answers.
Vocabulary: Requests / Waiting / History. Avoid exposing transport terms as primary navigation.
Locked means unknown, never zero. The badge counts known actionable rows, not unread locked-vault requests.
The app's Vault / Requests / Search navigation stays available; detail navigation must preserve existing behavior.

## 3. Flow and planned ending

```text
Tab / generic push → refreshed Waiting → request → Allow Once → required owner authentication
                                               ↘ Deny (no new Face ID requirement)
→ Sending → Answer sent / Waiting for Mac → authoritative Allowed once / Denied → Done
                                      ↘ Not confirmed → Check Again / Done
Waiting → History → search/filter → read-only outcome detail → History
Request → More answers → explicit scope review → existing permitted answer and authentication
```

Planned peak: the owner recognizes exactly which action, credential and environment are being authorized.
Ending: a specific outcome with requester, vault and confirmation source; “Execution: Not reported”.
Desired recollection: “I understood the permission, and I can check the result later.”
Target: list → review → decision → receipt; no speed target that rewards skipping review.
Negative peaks: production scope surprise, missing confirmation, stale command, lost history, and inaccessible unlock.

## 4. Screens and all states

| Screen / state | Exact prototype copy and behavior | Design requirement |
| --- | --- | --- |
| Waiting / normal | Requests; Waiting / History; actionable rows. | Credential first, agent/project next; text “Production”, not color alone. |
| Waiting / empty | “No requests waiting”; “View History”. | One calm state; no Suggestions or repeated setup paragraphs. |
| First connection | “Connect a Mac”; “Approve requests on this iPhone.”; “Connect Mac”. | Dedicated connection flow retains relay vs Wi-Fi pairing differences. |
| Loading | “Loading requests…” accessible status; placeholder rows. | No invented count or empty-success flash. Native implementation can use ProgressView. |
| Offline | “Offline”; “Last updated 10:42”; “Retry”. | Timestamp is real in implementation; cached requests are visibly stale. |
| Refresh failure | “Couldn’t refresh”; “Showing saved requests”; “Retry”. | If no saved data exists, omit that claim and show an actionable error. |
| Locked | “Work is locked”; “Unlock to view its requests”; “Unlock”. | Owner-triggered unlock; no private journal rows before authorized access. |
| Partial | “Work unavailable”; “Other vaults are up to date”; “Retry”. | Only claim the other vaults are current after their successful refresh. |
| Detail | Action, Project, Environment, Access “This request only”, Expires, Command, reason; “Request details”. | Scope/command/risk remain readable; user/agent context is available without replacing authoritative facts. |
| Detail / offline | “Refresh to answer”; “The request must be checked again.” | Disable new grants until freshness is checked; retain a useful read-only record. |
| More answers | Server-offered choices; broader grant has separate scope review. | Prototype demonstrates only; production must retain every permitted AnswerBar choice below. |
| Authentication | “Confirm this request”; “Simulate Face ID”; “Cancel”. | HTML explicitly says simulated; real owner authentication uses the existing signer. Cancel restores detail. |
| Sending | “Sending answer…”; disabled “Sending…”. | Suppress duplicate submission; preserve prepared-answer retry rules. |
| Delivered | “Answer sent”; “Waiting for Mac”; “Done”; “View History”. | Neutral, nonterminal confirmation state; keep checking when feasible. |
| Unconfirmed | “Not confirmed”; “The Mac hasn’t confirmed this answer.”; “Check Again”. | Never infer Denied/Allowed or retry a different authorization silently. |
| Confirmed | “Allowed once” or “Denied”; “Confirmed by Studio Mac”. | Render only from authoritative matching outcome. Execution remains “Not reported”. |
| Expired | “Request expired”; “No decision was confirmed.” | Only for an unanswered expiry. A sent answer without settle remains Not confirmed, even after deadline. |
| Changed | “Request changed”; “Review the updated request before answering.”; “Review new request”. | New immutable request/snapshot, rereview and tap guard; no automatic approval. |
| Access request | “Review access on Mac”; “This iPhone can deny this request.”; Done / Deny. | No Allow or broad grant; retain agent reason and source. |
| History | “Seen on this iPhone”; “Search history”; All / Allowed / Denied; Today / Yesterday. | All includes expired, sent, unconfirmed and unknown entries. Filters must not imply complete coverage. |
| History / empty | “No history yet”. | Metadata-only record of observed requests, including observed-but-unanswered ones. |
| Search / empty | “No matching requests”; “Try another name.” | Retain query/filter, clearable search, accessible result count. |
| History detail | Requester, Project, Vault, Device, Scope, Confirmation, Execution. | Read-only; show unknown values explicitly, no actionable replay of past requests. |
| Unreadable/unavailable | Existing “This question could not be read” / “Request unavailable”; refresh guidance. | Do not invent credential or terminal outcome from missing data. |

## 5. Authorization invariants

`QuestionsModel.swift:60–115` is authoritative for offered choices and their meaning, not a fixed mockup button set.
Preserve `Allow Once`, `Allow {Action} in {Project}` and **distinct** `Allow production: {Action} in {Project}`.
Preserve Development / Production corrections per unconfirmed credential, Not for this agent, Always ask for this agent and Disconnect.
Show remembered scope: all agents in the project, production inclusion where applicable, or this credential for correction.
Do not turn a project grant into once, or once into remembered access; no preselection of broader permissions.
`Questions.swift:390–397`: authority-increasing answers require Face ID; deny/restrictions do not; Development correction does.
`QuestionsModel.swift:569–629`: keep expired/settled checks, correct vault signer, duplicate guard and same-signed-answer retry (<55 s).
`RunDetailView.swift:75–81,255–305`: preserve local snapshot validity, changed-version acknowledgment, Allow and Remember when offered, and Deny.
`Decisions.swift:177–191`: preserve 0.5 s accidental-tap protection. A countdown displays real remaining validity, without pressure styling.
Generic push refreshes the list, never guesses a detail or starts unlock (`QuestionsModel.swift:711–725`).
Cold-start callback ordering is unverified: `PushRegistrar.swift:99–102` has no replay buffer; callbacks attach in `RootModel.swift:250–262`.

## 6. Implemented local history contract

Phase 1: an **encrypted, vault-scoped metadata journal of requests seen on this iPhone**; not complete cross-device audit history.
Record source-qualified request identity, vault identity, first/last seen time, title/agent/project/action/environment, requested/selected scope, delivery state and authoritative confirmation provenance/time.
No secret values, raw credentials, full command arguments, environment values, or user/agent prompt text in the journal by default. In-memory detail remains ephemeral; reopened history can show “Not saved”.
Use relay vault + qid; for companion use paired-device identity + run ID + digest. Do not correlate solely by title/time/Mac display name.
Keep observation, selected answer, relay acceptance, authoritative decision and execution distinct; unknown is a real value, not Denied.
Update one journal record idempotently with matching confirmation; model replacements explicitly. Missing activity correlation must not manufacture a confirmation.
Lock removes decrypted rows and search indexes from memory; removal deletes that vault's local journal. Journal encryption is domain-separated from the question key; corruption/key rotation reports unavailable and requires explicit clearing. No plaintext fallback or retained key is used.
**Implementation default: 30 days from first observation, at most 1,000 entries per vault.** The app verifies backup exclusion before enabling storage. Locked history is hidden; removal deletes its file. Clearing is explicit and cannot erase an unresolved live answer guard. Only relay vault requests are persisted; Wi-Fi companion requests have no verified vault association.
Phase 2 requires a cross-device/API history contract: authoritative pagination/retention, stable correlations, visibility scope, settlement replay, and permissions. The newest 50 Mac entries and 10-minute relay cache cannot supply it.

## 7. Emotional journey and ethics gate

| Step | Before → target emotion (-2…+2) | Intervention |
| --- | --- | --- |
| Interrupted arrival | -1 → 0 | One queue, known freshness and no setup clutter. |
| Scope review — planned peak | -1 → +1 | Credential/action/environment and concise once vs remembered scope. |
| Authentication / sending | -1 → 0 | Cancel, progress and duplicate protection. |
| Confirmation missing — worst moment | -2 → -1 | Honest Not confirmed, Check Again, safe exit. |
| Confirmed ending / retrieval | 0 → +1 | Specific receipt and discoverable limited-coverage History. |

| Element | Transparency / symmetry / reversibility / alignment | Verdict |
| --- | --- | --- |
| Allow Once emphasis | Exact scope; Deny equally reachable; execution cannot be undone; serves least authority. | Pass conditionally; no broader grant default. |
| Timer | Real deadline; no fake urgency; no loss-aversion copy. | Pass. |
| Receipt | Separate delivery, decision and execution; Done always available. | Pass only with authoritative status. |
| History | Explicit phone-only coverage; encrypted/minimal; 30 days, bounded, clearable, no backup. | Implemented after user instruction to implement. |

No celebration, streak, approval nudge, repeated permission prompt, fabricated trust marker or satisfaction survey during an authorization.
Editorial scorecard (judgment, not measured): current Information 1/3 · Meaning 2/3 · Time 2/3 · Memory 1/3; proposed target 3/3 · 3/3 · 2/3 · 3/3. Ethics: conditional PASS; accessibility remains unverified on device.

## 8. Validation and decision gate

Hypotheses: A improves history discovery and outcome comprehension without increasing accidental grants; concise empty state reduces unnecessary reading.
Measure retrieval success/time, correct scope/status comprehension, accidental action/cancellation reports, unconfirmed recovery, error recovery, and VoiceOver task success. **Approval rate is not a success metric.**
Research: neutral tasks across A/B/C, include a cautious refusal, offline settle, locked vault and expired request; ask users to explain what was granted and whether execution occurred.
IA A and implementation are authorized. This branch adds local relay history with the scope above; no live telemetry is introduced.
Acceptance/test cases are listed in [component-map.md](component-map.md). Native source, persistence, model and synthetic Simulator checks are recorded in the [implementation report](implementation-report.md); physical-device authentication and cold push delivery remain unverified.
Gate A direction: the user accepted A with list actions as the wireframe. Native visuals must follow Liquid Glass through master-product, apple-design and swiftui-pro. Retention/key lifecycle are implemented above; see the separate native implementation report for actual checks and device gaps.

## 9. Revision: act from the waiting list

- Eligible routine request: **Deny / Allow Once**. Show exact action, credential, agent/project, vault, environment and meaningful command before the owner grants. Development alone is not a safety classification; ambiguous, unreadable, changed, destructive or broader-scope requests require Review. The demo has one explicitly eligible synthetic Read request.
- Production/elevated request: **Deny / Review** when current and denial is valid. Review opens full context; it does not approve. Stale/offline decisions are disabled until validity is checked again.
- A row container owns separate navigation and action controls. Never nest buttons or make the whole card approve. Visible controls are the primary affordance; optional native swipe actions use `allowsFullSwipe: false`. No bulk approval or remembered grants from the list.
- Allow Once uses existing owner authentication, bound to immutable request identity, vault, answer and snapshot. Recheck validity when authentication completes. In HTML, the explicitly labeled simulation appears within the row. Real SwiftUI uses the native owner prompt, not a custom Face ID form.
- Cancel restores the same row and action focus. Deny adds no biometric requirement. Preserve the existing accidental-tap guard in native work.
- Hold the row in place through Sending → Answer sent → confirmed outcome. No success before a matching Mac confirmation. Explicit Done dismisses a confirmed receipt; History retains it. Unknown stays unconfirmed.
- The browser prototype preserves row position and history identity with synthetic data; this is not evidence of native transport/authentication correctness.

Revised routine journey: Waiting → visible Allow Once → required owner authentication → inline sent/confirmed receipt; no mandatory detail or success page. Full review remains reachable by tapping the request title.
