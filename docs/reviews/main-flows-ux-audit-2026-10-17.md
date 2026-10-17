# Apassy main-flow audit — 17 October 2026

Follow-up: [Customer journeys and cumulative friction](customer-journeys-2026-10-17.md) connects these findings into first use, sign-in, credential maintenance, organization, and approval journeys. It adds a verified onboarding completion mismatch and revises priority around complete customer outcomes.

## Verdict

**Needs work. The daily-use interface gives agent administration and system explanations more prominence than finding, storing, organizing, and using credentials.** Several problems are actual state-transition defects: desktop creation can lose an explicitly chosen folder; iOS can accept changes after taking the save snapshot; notification opening can lose context. The browser extension has no inline password-suggestion UI at all.

The product should feel like a quiet credential library, with security decisions presented when they matter. This is a product-design judgment, grounded in **Mental Model**, **Cognitive Load**, and **Progressive Disclosure**. Agents has real access-management functionality; its current prominence and information order are the issue. Preserve that functionality in a secondary destination.

Four independent reviewers covered iOS, desktop daily use, notifications, and extension suggestions. The main reviewer checked the strongest findings against their source paths and inspected the installed desktop window.

## Evidence and limits

- Source: `main`, `e13c1206654a435d9c53235a4979a38ff179488e`. Application files were not changed. Existing CI/test/documentation changes were preserved.
- iOS: SwiftUI; deployment target **iOS 26.0**, Swift **6.0** (`ios/ApassyCompanion/project.yml:16`). Recommendations preserve these targets. Source review, not a simulator or device walkthrough: no simulator was booted and no ready simulator app was found in the checked build locations.
- Desktop: Rust/eframe/egui with native helpers. Installed `/Applications/Apassy.app` was separately verified as **0.5.3**, commit `399a2b97042962ed71ba2b84d55b06503fe174f4`. Its visible credential detail confirmed substantial agent/status furniture. It is an older artifact than the audited checkout. No credential was revealed, copied, edited, or moved; the private screenshot was not saved into this report.
- Extension: manifest, popup, worker, form detection, native matching, and save protocols traced. JavaScript syntax passed; a dependency-free service-worker smoke passed **8/8**, independently rerun by the main reviewer. DOM fill was mocked. Browser integration, the installed extension/profile, native connection, Touch ID, and actual website forms were not tested.
- Notifications: routing/state verified in source, not actual APNs or macOS delivery. Cross-device, Focus, token registration, cold launch, and notification retention need device acceptance.
- No measured contrast, Dynamic Type, VoiceOver, timing, or task-completion claims. Severity describes source-supported task impact; design judgments are explicitly distinguished below.

Assumed user: the vault owner, interrupted or hurried, trying to get back to another task. User outcome: the right credential is stored, found, filled, or a request is safely resolved. Business outcome: dependable daily use. All proposals improve user satisfaction; no competing conversion objective or persuasive permission tactic is proposed.

Expert scorecard, not user research: **Information 1/3 · Meaning 1/3 · Time 1/3 · Memory 1/3 · Ethics PASS for the proposed changes.** Hypothesized emotional curve: enter task `0` → interpret extra screens `−1` → lost folder/missing suggestion/uncertain result `−2` → usable credential or confirmed decision `+1`. Repair those negative peaks before adding visual polish (**Peak-End Rule**).

## First five work packages

1. **Make saves trustworthy.** Preserve folder across creation modes; save item and destination atomically; protect the iOS submitted draft; commit or validate the pending tag. These are bounded correctness fixes (**Feedback Loop**).
2. **Make a notification end in a clear result.** Route Mac alerts to their event; use a refreshed Requests list for the existing private iOS push; distinguish sent from confirmed; reconcile old alerts when refreshing (**Mental Model**, **Peak-End Rule**).
3. **Make desktop organization practical.** Multi-select and bulk Move; expose Move Folder; reveal saved items despite old filters; add explicit search scope and safe identity-field search (**Tesler's Law**, **Discoverability**).
4. **Remove low-value reading and navigation.** iOS Vault opens credentials; Agents becomes Agent Access under Settings with contextual links; remove repeated unavailable sections and healthy-state furniture; make Login creation immediately visible (**Cognitive Load**, **Progressive Disclosure**).
5. **Build the missing browser interaction.** An opt-in field-context account chooser, safe form binding, unlock/retry recovery, and precise completion feedback. This is feature work, not a copy fix or reinstall (**Mental Model**, **Discoverability**).

These packages are ordered by dependencies and bounded fixes first, not a claim that browser suggestions are unimportant. Their design can proceed in parallel with the correctness work.

## Findings

P0 means the requested interaction is absent or blocked; P1 means significant friction/correctness risk; P2 means polish. Apple-style High/Medium describe impact. Evidence IDs below expand to exact source locations. UX principles justify proposals; they are not measurements of behavior.

| # | Screen / step | Issue observed in source | Principle(s) | Severity | Concrete recommendation | Expected effect | Metric / acceptance |
|---|---|---|---|---|---|---|---|
| F01 | Desktop: paste → manual → Save | Changing Folder to B, then choosing Fill in by hand, clears that choice. Manual save uses the original sidebar folder A and ignores a subsequent folder-assignment error. [E01] | **Mental Model**, **Feedback Loop** | High / P1, defect | One shared draft with a visible Folder in both modes; atomic create-with-folder. If B disappeared, retain draft and ask for a destination. | Trust the chosen save location. | A → choose B → manual → Save produces exactly one item in B; deleted B produces no silent fallback. |
| F02 | iOS: editing and saving | Only Save and swipe dismissal are blocked during save; Cancel and fields stay active. Later edits miss the already-submitted snapshot. Dirty swipe discards a draft; typed pending tag is omitted by Save. [E02] | **Feedback Loop**, **Peak-End Rule** | High / P1, defects | Freeze form/Cancel while submitting; retain draft on error. Block accidental dirty dismissal and provide Keep Editing / Discard Changes through Cancel. Commit or validate the pending tag before saving. | No apparent cancellation followed by save; no silent omissions. | Delayed-service tests; dirty swipe; type tag → tap Save without Return. |
| F03 | Browser: focus a login field | No password content script, field affordance, focus listener, or account suggestion menu. Existing scripts provide passkeys; passwords require the toolbar popup. [E03] | **Discoverability**, **Mental Model** | High / P0 for requested inline flow | Add independently understandable login-suggestion site access and a field-context chooser; retain toolbar/shortcut fallback. | Accounts appear where the user is working. | Eligible field → site-scoped accounts → explicit choice → owner check → fill. |
| F04 | Notification → destination | Mac notifier opens the app without event routing. iOS refreshes, may prompt across locked vaults, then opens the newest waiting question; the push identifies no question. [E04] | **Mental Model**, **Recognition Over Recall** | High / P1, behavior mismatch | Mac: route to exact local event after revalidation. iOS: generic Requests Are Waiting → refreshed Requests list; explicit vault unlock, no automatic newest selection. | Predictable context after a tap. | Old A notification with newer B never presents B as A; no unrelated unlock carousel. |
| F05 | Request → completion | Sent copy tells the owner to watch the agent and infer refusal after a minute. Missing confirmation does not prove refusal. Delivered notifications lack explicit reconciliation after settlement. [E05] | **Feedback Loop**, **Peak-End Rule** | High / P1, truth/ending | Answer sent · Waiting for Mac → confirmed Allowed/Denied; otherwise The Mac hasn't confirmed + Check Again. Reconcile delivered alerts on refresh; preserve Activity. | An honest end state and fewer stale signals. | Offline Mac never becomes assumed Allowed/Refused; second-device settlement clears waiting count on refresh. |
| F06 | Desktop: organize a library | One selected item and one-item Move. Folder create/rename/delete exist, but reparenting an existing folder has no desktop entry point despite a core API. Commands rely heavily on context menus. [E06] | **Tesler's Law**, **Familiarity Bias** | High / P1, capability gap | Cmd/Shift selection; one bulk Move with Undo; visible folder More and native menu commands including Move Folder. Keep contextual actions. | Cleanup takes one operation per group. | Move 20 items once; reparent subtree; keyboard equivalents; reject cycles/collisions. |
| F07 | Desktop: find and locate results | Search is folder-scoped without a scope control; title/notes/tags are searched, not visible username/Website/host. Existing query/archive filters can hide a newly saved selection; destination ancestors can stay collapsed. [E07] | **Mental Model**, **Feedback Loop** | High / P1, retrieval/state | Visible All Credentials / This Folder scope; search safe identity fields while unlocked. Reconcile filters and reveal saved item; announce any scope/filter change. | Find by remembered identity; see the result of saving. | Email/domain search, sibling-folder search, create under Archived/nonmatching query, collapsed destination. |
| F08 | Desktop: use a password/token | Direct Copy is absent by deliberate policy; secret rows provide Show/Hide. TOTP already has guarded clipboard support. [E08] | **Mental Model**, **Tesler's Law** | High / P1, product-policy choice | Decide on explicit owner-authorized per-field Copy with concealed pasteboard and conditional clear; no reveal prerequisite. If copy stays unsupported, expose the supported use action at the field. | Avoid manual reveal/transcription detours. | Copy authorization and clipboard replacement/clear tested separately; never weaken broker checks incidentally. |
| F09 | Create a normal login | Paste/developer formats lead; desktop manual entry is an 11-point secondary link then a type picker. Service/project/agent language intrudes; validation reveals schema constraints at Save. [E09] | **Cognitive Load**, **Progressive Disclosure** | High / P1, design + validation | Visible Login / Paste / Other choices. Login: Name, Username, Password, Website, Folder; optional details below. Inline validation. End with saved item/destination; optional agent setup. | A recognizable, short creation flow. | Create login without agent configuration; no validation loop for unmarked requirements; preserve batch paste. |
| F10 | iOS: Vault landing | Watchtower and healthy sync/count/unlocked messages precede or compete with All Credentials; Vault is a directory before the list. [E10] | **Cognitive Load**, **Progressive Disclosure** | High / P1, design judgment | Put the actual list at Vault root; folders/filter and Add remain easy to reach. Retain actionable security/sync problems; healthy detail is inspectable in settings. | One fewer navigation step and less status reading. | Reach item from root directly; find sync recovery and Watchtower issues without relying on color. |
| F11 | iOS: Agents | Top-level feed has real remote exception removal, but statistics/projects/read-only material precede the control. Connected count actually counts non-revoked agents, including stale ones. [E11] | **Progressive Disclosure**, **Mental Model** | High / P1 IA; Medium inaccurate label | Stable Agent Access under Settings, linked from request/item context. Show permissions/exceptions first, activity/details second. Use Agents rather than Connected unless liveness is proven. | Keep control without a monitoring dashboard in the daily path. | Find/revoke access in fresh/stale/no-feed/multi-vault states; preserve provenance and stale-action guards. |
| F12 | Credential details | iOS always inserts two Mac-only informational sections before notes/options. Desktop gives unused agent/rule sections substantial space for ordinary credentials. [E12] | **Cognitive Load**, **Progressive Disclosure** | Medium / P1, design judgment | Fields and use actions, notes, relevant options first. Remove unavailable placeholders. Put agent access/activity under a contextual destination; show warnings when consequential. | Faster scan to useful content. | Time to copy/use, read notes, and find real access controls. |
| F13 | Notification attention | Foreground iOS always requests banner+sound. Desktop suggestions map to approval-waiting copy/sound while being excluded from the pending badge; Activity is fragmented. [E13] | **Banner Blindness**, **Cognitive Load** | High / P1, channel mismatch | Requests for work needing a decision; Activity for outcomes; Suggestions nonurgent. Update visible Requests quietly. Preserve alerts for meaningful actionable risks. | Less interruption and clearer urgency. | Alerts per actionable decision; zero suggestion-as-blocked-agent copy. |
| F14 | iOS: notification settings | Toggle reflects saved intent; enabled is persisted before token arrives, registration failure is ignored, and effective OS settings are not read back. [E14] | **Feedback Loop**, **Feedforward** | High / P1, state truth | Settings → Notifications: On / Off in iOS Settings / Registering / Couldn't Register. Direct Open iOS Settings or Retry when appropriate. | Diagnose silence without guessing. | Revoke OS permission, fail registration, return to app: effective state is accurate. |
| F15 | Browser: select account/form | URL-only matching ignores typed username; fill picks a password field in document order, not the focused form. Injection targets frame 0 only. [E15] | **Feedforward**, **Mental Model** | High / P1, coverage/targeting | Bind chooser to field/form/frame/document. Filter permitted metadata by typed username. Deliberate frame support with independent origin checks; accurate unsupported recovery until then. | Fill the intended account into the intended form. | Two forms, username-first, SPA, shadow root, same/foreign-origin iframe, navigation during approval. |
| F16 | Browser: recovery and reuse | Open Apassy ignores show failure then closes; no-match help prescribes a custom Website detail despite built-in support; password change Save rejects an existing login instead of updating. Popup closure can hide result. [E16] | **Feedback Loop**, **Peak-End Rule** | High / P1, recovery/capability | Distinct locked/no-vault/not-running/host-missing states, Retry/resume, accurate Website repair. Explicit owner-approved Update Login; precise full/username-only/cancelled results on return. | Recover without duplicate items or repeated uncertain fills. | Recover by exact error state; update correct item preserving URL/passkey/TOTP; no auto-submit. |

### Exact source evidence

Paths are relative to the repository root; line numbers refer to the audited revision.

- **E01:** `src/desktop/ui/new_credential.rs:266` stores `Choices.folder`; `:306` calls `forget`, which removes it at `:192`; `src/desktop/ui/items.rs:505` opens the manual flow without that choice; `:2455` adds and `:2462` uses `app.place` for a separate ignored `set_item_folder` result. Detected add already has atomic folder-aware handling in `src/desktop/owner_store/add.rs:59`.
- **E02:** `ios/ApassyCompanion/Sources/Views/Vault/ItemEditorView.swift:26` Form; `:67` Cancel; `:70` Save; `:88` only saving disables interactive dismissal; `:283` local pending tag with submit/Add as its only commit paths. `Sources/Vault/ItemEditorModel.swift:334` serializes model tags, `:348` snapshots draft before the await. Folder move is also a second step (`:361`), with an explicit later failure path; do not falsely claim it is atomic on iOS.
- **E03:** `extension/manifest.json:8`, `:13`; `extension/background.js:624` registers passkey-only scripts; `:1256` restricts password messages to popup context. `docs/adr/0021-browser-extension.md:29`, `:111` explicitly scope out the inline menu. A new content-script route needs its own validation, not removal of the popup sender restriction.
- **E04:** `native/ApassyNotify/main.swift:43` → `Notify.swift:354`; `ios/ApassyCompanion/Sources/PushRegistrar.swift:74`; `Sources/Models/QuestionsModel.swift:591`, `:616`, `:636`. Privacy constraint: `docs/contracts/relay-questions-v1.md:503` contains no question/agent/item/vault identifier in APNs.
- **E05:** `Sources/Models/QuestionsModel.swift:565` outcome and `:587` sent text; `src/questions/worker.rs:1133` best-effort settle; `src/desktop/notify.rs:553` only clears in-memory deduplication; `native/ApassyNotify/main.swift:21` exposes no notification removal command; contract `relay-questions-v1.md:571` acknowledges stale push after another device answers. iOS source search found no delivered-notification removal API use.
- **E06:** `src/desktop/mod.rs:114` single selection; `src/desktop/ui/items.rs:240`, `:713`; `src/desktop/ui/folders.rs:198`, `:287` one-item move; `src/desktop/ui/sidebar.rs:386` New/Rename/Delete menu; `src/vault/folders.rs:365` core reparent API. Searches across desktop callers found no folder-move UI. Standard keyboard focus exists; this is not a claim that all keyboard access is missing.
- **E07:** `src/desktop/ui/items.rs:144` query/filter, `:157` scope; `src/vault/mod.rs:1467` title/notes/tags matching; `src/desktop/ui/new_credential.rs:817`, `src/desktop/ui/items.rs:2455`, `:2616` post-save; `src/desktop/mod.rs:370` selection; `src/desktop/ui/sidebar.rs:343` collapsed ancestry; `src/desktop/ui/folders.rs:293` follows move destination.
- **E08:** `src/desktop/clipboard.rs:1` deliberate TOTP-only policy, `:75`, `:123`, `:170` concealed/conditional-clear implementation; `src/desktop/ui/items.rs:1134` secret Show/Hide; `:700` toolbar. Manual selection of revealed text was not tested.
- **E09:** `src/desktop/ui/new_credential.rs:229`, `:467`, `:522`; `src/desktop/ui/items.rs:2356`, `:2690`, `:2468`; `src/desktop/owner_store.rs:2214`, `:2246`, `:2322` late validation. Service/project are optional, not required. iOS similarly begins with paste and a secondary manual menu: `Sources/Views/Vault/NewCredentialView.swift:46`, `:85`.
- **E10:** `Sources/Views/Vault/VaultRootView.swift:15`, `:24`, `:60`, `:81`; `Sources/Views/Vault/VaultComponents.swift:365` sync states.
- **E11:** `Sources/Views/Vault/VaultTabView.swift:27`; `Sources/Views/Agents/AgentsView.swift:50`, `:77`; `Sources/Views/Agents/AgentDetailView.swift:71`, `:237`; `Sources/Models/AgentsModel.swift:181` count. These `Sources/` paths are under `ios/ApassyCompanion/`.
- **E12:** `Sources/Views/Vault/ItemDetailView.swift:113`, `:388`; `Sources/Models/AgentsReach.swift:94`; `src/desktop/ui/items.rs:984`. Desktop appearance also observed in the installed older build, without proving current-source runtime rendering.
- **E13:** `Sources/PushRegistrar.swift:65`; `src/desktop/notify.rs:89`; `native/ApassyNotify/Notify.swift:92`, `:305`; `src/desktop/ui/decisions.rs:728`; `src/desktop/inbox.rs:124`; `Sources/Views/Decisions/DecisionsView.swift:303`; `Sources/Views/Main/ApprovalsView.swift:33`.
- **E14:** `Sources/Models/QuestionsModel.swift:276`, `:948`, `:980`; `Sources/PushRegistrar.swift:105`. Source search found no iOS `getNotificationSettings` readback. This does not establish that the current user's push delivery is broken.
- **E15:** `src/desktop/owner_store/browser.rs:145`, `:257` matching/list; `extension/fill.js:70`, `:113` chosen password; `extension/background.js:216`, `:265`, `:360` frame 0. Existing username-first handling and open shadow-root traversal should survive the redesign.
- **E16:** `extension/popup.js:53`, `:60`, `:73`, `:79`; `src/desktop/owner_store/browser.rs:678` Website/URL support; `src/desktop/browser.rs:493` existing login refusal; `src/browser/wire.rs:83` no Update command; `extension/background.js:230`, `:528` result/badge fallback.

## Proposed main flows

### iOS: Vault, Requests, Search

Use three stable destinations, with Settings reachable from the toolbar. Vault opens the real credential list, a folder/filter control, and Add. Search retains its existing dedicated role. Requests contains Waiting and Activity; Agent Access lives in Settings with contextual links from requests/items. This hierarchy is a design recommendation, not an Apple rule against four tabs (**Mental Model**, **Progressive Disclosure**).

`Unlock → credentials → select → use/copy` replaces `Unlock → Vault directory → All credentials → select`. Credential detail orders fields/actions, notes, relevant options, then secondary details. Do not display empty or unavailable agent sections. Keep actual security flags, conflicts, expiry and sync failures visible when relevant (**Cognitive Load**, **Feedback Loop**).

Create opens a visible choice of Login, Paste, or Other. Login shows Name, Username, Password with Generate, Website, Folder; optional empty notes/tags/agent details are disclosed below. Existing optional data remains visible while editing. Website is required for browser matching, not necessarily for storing a credential; state that at the relevant point. Changing field requirements needs a consumer/API review (**Feedforward**, **Progressive Disclosure**).

First run retains the real routes: Open Personal Vault, Join Team, Approve Mac Requests. Short help explains the next step; deeper iCloud/QR help is available when needed. Preserve document picker, passphrase and optional biometrics. Do not advertise standalone iPhone vault creation that the reviewed implementation does not provide (**Mental Model**, **Cognitive Load**).

### Desktop: complete the library task

`Cmd-N → Login → enter essential fields + visible destination → Save → selected visible item`. Paste detection stays equally accessible and shares the destination draft. Success says “Saved GitHub in Work.” Agent setup becomes an optional contextual action, not the prescribed next step (**Feedback Loop**, **Progressive Disclosure**).

`Select 20 items → Move to Folder → destination → Move → source list + Undo / Open Folder`. A folder's More/menu exposes New Folder, Rename, Move Folder and Delete. Move preserves item IDs, history and access semantics. Drag-and-drop may follow, but menu/keyboard paths must work first (**Tesler's Law**, **Familiarity Bias**).

Cmd-F makes scope visible and can search All Credentials. Match unlocked nonsecret identity fields without exporting them into plaintext metadata; never search passwords, tokens or OTP seeds. A creation transition reveals the result even if the previous query or Archived filter would hide it; the UI explains the scope change (**Mental Model**, **Feedback Loop**).

Direct password/token Copy is a separate product-policy decision. Proposed control: `Password ••••••••  Copy  Show`, with an owner check for the chosen field and conditional clipboard clear. This audit neither authorizes nor implements a relaxation of the existing TOTP-only clipboard policy (**Mental Model**, **Feedforward**).

### Notifications: Waiting → Sending → Confirmed result

Use one Requests model across relay and Wi-Fi; the existing deduplication is a foundation. Waiting means work requiring an answer; Activity records outcomes and blocked attempts. Agent statistics and suggestions are not urgent work. Preserve identity, action, scope/duration of approval, relevant environment/command, freshness and provenance before authorization (**Mental Model**, **Feedforward**).

| Event | In-app presentation | System presentation and tap destination |
|---|---|---|
| A request actually blocks work | Waiting + pending count | One allowed alert. Mac opens its event. Current private iOS payload opens refreshed Requests. |
| The owner is already viewing Requests | Insert/update row; accessible announcement | No duplicate foreground banner/sound for already-visible information. |
| A suggestion or routine policy denial | Suggestions or Activity | Quiet by default; meaningful actionable security risk can warrant an alert. |
| Resolved elsewhere / expired | Outcome, removed from Waiting | Reconcile old local alerts at next refresh; keep history. Do not promise immediate background clearing under the current contract. |
| Notification permission/registration failure | One actionable state + settings detail | Open iOS Settings or Retry, based on the actual failure. |
| Answer submitted, no confirmation yet | Answer sent · Waiting for Mac | No success claim. Later settle determines Allowed/Denied; missing settle means unconfirmed. |

Channel choices follow **Banner Blindness** and **Feedback Loop**. Notification dismissal is never approval or denial. Do not add question, vault, agent or credential identifiers to APNs as a routing shortcut: the existing privacy contract explicitly excludes them.

### Browser: the familiar interaction the user requested

`Focus field → choose account beside the form → confirm in Apassy → return to the same form, filled`. Add a named “Show Apassy Logins” control, Escape dismissal, arrow-key/Enter selection and visible focus. Suggestions contain only site-authorized title/username metadata. Filter those rows by typed username; allow Show All Logins for This Site (**Discoverability**, **Cognitive Load**).

Persistent field suggestions require opt-in site access; current `activeTab` access only follows a user toolbar action. Explain that permission at setup, keep passkeys and login suggestions understandable separately, and retain the toolbar path when permission is absent. Bind each selection to trusted browser sender/tab/frame/document data. Revalidate after owner approval; a stale page fills nothing. Only the approved account's secret is fetched for the selected fill; never retrieve all passwords for a menu (**Feedforward**, **Feedback Loop**).

Support multiple forms and username-first sites deliberately. Frame support must match and authorize the frame's origin independently; never inject parent-site credentials into an arbitrary child frame. Save and Update Login are distinct owner-approved operations preserving unrelated URLs, passkeys and TOTP. Do not auto-submit or treat form submission as proof of successful login (**Mental Model**, **Provide Exit Points**).

The current [1Password browser guide](https://support.1password.com/getting-started-browser/) documents a top-of-page sign-in prompt, alternate account choices, and field-level menus for other functions. Its [save/fill guide](https://support.1password.com/save-fill-passwords/) covers saving and filling in browser context. The proposal adopts the user's requested familiar account-selection behavior; it does not claim that every current 1Password browser uses an identical dropdown.

## Copy and status policy

Keep text that helps choose, explains a meaningful consequence, confirms an uncertain outcome, or provides recovery. Remove repeated reassurance, implementation explanations, empty analytics, and healthy-state duplication (**Cognitive Load**). Keep security explanations at the decision that needs them (**Feedforward**).

| Current copy / surface | Proposed treatment | Reason |
|---|---|---|
| Vault subtitle: vault + count + unlocked | Vault name; list owns count if useful | Duplicate state; **Cognitive Load**. |
| Permanent healthy sync capsule | Inspectable healthy state in settings; compact progress/error when relevant | **Progressive Disclosure**; retain failure recovery. |
| Agent use / Rules sections with unavailable Mac content | Remove from routine item detail; contextual Agent Access destination | **Cognitive Load**. |
| No agent used it yet / empty rule section | Omit unless user opened Activity/Access | **Progressive Disclosure**. |
| “None. The bouncer decides each use.” | Omit empty section; explain actual approval behavior inside Agent Access | Internal metaphor does not help the current task; **Mental Model**. |
| “Next, set up agent access.” after saving | “Saved {name} in {folder}.” Optional Set Up Agent Access | **Peak-End Rule**. |
| “N connected” based on non-revoked rows | “N agents”, with freshness only where it matters | **Feedback Loop**. |
| “Each one asks for Face ID.” | Use actual biometry name; mention vault-passphrase fallback where needed | Model supports fallback; **Mental Model**. `GeneralSettingsView.swift:121`, `AutoFill/AutoFillViews.swift:65`. |
| Long sent/refusal explanation | “Answer sent · Waiting for Mac”; later confirmed result or “The Mac hasn't confirmed.” | **Feedback Loop**. |
| No login / add a detail named Website | “No saved logins for {host}.” Actions Save This Login / Check Website in Apassy | Avoid invented diagnosis; **Feedback Loop**. |
| Locked / no vault / connection errors | Distinct states: Unlock Apassy; Open a Vault; Open Apassy; Connect This Browser. Retry restores context. | **Discoverability**. |
| Generic “Filled.” for username only | “Username filled. Continue on the website.” Offer same account again at password step with fresh approval. | **Feedback Loop**. |

## SwiftUI changes tied to real UX defects

These are implementation sketches, not applied patches. Both target the existing iOS 26 baseline. Do not turn this audit into unrelated API modernization.

### `ios/ApassyCompanion/Sources/Views/Vault/ItemEditorView.swift:26`

Rule: the displayed draft must not diverge from a submitted save, and Cancel must not imply cancellation of a write that continues.

```swift
// Before: Form and Cancel remain active; only Save and swipe are gated.
Form { editorFields }
Button("Cancel", role: .cancel) { dismiss() }

// After: conceptual extracted fields / close handler.
Form { editorFields }
    .disabled(model.isSaving)
Button("Cancel", role: .cancel) { requestClose() }
    .disabled(model.isSaving)
// requestClose offers Keep Editing / Discard Changes when dirty.
// Block dirty interactive dismissal; preserve lock/background secret policy.
```

### `ios/ApassyCompanion/Sources/Views/Vault/ItemEditorView.swift:70`

Rule: text visibly entered into the pending tag input must be committed or receive an error before the form closes.

```swift
// Before
Task { if await model.save(in: vault) != nil { dismiss() } }

// After: before starting the save task.
let pending = newTag.trimmingCharacters(in: .whitespacesAndNewlines)
if !pending.isEmpty {
    guard model.addTag(pending) else { return }
    newTag = ""
}
Task { if await model.save(in: vault) != nil { dismiss() } }
```

The implementation must focus/announce validation failures and use a real dirty-state comparison including pending tag input. Preserve secure draft clearing on lock; do not persist raw secrets in plaintext merely to recover accidental dismissal (**Feedback Loop**, **Peak-End Rule**).

## Accessibility and craft

The installed desktop observation returned only window chrome and the Apassy menu in the accessibility tree while the screenshot showed a populated library. **This is an observed AX integration gap, not a completed VoiceOver diagnosis.** `Cargo.toml:28` enables AccessKit and custom controls register semantics (`src/desktop/ui/kit.rs:1956`); do not misreport missing source support. Verify with Accessibility Inspector and VoiceOver on the target build. If core controls are unreachable, that is Critical and precedes visual work (**Discoverability**, **Feedback Loop**).

No contrast failure or target-size failure is asserted without measurements. Validate iOS largest accessibility sizes, keyboard avoidance, VoiceOver order, Reduce Motion, light/dark/increased contrast, compact and regular widths. Validate desktop minimum supported window size, keyboard-only folder/list operation, focus visibility and text scaling. Validate extension 200% zoom, keyboard navigation, screen-reader announcements, field overlap and collision with the browser's own password manager.

Craft judgment: a deliberately quiet utility is appropriate. Credentials, recognizable account identity and clear actions should carry the screen; decoration and monitoring statistics do not need to establish personality. Keep the familiar three-column desktop library and native SwiftUI controls; spend emphasis on the next useful action and genuine security consequences. Remove explanatory accessories before inventing a new visual theme (**Cognitive Load**, **Progressive Disclosure**).

## Apple and psychology grounding

References were read from the requested skills, with platform guidance translated to egui rather than pretending desktop uses SwiftUI. These short quotes establish principles; the exact proposed IA is our judgment.

| Read reference and heading | Short guideline | Application |
|---|---|---|
| [layout.md](https://developer.apple.com/design/human-interface-guidelines/layout) › Visual hierarchy | “Order content by relative importance.” | Credential task before status, statistics or unavailable sections. |
| [writing.md](https://developer.apple.com/design/human-interface-guidelines/writing) › Getting started | “Check each word to be sure it needs to be there.” | F09–F12 and copy policy. |
| [entering-data.md](https://developer.apple.com/design/human-interface-guidelines/entering-data) › Best practices | “Dynamically validate field values.” | Preserve choices and make errors actionable in F01/F02/F09. |
| [feedback.md](https://developer.apple.com/design/human-interface-guidelines/feedback) › Best practices | “Consider integrating status feedback into your interface.” | Contextual outcomes; no unnecessary success screens. |
| [notifications.md](https://developer.apple.com/design/human-interface-guidelines/notifications) › Best practices | “Handle notifications gracefully when your app is in the foreground.” | F04/F05/F13/F14, actual related content and quiet visible updates. |
| [accessibility.md](https://developer.apple.com/design/human-interface-guidelines/accessibility) › Vision | “Describe your app’s interface and content for VoiceOver.” | Validate the observed AX gap. |

Also read foundations layout/typography/color/accessibility, both platform guides, and targeted tab/sidebar/search/form/menu/notification references within the four reviews. Psychology names follow the supplied catalog, including **Recognition Over Recall**, **Mental Model**, **Feedback Loop**, **Progressive Disclosure**, **Tesler's Law**, **Discoverability**, **Banner Blindness**, and **Peak-End Rule**. They explain the design trade-offs, not causal promises about conversion.

Ethics gate: transparent permission purpose; dismissal and cancellation remain available; Undo for reversible organization; clear confirmation for irreversible changes; no fake urgency, permission nagging, automatic approval, or success without evidence. Broader site access and secret-copy policy require deliberate design review before implementation; neither was changed here.

## Validation and implementation gates

| Work package | Required synthetic checks | Required real interaction |
|---|---|---|
| Save correctness | A→B→manual destination; deleted folder race; delayed save; pending tag; retained draft on error; no duplicate create | iPhone dirty swipe/Cancel/lock and Mac keyboard creation. |
| Organization/search | Batch atomic move/Undo; folder cycle/collision; email/domain search excludes secrets; query/archive/ancestry reveal | Organize 20 items with keyboard and pointer; minimum-size window; VoiceOver. |
| Notification lifecycle | Event routing after lock; A settled/B new; permission/token states; late settle; expired request; badge semantics | Two Macs + iPhone; foreground/background, Focus, locked screen, cold launch, actual APNs delivery and retention. |
| Simplified iOS IA | Destinations remain reachable; Agent Access starts feed and preserves revocation/freshness; no dead-end placeholders | Small/large iPhone layouts, iPad widths, largest text, VoiceOver; neutral find/create/revoke tasks. |
| Inline browser flow | Trusted sender/origin/frame/document; metadata whitelist; no approval on focus; no auto-submit; update preservation | Plain and username-first forms, SPA replacement, multiple forms/accounts, open shadow DOM, same/foreign-origin iframe, browser manager collision, approval closing popup. |

Measure task completion, time to useful result, repeated entry, wrong-folder/wrong-form rate, notification-to-correct-context rate, stale-alert rate and recovery by error code. Record aggregate outcomes without passwords, usernames, sensitive URL queries or credential content. Include people who abandoned these tasks, not only maintainers. Proposed flows and emotional scores remain hypotheses until those sessions run.

Checks actually run:

- Read-only `git status --short`, `git rev-parse HEAD`, targeted `rg`, and line-numbered source traces. Four bounded subagent reviews; key claims rechecked by main reviewer.
- Installed app version/commit read through `PlistBuddy`; native CUA accessibility-tree and screenshot observation only. `xcrun simctl list devices booted`: none.
- `for f in extension/*.js; do node --check "$f"; done`: all five parsed.
- Existing targeted Node suite could not start: missing `@simplewebauthn/server`. No dependencies installed; no suite-pass claim.
- `node /tmp/apassy-extension-audit-smoke-2026-10-17.mjs`: **8/8 passed**, including locked/no-vault, missing host, stopped app, empty matches, metadata stripping, top-frame dispatch and wrong-origin rejection. This is mocked service-worker routing/state evidence, not browser or native-fill acceptance.
- Rust/Swift builds and full suites not run for this read-only audit. No release, push, commit, vault mutation, notification preference change or extension permission change.

Immediate priorities remain save correctness and truthful request completion, then daily organization and task-focused IA, with inline suggestions treated as a real missing feature. Existing authentication, origin checks, private push payloads and audit history are constraints for that work, not clutter to remove.
