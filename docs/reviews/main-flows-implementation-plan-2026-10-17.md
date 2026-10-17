# Main-flow implementation plan — 17 October 2026

Status: local implementation, corrective reviews and synthetic validation are complete in `feat/main-flow-ux` at `/Users/rafalw/Dev/apassy-flow-ux`, including native menus and their actual Mac walkthrough. The [validation ledger](main-flows-validation-2026-10-17.md) separates source/model/mock-browser/Simulator/native/device evidence, suite snapshots and two disclosed isolation exceptions. Physical-device, signed-helper/pasteboard, real-host, VoiceOver/contrast and complete customer-journey acceptance remain open. No release or merge is included. This plan records the completed implementation sequence, not a recurring automation or delivery-date estimate.

Inputs: [main-flow audit](main-flows-ux-audit-2026-10-17.md) and [customer journeys](customer-journeys-2026-10-17.md). Baseline: `e13c1206654a435d9c53235a4979a38ff179488e`. All F01–F16 findings and the additional onboarding finding (tracked here as F17) have an owner below. Journey acceptance governs completion; a screen change alone does not close a journey.

## Product decisions

- Lead with credentials and decisions the owner can act on. Use existing semantic styles and native controls; keep the current iOS deployment target. Healthy sync, counts, technical metadata and optional agent setup belong in secondary destinations.
- iOS has direct credential access, Requests and Search. Agent Access remains reachable from Settings and relevant context, with permissions, provenance and revocation preserved.
- Creation has clear Login, Paste and Other entry points. Folder choice survives mode changes. Save reports the actual item and destination and retains the draft on failure.
- Browser suggestions are an explicit, separately understandable site-access choice. Focusing a field only retrieves permitted metadata; filling still requires account selection and the existing owner checks. Never auto-submit.
- Requests, outcomes and nonurgent suggestions have different attention levels. Generic private phone pushes open a refreshed list; only local identifiers with revalidation may route to an exact request. Sent does not mean applied.
- Keep existing broker, sandbox and owner-authorization promises. For F08 the owner explicitly accepted [authenticated desktop Copy](desktop-copy-decision-2026-10-17.md): a fresh check for the exact item/field/revision and conditional clearing after 30 seconds. This replaces the earlier desktop clipboard restriction; automatic agent APIs remain secret-free.
- Use synthetic vaults, accounts and browser profiles. No live credential migration, production notifications, permission changes, release, installation over the user's app, publication or merge is part of these changes.

## Schedule and ownership

All workers use `gpt-6.1-sol` with high reasoning for implementation/review; a bounded difficult protocol/design investigation may use `gpt-6-astra` with high reasoning. Each reads `apple-design` and its relevant reference files. Swift workers additionally use `swiftui-pro` and the project deployment/toolchain settings. The lead owns integration, shared wiring, documentation and the final validation ledger.

### Wave 0 — prepare and establish interfaces

1. Create a T3-bound worktree `feat/main-flow-ux` from the audited commit. Preserve the original checkout's unrelated CI/test edits. Copy only the four audit artifacts and this plan.
2. Record baseline/toolchain/resource checks. Share the existing Cargo target directory and assign one Rust build owner. Do not rebuild concurrently in each worker.
3. Give each worker a strict allowlist. Require any extra file ownership or shared API change to be agreed with the lead before editing. Agree browser request/result types before frontend implementation; agree organization/create APIs before desktop UI integration.

### Wave 1 — independent correctness and platform work

| Workstream | Findings / journey | Primary ownership | Deliverable and dependency |
|---|---|---|---|
| A — iOS editor | F02, iOS F09; J3 | `ItemEditorModel.swift`, `NewCredentialModel.swift`, `ItemEditorView.swift`, `NewCredentialView.swift`, their dedicated model tests | Stable submitted snapshot, pending-tag handling, dirty-dismiss guard, clear login creation and honest errors. Does not edit RootModel, settings or navigation. |
| B — iOS navigation and first value | F10, F11, iOS F12, phone F17; J1/J3 | Vault root/tab/list composition, SettingsView, GeneralSettingsView, item and agent detail views, AgentsModel, iCloud import flow/model, RootModel; dedicated navigation tests | Credentials at root, Agent Access in Settings, useful detail order, optional AutoFill handoff and recovery. Owns shared root/settings wiring requested by C. |
| C — iOS request lifecycle | phone F04/F05/F13/F14; J5 | QuestionsModel, PushRegistrar, QuestionsView and request-specific views/models/tests; new notification-settings component if needed | List routing for generic push, explicit unlock, sent/waiting/confirmed states, delivered-alert reconciliation, effective OS/registration state and quiet visible foreground updates. Sends integration snippets/API contract to B instead of editing B's files. |
| D — desktop library core | F01/F06/F07/F09 core; J3/J4 | `src/vault/` relevant item/folder operations, `src/desktop/owner_store.rs`, `src/desktop/owner_store/add.rs`, dedicated vault/owner tests | Atomic create/destination handling, safe identity search, transactional multi-item move/Undo data and folder reparent validation. Owns shared owner_store types; coordinates browser types with E. No desktop UI edits. |
| E — browser authorization and update backend | F03/F15/F16 backend; J2/J3 | `src/browser/`, `src/desktop/browser.rs`, `src/desktop/owner_store/browser.rs`, browser protocol tests | Narrow metadata/target contract, fresh authorization, exact item update preserving unrelated fields, distinct recovery outcomes. Gives new shared owner-store/check hooks to D/lead; no unrelated security changes. |
| F — Mac notification lifecycle | Mac F04/F05/F13; J5 | `native/ApassyNotify/`, `src/desktop/notify.rs`, notification-specific tests | Local event routing/revalidation, nonurgent suggestions, settlement reconciliation. Shared `desktop/mod.rs` and UI wiring goes to lead/H. |

These are six independent initial assignments, not a target to fill every available slot. Workers must report changed files, commands/results, incomplete acceptance and integration needs. Stop at their file boundary.

### Wave 2 — complete desktop and browser journeys

Start each stream when its dependency contract is ready; it need not wait for every Wave 1 stream.

| Workstream | Dependency | Ownership | Deliverable |
|---|---|---|---|
| G — browser field chooser and recovery | E protocol agreement; E backend needed for full integration | `extension/`, `extension-tests/` and dedicated extension fixtures | Optional host access, field affordance/menu, keyboard and accessible selection, focused form/document binding, typed-username filtering, distinct recovery, durable return result and explicit Update Login. Supported frame behavior must be explicit and tested. |
| H — desktop daily use | D API agreement; F routing contract for integration | Desktop UI modules including `items.rs`, `new_credential.rs`, `folders.rs`, `sidebar.rs`, `first_steps.rs`, associated UI tests; `desktop/mod.rs` and `ui.rs` only after ownership handoff from lead | Shared create draft/destination, clear Login/Paste/Other, inline requirements, query scope/identity search/result reveal, Cmd/Shift batch selection, bulk Move/Undo, visible folder actions/reparent, contextual agent details, goal-relevant onboarding. Integrates F's routing. |
| I — credential use boundary | D/H contract; policy inspection | Initially read-only investigation of `clipboard.rs`, owner-check and contracts; then separately assigned files | Resolve F08 with a supported owner action and verify the clipboard/security boundary. Escalate a concrete policy decision only if the selected solution changes an existing promise. |

The lead handles documentation/contracts and required shared wiring that cannot be owned cleanly by one stream. Never have two editors in `items.rs`, `owner_store.rs`, `RootModel.swift`, GeneralSettingsView or the same test file.

### Wave 3 — integrate and adversarially review

1. Integrate each return against its acceptance cases before marking it complete. Run targeted tests first. A failed worker gets one corrective attempt with evidence; unresolved reasoning/implementation failures go to a replacement `gpt-6-astra` high worker after the previous editor stops.
2. Independent read-only review of SwiftUI state/navigation/accessibility using `swiftui-pro` and `apple-design`.
3. Independent read-only review of extension/native authorization, sender/origin/frame/document binding, update preservation and stale-target recovery.
4. Independent read-only desktop/notification journey review: selection/Undo, persistence/result reveal, truthful outcome and routing. Investigate the earlier accessibility-tree observation on the current test build; do not assume the installed build proves a current defect or fix.
5. Fix actionable findings under one-editor ownership; run the required repository gates and the five journey scenarios below. Record live/device checks separately from model, mock, simulator and local-browser checks.

## Coverage and closure ledger

Local implementation and synthetic checks address F01–F17, including native-menu parity. Device/customer acceptance is partial and no journey is blanket-closed. Counts, test sources, the harness exception and open gates are in the [validation ledger](main-flows-validation-2026-10-17.md#finding-evidence). “Implemented” is a source claim, not device acceptance.

| Finding | Owner(s) | Evidence and remaining gate |
| --- | --- | --- |
| F01 destination loss | D/H | Implemented; final library/integration PASS, native Login saved once in UX Destination, later Simulator Billing create/search/reopen PASS. Real host/owner/site reuse remains unverified. |
| F02 iOS draft/save | A | Implemented/corrected; Swift 394/35 PASS and separate Simulator 14/14, root 1/1, creation 2/2 PASS. Actual iOS 27 Keep Editing/Discard issue fixed and retested. Physical behavior unverified. |
| F03 inline suggestions | E/G | Implemented; 185 Node and 90 full Helium/mock PASS, 2 real/signed-host skips. Real host/owner/vault approval unverified. |
| F04 notification routing | C/F/H | Implemented; Swift and final fake-native integration cases PASS. Actual APNs/macOS click unverified. |
| F05 truthful completion | C/F/H | Implemented; sent/unconfirmed/settle and reconciliation model/library cases PASS. Physical two-device outcomes unverified. |
| F06 organization | D/H | Implemented and locally validated: menu 10 PASS; native folder creation/text undo/redo, subtree reparent/readback, delete cancellation and 12-item Move/Undo PASS. Headless exact-20-ID preservation remains separate. Relaunch isolation exception excluded. |
| F07 retrieval/reveal | D/H | Implemented; final safe-search/result library cases PASS; actual native current-folder→All credentials found saved login. Ancestor edge cases remain headless evidence. |
| F08 credential use | I/H | Accepted Copy implemented; memory/proof tests PASS. Final native exact-field/30-second prompt and passphrase input guards verified; cancelled without clipboard write. Signed helper/biometrics/pasteboard unverified. |
| F09 creation | A/D/H | Implemented; models/library PASS, separate UI 14/14 + root 1/1 + creation 2/2 PASS; native Login saved once in chosen folder. No single final 16-test suite or physical/customer claim. |
| F10 Vault root | B | Implemented; Simulator 14/14 plus later root 1/1 PASS. Largest-size/dark iPhone and full-width iPad inspected. Multitasking widths/VoiceOver/measured contrast unverified. |
| F11 Agent Access | B | Implemented; model and Simulator access/provenance/revocation cases PASS. Physical Face ID and remote confirmation unverified. |
| F12 detail clutter | B/H | Implemented; library/Simulator PASS, native minimum-window/final Copy prompt and phone/iPad root inspected. Full detail/VoiceOver/contrast limits remain. |
| F13 attention | C/F/H | Implemented; passive suggestions/visible-list quieting model/library PASS. Actual OS presentation/APNs unverified. |
| F14 effective notifications | C/B | Implemented/corrected; 394 models and 14 Simulator PASS. Physical OS/APNs permission/registration/delivery unverified. |
| F15 correct account/form | E/G | Implemented; 185 Node and 90 full Helium/mock PASS, 2 real/signed-host skips. Final deny-host cases PASS; earlier harness fallback disclosed historically. |
| F16 browser recovery/update | E/G | Implemented; final backend/library and controlled mock-site rotation/reuse PASS. Real native approval/vault/site acceptance unverified; captured-save/update semantics explicit. |
| F17 goal-relevant onboarding | B/H | Implemented; final model/library/Simulator PASS and native credential first value exercised. Agent/AutoFill optional; physical iCloud/AutoFill unverified. |

## End-to-end acceptance

Current journey evidence is summarized in the [journey ledger](main-flows-validation-2026-10-17.md#journey-acceptance). The scenarios below remain the acceptance requirements; component tests do not replace them.

- **J1 first iPhone value:** open existing synthetic vault → recover from an injected file/unlock problem → credentials → optional AutoFill setup → correct account handed to a controlled target. OS handoff and actual website authentication are separate recorded results.
- **J2 daily sign-in:** focus field → choose account → authorize → fill the intended form → authenticate on the synthetic site. Repeat with locked app, missing native host, two accounts/forms, navigation during approval and popup losing focus.
- **J3 save/find/update/reuse:** create into B → leave and find by username/domain → match site → rotate test password with explicit update → authenticate again. Preserve unrelated fields; missing Website has accurate repair guidance.
- **J4 organization:** import/use fixture library → select 20 known IDs → bulk move → keep source context → verify destination → Undo → reparent subtree. Verify exact IDs and no authority/history changes.
- **J5 request to outcome:** receive A → A settles while B arrives → tap old signal → make only a valid explicit decision → distinguish sent from confirmed → refresh second device and reconcile count/alerts. No confirmation must stay unconfirmed.

## Validation and reporting

Run baseline-required formatting, lint/build and meaningful behavior suites from the isolated checkout. Share `/Users/rafalw/Dev/apassy/target` for Rust after checking free space. Only the lead/designated build owner runs Cargo. Coordinate Swift model tests and app compilation; use existing toolchain and package/deployment settings. Follow the repository's documented synthetic extension workflow and report missing browser prerequisites accurately.

Visual/interaction checks include narrow desktop window, keyboard focus/selection, iPhone/iPad widths, large Dynamic Type, accessible names and reachability. Contrast claims need measured values. VoiceOver, APNs, real-device AutoFill and two-device notification behavior require actual execution to pass; otherwise list them as unverified gates, never infer them from source or mocked tests.

Do not invent customer completion rates, time savings or retention effects. The journey analysis contains hypotheses. Any customer study, acquisition/billing/support/exit research and production telemetry remain explicitly outside this implementation's evidence unless separately performed.

Final handoff: changed behavior by journey, findings closed versus unresolved, exact validation results and limits, branch/worktree, and any concrete remaining policy/device gate. No release or merge claim.
