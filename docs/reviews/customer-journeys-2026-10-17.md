# Apassy: customer journeys and friction — 17 October 2026

## What the first audit missed

The [main-flow audit](main-flows-ux-audit-2026-10-17.md) identified screen and state-transition problems, but did not sufficiently connect them across sessions, devices, and the task outside Apassy. This supplement adds those journeys. It is an **expert, source-grounded journey analysis**, not validated customer research. Customer expectations, emotional reactions, frequency and abandonment remain hypotheses.

The central finding is cumulative friction: each application boundary can make the owner reconstruct the account, destination and unfinished task. A locally successful action does not necessarily produce the customer's outcome. A saved login may be hard to find or ineligible for its website; an imported vault may still need AutoFill setup; a sent answer may not yet be accepted by the Mac.

Two original reviewers independently checked the cross-session desktop journey and first-use iPhone/AutoFill handoffs. The main reviewer inspected desktop onboarding. Source remains the revision recorded in the main audit. This follow-up changed documentation only; no new builds, device tests, vault operations or user research were performed.

## Customers and outcomes

These are working task segments, not validated demographic personas. One person can move between them.

| Task segment | Their job | What counts as value | What should not be a prerequisite |
|---|---|---|---|
| Everyday credential owner | “Get me into the right account and keep the login usable.” | Reliable sign-in and reuse after a password change. | Connecting an agent or understanding relay architecture. |
| Owner with an existing library | “Bring my accounts over, organize them, then find them later.” | Correctly preserved credentials, useful organization, successful retrieval. | Repeating an individual Move dialog for each item. |
| Owner approving agent work | “Tell me what needs permission, let me decide, then get back to work.” | Correct decision applied to the intended request, with an honest outcome. | Browsing agent statistics or decoding transport statuses. |
| Owner adding an iPhone | “Use the credentials I already have on my Mac.” | Correct account available in the intended phone app or website. | Learning the storage transport before choosing their goal. |

Recommendation: prioritize by the selected task and keep the secondary capabilities reachable (**Mental Model**, **Progressive Disclosure**). Agent access remains useful; the feature should not define completion of a password-only journey.

## Where friction accumulates

| Friction type | Evidence from the audit | Journey consequence | Change and principle |
|---|---|---|---|
| Discovery | No field suggestions; secondary manual creation; hidden AutoFill setup (F03/F09; J1 below). | User cannot find the next action where they expect it. | Put the action at the entry context (**Discoverability**). |
| Interpretation | Transport vocabulary, empty agent sections, repeated healthy status (F10–F12). | User spends effort deciding whether irrelevant information matters. | Surface task-relevant state; disclose detail on demand (**Cognitive Load**). |
| Unnecessary entry | Late schema validation; typed tag not committed (F02/F09). | Re-entry, fake filler values, or silent missing data. | Validate visible intent and preserve the draft (**Feedback Loop**). |
| Repetition | Single-item Move with destination-following (F06/F07). | Cleanup cost grows with every item, including the return to the source. | Batch operations with exact count and Undo (**Tesler's Law**). |
| Handoff | Browser → Mac owner check → disappearing popup; Mac → Files → phone → Settings → website (F16; J1). | User has to remember the original account and resume point. | Preserve context across authorization and setup (**Recognition Over Recall**). |
| Recovery | No matches → misleading Website instructions → title/folder-limited search (F07/F16). | One failure becomes a second retrieval task with no clear return path. | Explain the known state and provide a return to the original task (**Feedback Loop**). |
| Completion/trust | Saved result hidden; sent mistaken for applied; stale alerts (F01/F05/F07). | User repeats the operation or checks another device to establish what happened. | Make the result inspectable and distinguish intermediate milestones (**Peak-End Rule**). |
| Goal mismatch | Desktop setup requires both a credential and a connected agent to appear complete (new evidence below). | Password-only owner is repeatedly pointed toward an unrelated setup task. | Complete onboarding by the chosen goal; agent setup remains optional (**Mental Model**). |

Authentication, explicit site access, choosing an account, reviewing consequential permission and checking a changed request are protective friction. Keep them. Reopening the popup, repeating a folder choice, scanning empty sections and guessing whether work finished provide no equivalent protection. **Fewer clicks is not the sole objective:** retained context, recoverability, correct action and confidence matter more (**Feedforward**, **Feedback Loop**).

## J1 — Get first value on the iPhone

**Trigger:** “I saved this on my Mac; now I need it on my phone.” Entry assumptions: an existing Mac vault, its passphrase, and the necessary iCloud access. Separate branches exist for a team vault and approve-only pairing. New Mac installation and complete migration were not walked end-to-end.

| Stage / touchpoint | What the owner is trying to do | Current demand or friction | Recovery / proposed change |
|---|---|---|---|
| Mac vault → sync setup | Make the existing vault available on iPhone. | Choose iCloud and carry the filename/location to another device. | Show the actual filename and next phone action at this handoff (**Recognition Over Recall**). |
| Phone welcome → Files | Open that vault. | Choose among transport-led labels; locate the right file and wait for iCloud if necessary. | Goal label Open Personal Vault; distinguish missing file, download and wrong-file failures (**Mental Model**, **Feedback Loop**). |
| Passphrase → biometrics | Prove ownership and decide future unlock behavior. | Necessary verification; optional biometric setup. Some recovery wording sends users back to file selection for other errors. | Keep the correct stage on error; retain explicit biometric choice and Later (**Feedforward**). |
| Imported → Vault → item | Use the account. | Completion precedes useful content; Vault adds a directory before credentials. | Open actual credentials after completion; identify the imported vault (**Cognitive Load**). |
| Apassy → iOS Settings → target app | Enable and use AutoFill. | Import did not complete this setup. User must discover General → AutoFill and perform a second app handoff. | Offer one optional Enable AutoFill action after import, with Later and accurate return-state readback (**Discoverability**, **Progressive Disclosure**). |
| AutoFill → target app | Sign in with the intended account. | Owner check and account choice remain; completion of the provider call only proves OS handoff. | Preserve the intended account/context. Verify actual authentication on a synthetic test site; do not claim it from a fill callback (**Feedback Loop**). |

**Worst moment hypothesis:** “I finished setup, but the login still isn't offered.” **Value moment:** the correct account is usable in the target app. **End/exit:** the owner returns to the task they were doing, without another tour. **Necessary recovery:** wrong passphrase stays an unlock problem; unavailable cloud file stays a file-access problem; biometric failure has passphrase fallback.

Evidence: `src/desktop/ui/sync.rs:1578`, `:1728`; `ios/ApassyCompanion/Sources/Views/Vault/ICloudVaultFlowView.swift:38`, `:67`, `:85`, `:90`; `Sources/Vault/ICloudVaultModel.swift:46`, `:89`, `:112`, `:125`; `Sources/Models/RootModel.swift:173`; `Sources/Views/Settings/GeneralSettingsView.swift:119`; `AutoFill/AutoFillViews.swift:109`; `AutoFill/CredentialProviderViewController.swift:141`. `Sources/` and `AutoFill/` here are under `ios/ApassyCompanion/`.

## J2 — Sign into an existing account during daily work

**Trigger:** a website asks the owner to log in. They are trying to use the website, not manage a vault. Expected context: the login field and the account they have in mind.

| Stage | Current path | Friction / failure branch | Proposed behavior |
|---|---|---|---|
| Recognize sign-in | Focus a username/password field. | Nothing from Apassy appears; user must remember the toolbar or shortcut. | Field-context account chooser with toolbar fallback (**Discoverability**). |
| Find the right account | Popup → app/native status → site matching. | Locked/no-vault/connection failure; missing Website produces no match; similar accounts require scanning. | Distinct recovery states; filter authorized metadata by username; Show All for This Site (**Mental Model**). |
| Authorize | Choose account → Mac owner check. | Popup may close as focus changes. This extra rediscovery is separate from necessary authorization. | Preserve the selected account and target form as context; never auto-approve or auto-fill on unlock alone (**Recognition Over Recall**, **Feedforward**). |
| Resume website | Return after authorization. | Fill can target document-order form rather than focused form; username-only fill reports generic completion. | Bind to the chosen form; announce exact result; offer same account at the second step with fresh required approval (**Feedback Loop**). |
| Finish | Submit on the website. | Apassy cannot equate fill with a valid password or authenticated session. | In controlled tests verify the account actually signs in. In product copy report only what Apassy knows (**Feedback Loop**). |

**Worst moment hypothesis:** leaving a rushed sign-in to troubleshoot the password manager. **End:** authenticated in the intended account and back to the website task; “Filled” is an intermediate product event. **Recovery loop:** keep the original site/account/field context while the owner unlocks, repairs Website metadata or retries. Abort on stale document/origin rather than retaining unsafe context. Evidence: F03/F07/F15/F16 and E03/E07/E15/E16 in the main report.

## J3 — Save now, find later, reuse after a password change

**Trigger:** a new account, an imported account needing cleanup, or a changed password. This journey spans sessions; a successful form submission is too narrow an acceptance criterion.

| Stage | Friction supported by source | Impact at the next stage | Proposed repair |
|---|---|---|---|
| Create/store | Manual path is secondary; an explicit folder can be lost on mode switch; iOS pending input can be omitted. | The owner starts with incomplete or misplaced information. | Shared destination draft, visible fields, atomic destination save where supported, accurate validation (**Mental Model**, **Feedback Loop**). |
| Confirm/find | Search/filter can hide the saved result. | The owner may recreate it or doubt persistence. | Show saved item and destination; reconcile incompatible filter with explanation (**Peak-End Rule**). |
| Return later | Desktop search excludes visible email/domain fields; browser matching needs Website metadata. Website is optional at save time. | A stored login can be hard to retrieve and absent from site matches. These are conditional branches, not inevitable for every save. | Safe identity search and visible scope; explain Website's matching role without falsely requiring it for all storage (**Feedforward**). |
| Update at website | Extension Save rejects an existing matching account; no update command exists. | The account can retain an obsolete password even after the owner tries to save. | Explicit Update Login targeting the existing account, with owner approval and preservation of URLs/passkey/TOTP (**Mental Model**). |
| Reuse | User tries the account again. | A stored or filled obsolete password still fails the customer's task. | Verify authenticated reuse after rotation; keep failure recovery linked to the account being used (**Feedback Loop**). |

**Worst moment hypothesis:** “I saved it, but Apassy cannot get me back in.” **End:** the intended account can be retrieved and used in a later session, including after its password changes. The browser outcome is conditional on external service/network availability; classify those failures separately.

This is the clearest compounding-friction chain: creation correctness + retrieval scope + website eligibility + unlock handoff + update support. Fixing only the Add sheet does not complete it. Preserve owner checks and origin scoping throughout. Evidence: F01/F02/F07/F09/F15/F16; `src/desktop/owner_store.rs:2258` optional Website; `src/desktop/owner_store/browser.rs:676` browser eligibility; `src/desktop/browser.rs:493` existing-account refusal.

## J4 — Organize an imported or growing library

**Trigger:** “Move these twenty accounts into Project B so I can find them later.” Frequency is likely episodic, but actual usage frequency is unknown. Large libraries amplify per-item repetition.

Current repeated loop: select item → detail/Folder → Move → destination → return to source → repeat. Only one item is selected; persistent search/filter and collapsed ancestors complicate verification. Existing folder create/rename/delete are present, while reparenting lacks a desktop entry point (F06/F07).

Proposed: select a range/toggle exceptions → Move to Folder once → destination + exact count → Move → stable source list, Undo and Open Folder. Folder Move preserves the subtree. This reduces clerical repetition while preserving a clear selection review (**Tesler's Law**, **Feedback Loop**).

**Worst moment hypothesis:** repeated context switches followed by uncertainty about which items moved. **End:** every intended ID is in the intended destination, no unwanted ID moved, access/history are intact, and Undo restores original locations. Twenty success messages are not proof of that end condition. **Recovery:** fail atomically when possible; show a precise partial result otherwise, never imply all moved. Do not assume folders change authorization.

## J5 — Approve a request and resume work

**Trigger:** an agent is blocked while the owner is doing something else. The interruption itself has a cost; the notification must earn it. Approve-only adoption is separate from importing a vault: Mac pairing → scan → phone verification → code on Mac → Mac verification → paired. Keep these trust steps; first accepted real request, not Paired, proves usefulness.

| Stage | Friction / boundary | Proposed behavior |
|---|---|---|
| Notice | Suggestions and genuine blocking requests can have similar urgency. | Quiet Activity/Suggestions, alert for actual work needing attention (**Banner Blindness**). |
| Open | Mac opens app without event context; current private iOS payload cannot identify an individual question and selects newest after unlock work. | Mac routes to its exact event; iOS opens refreshed Requests with explicit vault selection. Keep APNs payload private (**Mental Model**). |
| Understand | Owner must establish requester, action, scope, freshness and consequence. | Keep this protective context; disclose nonessential technical detail without hiding the authorization meaning (**Feedforward**). |
| Decide | Signed owner approval is required; content can change or expire. | Preserve digest/freshness checks, cancellation and changed-request review (**Feedforward**). |
| Resume | Sent does not prove accepted authorization, and accepted authorization does not prove the command finished. Old alerts can remain. | Waiting for Mac → confirmed outcome; unconfirmed remains explicit. Reconcile alerts at refresh; retain Activity (**Feedback Loop**, **Peak-End Rule**). |

**Worst moment hypothesis:** needing to inspect the Mac manually to determine whether the phone answer did anything. **End:** for authorization, the Mac confirms the intended decision; for the customer's broader task, work resumes or a useful blocked/failed explanation is available. Do not label these the same event. **Recovery:** request expired, answered elsewhere, page changed, Mac offline and missing receipt each have distinct results; no automatic duplicate approval.

Evidence: F04/F05/F13/F14; `ios/ApassyCompanion/Sources/Models/RootModel.swift:190`; `Sources/Views/Pairing/CodeViews.swift:40`, `:65`, `:95`; `Sources/Models/SessionModel.swift:151`. Agent and vault details remain absent from APNs under the existing contract.

## New journey finding: onboarding completion follows the wrong goal

**Verified source:** `src/desktop/ui/first_steps.rs:32` returns complete only for `credential && agent`. Lines 74–88 offer Paste Your First Credential and Connect an Agent; lines 90–115 make the first unfinished step prominent. Import is available under Vault settings (`src/desktop/ui/settings.rs:55`), but it is not offered by this first-steps panel.

**Impact hypothesis:** an owner who saves and uses passwords without agents keeps seeing an incomplete setup and a prominent unrelated task. This is a misleading completion model, **not a functional block on using the vault**. It also makes the initial experience speak to developer-secret setup before the imported-library/password-owner job.

**Recommendation:** first-use actions reflect the owner's goal: Add Login or Import Credentials; browser/phone setup is optional and contextual. A password-only setup can finish without any agent. For agent users, Connect Agent belongs to their chosen path and should end with a real authorized use. Do not add a mandatory persona questionnaire just to solve this; use their chosen entry action (**Mental Model**, **Progressive Disclosure**).

**Acceptance:** an owner with usable logins and zero agents can finish onboarding and use the library without persistent incomplete-setup messaging. An agent-oriented owner can still discover and complete setup. Imported-library completion needs actual import fidelity and first-use checks; those have not been performed in this audit.

## Revised product priority

The original package order emphasized bounded implementation fixes. Customer-journey priority needs complete useful slices:

1. **Trust prerequisites:** save destination/draft correctness and any confirmed core accessibility blocker. These apply before simplifying navigation (**Feedback Loop**).
2. **Complete account use:** field-context chooser + correct account/form targeting + recoverable unlock/no-match path + update/reuse. Improve search and Website repair where they support that same loop; do not defer the browser feature until broad UI cleanup finishes (**Mental Model**, **Peak-End Rule**).
3. **Complete organization:** batch Move, folder reparent, visible result and Undo for existing libraries (**Tesler's Law**).
4. **Complete approval:** notification → correct context → decision → confirmed result. For an agent-heavy cohort, move this ahead of organization or even account-use work; observed frequency/impact must decide (**Feedback Loop**).
5. **Simplify IA/copy within each slice:** remove redundant statuses, make optional agent setup contextual, and retain access management. Avoid a separate cosmetic redesign that leaves the handoffs broken (**Cognitive Load**).

This is a provisional ordering based on the user's stated pain and dependencies. No frequency, conversion or churn data was provided. Do not compute a numeric frequency × impact score from invented inputs. Measure task frequency, failed-journey rate, recovery effort, user consequence and evidence confidence, then adjust by segment.

## Validate journeys, including people who stop

| Neutral research task | Falsifiable hypothesis | Primary measure with denominator | Supporting measures |
|---|---|---|---|
| “Use this existing Mac vault to sign into this test website on your iPhone.” | The file and hidden AutoFill handoffs prevent first value after apparent setup success. | Authenticated completions / all eligible journey starts, including abandonment. | Stage reached; unassisted first choice; OS/app switches; recovery; time distribution. |
| “Store this account. In a later session, sign into its website.” | Destination and Website ambiguity cause deferred retrieval failure. | Correct authenticated reuse / all store-and-return trials. | Wrong destinations / all saves; browser-ineligible records / all test accounts intended for browser use. |
| “Change this test account's password, then sign in again.” | Explicit update plus preserved context reduces stale-password and recovery failure. | Correct authenticated reuse / all rotation trials. | Recovery completions / all injected recovery cases; wrong account/form / all fill attempts; retries. |
| “Move these twenty specified accounts into Project B, then undo.” | Batch operation improves effort without introducing selection errors. | Exact cleanup successes / all cleanup starts; exact restorations / all Undo trials. | Unintended IDs moved; source-return count; perceived effort; time to verified outcome. |
| “Review this request on the phone and continue your work on the Mac.” | Correct routing and receipt state reduce repeated checking and wrong-context decisions. | Correct accepted decisions / all valid decision trials. | Expired/changed trials handled safely; unconfirmed outcomes misread as success; checks on another device. |

Use test accounts and synthetic vaults. Observe first-time password owners, existing-library users and agent users separately, including those who abandon a task. Do not train them on the desired route or ask “was this easy?” before watching. Ask what they believe happened at each apparent completion. Count all starts, not only successful completions; report failure categories alongside times. These choices apply **Survivorship Bias**, **Observer-Expectancy Effect**, and **Hindsight Bias** safeguards from the requested skill.

Any telemetry needs explicit design review: collect coarse stage/outcome counts without secrets, usernames, account titles or sensitive URLs. Authentication success should be checked in a controlled test site or observed user study, not inferred from arbitrary website contents or broad browsing surveillance. No new telemetry was added.

## Coverage honesty

Mapped: existing-vault phone adoption, daily sign-in, save/find/update lifecycle, library organization and approval/resumption. Recovery branches are part of each journey, not a separate error screen inventory.

Not established: acquisition promise and positioning, purchase/billing, complete first-install/import fidelity, every recovery/restore scenario, support experience, export/migration out, long-term retention, actual emotional responses or drop-off. Source review cannot complete those customer-research areas. No customer interviews, support-log analysis or measured completion study has occurred here.

The emotional low points above are testable hypotheses, not customer quotes or scored observations. Validate them before claiming reduced friction, faster completion or improved retention.
