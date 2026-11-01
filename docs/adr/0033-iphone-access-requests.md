# ADR 0033 — Answer access requests from the iPhone

Date: 2026-11-01.
Status: implemented for review, based on Connect onboarding #41 at `8e61e04`. Synthetic Rust/Core/Swift and Simulator acceptance is recorded with this implementation. Physical Face ID/Secure Enclave and notification acceptance remains pending; no release or deployment is authorized.

The owner decided: the iPhone can **Deny**, or **Allow once** after fresh Face ID. Durable access grants stay Mac-only. Local Mac answers remain available.

Contract: [relay-access-request-v1](../contracts/relay-access-request-v1.md).
Delivery: [implementation plan](../design/implementation-plan-0033.md).

## Context and evidence

This design reads app commit `0b103687689e9a61f4a13c8d8c2e333587f65456`, the separate audit files under `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/`, and the read-only relay checkout `/Users/rafalw/Dev/apassy-relay-release-056/src/server/questions.rs`. It does not establish deployed behavior or device acceptance.

The external `relay-audit.md`, F11, in the audit directory above identifies the missing access-request journey. Its sibling `approvals-frequency.md` distinguishes run approval (M16), remembered/project/production answers (M17–M22), durable access changes (M23), and remote answer verification (M37–M38). These audit files are not present at the pinned main tree; the paths identify read-only evidence, not new deliverables. The actions must not become aliases for one another.

### What exists today

| Aspect | Access request | Run approval |
| --- | --- | --- |
| Entry | `apassy_request_access`; `Action::RequestAccess` in `src/agent/{mcp,wire}.rs`; `src/broker/decide.rs::request_access` | `apassy_run_with_secrets` and other broker operations that need an owner decision |
| Data | `access_request`: local integer id, agent id, item id, reason, optional absolute cwd, creation time, `open/granted/denied`, decision time. Joined agent/item names in `AccessRequest` | `PendingRun` and `QuestionInfo`: command, user request, credential revisions/bindings, project, action, hosts and offered answers |
| Waiting | A persistent local vault row, excluded from sync by `src/vault/merge.rs`. The MCP call returns immediately. No request deadline, action, hosts, item revision, or one-use permit is stored | In-memory `ApprovalQueue`; the broker operation waits, normally for 300 seconds; relay questions mirror this queue |
| Deduplication | `src/vault/access.rs`: one open row per agent/item, first reason/cwd retained, at most 20 open per agent; cleaned reason at most 500 bytes | One waiting question per agent; same-operation retry can join the existing question |
| Mac answer | Owner CLI `request list/grant/deny`; `OwnerRequest::GrantRequest` becomes a fresh `ChangeGrant` proof, then `OwnerSession::grant_access_request` calls `set_exec_grants`. This writes durable `exec_grant` state and marks the row granted. Denial is ungated | Decisions and owner CLI apply an exact queue answer; ordinary Allow once saves no grant |
| iPhone today | `RequestsAccessRow` shows Wi-Fi companion access requests and Deny, with “Review access on Mac.” ApassyCore relay questions carry runs, not these rows | Relay `QuestionDetailView`, `QuestionsModel`, and ApassyCore support signed run answers |

The Requests section in `src/desktop/ui/decisions.rs` currently lists **requests to add a missing credential** (`CredentialRequest`, ADR 0025 §6), not `AccessRequest` for an existing item. This design adds a distinct access-request section; it must not reuse the credential-paste form.

An important historical limit: since ADR 0025 and [ADR 0031](0031-bouncer-decides-by-default.md), a connected agent normally needs no process grant. `run.rs::check` does not consult one for normal execution. The current MCP response explicitly calls an access request a note and points agents with `can_use` to the run tool. Absence of an `exec_grant` is **not** evidence that the credential is blocked. Never/Only-these-items restrictions still hide credentials; `request_access` cannot enumerate or request a hidden item. A missing secret belongs to `apassy_ask_owner_for_credential`.

### Related decisions and Connect

- ADR 0019 supplies relay device identity, not owner consent or authority from relay roles.
- ADR 0020 originally allowed phone denial of access requests, not granting. ADR 0024 allowed first-use **run** approval once on the phone. ADR 0025 expanded run-question answers; none implemented remote access-request consent.
- ADR 0028, read in `/Users/rafalw/Dev/apassy/docs/adr/0028-retire-wifi-companion.md`, proposes retirement and explicitly leaves access-request transport missing. It is absent from the pinned main tree. This ADR resolves its stage-2 deny/allow-once choice only; it does not accept or implement Wi-Fi retirement.
- [ADR 0030](0030-owner-check-window.md) keeps remote answers fresh and outside the local verification window.
- Connect onboarding merged as #41 before implementation; see [ADR 0032](0032-connect-onboarding.md). The following paragraph records the original design inspection: onboarding was being built on `feat/connect-onboarding`. Its worktree has uncommitted `src/relay/{connect,pairing}.rs` and `src/vault/connect.rs`, but no ADR 0032 file at inspection. `prepare_connect/create_connect` stage a stable questions-only membership; `PairingChannel` and `adopt_question_handoff` hand the question key and trusted rows to the confirmed iPhone without uploading an iCloud vault snapshot. This design consumes that result and preserves its separate handoff dispatch. These are observed work-in-progress interfaces, not a claim of completion. Implementation lands after Connect and reconciles its final interfaces.

## Decision

### 1. Add an access-consent type, separate from run approval

Use an encrypted, explicitly discriminated `access_request` card through the questions carrier. It has its own digest, card signature, answer signature and settle grammar. Never synthesize a `PendingRun`, call `ApproveRun`, or map phone Allow once to `ChangeGrant`/`ApproveInProject`/`AllowProduction`.

Versioned scoped requests add a concrete project, one action (`read/change/deploy/delete`) and an exact destination-host set to the existing MCP input. The Mac resolves project identity and snapshots the actual item revision, binding/delivery and policy. Agent-supplied scope is a claim that the broker validates again at use. Missing/ambiguous project, action or hosts permits **Deny only** remotely; the card explains what is missing. Never infer scope from reason prose, use an “any project/host/action” wildcard, or make an unscoped legacy note into authority.

Existing legacy rows remain local notes until explicitly dispatched from the Mac. New scoped requests expire 300 seconds after creation. Dispatch of a legacy note creates a new 300-second, deny-only incarnation. Neither a retry nor a duplicate extends expiry. The request remains asynchronous: the agent checks status, then explicitly attaches the allowed request id to its next matching run attempt. Non-creating status and cancellation calls are required. A lost response/disconnection is not abandonment; an agent that gives up explicitly cancels. Cancellation invalidates an open request or an unused/pending admission without rewriting an accepted answer or recalling a released value. Ordinary `can_use` agents should continue to use the direct run path.

### 2. What Allow once authorizes

It issues a memory-only `AccessOncePermit` on the asking Mac, for **one explicitly referenced, broker-checked use attempt** by that agent with that item revision, project, action and hosts, before the original request expires. No secret or bearer permit travels to the phone, relay, or agent. Knowing a request id gives no authority without the authenticated agent and matching live permit.

The permit is access consent, not execution consent. The broker:

1. Requires the request reference on the use call; it never silently selects a permit for another concurrent operation. V1 permits one item in that referenced operation.
2. Rechecks the live vault epoch, agent/token, item revision, process binding, declaration/policy snapshot, canonical cwd/project, hard-classified action and complete detected hosts against the approved scope. Unknown scope or any difference refuses this attempt.
3. Atomically burns the permit at admission, before the run proceeds, with one winner among concurrent calls. The permit is not restored after model refusal, timeout, spawn failure or cancellation. V1 adds no execution idempotency key: every repeated use after admission, including identical text after a lost response, is unavailable/consumed. Query status; never infer a safe operation join from command equality or bypass consumption through the ordinary waiting-question retry path.
4. Runs the normal ADR 0031 checks and bouncer decision. Production, Always ask, missing user request, command-analysis flags and all other existing vetoes still ask/refuse as before. A later run question is a separate execution decision; the access answer cannot resolve it. The admitted operation retains an epoch/revocation/deadline fence and rechecks it immediately before credential preparation/delivery and process spawn. A run question cannot extend the access deadline; expiry while it waits refuses the attempt. Authority already delivered to a running process cannot be recalled.

This adds no bypass for Never, Only-these-items, archived/restored items, missing bindings, OTP setup keys, revoked agents or host restrictions. On the current default route, missing process-grant state needs no bypass: the permit records and limits this explicit consent without pretending to unlock a previously forbidden operation. Supporting a hidden/restricted credential would require a separate visibility/exception design; it is excluded here. If a future adapter requires access consent, it consumes this same permit at its admission boundary, not through a durable grant.

For a placeholder, enforce the approved exact host/port set and deadline/revocation fence at each proxy substitution, intersected with the binding's existing host policy. Existing `HostRule::covers` also permits subdomains and cannot implement this new exact boundary unchanged. A redirect, dynamic destination or later request must not release the value to an unlisted subdomain/port or after the deadline. This does not restrict all process networking or recall a value already received by a service. With a real value, the process can use it beyond reviewed destinations; static command classification and supported script binding are bounded checks, not proof of arbitrary program behavior or transitive dependencies. The card must disclose this limit. One attempt means one admitted operation/process, which can make multiple network calls; it does not promise one API call or a bounded amount of work.

No `exec_grant`, agent exception, owner execution answer, remembered pattern, production allowance, evaluation permission, or declaration change results. A model allow also creates none. The phone says **“Allows one scoped use attempt. The bouncer still checks the command and may ask you.”** This deliberately avoids promising that an unreviewed command will run.

### 3. Card authenticity and limits

The Mac builds facts from its vault and broker, signs the complete card with its trusted Mac `sign_key`, then seals it with the existing question key. Shared-key encryption alone authenticates a vault-key holder, not the particular asking Mac; the additional signature authenticates that source. The iPhone verifies the Mac's live trusted row and exact questions-team device mapping before display and again before preparing an answer. The relay device list is not a key source.

The card covers: request/incarnation id, asking Mac and actual `sync_meta.vault_id`, authenticated agent id and host-label provenance, credential UUID/local id/title/revision, environment and delivery mode, project key/label and canonical folder, action, all hosts, agent reason, scope provenance, creation/expiry, and the two permitted choices (or Deny only). Check the vault id against the selected phone context as well as team/key/trust mapping. The title, reason and folder can contain attacker-influenced text even when Mac-signed. The signature proves what the Mac presented, not that the agent told the truth. Plain text only, separate “The agent says” attribution, unambiguous control/format-character escaping, no tappable links or agent-selected button labels.

The registered agent name and a stored connection label do not attest the running executable. `SubmitUserRequest.host` is explicitly a label in the existing wire format; an agent can claim “codex”. Always show the Mac-authenticated agent id beside the name, mark claimed host text **“Agent-reported host (not verified)”**, and expose exact item/Mac identities for ambiguous labels. At request time no command exists: **“Requested scope; checked against Mac policy”** means normalized/eligible scope, not verified intent or detected destinations. Display destination A-labels as ASCII; do not hide punycode behind a Unicode-only friendly name. Require successful canonicalization and lossless path identity before offering Allow once; a fallback/lossy `project_of` label is insufficient.

Critical scope is never silently shortened for signing or dropped to fit. Names/reason have bounded cleaned display copies; exact identifiers, revisions, scope and policy stay bound. Full project path and all canonical hosts remain readable in the detail. Unknown revision, unsupported delivery, malformed scope, too many hosts or an oversized card means local review; it never broadens scope. No credential values, hidden details, notes, tokens, secret-bearing URLs or command output are included. Agent prose cannot be guaranteed secret-free; bound and redact known secret values locally before export, and state that residual risk.

The contract stays within questions plaintext caps: card 32768, answer 8192, settle 1024 bytes. If a complete card cannot fit, show on Mac: **“Review this access request on this Mac. It could not be sent to your other devices.”**

### 4. Answer authentication

| Answer | iPhone signature | Face ID | Effect on asking Mac |
| --- | --- | --- | --- |
| Deny | Registered device `sign_key` | None; the Requests vault/context must still be unlocked | Terminal denial; gives no authority |
| Allow once | Registered per-team Secure Enclave `answer_key` | Fresh match for this exact answer, current biometric enrollment, no passcode fallback or reused unlock context | Terminal access answer and one memory-only permit |

The “device key” for Allow once means the biometric-protected **answer key**, not the relay sign-in key. `sign_key` must fail for Allow once; `answer_key` must fail in the Deny verification path. The Mac verifies the answer itself through a new narrowly typed owner action/check; no relay claim that “Face ID passed” is accepted. As today, the signature proves use of the registered protected key; protection enforcement is on the iPhone, not remotely attested by each signature.

Prepare immutable signed bytes before the prompt. Use a new authentication context with zero reuse duration, invalidate it after completion, and discard late results on background, lock, vault switch, expiry, changed card or lost membership. A cancelled match sends nothing and leaves Deny available. A changed biometric enrollment requires reconnecting the answer key through the Mac's confirmed device flow. Bounded retries may resend only the same signed choice before its original freshness deadline; a new choice or expired signing attempt requires a fresh match initiated by the owner.

The private Secure Enclave key itself must require `.privateKeyUsage + .biometryCurrentSet`, with no `.userPresence`/passcode alternative. Checking Face ID in the UI before an unprotected signature is insufficient. [Apple's current-set flag](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) accepts Face ID or Touch ID; require `.faceID` explicitly for this owner's Face ID-only choice. A Touch-ID-only iPhone offers Deny/local review. Extend the existing signer API with cancellation so lifecycle events call `LAContext.invalidate()` while the match is pending; merely ignoring an async result cannot stop the prompt. The Mac trusts the confirmed app's key creation: a P-256 signature is not remote attestation of the hardware/ACL. Reconnect/key/mapping changes fence old permits as well as later signatures.

The answer binds the exact request id/incarnation, vault id, team, asking/answering devices, card digest, agent, item UUID/revision, project, action, hosts and request expiry. Timestamp acceptance is `now-55 <= time <= now+5`, with `created_at <= time < expires_at`, and is checked again at commit. This replaces the ambiguous symmetric ±60-second rule with a 55-second past-age bound and 5-second future allowance; it assumes honest signing clocks within that skew bound. Retry only before `min(time+50, expires_at)`; detected clock jumps fail closed. Authority ends at request expiry and the Mac's sleep-inclusive deadline even if the signature is younger. Long biometric prompts need new preparation and a new match.

The relay appends even an identical answer POST; it provides no answer idempotency. Serialize submissions and cap total POST attempts at three per device/qid, counting uncertain responses and alternative choices. Once a POST succeeds, wait for settlement instead of resending. Exhaustion shows unconfirmed/local review and never silently renews a request or re-prompts Face ID. The arbiter still prevents duplicate permits if multiple copies arrive.

### 5. First accepted answer wins

The asking Mac is the sole authority. Local Mac, owner CLI, existing companion denial and iPhone relay handlers all use one request arbiter under the same vault/session lock and transactional compare-and-set. The first **valid answer committed there**, before expiry, wins. This is not tap time, relay arrival time or relay `settle` time. Invalid signatures never win. The relay can delay/reorder answers; global fair ordering cannot be promised.

Persist the terminal answer, answering device and audit record; install a permit only while holding the arbiter lock, after commit and before releasing the lock. Persistence or installation failure gives no permit. Crash/restart cannot reconstruct authority from an accepted answer: an unused permit is lost. A durable Mac grant answering a still-open request uses the same transaction and arbiter; a losing stale grant dialog must not write a grant.

Send a Mac-signed, encrypted settle after the local transition, with the exact winning device, choice and outcome. Both surfaces show **“Answered on <device>”**, and Allow once says **“Consent recorded for one attempt before <time>”**. The phone also says **“Check on <Mac> for remaining availability”**: an immutable receipt cannot establish whether the permit is still unused, cancelled, invalidated or lost after a crash. Only the asking Mac has live permit status; a second settle cannot update it. Submission shows **“Sent. Waiting for <Mac> to confirm.”** A relay receipt, `409`, dropped row or unsigned relay state never becomes “Allowed.” Without a verified settle, show **“Not confirmed. Check on <Mac>.”** Expiry ends buttons; an unconfirmed late receipt cannot reopen them. Receipt history distinguishes the access answer from whether an eventual command ran.

`open -> allowed_once/denied/granted_on_mac/expired/invalidated` is terminal. Permit state is independently `available -> consumed/expired/invalidated`. The winner cannot be overwritten by a later denial. A new owner revocation or stricter policy can invalidate an unused permit without rewriting the original answer. A local durable grant made as a separate new action remains possible; it is not a second answer to a closed request.

### 6. The local Touch ID window stays separate

The new remote check neither consumes nor starts/extends ADR 0030's window on the asking Mac. A second biometric on the Mac is not needed to accept a valid phone signature. Deny uses no window. The new local access-consent action requires fresh local verification in v1; ADR 0030's covered agent Allow once refers to exact waiting-run approval, not this new pre-run consent. Durable grants always require fresh local verification and cannot be requested by any access-card phone payload. Existing run-question answer policy is not widened or removed by this ADR.

### 7. UX specification: Requests access detail

This is a single-screen component specification, using the UX skill's screen-spec structure. The owner opens Requests or a generic notification, possibly hurried or uncertain about the agent; the goal is a knowledgeable decision, not a higher allow rate. Connect handles connection setup before this journey.

- **Purpose:** decide one existing-credential access request. One primary action: **“Allow once”**, only with complete scope. **“Deny”** is equally reachable, separately spaced, and never requires biometric verification (**Hick's Law**, **Fitts's Law**).
- **Hierarchy:** “Access request”; “<agent> (id <id>) asks for <credential>”; vault and “Asked on <Mac>”; host-label provenance; environment/delivery warning; project label plus full folder; requested action and every ASCII host with “Requested scope; checked against Mac policy”; “The agent says: <reason>”; actual expiry time; the one-attempt explanation; Allow once and separate Deny. Do not copy the run-detail durable-action bar (**Visual Hierarchy**, **Recognition Over Recall**).
- **Defaults/trust:** no preselected answer, approval swipe or notification action. Show “Real value reaches the process” or “Placeholder restricted to these hosts” from the binding. For a real value, hosts are reviewed destinations, not a network-confinement guarantee. For absent scope show “Review access on <Mac>: this request does not specify <fields>” and Deny only (**Feedforward**).
- **States:** loading is non-actionable; empty says “No access requests waiting”; unreadable/unsupported says “Update or sync this vault to read this request”; Face ID cancellation restores the same card; network failure retains its immutable answer for bounded retry; sent is pending; only a verified settle confirms; expired/invalidated disables both answers. Backgrounding clears sensitive content and cancels in-flight signing (**Feedback Loop**).
- **Accessibility:** semantic Dynamic Type, VoiceOver reading order matching the facts, complete hosts/path available without truncation, 44-point targets, text/icons as well as environment color, Reduce Motion, native Back/Done. Do not announce a countdown every second. The real deadline is neutral information, with no urgency animation (**Fitts's Law**, **Cognitive Load**).
- **Ending:** confirmed Denied, or consent recorded with its original deadline, live-status limitation and the bouncer explanation; **“Done”** exits. No available/unused permit badge based only on a settle, celebration or claim that a command succeeded. A user can invalidate an unused permit on the Mac; a consumed attempt cannot be undone (**Feedback Loop**, **Provide Exit Points**).

Ethics check: no conversion target, default, artificial urgency or authority claim from agent text. Deny and exit are as easy as Allow; the real expiry is disclosed; one-use authority is bounded and cancellation before sending is harmless. Measure wrong-scope decisions, comprehension, cancelled Face ID and unconfirmed receipts, not allow rate. Test neutral scenarios including owners who deny or abandon. Expected emotional path: uncertain entry `-1`, understood facts `0`, pending receipt `-1` softened by explicit status, confirmed result `+1`; these are hypotheses, not measured user results.

### 8. Threats and bounds

| Threat | Control | Residual risk |
| --- | --- | --- |
| Stolen unlocked iPhone | Fresh biometric-protected answer-key signature per Allow once; no unlock-context reuse or notification approval; revocation checked on Mac at answer and consumption | Thief can read already-unlocked request metadata and sign Deny, causing denial of service. Full phone/app compromise or coercion is outside the biometric guarantee |
| Compromised relay/edge | End-to-end ciphertext; source-signed card/settle; scoped answer signatures; trusted-vault keys and strict device mappings, never relay role authority | Outer team/device/routing ids, qid/key id, expiry, sizes, timing, IPs and push metadata remain visible; drop, replay, reorder and capacity denial remain possible |
| Spam/prompt fatigue | One active access request or unconsumed permit per agent, exact-scope coalescing, fixed expiry, creation and notification limits; local fallback | Multiple connected agents can exhaust a vault's bounded budget. Relay limits are aggregate and must not be increased to hide this |
| Misleading agent | Broker-built facts and provenance, Mac card signature, text escaping, plain-text reason, no agent labels/buttons; recheck at use | A signed card can still contain a plausible lie. Folder identity supplied by an agent and real-value delivery retain ADR 0025/0031 limits |
| Replay/race/stale authority | Random incarnation, scoped signatures, 55-second past-age/5-second future-clock bound, transactional first-winner, atomic permit burn, epoch and revision fences | A relay can choose which valid remote answer reaches the Mac first. A timeout cannot prove the earlier answer failed |
| Vault-key holder compromise | Mac/device signatures and current trusted rows add source checks | A vault holder can alter trust rows; Mac signing keys are usable with the vault unlocked. This does not defend a compromised trust root |

For v1 on **each asking Mac's local vault**: one active access request/permit per agent; five new requests per agent per rolling hour; twenty per local vault per rolling hour; ten open access requests. These counters do not sync, so twenty/hour is not a cross-Mac guarantee. Duplicates neither count as new nor create another dispatch. A changed scope while one is active is refused without mutating the displayed card. Denial/expiry/cancellation/failed publication/restart does not reset or refund hourly/cooldown counters; wall-clock rollback must not replenish them. Reserve budgets atomically before publication. One logical publication per incarnation (bounded retries keep the same qid/body), with a 30-second per-agent cooldown for new dispatches; actual relay/APNs notifications may duplicate, collapse, drop or retry. All types share the existing relay question budgets; multiple Macs can exhaust them, while a local safety question must remain answerable.

### 9. Relay impact and compatibility

No relay production code, schema, endpoint, outer version, routing value, limit or APNs payload change is required. Existing questions handlers validate only the outer v1 envelope, byte sizes, routing and lifetime; answers are append-only until the asker settles. Put type, scope, signatures and outcomes **inside** ciphertext, using the existing card/answer/settle AAD. Use `to: member`; cross-member/team approval is excluded until vault-authenticated roles and shared-key distribution are designed.

This reuses a specific existing push behavior: fixed **“A question is waiting”**, sound, `interruption-level: time-sensitive`, one shared `apassy-question` collapse id, and **no request/vault id or inner type**. A notification tap opens/refetches the Requests inbox; only selecting a verified row can navigate to an exact request. No generic tap may choose the newest request. There is no access-specific quiet class or exactly-once delivery guarantee. A quiet class, exact-card push link, or distributed access-only quota would need a separately scoped transport/coordinator design. No-relay-change is viable only with these disclosed limits. Expiry also prevents late settle publication, so a near-deadline local answer may remain unconfirmed remotely.

Keep `relay-feed-v1`'s reserved `grant_request` unused. A feed action is not a timed question and must not become a grant shortcut. No change to run-card schema, digest v2, answer strings or legacy companion approval wire is authorized. Updated clients dispatch the new inner protocol; old strict clients show their existing unreadable/update state and have no answer buttons. They must never reinterpret the new card as a run. Unknown/new phones and old Macs retain local Mac fallback.

Connect must provide the questions purpose, vault question key, per-team device mapping and Mac-confirmed iPhone answer key before Allow once is enabled. No capability boolean from the relay substitutes for those checks. Until that dependency is verified, the product stays local rather than inventing another pairing mechanism.

## Consequences and remaining review items

This resolves remote access-consent choices without changing durable authority. It adds a small request lifecycle/permit subsystem and a new protocol parser on both clients. It can involve a later separate run question because access consent is not execution consent. It intentionally does not manufacture useful access out of a missing legacy grant when the modern broker already allows an attempt.

Implementation review items remain, with defaults specified so they do not block this draft:

1. **Connect's final integration surface:** consume ADR 0032's confirmed membership/trust interfaces; recommendation: reconcile names and paths after its merge, with no duplicate onboarding or permissive fallback.
2. **Notification policy before rollout (owner):** accept per-Mac budgets and inherited generic time-sensitive pushes, or require coordinated quotas/quiet delivery that need a separate design. Recommendation: keep the disclosed carrier behavior and conservative local budgets for initial opt-in use, measure redacted aggregate counts and owner comprehension, and retain local-only fallback. Do not promise a global twenty/hour cap, expand relay limits or expose card contents in telemetry. The core Deny/Face ID/one-use/Mac-only durable choices are already decided.
