# Relay access-request contract v1

Date: 2026-11-01. Status: proposed; no implementation claimed.
Decision: [ADR 0033](../adr/0033-iphone-access-requests.md).

This is a new **inner protocol** over the unchanged [relay questions v1](relay-questions-v1.md) carrier. It is not an extension of the run `Card`, run digest v2, feed `grant_request`, or the durable grant API. MUST/MUST NOT below are implementation requirements.

## 1. Carrier, trust and versioning

Reuse questions sections 4–6 and 10–16 for sign-in, team membership, question keys, ChaCha20-Poly1305, nonce generation, outer request bodies, AAD, routing, long polling, error handling and retention. The [sync contract](relay-sync-v1.md) encodings apply. The [feed contract](relay-feed-v1.md) remains unchanged.

- Outer `v` remains `1`. Card post fields remain exactly `v,qid,to,expires_at,key_id,nonce,ciphertext`; answer and settle posts remain `v,key_id,nonce,ciphertext`. No access type, credential name, agent, project, action, hosts or answer choice appears in clear outer metadata.
- Card AAD remains `apassy-question-v1\0card\0<team>\0<qid>\0<key_id>\0member\0<expires_at>`. Answer AAD remains the questions `answer` form with stamped answering relay device id; settle AAD remains the questions `settle` form. No trailing NUL.
- Use `to: "member"` only. Before accepting any answer, the asking Mac requires a live vault `trusted_device` with an **exact** `relay_devices[team]` mapping equal to the stamped sender. Missing mapping fails closed; relay-provided roles never authorize an access answer.
- New plaintext uses `protocol: "apassy-access-request"`, `v: 1` and `part: card/answer/settle`. These three fields MUST be parsed before dispatch to a type-specific parser. Run plaintext has no such protocol and keeps its existing parser. Unknown protocols/versions/parts never fall back to run approval or grant APIs.
- Connect's in-progress `PairingChannel` uses a reserved handoff key marker and its own QR-capability key/AAD. Preserve its dedicated pre-card dispatch; never pass handoff records to a run/access parser or offer them as owner decisions. Access dispatch uses only the vault's real question-key id. Reconcile the final marker/route with ADR 0032 after merge.
- Every object rejects duplicate, unknown and missing fields; every enum rejects unknown variants. Canonical b64u without padding, lowercase hex, finite bounded integer values and UTF-8 only. No permissive JSON-to-map round trip that silently discards duplicate keys.
- Changing fields, digest bytes, signature bytes or semantics requires a new **inner** version/domain tag, not changing the outer questions version. An old strict client cannot parse these cards and shows its update/unreadable state, with no actionable run controls.

The question key remains in the vault; it is not sent to the relay or APNs. The asking Mac caches the key of a live request only for its bounded lifetime. Current trusted-device revocation checks are still required even if an old envelope decrypts.

## 2. Identifiers and local source

| Value | Form and meaning |
| --- | --- |
| `qid` | Fresh 16 random bytes, canonical 22-character b64u. One dispatch incarnation; never reused |
| `request_id`, `agent.id`, `item.local_id` | Positive canonical decimal strings within u64, meaningful only on the asking Mac in that vault; never used to find another device's local item |
| `item.uuid` | 32 lowercase hex characters, as feed item references. Missing/invalid UUID means local-only review |
| Device UUID | 36 lowercase characters, questions trusted-device UUID form |
| `vault_id` | Exact 36-character lowercase `sync_meta.vault_id`; never the display name or a phone-local vault handle |
| `revision` | Canonical decimal string of the Mac's item revision; exact match required at use |
| `digest`, `policy_digest` | 64 lowercase hex characters, SHA-256 |
| Times | JSON integer Unix seconds in `0..=2^53-1`; strict expiry is `now < expires_at` |
| `project.key` | Exact broker project identity from `project_of`, common git directory for worktrees; not merely a label. `cwd` is the resolved canonical directory |

The source is a new versioned local request record, not a synthetic pending run. It retains vault id, request id, qid, epoch, scope, immutable serialized card bytes/digest, creation/expiry, current state and terminal receipt. Agent, request and permit rows never sync; the encrypted card is their remote projection. Item lookup at consumption uses both UUID and local id plus revision, never a phone's local numeric id. Counters, tombstones and operation identity are local to this asking Mac; they are not a distributed vault-wide coordinator.

New MCP input extends `request_access` with optional `scope: {"action":"read|change|deploy|delete","hosts":["api.example.test"]}`; existing `cwd` must be present to produce an allowing card. The current parser rejects extra fields, so `mcp.rs`, tool schemas, `wire.rs`, broker and tests must change together. New callers MUST NOT send scope until supported by the installed tool schema. No separate feature probing may create a request. Run input gains optional `access_request_id` solely to consume a permit with the current authenticated agent; it is not an authorization token. A referenced v1 operation contains exactly this one credential.

Also provide agent-authenticated, non-creating status and cancellation operations for an exact `request_id` (tool names/DTOs frozen in unit A). Cancellation takes the same arbiter as answers and use: an open request becomes `invalidated`; an allowed request keeps its terminal answer but loses its available permit or pending admission fence. Cancellation cannot recall an already released credential. Repeats are idempotent, do not spend creation budget and reveal no other agent's requests. A disconnected MCP call or lost response is not cancellation: these requests are asynchronous. If the agent abandons its task it must cancel; otherwise the unused allowance can remain until the original deadline. Neither a late answer nor a retried use may undo cancellation.

Legacy calls without scope retain their asynchronous note behavior and cannot create a permit. Existing legacy notes are not automatically broadcast or expired on upgrade. Explicit Mac dispatch assigns a new qid and fixed 300-second deny-only incarnation. An incomplete new scoped request may be dispatched deny-only; it never silently chooses a project, action or host wildcard. A new scoped request has a fixed 300-second lifetime from creation.

## 3. Signed card

The encrypted card plaintext is exactly:

```json
{"protocol":"apassy-access-request","v":1,"part":"card","body":"<b64u exact UTF-8 body bytes>","digest":"<hex>","signature":"<b64u DER>"}
```

Decoded `body` is exactly the following object shape. Example values are synthetic; the example is structural, not a cryptographic vector.

```json
{
  "vault_id": "d070dc14-a3ac-42c2-95aa-cc85d6d58900",
  "team_id": "t_7k2m5q4x3c",
  "qid": "oKGio6SlpqeoqaqrrK2urw",
  "key_id": "630dcd2966c43366",
  "to": "member",
  "request_id": "81",
  "asker": {"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","relay_device_id":2,"name":"Test Mac"},
  "vault_name": "Synthetic vault",
  "agent": {"id":"4","name":"Test agent","host":"codex","host_source":"agent_claimed"},
  "item": {"local_id":"7","uuid":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","revision":"12","name":"Test API key","environment":"development","delivery":"placeholder","binding_name":"API_TOKEN"},
  "project": {"key":"/tmp/synthetic/.git","label":"synthetic"},
  "cwd": "/tmp/synthetic",
  "action": "read",
  "hosts": ["api.example.test"],
  "scope_source": "agent_requested_mac_checked",
  "reason": "Read synthetic service status.",
  "policy_digest": "<hex of current authorization snapshot>",
  "created_at": 1790000000,
  "expires_at": 1790000300,
  "valid_answers": ["deny","allow_once"],
  "local_review_reason": null
}
```

| Field | Rules |
| --- | --- |
| Identity/header fields | Must equal the outer record, current questions membership and live trusted Mac row. The exact relay mapping must exist; `asker.name` is the Mac-confirmed display name |
| `vault_name` | Display label from Mac; selection identity remains the phone's exact vault context, team, asker UUID and qid, never a name |
| `vault_id` | Equals the selected vault's sync identity, at display, answer preparation and receipt verification; team/key/name equality alone is insufficient |
| Agent/item names | Mac-read, cleaned bounded display text; identity is the separate immutable ids. Display the agent id beside its name and make exact Mac/item ids inspectable. Stored labels can originate with an agent, including agent-created credential titles; they are not attestations of a program or provider |
| `agent.host`, `agent.host_source` | Nullable host display label and Mac-assigned provenance: `mac_connection_label/agent_claimed/unknown`; unknown requires null. A connection label is not executable/process attestation. Caller-supplied host/session text is `agent_claimed`, displayed as “Agent-reported host (not verified)”; it cannot select another agent identity. The authenticated agent/token generation is retained in the Mac-local snapshot |
| `item.environment` | `development/staging/production/unconfirmed`; restrictive source state is included in `policy_digest` |
| `item.delivery` | `real_value/placeholder`; derived from actual process binding, never agent-selected. Unknown mode makes dispatch local-only |
| `binding_name` | Actual environment variable name, not value; valid existing binding required |
| `project`, `cwd`, `action`, `hosts` | Concrete scope, or nullable fields for deny-only cards. `hosts` is a sorted unique list, never null; empty is incomplete and deny-only. Missing project/action is JSON null; absent cwd is empty text. Require successful filesystem canonicalization and lossless UTF-8 identity; `project_of`'s fallback or lossy path text cannot authorize. Display escaping must preserve distinctions between literal escapes and escaped controls; never compare sanitized labels as paths |
| `action` | Exact `read/change/deploy/delete`; at consumption the broker must obtain the same certain action using its hard classification. Unknown/fallback classification cannot match a permit |
| `hosts` | 1–16 exact canonical destinations for allowing cards. Use existing broker host parsing, lowercase ASCII/IDNA A-labels and explicit non-default ports; no wildcard, scheme, path, userinfo, control character, IP ambiguity or invented DNS equivalence. Sort by ASCII bytes, reject duplicates. Reuse one normalizer on request and run paths; a host the binding/policy would forbid stays forbidden. Show ASCII A-labels, not Unicode alone. Exact scope equality MUST NOT use `HostRule::covers`, which also accepts subdomains |
| `scope_source` | `agent_requested_mac_checked` or `legacy_incomplete`. The Mac checked existence, normalization and policy eligibility only; no command exists yet. Display “Requested scope; checked against Mac policy”, not “verified command/intent/destinations”. Recheck actual detected action/hosts at use |
| `reason` | At most 500 UTF-8 bytes after control/format escaping and known-secret redaction, displayed as “The agent says”. Empty after redaction is allowed on the card, never filled from a secret field |
| `policy_digest` | Opaque Mac-local SHA-256 snapshot of all authorization-relevant item/binding/declaration/source, agent restriction and project state used by the request. Use the fields of the broker's authorization baseline, with a dedicated versioned explicit serializer frozen in unit A; do not make the current Debug-based `baseline_of` representation a wire standard or hash only item revision. It changes when these policies change, and consumption compares it as well as revision. The phone authenticates this value through D; it does not rebuild private Mac policy |
| Lifetime | `expires_at = created_at + 300`; no renewal. For legacy dispatch `created_at` is dispatch time, with original note time retained locally. The relay accepts only a remaining lifetime greater than 10 and at most 600 seconds; do not extend expiry to make a late post pass |
| Answers/reason | Exactly `["deny","allow_once"]` for complete eligible scope; `["deny"]` otherwise, with a bounded nonempty Mac-generated `local_review_reason`. No field may add durable choices |

Limits: body at most 20000 bytes; names at most 128 bytes (device/agent 64); variable at most 128; project key/cwd at most 4096 bytes each, project label 256; review reason 256. Total encrypted-card plaintext including base64 body, signatures and framing MUST still be at most 32768 bytes. Reject excess instead of truncating a scope or dropping a host. Body text may contain JSON escapes, but signed bytes are exact: receivers MUST NOT parse then reserialize to verify.

### Digest and signature bytes

Let `F(x) = u32_be(byte_length(x)) || x`. Text is exact UTF-8; `H(x)` is SHA-256; tags include exactly the final NUL shown. Let `B` be decoded body bytes, not its base64 text.

```text
D = H("apassy-access-request-card-v1\0" || F(B))
digest = lowercase_hex(D)
card_signature_message = "apassy-access-request-card-sign-v1\0" || D
```

The Mac signs `card_signature_message` with its live trusted Mac `sign_key` using ECDSA P-256 SHA-256, DER signature. Body contains team/qid/key/routing/expiry and every displayed fact; all are authenticated by this signature and digest. The wrapper's protocol/version/part is fixed by the dedicated parser and signature domain. Reordering/whitespace changes in body bytes changes the digest; equivalent JSON is not interchangeable. Store the exact bytes for retries.

The phone opens the AEAD envelope, parses the dedicated wrapper, decodes and hashes B, verifies the Mac signature, strictly parses B, matches outer identity/expiry, current trusted Mac key and team mapping, bounds and choices, then checks expiry. It offers no controls if any check fails. Verification keys come only from the vault's trusted rows, never keys delivered in this card. If a sync changes trust/card context during preparation, discard the preparation.

## 4. Answers and owner gate

The encrypted answer plaintext is exactly:

```json
{"protocol":"apassy-access-request","v":1,"part":"answer","qid":"<qid>","request_id":"81","asker":"<Mac UUID>","by":"<iPhone UUID>","kind":"allow_once","digest":"<card digest>","expires_at":1790000300,"time":1790000030,"signature":"<b64u DER>"}
```

`kind` is only `deny` or `allow_once`. `time` is set immediately before the biometric signing attempt (or denial signature). Exact signed bytes, using `F` above, `D` decoded from hex, and `U64` unsigned big-endian integers:

```text
"apassy-access-request-answer-v1\0"
|| F(vault_id) || F(team_id) || F(qid) || F(request_id) || F(asker_uuid) || F(by_uuid)
|| F(kind) || D || U64(expires_at) || U64(time)
```

All identity/scope values are rebuilt from the Mac's immutable current request, never trusted from caller-provided owner-action fields. D binds agent id, item id/UUID/revision, policy, project, action, exact hosts, display facts and request expiry. The answer's repeated fields must equal that request. Signature of another request, team, asker, item revision or choice fails. There is no unsigned “Face ID succeeded” flag.

- **Deny:** sign with the iPhone's trusted `sign_key` (existing relay device identity key), without a Face ID prompt. The unlocked Questions context is still required. No owner proof is minted for a grant or run.
- **Allow once:** sign only with the trusted per-team Secure Enclave P-256 `answer_key`, `.privateKeyUsage + .biometryCurrentSet`, `WhenUnlockedThisDeviceOnly`, a fresh authentication context and zero reuse. Require `LAContext.biometryType == .faceID`; a Touch-ID-only iPhone has Deny/local review. No `.userPresence` alternative, `.or` passcode constraint, generic unlock proof, software signing fallback in production or relay `sign_key` is acceptable. These are constraints on private-key use, not just access to its stored blob or a separate UI prompt. [Apple's current-set constraint](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) supports both biometric types and invalidates on enrollment change, so Face ID type checking is additional. Simulator keys are fixture evidence only. Changed enrollment follows Mac-confirmed reconnect; never silently register a replacement key. The Mac cannot attest Secure Enclave/ACL policy from a P-256 signature alone: this assumes the trusted app's key creation and confirmed registration.
- On the asking Mac, a new typed `AllowAccessOnce` action and `RemoteAccessAnswer` verifier can produce a one-use proof **only** for this open access request and exact scope. No broadening of existing `OwnerCheck::Remote` support to `ChangeGrant`. Its proof is non-Clone, epoch-bound, valid for at most `min(60 seconds, request remainder, remaining signature freshness)` and consumed by the request arbiter. Carry the original signed time; minting a proof cannot restart its age budget. Denial still verifies a signed exact answer but needs no biometric proof.
- V1 accepts remote access answers only from live trusted **iPhone** rows of this questions team. Another Mac's relay answer is unsupported; local Mac UI and owner CLI remain available. Broader remote-Mac answering is a separate extension, not inherited from run questions.
- Freshness: `now-55 <= time <= now+5`, `created_at <= time < expires_at`, `now < expires_at`; recheck at commit using overflow-safe comparisons. The acceptance window is 55 seconds of past age plus 5 seconds of future-clock slack, not the run protocol's symmetric 60-second allowance. Honest signing clocks must stay within that 5-second skew bound; this is not remotely attested time. At consumption `now < expires_at` plus the Mac's non-sliding, sleep-inclusive 300-second deadline and epoch must hold. Detected clock jumps/uncertainty invalidate rather than renew. A remote answer neither reads nor changes the local owner-check window.

Before and after signing, the phone requires the same foreground unlocked vault context, team membership, immutable card identity/digest and deadline. Background/lock, cancellation, changed state or expiry discards the signature result and clears preparation. The signer must expose cancellation and call `LAContext.invalidate()` on those events and after completion, including failures; dropping an async task is insufficient. A prompt that outlives freshness needs new bytes and a new match initiated by the owner. Only the same signed payload may be retried before `min(time+50,expires_at)`; a fresh envelope nonce is required if resealing. An alternative choice needs another preparation (and another Face ID for Allow once). Enrollment changes prevent new signatures with the old key; they cannot erase an already signed in-flight answer. Until the Mac learns of removal/reconnect/cancellation, that answer can still win within these existing freshness/expiry bounds.

Answer POST is **not idempotent** on this relay: every successful insertion, including identical ciphertext, consumes an answer slot. Permit at most one in-flight submission per prepared answer and at most three total POST attempts per device/qid across all choices and uncertain responses. After a successful POST, wait for a verified settle; do not keep posting while waiting. Exhaustion leaves “Not confirmed” and local Mac review, never a new qid, renewed timestamp or automated Face ID prompt. A malicious relay can still waste slots or suppress the result; local arbitration never depends on those slots.

## 5. Arbitration and permit consumption

One asking-Mac arbiter serializes every local/CLI/companion/relay answer, agent cancellation, expiry, policy invalidation and permit use. Persistent request transition is a compare-and-set from open in the same transaction as receipt/audit; Mac durable request-grant writes join this transaction. No stale dialog may write before or after losing that CAS. Returning `AlreadyAnswered` is side-effect-free.

```text
open -> denied | allowed_once | granted_on_mac | expired | invalidated
allowed_once => memory permit: available -> consumed | expired | invalidated
```

Receipt and permit are distinct. An accepted access answer is terminal even if its permit is later unused or lost. The arbiter installs the permit after successful terminal commit while holding the same lock; crash in between loses authority. Never reconstruct a permit from SQLite or a relay answer after restart. Persist receipt/id tombstones so repeats cannot install one. Lock, vault switch/restore/rekey, broker shutdown/restart, request expiry, item/binding/policy/project change, agent token rotation/expiry, device/agent revocation or a changed answering key/team mapping invalidates a live permit and pending admission; the original answer record remains history. Keep the accepted answering-key fingerprint and mapping in that local fence. Tombstones must survive any database retention that could reuse request ids; a restore starts a new epoch and invalidates old incarnations before dispatch.

The agent status reports `open/allowed_once/denied/expired/invalidated/granted_on_mac`, original deadline and available/consumed/unavailable permit status; it never claims that execution succeeded. A new request gets a new id and qid. On lock/restart pending dispatch incarnations become invalidated; legacy notes can remain notes, but cannot resurrect remote authority. Status lookup is scoped to the authenticated agent and does not reveal another agent's ids.

To consume: an authenticated one-item operation names `access_request_id`. Under the same arbiter, match the exact request agent and item, current item revision and policy digest, epoch, canonical cwd/project, certain broker action, complete exact normalized host set, expiry and available permit; then mark consumed and bind the admission to an internal operation id **before** normal routing/secret preparation. Concurrent calls yield at most one admission. No matching permit is `access_once_unavailable`, without falling back to a durable grant or an unreferenced execution. V1 has no caller-visible execution idempotency key: after admission every repeated use call, including an identical command after a lost response, gets unavailable/consumed and cannot join or start another operation. Status is the safe retry; command-text or ordinary waiting-question coalescing must not bypass the burn.

Never/Only restrictions, review/archive checks, binding/OTP protections and host policy still apply; a permit does not waive them. Bouncer/owner execution decisions follow ADR 0031. No pattern/history/classification authority is manufactured from access consent. Existing real-value delivery does not guarantee network confinement merely because destinations were reviewed.

For placeholder delivery, the admitted operation MUST additionally intersect the binding's permitted destinations with the card's **exact host/port** list and check its deadline/revocation fence at every credential substitution, including redirects and subsequent requests. The current `HostRule::covers` suffix match is insufficient for this consent boundary; `api.example.test` must not authorize `evil.api.example.test` or another port. Preserve existing TLS/private-address/auth-position checks. This restricts where/when the placeholder releases a value, not all process networking or a remote service's subsequent use of a value already received. A real-value process can use its delivered credential outside the reviewed destinations; the card must state that limit, and unknown/static-analysis scope cannot be presented as runtime confinement or proof of intent. “One attempt” is one admitted broker/process operation, potentially containing multiple network calls; it is not one API call or a bounded amount of work.

Consumption burns the permit but does not remove the admitted operation's expiry/revocation fence. Carry a private admission ticket bound to that operation, request, snapshot and epoch. Recheck the fence after model/owner waits and immediately before credential preparation/delivery and spawn; a changed snapshot, expired original deadline or revoked device refuses the attempt. Bound any subsequent run-question wait to the request remainder. A consumed failed/expired attempt never refunds the permit. This prevents a 300-second run question from turning an almost-expired access answer into another 300 seconds of authority. After actual release to a running process, there is no claim of recalling an already delivered real value.

## 6. Settle and UI receipts

The encrypted settle wrapper is the same shape as the card, but `part: "settle"`; its decoded body is:

```json
{"vault_id":"<vault UUID>","team_id":"<team>","qid":"<qid>","request_id":"81","asker":"<Mac UUID>","digest":"<card digest>","outcome":"allowed_once","answered_by":"<device UUID>","device_name":"Test iPhone","device_kind":"iphone","kind":"allow_once","at":1790000031,"expires_at":1790000300}
```

`outcome` is `allowed_once/denied/granted_on_mac/expired/invalidated`. For expiry/invalidation, `answered_by/device_name/device_kind/kind` are null. For a local durable answer `kind` is `grant_on_mac`, `device_kind` is `mac`. Other local answers use `allow_once/deny`. Device display names are loaded from trusted local state, not the answer. Settle contains no permit material. At most 512 decoded body bytes, complete wrapper at most 1024; bound the display name against the actual serialized size (including JSON escapes) before signing. Critical ids/digest/times cannot be truncated; device identity does not depend on that shortened label.

```text
S = H("apassy-access-request-settle-v1\0" || F(settle_body_bytes))
settle.digest = lowercase_hex(S)
settle.signature_message = "apassy-access-request-settle-sign-v1\0" || S
```

The asking Mac signs with the same trusted `sign_key`, then seals with existing settle AAD. Verify that signature, selected vault id, card digest, qid/request, team, asker, expiry and terminal shape before confirming a result. A holder of the question key cannot impersonate the Mac's receipt without its signing key (subject to the vault trust-root limitation).

Only after that check show “Answered on <device>” and Denied or “Consent recorded for one attempt before <time>.” This confirms the committed answer, **not current permit availability**: it may already be consumed, invalidated, cancelled or lost in a crash, even before expiry. Show “Check on <Mac> for remaining availability” rather than deriving an available/unused badge from a settle. It is immutable; subsequent permit changes cannot replace it on this relay. On the Mac, live local status is authoritative without a network round trip. The phone's successful answer POST shows “Sent. Waiting for <Mac> to confirm.” After 60 seconds or expiry without a verified receipt: “Not confirmed. Check on <Mac>.” A bare relay `409`, `expired/settled` flag, disappearance or missing receipt disables controls but cannot assert which answer won. If a valid allowed receipt arrives after the deadline, show its historical outcome with “Access expired”; do not show available authority.

Best-effort settle retries resend the identical envelope (the relay's idempotent-settle rule). The relay refuses a first settle at/after `expires_at`; do not promise an expiry receipt or confirmation for a near-deadline answer. The phone can expire its controls locally and retain an unconfirmed result. Do not delay lock or retain bearer credentials to complete a settle. If the relay drops it, the local result remains final; no replay/reopen is allowed. No background-removal push is added.

## 7. Bounds, offline operation and spam

| Bound | Value / behavior |
| --- | --- |
| Local request lifetime | 300 seconds, fixed; retry/coalescing never renews |
| Per agent | One active request **or unconsumed permit**; five new scoped/legacy-dispatch incarnations per rolling hour |
| Per local vault on each asking Mac | Ten open access requests; twenty new incarnations per rolling hour. Not a shared cross-Mac quota |
| Coalescing | Same agent/item UUID/revision/policy/canonical cwd/project/action/hosts returns the existing id/qid unchanged, retains first reason, sends no new push. A different scope while active is `access_request_waiting`; do not replace/relabel a card |
| Notification | One logical publication per incarnation (bounded card-POST retries use the same qid/body), and one new dispatch per agent per 30 seconds on this Mac. During cooldown refuse remote dispatch rather than delay beyond its deadline. Relay/APNs delivery may retry, duplicate, collapse or drop |
| Relay | Shared existing limits: 20 open/team, 10/asking device, 15/member; 300 questions/team/hour, configured shares/byte budget; three answers/device/question, twenty total; existing long-poll limits |
| Ciphertext caps | Card 32784; answer 8208; settle 1040 bytes; include wrapper/signature overhead before sending |

Creation counters survive denial, restart and expiry; duplicates do not spend budget. Apply limits before enqueue/export; unauthorized or hidden-item calls produce the same existing refusal and no remote card. Local Mac review is always available, including when relay admission fails. These bounds are independent of and stricter than the existing legacy 20-open-notes cap, which is not a sufficient notification limit.

Multiple Macs have independent local counters; aggregate traffic is bounded only by the relay's existing team/member/device quotas and shared byte budget. Do not describe twenty/hour as a vault-wide notification guarantee, and do not add synced agent/request state to simulate one. Access traffic must not replace or starve a local execution question. Apply admission under the same lock as coalescing and reserve hourly/cooldown budget before publication; terminal answers, cancellation, failed publication and restart cannot refund it. Persist budgets against wall-clock rollback; uncertainty refuses further remote admission until the window is safe.

The existing relay/Worker sends the fixed “A question is waiting” alert with sound and **`interruption-level: time-sensitive`**, a shared `apassy-question` collapse id, and no qid, vault id, inner type or category. Notification taps can only open/refetch the Requests inbox; the owner then selects a verified exact card. Do not route a generic tap to the newest row or claim an access-only quiet push class. Exact navigation is possible from an already verified in-app row. Retain these push bytes and generic routing for the no-relay-change option. A quiet access-specific class, an exact-card push link or a true global access quota needs a separately reviewed transport/coordinator change. Push is a hint, never evidence of an open request or authority.

Offline/retry behavior inherits questions backoff (2,4,8,16,30 seconds), stopping before the original deadline. Do not post with at most 10 seconds remaining. `403 too_many_questions`, `413`, unsupported relay `404`, exhausted answer slots or malformed/unreadable data keep local review and give no authority. A timed-out answer submission is uncertain: retain the identical bounded retry or query state, never issue another permit on an inferred failure. Local decisions do not wait for relay availability.

The relay sees ciphertext and existing outer metadata only; it can deny service, track traffic and reorder valid answers. A compromised trusted Mac/vault holder can subvert the trust root. A stolen unlocked phone can deny, but cannot authorize Allow once without its protected key match. Agent-crafted narrative and a real-value recipient process retain their existing risks.

## 8. Required interoperability evidence

Before implementation merge, freeze synthetic vectors for exact card/body bytes, card digest/signature, answer bytes/signatures for both choices, signed settle and unchanged outer AAD/ciphertexts in Rust and ApassyCore tests. Include one field-change negative per identity/scope/display/header field (including vault id and host provenance), wrong-key choices, duplicate JSON keys, no mapping/revoked device, late signature, `now-55/now-56/now+5/now+6` and exact expiry boundaries, old-client dispatch and cross-run/feed replay. Include two-iPhone/duplicate/reordered answers, answer-versus-cancel/use races, lost POST responses at the three-attempt limit, consumed or crash-lost permits with delayed valid settles, exact-host versus subdomain/port/redirect substitution, and independent cross-Mac quotas with generic time-sensitive push routing. The example above is not a vector and no interoperability test has run in this docs change.

The `policy_digest` serializer and added agent input/status/error types must be pinned during the first implementation unit before consumers are split. Existing questions vectors must continue to pass unchanged. Real Face ID freshness and no passcode fallback require physical-device acceptance; simulator/software signatures cannot establish either property.
