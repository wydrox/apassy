# Implementation plan — iPhone access requests (ADR 0033)

Date: 2026-11-01. Status: proposed; this change contains documentation only.
Decision: [ADR 0033](../adr/0033-iphone-access-requests.md).
Wire: [relay-access-request-v1](../contracts/relay-access-request-v1.md).

## Outcome and constraints

An owner can read an authenticated access-request card in iPhone Requests, Deny without Face ID, or Allow once with a fresh Face ID signature. The asking Mac commits the first valid answer and alone issues/consumes one scoped access permit. The eventual command still goes through the bouncer. The Mac UI/CLI remain available, durable grants stay local to the Mac, and relay unavailability never prevents local decisions.

No product code, schema change, release version, production relay mutation or deployment belongs to this design PR. Future work uses synthetic vaults/credentials and fake relays for automated tests; physical signing checks are a separate acceptance boundary. Do not run test containers on this Mac or on the production VPS.

## Dependency gate: Connect first

Base inspected: `origin/main` at `0b103687689e9a61f4a13c8d8c2e333587f65456`. Connect onboarding is concurrent on `feat/connect-onboarding`; its ADR 0032 was not yet present in the inspected worktree. Its in-progress `src/relay/connect.rs` supplies `prepare_connect/create_connect`, `src/vault/connect.rs` stages `PendingConnect` and adopts a question-key/trusted-device handoff, and `src/relay/pairing.rs::PairingChannel` carries that handoff through questions with its own QR-capability key and reserved marker. None is a stable merged API yet. Implementations must rebase onto its merged result, read its actual ADR and confirm these invariants before editing integration files:

1. One questions membership for this vault, with `MembershipPurpose::Questions`, or the existing relay-sync membership serving questions. Personal/iCloud vault data is not uploaded just to enable requests.
2. Live Mac and iPhone trusted rows in the vault; exact per-team relay device mapping; an iPhone `answer_key` confirmed by the Mac after the existing owner check. A relay-reported device or role is insufficient.
3. Per-team answer signer selected by the key actually registered in the row, including reconnect/revocation/enrollment-change behavior. Access requests must not register their own keys.
4. Question-key availability/rotation, push setup, membership cancellation and local fallback follow Connect's completed lifecycle. A half-connected phone cannot approve.
5. Connect handoffs retain separate dispatch and never appear as run/access requests. The carrier quota tests include handoff traffic; the new access publisher cannot assume the whole questions budget is free.

No additional scan/pair/account/team-creation journey is introduced here. Keep this PR based on main, with textual dependency on Connect; do not merge or cherry-pick its unfinished code into the design branch. Link ADR 0032 by its final filename once it exists. ADR 0028 was read in the main development checkout, but is absent at this base; restoring or accepting its retirement proposal is a separate decision, not a prerequisite for retaining the current companion.

## Work units and ownership

One editor owns each shared file at a time. The units below are boundaries, not an instruction to start workers in this design task. All paths are current evidence or explicitly labelled proposed additions; reconcile Connect's final file moves before assigning work.

### A — Freeze the inner protocol and agent API

**Own:** proposed `src/questions/access_request.rs`, `src/questions/mod.rs`; `docs/contracts/relay-access-request-v1.md`; access-specific fixtures under `tests/fixtures/`; coordinate `src/questions/envelope.rs` only for a narrow typed dispatch interface. Other units wait for this interface before touching their consumers.

Define strict card/answer/settle types and exact digest/signature builders, bounded parsing, the outer-carrier dispatch enum and status/error vocabulary. Freeze `policy_digest` with an explicit versioned serializer of the existing authorization baseline's fields; document every included field, without standardizing Debug output. Freeze the optional MCP `scope`, run `access_request_id`, status results and `AllowAccessOnce` action scope with B. Share pure Rust helpers with ApassyCore where possible, following current crate feature boundaries; no dependency on the FSL relay crate.

**Acceptance (Rust):** exact byte vectors and independently verified signatures for both choices; negative mutations to every signed field including names/reason and outer identity; duplicate keys/invalid UTF-8/unknown fields, scope overflow, wrong signature key, cross-run/feed protocol replay and wrong AAD. Prove a new inner card cannot be parsed as `PendingRun`, while existing questions digest/answer vectors remain unchanged. Signatures/digests must operate on exact body bytes, not reserialized JSON. Deliver the vectors before B/C/D consume the protocol.

### B — Local request lifecycle, owner gate and one-use broker admission

**Own:** `src/agent/{mcp,wire}.rs`; `src/broker/decide.rs`, `src/broker/approvals/owner_auth.rs`, `src/broker/run.rs`, `src/broker/mod.rs` as needed; proposed `src/broker/access_once.rs`; `src/vault/access.rs`, `src/vault/agents.rs` and schema registration/local-table declarations; `src/desktop/owner_store.rs`. Connect's in-progress staging uses schema 21: allocate the next free schema after its merge. Tests extend `tests/access_model.rs`, `tests/agent_run.rs`, `tests/owner_auth.rs`, and inline MCP parser tests; a new `tests/access_requests.rs` must be registered as a module in `tests/it.rs`, the single integration-test target.

Add a versioned local scope/lifecycle table and receipt/tombstone storage; preserve legacy notes and do not broadcast them at migration. New scoped requests have fixed expiry, exact-scope coalescing and durable rolling creation counters. No permit authority is persisted or synced. Make one arbiter own answer/expiry/invalidation and burn; integrate durable `set_exec_grants` request-answer transitions transactionally so a losing dialog cannot create a grant. Keep standalone fresh local grant actions possible after a closed request without treating them as another answer.

Add new non-Clone exact-action proofs for local fresh `AllowAccessOnce` and remote `RemoteAccessAnswer`; do not add access allowance to ADR 0030's window allowlist or use general remote `ChangeGrant`. Record the remote check method and answering device. Recheck fresh trusted device and scope at commit/consumption. Run references are agent-scoped, one-item admissions; mismatches do not fall back. Reserve the operation identity for legitimate retries, consume before downstream routing, and never restore after failure. Carry an operation-bound admission fence through all model/owner waits, credential preparation/delivery and spawn; expiry/revocation still refuses after consumption, and a later run question cannot extend it. The bouncer's current routing/hard checks stay authoritative. Never/Only restrictions are not bypassed.

**Acceptance (Rust):** one winner in local-allow/local-deny/iPhone/durable-grant/expiry races; loser has no DB or permit side effects; exactly one admission under concurrent consumers; same-operation join versus a distinct equal-text operation; no permit revival after lock/restart/rekey/restore or a failed commit. Changed item revision/binding/agent/policy/project/action/host/clock/deadline fails closed. Expiry/revocation after admission or during a run question prevents secret release/spawn and never refunds authority. No writes to durable grant/owner-answer/pattern/declaration/exception tables from phone allowance. A valid access permit plus a bouncer veto still asks/refuses; `can_use` remains usable without a new prerequisite. Hidden items stay indistinguishable from missing ones. Remote allow/deny neither seed nor consume an existing owner window; local access-consent stays fresh even in a window. Migration retains old notes without creating authority.

### C — Mac relay publication, verification, settlement and local Decisions

**Own:** `src/questions/worker.rs`, proposed `src/questions/access_worker.rs`; `src/questions/client.rs` only if the existing typed carrier API needs extension; `src/desktop/ui/decisions.rs`, `src/desktop/owner_check.rs`, `src/desktop/owner_cli.rs`, and relevant notification routing. Sequence handoff of `owner_store.rs` and the arbiter interfaces after B; C does not independently invent another answer store. Tests: `tests/relay_questions.rs`, `tests/common/fake_relay.rs`, access-specific integration fixtures and existing desktop UI tests.

Publish Mac-signed encrypted cards from eligible open requests with remaining lifetime greater than 10 seconds, using current membership/key. Add an **Access requests** distinction to Mac Decisions; do not reuse requests for pasting missing credentials. Local fresh Allow once, Deny and durable Mac grant actions all use B's arbiter. Keep CLI compatibility with explicit exact-request proof/receipt semantics. Route notification clicks to exact `(vault,asker,request,qid)` identity, never the next row.

Process only new inner access answers from exact live trusted iPhone mappings. Verify typed owner proofs and settle with the actual winner. Never trust relay sequence/timestamp/role as the winner. Keep local outcome on relay failure; retry one immutable signed settle envelope. Show confirmed device attribution, exhausted/expired permit status and local-only reason when export fails. Keep companion denial routed through the arbiter without extending its wire protocol.

**Acceptance (Rust + headless desktop):** fake relay normal/offline/delay/drop/reorder/replay, answer-first/local-first and grant-race tests; stale/revoked device, changed epoch, removed mapping/key, malformed/oversized card, `404/403/413/409` and full relay budgets. Lost POST response cannot make a second request or permit; lost settle cannot reopen. Exact row navigation and local card remain usable. Existing run relay tests, companion denial and owner CLI grant tests remain green. A signed card proves Mac source; a forged card signed by a different vault device or relay-supplied key is rejected.

### D — ApassyCore and typed Swift transport

**Own:** `ios/ApassyCore/src/core/questions.rs`, its `questions/envelope.rs`, proposed `core/access_requests.rs`, dispatch in `core/mod.rs` if needed; `ios/ApassyVaultKit/Sources/ApassyVaultKit/{Questions,VaultService,PreviewVaultService+Questions}.swift` and `Sources/ApassyVaultCore/CoreVaultService+Questions.swift` with their mocks/tests (reconcile moves after Connect); `docs/contracts/ios-core-v1.md` for the new callable interface, in the implementation PR only. Tests: `ios/ApassyCore/tests/{questions_flow,multi_device_questions,requests_compatibility}.rs` plus new access cases.

Add a typed access-card variant while keeping old run result shapes compatible; use new calls or a capability/version boundary instead of silently changing strict old DTOs. Calls prepare immutable scoped bytes and return signer choice; core signs denial with the relay identity and verifies an externally provided Allow once signature with this vault/team's registered answer key before posting. Separate vault contexts and exact request identity throughout preparation, retry and receipt verification. Mac-signed card/settle verification happens in the core before Swift gets actionable data. No API returns secret values or a permit.

**Acceptance (ApassyCore):** drive real JSON API through fake relay using A's same vectors, complete request/deny/allow/settle flow, wrong vault/team/asker/qid, mixed run/access cards, missing registration, expired/unconfirmed receipts and unsupported older core. Background/suspend/select/remove must discard prepared signatures and authority; stale completions cannot post into a new context. Replayed accepted answer never reports another available permit. Existing multi-vault questions, request history and run-answer compatibility tests pass unchanged.

### E — iPhone Requests and fresh biometric signing

**Own:** `ios/ApassyCompanion/Sources/Models/QuestionsModel.swift`, `AnswerSigners.swift`, `Decisions.swift`, `RequestActionsModel.swift`; new access detail/model files; `Sources/Views/Decisions/{RequestsAccessRow,DecisionsView,RequestsList}.swift` and row routing; `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/SecureEnclaveKeys.swift` only if scoped signer lifecycle hardening is required. Tests: `ModelTests/Tests/AppModelsTests/`, `UITests/RequestsUITests.swift`, and VaultKit/CompanionKit signer tests. One editor owns question-model files shared with Connect until handoff.

Use the ADR's exact labels, full critical facts, provenance and denial-only incomplete state. No durable button, menu item, swipe or notification answer is added for an access card. Keep run controls type-specific. Prepare the exact answer then call the existing per-team protected signer with a new zero-reuse context; invalidate that context and ignore late results after lifecycle changes. No passcode or production software-key fallback. Deny signs without a biometric prompt. Show pending until Mac-signed confirmation, then “Answered on <device>”; do not optimistically mark authority. Deduplicate legacy Wi-Fi and relay access rows only with proven source/request identity; do not hide a request by a matching display name.

**Acceptance (Swift models):** Allow once calls only the correct answer signer and exactly once per new choice; unlocking/previous signing does not satisfy it; Deny never calls that signer. Cancelled/failed Face ID, enrollment change, app background, vault switch, expired prompt, double tap, replaced row and stale network completion all fail closed. A transport retry reuses the same signed choice within its bound; a new choice calls for a new match. Multiple vaults/teams pick their own registered key. Unsupported core or missing trust gives local-review copy with no Allow once.

**Acceptance (iOS UI tests):** synthetic access request alongside a run request and a missing-credential request; complete facts and all hosts; distinct row/detail routing; Allow once and Deny only on the access detail; no durable options; actual expiry disables controls; Face ID cancellation is recoverable; pending/confirmed/other-device/expired/unconfirmed outcomes. VoiceOver order, accessibility text sizes, long similar paths/agent names, IDNA hosts, malicious control/bidi text, Reduce Motion, dark/light appearance and 44-point targets. Simulator tests validate UI/state, not actual Secure Enclave freshness.

### F — Integration and device acceptance

**Own:** integration-only tests, final ADR/contract corrections, `ios/README.md`/operations guidance and fixture evidence. No overlapping product edits while B–E own files. Run a combined review for broadened remote actions, grant writes, request/run conflation, lifecycle gaps and trust-row fallback.

On an isolated signed Mac and a physical iPhone with a synthetic vault, verify: each Allow once needs fresh Face ID even immediately after unlocking or another Allow once; Deny needs none; no passcode fallback; enrollment change invalidates the key; Mac receives without a second local biometric; lock/background and offline races do not authorize twice; unused permit dies at deadline/lock/restart; Mac and iPhone both attribute the first committed answer. Keep local Mac denial/allowance functional with internet off. Report native/device results separately from fixture/simulator results. No production relay or owner vault is needed.

## Merge order and checks

Order: **Connect onboarding + ADR 0032 -> A -> B -> C and D -> E -> F**. C and D can be built independently after B's shared lifecycle API is frozen; E can use D's fixture DTOs while waiting for its merge. Merge only integrated compatible pieces behind a local rollout gate until F passes. Do not expose Allow once ahead of permit enforcement, signer registration or signed receipt verification. This design PR can remain a draft during Connect work; no merge or release is requested.

Shared-file handoffs: A freezes protocol and owns `questions/mod.rs`; B owns `owner_auth.rs`, schema and `owner_store.rs` first; C follows for desktop integrations; D owns Core/VaultKit transport; E follows Connect/D for Swift request models and lifecycle. If Connect changes those boundaries, update the interface/ownership table before editing, rather than duplicating onboarding.

Representative commands for future implementation (use the existing pinned toolchain and synthetic fixtures):

```sh
cargo fmt --all -- --check
cargo test --locked --all-features --test it access_model::
cargo test --locked --all-features --test it relay_questions::
cargo test --locked --all-features --test it owner_auth::
cargo test --locked -p apassy-core
cargo clippy --locked --all-features --all-targets -- -D warnings
swift test --package-path ios/ApassyVaultKit
swift test --package-path ios/ApassyCompanion/ModelTests
scripts/build-ios-core.sh device sim
xcodebuild test -project ios/ApassyCompanion/ApassyCompanion.xcodeproj -scheme ApassyCompanion -destination 'platform=iOS Simulator,name=iPhone 17' -derivedDataPath /tmp/apassy-access-requests-dd
git diff --check
```

Run new access-request tests through their registered `it` module filter as well. Run broader repository-required CI once the combined change is ready; no repeated full suite without a new failure/change. This docs PR needs scope/whitespace/local-link validation and ordinary PR CI; it must not claim unimplemented acceptance tests passed.

## Relay impact and completion criteria

No relay release is a prerequisite: existing v1 opaque card/answer/settle endpoints, routing, aggregate quotas and generic pushes suffice. Do not edit `/Users/rafalw/Dev/apassy-relay-release-056` in these units. An optional fixture-level compatibility check against that code may demonstrate opaque forwarding, but any relay change would require fresh evidence that a necessary carrier invariant is missing. Keep outer metadata/limits unchanged.

Done means: Connect trust works; card facts and exact scope are Mac-authenticated; phone Deny/Face-ID Allow once work; first committed answer and one admission hold under races/replay; no durable authority/window change occurs; bouncer/hard checks remain; local Mac and compatibility fallbacks work; Rust, Core, Swift model, UI and physical-device evidence are recorded with their boundaries. It does not mean ADR 0028's Wi-Fi retirement is accepted or complete, another Mac can remotely answer these cards, production is deployed, or a run executed merely because access consent was granted.

Open implementation review items are limited to Connect's final interface reconciliation and initial spam-budget measurement, with the recommendations in ADR 0033. Neither leaves Deny, Face ID, one-use, expiry, arbitration or durable-grant semantics undecided.
