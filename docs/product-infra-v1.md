# Apassy — Product Infra v1

Date: 2026-09-16.
Status: target architecture with a partial Rust foundation. The owner selected macOS desktop with eframe/egui and approved SQLCipher evaluation.
Production storage, key handling, and isolation still require evidence and approval.
This revision supports the vault, plain-language rules, agent access, and bouncer in [Product Vision v1](product-vision-v1.md).
It replaces the earlier GitHub-centered architecture and does not carry forward Linux-only, SQLite, or age as approved decisions.

## 1. Design goals

The system must support a useful personal credential manager, not only a background approval service.
The owner interface, vault lifecycle, rule editor, approval inbox, and notifications are first-class components of MVP.

Keep the local installation small, maintainable, and responsive.
Use a modular Rust core rather than microservices unless actual requirements justify a service boundary.
Logical modules can share a binary. Security boundaries must correspond to real permissions, not module names.
Local operation does not imply complete offline operation: contextual models and connected services can require network access.

## 2. Components and authority

| Component | Responsibility | Authority limit |
| --- | --- | --- |
| Owner app | Vault management, rule review, agent enrollment, approvals, history, and alerts | Authenticated owner operations only; no agent can invoke them through its own channel. |
| Vault service | Encrypted items, lock/unlock, revisions, protected reveal/copy, backup, and restore | Only trusted callers can request secret values. |
| Rule interpreter | Convert owner language into a reviewable draft and identify unresolved clauses | Cannot activate rules or create permissions. |
| Policy engine | Enforce confirmed identity, resource, operation, time, and usage conditions | Deterministic denial takes precedence over model judgments. |
| Bouncer | Combine policy and required risk checks into allow, ask, or deny | Cannot override an explicit restriction. |
| Broker and connectors | Authenticate agent requests and execute bounded operations with credentials | No generic secret-read, unrestricted proxy, shell, or raw SQL interface. |
| State and audit | Sessions, grants, requests, approvals, counters, outcomes, and recovery | Durable, bounded records without secret values. |
| Notification service | Durable inbox, delivery attempts, grouping, and actionable alerts | Acknowledgment and delivery do not grant access. |
| Agent CLI and MCP bridge | Discover permitted uses and submit requests | No vault-wide inventory, owner session, rule activation, or self-approval authority. |

Rule interpretation and runtime risk assessment use separate versioned contracts.
Jev is the planned risk provider. Its suitability for rule interpretation is unverified and must not be assumed.

## 3. Vault and key lifecycle

The vault stores API keys/tokens, username/password logins, SSH keys, database credentials, and custom secret fields.
Each item has a stable ID, type, revision, protected values, labels, service references, and optional notes or tags.
Rule grants bind item IDs and revisions rather than matching arbitrary display names.
Replacing a credential or changing its service binding invalidates dependent pending authorizations.

Use maintained cryptographic libraries and an established encrypted storage design. Do not create a custom cipher or cryptographic protocol.
Evaluate the storage format for atomic edits, key derivation, authentication, corruption detection, schema changes, backup, and recovery.
The approved evaluation uses one SQLCipher database for vault content and operational state. See [ADR 0002](adr/0002-encrypted-state-probe.md).
This probe is not production storage acceptance. Key handling, restart, lock, recovery, and isolation still need implementation and verification.
A separate encrypted file and operational database are not the current direction. Such a split would require a crash-safe coordination protocol.

Sensitive labels, usernames, notes, connection strings, rule text, and task descriptions also require protection at rest.
Search must not leave an unprotected index of vault contents. Logs and ordinary metadata records must not contain credential values.

The owner authenticates to unlock the vault. Startup and recovery begin locked.
A lock stops new credential use, invalidates pending execution authority, and closes reusable service sessions where possible.
It does not guarantee cancellation of a remote operation already in progress.
Key material and cached values have bounded lifetimes. Secret wrappers do not prove complete memory erasure.
Disable unnecessary secret-bearing diagnostics and document memory, swap, and crash-dump limits on the supported platform.

Owner reveal/copy requires deliberate action and follows the configured reauthentication rule.
Record the action, not its value. Clipboard clearing is best effort and cannot retract copies in other applications.
Item deletion revokes future access. Backups can still contain older data, and deletion is not a claim of physical secure erasure.
Recovery material must be protected separately from ordinary backups. Lost recovery material can require credential replacement.

## 4. Plain-language rules

Rule state is `draft` → `needs_clarification` or `ready_for_review` → `active` → `superseded` or `revoked`.
Only the owner can activate a reviewed version. Editing an active rule creates a draft; the old version remains visible until replacement or revocation.

A draft includes the original text, a clause-by-clause interpretation, trusted resource bindings, enforceable conditions, contextual checks, and unresolved issues.
The validator rejects unknown agents, ambiguous resources, unsupported operations, unbounded interpretations, and silent omission of a clause.
Relative dates require an exact timestamp and time zone at confirmation. Recurring windows require an explicit daylight-saving rule.

The review shows expected allow, ask, and deny examples, plus differences from the active version.
The active policy is immutable and versioned. Record the interpreter, schema, owner confirmation, and connector capability version.
No request-time model can expand the confirmed policy by reinterpreting the original prose.
Policy replacement and grant invalidation must occur atomically from the execution service's perspective.

All applicable scopes restrict the request. An explicit denial wins, and limits intersect rather than add privileges.
Unresolved contradictions prevent activation. Missing grants mean denial.
Contextual conditions remain visible judgments, not falsely advertised deterministic guarantees.

## 5. Identity, isolation, and the owner channel

Choose one initial platform and isolation profile that fits the owner's daily use. The previous Linux-first proposal is not a requirement.
The current development host does not establish the supported product platform.
The [MVP plan](mvp-plan.md) requires this decision and a boundary test before work with real credentials.

The untrusted agent cannot read vault storage, keys, broker memory, rule configuration, owner credentials, or notification approval tokens.
It cannot control the owner app, inspect its clipboard, impersonate its channel, or obtain the broker's model credentials.
An unrestricted agent under the same effective account can invalidate these assumptions. A separate process or localhost endpoint is insufficient.
An OS keychain alone does not establish isolation from an agent with equivalent access.

The owner enrolls agent identities and establishes trusted project and task context outside the agent's control.
Agent requests use authenticated, scoped, short-lived sessions bound to a verified runtime identity where the platform supports it.
Session capabilities are Apassy credentials. They are separate from the stored provider secrets and still require careful handling.
A process inside the same agent boundary can share that authority; process labels alone do not establish distinct identities.

Separate owner and agent endpoints and authorization paths. Verify caller identity on each operation.
The owner app must not display remote HTML or execute agent-controlled content with administrative authority.
If the chosen app uses web technology, test origin, CSRF, session, and content-injection defenses. A port on localhost is not owner authentication.

Host administrator compromise, kernel escape, and owner account compromise are outside the local isolation claim.
The product must identify unsupported configurations rather than silently offering weaker guarantees.

## 6. Connectors and credential-use modes

A connector declares credential types, registered resources, operations, parameter schemas, result fields, side effects, and enforceable rule conditions.
The owner sees these capabilities before activating a rule. Unsupported use is refused, not redirected into a raw-secret fallback.
MVP delivers at least two mediated paths for different credential types, as proposed in the implementation plan.

The broker resolves destinations from owner-approved service bindings, not the agent's claim that an address is trusted.
Network clients enforce TLS identity, destination restrictions, connection targets, redirects, and SSRF/DNS-rebinding defenses independently of a model.
Private service destinations require explicit registration and a threat model; they are neither universally forbidden nor implicitly trusted.
Agent-controlled proxy settings, headers, arbitrary URLs, and raw command or query strings are not authorization shortcuts.

An HTTP verb alone does not prove that an operation is read-only. A SQL keyword or model judgment cannot establish database safety.
Use bounded operations with documented effects, least-privilege provider permissions, and service-specific tests.
Credentials, authentication headers, raw errors, and unrestricted service responses must not reach the agent.
Sensitive service data also needs an output contract; concealing the credential does not prevent all data disclosure.

Mediated use is the MVP default. Raw delivery to an agent, child process, environment, or file is outside the MVP contract.
Owner reveal/copy remains available as an explicit human operation with disclosure warnings.
A later compatibility mode requires a separate decision about which restrictions it cannot enforce after disclosure.

## 7. Decisions, approvals, and execution recovery

The [product concept](concept.md) defines the allow/ask/deny table. Routine permitted use must have an automatic path after its evaluation gate passes.
Each request binds agent identity, session, item revision, policy version, connector version, resource, operation, normalized parameters, and relevant risk configuration.
Approvals bind that exact request, an owner identity, expiry, and one attempt. They cannot authorize a changed request or override a denial.

Before execution, recheck expiry, revocation, item state, policy, required risk freshness, and limits.
Commit the execution intent, counter changes, any approval consumption, and required audit events in one durable transaction.
Automatic requests use the same path without an approval record. Atomicity is not optional for automatic use.

That commit is the authorization boundary. Revocation committed first prevents execution. Later revocation cannot guarantee cancellation of the remote effect.
Where possible, cancel pending work after revocation, but do not claim that cancellation always succeeds.

Deduplicate by authenticated session and client request ID, with a canonical content digest.
The same ID and content return existing state. A content mismatch is a conflict, never another execution.
An intent can reach `completed`, `failed`, or `unknown`. A timeout or crash after a possible remote effect produces uncertainty, not permission to retry.
Do not automatically replay state-changing requests with unknown outcomes. Local transactions cannot guarantee exactly-once remote effects.

A failed required audit or intent write prevents execution. A result-write failure after a possible effect stops new work until recovery.
Restart invalidates sessions and unused approvals through a fresh epoch that backups cannot restore.
Use monotonic expiry within that epoch, and safe handling for clock changes. Restored rules require owner review before new agent sessions.

## 8. Model privacy and failure behavior

Only a valid required assessment can contribute to automatic permission.
Timeouts, invalid results, unknown contracts, missing context, or unavailable models lead to ask or deny according to the active policy.
A rule interpreter failure cannot activate a draft. An evaluator failure cannot broaden an active rule.

Minimize context for both providers and obtain explicit permission for external processing.
Do not send credential values, raw conversations, complete environment variables, authentication headers, or arbitrary service responses.
Redaction does not prove anonymity. Verify processing terms, retention, region, model versions, limits, and cost before live use.

Validate output types and semantics. Record uncertainty separately from risk, and version thresholds by operation where needed.
Bound timeouts, retries, queue length, concurrency, payload sizes, and cost. Cached results cannot bypass revisions, revocation, TTL, or usage limits.
Offline fixtures and deterministic test adapters prove wiring and failure behavior, not model quality.

## 9. Audit and notification delivery

Persist decision events and the notification outbox together where delivery is required.
The durable inbox is the source of truth. A local notification is a delivery attempt, not proof that the owner read it.
Record queued, attempted, delivered where observable, and acknowledged states separately from approval state.

Use safe references, stable reason codes, severity, and bounded diagnostic detail. Notification previews hide sensitive labels by default.
Group repeated alerts with visible counts, preserve individual decisions, and enforce retention and storage limits.
Alerts need actions to inspect, approve once when allowed, deny, pause an agent, or revoke access.
Every action authenticates the owner and checks current request state. Old notifications cannot replay an approval.

Notification failure never releases a paused request. Show delivery health, retain the inbox item, and retry within limits.
If policy requires a notification and durable enqueue fails, do not execute the operation.
If even a denied event cannot be stored, retain the denial, expose the storage fault, and refuse new execution until required recording works.

## 10. Rust, distribution, and verification

Pin the Rust toolchain and dependencies. Select maintained libraries for cryptography, storage, networking, and protocols, with a documented license and native-code review.
First-party `unsafe` requires a justified exception and review. Rust does not eliminate authorization bugs or credential leaks.
The owner-app toolkit and package structure follow the platform decision, not an unapproved CLI-only design.
Use bundled, reviewed connectors rather than plugins with full vault authority.

Releases need authenticated integrity and provenance, not only a checksum. Updates are owner-controlled and preserve a recoverable installation.
Test schema changes, interrupted updates, backup restore, locked startup, and unsupported downgrades.
The first candidate uses fixture versions for migration tests, not an invented previous product release.
Publication and deployment require separate authorization.

Measure setup time, vault search, rule review, decision latency, notification latency, memory/CPU, storage growth, and external costs.
Report local, provider, and human delays separately. Approve resource budgets after the prototype and before the pilot.
A test report must distinguish passed, failed, skipped, and unsupported checks. Unset budgets or missing isolation evidence block readiness.

## 11. Decisions still required

- Product isolation profile, authenticated transports, and local notification channel. The owner selected macOS desktop with eframe/egui.
- Production acceptance of SQLCipher, key lifecycle, and crash-safe revision coordination. The synthetic single-store probe passed.
- First two services and their credential types, bounded operations, and least-privilege requirements.
- Rule interpreter provider and contract, plus verified Jev access and processing terms.
- Model evaluation thresholds, resource budgets, release channel, and supported recovery procedures.

These choices must serve the owner journey. They must not remove the human interface, natural-language rules, automatic permitted use, or alerts to simplify implementation.
