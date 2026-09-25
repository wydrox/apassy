# Apassy Rust contracts v1

Date: 2026-09-16.
Status: schema and validation for contract version 1. This is not a complete vault.

## 1. Scope

The file `src/contracts.rs` contains version 1 JSON contracts for Apassy.
A contract is a typed JSON record and a set of validation rules.

The validator checks record shape, IDs, versions, time order, clause coverage, and request bounds.
The validator does not authorize a request.
The validator does not encrypt data.
The validator does not authenticate an agent or a session at runtime.

Real providers, live services, and secret isolation remain unverified.
Do not treat a valid record as a runtime grant.

## 2. Shared UI types

The desktop app imports these names from `apassy::contracts`:

- `CONTRACT_VERSION` is `1`.
- `CredentialKind` has `ApiKey`, `Login`, `SshKey`, `Database`, and `Custom`.
- `Decision` has `Allow`, `RequireApproval`, and `Deny`.

JSON names use snake_case.
`CredentialKind::ALL` lists the five kinds in that order.
`label` returns a short English name for the owner interface.

`ApiKey` and `Database` have a contract-level mediated-use flag.
The flag is not a live connector and does not choose a provider.

## 3. Representation and trusted validation

JSON parse can produce a representation of a record.
A representation is not a trusted record.

Call `parse_json` or `Validate::validate` to apply the contract rules.
Do not construct a record through a public `new` function that skips these rules.

Leaf types such as `EntityId`, `Version`, `Epoch`, and `UsageLimit` check their own form during JSON parse.
Cross-field rules run in `validate`.
A successful `Deserialize` of a compound record is not enough.

## 4. Credential metadata

A credential metadata record stores identity, kind, revision, label, tags, and kind details.
The record does not store provider secret values.

Kind details are names and registered references:

- API key: registered service ID
- login: service ID and username
- SSH key: optional comment and fingerprint reference
- database: registered server ID and database name
- custom: field names and secret flags

The validator does not accept a kind that does not match `details.type`.
Zero revisions and inverted `created_at` / `updated_at` times fail validation.
A coarse PEM-shaped check applies to notes. Text bounds and PEM or SQL heuristics do not prove that a record contains no secrets.

## 5. Rule drafts

A rule draft stores the original owner text and a clause list.
Each clause has one disposition:

- `enforceable_restriction`
- `contextual_check`
- `unresolved_issue`

Every clause must have exactly one coverage item.
Clause indexes must be `1..n` with no gaps.
A draft with unresolved issues is valid as a draft.
`DraftStatus::NeedsClarification` or `ReadyForReview` is derived from that coverage.
An unresolved issue `detail` uses the clause-text bound (`MAX_CLAUSE_TEXT_LEN`).
An event diagnostic uses the shorter diagnostic bound (`MAX_DIAGNOSTIC_LEN`).
The clause-text bound is a schema design adjustment so a detail can quote a clause.
It is not a security control.

Enforceable restrictions bind agent, credential, destination, operation, time window, usage limit, or explicit denial.
Contextual checks use the Apassy dimensions from the concept document.
These names are not a verified Jev schema.
`on_failure` must be `require_approval` or `deny`. A check must not fail open.

## 6. Owner confirmation and activation

`OwnerConfirmation` binds an owner ID to one draft ID and draft version.
`activate` requires that confirmation.

Activation fails when:

- confirmation is missing
- the confirmation binds a different draft ID or version
- a clause is unresolved
- confirmation time precedes draft creation

`ActiveRuleRecord` stores that binding.
The record does not start a runtime policy engine.

## 7. Agent and session references

`AgentRef` and `SessionRef` are identifiers, revisions, and an epoch.
They are not proof of a live, trusted session.

A request must use the same agent ID as the session.
The request epoch must match the session epoch.
The request time must fall in the session window.
Zero epochs fail validation.

## 8. Named-operation requests

`AgentRequest` is the canonical agent request contract.
The request uses a named operation and a registered destination.
The schema has no URL, SQL, credential, or conversation fields.

Parameter values are text, integer, boolean, or identifier only.
Objects, arrays, and reserved names such as `url`, `sql`, `password`, and `messages` fail validation.
Text values must stay in length bounds.
Coarse URL, SQL, and PEM-shaped checks apply to some parameter text.
Those checks do not prove that a request contains no secrets.

Mediated named operations are contract-valid for `api_key` and `database` only.
The destination kind must match the credential kind.

## 9. Canonical JSON and digests

`AgentRequest::canonical_json_bytes` returns compact JSON.
Field order is the struct field order.
Parameter names are sorted.

That byte string is a canonical representation.
It is not a cryptographic digest.
It is not a signature.
It is not authentication of the request.

`BoundDigest` holds an algorithm name and octet string.
This module does not compute, sign, or verify a digest.
A later component that uses a reviewed cryptographic library may fill `BoundDigest`.

## 10. Decision and event envelopes

`DecisionEnvelope` stores identifiers, a decision, a reason code, and a time.
`EventEnvelope` wraps one decision with event kind, severity, and optional diagnostic text.

The envelope schema has no secret, conversation, or provider-response fields.
Diagnostic text has a length bound. The bound is not secret scrubbing.
Unknown fields fail validation.
Event kind and decision must agree for `request_denied` and `approval_requested`.
This schema does not authenticate an agent. It does not authorize a request.

## 11. Rejection rules

The validator does not accept:

- unknown fields
- invalid IDs
- zero versions, epochs, or usage limits
- invalid time order
- uncovered or duplicate clause coverage
- unresolved clauses at activation
- missing confirmation
- a confirmation bound to a different draft version
- unsupported operations or destination inputs
- request parameter bounds that are too large or reserved

`ErrorCode` names these cases in snake_case.

## 12. Limits of this module

This module does not:

- authorize or execute a request
- encrypt or decrypt vault data
- talk to a provider or connector
- interpret owner language
- isolate real secrets from an agent

P1 and MVP are not complete because this schema exists.
The parent runs `cargo test --locked --test contracts` and `cargo clippy --locked --lib --test contracts -- -D warnings`.
