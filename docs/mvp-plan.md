# Apassy — MVP plan

Date: 2026-09-16.
Status: revised scope and Grok implementation approved by the owner on 2026-09-16. P0 remains open. P1 foundation code is present. The experimental vault is connected to the owner vault and item views when both desktop and vault features are enabled. Rules, agents, and activity remain demo fixtures. P2b is not started.
This plan replaces the earlier GitHub-centered plan. Rust and macOS desktop with eframe/egui are confirmed. SQLCipher evaluation is approved.
Implementation starts with P0. Later tasks retain their decision, verification, and access gates.

Read [Product Vision v1](product-vision-v1.md) for the product, [the concept](concept.md) for the bouncer, and [Product Infra v1](product-infra-v1.md) for technical boundaries.

## 1. What we will build

A personal credential manager with controlled agent access.
You can store different credential types, manage them through a visual interface, and write access rules in ordinary language.
The bouncer permits normal use, asks about uncertain requests, blocks forbidden use, and informs you when needed.

The first complete experience is:

> Save a credential → write and confirm a rule → connect an agent → let it work → handle an alert or revoke access.

For example, you save a reporting service API key and allow your reporting agent to use it against staging for a limited period.
A normal report request completes without another approval prompt.
A production request is blocked and generates an alert. A request with unclear purpose waits for your decision.
You can inspect the history and stop future access without searching through terminal logs.

The same vault also holds your passwords, SSH keys, database credentials, and custom secrets.
Different items can have different rules and different permitted agents.
This is not a GitHub workflow tool, a CLI-only vault, or a system that asks permission for every normal request.

## 2. MVP scope

### Human-facing app

The app contains five main views:

- **Vault:** add, edit, search, organize, reveal/copy, and delete items; lock/unlock and encrypted backup/restore.
- **Credential details:** values masked by default, supported agent uses, rules, and recent activity for this item.
- **Rules:** ordinary-language editor, interpreted conditions, unresolved questions, examples, and confirmed version history.
- **Agents:** enroll an agent, inspect its grants and sessions, pause it, or revoke its access.
- **Activity and approvals:** decision history, durable approval inbox, alerts, and notification delivery health.

A visual owner interface is required for MVP. The desktop or local-web form and first platform are decisions in P0, not reasons to defer the interface.
CLI and MCP connect agents and support diagnostics. They are not the primary way the owner manages credentials and rules.

### Credential coverage

| Credential category | Vault support in MVP | Proposed agent-use scope |
| --- | --- | --- |
| API key or token | Create, protect, edit, reveal/copy, organize, and delete | Mediated access to one selected API service through named operations. |
| Username/password login | Same lifecycle, with service reference and protected fields | Storage and owner use. General website sign-in is not promised in MVP. |
| SSH key | Same lifecycle, including protected private key and optional passphrase | Storage and owner use. SSH execution is a later connector unless explicitly added to scope. |
| Database credential | Same lifecycle, with registered server and database identity | Mediated access to approved read operations on one selected database service. |
| Custom secret fields | Same lifecycle, with explicit field names and secret flags | Storage and owner use until a compatible connector is available. |

The two proposed execution paths exercise different credential types: an API key and a database credential.
A reporting API and PostgreSQL are candidates, not confirmed provider choices. P0 selects useful services with the owner and records their exact contracts.
Fixtures are necessary for tests, but a fixture-only demo does not satisfy the full mediated-use gate.
The interface clearly distinguishes “stored in the vault” from “agent use supported.”

### Access rules

The rule editor accepts conditions about who, which credential, project, destination, operation, time window, usage limit, purpose, approvals, and alerts.
It resolves those conditions against real agent identities and connector capabilities.
It shows the exact expiry and time zone for a phrase such as “until Friday.”

Before activation, each clause must become an enforceable condition, a visible contextual check, or an unresolved question.
Unclear, conflicting, or unsupported conditions cannot silently disappear.
The owner confirms the interpretation and examples. A later edit creates a new draft, not a silent change to active permission.

A task-fit check is a contextual judgment. A registered destination or expiry is an enforceable restriction.
The product must explain that difference without requiring the owner to understand policy code.

### Bouncer and notifications

- Active rule plus valid low-risk assessment: permit the supported operation without another approval prompt.
- Rule requires approval, or uncertainty permits an approval fallback: pause the exact request and notify the owner.
- Explicit restriction or verified critical risk: block the request and explain why; alert for the required security events.
- Missing grant, unsupported operation, revoked access, or expired session: no execution.
- Required model failure or invalid result: ask or deny according to the rule, never grant automatic access because the check failed.

Jev remains the planned risk provider. The rule interpreter is a separate integration whose provider must be selected and verified.
The owner can approve once where permitted, deny, pause an agent, revoke access, or separately edit a rule.
Approval cannot override an explicit denial, and dismissing a notification is not approval.
MVP includes a durable inbox and one local notification channel. External email, chat, and mobile channels are later scope.

### Not included

MVP does not promise full 1Password parity, cloud sync, mobile clients, universal autofill, passkeys, team sharing, billing, or automatic credential rotation.
It excludes raw secret delivery to agents, unrestricted HTTP forwarding, arbitrary shell or SQL execution, open plugins, and delegated product identities.
Owner reveal/copy remains available and explicitly warns that copied values are outside continued Apassy control.
Grok subagents implement the product; their use does not imply support for agent delegation inside the MVP.

## 3. Decisions before implementation depends on them

| Decision | Required result | Deadline |
| --- | --- | --- |
| Initial platform and app form | A visual owner experience that fits daily use, with a tested agent isolation profile. No inherited Linux-only requirement. | P0, before platform-dependent code |
| Vault and key lifecycle | Established encryption design; lock, authenticated reveal, atomic edits, protected metadata, backup, and lost-key behavior | P0, before P2a |
| Operational state | Transactional grants, approvals, counters, audit, and notification outbox; coordination with credential revisions | P0, before P2b |
| First two connectors | Useful services, credential types, approved operations, destination identities, provider permissions, and result limits | P0, before P4 |
| Rule interpretation | Versioned draft schema, clause coverage, review process, provider contract, privacy terms, and test fixtures | Schema in P1; verified live provider before P6 |
| Jev | Verified access, outputs, model identity, privacy terms, region, limits, and cost | Before live P5a work and the P6 gate |
| Notification channel | Persistent inbox plus one authenticated local delivery path with private previews and failure status | P0, before P5b |
| Performance and release | Measured baseline, numerical budgets, candidate package, integrity checks, and recovery procedure | Before P7 acceptance |

Rust and macOS desktop with eframe/egui are confirmed. The owner approved SQLCipher evaluation for one encrypted transactional store.
Production storage acceptance, key handling, and the product isolation profile remain open. See [ADR 0001](adr/0001-p0-feasibility.md).
No production credentials are needed to choose contracts or build deterministic tests.
Unresolved platform isolation blocks tests with real secrets, but not a visual walkthrough or synthetic fixtures.
Missing model access permits core development but blocks any claim that the live interpreter or bouncer is complete.

## 4. Non-negotiable implementation contracts

### Owner and agent separation

The owner enrolls agents, sets trusted task context, and activates rules through an authenticated owner channel.
The agent cannot obtain owner authority, alter policy, inspect the owner's revealed credentials or clipboard, or approve its own requests.
Sessions are scoped and revocable. Agent-supplied identity, environment labels, and approval claims are not trusted facts.
P0 tests the actual OS boundary with a fixture service before any claim that a broker hides secrets from an unrestricted agent.

### Stored credentials and controlled use

Only trusted vault and connector paths can retrieve provider credentials for mediated use.
The item revision, destination binding, policy version, and connector capability version are part of each authorization.
Agent discovery reveals permitted references and operations only. It does not enumerate private vault contents.
A supported operation cannot quietly become a general-purpose proxy, raw SQL runner, or credential export.

The API connector accepts named operations with typed inputs and bounded results, not arbitrary URLs or headers.
The database connector uses registered destinations, least-privilege credentials, and reviewed read operations, not model-approved SQL strings.
Provider permissions and operation semantics must support the advertised restriction. A GET method or SELECT prefix alone does not prove safety.

### Rule activation and decisions

Keep original text, reviewed interpretation, unresolved issues, examples, and an owner confirmation record.
A model can propose a draft. It cannot activate it, drop restrictions silently, or reinterpret active policy at request time.
Explicit denials win across applicable scopes. Missing grants mean denial.
A confirmed low-risk automatic path is required for MVP; an always-ask implementation is incomplete.

### Execution, lock, and recovery

Both automatic and approved requests use the same canonical request and execution path.
Recheck current authority, then atomically persist intent, usage changes, any consumed approval, and required audit/outbox events before external execution.
That transaction is the authorization boundary. Earlier revocation blocks execution; later revocation cannot guarantee cancellation of the remote effect.

The same authenticated request ID and digest return existing state. Different content under that ID is a conflict.
A crash or timeout after a possible effect produces `unknown`, not an automatic retry of a state-changing operation.
A completed request, a pending approval, and a notification acknowledgment are different states.

Lock prevents new credential use and invalidates pending authority. It cannot undo an in-flight remote action.
Restart or restore begins locked and invalidates sessions and unused approvals with a fresh epoch.
Restored rules require owner review before new agent sessions. Old backups cannot reactivate consumed approvals or revoked sessions.

### Alerts and privacy

Alerts contain safe references and recorded reasons, not secret values, raw conversations, or unrestricted provider responses.
Delivery status, acknowledgment, and approval are separate. The owner can act only on a currently valid request.
Notification failure retains the inbox entry and never releases a paused request.
Repeated alerts have visible counts and underlying history. Required durable-recording failures stop execution and expose a health problem.

## 5. Implementation phases and Grok task scopes

P0 workers started after owner approval. Later tasks remain gated by the dependencies below.
The parent coordinates Grok workers and owns shared contracts, dependency files, module roots, UI entry points, and CI configuration.
Workers request shared changes rather than editing shared files concurrently. Each file has one editor at a time.
P0 and P1 include current files. Later task paths remain planned outputs.
See [foundation verification](operations/foundation-verification.md) for local results and remaining gates.

Order change on 2026-09-25: [ADR 0004](adr/0004-agent-path-first.md) builds a thin agent path before P3.
That path has parts of P2b, P4a, and P4c with temporary manual grants. It does not satisfy their acceptance checks.
P3 and P5 then build on that path. See the [broker contract](contracts/broker-v0.md).

| Task | Dependencies | Worker scope | Required result |
| --- | --- | --- | --- |
| P0 — walkthrough and feasibility | Owner approves this revised plan | `docs/adr/`, `docs/contracts/`, `design/`, `tests/fixtures/`, `tests/isolation/` | Show the complete owner journey with synthetic items. Confirm platform/app form, two services, storage decisions, and isolation evidence. Separate unresolved provider access from completed decisions. |
| P1 — Rust and app foundation | P0 decisions needed for the foundation | Parent coordinates a bounded foundation worker for package layout, shared schemas, UI shell, toolchain, and CI | Pinned Rust/dependencies, versioned item/rule/request/event contracts, offline test harness, and a visible app shell. No claim of completed features from placeholders. |
| P2a — vault | P1 | `src/vault/`, `tests/vault_lifecycle.rs` | Five credential categories, atomic CRUD, protected search, lock/unlock, reveal/copy authorization, encrypted backup, and recovery tests. |
| P2b — state and identities | P1 | `src/state/`, `src/identity/`, `migrations/`, `tests/agent_access.rs`, `tests/recovery.rs` | Authenticated enrollment, scoped sessions, revision state, durable requests, counters, audit/outbox transactions, and invalidation tests. |
| P2c — vault and agent views | P1 shared contracts | `ui/vault/`, `ui/agents/`, `tests/ui_vault/` | Add/edit/search items and connect/revoke agents through the visual app. Mocks can support development, but completion requires P2a/P2b integration. |
| P3a — rules and policy | Integrated P2 | `src/rules/`, `src/policy/`, `tests/rules_contract.rs`, `tests/policy_contract.rs` | Plain-language draft adapter, clause coverage, clarification, deterministic restrictions, immutable active versions, and activation authorization tests. |
| P3b — rule editor | P3a contract frozen | `ui/rules/`, `tests/ui_rules/` | Review original text, interpretation, unresolved clauses, examples, version differences, and confirmation through the app. Final acceptance requires the real rule path. |
| P4a — API connector | P3 policy contract and confirmed API service | `src/connectors/api/`, `tests/api_connector.rs` | One useful mediated API path, typed operations, destination and output controls, permission checks, and error tests. |
| P4b — database connector | P3 policy contract and confirmed database service | `src/connectors/database/`, `tests/database_connector.rs` | A second credential type in mediated use, bounded read operations, server identity, least-privilege checks, and hostile input tests. |
| P4c — broker and agent interfaces | P2 state plus P3 policy and frozen connector contracts | `src/broker/`, `src/agent/`, `tests/mediated_use.rs`, `tests/isolation.rs` | Authenticated CLI/MCP requests, exact request binding, execution recovery, limits, revocation, and actual isolation tests. Full acceptance requires P4a/P4b integration. |
| P5a — bouncer | Integrated P4; live work also needs verified Jev access | `src/risk/`, `src/bouncer/`, `tests/bouncer_contract.rs` | Allow/ask/deny behavior, contextual checks, no fail-open behavior, privacy controls, and versioned model contracts. Synthetic adapters are clearly labeled. |
| P5b — approvals and alerts | Integrated P4 and frozen bouncer event contract | `src/notifications/`, `ui/approvals/`, `ui/activity/`, `tests/approvals.rs`, `tests/notifications.rs` | Durable inbox, safe explanations, one local channel, owner actions, grouping, delivery failure, and stale-approval tests. |
| P6 — evaluation and complete journey | Integrated P5 and real interpreter/evaluator access | `tests/evals/`, `tests/live_providers.rs`, `tests/live_evaluation.rs`, `tests/ui_journey/`, `docs/evaluation/` | Held-out rule/risk evaluations, real sandbox connector checks, automatic normal use, ask/deny alerts, and full visual journey. Read-only security review precedes separately scoped repairs. |
| P7 — package and pilot | P6 gates pass | `packaging/`, `docs/operations/`, `docs/pilot/`, parent-owned release configuration | Verified install/update/recovery, approved resource budgets, private release candidate, and measured daily-use pilot. No automatic publication. |

P2 tasks can run in parallel after contracts are frozen. P3b can begin against the frozen rule contract while P3a completes.
P4 tasks can run in parallel against frozen contracts. P5 tasks can run in parallel against the shared event contract.
The parent checks integration at each gate. Work against a mock does not satisfy end-to-end acceptance.
The product walkthrough and working vault remain visible milestones, rather than appearing only after a long infrastructure project.

## 6. Acceptance checks

The targets below are proposals for plan approval, not measured outcomes.
The owner approves final model thresholds and resource budgets before pilot entry. A missing threshold is a blocker, not an implied pass.

### Vault and human experience

- Add, edit, search, reveal/copy, and delete test items in all five categories through the app.
- Keep values masked except during an authenticated owner action. Check the absence of provider secrets in agent output, logs, notifications, and model inputs.
- Prove lock, restart, corruption handling, encrypted backup/restore, and invalidation of old authority.
- At least 9 of 10 scripted owner sessions complete setup, item creation, rule review, and agent connection without policy code or terminal debugging.
- Target 20 minutes for first setup on a prepared supported machine, excluding provider account approval.
- During a five-day pilot, record successful use, abandoned tasks, repeated use, approval frequency, and alert usefulness.

### Rule interpretation

Use at least 100 held-out examples: 50 clear rules, 20 ambiguous rules, 15 unsupported requests, and 15 conflicting rules.
Cover who, credential, where, when/time zone, operation, purpose, limits, and combinations across both connectors.
Keep development cases separate. Freeze expected interpretations and unresolved issues before scoring.

- No unconfirmed draft becomes active.
- Every designated safety case preserves explicit restrictions or remains blocked for clarification. No silent broadening is accepted.
- All ambiguous, unsupported, and conflicting activation cases are stopped until resolved.
- At least 90% of clear rules produce a faithful reviewable draft on the first attempt.
- Report human review corrections, unresolved clauses, false restrictions, latency, and cost separately from runtime bouncer results.

### Bouncer and connector decisions

Use at least 200 held-out cases: 100 normal permitted requests, 50 explicit violations, and 50 suspicious or uncertain requests.
Cover both connector paths, all risk dimensions from the concept, and attacks on identity, destination, purpose, parameters, and rule interpretation.
Run the model cases three times with recorded provider, model, prompt, thresholds, and contract versions. Report each run.

- Zero explicit violations execute, even if the model returns a permissive result.
- Zero designated critical-risk cases receive automatic permission.
- At least 90 of 100 normal cases complete without another approval prompt in each run.
- Approval-required cases do not execute before a valid owner decision. Changed or replayed requests cannot reuse approval.
- Model failure never enables automatic use. Revocation, lock, expiry, and limits retain their effect under load and failure.
- Report false allows, false denials, escalation rate, uncertainty intervals, calibration where supported, and cost/latency by connector.

Sample results are limited evidence, not a universal guarantee. Do not tune against held-out cases and then present the same cases as independent validation.
A failed gate requires a fix and fresh evidence, or an explicit scope revision. An always-ask fallback cannot be labeled a completed MVP.

### Notifications and operations

- Blocked security cases and approval requests appear in the durable inbox. Target local notification attempts within five seconds while the channel is healthy.
- A delivery error appears in the app, retains the pending request, and retries within limits.
- Old notifications, duplicate actions, grouping, and acknowledgment never bypass approval or suppress decision history.
- Crash injection covers intent commits, provider calls, result storage, audit, outbox writes, and recovery.
- Independent review has no unresolved critical or high-severity finding across the complete app, including interpreter and UI boundaries.
- Establish hardware, payload, queue, concurrency, timeout, memory, latency, and storage-growth budgets before pilot acceptance.
- Test installation, locked startup, interrupted update, fixture schema migration, backup restore, and authenticated artifact integrity.

## 7. Planned verification commands

Current targets are `contracts`, `desktop_model`, and the feature-gated `sqlcipher_probe`, plus the Node and Python fixture suites.
See [development checks](operations/checks.md) and [desktop development](operations/desktop-development.md) for commands that exist now.
The table below lists later acceptance targets. Those targets and live/isolation features do not exist yet. Do not treat them as completed checks.
Default tests use synthetic credentials and local fixtures. They make no live model or external service calls.

| Area | Planned command |
| --- | --- |
| Rust format | `cargo fmt --all -- --check` |
| Static analysis | `cargo clippy --locked --all-targets -- -D warnings` |
| Vault | `cargo test --locked --test vault_lifecycle` |
| Agent identity | `cargo test --locked --test agent_access` |
| Rule interpretation contract | `cargo test --locked --test rules_contract` |
| Deterministic policy | `cargo test --locked --test policy_contract` |
| API connector | `cargo test --locked --test api_connector` |
| Database connector | `cargo test --locked --test database_connector` |
| Mediated use | `cargo test --locked --test mediated_use` |
| Bouncer | `cargo test --locked --test bouncer_contract` |
| Approvals | `cargo test --locked --test approvals` |
| Notifications | `cargo test --locked --test notifications` |
| Recovery | `cargo test --locked --test recovery` |
| Default offline suite | `cargo test --locked --all-targets` |
| Core build | `cargo build --locked --release` |
| Prepared isolation environment only | `cargo test --locked --features isolation-tests --test isolation -- --ignored --test-threads=1` |
| Approved sandbox services only | `cargo test --locked --features live-providers --test live_providers -- --ignored --test-threads=1` |
| Approved model evaluation only | `cargo test --locked --features live-models --test live_evaluation -- --ignored --test-threads=1` |

Isolation and live targets are feature-gated and ignored by default. A skipped test never satisfies its release gate.
P1 adds exact UI build, interaction, accessibility, and visual-check commands for the selected app toolkit.
Cargo checks alone do not prove that the owner interface works. P6 must exercise the full visual journey and inspect the result.
Dependency, license, and release-composition checks also receive pinned commands in P1.

## 8. Grok execution rules after approval

- Check `command -v grok`, `grok --version`, and `grok --help` before launch. Do not rely on an earlier planning preflight.
- Read applicable `AGENTS.md`, `GROK.md`, and current Git state. Inspect hooks, plugins, MCP, and shared memory without exposing credentials.
- Keep the current account, provider, and model unless the owner requests a change. Verify supported options before use.
- Give each worker one bounded task, permitted paths, prohibited actions, exact tests, English writing rules, and applicable UI/browser restrictions.
- Verify tool names, permission rules, and sandbox behavior. A restrictive prompt alone does not restrict filesystem or network access.
- Create private prompt and result files with `mktemp -d`. Use absolute paths and a distinct UUID per Grok session.
- Use top-level `--prompt-file`, `--session-id`, bounded `--max-turns`, `--no-subagents`, `--disable-web-search`, and `--output-format streaming-json`.
- Apply verified task-specific permissions. Never solve a denial with `--always-approve` or `bypassPermissions`.
- Start through parent process control, retain its handle separately from the Grok UUID, and never detach workers.
- Track task, paths, working directory, process handle, Grok UUID, prompt/result paths, exit status, and unresolved limitations.
- Use one editor per file. The parent integrates shared changes and checks each diff without discarding user changes.
- Keep worker logs private. Never put real credentials, private provider responses, or sensitive prompts in repository artifacts.
- Live calls, billable evaluations, package installation, and privileged environment setup require specific authorization.
- Read stdout and stderr. Verify actual ACP events, exit codes, permission failures, and turn limits. Exit zero alone is insufficient.
- Require changed paths, exact checks, results, findings, and checks not run. The parent independently reruns focused checks.
- Resume with the exact UUID through `--resume`, with the same restrictions. Do not use `--continue` or `--restore-code` for concurrent work.
- Do not create worktrees, commit, push, publish, deploy, or delete sessions without an explicit owner request.

## 9. Approval and definition of done

The owner approved this revised plan and implementation with Grok subagents on 2026-09-16.
That approval starts P0. It does not settle the open technical choices or waive later acceptance gates.
The earlier mandatory-per-request-approval policy, GitHub workflow scope, and Linux-only baseline are not carried forward.

After approval, the first Grok task is P0: a concrete owner walkthrough, feasibility evidence, and the decisions needed for implementation.
The parent reports completed gates and stops on concrete blockers. Missing model access, isolation, or connector capability cannot be hidden by a stub or weaker mode.

MVP completion requires the visual vault, all five stored credential categories, two tested mediated-use paths, confirmed plain-language rules, and automatic normal use.
It also requires ask/deny behavior, useful notifications, revocation, live model evaluation, and verified recovery on the supported configuration.
A private pilot report must include exact commands, exit codes, meaningful results, unmet targets, and checks not run.
No release, production access, or Grok implementation worker is authorized by this document rewrite alone.
