# Apassy — Product Vision v1

Date: 2026-09-16.
Status: revised product direction before implementation. The document version is not a production release.
This revision replaces the earlier GitHub-centered scope. Rust remains confirmed for the core.

## 1. The product

Apassy is a credential manager for you and your agents.
The ambition is a better 1Password-like experience for a person who also wants agents to use credentials under their control.
This is a product direction, not a claim of feature parity or proven superiority.

You keep different credential types in one vault.
You write rules in ordinary language about who can use them, when, where, and for what purpose.
A bouncer checks agent requests, permits normal use, pauses uncertain requests, blocks forbidden use, and informs you when something needs attention.

The vault is the product's foundation, not an incidental place to keep a GitHub token.
A human-facing interface, plain-language rules, and useful alerts belong in MVP.
CLI and MCP are ways to connect agents. They do not replace the human experience.

## 2. The everyday experience

The first user is a person who stores credentials and wants an agent to use selected ones without unrestricted access.
The product is not limited to developers, one repository, or one provider.

The basic journey is:

1. Add a credential to the vault.
2. Give it a useful name and choose its type.
3. Connect an agent and confirm its identity.
4. Write a rule for that agent's use of the credential.
5. Review Apassy's interpretation and activate the rule.
6. Let the agent work within that rule.
7. Review alerts, answer approval requests, or revoke access when needed.

For example, you save an API key as “Project A reporting service.” You write:

> My reporting agent can use this credential for Project A, against staging, until Friday. Never use it for production. Ask me if the request does not fit the task.

Before activation, Apassy resolves the named agent, credential, service, environment, exact expiry, and time zone with you.
It shows what the connector can enforce and what requires a contextual risk assessment.
It does not silently guess what “staging” or “Friday” means.

A normal permitted report request completes without another approval prompt.
A request for production is blocked, and you receive an explanation.
An uncertain request pauses for your decision if your rule permits that fallback.
You can see which credential and agent were involved without exposing the secret in an alert.

## 3. What belongs in MVP

### A useful personal vault

- Add, view, edit, search, organize, and delete credentials through a visual interface.
- Store API keys/tokens, username/password logins, SSH keys, database credentials, and custom secret fields.
- Keep useful labels, service references, notes, and project tags with each item.
- Mask values by default. Permit deliberate owner reveal/copy after the required authentication.
- Lock and unlock the vault, make encrypted backups, and restore it through a documented procedure.
- Show each item's access rules, connected agents, supported uses, and recent history.

Credential storage and agent-use support are different capabilities.
MVP stores all the types above, but only claims agent use through tested connectors.
An unsupported item remains useful to its owner and clearly says that agent use is unavailable.

### Rules in ordinary language

The owner should not need to write JSON, YAML, or policy code.
Rules cover the agent, credential, project, destination, operation, time window, usage limit, and approval or alert conditions where supported.

Apassy shows the original text beside its interpretation and examples of allowed, blocked, and approval-required requests.
Unclear, conflicting, or unsupported conditions prevent activation until resolved.
The product keeps explicit restrictions separate from contextual judgments such as “does this fit the task?”
A rule change requires owner confirmation and cannot silently expand an existing grant.

### Agent access and the bouncer

- Connect agents with scoped identities and revocable sessions.
- Let agents discover only the credential references and supported operations they may use, not the whole vault.
- Check every request against active rules and trusted identity and destination information.
- Use contextual risk assessment to detect suspicious requests, prompt injection, possible disclosure, and unusual behavior.
- Permit routine, low-risk use under an active rule without repeated approval.
- Pause requests that require a decision. Block explicit violations.
- Prevent the requesting agent from approving itself or changing its own rules.

Jev remains the planned risk provider, subject to verified API access, processing terms, and evaluation.
Plain-language rule interpretation is a separate responsibility. It must not assume that Jev supports a rule-authoring API.
A model cannot override an explicit restriction. A failed or incomplete required assessment never grants automatic access.

### Alerts and control

MVP includes a persistent activity history, an approval inbox, and a local notification channel.
Alerts identify the agent, credential reference, requested use, relevant rule, decision, reason, and available next steps.
They do not contain secret values or raw conversations.

The owner can approve one request, deny it, pause an agent, revoke access to an item, or change a rule separately.
Dismissing a notification is not approval. Notification delivery failure does not turn a paused request into an allowed one.
Repeated alerts are grouped without hiding their frequency or losing the underlying decisions.

## 4. What access control can promise

For mediated use, Apassy uses the credential through a controlled connector and returns the permitted result.
The intended boundary keeps the provider credential out of the agent's context, files, and environment.
That claim requires tested isolation of the vault, owner interface, and execution service from the agent.

If a tool receives the raw credential, it can copy and reuse it outside Apassy.
Rules cannot then guarantee where or how the copied credential is used. Revocation may require a change at the provider.
MVP does not silently fall back to raw credential delivery. Such a compatibility mode requires a separate scope decision and visible warnings.
Owner reveal/copy is also deliberate disclosure, not continued control over the copied value.

Apassy does not guarantee that all harmful requests will be recognized.
It cannot undo completed actions, retract disclosed data, or protect against an attacker who controls the trusted host or owner account.
These limits must appear in the product, not only in technical documentation.

## 5. MVP boundaries

MVP serves one owner, multiple stored credentials, and explicitly enrolled agents on one tested local configuration.
The [MVP plan](mvp-plan.md) proposes two connector paths that exercise different credential types.
The first services and supported platform require confirmation. GitHub is an optional integration, not the product definition or a required workflow.

MVP does not attempt full 1Password parity, cloud sync, mobile clients, universal autofill, passkeys, team sharing, billing, or automatic rotation.
It also excludes arbitrary shell execution, unrestricted HTTP forwarding, delegated subagent identities, and unreviewed plugins.
These exclusions limit implementation breadth, not the central vault-and-bouncer experience.

## 6. Readiness and later scope

MVP is ready only when the owner can complete the full journey through the human interface:

- Store and manage the five credential categories.
- Activate a clear rule and correct an ambiguous one.
- Connect an agent and observe permitted use without another approval prompt.
- Receive and resolve an approval request, then observe a blocked request and its alert.
- Revoke access and verify that future execution is prevented.
- Recover the vault without restoring old sessions or consumed approvals.

Evidence must cover rule interpretation, bouncer quality, privacy, connector enforcement, notifications, usability, and failure recovery.
A CLI demo, a vault-only build, or an always-ask bouncer does not satisfy this definition.
The plan defines measurable gates and separates deterministic tests from live provider evaluation.

Later product versions can add more connectors, imports from existing managers, sync, shared vaults, teams, mobile access, and rotation.
Their priority should follow actual use. A human interface and normal automatic permitted use are not deferred to those versions.

Related documents: [product concept](concept.md), [infrastructure](product-infra-v1.md), and [implementation plan](mvp-plan.md).
