# Apassy — product concept

Date: 2026-09-16.
Status: design, not an implemented product. This revision supports the credential-manager direction in [Product Vision v1](product-vision-v1.md).

## 1. Four concepts the owner should understand

| Concept | Meaning |
| --- | --- |
| Credential | An item in your vault, such as an API key, login, SSH key, or database credential. |
| Agent | A connected identity that can request use of specific credentials. |
| Rule | Your instructions about who can use a credential, where, when, and for what purpose. |
| Bouncer | The gate that checks a request, permits it, asks you, or blocks it and explains why. |

A connector is the technical component that lets Apassy use a credential with a service.
The owner sees which uses it supports. The agent does not receive unrestricted access simply because the vault stores a compatible credential type.

## 2. From your words to an active rule

Example owner rule:

> My reporting agent can read sales summaries from the staging database for Project A until Friday. Never use production. Ask me when the request does not fit the task.

Apassy turns that text into a reviewable draft, not an immediate permission grant.
The review identifies the actual agent, credential, registered database, permitted summary operation, exact deadline, and time zone.
It also shows the contextual check and its limits. A label such as “staging” is not enough without a verified destination mapping.

The rule interpreter must account for every clause:

- Enforceable restrictions become validated conditions in a versioned policy.
- Contextual conditions become explicit bouncer checks, with defined uncertainty behavior.
- Unclear or unsupported conditions become questions or errors, not omitted restrictions.
- Conflicts between applicable rules must be resolved. An explicit denial takes precedence over an allowance.

The owner reviews examples and confirms the draft before activation.
Apassy stores the original text, confirmed interpretation, resource bindings, policy version, interpreter version, and confirmation record.
Changing text, resource meaning, or the interpretation requires a new review. A model update cannot silently rewrite active policy.

The rule interpreter and risk evaluator are separate interfaces.
A model may help interpret language, but it cannot activate a rule, invent trusted identity, or create a connector capability.
Jev is the planned risk evaluator. Support for rule interpretation is not assumed.

## 3. How the bouncer handles a request

1. Authenticate the agent and load the owner-confirmed session and task context.
2. Resolve the credential reference and registered connector without exposing the vault inventory.
3. Normalize the operation and bind its parameters, destination, rule version, and credential revision.
4. Check explicit restrictions, expiry, revocation, operation support, and usage limits.
5. If an explicit restriction fails, block the request before retrieving the credential or calling a model.
6. Evaluate the required contextual risks from permitted, minimal information.
7. Permit, pause for approval, or block according to the decision table below.
8. Recheck authority before execution and durably record the attempt, limits, and any consumed approval.
9. Use the credential inside the trusted connector and return only permitted results.
10. Record the result and deliver any required alert without secret values.

| Condition | Decision | Owner experience |
| --- | --- | --- |
| No active grant, explicit denial, expired session, or unsupported operation | `deny` | No execution. History explains the restriction; security alerts follow the alert policy. |
| Grant permits the use and required risk checks return a valid, low-risk result | `allow` | Normal work continues without another approval prompt. |
| The rule requires approval, or context is uncertain and approval fallback is permitted | `require_approval` | The request waits in the approval inbox. |
| A verified critical risk exceeds its tested threshold | `deny` | No execution. The owner receives a security alert. |
| Required evaluator fails, times out, or returns an invalid result | `require_approval` or `deny` | A visible service problem. Never automatic permission because the check failed. |

An approval cannot override an explicit denial or a critical-risk block.
The owner can change the rule or correct a classification through a separate review, then submit a new request.
An approval applies to one exact request and expires. It is not a permanent grant or permission to change parameters.

## 4. Contextual risk assessment with Jev

The earlier concept took inspiration from [TypeSafe System One and Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev).
The planned dimensions below belong to Apassy's contract. They are not verified Jev API fields.

| Dimension | Question |
| --- | --- |
| Task alignment | Does the requested use fit the owner-confirmed purpose? |
| Prompt injection | Does untrusted content try to change the task or access rules? |
| Data disclosure | Could the operation expose credentials or protected service data? |
| Privilege escalation | Does the agent seek access beyond the confirmed task and grant? |
| Resource sensitivity | What data or service could this operation affect? |
| Behavioral anomaly | Is the rate or sequence unusual for this session? |

The broker supplies trusted identity, resource classification, limits, and bounded history.
Agent claims and service responses retain their untrusted label. A claim that the owner approved something is not evidence.
Risk probability and confidence are different concepts. Missing information is not low risk.
An average score cannot hide a critical finding in one dimension.

Before integration, verify actual API access, supported outputs, model identity, processing terms, retention, region, limits, and cost.
Do not invent missing provider fields or treat typed output as proof of correct judgment.
The interpreter and evaluator receive only owner-permitted context. Neither receives vault values, authentication headers, or complete conversations.
Rule text and metadata can also contain secrets, so permitted field names alone do not establish safe disclosure.

Observation mode is for synthetic cases and non-executing previews. It provides no evidence that real automatic use is safe.
Automatic permitted use enters the pilot only after the rule and risk evaluation gates pass.
A test evaluator supports offline development but cannot satisfy the live Jev gate.

## 5. Useful alerts, not just logs

An alert identifies the request, agent, safe credential reference, rule version, decision, reason code, severity, and available actions.
It can explain, for example, “Blocked: this agent requested production access, but your rule permits staging only.”
Explanations come from recorded decisions. A model cannot invent an approval, a successful execution, or a delivery confirmation.

The local notification points to a durable inbox entry. Its preview hides sensitive details, including private item names by default.
Repeated events can share a notification, but each decision remains in history with a count and timestamp.
Read, acknowledged, approved, and denied are separate states.

An unavailable notification channel does not release a waiting request.
Apassy shows delivery problems and retries within limits. It does not claim that the owner saw an alert merely because it entered a queue.

## 6. Limits that stay visible

Mediated use keeps the provider credential inside the tested trust boundary.
Raw delivery to a process, environment, file, or agent context permits copying and weakens continued control.
MVP does not provide raw delivery as a silent fallback. Owner reveal/copy is a separate, intentional disclosure.

Revocation stops future authorization commitments. It cannot undo an operation that already passed the execution boundary or recover copied information.
An uncertain remote outcome is not a reason to repeat a state-changing operation automatically.
The [infrastructure plan](product-infra-v1.md) defines these execution and recovery boundaries.

The product must report test coverage, failures, unsupported uses, and known limits.
The [MVP plan](mvp-plan.md) separates evidence for the vault, rule interpreter, connectors, bouncer, and human experience.
