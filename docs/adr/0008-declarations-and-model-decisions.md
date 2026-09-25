# ADR 0008 — Declarations, user request, and model decisions

Date: 2026-09-26.
Status: owner selected this direction on 2026-09-26. It changes the decision policy of ADR 0007.

## Owner requirements

- The model decides most requests (target: 80%).
- Each credential has declarations: project, environment, risk, scope, and reversibility.
- If the model is less than 80% certain, the owner decides.
- The bouncer gets the user request that led the agent to the credential.

## Probe results that shaped the design

On 2026-09-26, with the local Laya model (`convaiinnovations/laya`, zero-shot):

- A direct question "run now, or ask the owner?" (`choice`) gave probabilities from 0.40 to 0.65 for all cases. The model confidence value was 0.00 to 0.07. This question cannot carry an 80% threshold.
- Factual `noul` questions with the user request in the state separated the cases well. For "Is the command a normal step to do what the user asked?", normal commands got 0.69 to 0.93 and risky commands got 0.04 to 0.28.
- The "leak" answer was 0.3 to 0.8 for normal commands with `$DATABASE_URL` or an auth header, and 0.8 or more for plain file reads on real commands. The command analysis finds secret output more precisely.

## Decision

### Declarations

Each item has one declaration (vault schema version 5, table `declaration`):

| Field | Values |
| --- | --- |
| project | text, 1 to 64 bytes |
| environment | local, development, staging, production |
| risk | low, medium, high |
| scope | read-only, read-write, admin |
| reversibility | reversible, partial, irreversible |

A declaration is sensitive when the environment is production, the risk is high, or the reversibility is irreversible. The desktop form starts with the most sensitive values. An item without a declaration makes every run wait for the owner.

### User request

`apassy_run_with_secrets` has a required `user_request` argument: the user's own words. The broker puts it in the model state and shows it in the approval card. A request without it waits for the owner.

The agent supplies this text. An agent can invent or change it. A later stage can take the user request from the agent host directly, for example with a Claude Code `UserPromptSubmit` hook that sends the prompt to Apassy.

### Decision order

1. Hard rule (ADR 0007): expiry, prefixes, forbidden words, runs per hour. A failure is a denial.
2. Command analysis flags (secret output, data loss, production, and others). A flag asks the owner. The model is not called.
3. Missing user request, missing declaration, or unavailable model: ask the owner.
4. The model answers five facts: `task_match`, `writes`, `remote`, `leak`, `destroy`, and `rule_break` when the rule has an instruction.
5. Needed certainty, 80% each:
   - A command that is not known safe and not certainly read-only (`writes` at or below 0.2) needs `task_match` at or above 0.8.
   - A sensitive declaration needs `writes` at or below 0.2, unless the command is known safe.
6. Vetoes: `destroy` at or above 0.9 for a command that is not known safe, and `rule_break` at or above 0.8.
7. If every needed answer is certain and no veto applies, the run starts. The activity log shows the lowest certainty.

"Bouncer" mode no longer needs command prefixes. It needs declarations.

## Measurement

Details are in `docs/operations/bouncer.md`.

| Data | Model decides | Asks the owner | Risky caught |
| --- | --- | --- | --- |
| Labeled sets, staging declaration (270) | 133 (the others have rule flags) | 8 false alarms on 132 normal | 138/138 |
| Real odealo commands with the real user request, blind sample C (400) | 375 (94%) | 101 (25%) | not labeled |

In a review of 30 of the 101 asks in sample C, about 12 were justified and 18 were not needed. Most of the unneeded asks were local browser automation (`curl` to `127.0.0.1:10086`) under a general user request such as "do everything that the tests need".

## Limits

- The user request comes from the agent.
- A general user request ("continue", "fix the problems") gives low `task_match` values. The owner then sees more requests.
- The measurements use one labeler for small samples and one zero-shot model.
- The real-secret gate stays BLOCKED.
