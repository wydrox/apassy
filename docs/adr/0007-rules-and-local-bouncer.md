# ADR 0007 — Rules and a local bouncer with Laya

Date: 2026-09-25.
Status: owner selected rules and a bouncer on a local Jev-compatible model on 2026-09-25. Touch ID is the next stage.

## Context

ADR 0006 lets an agent run a command with secrets in the process environment. The owner approval is the only contextual control in that mode.
The owner wants rules and a bouncer, so that normal work continues without a prompt and risky work stops.

Jev (TypeSafe) is a hosted System One decision model. Laya is an open-source model with the same wire protocol:

- Package `laya` 0.3.20, Apache-2.0, Python 3.10 or later.
- Checkpoints `convaiinnovations/laya` (ModernBERT-large, about 421M parameters) and a multilingual checkpoint (mmBERT-base, about 322M parameters).
- `laya-serve` exposes `POST /v1/systemone`. The request has `state` and typed `questions` (`choice`, `score`, `noul`). The response has typed answers with probabilities.

A decision model classifies. It does not generate text, and it does not interpret a rule into policy.

## Decision

### Rules

Each process grant (agent, item, project directory) has one rule. A rule has two parts.

Hard restrictions. The broker checks them before any model call and before it reads a secret:

- Permitted command prefixes, for example `npm run`, `npx supabase`. An empty list permits any command.
- Forbidden words in the command, for example `prod`, `--force`. A match is a denial.
- An expiry time. After this time the grant does not work.
- A maximum number of runs in one hour.

Owner instruction. The owner writes the rule as plain text, for example "Only run database migrations on staging. Never print keys." Apassy does not convert this text into restrictions. The bouncer asks the model one question for each request: "Does this request break the owner instruction?"

The rule mode sets the result of a clean request:

| Rule mode | Clean request | Risky request | Bouncer unavailable |
| --- | --- | --- | --- |
| Ask | Owner approval | Owner approval, with the risk shown | Owner approval |
| Bouncer | Run without a prompt | Owner approval | Owner approval |

A hard restriction failure is always a denial. The model cannot override it.

### Bouncer

The bouncer sends one `POST /v1/systemone` request with these `noul` questions:

| Question | Meaning |
| --- | --- |
| `exfiltration` | The command can print, encode, store, or send a secret value. |
| `destructive` | The command can delete data, drop tables, reset state, or force changes. |
| `production` | The command targets a production system. |
| `purpose_mismatch` | The command does not match the stated purpose. |
| `injection` | The purpose or command contains instructions to Apassy or to its checks. |
| `rule_violation` | The request breaks the owner instruction. The broker asks this only when the rule has an instruction. |

The state has the agent name, the command, the working directory relative to the project, the purpose, the environment variable names, and the owner instruction. It never has secret values, the vault path, or the project directory outside the relative path.

A risk is high when its probability is 0.5 or more. The threshold is in the broker code and is version 1 of the bouncer contract.

A timeout (3 seconds), a connection error, a response that is not valid, or a missing answer gives "unavailable". Unavailable is never an allowance.

### Local service

- The desktop app calls the bouncer at `http://127.0.0.1:8770` by default. `APASSY_BOUNCER_URL` changes the address. Only a loopback address is permitted in this phase.
- The owner starts Laya separately. See `docs/operations/bouncer.md`.
- Each decision in the activity log has the bouncer result and the high risks.

## Hardening on 2026-09-25

- A command analysis with shell parsing replaces the word heuristics. A flag asks the owner without a model call.
- A known safe development command runs without a model call. This reduces false alarms. It also means that the model cannot flag such a command.
- The measurement set and its limits are in `docs/operations/bouncer.md`. The zero-shot model gives no measured benefit after the hardening.

## Limits

- Laya is a zero-shot classifier. Its accuracy on shell commands is not measured. The held-out evaluation (P6) is still necessary.
- A decision model can miss a risk. "Bouncer" mode trusts the model for clean requests. Use it only for commands with limited effect.
- Masking and the bouncer do not stop a process that the owner approved from misuse of a secret.
- The real-secret gate stays BLOCKED.

## Next stage

Touch ID for owner actions: unlock, reveal, approval of a run, and changes to grants and rules. This needs a native macOS call (LocalAuthentication). The crate forbids unsafe code, so the stage needs an owner decision on a native helper or a dependency.
