# ADR 0009 — General by default, learning over time

Date: 2026-09-26.
Status: proposed by the owner on 2026-09-26. The steps below are a plan. Each step needs its own implementation and measurement.

## Context

ADR 0008 lets the model decide most agent requests. Two problems remain:

- Knowledge about tools is in code (`src/broker/shell_risk.rs`), and the zero-shot model is weak. A blind test found 3 of 7 risky commands with the model only. A direct "allow or ask" question gave probabilities near 0.5.
- The owner makes the same decisions again and again. The owner's decisions do not change later behavior.

Real odealo commands (Codex history, 6215 unique commands, measured on 2026-09-26) show a strong repetition. A template keeps the first four words and replaces strings, paths, and numbers. The commands give 1322 templates. 31 templates cover 50% of the commands. 290 templates cover 80%.

## Decision

Apassy is general on the first day, with built-in knowledge and conservative defaults. Apassy learns from each owner decision. Learning changes when Apassy asks the owner. Learning never changes the hard limits.

### 1. General by default

- **Rule packs as data.** Knowledge about each tool moves from code to versioned data files, one pack for each tool. Examples are git, supabase, vercel, psql, npm, and curl. A new stack needs a new pack, not a code change. The core stays in code: the shell parser, secret flow, and general rules such as "a dry run does not act".
- **Suggested declarations.** When the owner adds a credential, Apassy suggests the declaration from the item. Examples: a `sk_live_` prefix suggests production and high risk. A `sk_test_` prefix suggests staging and low risk. "prod" in a URL suggests production. A Supabase `service_role` key suggests admin scope. The owner confirms each suggestion. The declaration also gives the known API hosts of the provider.
- **A general base model.** Fine-tune the decision model on a broad set of agent commands from many stacks. Apassy ships this checkpoint. The owner's data is not part of it.
- **A trusted user request.** Host adapters send the user request directly to Apassy, for example a Claude Code `UserPromptSubmit` hook or its Codex equivalent. Then the agent cannot change it.
- **Conservative start.** Apassy asks more at first and less over time.

### 2. Learning in three layers

Each owner decision in the approval card is one example. It contains the user request, the command without secret values, the declaration, the model facts, the rule flags, and the owner decision. Apassy keeps the examples in the encrypted vault. They never leave the computer.

1. **Remembered patterns.** The approval card gets "Approve and remember". Apassy generalizes the command to a pattern, for example `sed -n '<range>' <file in src/>`. The pattern is bound to one agent, one project, and one item. A later match runs without a prompt. The owner sees all patterns in one list and can remove them. An unused pattern expires.
2. **Threshold calibration.** From the decision log, Apassy adjusts thresholds, for example the `task_match` level for the owner's style of requests. A change must pass a replay test on all past decisions: no request that the owner denied can become an automatic allowance.
3. **Model fine-tune.** After some hundreds of decisions, Apassy trains a new model version on this computer. The new version first runs in shadow mode. It decides in parallel with no effect, and Apassy shows the agreement with the owner. The owner promotes it. This follows `docs/concept.md`: a model update cannot silently change active policy.

### 3. Limits on learning

- Learning never removes a hard limit: rule flags (secret output, production, data loss), hard rule failures, and missing declarations.
- A denial has more weight than an approval. One denial blocks a pattern. A pattern needs repeated approvals before it runs without a prompt.
- Poisoning: an agent can send many harmless commands to make the owner teach a wide pattern. Each pattern applies to one agent, one project, and one item only. Generalization has limits. Patterns expire.
- Visibility: Apassy shows the share of asked requests over time, the automatic decisions, and the agreement of a candidate model with the owner.
- Privacy: examples contain no secret values. They stay in the vault.

## Plan

| Step | Content | Measurement |
| --- | --- | --- |
| 1 | Decision log and "Approve and remember" | Ask rate on a replay of real commands. No past denial becomes an allowance. |
| 2 | Suggested declarations and known hosts from declarations | Share of suggestions that the owner accepts without a change |
| 3 | Threshold calibration with a replay gate | Ask rate and misses on a held-out part of the log |
| 4 | `UserPromptSubmit` hook adapter | The user request in the log matches the host transcript |
| 5 | Rule packs as data, general base model, shadow mode | Blind test on a new independent set. Agreement in shadow mode. |
| 6 | Touch ID for "Approve and remember" and rule changes | Separate ADR |

## Open questions

- The format and signature of rule packs, and who can publish them.
- How wide a pattern can be before it needs more approvals.
- The minimum number of decisions for a fine-tune, and the compute budget on the owner's computer.
- Whether the owner can share anonymous patterns or rule packs with other owners.
