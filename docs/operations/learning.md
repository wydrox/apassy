# Learning: decision log, remembered patterns, and calibration

Date: 2026-09-26. Decisions: [ADR 0009](../adr/0009-general-by-default-and-learning.md), [ADR 0010](../adr/0010-closing-open-decisions.md). Goal items: B3, B5, B10, and the wait record of N3.

Apassy learns from the owner decisions in two ways:

- A remembered pattern lets a command that the owner approved 3 times run without a prompt (ADR 0009 step 1).
- A calibration lowers the `task_match` level of the model step when the decision log supports it (ADR 0009 step 3).

Both act only at the model step. They never change a hard rule, the production rule, a rule flag, a missing declaration, or a missing user request. The owner makes each change. Nothing changes the active policy without the owner (`docs/concept.md`).

A third way is a local fine-tune of the model (ADR 0009 step 5c, goal item B9). The candidate model runs in shadow mode with no effect, and only the owner promotes it. See [the fine-tune](fine-tune.md), sections 6 to 12, and section 5 below.

## 1. Decision log

Code: `src/vault/learning.rs` (storage), `src/broker/learning.rs` and `src/broker/run.rs` (the broker writes it).

The broker stores one entry for each decision in the encrypted vault (schema 7, table `decision_log`):

| Decision | `decided_by` | `decision` | `asked` |
| --- | --- | --- | --- |
| A hard rule or a request check denies the request | `rule` | `deny` | no |
| The model allows the run | `model` | `allow` | no |
| An active remembered pattern allows the run | `pattern` | `allow` | no |
| The owner approves or denies | `owner` | `allow` or `deny` | yes |
| The owner does not answer in time, or a lock ends the wait | `no_answer` | `deny` | yes |

An entry has: the time, the agent, the project directory, the working directory relative to the project (`cwd_rel`), the item IDs, the user request and its source (`agent`, `host`, or `none`), the command, the purpose, the owner instruction, the environment variable names, the declaration of each item, the rule flags, "known safe", the model facts, the generalized pattern, "a grant in ask mode", the decision, who made it, "approve and remember", the policy (bouncer contract and `task_match` level), and the decision note.

No secret value:

- The agent never gets a secret value, so the command and the user request normally have none.
- Before the vault stores an entry, it replaces each secret field value (4 bytes or more) of the items in the run with `[apassy:secret]`. This covers the command, the user request, the purpose, the instruction, the pattern, and the note. `decision_log_and_export_have_no_secret_values` in `tests/learning.rs` sends the secret value in the command and in the user request and checks the log and the export.
- Limit: the mask finds exact values only. It does not find a value of another item, or an encoded value.

Bounds:

- The log keeps the newest 10,000 entries that are not owner denials, and the newest 2,000 owner denials. Denials stay longer because the calibration replay needs them.
- The vault removes older entries once every 64 new entries. So the log can hold up to 63 entries more for a short time.
- Field limits: command 8192 bytes, user request 2000 bytes, purpose 500 bytes, note 1000 bytes, other text 2048 bytes.
- A restore keeps the log. It removes all patterns.

## 2. Remembered patterns ("Approve and remember")

Code: `src/broker/patterns.rs` (generalization), `src/broker/learning.rs`, `src/vault/learning.rs` (table `remembered_pattern`).

### Generalization

A pattern generalizes arguments by type only (ADR 0010):

- `<file>`: a path inside the project directory, by text. The working directory is the start of a relative path.
- `<number>`: digits, with an optional decimal part.
- `<string>`: a quoted argument. In an argument list without a shell, an argument with a space or a shell character counts as a quoted string.

Every other word stays literal. Narrow rules:

- The program and the next word (the subcommand) stay literal, also when the next word is a file. `node scripts/seed.js` stays literal.
- A command with a program that runs code or queries from its arguments keeps each file and string literal: shells, `node`, `deno`, `bun`, `tsx`, `python`, `ruby`, `perl`, `php`, `osascript`, `awk`, `jq`, `yq`, SQL clients, `eval`, `source`.
- A path with a hidden part (`.env`, `.git/config`), a path outside the project, a host (`example.com/x`), and a word with `:` or `@` stay literal.
- A word that the shell expands (`$NAME`, globs, `~`, `!`, braces) stays literal.
- `sh -c TEXT` and `bash -lc TEXT`: Apassy splits the script into commands and words. A line break ends a command. A comment is not part of the pattern. A word with a backslash stays literal. A script with a here-document or a command substitution stays literal. After `cd`, relative paths stay literal.

Examples:

| Command | Pattern |
| --- | --- |
| `git log -n 20 -- src/main.rs` | `git log -n <number> -- <file>` |
| `git commit -m "fix the login form"` | `git commit -m <string>` |
| `bash -lc "sed -n '1,80p' src/a.ts \| head -n 5"` | `bash -lc 'sed -n <string> <file> \| head -n <number>'` |
| `git add .env` | `git add .env` |
| `psql -c "select * from users"` | `psql -c 'select * from users'` |

### Binding and life

- A pattern belongs to one agent, one project directory, one working directory, one item set, and one policy. The policy is the declaration of each item and the owner instruction. A change of a declaration or of the instruction starts a new pattern.
- "Approve and remember" adds one approval. After 3 approvals, a matching request runs without a prompt.
- One owner denial blocks the pattern. Apassy blocks the pattern of every denied request, also of a request that could not teach a pattern (a rule flag or a production item). So a later rule change cannot open a denied request through a pattern. A blocked pattern stays until the owner removes it.
- A pattern that nobody approved or used for 30 days expires. An approval of an expired pattern starts again at 1.
- Limits: 1,000 learning and active patterns. When the list is full, the least recently used learning pattern goes. When all are active, Apassy does not store a new pattern. 5,000 blocked patterns; at the limit, the oldest block goes.
- A revoke of the agent, a delete of an item, and a restore remove the patterns.

### The approval card

The card offers "Approve and remember" only for a run that can teach a pattern: no production item, no rule flag, a user request, a declaration for each item, a grant in "bouncer" mode, and no block. The card shows the pattern and its approvals, for example `Pattern: sh -c './report.sh --limit <number>' (1 of 3 approvals)`.

"Approve and remember" is an approval. It uses the owner check of goal item A4 and the queue path of "Approve once":

1. `DesktopApp::ask_owner(OwnerRequest::ApproveAndRemember(run))` in `src/desktop/ui.rs` (`agents_view::draw_approvals`).
2. `OwnerGate::authorize(OwnerAction::ApproveAndRemember(run), check)`: Touch ID or the passphrase now.
3. `ApprovalQueue::approve(proof)` in `src/broker/approvals.rs`. The queue refuses it for a run without a pattern offer (`ApprovalRefusal::NothingToRemember`). The run ends with `ApprovedAndRemembered`.
4. The broker adds the approval after it checks the vault, the agent, and the rules again, in the same vault session (`learning::remember` in `src/broker/run.rs`).

A denial needs no owner check. Remove a pattern in the Learning view. A removal makes the policy stricter, so it needs no owner check.

Tests: `approve_and_remember_three_times_then_the_pattern_runs_without_a_prompt` and `one_denial_blocks_the_pattern` (`tests/learning.rs`) run the broker. `approve_and_remember_and_calibration_need_the_owner_check` (`src/desktop/ui/owner_tests.rs`) shows that a wrong passphrase approves nothing and the right one gives `ApprovedAndRemembered`. `approve_and_remember_with_an_offer` and `approve_refuses_without_a_matching_fresh_proof` (`src/broker/approvals.rs`) test the queue.

## 3. Place in the decision order

See [the bouncer](bouncer.md), section 3, step 4a. A pattern replaces only the model step. Tests:

| What must not change | Test |
| --- | --- |
| Hard rule failure: forbidden word, expired rule, hourly limit | `an_active_pattern_never_overrides_the_earlier_steps` (`tests/learning.rs`) |
| Production rule (goal item P2) | same test; `learning_replaces_only_the_model_step` (`src/broker/bouncer.rs`) |
| Rule flag (command analysis) | same two tests |
| Missing user request | same two tests |
| Missing declaration | same two tests |
| A grant in "ask" mode | `decision_log_and_export_have_no_secret_values` (no offer, the owner decides) |

## 4. Threshold calibration (goal item B5)

Code: `src/broker/calibration.rs`.

Only the `task_match` level changes. The range is 0.5 to 0.8. The default is 0.8. The production rule, the rule flags, the vetoes (`destroy`, `rule_break`), the read-only check for a sensitive declaration, and the hard rules are never calibrated (`calibration_changes_only_the_task_match_level`).

Proposal:

1. Apassy takes the decisions that reached the bouncer, oldest first. It splits them by time: the older 70% (fit part) and the newer 30% (held-out part).
2. The fit part needs 30 or more owner decisions at the model step: model facts, no rule flag, no production item, a user request, and declarations.
3. Apassy replays the fit part with the real policy (`decide_learned`) at levels from the current level down to 0.5, in steps of 0.05. It stops at the first level that allows an owner denial, also at 0.05 under that level. It proposes the lowest level before that stop that lets more owner approvals run.
4. The held-out part gives the ask rate now and with the proposal, and the misses: owner denials that the proposal allows.
5. The gate: a replay on all past decisions. The proposal is valid only if it allows no request that the owner denied.

Apply: the owner clicks "Apply" in the Learning view. This is a rule change, so it needs the owner check (`OwnerAction::ChangeCalibration`). `calibration::apply` computes the proposal and the gate again at this time, so a denial after the proposal counts. A lower level must be at or above a valid proposal. "Back to the default (75%)" removes the calibration. It needs no check. The vault keeps the last 100 changes with their replay numbers.

Test: `calibration_proposal_passes_the_replay_gate_and_the_owner_applies_it` (`tests/learning.rs`). The owner approves 45 general requests at `task_match` 0.7 and denies 5 at 0.3. The proposal is 0.7, the held-out misses are 0, and the held-out ask rate falls. Before the owner applies it, the broker asks for a request at 0.7. After, the model allows it. A production item still waits. A new owner denial at 0.72 makes the same level invalid, and `apply` refuses it.

## 5. Visibility (goal item B10)

The Learning view in the app (`src/desktop/learning_ui.rs`) shows:

- The ask rate per UTC day for 14 days: requests that reached the bouncer, asked, allowed by the model, allowed by a pattern. Rule denials do not count.
- The automatic decisions (model or pattern), newest first. "Inspect" shows each stored field of one decision.
- The remembered patterns: pattern, agent, project, items, state (learning with its approvals, active, blocked, or expired), and runs. "Remove" removes one.
- The calibration: the active level, "Compute a proposal", the replay numbers, "Apply", and "Back to the default (75%)".
- The candidate model card (goal items B9 and B10). [The fine-tune](fine-tune.md), sections 6 to 10, describes the pipeline.
  - Without a candidate: "No candidate model."
  - With a candidate in shadow mode: its version, the shadow decisions (owner decisions that the candidate also answered), the agreement with the owner, the owner denials that the candidate would allow, the requests in shadow mode, the requests without a candidate answer, the requests with the same outcome as the active model, and the command that starts the candidate server.
  - "Promote" is on only when the shadow gate passes: 100 or more shadow decisions, 95% or more agreement, and no owner denial that the candidate would allow (`CandidateAgreement::can_promote`, ADR 0010). Otherwise the card names each threshold that fails. "Promote" needs the owner check (`OwnerAction::PromoteModel`).
  - The training gate: the owner decisions of 300, the owner denials of 30, and the power source. "Train a candidate" is on only when the gate is open. During a training, the card shows the elapsed time against the limit of 60 minutes, and "Stop training".
  - The active model: the default model (`APASSY_BOUNCER_URL`), or the promoted version with its address and time. After a promotion, "Roll back to ..." returns to the model before it. The rollback needs the owner check (`OwnerAction::RollbackModel`).

Measured on this Mac with a candidate from 300 synthetic owner decisions: 46 of 48 owner decisions in shadow mode agree (95.8%) on `independent.tsv` with grants in "ask" mode, and 0 owner denials would be allowed. The run has fewer than 100 shadow decisions, so the candidate cannot be promoted. See [the fine-tune](fine-tune.md), section 11.2.

The data shape is `vault::CandidateAgreement`: model version, start time, shadow decisions, agreements, and owner denials that the candidate would allow. `Vault::shadow_summary` computes it from the shadow rows of schema 9. An agreement is a candidate "run" of an owner approval, or a candidate "ask" of an owner denial. A candidate "ask" of an owner approval is a disagreement. A candidate "run" of an owner denial is a disagreement and an allowed denial.

Tests: `learning_view_shows_the_ask_rate_decisions_patterns_and_candidate_slot`, `candidate_card_says_no_candidate_until_shadow_mode`, `training_card_shows_the_gate_and_the_active_model`, and `promotion_and_rollback_in_the_view_need_the_owner_check` (`src/desktop/learning_ui.rs`), `candidate_promotion_needs_100_decisions_95_percent_and_no_allowed_denial` (`src/vault/learning.rs`), `shadow_summary_counts_agreement_with_the_owner` (`src/vault/candidate.rs`). The view has no GUI check on a real screen.

## 6. Export for fine-tuning

`Vault::export_decisions_jsonl` returns all decisions as JSON Lines, oldest first. The app has no export button. The output has real commands and user requests, so keep it on this computer and delete it after training.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `apassy-decision-v1` |
| `time` | string | UTC time, `YYYY-MM-DDTHH:MM:SSZ` |
| `at` | integer | Unix time |
| `agent` | string | Agent name |
| `user_request` | string | The user request, from the host hook when there is one |
| `user_request_source` | string | `host`, `agent`, or `none` |
| `command` | array of string | The argument list, secret values masked |
| `cwd_rel` | string | Working directory relative to the project |
| `purpose` | string | The purpose that the agent stated |
| `instruction` | string | The owner instructions of the grants |
| `env_names` | array of string | Environment variable names, never values |
| `declaration` | array | One object per item (`project`, `environment`, `risk`, `scope`, `reversibility`), or `null` |
| `rule_flags` | array of string | Flags of the command analysis |
| `model_facts` | object | Model answers by name, each a probability. Empty when the model did not answer |
| `decision` | string | `allow` or `deny` |
| `decided_by` | string | `rule`, `model`, `pattern`, `owner`, or `no_answer` |
| `remembered` | boolean | The owner used "Approve and remember" |

The owner labels are the lines with `decided_by` = `owner`. [The fine-tune study](fine-tune.md), section 5, names some fields differently: `relative_dir` is `cwd_rel`, `owner_decision` is `decision` of an owner line, and `source` is `remembered`.

The local fine-tune (goal item B9) reads this export. `broker::finetune::examples_from_export` turns it into training examples. The label mapping is in [the fine-tune](fine-tune.md), section 6.2.

Example (synthetic):

```
{"schema":"apassy-decision-v1","time":"2026-09-26T10:00:00Z","at":1790416800,"agent":"Claude Code","user_request":"Print the weekly report.","user_request_source":"agent","command":["sh","-c","./report.sh --limit 1"],"cwd_rel":".","purpose":"Print the report.","instruction":"","env_names":["DEMO_KEY"],"declaration":[{"project":"demo","environment":"staging","risk":"medium","scope":"read-write","reversibility":"reversible"}],"rule_flags":[],"model_facts":{"task_match":0.95,"writes":0.02},"decision":"allow","decided_by":"model","remembered":false}
```

## 7. Replay measurement (goal item B3)

Code: `src/broker/replay.rs`, `tests/learning_replay.rs`.

The replay sends a chronological request sequence through the real decision code with learning: the command analysis, the pattern lookup, `decide_learned`, the decision log, and the pattern update. These are the functions of the broker. There are no hard rule checks and no processes. The simulated owner uses "Approve and remember" when the card offers it, and "Approve once" when it does not. The report gives the ask rate per window and checks two things:

- A request that the owner denied never runs without the owner later in the sequence.
- After the sequence, the final state (patterns and calibration) still asks for each denied request.

The frozen held-out set in `tests/evals/` is not used.

### Labeled sets as the simulated owner

Data: `tests/fixtures/bouncer/cases.tsv` and `independent.tsv` (270 cases). `ok` is an approval. `risk` is a denial. The sequence has 3,000 requests. A case of rank `r` has the weight `1 / (r + 1)`, because real agent traffic repeats (ADR 0009: 31 templates cover 50% of the real commands). Requests are 1 to 30 minutes apart, about 32 days. Staging declaration. The purpose plays the user request, as in `tests/bouncer_eval.rs`.

`cargo test --locked --features vault --test learning_replay -- --nocapture`

Without a model, the model step always asks. So only patterns lower the ask rate:

| Run | Asked | Rule flags | Pattern allowed | Owner denials | Denied, then allowed |
| --- | --- | --- | --- | --- | --- |
| No learning | 3000 (100%) | 1342 | 0 | 1355 | 0 |
| Learning | 1777 (59.2%) | 1342 | 1223 | 1355 | 0 |

Ask rate per window of 300 requests, with learning: 70%, 68%, 62%, 59%, 56%, 64%, 54%, 54%, 53%, 52%. The rule flags (45% of this sequence) always ask, so the ask rate cannot fall under that share. Patterns allowed 1223 of the 1658 requests without a flag (74%). At the end: 91 active, 28 learning, and 119 blocked patterns. Final state: 0 denied requests allowed. No request with the `risk` label ran without the owner.

With the local Laya model (zero-shot `convaiinnovations/laya`, `laya-serve` 0.3.20 on a loopback address):

`APASSY_EVAL_MODEL=http://127.0.0.1:8770 cargo test --locked --release --features vault --test learning_replay fixture_replay_with_model -- --ignored --nocapture`

| Run | Asked | Rule flags | Model allowed | Pattern allowed | Denied, then allowed |
| --- | --- | --- | --- | --- | --- |
| No learning | 1342 (44.7%) | 1342 | 1658 | 0 | 0 |
| Learning | 1342 (44.7%) | 1342 | 1658 | 0 | 0 |

The model allows each request without a rule flag. So the owner sees only flagged requests, and patterns have nothing to learn. The denials block 118 patterns. Final state: 0 denied requests allowed. 13 requests with the `risk` label ran without the owner. They are one case 13 times: `node scripts/grant-admin.js` with a false purpose. The rules do not flag it, and the model allows it. [The bouncer](bouncer.md), section 4, reports the same miss. Learning does not cause it and cannot fix it. The calibration has no owner decision at the model step, so it proposes no change.

`a_denial_blocks_a_pattern_and_later_approvals_cannot_open_it` shows three cases:

- 2 approvals, 1 denial, then more approvals: the pattern never runs alone, and the denied request still asks.
- 3 approvals first: the pattern is active. A new variant with the `risk` label runs without the owner. The owner did not see it, so this is a miss, not a denied request that became an allowance. This is the limit of patterns.
- After 30 idle days, the pattern expired. The next request asks.

### Real agent commands

The owner permitted a local run on the real odealo commands. Source: the Codex session history (`~/.codex/sessions`), odealo directories only. `tools/learning/extract_codex.py OUT.json` writes the commands, the working directory, and the last user request, in time order. The file stays outside the repository. The script and the test print counts only.

- 483 session files, 19,275 runs, 18,015 unique commands, 14,417 with a user request, from 2026-09-05 to 2026-09-23.
- The labels are not known. The simulated owner denies a request with a rule flag and approves the others. So this run measures the ask rate, not the safety. The safety check is the labeled sets above and the tests in section 3.

`APASSY_REAL_CTX=OUT.json cargo test --locked --release --features vault --test learning_replay real_commands_replay -- --ignored --nocapture`

Without a model, with the rule packs of `goal-v1` at commit 17b1095:

| Run | Asked | Rule flags | Pattern allowed | Denied, then allowed |
| --- | --- | --- | --- | --- |
| No learning | 19,275 (100%) | 2,531 | 0 | 0 |
| Learning | 17,864 (92.7%) | 2,531 | 1,411 | 0 |

Ask rate per window of 2,000 requests, with learning: 89%, 90%, 96%, 94%, 97%, 96%, 97%, 85%, 87%, 98%. At the end: 191 active, 809 learning, and 2,205 blocked patterns. With the earlier rule packs (742 rule flags), the same run gave 92.2% asks and 1,505 pattern allowances.

Patterns alone remove few asks on real commands. The commands vary much: 18,015 of 19,275 are unique. 5,529 have a here-document, 628 have a command substitution, and 5,159 start with an interpreter (`python3`, `node`). The narrow rules keep these literal on purpose. The model step and the calibration must give the larger part of the reduction.

With the local Laya model, on the first 3,000 commands of up to 300 characters, in time order (2026-09-05 to 2026-09-11). This run and the model run on the labeled sets used the rule packs before commit 17b1095. A long script gives a long model state, and the model then takes seconds for each request. So this run skips commands over 300 characters. Model answers took about 1 second each. The run took 24 minutes.

`APASSY_EVAL_MODEL=http://127.0.0.1:8770 APASSY_REAL_CTX=OUT.json APASSY_REPLAY_LIMIT=3000 APASSY_REPLAY_MAX_CHARS=300 APASSY_REPLAY_WINDOW=300 cargo test --locked --release --features vault --test learning_replay real_commands_replay -- --ignored --nocapture`

| Run | Asked | Rule flags | Model allowed | Pattern allowed | Denied, then allowed |
| --- | --- | --- | --- | --- | --- |
| No learning | 1,886 (62.9%) | 118 | 1,114 | 0 | 0 |
| Learning | 1,708 (56.9%) | 118 | 1,047 | 245 | 0 |

Ask rate per window of 300 requests:

| Window | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| No learning | 89% | 98% | 90% | 87% | 89% | 54% | 31% | 41% | 28% | 21% |
| Learning | 89% | 98% | 78% | 65% | 76% | 46% | 30% | 41% | 27% | 20% |
| Requests with no user request | 262 | 293 | 202 | 166 | 204 | 84 | 60 | 62 | 45 | 0 |

A request with no user request always waits for the owner (step 4), also with an active pattern. The extractor finds no user message for many early sessions. So the first windows ask often, with and without learning. At the end: 16 active, 239 learning, and 94 blocked patterns. Final state: 0 denied requests allowed.

Calibration on the decision log of this run (goal item B5):

| Value | Result |
| --- | --- |
| Owner decisions at the model step, older 70% | 161 |
| Proposal | `task_match` 0.80 to 0.50, valid |
| Held-out part (newer 30%), ask rate | 29.1% now, 23.2% with the proposal |
| Held-out misses (owner denials that the proposal allows) | 0 |
| Gate: replay on all 3,000 decisions, denials allowed | 0 |

Limit of this number: the simulated owner denies only requests with a rule flag, and a rule flag always asks. So no owner denial is at the model step, and the gate cannot fail here. The gate does fail when the owner denies at the model step: see `calibration_proposal_passes_the_replay_gate_and_the_owner_applies_it` in section 4. With the real owner, the proposal can be higher.

An earlier version of the generalizer kept every multi-line script and every script with a backslash literal, and refused new patterns when the list was full. With the earlier rule packs, it gave 94.7% asks on the same data. The current version gives 92.2% with those packs.

## 8. Wait records (goal item N3)

Code: `src/vault/waiting.rs`, `src/broker/run.rs`, `src/desktop/owner_store.rs` (`lock_ending_runs`).

- The broker stores a wait record (table `waiting_run`) before a run waits for the owner, and removes it when the wait ends. The record has the agent, the item, the operation label, and the purpose. It has no secret value.
- A lock or a quit of the app turns every record into one activity entry (`ENDED_BY_LOCK`, `ENDED_BY_QUIT`).
- A crash or `kill -9` leaves the record. The next unlock turns it into an activity entry that starts with "Ended by restart". The inbox shows it as "Approval ended without a run".
- A broker thread that still waits holds a ticket in this process. The unlock skips a record with a ticket, and the thread writes its own entry. So a run gets one entry, also after a fast lock and unlock.

Tests: `a_run_that_waits_during_a_crash_is_in_the_inbox_after_a_restart` and `a_quit_records_a_waiting_run_once` (`tests/waiting_restart.rs`), `an_unlock_ends_only_records_without_a_ticket` (`src/vault/waiting.rs`), and `approval_before_lock_is_not_valid_after_unlock` (`tests/agent_run.rs`). The crash test drops the vault and the broker state with no lock, no quit, and no final entry. This leaves the vault file as `kill -9` does.

## 9. Checks

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS |
| `cargo test --locked --features desktop,vault` | PASS |

## 10. Limits

- The pattern generalizer reads text. It does not resolve symbolic links. A link inside the project to a file outside matches `<file>`.
- A pattern does not pin the content of a script file. A matching command runs the file as it is now.
- An active pattern allows a new variant that the owner did not see (section 7).
- The calibration needs 30 owner decisions with model answers at the model step. Without a model, there are none.
- The replay on real commands has no owner labels. Its safety numbers come from the labeled sets, which the same author wrote together with the rules (see [the bouncer](bouncer.md), section 4).
