# Fine-tune study and local fine-tune of the bouncer model (goal B8/B9)

Date: 2026-09-26. Decisions: [ADR 0009](../adr/0009-general-by-default-and-learning.md), [ADR 0010](../adr/0010-closing-open-decisions.md).

Sections 1 to 5 are the study. They answer three questions for the goal:

1. Does the `laya` package support a fine-tune?
2. How long and how much memory does a local fine-tune need on the owner's Mac?
3. What does a shipped general base model (B8) need, and what is the on-disk
   format of an owner decision that the learning worker exports (B9)?

Sections 6 to 13 describe the local fine-tune of goal item B9: the pipeline, the
training gate, shadow mode, promotion and rollback, and the measurements.

All measurements are synthetic. No owner data and no real secret is used.

## 1. Does laya support a fine-tune?

`laya[serve]==0.3.20` is an inference package. It has no training entry point,
no optimizer, no loss, and no `train` command. `laya-serve` and `laya.Agent`
only answer questions with `@torch.no_grad()`.

The package does expose the parts a fine-tune needs:

- `laya.common.DecisionModel` — the model. It is a bidirectional encoder
  (ModernBERT-large, about 395M parameters) plus small decision heads
  (`head`, `type_emb`, `scorer`, `act_head`, about 26M parameters). Its
  `forward` returns per-option `logits` and an action head output.
- `Agent._encode_state` and `laya.common.collate_items` — the exact tokenizer
  pipeline. `collate_items` already accepts a `target` per item, one entry per
  option. For a `noul` question the two options are false and true.
- `laya.common.proper_reward` — a strictly proper scoring reward, the training
  objective the checkpoint was built with. `td_lambda_targets` is there too, for
  multi-turn credit assignment.

So there is no packaged trainer, but the building blocks are public. A minimal
supervised fine-tune of the `noul` questions is possible by reconstructing the
loss on the two markers. The script `tools/finetune/finetune.py` does this. It
loads the checkpoint, encodes `{state, question, answer}` examples with the
agent's own pipeline, runs cross-entropy on the two `noul` markers, and steps
AdamW. By default it trains the decision heads only and freezes the encoder.

## 2. Local fine-tune measurements

Machine: Apple M4, 16 GB unified memory, macOS 27.0, on AC power. MPS backend.
`torch==2.14.0`, `transformers==5.17.0`. Data: 310 synthetic
`{state, question, answer}` examples for the `writes`, `destroy`, `leak`, and
`task_match` questions, generated inside the script from a command pool that does
not overlap the held-out set (`tests/evals/heldout-v1.jsonl`). The script asserts
the disjointness.

Run:

```
cd "$HOME/Library/Application Support/Apassy/laya"
TMPDIR=/tmp ./.venv/bin/python <repo>/tools/finetune/finetune.py            # heads only
TMPDIR=/tmp ./.venv/bin/python <repo>/tools/finetune/finetune.py --full     # encoder too
```

| Variant | Trainable params | Fine-tune time | Peak driver memory | Checkpoint | Inference p50 |
| --- | --- | --- | --- | --- | --- |
| heads only (default) | 26.5M | 29.6 s (310 ex, 3 epochs, batch 16) | 3.67 GB | 106 MB | 129 ms |
| full encoder | 421.3M | 116.7 s for 3 steps (batch 8), about 39 s/step | 9.73 GB | 1685 MB | 110 ms |

The loss dropped from about 0.84 to 0.23 over three epochs in the heads-only run,
so the heads do learn the labels.

The full-encoder variant is heavy on this Mac. One optimizer step (batch 8) takes
about 39 s, so one epoch over 310 examples (about 39 steps) takes about 25
minutes, and three epochs take more than an hour. Its peak memory of 9.7 GB on a
16 GB machine leaves little headroom, and its checkpoint is 1.7 GB.

## 3. Recommendation on the one-hour budget (ADR 0010)

ADR 0010 sets a local fine-tune budget of one hour on AC power. The measurements
say:

- **Heads-only fine-tune fits the budget with a very large margin.** Even at 300
  to 1000 owner decisions and ten epochs, it stays under a few minutes and under
  4 GB. Its checkpoint is 106 MB, small enough to keep on disk beside the vault.
  This is the realistic local option for B9 (the local fine-tune and shadow gate).
- **Full-encoder fine-tune does not fit the budget on this Mac.** Three epochs
  exceed one hour, and the memory and checkpoint size are large. It is not the
  right local path.
- If a future step wants to adapt the encoder as well, a parameter-efficient
  method (LoRA or adapters on the encoder attention layers) is the path to test
  next. It would train far fewer parameters than the full encoder and should stay
  inside the budget. This study did not measure it, because `laya` ships no
  adapter hooks; it would need `peft` or a manual adapter, which is new work.

Recommendation: for B9, fine-tune the decision heads only, on MPS, on AC power.
The one-hour budget is realistic for that path and is not realistic for a full
fine-tune on this hardware. Keep at most one checkpoint on disk; the script saves
one, measures it, and deletes it.

Disk note: only about 13 GB was free during this study. The model weights (about
1.7 GB) are already in the Hugging Face cache from `laya-serve`. A heads-only
checkpoint adds 106 MB. A full checkpoint adds 1.7 GB, which is another reason to
prefer heads-only locally.

## 4. What a shipped general base model needs (B8)

B8 ships a general base model, fine-tuned off the owner's machine on commands
from many stacks, with no owner data. From this study and ADR 0009:

- **Training signal.** The same `{state, question, answer}` shape as here, for the
  `task_match`, `writes`, `remote`, `leak`, and `destroy` questions, plus
  `rule_break` when a rule is present. The `destroy` and `leak` questions are the
  ones the current zero-shot model is weak on (the held-out baseline shows means
  that do not separate normal work from violations), so they need the most
  labeled coverage.
- **Sources.** Shell commands from many stacks and tools, labeled by their known
  effect: package managers, migration tools, cloud CLIs, container tools, and VCS.
  The held-out set and `tests/fixtures/bouncer/*.tsv` show the register. A base
  model needs breadth well beyond one owner's stack.
- **Size.** The held-out baseline shows the heads can be moved with a few hundred
  examples per question. A shipped base model should use on the order of tens of
  thousands of commands across stacks, with a class balance that over-samples the
  rare risky classes, and a held-out split from stacks not in training (as B2
  does here).
- **Licenses.** Every command corpus and every label source must have a license
  that permits redistribution inside a shipped app. Public command datasets,
  synthetic generation, and the project's own synthetic fixtures are safe. Real
  agent transcripts (for example the odealo Codex history) are owner data and must
  not enter a shipped base model.
- **Compute.** The full-encoder training for a base model belongs on a GPU off the
  owner's Mac, given the per-step cost measured here. Only the small heads-only
  adaptation belongs on the owner's machine (B9).

## 5. On-disk format for an owner decision (B9 export)

The implemented export is `Vault::export_decisions_jsonl`. Its fields are in
[learning](learning.md), section 6. It uses `cwd_rel` for `relative_dir`,
`decision` with `decided_by` for `owner_decision`, and `remembered` for `source`.
It has one declaration per item, in an array. The table below is the plan of this
study.

The learning worker exports one record per owner decision. Each record is one
line of JSON. The records stay in the encrypted vault and never leave the
computer (ADR 0009). A record has no secret value.

Fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Format version, for example `apassy-decision-v1`. |
| `at` | integer | Unix time of the owner decision. |
| `agent` | string | The agent name. |
| `user_request` | string | The user's own words (from the host hook when available, else the agent claim). |
| `command` | array of string | The command argv, with no secret value. |
| `relative_dir` | string | Working directory relative to the project root. |
| `env_names` | array of string | Bound secret variable names, not their values. |
| `declaration` | object | `project`, `environment`, `risk`, `scope`, `reversibility`. |
| `instruction` | string | The owner rule text, or empty. |
| `rule_flags` | array of string | Flags from the command analysis (for example `secret_output`, `data_loss`, `production`). |
| `model_facts` | object | The model `noul` answers by name (for example `task_match`, `writes`, `destroy`, `leak`, `rule_break`), each a probability. |
| `owner_decision` | string | `allow` or `deny`. |
| `source` | string | `approval_card` or `approve_and_remember`. |

Example line (synthetic):

```
{"schema":"apassy-decision-v1","at":1790000000,"agent":"Claude Code",
 "user_request":"apply the staging migration","command":["alembic","upgrade","head"],
 "relative_dir":".","env_names":["DATABASE_URL"],
 "declaration":{"project":"acme-app","environment":"staging","risk":"medium",
 "scope":"read-write","reversibility":"reversible"},"instruction":"",
 "rule_flags":[],"model_facts":{"task_match":0.91,"writes":0.72,"remote":0.4,
 "leak":0.05,"destroy":0.08},"owner_decision":"allow","source":"approval_card"}
```

To build a training example from a record: the `state` is the same string the
bouncer sends (user request, command, purpose, and rule). Each question in
`model_facts` becomes one `{state, question, answer}` example, where the answer
is the owner-consistent label. A denial has more weight than an approval
(ADR 0009): the export can repeat denied records or weight them in the loss. The
fine-tune must never turn a denied request into an automatic allowance; the
shadow gate in ADR 0010 (100 shadow decisions, 95% agreement, no allowance of a
denied request, manual promotion) is the check before any new version acts.

## 6. Local fine-tune pipeline (goal B9)

Code: `src/broker/finetune.rs` (gate, examples, trainer supervisor),
`tools/finetune/local_train.py` (trainer), `tools/basemodel/train.py` (heads only),
`src/desktop/learning_ui.rs` (Learning tab).

### 6.1 Steps

1. The owner clicks "Train a candidate" in the Learning tab. Nothing else starts a
   training. There is no timer and no background trigger.
2. `finetune::train` checks the training gate (section 7). A closed gate stops here.
   The trainer does not start.
3. The broker exports the decision log (`Vault::export_decisions_jsonl`, format
   `apassy-decision-v1`) and converts it to training examples
   (`finetune::examples_from_export`, section 6.2). The state of each example is the
   state that the broker sends to the model (`bouncer::state_text`). The question
   texts come from `bouncer::questions()`.
4. The broker writes `train.jsonl`, `val.jsonl`, and `stats.json` to a new candidate
   folder with mode `0700` (files `0600`) under `$APASSY_LAYA_DIR/models/candidates/`.
5. The broker starts the trainer in its own process group:
   `$APASSY_LAYA_DIR/.venv/bin/python $APASSY_TOOLS_DIR/finetune/local_train.py
   --data <dir> --out <dir> --name apassy-local-v1 --deadline 3600
   [--init <base checkpoint>]`. `APASSY_TOOLS_DIR` is the `tools` folder of the
   repository (default `$APASSY_LAYA_DIR/tools`).
6. `local_train.py` checks the counts again and checks that `--init` has the SHA-256 of
   `tools/basemodel/manifest.json`. Then it runs `train.py` in the same process: heads
   only, 4 epochs, batch 32, learning rate 1e-4, warmup 20. It starts from the heads of
   the shipped base checkpoint `apassy-base-v1` when that file is present. It writes
   `candidate.safetensors`, `manifest.json` (with the base and serve parts of the base
   manifest, so `serve.py` accepts it), and `result.json`.
7. The broker deletes the example files and checks `result.json`: the version is
   `apassy-local-v1+<first 8 hex of the SHA-256>`, and the checkpoint is a file in the
   candidate folder. Then it registers the candidate in shadow mode (section 8). A
   failed, stopped, or timed-out training deletes the whole candidate folder.

The base checkpoint is the first file of: `APASSY_BASE_MODEL`,
`$APASSY_LAYA_DIR/models/apassy-base-v1.safetensors`,
`/Applications/Apassy.app/Contents/Resources/models/apassy-base-v1.safetensors` (the
order of `tools/basemodel/start.sh`). Each training starts from the base heads, not
from an earlier candidate.

### 6.2 Label mapping

Only owner decisions are labels. The model, pattern, rule, and "no answer" lines of
the export give no label.

| Export line | Example |
| --- | --- |
| `decided_by` = `owner`, `decision` = `allow` | `task_match` = yes for this request and command |
| `decided_by` = `owner`, `decision` = `deny`, no rule flag | `task_match` = no |
| `decided_by` = `owner`, `decision` = `deny`, with a rule flag | no `task_match` label, because the flag explains the denial. With the flag `data_loss`: `destroy` = yes |
| Approval and denial of the same state | the denial wins. The approval gives no example |
| An owner decision without a user request | no example |
| Each state of an owner decision | teacher examples for each question without an owner label: `task_match` (after a flagged denial), `writes`, `remote`, `destroy`, and `rule_break` (with an owner rule) |

- A teacher example has the answer of the starting heads as its target. `train.py`
  computes it before the first step (`teacher_targets`). So the fine-tune does not
  move the answers that the owner did not label ("learning without forgetting").
  `leak` has no example: the server gives the stock answer for `leak`
  (`serve.zero_shot_questions`).
- At most 3 identical examples.
- A denial has more weight (ADR 0009). Each denial example counts
  `round(task_match approvals / task_match denials)` times, from 2 to 10.
- A hash (FNV-1a) of the command puts 20% of the commands in the validation part. A
  command is in one part only.
- The loss is the cross-entropy with the target distribution `(1 - answer, answer)`.
  For the answers 0 and 1, it is the loss of the base training (goal B8).

Tests: `export_lines_map_to_owner_labels`, `many_approvals_give_a_heavier_denial`, and
`a_bad_export_gives_no_examples` (`src/broker/finetune.rs`).

## 7. Training gate

`finetune::train` enforces the gate in code. The Learning tab shows the gate and turns
"Train a candidate" on only when it is open.

| Condition (ADR 0010) | Code | Test |
| --- | --- | --- |
| 300 or more owner decisions (`decided_by` = `owner`) | `finetune::gate`, `MIN_OWNER_DECISIONS` | `the_gate_opens_at_exactly_300_decisions_and_30_denials_on_ac_power` (`tests/local_finetune.rs`): open at 300/30, closed at 299/30 |
| 30 or more of them are owner denials | `MIN_OWNER_DENIALS` | same test: closed at 300/29 |
| AC power at the start | `finetune::power_now` runs `/usr/bin/pmset -g batt` (an absolute path, so `PATH` cannot change it) and reads `Now drawing from 'AC Power'`. `'Battery Power'`, another source, or a failure keeps the gate closed | same test: closed on battery and with an unknown source; `pmset_output_names_the_power_source` |
| AC power during the training | the broker reads the power source every 30 s and stops the trainer on another source | `leaving_ac_power_stops_the_training` |
| One hour at most | `TIME_LIMIT` = 3600 s. At the limit, the broker sends `SIGKILL` to the process group of the trainer (`/bin/kill -KILL -- -<pgid>`). `local_train.py` also sets `alarm(3600)` | `the_time_limit_stops_the_training`: a trainer that sleeps stops at a limit of 1 s. Its process is gone, and no candidate and no folder stay |
| The owner starts and can stop it | only the Learning tab calls `finetune::train`. "Stop training" and a quit of the app stop the process group | `the_owner_can_stop_the_training`, `a_bad_or_failed_trainer_makes_no_candidate` |

A closed gate never starts the trainer: the test trainer writes a marker file, and the
marker is absent for each closed case. Model, rule, and "no answer" entries in the log
do not count.

## 8. Shadow mode

Code: `src/broker/shadow.rs`, `src/broker/run.rs`.

- The candidate server runs on its own loopback port. The default is
  `http://127.0.0.1:8775` (`APASSY_CANDIDATE_URL`). The owner starts it with
  `APASSY_BASE_MODEL=<candidate folder>/candidate.safetensors LAYA_PORT=8775
  tools/basemodel/start.sh`. `serve.py` reads `manifest.json` next to the checkpoint,
  checks the SHA-256 of the checkpoint and of the base weights, and answers with the
  version `apassy-local-v1+<hash8>`. The Learning tab shows this command.
- For each request that reaches the model step (no hard owner rule, no rule flag, a
  user request, declarations, and no active remembered pattern), the broker starts the
  candidate call on its own thread before it asks the active model. The broker decides
  with the active model only. It does not wait for the candidate.
- The candidate outcome is the decision of the same policy (`decide_learned`) with the
  candidate answers, at the active `task_match` level, without a pattern: "run" or
  "ask". The candidate client accepts only answers with the registered version.
  Another version or no answer is "no answer".
- After the decision (a run without the owner) or the owner answer, the thread stores
  one row: the candidate outcome, the real outcome (run or ask), and the owner decision
  (allow, deny, or none). A row has the candidate answers as probabilities. It has no
  command, no user request, and no secret value. A lock or an unlock in between drops
  the row.
- A new training replaces the candidate in shadow mode.

Agreement (goal item B10): only rows with an owner decision and a candidate answer
count. See [learning](learning.md), section 5.

| What must hold | Test |
| --- | --- |
| A candidate that answers the opposite of the active model changes no decision | `shadow_answers_never_change_a_decision` (`tests/shadow_mode.rs`): the same four decisions with and without the candidate, 3 candidate calls (the request with a rule flag skips it), and the rows give 2 owner decisions, 1 agreement, and 1 allowed denial |
| A candidate that is down, answers with another version, or is slow changes nothing | `a_candidate_that_is_down_slow_or_another_version_changes_nothing`: the same decisions, "no answer" rows, and a run that ends before a held candidate answer |
| The candidate decides with the broker policy | `candidate_answer_uses_the_broker_policy` (`src/broker/shadow.rs`) |

## 9. Schema 9

One transaction migrates a vault from schema 8 to 9 (`src/vault/candidate.rs`):

| Table | Content |
| --- | --- |
| `model_candidate` | version, loopback address, checkpoint path and SHA-256, creation time, state (`shadow`, `promoted`, `replaced`, `rolled_back`), end time, and the training report (numbers only). The newest 50 candidates stay |
| `shadow_decision` | candidate, time, real outcome, candidate outcome, owner decision, and candidate answers. The newest 20,000 rows stay |
| `model_activation` | each promotion and rollback: version and address, candidate, the version and address before, and shadow numbers. The newest row names the active model. No row, or an empty address, is the default bouncer. The newest 100 rows stay |

Tests: `unlock_migrates_each_earlier_schema_version_to_the_current_one` (versions 1 to 8,
with version 8 data) and `a_failed_migration_from_version_8_keeps_the_old_version_and_data`
(`tests/vault_migration.rs`).

## 10. Promotion and rollback

- "Promote" in the Learning tab is on only when the shadow gate passes. The owner check
  is `OwnerAction::PromoteModel { candidate_id, version }`: Touch ID or the passphrase
  now, for this candidate and this version, in this vault session.
- `shadow::promote` checks the proof and checks that the candidate is in shadow mode.
  While it holds the vault, it runs the shadow gate again with the rows of now. The
  vault function checks the gate a second time. Then one transaction stores the
  activation, marks the candidate `promoted`, and writes an activity entry ("promote
  model", with the version before and the shadow numbers).
- The broker reads the active model from the vault for each request. A promoted model
  is pinned to its version (`BouncerClient::expect_model`). An answer from another
  version is "unavailable", so the owner decides. A model update at the same address
  cannot change the policy silently (`docs/concept.md`).
- The model before the promotion stays available. "Roll back to ..." needs the owner
  check `OwnerAction::RollbackModel { activation_id }`. Only the newest promotion can be
  rolled back. One transaction stores the rollback, marks the candidate `rolled_back`,
  and writes an activity entry ("roll back model").

| What must hold | Test |
| --- | --- |
| Refused at 99 decisions, at 94% agreement, and with 1 allowed denial. The default model stays active | `promotion_is_refused_below_each_threshold_and_without_the_owner_check` (`tests/shadow_mode.rs`) |
| Refused without the owner check: a wrong passphrase gives no proof. A proof for another action, another candidate, another version, or a rollback is refused | same test |
| Promoted at exactly 100 decisions, 95 agreed, and 0 allowed denials. The activity log has the entry. The next run uses the candidate, and its note names the candidate version | same test |
| A promoted model is pinned to its version | `a_promoted_model_is_pinned_to_its_version`, `a_pinned_client_accepts_only_its_model_version` (`src/broker/bouncer.rs`) |
| A rollback needs the owner check, returns to the default model, writes the activity entry, and works once | `rollback_returns_to_the_previous_model_and_needs_the_owner_check` |
| In the Learning tab, a wrong passphrase promotes and rolls back nothing | `promotion_and_rollback_in_the_view_need_the_owner_check` (`src/desktop/learning_ui.rs`) |
| Each threshold of ADR 0010 has a refusal text | `promotion_refusal_names_each_failed_threshold` (`src/broker/shadow.rs`) |

## 11. Measurements on this Mac (2026-09-26)

Machine: Apple M4, 16 GB, macOS 27.0, on AC power at the start and at the end.
`torch==2.14.0`, `transformers==5.17.0`, `laya==0.3.20` in the Laya environment. The
model servers of another worker (ports 8772 and 8773) were stopped before the
training. No other model server ran during the training.

### 11.1 Training

Synthetic decision log: 300 owner decisions from the labeled cases of
`tests/fixtures/bouncer/cases.tsv` (174 cases, each once, then repeats in a fixed
order). `ok` is an approval and `risk` is a denial, as in [learning](learning.md)
section 7. Each request waited for the owner (a grant in "ask" mode), so each request
is an owner decision. `tests/evals/*` and `independent.tsv` were not used.

```
APASSY_TOOLS_DIR=<repo>/tools APASSY_FINETUNE_MODELS=/tmp/apassy-b9/models \
cargo test --locked --release --features vault --test local_finetune \
local_training_on_a_synthetic_log -- --ignored --nocapture
```

The test runs the real `finetune::train` (gate, examples, supervisor, registration)
with the trainer wrapped in `/usr/bin/time -l`.

| Value | Result |
| --- | --- |
| Owner decisions, approvals, denials | 300, 145, 155 |
| Denials with a rule flag | 153 |
| Examples: `task_match` yes, `task_match` no, `destroy` yes, teacher | 145, 2 (weight 10), 48 (weight 10), 583 |
| Train, validation examples | 919, 309 |
| Start checkpoint | `apassy-base-v1+83224960` (SHA-256 checked) |
| Candidate | `apassy-local-v1+c28c8cb7`, 104,996,060 bytes |
| Wall time of the trainer process | 75.6 s (2.1% of the limit of 3600 s) |
| Encoder cache, head training (4 epochs, best epoch 3) | 33.6 s, 35.1 s |
| Peak MPS driver memory | 3.52 GB |
| Maximum resident set size, peak memory footprint (`/usr/bin/time -l`) | 2.92 GB, 3.86 GB |

Validation (309 examples, 20% of the commands), start heads and candidate:

| Question | NLL before | NLL after | Accuracy before | Accuracy after | Mean p on "no" targets before, after |
| --- | --- | --- | --- | --- | --- |
| `task_match` (66) | 0.462 | 0.529 | 0.94 | 0.64 | 0.36, 0.53 |
| `writes` (37) | 0.287 | 0.303 | 1.00 | 0.95 | 0.13, 0.15 |
| `remote` (37) | 0.241 | 0.249 | 1.00 | 1.00 | 0.11, 0.08 |
| `destroy` (169) | 0.071 | 0.052 | 1.00 | 0.98 | 0.09, 0.12 |

The `task_match` validation rows mix owner labels and teacher rows. The target of a
teacher row is the answer of the start heads. The candidate moves `task_match` toward
"yes": the fixtures give 145
approvals and only 2 denials without a rule flag. An earlier run on the same log,
without the `task_match` teacher rows, took 63.1 s (2.92 GB resident, 3.45 GB MPS). Its
mean `task_match` on "no" targets went from 0.43 to 0.89. So the mapping now keeps the
start answer of `task_match` for each flagged denial. That earlier candidate was
deleted and has no shadow numbers.

### 11.2 Shadow session

The base model `apassy-base-v1+83224960` served as the active model on port 8774. The
candidate `apassy-local-v1+c28c8cb7` served on port 8775
(`APASSY_BASE_MODEL=<folder>/candidate.safetensors LAYA_PORT=8775
tools/basemodel/start.sh`). The requests went through the real broker. `PATH` had no
programs, so no command ran. The simulated owner approved `ok` and denied `risk`, with
the owner check.

```
APASSY_EVAL_MODEL=http://127.0.0.1:8774 APASSY_CANDIDATE_MODEL=http://127.0.0.1:8775 \
APASSY_CANDIDATE_DIR=<candidate folder> [APASSY_SHADOW_ASK=1] \
[APASSY_SHADOW_CASES=tests/fixtures/bouncer/cases.tsv] \
cargo test --locked --release --features vault --test shadow_mode \
shadow_session_on_synthetic_requests -- --ignored --nocapture
```

| Run | Requests | Time | At the model step | Owner decisions there | Candidate agreement | Owner denials that the candidate allows | Active model agreement, same decisions |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `independent.tsv`, grant "bouncer" | 96 | 22.6 s | 48 | 2 | 0 of 2 | 0 | 0 of 2 |
| `independent.tsv`, grant "ask" | 96 | 26.3 s | 48 | 48 | 46 of 48 (95.8%) | 0 | 46 of 48 (95.8%) |
| `cases.tsv` (training cases, in-sample), grant "ask" | 174 | 41.3 s | 85 | 85 | 80 of 85 (94.1%) | 0 | 75 of 85 (88.2%) |

- The candidate answered each request (0 "no answer").
- With the grant "bouncer", the base model ran 46 requests and asked for 2. The
  candidate gave the same outcome for all 48 requests at the model step. The owner
  approved both asked requests. The candidate would ask for both, so the agreement is
  0 of 2.
- In `independent.tsv`, a rule flag stops each of the 48 `risk` cases before the model
  step. So no owner denial reaches the model step, and this set does
  not test "no allowance of a denied request".
- No run reaches 100 shadow decisions. The candidate cannot be promoted with these
  numbers. On the training cases, the agreement rose from 88.2% (base) to 94.1%.

## 12. Limits

- The owner starts the candidate server, as the base server. Without it, each shadow
  row is "no answer" and does not count.
- Agreement counts only requests that the owner decided. A request that the active
  model ran without the owner has no owner label. The card shows "same outcome as the
  active model" for these requests. A candidate that asks more often is not measured
  against the owner there.
- The candidate outcome is the outcome of the model step. It does not include a grant
  in "ask" mode. So a candidate "run" of an owner denial counts as an allowed denial
  also when the grant would ask. This is stricter.
- The owner labels are `task_match` labels only. A flagged denial gives none. With few
  denials without a flag, the candidate learns mostly from approvals (section 11.1).
  The `destroy` examples of flagged denials also get the denial weight.
- During a training, the example files have commands and user requests. They are in a
  folder with mode `0700` and are deleted when the trainer ends. A crash of the app
  during a training can leave them. The next training does not use them.
- The app bundle does not ship `tools/`. The owner sets `APASSY_TOOLS_DIR`, or copies
  `tools/` to `$APASSY_LAYA_DIR/tools`.
- The gate counts all owner decisions in the log, also decisions that an earlier
  training used.
- The shadow and promotion measurements use synthetic cases. The labels of the
  fixtures come from the same author as the rules ([the bouncer](bouncer.md),
  section 4).

## 13. Checks

Results on 2026-09-26, after the merge of `goal-v1` at 02ebfef:

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS |
| `cargo test --locked --features desktop,vault` | PASS, 0 failed |
