# Fine-tune study for the bouncer model (goal B8/B9)

Date: 2026-09-26. Decisions: [ADR 0009](../adr/0009-general-by-default-and-learning.md), [ADR 0010](../adr/0010-closing-open-decisions.md).

This document answers three questions for the goal:

1. Does the `laya` package support a fine-tune?
2. How long and how much memory does a local fine-tune need on the owner's Mac?
3. What does a shipped general base model (B8) need, and what is the on-disk
   format of an owner decision that the learning worker exports (B9)?

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
