# Bouncer context: A/B review (harness, evidence, replay contract)

Date: 2026-11-04. Reviewer: Opus 5.5 (review sub-agent, no subagents, source only).
Checkout `apassy-bouncer-context`, branch `feat/bouncer-secret-context`, base `773f02c2`,
first snapshot `42f00dd6`. Contract hash `01a9340c6404684050788e233690a53f81fa5a48b0aae000a4a06239206ea51d`.

The reviewer ran no tests and no model, and made no commit. The reviewer did not read
`tests/evals/secret-context-heldout-v1.jsonl`, its manifest contents, or
`tests/evals/secret_context_heldout_v1.py`.

**Verdict: B is not PASS and cannot reach PASS with the current harness.** The tokenizer and budget
evidence (header 43, 99 segments, 10 000 fuzz cases, 21 golden fixtures) is accepted as tokenizer
evidence only. It is not model-quality evidence. The harness has five blocking defects (F1–F5 below).
The missing baseline (F6) has a sound, label-free fix for everything except the shipped heads. No
public source of the shipped heads exists, so one owner decision remains (section 2.4).

## 1. Findings

Most severe first. Line numbers are at `42f00dd6`.

| # | Severity | Path:line | Finding |
| --- | --- | --- | --- |
| F1 | **High, blocking** | `tools/basemodel/context_eval.py:78,82,95-96` | The facts-blind ablation tells us nothing. A pair must have an identical `request` (`:78`), and `blind()` maps both sides to the same facts. For a pair with the same action, the control text of both sides is byte-identical, so the scores tie and the pair counts as unordered. `control_ordered` is therefore ≈ 0 by construction. The "≥ 30 points better than control" gate reduces to `ordered ≥ 30 %`, which the 90 % gate already implies. The control head is trained (`context_train.py:239-249`) and scored (`:176`) but has no effect on any gate. |
| F2 | **High, blocking** | `tools/basemodel/context_data.py:57,58-59,103-107` | The train/val split is separated in name only. `family = G1:{split}:{cls}`, and the train and val templates are the same except for the `{split}` and index tokens. `overlap()` therefore finds 0 shared families and 0 shared pairs by construction. Validation is in-template, so τ (`context_eval.py:30`) and any checkpoint selection are optimistic. Nothing measures template generalization before the freeze. |
| F3 | **High, blocking** | `tools/basemodel/context_data.py:22-26,61` | Some labels depend on attributes the model cannot see. `clean_established_read` and `serves_request` are hidden row attributes. "Established" (R1, contract doc `:50`) has no serialized representation: a cold-start read has `owner_allowed=0` and `agent_used=not_recorded`. Rows with byte-identical `model_text` can therefore get different labels. Nothing tests that two rows with the same serialized text have the same label. |
| F4 | **High, blocking** | `tools/basemodel/context_data.py:47-99` (`:58-60`, `:68`, `:75-76`, `:81-83`) | The generator teaches shortcuts. Every `allow_ok` row has `action=read` and the program `synthetic-inspect`. The counterfactual pair toggles only `owner_denied` (`:68`). "Unrelated" changes only the program token (`synthetic-unrelated`). No `allow_ok` row is a change or deploy in local, development or staging, so "action ≠ read ⇒ ask" is learnable as a shortcut. The env/production, conflict, delete, agent-created and hosts clauses never appear as pairs. Held-out pairs for those clauses are out of distribution. That is not leakage, but it makes a FAIL likely for reasons unrelated to encoder capacity. |
| F5 | **High, blocking** | `tools/basemodel/context_train.py:141-170`, `:256-260` | The freeze is not sound. (a) `evaluate_frozen` accepts a `mode=probe` freeze; nothing checks `config.mode == 'full'`. (b) The freeze records only data and head hashes: no source commit, no hashes of `context_{v1,data,train,eval}.py`/`train.py`/`common.py`, and no torch/transformers versions. (c) Nothing records the freeze SHA outside the run before the held-out read, and the same process family can rewrite `freeze.json`. (d) The held-out file is in the training checkout, so separation is procedural only and nothing enforces it. |
| F6 | **High, blocking** (the stated main problem) | `tools/basemodel/context_train.py:185-189`, `context_eval.py:99-101` | The baseline and cost gates are never measured, so a run without a measured failure always ends UNSUPPORTED. Also, `policy_sim.decide` (`tools/basemodel/policy_sim.py:62-76`) is a port that predates policies v5 and v7. It has no `known_command`/`known_write`/`default_source` and no production `leak`/`destroy` checks (`src/broker/bouncer.rs:1196-1300`). It cannot be the baseline as the supervision doc §7 suggests. |
| F7 | Medium | `tools/basemodel/context_eval.py:69,93,106` | `risky.n` counts `must_ask` rows that were never scored (they did not fit the budget, so they asked by coverage). The "0 of ≥ 300" claim and the one-sided 95 % bound must use the **scored** risky N. |
| F8 | Medium | `tools/basemodel/context_v1.py:151-160`; `context_eval.py:60` | Blinded values (`not_recorded`, `legacy_unknown`→`none`, …) cost different tokens from the originals. A control text can get `OverBudget` while the original fits. The control score is then `None`, `unavailable` increases, and `available=False` gives a **spurious FAIL**. |
| F9 | Medium | `tools/basemodel/context_train.py:121-122,211-213,228-229` | Full mode cannot run in practice. `--limit` (default 128) also truncates full-mode train and val, from the head of a class-cycled list. `batch ≤ 8` is enforced. The frozen encoder is recomputed on every step and every epoch, with no feature cache, so 4 epochs × 2 heads on CPU multiplies encoder passes by 8. |
| F10 | Medium | `docs/contracts/secret-decision-context-v1.md:44-53` | `HostFit`/`ProjectFit` (`hosts=none/known/unknown`, `project=match/other/undeclared`) are "computed by the caller" and never defined. "Clean, established read" (R1) is not defined either. The replay in §2 depends on these definitions, so they must be pinned. |
| F11 | Low | `tools/basemodel/context_data.py:17` | `owner_denied=unknown` (log at capacity) is treated as "no denial". The contract text does not decide this case. This is acceptable for v1 if it is stated. C must decide it explicitly. |
| F12 | Low | `src/vault/decision_evidence.rs:168-182` | When `agent_id` is `None` or `project_key` is empty, every owner denial goes to `owner_denied_other`, which the rubric ignores. The facts then show `owner_denied=0` while denials exist. This conforms to §3.3, and an empty project asks NotProject in the route. In C, `agent_id=None` must map the same-scope counts to `unknown`, not `0`. |
| F13 | Low | `src/vault/decision_evidence.rs:167` | Malformed `hosts` JSON in any `item_use` row of the item fails the whole evidence read with `Storage`. This fails closed, which is correct. C must map it to an ask, not to a retry loop. |
| F14 | Low | `tests/decision_evidence.rs:49-135` | The vault→facts→wire privacy test writes no `item_use` or `item_event` rows and no provider. The free-text columns (`agent_name`, `command_summary`, `project_label`, event `detail`) are never exercised end to end. The SQL never selects them (`decision_evidence.rs:145,188`, `agents.rs:1390`), so this is a test gap, not a leak. Add canaries in those columns. |
| F15 | Low | `tools/basemodel/context_train.py:267` | Training always exits 3. CI must gate on `training_completed`, not on the exit code. |

Accepted without findings: the vault evidence SQL is read-only and selects no field-value table
(`decision_evidence.rs:75,90,109,116,145,188`; `agents.rs:1390`). Future rows are ignored.
Inclusive window. Global use cap → `Unknown`. Event cap without `created`/`tracked` → both ages
`Unknown`. `facts_from_evidence` maps a missing declaration to unknown/none and a missing source
row to `legacy_unknown`, and it uses stored `is_sensitive()` (`secret_facts.rs:149-219`). The context
client refuses a remote brain before sending and retries only after a timeout
(`context_brain.rs:147-190`). The gate math (`context_eval.py:48-112`) counts non-fitting rows as
asks and never lets a missing comparison hide a measured `False`.

## 2. Minimal replay and measurement contract (`sdc-baseline-replay-v1`)

Goal: compute the current route's ask/allow for each held-out row from the label-free view only,
using the real Rust policy and pinned heads. No label, class or rationale may influence the
baseline.

### 2.1 Label-free view

`view(row) = {request{user_request, command, purpose}, action, secrets, local_rule}`. The replay
code never receives `label`, `class`, `rationale`, `pair_of` or `injection_of`. Test: permuting
the labels across rows leaves every baseline outcome unchanged.

### 2.2 Model-free stage (exact, Rust)

Add a new example, `examples/context_route_replay.rs` (`required-features = ["vault"]`). Its only
build change is a 4-line `[[example]]` stanza in `Cargo.toml`: no dependency and no runtime change.
If the parent refuses even that stanza, put the same code in a `tests/` module behind an
environment variable, declared in `tests/it.rs`.

Pass `prepare`, for each view:

- `analysis = shell_risk::analyze(argv, …, env_names)`, with arguments copied exactly from the
  `run.rs` call site. The Sol cites the line. `argv = command_line_to_argv(command)`. Rows carry no
  env names: use `$NAME` references found in the command, else `SECRET_1..n`. This is recorded as
  approximation A1.
- Reconstructed `DecisionContext`. `env_from=none` ⇔ no declaration, and with it
  `env=unknown`/`scope=unknown`. Any other combination with `unknown` makes the row incoherent:
  UNSUPPORTED(`row_incoherent`). Otherwise `Declaration{environment=env, scope=scope,
  risk=High iff sensitive=yes ∧ env≠production, reversibility=Reversible}`; `is_sensitive()` is
  then exact. `has_user_request = !user_request.trim().is_empty()`.
- `pre = bouncer::before_model(&ctx)` (owner_required, flags, MissingTask, MissingDeclaration), plus
  the route-only asks that follow from the facts by their definition (pinned per F10):
  `local_rule ≠ null` → ask; `hosts=unknown` → ForeignHost; `project=other` → ForeignProject.
  Remembered answers and patterns are absent in **both** arms (supervision §6), and the report states
  this as assumption A2.
- `systemone_body = bouncer::request_body(&request)` with empty `instruction`.

Output: `{pre_ask: bool, pre_reason, systemone_body}`.

**Sound lower bound (LB).** The model step can only add asks, so `old_asks(class) ≥ Σ pre_ask`.
If `context_asks(class) ≤ LB(class)` holds for every class, the baseline gate passes **for any
heads**. That is a proof, not an approximation. Otherwise the gate needs the model stage.

### 2.3 Model stage

Score `systemone_body` in-process with the serve.py predictor path (the same `HeadSelection`, with
`zero_shot_questions=["leak"]` from the stock heads). Use the same Agent and the same CPU and
threads as the context arm, with no HTTP. Pass `decide`: `bouncer::parse_answers(body, asked)` →
`decide_learned(&verdict, &ctx, &Learned{thresholds: weak ? task_match=MIN_CONFIDENCE : default})`,
where `weak = env_from==default`. Approximation A3: `decide_routed` is `pub(super)`, so a
weak-source known-safe read is replayed as allowed. This **favors the baseline**, which makes B
stricter.

- **Heads H_ship** = `manifest.json` `checkpoint.sha256` `832249…` (26 248 193 parameters). Only this
  arm can decide `baseline_shipped`.
- **Heads H_stock** = the stock heads in the public base `convaiinnovations/laya@55cf4c4e`
  (weights SHA `891102…`). This arm is reported as `baseline_stock_public`, **informational only**,
  never the B gate.

### 2.4 The shipped heads are not public, so this is an owner decision

Checked read-only on 2026-11-04:

- GitHub releases v0.5.16–v0.5.18 carry no head asset.
- `ghcr.io/wydrox/apassy-brain` refuses anonymous pulls.
- The release and image workflows fetch the heads from R2 with Cloudflare secrets
  (`release.yml:262-271`, `bouncer-image.yml:85`).
- Public `latest.json` gives a 31 MB DMG, which cannot hold the 105 MB checkpoint.

So `baseline_shipped` is decided by LB, or it stays UNSUPPORTED(`shipped_heads_unavailable`) as a
**named single gate**. There is no fallback to stock heads and no retrained substitute.

Unblocking options, both needing the owner:

- (a) Attach `apassy-base-v1.safetensors` plus its SHA to a public release. That is publication.
- (b) A `workflow_dispatch`-only job reads R2 with the existing secret, verifies `832249…`, and never
  uploads the file. That is a secret use.

The reviewer recommends (b).

### 2.5 Cost (measurable now; head values do not change compute)

- Fresh subprocess per arm, CPU, threads fixed, warm-up 3, then N = 50 per arm for 1 and 3 secrets.
- Inputs come from G1 validation rows, never the held-out set.
- Baseline arm: encoder plus one head set of the shipped shape (H_ship if present, else H_stock).
  Assert 26 248 193 parameters. Use the 5 FACTS questions on `state_text`.
- Context arm: the context head set, 1 question on `model_text`.
- Record p50/p95 wall time of encode+heads, and peak RSS from `ru_maxrss` (Linux KiB × 1024).
  Also record a combined process (encoder + both head sets) as informational.
- Gate as §7: `p95 ≤ 1.5×`, `RSS ≤ +256 MiB`. Device `github-ubuntu-24.04-cpu` is recorded. C must
  measure again on the owner's Mac (MPS).

## 3. Separate feasibility-quality report: allowed, with conditions

The reviewer decides: **yes.** The question "can a head on the frozen encoder read the facts?" does
not depend on the old-route baseline or on cost. `context_eval.py` therefore writes **two outcomes**
in one report:

- `feasibility_quality` ∈ {PASS, FAIL, UNSUPPORTED}. Gates: environment, available, normal,
  risky (scored N), deterministic, facts (repaired, §4 item 4), injection, self_reinforcement,
  coverage, label audit (§4 item 5).
- `gate_b` ∈ {PASS, FAIL, UNSUPPORTED} = `feasibility_quality` AND `baseline_shipped` AND `cost`.
  `feasibility_quality=FAIL` ⇒ `gate_b=FAIL`. A missing `baseline_shipped` ⇒ `gate_b=UNSUPPORTED`,
  with `missing=["baseline_shipped"]`. The exit code follows `gate_b`.

Conditions:

- A `feasibility_quality=PASS` never unlocks C, D or E.
- It is never reported as "B PASS". The report text and CI summary must say "feasibility quality only".
- It needs a full-mode freeze. A probe-mode freeze is never evaluated against the held-out set.

## 4. Approved scope for the next Sol

Only these files. Everything else is forbidden:

- runtime code (`run.rs`, `bouncer.rs`, …, the full supervision §0 list)
- `serve.py`, `app.py`, `train.py`, `common.py`, `manifest.json`
- dependencies; the contract JSON and its hash (no change needed)
- held-out files
- `secret_facts.rs`, `context_brain.rs`, `decision_evidence.rs`

1. **`tools/basemodel/context_data.py`** (F2–F4):
   - Families `G1:<template_id>`, each template assigned to exactly one split by a seeded hash.
     ≥ 12 request/command templates per class, with distinct programs and verbs per split.
   - `allow_ok` rows include change/deploy in local, development and staging.
   - One counterfactual pair type per must_ask clause: denial, conflict, env+action, delete without
     2-4 allows, agent-created+hosts, and not-serving with a semantically different command (not a
     marker token).
   - Remove `clean_established_read`. Labels are computed by `rubric(view)` from serialized fields,
     plus a template-level `serves` that always changes the text.
   - Overlap also compares the normalized program and subcommand between splits.
2. **`tools/basemodel/context_v1.py`**:
   - `visible_view(row)`.
   - `blind()` unchanged. Scoring of the control uses `enforce_budget=False` plus an exact-count
     check against the 512 limit; an exact overflow is counted separately, never as unavailable (F8).
3. **`tools/basemodel/context_train.py`**:
   - Full mode: no limit, or a limit ≥ all rows. Batch ≤ 64.
   - Warm-up 100 and cosine schedule, using `train.py` helpers by import only.
   - Fp16 encoder feature cache in RAM or under `$RUNNER_TEMP`, bounded at 6 GiB, deleted at exit.
   - `sys.addaudithook` refuses any `open` of a path containing `secret-context-heldout` or
     `secret_context_heldout`.
   - Freeze adds `mode`, `source_commit`, SHA-256 of the 6 harness/helper files, the data-manifest
     SHA, and torch/transformers/laya versions.
   - Probe mode adds the encoder time per row (p50/p95, batch 1 and 8) and `projected_full_seconds`.
4. **`tools/basemodel/context_eval.py`**:
   - The two outcomes of §3.
   - `evaluate` requires `--expect-freeze-sha256` and `mode=full`; it refuses otherwise (F5).
   - Risky N and the one-sided bound on scored rows (F7).
   - The facts gate keeps pair ordering ≥ 90 % and 0 must_ask-side allows. The control comparison is
     replaced by held-out AUROC(context) − AUROC(control) ≥ 0.15 and normal auto-allow at the
     respective val-τ ≥ control + 15 points (F1).
   - Baseline from §2 (LB, then H_ship if present; H_stock informational).
   - Cost from the §2.5 JSON.
5. **Label audit, post-freeze only:**
   - A held-out `allow_ok` row whose facts trigger a fact-level must_ask clause ⇒ held-out invalid ⇒
     UNSUPPORTED(`label_audit`).
   - A `must_ask` row with clean facts is counted as "textual clause" and reported.
   - The audit never changes τ or scores.
6. **New `tools/basemodel/context_replay.py`**: the Python side of §2.3 and §2.5.
7. **New `examples/context_route_replay.rs` and its `[[example]]` stanza in `Cargo.toml`**: §2.2,
   with `prepare` and `decide`. This is the only `Cargo.toml` change and needs parent sign-off.
8. **Tests:**
   - `tests/basemodel/test_context_v1.py`: an observability invariant (same `model_text` ⇒ same
     label over train+val), split template disjointness, freeze refusal for probe mode and a wrong
     SHA, the F1 regression (an identical-text control must not satisfy the facts gate), and the
     F8 regression.
   - New `tests/basemodel/test_context_replay.py` (stdlib): label permutation invariance, LB
     soundness with fake scores, cost gate, and an example-fixture parity check (`SkipTest` without
     the binary).
9. **Workflow and docs:**
   - `.github/workflows/bouncer-context-experiment.yml` and `docs/evaluation/bouncer-context-ci-probe.md`.
   - The probe job as today, plus the timing/cost bench and `cargo build --locked --features vault
     --example context_route_replay`.
   - A **`workflow_dispatch`-only** full pipeline. Job `train` deletes `tests/evals/secret-context-heldout-v1*`
     and `tests/evals/secret_context_heldout_v1.py` from its checkout before any Python, trains, and
     publishes `freeze_sha256` as a job output and in the step summary. Job `evaluate` (`needs: train`)
     downloads the artifact, verifies the SHA, and only then reads the held-out set.
   - Both run on `ubuntu-24.04`, `contents: read`, no secrets, artifacts kept 7 days.
10. **Parent, not the Sol:** add the HostFit/ProjectFit definitions and the operational R1 sentence to
    `docs/contracts/secret-decision-context-v1.md` (F10). That file is not hashed. Also add the
    canaries of F14 to `tests/decision_evidence.rs`.

### Configuration

| | Bounded CPU probe (PR trigger) | Full run (dispatch, after the probe measurement) |
| --- | --- | --- |
| Data | `--groups 40 --seed 7` | `--groups 800 --seed 7` (val = groups/4) |
| Train | `--mode probe --limit 64 --epochs 1 --max-steps 4 --batch 1 --threads 2 --seconds-per-head 600` | `--mode full --limit 0(all) --epochs 4 --batch 32 --lr 3e-4 --wd 0.01 --warmup 100 --threads 4 --seed 7 --seconds-per-head 5400`, feature cache ≤ 6 GiB |
| Bench | 20 samples per arm × {1, 3} secrets, warm-up 3; encoder time per row for 32 val rows | 50 samples per arm × {1, 3} |
| Limits | job 40 min; never opens the held-out set; never PASS | train job 300 min, evaluate job 120 min |
| Start rule | always | only if the probe's `projected_full_seconds × 1.3 ≤ 0.6 × 300 min`; else lower groups to the largest fitting value ≥ 400; below 400 → UNSUPPORTED(`budget`) |

Threads 4 assume the 4-vCPU runner of a public repository; the repository is public. The control
head uses the same configuration. τ comes only from validation, as in §7. Model selection is the
lowest validation loss.

## 5. Remaining gates (none of them is PASS)

1. F1–F5 fixed and reviewed, and the Rust CI of PR #104 green (not checked here).
2. A full-mode run: `feasibility_quality` measured (PASS or FAIL, honestly).
3. `baseline_shipped`: decided by LB, or with H_ship after the owner decision in §2.4. Otherwise
   UNSUPPORTED as a single named gate.
4. `cost` measured on CI CPU. The Mac/MPS measurement belongs to C.
5. `gate_b=PASS` only with 2–4 all passing. Then a new Opus review before any start of C. D and E
   remain blocked.
