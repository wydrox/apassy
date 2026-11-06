# Bouncer context: A/B recheck after the F1–F9 repairs

Date: 2026-11-04. Reviewer: Opus 5.5 (review sub-agent, no subagents, source only).
Checkout `apassy-bouncer-context`, branch `feat/bouncer-secret-context`.
Reviewed commit **`b05556ef`**. The reviewer also read two later commits, `51e0355d` (safe replay
diagnostics) and `606255e0` (parity fixture fix). Each changes tests and diagnostics only.
Previous review: [bouncer-context-ab-review-2026-11-04.md](bouncer-context-ab-review-2026-11-04.md).

What the reviewer did not do: read `tests/evals/secret-context-heldout-v1.jsonl`, its manifest or
`tests/evals/secret_context_heldout_v1.py`; run a model, a test, a build, a network endpoint or a
secret; commit; push; touch `design/reviews/`. The only thing executed was the stdlib G1 generator
(`context_data.generate`), in memory, to count rows and sum token costs from the contract's segment
table. It wrote no file.

## 0. Verdict

- **F1–F9: closed in source**, except for one new defect in the same area as F4 (N2 below). See §1.
- **The compiled parity failure (CI run 41846245799, job 126630398009) was a test-fixture bug, not a
  route bug.** `view()` chose the first value from `('unknown', …)`, so the neutral case had
  `hosts=unknown`. The replay then correctly answered `ForeignHost`, and the `51e0355d` diagnostics
  confirm it (`flags=[]`, `pre_note=null`). `606255e0` fixes this correctly. The compiled parity check
  remains **unverified** until CI passes it on that commit. It is not a PASS.
- **Two blockers remain before a full run (N2, N3), plus one cheap pre-freeze fix (N4).** All of
  them are in files that the freeze pins. Each full run consumes the single held-out pass
  (supervision §7.4), so a known data or gate defect must be fixed **before** the first full run,
  not after it.
- **Manual-entry patch: YES, with the bounded conditions in §4.**
- **Full start: NO at `b05556ef`/`606255e0`. YES on a later commit if every condition in §5 holds.**
- Nothing here is a quality result. `feasibility_quality`, `gate_b` and C remain unmeasured.

## 1. F1–F9 status

| # | Status | Evidence (current tree) |
| --- | --- | --- |
| F1 control ablation | **Closed** | `context_eval.py:151-163`: AUROC(context) − AUROC(control) ≥ 0.15 and normal rate at the respective val-τ ≥ control + 15 points, on comparable rows. Pair ordering ≥ 90 %, ≥ 150 pairs, no allowed must_ask side. A measured pair failure stays `False` (`:165-166`). |
| F2 split | **Closed** | `context_data.py:111-126`: the seeded hash splits real templates by program key (24 per split, 6 per action). The family is `G1:<template_id>` without a split token. `overlap()` also compares program keys (`:260-263`). The generator asserts zero overlap (`:325`), and training re-checks it (`context_train.py:461-463`). |
| F3 hidden labels | **Closed** | `rubric()` reads only serialized fields plus the visible request/command catalog (`context_data.py:129-161`). `clean_established_read` is gone. The labels are a function of `model_text`. |
| F4 shortcuts | **Mostly closed; see N2** | Allow rows now include change/deploy/delete in local/dev/staging. There is one pair type per clause and a semantically different not-serving command. The host fact is still incoherent with the contract (N2). |
| F5 freeze | **Closed** | `verify_freeze` (`context_train.py:307-340`): external SHA, `mode=full` twice, contract/tokenizer/base pins, source hashes plus `git rev-parse HEAD`, package versions, exact reviewed config, artifact and data-manifest hashes, groups 400..800, no truncation. All of this runs before the first held-out IO (`:361`). The training process has an audit hook (`:61-68`), and the train job deletes the held-out files (workflow `:351-355`). |
| F6 baseline | **Closed as designed (conditional LB)** | Rust `examples/context_route_replay.rs` uses the actual `analyze_run`, `before_model`, `request_body`, `parse_answers` and `decide_learned`, with no `policy_sim`. LB passes only, and never FAILs (`context_eval.py:184-185`). `baseline_with_heads` requires SHA `832249…` and has no stock fallback (`context_replay.py:105-117`). |
| F7 risky N | **Closed** | `context_eval.py:148-150,178,198`: N and the one-sided bound use scored rows. Unscored and coverage asks are reported separately. |
| F8 control overflow | **Closed** | The control uses `enforce_budget=False` plus an exact 512 check (`context_train.py:125-132`). An overflow is not counted as unavailable (`context_eval.py:119-120`). A fitting overflow makes `facts` UNSUPPORTED, not FAIL (`:159`). That is conservative and acceptable. |
| F9 full mode | **Closed** | Full mode has no limit (`:470`), batch ≤ 64, warm-up plus cosine (`:230-233`), an fp16 cache with a 6 GiB bound and `finally` cleanup (`:71-99,422-423,539-541`), and per-head deadlines. |

Also accepted from R4: non-null `local_rule`, including `""`, is masked in both the scorer
(`context_train.py:163`) and the gates (`context_eval.py:111-112`). Any ask→allow flip through
injection or `agent_used=yes` fails, including on normal rows (`:170-171,182-183`). The label audit
runs after freeze and overlap and before `Scorer` (`context_train.py:368-375`). The strict replay
coherence check exists in both Python (`context_replay.py:45-60`) and Rust (`:76-95`), and they agree.

## 2. Findings in this recheck

| # | Severity | Path:line | Finding | Concrete fix |
| --- | --- | --- | --- | --- |
| N1 | High → **fixed in `606255e0`, CI pending** | `tests/basemodel/test_context_replay.py:19-22` | The neutral parity fixture had `hosts=unknown` (the first match in the preference tuple), so the expected `[false,true,true,true]` was wrong. The route-only `ForeignHost` ask was correct. | Done: `hosts='none', project='undeclared'` explicit, and `pre_reason` added to the safe diagnostics. Acceptance: the compiled parity test passes in CI on the commit that later trains. |
| N2 | **High, blocks full** | `tools/basemodel/context_data.py:167` (default `hosts='known'`), `:223-225` (`agent-none`, `unrecorded-host`, `created-host`) | **G1's `hosts` fact contradicts the contract.** Contract: `hosts=none` = no destination detected, `known` = every detected destination covered (`docs/contracts/secret-decision-context-v1.md:39-43`). Detection is `shell_risk::command_hosts` (`src/broker/shell_risk.rs:4605-4627`), which finds only scheme URLs and DB/HTTP-client hosts. None of the 48 catalog commands has one, so every G1 row should be `hosts=none`. Instead: (a) every base row says `known`, a combination that cannot occur in real traffic; (b) `hosts=none` appears **only** in `agent-none` rows, which are all must_ask, so "hosts=none ⇒ ask" predicts the label perfectly in G1. A held-out authored to the contract has `hosts=none` on its ordinary local rows, so a likely `normal` FAIL would come from the data, not the encoder. (c) `unrecorded-host` labels `hosts=unknown` **allow_ok**, but rubric step 1 makes it `deterministic_ask` (ForeignHost; the model never decides). The fixed fixture in `606255e0` now uses exactly the value G1 lacks: `git status` → `hosts=none`. | (1) Derive `hosts` from the command: `none` when it has no destination. Add ≥ 2 destination templates per action whose argv has an explicit `https://….example.test` host that `command_hosts` detects, and put the `known`/`unknown` variants only on those. (2) In `rubric()`, `hosts=unknown` (and `project=other`) is never `allow_ok` in G1: return `must_ask`, the conservative stand-in for deterministic. (3) Make the strict replay check `hosts == 'none'` ⇔ `command_hosts(argv)` is empty, in Rust (`context_route_replay.rs` after `:154`) and mirrored in the generated-view regression in `test_context_data.py`, so both G1 splits must pass. |
| N3 | **High (probable deterministic UNSUPPORTED), blocks full** | `tools/basemodel/context_train.py:368-370` | `any(collision.values())` also gates on `shared_program_subcommands` between G1 and held-out. The previous review asked for program disjointness **between the G1 train/val splits** only. §7.1 gates held-out on shared families and identical (request, command) pairs. G1's catalog spans 48 common program keys (`git status`, `kubectl get`, `rm`, `terraform apply`, …). An independently authored held-out almost surely shares at least one, so evaluation would end UNSUPPORTED after a 5–7 h run. The reviewer cannot confirm this without reading the held-out, and must not. Sharing a program is not leakage: val is already program-disjoint and measures template generalization. | Gate only `shared_families` and `shared_request_command_pairs`. Keep `shared_program_subcommands` in the report as information. Add a unit test: a held-out row with the same program but a different request/command is accepted, and an identical pair is refused. |
| N4 | Medium, fix with N2 (the freeze pins this file) | `tools/basemodel/context_eval.py:92-96` | The label audit misses allow_ok rows that the contract forbids: `hosts=unknown`, `project=other` (both deterministic), and `env=production ∧ action=read ∧ scope≠read_only` (not a positive allow). Such a held-out label error would count as a normal row, and allowing it would raise the normal rate and lower context asks against the LB. | Audit predicate = `fact_clause(view) or any(s['hosts']=='unknown' or s['project']=='other' or (s['env']=='production' and s['scope']!='read_only') …)`. Keep `fact_clause` itself for the textual-clause count. Add one test per new term. |

None of the following blocks a full run. They are recorded so that a result can be read correctly:

- **Budget projection** (`context_train.py:521-533`). `observed` divides the whole probe head time
  by 64 training rows. That time includes about 64 uncached validation encodes, and the result is
  then multiplied by 8 as if every epoch re-encoded. The projection is therefore several times too
  high, and the next probe will probably report UNSUPPORTED(`budget`) even at 400 groups. This fails
  closed, so it is honest but tells us nothing about capacity. If the parent wants a usable full run,
  the cheap fix (before the probe) is to time cached head steps separately at batch 32 and project
  `unique_texts × p95_encode + 8 × rows × cached_step`. It is not a correctness bug. If it stays
  unchanged, a `budget` UNSUPPORTED is the expected result.
- **Cache size:** computed with the contract's segment table plus ≈ 4 chars/token for the state, hidden
  size 1024, fp16, deduplicated keys. At 800 groups: 8 404 unique context texts plus 390 blind texts,
  about 3.7 GiB, under the 6 GiB bound (13 350 train+val rows; mean 212 tokens, maximum 394 < 469
  room). It fits.
- **R4 strict flip rule:** any normal-row ask→allow flip under `agent_used=yes` fails. That is
  defensible, but a score just under τ can flip by noise. G1 decorrelates `agent_used` (repeat and
  known_with_owner_history have equal base rates), so a FAIL here is a real dependence, not an
  injected signal. Report the margins with any FAIL.
- **Replay limits:** `_replay` refuses more than 4 096 views or more than 8 MiB. A larger held-out makes
  the LB UNSUPPORTED, and the gate stays named, so this is not a soundness issue.

## 3. Requested specific checks

- **LR / selection / identity:** warm-up 100, then cosine over `epochs × ceil(n/batch)`. Best
  validation loss restores the head state. τ = `nextafter(max risky val)`, on program-disjoint val
  only. Pins: the 6+1 harness hashes, `source_commit`, laya/torch/transformers/tokenizers versions,
  the data-manifest SHA, the probe report path, the external freeze SHA through job outputs. OK.
- **Cache identity:** the key is SHA(canonical text, question, contract/base/tokenizer/weights pins).
  The encoder is frozen: `TRAINED_PREFIXES` = head/type_emb/scorer, and `type_emb` is added after the
  cache in `head_logits`. Context and control can share one cache safely. OK.
- **Header completeness:** `Scorer.item` refuses unless `len(ids) == exact_tokens + header_tokens`
  (`:130-135`), and `environment()` refuses a measured header that is larger than the contract's. OK.
- **Risk denominators / control overflow:** see F7/F8. OK.
- **LB soundness (conditional):** route order `run.rs:690-801`: hard_rules (flags, MissingTask,
  DB-host, OneTimeCode, Production, AlwaysAsk) → readiness → NotProject → MissingDeclaration →
  Answer → UnfitAnswer → ForeignHost → ForeignProject → Pattern → Model. Each replay `pre_ask` reason
  is a route ask that only a remembered answer could bypass, and A2 rules those out. `local_rule` is a
  deterministic matrix row id by schema (supervision `:471`). Host reconstruction can only remove
  asks, which weakens the LB but keeps it sound. The LB **remains conditional on A1** (synthesized env
  names could add a flag that the real run would not have), on A2, and on the contract's HostFit and
  ProjectFit. It is correctly reported as conditional and never FAILs.
- **Held-out leak prevention:** the probe and train processes have audit hooks. The train job deletes
  the held-out files before any Python runs. Evaluate opens the held-out only after `verify_freeze`
  and `environment()`. The cost bench has its own audit hook plus a socket ban. OK.
- **Cost:** a fresh subprocess per arm and per secret count, `ru_maxrss` × 1024 on Linux, 3 warm-ups,
  50 samples in full mode, pins checked by `validate_cost_evidence`, and a parameter count of
  26 248 193 asserted. Stock heads are labelled `stock_public_informational`, which R3 allows
  **only** for cost, and they never stand in for H_ship. RSS includes load peaks for both arms
  equally. The combined process is NOT_RUN and informational. OK for B; C measures again on MPS.
- **Benchmark API:** `serve.HeadSelection(active, shadow, questions)` (`serve.py:162`),
  `make_multi_heads(tuned, stock|None)` (`:187`), `require_complete_state` (`:112`) and `bench.FACTS`
  (5 questions, `bench.py:67`) match the calls in `context_replay.py:194-222`. Only the CI run can
  confirm runtime compatibility with Laya 0.3.20.

## 4. Manual-entry patch `docs/reviews/bouncer-context-manual-entry-proposal.patch`: **YES**

The reviewer checked it read-only: `git apply --check --unidiff-zero` succeeds. The patch adds only a
`context_experiment` choice (off/probe/full, default off) and one job, `context-experiment`. That job
runs only when the event is `workflow_dispatch` and the choice is probe or full. It calls the local
reusable workflow from the same ref, passes no `secrets:` (no inheritance), and keeps `contents: read`.
The called workflow re-checks `github.event_name == 'workflow_dispatch' && inputs.mode == 'full'` for
train and evaluate (`:327,637`). Inside a called workflow, the `github` context is the caller's, so
that check still works. `release.yml` acts only on `workflow_run.event == 'push'` (`release.yml:39-41,91-93`),
so a dispatch run cannot publish.

Bounded conditions:

1. Apply exactly this patch. No other `ci.yml` edit.
2. **Known cost:** dispatching `ci.yml` also runs the **whole existing suite**. A dispatch is not a
   draft PR, so the macOS test shards, `extension`, `macos` and `release-binaries` all run on
   `macos-15`. That uses the shared five macOS runners. The suite's green result on that commit is also
   the Rust and macOS evidence the full run needs. Rule: one dispatch per commit for `probe` and one
   for `full`. Never re-dispatch while an earlier run on the same ref is in progress (the concurrency
   group would cancel it).
3. Dispatch only `--ref feat/bouncer-secret-context` at the reviewed commit. Record the run URL and the
   head SHA. A result applies only to that SHA.
4. Merging the patch to main is still the user's normal PR rule. The patch itself unlocks no gate.

## 5. Full-run start: **NO now; YES when all of these hold on one commit X**

1. N2, N3 and N4 are fixed, with their regressions, in X. The budget-projection fix from §2 is
   optional.
2. CI on X is green, including the compiled `test_rust_fixture_parity_and_all_verdicts`, which must
   **run, not skip**, and the Rust/rustfmt/actionlint jobs. `ci-status` exit 0 is not enough here, so
   read the jobs.
3. A probe on X writes `budget.json` with `outcome=ELIGIBLE` and a group count of 400..800. The full
   run uses that same X and that probe artifact.
4. The full run then reports what it measures. `feasibility_quality` FAIL or UNSUPPORTED is an
   acceptable, honest result. The held-out is used once. A re-run after a held-out-informed change
   needs a new held-out or an explicit owner decision.

If condition 3 gives UNSUPPORTED(`budget`), B stays UNSUPPORTED with `missing=["budget"]`. That is
not a quality FAIL, and the parent must not raise any bound to get past it.

## 6. Remaining gates

- **Source approval:** granted for the harness design, F1–F9. Pending N2–N4, with a re-read of only
  those diffs (no new full review).
- **Feasibility quality:** NOT MEASURED. It needs §5.
- **Gate B:** NOT MEASURED. It needs `feasibility_quality=PASS` ∧ `baseline_shipped` ∧ `cost`.
  `baseline_shipped` passes only through the conditional LB. Otherwise it is UNSUPPORTED
  (`shipped_heads_unavailable`), and only a separate explicit owner decision on the private R2 heads
  can change that. Stock heads are never H_ship. Cost may be measured with equal-shaped public heads.
- **C, D, E:** blocked. A `feasibility_quality=PASS` alone unlocks nothing. After `gate_b=PASS`, a new
  Opus review comes before C.
