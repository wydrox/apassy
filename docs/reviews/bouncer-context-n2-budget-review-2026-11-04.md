# Bouncer context: limited re-read of N2–N4, the cost fix and the budget repair

Date: 2026-11-04. Reviewer: Opus 5.5 (review sub-agent, source only, no subagents).
Checkout `apassy-bouncer-context`, branch `feat/bouncer-secret-context`, HEAD
**`1b9cbd9886a710ce4ba10f17229fb317c62fb460`** (PR #104). Scope: diff `606255e0..1b9cbd98` only.
Previous review: [bouncer-context-ab-recheck-2026-11-04.md](bouncer-context-ab-recheck-2026-11-04.md) (R5).
This is not a new architecture audit.

The reviewer did not read the held-out JSONL, its manifest or its generator, and did not run the
held-out generator. The reviewer ran no model, weights, network, secret, build, test suite or
install, and did not commit, push or dispatch. The only code executed was the stdlib G1 generator
plus `context_v1.serialize`, in memory with `python3 -I -B`. That run counted templates, label
priors and contract bound-token lengths. It wrote no file.

## 0. Verdict

**N2–N4 are closed in source. The cost fix is correct in source. The budget projection is a sound,
conservative upper bound of total work and does not mutate the model. There are no BLOCKING
findings.**
The R5 conditional approval for full **still holds**, on the same commit X = `1b9cbd98` (or a later
commit that changes none of these files), if both of these pass:
(1) CI on X is green, and the jobs show that both compiled test steps actually ran with zero skips;
(2) the single probe dispatched on X writes `budget.json` with `outcome=ELIGIBLE`, `groups` in 400..800.

Runtime status: **NOT_RUN** for everything new: host replay on both generated splits, the cost arms,
the cached-head calibration and the projection. Nothing here is a quality result.
`feasibility_quality`, gate B and C remain unmeasured or blocked. Read §3 L1 before dispatching full.

## 1. Required checks

| # | Status | Evidence |
| --- | --- | --- |
| N2 hosts derive from the visible command | **Closed** | `context_data.py:207`: `hosts = known` if the command has an explicit `https://….example.test` URL, else `none`. The default is `none` (`:190`). The catalog has exactly 2 destination templates per action, each with a distinct program key (`git ls-remote`/`helm list`, `git fetch`/`kubectl scale`, `git push`/`npm publish`, `kubectl delete`/`helm uninstall`). The global key-collision check (`:131-133`) plus the per-stratum half split (`:136-146`) give each split 1 destination and 5–6 local templates per action. That is 25 templates per split, and the program sets are disjoint. In memory, each class had 25 distinct base commands per split at 400/800 train and 200 val groups, and 20 at 100 val groups. All are ≥ 12. |
| N2 detection matches Rust | **Closed in source, runtime NOT_RUN** | `shell_risk::command_hosts` → `scheme_url_hosts` scans every argv word for `<alnum>://`, so `--server=https://…`, `--kube-apiserver=https://…` and `--registry=https://…` each yield one host (`shell_risk.rs:4605-4627,4685-4706`). The local templates have no URL. `dropdb`/`dropuser` are PG tools with `operand_host: false`, and their bare operand has no `host=`, so the result is empty. The new templates keep their action class: `helm list` is a plain-args Read (`action_kind.rs:1840-1851`), `git ls-remote` is a Read (`:1655`), and `kubectl --server` is a known value option (`:514,1803`). |
| N2 unknown host / project other never allow | **Closed** | `rubric()` returns `must_ask` first for either fact (`context_data.py:173`). The destination-only `agent-unknown`/`unrecorded-host`/`created-host` variants and `foreign-project` (`:246-254`) exercise it. The test asserts it on every row (`test_context_data.py:86-87`). |
| N2 no new shortcut or hidden flag | **Closed** | Allow prior in memory, train@800: local/`none` 2416/7086 (34 %), destination/`known` 623/1589 (39 %), `unknown` 0/273 (contract-deterministic). The `hosts` value no longer predicts the label outside the deterministic case. Positive `none` and `known` exist in every class and split for seeds 0/7/81 (test `:93-102`). The multi-secret count is now `(i//5)%2`. It is deterministic, independent of the label, and alternates against the 25-template cycle. |
| N2 not-serving keeps hosts coherent | **Closed** | `other` is chosen with the same destination/local stratum (`:272-273`), so `hosts=known` stays with a URL command and `none` with a local command. |
| N2 Rust invariant before decision | **Closed in source** | `context_route_replay.rs:155-159`: each secret, `(hosts=="none") != hosts.is_empty()` → `row_incoherent`. It runs before `analyze_run`, `before_model` and `decide` (the same `replay()` serves prepare and decide). A source-order test checks this (`test_context_replay.py`). Compiled regressions cover both directions × 3 secret positions × prepare/decide, plus parity with a destination `ForeignHost` row (`actual_host_count` = [0,0,1,0]). They also cover a full replay of both G1 splits against the real extractor (`test_context_data.py:117-136`). |
| N3 | **Closed** | `heldout_overlap` (`context_train.py:569-574`) refuses only `shared_families` and `shared_request_command_pairs`. It returns the program count as information. G1 train/val stays strictly disjoint, including programs: `context_train.py:694` and `context_data.main` (`assert not any(overlap(...).values())`). The test covers accept on a shared program, refuse on an identical pair, and refuse on a shared family. |
| N4 | **Closed** | `invalid_allow_label` (`context_eval.py:99-104`) = `fact_clause` ∨ `hosts=unknown` ∨ `project=other` ∨ (`production` ∧ `scope≠read_only`). `fact_clause` is unchanged and still drives the textual count. The audit runs after `verify_freeze`, the manifest hash and the overlap check, and before `FeatureCache`/`Scorer` (`context_train.py:602-605`). There is one test per term and a negative for production+read_only. |
| Cost `cost_arm_failed` | **Closed in source, runtime NOT_RUN** | `validation_views` (`context_replay.py:259-293`) skips only `Refusal('OverBudget')`. Any other refusal raises `validation_refusal`. Both children run the same deterministic filter on the same pinned file. The parent refuses differing `validation_selection` and records the counts per `n`. The tiny G1 val (10 groups) has fitting 1- and 3-secret views, and the test asserts that some 3-secret views are refused. Safe diagnostics: child stdout/stderr go to DEVNULL. `reason`/`child_reason` pass `_safe_cost_reason` (allowlist `:299-309`). `arm` and `secrets` come from argparse choices or the fixed loop. Exception text never crosses the boundary. In `606255e0`, `validation_views` had no filter and no reference to `Refusal`, so that failure was not a `NameError`. Over-budget 3-secret views in the context arm are the consistent explanation. The child output was suppressed, so this is **not proven**, and only a new CI run shows that the runtime is fixed. |
| Budget | **Sound (upper bound), no model mutation** | See §2. |
| Workflow | **OK** | All four verify blocks check `cache_write` (4 samples), `cached_head` provenance/shape/warmups/threads/`encoder_in_measured_step=False`/≤120 s, 3 samples per step, counts provenance and range. Each recomputes `T.project_workload` and requires equality. Both compiled steps discover `test_context_replay.py` and `test_context_data.py` and assert `not result.skipped`. Neither file has a skip other than the binary gate, which CI satisfies. Full and held-out gating is unchanged by this diff. The manual `ci.yml` bridge is the 16 approved lines, with no regression seen, so it is not reopened. |

## 2. Budget repair

- **Real head path:** `_cached_head_step` uses `train.collate`, `Scorer.features` (disk cache
  `torch.load`), `train.head_logits / temperature`, soft-target CE, `zero_grad`, `backward`,
  `clip_grad_norm_(1.0)` and FP32 AdamW (lr .0003, wd .01). This is the same sequence as
  `Scorer.train`. A precheck refuses any key missing from the cache, so the encoder can never run
  inside a measured step.
- **Padding:** only `input_ids` (pad id) and `attention_mask` (0) are padded to 512. `marker_pos` and
  `marker_mask` are untouched, and `features()` zero-fills positions past each row. The head layers
  are called directly with `src_key_padding_mask`, so no nested-tensor fast path skips the padding.
  Real batches are length-sorted and rounded to 32, so 512 is conservative.
- **Sampling:** 2 warm-ups inside the deadline, outside the distribution, then 3 samples for training
  b32, validation b32 and scoring b1. With 3 samples, p95 is the maximum. The cache write has 4
  per-row samples (32 rows at batch 8).
- **Restoration:** `cached_head_timings` restores the trained-prefix weights, `requires_grad`, `.grad`,
  every module's `training` flag, the CPU torch RNG and the Python `random` state in `finally`. Its
  deadline is a separate 120 s. `probe_timings` swaps in a disposable `FeatureCache` and closes it and
  restores the original in `finally`. Training is also independent: `initial` heads are captured
  before calibration, then `apply_heads(initial)` and `manual_seed`/`Random(seed)` run per head. The
  four-step probe policy is unchanged.
- **Counts:** `g1_workload_counts` uses G1 only (800/200, seed from the probe), buckets by group
  index, and walks prefixes with val added at `g%4==0` (= `max(10, g//4)` for g ≥ 400). It adds the
  context (budget-enforced) and blind (unenforced) serializations to one set. Cache keys are an
  injective function of the text, because the question and pins are fixed, so the set cardinality
  equals the real deduplicated cache. Each 800-equivalent is maximized separately over 400..800, and
  the sum of maxima ≥ the maximum of sums. Prefix stability holds: the templates depend only on
  (seed, split), and RNG use is sequential per group.
- **Projection:** encoder once × (p95 batch-1 encode + cache write), plus
  8 × (train batches × train step + val batches × val step), plus 2 × val rows × scoring step. All
  components must be > 0. Batches use `ceil(n/32)`. The 1600-row chunk is a multiple of 32, so this
  equals the real batch count. The inequality `projection·g/800·1.3 ≤ .6·300·60`, the 5400 s per-head
  limit, the 6 GiB cache and the full config are unchanged.
- **Work coverage (in memory):** the 32 encoder-timing rows are single-secret local reads, with
  contract bound mean 214 and max 282 tokens. The full workload has mean 248, p95 394 and max 469.
  The p95 per-row time comes from about a 280-token row, so it is at or above the mean-row cost
  (`Σ` over rows), and batch-32 sorted encoding is at least as efficient on CPU. The probe uses
  2 threads and full uses 4, which is also conservative. So the projection does not understate total
  work, within the margin (see L2).

## 3. Non-blocking limitations (no code change required for R5)

- **L1 (operational, read before full):** ELIGIBLE checks only the **total** projection.
  `Scorer.train` enforces 5400 s **per head** (`context_train.py:331-333`), and the context head carries
  almost all encoder work: about 8.4 k of the unique inputs, with only a few hundred blind. If
  `(encoder_cache_seconds + training_cache_io_seconds/2) · g/800 · 1.3` is above about 5400, the full run
  stops with `UNSUPPORTED('training wall limit reached')`. That is fail-closed: there is no freeze and
  the evaluate step does not run. It would still use up the one full dispatch on X. Recommendation:
  before dispatching full, the parent computes this per-head share from the probe artifact. If it
  exceeds 5400 s, report B `UNSUPPORTED(budget)` and do not dispatch. Do not raise any limit. A code
  check that only tightens the bound can wait for a later commit, so as not to move X.
- **L2:** The encoder sample comes from the first val templates by design. It is a measured
  estimate, not a strict per-row maximum. The 1.3 margin covers this.
- **L3:** The projection leaves out per-row `Scorer.item` tokenization (about 3 × rows per head, likely
  minutes) and page-cache effects of a cache of about 3–5 GiB. Both fall within the margin.
- **L4:** A held-out row whose `hosts` contradicts `command_hosts` now makes replay return
  `row_incoherent`, so the conditional LB is UNSUPPORTED. That is consistent with the contract and
  fails closed.

## 4. Gates

- Source approval: F1–F9 (earlier) plus N2–N4, cost and budget (here): **granted**.
- Full: **conditional** on same-X CI green with both compiled steps executed (0 skips, read the jobs)
  plus probe `ELIGIBLE` on X with 400..800 groups. Mind L1. One probe and one full per commit, never
  during an active run on the same ref.
- Feasibility quality, gate B: **NOT MEASURED**. `baseline_shipped` passes only through the
  conditional LB, otherwise UNSUPPORTED. Stock heads are cost-only. C, D and E: **blocked**. A new Opus
  review comes before C, even after gate B PASS.

## 5. Checks performed (read-only)

`git rev-parse HEAD`; `git diff 606255e0..1b9cbd98` of `context_data.py`, `context_eval.py`,
`context_train.py`, `context_replay.py`, `context_route_replay.rs`, the three test files, both
workflows and the two docs. Read `shell_risk.rs` (`command_hosts`, `scheme_url_hosts`,
`db_client_hosts`, PG tools), `action_kind.rs` (helm, kubectl, git reads), `train.py`
(`collate`, `head_logits`, `batches`, `encoder_states`) and `Scorer`/`main` in `context_train.py`.
Ran an in-memory G1 count with `python3 -I -B` (no files written). Free disk ≈ 11 GiB.

NOT_RUN: unit tests, Rust build and compiled tests, rustfmt and actionlint, CI, the probe, the cost
arms, the full run, the held-out, any model or weights.
