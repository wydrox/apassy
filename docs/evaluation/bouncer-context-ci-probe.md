# Bouncer context: supervised CPU experiment in CI

Status (2026-11-04): the actual probe for source HEAD `1b9cbd98` ended
**UNSUPPORTED** at the 120-second cached-head calibration limit. Compiled Rust/G1
checks (24 tests) and tokenizer checks (3 tests) passed without skips in that run;
these are not quality evidence. Source HEAD and Actions tested SHA are distinct,
as recorded in the timeout analysis. The new calibration method below is
**NOT_RUN**. B remains UNSUPPORTED; C/D/E remain blocked.

This implements the method accepted under W1–W8 in
[the calibration review](../reviews/bouncer-context-calibration-method-review-2026-11-04.md).
The entry flow follows the accepted
[single-probe review](../reviews/bouncer-context-single-probe-entry-review-2026-11-04.md),
including its explicit eligibility summary and documentation conditions.
A probe provides runtime eligibility evidence only, never B PASS. Existing
quality, safety, schema, freeze and runtime gates remain unchanged.

## Entry points and event boundary

The pull-request trigger runs **preflight only** on opened, synchronized and
reopened PRs matching the listed paths. The job is named `preflight` and requires
compiled replay, G1 host extraction and tokenizer checks without skips. It makes
no runtime calibration, checkpoint, freeze or eligibility result. Its resource
artifact has scope `synthetic_preflight_only`; a green preflight is not a probe
result or gate B PASS.

`workflow_dispatch` and `workflow_call` retain the `mode` input (`probe`/`full`,
default `probe`) for compatibility. **Do not dispatch probe mode.** Under the
accepted W8 entry review, commit every change into the final revision X, wait for
green CI and preflight on X, then send exactly one command through the already
registered, unchanged `ci.yml` bridge:

```bash
gh workflow run ci.yml --ref feat/bouncer-secret-context -f context_experiment=full
```

No manual dispatch has occurred. Do not push between green CI and this dispatch.
Do not dispatch while an earlier run on the same ref remains active. Identify the
new run and verify its head SHA is X. The bridge also runs the existing full CI
suite, including macOS jobs, with no secrets or publication.

This single pipeline runs one real probe on X, followed automatically by full
training only when the **whole probe job succeeds** and exports a nonempty group
count meeting both budget constraints. Train and evaluate also require the actual
`workflow_dispatch` event and `mode=full`; a PR call cannot start them. No standalone
probe followed by another full dispatch is allowed. Any non-ELIGIBLE result ends
the path with B UNSUPPORTED, without a rerun. Existing N2–N4, same-revision CI,
freeze, quality and further-review requirements remain in force.

The probe summary explicitly records ELIGIBLE or UNSUPPORTED. Read eligibility
from `budget.json` and job states, never from the run's overall conclusion: a
budget refusal can leave the run green while train and evaluate are skipped.

## Isolation and pinned inputs

All three jobs use the existing `ubuntu-24.04` runner type, Python 3.12 and only
`contents: read`. Checkout disables persisted credentials. Checkout, setup-python
and upload-artifact action SHAs match `ci.yml`; the download-artifact SHA is the
existing v8.0.2 pin in `bouncer-image.yml` (there is no download pin in `ci.yml`).
No repository secret, R2 read, owner data, endpoint, paid service or publication is
introduced. Dependency installation and the Rust build occur only in CI.

Each fresh job creates a private venv, public-model HF cache and package caches
under `$RUNNER_TEMP/bouncer-context` (`EXP`). It unsets the known HF/Laya owner
credential and base overrides, disables implicit HF credentials and telemetry,
hides CUDA and fixes math threads. It installs existing requirements after
CPU-only `torch==2.14.0`, checks dependency consistency and CPU/thread identity,
fetches the pinned public base, verifies its manifest revision and weights hash,
and then sets the HF/Transformers offline flags. These are library offline flags,
not an operating-system network sandbox. No owner cache is restored.

The probe builds the real baseline example using
`cargo build --locked --features vault --example context_route_replay` with a
job-private target directory. `APASSY_CONTEXT_REPLAY_BINARY` points at that binary.
The replay and G1 data suites, including compiled fixture parity and both generated
splits checked with Rust's actual host extractor, must pass with zero skips.
The tokenizer unittest suite must also pass with zero skips; an independent
10,000-context measurement must exactly match the canonical budget. A skip or
budget mismatch stops the job. Source-only unit tests are not quality evidence.

## Probe and projection

The 40-minute probe generates only G1 data with `--groups 40 --seed 7`. It uses the
current generator's validation split of ten groups. The trainer receives exactly:

```bash
--mode probe --limit 64 --epochs 1 --max-steps 4 --batch 1 \
--threads 2 --seconds-per-head 600 --seed 7
```

The whole training invocation has an external 1,250-second timeout and a
23-minute step limit, including setup, validation and writes. The per-head limit
is not a limit on the whole invocation. Exit 3 is accepted only with an exact
`training_completed=true`, probe/UNSUPPORTED training-only report and matching
freeze/data/checkpoint hashes at the expected paths. Configuration, contract,
tokenizer, base, source commit, harness/helper hashes and installed package
versions are independently verified.

The report must contain finite positive `projected_full_seconds`, additive
projection components, and encoder timings for 32 validation rows at batches one
and eight. Projection provenance records 800 groups, four epochs and two heads.
It also measures four fp16 cache-write batches. Cached FP32 head calibration
uses method `batch8x4_max_batch32_spot_v1` at sequence length 512, on two threads,
with the encoder excluded. Its five ordered phases share one 120-second limit,
including setup and restore:

1. Training batch 8: two warmups, then three raw samples.
2. Validation batch 8: two warmups, then three raw samples.
3. Scoring batch 1: two warmups, then three samples (including p95 per row).
4. Training spot batch 32: one sample, zero warmups.
5. Validation spot batch 32: one sample, zero warmups.

Raw training/validation p50 and p95 describe batch 8 only. Each spot records
`single_sample_seconds`, never p50/p95. The top-level record has
`projection_batch_size=32` and no `batch_size`. For training and validation,
`scaled_batch8_to32` is four times the raw p95; `projection_step_seconds` is
`max(scaled_batch8_to32, spot32)`. A spot greater than 1.3 times its scaled value
always makes the result UNSUPPORTED. The workflow checks all fields and derived
values with relative tolerance 1e-12 and recomputes `T.project_workload` from raw
measurements and counts, rejecting the old method.

This is a runtime estimate for eligibility, never a batch32 p95, training cost
or performance result. Measured work retains provenance
`frozen_fp16_disk_cache_fp32_head_logits_adamw` and includes disk cache lookup,
collate, forward/loss, backward, gradient clipping and AdamW; validation includes
loss and scoring includes softmax. Public base identity and private-weight
provenance are unchanged.

Head weights, gradients, flags, module modes and RNG are restored on success and
failure; the cache is disposable. A failure preserves the original exception.
Optional `diagnostics.cached_head_partial` has phase, completed calls, elapsed
seconds and `eligibility=false`; it never substitutes for completed `cached_head`
and never receives a group count. The four-step probe training policy is unchanged.

`g1_workload_counts` counts serialized context/control cache identities using only
G1 at 800 training and 200 validation groups. For every selectable prefix of
400..800 groups it computes encoder, training, validation and scoring workloads,
then takes conservative 800-group equivalents. This preserves the existing
linear group-selection inequality without assuming linear cache deduplication.
The workflow validates timing provenance and recomputes the projection from the
measured timings and recorded counts. Encoder work is counted once; cached head
passes and final validation scoring are separate positive components.
The probe publishes the freeze SHA and report SHA as job outputs. The training
job verifies both external hashes, all probe artifacts and code/package identity
before accepting the projection. `budget.json` records the checked provenance
and largest integer group count in 400..800 satisfying:

```text
projected_full_seconds * groups / 800 * 1.3 <= 0.6 * 300 * 60  # 10800 seconds
(encoder_cache_seconds + training_cache_io_seconds / 2) * groups / 800 * 1.3 <= 5400
```

If 800 fits, it is selected. If no count at least 400 fits, full training is skipped as
`UNSUPPORTED(budget)` and evaluation never starts. No held-out data influences the
projection or group selection.

After freeze verification, `context_replay.py` benchmarks G1 `val.jsonl` using
`--mode probe --threads 2` and the context checkpoint SHA read from
`freeze['context']['sha256']`. It uses a fresh subprocess per arm and secret count,
CPU, three warmups, N=20 for each of one and three secrets. The benchmark step has
the same 40-minute ceiling as the job; the job deadline also covers all prior
steps. It reports measured p50/p95 and RSS plus head/base/contract/tokenizer
provenance. It does not manufacture PASS. The public stock baseline heads are
compute-shape evidence only. The combined-process measurement remains explicitly
NOT_RUN/informational in the current harness.

## Manual full training and frozen handoff

The full sequence is probe → train (300 minutes) → evaluate (120 minutes).
Immediately after checkout, before setup-python or any Python command, the
training job removes exactly these three paths in its disposable CI checkout:
`tests/evals/secret-context-heldout-v1.jsonl`,
`tests/evals/secret-context-heldout-v1.manifest.json`, and
`tests/evals/secret_context_heldout_v1.py`. No glob or owner checkout deletion is
used. The trainer's existing audit hook independently refuses held-out opens.

The train job downloads the probe evidence, verifies its external identities,
copies the verified report to `$EXP/evidence/verified-probe-report.json`, and
replaces only the generated G1 data with the selected group count. Its trainer
configuration is exactly:

```bash
--mode full --limit 0 --epochs 4 --max-steps 0 --batch 32 --threads 4 \
--lr .0003 --wd .01 --warmup 100 --seconds-per-head 5400 --seed 7 \
--probe-report "$EXP/evidence/verified-probe-report.json"
```

The invocation is additionally capped at 17,000 seconds within the 300-minute
job. Exit 3 requires completion and all frozen data/checkpoint/configuration,
code, base and package checks, including the harness's full freeze verifier.
Feature caching is bounded at 6 GiB by the trainer and removed at exit. Before
any evaluation job starts, the training job writes the full freeze SHA to its
job output and the Actions summary. It does not publish a model release.

The allowlisted artifacts retain experimental context/control heads, G1 train/val,
data manifest, training report, verified probe report, freeze, budget, tokenizer,
base identity and timing/cost evidence for seven days. They exclude base weights,
HF/package caches, venv, feature caches and Rust build outputs. Upload on failure
is best effort; cancellation or a hard job timeout may prevent it.

Evaluation uses a fresh checkout/job and restores the full artifact directly
under `$RUNNER_TEMP/bouncer-context`, preserving the frozen absolute paths for
`synthetic/{train,val}.jsonl`, the manifest and `full/{context,control}.safetensors`.
It never rewrites `freeze.json`. A different runner path, package version, code
hash, data hash or checkpoint hash fails verification. The external train job SHA
is checked before any held-out open. Evaluation builds the baseline example,
requires replay parity without skips, then benchmarks full-mode cost at N=50,
three warmups, one and three secrets, four threads, fresh CPU subprocesses.

The evaluator receives `--expect-freeze-sha256`, `--baseline-binary` and
`--cost-json`. It independently verifies the full freeze before its first held-out
read. Full cost failure is retained as a failed benchmark step but permits quality
evaluation to report its separate result; missing/invalid cost stays UNSUPPORTED.
The final evaluator exit follows gate B: 0 PASS, 1 FAIL, 3 UNSUPPORTED. The summary
prints `feasibility_quality` and `gate_b` separately, with missing evidence. Quality
PASS alone never unlocks C/D/E. The baseline is proven by the Rust lower bound or
remains `baseline_shipped` UNSUPPORTED when H_ship is needed but unavailable.
Stock public heads cannot satisfy that gate. This workflow neither fetches shipped
heads through R2/secrets nor publishes them.

## W8 and evidence status

The accepted entry flow resolves the duplicate-probe issue: PRs perform preflight
only, and the one manual full-mode pipeline performs the sole runtime probe before
conditional training. The existing `ci.yml` bridge, artifact handoff, external
freeze checks and held-out isolation remain unchanged.

W8 allows exactly one actual bounded new-method probe on final SHA X with green
CI, within the existing 120-second head and 40-minute probe limits, offline,
without private weights or R2. Full must consume eligible evidence on that same X.
Any noneligible result ends this research path with B UNSUPPORTED: no automatic
retry or method adjustment to obtain eligibility. No eligible group means
`UNSUPPORTED`/`budget` and no full training. The added L1 inequality only tightens
the existing limits; 300 minutes, 5400 seconds per head, 6 GiB cache, four epochs,
full batch32, thresholds and the single held-out pass remain unchanged.

The integrated local context suite passed 87 tests and skipped four requiring an
explicit compiled Rust binary or tokenizer. Fake and stdlib checks cover state
restoration, refusal, projection arithmetic and all four workflow validators.
They do not execute a model, weights, training, held-out or a real probe and do
not establish runtime eligibility or gate B. Hosted CI must execute the compiled
and tokenizer checks without skips on the final revision before the one dispatch.

## Manual cost-only checkpoint input (runtime NOT_RUN)

`cost-only` is a separate optional entry for a checkpoint trained with the existing
`train.py` on the Mac. Quality evaluation remains on that same Mac/venv. It skips
probe/train/evaluate and requires the actual `workflow_dispatch` event, including
through `ci.yml` (`context_experiment=cost-only`). Ordinary CI jobs remain unchanged.
Supply `source_sha` (exact lowercase 40 hex, equal to both Actions SHA and checkout
HEAD), `checkpoint_asset` (positive numeric `release_id/asset_id` in `wydrox/apassy`),
`checkpoint_sha256` and `val_sha256` (external lowercase 64 hex from the Mac
checkpoint/freeze), and `groups` (400..800). Seed is fixed at 7. The final source
revision must include this workflow; the original task HEAD is not a dispatch target.

The owner must explicitly approve any later local upload to a **draft** GitHub
release. This implementation only reads. Before model training, one separately
approved transport preflight must establish that the workflow's `GITHUB_TOKEN`
with **Contents read** can see the draft release and download its asset. Draft
visibility with this token is **RUNTIME UNVERIFIED**; inaccessible metadata fails
closed. No credential or permission expansion is implied. GitHub documents
[release metadata](https://docs.github.com/en/rest/releases/releases#get-a-release)
and [asset download](https://docs.github.com/en/rest/releases/assets#get-a-release-asset)
with Contents read; download may return 200 or 302.

For that preflight, use `context_experiment=cost-only` with `transport_only=true`
in `ci.yml`. Dispatch through this bridge while the experiment workflow is absent
from `main`; direct `mode=cost-only` dispatch is available only after that workflow
exists on `main`. Every bridge dispatch also starts ordinary CI, including macOS
and `release-binaries` builds; the owner's run approval must include this work.
Supply only `source_sha`,
`checkpoint_asset` and `checkpoint_sha256`. The approved test asset may contain
small synthetic bytes; no model checkpoint is needed. This uses the same guarded
download, limited to five minutes within a ten-minute job. It ends by uploading
only `transport-receipt.json`, before dependency installation, base download, G1
generation or benchmark. `val_sha256` and `groups` are unused in that path. The
default `transport_only=false` retains the full cost measurement. No transport
preflight or asset upload has been performed.

The helper verifies draft status, release/asset membership, uploaded state and a
positive size no larger than 256 MiB. It streams into a new file with exact size
and external SHA-256 checks, removing partial files on failure. Only API requests
to `api.github.com` receive the token. Redirects use fresh unauthenticated requests
to exact HTTPS hosts `release-assets.githubusercontent.com`,
`objects.githubusercontent.com`, or `github-releases.githubusercontent.com`;
other hosts, userinfo, non-HTTPS, nonstandard ports and loops are refused. Errors
omit credentials, signed URLs, query strings and raw response bodies.

The fresh `ubuntu-24.04` job uses the existing pinned CPU dependencies and verified
public base, then HF/Transformers offline flags. It regenerates only G1 train/val
on the exact source with the supplied group count/seed, checks manifest hashes and
the external validation hash, and calls the unchanged replay in full mode, four
CPU threads, 50 samples, fresh arms. No control checkpoint, full freeze, H1 or
private shipped heads are needed. Stock baseline heads provide cost shape only.
The full cost job is bounded at 120 minutes and the benchmark at 110 minutes. Only completed
`cost-full.json` and a compact identity/device/budget receipt are upload-allowlisted;
checkpoint, G1, base/cache and token are excluded. Failures mean **cost unmeasured**.
Success is **cost evidence only**, never quality PASS or B PASS. Actual download,
training, models, hosted benchmark and artifact upload are **NOT_RUN** here.

## Existing trainer on Modal (runtime NOT_RUN)

The current preparation uses the existing `train.py` through
`context_existing_freeze.py`, on one Modal GPU, preferring A10 with optional L4
at scheduling. It generates only G1 with 400 groups
and seed 7, trains context and facts-blind heads with the existing fixed settings,
and fits both thresholds on validation using CPU. It does not run W8 again or
change the gates. Modal receives an explicit source inventory without `.git`, H1
or private shipped weights. Automatic source mounts are disabled.

Use the registered `ci.yml` bridge for the new manual modes. `cuda-preflight`
installs the hash-pinned `requirements-cu130.txt` distribution and the existing
dependencies on hosted Ubuntu, checks exact package versions and CPU-only tensor
execution, and records source and disk evidence. It executes no model. The
existing `cost-only` with `transport_only=true` separately checks access to a
small owner-approved draft asset before training. Both dispatches also start
ordinary CI. Neither preflight has been run for this package.

After source review, green CI and owner approval, the launch entrypoint is
`context_modal_existing.py launch` with `--source-sha`, a unique `--run-id`,
`--approved-budget-usd` and a fresh `--evidence-dir` outside the checkout. It
requires CPython 3.12 with Modal SDK 1.5.4 and a clean tracked checkout at that exact
SHA. Other interpreter or SDK versions are refused before provider calls; the
serialized launcher and remote container must use the same Python minor version.
The proposed envelope is USD 8 total for Modal, including setup/storage/egress;
GitHub usage is separate; USD 8 is an approval envelope, not a provider spend cap.
The fixed request is `gpu=['A10', 'L4']`: Modal respects this [preference order](https://modal.com/docs/guide/gpu#gpu-fallbacks)
when scheduling one GPU before training starts. There is one spawn, `retries=0`
and `max_containers=1`, with no training retry after OOM, error or preemption.
Worker and bundle validation accept only exact `NVIDIA A10`, `NVIDIA A10G` or
`NVIDIA L4` names and preserve the actual device name in the receipt. A10
availability and performance remain unmeasured; no shorter allocation or training
time is established. Other limits stay fixed: four CPU cores, 32 GiB RAM,
30-minute image build, four hours for the whole remote attempt
including export, and a 4h15 caller cleanup cutoff. A durable attempt marker
prevents a restart from repeating training. A budget argument does not raise the
resource or time limits.

The result is a deterministic, uncompressed tar of exactly nine regular files,
at most 256 MiB. It includes both checkpoints, reports, original G1, freeze and an
inventory receipt. The owner-approved draft upload supplies `bundle_asset` as
numeric `release_id/asset_id`. Dispatch `ci.yml` with
`context_experiment=external-evaluate`, `source_sha`, `run_id`, `bundle_asset`,
`bundle_sha256` and `freeze_sha256`. These hashes come from the launch evidence,
outside the downloaded bundle. Restore validates all headers before any write;
verification compares the receipt with the actual git checkout before H1.

The hosted evaluator uses the same CUDA distribution on CPU, removes its Rust
build directory after copying the replay binary, then performs the unchanged CPU
cost comparison and one held-out evaluation. Its job limit is 300 minutes, with
110 minutes for cost and 120 for quality. Cost failure does not discard measured
quality. Set `shipped_baseline=true` only with an approved
`APASSY_CONTEXT_SHIPPED_HEADS_URL`; this HTTPS URL is confined to that job and the
download must match the shipped SHA before H1. It is never sent to Modal. Without
a conclusive baseline or cost, gate B remains UNSUPPORTED even if quality passes.
Only compact evidence JSON is published by the evaluator. Training, paid calls,
draft transport, private baseline access, hosted evaluation and release remain
**NOT_RUN** by this source preparation.
