# Bouncer context: supervised CPU experiment in CI

Status (2026-11-04): runtime **not run**. This workflow implements the CI boundary
in Opus review §4.9 and Configuration, with integration decision R3. A probe is
training and cost feasibility evidence only. It never evaluates held-out quality,
never reports B PASS, and never unlocks C/D/E. A full run still requires review of
this revision by Opus before the parent starts it.

## Entry points and event boundary

The existing pull-request trigger runs the bounded probe on opened, synchronized
and reopened PRs matching the listed paths. It does not start full training.
`workflow_dispatch` has a choice input `mode`, default `probe`, with choices
`probe` and `full`. `workflow_call` has a string input `mode`, also default `probe`.
Both full jobs require **both** `inputs.mode == 'full'` and the actual
`github.event_name == 'workflow_dispatch'`. Thus a reusable call from a PR cannot
start full training even if its caller supplies `full`.

After this workflow is registered on the default branch, the manual entry points
are, for the reviewed committed revision on the implementation branch:

```bash
gh workflow run bouncer-context-experiment.yml --ref feat/bouncer-secret-context -f mode=probe
gh workflow run bouncer-context-experiment.yml --ref feat/bouncer-secret-context -f mode=full
```

These commands are instructions for the parent; neither was executed here.
A newly added workflow may be unavailable for dispatch until its file exists on
the default branch. The parent may later add a minimal reusable call from the
registered `ci.yml`, after Opus review. This change does not edit `ci.yml`. Such a
bridge must expose/forward the mode from its manual trigger; the original event
must still be `workflow_dispatch`. No PR label, publication or other trigger is
used to bypass registration or the manual-only full boundary.

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
The replay unittest suite, including compiled fixture parity, must pass with zero
skips. The tokenizer unittest suite must also pass with zero skips; an independent
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
The probe publishes the freeze SHA and report SHA as job outputs. The training
job verifies both external hashes, all probe artifacts and code/package identity
before accepting the projection. `budget.json` records the checked provenance
and largest integer group count in 400..800 satisfying:

```text
projected_full_seconds * groups / 800 * 1.3 <= 0.6 * 300 * 60
```

If 800 fits, it is selected. If no count at least 400 fits, full training stops as
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

## Integration blocker and evidence status

At source inspection, `context_data.default_secret()` still combines known
`env=development` with `scope=unknown`/`scope_from=none` and unknown sensitivity.
Strict replay rejects that declaration combination as `row_incoherent`; variants
can inherit it. The parent owns the correction in data/replay files. This workflow
does not weaken validation or claim the benchmark has run. Re-review the corrected
harness and this workflow together before full execution.

Local validation is limited to actionlint and YAML, Bash syntax and inline Python
AST checks through heavy-check. No local model test, install, encoder inference,
training or Rust build was run. The parent's earlier 46 PASS / 2 SKIP context tests
are source checks, not quality or cost evidence. CI runtime compatibility,
completion, projections, CPU/RSS costs, artifact restore, held-out quality and
gate B remain unmeasured. Missing shipped-head evidence, CI costs, full quality and
subsequent Opus approval remain gates; Mac/MPS cost belongs to C.

Source checks on this revision completed successfully:

- `~/.local/bin/heavy-check actionlint .github/workflows/bouncer-context-experiment.yml`: exit 0.
- `~/.local/bin/heavy-check python3 /tmp/bouncer-context-static.py`: exit 0;
  YAML/event/permissions/action-pin/artifact/gating/order assertions, `bash -n`
  for 26 shell blocks, `ast.parse` for 15 inline Python blocks, and three
  group-selection boundary examples (800, 553 and no fitting group). The temporary
  checker did not execute workflow scripts or import the harness/model.
- `git diff --check -- .github/workflows/bouncer-context-experiment.yml docs/evaluation/bouncer-context-ci-probe.md`: exit 0.

Only the two owned files were edited. No commit, push, PR, Actions dispatch,
subagent, package install or build was performed. No local build directory was
created. Available disk after checks was approximately 11.6 GiB; cleanup of other
sessions' files is outside this two-file task.
