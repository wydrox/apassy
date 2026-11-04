# Bouncer context: CI CPU probe

Status (2026-11-04): **not run**. This workflow is validation of bounded synthetic
training feasibility. A green job is never gate B PASS and does not unlock C/D/E,
production activation, deployment, or publication. The parent reviews and runs PR CI.

## Triggers and isolation

`.github/workflows/bouncer-context-experiment.yml` runs on pull requests
`opened`, `synchronize`, and `reopened` when the listed context implementation,
contract, fixtures, dependency/base-fetch inputs, evidence, or workflow paths change.
The new workflow itself matches the filter on the implementation branch. It also
supports `workflow_dispatch` with no inputs: only the same probe can run. There is
no full-training or held-out mode in the workflow. No dispatch was performed here.

The job uses the existing `ubuntu-24.04` runner type, Python 3.12, and checkout,
setup-python, and upload-artifact SHAs copied from `ci.yml`. Permissions are only
`contents: read`; checkout does not persist credentials. No repository secrets,
owner data, endpoints, Docker, paid services, new runners, or publication are used.
An artifact upload is CI evidence storage only. Concurrency cancels the older run
for the same PR/ref; the job timeout is 30 minutes. Cancellation or timeout may
prevent evidence upload; `always()` is best effort, not a guarantee after termination.

All model files, venv and caches live under `$RUNNER_TEMP/bouncer-context` (`EXP`).
`HF_HOME`, `HF_HUB_CACHE`, `XDG_CACHE_HOME`, and `PIP_CACHE_DIR` are isolated there.
A Bash startup file unsets `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`,
`HUGGINGFACE_HUB_TOKEN`, `HF_TOKEN_PATH`, `APASSY_BASE_MODEL`, and `LAYA_API_KEY`
for subsequent run steps. Implicit HF token use and telemetry are disabled.
No environment dump is logged. CPU math threads are limited to two and CUDA is hidden.

## Exact probe sequence

These commands describe future CI execution, not commands run locally:

```bash
python -m venv "$EXP/venv"
PY="$EXP/venv/bin/python"
"$PY" -m pip install --index-url https://download.pytorch.org/whl/cpu 'torch==2.14.0'
"$PY" -m pip install -r tools/basemodel/requirements.txt
"$PY" -m pip check
"$PY" -B tools/basemodel/fetch_weights.py
```

The workflow then calls `common.base_dir()` to record the exact resolved snapshot
path as `APASSY_CONTEXT_TOKENIZER_BASE` and in `base-identity.json`. It compares
`common.BASE_REPO` and `BASE_REVISION` with `manifest.json`, and hashes the weights
against its `base.weights_sha256`. The public base is
`convaiinnovations/laya@55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851`.
After fetch, `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` are set for later steps.
These flags prevent library downloads; they are not an OS network sandbox.

The inline unittest runner discovers only `tests/basemodel/test_context_tokens.py`
using `APASSY_CONTEXT_TOKENIZER_BASE`. It requires at least one executed test,
success, and zero skips. It then independently calls
`context_v1.measure(base, contract, fuzz=10000)` and requires exact equality of
the proposed and canonical `budget`, including header and segment measurements.
`token-report.json` records unittest counts, measurements and the contract hash.
No encoder training precedes this check.

```bash
"$PY" -B tools/basemodel/context_data.py --out "$EXP/synthetic" --groups 40 --seed 7
/usr/bin/time -v -o "$EXP/evidence/training-time.txt" \
  timeout --signal=TERM --kill-after=30s 1250s \
  "$PY" -B tools/basemodel/context_train.py \
  --data "$EXP/synthetic" --out "$EXP/probe" \
  --base-dir "$APASSY_CONTEXT_TOKENIZER_BASE" \
  --mode probe --limit 64 --epochs 1 --max-steps 4 --batch 1 \
  --threads 2 --seconds-per-head 600 --seed 7
```

G1 train/validation generation uses 40 training groups and the generator's minimum
10 validation groups; these are groups, not row counts. The trainer limits each
split to 64 rows, trains context and facts-blind control heads with at most four
steps each, and selects a threshold using validation only. The 600-second limit
is checked between training batches per head; it excludes setup and validation.
The external 1250-second timeout bounds the whole training invocation, including
validation and writes; the training step also has a 23-minute timeout. A slow CPU
may fail to finish. Partial checkpoints are diagnostic evidence only.

The training CLI returns **3 even on successful training-only completion**. The
workflow rejects every other exit, including timeout, and accepts 3 only if
`training_completed` is exactly true, mode is `probe`, outcome is `UNSUPPORTED`,
reason is `training_only_no_heldout_opened`, and freeze/report hashes match.
It requires nonempty context/control checkpoints and train/val files at the exact
expected paths with matching SHA-256, and checks the frozen configuration limits.
Errors caught by the CLI still yield 3 but lack completion evidence and fail CI.
Unexpected exceptions, absent reports and malformed freezes also fail.

No evaluator CLI is invoked and no `tests/evals` data, held-out generator or
held-out templates are opened. The trainer imports shared helpers from
`context_eval.py` for golden validation and validation-threshold selection only;
it does not call the held-out evaluation function.

## Evidence and limits

The explicit artifact allowlist includes the synthetic training report, freeze,
context/control checkpoints, data manifest, base identity, tokenizer report,
freeze verification, training exit, `/usr/bin/time -v` resource output and probe
costs. Costs contain elapsed time and directory sizes, not an estimated bill.
They identify both the source branch head and the tested SHA (the synthetic merge
commit for a pull request).
Step stdout/stderr remain in Actions logs without an owner environment dump.
The upload excludes synthetic row files, HF cache/base weights, venv and package
caches. Retention is seven days; resource collection and upload use `always()`
so failures retain whatever evidence exists. Missing files never imply completion.
Freeze paths are runner-local and cease to be usable after the job; the hashes
remain useful for audit. Artifacts are experimental and must not replace shipped heads.

Package availability, successful CPU installation, model runtime compatibility,
training completion, elapsed CPU/RAM costs and artifact delivery remain unmeasured
until CI runs. This probe provides no held-out quality, gate B acceptance,
same-device baseline latency, owner preference or production evidence.

## Source validation performed

`heavy-check actionlint .github/workflows/bouncer-context-experiment.yml` passed.
A lightweight Python/PyYAML source check through `heavy-check` parsed the YAML,
verified triggers, permissions, runner, timeout, concurrency and action pins against
`ci.yml`, ran `bash -n` on seven shell blocks, and parsed five inline Python blocks
with `ast.parse`. These checks did not execute those scripts or import model code.
No dependencies were installed, weights fetched, model tests/training run, or
Actions dispatched. Runtime evidence is still **not run**.
