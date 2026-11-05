# Parent integration decisions for the supervised A/B slice

Date: 2026-11-04. Base: `773f02c2`. Branch: `feat/bouncer-secret-context`.
Read together with [Opus supervision](bouncer-context-supervision.md).

1. The user authorized implementation under Opus supervision with multiple Sol workers. A separate model-validation workflow on the already used `ubuntu-24.04` runner type is ordinary validation within that authorization. It uses only public base weights and synthetic data, has bounded time/artifact retention, publishes nothing, and starts no paid devbox/service. No owner vault, profile, real endpoint or secret is used. No additional owner approval is inferred for devbox, deployment, activation or reading owner data.
2. Disk is below the 15 GiB floor. Local Rust builds and model training remain prohibited. Lightweight source checks and, if the shared gate permits, tokenizer-only checks using public cached assets are distinct from encoder training. Full validation goes to CI.
3. The unmeasured byte bound is intentionally not acceptance evidence: one representative unknown-facts suffix is 385 ASCII bytes, while the initial reserved room is 312. The parent must obtain exact header/segment measurements, review additivity, revise the canonical contract and regenerate pins/fixtures before claiming any supported context coverage or B PASS. Workers may implement fail-closed initial behavior; they must not weaken the bound or invent measured costs.
4. W4 may implement a tokenizer-only measurement command that writes a proposed measured contract to a caller-specified scratch path. It must not overwrite W1's contract. Contract revision is a sequential parent integration step after W1 finishes. Any updated hash must propagate to golden/wire fixtures and the model manifest; no model trained against an earlier hash is relabeled.
5. The parent also owns integration declarations in `tests/it.rs` for W1/W3 test modules, in addition to broker/vault module declarations. New integration test files otherwise would not run because `autotests=false`.
6. The training worker never reads the held-out dataset or its generator while authoring/training. The parent or a fresh evaluator opens it only after checkpoint, threshold and training configuration are frozen. The evaluator reports failure or unsupported honestly; no test-set tuning.

These are implementation coordination decisions, not a second Opus approval. The integrated changes return to a new Opus review before acceptance.

## Labeling clarification R1

The supervisor's positive rubric omitted the cold-start case that its own acceptance matrix requires. For the synthetic A/B experiment, `env=unknown` with `action=read` may be `allow_ok` only when it is a clean, established read serving the request, `local_rule=null`, and no other `must_ask` condition applies. This follows implementation plan v2 section 4. Missing declaration remains `env=unknown`, `env_from=none`, `scope=unknown`, `scope_from=none`; no development/read-only classification is fabricated. Unknown plus a state-changing or uncertain action remains `must_ask`.

This is a shared labeling correction for W1, W3 and W4, not an active policy or access change. Existing execution rules remain unchanged throughout A/B. Apply it symmetrically to training/validation and the independently authored held-out, without sharing their templates or contents.

## Token measurement R2

The parent ran a tokenizer-only check through heavy-check using the existing tokenizers runtime and public cached assets, without torch or model weights. The tokenizer SHA matches the contract. Exact pure functions from the installed pinned Laya source were executed via AST with a raw tokenizer adapter; the full Laya runtime must independently confirm these counts in the B harness.

Result: header_tokens=43; 99 segment entries; 10 000 deterministic random contexts; zero additivity mismatches and zero observed conservative-bound violations. Evidence: `docs/reviews/bouncer-context-token-budget-initial-2026-11-04.json`. This is NOT model quality evidence and does not unlock C/D/E.

To preserve one editor, the parent authorizes the still-running W1 editor to copy exactly `proposed_budget` from that evidence into its canonical contract, recalculate the contract hash and update only its owned pins/wire fixtures. This is the parent's measured contract revision, applied by the current editor. W2 has completed; the parent will regenerate its golden budget outcomes after W1 finishes. W4 must use the new hash and verify the tokenizer/header/segment properties in the full B environment before accepting them.

W1 had already completed when the steering message arrived. The parent read its final result, took over its files and applied R2 directly: header 43, 99 measured segments, new contract hash and wire pins, regenerated W2 budget outcomes. The serialized text did not change. Of 21 golden fixtures, 18 now fit, while NoSecrets, TooManySecrets and a long-request OverBudget remain explicit refusals.

## Review corrections R3

The parent accepts the source findings and implementation scope in
`docs/reviews/bouncer-context-ab-review-2026-11-04.md`. The parent approves the new
`context_route_replay` example stanza in Cargo.toml, with no dependency changes.
The next workers may repair data, training/evaluation and isolated replay in
disjoint files. The machine contract/hash, runtime and held-out files stay fixed.

The full report must separate `feasibility_quality` from `gate_b`. Quality PASS
alone never unlocks C/D/E. The baseline may pass through the proven model-free
lower bound; otherwise unavailable shipped heads produce the named
`baseline_shipped` UNSUPPORTED gate. Public stock heads cannot impersonate shipped
heads. No release publication, R2 access or new credential use is authorized by
this decision. Cost measurements may use equal-shaped public heads with explicit
provenance. Full training starts only after a bounded probe establishes that it
fits the reviewed CPU/time/cache budget.

R1 and HostFit/ProjectFit are pinned in the human contract without changing
serializer bytes. C must separately decide missing-agent scope evidence and
map evidence/storage failures to an owner question.

## Parent integration R4

The repaired G1 generator now produces coherent declaration states accepted by
the strict replay: a known environment has a known scope/source and sensitivity;
production is sensitive; absent declaration resets environment/scope/provenance,
sensitivity and project together. A generated-view regression checks both splits.

The evaluator masks every non-null local rule, including an empty string. Injection
and agent-use probes reject any ask-to-allow flip, including normal-label rows.
The held-out fact-label audit runs after freeze verification and overlap checks,
before constructing a scorer. An invalid dataset is UNSUPPORTED(label_audit).
The CPU workflow explicitly builds its replay with the existing Rust 1.97.0 pin.

CI passed all 16 checks for d543e4e. Its four-step-per-head CPU probe completed:
context training 4.345 seconds, control 4.087 seconds, 60 scored training rows per
arm. This used the old harness and provides no quality, baseline or cost gate.
Exact report and provenance are in the corresponding probe evidence JSON.

Manual entry is still a review item. GitHub's documentation requires a
workflow_dispatch file on the default branch:
https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow
The proposed patch below adds only an explicit off/probe/full manual input and a
reusable call to the existing registered CI file. It changes no existing job or
runner and is NOT applied or dispatched yet. Opus must review this concrete patch
with the repaired revision before the parent applies it.

## Supervisor recheck R5

Opus accepted the manual-entry patch and conditionally approved full start in
`docs/reviews/bouncer-context-ab-recheck-2026-11-04.md`. The parent applied exactly
that patch, with no other existing CI job or runner change. A manual run remains
limited to one probe and one full dispatch per commit, without a concurrent run
on the same ref. No dispatch has occurred.

Before the first held-out pass, one commit X must fix N2 (host facts and replay
coherence), N3 (held-out overlap scope), and N4 (allow-label audit), pass CI with
compiled parity executed, and have a measured eligible probe for 400–800 groups.
N3 keeps strict program disjointness inside G1 train/validation, while held-out
refuses shared families and identical request/command pairs only. Its program
overlap remains reported. N4 extends the positive-label audit without changing
the narrower textual-clause reporting predicate.

The optional budget repair approved by the reviewer must measure cached head
work separately from encoder work; it must preserve hard time/cache limits,
external probe provenance and the existing group-selection inequality. It may
not lower a bound merely to turn an unsupported projection into eligibility.

N2 now derives destination coverage from the finite G1 command catalog and checks
the invariant against the real Rust host extractor in CI. Unknown destinations
and foreign projects cannot receive positive G1 labels. Cost sampling excludes
only explicit OverBudget refusals, retains coverage counts for both arms, and
returns only fixed diagnostic codes from child processes.

The integrated local context suite reports 70 passed and four skipped: three
compiled-replay tests and the explicit full-tokenizer test. The experiment CI
requires all four to run without skips. Source approval of N2–N4 and the separate
cached-head budget calibration remains pending the limited Opus re-read; these
local results do not measure feasibility quality or gate B.

## Supervisor calibration decision R6

The limited source review closed N2–N4 and accepted the cost/budget repairs in
`docs/reviews/bouncer-context-n2-budget-review-2026-11-04.md`. Hosted probe
41852508456 on head `1b9cbd98` passed compiled replay/G1-host tests and the full
tokenizer without skips, then returned `UNSUPPORTED(cached timing wall limit)`
before training. Its checkout was the PR merge commit; the evidence JSON records
both identities. No freeze, cost benchmark or held-out result was produced.

Opus accepted one changed calibration method in
`docs/reviews/bouncer-context-calibration-method-review-2026-11-04.md`: batch-eight
timings scaled by four, guarded by real batch-32 spot checks. The report identifies
raw measurements and estimates separately. A spot exceeding 1.3 times its scaled
estimate refuses eligibility. The shared 120-second limit includes restoration;
partial diagnostics cannot supply a projection. All four workflow validators also
enforce the 5400-second per-head estimate alongside the existing total budget.

W8 permits one real probe on the final new revision. Any outcome other than
ELIGIBLE ends this experimental path with B UNSUPPORTED, without another attempt
or method change to obtain eligibility. Quality, baseline, cost and the further
review before C remain separate gates.

Opus accepted `docs/reviews/bouncer-context-single-probe-entry-proposal.patch` in
`docs/reviews/bouncer-context-single-probe-entry-review-2026-11-04.md`. The parent
applied it and both small conditions in the same revision: an explicit eligibility
summary and documentation of the single full-mode dispatch. The existing `ci.yml`
bridge is unchanged. PRs run only compiled/tokenizer preflight; after green CI on
the final revision, one manual pipeline runs the probe and starts training only
after the whole probe job succeeds with nonempty eligible groups. Any other
outcome ends this path without a retry. No manual dispatch has occurred.

## Owner-approved Intel validation fallback R7

After repeated GitHub-hosted ARM runner capacity cancellations, the owner approved
the prepared two-job fallback on 2026-11-04. `extension` and `macos` select
`macos-15-intel` when repository variable `APASSY_MACOS_INTEL_FALLBACK` is exactly
`true`; otherwise they retain `macos-15`. The variable was enabled and read back as
`true`. This is an explicit switch, not an automatic retry of failed tests.

The contextual experiment still uses the reviewed Ubuntu runner and resource
limits. The owner approval changes only these two validation jobs. The final
revision must pass CI before its single manual full-mode pipeline; no actual
new-method probe has been consumed. Intel runtime validation remains pending CI.

## CI reliability repairs R8

The Intel extension job reached the browser tests and failed on two initial
Helium navigations with `ERR_ABORTED`. Those navigations now use the existing
bounded transport helper. WebAuthn actions, assertions and the cancellation-test
navigation remain unchanged. The three helper unit checks passed locally.

The relay failed its synchronous tailnet-listener stop assertion in both nextest
attempts. The vendored HTTP server now owns and joins its accept thread before
drop returns. Nonblocking accept and a 10 ms idle park remove dependence on a
connect-to-self wakeup. The admission latency and roughly 100 idle wakeups per
second per listener are recorded in the patch notes. Deadline-free responses and
guarded-connection shutdown are documented separately.

Opus accepted these changes in
`docs/reviews/bouncer-context-ci-reliability-review-2026-11-04.md`; the parent
applied its small documentation corrections. The original tailnet assertion is
unchanged. Three additional vendored shutdown behavior tests run in relay slice 1.
Cargo package selection, formatting, workflow syntax and whitespace were checked;
Rust compilation and runtime tests still require CI. Browser E2E uses the existing
macOS Helium harness on the approved Intel fallback; no Ubuntu browser result is
claimed. These repairs do not establish gate B or unlock C/D/E.

## Delivery review and dormant adapter R9

Draft CI on `a6d0fee1ec87de3bb9560d68d3193610439c7845` passed all 20 checks.
The subsequent single W8 pipeline, run `41874913253` on that exact revision,
completed calibration but returned `UNSUPPORTED(budget)` with no eligible group.
Full training and held-out evaluation were skipped. Three ordinary ARM macOS
jobs in that manual run were cancelled for runner capacity; the approved Intel
jobs passed. W8 is consumed and will not be repeated or adjusted for eligibility.
The small evidence JSON files are retained outside the checkout at
`/Users/rafalw/Dev/apassy-bouncer-context-evidence/41874913253/`.

Opus reviewed the delivery gap in
`docs/reviews/bouncer-context-delivery-plan-review-2026-11-04.md`. The parent
corrected the audit's obsolete quality thresholds and its overly literal reading
of the full-record requirement. The local builder reads metadata and history;
the brain receives the existing closed projection without secret values or free
metadata text. The review's shorter C/D path remains a proposal for later review.

The only newly accepted implementation package is a dormant run-to-context
adapter, with no call-site in the decision path. Sol-1 owns the new
`src/broker/context_adapter.rs`, its module declaration, and only the visibility
change of `run::host_matches` to `pub(super)`. Sol-2 owns the new synthetic
`tests/context_adapter.rs`; the parent registers it in `tests/it.rs`. These are
the five code paths allowed by review §4. This decision record, corrected audit
and review are supporting documentation, not extra runtime changes.

The adapter consumes the already sanitized request, preserves request item
order, computes per-item project/host fit, reads metadata-only evidence, and
returns either a complete ContextInput or a closed ContextAsk reason. No new
feature flag, server route, schema, shadow or production invocation is included.
Golden parity, synthetic canaries, fit boundaries and all refusal variants must
run in draft CI on the new exact SHA, followed by a short Opus diff review.
Local Rust compilation is not part of this package.

B remains UNSUPPORTED and C/D/E are not unlocked. A new B2 experiment needs a
concrete executor, verified cost and resource limits, explicit owner approval
including one read of shipped heads from R2, and supervision before any compute.
No such experiment, secret access, runner change or publication is authorized
by this adapter package.

## Existing trainer reuse R10

The owner challenged preparing a separate GPU trainer. The parent stopped the
new B2 infrastructure expansion, cancelled its unfinished trainer worker and did
not start the executor. Five uncommitted preparation files were preserved at
`/Users/rafalw/Dev/apassy-bouncer-context-evidence/parked-b2-jldxup7q/`, with a
receipt and tracked diff, then removed from the active checkout. None was pushed.
No model run, paid resource, R2 read or external upload occurred. The Modal/B2
preparation proposal is not the active implementation path.

The bounded replacement is input conversion for the existing `train.py`, which
already supports MPS and CUDA. `context_train_rows.py` exports synthetic G1 rows
through the existing serializer into that trainer's state/instructions/answer
format. The trainer change only appends `owner_accepts_use` to its question
catalog; its loop, optimizer, device handling and defaults are unchanged.

Conversion validates source hashes, strict G1 rows and disjoint splits, preserves
source datasets, and records separate context/control selection and refusal
counts. It rejects held-out/H1 paths before opening them, never truncates input,
and refuses an empty trainable split. Output provenance describes input data;
it is not a model freeze. Complete context checkpoint metadata and freeze
compatibility still need acceptance before any model execution. All quality,
baseline and cost gates remain; B is UNSUPPORTED and production is unchanged.

## Existing trainer checkpoint preparation R11

The data-only package on `009e7999d976a63a45ac65c7c3cfc270ff49b7fe` passed draft
CI and received Opus ACCEPT. The next source-only preparation follows
`existing-trainer-data-review-2026-11-04.md`, retained outside the checkout with
the CI receipt. That acceptance did not authorize model execution.

The existing trainer accepts an explicitly pinned local base directory and
additional checkpoint metadata, refusing collisions with its own fields before
training. Its default learning loop, optimizer and device behavior are preserved.
The contextual caller requests `apassy-context-v1` names and strict device
selection; an unavailable selected MPS device refuses instead of falling back to
CPU. Training with explicit metadata installs the held-out read guard in the
child process as well as the parent.

`context_existing_freeze.py` validates original G1 hashes, labels and class
coverage, exports each arm, and checks exact token/occurrence selection before
calling the existing trainer. Each arm has its existing 5400-second subprocess
limit and a fresh cache cleaned on success or failure. Saved checkpoints and
reports are checked before thresholds are fitted on validation using a fresh
CPU scorer. The freeze retains original G1 paths and conversion/report hashes.
The converter and integration module are included in source identity. The
control arm follows the evaluator's exact-token policy, with no truncation.

Freeze verification checks every artifact path before any artifact read, then
recomputes the conversion and trainer-report evidence before held-out IO. Tests
use synthetic data and fake runtimes; import guards run in isolated child
processes so they do not alter unrelated test modules.

This is preparation for a distinct, subsequently approved training run. It
neither repeats W8 nor supplies its eligibility result. Resources, compatible
training/evaluation packages, supervision, quality, baseline and CPU cost
evidence remain required. No model, held-out evaluation, paid service, R2 read,
runtime activation or release was performed by this package.

## Existing trainer on Modal R12

The owner requested Modal to shorten training. The active preparation path runs
the existing `context_existing_freeze.run(device='cuda')` and `train.py` on one
L4, followed by one hosted Ubuntu CPU evaluation. It does not restore the parked
B2 trainer or repeat the consumed W8 probe. The training loop, quality gates,
baseline and CPU cost comparison remain unchanged.

The source upload contains only an explicit git-verified inventory at commit S,
including all 21 serializer goldens. It excludes `.git`, held-out data and private
weights. A gitless worker receives S explicitly; a checkout with git must match S.
The deterministic nine-file plain-tar result binds the upload inventory, G1
groups=400/seed=7, checkpoint reports and freeze. The evaluator checks the bundle,
external freeze hash and its own checkout before reading held-out data.

The proposed attempt has one L4 with no fallback, four CPU cores and 32 GiB RAM.
The whole remote attempt, including image build and export, is bounded at four
hours; image build has a 30-minute sublimit and the caller has a 4h15 cleanup
cutoff. A persistent marker refuses a repeated attempt. The proposed total Modal
envelope is USD 8; this is not an account-level billing cap or a GitHub Actions
cost quote. No paid execution has been approved by this preparation package.

Before allocation: narrow source review, green CI on S, the hosted CUDA-package
preflight, and a draft-asset transport preflight must succeed. The owner's run
approval must cover those dispatches, draft uploads and the paid attempt. Any
requested private baseline URL is confined to the hosted evaluator and checked
against the shipped SHA before held-out reads. Training, transport, CPU cost,
quality and runtime activation remain unmeasured until their actual runs.
