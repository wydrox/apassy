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
GPU, preferring A10 with optional L4 at scheduling, followed by one hosted Ubuntu
CPU evaluation. It does not restore the parked
B2 trainer or repeat the consumed W8 probe. The training loop, quality gates,
baseline and CPU cost comparison remain unchanged.

The source upload contains only an explicit git-verified inventory at commit S,
including all 21 serializer goldens. It excludes `.git`, held-out data and private
weights. A gitless worker receives S explicitly; a checkout with git must match S.
The deterministic nine-file plain-tar result binds the upload inventory, G1
groups=400/seed=7, checkpoint reports and freeze. The evaluator checks the bundle,
external freeze hash and its own checkout before reading held-out data.

The proposed attempt requests `gpu=['A10', 'L4']` in that order, with one GPU,
four CPU cores and 32 GiB RAM. Modal's [ordered GPU fallbacks](https://modal.com/docs/guide/gpu#gpu-fallbacks)
select the resource before training starts; there is one spawn, `retries=0` and
`max_containers=1`. There is no training retry after OOM, error or preemption.
Worker and bundle validation accept only the exact device names `NVIDIA A10`,
`NVIDIA A10G` and `NVIDIA L4`, preserving the actual name in the receipt. A10
availability and performance have not been measured; no shorter allocation or
training time is established.
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

## Independent held-out validation R13

R12 ended with `UNSUPPORTED(label_audit)` on hosted run 42100538530. Its H1
rows were loaded, but no candidate scores were computed. H1 is consumed and
stays unchanged. The row, clause and count behind the audit failure are unknown.
The auditor agrees with the visible-facts contract; its exclusions stay fixed.

Root interprets the owner's instruction to train and test the bouncer as covering
preparation and one CPU-only evaluation on an independent H2 set. The presented
approval asked about one A10/L4 attempt and its USD 8 cost; the subsequent owner
instruction did not restrict independent CPU test data. This is a protocol
decision under that request, not a new owner instruction or payment approval.
The one paid training attempt remains consumed. No new GPU, Modal allocation,
budget, threshold, head training, activation, merge or release is part of R13.

The candidate remains the original bundle and freeze from training source
`7a63ffad557ace5e396c4a709ad8453fb611b565`. Its weights, thresholds, training
reports and data are immutable. H2 uses that source's unchanged evaluator and
the same quality, shipped-baseline and CPU cost gates. The facts gate uses the
current implementation's AUROC and normal-rate deltas of at least 0.15; the
older supervision table's control-ordering delta is superseded.

Before H2 exists, a worker who never sees it implements a candidate-free
preflight. A fresh author may read only the public context contract, R1 and a
fixed author brief. The author must not read H1, G1 templates/data, experiment
reviews, checkpoints, freezes, model scores or baseline ask rates. A separate
read-only judge checks command/request alignment with labels and relationship
annotations removed. Independence is procedural in a shared checkout; all
examples are synthetic and make no claim about production preferences.

H2 has at most 1000 rows and families `H1:h2-*`, as required by the frozen
reader. Its manifest has a top-level lowercase SHA-256 and no `file` key. Target
populations are at least 340 allow rows, 60 per mandatory class, 340 risky rows
with at least 300 fitting rows, 110 deterministic rows, 170 counterfactual pairs
and 120 injection variants. Each mandatory class has at least 30 risky rows;
allow fit is at least 70 percent per class. At least 40 allow rows use an explicit
HTTPS `.example.test` host. Text stays natural rather than being shortened to
fit the budget.

Necessary class conditions use visible facts: every cold-start secret has
`env_from=none`, and every multi-secret row has at least two secrets. Positive
known-history rows have a positive owner-allow bucket; positive changed/rotated
rows have a `secret_changed` or `access_changed` bucket within 30 days; positive
repeat rows have `agent_used=yes`. These conditions qualify the synthetic
populations without claiming that they fully define a representative class.

Preflight checks schema, provenance and host coherence, the unchanged positive
label exclusions, local-rule/label consistency, pair and injection structure,
populations and budget arithmetic, blinded-context fit, and disjointness from
the exact original G1 generation. Compiled replay checks must run without skips
in CI. Fake label-derived scores may test gate structure only: their results
must never be emitted as model quality or a Gate B verdict. Preflight and judge
feedback to the author contains only check names, counts and at most 50 H2 IDs.
Two unsuccessful repair rounds return to supervisor review before further work.

After preflight and judging pass, the author commits H2 and its generator and
manifest. Root records the byte hash and commit before dispatch and does not
read H2 rows. No bytes change after the seal. The hosted workflow copies and
hash-checks sealed H2 outside the checkout, then switches to immutable training
source. Separate binding evidence records the workflow and training commits,
H2 seal and original bundle/freeze hashes. No source pin is bypassed or rewritten.

One hosted Ubuntu CPU evaluation follows green CI and supervisor review. Only
the evaluate step may use 240 minutes; the outer job stays bounded at 300
minutes. CPU cost is freshly measured. Temporary read URLs are restricted to
the original draft assets; owned transport secrets are deleted after download.
The report preserves the evaluator's measured FAIL and UNSUPPORTED outcomes.

Once the evaluator loads any H2 row, H2 is consumed regardless of outcome,
including audit failure, timeout or missing evidence. There is no automatic
repeat, H2 repair, H3, retraining or threshold adjustment after that point. A
failure before row loading stops for supervisor review; at most one retry may
be considered with unchanged H2 bytes. Any further training or evaluation needs
a new owner decision. A synthetic Gate B PASS permits only supervisor review
before C; it is not activation or a production-quality claim.


## R14 — one-shot H3 preparation after H2 closure (2026-11-06)

This is a protocol decision under the owner's active instruction to train and test the bouncer. It is not a new owner instruction. H2 is CLOSED, unsealed and unconsumed; data preparation is BLOCKED and independent model-quality evidence is UNSUPPORTED. The trained candidate has neither a PASS nor a FAIL and production is unchanged. H2 receives no further repair, probe, author feedback or evaluation.

The review `h2-closure-h3-one-shot-plan-review.md` accepts one independent H3 attempt through seal review, with C1–C10. Candidate scoring requires a separate reviewed execution package. No further training, paid service, activation, merge or release is authorized here.

H3 lives only in `tests/evals/secret-context-heldout-v3/` to exclude it from development-data globs. A fresh author sees only the public contract, R1, a data-only brief and owned files. One handover; an existing no-binary self-check is allowed before it. CI hashes but never executes the author's generator. There is no author feedback or repair after handover.

The raw recipe is 1000 rows: 430 allow, 460 must-ask and 110 deterministic, with 230 base pairs, 180 injection twins, 90 sole-delete-history-clause rows and 50 textual-only rows. Delete quota breadth is at least 15 programs and at most 12 rows per program. Raw risky-fit is at least 420, known-HTTPS allow at least 70 and allow-fit at least 80 percent per class. The reviewed data-only brief must state host coherence and give no reason for quotas. Per class, in the order cold start, known with history, changed or rotated, repeat, multi secret, these 90 and 50 rows split 0/28, 23/5, 23/5, 22/6 and 22/6, because a row with no declaration has unknown environment and a delete there always carries the environment clause too. Pairs stay within a class and at least 29 non-read pairs use an absent declaration. This corrected a specification defect in review, before any raw data existed. No total, floor or gate changed. Scored cold-start rows are read-only as a result, and the report states this limit.

A distinct worker implements `route.py`, using the actual replay pinned to training source `7a63ffad557ace5e396c4a709ad8453fb611b565`. One CI run routes raw data without a candidate or tokenizer. Nonempty flags make a non-deterministic row deterministic under `HookFlags`; prior deterministic rules stay. Only label, local_rule and affected pair/injection references may change; texts, facts, actions, IDs and row count remain. Unknown codes, malformed evidence, source drift or a batch refusal stop the attempt. Remaining pre-model asks must arise only from missing declaration. Reports separate today's reachability from reachability under proposed context activation.

Floors apply after routing on model-reachable, budget-fitting rows. Existing preflight floors remain unchanged. Each of the six clauses needs at least 25 such rows, and at least 25 rows must carry only the delete-history clause. These evidence-strength floors are reviewer decisions, not owner rules or new learned-model gates. No floor is lowered after an outcome.

The parent verifies and commits the routed artifact bytes. The next CI run only recomputes and byte-compares them with `--check`, then repeats preflight. This is verification, not a second routing decision. All route/preflight source freezes before raw hashes are recorded. Implementation fixes are allowed before that point only.

Fresh judges see scored text/action views with neutral shuffled IDs, without secret facts, labels, classes, relations, flags, reviews or prior datasets. A fixed script joins closed judgments to labels. One fresh adjudicator resolves used uncertain fields; a confirmed defect or incomplete judgment is terminal. The judge is the only check of action honesty, and independence remains procedural.

Any author BLOCKED reply, post-handover defect, invariant/floor/preflight failure, byte mismatch or boundary breach ends H3 as UNSUPPORTED without repair, H4 or candidate failure. The parent records a closed `TERMINAL.json` marker; CI skips a terminal attempt and future execution refuses it. Infrastructure with no report, or rule-pack failure reproduced on a known synthetic case, stops for one review with unchanged bytes.

A future execution package will use fresh CPU cost evidence on the locked candidate and G1 validation inputs, then verify capacity before the evaluator reads any H3 row. No reuse departure from R13 is selected here. It must include the shipped baseline, immutable training-source evaluator, one scoring pass, 240-minute evaluation and 300-minute job envelope, and bounded JSON evidence. Any genuinely new cost returns to the owner. No model execution is authorized by this record.
## R15 — goal50 development recipe (2026-11-06)

The owner requested continued work until at least 50 percent of correct uses are
automatically allowed. D0's measured 3/85 unpaired and 0/91 paired correct uses
remain negative development evidence. They do not establish independent quality.
The existing production normal gate of 60 percent and all safety gates remain
unchanged. Activation, merge and release are separate owner decisions.

The next prepared recipe is explicitly `context-v1-e20`: the existing `train.py`
and frozen encoder, 20 epochs, both context and blind arms, batch 32, FP32/noAMP,
lr 3e-4, wd 0.01, warmup 100, seed 7, 4 threads, no init/LoRA/teacher/limit/max-steps,
and 5400 seconds per head. More epochs also changes the cosine schedule. This is
a training-length/schedule hypothesis, not an established cause or fix. Legacy
`CONFIG`, default four-epoch behavior and historical source-bound freezes retain
their own identities. Checkpoint choice remains minimum validation NLL.

The new recipe binds the same G1 groups 400/seed 7 source hashes and the original
D0 sample SHA-256 `864ea9c6f39c3c2cc910aa5fa1af2bc0e0f3ce78279b2fc4d8f5c74f8cc8dce4`
before training. No data, label, feature, loss or threshold policy is changed.
After loading the chosen checkpoint, the existing full-validation CPU scoring
pass fits the threshold. The same aligned probabilities supply aggregate-only
development evidence; no extra encoder/scoring pass is added. Every original
normal row is accounted for, and contractual exclusions and unavailable scores
remain explicit. The saved reading contains no row IDs, text or individual scores.

Development progress requires both at least 43 of 85 unpaired and 46 of 91 paired
correct uses on that pinned sample, with complete coverage. Its only positive
reading is `DEV_50_NOT_RULED_OUT`, alongside the unchanged D0 references of 60 percent
normal permission and 90 percent pair ordering. The sample has already been read
once for D0; this candidate is read attempt 2, including the historical miss.
Calibration zeros are not independent safety evidence. Independent confirmation
and all existing safety gates are still required before claiming goal completion;
no new held-out corpus or independent execution is authorized by this record.

The U1 source-only input check found that selected context labels use only the
visible request/action/facts; non-null local rules are excluded before conversion.
It establishes no neural learnability or label correctness. Per-epoch empirical
operating-point diagnostics are observational and do not choose the checkpoint.

The prepared resource envelope is one opt-in A10/L4 attempt in workspace
`rodzina260622`, environment `main`, 4 CPU cores/32 GiB, no retry, global remote limit
120 minutes including image build <= 30 minutes and 15 minutes export reserve, and an
independent 135-minute caller cutoff. The previous one-USD8 training is consumed.
This record grants no new spending: a concrete new USD 8 owner decision follows
source review and green exact-source CI. It is an authorization envelope, not a
provider-enforced spend cap or a billing measurement. Legacy launcher limits
remain unchanged. Existing app/volume cleanup and persistent run markers apply.

Read the D1 outcome in this order. These branch cutoffs are reviewer choices,
fixed before scoring; they are not quality gates or a diagnosis proven by D0.

| Result | Reading | Next step (each paid step is a new owner question) |
| --- | --- | --- |
| Both pass points met | `DEV_50_NOT_RULED_OUT` | Owner decision on an independent-evidence mandate |
| Miss; best epoch ≥16 and final train loss >0.42 | Still limited by optimization or representation | Source review of schedule and representation; no automatic retry |
| Miss; best epoch <16 and best val NLL exceeds final train loss by ≥0.10 | Longer training falsified; failure to generalize | Features or data for unseen families, not more epochs |
| Miss; train and val NLL both ≤0.42 | Ranking tail | Audit the top must-ask population by class, in aggregate; τ stays unchanged |
| Anything else | Unclassified | Report as is; no narrative fit |

Zero-shot NLL should reproduce context 1.1431 and control 1.1348 within 0.001
(a reviewer tolerance). A miss means the run is not a pure training-length trial:
explicit encoder eval mode may differ from the historical constructor state.
Full validation should show context `allow_ok` with 377 original rows, 372 eligible
scorer rows and 5 `OverBudget` refusals; control should have 377 original and 377
eligible. These are pre-registered sanity checks, not new safety evidence.
After this recipe's one completed sample reading, another candidate needs a new
recipe identity and updated sample-read accounting. The run marker enforces
uniqueness per run ID; the operator ledger enforces this recipe's single attempt.

## R16 — fixed denial-balanced training view (2026-11-06)

E20 ended `DEV_50_MISS`: 62/85 unpaired and 7/91 paired normal uses, 151/377
original normal validation rows. This is development evidence; independent
quality is UNKNOWN. A training-only count found last-secret `owner_denied=unknown`
in 343 positives and no negatives. This is a shortcut opportunity, not proof that
the head uses it. Both paid attempts and their one-launcher disk exceptions are
consumed; this record authorizes unpaid source preparation only.

The next opt-in recipe is `context-v1-e20-denial-invariance-v1`, policy
`denial-balanced-v1`. It uses a fixed replacement before conversion, not dynamic
views. Deep-copy original training rows; among rows with no local rule and final
`owner_denied` in `('0','unknown')`, group by label, action, class and original
denial value, sort by SHA-256 of canonical original rows, and assign alternating
`0`/`unknown` by rank. Preserve row order, every other field, input objects and
labels. Refuse any changed rubric result. Denial 1/2-4/5+ and earlier secrets stay.

Only the training export and its provenance change. Validation, calibration,
the D0 sample and all original G1 bytes/hashes remain unchanged. The converter
refuses any difference in selected, local-rule or OverBudget counts. Control
training text and both validation exports remain byte-identical. Record the
view policy/counts and distinct training-state count in conversion provenance;
no IDs, labels or view fields are added to model text or emitted legacy rows.

The existing trainer and scoring code stay unchanged: 20 epochs, original slot
and optimizer-step counts, BCE, E20 schedule, seed 7, batch 32, frozen encoder and
minimum-validation-NLL checkpoint. The exact preflight sees the training view;
all scoring and threshold paths see original validation rows. A tokenizer-only
hosted check must confirm equal original/view token counts and the 512-token
limit for every selected view. The 6 GiB feature-cache cap and cleanup stay.

Bind the new recipe and policy in the exact config, conversion hashes and
checkpoint identity. Legacy and E20 behavior keep their own identities. The
next completed D0 sample reading is candidate attempt 3, with the same sample
SHA-256 `864ea9c6f39c3c2cc910aa5fa1af2bc0e0f3ce78279b2fc4d8f5c74f8cc8dce4`.
Use the best-NLL checkpoint and unchanged full-validation threshold fit. Both
43/85 unpaired and 46/91 paired normal permissions are required for
`DEV_50_NOT_RULED_OUT`; otherwise report `DEV_50_MISS` or incomplete coverage.
Report the full original-normal denominator, without a pooled/per-class rescue.
A miss rejects this fixed intervention as sufficient, not all coverage ideas.
No automatic retry or threshold adjustment follows. Production normal 60 percent
and all safety gates remain unchanged; independent confirmation is still needed.

Report zero-shot NLL 1.1431 and control threshold 0.55096 as sanity comparisons,
never gates or independent evidence. Runtime reachability of the synthetic
views remains unmeasured. Limits stay one A10/L4, 4 CPU/32 GiB, 120 minutes remote,
135 minutes caller, 38 upload paths, 9 plain-USTAR members and 256 MiB output. A new
owner resource decision follows source review and green exact-source CI. No
model run, held-out effort, activation, merge or release is approved here.

## R17 — explicit deterministic runtime preparation (2026-11-06)

R16's one approved trial ended `DEV_50_MISS`: 0/85 unpaired, 0/91 paired,
and 7/377 original normal validation rows. The model and artifact checks passed.
Independent quality and safety remain UNKNOWN; B remains UNSUPPORTED and
production is unchanged. Its resource approval and launcher exception are
consumed. No fourth training or new held-out attempt is authorized.

The unchanged control's recorded trajectory also differed between trials.
Source inspection found no demonstrated training/scoring bug and no explicit
fail-closed deterministic startup profile. This is a reproducibility prerequisite
gap, not a proven explanation of the quality result or a causal policy effect.

Prepare only an opt-in `--runtime-profile cuda-deterministic-v1` in the existing
generic trainer. No current context recipe or workflow passes that option. With
the option absent, retain the existing training, data, loss, schedule, checkpoint
selection, threshold and report behavior. Reserve the trainer-owned metadata key
`runtime_profile` against caller assertions.

The explicit profile must refuse an unknown profile, unsupported device/runtime,
AMP, an already initialized CUDA context, or conflicting startup environment.
Require a process-start `PYTHONHASHSEED` matching the seed. Establish the cuBLAS
workspace and IEEE FP32 settings before CUDA initialization; enable deterministic
algorithms with errors rather than warnings, disable cuDNN benchmarking, and seed
the relevant RNGs before Agent construction. Use the pinned PyTorch 2.14 APIs
without mixing old and new precision controls.

Read back the effective settings after model initialization and before saving
checkpoints or the final report. Refuse drift. Bind the profile, seed, software
and device identity, effective settings and the initial trained-head tensor hash
in the checkpoint metadata and report. Emit no tensor values or row data.

Synthetic tests must cover startup ordering, unsupported/conflicting settings,
ineffective setters, drift, metadata collisions, stable initial-head hashing,
and unchanged default behavior. Hosted source CI is required; fake tests do not
prove CUDA execution or repeated-run equality. This profile does not promise
bitwise equality across hardware or software versions, or any quality gain.

References: [PyTorch 2.14 reproducibility](https://docs.pytorch.org/docs/2.14/notes/randomness.html)
and [CUDA precision controls](https://docs.pytorch.org/docs/2.14/notes/cuda.html).
This record permits unpaid source preparation only. A future training candidate
still needs its own recipe, reading rule, runtime validation and resource decision.
