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
