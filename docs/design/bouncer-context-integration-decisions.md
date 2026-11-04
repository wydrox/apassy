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
