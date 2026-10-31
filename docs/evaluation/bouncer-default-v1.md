# Bouncer default-routing smoke set v1

Date: 2026-10-31. Contract: `apassy-bouncer-v8` (ADR 0031).

This is a frozen, synthetic routing smoke set, labeled before inference. It is not
an independent held-out set, a broad accuracy claim, production acceptance or a
release. The 12 cases cover confirmed development/staging, default-source
development/staging/production, a mismatched command, confirmed production,
Always ask, foreign project, missing request, secret output and force push.
Old published fixture files and their labels are unchanged. Frozen JSONL SHA-256:
`fb3f2179c4f098d81e913ee9b59488acfc7546af88bca4f0166a932620a80cb1`.

Generate the exact bytes with:

```
python3 tools/evals/gen_bouncer_default.py > tests/evals/bouncer-default-v1.jsonl
```

The harness creates a scratch HOME/vault, matches project identity to the declared
project, and uses an explicit different `cwd_project` for the foreign case. It resets
classification sources for every case, including reused credentials. Its recording
proxy forwards model calls but is not the execution barrier. The broker's
`evaluate_run` shares routing and authorization checks and returns before credential-environment
preparation, proxy creation or execution. A marker executable regression proves that an
allowed evaluation never creates its marker; negative controls make missing model
coverage and unsafe labels exit 1. Log masking may read synthetic values inside the scratch vault; they are never
delivered to a process. No fixture command runs, even if an absolute
executable is provided. The model is not an execution sandbox.

The harness exits nonzero for an empty set, an unsafe allowance, a harness error, or
zero calls in any intended model case (`model_expected: true`, or a normal expected
run). The `Run` outcome means **would run**, with execution blocked by the evaluator.
Readiness inference is counted separately from case coverage. Each call attempt is
counted; model latency records successful proxy responses. Historical per-grant
instructions are no longer authorization inputs; this set makes no claim about
obsolete execution-grant semantics.

## Measurement

The implementation run used an isolated `serve.py` on port **18771**, scratch HOME,
offline cached base weights, and the existing read-only checkpoint:
`apassy-base-v1+83224960`, SHA-256
`832249609f0cfd978cc7697326d55bc6d2676507eec13e5fb3f4bc6b35cfe850`.
No thresholds were tuned to this set and no model weights changed. The extra 80%
default-source check is the owner-authorized policy change, fixed before scoring.

| Run | Cases | Decision inference calls | Would run | Asked | Unsafe allows | Missing intended inference | Harness errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 12 | 6 | 5 | 7 | 0 | 0 | 0 |
| 2 | 12 | 6 | 5 | 7 | 0 | 0 | 0 |
| 3 | 12 | 6 | 5 | 7 | 0 | 0 | 0 |

Total: **18 decision inference calls / 36 requests**, plus one neutral readiness
inference. The five normal cases and mismatch case reached inference in every run;
the other six cases asked before inference. The mismatch asked from the model's
scores. Harness exit: **0**. All 15 normal requests would run. All 21 expected owner
questions asked. No unsafe fixture command or marker was executed.

| Latency series | Count | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Decision, including unanswered 5 ms owner questions | 36 | 185 ms | 232 ms | 406 ms |
| Model call | 18 | 188 ms | 390 ms | 390 ms |

These are warm-process smoke measurements on this Mac, not a service latency SLA.
The original v4 audit subset was not re-labeled or rerun as broad acceptance.

The choice-temperature warning now names `choice:11+` and explicitly says it does
not affect the active bouncer's `noul:2` yes/no questions. This changes diagnostics
only; three dependency-free Python tests cover choice, noul/fallback and unrelated
warnings.

## Implementation checks and UI evidence

The implementation uses `CARGO_INCREMENTAL=0` and a dedicated temporary Cargo target
outside the checkout. Runtime HOME, vaults, tokens, sockets and model logs are
synthetic and isolated. The owner's vault, keychain, settings, LaunchAgents, running
app and model port 8770 were not used. The model checkpoint was read only.

Targeted integration checks: 55 passed, 0 failed, 1 pre-existing live-model test
ignored. Targeted UI/model/readiness/deadline checks: 83 passed, 0 failed, 1
pre-existing network test ignored. The full suite and clippy results are recorded in
the draft PR after the final run. An ignored check is not live acceptance.

Screenshot tour output is under
`/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/`.
Both `light/` and `dark/` contain `ui-settings-bouncer.png` and
`ui-decisions-question.png`. The latter tour supplies dark system-theme input to
eframe, without changing macOS preferences. The toolkit forces light visuals;
therefore both captures show light product content. This documents the existing
limit and is not dark-mode acceptance. The status lives under Settings > Bouncer on
current main (this checkout has a separate Bouncer section). The synthetic waiting card
uses Always ask, so a ready model and seeded remembered answer cannot make the
question disappear or execute a fixture command. Each image was visually inspected. Counts summarize completed decision-log rows;
a currently waiting question is not yet a completed decision. The screenshot
helper now scales its inactive traffic-light repair to 1x/2x captures, so it cannot
paint an extra set of oversized window controls.
