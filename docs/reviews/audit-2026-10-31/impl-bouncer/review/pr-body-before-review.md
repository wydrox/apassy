The owner decided **"Decide by default"** on 2026-10-31. A ready bouncer now evaluates each process request after the hard checks, including first use and credentials with default classification. A model allow permits only that run and creates no grant, remembered answer, evaluation scope or classification confirmation. This implements ADR 0031 and supersedes ADR 0029's routing requirement; ADR 0029 remains the historical record. Schema stays at 20.

| Routing gate | Before | After |
| --- | --- | --- |
| Unconfirmed/default production | First use asked before inference | Fresh model decision; task match must be at least 80%, including safe commands/reads |
| Environment or risk from a default source | Asked before inference | Same stricter model treatment; high-risk/irreversible declarations retain their sensitive write check |
| Missing evaluation scope outside confirmed dev/local low risk | Asked before inference | No evaluation setup required; evaluate this run |
| Stored scope does not fit | Asked to review scope | Stored scope has no routing effect; current request is evaluated again |
| Foreign-project declaration | A fitting evaluation scope could bypass it | Asks unless a fitting explicit owner execution answer covers the project |
| Confirmed production without a fitting allowance; Always ask; Never/access restrictions; analysis flags; foreign DB hosts | Ask/refuse | Preserved |
| Not ready/Off; root/HOME; unfit owner answer; missing user request/declaration | Ask with the exact reason | Preserved |
| Explicit owner execution answers and owner-taught patterns | Their existing execution semantics | Preserved; a model allowance never creates either |
| Credential/access/script changes during inference | Invalidate the decision | Preserved for authorization and supported command bindings |

Decisions hides the obsolete evaluation offer. The broker no longer creates offers. Stored scopes and authenticated compatibility APIs remain; the credential page labels stored scopes as legacy data with no routing effect. No migration or model retraining is involved. The model input has no structured classification-source fields, so the broker applies the extra 80% task-match requirement locally; calibration cannot lower it. Shadow decisions use the same treatment.

Settings > Bouncer shows successful inference readiness and today's UTC model allowances, owner questions and failures, using completed decision-log rows. Failure means unavailable inference/readiness or an unanswered/invalidated question and can overlap asked. The temperature warning now names `choice:11+` and states that it does not affect the bouncer's `noul:2` yes/no questions. No existing model thresholds or checkpoint weights were tuned.

The stale harness now uses a non-executing broker entry point that shares routing and authorization checks and stops before credential-environment preparation, proxy startup or process creation. This mode has no wire action. The recording proxy is only measurement. Scratch project identity matches declarations, deliberate foreign projects stay explicit, and declaration sources reset between cases. Log masking can read synthetic vault values; none are delivered to a fixture process. Missing intended inference, unsafe allowances, empty input and harness errors exit nonzero. Marker and negative-control regressions prove the barrier and failure exits. Historical published fixtures/labels stay unchanged.

| Frozen smoke evaluation | Result |
| --- | --- |
| Cases and runs | 12 cases × 3 runs = 36 requests |
| Decision inference coverage | **18 model calls**, 6 per run; zero intended cases missed; one additional neutral readiness call |
| Outcomes | 15 would-run, 21 ask; zero unsafe allowances, zero harness errors; exit 0 |
| Model-derived uncertainty | Mismatch reaches inference and asks in all three runs |
| Model latency | p50 188 ms, p95/max 390 ms |
| End-to-end decision latency | p50 185 ms, p95 232 ms, max 406 ms (5 ms synthetic approval timeout) |
| Model | `apassy-base-v1+83224960`; checkpoint SHA-256 unchanged before/after |

This is bounded synthetic routing evidence, not a broad held-out model-acceptance or production claim. The isolated model ran on **18771**, using the existing venv/checkpoint read-only and offline cached base weights. All runtime data used scratch HOME. The owner's vault, keychain, app, settings, LaunchAgents and port 8770 were not used.

Validation:

- Full `cargo test --offline --locked --all-features --all-targets -- --test-threads=1`: PASS — **1,927 passed, 0 failed, 19 pre-existing manual/network checks ignored** (1,138 library, 780 integration, 9 binary tests).
- `cargo clippy --offline --locked --all-features --all-targets -j 2 -- -D warnings`: PASS.
- Doc tests with all features: 6 passed.
- Targeted integration: 55 passed, 1 pre-existing live-model test ignored. Targeted UI/model/readiness/deadline checks: 83 passed, 1 pre-existing network test ignored.
- Temperature diagnostic Python tests: 3 passed. Node walkthrough: 33 passed. Python isolation fixture: 9 passed.
- `cargo fmt --all -- --check`, `git diff --check`, `bash -n scripts/screenshots.sh`, frozen generator byte comparison: PASS.
- Exception tests create questions from an unavailable model rather than the retired staging gate. The isolation launcher test copies the executable into a synthetic `target/debug` layout, so it checks the existing source-build contract independently of the required custom Cargo target directory. Product isolation behavior is unchanged.
- The isolated model and screenshot processes were stopped; checkpoint hash is unchanged. `/Users/rafalw/Dev/.target-bouncer` and the scratch runtime directory were deleted after saving these receipts.

Screenshots (all four visually inspected):

- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/light/ui-settings-bouncer.png`
- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/light/ui-decisions-question.png`
- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/dark/ui-settings-bouncer.png`
- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/dark/ui-decisions-question.png`

Limits/deviations: current main places this section under **Settings > Bouncer**, so no navigation rename was introduced. The toolkit explicitly forces light appearance. The dark tour supplies dark system-theme input without changing macOS preferences; its product content remains light, and it is not dark-mode acceptance. Counters cover completed UTC decision-log rows, so a currently waiting question is not counted until it settles. The screenshot tour now supports a bounded custom tour, keeps the waiting card deterministic, and handles 1x/2x window-control capture scaling.

Source evidence: [ADR 0031](https://github.com/wydrox/apassy/blob/fix/bouncer-default-on/docs/adr/0031-bouncer-decides-by-default.md) and [frozen evaluation report](https://github.com/wydrox/apassy/blob/fix/bouncer-default-on/docs/evaluation/bouncer-default-v1.md). Local logs, raw evaluation rows and screenshot hashes are in the screenshot directory's `manifest.json` and adjacent receipts.

Current PR state: local validation above applies to head `9084d51c061443e3031d9c326c7d7c39e9787807`, implemented from the requested base `6759f32022e6435ecb60aaba7fdd5d04e4c83e36`. Main advanced to `153fcc42a0fe61c0bbde95288340e1294485f80b` during verification. GitHub reports **CONFLICTING / DIRTY**. The site check is successful; no Rust PR CI result is reported, and there are no reviews. Per the instruction to open a draft and stop, merge conflicts were left for integration; no rebase or merge was attempted.

Draft only. No merge, ready-for-review action, release or deployment.
