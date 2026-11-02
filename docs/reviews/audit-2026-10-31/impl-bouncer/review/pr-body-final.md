The bouncer evaluates each process request after the hard checks, including first use, staging, unconfirmed production and credentials with default classification sources. A model allow permits the current run and creates no grant, answer, evaluation scope, pattern or source confirmation. This implements ADR 0031 and supersedes ADR 0029's routing requirement. Schema remains 20.

| Gate | Before | After |
| --- | --- | --- |
| Unconfirmed production/default environment or risk | First-use owner question | Fresh model decision; task_match >= 0.80, including safe reads; calibration cannot lower it |
| Missing or mismatched evaluation scope | Setup question outside confirmed dev/local low risk | No setup; stored scopes have no routing effect |
| Owner-confirmed production without fitting allowance; Always ask; analysis flags; foreign hosts/project; missing request/declaration; root/HOME; unfit answer; model not ready | Ask before inference | Preserved and tightened; Never/access restrictions still refuse |
| Explicit owner answers and taught patterns | Existing execution authority | Existing semantics after all applicable hard checks; model allows create neither |

Independent review merged main through PRs #29, #30 and #32, without rebase or force-push. Extension/app fixes, owner-verification windows and native-helper protections remain. The window can supply identity proof only after an explicit local Allow Once click; it cannot answer questions or bypass routing. Model paths never read or seed it. The PR remains draft.

Review fixes:

- Each credential must cover every detected host, even without a literal secret-variable reference. Encoded DNS, Unicode/IDN hosts and IPv6 zones remain visible when normalization fails. Explicit execution answers retain their non-database host scope; foreign database hosts still ask.
- Missing user request/declaration veto automatic execution answers. Structural model-field/answer spoofing is checked in purpose, user text and every command argument.
- A pinned-model regression reproduced silent state truncation: padding hid the actual Python write and yielded three allows at task_match 0.801. Bundled serve.py now checks exact tokenizer budgets for every question and rejects incomplete states before inference. All three now ask, with zero scored calls. No fixture command executes; model weights and thresholds are unchanged.
- apassy-eval uses the non-executing broker entry point, stopping before credential-environment preparation, proxy startup or process creation. A marker never executes even when the model allows. Project identity matches the case; deliberate foreign projects stay explicit. Coverage counts valid scored 2xx answers, so zero inference and malformed-response controls fail.
- Settings > Bouncer uses Ready/Starting/Not running and Today. Counts use completed decision rows in the owner's local calendar day, including DST boundaries; waiting questions count after settlement. Failures can overlap asked.
- Retained schema-20 scopes, hidden setup UI, repeated-model persistence and five authorization/script-change races have regressions.

Validation on final review head:

- Full `cargo test --offline --locked --all-features -j2 -- --test-threads=1`: **1,987 passed, 0 failed, 19 ignored** (1,184 library, 9 binary, 788 integration, 6 doc tests).
- `cargo clippy --offline --locked --all-features --all-targets -j2 -- -D warnings`: **PASS**, exit 0.
- Final targeted routing and evaluator checks: **23 + 2 passed**. Formatting, diff whitespace and screenshot shell syntax: PASS.
- Review helper checks: Python model/boundary 6, Node walkthrough 33, isolation fixture 9, CI helpers 77 and source version checks 8 passed.
- Tests and Clippy used `CARGO_TARGET_DIR=/Users/rafalw/Dev/.target-review31 CARGO_INCREMENTAL=0`. That target was removed after final ancestry/open-file checks. Latest main 5617e54f is integrated; remote PR head matches c710c725.

All 14 CI checks pass on c710c725; draft state retained.

Real pinned-model smoke on port 18772: 12 cases x 3 runs, 36 requests, 18 scored inference calls, 15 would-run, 21 ask, zero unsafe allows or harness errors, exit 0. Oversized-input negative control: 3 asks, zero scored calls, expected coverage failure exit 1. This is bounded synthetic routing evidence. Arbitrary adversarial prose is not proven harmless; agent-provided user text is not authenticated intent. Older/custom model services require equivalent complete-input handling. Existing dynamic-host and transitive-script binding limits remain.

Four screenshots were retaken at the final head using examples/screenshots.rs and scripts/screenshots.sh, and all were visually inspected:

- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/review/light/ui-settings-bouncer.png`
- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/review/light/ui-decisions-question.png`
- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/review/dark/ui-settings-bouncer.png`
- `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-bouncer/review/dark/ui-decisions-question.png`

The existing app forces light appearance, so dark-input screenshots are not dark-mode acceptance. Native helpers were disabled and all runtime data was synthetic scratch data. The full before/after gate table, findings, logs, screenshot hashes and cleanup receipts are in the same review directory. Checkpoint SHA-256 stayed unchanged; the isolated model and scratch HOME were stopped/removed. No owner's vault, keychain, running app, bouncer settings or LaunchAgents were used. No owner prompts, browsers, Docker, release, deployment, merge or ready action.

[ADR 0031](https://github.com/wydrox/apassy/blob/fix/bouncer-default-on/docs/adr/0031-bouncer-decides-by-default.md) · [Frozen routing evaluation](https://github.com/wydrox/apassy/blob/fix/bouncer-default-on/docs/evaluation/bouncer-default-v1.md).

