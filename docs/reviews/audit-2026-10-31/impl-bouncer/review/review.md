# Independent review of PR 31

Implementation head: 9084d51c061443e3031d9c326c7d7c39e9787807.
Reviewed/fixed head: c710c725a7b8ccd8964795b40e21fb1dc4555122.
The final follow-up preserves encoded and Unicode hosts instead of dropping them.
Main integrated: 5617e54f0a31c0cf0070d0e43005aca82f0ffebb (PRs 29, 30 and 32).

The PR branch was already checked out in another clean worktree. This review used
the assigned t3/review-bouncer-routing-security worktree and pushed HEAD to
fix/bouncer-default-on without rewriting history. The initial changelog conflict preserved extension fixes and replaced obsolete
bouncer setup text. PR 30 merged cleanly. PR 32 then required resolutions in
SECURITY.md, the screenshot script, Settings tests and the product-isolation fixture.
Its owner-window behavior, protected native helpers, Security picker and isolation
checks were preserved alongside the routing/UI review fixes.

## Complete gate table

Before means main before PR 31. After means the reviewed branch including fixes.
Answers and patterns remain explicit owner authority. All automatic routes need
readiness and the final authorization recheck.

| Gate | Before | After | Evidence |
| --- | --- | --- | --- |
| Locked vault, invalid/expired/revoked agent | Refuse | Refuse | Existing authentication tests |
| Invalid request, argv, item list, purpose, path or nonexistent cwd | Refuse | Refuse | Request/check validation tests |
| Never, Only these items, unknown item | Identical refusal | Preserved, zero inference | first_use hard-veto table and exceptions tests |
| Archive, restore review, missing binding, duplicate variables | Refuse before routing | Preserved | Access, binding and restore tests |
| Analysis flags, secret output, production words, invalid host-hook context | Ask | Preserved, zero inference | Hard-veto table; secret_output and hook tests |
| Text addressing reviewer or spoofing state/answer fields | Purpose/request scanned; argv could reach model | Scan purpose, request and each argv; ask before inference | model_field_spoofing_in_each_agent_text_field_asks_before_inference |
| Foreign database host | Ask despite remembered answer | Preserved | psql_to_a_foreign_host_asks |
| Other detected foreign destination, including encoded DNS, IDNs and IPv6 zones | Analysis generally needed literal secret reference/provider knowledge | Each item must cover every host; fitting explicit execution answer can add non-DB hosts | a_foreign_host_asks_even_without_a_literal_secret_reference; answer-host tests |
| Confirmed production | Ask without fitting production allowance | Preserved, zero inference | Hard-veto table and production-answer tests |
| Always ask (item or agent) | Ask | Preserved, zero inference | Hard-veto table, exceptions tests |
| Model absent, Off, failed readiness or unavailable | Ask; remembered routes need readiness | Preserved | without_a_bouncer_nothing_remembered_runs; supervisor/readiness tests |
| Root, HOME, parent, filesystem alias | Ask; no remembered authority | Preserved | a_root_home_or_alias_folder_asks_and_refuses_a_crafted_answer |
| Missing user request or declaration | Checked after fitting execution answer could return | Ask before answer or pattern; remove remember offer | Missing-request integration regression and run::tests legacy-scope test |
| Fitting explicit owner answer | Existing automatic authority | Preserved with required context | Owner-answer suite |
| Existing owner answer does not fit action/hosts | Ask | Preserved | Owner-answer host/action tests |
| Foreign declaration project | Execution answer or evaluation scope could cover it | Only explicit execution answer can cover it | Foreign-project integration and retained-scope unit tests |
| Active owner-taught pattern | Automatic after hard/context checks | Preserved after stronger gates | Learning/pattern tests |
| Unconfirmed production or default sources | Ask before inference | Fresh model decision, task_match >= 0.80 even for safe reads; calibration cannot lower it | Default-source and calibrated 79% regressions |
| Confirmed dev/local low risk | Model without scope | Model on every use | Repeated-use regression |
| Staging/other classification without scope | Ask before inference | Fresh model decision | First-use staging and live smoke |
| Missing or mismatched schema-20 scope | Setup gate except dev/local low | Ignored; never supplies permission or waives hard veto | legacy_schema_twenty_scopes_neither_require_setup_nor_waive_vetoes |
| Oversized model input | Silent truncation could hide command | Bundled server rejects before inference; explicit unavailable reason asks owner | truncation-before.jsonl vs truncation-after.jsonl |
| Low confidence, sensitive writes, destroy veto, invalid answer | Ask | Preserved, stricter defaults | Bouncer policy/integration tests |
| Authorization, project/cwd or supported script binding changes during decision | Invalidate before secret read | Preserved with expanded race coverage | changing_access_during_inference_prevents_execution_and_secret_delivery |
| Evaluation execution | Obsolete revoked grant did not prevent execution | evaluate_run stops before environment preparation, proxy and process | Marker regression |
| Zero scored inference | Gate counted HTTP attempts | Only valid 2xx scored responses count | invalid_model_answers_cannot_count_as_inference_coverage |

## Findings

| Severity | Fixed file:line | Evidence | Fixed |
| --- | --- | --- | --- |
| P1 | tools/basemodel/serve.py:87 | Padding hid actual Python write. Pinned model allowed 3/3 runs at task_match 0.801, clearing default 0.80 threshold. After fix: 3 asks, zero scored calls. Evaluator never executed the command. | Yes |
| P1 | src/broker/run.rs:478 | Foreign URL without literal secret reference returned Bouncer allowed under permissive model before fix; now asks with zero inference. | Yes |
| P1 | src/broker/run.rs:1777; src/broker/shell_risk.rs:4664 | Percent-encoded and Unicode destinations could vanish during host normalization, including clearing a foreign DB flag. Curl decoded %65vil.example.net to evil.example.net through a deliberately unavailable local proxy. Regression returned Bouncer allowed before fix; 6 HTTP/DB/IDN/zone variants now ask with zero model calls. | Yes |
| P2 | src/broker/run.rs:454 | Fitting execution answer preceded required-context vetoes. Missing context now asks before automatic answer reuse and removes remember offer. | Yes |
| P2 | src/broker/run.rs:671; src/broker/shell_risk.rs:449 | Model-field spoofing inside command arguments reached inference. Structural/answer claims in command, request and purpose now ask before inference. | Yes |
| P2 | src/bin/apassy-eval.rs:120 | Error/invalid HTTP attempts could satisfy coverage without scored inference. Readiness-valid/task-invalid stub now exits 1 with zero coverage. | Yes |
| P2 | src/desktop/ui/settings.rs:800 | UTC day and ambiguous Answers label. Local-day bounds handle DST, non-hour offsets and skipped midnight. Both bounds exclude adjacent days. Ready label is plain. | Yes |

## Persistence and UI

Repeated model allows leave grants, owner answers, scopes and patterns empty and
do not confirm sources. learning::record stores the decision and blocks owner-denied
patterns; only explicit ApprovedAndRemembered calls learning::remember. Real retained
schema-20 rows are tested against both normal routing and a foreign-project veto.
Decisions clears compatibility drafts, even with a queued old offer. Its regression
and screenshots show no setup offer. Legacy records remain removable.

state_text sends user request, joined shell command and stated purpose, plus optional
owner instruction for legacy callers. Declaration text, cwd, relative_dir, env_names,
hosts and classification sources are not added to the model state. Literal argv
can itself include absolute paths or other data. Source strictness is
applied in the broker. Known structural spoofing is an analysis flag. The bundled
server checks actual tokenizer budgets for every question without changing the
normal trained format.

This is bounded adversarial evidence, not proof of immunity to arbitrary natural
language. Agent-supplied user text is not authenticated owner intent; existing host-hook,
project-label and filesystem limits remain. The length guard is in bundled serve.py;
custom/older services must provide equivalent complete-input handling. Dynamic hosts
and transitive script dependencies retain existing parser/binding limits.

## Real model and screenshots

Only scratch HOME and 127.0.0.1:18772 were used. Model version:
apassy-base-v1+83224960. Frozen smoke: 12 cases x 3 runs, 18 successful inference
calls, 15 would-run, 21 ask, zero unsafe allows, exit 0. This is routing evidence,
not broad acceptance. Oversized negative control: 3 allows before, 3 asks and zero
scored calls after; expected failing coverage exit 1. Marker, unsafe-label,
foreign-project/zero-inference and invalid-response negative controls pass.
Weights and thresholds were not tuned.

All four screenshots in light/ and dark/ were inspected. Ready and Today are legible;
the ordinary Allow Once/Deny card has no setup offer. Product still forces light
appearance; dark-input captures do not establish dark-mode support. screenshots.json
contains SHA-256 receipts.

## Validation

Full combined-head `cargo test --offline --locked --all-features -j2 -- --test-threads=1`: **1,987 passed, 0 failed, 19 ignored** (1,184 library + 9 binary + 788 integration + 6 doc tests).
`cargo clippy --offline --locked --all-features --all-targets -j2 -- -D warnings`: **PASS**, exit 0.
Both used `CARGO_TARGET_DIR=/Users/rafalw/Dev/.target-review31 CARGO_INCREMENTAL=0`.
Formatting, `git diff --check` and `bash -n scripts/screenshots.sh`: PASS.
Final targeted routing/evaluation checks: **23 + 2 passed**.
Current main 5617e54f is an ancestor; the remote PR head equals c710c725.
The target was deleted after confirming no open files. Its measured size was
2,272,628 KiB; root filesystem available space was 8,981,540 KiB afterward.
Other builds share APFS, so this is not an isolated recovery measurement.
Detailed commands/results are in validation.json, review31-window-full.log,
review31-window-clippy.log and cleanup.json.

CI on c710c725: all 14 checks green (ci.json). PR remains draft and unmerged.

Targeted checks on the combined head: first_use 23 pass; eval_harness 2 pass.
Other bounded review checks: owner_answers 19 pass; expanded authorization race
(5 changes) pass; retained-scope routing 1 pass; Settings 10 pass; Python
model/boundary 6 pass; Node walkthrough 33 pass; Python isolation fixture 9 pass;
CI helper tests 77 pass; source version tests 8 pass. Source versions match 0.5.7.
These earlier targeted results are supplemented by the final combined-head suite,
not attributed to a later snapshot on their own. No release or relay-checkout
acceptance is claimed.

The final real-model smoke and truncation negative control were repeated on
c710c725 after both main integrations. Final smoke: 36 requests, 18 scored
inferences, 15 would-run, 21 ask, zero unsafe allows, zero harness errors; exit 0.
The oversized negative control asks 3/3 times with zero scored calls and exits 1
for the intentionally missing inference coverage. The marker regression separately
proves that even an allow cannot execute fixture commands.

All four current-head screenshots were retaken using examples/screenshots.rs and
scripts/screenshots.sh. Parent APASSY_/LAYA_ configuration was removed, all native
helper paths were explicitly /usr/bin/false, and only tour-specific scratch
configuration was provided. Ready and Today are visible. No setup offer is shown.
The exact files, hashes and source blobs are in screenshots.json and
capture-provenance.json. Both theme-input tours still show the existing forced-light
product appearance.

The own model on port 18772 was stopped. The read-only checkpoint SHA-256 remained
832249609f0cfd978cc7697326d55bc6d2676507eec13e5fb3f4bc6b35cfe850.
Its scratch HOME was removed; runtime-final.json records the cleanup.

The owner-verification window from main supplies identity proof only after an
explicit local Allow Once click. It never answers a pending question, grants
remembered authority or bypasses routing. Model paths neither read nor seed it.
Durable actions retain their fresh-check requirements.

An early full run found two stale assertions for the old status labels. They were
corrected and all later suites passed. Target cleanup was followed by two new main
integrations, requiring rebuilds; final cleanup.json records only the last cleanup.
No owner vault, keychain, app process, bouncer settings or LaunchAgent was used.
No owner prompt, browser, Docker, PR merge, ready action, release or deployment.
