# Bouncer implementation verification

Head: `9084d51c061443e3031d9c326c7d7c39e9787807`. Base: `6759f32022e6435ecb60aaba7fdd5d04e4c83e36`.

- Full Rust all-features/all-targets: 1,927 passed, 0 failed, 19 pre-existing manual/network checks ignored.
- Clippy all-features/all-targets with warnings denied: PASS. Doc tests: 6 passed.
- Frozen routing evaluation: 36 requests, 18 decision model calls, 15 would-run, 21 asked; zero unsafe allowances/missing inference/harness errors. Model p50 188 ms, p95/max 390 ms. No evaluation command executed.
- Python temperature diagnostics: 3 passed. Node walkthrough: 33 passed. Python isolation fixture: 9 passed.
- Four screenshots under `light/` and `dark/`, all visually inspected. Dark system-theme input still renders light content because the product forces light appearance. The section is Settings > Bouncer on current main. Counts use completed UTC decision-log rows.
- Model checkpoint unchanged; isolated port 18771 process stopped. Dedicated Cargo target and scratch runtime directory removed.

`initial-full-test.log` records three fixture failures. They were corrected without changes to product isolation: owner-question fixtures no longer rely on the removed staging gate, and the launcher fixture uses a synthetic standard target layout. `fixture-recheck.log` has all 8 checks passing; `full-test.log` is the final complete green run.

Raw evaluation rows, logs, exact PR body and screenshot/checkpoint hashes are adjacent. This is synthetic local verification, not live owner/provider/device acceptance or a release.

Draft PR: https://github.com/wydrox/apassy/pull/31. Main advanced during verification; GitHub reports merge conflicts. Site check passed; no Rust PR CI result or reviews were reported. Integration was left unchanged per the request to open the draft and stop.
