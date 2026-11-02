# PR 37 independent repair review

Screenshots use examples/screenshots.rs through scripts/screenshots.sh, a scratch HOME, scratch CLAUDE_CONFIG_DIR and CODEX_HOME. All agents, vault records, wrappers and host settings are synthetic. The connected fixture demonstrates complete local configuration, not live host acceptance. The UI says "Set up · connection unverified" for that reason. No owner app, vault, keychain, real host settings or LaunchAgents were used.

The fixture runner and tour are in fixtures/. Use REVIEW37_STATE=not-connected|connected|needs-repair with the runner as APASSY_TOUR_BIN and the tour file as APASSY_TOUR. The example binary path is the dedicated review target. Screenshots were built from 343c232b; the subsequent lock-only commit does not change UI code.

Confirmed fixes: best-effort rollback continues after a restore error; six commit boundaries have failure injection; live doctor uses a private namespace and process lock to clean abandoned fixtures on the next run; conflicting wrapper tokens and explicit identity reassignment are refused; Settings Repair resolves its agent ID and retains the fresh owner check; host summaries/actions/disclosures and browser Touch ID wording were corrected. The pre-existing five-second aggregate wall-clock assertion in agent_path was replaced with its existing semantic checks (timeout outcome, owner decision and zero model requests).

Remaining limits: no crash journal for multi-file setup; GUI token rotation cannot restore the former token if file installation fails; unbound legacy/GUI connections require explicit agent selection; no token-to-ID attestation or complete orphan reconciliation; failed new CLI revocation can still require owner cleanup; no MCP last-request timestamps; installed-host trust, native sandbox enforcement and secret-injected command execution remain unverified. Filesystem failures can prevent rollback; this is reported, and restoration of other files is still attempted. The live doctor's empty private control directory and lock remain, without vaults or credentials. Older /tmp/apassy-doctor-* artifacts from the former implementation are not swept.

## Verification

Final pushed head: 491d71aaccb2ebc7a2c755ed6a199a25368d9ce0 (draft remains draft).

Dedicated target: /Users/rafalw/Dev/.target-review37; CARGO_INCREMENTAL=0. HOME=/tmp/review37-home with scratch Claude and Codex configuration directories. Initial df: 34 GiB available; all build starts were above 8 GiB.

- `cargo test --all-features --lib cli::`: 60 passed.
- `cargo test --all-features --lib agent_onboarding`: 4 passed; the full final library run also passed these tests.
- `cargo test --all-features --test it a_connector_use_without_a_running_bouncer_waits_for_the_owner`: 1 passed, 5.19 s including fixture work.
- Four helper CLI discovery checks: help/version exit 0; invalid option exit 2.
- SIGKILL during live fixture creation followed by another live doctor: abandoned fixture removed; broker/MCP/hook/cleanup stages OK; native sandbox unverified.
- `cargo test --all-features`: library 1224 passed, 3 failed, 5 ignored. Cargo stopped before integration/binary tests. The failures were `a_failed_weights_download_still_starts_the_server_with_apassy` and `with_apassy_replaces_an_outside_server_that_stops` at model_server.rs:3150 (`pid`, consistent with reading the PID file before content is written), and `timed_out_cloud_read_cannot_publish_a_late_file_and_retry_succeeds` at sync/mod.rs:1250 (late-read timeout). All three pass in isolation. These files are identical to origin/main (blob hashes 1dcd7c282a7f92f1c3a35640bd88d2ba91ce1dc6 and 0dad72fbdeb531069081da82e13db0035b20ac1a respectively); no claim of new regression causality.
- `cargo clippy --all-features --all-targets -- -D warnings`: passed.
- `cargo test --all-features --test it`: 795 passed, 0 failed, 14 ignored, 258.21 s.
- `cargo test --all-features --bins`: 11 passed across helper binary test suites, no failures.
- Dedicated review target deleted after verification. Final df: 17 GiB free.
- Latest CI readback 2026-10-31 23:58 UTC: nine passed, four macOS checks pending, no failed checks. PR remains draft at the final pushed head. CI green is not yet established.
