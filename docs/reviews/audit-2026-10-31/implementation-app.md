# Whole-app audit implementation — 2026-10-31

Base: 6759f32022e6435ecb60aaba7fdd5d04e4c83e36. Synthetic fixtures only.
No owner vault, keychain, iCloud directory, installed app, LaunchAgent, browser,
or Docker access. No excluded source file was changed.

| Finding | Status | Regression |
| --- | --- | --- |
| A01 / P1 inactivity and session lock | Skipped; unresolved P1. Needs coordinated owner lifecycle work in excluded `src/desktop/owner_check.rs`, including pending proof completion and cancellation, plus native sleep/screen-lock notification integration. No auto-lock setting shipped. | No executable reproduction added; source audit only. |
| A02 / P1 short masking | Fixed; short values require token boundaries, longer values match anywhere. Single output pass does not rescan replacement labels. | `audit_short_secrets_are_masked_at_token_boundaries`: 1, 2, 3 bytes; quoted and key=value output, embedded words preserved. |
| A03 / P1 Website loss | Fixed; complete URL cell stored as visible Website detail. Multiple URI text is preserved verbatim, not normalized into separate site identities. | `audit_csv_preserves_website`: scheme, port, path, query and multiple URI text. |
| A04 / P1 trailing password bytes | Fixed for CR/LF; spaces were already preserved. | `audit_csv_preserves_password_bytes`: spaces, LF, CRLF. |
| A05 / P1 unsandboxed onboarding | Fixed; both hosts get launcher commands matching CLI setup, with configuration/connection verification distinguished. macOS limitation stated. | `audit_hosts_have_names_setup_targets_and_a_guess_from_the_agent_name`. |
| A06 / P2 unbounded MCP line | Fixed; reads at most 64 KiB + one sentinel byte, then terminates on oversized input. | `audit_mcp_frame_is_bounded_without_a_newline`: stream 8x the limit, bounded consumed bytes and retained string. |
| A07 / P2 expired tombstones | Fixed; retain tombstones indefinitely. Already-pruned deletion knowledge cannot be recovered. Storage grows with deletes; future compaction needs replica acknowledgements or explicit reseeding. | `audit_old_tombstone_still_blocks_a_stale_replica`: aged tombstone survives repeated merges of pre-deletion snapshot. |
| A08 / P2 same-name accounts | Fixed; names/kinds cannot establish identity, so they no longer mark duplicates or alter selection. Deliberate repeat imports require owner review. | `audit_same_name_is_not_proof_of_an_existing_account`, `matching_names_do_not_change_account_selection`. |
| A09 / P2 dead Share | Skipped as unreachable on audited base. `rg 'Sheet::Share' src` finds its only opener in `items::place_group`; it requires a nonempty `shared_vaults`, whose implementation returns `Vec::new()` unconditionally. The empty-state instruction to use Share is misleading; follow up with shared-vault UX owner. | Source evidence; no active Share affordance found. No Share UI changed. |
| A10 / P2 malformed CSV | Fixed; shared strict reader validates the complete export before producing entries. CLI returns an error before vault calls. | `audit_csv_rejects_truncated_export_before_any_entries`: unmatched quote and text after closing quote, each after a valid row. |
| A11 / P3 README | Deferred; outside requested P1/P2 implementation. | Not run. |

## Red-first evidence

Eight new/updated regression cases were run before fixes. Seven failed on the
reported behavior. The tombstone fixture initially failed too early because vault
creation and backup leave it locked. After correcting that fixture, it was rerun
against the original expiry code: expected one tombstone, observed zero. Only then
was the expiry removed. An old custom-field count and duplicate-selection test
were updated to reflect the intended new behavior.

Local raw receipts are in the requested external directory:
`/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/impl-app/`.
`red.log` has the initial seven behavior failures plus the early tombstone fixture
failure; `tombstone-red.log` has the corrected tombstone behavior failure.

No auto-lock or Share view changed, so the conditional light/dark screenshot tour
for those two views was not run. No screenshots are claimed. The onboarding
command has a string regression; native visual acceptance remains unverified.

## Checks

Final results are recorded in the draft PR. These checks use scratch HOME
`/tmp/apassy-appfix-home`, the prescribed target directory and incremental setting.
Disk availability was checked before each build and remained above 6 GiB.

Validation:

- Full `cargo test --offline --locked --all-features --all-targets --no-fail-fast -- --test-threads=1`: **1929 passed, 1 failed, 19 ignored**; exit 101. The sole failure is `isolation_profile::launcher_passes_the_installed_and_the_build_app`. Its unchanged launcher recognizes a literal `target` directory; the required `.target-appfix` path therefore has no default `APASSY_APP_BUILD`. The test expects that parameter. Launcher blob `5dc4615e1ece9255818418dcc7ea1c3eba7d4fe6` and test blob `5cad07d70d504360eb77618a058693ce2321ada7` exactly match base 6759f320. Not changed outside audit scope.
- Library: **1,144 passed, 0 failed, 5 ignored**. All eight audit regression cases pass; the `audit_` filter also includes one existing case (9/9 pass, no ignored tests). Initial full-library run exposed two old import assertions; corrected assertions pass in the final run.
- `cargo clippy --offline --locked --all-features --all-targets -- -D warnings`: **PASS**.
- All-feature doc tests: **6 passed**. Node model: **33 passed**. Python isolation fixtures: **9 passed**. Format and whitespace checks: **PASS**.
- No live/provider/native visual acceptance or remote CI acceptance claimed.
