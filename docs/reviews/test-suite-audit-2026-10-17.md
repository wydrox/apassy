# Rust test timing and overlap audit

Follow-up: the [complete necessity review and reduction plan](test-reduction-plan-2026-10-17.md)
accounts for every inventoried test, including suites outside this timing run.
Its proposals supersede the limited overlap list below; the timing evidence remains valid.

Scope: the root Cargo package, with `--all-features --all-targets`, on the local
macOS arm64 host. The timing tool does not cover doctests, the iPhone core workspace
member, Swift, Python, Node or browser suites. Existing ignored tests are reported
separately and remain disabled. All fixtures are synthetic.

## Execution policy

`scripts/parallel-tests.json` identifies 201 reviewed tests by exact name: 159
library tests and 42 integration tests. Each group records why its tests have no
shared mutable state. They run with four threads; remaining tests run in a separate
serial invocation. New tests remain serial until explicitly reviewed.

The library selections cover pure parsing, wire contracts, crypto vectors, local
HTTP buffers, version/manifest validation, formatting, and per-test in-memory
clipboard fixtures. Integration selections cover contract validation, the demo
model, and a base64 helper.

Stateful tests retain serial execution. In particular, active rule packs are a
mutable process-wide value; vault unlock touches the live-wait registry; corrections,
relay rate limits, and sync workers have global bookkeeping. The model smoke wrapper
also opens a vault under `--all-features` and therefore remains serial. Child-process
isolation and mutexes are useful existing protections, but are not proof that a test
touches no shared state.

The runner validates both the shard partition and the serial/parallel partition
against the compiled test inventory. Missing names, duplicate selection and filter
collisions fail before tests execute. Tests and assertions have not been deleted.

## Proposed merges

No byte-identical duplicate test bodies were confirmed. These are reviewed overlaps,
not an automated claim that every similar test is redundant. Retain each distinct
behavior below before deleting a separate test.
When applying a merge, remove any retired exact name from `scripts/parallel-tests.json`
as well; stale entries intentionally fail the partition check.

1. **Owner error wording:** merge `owner_messages_name_the_problem` in
   [tests/owner_vault.rs](../../tests/owner_vault.rs) into
   `create_starts_locked_and_wrong_passphrase_stays_locked`. Both construct an
   encrypted vault and reject short creation passwords and wrong unlock passwords.
   The wording test repeats `unlock(WRONG)` again solely to check sentence formatting.
   Keep minimum-length wording, no file after rejected creation, the empty-password
   prompt, existing-target rejection, locked state and redaction assertions. Reuse
   the captured wrong-key error instead of repeating the KDF operation.

2. **Notification failure:** merge `failed_notification_keeps_waiting_request` in
   [tests/desktop_model.rs](../../tests/desktop_model.rs) into
   `approval_updates_current_state_but_keeps_initial_decision_and_delivery_failure`.
   The setup and approval are the same. Add the shorter test's pre-approval
   `Pending`, delivery `failed`, and `!executed` checks to the longer lifecycle test.
   This simplifies coverage; runtime savings will be small.

3. **Owner denial:** merge `owner_can_deny_a_waiting_request` in the same file into
   the `deny` case of
   `lock_revoke_and_owner_denial_synchronize_alerts_without_rewriting_initial_decision`.
   The longer test already covers status, nonexecution, initial decision and alerts.
   Preserve `reason_code == "owner_denied"` specifically for the denial case.

4. **Password hint before passkey removal:** merge
   `editing_a_login_with_a_password_still_shows_the_unchanged_hint` in
   [src/desktop/ui/passkey_tests.rs](../../src/desktop/ui/passkey_tests.rs) into
   `removing_a_passkey_asks_the_owner_with_the_shown_revision_and_name`.
   Check `Unchanged` and absence of `A password is optional` before removal, then
   close the editor without saving or leaving a pending sheet/check. Retain the
   existing revision and owner-authorization assertions. This avoids a separate
   encrypted-vault/password/passkey setup for two wording assertions.

5. **Password hint after passkey removal:** merge
   `a_login_with_a_password_keeps_requiring_one_when_the_passkey_is_gone` into the
   end of that same removal lifecycle. Open the surviving login's edit form and
   keep both hint assertions. The pre-removal and post-removal states are distinct;
   neither should be discarded. The current test name implies stronger validation
   than its two rendered-text assertions actually prove.

6. **OTP error wording, optional:** fold `the_error_messages_are_plain` in
   [src/otp.rs](../../src/otp.rs) into `refuses_hotp_short_and_bad_values`, retaining
   the `HOTP` and `TOTP` wording checks beside their respective invalid cases.
   This is an organization improvement with negligible timing benefit.

Do not remove version-specific migration/rollback cases in
[tests/vault_migration.rs](../../tests/vault_migration.rs): their repeated scaffolding
guards different schema versions and rollback conditions. A shared helper may reduce
source repetition while preserving every case. Likewise, CLI integration tests
add process exit-code/stdout/stderr coverage beyond unit help rendering, and the
public smoke wrapper has its own entrypoint coverage. Path/provider formatting
assertions are behavior tests, even when their outputs are strings.

One separate timing opportunity is
`relay_feed::a_feed_rate_answer_makes_the_mac_wait_a_minute` in
[tests/relay_feed.rs](../../tests/relay_feed.rs). It deliberately requires at least
60 seconds before a successful retry. It is neither a duplicate nor a wording
test. Replacing the wall-clock wait would need a controllable clock and preservation
of the no-early-retry, no-busy-loop and eventual-publication assertions; that change
is outside this audit.

## Validation

Local macOS arm64 validation used revision `e13c120` plus the test-tooling changes:

- All three macOS shard commands passed: 1,804 tests passed and 19 existing tests
  remained ignored. This includes all 201 tests in their parallel lanes.
- Compiled inventory checks passed for both the three-shard and four-shard layouts.
- All 95 Python CI-helper tests passed with Python 3.12.
- `git diff --check` passed.

The four-shard selection was checked locally; Linux execution and hosted CI were
not run. The source revision remained stable during the final validation/measurement
runs.

## Reproduction

```
python3 scripts/ci-test-timings.py
python3 scripts/ci-test-shard.py --list --check --shard-count 3
python3 scripts/ci-test-shard.py --list --check --shard-count 4
python3.12 -m unittest discover -s scripts/tests -p 'test_ci_*.py'
```

The profiler writes every duration and status to `target/test-timings/results.json`
and the slowest `ceil(executed_tests * 0.05)` to `target/test-timings/slowest.md`.
Durations are sequential process wall time, including startup and excluding the
build. They are not measured CI speedup or native/device acceptance.

## Measured slowest 5%

The final sequential timing run passed all 1,804 nonignored tests and recorded 19 ignored tests across 15 root Cargo targets. The slowest 91 tests took 366.84 of 777.59 summed test seconds (47.2%). These are per-process timings, not CI job wall times. Every duration and status is retained in `target/test-timings/results.json`.

| Target and test | Seconds |
| --- | ---: |
| `test:it::relay_feed::a_feed_rate_answer_makes_the_mac_wait_a_minute` | 60.521 |
| `lib:apassy::desktop::ui::sync_tests::relay_calls_of_the_owner_leave_the_window_responsive` | 21.790 |
| `lib:apassy::broker::model_server::tests::with_apassy_replaces_an_outside_server_that_stops` | 10.141 |
| `test:it::analysis_replay::analysis_matches_golden_replay` | 9.896 |
| `test:it::relay_feed::no_feed_without_a_live_iphone_or_while_the_vault_is_locked` | 8.359 |
| `test:it::companion::a_request_refused_for_the_device_rate_records_no_nonce_and_no_last_seen` | 8.013 |
| `test:it::relay_questions::a_question_expires_with_its_wait` | 7.722 |
| `test:it::companion::a_paired_device_gets_120_requests_per_minute` | 7.452 |
| `test:it::relay_feed::bad_removals_are_refused_or_stale` | 7.343 |
| `test:it::companion::unsigned_requests_are_limited_per_address_and_a_correct_poll_and_a_paired_phone_are_not` | 6.791 |
| `test:it::relay_feed::a_flood_of_actions_that_do_not_open_leaves_activity_alone` | 6.464 |
| `test:it::vault_passphrase::failed_passphrase_change_keeps_the_old_passphrase` | 6.211 |
| `test:it::learning_replay::fixture_replay_learns_and_never_allows_a_denied_request` | 5.869 |
| `test:it::isolation_profile::notifier_bundle_cannot_be_opened_in_profile` | 5.439 |
| `test:it::companion::a_connection_from_any_address_of_the_mac_is_closed_at_once` | 4.739 |
| `test:it::vault_migration::unlock_migrates_each_earlier_schema_version_to_the_current_one` | 4.375 |
| `test:it::isolation_profile::profile_denies_lsopen_of_an_application` | 3.928 |
| `test:it::notifications::another_vault_starts_a_new_notification_baseline` | 3.904 |
| `test:it::notifications::blocked_request_notifies_within_five_seconds` | 3.881 |
| `test:it::relay_feed::three_answers_seq_not_newer_make_the_mac_wait` | 3.790 |
| `test:it::agent_items::ask_owner_waits_reattaches_and_gets_the_item_or_a_dismissal` | 3.778 |
| `test:it::relay_feed::a_seq_that_landed_with_other_bytes_is_published_again` | 3.749 |
| `lib:apassy::desktop::sync_worker::tests::live::a_failing_pull_does_not_spin` | 3.559 |
| `test:it::notifications::waiting_approval_notifies_within_five_seconds` | 3.540 |
| `lib:apassy::desktop::sync_worker::tests::live::the_waiter_of_a_removed_mac_tells_at_once_and_stops` | 3.503 |
| `test:it::relay_feed::a_removal_that_signs_the_names_is_applied` | 3.486 |
| `test:it::first_use::a_root_home_or_alias_folder_asks_and_refuses_a_crafted_answer` | 3.477 |
| `lib:apassy::desktop::sync_worker::tests::live::an_early_long_poll_answer_does_not_spin` | 3.470 |
| `lib:apassy::desktop::ui::sync_tests::a_second_mac_joins_the_questions_team_with_a_link` | 3.466 |
| `test:it::relay_sync::a_failed_sync_after_a_new_passphrase_keeps_the_new_passphrase` | 3.435 |
| `test:it::relay_feed::a_bad_copy_before_the_real_action_gets_the_only_settle` | 3.308 |
| `test:it::relay_questions::the_first_valid_answer_wins` | 3.291 |
| `test:it::relay_feed::an_action_that_a_lock_cut_short_is_checked_after_the_unlock` | 3.255 |
| `test:it::host_hook::a_false_hook_request_waits_for_the_owner` | 3.230 |
| `test:it::host_hook::the_hook_never_blocks_the_prompt` | 3.060 |
| `test:it::relay_sync::a_sync_that_waits_during_a_pause_does_not_run` | 2.869 |
| `test:it::bouncer_rules::production_declaration_always_waits_for_the_owner` | 2.748 |
| `test:it::relay_feed::seq_goes_up_across_restarts` | 2.736 |
| `test:it::bouncer_rules::risky_or_unavailable_bouncer_waits_for_the_owner` | 2.671 |
| `test:it::browser_passkeys::the_guard_reads_real_process_arguments_from_the_kernel` | 2.658 |
| `lib:apassy::desktop::ui::vault_tests::every_variant_of_the_credential_page_draws_at_default_and_minimum_sizes` | 2.632 |
| `test:it::isolation_profile::apassy_mcp_and_hook_in_the_app_bundle_work_in_profile` | 2.579 |
| `test:it::relay_sync::a_429_waits_retry_after` | 2.572 |
| `test:it::host_hook::a_command_that_names_the_hook_channel_waits_for_the_owner` | 2.565 |
| `lib:apassy::desktop::sync_worker::tests::live::a_mac_refused_for_a_moment_syncs_again_at_its_next_try` | 2.505 |
| `test:it::browser_passkeys::check_peer_runs_the_guard_and_refuses` | 2.489 |
| `test:it::isolation_profile::a_helper_outside_the_bundle_refuses_a_caller_in_profile` | 2.460 |
| `test:it::bouncer_rules::trace_settings_and_personal_data_reads_ask` | 2.454 |
| `test:it::relay_feed::a_face_id_removal_is_applied_settled_and_published` | 2.436 |
| `lib:apassy::desktop::ui::vault_tests::settings_show_start_now_and_the_first_start_download` | 2.433 |
| `test:it::relay_feed::an_action_from_an_older_feed_applies_while_the_row_is_the_same` | 2.431 |
| `lib:apassy::desktop::ui::sync_tests::joining_a_relay_copy_under_another_passphrase_asks_for_it` | 2.419 |
| `test:it::relay_sync::a_transient_error_keeps_a_join_waiting` | 2.334 |
| `lib:apassy::broker::model_server::tests::the_idle_stop_ends_the_process_group_of_its_own_server` | 2.332 |
| `lib:apassy::desktop::ui::tests::every_place_draws_at_default_and_minimum_sizes` | 2.323 |
| `test:it::native_helper::real_unsigned_helper_reports_missing_keychain_and_bundle` | 2.298 |
| `test:it::isolation_profile::apassy_programs_cannot_start_in_profile` | 2.297 |
| `test:it::isolation_profile::profile_protects_the_build_app_without_the_installed_app_parameter` | 2.244 |
| `test:it::relay_feed::the_feed_leaves_the_relay_when_it_goes_off` | 2.237 |
| `test:it::isolation_profile::keychain_item_is_not_readable_in_profile` | 2.216 |
| `lib:apassy::companion::hosts::tests::an_output_over_the_limit_or_a_command_that_hangs_gives_nothing` | 2.160 |
| `test:it::relay_sync::the_step_before_a_lock_skips_while_another_sync_runs` | 2.146 |
| `test:it::native_helper::a_helper_built_without_the_dev_flag_ignores_the_override` | 2.111 |
| `test:it::isolation_profile::apassy_programs_cannot_be_read_copied_linked_or_changed_in_profile` | 2.105 |
| `lib:apassy::desktop::sync_worker::tests::live::a_relay_transfer_leaves_the_op_lock_free` | 2.098 |
| `test:it::companion::an_address_past_its_unsigned_budget_costs_no_vault_work` | 2.095 |
| `lib:apassy::vault::merge::schema17_tests::schema17_copies_keep_every_check_and_other_schemas_fail` | 2.095 |
| `lib:apassy::desktop::sync_worker::tests::live::a_slow_relay_transfer_does_not_hold_the_vault` | 2.078 |
| `test:it::shadow_mode::a_candidate_that_is_down_slow_or_another_version_changes_nothing` | 2.005 |
| `lib:apassy::desktop::ui::decisions_tests::requests_and_suggestions_draw_at_every_size` | 1.989 |
| `test:it::native_helper::real_notifier_refuses_a_parent_that_is_not_apassy` | 1.985 |
| `test:it::native_helper::real_helper_reads_the_icloud_status_of_a_file` | 1.969 |
| `test:it::bouncer_rules::low_confidence_and_missing_context_wait_for_the_owner` | 1.969 |
| `test:it::relay_questions::a_question_of_mac_b_shows_on_mac_a_and_its_answers_reach_b` | 1.912 |
| `test:it::relay_sync::the_long_poll_hears_a_push_of_another_mac` | 1.900 |
| `lib:apassy::broker::model_server::tests::the_install_runs_each_step_and_ends_done_or_failed` | 1.873 |
| `test:it::companion::a_slow_head_and_a_slow_body_run_out_of_total_time` | 1.866 |
| `lib:apassy::desktop::ui::sync_tests::add_a_mac_shows_a_link_then_the_safety_words_and_confirm_needs_the_owner_check` | 1.827 |
| `lib:apassy::desktop::ui::sync_tests::the_sync_setting_waits_while_relay_sync_turns_on` | 1.823 |
| `test:it::learning::an_active_pattern_never_overrides_the_earlier_steps` | 1.706 |
| `test:it::relay_feed::the_read_back_follows_more` | 1.693 |
| `lib:apassy::desktop::ui::keyboard_tests::the_page_scrolls_to_the_focus_and_with_page_keys` | 1.652 |
| `test:it::local_finetune::the_gate_opens_at_exactly_300_decisions_and_30_denials_on_ac_power` | 1.633 |
| `test:it::sync_schema_upgrade::folder_sync_adopts_a_schema17_file_and_a_new_passphrase_replaces_it` | 1.626 |
| `lib:apassy::desktop::ui::sync_tests::a_mac_that_turned_relay_sync_off_joins_again_with_a_link_and_merges` | 1.580 |
| `test:it::agent_run::a_changed_process_binding_invalidates_a_pending_approval` | 1.505 |
| `test:it::provider_hosts::a_foreign_host_with_a_secret_is_flagged` | 1.479 |
| `test:it::relay_questions::questions_through_the_relay_are_off_by_default` | 1.464 |
| `test:it::agent_run::a_run_result_stays_in_the_vault_of_the_run` | 1.443 |
| `lib:apassy::desktop::ui::cli_tests::the_command_line_program_drives_the_app` | 1.442 |
| `test:it::relay_feed::a_title_matches_in_either_form_that_an_iphone_shows` | 1.433 |
