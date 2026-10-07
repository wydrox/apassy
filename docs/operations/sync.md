# Sync through a folder or the Apassy relay

Date: 2026-09-28. The relay: 2026-10-06.
Decision: [ADR 0014](../adr/0014-icloud-sync.md); the relay: [ADR 0022](../adr/0022-relay-sync.md). Related: [several vaults](multiple-vaults.md), [backup and restore](backup-restore.md), [isolation](isolation.md).
Use only synthetic values for tests. The real-secret gate stays BLOCKED.

A vault can sync with your other Macs, or with a small team, through a folder that a sync service keeps in step: iCloud Drive, Dropbox, Google Drive, OneDrive, Syncthing, or a network share. Your own Macs can also sync a vault through the Apassy relay (section 17). Changes from each Mac merge by credential. In normal use there is nothing to choose and no passphrase to type.

## 1. What syncs, and what stays on each Mac

Syncs: the credentials and their settings.

- each credential: its name, kind, notes, tags, fields and secret values, and whether it is archived,
- its declaration, its environment variable (with the hosts of placeholder mode), and its connector,
- its history: added, edited, archived, declaration, variable, and connector events.

Stays on each Mac and never merges:

- agents and their tokens, grants, rules, and the token lifetime,
- the activity log, the decision log, remembered patterns, calibrations, candidate models and shadow answers,
- access requests, runs that wait for you, and the review marks after a restore,
- the history events about agents and reveals,
- the Touch ID unlock, the vault list, and the sync bookkeeping.

So each Mac registers its own agents. Their tokens are in the MCP configuration of each Mac, and their project folders are on each Mac anyway. An agent on one Mac never sees an agent, a grant, or the activity of another Mac or of a teammate.

## 2. Files

| File | Place | Content |
| --- | --- | --- |
| synced file | `<folder>/<name>.apassy` | a closed, encrypted copy of the vault without the local data (section 1). It has the passphrase of the vault. |
| push temporary file | `<folder>/<name>.apassy.push.nosync` | exists only during a push; iCloud Drive does not sync it |
| sync state | `<data folder>/sync/<list ID>.json` (mode `0600`) | the file name, the vault ID, the hash of the synced file and the digest of the synced content after the last sync, the folder, and the vault file. No secret. |
| work copies | `<data folder>/sync/.<name>.*` | exist only during a merge or a push |
| setting | `<data folder>/vaults.json`, field `sync` of the vault | the folder, the file name, and the name of the sync state |

The folder is `<sync service>/Apassy` for a detected service, for example `~/Library/Mobile Documents/com~apple~CloudDocs/Apassy` (iCloud Drive) or `~/Library/CloudStorage/Dropbox/Apassy`. The data folder is `~/Library/Application Support/Apassy`. The live vault stays a local file there; SQLite never opens a file in the synced folder.

## 3. Turn on sync

For a new vault: on the Create screen, pick a folder in "Sync". It is off by default.

For a vault that you have:

1. Open and unlock the vault.
2. In Settings > General, find the section "Sync". Open the menu in the row of the vault (it says "Off").
3. Pick "iCloud Drive", another detected folder (Dropbox, Google Drive, OneDrive), or "Choose folder…" and type the path of any folder that a sync service keeps in step.

Apassy then:

1. makes the folder when its parent exists,
2. picks the name `<vault name>.apassy`. When a file with that name does not open with the key of this vault, or holds another vault, it tries `<vault name>-2.apassy`, `-3`, and so on.
3. writes the first copy. When the file already holds this vault (sync was on before, or another Mac turned it on), Apassy merges with it instead.

No passphrase: the unlocked vault has the key. A vault name that ends in a space and a number (`Work 2`) gets a `-` (`Work-2.apassy`), so it does not look like a duplicate that iCloud made.

The detected folders are iCloud Drive, each folder in `~/Library/CloudStorage` (Dropbox, Google Drive, OneDrive, and other File Provider services), and `~/Dropbox`.

## 4. When it syncs

- **At unlock**, before you see the list. A merge that brought changes says so: "Sync brought 2 changed credentials from Mac mini."
- **While the vault is unlocked**: every 30 seconds Apassy looks at the synced file and merges it when it changed. A few seconds (5 to 8) after you stop changing credentials, it pushes. This runs in the background, also when the window is hidden, minimized, or covered, or the display sleeps.
- **Before each lock**: "Lock now", the lock button, a switch to another vault, "New vault…" or "Open vault file…" from an open vault, a backup, a restore over an open vault, a quit, and "Restart now" for an update.
- **"Sync now"** in Settings > General > Sync.

Never while an agent run waits for you. A sync never stops a lock or a quit: a failure shows once as a note, and the changes stay on this Mac until the next sync.

Agent use writes the activity log, but that is not synced content: it does not start a push.

A worker thread of the app keeps this schedule (`src/desktop/sync_worker.rs`). It syncs only the open vault, only while it is unlocked. The window only shows what the worker did: the status, a note, or the passphrase prompt. A sync of the worker and a sync that you start never run at the same time. The step before a lock does not wait for a relay sync that runs: it leaves the change for the push after the next unlock.

## 5. How a sync works

A sync of an unlocked vault:

1. It reads the synced file. When its hash is the one after the last sync, nothing changed there.
2. When it changed, Apassy copies it to the work folder and attaches the copy to the open vault. SQLCipher opens it with the key of the vault, without a passphrase.
3. It checks the copy: the page checks of SQLCipher, the integrity of SQLite, the schema, and the digest of the content (a file that mixes pages of different copies fails).
4. It merges the copy into the vault, credential by credential (section 6), in one transaction.
5. When the vault has content that the file does not have, it pushes: it writes a copy in the work folder, removes the local data from it (section 1), shrinks it, copies it to `<name>.apassy.push.nosync`, syncs it, and renames it to `<name>.apassy`.

## 6. How changes merge

Each credential has a stable ID and a version: the time and the device of its last change, and a count of the changes of each device (a version vector). A delete leaves a tombstone with the same kind of version. A tombstone stays 180 days.

| This Mac | The synced file | Result |
| --- | --- | --- |
| has the credential | has a newer version of it | this Mac takes the newer version |
| has a newer version | has an older version | this Mac keeps its version; the next push sends it |
| changed it | changed it too, the same content | nothing to do |
| changed it | changed it too, other content | a conflict (below) |
| has it | has a tombstone that saw this version | the credential is deleted here |
| changed it after the delete there | has a tombstone | the credential stays, and comes back there |
| has a tombstone | has an older version | it stays deleted |
| does not have it | has it | this Mac adds it |

An old copy of the synced file (for example from a backup of the folder) has only older versions. It changes nothing and makes no conflict copy.

**A conflict** is a credential that both sides changed since they last saw each other's change, with different content. The later change (by time, then by device) wins. The other version stays as an archived credential "<title> (conflict copy, <device>)", without its variable and connector. Nothing is lost. A note says "Sync kept both versions in …". Open Credentials > Archived to compare, copy what you need, and delete the copy. Each Mac that sees the conflict makes the same copy, so it is there once.

**A variable name** that another credential on this Mac has already: the incoming credential comes without its variable, and a note says so. Rename one of the variables.

## 7. Status

Settings > General > Sync shows each synced vault with a tag and a line:

| Tag | Line | What to do |
| --- | --- | --- |
| Up to date | Up to date. Last sync 5 minutes ago. | nothing |
| Syncing | a change waits to sync | nothing: it syncs within seconds |
| Downloading | Waiting for iCloud to download the synced file. | wait; Apassy asked iCloud for the file (`brctl download`) |
| Needs the new passphrase | The passphrase changed on another Mac. Type the new passphrase. | section 8 |
| Folder not available | The synced folder is not available. | connect the drive or the share, or turn the sync service on; Apassy syncs when it is back |
| Damaged copy | The synced copy is damaged. | section 10 |

The line also names the file and the folder. The unlock screen shows "Waiting for iCloud to download…" and "Folder not available"; you can unlock the vault on this Mac at once.

## 8. A passphrase that changed on another Mac

The synced file has the passphrase of the Mac that pushed last. After a passphrase change on another Mac, it does not open with the key of this Mac. Apassy shows "The passphrase of <vault> changed on another Mac" and asks for the new passphrase once:

1. It checks the new passphrase with the synced file, and that the file holds this vault.
2. It rekeys the vault on this Mac to the new passphrase. The old one is not needed: the vault is unlocked.
3. It merges and pushes.

After that, unlock this Mac with the new passphrase. Touch ID unlock has the old passphrase: turn it on again in Settings > Security.

If you do not know the old passphrase any more, you cannot unlock this Mac's copy. Open the synced vault again with "Open a synced vault…" and the new passphrase; this Mac's agents need to be registered again.

## 9. Another Mac, or a teammate

1. The synced folder must be on the Mac: sign in to iCloud Drive, or set up Dropbox, Syncthing, or the share.
2. In Apassy, click "Open a synced vault…" on the welcome screen or the unlock screen, or in Settings > General > Sync.
3. Pick a file from the list (the `.apassy` files in the detected folders that are not in your list), or type the path of any `.apassy` file.
4. Type a name and the passphrase of the vault, and click "Open synced vault".

Apassy checks the file, makes the vault file `<data folder>/vaults/<name>.db`, adds it to the list with sync on, unlocks it, and syncs. It has no agents: register the agents of this Mac in Agents.

## 10. A damaged synced file

A synced file that opens with the key but fails a check (a damaged file, or one made of pages of different copies) is not merged. The vault on this Mac does not change. A note says so. If no other Mac can repair the file by its next push, choose "Replace with this Mac's vault…" in the note: Apassy writes the vault of this Mac in its place without a merge. A change that only the damaged file had is lost; a change that another Mac still has comes back at that Mac's next sync.

This is the one case where Apassy picks a whole version. There is no other "choose a version" step.

## 11. Share a vault with a small team

A synced file in a folder that several people share (a shared Dropbox or Google Drive folder, Syncthing, a network share) is a shared vault. Each person opens it with "Open a synced vault…" and the passphrase. Credentials merge as between your own Macs; agents, grants, and activity stay with each person.

Limits:

- Everyone with the passphrase can read and change every value of the vault. There is no role and no per-credential access.
- To remove a person, change the passphrase (Settings > Security) and rotate every credential in the vault at its provider. The person keeps the old copies and the old values.
- There is no audit of who read or changed what. The history of a credential names the change, not the person; the conflict copy names the device.
- Everyone can delete credentials, and the deletes sync.
- The passphrase is shared, so share it the way you share a password manager master password: in person, or through a channel you trust.

A shared collection with its own key (a group of credentials that syncs to its own file) is planned; the sync engine keeps each sync to a "scope" for it.

## 12. Turn off sync, and remove from list

- Pick "Off" in the Sync menu and confirm ("Turn off…" for a vault that is not open): Apassy removes the sync state and the setting. The vault on this Mac stays. The synced file stays in the folder, and the other Macs keep it. Delete it there if you do not want it. Turning sync on again with the same folder merges with the same file.
- "Remove from list…" of a synced vault turns off its sync first. The result says that the synced copy stays.

## 13. A damaged vault list

When Apassy rebuilds a damaged vault list ([several vaults](multiple-vaults.md), section 8), the new list has no sync setting. Apassy links each sync state in `<data folder>/sync/` to the vault file that it names, with its folder and file. Each sync checks the vault ID, so a different vault at that path never syncs. The note of the list says "Sync is on again for …". A vault in another folder is not in the rebuilt list: open it, then choose its folder again; Apassy merges with the same file.

## 14. Isolation

The Seatbelt profile denies read and write under the Apassy folder in iCloud Drive (`APASSY_CLOUD_DIR`). For a synced vault in another folder it denies only its files, not the folder, because an agent's projects can live in Dropbox too: the synced file, its push temporary file, and its SQLite companions (`APASSY_SYNC_FILE_1` to `APASSY_SYNC_FILE_16`, which `apassy-sandbox` reads from the vault list). It also denies a rename or a delete of the folders above the file. The sync state and the work copies are in the data folder, which the profile denies. See [isolation.md](isolation.md).

## 15. Tests

```
cargo test --locked --features vault --test folder_sync --test vault_migration
cargo test --locked --features vault --test relay_sync
cargo test --locked --features desktop,vault --lib sync
cargo test --locked --features vault --test isolation_profile -- icloud synced launcher
```

The engine (`tests/folder_sync.rs`):

| Test | What it shows |
| --- | --- |
| `two_macs_editing_different_credentials_merge_without_a_conflict` | Two Macs add and edit different credentials; both end with the same content. |
| `the_same_credential_edited_on_both_sides_gives_a_conflict_copy` | The later edit wins; the other is an archived copy on both Macs, once. |
| `concurrent_edits_converge_when_both_see_the_conflict` | A push over a file that the other Mac's push did not reach yet: the edits converge with one copy. |
| `deletes_propagate_and_a_tombstone_beats_an_old_copy` | A delete reaches the other Mac; an old copy does not bring the credential back. |
| `an_old_copy_no_longer_undoes_anything` | An old synced file changes nothing and makes no conflict copy. |
| `an_edit_that_the_delete_did_not_see_keeps_the_credential` | A concurrent edit beats a delete. |
| `agent_side_data_never_syncs_and_is_stripped_from_the_pushed_copy` | Each local table is empty in the pushed copy; the other Mac gets the variable and the connector, no agent. |
| `activity_alone_does_not_count_as_a_change` | Activity, a reveal, and an agent do not change the synced content. |
| `attach_uses_the_key_and_a_new_passphrase_on_another_mac_needs_the_prompt` | ATTACH with the key; after a change on another Mac: the prompt, the rekey, the merge. |
| `adopt_on_a_new_mac_and_a_wrong_passphrase_makes_no_file` | A new Mac opens the vault; a later edit merges without a conflict. |
| `a_small_team_shares_one_folder_and_keeps_its_own_agents` | Three data folders share one file; credentials merge; each keeps its agents. |
| `a_folder_outside_icloud_is_made_and_an_unreachable_one_is_calm` | A Dropbox-like folder, a missing folder, a download, a missing file. |
| `enable_picks_a_free_name_and_links_the_same_vault` | Another vault gets `-2`; the same vault links. |
| `a_damaged_or_foreign_file_is_refused_and_can_be_replaced` | A mixed-page file is `Damaged`; the last-resort replace; another vault does not open with the key. |
| `a_variable_name_that_is_taken_here_is_left_out_and_reported` | The variable collision. |
| `companion_files_refuse_the_push` | A journal, WAL, or SHM file stops a push. |
| `status_reports_duplicates_and_names` | The status, duplicates, names, and the folders. |

The app (`src/desktop/ui/sync_tests.rs`):

| Test | What it shows |
| --- | --- |
| `create_with_sync_writes_the_file_and_settings_shows_the_status` | The Create choice, the list on disk, the status in Settings. |
| `the_sync_picker_turns_on_moves_and_turns_off` | iCloud Drive, "Choose folder…", Off; the synced copy stays; no push after off. |
| `unlock_merges_before_the_list_and_a_lock_pushes` | The merge at unlock (typed and Touch ID) and the push at lock. |
| `a_change_syncs_after_a_pause_and_a_changed_file_merges_while_unlocked` | The pause before a push, and the merge of a changed file without a lock. |
| `agent_activity_alone_does_not_sync` | Activity does not push. |
| `both_macs_editing_one_credential_keep_both_versions_with_a_notice` | The conflict note and the archived copy. |
| `a_new_passphrase_from_another_mac_asks_once_and_rekeys` | The prompt, a wrong passphrase, the rekey. |
| `open_a_synced_vault_adds_it_with_sync_on` | The screen lists the Dropbox file; a wrong passphrase adds nothing. |
| `a_rebuilt_list_links_sync_again` | A damaged list links the sync again. |
| `the_switch_does_not_sync_into_the_wrong_vault` | A switch syncs the vault that it leaves; a vault without sync never reaches the folder. |
| `an_unreachable_folder_never_blocks_a_lock_or_an_unlock` | "Folder not available", and the lock and the unlock still work. |
| `remove_from_list_stops_sync_and_keeps_the_synced_file` | The texts; the state goes; the file stays. |
| `without_sync_the_app_shows_no_sync_control` | A unit test never uses a real synced folder. |
| `the_worker_pushes_and_merges_without_any_frame` | The worker pushes and merges with no frame of the window. |
| `the_worker_does_not_sync_while_a_run_waits_for_the_owner` | No sync while a run waits; the change syncs after. |
| `the_worker_does_not_sync_a_locked_vault` | A locked vault neither pushes nor merges; the unlock syncs. |
| `a_new_passphrase_found_by_the_worker_opens_the_sheet_in_the_next_frame` | The worker finds a new passphrase; the next frame asks for it. |
| `the_worker_thread_starts_only_with_sync_and_stops` | No thread without sync; the thread stops. |
| `the_picker_offers_the_relay_after_the_detected_folders` | The Sync menu: Off, the folders, "Apassy relay", "Choose folder…"; the Create screen has no relay. |
| `the_relay_setup_sheet_asks_for_the_address_the_team_code_and_the_name` | The sheet, the default address, the focus on its first field, a wrong team code, a plain `http://` address, and Return turns sync on with version 1 on the relay. |
| `add_a_mac_shows_a_link_then_the_safety_words_and_confirm_needs_the_owner_check` | The link and its QR code, "Waiting for the other device…", the same words on both Macs, the owner check for exactly that Mac (a wrong passphrase adds nothing), after it only "Added. …" and "Done", "Devices…", a wrong and a right passphrase on the new Mac, then "Sync now", a lock, and the worker. |
| `add_a_device_shows_the_link_as_a_qr_code_for_the_iphone` | The QR code of "Add a device…" holds exactly the text of the link, the sheet draws it black on white at about 180 points, and a new link gets a new QR code. |
| `the_team_code_field_is_masked_and_erased_after_each_try` | The team code does not show in the sheet, and a try with a used code erases it. |
| `removing_a_mac_asks_first_and_return_keeps_it` | "Remove" in "Devices…" asks first; Return presses Cancel, Escape closes the question only, and "Remove" in it removes the Mac. |
| `relay_statuses_read_as_in_the_adr` | The tags and lines of section 17.3, and "Relay not reachable" when the relay is away; a lock still works. |
| `turning_relay_sync_off_keeps_the_copy_and_the_last_mac_can_delete_it` | Off keeps the relay copy and removes the device key; the last Mac deletes the copy. |
| `a_mac_that_turned_relay_sync_off_joins_again_with_a_link_and_merges` | A Mac that left the team joins again with "Join from another Mac" and merges its own change. |
| `joining_a_relay_copy_under_another_passphrase_asks_for_it` | A join whose relay copy has another passphrase asks for the passphrase of the copy, and the step stays while the merge runs: a wrong one changes nothing and asks again, the right one merges and the vault takes the passphrase of the copy, and the other Mac syncs on; closing the sheet in that step removes the new device. |
| `turn_off_of_a_removed_or_last_mac_says_what_happened` | A removed Mac says "Removed from the relay" at its next sync; its "Turn off" asks the relay once (one challenge, no removal call) and says that it was no longer in the team; on the last Mac without the answer of its check, that it was the last Mac. |
| `a_removed_mac_offers_only_turning_relay_sync_off` | A removed Mac shows no "Sync now", "Add a device…", or "Devices…"; "Add a device…" and "Devices…" opened anyway show why, without "Check again", "New link", or "Refresh", and ask the relay nothing. |
| `use_the_relay_copy_asks_for_the_passphrase_of_an_older_copy` | After "Use the relay copy" a copy from before a passphrase change asks for the passphrase of the copy, merges with it, and the vault keeps the passphrase of this Mac. |
| `relay_calls_of_the_owner_leave_the_window_responsive` | With a slow relay, "Turn on", "Sync now", "Add a device…", and "Devices…" return at once, the window draws and keeps the vault, and the sheet shows what runs; the answers come later. |
| `cancel_of_a_waiting_mac_cancels_its_link_on_the_relay` | "Cancel" and a quit on a Mac that waits cancel its link on the relay; after a confirmation, "Cancel" removes the new device. |
| `switching_a_relay_vault_to_a_folder_leaves_the_relay_team` | Picking a folder for a relay vault asks in the "Turn off" sheet, removes this Mac from the relay team, then syncs with the folder; "Turn off" of a locked vault says that this Mac stays in the team. |
| `a_damaged_relay_copy_offers_replace_with_this_macs_vault` | A damaged relay copy shows "Replace with this Mac's vault…"; the sheet and the replace push version 3, and the other Mac keeps its change. |
| `received_by_shows_the_receipt_of_the_other_mac` | Settings reads the receipts of the other Macs and shows "Received by …". |
| `a_new_passphrase_from_another_mac_on_the_relay_rekeys_off_the_window_thread` | A passphrase that changed on another Mac: a wrong one keeps the sheet, the right one rekeys and syncs. |
| `a_lone_mac_after_a_relay_rollback_uses_the_relay_copy` | One Mac and a relay back from a backup: "Use the relay copy…", the sheet, and the merge and push with the same device; nothing is lost. |
| `a_refused_team_code_keeps_the_folder_sync` | A used team code keeps the folder sync and says so; a good code then moves the vault from the folder to the relay. |
| `the_sync_setting_waits_while_relay_sync_turns_on` | A folder pick while "Turn on" runs is refused at once; relay sync then turns on and syncs. |
| `a_lock_drops_the_relay_key_at_once` | A lock drops the relay key without a step of the worker. |

The app tests use the fake relay of the engine tests (`tests/common/fake_relay.rs`, included with `#[path]`).

The relay engine (`tests/relay_sync.rs`, against an in-process fake relay in `tests/common/fake_relay.rs`) covers a new team and its first push, push and pull between two Macs, a `412` followed by a merge and a new push with nothing lost, three lost rounds, a stale copy, the same version with another head, a forked chain, a head of a key outside the team, an oversized copy (refused by the app and by the relay), loopback `http://` allowed and other plain `http://` refused, a relay that calls itself by another address, a removed Mac (`a_removed_mac_signs_in_no_more_until_it_turns_sync_off`: one sign-in, then no relay call, also after a lock, while the other Mac goes on), a refusal that passes (`a_refused_challenge_is_asked_again_later_and_sync_comes_back`: a suspended relay, then one more sign-in at the next try), "Turn off" after a refusal (`turn_off_asks_the_relay_after_a_refusal`), a failed token call that is no removal (`a_refused_token_is_no_removal`), a join under another passphrase (`a_join_under_another_passphrase_takes_the_passphrase_of_the_copy`: the joining Mac has the old passphrase and takes the new one), a refused link, the long poll, and the contract test vectors checked with `ring`; `removing_the_mac_that_signed_the_head_keeps_sync_working`, `a_mac_far_behind_reads_the_chain_in_pages` (1100 heads), `a_merged_version_is_acknowledged`, `a_lock_ends_the_long_poll_at_once`, `a_429_waits_retry_after`, `a_transient_error_keeps_a_join_waiting`, `a_pending_join_can_be_cancelled`, `a_damaged_relay_copy_is_replaced_with_this_macs_vault`, `a_copy_with_a_new_passphrase_is_downloaded_once`, `a_failed_sync_after_a_new_passphrase_keeps_the_new_passphrase`, `a_copy_with_a_newer_schema_is_downloaded_once`, `a_lone_mac_uses_the_relay_copy_after_a_relay_rollback`, `receipts_ask_from_the_version_this_mac_saw`, `a_lock_ends_a_transfer_at_once`, `the_step_before_a_lock_skips_while_another_sync_runs`, and `the_step_before_a_lock_ends_within_its_limit`. The unit tests in `src/sync/relay_crypto.rs`, `src/sync/relay.rs`, and `src/sync/relay_http.rs` check the same vectors, the chain and signer rules, a cancelled long poll, one cancel that ends a download and a long poll together, and a deadline that ends a slow download; `the_worker_pulls_a_relay_vault_and_a_lock_drops_its_key`, `a_failing_pull_does_not_spin`, `an_early_long_poll_answer_does_not_spin`, `a_slow_relay_transfer_does_not_hold_the_vault`, `a_stop_ends_a_relay_transfer_at_once`, `a_relay_transfer_leaves_the_op_lock_free`, `the_waiter_of_a_removed_mac_tells_at_once_and_stops`, `the_worker_asks_a_removed_mac_nothing_more_and_other_vaults_go_on`, and `a_mac_refused_for_a_moment_syncs_again_at_its_next_try` (`src/desktop/sync_worker.rs`) check the worker and the waiter; `relay_links_are_skipped` (`src/bin/apassy-sandbox.rs`) checks the launcher.

Other suites: `unlock_migrates_each_earlier_schema_version_to_the_current_one`, `version_15_migration_adds_the_relay_device_table_and_is_atomic`, `two_copies_of_one_vault_get_the_same_record_uuids`, `a_failed_migration_from_version_13_keeps_the_old_version_and_data` (`tests/vault_migration.rs`); `profile_denies_the_icloud_folder`, `profile_denies_a_synced_file_and_keeps_its_folder_usable`, `launcher_passes_each_synced_file_outside_icloud` (`tests/isolation/product_profile.rs`); `synced_files_outside_the_denied_folders_get_a_parameter` (`src/bin/apassy-sandbox.rs`).

The tests use temporary folders. They do not test a sync service itself.

## 16. Limits

- A sync service delivers a file later, sometimes minutes later. Until then another Mac sees the older file.
- Two Macs can push at the same time; the sync service keeps one file (iCloud can keep the other as a duplicate). The change in the other file is not lost: that Mac still has it and pushes it again at its next sync.
- A conflict picks the later change by the clock of each Mac. A Mac with a wrong clock can win a conflict that it should lose; the other version is still kept as a copy.
- A tombstone stays 180 days. A Mac that was away longer can bring a deleted credential back.
- The unit of merge is a credential with all its settings: a change of the variable on one Mac and of the declaration of the same credential on another is a conflict.
- A person with the passphrase and the synced folder can write a valid file with any content. The other Macs merge it. The passphrase is the root key of the vault (ADR 0003).
- Evicted files: Apassy detects a `.<name>.icloud` placeholder and a dataless file (macOS 14 and later). The tests cover the placeholder only.
- A merge and a push hold the vault while they read and write the copy (milliseconds for a small vault). The broker waits for them.
- Apassy does not delete conflict copies, duplicates that a sync service made, or old synced files.

## 17. Sync through the Apassy relay (stage 1)

[ADR 0022](../adr/0022-relay-sync.md) adds a second way to sync a vault between your own Macs: the Apassy relay. The wire is in the [relay sync contract](../contracts/relay-sync-v1.md). A vault syncs through a folder or through the relay, never both. What syncs is the same as for a folder (section 1).

### 17.1 Turn it on

1. Open and unlock the vault. In Settings > General > Sync, open the menu of the vault and pick "Apassy relay". It is after the detected folders.
2. The sheet "Sync “<vault>” through the Apassy relay" has two ways:
   - "New relay copy": the relay address (`https://apassy-relay.wyderka.cc` by default), the team code from the operator of the relay (`apassy_tcd_…`; it works once, so the field is masked and its text goes after each try), and the name of this Mac. "Turn on" makes a team for the vault on the relay and a key for this Mac, and pushes the first copy. A wrong, used, or expired code changes nothing. A vault that syncs with a folder keeps its folder sync until relay sync is on, and keeps it when the relay refuses ("Folder sync stays on."). While relay sync turns on or off, the Sync menu of the vault waits.
   - "Join from another Mac": for a vault that is on the relay already, for example after relay sync was off on this Mac. Paste a link of "Add a device…" from a Mac that syncs the vault, select "Send link", and confirm on that Mac (17.2). Apassy merges the relay copy with this vault and pushes. A relay copy of another vault is refused. When the relay copy has another passphrase than this vault, the sheet asks for it: "The relay copy of “<vault>” uses another passphrase than this vault", with the field "Passphrase of the copy" and "Merge". The relay copy is the copy of your other Macs, so, as in section 8, the vault takes that passphrase, then merges the copy and uploads the result: you unlock it with the passphrase of the copy from then on. Touch ID unlock has the old passphrase: turn it on again in Settings > Security. An old passphrase of this Mac, maybe one that leaked, does not come back, and your other Macs go on with no question. A wrong passphrase changes nothing; type it again. The step stays on the screen while the merge runs. When the merge fails after the passphrase opened the copy (the network, a lock), the message says that the vault uses the passphrase of the copy now; join again, with no passphrase step. "Cancel" removes the new device of this Mac from the relay again.
3. A folder sync of the vault turns off first. Its synced file stays in the folder.

### 17.2 Add a device

"Add a device…" adds another Mac or an iPhone. The steps below are for a Mac; the iPhone app scans the QR code of the same link instead of a paste.

1. On a Mac that syncs the vault, select "Add a device…" in the row of the vault. The sheet "Add a device to “<vault>”" shows a QR code of the link for an iPhone, the link as text (`<relay address>/link#apassy_lnk_…`), and "Copy link". The QR code holds exactly the text of the link. The link works once, for 10 minutes, and gives nothing until you confirm. When it expires, the QR code goes and "New link" makes a new one.
2. On the new Mac, select "Use a vault from another Mac" on the welcome or unlock screen, then "Apassy relay". Paste the link, check the name of this Mac, and select "Connect". The new Mac shows "Waiting for the other Mac… Both Macs show:" and two safety words.
3. The first Mac asks the relay every 5 seconds. It shows "“Mac mini” asks to sync “Personal”. Both devices show:" with the words, "Confirm…", and "Refuse". Confirm only when both devices show the same words. "Confirm…" opens the owner check (Touch ID or the passphrase) for exactly that device; the prompt says `add the device "Mac mini" to the sync of this vault`. Then the sheet says "Added. Mac mini receives the vault now." and shows only that and "Done"
4. The new Mac downloads the copy and asks for the passphrase of the vault and a name on this Mac. A wrong passphrase makes no file: type it again. "Use this vault" makes the vault file `<data folder>/vaults/<name>.db`, adds it to the list with relay sync on, and unlocks it. It has no agents: register the agents of this Mac in Agents.

"Done" or Escape on the first Mac refuses a Mac that still waits. "Cancel" on the new Mac cancels its link on the relay, so the first Mac no longer shows it; after the confirmation it removes the new device instead. Quitting Apassy while the new Mac waits does the same, and the quit waits up to 3 seconds for the relay. What the relay does not hear stays: a link ends on its own within 10 minutes, and the Mac shows the note "The relay did not hear that this Mac cancelled…"; a device that stays shows in "Devices…" on the first Mac, where you can remove it.

### 17.3 Devices, Sync now, and the status

- "Devices…" lists the Macs of the vault on the relay, with "This Mac" and the last time each Mac signed in. "Remove" asks first: "Remove “Mac mini” from the relay? It keeps its vault but stops syncing. To add it again you need a new link and the owner check." Cancel has the focus, so Return keeps the Mac. "Remove" there ends the access of that Mac at once. It needs no owner check, because it only takes access away. A removed Mac keeps its copy of the vault and the passphrase: to lock a person out, also change the passphrase and rotate each credential.
- "Sync now" merges and pushes at once, then reads which Macs received the current version. While Settings shows the open vault, it reads them again every 15 seconds.
- When it syncs: as in section 4, with three changes. After an unlock the worker pulls in the background, so an unlock does not wait for the network. The worker pulls again every 5 minutes, and at once when another Mac pushed (a long poll). Before a lock, Apassy pushes only when a change waits, no other relay sync of the vault runs, and the last relay sync did not fail; that push ends within 10 seconds. Otherwise the change goes up after the next unlock.
- Every relay call that you start runs in the background: turning sync on with the first upload, "Add a device…" and its question every 5 seconds, "Confirm…", "Refuse", "Devices…", "Remove", "Sync now", turning it off, "Replace with this Mac's vault…", a new passphrase, and the link, the wait, the download, and the passphrase of a Mac that joins. The window stays responsive and shows what runs ("Apassy syncs with the relay…"); the button of a call that runs is dimmed. The result comes as the usual message. These calls take the vault only to read it or to write it, never while they wait for the relay.

| Tag | Line |
| --- | --- |
| Saved to the relay | Saved to the relay. Received by Mac mini 1 minute ago. |
| Sync pending | Saved on this Mac. A change waits for the relay. |
| Relay not reachable | Relay not reachable. Apassy syncs when it is back. |
| Sync pending | The relay asks Apassy to wait a minute. Apassy syncs after that. (A `429`; also a relay that stays busy.) |
| Sync paused | The relay limits the pushes of this vault for this hour. The changes stay on this Mac and sync later. |
| Damaged copy | The copy on the relay fails a check. Apassy did not use it, and does not download it again until it changes. |
| Removed from the relay | Removed from the relay. This Mac keeps its vault. Turn relay sync off, then join again with a link from another Mac. |
| Relay copy refused | The relay served a copy that does not include this Mac's last change (or an older copy than this Mac saw). To go on, select “Use the relay copy…” in Settings > General > Sync. |
| Needs a passphrase | as in section 8; after "Use the relay copy": The copy on the relay uses another passphrase than this vault. It can be from before a passphrase change. Type the passphrase of that copy. |

A Mac that another Mac removed shows "Removed from the relay" as soon as the relay refuses it: at its next sync, or when its long poll ends (at most 25 seconds later). From then on Apassy makes no relay call for that vault: no sign-in, no long poll, no sync, no device call, also after a lock and an unlock, and the step before a lock does not push. The vault on this Mac stays, and folder sync and the other vaults go on. A relay that is suspended or stops refuses a Mac the same way, so Apassy asks once more 15 minutes after the last refusal, and after a new start of the app: when the relay knows the Mac again, sync goes on and the status goes. Turn relay sync off ("Off" in the menu: Apassy asks the relay to remove this Mac, and the message says when it was no longer in the team), then use "Join from another Mac" with a new link to sync again. While the vault shows "Removed from the relay", Settings has only the sync menu for it: "Sync now", "Add a device…", and "Devices…" do not show, since each of them would fail at once.

"Received by …" needs a receipt from the other Mac: each Mac sends one after it merged a version from the relay, and after it adopted the vault. Until the other Mac merged the newest version, the line says "Last sync …". A receipt without a name says "Received by another Mac". The sidebar says "Synced 2 minutes ago · Apassy relay".

A damaged copy also shows the note "The copy of “<vault>” on the relay fails a check" with "Replace with this Mac's vault…". The sheet "Replace the damaged copy on the relay?" says what is lost; "Replace" uploads the vault of this Mac as a new version over the damaged one, without a merge, and the other Macs merge it at their next sync. Changes that only the damaged copy had are lost; a change that another Mac still has comes back when that Mac syncs. A copy of another vault on the relay is not replaced: "Delete the copy on the relay" is the way out.

A refused copy ("Relay copy refused") shows "Use the relay copy…" for the open vault. That happens when the relay comes back from a backup, or when its history does not include the last change of this Mac. The sheet "Use the copy on the relay?" asks you to look at "Devices…" first. "Use the relay copy" takes the relay copy as it is now, as at a first sync: Apassy still checks that a device of the team signed it and that it holds this vault, merges it with the vault on this Mac, and uploads the result. Nothing on this Mac is lost, and this Mac stays in the relay team, so this works also for the last Mac of a team. When the relay copy has another passphrase (a backup from before a passphrase change), Apassy asks for that passphrase next: "The relay copy of “<vault>” uses another passphrase" with the field "Passphrase of the copy" (and "Type the passphrase of the copy…" in Settings). Unlike section 8, the vault does not take that passphrase: it only opens the copy for the merge, the vault keeps the passphrase of this Mac, and the merged vault goes up under it. So an old passphrase, maybe one that leaked, does not come back. The message says "Apassy merged the relay copy into “<vault>”, which keeps the passphrase of this Mac." Your other Macs that still use the passphrase of the copy then ask for the passphrase of this Mac, as in section 8. A damaged copy shows "Replace with this Mac's vault…" next.

### 17.4 Turn it off

Pick "Off" in the menu of the vault and confirm. The key of this Mac for the relay is in the vault, so the vault must be open and unlocked: for a locked vault, or one that is not open, the sheet asks you to open and unlock it first. The vault on this Mac stays. The copy on the relay stays, and the other Macs keep syncing with it. For an open vault, the key of this Mac leaves the vault, and this Mac leaves the relay team when another Mac stays in it. To sync this Mac again, use "Join from another Mac" with a new link. The last Mac of the team gets the switch "Delete the copy on the relay": Apassy then deletes every version of the copy on the relay. Without it, the message says that only the operator of the relay can delete the copy now.

Picking a folder for a vault on the relay (in the menu, or "Choose folder…") opens the same sheet first: "Sync “<vault>” with <folder> instead of the relay?" with "Switch". This Mac leaves the relay team, then the vault syncs with the folder.

The message says what stays on the relay. When this Mac cannot leave the team (the relay does not answer), it says "This Mac is still in the relay team (…): remove it in “Devices…” on another Mac." A Mac that the relay does not know says "This Mac was no longer in the relay team. If the relay was paused and this Mac still shows in “Devices…” on another Mac, remove it there." The relay keeps the last Mac of a team; when Apassy did not know that this Mac is the last, the message says so after the relay answered. "Remove from list…" turns relay sync off and keeps the relay copy; this Mac stays in the team, and the message says so.

### 17.5 The engine

- The relay keeps one copy per vault: the same stripped, encrypted copy as a folder file. Each copy has a version and a head that the pushing Mac signs with its device key. A push sends `If-Match` with the version that the Mac saw; a `412` means that another Mac pushed first, so the Mac merges that copy and pushes again, at most three times. After that the change stays on the Mac for the next sync.
- Before a merge the Mac checks the head: a device of the team signed it, it holds this vault, its version is above the one this Mac saw last, and the chain of heads since then includes that version. A failure merges nothing. "Use the relay copy…" is the way out of an older or a forked copy (`RelaySync::use_relay_copy`): the Mac forgets the version it saw and keeps its device.
- The keys that check the heads come with the relay's answer. A Mac that was removed ("Devices…" > "Remove", or "Off" while another Mac stays) stays a signer of the versions it pushed while it was in the team, so the other Macs keep syncing on top of its last copy. It cannot push again, and a head of it above its last push is refused.
- A Mac that was away for more than 1000 versions reads the chain of heads in pages of 1000 and catches up. The relay keeps the newest 10000 heads; a Mac further behind gets "Relay copy refused".
- A damaged relay copy ("The copy on the relay fails a check.") can be replaced with the vault of this Mac: the engine pushes a new version over it, signed as usual, without a merge (`RelaySync::replace_relay_copy`; the app uses `replace_relay_copy_shared`). The other Macs then sync with it.
- The app runs each relay call of the owner on its own thread. A device call reads the device key from the unlocked vault first, with no network, then signs in with the key in memory (`KeySource::Memory`). A call that changes the vault (turning sync on, joining, "Sync now", a replace, "Use the relay copy", a new passphrase) uses the `*_shared` calls of the engine: they hold the vault only for each local step. One relay sync of a vault runs at a time; no relay call holds the sync op lock, so the window never waits for a transfer. "Turn off" pauses the relay sync of the vault while the device leaves the team (`RelaySync::pause`: the sync that runs ends, and a sync that waits for it does not start), and ends the relay sync that runs before it removes the key (`RelaySync::stop_runs`). A lock ends every relay call in flight at once, also a device call, a TCP connect, and a TLS handshake. The step before a lock pushes with the vault held, because the lock holds it; so it pushes only when no other relay sync of the vault runs and the last one did not fail, and its relay calls end within 10 seconds (`RelaySync::sync_within`).
- The new Mac of "Use a vault from another Mac" can take back its request before the first Mac confirms it (`PendingJoin::cancel`): the first Mac no longer shows it. After the confirmation the cancel removes the new device. While it waits, a network failure or a busy relay does not end the join: it asks again after 2 seconds, then 4, up to 60.
- The device key is in the vault, in the local table `relay_device` (schema 16): a sync copy never carries it, and the agent sandbox cannot read it. So the Mac syncs through the relay only while the vault is unlocked. A lock drops the key and the access token from memory.
- The relay address must be `https://`. Plain `http://` works only for `127.0.0.1`, `localhost`, or `[::1]` with a port, for tests.
- A copy has at most 64 MiB. Apassy refuses a larger one before it sends or downloads it.
- The sync state of a relay vault has format 3: the relay, the team, the device, and the version and head hash that the Mac saw last. A folder state stays format 2. A rebuilt vault list links a relay state again, as in section 13.
- The vault list keeps `sync.relay` (the relay address, the team ID, and the device number) and no folder or file. `apassy-sandbox` skips such a vault: there is no synced file to deny. An older launcher stops on such a list, so the app and the launcher ship together.
- The worker pulls a relay vault at the first step after an unlock, every 5 minutes, and at the retry time after a failed pull. A waiter thread holds a long poll on the relay (25 seconds) and makes the worker pull at once when another Mac pushed.
- Nothing asks the relay again and again. A relay sync of the worker that fails waits 5 seconds before the next one, then 10, 20, 40, and 60 (60 at least when the relay asked to wait with `429`); a command of the window starts again at once. The waiter tells the worker of one new version once, and waits the same way after an error or an answer that brought nothing new. A copy that needs the new passphrase, whose bytes are damaged, that is too large, that holds another vault, or that has a newer schema (another Mac runs a newer Apassy) is downloaded once: the next syncs say so from the head alone, until the head changes, you act, or the vault locks. A new passphrase checks the copy and merges it with one download. While an agent run waits for you, the pull waits too.
- The worker takes the vault only to read it, to merge, and to write the copy to push. The downloads and the uploads run without it, so the window and the agents keep the vault while a copy goes to or comes from the relay.
- A lock ends the long poll and a download or an upload in flight at once, and drops the key and the access token. The worker also looks at the lock every second while the key is in memory. A download or an upload ends after 10 minutes in any case. A quit stops the worker without waiting for a transfer, and ends the relay calls of the owner that run.
- Receipts ("Received by …") are read from the version that this Mac saw, so the answer has no chain of older heads.
