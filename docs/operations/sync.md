# Sync through a folder

Date: 2026-09-28.
Decision: [ADR 0014](../adr/0014-icloud-sync.md). Related: [several vaults](multiple-vaults.md), [backup and restore](backup-restore.md), [isolation](isolation.md).
Use only synthetic values for tests. The real-secret gate stays BLOCKED.

A vault can sync with your other Macs, or with a small team, through a folder that a sync service keeps in step: iCloud Drive, Dropbox, Google Drive, OneDrive, Syncthing, or a network share. Changes from each Mac merge by credential. In normal use there is nothing to choose and no passphrase to type.

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
2. In Settings > Vaults, find the section "Sync". Open the menu in the row of the vault (it says "Off").
3. Pick "iCloud Drive", another detected folder (Dropbox, Google Drive, OneDrive), or "Choose folder…" and type the path of any folder that a sync service keeps in step.

Apassy then:

1. makes the folder when its parent exists,
2. picks the name `<vault name>.apassy`. When a file with that name does not open with the key of this vault, or holds another vault, it tries `<vault name>-2.apassy`, `-3`, and so on.
3. writes the first copy. When the file already holds this vault (sync was on before, or another Mac turned it on), Apassy merges with it instead.

No passphrase: the unlocked vault has the key. A vault name that ends in a space and a number (`Work 2`) gets a `-` (`Work-2.apassy`), so it does not look like a duplicate that iCloud made.

The detected folders are iCloud Drive, each folder in `~/Library/CloudStorage` (Dropbox, Google Drive, OneDrive, and other File Provider services), and `~/Dropbox`.

## 4. When it syncs

- **At unlock**, before you see the list. A merge that brought changes says so: "Sync brought 2 changed credentials from Mac mini."
- **While the vault is unlocked**: every 30 seconds Apassy looks at the synced file and merges it when it changed. A few seconds (5 to 8) after you stop changing credentials, it pushes.
- **Before each lock**: "Lock now", the lock button, a switch to another vault, "New vault…" or "Open vault file…" from an open vault, a backup, a restore over an open vault, a quit, and "Restart now" for an update.
- **"Sync now"** in Settings > Vaults.

Never while an agent run waits for you. A sync never stops a lock or a quit: a failure shows once as a note, and the changes stay on this Mac until the next sync.

Agent use writes the activity log, but that is not synced content: it does not start a push.

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

Settings > Vaults > Sync shows each synced vault with a tag and a line:

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
2. In Apassy, click "Open a synced vault…" on the welcome screen or the unlock screen, or in Settings > Vaults.
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

Other suites: `unlock_migrates_each_earlier_schema_version_to_the_current_one`, `two_copies_of_one_vault_get_the_same_record_uuids`, `a_failed_migration_from_version_13_keeps_the_old_version_and_data` (`tests/vault_migration.rs`); `profile_denies_the_icloud_folder`, `profile_denies_a_synced_file_and_keeps_its_folder_usable`, `launcher_passes_each_synced_file_outside_icloud` (`tests/isolation/product_profile.rs`); `synced_files_outside_the_denied_folders_get_a_parameter` (`src/bin/apassy-sandbox.rs`).

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
