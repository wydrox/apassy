# iCloud sync

Date: 2026-09-28.
Decision: [ADR 0014](../adr/0014-icloud-sync.md). Related: [several vaults](multiple-vaults.md), [backup and restore](backup-restore.md), [isolation](isolation.md).
Use only synthetic values for tests. The real-secret gate stays BLOCKED.

The app shows iCloud sync on macOS. Where there is no iCloud Drive (Linux), it shows nothing about iCloud.

## 1. What syncs

- The whole vault file: items, secrets, declarations, environment variables, connectors, agents, grants, rules, the history, and the activity log.
- iCloud Drive holds a closed, encrypted copy of the vault in `~/Library/Mobile Documents/com~apple~CloudDocs/Apassy/<name>.apassy`. The copy has the format of a backup and the passphrase of the last push.
- The vault file on each Mac stays the working vault. SQLite never opens a file in iCloud Drive.
- These do not sync: the lock file (`<vault>.lock`), the vault list and the settings of this Mac, the Touch ID unlock, the Laya model, and the sync state.
- Each vault has its own setting. A vault without it never goes to iCloud.

## 2. Files

| File | Place | Content |
| --- | --- | --- |
| cloud copy | `<iCloud Drive>/Apassy/<name>.apassy` | the encrypted vault at the last push |
| push temporary file | `<iCloud Drive>/Apassy/.<name>.push.nosync` | exists only during a push; iCloud does not sync it |
| sync state | `<data folder>/icloud/<list ID>.json` (mode `0600`) | cloud file name, vault ID, vault file, SHA-256 and generation of the last push or pull. No secret. |
| setting | `<data folder>/vaults.json`, field `cloud` of the vault | the name of its sync state file |
| pull temporary file | `<vault>.sync-incoming` | exists only during a pull |
| conflict copies | `<data folder>/conflicts/` (mode `0700`) | `<name>-icloud-<time>.apassy`, `<name>-this-mac-<time>.apassy` |

`<time>` is UTC, `YYYYMMDD-HHMMSS`. The data folder is `~/Library/Application Support/Apassy`.

## 3. Turn on sync

For a new vault: on the Create screen, turn on "Keep a copy in iCloud Drive". Apassy creates the vault, then turns on sync with the passphrase that you typed.

For a vault that you have:

1. Open and unlock the vault.
2. In Settings > Vaults, find the section "iCloud Drive". Click "Turn on iCloud sync…" in the row of the vault.
3. Type the passphrase of the vault, and click "Turn on".

Apassy then:

1. checks the passphrase against the vault,
2. makes the Apassy folder in iCloud Drive when it is missing,
3. picks the name `<vault name>.apassy`. When a file with that name holds another vault, it tries `<vault name>-2.apassy`, `-3`, and so on. A file holds this vault when it opens with the passphrase and has the vault ID of this vault.
4. pushes the first copy. When the file already holds this vault (sync was on before), Apassy does not push: equal files are in sync, other files are a conflict (section 8).

A vault name that ends in a space and a number (`Work 2`) gets a `-` (`Work-2.apassy`), so it does not look like an iCloud duplicate.

When iCloud Drive is off on the Mac, the option and the button do not work, and the app says "iCloud Drive is off on this Mac".

## 4. Status

Settings > Vaults > iCloud Drive shows each vault with a tag and a line. Apassy reads the status without the passphrase, every 30 seconds, and every 2 seconds while iCloud downloads the copy of the open vault.

| Tag | Line | Next step |
| --- | --- | --- |
| In sync | In sync with iCloud. Last sync 5 minutes ago. | none |
| Not uploaded | Changes on this Mac are not uploaded yet. | none: Apassy pushes at the next lock or within a few minutes; or "Sync now" |
| Newer in iCloud | A newer copy from another Mac is in iCloud, saved 2 minutes ago. | lock, then unlock |
| Conflict | This Mac and iCloud both changed the vault. | "Choose version…" (section 8) |
| Missing in iCloud | The copy in iCloud is missing. | "Sync now" uploads it again |
| Downloading | Downloading from iCloud… | wait; Apassy asked iCloud for the file (`brctl download`) |
| iCloud Drive off | iCloud Drive is off on this Mac. | turn on iCloud Drive |
| Off | iCloud sync is off. | "Turn on iCloud sync…" |

The line also names the iCloud file. When iCloud made its own duplicates of the file (`Personal 2.apassy`), a note says so. Apassy does not use a duplicate. Open it from iCloud as a separate vault to see what it has, or delete it in Finder.

The status knows when the iCloud copy was saved, from the file time. It does not know which Mac saved it: that name is inside the encrypted copy. The result of a pull names the Mac.

While a vault is open, a banner on each page shows a newer copy in iCloud ("Lock and unlock to load it", with "Lock now") and a conflict ("Choose version…").

## 5. Push

Apassy pushes the open vault when it has changes:

- before each lock: "Lock now", the lock button, a switch to another vault, "New vault…" or "Open vault file…" from an open vault, a backup, a restore over an open vault, a quit, and "Restart now" for an update,
- every few minutes (at most every 3 minutes) while the vault is unlocked and no agent run waits for you,
- when you click "Sync now".

The push before a lock runs after the runs that wait have ended, so the copy does not hold a waiting run. It does not stop the lock: a failure shows once as a note, and the changes stay on this Mac. A push does not happen when the iCloud copy changed too (a conflict), when the copy is still downloading, or when iCloud Drive is off.

The engine then:

1. refuses the push when the cloud file changed since the last sync, or is not downloaded,
2. refuses the push when a `-journal`, `-wal`, or `-shm` file is next to the vault file,
3. raises the generation in one transaction, and writes the name of this Mac, the time, and a digest of the content into the vault,
4. copies the vault file to `.<name>.push.nosync`, syncs it, renames it to `<name>.apassy`, and syncs the folder,
5. writes the SHA-256 and the generation to the sync state.

Each agent use writes the activity log, so an unlocked vault is often "Not uploaded" for a few minutes.

## 6. Pull

Apassy pulls when you unlock a vault with a newer copy in iCloud. It uses the passphrase that you type, or the one that Touch ID gives.

1. Apassy refuses the pull when this Mac has changes that are not in iCloud (that is a conflict), or when a `-journal`, `-wal`, or `-shm` file is next to the vault file.
2. It copies the cloud file to `<vault>.sync-incoming`.
3. It checks the copy with the passphrase: cipher settings, schema, integrity, and the content digest. A wrong passphrase or a damaged copy stops the pull.
4. It refuses a copy of another vault (another vault ID).
5. It refuses an older copy (section 9).
6. It renames the copy over the vault file. The unlock then opens it. A copy from an older Apassy migrates at that unlock.

The result says "The vault is unlocked. Apassy loaded the newer copy from <Mac>, saved <time>."

When a step fails, the file on this Mac does not change, and the unlock still opens it. A note "Apassy did not load the iCloud copy" says why: an older copy, two Macs that saved at the same time, another vault in the iCloud file, or a passphrase that does not open the copy.

Unlike a restore, a pull keeps agents, grants, and rules. The passphrase authenticates the copy, and the generation check refuses an old one. ADR 0014, section 6, has the reasons and the limit.

After a passphrase change on another Mac, type the new passphrase at the unlock. The pull loads the copy with the new passphrase, and the unlock opens it. Touch ID unlock on this Mac then has the old passphrase: turn it on again in Settings > Security.

While iCloud downloads the copy, the unlock screen says "Downloading from iCloud…". You can unlock the file on this Mac at once; Apassy checks the copy again when the download ends.

## 7. A new Mac

1. Sign in to iCloud Drive and wait for the Apassy folder.
2. In Apassy, click "Open a vault from iCloud…" on the welcome screen or the unlock screen, or in Settings > Vaults.
3. Apassy lists the vaults in iCloud Drive that are not in your list. A file that is not downloaded says so; a click asks iCloud for it.
4. Click the vault, type a name (the name of the iCloud file is the default) and its passphrase, and click "Open from iCloud".

Apassy checks the copy, makes the vault file `<data folder>/vaults/<name>.db`, adds it to the list with sync on, and unlocks it. It accepts any generation, because this Mac has no earlier one. The agents and rules come with the vault; the agent hosts on this Mac need their own tokens.

## 8. Conflicts

Both Macs changed the vault since the last sync. Apassy does not merge. You choose, and Apassy keeps the other version as a file.

Where: the banner "This Mac and iCloud both changed …" and "Choose version…" in Settings > Vaults open the sheet "Choose which version to keep". On the unlock screen, the same two buttons use the passphrase in the field. "Unlock" there opens the version of this Mac and keeps the choice for later.

- "Keep this Mac's version": Apassy saves the iCloud copy to `conflicts/<name>-icloud-<time>.apassy`, then pushes. It reads the generation of the iCloud copy with the passphrase, so the push gets a higher one and the other Macs accept it.
- "Use the iCloud version": Apassy saves the file of this Mac to `conflicts/<name>-this-mac-<time>.apassy`, then pulls. In the sheet, Apassy locks the vault for the pull and unlocks it again with the same passphrase. It checks the passphrase first, so a typo does not lock you out.

A note then says where the other version is. To see it: "Open vault file…" with that path, and the passphrase of its time. Copy what you need by hand, then remove it from the list.

"Keep this Mac's version" also puts this Mac's version back when the iCloud copy is older (section 9).

## 9. Rollback refusal

Each push raises the generation in the vault. The sync state keeps the generation of the last push or pull on this Mac. A pull refuses:

- a copy with a lower generation: "The iCloud copy is older than the copy that this Mac synced last". Someone put an old copy back, or iCloud delivered an old push late.
- a copy with the same generation and other content: two Macs pushed from the same copy. Choose "Use the iCloud version" or "Keep this Mac's version". "Use the iCloud version" accepts the same generation; it still refuses a lower one.

In both cases the file on this Mac does not change.

## 10. Turn off sync, and remove from list

- "Turn off…" in Settings > Vaults > iCloud Drive: Apassy removes the sync state and the setting. The vault on this Mac stays. The iCloud file stays, and the other Macs keep it. Delete it in Finder if you do not want it there. Turning sync on again links to the same file (section 3).
- "Remove from list…" of a synced vault turns off its sync first. The result says that the iCloud copy stays. The vault then shows in "Open a vault from iCloud…" again.

## 11. A damaged vault list

When Apassy rebuilds a damaged vault list ([several vaults](multiple-vaults.md), section 8), the new list has no iCloud setting. Apassy links each sync state file in `<data folder>/icloud/` to its vault again when it can prove the match: the state names the vault file, and the file has the SHA-256 of the last sync. The note of the list then says "iCloud sync is on again for …". A vault that changed after its last sync, or a vault in another folder, is not proven: the note says to turn iCloud sync on again. Turning it on again links to the same iCloud file.

## 12. Isolation

The Seatbelt profile denies read and write under the Apassy folder in iCloud Drive (`APASSY_CLOUD_DIR`), and `<vault>.sync-incoming` like the vault. `apassy-sandbox` passes the folder by default; `--cloud-dir` changes it. The sync state and the conflict copies are in the data folder, which the profile denies. See [isolation.md](isolation.md).

## 13. Tests

```
cargo test --locked --features vault --test icloud_sync --test vault_migration
cargo test --locked --features desktop,vault --lib icloud
cargo test --locked --features vault --test isolation_profile -- icloud launcher
```

The engine (`tests/icloud_sync.rs`):

| Test | What it shows |
| --- | --- |
| `push_then_pull_round_trip_on_a_second_mac` | Enable, the copy while unlocked opens with the passphrase and has the same items, adopt on a second Mac, push, pull; the agent and its grant stay. |
| `status_reports_each_state` | Each status, and a push after the folder and iCloud Drive were gone. |
| `pull_refuses_an_older_copy` | A lower generation is refused; "Keep this Mac" puts the newer copy back. |
| `equal_generation_with_other_content_needs_the_owner` | Two pushes from the same copy; the pull refuses, "Use iCloud" accepts and saves this Mac's copy. |
| `conflict_keep_this_mac_saves_the_icloud_copy_then_pushes` | The conflict copy, the higher generation, and the pull on the other Mac. |
| `conflict_use_icloud_saves_this_mac_then_pulls` | The conflict copy of this Mac, then the pull. |
| `wrong_passphrase_leaves_the_local_file_untouched` | Pull, "Use iCloud", and adopt with a wrong passphrase change nothing. |
| `companion_files_refuse_the_push_and_the_pull` | A journal, WAL, or SHM file stops a push and a pull. |
| `evicted_cloud_file_is_not_downloaded` | A `.icloud` placeholder is "Not downloaded" for status, push, pull, list, and adopt. |
| `icloud_duplicates_are_reported` | `Personal 2.apassy` and an evicted `Personal 3.apassy` are duplicates. |
| `enable_picks_a_free_name_and_links_the_same_vault` | Another vault gets `-2` or `-3`; the same vault links. |
| `pull_refuses_another_vault_at_the_cloud_name` | Another vault ID is refused. |
| `a_copy_that_mixes_pages_of_two_pushes_is_refused` | SQLCipher accepts a mixed file; the content digest refuses it. |
| `adopt_accepts_a_vault_file_put_in_icloud_by_hand` | A vault that was never pushed (generation 0) can be adopted. |

The app (`src/desktop/ui/icloud_tests.rs`):

| Test | What it shows |
| --- | --- |
| `create_with_icloud_on_pushes_the_first_copy` | The Create option, the setting in the list on disk, the status in Settings. |
| `turn_on_and_off_in_settings_keeps_the_icloud_file` | The sheets, a wrong passphrase, "off" keeps the file and stops the push, "on" again links. |
| `lock_pushes_and_a_failed_push_does_not_block_the_lock` | A lock and a poll push; without iCloud Drive the lock and the unlock work and the failure shows once. |
| `unlock_pulls_a_newer_copy_and_the_banner_says_so` | The banner, the unlock screen, the pull at unlock, and the pull at a Touch ID unlock. |
| `a_refused_copy_does_not_block_the_unlock_of_this_mac` | An older copy and another vault are refused with a note; the file of this Mac unlocks. |
| `the_conflict_sheet_keeps_this_mac_and_saves_the_icloud_copy` | The banner, the sheet, no push at a lock during a conflict, the choice on the unlock screen, the conflict copy. |
| `the_conflict_sheet_uses_the_icloud_version_and_saves_this_mac` | A wrong passphrase keeps the vault unlocked; the choice saves this Mac's file. |
| `open_a_vault_from_icloud_adds_it_to_the_list` | The screen lists the vault; a wrong passphrase adds nothing; the vault goes to `vaults/` with sync on. |
| `a_rebuilt_list_links_a_proven_vault_again` | A damaged list links the proven vault and asks to turn on the other again. |
| `the_switch_does_not_push_into_the_wrong_vault` | A switch pushes the vault that it leaves; a vault without sync never reaches iCloud; two synced vaults keep their own files. |
| `downloading_shows_on_the_unlock_screen_and_does_not_block_it` | "Downloading from iCloud…" and the unlock of the file on this Mac. |
| `remove_from_list_stops_sync_and_keeps_the_icloud_file` | The sheet text, the result text, the state goes, the file stays. |
| `sync_now_and_quit_push_the_changes` | "Sync now", its text for a newer copy, and the push at quit. |
| `no_icloud_folder_hides_icloud` | Without an iCloud Drive path the app shows no iCloud control, and a unit test never uses the real iCloud Drive. |

Other suites: `unlock_migrates_each_earlier_schema_version_to_the_current_one` (`tests/vault_migration.rs`), `profile_denies_the_icloud_folder` and `launcher_passes_the_installed_and_the_build_app` (`tests/isolation/product_profile.rs`).

The tests use a temporary folder as iCloud Drive. They do not test iCloud itself.

## 14. Limits

- iCloud delivers a push later, sometimes minutes later. Until then another Mac sees the old copy.
- A person with the passphrase and access to the iCloud account can put a valid copy with a high generation in iCloud. The other Macs accept it.
- The status does not name the Mac of a newer copy; it gives the time of the file.
- Evicted files: Apassy detects a `.<name>.icloud` placeholder and a dataless file (macOS 14 and later). The tests cover the placeholder only.
- A write to the vault by another SQLite client during a push is not supported, as for a backup.
- A push holds the vault while it copies the file (milliseconds for a small vault). The broker waits for it.
- Apassy does not delete conflict copies, iCloud duplicates, or old cloud files.
- A rename of a vault does not rename its iCloud file. The other Macs keep their own names for it.
- When the iCloud copy with the vault name opens with another passphrase (it was changed on another Mac), turning sync on treats it as another vault and picks a new name. Unlock on a Mac where sync is on instead.
- A crash after the rename and before the state write leaves an old hash in the sync state. The status then shows "In sync" (the files are equal), and the next push or pull writes the state again.
