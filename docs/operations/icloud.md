# iCloud sync

Date: 2026-09-28.
Decision: [ADR 0014](../adr/0014-icloud-sync.md). Related: [backup and restore](backup-restore.md), [isolation](isolation.md).
Use only synthetic values for tests. The real-secret gate stays BLOCKED.

Status: the sync engine (`apassy::cloud`), schema version 13, and the Seatbelt rule are in the code. The desktop steps below come in phase 2 and are marked "(phase 2)".

## 1. What syncs

- The whole vault file: items, secrets, declarations, environment variables, connectors, agents, grants, rules, the history, and the activity log.
- iCloud Drive holds a closed, encrypted copy of the vault in `~/Library/Mobile Documents/com~apple~CloudDocs/Apassy/<name>.apassy`. The copy has the format of a backup and the passphrase of the last push.
- The live vault stays a local file on each Mac. SQLite never opens a file in iCloud Drive.
- These do not sync: the lock file (`<vault>.lock`), the settings of this Mac, the Touch ID unlock, the Laya model, and the local sync state.

## 2. Files

| File | Place | Content |
| --- | --- | --- |
| cloud copy | `<iCloud Drive>/Apassy/<name>.apassy` | the encrypted vault at the last push |
| push temporary file | `<iCloud Drive>/Apassy/.<name>.push.nosync` | exists only during a push; iCloud does not sync it |
| sync state | `<data folder>/icloud/<vault>.json` (mode `0600`) | cloud file name, vault id, SHA-256 and generation of the last push or pull. No secret. |
| pull temporary file | `<vault>.sync-incoming` | exists only during a pull |
| conflict copies | `<data folder>/conflicts/` (mode `0700`) | `<name>-icloud-<time>.apassy`, `<name>-this-mac-<time>.apassy` |

`<time>` is UTC, `YYYYMMDD-HHMMSS`. The data folder is `~/Library/Application Support/Apassy`.

## 3. Turn on sync

1. Unlock the vault.
2. (phase 2) In the settings of the vault, turn on "Sync with iCloud", and type the passphrase.

Apassy then:

1. checks the passphrase against the vault,
2. makes the Apassy folder in iCloud Drive when it is missing,
3. picks the name `<vault name>.apassy`. When a file with that name holds another vault, it tries `<vault name>-2.apassy`, `-3`, and so on. A file holds this vault when it opens with the passphrase and has the vault id of this vault.
4. pushes the first copy. When the file already holds this vault (sync was on before), Apassy does not push: equal files are in sync, other files are a conflict (section 7).

A vault name that ends in a space and a number (`Work 2`) gets a `-` (`Work-2.apassy`), so it does not look like an iCloud duplicate.

## 4. Status

Apassy compares the files. It needs no passphrase.

| Status | Meaning | Next step |
| --- | --- | --- |
| In sync | both files are as at the last sync, or equal | none |
| Push needed | this Mac changed the vault | push |
| Pull available | another Mac pushed | lock, then pull |
| Conflict | both changed | choose (section 7) |
| Cloud copy missing | the file or the Apassy folder is gone | push writes it again |
| Not downloaded | the file is in iCloud but not on this Mac | wait; Apassy asks iCloud for the download (`brctl download`) |
| iCloud not available | no iCloud Drive folder (signed out, or Linux) | sign in to iCloud Drive |

The status also lists iCloud duplicates of the cloud file (`Personal 2.apassy`). Apassy does not use them. Adopt one as a separate vault to see its content, or delete it in Finder.

Each agent use writes the activity log, so the status often says "Push needed". (phase 2) The app pushes when the owner locks the vault.

## 5. Push

The vault is unlocked, and stays unlocked. (phase 2) "Send to iCloud", or automatic at lock.

1. Apassy refuses the push when the cloud file changed since the last sync, or is not downloaded.
2. It refuses the push when a `-journal`, `-wal`, or `-shm` file is next to the vault file.
3. One transaction raises the generation, and writes the name of this Mac, the time, and a digest of the content into the vault.
4. Apassy copies the vault file to `.<name>.push.nosync`, syncs it, renames it to `<name>.apassy`, and syncs the folder.
5. It writes the SHA-256 and the generation to the sync state.

## 6. Pull

(phase 2) "Get from iCloud": Apassy locks the vault and asks for the passphrase.

1. Apassy refuses the pull when this Mac has changes that are not in iCloud ("Push needed" or "Conflict"), or when a `-journal`, `-wal`, or `-shm` file is next to the vault file.
2. It copies the cloud file to `<vault>.sync-incoming`.
3. It checks the copy with the passphrase: cipher settings, schema, integrity, and the content digest. A wrong passphrase or a damaged copy stops the pull.
4. It refuses a copy of another vault (another vault id).
5. It refuses an older copy (section 8).
6. It renames the copy over the vault file. The next unlock opens it. A copy from an older Apassy migrates at that unlock.

The local file does not change when a step fails.

Unlike a restore, a pull keeps agents, grants, and rules. The passphrase authenticates the copy, and the generation check refuses an old one. ADR 0014, section 6, has the reasons and the limit.

After a passphrase change on another Mac, type the new passphrase at the pull. (phase 2) Set up Touch ID unlock again after such a pull.

## 7. Conflicts

Both Macs changed the vault. Apassy does not merge. You choose, and Apassy keeps the other copy as a file.

- "Keep this Mac" (vault unlocked, passphrase): Apassy saves the iCloud copy to `conflicts/<name>-icloud-<time>.apassy`, then pushes. It reads the generation of the iCloud copy with the passphrase, so the push gets a higher one and the other Macs accept it.
- "Use iCloud" (vault locked, passphrase): Apassy saves the local file to `conflicts/<name>-this-mac-<time>.apassy`, then pulls.

To see the other copy later: (phase 2) open the conflict copy as a vault with the passphrase of its time. Copy the items that you need by hand.

"Keep this Mac" also puts this Mac's copy back when the iCloud copy is older (section 8).

## 8. Rollback refusal

Each push raises the generation in the vault. The sync state keeps the generation of the last push or pull on this Mac. A pull refuses:

- a copy with a lower generation: "the iCloud copy is older than the copy that this Mac synced last". Someone put an old copy back, or iCloud delivered an old push late.
- a copy with the same generation and other content: two Macs pushed from the same copy. Choose "Use iCloud" or "Keep this Mac". "Use iCloud" accepts the same generation; it still refuses a lower one.

In both cases the local file does not change.

## 9. A new Mac

1. Sign in to iCloud Drive and wait for the Apassy folder.
2. (phase 2) In Apassy, choose "Open from iCloud". Apassy lists the `*.apassy` files. A file that is not downloaded shows so; Apassy asks iCloud for it.
3. Pick the vault, type its passphrase, and choose where to keep the local file.

Apassy checks the copy, makes the new local vault file, and turns on sync for it. It accepts any generation, because this Mac has no earlier one.

## 10. Turn off sync

(phase 2) Turn off "Sync with iCloud". Apassy removes the sync state. The cloud file stays in iCloud Drive; delete it in Finder if you do not want it there. Turning sync on again links to the same file (section 3).

## 11. Isolation

The Seatbelt profile denies read and write under the Apassy folder in iCloud Drive (`APASSY_CLOUD_DIR`), and `<vault>.sync-incoming` like the vault. `apassy-sandbox` passes the folder by default; `--cloud-dir` changes it. The sync state and the conflict copies are in the data folder, which the profile denies. See [isolation.md](isolation.md).

## 12. Tests

```
cargo test --locked --features vault --test icloud_sync --test vault_migration
cargo test --locked --features vault --test isolation_profile -- icloud launcher
```

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
| `pull_refuses_another_vault_at_the_cloud_name` | Another vault id is refused. |
| `a_copy_that_mixes_pages_of_two_pushes_is_refused` | SQLCipher accepts a mixed file; the content digest refuses it. |
| `unlock_migrates_each_earlier_schema_version_to_the_current_one` (`tests/vault_migration.rs`) | Versions 1 to 12 migrate to 13 with a new vault id and generation 0. |
| `profile_denies_the_icloud_folder` (`tests/isolation/product_profile.rs`) | The profile denies the Apassy folder, a rename of iCloud Drive, and the incoming copy; another iCloud folder stays readable. |
| `launcher_passes_the_installed_and_the_build_app` | The launcher passes `APASSY_CLOUD_DIR` by default and with `--cloud-dir`. |

The tests use a temporary folder as iCloud Drive. They do not test iCloud itself.

## 13. Limits

- iCloud delivers a push later, sometimes minutes later. Until then another Mac sees the old copy.
- A person with the passphrase and access to the iCloud account can put a valid copy with a high generation in iCloud. The other Macs accept it.
- Evicted files: Apassy detects a `.<name>.icloud` placeholder and a dataless file (macOS 14 and later). The tests cover the placeholder only.
- A write to the vault by another SQLite client during a push is not supported, as for a backup.
- Apassy does not delete conflict copies, iCloud duplicates, or old cloud files.
- When the iCloud copy with the vault name opens with another passphrase (it was changed on another Mac), enable treats it as another vault and picks a new name. Pull on a Mac where sync is on instead.
- A crash after the rename and before the state write leaves an old hash in the sync state. The status then shows "In sync" (the files are equal), and the next push or pull writes the state again.
