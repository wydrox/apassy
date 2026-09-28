# Several vaults

Date: 2026-09-28.
Scope: several vault files, one open at a time. Decision: [ADR 0013](../adr/0013-multiple-vaults.md).
Use only synthetic values for tests. The real-secret gate stays BLOCKED.

## 1. What a vault is

- A vault is one encrypted file with its own passphrase. It has its own credentials, agents, grants, rules, activity, and learning data. Two vaults share nothing.
- One vault is open at a time. Agents reach only the open vault.
- Each vault has a name of 1 to 40 characters. Two vaults cannot have the same name, without regard to case.
- Apassy keeps the list of vaults in `~/Library/Application Support/Apassy/vaults.json` (Linux: `$XDG_DATA_HOME/apassy/vaults.json`). The list has the names and the paths, no key and no item. The file has mode `0600`.
- On macOS a vault can keep a copy in iCloud Drive and sync with your other Macs. Each vault has its own setting: [iCloud sync](icloud.md).

## 2. Create a vault

1. In the sidebar, click the name of the open vault at the top, then "New vault…". Or, on the unlock screen, click "New vault…".
2. Type a name, for example "Client A".
3. Type a passphrase two times. Each vault has its own passphrase. A lost passphrase loses only that vault.
4. Click "Create vault".

The new file is `~/Library/Application Support/Apassy/vaults/<name>.db`. The folder has mode `0700`. "Location" takes another path. The new vault is open and unlocked.

The first vault on a Mac has the name "Personal" when you type no name.

## 3. Switch vaults

1. In the sidebar, click the name of the open vault at the top.
2. Click the name of another vault.

Or, on the unlock screen, pick the vault above the passphrase field. Settings > Vaults also has "Open" for each vault.

Apassy then does these steps:

1. It locks the open vault. Each run that waits for you ends. The inbox of that vault keeps each such run with the text "The owner switched to another vault before a decision. The run did not start."
2. It clears what the window holds of that vault: typed secrets, forms, the selection, shown values, an open owner check, a Touch ID prompt, and the learning view. A local training stops.
3. It opens the chosen file, locked. The unlock screen shows its name.
4. It reads the Touch ID unlock setting of that file. Touch ID unlock is set up for each vault file.

The next start opens the vault that you used last, locked.

## 4. Add a vault file

1. Click the name of the open vault at the top of the sidebar, then "Open vault file…". Or, on the unlock screen, click "Open vault file…".
2. Type the path of the file.
3. Type a name, or leave the field empty for the name of the file.
4. Click "Open".

A file that is in the list already opens as it is. A restore from a backup also adds the restored file to the list with a name: [backup and restore](backup-restore.md).

## 5. Rename or remove a vault

In Settings > Vaults:

- "Rename…" changes the name. The file does not move.
- "Remove from list…" takes the vault out of the list. Apassy does not delete the file. You can open it again with "Open vault file…". The open vault stays in the list; open another vault first. iCloud sync of the vault stops; its copy in iCloud Drive stays ([iCloud sync](icloud.md), section 10).

A vault whose file is missing shows "File missing". A switch to it changes nothing and offers "Remove from list".

## 6. Agents and several vaults

- An agent belongs to the vault where you registered it. Its token works only while that vault is open and unlocked.
- With another vault open, the agent gets `unauthenticated`. `apassy-mcp` tells the user that the token is not valid for the vault that is open now, and that the owner may have another vault open. The message names no vault.
- Register an agent in each vault that it needs. Each registration gives its own token.
- A run that ends after a switch writes its result only to its own vault. That vault is locked, so the result entry is not written.

## 7. The agent profile

`apassy-sandbox` reads the list when it starts and denies each vault file:

- A vault in `~/Library/Application Support/Apassy` is inside the denied data directory.
- A vault in another folder gets its own profile parameter, `APASSY_VAULT_FILE_2` to `APASSY_VAULT_FILE_16`. The profile denies the file, its SQLite companions, its `.lock` file, and a rename of its folders.

The launcher stops with an error in these cases:

- The list cannot be read, is damaged, or comes from a newer Apassy. Open Apassy once: it moves the list aside and makes a new one.
- More than 15 vaults are outside the data directory. Move vaults into the data directory, or remove vaults from the list.

A host reads the list only when it starts. After you add a vault in another folder, start the host in the profile again. The details are in [isolation](isolation.md).

## 8. Upgrade from 0.2 and a damaged list

- At the first start of 0.3, Apassy finds `vault.db` and adds it to the list as "Personal". The file stays where it is.
- A damaged list, or a list from a newer Apassy, does not stop the start. Apassy moves it to `vaults.json.bad-<unix time>` and makes a new list from `vault.db` and the files in `vaults/`. A note says so. Open each vault in another folder again with "Open vault file…".
- The new list links iCloud sync again where the sync state proves the vault; the note names the others, which need "Turn on iCloud sync…" again ([iCloud sync](icloud.md), section 11).

## 9. Tests

```
cargo test --locked --features desktop,vault --lib vaults
cargo test --locked --features desktop,vault --lib vault_tests
cargo test --locked --features desktop,vault --test notifications another_vault
cargo test --locked --features desktop,vault --test agent_run a_run_result
cargo test --locked --bin apassy-sandbox
cargo test --locked --features desktop,vault --test isolation_profile vault
```

| Test | What it shows |
| --- | --- |
| `src/vaults.rs` tests | Names, unique names, slugs, default paths, the atomic write with mode `0600`, unknown fields that stay, the migration of `vault.db`, and a damaged or newer list that moves aside. |
| `create_asks_for_a_name_and_lists_the_vault` | Create asks for a name, a new vault goes to `vaults/`, a taken name keeps the typed passphrase, and the sidebar and Settings show the vaults. |
| `a_switch_ends_waiting_runs_and_clears_the_state_of_the_vault` | A switch ends a waiting run with the switch text, clears the state of the old vault, puts the new vault locked in the slot of the broker, and a token of the old vault gets the clear refusal. |
| `start_opens_the_last_used_vault_locked` | The start opens the last used vault on the unlock screen, and the picker switches. |
| `remove_from_list_keeps_the_file_and_rename_checks_the_name` | "Remove from list" keeps the file and refuses the open vault. A rename refuses a taken name. |
| `a_missing_vault_file_is_shown_and_can_be_removed` | A missing file changes nothing on a switch, shows on the welcome screen, and leaves the list on "Remove from list". |
| `open_and_restore_add_the_file_to_the_list` | Open and Restore add the file with a name. |
| `another_vault_starts_a_new_notification_baseline` | The old entries of another vault cause no notification. |
| `a_run_result_stays_in_the_vault_of_the_run` | A run result does not go to a vault that opened during the run. |
| `apassy-sandbox` unit tests and `launcher_*`, `profile_denies_a_listed_vault_outside_the_data_directory` | The launcher passes each vault outside the data directory, fails closed, and the profile denies such a vault. |

## 10. Limits

- One vault is open at a time. Agents of the other vaults wait until you open their vault.
- A host in the profile does not get a vault that you add in another folder after its start.
- "Remove from list" and a damaged list take a vault in another folder out of the profile for hosts that start later.
- The list shows the names and the paths of your vaults to your own processes outside the profile.
