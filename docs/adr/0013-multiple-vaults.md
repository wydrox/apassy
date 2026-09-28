# ADR 0013 — Several vaults, one open at a time

Date: 2026-09-28.
Status: ACCEPTED by the owner for 0.3.0. In the code.

## Context

Apassy 0.2 has one vault: the file `<data dir>/vault.db`. The owner wants to keep credentials apart, for example a personal vault and a vault for one client. Each group needs its own passphrase, its own agents, and its own rules.

The code has one rule for the open vault: `broker::SharedVault` is "the one open vault in this process". The desktop app and the broker share this slot. Owner checks, approvals, the decision log, the learning data, and the notifications read the vault in the slot.

## Decision

### 1. Several vaults, one open at a time

- A vault is one SQLCipher file with its own passphrase, items, agents, grants, rules, activity, and learning data. Nothing is shared between two vaults.
- One vault is open at a time. The broker serves only the open vault. The slot keeps its meaning: the one open vault in this process.
- A switch locks the open vault first, as "Lock" does. Each run that waits for the owner ends with the text "The owner switched to another vault before a decision. The run did not start." The inbox keeps each of these runs. Then the chosen file opens locked, and the unlock screen shows.
- A switch also clears the state of the vault that was open: typed secrets and their undo history, forms, the selection, revealed values, the owner check, a Touch ID unlock that still runs, inbox marks, notification results of activity entries, and the learning view. A local training stops.
- The Touch ID unlock setting is for one vault file. After a switch, Apassy reads the setting of the new file.

### 2. The vault list

Apassy keeps the list in `<data dir>/vaults.json` (`src/vaults.rs`):

- Format version 1. Each entry has a random ID, a name, the absolute path of the file, the time it came into the list, and the time of the last open. The list also names the last used vault.
- A name has 1 to 40 characters. Two vaults cannot have the same name, without regard to case.
- The file has mode `0600`. A write goes to a temporary file, then a sync, then a rename over the list.
- A field that this version does not know stays in the file when this version writes it. A later version adds an optional field, for example the iCloud setting of a vault.
- The list is not secret. It has names and paths, no key and no item.

At start, Apassy opens the last used vault, locked.

Migration: without a list, Apassy makes one. The file `vault.db` becomes "Personal". It stays where it is. Each `*.db` file in `<data dir>/vaults/` comes in with the name of its file.

A damaged list, or a list from a newer Apassy, never blocks the start. Apassy moves it to `vaults.json.bad-<unix time>`, makes a new list with the migration rule, and shows a note. A vault in another folder is then not in the list; the owner opens it again.

### 3. Where new vaults go

A new vault goes to `<data dir>/vaults/<name>.db` (folder mode `0700`). The file name comes from the vault name: lower-case letters, digits, and `-`. A taken file name gets `-2`, `-3`, and so on. "Location" still takes another path.

### 4. Agents

An agent token belongs to one vault. The broker does not look in other vaults. A token that is not valid for the open vault gets `unauthenticated` with the text "The agent token is not valid for the Apassy vault that is open now. The owner may have another vault open, or the owner revoked the token." `apassy-mcp` adds the next step for the user. The text names no other vault and no count of vaults. It says the same when the owner has one vault.

A run, a connector call, and a local training write their result only to the vault file that they started in. The owner can switch during a run; the result entry then does not go to the new vault.

### 5. The agent profile

`apassy-sandbox` reads the list and denies every listed vault file:

- A vault in the data directory: the subtree deny of the data directory covers it, with its SQLite companions and its `.lock` file.
- A vault outside the data directory: the launcher passes it as `APASSY_VAULT_FILE_2` to `APASSY_VAULT_FILE_16`. The profile applies each parameter with `(if (param …) …)`: the file, `-wal`, `-shm`, `-journal`, `.lock`, and no rename or delete of each parent folder.

The launcher fails closed:

- More than 15 vaults outside the data directory stop it with an error.
- A list that it cannot read or that is not valid stops it with an error. The launcher cannot name a vault file in a damaged list, so it cannot prove that the profile denies each vault. A fallback that denies only the data directory would leave a vault in another folder open to agents without a warning. The owner opens Apassy once, which moves the damaged list aside and makes a new one, and then starts the launcher again.

## What this does not protect

- The launcher reads the list when it starts. A host that started earlier does not get a vault that the owner adds later in another folder. Restart the host in the profile after you add such a vault. A vault in the default folder needs no restart.
- "Remove from list" keeps the file. A removed vault outside the data directory is then not denied to agents that start later.
- After a damaged list, a vault in another folder is not in the new list, so the profile does not deny it until the owner opens it again.
- The list shows the names and the paths of the vaults to each process of the owner outside the profile.
- One vault is open at a time. An agent of another vault gets `unauthenticated` until the owner opens that vault.

## Relation to other records

- ADR 0003: each vault keeps the passphrase rules. A lost passphrase loses only that vault.
- ADR 0004: the broker and the desktop app still share one slot.
- ADR 0010: a switch ends waiting runs as a lock does (goal items V3, N3).
- ADR 0014 and ADR 0015 (iCloud sync and updates) build on this list. A per-vault sync setting is an optional field of a list entry.
