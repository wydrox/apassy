# ADR 0014 — iCloud sync of a vault

Date: 2026-09-28.
Status: PROPOSED for 0.3.0. Phase 1 is in the code: the sync engine (`apassy::cloud`), schema version 13, the Seatbelt rule, and the tests. Phase 2 adds the desktop UI and the setting of each vault in the vault registry.
Operations: [icloud.md](../operations/icloud.md).

## Context

The owner wants the same vault on more than one Mac. iCloud Drive is on each Mac of the owner and needs no Apassy server.

A live SQLite database in iCloud Drive is not safe:

- iCloud can replace the file while a connection has it open.
- iCloud syncs a rollback journal (`-journal`) or a WAL apart from its database. A Mac can then get a database without its journal, or a journal of another state.
- iCloud can evict a file (keep only the name on the Mac) and download it again later.
- Two Macs can change the file at the same time. iCloud then keeps one version, or makes a duplicate like `Personal 2.apassy`.

## Decision

### 1. The live vault stays local

The live vault is a local file, as before. The Seatbelt profile protects it. iCloud Drive holds a closed, encrypted copy of the vault in `~/Library/Mobile Documents/com~apple~CloudDocs/Apassy/<name>.apassy`. The copy has the format of a backup: the SQLCipher file with the passphrase of its time. SQLite never opens a file in iCloud Drive; each check opens a local copy.

### 2. Schema version 13: the sync record

The table `sync_meta` has one row:

| Column | Meaning |
| --- | --- |
| `vault_id` | a random UUID (version 4), made at create or at the migration. Every copy of the vault has it. |
| `generation` | 0 before the first push. Each push makes it larger. |
| `pushed_by`, `pushed_at` | the device name (`scutil --get ComputerName`, else the host name) and the time of the last push |
| `content_digest` | SHA-256 of the schema and of every row of every other table at the last push |

The row is inside the encrypted database. Only an unlocked vault, or a copy opened with the passphrase, shows it.

### 3. Push

The vault is unlocked. One transaction raises the generation above the current one and above the last known one, and writes the device, the time, and the content digest. Then Apassy copies the vault file to `.<name>.push.nosync` in the Apassy folder (iCloud does not sync a name that ends in `.nosync`), syncs the copy, renames it to `<name>.apassy`, and syncs the folder. The vault stays unlocked.

The copy while the connection is open is safe: the vault uses DELETE journal mode, each vault method ends its transaction before it returns, and `&mut Vault` means that no statement runs. An idle connection in rollback-journal mode holds no lock and no unwritten page, so the file is a complete database. The `.lock` sidecar keeps other Apassy processes out. A `-journal`, `-wal`, or `-shm` file next to the vault refuses the push.

### 4. Status without the passphrase

A small JSON file in the data folder keeps, for each vault: the cloud file name, the vault id, the SHA-256 of the file at the last push or pull, and the generation at that time. The status compares the SHA-256 of the local file and of the cloud file with the last one:

| Local file | Cloud file | Status |
| --- | --- | --- |
| as at the last sync | as at the last sync | in sync |
| changed | as at the last sync | push needed |
| as at the last sync | changed | pull available |
| changed | changed | conflict (in sync when the two are equal) |

Other states: the cloud file is missing, the cloud file is not downloaded (a `.<name>.icloud` placeholder, or a dataless file on macOS 14 and later), and iCloud Drive is not available. The status also lists iCloud duplicates of the cloud file.

### 5. Pull

The vault is locked, and the owner types the passphrase. Apassy copies the cloud file next to the vault (`<vault>.sync-incoming`), and checks it with the passphrase: the cipher settings, the schema, the integrity, and the content digest. It refuses:

- local changes that are not in iCloud,
- a copy with another vault id,
- a copy with a lower generation than the last sync, or with the same generation and other content (a rollback).

Then Apassy renames the copy over the vault file. The vault keeps its `.lock` sidecar and has no connection while locked, so the next unlock opens the new file. A copy from an older schema migrates at that unlock, as always.

### 6. A pull keeps agents and grants

A restore removes agent authority, because an old or changed backup can have wrong settings (ADR 0003, goal item V4). A pull keeps agents, grants, and rules:

- The passphrase authenticates the copy. SQLCipher checks the HMAC of each page with a key from the passphrase. Without the passphrase, nobody can make a copy that passes.
- The generation check refuses an old copy, for example one with an agent that the owner revoked since.
- SQLCipher authenticates each page, not the file. All copies of a vault share the key, so a page of an older copy still passes its HMAC in a newer copy. The content digest in the sync record covers every row, so a copy that mixes pages of different copies fails the check. A test shows that SQLCipher accepts such a mixed file and the pull refuses it.

The limit: a person with the passphrase and access to the iCloud account can make a valid copy with any content and a high generation. The other Macs then accept it. The passphrase is the root key of the vault (ADR 0003), so this is the same trust as for an unlock.

### 7. Conflicts

The owner chooses. Apassy never merges.

- "Keep this Mac": Apassy reads the generation of the iCloud copy with the passphrase, saves the iCloud copy to `<data folder>/conflicts/<name>-icloud-<time>.apassy`, and pushes with a higher generation.
- "Use iCloud": Apassy saves the local file to `<data folder>/conflicts/<name>-this-mac-<time>.apassy`, then pulls. Here a copy with the generation of the last sync and other content is accepted (two Macs pushed from the same copy). A lower generation is still refused.

A conflict copy is an ordinary vault file. The owner can open it later with the passphrase of its time.

### 8. Enable, disable, adopt

- Enable (vault unlocked, passphrase): the first push. The cloud file name comes from the vault name. When a file with that name holds another vault (another vault id, or it does not open with the passphrase), Apassy tries `<name>-2`, `<name>-3`, and so on. When the file holds the same vault, Apassy links to it without a push: equal files are in sync, other files are a conflict.
- Disable: Apassy removes the state file. The cloud file stays.
- Adopt (a new Mac): Apassy lists the `*.apassy` files in the Apassy folder. The owner picks one and types its passphrase. Apassy checks the copy and makes a new local vault file. There is no earlier generation, so any generation is accepted.

### 9. Isolation

The Seatbelt profile has an optional parameter `APASSY_CLOUD_DIR`. It denies read and write under the Apassy folder in iCloud Drive, and a rename or a delete of its parent folders. `apassy-sandbox` passes `$HOME/Library/Mobile Documents/com~apple~CloudDocs/Apassy` by default. The profile also denies `<vault>.sync-incoming` like the vault file. The state file and the conflict copies are in the data folder, which the profile denies.

### 10. Linux

Linux has no iCloud Drive. The code builds there, and `default_cloud_dir()` is `None`. The tests use a temporary folder as iCloud Drive, so they run on Linux and on macOS.

## Alternatives

- The live database in iCloud Drive. Refused: see Context.
- A sidecar file in iCloud with the generation or a MAC. Refused: iCloud syncs it apart from the vault copy, so the two can disagree.
- A merge of two copies by rows. Refused for now: agents, grants, and the history of items make a merge hard to prove correct. The owner chooses a copy and keeps the other as a file.
- The time as the generation. Refused: the clocks of two Macs can differ. The counter with "Keep this Mac" above the iCloud generation needs no clock.

## What this does not protect

- A person with the passphrase and the iCloud account (section 6).
- The iCloud copy holds the passphrase of the last push. After a passphrase change on one Mac, the other Macs type the new passphrase at the pull. An old iCloud copy, a conflict copy, and iCloud's own file versions keep the old passphrase.
- iCloud can deliver a push late. A push on another Mac in that time is a conflict or an iCloud duplicate. Apassy shows both; the owner chooses.
- Between the read of the iCloud copy and the rename, iCloud can deliver a newer version. The rename then replaces it in iCloud. The Mac that pushed that version still has it; its next pull stops with the equal-generation message, and the owner chooses there.
- The activity log is part of the vault. Each agent use changes the local file, so the status often says "push needed".
- Apassy does not delete conflict copies or iCloud duplicates.
