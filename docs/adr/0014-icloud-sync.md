# ADR 0014 — Sync of a vault through a folder, merged by credential

Date: 2026-09-28.
Status: ACCEPTED for 0.3.0: on 2026-09-28 the owner asked for sync that works "like other apps", with a folder of choice, automatic merges, and no version choice. In the code. It replaces the first design of this ADR (a whole-file copy in iCloud Drive, with "Keep this Mac" or "Use iCloud" in a conflict), which did not ship.
Operations: [sync.md](../operations/sync.md).

## Context

The owner wants the same vault on more than one Mac, and a small team wants to share a vault. They expect it to work like other apps that sync through a folder (Obsidian, for example): the owner picks where the vault syncs, it just syncs, and changes from two Macs merge. A choice of a whole version is not acceptable in normal use.

A live SQLite database in a synced folder is not safe: a sync service can replace the file under an open connection, sync a rollback journal apart from its database, evict the file, or keep one of two concurrent versions.

## Decision

### 1. Where a vault syncs

The sync setting of a vault holds a folder. iCloud Drive (`…/com~apple~CloudDocs/Apassy`) is the default when it is on. The app also offers the folders in `~/Library/CloudStorage` (Dropbox, Google Drive, OneDrive, other File Provider services), `~/Dropbox`, and "Choose folder…" for any path (Syncthing, a network share). The file is `<folder>/<name>.apassy`: a closed, encrypted copy. The live database stays local; SQLite never opens a file in the folder. The vault list (ADR 0013) keeps the folder, the file name, and the name of the sync state of each vault.

### 2. What syncs

The credentials and their settings sync: items, fields, tags, the archive state, declarations, environment variables with placeholder hosts, connectors, and the history events of a credential (added, edited, archived, declaration, variable, connector).

Everything else stays on each Mac (`vault::LOCAL_TABLES`): agents and tokens, grants, rules, the token lifetime, activity, the decision log, patterns, calibrations, candidates and shadow answers, access requests, waits, review marks, the history events about agents and reveals, and the sync bookkeeping. A push removes these rows from the copy (`ATTACH` of the copy, `DELETE`, `VACUUM`) before the copy goes to the folder. So the agents and the activity of one Mac never reach another Mac or a teammate. Each Mac registers its own agents; their tokens live in the MCP configuration of each Mac, and their folders are on each Mac.

A test lists every table of the schema and fails when a new table is neither synced nor local.

### 3. Records, versions, and tombstones (schema version 14)

Each credential has a stable `uuid`, `updated_at` (Unix milliseconds), `updated_by` (the random device ID of the vault file; `sync_device`), and a version vector `clock` (for each device ID, the count of its changes). SQL triggers keep the time and the device on each change of the item or of one of its child rows, and write a tombstone at a delete. So the many write paths of the app need no edit. Before each merge and each push, the app counts each change since the last stamp in the clock of its device (`sync_stamp`, local).

A tombstone has the clock of the record with the delete counted. It stays 180 days.

The migration from 13 gives existing records UUIDs derived from the vault ID, the table, and the row ID (SHA-256), so two copies of the same vault agree on them, and it counts them as stamped with an empty clock. A readable device name for the conflict copies is in `sync_peer`, which syncs.

The unit of merge is the credential with all its settings. A change of the variable on one Mac and of the declaration on another is a conflict of that credential.

### 4. Merge

The other copy is always a local copy in the data folder, never the file in the synced folder. The app attaches it to the open connection without a key argument: SQLCipher then uses the key of the vault (a test shows this, and that a copy made after a passphrase change on another Mac does not open). The copy must pass the page checks of SQLCipher, the integrity check, the schema check, and the content digest of its last push (a file that mixes pages of different copies fails: each page passes its HMAC, the digest does not). It must have the vault ID of the vault.

Then, per credential, in one transaction:

| Clocks | Result |
| --- | --- |
| equal, or the local one contains the other | keep the local version (an old copy changes nothing) |
| the other contains the local one | take the other version |
| each has a change that the other lacks, same content | keep it, join the clocks |
| each has a change that the other lacks, other content | the later change (time, then device ID) wins; the other version stays as an archived credential "<title> (conflict copy, <device>)" without its variable and connector |

A record only on the other side is added, unless a local tombstone saw its version. A tombstone of the other side that saw the local version deletes the local credential with its agent links; a local change that the delete did not see keeps it. Integer IDs are local: each reference between synced tables goes through the UUIDs. A variable name that another local credential has already is left out and reported.

The conflict copy has a UUID, a version, and a clock from the losing version, so each Mac that sees the conflict makes the same copy, and it is there once.

After a merge, when the vault has content that the file lacks, the app pushes. "Content to push" is a digest of the synced content only: agent activity does not start a push.

### 5. No passphrase in normal use

A merge and a push use the key of the unlocked vault. When the synced file does not open with it (another Mac changed the passphrase), the app asks once: "The passphrase of <vault> changed on another Mac. Type the new passphrase." The new passphrase must open the file and the file must hold this vault; then the local vault is rekeyed to it (`PRAGMA rekey` on the open connection; the old passphrase is not needed) and the merge runs. Opening a synced vault on a new Mac or by a teammate takes the passphrase.

### 6. When it runs

At each unlock, before the list shows; while unlocked, every 30 seconds for the file (by its hash) and 5 to 8 seconds after a change of a credential; before each lock of the session, including a switch, a backup, a quit, and the restart for an update (the step before a lock of `OwnerSession`, after waiting runs end); and at "Sync now". Never while an agent run waits for the owner. A failure never stops a lock or a quit. An evicted iCloud file is requested with `brctl download`; a missing or unreachable folder shows "Folder not available" and syncs when it is back.

### 7. A sync scope

One sync covers a scope (`vault::SyncScope`): which records, which file, which key. Now the only scope is the whole vault with the key of the vault. A shared collection (a group of credentials with its own file and its own random key) will be another scope: the merge takes the scope and does not change. Version vectors belong to the record, not to the file, so a record can later sync through two files.

### 8. What was kept from the first design, and what went

- Kept: the live vault stays local; the closed copy; the `.nosync` temporary file and the rename; the content digest against mixed pages; the stable vault ID; the sync state per vault in the data folder; the detection of evicted iCloud files and of iCloud duplicates; the Seatbelt denial of the iCloud Apassy folder.
- Dropped: the refusal of an older generation. With version vectors and tombstones an old copy cannot undo a newer change and makes no conflict copy, so the refusal adds nothing; the generation stays in the sync record as a push counter for display. Dropped: "Keep this Mac" and "Use iCloud". The only whole-file choice left is the last resort for a damaged synced file ("Replace with this Mac's vault"), because a damaged file cannot be merged.

### 9. Isolation

`APASSY_CLOUD_DIR` denies the iCloud Apassy folder as a whole. For a synced file in another folder, the profile denies only its files, because an agent's projects can live in Dropbox too: the file, `<file>.push.nosync`, and its SQLite companions (`APASSY_SYNC_FILE_1` to `APASSY_SYNC_FILE_16`, read from the vault list; a damaged list, a synced vault without a valid file, or more than 16 such files stop the launcher). The folders above the file cannot be renamed or deleted, as for the other rules. Sealing a Dropbox folder this way stops only a rename or a delete of that folder and its parents; files and folders inside stay usable (a test shows a project in the same Dropbox folder).

## Sharing a vault with a small team

The same `.apassy` file in a folder that several people share is a shared vault: each person opens it with the passphrase. Limits: everyone with the passphrase can read and change every value; removing a person means changing the passphrase and rotating the credentials; there is no per-person audit.

## Alternatives

- The live database in the synced folder. Refused: see Context.
- A whole-file copy with a version choice (the first design of this ADR). Refused by the owner.
- Last writer wins by time alone. Refused: a push over a file that another Mac's push did not reach yet would drop that Mac's change silently, and a base-version scheme either drops such changes or makes a false conflict copy in ordinary back-and-forth editing. A test covers the case. Version vectors tell a concurrent change from an old one.
- Merging each child table as its own record. Refused for now: the credential is what the owner sees and edits; a finer merge can come later without a format change of the file.
- A sidecar file with metadata next to the vault file. Refused: a sync service syncs it apart from the vault file.

## What this does not protect

- A person with the passphrase and the synced folder can write a valid file with any content, and the other Macs merge it. The passphrase is the root key of the vault (ADR 0003).
- A conflict picks the later change by the clock of each Mac; a wrong clock can pick the wrong winner, but the other version is kept.
- A Mac away longer than 180 days can bring a deleted credential back.
- The synced file has the passphrase of the Mac that pushed last. Old copies in the folder's version history keep old passphrases.
- Apassy does not delete conflict copies, duplicates, or old synced files.

## Relation to other records

- ADR 0003: the passphrase stays the root key; a rekey from a synced copy needs the new passphrase.
- ADR 0013: the sync setting is an optional field of a vault list entry; the launcher reads it.
- ADR 0015: "Restart now" locks through the same step, so it syncs.
