# Backup and restore

Date: 2026-09-26.
Scope: the encrypted vault file (goal item V4 in [the goal](../goal.md)). Decisions: [ADR 0003](../adr/0003-passphrase-vault.md), [ADR 0004](../adr/0004-agent-path-first.md), [ADR 0010](../adr/0010-closing-open-decisions.md).
Use only synthetic values for tests. The real-secret gate stays BLOCKED.

## 1. What a backup is

- A backup is a closed copy of the encrypted vault file. SQLCipher encrypts it with the passphrase that the vault has at the time of the backup.
- The backup has all items, declarations, environment variables, connectors, agents, grants, rules, and the activity log.
- The backup does not have the lock file (`<vault>.lock`).
- Apassy does not make backups automatically. Apassy does not delete old backups.

## 2. Make a backup

1. Unlock the vault.
2. In Vault, open "Vault file and backup".
3. In "Backup path", type the full path of a new file. The file must not exist. The name cannot end in `.lock`, `-journal`, `-wal`, or `-shm`.
4. Click "Back up vault".

Apassy then does these steps:

1. It locks the vault and closes the database connection. Each agent run that waits for you ends with `approval_invalidated`.
2. It refuses the backup if a journal, WAL, or SHM file is next to the vault file.
3. It copies the file to the new path with mode `0600` and syncs the copy.
4. The vault stays locked, also when the copy fails. Unlock it to continue.

Keep backups on a disk that only you can read. The Seatbelt profile for agents (goal item I1) must deny the backup paths.

## 3. Restore a backup

1. In "Backup to restore", type the path of the backup file.
2. In "Restored file path", type the path of a new file. Apassy does not overwrite a file.
3. In "Passphrase", type the passphrase that the vault had at the time of the backup.
4. Click "Restore vault".

Apassy then does these steps:

1. It locks the source and the destination with their lock files.
2. It refuses a source with a journal, WAL, or SHM file. Use a closed single-file backup.
3. It checks the passphrase, the cipher settings, the schema version, the columns, and the integrity of the backup. A wrong passphrase or a damaged file does not make the destination file.
4. It copies the backup to the new path.
5. It migrates a backup from an earlier schema version to the current version.
6. In one transaction, it revokes every agent, removes every grant and every rule, and marks each item with agent settings for review. Agent settings are a declaration, an environment variable, or a connector.
7. It opens the restored file in the locked state.

## 4. After a restore

The restored vault does not trust the agent authority in the backup. An old or changed backup can have wrong settings. For example, a connector can send the token to another host, or a production item can have a staging declaration.

1. Unlock the restored vault.
2. Find the card "Review after restore" in Vault or Agents. It lists each item that waits for your review.
3. Click "Open item". Examine the declaration, the environment variable, and the connector in the card "Review after restore". Correct them in the cards below if necessary.
4. Click "Confirm settings". Do this for each item in the list.
5. In Agents, register each agent again. Put the new token in `APASSY_AGENT_TOKEN` of the MCP configuration of the agent host. The old tokens do not work.
6. Give process access, grants, and rules again.

Until you confirm an item, the broker refuses each run and each connector call with that item. The code is `review_required`. `apassy-mcp` tells the agent to ask you for the review. `apassy_list_access` shows `"owner_review_needed": true` for the item.

## 5. Passphrase and backups

- A backup keeps the passphrase of its time. A change of the passphrase (Vault, "Change passphrase") does not change old backups. To restore an old backup, type the old passphrase.
- If you change the passphrase because it leaked, delete the old backups, or keep them in a place that nobody else can read.
- A lost passphrase makes each backup with that passphrase unrecoverable.

## 6. Tests

Run the tests from the repository root:

```
cargo test --locked --features desktop,vault --test owner_vault --test agent_run --test agent_path
cargo test --locked --features desktop,vault --lib restored_item_shows_the_review_and_confirm_action
```

| Test | What it shows |
| --- | --- |
| `restore_lists_items_for_review_until_the_owner_confirms` (`tests/owner_vault.rs`) | The procedure in the owner session: backup locks the vault, restore opens the new file locked, agents are revoked, the item with settings waits for review, and "Confirm settings" ends the review. |
| `restore_needs_owner_review_before_runs` (`tests/agent_run.rs`) | After the restore, grants and rules are gone and agents are revoked. A run with the restored item gets `review_required`. After the review, the run starts. |
| `restored_connector_waits_for_the_owner_review` (`tests/agent_path.rs`) | A connector call with a restored item gets `review_required` until the review. A second restore marks the item again. A delete removes the mark. |
| `restored_item_shows_the_review_and_confirm_action` (`src/desktop/ui.rs`) | The Vault view lists the item. Item details shows the settings and "Confirm settings". |
| `delete_item_removes_links_and_restore_revokes_agents` (`tests/agent_path.rs`) | A restore revokes every agent and removes the grants. |
| `backup_restore_passphrase_overwrite_and_source_bytes` (`tests/vault_lifecycle.rs`) | Backup and restore keep all item data, refuse existing targets, and do not change the backup file. |

## 7. Limits

- A completed copy does not prove that the directory entry is safe after a crash.
- Apassy does not encrypt a backup a second time, and it does not check where you store it.
- A backup made while an external SQLite client writes to the vault file is not supported. The advisory lock stops only other Apassy instances.
- The review is a check by you. Apassy cannot know which restored setting is wrong.
