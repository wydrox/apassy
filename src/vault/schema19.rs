//! Schema version 19: the trust root of the relay questions and the tables of shared
//! vaults (stage 5 plan §A1, ADR 0019 §4).
//!
//! - `trusted_device` is synced ([`super::merge::SYNCED_TABLES`]): one row per device
//!   that may answer a question of this vault, with its relay key and (iPhone) its
//!   answer key. Rows sync one by one, like `folder`: the later `(updated_at,
//!   updated_by)` wins, and a removed device keeps its row with `deleted_at`. A removal
//!   wins over any edit, earlier or later, so a revoked device never comes back through
//!   a sync ([`super::merge`]).
//! - `item_home` is a child row of a credential ([`super::merge::CHILD_TABLES`]): the
//!   shared vault and the home credential of a read-only mirror (V3). It syncs with the
//!   credential, and its triggers mark a change of the credential.
//! - `relay_membership` is local ([`super::merge::LOCAL_TABLES`]): one key pair per
//!   relay team, with the purposes that use it (`sync`, `questions`, `share`). It
//!   replaces the one-row `relay_device` of schema 16.
//!
//! The migration from schema 18 moves the `relay_device` row (relay address, team,
//! device number, and key) to `relay_membership` with the purpose `sync`, and drops
//! `relay_device`, in the same transaction as the new tables. A failure of any step
//! leaves the file at schema 18 with its row.

use super::types::{VaultErrorKind, VaultResult, err};
use super::{merge, verify_expected_columns_in};

/// Tables of schema 19, and the move of the relay row. The triggers of the new child
/// table come from [`merge::child_triggers_sql`].
const SCHEMA_V19_SQL: &str = r#"
CREATE TABLE trusted_device (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('mac', 'iphone')),
    relay_devices TEXT NOT NULL DEFAULT '{}',
    sign_key BLOB NOT NULL,
    answer_key BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted_at INTEGER
);
CREATE TABLE item_home (
    item_id INTEGER PRIMARY KEY,
    shared_vault_uuid TEXT NOT NULL,
    home_uuid TEXT NOT NULL
);
CREATE TABLE relay_membership (
    team_id TEXT PRIMARY KEY,
    relay_url TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    purposes TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
INSERT INTO relay_membership
    (team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at)
    SELECT team_id, relay_url, device_id, public_key, key_pkcs8, '["sync"]', created_at
    FROM relay_device WHERE id = 1;
DROP TABLE relay_device;
"#;

/// The version marks of schema 19. They run after the move of the relay row.
const SCHEMA_V19_MARKS_SQL: &str = "
UPDATE vault_meta SET schema_version = 19 WHERE id = 1;
PRAGMA user_version = 19;
";

/// The child tables of a credential added in schema 19.
pub(super) const CHILD_TABLES_V19: [&str; 1] = ["item_home"];

pub(super) const SCHEMA_V19_COLUMNS: [&str; 3] = [
    "SELECT uuid, name, kind, relay_devices, sign_key, answer_key, created_at, updated_at, updated_by, deleted_at FROM trusted_device LIMIT 0",
    "SELECT item_id, shared_vault_uuid, home_uuid FROM item_home LIMIT 0",
    "SELECT team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at FROM relay_membership LIMIT 0",
];

/// What a vault of schema 19 has and a vault of schema 18 has not, for test fixtures
/// that make a file or a copy of schema 18: the new tables go, and `relay_device` comes
/// back (empty) with the DDL of schema 16.
#[cfg(test)]
pub(super) const DOWNGRADE_TO_18_SQL: &str = "
DROP TABLE trusted_device; DROP TABLE item_home; DROP TABLE relay_membership;
CREATE TABLE relay_device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    relay_url TEXT NOT NULL,
    team_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
UPDATE vault_meta SET schema_version = 18 WHERE id = 1;
PRAGMA user_version = 18;
";

/// Add schema version 19 in the migration or create transaction: the tables, the
/// triggers of `item_home`, the move of the relay row, and the version marks. Then the
/// columns of schema 19 are checked in the same transaction, so a failure of any step
/// leaves the file at its old version.
pub(super) fn add_schema_v19(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    add_schema_v19_with(tx, |_| Ok(()))
}

/// [`add_schema_v19`] with `before_check`, a step that runs after the version marks and
/// before the check. Tests use it to fail late in the migration.
fn add_schema_v19_with(
    tx: &rusqlite::Transaction<'_>,
    before_check: impl FnOnce(&rusqlite::Transaction<'_>) -> VaultResult<()>,
) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    tx.execute_batch(SCHEMA_V19_SQL).map_err(storage)?;
    tx.execute_batch(&merge::child_triggers_sql(&CHILD_TABLES_V19))
        .map_err(storage)?;
    tx.execute_batch(SCHEMA_V19_MARKS_SQL).map_err(storage)?;
    before_check(tx)?;
    verify_expected_columns_in(tx, "main", super::TRUSTED_DEVICE_SCHEMA_VERSION)
}

/// Remove the schema 19 rows of a deleted item: its home, when it is a mirror.
pub(super) fn forget_item(tx: &rusqlite::Transaction<'_>, item: i64) -> VaultResult<()> {
    for table in CHILD_TABLES_V19 {
        tx.execute(&format!("DELETE FROM {table} WHERE item_id = ?1"), [item])
            .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::vault::{OPEN_EXISTING, Vault, apply_key, close_conn};

    const PASS: &str = "synthetic-schema19-pass";

    /// A new vault, closed, and made schema 18 again with a relay row.
    fn schema18_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("v18.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault.lock().unwrap();
        let conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        conn.execute_batch(&super::super::schema20::downgrade_sql())
            .unwrap();
        conn.execute_batch(DOWNGRADE_TO_18_SQL).unwrap();
        conn.execute(
            "INSERT INTO relay_device
                 (id, relay_url, team_id, device_id, public_key, key_pkcs8, created_at)
             VALUES (1, 'https://relay.example.test', 't_7k2m5q4x3c', 4, ?1, ?2, 1700000000)",
            ([&[0x04u8][..], &[9u8; 64][..]].concat(), vec![5u8; 138]),
        )
        .unwrap();
        close_conn(conn).unwrap();
        path
    }

    #[test]
    fn a_failure_after_the_marks_rolls_back_the_move() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema18_file(&dir);
        let mut conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        let tx = conn.transaction().unwrap();
        let failed = add_schema_v19_with(&tx, |tx| {
            // The row moved in this transaction.
            let moved: (i64, String) = tx
                .query_row(
                    "SELECT device_id, purposes FROM relay_membership",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(moved, (4, r#"["sync"]"#.to_owned()));
            Err(err(VaultErrorKind::Storage))
        });
        assert_eq!(failed.unwrap_err().kind(), VaultErrorKind::Storage);
        drop(tx);
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 18);
        let kept: i64 = conn
            .query_row(
                "SELECT device_id FROM relay_device WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kept, 4);
        for table in ["trusted_device", "item_home", "relay_membership"] {
            assert!(conn.prepare(&format!("SELECT 1 FROM {table}")).is_err());
        }
        close_conn(conn).unwrap();

        // The next unlock migrates the same file.
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(vault.relay_device().unwrap().unwrap().device_id, 4);
    }

    #[test]
    fn every_new_table_is_classified() {
        for table in CHILD_TABLES_V19 {
            assert!(merge::CHILD_TABLES.contains(&table));
            assert!(merge::SYNCED_TABLES.contains(&table));
        }
        assert!(merge::SYNCED_TABLES.contains(&"trusted_device"));
        assert!(merge::LOCAL_TABLES.contains(&"relay_membership"));
        assert!(!merge::LOCAL_TABLES.contains(&"relay_device"));
        assert!(!merge::SYNCED_TABLES.contains(&"relay_device"));
    }
}
