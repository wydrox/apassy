//! Schema version 24: the device kind `watch` (ADR 0039 §1).
//!
//! The `trusted_device` table of schema 19 takes the kinds `mac` and `iphone` only.
//! SQLite cannot change a `CHECK` constraint in place, so schema 24 rebuilds the table
//! with `CHECK (kind IN ('mac', 'iphone', 'watch'))` in the migration transaction: a new
//! table, a copy of every row with every column (removed devices too), a drop of the old
//! table, a rename of the new one, and the indexes and triggers of the old table made
//! again from their stored SQL. A failure of any step leaves the file at schema 23 with
//! its rows.
//!
//! The table still syncs one row at a time ([`super::merge`]). A copy of schema 23 or
//! earlier has only `mac` and `iphone` rows, so a merge takes it unchanged. A device of
//! schema 23 or earlier refuses a copy of schema 24.

use rusqlite::Transaction;

use super::types::{VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version that adds the kind `watch`.
pub(super) const WATCH_SCHEMA_VERSION: i64 = 24;

/// Every column of `trusted_device`, in the order of the table.
const COLUMNS: &str = "uuid, name, kind, relay_devices, sign_key, answer_key, created_at, \
                       updated_at, updated_by, deleted_at";

/// The table of schema 24 under a temporary name. Only the `CHECK` of `kind` differs
/// from schema 19.
const TABLE_V24_SQL: &str = "
CREATE TABLE trusted_device_v24 (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('mac', 'iphone', 'watch')),
    relay_devices TEXT NOT NULL DEFAULT '{}',
    sign_key BLOB NOT NULL,
    answer_key BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted_at INTEGER
);
";

/// What a vault of schema 24 has and a vault of schema 23 has not, for test fixtures:
/// the table of schema 19 again, with its rows. A `watch` row makes it fail.
#[cfg(test)]
pub(super) const DOWNGRADE_TO_23_SQL: &str = "
CREATE TABLE trusted_device_v23 (
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
INSERT INTO trusted_device_v23 SELECT * FROM trusted_device;
DROP TABLE trusted_device;
ALTER TABLE trusted_device_v23 RENAME TO trusted_device;
UPDATE vault_meta SET schema_version = 23 WHERE id = 1;
PRAGMA user_version = 23;
";

/// Add schema version 24 in the migration or create transaction: the rebuild of
/// `trusted_device` and the version marks. Then the columns of schema 24 are checked in
/// the same transaction.
pub(super) fn add_schema_v24(tx: &Transaction<'_>) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    // The indexes and triggers of the table go with the drop: keep their SQL. The
    // indexes of the primary key have no SQL; the new table makes them.
    let extras: Vec<String> = {
        let mut stmt = tx
            .prepare(
                "SELECT sql FROM main.sqlite_master
                 WHERE tbl_name = 'trusted_device' AND type IN ('index', 'trigger')
                     AND sql IS NOT NULL
                 ORDER BY type, name",
            )
            .map_err(storage)?;
        stmt.query_map([], |row| row.get(0))
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?
    };
    let before: i64 = tx
        .query_row("SELECT count(*) FROM trusted_device", [], |row| row.get(0))
        .map_err(storage)?;
    tx.execute_batch(TABLE_V24_SQL).map_err(storage)?;
    tx.execute_batch(&format!(
        "INSERT INTO trusted_device_v24 ({COLUMNS}) SELECT {COLUMNS} FROM trusted_device;
         DROP TABLE trusted_device;
         ALTER TABLE trusted_device_v24 RENAME TO trusted_device;"
    ))
    .map_err(storage)?;
    for sql in &extras {
        tx.execute_batch(sql).map_err(storage)?;
    }
    let after: i64 = tx
        .query_row("SELECT count(*) FROM trusted_device", [], |row| row.get(0))
        .map_err(storage)?;
    if after != before {
        return Err(err(VaultErrorKind::Storage));
    }
    tx.execute_batch(
        "UPDATE vault_meta SET schema_version = 24 WHERE id = 1; PRAGMA user_version = 24;",
    )
    .map_err(storage)?;
    verify_expected_columns_in(tx, "main", WATCH_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::vault::{OPEN_EXISTING, TrustedDeviceKind, Vault, apply_key, close_conn};

    const PASS: &str = "synthetic-schema24-pass";

    fn point(fill: u8) -> Vec<u8> {
        let mut key = vec![0x04];
        key.extend_from_slice(&[fill; 64]);
        key
    }

    type Row = (
        String,
        String,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        i64,
        i64,
        String,
        Option<i64>,
    );

    fn rows(conn: &Connection) -> Vec<Row> {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM trusted_device ORDER BY uuid"
            ))
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn insert_raw(conn: &Connection, uuid: &str, kind: &str) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO trusted_device (uuid, name, kind, sign_key, created_at, updated_at, updated_by)
             VALUES (?1, 'Synthetic', ?2, ?3, 1700000000, 1, 'synthetic-device')",
            rusqlite::params![uuid, kind, point(0x31)],
        )
    }

    fn version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    /// A vault of schema 23 with a Mac, an iPhone, a removed iPhone, an index, and a
    /// trigger on `trusted_device`. Returns the path and the rows.
    fn schema23_file(dir: &tempfile::TempDir) -> (std::path::PathBuf, Vec<Row>) {
        let path = dir.path().join("v23.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .register_trusted_device(
                "mac-1",
                "Synthetic Mac",
                TrustedDeviceKind::Mac,
                &point(1),
                None,
            )
            .unwrap();
        vault
            .set_trusted_device_relay_id("mac-1", "t_aaaaaaaaaa", 2)
            .unwrap();
        vault
            .register_trusted_device(
                "phone-1",
                "Synthetic iPhone",
                TrustedDeviceKind::Iphone,
                &point(2),
                Some(&point(3)),
            )
            .unwrap();
        vault
            .register_trusted_device(
                "phone-2",
                "Old iPhone",
                TrustedDeviceKind::Iphone,
                &point(4),
                Some(&point(5)),
            )
            .unwrap();
        assert!(vault.remove_trusted_device("phone-2").unwrap());
        vault.lock().unwrap();
        let conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        conn.execute_batch(DOWNGRADE_TO_23_SQL).unwrap();
        conn.execute_batch(
            "CREATE INDEX synthetic_trusted_kind ON trusted_device(kind);
             CREATE TRIGGER synthetic_trusted_touch AFTER UPDATE OF name ON trusted_device
             BEGIN SELECT 1; END;",
        )
        .unwrap();
        assert_eq!(version(&conn), 23);
        // The fixture is a real schema 23 file: it refuses a watch.
        assert!(insert_raw(&conn, "watch-0", "watch").is_err());
        let before = rows(&conn);
        assert_eq!(before.len(), 3);
        assert!(
            before
                .iter()
                .any(|row| row.0 == "phone-2" && row.9.is_some())
        );
        close_conn(conn).unwrap();
        (path, before)
    }

    #[test]
    fn a_schema23_vault_keeps_every_device_and_takes_a_watch() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, before) = schema23_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), WATCH_SCHEMA_VERSION);
        assert_eq!(rows(conn), before);
        let extras: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE tbl_name = 'trusted_device'
                     AND type IN ('index', 'trigger') AND sql IS NOT NULL ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            extras,
            ["synthetic_trusted_kind", "synthetic_trusted_touch"]
        );
        assert!(
            conn.prepare("SELECT 1 FROM trusted_device_v24").is_err(),
            "the temporary table is gone"
        );
        // An unknown kind is still refused.
        for kind in ["ipad", "Watch", ""] {
            assert!(insert_raw(conn, "other-1", kind).is_err(), "{kind:?}");
        }

        let watch = vault
            .register_trusted_device(
                "watch-1",
                "Synthetic Watch",
                TrustedDeviceKind::Watch,
                &point(6),
                Some(&point(7)),
            )
            .unwrap();
        assert_eq!(watch.kind, TrustedDeviceKind::Watch);
        assert_eq!(vault.trusted_device("watch-1").unwrap(), Some(watch));
        let stored: String = vault
            .conn_ref()
            .unwrap()
            .query_row(
                "SELECT kind FROM trusted_device WHERE uuid = 'watch-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, "watch");
        // The removed iPhone stays removed, and its keys stay refused.
        assert_eq!(vault.trusted_device("phone-2").unwrap(), None);
        assert!(vault.trusted_key_removed(&point(5)).unwrap());
    }

    #[test]
    fn a_failed_migration_keeps_schema_23() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, before) = schema23_file(&dir);
        let mut conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        let tx = conn.transaction().unwrap();
        add_schema_v24(&tx).unwrap();
        insert_raw(&tx, "watch-0", "watch").unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), 23);
        assert_eq!(rows(&conn), before);
        assert!(insert_raw(&conn, "watch-0", "watch").is_err());
        close_conn(conn).unwrap();
    }

    #[test]
    fn a_new_vault_takes_a_watch() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .register_trusted_device(
                "watch-1",
                "Watch",
                TrustedDeviceKind::Watch,
                &point(1),
                Some(&point(2)),
            )
            .unwrap();
        assert!(insert_raw(vault.conn_ref().unwrap(), "other-1", "ipad").is_err());
    }

    /// A watch row syncs like an iPhone row, and its removal wins.
    #[test]
    fn a_watch_row_merges_and_its_removal_wins() {
        use crate::vault::SyncScope;
        let dir = tempfile::TempDir::new().unwrap();
        let mut a = Vault::create(&dir.path().join("a.db"), PASS).unwrap();
        a.unlock(PASS).unwrap();
        let seed = dir.path().join("seed.apassy");
        a.write_sync_copy(&seed, "Mac A").unwrap();
        let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
        b.unlock(PASS).unwrap();
        let watch = a
            .register_trusted_device(
                "watch-1",
                "Synthetic Watch",
                TrustedDeviceKind::Watch,
                &point(1),
                Some(&point(2)),
            )
            .unwrap();
        let from_a = dir.path().join("push-1.apassy");
        a.write_sync_copy(&from_a, "Mac A").unwrap();
        b.merge_from(&from_a, &SyncScope::vault()).unwrap();
        assert_eq!(b.trusted_device("watch-1").unwrap(), Some(watch));

        assert!(b.remove_trusted_device("watch-1").unwrap());
        let from_b = dir.path().join("push-2.apassy");
        b.write_sync_copy(&from_b, "Mac B").unwrap();
        a.merge_from(&from_b, &SyncScope::vault()).unwrap();
        assert_eq!(a.trusted_device("watch-1").unwrap(), None);
        assert!(a.trusted_key_removed(&point(2)).unwrap());
    }
}
