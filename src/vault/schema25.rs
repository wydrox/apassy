//! Schema version 25: more passkey algorithms and WebAuthn extension data.
//!
//! A passkey is a set of reserved `passkey_` fields of a login (schema 17). Schema 25
//! adds three values of `passkey_format` (`es384-pkcs8-v1`, `ed25519-pkcs8-v1`,
//! `rs256-pkcs8-v1`) and the optional fields `passkey_prf_uv`, `passkey_prf_no_uv`,
//! `passkey_large_blob`, and `passkey_large_blob_size` (see [`super::passkey`]). No
//! table and no column changes, and the migration changes no row: only the version
//! marks.
//!
//! The version keeps a device of schema 24 or earlier away from these passkeys: it
//! refuses a copy of schema 25 (`UnsupportedSchema`), so it never sees a format that it
//! cannot sign with, and it never drops the extension fields in an edit. A merge of
//! schema 25 takes a copy of schema 16 to 24 as before: its passkeys are ES256 without
//! extension fields, which schema 25 reads unchanged.

use rusqlite::Transaction;

use super::types::{VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version of the passkey formats and fields of WebAuthn extensions.
pub(super) const PASSKEY_EXTENSIONS_SCHEMA_VERSION: i64 = 25;

/// What a vault of schema 25 has and a vault of schema 24 has not, for test fixtures:
/// only the version marks.
#[cfg(test)]
pub(super) const DOWNGRADE_TO_24_SQL: &str = "
UPDATE vault_meta SET schema_version = 24 WHERE id = 1;
PRAGMA user_version = 24;
";

/// Add schema version 25 in the migration or create transaction: the version marks.
/// Then the columns of schema 25 are checked in the same transaction.
pub(super) fn add_schema_v25(tx: &Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(
        "UPDATE vault_meta SET schema_version = 25 WHERE id = 1; PRAGMA user_version = 25;",
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    verify_expected_columns_in(tx, "main", PASSKEY_EXTENSIONS_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::vault::passkey::{ES256, PasskeyCreate, PasskeyTarget};
    use crate::vault::{OPEN_EXISTING, Vault, apply_key, close_conn};

    const PASS: &str = "synthetic-schema25-pass";
    const HASH: [u8; 32] = [0x25; 32];

    fn version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    /// Every row of `item_field` with its position, name, value and secret flag.
    fn field_rows(conn: &Connection) -> Vec<(i64, i64, String, String, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT item_id, position, name, value, secret FROM item_field
                 ORDER BY item_id, position",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// A schema 24 vault with one ES256 passkey. Returns the path, the item, the
    /// credential ID, and the field rows.
    /// An `item_field` row: item, position, name, value, secret.
    type FieldRow = (i64, i64, String, String, i64);

    fn schema24_file(dir: &tempfile::TempDir) -> (std::path::PathBuf, u64, Vec<u8>, Vec<FieldRow>) {
        let path = dir.path().join("v24.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let created = vault
            .create_passkey(PasskeyCreate {
                rp_id: "example.com",
                user_handle: b"synthetic-user",
                user_name: "alice",
                user_display_name: "Alice",
                client_data_hash: &HASH,
                algorithms: &[ES256],
                exclude: &[],
                target: PasskeyTarget::NewItem {
                    title: "Example".to_owned(),
                },
            })
            .unwrap();
        vault.lock().unwrap();
        let conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        // Schema 26 (the cloud agents of the node) first: it has tables and a column.
        conn.execute_batch(crate::vault::schema26::DOWNGRADE_TO_25_SQL)
            .unwrap();
        conn.execute_batch(DOWNGRADE_TO_24_SQL).unwrap();
        assert_eq!(version(&conn), 24);
        let rows = field_rows(&conn);
        close_conn(conn).unwrap();
        (path, created.item_id, created.credential_id, rows)
    }

    #[test]
    fn a_schema24_vault_migrates_and_its_es256_rows_stay() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, item_id, credential_id, before) = schema24_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        // The unlock runs schema 26 after 25 (`schema26.rs`).
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert_eq!(field_rows(conn), before, "no row changes");
        let format = before
            .iter()
            .find(|row| row.2 == "passkey_format")
            .map(|row| row.3.as_str());
        assert_eq!(format, Some("es256-pkcs8-v1"));
        let assertion = vault
            .sign_passkey(item_id, "example.com", &credential_id, &HASH)
            .unwrap();
        assert_eq!(assertion.algorithm, ES256);
        assert!(assertion.prf.is_none() && assertion.large_blob.is_none());
        let export = vault.export_passkey(item_id).unwrap();
        assert_eq!(export.algorithm, ES256);
        assert!(export.prf.is_none() && export.large_blob.is_none());
    }

    #[test]
    fn a_failed_migration_keeps_schema_24() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, _, _, before) = schema24_file(&dir);
        let mut conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        let tx = conn.transaction().unwrap();
        add_schema_v25(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), 24);
        assert_eq!(field_rows(&conn), before);
        close_conn(conn).unwrap();
    }

    #[test]
    fn a_new_vault_has_schema_25() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        // A new vault has schema 25 and the later schema 26 (`schema26.rs`).
        assert_eq!(
            version(vault.conn_ref().unwrap()),
            crate::vault::SCHEMA_VERSION
        );
        const { assert!(PASSKEY_EXTENSIONS_SCHEMA_VERSION < crate::vault::SCHEMA_VERSION) };
    }
}
