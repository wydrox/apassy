//! Schema version 34: relay memberships that sign with the Connect account device key
//! (ADR 0037 stage 7, docs/design/implementation-plan-s7-connect.md unit M1, contract
//! connect-account-v1 section 5).
//!
//! - `relay_membership.key_source`: `vault` (every row before this schema) keeps its own
//!   P-256 key in `key_pkcs8`, as before. `account` is a vault store of Apassy Connect: the
//!   row names the team, the device number, and the public key, and holds no private key
//!   (`key_pkcs8` is empty). The account device key of this Mac, one Keychain item
//!   outside every vault (`crate::connect::device_key`), signs for it. A `CHECK` keeps a
//!   private key out of an `account` row.
//!
//! The plan names the column `relay_device.key_source`; schema 19 moved the rows of
//! `relay_device` to `relay_membership` and dropped that table, so the column is on
//! `relay_membership`. The table is local ([`super::merge::LOCAL_TABLES`]): a pushed copy
//! carries none of its rows, so the column changes nothing that syncs.
//!
//! Schema 34 follows [`PREVIOUS_SCHEMA_VERSION`]: a vault of an earlier schema runs the
//! steps before it and then this one, in one migration. A failure rolls the whole
//! migration back and the file keeps its old version. A device of the previous schema or
//! earlier refuses a copy of schema 34 (`UnsupportedSchema`).
//!
//! The way back ([`downgrade_sql`], for the fixtures and the rollback notes) deletes the
//! `account` rows, then the column: an older build has no account key, so those rows
//! could only fail there. Relay sync of that vault through Connect is then off on this Mac
//! until a build of this schema turns it on again.
//!
//! The number lives in [`ACCOUNT_KEY_SCHEMA_VERSION`] only, and the step before it in
//! [`PREVIOUS_SCHEMA_VERSION`], so a release coordinator that renumbers this step (the
//! parallel plans add schemas of their own) changes those two constants.

use rusqlite::Transaction;

use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version of the account key source of relay memberships.
pub(super) const ACCOUNT_KEY_SCHEMA_VERSION: i64 = 34;
/// The newest schema before this one in the migration chain.
pub(super) const PREVIOUS_SCHEMA_VERSION: i64 = super::schema29::BOUNCER_HOST_SCHEMA_VERSION;

const _: () = assert!(SCHEMA_VERSION == ACCOUNT_KEY_SCHEMA_VERSION);
const _: () = assert!(PREVIOUS_SCHEMA_VERSION < ACCOUNT_KEY_SCHEMA_VERSION);

/// The stored name of a row that keeps its own key.
pub(super) const KEY_SOURCE_VAULT: &str = "vault";
/// The stored name of a row that signs with the Connect account device key.
pub(super) const KEY_SOURCE_ACCOUNT: &str = "account";

/// The column of schema 34. An `account` row has an empty `key_pkcs8`.
const SCHEMA_V34_SQL: &str = "
ALTER TABLE relay_membership ADD COLUMN key_source TEXT NOT NULL DEFAULT 'vault'
    CHECK (key_source = 'vault' OR (key_source = 'account' AND length(key_pkcs8) = 0));
";

/// What `verify_expected_columns_in` reads for schema 34 and later.
pub(super) const COLUMNS: [&str; 1] = ["SELECT key_source FROM relay_membership LIMIT 0"];

/// The version marks of `version` in `vault_meta` and in the header.
fn marks_sql(version: i64) -> String {
    format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    )
}

/// Add schema version 34 in the migration or create transaction. Then the columns of
/// schema 34 are checked in the same transaction.
pub(super) fn add_schema_v34(tx: &Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(SCHEMA_V34_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute_batch(&marks_sql(ACCOUNT_KEY_SCHEMA_VERSION))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    verify_expected_columns_in(tx, "main", ACCOUNT_KEY_SCHEMA_VERSION)
}

/// The way back to the previous schema, for test fixtures and for the rollback notes:
/// the `account` rows are deleted (they hold no key an older build could use), then the
/// column goes.
#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut sql = "
DELETE FROM relay_membership WHERE key_source = 'account';
ALTER TABLE relay_membership DROP COLUMN key_source;
"
    .to_owned();
    sql.push_str(&marks_sql(PREVIOUS_SCHEMA_VERSION));
    sql
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rusqlite::Connection;
    use zeroize::Zeroizing;

    use super::*;
    use crate::vault::{
        MembershipPurpose, OPEN_EXISTING, RelayMembership, Vault, VaultErrorKind, apply_key,
        close_conn,
    };

    const PASS: &str = "synthetic-schema34-pass";

    fn version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    fn meta_version(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn raw(path: &std::path::Path) -> Connection {
        let conn = Connection::open_with_flags(path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        conn
    }

    fn public_key(byte: u8) -> Vec<u8> {
        let mut key = vec![0x04];
        key.extend_from_slice(&[byte; 64]);
        key
    }

    fn questions(team: &str) -> RelayMembership {
        RelayMembership {
            team_id: team.to_owned(),
            relay_url: "https://relay.example.test".to_owned(),
            device_id: 2,
            public_key: public_key(7),
            key_pkcs8: Zeroizing::new(vec![0xab; 138]),
            purposes: BTreeSet::from([MembershipPurpose::Questions]),
            created_at: 0,
        }
    }

    /// A vault of the previous schema with one membership that keeps its own key.
    fn previous_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("previous.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .add_relay_membership(&questions("t_aaaaaaaaaa"))
            .unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        conn.execute_batch(&downgrade_sql()).unwrap();
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(
            conn.prepare("SELECT key_source FROM relay_membership")
                .is_err()
        );
        close_conn(conn).unwrap();
        path
    }

    #[test]
    fn a_previous_vault_moves_to_34_and_its_rows_keep_their_own_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = previous_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), SCHEMA_VERSION);
        assert_eq!(meta_version(conn), SCHEMA_VERSION);
        let source: String = conn
            .query_row(
                "SELECT key_source FROM relay_membership WHERE team_id = 't_aaaaaaaaaa'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, KEY_SOURCE_VAULT);
        let read = vault.relay_membership("t_aaaaaaaaaa").unwrap().unwrap();
        assert!(!read.uses_account_key());
        assert_eq!(read.key_pkcs8.as_slice(), &[0xab; 138][..]);
    }

    #[test]
    fn an_account_row_never_holds_a_private_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        // The check of the column refuses a key in an account row and an unknown source.
        for (source, key) in [
            (KEY_SOURCE_ACCOUNT, vec![1u8; 138]),
            ("keychain", Vec::new()),
        ] {
            assert!(
                conn.execute(
                    "INSERT INTO relay_membership
                         (team_id, relay_url, device_id, public_key, key_pkcs8, purposes,
                          created_at, key_source)
                     VALUES ('t_bbbbbbbbbb', 'https://relay.example.test', 1, ?1, ?2,
                             '[\"sync\"]', 1, ?3)",
                    rusqlite::params![public_key(9), key, source],
                )
                .is_err(),
                "{source}"
            );
        }
        conn.execute(
            "INSERT INTO relay_membership
                 (team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at,
                  key_source)
             VALUES ('t_bbbbbbbbbb', 'https://relay.example.test', 1, ?1, X'', '[\"sync\"]', 1,
                     'account')",
            [public_key(9)],
        )
        .unwrap();
    }

    #[test]
    fn the_way_back_deletes_the_account_rows_and_keeps_the_others() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("down.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .add_relay_membership(&questions("t_aaaaaaaaaa"))
            .unwrap();
        vault
            .set_account_relay_device(
                "https://connect.example.test",
                "t_cccccccccc",
                1,
                &public_key(5),
            )
            .unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        conn.execute_batch(&downgrade_sql()).unwrap();
        let teams: Vec<String> = conn
            .prepare("SELECT team_id FROM relay_membership ORDER BY team_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(teams, ["t_aaaaaaaaaa"]);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        close_conn(conn).unwrap();
        // The next unlock of this build moves the file to 34 again.
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(version(vault.conn_ref().unwrap()), SCHEMA_VERSION);
        assert!(vault.relay_device().unwrap().is_none());
    }

    #[test]
    fn a_failed_migration_keeps_the_previous_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = previous_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v34(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        // A column of that name already there makes the unlock fail, and the file keeps
        // the previous schema.
        conn.execute_batch("ALTER TABLE relay_membership ADD COLUMN key_source TEXT;")
            .unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        assert_eq!(
            vault.unlock(PASS).unwrap_err().kind(),
            VaultErrorKind::Storage
        );
        drop(vault);
        let conn = raw(&path);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        conn.execute_batch("ALTER TABLE relay_membership DROP COLUMN key_source;")
            .unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(version(vault.conn_ref().unwrap()), SCHEMA_VERSION);
    }

    #[test]
    fn copies_of_the_previous_schema_still_merge_and_later_ones_do_not() {
        assert!(crate::vault::merge::LOCAL_TABLES.contains(&"relay_membership"));
        for version in [16, PREVIOUS_SCHEMA_VERSION, ACCOUNT_KEY_SCHEMA_VERSION] {
            assert!(
                crate::vault::merge::is_mergeable_schema(version),
                "{version}"
            );
        }
        for version in [28, 30, 33, ACCOUNT_KEY_SCHEMA_VERSION + 1] {
            assert!(
                !crate::vault::merge::is_mergeable_schema(version),
                "{version}"
            );
        }
    }
}
