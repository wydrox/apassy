//! Schema version 29: who hosts and who trains the bouncer brain (ADR 0035,
//! docs/design/implementation-plan-0035.md, units C2 and F).
//!
//! - `bouncer_host`: at most one row for each role (`hosting`, `training`). No row for a
//!   role means "this Mac", as before. A row names the owner's own server (`own_server`,
//!   with its bearer token) or Apassy Connect (`connect`, no bearer: the Connect device
//!   key signs in). The row records the version of the consent screen that the owner
//!   accepted and when. Only the owner changes a row, with a fresh owner check
//!   (`OwnerAction::ChangeBouncerHosting`, `OwnerAction::ChangeBouncerTraining`), which
//!   the global owner window never covers.
//! - `model_candidate.origin`, `job_host`, `job_id` and `uploaded_to`, and
//!   `model_activation.heads_sha256`: the columns of unit F (a head set trained by a
//!   remote job, and the head hash that a promotion pins). This schema only adds them.
//!
//! The table is local ([`super::merge::LOCAL_TABLES`]): the host and its bearer belong to
//! this Mac, so a pushed copy carries none of its rows, and a merge never reads them.
//! The new columns are in local tables too. `Vault::read_vault_secret` was rejected for
//! the bearer, because a vault secret syncs last-writer-wins across devices.
//!
//! Schema 29 follows [`PREVIOUS_SCHEMA_VERSION`]: a vault of an earlier schema runs the
//! steps before it and then this one, in one migration. A merge takes a synced copy of
//! schema 16 to the previous schema as before. A device of the previous schema or
//! earlier refuses a copy of schema 29 (`UnsupportedSchema`).
//!
//! The number lives in [`BOUNCER_HOST_SCHEMA_VERSION`] only, so a release coordinator
//! that renumbers this step changes that constant and [`PREVIOUS_SCHEMA_VERSION`].

use rusqlite::Transaction;

use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version of the bouncer brain host.
pub(super) const BOUNCER_HOST_SCHEMA_VERSION: i64 = 29;
/// The newest schema before this one in the migration chain.
pub(super) const PREVIOUS_SCHEMA_VERSION: i64 = super::schema27::STATS_SCHEMA_VERSION;

const _: () = assert!(SCHEMA_VERSION == BOUNCER_HOST_SCHEMA_VERSION);
const _: () = assert!(PREVIOUS_SCHEMA_VERSION < BOUNCER_HOST_SCHEMA_VERSION);

/// The table and the columns of schema 29. The DDL is the one of the plan.
const SCHEMA_V29_SQL: &str = "
CREATE TABLE bouncer_host (
    role TEXT PRIMARY KEY CHECK (role IN ('hosting', 'training')),
    kind TEXT NOT NULL CHECK (kind IN ('own_server', 'connect')),
    url TEXT NOT NULL,
    bearer BLOB,
    consent_version INTEGER NOT NULL,
    consented_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
ALTER TABLE model_candidate ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'
    CHECK (origin IN ('local', 'remote_job'));
ALTER TABLE model_candidate ADD COLUMN job_host TEXT;
ALTER TABLE model_candidate ADD COLUMN job_id TEXT;
ALTER TABLE model_candidate ADD COLUMN uploaded_to TEXT;
ALTER TABLE model_activation ADD COLUMN heads_sha256 TEXT;
";

/// What `verify_expected_columns_in` reads for schema 29 and later.
pub(super) const COLUMNS: [&str; 3] = [
    "SELECT role, kind, url, bearer, consent_version, consented_at, updated_at
            FROM bouncer_host LIMIT 0",
    "SELECT origin, job_host, job_id, uploaded_to FROM model_candidate LIMIT 0",
    "SELECT heads_sha256 FROM model_activation LIMIT 0",
];

/// The version marks of `version` in `vault_meta` and in the header.
fn marks_sql(version: i64) -> String {
    format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    )
}

/// Add schema version 29 in the migration or create transaction. Then the columns of
/// schema 29 are checked in the same transaction.
pub(super) fn add_schema_v29(tx: &Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(SCHEMA_V29_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute_batch(&marks_sql(BOUNCER_HOST_SCHEMA_VERSION))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    verify_expected_columns_in(tx, "main", BOUNCER_HOST_SCHEMA_VERSION)
}

/// The way back to the previous schema, for test fixtures and for the rollback notes:
/// the host rows go with their table (the next unlock of this build starts again with
/// "this Mac"), then the columns of unit F go.
#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut sql = "
DROP TABLE bouncer_host;
ALTER TABLE model_candidate DROP COLUMN origin;
ALTER TABLE model_candidate DROP COLUMN job_host;
ALTER TABLE model_candidate DROP COLUMN job_id;
ALTER TABLE model_candidate DROP COLUMN uploaded_to;
ALTER TABLE model_activation DROP COLUMN heads_sha256;
"
    .to_owned();
    sql.push_str(&marks_sql(PREVIOUS_SCHEMA_VERSION));
    sql
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::vault::{
        BouncerHostChange, BouncerHostKind, BouncerHostRole, HOSTING_CONSENT_VERSION,
        OPEN_EXISTING, SecretValue, Vault, VaultErrorKind, apply_key, close_conn,
    };

    const PASS: &str = "synthetic-schema29-pass";
    const BEARER: &str = "SYNTH-bearer-schema29-0123456789abcdef";

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

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    fn own_server() -> BouncerHostChange {
        BouncerHostChange {
            kind: BouncerHostKind::OwnServer,
            url: "https://brain.synthetic.ts.net".to_owned(),
            bearer: Some(SecretValue::new(BEARER.to_owned())),
            consent_version: HOSTING_CONSENT_VERSION,
        }
    }

    /// A vault of the previous schema with one candidate model and one host row before
    /// the downgrade (the row goes with the table).
    fn previous_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("previous.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .set_bouncer_host(BouncerHostRole::Hosting, &own_server(), 1_700_000_000)
            .unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        conn.execute(
            "INSERT INTO model_candidate
                 (version, url, checkpoint, checkpoint_sha256, created_at, state, report)
             VALUES ('cand-1', 'http://127.0.0.1:8775', 'heads.safetensors', ?1, 1, 'shadow', '{}')",
            ["ab".repeat(32)],
        )
        .unwrap();
        conn.execute_batch(&downgrade_sql()).unwrap();
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_table(&conn, "bouncer_host"));
        assert!(conn.prepare("SELECT origin FROM model_candidate").is_err());
        close_conn(conn).unwrap();
        path
    }

    #[test]
    fn a_previous_vault_moves_to_29_with_this_mac_and_local_candidates() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = previous_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), BOUNCER_HOST_SCHEMA_VERSION);
        assert_eq!(meta_version(conn), BOUNCER_HOST_SCHEMA_VERSION);
        let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = conn
            .prepare("SELECT origin, job_host, job_id, uploaded_to FROM model_candidate")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, [("local".to_owned(), None, None, None)]);
        // An unknown origin is refused.
        assert!(
            conn.execute("UPDATE model_candidate SET origin = 'cloud'", [])
                .is_err()
        );
        // No row: this Mac hosts and trains.
        for role in [BouncerHostRole::Hosting, BouncerHostRole::Training] {
            assert_eq!(vault.bouncer_host(role).unwrap(), None, "{role:?}");
            assert!(vault.bouncer_host_bearer(role).unwrap().is_none());
        }
    }

    #[test]
    fn a_failed_migration_keeps_the_previous_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = previous_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v29(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_table(&conn, "bouncer_host"));
        // A table with the name of the new table makes the unlock fail, and the file
        // keeps the previous schema.
        conn.execute_batch("CREATE TABLE bouncer_host (x INTEGER);")
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
        assert!(
            conn.prepare("SELECT heads_sha256 FROM model_activation")
                .is_err()
        );
        conn.execute_batch("DROP TABLE bouncer_host;").unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(
            version(vault.conn_ref().unwrap()),
            BOUNCER_HOST_SCHEMA_VERSION
        );
    }

    #[test]
    fn a_new_vault_has_the_local_table_of_schema_29() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), BOUNCER_HOST_SCHEMA_VERSION);
        assert!(has_table(conn, "bouncer_host"));
        assert!(crate::vault::merge::LOCAL_TABLES.contains(&"bouncer_host"));
        assert!(!crate::vault::merge::SYNCED_TABLES.contains(&"bouncer_host"));
        for version in [16, PREVIOUS_SCHEMA_VERSION, BOUNCER_HOST_SCHEMA_VERSION] {
            assert!(
                crate::vault::merge::is_mergeable_schema(version),
                "{version}"
            );
        }
        assert!(!crate::vault::merge::is_mergeable_schema(
            BOUNCER_HOST_SCHEMA_VERSION + 1
        ));
    }
}
