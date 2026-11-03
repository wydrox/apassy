//! Schema version 32: short-lived credentials ("way C") and keys per member (ADR 0037
//! stage 6, docs/design/implementation-plan-s6-sharing.md unit D, contract
//! docs/contracts/private-sharing-v1.md sections 3 and 8).
//!
//! - `short_lived`: at most one row per item. The row makes the item a source: the key
//!   holder makes a lease from its fields for each run instead of releasing the value
//!   (S6-3). `kind` names the provider call, `settings` holds the strict settings object
//!   of the kind (role ARN, policy, region, services, scopes, URLs; never a secret), and
//!   `enabled` is way C on (`1`) or off (`0`, only by the owner with
//!   `OwnerAction::ChangeDelivery`). A row that is off keeps its kind and its settings:
//!   a signer item reads `region` and `services` from it.
//! - `member_key`: a key that the team host made for one member from a source item
//!   (contract section 8, units J1 and J2). `item_id` is the member key item;
//!   `source_uuid` names the team item by its sync UUID, because row IDs differ between
//!   copies (as `item_home.home_uuid` does). `remote_id` is the provider's id of the key,
//!   not a secret.
//!
//! Both tables are child tables of a credential ([`CHILD_TABLES_V32`]): they sync with
//! their item, in [`super::merge::SYNCED_TABLES`], and their triggers mark a change of
//! the item. They hold no secret, so a pushed copy keeps them. They are not in
//! [`super::merge::CHILD_TABLES`], because schema 20 makes its bouncer scope triggers for
//! each table of that list, before this schema exists; this step makes those triggers
//! for its own tables.
//!
//! Schema 32 follows [`PREVIOUS_SCHEMA_VERSION`]: a vault of an earlier schema runs the
//! steps before it and then this one, in one migration. A merge takes a synced copy of
//! an earlier schema and keeps the rows of this vault for its records
//! (`merge::keep_local_v32`). A device of the previous schema or earlier refuses a copy
//! of schema 32 (`UnsupportedSchema`).
//!
//! The number lives in [`SHORT_LIVED_SCHEMA_VERSION`] only, so a release coordinator that
//! renumbers this step (schemas 28, 30 and 31 come from other plans) changes that
//! constant and [`PREVIOUS_SCHEMA_VERSION`].

use rusqlite::Transaction;

use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err};
use super::{merge, verify_expected_columns_in};

/// The schema version of short-lived credentials and member keys.
pub(super) const SHORT_LIVED_SCHEMA_VERSION: i64 = 32;
/// The newest schema before this one in the migration chain.
pub(super) const PREVIOUS_SCHEMA_VERSION: i64 = super::schema29::BOUNCER_HOST_SCHEMA_VERSION;

// Schema 34 (`schema34.rs`) follows this step.
const _: () = assert!(SHORT_LIVED_SCHEMA_VERSION < SCHEMA_VERSION);
const _: () = assert!(PREVIOUS_SCHEMA_VERSION < SHORT_LIVED_SCHEMA_VERSION);

/// The child tables of a credential added in schema 32.
pub(super) const CHILD_TABLES_V32: [&str; 2] = ["short_lived", "member_key"];

/// The tables and indexes of schema 32. The DDL is the one of the plan, with
/// `source_uuid` for the source item of a member key.
const SCHEMA_V32_SQL: &str = "
CREATE TABLE short_lived (
    item_id INTEGER PRIMARY KEY REFERENCES item(id),
    kind TEXT NOT NULL CHECK (kind IN ('aws_sts', 'github_app', 'google_service_account',
        'oauth_refresh', 'cloudflare_token', 'planetscale_password', 'neon_role')),
    settings TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE member_key (
    item_id INTEGER PRIMARY KEY REFERENCES item(id),
    source_uuid TEXT NOT NULL,
    team_id TEXT NOT NULL CHECK (length(team_id) BETWEEN 1 AND 128),
    member_id INTEGER NOT NULL CHECK (member_id >= 1),
    manager TEXT NOT NULL CHECK (manager IN ('cloudflare_token', 'aws_iam')),
    remote_id TEXT NOT NULL CHECK (length(remote_id) BETWEEN 1 AND 256),
    created_at INTEGER NOT NULL
);
CREATE INDEX member_key_source ON member_key(source_uuid);
CREATE INDEX member_key_member ON member_key(team_id, member_id);
";

/// What `verify_expected_columns_in` reads for schema 32 and later.
pub(super) const COLUMNS: [&str; 2] = [
    "SELECT item_id, kind, settings, enabled, created_at, updated_at FROM short_lived LIMIT 0",
    "SELECT item_id, source_uuid, team_id, member_id, manager, remote_id, created_at
            FROM member_key LIMIT 0",
];

/// The bouncer scope triggers of the new child tables, as schema 20 makes them for the
/// child tables of its time: a change of the delivery of an item is a change of what an
/// agent may get from it.
fn bouncer_scope_triggers_sql() -> String {
    let mut sql = String::new();
    for table in CHILD_TABLES_V32 {
        for (event, target) in [("insert", "NEW"), ("delete", "OLD")] {
            sql.push_str(&format!(
                "CREATE TRIGGER bouncer_scope_{table}_{event} AFTER {event} ON {table} BEGIN
                 DELETE FROM bouncer_scope WHERE item_id = {target}.item_id; END;\n"
            ));
        }
        sql.push_str(&format!(
            "CREATE TRIGGER bouncer_scope_{table}_update AFTER UPDATE ON {table} BEGIN
             DELETE FROM bouncer_scope WHERE item_id IN (OLD.item_id, NEW.item_id); END;\n"
        ));
    }
    sql
}

/// The version marks of `version` in `vault_meta` and in the header.
fn marks_sql(version: i64) -> String {
    format!(
        "UPDATE vault_meta SET schema_version = {version} WHERE id = 1;
         PRAGMA user_version = {version};"
    )
}

/// Add schema version 32 in the migration or create transaction: the tables, the sync
/// and bouncer scope triggers of the new child tables, and the version marks. Then the
/// columns of schema 32 are checked in the same transaction, so a failure of any step
/// leaves the file at its old version.
pub(super) fn add_schema_v32(tx: &Transaction<'_>) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    tx.execute_batch(SCHEMA_V32_SQL).map_err(storage)?;
    tx.execute_batch(&merge::child_triggers_sql(&CHILD_TABLES_V32))
        .map_err(storage)?;
    tx.execute_batch(&bouncer_scope_triggers_sql())
        .map_err(storage)?;
    tx.execute_batch(&marks_sql(SHORT_LIVED_SCHEMA_VERSION))
        .map_err(storage)?;
    verify_expected_columns_in(tx, "main", SHORT_LIVED_SCHEMA_VERSION)
}

/// Remove the schema 32 rows of a deleted item: its source row and its member key row.
/// A member key row of another item that names this item as its source stays: the
/// remote key still exists until the team host deletes it ("Replace now", unit J2).
pub(super) fn forget_item(tx: &Transaction<'_>, item: i64) -> VaultResult<()> {
    for table in CHILD_TABLES_V32 {
        tx.execute(&format!("DELETE FROM {table} WHERE item_id = ?1"), [item])
            .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    Ok(())
}

/// The way back to the previous schema, for test fixtures and for the rollback notes:
/// the rows go with their tables (an item of a build of the previous schema is a static
/// key again, delivered as its binding says), and with the tables their triggers.
#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut sql = "
DROP TABLE member_key;
DROP TABLE short_lived;
"
    .to_owned();
    sql.push_str(&marks_sql(PREVIOUS_SCHEMA_VERSION));
    sql
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{
        Field, ItemDraft, OPEN_EXISTING, SecretValue, ShortLivedKind, Vault, apply_key, close_conn,
    };

    const PASS: &str = "synthetic-schema32-pass";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

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

    fn aws_pair() -> ItemDraft {
        ItemDraft {
            title: "Synthetic AWS".to_owned(),
            kind: CredentialKind::Custom,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                Field {
                    name: "access_key_id".to_owned(),
                    value: SecretValue::new("AKIAIOSFODNN7EXAMPLE".to_owned()),
                    secret: false,
                },
                Field {
                    name: "secret_access_key".to_owned(),
                    value: SecretValue::new(SECRET.to_owned()),
                    secret: true,
                },
            ],
        }
    }

    /// A vault of the previous schema with one AWS item (and its source row before the
    /// downgrade: the row goes with the table).
    fn previous_file(dir: &tempfile::TempDir) -> (std::path::PathBuf, u64) {
        let path = dir.path().join("previous.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(aws_pair()).unwrap().id;
        vault
            .set_short_lived(item, ShortLivedKind::AwsSts, "{}", 1_700_000_000)
            .unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        // Schema 34 (the account key source of relay memberships, `schema34.rs`) first.
        conn.execute_batch(&crate::vault::schema34::downgrade_sql())
            .unwrap();
        conn.execute_batch(&downgrade_sql()).unwrap();
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_table(&conn, "short_lived"));
        assert!(!has_table(&conn, "member_key"));
        close_conn(conn).unwrap();
        (path, item)
    }

    #[test]
    fn a_previous_vault_moves_to_32_with_static_items() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, item) = previous_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert_eq!(meta_version(conn), crate::vault::SCHEMA_VERSION);
        assert!(has_table(conn, "short_lived"));
        assert!(has_table(conn, "member_key"));
        // No row: the item is a static key, as before.
        assert_eq!(vault.short_lived(item).unwrap(), None);
        assert!(vault.short_lived_items().unwrap().is_empty());
        // The item keeps its fields.
        assert_eq!(
            vault.reveal(item, "secret_access_key").unwrap().expose(),
            SECRET
        );
    }

    #[test]
    fn a_failed_migration_keeps_the_previous_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let (path, _) = previous_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v32(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert_eq!(meta_version(&conn), PREVIOUS_SCHEMA_VERSION);
        assert!(!has_table(&conn, "short_lived"));
        // A table with the name of a new table makes the unlock fail, and the file keeps
        // the previous schema.
        conn.execute_batch("CREATE TABLE member_key (x INTEGER);")
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
        assert!(!has_table(&conn, "short_lived"));
        conn.execute_batch("DROP TABLE member_key;").unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(
            version(vault.conn_ref().unwrap()),
            crate::vault::SCHEMA_VERSION
        );
    }

    #[test]
    fn a_new_vault_has_the_synced_child_tables_of_schema_32() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        for table in CHILD_TABLES_V32 {
            assert!(has_table(conn, table), "{table}");
            assert!(merge::SYNCED_TABLES.contains(&table), "{table}");
            assert!(!merge::LOCAL_TABLES.contains(&table), "{table}");
            // Not in the list that schema 20 reads when it runs before this step.
            assert!(!merge::CHILD_TABLES.contains(&table), "{table}");
            for event in ["insert", "update", "delete"] {
                for prefix in ["", "bouncer_scope_"] {
                    let name = if prefix.is_empty() {
                        format!("{table}_sync_{event}")
                    } else {
                        format!("{prefix}{table}_{event}")
                    };
                    let count: i64 = conn
                        .query_row(
                            "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                            [&name],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert_eq!(count, 1, "{name}");
                }
            }
        }
        // Unknown kinds and managers are refused by the table itself.
        assert!(
            conn.execute(
                "INSERT INTO short_lived (item_id, kind, created_at, updated_at)
                 VALUES (1, 'static', 1, 1)",
                [],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO member_key
                     (item_id, source_uuid, team_id, member_id, manager, remote_id, created_at)
                 VALUES (1, 'u', 't', 1, 'github', 'r', 1)",
                [],
            )
            .is_err()
        );
        for version in [16, 27, PREVIOUS_SCHEMA_VERSION, SHORT_LIVED_SCHEMA_VERSION] {
            assert!(merge::is_mergeable_schema(version), "{version}");
        }
        // No build has the numbers between the previous schema and this one.
        for version in (PREVIOUS_SCHEMA_VERSION + 1)..SHORT_LIVED_SCHEMA_VERSION {
            assert!(!merge::is_mergeable_schema(version), "{version}");
        }
        assert!(!merge::is_mergeable_schema(SHORT_LIVED_SCHEMA_VERSION + 1));
    }

    #[test]
    fn a_change_of_a_source_row_marks_the_item_changed() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("mark.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(aws_pair()).unwrap().id;
        let stamp = |vault: &Vault| -> i64 {
            vault
                .conn_ref()
                .unwrap()
                .query_row(
                    "SELECT updated_at FROM item WHERE id = ?1",
                    [i64::try_from(item).unwrap()],
                    |row| row.get(0),
                )
                .unwrap()
        };
        vault
            .conn_ref()
            .unwrap()
            .execute(
                "UPDATE item SET updated_at = 1 WHERE id = ?1",
                [i64::try_from(item).unwrap()],
            )
            .unwrap();
        // The update trigger of the item itself keeps the explicit time here.
        let before = stamp(&vault);
        vault
            .set_short_lived(item, ShortLivedKind::AwsSts, "{}", 1_700_000_000)
            .unwrap();
        assert!(stamp(&vault) > before, "the insert marks the item");
        let before = stamp(&vault);
        std::thread::sleep(std::time::Duration::from_millis(5));
        vault
            .set_short_lived_enabled(item, false, 1_700_000_100)
            .unwrap();
        assert!(stamp(&vault) > before, "the switch marks the item");
    }
}
