//! Schema version 26: the cloud agents of the Mac's own node (ADR 0037, cloud slice,
//! decision 3; docs/design/implementation-plan-0037-cloud-agents.md).
//!
//! - `agent.kind`: `local` (an agent on this Mac with a vault token, as before) or
//!   `cloud` (a hosted agent that reaches the node of this Mac through Tailscale Funnel).
//!   A cloud agent is an ordinary vault agent: ADR 0012 visibility, its exceptions, and
//!   the activity log work for it unchanged. Its token is a token of the node, which
//!   keeps only its hash; the vault token of its row is random, never shown, and never
//!   authenticates ([`super::Vault::identify_agent`] reads `local` agents only).
//! - `cloud_agent`: for each cloud agent, its id in the node, the expiry of its node
//!   token, and its last use. A row of a revoked agent stays until the node revoked the
//!   agent too ([`super::Vault::pending_cloud_revocations`]).
//! - `cloud_item`: the uid of each vault item in the catalog mirror of the node. The uid
//!   names the item at the node boundary for its whole life.
//! - `cloud_node`: one row: the team of this vault in the node, the loopback port of the
//!   public listener (the Funnel target, chosen once in 49152 to 65535), and the switch
//!   of the public route (off by default).
//!
//! All four are local ([`super::merge::LOCAL_TABLES`]): a node belongs to one Mac, so a
//! pushed copy carries none of their rows, and a merge never reads them.
//!
//! Schema 25 is the passkey formats and WebAuthn extension fields of another change,
//! which this build does not have. This build refuses a file and a synced copy of schema
//! 25 as it refuses any version that it does not know, and it moves a vault of schema 24
//! or earlier straight to 26. With the passkey change in the same build, the steps run
//! in order: 24, 25, 26.

use rusqlite::Transaction;

use super::types::{VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version of the cloud agents.
pub(super) const CLOUD_SCHEMA_VERSION: i64 = 26;

/// The version of another change that this build does not know (see the module text).
pub(super) const UNKNOWN_SCHEMA_VERSION: i64 = 25;

/// The column and the tables of schema 26. The node row starts empty with the route off.
const SCHEMA_V26_SQL: &str = "
ALTER TABLE agent ADD COLUMN kind TEXT NOT NULL DEFAULT 'local' CHECK (kind IN ('local', 'cloud'));
CREATE TABLE cloud_agent (
    agent_id INTEGER PRIMARY KEY,
    relay_agent_id INTEGER NOT NULL CHECK (relay_agent_id >= 1),
    token_expires_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE TABLE cloud_item (
    item_id INTEGER PRIMARY KEY,
    uid TEXT NOT NULL UNIQUE CHECK (length(uid) = 32)
);
CREATE TABLE cloud_node (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    team_id TEXT,
    port INTEGER CHECK (port IS NULL OR port BETWEEN 49152 AND 65535),
    route_on INTEGER NOT NULL DEFAULT 0 CHECK (route_on IN (0, 1))
);
INSERT INTO cloud_node (id, team_id, port, route_on) VALUES (1, NULL, NULL, 0);
UPDATE vault_meta SET schema_version = 26 WHERE id = 1;
PRAGMA user_version = 26;
";

/// What `verify_expected_columns_in` reads for schema 26 and later.
pub(super) const COLUMNS: [&str; 4] = [
    "SELECT kind FROM agent LIMIT 0",
    "SELECT agent_id, relay_agent_id, token_expires_at, last_used_at FROM cloud_agent LIMIT 0",
    "SELECT item_id, uid FROM cloud_item LIMIT 0",
    "SELECT id, team_id, port, route_on FROM cloud_node LIMIT 0",
];

/// The way back to schema 24, for test fixtures and for the rollback notes: a cloud
/// agent becomes a revoked ordinary agent (a build of schema 24 would take it for a
/// local agent with a token that nobody has), then the tables and the column go.
#[cfg(test)]
pub(super) const DOWNGRADE_TO_24_SQL: &str = "
UPDATE agent SET revoked_at = COALESCE(revoked_at, CAST(strftime('%s', 'now') AS INTEGER))
    WHERE kind = 'cloud';
DROP TABLE cloud_node;
DROP TABLE cloud_item;
DROP TABLE cloud_agent;
ALTER TABLE agent DROP COLUMN kind;
UPDATE vault_meta SET schema_version = 24 WHERE id = 1;
PRAGMA user_version = 24;
";

/// Add schema version 26 in the migration or create transaction. Then the columns of
/// schema 26 are checked in the same transaction.
pub(super) fn add_schema_v26(tx: &Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(SCHEMA_V26_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    verify_expected_columns_in(tx, "main", CLOUD_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, OPEN_EXISTING, SecretValue, Vault, apply_key, close_conn};

    const PASS: &str = "synthetic-schema26-pass";

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

    fn api_key(title: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(format!("SYNTH-{title}-value-0123456789")),
                secret: true,
            }],
        }
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

    /// A vault of schema 24 with one local agent and one item.
    fn schema24_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("v24.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault.add(api_key("Synthetic")).unwrap();
        vault.register_agent("Synthetic local").unwrap();
        vault.lock().unwrap();
        let conn = raw(&path);
        conn.execute_batch(DOWNGRADE_TO_24_SQL).unwrap();
        assert_eq!(version(&conn), 24);
        assert!(!has_table(&conn, "cloud_agent"));
        assert!(conn.prepare("SELECT kind FROM agent").is_err());
        close_conn(conn).unwrap();
        path
    }

    #[test]
    fn a_schema24_vault_moves_to_26_with_local_agents_and_the_route_off() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema24_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), CLOUD_SCHEMA_VERSION);
        assert_eq!(meta_version(conn), CLOUD_SCHEMA_VERSION);
        let kinds: Vec<String> = conn
            .prepare("SELECT kind FROM agent ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(kinds, ["local"]);
        let setting = vault.cloud_node_setting().unwrap();
        assert_eq!(setting, crate::vault::CloudNodeSetting::default());
        assert!(!vault.has_cloud_agents().unwrap());
        // An unknown kind is refused.
        assert!(
            vault
                .conn_ref()
                .unwrap()
                .execute("UPDATE agent SET kind = 'remote'", [])
                .is_err()
        );
    }

    #[test]
    fn a_failed_migration_keeps_schema_24() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema24_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v26(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), 24);
        assert_eq!(meta_version(&conn), 24);
        assert!(!has_table(&conn, "cloud_node"));
        assert!(conn.prepare("SELECT kind FROM agent").is_err());
        close_conn(conn).unwrap();
    }

    #[test]
    fn the_way_back_to_24_revokes_cloud_agents_and_the_next_unlock_moves_to_26_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("v26.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(api_key("Cloud")).unwrap().id;
        let (local, token) = vault.register_agent("Synthetic local").unwrap();
        let cloud = vault
            .add_cloud_agent("Synthetic cloud", &[item], 7, 4_000_000_000)
            .unwrap();
        vault.set_cloud_node_team(Some("t_abcdefgh23")).unwrap();
        vault.lock().unwrap();
        // The file lock goes with the vault.
        drop(vault);

        let conn = raw(&path);
        conn.execute_batch(DOWNGRADE_TO_24_SQL).unwrap();
        assert_eq!(version(&conn), 24);
        let revoked: Vec<(i64, bool)> = conn
            .prepare("SELECT id, revoked_at IS NOT NULL FROM agent ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            revoked,
            [
                (i64::try_from(local.id).unwrap(), false),
                (i64::try_from(cloud).unwrap(), true)
            ]
        );
        close_conn(conn).unwrap();

        // This build moves the file to 26 again: the old cloud agent stays revoked, the
        // local agent keeps its token, and the node settings start again.
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(version(vault.conn_ref().unwrap()), CLOUD_SCHEMA_VERSION);
        assert_eq!(vault.authenticate_agent(token.expose()).unwrap().id, local.id);
        assert!(vault.cloud_agents().unwrap().is_empty());
        assert_eq!(vault.cloud_node_setting().unwrap().team_id, None);
    }

    #[test]
    fn a_file_of_schema_25_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema24_file(&dir);
        let conn = raw(&path);
        conn.execute_batch(&format!(
            "UPDATE vault_meta SET schema_version = {UNKNOWN_SCHEMA_VERSION} WHERE id = 1;
             PRAGMA user_version = {UNKNOWN_SCHEMA_VERSION};"
        ))
        .unwrap();
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        let refused = vault.unlock(PASS).unwrap_err();
        assert_eq!(refused.kind(), VaultErrorKind::UnsupportedSchema);
        assert!(!crate::vault::merge::is_mergeable_schema(UNKNOWN_SCHEMA_VERSION));
        assert!(crate::vault::merge::is_mergeable_schema(CLOUD_SCHEMA_VERSION));
        assert!(crate::vault::merge::is_mergeable_schema(24));
    }

    #[test]
    fn a_new_vault_has_the_tables_of_schema_26() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), CLOUD_SCHEMA_VERSION);
        for table in ["cloud_agent", "cloud_item", "cloud_node"] {
            assert!(has_table(conn, table), "{table}");
            assert!(crate::vault::merge::LOCAL_TABLES.contains(&table), "{table}");
        }
    }
}
