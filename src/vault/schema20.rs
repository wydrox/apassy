//! Local owner-authorized permission to ask the bouncer (never permission to execute).
//! No rows migrate from answers or usage, and no scope is exported or merged.

use super::types::{VaultErrorKind, VaultResult, err};

pub(super) const SCHEMA_V20_COLUMNS: [&str; 1] = [
    "SELECT id, agent_id, item_id, item_uuid, project_key, project_label, action_kind, revision, hosts, command_binding, answered_on FROM bouncer_scope LIMIT 0",
];

const TABLE_SQL: &str = "
CREATE TABLE bouncer_scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    item_uuid TEXT NOT NULL,
    project_key TEXT NOT NULL,
    project_label TEXT NOT NULL,
    action_kind TEXT NOT NULL CHECK (action_kind IN ('read', 'change', 'deploy', 'delete')),
    revision INTEGER NOT NULL,
    hosts TEXT NOT NULL,
    command_binding TEXT,
    answered_on TEXT NOT NULL,
    UNIQUE (agent_id, item_id, project_key, action_kind)
);
CREATE TRIGGER bouncer_scope_item_update AFTER UPDATE OF title, kind, notes, revision, uuid ON item BEGIN
    DELETE FROM bouncer_scope WHERE item_id = OLD.id;
END;
CREATE TRIGGER bouncer_scope_item_delete AFTER DELETE ON item BEGIN
    DELETE FROM bouncer_scope WHERE item_id = OLD.id;
END;
CREATE TRIGGER bouncer_scope_agent_update AFTER UPDATE OF revoked_at, token, see_all ON agent BEGIN
    DELETE FROM bouncer_scope WHERE agent_id = OLD.id;
END;
CREATE TRIGGER bouncer_scope_agent_delete AFTER DELETE ON agent BEGIN
    DELETE FROM bouncer_scope WHERE agent_id = OLD.id;
END;
";

fn triggers_sql() -> String {
    let mut sql = String::new();
    // Direct child triggers also run while sync applies rows. A timestamp or vector
    // clock stamp alone is not an edit and must not discard the owner's scope.
    for table in super::merge::CHILD_TABLES {
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
    for table in ["agent_exception", "grant_rule", "exec_grant"] {
        // An only-list edit can restrict other items too. Other grants invalidate
        // only the affected item, so granting a new credential preserves old scopes.
        let predicate = |target: &str| {
            let agent = format!("agent_id = {target}.agent_id");
            if table == "agent_exception" {
                agent
            } else {
                format!("({agent} AND item_id = {target}.item_id)")
            }
        };
        for (event, target) in [("insert", "NEW"), ("delete", "OLD")] {
            let predicate = predicate(target);
            sql.push_str(&format!(
                "CREATE TRIGGER bouncer_scope_{table}_{event} AFTER {event} ON {table} BEGIN
                 DELETE FROM bouncer_scope WHERE {predicate}; END;\n"
            ));
        }
        let old = predicate("OLD");
        let new = predicate("NEW");
        sql.push_str(&format!(
            "CREATE TRIGGER bouncer_scope_{table}_update AFTER UPDATE ON {table} BEGIN
             DELETE FROM bouncer_scope WHERE {old} OR {new}; END;\n"
        ));
    }
    sql
}

pub(super) fn add_schema_v20(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    tx.execute_batch(TABLE_SQL).map_err(storage)?;
    tx.execute_batch(&triggers_sql()).map_err(storage)?;
    tx.execute_batch(
        "UPDATE vault_meta SET schema_version = 20 WHERE id = 1; PRAGMA user_version = 20;",
    )
    .map_err(storage)?;
    super::verify_expected_columns_in(tx, "main", 20)
}

#[cfg(test)]
pub(super) fn downgrade_sql() -> String {
    let mut names = vec![
        "item_update".to_owned(),
        "item_delete".to_owned(),
        "agent_update".to_owned(),
        "agent_delete".to_owned(),
    ];
    for table in super::merge::CHILD_TABLES.into_iter().chain([
        "agent_exception",
        "grant_rule",
        "exec_grant",
    ]) {
        for event in ["insert", "update", "delete"] {
            names.push(format!("{table}_{event}"));
        }
    }
    let mut sql = names
        .into_iter()
        .map(|name| format!("DROP TRIGGER bouncer_scope_{name};\n"))
        .collect::<String>();
    sql.push_str("DROP TABLE IF EXISTS relay_connect_pending; DROP TABLE bouncer_scope; UPDATE vault_meta SET schema_version = 19 WHERE id = 1; PRAGMA user_version = 19;");
    sql
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{OPEN_EXISTING, Vault, apply_key, close_conn};

    #[test]
    fn schema19_migrates_to_empty_local_scopes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("scope-migration.db");
        let pass = "synthetic-scope-migration";
        let mut vault = Vault::create(&path, pass).unwrap();
        vault.unlock(pass).unwrap();
        vault.lock().unwrap();
        let conn = rusqlite::Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, pass).unwrap();
        conn.execute_batch(&downgrade_sql()).unwrap();
        close_conn(conn).unwrap();
        vault.unlock(pass).unwrap();
        let count: i64 = vault
            .conn_ref()
            .unwrap()
            .query_row("SELECT count(*) FROM bouncer_scope", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        assert!(super::super::merge::LOCAL_TABLES.contains(&"bouncer_scope"));
        assert!(!super::super::merge::SYNCED_TABLES.contains(&"bouncer_scope"));
    }
}
