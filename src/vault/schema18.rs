//! Schema version 18: folders, shared vaults, item policy, and the local tables of the
//! low-friction access model (ADR 0025, ADR 0026).
//!
//! Synced tables ([`super::merge::SYNCED_TABLES`]):
//!
//! - `folder`, `shared_vault`, and `vault_secret` sync row by row: the later
//!   `(updated_at, updated_by)` wins. A deleted folder or shared vault keeps its row
//!   with `deleted_at`, so the delete reaches the other Macs.
//! - `item_folder`, `item_policy`, `declaration_source`, and `item_share` are child rows
//!   of a credential ([`super::merge::CHILD_TABLES`]). They sync with the credential,
//!   and their triggers mark a change of the credential.
//!
//! Local tables ([`super::merge::LOCAL_TABLES`]): `agent.note`, `agent_exception`,
//! `owner_answer`, `item_use`, `item_origin`, `credential_request`, `correction`, and
//! `owner_interaction`.
//!
//! The migration from schema 17 turns the agent settings of ADR 0012 into exceptions
//! (ADR 0025 §3f), in the same transaction, so nothing gets looser without the owner.
//! Revoked agents, and grants of items that are gone, get nothing.
//!
//! - An active agent that does not see all items (`see_all = 0`) gets the exception
//!   "only these items": one `only` row with item [`ONLY_MARKER_ITEM`], one `only` row
//!   for each item of its process grants that still works (not expired, rule readable),
//!   and one for each item of its connector grants (`grant_rule`). The marker keeps an
//!   agent without grants restricted to no item.
//! - A process grant of an active agent becomes "Always ask for this agent"
//!   (`always_ask`) when today a run with it waits for the owner or meets a limit that the
//!   new model cannot hold: "Ask me each time" (`mode = 'ask'`); a rule with a command
//!   prefix, a forbidden word, a run limit, an expiry (past or future), or an
//!   instruction; a rule that does not read; or "any folder" with a variable that gets
//!   the real value (no binding counts as the real value).
//! - Any other grant in "Bouncer decides" becomes nothing: it is the default now.
//!   Grants, rules, requests, and remembered patterns stay as history; nothing is
//!   deleted.

use super::types::{VaultErrorKind, VaultResult, err};
use super::{FOLDER_SCHEMA_VERSION, agents, merge, verify_expected_columns_in};

/// The item ID of the `only` row that marks the exception "only these items" of an
/// agent. Item IDs start at 1, so the marker names no item. The other `only` rows of
/// the agent are the items that it may use.
///
/// `to_sql_id` refuses 0, so the code that removes the exception "only these items"
/// (stream B1, `exceptions.rs`) deletes the agent's rows by kind,
/// `DELETE FROM agent_exception WHERE agent_id = ?1 AND kind = 'only'`, marker included.
/// Removing the `only` row of one item keeps the marker, so an agent whose last item
/// goes stays restricted to no item.
pub const ONLY_MARKER_ITEM: u64 = 0;

/// Tables, columns, the exception derivation, and the version marks of schema 18. The
/// triggers of the new child tables come from [`merge::child_triggers_sql`].
const SCHEMA_V18_SQL: &str = "
CREATE TABLE folder (
    uuid TEXT PRIMARY KEY,
    parent_uuid TEXT,
    name TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted_at INTEGER
);
CREATE INDEX folder_parent ON folder(parent_uuid, position);
CREATE TABLE item_folder (
    item_id INTEGER PRIMARY KEY,
    folder_uuid TEXT NOT NULL
);
CREATE TABLE item_policy (
    item_id INTEGER PRIMARY KEY,
    always_ask INTEGER NOT NULL DEFAULT 0 CHECK (always_ask IN (0, 1))
);
CREATE TABLE declaration_source (
    item_id INTEGER PRIMARY KEY,
    environment TEXT NOT NULL CHECK (environment IN ('owner', 'signal', 'usage', 'default')),
    risk TEXT NOT NULL CHECK (risk IN ('owner', 'signal', 'usage', 'default')),
    scope TEXT NOT NULL CHECK (scope IN ('owner', 'signal', 'usage', 'default')),
    reversibility TEXT NOT NULL CHECK (reversibility IN ('owner', 'signal', 'usage', 'default'))
);
CREATE TABLE shared_vault (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '',
    relay_url TEXT NOT NULL,
    team_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted_at INTEGER
);
CREATE TABLE item_share (
    item_id INTEGER NOT NULL,
    shared_vault_uuid TEXT NOT NULL,
    PRIMARY KEY (item_id, shared_vault_uuid)
);
CREATE TABLE vault_secret (
    name TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
ALTER TABLE agent ADD COLUMN note TEXT NOT NULL DEFAULT '';
CREATE TABLE agent_exception (
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('never', 'always_ask', 'only')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, item_id, kind)
);
CREATE INDEX agent_exception_item ON agent_exception(item_id);
CREATE TABLE owner_answer (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    project_key TEXT NOT NULL,
    project_label TEXT NOT NULL,
    action_kind TEXT NOT NULL CHECK (action_kind IN ('read', 'change', 'deploy', 'delete')),
    scope TEXT NOT NULL CHECK (scope IN ('project', 'production')),
    created_at INTEGER NOT NULL,
    answered_on TEXT NOT NULL,
    hosts TEXT NOT NULL DEFAULT '[]',
    UNIQUE (item_id, project_key, action_kind, scope)
);
CREATE INDEX owner_answer_item ON owner_answer(item_id);
CREATE TABLE item_use (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    project_key TEXT NOT NULL,
    project_label TEXT NOT NULL,
    action_kind TEXT NOT NULL,
    command_summary TEXT NOT NULL,
    hosts TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'refused', 'timed_out')),
    decided_by TEXT NOT NULL CHECK (decided_by IN ('bouncer', 'pattern', 'answer', 'owner', 'rule')),
    answered_on TEXT NOT NULL DEFAULT '',
    decision_log_id INTEGER
);
CREATE INDEX item_use_item ON item_use(item_id, at);
CREATE INDEX item_use_agent ON item_use(agent_id, at);
CREATE TABLE item_origin (
    item_id INTEGER PRIMARY KEY,
    agent_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    project_key TEXT NOT NULL,
    project_label TEXT NOT NULL,
    tool TEXT NOT NULL CHECK (tool IN ('capture', 'generate', 'save', 'ask_owner')),
    created_at INTEGER NOT NULL,
    previous_value TEXT,
    previous_field TEXT,
    previous_at INTEGER,
    previous_use INTEGER
);
CREATE INDEX item_origin_agent ON item_origin(agent_id, created_at);
CREATE TABLE credential_request (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    project_key TEXT NOT NULL,
    project_label TEXT NOT NULL,
    name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    where_to_get TEXT NOT NULL,
    folder_uuid TEXT,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'saved', 'dismissed')),
    item_id INTEGER,
    decided_at INTEGER
);
CREATE INDEX credential_request_state ON credential_request(state, id);
CREATE TABLE correction (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('environment', 'project')),
    proposed TEXT NOT NULL,
    facts TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'accepted', 'ignored')),
    decided_at INTEGER,
    UNIQUE (item_id, kind, proposed)
);
CREATE TABLE owner_interaction (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('question', 'approval', 'owner_check', 'correction')),
    detail TEXT NOT NULL
);
CREATE INDEX owner_interaction_at ON owner_interaction(at);
";

/// The version marks of schema 18. They run after the exception derivation.
const SCHEMA_V18_MARKS_SQL: &str = "
UPDATE vault_meta SET schema_version = 18 WHERE id = 1;
PRAGMA user_version = 18;
";

/// The child tables of a credential added in schema 18. Each row names its item in
/// `item_id`.
pub(super) const CHILD_TABLES_V18: [&str; 4] = [
    "item_folder",
    "item_policy",
    "declaration_source",
    "item_share",
];

pub(super) const SCHEMA_V18_COLUMNS: [&str; 15] = [
    "SELECT uuid, parent_uuid, name, position, created_at, updated_at, updated_by, deleted_at FROM folder LIMIT 0",
    "SELECT item_id, folder_uuid FROM item_folder LIMIT 0",
    "SELECT item_id, always_ask FROM item_policy LIMIT 0",
    "SELECT item_id, environment, risk, scope, reversibility FROM declaration_source LIMIT 0",
    "SELECT uuid, name, color, relay_url, team_id, created_at, updated_at, updated_by, deleted_at FROM shared_vault LIMIT 0",
    "SELECT item_id, shared_vault_uuid FROM item_share LIMIT 0",
    "SELECT name, value, updated_at, updated_by FROM vault_secret LIMIT 0",
    "SELECT note FROM agent LIMIT 0",
    "SELECT agent_id, item_id, kind, created_at FROM agent_exception LIMIT 0",
    "SELECT id, item_id, project_key, project_label, action_kind, scope, created_at, answered_on, hosts FROM owner_answer LIMIT 0",
    "SELECT id, at, item_id, agent_id, agent_name, project_key, project_label, action_kind, command_summary, hosts, outcome, decided_by, answered_on, decision_log_id FROM item_use LIMIT 0",
    "SELECT item_id, agent_id, agent_name, project_key, project_label, tool, created_at, previous_value, previous_field, previous_at, previous_use FROM item_origin LIMIT 0",
    "SELECT id, agent_id, agent_name, project_key, project_label, name, purpose, where_to_get, folder_uuid, created_at, state, item_id, decided_at FROM credential_request LIMIT 0",
    "SELECT id, item_id, kind, proposed, facts, created_at, state, decided_at FROM correction LIMIT 0",
    "SELECT id, at, kind, detail FROM owner_interaction LIMIT 0",
];

/// Add schema version 18 in the migration or create transaction: the tables, the
/// triggers of the new child tables, the exceptions from the agent settings, and the
/// version marks. Then the columns of schema 18 are checked in the same transaction,
/// so a failure of any step leaves the file at its old version.
pub(super) fn add_schema_v18(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    add_schema_v18_with(tx, |_| Ok(()))
}

/// [`add_schema_v18`] with `before_marks`, a step that runs after the derivation and
/// before the check. Tests use it to fail late in the migration.
fn add_schema_v18_with(
    tx: &rusqlite::Transaction<'_>,
    before_marks: impl FnOnce(&rusqlite::Transaction<'_>) -> VaultResult<()>,
) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    tx.execute_batch(SCHEMA_V18_SQL).map_err(storage)?;
    tx.execute_batch(&merge::child_triggers_sql(&CHILD_TABLES_V18))
        .map_err(storage)?;
    derive_exceptions(tx, agents::now_unix())?;
    tx.execute_batch(SCHEMA_V18_MARKS_SQL).map_err(storage)?;
    before_marks(tx)?;
    verify_expected_columns_in(tx, "main", FOLDER_SCHEMA_VERSION)
}

/// One process grant of an active agent, as the derivation reads it.
struct LegacyGrant {
    agent_id: i64,
    item_id: i64,
    ask_mode: bool,
    rule: String,
    any_folder: bool,
    placeholder: bool,
    created_at: i64,
    see_all: bool,
}

/// Turn the agent settings of ADR 0012 into exceptions (see the module documentation).
/// `now` is the Unix time at which a rule expiry counts as past.
fn derive_exceptions(tx: &rusqlite::Transaction<'_>, now: u64) -> VaultResult<()> {
    let storage = |_: rusqlite::Error| err(VaultErrorKind::Storage);
    let marker = i64::try_from(ONLY_MARKER_ITEM).map_err(|_| err(VaultErrorKind::Storage))?;
    // "Only these items": the marker for each active agent that does not see all items.
    tx.execute(
        "INSERT INTO agent_exception (agent_id, item_id, kind, created_at)
         SELECT a.id, ?1, 'only', a.created_at FROM agent a
         WHERE a.see_all = 0 AND a.revoked_at IS NULL",
        [marker],
    )
    .map_err(storage)?;
    let grants: Vec<LegacyGrant> = {
        let mut stmt = tx
            .prepare(
                "SELECT g.agent_id, g.item_id, g.mode, g.rule, g.any_folder,
                     b.placeholder_hosts IS NOT NULL, g.created_at, a.see_all
                 FROM exec_grant g
                 JOIN agent a ON a.id = g.agent_id
                 JOIN item i ON i.id = g.item_id
                 LEFT JOIN env_binding b ON b.item_id = g.item_id
                 WHERE a.revoked_at IS NULL",
            )
            .map_err(storage)?;
        stmt.query_map([], |row| {
            Ok(LegacyGrant {
                agent_id: row.get(0)?,
                item_id: row.get(1)?,
                ask_mode: row.get::<_, String>(2)? != "allow",
                rule: row.get(3)?,
                any_folder: row.get::<_, i64>(4)? != 0,
                placeholder: row.get(5)?,
                created_at: row.get(6)?,
                see_all: row.get::<_, i64>(7)? != 0,
            })
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?
    };
    for grant in grants {
        // A rule that does not read fails the grant today: it counts as expired.
        let rule = serde_json::from_str::<agents::ExecRule>(&grant.rule).ok();
        let usable = rule
            .as_ref()
            .is_some_and(|rule| rule.expires_at.is_none_or(|at| now < at));
        let limited = rule.as_ref().is_none_or(|rule| {
            !rule.allowed_prefixes.is_empty()
                || !rule.forbidden_words.is_empty()
                || rule.max_runs_per_hour.is_some()
                || rule.expires_at.is_some()
                || !rule.instruction.trim().is_empty()
        });
        // ADR 0012: in any folder, a run with the real value waits for the owner.
        let real_value_anywhere = grant.any_folder && !grant.placeholder;
        let mut kinds = Vec::new();
        if !grant.see_all && usable {
            kinds.push("only");
        }
        if grant.ask_mode || limited || real_value_anywhere {
            kinds.push("always_ask");
        }
        for kind in kinds {
            tx.execute(
                "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                (grant.agent_id, grant.item_id, kind, grant.created_at),
            )
            .map_err(storage)?;
        }
    }
    // The items of connector grants are in "only these items" too, once per item.
    tx.execute(
        "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
         SELECT r.agent_id, r.item_id, 'only', min(r.created_at) FROM grant_rule r
         JOIN agent a ON a.id = r.agent_id
         JOIN item i ON i.id = r.item_id
         WHERE a.see_all = 0 AND a.revoked_at IS NULL
         GROUP BY r.agent_id, r.item_id",
        [],
    )
    .map_err(storage)?;
    Ok(())
}

/// Remove the schema 18 rows of a deleted item: its child rows and the local exceptions,
/// answers, origin, and corrections. The use log and the owner interactions stay as
/// history, like the activity.
pub(super) fn forget_item(tx: &rusqlite::Transaction<'_>, item: i64) -> VaultResult<()> {
    for table in CHILD_TABLES_V18.iter().chain(&[
        "agent_exception",
        "owner_answer",
        "item_origin",
        "correction",
    ]) {
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

    const PASS: &str = "synthetic-schema18-pass";

    /// A new vault, closed, and made schema 17 again: the tables of schema 18 are gone,
    /// one agent with `see_all = 0` has a grant in "Ask me each time".
    fn schema17_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("v17.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault.lock().unwrap();
        let conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        let mut sql = crate::vault::schema20::downgrade_sql();
        sql.push_str(crate::vault::schema19::DOWNGRADE_TO_18_SQL);
        for table in [
            "folder",
            "item_folder",
            "item_policy",
            "declaration_source",
            "shared_vault",
            "item_share",
            "vault_secret",
            "agent_exception",
            "owner_answer",
            "item_use",
            "item_origin",
            "credential_request",
            "correction",
            "owner_interaction",
        ] {
            sql.push_str(&format!("DROP TABLE {table};"));
        }
        sql.push_str(
            "ALTER TABLE agent DROP COLUMN note;
             INSERT INTO item (id, title, kind, notes, revision) VALUES (7, 'Synthetic', 'custom', '', 1);
             INSERT INTO agent (id, name, token, created_at, token_issued_at, see_all)
                 VALUES (3, 'Synthetic agent', x'00', 100, 100, 0);
             INSERT INTO exec_grant (agent_id, item_id, project_dir, mode, created_at)
                 VALUES (3, 7, '/tmp/synthetic', 'ask', 200);
             UPDATE vault_meta SET schema_version = 17 WHERE id = 1;
             PRAGMA user_version = 17;",
        );
        conn.execute_batch(&sql).unwrap();
        close_conn(conn).unwrap();
        path
    }

    fn exceptions(conn: &Connection) -> Vec<(i64, i64, String, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, item_id, kind, created_at FROM agent_exception
                 ORDER BY agent_id, item_id, kind",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    #[test]
    fn a_failure_after_the_derivation_rolls_back_every_step() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema17_file(&dir);
        let mut conn = Connection::open_with_flags(&path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        let tx = conn.transaction().unwrap();
        let failed = add_schema_v18_with(&tx, |tx| {
            // The derivation ran in this transaction.
            assert_eq!(
                exceptions(tx),
                [
                    (3, 0, "only".to_owned(), 100),
                    (3, 7, "always_ask".to_owned(), 200),
                    (3, 7, "only".to_owned(), 200),
                ]
            );
            Err(err(VaultErrorKind::Storage))
        });
        assert_eq!(failed.unwrap_err().kind(), VaultErrorKind::Storage);
        drop(tx);
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 17);
        assert!(conn.prepare("SELECT 1 FROM agent_exception").is_err());
        assert!(conn.prepare("SELECT 1 FROM folder").is_err());
        assert!(conn.prepare("SELECT note FROM agent").is_err());
        close_conn(conn).unwrap();

        // The next unlock migrates the same file.
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(exceptions(vault.conn_ref().unwrap()).len(), 3);
    }

    #[test]
    fn every_new_table_is_classified() {
        for table in CHILD_TABLES_V18 {
            assert!(merge::CHILD_TABLES.contains(&table));
            assert!(merge::SYNCED_TABLES.contains(&table));
        }
        for table in ["folder", "shared_vault", "vault_secret"] {
            assert!(merge::SYNCED_TABLES.contains(&table));
        }
        for table in [
            "agent_exception",
            "owner_answer",
            "item_use",
            "item_origin",
            "credential_request",
            "correction",
            "owner_interaction",
        ] {
            assert!(merge::LOCAL_TABLES.contains(&table));
        }
    }
}
