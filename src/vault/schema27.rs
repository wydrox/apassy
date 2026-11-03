//! Schema version 27: the figures of the Bouncer section and self-connecting remote
//! agents (docs/design/implementation-plan-bouncer-section.md, section 2).
//!
//! - `decision_log.request`: what the decision was for: `run` (a run of a command, also
//!   a cloud run), `browser_fill`, or `connector`. Every row before 27 is a `run`: the
//!   broker wrote no other kind to the vault log. The Overview counts one row with
//!   `request = 'run'` as one run (`stats.rs`).
//! - `decision_log.wait_ms`: the milliseconds from the question to the owner's answer,
//!   for a row that the owner answered (`asked = 1`, `decided_by = 'owner'`). `NULL` for
//!   every other row and for every row before 27. The median answer of the Overview
//!   reads it.
//! - `cloud_agent.client_id`: the OAuth client of a remote agent that connected by
//!   itself (the MCP authorization flow); `NULL` for an agent made with a token.
//! - `cloud_agent.connected_with`: `oauth` or `token` (the CLI fallback, and every cloud
//!   agent before 27).
//! - `cloud_run`: one row for each cloud run that the node of this Mac asked about: the
//!   run id of the node, the decision log row of the owner's answer, the vault agent,
//!   when it was asked and ended, and the requests of its session that the proxy of the
//!   node forwarded, refused, or failed. The Logs page joins it to the decision log.
//! - `item_use_decision` and `cloud_run_decision`: indexes for the join of the decision
//!   log with the uses and the cloud runs of each decision.
//!
//! All of it is local ([`super::merge::LOCAL_TABLES`]): `decision_log` and `cloud_agent`
//! are local already, and `cloud_run` belongs to the node of one Mac.
//!
//! Schema 27 follows schema 26 (the cloud agents): a vault of schema 25 or earlier runs
//! 26 and then 27 in one migration. A merge takes a synced copy of schema 16 to 26 as
//! before: a pushed copy has no row of the local tables. A device of schema 26 or
//! earlier refuses a copy of schema 27 (`UnsupportedSchema`).

use rusqlite::Transaction;

use super::types::{VaultErrorKind, VaultResult, err};
use super::verify_expected_columns_in;

/// The schema version of the Bouncer figures.
pub(super) const STATS_SCHEMA_VERSION: i64 = 27;

/// The columns, the table, and the indexes of schema 27.
const SCHEMA_V27_SQL: &str = "
ALTER TABLE decision_log ADD COLUMN request TEXT NOT NULL DEFAULT 'run'
    CHECK (request IN ('run', 'browser_fill', 'connector'));
ALTER TABLE decision_log ADD COLUMN wait_ms INTEGER CHECK (wait_ms IS NULL OR wait_ms >= 0);
ALTER TABLE cloud_agent ADD COLUMN client_id TEXT
    CHECK (client_id IS NULL OR length(client_id) BETWEEN 1 AND 255);
ALTER TABLE cloud_agent ADD COLUMN connected_with TEXT NOT NULL DEFAULT 'token'
    CHECK (connected_with IN ('oauth', 'token'));
CREATE TABLE cloud_run (
    relay_run_id INTEGER PRIMARY KEY CHECK (relay_run_id >= 1),
    decision_log_id INTEGER,
    agent_id INTEGER NOT NULL,
    at INTEGER NOT NULL,
    ended_at INTEGER,
    forwarded INTEGER NOT NULL DEFAULT 0 CHECK (forwarded >= 0),
    refused INTEGER NOT NULL DEFAULT 0 CHECK (refused >= 0),
    failed INTEGER NOT NULL DEFAULT 0 CHECK (failed >= 0)
);
CREATE INDEX cloud_run_decision ON cloud_run(decision_log_id);
CREATE INDEX item_use_decision ON item_use(decision_log_id);
UPDATE vault_meta SET schema_version = 27 WHERE id = 1;
PRAGMA user_version = 27;
";

/// What `verify_expected_columns_in` reads for schema 27 and later.
pub(super) const COLUMNS: [&str; 3] = [
    "SELECT request, wait_ms FROM decision_log LIMIT 0",
    "SELECT client_id, connected_with FROM cloud_agent LIMIT 0",
    "SELECT relay_run_id, decision_log_id, agent_id, at, ended_at, forwarded, refused, failed FROM cloud_run LIMIT 0",
];

/// The way back to schema 26, for test fixtures and for the rollback notes. A build of
/// schema 26 has no use for any of it: the decision rows stay with their schema 7
/// columns, and a cloud agent of either kind is a cloud agent of schema 26 (its node
/// token keeps working until it expires or the owner disconnects it).
#[cfg(test)]
pub(super) const DOWNGRADE_TO_26_SQL: &str = "
DROP INDEX item_use_decision;
DROP INDEX cloud_run_decision;
DROP TABLE cloud_run;
ALTER TABLE cloud_agent DROP COLUMN connected_with;
ALTER TABLE cloud_agent DROP COLUMN client_id;
ALTER TABLE decision_log DROP COLUMN wait_ms;
ALTER TABLE decision_log DROP COLUMN request;
UPDATE vault_meta SET schema_version = 26 WHERE id = 1;
PRAGMA user_version = 26;
";

/// The way back from the current schema to schema 27: `schema34::downgrade_sql` (the
/// account key source of relay memberships), `schema32::downgrade_sql` (short-lived
/// credentials), `schema29::downgrade_sql` (the host of the bouncer brain), and then
/// `schema28::downgrade_sql` (the pinned trust of a membership).
#[cfg(test)]
pub(super) fn downgrade_to_27_sql() -> String {
    format!(
        "{}{}{}{}",
        super::schema34::downgrade_sql(),
        super::schema32::downgrade_sql(),
        super::schema29::downgrade_sql(),
        super::schema28::downgrade_sql()
    )
}

/// The way back from the current schema to schema 25, which the fixtures of schema 25
/// and earlier start with: [`downgrade_to_27_sql`], [`DOWNGRADE_TO_26_SQL`], and then
/// `schema26::DOWNGRADE_TO_25_SQL`.
#[cfg(test)]
pub(super) fn downgrade_to_25_sql() -> String {
    format!(
        "{}{DOWNGRADE_TO_26_SQL}{}",
        downgrade_to_27_sql(),
        super::schema26::DOWNGRADE_TO_25_SQL
    )
}

/// Add schema version 27 in the migration or create transaction. Then the columns of
/// schema 27 are checked in the same transaction.
pub(super) fn add_schema_v27(tx: &Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(SCHEMA_V27_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    verify_expected_columns_in(tx, "main", STATS_SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{
        DecidedBy, DecisionEntry, Field, ItemDraft, LoggedDecision, OPEN_EXISTING, RequestSource,
        SecretValue, Vault, apply_key, close_conn,
    };

    const PASS: &str = "synthetic-schema27-pass";

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

    fn decision(agent_id: u64, at: u64) -> DecisionEntry {
        DecisionEntry {
            at,
            agent_id,
            agent_name: "Synthetic local".to_owned(),
            project_dir: String::new(),
            cwd_rel: String::new(),
            items: Vec::new(),
            user_request: String::new(),
            user_request_source: RequestSource::None,
            command: vec!["true".to_owned()],
            purpose: "synthetic".to_owned(),
            env_names: Vec::new(),
            declarations: Vec::new(),
            rule_flags: Vec::new(),
            known_safe: false,
            model_facts: Vec::new(),
            pattern: String::new(),
            grant_asks: false,
            asked: true,
            decision: LoggedDecision::Allow,
            decided_by: DecidedBy::Owner,
            remembered: false,
            policy: String::new(),
            note: String::new(),
            instruction: String::new(),
        }
    }

    /// A vault of schema 26 with one local agent, one cloud agent, one item, and one
    /// decision.
    fn schema26_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("v26.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(api_key("Synthetic")).unwrap().id;
        let (local, _) = vault.register_agent("Synthetic local").unwrap();
        vault
            .add_cloud_agent("Synthetic cloud", &[item], 7, 4_000_000_000)
            .unwrap();
        vault.record_decision(&decision(local.id, 1_000)).unwrap();
        vault.lock().unwrap();
        drop(vault);
        let conn = raw(&path);
        // Schemas 32, 29, and 28 (`schema32.rs`, `schema29.rs`, `schema28.rs`) first.
        conn.execute_batch(&downgrade_to_27_sql()).unwrap();
        conn.execute_batch(DOWNGRADE_TO_26_SQL).unwrap();
        assert_eq!(version(&conn), 26);
        assert!(!has_table(&conn, "cloud_run"));
        assert!(conn.prepare("SELECT wait_ms FROM decision_log").is_err());
        assert!(conn.prepare("SELECT client_id FROM cloud_agent").is_err());
        close_conn(conn).unwrap();
        path
    }

    #[test]
    fn a_schema26_vault_moves_to_27_with_runs_and_token_agents() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema26_file(&dir);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert_eq!(meta_version(conn), crate::vault::SCHEMA_VERSION);
        // The old decision is a run that waited for nobody's recorded answer time.
        let row: (String, Option<i64>) = conn
            .query_row("SELECT request, wait_ms FROM decision_log", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(row, ("run".to_owned(), None));
        // The old cloud agent was made with a token.
        let agent: (Option<String>, String) = conn
            .query_row(
                "SELECT client_id, connected_with FROM cloud_agent",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(agent, (None, "token".to_owned()));
        assert!(has_table(conn, "cloud_run"));
        // Unknown kinds and negative times are refused.
        for bad in [
            "UPDATE decision_log SET request = 'fill'",
            "UPDATE decision_log SET wait_ms = -1",
            "UPDATE cloud_agent SET connected_with = 'password'",
            "INSERT INTO cloud_run (relay_run_id, agent_id, at) VALUES (0, 1, 1)",
        ] {
            assert!(conn.execute(bad, []).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_failed_migration_keeps_schema_26() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema26_file(&dir);
        let mut conn = raw(&path);
        let tx = conn.transaction().unwrap();
        add_schema_v27(&tx).unwrap();
        // Roll back, as a failure of a later step does.
        drop(tx);
        assert_eq!(version(&conn), 26);
        assert_eq!(meta_version(&conn), 26);
        assert!(!has_table(&conn, "cloud_run"));
        assert!(conn.prepare("SELECT request FROM decision_log").is_err());
        close_conn(conn).unwrap();
    }

    #[test]
    fn the_way_back_to_26_keeps_decisions_and_agents_and_the_next_unlock_moves_to_27_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("v27.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(api_key("Cloud")).unwrap().id;
        let (local, token) = vault.register_agent("Synthetic local").unwrap();
        let cloud = vault
            .add_cloud_agent("Synthetic cloud", &[item], 7, 4_000_000_000)
            .unwrap();
        let id = vault
            .record_decision_with(
                &decision(local.id, 2_000),
                &crate::vault::DecisionMeta {
                    request: crate::vault::RequestKind::BrowserFill,
                    wait_ms: Some(4_200),
                },
            )
            .unwrap();
        vault
            .record_cloud_run(&crate::vault::NewCloudRun {
                relay_run_id: 41,
                decision_log_id: Some(id),
                agent_id: cloud,
                at: 2_000,
            })
            .unwrap();
        vault.lock().unwrap();
        drop(vault);

        let conn = raw(&path);
        // Schemas 32, 29, and 28 (`schema32.rs`, `schema29.rs`, `schema28.rs`) first.
        conn.execute_batch(&downgrade_to_27_sql()).unwrap();
        conn.execute_batch(DOWNGRADE_TO_26_SQL).unwrap();
        assert_eq!(version(&conn), 26);
        assert_eq!(meta_version(&conn), 26);
        let decisions: i64 = conn
            .query_row("SELECT count(*) FROM decision_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(decisions, 1);
        let cloud_agents: i64 = conn
            .query_row("SELECT count(*) FROM cloud_agent", [], |row| row.get(0))
            .unwrap();
        assert_eq!(cloud_agents, 1);
        close_conn(conn).unwrap();

        // This build moves the file to 27 again: the decision is a run with no answer
        // time, the cloud agent a token agent, and the cloud runs start again.
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        assert_eq!(
            version(vault.conn_ref().unwrap()),
            crate::vault::SCHEMA_VERSION
        );
        assert_eq!(
            vault.authenticate_agent(token.expose()).unwrap().id,
            local.id
        );
        let row: (String, Option<i64>) = vault
            .conn_ref()
            .unwrap()
            .query_row("SELECT request, wait_ms FROM decision_log", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(row, ("run".to_owned(), None));
        assert_eq!(vault.cloud_agents().unwrap().len(), 1);
        assert_eq!(
            vault.cloud_agent_link(cloud).unwrap(),
            Some((None, crate::vault::ConnectedWith::Token))
        );
        assert!(vault.cloud_run(41).unwrap().is_none());
    }

    #[test]
    fn a_schema25_vault_runs_26_and_27_and_copies_of_16_to_27_merge() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = schema26_file(&dir);
        let conn = raw(&path);
        conn.execute_batch(crate::vault::schema26::DOWNGRADE_TO_25_SQL)
            .unwrap();
        assert_eq!(version(&conn), 25);
        close_conn(conn).unwrap();
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert_eq!(meta_version(conn), crate::vault::SCHEMA_VERSION);
        assert!(has_table(conn, "cloud_node"));
        assert!(has_table(conn, "cloud_run"));
        for version in [16, 25, 26, STATS_SCHEMA_VERSION] {
            assert!(
                crate::vault::merge::is_mergeable_schema(version),
                "{version}"
            );
        }
        // An app of schema 26 refuses a copy of 27, and this one a copy of a later schema.
        assert!(!crate::vault::merge::is_mergeable_schema(
            crate::vault::SCHEMA_VERSION + 1
        ));
        // Schemas 28 and 29 (`schema28.rs`, `schema29.rs`) follow 27.
        const { assert!(STATS_SCHEMA_VERSION < crate::vault::SCHEMA_VERSION) };
    }

    #[test]
    fn a_new_vault_has_the_table_of_schema_27_and_it_is_local() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("new.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let conn = vault.conn_ref().unwrap();
        assert_eq!(version(conn), crate::vault::SCHEMA_VERSION);
        assert!(has_table(conn, "cloud_run"));
        assert!(crate::vault::merge::LOCAL_TABLES.contains(&"cloud_run"));
    }
}
