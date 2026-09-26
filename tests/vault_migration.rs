#![cfg(feature = "vault")]

//! Goal item V6: unlock migrates a vault from each earlier schema version (1 to 6) to the
//! current version, with data at each version. Synthetic values only.
//!
//! The schema SQL below is a frozen copy of the statements that each earlier version ran
//! at create: version 1 in commit a2f860a, 2 in 4ffdb5e, 3 in 22d1784, 4 in 2eb8366,
//! 5 in 9ce2e01, and 6 in 4193991. Do not change these copies when the current schema
//! changes.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use apassy::contracts::CredentialKind;
use apassy::vault::{
    DecidedBy, DecisionEntry, Environment, ExecMode, ExecRule, LoggedDecision, PatternKey,
    PatternState, RequestSource, Reversibility, RiskLevel, Scope, Vault, VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "synthetic-migration-passphrase";
const CURRENT_VERSION: i64 = 7;

const V1_SQL: &str = "
CREATE TABLE vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL
);
CREATE TABLE item (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    kind TEXT NOT NULL,
    notes TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1)
);
CREATE TABLE item_tag (
    item_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    tag TEXT NOT NULL
);
CREATE TABLE item_field (
    item_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    secret INTEGER NOT NULL CHECK (secret IN (0, 1))
);
CREATE INDEX item_tag_item_id ON item_tag(item_id);
CREATE INDEX item_field_item_id ON item_field(item_id);
INSERT INTO vault_meta (id, schema_version) VALUES (1, 1);
PRAGMA user_version = 1;
";

const V2_SQL: &str = "
CREATE TABLE agent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE destination (
    item_id INTEGER PRIMARY KEY,
    profile TEXT NOT NULL,
    base_url TEXT NOT NULL
);
CREATE TABLE grant_rule (
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    operation TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, item_id, operation)
);
CREATE TABLE activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    item_id INTEGER,
    operation TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'error')),
    reason TEXT NOT NULL
);
CREATE INDEX grant_rule_item_id ON grant_rule(item_id);
UPDATE vault_meta SET schema_version = 2 WHERE id = 1;
PRAGMA user_version = 2;
";

const V3_SQL: &str = "
CREATE TABLE env_binding (
    item_id INTEGER PRIMARY KEY,
    env_name TEXT NOT NULL,
    field TEXT NOT NULL
);
CREATE TABLE exec_grant (
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    project_dir TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('ask', 'allow')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, item_id)
);
CREATE INDEX exec_grant_item_id ON exec_grant(item_id);
UPDATE vault_meta SET schema_version = 3 WHERE id = 1;
PRAGMA user_version = 3;
";

const V4_SQL: &str = "
ALTER TABLE exec_grant ADD COLUMN rule TEXT NOT NULL DEFAULT '{}';
CREATE TABLE run_log (
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX run_log_agent_item ON run_log(agent_id, item_id, at);
UPDATE vault_meta SET schema_version = 4 WHERE id = 1;
PRAGMA user_version = 4;
";

const V5_SQL: &str = "
CREATE TABLE declaration (
    item_id INTEGER PRIMARY KEY,
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    risk TEXT NOT NULL,
    scope TEXT NOT NULL,
    reversibility TEXT NOT NULL
);
UPDATE vault_meta SET schema_version = 5 WHERE id = 1;
PRAGMA user_version = 5;
";

const V6_SQL: &str = "
ALTER TABLE agent ADD COLUMN token_issued_at INTEGER NOT NULL DEFAULT 0;
UPDATE agent SET token_issued_at = created_at;
ALTER TABLE vault_meta ADD COLUMN token_lifetime_days INTEGER NOT NULL DEFAULT 30;
CREATE TABLE restore_review (
    item_id INTEGER PRIMARY KEY,
    restored_at INTEGER NOT NULL
);
UPDATE vault_meta SET schema_version = 6 WHERE id = 1;
PRAGMA user_version = 6;
";

/// Five items, one of each kind: (title, kind, notes, tags, fields as (name, value, secret)).
type ItemRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static [(&'static str, &'static str, bool)],
);

const ITEMS: [ItemRow; 5] = [
    (
        "MIG api key",
        "api_key",
        "MIG notes api",
        &["mig-tag-api", "project-mig"],
        &[
            ("token", "MIG-SECRET-api-token", true),
            ("service", "mig-service", false),
        ],
    ),
    (
        "MIG login",
        "login",
        "",
        &["mig-tag-login"],
        &[
            ("username", "mig-user", false),
            ("password", "MIG-SECRET-login-pass", true),
        ],
    ),
    (
        "MIG ssh key",
        "ssh_key",
        "",
        &[],
        &[
            ("private_key", "MIG-SECRET-ssh-private", true),
            ("passphrase", "MIG-SECRET-ssh-phrase", true),
        ],
    ),
    (
        "MIG database",
        "database",
        "",
        &[],
        &[
            ("host", "db.mig.invalid", false),
            ("database", "mig_db", false),
            ("username", "mig_reader", false),
            ("password", "MIG-SECRET-db-pass", true),
        ],
    ),
    (
        "MIG custom",
        "custom",
        "",
        &["mig-tag-custom"],
        &[("blob", "MIG-SECRET-custom", true)],
    ),
];

const ACTIVE_TOKEN: [u8; 32] = [0x11; 32];
const OLD_TOKEN: [u8; 32] = [0x22; 32];
const REVOKED_TOKEN: [u8; 32] = [0x33; 32];
const RULE_JSON: &str = r#"{"allowed_prefixes":["npm test"],"forbidden_words":["prod"],"expires_at":null,"max_runs_per_hour":5,"instruction":"Only tests."}"#;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time")
}

fn token_text(bytes: &[u8; 32]) -> String {
    let mut text = String::from("apassy_agt_");
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Write a vault file as the app of `version` made it, with data of that version.
fn build_legacy(path: &Path, version: i64) {
    let mut conn = rusqlite::Connection::open(path).expect("create legacy file");
    conn.pragma_update(None, "key", PASS).expect("key");
    let journal: String = conn
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .expect("journal mode");
    assert_eq!(journal, "delete");
    let tx = conn.transaction().expect("transaction");
    let steps = [V1_SQL, V2_SQL, V3_SQL, V4_SQL, V5_SQL, V6_SQL];
    for sql in &steps[..usize::try_from(version).expect("version")] {
        tx.execute_batch(sql).expect("legacy schema");
    }
    for (index, (title, kind, notes, tags, fields)) in ITEMS.iter().enumerate() {
        let id = i64::try_from(index).expect("index") + 1;
        tx.execute(
            "INSERT INTO item (id, title, kind, notes, revision) VALUES (?1, ?2, ?3, ?4, ?5)",
            (id, title, kind, notes, id),
        )
        .expect("item");
        for (position, tag) in tags.iter().enumerate() {
            tx.execute(
                "INSERT INTO item_tag (item_id, position, tag) VALUES (?1, ?2, ?3)",
                (id, i64::try_from(position).expect("position"), tag),
            )
            .expect("tag");
        }
        for (position, (name, value, secret)) in fields.iter().enumerate() {
            tx.execute(
                "INSERT INTO item_field (item_id, position, name, value, secret)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    id,
                    i64::try_from(position).expect("position"),
                    name,
                    value,
                    i64::from(*secret),
                ),
            )
            .expect("field");
        }
    }
    let now = now();
    if version >= 2 {
        let agents: [(&str, &[u8; 32], i64, Option<i64>); 3] = [
            ("MIG active agent", &ACTIVE_TOKEN, now - 86_400, None),
            ("MIG old agent", &OLD_TOKEN, now - 40 * 86_400, None),
            (
                "MIG revoked agent",
                &REVOKED_TOKEN,
                now - 2 * 86_400,
                Some(now - 86_400),
            ),
        ];
        for (name, token, created_at, revoked_at) in agents {
            tx.execute(
                "INSERT INTO agent (name, token, created_at, revoked_at) VALUES (?1, ?2, ?3, ?4)",
                (name, token.as_slice(), created_at, revoked_at),
            )
            .expect("agent");
        }
        tx.execute(
            "INSERT INTO destination (item_id, profile, base_url)
             VALUES (1, 'reporting-api-v0', 'http://127.0.0.1:8787')",
            [],
        )
        .expect("destination");
        tx.execute(
            "INSERT INTO grant_rule (agent_id, item_id, operation, created_at)
             VALUES (1, 1, 'get_sales_summary', ?1)",
            [now],
        )
        .expect("grant");
        tx.execute(
            "INSERT INTO activity (at, agent_id, agent_name, item_id, operation, decision, reason)
             VALUES (?1, 1, 'MIG active agent', 1, 'get_sales_summary', 'allow', 'MIG reason')",
            [now - 60],
        )
        .expect("activity");
    }
    if version >= 3 {
        tx.execute(
            "INSERT INTO env_binding (item_id, env_name, field) VALUES (1, 'MIG_API_KEY', 'token')",
            [],
        )
        .expect("binding");
        tx.execute(
            "INSERT INTO env_binding (item_id, env_name, field) VALUES (2, 'MIG_LOGIN', 'password')",
            [],
        )
        .expect("binding");
        tx.execute(
            "INSERT INTO exec_grant (agent_id, item_id, project_dir, mode, created_at)
             VALUES (1, 1, '/tmp/mig-project', 'allow', ?1)",
            [now],
        )
        .expect("exec grant");
        tx.execute(
            "INSERT INTO exec_grant (agent_id, item_id, project_dir, mode, created_at)
             VALUES (1, 2, '/tmp/mig-project', 'ask', ?1)",
            [now],
        )
        .expect("exec grant");
    }
    if version >= 4 {
        tx.execute(
            "UPDATE exec_grant SET rule = ?1 WHERE item_id = 1",
            [RULE_JSON],
        )
        .expect("rule");
        tx.execute(
            "INSERT INTO run_log (agent_id, item_id, at) VALUES (1, 1, ?1)",
            [now - 60],
        )
        .expect("run log");
    }
    if version >= 5 {
        tx.execute(
            "INSERT INTO declaration (item_id, project, environment, risk, scope, reversibility)
             VALUES (1, 'mig', 'staging', 'medium', 'read-write', 'reversible')",
            [],
        )
        .expect("declaration");
    }
    if version >= 6 {
        // Version 6 registration sets the issue time. The owner rotated the old token an
        // hour ago, changed the token lifetime, and did not review item 2 after a restore.
        tx.execute("UPDATE agent SET token_issued_at = created_at", [])
            .expect("issue time");
        tx.execute(
            "UPDATE agent SET token_issued_at = ?1 WHERE name = 'MIG old agent'",
            [now - 3600],
        )
        .expect("rotation");
        tx.execute("UPDATE vault_meta SET token_lifetime_days = 45", [])
            .expect("lifetime");
        tx.execute(
            "INSERT INTO restore_review (item_id, restored_at) VALUES (2, ?1)",
            [now - 120],
        )
        .expect("review");
    }
    tx.commit().expect("commit");
    conn.close().map_err(|(_, err)| err).expect("close");
}

fn raw_versions(path: &Path) -> (i64, i64) {
    let conn = rusqlite::Connection::open(path).expect("open");
    conn.pragma_update(None, "key", PASS).expect("key");
    let user: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user_version");
    let meta: i64 = conn
        .query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("vault_meta");
    conn.close().map_err(|(_, err)| err).expect("close");
    (user, meta)
}

fn assert_items(vault: &Vault) {
    let found = vault.search("").expect("search");
    assert_eq!(found.len(), ITEMS.len());
    let kinds = [
        CredentialKind::ApiKey,
        CredentialKind::Login,
        CredentialKind::SshKey,
        CredentialKind::Database,
        CredentialKind::Custom,
    ];
    for ((summary, (title, _, notes, tags, fields)), kind) in
        found.iter().zip(ITEMS.iter()).zip(kinds)
    {
        assert_eq!(summary.title, *title);
        assert_eq!(summary.kind, kind);
        assert_eq!(summary.revision, summary.id, "revisions stay");
        let details = vault.details(summary.id).expect("details");
        assert_eq!(details.notes, *notes);
        assert_eq!(
            details.tags,
            tags.iter().map(|tag| (*tag).to_owned()).collect::<Vec<_>>()
        );
        assert_eq!(details.fields.len(), fields.len());
        for (name, value, secret) in fields.iter() {
            let field = details
                .fields
                .iter()
                .find(|field| field.name == *name)
                .expect("field");
            assert_eq!(field.secret, *secret);
            assert_eq!(
                vault.reveal(summary.id, name).expect("value").expose(),
                *value
            );
        }
    }
    assert_eq!(vault.search("mig-tag-login").expect("tag search").len(), 1);
    assert!(
        vault
            .search("MIG-SECRET-api-token")
            .expect("secret search")
            .is_empty()
    );
}

fn assert_version_data(vault: &mut Vault, version: i64) {
    assert_items(vault);
    let lifetime: u64 = if version >= 6 { 45 } else { 30 };
    assert_eq!(
        u64::from(vault.token_lifetime_days().expect("lifetime")),
        lifetime
    );
    let review = vault.items_needing_review().expect("review");
    if version >= 6 {
        assert_eq!(review, vec![2], "a review that waits stays");
    } else {
        assert!(review.is_empty(), "a migration is not a restore");
    }
    // The learning tables of version 7 start empty. The default level is active.
    assert!(vault.decision_log().expect("log").is_empty());
    assert!(vault.patterns().expect("patterns").is_empty());
    assert!(vault.calibration().expect("calibration").is_none());
    if version < 2 {
        assert!(vault.list_agents().expect("agents").is_empty());
        return;
    }
    let agents = vault.list_agents().expect("agents");
    assert_eq!(agents.len(), 3);
    assert_eq!(agents[0].name, "MIG active agent");
    assert!(!agents[0].revoked);
    assert!(agents[2].revoked);
    for agent in &agents {
        let rotated = version >= 6 && agent.name == "MIG old agent";
        if !rotated {
            assert_eq!(agent.token_issued_at, agent.created_at);
        }
        assert_eq!(
            agent.token_expires_at,
            agent.token_issued_at + lifetime * 86_400
        );
    }
    let active = vault
        .authenticate_agent(&token_text(&ACTIVE_TOKEN))
        .expect("the active token works after the migration");
    assert_eq!(active.id, agents[0].id);
    if version >= 6 {
        // The owner rotated the old token under version 6. It works.
        vault
            .authenticate_agent(&token_text(&OLD_TOKEN))
            .expect("the rotated token works after the migration");
    } else {
        // The registration time is the issue time. A token older than 30 days expires.
        assert_eq!(
            vault
                .authenticate_agent(&token_text(&OLD_TOKEN))
                .unwrap_err()
                .kind(),
            VaultErrorKind::Expired
        );
    }
    assert_eq!(
        vault
            .authenticate_agent(&token_text(&REVOKED_TOKEN))
            .unwrap_err()
            .kind(),
        VaultErrorKind::NotFound
    );
    let destination = vault.destination(1).expect("destination").expect("some");
    assert_eq!(destination.base_url, "http://127.0.0.1:8787");
    assert!(vault.has_grant(1, 1, "get_sales_summary").expect("grant"));
    let activity = vault.recent_activity(10).expect("activity");
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].reason, "MIG reason");
    if version < 3 {
        assert!(vault.env_binding(1).expect("binding").is_none());
        assert!(vault.exec_grants_for_agent(1).expect("grants").is_empty());
        return;
    }
    assert_eq!(
        vault
            .env_binding(1)
            .expect("binding")
            .expect("some")
            .env_name,
        "MIG_API_KEY"
    );
    let grants = vault.exec_grants_for_agent(1).expect("grants");
    assert_eq!(grants.len(), 2);
    // Version 3 stored "allow". ADR 0007 puts those grants under the bouncer.
    assert_eq!(grants[0].mode, ExecMode::Bouncer);
    assert_eq!(grants[1].mode, ExecMode::Ask);
    assert_eq!(grants[1].rule, ExecRule::default());
    if version < 4 {
        assert_eq!(grants[0].rule, ExecRule::default());
        assert_eq!(vault.runs_in_last_hour(1, 1).expect("runs"), 0);
    } else {
        assert_eq!(grants[0].rule.allowed_prefixes, vec!["npm test".to_owned()]);
        assert_eq!(grants[0].rule.forbidden_words, vec!["prod".to_owned()]);
        assert_eq!(grants[0].rule.max_runs_per_hour, Some(5));
        assert_eq!(grants[0].rule.instruction, "Only tests.");
        assert_eq!(vault.runs_in_last_hour(1, 1).expect("runs"), 1);
    }
    let declaration = vault.declaration(1).expect("declaration");
    if version < 5 {
        assert!(declaration.is_none());
    } else {
        let declaration = declaration.expect("some");
        assert_eq!(declaration.project, "mig");
        assert_eq!(declaration.environment, Environment::Staging);
        assert_eq!(declaration.risk, RiskLevel::Medium);
        assert_eq!(declaration.scope, Scope::ReadWrite);
        assert_eq!(declaration.reversibility, Reversibility::Reversible);
    }
}

#[test]
fn unlock_migrates_each_earlier_schema_version_to_the_current_one() {
    for version in 1..CURRENT_VERSION {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(format!("v{version}.db"));
        build_legacy(&path, version);
        assert_eq!(raw_versions(&path), (version, version));

        let mut vault = Vault::open(&path).expect("open");
        assert!(vault.is_locked());
        vault.unlock(PASS).expect("unlock migrates");
        assert_version_data(&mut vault, version);

        // The current features work on the migrated file.
        vault.set_token_lifetime_days(60).expect("lifetime");
        let (agent, token) = vault.register_agent("MIG new agent").expect("register");
        let rotated = vault.rotate_agent_token(agent.id).expect("rotate");
        assert!(vault.authenticate_agent(token.expose()).is_err());
        assert_eq!(
            vault
                .authenticate_agent(rotated.expose())
                .expect("rotated")
                .id,
            agent.id
        );
        // The decision log and remembered patterns of version 7 work on the migrated file.
        vault
            .record_decision(&migrated_decision(agent.id))
            .expect("decision");
        let key = migrated_pattern(agent.id);
        vault
            .remember_approval(&key, "npm test", u64::try_from(now()).expect("now"))
            .expect("pattern");
        drop(vault);
        assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));

        // A second unlock finds the current version and changes nothing.
        let mut again = Vault::open(&path).expect("open");
        again.unlock(PASS).expect("unlock");
        assert_items(&again);
        assert_eq!(again.token_lifetime_days().expect("lifetime"), 60);
        let log = again.decision_log().expect("log");
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].entry.user_request, "Use [apassy:secret].",
            "the secret value of item 1 is masked"
        );
        let pattern = again.pattern(&key).expect("read").expect("pattern");
        assert_eq!(
            pattern.state(u64::try_from(now()).expect("now")),
            PatternState::Learning { approvals: 1 }
        );
    }
}

fn migrated_decision(agent_id: u64) -> DecisionEntry {
    DecisionEntry {
        at: u64::try_from(now()).expect("now"),
        agent_id,
        agent_name: "MIG new agent".to_owned(),
        project_dir: "/tmp/mig-project".to_owned(),
        cwd_rel: ".".to_owned(),
        items: vec![1],
        user_request: "Use MIG-SECRET-api-token.".to_owned(),
        user_request_source: RequestSource::Agent,
        command: vec!["npm".to_owned(), "test".to_owned()],
        purpose: "Test.".to_owned(),
        env_names: vec!["MIG_API_KEY".to_owned()],
        declarations: vec![None],
        rule_flags: Vec::new(),
        known_safe: true,
        model_facts: Vec::new(),
        pattern: "npm test".to_owned(),
        grant_asks: false,
        asked: true,
        decision: LoggedDecision::Allow,
        decided_by: DecidedBy::Owner,
        remembered: true,
        policy: "apassy-bouncer-v4".to_owned(),
        note: String::new(),
    }
}

fn migrated_pattern(agent_id: u64) -> PatternKey {
    PatternKey {
        agent_id,
        project_dir: "/tmp/mig-project".to_owned(),
        items: vec![1],
        policy: "1=none|".to_owned(),
        cwd_rel: ".".to_owned(),
        template: "[{\"Lit\":\"npm\"},{\"Lit\":\"test\"}]".to_owned(),
    }
}

/// The step from version 6 to 7 also runs in one transaction.
#[test]
fn a_failed_migration_from_version_6_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked6.db");
    build_legacy(&path, 6);
    {
        // A table with the name of a version 7 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE calibration (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (6, 6), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let log_table = conn.prepare("SELECT id FROM decision_log LIMIT 0");
        assert!(log_table.is_err(), "no table of version 7");
        drop(log_table);
        conn.execute_batch("DROP TABLE calibration;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 6);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

/// The migration runs in one transaction. A failure leaves the file at its old version.
#[test]
fn a_failed_migration_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked.db");
    build_legacy(&path, 5);
    {
        // A table with the name of a version 6 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE restore_review (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    assert!(vault.is_locked());
    drop(vault);
    assert_eq!(raw_versions(&path), (5, 5), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let token_column = conn.prepare("SELECT token_issued_at FROM agent LIMIT 0");
        assert!(token_column.is_err(), "no column of version 6");
        drop(token_column);
        conn.execute_batch("DROP TABLE restore_review;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 5);
}

/// A restore of an old backup migrates it, revokes its agents, and marks the items with
/// agent settings for the owner review (goal items V4 and V6).
#[test]
fn restore_migrates_an_old_backup() {
    let dir = TempDir::new().expect("temp dir");
    let backup = dir.path().join("v3.backup");
    build_legacy(&backup, 3);
    let mut restored =
        Vault::restore(&backup, &dir.path().join("restored.db"), PASS).expect("restore");
    assert_eq!(raw_versions(&backup), (3, 3), "the backup does not change");
    restored.unlock(PASS).expect("unlock");
    assert_items(&restored);
    assert!(
        restored
            .list_agents()
            .expect("agents")
            .iter()
            .all(|agent| agent.revoked)
    );
    assert!(
        !restored
            .has_grant(1, 1, "get_sales_summary")
            .expect("grant")
    );
    assert!(
        restored
            .exec_grants_for_agent(1)
            .expect("grants")
            .is_empty()
    );
    // Item 1 has a connector and a variable. Item 2 has a variable.
    assert_eq!(restored.items_needing_review().expect("review"), vec![1, 2]);
}
