#![cfg(feature = "vault")]

//! Goal item V6: unlock migrates a vault from each earlier schema version (1 to 16) to
//! the current version, with data at each version. Synthetic values only.
//!
//! The schema SQL below is a frozen copy of the statements that each earlier version ran
//! at create: version 1 in commit a2f860a, 2 in 4ffdb5e, 3 in 22d1784, 4 in 2eb8366,
//! 5 in 9ce2e01, 6 in 4193991, 7 in c5a91c0, 8 in 2acde80, 9 in cff4303, 10 and 11 in
//! ab935b8, 12 in 8f1a8e0, 13 in 611fa6e (its sync row had a random vault ID; the copy
//! uses a fixed one). Do not change these copies when the current schema changes.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use apassy::contracts::CredentialKind;
use apassy::vault::{
    CandidateState, DecidedBy, DecisionEntry, Declaration, DeclarationField, EnvDelivery,
    Environment, ExecMode, ExecRule, GrantPlace, ItemEventKind, LoggedDecision, NewCandidate,
    OwnerLabel, PatternKey, PatternState, RealOutcome, RequestSource, RequestState, Reversibility,
    RiskLevel, Scope, ShadowAnswer, ShadowEntry, SuggestedDeclaration, Vault, VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "synthetic-migration-passphrase";
const CURRENT_VERSION: i64 = 17;
/// The vault ID of the frozen version 13 file.
const V13_VAULT_ID: &str = "6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab";

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

const V7_SQL: &str = "
CREATE TABLE decision_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    agent_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    project_dir TEXT NOT NULL,
    cwd_rel TEXT NOT NULL,
    items TEXT NOT NULL,
    user_request TEXT NOT NULL,
    user_request_source TEXT NOT NULL,
    command TEXT NOT NULL,
    purpose TEXT NOT NULL,
    env_names TEXT NOT NULL,
    declarations TEXT NOT NULL,
    rule_flags TEXT NOT NULL,
    known_safe INTEGER NOT NULL,
    model_facts TEXT NOT NULL,
    pattern TEXT NOT NULL,
    grant_asks INTEGER NOT NULL,
    asked INTEGER NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    decided_by TEXT NOT NULL
        CHECK (decided_by IN ('rule', 'model', 'pattern', 'owner', 'no_answer')),
    remembered INTEGER NOT NULL,
    policy TEXT NOT NULL,
    note TEXT NOT NULL,
    instruction TEXT NOT NULL
);
CREATE INDEX decision_log_at ON decision_log(at);
CREATE TABLE remembered_pattern (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    project_dir TEXT NOT NULL,
    items TEXT NOT NULL,
    policy TEXT NOT NULL,
    cwd_rel TEXT NOT NULL,
    template TEXT NOT NULL,
    display TEXT NOT NULL,
    approvals INTEGER NOT NULL,
    blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    uses INTEGER NOT NULL,
    UNIQUE (agent_id, project_dir, items, policy, cwd_rel, template)
);
CREATE TABLE calibration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    task_match REAL NOT NULL,
    report TEXT NOT NULL
);
CREATE TABLE waiting_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    item_id INTEGER,
    operation TEXT NOT NULL,
    purpose TEXT NOT NULL
);
UPDATE vault_meta SET schema_version = 7 WHERE id = 1;
PRAGMA user_version = 7;
";

const V8_SQL: &str = "
ALTER TABLE declaration ADD COLUMN provider TEXT NOT NULL DEFAULT '';
CREATE TABLE suggestion_outcome (
    item_id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    provider TEXT NOT NULL,
    environment TEXT NOT NULL,
    risk TEXT NOT NULL,
    scope TEXT NOT NULL,
    reversibility TEXT NOT NULL,
    from_signals TEXT NOT NULL,
    changed TEXT NOT NULL,
    accepted INTEGER NOT NULL CHECK (accepted IN (0, 1))
);
UPDATE vault_meta SET schema_version = 8 WHERE id = 1;
PRAGMA user_version = 8;
";

const V9_SQL: &str = "
CREATE TABLE model_candidate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    url TEXT NOT NULL,
    checkpoint TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('shadow', 'promoted', 'replaced', 'rolled_back')),
    ended_at INTEGER,
    report TEXT NOT NULL
);
CREATE TABLE shadow_decision (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id INTEGER NOT NULL,
    at INTEGER NOT NULL,
    real_outcome TEXT NOT NULL CHECK (real_outcome IN ('run', 'ask')),
    candidate_outcome TEXT NOT NULL CHECK (candidate_outcome IN ('run', 'ask', 'no_answer')),
    owner_decision TEXT NOT NULL CHECK (owner_decision IN ('allow', 'deny', 'none')),
    facts TEXT NOT NULL
);
CREATE INDEX shadow_decision_candidate ON shadow_decision(candidate_id);
CREATE TABLE model_activation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('promote', 'rollback')),
    version TEXT NOT NULL,
    url TEXT NOT NULL,
    candidate_id INTEGER,
    previous_version TEXT NOT NULL,
    previous_url TEXT NOT NULL,
    report TEXT NOT NULL
);
UPDATE vault_meta SET schema_version = 9 WHERE id = 1;
PRAGMA user_version = 9;
";

const V10_SQL: &str = "
CREATE TABLE item_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX item_event_item ON item_event(item_id, id);
CREATE TABLE item_archive (
    item_id INTEGER PRIMARY KEY,
    archived_at INTEGER NOT NULL
);
CREATE TABLE activity_item (
    activity_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL
);
CREATE INDEX activity_item_item ON activity_item(item_id);
INSERT INTO item_event (item_id, at, kind, detail)
    SELECT id, CAST(strftime('%s', 'now') AS INTEGER), 'tracked', '' FROM item;
UPDATE vault_meta SET schema_version = 10 WHERE id = 1;
PRAGMA user_version = 10;
";

const V11_SQL: &str = "
ALTER TABLE env_binding ADD COLUMN placeholder_hosts TEXT;
UPDATE vault_meta SET schema_version = 11 WHERE id = 1;
PRAGMA user_version = 11;
";

const V13_SQL: &str = "
CREATE TABLE sync_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    pushed_by TEXT NOT NULL,
    pushed_at INTEGER,
    content_digest BLOB
);
INSERT INTO sync_meta (id, vault_id, generation, pushed_by)
    VALUES (1, '6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab', 0, '');
UPDATE vault_meta SET schema_version = 13 WHERE id = 1;
PRAGMA user_version = 13;
";

const V12_SQL: &str = "
ALTER TABLE agent ADD COLUMN see_all INTEGER NOT NULL DEFAULT 0 CHECK (see_all IN (0, 1));
ALTER TABLE exec_grant ADD COLUMN any_folder INTEGER NOT NULL DEFAULT 0 CHECK (any_folder IN (0, 1));
CREATE TABLE access_request (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    cwd TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'granted', 'denied')),
    decided_at INTEGER
);
CREATE INDEX access_request_state ON access_request(state, id);
UPDATE vault_meta SET schema_version = 12 WHERE id = 1;
PRAGMA user_version = 12;
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
    let steps = [
        V1_SQL, V2_SQL, V3_SQL, V4_SQL, V5_SQL, V6_SQL, V7_SQL, V8_SQL, V9_SQL, V10_SQL, V11_SQL,
        V12_SQL, V13_SQL,
    ];
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
    if version >= 7 {
        // Version 7 learning: one owner denial, its blocked pattern, and a calibration.
        tx.execute(
            r#"INSERT INTO decision_log (at, agent_id, agent_name, project_dir, cwd_rel, items,
                 user_request, user_request_source, command, purpose, env_names, declarations,
                 rule_flags, known_safe, model_facts, pattern, grant_asks, asked, decision,
                 decided_by, remembered, policy, note, instruction)
             VALUES (?1, 1, 'MIG active agent', '/tmp/mig-project', '.', '[1]',
                 'Run the old tests.', 'agent', '["npm","run","old"]', 'Old.',
                 '["MIG_API_KEY"]', '[null]', '[]', 0, '{"task_match":0.4}',
                 'npm run old', 0, 1, 'deny', 'owner', 0, 'apassy-bouncer-v4', '', '')"#,
            [now - 600],
        )
        .expect("decision");
        tx.execute(
            "INSERT INTO remembered_pattern (agent_id, project_dir, items, policy, cwd_rel,
                 template, display, approvals, blocked, created_at, last_used_at, uses)
             VALUES (1, '/tmp/mig-project', '[1]', '1=none|', '.', 'mig-old-template',
                 'npm run old', 0, 1, ?1, ?1, 0)",
            [now - 600],
        )
        .expect("pattern");
        tx.execute(
            "INSERT INTO calibration (at, task_match, report) VALUES (?1, 0.7, 'MIG report')",
            [now - 300],
        )
        .expect("calibration");
    }
    if version >= 8 {
        // Version 8: the declaration of item 1 names its provider, and the owner accepted
        // the suggestion as it was.
        tx.execute(
            "UPDATE declaration SET provider = 'github' WHERE item_id = 1",
            [],
        )
        .expect("provider");
        tx.execute(
            "INSERT INTO suggestion_outcome (item_id, at, provider, environment, risk, scope,
                 reversibility, from_signals, changed, accepted)
             VALUES (1, ?1, 'github', 'staging', 'medium', 'read-write', 'reversible',
                 'provider', '', 1)",
            [now - 200],
        )
        .expect("suggestion");
    }
    if version >= 10 {
        // Version 10: each item has an "added" event.
        tx.execute(
            "INSERT INTO item_event (item_id, at, kind, detail) SELECT id, ?1, 'created', '' FROM item",
            [now - 100],
        )
        .expect("history");
    }
    if version >= 12 {
        // Version 12: the active agent sees all credentials.
        tx.execute(
            "UPDATE agent SET see_all = 1 WHERE name = 'MIG active agent'",
            [],
        )
        .expect("see all");
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
    if version >= 7 {
        // The learning data of version 7 stays.
        let log = vault.decision_log().expect("log");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].entry.pattern, "npm run old");
        assert_eq!(log[0].entry.decision, LoggedDecision::Deny);
        let patterns = vault.patterns().expect("patterns");
        assert_eq!(patterns.len(), 1);
        assert!(patterns[0].blocked);
        let calibration = vault.calibration().expect("calibration").expect("some");
        assert!((calibration.task_match - 0.7).abs() < 1e-9);
    } else {
        // The learning tables of version 7 start empty. The default level is active.
        assert!(vault.decision_log().expect("log").is_empty());
        assert!(vault.patterns().expect("patterns").is_empty());
        assert!(vault.calibration().expect("calibration").is_none());
    }
    if version >= 8 {
        // The provider and the suggestion outcome of version 8 stay.
        assert_eq!(
            vault.declaration_provider(1).expect("provider").as_deref(),
            Some("github")
        );
        let stats = vault.suggestion_stats().expect("stats");
        assert_eq!((stats.total, stats.accepted), (1, 1));
    } else {
        // Schema 8: a migrated declaration names no provider, and no suggestion is
        // recorded.
        assert_eq!(vault.declaration_provider(1).expect("provider"), None);
        assert_eq!(vault.suggestion_stats().expect("stats").total, 0);
    }
    // Schema 9: no candidate model, no shadow row, and no promotion. The default model
    // is active.
    assert!(vault.shadow_candidate().expect("candidate").is_none());
    assert!(vault.candidates(10).expect("candidates").is_empty());
    assert!(vault.active_model().expect("active").is_none());
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
    assert_eq!(
        vault.agent_sees_all(active.id).expect("see all"),
        version >= 12,
        "the setting of version 12 stays"
    );
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
    let binding = vault.env_binding(1).expect("binding").expect("some");
    assert_eq!(binding.env_name, "MIG_API_KEY");
    // Version 11: an old binding keeps the real value mode.
    assert_eq!(binding.delivery, EnvDelivery::Value);
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
    let mut sync_ids: Vec<String> = Vec::new();
    for version in 1..14 {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(format!("v{version}.db"));
        build_legacy(&path, version);
        assert_eq!(raw_versions(&path), (version, version));

        let mut vault = Vault::open(&path).expect("open");
        assert!(vault.is_locked());
        vault.unlock(PASS).expect("unlock migrates");
        assert_version_data(&mut vault, version);
        // Version 13: the migration gives the vault a new sync record, never pushed. A
        // version 13 file keeps its own.
        let identity = vault.sync_identity().expect("sync record");
        assert_eq!(identity.vault_id.len(), 36, "{identity:?}");
        if version == 13 {
            assert_eq!(identity.vault_id, V13_VAULT_ID);
        }
        // Version 14: each credential and each history event has a UUID, and the
        // migrated rows have no sync version yet.
        let (uuids, versions) = sync_columns(&path);
        assert_eq!(uuids.len(), 5, "{uuids:?}");
        assert!(uuids.iter().all(|uuid| uuid.len() == 32));
        assert!(
            versions
                .iter()
                .all(|(at, by, clock)| *at == 0 && by.is_empty() && clock.is_empty())
        );
        assert_eq!(identity.generation, 0);
        assert!(identity.pushed_by.is_empty());
        assert_eq!(identity.pushed_at, None);
        assert!(
            !sync_ids.contains(&identity.vault_id),
            "each migrated vault gets its own id"
        );
        sync_ids.push(identity.vault_id.clone());

        assert_eq!(
            vault.companion_setting().expect("setting"),
            apassy::vault::CompanionSetting {
                enabled: false,
                port: apassy::vault::DEFAULT_COMPANION_PORT
            }
        );
        assert!(vault.companion_devices().expect("devices").is_empty());
        assert!(
            vault
                .companion_certificate()
                .expect("certificate")
                .is_none()
        );
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
        // The provider and the suggestion outcome of version 8 work on the migrated file.
        // Item 3 has no declaration in any version.
        let outcome = vault
            .save_declaration(
                3,
                &migrated_declaration(),
                Some("github"),
                Some(&migrated_form()),
            )
            .expect("declaration")
            .expect("the first declaration records the outcome");
        assert_eq!(outcome.changed, vec![DeclarationField::Risk]);
        // The candidate model and shadow mode of version 9 work on the migrated file.
        let candidate = vault
            .register_candidate(&migrated_candidate(), u64::try_from(now()).expect("now"))
            .expect("candidate");
        assert!(
            vault
                .record_shadow(&ShadowEntry {
                    candidate_id: candidate.id,
                    at: u64::try_from(now()).expect("now"),
                    real: RealOutcome::Ask,
                    candidate: ShadowAnswer::Run,
                    owner: OwnerLabel::Allow,
                    facts: vec![("task_match".to_owned(), 0.9)],
                })
                .expect("shadow")
        );
        // Version 10: the history of each old item starts with the migration (or with
        // its "added" event in a version 10 file), and the archive and the request log
        // work on the migrated file.
        let first_kind = if version >= 10 {
            ItemEventKind::Created
        } else {
            ItemEventKind::Tracked
        };
        for item in 1..=5u64 {
            let history = vault.item_events(item, 10).expect("history");
            let oldest = history.last().expect("an event");
            assert_eq!(oldest.kind, first_kind, "item {item}: {history:?}");
        }
        // Item 3 got its declaration above, after the migration.
        assert_eq!(
            vault.item_events(3, 10).expect("history")[0].kind,
            ItemEventKind::Declaration
        );
        vault.set_archived(4, true).expect("archive");
        assert!(vault.is_archived(4).expect("archived"));
        assert!(vault.item_activity(1, 10).is_ok());
        // Version 11: a variable in placeholder mode works on the migrated file.
        let placeholder = EnvDelivery::Placeholder(vec!["api.mig.invalid".to_owned()]);
        vault
            .set_env_binding_with(5, "MIG_CUSTOM", "blob", &placeholder)
            .expect("placeholder binding");
        // Version 12: "see all", a grant for any folder, and an access request work on
        // the migrated file. Old grants keep their folder.
        for grant in vault.exec_grants_for_agent(1).expect("grants") {
            assert!(matches!(grant.place, GrantPlace::Folder(_)), "{grant:?}");
        }
        vault.set_agent_sees_all(agent.id, true).expect("see all");
        let (request, created) = vault
            .request_access(agent.id, 5, "Run the custom job.", "")
            .expect("request");
        assert!(created);
        vault
            .set_exec_grants(agent.id, &[5], &GrantPlace::AnyFolder, ExecMode::Bouncer)
            .expect("grant");
        assert_eq!(
            vault.access_requests(false, 10).expect("requests")[0].id,
            request
        );
        drop(vault);
        assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));

        // A second unlock finds the current version and changes nothing.
        let mut again = Vault::open(&path).expect("open");
        again.unlock(PASS).expect("unlock");
        assert_items(&again);
        assert_eq!(
            again.sync_identity().expect("sync record"),
            identity,
            "a second unlock keeps the sync record"
        );
        assert_eq!(again.token_lifetime_days().expect("lifetime"), 60);
        let log = again.decision_log().expect("log");
        assert_eq!(log.len(), if version >= 7 { 2 } else { 1 });
        assert!(
            log.iter()
                .any(|record| record.entry.user_request == "Use [apassy:secret]."),
            "the secret value of item 1 is masked"
        );
        assert_eq!(
            again.declaration_provider(3).expect("provider").as_deref(),
            Some("github")
        );
        let stats = again.suggestion_stats().expect("stats");
        let expected = if version >= 8 { (2, 1) } else { (1, 0) };
        assert_eq!((stats.total, stats.accepted), expected);
        let candidate = again
            .shadow_candidate()
            .expect("read")
            .expect("the candidate stays");
        assert_eq!(candidate.state, CandidateState::Shadow);
        let summary = again.shadow_summary(candidate.id).expect("summary");
        assert_eq!(
            (summary.requests, summary.agreement.shadow_decisions),
            (1, 1)
        );
        assert!(again.is_archived(4).expect("archived"), "the archive stays");
        assert_eq!(
            again
                .env_binding(5)
                .expect("binding")
                .expect("some")
                .delivery,
            EnvDelivery::Placeholder(vec!["api.mig.invalid".to_owned()])
        );
        let agent_id = again
            .list_agents()
            .expect("agents")
            .iter()
            .find(|agent| agent.name == "MIG new agent")
            .expect("agent")
            .id;
        assert!(again.agent_sees_all(agent_id).expect("see all"));
        assert_eq!(
            again.access_requests(false, 10).expect("requests")[0].state,
            RequestState::Granted
        );
        assert_eq!(
            again.exec_grants_for_agent(agent_id).expect("grants")[0].place,
            GrantPlace::AnyFolder
        );
        assert_eq!(again.item_events(1, 10).expect("history").len(), 1);
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
        instruction: String::new(),
    }
}

fn migrated_declaration() -> Declaration {
    Declaration {
        project: "mig".to_owned(),
        environment: Environment::Production,
        risk: RiskLevel::Medium,
        scope: Scope::Admin,
        reversibility: Reversibility::Irreversible,
    }
}

/// The form that a suggestion for a GitHub token gives.
fn migrated_form() -> SuggestedDeclaration {
    SuggestedDeclaration {
        provider: Some("github".to_owned()),
        environment: Environment::Production,
        risk: RiskLevel::High,
        scope: Scope::Admin,
        reversibility: Reversibility::Irreversible,
        from_signals: vec![DeclarationField::Provider, DeclarationField::Risk],
    }
}

fn migrated_candidate() -> NewCandidate {
    NewCandidate {
        version: "apassy-local-v1+0badc0de".to_owned(),
        url: "http://127.0.0.1:8775".to_owned(),
        checkpoint: "/tmp/mig-candidate.safetensors".to_owned(),
        checkpoint_sha256: "0badc0de".repeat(8),
        report: "{}".to_owned(),
    }
}

/// The sync columns of the items of a migrated file: the UUIDs, and (updated_at,
/// updated_by, clock) for each.
fn sync_columns(path: &Path) -> (Vec<String>, Vec<(i64, String, String)>) {
    let conn = rusqlite::Connection::open(path).expect("open");
    conn.pragma_update(None, "key", PASS).expect("key");
    let mut stmt = conn
        .prepare("SELECT uuid, updated_at, updated_by, clock FROM item ORDER BY id")
        .expect("prepare");
    let rows: Vec<(String, i64, String, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    let null_events: i64 = conn
        .query_row(
            "SELECT count(*) FROM item_event WHERE uuid IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("events");
    assert_eq!(null_events, 0, "every history event has a UUID");
    drop(stmt);
    conn.close().map_err(|(_, err)| err).expect("close");
    (
        rows.iter().map(|row| row.0.clone()).collect(),
        rows.into_iter().map(|row| (row.1, row.2, row.3)).collect(),
    )
}

/// Two copies of the same version 13 file agree on the UUID of each credential after
/// each migrates on its own Mac, so they merge record by record.
#[test]
fn two_copies_of_one_vault_get_the_same_record_uuids() {
    let dir = TempDir::new().expect("temp dir");
    let first = dir.path().join("first.db");
    build_legacy(&first, 13);
    let second = dir.path().join("second.db");
    std::fs::copy(&first, &second).expect("copy");
    let mut contents = Vec::new();
    for path in [&first, &second] {
        let mut vault = Vault::open(path).expect("open");
        vault.unlock(PASS).expect("unlock migrates");
        contents.push(
            vault
                .sync_content(&apassy::vault::SyncScope::vault())
                .expect("content"),
        );
    }
    assert_eq!(sync_columns(&first).0, sync_columns(&second).0);
    assert_eq!(contents[0], contents[1], "the same synced content");
}

/// The step from version 13 to 14 runs in one transaction. A failure leaves version 13
/// and its data.
#[test]
fn a_failed_migration_from_version_13_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked13.db");
    build_legacy(&path, 13);
    {
        // A table with the name of a version 14 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE sync_tombstone (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (13, 13), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let column = conn.prepare("SELECT uuid FROM item LIMIT 0");
        assert!(column.is_err(), "no column of version 14");
        drop(column);
        conn.execute_batch("DROP TABLE sync_tombstone;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 13);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

/// The step from version 12 to 14 runs in one transaction. A failure leaves version 12
/// and its data.
#[test]
fn a_failed_migration_from_version_12_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked12.db");
    build_legacy(&path, 12);
    {
        // A table with the name of the version 13 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE sync_meta (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (12, 12), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("DROP TABLE sync_meta;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 12);
    assert_eq!(vault.sync_identity().expect("sync record").generation, 0);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

/// The step from version 11 to 14 runs in one transaction. A failure leaves version 11
/// and its data.
#[test]
fn a_failed_migration_from_version_11_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked11.db");
    build_legacy(&path, 11);
    {
        // A table with the name of the version 12 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE access_request (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (11, 11), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let column = conn.prepare("SELECT see_all FROM agent LIMIT 0");
        assert!(column.is_err(), "no column of version 12");
        drop(column);
        conn.execute_batch("DROP TABLE access_request;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 11);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

#[test]
fn a_failed_migration_from_version_10_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked10.db");
    build_legacy(&path, 10);
    {
        // A column with the name of the version 11 column makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("ALTER TABLE env_binding ADD COLUMN placeholder_hosts INTEGER;")
            .expect("blocking column");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (10, 10), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("ALTER TABLE env_binding DROP COLUMN placeholder_hosts;")
            .expect("drop blocking column");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 10);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

#[test]
fn a_failed_migration_from_version_9_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked9.db");
    build_legacy(&path, 9);
    {
        // A table with the name of a version 10 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE item_archive (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (9, 9), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let history_table = conn.prepare("SELECT id FROM item_event LIMIT 0");
        assert!(history_table.is_err(), "no table of version 10");
        drop(history_table);
        conn.execute_batch("DROP TABLE item_archive;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 9);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

#[test]
fn a_failed_migration_from_version_8_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked8.db");
    build_legacy(&path, 8);
    {
        // A table with the name of a version 9 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE model_activation (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (8, 8), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let candidate_table = conn.prepare("SELECT id FROM model_candidate LIMIT 0");
        assert!(candidate_table.is_err(), "no table of version 9");
        drop(candidate_table);
        conn.execute_batch("DROP TABLE model_activation;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 8);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
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

/// The step from version 7 to 8 runs in one transaction. A failure leaves version 7 and
/// its learning data.
#[test]
fn a_failed_migration_from_version_7_keeps_the_old_version_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("blocked7.db");
    build_legacy(&path, 7);
    {
        // A table with the name of the version 8 table makes the migration fail.
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        conn.execute_batch("CREATE TABLE suggestion_outcome (x INTEGER);")
            .expect("blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (7, 7), "no partial migration");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", PASS).expect("key");
        let provider_column = conn.prepare("SELECT provider FROM declaration LIMIT 0");
        assert!(provider_column.is_err(), "no column of version 8");
        drop(provider_column);
        conn.execute_batch("DROP TABLE suggestion_outcome;")
            .expect("drop blocking table");
        conn.close().map_err(|(_, err)| err).expect("close");
    }
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("unlock migrates");
    assert_version_data(&mut vault, 7);
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
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

// Frozen schema 14, before the companion tables. Do not use current migration code.
const V14_SQL: &str = r#"
ALTER TABLE item ADD COLUMN uuid TEXT;
ALTER TABLE item ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE item ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE item ADD COLUMN clock TEXT NOT NULL DEFAULT '';
ALTER TABLE item_event ADD COLUMN uuid TEXT;
CREATE TABLE sync_tombstone (
    uuid TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL,
    deleted_by TEXT NOT NULL,
    clock TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sync_stamp (
    uuid TEXT PRIMARY KEY,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE sync_device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    applying INTEGER NOT NULL DEFAULT 0 CHECK (applying IN (0, 1))
);
CREATE TABLE sync_peer (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    seen_at INTEGER NOT NULL
);
INSERT INTO sync_device (id, device_id, device_name) VALUES (1, lower(hex(randomblob(16))), '');
UPDATE item SET uuid = printf('%032x', id);
UPDATE item_event SET uuid = printf('%032x', id);
INSERT INTO sync_stamp (uuid, updated_at, updated_by) SELECT uuid, updated_at, updated_by FROM item;

CREATE UNIQUE INDEX item_uuid ON item(uuid);
CREATE UNIQUE INDEX item_event_uuid ON item_event(uuid);
CREATE TRIGGER item_sync_insert AFTER INSERT ON item WHEN NEW.uuid IS NULL BEGIN
    UPDATE item SET uuid = lower(hex(randomblob(16))), updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER),
        updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.id;
END;
CREATE TRIGGER item_sync_update AFTER UPDATE ON item
WHEN NEW.updated_at = OLD.updated_at AND COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.id;
END;
CREATE TRIGGER item_sync_delete AFTER DELETE ON item
WHEN OLD.uuid IS NOT NULL AND COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    INSERT OR REPLACE INTO sync_tombstone (uuid, deleted_at, deleted_by, clock)
        VALUES (OLD.uuid, CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), COALESCE((SELECT device_id FROM sync_device WHERE id = 1), ''), OLD.clock);
END;
CREATE TRIGGER item_event_sync_insert AFTER INSERT ON item_event WHEN NEW.uuid IS NULL BEGIN
    UPDATE item_event SET uuid = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;

CREATE TRIGGER item_tag_sync_insert AFTER INSERT ON item_tag WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.item_id;
END;
CREATE TRIGGER item_tag_sync_update AFTER UPDATE ON item_tag WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER item_tag_sync_delete AFTER DELETE ON item_tag WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = OLD.item_id;
END;

CREATE TRIGGER item_field_sync_insert AFTER INSERT ON item_field WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.item_id;
END;
CREATE TRIGGER item_field_sync_update AFTER UPDATE ON item_field WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER item_field_sync_delete AFTER DELETE ON item_field WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = OLD.item_id;
END;

CREATE TRIGGER item_archive_sync_insert AFTER INSERT ON item_archive WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.item_id;
END;
CREATE TRIGGER item_archive_sync_update AFTER UPDATE ON item_archive WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER item_archive_sync_delete AFTER DELETE ON item_archive WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = OLD.item_id;
END;

CREATE TRIGGER declaration_sync_insert AFTER INSERT ON declaration WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.item_id;
END;
CREATE TRIGGER declaration_sync_update AFTER UPDATE ON declaration WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER declaration_sync_delete AFTER DELETE ON declaration WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = OLD.item_id;
END;

CREATE TRIGGER env_binding_sync_insert AFTER INSERT ON env_binding WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.item_id;
END;
CREATE TRIGGER env_binding_sync_update AFTER UPDATE ON env_binding WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER env_binding_sync_delete AFTER DELETE ON env_binding WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = OLD.item_id;
END;

CREATE TRIGGER destination_sync_insert AFTER INSERT ON destination WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = NEW.item_id;
END;
CREATE TRIGGER destination_sync_update AFTER UPDATE ON destination WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER destination_sync_delete AFTER DELETE ON destination WHEN COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0 BEGIN
    UPDATE item SET updated_at = CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER), updated_by = COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '') WHERE id = OLD.item_id;
END;
UPDATE vault_meta SET schema_version = 14 WHERE id = 1;
PRAGMA user_version = 14;
"#;

#[test]
fn version_14_migration_keeps_sync_records_and_is_atomic() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("v14.db");
    build_legacy(&path, 13);
    let conn = rusqlite::Connection::open(&path).expect("open");
    conn.pragma_update(None, "key", PASS).expect("key");
    conn.execute_batch(V14_SQL).expect("frozen schema 14");
    let device: String = conn
        .query_row("SELECT device_id FROM sync_device WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    conn.execute_batch("CREATE TABLE companion_device (x INTEGER);")
        .unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    let before = sync_columns(&path);
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (14, 14));
    let conn = rusqlite::Connection::open(&path).expect("open");
    conn.pragma_update(None, "key", PASS).unwrap();
    assert!(conn.prepare("SELECT id FROM companion_setting").is_err());
    assert!(
        conn.prepare("SELECT id FROM companion_certificate")
            .is_err()
    );
    conn.execute_batch("DROP TABLE companion_device;").unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("schema 14 to the current one");
    assert_version_data(&mut vault, 14);
    assert_eq!(vault.sync_identity().unwrap().vault_id, V13_VAULT_ID);
    assert_eq!(
        vault.companion_setting().unwrap(),
        apassy::vault::CompanionSetting {
            enabled: false,
            port: apassy::vault::DEFAULT_COMPANION_PORT
        }
    );
    assert!(vault.companion_devices().unwrap().is_empty());
    assert!(vault.companion_certificate().unwrap().is_none());
    assert_eq!(sync_columns(&path), before, "record IDs and clocks stay");
    drop(vault);
    let conn = rusqlite::Connection::open(&path).expect("open");
    conn.pragma_update(None, "key", PASS).unwrap();
    let after: String = conn
        .query_row("SELECT device_id FROM sync_device WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(device, after, "this is a migration, not a restore");
    conn.close().map_err(|(_, e)| e).unwrap();
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}

/// The tables of schema version 15 (ADR 0020), as the app made them on 2026-10-05.
const V15_SQL: &str = "
CREATE TABLE companion_setting (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    port INTEGER NOT NULL CHECK (port BETWEEN 1024 AND 65535)
);
INSERT INTO companion_setting (id, enabled, port) VALUES (1, 0, 48620);
CREATE TABLE companion_certificate (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    cert_der BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE companion_device (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    request_key BLOB NOT NULL,
    approval_key BLOB NOT NULL,
    paired_at INTEGER NOT NULL,
    last_seen_at INTEGER
);
UPDATE vault_meta SET schema_version = 15 WHERE id = 1;
PRAGMA user_version = 15;
";

/// ADR 0022: the migration from 15 adds the local `relay_device` table in one
/// transaction. A failure keeps version 15 and its data.
#[test]
fn version_15_migration_adds_the_relay_device_table_and_is_atomic() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("v15.db");
    build_legacy(&path, 13);
    let conn = rusqlite::Connection::open(&path).expect("open");
    conn.pragma_update(None, "key", PASS).expect("key");
    conn.execute_batch(V14_SQL).expect("frozen schema 14");
    conn.execute_batch(V15_SQL).expect("frozen schema 15");
    conn.execute(
        "UPDATE companion_setting SET enabled = 1, port = 49000 WHERE id = 1",
        [],
    )
    .expect("setting");
    // A table with this name but other columns makes the migration fail.
    conn.execute_batch("CREATE TABLE relay_device (x INTEGER);")
        .unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();
    let before = sync_columns(&path);
    let mut vault = Vault::open(&path).expect("open");
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::Storage
    );
    drop(vault);
    assert_eq!(raw_versions(&path), (15, 15));
    let conn = rusqlite::Connection::open(&path).expect("open");
    conn.pragma_update(None, "key", PASS).unwrap();
    conn.execute_batch("DROP TABLE relay_device;").unwrap();
    conn.close().map_err(|(_, e)| e).unwrap();

    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("schema 15 to current");
    assert_version_data(&mut vault, 14);
    assert_eq!(vault.sync_identity().unwrap().vault_id, V13_VAULT_ID);
    assert_eq!(
        vault.companion_setting().unwrap(),
        apassy::vault::CompanionSetting {
            enabled: true,
            port: 49000
        },
        "the companion setting stays"
    );
    assert!(vault.relay_device().unwrap().is_none());
    assert_eq!(sync_columns(&path), before, "record IDs and clocks stay");
    drop(vault);
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
    assert!(apassy::vault::LOCAL_TABLES.contains(&"relay_device"));
}

/// The table of schema version 16 (ADR 0022), as the app made it on 2026-10-06.
const V16_SQL: &str = "
CREATE TABLE relay_device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    relay_url TEXT NOT NULL,
    team_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
UPDATE vault_meta SET schema_version = 16 WHERE id = 1;
PRAGMA user_version = 16;
";

/// Schema 17 reserves the `passkey_` field names. The migration gives an ordinary field
/// of schema 16 with such a name a free name, and the environment binding of the field
/// follows it, so an agent run still reads the value. The revision and the sync columns
/// stay. The test compares values and does not print them.
#[test]
fn version_17_migration_renames_reserved_fields_and_their_binding() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("v16.db");
    build_legacy(&path, 13);
    let conn = rusqlite::Connection::open(&path).expect("open");
    conn.pragma_update(None, "key", PASS).expect("key");
    conn.execute_batch(V14_SQL).expect("frozen schema 14");
    conn.execute_batch(V15_SQL).expect("frozen schema 15");
    conn.execute_batch(V16_SQL).expect("frozen schema 16");
    // Item 1 has the secret field `token` and the binding MIG_API_KEY to it. In schema 16
    // the owner could name that field `passkey_key`.
    conn.execute_batch(
        "UPDATE sync_device SET applying = 1 WHERE id = 1;
         UPDATE item_field SET name = 'passkey_key' WHERE item_id = 1 AND name = 'token';
         UPDATE env_binding SET field = 'passkey_key' WHERE item_id = 1;
         UPDATE sync_device SET applying = 0 WHERE id = 1;",
    )
    .expect("reserved name");
    let revision: i64 = conn
        .query_row("SELECT revision FROM item WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("revision");
    conn.close().map_err(|(_, e)| e).unwrap();
    assert_eq!(raw_versions(&path), (16, 16));
    let before = sync_columns(&path);

    let mut vault = Vault::open(&path).expect("open");
    vault.unlock(PASS).expect("schema 16 to current");
    let renamed: String = "passkey_key"
        .bytes()
        .fold(String::from("x_"), |mut text, byte| {
            text.push_str(&format!("{byte:02x}"));
            text
        });
    // The binding has the new name, and the path of an agent run reads the value.
    let binding = vault.env_binding(1).expect("binding").expect("some");
    assert_eq!(binding.env_name, "MIG_API_KEY");
    assert_eq!(binding.field, renamed);
    assert_eq!(binding.delivery, EnvDelivery::Value);
    let value = vault
        .reveal(1, &binding.field)
        .expect("reveal of the binding");
    assert!(
        value.expose() == "MIG-SECRET-api-token",
        "the bound field keeps its value"
    );
    let details = vault.details(1).expect("details");
    let names: Vec<&str> = details.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, [renamed.as_str(), "service"]);
    assert!(details.fields[0].secret);
    assert_eq!(details.summary.revision, u64::try_from(revision).unwrap());
    assert!(
        vault.reveal(1, "service").expect("plain field").expose() == "mig-service",
        "an ordinary field keeps its value"
    );
    // The other binding does not change.
    assert_eq!(
        vault.env_binding(2).expect("binding").expect("some").field,
        "password"
    );
    drop(vault);
    assert_eq!(sync_columns(&path), before, "record IDs and clocks stay");
    assert_eq!(raw_versions(&path), (CURRENT_VERSION, CURRENT_VERSION));
}
