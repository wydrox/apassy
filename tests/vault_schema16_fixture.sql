-- Frozen schema 16 from released Apassy 0.3.6, commit a1678e334960bcdb7df66a081058782b4422f47a.
-- initialize_new_db SQL components, in historical order; merge triggers expanded.
-- No current schema builders or version-only downgrade. Synthetic test data is added separately.

-- mod.rs::SCHEMA_SQL

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

-- agents.rs::SCHEMA_V2_SQL

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

-- agents.rs::SCHEMA_V3_SQL

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

-- agents.rs::SCHEMA_V4_SQL

ALTER TABLE exec_grant ADD COLUMN rule TEXT NOT NULL DEFAULT '{}';
CREATE TABLE run_log (
    agent_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX run_log_agent_item ON run_log(agent_id, item_id, at);
UPDATE vault_meta SET schema_version = 4 WHERE id = 1;
PRAGMA user_version = 4;

-- agents.rs::SCHEMA_V5_SQL

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

-- agents.rs::SCHEMA_V6_SQL

ALTER TABLE agent ADD COLUMN token_issued_at INTEGER NOT NULL DEFAULT 0;
UPDATE agent SET token_issued_at = created_at;
ALTER TABLE vault_meta ADD COLUMN token_lifetime_days INTEGER NOT NULL DEFAULT 30;
CREATE TABLE restore_review (
    item_id INTEGER PRIMARY KEY,
    restored_at INTEGER NOT NULL
);
UPDATE vault_meta SET schema_version = 6 WHERE id = 1;
PRAGMA user_version = 6;

-- learning.rs::SCHEMA_V7_SQL

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

-- suggestions.rs::SCHEMA_V8_SQL

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

-- candidate.rs::SCHEMA_V9_SQL

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

-- history.rs::SCHEMA_V10_SQL

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

-- agents.rs::SCHEMA_V11_SQL

ALTER TABLE env_binding ADD COLUMN placeholder_hosts TEXT;
UPDATE vault_meta SET schema_version = 11 WHERE id = 1;
PRAGMA user_version = 11;

-- agents.rs::SCHEMA_V12_SQL

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

-- sync.rs::SCHEMA_V13_SQL

CREATE TABLE sync_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    pushed_by TEXT NOT NULL,
    pushed_at INTEGER,
    content_digest BLOB
);
UPDATE vault_meta SET schema_version = 13 WHERE id = 1;
PRAGMA user_version = 13;

INSERT INTO sync_meta (id, vault_id, generation, pushed_by) VALUES (1, '11111111-1111-4111-8111-111111111111', 0, '');

-- merge.rs::SCHEMA_V14_SQL

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

-- merge.rs::triggers_sql, expanded

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

-- companion.rs::SCHEMA_V15_SQL

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

-- relay_device.rs::SCHEMA_V16_SQL

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
