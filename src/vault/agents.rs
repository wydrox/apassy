//! Agent identity, manual grants, connector destinations, and activity (schema v2).
//!
//! These records support the thin agent path in ADR 0004. Manual grants are a
//! temporary substitute for confirmed rules. They are not a policy engine.
//! Agent tokens stay inside the encrypted database. A token is shown to the
//! owner one time at registration.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, fresh_epoch, to_public_id, to_sql_id};

pub const AGENT_TOKEN_PREFIX: &str = "apassy_agt_";
pub const MAX_AGENT_NAME_BYTES: usize = 64;
pub const MAX_OPERATION_BYTES: usize = 64;
pub const MAX_PROFILE_BYTES: usize = 64;
pub const MAX_BASE_URL_BYTES: usize = 256;
pub const MAX_ACTIVITY_REASON_BYTES: usize = 700;
pub const MAX_ACTIVITY_ROWS: usize = 500;
const TOKEN_BYTES: usize = 32;

/// Tables added in schema version 2. The statements run in one transaction.
pub(super) const SCHEMA_V2_SQL: &str = "
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

/// Tables added in schema version 3 (ADR 0006): process secrets.
pub(super) const SCHEMA_V3_SQL: &str = "
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

pub(super) const SCHEMA_V3_COLUMNS: [&str; 2] = [
    "SELECT item_id, env_name, field FROM env_binding LIMIT 0",
    "SELECT agent_id, item_id, project_dir, mode, created_at FROM exec_grant LIMIT 0",
];

/// Tables and columns added in schema version 4 (ADR 0007): rules and a run log.
pub(super) const SCHEMA_V4_SQL: &str = "
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

pub(super) const SCHEMA_V4_COLUMNS: [&str; 2] = [
    "SELECT rule FROM exec_grant LIMIT 0",
    "SELECT agent_id, item_id, at FROM run_log LIMIT 0",
];

pub const MAX_RULE_ENTRIES: usize = 32;
pub const MAX_RULE_ENTRY_BYTES: usize = 128;
pub const MAX_INSTRUCTION_BYTES: usize = 1000;

pub const MAX_ENV_NAME_BYTES: usize = 64;
pub const MAX_PROJECT_DIR_BYTES: usize = 1024;

/// Environment names that an owner cannot bind. They change how programs load or run.
const RESERVED_ENV_NAMES: [&str; 12] = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "PWD",
    "IFS",
    "ENV",
    "BASH_ENV",
    "NODE_OPTIONS",
    "PYTHONPATH",
];
const RESERVED_ENV_PREFIXES: [&str; 4] = ["DYLD_", "LD_", "APASSY_", "__CF"];

pub(super) const SCHEMA_V2_COLUMNS: [&str; 4] = [
    "SELECT id, name, token, created_at, revoked_at FROM agent LIMIT 0",
    "SELECT item_id, profile, base_url FROM destination LIMIT 0",
    "SELECT agent_id, item_id, operation, created_at FROM grant_rule LIMIT 0",
    "SELECT id, at, agent_id, agent_name, item_id, operation, decision, reason FROM activity LIMIT 0",
];

/// Agent token text. Debug is redacted. There is no `Serialize` impl.
pub struct AgentToken(String);

impl AgentToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AgentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AgentToken([redacted])")
    }
}

impl Drop for AgentToken {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSummary {
    pub id: u64,
    pub name: String,
    pub created_at: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    pub agent_id: u64,
    pub item_id: u64,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub item_id: u64,
    pub profile: String,
    pub base_url: String,
}

/// One vault item bound to one environment variable for agent processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvBinding {
    pub item_id: u64,
    pub env_name: String,
    pub field: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// The owner approves each run.
    Ask,
    /// The bouncer decides. A clean run starts without a prompt. A risky run,
    /// or a run when the bouncer is unavailable, waits for the owner (ADR 0007).
    Bouncer,
}

impl ExecMode {
    /// Stored text. Schema version 3 stored "allow" for a run without a prompt.
    /// ADR 0007 puts those grants under the bouncer.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Bouncer => "allow",
        }
    }

    fn from_str(text: &str) -> VaultResult<Self> {
        match text {
            "ask" => Ok(Self::Ask),
            "allow" => Ok(Self::Bouncer),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// Owner rule for one process grant (ADR 0007). Stored as JSON in the vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExecRule {
    /// The command must start with one of these, at a word boundary. Empty permits any command.
    pub allowed_prefixes: Vec<String>,
    /// A command that contains one of these words, without regard to case, is denied.
    pub forbidden_words: Vec<String>,
    /// Unix time after which the grant does not work.
    pub expires_at: Option<u64>,
    /// Maximum number of runs in one hour.
    pub max_runs_per_hour: Option<u32>,
    /// Owner instruction in plain text. The bouncer checks each request against it.
    pub instruction: String,
}

impl ExecRule {
    /// Trim and check the rule. Empty entries are removed.
    pub fn normalized(mut self) -> VaultResult<Self> {
        let clean = |list: Vec<String>| -> VaultResult<Vec<String>> {
            let list: Vec<String> = list
                .into_iter()
                .map(|entry| entry.trim().to_owned())
                .filter(|entry| !entry.is_empty())
                .collect();
            let bad = list.len() > MAX_RULE_ENTRIES
                || list.iter().any(|entry| {
                    entry.len() > MAX_RULE_ENTRY_BYTES || entry.chars().any(char::is_control)
                });
            if bad {
                Err(err(VaultErrorKind::InvalidInput))
            } else {
                Ok(list)
            }
        };
        self.allowed_prefixes = clean(self.allowed_prefixes)?;
        self.forbidden_words = clean(self.forbidden_words)?;
        self.instruction = self.instruction.trim().to_owned();
        if self.instruction.len() > MAX_INSTRUCTION_BYTES
            || self.instruction.contains('\0')
            || self.max_runs_per_hour == Some(0)
        {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        Ok(self)
    }
}

/// Process access for one agent and one item, limited to one project directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecGrant {
    pub agent_id: u64,
    pub item_id: u64,
    pub project_dir: String,
    pub mode: ExecMode,
    pub rule: ExecRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDecision {
    Allow,
    Deny,
    Error,
}

impl ActivityDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }

    fn from_str(text: &str) -> VaultResult<Self> {
        match text {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "error" => Ok(Self::Error),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// One activity entry to store. Text must not contain secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewActivity {
    pub agent_id: Option<u64>,
    pub agent_name: String,
    pub item_id: Option<u64>,
    pub operation: String,
    pub decision: ActivityDecision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityRecord {
    pub id: u64,
    pub at: u64,
    pub agent_id: Option<u64>,
    pub agent_name: String,
    pub item_id: Option<u64>,
    pub operation: String,
    pub decision: ActivityDecision,
    pub reason: String,
}

impl Vault {
    /// Register an agent. The returned token is the only copy outside the vault.
    pub fn register_agent(&mut self, name: &str) -> VaultResult<(AgentSummary, AgentToken)> {
        let name = checked_text(name.trim(), MAX_AGENT_NAME_BYTES)?.to_owned();
        let token = fresh_epoch()?;
        let at = now_unix();
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO agent (name, token, created_at, revoked_at) VALUES (?1, ?2, ?3, NULL)",
            (name.as_str(), token.as_slice(), to_sql_time(at)?),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = to_public_id(tx.last_insert_rowid())?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        let summary = AgentSummary {
            id,
            name,
            created_at: at,
            revoked: false,
        };
        Ok((summary, AgentToken(format_token(&token))))
    }

    pub fn list_agents(&self) -> VaultResult<Vec<AgentSummary>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare("SELECT id, name, created_at, revoked_at FROM agent ORDER BY id ASC")
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut agents = Vec::new();
        for row in rows {
            let (id, name, created_at, revoked_at) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            agents.push(AgentSummary {
                id: to_public_id(id)?,
                name,
                created_at: from_sql_time(created_at)?,
                revoked: revoked_at.is_some(),
            });
        }
        Ok(agents)
    }

    /// Revoke an agent. Its token stops working at once. Its grants are removed.
    pub fn revoke_agent(&mut self, agent_id: u64) -> VaultResult<()> {
        let sql_id = to_sql_id(agent_id)?;
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let changed = tx
            .execute(
                "UPDATE agent SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                (at, sql_id),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if changed == 0 {
            let exists: Option<i64> = tx
                .query_row("SELECT id FROM agent WHERE id = ?1", [sql_id], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|_| err(VaultErrorKind::Storage))?;
            if exists.is_none() {
                return Err(err(VaultErrorKind::NotFound));
            }
        }
        tx.execute("DELETE FROM grant_rule WHERE agent_id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM exec_grant WHERE agent_id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Find the active agent for a token. Every stored token is compared in constant time.
    pub fn authenticate_agent(&self, token: &str) -> VaultResult<AgentSummary> {
        let presented = parse_token(token).ok_or_else(|| err(VaultErrorKind::NotFound))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare("SELECT id, name, token, created_at FROM agent WHERE revoked_at IS NULL")
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut found = None;
        for row in rows {
            let (id, name, stored, created_at) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            if constant_time_eq(&stored, &presented) && found.is_none() {
                found = Some(AgentSummary {
                    id: to_public_id(id)?,
                    name,
                    created_at: from_sql_time(created_at)?,
                    revoked: false,
                });
            }
        }
        found.ok_or_else(|| err(VaultErrorKind::NotFound))
    }

    /// Permit or remove one named operation for one agent and one item.
    pub fn set_grant(
        &mut self,
        agent_id: u64,
        item_id: u64,
        operation: &str,
        allowed: bool,
    ) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let operation = checked_identifier(operation, MAX_OPERATION_BYTES)?;
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if allowed {
            require_active_agent(&tx, agent)?;
            require_item(&tx, item)?;
            tx.execute(
                "INSERT OR IGNORE INTO grant_rule (agent_id, item_id, operation, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                (agent, item, operation, at),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        } else {
            tx.execute(
                "DELETE FROM grant_rule WHERE agent_id = ?1 AND item_id = ?2 AND operation = ?3",
                (agent, item, operation),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    pub fn grants_for_agent(&self, agent_id: u64) -> VaultResult<Vec<GrantSummary>> {
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT item_id, operation FROM grant_rule WHERE agent_id = ?1
                 ORDER BY item_id ASC, operation ASC",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([agent], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut grants = Vec::new();
        for row in rows {
            let (item_id, operation) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            grants.push(GrantSummary {
                agent_id,
                item_id: to_public_id(item_id)?,
                operation,
            });
        }
        Ok(grants)
    }

    pub fn has_grant(&self, agent_id: u64, item_id: u64, operation: &str) -> VaultResult<bool> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM grant_rule
                 JOIN agent ON agent.id = grant_rule.agent_id
                 WHERE grant_rule.agent_id = ?1 AND grant_rule.item_id = ?2
                   AND grant_rule.operation = ?3 AND agent.revoked_at IS NULL",
                (agent, item, operation),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(found.is_some())
    }

    /// Register the connector destination for an item. The broker checks the profile and URL form.
    pub fn set_destination(
        &mut self,
        item_id: u64,
        profile: &str,
        base_url: &str,
    ) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let profile = checked_identifier(profile, MAX_PROFILE_BYTES)?;
        let base_url = checked_text(base_url.trim(), MAX_BASE_URL_BYTES)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_item(&tx, item)?;
        tx.execute(
            "INSERT INTO destination (item_id, profile, base_url) VALUES (?1, ?2, ?3)
             ON CONFLICT(item_id) DO UPDATE SET profile = excluded.profile, base_url = excluded.base_url",
            (item, profile, base_url),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Remove the destination and every grant for the item.
    pub fn clear_destination(&mut self, item_id: u64) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM destination WHERE item_id = ?1", [item])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM grant_rule WHERE item_id = ?1", [item])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    pub fn destination(&self, item_id: u64) -> VaultResult<Option<Destination>> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let row = conn
            .query_row(
                "SELECT profile, base_url FROM destination WHERE item_id = ?1",
                [item],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(row.map(|(profile, base_url)| Destination {
            item_id,
            profile,
            base_url,
        }))
    }

    /// Bind an item to an environment variable. `field` must be a secret field of the item.
    pub fn set_env_binding(
        &mut self,
        item_id: u64,
        env_name: &str,
        field: &str,
    ) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let env_name = checked_env_name(env_name.trim())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_item(&tx, item)?;
        let secret: Option<i64> = tx
            .query_row(
                "SELECT secret FROM item_field WHERE item_id = ?1 AND name = ?2",
                (item, field),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if secret != Some(1) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let taken: Option<i64> = tx
            .query_row(
                "SELECT item_id FROM env_binding WHERE env_name = ?1 AND item_id != ?2",
                (env_name, item),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if taken.is_some() {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        tx.execute(
            "INSERT INTO env_binding (item_id, env_name, field) VALUES (?1, ?2, ?3)
             ON CONFLICT(item_id) DO UPDATE SET env_name = excluded.env_name, field = excluded.field",
            (item, env_name, field),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Remove the binding and every process grant for the item.
    pub fn clear_env_binding(&mut self, item_id: u64) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM env_binding WHERE item_id = ?1", [item])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM exec_grant WHERE item_id = ?1", [item])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    pub fn env_binding(&self, item_id: u64) -> VaultResult<Option<EnvBinding>> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let row = conn
            .query_row(
                "SELECT env_name, field FROM env_binding WHERE item_id = ?1",
                [item],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(row.map(|(env_name, field)| EnvBinding {
            item_id,
            env_name,
            field,
        }))
    }

    /// Give or change process access. `project_dir` must be an absolute path.
    pub fn set_exec_grant(
        &mut self,
        agent_id: u64,
        item_id: u64,
        project_dir: &str,
        mode: ExecMode,
    ) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let project_dir = checked_text(project_dir.trim(), MAX_PROJECT_DIR_BYTES)?;
        if !project_dir.starts_with('/') {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_active_agent(&tx, agent)?;
        require_item(&tx, item)?;
        let bound: Option<i64> = tx
            .query_row(
                "SELECT item_id FROM env_binding WHERE item_id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if bound.is_none() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        tx.execute(
            "INSERT INTO exec_grant (agent_id, item_id, project_dir, mode, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(agent_id, item_id) DO UPDATE SET
                 project_dir = excluded.project_dir, mode = excluded.mode",
            (agent, item, project_dir, mode.as_str(), at),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    pub fn remove_exec_grant(&mut self, agent_id: u64, item_id: u64) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        self.conn_mut()?
            .execute(
                "DELETE FROM exec_grant WHERE agent_id = ?1 AND item_id = ?2",
                (agent, item),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(())
    }

    /// Process grants of an active agent. A revoked agent has none.
    pub fn exec_grants_for_agent(&self, agent_id: u64) -> VaultResult<Vec<ExecGrant>> {
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT exec_grant.item_id, exec_grant.project_dir, exec_grant.mode, exec_grant.rule
                 FROM exec_grant JOIN agent ON agent.id = exec_grant.agent_id
                 WHERE exec_grant.agent_id = ?1 AND agent.revoked_at IS NULL
                 ORDER BY exec_grant.item_id ASC",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([agent], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut grants = Vec::new();
        for row in rows {
            let (item_id, project_dir, mode, rule) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            grants.push(ExecGrant {
                agent_id,
                item_id: to_public_id(item_id)?,
                project_dir,
                mode: ExecMode::from_str(&mode)?,
                rule: serde_json::from_str(&rule).map_err(|_| err(VaultErrorKind::Storage))?,
            });
        }
        Ok(grants)
    }

    /// Replace the rule of a process grant. The grant must exist.
    pub fn set_exec_rule(
        &mut self,
        agent_id: u64,
        item_id: u64,
        rule: ExecRule,
    ) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let rule =
            serde_json::to_string(&rule.normalized()?).map_err(|_| err(VaultErrorKind::Storage))?;
        let changed = self
            .conn_mut()?
            .execute(
                "UPDATE exec_grant SET rule = ?1 WHERE agent_id = ?2 AND item_id = ?3",
                (rule, agent, item),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if changed == 0 {
            Err(err(VaultErrorKind::NotFound))
        } else {
            Ok(())
        }
    }

    /// Record that a run started. The hourly limit counts these entries.
    pub fn record_run(&mut self, agent_id: u64, item_id: u64) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO run_log (agent_id, item_id, at) VALUES (?1, ?2, ?3)",
            (agent, item, at),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        conn.execute("DELETE FROM run_log WHERE at < ?1", [at - 7200])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(())
    }

    /// Runs in the last hour for one agent and one item.
    pub fn runs_in_last_hour(&self, agent_id: u64, item_id: u64) -> VaultResult<u32> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let since = to_sql_time(now_unix())? - 3600;
        let count: i64 = self
            .conn_ref()?
            .query_row(
                "SELECT COUNT(*) FROM run_log WHERE agent_id = ?1 AND item_id = ?2 AND at > ?3",
                (agent, item, since),
                |row| row.get(0),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        u32::try_from(count).map_err(|_| err(VaultErrorKind::Storage))
    }

    pub fn record_activity(&mut self, entry: &NewActivity) -> VaultResult<()> {
        let agent_id = entry.agent_id.map(to_sql_id).transpose()?;
        let item_id = entry.item_id.map(to_sql_id).transpose()?;
        let agent_name = truncate_text(&entry.agent_name, MAX_AGENT_NAME_BYTES);
        let operation = truncate_text(&entry.operation, MAX_OPERATION_BYTES);
        let reason = truncate_text(&entry.reason, MAX_ACTIVITY_REASON_BYTES);
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO activity (at, agent_id, agent_name, item_id, operation, decision, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                at,
                agent_id,
                agent_name,
                item_id,
                operation,
                entry.decision.as_str(),
                reason,
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        conn.execute(
            "DELETE FROM activity WHERE id NOT IN
             (SELECT id FROM activity ORDER BY id DESC LIMIT ?1)",
            [i64::try_from(MAX_ACTIVITY_ROWS).map_err(|_| err(VaultErrorKind::Storage))?],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(())
    }

    /// Newest entries first.
    pub fn recent_activity(&self, limit: usize) -> VaultResult<Vec<ActivityRecord>> {
        let limit = i64::try_from(limit.min(MAX_ACTIVITY_ROWS))
            .map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, at, agent_id, agent_name, item_id, operation, decision, reason
                 FROM activity ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut records = Vec::new();
        for row in rows {
            let (id, at, agent_id, agent_name, item_id, operation, decision, reason) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            records.push(ActivityRecord {
                id: to_public_id(id)?,
                at: from_sql_time(at)?,
                agent_id: agent_id.map(to_public_id).transpose()?,
                agent_name,
                item_id: item_id.map(to_public_id).transpose()?,
                operation,
                decision: ActivityDecision::from_str(&decision)?,
                reason,
            });
        }
        Ok(records)
    }
}

/// Revoke every active agent. Restore calls this before the restored vault is used.
pub(super) fn revoke_all_agents(conn: &mut Connection) -> VaultResult<()> {
    let at = to_sql_time(now_unix())?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute(
        "UPDATE agent SET revoked_at = ?1 WHERE revoked_at IS NULL",
        [at],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute("DELETE FROM grant_rule", [])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute("DELETE FROM exec_grant", [])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.commit().map_err(|_| err(VaultErrorKind::Storage))
}

/// Remove the grants and the destination of a deleted item in the same transaction.
pub(super) fn delete_item_links(tx: &rusqlite::Transaction<'_>, item_id: i64) -> VaultResult<()> {
    tx.execute("DELETE FROM grant_rule WHERE item_id = ?1", [item_id])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute("DELETE FROM destination WHERE item_id = ?1", [item_id])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute("DELETE FROM env_binding WHERE item_id = ?1", [item_id])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute("DELETE FROM exec_grant WHERE item_id = ?1", [item_id])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

fn require_active_agent(tx: &rusqlite::Transaction<'_>, agent: i64) -> VaultResult<()> {
    let row: Option<Option<i64>> = tx
        .query_row(
            "SELECT revoked_at FROM agent WHERE id = ?1",
            [agent],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    match row {
        Some(None) => Ok(()),
        Some(Some(_)) => Err(err(VaultErrorKind::InvalidInput)),
        None => Err(err(VaultErrorKind::NotFound)),
    }
}

fn require_item(tx: &rusqlite::Transaction<'_>, item: i64) -> VaultResult<()> {
    let found: Option<i64> = tx
        .query_row("SELECT id FROM item WHERE id = ?1", [item], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    found
        .map(|_| ())
        .ok_or_else(|| err(VaultErrorKind::NotFound))
}

fn checked_text(text: &str, max: usize) -> VaultResult<&str> {
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        Err(err(VaultErrorKind::InvalidInput))
    } else {
        Ok(text)
    }
}

fn checked_identifier(text: &str, max: usize) -> VaultResult<&str> {
    let valid = !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if valid {
        Ok(text)
    } else {
        Err(err(VaultErrorKind::InvalidInput))
    }
}

/// `[A-Z_][A-Z0-9_]*`, at most 64 bytes, and not a reserved name.
pub fn checked_env_name(name: &str) -> VaultResult<&str> {
    let mut bytes = name.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_');
    let rest_ok = bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    let reserved = RESERVED_ENV_NAMES.contains(&name)
        || RESERVED_ENV_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
    if first_ok && rest_ok && name.len() <= MAX_ENV_NAME_BYTES && !reserved {
        Ok(name)
    } else {
        Err(err(VaultErrorKind::InvalidInput))
    }
}

fn truncate_text(text: &str, max: usize) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.len() <= max {
        return clean;
    }
    let mut end = max;
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}

fn format_token(bytes: &[u8; TOKEN_BYTES]) -> String {
    let mut text = String::with_capacity(AGENT_TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
    text.push_str(AGENT_TOKEN_PREFIX);
    for byte in bytes {
        text.push(hex_digit(byte >> 4));
        text.push(hex_digit(byte & 0x0f));
    }
    text
}

fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble & 0x0f)])
}

fn parse_token(text: &str) -> Option<[u8; TOKEN_BYTES]> {
    let hex = text.trim().strip_prefix(AGENT_TOKEN_PREFIX)?.as_bytes();
    if hex.len() != TOKEN_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; TOKEN_BYTES];
    for (slot, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        *slot = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn constant_time_eq(stored: &[u8], presented: &[u8; TOKEN_BYTES]) -> bool {
    if stored.len() != TOKEN_BYTES {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(presented.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn to_sql_time(at: u64) -> VaultResult<i64> {
    i64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))
}

fn from_sql_time(at: i64) -> VaultResult<u64> {
    u64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip_and_rejects_bad_text() {
        let bytes = [0xabu8; TOKEN_BYTES];
        let text = format_token(&bytes);
        assert!(text.starts_with(AGENT_TOKEN_PREFIX));
        assert_eq!(parse_token(&text), Some(bytes));
        assert_eq!(parse_token("apassy_agt_zz"), None);
        assert_eq!(parse_token(&text.to_uppercase()), None);
        assert_eq!(parse_token(&text[AGENT_TOKEN_PREFIX.len()..]), None);
    }

    #[test]
    fn constant_time_eq_checks_length_and_value() {
        let presented = [1u8; TOKEN_BYTES];
        assert!(constant_time_eq(&[1u8; TOKEN_BYTES], &presented));
        assert!(!constant_time_eq(&[2u8; TOKEN_BYTES], &presented));
        assert!(!constant_time_eq(&[1u8; 16], &presented));
    }

    #[test]
    fn env_names() {
        assert!(checked_env_name("SUPABASE_SERVICE_KEY").is_ok());
        assert!(checked_env_name("_X1").is_ok());
        for bad in [
            "",
            "path",
            "PATH",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "APASSY_X",
            "1ABC",
            "A-B",
            "NODE_OPTIONS",
        ] {
            assert!(checked_env_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn truncate_keeps_char_boundaries_and_drops_controls() {
        assert_eq!(truncate_text("a\nb", 10), "ab");
        assert_eq!(truncate_text("ąąą", 3), "ą");
    }
}
