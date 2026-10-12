//! The directory of the relay: `relay.db` (ADR 0019, docs/SPEC.md "Teams").
//!
//! One SQLCipher file, keyed with the master key. It holds the teams (public id, name,
//! state, and the random key of each team file), the one-time team codes of the
//! operator, and the audit of the relay: operator actions, and refused requests that
//! name no known team. It holds no people, no items, and no runs: those are in the
//! file of each team.

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::secret::{SecretString, TokenKind, new_team_code, parse_token, token_hash};
use crate::server::audit::Audit;
use crate::server::store::{Store, db, to_i, to_u};

/// `PRAGMA user_version` of the directory. Far from the team versions, so one file is
/// never taken for the other.
pub const DIRECTORY_VERSION: i64 = 1002;

const SCHEMA: &str = "
CREATE TABLE team (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, file_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','suspended')),
  legacy INTEGER NOT NULL DEFAULT 0 CHECK (legacy IN (0, 1)),
  created_at INTEGER NOT NULL, suspended_at INTEGER, limits TEXT);
CREATE UNIQUE INDEX team_legacy ON team(legacy) WHERE legacy = 1;
CREATE TABLE team_code (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, team_id TEXT);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);
PRAGMA user_version = 1002;
";

/// The actor of an operator action, in the directory and in the team's own audit.
pub const OPERATOR_ACTOR: &str = "operator";

/// The longest life of a team code, in hours.
pub const MAX_TEAM_CODE_HOURS: u64 = 720;

/// The effective resource limits of one team.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TeamLimits {
    pub members: u64,
    pub items: u64,
    pub agents: u64,
    pub runs_per_hour: u64,
    pub pending_runs: u64,
    pub agent_requests: u64,
    /// The largest vault snapshot, in bytes (docs/SPEC.md section 24).
    pub sync_bytes: u64,
    /// Snapshot pushes in the last 3600 seconds.
    pub sync_pushes_per_hour: u64,
    /// Snapshot pushes and downloads of the team at once.
    pub sync_transfers: u64,
    /// Questions with the state `open` (docs/SPEC.md section 25).
    pub open_questions: u64,
    /// Questions posted in the last 3600 seconds.
    pub questions_per_hour: u64,
}

impl Default for TeamLimits {
    fn default() -> Self {
        Self {
            members: 50,
            items: 500,
            agents: 100,
            runs_per_hour: 1000,
            pending_runs: 50,
            agent_requests: 56,
            sync_bytes: 67_108_864,
            sync_pushes_per_hour: 600,
            sync_transfers: 2,
            open_questions: 20,
            questions_per_hour: 300,
        }
    }
}

/// Only the fields supplied by the operator change.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TeamLimitsUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runs_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_runs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_requests: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_pushes_per_hour: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_transfers: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_questions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub questions_per_hour: Option<u64>,
}

impl TeamLimits {
    pub fn validate(&self) -> RelayResult<()> {
        for (field, value) in [
            ("members", self.members),
            ("items", self.items),
            ("agents", self.agents),
            ("runs_per_hour", self.runs_per_hour),
            ("pending_runs", self.pending_runs),
            ("sync_pushes_per_hour", self.sync_pushes_per_hour),
            ("questions_per_hour", self.questions_per_hour),
        ] {
            if !(1..=1_000_000).contains(&value) {
                return Err(RelayError::invalid(format!(
                    "{field} must be 1 to 1000000."
                )));
            }
        }
        if !(1..=224).contains(&self.agent_requests) {
            return Err(RelayError::invalid("agent_requests must be 1 to 224."));
        }
        if !(1_048_576..=crate::sync_head::MAX_SNAPSHOT_BYTES).contains(&self.sync_bytes) {
            return Err(RelayError::invalid(
                "sync_bytes must be 1048576 to 67108864.",
            ));
        }
        if !(1..=8).contains(&self.sync_transfers) {
            return Err(RelayError::invalid("sync_transfers must be 1 to 8."));
        }
        if !(1..=1000).contains(&self.open_questions) {
            return Err(RelayError::invalid("open_questions must be 1 to 1000."));
        }
        Ok(())
    }

    pub fn apply(self, update: TeamLimitsUpdate) -> RelayResult<Self> {
        let limits = Self {
            members: update.members.unwrap_or(self.members),
            items: update.items.unwrap_or(self.items),
            agents: update.agents.unwrap_or(self.agents),
            runs_per_hour: update.runs_per_hour.unwrap_or(self.runs_per_hour),
            pending_runs: update.pending_runs.unwrap_or(self.pending_runs),
            agent_requests: update.agent_requests.unwrap_or(self.agent_requests),
            sync_bytes: update.sync_bytes.unwrap_or(self.sync_bytes),
            sync_pushes_per_hour: update
                .sync_pushes_per_hour
                .unwrap_or(self.sync_pushes_per_hour),
            sync_transfers: update.sync_transfers.unwrap_or(self.sync_transfers),
            open_questions: update.open_questions.unwrap_or(self.open_questions),
            questions_per_hour: update.questions_per_hour.unwrap_or(self.questions_per_hour),
        };
        limits.validate()?;
        Ok(limits)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamState {
    Active,
    Suspended,
}

impl TeamState {
    fn text(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// One team of the directory, with the key of its file.
pub struct TeamRow {
    pub id: TeamId,
    pub name: String,
    pub file_key: SecretString,
    pub state: TeamState,
    /// The team migrated from a relay before teams. Its old member and agent tokens
    /// have no team id; the relay sends them here.
    pub legacy: bool,
    pub created_at: u64,
    pub suspended_at: Option<u64>,
    pub limits: TeamLimits,
}

fn team_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamRow> {
    let id: String = row.get(0)?;
    let state: String = row.get(3)?;
    let text: Option<String> = row.get(7)?;
    let limits = match text {
        Some(text) => {
            serde_json::from_str::<TeamLimits>(&text).map_err(|_| rusqlite::Error::InvalidQuery)?
        }
        None => TeamLimits::default(),
    };
    limits
        .validate()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(TeamRow {
        id: TeamId::parse(&id).ok_or(rusqlite::Error::InvalidQuery)?,
        name: row.get(1)?,
        file_key: SecretString::new(row.get(2)?),
        state: if state == "active" {
            TeamState::Active
        } else {
            TeamState::Suspended
        },
        legacy: row.get::<_, i64>(4)? == 1,
        created_at: to_u(row.get(5)?),
        suspended_at: row.get::<_, Option<i64>>(6)?.map(to_u),
        limits,
    })
}

const TEAM_COLUMNS: &str = "id, name, file_key, state, legacy, created_at, suspended_at, limits";

/// The directory: its file, and the audit writer of the relay.
pub struct Directory {
    pub store: Arc<Store>,
    pub audit: Arc<Audit>,
}

impl Directory {
    /// Creates `relay.db`. Refuses when it exists.
    pub fn create(config: &RelayConfig) -> RelayResult<Self> {
        Self::create_at(&config.directory_path(), &config.master_key)
    }

    /// Creates a directory file at `path` (`migrate` writes it under another name and
    /// renames it last). Refuses when it exists.
    pub fn create_at(path: &std::path::Path, master_key: &SecretString) -> RelayResult<Self> {
        let store = Store::create_at(path, master_key, SCHEMA).map_err(|error| {
            if error.code == codes::CONFLICT {
                RelayError::new(
                    codes::CONFLICT,
                    "The relay already exists. Refusing to create it again.",
                )
            } else {
                error
            }
        })?;
        Ok(Self {
            store: Arc::new(store),
            audit: Audit::new(),
        })
    }

    /// Opens `relay.db` and checks its version.
    pub fn open(config: &RelayConfig) -> RelayResult<Self> {
        let store = Store::open_at(&config.directory_path(), &config.master_key)?;
        match store.user_version()? {
            DIRECTORY_VERSION => {}
            1001 => store.tx(|tx| {
                tx.execute_batch(
                    "ALTER TABLE team ADD COLUMN limits TEXT; PRAGMA user_version = 1002;",
                )
                .map_err(db)
            })?,
            _ => {
                return Err(RelayError::internal(
                    "relay.db is not the directory of a relay, or has an unknown version.",
                ));
            }
        }
        Ok(Self {
            store: Arc::new(store),
            audit: Audit::new(),
        })
    }

    /// Every team, oldest first.
    pub fn teams(&self) -> RelayResult<Vec<TeamRow>> {
        self.store.with(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {TEAM_COLUMNS} FROM team ORDER BY created_at, id"
                ))
                .map_err(db)?;
            let rows = statement.query_map([], team_from_row).map_err(db)?;
            rows.map(|row| row.map_err(db)).collect()
        })
    }

    /// One team by id.
    pub fn team(&self, id: &TeamId) -> RelayResult<Option<TeamRow>> {
        self.store.with(|conn| team_by_id(conn, id))
    }

    /// Sets the state of a team, and writes an operator row.
    pub fn set_state(&self, id: &TeamId, state: TeamState, now: u64) -> RelayResult<()> {
        self.store.tx(|tx| {
            let changed = tx
                .execute(
                    "UPDATE team SET state = ?1, suspended_at = ?2 WHERE id = ?3",
                    params![
                        state.text(),
                        (state == TeamState::Suspended).then_some(to_i(now)),
                        id.as_str()
                    ],
                )
                .map_err(db)?;
            if changed == 0 {
                return Err(RelayError::not_found("team"));
            }
            let action = match state {
                TeamState::Active => "team_resumed",
                TeamState::Suspended => "team_suspended",
            };
            self.audit.write_on(
                tx,
                now,
                OPERATOR_ACTOR,
                action,
                None,
                &serde_json::json!({"team_id": id}),
            )?;
            Ok(())
        })
    }

    /// Removes a team from the directory: its row and the key of its file. The caller
    /// deletes the file.
    pub fn remove(&self, id: &TeamId, now: u64) -> RelayResult<()> {
        self.store.tx(|tx| {
            let changed = tx
                .execute("DELETE FROM team WHERE id = ?1", params![id.as_str()])
                .map_err(db)?;
            if changed == 0 {
                return Err(RelayError::not_found("team"));
            }
            self.audit.write_on(
                tx,
                now,
                OPERATOR_ACTOR,
                "team_deleted",
                None,
                &serde_json::json!({"team_id": id}),
            )?;
            Ok(())
        })
    }

    /// A new one-time team code. Returns the code (shown once) and its expiry.
    pub fn new_team_code(&self, hours: u64, now: u64) -> RelayResult<(SecretString, u64)> {
        if !(1..=MAX_TEAM_CODE_HOURS).contains(&hours) {
            return Err(RelayError::invalid(format!(
                "A team code lives 1 to {MAX_TEAM_CODE_HOURS} hours."
            )));
        }
        let code = new_team_code()?;
        let expires_at = now + hours * 3600;
        self.store.tx(|tx| {
            tx.execute(
                "INSERT INTO team_code (code_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
                params![
                    token_hash(code.expose()).0.as_slice(),
                    to_i(now),
                    to_i(expires_at)
                ],
            )
            .map_err(db)?;
            let id = to_u(tx.last_insert_rowid());
            self.audit.write_on(
                tx,
                now,
                OPERATOR_ACTOR,
                "team_code_created",
                None,
                &serde_json::json!({"code_id": id, "expires_at": expires_at}),
            )?;
            Ok(())
        })?;
        Ok((code, expires_at))
    }
}

/// One team by id, on a connection.
pub fn team_by_id(conn: &Connection, id: &TeamId) -> RelayResult<Option<TeamRow>> {
    conn.query_row(
        &format!("SELECT {TEAM_COLUMNS} FROM team WHERE id = ?1"),
        params![id.as_str()],
        team_from_row,
    )
    .optional()
    .map_err(db)
}

/// The error for a team code that is wrong, used, or expired. One message for all.
pub fn team_code_invalid() -> RelayError {
    RelayError::new(
        codes::INVITE_INVALID,
        "The team code is not valid, was used, or expired.",
    )
}

/// The id of a live team code, inside a transaction. Refuses a wrong, used, or expired
/// code. Check it before any work for a new team.
pub fn find_team_code(conn: &Connection, code: &str, now: u64) -> RelayResult<u64> {
    if parse_token(code).is_none_or(|parsed| parsed.kind != TokenKind::TeamCode) {
        return Err(team_code_invalid());
    }
    conn.query_row(
        "SELECT id FROM team_code WHERE code_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
        params![token_hash(code).0.as_slice(), to_i(now)],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(db)?
    .map(to_u)
    .ok_or_else(team_code_invalid)
}

/// Marks a team code used for `team`, inside the transaction of `find_team_code`.
pub fn mark_team_code_used(conn: &Connection, id: u64, team: &TeamId, now: u64) -> RelayResult<()> {
    conn.execute(
        "UPDATE team_code SET used_at = ?1, team_id = ?2 WHERE id = ?3 AND used_at IS NULL",
        params![to_i(now), team.as_str(), to_i(id)],
    )
    .map_err(db)
    .and_then(|changed| {
        if changed == 1 {
            Ok(())
        } else {
            Err(team_code_invalid())
        }
    })
}

/// Adds a team row, inside a transaction.
pub fn insert_team(
    conn: &Connection,
    id: &TeamId,
    name: &str,
    file_key: &SecretString,
    legacy: bool,
    now: u64,
) -> RelayResult<()> {
    conn.execute(
        "INSERT INTO team (id, name, file_key, state, legacy, created_at) VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        params![id.as_str(), name, file_key.expose(), i64::from(legacy), to_i(now)],
    )
    .map_err(db)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> RelayConfig {
        RelayConfig::from_lookup(|name| match name {
            "APASSY_RELAY_DATA" => Some(dir.to_string_lossy().into_owned()),
            "APASSY_RELAY_PUBLIC_URL" => Some("https://relay.example.test".to_string()),
            "APASSY_RELAY_EDGE_SECRET" => Some("test-edge-secret-32-bytes-minimum".to_string()),
            "APASSY_RELAY_KEY" => Some("test-master-key-16-bytes-minimum".to_string()),
            _ => None,
        })
        .unwrap()
    }

    #[test]
    fn limits_defaults_partial_json_and_validation() {
        let defaults = TeamLimits::default();
        assert_eq!(
            serde_json::to_value(defaults).unwrap(),
            serde_json::json!({
                "members": 50, "items": 500, "agents": 100,
                "runs_per_hour": 1000, "pending_runs": 50, "agent_requests": 56,
                "sync_bytes": 67108864, "sync_pushes_per_hour": 600, "sync_transfers": 2,
                "open_questions": 20, "questions_per_hour": 300,
            })
        );
        assert_eq!(serde_json::from_str::<TeamLimits>("{}").unwrap(), defaults);
        let partial: TeamLimits = serde_json::from_str(r#"{"members":7}"#).unwrap();
        assert_eq!(partial.members, 7);
        assert_eq!(partial.items, defaults.items);
        let update: TeamLimitsUpdate = serde_json::from_str(r#"{"agent_requests":224}"#).unwrap();
        assert_eq!(defaults.apply(update).unwrap().agent_requests, 224);
        assert_eq!(
            serde_json::to_string(&update).unwrap(),
            r#"{"agent_requests":224}"#
        );
        assert!(serde_json::from_str::<TeamLimitsUpdate>(r#"{"unknown":1}"#).is_err());
        assert!(serde_json::from_str::<TeamLimitsUpdate>(r#"{"members":-1}"#).is_err());
        assert!(serde_json::from_str::<TeamLimitsUpdate>(r#"{"members":1.5}"#).is_err());
        for field in [
            "members",
            "items",
            "agents",
            "runs_per_hour",
            "pending_runs",
        ] {
            for value in [0, 1_000_001] {
                let update =
                    serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: value}))
                        .unwrap();
                assert!(defaults.apply(update).is_err(), "{field}={value}");
            }
            for value in [1, 1_000_000] {
                let update =
                    serde_json::from_value::<TeamLimitsUpdate>(serde_json::json!({field: value}))
                        .unwrap();
                assert!(defaults.apply(update).is_ok(), "{field}={value}");
            }
        }
        for value in [0, 225] {
            assert!(
                defaults
                    .apply(TeamLimitsUpdate {
                        agent_requests: Some(value),
                        ..Default::default()
                    })
                    .is_err()
            );
        }
        let questions = |open: u64, per_hour: u64| {
            defaults.apply(TeamLimitsUpdate {
                open_questions: Some(open),
                questions_per_hour: Some(per_hour),
                ..Default::default()
            })
        };
        assert!(questions(1, 1).is_ok());
        assert!(questions(1000, 1_000_000).is_ok());
        assert!(questions(0, 300).is_err());
        assert!(questions(1001, 300).is_err());
        assert!(questions(20, 0).is_err());
        assert!(questions(20, 1_000_001).is_err());
        // A stored row from before questions reads the question defaults.
        let old: TeamLimits = serde_json::from_str(r#"{"members":7,"sync_transfers":3}"#).unwrap();
        assert_eq!((old.open_questions, old.questions_per_hour), (20, 300));
    }

    #[test]
    fn directory_migrates_1001_and_defaults_null_or_partial_limits() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let old_schema = SCHEMA
            .replace(", limits TEXT", "")
            .replace("user_version = 1002", "user_version = 1001");
        let store =
            Store::create_at(&config.directory_path(), &config.master_key, &old_schema).unwrap();
        let id = TeamId::parse("t_abcdefgh23").unwrap();
        let key = SecretString::new("test-team-file-key".to_string());
        store
            .with(|conn| insert_team(conn, &id, "Team", &key, false, 42))
            .unwrap();
        drop(store);

        let directory = Directory::open(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        let row = directory.team(&id).unwrap().unwrap();
        assert_eq!(row.name, "Team");
        assert_eq!(row.created_at, 42);
        assert_eq!(row.file_key, key);
        assert_eq!(row.limits, TeamLimits::default());
        directory
            .store
            .with(|conn| {
                conn.execute("UPDATE team SET limits = ?1", [r#"{"members":7}"#])
                    .map_err(db)?;
                Ok(())
            })
            .unwrap();
        let row = directory.team(&id).unwrap().unwrap();
        assert_eq!(row.limits.members, 7);
        assert_eq!(row.limits.items, 500);
        drop(directory);
        assert_eq!(
            Directory::open(&config)
                .unwrap()
                .team(&id)
                .unwrap()
                .unwrap()
                .limits
                .members,
            7
        );
    }

    #[test]
    fn new_directory_uses_1002_and_refuses_unknown_versions() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let directory = Directory::create(&config).unwrap();
        assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
        directory
            .store
            .with(|conn| conn.pragma_update(None, "user_version", 1003).map_err(db))
            .unwrap();
        drop(directory);
        assert!(Directory::open(&config).is_err());
        assert_eq!(
            Store::open_at(&config.directory_path(), &config.master_key)
                .unwrap()
                .user_version()
                .unwrap(),
            1003
        );
    }

    #[test]
    fn failed_migration_does_not_advance_version() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let directory = Directory::create(&config).unwrap();
        directory
            .store
            .with(|conn| conn.pragma_update(None, "user_version", 1001).map_err(db))
            .unwrap();
        drop(directory);
        assert!(Directory::open(&config).is_err());
        assert_eq!(
            Store::open_at(&config.directory_path(), &config.master_key)
                .unwrap()
                .user_version()
                .unwrap(),
            1001
        );
    }
}
