//! The directory of the relay: `relay.db` (ADR 0019, docs/SPEC.md "Teams").
//!
//! One SQLCipher file, keyed with the master key. It holds the teams (public id, name,
//! state, and the random key of each team file), the one-time team codes of the
//! operator, and the audit of the relay: operator actions, and refused requests that
//! name no known team. It holds no people, no items, and no runs: those are in the
//! file of each team.

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::secret::{SecretString, TokenKind, new_team_code, parse_token, token_hash};
use crate::server::audit::Audit;
use crate::server::store::{Store, db, to_i, to_u};

/// `PRAGMA user_version` of the directory. Far from the team versions, so one file is
/// never taken for the other.
pub const DIRECTORY_VERSION: i64 = 1001;

const SCHEMA: &str = "
CREATE TABLE team (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, file_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','suspended')),
  legacy INTEGER NOT NULL DEFAULT 0 CHECK (legacy IN (0, 1)),
  created_at INTEGER NOT NULL, suspended_at INTEGER);
CREATE UNIQUE INDEX team_legacy ON team(legacy) WHERE legacy = 1;
CREATE TABLE team_code (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, team_id TEXT);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);
PRAGMA user_version = 1001;
";

/// The actor of an operator action, in the directory and in the team's own audit.
pub const OPERATOR_ACTOR: &str = "operator";

/// The longest life of a team code, in hours.
pub const MAX_TEAM_CODE_HOURS: u64 = 720;

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
}

fn team_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamRow> {
    let id: String = row.get(0)?;
    let state: String = row.get(3)?;
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
    })
}

const TEAM_COLUMNS: &str = "id, name, file_key, state, legacy, created_at, suspended_at";

/// The directory: its file, and the audit writer of the relay.
pub struct Directory {
    pub store: Arc<Store>,
    pub audit: Arc<Audit>,
}

impl Directory {
    /// Creates `relay.db`. Refuses when it exists.
    pub fn create(config: &RelayConfig) -> RelayResult<Self> {
        let store = Store::create_at(&config.directory_path(), &config.master_key, SCHEMA)
            .map_err(|error| {
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
        if store.user_version()? != DIRECTORY_VERSION {
            return Err(RelayError::internal(
                "relay.db is not the directory of a relay, or has an unknown version.",
            ));
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
