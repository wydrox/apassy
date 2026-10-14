//! `apassy-relay rollback-check` (docs/OPERATIONS.md section 21.3, docs/SPEC.md section
//! 27.15): what a rollback to the schema 5 image would undo.
//!
//! The rollback copies each `teams/<id>.db.pre-v6` back over its team file. That copy is
//! the team as it was at the migration, so every change of access since then comes back
//! undone: a revoked device signs in again, a revoked member's or agent's token works
//! again, a revoked grant gives access again, a revoked invite can be used, a member
//! token ended at a device enrollment works again, a demoted member gets its old role, a
//! collection gets its old policy, and the key holder moves back. And the audit rows
//! written since then, the ones that recorded those changes, are gone. This command
//! compares each team file with its `.pre-v6` copy, names each such change by kind and
//! id, and counts the audit rows that the copy lacks, by action.
//!
//! It runs without the relay: it reads `relay.db` with the master key and each file with
//! its key, all read-only, so it works with the relay up (`docker compose exec`) or down
//! (`docker compose run`), and it takes no lock. It names kinds, ids, times, and audit
//! action names, never a name, a token, a policy, or an audit detail.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Serialize;

use crate::api::TeamKind;
use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult};
use crate::ids::TeamId;
use crate::server::directory::{self, DIRECTORY_VERSION, TeamRow, TeamState};
use crate::server::store::{Store, db, to_u};

/// The tables whose rows a revocation marks with `revoked_at`, and the kind each is named
/// by in the answer.
const REVOCABLE: [(&str, &str); 5] = [
    ("device", "device"),
    ("member", "member"),
    ("agent", "agent"),
    ("access_grant", "grant"),
    ("invite", "invite"),
];

/// The other changes of access that a rollback undoes: the kind, the table, a column
/// (as text), and whether only a change to `1` counts (a member token that ended). Rows
/// that only one of the two files has are left out: a row made after the copy goes with
/// the rollback.
const CHANGED: [(&str, &str, &str, bool); 4] = [
    ("member_role", "member", "role", false),
    ("member_token", "member", "token_hash IS NULL", true),
    ("collection_policy", "collection", "policy", false),
    ("key_holder", "device", "key_holder", false),
];

/// One revocation that a rollback would undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revocation {
    /// `device`, `member`, `agent`, `grant`, or `invite`.
    pub kind: &'static str,
    /// The id of the row in the team file (the same in the `.pre-v6` copy).
    pub id: u64,
    pub revoked_at: u64,
}

/// One other change of access that a rollback would undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// `member_role` (a member's role changed), `member_token` (a member token ended at a
    /// device enrollment), `collection_policy` (a policy changed), or `key_holder` (the
    /// device's key-holder flag changed).
    pub kind: &'static str,
    pub id: u64,
}

/// What a rollback to schema 5 does to one team.
#[derive(Debug, Serialize)]
pub struct TeamRollback {
    pub team: TeamId,
    pub kind: TeamKind,
    pub state: TeamState,
    /// The schema version of the team file now, when it could be read.
    pub schema: Option<i64>,
    /// Whether `teams/<id>.db.pre-v6` exists. Without it a version 6 file was made after
    /// the migration (the old image cannot open it), and a version 5 file was never
    /// migrated (the rollback leaves it as it is).
    pub pre_v6: bool,
    /// The revocations since the migration that the copy would undo, oldest first.
    pub revocations: Vec<Revocation>,
    /// The other changes of access since the migration that the copy would undo.
    pub changes: Vec<Change>,
    /// The audit rows of the file that the copy lacks: they go with the rollback.
    pub audit_rows_lost: u64,
    /// The same rows by audit action.
    pub audit_lost: BTreeMap<String, u64>,
    /// Why the team could not be read, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TeamRollback {
    /// True when a rollback undoes nothing of this team but its feeds: it has a copy and
    /// nothing in `revocations` or `changes`, or it is a version 5 file left as it is.
    pub fn clean(&self) -> bool {
        self.error.is_none()
            && self.revocations.is_empty()
            && self.changes.is_empty()
            && (self.pre_v6 || self.schema == Some(5))
    }
}

/// `<team file>.pre-v6`.
fn pre_v6_path(file: &Path) -> PathBuf {
    let mut path = file.as_os_str().to_os_string();
    path.push(".pre-v6");
    PathBuf::from(path)
}

fn ids(conn: &Connection, sql: &str) -> RelayResult<Vec<u64>> {
    let mut statement = conn.prepare(sql).map_err(db)?;
    statement
        .query_map([], |row| row.get::<_, i64>(0).map(to_u))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)
}

/// `column` of each row of `table`, as text, by id.
fn column(conn: &Connection, table: &str, column: &str) -> RelayResult<BTreeMap<u64, String>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT id, coalesce(CAST({column} AS TEXT), '') FROM {table}"
        ))
        .map_err(db)?;
    statement
        .query_map([], |row| Ok((to_u(row.get::<_, i64>(0)?), row.get(1)?)))
        .map_err(db)?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .map_err(db)
}

/// The revoked rows of `table`: id and time.
fn revoked_rows(conn: &Connection, table: &str) -> RelayResult<Vec<(u64, u64)>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT id, revoked_at FROM {table} WHERE revoked_at IS NOT NULL ORDER BY revoked_at, id"
        ))
        .map_err(db)?;
    statement
        .query_map([], |row| {
            Ok((to_u(row.get::<_, i64>(0)?), to_u(row.get::<_, i64>(1)?)))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)
}

/// What a comparison found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub revocations: Vec<Revocation>,
    pub changes: Vec<Change>,
    pub audit_lost: BTreeMap<String, u64>,
}

/// Compares the file (`now`) with its copy (`pre`): the revocations of rows that are
/// live in the copy, the other changes of access, and the audit rows after the copy's
/// last one, by action.
pub fn compare(now: &Connection, pre: &Connection) -> RelayResult<Found> {
    let mut found = Found::default();
    for (table, kind) in REVOCABLE {
        let live = ids(
            pre,
            &format!("SELECT id FROM {table} WHERE revoked_at IS NULL"),
        )?;
        for (id, revoked_at) in revoked_rows(now, table)? {
            if live.contains(&id) {
                found.revocations.push(Revocation {
                    kind,
                    id,
                    revoked_at,
                });
            }
        }
    }
    found
        .revocations
        .sort_by_key(|revocation| (revocation.revoked_at, revocation.kind, revocation.id));
    for (kind, table, expr, to_one) in CHANGED {
        let before = column(pre, table, expr)?;
        for (id, value) in column(now, table, expr)? {
            let Some(old) = before.get(&id) else {
                continue;
            };
            let changed = if to_one {
                value == "1" && old == "0"
            } else {
                value != *old
            };
            if changed {
                found.changes.push(Change { kind, id });
            }
        }
    }
    let after: i64 = pre
        .query_row("SELECT coalesce(max(id), 0) FROM audit", [], |row| {
            row.get(0)
        })
        .map_err(db)?;
    let mut statement = now
        .prepare("SELECT action, count(*) FROM audit WHERE id > ?1 GROUP BY action")
        .map_err(db)?;
    let rows = statement
        .query_map([after], |row| {
            Ok((row.get::<_, String>(0)?, to_u(row.get(1)?)))
        })
        .map_err(db)?;
    for row in rows {
        let (action, count) = row.map_err(db)?;
        found.audit_lost.insert(action, count);
    }
    Ok(found)
}

/// The answer for one team of the directory: both files read-only, the copy attached to
/// the file's connection with its key.
fn check_team(config: &RelayConfig, row: &TeamRow) -> TeamRollback {
    let mut answer = TeamRollback {
        team: row.id.clone(),
        kind: row.kind,
        state: row.state,
        schema: None,
        pre_v6: false,
        revocations: Vec::new(),
        changes: Vec::new(),
        audit_rows_lost: 0,
        audit_lost: BTreeMap::new(),
        error: None,
    };
    let file = config.team_path(&row.id);
    let pre = pre_v6_path(&file);
    answer.pre_v6 = std::fs::symlink_metadata(&pre).is_ok_and(|meta| meta.is_file());
    let result = (|| -> RelayResult<()> {
        let store = Store::open_read_only(&file, &row.file_key)?;
        answer.schema = Some(store.user_version()?);
        if !answer.pre_v6 {
            return Ok(());
        }
        let copy = Store::open_read_only(&pre, &row.file_key)?;
        let found = copy.with(|pre| store.with(|now| compare(now, pre)))?;
        answer.audit_rows_lost = found.audit_lost.values().sum();
        answer.revocations = found.revocations;
        answer.changes = found.changes;
        answer.audit_lost = found.audit_lost;
        Ok(())
    })();
    if let Err(error) = result {
        answer.error = Some(error.message);
    }
    answer
}

/// The teams of `relay.db`, read-only with the master key.
fn directory_teams(config: &RelayConfig) -> RelayResult<Vec<TeamRow>> {
    let store = Store::open_read_only(&config.directory_path(), &config.master_key)?;
    if store.user_version()? != DIRECTORY_VERSION {
        return Err(RelayError::internal(
            "relay.db is not the directory of this relay version (1003).",
        ));
    }
    store.with(directory::read_teams)
}

/// `apassy-relay rollback-check`: every team of the directory, active or suspended. Each
/// file key is derived once per file (PBKDF2), so the teams are read on up to 8 threads,
/// no more than the cores.
pub fn check(config: &RelayConfig) -> RelayResult<Vec<TeamRollback>> {
    let rows = directory_teams(config)?;
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .clamp(1, 8);
    let chunk = rows.len().div_ceil(threads).max(1);
    let mut answers: Vec<TeamRollback> = std::thread::scope(|scope| {
        let parts: Vec<_> = rows
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .map(|row| check_team(config, row))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        parts
            .into_iter()
            .flat_map(|part| part.join().unwrap_or_default())
            .collect()
    });
    // The order of the directory: oldest team first.
    answers.sort_by_key(|answer| {
        rows.iter()
            .position(|row| row.id == answer.team)
            .unwrap_or(usize::MAX)
    });
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tables and columns that `compare` reads.
    fn file(rows: &str) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE device (id INTEGER PRIMARY KEY, key_holder INTEGER NOT NULL DEFAULT 0,
               revoked_at INTEGER);
             CREATE TABLE member (id INTEGER PRIMARY KEY, role TEXT NOT NULL DEFAULT 'member',
               token_hash BLOB, revoked_at INTEGER);
             CREATE TABLE agent (id INTEGER PRIMARY KEY, revoked_at INTEGER);
             CREATE TABLE access_grant (id INTEGER PRIMARY KEY, revoked_at INTEGER);
             CREATE TABLE invite (id INTEGER PRIMARY KEY, revoked_at INTEGER);
             CREATE TABLE collection (id INTEGER PRIMARY KEY, policy TEXT NOT NULL);
             CREATE TABLE audit (id INTEGER PRIMARY KEY, action TEXT NOT NULL);",
        )
        .unwrap();
        conn.execute_batch(rows).unwrap();
        conn
    }

    #[test]
    fn a_rollback_undoes_each_change_of_access_since_the_copy() {
        let base = "INSERT INTO device (id, key_holder, revoked_at) VALUES (1, 1, NULL), (2, 0, NULL), (3, 0, 50);
            INSERT INTO member (id, role, token_hash, revoked_at) VALUES
              (1, 'owner', x'01', NULL), (2, 'manager', NULL, NULL), (3, 'member', x'03', NULL);
            INSERT INTO agent VALUES (4, NULL), (5, NULL);
            INSERT INTO access_grant VALUES (6, NULL);
            INSERT INTO invite VALUES (7, NULL), (8, 60);
            INSERT INTO collection VALUES (1, '{\"mode\":\"open\"}');
            INSERT INTO audit VALUES (1, 'a'), (2, 'b');";
        let pre = file(base);
        let now = file(&format!(
            "{base}
            UPDATE device SET revoked_at = 300 WHERE id = 2;
            UPDATE member SET revoked_at = 200 WHERE id = 3;
            UPDATE agent SET revoked_at = 100 WHERE id = 5;
            UPDATE access_grant SET revoked_at = 300 WHERE id = 6;
            UPDATE invite SET revoked_at = 400 WHERE id = 7;
            UPDATE member SET role = 'member' WHERE id = 2;
            UPDATE member SET token_hash = NULL WHERE id = 1;
            UPDATE collection SET policy = '{{\"mode\":\"approve\"}}' WHERE id = 1;
            UPDATE device SET key_holder = 0 WHERE id = 1;
            INSERT INTO device (id, key_holder, revoked_at) VALUES (9, 1, 500);
            INSERT INTO member (id, role) VALUES (10, 'owner');
            INSERT INTO audit VALUES (3, 'device_revoked'), (4, 'member_revoked'), (5, 'device_revoked');"
        ));
        let found = compare(&now, &pre).unwrap();
        let named: Vec<(&str, u64, u64)> = found
            .revocations
            .iter()
            .map(|r| (r.kind, r.id, r.revoked_at))
            .collect();
        // Oldest first. Device 3 and invite 8 were revoked before the copy, and device 9
        // was made after it: the rollback does not bring those back.
        assert_eq!(
            named,
            vec![
                ("agent", 5, 100),
                ("member", 3, 200),
                ("device", 2, 300),
                ("grant", 6, 300),
                ("invite", 7, 400),
            ]
        );
        // The demotion, the ended member token, the policy, and the key holder; member
        // 10 was made after the copy.
        let changes: Vec<(&str, u64)> = found.changes.iter().map(|c| (c.kind, c.id)).collect();
        assert_eq!(
            changes,
            vec![
                ("member_role", 2),
                ("member_token", 1),
                ("collection_policy", 1),
                ("key_holder", 1),
            ]
        );
        assert_eq!(
            found.audit_lost,
            BTreeMap::from([
                ("device_revoked".to_string(), 2),
                ("member_revoked".to_string(), 1)
            ])
        );
        // Nothing since the copy: nothing to undo.
        assert_eq!(compare(&pre, &pre).unwrap(), Found::default());
    }

    #[test]
    fn a_team_is_clean_with_its_copy_and_nothing_to_undo_or_as_an_untouched_version_5() {
        let team = |schema, pre_v6| TeamRollback {
            team: TeamId::parse("t_abcdefgh23").unwrap(),
            kind: TeamKind::Connect,
            state: TeamState::Active,
            schema,
            pre_v6,
            revocations: Vec::new(),
            changes: Vec::new(),
            audit_rows_lost: 4,
            audit_lost: BTreeMap::new(),
            error: None,
        };
        assert!(team(Some(6), true).clean());
        assert!(team(Some(5), false).clean());
        // Made after the migration: the old image cannot open it.
        assert!(!team(Some(6), false).clean());
        let mut revoked = team(Some(6), true);
        revoked.revocations.push(Revocation {
            kind: "device",
            id: 2,
            revoked_at: 9,
        });
        assert!(!revoked.clean());
        let mut changed = team(Some(6), true);
        changed.changes.push(Change {
            kind: "member_role",
            id: 2,
        });
        assert!(!changed.clean());
        let mut unread = team(None, true);
        unread.error = Some("The vault key is wrong.".to_string());
        assert!(!unread.clean());
    }
}
