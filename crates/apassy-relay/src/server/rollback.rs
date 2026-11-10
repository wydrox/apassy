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
//! (`docker compose run`). It does not take `relay.lock`, but its reads take SQLite's
//! shared locks for a moment, and a write of the relay waits for them (up to 5 s). It
//! names kinds, ids, times, and audit action names, never a name, a token, a policy, or
//! an audit detail.

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
const CHANGED: [(&str, &str, &str, bool); 7] = [
    ("member_role", "member", "role", false),
    ("member_token", "member", "token_hash IS NULL", true),
    ("collection_policy", "collection", "policy", false),
    ("key_holder", "device", "key_holder", false),
    // An archived item (a credential deleted or rotated out) is live again for the
    // agents of its grants.
    ("item_archived", "item", "archived_at IS NOT NULL", true),
    // A used invite can be used again.
    ("invite_used", "invite", "used_at IS NOT NULL", true),
    // An agent bound to a device since then is unbound again: a later revocation of
    // the device no longer revokes it.
    ("agent_device", "agent", "device_id IS NOT NULL", true),
];

/// Audit actions that record a change of access. A team that lost any of these rows is
/// not clean even when the comparison found nothing (a row made and changed after the
/// copy, or a change this module does not compare): the operator looks at it.
const ACCESS_ACTIONS: [&str; 10] = [
    "device_revoked",
    "member_revoked",
    "agent_revoked",
    "grant_revoked",
    "member_role_changed",
    "policy_changed",
    "item_archived",
    "key_holder_moved",
    "key_holder_claimed",
    "member_enrolled",
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
    /// The actions of `audit_lost` that record a change of access (`ACCESS_ACTIONS`).
    pub access_rows_lost: Vec<String>,
    /// The team's limits in `relay.db` hold `feed_bytes` or `feed_actions_per_hour`
    /// (a value away from the preset): the schema 5 image refuses the whole directory.
    pub feed_limits_stored: bool,
    /// `TeamRollback::is_clean`.
    pub clean: bool,
    /// Why the team could not be read, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TeamRollback {
    /// True when a rollback undoes nothing of this team but its feeds and its other new
    /// rows: the file could be read, nothing is in `revocations`, `changes`, or
    /// `access_rows_lost`, no feed limit is stored, and the team has a copy or is a file
    /// below version 6 that the migration never touched (a team suspended through it).
    pub fn is_clean(&self) -> bool {
        self.error.is_none()
            && self.revocations.is_empty()
            && self.changes.is_empty()
            && self.access_rows_lost.is_empty()
            && !self.feed_limits_stored
            && (self.pre_v6 || self.schema.is_some_and(|schema| schema < 6))
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
        access_rows_lost: Vec::new(),
        feed_limits_stored: false,
        clean: false,
        error: None,
    };
    match row.limits.stored_json(row.kind) {
        Ok(text) => answer.feed_limits_stored = text.contains("\"feed_"),
        Err(error) => answer.error = Some(error.message),
    }
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
        answer.access_rows_lost = found
            .audit_lost
            .keys()
            .filter(|action| ACCESS_ACTIONS.contains(&action.as_str()))
            .cloned()
            .collect();
        answer.audit_lost = found.audit_lost;
        Ok(())
    })();
    if let Err(error) = result {
        answer.error = Some(error.message);
    }
    answer.clean = answer.is_clean();
    answer
}

/// The answer for a team whose reading thread ended without one.
fn unread(row: &TeamRow) -> TeamRollback {
    TeamRollback {
        team: row.id.clone(),
        kind: row.kind,
        state: row.state,
        schema: None,
        pre_v6: false,
        revocations: Vec::new(),
        changes: Vec::new(),
        audit_rows_lost: 0,
        audit_lost: BTreeMap::new(),
        access_rows_lost: Vec::new(),
        feed_limits_stored: false,
        clean: false,
        error: Some("The check of this team stopped before its end.".to_string()),
    }
}

/// The teams of `relay.db`, read-only with the master key.
fn directory_teams(config: &RelayConfig) -> RelayResult<Vec<TeamRow>> {
    let store = Store::open_read_only(&config.directory_path(), &config.master_key)?;
    if store.user_version()? != DIRECTORY_VERSION {
        return Err(RelayError::internal(format!(
            "relay.db is not the directory of this relay version ({DIRECTORY_VERSION})."
        )));
    }
    store.with(directory::read_teams)
}

/// `apassy-relay rollback-check`: every team of the directory, active or suspended. Each
/// file key is derived once per file (PBKDF2), so the teams are read on up to 8 threads,
/// no more than the cores.
pub fn check(config: &RelayConfig) -> RelayResult<Vec<TeamRollback>> {
    // A rollback to schema 5 compares keyed files with their `.pre-v6` copies; a relay in
    // `connect` mode has plain files and no such copies (docs/SPEC.md section 37).
    config.refuse_connect_mode("`apassy-relay rollback-check`")?;
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
        // A thread that panicked leaves no answer: each of its teams gets an error, so
        // the check is not clean.
        parts
            .into_iter()
            .zip(rows.chunks(chunk))
            .flat_map(|(part, part_rows)| {
                part.join()
                    .unwrap_or_else(|_| part_rows.iter().map(unread).collect())
            })
            .collect()
    });
    if answers.len() != rows.len() {
        return Err(RelayError::internal(
            "The check did not read every team of the directory.",
        ));
    }
    // The order of the directory: oldest team first.
    answers.sort_by_key(|answer| {
        rows.iter()
            .position(|row| row.id == answer.team)
            .unwrap_or(usize::MAX)
    });
    Ok(answers)
}

/// What `downgrade-schema-6` or `downgrade-schema-7` did to one team file.
#[derive(Debug, Serialize)]
pub struct Downgraded {
    pub team: TeamId,
    /// The schema version of the file before, when it could be read.
    pub from: Option<i64>,
    /// The schema version of the file after: the target when it was above it, else as it
    /// was.
    pub to: Option<i64>,
    /// The agents with an item list that were revoked (`Store::downgrade_to_v6`).
    pub agents_revoked: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `apassy-relay downgrade-schema-6` (docs/OPERATIONS.md section 23.3): with the relay
/// stopped (it takes `relay.lock`), every team file of version 7 or 8 goes back to
/// version 6 in place, for the image of schema 6. Each agent with an item list is
/// revoked, since that image would give it every item of its member's grants. A file of
/// another version is left as it is. One team that fails does not stop the others: its
/// `error` says why.
pub fn downgrade_to_6(config: &RelayConfig) -> RelayResult<Vec<Downgraded>> {
    config.refuse_connect_mode("`apassy-relay downgrade-schema-6`")?;
    downgrade_each(config, |store, now| {
        if matches!(store.user_version()?, 7 | 8) {
            return store.downgrade_to_v6(now);
        }
        Ok(0)
    })
}

/// `apassy-relay downgrade-schema-7` (docs/OPERATIONS.md section 25.2): with the relay
/// stopped (it takes `relay.lock`), every team file of version 8 goes back to version 7
/// in place, for the image of schema 7. Only the version changes: the push handles stay
/// for the next start of schema 8 (`Store::downgrade_to_v7`). A file of another version
/// is left as it is. One team that fails does not stop the others.
pub fn downgrade_to_7(config: &RelayConfig) -> RelayResult<Vec<Downgraded>> {
    config.refuse_connect_mode("`apassy-relay downgrade-schema-7`")?;
    downgrade_each(config, |store, _| {
        if store.user_version()? == 8 {
            store.downgrade_to_v7()?;
        }
        Ok(0)
    })
}

/// Runs `step` on the file of every team of the directory, with the relay stopped.
/// `step` returns the agents it revoked.
fn downgrade_each(
    config: &RelayConfig,
    step: impl Fn(&Store, u64) -> RelayResult<u64>,
) -> RelayResult<Vec<Downgraded>> {
    let _lock = crate::server::hub::lock_data_dir(config)?;
    let rows = directory::Directory::open(config)?.teams()?;
    let now = crate::now_unix();
    Ok(rows
        .iter()
        .map(|row| {
            let mut answer = Downgraded {
                team: row.id.clone(),
                from: None,
                to: None,
                agents_revoked: 0,
                error: None,
            };
            let result = (|| -> RelayResult<()> {
                let store = Store::open_at(&config.team_path(&row.id), &row.file_key)?;
                answer.from = Some(store.user_version()?);
                answer.agents_revoked = step(&store, now)?;
                answer.to = Some(store.user_version()?);
                Ok(())
            })();
            if let Err(error) = result {
                answer.error = Some(error.message);
            }
            answer
        })
        .collect())
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
             CREATE TABLE agent (id INTEGER PRIMARY KEY, device_id INTEGER, revoked_at INTEGER);
             CREATE TABLE access_grant (id INTEGER PRIMARY KEY, revoked_at INTEGER);
             CREATE TABLE invite (id INTEGER PRIMARY KEY, used_at INTEGER, revoked_at INTEGER);
             CREATE TABLE collection (id INTEGER PRIMARY KEY, policy TEXT NOT NULL);
             CREATE TABLE item (id INTEGER PRIMARY KEY, archived_at INTEGER);
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
            INSERT INTO agent (id, device_id, revoked_at) VALUES (4, NULL, NULL), (5, NULL, NULL), (6, 1, NULL);
            INSERT INTO access_grant VALUES (6, NULL);
            INSERT INTO invite (id, used_at, revoked_at) VALUES (7, NULL, NULL), (8, NULL, 60), (9, NULL, NULL);
            INSERT INTO collection VALUES (1, '{\"mode\":\"open\"}');
            INSERT INTO item VALUES (1, NULL), (2, 40);
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
            UPDATE item SET archived_at = 500 WHERE id = 1;
            UPDATE invite SET used_at = 500 WHERE id = 9;
            UPDATE agent SET device_id = 1 WHERE id = 4;
            INSERT INTO device (id, key_holder, revoked_at) VALUES (9, 1, 500);
            INSERT INTO member (id, role) VALUES (10, 'owner');
            INSERT INTO item VALUES (3, 600);
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
        // The demotion, the ended member token, the policy, the key holder, the archived
        // item, the used invite, and the agent bound to a device; member 10 and item 3
        // were made after the copy, and item 2 was archived before it.
        let changes: Vec<(&str, u64)> = found.changes.iter().map(|c| (c.kind, c.id)).collect();
        assert_eq!(
            changes,
            vec![
                ("member_role", 2),
                ("member_token", 1),
                ("collection_policy", 1),
                ("key_holder", 1),
                ("item_archived", 1),
                ("invite_used", 9),
                ("agent_device", 4),
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
    fn a_team_is_clean_only_when_a_rollback_undoes_no_access() {
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
            access_rows_lost: Vec::new(),
            feed_limits_stored: false,
            clean: false,
            error: None,
        };
        assert!(team(Some(6), true).is_clean());
        // Below version 6 without a copy: suspended through the migration, left as is.
        assert!(team(Some(5), false).is_clean());
        assert!(team(Some(4), false).is_clean());
        // Made after the migration: the old image cannot open it.
        assert!(!team(Some(6), false).is_clean());
        let mut revoked = team(Some(6), true);
        revoked.revocations.push(Revocation {
            kind: "device",
            id: 2,
            revoked_at: 9,
        });
        assert!(!revoked.is_clean());
        let mut changed = team(Some(6), true);
        changed.changes.push(Change {
            kind: "member_role",
            id: 2,
        });
        assert!(!changed.is_clean());
        let mut lost = team(Some(6), true);
        lost.access_rows_lost.push("item_archived".to_string());
        assert!(!lost.is_clean());
        let mut stored = team(Some(6), true);
        stored.feed_limits_stored = true;
        assert!(!stored.is_clean());
        let mut unread = team(None, true);
        unread.error = Some("The vault key is wrong.".to_string());
        assert!(!unread.is_clean());
        assert!(!unread_answer().is_clean());
    }

    fn unread_answer() -> TeamRollback {
        let row = TeamRow {
            id: TeamId::parse("t_abcdefgh23").unwrap(),
            name: "T".to_string(),
            file_key: crate::secret::SecretString::new("k".to_string()),
            state: TeamState::Active,
            legacy: false,
            created_at: 0,
            suspended_at: None,
            limits: crate::server::directory::TeamLimits::default(),
            kind: TeamKind::Operator,
            suspend_reason: None,
            account_id: None,
            vault_id: None,
        };
        unread(&row)
    }
}
