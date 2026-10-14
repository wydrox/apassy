//! `admin rollback-check` (docs/OPERATIONS.md section 21.3, docs/SPEC.md section 27.10):
//! what a rollback to the schema 5 image would undo, read with the new image still up.
//!
//! The rollback copies each `teams/<id>.db.pre-v6` back over its team file. That copy is
//! the team as it was at the migration, so every revocation made since then comes back
//! undone: a revoked device signs in again, a revoked member's or agent's token works
//! again, a revoked grant gives access again, a revoked invite can be used. And the audit
//! rows written since then, the ones that recorded those revocations, are gone. This
//! command compares each team file with its `.pre-v6` copy and names, by kind and id,
//! each device, member, agent token, access grant, and invite that is revoked in the
//! file and live in the copy, with the time of its revocation, and counts the audit rows
//! that the copy lacks. It reads only: both files are opened read-only, or through the
//! team's open connection. It names ids and times, never a name, a token, or an audit row.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Serialize;

use crate::api::TeamKind;
use crate::error::RelayResult;
use crate::ids::TeamId;
use crate::server::directory::{TeamRow, TeamState};
use crate::server::hub::Hub;
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

/// One revocation that a rollback would undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revocation {
    /// `device`, `member`, `agent`, `grant`, or `invite`.
    pub kind: &'static str,
    /// The id of the row in the team file (the same in the `.pre-v6` copy).
    pub id: u64,
    pub revoked_at: u64,
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
    /// The audit rows of the file that the copy lacks: they go with the rollback.
    pub audit_rows_lost: u64,
    /// Why the team could not be read, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `<team file>.pre-v6`.
fn pre_v6_path(file: &Path) -> PathBuf {
    let mut path = file.as_os_str().to_os_string();
    path.push(".pre-v6");
    PathBuf::from(path)
}

/// The ids of the rows of `table` that are not revoked.
fn live_ids(conn: &Connection, table: &str) -> RelayResult<Vec<u64>> {
    let mut statement = conn
        .prepare(&format!("SELECT id FROM {table} WHERE revoked_at IS NULL"))
        .map_err(db)?;
    statement
        .query_map([], |row| row.get::<_, i64>(0).map(to_u))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
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

fn max_audit_id(conn: &Connection) -> RelayResult<u64> {
    conn.query_row("SELECT coalesce(max(id), 0) FROM audit", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(to_u)
    .map_err(db)
}

/// Compares the file (`now`) with its copy (`pre`): the revocations of rows that are live
/// in the copy, and the audit rows after the copy's last one.
pub fn compare(now: &Connection, pre: &Connection) -> RelayResult<(Vec<Revocation>, u64)> {
    let mut revocations = Vec::new();
    for (table, kind) in REVOCABLE {
        let live = live_ids(pre, table)?;
        for (id, revoked_at) in revoked_rows(now, table)? {
            if live.contains(&id) {
                revocations.push(Revocation {
                    kind,
                    id,
                    revoked_at,
                });
            }
        }
    }
    revocations.sort_by_key(|revocation| (revocation.revoked_at, revocation.kind, revocation.id));
    let after = max_audit_id(pre)?;
    let lost = now
        .query_row(
            "SELECT count(*) FROM audit WHERE id > ?1",
            [i64::try_from(after).unwrap_or(i64::MAX)],
            |row| row.get::<_, i64>(0),
        )
        .map(to_u)
        .map_err(db)?;
    Ok((revocations, lost))
}

/// The answer for one team of the directory.
fn check_team(hub: &Hub, row: &TeamRow) -> TeamRollback {
    let mut answer = TeamRollback {
        team: row.id.clone(),
        kind: row.kind,
        state: row.state,
        schema: None,
        pre_v6: false,
        revocations: Vec::new(),
        audit_rows_lost: 0,
        error: None,
    };
    let file = hub.config.team_path(&row.id);
    let pre = pre_v6_path(&file);
    answer.pre_v6 = std::fs::symlink_metadata(&pre).is_ok_and(|meta| meta.is_file());
    let result = (|| -> RelayResult<()> {
        // An open team is read through its own connection; any other file read-only.
        let open = hub.team(&row.id).map(|core| core.store.clone());
        let store = match open {
            Some(store) => store,
            None => std::sync::Arc::new(Store::open_read_only(&file, &row.file_key)?),
        };
        answer.schema = Some(store.user_version()?);
        if !answer.pre_v6 {
            return Ok(());
        }
        let copy = Store::open_read_only(&pre, &row.file_key)?;
        let (revocations, lost) = copy.with(|pre| store.with(|now| compare(now, pre)))?;
        answer.revocations = revocations;
        answer.audit_rows_lost = lost;
        Ok(())
    })();
    if let Err(error) = result {
        answer.error = Some(error.message);
    }
    answer
}

/// `admin rollback-check`: every team of the directory, active or suspended.
pub fn check(hub: &Hub) -> RelayResult<Vec<TeamRollback>> {
    Ok(hub
        .directory
        .teams()?
        .iter()
        .map(|row| check_team(hub, row))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The revocable tables and the audit with only the columns that `compare` reads.
    fn file(rows: &str) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        let mut schema = String::new();
        for (table, _) in REVOCABLE {
            schema.push_str(&format!(
                "CREATE TABLE {table} (id INTEGER PRIMARY KEY, revoked_at INTEGER);"
            ));
        }
        schema.push_str("CREATE TABLE audit (id INTEGER PRIMARY KEY, action TEXT);");
        conn.execute_batch(&schema).unwrap();
        conn.execute_batch(rows).unwrap();
        conn
    }

    #[test]
    fn a_rollback_undoes_each_revocation_of_a_row_that_the_copy_holds_live() {
        let base = "INSERT INTO device VALUES (1, NULL), (2, NULL), (3, 50);
            INSERT INTO member VALUES (1, NULL), (2, NULL);
            INSERT INTO agent VALUES (4, NULL), (5, NULL);
            INSERT INTO access_grant VALUES (6, NULL);
            INSERT INTO invite VALUES (7, NULL), (8, 60);
            INSERT INTO audit VALUES (1, 'a'), (2, 'b');";
        let pre = file(base);
        let now = file(&format!(
            "{base}
            UPDATE device SET revoked_at = 300 WHERE id = 2;
            UPDATE member SET revoked_at = 200 WHERE id = 2;
            UPDATE agent SET revoked_at = 100 WHERE id = 5;
            UPDATE access_grant SET revoked_at = 300 WHERE id = 6;
            UPDATE invite SET revoked_at = 400 WHERE id = 7;
            INSERT INTO device VALUES (9, 500);
            INSERT INTO audit VALUES (3, 'c'), (4, 'd'), (5, 'e');"
        ));
        let (revocations, lost) = compare(&now, &pre).unwrap();
        let named: Vec<(&str, u64, u64)> = revocations
            .iter()
            .map(|r| (r.kind, r.id, r.revoked_at))
            .collect();
        // Oldest first. Device 3 and invite 8 were revoked before the copy, and device 9
        // was made after it: the rollback does not bring those back.
        assert_eq!(
            named,
            vec![
                ("agent", 5, 100),
                ("member", 2, 200),
                ("device", 2, 300),
                ("grant", 6, 300),
                ("invite", 7, 400),
            ]
        );
        assert_eq!(lost, 3);
        // Nothing since the copy: nothing to undo.
        assert_eq!(compare(&pre, &pre).unwrap(), (Vec::new(), 0));
    }
}
