//! Durable records of runs that wait for the owner (schema v7, goal item N3).
//!
//! The broker stores a record when a run starts to wait, and removes it when the wait
//! ends. The final entry of the run goes to the activity log. When the process ends
//! without this step (a crash or `kill -9`), the record stays in the vault. The next
//! unlock turns each record into an activity entry that starts with
//! [`ENDED_BY_RESTART`], so the inbox shows the event after the restart.
//!
//! A record has no secret value: the agent name, the item, the operation label, and the
//! purpose, as in the activity log.
//!
//! A run that still waits in this process holds a [`WaitTicket`]. An unlock ends only
//! the records without a ticket. So a broker thread that ends its wait after a quick
//! lock and unlock writes its own entry, and no run gets two entries.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use rusqlite::TransactionBehavior;

use super::agents::{
    ActivityDecision, MAX_ACTIVITY_REASON_BYTES, MAX_ACTIVITY_ROWS, MAX_OPERATION_BYTES,
    NewActivity, format_utc,
};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_sql_id};

/// Activity text for a run that waited when Apassy stopped or the vault was locked, and
/// that had no final entry.
pub const ENDED_BY_RESTART: &str = "Ended by restart: Apassy stopped, or the vault was locked, before the owner decided. The run did not start.";

const MAX_TEXT_BYTES: usize = 700;

/// Wait records of this process that a broker thread still holds: (vault file, ID).
static LIVE_WAITS: Mutex<BTreeSet<(PathBuf, i64)>> = Mutex::new(BTreeSet::new());

fn live_waits() -> std::sync::MutexGuard<'static, BTreeSet<(PathBuf, i64)>> {
    LIVE_WAITS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A wait record that a broker thread holds. Drop releases it, also when the vault is
/// locked or gone. A crash releases every ticket with the process.
#[derive(Debug)]
pub struct WaitTicket {
    path: PathBuf,
    id: i64,
}

impl Drop for WaitTicket {
    fn drop(&mut self) {
        live_waits().remove(&(std::mem::take(&mut self.path), self.id));
    }
}

impl Vault {
    /// A run starts to wait for the owner. `entry` names the run as the activity log
    /// does. Its `reason` is the purpose. Keep the ticket until the wait ends.
    pub fn start_wait(&mut self, entry: &NewActivity) -> VaultResult<WaitTicket> {
        let at = i64::try_from(now()).map_err(|_| err(VaultErrorKind::Storage))?;
        let agent_id = entry.agent_id.map(to_sql_id).transpose()?;
        let item_id = entry.item_id.map(to_sql_id).transpose()?;
        let path = self.path.clone();
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO waiting_run (at, agent_id, agent_name, item_id, operation, purpose)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                at,
                agent_id,
                cut(&entry.agent_name),
                item_id,
                cut(&entry.operation),
                cut(&entry.reason),
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = conn.last_insert_rowid();
        live_waits().insert((path.clone(), id));
        Ok(WaitTicket { path, id })
    }

    /// The wait ended in this session. Returns true when the record was still there.
    /// False means that a lock, a quit, or an unlock already gave the run its entry.
    pub fn end_wait(&mut self, ticket: &WaitTicket) -> VaultResult<bool> {
        let changed = self
            .conn_mut()?
            .execute("DELETE FROM waiting_run WHERE id = ?1", [ticket.id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(changed > 0)
    }

    /// Give every recorded wait an activity entry, a denial with `why`, and remove the
    /// records, in one transaction. A lock or a quit of the app calls this. Returns the
    /// number of runs.
    pub fn end_waits(&mut self, why: &str) -> VaultResult<usize> {
        self.end_recorded_waits(why, false)
    }

    /// The unlock: end the records without a live ticket. Their runs ended with a crash,
    /// a quit without the app, or a lock.
    pub(super) fn end_stale_waits(&mut self) -> VaultResult<usize> {
        self.end_recorded_waits(ENDED_BY_RESTART, true)
    }

    fn end_recorded_waits(&mut self, why: &str, stale_only: bool) -> VaultResult<usize> {
        let live: BTreeSet<i64> = if stale_only {
            live_waits()
                .iter()
                .filter(|(path, _)| *path == self.path)
                .map(|(_, id)| *id)
                .collect()
        } else {
            BTreeSet::new()
        };
        let at = i64::try_from(now()).map_err(|_| err(VaultErrorKind::Storage))?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let waits = {
            let mut stmt = tx
                .prepare(
                    "SELECT id, at, agent_id, agent_name, item_id, operation, purpose
                     FROM waiting_run ORDER BY id ASC",
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                })
                .map_err(|_| err(VaultErrorKind::Storage))?;
            let mut waits = Vec::new();
            for row in rows {
                let wait = row.map_err(|_| err(VaultErrorKind::Storage))?;
                if !live.contains(&wait.0) {
                    waits.push(wait);
                }
            }
            waits
        };
        if waits.is_empty() {
            return Ok(0);
        }
        for (id, since, agent_id, agent_name, item_id, operation, purpose) in &waits {
            let since = u64::try_from(*since).map(format_utc).unwrap_or_default();
            let reason = cut_to(
                &format!("{why} It waited from {since}. Purpose: {purpose}"),
                MAX_ACTIVITY_REASON_BYTES,
            );
            tx.execute(
                "INSERT INTO activity (at, agent_id, agent_name, item_id, operation, decision, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    at,
                    agent_id,
                    agent_name,
                    item_id,
                    cut_to(operation, MAX_OPERATION_BYTES),
                    ActivityDecision::Deny.as_str(),
                    reason,
                ],
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
            tx.execute("DELETE FROM waiting_run WHERE id = ?1", [id])
                .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        tx.execute(
            "DELETE FROM activity WHERE id NOT IN
             (SELECT id FROM activity ORDER BY id DESC LIMIT ?1)",
            [i64::try_from(MAX_ACTIVITY_ROWS).map_err(|_| err(VaultErrorKind::Storage))?],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(waits.len())
    }

    /// Recorded waits that have no final entry yet.
    pub fn waiting_count(&self) -> VaultResult<usize> {
        let count: i64 = self
            .conn_ref()?
            .query_row("SELECT COUNT(*) FROM waiting_run", [], |row| row.get(0))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        usize::try_from(count).map_err(|_| err(VaultErrorKind::Storage))
    }
}

fn cut(text: &str) -> String {
    cut_to(text, MAX_TEXT_BYTES)
}

/// Without control characters, cut at a character boundary.
fn cut_to(text: &str, max: usize) -> String {
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> NewActivity {
        NewActivity {
            agent_id: None,
            agent_name: "Unit agent".to_owned(),
            item_id: None,
            operation: "run npm test".to_owned(),
            decision: ActivityDecision::Deny,
            reason: "Run the tests.".to_owned(),
        }
    }

    /// An unlock ends only a record without a live ticket. A lock or a quit ends all.
    #[test]
    fn an_unlock_ends_only_records_without_a_ticket() {
        let dir = tempfile::TempDir::new().expect("dir");
        let pass = "waiting-unit-pass";
        let mut vault = Vault::create(&dir.path().join("waits.db"), pass).expect("create");
        vault.unlock(pass).expect("unlock");
        let live = vault.start_wait(&entry()).expect("wait");
        let gone = vault.start_wait(&entry()).expect("wait");
        drop(gone);
        vault.lock().expect("lock");
        vault.unlock(pass).expect("unlock");
        assert_eq!(
            vault.waiting_count().expect("count"),
            1,
            "the live wait stays"
        );
        let activity = vault.recent_activity(10).expect("activity");
        assert_eq!(activity.len(), 1);
        assert!(activity[0].reason.starts_with(ENDED_BY_RESTART));
        assert!(activity[0].reason.ends_with("Purpose: Run the tests."));
        assert!(
            vault.end_wait(&live).expect("end"),
            "the thread ends its own wait"
        );
        assert!(!vault.end_wait(&live).expect("end"));

        let _third = vault.start_wait(&entry()).expect("wait");
        assert_eq!(vault.end_waits("Quit.").expect("quit"), 1);
        assert_eq!(vault.waiting_count().expect("count"), 0);
    }
}
