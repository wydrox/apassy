//! Runs, approvals, denials, timeouts, and the long poll (docs/SPEC.md, "Session
//! lifecycle and environment").
//!
//! States of a run: `pending` to `ready` to `ended`, or `pending` to `denied` or
//! `timed_out`. A timeout is checked lazily, at each read of a run and each list of
//! approvals. Nothing here allows a run on an error.

use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde_json::json;

use crate::api::{ApprovalItem, ApprovalView, DecidedBy, DecisionRequest, RunStatus, RunView};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, ItemId, MemberId, RunId};
use crate::now_unix;
use crate::server::Core;
use crate::server::audit::{RELAY_ACTOR, member_actor};
use crate::server::auth::{self, AgentAuth, MemberAuth};
use crate::server::decide;
use crate::server::store::{db, load_item, member_name, to_i, to_u};

/// The longest long poll, in seconds.
pub const MAX_WAIT_SECS: u64 = 25;
/// The longest reason of an approver, in bytes.
pub const MAX_REASON_BYTES: usize = 500;

/// Wakes the long polls when a run changes.
#[derive(Default)]
pub struct Notifier {
    version: Mutex<u64>,
    changed: Condvar,
}

impl Notifier {
    pub fn notify(&self) {
        let mut version = self.version.lock().unwrap_or_else(PoisonError::into_inner);
        *version = version.wrapping_add(1);
        self.changed.notify_all();
    }

    fn current(&self) -> u64 {
        *self.version.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the version differs from `seen`, or `timeout` passes.
    fn wait_from(&self, seen: u64, timeout: Duration) {
        let guard = self.version.lock().unwrap_or_else(PoisonError::into_inner);
        if *guard != seen {
            return;
        }
        let _ = self
            .changed
            .wait_timeout(guard, timeout)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// One stored run. Text fields are masked.
#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: RunId,
    pub agent_id: AgentId,
    pub member_id: MemberId,
    pub items: Vec<ItemId>,
    pub command: Vec<String>,
    pub purpose: String,
    pub user_request: Option<String>,
    pub cwd: Option<String>,
    pub ttl_secs: u64,
    pub flags: Vec<String>,
    pub note: String,
    pub status: RunStatus,
    pub decided_by: Option<DecidedBy>,
    pub approver_id: Option<MemberId>,
    pub code: Option<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub decided_at: Option<u64>,
    pub session_expires_at: Option<u64>,
}

pub fn status_text(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Pending => "pending",
        RunStatus::Ready => "ready",
        RunStatus::Denied => "denied",
        RunStatus::TimedOut => "timed_out",
        RunStatus::Ended => "ended",
    }
}

fn parse_status(text: &str) -> RunStatus {
    match text {
        "pending" => RunStatus::Pending,
        "ready" => RunStatus::Ready,
        "denied" => RunStatus::Denied,
        "timed_out" => RunStatus::TimedOut,
        _ => RunStatus::Ended,
    }
}

pub fn decided_text(by: DecidedBy) -> &'static str {
    match by {
        DecidedBy::KnownSafe => "known_safe",
        DecidedBy::Approver => "approver",
        DecidedBy::Revocation => "revocation",
        DecidedBy::Timeout => "timeout",
    }
}

fn parse_decided(text: &str) -> Option<DecidedBy> {
    match text {
        "known_safe" => Some(DecidedBy::KnownSafe),
        "approver" => Some(DecidedBy::Approver),
        "revocation" => Some(DecidedBy::Revocation),
        "timeout" => Some(DecidedBy::Timeout),
        _ => None,
    }
}

const RUN_COLUMNS: &str = "id, agent_id, member_id, items, command, purpose, user_request, cwd, \
    ttl_secs, flags, note, status, decided_by, approver_id, code, created_at, expires_at, \
    decided_at, session_expires_at";

fn run_from_row(row: &Row<'_>) -> rusqlite::Result<RunRow> {
    let items: Vec<u64> = serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default();
    Ok(RunRow {
        id: RunId(to_u(row.get(0)?)),
        agent_id: AgentId(to_u(row.get(1)?)),
        member_id: MemberId(to_u(row.get(2)?)),
        items: items.into_iter().map(ItemId).collect(),
        command: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default(),
        purpose: row.get(5)?,
        user_request: row.get(6)?,
        cwd: row.get(7)?,
        ttl_secs: to_u(row.get(8)?),
        flags: serde_json::from_str(&row.get::<_, String>(9)?).unwrap_or_default(),
        note: row.get(10)?,
        status: parse_status(&row.get::<_, String>(11)?),
        decided_by: row
            .get::<_, Option<String>>(12)?
            .as_deref()
            .and_then(parse_decided),
        approver_id: row.get::<_, Option<i64>>(13)?.map(|v| MemberId(to_u(v))),
        code: row.get(14)?,
        created_at: to_u(row.get(15)?),
        expires_at: row.get::<_, Option<i64>>(16)?.map(to_u),
        decided_at: row.get::<_, Option<i64>>(17)?.map(to_u),
        session_expires_at: row.get::<_, Option<i64>>(18)?.map(to_u),
    })
}

pub fn load_run(conn: &Connection, id: RunId) -> RelayResult<Option<RunRow>> {
    conn.query_row(
        &format!("SELECT {RUN_COLUMNS} FROM run WHERE id = ?1"),
        params![to_i(id.0)],
        run_from_row,
    )
    .optional()
    .map_err(db)
}

/// Stores a new run and returns its id.
pub fn insert_run(conn: &Connection, run: &RunRow) -> RelayResult<RunId> {
    let items: Vec<u64> = run.items.iter().map(|i| i.0).collect();
    conn.execute(
        "INSERT INTO run (agent_id, member_id, items, command, purpose, user_request, cwd, \
         ttl_secs, flags, note, status, decided_by, approver_id, code, created_at, expires_at, \
         decided_at, session_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            to_i(run.agent_id.0),
            to_i(run.member_id.0),
            serde_json::to_string(&items).unwrap_or_default(),
            serde_json::to_string(&run.command).unwrap_or_default(),
            run.purpose,
            run.user_request,
            run.cwd,
            to_i(run.ttl_secs),
            serde_json::to_string(&run.flags).unwrap_or_default(),
            run.note,
            status_text(run.status),
            run.decided_by.map(decided_text),
            run.approver_id.map(|m| to_i(m.0)),
            run.code,
            to_i(run.created_at),
            run.expires_at.map(to_i),
            run.decided_at.map(to_i),
            run.session_expires_at.map(to_i),
        ],
    )
    .map_err(db)?;
    Ok(RunId(to_u(conn.last_insert_rowid())))
}

/// Makes the lazy changes to a run: a pending run past its expiry times out, and a
/// ready run without a live session ends. Returns the current row.
fn settle(core: &Core, conn: &Connection, mut run: RunRow, now: u64) -> RelayResult<RunRow> {
    match run.status {
        RunStatus::Pending if run.expires_at.is_some_and(|at| now >= at) => {
            conn.execute(
                "UPDATE run SET status = 'timed_out', code = ?2, decided_by = 'timeout', decided_at = ?3 \
                 WHERE id = ?1 AND status = 'pending'",
                params![to_i(run.id.0), codes::APPROVAL_TIMEOUT, to_i(now)],
            )
            .map_err(db)?;
            core.audit.write_on(
                conn,
                now,
                RELAY_ACTOR,
                "run_timed_out",
                Some(run.id),
                &json!({"agent_id": run.agent_id}),
            )?;
            run.status = RunStatus::TimedOut;
            run.code = Some(codes::APPROVAL_TIMEOUT.to_string());
            run.decided_by = Some(DecidedBy::Timeout);
            run.decided_at = Some(now);
            core.notify.notify();
        }
        RunStatus::Ready => {
            let expired = run.session_expires_at.is_none_or(|at| now >= at);
            let live = core.sessions.view_for_run(run.id, now).is_some();
            if expired || !live {
                core.sessions.remove_matching(|s| s.run_id == run.id);
                conn.execute(
                    "UPDATE run SET status = 'ended' WHERE id = ?1 AND status = 'ready'",
                    params![to_i(run.id.0)],
                )
                .map_err(db)?;
                core.audit.write_on(
                    conn,
                    now,
                    RELAY_ACTOR,
                    "session_ended",
                    Some(run.id),
                    &json!({"reason": if expired { "expired" } else { "not_live" }}),
                )?;
                run.status = RunStatus::Ended;
            }
        }
        _ => {}
    }
    Ok(run)
}

/// Times out every pending run past its expiry, and ends expired sessions.
pub fn maintenance(core: &Core, now: u64) -> RelayResult<()> {
    core.store.tx(|tx| {
        let ids: Vec<u64> = {
            let mut statement = tx
                .prepare(
                    "SELECT id FROM run WHERE (status = 'pending' AND expires_at <= ?1) \
                     OR (status = 'ready' AND session_expires_at <= ?1)",
                )
                .map_err(db)?;
            let rows = statement
                .query_map(params![to_i(now)], |row| Ok(to_u(row.get(0)?)))
                .map_err(db)?;
            rows.collect::<Result<_, _>>().map_err(db)?
        };
        for id in ids {
            if let Some(run) = load_run(tx, RunId(id))? {
                settle(core, tx, run, now)?;
            }
        }
        Ok(())
    })
}

/// The `RunView` of a row. `with_session` puts in the environment of a live session:
/// only for the agent that asked for the run.
pub fn run_view(
    core: &Core,
    conn: &Connection,
    run: &RunRow,
    with_session: bool,
    now: u64,
) -> RelayResult<RunView> {
    let approver = match (run.decided_by, run.approver_id) {
        (Some(DecidedBy::Approver), Some(id)) => member_name(conn, id)?,
        _ => None,
    };
    let session = if with_session && run.status == RunStatus::Ready {
        core.sessions.view_for_run(run.id, now)
    } else {
        None
    };
    Ok(RunView {
        run_id: run.id,
        status: run.status,
        decided_by: run.decided_by,
        approver,
        code: run.code.clone(),
        note: run.note.clone(),
        flags: run.flags.clone(),
        created_at: run.created_at,
        expires_at: match run.status {
            RunStatus::Pending => run.expires_at,
            _ => None,
        },
        session,
    })
}

/// `GET /v1/approvals`: the pending runs, oldest first.
pub fn list(core: &Core, now: u64) -> RelayResult<Vec<ApprovalView>> {
    maintenance(core, now)?;
    core.store.with(|conn| {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {RUN_COLUMNS} FROM run WHERE status = 'pending' ORDER BY id"
            ))
            .map_err(db)?;
        let runs: Vec<RunRow> = statement
            .query_map([], run_from_row)
            .map_err(db)?
            .collect::<Result<_, _>>()
            .map_err(db)?;
        let mut views = Vec::with_capacity(runs.len());
        for run in runs {
            let agent: String = conn
                .query_row(
                    "SELECT name FROM agent WHERE id = ?1",
                    params![to_i(run.agent_id.0)],
                    |row| row.get(0),
                )
                .map_err(db)?;
            let member = member_name(conn, run.member_id)?.unwrap_or_default();
            let mut items = Vec::new();
            for id in &run.items {
                if let Some(item) = load_item(conn, *id)? {
                    items.push(ApprovalItem {
                        id: item.id,
                        name: item.name,
                        collection: item.collection,
                        environment: item.environment,
                    });
                }
            }
            views.push(ApprovalView {
                run_id: run.id,
                agent_id: run.agent_id,
                agent,
                member,
                items,
                command: run.command,
                purpose: run.purpose,
                user_request: run.user_request,
                cwd: run.cwd,
                flags: run.flags,
                note: run.note,
                created_at: run.created_at,
                expires_at: run.expires_at.unwrap_or(0),
            });
        }
        Ok(views)
    })
}

fn checked_reason(request: &DecisionRequest) -> RelayResult<Option<String>> {
    match request.reason.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(reason) if reason.len() > MAX_REASON_BYTES || reason.contains('\0') => Err(
            RelayError::invalid("The reason is at most 500 bytes and has no NUL."),
        ),
        Some(reason) => Ok(Some(reason.to_string())),
    }
}

/// `POST /v1/approvals/{id}/approve`.
pub fn approve(
    core: &Core,
    approver: &MemberAuth,
    run_id: RunId,
    request: &DecisionRequest,
    now: u64,
) -> RelayResult<RunView> {
    let reason = checked_reason(request)?.map(|r| core.audit.mask_text(&r));
    let mut created = None;
    let result = core.store.tx(|tx| {
        let run = load_run(tx, run_id)?.ok_or_else(|| RelayError::not_found("run"))?;
        let run = settle(core, tx, run, now)?;
        if run.status != RunStatus::Pending {
            // A run that timed out just now is stored; the caller still gets 409.
            return Ok(Err(RelayError::new(
                codes::RUN_NOT_PENDING,
                "The run is not waiting for an approver.",
            )));
        }
        // Step 1 and step 3 of the decision, again.
        let still_valid = auth::agent_by_id(tx, run.agent_id, now).is_ok()
            && decide::check_access(tx, run.member_id, &run.items).is_ok();
        let items = if still_valid {
            decide::check_access(tx, run.member_id, &run.items).ok()
        } else {
            None
        };
        let Some(items) = items else {
            let note = "The agent or its access changed while the run waited.".to_string();
            tx.execute(
                "UPDATE run SET status = 'denied', code = ?2, decided_by = 'revocation', \
                 decided_at = ?3, note = ?4 WHERE id = ?1",
                params![to_i(run.id.0), codes::APPROVAL_INVALIDATED, to_i(now), note],
            )
            .map_err(db)?;
            core.audit.write_on(
                tx,
                now,
                &member_actor(approver.id.0),
                "run_invalidated",
                Some(run.id),
                &json!({"reason": "revocation"}),
            )?;
            let row = load_run(tx, run.id)?.ok_or_else(|| RelayError::not_found("run"))?;
            return Ok(Ok(run_view(core, tx, &row, false, now)?));
        };
        let expires_at = now + run.ttl_secs;
        let env_items = decide::env_items(&items)?;
        let (_, hash) = core.sessions.create(
            &core.config.public_url,
            run.id,
            run.agent_id,
            run.member_id,
            expires_at,
            &env_items,
        )?;
        created = Some(hash);
        let note = reason
            .clone()
            .unwrap_or_else(|| format!("Approved by {}.", approver.name));
        tx.execute(
            "UPDATE run SET status = 'ready', decided_by = 'approver', approver_id = ?2, \
             decided_at = ?3, session_expires_at = ?4, note = ?5, code = NULL WHERE id = ?1",
            params![
                to_i(run.id.0),
                to_i(approver.id.0),
                to_i(now),
                to_i(expires_at),
                note
            ],
        )
        .map_err(db)?;
        let actor = member_actor(approver.id.0);
        core.audit.write_on(
            tx,
            now,
            &actor,
            "run_approved",
            Some(run.id),
            &json!({"reason": note}),
        )?;
        core.audit.write_on(
            tx,
            now,
            RELAY_ACTOR,
            "session_started",
            Some(run.id),
            &json!({"expires_at": expires_at, "items": run.items}),
        )?;
        let row = load_run(tx, run.id)?.ok_or_else(|| RelayError::not_found("run"))?;
        Ok(Ok(run_view(core, tx, &row, false, now)?))
    });
    match result {
        Ok(outcome) => {
            core.notify.notify();
            outcome
        }
        Err(error) => {
            if let Some(hash) = created {
                core.sessions.remove_hash(&hash);
            }
            Err(error)
        }
    }
}

/// `POST /v1/approvals/{id}/deny`.
pub fn deny(
    core: &Core,
    approver: &MemberAuth,
    run_id: RunId,
    request: &DecisionRequest,
    now: u64,
) -> RelayResult<RunView> {
    let reason = checked_reason(request)?.map(|r| core.audit.mask_text(&r));
    let result = core.store.tx(|tx| {
        let run = load_run(tx, run_id)?.ok_or_else(|| RelayError::not_found("run"))?;
        let run = settle(core, tx, run, now)?;
        if run.status != RunStatus::Pending {
            return Ok(Err(RelayError::new(
                codes::RUN_NOT_PENDING,
                "The run is not waiting for an approver.",
            )));
        }
        let note = reason.clone().unwrap_or_else(|| format!("Denied by {}.", approver.name));
        tx.execute(
            "UPDATE run SET status = 'denied', code = ?2, decided_by = 'approver', approver_id = ?3, \
             decided_at = ?4, note = ?5 WHERE id = ?1",
            params![
                to_i(run.id.0),
                codes::APPROVAL_DENIED,
                to_i(approver.id.0),
                to_i(now),
                note
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(approver.id.0),
            "run_denied",
            Some(run.id),
            &json!({"code": codes::APPROVAL_DENIED, "reason": note}),
        )?;
        let row = load_run(tx, run.id)?.ok_or_else(|| RelayError::not_found("run"))?;
        Ok(Ok(run_view(core, tx, &row, false, now)?))
    })?;
    core.notify.notify();
    result
}

/// `GET /v1/runs/{id}?wait=s`: the run of this agent. While it is pending, holds the
/// response up to `wait` seconds.
pub fn get_run(
    core: &Core,
    agent: &AgentAuth,
    run_id: RunId,
    wait_secs: u64,
) -> RelayResult<RunView> {
    let deadline = Instant::now() + Duration::from_secs(wait_secs.min(MAX_WAIT_SECS));
    loop {
        let seen = core.notify.current();
        let now = now_unix();
        let view = core.store.tx(|tx| {
            let run = load_run(tx, run_id)?
                .filter(|run| run.agent_id == agent.id)
                .ok_or_else(|| RelayError::not_found("run"))?;
            let run = settle(core, tx, run, now)?;
            let view = run_view(core, tx, &run, true, now)?;
            Ok(view)
        })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if view.status != RunStatus::Pending || remaining.is_zero() || core.stopping() {
            return Ok(view);
        }
        core.notify
            .wait_from(seen, remaining.min(Duration::from_millis(500)));
    }
}
