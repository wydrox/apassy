//! Runs, denials, timeouts, revocations of pending runs, and the long poll
//! (docs/SPEC.md, "Session lifecycle and environment").
//!
//! States of a run: `pending` to `ready` to `ended`, or `pending` to `denied` or
//! `timed_out`. A timeout is checked lazily, at each read of a run and each list of
//! approvals. A run becomes `ready` only by a release from the owner's host
//! (`server::host`): nobody approves on the relay. Nothing here allows a run on an
//! error.

use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde_json::json;

use crate::api::{ApprovalItem, ApprovalView, DecidedBy, DecisionRequest, RunStatus, RunView};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, ItemId, MemberId, RunId};
use crate::now_unix;
use crate::server::Core;
use crate::server::audit::{EMBEDDED_HOST_ACTOR, RELAY_ACTOR, member_actor};
use crate::server::auth::{AgentAuth, MemberAuth};
use crate::server::store::{db, load_item, member_name, to_i, to_u};

/// The longest long poll, in seconds.
pub const MAX_WAIT_SECS: u64 = 25;
/// The longest reason of an approver or of the host, in bytes.
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

    pub fn current(&self) -> u64 {
        *self.version.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the version differs from `seen`, or `timeout` passes.
    pub fn wait_from(&self, seen: u64, timeout: Duration) {
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

/// The open long polls of each caller (an agent id, or the owner's id for the host).
/// One caller cannot hold many request threads by long polls: a poll over the limit
/// is answered at once.
pub struct LongPolls {
    max: usize,
    open: Mutex<HashMap<u64, usize>>,
}

/// One open long poll. Dropping it closes it.
pub struct LongPoll<'a> {
    polls: &'a LongPolls,
    caller: u64,
}

impl LongPolls {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            open: Mutex::new(HashMap::new()),
        }
    }

    /// Opens a long poll for `caller`, or `None` when it has `max` open.
    pub fn enter(&self, caller: u64) -> Option<LongPoll<'_>> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let count = open.entry(caller).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(LongPoll {
            polls: self,
            caller,
        })
    }
}

impl Drop for LongPoll<'_> {
    fn drop(&mut self) {
        let mut open = self
            .polls
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = open.get_mut(&self.caller) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.caller);
            }
        }
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
        DecidedBy::Approver => "approver",
        DecidedBy::Revocation => "revocation",
        DecidedBy::Timeout => "timeout",
        DecidedBy::Host => "host",
    }
}

fn parse_decided(text: &str) -> Option<DecidedBy> {
    match text {
        "approver" => Some(DecidedBy::Approver),
        "revocation" => Some(DecidedBy::Revocation),
        "timeout" => Some(DecidedBy::Timeout),
        "host" => Some(DecidedBy::Host),
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

/// Makes the lazy changes to a run: a pending run past its expiry times out (and its
/// key is dropped), and a ready run without a live session ends. Returns the current
/// row.
pub(super) fn settle(
    core: &Core,
    conn: &Connection,
    mut run: RunRow,
    now: u64,
) -> RelayResult<RunRow> {
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
            core.run_keys.remove(run.id);
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

/// Times out every pending run past its expiry, ends expired sessions, and drops the
/// key of every run that is not pending any more.
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
        // Inside the transaction, so a run that commits now cannot lose its key.
        let pending: HashSet<u64> = {
            let mut statement = tx
                .prepare("SELECT id FROM run WHERE status = 'pending'")
                .map_err(db)?;
            let rows = statement
                .query_map([], |row| Ok(to_u(row.get(0)?)))
                .map_err(db)?;
            rows.collect::<Result<_, _>>().map_err(db)?
        };
        core.run_keys.retain(|run| pending.contains(&run.0));
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

/// The pending runs that have not passed their expiry, oldest first.
pub fn pending_runs(conn: &Connection, now: u64) -> RelayResult<Vec<RunRow>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {RUN_COLUMNS} FROM run WHERE status = 'pending' \
             AND (expires_at IS NULL OR expires_at > ?1) ORDER BY id"
        ))
        .map_err(db)?;
    statement
        .query_map(params![to_i(now)], run_from_row)
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)
}

/// The name of an agent.
pub fn agent_name(conn: &Connection, id: AgentId) -> RelayResult<String> {
    conn.query_row(
        "SELECT name FROM agent WHERE id = ?1",
        params![to_i(id.0)],
        |row| row.get(0),
    )
    .map_err(db)
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
            let agent = agent_name(conn, run.agent_id)?;
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

/// The reason of a decision: trimmed, at most 500 bytes, no NUL. `None` when empty.
pub fn checked_reason(reason: Option<&str>) -> RelayResult<Option<String>> {
    match reason.map(str::trim) {
        None | Some("") => Ok(None),
        Some(reason) if reason.len() > MAX_REASON_BYTES || reason.contains('\0') => Err(
            RelayError::invalid("The reason is at most 500 bytes and has no NUL."),
        ),
        Some(reason) => Ok(Some(reason.to_string())),
    }
}

/// `POST /v1/approvals/{id}/approve`: always refused. The keys of the items are on the
/// owner's host, so the relay cannot start a session on its own say.
pub fn approve_on_host() -> RelayError {
    RelayError::new(
        codes::APPROVE_ON_HOST,
        "The keys are on the owner's host. Approve there with apassy-team host.",
    )
}

/// Who denies a run.
#[derive(Clone, Copy)]
pub enum Denier<'a> {
    /// An owner or manager, on `POST /v1/approvals/{id}/deny`.
    Approver(&'a MemberAuth),
    /// The owner's host, on `POST /v1/host/requests/{id}/deny`.
    Host(&'a MemberAuth),
    /// The in-process host of an embedded node (docs/SPEC.md section 28.6). No HTTP
    /// route leads here: the caller owns the store.
    Embedded,
}

/// Denies a pending run and drops its key. `POST /v1/approvals/{id}/deny` and
/// `POST /v1/host/requests/{id}/deny`.
pub fn deny(
    core: &Core,
    who: Denier<'_>,
    run_id: RunId,
    request: &DecisionRequest,
    now: u64,
) -> RelayResult<RunView> {
    let reason = checked_reason(request.reason.as_deref())?.map(|r| core.audit.mask_text(&r));
    let name = match who {
        Denier::Approver(member) => format!("Denied by {}.", member.name),
        Denier::Host(_) | Denier::Embedded => "Denied by the owner's host.".to_string(),
    };
    let actor = match who {
        Denier::Approver(member) | Denier::Host(member) => member_actor(member.id.0),
        Denier::Embedded => EMBEDDED_HOST_ACTOR.to_string(),
    };
    let (decided_by, approver_id) = match who {
        Denier::Approver(member) => (DecidedBy::Approver, Some(to_i(member.id.0))),
        Denier::Host(_) | Denier::Embedded => (DecidedBy::Host, None),
    };
    let result = core.store.tx(|tx| {
        match who {
            Denier::Host(by) => crate::server::devices::authorize_host_on(tx, by)?,
            Denier::Approver(by) => crate::server::auth::require_member(tx, by, crate::server::auth::Need::Approver, now)?,
            Denier::Embedded => {}
        }
        let run = load_run(tx, run_id)?.ok_or_else(|| RelayError::not_found("run"))?;
        let run = settle(core, tx, run, now)?;
        if run.status != RunStatus::Pending {
            return Ok(Err(RelayError::new(
                codes::RUN_NOT_PENDING,
                "The run is not waiting for a decision.",
            )));
        }
        let note = reason.clone().unwrap_or_else(|| name.clone());
        tx.execute(
            "UPDATE run SET status = 'denied', code = ?2, decided_by = ?3, approver_id = ?4, \
             decided_at = ?5, note = ?6 WHERE id = ?1",
            params![
                to_i(run.id.0),
                codes::APPROVAL_DENIED,
                decided_text(decided_by),
                approver_id,
                to_i(now),
                note
            ],
        )
        .map_err(db)?;
        core.run_keys.remove(run.id);
        core.audit.write_on(
            tx,
            now,
            &actor,
            "run_denied",
            Some(run.id),
            &json!({"code": codes::APPROVAL_DENIED, "reason": note, "by": decided_text(decided_by)}),
        )?;
        let row = load_run(tx, run.id)?.ok_or_else(|| RelayError::not_found("run"))?;
        Ok(Ok(run_view(core, tx, &row, false, now)?))
    })?;
    core.notify.notify();
    result
}

/// Denies the pending runs that `depends` selects, with `approval_invalidated`, and
/// drops their keys. Call it in the transaction of the revocation of an agent, a
/// member, a grant, or an item. Returns how many runs it denied.
pub fn invalidate_pending(
    core: &Core,
    conn: &Connection,
    now: u64,
    actor: &str,
    reason: &str,
    depends: impl Fn(&RunRow) -> bool,
) -> RelayResult<usize> {
    let runs: Vec<RunRow> = {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {RUN_COLUMNS} FROM run WHERE status = 'pending' ORDER BY id"
            ))
            .map_err(db)?;
        statement
            .query_map([], run_from_row)
            .map_err(db)?
            .collect::<Result<_, _>>()
            .map_err(db)?
    };
    let mut count = 0;
    for run in runs.iter().filter(|run| depends(run)) {
        core.run_keys.remove(run.id);
        conn.execute(
            "UPDATE run SET status = 'denied', code = ?2, decided_by = 'revocation', \
             decided_at = ?3, note = ?4 WHERE id = ?1 AND status = 'pending'",
            params![
                to_i(run.id.0),
                codes::APPROVAL_INVALIDATED,
                to_i(now),
                INVALIDATED_NOTE
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            conn,
            now,
            actor,
            "run_invalidated",
            Some(run.id),
            &json!({"reason": reason}),
        )?;
        count += 1;
    }
    Ok(count)
}

/// The note of a run that a revocation or a failed re-check denied.
pub const INVALIDATED_NOTE: &str = "The agent or its access changed while the run waited.";

/// `GET /v1/runs/{id}?wait=s`: the run of this agent. While it is pending, holds the
/// response up to `wait` seconds. An agent that has `long_polls_per_agent` long polls
/// open gets the answer at once, as with `wait=0`.
pub fn get_run(
    core: &Core,
    agent: &AgentAuth,
    run_id: RunId,
    wait_secs: u64,
) -> RelayResult<RunView> {
    let poll = if wait_secs > 0 {
        core.polls.enter(agent.id.0)
    } else {
        None
    };
    let seat = poll.as_ref().and_then(|_| core.poll_seat());
    let wait_secs = if seat.is_some() { wait_secs } else { 0 };
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
