//! The endpoints of the owner's host (docs/SPEC.md, "Host-held item keys").
//!
//! The relay keeps only sealed item values. For each pending run it makes a one-time
//! X25519 key (`runkeys`). The host long-polls `GET /v1/host/requests`, decides, and
//! answers a run with `release` (the keys of that run's items, sealed to the run key)
//! or `deny`. A release is opened in memory, the values are decrypted for the session
//! and forgotten when it ends. Any fault denies the run and never allows it.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::api::{HostItem, HostRequestView, ReleaseRequest, RunStatus, RunView, Suggestion};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{
    self, CryptoError, MAX_SEALED_KEYS_BYTES, ReleasePlain, RunKey, check_value, decode_array,
    decode_b64, decode_key, encode_b64, open_item,
};
use crate::ids::RunId;
use crate::now_unix;
use crate::secret::{SecretString, TokenHash};
use crate::server::Core;
use crate::server::approvals::{
    self, INVALIDATED_NOTE, MAX_WAIT_SECS, RunRow, agent_name, checked_reason, load_run, run_view,
    settle,
};
use crate::server::audit::{EMBEDDED_HOST_ACTOR, RELAY_ACTOR, member_actor};
use crate::server::auth::{self, MemberAuth};
use crate::server::decide;
use crate::server::runkeys::PendingKey;
use crate::server::store::{ItemRow, db, load_item, member_name, to_i};

/// The note of a released run when the host gives no reason.
pub const RELEASED_NOTE: &str = "Released by the owner's host.";

/// `GET /v1/host/requests?wait=s`: the pending runs that wait for the host, oldest
/// first. A run is listed only while its key is in memory and it is not past its
/// expiry. While there is none, holds the response up to `wait` seconds. The host
/// has at most `host_long_polls` long polls open; a poll over that is answered at
/// once, as with `wait=0`, and so is a poll of a team whose `agents` limit is 0 (it can
/// have no run), or a Connect team's poll over `Limits::connect_long_polls`.
pub fn list(core: &Core, owner: &MemberAuth, wait_secs: u64) -> RelayResult<Vec<HostRequestView>> {
    // A team without agents has no run to wait for (a Connect team): answer at once.
    let poll = if wait_secs > 0 && core.limits().agents > 0 {
        core.host_polls.enter(owner.id.0)
    } else {
        None
    };
    let seat = poll.as_ref().and_then(|_| core.poll_seat());
    let wait_secs = if seat.is_some() { wait_secs } else { 0 };
    let deadline = Instant::now() + Duration::from_secs(wait_secs.min(MAX_WAIT_SECS));
    loop {
        crate::server::devices::authorize_host(core, owner)?;
        let now = now_unix();
        approvals::maintenance(core, now)?;
        let seen = core.notify.current();
        let views = pending_requests(core, now)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !views.is_empty() || remaining.is_zero() || core.stopping() {
            return Ok(views);
        }
        core.notify
            .wait_from(seen, remaining.min(Duration::from_millis(500)));
    }
}

fn pending_requests(core: &Core, now: u64) -> RelayResult<Vec<HostRequestView>> {
    core.store.with(|conn| {
        let mut views = Vec::new();
        for run in approvals::pending_runs(conn, now)? {
            // No key in memory (a restart, or a revocation): never shown to the host.
            let Some((run_key, suggestion)) = core.run_keys.offer(run.id) else {
                continue;
            };
            let mut items = Vec::with_capacity(run.items.len());
            for id in &run.items {
                match load_item(conn, *id)? {
                    Some(item) if !item.archived => items.push(HostItem {
                        uid: item.uid,
                        id: item.id,
                        name: item.name,
                        env_name: item.env_name,
                    }),
                    _ => break,
                }
            }
            if items.len() != run.items.len() {
                continue;
            }
            views.push(HostRequestView {
                run_id: run.id,
                agent: agent_name(conn, run.agent_id)?,
                member: member_name(conn, run.member_id)?.unwrap_or_default(),
                items,
                command: run.command,
                purpose: run.purpose,
                user_request: run.user_request,
                cwd: run.cwd,
                ttl_secs: run.ttl_secs,
                flags: run.flags,
                suggestion,
                note: run.note,
                run_key: encode_b64(&run_key),
                expires_at: run.expires_at.unwrap_or(0),
            });
        }
        Ok(views)
    })
}

/// Why a release did not check. The answer to the host never says which.
struct Fault;

impl From<CryptoError> for Fault {
    fn from(_: CryptoError) -> Self {
        Fault
    }
}

/// Opens a release and decrypts the values of the items of a run, in the order of
/// `items`. The run key is used up.
fn open_values(
    items: &[ItemRow],
    run_id: RunId,
    key: RunKey,
    request: &ReleaseRequest,
) -> Result<Vec<SecretString>, Fault> {
    // The value of an embedded node's item is in the owner's vault, not here: only the
    // in-process host releases it (`release_values`). Over HTTP it fails closed.
    if items
        .iter()
        .any(|item| hostkeys::is_value_on_host(&item.sealed))
    {
        return Err(Fault);
    }
    let host_key = decode_array::<{ hostkeys::KEY_BYTES }>(&request.host_key)?;
    let nonce = decode_array::<{ hostkeys::NONCE_BYTES }>(&request.nonce)?;
    let sealed_keys = decode_b64(&request.sealed_keys, MAX_SEALED_KEYS_BYTES)?;
    let plain = key.open_release(run_id.0, &host_key, nonce, &sealed_keys)?;
    let plain: ReleasePlain = serde_json::from_slice(&plain).map_err(|_| Fault)?;
    if plain.run_id != run_id.0 || plain.keys.len() != items.len() {
        return Err(Fault);
    }
    // The uids of the release are exactly the uids of the items: no more, no fewer,
    // none twice.
    let sent: HashSet<&str> = plain.keys.iter().map(|k| k.uid.as_str()).collect();
    let wanted: HashSet<&str> = items.iter().map(|i| i.uid.as_str()).collect();
    if sent.len() != plain.keys.len() || sent != wanted {
        return Err(Fault);
    }
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let entry = plain.keys.iter().find(|k| k.uid == item.uid).ok_or(Fault)?;
        let item_key = decode_key(entry.key.expose())?;
        let bytes = open_item(&item_key, &item.uid, &item.sealed)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Fault)?;
        // The CLI checked the value. The relay checks it again: the session needs a
        // placeholder, and the swap depends on the shape of the value.
        check_value(text).map_err(|_| Fault)?;
        values.push(SecretString::new(text.to_owned()));
    }
    Ok(values)
}

/// The pending run and its one-time key, taken out of the table: it is used up whatever
/// happens next. `Err` (409 `run_not_pending`) when the run is not pending, is past its
/// expiry, or has no key in memory.
fn take_pending(
    core: &Core,
    tx: &rusqlite::Connection,
    run_id: RunId,
    now: u64,
) -> RelayResult<Result<(RunRow, PendingKey), RelayError>> {
    let run = load_run(tx, run_id)?.ok_or_else(|| RelayError::not_found("run"))?;
    let run = settle(core, tx, run, now)?;
    let not_pending = || {
        RelayError::new(
            codes::RUN_NOT_PENDING,
            "The run is not waiting for the host.",
        )
    };
    if run.status != RunStatus::Pending {
        return Ok(Err(not_pending()));
    }
    let Some(pending) = core.run_keys.take(run.id) else {
        return Ok(Err(not_pending()));
    };
    Ok(Ok((run, pending)))
}

/// Step 1 and step 3 of the decision, again: the agent is live and the items pass
/// `check_access`. `None` after the run was denied with `approval_invalidated`.
fn recheck(
    core: &Core,
    tx: &rusqlite::Connection,
    run: &RunRow,
    actor: &str,
    now: u64,
) -> RelayResult<Option<Vec<ItemRow>>> {
    let items = if auth::agent_by_id(tx, run.agent_id, now).is_ok() {
        decide::check_access(tx, run.agent_id, run.member_id, &run.items).ok()
    } else {
        None
    };
    if items.is_none() {
        tx.execute(
            "UPDATE run SET status = 'denied', code = ?2, decided_by = 'revocation', \
             decided_at = ?3, note = ?4 WHERE id = ?1",
            rusqlite::params![
                to_i(run.id.0),
                codes::APPROVAL_INVALIDATED,
                to_i(now),
                INVALIDATED_NOTE
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            actor,
            "run_invalidated",
            Some(run.id),
            &json!({"reason": "revocation"}),
        )?;
    }
    Ok(items)
}

/// Denies a run whose release did not check, with `release_invalid`, and returns the
/// answer for the host. The answer never says which check failed.
fn deny_invalid(
    core: &Core,
    tx: &rusqlite::Connection,
    run_id: RunId,
    actor: &str,
    note: &str,
    now: u64,
) -> RelayResult<RelayError> {
    tx.execute(
        "UPDATE run SET status = 'denied', code = ?2, decided_by = 'host', \
         decided_at = ?3, note = ?4 WHERE id = ?1",
        rusqlite::params![to_i(run_id.0), codes::RELEASE_INVALID, to_i(now), note],
    )
    .map_err(db)?;
    core.audit.write_on(
        tx,
        now,
        actor,
        "run_denied",
        Some(run_id),
        &json!({"code": codes::RELEASE_INVALID, "by": "host"}),
    )?;
    Ok(RelayError::new(
        codes::RELEASE_INVALID,
        "The release did not open or did not match this run. The run is denied.",
    ))
}

/// Makes the session of a released run with `values[i]` for `items[i]`, sets the run
/// `ready`, and writes `run_released` (by `actor`) and `session_started`. `created` gets
/// the handle of the session as soon as it exists, so the caller removes it when the
/// transaction does not commit.
#[allow(clippy::too_many_arguments)]
fn start_session(
    core: &Core,
    tx: &rusqlite::Connection,
    run: &RunRow,
    items: &[ItemRow],
    values: Vec<SecretString>,
    suggestion: Suggestion,
    reason: Option<&str>,
    actor: &str,
    created: &mut Option<TokenHash>,
    now: u64,
) -> RelayResult<RunView> {
    let expires_at = now + run.ttl_secs;
    let env_items = decide::env_items(items, values)?;
    let (_, hash) = core.sessions.create(
        &core.config.public_url,
        run.id,
        run.agent_id,
        run.member_id,
        expires_at,
        &env_items,
    )?;
    *created = Some(hash);
    let note = reason.map_or_else(|| RELEASED_NOTE.to_string(), |r| core.audit.mask_text(r));
    tx.execute(
        "UPDATE run SET status = 'ready', decided_by = 'host', approver_id = NULL, \
         decided_at = ?2, session_expires_at = ?3, note = ?4, code = NULL WHERE id = ?1",
        rusqlite::params![to_i(run.id.0), to_i(now), to_i(expires_at), note],
    )
    .map_err(db)?;
    core.audit.write_on(
        tx,
        now,
        actor,
        "run_released",
        Some(run.id),
        &json!({
            "items": run.items,
            "suggestion": match suggestion {
                Suggestion::Allow => "allow",
                Suggestion::Ask => "ask",
            },
            "reason": note,
        }),
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
    run_view(core, tx, &row, false, now)
}

/// The view of a run that a recheck denied.
fn invalidated_view(
    core: &Core,
    tx: &rusqlite::Connection,
    run_id: RunId,
    now: u64,
) -> RelayResult<RunView> {
    let row = load_run(tx, run_id)?.ok_or_else(|| RelayError::not_found("run"))?;
    run_view(core, tx, &row, false, now)
}

/// Wakes the waiting polls after a committed release, or removes the session of a
/// transaction that did not commit.
fn finish(
    core: &Core,
    result: RelayResult<RelayResult<RunView>>,
    created: Option<TokenHash>,
) -> RelayResult<RunView> {
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

/// `POST /v1/host/requests/{run_id}/release`.
///
/// The run must be pending, not expired, and have its key in memory, else 409
/// `run_not_pending`. The key is taken out first: it is used up whatever happens
/// next. Then steps 1 and 3 of the decision are checked again (a failure denies the
/// run with `approval_invalidated`), the release is opened, and the session is made.
/// A release that does not check denies the run with `release_invalid` (HTTP 403), and
/// so does a run with an item of an embedded node (`hostkeys::VALUE_ON_HOST`).
pub fn release(
    core: &Core,
    owner: &MemberAuth,
    run_id: RunId,
    request: &ReleaseRequest,
    now: u64,
) -> RelayResult<RunView> {
    crate::server::devices::authorize_host(core, owner)?;
    // Masked after the session exists: only then does the relay know the values.
    let reason = checked_reason(request.reason.as_deref())?;
    let mut created = None;
    let result = core.store.tx(|tx| {
        crate::server::devices::authorize_host_on(tx, owner)?;
        let (run, pending) = match take_pending(core, tx, run_id, now)? {
            Ok(taken) => taken,
            Err(error) => return Ok(Err(error)),
        };
        let actor = member_actor(owner.id.0);
        let Some(items) = recheck(core, tx, &run, &actor, now)? else {
            return Ok(Ok(invalidated_view(core, tx, run.id, now)?));
        };
        let values = match open_values(&items, run.id, pending.key, request) {
            Ok(values) => values,
            Err(Fault) => {
                let note = "The release from the owner's host did not check.";
                return Ok(Err(deny_invalid(core, tx, run.id, &actor, note, now)?));
            }
        };
        start_session(
            core,
            tx,
            &run,
            &items,
            values,
            pending.suggestion,
            reason.as_deref(),
            &actor,
            &mut created,
            now,
        )
        .map(Ok)
    });
    finish(core, result, created)
}

/// The release of the in-process host of an embedded node (docs/SPEC.md section 30.6).
/// The values come from the owner's vault in the same process, `values[i]` for the i-th
/// item of the run. As `release`: the run key is taken out first (one use), and steps 1
/// and 3 are checked again (`approval_invalidated`). Then every item must hold its
/// value on the host (`hostkeys::VALUE_ON_HOST`), there must be one value for each, and
/// each value must pass `check_value`; else the run is denied with `release_invalid`. The
/// session is made and `run_released` is written by `host:embedded`. There is no
/// `authorize_host`: the caller owns the store, and no HTTP route leads here.
pub fn release_values(
    core: &Core,
    run_id: RunId,
    values: Vec<SecretString>,
    reason: Option<&str>,
    now: u64,
) -> RelayResult<RunView> {
    let reason = checked_reason(reason)?;
    let mut created = None;
    let result = core.store.tx(|tx| {
        let (run, pending) = match take_pending(core, tx, run_id, now)? {
            Ok(taken) => taken,
            Err(error) => return Ok(Err(error)),
        };
        // The key is used up here: values in process need no release to open with it.
        let suggestion = pending.suggestion;
        let Some(items) = recheck(core, tx, &run, EMBEDDED_HOST_ACTOR, now)? else {
            return Ok(Ok(invalidated_view(core, tx, run.id, now)?));
        };
        let checked = values.len() == items.len()
            && items
                .iter()
                .all(|item| hostkeys::is_value_on_host(&item.sealed))
            && values
                .iter()
                .all(|value| check_value(value.expose()).is_ok());
        if !checked {
            let note = "The values from the owner's host did not check.";
            let actor = EMBEDDED_HOST_ACTOR;
            return Ok(Err(deny_invalid(core, tx, run.id, actor, note, now)?));
        }
        start_session(
            core,
            tx,
            &run,
            &items,
            values,
            suggestion,
            reason.as_deref(),
            EMBEDDED_HOST_ACTOR,
            &mut created,
            now,
        )
        .map(Ok)
    });
    finish(core, result, created)
}

/// A pending run as the in-process host of an embedded node sees it.
pub struct EmbeddedRequest {
    /// The stored run: masked command, purpose, user request, and working directory.
    pub run: RunRow,
    pub agent: String,
    /// The items of the run, in its order.
    pub items: Vec<HostItem>,
    /// The relay's own verdict.
    pub suggestion: Suggestion,
}

/// The pending runs that wait for the in-process host, oldest first, as
/// `GET /v1/host/requests` lists them (only a run with its key in memory and every item
/// live), without `authorize_host` and without the run key.
pub fn embedded_requests(core: &Core, now: u64) -> RelayResult<Vec<EmbeddedRequest>> {
    approvals::maintenance(core, now)?;
    core.store.with(|conn| {
        let mut list = Vec::new();
        for run in approvals::pending_runs(conn, now)? {
            let Some((_, suggestion)) = core.run_keys.offer(run.id) else {
                continue;
            };
            let mut items = Vec::with_capacity(run.items.len());
            for id in &run.items {
                match load_item(conn, *id)? {
                    Some(item) if !item.archived => items.push(HostItem {
                        uid: item.uid,
                        id: item.id,
                        name: item.name,
                        env_name: item.env_name,
                    }),
                    _ => break,
                }
            }
            if items.len() != run.items.len() {
                continue;
            }
            let agent = agent_name(conn, run.agent_id)?;
            list.push(EmbeddedRequest {
                run,
                agent,
                items,
                suggestion,
            });
        }
        Ok(list)
    })
}

/// The current row of a run, for the in-process host: a timeout or a session end that is
/// due is written first (`approvals::settle`).
pub fn embedded_run(core: &Core, run_id: RunId, now: u64) -> RelayResult<RunRow> {
    core.store.tx(|tx| {
        let run = load_run(tx, run_id)?.ok_or_else(|| RelayError::not_found("run"))?;
        settle(core, tx, run, now)
    })
}
