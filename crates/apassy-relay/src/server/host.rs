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
use crate::secret::SecretString;
use crate::server::Core;
use crate::server::approvals::{
    self, INVALIDATED_NOTE, MAX_WAIT_SECS, agent_name, checked_reason, load_run, run_view, settle,
};
use crate::server::audit::{RELAY_ACTOR, member_actor};
use crate::server::auth::{self, MemberAuth};
use crate::server::decide;
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

/// `POST /v1/host/requests/{run_id}/release`.
///
/// The run must be pending, not expired, and have its key in memory, else 409
/// `run_not_pending`. The key is taken out first: it is used up whatever happens
/// next. Then steps 1 and 3 of the decision are checked again (a failure denies the
/// run with `approval_invalidated`), the release is opened, and the session is made.
/// A release that does not check denies the run with `release_invalid` (HTTP 403).
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
        let actor = member_actor(owner.id.0);
        // Step 1 and step 3 of the decision, again.
        let items = if auth::agent_by_id(tx, run.agent_id, now).is_ok() {
            decide::check_access(tx, run.agent_id, run.member_id, &run.items).ok()
        } else {
            None
        };
        let Some(items) = items else {
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
                &actor,
                "run_invalidated",
                Some(run.id),
                &json!({"reason": "revocation"}),
            )?;
            let row = load_run(tx, run.id)?.ok_or_else(|| RelayError::not_found("run"))?;
            return Ok(Ok(run_view(core, tx, &row, false, now)?));
        };
        let values = match open_values(&items, run.id, pending.key, request) {
            Ok(values) => values,
            Err(Fault) => {
                let note = "The release from the owner's host did not check.";
                tx.execute(
                    "UPDATE run SET status = 'denied', code = ?2, decided_by = 'host', \
                     decided_at = ?3, note = ?4 WHERE id = ?1",
                    rusqlite::params![to_i(run.id.0), codes::RELEASE_INVALID, to_i(now), note],
                )
                .map_err(db)?;
                core.audit.write_on(
                    tx,
                    now,
                    &actor,
                    "run_denied",
                    Some(run.id),
                    &json!({"code": codes::RELEASE_INVALID, "by": "host"}),
                )?;
                return Ok(Err(RelayError::new(
                    codes::RELEASE_INVALID,
                    "The release did not open or did not match this run. The run is denied.",
                )));
            }
        };
        let expires_at = now + run.ttl_secs;
        let env_items = decide::env_items(&items, values)?;
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
            .as_deref()
            .map_or_else(|| RELEASED_NOTE.to_string(), |r| core.audit.mask_text(r));
        tx.execute(
            "UPDATE run SET status = 'ready', decided_by = 'host', approver_id = NULL, \
             decided_at = ?2, session_expires_at = ?3, note = ?4, code = NULL WHERE id = ?1",
            rusqlite::params![to_i(run.id.0), to_i(now), to_i(expires_at), note],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &actor,
            "run_released",
            Some(run.id),
            &json!({
                "items": run.items,
                "suggestion": match pending.suggestion {
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
