//! Reconnectable, bounded operation receipts. No arguments, output, or raw errors
//! are retained. Execution still uses the ordinary broker authorization path.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ring::hmac;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::decide::{self, BrokerContext};
use crate::agent::wire::{Action, WIRE_VERSION, WireRequest, WireResponse};

const RETENTION: Duration = Duration::from_secs(15 * 60);
const MAX_RECORDS: usize = 256;
const MAX_ACTIVE: usize = 8;

type Scope = ([u8; 32], u64);

#[derive(Debug, Default)]
struct State {
    cancelled: bool,
    effect_started: bool,
    waiting: bool,
    outcome: Option<Value>,
    finished: Option<Instant>,
}

#[derive(Debug, Default)]
pub(super) struct Control {
    state: Mutex<State>,
    changed: Condvar,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<Control>>> = const { RefCell::new(None) };
}

/// Checked at effect boundaries, independent of routing and owner approval.
/// Once an effect starts, cancellation cannot claim to undo it.
pub(super) fn start_effect() -> bool {
    CURRENT.with(|current| {
        let current = current.borrow();
        let Some(control) = current.as_ref() else {
            return true;
        };
        let mut state = lock(&control.state);
        if state.cancelled && !state.effect_started {
            return false;
        }
        state.effect_started = true;
        true
    })
}

pub(super) fn observed_effect() {
    CURRENT.with(|current| {
        if let Some(control) = current.borrow().as_ref() {
            lock(&control.state).effect_started = true;
        }
    });
}

pub(super) fn cancelled() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(|c| lock(&c.state).cancelled)
    })
}

pub(super) struct Waiting;
impl Drop for Waiting {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            if let Some(control) = current.borrow().as_ref() {
                lock(&control.state).waiting = false;
            }
        });
    }
}

pub(super) fn waiting() -> Waiting {
    CURRENT.with(|current| {
        if let Some(control) = current.borrow().as_ref() {
            lock(&control.state).waiting = true;
        }
    });
    Waiting
}

pub(super) fn cancelled_response() -> WireResponse {
    WireResponse::failure("cancelled", "The operation was cancelled before execution.")
}

struct Record {
    scope: Scope,
    fingerprint: [u8; 32],
    key: Option<[u8; 32]>,
    control: Arc<Control>,
}

pub(super) struct Operations {
    records: Mutex<BTreeMap<String, Record>>,
    // Keyed digests avoid retaining keys or secret-bearing arguments, including
    // dictionary-testable plain hashes of saved passwords.
    digest_key: hmac::Key,
}

impl Operations {
    pub(super) fn new() -> std::io::Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        getrandom::fill(key.as_mut()).map_err(std::io::Error::other)?;
        Ok(Self {
            records: Mutex::new(BTreeMap::new()),
            digest_key: hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
        })
    }

    fn digest(&self, bytes: &[u8]) -> [u8; 32] {
        hmac::sign(&self.digest_key, bytes)
            .as_ref()
            .try_into()
            .expect("SHA-256")
    }

    pub(super) fn handle(&self, ctx: &BrokerContext, request: &WireRequest) -> WireResponse {
        if request.v != WIRE_VERSION {
            return decide::handle(ctx, request);
        }
        if !matches!(
            request.action,
            Action::Tracked { .. }
                | Action::OperationStatus { .. }
                | Action::CancelOperation { .. }
        ) {
            return decide::handle(ctx, request);
        }
        let scope = {
            let mut guard = decide::lock(&ctx.vault);
            let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
                return decide::locked_response();
            };
            let agent = match decide::authenticate(vault, &request.token, request.action.name()) {
                Ok(agent) => agent,
                Err(response) => return response,
            };
            (vault.epoch(), agent.id)
        };
        let (id, key, action) = match &request.action {
            Action::Tracked {
                operation_id,
                idempotency_key,
                action,
            } => (
                operation_id,
                idempotency_key.as_deref(),
                Some(action.as_ref()),
            ),
            Action::OperationStatus { operation_id } | Action::CancelOperation { operation_id } => {
                (operation_id, None, None)
            }
            _ => unreachable!(),
        };
        if id.len() != 32
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || key.is_some_and(|k| k.is_empty() || k.len() > 128)
            || action.is_some_and(|a| !a.trackable())
        {
            return WireResponse::failure(
                "invalid_request",
                "Invalid operation ID, key, or action.",
            );
        }
        let mut records = lock(&self.records);
        records.retain(|_, r| {
            lock(&r.control.state)
                .finished
                .is_none_or(|t| t.elapsed() < RETENTION)
        });
        if action.is_none() {
            if let Some(record) = records.get(id).filter(|r| r.scope == scope) {
                let control = Arc::clone(&record.control);
                drop(records);
                let mut state = lock(&control.state);
                if matches!(request.action, Action::CancelOperation { .. })
                    && state.outcome.is_none()
                {
                    state.cancelled = true;
                    // Wait only for withdrawal of a pending question. Inference may
                    // still be running; its later effect boundary refuses execution.
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while state.waiting && state.outcome.is_none() && Instant::now() < deadline {
                        state = control
                            .changed
                            .wait_timeout(state, Duration::from_millis(20))
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .0;
                    }
                }
                return receipt(id, &state);
            }
            if matches!(request.action, Action::CancelOperation { .. })
                && records.len() < MAX_RECORDS
                && !records.contains_key(id)
            {
                // Cancellation can arrive before the original socket is accepted.
                let control = Arc::new(Control::default());
                let mut state = lock(&control.state);
                state.cancelled = true;
                state.finished = Some(Instant::now());
                state.outcome = Some(summary(&cancelled_response()));
                let response = receipt(id, &state);
                drop(state);
                records.insert(
                    id.clone(),
                    Record {
                        scope,
                        key: None,
                        fingerprint: [0; 32],
                        control,
                    },
                );
                return response;
            }
            return WireResponse::failure(
                "operation_not_found",
                "No retained operation for this agent and vault session. Do not assume it did not run.",
            );
        }
        let action = action.expect("tracked action");
        let bytes = Zeroizing::new(serde_json::to_vec(action).expect("serializable action"));
        let fingerprint = self.digest(&bytes);
        let key = key.map(|k| self.digest(k.as_bytes()));
        let known = records.get_key_value(id).or_else(|| {
            key.and_then(|k| {
                records
                    .iter()
                    .find(|(_, r)| r.scope == scope && r.key == Some(k))
            })
        });
        if let Some((known_id, _)) = known {
            let known_id = known_id.clone();
            let record = records.get_mut(&known_id).expect("known operation");
            if record.scope != scope {
                return WireResponse::failure(
                    "operation_conflict",
                    "The operation ID is already used.",
                );
            }
            if record.fingerprint != fingerprint && record.fingerprint != [0; 32] {
                let mut response = WireResponse::failure(
                    "idempotency_conflict",
                    "The key or operation ID was already used with different arguments.",
                );
                response.operation_id = Some(known_id);
                return response;
            }
            if record.fingerprint == [0; 32] {
                record.fingerprint = fingerprint;
                record.key = key;
            }
            return receipt(&known_id, &lock(&record.control.state));
        }
        let active = records
            .values()
            .filter(|r| lock(&r.control.state).finished.is_none())
            .count();
        if records.len() >= MAX_RECORDS || active >= MAX_ACTIVE {
            return WireResponse::failure(
                "busy",
                "The operation table is full. No operation was started.",
            );
        }
        let control = Arc::new(Control::default());
        records.insert(
            id.clone(),
            Record {
                scope,
                fingerprint,
                key,
                control: Arc::clone(&control),
            },
        );
        drop(records);
        let inner = WireRequest {
            v: request.v,
            token: request.token.clone(),
            host_session: request.host_session.clone(),
            action: action.clone(),
        };
        CURRENT.with(|current| *current.borrow_mut() = Some(Arc::clone(&control)));
        // Short mutations have no blocking approval/execution stage. Mark them
        // conservatively before entering their existing authorization path.
        let mut response = if !action.waits()
            && !matches!(action, Action::Call { .. })
            && !start_effect()
        {
            cancelled_response()
        } else {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decide::handle(ctx, &inner)))
                .unwrap_or_else(|_| {
                    WireResponse::failure(
                        "unknown_outcome",
                        "The operation handler stopped; verify its outcome before retrying.",
                    )
                })
        };
        CURRENT.with(|current| *current.borrow_mut() = None);
        let mut state = lock(&control.state);
        if state.cancelled && !state.effect_started {
            response = cancelled_response();
        }
        state.outcome = Some(summary(&response));
        state.finished = Some(Instant::now());
        state.waiting = false;
        control.changed.notify_all();
        response.operation_id = Some(id.clone());
        response
    }
}

fn receipt(id: &str, state: &State) -> WireResponse {
    let mut response = WireResponse::success(json!({
        "operation_id": id,
        "state": if state.outcome.is_some() { "completed" } else if state.waiting { "waiting_for_owner" } else if state.effect_started { "executing" } else { "checking" },
        "cancellation_requested": state.cancelled,
        "may_have_run": state.effect_started,
        "outcome": state.outcome,
        "retention_seconds": RETENTION.as_secs(),
    }));
    response.operation_id = Some(id.to_owned());
    response
}

/// Deliberately omit stdout, stderr, names, paths, network data, parameters, and
/// broker prose: even masked command output can contain unrelated secret values.
fn summary(response: &WireResponse) -> Value {
    let mut result = json!({});
    if let Some(value) = &response.result {
        for name in [
            "exit_code",
            "timed_out",
            "truncated",
            "item_id",
            "created",
            "request_id",
        ] {
            if let Some(v) = value
                .get(name)
                .filter(|v| v.is_boolean() || v.is_number() || v.is_null())
            {
                result[name] = v.clone();
            }
        }
    }
    let code = response
        .error
        .as_ref()
        .map(|e| crate::agent::mcp::broker_error(&e.code)["structuredContent"]["code"].clone());
    json!({ "ok": response.ok, "result": result, "code": code, "output_retained": false })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_outcomes_exclude_output_arguments_names_and_raw_errors() {
        let secret = "FAKE-status-canary-1234";
        let success = summary(&WireResponse::success(
            json!({"stdout":secret,"stderr":secret,"name":secret,"network":{"token":secret},"exit_code":7,"timed_out":false,"item_id":1,"created":true}),
        ));
        assert!(!success.to_string().contains(secret));
        assert_eq!(success["result"]["exit_code"], 7);
        assert_eq!(success["output_retained"], false);
        let failure = summary(&WireResponse::failure(secret, secret));
        assert!(!failure.to_string().contains(secret));
        assert_eq!(failure["code"], "broker_error");
    }

    #[test]
    fn retention_is_at_least_fifteen_minutes_and_digests_are_keyed() {
        assert!(RETENTION >= Duration::from_secs(900));
        let a = Operations::new().unwrap();
        let b = Operations::new().unwrap();
        assert_eq!(
            a.digest(b"synthetic password"),
            a.digest(b"synthetic password")
        );
        assert_ne!(
            a.digest(b"synthetic password"),
            b.digest(b"synthetic password")
        );
    }
}
