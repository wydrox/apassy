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
const MAX_AGENT_ACTIVE: usize = 3;
const MAX_AGENT_RECORDS: usize = 64;

type Scope = ([u8; 32], u64);

#[derive(Debug, Default)]
struct State {
    invalidated: bool,
    cancelled: bool,
    effect_started: bool,
    waiting: bool,
    outcome: Option<Value>,
    finished: Option<Instant>,
    // An asynchronous scoped request can outlive this operation's response.
    access_request: Option<u64>,
}

#[derive(Debug, Default)]
pub(super) struct Control {
    epoch: [u8; 32],
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
        if state.invalidated || (state.cancelled && !state.effect_started) {
            return false;
        }
        state.effect_started = true;
        true
    })
}

pub(super) fn session_matches(epoch: [u8; 32]) -> bool {
    CURRENT.with(|current| current.borrow().as_ref().is_none_or(|c| c.epoch == epoch))
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
        current.borrow().as_ref().is_some_and(|c| {
            let state = lock(&c.state);
            state.cancelled && !state.invalidated
        })
    })
}

/// Bind while holding the vault arbiter. Cancellation before binding is applied
/// here; cancellation after binding uses the same exact agent/request target.
pub(super) fn bind_access_request(
    vault: &mut crate::vault::Vault,
    agent: u64,
    id: u64,
) -> crate::vault::VaultResult<bool> {
    CURRENT.with(|current| {
        let current = current.borrow();
        let Some(control) = current.as_ref() else {
            return Ok(false);
        };
        let mut state = lock(&control.state);
        state.access_request = Some(id);
        let cancelled = state.cancelled || state.invalidated;
        drop(state);
        if cancelled {
            vault.cancel_scoped_access_request(agent, id)?;
        }
        Ok(cancelled)
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
    records: Arc<Mutex<BTreeMap<String, Record>>>,
    session: Arc<Mutex<Option<[u8; 32]>>>,
    // Keyed digests avoid retaining keys or secret-bearing arguments, including
    // dictionary-testable plain hashes of saved passwords.
    digest_key: hmac::Key,
}

impl Operations {
    pub(super) fn new() -> std::io::Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        getrandom::fill(key.as_mut()).map_err(std::io::Error::other)?;
        Ok(Self {
            records: Arc::new(Mutex::new(BTreeMap::new())),
            session: Arc::new(Mutex::new(None)),
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
        if request.action.trackable() {
            // Legacy clients must not bypass active-operation fairness. Their
            // temporary admission record is removed before the ordinary v0 reply.
            let mut random = [0; 16];
            if getrandom::fill(&mut random).is_err() {
                return WireResponse::failure("busy", "No operation was started.");
            }
            let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let mut response = self.handle(
                ctx,
                &WireRequest {
                    v: request.v,
                    token: request.token.clone(),
                    host_session: request.host_session.clone(),
                    action: Action::Tracked {
                        operation_id: id.clone(),
                        idempotency_key: None,
                        action: Box::new(request.action.clone()),
                    },
                },
            );
            lock(&self.records).remove(&id);
            response.operation_id = None;
            return response;
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
            let new_session = *lock(&self.session) != Some(vault.epoch());
            if new_session {
                clear_records(&self.records);
                *lock(&self.session) = Some(vault.epoch());
                let records = Arc::downgrade(&self.records);
                let session = Arc::downgrade(&self.session);
                vault.on_session_end(move || {
                    if let Some(session) = session.upgrade() {
                        *lock(&session) = None;
                    }
                    if let Some(records) = records.upgrade() {
                        clear_records(&records);
                    }
                });
            }
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
        // A lock can occur after authentication but before table admission.
        if *lock(&self.session) != Some(scope.0) {
            return decide::locked_response();
        }
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
                    && (state.outcome.is_none() || state.access_request.is_some())
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
                let access = matches!(request.action, Action::CancelOperation { .. })
                    .then_some(state.access_request)
                    .flatten();
                // Never take the vault while holding control.state: creation
                // binds its request under the opposite lock order.
                drop(state);
                if let Some(access) = access {
                    let mut guard = decide::lock(&ctx.vault);
                    let Some(vault) = guard
                        .as_mut()
                        .filter(|v| !v.is_locked() && v.epoch() == scope.0)
                    else {
                        return decide::locked_response();
                    };
                    if vault.cancel_scoped_access_request(scope.1, access).is_err() {
                        return WireResponse::failure(
                            "access_once_unavailable",
                            "The scoped request could not be withdrawn. Check its status on the Mac.",
                        );
                    }
                }
                return receipt(id, &lock(&control.state));
            }
            if matches!(request.action, Action::CancelOperation { .. })
                && records.len() < MAX_RECORDS
                && records.values().filter(|r| r.scope == scope).count() < MAX_AGENT_RECORDS
                && !records.contains_key(id)
            {
                // Cancellation can arrive before the original socket is accepted.
                let control = Arc::new(Control {
                    epoch: scope.0,
                    ..Control::default()
                });
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
        let bytes = fingerprint_bytes(action);
        let fingerprint = self.digest(&bytes);
        let key = key.map(|k| self.digest(k.as_bytes()));
        // A pre-submission cancellation tombstone for a retry ID must never
        // replace a key's original binding.
        let known = key
            .and_then(|k| {
                records
                    .iter()
                    .find(|(_, r)| r.scope == scope && r.key == Some(k))
            })
            .or_else(|| records.get_key_value(id));
        if let Some((known_id, _)) = known {
            let known_id = known_id.clone();
            let record = records.get_mut(&known_id).expect("known operation");
            if record.scope != scope {
                return WireResponse::failure(
                    "operation_conflict",
                    "The operation ID is already used.",
                );
            }
            // ADR 0033 deliberately has no execution idempotency. A caller uses
            // status after an uncertain admission, never a repeated use call.
            if matches!(
                action,
                Action::Run {
                    access_request_id: Some(_),
                    ..
                }
            ) {
                let mut response = WireResponse::failure(
                    "access_once_unavailable",
                    "This referenced use was already submitted. Query access/operation status; do not repeat it.",
                );
                response.operation_id = Some(known_id.clone());
                return response;
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
        let own_records = records.values().filter(|r| r.scope == scope).count();
        let own_active = records
            .values()
            .filter(|r| r.scope == scope && lock(&r.control.state).finished.is_none())
            .count();
        if records.len() >= MAX_RECORDS
            || active >= MAX_ACTIVE
            || own_records >= MAX_AGENT_RECORDS
            || own_active >= MAX_AGENT_ACTIVE
        {
            return WireResponse::failure(
                "busy",
                "The operation table is full. No operation was started.",
            );
        }
        let control = Arc::new(Control {
            epoch: scope.0,
            ..Control::default()
        });
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
        if state.cancelled && !state.invalidated && !state.effect_started {
            response = cancelled_response();
        }
        if !state.invalidated {
            state.outcome = Some(summary(&response));
        }
        state.finished = Some(Instant::now());
        state.waiting = false;
        control.changed.notify_all();
        response.operation_id = Some(id.clone());
        response
    }
}

fn clear_records(records: &Mutex<BTreeMap<String, Record>>) {
    let mut records = lock(records);
    for record in records.values() {
        let mut state = lock(&record.control.state);
        state.cancelled = true;
        state.invalidated = true;
        state.outcome = None;
        record.control.changed.notify_all();
    }
    records.clear();
}

fn fingerprint_bytes(action: &Action) -> Zeroizing<Vec<u8>> {
    let mut action = action.clone();
    match &mut action {
        // Credentials form a set; argv order and whitespace within values do not.
        Action::Run { items, codes, .. } => {
            items.sort_unstable();
            codes.sort_unstable();
        }
        Action::GenerateCredential {
            length, alphabet, ..
        } => {
            *length = Some(length.unwrap_or(32));
            *alphabet = Some(alphabet.take().unwrap_or_else(|| "alnum".into()));
        }
        Action::UpdateCredential {
            generate: Some(spec),
            ..
        } => {
            spec.length = Some(spec.length.unwrap_or(32));
            spec.alphabet = Some(spec.alphabet.take().unwrap_or_else(|| "alnum".into()));
        }
        _ => {}
    }
    Zeroizing::new(serde_json::to_vec(&action).expect("serializable action"))
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
    fn legacy_clients_share_active_limits_without_changing_their_wire_responses() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            crate::vault::Vault::create(&dir.path().join("vault.db"), "synthetic-legacy-pass")
                .unwrap();
        vault.unlock("synthetic-legacy-pass").unwrap();
        let (_, token) = vault.register_agent("Synthetic legacy caller").unwrap();
        let ctx = BrokerContext {
            vault: Arc::new(Mutex::new(Some(vault))),
            tls: super::super::http::TlsClient::platform().unwrap(),
            approvals: Arc::new(super::super::approvals::ApprovalQueue::new()),
            approval_timeout: Duration::from_secs(5),
            run_timeout: Duration::from_secs(2),
            bouncer: None,
            model_gate: None,
            prompts: Arc::new(super::super::prompts::PromptStore::new(vec![])),
        };
        let operations = Operations::new().unwrap();
        let request = WireRequest {
            v: WIRE_VERSION,
            token: token.expose().into(),
            host_session: None,
            action: Action::AskOwnerForCredential {
                name: "Synthetic legacy wait".into(),
                purpose: "Test legacy limits".into(),
                where_to_get: None,
                cwd: Some(dir.path().display().to_string()),
                folder: None,
            },
        };
        std::thread::scope(|threads| {
            let mut workers = Vec::new();
            for n in 1..=MAX_AGENT_ACTIVE {
                workers.push(threads.spawn(|| operations.handle(&ctx, &request)));
                let deadline = Instant::now() + Duration::from_secs(2);
                while lock(&operations.records)
                    .values()
                    .filter(|r| lock(&r.control.state).waiting)
                    .count()
                    < n
                {
                    assert!(Instant::now() < deadline, "legacy calls bypassed admission");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let mut mutation = request.clone();
            mutation.action = Action::GenerateCredential {
                name: "Must not bypass the active cap".into(),
                length: None,
                alphabet: None,
                cwd: Some(dir.path().display().to_string()),
                folder: None,
            };
            let refused = operations.handle(&ctx, &mutation);
            ctx.vault.lock().unwrap().as_mut().unwrap().lock().unwrap();
            for worker in workers {
                assert!(worker.join().unwrap().operation_id.is_none());
            }
            assert_eq!(refused.error.unwrap().code, "busy");
            assert!(refused.operation_id.is_none());
        });
        assert!(lock(&operations.records).is_empty());
        ctx.vault
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .unlock("synthetic-legacy-pass")
            .unwrap();
        let mut refusal = request.clone();
        refusal.action = Action::RequestAccess {
            scope: None,
            item_id: 0,
            reason: "Synthetic refusal".into(),
            cwd: None,
        };
        let response = operations.handle(&ctx, &refusal);
        assert!(response.operation_id.is_none());
        assert!(
            lock(&operations.records).is_empty(),
            "legacy completion must not consume retained capacity"
        );
    }

    #[test]
    fn vault_lock_erases_receipts_and_late_workers_cannot_restore_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            crate::vault::Vault::create(&dir.path().join("vault.db"), "synthetic-review-pass")
                .unwrap();
        vault.unlock("synthetic-review-pass").unwrap();
        let (_, token) = vault.register_agent("Synthetic reviewer").unwrap();
        let ctx = BrokerContext {
            vault: Arc::new(Mutex::new(Some(vault))),
            tls: super::super::http::TlsClient::platform().unwrap(),
            approvals: Arc::new(super::super::approvals::ApprovalQueue::new()),
            approval_timeout: Duration::from_secs(2),
            run_timeout: Duration::from_secs(2),
            bouncer: None,
            model_gate: None,
            prompts: Arc::new(super::super::prompts::PromptStore::new(vec![])),
        };
        let operations = Operations::new().unwrap();
        let request = WireRequest {
            v: WIRE_VERSION,
            token: token.expose().into(),
            host_session: None,
            action: Action::Tracked {
                operation_id: "00000000000000000000000000000001".into(),
                idempotency_key: Some("synthetic-key".into()),
                action: Box::new(Action::GenerateCredential {
                    name: "Synthetic receipt".into(),
                    length: None,
                    alphabet: None,
                    cwd: Some(dir.path().display().to_string()),
                    folder: None,
                }),
            },
        };
        assert!(operations.handle(&ctx, &request).ok);
        let control = Arc::clone(&lock(&operations.records).values().next().unwrap().control);
        assert!(lock(&control.state).outcome.is_some());
        ctx.vault.lock().unwrap().as_mut().unwrap().lock().unwrap();
        assert!(lock(&operations.records).is_empty());
        assert!(lock(&control.state).outcome.is_none());
        assert!(lock(&control.state).invalidated);
        ctx.vault
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .unlock("synthetic-review-pass")
            .unwrap();
        CURRENT.with(|current| *current.borrow_mut() = Some(control));
        // A delayed worker from the old session cannot authenticate in the new one.
        assert!(!decide::handle(&ctx, &request).ok);
        let mut vault = ctx.vault.lock().unwrap();
        assert!(
            decide::authenticate(
                vault.as_mut().unwrap(),
                token.expose(),
                "generate_credential"
            )
            .is_err()
        );
        assert!(!start_effect());
        CURRENT.with(|current| *current.borrow_mut() = None);
    }

    #[test]
    fn fingerprints_canonicalize_json_maps_and_credential_sets_but_preserve_command_text() {
        let a: Action = serde_json::from_str(
            r#"{"kind":"call","item_id":1,"operation":"read","params":{"a":"one","b":"two"}}"#,
        )
        .unwrap();
        let b: Action = serde_json::from_str(r#"{ "params": {"b":"two", "a":"one"}, "operation":"read", "item_id":1, "kind":"call" }"#).unwrap();
        assert_eq!(*fingerprint_bytes(&a), *fingerprint_bytes(&b));
        let generate = |length, alphabet| Action::GenerateCredential {
            name: "Synthetic defaults".into(),
            length,
            alphabet,
            cwd: None,
            folder: None,
        };
        assert_eq!(
            *fingerprint_bytes(&generate(None, None)),
            *fingerprint_bytes(&generate(Some(32), Some("alnum".into())))
        );
        let run = |items, command| Action::Run {
            access_request_id: None,
            codes: Default::default(),
            items,
            command,
            cwd: "/synthetic".into(),
            purpose: "Test".into(),
            path: None,
            user_request: None,
        };
        assert_eq!(
            *fingerprint_bytes(&run(vec![1, 2], vec!["true".into()])),
            *fingerprint_bytes(&run(vec![2, 1], vec!["true".into()]))
        );
        assert_ne!(
            *fingerprint_bytes(&run(vec![1], vec!["echo".into(), "a b".into()])),
            *fingerprint_bytes(&run(vec![1], vec!["echo".into(), "a  b".into()]))
        );
    }

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
    #[test]
    fn a_referenced_use_never_returns_an_idempotency_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let mut v =
            crate::vault::Vault::create(&dir.path().join("vault.db"), "synthetic-access-retry")
                .unwrap();
        v.unlock("synthetic-access-retry").unwrap();
        let (_, token) = v.register_agent("Synthetic retry").unwrap();
        let ctx = BrokerContext {
            vault: Arc::new(Mutex::new(Some(v))),
            tls: super::super::http::TlsClient::platform().unwrap(),
            approvals: Arc::new(super::super::approvals::ApprovalQueue::new()),
            approval_timeout: Duration::from_secs(1),
            run_timeout: Duration::from_secs(1),
            bouncer: None,
            model_gate: None,
            prompts: Arc::new(super::super::prompts::PromptStore::new(vec![])),
        };
        let operations = Operations::new().unwrap();
        let request = WireRequest {
            v: WIRE_VERSION,
            token: token.expose().into(),
            host_session: None,
            action: Action::Tracked {
                operation_id: "abcd1234abcd1234abcd1234abcd1234".into(),
                idempotency_key: Some("synthetic-access-retry".into()),
                action: Box::new(Action::Run {
                    access_request_id: Some(81),
                    codes: Default::default(),
                    items: vec![7],
                    command: vec!["true".into()],
                    cwd: dir.path().display().to_string(),
                    purpose: "Synthetic refusal".into(),
                    path: None,
                    user_request: Some("Synthetic test".into()),
                }),
            },
        };
        let _ = operations.handle(&ctx, &request);
        let retried = operations.handle(&ctx, &request);
        assert_eq!(retried.error.unwrap().code, "access_once_unavailable");
        assert!(retried.result.is_none());
        let status = operations.handle(
            &ctx,
            &WireRequest {
                action: Action::OperationStatus {
                    operation_id: "abcd1234abcd1234abcd1234abcd1234".into(),
                },
                v: request.v,
                token: request.token.clone(),
                host_session: request.host_session.clone(),
            },
        );
        assert!(status.ok);
        assert!(status.result.is_some());
    }
}
