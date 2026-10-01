//! The endpoints of the companion listener (contract companion-v1, sections 4 to 7).
//!
//! [`handle`] takes one parsed request and gives one answer. It has no socket, so the
//! order of the checks is the order of the contract:
//!
//! - `POST /v1/pair` and `GET /v1/pair/<id>` have no request signature. They are counted
//!   in the rate limit of unsigned requests, except a pair status poll with the right
//!   proof.
//! - Every other route needs the four signed headers (section 6). An address that has
//!   used its budget of requests without a valid signature gets `429` before the vault
//!   or a signature is touched. A request that then fails any check counts as unsigned.
//!   A verified request counts against its device, and only after the signature
//!   verified and before the nonce is recorded.
//! - An approval goes through `OwnerGate::authorize` with `OwnerCheck::Companion` and
//!   then `ApprovalQueue::approve`. The server never makes a proof itself.
//!
//! Lock order: the pairing lock, then the vault mutex, then the queue mutex. The handler
//! never holds the vault mutex while it calls the queue. The gate takes the vault mutex
//! and releases it before it returns.

use std::net::IpAddr;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::crypto::{request_string, verify_ecdsa};
use super::digest::run_digest_hex;
use super::http::{Request, Response};
use super::limits::{DEVICE_PER_MINUTE, NonceCache, RateLimiter, UNSIGNED_PER_MINUTE};
use super::pairing::Pairing;
use super::wire::{
    ApproveRequest, DeviceInfo, ErrorBody, ErrorCode, InboxAccessRequest, InboxActivity,
    InboxResponse, InboxRun, OutcomeBody, PairRequest, StatusResponse, decode_fixed,
    decode_signature, is_empty_object, parse_body, parse_id, parse_nonce, parse_time_header,
    valid_device_id,
};
use crate::broker::SharedVault;
use crate::broker::approvals::{
    ApprovalQueue, ApprovalRefusal, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate,
};
use crate::vault::{Vault, VaultError, VaultErrorKind};

/// A request time may differ from the Mac time by this many seconds.
const MAX_SKEW_SECONDS: u64 = 60;
/// The newest activity entries in the inbox.
const INBOX_ACTIVITY: usize = 50;
/// The open access requests in the inbox.
const INBOX_ACCESS_REQUESTS: usize = 50;

/// What the handler needs. One value per listener, shared by the connection threads.
pub struct Shared {
    pub vault: SharedVault,
    pub approvals: Arc<ApprovalQueue>,
    pub gate: OwnerGate,
    pub pairing: Arc<Pairing>,
    pub mac_name: String,
    pub app_version: String,
    pub approval_timeout: Duration,
    /// The vault session in which the listener started. Another session gets `423`.
    pub epoch: [u8; 32],
    pub unsigned: RateLimiter<IpAddr>,
    pub devices: RateLimiter<String>,
    pub nonces: NonceCache,
}

impl Shared {
    pub fn new(
        vault: SharedVault,
        approvals: Arc<ApprovalQueue>,
        gate: OwnerGate,
        pairing: Arc<Pairing>,
        epoch: [u8; 32],
    ) -> Self {
        Self {
            vault,
            approvals,
            gate,
            pairing,
            mac_name: String::new(),
            app_version: String::new(),
            approval_timeout: Duration::from_secs(120),
            epoch,
            unsigned: RateLimiter::new(UNSIGNED_PER_MINUTE),
            devices: RateLimiter::new(DEVICE_PER_MINUTE),
            nonces: NonceCache::new(),
        }
    }

    /// The answer to a request without a valid signature. It counts against the IP
    /// address of the peer: past the limit the answer is `429`.
    pub fn unsigned_answer(&self, peer: IpAddr, response: Response) -> Response {
        if self.unsigned.admit(peer) {
            response
        } else {
            Response::error(ErrorCode::TooManyRequests)
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn error(code: ErrorCode) -> Response {
    Response::error(code)
}

/// The wire error for a vault failure. The text names no path and no cause.
fn vault_error(err: &VaultError) -> ErrorCode {
    match err.kind() {
        VaultErrorKind::Locked => ErrorCode::VaultLocked,
        _ => ErrorCode::Internal,
    }
}

/// Run `f` on the vault while the mutex is held. The vault must be unlocked and in the
/// session of the listener, else `vault_locked`.
fn with_vault<T>(
    shared: &Shared,
    f: impl FnOnce(&mut Vault) -> Result<T, ErrorCode>,
) -> Result<T, ErrorCode> {
    let mut guard = shared.vault.lock().unwrap_or_else(PoisonError::into_inner);
    match guard.as_mut() {
        Some(vault) if !vault.is_locked() && vault.epoch() == shared.epoch => f(vault),
        _ => Err(ErrorCode::VaultLocked),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Route<'a> {
    Pair,
    PairStatus(&'a str),
    Status,
    Inbox,
    Unpair,
    RunApprove(&'a str),
    RunDeny(&'a str),
    AccessDeny(&'a str),
    Unknown,
}

/// The ID in `<id>/<action>`, or `None` when the rest has another shape.
fn id_before<'a>(rest: &'a str, action: &str) -> Option<&'a str> {
    let (id, tail) = rest.split_once('/')?;
    (tail == action).then_some(id)
}

fn route<'a>(method: &str, target: &'a str) -> Route<'a> {
    match method {
        "POST" if target == "/v1/pair" => Route::Pair,
        "POST" => {
            let runs = target.strip_prefix("/v1/runs/");
            let access = target.strip_prefix("/v1/access-requests/");
            if let Some(id) = runs.and_then(|rest| id_before(rest, "approve")) {
                Route::RunApprove(id)
            } else if let Some(id) = runs.and_then(|rest| id_before(rest, "deny")) {
                Route::RunDeny(id)
            } else if let Some(id) = access.and_then(|rest| id_before(rest, "deny")) {
                Route::AccessDeny(id)
            } else {
                Route::Unknown
            }
        }
        "GET" => match target {
            "/v1/status" => Route::Status,
            "/v1/inbox" => Route::Inbox,
            _ => match target.strip_prefix("/v1/pair/") {
                Some(id) if !id.contains('/') => Route::PairStatus(id),
                _ => Route::Unknown,
            },
        },
        "DELETE" if target == "/v1/device" => Route::Unpair,
        _ => Route::Unknown,
    }
}

/// Answer one request from `peer`.
pub fn handle(shared: &Shared, peer: IpAddr, request: &Request) -> Response {
    match route(&request.method, &request.target) {
        Route::Pair => pair(shared, peer, request),
        Route::PairStatus(id) => pair_status(shared, peer, request, id),
        Route::Unknown => shared.unsigned_answer(peer, error(ErrorCode::NotFound)),
        signed => {
            // The budget is decided first: an address past it costs the Mac no vault
            // query and no signature check. The outcome is counted after the work.
            if !shared.unsigned.would_admit(&peer) {
                return error(ErrorCode::TooManyRequests);
            }
            match authenticate(shared, request) {
                Ok(device_id) => signed_route(shared, &device_id, signed, request),
                Err(Denied::Unsigned(response)) => shared.unsigned_answer(peer, response),
                Err(Denied::Limited) => error(ErrorCode::TooManyRequests),
            }
        }
    }
}

// ----- pairing, without a request signature -----

/// `POST /v1/pair` (contract 5.3).
fn pair(shared: &Shared, peer: IpAddr, request: &Request) -> Response {
    // The request has no signature, so it counts before it is read.
    if !shared.unsigned.admit(peer) {
        return error(ErrorCode::TooManyRequests);
    }
    let Some(body) = parse_body::<PairRequest>(&request.body) else {
        return error(ErrorCode::BadRequest);
    };
    // The check "is this device paired" runs last, under the pairing lock, and takes the
    // vault mutex. A locked vault answers `423` instead.
    let mut vault_answer = None;
    let result = shared.pairing.submit(&body, |device_id| {
        match with_vault(shared, |vault| {
            vault
                .companion_device(device_id)
                .map(|device| device.is_some())
                .map_err(|err| vault_error(&err))
        }) {
            Ok(paired) => paired,
            Err(code) => {
                vault_answer = Some(code);
                true
            }
        }
    });
    if let Some(code) = vault_answer {
        return error(code);
    }
    match result {
        Ok(accepted) => Response::json(&accepted),
        Err(refusal) => error(refusal.code()),
    }
}

/// `GET /v1/pair/<device_id>` (contract 5.5). A wrong format is `400`. A wrong device ID
/// or proof, or an answer that is not kept, is `404`. A poll with the right proof is not
/// counted in the rate limit.
fn pair_status(shared: &Shared, peer: IpAddr, request: &Request, device_id: &str) -> Response {
    let Some(proof) = request.header("x-apassy-pair-proof") else {
        return shared.unsigned_answer(peer, error(ErrorCode::BadRequest));
    };
    if !valid_device_id(device_id) || decode_fixed::<32>(proof).is_none() {
        return shared.unsigned_answer(peer, error(ErrorCode::BadRequest));
    }
    if !request.body.is_empty() {
        return shared.unsigned_answer(peer, error(ErrorCode::BadRequest));
    }
    match shared.pairing.status(device_id, proof) {
        Some(status) => Response::json(&status),
        None => shared.unsigned_answer(peer, error(ErrorCode::NotFound)),
    }
}

// ----- signed requests -----

enum Denied {
    /// The request has no valid signature. It counts as an unsigned answer.
    Unsigned(Response),
    /// The device used its 120 requests of this minute.
    Limited,
}

fn unsigned(code: ErrorCode) -> Denied {
    Denied::Unsigned(error(code))
}

/// The checks of contract section 6, in order. Returns the device ID.
fn authenticate(shared: &Shared, request: &Request) -> Result<String, Denied> {
    let device_id = request
        .header("x-apassy-device")
        .filter(|id| valid_device_id(id));
    let time = request.header("x-apassy-time").and_then(parse_time_header);
    let nonce = request.header("x-apassy-nonce").and_then(parse_nonce);
    let signature = request
        .header("x-apassy-signature")
        .and_then(decode_signature);
    let (Some(device_id), Some(time), Some(nonce), Some(signature)) =
        (device_id, time, nonce, signature)
    else {
        return Err(unsigned(ErrorCode::Unauthorized));
    };
    let Some(text) = request_string(
        &request.method,
        &request.target,
        device_id,
        time,
        &nonce,
        &request.body,
    ) else {
        return Err(unsigned(ErrorCode::BadRequest));
    };
    let keys = with_vault(shared, |vault| {
        vault
            .companion_device_keys(device_id)
            .map_err(|err| vault_error(&err))
    })
    .map_err(unsigned)?;
    let Some(keys) = keys else {
        return Err(unsigned(ErrorCode::Unpaired));
    };
    let now = unix_now();
    if time.abs_diff(now) > MAX_SKEW_SECONDS {
        let difference =
            i64::try_from(time).unwrap_or(i64::MAX) - i64::try_from(now).unwrap_or(i64::MAX);
        return Err(Denied::Unsigned(Response::from_body(
            ErrorCode::ClockSkew,
            &ErrorBody::clock_skew(difference),
        )));
    }
    if shared.nonces.seen(device_id, &nonce) {
        return Err(unsigned(ErrorCode::Unauthorized));
    }
    if !verify_ecdsa(&keys.request_key, text.as_bytes(), &signature) {
        return Err(unsigned(ErrorCode::Unauthorized));
    }
    // The device budget comes after the signature and before any state changes: a
    // request that gets `429` records no nonce and does not touch "last seen".
    if !shared.devices.admit(device_id.to_owned()) {
        return Err(Denied::Limited);
    }
    // Only a request that verified uses up its nonce. The insert also settles two
    // requests with one nonce that arrive together.
    if !shared.nonces.insert(device_id, nonce) {
        return Err(unsigned(ErrorCode::Unauthorized));
    }
    let known = with_vault(shared, |vault| {
        vault
            .touch_companion_device(device_id, now)
            .map_err(|err| vault_error(&err))
    })
    .map_err(unsigned)?;
    if !known {
        return Err(unsigned(ErrorCode::Unpaired));
    }
    Ok(device_id.to_owned())
}

fn signed_route(shared: &Shared, device_id: &str, route: Route<'_>, request: &Request) -> Response {
    match route {
        Route::Status if request.body.is_empty() => status(shared, device_id),
        Route::Inbox if request.body.is_empty() => inbox(shared),
        Route::Unpair if request.body.is_empty() => unpair(shared, device_id),
        Route::Status | Route::Inbox | Route::Unpair => error(ErrorCode::BadRequest),
        Route::RunApprove(id) => approve(shared, device_id, id, request),
        Route::RunDeny(id) => deny_run(shared, id, request),
        Route::AccessDeny(id) => deny_access_request(shared, id, request),
        Route::Pair | Route::PairStatus(_) | Route::Unknown => error(ErrorCode::NotFound),
    }
}

/// `GET /v1/status`.
fn status(shared: &Shared, device_id: &str) -> Response {
    let device = with_vault(shared, |vault| {
        vault
            .companion_device(device_id)
            .map_err(|err| vault_error(&err))
    });
    match device {
        Ok(Some(device)) => Response::json(&StatusResponse {
            v: super::wire::CONTRACT_VERSION,
            mac_name: shared.mac_name.clone(),
            app_version: shared.app_version.clone(),
            approval_timeout_seconds: shared.approval_timeout.as_secs(),
            device: DeviceInfo {
                id: device.device_id,
                name: device.name,
                paired_at: device.paired_at,
            },
        }),
        Ok(None) => error(ErrorCode::Unpaired),
        Err(code) => error(code),
    }
}

/// `GET /v1/inbox`. Each field comes from a type that has no secret value, no
/// placeholder, no token, no note, and no hidden detail.
fn inbox(shared: &Shared) -> Response {
    let stored = with_vault(shared, |vault| {
        let requests = vault
            .access_requests(true, INBOX_ACCESS_REQUESTS)
            .map_err(|err| vault_error(&err))?;
        let activity = vault
            .recent_activity(INBOX_ACTIVITY)
            .map_err(|err| vault_error(&err))?;
        Ok((requests, activity))
    });
    let (requests, activity) = match stored {
        Ok(stored) => stored,
        Err(code) => return error(code),
    };
    // The vault mutex is free here: the queue is read without it.
    let runs = shared
        .approvals
        .pending_with_age()
        .iter()
        .map(|(run, age)| InboxRun::from_pending(run, Some(age.as_secs())))
        .collect();
    Response::json(&InboxResponse {
        runs,
        access_requests: requests
            .iter()
            .map(InboxAccessRequest::from_request)
            .collect(),
        activity: activity.iter().map(InboxActivity::from_record).collect(),
    })
}

/// `DELETE /v1/device`.
fn unpair(shared: &Shared, device_id: &str) -> Response {
    let removed = with_vault(shared, |vault| {
        vault
            .remove_companion_device(device_id)
            .map_err(|err| vault_error(&err))
    });
    match removed {
        Ok(true) => Response::json(&OutcomeBody::unpaired()),
        Ok(false) => error(ErrorCode::Unpaired),
        Err(code) => error(code),
    }
}

/// `POST /v1/runs/<id>/deny`. A denial needs no approval signature.
fn deny_run(shared: &Shared, id: &str, request: &Request) -> Response {
    let (Some(id), true) = (parse_id(id), is_empty_object(&request.body)) else {
        return error(ErrorCode::BadRequest);
    };
    if shared.approvals.deny(id) {
        Response::json(&OutcomeBody::denied())
    } else {
        error(ErrorCode::NotWaiting)
    }
}

/// `POST /v1/access-requests/<id>/deny`. The phone can deny and cannot give access.
fn deny_access_request(shared: &Shared, id: &str, request: &Request) -> Response {
    let (Some(id), true) = (parse_id(id), is_empty_object(&request.body)) else {
        return error(ErrorCode::BadRequest);
    };
    let denied = with_vault(shared, |vault| {
        vault
            .deny_access_request(id)
            .map_err(|err| match err.kind() {
                VaultErrorKind::NotFound => ErrorCode::NotWaiting,
                _ => vault_error(&err),
            })
    });
    match denied {
        Ok(()) => Response::json(&OutcomeBody::denied()),
        Err(code) => error(code),
    }
}

/// `POST /v1/runs/<id>/approve`, with the checks of contract section 7 in order.
fn approve(shared: &Shared, device_id: &str, id: &str, request: &Request) -> Response {
    let Some(id) = parse_id(id) else {
        return error(ErrorCode::BadRequest);
    };
    let Some(body) = parse_body::<ApproveRequest>(&request.body).and_then(|body| body.validate())
    else {
        return error(ErrorCode::BadRequest);
    };
    // 1. The vault is unlocked, in the session of the listener.
    if let Err(code) = with_vault(shared, |_| Ok(())) {
        return error(code);
    }
    // 2. The run waits.
    let Some(run) = shared
        .approvals
        .pending()
        .into_iter()
        .find(|run| run.id == id)
    else {
        return error(ErrorCode::NotWaiting);
    };
    // 3. The digest is the digest of the run as it waits now.
    if run_digest_hex(&run) != body.digest {
        return error(ErrorCode::Changed);
    }
    // 4. "Approve and remember" needs an offer.
    if body.remember && run.remember.is_none() {
        return error(ErrorCode::NothingToRemember);
    }
    // 5. The gate checks the approval signature.
    let (action, outcome) = if body.remember {
        (
            OwnerAction::ApproveAndRemember(run),
            OutcomeBody::approved_and_remembered(),
        )
    } else {
        (OwnerAction::ApproveRun(run), OutcomeBody::approved())
    };
    let check = OwnerCheck::Companion {
        device_id: device_id.to_owned(),
        time: body.time,
        signature: body.approval_signature,
    };
    let proof = match shared.gate.authorize(action, check) {
        Ok(proof) => proof,
        Err(OwnerAuthError::CompanionStale) => return error(ErrorCode::Stale),
        Err(OwnerAuthError::CompanionRejected) => return error(ErrorCode::OwnerCheckFailed),
        Err(OwnerAuthError::VaultLocked | OwnerAuthError::SessionChanged) => {
            return error(ErrorCode::VaultLocked);
        }
        Err(_) => return error(ErrorCode::Internal),
    };
    // 6. The queue takes the proof for the run as it waits.
    match shared.approvals.approve(proof) {
        Ok(()) => Response::json(&outcome),
        Err(ApprovalRefusal::NotWaiting) => error(ErrorCode::NotWaiting),
        Err(ApprovalRefusal::Changed) => error(ErrorCode::Changed),
        Err(ApprovalRefusal::NothingToRemember) => error(ErrorCode::NothingToRemember),
        Err(ApprovalRefusal::Stale) => error(ErrorCode::Stale),
        Err(ApprovalRefusal::NotAnApproval) => error(ErrorCode::Internal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_match_method_and_path_exactly() {
        assert_eq!(route("POST", "/v1/pair"), Route::Pair);
        assert_eq!(route("GET", "/v1/pair/abc"), Route::PairStatus("abc"));
        assert_eq!(route("GET", "/v1/pair/"), Route::PairStatus(""));
        assert_eq!(route("GET", "/v1/status"), Route::Status);
        assert_eq!(route("GET", "/v1/inbox"), Route::Inbox);
        assert_eq!(route("DELETE", "/v1/device"), Route::Unpair);
        assert_eq!(
            route("POST", "/v1/runs/123/approve"),
            Route::RunApprove("123")
        );
        assert_eq!(route("POST", "/v1/runs/123/deny"), Route::RunDeny("123"));
        assert_eq!(
            route("POST", "/v1/access-requests/42/deny"),
            Route::AccessDeny("42")
        );
        for (method, target) in [
            ("GET", "/v1/pair"),
            ("POST", "/v1/status"),
            ("GET", "/v1/runs/123/approve"),
            ("POST", "/v1/runs/123/approve/"),
            ("POST", "/v1/runs/1/2/approve"),
            ("POST", "/v1/runs//approve/x"),
            ("POST", "/v1/runs/123"),
            ("POST", "/v1/access-requests/42/approve"),
            ("GET", "/v1/pair/a/b"),
            ("GET", "/v1/inbox?x=1"),
            ("GET", "/v1/inbox/"),
            ("PUT", "/v1/device"),
            ("DELETE", "/v1/inbox"),
            ("GET", "/"),
        ] {
            assert_eq!(route(method, target), Route::Unknown, "{method} {target}");
        }
    }
}
