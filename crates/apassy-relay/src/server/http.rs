//! The HTTP layer (docs/SPEC.md, "HTTP API").
//!
//! One accept loop, one thread per request, with limits (`config::Limits`): agent
//! paths leave a reserve of threads to members. Order for each request: `GET /healthz`;
//! the edge secret; the proxy path `/p/`; the route (404, 405); the body (413); the
//! token and its role; the endpoint. Every JSON answer is an envelope. The endpoints of
//! the owner's host (`/v1/host/...`) are not agent paths: they use the member lane.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tiny_http::{Header, Request, Response};

use crate::api::{
    self, ChallengeRequest, DecisionRequest, EDGE_HEADER, Envelope, JoinRequest, LinkRequest,
    NewItem, Policy, ReleaseRequest, RunRequest, TeamCreate, TeamCreatedRef, TokenRequest, paths,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, CollectionId, DeviceId, GrantId, ItemId, MemberId, RunId};
use crate::now_unix;
use crate::proxy::Proxy;
use crate::secret::{TokenKind, parse_token};
use crate::server::approvals::Denier;
use crate::server::auth::{self, Need, Principal};
use crate::server::hub::Hub;
use crate::server::{Core, admin, approvals, decide, devices, host, joins, mcp};

/// Seconds a client waits after 503 `busy` (`Retry-After`).
pub const BUSY_RETRY_AFTER: &str = "2";
/// Seconds between two sweeps of timed out runs and expired sessions.
const MAINTENANCE_SECS: u64 = 5;

/// The endpoints of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Me,
    TeamCreate,
    Join,
    Challenge,
    Token,
    DeviceEnroll,
    DeviceList,
    DeviceRevoke(u64),
    KeyHolder(u64),
    LinkCreate,
    Link,
    LinkList,
    LinkConfirm(u64),
    LinkRefuse(u64),
    JoinList,
    JoinConfirm(u64),
    JoinRefuse(u64),
    Leave,
    MemberRole(u64),
    InviteCreate,
    InviteList,
    MemberList,
    MemberRevoke(u64),
    CollectionCreate,
    CollectionList,
    PolicyPut(u64),
    ItemCreate,
    ItemList,
    ItemArchive(u64),
    GrantCreate,
    GrantList,
    GrantRevoke(u64),
    AgentCreate,
    AgentList,
    AgentRevoke(u64),
    ApprovalList,
    Approve(u64),
    Deny(u64),
    Audit,
    Access,
    RunCreate,
    RunGet(u64),
    HostRequests,
    HostRelease(u64),
    HostDeny(u64),
    Mcp,
}

type Routed = (Need, Endpoint);

fn pick(method: &str, choices: &[(&str, Need, Endpoint)]) -> RelayResult<Routed> {
    choices
        .iter()
        .find(|(m, _, _)| *m == method)
        .map(|(_, need, endpoint)| (*need, *endpoint))
        .ok_or_else(|| {
            RelayError::new(
                codes::METHOD_NOT_ALLOWED,
                "This path does not allow this method.",
            )
        })
}

/// Resolves a method and a path to the auth need and the endpoint.
pub fn route(method: &str, path: &str) -> RelayResult<Routed> {
    use Endpoint::*;
    let not_found = || RelayError::new(codes::NOT_FOUND, "No such path.");
    let id = |text: &str| text.parse::<u64>().map_err(|_| not_found());
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
    match segments.as_slice() {
        ["mcp"] => pick(method, &[("POST", Need::Agent, Mcp)])
            .map_err(|_| RelayError::new(codes::METHOD_NOT_ALLOWED, "MCP takes POST only.")),
        ["v1", "me"] => pick(method, &[("GET", Need::Any, Me)]),
        ["v1", "auth", "challenge"] => pick(method, &[("POST", Need::Edge, Challenge)]),
        ["v1", "auth", "token"] => pick(method, &[("POST", Need::Edge, Token)]),
        ["v1", "devices", "enroll"] => pick(method, &[("POST", Need::Member, DeviceEnroll)]),
        ["v1", "devices"] => pick(method, &[("GET", Need::Member, DeviceList)]),
        ["v1", "devices", "links"] => pick(
            method,
            &[
                ("POST", Need::Member, LinkCreate),
                ("GET", Need::Member, LinkList),
            ],
        ),
        ["v1", "devices", "link"] => pick(method, &[("POST", Need::Edge, Link)]),
        ["v1", "devices", "links", n, "confirm"] => {
            pick(method, &[("POST", Need::Member, LinkConfirm(id(n)?))])
        }
        ["v1", "devices", "links", n, "refuse"] => {
            pick(method, &[("POST", Need::Member, LinkRefuse(id(n)?))])
        }
        ["v1", "devices", n, "key-holder"] => {
            pick(method, &[("POST", Need::Owner, KeyHolder(id(n)?))])
        }
        ["v1", "devices", n] => pick(method, &[("DELETE", Need::Member, DeviceRevoke(id(n)?))]),
        ["v1", "joins"] => pick(method, &[("GET", Need::Approver, JoinList)]),
        ["v1", "joins", n, "confirm"] => {
            pick(method, &[("POST", Need::Approver, JoinConfirm(id(n)?))])
        }
        ["v1", "joins", n, "refuse"] => {
            pick(method, &[("POST", Need::Approver, JoinRefuse(id(n)?))])
        }
        ["v1", "leave"] => pick(method, &[("POST", Need::Member, Leave)]),
        ["v1", "members", n, "role"] => pick(method, &[("PUT", Need::Owner, MemberRole(id(n)?))]),
        ["v1", "join"] => pick(method, &[("POST", Need::Edge, Join)]),
        ["v1", "teams"] => pick(method, &[("POST", Need::Edge, TeamCreate)]),
        ["v1", "invites"] => pick(
            method,
            &[
                ("POST", Need::Approver, InviteCreate),
                ("GET", Need::Approver, InviteList),
            ],
        ),
        ["v1", "members"] => pick(method, &[("GET", Need::Approver, MemberList)]),
        ["v1", "members", n] => pick(method, &[("DELETE", Need::Owner, MemberRevoke(id(n)?))]),
        ["v1", "collections"] => pick(
            method,
            &[
                ("POST", Need::Approver, CollectionCreate),
                ("GET", Need::Member, CollectionList),
            ],
        ),
        ["v1", "collections", n, "policy"] => {
            pick(method, &[("PUT", Need::Approver, PolicyPut(id(n)?))])
        }
        ["v1", "items"] => pick(
            method,
            &[
                ("POST", Need::Approver, ItemCreate),
                ("GET", Need::Member, ItemList),
            ],
        ),
        ["v1", "items", n] => pick(method, &[("DELETE", Need::Approver, ItemArchive(id(n)?))]),
        ["v1", "grants"] => pick(
            method,
            &[
                ("POST", Need::Approver, GrantCreate),
                ("GET", Need::Approver, GrantList),
            ],
        ),
        ["v1", "grants", n] => pick(method, &[("DELETE", Need::Approver, GrantRevoke(id(n)?))]),
        ["v1", "agents"] => pick(
            method,
            &[
                ("POST", Need::Member, AgentCreate),
                ("GET", Need::Member, AgentList),
            ],
        ),
        ["v1", "agents", n] => pick(method, &[("DELETE", Need::Member, AgentRevoke(id(n)?))]),
        ["v1", "approvals"] => pick(method, &[("GET", Need::Approver, ApprovalList)]),
        ["v1", "approvals", n, "approve"] => {
            pick(method, &[("POST", Need::Approver, Approve(id(n)?))])
        }
        ["v1", "approvals", n, "deny"] => pick(method, &[("POST", Need::Approver, Deny(id(n)?))]),
        ["v1", "audit"] => pick(method, &[("GET", Need::Approver, Audit)]),
        ["v1", "access"] => pick(method, &[("GET", Need::Agent, Access)]),
        ["v1", "runs"] => pick(method, &[("POST", Need::Agent, RunCreate)]),
        ["v1", "runs", n] => pick(method, &[("GET", Need::Agent, RunGet(id(n)?))]),
        ["v1", "host", "requests"] => pick(method, &[("GET", Need::Owner, HostRequests)]),
        ["v1", "host", "requests", n, "release"] => {
            pick(method, &[("POST", Need::Owner, HostRelease(id(n)?))])
        }
        ["v1", "host", "requests", n, "deny"] => {
            pick(method, &[("POST", Need::Owner, HostDeny(id(n)?))])
        }
        _ => Err(not_found()),
    }
}

/// What the accept loop needs.
pub struct Serving {
    pub hub: Arc<Hub>,
    pub proxy: Arc<Proxy>,
    pub server: tiny_http::Server,
    pub stop: Arc<AtomicBool>,
}

/// True for a path that agents use: the proxy, MCP, runs, and access. These
/// requests can be slow (a long poll, a slow upstream host), so they never take the
/// slots kept for members and approvers.
pub fn is_agent_path(url: &str) -> bool {
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    path.starts_with(paths::PROXY_PREFIX)
        || path == "/mcp"
        || path == "/v1/access"
        || path == "/v1/runs"
        || path.starts_with("/v1/runs/")
}

/// The request threads in use: all of them, and those of agent paths.
struct Slots {
    all: AtomicUsize,
    agent: AtomicUsize,
}

impl Slots {
    fn release(&self, agent: bool) {
        self.all.fetch_sub(1, Ordering::Relaxed);
        if agent {
            self.agent.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Owns the global slots even if the handler panics or its thread cannot start.
struct SlotGuard {
    slots: Arc<Slots>,
    agent: bool,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.slots.release(self.agent);
    }
}

/// Owns one team's agent slot until the response and handler are complete.
struct TeamSlotGuard {
    core: Arc<Core>,
}

impl TeamSlotGuard {
    fn take(core: &Arc<Core>, now: u64) -> Option<Self> {
        let limits = core
            .team_limits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let acquired = core
            .agent_requests
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < limits.agent_requests as usize).then_some(active + 1)
            })
            .is_ok();
        drop(limits);
        if acquired {
            Some(Self { core: core.clone() })
        } else {
            let _ = core
                .store
                .with(|conn| core.limit_error_on(conn, now, "agent_requests"));
            None
        }
    }
}

impl Drop for TeamSlotGuard {
    fn drop(&mut self) {
        self.core.agent_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Accepts requests until `stop` is set. At most `max_active` requests run at
/// once, and agent paths leave `member_reserve` of them free. A request over a
/// limit gets 503 `busy` with `Retry-After`.
pub fn serve(serving: Serving) {
    let Serving {
        hub,
        proxy,
        server,
        stop,
    } = serving;
    let limits = hub.config.limits;
    let agent_max = limits.max_active.saturating_sub(limits.member_reserve);
    let slots = Arc::new(Slots {
        all: AtomicUsize::new(0),
        agent: AtomicUsize::new(0),
    });
    let mut last_maintenance = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(request)) => {
                // Only the accept loop takes a slot, so a load and an add do not race.
                let agent = is_agent_path(request.url());
                let full = slots.all.load(Ordering::Relaxed) >= limits.max_active
                    || (agent && slots.agent.load(Ordering::Relaxed) >= agent_max);
                if full {
                    respond_busy(request);
                } else {
                    slots.all.fetch_add(1, Ordering::Relaxed);
                    if agent {
                        slots.agent.fetch_add(1, Ordering::Relaxed);
                    }
                    let (hub, proxy) = (hub.clone(), proxy.clone());
                    let guard = SlotGuard {
                        slots: slots.clone(),
                        agent,
                    };
                    let _ = std::thread::Builder::new()
                        .name("relay-request".to_string())
                        .spawn(move || {
                            let _guard = guard;
                            handle(&hub, &proxy, request);
                        });
                }
            }
            Ok(None) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
        if last_maintenance.elapsed() >= Duration::from_secs(MAINTENANCE_SECS) {
            last_maintenance = Instant::now();
            for core in hub.all() {
                if approvals::maintenance(&core, now_unix())
                    .and_then(|()| devices::maintenance(&core, now_unix()))
                    .and_then(|()| joins::expire(&core, now_unix()))
                    .is_err()
                {
                    eprintln!(
                        "apassy-relay: the maintenance sweep of team {} failed",
                        core.team
                    );
                }
            }
        }
    }
}

fn header_value(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header")
}

fn no_store_header() -> Header {
    Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).expect("static header")
}

fn respond_json(request: Request, status: u16, envelope: &Envelope, close: bool) {
    let body = serde_json::to_vec(envelope).unwrap_or_default();
    let mut response = Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
        .with_header(no_store_header());
    if close && let Ok(header) = Header::from_bytes(&b"Connection"[..], &b"close"[..]) {
        response.add_header(header);
    }
    let _ = request.respond(response);
}

/// 503 `busy` as an envelope, with `Retry-After`.
fn respond_busy(request: Request) {
    let error = RelayError::new(codes::BUSY, "The relay is busy. Try again in a moment.");
    let body = serde_json::to_vec(&error.to_envelope()).unwrap_or_default();
    let mut response = Response::from_data(body)
        .with_status_code(error.status())
        .with_header(json_header())
        .with_header(no_store_header());
    if let Ok(header) = Header::from_bytes(&b"Retry-After"[..], BUSY_RETRY_AFTER.as_bytes()) {
        response.add_header(header);
    }
    let _ = request.respond(response);
}

fn respond_error(request: Request, error: &RelayError) {
    let close = error.code == codes::PAYLOAD_TOO_LARGE;
    respond_json(request, error.status(), &error.to_envelope(), close);
}

fn respond_ok(request: Request, result: Value) {
    respond_json(request, 200, &Envelope::success(result), false);
}

/// Handles one request.
fn handle(hub: &Hub, proxy: &Proxy, mut request: Request) {
    let now = now_unix();
    let method = request.method().as_str().to_string();
    let url = request.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (url.clone(), String::new()),
    };
    if method == "GET" && path == paths::HEALTH {
        let _ = request.respond(Response::from_string("ok\n"));
        return;
    }
    let edge = header_value(&request, EDGE_HEADER);
    if !auth::edge_ok(&hub.config.edge_secret, edge.as_deref()) {
        hub.refusal(
            now,
            "edge",
            "auth_failed",
            &json!({"code": codes::EDGE_REFUSED, "kind": "edge"}),
        );
        respond_error(
            request,
            &RelayError::new(
                codes::EDGE_REFUSED,
                "The request did not come through the edge.",
            ),
        );
        return;
    }
    if path.starts_with(paths::PROXY_PREFIX) {
        // Parse only: the proxy still validates and finds the session itself.
        let core = path
            .strip_prefix(paths::PROXY_PREFIX)
            .and_then(|rest| rest.split('/').next())
            .and_then(parse_token)
            .filter(|parsed| parsed.kind == TokenKind::Session)
            .and_then(|parsed| parsed.team)
            .and_then(|team| hub.team(&team));
        let _guard = if let Some(core) = core {
            match TeamSlotGuard::take(&core, now) {
                Some(guard) => Some(guard),
                None => {
                    respond_busy(request);
                    return;
                }
            }
        } else {
            None
        };
        proxy.handle(request, now);
        return;
    }
    let (need, endpoint) = match route(&method, &path) {
        Ok(routed) => routed,
        Err(error) => {
            respond_error(request, &error);
            return;
        }
    };
    // Edge endpoints choose a team only from their contract body or code.
    if matches!(
        endpoint,
        Endpoint::TeamCreate
            | Endpoint::Join
            | Endpoint::Challenge
            | Endpoint::Token
            | Endpoint::Link
    ) {
        let authorization = header_value(&request, "Authorization");
        if auth::bearer(authorization.as_deref()).is_some() {
            respond_error(request, &RelayError::unauthenticated());
            return;
        }
        let body = match read_body(&mut request, &method) {
            Ok(body) => body,
            Err(error) => {
                respond_error(request, &error);
                return;
            }
        };
        let result = dispatch_edge(hub, endpoint, &body, now);
        match result {
            Ok(result) => respond_ok(request, result),
            Err(error) => respond_error(request, &error),
        }
        return;
    }
    // Every other endpoint: the team comes from the token, before anything is opened.
    // The token is checked before the body is read and before a slot of the team is
    // taken, so a caller without a valid token cannot hold a team's slots (team ids are
    // public).
    let authorization = header_value(&request, "Authorization");
    let token = auth::bearer(authorization.as_deref());
    let Some(core) = token.and_then(|token| hub.for_token(token)) else {
        hub.refusal(
            now,
            "token",
            "auth_failed",
            &json!({"code": codes::UNAUTHENTICATED, "path_kind": endpoint_kind(endpoint)}),
        );
        respond_error(request, &RelayError::unauthenticated());
        return;
    };
    let principal = match authenticate(&core, need, token, now) {
        Ok(principal) => principal,
        Err(error) => {
            if error.code == codes::UNAUTHENTICATED || error.code == codes::TOKEN_EXPIRED {
                core.audit.refusal(
                    &core.store,
                    now,
                    "token",
                    "auth_failed",
                    &json!({"code": error.code, "path_kind": endpoint_kind(endpoint)}),
                );
            }
            respond_error(request, &error);
            return;
        }
    };
    let _guard = if is_agent_path(&path) {
        match TeamSlotGuard::take(&core, now) {
            Some(guard) => Some(guard),
            None => {
                respond_busy(request);
                return;
            }
        }
    } else {
        None
    };
    let body = match read_body(&mut request, &method) {
        Ok(body) => body,
        Err(error) => {
            respond_error(request, &error);
            return;
        }
    };
    // A body can take a long time to arrive. Read the caller again now, so a device or
    // member revoked, or a role changed, while the body was on its way counts for this
    // request too (the token was checked first only to protect the team's slots).
    let principal = if method == "POST" || method == "PUT" {
        match authenticate(&core, need, token, now_unix()) {
            Ok(principal) => principal,
            Err(error) => {
                respond_error(request, &error);
                return;
            }
        }
    } else {
        principal
    };
    if endpoint == Endpoint::Mcp {
        respond_mcp(&core, request, principal, &body);
        return;
    }
    match dispatch(&core, endpoint, principal.as_ref(), &query, &body, now) {
        Ok(result) => respond_ok(request, result),
        Err(error) => respond_error(request, &error),
    }
}

fn dispatch_edge(hub: &Hub, endpoint: Endpoint, body: &[u8], now: u64) -> RelayResult<Value> {
    match endpoint {
        Endpoint::TeamCreate => team_create(hub, body, now),
        Endpoint::Join => {
            let request: JoinRequest = parse_body(body)?;
            let code = request.code.expose();
            let core = (TokenKind::of(code) == Some(TokenKind::Invite))
                .then(|| hub.for_token(code))
                .flatten()
                .ok_or_else(admin::invite_invalid)?;
            joins::join(&core, &request, now)
        }
        Endpoint::Link => {
            let request: LinkRequest = parse_body(body)?;
            let code = request.code.expose();
            let core = (TokenKind::of(code) == Some(TokenKind::Link))
                .then(|| hub.for_token(code))
                .flatten()
                .ok_or_else(RelayError::unauthenticated)?;
            joins::link(&core, &request, now)
        }
        Endpoint::Challenge => {
            let request: ChallengeRequest = parse_body(body)?;
            let core = hub
                .team(&request.team_id)
                .ok_or_else(RelayError::unauthenticated)?;
            devices::challenge(&core, &request, now)
        }
        Endpoint::Token => {
            let request: TokenRequest = parse_body(body)?;
            let core = hub
                .team(&request.team_id)
                .ok_or_else(RelayError::unauthenticated)?;
            devices::token(&core, &request, now)
        }
        _ => Err(RelayError::internal("This endpoint needs a bearer token.")),
    }
}

/// `POST /v1/teams`.
fn team_create(hub: &Hub, body: &[u8], now: u64) -> RelayResult<Value> {
    let request: TeamCreate = parse_body(body)?;
    let (team_id, member_id, device_id) = hub.create_team(&request, now)?;
    to_value(&TeamCreatedRef {
        team_id: &team_id,
        member_id,
        secret: None,
        device_id: Some(device_id),
    })
}

/// A short name of an endpoint for the audit. No path, so no id or query leaks.
fn endpoint_kind(endpoint: Endpoint) -> &'static str {
    match endpoint {
        Endpoint::Mcp => "mcp",
        Endpoint::RunCreate | Endpoint::RunGet(_) | Endpoint::Access => "agent",
        _ => "v1",
    }
}

fn authenticate(
    core: &Core,
    need: Need,
    token: Option<&str>,
    now: u64,
) -> RelayResult<Option<Principal>> {
    if need == Need::Edge {
        return Ok(None);
    }
    let principal = match token {
        Some(token) => Some(auth::authenticate_core(core, token, now)?),
        None => None,
    };
    auth::allow(need, principal.as_ref())?;
    Ok(principal)
}

/// Reads a JSON body of at most `MAX_JSON_BODY` bytes for POST and PUT.
fn read_body(request: &mut Request, method: &str) -> RelayResult<Vec<u8>> {
    if method != "POST" && method != "PUT" {
        return Ok(Vec::new());
    }
    let too_large = || RelayError::new(codes::PAYLOAD_TOO_LARGE, "The body is larger than 64 KiB.");
    if request
        .body_length()
        .is_some_and(|len| len > api::MAX_JSON_BODY)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    request
        .as_reader()
        .take(api::MAX_JSON_BODY as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| RelayError::invalid("The body cannot be read."))?;
    if body.len() > api::MAX_JSON_BODY {
        return Err(too_large());
    }
    Ok(body)
}

fn respond_mcp(core: &Core, request: Request, principal: Option<Principal>, body: &[u8]) {
    let origin = header_value(&request, "Origin");
    if let Some(origin) = origin
        && origin.trim_end_matches('/') != core.config.public_url
    {
        respond_error(
            request,
            &RelayError::forbidden("The Origin header is not the origin of this relay."),
        );
        return;
    }
    let Some(Principal::Agent(agent)) = principal else {
        respond_error(request, &RelayError::unauthenticated());
        return;
    };
    match mcp::handle(core, &agent, body) {
        mcp::Reply::Accepted => {
            let response = Response::empty(202).with_header(no_store_header());
            let _ = request.respond(response);
        }
        mcp::Reply::Json(message) => {
            let bytes = serde_json::to_vec(&message).unwrap_or_default();
            let response = Response::from_data(bytes)
                .with_header(json_header())
                .with_header(no_store_header());
            let _ = request.respond(response);
        }
    }
}

fn parse_body<T: DeserializeOwned>(body: &[u8]) -> RelayResult<T> {
    serde_json::from_slice(body).map_err(|_| {
        RelayError::invalid("The JSON body is missing, or does not match this endpoint.")
    })
}

/// A body that may be empty: an empty body is `{}`.
fn parse_optional<T: DeserializeOwned>(body: &[u8]) -> RelayResult<T> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return parse_body(b"{}");
    }
    parse_body(body)
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn number(query: &str, name: &str) -> RelayResult<Option<u64>> {
    query_param(query, name)
        .map(|text| {
            text.parse::<u64>()
                .map_err(|_| RelayError::invalid(format!("The query value `{name}` is a number.")))
        })
        .transpose()
}

fn member_of(principal: Option<&Principal>) -> RelayResult<&auth::MemberAuth> {
    match principal {
        Some(Principal::Member(member)) => Ok(member),
        _ => Err(RelayError::unauthenticated()),
    }
}

fn agent_of(principal: Option<&Principal>) -> RelayResult<&auth::AgentAuth> {
    match principal {
        Some(Principal::Agent(agent)) => Ok(agent),
        _ => Err(RelayError::unauthenticated()),
    }
}

/// Runs one endpoint. The principal has passed `auth::allow` for its need.
fn dispatch(
    core: &Core,
    endpoint: Endpoint,
    principal: Option<&Principal>,
    query: &str,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    use Endpoint::*;
    if matches!(endpoint, HostRequests | HostRelease(_) | HostDeny(_)) {
        devices::authorize_host(core, member_of(principal)?)?;
    }
    match endpoint {
        Me => admin::me(core, principal.ok_or_else(RelayError::unauthenticated)?),
        DeviceEnroll => devices::enroll(core, member_of(principal)?, &parse_body(body)?, now),
        DeviceList => devices::list(core, member_of(principal)?),
        DeviceRevoke(id) => devices::revoke(core, member_of(principal)?, DeviceId(id), now),
        KeyHolder(id) => devices::key_holder(core, member_of(principal)?, DeviceId(id), now),
        LinkCreate => joins::links_create(core, member_of(principal)?, now),
        LinkList => joins::links_list(core, member_of(principal)?, now),
        LinkConfirm(id) => {
            joins::links_confirm(core, member_of(principal)?, id, &parse_body(body)?, now)
        }
        LinkRefuse(id) => joins::links_refuse(core, member_of(principal)?, id, now),
        JoinList => joins::list(core, now),
        JoinConfirm(id) => joins::confirm(core, member_of(principal)?, id, &parse_body(body)?, now),
        JoinRefuse(id) => joins::refuse(core, member_of(principal)?, id, now),
        Leave => admin::leave(core, member_of(principal)?, now),
        MemberRole(id) => admin::role_change(
            core,
            member_of(principal)?,
            MemberId(id),
            &parse_body(body)?,
            now,
        ),
        Join | TeamCreate | Challenge | Token | Link => {
            Err(RelayError::internal("This endpoint is served elsewhere."))
        }
        InviteCreate => admin::invite_create(core, member_of(principal)?, &parse_body(body)?, now),
        InviteList => admin::invite_list(core),
        MemberList => admin::member_list(core),
        MemberRevoke(id) => admin::member_revoke(core, member_of(principal)?, MemberId(id), now),
        CollectionCreate => {
            admin::collection_create(core, member_of(principal)?, parse_body(body)?, now)
        }
        CollectionList => admin::collection_list(core, member_of(principal)?),
        PolicyPut(id) => admin::policy_put(
            core,
            member_of(principal)?,
            CollectionId(id),
            parse_body::<Policy>(body)?,
            now,
        ),
        ItemCreate => admin::item_create(
            core,
            member_of(principal)?,
            parse_body::<NewItem>(body)?,
            now,
        ),
        ItemList => admin::item_list(
            core,
            member_of(principal)?,
            number(query, "collection")?.map(CollectionId),
        ),
        ItemArchive(id) => admin::item_archive(core, member_of(principal)?, ItemId(id), now),
        GrantCreate => admin::grant_create(core, member_of(principal)?, &parse_body(body)?, now),
        GrantList => admin::grant_list(core),
        GrantRevoke(id) => admin::grant_revoke(core, member_of(principal)?, GrantId(id), now),
        AgentCreate => admin::agent_create(core, member_of(principal)?, &parse_body(body)?, now),
        AgentList => admin::agent_list(core, member_of(principal)?),
        AgentRevoke(id) => admin::agent_revoke(core, member_of(principal)?, AgentId(id), now),
        ApprovalList => to_value(&approvals::list(core, now)?),
        // The keys are on the owner's host: nobody approves here, whatever the body is.
        Approve(_) => Err(approvals::approve_on_host()),
        Deny(id) => to_value(&approvals::deny(
            core,
            Denier::Approver(member_of(principal)?),
            RunId(id),
            &parse_optional::<DecisionRequest>(body)?,
            now,
        )?),
        Audit => {
            let after = number(query, "after")?.unwrap_or(0);
            let limit = number(query, "limit")?.unwrap_or(100);
            if !(1..=500).contains(&limit) {
                return Err(RelayError::invalid("The limit is from 1 to 500."));
            }
            admin::audit_list(core, after, limit as u32)
        }
        Access => admin::access(core, agent_of(principal)?),
        RunCreate => {
            let request: RunRequest = parse_body(body)?;
            to_value(&decide::request_run(
                core,
                agent_of(principal)?,
                &request,
                now,
            )?)
        }
        RunGet(id) => {
            let wait = number(query, "wait")?.unwrap_or(0);
            if wait > approvals::MAX_WAIT_SECS {
                return Err(RelayError::invalid("The wait is from 0 to 25 seconds."));
            }
            to_value(&approvals::get_run(
                core,
                agent_of(principal)?,
                RunId(id),
                wait,
            )?)
        }
        HostRequests => {
            let wait = number(query, "wait")?.unwrap_or(0);
            if wait > approvals::MAX_WAIT_SECS {
                return Err(RelayError::invalid("The wait is from 0 to 25 seconds."));
            }
            to_value(&host::list(core, member_of(principal)?, wait)?)
        }
        HostRelease(id) => to_value(&host::release(
            core,
            member_of(principal)?,
            RunId(id),
            &parse_body::<ReleaseRequest>(body)?,
            now,
        )?),
        HostDeny(id) => to_value(&approvals::deny(
            core,
            Denier::Host(member_of(principal)?),
            RunId(id),
            &parse_optional::<DecisionRequest>(body)?,
            now,
        )?),
        Mcp => Err(RelayError::internal("MCP is served elsewhere.")),
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("A result cannot be written."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn team_core() -> (tempfile::TempDir, Arc<Hub>, Arc<Core>) {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::config::RelayConfig::from_lookup(|name| match name {
            "APASSY_RELAY_DATA" => Some(dir.path().join("data").display().to_string()),
            "APASSY_RELAY_PUBLIC_URL" => Some("https://relay.example.test".into()),
            "APASSY_RELAY_EDGE_SECRET" => Some("synthetic-edge-secret-0123456789abcdef".into()),
            "APASSY_RELAY_KEY" => Some("synthetic-master-key-for-test".into()),
            _ => None,
        })
        .unwrap();
        crate::server::Relay::init(&config, "Test", "owner").unwrap();
        let hub = Hub::open(config, Arc::new(AtomicBool::new(false))).unwrap();
        let core = hub.all().pop().unwrap();
        (dir, hub, core)
    }

    #[test]
    fn slot_guards_release_during_unwind() {
        let (_dir, _hub, core) = team_core();
        let slots = Arc::new(Slots {
            all: AtomicUsize::new(1),
            agent: AtomicUsize::new(1),
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _global = SlotGuard {
                slots: slots.clone(),
                agent: true,
            };
            let _team = TeamSlotGuard::take(&core, now_unix()).unwrap();
            assert_eq!(core.agent_requests.load(Ordering::Relaxed), 1);
            panic!("synthetic handler panic");
        }));
        assert!(result.is_err());
        assert_eq!(slots.all.load(Ordering::Relaxed), 0);
        assert_eq!(slots.agent.load(Ordering::Relaxed), 0);
        assert_eq!(core.agent_requests.load(Ordering::Relaxed), 0);
        assert!(TeamSlotGuard::take(&core, now_unix()).is_some());
        assert_eq!(core.agent_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn limit_audit_has_an_independent_ten_second_window_per_kind() {
        let (_dir, _hub, core) = team_core();
        for (now, kind) in [
            (100, "members"),
            (105, "members"),
            (105, "items"),
            (110, "members"),
        ] {
            let error = core
                .store
                .with(|conn| core.limit_error_on(conn, now, kind))
                .unwrap();
            assert_eq!(error.code, codes::TEAM_LIMIT);
            assert!(error.message.contains(kind));
        }
        let rows = core
            .store
            .with(|conn| crate::server::audit::list(conn, 0, 100))
            .unwrap();
        let rows: Vec<_> = rows
            .iter()
            .filter(|row| row.action == "limit_reached")
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows.iter().map(|row| row.at).collect::<Vec<_>>(),
            [100, 105, 110]
        );
        assert!(rows.iter().all(|row| row.actor == "relay"));
    }

    #[test]
    fn routes_and_methods() {
        assert_eq!(route("GET", "/v1/me").unwrap(), (Need::Any, Endpoint::Me));
        assert_eq!(
            route("POST", "/v1/approvals/7/approve").unwrap(),
            (Need::Approver, Endpoint::Approve(7))
        );
        assert_eq!(
            route("DELETE", "/v1/members/3").unwrap(),
            (Need::Owner, Endpoint::MemberRevoke(3))
        );
        assert_eq!(
            route("GET", "/v1/host/requests").unwrap(),
            (Need::Owner, Endpoint::HostRequests)
        );
        assert_eq!(
            route("POST", "/v1/host/requests/7/release").unwrap(),
            (Need::Owner, Endpoint::HostRelease(7))
        );
        assert_eq!(
            route("POST", "/v1/host/requests/7/deny").unwrap(),
            (Need::Owner, Endpoint::HostDeny(7))
        );
        assert_eq!(
            route("GET", "/v1/host/requests/7/release")
                .unwrap_err()
                .code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("GET", "/v1/host/requests/x/release")
                .unwrap_err()
                .code,
            codes::NOT_FOUND
        );
        assert_eq!(
            route("GET", "/v1/join").unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("GET", "/mcp").unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("DELETE", "/mcp").unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("GET", "/v1/nothing").unwrap_err().code,
            codes::NOT_FOUND
        );
        assert_eq!(
            route("GET", "/v1/runs/abc").unwrap_err().code,
            codes::NOT_FOUND
        );
        assert_eq!(route("GET", "/v1/me/").unwrap_err().code, codes::NOT_FOUND);
    }

    #[test]
    fn agent_paths_are_the_slow_ones() {
        for url in [
            "/p/apassy_ses_x/api.example.com/v1",
            "/mcp",
            "/v1/access",
            "/v1/runs",
            "/v1/runs/7?wait=25",
        ] {
            assert!(is_agent_path(url), "{url}");
        }
        for url in [
            "/healthz",
            "/v1/approvals/7/approve",
            "/v1/approvals",
            "/v1/host/requests?wait=25",
            "/v1/host/requests/7/release",
            "/v1/me",
            "/v1/runsx",
            "/mcp/x",
            "/v1/items?x=/p/",
        ] {
            assert!(!is_agent_path(url), "{url}");
        }
    }

    #[test]
    fn query_values() {
        assert_eq!(query_param("after=3&limit=9", "limit"), Some("9"));
        assert_eq!(number("wait=12", "wait").unwrap(), Some(12));
        assert!(number("wait=x", "wait").is_err());
        assert_eq!(number("", "wait").unwrap(), None);
    }
}
