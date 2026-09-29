//! The HTTP layer (docs/SPEC.md, "HTTP API").
//!
//! One accept loop, one thread per request, with limits (`config::Limits`): agent
//! paths leave a reserve of threads to members. Order for each request: `GET /healthz`;
//! the edge secret; the proxy path `/p/`; the route (404, 405); the body (413); the
//! token and its role; the endpoint. Every JSON answer is an envelope.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tiny_http::{Header, Request, Response};

use crate::api::{
    self, DecisionRequest, EDGE_HEADER, Envelope, JoinRequest, NewItem, Policy, RunRequest, paths,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, CollectionId, GrantId, ItemId, MemberId, RunId};
use crate::now_unix;
use crate::proxy::Proxy;
use crate::server::auth::{self, Need, Principal};
use crate::server::{Core, admin, approvals, decide, mcp};

/// Seconds a client waits after 503 `busy` (`Retry-After`).
pub const BUSY_RETRY_AFTER: &str = "2";
/// Seconds between two sweeps of timed out runs and expired sessions.
const MAINTENANCE_SECS: u64 = 5;

/// The endpoints of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Me,
    Join,
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
        ["v1", "join"] => pick(method, &[("POST", Need::Edge, Join)]),
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
        _ => Err(not_found()),
    }
}

/// What the accept loop needs.
pub struct Serving {
    pub core: Arc<Core>,
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

/// Accepts requests until `stop` is set. At most `max_active` requests run at
/// once, and agent paths leave `member_reserve` of them free. A request over a
/// limit gets 503 `busy` with `Retry-After`.
pub fn serve(serving: Serving) {
    let Serving {
        core,
        proxy,
        server,
        stop,
    } = serving;
    let limits = core.config.limits;
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
                    let (core, proxy, held) = (core.clone(), proxy.clone(), slots.clone());
                    let spawned = std::thread::Builder::new()
                        .name("relay-request".to_string())
                        .spawn(move || {
                            handle(&core, &proxy, request);
                            held.release(agent);
                        });
                    if spawned.is_err() {
                        slots.release(agent);
                    }
                }
            }
            Ok(None) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
        if last_maintenance.elapsed() >= Duration::from_secs(MAINTENANCE_SECS) {
            last_maintenance = Instant::now();
            if approvals::maintenance(&core, now_unix()).is_err() {
                eprintln!("apassy-relay: the maintenance sweep failed");
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
fn handle(core: &Core, proxy: &Proxy, mut request: Request) {
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
    if !auth::edge_ok(&core.config.edge_secret, edge.as_deref()) {
        core.audit.refusal(
            &core.store,
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
    let body = match read_body(&mut request, &method) {
        Ok(body) => body,
        Err(error) => {
            respond_error(request, &error);
            return;
        }
    };
    let authorization = header_value(&request, "Authorization");
    let principal = match authenticate(core, need, authorization.as_deref(), now) {
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
    if endpoint == Endpoint::Mcp {
        respond_mcp(core, request, principal, &body);
        return;
    }
    match dispatch(core, endpoint, principal.as_ref(), &query, &body, now) {
        Ok(result) => respond_ok(request, result),
        Err(error) => respond_error(request, &error),
    }
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
    authorization: Option<&str>,
    now: u64,
) -> RelayResult<Option<Principal>> {
    if need == Need::Edge {
        return Ok(None);
    }
    let principal = match auth::bearer(authorization) {
        Some(token) => Some(
            core.store
                .with(|conn| auth::authenticate(conn, token, now))?,
        ),
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
    match endpoint {
        Me => admin::me(core, principal.ok_or_else(RelayError::unauthenticated)?),
        Join => admin::join(core, &parse_body::<JoinRequest>(body)?, now),
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
        Approve(id) => to_value(&approvals::approve(
            core,
            member_of(principal)?,
            RunId(id),
            &parse_optional::<DecisionRequest>(body)?,
            now,
        )?),
        Deny(id) => to_value(&approvals::deny(
            core,
            member_of(principal)?,
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
        Mcp => Err(RelayError::internal("MCP is served elsewhere.")),
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("A result cannot be written."))
}

#[cfg(test)]
mod tests {
    use super::*;

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
