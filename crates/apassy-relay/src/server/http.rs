//! The HTTP layer (docs/SPEC.md, "HTTP API").
//!
//! One accept loop, one thread per request, with limits (`config::Limits`): agent
//! paths leave a reserve of threads to members. Order for each request: `GET /healthz`;
//! the edge secret; the proxy path `/p/`; the route (404, 405); the body (413); the
//! token and its role; the endpoint. Every JSON answer is an envelope. The endpoints of
//! the owner's host (`/v1/host/...`) are not agent paths: they use the member lane.
//! Question long polls have a lane of their own (`Limits::question_long_polls`), and feed
//! long polls another (`Limits::feed_long_polls`), apart from `max_active`, so they never
//! take the threads of the member reserve, and feed polls never take a question poll's.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tiny_http::{Header, Request, Response};

use crate::api::{
    self, CLIENT_PREFIX_HEADER, CLIENT_PREFIX_MAC_HEADER, ChallengeRequest, ConnectCreate,
    DecisionRequest, EDGE_HEADER, Envelope, JoinRequest, LinkCancel, LinkRequest, NewItem, Policy,
    ReleaseRequest, RunRequest, TeamCreate, TeamCreatedRef, TeamKind, TokenRequest, paths,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, CollectionId, DeviceId, GrantId, ItemId, MemberId, RunId};
use crate::now_unix;
use crate::proxy::Proxy;
use crate::secret::{TokenKind, parse_token};
use crate::server::approvals::Denier;
use crate::server::auth::{self, Need, Principal};
use crate::server::feed::{self, ActionId};
use crate::server::hub::Hub;
use crate::server::questions::{self, Qid};
use crate::server::sync::{PushRequest, SyncError};
use crate::server::{Core, admin, approvals, connect, decide, devices, host, joins, mcp, sync};

/// Seconds a client waits after 503 `busy` (`Retry-After`).
pub const BUSY_RETRY_AFTER: &str = "2";
/// `Retry-After` of `POST /v1/connect` when the relay made its Connect teams of the day.
pub const CONNECT_RETRY_AFTER: &str = "3600";
/// Seconds between two probes of the listener (`listener_alive`), and the failed probes
/// in a row after which the relay stops with an error, so its container restarts.
const LISTENER_PROBE_SECS: u64 = 10;
const LISTENER_PROBE_FAILURES: u32 = 3;
/// Seconds between two sweeps of timed out runs and expired sessions.
const MAINTENANCE_SECS: u64 = 5;
/// Seconds between two sweeps of a Connect team that had no request since its last one.
const IDLE_MAINTENANCE_SECS: u64 = 60;

/// The endpoints of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Me,
    TeamCreate,
    Connect,
    Join,
    Challenge,
    Token,
    DeviceEnroll,
    DeviceList,
    DeviceRevoke(u64),
    KeyHolder(u64),
    LinkCreate,
    Link,
    LinkCancel,
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
    SyncHead,
    SyncSnapshot,
    SyncPush,
    SyncReceipt,
    SyncDelete,
    QuestionPost,
    QuestionList,
    AnswerPost(Qid),
    AnswerList(Qid),
    Settle(Qid),
    PushTokenPut,
    PushTokenDelete,
    FeedPut,
    FeedList,
    FeedDelete,
    FeedActionPost,
    FeedActionList,
    FeedActionGet(ActionId),
    FeedActionSettle(ActionId),
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
        ["v1", "devices", "link", "cancel"] => pick(method, &[("POST", Need::Edge, LinkCancel)]),
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
        ["v1", "connect"] => pick(method, &[("POST", Need::Edge, Connect)]),
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
        ["v1", "sync"] => pick(method, &[("DELETE", Need::Owner, SyncDelete)]),
        ["v1", "sync", "head"] => pick(method, &[("GET", Need::Member, SyncHead)]),
        ["v1", "sync", "snapshot"] => pick(
            method,
            &[
                ("GET", Need::Member, SyncSnapshot),
                ("PUT", Need::Member, SyncPush),
            ],
        ),
        ["v1", "sync", "receipt"] => pick(method, &[("POST", Need::Member, SyncReceipt)]),
        ["v1", "questions"] => pick(
            method,
            &[
                ("POST", Need::Member, QuestionPost),
                ("GET", Need::Member, QuestionList),
            ],
        ),
        ["v1", "questions", qid, "answers"] => {
            let qid = questions::path_qid(qid)?;
            pick(
                method,
                &[
                    ("POST", Need::Member, AnswerPost(qid)),
                    ("GET", Need::Member, AnswerList(qid)),
                ],
            )
        }
        ["v1", "questions", qid, "settle"] => pick(
            method,
            &[("POST", Need::Member, Settle(questions::path_qid(qid)?))],
        ),
        ["v1", "push", "token"] => pick(
            method,
            &[
                ("PUT", Need::Member, PushTokenPut),
                ("DELETE", Need::Member, PushTokenDelete),
            ],
        ),
        ["v1", "feed"] => pick(
            method,
            &[
                ("PUT", Need::Member, FeedPut),
                ("GET", Need::Member, FeedList),
                ("DELETE", Need::Member, FeedDelete),
            ],
        ),
        ["v1", "feed", "actions"] => pick(
            method,
            &[
                ("POST", Need::Member, FeedActionPost),
                ("GET", Need::Member, FeedActionList),
            ],
        ),
        ["v1", "feed", "actions", id] => pick(
            method,
            &[(
                "GET",
                Need::Member,
                FeedActionGet(feed::path_action_id(id)?),
            )],
        ),
        ["v1", "feed", "actions", id, "settle"] => pick(
            method,
            &[(
                "POST",
                Need::Member,
                FeedActionSettle(feed::path_action_id(id)?),
            )],
        ),
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

/// The long polls that have threads of their own, apart from `max_active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollKind {
    /// `GET /v1/questions` or `GET /v1/questions/{qid}/answers` with a `wait` above 0:
    /// the question lane (`Limits::question_long_polls`, docs/SPEC.md 25.5).
    Question,
    /// `GET /v1/feed`, `GET /v1/feed/actions`, or `GET /v1/feed/actions/{id}` with a
    /// `wait` above 0: the feed lane (`Limits::feed_long_polls`, docs/SPEC.md 27.7).
    Feed,
}

/// The kind of a question or feed long poll, or `None` for any other request.
pub fn poll_kind(method: &str, url: &str) -> Option<PollKind> {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let one_segment = |rest: &str| !rest.is_empty() && !rest.contains('/');
    let waits = method == "GET"
        && query_param(query, "wait")
            .and_then(|wait| wait.parse::<u64>().ok())
            .is_some_and(|wait| wait > 0);
    if !waits {
        return None;
    }
    if path == paths::QUESTIONS
        || path
            .strip_prefix("/v1/questions/")
            .and_then(|rest| rest.strip_suffix("/answers"))
            .is_some_and(one_segment)
    {
        return Some(PollKind::Question);
    }
    let feed = path == paths::FEED
        || path == paths::FEED_ACTIONS
        || path
            .strip_prefix("/v1/feed/actions/")
            .is_some_and(one_segment);
    feed.then_some(PollKind::Feed)
}

/// True for a question long poll with a `wait` above 0 (docs/SPEC.md 25.5).
pub fn is_question_poll(method: &str, url: &str) -> bool {
    poll_kind(method, url) == Some(PollKind::Question)
}

/// The threads a request runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Health,
    Rejected,
    /// Members, approvers, the host, `/healthz`: any of `max_active`.
    Member,
    /// The proxy, MCP, runs, access: `max_active` without the member reserve.
    Agent,
    /// A question long poll: `question_long_polls`, apart from `max_active`.
    Question,
    /// A feed long poll: `feed_long_polls`, apart from `max_active` and the question
    /// lane.
    Feed,
}

/// The request threads in use: all of them, those of agent paths, and the question and
/// feed long polls (not in `all`).
struct Slots {
    all: AtomicUsize,
    agent: AtomicUsize,
    questions: AtomicUsize,
    feeds: AtomicUsize,
    health: AtomicUsize,
    rejected: AtomicUsize,
}

impl Slots {
    fn release(&self, lane: Lane) {
        match lane {
            Lane::Health => {
                self.health.fetch_sub(1, Ordering::Relaxed);
            }
            Lane::Rejected => {
                self.rejected.fetch_sub(1, Ordering::Relaxed);
            }
            Lane::Question => {
                self.questions.fetch_sub(1, Ordering::Relaxed);
            }
            Lane::Feed => {
                self.feeds.fetch_sub(1, Ordering::Relaxed);
            }
            Lane::Agent => {
                self.all.fetch_sub(1, Ordering::Relaxed);
                self.agent.fetch_sub(1, Ordering::Relaxed);
            }
            Lane::Member => {
                self.all.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// Owns the global slots even if the handler panics or its thread cannot start.
struct SlotGuard {
    slots: Arc<Slots>,
    lane: Lane,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.slots.release(self.lane);
    }
}

/// Owns one team's agent slot until the response and handler are complete.
struct TeamSlotGuard {
    core: Arc<Core>,
}

impl TeamSlotGuard {
    /// One agent slot of the team. Over `agent_requests`: `None`, and a `limit_reached`
    /// row. `checked`: the caller's token was checked. On the proxy path it was not (the
    /// session is found later), so the row is one of `Core::outside_limit`.
    fn take(core: &Arc<Core>, now: u64, checked: bool) -> Option<Self> {
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
            if checked {
                let _ = core
                    .store
                    .with(|conn| core.limit_error_on(conn, now, "agent_requests"));
            } else {
                core.outside_limit(now, "agent_requests");
            }
            None
        }
    }
}

impl Drop for TeamSlotGuard {
    fn drop(&mut self) {
        self.core.agent_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

/// True when a TCP connection to the listener at `addr` (an unspecified address as the
/// loopback) opens within a second. tiny_http accepts on a thread of its own and drops
/// the listener when that thread ends, for example when it cannot start a thread for a
/// connection (out of PIDs): then no request comes any more, and the process would stay
/// up without serving.
pub fn listener_alive(addr: std::net::SocketAddr) -> bool {
    let mut target = addr;
    if target.ip().is_unspecified() {
        target.set_ip(match target {
            std::net::SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            std::net::SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        });
    }
    std::net::TcpStream::connect_timeout(&target, Duration::from_secs(1)).is_ok()
}

/// Accepts requests until `stop` is set. At most `max_active` requests run at
/// once, and agent paths leave `member_reserve` of them free. A request over a
/// limit gets 503 `busy` with `Retry-After`. Returns an error when tiny_http's accept
/// thread ended (an accept error, or `LISTENER_PROBE_FAILURES` failed probes of the
/// listener in a row), so the process exits non-zero and `restart` brings it back.
pub fn serve(serving: Serving) -> RelayResult<()> {
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
        questions: AtomicUsize::new(0),
        feeds: AtomicUsize::new(0),
        health: AtomicUsize::new(0),
        rejected: AtomicUsize::new(0),
    });
    // The maintenance of every team runs on its own thread, so many teams never slow the
    // accept loop.
    let maintenance = {
        let (hub, stop) = (hub.clone(), stop.clone());
        std::thread::Builder::new()
            .name("relay-maintenance".to_string())
            .spawn(move || {
                let mut last = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    if last.elapsed() >= Duration::from_secs(MAINTENANCE_SECS) {
                        last = Instant::now();
                        maintain(&hub, now_unix());
                    }
                }
            })
    };
    if maintenance.is_err() {
        eprintln!("apassy-relay: the maintenance thread cannot start");
    }
    let listen = server.server_addr().to_ip();
    let mut probed = Instant::now();
    let mut failed_probes = 0;
    let mut outcome = Ok(());
    while !stop.load(Ordering::Relaxed) {
        if let Some(addr) = listen
            && probed.elapsed() >= Duration::from_secs(LISTENER_PROBE_SECS)
        {
            probed = Instant::now();
            failed_probes = if listener_alive(addr) {
                0
            } else {
                failed_probes + 1
            };
            if failed_probes >= LISTENER_PROBE_FAILURES {
                eprintln!(
                    "apassy-relay: the listener on {addr} does not accept connections any more: stopping, so the container restarts"
                );
                outcome = Err(RelayError::internal("The listener stopped."));
                break;
            }
        }
        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(request)) => {
                // Only the accept loop takes a slot, so a load and an add do not race.
                let poll = poll_kind(request.method().as_str(), request.url());
                let lane = if request.method().as_str() == "GET" && request.url() == "/healthz" {
                    Lane::Health
                } else if poll == Some(PollKind::Question)
                    && slots.questions.load(Ordering::Relaxed) < limits.question_long_polls
                {
                    Lane::Question
                } else if poll == Some(PollKind::Feed)
                    && slots.feeds.load(Ordering::Relaxed) < limits.feed_long_polls
                {
                    Lane::Feed
                } else if is_agent_path(request.url()) {
                    Lane::Agent
                } else {
                    Lane::Member
                };
                let full = match lane {
                    Lane::Health => slots.health.load(Ordering::Relaxed) >= 4,
                    Lane::Rejected => unreachable!(),
                    Lane::Question | Lane::Feed => false,
                    Lane::Agent => {
                        slots.all.load(Ordering::Relaxed) >= limits.max_active
                            || slots.agent.load(Ordering::Relaxed) >= agent_max
                    }
                    Lane::Member => slots.all.load(Ordering::Relaxed) >= limits.max_active,
                };
                if full {
                    // Never write or drain a refused body on the accept loop. A bounded
                    // refusal lane closes input first; overflow closes the transport.
                    request.abort_input();
                    if slots.rejected.load(Ordering::Relaxed) >= 8 {
                        request.abort();
                        drop(request);
                        continue;
                    }
                    slots.rejected.fetch_add(1, Ordering::Relaxed);
                    let guard = SlotGuard {
                        slots: slots.clone(),
                        lane: Lane::Rejected,
                    };
                    let _ = std::thread::Builder::new()
                        .name("relay-refusal".into())
                        .spawn(move || {
                            let _guard = guard;
                            respond_busy(request);
                        });
                } else {
                    match lane {
                        Lane::Health => {
                            slots.health.fetch_add(1, Ordering::Relaxed);
                        }
                        Lane::Rejected => unreachable!(),
                        Lane::Question => {
                            slots.questions.fetch_add(1, Ordering::Relaxed);
                        }
                        Lane::Feed => {
                            slots.feeds.fetch_add(1, Ordering::Relaxed);
                        }
                        Lane::Agent => {
                            slots.all.fetch_add(1, Ordering::Relaxed);
                            slots.agent.fetch_add(1, Ordering::Relaxed);
                        }
                        Lane::Member => {
                            slots.all.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let (hub, proxy) = (hub.clone(), proxy.clone());
                    let guard = SlotGuard {
                        slots: slots.clone(),
                        lane,
                    };
                    // Only a question or feed poll in its own lane may wait: one that
                    // overflows into the member lane is answered at once.
                    let hold = matches!(lane, Lane::Question | Lane::Feed);
                    let _ = std::thread::Builder::new()
                        .name("relay-request".to_string())
                        .spawn(move || {
                            let _guard = guard;
                            handle(&hub, &proxy, request, hold);
                        });
                }
            }
            Ok(None) => {}
            // tiny_http's accept thread sends its error and ends: nothing is accepted
            // any more.
            Err(error) => {
                eprintln!(
                    "apassy-relay: the listener failed ({error}): stopping, so the container restarts"
                );
                outcome = Err(RelayError::internal("The listener failed."));
                break;
            }
        }
    }
    if outcome.is_err() {
        stop.store(true, Ordering::Relaxed);
    }
    if let Ok(handle) = maintenance {
        let _ = handle.join();
    }
    outcome
}

/// One maintenance pass over every team: timed out runs, expired sessions, joins,
/// links, and questions, old sync heads, and a warning for a Connect team near or at its
/// file cap (`audit::watch_cap`; nothing is deleted). A Connect team with no request
/// since its last pass is passed over until `IDLE_MAINTENANCE_SECS` went by: its expiries
/// are read at request time too, so the pass only writes them down.
pub fn maintain(hub: &Hub, now: u64) {
    for core in hub.all() {
        let last_pass = core.maintained_at.load(Ordering::Relaxed);
        let idle = core.last_request.load(Ordering::Relaxed) < last_pass
            && now < last_pass.saturating_add(IDLE_MAINTENANCE_SECS);
        if core.kind == TeamKind::Connect && idle {
            continue;
        }
        core.maintained_at.store(now, Ordering::Relaxed);
        // First, so a failed sweep below does not hide a full file.
        let level = crate::server::audit::watch_cap(&core, now)
            .unwrap_or(crate::server::audit::CapLevel::Ok);
        let swept = approvals::maintenance(&core, now)
            .and_then(|()| devices::maintenance(&core, now))
            .and_then(|()| joins::expire(&core, now))
            .and_then(|()| sync::maintenance(&core, now))
            .and_then(|()| questions::maintenance(&core, now));
        // The feed sweep writes no row: it runs also when a sweep above failed (a full
        // file), so old feeds and actions still go.
        let swept = feed::maintenance(&core, now).and(swept);
        // A full file refuses the rows of a sweep too: `watch_cap` warned about it, at
        // most once an hour, so the pass does not log it again every few seconds.
        if let Err(error) = swept
            && !(error.code == codes::TEAM_LIMIT && level != crate::server::audit::CapLevel::Ok)
        {
            eprintln!(
                "apassy-relay: the maintenance sweep of team {} failed",
                core.team
            );
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
    respond_json_with(request, status, envelope, close, Vec::new());
}

/// A JSON answer with extra headers (`ETag`, `Retry-After`).
fn respond_json_with(
    request: Request,
    status: u16,
    envelope: &Envelope,
    close: bool,
    headers: Vec<Header>,
) {
    let body = serde_json::to_vec(envelope).unwrap_or_default();
    // The body is in memory: always `Content-Length`, never chunked.
    let mut response = Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
        .with_header(no_store_header())
        .with_chunked_threshold(usize::MAX);
    if close && let Ok(header) = Header::from_bytes(&b"Connection"[..], &b"close"[..]) {
        response.add_header(header);
    }
    let own_retry = headers
        .iter()
        .any(|header| header.field.equiv("Retry-After"));
    if status == 503
        && !own_retry
        && let Ok(header) = Header::from_bytes(&b"Retry-After"[..], BUSY_RETRY_AFTER.as_bytes())
    {
        response.add_header(header);
    }
    for header in headers {
        response.add_header(header);
    }
    let _ = request.respond(response);
}

/// `ETag: "<version>"`.
fn etag(version: u64) -> Option<Header> {
    Header::from_bytes(&b"ETag"[..], format!("\"{version}\"").as_bytes()).ok()
}

/// 503 `busy` as an envelope, with `Retry-After`.
fn respond_busy(request: Request) {
    request.abort_input();
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

/// Handles one request. `hold`: a question or feed long poll may wait (its own lane).
fn handle(hub: &Hub, proxy: &Proxy, mut request: Request, hold: bool) {
    let now = now_unix();
    let method = request.method().as_str().to_string();
    let url = request.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (url.clone(), String::new()),
    };
    if method == "GET" && path == paths::HEALTH {
        let version = Header::from_bytes("x-apassy-relay-version", env!("CARGO_PKG_VERSION"))
            .expect("the Cargo version is a valid header");
        let commit = Header::from_bytes(
            "x-apassy-relay-commit",
            option_env!("APASSY_RELEASE_COMMIT").unwrap_or("unknown"),
        )
        .expect("the build commit is a valid header");
        let _ = request.respond(
            Response::from_string("ok\n")
                .with_header(version)
                .with_header(commit),
        );
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
            match TeamSlotGuard::take(&core, now, false) {
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
            | Endpoint::Connect
            | Endpoint::Join
            | Endpoint::Challenge
            | Endpoint::Token
            | Endpoint::Link
            | Endpoint::LinkCancel
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
        // Only the Worker sets the client prefix, and only on `POST /v1/connect`. A
        // Worker from before its proof forwarded a client's copy, so the edge secret alone
        // does not prove it: the prefix counts only with the Worker's HMAC of it.
        let (prefix, mac) = if endpoint == Endpoint::Connect {
            (
                header_value(&request, CLIENT_PREFIX_HEADER),
                header_value(&request, CLIENT_PREFIX_MAC_HEADER),
            )
        } else {
            (None, None)
        };
        let prefix = connect::verified_prefix(
            hub.config.edge_secret.expose(),
            prefix.as_deref(),
            mac.as_deref(),
        );
        let result = dispatch_edge(hub, endpoint, &body, prefix, now);
        match result {
            Ok(result) => respond_ok(request, result),
            // The caps of Connect teams last longer than a busy moment: the daily caps an
            // hour, the count of a client prefix until the next UTC day.
            Err(error)
                if endpoint == Endpoint::Connect
                    && (error.code == codes::BUSY || error.code == codes::RATE_LIMITED) =>
            {
                let wait = if error.code == codes::BUSY {
                    CONNECT_RETRY_AFTER.to_string()
                } else {
                    connect::until_tomorrow(now).to_string()
                };
                respond_json_with(
                    request,
                    error.status(),
                    &error.to_envelope(),
                    false,
                    Header::from_bytes(&b"Retry-After"[..], wait.as_bytes())
                        .ok()
                        .into_iter()
                        .collect(),
                );
            }
            Err(error) => respond_error(request, &error),
        }
        return;
    }
    // A feed must declare its length within its cap (400, then 413) before the token is
    // read, as a push (section 27.4).
    if endpoint == Endpoint::FeedPut
        && let Err(error) = feed_length(&request)
    {
        respond_error(request, &error);
        return;
    }
    // A push answers a malformed request (400) before it reads the token (section 24.3).
    let push = if endpoint == Endpoint::SyncPush {
        match PushRequest::from_headers(|name| header_value(&request, name)) {
            Ok(push) => Some(push),
            Err(error) => {
                respond_error(request, &error);
                return;
            }
        }
    } else {
        None
    };
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
            // Anyone can send a token with the team's id: for a Connect team the row
            // goes to the relay audit, not the team's capped file.
            if error.code == codes::UNAUTHENTICATED || error.code == codes::TOKEN_EXPIRED {
                core.outside_refusal(
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
    // A Connect team has a request rate (section 26); an operator team has none.
    if let Err((error, wait)) = core.take_request(now) {
        respond_json_with(
            request,
            error.status(),
            &error.to_envelope(),
            false,
            Header::from_bytes(&b"Retry-After"[..], wait.to_string().as_bytes())
                .ok()
                .into_iter()
                .collect(),
        );
        return;
    }
    let _guard = if is_agent_path(&path) {
        match TeamSlotGuard::take(&core, now, true) {
            Some(guard) => Some(guard),
            None => {
                respond_busy(request);
                return;
            }
        }
    } else {
        None
    };
    if matches!(
        endpoint,
        Endpoint::SyncHead | Endpoint::SyncSnapshot | Endpoint::SyncPush | Endpoint::SyncDelete
    ) {
        respond_sync(
            &core, endpoint, request, principal, need, token, &query, push,
        );
        return;
    }
    let max_body = if endpoint == Endpoint::FeedPut {
        api::MAX_FEED_BODY
    } else {
        api::MAX_JSON_BODY
    };
    let body = match read_body_max(&mut request, &method, max_body) {
        Ok(body) => body,
        Err(error) => {
            respond_error(request, &error);
            return;
        }
    };
    // A body can take a long time to arrive. Read the caller again now, so a device or
    // member revoked, or a role changed, while the body was on its way counts for this
    // request too (the token was checked first only to protect the team's slots).
    let after_body = now_unix();
    let principal = if method == "POST" || method == "PUT" {
        match authenticate(&core, need, token, after_body) {
            Ok(principal) => principal,
            Err(error) => {
                respond_error(request, &error);
                return;
            }
        }
    } else {
        principal
    };
    // The question routes take the time after the body too: a slow body cannot answer
    // a question that expired while it arrived, or post one with an old clock.
    let now = if matches!(
        endpoint,
        Endpoint::QuestionPost
            | Endpoint::AnswerPost(_)
            | Endpoint::Settle(_)
            | Endpoint::PushTokenPut
            | Endpoint::FeedPut
            | Endpoint::FeedActionPost
            | Endpoint::FeedActionSettle(_)
    ) {
        after_body
    } else {
        now
    };
    if endpoint == Endpoint::Mcp {
        respond_mcp(&core, request, principal, &body);
        return;
    }
    match dispatch(
        &core,
        endpoint,
        principal.as_ref(),
        &query,
        &body,
        hold,
        now,
    ) {
        Ok(result) => respond_ok(request, result),
        Err(error) => respond_error(request, &error),
    }
}

/// The sync endpoints with headers, a streamed body, or a streamed answer (docs/SPEC.md
/// section 24.5). `PUT /v1/sync/snapshot` is the one route that bypasses `read_body` and
/// its 64 KiB cap: the snapshot streams to a temporary file. It reads the caller again
/// after the body, as every POST and PUT does.
#[allow(clippy::too_many_arguments)]
fn respond_sync(
    core: &Core,
    endpoint: Endpoint,
    mut request: Request,
    principal: Option<Principal>,
    need: Need,
    token: Option<&str>,
    query: &str,
    push: Option<PushRequest>,
) {
    let now = now_unix();
    let Ok(member) = member_of(principal.as_ref()).cloned() else {
        respond_error(request, &RelayError::unauthenticated());
        return;
    };
    let answer: Result<(Value, Option<u64>), SyncError> = match endpoint {
        Endpoint::SyncHead => (|| {
            let since = number(query, "since")?.unwrap_or(0);
            let wait = number(query, "wait")?.unwrap_or(0);
            if wait > approvals::MAX_WAIT_SECS {
                return Err(RelayError::invalid("The wait is from 0 to 25 seconds."));
            }
            let view = sync::head(core, &member, since, wait, now)?;
            Ok((to_value(&view)?, Some(view.version)))
        })()
        .map_err(SyncError::from),
        Endpoint::SyncSnapshot => {
            let snapshot = number(query, "version").and_then(|version| {
                let version = version
                    .ok_or_else(|| RelayError::invalid("The query value `version` is required."))?;
                sync::open_snapshot(core, &member, version, now)
            });
            match snapshot {
                Ok(snapshot) => {
                    let version = snapshot.version;
                    if respond_snapshot(request, snapshot) {
                        let _ = sync::record_fetch(core, &member, version, now_unix());
                    }
                }
                Err(error) => respond_error(request, &error),
            }
            return;
        }
        Endpoint::SyncPush => {
            let Some(push) = push else {
                respond_error(request, &RelayError::internal("The push has no headers."));
                return;
            };
            let reauth = || match authenticate(core, need, token, now_unix())? {
                Some(Principal::Member(member)) => Ok(member),
                _ => Err(RelayError::unauthenticated()),
            };
            sync::push(core, &member, &push, request.as_reader(), &reauth, now)
                .and_then(|view| Ok((to_value(&view)?, Some(view.version))))
        }
        Endpoint::SyncDelete => header_value(&request, "If-Match")
            .as_deref()
            .and_then(sync::parse_if_match)
            .ok_or_else(|| {
                SyncError::from(RelayError::invalid(
                    "If-Match is required: the version in quotes, such as \"3\".",
                ))
            })
            .and_then(|if_match| sync::delete(core, &member, if_match, now))
            .map(|value| (value, None)),
        _ => Err(RelayError::internal("This endpoint is served elsewhere.").into()),
    };
    match answer {
        Ok((value, version)) => respond_json_with(
            request,
            200,
            &Envelope::success(value),
            false,
            version.and_then(etag).into_iter().collect(),
        ),
        Err(SyncError { error, current }) => respond_json_with(
            request,
            error.status(),
            &error.to_envelope(),
            error.code == codes::PAYLOAD_TOO_LARGE,
            current.and_then(etag).into_iter().collect(),
        ),
    }
}

/// Streams a snapshot file with its head. True when the answer was sent.
fn respond_snapshot(request: Request, snapshot: sync::Snapshot<'_>) -> bool {
    let sync::Snapshot {
        file,
        version,
        head,
        signature,
        slot,
        ..
    } = snapshot;
    let headers = [
        Header::from_bytes(&b"Content-Type"[..], &b"application/octet-stream"[..]).ok(),
        Some(no_store_header()),
        etag(version),
        Header::from_bytes(crate::sync_head::HEAD_HEADER.as_bytes(), head.as_bytes()).ok(),
        Header::from_bytes(
            crate::sync_head::SIGNATURE_HEADER.as_bytes(),
            signature.as_bytes(),
        )
        .ok(),
    ];
    // Always `Content-Length`, never chunked: the app checks the size.
    let mut response = Response::from_file(file).with_chunked_threshold(usize::MAX);
    for header in headers.into_iter().flatten() {
        response.add_header(header);
    }
    let sent = request.respond(response).is_ok();
    // The transfer slot is held until the bytes are sent.
    drop(slot);
    sent
}

fn dispatch_edge(
    hub: &Hub,
    endpoint: Endpoint,
    body: &[u8],
    prefix: Option<&str>,
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        Endpoint::TeamCreate => team_create(hub, body, now),
        Endpoint::Connect => connect_create(hub, body, prefix, now),
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
        Endpoint::LinkCancel => {
            let request: LinkCancel = parse_body(body)?;
            let code = request.code.expose();
            let core = (TokenKind::of(code) == Some(TokenKind::Link))
                .then(|| hub.for_token(code))
                .flatten()
                .ok_or_else(RelayError::unauthenticated)?;
            joins::link_cancel(&core, &request, now)
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
        kind: None,
    })
}

/// `POST /v1/connect` (docs/SPEC.md section 26). Without the Worker's prefix header and
/// its proof the request counts as the prefix `unknown`.
fn connect_create(hub: &Hub, body: &[u8], prefix: Option<&str>, now: u64) -> RelayResult<Value> {
    let request: ConnectCreate = parse_body(body)?;
    let prefix = prefix.unwrap_or(connect::UNKNOWN_PREFIX);
    let (team_id, member_id, device_id) = hub.create_connect_team(&request, prefix, now)?;
    to_value(&TeamCreatedRef {
        team_id: &team_id,
        member_id,
        secret: None,
        device_id: Some(device_id),
        kind: Some(TeamKind::Connect),
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
    read_body_max(request, method, api::MAX_JSON_BODY)
}

/// Reads a JSON body of at most `max` bytes for POST and PUT.
fn read_body_max(request: &mut Request, method: &str, max: usize) -> RelayResult<Vec<u8>> {
    if method != "POST" && method != "PUT" {
        return Ok(Vec::new());
    }
    let too_large = || {
        RelayError::new(
            codes::PAYLOAD_TOO_LARGE,
            format!("The body is larger than {} KiB.", max / 1024),
        )
    };
    if request.body_length().is_some_and(|len| len > max) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    request
        .as_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| RelayError::invalid("The body cannot be read."))?;
    if body.len() > max {
        return Err(too_large());
    }
    Ok(body)
}

/// `PUT /v1/feed` declares its length (400 without `Content-Length` or with
/// `Transfer-Encoding`) within `MAX_FEED_BODY` (413).
fn feed_length(request: &Request) -> RelayResult<()> {
    if header_value(request, "Transfer-Encoding").is_some() {
        return Err(RelayError::invalid(
            "Send the feed with Content-Length, not Transfer-Encoding.",
        ));
    }
    match request.body_length() {
        None => Err(RelayError::invalid("Content-Length is required.")),
        Some(len) if len > api::MAX_FEED_BODY => Err(RelayError::new(
            codes::PAYLOAD_TOO_LARGE,
            "The body is larger than 352 KiB.",
        )),
        Some(_) => Ok(()),
    }
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

/// The member of a device's access token. The question and push endpoints are for
/// devices only: a member token is 401 before its body is read as a request.
fn device_member_of(principal: Option<&Principal>) -> RelayResult<&auth::MemberAuth> {
    let member = member_of(principal)?;
    if member.device.is_none() {
        return Err(RelayError::unauthenticated());
    }
    Ok(member)
}

fn agent_of(principal: Option<&Principal>) -> RelayResult<&auth::AgentAuth> {
    match principal {
        Some(Principal::Agent(agent)) => Ok(agent),
        _ => Err(RelayError::unauthenticated()),
    }
}

/// The `wait` of a query: 0 to 25 seconds.
fn wait_of(query: &str) -> RelayResult<u64> {
    let wait = number(query, "wait")?.unwrap_or(0);
    if wait > approvals::MAX_WAIT_SECS {
        return Err(RelayError::invalid("The wait is from 0 to 25 seconds."));
    }
    Ok(wait)
}

/// Runs one endpoint. The principal has passed `auth::allow` for its need. `hold`: a
/// question long poll may wait.
fn dispatch(
    core: &Core,
    endpoint: Endpoint,
    principal: Option<&Principal>,
    query: &str,
    body: &[u8],
    hold: bool,
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
        Join | TeamCreate | Connect | Challenge | Token | Link | LinkCancel => {
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
        SyncReceipt => sync::receipt(core, member_of(principal)?, &parse_body(body)?, now),
        QuestionPost => {
            questions::post(core, device_member_of(principal)?, &parse_body(body)?, now)
        }
        QuestionList => {
            let since = number(query, "since")?.unwrap_or(0);
            let wait = wait_of(query)?;
            to_value(&questions::list(
                core,
                device_member_of(principal)?,
                since,
                wait,
                hold,
            )?)
        }
        AnswerPost(qid) => questions::answer(
            core,
            device_member_of(principal)?,
            qid,
            &parse_body(body)?,
            now,
        ),
        AnswerList(qid) => {
            let after = number(query, "after")?.unwrap_or(0);
            let wait = wait_of(query)?;
            to_value(&questions::answers(
                core,
                device_member_of(principal)?,
                qid,
                after,
                wait,
                hold,
            )?)
        }
        Settle(qid) => questions::settle(
            core,
            device_member_of(principal)?,
            qid,
            &parse_body(body)?,
            now,
        ),
        PushTokenPut => {
            questions::push_token_put(core, device_member_of(principal)?, &parse_body(body)?, now)
        }
        PushTokenDelete => questions::push_token_delete(core, device_member_of(principal)?, now),
        FeedPut => feed::put(core, device_member_of(principal)?, &parse_body(body)?, now),
        FeedDelete => feed::delete(core, device_member_of(principal)?, now),
        FeedList => {
            let since = number(query, "since")?.unwrap_or(0);
            let wait = wait_of(query)?;
            to_value(&feed::list(
                core,
                device_member_of(principal)?,
                since,
                wait,
                hold,
            )?)
        }
        FeedActionPost => {
            feed::post_action(core, device_member_of(principal)?, &parse_body(body)?, now)
        }
        FeedActionList => {
            let after = number(query, "after")?.unwrap_or(0);
            let wait = wait_of(query)?;
            to_value(&feed::actions(
                core,
                device_member_of(principal)?,
                after,
                wait,
                hold,
            )?)
        }
        FeedActionGet(id) => {
            let wait = wait_of(query)?;
            to_value(&feed::status(
                core,
                device_member_of(principal)?,
                id,
                wait,
                hold,
            )?)
        }
        FeedActionSettle(id) => feed::settle(
            core,
            device_member_of(principal)?,
            id,
            &parse_body(body)?,
            now,
        ),
        SyncHead | SyncSnapshot | SyncPush | SyncDelete => {
            Err(RelayError::internal("This endpoint is served elsewhere."))
        }
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
    fn the_listener_probe_sees_a_listener_go() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(listener_alive(addr));
        drop(listener);
        assert!(!listener_alive(addr));
        // An unspecified address is probed on the loopback.
        let any = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = any.local_addr().unwrap().port();
        assert!(listener_alive(std::net::SocketAddr::from((
            [0, 0, 0, 0],
            port
        ))));
    }

    #[test]
    fn slot_guards_release_during_unwind() {
        let (_dir, _hub, core) = team_core();
        let slots = Arc::new(Slots {
            all: AtomicUsize::new(1),
            agent: AtomicUsize::new(1),
            questions: AtomicUsize::new(0),
            feeds: AtomicUsize::new(1),
            health: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _global = SlotGuard {
                slots: slots.clone(),
                lane: Lane::Agent,
            };
            let _feed = SlotGuard {
                slots: slots.clone(),
                lane: Lane::Feed,
            };
            let _team = TeamSlotGuard::take(&core, now_unix(), true).unwrap();
            assert_eq!(core.agent_requests.load(Ordering::Relaxed), 1);
            panic!("synthetic handler panic");
        }));
        assert!(result.is_err());
        assert_eq!(slots.all.load(Ordering::Relaxed), 0);
        assert_eq!(slots.agent.load(Ordering::Relaxed), 0);
        assert_eq!(slots.feeds.load(Ordering::Relaxed), 0);
        assert_eq!(core.agent_requests.load(Ordering::Relaxed), 0);
        assert!(TeamSlotGuard::take(&core, now_unix(), true).is_some());
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
        assert_eq!(
            route("PUT", "/v1/sync/snapshot").unwrap(),
            (Need::Member, Endpoint::SyncPush)
        );
        assert_eq!(
            route("GET", "/v1/sync/snapshot").unwrap(),
            (Need::Member, Endpoint::SyncSnapshot)
        );
        assert_eq!(
            route("GET", "/v1/sync/head").unwrap(),
            (Need::Member, Endpoint::SyncHead)
        );
        assert_eq!(
            route("POST", "/v1/sync/receipt").unwrap(),
            (Need::Member, Endpoint::SyncReceipt)
        );
        assert_eq!(
            route("DELETE", "/v1/sync").unwrap(),
            (Need::Owner, Endpoint::SyncDelete)
        );
        assert_eq!(
            route("POST", "/v1/devices/link/cancel").unwrap(),
            (Need::Edge, Endpoint::LinkCancel)
        );
        assert_eq!(
            route("POST", "/v1/connect").unwrap(),
            (Need::Edge, Endpoint::Connect)
        );
        for (method, path) in [
            ("GET", "/v1/connect"),
            ("GET", "/v1/sync"),
            ("POST", "/v1/sync/snapshot"),
            ("PUT", "/v1/sync/head"),
        ] {
            assert_eq!(
                route(method, path).unwrap_err().code,
                codes::METHOD_NOT_ALLOWED
            );
        }
        assert!(!is_agent_path("/v1/sync/head?since=1&wait=25"));
        let qid = Qid::parse("oKGio6SlpqeoqaqrrK2urw").unwrap();
        assert_eq!(
            route("POST", "/v1/questions").unwrap(),
            (Need::Member, Endpoint::QuestionPost)
        );
        assert_eq!(
            route("GET", "/v1/questions").unwrap(),
            (Need::Member, Endpoint::QuestionList)
        );
        assert_eq!(
            route("POST", "/v1/questions/oKGio6SlpqeoqaqrrK2urw/answers").unwrap(),
            (Need::Member, Endpoint::AnswerPost(qid))
        );
        assert_eq!(
            route("GET", "/v1/questions/oKGio6SlpqeoqaqrrK2urw/answers").unwrap(),
            (Need::Member, Endpoint::AnswerList(qid))
        );
        assert_eq!(
            route("POST", "/v1/questions/oKGio6SlpqeoqaqrrK2urw/settle").unwrap(),
            (Need::Member, Endpoint::Settle(qid))
        );
        assert_eq!(
            route("PUT", "/v1/push/token").unwrap(),
            (Need::Member, Endpoint::PushTokenPut)
        );
        assert_eq!(
            route("DELETE", "/v1/push/token").unwrap(),
            (Need::Member, Endpoint::PushTokenDelete)
        );
        assert_eq!(
            route("POST", "/v1/questions/short/answers")
                .unwrap_err()
                .code,
            codes::INVALID_REQUEST
        );
        for (method, path) in [
            ("PUT", "/v1/questions"),
            ("GET", "/v1/questions/oKGio6SlpqeoqaqrrK2urw/settle"),
            ("DELETE", "/v1/questions/oKGio6SlpqeoqaqrrK2urw/answers"),
            ("GET", "/v1/push/token"),
        ] {
            assert_eq!(
                route(method, path).unwrap_err().code,
                codes::METHOD_NOT_ALLOWED
            );
        }
        assert_eq!(
            route("GET", "/v1/questions/oKGio6SlpqeoqaqrrK2urw")
                .unwrap_err()
                .code,
            codes::NOT_FOUND
        );
        let action = ActionId::parse("sLGys7S1tre4ubq7vL2-vw").unwrap();
        for (method, path, endpoint) in [
            ("PUT", "/v1/feed", Endpoint::FeedPut),
            ("GET", "/v1/feed", Endpoint::FeedList),
            ("DELETE", "/v1/feed", Endpoint::FeedDelete),
            ("POST", "/v1/feed/actions", Endpoint::FeedActionPost),
            ("GET", "/v1/feed/actions", Endpoint::FeedActionList),
            (
                "GET",
                "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw",
                Endpoint::FeedActionGet(action),
            ),
            (
                "POST",
                "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw/settle",
                Endpoint::FeedActionSettle(action),
            ),
        ] {
            assert_eq!(route(method, path).unwrap(), (Need::Member, endpoint));
        }
        for (method, path) in [
            ("POST", "/v1/feed"),
            ("DELETE", "/v1/feed/actions"),
            ("POST", "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw"),
            ("GET", "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw/settle"),
        ] {
            assert_eq!(
                route(method, path).unwrap_err().code,
                codes::METHOD_NOT_ALLOWED
            );
        }
        assert_eq!(
            route("GET", "/v1/feed/actions/short").unwrap_err().code,
            codes::INVALID_REQUEST
        );
        assert_eq!(
            route("GET", "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw/x")
                .unwrap_err()
                .code,
            codes::NOT_FOUND
        );
        assert!(!is_agent_path("/v1/feed?since=0&wait=25"));
    }

    #[test]
    fn question_and_feed_polls_are_gets_with_a_wait() {
        for (method, url, kind) in [
            ("GET", "/v1/questions?since=3&wait=25", PollKind::Question),
            ("GET", "/v1/questions?wait=1", PollKind::Question),
            (
                "GET",
                "/v1/questions/oKGio6SlpqeoqaqrrK2urw/answers?after=0&wait=25",
                PollKind::Question,
            ),
            ("GET", "/v1/feed?since=3&wait=25", PollKind::Feed),
            ("GET", "/v1/feed/actions?after=0&wait=1", PollKind::Feed),
            (
                "GET",
                "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw?wait=25",
                PollKind::Feed,
            ),
        ] {
            assert_eq!(poll_kind(method, url), Some(kind), "{method} {url}");
            assert_eq!(
                is_question_poll(method, url),
                kind == PollKind::Question,
                "{method} {url}"
            );
        }
        for (method, url) in [
            ("GET", "/v1/questions"),
            ("GET", "/v1/questions?since=3&wait=0"),
            ("GET", "/v1/questions?wait=x"),
            ("POST", "/v1/questions?wait=25"),
            ("GET", "/v1/questions/x/settle?wait=25"),
            ("GET", "/v1/questions//answers?wait=25"),
            ("GET", "/v1/questions/a/b/answers?wait=25"),
            ("GET", "/v1/sync/head?wait=25"),
            ("GET", "/v1/questionsx?wait=25"),
            ("GET", "/v1/feed?since=3&wait=0"),
            ("PUT", "/v1/feed?wait=25"),
            ("POST", "/v1/feed/actions?wait=25"),
            ("GET", "/v1/feed/actions/a/settle?wait=25"),
            ("GET", "/v1/feed/actions/?wait=25"),
            ("GET", "/v1/feedx?wait=25"),
        ] {
            assert_eq!(poll_kind(method, url), None, "{method} {url}");
        }
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
