//! The one transport of the questions, the feed, the access requests, and relay sync
//! (ADR 0037 stage 7, plan s7 unit I2; ios-core-v1 section 5.15; contracts
//! connect-tunnel-v1 section 3.3 and node-pairing-v1 section 7a).
//!
//! Every relay call of the core goes through `apassy::sync`'s relay client to a
//! [`RelayUrl`]. This module gives those addresses their second route: a pinned node whose
//! pairing code carried a Connect route (`alt=…,wss://<Connect>/v1/tunnel/dial/<node>`)
//! gets the [`Routes`] of this core as its [`TunnelDialer`]. The questions and the feed
//! and the access requests (their members, [`Transport::member`]), the joins
//! ([`Transport::dialer`]), and relay sync ([`Transport::config`]) all take it here, so
//! one route order and one state hold for all of them.
//!
//! **Route order.** The tailnet first: the node origin and its alternatives, as before.
//! When none connects, the dial: `GET /v1/tunnel/dial/{node}` at the account's Connect
//! origin with the account token of `connect.rs` (unit I1), and then, inside that byte
//! pipe, the **same** pinned TLS 1.3 handshake to the node as on the tailnet (the relay
//! client runs it, with the pin of the pairing): Connect sees TLS records only and can
//! neither read nor change a request; a wrong certificate ends the dial before any
//! request byte. While the tailnet failed recently the dial goes first, and a probe in
//! the background (a pinned TLS handshake, no request, no token) brings the requests back
//! to the tailnet as soon as it answers again.
//!
//! **States.** A refusal of the dial holds the next dial back, so no request makes a
//! storm of dials: `403 plan_required` (and no account) is `not_on_connect` for 15
//! minutes, `503 tunnel_offline` (the Mac has no tunnel open) is `mac_offline` and
//! `429 tunnel_limit` is `limit`, each with its own wait, and an unreachable Connect
//! waits 1 s, doubling, at most 60 s. None of them is an error to show, and none names a
//! plan, a price, or a purchase (plan section 6). `connect_status` reports the state and
//! whether the Mac is reached through Connect now (`dial_route`).
//!
//! **The pipe.** One dial for each connection of the relay client. A reader thread turns
//! the WebSocket messages into bytes and answers Connect's pings; a ping thread pings
//! every 30 s and ends a dial that hears nothing for 90 s (contract 3.2 and 8), so a long
//! poll keeps its dial through Cloudflare and Connect. `lock` and `suspend` end every
//! dial at once ([`Transport::close`]), and the relay client's cancel ends the dial of
//! its request.
//!
//! **One dial for requests that follow each other.** The relay client keeps the pinned
//! connection inside a dial open after a complete answer ([`KeptDials`], one for each
//! node), and the next request to that node through the dial takes it: no new dial, no
//! new TLS handshake, so a burst of requests stays far below Connect's 60 dials a minute.
//! A kept dial closes after [`Timing::kept_idle`] (30 s) without a request, below the
//! node's 45 s wait for the next request; at `lock` and `suspend` with every other dial;
//! and when Connect or the node ends it. A long poll always has a dial of its own. When a
//! kept dial turns out dead, a request that did not reach it, and a read (`GET`) that
//! did, take a fresh dial; any other request fails as a broken connection does (it may
//! have reached the Mac).
//!
//! The WebSocket and its codec are the relay crate's own (`apassy::node::tunnel::ws`,
//! compiled from `crates/apassy-relay/src/server/tunnel/ws.rs`), and the TLS socket to
//! Connect is the node's (`apassy::node::tunnel::open_socket`): no second codec and no
//! new crypto. The account token goes only into the `Authorization` of the dial to the
//! account's own Connect origin, and a route through another host is never dialled.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use apassy::broker::http::{TlsClient, parse_destination};
use apassy::connect::ConnectError;
use apassy::node::tunnel::ws::{self, Message, client, close};
use apassy::node::tunnel::{Socket, frame, open_socket};
use apassy::sync::{
    HttpError, KEPT_DIAL_IDLE, KeptDials, NodeRoute, RelayConfig, RelayMember, RelayUrl,
    TunnelDialer, TunnelPipe, TunnelRoute, membership_relay_url, probe_direct,
};
use apassy::vault::RelayMembership;
use zeroize::Zeroizing;

use super::connect::Accounts;
use super::errors::CoreResult;
use super::guard;

/// The dial pings this often (contract 3.2: 30 s).
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
/// A dial that hears nothing for this long ends (contract 3.2: 90 s).
pub const IDLE_LIMIT: Duration = Duration::from_secs(90);
/// The first wait after a failed dial (contract 3.2: 1 s, doubling).
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);
/// The longest wait after failed dials (contract 3.2: at most 60 s).
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// No dial for this long after `403 plan_required`, or without an account.
pub const NOT_ON_CONNECT_WAIT: Duration = Duration::from_secs(15 * 60);
/// No dial for this long after `429 tunnel_limit`.
pub const LIMIT_WAIT: Duration = Duration::from_secs(60);
/// While the dial goes first, the tailnet is probed again this often.
pub const PROBE_EVERY: Duration = Duration::from_secs(30);
/// One probe of the tailnet ends within this.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bytes buffered from Connect toward the TLS of one dial (contract 4: 256 KiB).
const PIPE_BUFFER: usize = 256 * 1024;
/// How often a dial on its way looks at its deadline.
const STEP: Duration = Duration::from_millis(25);

/// The times of the dial. The product uses [`Timing::default`]; tests shorten them
/// (`Core::with_dial_timing`) so that "90 s of silence" or "15 minutes" fit a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub ping: Duration,
    pub idle: Duration,
    pub backoff_first: Duration,
    pub backoff_max: Duration,
    pub not_on_connect: Duration,
    pub limit: Duration,
    pub probe_every: Duration,
    /// A kept dial without a request closes after this ([`KEPT_DIAL_IDLE`]).
    pub kept_idle: Duration,
    /// Tests only: the dial neither pings nor answers Connect's pings, to show what the
    /// pings keep alive. Always false in the product.
    pub silent: bool,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ping: PING_INTERVAL,
            idle: IDLE_LIMIT,
            backoff_first: BACKOFF_FIRST,
            backoff_max: BACKOFF_MAX,
            not_on_connect: NOT_ON_CONNECT_WAIT,
            limit: LIMIT_WAIT,
            probe_every: PROBE_EVERY,
            kept_idle: KEPT_DIAL_IDLE,
            silent: false,
        }
    }
}

/// The state of the dial, as `connect_status` reports it (`dial_state`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DialState {
    /// No dial was needed (or none since the last lock).
    #[default]
    Unused,
    /// The last dial reached the node.
    Connected,
    /// `403 plan_required`, `403 account_required`, or no Connect account on this
    /// iPhone: no dial for 15 minutes.
    NotOnConnect,
    /// `503 tunnel_offline` or `404 node_unknown`: the Mac has no tunnel open now.
    MacOffline,
    /// `429 tunnel_limit` (or `rate_limited`): a limit of the account.
    Limit,
    /// Connect did not answer.
    Unreachable,
    /// Another refusal (`not_in_group`, a sign-in that Connect does not accept).
    Refused,
}

impl DialState {
    /// The wire text of ios-core-v1 section 5.15.
    pub fn text(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Connected => "connected",
            Self::NotOnConnect => "not_on_connect",
            Self::MacOffline => "mac_offline",
            Self::Limit => "limit",
            Self::Unreachable => "unreachable",
            Self::Refused => "refused",
        }
    }
}

/// Why one dial failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// `401`: the account seam signs in again once.
    Unauthenticated,
    NotOnConnect,
    MacOffline,
    Limit,
    Unreachable,
    Refused,
}

impl Failure {
    fn state(self) -> DialState {
        match self {
            Self::NotOnConnect => DialState::NotOnConnect,
            Self::MacOffline => DialState::MacOffline,
            Self::Limit => DialState::Limit,
            Self::Unreachable => DialState::Unreachable,
            Self::Refused | Self::Unauthenticated => DialState::Refused,
        }
    }
}

/// The route memory of one pinned node origin.
#[derive(Debug, Default)]
struct NodeMemory {
    /// The route of its last connection, since the last lock.
    route: Option<NodeRoute>,
    /// When its direct destinations last failed; `None` while they work.
    direct_failed_at: Option<Instant>,
    /// When its last probe started.
    probe_at: Option<Instant>,
    probing: bool,
}

#[derive(Debug, Default)]
struct Memory {
    state: DialState,
    /// No dial before this.
    hold_until: Option<Instant>,
    /// The last wait of the backoff; `None` after a dial that worked.
    backoff: Option<Duration>,
    nodes: BTreeMap<String, NodeMemory>,
}

/// The routes of one core: its account, its times, and its open dials. It is the
/// [`TunnelDialer`] of every pinned address of the core with a Connect route.
pub struct Routes {
    me: Weak<Routes>,
    accounts: Arc<Accounts>,
    timing: Mutex<Timing>,
    memory: Mutex<Memory>,
    /// The ends of the dials that are open or on their way.
    pipes: Mutex<BTreeMap<u64, Arc<dyn Fn() + Send + Sync>>>,
    next_pipe: AtomicU64,
    /// The dials that reached Connect (a handshake was sent): for the tests and the
    /// diagnostics.
    dials: AtomicU64,
    /// Counts each close (a lock, a suspend): a dial on its way when one came ends.
    closes: AtomicU64,
    /// The pinned connections of finished requests, kept open in their dials.
    kept: KeptDials,
}

/// The transport of a core ([`Routes`] and whether this process dials at all: only the
/// app; the AutoFill extension and the Apple Watch never do).
pub struct Transport {
    routes: Arc<Routes>,
    dials: bool,
}

impl Transport {
    /// The transport of a core with the account `accounts`; `dials`: this process may
    /// dial (the role `app`).
    pub fn new(accounts: Arc<Accounts>, dials: bool) -> Self {
        let routes = Arc::new_cyclic(|me| Routes {
            me: me.clone(),
            accounts,
            timing: Mutex::new(Timing::default()),
            memory: Mutex::new(Memory::default()),
            pipes: Mutex::new(BTreeMap::new()),
            next_pipe: AtomicU64::new(1),
            dials: AtomicU64::new(0),
            closes: AtomicU64::new(0),
            kept: KeptDials::new(),
        });
        Self { routes, dials }
    }

    /// The dialer of the addresses of this core, when it dials.
    pub fn dialer(&self) -> Option<Arc<dyn TunnelDialer>> {
        self.dials
            .then(|| Arc::clone(&self.routes) as Arc<dyn TunnelDialer>)
    }

    /// `url` with the dialer of this core: its Connect route, when it has one, is the
    /// second route after the tailnet.
    pub fn url(&self, url: RelayUrl) -> RelayUrl {
        match self.dialer() {
            Some(dialer) => url.with_dialer(dialer),
            None => url,
        }
    }

    /// The device of the relay membership `membership` with its pin, its alternatives,
    /// and its Connect route (node-pairing-v1 section 9): the member of the questions,
    /// the feed, and the access requests of a vault.
    pub fn member(&self, membership: &RelayMembership) -> CoreResult<RelayMember> {
        Ok(RelayMember::with_url(
            self.url(membership_relay_url(membership)?),
            &membership.team_id,
            membership.device_id,
            membership.key_pkcs8.clone(),
        )?)
    }

    /// The relay sync layout `config` with the dialer of this core.
    pub fn config(&self, config: RelayConfig) -> RelayConfig {
        match self.dialer() {
            Some(dialer) => config.with_dialer(dialer),
            None => config,
        }
    }

    /// `lock` and `suspend`: every dial ends at once, also one on its way and every kept
    /// one (its connection leaves memory), and the route memory starts again (no route
    /// is "in use" after a lock). The waits of the states stay, so an unlock makes no
    /// storm of dials.
    pub fn close(&self) {
        self.routes.closes.fetch_add(1, Ordering::SeqCst);
        let ends: Vec<_> = std::mem::take(&mut *guard(&self.routes.pipes))
            .into_values()
            .collect();
        for end in ends {
            end();
        }
        self.routes.kept.clear();
        let mut memory = guard(&self.routes.memory);
        for node in memory.nodes.values_mut() {
            node.route = None;
        }
        if memory.state == DialState::Connected {
            memory.state = DialState::Unused;
        }
    }

    /// True when the last connection to a node went through Connect, since the last
    /// lock: "Reaches your Mac through: Apassy Connect".
    pub fn dial_route(&self) -> bool {
        guard(&self.routes.memory)
            .nodes
            .values()
            .any(|node| node.route == Some(NodeRoute::Tunnel))
    }

    /// The state of the dial.
    pub fn dial_state(&self) -> DialState {
        guard(&self.routes.memory).state
    }

    /// Other times (tests).
    pub fn set_timing(&self, timing: Timing) {
        self.routes.kept.set_idle(timing.kept_idle);
        *guard(&self.routes.timing) = timing;
    }

    /// The dials that reached Connect since the start (tests).
    pub fn dials(&self) -> u64 {
        self.routes.dials.load(Ordering::SeqCst)
    }
}

impl Routes {
    fn timing(&self) -> Timing {
        *guard(&self.timing)
    }

    /// The memory after one dial: a dial that worked ends the backoff; a refusal holds
    /// the next dial back by its own wait.
    fn after_dial(&self, failure: Option<Failure>) {
        let timing = self.timing();
        let mut memory = guard(&self.memory);
        let Some(failure) = failure else {
            memory.backoff = None;
            memory.hold_until = None;
            return;
        };
        let wait = match failure {
            Failure::NotOnConnect | Failure::Refused | Failure::Unauthenticated => {
                timing.not_on_connect
            }
            Failure::Limit => timing.limit,
            Failure::MacOffline | Failure::Unreachable => {
                let next = memory.backoff.map_or(timing.backoff_first, |last| {
                    last.saturating_mul(2).min(timing.backoff_max)
                });
                memory.backoff = Some(next);
                next
            }
        };
        memory.state = failure.state();
        memory.hold_until = Some(Instant::now() + wait);
    }

    /// The state of a close code that Connect sent during a dial (contract 4).
    fn closed_with(&self, code: u16) {
        let failure = match code {
            close::NODE_OFFLINE => Failure::MacOffline,
            close::TUNNEL_LIMIT => Failure::Limit,
            close::REVOKED => Failure::NotOnConnect,
            _ => return,
        };
        self.after_dial(Some(failure));
    }

    fn register(&self, end: Arc<dyn Fn() + Send + Sync>) -> u64 {
        let id = self.next_pipe.fetch_add(1, Ordering::SeqCst);
        guard(&self.pipes).insert(id, end);
        id
    }

    fn replace(&self, id: u64, end: Arc<dyn Fn() + Send + Sync>) -> bool {
        match guard(&self.pipes).get_mut(&id) {
            Some(slot) => {
                *slot = end;
                true
            }
            None => false,
        }
    }

    fn unregister(&self, id: u64) {
        guard(&self.pipes).remove(&id);
    }

    /// Probe the tailnet of `url` in the background; when it answers, the next
    /// connection takes it again.
    fn probe(&self, url: RelayUrl) {
        let Some(me) = self.me.upgrade() else {
            return;
        };
        let origin = url.as_str().to_owned();
        let failed_origin = origin.clone();
        let started = thread::Builder::new()
            .name("apassy-route-probe".to_owned())
            .spawn(move || {
                let answered = probe_direct(&url, PROBE_TIMEOUT).is_ok();
                let mut memory = guard(&me.memory);
                if let Some(node) = memory.nodes.get_mut(&origin) {
                    node.probing = false;
                    if answered {
                        node.direct_failed_at = None;
                    }
                }
            });
        if started.is_err() {
            let mut memory = guard(&self.memory);
            if let Some(node) = memory.nodes.get_mut(&failed_origin) {
                node.probing = false;
            }
        }
    }

    /// Open the dial of `route` at `origin` with `token`, before `deadline`.
    fn open(
        &self,
        origin: &str,
        route: &TunnelRoute,
        token: &str,
        deadline: Instant,
        closes: u64,
    ) -> Result<DialPipe, Failure> {
        let destination = parse_destination(origin).map_err(|_| Failure::Refused)?;
        let tls = platform_tls().ok_or(Failure::Unreachable)?;
        let mut socket: Socket =
            open_socket(&destination, tls, deadline).map_err(|_| Failure::Unreachable)?;
        let id = self.register(Arc::clone(&socket.shutdown));
        let failed = |socket: &Socket, failure: Failure| {
            (socket.shutdown)();
            self.unregister(id);
            Err(failure)
        };
        if self.closes.load(Ordering::SeqCst) != closes {
            // A lock came while the connection was on its way.
            return failed(&socket, Failure::Unreachable);
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        let key = client::new_key();
        let request = Zeroizing::new(client::request(
            &destination.host_header(),
            &route.dial_path(),
            &key,
            Some(token),
        ));
        let sent = socket
            .writer
            .write_all(&request)
            .and_then(|()| socket.writer.flush());
        drop(request);
        if sent.is_err() {
            return failed(&socket, Failure::Unreachable);
        }
        // The answer comes before the deadline, or the socket ends.
        let answered = Arc::new(AtomicBool::new(false));
        let watch = {
            let answered = Arc::clone(&answered);
            let shutdown = Arc::clone(&socket.shutdown);
            thread::Builder::new()
                .name("apassy-dial-handshake".to_owned())
                .spawn(move || {
                    while !answered.load(Ordering::SeqCst) {
                        if Instant::now() >= deadline {
                            shutdown();
                            return;
                        }
                        thread::sleep(STEP);
                    }
                })
        };
        let Ok(watch) = watch else {
            return failed(&socket, Failure::Unreachable);
        };
        let result = client::finish(&mut socket.reader, &key);
        answered.store(true, Ordering::SeqCst);
        let _ = watch.join();
        match result {
            Ok(()) => {}
            Err(client::HandshakeError::Refused(refused)) => {
                return failed(&socket, refusal(refused.status, &refused.body));
            }
            Err(_) => return failed(&socket, Failure::Unreachable),
        }
        if self.closes.load(Ordering::SeqCst) != closes {
            return failed(&socket, Failure::Unreachable);
        }
        let pipe = DialPipe::start(socket, self.timing(), id, self.me.clone());
        if !self.replace(id, pipe.closer()) {
            // A close took the dial in between: it ends now.
            return Err(Failure::Unreachable);
        }
        Ok(pipe)
    }
}

/// The failure of a refused dial (contract 3.3, in its order of checks).
fn refusal(status: u16, body: &[u8]) -> Failure {
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["error"]["code"].as_str().map(str::to_owned))
        .unwrap_or_default();
    match (status, code.as_str()) {
        (401, _) => Failure::Unauthenticated,
        (403, "plan_required" | "account_required") => Failure::NotOnConnect,
        (404, _) | (503, "tunnel_offline") => Failure::MacOffline,
        (429, _) => Failure::Limit,
        (503, _) | (500..=599, _) => Failure::Unreachable,
        _ => Failure::Refused,
    }
}

/// The TLS client of the Connect origin: the platform roots.
fn platform_tls() -> Option<&'static TlsClient> {
    static TLS: OnceLock<Option<TlsClient>> = OnceLock::new();
    TLS.get_or_init(|| TlsClient::platform().ok()).as_ref()
}

impl TunnelDialer for Routes {
    fn direct_first(&self, url: &RelayUrl) -> bool {
        let probe_every = self.timing().probe_every;
        let due = {
            let mut memory = guard(&self.memory);
            let node = memory.nodes.entry(url.as_str().to_owned()).or_default();
            if node.direct_failed_at.is_none() {
                return true;
            }
            let due = !node.probing && node.probe_at.is_none_or(|at| at.elapsed() >= probe_every);
            if due {
                node.probing = true;
                node.probe_at = Some(Instant::now());
            }
            due
        };
        if due {
            self.probe(url.clone());
        }
        false
    }

    fn reached(&self, url: &RelayUrl, route: NodeRoute) {
        let mut memory = guard(&self.memory);
        if route == NodeRoute::Tunnel {
            memory.state = DialState::Connected;
        }
        let node = memory.nodes.entry(url.as_str().to_owned()).or_default();
        node.route = Some(route);
        if route == NodeRoute::Direct {
            node.direct_failed_at = None;
        }
    }

    fn direct_failed(&self, url: &RelayUrl) {
        let mut memory = guard(&self.memory);
        let node = memory.nodes.entry(url.as_str().to_owned()).or_default();
        node.direct_failed_at = Some(Instant::now());
    }

    fn kept(&self) -> Option<KeptDials> {
        Some(self.kept.clone())
    }

    fn dial(
        &self,
        route: &TunnelRoute,
        deadline: Instant,
    ) -> Result<Box<dyn TunnelPipe>, HttpError> {
        if guard(&self.memory)
            .hold_until
            .is_some_and(|until| Instant::now() < until)
        {
            // A refusal or a failure holds the dials back: no network now.
            return Err(HttpError::Connect);
        }
        let closes = self.closes.load(Ordering::SeqCst);
        let mut opened: Option<DialPipe> = None;
        let mut kept: Option<Failure> = None;
        let result = self.accounts.with_token(|client, token| {
            // Only the account's own Connect origin gets its token, and only for a
            // route through it.
            if !route.is_through(client.origin()) {
                kept = Some(Failure::Refused);
                return Err(ConnectError::Local);
            }
            match self.open(client.origin(), route, token, deadline, closes) {
                Ok(pipe) => {
                    opened = Some(pipe);
                    Ok(())
                }
                Err(Failure::Unauthenticated) => Err(ConnectError::Unauthenticated),
                Err(failure) => {
                    kept = Some(failure);
                    Err(ConnectError::Local)
                }
            }
        });
        let outcome = match (result, opened) {
            (Ok(Some(())), Some(pipe)) => Ok(pipe),
            (Ok(None), _) => Err(Failure::NotOnConnect),
            (Ok(Some(())), None) => Err(Failure::Unreachable),
            (Err(ConnectError::Local), _) => Err(kept.unwrap_or(Failure::Unreachable)),
            (
                Err(
                    ConnectError::Revoked
                    | ConnectError::NoAccount
                    | ConnectError::KeyLost
                    | ConnectError::NoDeviceKey
                    | ConnectError::AccountRequired
                    | ConnectError::PlanRequired,
                ),
                _,
            ) => Err(Failure::NotOnConnect),
            (Err(ConnectError::Unauthenticated | ConnectError::Forbidden), _) => {
                Err(Failure::Refused)
            }
            (Err(ConnectError::RateLimited(_)), _) => Err(Failure::Limit),
            // Connect, or the Keychain (the iPhone is locked), is not there now.
            (Err(_), _) => Err(Failure::Unreachable),
        };
        match outcome {
            Ok(pipe) => {
                self.after_dial(None);
                Ok(Box::new(pipe))
            }
            Err(failure) => {
                self.after_dial(Some(failure));
                Err(HttpError::Connect)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The pipe of one dial.

#[derive(Default)]
struct Inbox {
    bytes: VecDeque<u8>,
    /// No more bytes come: the dial ended.
    eof: bool,
}

struct PipeShared {
    inbox: Mutex<Inbox>,
    /// Bytes came, room was made, or the dial ended.
    changed: Condvar,
    writer: Mutex<Box<dyn Write + Send>>,
    shutdown: Arc<dyn Fn() + Send + Sync>,
    ended: AtomicBool,
    started: Instant,
    /// Milliseconds after `started` of the last message from Connect.
    last_seen: AtomicU64,
    read_timeout: Mutex<Duration>,
    routes: Weak<Routes>,
}

impl PipeShared {
    fn touch(&self) {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_seen.store(now, Ordering::Relaxed);
    }

    fn silent_for(&self) -> Duration {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(now.saturating_sub(self.last_seen.load(Ordering::Relaxed)))
    }

    fn send(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if self.ended.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut writer = guard(&self.writer);
        let result = client::send(&mut **writer, opcode, payload);
        if result.is_err() {
            drop(writer);
            self.end(None);
        }
        result
    }

    /// End the dial: a close with `code` (best effort: not while a write is stuck), the
    /// socket shut down, and no more bytes for the reader.
    fn end(&self, code: Option<u16>) {
        if self.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(code) = code {
            let writer = match self.writer.try_lock() {
                Ok(writer) => Some(writer),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(mut writer) = writer {
                let _ = client::send(&mut **writer, ws::OP_CLOSE, &ws::close_payload(code));
            }
        }
        (self.shutdown)();
        guard(&self.inbox).eof = true;
        self.changed.notify_all();
    }
}

/// The byte pipe of one dial: the TLS of the node runs over it.
struct DialPipe {
    shared: Arc<PipeShared>,
    id: u64,
}

impl DialPipe {
    fn start(socket: Socket, timing: Timing, id: u64, routes: Weak<Routes>) -> Self {
        let Socket {
            reader,
            writer,
            shutdown,
        } = socket;
        let shared = Arc::new(PipeShared {
            inbox: Mutex::new(Inbox::default()),
            changed: Condvar::new(),
            writer: Mutex::new(writer),
            shutdown,
            ended: AtomicBool::new(false),
            started: Instant::now(),
            last_seen: AtomicU64::new(0),
            read_timeout: Mutex::new(Duration::from_secs(30)),
            routes,
        });
        let reading = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("apassy-dial-read".to_owned())
                .spawn(move || read_loop(&shared, reader, timing.silent))
        };
        let pinging = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("apassy-dial-ping".to_owned())
                .spawn(move || ping_loop(&shared, timing))
        };
        if reading.is_err() || pinging.is_err() {
            shared.end(Some(close::INTERNAL));
        }
        Self { shared, id }
    }

    fn closer(&self) -> Arc<dyn Fn() + Send + Sync> {
        let shared = Arc::clone(&self.shared);
        Arc::new(move || shared.end(Some(close::NORMAL)))
    }
}

impl Drop for DialPipe {
    fn drop(&mut self) {
        self.shared.end(Some(close::NORMAL));
        if let Some(routes) = self.shared.routes.upgrade() {
            routes.unregister(self.id);
        }
    }
}

/// The messages of Connect until the dial ends: bytes for the TLS, pongs for pings.
fn read_loop(shared: &PipeShared, reader: Box<dyn Read + Send>, silent: bool) {
    let mut reader = ws::Reader::client(reader, frame::MAX_PAYLOAD);
    loop {
        let message = match reader.read_message() {
            Ok(message) => message,
            Err(error) => {
                shared.end(error.close_code());
                return;
            }
        };
        match message {
            Message::Binary(bytes) => {
                shared.touch();
                let mut inbox = guard(&shared.inbox);
                while inbox.bytes.len() >= PIPE_BUFFER && !shared.ended.load(Ordering::SeqCst) {
                    inbox = shared
                        .changed
                        .wait(inbox)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                if shared.ended.load(Ordering::SeqCst) {
                    return;
                }
                inbox.bytes.extend(bytes);
                drop(inbox);
                shared.changed.notify_all();
            }
            Message::Ping(payload) => {
                if !silent {
                    shared.touch();
                    let _ = shared.send(ws::OP_PONG, &payload);
                }
            }
            Message::Pong(_) => shared.touch(),
            Message::Text => {
                shared.end(Some(close::UNSUPPORTED));
                return;
            }
            Message::Close(code) => {
                if let (Some(code), Some(routes)) = (code, shared.routes.upgrade()) {
                    routes.closed_with(code);
                }
                shared.end(Some(close::NORMAL));
                return;
            }
        }
    }
}

/// Ping every `timing.ping`; end the dial after `timing.idle` without a message.
fn ping_loop(shared: &PipeShared, timing: Timing) {
    let mut next_ping = Instant::now() + timing.ping;
    let mut inbox = guard(&shared.inbox);
    loop {
        if shared.ended.load(Ordering::SeqCst) {
            return;
        }
        let silent = shared.silent_for();
        if silent >= timing.idle {
            drop(inbox);
            shared.end(None);
            return;
        }
        let now = Instant::now();
        if now >= next_ping {
            drop(inbox);
            if !timing.silent && shared.send(ws::OP_PING, &[]).is_err() {
                return;
            }
            next_ping = now + timing.ping;
            inbox = guard(&shared.inbox);
            continue;
        }
        let wait = (next_ping - now)
            .min(timing.idle.saturating_sub(silent))
            .max(Duration::from_millis(1));
        inbox = shared
            .changed
            .wait_timeout(inbox, wait)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
}

impl Read for DialPipe {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let until = Instant::now() + *guard(&self.shared.read_timeout);
        let mut inbox = guard(&self.shared.inbox);
        loop {
            if !inbox.bytes.is_empty() {
                let count = out.len().min(inbox.bytes.len());
                for (slot, byte) in out.iter_mut().zip(inbox.bytes.drain(..count)) {
                    *slot = byte;
                }
                drop(inbox);
                self.shared.changed.notify_all();
                return Ok(count);
            }
            if inbox.eof {
                return Ok(0);
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            inbox = self
                .shared
                .changed
                .wait_timeout(inbox, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}

impl Write for DialPipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // One binary message carries 1 to 16384 bytes (contract 3.3).
        let count = bytes.len().min(frame::MAX_PAYLOAD);
        self.shared.send(ws::OP_BINARY, &bytes[..count])?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Each message is written and flushed whole.
        Ok(())
    }
}

impl TunnelPipe for DialPipe {
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        *guard(&self.shared.read_timeout) = timeout.max(Duration::from_millis(1));
        Ok(())
    }

    /// The socket to Connect keeps its own stall limit for each write (20 s, the
    /// node's socket), which is shorter than every request's.
    fn set_write_timeout(&self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }

    fn closer(&self) -> Arc<dyn Fn() + Send + Sync> {
        DialPipe::closer(self)
    }

    /// Open, and no byte from Connect waits unread: an idle TLS connection to the node
    /// gets none (the front sends no tickets), so a byte here is the node's close.
    fn is_idle_open(&self) -> bool {
        let inbox = guard(&self.shared.inbox);
        !self.shared.ended.load(Ordering::SeqCst) && !inbox.eof && inbox.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_contract_times_are_the_constants() {
        let timing = Timing::default();
        assert_eq!(timing.ping, Duration::from_secs(30));
        assert_eq!(timing.idle, Duration::from_secs(90));
        assert_eq!(timing.backoff_first, Duration::from_secs(1));
        assert_eq!(timing.backoff_max, Duration::from_secs(60));
        assert_eq!(timing.kept_idle, Duration::from_secs(30));
        assert!(!timing.silent);
    }

    #[test]
    fn each_refusal_of_the_dial_has_its_own_quiet_state() {
        let body = |code: &str| format!(r#"{{"ok":false,"error":{{"code":"{code}"}}}}"#);
        let cases = [
            (403, "plan_required", Failure::NotOnConnect),
            (403, "account_required", Failure::NotOnConnect),
            (403, "not_in_group", Failure::Refused),
            (401, "unauthenticated", Failure::Unauthenticated),
            (404, "node_unknown", Failure::MacOffline),
            (503, "tunnel_offline", Failure::MacOffline),
            (429, "tunnel_limit", Failure::Limit),
            (429, "rate_limited", Failure::Limit),
            (503, "busy", Failure::Unreachable),
            (400, "invalid_request", Failure::Refused),
        ];
        for (status, code, failure) in cases {
            assert_eq!(
                refusal(status, body(code).as_bytes()),
                failure,
                "{status} {code}"
            );
        }
        assert_ne!(Failure::MacOffline.state(), Failure::Limit.state());
        for state in [
            DialState::Unused,
            DialState::Connected,
            DialState::NotOnConnect,
            DialState::MacOffline,
            DialState::Limit,
            DialState::Unreachable,
            DialState::Refused,
        ] {
            let text = state.text();
            for banned in ["buy", "subscribe", "upgrade", "price", "plan"] {
                assert!(!text.contains(banned), "{text}");
            }
        }
    }
}
