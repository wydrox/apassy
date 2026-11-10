//! The Connect tunnel broker (ADR 0037 stage 7, unit C4; docs/contracts/connect-tunnel-v1.md).
//!
//! A node keeps one WebSocket to Connect (`GET /v1/tunnel/node`); a device dials it
//! (`GET /v1/tunnel/dial/{node_id}`), and the SNI ingress (`super::ingress`) brings cloud
//! agents. Each dial or ingress connection is one stream of the frame mux on the node's
//! WebSocket ([`frame`]). The broker is a blind byte relay: it forwards bytes unchanged,
//! keeps none of them, and logs nothing. It counts, for each account and month, dials,
//! streams, and bytes ([`Usage`]); it never sees a client address (the ingress keeps
//! those in memory for its own rate limit only).
//!
//! The WebSocket is this crate's own RFC 6455 implementation ([`ws`], where the reason
//! is written down). The HTTP part runs on the vendored `tiny_http`:
//! [`Broker::serve_node`] and [`Broker::serve_dial`] take a request, answer an error
//! with the error envelope, or answer `101` through `Request::upgrade_split` and return
//! at once; two threads carry each WebSocket after that.
//!
//! Authorisation goes through [`TunnelDirectory`]: which account a bearer token is,
//! which node a device has, whether an account is entitled, and the `tunnel_grant`s.
//! `super::tunnel_routes::AccountDirectory` implements it on the account store;
//! [`MemoryDirectory`] is the test one.
//!
//! Every queue has a cap. A node's outgoing queue holds at most
//! [`Limits::node_queue`] bytes; a client that sends faster waits (backpressure to its
//! TCP window). A stream buffers at most [`Limits::stream_buffer`] bytes toward a
//! client; over it the stream is reset (contract section 4). Control messages (resets,
//! pongs) have their own small queue with a count cap. Reads have an idle limit, writes
//! a timeout, and a maintenance thread resets idle streams.
//!
//! Locks, in the only order they nest: the node map, a node's stream state, a stream's
//! inbox. The account counters and each outbox are leaves (nothing is locked inside).

pub mod frame;
pub mod ws;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frame::{Applied, CLOSE, Dir, Kind, OPEN, RESET, Sequencer};
use ws::{Message, WsError, close};

/// Error codes of the tunnel routes (connect-account-v1 section 4, tunnel contract 3.3).
pub mod codes {
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const UNAUTHENTICATED: &str = "unauthenticated";
    pub const ACCOUNT_REQUIRED: &str = "account_required";
    pub const NODE_UNKNOWN: &str = "node_unknown";
    pub const NOT_IN_GROUP: &str = "not_in_group";
    pub const PLAN_REQUIRED: &str = "plan_required";
    pub const ACCOUNT_LIMIT: &str = "account_limit";
    pub const TUNNEL_LIMIT: &str = "tunnel_limit";
    pub const TUNNEL_OFFLINE: &str = "tunnel_offline";
}

/// A refusal before the `101`, with its HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelError {
    pub status: u16,
    pub code: &'static str,
    pub message: &'static str,
}

impl TunnelError {
    const fn new(status: u16, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
    pub const fn invalid(message: &'static str) -> Self {
        Self::new(400, codes::INVALID_REQUEST, message)
    }
    pub const UNAUTHENTICATED: Self = Self::new(
        401,
        codes::UNAUTHENTICATED,
        "The token is missing, unknown, or revoked.",
    );
    pub const ACCOUNT_REQUIRED: Self = Self::new(
        403,
        codes::ACCOUNT_REQUIRED,
        "The tunnel needs an account token.",
    );
    pub const NODE_UNKNOWN: Self = Self::new(404, codes::NODE_UNKNOWN, "No such node.");
    pub const NOT_IN_GROUP: Self = Self::new(
        403,
        codes::NOT_IN_GROUP,
        "That node belongs to an account that gave yours no access.",
    );
    pub const PLAN_REQUIRED: Self = Self::new(
        403,
        codes::PLAN_REQUIRED,
        "The node's account is not on Apassy Connect.",
    );
    pub const ACCOUNT_LIMIT: Self = Self::new(
        403,
        codes::ACCOUNT_LIMIT,
        "The account has the most nodes it may have online.",
    );
    pub const TUNNEL_LIMIT: Self = Self::new(
        429,
        codes::TUNNEL_LIMIT,
        "A tunnel limit of the account is reached.",
    );
    pub const TUNNEL_OFFLINE: Self = Self::new(
        503,
        codes::TUNNEL_OFFLINE,
        "The node is not connected to Apassy Connect.",
    );

    /// The JSON error envelope (`{"ok":false,"error":{...}}`).
    pub fn body(&self) -> Vec<u8> {
        let envelope =
            apassy::agent::wire::WireResponse::failure(self.code, self.message.to_string());
        serde_json::to_vec(&envelope).unwrap_or_default()
    }
}

/// The limits of the tunnel (contract section 8). Configuration, not wire constants.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Open streams of one account (its nodes, all kinds).
    pub streams_per_account: usize,
    /// Nodes of one account online at once (the store also refuses a ninth node).
    pub nodes_per_account: usize,
    /// Dials of one account in one clock minute.
    pub dials_per_minute: u32,
    /// Bytes of one account in one UTC month, both directions, for each budget unit
    /// ([`TunnelDirectory::budget_units`]: each person of Family, each member of Team).
    pub bytes_per_month: u64,
    /// Connect pings each WebSocket this often.
    pub ping_interval: Duration,
    /// A WebSocket with no message for this long closes (reads and writes time out).
    pub idle_timeout: Duration,
    /// A stream with no bytes for this long is reset.
    pub stream_idle: Duration,
    /// Bytes buffered toward one client; over it the stream is reset.
    pub stream_buffer: usize,
    /// Bytes queued toward one node; a client sending more waits.
    pub node_queue: usize,
    /// After a client left, the node has this long to close its side, then a reset.
    pub close_grace: Duration,
    /// All node WebSockets of this broker.
    pub max_nodes: usize,
    /// All open streams of this broker.
    pub max_streams: usize,
    /// How often the maintenance thread looks at idle streams.
    pub tick: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            streams_per_account: 64,
            nodes_per_account: 8,
            dials_per_minute: 60,
            bytes_per_month: 20 * 1024 * 1024 * 1024,
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            stream_idle: Duration::from_secs(15 * 60),
            stream_buffer: 256 * 1024,
            node_queue: 1024 * 1024,
            close_grace: Duration::from_secs(10),
            max_nodes: 4096,
            max_streams: 4096,
            tick: Duration::from_secs(1),
        }
    }
}

/// Seconds since the Unix epoch, for months and minutes. Injectable for tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }
}

/// A clock that moves only when told.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The UTC month of a time as `yyyymm` (e.g. 202611).
pub fn month_of(unix: u64) -> u32 {
    // Days to civil date (H. Hinnant's algorithm), for days since 1970-01-01.
    let days = (unix / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year * 100 + month) as u32
}

/// The account (and device) of a bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caller {
    pub account_id: String,
    pub device_id: String,
}

/// A registered node: what the broker needs of the `NodeView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    pub node_id: String,
    pub account_id: String,
    pub device_id: String,
}

/// Why a token is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 401 `unauthenticated`: no valid account token.
    Unauthenticated,
    /// 403 `account_required`: a token that is not an account token (a team token).
    AccountRequired,
}

/// What the broker asks of the account store (unit C1 implements it).
pub trait TunnelDirectory: Send + Sync {
    /// The caller of a bearer token (the value after `Bearer `).
    fn caller(&self, bearer: &str) -> Result<Caller, Refusal>;
    /// The node registered for the caller's device, if any.
    fn device_node(&self, caller: &Caller) -> Option<NodeEntry>;
    /// A node by id.
    fn node(&self, node_id: &str) -> Option<NodeEntry>;
    /// Whether the node's account granted the given account (`tunnel_grant`).
    fn has_grant(&self, node_id: &str, grantee_account: &str) -> bool;
    /// Whether the account has a plan with the tunnel (connect-billing-v1 section 8).
    fn entitled(&self, account_id: &str) -> bool;
    /// How many byte budgets the account has: 1, or the people of Family, or the members
    /// of Team.
    fn budget_units(&self, _account_id: &str) -> u64 {
        1
    }
}

/// May `caller_account` dial `node`: its own node, or one whose account granted it.
pub fn may_dial(directory: &dyn TunnelDirectory, caller_account: &str, node: &NodeEntry) -> bool {
    node.account_id == caller_account || directory.has_grant(&node.node_id, caller_account)
}

/// A node id: `node_` and 10 characters of `a-z2-7`.
pub fn valid_node_id(node_id: &str) -> bool {
    node_id
        .strip_prefix("node_")
        .is_some_and(|label| label.len() == 10 && label.bytes().all(is_base32))
}

fn is_base32(byte: u8) -> bool {
    byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)
}

/// The public name of a node in a zone: `k7m2q4x3ca.node.example`.
pub fn public_name(node_id: &str, zone: &str) -> Option<String> {
    let label = node_id.strip_prefix("node_")?;
    valid_node_id(node_id).then(|| format!("{label}.{}", zone.to_ascii_lowercase()))
}

/// The node id of a public name in a zone (case-insensitive), if the name has the form.
pub fn node_of_public_name(name: &str, zone: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    let (label, rest) = name.split_once('.')?;
    if !rest.eq_ignore_ascii_case(zone) {
        return None;
    }
    let node_id = format!("node_{label}");
    valid_node_id(&node_id).then_some(node_id)
}

/// The tunnel use of one account in one month.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    /// `yyyymm`, UTC.
    pub month: u32,
    pub bytes: u64,
    pub dials: u64,
    pub streams: u64,
    /// Open streams now (not stored).
    pub open_streams: usize,
    /// Over the byte budget this month.
    pub tripped: bool,
}

#[derive(Debug, Default)]
struct Account {
    month: u32,
    bytes: u64,
    dials: u64,
    streams: u64,
    tripped: bool,
    budget: u64,
    minute: u64,
    minute_dials: u32,
    open: usize,
}

impl Account {
    fn roll(&mut self, now: u64) {
        let month = month_of(now);
        if self.month != month {
            self.month = month;
            self.bytes = 0;
            self.dials = 0;
            self.streams = 0;
            self.tripped = false;
        }
        let minute = now / 60;
        if self.minute != minute {
            self.minute = minute;
            self.minute_dials = 0;
        }
    }
}

#[derive(Default)]
struct Accounts {
    by_id: HashMap<String, Account>,
    open_total: usize,
}

/// An open-stream slot of an account; released once, when its stream ends.
struct Slot {
    inner: Weak<Inner>,
    account: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut accounts = lock(&inner.accounts);
            accounts.open_total = accounts.open_total.saturating_sub(1);
            if let Some(account) = accounts.by_id.get_mut(&self.account) {
                account.open = account.open.saturating_sub(1);
            }
        }
    }
}

/// A raw byte stream after the upgrade, split so that two threads can use it.
pub struct Transport {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    /// Shuts the socket down both ways from any thread (unblocks a pending read).
    pub shutdown: Arc<dyn Fn() + Send + Sync>,
}

impl Transport {
    /// A TCP stream with read and write timeouts of `idle`.
    pub fn from_tcp(stream: TcpStream, idle: Duration) -> io::Result<Self> {
        stream.set_read_timeout(Some(idle))?;
        stream.set_write_timeout(Some(idle))?;
        let writer = stream.try_clone()?;
        let closer = stream.try_clone()?;
        Ok(Self {
            reader: Box::new(stream),
            writer: Box::new(writer),
            shutdown: Arc::new(move || {
                let _ = closer.shutdown(Shutdown::Both);
            }),
        })
    }

    /// The halves of `tiny_http::Request::upgrade_split`.
    pub fn from_upgrade(parts: tiny_http::UpgradedParts) -> Self {
        let shutdown = parts.shutdown;
        Self {
            reader: parts.reader,
            writer: parts.writer,
            shutdown: Arc::from(shutdown),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What a node's writer sends.
enum Out {
    /// A frame (one binary message).
    Frame(Vec<u8>),
    Pong(Vec<u8>),
}

#[derive(Default)]
struct OutState {
    /// Resets and pongs: may pass queued data (a reset can cross data in flight).
    urgent: VecDeque<Out>,
    /// Opens, data, and closes, in order.
    fifo: VecDeque<Vec<u8>>,
    fifo_bytes: usize,
    close: Option<u16>,
}

/// The queue toward one node: a byte cap with backpressure for data, a count cap for
/// control messages.
struct Outbox {
    state: Mutex<OutState>,
    ready: Condvar,
    space: Condvar,
    cap: usize,
}

const URGENT_CAP: usize = 1024;

enum Next {
    Send(Out),
    Ping,
    Close(u16),
}

impl Outbox {
    fn new(cap: usize) -> Self {
        Self {
            state: Mutex::new(OutState::default()),
            ready: Condvar::new(),
            space: Condvar::new(),
            cap,
        }
    }

    /// Queues a reset or a pong. A pong replaces a queued pong; over the count cap the
    /// message is dropped (a reset is advisory: the node drops late frames anyway).
    fn push_urgent(&self, out: Out) {
        let mut state = lock(&self.state);
        if state.close.is_some() {
            return;
        }
        if matches!(out, Out::Pong(_)) {
            state
                .urgent
                .retain(|queued| !matches!(queued, Out::Pong(_)));
        }
        if state.urgent.len() < URGENT_CAP {
            state.urgent.push_back(out);
            self.ready.notify_one();
        }
    }

    /// Queues a frame in order, waiting for space while `ended` is false. `wait: false`
    /// queues over the cap (an `open`, bounded by the stream count).
    fn push(&self, frame: Vec<u8>, ended: &AtomicBool, wait: bool) -> bool {
        let mut state = lock(&self.state);
        loop {
            if state.close.is_some() || ended.load(Ordering::SeqCst) {
                return false;
            }
            if !wait || state.fifo_bytes + frame.len() <= self.cap || state.fifo.is_empty() {
                break;
            }
            let (next, _) = self
                .space
                .wait_timeout(state, Duration::from_millis(200))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
        state.fifo_bytes += frame.len();
        state.fifo.push_back(frame);
        self.ready.notify_one();
        true
    }

    fn close(&self, code: u16) {
        let mut state = lock(&self.state);
        if state.close.is_none() {
            state.close = Some(code);
        }
        self.ready.notify_all();
        self.space.notify_all();
    }

    fn wake(&self) {
        self.space.notify_all();
    }

    fn next(&self, ping_at: Instant) -> Next {
        let mut state = lock(&self.state);
        loop {
            if let Some(code) = state.close {
                return Next::Close(code);
            }
            if let Some(out) = state.urgent.pop_front() {
                return Next::Send(out);
            }
            if let Some(frame) = state.fifo.pop_front() {
                state.fifo_bytes -= frame.len();
                self.space.notify_all();
                return Next::Send(Out::Frame(frame));
            }
            let now = Instant::now();
            if now >= ping_at {
                return Next::Ping;
            }
            let (next, _) = self
                .ready
                .wait_timeout(state, ping_at - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
    }
}

#[derive(Default)]
struct Inbox {
    chunks: VecDeque<Vec<u8>>,
    bytes: usize,
    /// The node closed its direction.
    node_closed: bool,
    /// The stream ended: the close code for the client (1000 after the last bytes).
    end: Option<u16>,
    /// A pong to send to a WebSocket client.
    pong: Option<Vec<u8>>,
    /// The client closed its WebSocket: reply with this close code.
    client_close: Option<u16>,
}

/// One stream, as Connect holds it: the client side of a dial or an ingress connection.
struct Stream {
    id: u32,
    kind: Kind,
    /// The node's account: limits and bytes count here.
    account: String,
    /// The device that dialed (device streams only).
    dialer: Option<Caller>,
    inbox: Mutex<Inbox>,
    cond: Condvar,
    ended: AtomicBool,
    /// Milliseconds since the broker's epoch: the last byte either way.
    activity: AtomicU64,
    /// Milliseconds since the epoch when the client left (0: still there).
    client_gone: AtomicU64,
    /// Most bytes the node may send on this stream (ACME answers), else unlimited.
    max_from_node: Option<usize>,
    from_node: AtomicU64,
    /// Held while a frame of the client direction is queued; `true` once its `close` is
    /// queued, so no data frame can follow the `close`.
    send: Mutex<bool>,
    slot: Mutex<Option<Slot>>,
    /// Shuts the client's socket; used when Connect ends a stream while the client's
    /// writer is stuck in a write (a client that does not read).
    client: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// The client's writer is inside a write.
    writing: AtomicBool,
}

impl Stream {
    fn touch(&self, inner: &Inner) {
        self.activity.store(inner.millis(), Ordering::Relaxed);
    }

    /// Ends the stream with a close code for the client, once; frees its slot.
    fn finish(&self, code: u16) {
        {
            let mut inbox = lock(&self.inbox);
            if inbox.end.is_some() {
                return;
            }
            inbox.end = Some(code);
            if code != close::NORMAL {
                inbox.chunks.clear();
                inbox.bytes = 0;
            }
            self.ended.store(true, Ordering::SeqCst);
            self.cond.notify_all();
        }
        drop(lock(&self.slot).take());
    }

    fn is_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

struct ConnState {
    seq: Sequencer<Arc<Stream>>,
}

/// One node WebSocket.
struct NodeConn {
    node_id: String,
    account: String,
    device: String,
    generation: u64,
    outbox: Outbox,
    state: Mutex<ConnState>,
    closed: AtomicBool,
    shutdown: Arc<dyn Fn() + Send + Sync>,
}

struct Inner {
    directory: Arc<dyn TunnelDirectory>,
    limits: Limits,
    clock: Arc<dyn Clock>,
    zone: String,
    epoch: Instant,
    nodes: Mutex<HashMap<String, Arc<NodeConn>>>,
    accounts: Mutex<Accounts>,
    generation: AtomicU64,
    stop: AtomicBool,
}

/// The tunnel broker. Cheap to clone; all clones share one registry.
#[derive(Clone)]
pub struct Broker {
    inner: Arc<Inner>,
}

/// Why the ingress refuses a name (all get the same TLS alert, except the limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRefusal {
    /// No such node, no WebSocket, or not entitled: one answer for all three.
    Unrecognized,
    /// A tunnel limit of the node's account: the connection is closed.
    Limit,
}

/// A stream opened before its client side runs. Dropped unused, it resets the stream.
pub struct Ticket {
    inner: Arc<Inner>,
    conn: Arc<NodeConn>,
    stream: Option<Arc<Stream>>,
}

impl Ticket {
    /// The stream id on the node's WebSocket.
    pub fn stream_id(&self) -> u32 {
        self.stream.as_ref().map_or(0, |stream| stream.id)
    }
    fn take(mut self) -> (Arc<Inner>, Arc<NodeConn>, Arc<Stream>) {
        let stream = self.stream.take().expect("ticket used once");
        (self.inner.clone(), self.conn.clone(), stream)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            self.inner.abort(&self.conn, &stream, close::INTERNAL);
        }
    }
}

/// A node that may connect, checked before the `101`.
pub struct NodeTicket {
    entry: NodeEntry,
}

impl NodeTicket {
    pub fn node_id(&self) -> &str {
        &self.entry.node_id
    }
}

const STACK: usize = 256 * 1024;

fn spawn(name: &str, work: impl FnOnce() + Send + 'static) -> bool {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(STACK)
        .spawn(work)
        .is_ok()
}

impl Broker {
    /// A broker for public names under `zone`, with the maintenance thread.
    pub fn new(
        directory: Arc<dyn TunnelDirectory>,
        limits: Limits,
        clock: Arc<dyn Clock>,
        zone: &str,
    ) -> Self {
        let inner = Arc::new(Inner {
            directory,
            limits,
            clock,
            zone: zone.trim_end_matches('.').to_ascii_lowercase(),
            epoch: Instant::now(),
            nodes: Mutex::new(HashMap::new()),
            accounts: Mutex::new(Accounts::default()),
            generation: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&inner);
        let tick = inner.limits.tick;
        spawn("tunnel-maintenance", move || {
            loop {
                std::thread::sleep(tick);
                let Some(inner) = weak.upgrade() else { return };
                if inner.stop.load(Ordering::SeqCst) {
                    return;
                }
                inner.maintain();
            }
        });
        Self { inner }
    }

    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }

    pub fn zone(&self) -> &str {
        &self.inner.zone
    }

    /// Stops the maintenance thread and closes every node WebSocket.
    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        let conns: Vec<_> = lock(&self.inner.nodes).values().cloned().collect();
        for conn in conns {
            self.inner
                .terminate(&conn, close::NORMAL, close::NODE_OFFLINE);
        }
    }

    /// Whether the node has an open WebSocket (`NodeView.online`).
    pub fn online(&self, node_id: &str) -> bool {
        lock(&self.inner.nodes).contains_key(node_id)
    }

    /// The node ids with an open WebSocket.
    pub fn online_nodes(&self) -> Vec<String> {
        lock(&self.inner.nodes).keys().cloned().collect()
    }

    /// The use of an account this month.
    pub fn usage(&self, account_id: &str) -> Usage {
        let now = self.inner.clock.now();
        let mut accounts = lock(&self.inner.accounts);
        let account = accounts.by_id.entry(account_id.to_string()).or_default();
        account.roll(now);
        Usage {
            month: account.month,
            bytes: account.bytes,
            dials: account.dials,
            streams: account.streams,
            open_streams: account.open,
            tripped: account.tripped,
        }
    }

    /// The counters of every account with use this month, to store (contract section 9).
    pub fn usage_all(&self) -> Vec<(String, Usage)> {
        let ids: Vec<String> = lock(&self.inner.accounts).by_id.keys().cloned().collect();
        ids.into_iter()
            .map(|id| {
                let usage = self.usage(&id);
                (id, usage)
            })
            .collect()
    }

    /// Restores stored counters of the current month after a restart. Counters of
    /// another month are ignored.
    pub fn restore_usage(&self, account_id: &str, usage: &Usage) {
        let now = self.inner.clock.now();
        if usage.month != month_of(now) {
            return;
        }
        let mut accounts = lock(&self.inner.accounts);
        let account = accounts.by_id.entry(account_id.to_string()).or_default();
        account.roll(now);
        account.bytes = account.bytes.max(usage.bytes);
        account.dials = account.dials.max(usage.dials);
        account.streams = account.streams.max(usage.streams);
        account.tripped |= usage.tripped;
    }

    /// Checks a node WebSocket before the `101` (contract 3.2): the upgrade, the token,
    /// the device's node, the plan, and the node count.
    pub fn prepare_node(
        &self,
        upgrade: Result<(), &'static str>,
        bearer: Option<&str>,
    ) -> Result<NodeTicket, TunnelError> {
        upgrade.map_err(TunnelError::invalid)?;
        let caller = self.inner.caller(bearer)?;
        let entry = self
            .inner
            .directory
            .device_node(&caller)
            .ok_or(TunnelError::NODE_UNKNOWN)?;
        if !self.inner.directory.entitled(&entry.account_id) {
            return Err(TunnelError::PLAN_REQUIRED);
        }
        self.inner.admit_node(&entry)?;
        Ok(NodeTicket { entry })
    }

    /// Runs a node WebSocket after the `101`: replaces an earlier one of the same node
    /// (close 4005, its streams reset), and starts its reader and writer.
    pub fn run_node(&self, ticket: NodeTicket, transport: Transport) {
        let inner = &self.inner;
        if inner.admit_node(&ticket.entry).is_err() {
            let mut writer = transport.writer;
            let _ = ws::write_frame(
                &mut *writer,
                ws::OP_CLOSE,
                &ws::close_payload(close::TUNNEL_LIMIT),
                None,
            );
            (transport.shutdown)();
            return;
        }
        let conn = Arc::new(NodeConn {
            node_id: ticket.entry.node_id.clone(),
            account: ticket.entry.account_id.clone(),
            device: ticket.entry.device_id.clone(),
            generation: inner.generation.fetch_add(1, Ordering::SeqCst) + 1,
            outbox: Outbox::new(inner.limits.node_queue),
            state: Mutex::new(ConnState {
                seq: Sequencer::new(),
            }),
            closed: AtomicBool::new(false),
            shutdown: transport.shutdown.clone(),
        });
        let old = lock(&inner.nodes).insert(conn.node_id.clone(), conn.clone());
        if let Some(old) = old {
            inner.terminate(&old, close::REPLACED, close::NODE_OFFLINE);
        }
        let reader_inner = inner.clone();
        let reader_conn = conn.clone();
        let reader = transport.reader;
        let started = spawn("tunnel-node-read", move || {
            reader_inner.node_reader(&reader_conn, reader);
        });
        let writer_inner = inner.clone();
        let writer_conn = conn.clone();
        let writer = transport.writer;
        let started = started
            && spawn("tunnel-node-write", move || {
                writer_inner.node_writer(&writer_conn, writer);
            });
        if !started {
            inner.terminate(&conn, close::INTERNAL, close::NODE_OFFLINE);
        }
    }

    /// Checks a dial before the `101`, in the contract's order (3.3), and opens its
    /// `device` stream on the node's WebSocket.
    pub fn prepare_dial(
        &self,
        upgrade: Result<(), &'static str>,
        bearer: Option<&str>,
        node_id: &str,
    ) -> Result<Ticket, TunnelError> {
        upgrade.map_err(TunnelError::invalid)?;
        let caller = self.inner.caller(bearer)?;
        let entry = valid_node_id(node_id)
            .then(|| self.inner.directory.node(node_id))
            .flatten()
            .ok_or(TunnelError::NODE_UNKNOWN)?;
        if !may_dial(&*self.inner.directory, &caller.account_id, &entry) {
            return Err(TunnelError::NOT_IN_GROUP);
        }
        if !self.inner.directory.entitled(&entry.account_id) {
            return Err(TunnelError::PLAN_REQUIRED);
        }
        let slot = self.inner.reserve(&entry.account_id, true)?;
        self.inner
            .open(&entry, Kind::Device, 0, Vec::new(), Some(caller), slot)
            .ok_or(TunnelError::TUNNEL_OFFLINE)
    }

    /// Runs a dial after the `101`: binary messages to and from the stream.
    pub fn run_dial(&self, ticket: Ticket, transport: Transport) {
        let (inner, conn, stream) = ticket.take();
        inner.spawn_dial(conn, stream, transport);
    }

    /// Opens a `public` or `acme` stream for the ingress, with the bytes read so far.
    /// `flags` may add `CLOSE` (an ACME request is the whole client direction).
    pub fn open_ingress(
        &self,
        server_name: &str,
        kind: Kind,
        first: Vec<u8>,
        flags: u8,
    ) -> Result<Ticket, IngressRefusal> {
        let node_id = node_of_public_name(server_name, &self.inner.zone)
            .ok_or(IngressRefusal::Unrecognized)?;
        let entry = self
            .inner
            .directory
            .node(&node_id)
            .ok_or(IngressRefusal::Unrecognized)?;
        if !self.online(&node_id) || !self.inner.directory.entitled(&entry.account_id) {
            return Err(IngressRefusal::Unrecognized);
        }
        let slot = self
            .inner
            .reserve(&entry.account_id, false)
            .map_err(|_| IngressRefusal::Limit)?;
        self.inner
            .open(&entry, kind, flags & CLOSE, first, None, slot)
            .ok_or(IngressRefusal::Unrecognized)
    }

    /// Runs an ingress stream on its TCP connection. `read_client: false` when the client
    /// direction was closed with the `open` (ACME).
    pub fn run_raw(&self, ticket: Ticket, tcp: TcpStream, read_client: bool) {
        let (inner, conn, stream) = ticket.take();
        inner.spawn_raw(conn, stream, tcp, read_client);
    }

    /// `GET /v1/tunnel/node`: answers an error, or `101` and runs the WebSocket.
    pub fn serve_node(&self, request: tiny_http::Request) {
        let upgrade = upgrade_of(&request);
        let checked = self.prepare_node(
            upgrade.as_ref().map(|_| ()).map_err(|error| *error),
            bearer_of(&request).as_deref(),
        );
        match (checked, upgrade) {
            (Ok(ticket), Ok(accept)) => {
                let idle = self.inner.limits.idle_timeout;
                if let Ok(parts) = request.upgrade_split("websocket", switching(&accept), idle) {
                    self.run_node(ticket, Transport::from_upgrade(parts));
                }
            }
            (Err(error), _) => respond_error(request, &error),
            (Ok(_), Err(error)) => respond_error(request, &TunnelError::invalid(error)),
        }
    }

    /// `GET /v1/tunnel/dial/{node_id}`: answers an error, or `101` and runs the dial.
    pub fn serve_dial(&self, request: tiny_http::Request, node_id: &str) {
        let upgrade = upgrade_of(&request);
        let checked = self.prepare_dial(
            upgrade.as_ref().map(|_| ()).map_err(|error| *error),
            bearer_of(&request).as_deref(),
            node_id,
        );
        match (checked, upgrade) {
            (Ok(ticket), Ok(accept)) => {
                let idle = self.inner.limits.idle_timeout;
                // A failed upgrade drops the ticket, which resets the stream.
                if let Ok(parts) = request.upgrade_split("websocket", switching(&accept), idle) {
                    self.run_dial(ticket, Transport::from_upgrade(parts));
                }
            }
            (Err(error), _) => respond_error(request, &error),
            (Ok(_), Err(error)) => respond_error(request, &TunnelError::invalid(error)),
        }
    }

    /// `DELETE /v1/tunnel/grants/{id}`: resets the grantee's open streams to the node
    /// (close 4003 to its devices). Returns how many.
    pub fn revoke_grant(&self, node_id: &str, grantee_account: &str) -> usize {
        self.inner.reset_where(
            |conn, stream| {
                conn.node_id == node_id
                    && stream
                        .dialer
                        .as_ref()
                        .is_some_and(|caller| caller.account_id == grantee_account)
            },
            close::REVOKED,
        )
    }

    /// `DELETE /v1/tunnel/nodes/{id}` or a revoked device's node: closes its WebSocket
    /// (4003) and its streams (4001 to its dialers).
    pub fn remove_node(&self, node_id: &str) -> bool {
        let conn = lock(&self.inner.nodes).get(node_id).cloned();
        match conn {
            Some(conn) => {
                self.inner
                    .terminate(&conn, close::REVOKED, close::NODE_OFFLINE);
                true
            }
            None => false,
        }
    }

    /// A revoked device: its dials end (4003) and its node closes.
    pub fn revoke_device(&self, device_id: &str) -> usize {
        let nodes: Vec<String> = lock(&self.inner.nodes)
            .values()
            .filter(|conn| conn.device == device_id)
            .map(|conn| conn.node_id.clone())
            .collect();
        for node_id in &nodes {
            self.remove_node(node_id);
        }
        self.inner.reset_where(
            |_, stream| {
                stream
                    .dialer
                    .as_ref()
                    .is_some_and(|caller| caller.device_id == device_id)
            },
            close::REVOKED,
        )
    }

    /// The plan of an account ended: the open streams of its nodes end (4003 to their
    /// clients, a `reset` to the node). Its node WebSockets stay; new dials and ingress
    /// streams are refused by [`TunnelDirectory::entitled`]. Returns how many streams.
    pub fn end_plan(&self, account_id: &str) -> usize {
        self.inner
            .reset_where(|conn, _| conn.account == account_id, close::REVOKED)
    }

    /// The plan of an account ended: its nodes close (4003), and its devices' dials to
    /// other accounts' nodes end (4003).
    pub fn end_account(&self, account_id: &str) {
        let conns: Vec<_> = lock(&self.inner.nodes)
            .values()
            .filter(|conn| conn.account == account_id)
            .cloned()
            .collect();
        for conn in conns {
            self.inner.terminate(&conn, close::REVOKED, close::REVOKED);
        }
        self.inner.reset_where(
            |_, stream| {
                stream
                    .dialer
                    .as_ref()
                    .is_some_and(|caller| caller.account_id == account_id)
            },
            close::REVOKED,
        );
    }
}

/// The upgrade checks of a request; `Ok` is the `Sec-WebSocket-Accept` value.
fn upgrade_of(request: &tiny_http::Request) -> Result<String, &'static str> {
    let method = request.method().as_str();
    ws::check_upgrade(
        method,
        request
            .headers()
            .iter()
            .map(|header| (header.field.as_str().as_str(), header.value.as_str())),
    )
}

/// The token of `Authorization: Bearer <token>` (one header, the scheme in any case).
fn bearer_of(request: &tiny_http::Request) -> Option<String> {
    let mut values = request
        .headers()
        .iter()
        .filter(|header| header.field.equiv("Authorization"));
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.value.as_str().split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_string())
}

fn switching(accept: &str) -> tiny_http::Response<io::Empty> {
    let mut response = tiny_http::Response::empty(101);
    for (name, value) in [
        ("Sec-WebSocket-Accept", accept),
        ("Sec-WebSocket-Protocol", ws::SUBPROTOCOL),
    ] {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
    response
}

fn respond_error(request: tiny_http::Request, error: &TunnelError) {
    let mut response = tiny_http::Response::from_data(error.body())
        .with_status_code(error.status)
        .with_chunked_threshold(usize::MAX);
    for (name, value) in [
        ("Content-Type", "application/json"),
        ("Cache-Control", "no-store"),
    ] {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
    // A GET upgrade has no body; the deadline transport closes after this answer.
    let _ = request.respond(response);
}

impl Inner {
    fn millis(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn caller(&self, bearer: Option<&str>) -> Result<Caller, TunnelError> {
        let bearer = bearer.ok_or(TunnelError::UNAUTHENTICATED)?;
        self.directory
            .caller(bearer)
            .map_err(|refusal| match refusal {
                Refusal::Unauthenticated => TunnelError::UNAUTHENTICATED,
                Refusal::AccountRequired => TunnelError::ACCOUNT_REQUIRED,
            })
    }

    /// The node count of the account and of the broker, not counting a WebSocket of
    /// this node that a new one replaces.
    fn admit_node(&self, entry: &NodeEntry) -> Result<(), TunnelError> {
        let nodes = lock(&self.nodes);
        let replaces = nodes.contains_key(&entry.node_id);
        let of_account = nodes
            .values()
            .filter(|conn| conn.account == entry.account_id && conn.node_id != entry.node_id)
            .count();
        if of_account >= self.limits.nodes_per_account {
            return Err(TunnelError::ACCOUNT_LIMIT);
        }
        if !replaces && nodes.len() >= self.limits.max_nodes {
            return Err(TunnelError::TUNNEL_LIMIT);
        }
        Ok(())
    }

    /// Reserves an open-stream slot of the node's account (and counts a dial).
    fn reserve(self: &Arc<Self>, account_id: &str, dial: bool) -> Result<Slot, TunnelError> {
        let budget = self
            .limits
            .bytes_per_month
            .saturating_mul(self.directory.budget_units(account_id).max(1));
        let now = self.clock.now();
        let mut accounts = lock(&self.accounts);
        let open_total = accounts.open_total;
        let account = accounts.by_id.entry(account_id.to_string()).or_default();
        account.roll(now);
        account.budget = budget;
        if dial {
            if account.minute_dials >= self.limits.dials_per_minute {
                return Err(TunnelError::TUNNEL_LIMIT);
            }
            account.minute_dials += 1;
            account.dials += 1;
        }
        if account.open >= self.limits.streams_per_account
            || account.tripped
            || account.bytes >= budget
            || open_total >= self.limits.max_streams
        {
            return Err(TunnelError::TUNNEL_LIMIT);
        }
        account.open += 1;
        accounts.open_total += 1;
        Ok(Slot {
            inner: Arc::downgrade(self),
            account: account_id.to_string(),
        })
    }

    /// Opens a stream on the node's WebSocket. `None`: the node is offline.
    fn open(
        self: &Arc<Self>,
        entry: &NodeEntry,
        kind: Kind,
        extra_flags: u8,
        first: Vec<u8>,
        dialer: Option<Caller>,
        slot: Slot,
    ) -> Option<Ticket> {
        let conn = lock(&self.nodes).get(&entry.node_id).cloned()?;
        if conn.account != entry.account_id || first.len() > frame::MAX_PAYLOAD {
            return None;
        }
        let stream = {
            let mut state = lock(&conn.state);
            if conn.closed.load(Ordering::SeqCst) {
                return None;
            }
            let id = state.seq.last_opened().checked_add(1)?;
            let stream = Arc::new(Stream {
                id,
                kind,
                account: entry.account_id.clone(),
                dialer,
                inbox: Mutex::new(Inbox::default()),
                cond: Condvar::new(),
                ended: AtomicBool::new(false),
                activity: AtomicU64::new(self.millis()),
                client_gone: AtomicU64::new(0),
                max_from_node: (kind == Kind::Acme).then_some(64 * 1024),
                from_node: AtomicU64::new(0),
                send: Mutex::new(extra_flags & CLOSE != 0),
                slot: Mutex::new(Some(slot)),
                client: Mutex::new(None),
                writing: AtomicBool::new(false),
            });
            let flags = OPEN | extra_flags;
            state
                .seq
                .apply_head(Dir::ToNode, id, kind, flags, || stream.clone())
                .ok()?;
            let frame = frame::encode(id, kind, flags, &first);
            if !conn.outbox.push(frame, &stream.ended, false) {
                state.seq.remove(id);
                return None;
            }
            stream
        };
        if !first.is_empty() {
            self.count(&conn.account, first.len());
        }
        {
            let mut accounts = lock(&self.accounts);
            if let Some(account) = accounts.by_id.get_mut(&entry.account_id) {
                account.streams += 1;
            }
        }
        Some(Ticket {
            inner: self.clone(),
            conn,
            stream: Some(stream),
        })
    }

    /// Counts bytes of an account; trips the budget once it is spent.
    fn count(self: &Arc<Self>, account_id: &str, bytes: usize) {
        let now = self.clock.now();
        let tripped = {
            let mut accounts = lock(&self.accounts);
            let account = accounts.by_id.entry(account_id.to_string()).or_default();
            account.roll(now);
            account.bytes = account.bytes.saturating_add(bytes as u64);
            if !account.tripped && account.budget > 0 && account.bytes >= account.budget {
                account.tripped = true;
                true
            } else {
                false
            }
        };
        if tripped {
            self.reset_where(
                |_, stream| stream.account == account_id,
                close::TUNNEL_LIMIT,
            );
        }
    }

    /// Resets a stream from Connect's side: a `reset` frame to the node, and `code` to
    /// the client.
    fn abort(&self, conn: &NodeConn, stream: &Arc<Stream>, code: u16) {
        let live = lock(&conn.state).seq.remove(stream.id).is_some();
        if live {
            conn.outbox.push_urgent(Out::Frame(frame::encode(
                stream.id,
                stream.kind,
                RESET,
                &[],
            )));
        }
        stream.finish(code);
        conn.outbox.wake();
        if stream.writing.load(Ordering::SeqCst) {
            let client = lock(&stream.client).clone();
            if let Some(shutdown) = client {
                shutdown();
            }
        }
    }

    /// Resets every live stream that matches. Returns how many.
    fn reset_where(&self, matches: impl Fn(&NodeConn, &Stream) -> bool, code: u16) -> usize {
        let conns: Vec<_> = lock(&self.nodes).values().cloned().collect();
        let mut count = 0;
        for conn in conns {
            let streams: Vec<_> = lock(&conn.state)
                .seq
                .values()
                .filter(|(_, stream)| matches(&conn, stream))
                .map(|(_, stream)| stream.clone())
                .collect();
            for stream in streams {
                self.abort(&conn, &stream, code);
                count += 1;
            }
        }
        count
    }

    /// Closes a node WebSocket with `ws_code` and ends its streams with `stream_code`.
    fn terminate(&self, conn: &NodeConn, ws_code: u16, stream_code: u16) {
        conn.closed.store(true, Ordering::SeqCst);
        {
            let mut nodes = lock(&self.nodes);
            if nodes
                .get(&conn.node_id)
                .is_some_and(|current| current.generation == conn.generation)
            {
                nodes.remove(&conn.node_id);
            }
        }
        conn.outbox.close(ws_code);
        let streams = lock(&conn.state).seq.drain();
        for (_, stream) in streams {
            stream.finish(stream_code);
        }
    }

    fn maintain(&self) {
        let now = self.millis();
        let idle = self.limits.stream_idle.as_millis() as u64;
        let grace = self.limits.close_grace.as_millis() as u64;
        self.reset_where(
            |_, stream| {
                let gone = stream.client_gone.load(Ordering::Relaxed);
                now.saturating_sub(stream.activity.load(Ordering::Relaxed)) >= idle
                    || (gone != 0 && now.saturating_sub(gone) >= grace)
            },
            close::RESET_BY_NODE,
        );
    }

    // ----- The node's WebSocket.

    fn node_reader(self: &Arc<Self>, conn: &Arc<NodeConn>, reader: Box<dyn Read + Send>) {
        let mut reader = ws::Reader::server(reader, frame::MAX_MESSAGE);
        let code = loop {
            match reader.read_message() {
                Ok(Message::Binary(message)) => match frame::decode(&message) {
                    Ok(frame) => self.node_frame(conn, frame),
                    Err(_) => break Some(close::PROTOCOL),
                },
                Ok(Message::Text) => break Some(close::UNSUPPORTED),
                Ok(Message::Ping(payload)) => conn.outbox.push_urgent(Out::Pong(payload)),
                Ok(Message::Pong(_)) => {}
                Ok(Message::Close(_)) => break Some(close::NORMAL),
                // Contract section 4: a message over 8 + 16384 bytes is a malformed frame.
                Err(WsError::TooBig) => break Some(close::PROTOCOL),
                Err(error) => break error.close_code(),
            }
        };
        match code {
            Some(code) => self.terminate(conn, code, close::NODE_OFFLINE),
            None => {
                self.terminate(conn, close::NORMAL, close::NODE_OFFLINE);
                (conn.shutdown)();
            }
        }
    }

    fn node_frame(self: &Arc<Self>, conn: &Arc<NodeConn>, frame: frame::Frame) {
        let applied = lock(&conn.state)
            .seq
            .apply(Dir::ToConnect, &frame, unreachable_stream);
        let (reset, closing) = (frame.is_reset(), frame.is_close());
        match applied {
            Ok(Applied::Frame {
                value: stream,
                ended,
            }) => {
                if !frame.payload.is_empty() {
                    self.count(&conn.account, frame.payload.len());
                    stream.touch(self);
                    if !self.deliver(&stream, frame.payload) {
                        self.abort(conn, &stream, close::RESET_BY_NODE);
                        return;
                    }
                }
                if reset {
                    stream.finish(close::RESET_BY_NODE);
                } else {
                    if closing {
                        lock(&stream.inbox).node_closed = true;
                        stream.cond.notify_all();
                    }
                    if ended {
                        stream.finish(close::NORMAL);
                    }
                }
            }
            Ok(Applied::Opened(_)) | Ok(Applied::Dropped) => {}
            Err(_) => {
                // A broken stream rule resets that stream if it is live; a frame for
                // no live stream has nothing to reset (and a reset is never answered).
                let live = lock(&conn.state).seq.get(frame.stream).cloned();
                if let Some(stream) = live
                    && !frame.is_reset()
                {
                    self.abort(conn, &stream, close::RESET_BY_NODE);
                }
            }
        }
    }

    /// Queues bytes for the client. `false`: over the stream's buffer (reset it).
    fn deliver(&self, stream: &Stream, payload: Vec<u8>) -> bool {
        if let Some(max) = stream.max_from_node {
            let total = stream
                .from_node
                .fetch_add(payload.len() as u64, Ordering::SeqCst)
                + payload.len() as u64;
            if total > max as u64 {
                return false;
            }
        }
        let mut inbox = lock(&stream.inbox);
        if inbox.end.is_some() || inbox.client_close.is_some() {
            return true; // the client is gone: drop
        }
        if inbox.bytes + payload.len() > self.limits.stream_buffer {
            return false;
        }
        inbox.bytes += payload.len();
        inbox.chunks.push_back(payload);
        stream.cond.notify_all();
        true
    }

    fn node_writer(&self, conn: &NodeConn, mut writer: Box<dyn Write + Send>) {
        let mut ping_at = Instant::now() + self.limits.ping_interval;
        loop {
            let result = match conn.outbox.next(ping_at) {
                Next::Send(Out::Frame(frame)) => {
                    ws::write_frame(&mut *writer, ws::OP_BINARY, &frame, None)
                }
                Next::Send(Out::Pong(payload)) => {
                    ws::write_frame(&mut *writer, ws::OP_PONG, &payload, None)
                }
                Next::Ping => {
                    ping_at = Instant::now() + self.limits.ping_interval;
                    ws::write_frame(&mut *writer, ws::OP_PING, &[], None)
                }
                Next::Close(code) => {
                    let _ =
                        ws::write_frame(&mut *writer, ws::OP_CLOSE, &ws::close_payload(code), None);
                    (conn.shutdown)();
                    return;
                }
            };
            if result.is_err() {
                self.terminate(conn, close::NORMAL, close::NODE_OFFLINE);
                (conn.shutdown)();
                return;
            }
        }
    }

    // ----- Client sides.

    /// Sends client bytes on a stream, in frames of at most 16384 bytes. `false`: the
    /// stream or the node is gone.
    fn send_client_bytes(self: &Arc<Self>, conn: &NodeConn, stream: &Stream, bytes: &[u8]) -> bool {
        for chunk in bytes.chunks(frame::MAX_PAYLOAD) {
            let closed = lock(&stream.send);
            if *closed || stream.is_ended() {
                return false;
            }
            let frame = frame::encode(stream.id, stream.kind, 0, chunk);
            if !conn.outbox.push(frame, &stream.ended, true) {
                return false;
            }
            drop(closed);
            self.count(&stream.account, chunk.len());
            stream.touch(self);
        }
        true
    }

    /// The client closed its direction: a `close` frame to the node. `websocket`: reply
    /// to the client's close.
    fn client_closed(&self, conn: &NodeConn, stream: &Arc<Stream>, websocket: bool) {
        if websocket {
            let mut inbox = lock(&stream.inbox);
            inbox.client_close = Some(close::NORMAL);
            inbox.chunks.clear();
            inbox.bytes = 0;
            stream.cond.notify_all();
        }
        {
            let mut closed = lock(&stream.send);
            if *closed {
                return;
            }
            *closed = true;
            let frame = frame::encode(stream.id, stream.kind, CLOSE, &[]);
            if !conn.outbox.push(frame, &stream.ended, true) {
                return;
            }
        }
        let ended = matches!(
            lock(&conn.state)
                .seq
                .apply_head(Dir::ToNode, stream.id, stream.kind, CLOSE, || {
                    unreachable_stream()
                }),
            Ok(Applied::Frame { ended: true, .. })
        );
        if ended {
            stream.finish(close::NORMAL);
        }
    }

    fn client_left(&self, stream: &Stream) {
        let _ = stream.client_gone.compare_exchange(
            0,
            self.millis().max(1),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    fn spawn_dial(
        self: &Arc<Self>,
        conn: Arc<NodeConn>,
        stream: Arc<Stream>,
        transport: Transport,
    ) {
        let Transport {
            reader,
            writer,
            shutdown,
        } = transport;
        *lock(&stream.client) = Some(shutdown.clone());
        // Only the writer shuts the socket down, after it wrote the close code.
        let (inner, read_conn, read_stream) = (self.clone(), conn.clone(), stream.clone());
        let started = spawn("tunnel-dial-read", move || {
            inner.dial_reader(&read_conn, &read_stream, reader);
        });
        let (inner, write_conn, write_stream) = (self.clone(), conn.clone(), stream.clone());
        let started = started
            && spawn("tunnel-dial-write", move || {
                inner.dial_writer(&write_conn, &write_stream, writer, &shutdown);
            });
        if !started {
            self.abort(&conn, &stream, close::INTERNAL);
        }
    }

    fn dial_reader(
        self: &Arc<Self>,
        conn: &NodeConn,
        stream: &Arc<Stream>,
        reader: Box<dyn Read + Send>,
    ) {
        let mut reader = ws::Reader::server(reader, frame::MAX_PAYLOAD);
        loop {
            match reader.read_message() {
                Ok(Message::Binary(bytes)) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    if !self.send_client_bytes(conn, stream, &bytes) {
                        return;
                    }
                }
                Ok(Message::Text) => return self.abort(conn, stream, close::UNSUPPORTED),
                // Pings and pongs keep the WebSocket, not the stream, alive.
                Ok(Message::Ping(payload)) => {
                    lock(&stream.inbox).pong = Some(payload);
                    stream.cond.notify_all();
                }
                Ok(Message::Pong(_)) => {}
                Ok(Message::Close(_)) => {
                    self.client_closed(conn, stream, true);
                    self.client_left(stream);
                    return;
                }
                Err(error) => {
                    let code = error.close_code().unwrap_or(close::NORMAL);
                    return self.abort(conn, stream, code);
                }
            }
        }
    }

    fn dial_writer(
        &self,
        conn: &NodeConn,
        stream: &Arc<Stream>,
        mut writer: Box<dyn Write + Send>,
        shutdown: &Arc<dyn Fn() + Send + Sync>,
    ) {
        enum Act {
            Data(Vec<u8>),
            Pong(Vec<u8>),
            Ping,
            /// Close the WebSocket with this code and stop.
            Close(u16, bool),
        }
        let mut ping_at = Instant::now() + self.limits.ping_interval;
        loop {
            let act = {
                let mut inbox = lock(&stream.inbox);
                loop {
                    if let Some(code) = inbox.end
                        && (code != close::NORMAL || inbox.chunks.is_empty())
                    {
                        break Act::Close(code, false);
                    }
                    if let Some(code) = inbox.client_close.take() {
                        break Act::Close(code, false);
                    }
                    if let Some(payload) = inbox.pong.take() {
                        break Act::Pong(payload);
                    }
                    if let Some(chunk) = inbox.chunks.pop_front() {
                        inbox.bytes -= chunk.len();
                        break Act::Data(chunk);
                    }
                    if inbox.node_closed {
                        break Act::Close(close::NORMAL, true);
                    }
                    let now = Instant::now();
                    if now >= ping_at {
                        break Act::Ping;
                    }
                    inbox = stream
                        .cond
                        .wait_timeout(inbox, ping_at - now)
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .0;
                }
            };
            stream.writing.store(true, Ordering::SeqCst);
            let result = match act {
                Act::Data(chunk) => ws::write_frame(&mut *writer, ws::OP_BINARY, &chunk, None),
                Act::Pong(payload) => ws::write_frame(&mut *writer, ws::OP_PONG, &payload, None),
                Act::Ping => {
                    ping_at = Instant::now() + self.limits.ping_interval;
                    ws::write_frame(&mut *writer, ws::OP_PING, &[], None)
                }
                Act::Close(code, node_closed) => {
                    let _ =
                        ws::write_frame(&mut *writer, ws::OP_CLOSE, &ws::close_payload(code), None);
                    self.client_left(stream);
                    if node_closed {
                        // The dial ends with the node's close: close the other direction.
                        self.client_closed(conn, stream, false);
                    }
                    shutdown();
                    return;
                }
            };
            stream.writing.store(false, Ordering::SeqCst);
            if result.is_err() {
                self.client_left(stream);
                self.abort(conn, stream, close::NORMAL);
                shutdown();
                return;
            }
        }
    }

    fn spawn_raw(
        self: &Arc<Self>,
        conn: Arc<NodeConn>,
        stream: Arc<Stream>,
        tcp: TcpStream,
        read_client: bool,
    ) {
        let setup = tcp
            .set_read_timeout(Some(self.limits.stream_idle))
            .and_then(|()| tcp.set_write_timeout(Some(self.limits.idle_timeout)))
            .and_then(|()| tcp.try_clone());
        let Ok(reader) = setup else {
            return self.abort(&conn, &stream, close::INTERNAL);
        };
        if let Ok(closer) = tcp.try_clone() {
            *lock(&stream.client) = Some(Arc::new(move || {
                let _ = closer.shutdown(Shutdown::Both);
            }));
        }
        let mut started = true;
        if read_client {
            let (inner, read_conn, read_stream) = (self.clone(), conn.clone(), stream.clone());
            started = spawn("tunnel-raw-read", move || {
                inner.raw_reader(&read_conn, &read_stream, reader);
            });
        }
        let (inner, write_conn, write_stream) = (self.clone(), conn.clone(), stream.clone());
        let started = started
            && spawn("tunnel-raw-write", move || {
                inner.raw_writer(&write_conn, &write_stream, tcp);
            });
        if !started {
            self.abort(&conn, &stream, close::INTERNAL);
        }
    }

    fn raw_reader(self: &Arc<Self>, conn: &NodeConn, stream: &Arc<Stream>, mut tcp: TcpStream) {
        let mut buffer = vec![0u8; frame::MAX_PAYLOAD];
        loop {
            match tcp.read(&mut buffer) {
                Ok(0) => return self.client_closed(conn, stream, false),
                Ok(read) => {
                    if !self.send_client_bytes(conn, stream, &buffer[..read]) {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.client_left(stream);
                    return self.abort(conn, stream, close::NORMAL);
                }
            }
        }
    }

    fn raw_writer(&self, conn: &NodeConn, stream: &Arc<Stream>, mut tcp: TcpStream) {
        let mut write_closed = false;
        loop {
            let chunk = {
                let mut inbox = lock(&stream.inbox);
                loop {
                    if let Some(code) = inbox.end
                        && (code != close::NORMAL || inbox.chunks.is_empty())
                    {
                        drop(inbox);
                        let _ = tcp.shutdown(Shutdown::Both);
                        return;
                    }
                    if let Some(chunk) = inbox.chunks.pop_front() {
                        inbox.bytes -= chunk.len();
                        break Some(chunk);
                    }
                    if inbox.node_closed && !write_closed {
                        break None;
                    }
                    inbox = stream
                        .cond
                        .wait_timeout(inbox, Duration::from_secs(1))
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .0;
                }
            };
            match chunk {
                Some(chunk) => {
                    stream.writing.store(true, Ordering::SeqCst);
                    let written = tcp.write_all(&chunk).and_then(|()| tcp.flush());
                    stream.writing.store(false, Ordering::SeqCst);
                    if written.is_err() {
                        self.client_left(stream);
                        self.abort(conn, stream, close::NORMAL);
                        let _ = tcp.shutdown(Shutdown::Both);
                        return;
                    }
                }
                None => {
                    // The node closed its direction: half-close toward the client.
                    write_closed = true;
                    let _ = tcp.shutdown(Shutdown::Write);
                }
            }
        }
    }
}

fn unreachable_stream() -> Arc<Stream> {
    // `apply` from the node's side or with `CLOSE` never opens a stream (`open_by_node`
    // first), so this value is never made.
    unreachable!("a stream opened by the node or by a close")
}

/// An in-memory [`TunnelDirectory`] for tests and for a self-hosted relay without
/// accounts.
#[derive(Default)]
pub struct MemoryDirectory {
    state: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    tokens: HashMap<String, Result<Caller, Refusal>>,
    nodes: HashMap<String, NodeEntry>,
    grants: HashSet<(String, String)>,
    entitled: HashSet<String>,
    units: HashMap<String, u64>,
}

impl MemoryDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// A device of an account, signed in with `token`. The account is entitled.
    pub fn add_device(&self, token: &str, account_id: &str, device_id: &str) {
        let mut state = lock(&self.state);
        state.tokens.insert(
            token.to_string(),
            Ok(Caller {
                account_id: account_id.to_string(),
                device_id: device_id.to_string(),
            }),
        );
        state.entitled.insert(account_id.to_string());
    }

    /// A token that is not an account token (a team token).
    pub fn add_team_token(&self, token: &str) {
        lock(&self.state)
            .tokens
            .insert(token.to_string(), Err(Refusal::AccountRequired));
    }

    /// Registers the node of a device.
    pub fn add_node(&self, node_id: &str, account_id: &str, device_id: &str) {
        lock(&self.state).nodes.insert(
            node_id.to_string(),
            NodeEntry {
                node_id: node_id.to_string(),
                account_id: account_id.to_string(),
                device_id: device_id.to_string(),
            },
        );
    }

    pub fn grant(&self, node_id: &str, grantee_account: &str) {
        lock(&self.state)
            .grants
            .insert((node_id.to_string(), grantee_account.to_string()));
    }

    pub fn revoke(&self, node_id: &str, grantee_account: &str) {
        lock(&self.state)
            .grants
            .remove(&(node_id.to_string(), grantee_account.to_string()));
    }

    pub fn set_entitled(&self, account_id: &str, entitled: bool) {
        let mut state = lock(&self.state);
        if entitled {
            state.entitled.insert(account_id.to_string());
        } else {
            state.entitled.remove(account_id);
        }
    }

    pub fn set_budget_units(&self, account_id: &str, units: u64) {
        lock(&self.state)
            .units
            .insert(account_id.to_string(), units);
    }
}

impl TunnelDirectory for MemoryDirectory {
    fn caller(&self, bearer: &str) -> Result<Caller, Refusal> {
        lock(&self.state)
            .tokens
            .get(bearer)
            .cloned()
            .unwrap_or(Err(Refusal::Unauthenticated))
    }

    fn device_node(&self, caller: &Caller) -> Option<NodeEntry> {
        lock(&self.state)
            .nodes
            .values()
            .find(|node| node.device_id == caller.device_id && node.account_id == caller.account_id)
            .cloned()
    }

    fn node(&self, node_id: &str) -> Option<NodeEntry> {
        lock(&self.state).nodes.get(node_id).cloned()
    }

    fn has_grant(&self, node_id: &str, grantee_account: &str) -> bool {
        lock(&self.state)
            .grants
            .contains(&(node_id.to_string(), grantee_account.to_string()))
    }

    fn entitled(&self, account_id: &str) -> bool {
        lock(&self.state).entitled.contains(account_id)
    }

    fn budget_units(&self, account_id: &str) -> u64 {
        lock(&self.state)
            .units
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months_and_names() {
        assert_eq!(month_of(0), 197001);
        // 2026-11-03T00:00:00Z
        assert_eq!(month_of(1_793_664_000), 202611);
        // 2026-11-30T23:59:59Z and 2026-12-01T00:00:00Z
        assert_eq!(month_of(1_796_083_199), 202611);
        assert_eq!(month_of(1_796_083_200), 202612);
        // 2024-02-29
        assert_eq!(month_of(1_709_164_800), 202402);
        assert!(valid_node_id("node_k7m2q4x3ca"));
        assert!(!valid_node_id("node_k7m2q4x3c1"));
        assert!(!valid_node_id("node_K7m2q4x3ca"));
        assert_eq!(
            public_name("node_k7m2q4x3ca", "Node.Example.Test").as_deref(),
            Some("k7m2q4x3ca.node.example.test")
        );
        assert_eq!(
            node_of_public_name("K7M2Q4X3CA.node.example.test", "node.example.test").as_deref(),
            Some("node_k7m2q4x3ca")
        );
        assert_eq!(
            node_of_public_name("a.b.node.example.test", "node.example.test"),
            None
        );
        assert_eq!(
            node_of_public_name("k7m2q4x3ca.node.example.test.", "node.example.test"),
            None
        );
    }
}
