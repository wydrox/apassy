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
//! Each stream is in one class of the node's account, with its own slots and counts: the
//! dials of the account's own devices, the dials of another account with a grant (a share
//! of the slots and of the dial budget), and the public and ACME streams of the ingress
//! (slots, a per-node open rate, a first-byte deadline, and a byte budget of their own).
//! See [`Limits`].
//!
//! A node's `close` ends the stream for its client, a dial and an ingress connection
//! alike: the client gets the last bytes, then its connection closes, and Connect closes
//! the client's direction; client bytes after the node's close are neither forwarded nor
//! counted.
//!
//! Every queue has a cap. A node's outgoing queue holds at most
//! [`Limits::node_queue`] bytes; a client that sends faster waits (backpressure to its
//! TCP window). A stream buffers at most [`Limits::stream_buffer`] bytes toward a
//! client; over it the stream is reset (contract section 4). Resets and pongs go ahead
//! of the data, bounded by the streams (one reset for each, one pong): none is dropped,
//! and a reset never goes ahead of its own stream's `open` (a stream whose `open` was
//! still queued leaves the queue without a trace). Reads have an idle limit, writes a
//! timeout, and a maintenance thread resets idle streams and asks the directory again
//! about the plans and grants of the open streams ([`Limits::recheck`]).
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
///
/// Each account has three kinds of open streams, each with its own slots and counts:
/// the dials of its own devices, the dials of other accounts with a grant (a share of
/// the dial slots and of the dial budget, so the account's own devices always keep the
/// rest), and the public and ACME streams of the ingress (slots, an open rate, and a byte
/// budget of their own, so a stranger at the ingress never makes a dial fail).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Open dials of one account's nodes (its own devices and other accounts together).
    pub streams_per_account: usize,
    /// Nodes of one account online at once (the store also refuses a ninth node).
    pub nodes_per_account: usize,
    /// Dials in one clock minute: of one account's own devices, and of each other account
    /// to the nodes of one account (each pair counts apart).
    pub dials_per_minute: u32,
    /// Dial bytes of one account in one UTC month, both directions, for each budget unit
    /// ([`TunnelDirectory::budget_units`]: each person of Family, each member of Team).
    pub bytes_per_month: u64,
    /// Open dials of one other account to the nodes of one account.
    pub streams_per_grantee: usize,
    /// Open dials of all other accounts together to the nodes of one account: at most
    /// this many of [`Limits::streams_per_account`]; the rest stays for its own devices.
    pub grantee_streams: usize,
    /// The share of the dial budget, in percent, that the dials of other accounts may
    /// spend together; the rest stays for the account's own devices.
    pub grantee_bytes_percent: u64,
    /// Open public and ACME streams of one account: slots of their own.
    pub ingress_streams: usize,
    /// New public and ACME streams of one node in one clock minute.
    pub ingress_per_minute: u32,
    /// The node sends its first frame on a public or ACME stream within this, else the
    /// stream is reset.
    pub ingress_first_byte: Duration,
    /// Bytes of the public and ACME streams of one account in one UTC month, for each
    /// budget unit: a budget of their own, apart from the dial budget.
    pub ingress_bytes_per_month: u64,
    /// How often the plan of each account with open streams, and the grant of each open
    /// dial of another account, are checked again (a plan or a group can end by time).
    pub recheck: Duration,
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
            streams_per_grantee: 16,
            grantee_streams: 32,
            grantee_bytes_percent: 50,
            ingress_streams: 16,
            ingress_per_minute: 60,
            ingress_first_byte: Duration::from_secs(10),
            ingress_bytes_per_month: 5 * 1024 * 1024 * 1024,
            recheck: Duration::from_secs(60),
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

/// The tunnel use of one account in one month, or of one part of it
/// ([`Broker::ingress_usage`], [`Broker::grantee_usage`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    /// `yyyymm`, UTC.
    pub month: u32,
    pub bytes: u64,
    pub dials: u64,
    pub streams: u64,
    /// Open streams now (not stored).
    pub open_streams: usize,
    /// Over its byte budget this month.
    pub tripped: bool,
}

/// The stored key of the ingress counters of an account: `<account>/ingress`.
const INGRESS_SUFFIX: &str = "/ingress";
/// The stored key of the counters of another account's dials to an account's nodes:
/// `<account>/dial/<other account>`.
const GRANTEE_INFIX: &str = "/dial/";

/// Who opened a stream, for the slots and the counts of the node's account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Class {
    /// A dial of a device of the node's account.
    Own,
    /// A dial of a device of another account, with a grant.
    Grantee(String),
    /// A public or ACME stream of the ingress.
    Ingress,
}

/// The counts of one other account's dials to the nodes of an account.
#[derive(Debug, Default)]
struct Grantee {
    bytes: u64,
    dials: u64,
    streams: u64,
    open: usize,
    minute: u64,
    minute_dials: u32,
}

#[derive(Debug, Default)]
struct Account {
    month: u32,
    /// Every byte of the month, dials and ingress (the stored row of the account).
    bytes: u64,
    /// Every dial of the month, of its own devices and of other accounts.
    dials: u64,
    /// Every stream of the month.
    streams: u64,
    /// The dial budget of the month is spent.
    tripped: bool,
    budget: u64,
    minute: u64,
    minute_dials: u32,
    /// Open dials (its own devices and other accounts).
    open: usize,
    ingress_bytes: u64,
    ingress_streams: u64,
    ingress_tripped: bool,
    ingress_budget: u64,
    ingress_open: usize,
    grantees: HashMap<String, Grantee>,
    /// Bytes of all other accounts' dials this month.
    grantee_bytes: u64,
    grantees_tripped: bool,
    grantee_budget: u64,
    grantee_open: usize,
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
            self.ingress_bytes = 0;
            self.ingress_streams = 0;
            self.ingress_tripped = false;
            self.grantee_bytes = 0;
            self.grantees_tripped = false;
            self.grantees.retain(|_, grantee| grantee.open > 0);
            for grantee in self.grantees.values_mut() {
                grantee.bytes = 0;
                grantee.dials = 0;
                grantee.streams = 0;
            }
        }
        let minute = now / 60;
        if self.minute != minute {
            self.minute = minute;
            self.minute_dials = 0;
        }
    }

    /// The bytes of the dials this month (all bytes but the ingress's).
    fn dial_bytes(&self) -> u64 {
        self.bytes.saturating_sub(self.ingress_bytes)
    }

    fn dials_spent(&self) -> bool {
        self.tripped || (self.budget > 0 && self.dial_bytes() >= self.budget)
    }

    fn grantees_spent(&self) -> bool {
        self.grantees_tripped || (self.budget > 0 && self.grantee_bytes >= self.grantee_budget)
    }

    fn ingress_spent(&self) -> bool {
        self.ingress_tripped
            || (self.ingress_budget > 0 && self.ingress_bytes >= self.ingress_budget)
    }

    fn usage(&self) -> Usage {
        Usage {
            month: self.month,
            bytes: self.bytes,
            dials: self.dials,
            streams: self.streams,
            open_streams: self.open + self.ingress_open,
            tripped: self.tripped,
        }
    }

    fn ingress_usage(&self) -> Usage {
        Usage {
            month: self.month,
            bytes: self.ingress_bytes,
            dials: 0,
            streams: self.ingress_streams,
            open_streams: self.ingress_open,
            tripped: self.ingress_tripped,
        }
    }

    fn grantee_usage(&self, grantee: &str) -> Usage {
        let counts = self.grantees.get(grantee);
        Usage {
            month: self.month,
            bytes: counts.map_or(0, |counts| counts.bytes),
            dials: counts.map_or(0, |counts| counts.dials),
            streams: counts.map_or(0, |counts| counts.streams),
            open_streams: counts.map_or(0, |counts| counts.open),
            tripped: self.grantees_tripped,
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
    class: Class,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut accounts = lock(&inner.accounts);
            accounts.open_total = accounts.open_total.saturating_sub(1);
            if let Some(account) = accounts.by_id.get_mut(&self.account) {
                match &self.class {
                    Class::Own => account.open = account.open.saturating_sub(1),
                    Class::Grantee(grantee) => {
                        account.open = account.open.saturating_sub(1);
                        account.grantee_open = account.grantee_open.saturating_sub(1);
                        if let Some(counts) = account.grantees.get_mut(grantee) {
                            counts.open = counts.open.saturating_sub(1);
                        }
                    }
                    Class::Ingress => {
                        account.ingress_open = account.ingress_open.saturating_sub(1);
                    }
                }
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

/// A frame in the ordered queue, with the stream it belongs to.
struct Queued {
    stream: u32,
    /// The `open` of its stream.
    open: bool,
    frame: Vec<u8>,
}

#[derive(Default)]
struct OutState {
    /// Resets and pongs: may pass queued data (a reset can cross data in flight). At most
    /// one pong (a new one replaces it) and one reset for each stream that Connect ends,
    /// so its length is bounded by the streams of the WebSocket: nothing here is dropped.
    urgent: VecDeque<Out>,
    /// Opens, data, and closes, in order.
    fifo: VecDeque<Queued>,
    fifo_bytes: usize,
    close: Option<u16>,
}

/// The queue toward one node: a byte cap with backpressure for data; control messages
/// are bounded by the stream count.
struct Outbox {
    state: Mutex<OutState>,
    ready: Condvar,
    space: Condvar,
    cap: usize,
}

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

    /// Queues a pong ahead of the data; it replaces a queued pong.
    fn push_pong(&self, payload: Vec<u8>) {
        let mut state = lock(&self.state);
        if state.close.is_some() {
            return;
        }
        state
            .urgent
            .retain(|queued| !matches!(queued, Out::Pong(_)));
        state.urgent.push_back(Out::Pong(payload));
        self.ready.notify_one();
    }

    /// Ends a stream in the queue. Its queued frames leave the queue. When its `open` was
    /// still among them, the node never heard of the stream and nothing is sent; else its
    /// `reset` goes ahead of the data, never ahead of its own `open`, and is never
    /// dropped.
    fn cancel(&self, stream: u32, reset: Vec<u8>) {
        let mut state = lock(&self.state);
        if state.close.is_some() {
            return;
        }
        let unsent_open = state
            .fifo
            .iter()
            .any(|queued| queued.stream == stream && queued.open);
        let mut freed = 0;
        state.fifo.retain(|queued| {
            let keep = queued.stream != stream;
            if !keep {
                freed += queued.frame.len();
            }
            keep
        });
        state.fifo_bytes -= freed;
        if freed > 0 {
            self.space.notify_all();
        }
        if !unsent_open {
            state.urgent.push_back(Out::Frame(reset));
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
        let stream = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let open = frame[5] & OPEN != 0;
        state.fifo_bytes += frame.len();
        state.fifo.push_back(Queued {
            stream,
            open,
            frame,
        });
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
            if let Some(queued) = state.fifo.pop_front() {
                state.fifo_bytes -= queued.frame.len();
                self.space.notify_all();
                return Next::Send(Out::Frame(queued.frame));
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
    /// Whose slot and counts the stream uses in the node's account.
    class: Class,
    /// The device that dialed (device streams only).
    dialer: Option<Caller>,
    inbox: Mutex<Inbox>,
    cond: Condvar,
    ended: AtomicBool,
    /// The node closed its direction or reset the stream: client bytes are no longer
    /// forwarded or counted, and the client side ends after the node's last bytes.
    node_done: AtomicBool,
    /// A frame of the node arrived on this stream.
    node_seen: AtomicBool,
    /// Milliseconds since the broker's epoch when the stream opened.
    opened: u64,
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
    /// The clock minute and the public and ACME streams opened in it.
    ingress_minute: Mutex<(u64, u32)>,
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
    /// Milliseconds since the epoch of the last check of plans and grants.
    rechecked: AtomicU64,
    /// Ended streams whose client writer was inside a write, with a deadline.
    stuck: Mutex<Vec<(Arc<Stream>, u64)>>,
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
            rechecked: AtomicU64::new(0),
            stuck: Mutex::new(Vec::new()),
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

    /// The use of an account this month: every byte, dial, and stream of its nodes;
    /// `open_streams` counts its open dials and ingress streams, `tripped` its dial budget.
    pub fn usage(&self, account_id: &str) -> Usage {
        self.with_account(account_id, |account| account.usage())
    }

    /// The public and ACME streams of an account this month (their own budget).
    pub fn ingress_usage(&self, account_id: &str) -> Usage {
        self.with_account(account_id, |account| account.ingress_usage())
    }

    /// The dials of `grantee`'s devices to the nodes of `account_id` this month;
    /// `tripped` is the share of all other accounts.
    pub fn grantee_usage(&self, account_id: &str, grantee: &str) -> Usage {
        self.with_account(account_id, |account| account.grantee_usage(grantee))
    }

    fn with_account<T>(&self, account_id: &str, read: impl FnOnce(&Account) -> T) -> T {
        let now = self.inner.clock.now();
        let mut accounts = lock(&self.inner.accounts);
        let account = accounts.by_id.entry(account_id.to_string()).or_default();
        account.roll(now);
        read(account)
    }

    /// The counters of every account with use this month, to store (contract section 9):
    /// the account's own row (key: the account id), its ingress (`<account>/ingress`), and
    /// each other account that dialed its nodes (`<account>/dial/<other account>`).
    pub fn usage_all(&self) -> Vec<(String, Usage)> {
        let now = self.inner.clock.now();
        let mut accounts = lock(&self.inner.accounts);
        let mut out = Vec::new();
        for (id, account) in accounts.by_id.iter_mut() {
            account.roll(now);
            out.push((id.clone(), account.usage()));
            if account.ingress_bytes > 0 || account.ingress_streams > 0 {
                out.push((format!("{id}{INGRESS_SUFFIX}"), account.ingress_usage()));
            }
            for (grantee, counts) in &account.grantees {
                if counts.bytes > 0 || counts.dials > 0 || counts.streams > 0 {
                    out.push((
                        format!("{id}{GRANTEE_INFIX}{grantee}"),
                        account.grantee_usage(grantee),
                    ));
                }
            }
        }
        out
    }

    /// Restores stored counters of the current month after a restart, by the keys of
    /// [`Broker::usage_all`]. Counters of another month are ignored.
    pub fn restore_usage(&self, key: &str, usage: &Usage) {
        let now = self.inner.clock.now();
        if usage.month != month_of(now) {
            return;
        }
        let (account_id, part) = match key.split_once('/') {
            Some((account_id, _)) => (account_id, &key[account_id.len()..]),
            None => (key, ""),
        };
        let mut accounts = lock(&self.inner.accounts);
        let account = accounts.by_id.entry(account_id.to_string()).or_default();
        account.roll(now);
        if part.is_empty() {
            account.bytes = account.bytes.max(usage.bytes);
            account.dials = account.dials.max(usage.dials);
            account.streams = account.streams.max(usage.streams);
            account.tripped |= usage.tripped;
        } else if part == INGRESS_SUFFIX {
            account.ingress_bytes = account.ingress_bytes.max(usage.bytes);
            account.ingress_streams = account.ingress_streams.max(usage.streams);
        } else if let Some(grantee) = part.strip_prefix(GRANTEE_INFIX)
            && !grantee.is_empty()
        {
            let counts = account.grantees.entry(grantee.to_string()).or_default();
            counts.bytes = counts.bytes.max(usage.bytes);
            counts.dials = counts.dials.max(usage.dials);
            counts.streams = counts.streams.max(usage.streams);
            account.grantee_bytes = account.grantees.values().map(|counts| counts.bytes).sum();
        }
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
            ingress_minute: Mutex::new((0, 0)),
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
        let class = if caller.account_id == entry.account_id {
            Class::Own
        } else {
            Class::Grantee(caller.account_id.clone())
        };
        let slot = self.inner.reserve(&entry, &class)?;
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
            .reserve(&entry, &Class::Ingress)
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

    /// `GET /v1/tunnel/node`: answers an error, or `101` and runs the WebSocket. Returns
    /// the refusal it answered, so the caller can count a bad token.
    pub fn serve_node(&self, request: tiny_http::Request) -> Option<TunnelError> {
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
                None
            }
            (Err(error), _) => {
                respond_error(request, &error);
                Some(error)
            }
            (Ok(_), Err(error)) => {
                let error = TunnelError::invalid(error);
                respond_error(request, &error);
                Some(error)
            }
        }
    }

    /// `GET /v1/tunnel/dial/{node_id}`: answers an error, or `101` and runs the dial.
    /// Returns the refusal it answered, so the caller can count a bad token.
    pub fn serve_dial(&self, request: tiny_http::Request, node_id: &str) -> Option<TunnelError> {
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
                None
            }
            (Err(error), _) => {
                respond_error(request, &error);
                Some(error)
            }
            (Ok(_), Err(error)) => {
                let error = TunnelError::invalid(error);
                respond_error(request, &error);
                Some(error)
            }
        }
    }

    /// `DELETE /v1/tunnel/grants/{id}`: resets the grantee's open streams to the node
    /// (close 4003 to its devices). Returns how many.
    pub fn revoke_grant(&self, node_id: &str, grantee_account: &str) -> usize {
        self.inner.revoke_grant(node_id, grantee_account)
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

    /// Reserves an open-stream slot of the node's account for a stream of `class`, and
    /// counts a dial. Each class has its own slots and checks (see [`Limits`]).
    fn reserve(self: &Arc<Self>, entry: &NodeEntry, class: &Class) -> Result<Slot, TunnelError> {
        let account_id = entry.account_id.as_str();
        let units = self.directory.budget_units(account_id).max(1);
        let budget = self.limits.bytes_per_month.saturating_mul(units);
        let ingress_budget = self.limits.ingress_bytes_per_month.saturating_mul(units);
        let grantee_budget = u64::try_from(
            u128::from(budget) * u128::from(self.limits.grantee_bytes_percent.min(100)) / 100,
        )
        .unwrap_or(u64::MAX);
        let now = self.clock.now();
        if *class == Class::Ingress && !self.ingress_rate(&entry.node_id, now) {
            return Err(TunnelError::TUNNEL_LIMIT);
        }
        let limits = &self.limits;
        let mut accounts = lock(&self.accounts);
        let full = accounts.open_total >= limits.max_streams;
        let account = accounts.by_id.entry(account_id.to_string()).or_default();
        account.roll(now);
        account.budget = budget;
        account.ingress_budget = ingress_budget;
        account.grantee_budget = grantee_budget;
        match class {
            Class::Own => {
                if account.minute_dials >= limits.dials_per_minute {
                    return Err(TunnelError::TUNNEL_LIMIT);
                }
                account.minute_dials += 1;
                account.dials += 1;
                if full || account.open >= limits.streams_per_account || account.dials_spent() {
                    return Err(TunnelError::TUNNEL_LIMIT);
                }
                account.open += 1;
            }
            Class::Grantee(grantee) => {
                let spent = account.dials_spent() || account.grantees_spent();
                let counts = account.grantees.entry(grantee.clone()).or_default();
                let minute = now / 60;
                if counts.minute != minute {
                    counts.minute = minute;
                    counts.minute_dials = 0;
                }
                if counts.minute_dials >= limits.dials_per_minute {
                    return Err(TunnelError::TUNNEL_LIMIT);
                }
                counts.minute_dials += 1;
                counts.dials += 1;
                account.dials += 1;
                if full
                    || spent
                    || counts.open >= limits.streams_per_grantee
                    || account.grantee_open >= limits.grantee_streams
                    || account.open >= limits.streams_per_account
                {
                    return Err(TunnelError::TUNNEL_LIMIT);
                }
                counts.open += 1;
                account.grantee_open += 1;
                account.open += 1;
            }
            Class::Ingress => {
                if full || account.ingress_open >= limits.ingress_streams || account.ingress_spent()
                {
                    return Err(TunnelError::TUNNEL_LIMIT);
                }
                account.ingress_open += 1;
            }
        }
        accounts.open_total += 1;
        Ok(Slot {
            inner: Arc::downgrade(self),
            account: account_id.to_string(),
            class: class.clone(),
        })
    }

    /// Counts a new public or ACME stream of a node in this clock minute; `false` over
    /// [`Limits::ingress_per_minute`].
    fn ingress_rate(&self, node_id: &str, now: u64) -> bool {
        let Some(conn) = lock(&self.nodes).get(node_id).cloned() else {
            // Offline: the open is refused anyway.
            return true;
        };
        let mut rate = lock(&conn.ingress_minute);
        let minute = now / 60;
        if rate.0 != minute {
            *rate = (minute, 0);
        }
        if rate.1 >= self.limits.ingress_per_minute {
            return false;
        }
        rate.1 += 1;
        true
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
            let opened = self.millis();
            let stream = Arc::new(Stream {
                id,
                kind,
                account: entry.account_id.clone(),
                class: slot.class.clone(),
                dialer,
                inbox: Mutex::new(Inbox::default()),
                cond: Condvar::new(),
                ended: AtomicBool::new(false),
                node_done: AtomicBool::new(false),
                node_seen: AtomicBool::new(false),
                opened,
                activity: AtomicU64::new(opened),
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
        {
            let mut accounts = lock(&self.accounts);
            if let Some(account) = accounts.by_id.get_mut(&entry.account_id) {
                account.streams += 1;
                match &stream.class {
                    Class::Own => {}
                    Class::Grantee(grantee) => {
                        if let Some(counts) = account.grantees.get_mut(grantee) {
                            counts.streams += 1;
                        }
                    }
                    Class::Ingress => account.ingress_streams += 1,
                }
            }
        }
        if !first.is_empty() {
            self.count(&stream, first.len());
        }
        Some(Ticket {
            inner: self.clone(),
            conn,
            stream: Some(stream),
        })
    }

    /// Counts bytes of a stream in its account and its class; trips a budget once it is
    /// spent and ends the streams that it covers (4002): the dial budget ends the dials,
    /// the share of other accounts their dials, the ingress budget the ingress streams.
    fn count(self: &Arc<Self>, stream: &Stream, bytes: usize) {
        #[derive(PartialEq)]
        enum Ends {
            Dials,
            Grantees,
            Ingress,
        }
        let now = self.clock.now();
        let bytes = bytes as u64;
        let mut ends = Vec::new();
        {
            let mut accounts = lock(&self.accounts);
            let account = accounts.by_id.entry(stream.account.clone()).or_default();
            account.roll(now);
            account.bytes = account.bytes.saturating_add(bytes);
            match &stream.class {
                Class::Ingress => {
                    account.ingress_bytes = account.ingress_bytes.saturating_add(bytes);
                    if !account.ingress_tripped && account.ingress_spent() {
                        account.ingress_tripped = true;
                        ends.push(Ends::Ingress);
                    }
                }
                class => {
                    if let Class::Grantee(grantee) = class {
                        let counts = account.grantees.entry(grantee.clone()).or_default();
                        counts.bytes = counts.bytes.saturating_add(bytes);
                        account.grantee_bytes = account.grantee_bytes.saturating_add(bytes);
                        if !account.grantees_tripped && account.grantees_spent() {
                            account.grantees_tripped = true;
                            ends.push(Ends::Grantees);
                        }
                    }
                    if !account.tripped && account.dials_spent() {
                        account.tripped = true;
                        ends.push(Ends::Dials);
                    }
                }
            }
        }
        for end in ends {
            self.reset_where(
                |_, other| {
                    other.account == stream.account
                        && match end {
                            Ends::Dials => other.class != Class::Ingress,
                            Ends::Grantees => matches!(other.class, Class::Grantee(_)),
                            Ends::Ingress => other.class == Class::Ingress,
                        }
                },
                close::TUNNEL_LIMIT,
            );
        }
    }

    /// Resets a stream from Connect's side: a `reset` frame to the node (or nothing, when
    /// its `open` was still queued), and `code` to the client.
    fn abort(&self, conn: &NodeConn, stream: &Arc<Stream>, code: u16) {
        // No frame of the stream is queued after this: the senders check `ended` while
        // they hold `send`, and a sender waiting for room sees it at once.
        stream.ended.store(true, Ordering::SeqCst);
        conn.outbox.wake();
        {
            let _sending = lock(&stream.send);
            let live = lock(&conn.state).seq.remove(stream.id).is_some();
            if live {
                conn.outbox
                    .cancel(stream.id, frame::encode(stream.id, stream.kind, RESET, &[]));
            }
        }
        stream.finish(code);
        // A writer inside a data write when the stream ends may be stuck on a client that
        // does not read: the maintenance thread shuts its socket down if it is still
        // there a tick later. A writer that only takes a moment (or writes the close
        // code, which is not marked) is left alone, so the client still gets its code.
        if stream.writing.load(Ordering::SeqCst) {
            let deadline = self.millis() + self.limits.tick.as_millis() as u64;
            lock(&self.stuck).push((Arc::clone(stream), deadline));
        }
    }

    /// Shuts down the clients of ended streams whose writer is still inside the same
    /// write after its deadline.
    fn unstick(&self) {
        let now = self.millis();
        let due: Vec<Arc<Stream>> = {
            let mut stuck = lock(&self.stuck);
            stuck.retain(|(stream, _)| stream.writing.load(Ordering::SeqCst));
            let (due, waiting): (Vec<_>, Vec<_>) =
                stuck.drain(..).partition(|(_, deadline)| now >= *deadline);
            *stuck = waiting;
            due.into_iter().map(|(stream, _)| stream).collect()
        };
        for stream in due {
            let client = lock(&stream.client).clone();
            if let Some(shutdown) = client {
                shutdown();
            }
        }
    }

    /// Resets the open dials of `grantee_account` to the node (4003). Returns how many.
    fn revoke_grant(&self, node_id: &str, grantee_account: &str) -> usize {
        self.reset_where(
            |conn, stream| {
                conn.node_id == node_id
                    && matches!(&stream.class, Class::Grantee(grantee) if grantee == grantee_account)
            },
            close::REVOKED,
        )
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
        self.unstick();
        let now = self.millis();
        let idle = self.limits.stream_idle.as_millis() as u64;
        let grace = self.limits.close_grace.as_millis() as u64;
        let first = self.limits.ingress_first_byte.as_millis() as u64;
        self.reset_where(
            |_, stream| {
                let gone = stream.client_gone.load(Ordering::Relaxed);
                now.saturating_sub(stream.activity.load(Ordering::Relaxed)) >= idle
                    || (gone != 0 && now.saturating_sub(gone) >= grace)
                    || (stream.class == Class::Ingress
                        && !stream.node_seen.load(Ordering::Relaxed)
                        && now.saturating_sub(stream.opened) >= first)
            },
            close::RESET_BY_NODE,
        );
        let every = self.limits.recheck.as_millis() as u64;
        let last = self.rechecked.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= every {
            self.rechecked.store(now, Ordering::Relaxed);
            self.recheck();
        }
    }

    /// Asks the directory again about the open streams: the open streams of an account
    /// whose plan ended (also by time, without a hook) end with 4003, and so do the open
    /// dials of another account whose grant no longer holds (the grant went, or the two
    /// accounts no longer share a group). No lock is held while the directory answers.
    fn recheck(&self) {
        let conns: Vec<_> = lock(&self.nodes).values().cloned().collect();
        let mut accounts = HashSet::new();
        let mut grants = HashSet::new();
        for conn in &conns {
            for (_, stream) in lock(&conn.state).seq.values() {
                accounts.insert(stream.account.clone());
                if let Class::Grantee(grantee) = &stream.class {
                    grants.insert((conn.node_id.clone(), grantee.clone()));
                }
            }
        }
        for account in accounts {
            if !self.directory.entitled(&account) {
                self.reset_where(|conn, _| conn.account == account, close::REVOKED);
            }
        }
        for (node_id, grantee) in grants {
            if !self.directory.has_grant(&node_id, &grantee) {
                self.revoke_grant(&node_id, &grantee);
            }
        }
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
                Ok(Message::Ping(payload)) => conn.outbox.push_pong(payload),
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
                stream.node_seen.store(true, Ordering::Relaxed);
                if !frame.payload.is_empty() {
                    self.count(&stream, frame.payload.len());
                    stream.touch(self);
                    if !self.deliver(&stream, frame.payload) {
                        self.abort(conn, &stream, close::RESET_BY_NODE);
                        return;
                    }
                }
                if reset {
                    stream.node_done.store(true, Ordering::SeqCst);
                    stream.finish(close::RESET_BY_NODE);
                } else {
                    if closing {
                        // The node's close ends the stream for the client, as a dial is
                        // ended: the client gets the last bytes, then its connection
                        // closes; client bytes after it are neither forwarded nor counted.
                        stream.node_done.store(true, Ordering::SeqCst);
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
            if *closed || stream.is_ended() || stream.node_done.load(Ordering::SeqCst) {
                return false;
            }
            let frame = frame::encode(stream.id, stream.kind, 0, chunk);
            if !conn.outbox.push(frame, &stream.ended, true) {
                return false;
            }
            drop(closed);
            self.count(stream, chunk.len());
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
            // The close code is not marked as a write: Connect never cuts it off.
            stream
                .writing
                .store(!matches!(act, Act::Close(..)), Ordering::SeqCst);
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
                    if inbox.node_closed {
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
                    // The node closed its direction, and its last bytes are out: the
                    // stream ends, as a dial does. Connect closes the client's direction
                    // and the connection.
                    self.client_left(stream);
                    self.client_closed(conn, stream, false);
                    let _ = tcp.shutdown(Shutdown::Both);
                    return;
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

    /// Everything the writer would send now: (stream, flags) of each frame.
    fn drain(outbox: &Outbox) -> Vec<(u32, u8)> {
        let mut sent = Vec::new();
        loop {
            match outbox.next(Instant::now()) {
                Next::Send(Out::Frame(bytes)) => {
                    let frame = frame::decode(&bytes).unwrap();
                    sent.push((frame.stream, frame.flags));
                }
                Next::Send(Out::Pong(_)) => {}
                Next::Ping | Next::Close(_) => return sent,
            }
        }
    }

    fn reset(stream: u32) -> Vec<u8> {
        frame::encode(stream, Kind::Device, RESET, &[])
    }

    #[test]
    fn a_reset_never_overtakes_its_own_open() {
        let outbox = Outbox::new(1 << 20);
        let live = AtomicBool::new(false);
        // Stream 5's open and data are still queued when Connect ends it: nothing of it
        // reaches the node, not even a reset.
        outbox.push(frame::encode(4, Kind::Device, 0, b"backlog"), &live, true);
        outbox.push(frame::encode(5, Kind::Device, OPEN, b""), &live, false);
        outbox.push(frame::encode(5, Kind::Device, 0, b"data"), &live, true);
        outbox.cancel(5, reset(5));
        assert_eq!(drain(&outbox), [(4, 0)]);
        // Stream 6's open went out: its reset passes its own queued data (which leaves
        // the queue), never the open of stream 7 behind it.
        outbox.push(frame::encode(6, Kind::Device, OPEN, b""), &live, false);
        assert_eq!(drain(&outbox), [(6, OPEN)]);
        outbox.push(frame::encode(6, Kind::Device, 0, b"late"), &live, true);
        outbox.push(frame::encode(7, Kind::Device, OPEN, b""), &live, false);
        outbox.cancel(6, reset(6));
        assert_eq!(drain(&outbox), [(6, RESET), (7, OPEN)]);
        assert_eq!(lock(&outbox.state).fifo_bytes, 0);
    }

    #[test]
    fn no_reset_is_dropped() {
        let outbox = Outbox::new(1 << 20);
        for stream in 1..=3000 {
            outbox.cancel(stream, reset(stream));
        }
        outbox.push_pong(b"a".to_vec());
        outbox.push_pong(b"b".to_vec());
        let sent = drain(&outbox);
        assert_eq!(sent.len(), 3000);
        assert!(sent.iter().all(|(_, flags)| *flags == RESET));
    }

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
