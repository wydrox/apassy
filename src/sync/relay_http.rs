//! The HTTPS client of the relay (contract relay-sync-v1, section 3).
//!
//! `https://` uses rustls with the macOS trust store, as `crate::broker::http` does.
//! Plain `http://` is allowed only for a loopback address with a port (the rule of
//! `broker::http::parse_destination`). One connection per request, HTTP/1.1,
//! `Connection: close`, no redirect; the one exception is a request through a Connect
//! dial whose host keeps its dials ([`KeptDials`], below). A request always has
//! `Content-Length`; a snapshot streams from or to a file and never sits in memory. A
//! JSON answer is read up to 2 MiB.
//!
//! The request head holds the access token, so it is built in one buffer of the exact
//! size and erased after the write. A JSON request body and every answer buffer are
//! erased on drop too: they can hold a token, a link code, or a team code.
//!
//! A request can be ended from another thread ([`Cancel`]): a lock closes the sockets of
//! a long poll and of a download or an upload in flight, so the device key and the token
//! do not wait in memory for the relay. The name lookup and the TCP connect run on a
//! helper thread that holds no token, and the request stops waiting for it at a cancel;
//! the socket is in the [`Cancel`] before the TLS handshake. A request can also have an
//! overall deadline ([`Request::deadline`]): connecting, sending, and reading all end by
//! then.
//!
//! A host can install an external transport once per process ([`set_http_transport`],
//! ADR 0039 section 5): the Apple Watch app, where URLSession is the only network API.
//! [`exchange`] then hands each request to it instead of TCP and TLS: the method, the full
//! URL, the headers with the bearer, the JSON body, and a timeout. The answer goes through
//! the same checks and limits as an answer read from a socket. A request with a [`Cancel`]
//! registers its request ID there, and [`Cancel::close`] cancels it through the transport.
//! A snapshot (a file body or a download) never goes through it. Without an external
//! transport nothing changes.
//!
//! A relay address can be **pinned** (contract node-pairing-v1, sections 3, 4, and 7): a
//! node on the tailnet with a self-signed certificate. Its [`RelayUrl`] carries
//! [`TlsTrust::Pinned`] and up to four alternative destinations. Each connection then
//! takes TLS 1.3 only and the pinned leaf only, never the system trust store; it tries
//! the origin's host first and then each alternative in order while a connection is
//! refused or times out, all within 30 s, and stops at once at a pin mismatch
//! ([`HttpError::PinMismatch`]). Every attempt sends the origin as `Host`, and the origin
//! stays the signed value. A hosted address ([`TlsTrust::System`]) is unchanged.
//!
//! The Mac's own node sets a **local route** for its origin ([`set_local_route`], plan
//! S2–S3 decision D1): a request to that origin then connects plain to the loopback
//! address of the node and still names (and signs) the node origin. The external
//! transport carries the pin of a pinned request ([`ExternalRequest::pin`], unit N6):
//! the host accepts only the leaf with that pin, over TLS 1.3, and answers
//! [`HttpError::PinMismatch`] for another certificate. It connects to the origin only:
//! the host sets `Host` from the URL, so it tries no alternative destination.
//!
//! A pinned address can also have a **Connect route** (node-pairing-v1 section 7a,
//! connect-tunnel-v1 section 3.3, plan s7 unit I2): its last alternative is a
//! [`TunnelRoute`], the dial `wss://<Connect host>/v1/tunnel/dial/<node id>`. A host that
//! sets a [`TunnelDialer`] on the address ([`RelayUrl::with_dialer`], the iPhone core)
//! reaches the node through the dial when the tailnet destinations do not connect: the
//! dialer opens a byte pipe to the node's TLS front ([`TunnelPipe`]), and the request
//! runs the same pinned TLS handshake inside it as on the tailnet, before any request
//! byte. Connect then carries TLS records only; it never sees or changes a request, a
//! token, or an answer, and a wrong certificate ends the dial with
//! [`HttpError::PinMismatch`]. The request, its head, its body, and its answer do not
//! change by one byte. An address without a dialer ignores the route.
//!
//! A host whose dialer keeps connections ([`TunnelDialer::kept`], the iPhone core) keeps
//! the pinned connection inside a dial open after a complete answer, so that requests
//! that follow each other share one dial and one TLS handshake ([`KeptDials`]: one for
//! each node, closed after [`KEPT_DIAL_IDLE`] without a request, at a lock, or when the
//! dial ends). Such a request does not send `Connection: close`; that line is the only
//! byte of it that changes. A long poll dials for itself and closes after its answer, as
//! before. A kept connection that turns out dead is replaced by a fresh one when nothing
//! of the request reached it, and a `GET` or `HEAD` without a body goes once more on a
//! fresh connection when the kept one ended before any byte of the answer; any other
//! request then fails with [`HttpError::Broken`].

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use zeroize::Zeroizing;

use super::SyncError;
use crate::broker::http::{DestinationUrl, TlsClient, is_pin_mismatch, parse_destination};
use crate::net::pin::{Pin, parse as parse_pin};

/// The relay address that the app proposes.
pub const DEFAULT_RELAY_URL: &str = "https://apassy-relay.wyderka.cc";
/// The time to connect to one address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest name lookup and connect of a request, over every address.
const CONNECT_LIMIT: Duration = Duration::from_secs(30);
/// How often a request that waits for its connection looks at its cancel.
const CANCEL_CHECK: Duration = Duration::from_millis(50);
/// The time for the answer headers. A long poll adds its wait.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// A body read or write that makes no progress for this long fails.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest JSON answer that the app reads.
pub(crate) const MAX_JSON_ANSWER: usize = 2 * 1024 * 1024;
/// The largest answer head.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The size of one read or write of a body.
const CHUNK: usize = 64 * 1024;
/// The first capacity of an answer buffer. A small answer (a token, a link code) then
/// never moves to a larger buffer and leaves no copy behind.
const ANSWER_CAPACITY: usize = 64 * 1024;

/// How a relay client checks the certificate of its relay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TlsTrust {
    /// A hosted relay: the platform trust store, as before node-pairing-v1.
    #[default]
    System,
    /// A node: only the leaf certificate with this pin (node-pairing-v1 section 4).
    Pinned(Pin),
}

impl TlsTrust {
    /// The trust of a stored pin text: `None` is [`TlsTrust::System`]; a text that is not
    /// a canonical pin is `InvalidRelayAddress` (a stored pin never silently goes).
    pub fn from_pin_text(pin: Option<&str>) -> Result<Self, SyncError> {
        match pin {
            None => Ok(Self::System),
            Some(text) => parse_pin(text)
                .map(Self::Pinned)
                .ok_or(SyncError::InvalidRelayAddress),
        }
    }

    /// The pin, when pinned.
    pub fn pin(&self) -> Option<Pin> {
        match self {
            Self::System => None,
            Self::Pinned(pin) => Some(*pin),
        }
    }

    /// The text of the pin, when pinned: the stored form.
    pub fn pin_text(&self) -> Option<String> {
        self.pin().map(|pin| pin.text())
    }
}

/// The most alternative destinations of a pinned origin (node-pairing-v1 section 7),
/// the Connect route included.
pub const MAX_ALTERNATIVES: usize = 4;

/// The path of a dial before the node id (connect-tunnel-v1 section 3.3).
pub const TUNNEL_DIAL_PATH: &str = "/v1/tunnel/dial/";

/// Whether `text` is a node id of connect-tunnel-v1 section 2: `node_` and 10
/// characters of `a-z2-7`.
pub fn valid_node_id(text: &str) -> bool {
    text.strip_prefix("node_").is_some_and(|rest| {
        rest.len() == 10
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    })
}

/// The Connect route of a pinned node (node-pairing-v1 section 7a, connect-tunnel-v1
/// section 3.3): the dial `wss://<Connect host>/v1/tunnel/dial/<node id>`. It is a
/// second way to the same node, after the tailnet destinations: the client runs the
/// same pinned TLS inside the dial, so Connect carries TLS records only. The address
/// keeps it as its last alternative; only a [`TunnelDialer`] of the host uses it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunnelRoute {
    /// `host[:port]` of the Connect host, the port written only when it is not 443.
    connect: String,
    node: String,
}

impl TunnelRoute {
    /// The route to the node `node` through the Connect origin `connect_origin`
    /// (`https://apassy-relay.wyderka.cc`, or a loopback `http://` in tests).
    /// `InvalidRelayAddress` for another origin or node id.
    pub fn new(connect_origin: &str, node: &str) -> Result<Self, SyncError> {
        let origin = RelayUrl::parse(connect_origin)?;
        if !valid_node_id(node) || origin.as_str() != connect_origin.trim_end_matches('/') {
            return Err(SyncError::InvalidRelayAddress);
        }
        Ok(Self {
            connect: origin.host_header().to_owned(),
            node: node.to_owned(),
        })
    }

    /// Read the canonical text of a route, as [`Self::text`] writes it: `wss://`, a host
    /// of the alternatives' form with a port only when it is not 443, the dial path, and
    /// a node id. Nothing else (no user, query, fragment, or trailing slash).
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("wss://")?;
        let (authority, node) = rest.split_once(TUNNEL_DIAL_PATH)?;
        if authority.contains('/') || !valid_node_id(node) {
            return None;
        }
        let (host, port) = split_host_port(authority)?;
        let connect = match port {
            Some(443) => return None,
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        (connect == authority).then(|| Self {
            connect,
            node: node.to_owned(),
        })
    }

    /// The canonical text: `wss://apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3ca`.
    pub fn text(&self) -> String {
        format!("wss://{}{TUNNEL_DIAL_PATH}{}", self.connect, self.node)
    }

    /// The node id.
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The Connect host, `host[:port]`.
    pub fn connect_host(&self) -> &str {
        &self.connect
    }

    /// The path of the dial: `/v1/tunnel/dial/<node id>`.
    pub fn dial_path(&self) -> String {
        format!("{TUNNEL_DIAL_PATH}{}", self.node)
    }

    /// Whether the route goes through `connect_origin`: its host and port are the
    /// origin's. A route through another host is never dialled.
    pub fn is_through(&self, connect_origin: &str) -> bool {
        RelayUrl::parse(connect_origin).is_ok_and(|origin| origin.host_header() == self.connect)
    }
}

/// Which way a connection reached a pinned node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRoute {
    /// The origin's host or one of its tailnet alternatives.
    Direct,
    /// The Connect dial.
    Tunnel,
}

/// The byte pipe of a dial (connect-tunnel-v1 section 3.3): after the `101` of Connect,
/// the bytes to and from the node's TLS front. The pinned TLS of the node runs inside
/// it, as over a socket of the tailnet.
pub trait TunnelPipe: Read + Write + Send {
    /// A read that waits longer fails with `TimedOut`.
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()>;
    /// A write that waits longer fails.
    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()>;
    /// Ends the pipe from another thread (a cancel, a lock): reads and writes then fail.
    fn closer(&self) -> Arc<dyn Fn() + Send + Sync>;
    /// True while the pipe is open and holds no byte that was not read yet, so that a kept
    /// connection over it may carry the next request ([`KeptDials`]). A pipe that cannot
    /// tell answers false (the default): its connections are never reused.
    fn is_idle_open(&self) -> bool {
        false
    }
}

/// The Connect route of a host (the iPhone core, plan s7 unit I2): it opens the dials
/// with the account token, and it decides the route order of each pinned address with a
/// [`TunnelRoute`]. The client calls it for every connection of such an address; an
/// address without a dialer never dials.
pub trait TunnelDialer: Send + Sync {
    /// Whether the direct destinations come first now. False while they failed
    /// recently: the dial comes first, and the direct destinations are the last resort.
    fn direct_first(&self, url: &RelayUrl) -> bool;
    /// A connection to `url` finished its pinned handshake through `route`.
    fn reached(&self, url: &RelayUrl, route: NodeRoute);
    /// No direct destination of `url` connected.
    fn direct_failed(&self, url: &RelayUrl);
    /// Open the dial of `route` before `deadline`. `HttpError::Connect`: no dial (Connect
    /// unreachable or refusing; the dialer keeps why).
    fn dial(
        &self,
        route: &TunnelRoute,
        deadline: Instant,
    ) -> Result<Box<dyn TunnelPipe>, HttpError>;
    /// Where this host keeps the pinned connections of its dials between requests
    /// ([`KeptDials`]). `None` (the default): no connection is kept, and every request
    /// through a dial asks the node to close its connection after the answer.
    fn kept(&self) -> Option<KeptDials> {
        None
    }
}

/// How long a kept dial waits for its next request before it closes. It is below every
/// idle limit after it on the way to the node: the relay's wait for the next request on a
/// stream of the tunnel (45 s, `apassy_relay::server::TUNNEL_KEEP_IDLE`), the TLS front's
/// 120 s (`FrontLimits::idle`), and Connect's 15 minutes for a stream without a byte. The
/// dial's own pings keep its WebSocket open meanwhile (connect-tunnel-v1 section 3.2).
pub const KEPT_DIAL_IDLE: Duration = Duration::from_secs(30);
/// The most connections that one host keeps: one for each node.
const KEPT_MAX: usize = 8;

/// The pinned connections inside Connect dials that a host keeps open between requests
/// (one for each node), so that requests that follow each other share one dial instead of
/// a dial and a TLS handshake each: Connect counts dials (60 a minute for an account).
///
/// A request through the dial that is not a long poll takes the kept connection of its
/// node when there is one, and gives its connection back after a complete answer that
/// keeps it open (HTTP/1.1, no `Connection: close`, a body with a length, nothing more on
/// the connection). Such a request does not send `Connection: close`; nothing else of it
/// changes. A long poll always dials for itself and closes after its answer.
///
/// A kept connection closes after [`KEPT_DIAL_IDLE`] (or [`Self::set_idle`]) without a
/// request, when its pipe ends, and at [`Self::clear`] (a lock, a suspend). A kept
/// connection that turns out dead takes a fresh connection: always when nothing of the
/// request reached the pipe; when it did and the connection ended before any byte of the
/// answer, only a `GET` or `HEAD` without a body is sent again, once. Any other request
/// then fails with [`HttpError::Broken`]: it may have reached the node.
#[derive(Clone, Default)]
pub struct KeptDials(Arc<KeptShared>);

#[derive(Default)]
struct KeptShared {
    state: Mutex<KeptState>,
    changed: std::sync::Condvar,
}

#[derive(Default)]
struct KeptState {
    /// `None`: [`KEPT_DIAL_IDLE`].
    idle: Option<Duration>,
    /// One more at each [`KeptDials::clear`]: a connection of a request that started
    /// before it is not kept.
    epoch: u64,
    /// For each node (origin, pin, route): its connection and since when it waits.
    entries: BTreeMap<String, (Box<TunnelTls>, Instant)>,
    /// A thread closes the connections at their idle limit.
    reaping: bool,
}

impl KeptState {
    fn idle(&self) -> Duration {
        self.idle.unwrap_or(KEPT_DIAL_IDLE)
    }

    /// Take out the connections that waited too long or whose pipe ended. The caller
    /// drops them outside the lock (a drop ends the dial).
    fn expired(&mut self, now: Instant) -> Vec<Box<TunnelTls>> {
        let idle = self.idle();
        let mut gone = Vec::new();
        for (key, (tls, since)) in &mut self.entries {
            if now.duration_since(*since) >= idle || !reusable(tls) {
                gone.push(key.clone());
            }
        }
        gone.iter()
            .filter_map(|key| self.entries.remove(key))
            .map(|(tls, _)| tls)
            .collect()
    }
}

/// True when `tls` may carry another request: its pipe is open with nothing unread in it,
/// and TLS holds no unread plaintext and no close from the node.
fn reusable(tls: &mut TunnelTls) -> bool {
    tls.sock.pipe.is_idle_open()
        && matches!(
            tls.conn.process_new_packets(),
            Ok(state) if state.plaintext_bytes_to_read() == 0 && !state.peer_has_closed()
        )
}

impl std::fmt::Debug for KeptDials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptDials")
            .field("kept", &self.len())
            .finish()
    }
}

impl KeptDials {
    /// No connection kept yet; each waits at most [`KEPT_DIAL_IDLE`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Another wait for a kept connection (tests shorten it).
    pub fn set_idle(&self, idle: Duration) {
        self.lock().idle = Some(idle);
        self.0.changed.notify_all();
    }

    /// Close every kept connection now (a lock, a suspend): their dials end, and a
    /// request that started before this keeps nothing.
    pub fn clear(&self) {
        let gone = {
            let mut state = self.lock();
            state.epoch = state.epoch.wrapping_add(1);
            std::mem::take(&mut state.entries)
        };
        self.0.changed.notify_all();
        drop(gone);
    }

    /// The connections kept now.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// True when no connection is kept.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, KeptState> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn epoch(&self) -> u64 {
        self.lock().epoch
    }

    /// The kept connection of `key`, when one is there and may carry a request.
    fn take(&self, key: &str) -> Option<Box<TunnelTls>> {
        let (mut tls, fresh) = {
            let mut state = self.lock();
            let idle = state.idle();
            let (tls, since) = state.entries.remove(key)?;
            (tls, since.elapsed() < idle)
        };
        (fresh && reusable(&mut tls)).then_some(tls)
    }

    /// Keep `tls` for the next request to `key`, unless a clear came after `epoch`, the
    /// node has one already, or this host keeps [`KEPT_MAX`] already.
    fn put(&self, key: String, epoch: u64, mut tls: Box<TunnelTls>) {
        if !reusable(&mut tls) {
            return;
        }
        let refused = {
            let mut state = self.lock();
            if state.epoch != epoch
                || state.entries.contains_key(&key)
                || state.entries.len() >= KEPT_MAX
            {
                Some(tls)
            } else {
                state.entries.insert(key, (tls, Instant::now()));
                if !state.reaping {
                    state.reaping = true;
                    let shared = Arc::clone(&self.0);
                    let started = std::thread::Builder::new()
                        .name("apassy-kept-dials".to_owned())
                        .spawn(move || reap(&shared));
                    if started.is_err() {
                        // The next `take` still closes a connection that waited too long.
                        state.reaping = false;
                    }
                }
                None
            }
        };
        self.0.changed.notify_all();
        drop(refused);
    }
}

/// Close the kept connections at their idle limit; end when none is left.
fn reap(shared: &KeptShared) {
    let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        let now = Instant::now();
        let gone = state.expired(now);
        if !gone.is_empty() {
            drop(state);
            drop(gone);
            state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
            continue;
        }
        if state.entries.is_empty() {
            state.reaping = false;
            return;
        }
        let idle = state.idle();
        let next = state
            .entries
            .values()
            .map(|(_, since)| (*since + idle).saturating_duration_since(now))
            .min()
            .unwrap_or(idle)
            .max(Duration::from_millis(10));
        state = shared
            .changed
            .wait_timeout(state, next)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// The dialer of an address. It is how the address is reached, not where: two
/// addresses are equal whatever their dialers.
#[derive(Clone)]
pub(crate) struct DialerRef(pub(crate) Arc<dyn TunnelDialer>);

impl std::fmt::Debug for DialerRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunnelDialer")
    }
}

impl PartialEq for DialerRef {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for DialerRef {}

/// A relay address: an origin, `https://<host>[:port]` or a loopback `http://` with a
/// port. It has no path, query, user, or trailing slash. A pinned address also has its
/// trust and its alternative destinations ([`Self::parse_with_trust`],
/// [`Self::alternatives`]), one of which can be its Connect route ([`TunnelRoute`]);
/// [`Self::as_str`] is the origin either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    origin: String,
    destination: DestinationUrl,
    trust: TlsTrust,
    /// The other destinations of the same relay, tried in order after `destination`:
    /// the text `host:port` (an IPv6 host in brackets, the port always written) and
    /// where it connects.
    alternatives: Vec<(String, DestinationUrl)>,
    /// The Connect route of a pinned node, after the alternatives.
    tunnel: Option<TunnelRoute>,
    /// What dials `tunnel`: set by the host ([`Self::with_dialer`]).
    dialer: Option<DialerRef>,
}

/// `host[:port]` of an alternative destination or of a pinned origin (node-pairing-v1
/// sections 3 and 7): a canonical IPv4 address, an RFC 5952 IPv6 address in brackets,
/// or a name of two or more lowercase LDH labels; a port of 1 to 65535 without leading
/// zeros. Returns the host as written and the port when one is written.
pub(crate) fn split_host_port(text: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let address: std::net::Ipv6Addr = inside.parse().ok()?;
        if address.to_string() != inside {
            return None;
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (format!("[{inside}]"), port)
    } else {
        let (host, port) = match text.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (text, None),
        };
        if !valid_ipv4_or_name(host) {
            return None;
        }
        (host.to_owned(), port)
    };
    let port = match port {
        None => None,
        Some(text)
            if !text.is_empty()
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && !text.starts_with('0') =>
        {
            Some(text.parse::<u16>().ok()?)
        }
        Some(_) => return None,
    };
    Some((host, port))
}

/// A canonical dotted IPv4 address, or a name of at least two lowercase LDH labels of 1
/// to 63 characters, at most 253 characters in all.
fn valid_ipv4_or_name(host: &str) -> bool {
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == host);
    }
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

impl RelayUrl {
    /// Parse an origin and give it the trust `trust`. A pinned origin is `https://` with
    /// an explicit port other than 443 (node-pairing-v1 section 3); anything else is
    /// `InvalidRelayAddress`.
    pub fn parse_with_trust(text: &str, trust: TlsTrust) -> Result<Self, SyncError> {
        Self::parse(text)?.with_trust(trust)
    }

    /// This address with the trust `trust`. A pinned origin needs `https://` and a port
    /// other than 443, and system trust takes no alternative destinations.
    pub fn with_trust(mut self, trust: TlsTrust) -> Result<Self, SyncError> {
        match trust {
            TlsTrust::Pinned(_) => {
                if !matches!(self.destination, DestinationUrl::Https { port, .. } if port != 443) {
                    return Err(SyncError::InvalidRelayAddress);
                }
            }
            TlsTrust::System => {
                if !self.alternatives.is_empty() || self.tunnel.is_some() {
                    return Err(SyncError::InvalidRelayAddress);
                }
            }
        }
        self.trust = trust;
        Ok(self)
    }

    /// This pinned address with the alternative destinations `list` (each
    /// `host[:port]`, without a port the origin's port), in the order to try them, in
    /// place of any earlier ones. One entry may be the Connect route of the node, the
    /// text of a [`TunnelRoute`] (`wss://…/v1/tunnel/dial/<node>`): it is tried after the
    /// others, and only with a dialer ([`Self::with_dialer`]). At most
    /// [`MAX_ALTERNATIVES`] in all; an entry of another form, an entry equal to the
    /// origin's host and port, a repeated entry, a second route, or an alternative of an
    /// address without a pin is `InvalidRelayAddress`. An empty list clears them. The
    /// stricter rules of a link (no loopback, no link-local address, the configured
    /// Connect host) are the link reader's (`PairedLink::parse`).
    pub fn alternatives(mut self, list: &[String]) -> Result<Self, SyncError> {
        if list.is_empty() {
            self.alternatives.clear();
            self.tunnel = None;
            return Ok(self);
        }
        let (origin_host, origin_port) = match (&self.destination, self.trust) {
            (DestinationUrl::Https { host, port }, TlsTrust::Pinned(_)) => (host.clone(), *port),
            _ => return Err(SyncError::InvalidRelayAddress),
        };
        if list.len() > MAX_ALTERNATIVES {
            return Err(SyncError::InvalidRelayAddress);
        }
        let mut alternatives: Vec<(String, DestinationUrl)> = Vec::with_capacity(list.len());
        let mut tunnel: Option<TunnelRoute> = None;
        for entry in list {
            if entry.starts_with("wss://") {
                let route = TunnelRoute::parse(entry).ok_or(SyncError::InvalidRelayAddress)?;
                if tunnel.replace(route).is_some() {
                    return Err(SyncError::InvalidRelayAddress);
                }
                continue;
            }
            let (host, port) = split_host_port(entry).ok_or(SyncError::InvalidRelayAddress)?;
            let port = port.unwrap_or(origin_port);
            let bare = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            let text = format!("{host}:{port}");
            if (bare == origin_host && port == origin_port)
                || alternatives.iter().any(|(known, _)| *known == text)
                || ServerName::try_from(bare.clone()).is_err()
            {
                return Err(SyncError::InvalidRelayAddress);
            }
            alternatives.push((text, DestinationUrl::Https { host: bare, port }));
        }
        self.alternatives = alternatives;
        self.tunnel = tunnel;
        Ok(self)
    }

    /// This pinned address with the Connect route `route` in place of any earlier one
    /// (`None` removes it). The route counts as one of the [`MAX_ALTERNATIVES`];
    /// `InvalidRelayAddress` for an address without a pin or with no room left.
    pub fn with_tunnel(mut self, route: Option<TunnelRoute>) -> Result<Self, SyncError> {
        if route.is_some()
            && (self.trust == TlsTrust::System || self.alternatives.len() >= MAX_ALTERNATIVES)
        {
            return Err(SyncError::InvalidRelayAddress);
        }
        self.tunnel = route;
        Ok(self)
    }

    /// The Connect route of this pinned address, when it has one.
    pub fn tunnel(&self) -> Option<&TunnelRoute> {
        self.tunnel.as_ref()
    }

    /// This address with the dialer of its Connect route: a connection then tries the
    /// direct destinations and the dial in the order that the dialer gives. An address
    /// without a pin or without a route never dials.
    #[must_use]
    pub fn with_dialer(mut self, dialer: Arc<dyn TunnelDialer>) -> Self {
        self.dialer = Some(DialerRef(dialer));
        self
    }

    /// This address without its Connect route and its dialer: the direct destinations
    /// only, for a probe of the direct route.
    fn direct_only(&self) -> Self {
        let mut url = self.clone();
        url.tunnel = None;
        url.dialer = None;
        url
    }

    /// How this address checks the certificate of its relay.
    pub fn trust(&self) -> TlsTrust {
        self.trust
    }

    /// The pin, when the address is pinned.
    pub fn pin(&self) -> Option<Pin> {
        self.trust.pin()
    }

    /// The alternative destinations, `host:port` each, in the order they are tried, and
    /// the Connect route last: the stored form.
    pub fn alternative_list(&self) -> Vec<String> {
        self.alternatives
            .iter()
            .map(|(text, _)| text.clone())
            .chain(self.tunnel.iter().map(TunnelRoute::text))
            .collect()
    }

    /// Where a connection goes: the origin's host, then each alternative in order.
    fn destinations(&self) -> impl Iterator<Item = &DestinationUrl> {
        std::iter::once(&self.destination).chain(self.alternatives.iter().map(|(_, to)| to))
    }

    /// Parse an address that the owner typed. A trailing slash goes.
    pub fn parse(text: &str) -> Result<Self, SyncError> {
        let destination =
            parse_destination(text.trim()).map_err(|_| SyncError::InvalidRelayAddress)?;
        let origin = match &destination {
            DestinationUrl::Loopback { host_header, .. } => format!("http://{host_header}"),
            DestinationUrl::Https { host, port } => {
                let host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                if *port == 443 {
                    format!("https://{host}")
                } else {
                    format!("https://{host}:{port}")
                }
            }
        };
        Ok(Self {
            origin,
            destination,
            trust: TlsTrust::System,
            alternatives: Vec::new(),
            tunnel: None,
            dialer: None,
        })
    }

    /// The origin, as the app stores it and as the sign-in message has it.
    pub fn as_str(&self) -> &str {
        &self.origin
    }

    /// Whether this is a plain `http://` address on this computer.
    pub fn is_loopback(&self) -> bool {
        matches!(self.destination, DestinationUrl::Loopback { .. })
    }

    fn host_header(&self) -> &str {
        self.origin
            .strip_prefix("https://")
            .or_else(|| self.origin.strip_prefix("http://"))
            .unwrap_or(&self.origin)
    }
}

/// Why an exchange failed. No value holds the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// No connection: no byte of the request reached the relay.
    Connect,
    /// The connection failed after the request started. A push may have landed.
    Broken,
    /// The answer is not valid HTTP, too large, or a body is longer than allowed.
    Protocol,
    /// A pinned relay presented another certificate (node-pairing-v1 section 4): no byte
    /// of the request went out, and no other destination was tried.
    PinMismatch,
}

/// The local routes of this process: the origin of the Mac's own node and the loopback
/// address of its relay (plan S2–S3 decision D1).
fn local_routes() -> &'static Mutex<BTreeMap<String, SocketAddr>> {
    static ROUTES: OnceLock<Mutex<BTreeMap<String, SocketAddr>>> = OnceLock::new();
    ROUTES.get_or_init(Mutex::default)
}

/// Route the requests to `origin` plain to `addr`, a loopback address of this computer,
/// until [`clear_local_route`]: the node of this Mac sets it when it starts. A request
/// keeps the origin as `Host` and as the signed value, so the callers do not change.
/// `InvalidRelayAddress` when `origin` is not a relay origin or `addr` is not loopback.
pub fn set_local_route(origin: &str, addr: SocketAddr) -> Result<(), SyncError> {
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err(SyncError::InvalidRelayAddress);
    }
    let origin = RelayUrl::parse(origin)?;
    local_routes()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(origin.as_str().to_owned(), addr);
    Ok(())
}

/// End the local route of `origin`: the node of this Mac stopped. A request in flight
/// keeps its connection.
pub fn clear_local_route(origin: &str) {
    let Ok(origin) = RelayUrl::parse(origin) else {
        return;
    };
    local_routes()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(origin.as_str());
}

/// The local route of `url`, for the tests of the node (`crate::node::tailnet`).
#[cfg(test)]
pub(crate) fn local_route_for_test(url: &RelayUrl) -> Option<SocketAddr> {
    local_route(url)
}

/// The local route of `url`, when the node of this Mac set one.
fn local_route(url: &RelayUrl) -> Option<SocketAddr> {
    local_routes()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(url.as_str())
        .copied()
        .filter(|addr| addr.ip().is_loopback())
}

/// The body of a request.
pub(crate) enum Body<'a> {
    None,
    /// JSON bytes, erased on drop.
    Json(Zeroizing<Vec<u8>>),
    /// A file that streams with its exact size.
    File(&'a Path, u64),
}

/// One request.
pub(crate) struct Request<'a> {
    pub(crate) method: &'static str,
    /// The path and query, pre-validated ASCII.
    pub(crate) path: String,
    pub(crate) bearer: Option<&'a str>,
    /// More headers: `If-Match`, the sync headers.
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Body<'a>,
    /// The extra time of a long poll for the answer headers.
    pub(crate) wait: Duration,
    /// Lets another thread end this request (a lock, a pause, a quit).
    pub(crate) cancel: Option<&'a Cancel>,
    /// The request ends by then, whatever it is doing: connecting, sending, or reading.
    pub(crate) deadline: Option<Instant>,
}

/// Ends the requests in flight from another thread: [`Self::close`] shuts their sockets
/// down or cancels them through the external transport, and a request that starts after
/// it fails at once. Several requests can use one `Cancel` at the same time (a long poll
/// and a download).
#[derive(Debug, Default)]
pub struct Cancel {
    closed: AtomicBool,
    /// The requests in flight, with a number for each request.
    sockets: Mutex<Vec<(u64, InFlight)>>,
    next: AtomicU64,
}

/// A request in flight that a [`Cancel`] can end.
enum InFlight {
    /// A handle of the socket of a TCP request.
    Socket(TcpStream),
    /// The ID of a request of the external transport, with the transport.
    External(u64, &'static dyn HttpTransport),
    /// The end of the pipe of a Connect dial ([`TunnelPipe::closer`]).
    Pipe(Arc<dyn Fn() + Send + Sync>),
}

impl std::fmt::Debug for InFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(socket) => f.debug_tuple("Socket").field(socket).finish(),
            Self::External(id, _) => f.debug_tuple("External").field(id).finish(),
            Self::Pipe(_) => f.write_str("Pipe"),
        }
    }
}

impl Cancel {
    /// End the requests in flight and every later one.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let held =
            std::mem::take(&mut *self.sockets.lock().unwrap_or_else(PoisonError::into_inner));
        for (_, in_flight) in held {
            match in_flight {
                InFlight::Socket(socket) => {
                    let _ = socket.shutdown(Shutdown::Both);
                }
                InFlight::External(id, transport) => transport.cancel(id),
                InFlight::Pipe(close) => close(),
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Keep a handle of the socket of a request in flight. Fails when closed.
    fn hold(&self, socket: &TcpStream) -> Result<u64, HttpError> {
        let mut sockets = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
        if self.is_closed() {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(HttpError::Broken);
        }
        let number = self.next.fetch_add(1, Ordering::SeqCst);
        if let Ok(handle) = socket.try_clone() {
            sockets.push((number, InFlight::Socket(handle)));
        }
        Ok(number)
    }

    /// Keep the ID of a request of the external transport before it starts. Fails when
    /// closed: the request then never goes out.
    fn hold_external(
        &self,
        id: u64,
        transport: &'static dyn HttpTransport,
    ) -> Result<u64, HttpError> {
        let mut held = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
        if self.is_closed() {
            return Err(HttpError::Connect);
        }
        let number = self.next.fetch_add(1, Ordering::SeqCst);
        held.push((number, InFlight::External(id, transport)));
        Ok(number)
    }

    /// Keep the end of the pipe of a dial in flight. Fails, and ends the pipe, when
    /// closed.
    fn hold_pipe(&self, close: Arc<dyn Fn() + Send + Sync>) -> Result<u64, HttpError> {
        let mut held = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
        if self.is_closed() {
            close();
            return Err(HttpError::Connect);
        }
        let number = self.next.fetch_add(1, Ordering::SeqCst);
        held.push((number, InFlight::Pipe(close)));
        Ok(number)
    }

    fn release(&self, number: u64) {
        self.sockets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(held, _)| *held != number);
    }
}

/// Releases the socket handle of a [`Cancel`] when the request ends.
struct Held<'a>(Option<(&'a Cancel, u64)>);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some((cancel, number)) = self.0 {
            cancel.release(number);
        }
    }
}

/// The time left before `deadline`, at most `cap`. `Err(error)` when it passed.
fn time_left(
    deadline: Option<Instant>,
    cap: Duration,
    error: HttpError,
) -> Result<Duration, HttpError> {
    match deadline {
        None => Ok(cap),
        Some(deadline) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                Err(error)
            } else {
                Ok(left.min(cap))
            }
        }
    }
}

impl<'a> Request<'a> {
    pub(crate) fn new(method: &'static str, path: String, bearer: Option<&'a str>) -> Self {
        Self {
            method,
            path,
            bearer,
            headers: Vec::new(),
            body: Body::None,
            wait: Duration::ZERO,
            cancel: None,
            deadline: None,
        }
    }
}

/// An answer. A download leaves `body` empty after a `200`. The body is erased on drop.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) status: u16,
    headers: Vec<(String, String)>,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl Answer {
    /// An answer with a body, for a test.
    #[cfg(test)]
    pub(crate) fn for_test(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Zeroizing::new(body.as_bytes().to_vec()),
        }
    }

    /// The value of the header `name` (lowercase), when it is there.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The longest time that an external request may take beyond the wait of a long poll,
/// when the request has no earlier deadline.
const EXTERNAL_MARGIN: Duration = HEADER_TIMEOUT;
/// The most header lines of an answer of the external transport.
const MAX_EXTERNAL_HEADERS: usize = 100;

/// One request for the external transport. It holds the bearer (in `headers`) and the
/// JSON body: the transport keeps no copy after [`HttpTransport::send`] returns.
pub struct ExternalRequest<'a> {
    /// Unique in this process. [`HttpTransport::cancel`] names it.
    pub id: u64,
    pub method: &'static str,
    /// The relay origin and the path with its query.
    pub url: String,
    /// `Authorization`, `Content-Type`, the headers of the request, and `User-Agent`.
    /// The transport sets `Host` and `Content-Length` itself.
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    /// The JSON body, when there is one.
    pub body: Option<&'a [u8]>,
    /// The whole request ends by then: the wait of a long poll and a margin, or less
    /// when the request has a deadline.
    pub timeout: Duration,
    /// The pin of a pinned origin (node-pairing-v1 section 4), its 43-character text:
    /// the transport accepts only the leaf certificate with this pin, over TLS 1.3, and
    /// never the system trust store; another certificate is
    /// [`HttpError::PinMismatch`] before any request byte. `None`: system trust.
    pub pin: Option<String>,
}

impl std::fmt::Debug for ExternalRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalRequest")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("timeout", &self.timeout)
            .field("pinned", &self.pin.is_some())
            .finish_non_exhaustive()
    }
}

/// The answer of the external transport. The body is erased on drop.
pub struct ExternalAnswer {
    pub status: u16,
    /// The header lines as the transport got them.
    pub headers: Vec<(String, String)>,
    pub body: Zeroizing<Vec<u8>>,
}

/// A transport of the host for the relay requests (the URLSession of the Apple Watch
/// app). Both calls can come from several threads at once.
pub trait HttpTransport: Send + Sync {
    /// Perform `request` and wait for its answer. [`HttpError::Connect`] when no byte
    /// went out, [`HttpError::Broken`] when the request failed after it started or was
    /// cancelled, [`HttpError::Protocol`] when the answer is not valid.
    fn send(&self, request: &ExternalRequest<'_>) -> Result<ExternalAnswer, HttpError>;

    /// End the request `id` at once. It can come from another thread while `send` of
    /// that request runs, and also just before that `send` starts: the transport then
    /// fails that `send` at once.
    fn cancel(&self, id: u64);
}

static EXTERNAL: OnceLock<Box<dyn HttpTransport>> = OnceLock::new();
static NEXT_EXTERNAL_ID: AtomicU64 = AtomicU64::new(1);

/// Install the external transport of this process, before the first relay request.
/// Returns false, and changes nothing, when one is installed already.
pub fn set_http_transport(transport: Box<dyn HttpTransport>) -> bool {
    EXTERNAL.set(transport).is_ok()
}

/// The external transport, when the host installed one.
fn external() -> Option<&'static dyn HttpTransport> {
    EXTERNAL.get().map(Box::as_ref)
}

/// The timeout of an external request: the wait of a long poll and
/// [`EXTERNAL_MARGIN`], at most the time left before the deadline. `Connect` when the
/// deadline passed.
fn external_timeout(request: &Request<'_>) -> Result<Duration, HttpError> {
    let normal = request.wait.saturating_add(EXTERNAL_MARGIN);
    let timeout = time_left(request.deadline, normal, HttpError::Connect)?;
    Ok(timeout.max(Duration::from_millis(1)))
}

/// The header lines of an external request, with the checks of [`request_head`].
fn external_headers(
    request: &Request<'_>,
    has_body: bool,
) -> Result<Vec<(&'static str, Zeroizing<String>)>, HttpError> {
    let mut lines = Vec::with_capacity(request.headers.len() + 3);
    if let Some(token) = request.bearer {
        if !valid_header_text(token) || token.contains(' ') {
            return Err(HttpError::Protocol);
        }
        lines.push(("Authorization", Zeroizing::new(format!("Bearer {token}"))));
    }
    if has_body {
        lines.push((
            "Content-Type",
            Zeroizing::new("application/json".to_owned()),
        ));
    }
    for (name, value) in &request.headers {
        if !valid_header_text(value) {
            return Err(HttpError::Protocol);
        }
        lines.push((*name, Zeroizing::new(value.clone())));
    }
    lines.push(("User-Agent", Zeroizing::new("apassy-sync/1".to_owned())));
    Ok(lines)
}

/// Whether `name` is an HTTP header name (a token).
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// An answer of the external transport, with the checks and limits of an answer read
/// from a socket: a final status, at most [`MAX_HEAD_BYTES`] of valid header lines, and
/// at most [`MAX_JSON_ANSWER`] bytes of body.
fn checked_external(answer: ExternalAnswer) -> Result<Answer, HttpError> {
    let ExternalAnswer {
        status,
        headers: lines,
        body,
    } = answer;
    if !(200..600).contains(&status) || lines.len() > MAX_EXTERNAL_HEADERS {
        return Err(HttpError::Protocol);
    }
    let mut size = 0usize;
    let mut headers = Vec::with_capacity(lines.len());
    for (name, value) in lines {
        size = size.saturating_add(name.len() + value.len() + 4);
        if size > MAX_HEAD_BYTES
            || !valid_header_name(&name)
            || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        {
            return Err(HttpError::Protocol);
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    if body.len() > MAX_JSON_ANSWER {
        return Err(HttpError::Protocol);
    }
    Ok(Answer {
        status,
        headers,
        body,
    })
}

/// [`exchange`] through the external transport `transport`. A file body fails: a
/// snapshot never goes through it.
fn exchange_external(
    transport: &'static dyn HttpTransport,
    url: &RelayUrl,
    request: &Request<'_>,
) -> Result<Answer, HttpError> {
    if request.cancel.is_some_and(Cancel::is_closed) {
        return Err(HttpError::Connect);
    }
    if !request.path.starts_with('/') || request.path.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(HttpError::Protocol);
    }
    let body = match &request.body {
        Body::None => None,
        Body::Json(bytes) => Some(bytes.as_slice()),
        Body::File(..) => return Err(HttpError::Protocol),
    };
    let timeout = external_timeout(request)?;
    let headers = external_headers(request, body.is_some())?;
    let id = NEXT_EXTERNAL_ID.fetch_add(1, Ordering::SeqCst);
    let mut held = Held(None);
    if let Some(cancel) = request.cancel {
        let number = cancel.hold_external(id, transport)?;
        held = Held(Some((cancel, number)));
    }
    let external = ExternalRequest {
        id,
        method: request.method,
        url: format!("{}{}", url.as_str(), request.path),
        headers,
        body,
        timeout,
        // A pinned origin: the transport checks the pin and never falls back to the
        // system trust of the host (node-pairing-v1 section 4).
        pin: url.pin().map(|pin| pin.text()),
    };
    let answer = transport.send(&external);
    drop(external);
    drop(held);
    checked_external(answer?)
}

/// The pinned TLS of a node inside a Connect dial.
type TunnelTls = StreamOwned<ClientConnection, CountingPipe>;

/// The pipe of a dial with the bytes that went into it since [`CountingPipe::sent`] was
/// last set to zero: a kept connection whose request left nothing in the pipe can take a
/// fresh connection without any risk of a double request.
struct CountingPipe {
    pipe: Box<dyn TunnelPipe>,
    sent: u64,
}

impl Read for CountingPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.pipe.read(buf)
    }
}

impl Write for CountingPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.pipe.write(buf)?;
        self.sent = self.sent.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pipe.flush()
    }
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    /// The pinned TLS of a node inside a Connect dial.
    Tunnel(Box<TunnelTls>),
}

impl Conn {
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), HttpError> {
        let timeout = timeout.max(Duration::from_millis(1));
        match self {
            Self::Plain(stream) => stream.set_read_timeout(Some(timeout)),
            Self::Tls(stream) => stream.sock.set_read_timeout(Some(timeout)),
            Self::Tunnel(stream) => stream.sock.pipe.set_read_timeout(timeout),
        }
        .map_err(|_| HttpError::Broken)
    }

    fn set_write_timeout(&self, timeout: Duration) -> Result<(), HttpError> {
        let timeout = timeout.max(Duration::from_millis(1));
        match self {
            Self::Plain(stream) => stream.set_write_timeout(Some(timeout)),
            Self::Tls(stream) => stream.sock.set_write_timeout(Some(timeout)),
            Self::Tunnel(stream) => stream.sock.pipe.set_write_timeout(timeout),
        }
        .map_err(|_| HttpError::Broken)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
            Self::Tunnel(stream) => stream.read(buf),
        };
        match read {
            // A server can close TLS without close_notify. The body length decides.
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
            Self::Tunnel(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
            Self::Tunnel(stream) => stream.flush(),
        }
    }
}

fn tls() -> Result<&'static TlsClient, HttpError> {
    static TLS: OnceLock<Option<TlsClient>> = OnceLock::new();
    TLS.get_or_init(|| TlsClient::platform().ok())
        .as_ref()
        .ok_or(HttpError::Connect)
}

/// Connect to the first address that answers, each within `CONNECT_TIMEOUT`, all by
/// `end`. Stops when the request gave up (`abandoned`).
fn connect_any(
    addrs: &[SocketAddr],
    end: Instant,
    abandoned: &AtomicBool,
) -> Result<TcpStream, HttpError> {
    for addr in addrs {
        if abandoned.load(Ordering::SeqCst) {
            break;
        }
        let timeout = time_left(Some(end), CONNECT_TIMEOUT, HttpError::Connect)?;
        if let Ok(stream) = TcpStream::connect_timeout(addr, timeout) {
            return Ok(stream);
        }
    }
    Err(HttpError::Connect)
}

/// The TCP connection of a request to `destination`. The name lookup and the connect
/// run on a helper thread that holds no token: a cancel or `end` ends the wait at once,
/// and the helper drops a connection that comes too late.
fn open_tcp(
    destination: &DestinationUrl,
    cancel: Option<&Cancel>,
    end: Instant,
) -> Result<TcpStream, HttpError> {
    let destination = destination.clone();
    let abandoned = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    {
        let abandoned = Arc::clone(&abandoned);
        std::thread::Builder::new()
            .name("apassy-relay-connect".to_owned())
            .spawn(move || {
                let addrs = match &destination {
                    DestinationUrl::Loopback { addr, .. } => Ok(vec![*addr]),
                    DestinationUrl::Https { host, port } => (host.as_str(), *port)
                        .to_socket_addrs()
                        .map(Iterator::collect)
                        .map_err(|_| HttpError::Connect),
                };
                let _ = sender.send(addrs.and_then(|addrs| connect_any(&addrs, end, &abandoned)));
            })
            .map_err(|_| HttpError::Connect)?;
    }
    let give_up = || {
        abandoned.store(true, Ordering::SeqCst);
        Err(HttpError::Connect)
    };
    loop {
        if cancel.is_some_and(Cancel::is_closed) {
            return give_up();
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return give_up();
        }
        match receiver.recv_timeout(left.min(CANCEL_CHECK)) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return give_up(),
        }
    }
}

/// The socket limits of `request` on `tcp`, and its place in the [`Cancel`] of the
/// request.
fn hold_socket<'a>(tcp: &TcpStream, request: &Request<'a>) -> Result<Held<'a>, HttpError> {
    let stall = time_left(request.deadline, STALL_TIMEOUT, HttpError::Connect)?;
    let header = time_left(request.deadline, HEADER_TIMEOUT, HttpError::Connect)?;
    tcp.set_write_timeout(Some(stall))
        .map_err(|_| HttpError::Connect)?;
    tcp.set_read_timeout(Some(header))
        .map_err(|_| HttpError::Connect)?;
    let mut held = Held(None);
    if let Some(cancel) = request.cancel {
        let number = cancel.hold(tcp).map_err(|_| HttpError::Connect)?;
        held = Held(Some((cancel, number)));
    }
    Ok(held)
}

/// Connect for `request`. Its socket is in its [`Cancel`] from the TCP connect on, so a
/// cancel also ends the TLS handshake. A failed check sends no token.
///
/// A local route connects plain to the loopback address of this Mac's node. Otherwise
/// the origin's host comes first, then each alternative of a pinned address, while a
/// connection is refused or times out; all of it ends within `CONNECT_LIMIT`. A TLS
/// failure stops at once: a pin mismatch is [`HttpError::PinMismatch`], and no other
/// destination is tried after a wrong certificate.
///
/// A pinned address with a Connect route and a dialer (plan s7 unit I2) has a second
/// route: the dial, with the same pinned TLS inside it. The dialer gives the order: the
/// direct destinations first (within [`DIRECT_SHARE`], so the dial keeps time), then
/// the dial; or, while the direct destinations failed recently, the dial first and the
/// direct destinations last. A pin mismatch on either route stops at once.
fn connect<'a>(url: &RelayUrl, request: &Request<'a>) -> Result<(Conn, Held<'a>), HttpError> {
    let limit = Instant::now() + CONNECT_LIMIT;
    let end = request
        .deadline
        .map_or(limit, |deadline| deadline.min(limit));
    if let Some(addr) = local_route(url) {
        let local = DestinationUrl::Loopback {
            addr,
            host_header: String::new(),
        };
        let tcp = open_tcp(&local, request.cancel, end)?;
        let held = hold_socket(&tcp, request)?;
        return Ok((Conn::Plain(tcp), held));
    }
    let pinned = match url.trust {
        TlsTrust::System => None,
        TlsTrust::Pinned(pin) => Some(TlsClient::pinned(&pin).map_err(|_| HttpError::Connect)?),
    };
    let (Some(route), Some(dialer), Some(tls)) = (&url.tunnel, &url.dialer, &pinned) else {
        return connect_direct(url, request, pinned.as_ref(), end);
    };
    let dialer = dialer.0.as_ref();
    let cancelled = || request.cancel.is_some_and(Cancel::is_closed);
    if dialer.direct_first(url) {
        let direct_end = end.min(Instant::now() + DIRECT_SHARE);
        match connect_direct(url, request, pinned.as_ref(), direct_end) {
            Ok(found) => {
                dialer.reached(url, NodeRoute::Direct);
                return Ok(found);
            }
            Err(HttpError::Connect) if !cancelled() => dialer.direct_failed(url),
            Err(error) => return Err(error),
        }
        let found = connect_tunnel(url, request, tls, route, dialer, end)?;
        dialer.reached(url, NodeRoute::Tunnel);
        return Ok(found);
    }
    match connect_tunnel(url, request, tls, route, dialer, end) {
        Ok(found) => {
            dialer.reached(url, NodeRoute::Tunnel);
            Ok(found)
        }
        Err(HttpError::Connect) if !cancelled() => {
            let found = connect_direct(url, request, pinned.as_ref(), end)?;
            dialer.reached(url, NodeRoute::Direct);
            Ok(found)
        }
        Err(error) => Err(error),
    }
}

/// The longest time of the direct destinations when a Connect dial comes after them.
const DIRECT_SHARE: Duration = CONNECT_TIMEOUT;

/// The pinned (or system) TLS handshake of `name` on `sock`, before any request byte.
/// A pin mismatch is [`HttpError::PinMismatch`]; every other failure `Connect`.
fn handshake<S: Read + Write>(
    config: Arc<rustls::ClientConfig>,
    host: &str,
    sock: S,
    pinned: bool,
) -> Result<StreamOwned<ClientConnection, S>, HttpError> {
    let name = ServerName::try_from(host.to_owned()).map_err(|_| HttpError::Connect)?;
    let conn = ClientConnection::new(config, name).map_err(|_| HttpError::Connect)?;
    let mut stream = StreamOwned::new(conn, sock);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(|error| {
            if pinned && is_pin_mismatch(&error) {
                HttpError::PinMismatch
            } else {
                HttpError::Connect
            }
        })?;
    }
    Ok(stream)
}

/// The direct destinations of `url`, the origin's host first: [`connect`] without a
/// local route and without the dial.
fn connect_direct<'a>(
    url: &RelayUrl,
    request: &Request<'a>,
    pinned: Option<&TlsClient>,
    end: Instant,
) -> Result<(Conn, Held<'a>), HttpError> {
    for destination in url.destinations() {
        if request.cancel.is_some_and(Cancel::is_closed) {
            break;
        }
        let Ok(tcp) = open_tcp(destination, request.cancel, end) else {
            // Refused, unreachable, or timed out: the next destination, if any.
            continue;
        };
        let held = hold_socket(&tcp, request)?;
        let host = match destination {
            // Plain http:// is loopback only, and never pinned (`with_trust`).
            DestinationUrl::Loopback { .. } => return Ok((Conn::Plain(tcp), held)),
            DestinationUrl::Https { host, .. } => host,
        };
        let config = match pinned {
            Some(pinned) => pinned.client_config(),
            None => tls()?.client_config(),
        };
        // Finish the handshake before any request byte.
        let stream = handshake(config, host, tcp, pinned.is_some())?;
        return Ok((Conn::Tls(Box::new(stream)), held));
    }
    Err(HttpError::Connect)
}

/// The Connect dial of `route`, and the pinned TLS of the node inside it: the same
/// verifier and the same server name as on the tailnet, so Connect sees TLS records
/// only. The end of the pipe is in the [`Cancel`] of the request from the dial on. A
/// pin mismatch ends the dial before any request byte.
fn connect_tunnel<'a>(
    url: &RelayUrl,
    request: &Request<'a>,
    pinned: &TlsClient,
    route: &TunnelRoute,
    dialer: &dyn TunnelDialer,
    end: Instant,
) -> Result<(Conn, Held<'a>), HttpError> {
    if request.cancel.is_some_and(Cancel::is_closed) {
        return Err(HttpError::Connect);
    }
    let DestinationUrl::Https { host, .. } = &url.destination else {
        return Err(HttpError::Connect);
    };
    let pipe = dialer.dial(route, end)?;
    let close = pipe.closer();
    let mut held = Held(None);
    if let Some(cancel) = request.cancel {
        let number = cancel.hold_pipe(Arc::clone(&close))?;
        held = Held(Some((cancel, number)));
    }
    let stall = time_left(request.deadline, STALL_TIMEOUT, HttpError::Connect)?;
    let header = time_left(Some(end), HEADER_TIMEOUT, HttpError::Connect)?;
    if pipe.set_write_timeout(stall).is_err() || pipe.set_read_timeout(header).is_err() {
        close();
        return Err(HttpError::Connect);
    }
    let mut stream = handshake(
        pinned.client_config(),
        host,
        CountingPipe { pipe, sent: 0 },
        true,
    )?;
    stream.sock.sent = 0;
    // The handshake had the connect time; the answer has the header time.
    let header = time_left(request.deadline, HEADER_TIMEOUT, HttpError::Connect)?;
    stream
        .sock
        .pipe
        .set_read_timeout(header)
        .map_err(|_| HttpError::Connect)?;
    Ok((Conn::Tunnel(Box::new(stream)), held))
}

/// Whether the direct destinations of the pinned address `url` reach the node now: a
/// TCP connection and the pinned TLS handshake within `timeout`, with no request byte
/// and no token. A dialer uses it to come back from the dial to the tailnet.
/// [`HttpError::PinMismatch`] for another certificate.
pub fn probe_direct(url: &RelayUrl, timeout: Duration) -> Result<(), HttpError> {
    let pin = url.pin().ok_or(HttpError::Connect)?;
    let pinned = TlsClient::pinned(&pin).map_err(|_| HttpError::Connect)?;
    let end = Instant::now() + timeout.min(CONNECT_LIMIT);
    let mut request = Request::new("GET", "/".to_owned(), None);
    request.deadline = Some(end);
    let direct = url.direct_only();
    connect_direct(&direct, &request, Some(&pinned), end).map(|_| ())
}

fn valid_header_text(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| (0x20..0x7f).contains(&byte))
}

/// The request head in one buffer of the exact size. `close`: it asks for
/// `Connection: close` (every request but one on a connection that may be kept,
/// [`KeptDials`]).
fn request_head(
    url: &RelayUrl,
    request: &Request<'_>,
    close: bool,
) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    if !request.path.starts_with('/') || request.path.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(HttpError::Protocol);
    }
    let (content_type, length) = match &request.body {
        Body::None => (None, 0),
        Body::Json(bytes) => (Some("application/json"), bytes.len() as u64),
        Body::File(_, size) => (Some("application/octet-stream"), *size),
    };
    let mut lines: Vec<(&str, &str)> = vec![("Host", url.host_header())];
    let bearer;
    if let Some(token) = request.bearer {
        if !valid_header_text(token) || token.contains(' ') {
            return Err(HttpError::Protocol);
        }
        bearer = Zeroizing::new(format!("Bearer {token}"));
        lines.push(("Authorization", bearer.as_str()));
    }
    if let Some(content_type) = content_type {
        lines.push(("Content-Type", content_type));
    }
    let length = length.to_string();
    lines.push(("Content-Length", &length));
    for (name, value) in &request.headers {
        if !valid_header_text(value) {
            return Err(HttpError::Protocol);
        }
        lines.push((name, value));
    }
    lines.push(("User-Agent", "apassy-sync/1"));
    if close {
        lines.push(("Connection", "close"));
    }
    let size = request.method.len()
        + 1
        + request.path.len()
        + 11
        + lines
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum::<usize>()
        + 2;
    let mut head = Zeroizing::new(Vec::with_capacity(size));
    head.extend_from_slice(request.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in lines {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    Ok(head)
}

/// A request that went out on its connection.
struct Sent<'a> {
    conn: Conn,
    /// The whole request went out (an early answer can come before the end of a body).
    complete: bool,
    held: Held<'a>,
    /// Where the connection may go after a complete answer ([`KeptDials`]).
    slot: Option<KeepSlot>,
    /// The connection was kept from an earlier request.
    reused: bool,
}

/// The place of a request's connection in the [`KeptDials`] of its host.
#[derive(Clone)]
struct KeepSlot {
    dials: KeptDials,
    /// The node: its origin, its pin, and its Connect route.
    key: String,
    /// [`KeptDials::clear`] after this: the connection is not kept.
    epoch: u64,
}

impl Sent<'_> {
    /// The answer was read whole and `keeps` the connection: it goes back to the kept
    /// dials of its node. Otherwise it closes, as it always did.
    fn finish(self, keeps: bool) {
        let Sent {
            conn,
            complete,
            held,
            slot,
            ..
        } = self;
        drop(held);
        if let (true, Some(slot), Conn::Tunnel(tls)) = (keeps && complete, slot, conn) {
            slot.dials.put(slot.key, slot.epoch, tls);
        }
    }
}

/// A GET or HEAD without a body: the only requests that are sent again when a kept
/// connection ended after they went out and before any byte of the answer.
fn repeatable(request: &Request<'_>) -> bool {
    matches!(request.method, "GET" | "HEAD") && matches!(request.body, Body::None)
}

/// The kept dials of the host of `url` and the slot of `request` there: a request
/// through the Connect route of a pinned address whose dialer keeps connections, that
/// is not a long poll. `None` for every other request.
fn keep_slot(url: &RelayUrl, request: &Request<'_>) -> Option<KeepSlot> {
    if !request.wait.is_zero() || local_route(url).is_some() {
        return None;
    }
    let (Some(route), Some(dialer), Some(pin)) = (&url.tunnel, &url.dialer, url.pin()) else {
        return None;
    };
    let dials = dialer.0.kept()?;
    let epoch = dials.epoch();
    Some(KeepSlot {
        dials,
        key: format!("{} {} {}", url.as_str(), pin.text(), route.text()),
        epoch,
    })
}

/// The kept connection of `slot` for `request`, unless the direct destinations come
/// first now: in the [`Cancel`] of the request, with its timeouts. The dialer learns
/// that the node was reached through the dial.
fn take_kept<'a>(
    url: &RelayUrl,
    request: &Request<'a>,
    slot: &KeepSlot,
) -> Result<Option<(Conn, Held<'a>)>, HttpError> {
    let Some(dialer) = &url.dialer else {
        return Ok(None);
    };
    if dialer.0.direct_first(url) {
        return Ok(None);
    }
    let Some(mut tls) = slot.dials.take(&slot.key) else {
        return Ok(None);
    };
    tls.sock.sent = 0;
    let mut held = Held(None);
    if let Some(cancel) = request.cancel {
        let number = cancel.hold_pipe(tls.sock.pipe.closer())?;
        held = Held(Some((cancel, number)));
    }
    let stall = time_left(request.deadline, STALL_TIMEOUT, HttpError::Connect)?;
    let header = time_left(request.deadline, HEADER_TIMEOUT, HttpError::Connect)?;
    if tls.sock.pipe.set_write_timeout(stall).is_err()
        || tls.sock.pipe.set_read_timeout(header).is_err()
    {
        return Err(HttpError::Connect);
    }
    dialer.0.reached(url, NodeRoute::Tunnel);
    Ok(Some((Conn::Tunnel(tls), held)))
}

/// Write `head` and the body of `request` to `conn`, and flush. `Ok(false)`: a write of
/// the body or the flush failed (the caller reads an early answer anyway).
fn write_request(
    conn: &mut Conn,
    head: &[u8],
    request: &Request<'_>,
    file: Option<&mut File>,
) -> Result<bool, HttpError> {
    if conn.write_all(head).is_err() {
        return Err(HttpError::Broken);
    }
    let complete = match (&request.body, file) {
        (Body::Json(bytes), _) => conn.write_all(bytes).is_ok(),
        (Body::File(..), Some(file)) => {
            let mut buffer = vec![0u8; CHUNK];
            loop {
                let read = file.read(&mut buffer).map_err(|_| HttpError::Broken)?;
                if read == 0 {
                    break true;
                }
                let Ok(stall) = time_left(request.deadline, STALL_TIMEOUT, HttpError::Broken)
                else {
                    break false;
                };
                if conn.set_write_timeout(stall).is_err()
                    || conn.write_all(&buffer[..read]).is_err()
                {
                    break false;
                }
            }
        }
        _ => true,
    };
    Ok(complete && conn.flush().is_ok())
}

/// Send the request. Returns the connection and whether the whole request went out.
/// The body always goes out whole: a relay that answers early (a `412` or a `413`)
/// reads the rest anyway, and the caller then reads that answer. A request with a
/// [`Cancel`] registers its socket there; a body write stops at the deadline.
///
/// A request through the dial of a host that keeps connections ([`keep_slot`]) first
/// takes the kept connection of its node, if any (`kept`), and never asks for
/// `Connection: close` on a dial. When nothing of the request reached the pipe of the
/// kept connection, it goes out on a fresh connection instead.
fn send<'a>(url: &RelayUrl, request: &Request<'a>, kept: bool) -> Result<Sent<'a>, HttpError> {
    if request.cancel.is_some_and(Cancel::is_closed) {
        return Err(HttpError::Connect);
    }
    time_left(request.deadline, CONNECT_TIMEOUT, HttpError::Connect)?;
    let head = request_head(url, request, true)?;
    let mut file = match &request.body {
        Body::File(path, size) => {
            let file = File::open(path).map_err(|_| HttpError::Protocol)?;
            let actual = file.metadata().map_err(|_| HttpError::Protocol)?.len();
            if actual != *size {
                return Err(HttpError::Protocol);
            }
            Some(file)
        }
        _ => None,
    };
    let slot = keep_slot(url, request);
    if kept
        && let Some(slot) = &slot
        && let Some((mut conn, held)) = take_kept(url, request, slot)?
    {
        let open = request_head(url, request, false)?;
        let written = write_request(&mut conn, &open, request, file.as_mut());
        drop(open);
        let nothing_sent = matches!(&conn, Conn::Tunnel(tls) if tls.sock.sent == 0);
        match written {
            Ok(complete) if complete || !nothing_sent => {
                return Ok(Sent {
                    conn,
                    complete,
                    held,
                    slot: Some(slot.clone()),
                    reused: true,
                });
            }
            // A part of the request may have reached the node.
            Err(error) if !nothing_sent && !repeatable(request) => return Err(error),
            // Nothing reached the node, or a read that may go again: a fresh connection.
            _ => {}
        }
        drop(conn);
        drop(held);
        if let Some(file) = file.as_mut() {
            file.seek(io::SeekFrom::Start(0))
                .map_err(|_| HttpError::Broken)?;
        }
    }
    let (mut conn, held) = connect(url, request)?;
    let keeps = slot.is_some() && matches!(conn, Conn::Tunnel(_));
    let head = if keeps {
        drop(head);
        request_head(url, request, false)?
    } else {
        head
    };
    let complete = write_request(&mut conn, &head, request, file.as_mut())?;
    drop(head);
    Ok(Sent {
        conn,
        complete,
        held,
        slot: slot.filter(|_| keeps),
        reused: false,
    })
}

/// Why no byte of an answer came.
enum NoAnswer {
    /// The connection ended or failed first.
    Ended,
    /// The time ran out.
    Late,
}

/// When the answer head must be there: the header time, and a long poll's wait, within
/// the request's deadline.
fn head_deadline(request: &Request<'_>) -> Instant {
    let deadline = Instant::now() + HEADER_TIMEOUT + request.wait;
    request
        .deadline
        .map_or(deadline, |overall| deadline.min(overall))
}

/// The first bytes of the answer, before `deadline`.
fn first_bytes(conn: &mut Conn, deadline: Instant) -> Result<Zeroizing<Vec<u8>>, NoAnswer> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(NoAnswer::Late);
    }
    conn.set_read_timeout(left.min(STALL_TIMEOUT))
        .map_err(|_| NoAnswer::Ended)?;
    let mut chunk = Zeroizing::new([0u8; 8192]);
    match conn.read(chunk.as_mut()) {
        Ok(0) => Err(NoAnswer::Ended),
        Ok(read) => {
            let mut buffer = Zeroizing::new(Vec::with_capacity(ANSWER_CAPACITY));
            buffer.extend_from_slice(&chunk[..read]);
            Ok(buffer)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(NoAnswer::Late)
        }
        Err(_) => Err(NoAnswer::Ended),
    }
}

/// Send `request` and wait for the first bytes of its answer. A kept connection that
/// ended before any byte of the answer sends a [`repeatable`] request once more on a
/// fresh connection; any other request then fails with [`HttpError::Broken`], as a
/// connection that breaks after the request started always does.
fn send_and_await<'a>(
    url: &RelayUrl,
    request: &Request<'a>,
) -> Result<(Sent<'a>, Zeroizing<Vec<u8>>, Instant), HttpError> {
    let mut sent = send(url, request, true)?;
    let deadline = head_deadline(request);
    match first_bytes(&mut sent.conn, deadline) {
        Ok(start) => Ok((sent, start, deadline)),
        Err(NoAnswer::Ended) if sent.reused && repeatable(request) => {
            drop(sent);
            let mut sent = send(url, request, false)?;
            let deadline = head_deadline(request);
            let start = first_bytes(&mut sent.conn, deadline).map_err(|_| HttpError::Broken)?;
            Ok((sent, start, deadline))
        }
        Err(_) => Err(HttpError::Broken),
    }
}

/// Bytes from the connection with a buffer in front. The buffer is erased on drop.
struct Source<'a> {
    conn: &'a mut Conn,
    buffer: Zeroizing<Vec<u8>>,
    start: usize,
    /// A read after this fails.
    deadline: Option<Instant>,
}

impl Source<'_> {
    fn pending(&self) -> &[u8] {
        &self.buffer[self.start..]
    }

    /// Read more bytes into the buffer. `false` at the end of the stream.
    fn fill(&mut self) -> io::Result<bool> {
        if self.start > 0 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        if self.deadline.is_some() {
            let stall = time_left(self.deadline, STALL_TIMEOUT, HttpError::Broken)
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            self.conn
                .set_read_timeout(stall)
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        }
        let mut chunk = Zeroizing::new([0u8; 8192]);
        let read = self.conn.read(chunk.as_mut())?;
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(read > 0)
    }

    fn take(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pending().is_empty() && !self.fill()? {
            return Ok(0);
        }
        let count = out.len().min(self.pending().len());
        out[..count].copy_from_slice(&self.buffer[self.start..self.start + count]);
        self.start += count;
        Ok(count)
    }

    /// One line without its `\r\n`, at most `max` bytes.
    fn line(&mut self, max: usize) -> io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.pending().windows(2).position(|pair| pair == b"\r\n") {
                let line = self.pending()[..end].to_vec();
                self.start += end + 2;
                return Ok(line);
            }
            if self.pending().len() > max {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if !self.fill()? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

enum BodyKind {
    Length(u64),
    Chunked,
    UntilClose,
}

/// The body of an answer as a reader.
struct BodyReader<'a> {
    source: Source<'a>,
    kind: BodyKind,
    /// The bytes left of the current chunk.
    chunk_left: u64,
    done: bool,
}

impl BodyReader<'_> {
    /// The body was read to its end, it had a length or chunks (not "until the
    /// connection closes"), and no byte came after it: the connection may carry another
    /// request.
    fn whole(&self) -> bool {
        self.done && !matches!(self.kind, BodyKind::UntilClose) && self.source.pending().is_empty()
    }
}

impl Read for BodyReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        match self.kind {
            BodyKind::Length(ref mut left) => {
                if *left == 0 {
                    self.done = true;
                    return Ok(0);
                }
                let want = usize::try_from(*left).unwrap_or(usize::MAX).min(out.len());
                let read = self.source.take(&mut out[..want])?;
                if read == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                *left -= read as u64;
                Ok(read)
            }
            BodyKind::UntilClose => {
                let read = self.source.take(out)?;
                self.done = read == 0;
                Ok(read)
            }
            BodyKind::Chunked => {
                if self.chunk_left == 0 {
                    let line = self.source.line(1024)?;
                    let text = std::str::from_utf8(&line)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                    let size = text.split(';').next().unwrap_or_default().trim();
                    let size = u64::from_str_radix(size, 16)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                    if size == 0 {
                        // Trailers end with an empty line. This client ignores them.
                        while !self.source.line(MAX_HEAD_BYTES)?.is_empty() {}
                        self.done = true;
                        return Ok(0);
                    }
                    self.chunk_left = size;
                }
                let want = usize::try_from(self.chunk_left)
                    .unwrap_or(usize::MAX)
                    .min(out.len());
                let read = self.source.take(&mut out[..want])?;
                if read == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                self.chunk_left -= read as u64;
                if self.chunk_left == 0 && !self.source.line(2)?.is_empty() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(read)
            }
        }
    }
}

/// The header lines of an answer: lowercase names and trimmed values.
type Headers = Vec<(String, String)>;

/// The status, the headers, and the rest of the stream after the head.
struct Head<'a> {
    status: u16,
    headers: Headers,
    source: Source<'a>,
    /// The answer may leave its connection open: HTTP/1.1 without `Connection: close`.
    keeps: bool,
}

/// True when the `connection` headers of an answer carry the token `close`.
fn asks_close(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name == "connection")
        .flat_map(|(_, value)| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"))
}

/// Read the answer head, after its first bytes `start` ([`first_bytes`]), by
/// `deadline`. Interim `1xx` answers are skipped. Every read of the answer ends by
/// `overall`, when the request has a deadline.
fn read_head(
    conn: &mut Conn,
    start: Zeroizing<Vec<u8>>,
    deadline: Instant,
    overall: Option<Instant>,
) -> Result<Head<'_>, HttpError> {
    let mut source = Source {
        conn,
        buffer: start,
        start: 0,
        deadline: None,
    };
    loop {
        let end = loop {
            if let Some(end) = source.pending().windows(4).position(|w| w == b"\r\n\r\n") {
                break end;
            }
            if source.pending().len() > MAX_HEAD_BYTES {
                return Err(HttpError::Protocol);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(HttpError::Broken);
            }
            source.conn.set_read_timeout(left.min(STALL_TIMEOUT))?;
            match source.fill() {
                Ok(true) => {}
                Ok(false) | Err(_) => return Err(HttpError::Broken),
            }
        };
        let text = std::str::from_utf8(&source.pending()[..end])
            .map_err(|_| HttpError::Protocol)?
            .to_owned();
        source.start += end + 4;
        let mut lines = text.split("\r\n");
        let mut status_line = lines.next().unwrap_or_default().split(' ');
        let version = status_line.next().unwrap_or_default();
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err(HttpError::Protocol);
        }
        let status: u16 = status_line
            .next()
            .and_then(|code| code.parse().ok())
            .filter(|code| (100..600).contains(code))
            .ok_or(HttpError::Protocol)?;
        if (100..200).contains(&status) {
            continue;
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or(HttpError::Protocol)?;
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        source.conn.set_read_timeout(STALL_TIMEOUT)?;
        source.deadline = overall;
        let keeps = version == "HTTP/1.1" && !asks_close(&headers);
        return Ok(Head {
            status,
            headers,
            source,
            keeps,
        });
    }
}

fn body_kind(status: u16, headers: &[(String, String)]) -> Result<BodyKind, HttpError> {
    if status == 204 || status == 304 {
        return Ok(BodyKind::Length(0));
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if let Some(encoding) = find("transfer-encoding") {
        return if encoding.eq_ignore_ascii_case("chunked") {
            Ok(BodyKind::Chunked)
        } else {
            Err(HttpError::Protocol)
        };
    }
    match find("content-length") {
        Some(length) => length
            .parse()
            .map(BodyKind::Length)
            .map_err(|_| HttpError::Protocol),
        None => Ok(BodyKind::UntilClose),
    }
}

fn read_limited(reader: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let mut body = Zeroizing::new(Vec::with_capacity(ANSWER_CAPACITY));
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| HttpError::Broken)?;
    if body.len() > limit {
        return Err(HttpError::Protocol);
    }
    Ok(body)
}

/// Send a request and read the answer into memory (at most 2 MiB): through the external
/// transport when the host installed one, else over TCP.
pub(crate) fn exchange(url: &RelayUrl, request: &Request<'_>) -> Result<Answer, HttpError> {
    match external() {
        Some(transport) if local_route(url).is_none() => exchange_external(transport, url, request),
        _ => exchange_tcp(url, request),
    }
}

/// One JSON `POST` without a bearer to `path` of a service that is not a relay: the push
/// gateway of push-gateway-v1 (`POST /v1/handles`). System trust, as a relay origin; the
/// whole call ends within `timeout`; the answer is read into memory (at most 2 MiB).
/// Returns the status and the body, which is erased on drop. Through the external
/// transport when the host installed one.
pub fn post_json(
    origin: &RelayUrl,
    path: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Zeroizing<Vec<u8>>), HttpError> {
    if !path.starts_with('/') || !path.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(HttpError::Protocol);
    }
    let mut request = Request::new("POST", path.to_owned(), None);
    request.body = Body::Json(Zeroizing::new(body.to_vec()));
    request.deadline = Some(Instant::now() + timeout);
    let answer = exchange(origin, &request)?;
    Ok((answer.status, answer.body))
}

fn exchange_tcp(url: &RelayUrl, request: &Request<'_>) -> Result<Answer, HttpError> {
    let (mut sent, start, deadline) = send_and_await(url, request)?;
    let Head {
        status,
        headers,
        source,
        keeps,
    } = read_head(&mut sent.conn, start, deadline, request.deadline)?;
    let kind = body_kind(status, &headers)?;
    let mut reader = BodyReader {
        source,
        kind,
        chunk_left: 0,
        done: false,
    };
    let body = read_limited(&mut reader, MAX_JSON_ANSWER)?;
    let keeps = keeps && reader.whole();
    drop(reader);
    sent.finish(keeps);
    Ok(Answer {
        status,
        headers,
        body,
    })
}

/// What a download wrote.
#[derive(Debug)]
pub(crate) struct Downloaded {
    /// SHA-256 of the bytes.
    pub(crate) sha256: [u8; 32],
    /// The number of bytes.
    pub(crate) size: u64,
}

/// Send a request and stream a `200` body to `dest` while hashing it. A body longer
/// than `max` bytes fails. Another status reads its (JSON) body into the answer. With an
/// external transport it fails: the Apple Watch never downloads a snapshot.
pub(crate) fn download(
    url: &RelayUrl,
    request: &Request<'_>,
    dest: &mut File,
    max: u64,
) -> Result<(Answer, Option<Downloaded>), HttpError> {
    if external().is_some() {
        return Err(HttpError::Protocol);
    }
    let (mut sent, start, deadline) = send_and_await(url, request)?;
    let Head {
        status,
        headers,
        source,
        keeps,
    } = read_head(&mut sent.conn, start, deadline, request.deadline)?;
    let kind = body_kind(status, &headers)?;
    let mut reader = BodyReader {
        source,
        kind,
        chunk_left: 0,
        done: false,
    };
    if status != 200 {
        let body = read_limited(&mut reader, MAX_JSON_ANSWER)?;
        let keeps = keeps && reader.whole();
        drop(reader);
        sent.finish(keeps);
        return Ok((
            Answer {
                status,
                headers,
                body,
            },
            None,
        ));
    }
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut size = 0u64;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| HttpError::Broken)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > max {
            return Err(HttpError::Protocol);
        }
        hash.update(&buffer[..read]);
        dest.write_all(&buffer[..read])
            .map_err(|_| HttpError::Broken)?;
    }
    let keeps = keeps && reader.whole();
    drop(reader);
    dest.sync_all().map_err(|_| HttpError::Broken)?;
    sent.finish(keeps);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(hash.finish().as_ref());
    Ok((
        Answer {
            status,
            headers,
            body: Zeroizing::new(Vec::new()),
        },
        Some(Downloaded { sha256, size }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn https_anywhere_and_plain_http_only_on_loopback() {
        for (text, origin) in [
            (
                "https://apassy-relay.wyderka.cc",
                "https://apassy-relay.wyderka.cc",
            ),
            ("https://Relay.Example.test/", "https://relay.example.test"),
            (
                "https://relay.example.test:443",
                "https://relay.example.test",
            ),
            (
                "https://relay.example.test:8443",
                "https://relay.example.test:8443",
            ),
            ("http://127.0.0.1:8787", "http://127.0.0.1:8787"),
            ("http://localhost:8787/", "http://localhost:8787"),
            ("http://[::1]:8787", "http://[::1]:8787"),
        ] {
            let url = RelayUrl::parse(text).expect(text);
            assert_eq!(url.as_str(), origin, "{text}");
        }
        assert!(
            RelayUrl::parse("http://127.0.0.1:8787")
                .unwrap()
                .is_loopback()
        );
        for bad in [
            "http://relay.example.test:80",
            "http://10.0.0.1:8787",
            "http://127.0.0.1",
            "https://relay.example.test/v1",
            "https://user@relay.example.test",
            "https://relay.example.test?x=1",
            "ftp://relay.example.test",
            "relay.example.test",
        ] {
            assert_eq!(
                RelayUrl::parse(bad),
                Err(SyncError::InvalidRelayAddress),
                "{bad}"
            );
        }
    }

    /// Accept one connection and answer with `answer` after reading the head.
    fn serve_once(answer: &'static [u8]) -> (RelayUrl, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut buf).unwrap();
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..read]);
            }
            stream.write_all(answer).unwrap();
            seen
        });
        (url, server)
    }

    #[test]
    fn a_request_has_its_headers_and_a_chunked_answer_reads() {
        let (url, server) = serve_once(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: \"3\"\r\n\r\n4\r\n{\"ok\r\n3;x=1\r\n\":1\r\n1\r\n}\r\n0\r\n\r\n",
        );
        let mut request = Request::new(
            "GET",
            "/v1/sync/head?since=2".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        request.headers.push(("If-Match", "\"2\"".to_owned()));
        let answer = exchange(&url, &request).unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body.as_slice(), b"{\"ok\":1}");
        assert_eq!(answer.header("etag"), Some("\"3\""));
        let seen = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(seen.starts_with("GET /v1/sync/head?since=2 HTTP/1.1\r\nHost: 127.0.0.1:"));
        assert!(seen.contains("\r\nAuthorization: Bearer apassy_acc_synthetic\r\n"));
        assert!(seen.contains("\r\nContent-Length: 0\r\n"));
        assert!(seen.contains("\r\nIf-Match: \"2\"\r\n"));
        assert!(seen.ends_with("Connection: close\r\n\r\n"));
        assert!(!seen.contains("chunked"));
    }

    #[test]
    fn a_download_stops_at_its_limit_and_a_short_body_fails() {
        let (url, _server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789");
        let mut file = tempfile::tempfile().unwrap();
        let request = Request::new("GET", "/v1/sync/snapshot?version=1".to_owned(), None);
        assert_eq!(
            download(&url, &request, &mut file, 9).unwrap_err(),
            HttpError::Protocol
        );
        let (url, _server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234");
        let mut file = tempfile::tempfile().unwrap();
        assert_eq!(
            download(&url, &request, &mut file, 100).unwrap_err(),
            HttpError::Broken
        );
        let (url, _server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
        let mut file = tempfile::tempfile().unwrap();
        let (_, got) = download(&url, &request, &mut file, 100).unwrap();
        let got = got.unwrap();
        assert_eq!(got.size, 3);
        assert_eq!(
            crate::companion::crypto::hex(&got.sha256),
            crate::companion::crypto::sha256_hex(b"abc")
        );
    }

    /// A lock ends a long poll at once: closing its [`Cancel`] shuts the socket down,
    /// and a request after the close does not connect.
    #[test]
    fn a_cancel_ends_a_long_poll_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        // A relay that takes the request and never answers.
        let _server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            drop(stream);
        });
        let cancel = std::sync::Arc::new(Cancel::default());
        let poll = {
            let cancel = std::sync::Arc::clone(&cancel);
            let url = url.clone();
            std::thread::spawn(move || {
                let mut request = Request::new(
                    "GET",
                    "/v1/sync/head?since=1&wait=25".to_owned(),
                    Some("apassy_acc_synthetic"),
                );
                request.wait = Duration::from_secs(25);
                request.cancel = Some(&cancel);
                let started = Instant::now();
                (exchange(&url, &request).unwrap_err(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        cancel.close();
        let (error, waited) = poll.join().unwrap();
        assert_eq!(error, HttpError::Broken);
        assert!(waited < Duration::from_secs(3), "{waited:?}");
        let mut request = Request::new("GET", "/v1/sync/head".to_owned(), None);
        request.cancel = Some(&cancel);
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
    }

    /// A cancel ends a request in its TLS handshake at once: the socket is in the
    /// `Cancel` from the TCP connect on, and no request byte went out.
    #[test]
    fn a_cancel_ends_a_tls_handshake_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        // A relay that takes the connection and never answers the client hello.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let cancel = std::sync::Arc::new(Cancel::default());
        let call = {
            let cancel = std::sync::Arc::clone(&cancel);
            std::thread::spawn(move || {
                let mut request = Request::new(
                    "GET",
                    "/v1/devices".to_owned(),
                    Some("apassy_acc_synthetic"),
                );
                request.cancel = Some(&cancel);
                let started = Instant::now();
                (exchange(&url, &request).unwrap_err(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        cancel.close();
        let (error, waited) = call.join().unwrap();
        assert_eq!(error, HttpError::Connect);
        assert!(waited < Duration::from_secs(3), "{waited:?}");
    }

    /// A relay that takes each request, sends `head`, then trickles one byte every 100
    /// ms and never ends the body.
    fn serve_slow(head: &'static [u8], connections: usize) -> RelayUrl {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(head);
                    for _ in 0..300 {
                        std::thread::sleep(Duration::from_millis(100));
                        if stream.write_all(b"x").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    /// One `Cancel` ends a long poll and a download that run at the same time: a lock
    /// stops a transfer, not only the long poll.
    #[test]
    fn a_cancel_ends_a_download_and_a_long_poll_together() {
        let url = serve_slow(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n", 2);
        let cancel = std::sync::Arc::new(Cancel::default());
        let download = {
            let (cancel, url) = (std::sync::Arc::clone(&cancel), url.clone());
            std::thread::spawn(move || {
                let mut request =
                    Request::new("GET", "/v1/sync/snapshot?version=2".to_owned(), None);
                request.cancel = Some(&cancel);
                let mut file = tempfile::tempfile().unwrap();
                let started = Instant::now();
                let error = download(&url, &request, &mut file, 2_000_000).unwrap_err();
                (error, started.elapsed())
            })
        };
        let poll = {
            let (cancel, url) = (std::sync::Arc::clone(&cancel), url.clone());
            std::thread::spawn(move || {
                let mut request =
                    Request::new("GET", "/v1/sync/head?since=1&wait=25".to_owned(), None);
                request.wait = Duration::from_secs(25);
                request.cancel = Some(&cancel);
                let started = Instant::now();
                (exchange(&url, &request).unwrap_err(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        cancel.close();
        for (error, waited) in [download.join().unwrap(), poll.join().unwrap()] {
            assert_eq!(error, HttpError::Broken);
            assert!(waited < Duration::from_secs(3), "{waited:?}");
        }
    }

    /// A request with a deadline ends by then, also while the relay still sends.
    #[test]
    fn a_deadline_ends_a_slow_download() {
        let url = serve_slow(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n", 1);
        let mut request = Request::new("GET", "/v1/sync/snapshot?version=2".to_owned(), None);
        request.deadline = Some(Instant::now() + Duration::from_millis(600));
        let mut file = tempfile::tempfile().unwrap();
        let started = Instant::now();
        let error = download(&url, &request, &mut file, 2_000_000).unwrap_err();
        assert_eq!(error, HttpError::Broken);
        let waited = started.elapsed();
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        // A deadline that passed sends nothing.
        request.deadline = Some(Instant::now());
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
    }

    #[test]
    fn a_closed_port_is_a_connect_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = RelayUrl::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let request = Request::new("GET", "/v1/sync/head".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
    }

    /// A transport of the host for the tests: it records each request, answers with
    /// `answer`, and, when `blocks`, waits until its request is cancelled.
    struct FakeTransport {
        answer: Box<dyn Fn() -> Result<ExternalAnswer, HttpError> + Send + Sync>,
        blocks: bool,
        seen: Mutex<Vec<SeenRequest>>,
        cancelled: Mutex<Vec<u64>>,
    }

    struct SeenRequest {
        id: u64,
        method: &'static str,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        timeout: Duration,
        pin: Option<String>,
    }

    impl FakeTransport {
        fn leaked(
            blocks: bool,
            answer: impl Fn() -> Result<ExternalAnswer, HttpError> + Send + Sync + 'static,
        ) -> &'static Self {
            Box::leak(Box::new(Self {
                answer: Box::new(answer),
                blocks,
                seen: Mutex::new(Vec::new()),
                cancelled: Mutex::new(Vec::new()),
            }))
        }

        fn seen(&self) -> std::sync::MutexGuard<'_, Vec<SeenRequest>> {
            self.seen.lock().unwrap()
        }
    }

    impl HttpTransport for FakeTransport {
        fn send(&self, request: &ExternalRequest<'_>) -> Result<ExternalAnswer, HttpError> {
            self.seen.lock().unwrap().push(SeenRequest {
                id: request.id,
                method: request.method,
                url: request.url.clone(),
                headers: request
                    .headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.as_str().to_owned()))
                    .collect(),
                body: request.body.map(<[u8]>::to_vec),
                timeout: request.timeout,
                pin: request.pin.clone(),
            });
            if self.blocks {
                let started = Instant::now();
                while !self.cancelled.lock().unwrap().contains(&request.id) {
                    if started.elapsed() > Duration::from_secs(10) {
                        return Err(HttpError::Protocol);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                return Err(HttpError::Broken);
            }
            (self.answer)()
        }

        fn cancel(&self, id: u64) {
            self.cancelled.lock().unwrap().push(id);
        }
    }

    type AnswerFn = Box<dyn Fn() -> Result<ExternalAnswer, HttpError> + Send + Sync>;

    fn boxed(
        answer: impl Fn() -> Result<ExternalAnswer, HttpError> + Send + Sync + 'static,
    ) -> AnswerFn {
        Box::new(answer)
    }

    fn external_answer(
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<ExternalAnswer, HttpError> {
        Ok(ExternalAnswer {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: Zeroizing::new(body.to_vec()),
        })
    }

    fn loopback() -> RelayUrl {
        RelayUrl::parse("http://127.0.0.1:8787").unwrap()
    }

    /// The external transport gets the method, the full URL, the headers with the
    /// bearer, the JSON body, and the timeout of a long poll; its answer reads as one
    /// from a socket.
    #[test]
    fn an_external_transport_carries_the_request_and_its_answer() {
        let transport = FakeTransport::leaked(false, || {
            external_answer(
                200,
                &[("ETag", " \"3\" "), ("Content-Type", "application/json")],
                b"{\"ok\":1}",
            )
        });
        let mut request = Request::new(
            "POST",
            "/v1/questions?since=2&wait=25".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        request.headers.push(("If-Match", "\"2\"".to_owned()));
        request.body = Body::Json(Zeroizing::new(b"{\"code\":\"synthetic\"}".to_vec()));
        request.wait = Duration::from_secs(25);
        let answer = exchange_external(transport, &loopback(), &request).unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(answer.header("etag"), Some("\"3\""));
        assert_eq!(answer.header("content-type"), Some("application/json"));
        assert_eq!(answer.body.as_slice(), b"{\"ok\":1}");
        let all = transport.seen();
        let [seen] = all.as_slice() else {
            panic!("one request");
        };
        assert!(seen.id > 0);
        assert_eq!(seen.method, "POST");
        assert_eq!(
            seen.url,
            "http://127.0.0.1:8787/v1/questions?since=2&wait=25"
        );
        let headers: Vec<(&str, &str)> = seen
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            headers,
            [
                ("Authorization", "Bearer apassy_acc_synthetic"),
                ("Content-Type", "application/json"),
                ("If-Match", "\"2\""),
                ("User-Agent", "apassy-sync/1"),
            ]
        );
        assert_eq!(seen.body.as_deref(), Some(&b"{\"code\":\"synthetic\"}"[..]));
        assert_eq!(seen.timeout, Duration::from_secs(25) + HEADER_TIMEOUT);
        drop(all);
        // A request without a body sends none; a deadline shortens the timeout.
        let mut request = Request::new("GET", "/v1/devices".to_owned(), None);
        request.deadline = Some(Instant::now() + Duration::from_secs(5));
        exchange_external(transport, &loopback(), &request).unwrap();
        let seen = transport.seen();
        let last = seen.last().unwrap();
        assert!(last.body.is_none());
        assert!(last.timeout <= Duration::from_secs(5), "{:?}", last.timeout);
        assert_eq!(
            last.headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["User-Agent"]
        );
        assert_ne!(last.id, seen[0].id);
    }

    /// The errors of the transport come back as they are; an answer that a socket answer
    /// would fail on fails the same way; a request that cannot go out never reaches the
    /// transport.
    #[test]
    fn an_external_answer_has_the_limits_of_a_socket_answer() {
        let request = Request::new("GET", "/v1/devices".to_owned(), None);
        for error in [HttpError::Connect, HttpError::Broken, HttpError::Protocol] {
            let transport = FakeTransport::leaked(false, move || Err(error));
            assert_eq!(
                exchange_external(transport, &loopback(), &request).unwrap_err(),
                error
            );
        }
        let large = vec![b'x'; MAX_JSON_ANSWER + 1];
        let fits = vec![b'x'; MAX_JSON_ANSWER];
        let long_value = "v".repeat(MAX_HEAD_BYTES);
        let refused: Vec<AnswerFn> = vec![
            boxed(|| external_answer(101, &[], b"")),
            boxed(|| external_answer(600, &[], b"")),
            boxed(|| external_answer(200, &[("X-Bad", "a\r\nSet: 1")], b"")),
            boxed(|| external_answer(200, &[("Bad Name", "1")], b"")),
            boxed(|| external_answer(200, &[("", "1")], b"")),
            boxed(move || external_answer(200, &[("X-Long", long_value.as_str())], b"")),
            boxed(move || external_answer(200, &[], &large)),
        ];
        for answer in refused {
            let transport = FakeTransport::leaked(false, answer);
            assert_eq!(
                exchange_external(transport, &loopback(), &request).unwrap_err(),
                HttpError::Protocol
            );
        }
        let transport = FakeTransport::leaked(false, move || external_answer(404, &[], &fits));
        let answer = exchange_external(transport, &loopback(), &request).unwrap();
        assert_eq!((answer.status, answer.body.len()), (404, MAX_JSON_ANSWER));
        // A file body, a bad path, a bad bearer, and a deadline that passed send nothing.
        let transport = FakeTransport::leaked(false, || external_answer(200, &[], b""));
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut upload = Request::new("PUT", "/v1/sync/snapshot".to_owned(), None);
        upload.body = Body::File(file.path(), 0);
        assert_eq!(
            exchange_external(transport, &loopback(), &upload).unwrap_err(),
            HttpError::Protocol
        );
        let bad_path = Request::new("GET", "v1/devices".to_owned(), None);
        assert_eq!(
            exchange_external(transport, &loopback(), &bad_path).unwrap_err(),
            HttpError::Protocol
        );
        let bad_bearer = Request::new("GET", "/v1/devices".to_owned(), Some("a b"));
        assert_eq!(
            exchange_external(transport, &loopback(), &bad_bearer).unwrap_err(),
            HttpError::Protocol
        );
        let mut late = Request::new("GET", "/v1/devices".to_owned(), None);
        late.deadline = Some(Instant::now());
        assert_eq!(
            exchange_external(transport, &loopback(), &late).unwrap_err(),
            HttpError::Connect
        );
        assert!(transport.seen().is_empty());
    }

    /// A close of the [`Cancel`] cancels an external request in flight through the
    /// transport, and a request after the close never reaches it.
    #[test]
    fn a_cancel_ends_an_external_request() {
        let transport = FakeTransport::leaked(true, || external_answer(200, &[], b""));
        let cancel = std::sync::Arc::new(Cancel::default());
        let poll = {
            let cancel = std::sync::Arc::clone(&cancel);
            std::thread::spawn(move || {
                let mut request = Request::new(
                    "GET",
                    "/v1/questions?since=1&wait=25".to_owned(),
                    Some("apassy_acc_synthetic"),
                );
                request.wait = Duration::from_secs(25);
                request.cancel = Some(&cancel);
                let started = Instant::now();
                let error = exchange_external(transport, &loopback(), &request).unwrap_err();
                let left = cancel.sockets.lock().unwrap().len();
                (error, started.elapsed(), left)
            })
        };
        let started = Instant::now();
        while transport.seen().is_empty() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        cancel.close();
        let (error, waited, left) = poll.join().unwrap();
        assert_eq!(error, HttpError::Broken);
        assert!(waited < Duration::from_secs(3), "{waited:?}");
        assert_eq!(left, 0, "the request leaves its cancel");
        let id = transport.seen()[0].id;
        assert_eq!(*transport.cancelled.lock().unwrap(), vec![id]);
        let mut request = Request::new("GET", "/v1/devices".to_owned(), None);
        request.cancel = Some(&cancel);
        assert_eq!(
            exchange_external(transport, &loopback(), &request).unwrap_err(),
            HttpError::Connect
        );
        assert_eq!(transport.seen().len(), 1);
    }

    /// Without an external transport (no test installs one), `exchange` and `download`
    /// use TCP.
    #[test]
    fn without_an_external_transport_requests_use_tcp() {
        assert!(external().is_none());
        let (url, server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let request = Request::new("GET", "/v1/devices".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap().body.as_slice(), b"{}");
        assert!(
            String::from_utf8(server.join().unwrap())
                .unwrap()
                .starts_with("GET /v1/devices HTTP/1.1\r\n")
        );
    }

    // ---- Pinned relays (contract node-pairing-v1 sections 3, 4, and 7). ----

    const CONTRACT_PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";

    fn contract_pin() -> TlsTrust {
        TlsTrust::Pinned(parse_pin(CONTRACT_PIN).unwrap())
    }

    /// A node certificate and a server that presents it.
    fn node_tls() -> (Arc<rustls::ServerConfig>, Pin) {
        let (config, der) =
            crate::broker::http::test_support::self_signed_tls(&[&rustls::version::TLS13]);
        (config, Pin::of_certificate(&der))
    }

    /// Serve one TLS connection with `config`: read the head and answer `{}`. Returns
    /// the plaintext that arrived, empty after a failed handshake.
    fn serve_tls_once(
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return seen,
                    Ok(read) => seen.extend_from_slice(&buf[..read]),
                }
            }
            let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(&mut tls.sock);
            seen
        })
    }

    /// Two different ports of this computer where nothing listens, while `live` holds
    /// its own.
    fn closed_ports(live: &TcpListener) -> [u16; 2] {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let ports = [port_of(&a), port_of(&b)];
        assert!(!ports.contains(&port_of(live)));
        ports
    }

    fn port_of(listener: &TcpListener) -> u16 {
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn a_pinned_address_is_https_with_a_port_and_its_alternatives_have_their_form() {
        let url = RelayUrl::parse_with_trust("https://100.64.0.7:8444", contract_pin())
            .unwrap()
            .alternatives(&[
                "apassy-mini.tail0123.ts.net".to_owned(),
                "[fd7a:115c:a1e0::7]:8444".to_owned(),
            ])
            .unwrap();
        assert_eq!(url.as_str(), "https://100.64.0.7:8444");
        assert_eq!(url.pin().unwrap().text(), CONTRACT_PIN);
        assert_eq!(url.trust().pin_text().as_deref(), Some(CONTRACT_PIN));
        assert_eq!(
            url.alternative_list(),
            [
                "apassy-mini.tail0123.ts.net:8444",
                "[fd7a:115c:a1e0::7]:8444"
            ]
        );
        assert_eq!(url.destinations().count(), 3);
        // The host header is the origin's, whatever destination connects.
        assert_eq!(url.host_header(), "100.64.0.7:8444");

        for bad in [
            "http://127.0.0.1:8444",
            "https://100.64.0.7",
            "https://100.64.0.7:443",
            "https://100.64.0.7:8444/v1",
        ] {
            assert_eq!(
                RelayUrl::parse_with_trust(bad, contract_pin()),
                Err(SyncError::InvalidRelayAddress),
                "{bad}"
            );
        }
        let pinned = || RelayUrl::parse_with_trust("https://100.64.0.7:8444", contract_pin());
        for list in [
            vec!["100.64.0.7:8444"],
            vec!["100.64.0.7"],
            vec!["a.example.com", "a.example.com:8444"],
            vec!["[FD7A:115C:A1E0::7]"],
            vec!["single"],
            vec!["a.example.com:08444"],
            vec!["a.example.com:0"],
            vec!["Upper.example.com"],
            vec![
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
                "e.example.com",
            ],
        ] {
            let list: Vec<String> = list.into_iter().map(str::to_owned).collect();
            assert_eq!(
                pinned().unwrap().alternatives(&list),
                Err(SyncError::InvalidRelayAddress),
                "{list:?}"
            );
        }
        // Alternatives need a pin, and a pinned address keeps them only while pinned.
        let hosted = RelayUrl::parse("https://relay.example.test:8443").unwrap();
        assert_eq!(hosted.trust(), TlsTrust::System);
        assert!(
            hosted
                .clone()
                .alternatives(&["b.example.com".to_owned()])
                .is_err()
        );
        assert_eq!(hosted.clone().alternatives(&[]).unwrap(), hosted);
        assert!(url.with_trust(TlsTrust::System).is_err());
        assert_eq!(TlsTrust::from_pin_text(None), Ok(TlsTrust::System));
        assert_eq!(
            TlsTrust::from_pin_text(Some(CONTRACT_PIN)),
            Ok(contract_pin())
        );
        assert_eq!(
            TlsTrust::from_pin_text(Some(&CONTRACT_PIN[..42])),
            Err(SyncError::InvalidRelayAddress)
        );
    }

    #[test]
    fn a_pinned_request_reaches_the_pinned_relay_and_refuses_another_certificate() {
        let (config, pin) = node_tls();
        for (trust, refused) in [(TlsTrust::Pinned(pin), false), (contract_pin(), true)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = RelayUrl::parse_with_trust(
                &format!("https://127.0.0.1:{}", port_of(&listener)),
                trust,
            )
            .unwrap();
            let server = serve_tls_once(listener, Arc::clone(&config));
            let request = Request::new(
                "POST",
                "/v1/auth/token".to_owned(),
                Some("apassy_acc_synthetic"),
            );
            let result = exchange(&url, &request);
            let seen = server.join().unwrap();
            if refused {
                assert_eq!(result.unwrap_err(), HttpError::PinMismatch);
                assert!(seen.is_empty(), "no request byte before the pin check");
            } else {
                assert_eq!(result.unwrap().body.as_slice(), b"{}");
                let head = String::from_utf8(seen).unwrap();
                assert!(
                    head.starts_with("POST /v1/auth/token HTTP/1.1\r\n"),
                    "{head}"
                );
                assert!(head.contains(&format!("Host: {}\r\n", url.host_header())));
            }
        }
    }

    #[test]
    fn a_hosted_address_never_takes_a_self_signed_node_certificate() {
        // System trust as before: the node certificate is not in any trust store.
        let (config, _) = node_tls();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!("https://127.0.0.1:{}", port_of(&listener))).unwrap();
        let server = serve_tls_once(listener, config);
        let request = Request::new("GET", "/healthz".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
        assert!(server.join().unwrap().is_empty());
    }

    #[test]
    fn the_next_destination_is_tried_after_a_refused_connection_and_the_origin_stays() {
        let (config, pin) = node_tls();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, also_closed] = closed_ports(&listener);
        let origin = format!("https://127.0.0.1:{closed}");
        let url = RelayUrl::parse_with_trust(&origin, TlsTrust::Pinned(pin))
            .unwrap()
            .alternatives(&[
                format!("127.0.0.1:{also_closed}"),
                format!("127.0.0.1:{}", port_of(&listener)),
            ])
            .unwrap();
        let server = serve_tls_once(listener, config);
        let request = Request::new("GET", "/healthz".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap().body.as_slice(), b"{}");
        let head = String::from_utf8(server.join().unwrap()).unwrap();
        // The third destination answered with the origin's Host: the origin stays the
        // value that the app signs and stores.
        let host = origin.strip_prefix("https://").unwrap();
        assert!(head.contains(&format!("Host: {host}\r\n")), "{head}");
        assert_eq!(url.as_str(), origin);
    }

    #[test]
    fn a_pin_mismatch_stops_before_the_next_destination() {
        let (wrong, _) = node_tls();
        let (_, pin) = node_tls();
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse_with_trust(
            &format!("https://127.0.0.1:{}", port_of(&first)),
            TlsTrust::Pinned(pin),
        )
        .unwrap()
        .alternatives(&[format!("127.0.0.1:{}", port_of(&second))])
        .unwrap();
        let server = serve_tls_once(first, wrong);
        let request = Request::new("GET", "/healthz".to_owned(), Some("apassy_acc_synthetic"));
        assert_eq!(
            exchange(&url, &request).unwrap_err(),
            HttpError::PinMismatch
        );
        assert!(server.join().unwrap().is_empty());
        second.set_nonblocking(true).unwrap();
        assert_eq!(
            second.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no connection to the alternative after a wrong certificate"
        );
    }

    #[test]
    fn a_local_route_connects_plain_to_the_node_and_names_the_node_origin() {
        let (plain, server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let port: u16 = plain.as_str().rsplit(':').next().unwrap().parse().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        // A synthetic node origin that no other test uses (the route table is of the
        // process). Nothing connects to it: the route goes to the loopback server.
        let origin = "https://100.64.0.77:8444";
        let url = RelayUrl::parse_with_trust(origin, contract_pin()).unwrap();
        assert_eq!(local_route(&url), None);
        set_local_route(origin, addr).unwrap();
        assert_eq!(local_route(&url), Some(addr));
        let request = Request::new(
            "GET",
            "/v1/questions".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        assert_eq!(exchange(&url, &request).unwrap().body.as_slice(), b"{}");
        let head = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(
            head.starts_with("GET /v1/questions HTTP/1.1\r\nHost: 100.64.0.77:8444\r\n"),
            "{head}"
        );
        clear_local_route(origin);
        assert_eq!(local_route(&url), None);
        // Only a loopback address is a local route.
        assert_eq!(
            set_local_route(origin, SocketAddr::from(([100, 64, 0, 77], 8444))),
            Err(SyncError::InvalidRelayAddress)
        );
        assert_eq!(
            set_local_route("not an origin", addr),
            Err(SyncError::InvalidRelayAddress)
        );
    }

    /// The watch (unit N6): a pinned request goes through the external transport with
    /// its pin and the origin (no alternative), a hosted one without a pin, and a pin
    /// mismatch of the host stays a pin mismatch.
    #[test]
    fn a_pinned_request_carries_its_pin_through_the_external_transport() {
        let transport = FakeTransport::leaked(false, || external_answer(200, &[], b"{}"));
        let url = RelayUrl::parse_with_trust("https://100.64.0.7:8444", contract_pin())
            .unwrap()
            .alternatives(&["apassy-mini.tail0123.ts.net:8444".to_owned()])
            .unwrap();
        let request = Request::new(
            "GET",
            "/v1/questions".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        exchange_external(transport, &url, &request).unwrap();
        {
            let seen = transport.seen();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].url, "https://100.64.0.7:8444/v1/questions");
            assert_eq!(seen[0].pin.as_deref(), Some(CONTRACT_PIN));
        }
        // A hosted address goes through it without a pin.
        exchange_external(transport, &loopback(), &request).unwrap();
        assert_eq!(transport.seen().len(), 2);
        assert_eq!(transport.seen()[1].pin, None);

        let refusing = FakeTransport::leaked(false, || Err(HttpError::PinMismatch));
        assert_eq!(
            exchange_external(refusing, &url, &request).unwrap_err(),
            HttpError::PinMismatch
        );
        assert_eq!(
            refusing.seen().len(),
            1,
            "no alternative after a wrong certificate"
        );
    }

    // ---- The Connect route (node-pairing-v1 section 7a, plan s7 unit I2). ----

    const ROUTE: &str = "wss://apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3ca";

    #[test]
    fn a_connect_route_has_one_form_and_is_the_last_alternative() {
        let route = TunnelRoute::parse(ROUTE).unwrap();
        assert_eq!(route.text(), ROUTE);
        assert_eq!(route.node(), "node_k7m2q4x3ca");
        assert_eq!(route.connect_host(), "apassy-relay.wyderka.cc");
        assert_eq!(route.dial_path(), "/v1/tunnel/dial/node_k7m2q4x3ca");
        assert!(route.is_through("https://apassy-relay.wyderka.cc"));
        assert!(!route.is_through("https://apassy-relay.wyderka.cc:8443"));
        assert!(!route.is_through("https://connect.example.com"));
        assert_eq!(
            TunnelRoute::new("https://apassy-relay.wyderka.cc", "node_k7m2q4x3ca").unwrap(),
            route
        );
        // A loopback Connect of the tests: its host and port.
        let local = TunnelRoute::new("http://127.0.0.1:8787", "node_k7m2q4x3ca").unwrap();
        assert_eq!(
            local.text(),
            "wss://127.0.0.1:8787/v1/tunnel/dial/node_k7m2q4x3ca"
        );
        assert!(local.is_through("http://127.0.0.1:8787"));
        for bad in [
            "ws://apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3ca",
            "wss://apassy-relay.wyderka.cc:443/v1/tunnel/dial/node_k7m2q4x3ca",
            "wss://Apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3ca",
            "wss://apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3ca/",
            "wss://apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3c",
            "wss://apassy-relay.wyderka.cc/x/v1/tunnel/dial/node_k7m2q4x3ca",
            "wss://u@apassy-relay.wyderka.cc/v1/tunnel/dial/node_k7m2q4x3ca",
        ] {
            assert!(TunnelRoute::parse(bad).is_none(), "{bad}");
        }
        assert!(TunnelRoute::new("https://apassy-relay.wyderka.cc", "node_1").is_err());

        // The stored form: the tailnet alternatives, then the route.
        let url = RelayUrl::parse_with_trust("https://100.64.0.7:8444", contract_pin())
            .unwrap()
            .alternatives(&["apassy-mini.tail0123.ts.net".to_owned(), ROUTE.to_owned()])
            .unwrap();
        assert_eq!(url.tunnel(), Some(&route));
        assert_eq!(
            url.alternative_list(),
            ["apassy-mini.tail0123.ts.net:8444", ROUTE]
        );
        assert_eq!(url.destinations().count(), 2, "the route is no destination");
        let back = RelayUrl::parse_with_trust("https://100.64.0.7:8444", contract_pin())
            .unwrap()
            .alternatives(&url.alternative_list())
            .unwrap();
        assert_eq!(back, url);
        assert!(back.clone().alternatives(&[]).unwrap().tunnel().is_none());
        // One route, four entries in all, and a pin.
        let pinned = RelayUrl::parse_with_trust("https://100.64.0.7:8444", contract_pin()).unwrap();
        for bad in [
            vec![ROUTE.to_owned(), ROUTE.to_owned()],
            vec![
                "a.example.com".to_owned(),
                "b.example.com".to_owned(),
                "c.example.com".to_owned(),
                "d.example.com".to_owned(),
                ROUTE.to_owned(),
            ],
            vec!["wss://apassy-relay.wyderka.cc/v1/tunnel/node".to_owned()],
        ] {
            assert_eq!(
                pinned.clone().alternatives(&bad),
                Err(SyncError::InvalidRelayAddress),
                "{bad:?}"
            );
        }
        let hosted = RelayUrl::parse("https://apassy-relay.wyderka.cc").unwrap();
        assert!(hosted.clone().with_tunnel(Some(route.clone())).is_err());
        assert!(hosted.with_tunnel(None).is_ok());
        assert!(url.with_trust(TlsTrust::System).is_err());
    }

    /// A pipe over a TCP connection, for the dial of the tests.
    struct TcpPipe(TcpStream);

    impl Read for TcpPipe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.0.read(out)
        }
    }

    impl Write for TcpPipe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl TunnelPipe for TcpPipe {
        fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
            self.0.set_read_timeout(Some(timeout))
        }
        fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
            self.0.set_write_timeout(Some(timeout))
        }
        fn closer(&self) -> Arc<dyn Fn() + Send + Sync> {
            let socket = self.0.try_clone().unwrap();
            Arc::new(move || {
                let _ = socket.shutdown(Shutdown::Both);
            })
        }
        /// Open with nothing to read: a peek that does not block finds no byte and no end.
        fn is_idle_open(&self) -> bool {
            if self.0.set_nonblocking(true).is_err() {
                return false;
            }
            let mut byte = [0u8; 1];
            let idle = matches!(
                self.0.peek(&mut byte),
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
            );
            self.0.set_nonblocking(false).is_ok() && idle
        }
    }

    /// A dialer that connects its dials to `to` and writes down what the client did.
    struct FakeDialer {
        to: Mutex<Option<SocketAddr>>,
        direct_first: AtomicBool,
        events: Mutex<Vec<String>>,
        kept: Option<KeptDials>,
    }

    impl FakeDialer {
        fn new(to: Option<SocketAddr>, direct_first: bool) -> Arc<Self> {
            Arc::new(Self {
                to: Mutex::new(to),
                direct_first: AtomicBool::new(direct_first),
                events: Mutex::new(Vec::new()),
                kept: None,
            })
        }

        /// A dialer of the tailnet-down state that keeps its connections, as the iPhone's.
        fn keeping(to: SocketAddr) -> Arc<Self> {
            Arc::new(Self {
                to: Mutex::new(Some(to)),
                direct_first: AtomicBool::new(false),
                events: Mutex::new(Vec::new()),
                kept: Some(KeptDials::new()),
            })
        }

        fn dials(&self) -> usize {
            self.events()
                .iter()
                .filter(|event| event.starts_with("dial "))
                .count()
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    impl TunnelDialer for FakeDialer {
        fn direct_first(&self, _url: &RelayUrl) -> bool {
            self.direct_first.load(Ordering::SeqCst)
        }
        fn reached(&self, _url: &RelayUrl, route: NodeRoute) {
            self.events
                .lock()
                .unwrap()
                .push(format!("reached {route:?}"));
        }
        fn direct_failed(&self, _url: &RelayUrl) {
            self.events.lock().unwrap().push("direct failed".to_owned());
        }
        fn kept(&self) -> Option<KeptDials> {
            self.kept.clone()
        }
        fn dial(
            &self,
            route: &TunnelRoute,
            _deadline: Instant,
        ) -> Result<Box<dyn TunnelPipe>, HttpError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("dial {}", route.node()));
            let to = (*self.to.lock().unwrap()).ok_or(HttpError::Connect)?;
            let tcp = TcpStream::connect(to).map_err(|_| HttpError::Connect)?;
            Ok(Box::new(TcpPipe(tcp)))
        }
    }

    /// A pinned address at a closed port with the Connect route and `dialer`.
    fn routed(origin_port: u16, pin: Pin, dialer: Arc<FakeDialer>) -> RelayUrl {
        RelayUrl::parse_with_trust(
            &format!("https://127.0.0.1:{origin_port}"),
            TlsTrust::Pinned(pin),
        )
        .unwrap()
        .alternatives(&[ROUTE.to_owned()])
        .unwrap()
        .with_dialer(dialer)
    }

    #[test]
    fn a_closed_tailnet_goes_through_the_dial_with_the_same_pinned_tls_and_bytes() {
        let (config, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::new(Some(node.local_addr().unwrap()), true);
        let url = routed(closed, pin, Arc::clone(&dialer));
        let server = serve_tls_once(node, config.clone());
        let request = Request::new(
            "POST",
            "/v1/questions/abc/answers".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        assert_eq!(exchange(&url, &request).unwrap().body.as_slice(), b"{}");
        let through_dial = server.join().unwrap();
        assert_eq!(
            dialer.events(),
            ["direct failed", "dial node_k7m2q4x3ca", "reached Tunnel"]
        );
        // The bytes inside the pinned TLS of the dial are those of the tailnet route.
        let direct_node = TcpListener::bind("127.0.0.1:0").unwrap();
        let direct = RelayUrl::parse_with_trust(
            &format!("https://127.0.0.1:{closed}"),
            TlsTrust::Pinned(pin),
        )
        .unwrap()
        .alternatives(&[format!("127.0.0.1:{}", port_of(&direct_node))])
        .unwrap();
        let server = serve_tls_once(direct_node, config);
        assert_eq!(exchange(&direct, &request).unwrap().body.as_slice(), b"{}");
        assert_eq!(server.join().unwrap(), through_dial);
        let head = String::from_utf8(through_dial).unwrap();
        assert!(head.starts_with("POST /v1/questions/abc/answers HTTP/1.1\r\n"));
        assert!(head.contains(&format!("Host: 127.0.0.1:{closed}\r\n")));
    }

    #[test]
    fn a_wrong_certificate_through_the_dial_stops_before_any_request_byte() {
        let (wrong, _) = node_tls();
        let (_, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::new(Some(node.local_addr().unwrap()), true);
        let url = routed(closed, pin, Arc::clone(&dialer));
        let server = serve_tls_once(node, wrong);
        let request = Request::new(
            "GET",
            "/v1/questions".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        assert_eq!(
            exchange(&url, &request).unwrap_err(),
            HttpError::PinMismatch
        );
        assert!(server.join().unwrap().is_empty(), "no request byte");
        assert!(
            !dialer
                .events()
                .iter()
                .any(|event| event.starts_with("reached"))
        );
    }

    #[test]
    fn the_dialer_puts_the_dial_first_and_the_tailnet_is_the_last_resort() {
        let (config, pin) = node_tls();
        // The dial does not connect; the tailnet does.
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let dialer = FakeDialer::new(None, false);
        let url = routed(port_of(&node), pin, Arc::clone(&dialer));
        let server = serve_tls_once(node, config.clone());
        let request = Request::new("GET", "/healthz".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap().body.as_slice(), b"{}");
        server.join().unwrap();
        assert_eq!(dialer.events(), ["dial node_k7m2q4x3ca", "reached Direct"]);

        // A tailnet that works comes first and never dials.
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let dialer = FakeDialer::new(None, true);
        let url = routed(port_of(&node), pin, Arc::clone(&dialer));
        let server = serve_tls_once(node, config);
        assert_eq!(exchange(&url, &request).unwrap().body.as_slice(), b"{}");
        server.join().unwrap();
        assert_eq!(dialer.events(), ["reached Direct"]);
    }

    #[test]
    fn without_a_dialer_the_route_is_kept_and_never_dialled() {
        let (_, pin) = node_tls();
        let live = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&live);
        let url = RelayUrl::parse_with_trust(
            &format!("https://127.0.0.1:{closed}"),
            TlsTrust::Pinned(pin),
        )
        .unwrap()
        .alternatives(&[ROUTE.to_owned()])
        .unwrap();
        let request = Request::new("GET", "/healthz".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
        // A probe of the direct route needs no request and no token.
        assert_eq!(
            probe_direct(&url, Duration::from_secs(2)).unwrap_err(),
            HttpError::Connect
        );
    }

    #[test]
    fn a_cancel_ends_a_long_poll_through_the_dial() {
        let (config, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::new(Some(node.local_addr().unwrap()), true);
        let url = routed(closed, pin, dialer);
        // The node finishes the handshake and never answers.
        let server = std::thread::spawn(move || {
            let (tcp, _) = node.accept().unwrap();
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 1024];
            while tls.read(&mut buf).is_ok_and(|read| read > 0) {}
        });
        let cancel = Arc::new(Cancel::default());
        let closer = {
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                cancel.close();
            })
        };
        let mut request = Request::new("GET", "/v1/questions?wait=25".to_owned(), None);
        request.wait = Duration::from_secs(25);
        request.cancel = Some(&cancel);
        let started = Instant::now();
        assert!(exchange(&url, &request).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the cancel ended the dial"
        );
        closer.join().unwrap();
        server.join().unwrap();
    }

    /// What a node that keeps its connections does with the `n`-th request (from 1) of a
    /// connection.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Turn {
        /// Answer `{}` and keep the connection (close after a request that asks for it).
        Answer,
        /// Read the request and close the connection without a byte: a kept connection
        /// that turns out dead.
        Drop,
        /// Answer `{}` without `Connection: close`, then close: an idle limit that
        /// passed while the client kept the connection.
        AnswerAndClose,
    }

    /// The requests of each connection of a [`keeping_node`].
    type Connections = Arc<Mutex<Vec<Vec<Vec<u8>>>>>;

    /// A node behind the dial that serves sequential requests on one TLS connection, as
    /// the tailnet listener does for a stream of the tunnel. `turn(n)` says what it does
    /// with the `n`-th request of each connection.
    fn keeping_node(
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
        turn: fn(usize) -> Turn,
    ) -> Connections {
        let connections: Connections = Arc::default();
        let log = Arc::clone(&connections);
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { return };
                let config = Arc::clone(&config);
                let index = {
                    let mut log = log.lock().unwrap();
                    log.push(Vec::new());
                    log.len() - 1
                };
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    let conn = rustls::ServerConnection::new(config).unwrap();
                    let mut tls = StreamOwned::new(conn, tcp);
                    let mut pending = Vec::new();
                    let mut buf = [0u8; 4096];
                    for n in 1.. {
                        let end = loop {
                            if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                                break end + 4;
                            }
                            match tls.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(read) => pending.extend_from_slice(&buf[..read]),
                            }
                        };
                        let head = String::from_utf8_lossy(&pending[..end]).to_ascii_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .map_or(0, |value| value.trim().parse().unwrap());
                        while pending.len() < end + length {
                            match tls.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(read) => pending.extend_from_slice(&buf[..read]),
                            }
                        }
                        let request: Vec<u8> = pending.drain(..end + length).collect();
                        log.lock().unwrap()[index].push(request);
                        let turn = turn(n);
                        if turn == Turn::Drop {
                            let _ = tls.sock.shutdown(Shutdown::Both);
                            return;
                        }
                        let close = head.contains("connection: close");
                        let answer: &[u8] = if close {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                        } else {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                        };
                        if tls.write_all(answer).and_then(|()| tls.flush()).is_err() {
                            return;
                        }
                        if close || turn == Turn::AnswerAndClose {
                            tls.conn.send_close_notify();
                            let _ = tls.conn.complete_io(&mut tls.sock);
                            let _ = tls.sock.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                });
            }
        });
        connections
    }

    fn requests_of(connections: &Connections) -> Vec<Vec<String>> {
        connections
            .lock()
            .unwrap()
            .iter()
            .map(|requests| {
                requests
                    .iter()
                    .map(|bytes| String::from_utf8(bytes.clone()).unwrap())
                    .collect()
            })
            .collect()
    }

    fn json_post(path: &str) -> Request<'static> {
        let mut request = Request::new("POST", path.to_owned(), Some("apassy_acc_synthetic"));
        request.body = Body::Json(Zeroizing::new(b"{\"v\":1}".to_vec()));
        request
    }

    #[test]
    fn requests_that_follow_each_other_share_one_dial_and_a_long_poll_has_its_own() {
        let (config, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::keeping(node.local_addr().unwrap());
        let url = routed(closed, pin, Arc::clone(&dialer));
        let connections = keeping_node(node, config, |_| Turn::Answer);
        let get = Request::new("GET", "/v1/feed".to_owned(), Some("apassy_acc_synthetic"));
        for _ in 0..5 {
            assert_eq!(exchange(&url, &get).unwrap().body.as_slice(), b"{}");
        }
        assert_eq!(
            exchange(&url, &json_post("/v1/questions/abc/answers"))
                .unwrap()
                .status,
            200
        );
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(dialer.dials(), 1, "{:?}", dialer.events());
        let seen = requests_of(&connections);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].len(), 7);
        for request in &seen[0] {
            assert!(!request.contains("Connection: close"), "{request}");
            assert!(
                request.contains("User-Agent: apassy-sync/1\r\n"),
                "{request}"
            );
        }
        // The head of a kept request is the head of the same request on a connection that
        // closes, without the line `Connection: close`, and nothing else.
        let closing = request_head(&url, &get, true).unwrap();
        let open = request_head(&url, &get, false).unwrap();
        assert_eq!(
            String::from_utf8(closing.to_vec())
                .unwrap()
                .replace("Connection: close\r\n", ""),
            String::from_utf8(open.to_vec()).unwrap()
        );
        assert_eq!(seen[0][0].as_bytes(), open.as_slice());
        // A long poll dials for itself, asks to close, and is not kept.
        let mut poll = Request::new("GET", "/v1/questions?wait=1".to_owned(), None);
        poll.wait = Duration::from_secs(1);
        assert_eq!(exchange(&url, &poll).unwrap().status, 200);
        assert_eq!(dialer.dials(), 2);
        let seen = requests_of(&connections);
        assert_eq!(seen.len(), 2);
        assert!(
            seen[1][0].contains("Connection: close\r\n"),
            "{}",
            seen[1][0]
        );
        // The kept dial is still there for the next request.
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(dialer.dials(), 2);
        assert_eq!(requests_of(&connections)[0].len(), 8);
        assert_eq!(dialer.kept.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn a_dead_kept_dial_sends_a_read_again_once_and_never_a_post() {
        let (config, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::keeping(node.local_addr().unwrap());
        let url = routed(closed, pin, Arc::clone(&dialer));
        // Every second request of a connection meets a dead connection.
        let connections =
            keeping_node(
                node,
                config,
                |n| {
                    if n == 2 { Turn::Drop } else { Turn::Answer }
                },
            );
        let get = Request::new("GET", "/v1/feed".to_owned(), Some("apassy_acc_synthetic"));
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(dialer.dials(), 1);
        // The kept dial is dead after the read went out: the read goes once more on a
        // fresh dial.
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(dialer.dials(), 2);
        // The POST meets the same on the second dial: it may have reached the node, so
        // it fails and is not sent again.
        let post = json_post("/v1/questions/abc/answers");
        assert_eq!(exchange(&url, &post).unwrap_err(), HttpError::Broken);
        assert_eq!(dialer.dials(), 2, "no dial for the POST");
        let seen = requests_of(&connections);
        let posts = seen
            .iter()
            .flatten()
            .filter(|request| request.starts_with("POST "))
            .count();
        assert_eq!(posts, 1, "the POST went out once: {seen:?}");
        assert_eq!(seen.len(), 2);
        assert!(dialer.kept.as_ref().unwrap().is_empty());
    }

    #[test]
    fn a_kept_dial_that_the_node_closed_is_not_used() {
        let (config, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::keeping(node.local_addr().unwrap());
        let url = routed(closed, pin, Arc::clone(&dialer));
        let connections = keeping_node(node, config, |_| Turn::AnswerAndClose);
        let get = Request::new("GET", "/v1/feed".to_owned(), Some("apassy_acc_synthetic"));
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        std::thread::sleep(Duration::from_millis(200));
        // The node closed the kept connection while it waited: a POST takes a fresh dial
        // before any byte, so it goes out once and succeeds.
        let post = json_post("/v1/questions/abc/answers");
        assert_eq!(exchange(&url, &post).unwrap().status, 200);
        assert_eq!(dialer.dials(), 2);
        let seen = requests_of(&connections);
        assert_eq!(seen.iter().map(Vec::len).collect::<Vec<_>>(), [1, 1]);
    }

    #[test]
    fn a_clear_and_the_idle_limit_close_the_kept_dials() {
        let (config, pin) = node_tls();
        let node = TcpListener::bind("127.0.0.1:0").unwrap();
        let [closed, _] = closed_ports(&node);
        let dialer = FakeDialer::keeping(node.local_addr().unwrap());
        let kept = dialer.kept.clone().unwrap();
        let url = routed(closed, pin, Arc::clone(&dialer));
        let _connections = keeping_node(node, config, |_| Turn::Answer);
        let get = Request::new("GET", "/v1/feed".to_owned(), Some("apassy_acc_synthetic"));
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(kept.len(), 1);
        // A lock: the kept dial closes, and the next request dials again.
        kept.clear();
        assert!(kept.is_empty());
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(dialer.dials(), 2);
        // Without a request for the idle time, the kept dial closes by itself.
        kept.set_idle(Duration::from_millis(200));
        let until = Instant::now() + Duration::from_secs(5);
        while !kept.is_empty() {
            assert!(Instant::now() < until, "the idle dial closed");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(exchange(&url, &get).unwrap().status, 200);
        assert_eq!(dialer.dials(), 3);
        // A request that started before a clear does not keep its connection.
        let slot = keep_slot(&url, &get).unwrap();
        kept.clear();
        assert_ne!(slot.epoch, kept.epoch());
    }
}
