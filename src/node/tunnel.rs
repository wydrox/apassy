//! The node's side of the Connect tunnel (ADR 0037 stage 7, plan s7 unit M4; contract
//! docs/contracts/connect-tunnel-v1.md).
//!
//! The node keeps one outbound WebSocket to Connect, `GET /v1/tunnel/node` with the
//! account token and the subprotocol `apassy-tunnel-v1` (contract 3.2), over the
//! platform TLS client (`TlsClient::platform`; plain HTTP on the loopback in tests).
//! Each binary message is one frame of the mux (contract 4); Connect opens streams, the
//! node never does. Each stream is handed to the TLS front as an accepted connection of
//! its kind ([`crate::net::tls_front::serve_connection`]):
//!
//! - `device` (a dial of a device of the account): TLS with the pinned node certificate,
//!   then the relay's tailnet listener (the device routes), as on the tailnet.
//! - `public` (a cloud agent through the SNI ingress): TLS with the public certificate of
//!   `<node>.node.<zone>` (`super::public_cert`), then the relay's public listener
//!   (`Scope::Public`: `/mcp`, `/p/`, the MCP authorization flow).
//! - `acme` (plain HTTP from the ingress on port 80): the node answers only the
//!   HTTP-01 token of its own pending order (`super::acme::Challenges`) and nothing else.
//!
//! So TLS ends on this Mac and Connect sees TLS records only.
//!
//! The wire code is the relay crate's own: the frame codec and the stream rules
//! ([`frame`]) and the RFC 6455 WebSocket ([`ws`]) are compiled here from the relay's
//! source files (`crates/apassy-relay/src/server/tunnel/{frame,ws}.rs`), because this
//! crate cannot depend on the relay crate (the relay depends on it). One codec, two
//! builds.
//!
//! The connection lives on the tunnel's thread ([`Tunnel::start`]): it signs in (the
//! account seam [`TunnelAuth`]), registers the node with its pin (`POST
//! /v1/tunnel/nodes`, contract 3.1), opens the WebSocket, and reads frames until the
//! WebSocket ends. A ping thread pings every [`PING_INTERVAL`] and ends a WebSocket that
//! is silent for [`IDLE_LIMIT`]. After an end or a refusal it tries again with backoff:
//! 1 s, doubling, at most 60 s ([`Backoff`]), each wait a random time between half and
//! all of it ([`jitter`]); the backoff starts again only after a WebSocket that stayed
//! open for [`STABLE_LINK`]. A WebSocket that Connect replaced (another process of this
//! node, close 4005) waits [`REPLACED_WAIT`]; a tunnel limit or byte budget of the account
//! (close 4002, `429 tunnel_limit`, `403 account_limit`) waits [`LIMIT_WAIT`]; an account
//! without the tunnel waits [`NOT_ON_CONNECT_WAIT`]. Any other refusal, the edge's `429
//! rate_limited` too (a limit of the address, shared with other clients behind it), takes
//! the next step of the backoff. An end of the WebSocket resets every
//! open stream: the front ends its connections to the relay, so no stream survives.
//! [`TunnelHandle::stop`] (a lock, a quit, a node stop) closes the WebSocket with 1000,
//! ends every stream at once, and joins its threads (at most [`STOP_WAIT`] for one inside
//! a request with its own deadline).
//!
//! A stream ends on the node in one of two ways, and the node forgets it at once either
//! way: the front's connection ended cleanly (`Conn::finish`: the node's `close` follows
//! its last bytes, and Connect ends the stream after them), or it ended otherwise
//! (`shutdown(Both)`: a `reset`). The node never keeps a stream whose own side is closed,
//! so it has no half-closed stream to time out (Connect keeps the close grace of its
//! clients, contract 4).
//!
//! Each direction of a stream has a window (contract 4): the node sends the front's
//! bytes only within the window that Connect granted (a write waits for more, up to the
//! front's write timeout), and it grants Connect more as the front reads, so at most
//! [`STREAM_BUFFER`] bytes wait toward the front for one stream. Connect sending over
//! the window breaks the stream rule `over_window`, and the node resets the stream.
//!
//! Limits of the node: at most [`MAX_DEVICE_STREAMS`] open `device` streams,
//! [`MAX_PUBLIC_STREAMS`] `public` streams, and [`MAX_ACME_STREAMS`] `acme` streams, each
//! kind in slots of its own as at Connect (contract 8; a stream over them is reset), the
//! window of each stream, and the front's own limits for each connection.
//!
//! No stream content is logged. The account token stays in the account seam: it goes
//! only into the `Authorization` header of the requests to the Connect origin.

#[path = "../../crates/apassy-relay/src/server/tunnel/frame.rs"]
pub mod frame;
#[path = "../../crates/apassy-relay/src/server/tunnel/ws.rs"]
pub mod ws;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use self::frame::{Applied, CLOSE, Dir, Kind, OPEN, RESET, Sequencer, WINDOW};
use self::ws::{Message, client, close};
use super::acme::{self, AcmeOptions, Challenges};
use super::public_cert::{self, CertPicker};
use crate::broker::http::{DestinationUrl, TlsClient, parse_destination};
use crate::connect::{AccountSession, ConnectClient, ConnectError, Feature};
use crate::net::certificate::NodeCertificate;
use crate::net::sealed_key::SealKey;
use crate::net::tls_front::{self, Conn, FrontLimits};

/// The path of the node's WebSocket (contract 3.2).
pub const NODE_PATH: &str = "/v1/tunnel/node";
/// The node pings this often (contract 3.2: 30 s).
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
/// A WebSocket with no message or pong for this long ends (contract 3.2: 90 s).
pub const IDLE_LIMIT: Duration = Duration::from_secs(90);
/// The first wait before a new try (contract 3.2: 1 s, doubling).
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);
/// The longest wait before a new try (contract 3.2: at most 60 s).
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// The wait after Connect said the account has no plan with the tunnel.
pub const NOT_ON_CONNECT_WAIT: Duration = Duration::from_secs(15 * 60);
/// The wait after Connect replaced this WebSocket with another one of this node (close
/// 4005: another process with this node's account device).
pub const REPLACED_WAIT: Duration = Duration::from_secs(5 * 60);
/// The wait after a tunnel limit or the byte budget of the account (close 4002, `429
/// tunnel_limit`, `403 account_limit`). Not after the edge's `429 rate_limited`: the
/// backoff.
pub const LIMIT_WAIT: Duration = Duration::from_secs(15 * 60);
/// A WebSocket that stayed open this long starts the backoff again at 1 s.
pub const STABLE_LINK: Duration = Duration::from_secs(60);
/// Bytes buffered toward the front for one stream (contract 4: 256 KiB): the window that
/// the node grants Connect for each stream.
pub const STREAM_BUFFER: usize = 256 * 1024;
/// Open `device` streams of this node at once (the dial slots of contract 8).
pub const MAX_DEVICE_STREAMS: usize = 64;
/// Open `public` streams of this node at once (the public slots of contract 8).
pub const MAX_PUBLIC_STREAMS: usize = 16;
/// Open `acme` streams of this node at once: slots of their own, as at Connect (contract
/// 8), so open `public` streams never keep the certificate renewal out.
pub const MAX_ACME_STREAMS: usize = 4;
/// Open streams of this node at once.
pub const MAX_STREAMS: usize = MAX_DEVICE_STREAMS + MAX_PUBLIC_STREAMS + MAX_ACME_STREAMS;
/// The zone of the public names when `APASSY_CONNECT_NODE_ZONE` is not set (contract 2).
pub const DEFAULT_NODE_ZONE: &str = "node.apassy.wyderka.cc";
/// The setting of the zone of the public names (a sandbox Connect).
pub const NODE_ZONE_ENV: &str = "APASSY_CONNECT_NODE_ZONE";
/// The connection, the TLS handshake, and the WebSocket handshake end within this.
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
/// The longest ACME request head (contract 7.2: 8 KiB).
const ACME_HEAD_LIMIT: usize = 8 * 1024;
/// An ACME request is read within this.
const ACME_READ: Duration = Duration::from_secs(5);
/// One read from the socket.
const CHUNK: usize = 16 * 1024;
/// The file with the last registration of this node (no secret: ids, the public name,
/// and the pin), in the Connect directory of the node.
const NODE_FILE: &str = "node.json";
/// A small wait step of the threads that look at the stop flag.
const STEP: Duration = Duration::from_millis(25);
/// How long a stop waits for the threads of the tunnel.
pub const STOP_WAIT: Duration = Duration::from_secs(2);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// The clock of the backoff.

/// The time source of the waits between tries. The product uses [`SystemClock`]; tests
/// move time by hand, so "reconnects within 30 s" is checked without waiting 30 s.
pub trait Clock: Send + Sync {
    /// The time since an arbitrary start.
    fn now(&self) -> Duration;
    /// Wait `duration`, or less when `stop` turns true. True when the whole wait passed.
    fn wait(&self, duration: Duration, stop: &AtomicBool) -> bool;
}

/// The system clock.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn wait(&self, duration: Duration, stop: &AtomicBool) -> bool {
        let until = Instant::now() + duration;
        loop {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            thread::sleep(left.min(STEP));
        }
    }
}

/// The waits between tries: 1 s, doubling, at most 60 s (contract 3.2). A WebSocket that
/// stayed open for [`STABLE_LINK`] resets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next: BACKOFF_FIRST,
        }
    }
}

impl Backoff {
    /// The wait before the next try; the one after it is twice as long, up to the cap.
    pub fn next_wait(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next * 2).min(BACKOFF_MAX);
        wait
    }

    pub fn reset(&mut self) {
        self.next = BACKOFF_FIRST;
    }
}

/// A random time between half of `wait` and all of it, so that many nodes that lost
/// Connect at once do not come back at once.
pub fn jitter(wait: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    // A fresh `RandomState` is seeded from the system's randomness (per process, then
    // advanced per instance): enough for a spread of waits, and no new crate.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    hasher.write_u128(now);
    jitter_with(wait, hasher.finish())
}

/// [`jitter`] with the random value `random`: `wait / 2 + (random mod (wait / 2 + 1))`
/// in milliseconds.
pub fn jitter_with(wait: Duration, random: u64) -> Duration {
    let millis = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
    let half = millis / 2;
    Duration::from_millis(half + random % (millis - half + 1))
}

/// The zone of the public names of this build: [`NODE_ZONE_ENV`] when it is set, else
/// [`DEFAULT_NODE_ZONE`]. Lowercase, without a trailing dot.
pub fn configured_zone() -> String {
    std::env::var(NODE_ZONE_ENV)
        .ok()
        .map(|zone| zone.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|zone| !zone.is_empty())
        .unwrap_or_else(|| DEFAULT_NODE_ZONE.to_owned())
}

/// The public name of the node `node_id` in `zone` (contract 2): the 10 characters after
/// `node_`, `.`, and the zone. `None` for an id of another form.
pub fn expected_public_name(node_id: &str, zone: &str) -> Option<String> {
    let label = node_id.strip_prefix("node_")?;
    let name = format!(
        "{label}.{}",
        zone.trim_end_matches('.').to_ascii_lowercase()
    );
    (label.len() == 10 && public_cert::valid_public_name(&name)).then_some(name)
}

// ---------------------------------------------------------------------------
// The account seam.

/// Why one step of the tunnel failed. No value holds a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// `401`: the token is not valid (the seam signs in again once).
    Unauthenticated,
    /// `403 plan_required`, or the entitlement has no `tunnel`.
    NotEntitled,
    /// This Mac has no Connect account, or is no longer a device of it.
    NoAccount,
    /// `404 node_unknown`: the node is not registered (any more).
    NodeUnknown,
    /// Another refusal of Connect, with its status and code.
    Refused { status: u16, code: String },
    /// Connect's registration answer is not this node's: another node id than the one
    /// kept for this device, another device, another pin, or a public name that is not
    /// the node's own in the configured zone.
    WrongNode,
    /// Connect could not be reached, or the connection broke.
    Offline(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("Apassy Connect did not accept the sign-in"),
            Self::NotEntitled => f.write_str("the account has no plan with Apassy Connect"),
            Self::NoAccount => f.write_str(concat!(
                "this ",
                crate::computer!(),
                " has no Apassy Connect account"
            )),
            Self::NodeUnknown => f.write_str(concat!(
                "Apassy Connect does not know this ",
                crate::computer!(),
                "'s node"
            )),
            Self::Refused { status, code } => {
                write!(f, "Apassy Connect refused the tunnel ({status} {code})")
            }
            Self::WrongNode => f.write_str(concat!(
                "Apassy Connect answered with a registration that is not this ",
                crate::computer!(),
                "'s node"
            )),
            Self::Offline(why) => write!(f, "Apassy Connect could not be reached: {why}"),
        }
    }
}

fn from_connect(error: ConnectError) -> Failure {
    match error {
        ConnectError::Unauthenticated => Failure::Unauthenticated,
        ConnectError::PlanRequired => Failure::NotEntitled,
        ConnectError::Revoked
        | ConnectError::NoAccount
        | ConnectError::KeyLost
        | ConnectError::NoDeviceKey
        | ConnectError::AccountRequired => Failure::NoAccount,
        ConnectError::NotFound => Failure::NodeUnknown,
        ConnectError::Refused { status, code } => Failure::Refused { status, code },
        other => Failure::Offline(other.to_string()),
    }
}

/// The account of this Mac, as the tunnel needs it. The product is [`AccountAuth`];
/// tests use a fixed token.
pub trait TunnelAuth: Send + Sync {
    /// The Connect origin, without a trailing slash: `https://…`, or `http://` on the
    /// loopback.
    fn origin(&self) -> String;
    /// Run `call` with a fresh account token. After [`Failure::Unauthenticated`] the seam
    /// signs in again and runs it once more; a second one means this Mac is no longer a
    /// device of the account ([`Failure::NoAccount`]).
    fn with_token(&self, call: &mut dyn FnMut(&str) -> Result<(), Failure>) -> Result<(), Failure>;
    /// `Ok` when the account's entitlement has the `tunnel` feature now.
    fn entitled(&self) -> Result<(), Failure>;
    /// This Mac has a Connect account (the account file), without asking Connect.
    fn has_account(&self) -> bool;
    /// The account device id of this Mac (`dev_…`), for the node file.
    fn device_id(&self) -> Option<String>;
    /// Drop the token and the account key from memory (a lock, a quit).
    fn sign_out(&self);
}

/// The account of this device through the one account session of the app
/// (`crate::connect::AccountSession`, plan s7 unit M5b): the tunnel never reads the key
/// store itself. The session opens with the vault unlock and closes at a lock and a
/// quit; while it is closed or opening, a sign-in of the tunnel waits for the next try
/// ([`Failure::Offline`]), and a removal of this device is [`Failure::NoAccount`] here
/// as in Settings › Connect and the sync.
pub struct AccountAuth {
    session: Arc<AccountSession>,
}

impl std::fmt::Debug for AccountAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAuth")
            .field("session", &self.session)
            .finish()
    }
}

impl AccountAuth {
    /// The tunnel's view of `session`. The account file is read at each use: an account
    /// made later in Settings › Connect counts at the next start of the node.
    pub fn new(session: Arc<AccountSession>) -> Self {
        Self { session }
    }
}

impl TunnelAuth for AccountAuth {
    fn origin(&self) -> String {
        self.session
            .account_state()
            .map_or_else(crate::connect::configured_origin, |state| state.origin)
    }

    fn with_token(&self, call: &mut dyn FnMut(&str) -> Result<(), Failure>) -> Result<(), Failure> {
        let mut kept: Option<Failure> = None;
        let result = self.session.with_account(|account| {
            account.with_token(|_, token| match call(token) {
                Ok(()) => Ok(()),
                Err(Failure::Unauthenticated) => Err(ConnectError::Unauthenticated),
                Err(other) => {
                    kept = Some(other);
                    Err(ConnectError::Local)
                }
            })
        });
        match (result, kept) {
            (Ok(()), _) => Ok(()),
            (Err(_), Some(failure)) => Err(failure),
            (Err(error), None) => Err(from_connect(error)),
        }
    }

    fn entitled(&self) -> Result<(), Failure> {
        self.session
            .with_account(|account| {
                account
                    .entitlement()
                    .map(|entitlement| entitlement.is_some_and(|e| e.has(Feature::Tunnel)))
            })
            .map_err(from_connect)
            .and_then(|tunnel| {
                if tunnel {
                    Ok(())
                } else {
                    Err(Failure::NotEntitled)
                }
            })
    }

    fn has_account(&self) -> bool {
        self.session.has_account()
    }

    fn device_id(&self) -> Option<String> {
        self.session.account_state().map(|state| state.device_id)
    }

    /// Nothing: the account session closes with the vault (a lock, a quit), not with the
    /// tunnel. A route that goes off leaves the session to Settings and the sync.
    fn sign_out(&self) {}
}

// ---------------------------------------------------------------------------
// The registration (contract 3.1).

/// The node as Connect registered it (`NodeView`, contract 3.1).
pub use crate::connect::client::TunnelNodeView as NodeView;

/// The last registration of this node, kept in `<node dir>/connect/node.json` so the
/// public name is known before Connect answers. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeFile {
    pub origin: String,
    pub node_id: String,
    pub public_name: String,
    pub pin: String,
    /// The account device of the registration: while this device stays, Connect's
    /// answers must name this node id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

fn node_file(node_dir: &Path) -> PathBuf {
    node_dir.join(public_cert::CONNECT_DIR).join(NODE_FILE)
}

/// The kept registration of `node_dir` for `origin`, if any, and only when its public
/// name is the node's own name in `zone`.
pub fn load_node_file(node_dir: &Path, origin: &str, zone: &str) -> Option<NodeFile> {
    let bytes = public_cert::read_private(&node_file(node_dir)).ok()??;
    let file: NodeFile = serde_json::from_slice(&bytes).ok()?;
    (file.origin == origin
        && expected_public_name(&file.node_id, zone).as_deref() == Some(file.public_name.as_str()))
    .then_some(file)
}

fn save_node_file(node_dir: &Path, file: &NodeFile) -> io::Result<()> {
    let dir = node_dir.join(public_cert::CONNECT_DIR);
    public_cert::ensure_private_dir(&dir)?;
    let bytes = serde_json::to_vec_pretty(file).map_err(io::Error::other)?;
    public_cert::write_private(&dir.join(NODE_FILE), &bytes)
}

/// Check the plan, register the node (contract 3.1), and keep the registration in
/// `node_dir`. The node calls it at a start that knows no public name yet; the tunnel
/// registers again at each start of its own (Connect updates the name and the pin).
pub fn register_now(
    auth: &dyn TunnelAuth,
    node_dir: &Path,
    name: &str,
    pin: &str,
    zone: &str,
) -> Result<NodeView, Failure> {
    auth.entitled()?;
    let origin = auth.origin();
    let device = auth.device_id();
    // The node id of an earlier registration of this device at this origin: the node of
    // an account device is stable (contract 2), so a later answer must name it.
    let kept = load_node_file(node_dir, &origin, zone)
        .filter(|file| file.device_id.is_some() && file.device_id == device)
        .map(|file| file.node_id);
    let view = register(auth, name, pin, zone, kept.as_deref())?;
    let _ = save_node_file(
        node_dir,
        &NodeFile {
            origin,
            node_id: view.node_id.clone(),
            public_name: view.public_name.clone(),
            pin: pin.to_owned(),
            device_id: device,
        },
    );
    Ok(view)
}

fn register(
    auth: &dyn TunnelAuth,
    name: &str,
    pin: &str,
    zone: &str,
    kept_node: Option<&str>,
) -> Result<NodeView, Failure> {
    let client = ConnectClient::new(&auth.origin()).map_err(from_connect)?;
    let mut view = None;
    auth.with_token(&mut |token| {
        view = Some(
            client
                .register_node(token, name, pin)
                .map_err(|error| match error {
                    // No tunnel routes on that relay.
                    ConnectError::NotFound => Failure::Refused {
                        status: 404,
                        code: "not_found".to_owned(),
                    },
                    other => from_connect(other),
                })?,
        );
        Ok(())
    })?;
    let view = view.ok_or(Failure::Offline("no answer".to_owned()))?;
    check_registration(&view, pin, zone, auth.device_id().as_deref(), kept_node)?;
    Ok(view)
}

/// Connect's answer must be this node's registration: the node id kept for this device
/// (when one is kept), this device, this pin, and the public name of that node id in the
/// configured zone. A certificate is ordered for the name and agents are sent to it.
pub fn check_registration(
    view: &NodeView,
    pin: &str,
    zone: &str,
    device: Option<&str>,
    kept_node: Option<&str>,
) -> Result<(), Failure> {
    let node_id = kept_node.unwrap_or(&view.node_id);
    let own = expected_public_name(node_id, zone);
    if view.node_id != node_id
        || device.is_some_and(|device| device != view.device_id)
        || view.pin != pin
        || own.as_deref() != Some(view.public_name.as_str())
    {
        return Err(Failure::WrongNode);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The transport: TCP on the loopback, or TLS with the platform roots.

/// One duplex connection: a reader, a writer, and a shutdown that ends both.
pub struct Socket {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub shutdown: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Socket")
    }
}

/// The TLS state and the write half under one lock, so the records reach Connect in the
/// order rustls made them; the read half reads without the lock.
struct TlsSide {
    conn: ClientConnection,
    socket: TcpStream,
}

impl TlsSide {
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.socket)?;
        }
        Ok(())
    }
}

struct TlsReader {
    side: Arc<Mutex<TlsSide>>,
    socket: TcpStream,
    plain: VecDeque<u8>,
    closed: bool,
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut raw = [0u8; CHUNK];
        while self.plain.is_empty() {
            if self.closed {
                return Ok(0);
            }
            let read = self.socket.read(&mut raw)?;
            let mut side = lock(&self.side);
            if read == 0 {
                self.closed = true;
            } else {
                let mut input = &raw[..read];
                while !input.is_empty() {
                    side.conn.read_tls(&mut input)?;
                }
            }
            let state = side
                .conn
                .process_new_packets()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let mut buffer = [0u8; CHUNK];
            loop {
                match side.conn.reader().read(&mut buffer) {
                    Ok(0) => {
                        self.closed = true;
                        break;
                    }
                    Ok(n) => self.plain.extend(&buffer[..n]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            if state.peer_has_closed() {
                self.closed = true;
            }
            side.flush()?;
        }
        let n = buf.len().min(self.plain.len());
        for (slot, byte) in buf.iter_mut().zip(self.plain.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

struct TlsWriter {
    side: Arc<Mutex<TlsSide>>,
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut side = lock(&self.side);
        let written = side.conn.writer().write(buf)?;
        side.flush()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        lock(&self.side).flush()
    }
}

fn offline(error: impl std::fmt::Display) -> Failure {
    Failure::Offline(error.to_string())
}

fn tcp_to(addrs: &[SocketAddr], deadline: Instant) -> Result<TcpStream, Failure> {
    let mut last = Failure::Offline("no address".to_owned());
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(addr, left) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = offline(error),
        }
    }
    Err(last)
}

/// Open a connection to `destination` before `deadline`: plain TCP on the loopback, or
/// TLS with `tls` (the platform roots in the product). The TLS handshake is done here.
pub fn open_socket(
    destination: &DestinationUrl,
    tls: &TlsClient,
    deadline: Instant,
) -> Result<Socket, Failure> {
    match destination {
        DestinationUrl::Loopback { addr, .. } => {
            let stream = tcp_to(&[*addr], deadline)?;
            stream
                .set_write_timeout(Some(CONNECT_DEADLINE))
                .map_err(offline)?;
            let reader = stream.try_clone().map_err(offline)?;
            let closer = stream.try_clone().map_err(offline)?;
            Ok(Socket {
                reader: Box::new(reader),
                writer: Box::new(stream),
                shutdown: Arc::new(move || {
                    let _ = closer.shutdown(Shutdown::Both);
                }),
            })
        }
        DestinationUrl::Https { host, port } => {
            let addrs: Vec<SocketAddr> = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(offline)?
                .collect();
            let mut stream = tcp_to(&addrs, deadline)?;
            let name = ServerName::try_from(host.clone()).map_err(offline)?;
            let mut conn = ClientConnection::new(tls.client_config(), name).map_err(offline)?;
            while conn.is_handshaking() {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(Failure::Offline("the TLS handshake timed out".to_owned()));
                }
                stream.set_read_timeout(Some(left)).map_err(offline)?;
                stream.set_write_timeout(Some(left)).map_err(offline)?;
                conn.complete_io(&mut stream).map_err(offline)?;
            }
            stream.set_read_timeout(None).map_err(offline)?;
            stream
                .set_write_timeout(Some(CONNECT_DEADLINE))
                .map_err(offline)?;
            let read_half = stream.try_clone().map_err(offline)?;
            let closer = stream.try_clone().map_err(offline)?;
            let side = Arc::new(Mutex::new(TlsSide {
                conn,
                socket: stream,
            }));
            Ok(Socket {
                reader: Box::new(TlsReader {
                    side: Arc::clone(&side),
                    socket: read_half,
                    plain: VecDeque::new(),
                    closed: false,
                }),
                writer: Box::new(TlsWriter { side }),
                shutdown: Arc::new(move || {
                    let _ = closer.shutdown(Shutdown::Both);
                }),
            })
        }
    }
}

/// The error code of a refusal body (`{"ok":false,"error":{"code":…}}`).
fn refusal_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["error"]["code"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Open the node's WebSocket on `socket` with `token` (contract 3.2).
fn handshake(
    socket: &mut Socket,
    host: &str,
    token: &str,
    deadline: Instant,
) -> Result<(), Failure> {
    let key = client::new_key();
    let request = Zeroizing::new(client::request(host, NODE_PATH, &key, Some(token)));
    socket.writer.write_all(&request).map_err(offline)?;
    socket.writer.flush().map_err(offline)?;
    drop(request);
    // The answer comes before the deadline, or the socket ends.
    let shutdown = Arc::clone(&socket.shutdown);
    let answered = Arc::new(AtomicBool::new(false));
    let watch = {
        let answered = Arc::clone(&answered);
        thread::Builder::new()
            .name("apassy-tunnel-handshake".to_owned())
            .spawn(move || {
                while !answered.load(Ordering::SeqCst) {
                    if Instant::now() >= deadline {
                        shutdown();
                        return;
                    }
                    thread::sleep(STEP);
                }
            })
            .map_err(offline)?
    };
    let result = client::finish(&mut socket.reader, &key);
    answered.store(true, Ordering::SeqCst);
    let _ = watch.join();
    match result {
        Ok(()) => Ok(()),
        Err(client::HandshakeError::Refused(refused)) => {
            let code = refusal_code(&refused.body);
            Err(match (refused.status, code.as_str()) {
                (401, _) => Failure::Unauthenticated,
                (403, "plan_required") => Failure::NotEntitled,
                (403, "account_required") => Failure::NoAccount,
                (404, _) => Failure::NodeUnknown,
                (status, _) => Failure::Refused { status, code },
            })
        }
        Err(client::HandshakeError::BadAnswer(why)) => Err(offline(why)),
        Err(client::HandshakeError::Io(error)) => Err(offline(error)),
    }
}

// ---------------------------------------------------------------------------
// One node WebSocket and its streams.

/// Where the streams of each kind go: the relay's loopback listeners of the running node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Targets {
    /// The relay's tailnet listener (the device routes), for `device` streams.
    pub device: Option<SocketAddr>,
    /// The relay's public listener (`Scope::Public`), for `public` streams.
    pub public: Option<SocketAddr>,
}

struct Link {
    writer: Mutex<Box<dyn Write + Send>>,
    shutdown: Arc<dyn Fn() + Send + Sync>,
    seq: Mutex<Sequencer<Arc<StreamShared>>>,
    started: Instant,
    /// Milliseconds after `started` of the last message from Connect.
    last_seen: AtomicU64,
    closed: AtomicBool,
}

impl Link {
    /// Milliseconds since the link started.
    fn millis(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_seen.store(self.millis(), Ordering::Relaxed);
    }

    fn silent_for(&self) -> Duration {
        Duration::from_millis(
            self.millis()
                .saturating_sub(self.last_seen.load(Ordering::Relaxed)),
        )
    }

    fn send(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut writer = lock(&self.writer);
        let result = client::send(&mut **writer, opcode, payload);
        if result.is_err() {
            drop(writer);
            self.end();
        }
        result
    }

    fn send_frame(&self, stream: u32, kind: Kind, flags: u8, payload: &[u8]) -> io::Result<()> {
        self.send(ws::OP_BINARY, &frame::encode(stream, kind, flags, payload))
    }

    /// Send a close with `code` (best effort: not while a write is stuck) and end the
    /// transport.
    fn close(&self, code: u16) {
        if !self.closed.load(Ordering::SeqCst) {
            let writer = match self.writer.try_lock() {
                Ok(writer) => Some(writer),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(mut writer) = writer {
                let _ = client::send(&mut **writer, ws::OP_CLOSE, &ws::close_payload(code));
            }
        }
        self.end();
    }

    fn end(&self) {
        self.closed.store(true, Ordering::SeqCst);
        (self.shutdown)();
    }

    /// Reset a stream from this side: Connect gets `reset`, the front's connection ends.
    /// Also for an id that is not live (a broken rule of a frame for it).
    fn reset(&self, id: u32, kind: Kind) {
        let removed = lock(&self.seq).remove(id);
        if let Some(stream) = removed {
            stream.abort();
        }
        let _ = self.send_frame(id, kind, RESET, &[]);
    }

    /// Reset a live stream; nothing for a stream that already ended.
    fn reset_live(&self, id: u32, kind: Kind) {
        let removed = lock(&self.seq).remove(id);
        if let Some(stream) = removed {
            stream.abort();
            let _ = self.send_frame(id, kind, RESET, &[]);
        }
    }

    fn live(&self) -> usize {
        lock(&self.seq).live()
    }

    /// End every stream (the WebSocket ended).
    fn drain(&self) {
        let streams = lock(&self.seq).drain();
        for (_, stream) in streams {
            stream.abort();
        }
    }
}

#[derive(Default)]
struct Inbox {
    bytes: VecDeque<u8>,
    /// Connect closed its direction: reads end after the bytes.
    eof: bool,
    /// The stream ended by a reset, the end of the WebSocket, or this side's end: reads
    /// fail, writes fail, and nothing more is buffered.
    aborted: bool,
    /// This side sent its `close`.
    closed_out: bool,
}

/// One stream of the tunnel, as the front sees it: an accepted connection.
struct StreamShared {
    id: u32,
    kind: Kind,
    link: Arc<Link>,
    inbox: Mutex<Inbox>,
    ready: Condvar,
    read_timeout: Mutex<Option<Duration>>,
    /// How long a write waits for window (the front's write timeout).
    write_timeout: Mutex<Option<Duration>>,
    /// Counts Connect's `window` frames on this stream (and its end); a write that waits
    /// for window waits for it to change.
    window_seen: Mutex<u64>,
    window_cond: Condvar,
    /// Bytes that the front read since the node last granted Connect more.
    drained: AtomicU64,
}

impl StreamShared {
    fn new(id: u32, kind: Kind, link: Arc<Link>) -> Arc<Self> {
        Arc::new(Self {
            id,
            kind,
            link,
            inbox: Mutex::new(Inbox::default()),
            ready: Condvar::new(),
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            window_seen: Mutex::new(0),
            window_cond: Condvar::new(),
            drained: AtomicU64::new(0),
        })
    }

    /// Wakes a write that waits for window.
    fn window_changed(&self) {
        *lock(&self.window_seen) += 1;
        self.window_cond.notify_all();
    }

    /// Grants Connect `added` more bytes of window (a `window` frame), if the stream is
    /// live.
    fn grant(&self, added: u32) {
        if added == 0 {
            return;
        }
        let granted = {
            let mut seq = lock(&self.link.seq);
            matches!(
                seq.apply_parts(
                    Dir::ToConnect,
                    self.id,
                    self.kind,
                    WINDOW,
                    &added.to_be_bytes(),
                    || unreachable!("a window never opens a stream"),
                ),
                Ok(Applied::Frame { .. })
            )
        };
        if granted {
            let _ = self
                .link
                .send(ws::OP_BINARY, &frame::window(self.id, self.kind, added));
        }
    }

    /// The front read `bytes`: once a quarter of the window is read, the node grants
    /// Connect that much more.
    fn drained(&self, bytes: usize) {
        let step = (STREAM_BUFFER / 4) as u64;
        let total = self.drained.fetch_add(bytes as u64, Ordering::SeqCst) + bytes as u64;
        if total >= step {
            let total = self.drained.swap(0, Ordering::SeqCst);
            self.grant(u32::try_from(total).unwrap_or(u32::MAX));
        }
    }

    /// Bytes from Connect. False when the buffer is over its cap (the caller resets).
    fn push(&self, payload: &[u8], eof: bool) -> bool {
        let mut inbox = lock(&self.inbox);
        if !inbox.aborted {
            if inbox.bytes.len() + payload.len() > STREAM_BUFFER {
                return false;
            }
            inbox.bytes.extend(payload);
        }
        inbox.eof |= eof;
        drop(inbox);
        self.ready.notify_all();
        true
    }

    fn abort(&self) {
        let mut inbox = lock(&self.inbox);
        inbox.aborted = true;
        inbox.bytes.clear();
        drop(inbox);
        self.ready.notify_all();
        self.window_changed();
    }

    fn is_aborted(&self) -> bool {
        lock(&self.inbox).aborted
    }

    /// Check a frame of this side against the stream rules, under the lock of the
    /// sequencer; the frame goes out after it. False: the stream is gone or closed.
    fn admit_out(self: &Arc<Self>, flags: u8) -> bool {
        let mut seq = lock(&self.link.seq);
        matches!(
            seq.apply_head(Dir::ToConnect, self.id, self.kind, flags, || Arc::clone(
                self
            )),
            Ok(Applied::Frame { .. })
        )
    }

    /// Spends window for up to `wanted` bytes of data, under the lock of the sequencer;
    /// the data frame goes out after it. `Some(0)`: no window now. `None`: the stream is
    /// gone or this side is closed.
    fn take_window(self: &Arc<Self>, data: &[u8]) -> Option<usize> {
        let mut seq = lock(&self.link.seq);
        let credit = seq.credit(self.id, Dir::ToConnect)?;
        let take = data
            .len()
            .min(frame::MAX_PAYLOAD)
            .min(usize::try_from(credit).unwrap_or(usize::MAX));
        if take == 0 {
            return Some(0);
        }
        match seq.apply_parts(Dir::ToConnect, self.id, self.kind, 0, &data[..take], || {
            Arc::clone(self)
        }) {
            Ok(Applied::Frame { .. }) => Some(take),
            _ => None,
        }
    }

    fn close_out(self: &Arc<Self>) {
        {
            let mut inbox = lock(&self.inbox);
            if inbox.closed_out || inbox.aborted {
                return;
            }
            inbox.closed_out = true;
        }
        if self.admit_out(CLOSE) {
            let _ = self.link.send_frame(self.id, self.kind, CLOSE, &[]);
        }
    }

    /// The front's connection ended cleanly after its last bytes: this side's `close`
    /// follows them (Connect ends the stream once they reached the client), and the node
    /// forgets the stream now; later frames of Connect for it are dropped.
    fn finish(self: &Arc<Self>) {
        self.close_out();
        lock(&self.link.seq).remove(self.id);
        self.abort();
    }

    /// The front's connection ended otherwise: `reset`, and the node forgets the stream.
    fn end_now(&self) {
        self.link.reset_live(self.id, self.kind);
        self.abort();
    }
}

/// A stream of the tunnel as a connection of the front ([`Conn`]). Clones are handles
/// to the same stream.
#[derive(Clone)]
pub struct TunnelStream(Arc<StreamShared>);

impl std::fmt::Debug for TunnelStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelStream")
            .field("id", &self.0.id)
            .field("kind", &self.0.kind)
            .finish()
    }
}

impl Read for TunnelStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = *lock(&self.0.read_timeout);
        let until = timeout.map(|timeout| Instant::now() + timeout);
        let mut inbox = lock(&self.0.inbox);
        loop {
            if !inbox.bytes.is_empty() {
                let n = buf.len().min(inbox.bytes.len());
                for (slot, byte) in buf.iter_mut().zip(inbox.bytes.drain(..n)) {
                    *slot = byte;
                }
                drop(inbox);
                self.0.drained(n);
                return Ok(n);
            }
            if inbox.aborted {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            if inbox.eof {
                return Ok(0);
            }
            match until {
                None => {
                    inbox = self
                        .0
                        .ready
                        .wait(inbox)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                Some(until) => {
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    inbox = self
                        .0
                        .ready
                        .wait_timeout(inbox, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }
}

impl Write for TunnelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        {
            let inbox = lock(&self.0.inbox);
            if inbox.aborted || inbox.closed_out {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        // Within the window that Connect granted: wait for more, at most the write
        // timeout.
        let until = lock(&self.0.write_timeout).map(|timeout| Instant::now() + timeout);
        let take = loop {
            let seen = *lock(&self.0.window_seen);
            match self.0.take_window(buf) {
                None => return Err(io::ErrorKind::BrokenPipe.into()),
                Some(0) => {}
                Some(take) => break take,
            }
            if self.0.is_aborted() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let mut current = lock(&self.0.window_seen);
            if *current == seen {
                let wait = match until {
                    Some(until) => {
                        let left = until.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        left.min(Duration::from_secs(1))
                    }
                    None => Duration::from_secs(1),
                };
                current = self
                    .0
                    .window_cond
                    .wait_timeout(current, wait)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            drop(current);
        };
        self.0
            .link
            .send_frame(self.0.id, self.0.kind, 0, &buf[..take])
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Conn for TunnelStream {
    fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    /// `Write`: `close` to Connect. `Both`: the connection ends now: `reset` to Connect,
    /// and the node forgets the stream. `Read`: nothing.
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match how {
            Shutdown::Read => {}
            Shutdown::Write => self.0.close_out(),
            Shutdown::Both => self.0.end_now(),
        }
        Ok(())
    }

    /// The last bytes are written: `close` after them, and the node forgets the stream.
    fn finish(&self) -> io::Result<()> {
        self.0.finish();
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *lock(&self.0.read_timeout) = timeout;
        Ok(())
    }

    /// The longest wait of a write for window; the WebSocket's socket has its own write
    /// timeout.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *lock(&self.0.write_timeout) = timeout;
        Ok(())
    }
}

/// What the stream handlers of one tunnel need.
struct Serving {
    targets: Targets,
    picker: Arc<CertPicker>,
    challenges: Arc<Challenges>,
    limits: FrontLimits,
    stop: Arc<AtomicBool>,
}

fn serve_stream(serving: &Serving, stream: TunnelStream) {
    let kind = stream.0.kind;
    match kind {
        Kind::Acme => answer_acme(&serving.challenges, stream),
        Kind::Device | Kind::Public => {
            let target = match kind {
                Kind::Device => serving.targets.device,
                _ => serving.targets.public,
            };
            let (Some(target), Some(config)) = (target, serving.picker.config(kind)) else {
                stream.0.link.reset(stream.0.id, kind);
                return;
            };
            tls_front::serve_connection(
                stream.clone(),
                config,
                target,
                serving.limits,
                &serving.stop,
            );
            // A clean end already let the stream go (`Conn::finish`); anything else ends
            // it now.
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// Answer one ACME request (contract 7.2): only `GET` of the token of the pending order;
/// anything else is `404`.
fn answer_acme(challenges: &Challenges, mut stream: TunnelStream) {
    let _ = stream.set_read_timeout(Some(ACME_READ));
    let until = Instant::now() + ACME_READ;
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() > ACME_HEAD_LIMIT || Instant::now() >= until {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return,
        }
    }
    let answer = acme::http01_answer(challenges, &head);
    let _ = stream.write_all(&answer);
    let _ = stream.finish();
}

/// Read frames until the WebSocket ends. Every stream is reset at the end. Returns the
/// close code that Connect sent, if it sent one.
fn read_link(
    link: &Arc<Link>,
    reader: Box<dyn Read + Send>,
    serving: &Arc<Serving>,
    workers: &Mutex<Vec<JoinHandle<()>>>,
) -> Option<u16> {
    let mut reader = ws::Reader::client(reader, frame::MAX_MESSAGE);
    let mut code = None;
    loop {
        let message = match reader.read_message() {
            Ok(message) => message,
            Err(error) => {
                if let Some(code) = error.close_code() {
                    link.close(code);
                }
                break;
            }
        };
        link.touch();
        match message {
            Message::Binary(bytes) => {
                let frame = match frame::decode(&bytes) {
                    Ok(frame) => frame,
                    Err(_) => {
                        link.close(close::PROTOCOL);
                        break;
                    }
                };
                apply(link, frame, serving, workers);
            }
            Message::Ping(payload) => {
                let _ = link.send(ws::OP_PONG, &payload);
            }
            Message::Pong(_) => {}
            Message::Text => {
                link.close(close::UNSUPPORTED);
                break;
            }
            Message::Close(sent) => {
                code = sent;
                link.close(close::NORMAL);
                break;
            }
        }
    }
    link.end();
    link.drain();
    code
}

/// The open streams of `kind`: each kind has slots of its own.
fn live_of(seq: &Sequencer<Arc<StreamShared>>, kind: Kind) -> usize {
    seq.values()
        .filter(|(_, stream)| stream.kind == kind)
        .count()
}

fn apply(
    link: &Arc<Link>,
    frame: frame::Frame,
    serving: &Arc<Serving>,
    workers: &Mutex<Vec<JoinHandle<()>>>,
) {
    let (id, kind) = (frame.stream, frame.kind);
    let applied = {
        let mut seq = lock(&link.seq);
        let cap = match kind {
            Kind::Device => MAX_DEVICE_STREAMS,
            Kind::Public => MAX_PUBLIC_STREAMS,
            Kind::Acme => MAX_ACME_STREAMS,
        };
        if frame.flags & OPEN != 0 && live_of(&seq, kind) >= cap {
            // Over the node's cap: the id is used up, the stream is refused.
            drop(seq);
            let _ = link.send_frame(id, kind, RESET, &[]);
            return;
        }
        seq.apply(Dir::ToNode, &frame, || {
            StreamShared::new(id, kind, Arc::clone(link))
        })
    };
    match applied {
        // A broken stream rule resets that stream; the WebSocket stays. A reset is never
        // answered with a reset.
        Err(_) if frame.flags & RESET != 0 => {}
        Err(_) => link.reset(id, kind),
        Ok(Applied::Dropped) => {}
        Ok(Applied::Opened(stream)) => {
            if !stream.push(&frame.payload, frame.flags & CLOSE != 0) {
                link.reset(id, kind);
                return;
            }
            // Connect may send the initial window; the node grants the rest of its buffer
            // at once.
            stream.grant(u32::try_from(STREAM_BUFFER as u64 - frame::INITIAL_WINDOW).unwrap_or(0));
            let handle = TunnelStream(stream);
            let serving = Arc::clone(serving);
            let spawned = thread::Builder::new()
                .name("apassy-tunnel-stream".to_owned())
                .spawn(move || serve_stream(&serving, handle));
            match spawned {
                Ok(worker) => {
                    let mut workers = lock(workers);
                    workers.retain(|worker| !worker.is_finished());
                    workers.push(worker);
                }
                Err(_) => link.reset(id, kind),
            }
        }
        Ok(Applied::Frame { value, ended }) => {
            if frame.flags & RESET != 0 {
                value.abort();
                return;
            }
            if frame.is_window() {
                // Connect lets the node send more of the front's bytes.
                value.window_changed();
                return;
            }
            if !value.push(&frame.payload, frame.flags & CLOSE != 0) {
                link.reset(id, kind);
                return;
            }
            if ended && value.is_aborted() {
                value.abort();
            }
        }
    }
}

/// Ping every `interval`; end the WebSocket after `idle` without a message.
fn ping_link(link: &Link, interval: Duration, idle: Duration, stop: &AtomicBool) {
    let mut next = Instant::now() + interval;
    while !link.closed.load(Ordering::SeqCst) {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        if link.silent_for() >= idle {
            link.end();
            return;
        }
        if Instant::now() >= next {
            next = Instant::now() + interval;
            if link.send(ws::OP_PING, b"apassy").is_err() {
                return;
            }
        }
        thread::sleep(STEP);
    }
}

// ---------------------------------------------------------------------------
// The tunnel.

/// The state of the tunnel for the "Apassy Connect" row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// The tunnel does not run (the route is off, or the node stopped).
    Off,
    /// The first connection is on its way.
    Connecting,
    /// The WebSocket to Connect is open.
    On,
    /// The connection ended or was refused; the next try waits for the backoff.
    Reconnecting { why: String },
    /// This Mac has no Connect account, or the account has no plan with the tunnel.
    NotOnConnect,
}

/// The public certificate of the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertState {
    /// None yet, and why (for "No certificate yet: <reason>").
    Missing(String),
    /// An order runs.
    Requesting,
    /// A certificate is installed; it ends at this Unix time.
    Valid { not_after: u64 },
}

/// What the tunnel shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelStatus {
    pub state: TunnelState,
    /// `k7m2q4x3ca.node.apassy.wyderka.cc`, once registered.
    pub public_name: Option<String>,
    /// The MCP URL of cloud agents: `https://<public name>/mcp`.
    pub url: Option<String>,
    pub certificate: CertState,
    pub open_streams: usize,
    /// Tries to open the WebSocket since the start.
    pub attempts: u64,
    /// WebSockets that opened since the start.
    pub connects: u64,
    /// The clock time of the last WebSocket that opened.
    pub connected_at: Option<Duration>,
}

impl TunnelStatus {
    fn new() -> Self {
        Self {
            state: TunnelState::Connecting,
            public_name: None,
            url: None,
            certificate: CertState::Missing("the node is not registered yet".to_owned()),
            open_streams: 0,
            attempts: 0,
            connects: 0,
            connected_at: None,
        }
    }
}

/// What the tunnel needs from the build: the account seam, the TLS client, ACME, and the
/// times.
#[derive(Clone)]
pub struct ConnectSetup {
    pub auth: Arc<dyn TunnelAuth>,
    /// The TLS client of the Connect origin; `None`: the platform roots.
    pub tls: Option<TlsClient>,
    /// ACME for the public certificate; `None`: no certificate is requested (public
    /// streams then fail their handshake: "No certificate yet").
    pub acme: Option<AcmeOptions>,
    pub clock: Arc<dyn Clock>,
    pub ping_interval: Duration,
    pub idle_limit: Duration,
    /// The limits of each stream's connection to the relay (the front's).
    pub limits: FrontLimits,
    /// The zone of the public names (contract 2): Connect's answer must name this node's
    /// label in it.
    pub zone: String,
}

impl std::fmt::Debug for ConnectSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectSetup")
            .field("origin", &self.auth.origin())
            .field("acme", &self.acme.is_some())
            .finish_non_exhaustive()
    }
}

impl ConnectSetup {
    /// The setup of `auth` with the product's times, the platform TLS, and ACME at the
    /// configured directory.
    pub fn new(auth: Arc<dyn TunnelAuth>) -> Self {
        Self {
            auth,
            tls: None,
            acme: Some(AcmeOptions::configured()),
            clock: Arc::new(SystemClock::default()),
            ping_interval: PING_INTERVAL,
            idle_limit: IDLE_LIMIT,
            limits: FrontLimits::default(),
            zone: configured_zone(),
        }
    }

    /// The product: the one account session of the app.
    pub fn for_session(session: Arc<AccountSession>) -> Self {
        Self::new(Arc::new(AccountAuth::new(session)))
    }
}

/// What a tunnel of a running node is given.
pub struct TunnelOptions {
    pub setup: ConnectSetup,
    /// The node directory (the Connect files: `connect/`).
    pub node_dir: PathBuf,
    /// The node's display name at Connect.
    pub name: String,
    /// The pinned node certificate (its pin goes to Connect; its key serves `device`).
    pub certificate: NodeCertificate,
    pub targets: Targets,
    /// Seals the keys of the Connect files (the public certificate's key, the ACME
    /// account key): derived from the node master key
    /// (`crate::net::sealed_key::CONNECT_INFO`).
    pub seal: Arc<SealKey>,
}

struct Shared {
    stop: Arc<AtomicBool>,
    status: Mutex<TunnelStatus>,
    link: Mutex<Option<Arc<Link>>>,
    /// The shutdown of a connection on its way (before its WebSocket opened), so a stop
    /// does not wait for its deadline.
    connecting: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    picker: Mutex<Option<Arc<CertPicker>>>,
    challenges: Arc<Challenges>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    fn set_state(&self, state: TunnelState) {
        lock(&self.status).state = state;
    }

    fn set_cert(&self, certificate: CertState) {
        lock(&self.status).certificate = certificate;
    }
}

/// The tunnel of a running node. [`Tunnel::start`] gives the handle.
pub struct Tunnel;

/// The running tunnel. Drop stops it.
pub struct TunnelHandle {
    shared: Arc<Shared>,
    auth: Arc<dyn TunnelAuth>,
    main: Option<JoinHandle<()>>,
    acme: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for TunnelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelHandle")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl Tunnel {
    /// Start the tunnel thread. It connects by itself and keeps trying; it never blocks
    /// the caller on the network.
    pub fn start(options: TunnelOptions) -> io::Result<TunnelHandle> {
        let TunnelOptions {
            setup,
            node_dir,
            name,
            certificate,
            targets,
            seal,
        } = options;
        let shared = Arc::new(Shared {
            stop: Arc::new(AtomicBool::new(false)),
            status: Mutex::new(TunnelStatus::new()),
            link: Mutex::new(None),
            connecting: Mutex::new(None),
            picker: Mutex::new(None),
            challenges: Arc::new(Challenges::default()),
            workers: Mutex::new(Vec::new()),
        });
        let pin = certificate.pin.text();
        let origin = setup.auth.origin();
        // A kept registration with this pin gives the public name (and the kept
        // certificate) at once, and Connect knows the node: the tunnel registers again
        // only when Connect answers `node_unknown`.
        let kept = load_node_file(&node_dir, &origin, &setup.zone).filter(|file| file.pin == pin);
        if let Some(file) = &kept {
            install_picker(&shared, &node_dir, &certificate, &file.public_name, &seal);
        }
        let registered = kept.is_some();
        let auth = Arc::clone(&setup.auth);
        let main_shared = Arc::clone(&shared);
        let main_setup = setup.clone();
        let main_dir = node_dir.clone();
        let main_seal = Arc::clone(&seal);
        let main = thread::Builder::new()
            .name("apassy-tunnel".to_owned())
            .spawn(move || {
                run(
                    &main_shared,
                    &main_setup,
                    &main_dir,
                    &name,
                    &certificate,
                    targets,
                    registered,
                    &main_seal,
                );
            })?;
        let acme = match setup.acme.clone() {
            Some(options) => {
                let acme_shared = Arc::clone(&shared);
                let clock = Arc::clone(&setup.clock);
                Some(
                    thread::Builder::new()
                        .name("apassy-tunnel-acme".to_owned())
                        .spawn(move || {
                            renew_loop(&acme_shared, &options, &node_dir, &*clock, &seal);
                        })?,
                )
            }
            None => None,
        };
        Ok(TunnelHandle {
            shared,
            auth,
            main: Some(main),
            acme,
        })
    }
}

impl TunnelHandle {
    pub fn status(&self) -> TunnelStatus {
        let mut status = lock(&self.shared.status).clone();
        status.open_streams = lock(&self.shared.link)
            .as_ref()
            .map_or(0, |link| link.live());
        status
    }

    /// The certificates of the streams, once the node is registered.
    pub fn picker(&self) -> Option<Arc<CertPicker>> {
        lock(&self.shared.picker).clone()
    }

    /// Stop: the WebSocket closes with 1000 (a connection on its way is cut), every
    /// stream ends at once, the account leaves memory, and the threads of the tunnel are
    /// joined. A lock calls it on the UI thread, so it waits at most [`STOP_WAIT`] for a
    /// thread that is inside a request with its own deadline (a registration, an ACME
    /// request): such a thread sees the stop when the request ends and opens nothing.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(cut) = lock(&self.shared.connecting).take() {
            cut();
        }
        if let Some(link) = lock(&self.shared.link).take() {
            link.close(close::NORMAL);
            link.drain();
        }
        let until = Instant::now() + STOP_WAIT;
        let mut threads: Vec<JoinHandle<()>> = self.main.take().into_iter().collect();
        threads.extend(self.acme.take());
        threads.extend(lock(&self.shared.workers).drain(..));
        for handle in threads {
            while !handle.is_finished() && Instant::now() < until {
                thread::sleep(STEP);
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
        self.shared.challenges.clear();
        self.auth.sign_out();
        self.shared.set_state(TunnelState::Off);
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn install_picker(
    shared: &Shared,
    node_dir: &Path,
    certificate: &NodeCertificate,
    name: &str,
    seal: &SealKey,
) {
    let Ok(picker) = CertPicker::new(certificate, name) else {
        return;
    };
    let picker = Arc::new(picker);
    match public_cert::load_public(node_dir, seal) {
        Ok(Some(stored)) => match acme::not_after(&stored.chain[0]) {
            Some(not_after)
                if acme::covers(&stored.chain[0], name)
                    && picker.install_public(&stored.chain, &stored.key).is_ok() =>
            {
                shared.set_cert(CertState::Valid { not_after });
            }
            _ => shared.set_cert(CertState::Missing(
                "the kept certificate is not for this name".to_owned(),
            )),
        },
        Ok(None) => shared.set_cert(CertState::Missing(
            "Apassy has not asked for it yet".to_owned(),
        )),
        Err(error) => shared.set_cert(CertState::Missing(format!(
            "the kept certificate cannot be read: {error}"
        ))),
    }
    let mut status = lock(&shared.status);
    status.public_name = Some(name.to_owned());
    status.url = Some(format!("https://{name}/mcp"));
    drop(status);
    *lock(&shared.picker) = Some(picker);
}

/// How one open WebSocket ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEnd {
    /// How long it was open, on the tunnel's clock.
    pub lasted: Duration,
    /// The close code that Connect sent, if it sent one.
    pub code: Option<u16>,
}

/// What the tunnel waits for after a try, before the jitter: the next step of the backoff
/// (`reset`: from 1 s again), or a fixed wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextTry {
    Backoff { reset: bool },
    Wait(Duration),
}

/// The wait after a WebSocket that opened and ended (module text): a replaced WebSocket
/// and a limit of the account wait long; a WebSocket that stayed open for
/// [`STABLE_LINK`] starts the backoff again; any other end takes its next step.
pub fn after_link(end: LinkEnd) -> NextTry {
    match end.code {
        Some(close::REPLACED) => NextTry::Wait(REPLACED_WAIT),
        Some(close::TUNNEL_LIMIT) => NextTry::Wait(LIMIT_WAIT),
        _ => NextTry::Backoff {
            reset: end.lasted >= STABLE_LINK,
        },
    }
}

/// The wait after a refusal before a WebSocket opened.
pub fn after_refusal(failure: &Failure) -> NextTry {
    match failure {
        Failure::NotEntitled | Failure::NoAccount => NextTry::Wait(NOT_ON_CONNECT_WAIT),
        // Only the relay's own limit of the account waits long; the edge's per-address
        // `rate_limited` (other clients behind the same address) takes the backoff.
        Failure::Refused { status: 429, code } if code == "tunnel_limit" => {
            NextTry::Wait(LIMIT_WAIT)
        }
        Failure::Refused { status: 403, code } if code == "account_limit" => {
            NextTry::Wait(LIMIT_WAIT)
        }
        _ => NextTry::Backoff { reset: false },
    }
}

/// The tunnel thread: register, connect, read, and try again. See the module text.
#[allow(clippy::too_many_arguments)] // The whole state of the thread; a struct would only rename it.
fn run(
    shared: &Arc<Shared>,
    setup: &ConnectSetup,
    node_dir: &Path,
    name: &str,
    certificate: &NodeCertificate,
    targets: Targets,
    registered: bool,
    seal: &SealKey,
) {
    let auth = setup.auth.as_ref();
    let origin = auth.origin();
    let Ok(destination) = parse_destination(&origin) else {
        shared.set_state(TunnelState::Reconnecting {
            why: "the Connect address is not valid".to_owned(),
        });
        return;
    };
    let tls = match &setup.tls {
        Some(tls) => tls.clone(),
        None => match TlsClient::platform() {
            Ok(tls) => tls,
            Err(error) => {
                shared.set_state(TunnelState::Reconnecting {
                    why: format!("TLS is not available: {error}"),
                });
                return;
            }
        },
    };
    let host = destination.host_header();
    let pin = certificate.pin.text();
    let mut registered = registered;
    let mut backoff = Backoff::default();
    let stop = &shared.stop;
    while !stop.load(Ordering::SeqCst) {
        let outcome = (|| -> Result<LinkEnd, Failure> {
            if registered {
                auth.entitled()?;
            }
            if !registered {
                let view = register_now(auth, node_dir, name, &pin, &setup.zone)?;
                let known = lock(&shared.picker)
                    .as_ref()
                    .is_some_and(|picker| picker.public_name() == view.public_name);
                if !known {
                    install_picker(shared, node_dir, certificate, &view.public_name, seal);
                }
                registered = true;
            }
            let picker = lock(&shared.picker)
                .clone()
                .ok_or_else(|| Failure::Offline("no public name".to_owned()))?;
            lock(&shared.status).attempts += 1;
            let deadline = Instant::now() + CONNECT_DEADLINE;
            let mut opened: Option<Socket> = None;
            auth.with_token(&mut |token| {
                let mut socket = open_socket(&destination, &tls, deadline)?;
                *lock(&shared.connecting) = Some(Arc::clone(&socket.shutdown));
                if stop.load(Ordering::SeqCst) {
                    (socket.shutdown)();
                }
                let shook = handshake(&mut socket, &host, token, deadline);
                lock(&shared.connecting).take();
                if let Err(failure) = shook {
                    (socket.shutdown)();
                    return Err(failure);
                }
                opened = Some(socket);
                Ok(())
            })?;
            let socket = opened.ok_or_else(|| Failure::Offline("no socket".to_owned()))?;
            Ok(serve_link(shared, setup, socket, picker, targets))
        })();
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let next = match &outcome {
            Ok(end) => {
                shared.set_state(TunnelState::Reconnecting {
                    why: match end.code {
                        Some(close::REPLACED) => {
                            "another Apassy of this Mac connected to Apassy Connect".to_owned()
                        }
                        Some(close::TUNNEL_LIMIT) => {
                            "a tunnel limit of the account is reached".to_owned()
                        }
                        _ => "the connection to Apassy Connect ended".to_owned(),
                    },
                });
                after_link(*end)
            }
            Err(failure) => {
                match failure {
                    Failure::NotEntitled | Failure::NoAccount => {
                        shared.set_state(TunnelState::NotOnConnect);
                    }
                    Failure::NodeUnknown => {
                        registered = false;
                        shared.set_state(TunnelState::Reconnecting {
                            why: Failure::NodeUnknown.to_string(),
                        });
                    }
                    failure => shared.set_state(TunnelState::Reconnecting {
                        why: failure.to_string(),
                    }),
                }
                after_refusal(failure)
            }
        };
        let wait = match next {
            NextTry::Backoff { reset } => {
                if reset {
                    backoff.reset();
                }
                backoff.next_wait()
            }
            NextTry::Wait(wait) => wait,
        };
        if !setup.clock.wait(jitter(wait), stop) {
            break;
        }
    }
}

/// Run one open WebSocket until it ends.
fn serve_link(
    shared: &Arc<Shared>,
    setup: &ConnectSetup,
    socket: Socket,
    picker: Arc<CertPicker>,
    targets: Targets,
) -> LinkEnd {
    let Socket {
        reader,
        writer,
        shutdown,
    } = socket;
    let opened_at = setup.clock.now();
    let link = Arc::new(Link {
        writer: Mutex::new(writer),
        shutdown,
        seq: Mutex::new(Sequencer::new()),
        started: Instant::now(),
        last_seen: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    });
    *lock(&shared.link) = Some(Arc::clone(&link));
    if shared.stop.load(Ordering::SeqCst) {
        link.close(close::NORMAL);
        lock(&shared.link).take();
        return LinkEnd {
            lasted: Duration::ZERO,
            code: None,
        };
    }
    {
        let mut status = lock(&shared.status);
        status.state = TunnelState::On;
        status.connects += 1;
        status.connected_at = Some(opened_at);
    }
    let serving = Arc::new(Serving {
        targets,
        picker,
        challenges: Arc::clone(&shared.challenges),
        limits: setup.limits,
        stop: Arc::clone(&shared.stop),
    });
    let pinger = {
        let link = Arc::clone(&link);
        let stop = Arc::clone(&shared.stop);
        let (interval, idle) = (setup.ping_interval, setup.idle_limit);
        thread::Builder::new()
            .name("apassy-tunnel-ping".to_owned())
            .spawn(move || ping_link(&link, interval, idle, &stop))
    };
    let code = read_link(&link, reader, &serving, &shared.workers);
    if let Ok(pinger) = pinger {
        let _ = pinger.join();
    }
    lock(&shared.link).take();
    LinkEnd {
        lasted: setup.clock.now().saturating_sub(opened_at),
        code,
    }
}

/// What [`keep_issued`] did with an issued certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The certificate state of the node after it.
    pub state: CertState,
    /// Stored and installed: nothing is left to retry.
    pub done: bool,
}

/// Keeps an issued certificate: the picker installs it for the `public` streams at once,
/// then `store` writes it to the node directory. A store that fails leaves it serving
/// from memory, and the caller stores it again later (`done: false`).
pub fn keep_issued(
    picker: &CertPicker,
    issued: &acme::Issued,
    store: impl FnOnce() -> io::Result<()>,
) -> Kept {
    if let Err(error) = picker.install_public(&issued.chain, &issued.key) {
        return Kept {
            state: CertState::Missing(format!("the certificate cannot be used: {error}")),
            done: false,
        };
    }
    let state = CertState::Valid {
        not_after: issued.not_after,
    };
    Kept {
        state,
        done: store().is_ok(),
    }
}

/// The certificate thread: order a certificate when there is none or it ends within the
/// renewal window, through the tunnel once it is open; then look again every hour. An
/// issued certificate is installed at once; one that could not be stored (or installed)
/// is kept in memory and stored again with the backoff, without a new order, while it is
/// usable.
fn renew_loop(
    shared: &Arc<Shared>,
    options: &AcmeOptions,
    node_dir: &Path,
    clock: &dyn Clock,
    seal: &SealKey,
) {
    let stop = &shared.stop;
    let mut failures: u32 = 0;
    let mut pending: Option<acme::Issued> = None;
    while !stop.load(Ordering::SeqCst) {
        let ready = lock(&shared.status).state == TunnelState::On;
        let picker = lock(&shared.picker).clone();
        let (Some(picker), true) = (picker, ready) else {
            if !clock.wait(Duration::from_secs(1), stop) {
                return;
            }
            continue;
        };
        let name = picker.public_name().to_owned();
        let installed = match lock(&shared.status).certificate.clone() {
            CertState::Valid { not_after } => Some(not_after),
            _ => None,
        };
        let step = acme::renew_step(
            pending.as_ref(),
            &name,
            installed,
            (options.now)(),
            options.renew_before,
        );
        let issued = match step {
            acme::RenewStep::Wait => {
                if !clock.wait(options.check_every, stop) {
                    return;
                }
                continue;
            }
            acme::RenewStep::KeepIssued => pending.take(),
            acme::RenewStep::Order => {
                pending = None;
                shared.set_cert(CertState::Requesting);
                match acme::obtain(options, node_dir, seal, &name, &shared.challenges, stop) {
                    Ok(issued) => Some(issued),
                    Err(error) => {
                        shared.set_cert(CertState::Missing(error.to_string()));
                        None
                    }
                }
            }
        };
        match issued {
            Some(issued) => {
                let kept = keep_issued(&picker, &issued, || {
                    public_cert::store_public(node_dir, &issued.chain_pem, &issued.key, seal)
                });
                shared.set_cert(kept.state);
                if kept.done {
                    failures = 0;
                } else {
                    failures += 1;
                    pending = Some(issued);
                }
            }
            None => failures += 1,
        }
        if failures > 0 {
            // 1 min, doubling, at most the check interval.
            let wait = (options.retry_first * 2u32.saturating_pow(failures.saturating_sub(1)))
                .min(options.check_every);
            if !clock.wait(wait, stop) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_to_sixty_seconds() {
        let mut backoff = Backoff::default();
        let waits: Vec<u64> = (0..8).map(|_| backoff.next_wait().as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60]);
        backoff.reset();
        assert_eq!(backoff.next_wait(), BACKOFF_FIRST);
        // A Connect that is back within 15 s is reached by the fifth try, at 15 s.
        let mut backoff = Backoff::default();
        let mut at = 0;
        let tries: Vec<u64> = (0..5)
            .map(|_| {
                at += backoff.next_wait().as_secs();
                at
            })
            .collect();
        assert_eq!(tries, [1, 3, 7, 15, 31]);
    }

    #[test]
    fn the_contract_times_are_the_constants() {
        assert_eq!(PING_INTERVAL, Duration::from_secs(30));
        assert_eq!(IDLE_LIMIT, Duration::from_secs(90));
        assert_eq!(STREAM_BUFFER, 256 * 1024);
        assert_eq!(
            (MAX_DEVICE_STREAMS, MAX_PUBLIC_STREAMS, MAX_ACME_STREAMS),
            (64, 16, 4)
        );
        assert_eq!(frame::INITIAL_WINDOW, 64 * 1024);
        assert_eq!(ws::SUBPROTOCOL, "apassy-tunnel-v1");
    }

    #[test]
    fn a_wait_is_between_half_and_all_of_it() {
        let wait = Duration::from_secs(8);
        assert_eq!(jitter_with(wait, 0), Duration::from_secs(4));
        assert_eq!(jitter_with(wait, 4000), Duration::from_secs(8));
        assert_eq!(jitter_with(wait, 4001), Duration::from_secs(4));
        assert_eq!(jitter_with(Duration::ZERO, 7), Duration::ZERO);
        for _ in 0..100 {
            let got = jitter(wait);
            assert!(got >= Duration::from_secs(4) && got <= wait, "{got:?}");
        }
        let spread: std::collections::HashSet<_> = (0..20).map(|_| jitter(wait)).collect();
        assert!(spread.len() > 1, "the waits are spread");
    }

    #[test]
    fn the_backoff_starts_again_only_after_a_stable_link_and_codes_wait_long() {
        let short = LinkEnd {
            lasted: Duration::from_secs(2),
            code: None,
        };
        assert_eq!(after_link(short), NextTry::Backoff { reset: false });
        let stable = LinkEnd {
            lasted: STABLE_LINK,
            code: Some(close::NORMAL),
        };
        assert_eq!(after_link(stable), NextTry::Backoff { reset: true });
        for (code, wait) in [
            (close::REPLACED, REPLACED_WAIT),
            (close::TUNNEL_LIMIT, LIMIT_WAIT),
        ] {
            let end = LinkEnd {
                lasted: Duration::from_secs(3600),
                code: Some(code),
            };
            assert_eq!(after_link(end), NextTry::Wait(wait), "{code}");
        }
        let limited = Failure::Refused {
            status: 429,
            code: "tunnel_limit".to_owned(),
        };
        assert_eq!(after_refusal(&limited), NextTry::Wait(LIMIT_WAIT));
        let nodes = Failure::Refused {
            status: 403,
            code: "account_limit".to_owned(),
        };
        assert_eq!(after_refusal(&nodes), NextTry::Wait(LIMIT_WAIT));
        assert_eq!(
            after_refusal(&Failure::NotEntitled),
            NextTry::Wait(NOT_ON_CONNECT_WAIT)
        );
        assert_eq!(
            after_refusal(&Failure::Offline("x".to_owned())),
            NextTry::Backoff { reset: false }
        );
    }

    #[test]
    fn the_public_name_is_the_node_label_in_the_zone() {
        assert_eq!(
            expected_public_name("node_k7m2q4x3ca", "Node.Example.Test.").as_deref(),
            Some("k7m2q4x3ca.node.example.test")
        );
        assert_eq!(expected_public_name("node_k7m2", "node.example.test"), None);
        assert_eq!(
            expected_public_name("k7m2q4x3ca", "node.example.test"),
            None
        );
        assert_eq!(
            expected_public_name("node_K7M2Q4X3CA", "node.example.test"),
            None
        );
    }

    /// A writer that keeps what the link sends.
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            lock(&self.0).extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn test_link() -> (Arc<Link>, Arc<Mutex<Vec<u8>>>) {
        let out = Arc::new(Mutex::new(Vec::new()));
        let link = Arc::new(Link {
            writer: Mutex::new(Box::new(Capture(Arc::clone(&out)))),
            shutdown: Arc::new(|| {}),
            seq: Mutex::new(Sequencer::new()),
            started: Instant::now(),
            last_seen: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        });
        (link, out)
    }

    fn opened(link: &Arc<Link>, id: u32) -> Arc<StreamShared> {
        let stream = StreamShared::new(id, Kind::Public, Arc::clone(link));
        lock(&link.seq)
            .apply_head(Dir::ToNode, id, Kind::Public, OPEN, || Arc::clone(&stream))
            .expect("open");
        stream
    }

    /// The frames that the link sent: (stream, flags).
    fn sent(out: &Mutex<Vec<u8>>) -> Vec<(u32, u8)> {
        let bytes = lock(out).clone();
        let mut reader = ws::Reader::server(io::Cursor::new(bytes), frame::MAX_MESSAGE);
        let mut frames = Vec::new();
        while let Ok(Message::Binary(message)) = reader.read_message() {
            let frame = frame::decode(&message).expect("frame");
            frames.push((frame.stream, frame.flags));
        }
        frames
    }

    #[test]
    fn a_clean_end_closes_and_forgets_the_stream_and_any_other_end_resets_it() {
        let (link, out) = test_link();
        let clean = TunnelStream(opened(&link, 3));
        let abrupt = TunnelStream(opened(&link, 4));
        clean.finish().expect("finish");
        assert_eq!(
            link.live(),
            1,
            "the node forgets a stream that ended cleanly"
        );
        assert!(clean.0.is_aborted());
        abrupt.shutdown(Shutdown::Both).expect("shutdown");
        assert_eq!(link.live(), 0);
        // A later end of either sends nothing more, and bytes of Connect are not kept.
        clean.shutdown(Shutdown::Both).expect("again");
        assert!(clean.0.push(&[0u8; STREAM_BUFFER], false));
        assert!(lock(&clean.0.inbox).bytes.is_empty());
        assert_eq!(sent(&out), [(3, CLOSE), (4, RESET)]);
    }

    #[test]
    fn a_write_waits_for_the_window_of_connect_and_a_read_grants_connect_more() {
        let (link, out) = test_link();
        let stream = TunnelStream(opened(&link, 1));
        let mut writer = stream.clone();
        writer
            .set_write_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        // The initial window goes out in frames of at most 16 KiB, then a write waits
        // and times out.
        let data = vec![7u8; frame::INITIAL_WINDOW as usize];
        let mut written = 0;
        while written < data.len() {
            written += writer.write(&data[written..]).expect("within the window");
        }
        let started = Instant::now();
        let error = writer.write(b"x").expect_err("no window");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(150));
        // A window frame of Connect lets 10 more bytes go, from another thread.
        let waiting = {
            let mut writer = writer.clone();
            writer
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            thread::spawn(move || writer.write(&[1u8; 64]))
        };
        thread::sleep(Duration::from_millis(50));
        let grant = frame::decode(&frame::window(1, Kind::Public, 10)).expect("window");
        lock(&link.seq)
            .apply(Dir::ToNode, &grant, || unreachable!())
            .expect("applied");
        stream.0.window_changed();
        assert_eq!(waiting.join().expect("joined").expect("written"), 10);
        // Connect's bytes: reading a quarter of the buffer grants Connect that much more.
        assert!(stream.0.push(&vec![0u8; STREAM_BUFFER / 4], false));
        let mut reader = stream.clone();
        let mut buffer = vec![0u8; STREAM_BUFFER];
        let mut read = 0;
        while read < STREAM_BUFFER / 4 {
            read += reader.read(&mut buffer).expect("read");
        }
        let frames = sent(&out);
        assert_eq!(frames.last(), Some(&(1, WINDOW)));
        assert_eq!(
            lock(&link.seq).credit(1, Dir::ToNode),
            Some(frame::INITIAL_WINDOW + (STREAM_BUFFER / 4) as u64)
        );
        // A reset ends a waiting write at once.
        let blocked = {
            let mut writer = writer.clone();
            thread::spawn(move || writer.write(b"y"))
        };
        thread::sleep(Duration::from_millis(50));
        link.reset_live(1, Kind::Public);
        assert_eq!(
            blocked.join().expect("joined").expect_err("ended").kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    fn view(node_id: &str, device_id: &str, pin: &str, public_name: &str) -> NodeView {
        NodeView {
            node_id: node_id.to_owned(),
            account_id: "acc_aaaaaaaaaa".to_owned(),
            device_id: device_id.to_owned(),
            name: "Mac".to_owned(),
            pin: pin.to_owned(),
            public_name: public_name.to_owned(),
            online: false,
            created_at: 0,
        }
    }

    #[test]
    fn the_registration_must_name_the_node_kept_for_this_device() {
        let zone = "node.example.test";
        let own = view(
            "node_aaaaaaaaaa",
            "dev_1",
            "pin",
            "aaaaaaaaaa.node.example.test",
        );
        assert_eq!(
            check_registration(&own, "pin", zone, Some("dev_1"), None),
            Ok(())
        );
        assert_eq!(
            check_registration(&own, "pin", zone, Some("dev_1"), Some("node_aaaaaaaaaa")),
            Ok(())
        );
        // Another node id than the kept one, even with its own matching name.
        let other = view(
            "node_bbbbbbbbbb",
            "dev_1",
            "pin",
            "bbbbbbbbbb.node.example.test",
        );
        assert_eq!(
            check_registration(&other, "pin", zone, Some("dev_1"), Some("node_aaaaaaaaaa")),
            Err(Failure::WrongNode)
        );
        // Another device, another pin, another name.
        assert_eq!(
            check_registration(&own, "pin", zone, Some("dev_2"), None),
            Err(Failure::WrongNode)
        );
        assert_eq!(
            check_registration(&own, "other", zone, Some("dev_1"), None),
            Err(Failure::WrongNode)
        );
        let renamed = view("node_aaaaaaaaaa", "dev_1", "pin", "aaaaaaaaaa.other.test");
        assert_eq!(
            check_registration(&renamed, "pin", zone, Some("dev_1"), None),
            Err(Failure::WrongNode)
        );
        assert!(
            !Failure::WrongNode
                .to_string()
                .contains("could not be reached")
        );
    }

    #[test]
    fn refusal_codes_are_read_from_the_envelope() {
        assert_eq!(
            refusal_code(br#"{"ok":false,"error":{"code":"plan_required","message":"x"}}"#),
            "plan_required"
        );
        assert_eq!(refusal_code(b"not json"), "");
    }

    #[test]
    fn only_the_relays_tunnel_limit_waits_long_and_an_edge_rate_limit_backs_off() {
        let limit = |status: u16, code: &str| Failure::Refused {
            status,
            code: code.to_owned(),
        };
        assert_eq!(
            after_refusal(&limit(429, "tunnel_limit")),
            NextTry::Wait(LIMIT_WAIT)
        );
        // The edge's per-address limit (other clients behind the same address): the
        // short backoff, never the long wait.
        for code in ["rate_limited", ""] {
            assert_eq!(
                after_refusal(&limit(429, code)),
                NextTry::Backoff { reset: false },
                "{code}"
            );
        }
    }

    #[test]
    fn a_certificate_that_cannot_be_stored_is_installed_at_once_and_stored_again() {
        let name = "aaaaaaaaaa.node.example.test";
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let issued = acme::Issued {
            chain_pem: cert.pem(),
            chain: vec![cert.der().to_vec()],
            key: Zeroizing::new(key.serialize_der()),
            not_after: 1_800_000_000,
        };
        let node = NodeCertificate::generate("Synthetic Mac").expect("node certificate");
        let picker = CertPicker::new(&node, name).expect("picker");
        let kept = keep_issued(&picker, &issued, || Err(io::Error::other("disk full")));
        assert!(picker.has_public(), "the certificate serves at once");
        assert_eq!(
            kept.state,
            CertState::Valid {
                not_after: 1_800_000_000
            }
        );
        assert!(!kept.done, "the store is tried again");
        let mut stored = false;
        let kept = keep_issued(&picker, &issued, || {
            stored = true;
            Ok(())
        });
        assert!(stored && kept.done);
    }
}
