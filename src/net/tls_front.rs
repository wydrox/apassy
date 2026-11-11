//! The TLS front of the node (ADR 0037 D4, plan D2, unit N2).
//!
//! The relay listens on the loopback only. The front makes it reachable on the tailnet:
//!
//! - It binds only the tailnet addresses of this machine (`100.64.0.0/10`,
//!   `fd7a:115c:a1e0::/48`; [`super::tailnet`]). `0.0.0.0`, `::`, and any other address
//!   are refused before a socket is made. [`FrontHandle::rebind`] moves the listeners
//!   when the addresses change, and [`FrontHandle::follow`] polls a source of addresses
//!   so that a change takes effect within 10 s.
//! - A peer outside the two ranges is closed before the TLS handshake. Then the rate of
//!   new connections per peer and the connection slots apply ([`FrontLimits`]).
//! - TLS is `rustls`: TLS 1.3 only, ALPN `http/1.1`, no tickets, no early data, no
//!   client authentication, one certificate ([`super::certificate`]). The handshake has
//!   a deadline.
//! - After the handshake the front pumps bytes in both directions between the TLS
//!   stream and a plain TCP connection to the loopback target (the relay's tailnet-scope
//!   listener). It does **not** parse HTTP: the relay's own parser and limits apply.
//!   The pump ends a connection that is idle for [`FrontLimits::idle`] in both
//!   directions; long polls of 25 s pass.
//! - Stopping the front closes the listeners, ends every connection, and drops the TLS
//!   configuration with the private key.
//!
//! The fallback of the plan's first risk (a socket bound to the Tailscale IPv4 does not
//! receive tailnet connections with some Tailscale variant on macOS) is
//! [`FrontRoute::ServeTcp`]: the front binds `127.0.0.1` only, and Tailscale Serve in TCP
//! mode forwards the tailnet port to it (`tailnet::ServeTcp`). Serve in TCP mode does not
//! end TLS, so the pin holds end to end. It is never a bind on all interfaces.
//!
//! The Wi-Fi companion builds its TLS configuration with [`server_config`] too.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ServerConfig, ServerConnection};

use super::certificate::NodeCertificate;
use super::front_peers;
use super::limits::{Connections, RateLimiter};
use super::pin::Pin;
use super::tailnet;

/// The port of the front (plan D1): next to Funnel's 8443, never 443.
pub const DEFAULT_PORT: u16 = 8444;
/// How often [`FrontHandle::follow`] looks at the addresses: a change takes effect
/// within 10 s.
pub const FOLLOW_INTERVAL: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// At most this many connections are taken from one listener per round.
const ACCEPT_BURST: usize = 16;
/// How long a stop waits for the connection threads to end.
const STOP_WAIT: Duration = Duration::from_secs(2);
/// One read from a socket. A TLS record is at most 16 KiB of plaintext.
const CHUNK: usize = 16 * 1024;
/// The TLS bytes that rustls holds for the peer before the pump writes them out.
const SEND_BUFFER: usize = 256 * 1024;

/// The limits of the front. [`FrontLimits::default`] gives the numbers of plan D2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontLimits {
    /// Open connections in total: 64.
    pub max_connections: usize,
    /// Open connections from one peer address: 8.
    pub max_per_peer: usize,
    /// New connections per peer address and minute: 60.
    pub new_per_peer_per_minute: usize,
    /// The TLS handshake ends within this time: 15 s.
    pub handshake: Duration,
    /// A connection with no byte in either direction for this long ends: 120 s.
    pub idle: Duration,
    /// The connection to the loopback target is made within this time: 5 s.
    pub connect_target: Duration,
    /// At most this many plaintext bytes per direction and connection. `None` (the
    /// default): no cap, because a snapshot upload of relay sync is larger than any
    /// fixed number; the relay has the size limits of its routes (plan D2).
    pub max_bytes_per_direction: Option<u64>,
    /// With [`FrontRoute::ServeTcp`], open connections of one tailnet peer that Serve
    /// names in its PROXY line, inside the shared pool: 16 (N8-5).
    pub max_per_forwarded_peer: usize,
    /// With [`FrontRoute::ServeTcp`], new connections per named tailnet peer and minute:
    /// 60.
    pub new_per_forwarded_peer_per_minute: usize,
}

impl Default for FrontLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_per_peer: 8,
            new_per_peer_per_minute: 60,
            handshake: Duration::from_secs(15),
            idle: Duration::from_secs(120),
            connect_target: Duration::from_secs(5),
            max_bytes_per_direction: None,
            max_per_forwarded_peer: 16,
            new_per_forwarded_peer_per_minute: 60,
        }
    }
}

/// How the tailnet reaches the front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FrontRoute {
    /// The front binds the tailnet addresses of this machine (plan D2).
    #[default]
    Direct,
    /// The fallback of the plan's first risk: the front binds `127.0.0.1` on its port
    /// (`0`: any free port) and Tailscale Serve in TCP mode forwards the tailnet port to
    /// it (`tailnet::ServeTcp::enable`). Every peer is Tailscale's daemon on the
    /// loopback, so the per-peer limits of [`FrontLimits`] apply to all tailnet peers
    /// together. When Serve sends a PROXY protocol v1 line (`--proxy-protocol=1`), the
    /// front reads the tailnet peer from it and applies
    /// [`FrontLimits::max_per_forwarded_peer`] and
    /// [`FrontLimits::new_per_forwarded_peer_per_minute`] to that peer inside the pool
    /// (N8-5). The front cannot tell Serve from another local process: any process on
    /// this machine can connect to it and can write a PROXY line too.
    ServeTcp,
}

/// What the front needs to start.
pub struct FrontOptions {
    /// The tailnet addresses to bind ([`tailnet::system_addresses`]). Empty: no
    /// listener until [`FrontHandle::rebind`]. Ignored with [`FrontRoute::ServeTcp`].
    pub addresses: Vec<IpAddr>,
    /// The port on each address ([`DEFAULT_PORT`]). `0` takes a free port per address
    /// (tests).
    pub port: u16,
    /// The certificate and its key. The key moves into the TLS configuration.
    pub certificate: NodeCertificate,
    /// The loopback address of the relay's tailnet-scope listener.
    pub target: SocketAddr,
    pub limits: FrontLimits,
    pub route: FrontRoute,
    /// Tests only: a loopback address may be bound as if it were a tailnet address.
    #[doc(hidden)]
    pub allow_loopback_bind: bool,
    /// Tests only: a loopback peer stands in for a tailnet peer (as the companion's
    /// `allow_local_peers`).
    #[doc(hidden)]
    pub allow_test_peers: bool,
}

impl FrontOptions {
    /// The options of the node: [`FrontRoute::Direct`], the limits of plan D2.
    pub fn new(
        addresses: Vec<IpAddr>,
        port: u16,
        certificate: NodeCertificate,
        target: SocketAddr,
    ) -> Self {
        Self {
            addresses,
            port,
            certificate,
            target,
            limits: FrontLimits::default(),
            route: FrontRoute::Direct,
            allow_loopback_bind: false,
            allow_test_peers: false,
        }
    }
}

/// Why the front did not start or did not move.
#[derive(Debug)]
pub enum FrontError {
    /// The address is not a tailnet address of this machine: `0.0.0.0`, `::`, a LAN
    /// address, or a loopback address without the test hook. Nothing was bound.
    NotTailnet(IpAddr),
    /// The target is not a loopback address.
    TargetNotLoopback(SocketAddr),
    /// The certificate and its key do not make a TLS configuration.
    Tls(String),
    /// No address could be bound (the port is taken, or the address is gone).
    Bind(Vec<(SocketAddr, io::Error)>),
    /// A thread did not start.
    Io(io::Error),
}

impl std::fmt::Display for FrontError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTailnet(ip) => write!(
                f,
                "{ip} is not a tailnet address; the front binds only tailnet addresses"
            ),
            Self::TargetNotLoopback(target) => {
                write!(
                    f,
                    "the front forwards only to the loopback, not to {target}"
                )
            }
            Self::Tls(why) => write!(
                f,
                "the node certificate does not make a TLS configuration: {why}"
            ),
            Self::Bind(errors) => {
                f.write_str("the front could not listen:")?;
                for (address, error) in errors {
                    write!(f, " {address}: {error};")?;
                }
                Ok(())
            }
            Self::Io(error) => write!(f, "the front did not start: {error}"),
        }
    }
}

impl std::error::Error for FrontError {}

/// The TLS configuration of a listener: TLS 1.3 only, one certificate, no client
/// authentication, HTTP/1.1 only, no tickets, no early data.
///
/// The key is parsed by reference, so this makes no other copy of the PKCS#8 bytes.
/// `rustls-pki-types` does not erase an owned key when it drops, and the single-cert
/// path takes an owned one. The parsed key inside `ring` is out of reach and is not
/// erased. (Moved from the companion's `tls_config`.)
pub fn server_config(certificate_der: &[u8], key_pkcs8: &[u8]) -> io::Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8));
    let signing_key = any_ecdsa_type(&key).map_err(io::Error::other)?;
    let certified = CertifiedKey::new(
        vec![CertificateDer::from(certificate_der.to_vec())],
        signing_key,
    );
    certified.keys_match().map_err(io::Error::other)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// True when the front may bind `ip`: a tailnet address, or a loopback address with the
/// test hook. Never an unspecified, multicast, or broadcast address.
pub fn may_bind(ip: IpAddr, allow_loopback_bind: bool) -> bool {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if let IpAddr::V4(v4) = ip
        && v4.is_broadcast()
    {
        return false;
    }
    tailnet::is_tailnet_peer(ip) || (allow_loopback_bind && ip.is_loopback())
}

/// True when the front serves a peer at `ip`: a tailnet address, or a loopback address
/// with the test hook (or with [`FrontRoute::ServeTcp`], where Tailscale's daemon is the
/// peer).
pub fn admits_peer(ip: IpAddr, loopback_is_tailnet: bool) -> bool {
    let ip = ip.to_canonical();
    tailnet::is_tailnet_peer(ip) || (loopback_is_tailnet && ip.is_loopback())
}

/// What [`TlsSide::receive`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// The connection stays open.
    Open,
    /// The peer sent `close_notify`: no more plaintext comes from it.
    Closed,
}

/// The TLS side of one connection, without I/O: raw bytes in, plaintext out, and the
/// other way. The pump and the fuzz target `tls_front_pump` use it.
pub struct TlsSide {
    conn: ServerConnection,
}

impl TlsSide {
    pub fn new(config: Arc<ServerConfig>) -> io::Result<Self> {
        let mut conn = ServerConnection::new(config).map_err(io::Error::other)?;
        conn.set_buffer_limit(Some(SEND_BUFFER));
        Ok(Self { conn })
    }

    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// The ALPN protocol after the handshake.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// Take raw bytes from the peer and append the plaintext that they carry to
    /// `plain`. An error is a TLS error: the caller sends [`TlsSide::outgoing`] (the
    /// alert) and closes.
    pub fn receive(&mut self, mut raw: &[u8], plain: &mut Vec<u8>) -> io::Result<Received> {
        let mut closed = false;
        loop {
            if !raw.is_empty() {
                self.conn.read_tls(&mut raw)?;
            }
            let state = self
                .conn
                .process_new_packets()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if state.peer_has_closed() {
                closed = true;
            }
            let mut buffer = [0u8; CHUNK];
            loop {
                match self.conn.reader().read(&mut buffer) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(read) => plain.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            if raw.is_empty() {
                break;
            }
        }
        Ok(if closed {
            Received::Closed
        } else {
            Received::Open
        })
    }

    /// Append the bytes that must go to the peer now.
    pub fn outgoing(&mut self, out: &mut Vec<u8>) {
        while self.conn.wants_write() {
            if self.conn.write_tls(out).is_err() {
                break;
            }
        }
    }

    /// Encrypt plaintext for the peer. The caller takes [`TlsSide::outgoing`] after
    /// each call; a chunk of at most 16 KiB always fits.
    pub fn send(&mut self, mut plain: &[u8]) -> io::Result<()> {
        while !plain.is_empty() {
            let written = self.conn.writer().write(plain)?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            plain = &plain[written..];
        }
        Ok(())
    }

    /// Queue `close_notify`.
    pub fn close(&mut self) {
        self.conn.send_close_notify();
    }
}

/// The front. [`Front::start`] gives the running handle.
pub struct Front;

struct Bound {
    address: SocketAddr,
    listener: TcpListener,
}

struct Shared {
    config: Mutex<Option<Arc<ServerConfig>>>,
    target: SocketAddr,
    limits: FrontLimits,
    connections: Arc<Connections>,
    rate: RateLimiter<IpAddr>,
    /// The slots and the rate of the tailnet peers that Serve names (ServeTcp only).
    forwarded: Arc<Connections>,
    forwarded_rate: RateLimiter<IpAddr>,
    /// Shared with the pumps of this front's connections.
    stop: Arc<AtomicBool>,
    loopback_is_tailnet: bool,
    allow_loopback_bind: bool,
    route: FrontRoute,
    port: u16,
    listeners: Mutex<Vec<Bound>>,
    refused_peers: AtomicU64,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The running front. Drop stops it.
pub struct FrontHandle {
    shared: Arc<Shared>,
    pin: Pin,
    accept: Option<JoinHandle<()>>,
    follow: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for FrontHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrontHandle")
            .field("bound", &self.bound())
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

impl Front {
    /// Start the front. It fails when an address is not a tailnet address (nothing is
    /// bound then), when the target is not on the loopback, when the certificate does
    /// not make a TLS configuration, or when addresses are given and none can be bound.
    pub fn start(options: FrontOptions) -> Result<FrontHandle, FrontError> {
        if !options.target.ip().to_canonical().is_loopback() {
            return Err(FrontError::TargetNotLoopback(options.target));
        }
        let addresses = match options.route {
            FrontRoute::Direct => {
                check_addresses(&options.addresses, options.allow_loopback_bind)?;
                options.addresses.clone()
            }
            FrontRoute::ServeTcp => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        };
        let config = server_config(&options.certificate.der, &options.certificate.key)
            .map_err(|error| FrontError::Tls(error.to_string()))?;
        let pin = options.certificate.pin;
        // The PKCS#8 bytes are erased here. The parsed key lives in `config`.
        drop(options.certificate);
        let limits = options.limits;
        let shared = Arc::new(Shared {
            config: Mutex::new(Some(config)),
            target: options.target,
            limits,
            connections: Connections::new(limits.max_connections, limits.max_per_peer),
            rate: RateLimiter::new(limits.new_per_peer_per_minute),
            forwarded: Connections::new(limits.max_connections, limits.max_per_forwarded_peer),
            forwarded_rate: RateLimiter::new(limits.new_per_forwarded_peer_per_minute),
            stop: Arc::new(AtomicBool::new(false)),
            loopback_is_tailnet: options.allow_test_peers || options.route == FrontRoute::ServeTcp,
            allow_loopback_bind: options.allow_loopback_bind
                || options.route == FrontRoute::ServeTcp,
            route: options.route,
            port: options.port,
            listeners: Mutex::new(Vec::new()),
            refused_peers: AtomicU64::new(0),
        });
        shared.bind_set(&addresses)?;
        let accept_shared = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("apassy-front".to_owned())
            .spawn(move || accept_loop(&accept_shared))
            .map_err(FrontError::Io)?;
        Ok(FrontHandle {
            shared,
            pin,
            accept: Some(accept),
            follow: None,
        })
    }
}

fn check_addresses(addresses: &[IpAddr], allow_loopback_bind: bool) -> Result<(), FrontError> {
    match addresses
        .iter()
        .find(|ip| !may_bind(**ip, allow_loopback_bind))
    {
        Some(ip) => Err(FrontError::NotTailnet(*ip)),
        None => Ok(()),
    }
}

impl Shared {
    /// Make the listeners match `addresses`: keep the ones that stay, close the ones
    /// that go, bind the new ones. Fails only when addresses are given and none is
    /// bound afterwards.
    fn bind_set(&self, addresses: &[IpAddr]) -> Result<Vec<SocketAddr>, FrontError> {
        let mut wanted: Vec<IpAddr> = Vec::new();
        for ip in addresses.iter().map(|ip| ip.to_canonical()) {
            if !wanted.contains(&ip) {
                wanted.push(ip);
            }
        }
        let mut listeners = locked(&self.listeners);
        if self.stop.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }
        listeners.retain(|bound| wanted.contains(&bound.address.ip()));
        let mut errors = Vec::new();
        for ip in &wanted {
            if listeners.iter().any(|bound| bound.address.ip() == *ip) {
                continue;
            }
            let address = SocketAddr::new(*ip, self.port);
            match bind(address) {
                Ok(bound) => listeners.push(bound),
                Err(error) => errors.push((address, error)),
            }
        }
        if !wanted.is_empty() && listeners.is_empty() {
            return Err(FrontError::Bind(errors));
        }
        Ok(listeners.iter().map(|bound| bound.address).collect())
    }

    fn config(&self) -> Option<Arc<ServerConfig>> {
        locked(&self.config).clone()
    }
}

fn bind(address: SocketAddr) -> io::Result<Bound> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    Ok(Bound { address, listener })
}

impl FrontHandle {
    /// The pin of the certificate. It is public: a pairing link has it.
    pub fn pin(&self) -> Pin {
        self.pin
    }

    /// The addresses that the front listens on now.
    pub fn bound(&self) -> Vec<SocketAddr> {
        locked(&self.shared.listeners)
            .iter()
            .map(|bound| bound.address)
            .collect()
    }

    /// The number of open connections.
    pub fn open_connections(&self) -> usize {
        self.shared.connections.open()
    }

    /// The number of connections closed before the handshake because the peer is not on
    /// the tailnet.
    pub fn refused_peers(&self) -> u64 {
        self.shared.refused_peers.load(Ordering::Relaxed)
    }

    /// Listen on `addresses` instead: the ones that stay keep their sockets and their
    /// connections. With [`FrontRoute::ServeTcp`] the front stays on the loopback.
    pub fn rebind(&self, addresses: &[IpAddr]) -> Result<Vec<SocketAddr>, FrontError> {
        if self.shared.route == FrontRoute::ServeTcp {
            return Ok(self.bound());
        }
        check_addresses(addresses, self.shared.allow_loopback_bind)?;
        self.shared.bind_set(addresses)
    }

    /// Look at `source` every `every` and [`FrontHandle::rebind`] when the addresses
    /// change. The node passes [`tailnet::system_addresses`] and [`FOLLOW_INTERVAL`]. An
    /// address that `source` gives and that is not a tailnet address is ignored.
    pub fn follow(
        &mut self,
        source: impl Fn() -> Vec<IpAddr> + Send + 'static,
        every: Duration,
    ) -> io::Result<()> {
        if self.follow.is_some() || self.shared.route == FrontRoute::ServeTcp {
            return Ok(());
        }
        let shared = Arc::clone(&self.shared);
        let thread = thread::Builder::new()
            .name("apassy-front-follow".to_owned())
            .spawn(move || {
                let step = every.min(ACCEPT_POLL * 2).max(Duration::from_millis(1));
                let mut next = Instant::now() + every;
                while !shared.stop.load(Ordering::SeqCst) {
                    if Instant::now() < next {
                        thread::sleep(step);
                        continue;
                    }
                    next = Instant::now() + every;
                    let wanted: Vec<IpAddr> = source()
                        .into_iter()
                        .filter(|ip| may_bind(*ip, shared.allow_loopback_bind))
                        .collect();
                    let mut now: Vec<IpAddr> = locked(&shared.listeners)
                        .iter()
                        .map(|bound| bound.address.ip())
                        .collect();
                    let mut sorted = wanted.clone();
                    sorted.sort();
                    sorted.dedup();
                    now.sort();
                    if sorted != now {
                        let _ = shared.bind_set(&wanted);
                    }
                }
            })?;
        self.follow = Some(thread);
        Ok(())
    }

    /// Stop the front: close the listeners, end every connection, and drop the TLS
    /// configuration with the private key.
    pub fn stop(&mut self) {
        if self.shared.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(thread) = self.accept.take() {
            let _ = thread.join();
        }
        // The follow thread may wait up to 10 s for the Tailscale command line. It ends
        // at its next look; after the stop it binds nothing (`bind_set`).
        self.follow = None;
        locked(&self.shared.listeners).clear();
        locked(&self.shared.config).take();
        self.shared.connections.shutdown_all();
        self.shared.connections.wait_idle(STOP_WAIT);
    }
}

impl Drop for FrontHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(shared: &Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        let mut accepted = Vec::new();
        {
            let listeners = locked(&shared.listeners);
            for bound in listeners.iter() {
                for _ in 0..ACCEPT_BURST {
                    match bound.listener.accept() {
                        Ok(connection) => accepted.push(connection),
                        Err(_) => break,
                    }
                }
            }
        }
        if accepted.is_empty() {
            thread::sleep(ACCEPT_POLL);
            continue;
        }
        for (stream, peer) in accepted {
            admit(shared, stream, peer);
        }
    }
}

/// Decide about a new connection: close it, or start its thread. The peer check, the
/// rate, and the slots come before any TLS byte.
fn admit(shared: &Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    let peer_ip = peer.ip().to_canonical();
    if !admits_peer(peer_ip, shared.loopback_is_tailnet) {
        shared.refused_peers.fetch_add(1, Ordering::Relaxed);
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    // A socket from a non-blocking listener can inherit the flag.
    if stream.set_nonblocking(false).is_err() || !shared.rate.admit(peer_ip) {
        return;
    }
    let Ok(copy) = stream.try_clone() else {
        return;
    };
    let Some(slot) = shared.connections.admit(peer_ip, copy) else {
        return;
    };
    let Some(config) = shared.config() else {
        return;
    };
    let worker = Arc::clone(shared);
    // When the thread does not start, the closure drops with its slot.
    let _ = thread::Builder::new()
        .name("apassy-front-conn".to_owned())
        .spawn(move || {
            serve(&worker, stream, config, peer_ip);
            drop(slot);
        });
}

/// The time of the last byte in either direction, in milliseconds since `start`.
struct Activity {
    start: Instant,
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(now, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(now.saturating_sub(self.last.load(Ordering::Relaxed)))
    }
}

/// The peer side of a connection that the front serves: a TCP socket of a listener, or a
/// stream of the Connect tunnel (`crate::node::tunnel`), which arrives as an accepted
/// connection. The pump needs a second handle for the other direction, a shutdown, and
/// timeouts, with the meaning they have on a [`TcpStream`]: a read that times out fails
/// with `WouldBlock` or `TimedOut` and the connection stays usable.
pub trait Conn: Read + Write + Send + Sized + 'static {
    /// A second handle to the same connection.
    fn try_clone(&self) -> io::Result<Self>;
    /// `Write`: no more bytes go to the peer. `Both`: the connection ends now (bytes not
    /// yet delivered may be lost).
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    /// The last bytes are written: the connection ends after them reach the peer. On TCP
    /// this is `shutdown(Both)`, which still sends the queued bytes before the FIN.
    fn finish(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Conn for TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        TcpStream::try_clone(self)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/// Serve one connection that no listener of a front accepted: a stream of the Connect
/// tunnel, handed over with the TLS configuration of its kind (`crate::node::public_cert`).
/// The same handshake deadline, connection to the loopback `target`, pump, and idle limit
/// as a tailnet connection. There is no peer check and no per-peer slot: Connect tells
/// the node nothing about the caller, who authenticates inside TLS as on the tailnet, and
/// the tunnel has its own stream limits. While it pumps, the connection to the target is
/// written down as a tunnel stream in [`front_peers`], so the relay never reads a header
/// of the client for its failed-auth counts (`X-Forwarded-For` comes from the client
/// here). `stop` ends the pump (the tunnel stops). It returns when the connection ended.
pub fn serve_connection<C: Conn>(
    mut conn: C,
    config: Arc<ServerConfig>,
    target: SocketAddr,
    limits: FrontLimits,
    stop: &Arc<AtomicBool>,
) {
    if !target.ip().to_canonical().is_loopback() {
        let _ = conn.shutdown(Shutdown::Both);
        return;
    }
    let Ok(mut tls) = TlsSide::new(config) else {
        let _ = conn.shutdown(Shutdown::Both);
        return;
    };
    let deadline = Instant::now() + limits.handshake;
    let Some(early) = handshake(&mut tls, &mut conn, deadline) else {
        let _ = conn.shutdown(Shutdown::Both);
        return;
    };
    let Ok(target) = TcpStream::connect_timeout(&target, limits.connect_target) else {
        tls.close();
        let mut out = Vec::new();
        tls.outgoing(&mut out);
        let _ = conn.write_all(&out);
        let _ = conn.finish();
        return;
    };
    let _ = target.set_nodelay(true);
    // Before the first byte to the target: the relay reads the request only after it.
    let _entry = match (target.local_addr(), target.peer_addr()) {
        (Ok(source), Ok(listener)) => Some(front_peers::register_tunnel(source, listener)),
        _ => None,
    };
    pump(limits, stop, conn, target, tls, early);
}

/// The TLS state and the write half to the peer, under one lock: the records of both
/// directions reach the peer in the order that rustls made them.
struct PeerSide<C> {
    tls: TlsSide,
    socket: C,
}

impl<C: Conn> PeerSide<C> {
    fn flush(&mut self) -> io::Result<()> {
        let mut out = Vec::new();
        self.tls.outgoing(&mut out);
        if out.is_empty() {
            Ok(())
        } else {
            self.socket.write_all(&out)
        }
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The TLS handshake with a deadline. `None` when it failed or took too long. Else the
/// plaintext that came in the same read as the client's Finished (a client may send its
/// first request right behind it), for the pump. Early data is off, so no plaintext
/// comes before the handshake ends.
fn handshake<C: Conn>(tls: &mut TlsSide, socket: &mut C, deadline: Instant) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; CHUNK];
    let mut plain = Vec::new();
    while tls.is_handshaking() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut out = Vec::new();
        tls.outgoing(&mut out);
        if !out.is_empty() {
            if socket.set_write_timeout(Some(left)).is_err() || socket.write_all(&out).is_err() {
                return None;
            }
            continue;
        }
        if socket.set_read_timeout(Some(left)).is_err() {
            return None;
        }
        let read = match socket.read(&mut buffer) {
            Ok(0) | Err(_) => return None,
            Ok(read) => read,
        };
        match tls.receive(&buffer[..read], &mut plain) {
            Ok(Received::Open) => {}
            Ok(Received::Closed) => return None,
            Err(_) => {
                let mut alert = Vec::new();
                tls.outgoing(&mut alert);
                let _ = socket.write_all(&alert);
                return None;
            }
        }
    }
    let mut out = Vec::new();
    tls.outgoing(&mut out);
    (out.is_empty() || socket.write_all(&out).is_ok()).then_some(plain)
}

/// One connection: the handshake, the connection to the target, then the pump. While it
/// pumps, the connection to the target names `peer` in [`front_peers`], so the relay
/// counts the failed authentications of each peer apart (N8-1).
fn serve(shared: &Arc<Shared>, mut client: TcpStream, config: Arc<ServerConfig>, peer: IpAddr) {
    let _ = client.set_nodelay(true);
    let limits = shared.limits;
    let deadline = Instant::now() + limits.handshake;
    let mut peer = peer;
    // The slot of a peer that Serve names; it frees itself when the connection ends.
    let mut _forwarded_slot = None;
    if shared.route == FrontRoute::ServeTcp {
        match forwarded_peer(&mut client, deadline) {
            Ok(None) => {}
            Ok(Some(named)) => {
                let Ok(copy) = client.try_clone() else {
                    return;
                };
                if !tailnet::is_tailnet_peer(named) || !shared.forwarded_rate.admit(named) {
                    let _ = client.shutdown(Shutdown::Both);
                    return;
                }
                let Some(slot) = shared.forwarded.admit(named, copy) else {
                    let _ = client.shutdown(Shutdown::Both);
                    return;
                };
                _forwarded_slot = Some(slot);
                peer = named;
            }
            Err(()) => {
                let _ = client.shutdown(Shutdown::Both);
                return;
            }
        }
    }
    let Ok(mut tls) = TlsSide::new(config) else {
        return;
    };
    let Some(early) = handshake(&mut tls, &mut client, deadline) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let Ok(target) = TcpStream::connect_timeout(&shared.target, limits.connect_target) else {
        tls.close();
        let mut out = Vec::new();
        tls.outgoing(&mut out);
        let _ = client.write_all(&out);
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let _ = target.set_nodelay(true);
    // Before the first byte to the target: the relay reads the request only after it.
    let _entry = match (target.local_addr(), target.peer_addr()) {
        (Ok(source), Ok(listener)) => Some(front_peers::register(source, listener, peer)),
        _ => None,
    };
    pump(shared.limits, &shared.stop, client, target, tls, early);
}

/// The longest PROXY protocol v1 line, `\r\n` included.
const PROXY_V1_MAX: usize = 107;

/// The tailnet peer that Tailscale Serve names in a PROXY protocol v1 line before the TLS
/// bytes (`tailscale serve --proxy-protocol=1`, N8-5). `Ok(None)`: the connection starts
/// with TLS (a Serve without the PROXY protocol), or the line says `UNKNOWN`. `Err`: a
/// line that is not a PROXY v1 line, or no line before `deadline`. The line is read one
/// byte at a time, so no TLS byte is taken from the socket.
fn forwarded_peer(socket: &mut TcpStream, deadline: Instant) -> Result<Option<IpAddr>, ()> {
    let mut first = [0u8; 1];
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
        return Err(());
    }
    match socket.peek(&mut first) {
        Ok(1) if first[0] == b'P' => {}
        Ok(1) => return Ok(None),
        _ => return Err(()),
    }
    let mut line = Vec::with_capacity(PROXY_V1_MAX);
    while !line.ends_with(b"\r\n") {
        if line.len() >= PROXY_V1_MAX {
            return Err(());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            return Err(());
        }
        match socket.read(&mut first) {
            Ok(1) => line.push(first[0]),
            _ => return Err(()),
        }
    }
    parse_proxy_v1(&line).map_err(|_| ())
}

/// A first line that is not a PROXY protocol v1 line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadProxyLine;

/// The source address of a PROXY protocol v1 line such as
/// `PROXY TCP4 100.64.0.2 100.64.0.1 54321 8444\r\n`. `Ok(None)` for `PROXY UNKNOWN`.
pub fn parse_proxy_v1(line: &[u8]) -> Result<Option<IpAddr>, BadProxyLine> {
    let text = std::str::from_utf8(line).map_err(|_| BadProxyLine)?;
    let text = text.strip_suffix("\r\n").ok_or(BadProxyLine)?;
    let mut parts = text.split(' ');
    if parts.next() != Some("PROXY") {
        return Err(BadProxyLine);
    }
    let family = parts.next().ok_or(BadProxyLine)?;
    if family == "UNKNOWN" {
        return Ok(None);
    }
    let fields: Vec<&str> = parts.collect();
    let [source, destination, source_port, destination_port] = fields[..] else {
        return Err(BadProxyLine);
    };
    let source: IpAddr = source.parse().map_err(|_| BadProxyLine)?;
    let destination: IpAddr = destination.parse().map_err(|_| BadProxyLine)?;
    source_port.parse::<u16>().map_err(|_| BadProxyLine)?;
    destination_port.parse::<u16>().map_err(|_| BadProxyLine)?;
    let family_matches = match family {
        "TCP4" => source.is_ipv4() && destination.is_ipv4(),
        "TCP6" => source.is_ipv6() && destination.is_ipv6(),
        _ => false,
    };
    if family_matches {
        Ok(Some(source.to_canonical()))
    } else {
        Err(BadProxyLine)
    }
}

/// The read timeout of the pump: the idle limit and the stop flag are checked this
/// often.
fn tick(idle: Duration) -> Duration {
    (idle / 4)
        .min(Duration::from_secs(1))
        .max(Duration::from_millis(5))
}

fn end_both<C: Conn>(client: &C, target: &TcpStream) {
    let _ = client.shutdown(Shutdown::Both);
    let _ = target.shutdown(Shutdown::Both);
}

fn pump<C: Conn>(
    limits: FrontLimits,
    stop: &Arc<AtomicBool>,
    client: C,
    target: TcpStream,
    tls: TlsSide,
    early: Vec<u8>,
) {
    let (Ok(client_write), Ok(target_read)) = (client.try_clone(), target.try_clone()) else {
        end_both(&client, &target);
        return;
    };
    let _ = client_write.set_write_timeout(Some(limits.idle));
    let _ = target.set_write_timeout(Some(limits.idle));
    let peer = Arc::new(Mutex::new(PeerSide {
        tls,
        socket: client_write,
    }));
    let activity = Arc::new(Activity::new());
    activity.touch();
    let tick = tick(limits.idle);

    // Target to peer, on its own thread.
    let down = {
        let peer = Arc::clone(&peer);
        let activity = Arc::clone(&activity);
        let stop = Arc::clone(stop);
        thread::Builder::new()
            .name("apassy-front-down".to_owned())
            .spawn(move || down_pump(limits, &stop, target_read, &peer, &activity, tick))
    };
    let Ok(down) = down else {
        end_both(&client, &target);
        return;
    };
    up_pump(limits, stop, client, target, &peer, &activity, tick, early);
    let _ = down.join();
}

/// Peer to target. It runs on the connection's thread.
#[allow(clippy::too_many_arguments)] // The pump's whole state; a struct would only rename it.
fn up_pump<C: Conn>(
    limits: FrontLimits,
    stop: &AtomicBool,
    mut client: C,
    mut target: TcpStream,
    peer: &Mutex<PeerSide<C>>,
    activity: &Activity,
    tick: Duration,
    early: Vec<u8>,
) {
    let mut buffer = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    // Plaintext that came with the client's Finished.
    let mut plain = early;
    let mut closed = false;
    if client.set_read_timeout(Some(tick)).is_err() {
        end_both(&client, &target);
        return;
    }
    loop {
        if !plain.is_empty() {
            total = total.saturating_add(plain.len() as u64);
            if limits
                .max_bytes_per_direction
                .is_some_and(|cap| total > cap)
                || target.write_all(&plain).is_err()
            {
                end_both(&client, &target);
                return;
            }
            plain.clear();
            activity.touch();
        }
        if closed {
            // The peer ended its side: the target sees the end of its request.
            let _ = target.shutdown(Shutdown::Write);
            return;
        }
        if stop.load(Ordering::SeqCst) || activity.idle_for() >= limits.idle {
            end_both(&client, &target);
            return;
        }
        let read = match client.read(&mut buffer) {
            Ok(0) => {
                let _ = target.shutdown(Shutdown::Write);
                return;
            }
            Ok(read) => read,
            Err(error) if is_timeout(&error) => continue,
            Err(_) => {
                end_both(&client, &target);
                return;
            }
        };
        activity.touch();
        let result = {
            let mut side = locked(peer);
            let result = side.tls.receive(&buffer[..read], &mut plain);
            // Alerts, key updates, and the answer to a close go out under the lock.
            let flushed = side.flush();
            result.and_then(|received| flushed.map(|()| received))
        };
        match result {
            Ok(Received::Open) => {}
            Ok(Received::Closed) => closed = true,
            Err(_) => {
                end_both(&client, &target);
                return;
            }
        }
    }
}

/// Target to peer.
fn down_pump<C: Conn>(
    limits: FrontLimits,
    stop: &AtomicBool,
    mut target: TcpStream,
    peer: &Mutex<PeerSide<C>>,
    activity: &Activity,
    tick: Duration,
) {
    let mut buffer = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    if target.set_read_timeout(Some(tick)).is_err() {
        let side = locked(peer);
        end_both(&side.socket, &target);
        return;
    }
    loop {
        if stop.load(Ordering::SeqCst) || activity.idle_for() >= limits.idle {
            let side = locked(peer);
            end_both(&side.socket, &target);
            return;
        }
        let read = match target.read(&mut buffer) {
            Ok(0) => {
                // The target answered and closed: close_notify, then the end of the
                // connection. The queued bytes still reach the peer; the read of the
                // other thread ends, so a peer cannot keep the slot open.
                let mut side = locked(peer);
                side.tls.close();
                let _ = side.flush();
                let _ = side.socket.finish();
                return;
            }
            Ok(read) => read,
            Err(error) if is_timeout(&error) => continue,
            Err(_) => {
                let side = locked(peer);
                end_both(&side.socket, &target);
                return;
            }
        };
        activity.touch();
        total = total.saturating_add(read as u64);
        let mut side = locked(peer);
        let sent = if limits
            .max_bytes_per_direction
            .is_some_and(|cap| total > cap)
        {
            Err(io::ErrorKind::FileTooLarge.into())
        } else {
            side.tls.send(&buffer[..read]).and_then(|()| side.flush())
        };
        if sent.is_err() {
            end_both(&side.socket, &target);
            return;
        }
        drop(side);
        activity.touch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_are_the_numbers_of_the_plan() {
        let limits = FrontLimits::default();
        assert_eq!(limits.max_connections, 64);
        assert_eq!(limits.max_per_peer, 8);
        assert_eq!(limits.new_per_peer_per_minute, 60);
        assert_eq!(limits.handshake, Duration::from_secs(15));
        assert_eq!(limits.idle, Duration::from_secs(120));
        assert_eq!(limits.max_bytes_per_direction, None);
        assert_eq!(limits.max_per_forwarded_peer, 16);
        assert_eq!(limits.new_per_forwarded_peer_per_minute, 60);
        assert!(
            limits.idle > Duration::from_secs(25),
            "a 25 s long poll passes"
        );
        assert_eq!(DEFAULT_PORT, 8444);
        assert!(FOLLOW_INTERVAL * 2 <= Duration::from_secs(10));
    }

    #[test]
    fn a_proxy_v1_line_names_its_source() {
        let ip = |text: &str| text.parse::<IpAddr>().expect("address");
        assert_eq!(
            parse_proxy_v1(b"PROXY TCP4 100.64.0.2 100.64.0.1 54321 8444\r\n"),
            Ok(Some(ip("100.64.0.2")))
        );
        assert_eq!(
            parse_proxy_v1(b"PROXY TCP6 fd7a:115c:a1e0::2 fd7a:115c:a1e0::1 54321 8444\r\n"),
            Ok(Some(ip("fd7a:115c:a1e0::2")))
        );
        assert_eq!(parse_proxy_v1(b"PROXY UNKNOWN\r\n"), Ok(None));
        for bad in [
            &b"PROXY TCP4 100.64.0.2 100.64.0.1 54321 8444\n"[..],
            b"PROXY TCP4 100.64.0.2 100.64.0.1 54321\r\n",
            b"PROXY TCP6 100.64.0.2 100.64.0.1 54321 8444\r\n",
            b"PROXY TCP4 100.64.0.2 100.64.0.1 99999 8444\r\n",
            b"PROXY UDP4 100.64.0.2 100.64.0.1 1 2\r\n",
            b"PROXI TCP4 100.64.0.2 100.64.0.1 1 2\r\n",
            b"PROXY TCP4 100.64.0.2 100.64.0.1 1 2 3\r\n",
            b"\x16\x03\x01",
        ] {
            assert_eq!(parse_proxy_v1(bad), Err(BadProxyLine), "{bad:?}");
        }
    }

    #[test]
    fn only_tailnet_addresses_may_be_bound() {
        let ip = |text: &str| text.parse::<IpAddr>().expect("address");
        for good in ["100.64.0.7", "100.127.0.1", "fd7a:115c:a1e0::7"] {
            assert!(may_bind(ip(good), false), "{good}");
        }
        for bad in [
            "0.0.0.0",
            "::",
            "192.168.1.5",
            "10.0.0.2",
            "127.0.0.1",
            "::1",
            "255.255.255.255",
            "224.0.0.1",
            "ff02::1",
            "100.128.0.1",
        ] {
            assert!(!may_bind(ip(bad), false), "{bad}");
        }
        // The test hook adds the loopback, never the unspecified addresses.
        assert!(may_bind(ip("127.0.0.1"), true));
        assert!(may_bind(ip("::1"), true));
        assert!(!may_bind(ip("0.0.0.0"), true));
        assert!(!may_bind(ip("::"), true));
        assert!(!may_bind(ip("192.168.1.5"), true));
    }

    #[test]
    fn only_tailnet_peers_are_served() {
        let ip = |text: &str| text.parse::<IpAddr>().expect("address");
        assert!(admits_peer(ip("100.64.0.9"), false));
        assert!(admits_peer(ip("::ffff:100.64.0.9"), false));
        assert!(admits_peer(ip("fd7a:115c:a1e0::9"), false));
        assert!(!admits_peer(ip("192.168.1.5"), false));
        assert!(!admits_peer(ip("127.0.0.1"), false));
        assert!(!admits_peer(ip("192.168.1.5"), true));
        assert!(admits_peer(ip("127.0.0.1"), true));
    }

    #[test]
    fn the_tick_is_short_enough_for_the_idle_limit() {
        assert_eq!(tick(Duration::from_secs(120)), Duration::from_secs(1));
        assert_eq!(tick(Duration::from_millis(400)), Duration::from_millis(100));
        assert_eq!(tick(Duration::from_millis(1)), Duration::from_millis(5));
    }

    #[test]
    fn a_key_that_does_not_belong_to_the_certificate_is_refused() {
        let first = NodeCertificate::generate("one").expect("first");
        let second = NodeCertificate::generate("two").expect("second");
        assert!(server_config(&first.der, &first.key).is_ok());
        assert!(server_config(&first.der, &second.key).is_err());
        assert!(server_config(&first.der, &[1, 2, 3]).is_err());
    }
}
