//! The HTTPS listener for the iPhone companion (ADR 0020, contract companion-v1).
//!
//! The listener runs in the Mac app process, on IPv4, in threads like the broker:
//!
//! - One accept thread polls a non-blocking `TcpListener` and a stop flag. Each accepted
//!   connection gets one thread that reads one request, answers, and closes.
//! - TLS is `rustls` with TLS 1.3 only, one certificate from the vault, and no client
//!   authentication. The private key lives in the running server. Stopping the listener
//!   ends every connection and drops the configuration.
//! - A connection from a loopback address or from any address of the Mac itself is
//!   closed at once, so an agent on the Mac cannot use the companion, also on a Mac
//!   with more than one address. The option `allow_local_peers` turns this off for
//!   tests and the development server.
//! - The framing, the deadlines, and the limits of connections and requests are in
//!   [`super::http`] and [`super::limits`]. The endpoints are in `handler`.
//!
//! The listener starts only when the vault is unlocked and the setting is on. It serves
//! only in the vault session in which it started: after a lock and an unlock every
//! signed request gets `423` until the app starts a new listener.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::control::{ControllerParts, PairingController};
use super::crypto::certificate_pin;
use super::handler::{self, Shared};
use super::http::{self, ReadFailure, Response, Timed};
use super::limits::Connections;
use super::pairing::{Clock, Pairing};
use super::wire::MAX_DEVICE_NAME_CHARS;
use crate::broker::SharedVault;
use crate::broker::approvals::{ApprovalQueue, OwnerGate};
use crate::vault::CompanionCertificate;

pub use super::http::Timeouts;

const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// After a refusal that leaves request bytes unread, the listener reads and drops the
/// rest for this long, so that the phone gets the answer and not a reset.
const DRAIN_TIME: Duration = Duration::from_secs(1);
const DRAIN_BYTES: usize = 128 * 1024;
/// How long a stop waits for the connection threads to end.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// What the listener needs to start. [`CompanionOptions::new`] gives the app defaults.
pub struct CompanionOptions {
    /// The one open vault. It must be unlocked, with the companion setting on.
    pub vault: SharedVault,
    /// The runs that wait. This is the queue of the broker
    /// (`BrokerHandle::approvals`).
    pub approvals: Arc<ApprovalQueue>,
    /// The owner gate of the app. A phone approval goes through it.
    pub gate: OwnerGate,
    /// The name of the Mac for the phone, for example the computer name.
    pub mac_name: String,
    /// The version of the app, for `GET /v1/status`.
    pub app_version: String,
    /// How long a run waits for the owner. The phone shows it.
    pub approval_timeout: Duration,
    /// Serve a peer on a loopback address or on an address of the Mac itself. The app
    /// never sets it. Tests and the development server do.
    pub allow_local_peers: bool,
    /// The address to bind. The app binds all IPv4 addresses.
    pub bind: Ipv4Addr,
    /// The port instead of the port in the vault. `Some(0)` takes any free port.
    pub port: Option<u16>,
    /// Deadlines. The defaults are the ones in the contract; tests use short ones.
    pub timeouts: Timeouts,
    /// The clock of the pairing window. `None` is the system clock.
    pub pairing_clock: Option<Arc<dyn Clock>>,
    /// Hosts for the pairing link instead of the found ones. The development server
    /// names `127.0.0.1`. A link may name a loopback host only with `allow_local_peers`.
    pub link_hosts: Option<Vec<String>>,
}

impl CompanionOptions {
    /// The options of the app: all IPv4 addresses, the port of the vault, the deadlines
    /// of the contract, no local peers.
    pub fn new(
        vault: SharedVault,
        approvals: Arc<ApprovalQueue>,
        gate: OwnerGate,
        mac_name: impl Into<String>,
        app_version: impl Into<String>,
        approval_timeout: Duration,
    ) -> Self {
        Self {
            vault,
            approvals,
            gate,
            mac_name: mac_name.into(),
            app_version: app_version.into(),
            approval_timeout,
            allow_local_peers: false,
            bind: Ipv4Addr::UNSPECIFIED,
            port: None,
            timeouts: Timeouts::default(),
            pairing_clock: None,
            link_hosts: None,
        }
    }
}

/// The running listener. Drop stops it.
pub struct CompanionHandle {
    port: u16,
    pin: String,
    stop: Arc<AtomicBool>,
    connections: Arc<Connections>,
    pairing: PairingController,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for CompanionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompanionHandle")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl CompanionHandle {
    /// The port that the listener uses, also when the options asked for port 0.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The pin of the certificate: `b64u(SHA-256(certificate DER))`. It is public: the
    /// pairing link has it.
    pub fn certificate_pin(&self) -> &str {
        &self.pin
    }

    /// The pairing calls for the app.
    pub fn pairing(&self) -> &PairingController {
        &self.pairing
    }

    /// The number of open connections.
    pub fn open_connections(&self) -> usize {
        self.connections.open()
    }

    /// Stop the listener. It closes the pairing window, ends every connection, and
    /// drops the TLS configuration with the private key.
    pub fn stop(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        self.pairing.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.connections.shutdown_all();
        self.connections.wait_idle(STOP_WAIT);
    }
}

impl Drop for CompanionHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The Mac name for the phone: no control character, at most 40 characters, and `Mac`
/// when nothing is left.
fn clean_mac_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_NAME_CHARS)
        .collect();
    if clean.trim().is_empty() {
        "Mac".to_owned()
    } else {
        clean
    }
}

fn refused(kind: io::ErrorKind, text: &str) -> io::Error {
    io::Error::new(kind, text.to_owned())
}

/// The TLS configuration: TLS 1.3 only, the certificate of the vault, no client
/// authentication, HTTP/1.1 only, no tickets, no early data.
///
/// The key is parsed from the erasing buffer of the vault by reference, so the code
/// makes no other copy of the PKCS#8 bytes. `rustls-pki-types` does not erase an owned
/// key when it drops, and `with_single_cert` takes an owned one. The parsed key inside
/// `ring` is out of reach and is not erased.
fn tls_config(certificate: &CompanionCertificate) -> io::Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(&certificate.key[..]));
    let signing_key = any_ecdsa_type(&key).map_err(io::Error::other)?;
    let certified = CertifiedKey::new(
        vec![CertificateDer::from(certificate.der.clone())],
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

/// Start the listener. It fails when the vault is locked, when the companion setting is
/// off, or when the port is not free. The first start makes the certificate.
pub fn start(options: CompanionOptions) -> io::Result<CompanionHandle> {
    let (certificate, setting, epoch) = {
        let mut guard = options.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let vault = guard
            .as_mut()
            .filter(|vault| !vault.is_locked())
            .ok_or_else(|| {
                refused(
                    io::ErrorKind::PermissionDenied,
                    "the vault is locked, so the iPhone listener does not start",
                )
            })?;
        let setting = vault.companion_setting().map_err(io::Error::other)?;
        if !setting.enabled {
            return Err(refused(
                io::ErrorKind::PermissionDenied,
                "the iPhone companion is off in the vault",
            ));
        }
        let certificate = vault
            .ensure_companion_certificate()
            .map_err(io::Error::other)?;
        (certificate, setting, vault.epoch())
    };
    let config = tls_config(&certificate)?;
    let pin = certificate_pin(&certificate.der);
    // The PKCS#8 bytes are erased here. The parsed key lives in `config`.
    drop(certificate);

    let listener = TcpListener::bind(SocketAddr::from((
        options.bind,
        options.port.unwrap_or(setting.port),
    )))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let pairing = Arc::new(match &options.pairing_clock {
        Some(clock) => Pairing::with_clock(Arc::clone(clock)),
        None => Pairing::new(),
    });
    let mac_name = clean_mac_name(&options.mac_name);
    let mut shared = Shared::new(
        Arc::clone(&options.vault),
        options.approvals,
        options.gate,
        Arc::clone(&pairing),
        epoch,
    );
    shared.mac_name.clone_from(&mac_name);
    shared.app_version = options.app_version;
    shared.approval_timeout = options.approval_timeout;

    let stop = Arc::new(AtomicBool::new(false));
    let connections = Connections::new();
    let controller = PairingController::new(ControllerParts {
        pairing,
        vault: options.vault,
        mac_name,
        port,
        pin: pin.clone(),
        epoch,
        stopped: Arc::clone(&stop),
        hosts: options.link_hosts,
        development: options.allow_local_peers,
    });
    let accept = AcceptLoop {
        listener,
        config,
        shared: Arc::new(shared),
        connections: Arc::clone(&connections),
        stop: Arc::clone(&stop),
        allow_local_peers: options.allow_local_peers,
        timeouts: options.timeouts,
    };
    let thread = thread::Builder::new()
        .name("apassy-companion".to_owned())
        .spawn(move || accept.run())?;
    Ok(CompanionHandle {
        port,
        pin,
        stop,
        connections,
        pairing: controller,
        thread: Some(thread),
    })
}

struct AcceptLoop {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    shared: Arc<Shared>,
    connections: Arc<Connections>,
    stop: Arc<AtomicBool>,
    allow_local_peers: bool,
    timeouts: Timeouts,
}

impl AcceptLoop {
    fn run(self) {
        while !self.stop.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, peer)) => self.admit(stream, peer),
                Err(_) => thread::sleep(ACCEPT_POLL),
            }
        }
    }

    /// Decide about a new connection: close it, or start its thread.
    fn admit(&self, stream: TcpStream, peer: SocketAddr) {
        // A socket from a non-blocking listener can inherit the flag.
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let peer_ip = peer.ip().to_canonical();
        if !self.allow_local_peers {
            let own = stream
                .local_addr()
                .ok()
                .map(|addr| addr.ip().to_canonical());
            if is_local_peer(peer_ip, own, is_address_of_this_host) {
                return;
            }
        }
        let Ok(copy) = stream.try_clone() else {
            return;
        };
        let Some(slot) = self.connections.admit(peer_ip, copy) else {
            return;
        };
        let shared = Arc::clone(&self.shared);
        let config = Arc::clone(&self.config);
        let timeouts = self.timeouts;
        // When the thread does not start, the closure drops with its slot.
        let _ = thread::Builder::new()
            .name("apassy-companion-conn".to_owned())
            .spawn(move || {
                serve(stream, peer_ip, &shared, config, &timeouts);
                drop(slot);
            });
    }
}

/// True when a peer is a program on the Mac itself: a loopback address, the address
/// that the connection reached (`own`, the local address of the socket), or any other
/// address of the Mac (`on_this_host`). A program on a Mac with two addresses can reach
/// one from the other, and then the peer is not the address that it reached.
fn is_local_peer(peer: IpAddr, own: Option<IpAddr>, on_this_host: impl Fn(IpAddr) -> bool) -> bool {
    peer.is_loopback() || own == Some(peer) || on_this_host(peer)
}

/// True when `ip` is an address of this host, on any interface. Binding a UDP socket to
/// an address works only for an address of the host. The bind sends no packet, does not
/// wait for the network, and uses a port that the OS picks and frees at once.
fn is_address_of_this_host(ip: IpAddr) -> bool {
    UdpSocket::bind((ip, 0)).is_ok()
}

/// A socket with a deadline for the reads and the writes that follow. The deadline is a
/// point in time, so a peer that sends one byte at a time does not get more time.
struct TimedSocket {
    socket: TcpStream,
    deadline: Instant,
}

impl TimedSocket {
    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }
}

impl Read for TimedSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}

impl Write for TimedSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

type Tls = StreamOwned<ServerConnection, TimedSocket>;

impl Timed for Tls {
    fn set_deadline(&mut self, at: Instant) {
        self.sock.deadline = at;
    }
}

/// One connection: one request, one answer.
fn serve(
    stream: TcpStream,
    peer: IpAddr,
    shared: &Shared,
    config: Arc<ServerConfig>,
    timeouts: &Timeouts,
) {
    let _ = stream.set_nodelay(true);
    let Ok(connection) = ServerConnection::new(config) else {
        return;
    };
    let mut tls: Tls = StreamOwned::new(
        connection,
        TimedSocket {
            socket: stream,
            deadline: Instant::now() + timeouts.head,
        },
    );
    let (response, drain) = match http::read_request(&mut tls, timeouts) {
        Ok(request) => (handler::handle(shared, peer, &request), false),
        Err(ReadFailure::Refuse(code)) => {
            (shared.unsigned_answer(peer, Response::error(code)), true)
        }
        // A failed handshake, a timeout, or an end of stream. There is nothing to answer.
        Err(ReadFailure::Drop) => return,
    };
    tls.set_deadline(Instant::now() + timeouts.write);
    if http::write_response(&mut tls, &response).is_ok() {
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
    let _ = tls.sock.socket.shutdown(Shutdown::Write);
    if drain {
        drain_rest(&mut tls.sock);
    }
}

/// Read and drop what the peer still sends, for a moment.
fn drain_rest(socket: &mut TimedSocket) {
    socket.deadline = Instant::now() + DRAIN_TIME;
    let mut buffer = [0u8; 4096];
    let mut total = 0;
    while total < DRAIN_BYTES {
        match socket.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => total += read,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mac_name_is_clean_and_at_most_40_characters() {
        assert_eq!(clean_mac_name("Mac mini"), "Mac mini");
        assert_eq!(clean_mac_name("Mac\nmini\u{7}"), "Macmini");
        assert_eq!(clean_mac_name(&"m".repeat(60)), "m".repeat(40));
        assert_eq!(clean_mac_name(&"\u{142}".repeat(50)), "\u{142}".repeat(40));
        assert_eq!(clean_mac_name(" \n "), "Mac");
        assert_eq!(clean_mac_name(""), "Mac");
    }

    /// An address of this host that is not loopback, when the host has one: the source
    /// address of the route to a documentation address. Nothing is sent.
    fn own_lan_address() -> Option<Ipv4Addr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
        match socket.local_addr().ok()?.ip() {
            IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => {
                Some(address)
            }
            _ => None,
        }
    }

    #[test]
    fn a_peer_on_the_mac_is_local() {
        let lan: IpAddr = Ipv4Addr::new(192, 168, 1, 20).into();
        let phone: IpAddr = Ipv4Addr::new(192, 168, 1, 31).into();
        let never = |_: IpAddr| false;
        assert!(is_local_peer(Ipv4Addr::LOCALHOST.into(), Some(lan), never));
        assert!(is_local_peer(
            Ipv4Addr::new(127, 5, 5, 5).into(),
            None,
            never
        ));
        // The Mac connects to its own LAN address: the peer is the address it reached.
        assert!(is_local_peer(lan, Some(lan), never));
        assert!(!is_local_peer(phone, Some(lan), never));
        // Without a local address the check cannot say the peer is the Mac. The
        // address of a phone on the network is not loopback.
        assert!(!is_local_peer(phone, None, never));
        // Another address of the Mac (Wi-Fi and Ethernet): the peer is not the address
        // that the connection reached, and it is still the Mac.
        let other_interface = |ip: IpAddr| ip == phone;
        assert!(is_local_peer(phone, Some(lan), other_interface));
        assert!(!is_local_peer(lan, None, other_interface));
    }

    #[test]
    fn an_address_of_this_host_is_found_without_a_packet() {
        assert!(is_address_of_this_host(Ipv4Addr::LOCALHOST.into()));
        // Documentation addresses (RFC 5737) are never an address of a host.
        for foreign in [
            Ipv4Addr::new(192, 0, 2, 55),
            Ipv4Addr::new(198, 51, 100, 7),
            Ipv4Addr::new(203, 0, 113, 9),
        ] {
            assert!(!is_address_of_this_host(foreign.into()), "{foreign}");
        }
        // Every non-loopback address that the host has is one of its own. On a host
        // with two addresses, each is the Mac for a peer that reached the other.
        if let Some(lan) = own_lan_address() {
            assert!(is_address_of_this_host(lan.into()), "{lan}");
            let foreign: IpAddr = Ipv4Addr::new(192, 0, 2, 55).into();
            assert!(is_local_peer(
                lan.into(),
                Some(foreign),
                is_address_of_this_host
            ));
            assert!(!is_local_peer(
                foreign,
                Some(lan.into()),
                is_address_of_this_host
            ));
        }
    }

    #[test]
    fn a_key_that_does_not_belong_to_the_certificate_is_refused() {
        let first =
            rcgen::generate_simple_self_signed(vec!["mac.local".to_owned()]).expect("first");
        let second =
            rcgen::generate_simple_self_signed(vec!["mac.local".to_owned()]).expect("second");
        let good = CompanionCertificate {
            der: first.cert.der().to_vec(),
            key: zeroize::Zeroizing::new(first.signing_key.serialize_der()),
        };
        assert!(tls_config(&good).is_ok());
        let mismatch = CompanionCertificate {
            der: first.cert.der().to_vec(),
            key: zeroize::Zeroizing::new(second.signing_key.serialize_der()),
        };
        assert!(tls_config(&mismatch).is_err());
        let junk = CompanionCertificate {
            der: first.cert.der().to_vec(),
            key: zeroize::Zeroizing::new(vec![1, 2, 3]),
        };
        assert!(tls_config(&junk).is_err());
    }
}
