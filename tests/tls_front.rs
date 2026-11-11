#![cfg(feature = "vault")]

//! The TLS front of the node (ADR 0037 D4, plan `implementation-plan-s2-s3.md`, unit N2).
//! A real front runs on the loopback with the test hooks: `allow_loopback_bind` lets it
//! bind `127.0.0.1`, and `allow_test_peers` lets a loopback peer stand in for a tailnet
//! peer (the companion's `allow_local_peers`). The target is a loopback echo server. The
//! client is rustls with a verifier that accepts only the pin, as the iPhone does.
//! Timing tests use short limits; the defaults are checked as numbers.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy::net::certificate::{CertificateError, NodeCertificate};
use apassy::net::front_peers;
use apassy::net::pin::{self, Pin};
use apassy::net::tls_front::{
    DEFAULT_PORT, Front, FrontError, FrontHandle, FrontLimits, FrontOptions, FrontRoute,
    admits_peer,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MASTER: &[u8] = b"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

// ----- the client: pinned TLS -----

#[derive(Debug)]
struct PinVerifier {
    pin: Pin,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && self.pin.matches(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".to_owned()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(
    pin: Pin,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// A finished TLS 1.3 session with the front at `address`.
fn connect_with(address: SocketAddr, pin: Pin) -> io::Result<Tls> {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let name = ServerName::try_from("apassy-node.invalid")
        .expect("name")
        .to_owned();
    let connection = ClientConnection::new(client_config(pin, &[&rustls::version::TLS13]), name)
        .map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

fn connect(front: &FrontHandle) -> io::Result<Tls> {
    connect_with(front.bound()[0], front.pin())
}

fn send_line(tls: &mut Tls, line: &str) -> io::Result<String> {
    tls.write_all(format!("{line}\n").as_bytes())?;
    tls.flush()?;
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tls.read(&mut byte)? {
            0 => break,
            _ if byte[0] == b'\n' => break,
            _ => answer.push(byte[0]),
        }
    }
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

/// True when the connection ends (an end of stream or an error) within `within`.
fn ends_within(tls: &mut Tls, within: Duration) -> bool {
    let _ = tls.sock.set_read_timeout(Some(within));
    let mut byte = [0u8; 1];
    match tls.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
    }
}

// ----- the target: a loopback line server -----

/// Answers each line `x` with `echo:x`, and `wait:<ms>` with `late` after that time.
fn line_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target");
    let address = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            thread::spawn(move || {
                let Ok(mut writer) = stream.try_clone() else {
                    return;
                };
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { return };
                    let answer = match line.strip_prefix("wait:") {
                        Some(ms) => {
                            thread::sleep(Duration::from_millis(ms.parse().unwrap_or(0)));
                            "late".to_owned()
                        }
                        None => format!("echo:{line}"),
                    };
                    if writer.write_all(format!("{answer}\n").as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

fn certificate() -> NodeCertificate {
    NodeCertificate::generate("Test Mac").expect("certificate")
}

fn options(limits: FrontLimits) -> FrontOptions {
    let mut options = FrontOptions::new(vec![LOOPBACK], 0, certificate(), line_server());
    options.limits = limits;
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    options
}

fn start(limits: FrontLimits) -> FrontHandle {
    Front::start(options(limits)).expect("front")
}

fn wait_until(within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    done()
}

// ----- binds -----

#[test]
fn a_bind_to_all_interfaces_or_a_non_tailnet_address_is_refused() {
    let refused = |addresses: Vec<IpAddr>, hook: bool| {
        let mut options = FrontOptions::new(addresses, 0, certificate(), line_server());
        options.allow_loopback_bind = hook;
        Front::start(options)
    };
    for address in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        "192.168.1.5".parse().unwrap(),
        "10.1.2.3".parse().unwrap(),
        "100.128.0.1".parse().unwrap(),
    ] {
        for hook in [false, true] {
            assert!(
                matches!(refused(vec![address], hook), Err(FrontError::NotTailnet(ip)) if ip == address),
                "{address} with hook {hook}"
            );
        }
    }
    // The loopback only with the test hook.
    assert!(matches!(
        refused(vec![LOOPBACK], false),
        Err(FrontError::NotTailnet(_))
    ));
    // One bad address refuses the whole set: nothing is bound.
    assert!(matches!(
        refused(vec![LOOPBACK, IpAddr::V4(Ipv4Addr::UNSPECIFIED)], true),
        Err(FrontError::NotTailnet(_))
    ));
    // The target is on the loopback, never elsewhere.
    let mut options = FrontOptions::new(
        vec![LOOPBACK],
        0,
        certificate(),
        "192.168.1.5:9".parse().unwrap(),
    );
    options.allow_loopback_bind = true;
    assert!(matches!(
        Front::start(options),
        Err(FrontError::TargetNotLoopback(_))
    ));
    // A running front does not move to a bad address either.
    let front = start(FrontLimits::default());
    let before = front.bound();
    assert!(matches!(
        front.rebind(&[IpAddr::V6(Ipv6Addr::UNSPECIFIED)]),
        Err(FrontError::NotTailnet(_))
    ));
    assert_eq!(front.bound(), before);
    assert_eq!(DEFAULT_PORT, 8444);
}

#[test]
fn the_serve_fallback_binds_only_the_loopback() {
    let mut options = FrontOptions::new(
        vec!["100.64.0.7".parse().unwrap()],
        0,
        certificate(),
        line_server(),
    );
    options.route = FrontRoute::ServeTcp;
    let front = Front::start(options).expect("front");
    let bound = front.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].ip(), LOOPBACK);
    // Tailscale's daemon is the peer on the loopback.
    let mut tls = connect(&front).expect("tls");
    assert_eq!(
        send_line(&mut tls, "via serve").expect("line"),
        "echo:via serve"
    );
    assert_eq!(
        front
            .rebind(&["100.64.0.8".parse().unwrap()])
            .expect("no-op"),
        bound
    );
}

/// A finished TLS 1.3 session with the front at `address`, after a PROXY v1 line
/// `proxy` as Tailscale Serve writes it with `--proxy-protocol=1`.
fn connect_proxied(address: SocketAddr, pin: Pin, proxy: &str) -> io::Result<Tls> {
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.write_all(proxy.as_bytes())?;
    let name = ServerName::try_from("apassy-node.invalid")
        .expect("name")
        .to_owned();
    let connection = ClientConnection::new(client_config(pin, &[&rustls::version::TLS13]), name)
        .map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

fn proxy_line(peer: &str) -> String {
    format!("PROXY TCP4 {peer} 100.64.0.7 50123 8444\r\n")
}

#[test]
fn the_serve_fallback_reads_the_peer_of_a_proxy_line_and_caps_each_peer() {
    let (sender, _sources) = std::sync::mpsc::channel();
    let target = peer_server(sender);
    let mut options = FrontOptions::new(Vec::new(), 0, certificate(), target);
    options.route = FrontRoute::ServeTcp;
    // The node's limits of the fallback (`node::tailnet::front_limits`): every connection
    // comes from the loopback, so the loopback's share is the whole pool.
    options.limits = FrontLimits {
        max_per_peer: 64,
        new_per_peer_per_minute: 480,
        ..FrontLimits::default()
    };
    let front = Front::start(options).expect("front");
    let address = front.bound()[0];
    let pin = front.pin();
    // The relay sees the tailnet peer that Serve names, not the loopback.
    let mut first = connect_proxied(address, pin, &proxy_line("100.64.0.21")).expect("proxied tls");
    assert_eq!(send_line(&mut first, "who").expect("line"), "100.64.0.21");
    // Serve without the PROXY protocol: TLS first, and the peer is the loopback.
    let mut plain = connect(&front).expect("tls");
    assert_eq!(send_line(&mut plain, "who").expect("line"), "127.0.0.1");
    // One peer gets 16 connections inside the pool of 64; the 17th is closed.
    let cap = FrontLimits::default().max_per_forwarded_peer;
    let mut held = vec![first];
    for _ in 1..cap {
        let mut tls =
            connect_proxied(address, pin, &proxy_line("100.64.0.21")).expect("within the cap");
        assert_eq!(send_line(&mut tls, "who").expect("line"), "100.64.0.21");
        held.push(tls);
    }
    let over = connect_proxied(address, pin, &proxy_line("100.64.0.21"))
        .and_then(|mut tls| send_line(&mut tls, "who"));
    assert!(
        over.as_deref().map_or(true, str::is_empty),
        "the 17th connection of one peer is closed: {over:?}"
    );
    // Another peer still gets in.
    let mut other =
        connect_proxied(address, pin, &proxy_line("100.64.0.22")).expect("another peer");
    assert_eq!(send_line(&mut other, "who").expect("line"), "100.64.0.22");
    // A line that names no tailnet peer, or is not a PROXY line, is closed before TLS.
    for bad in [
        proxy_line("192.0.2.9"),
        "PROXY TCP4 nonsense\r\n".to_owned(),
    ] {
        let refused =
            connect_proxied(address, pin, &bad).and_then(|mut tls| send_line(&mut tls, "who"));
        assert!(
            refused.as_deref().map_or(true, str::is_empty),
            "{bad:?}: {refused:?}"
        );
    }
    drop(held);
}

// ----- peers -----

#[test]
fn a_peer_outside_the_tailnet_is_closed_before_the_handshake() {
    assert!(!admits_peer("192.168.1.5".parse().unwrap(), false));
    assert!(admits_peer("100.64.0.9".parse().unwrap(), false));
    assert!(admits_peer("fd7a:115c:a1e0::9".parse().unwrap(), false));
    // A front on the loopback without the peer hook: the loopback is no tailnet peer.
    let mut lan_only = options(FrontLimits::default());
    lan_only.allow_test_peers = false;
    let front = Front::start(lan_only).expect("front");
    let mut raw = TcpStream::connect(front.bound()[0]).expect("tcp");
    raw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut byte = [0u8; 1];
    let read = raw.read(&mut byte);
    assert!(
        matches!(read, Ok(0)) || read.is_err(),
        "no byte from the front: {read:?}"
    );
    assert!(connect(&front).is_err(), "no handshake");
    assert!(wait_until(Duration::from_secs(2), || front.refused_peers() >= 2));
    assert_eq!(front.open_connections(), 0);
}

#[test]
fn a_tailnet_peer_gets_tls_13_with_the_pin_and_its_bytes_reach_the_target() {
    let front = start(FrontLimits::default());
    let mut tls = connect(&front).expect("tls");
    assert_eq!(
        tls.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(tls.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    let leaf = tls.conn.peer_certificates().expect("certificate")[0].clone();
    assert_eq!(pin::certificate_pin(leaf.as_ref()), front.pin().text());
    let long = "x".repeat(40_000);
    for line in ["one", "two", long.as_str()] {
        assert_eq!(
            send_line(&mut tls, line).expect("line"),
            format!("echo:{line}")
        );
    }
    // Another pin refuses the certificate, and TLS 1.2 is refused.
    let other = Pin::of_certificate(b"another certificate");
    assert!(connect_with(front.bound()[0], other).is_err());
    let socket = TcpStream::connect(front.bound()[0]).expect("tcp");
    let name = ServerName::try_from("apassy-node.invalid")
        .unwrap()
        .to_owned();
    let connection =
        ClientConnection::new(client_config(front.pin(), &[&rustls::version::TLS12]), name)
            .expect("client");
    let mut old = StreamOwned::new(connection, socket);
    let mut handshake = Ok(0);
    while old.conn.is_handshaking() && handshake.is_ok() {
        handshake = old.conn.complete_io(&mut old.sock).map(|_| 0);
    }
    assert!(handshake.is_err(), "TLS 1.2 is refused");
}

/// A target that answers each connection's first line with the peer that the front
/// named for it (`front_peers`), and sends the connection's source to `sources`.
fn peer_server(sources: std::sync::mpsc::Sender<SocketAddr>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target");
    let address = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let sources = sources.clone();
            thread::spawn(move || {
                let Ok(source) = stream.peer_addr() else {
                    return;
                };
                let _ = sources.send(source);
                let Ok(mut writer) = stream.try_clone() else {
                    return;
                };
                // Each line gets the named peer; the connection stays until the peer ends.
                for line in BufReader::new(stream).lines() {
                    if line.is_err() {
                        return;
                    }
                    let named = front_peers::peer_of(source, address)
                        .map_or_else(|| "none".to_owned(), |ip| ip.to_string());
                    if writer.write_all(format!("{named}\n").as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

#[test]
fn the_front_names_the_peer_of_each_pumped_connection_until_it_ends() {
    let (sender, sources) = std::sync::mpsc::channel();
    let target = peer_server(sender);
    let mut options = FrontOptions::new(vec![LOOPBACK], 0, certificate(), target);
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    let front = Front::start(options).expect("front");
    let mut tls = connect(&front).expect("tls");
    // The test peer is the loopback; on the tailnet it is the peer's 100.x address.
    assert_eq!(send_line(&mut tls, "who").expect("line"), "127.0.0.1");
    let source = sources
        .recv_timeout(Duration::from_secs(5))
        .expect("a connection to the target");
    assert_eq!(front_peers::peer_of(source, target), Some(LOOPBACK));
    drop(tls);
    assert!(
        wait_until(Duration::from_secs(5), || front_peers::peer_of(
            source, target
        )
        .is_none()),
        "the entry goes with the connection"
    );
}

/// A stream of the Connect tunnel (`serve_connection`): the front writes the connection
/// to the target down as a tunnel stream with the server name of the client's hello, so
/// the relay's public listener knows the public origin of the request without a header.
#[test]
fn a_tunnel_stream_is_written_down_with_the_server_name_of_its_handshake() {
    use std::sync::atomic::AtomicBool;
    let (sender, sources) = std::sync::mpsc::channel();
    let target = peer_server(sender);
    let certificate = certificate();
    let config =
        apassy::net::tls_front::server_config(&certificate.der, &certificate.key).expect("config");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let address = listener.local_addr().expect("addr");
    let stop = Arc::new(AtomicBool::new(false));
    let serving = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let (conn, _) = listener.accept().expect("accept");
            apassy::net::tls_front::serve_connection(
                conn,
                config,
                target,
                FrontLimits::default(),
                &stop,
            );
        })
    };
    let socket = TcpStream::connect(address).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let name = ServerName::try_from("K7M2Q4X3CA.node.example.test")
        .expect("name")
        .to_owned();
    let connection = ClientConnection::new(
        client_config(certificate.pin, &[&rustls::version::TLS13]),
        name,
    )
    .expect("client");
    let mut tls = StreamOwned::new(connection, socket);
    assert_eq!(send_line(&mut tls, "who").expect("line"), "none", "no peer");
    let source = sources
        .recv_timeout(Duration::from_secs(5))
        .expect("a connection to the target");
    let stream = front_peers::tunnel_stream(source, target).expect("a tunnel stream");
    assert_eq!(
        stream
            .server_name
            .map(|name| name.to_ascii_lowercase())
            .as_deref(),
        Some("k7m2q4x3ca.node.example.test")
    );
    assert_eq!(front_peers::peer_of(source, target), None);
    drop(tls);
    assert!(
        wait_until(Duration::from_secs(5), || front_peers::tunnel_stream(
            source, target
        )
        .is_none()),
        "the entry goes with the connection"
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    serving.join().expect("served");
}

#[test]
fn a_request_right_behind_the_finished_reaches_the_target() {
    // The client writes its first line before the handshake ends; rustls sends it
    // right behind its Finished, often in the same segment.
    let front = start(FrontLimits::default());
    let socket = TcpStream::connect(front.bound()[0]).expect("tcp");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let name = ServerName::try_from("apassy-node.invalid")
        .unwrap()
        .to_owned();
    let mut connection =
        ClientConnection::new(client_config(front.pin(), &[&rustls::version::TLS13]), name)
            .expect("client");
    connection.writer().write_all(b"early\n").expect("queue");
    let mut tls = StreamOwned::new(connection, socket);
    let mut answer = String::new();
    let mut byte = [0u8; 1];
    while tls.read(&mut byte).expect("read") == 1 && byte[0] != b'\n' {
        answer.push(char::from(byte[0]));
    }
    assert_eq!(answer, "echo:early");
}

// ----- the pump's deadlines -----

#[test]
fn a_long_poll_passes_and_an_idle_connection_ends() {
    // Scaled: the defaults are a 25 s long poll under a 120 s idle limit; here 250 ms
    // under 1.2 s.
    let defaults = FrontLimits::default();
    assert_eq!(defaults.idle, Duration::from_secs(120));
    let limits = FrontLimits {
        idle: Duration::from_millis(1200),
        ..FrontLimits::default()
    };
    let front = start(limits);
    let mut tls = connect(&front).expect("tls");
    assert_eq!(send_line(&mut tls, "wait:250").expect("long poll"), "late");
    assert_eq!(send_line(&mut tls, "after").expect("line"), "echo:after");
    // Nothing in either direction: the front ends the connection.
    let quiet = Instant::now();
    assert!(ends_within(&mut tls, Duration::from_secs(5)), "idle ends");
    let waited = quiet.elapsed();
    assert!(
        waited >= Duration::from_millis(900),
        "not before the idle limit: {waited:?}"
    );
    assert!(wait_until(Duration::from_secs(2), || front
        .open_connections()
        == 0));
}

#[test]
fn a_slow_handshake_ends_at_the_deadline() {
    let limits = FrontLimits {
        handshake: Duration::from_millis(300),
        ..FrontLimits::default()
    };
    let front = start(limits);
    let mut raw = TcpStream::connect(front.bound()[0]).expect("tcp");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Half a TLS record header, then nothing.
    raw.write_all(&[0x16, 0x03]).expect("write");
    let started = Instant::now();
    let mut byte = [0u8; 1];
    let read = raw.read(&mut byte);
    assert!(matches!(read, Ok(0)) || read.is_err(), "{read:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(wait_until(Duration::from_secs(2), || front
        .open_connections()
        == 0));
}

#[test]
fn a_byte_cap_when_set_ends_the_connection() {
    let limits = FrontLimits {
        max_bytes_per_direction: Some(1000),
        ..FrontLimits::default()
    };
    let front = start(limits);
    let mut tls = connect(&front).expect("tls");
    assert_eq!(send_line(&mut tls, "small").expect("line"), "echo:small");
    let _ = tls.write_all(&[b'a'; 4000]);
    let _ = tls.flush();
    assert!(ends_within(&mut tls, Duration::from_secs(3)));
}

// ----- limits -----

#[test]
fn the_per_peer_and_total_limits_hold() {
    let limits = FrontLimits {
        max_connections: 3,
        max_per_peer: 2,
        ..FrontLimits::default()
    };
    let front = start(limits);
    let first = connect(&front).expect("first");
    let mut second = connect(&front).expect("second");
    assert_eq!(send_line(&mut second, "two").expect("line"), "echo:two");
    assert!(wait_until(Duration::from_secs(2), || front
        .open_connections()
        == 2));
    assert!(
        connect(&front).is_err(),
        "a third from the same peer is refused"
    );
    drop(first);
    assert!(wait_until(Duration::from_secs(3), || front
        .open_connections()
        == 1));
    let mut third = connect(&front).expect("a freed slot");
    assert_eq!(send_line(&mut third, "three").expect("line"), "echo:three");

    // The total: one peer address on the loopback, so the total equals the share.
    let total = start(FrontLimits {
        max_connections: 2,
        max_per_peer: 8,
        ..FrontLimits::default()
    });
    let _a = connect(&total).expect("a");
    let _b = connect(&total).expect("b");
    assert!(wait_until(Duration::from_secs(2), || total
        .open_connections()
        == 2));
    assert!(connect(&total).is_err(), "the total is full");
}

#[test]
fn new_connections_per_peer_and_minute_are_limited() {
    let front = start(FrontLimits {
        new_per_peer_per_minute: 3,
        ..FrontLimits::default()
    });
    for n in 0..3 {
        let mut tls = connect(&front).unwrap_or_else(|error| panic!("{n}: {error}"));
        assert_eq!(send_line(&mut tls, "hi").expect("line"), "echo:hi");
    }
    assert!(
        connect(&front).is_err(),
        "the fourth in a minute is refused"
    );
}

// ----- rebind, follow, stop -----

#[test]
fn rebind_moves_the_listener() {
    let front = start(FrontLimits::default());
    let first = front.bound();
    assert_eq!(first.len(), 1);
    assert!(front.rebind(&[]).expect("none").is_empty());
    assert!(front.bound().is_empty());
    assert!(
        TcpStream::connect_timeout(&first[0], Duration::from_millis(500)).is_err(),
        "the old listener is closed"
    );
    let moved = front.rebind(&[LOOPBACK]).expect("back");
    assert_eq!(moved.len(), 1);
    let mut tls = connect(&front).expect("tls on the new listener");
    assert_eq!(send_line(&mut tls, "moved").expect("line"), "echo:moved");
    // A listener that stays keeps its socket and its connections.
    assert_eq!(front.rebind(&[LOOPBACK]).expect("same"), moved);
    assert_eq!(send_line(&mut tls, "kept").expect("line"), "echo:kept");
    // IPv6 loopback, where the machine has it.
    if TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok() {
        let v6 = front
            .rebind(&[IpAddr::V6(Ipv6Addr::LOCALHOST)])
            .expect("v6");
        assert_eq!(v6.len(), 1);
        assert!(v6[0].is_ipv6());
        assert!(connect(&front).is_ok());
    }
}

#[test]
fn follow_rebinds_when_the_addresses_change() {
    let mut front = start(FrontLimits::default());
    let source = Arc::new(Mutex::new(vec![LOOPBACK]));
    let shared = Arc::clone(&source);
    front
        .follow(
            move || shared.lock().unwrap().clone(),
            Duration::from_millis(50),
        )
        .expect("follow");
    // Tailscale goes down: no address.
    source.lock().unwrap().clear();
    assert!(wait_until(Duration::from_secs(2), || front
        .bound()
        .is_empty()));
    // It comes back.
    source.lock().unwrap().push(LOOPBACK);
    assert!(wait_until(Duration::from_secs(2), || front.bound().len() == 1));
    // A source that names a non-tailnet address does not make the front bind it.
    source
        .lock()
        .unwrap()
        .push(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    thread::sleep(Duration::from_millis(200));
    assert!(front.bound().iter().all(|address| address.ip() == LOOPBACK));
}

#[test]
fn stop_ends_every_connection_and_closes_the_listener() {
    let mut front = start(FrontLimits::default());
    let address = front.bound()[0];
    let mut tls = connect(&front).expect("tls");
    assert_eq!(send_line(&mut tls, "before").expect("line"), "echo:before");
    front.stop();
    assert!(front.bound().is_empty());
    assert_eq!(front.open_connections(), 0);
    assert!(ends_within(&mut tls, Duration::from_secs(3)));
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
}

// ----- the certificate, the sealed key, and the pin -----

#[test]
fn the_sealed_key_opens_only_with_the_right_master_key() {
    let dir = tempfile::tempdir().expect("dir");
    let front_dir = dir.path().join("node").join("front");
    let made = NodeCertificate::load_or_make(&front_dir, MASTER, "Mac mini").expect("make");
    let loaded = NodeCertificate::load_or_make(&front_dir, MASTER, "Mac mini").expect("load");
    assert_eq!(loaded.pin, made.pin);
    let mut wrong = MASTER.to_vec();
    wrong[63] ^= 1;
    assert!(matches!(
        NodeCertificate::load_or_make(&front_dir, &wrong, "Mac mini"),
        Err(CertificateError::Unreadable)
    ));
    // The loaded certificate serves TLS with the same pin.
    let pin = loaded.pin;
    let mut options = FrontOptions::new(vec![LOOPBACK], 0, loaded, line_server());
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    let front = Front::start(options).expect("front");
    assert_eq!(front.pin(), pin);
    assert!(connect(&front).is_ok());
}

#[test]
fn the_pin_equals_the_iphone_pinned_tls_vector() {
    // `PinnedTLS.pinText(ofCertificate: Data([0x30, 0x00])) == Vectors.pinOf3000` in the
    // Kit's ContractVectorTests; the Rust pin of the same DER is the same text.
    let swift =
        include_str!("../ios/ApassyCompanionKit/Tests/ApassyCompanionKitTests/Vectors.swift");
    let line = swift
        .lines()
        .find(|line| line.contains("static let pinOf3000"))
        .expect("the Swift vector");
    let vector = line.split('"').nth(1).expect("a quoted pin");
    assert_eq!(pin::certificate_pin(&[0x30, 0x00]), vector);
    assert_eq!(pin::parse(vector).expect("parses").text(), vector);
}

// ----- the live bind check (the plan's first risk) -----

/// Bind the front to this machine's tailnet addresses on port 8444 (or
/// `APASSY_TEST_FRONT_PORT`) and wait up to `APASSY_TEST_FRONT_WAIT` seconds (default
/// 120) for connections from another tailnet device:
///
/// ```text
/// openssl s_client -connect <tailscale-ip>:8444 -tls1_3 -alpn http/1.1 -quiet
/// ```
///
/// Each line typed there comes back as `echo:<line>`. The test prints the pin and passes
/// when a peer other than this machine sent a line.
#[test]
#[ignore = "needs a running Tailscale and a second tailnet device; see the N2 bind check"]
fn live_front_on_the_tailnet_address_serves_another_device() {
    let addresses = apassy::net::tailnet::system_addresses();
    assert!(!addresses.is_empty(), "no tailnet address on this machine");
    let port = std::env::var("APASSY_TEST_FRONT_PORT")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let wait = std::env::var("APASSY_TEST_FRONT_WAIT")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(120);
    // A target that records the lines it gets.
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target");
    let target_address = target.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in target.incoming().flatten() {
            let record = Arc::clone(&record);
            thread::spawn(move || {
                let mut writer = stream.try_clone().unwrap();
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    record.lock().unwrap().push(line.clone());
                    let _ = writer.write_all(format!("echo:{line}\n").as_bytes());
                }
            });
        }
    });
    let front = Front::start(FrontOptions::new(
        addresses.clone(),
        port,
        certificate(),
        target_address,
    ))
    .expect("the front binds the tailnet addresses");
    eprintln!("front bound: {:?}", front.bound());
    eprintln!("front pin:   {}", front.pin());
    for address in front.bound() {
        assert!(
            apassy::net::tailnet::is_tailnet_peer(address.ip()),
            "{address} is a tailnet address"
        );
    }
    // This machine itself is a tailnet peer by address; it proves the bind only.
    let mut own = connect(&front).expect("a connection from this machine");
    assert_eq!(send_line(&mut own, "self").expect("line"), "echo:self");
    drop(own);
    eprintln!("now connect from another tailnet device within {wait} s");
    let ok = wait_until(Duration::from_secs(wait), || {
        seen.lock().unwrap().iter().any(|line| line != "self")
    });
    eprintln!("lines: {:?}", seen.lock().unwrap());
    assert!(
        ok,
        "no line from another device: use the Serve fallback (FrontRoute::ServeTcp)"
    );
}
