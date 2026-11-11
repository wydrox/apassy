//! Sequential requests on a device stream of the Connect tunnel (docs/SPEC.md section
//! 35.6): the tailnet listener keeps a connection open between requests only when the
//! TLS front of this process wrote it down as a tunnel stream
//! (`apassy::net::front_peers::is_tunnel`), never because of a header. Every other
//! connection, on this listener and on the others, serves one request and says
//! `Connection: close`. Each node listens on free loopback ports and keeps its data in a
//! temporary directory. Synthetic values only.

#[path = "common/node.rs"]
mod node;
#[path = "common/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use apassy::net::certificate::NodeCertificate;
use apassy::net::front_peers;
use apassy::net::pin::Pin;
use apassy::net::tls_front::{self, FrontLimits};
use apassy::node::backend::RunningNode;
use apassy_relay::server::TUNNEL_KEEP_IDLE;
use node::{Node, NodeOptions};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

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

/// A stream of the tunnel as the node serves it: the front's own `serve_connection` (the
/// pinned TLS, the connection to the tailnet listener written down as a tunnel stream),
/// over a loopback TCP connection in place of the stream of Connect. Returns the client's
/// side after the pinned handshake.
fn tunnel_stream(tailnet: SocketAddr) -> StreamOwned<ClientConnection, TcpStream> {
    let certificate = NodeCertificate::generate("Synthetic Test Mac").expect("certificate");
    let config = tls_front::server_config(&certificate.der, &certificate.key).expect("config");
    let pin = certificate.pin;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let stop = Arc::new(AtomicBool::new(false));
        tls_front::serve_connection(stream, config, tailnet, FrontLimits::default(), &stop);
    });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let socket = TcpStream::connect(addr).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let name = ServerName::try_from("100.64.0.7").expect("name").to_owned();
    let connection = ClientConnection::new(Arc::new(config), name).expect("client");
    let mut tls = StreamOwned::new(connection, socket);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).expect("handshake");
    }
    tls
}

/// One answer: its head (lowercase) and its body, by `Content-Length`. `None` when the
/// stream ends before any byte.
fn answer(stream: &mut impl Read) -> Option<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => bytes.push(byte[0]),
            Ok(_) | Err(_) if bytes.is_empty() => return None,
            other => panic!("the answer head ended: {other:?}"),
        }
    }
    let head = String::from_utf8(bytes)
        .expect("ascii")
        .to_ascii_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().expect("length"));
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).expect("body");
    Some((head, body))
}

fn status(head: &str) -> u16 {
    head.split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status")
}

fn closes(head: &str) -> bool {
    head.lines().any(|line| line == "connection: close")
}

/// Nothing more comes on the stream: it ends (or fails) without another byte.
fn ends(stream: &mut impl Read) -> bool {
    let mut rest = Vec::new();
    match stream.read_to_end(&mut rest) {
        Ok(_) => rest.is_empty(),
        Err(_) => rest.is_empty(),
    }
}

fn get(path: &str, token: Option<&str>) -> String {
    let auth = token.map_or(String::new(), |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    format!(
        "GET {path} HTTP/1.1\r\nHost: 100.64.0.7:8444\r\n{auth}User-Agent: apassy-sync/1\r\n\r\n"
    )
}

#[test]
fn a_device_stream_of_the_tunnel_carries_sequential_requests() {
    let node = Node::start(NodeOptions::default());
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    let (_, mac) = node.device_team("Questions");
    let mut tls = tunnel_stream(tailnet);
    // Reads with the device token and a bad token among them: one stream.
    for (request, expected) in [
        (get("/v1/me", Some(&mac.token)), 200),
        (get("/v1/questions?since=0", Some(&mac.token)), 200),
        (get("/v1/me", Some("apr_bad")), 401),
        (get("/v1/me", Some(&mac.token)), 200),
    ] {
        tls.write_all(request.as_bytes()).expect("write");
        tls.flush().expect("flush");
        let (head, _) = answer(&mut tls).expect("an answer on the kept stream");
        assert_eq!(status(&head), expected, "{request}");
        assert!(!closes(&head), "{head}");
    }
    // A POST whose body the relay reads (a sign-in step with a body it refuses), then a
    // read again.
    let post = |path: &str, body: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nHost: 100.64.0.7:8444\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    tls.write_all(post("/v1/auth/challenge", "{}").as_bytes())
        .expect("write");
    tls.flush().expect("flush");
    let (head, _) = answer(&mut tls).expect("an answer");
    assert_eq!(status(&head), 400, "{head}");
    assert!(!closes(&head), "{head}");
    tls.write_all(get("/v1/me", Some(&mac.token)).as_bytes())
        .expect("write");
    tls.flush().expect("flush");
    let (head, _) = answer(&mut tls).expect("an answer");
    assert_eq!(status(&head), 200);
    assert!(!closes(&head), "{head}");
    // `/healthz` cancels its input (its seats never wait for a body): it closes too.
    tls.write_all(get("/healthz", None).as_bytes())
        .expect("write");
    tls.flush().expect("flush");
    let (head, _) = answer(&mut tls).expect("an answer");
    assert_eq!(status(&head), 200);
    assert!(closes(&head), "{head}");
    assert!(ends(&mut tls));
    // The client asks to close: the answer says so, and the stream ends.
    let mut tls = tunnel_stream(tailnet);
    tls.write_all(
        format!(
            "GET /v1/me HTTP/1.1\r\nHost: 100.64.0.7:8444\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            mac.token
        )
        .as_bytes(),
    )
    .expect("write");
    tls.flush().expect("flush");
    let (head, _) = answer(&mut tls).expect("an answer");
    assert!(closes(&head), "{head}");
    assert!(ends(&mut tls));
}

#[test]
fn an_answer_before_the_body_closes_the_tunnel_stream() {
    let node = Node::start(NodeOptions::default());
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    let mut tls = tunnel_stream(tailnet);
    // A team code is not a route of a tunnel stream (section 35.3): 404 before the body
    // is read, so the stream ends after the answer instead of draining the body.
    let body = r#"{"name":"x"}"#;
    tls.write_all(
        format!(
            "POST /v1/teams HTTP/1.1\r\nHost: 100.64.0.7:8444\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .expect("write");
    tls.flush().expect("flush");
    let (head, _) = answer(&mut tls).expect("an answer");
    assert_eq!(status(&head), 404, "{head}");
    assert!(closes(&head), "{head}");
    assert!(ends(&mut tls));
}

#[test]
fn a_pipelined_request_on_a_tunnel_stream_closes_it() {
    let node = Node::start(NodeOptions::default());
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    let (_, mac) = node.device_team("Questions");
    let me = get("/v1/me", Some(&mac.token));
    let mut tls = tunnel_stream(tailnet);
    tls.write_all(me.as_bytes()).expect("write");
    tls.flush().expect("flush");
    assert_eq!(status(&answer(&mut tls).expect("answer").0), 200);
    // Two requests in one write: the first is answered, the second never.
    tls.write_all(format!("{me}{me}").as_bytes())
        .expect("write");
    tls.flush().expect("flush");
    assert_eq!(status(&answer(&mut tls).expect("answer").0), 200);
    assert!(ends(&mut tls), "nothing after the first answer");
}

/// One request on a new TCP connection to `listener`, written down as a tailnet peer's
/// (`Some`) or as nothing (`None`, a local process). Returns the answer head and whether
/// a second request on the same connection got an answer.
fn twice_without_the_tunnel(
    listener: SocketAddr,
    peer: Option<&str>,
    request: &str,
) -> (String, bool) {
    let mut stream = TcpStream::connect(listener).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let _entry = peer.map(|peer| {
        front_peers::register(
            stream.local_addr().expect("local"),
            stream.peer_addr().expect("peer"),
            peer.parse().expect("peer address"),
        )
    });
    stream.write_all(request.as_bytes()).expect("write");
    let (head, _) = answer(&mut stream).expect("an answer");
    let _ = stream.write_all(request.as_bytes());
    let second = answer(&mut stream).is_some();
    (head, second)
}

#[test]
fn every_other_connection_serves_one_request_and_says_close() {
    let node = Node::start(NodeOptions::default());
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    let running = node.node().running();
    let local_route = running.tailnet_local_addr.expect("a local route listener");
    let public = running.public_addr.expect("a public listener");
    let local = running.addr;
    let (_, mac) = node.device_team("Questions");
    // A read that a tunnel stream keeps open (the test above).
    let me = get("/v1/me", Some(&mac.token));
    for (name, listener, peer) in [
        ("tailnet peer", tailnet, Some("100.64.0.9")),
        ("tailnet without the front", tailnet, None),
        ("local route", local_route, None),
        ("node listener", local, None),
        ("public listener", public, None),
    ] {
        let (head, second) = twice_without_the_tunnel(listener, peer, &me);
        assert!(closes(&head), "{name}: {head}");
        assert!(!second, "{name}: a second request was answered");
    }
    // A tunnel stream that reaches the public listener (a cloud agent through the
    // ingress) is not kept either: only the tailnet listener keeps device streams.
    let mut stream = TcpStream::connect(public).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let _entry = front_peers::register_tunnel(
        stream.local_addr().expect("local"),
        stream.peer_addr().expect("peer"),
    );
    stream
        .write_all(
            b"POST /mcp HTTP/1.1\r\nHost: k7m2q4x3ca.node.example.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("write");
    let (head, _) = answer(&mut stream).expect("an answer");
    assert!(closes(&head), "{head}");
}

#[test]
fn the_wait_for_a_next_request_is_between_the_kept_dial_and_the_front() {
    // The client closes a kept dial first (apassy::sync::KEPT_DIAL_IDLE), the front and
    // Connect later.
    assert_eq!(TUNNEL_KEEP_IDLE, Duration::from_secs(45));
    assert!(apassy::sync::KEPT_DIAL_IDLE + Duration::from_secs(10) <= TUNNEL_KEEP_IDLE);
    assert!(TUNNEL_KEEP_IDLE < FrontLimits::default().idle);
}
