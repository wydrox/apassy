//! The node's tunnel to Apassy Connect, end to end (ADR 0037 stage 7, plan s7 unit M4;
//! docs/contracts/connect-tunnel-v1.md). Synthetic values only; nothing leaves the
//! loopback.
//!
//! - **The loopback Connect** is the relay crate's own tunnel broker
//!   (`apassy_relay::server::tunnel::Broker`) behind the relay's own HTTP server (the
//!   vendored `tiny_http` with deadlines), routing `GET /v1/tunnel/node` and `GET
//!   /v1/tunnel/dial/{node}` to `Broker::serve_node` and `Broker::serve_dial` as
//!   `crates/apassy-relay/tests/server_tunnel.rs` does, and the relay's SNI and ACME
//!   ingress (`server::ingress::serve_sni`, `serve_acme`) on free ports. The relay has no
//!   `POST /v1/tunnel/nodes` route yet: this harness answers it (the `NodeView` of the
//!   contract) and adds the node to the broker's `MemoryDirectory`.
//! - **The node** is the app's node service (`apassy::node::Node`) with the real embedded
//!   relay, its tailnet route on the loopback test hook, and the Connect route on, with a
//!   test account seam (a fixed account token).
//! - **The dialing device** is the Rust client of the questions (the pieces the iPhone
//!   core uses) through a dial bridge: a loopback listener that turns each connection into
//!   a WebSocket dial (`/v1/tunnel/dial/{node}`), so the device's pinned TLS runs inside
//!   the dial, end to end with the node.
//! - **The ingress client** is an ordinary TLS client to the SNI ingress that trusts only
//!   the root of the fake CA.
//! - **The fake CA** is an ACME v2 server on the loopback that checks the JWS (ES256, the
//!   nonces, the URL), validates HTTP-01 through the ACME ingress (port 80 of Connect, so
//!   through the tunnel), and signs the CSR's key.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy::broker::SharedVault;
use apassy::broker::approvals::ApprovalQueue;
use apassy::broker::decide::BrokerContext;
use apassy::broker::http::TlsClient;
use apassy::broker::prompts::PromptStore;
use apassy::node::acme::AcmeOptions;
use apassy::node::funnel::{CliOutput, TailscaleCli};
use apassy::node::master_key::NoKeychain;
use apassy::node::tunnel::{
    CertState, Clock, ConnectSetup, Failure, SystemClock, TunnelAuth, TunnelState,
};
use apassy::node::{Node, NodeOptions};
use apassy::questions::{QuestionsClient, Sealed};
use apassy::sync::{PairedLink, PendingJoin, RelayMember, RelayUrl, TlsTrust, parse_pin};
use apassy::vault::Vault;
use apassy_relay::embedded::EmbeddedRelay;
use apassy_relay::server::ingress::{self, IngressConfig, IngressHandle};
use apassy_relay::server::tunnel::ws::{self, Message, client};
use apassy_relay::server::tunnel::{Broker, Limits, ManualClock, MemoryDirectory};
use base64_shim::{b64u_decode, b64u_encode};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned};
use serde_json::{Value, json};

const PASS: &str = "synthetic-connect-tunnel-pass";
const ZONE: &str = "node.example.test";
const NODE_ID: &str = "node_aaaaaaaaaa";
const PUBLIC_NAME: &str = "aaaaaaaaaa.node.example.test";
const ACCOUNT: &str = "acc_aaaaaaaaaa";
/// The account token of the node's device (the Mac).
const MAC_TOKEN: &str = "tok-synthetic-mac";
/// The account token of another device of the account (the iPhone).
const PHONE_TOKEN: &str = "tok-synthetic-phone";
const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
const KEY_ID: &str = "630dcd2966c43366";
const WAIT: Duration = Duration::from_secs(20);

/// Base64url without padding, without a crate this test does not have.
mod base64_shim {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    pub fn b64u_encode(input: &[u8]) -> String {
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            let take = chunk.len() + 1;
            for i in 0..take {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            }
        }
        out
    }

    pub fn b64u_decode(text: &str) -> Option<Vec<u8>> {
        let mut bits = 0u32;
        let mut count = 0;
        let mut out = Vec::new();
        for byte in text.bytes() {
            let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
            bits = (bits << 6) | value;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Small helpers.

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "apassy-connect-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe");
    probe.local_addr().expect("address").port()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting: {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn sealed(nonce: &str, ciphertext: &str) -> Sealed {
    Sealed {
        key_id: KEY_ID.to_owned(),
        nonce: nonce.to_owned(),
        ciphertext: ciphertext.to_owned(),
    }
}

/// No Tailscale on the test machine.
struct NoTailscale;

impl TailscaleCli for NoTailscale {
    fn run(&self, _args: &[&str]) -> Option<CliOutput> {
        None
    }
}

fn broker_context(vault: &SharedVault) -> BrokerContext {
    BrokerContext {
        vault: Arc::clone(vault),
        tls: TlsClient::platform().expect("tls"),
        approvals: Arc::new(ApprovalQueue::new()),
        approval_timeout: Duration::from_secs(20),
        run_timeout: Duration::from_secs(20),
        bouncer: None,
        model_gate: None,
        prompts: Arc::new(PromptStore::new(Vec::new())),
    }
}

/// A test account seam: one fixed account token of the node's device.
struct TestAuth {
    origin: String,
    entitled: AtomicBool,
    sign_outs: AtomicUsize,
}

impl TestAuth {
    fn new(origin: String) -> Arc<Self> {
        Arc::new(Self {
            origin,
            entitled: AtomicBool::new(true),
            sign_outs: AtomicUsize::new(0),
        })
    }
}

impl TunnelAuth for TestAuth {
    fn origin(&self) -> String {
        self.origin.clone()
    }

    fn with_token(&self, call: &mut dyn FnMut(&str) -> Result<(), Failure>) -> Result<(), Failure> {
        match call(MAC_TOKEN) {
            Err(Failure::Unauthenticated) => match call(MAC_TOKEN) {
                Err(Failure::Unauthenticated) => Err(Failure::NoAccount),
                other => other,
            },
            other => other,
        }
    }

    fn entitled(&self) -> Result<(), Failure> {
        if self.entitled.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Failure::NotEntitled)
        }
    }

    fn has_account(&self) -> bool {
        true
    }

    fn device_id(&self) -> Option<String> {
        Some("dev_aaaaaaaaaa".to_owned())
    }

    fn sign_out(&self) {
        self.sign_outs.fetch_add(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// The loopback Connect.

struct Connect {
    broker: Broker,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    registrations: Arc<AtomicUsize>,
    sni: IngressHandle,
    acme: IngressHandle,
}

fn header_of(request: &tiny_http::Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv(name))
        .map(|header| header.value.as_str().to_owned())
}

fn respond_json(request: tiny_http::Request, status: u16, body: &Value) {
    let response = tiny_http::Response::from_data(body.to_string().into_bytes())
        .with_status_code(status)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("header"),
        );
    let _ = request.respond(response);
}

impl Connect {
    fn start(clock: Arc<ManualClock>) -> Self {
        let directory = Arc::new(MemoryDirectory::new());
        directory.add_device(MAC_TOKEN, ACCOUNT, "dev_aaaaaaaaaa");
        directory.add_device(PHONE_TOKEN, ACCOUNT, "dev_bbbbbbbbbb");
        let limits = Limits {
            tick: Duration::from_millis(50),
            close_grace: Duration::from_millis(500),
            ..Limits::default()
        };
        let broker = Broker::new(directory.clone(), limits, clock, ZONE);
        let server = tiny_http::Server::http_with_deadlines(
            "127.0.0.1:0",
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
        .expect("server");
        let addr = server.server_addr().to_ip().expect("ip");
        let stop = Arc::new(AtomicBool::new(false));
        let registrations = Arc::new(AtomicUsize::new(0));
        let (routed, stopped, registry, counted) = (
            broker.clone(),
            Arc::clone(&stop),
            Arc::clone(&directory),
            Arc::clone(&registrations),
        );
        thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(50)) else {
                    continue;
                };
                let path = request.url().split('?').next().unwrap_or("").to_owned();
                if path == "/v1/tunnel/node" {
                    routed.serve_node(request);
                } else if let Some(node_id) = path.strip_prefix("/v1/tunnel/dial/") {
                    let node_id = node_id.to_owned();
                    routed.serve_dial(request, &node_id);
                } else if path == "/v1/tunnel/nodes" && request.method() == &tiny_http::Method::Post
                {
                    // The registration of contract 3.1, until the relay has the route.
                    if header_of(&request, "Authorization").as_deref()
                        != Some(&format!("Bearer {MAC_TOKEN}"))
                    {
                        respond_json(
                            request,
                            401,
                            &json!({"ok": false, "error": {"code": "unauthenticated", "message": "x"}}),
                        );
                        continue;
                    }
                    let mut body = String::new();
                    let _ = request.as_reader().read_to_string(&mut body);
                    let body: Value = serde_json::from_str(&body).unwrap_or_default();
                    registry.add_node(NODE_ID, ACCOUNT, "dev_aaaaaaaaaa");
                    counted.fetch_add(1, Ordering::SeqCst);
                    respond_json(
                        request,
                        200,
                        &json!({"ok": true, "result": {
                            "node_id": NODE_ID,
                            "account_id": ACCOUNT,
                            "device_id": "dev_aaaaaaaaaa",
                            "name": body["name"],
                            "pin": body["pin"],
                            "public_name": PUBLIC_NAME,
                            "online": false,
                            "created_at": 1_790_000_000u64,
                        }}),
                    );
                } else {
                    let _ = request.respond(tiny_http::Response::empty(404));
                }
            }
        });
        let sni = ingress::serve_sni(
            TcpListener::bind("127.0.0.1:0").expect("sni"),
            broker.clone(),
            IngressConfig::default(),
        )
        .expect("sni ingress");
        let acme = ingress::serve_acme(
            TcpListener::bind("127.0.0.1:0").expect("acme"),
            broker.clone(),
            IngressConfig::default(),
        )
        .expect("acme ingress");
        Self {
            broker,
            addr,
            stop,
            registrations,
            sni,
            acme,
        }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    fn open_streams(&self) -> usize {
        self.broker.usage(ACCOUNT).open_streams
    }

    /// A dial WebSocket of the iPhone to the node.
    fn dial(&self) -> Result<WsStream, (u16, String)> {
        let mut stream = TcpStream::connect(self.addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        match client::handshake(
            &mut stream,
            "connect.test",
            &format!("/v1/tunnel/dial/{NODE_ID}"),
            Some(PHONE_TOKEN),
        ) {
            Ok(()) => Ok(WsStream::new(stream)),
            Err(client::HandshakeError::Refused(refused)) => {
                let body: Value = serde_json::from_slice(&refused.body).unwrap_or_default();
                Err((
                    refused.status,
                    body["error"]["code"].as_str().unwrap_or("").to_owned(),
                ))
            }
            Err(other) => panic!("dial: {other:?}"),
        }
    }
}

impl Drop for Connect {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.sni.stop();
        self.acme.stop();
        self.broker.stop();
    }
}

/// The bytes of a dial WebSocket as one stream (the client side of the dial).
struct WsStream {
    reader: ws::Reader<TcpStream>,
    writer: TcpStream,
    pending: Vec<u8>,
    /// The close code, once the dial closed.
    closed: Option<Option<u16>>,
}

impl WsStream {
    fn new(stream: TcpStream) -> Self {
        let writer = stream.try_clone().expect("clone");
        Self {
            reader: ws::Reader::client(stream, 1 << 20),
            writer,
            pending: Vec::new(),
            closed: None,
        }
    }

    /// Read until the dial closes; the close code.
    fn wait_close(&mut self) -> Option<u16> {
        let mut buffer = [0u8; 4096];
        while self.closed.is_none() {
            match self.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        self.closed.flatten()
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pending.is_empty() {
            if self.closed.is_some() {
                return Ok(0);
            }
            match self.reader.read_message() {
                Ok(Message::Binary(bytes)) => self.pending = bytes,
                Ok(Message::Ping(payload)) => {
                    let _ = client::send(&mut self.writer, ws::OP_PONG, &payload);
                }
                Ok(Message::Close(code)) => {
                    self.closed = Some(code);
                    return Ok(0);
                }
                Ok(_) => {}
                Err(ws::WsError::Io(error)) => {
                    self.closed = Some(None);
                    return Err(error);
                }
                Err(_) => {
                    self.closed = Some(None);
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(16 * 1024);
        client::send(&mut self.writer, ws::OP_BINARY, &buf[..n])?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A loopback listener that carries each connection through a dial of the iPhone: the
/// device's own transport to Connect in this test.
struct DialBridge {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl DialBridge {
    fn start(connect_addr: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bridge");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (counted, stopped) = (Arc::clone(&connections), Arc::clone(&stop));
        thread::spawn(move || {
            for incoming in listener.incoming() {
                if stopped.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(local) = incoming else { continue };
                counted.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || bridge(local, connect_addr));
            }
        });
        Self {
            addr,
            connections,
            stop,
        }
    }
}

impl Drop for DialBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn bridge(local: TcpStream, connect_addr: SocketAddr) {
    let mut remote = TcpStream::connect(connect_addr).expect("connect");
    if client::handshake(
        &mut remote,
        "connect.test",
        &format!("/v1/tunnel/dial/{NODE_ID}"),
        Some(PHONE_TOKEN),
    )
    .is_err()
    {
        let _ = local.shutdown(Shutdown::Both);
        return;
    }
    let mut up_local = local.try_clone().expect("clone");
    let mut up_remote = remote.try_clone().expect("clone");
    let up = thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match up_local.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    let _ = client::send(&mut up_remote, ws::OP_CLOSE, &ws::close_payload(1000));
                    return;
                }
                Ok(n) => {
                    if client::send(&mut up_remote, ws::OP_BINARY, &buffer[..n]).is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut down_local = local;
    let mut reader = ws::Reader::client(remote.try_clone().expect("clone"), 1 << 20);
    loop {
        match reader.read_message() {
            Ok(Message::Binary(bytes)) => {
                if down_local.write_all(&bytes).is_err() {
                    break;
                }
            }
            Ok(Message::Ping(payload)) => {
                let _ = client::send(&mut remote, ws::OP_PONG, &payload);
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = down_local.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    let _ = up.join();
}

// ---------------------------------------------------------------------------
// TLS clients of the test.

/// A verifier that accepts any certificate and keeps the leaf it saw: the tests of which
/// certificate the node serves.
#[derive(Debug)]
struct Capture {
    leaf: Arc<Mutex<Option<Vec<u8>>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.leaf.lock().expect("leaf") = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
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
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS handshake over `transport` to `server_name`; the leaf the server showed, or the
/// error.
fn served_leaf<S: Read + Write>(transport: S, server_name: &str) -> Result<Vec<u8>, String> {
    let leaf = Arc::new(Mutex::new(None));
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture {
            leaf: Arc::clone(&leaf),
            provider: provider(),
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(server_name.to_owned()).expect("name");
    let conn = ClientConnection::new(Arc::new(config), name).expect("client");
    let mut tls = StreamOwned::new(conn, transport);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|error| error.to_string())?;
    }
    let seen = leaf.lock().expect("leaf").clone();
    seen.ok_or_else(|| "no certificate".to_owned())
}

/// One HTTP/1.1 request of a cloud agent through the SNI ingress, with TLS that trusts
/// only `root`. The status, the headers, and the body.
fn agent_request(sni: SocketAddr, root: &[u8], request: &[u8]) -> (u16, String, Vec<u8>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.to_vec()))
        .expect("root");
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(PUBLIC_NAME.to_owned()).expect("name");
    let conn = ClientConnection::new(Arc::new(config), name).expect("client");
    let tcp = TcpStream::connect(sni).expect("ingress");
    tcp.set_read_timeout(Some(WAIT)).expect("timeout");
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(request).expect("request");
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, head.to_owned(), body.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// The fake ACME CA.

/// A tiny DER reader: one TLV.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    Some((tag, &rest[..length], &rest[length..]))
}

/// The EC point of the subject key of a CSR (PKCS #10).
fn csr_point(csr: &[u8]) -> Vec<u8> {
    let (_, request, _) = tlv(csr).expect("csr");
    let (_, info, _) = tlv(request).expect("info");
    let (_, _version, rest) = tlv(info).expect("version");
    let (_, _subject, rest) = tlv(rest).expect("subject");
    let (_, spki, _) = tlv(rest).expect("spki");
    let (_, _algorithm, rest) = tlv(spki).expect("algorithm");
    let (tag, bits, _) = tlv(rest).expect("key");
    assert_eq!(tag, 0x03);
    bits[1..].to_vec()
}

struct CsrKey(Vec<u8>);

impl rcgen::PublicKeyData for CsrKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

#[derive(Default)]
struct CaState {
    nonces: HashSet<String>,
    next_nonce: u64,
    /// The account key (X9.63 point) of the account.
    account: Option<Vec<u8>>,
    thumbprint: String,
    token: String,
    authz: String,
    order: String,
    chain: Option<String>,
    bad_nonce_sent: bool,
    validations: Vec<(String, u16, Vec<u8>)>,
    jose_types: Vec<String>,
}

struct FakeCa {
    base: String,
    root_der: Vec<u8>,
    state: Arc<Mutex<CaState>>,
}

fn http_answer(status: u16, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

impl FakeCa {
    fn start(acme_ingress: SocketAddr) -> Self {
        let mut root = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Synthetic ACME test root");
        root.distinguished_name = name;
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let year = 1970 + i32::try_from(now() / 31_556_952).unwrap_or(56);
        root.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
        root.not_after = rcgen::date_time_ymd(year + 2, 1, 1);
        let root_key = KeyPair::generate().expect("root key");
        let root_cert = root.self_signed(&root_key).expect("root");
        let root_der = root_cert.der().to_vec();
        let root_pem = root_cert.pem();
        let issuer = Arc::new(Issuer::new(root, root_key));
        let listener = TcpListener::bind("127.0.0.1:0").expect("ca");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let state = Arc::new(Mutex::new(CaState::default()));
        let (thread_state, thread_base) = (Arc::clone(&state), base.clone());
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (state, base, issuer, root_pem) = (
                    Arc::clone(&thread_state),
                    thread_base.clone(),
                    Arc::clone(&issuer),
                    root_pem.clone(),
                );
                thread::spawn(move || {
                    ca_serve(stream, &state, &base, &issuer, &root_pem, acme_ingress);
                });
            }
        });
        Self {
            base,
            root_der,
            state,
        }
    }

    fn directory(&self) -> String {
        format!("{}/directory", self.base)
    }
}

/// A request of the fake CA: the method, the path, the headers, and the body.
type CaRequest = (String, String, HashMap<String, String>, Vec<u8>);

fn read_request(stream: &mut TcpStream) -> Option<CaRequest> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).ok()?;
    Some((method, path, headers, body))
}

fn ca_serve(
    mut stream: TcpStream,
    state: &Mutex<CaState>,
    base: &str,
    issuer: &Issuer<'static, KeyPair>,
    root_pem: &str,
    acme_ingress: SocketAddr,
) {
    let Some((method, path, headers, body)) = read_request(&mut stream) else {
        return;
    };
    let nonce = {
        let mut state = state.lock().expect("state");
        state.next_nonce += 1;
        let nonce = format!("synthetic-nonce-{}", state.next_nonce);
        state.nonces.insert(nonce.clone());
        nonce
    };
    let json_headers = |extra: Vec<(&'static str, String)>| {
        let mut all = vec![
            ("Replay-Nonce", nonce.clone()),
            ("Content-Type", "application/json".to_owned()),
        ];
        all.extend(extra);
        all
    };
    let answer = if method == "GET" && path == "/directory" {
        let body = json!({
            "newNonce": format!("{base}/nonce"),
            "newAccount": format!("{base}/acct"),
            "newOrder": format!("{base}/order"),
        });
        http_answer(200, &json_headers(vec![]), body.to_string().as_bytes())
    } else if method == "GET" && path == "/nonce" {
        http_answer(204, &[("Replay-Nonce", nonce.clone())], b"")
    } else if method == "POST" {
        ca_post(
            state,
            base,
            issuer,
            root_pem,
            acme_ingress,
            &path,
            &headers,
            &body,
            &nonce,
        )
    } else {
        http_answer(404, &[], b"")
    };
    let _ = stream.write_all(&answer);
}

fn problem(nonce: &str, status: u16, kind: &str) -> Vec<u8> {
    http_answer(
        status,
        &[
            ("Replay-Nonce", nonce.to_owned()),
            ("Content-Type", "application/problem+json".to_owned()),
        ],
        json!({"type": format!("urn:ietf:params:acme:error:{kind}"), "detail": kind})
            .to_string()
            .as_bytes(),
    )
}

#[allow(clippy::too_many_arguments)]
fn ca_post(
    state: &Mutex<CaState>,
    base: &str,
    issuer: &Issuer<'static, KeyPair>,
    root_pem: &str,
    acme_ingress: SocketAddr,
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    nonce: &str,
) -> Vec<u8> {
    state
        .lock()
        .expect("state")
        .jose_types
        .push(headers.get("content-type").cloned().unwrap_or_default());
    let jws: Value = serde_json::from_slice(body).unwrap_or_default();
    let (Some(protected_b64), Some(payload_b64), Some(signature_b64)) = (
        jws["protected"].as_str(),
        jws["payload"].as_str(),
        jws["signature"].as_str(),
    ) else {
        return problem(nonce, 400, "malformed");
    };
    let protected: Value =
        serde_json::from_slice(&b64u_decode(protected_b64).unwrap_or_default()).unwrap_or_default();
    let url = format!("{base}{path}");
    if protected["alg"] != "ES256" || protected["url"] != url.as_str() {
        return problem(nonce, 400, "malformed");
    }
    let used = protected["nonce"].as_str().unwrap_or_default().to_owned();
    {
        let mut state = state.lock().expect("state");
        // The first signed request gets one badNonce: the client must retry.
        if !state.bad_nonce_sent {
            state.bad_nonce_sent = true;
            state.nonces.remove(&used);
            drop(state);
            return problem(nonce, 400, "badNonce");
        }
        if !state.nonces.remove(&used) {
            drop(state);
            return problem(nonce, 400, "badNonce");
        }
    }
    let point = if path == "/acct" {
        let jwk = &protected["jwk"];
        let mut point = vec![4u8];
        point.extend(b64u_decode(jwk["x"].as_str().unwrap_or_default()).unwrap_or_default());
        point.extend(b64u_decode(jwk["y"].as_str().unwrap_or_default()).unwrap_or_default());
        let thumb_input = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap_or_default(),
            jwk["y"].as_str().unwrap_or_default()
        );
        let thumbprint = b64u_encode(
            ring::digest::digest(&ring::digest::SHA256, thumb_input.as_bytes()).as_ref(),
        );
        let mut state = state.lock().expect("state");
        state.account = Some(point.clone());
        state.thumbprint = thumbprint;
        point
    } else {
        if protected["kid"] != format!("{base}/acct/1").as_str() {
            return problem(nonce, 401, "unauthorized");
        }
        match state.lock().expect("state").account.clone() {
            Some(point) => point,
            None => return problem(nonce, 400, "accountDoesNotExist"),
        }
    };
    let signature = b64u_decode(signature_b64).unwrap_or_default();
    let input = format!("{protected_b64}.{payload_b64}");
    if UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(input.as_bytes(), &signature)
        .is_err()
    {
        return problem(nonce, 400, "malformed");
    }
    let payload: Value = if payload_b64.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&b64u_decode(payload_b64).unwrap_or_default()).unwrap_or_default()
    };
    let ok = |status: u16, extra: Vec<(&'static str, String)>, body: Value| {
        let mut all = vec![
            ("Replay-Nonce", nonce.to_owned()),
            ("Content-Type", "application/json".to_owned()),
        ];
        all.extend(extra);
        http_answer(status, &all, body.to_string().as_bytes())
    };
    let order_body = |state: &CaState| {
        let mut order = json!({
            "status": state.order,
            "identifiers": [{"type": "dns", "value": PUBLIC_NAME}],
            "authorizations": [format!("{base}/authz/1")],
            "finalize": format!("{base}/finalize/1"),
        });
        if state.chain.is_some() {
            order["certificate"] = json!(format!("{base}/cert/1"));
        }
        order
    };
    match path {
        "/acct" => {
            assert_eq!(payload["termsOfServiceAgreed"], true);
            ok(
                201,
                vec![("Location", format!("{base}/acct/1"))],
                json!({"status": "valid"}),
            )
        }
        "/order" => {
            assert_eq!(payload["identifiers"][0]["value"], PUBLIC_NAME);
            let mut state = state.lock().expect("state");
            state.token = "synthetic_token-0123456789".to_owned();
            state.authz = "pending".to_owned();
            state.order = "pending".to_owned();
            let body = order_body(&state);
            ok(201, vec![("Location", format!("{base}/order/1"))], body)
        }
        "/authz/1" => {
            let state = state.lock().expect("state");
            ok(
                200,
                vec![],
                json!({
                    "status": state.authz,
                    "identifier": {"type": "dns", "value": PUBLIC_NAME},
                    "challenges": [{
                        "type": "http-01",
                        "url": format!("{base}/chall/1"),
                        "token": state.token,
                        "status": state.authz,
                    }],
                }),
            )
        }
        "/chall/1" => {
            // HTTP-01: the CA fetches the token from port 80 of Connect, with the public name.
            let (token, thumbprint) = {
                let state = state.lock().expect("state");
                (state.token.clone(), state.thumbprint.clone())
            };
            let mut probe = TcpStream::connect(acme_ingress).expect("acme ingress");
            probe.set_read_timeout(Some(WAIT)).expect("timeout");
            probe
                .write_all(
                    format!(
                        "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {PUBLIC_NAME}\r\nUser-Agent: synthetic-ca\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .expect("probe");
            let mut answer = Vec::new();
            let _ = probe.read_to_end(&mut answer);
            let text = String::from_utf8_lossy(&answer).into_owned();
            let status = text
                .split(' ')
                .nth(1)
                .and_then(|code| code.parse().ok())
                .unwrap_or(0);
            let body = text
                .split_once("\r\n\r\n")
                .map_or("", |(_, body)| body)
                .to_owned();
            let mut state = state.lock().expect("state");
            state
                .validations
                .push((token.clone(), status, body.clone().into_bytes()));
            state.authz = if status == 200 && body == format!("{token}.{thumbprint}") {
                "valid".to_owned()
            } else {
                "invalid".to_owned()
            };
            if state.authz == "valid" {
                state.order = "ready".to_owned();
            }
            ok(
                200,
                vec![],
                json!({"type": "http-01", "url": format!("{base}/chall/1"), "token": token, "status": "processing"}),
            )
        }
        "/finalize/1" => {
            let csr = b64u_decode(payload["csr"].as_str().unwrap_or_default()).unwrap_or_default();
            let key = CsrKey(csr_point(&csr));
            let mut leaf = CertificateParams::new(vec![PUBLIC_NAME.to_owned()]).expect("leaf");
            let year = 1970 + i32::try_from(now() / 31_556_952).unwrap_or(56);
            leaf.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
            leaf.not_after = rcgen::date_time_ymd(year + 1, 6, 1);
            leaf.use_authority_key_identifier_extension = true;
            let cert = leaf.signed_by(&key, issuer).expect("signed");
            let mut state = state.lock().expect("state");
            state.chain = Some(format!("{}{root_pem}", cert.pem()));
            state.order = "valid".to_owned();
            let body = order_body(&state);
            ok(200, vec![], body)
        }
        "/order/1" => {
            let state = state.lock().expect("state");
            let body = order_body(&state);
            ok(200, vec![], body)
        }
        "/cert/1" => {
            let chain = state
                .lock()
                .expect("state")
                .chain
                .clone()
                .unwrap_or_default();
            http_answer(
                200,
                &[
                    ("Replay-Nonce", nonce.to_owned()),
                    (
                        "Content-Type",
                        "application/pem-certificate-chain".to_owned(),
                    ),
                ],
                chain.as_bytes(),
            )
        }
        _ => problem(nonce, 404, "malformed"),
    }
}

// ---------------------------------------------------------------------------
// The node.

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("file").permissions().mode() & 0o777
}

fn setup(connect: &Connect, acme: Option<AcmeOptions>, clock: Arc<dyn Clock>) -> ConnectSetup {
    let mut setup = ConnectSetup::new(TestAuth::new(connect.origin()));
    setup.acme = acme;
    setup.clock = clock;
    setup
}

fn tunnel_state(node: &Node) -> Option<TunnelState> {
    node.connect_status().tunnel.map(|tunnel| tunnel.state)
}

/// The main path: a node with its tunnel, the public certificate through ACME, a cloud
/// agent through the SNI ingress, the certificate separation both ways, a device's
/// question round trip through a dial, and lock and quit.
#[test]
fn the_tunnel_carries_dials_public_agents_and_acme_and_ends_with_the_node() {
    let dir = TempDir::new("main");
    let connect = Connect::start(Arc::new(ManualClock::new(now())));
    let ca = FakeCa::start(connect.acme.addr);
    let port = free_port();
    let mut vault = Vault::create(&dir.0.join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault.set_cloud_tailnet_on(true).expect("tailnet on");
    vault.set_cloud_tailnet_port(Some(port)).expect("port");
    vault.set_cloud_route_on(true).expect("remote access on");
    let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let node_dir = dir.0.join("node");
    let node = Node::new(NodeOptions {
        backend: Arc::new(EmbeddedRelay::default()),
        keys: Arc::new(NoKeychain),
        cli: Arc::new(NoTailscale),
        data_dir: node_dir.clone(),
    })
    .with_test_tailnet();
    let mut acme = AcmeOptions::new(&ca.directory());
    acme.poll_every = Duration::from_millis(50);
    node.set_connect(Some(setup(
        &connect,
        Some(acme),
        Arc::new(SystemClock::default()),
    )));
    node.set_connect_route(true).expect("the Connect route on");

    // Phase A: the tailnet route and the Connect route.
    node.start(&vault, broker_context(&vault))
        .expect("the node starts");
    let status = node.status(&vault);
    assert!(status.running, "{:?}", status.warnings);
    let pin = status.tailnet.pin.clone().expect("a pin");
    wait_until("the tunnel is on", || {
        tunnel_state(&node) == Some(TunnelState::On) && connect.broker.online(NODE_ID)
    });
    assert_eq!(
        connect.registrations.load(Ordering::SeqCst),
        1,
        "one registration"
    );
    let route = node.connect_status();
    assert_eq!(route.public_name.as_deref(), Some(PUBLIC_NAME));
    assert_eq!(
        route
            .tunnel
            .as_ref()
            .and_then(|tunnel| tunnel.url.clone())
            .as_deref(),
        Some("https://aaaaaaaaaa.node.example.test/mcp")
    );

    // ACME: the fake CA validated HTTP-01 through port 80 of Connect and the tunnel.
    wait_until("the certificate is installed", || {
        matches!(
            node.connect_status()
                .tunnel
                .map(|tunnel| tunnel.certificate),
            Some(CertState::Valid { .. })
        )
    });
    {
        let state = ca.state.lock().expect("state");
        assert_eq!(state.validations.len(), 1);
        assert_eq!(state.validations[0].1, 200, "the node answered its token");
        assert!(
            state
                .jose_types
                .iter()
                .all(|kind| kind == "application/jose+json"),
            "{:?}",
            state.jose_types
        );
    }
    let connect_dir = node_dir.join("connect");
    for file in [
        "public-key.der",
        "public-chain.pem",
        "acme-account.der",
        "node.json",
    ] {
        assert_eq!(mode_of(&connect_dir.join(file)), 0o600, "{file}");
    }
    assert_eq!(mode_of(&connect_dir), 0o700);
    // The node answers nothing but its pending token on the ACME path (none now).
    let mut probe = TcpStream::connect(connect.acme.addr).expect("acme");
    probe.set_read_timeout(Some(WAIT)).expect("timeout");
    probe
        .write_all(
            format!(
                "GET /.well-known/acme-challenge/synthetic_token-0123456789 HTTP/1.1\r\nHost: {PUBLIC_NAME}\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("probe");
    let mut answer = Vec::new();
    let _ = probe.read_to_end(&mut answer);
    assert!(
        answer.starts_with(b"HTTP/1.1 404"),
        "{}",
        String::from_utf8_lossy(&answer)
    );

    // A cloud agent through the SNI ingress reaches /mcp of the public listener, and
    // /v1/me is not there (Scope::Public).
    let (status_me, _, _) = agent_request(
        connect.sni.addr,
        &ca.root_der,
        format!("GET /v1/me HTTP/1.1\r\nHost: {PUBLIC_NAME}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    assert_eq!(status_me, 404, "/v1/me is not on the public listener");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let (status_mcp, head, _) = agent_request(
        connect.sni.addr,
        &ca.root_der,
        format!(
            "POST /mcp HTTP/1.1\r\nHost: {PUBLIC_NAME}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    assert_eq!(status_mcp, 401, "{head}");
    assert!(
        head.to_ascii_lowercase().contains(
            "resource_metadata=\"https://aaaaaaaaaa.node.example.test/.well-known/oauth-protected-resource"
        ),
        "the MCP endpoint of the node names its public name: {head}"
    );

    // The certificates, both ways.
    let node_pin = parse_pin(&pin).expect("pin");
    let public_leaf = {
        let tcp = TcpStream::connect(connect.sni.addr).expect("ingress");
        tcp.set_read_timeout(Some(WAIT)).expect("timeout");
        served_leaf(tcp, PUBLIC_NAME).expect("the public stream has a certificate")
    };
    assert!(
        !node_pin.matches(&public_leaf),
        "the node certificate is not public"
    );
    assert!(apassy::node::acme::covers(&public_leaf, PUBLIC_NAME));
    let device_leaf = served_leaf(connect.dial().expect("dial"), "device.example.test")
        .expect("a device dial has a certificate");
    assert!(
        node_pin.matches(&device_leaf),
        "a dial gets the pinned node certificate"
    );
    assert_ne!(device_leaf, public_leaf);
    let refused = served_leaf(connect.dial().expect("dial"), PUBLIC_NAME);
    assert!(
        refused.is_err(),
        "a dial that names the public name gets no certificate at all: {refused:?}"
    );

    // Pairing over the tailnet front (phase A).
    let membership = node
        .ensure_questions_team(&vault, "Synthetic Mac")
        .expect("the questions team");
    let origin = format!("https://127.0.0.1:{port}");
    assert_eq!(membership.relay_url, origin);
    let (mac, code) = node.pairing_link(&vault).expect("a pairing link");
    let paired = PairedLink::parse(&code.link).expect("link");
    assert_eq!(paired.origin, origin);
    apassy::sync::clear_local_route(&origin);
    let pending = PendingJoin::request(&code.link, "", "Synthetic iPhone").expect("join");
    let links = mac.pending_links(Some(&code)).expect("links");
    let device = mac.confirm_link(&links[0]).expect("confirm");
    let end = Instant::now() + WAIT;
    let joined = loop {
        if let Some(joined) = pending.poll().expect("poll") {
            break joined;
        }
        assert!(Instant::now() < end, "the join was not confirmed");
        thread::sleep(Duration::from_millis(100));
    };
    let phone_key = joined.key_pkcs8().expect("key");
    mac.close();

    // Phase B: the tailnet route off. The node keeps the origin that the devices paired
    // with, and the devices reach it only through Connect.
    node.stop();
    {
        let mut guard = vault.lock().expect("vault");
        guard
            .as_mut()
            .expect("vault")
            .set_cloud_tailnet_on(false)
            .expect("tailnet off");
    }
    node.start(&vault, broker_context(&vault))
        .expect("the node starts on Connect");
    assert!(!node.tailnet_running(), "no front");
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
        "nothing listens on the tailnet port"
    );
    wait_until("the tunnel is on again", || {
        tunnel_state(&node) == Some(TunnelState::On) && connect.broker.online(NODE_ID)
    });
    let bridge = DialBridge::start(connect.addr);
    let through_connect = |team: &str, device_id: u64, key| {
        let url = RelayUrl::parse_with_trust(&origin, TlsTrust::Pinned(node_pin))
            .expect("url")
            .alternatives(&[format!("127.0.0.1:{}", bridge.addr.port())])
            .expect("alternative");
        QuestionsClient::from_member(
            RelayMember::with_url(url, team, device_id, key).expect("member"),
        )
    };
    let mac = through_connect(
        &membership.team_id,
        membership.device_id,
        membership.key_pkcs8.clone(),
    );
    let phone = through_connect(&membership.team_id, device.id, phone_key);
    let streams_before = connect.broker.usage(ACCOUNT).streams;
    let card = sealed(
        "AAECAwQFBgcICQoL",
        "c3ludGhldGljIHF1ZXN0aW9uIGNhcmQgY2lwaGVydGV4dCAwMDAx",
    );
    mac.post_question(QID, "member", now() + 300, &card)
        .expect("post through Connect");
    let listed = phone.list(0, Duration::ZERO).expect("list through Connect");
    let question = listed
        .questions
        .iter()
        .find(|question| question.qid == QID)
        .expect("the device sees the question");
    assert_eq!(
        question.ciphertext, card.ciphertext,
        "the digest input is unchanged"
    );
    assert_eq!(question.from_device_id, membership.device_id);
    phone
        .post_answer(
            QID,
            &sealed(
                "AQIDBAUGBwgJCgsM",
                "c3ludGhldGljIGFuc3dlciBjaXBoZXJ0ZXh0IGJvZHkgMDAwMg",
            ),
        )
        .expect("answer");
    let answers = mac.answers(QID, 0, Duration::ZERO).expect("answers");
    assert_eq!(answers.answers.len(), 1);
    assert_eq!(answers.answers[0].device_id, device.id);
    mac.settle(
        QID,
        &sealed(
            "AgMEBQYHCAkKCwwN",
            "c3ludGhldGljIHNldHRsZSBjaXBoZXJ0ZXh0IGJvZHkgMDAwMw",
        ),
    )
    .expect("settle");
    assert!(
        bridge.connections.load(Ordering::SeqCst) > 0,
        "the device used the dial"
    );
    assert!(
        connect.broker.usage(ACCOUNT).streams > streams_before,
        "the requests were streams of the tunnel"
    );
    phone.close();
    mac.close();

    // Lock: the tunnel closes, and an open dial ends.
    let mut open_dial = connect.dial().expect("an open dial");
    wait_until("the dial is a stream", || connect.open_streams() >= 1);
    node.stop();
    assert_eq!(tunnel_state(&node), None, "no tunnel after a stop");
    assert!(
        !connect.broker.online(NODE_ID),
        "the node WebSocket is closed"
    );
    let code = open_dial.wait_close();
    assert!(
        matches!(code, Some(4001) | None),
        "the dial ends with the node: {code:?}"
    );
    wait_until("no stream survives", || connect.open_streams() == 0);
    assert_eq!(
        connect.dial().map(|_| ()),
        Err((503, "tunnel_offline".to_owned())),
        "a dial after the lock finds no node"
    );

    // Quit: the drop of the node service closes the tunnel too.
    node.start(&vault, broker_context(&vault))
        .expect("start again");
    wait_until("the tunnel is on for the quit", || {
        connect.broker.online(NODE_ID)
    });
    drop(node);
    wait_until("the quit closed the tunnel", || {
        !connect.broker.online(NODE_ID)
    });
    assert_eq!(connect.open_streams(), 0);
}

// ---------------------------------------------------------------------------
// The outage.

/// A clock that moves only when the test moves it.
#[derive(Default)]
struct HandClock {
    now: AtomicU64,
}

impl HandClock {
    fn advance(&self, by: Duration) {
        self.now
            .fetch_add(u64::try_from(by.as_millis()).unwrap_or(0), Ordering::SeqCst);
    }
}

impl Clock for HandClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.now.load(Ordering::SeqCst))
    }

    fn wait(&self, duration: Duration, stop: &AtomicBool) -> bool {
        let until = self.now() + duration;
        while self.now() < until {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
        true
    }
}

/// A TCP proxy in front of Connect that the test can cut: an outage of Connect for the
/// node.
struct Proxy {
    addr: SocketAddr,
    down: Arc<AtomicBool>,
    live: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy");
        let addr = listener.local_addr().expect("addr");
        let down = Arc::new(AtomicBool::new(false));
        let live = Arc::new(Mutex::new(Vec::new()));
        let (thread_down, thread_live) = (Arc::clone(&down), Arc::clone(&live));
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(client) = incoming else { continue };
                if thread_down.load(Ordering::SeqCst) {
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(upstream) = TcpStream::connect(target) else {
                    continue;
                };
                {
                    let mut live = thread_live.lock().expect("live");
                    live.push(client.try_clone().expect("clone"));
                    live.push(upstream.try_clone().expect("clone"));
                }
                let (mut a, mut b) = (
                    client.try_clone().expect("a"),
                    upstream.try_clone().expect("b"),
                );
                thread::spawn(move || {
                    let _ = io::copy(&mut a, &mut b);
                    let _ = b.shutdown(Shutdown::Both);
                });
                let (mut c, mut d) = (upstream, client);
                thread::spawn(move || {
                    let _ = io::copy(&mut c, &mut d);
                    let _ = d.shutdown(Shutdown::Both);
                });
            }
        });
        Self { addr, down, live }
    }

    fn cut(&self) {
        self.down.store(true, Ordering::SeqCst);
        for stream in self.live.lock().expect("live").drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
    }
}

#[test]
fn an_outage_reconnects_within_thirty_seconds_on_a_fake_clock_and_ends_open_streams() {
    let dir = TempDir::new("outage");
    let connect = Connect::start(Arc::new(ManualClock::new(now())));
    let proxy = Proxy::start(connect.addr);
    let mut vault = Vault::create(&dir.0.join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let node = Node::new(NodeOptions {
        backend: Arc::new(EmbeddedRelay::default()),
        keys: Arc::new(NoKeychain),
        cli: Arc::new(NoTailscale),
        data_dir: dir.0.join("node"),
    });
    let clock = Arc::new(HandClock::default());
    let mut setup = ConnectSetup::new(TestAuth::new(format!(
        "http://127.0.0.1:{}",
        proxy.addr.port()
    )));
    setup.acme = None;
    setup.clock = clock.clone();
    node.set_connect(Some(setup));
    node.set_connect_route(true).expect("route on");
    // Only the Connect route: the node runs for it alone.
    {
        let guard = vault.lock().expect("vault");
        assert!(node.wanted_here(guard.as_ref().expect("vault")).is_some());
        assert!(Node::wanted(guard.as_ref().expect("vault")).is_none());
    }
    node.start(&vault, broker_context(&vault))
        .expect("the node starts on Connect");
    wait_until("the tunnel is on", || {
        tunnel_state(&node) == Some(TunnelState::On) && connect.broker.online(NODE_ID)
    });
    let connects = || {
        node.connect_status()
            .tunnel
            .map_or(0, |tunnel| tunnel.connects)
    };
    assert_eq!(connects(), 1);

    // A device stream is open (a pinned TLS session inside a dial).
    let mut dial = connect.dial().expect("dial");
    let leaf = served_leaf(&mut dial, "device.example.test").expect("handshake");
    assert!(!leaf.is_empty());
    wait_until("one open stream", || {
        node.connect_status()
            .tunnel
            .is_some_and(|tunnel| tunnel.open_streams == 1)
    });

    // The outage starts.
    let started = clock.now();
    proxy.cut();
    wait_until("the node sees the outage", || {
        matches!(tunnel_state(&node), Some(TunnelState::Reconnecting { .. }))
    });
    // The open stream ends cleanly: the dial closes, nothing is left at the node.
    let code = dial.wait_close();
    assert!(matches!(code, Some(4001) | None), "{code:?}");
    assert_eq!(
        node.connect_status()
            .tunnel
            .map(|tunnel| tunnel.open_streams),
        Some(0)
    );
    wait_until("the broker has no stream", || connect.open_streams() == 0);

    // Connect is back after 10 s of the fake clock; the node is back within 30 s.
    let mut restored = false;
    for _ in 0..120 {
        if connects() >= 2 {
            break;
        }
        clock.advance(Duration::from_millis(500));
        if !restored && clock.now() - started >= Duration::from_secs(10) {
            proxy.restore();
            restored = true;
        }
        thread::sleep(Duration::from_millis(40));
    }
    assert!(connects() >= 2, "the node reconnected");
    let at = node
        .connect_status()
        .tunnel
        .and_then(|tunnel| tunnel.connected_at)
        .expect("connected at");
    assert!(
        at - started <= Duration::from_secs(30),
        "reconnected after {:?} of the fake clock",
        at - started
    );
    wait_until("online again", || connect.broker.online(NODE_ID));
    let attempts = node
        .connect_status()
        .tunnel
        .map_or(0, |tunnel| tunnel.attempts);
    assert!(attempts >= 3, "tries during the outage: {attempts}");
    node.stop();
    assert!(!connect.broker.online(NODE_ID));
}
