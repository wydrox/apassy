//! The node's side of the Connect tunnel against the contract (plan s7 unit M4;
//! docs/contracts/connect-tunnel-v1.md). Synthetic values only.
//!
//! - The vectors of `tests/fixtures/connect-tunnel-v1/frames.json` through the codec that
//!   the node uses (`apassy::node::tunnel::frame`, the relay crate's own source).
//! - A fake Connect made of the same code's server side (`ws::check_upgrade`,
//!   `ws::Reader::server`) talks to a running [`Tunnel`]: the handshake carries the
//!   account token and the subprotocol, the node pings and ends a silent WebSocket, the
//!   node never opens a stream and resets a stream that breaks a rule, it answers an
//!   `acme` stream with `404` unless it is its own token, it closes a WebSocket with 1002
//!   for a malformed frame and 1003 for a text message, and a stop closes with 1000.
//!
//! The end-to-end tests with the relay's real broker and ingress (pinned TLS of a dial,
//! a question round trip, `/mcp` of the public listener, the certificate separation, ACME
//! through the tunnel, the outage, lock and quit) are in
//! `crates/apassy-app/tests/connect_tunnel.rs`: only that crate links both.

#![cfg(feature = "vault")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use apassy::net::NodeCertificate;
use apassy::net::sealed_key::{CONNECT_INFO, SealKey};
use apassy::node::tunnel::frame::{self, CLOSE, Dir, Kind, OPEN, RESET, Sequencer};
use apassy::node::tunnel::ws::{self, Message};
use apassy::node::tunnel::{
    ConnectSetup, Failure, Targets, Tunnel, TunnelAuth, TunnelOptions, TunnelState,
};
use serde::Deserialize;
use serde_json::json;

const TOKEN: &str = "tok-synthetic-node";
const NODE_ID: &str = "node_aaaaaaaaaa";
const PUBLIC_NAME: &str = "aaaaaaaaaa.node.example.test";
const ZONE: &str = "node.example.test";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

#[derive(Deserialize)]
struct FramesFile {
    frames: Vec<ValidFrame>,
    invalid: Vec<InvalidFrame>,
    sequences: Vec<SequenceCase>,
}

#[derive(Deserialize)]
struct ValidFrame {
    name: String,
    hex: String,
    stream: u32,
    kind: u8,
    flags: u8,
    payload_hex: String,
}

#[derive(Deserialize)]
struct InvalidFrame {
    name: String,
    hex: String,
    reason: String,
}

#[derive(Deserialize)]
struct SequenceCase {
    name: String,
    frames: Vec<(String, String)>,
    error: Option<(usize, String)>,
}

#[test]
fn the_codec_of_the_node_passes_every_vector_of_the_contract() {
    let file: FramesFile =
        serde_json::from_str(include_str!("fixtures/connect-tunnel-v1/frames.json"))
            .expect("frames.json");
    for case in &file.frames {
        let bytes = hex(&case.hex);
        let decoded =
            frame::decode(&bytes).unwrap_or_else(|error| panic!("{}: {error:?}", case.name));
        assert_eq!(decoded.stream, case.stream, "{}", case.name);
        assert_eq!(decoded.kind as u8, case.kind, "{}", case.name);
        assert_eq!(decoded.flags, case.flags, "{}", case.name);
        assert_eq!(decoded.payload, hex(&case.payload_hex), "{}", case.name);
        assert_eq!(decoded.encode(), bytes, "{}", case.name);
    }
    for case in &file.invalid {
        assert_eq!(
            frame::decode(&hex(&case.hex))
                .map(drop)
                .map_err(|error| error.code()),
            Err(case.reason.as_str()),
            "{}",
            case.name
        );
    }
    for case in &file.sequences {
        let mut sequencer: Sequencer<()> = Sequencer::new();
        let mut first = None;
        for (index, (direction, bytes)) in case.frames.iter().enumerate() {
            let dir = if direction == "to_node" {
                Dir::ToNode
            } else {
                Dir::ToConnect
            };
            let decoded = frame::decode(&hex(bytes)).expect("a valid frame");
            if let Err(error) = sequencer.apply(dir, &decoded, || ()) {
                first = Some((index, error.code().to_owned()));
                break;
            }
        }
        assert_eq!(first, case.error, "{}", case.name);
    }
}

// ---------------------------------------------------------------------------
// A fake Connect of the shared server-side code.

/// The account seam of the test: one fixed token.
struct FixedToken {
    origin: String,
    sign_outs: AtomicUsize,
}

impl TunnelAuth for FixedToken {
    fn origin(&self) -> String {
        self.origin.clone()
    }

    fn with_token(&self, call: &mut dyn FnMut(&str) -> Result<(), Failure>) -> Result<(), Failure> {
        call(TOKEN)
    }

    fn entitled(&self) -> Result<(), Failure> {
        Ok(())
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

/// One node WebSocket that the fake Connect accepted.
struct NodeSocket {
    reader: ws::Reader<TcpStream>,
    writer: TcpStream,
    /// The request head of the upgrade.
    head: String,
}

impl NodeSocket {
    fn send_frame(&mut self, stream: u32, kind: Kind, flags: u8, payload: &[u8]) {
        ws::write_frame(
            &mut self.writer,
            ws::OP_BINARY,
            &frame::encode(stream, kind, flags, payload),
            None,
        )
        .expect("send");
    }

    /// The next message that is not a ping (pings are answered).
    fn next(&mut self) -> Message {
        loop {
            match self.reader.read_message().expect("read") {
                Message::Ping(payload) => {
                    ws::write_frame(&mut self.writer, ws::OP_PONG, &payload, None).expect("pong");
                }
                other => return other,
            }
        }
    }

    /// The next frame of the node that is not a `window` (flow control, contract 4).
    fn next_frame(&mut self) -> frame::Frame {
        loop {
            let frame = match self.next() {
                Message::Binary(bytes) => frame::decode(&bytes).expect("a frame of the node"),
                other => panic!("expected a frame, got {other:?}"),
            };
            if !frame.is_window() {
                return frame;
            }
        }
    }
}

fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A fake Connect on the loopback: it registers the node and hands each node WebSocket
/// to the test.
fn fake_connect() -> (SocketAddr, mpsc::Receiver<NodeSocket>) {
    fake_connect_naming(PUBLIC_NAME)
}

/// [`fake_connect`] whose registration answer names `public_name`.
fn fake_connect_naming(public_name: &'static str) -> (SocketAddr, mpsc::Receiver<NodeSocket>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (sender, sockets) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            let head = read_head(&mut stream);
            let mut lines = head.split("\r\n");
            let first = lines.next().unwrap_or_default().to_owned();
            let headers: Vec<(String, String)> = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
                .collect();
            if first.starts_with("POST /v1/tunnel/nodes ") {
                let length: usize = headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                let _ = stream.read_exact(&mut body);
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let answer = json!({"ok": true, "result": {
                    "node_id": NODE_ID, "account_id": "acc_aaaaaaaaaa", "device_id": "dev_aaaaaaaaaa",
                    "name": request["name"], "pin": request["pin"], "public_name": public_name,
                    "online": false, "created_at": 1_790_000_000u64,
                }})
                .to_string();
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    )
                    .as_bytes(),
                );
                continue;
            }
            let method = first.split(' ').next().unwrap_or_default().to_owned();
            let accept = ws::check_upgrade(
                &method,
                headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
            .expect("a valid upgrade");
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
                    ws::SUBPROTOCOL
                )
                .as_bytes(),
            );
            let writer = stream.try_clone().expect("clone");
            if sender
                .send(NodeSocket {
                    reader: ws::Reader::server(stream, frame::MAX_MESSAGE),
                    writer,
                    head,
                })
                .is_err()
            {
                return;
            }
        }
    });
    (addr, sockets)
}

struct Running {
    handle: apassy::node::tunnel::TunnelHandle,
    auth: Arc<FixedToken>,
    _dir: tempfile::TempDir,
}

fn tunnel(addr: SocketAddr, ping: Duration, idle: Duration) -> Running {
    let dir = tempfile::tempdir().expect("dir");
    let auth = Arc::new(FixedToken {
        origin: format!("http://127.0.0.1:{}", addr.port()),
        sign_outs: AtomicUsize::new(0),
    });
    let mut setup = ConnectSetup::new(auth.clone());
    setup.acme = None;
    setup.ping_interval = ping;
    setup.idle_limit = idle;
    setup.zone = ZONE.to_owned();
    let handle = Tunnel::start(TunnelOptions {
        setup,
        node_dir: dir.path().to_path_buf(),
        name: "Synthetic Mac".to_owned(),
        certificate: NodeCertificate::generate("Synthetic Mac").expect("certificate"),
        targets: Targets::default(),
        seal: Arc::new(SealKey::derive(&[3u8; 32], CONNECT_INFO).expect("seal")),
    })
    .expect("tunnel");
    Running {
        handle,
        auth,
        _dir: dir,
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn the_node_follows_the_stream_rules_and_closes_bad_websockets() {
    let (addr, sockets) = fake_connect();
    let mut running = tunnel(addr, Duration::from_secs(30), Duration::from_secs(90));
    let mut socket = sockets
        .recv_timeout(Duration::from_secs(20))
        .expect("the node connects");
    assert!(
        socket.head.starts_with("GET /v1/tunnel/node HTTP/1.1\r\n"),
        "{}",
        socket.head
    );
    assert!(
        socket
            .head
            .contains(&format!("Authorization: Bearer {TOKEN}\r\n"))
    );
    assert!(
        socket
            .head
            .contains("Sec-WebSocket-Protocol: apassy-tunnel-v1\r\n")
    );
    wait_for("on", || running.handle.status().state == TunnelState::On);
    let status = running.handle.status();
    assert_eq!(status.public_name.as_deref(), Some(PUBLIC_NAME));
    assert_eq!(
        status.url.as_deref(),
        Some("https://aaaaaaaaaa.node.example.test/mcp")
    );

    // A reset for a stream that never opened is not answered; data before an open is
    // reset, and the WebSocket stays.
    socket.send_frame(8, Kind::Device, RESET, b"");
    socket.send_frame(9, Kind::Device, 0, b"x");
    let reset = socket.next_frame();
    assert_eq!((reset.stream, reset.flags), (9, RESET));

    // An ACME request for anything but the pending token of the node: 404, then close.
    socket.send_frame(
        2,
        Kind::Acme,
        OPEN | CLOSE,
        format!(
            "GET /.well-known/acme-challenge/not_pending HTTP/1.1\r\nHost: {PUBLIC_NAME}\r\n\r\n"
        )
        .as_bytes(),
    );
    let mut answer = Vec::new();
    loop {
        let part = socket.next_frame();
        assert_eq!((part.stream, part.kind), (2, Kind::Acme));
        assert_eq!(part.flags & OPEN, 0, "the node never opens a stream");
        answer.extend_from_slice(&part.payload);
        if part.flags & CLOSE != 0 {
            break;
        }
    }
    assert!(
        answer.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
        "{answer:?}"
    );
    socket.send_frame(
        3,
        Kind::Acme,
        OPEN | CLOSE,
        format!("GET /v1/me HTTP/1.1\r\nHost: {PUBLIC_NAME}\r\n\r\n").as_bytes(),
    );
    let mut answer = Vec::new();
    loop {
        let part = socket.next_frame();
        answer.extend_from_slice(&part.payload);
        if part.flags & CLOSE != 0 {
            break;
        }
    }
    assert!(answer.starts_with(b"HTTP/1.1 404 Not Found\r\n"));

    // A reused id is reset; a device stream with no device route of the node too.
    socket.send_frame(1, Kind::Device, OPEN, b"");
    let reset = socket.next_frame();
    assert_eq!((reset.stream, reset.flags), (1, RESET));
    socket.send_frame(4, Kind::Device, OPEN, b"");
    let reset = socket.next_frame();
    assert_eq!((reset.stream, reset.flags), (4, RESET), "no device target");

    // A text message closes the WebSocket with 1003; the node connects again.
    ws::write_frame(&mut socket.writer, ws::OP_TEXT, b"hello", None).expect("text");
    assert_eq!(socket.next(), Message::Close(Some(ws::close::UNSUPPORTED)));
    let mut socket = sockets
        .recv_timeout(Duration::from_secs(20))
        .expect("the node connects again");
    wait_for("on again", || {
        running.handle.status().state == TunnelState::On
    });

    // A malformed frame closes it with 1002.
    ws::write_frame(&mut socket.writer, ws::OP_BINARY, b"short", None).expect("short");
    assert_eq!(socket.next(), Message::Close(Some(ws::close::PROTOCOL)));
    let mut socket = sockets
        .recv_timeout(Duration::from_secs(20))
        .expect("and again");
    wait_for("on a third time", || {
        running.handle.status().state == TunnelState::On
    });
    assert!(running.handle.status().connects >= 3);

    // A stop (lock, quit): close 1000, the key leaves memory, nothing reconnects.
    running.handle.stop();
    assert_eq!(socket.next(), Message::Close(Some(ws::close::NORMAL)));
    assert_eq!(running.handle.status().state, TunnelState::Off);
    assert_eq!(running.auth.sign_outs.load(Ordering::SeqCst), 1);
    assert!(
        sockets.recv_timeout(Duration::from_millis(500)).is_err(),
        "no new WebSocket after the stop"
    );
}

#[test]
fn the_node_pings_and_ends_a_silent_websocket() {
    let (addr, sockets) = fake_connect();
    let running = tunnel(addr, Duration::from_millis(100), Duration::from_millis(600));
    let mut socket = sockets
        .recv_timeout(Duration::from_secs(20))
        .expect("connects");
    // A ping comes; the fake answers nothing at all after it.
    let started = Instant::now();
    match socket.reader.read_message().expect("read") {
        Message::Ping(_) => {}
        other => panic!("expected a ping, got {other:?}"),
    }
    // Silent for the idle limit: the node ends the WebSocket and connects again.
    loop {
        match socket.reader.read_message() {
            Ok(Message::Ping(_)) => continue,
            Ok(other) => panic!("unexpected {other:?}"),
            Err(_) => break,
        }
    }
    assert!(started.elapsed() >= Duration::from_millis(400));
    let _again = sockets
        .recv_timeout(Duration::from_secs(20))
        .expect("the node connects again after the idle end");
    drop(running);
}

#[test]
fn the_node_takes_only_its_own_public_name_in_the_zone() {
    // Connect names another node's label: the node registers nothing and opens nothing.
    let (addr, sockets) = fake_connect_naming("bbbbbbbbbb.node.example.test");
    let running = tunnel(addr, Duration::from_secs(30), Duration::from_secs(90));
    wait_for("the registration is refused", || {
        matches!(
            &running.handle.status().state,
            TunnelState::Reconnecting { why } if why.contains("a registration that is not this")
        )
    });
    assert_eq!(running.handle.status().public_name, None);
    assert!(
        sockets.recv_timeout(Duration::from_millis(500)).is_err(),
        "no WebSocket for a name that is not the node's"
    );
    // The right label in another zone is refused the same way.
    let (addr, sockets) = fake_connect_naming("aaaaaaaaaa.other.example.test");
    let running = tunnel(addr, Duration::from_secs(30), Duration::from_secs(90));
    wait_for("refused again", || {
        matches!(
            &running.handle.status().state,
            TunnelState::Reconnecting { .. }
        )
    });
    assert!(sockets.recv_timeout(Duration::from_millis(500)).is_err());
}

#[test]
fn a_replaced_websocket_does_not_connect_again_at_once() {
    let (addr, sockets) = fake_connect();
    let running = tunnel(addr, Duration::from_secs(30), Duration::from_secs(90));
    let mut socket = sockets
        .recv_timeout(Duration::from_secs(20))
        .expect("connects");
    wait_for("on", || running.handle.status().state == TunnelState::On);
    // Another process of this node took the WebSocket (4005): the node waits minutes,
    // not a second, so two of them do not take turns.
    ws::write_frame(
        &mut socket.writer,
        ws::OP_CLOSE,
        &ws::close_payload(ws::close::REPLACED),
        None,
    )
    .expect("close");
    wait_for("reconnecting", || {
        matches!(
            &running.handle.status().state,
            TunnelState::Reconnecting { why } if why.contains("another Apassy")
        )
    });
    assert!(
        sockets.recv_timeout(Duration::from_secs(3)).is_err(),
        "no new WebSocket right after a replacement"
    );
}
