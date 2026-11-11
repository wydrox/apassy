//! The Connect tunnel broker and the ingress (unit C4, docs/contracts/connect-tunnel-v1.md).
//!
//! A fake node registers and echoes, fake devices dial, and the SNI and ACME listeners run
//! on free loopback ports. The HTTP side is the relay's own transport: the vendored
//! `tiny_http` with deadlines, as `Relay::start` binds it, routing the two tunnel paths
//! to `Broker::serve_node` and `Broker::serve_dial`. No fixed port, no fixed path.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use apassy_relay::server::ingress::{self, IngressConfig};
use apassy_relay::server::tunnel::frame::{
    self, Applied, CLOSE, Dir, Kind, OPEN, RESET, Sequencer,
};
use apassy_relay::server::tunnel::ws::{self, Message, client, close};
use apassy_relay::server::tunnel::{Broker, Limits, ManualClock, MemoryDirectory};

const ZONE: &str = "node.example.test";
/// 2026-11-10T00:00:00Z.
const NOW: u64 = 1_794_268_800;
const NODE_A: &str = "node_aaaaaaaaaa";
const NODE_A2: &str = "node_dddddddddd";
const NODE_B: &str = "node_bbbbbbbbbb";
const NODE_NONE: &str = "node_cccccccccc";

// ---------------------------------------------------------------------------
// The harness.

struct Harness {
    broker: Broker,
    directory: Arc<MemoryDirectory>,
    clock: Arc<ManualClock>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

fn test_limits() -> Limits {
    Limits {
        tick: Duration::from_millis(50),
        close_grace: Duration::from_millis(300),
        ..Limits::default()
    }
}

impl Harness {
    fn new() -> Self {
        Self::with(test_limits(), Duration::from_secs(30))
    }

    /// A broker and the relay transport with the given request handle deadline.
    fn with(limits: Limits, handle_deadline: Duration) -> Self {
        let directory = Arc::new(MemoryDirectory::new());
        directory.add_device("tok-a1", "acc_a", "dev_a1");
        directory.add_device("tok-a2", "acc_a", "dev_a2");
        directory.add_device("tok-b", "acc_b", "dev_b");
        directory.add_team_token("tok-team");
        directory.add_node(NODE_A, "acc_a", "dev_a1");
        directory.add_node(NODE_A2, "acc_a", "dev_a2");
        directory.add_node(NODE_B, "acc_b", "dev_b");
        let clock = Arc::new(ManualClock::new(NOW));
        let broker = Broker::new(directory.clone(), limits, clock.clone(), ZONE);
        let server = tiny_http::Server::http_with_deadlines(
            "127.0.0.1:0",
            Duration::from_secs(10),
            Duration::from_secs(10),
            handle_deadline,
        )
        .unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (routed, stopped) = (broker.clone(), stop.clone());
        thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(50)) else {
                    continue;
                };
                let path = request.url().split('?').next().unwrap_or("").to_string();
                if path == "/v1/tunnel/node" {
                    routed.serve_node(request);
                } else if let Some(node_id) = path.strip_prefix("/v1/tunnel/dial/") {
                    routed.serve_dial(request, node_id);
                } else {
                    let _ = request.respond(tiny_http::Response::empty(404));
                }
            }
        });
        Self {
            broker,
            directory,
            clock,
            addr,
            stop,
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(self.addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }

    /// The WebSocket handshake to `path`; `Err` is the refusal (status and error code).
    fn upgrade(&self, path: &str, token: Option<&str>) -> Result<TcpStream, (u16, String)> {
        let mut stream = self.connect();
        match client::handshake(&mut stream, "relay.test", path, token) {
            Ok(()) => Ok(stream),
            Err(client::HandshakeError::Refused(refused)) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&refused.body).unwrap_or_default();
                let code = body["error"]["code"].as_str().unwrap_or("").to_string();
                Err((refused.status, code))
            }
            Err(other) => panic!("handshake: {other:?}"),
        }
    }

    fn dial(&self, token: &str, node_id: &str) -> Result<Peer, (u16, String)> {
        self.upgrade(&format!("/v1/tunnel/dial/{node_id}"), Some(token))
            .map(Peer::new)
    }

    fn node(&self, token: &str) -> Result<Peer, (u16, String)> {
        self.upgrade("/v1/tunnel/node", Some(token)).map(Peer::new)
    }

    fn open_streams(&self, account: &str) -> usize {
        self.broker.usage(account).open_streams
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.broker.stop();
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < until, "timed out waiting: {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// A client WebSocket (a device or a node).
struct Peer {
    reader: ws::Reader<TcpStream>,
    writer: TcpStream,
}

impl Peer {
    fn new(stream: TcpStream) -> Self {
        let writer = stream.try_clone().unwrap();
        Self {
            reader: ws::Reader::client(stream, 1 << 20),
            writer,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        client::send(&mut self.writer, ws::OP_BINARY, bytes).unwrap();
    }

    fn send_frame(&mut self, stream: u32, kind: Kind, flags: u8, payload: &[u8]) {
        self.send(&frame::encode(stream, kind, flags, payload));
    }

    /// The next message that is not a ping (pings are answered).
    fn next(&mut self) -> Message {
        loop {
            match self.reader.read_message() {
                Ok(Message::Ping(payload)) => {
                    let _ = client::send(&mut self.writer, ws::OP_PONG, &payload);
                }
                Ok(message) => return message,
                Err(error) => panic!("read: {error:?}"),
            }
        }
    }

    /// The next frame that is not a `window` (flow control, section 4).
    fn next_frame(&mut self) -> frame::Frame {
        loop {
            let frame = self.next_any_frame();
            if !frame.is_window() {
                return frame;
            }
        }
    }

    fn next_any_frame(&mut self) -> frame::Frame {
        match self.next() {
            Message::Binary(bytes) => frame::decode(&bytes).unwrap(),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    fn expect_close(&mut self, code: u16) {
        loop {
            match self.next() {
                Message::Close(got) => {
                    assert_eq!(got, Some(code));
                    return;
                }
                Message::Binary(_) => {}
                other => panic!("expected close {code}, got {other:?}"),
            }
        }
    }

    /// Bytes until `len` arrived.
    fn read_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < len {
            match self.next() {
                Message::Binary(bytes) => out.extend(bytes),
                other => panic!("expected bytes, got {other:?}"),
            }
        }
        out
    }
}

/// Opens seen by a fake node: stream id, kind, flags, first bytes.
type Opens = mpsc::Receiver<(u32, Kind, u8, Vec<u8>)>;

/// A node that echoes every stream back, in random pieces, and closes when Connect
/// closes. It grants Connect the window of each byte it echoed. It reports each `open`
/// and each `reset` it receives.
struct EchoNode {
    opens: Opens,
    resets: mpsc::Receiver<u32>,
    closed: mpsc::Receiver<Option<u16>>,
}

fn echo_node(h: &Harness, token: &str, seed: u64) -> EchoNode {
    let mut node = h.node(token).expect("node connects");
    let (open_tx, opens) = mpsc::channel();
    let (reset_tx, resets) = mpsc::channel();
    let (close_tx, closed) = mpsc::channel();
    thread::spawn(move || {
        let mut rng = Rng(seed | 1);
        let mut kinds: HashMap<u32, Kind> = HashMap::new();
        loop {
            let message = match node.reader.read_message() {
                Ok(message) => message,
                Err(_) => {
                    let _ = close_tx.send(None);
                    return;
                }
            };
            let frame = match message {
                Message::Binary(bytes) => frame::decode(&bytes).unwrap(),
                Message::Ping(payload) => {
                    let _ = client::send(&mut node.writer, ws::OP_PONG, &payload);
                    continue;
                }
                Message::Close(code) => {
                    let _ = close_tx.send(code);
                    return;
                }
                _ => continue,
            };
            if frame.is_reset() {
                kinds.remove(&frame.stream);
                let _ = reset_tx.send(frame.stream);
                continue;
            }
            if frame.is_window() {
                continue;
            }
            if frame.is_open() {
                kinds.insert(frame.stream, frame.kind);
                let _ =
                    open_tx.send((frame.stream, frame.kind, frame.flags, frame.payload.clone()));
            }
            let Some(kind) = kinds.get(&frame.stream).copied() else {
                continue;
            };
            let mut rest = &frame.payload[..];
            while !rest.is_empty() {
                let take = 1 + (rng.next() as usize % rest.len());
                let (piece, after) = rest.split_at(take);
                node.send_frame(frame.stream, kind, 0, piece);
                rest = after;
            }
            if !frame.payload.is_empty() && !frame.is_close() {
                node.send(&frame::window(
                    frame.stream,
                    kind,
                    frame.payload.len() as u32,
                ));
            }
            if frame.is_close() {
                node.send_frame(frame.stream, kind, CLOSE, &[]);
                kinds.remove(&frame.stream);
            }
        }
    });
    EchoNode {
        opens,
        resets,
        closed,
    }
}

impl EchoNode {
    fn open(&self) -> (u32, Kind, u8, Vec<u8>) {
        self.opens
            .recv_timeout(Duration::from_secs(10))
            .expect("an open")
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

// ---------------------------------------------------------------------------
// Contract vectors (section 11).

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn vectors() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/connect-tunnel-v1/frames.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn contract_frames_decode_encode_and_fail_with_their_codes() {
    let vectors = vectors();
    assert_eq!(vectors["header_bytes"], frame::HEADER_LEN);
    assert_eq!(vectors["max_payload"], frame::MAX_PAYLOAD);
    for valid in vectors["frames"].as_array().unwrap() {
        let bytes = unhex(valid["hex"].as_str().unwrap());
        let decoded = frame::decode(&bytes).unwrap_or_else(|error| {
            panic!("{}: {error:?}", valid["name"]);
        });
        assert_eq!(u64::from(decoded.stream), valid["stream"].as_u64().unwrap());
        assert_eq!(decoded.kind as u64, valid["kind"].as_u64().unwrap());
        assert_eq!(u64::from(decoded.flags), valid["flags"].as_u64().unwrap());
        assert_eq!(
            decoded.payload,
            unhex(valid["payload_hex"].as_str().unwrap())
        );
        assert_eq!(decoded.encode(), bytes, "{}", valid["name"]);
    }
    for invalid in vectors["invalid"].as_array().unwrap() {
        let bytes = unhex(invalid["hex"].as_str().unwrap());
        let error = frame::decode(&bytes).expect_err(invalid["name"].as_str().unwrap());
        assert_eq!(error.code(), invalid["reason"], "{}", invalid["name"]);
    }
}

#[test]
fn contract_sequences_give_their_first_error() {
    for sequence in vectors()["sequences"].as_array().unwrap() {
        let mut seq: Sequencer<()> = Sequencer::new();
        let mut first = None;
        for (index, step) in sequence["frames"].as_array().unwrap().iter().enumerate() {
            let dir = match step[0].as_str().unwrap() {
                "to_node" => Dir::ToNode,
                _ => Dir::ToConnect,
            };
            let frame = frame::decode(&unhex(step[1].as_str().unwrap())).unwrap();
            if let Err(error) = seq.apply(dir, &frame, || ()) {
                first = Some((index, error.code()));
                break;
            }
        }
        let expected = sequence["error"].as_array().map(|pair| {
            (
                pair[0].as_u64().unwrap() as usize,
                pair[1].as_str().unwrap(),
            )
        });
        assert_eq!(first, expected, "{}", sequence["name"]);
    }
}

#[test]
fn sequencer_keeps_streams_apart_under_random_interleaving() {
    // Property: for random scripts of many streams, interleaved at random (each stream
    // keeps its own order), every frame lands on its own stream and no rule breaks.
    for seed in 1..200u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let streams = 1 + rng.next() as usize % 12;
        let mut scripts: Vec<VecDeque<(Dir, u8)>> = Vec::new();
        for _ in 0..streams {
            let mut script = VecDeque::from([(Dir::ToNode, OPEN)]);
            for _ in 0..rng.next() % 6 {
                let dir = if rng.next().is_multiple_of(2) {
                    Dir::ToNode
                } else {
                    Dir::ToConnect
                };
                script.push_back((dir, 0));
            }
            if rng.next().is_multiple_of(4) {
                let dir = if rng.next().is_multiple_of(2) {
                    Dir::ToNode
                } else {
                    Dir::ToConnect
                };
                script.push_back((dir, RESET));
            } else {
                script.push_back((Dir::ToNode, CLOSE));
                script.push_back((Dir::ToConnect, CLOSE));
            }
            scripts.push(script);
        }
        // Opens go in id order; the rest interleave freely.
        let mut seq: Sequencer<u32> = Sequencer::new();
        let mut opened = 0usize;
        loop {
            let mut candidates: Vec<usize> = (0..opened)
                .filter(|&index| !scripts[index].is_empty())
                .collect();
            if opened < streams {
                candidates.push(opened);
            }
            if candidates.is_empty() {
                break;
            }
            let pick = candidates[rng.next() as usize % candidates.len()];
            let (dir, flags) = scripts[pick].pop_front().unwrap();
            let id = pick as u32 + 1;
            let kind = if pick.is_multiple_of(2) {
                Kind::Device
            } else {
                Kind::Public
            };
            match seq.apply_head(dir, id, kind, flags, || id).unwrap() {
                Applied::Opened(value) => {
                    assert_eq!(value, id);
                    opened += 1;
                }
                Applied::Frame { value, ended } => {
                    assert_eq!(value, id, "seed {seed}: a frame crossed streams");
                    assert_eq!(ended, scripts[pick].is_empty(), "seed {seed}: early end");
                }
                Applied::Dropped => panic!("seed {seed}: dropped a live frame"),
            }
        }
        assert_eq!(seq.live(), 0);
    }
}

// ---------------------------------------------------------------------------
// The checks before the 101 (contract 3.3).

#[test]
fn a_dial_to_an_unknown_node_is_404() {
    let h = Harness::new();
    assert_eq!(
        h.dial("tok-a1", NODE_NONE).err(),
        Some((404, "node_unknown".into()))
    );
    assert_eq!(
        h.dial("tok-a1", "node_NOTVALID1").err(),
        Some((404, "node_unknown".into()))
    );
}

#[test]
fn a_dial_to_an_offline_node_is_503_tunnel_offline() {
    let h = Harness::new();
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((503, "tunnel_offline".into()))
    );
}

#[test]
fn tokens_upgrades_and_plans_are_checked_in_order() {
    let h = Harness::new();
    assert_eq!(
        h.upgrade(&format!("/v1/tunnel/dial/{NODE_A}"), None).err(),
        Some((401, "unauthenticated".into()))
    );
    assert_eq!(
        h.dial("tok-unknown", NODE_A).err(),
        Some((401, "unauthenticated".into()))
    );
    assert_eq!(
        h.dial("tok-team", NODE_A).err(),
        Some((403, "account_required".into()))
    );
    // Not an upgrade, or another subprotocol: 400 before the token is looked at.
    let mut plain = h.connect();
    write!(
        plain,
        "GET /v1/tunnel/dial/{NODE_A} HTTP/1.1\r\nHost: relay.test\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    let _ = plain.read_to_string(&mut answer);
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    assert!(answer.contains("invalid_request"), "{answer}");
    let mut other = h.connect();
    let request = String::from_utf8(client::request(
        "relay.test",
        "/v1/tunnel/node",
        &client::new_key(),
        None,
    ))
    .unwrap()
    .replace("apassy-tunnel-v1", "chat");
    other.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = other.read_to_string(&mut answer);
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    // The node's account without a plan.
    let _node = echo_node(&h, "tok-a1", 1);
    h.directory.set_entitled("acc_a", false);
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((403, "plan_required".into()))
    );
    assert_eq!(h.node("tok-a2").err(), Some((403, "plan_required".into())));
    h.directory.set_entitled("acc_a", true);
    assert!(h.dial("tok-a2", NODE_A).is_ok());
}

#[test]
fn another_account_needs_a_grant_and_loses_it_at_once() {
    let h = Harness::new();
    let _node = echo_node(&h, "tok-a1", 2);
    assert_eq!(
        h.dial("tok-b", NODE_A).err(),
        Some((403, "not_in_group".into()))
    );
    h.directory.grant(NODE_A, "acc_b");
    let mut device = h.dial("tok-b", NODE_A).expect("granted");
    device.send(b"hello from b");
    assert_eq!(device.read_bytes(12), b"hello from b");
    let mut own = h.dial("tok-a2", NODE_A).unwrap();
    // DELETE /v1/tunnel/grants/{id}: the grantee's streams end with 4003, others stay.
    h.directory.revoke(NODE_A, "acc_b");
    assert_eq!(h.broker.revoke_grant(NODE_A, "acc_b"), 1);
    device.expect_close(close::REVOKED);
    assert_eq!(
        h.dial("tok-b", NODE_A).err(),
        Some((403, "not_in_group".into()))
    );
    own.send(b"still here");
    assert_eq!(own.read_bytes(10), b"still here");
}

#[test]
fn a_node_without_a_registration_is_404_and_the_ninth_node_is_403() {
    let h = Harness::with(
        Limits {
            nodes_per_account: 1,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    h.directory.add_device("tok-a3", "acc_a", "dev_a3");
    assert_eq!(h.node("tok-a3").err(), Some((404, "node_unknown".into())));
    let _first = echo_node(&h, "tok-a1", 3);
    assert_eq!(h.node("tok-a2").err(), Some((403, "account_limit".into())));
    // A reconnect of the same node is not a second node.
    assert!(h.node("tok-a1").is_ok());
}

// ---------------------------------------------------------------------------
// Dials.

#[test]
fn upgrade_keeps_bytes_sent_with_the_head() {
    // The open question of the plan: the handshake and the first WebSocket frame arrive in
    // one TCP segment. The vendored `tiny_http` reads the head through a buffered reader;
    // `Request::upgrade_split` hands that same reader over, so the frame is not lost.
    let h = Harness::new();
    let node = echo_node(&h, "tok-a1", 4);
    let mut stream = h.connect();
    let key = client::new_key();
    let mut segment = client::request(
        "relay.test",
        &format!("/v1/tunnel/dial/{NODE_A}"),
        &key,
        Some("tok-a2"),
    );
    let hello = b"\x16\x03\x01\x00\x05first";
    segment.extend(ws::encode_frame(
        ws::OP_BINARY,
        hello,
        Some(ws::random_mask()),
    ));
    stream.set_nodelay(true).unwrap();
    stream.write_all(&segment).unwrap();
    client::finish(&mut stream, &key).unwrap();
    let (_, kind, flags, payload) = node.open();
    assert_eq!((kind, flags, payload.len()), (Kind::Device, OPEN, 0));
    let mut device = Peer::new(stream);
    assert_eq!(device.read_bytes(hello.len()), hello);
}

#[test]
fn an_upgraded_socket_outlives_the_request_deadlines() {
    // The relay transport closes a request after its handle deadline; an upgraded tunnel
    // is released from it.
    let h = Harness::with(test_limits(), Duration::from_millis(500));
    let _node = echo_node(&h, "tok-a1", 5);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    thread::sleep(Duration::from_millis(1500));
    device.send(b"after the deadline");
    assert_eq!(device.read_bytes(18), b"after the deadline");
}

#[test]
fn frames_never_cross_streams_with_random_interleaving() {
    let h = Harness::with(
        Limits {
            dials_per_minute: 1000,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 6);
    for round in 0..3u64 {
        let workers: Vec<_> = (0..8u64)
            .map(|index| {
                let mut device = h.dial("tok-a2", NODE_A).unwrap();
                thread::spawn(move || {
                    let mut rng =
                        Rng((round * 100 + index + 1).wrapping_mul(0x2545_F491_4F6C_DD1D));
                    let mut sent = Vec::new();
                    for _ in 0..(1 + rng.next() % 12) {
                        let len = 1 + rng.next() as usize % frame::MAX_PAYLOAD;
                        let mut bytes = rng.bytes(len);
                        bytes[0] = index as u8; // a marker of the sender
                        device.send(&bytes);
                        sent.extend(bytes);
                        if rng.next().is_multiple_of(3) {
                            thread::sleep(Duration::from_millis(rng.next() % 5));
                        }
                    }
                    let echoed = device.read_bytes(sent.len());
                    assert_eq!(echoed.len(), sent.len());
                    assert!(
                        echoed == sent,
                        "round {round} device {index}: bytes crossed"
                    );
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

#[test]
fn a_closed_stream_frees_its_slot_and_the_65th_stream_is_429() {
    let h = Harness::with(
        Limits {
            dials_per_minute: 1000,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 7);
    let mut devices: Vec<Peer> = (0..64)
        .map(|_| h.dial("tok-a2", NODE_A).expect("within the limit"))
        .collect();
    assert_eq!(h.open_streams("acc_a"), 64);
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
    // The ingress has slots of its own: with every dial slot taken, an agent still gets
    // its stream (the echo of its hello).
    let sni = ingress::serve_sni(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        h.broker.clone(),
        IngressConfig::default(),
    )
    .unwrap();
    let mut agent = TcpStream::connect(sni.addr).unwrap();
    agent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let hello = client_hello("aaaaaaaaaa.node.example.test");
    agent.write_all(&hello).unwrap();
    let mut echoed = vec![0u8; hello.len()];
    agent.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, hello);
    assert_eq!(h.broker.ingress_usage("acc_a").open_streams, 1);
    drop(agent);
    wait_until("the ingress slot is free", || {
        h.broker.ingress_usage("acc_a").open_streams == 0
    });
    // A WebSocket close of one dial ends its stream; the node's echo closes the other way.
    let mut last = devices.pop().unwrap();
    client::send(
        &mut last.writer,
        ws::OP_CLOSE,
        &ws::close_payload(close::NORMAL),
    )
    .unwrap();
    last.expect_close(close::NORMAL);
    wait_until("the slot is free", || h.open_streams("acc_a") == 63);
    let mut again = h.dial("tok-a2", NODE_A).expect("the freed slot");
    again.send(b"x");
    assert_eq!(again.read_bytes(1), b"x");
    assert_eq!(h.broker.usage("acc_a").streams, 66);
}

#[test]
fn the_dial_rate_is_per_minute() {
    let h = Harness::with(
        Limits {
            dials_per_minute: 3,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 8);
    let _held: Vec<_> = (0..3).map(|_| h.dial("tok-a2", NODE_A).unwrap()).collect();
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
    h.clock.advance(60);
    assert!(h.dial("tok-a2", NODE_A).is_ok());
}

#[test]
fn the_byte_budget_trips_and_resets_on_the_first_of_the_month() {
    let h = Harness::with(
        Limits {
            bytes_per_month: 1000,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    // 2026-11-30T23:59:00Z.
    h.clock.set(1_796_083_140);
    let _node = echo_node(&h, "tok-a1", 9);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    device.send(&[7u8; 400]);
    assert_eq!(device.read_bytes(400), vec![7u8; 400]);
    assert_eq!(h.broker.usage("acc_a").bytes, 800);
    // 200 more each way crosses 1000: the open streams close with 4002.
    device.send(&[8u8; 200]);
    device.expect_close(close::TUNNEL_LIMIT);
    assert!(h.broker.usage("acc_a").tripped);
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
    // The budget scales with the plan's people, and a larger one counts at once: with
    // three, 3000 bytes, so the month's 1200 no longer spend it.
    h.directory.set_budget_units("acc_a", 3);
    let mut more = h
        .dial("tok-a2", NODE_A)
        .expect("a larger budget counts from the next stream");
    more.send(b"hi");
    assert_eq!(more.read_bytes(2), b"hi");
    assert!(!h.broker.usage("acc_a").tripped);
    drop(more);
    // 2026-12-01T00:00:00Z.
    h.clock.set(1_796_083_200);
    let mut next_month = h.dial("tok-a2", NODE_A).expect("a new month");
    next_month.send(b"ok");
    assert_eq!(next_month.read_bytes(2), b"ok");
    let usage = h.broker.usage("acc_a");
    assert_eq!(
        (usage.month, usage.bytes, usage.tripped),
        (202612, 4, false)
    );
}

#[test]
fn a_node_reconnect_replaces_the_registration_and_resets_its_streams() {
    let h = Harness::new();
    let first = echo_node(&h, "tok-a1", 10);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    device.send(b"one");
    assert_eq!(device.read_bytes(3), b"one");
    let _second = echo_node(&h, "tok-a1", 11);
    assert_eq!(
        first.closed.recv_timeout(Duration::from_secs(10)).unwrap(),
        Some(close::REPLACED)
    );
    device.expect_close(close::NODE_OFFLINE);
    wait_until("the old stream is released", || {
        h.open_streams("acc_a") == 0
    });
    let mut again = h.dial("tok-a2", NODE_A).unwrap();
    again.send(b"two");
    assert_eq!(again.read_bytes(3), b"two");
    assert_eq!(h.broker.online_nodes(), vec![NODE_A.to_string()]);
}

#[test]
fn a_node_that_goes_away_closes_its_dials_with_4001() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    let open = node.next_frame();
    assert!(open.is_open());
    drop(node);
    device.expect_close(close::NODE_OFFLINE);
    wait_until("offline", || !h.broker.online(NODE_A));
}

#[test]
fn node_close_and_reset_reach_the_device() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let mut closing = h.dial("tok-a2", NODE_A).unwrap();
    let first = node.next_frame();
    node.send_frame(first.stream, Kind::Device, CLOSE, b"last bytes");
    assert_eq!(closing.read_bytes(10), b"last bytes");
    closing.expect_close(close::NORMAL);
    // Connect closes the other direction, and the stream ends.
    let other_way = node.next_frame();
    assert_eq!((other_way.stream, other_way.flags), (first.stream, CLOSE));
    let mut reset = h.dial("tok-a2", NODE_A).unwrap();
    let second = node.next_frame();
    assert!(second.stream > first.stream);
    node.send_frame(second.stream, Kind::Device, RESET, &[]);
    reset.expect_close(close::RESET_BY_NODE);
    wait_until("both streams released", || h.open_streams("acc_a") == 0);
}

#[test]
fn a_broken_stream_rule_resets_only_that_stream_and_a_bad_frame_closes_1002() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let mut bad = h.dial("tok-a2", NODE_A).unwrap();
    let first = node.next_frame();
    let mut good = h.dial("tok-a2", NODE_A).unwrap();
    let second = node.next_frame();
    // kind_mismatch on the first stream: Connect resets it; the second one works.
    node.send_frame(first.stream, Kind::Public, 0, b"x");
    let reset = node.next_frame();
    assert_eq!((reset.stream, reset.flags), (first.stream, RESET));
    bad.expect_close(close::RESET_BY_NODE);
    // A frame for a stream that was never opened has nothing to reset.
    node.send_frame(second.stream + 10, Kind::Device, 0, b"y");
    node.send_frame(second.stream, Kind::Device, 0, b"ok");
    assert_eq!(good.read_bytes(2), b"ok");
    // An open from the node resets that (live) stream.
    node.send_frame(second.stream, Kind::Device, OPEN, &[]);
    let reset = node.next_frame();
    assert_eq!((reset.stream, reset.flags), (second.stream, RESET));
    good.expect_close(close::RESET_BY_NODE);
    // A malformed frame closes the node's WebSocket with 1002.
    node.send(&[0, 0, 0, 1, 1, 0]);
    node.expect_close(close::PROTOCOL);
}

#[test]
fn text_messages_are_refused_with_1003() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    let open = node.next_frame();
    client::send(&mut device.writer, ws::OP_TEXT, b"text").unwrap();
    device.expect_close(close::UNSUPPORTED);
    let reset = node.next_frame();
    assert_eq!((reset.stream, reset.flags), (open.stream, RESET));
    client::send(&mut node.writer, ws::OP_TEXT, b"text").unwrap();
    node.expect_close(close::UNSUPPORTED);
}

#[test]
fn a_dial_message_over_16384_bytes_closes_1009() {
    let h = Harness::new();
    let _node = echo_node(&h, "tok-a1", 12);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    device.send(&vec![1u8; frame::MAX_PAYLOAD + 1]);
    device.expect_close(close::TOO_BIG);
}

#[test]
fn a_node_that_sends_over_its_window_is_reset_and_no_other_stream() {
    let h = Harness::with(
        Limits {
            stream_buffer: 64 * 1024,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let mut node = h.node("tok-a1").unwrap();
    let mut slow = h.dial("tok-a2", NODE_A).unwrap();
    let slow_open = node.next_frame();
    let mut fast = h.dial("tok-a2", NODE_A).unwrap();
    let fast_open = node.next_frame();
    let mut seq: Sequencer<()> = Sequencer::new();
    seq.apply(Dir::ToNode, &slow_open, || ()).unwrap();
    seq.apply(Dir::ToNode, &fast_open, || ()).unwrap();
    // Only the window lets this through: the node sends eight windows (512 KiB) strictly
    // within what Connect granted it, and Connect grants more only as the client reads.
    let total = 8 * 64 * 1024;
    let reader = thread::spawn(move || {
        let got = slow.read_bytes(total);
        (slow, got)
    });
    let (mut sent, mut grants) = (0usize, 0usize);
    while sent < total {
        let credit = seq.credit(slow_open.stream, Dir::ToConnect).expect("live") as usize;
        if credit == 0 {
            let frame = node.next_any_frame();
            grants += usize::from(frame.is_window() && frame.stream == slow_open.stream);
            seq.apply(Dir::ToNode, &frame, || ())
                .expect("Connect keeps the rules");
            continue;
        }
        let take = credit.min(frame::MAX_PAYLOAD).min(total - sent);
        let piece = vec![0x5Au8; take];
        seq.apply_parts(
            Dir::ToConnect,
            slow_open.stream,
            Kind::Device,
            0,
            &piece,
            || (),
        )
        .unwrap();
        node.send_frame(slow_open.stream, Kind::Device, 0, &piece);
        sent += take;
    }
    let (slow, got) = reader.join().unwrap();
    assert_eq!(
        got.len(),
        total,
        "the client gets every byte of the windows"
    );
    assert!(
        grants >= 7,
        "Connect granted the node more as the client read: {grants}"
    );
    // Then the client stops reading and the node floods its stream far past every window
    // it got: Connect resets that stream (`over_window`). The node's writes never block on
    // it, and the other stream goes on.
    let chunk = vec![0xEEu8; frame::MAX_PAYLOAD];
    let mut reset_seen = false;
    for _ in 0..1024 {
        node.send_frame(slow_open.stream, Kind::Device, 0, &chunk);
    }
    node.send_frame(fast_open.stream, Kind::Device, 0, b"fast");
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        let frame = node.next_frame();
        if frame.stream == slow_open.stream && frame.is_reset() {
            reset_seen = true;
            break;
        }
    }
    assert!(reset_seen, "the slow stream was reset");
    assert_eq!(fast.read_bytes(4), b"fast");
    drop(slow);
}

#[test]
fn a_window_over_sixteen_mebibytes_resets_only_that_stream() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let mut first = h.dial("tok-a2", NODE_A).unwrap();
    let first_open = node.next_frame();
    let mut second = h.dial("tok-a2", NODE_A).unwrap();
    let second_open = node.next_frame();
    // With the initial 64 KiB, 16 MiB more is over the largest window (contract 4).
    node.send(&frame::window(
        first_open.stream,
        Kind::Device,
        16 * 1024 * 1024,
    ));
    let reset = node.next_frame();
    assert_eq!((reset.stream, reset.flags), (first_open.stream, RESET));
    first.expect_close(close::RESET_BY_NODE);
    second.send(b"ping");
    let data = node.next_frame();
    assert_eq!(
        (data.stream, &data.payload[..]),
        (second_open.stream, &b"ping"[..])
    );
    node.send_frame(second_open.stream, Kind::Device, 0, b"pong");
    assert_eq!(second.read_bytes(4), b"pong");
    assert!(h.broker.online(NODE_A));
}

#[test]
fn a_stream_without_window_does_not_hold_up_another_dial_of_the_node() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let stuck = h.dial("tok-a2", NODE_A).unwrap();
    let stuck_open = node.next_frame();
    // The stuck client sends four windows; the node never grants more than the first.
    let mut writer = stuck.writer.try_clone().unwrap();
    thread::spawn(move || {
        for _ in 0..16 {
            if client::send(&mut writer, ws::OP_BINARY, &[1u8; 16384]).is_err() {
                return;
            }
        }
    });
    let mut got = 0u64;
    while got < frame::INITIAL_WINDOW {
        let data = node.next_frame();
        assert_eq!(data.stream, stuck_open.stream);
        got += data.payload.len() as u64;
    }
    assert_eq!(got, frame::INITIAL_WINDOW);
    // Another dial of the same node opens and carries bytes both ways meanwhile.
    let mut other = h.dial("tok-a2", NODE_A).expect("another dial");
    let other_open = node.next_frame();
    assert_eq!(
        other_open.flags, OPEN,
        "nothing of the stuck stream before it"
    );
    other.send(b"hello");
    let data = node.next_frame();
    assert_eq!(
        (data.stream, &data.payload[..]),
        (other_open.stream, &b"hello"[..])
    );
    node.send_frame(other_open.stream, Kind::Device, 0, b"world");
    assert_eq!(other.read_bytes(5), b"world");
    drop(stuck);
}

#[test]
fn a_reset_while_a_client_waits_for_window_frees_its_slot() {
    let h = Harness::with(
        Limits {
            streams_per_account: 1,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let mut node = h.node("tok-a1").unwrap();
    let mut waiting = h.dial("tok-a2", NODE_A).unwrap();
    let open = node.next_frame();
    let mut writer = waiting.writer.try_clone().unwrap();
    thread::spawn(move || {
        for _ in 0..8 {
            if client::send(&mut writer, ws::OP_BINARY, &[2u8; 16384]).is_err() {
                return;
            }
        }
    });
    let mut got = 0u64;
    while got < frame::INITIAL_WINDOW {
        got += node.next_frame().payload.len() as u64;
    }
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
    // The node resets the stream while Connect holds client bytes that wait for window.
    node.send_frame(open.stream, Kind::Device, RESET, &[]);
    waiting.expect_close(close::RESET_BY_NODE);
    wait_until("the slot is free", || h.open_streams("acc_a") == 0);
    let mut again = h.dial("tok-a2", NODE_A).expect("the slot is free again");
    let again_open = node.next_frame();
    assert_eq!(again_open.flags, OPEN);
    again.send(b"z");
    assert_eq!(node.next_frame().payload, b"z");
}

#[test]
fn the_recheck_count_starts_again_after_an_answer_and_a_definite_no_ends_with_4003() {
    let h = Harness::with(
        Limits {
            // Rounds only when the test asks for one.
            recheck: Duration::from_secs(3600),
            recheck_skips: 3,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 44);
    h.directory.grant(NODE_A, "acc_b");
    let mut own = h.dial("tok-a2", NODE_A).unwrap();
    let mut granted = h.dial("tok-b", NODE_A).unwrap();
    let round = |failing: bool| {
        h.directory.set_failing(failing);
        h.broker.recheck_now();
        h.directory.set_failing(false);
    };
    // Fail, fail, an answer, then three failures: never more than three in a row.
    for failing in [true, true, false, true, true, true] {
        round(failing);
    }
    own.send(b"a");
    assert_eq!(own.read_bytes(1), b"a");
    granted.send(b"b");
    assert_eq!(granted.read_bytes(1), b"b");
    // A definite "no" after failed rounds ends the stream with 4003, never 1013: the
    // grant first, then the plan.
    round(false);
    round(true);
    round(true);
    h.directory.revoke(NODE_A, "acc_b");
    round(false);
    granted.expect_close(close::REVOKED);
    own.send(b"c");
    assert_eq!(own.read_bytes(1), b"c");
    round(true);
    round(true);
    h.directory.set_entitled("acc_a", false);
    round(false);
    own.expect_close(close::REVOKED);
}

// ---------------------------------------------------------------------------
// The ingress.

/// A real ClientHello from rustls for `name`: the bytes a cloud agent sends first.
fn client_hello(name: &str) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server).unwrap();
    let mut out = Vec::new();
    while connection.wants_write() {
        connection.write_tls(&mut out).unwrap();
    }
    out
}

fn sni_listener(h: &Harness, config: IngressConfig) -> ingress::IngressHandle {
    ingress::serve_sni(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        h.broker.clone(),
        config,
    )
    .unwrap()
}

fn agent(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

#[test]
fn the_ingress_forwards_a_recorded_client_hello_unchanged_both_ways() {
    let h = Harness::new();
    let node = echo_node(&h, "tok-a1", 13);
    let sni = sni_listener(&h, IngressConfig::default());
    let hello = client_hello("AAAAAAAAAA.node.example.test");
    assert_eq!(
        ingress::server_name(&hello).unwrap(),
        "aaaaaaaaaa.node.example.test"
    );
    let mut agent = agent(sni.addr);
    // The ClientHello and the next bytes in one segment: the ingress reads only the
    // first record for the open and forwards the rest as data.
    let mut segment = hello.clone();
    segment.extend_from_slice(b"\x17\x03\x03\x00\x03abc");
    agent.write_all(&segment).unwrap();
    let (_, kind, flags, payload) = node.open();
    assert_eq!((kind, flags), (Kind::Public, OPEN));
    assert_eq!(payload, hello, "the open carries the exact first record");
    let mut echoed = vec![0u8; segment.len()];
    agent.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, segment);
    // A half-close of the agent reaches the node, whose close ends the connection.
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    agent.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    wait_until("released", || h.open_streams("acc_a") == 0);
    let stats: HashMap<_, _> = sni.stats.snapshot().into_iter().collect();
    assert_eq!(stats["forwarded"], 1);
}

#[test]
fn the_ingress_refuses_unknown_offline_and_foreign_names_with_unrecognized_name() {
    let h = Harness::new();
    let node = echo_node(&h, "tok-a1", 14);
    let sni = sni_listener(&h, IngressConfig::default());
    for name in [
        "cccccccccc.node.example.test", // no such node
        "bbbbbbbbbb.node.example.test", // registered, offline
        "aaaaaaaaaa.other.example",     // another zone
        "node.example.test",
    ] {
        let mut agent = agent(sni.addr);
        agent.write_all(&client_hello(name)).unwrap();
        let mut answer = Vec::new();
        let _ = agent.read_to_end(&mut answer);
        assert_eq!(answer, ingress::ALERT_UNRECOGNIZED_NAME, "{name}");
    }
    // A node whose account has no plan: the same answer.
    h.directory.set_entitled("acc_a", false);
    let mut agent = agent(sni.addr);
    agent
        .write_all(&client_hello("aaaaaaaaaa.node.example.test"))
        .unwrap();
    let mut answer = Vec::new();
    let _ = agent.read_to_end(&mut answer);
    assert_eq!(answer, ingress::ALERT_UNRECOGNIZED_NAME);
    assert!(node.opens.try_recv().is_err(), "nothing was forwarded");
}

#[test]
fn the_ingress_closes_truncated_malformed_and_slow_hellos() {
    let h = Harness::new();
    let node = echo_node(&h, "tok-a1", 15);
    let sni = sni_listener(
        &h,
        IngressConfig {
            read_limit: Duration::from_millis(300),
            ..IngressConfig::default()
        },
    );
    let hello = client_hello("aaaaaaaaaa.node.example.test");
    let mut not_tls = b"GET / HTTP/1.1\r\n\r\n".to_vec();
    not_tls.resize(64, b' ');
    let mut too_long = hello.clone();
    too_long[3..5].copy_from_slice(&(16 * 1024 + 1u16).to_be_bytes());
    for (what, bytes) in [
        ("slow", hello[..20].to_vec()),
        ("not tls", not_tls),
        ("record over 16 KiB", too_long),
    ] {
        let started = Instant::now();
        let mut agent = agent(sni.addr);
        agent.write_all(&bytes).unwrap();
        let mut answer = Vec::new();
        let _ = agent.read_to_end(&mut answer);
        assert!(answer.is_empty(), "{what}: {answer:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{what}: deadline"
        );
    }
    // A client that sends nothing is closed at the deadline.
    let started = Instant::now();
    let mut silent = agent(sni.addr);
    let mut answer = Vec::new();
    let _ = silent.read_to_end(&mut answer);
    assert!(answer.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert!(node.opens.try_recv().is_err(), "nothing was forwarded");
    let stats: HashMap<_, _> = sni.stats.snapshot().into_iter().collect();
    assert_eq!(stats["timeouts"], 2);
    assert_eq!(stats["malformed"], 2);
}

#[test]
fn the_ingress_limits_new_connections_by_address() {
    let h = Harness::new();
    let _node = echo_node(&h, "tok-a1", 16);
    let sni = sni_listener(
        &h,
        IngressConfig {
            per_address_per_minute: 2,
            ..IngressConfig::default()
        },
    );
    let hello = client_hello("cccccccccc.node.example.test");
    for _ in 0..2 {
        let mut agent = agent(sni.addr);
        agent.write_all(&hello).unwrap();
        let mut answer = Vec::new();
        let _ = agent.read_to_end(&mut answer);
        assert_eq!(answer, ingress::ALERT_UNRECOGNIZED_NAME);
    }
    let mut third = agent(sni.addr);
    let _ = third.write_all(&hello);
    let mut answer = Vec::new();
    let _ = third.read_to_end(&mut answer);
    assert!(
        answer.is_empty(),
        "the third connection of the minute is closed"
    );
    let stats: HashMap<_, _> = sni.stats.snapshot().into_iter().collect();
    assert_eq!(stats["rate_limited"], 1);
}

fn acme_request(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: synthetic-acme\r\n\r\n")
        .into_bytes()
}

#[test]
fn the_acme_path_forwards_only_challenges_for_a_known_name() {
    let h = Harness::new();
    let node = echo_node(&h, "tok-a1", 17);
    let acme = ingress::serve_acme(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        h.broker.clone(),
        IngressConfig::default(),
    )
    .unwrap();
    let request = acme_request(
        "aaaaaaaaaa.node.example.test",
        "/.well-known/acme-challenge/SynthToken_0123",
    );
    let mut client = agent(acme.addr);
    client.write_all(&request).unwrap();
    let (_, kind, flags, payload) = node.open();
    assert_eq!((kind, flags), (Kind::Acme, OPEN | CLOSE));
    assert_eq!(payload, request);
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, request, "the node's answer comes back unchanged");
    for (host, path) in [
        ("aaaaaaaaaa.node.example.test", "/mcp"),
        (
            "aaaaaaaaaa.node.example.test",
            "/.well-known/acme-challenge/../x",
        ),
        ("aaaaaaaaaa.node.example.test", "/.well-known/other"),
        (
            "cccccccccc.node.example.test",
            "/.well-known/acme-challenge/tok",
        ),
        (
            "bbbbbbbbbb.node.example.test",
            "/.well-known/acme-challenge/tok",
        ),
        ("example.org", "/.well-known/acme-challenge/tok"),
    ] {
        let mut client = agent(acme.addr);
        client.write_all(&acme_request(host, path)).unwrap();
        let mut answer = Vec::new();
        let _ = client.read_to_end(&mut answer);
        assert_eq!(answer, ingress::ACME_NOT_FOUND, "{host}{path}");
    }
    assert!(node.opens.try_recv().is_err(), "nothing else was forwarded");
}

#[test]
fn removing_a_node_and_ending_a_plan_close_the_tunnel() {
    let h = Harness::new();
    let node = echo_node(&h, "tok-a1", 18);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    assert!(h.broker.remove_node(NODE_A));
    assert_eq!(
        node.closed.recv_timeout(Duration::from_secs(10)).unwrap(),
        Some(close::REVOKED)
    );
    device.expect_close(close::NODE_OFFLINE);
    let node = echo_node(&h, "tok-a1", 19);
    h.directory.grant(NODE_A, "acc_b");
    let mut granted = h.dial("tok-b", NODE_A).unwrap();
    granted.send(b"b");
    assert_eq!(granted.read_bytes(1), b"b");
    h.broker.end_account("acc_b");
    granted.expect_close(close::REVOKED);
    assert!(node.resets.recv_timeout(Duration::from_secs(10)).is_ok());
    assert!(h.broker.online(NODE_A), "the granting account's node stays");
}

#[test]
fn usage_counts_bytes_and_streams_and_restores_after_a_restart() {
    let h = Harness::new();
    let _node = echo_node(&h, "tok-a1", 20);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    device.send(&[1u8; 100]);
    assert_eq!(device.read_bytes(100), vec![1u8; 100]);
    let usage = h.broker.usage("acc_a");
    assert_eq!((usage.bytes, usage.dials, usage.streams), (200, 1, 1));
    let restarted = Harness::new();
    restarted.broker.restore_usage("acc_a", &usage);
    assert_eq!(restarted.broker.usage("acc_a").bytes, 200);
    let mut stale = usage.clone();
    stale.month = 202610;
    let other = Harness::new();
    other.broker.restore_usage("acc_a", &stale);
    assert_eq!(other.broker.usage("acc_a").bytes, 0);
}

// ---------------------------------------------------------------------------
// The review of the tunnel: stream ends, the ingress's own limits, other accounts'
// dials, plans and grants that end without a hook, and the stored counters.

fn hello_a() -> Vec<u8> {
    client_hello("aaaaaaaaaa.node.example.test")
}

#[test]
fn an_ingress_stream_ends_when_the_node_closes_it_and_later_client_bytes_are_not_counted() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let sni = sni_listener(&h, IngressConfig::default());
    let mut agent = agent(sni.addr);
    agent.write_all(&hello_a()).unwrap();
    let open = node.next_frame();
    assert_eq!((open.kind, open.flags), (Kind::Public, OPEN));
    // The node answers and closes its side; the agent keeps its own side open.
    node.send_frame(open.stream, Kind::Public, CLOSE, b"last bytes");
    let mut answer = Vec::new();
    agent.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"last bytes");
    // Connect closes the client's direction too: the stream ends at once, as a dial.
    let other_way = node.next_frame();
    assert_eq!((other_way.stream, other_way.flags), (open.stream, CLOSE));
    wait_until("the slot is free", || h.open_streams("acc_a") == 0);
    // Bytes that the agent sends after the node's close are not counted.
    let before = h.broker.usage("acc_a").bytes;
    let _ = agent.write_all(b"more bytes after the end");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(h.broker.usage("acc_a").bytes, before);
}

#[test]
fn the_ingress_has_slots_an_open_rate_and_a_first_byte_deadline_of_its_own() {
    let h = Harness::with(
        Limits {
            dials_per_minute: 1000,
            ingress_streams: 2,
            ingress_per_minute: 3,
            ingress_first_byte: Duration::from_secs(1),
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let mut node = h.node("tok-a1").unwrap();
    // Every dial slot is taken: the ingress still opens, on its own slots.
    let _dials: Vec<Peer> = (0..64)
        .map(|_| h.dial("tok-a2", NODE_A).expect("a dial slot"))
        .collect();
    for _ in 0..64 {
        assert!(node.next_frame().is_open());
    }
    let sni = sni_listener(&h, IngressConfig::default());
    let mut first = agent(sni.addr);
    first.write_all(&hello_a()).unwrap();
    let first_open = node.next_frame();
    assert_eq!(first_open.kind, Kind::Public);
    let mut second = agent(sni.addr);
    second.write_all(&hello_a()).unwrap();
    let second_open = node.next_frame();
    assert_eq!(second_open.kind, Kind::Public);
    // A third is over the two ingress slots: closed. The dials are untouched.
    let mut third = agent(sni.addr);
    third.write_all(&hello_a()).unwrap();
    let mut answer = Vec::new();
    let _ = third.read_to_end(&mut answer);
    assert!(answer.is_empty(), "over the ingress slots");
    assert_eq!(h.broker.usage("acc_a").open_streams, 66);
    // The node answers the first and never the second: the second is reset at the
    // first-byte deadline; the first stays.
    node.send_frame(first_open.stream, Kind::Public, 0, b"server hello");
    let mut got = [0u8; 12];
    first.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"server hello");
    let reset = loop {
        let frame = node.next_frame();
        if frame.is_reset() {
            break frame;
        }
    };
    assert_eq!(reset.stream, second_open.stream);
    let mut answer = Vec::new();
    let _ = second.read_to_end(&mut answer);
    assert!(answer.is_empty());
    wait_until("one ingress stream", || {
        h.broker.ingress_usage("acc_a").open_streams == 1
    });
    // Three streams opened this minute, the refused one too: a fourth waits for the next
    // minute although a slot is free.
    let mut fourth = agent(sni.addr);
    fourth.write_all(&hello_a()).unwrap();
    let mut answer = Vec::new();
    let _ = fourth.read_to_end(&mut answer);
    assert!(answer.is_empty(), "over the open rate");
    h.clock.advance(60);
    let mut fifth = agent(sni.addr);
    fifth.write_all(&hello_a()).unwrap();
    let fifth_open = node.next_frame();
    assert!(fifth_open.is_open() && fifth_open.stream > reset.stream);
    // The dials stay at their own limit all along.
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
}

#[test]
fn the_ingress_spends_a_budget_of_its_own_and_never_the_dials() {
    let hello = hello_a();
    let h = Harness::with(
        Limits {
            bytes_per_month: 10_000,
            // The hello and its echo fit; 100 more bytes of the agent do not.
            ingress_bytes_per_month: 2 * hello.len() as u64 + 100,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 22);
    let sni = sni_listener(&h, IngressConfig::default());
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    device.send(&[3u8; 100]);
    assert_eq!(device.read_bytes(100), vec![3u8; 100]);
    let mut agent = agent(sni.addr);
    agent.write_all(&hello).unwrap();
    let mut echoed = vec![0u8; hello.len()];
    agent.read_exact(&mut echoed).unwrap();
    assert_eq!(
        h.broker.ingress_usage("acc_a").bytes,
        2 * hello.len() as u64
    );
    agent.write_all(&[4u8; 100]).unwrap();
    let mut rest = Vec::new();
    let _ = agent.read_to_end(&mut rest);
    let ingress = h.broker.ingress_usage("acc_a");
    assert!(ingress.tripped, "the ingress budget is spent");
    // A new agent is refused for the rest of the month; the dial goes on, and new dials
    // open: the dial budget is not touched.
    let mut late = TcpStream::connect(sni.addr).unwrap();
    late.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    late.write_all(&hello).unwrap();
    let mut answer = Vec::new();
    let _ = late.read_to_end(&mut answer);
    assert!(answer.is_empty());
    device.send(b"still here");
    assert_eq!(device.read_bytes(10), b"still here");
    let mut again = h.dial("tok-a2", NODE_A).expect("dials are not limited");
    again.send(b"ok");
    assert_eq!(again.read_bytes(2), b"ok");
    let usage = h.broker.usage("acc_a");
    assert!(!usage.tripped);
    assert!(
        usage.bytes > ingress.bytes,
        "the account's bytes count both"
    );
}

#[test]
fn another_accounts_dials_count_apart_and_leave_the_owner_its_share() {
    let h = Harness::with(
        Limits {
            dials_per_minute: 3,
            streams_per_account: 4,
            streams_per_grantee: 2,
            grantee_streams: 2,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 23);
    h.directory.grant(NODE_A, "acc_b");
    let _b: Vec<Peer> = (0..2)
        .map(|_| h.dial("tok-b", NODE_A).expect("the grantee's slots"))
        .collect();
    // Its third dial is over its slots, its fourth over its own rate.
    for _ in 0..2 {
        assert_eq!(
            h.dial("tok-b", NODE_A).err(),
            Some((429, "tunnel_limit".into()))
        );
    }
    // The owner's devices have their own rate and the rest of the slots.
    let _own: Vec<Peer> = (0..2)
        .map(|_| h.dial("tok-a2", NODE_A).expect("the owner's share"))
        .collect();
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((429, "tunnel_limit".into())),
        "the account's four slots are taken"
    );
    let grantee = h.broker.grantee_usage("acc_a", "acc_b");
    assert_eq!((grantee.dials, grantee.open_streams), (3, 2));
    let usage = h.broker.usage("acc_a");
    assert_eq!((usage.dials, usage.open_streams), (6, 4));
}

#[test]
fn the_dials_of_other_accounts_spend_only_their_share_of_the_dial_budget() {
    let h = Harness::with(
        Limits {
            bytes_per_month: 1000,
            grantee_bytes_percent: 50,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 24);
    h.directory.grant(NODE_A, "acc_b");
    let mut own = h.dial("tok-a2", NODE_A).unwrap();
    own.send(&[5u8; 100]);
    assert_eq!(own.read_bytes(100), vec![5u8; 100]);
    // 250 bytes each way: the grantees' half (500) is spent, its dial closes with 4002.
    let mut granted = h.dial("tok-b", NODE_A).unwrap();
    granted.send(&[6u8; 250]);
    granted.expect_close(close::TUNNEL_LIMIT);
    assert!(h.broker.grantee_usage("acc_a", "acc_b").tripped);
    assert_eq!(
        h.dial("tok-b", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
    // The owner's dials go on with the rest of the budget.
    own.send(b"mine");
    assert_eq!(own.read_bytes(4), b"mine");
    assert!(h.dial("tok-a2", NODE_A).is_ok());
    assert!(!h.broker.usage("acc_a").tripped);
}

#[test]
fn a_plan_or_a_grant_that_ends_without_a_hook_ends_its_open_streams() {
    let h = Harness::with(
        Limits {
            recheck: Duration::from_millis(100),
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 25);
    h.directory.grant(NODE_A, "acc_b");
    let mut granted = h.dial("tok-b", NODE_A).unwrap();
    let mut own = h.dial("tok-a2", NODE_A).unwrap();
    granted.send(b"b");
    assert_eq!(granted.read_bytes(1), b"b");
    // The grant stops holding (the accounts no longer share a group): its dial ends.
    h.directory.revoke(NODE_A, "acc_b");
    granted.expect_close(close::REVOKED);
    own.send(b"a");
    assert_eq!(own.read_bytes(1), b"a");
    // The plan ends by time, without billing's hook: the account's streams end.
    h.directory.set_entitled("acc_a", false);
    own.expect_close(close::REVOKED);
    assert!(h.broker.online(NODE_A), "the node stays connected");
    assert_eq!(
        h.dial("tok-a2", NODE_A).err(),
        Some((403, "plan_required".into()))
    );
}

#[test]
fn the_ingress_and_other_accounts_have_stored_counters_of_their_own() {
    let h = Harness::new();
    let _node = echo_node(&h, "tok-a1", 26);
    h.directory.grant(NODE_A, "acc_b");
    let mut granted = h.dial("tok-b", NODE_A).unwrap();
    granted.send(&[1u8; 10]);
    assert_eq!(granted.read_bytes(10), vec![1u8; 10]);
    let sni = sni_listener(&h, IngressConfig::default());
    let hello = hello_a();
    let mut agent = agent(sni.addr);
    agent.write_all(&hello).unwrap();
    let mut echoed = vec![0u8; hello.len()];
    agent.read_exact(&mut echoed).unwrap();
    let all: HashMap<String, _> = h.broker.usage_all().into_iter().collect();
    assert_eq!(all["acc_a"].bytes, 20 + 2 * hello.len() as u64);
    assert_eq!(all["acc_a"].streams, 2);
    assert_eq!(all["acc_a/ingress"].bytes, 2 * hello.len() as u64);
    assert_eq!(all["acc_a/dial/acc_b"].bytes, 20);
    assert_eq!(all["acc_a/dial/acc_b"].dials, 1);
    let restarted = Harness::new();
    for (key, usage) in &all {
        restarted.broker.restore_usage(key, usage);
    }
    assert_eq!(restarted.broker.usage("acc_a").bytes, all["acc_a"].bytes);
    assert_eq!(
        restarted.broker.ingress_usage("acc_a").bytes,
        2 * hello.len() as u64
    );
    assert_eq!(restarted.broker.grantee_usage("acc_a", "acc_b").bytes, 20);
}

#[test]
fn a_substring_of_upgrade_is_not_an_upgrade_and_a_body_keeps_its_length() {
    let server = tiny_http::Server::http_with_deadlines(
        "127.0.0.1:0",
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let handler = thread::spawn(move || {
        let mut request = server.recv().unwrap();
        let mut body = Vec::new();
        let read = request.as_reader().read_to_end(&mut body);
        let _ = request.respond(tiny_http::Response::from_string("ok"));
        (read.is_ok(), body)
    });
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // A token that only contains "upgrade", and bytes after the body that are not its.
    client
        .write_all(
            b"POST /x HTTP/1.1\r\nHost: relay.test\r\nConnection: keep-alive, x-upgraded\r\nContent-Length: 5\r\n\r\nhelloGET /y HTTP/1.1\r\n",
        )
        .unwrap();
    let (read, body) = handler.join().unwrap();
    assert!(read);
    assert_eq!(body, b"hello", "the body is framed by its Content-Length");
}

#[test]
fn the_ingress_of_many_nodes_never_takes_the_streams_kept_for_dials() {
    assert_eq!(Limits::default().ingress_cap(), 2048);
    let limits = Limits {
        max_streams: 8,
        ingress_share_percent: 50,
        ..test_limits()
    };
    assert_eq!(limits.ingress_cap(), 4);
    let h = Harness::with(limits, Duration::from_secs(30));
    let mut node_a = h.node("tok-a1").unwrap();
    let mut node_b = h.node("tok-b").unwrap();
    let sni = sni_listener(&h, IngressConfig::default());
    let hello = |label: &str| client_hello(&format!("{label}.node.example.test"));
    // Two nodes of two accounts, each far below its own ingress slots (16), fill the
    // broker's ingress share together.
    let mut agents = Vec::new();
    for round in 0..2 {
        for (label, node) in [("aaaaaaaaaa", &mut node_a), ("bbbbbbbbbb", &mut node_b)] {
            let mut client = agent(sni.addr);
            client.write_all(&hello(label)).unwrap();
            let open = node.next_frame();
            assert_eq!(
                (open.kind, open.flags),
                (Kind::Public, OPEN),
                "{label} {round}"
            );
            agents.push(client);
        }
    }
    assert_eq!(h.broker.ingress_usage("acc_a").open_streams, 2);
    assert_eq!(h.broker.ingress_usage("acc_b").open_streams, 2);
    // A fifth ingress stream, to either node, is over the share although the broker has
    // room: closed without an answer.
    for label in ["aaaaaaaaaa", "bbbbbbbbbb"] {
        let mut client = agent(sni.addr);
        client.write_all(&hello(label)).unwrap();
        let mut answer = Vec::new();
        let _ = client.read_to_end(&mut answer);
        assert!(answer.is_empty(), "{label}: over the ingress share");
    }
    // The rest of the broker's streams stays for the dials.
    let dials: Vec<Peer> = (0..4)
        .map(|_| h.dial("tok-a2", NODE_A).expect("a stream kept for dials"))
        .collect();
    // Now the broker is full: one more dial is 429.
    assert_eq!(
        h.dial("tok-b", NODE_B).err(),
        Some((429, "tunnel_limit".into()))
    );
    // An ingress stream that ends gives its place back to the ingress.
    drop(agents.pop());
    loop {
        let frame = node_b.next_frame();
        if frame.flags & CLOSE != 0 {
            node_b.send_frame(frame.stream, Kind::Public, CLOSE, b"");
            break;
        }
    }
    wait_until("one ingress place free", || {
        h.broker.ingress_usage("acc_b").open_streams == 1
    });
    let mut client = agent(sni.addr);
    client.write_all(&hello("bbbbbbbbbb")).unwrap();
    let open = node_b.next_frame();
    assert_eq!((open.kind, open.flags), (Kind::Public, OPEN));
    drop(dials);
}

// ---------------------------------------------------------------------------
// Windows, ACME slots, the recheck, and half-closed clients.

/// A node that answers the first stream with `total` bytes (`i % 251`), only within the
/// window that Connect grants, then closes. Every frame of Connect goes through a
/// sequencer of its own, so Connect sending over the node's window fails the test.
fn window_node(mut node: Peer, total: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut seq: Sequencer<()> = Sequencer::new();
        let open = node.next_any_frame();
        seq.apply(Dir::ToNode, &open, || ()).expect("open");
        let mut sent = 0usize;
        while sent < total {
            let credit = seq.credit(open.stream, Dir::ToConnect).expect("live") as usize;
            if credit == 0 {
                let frame = node.next_any_frame();
                seq.apply(Dir::ToNode, &frame, || ())
                    .expect("within the rules");
                continue;
            }
            let take = credit.min(frame::MAX_PAYLOAD).min(total - sent);
            let piece: Vec<u8> = (sent..sent + take).map(|i| (i % 251) as u8).collect();
            seq.apply_parts(Dir::ToConnect, open.stream, open.kind, 0, &piece, || ())
                .expect("within the window");
            node.send_frame(open.stream, open.kind, 0, &piece);
            sent += take;
        }
        node.send_frame(open.stream, open.kind, CLOSE, &[]);
        // Keep the WebSocket until Connect closes its direction.
        loop {
            let frame = node.next_any_frame();
            if frame.is_close() || frame.is_reset() {
                return;
            }
        }
    })
}

#[test]
fn a_large_answer_reaches_a_slow_client_whole_and_the_buffer_stays_bounded() {
    let h = Harness::new();
    let node = window_node(h.node("tok-a1").unwrap(), 5 * 1024 * 1024);
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    // The client reads 64 KiB, then waits: twenty times slower than the node can send.
    let mut answer = Vec::new();
    while answer.len() < 5 * 1024 * 1024 {
        let target = (answer.len() + 64 * 1024).min(5 * 1024 * 1024);
        while answer.len() < target {
            match device.next() {
                Message::Binary(bytes) => answer.extend(bytes),
                other => panic!("expected the answer, got {other:?}"),
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(answer.len(), 5 * 1024 * 1024);
    assert!(
        answer
            .iter()
            .enumerate()
            .all(|(i, byte)| *byte == (i % 251) as u8),
        "every byte arrives, in order"
    );
    device.expect_close(close::NORMAL);
    assert!(
        h.broker.peak_stream_buffer() <= Limits::default().stream_buffer,
        "at most the window waits for the client: {}",
        h.broker.peak_stream_buffer()
    );
    node.join().unwrap();
}

#[test]
fn connect_sends_a_clients_bytes_only_within_the_nodes_window() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let mut device = h.dial("tok-a2", NODE_A).unwrap();
    let mut seq: Sequencer<()> = Sequencer::new();
    let open = node.next_any_frame();
    seq.apply(Dir::ToNode, &open, || ()).unwrap();
    let total = 4 * frame::INITIAL_WINDOW as usize;
    let sender = thread::spawn(move || {
        for piece in vec![9u8; total].chunks(frame::MAX_PAYLOAD) {
            device.send(piece);
        }
        device
    });
    // The node grants a little at a time, late; every frame of Connect stays within it.
    let mut got = 0usize;
    while got < total {
        let frame = node.next_any_frame();
        seq.apply(Dir::ToNode, &frame, || ())
            .unwrap_or_else(|error| panic!("{}", error.code()));
        got += if frame.is_window() {
            0
        } else {
            frame.payload.len()
        };
        if seq.credit(open.stream, Dir::ToNode) == Some(0) && got < total {
            thread::sleep(Duration::from_millis(100));
            let grant = frame::window(open.stream, Kind::Device, 32 * 1024);
            seq.apply(Dir::ToConnect, &frame::decode(&grant).unwrap(), || ())
                .unwrap();
            node.send(&grant);
        }
    }
    assert_eq!(got, total);
    let _device = sender.join().unwrap();
}

#[test]
fn the_acme_challenge_gets_through_when_the_public_streams_are_full_and_spent() {
    let hello = hello_a();
    let h = Harness::with(
        Limits {
            ingress_streams: 1,
            ingress_per_minute: 1,
            ingress_bytes_per_month: 2 * hello.len() as u64 + 100,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 41);
    let sni = sni_listener(&h, IngressConfig::default());
    let acme = ingress::serve_acme(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        h.broker.clone(),
        IngressConfig::default(),
    )
    .unwrap();
    let challenge = || {
        let request = acme_request(
            "aaaaaaaaaa.node.example.test",
            "/.well-known/acme-challenge/SynthToken_0123",
        );
        let mut client = agent(acme.addr);
        client.write_all(&request).unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, request, "the challenge reaches the node and back");
    };
    // The one public slot is taken and the minute's public rate is used up.
    let mut holder = agent(sni.addr);
    holder.write_all(&hello).unwrap();
    let mut echoed = vec![0u8; hello.len()];
    holder.read_exact(&mut echoed).unwrap();
    let mut refused = agent(sni.addr);
    refused.write_all(&hello).unwrap();
    let mut nothing = Vec::new();
    let _ = refused.read_to_end(&mut nothing);
    assert!(nothing.is_empty(), "the public class is full");
    challenge();
    // The public budget of the month is spent: public streams end and are refused.
    holder.write_all(&[4u8; 100]).unwrap();
    let mut rest = Vec::new();
    let _ = holder.read_to_end(&mut rest);
    assert!(h.broker.ingress_usage("acc_a").tripped);
    h.clock.advance(60);
    let mut late = agent(sni.addr);
    late.write_all(&hello).unwrap();
    let mut nothing = Vec::new();
    let _ = late.read_to_end(&mut nothing);
    assert!(nothing.is_empty(), "the public budget is spent");
    challenge();
    let acme_usage = h.broker.acme_usage("acc_a");
    assert_eq!(acme_usage.streams, 2);
    assert!(!acme_usage.tripped);
    assert!(
        h.broker.ingress_usage("acc_a").bytes <= 2 * hello.len() as u64 + 200,
        "the challenges are not in the public budget"
    );
}

#[test]
fn the_acme_class_has_slots_of_its_own_inside_the_brokers_ingress_share() {
    let h = Harness::with(
        Limits {
            acme_streams: 1,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    // A node that never answers keeps the one ACME slot.
    let mut node = h.node("tok-a1").unwrap();
    let request = acme_request(
        "aaaaaaaaaa.node.example.test",
        "/.well-known/acme-challenge/SynthToken_0123",
    );
    let first = h
        .broker
        .open_ingress(
            "aaaaaaaaaa.node.example.test",
            Kind::Acme,
            request.clone(),
            CLOSE,
        )
        .expect("the first ACME stream");
    assert_eq!(node.next_frame().kind, Kind::Acme);
    assert!(
        h.broker
            .open_ingress("aaaaaaaaaa.node.example.test", Kind::Acme, request, CLOSE)
            .is_err(),
        "the ACME slots are full"
    );
    drop(first);
}

#[test]
fn a_directory_that_cannot_answer_skips_rounds_and_then_ends_streams_with_1013() {
    let h = Harness::with(
        Limits {
            recheck: Duration::from_millis(100),
            recheck_skips: 5,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let _node = echo_node(&h, "tok-a1", 42);
    h.directory.grant(NODE_A, "acc_b");
    let mut own = h.dial("tok-a2", NODE_A).unwrap();
    let mut granted = h.dial("tok-b", NODE_A).unwrap();
    // A short failure of the store: a few rounds are skipped and the streams stay.
    h.directory.set_failing(true);
    thread::sleep(Duration::from_millis(250));
    h.directory.set_failing(false);
    thread::sleep(Duration::from_millis(250));
    own.send(b"a");
    assert_eq!(own.read_bytes(1), b"a");
    granted.send(b"b");
    assert_eq!(granted.read_bytes(1), b"b");
    // A new dial while the store fails is 503 `busy`, never `plan_required`.
    h.directory.set_failing(true);
    assert_eq!(h.dial("tok-a2", NODE_A).err(), Some((503, "busy".into())));
    // A long failure ends the open streams with 1013 (try again), never 4003.
    own.expect_close(close::TRY_AGAIN);
    granted.expect_close(close::TRY_AGAIN);
    assert!(h.broker.online(NODE_A), "the node stays connected");
    h.directory.set_failing(false);
    let mut again = h.dial("tok-a2", NODE_A).expect("a dial again");
    again.send(b"c");
    assert_eq!(again.read_bytes(1), b"c");
}

#[test]
fn one_other_account_spends_only_its_part_of_the_share_of_other_accounts() {
    let h = Harness::with(
        Limits {
            bytes_per_month: 1000,
            grantee_bytes_percent: 50,
            streams_per_grantee: 16,
            grantee_streams: 32,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    h.directory.add_device("tok-c", "acc_c", "dev_c");
    let _node = echo_node(&h, "tok-a1", 43);
    h.directory.grant(NODE_A, "acc_b");
    h.directory.grant(NODE_A, "acc_c");
    // The share of other accounts is 500 bytes, of which one spends at most 250.
    let mut b = h.dial("tok-b", NODE_A).unwrap();
    b.send(&[6u8; 125]);
    b.expect_close(close::TUNNEL_LIMIT);
    assert!(h.broker.grantee_usage("acc_a", "acc_b").tripped);
    assert_eq!(
        h.dial("tok-b", NODE_A).err(),
        Some((429, "tunnel_limit".into()))
    );
    // The other account still has its part.
    let mut c = h.dial("tok-c", NODE_A).expect("its own part");
    c.send(&[7u8; 100]);
    assert_eq!(c.read_bytes(100), vec![7u8; 100]);
    assert!(!h.broker.grantee_usage("acc_a", "acc_c").tripped);
}

#[test]
fn an_agent_that_half_closes_gives_the_node_the_close_grace_of_silence() {
    let h = Harness::new();
    let mut node = h.node("tok-a1").unwrap();
    let sni = sni_listener(&h, IngressConfig::default());
    let mut agent = agent(sni.addr);
    agent.write_all(&hello_a()).unwrap();
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    let open = node.next_frame();
    assert_eq!(open.kind, Kind::Public);
    let close_frame = node.next_frame();
    assert_eq!(
        (close_frame.stream, close_frame.flags),
        (open.stream, CLOSE)
    );
    // The node may still answer the half-closed agent within the grace.
    node.send_frame(open.stream, Kind::Public, 0, b"answer");
    let mut answer = [0u8; 6];
    agent.read_exact(&mut answer).unwrap();
    assert_eq!(&answer, b"answer");
    // Then it stays silent: Connect resets the stream and ends the agent's connection.
    let started = Instant::now();
    let reset = node.next_frame();
    assert_eq!((reset.stream, reset.flags), (open.stream, RESET));
    assert!(started.elapsed() >= Duration::from_millis(200));
    let mut rest = Vec::new();
    let _ = agent.read_to_end(&mut rest);
    assert!(rest.is_empty());
}

#[test]
fn a_half_closed_agent_that_reads_slowly_gets_a_large_answer_whole() {
    // A window of 4 MiB: Connect grants the node 1 MiB more each time the agent read a
    // quarter of it. The agent reads 64 KiB each 100 ms, so between two grants the node
    // waits for window for about 1.6 s, longer than the grace of silence (1 s), while the
    // bytes that reach the agent move every 100 ms.
    let h = Harness::with(
        Limits {
            close_grace: Duration::from_secs(1),
            stream_buffer: 4 * 1024 * 1024,
            ..test_limits()
        },
        Duration::from_secs(30),
    );
    let total = 8 * 1024 * 1024;
    let mut node = h.node("tok-a1").unwrap();
    let sni = sni_listener(&h, IngressConfig::default());
    let mut agent = agent(sni.addr);
    agent
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    agent.write_all(&hello_a()).unwrap();
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    let open = node.next_any_frame();
    assert_eq!(open.kind, Kind::Public);
    let sender = thread::spawn(move || {
        let mut seq: Sequencer<()> = Sequencer::new();
        seq.apply(Dir::ToNode, &open, || ()).expect("open");
        let mut sent = 0usize;
        while sent < total {
            let credit = seq.credit(open.stream, Dir::ToConnect).unwrap_or(0) as usize;
            if credit == 0 {
                // Connect's frames: its close of the agent's direction, windows, or a reset.
                let frame = match node.reader.read_message() {
                    Ok(Message::Binary(bytes)) => frame::decode(&bytes).unwrap(),
                    Ok(Message::Ping(payload)) => {
                        let _ = client::send(&mut node.writer, ws::OP_PONG, &payload);
                        continue;
                    }
                    other => return Err(format!("after {sent} bytes: {other:?}")),
                };
                if frame.is_reset() {
                    return Err(format!("reset after {sent} bytes"));
                }
                seq.apply(Dir::ToNode, &frame, || ()).expect("the rules");
                continue;
            }
            let take = credit.min(frame::MAX_PAYLOAD).min(total - sent);
            let piece: Vec<u8> = (sent..sent + take).map(|i| (i % 251) as u8).collect();
            seq.apply_parts(Dir::ToConnect, open.stream, open.kind, 0, &piece, || ())
                .expect("within the window");
            node.send_frame(open.stream, open.kind, 0, &piece);
            sent += take;
        }
        node.send_frame(open.stream, open.kind, CLOSE, &[]);
        Ok(node)
    });
    let mut answer = Vec::with_capacity(total);
    let mut buffer = vec![0u8; 64 * 1024];
    'reading: loop {
        let mut got = 0;
        while got < buffer.len() {
            match agent.read(&mut buffer[got..]) {
                Ok(0) => {
                    answer.extend_from_slice(&buffer[..got]);
                    break 'reading;
                }
                Ok(n) => got += n,
                Err(error) => panic!("read after {} bytes: {error}", answer.len() + got),
            }
        }
        answer.extend_from_slice(&buffer[..got]);
        thread::sleep(Duration::from_millis(100));
    }
    let node = sender.join().unwrap().expect("the node sent all of it");
    assert_eq!(answer.len(), total, "the whole answer");
    assert!(
        answer
            .iter()
            .enumerate()
            .all(|(i, byte)| *byte == (i % 251) as u8),
        "in order"
    );
    drop(node);
}

#[test]
fn the_acme_class_has_an_open_rate_of_its_own_for_each_account() {
    let h = Harness::new();
    let _node = h.node("tok-a1").unwrap();
    let request = acme_request(
        "aaaaaaaaaa.node.example.test",
        "/.well-known/acme-challenge/SynthToken_0123",
    );
    let open = || {
        h.broker
            .open_ingress(
                "aaaaaaaaaa.node.example.test",
                Kind::Acme,
                request.clone(),
                CLOSE,
            )
            .map(drop)
    };
    // Each stream ends at once, so its slot is free again: only the rate refuses.
    for n in 0..30 {
        assert!(open().is_ok(), "ACME stream {n} of this minute");
    }
    assert!(open().is_err(), "the 31st ACME stream of a minute");
    h.clock.advance(60);
    assert!(open().is_ok(), "a new minute");
}
