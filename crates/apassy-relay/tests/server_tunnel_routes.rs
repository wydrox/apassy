//! The Connect tunnel wired to the accounts (unit CW; docs/contracts/connect-tunnel-v1.md,
//! docs/SPEC.md section 35): the routes of sections 3 and 6 on a running relay with the
//! account routes, real account devices, a fake node that echoes, the hooks of revoke,
//! account deletion, plans, and groups, the usage across a restart, the ingress started
//! from the configuration, and the refusal of an `Upgrade` on every other route. Each test
//! starts its own relay on free loopback ports in a temporary directory. Synthetic values
//! only.

#[path = "common/relay.rs"]
mod relay;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy_relay::api::{
    PlanView, TunnelGrantDeleted, TunnelGrantRequest, TunnelGrantView, TunnelNodeDeleted,
    TunnelNodeRegister, TunnelNodeView,
};
use apassy_relay::config::{ConnectConfig, RelayConfig, UpstreamOptions};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::error::{RelayResult, status_of};
use apassy_relay::hostkeys::encode_b64;
use apassy_relay::server::account::{Groups, Plans};
use apassy_relay::server::ingress;
use apassy_relay::server::store::Store;
use apassy_relay::server::tunnel::frame::{self, CLOSE, Kind, OPEN};
use apassy_relay::server::tunnel::ws::{self, Message, client, close};
use apassy_relay::server::tunnel_routes;
use apassy_relay::server::{Relay, RunningRelay};
use relay::{EDGE_SECRET, call_url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const ZONE: &str = "node.example.test";
const PIN: &str = "7a1oa64ozJdU3s56iDjUthpkQFsZwnCaD5CYEkabiDk";
const PIN2: &str = "kzYVkHzBOBuYVbwRjhZCuGpp0da_DLwpc6ttWPAckLM";
const EXAMPLES: &str = include_str!("../../../tests/fixtures/connect-tunnel-v1/examples.json");

// ---- The plans and groups of the tests: billing and groups fill the real ones. ----

#[derive(Default)]
struct TestPlans(Mutex<HashMap<String, (bool, u64)>>);

impl TestPlans {
    fn set(&self, account: &str, entitled: bool) {
        self.0
            .lock()
            .unwrap()
            .entry(account.to_string())
            .or_insert((false, 1))
            .0 = entitled;
    }
}

impl Plans for TestPlans {
    fn plan(&self, _directory: &Store, account: &str, _now: u64) -> RelayResult<PlanView> {
        let entitled = self
            .0
            .lock()
            .unwrap()
            .get(account)
            .is_some_and(|(entitled, _)| *entitled);
        Ok(if entitled {
            PlanView {
                plan: Some("family".into()),
                status: "active".into(),
                entitled: true,
                interval: Some("month".into()),
                quantity: Some(1),
                ..PlanView::none()
            }
        } else {
            PlanView::none()
        })
    }

    fn people(&self, _directory: &Store, account: &str, _now: u64) -> RelayResult<u64> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(account)
            .map_or(1, |(_, people)| *people))
    }
}

#[derive(Default)]
struct TestGroups(Mutex<HashSet<(String, String)>>);

impl TestGroups {
    fn join(&self, a: &str, b: &str) {
        let mut pairs = self.0.lock().unwrap();
        pairs.insert((a.to_string(), b.to_string()));
        pairs.insert((b.to_string(), a.to_string()));
    }

    fn part(&self, a: &str, b: &str) {
        let mut pairs = self.0.lock().unwrap();
        pairs.remove(&(a.to_string(), b.to_string()));
        pairs.remove(&(b.to_string(), a.to_string()));
    }
}

impl Groups for TestGroups {
    fn share_group(
        &self,
        _directory: &Store,
        account: &str,
        other: &str,
        _now: u64,
    ) -> RelayResult<bool> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .contains(&(account.to_string(), other.to_string())))
    }
}

// ---- A relay with the account routes. ----

struct Connect {
    running: Option<RunningRelay>,
    cfg: RelayConfig,
    /// The owner token of the operator team that `Relay::init` made: a team token.
    team_token: String,
    plans: Arc<TestPlans>,
    groups: Arc<TestGroups>,
    _dir: tempfile::TempDir,
}

fn connect_with(edit: impl FnOnce(&mut RelayConfig)) -> Connect {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = relay::test_config(dir.path(), UpstreamOptions::default());
    cfg.connect = ConnectConfig::accounts(None);
    cfg.connect.tunnel.node_zone = ZONE.to_string();
    edit(&mut cfg);
    let owner = Relay::init(&cfg, "Test Team", "owner").unwrap();
    let running = relay::start_on_free_port(&mut cfg);
    let connect = Connect {
        running: Some(running),
        cfg,
        team_token: owner.expose().to_string(),
        plans: Arc::new(TestPlans::default()),
        groups: Arc::new(TestGroups::default()),
        _dir: dir,
    };
    connect.install();
    connect
}

fn start() -> Connect {
    connect_with(|_| {})
}

impl Drop for Connect {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
    }
}

impl Connect {
    fn install(&self) {
        let hub = self.running().hub();
        hub.set_plans(self.plans.clone());
        hub.set_groups(self.groups.clone());
    }

    fn running(&self) -> &RunningRelay {
        self.running.as_ref().expect("running")
    }

    fn addr(&self) -> SocketAddr {
        self.running().addr
    }

    fn origin(&self) -> &str {
        &self.cfg.public_url
    }

    /// Stops the relay and starts it again on the same data directory.
    fn restart(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        self.running = Some(relay::start_on_free_port(&mut self.cfg));
        self.install();
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        call_url(
            &self.running().url(),
            Some(EDGE_SECRET),
            method,
            path,
            token,
            body,
        )
    }

    fn ok(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> Value {
        let (status, value) = self.call(method, path, token, body);
        assert_eq!(status, 200, "{method} {path}: {value}");
        value["result"].clone()
    }

    fn fails(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        status: u16,
        code: &str,
    ) {
        let (got, value) = self.call(method, path, token, body);
        assert_eq!(
            (got, value["error"]["code"].as_str()),
            (status, Some(code)),
            "{method} {path}: {value}"
        );
    }

    fn directory_rows(&self, sql: &str) -> Vec<String> {
        let conn = rusqlite::Connection::open(self.cfg.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// A WebSocket handshake through the edge to `path`; `Err` is the refusal.
    fn upgrade(&self, path: &str, token: Option<&str>) -> Result<Peer, (u16, String)> {
        let mut stream = TcpStream::connect(self.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let key = client::new_key();
        stream
            .write_all(&ws_request(path, &key, token, &[]))
            .unwrap();
        match client::finish(&mut stream, &key) {
            Ok(()) => Ok(Peer::new(stream)),
            Err(client::HandshakeError::Refused(refused)) => {
                let body: Value = serde_json::from_slice(&refused.body).unwrap_or_default();
                Err((
                    refused.status,
                    body["error"]["code"].as_str().unwrap_or("").to_string(),
                ))
            }
            Err(other) => panic!("handshake: {other:?}"),
        }
    }

    fn node_socket(&self, token: &str) -> Result<Peer, (u16, String)> {
        self.upgrade("/v1/tunnel/node", Some(token))
    }

    fn dial(&self, token: &str, node_id: &str) -> Result<Peer, (u16, String)> {
        self.upgrade(&format!("/v1/tunnel/dial/{node_id}"), Some(token))
    }

    fn register(&self, token: &str, name: &str) -> Value {
        self.ok(
            "POST",
            "/v1/tunnel/nodes",
            Some(token),
            Some(&json!({"name": name, "pin": PIN})),
        )
    }

    fn online(&self, node_id: &str) -> bool {
        self.running()
            .hub()
            .tunnel()
            .is_some_and(|broker| broker.online(node_id))
    }
}

/// The upgrade request of `ws::client`, with the edge header and `extra` headers.
fn ws_request(path: &str, key: &str, token: Option<&str>, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut text = String::from_utf8(client::request("relay.test", path, key, token)).unwrap();
    text.truncate(text.len() - 2);
    text.push_str(&format!("X-Apassy-Edge: {EDGE_SECRET}\r\n"));
    for (name, value) in extra {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    text.into_bytes()
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < until, "timed out waiting: {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

// ---- Account devices (connect-account-v1). ----

struct Dev {
    key: DeviceKey,
    account: String,
    id: String,
}

fn create(c: &Connect) -> Dev {
    let key = DeviceKey::generate().unwrap();
    let public_key = key.public_key_b64();
    let recovery_key = device::RecoveryKey::from_code(&[7u8; 16])
        .unwrap()
        .public_key_b64();
    let signature = key
        .sign(&device::account_message(
            c.origin(),
            &public_key,
            &recovery_key,
        ))
        .unwrap();
    let made = c.ok(
        "POST",
        "/v1/account",
        None,
        Some(
            &json!({"name": "Rafal", "device_name": "MacBook Pro", "platform": "mac",
                     "public_key": public_key, "recovery_key": recovery_key,
                     "signature": encode_b64(&signature)}),
        ),
    );
    Dev {
        key,
        account: made["account_id"].as_str().unwrap().to_string(),
        id: made["device_id"].as_str().unwrap().to_string(),
    }
}

fn sign_in(c: &Connect, dev: &Dev) -> String {
    let answer = c.ok(
        "POST",
        "/v1/account/challenge",
        None,
        Some(&json!({"account_id": dev.account, "public_key": dev.key.public_key_b64()})),
    );
    let nonce = answer["nonce"].as_str().unwrap().to_string();
    let message = device::account_sign_in_message(
        c.origin(),
        &dev.account,
        &dev.key.public_key_b64(),
        &nonce,
    );
    let granted = c.ok(
        "POST",
        "/v1/account/token",
        None,
        Some(
            &json!({"account_id": dev.account, "public_key": dev.key.public_key_b64(),
                     "nonce": nonce, "signature": encode_b64(&dev.key.sign(&message).unwrap())}),
        ),
    );
    granted["token"].as_str().unwrap().to_string()
}

/// `a` adds a new device to its account: the link, the join, the confirmation.
fn add_device(c: &Connect, a: &Dev, token: &str, name: &str) -> Dev {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    let code = format!(
        "apassy_alk_{}_{}",
        a.account,
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let hash = device::account_link_hash(&code);
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(token),
        Some(&json!({"link_hash": hash})),
    );
    let key = DeviceKey::generate().unwrap();
    let public_key = key.public_key_b64();
    let signature = key
        .sign(&device::account_join_message(
            c.origin(),
            &a.account,
            &hash,
            &public_key,
        ))
        .unwrap();
    let joined = c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(
            &json!({"account_id": a.account, "link_hash": hash, "device_name": name,
                     "platform": "iphone", "public_key": public_key,
                     "signature": encode_b64(&signature)}),
        ),
    );
    let join_id = joined["join_id"].as_u64().unwrap();
    let statement = a
        .key
        .sign(&device::account_device_message(
            c.origin(),
            &a.account,
            &hash,
            &public_key,
        ))
        .unwrap();
    let added = c.ok(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(token),
        Some(&json!({"public_key": public_key, "statement": encode_b64(&statement)})),
    );
    Dev {
        key,
        account: a.account.clone(),
        id: added["device_id"].as_str().unwrap().to_string(),
    }
}

// ---- A client WebSocket (a device or a node) and a node that echoes. ----

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

/// A node that echoes every stream back and closes its side when Connect closes. It
/// reports each `open` and the close code of its WebSocket.
struct EchoNode {
    opens: mpsc::Receiver<(Kind, u8, Vec<u8>)>,
    closed: mpsc::Receiver<Option<u16>>,
}

impl EchoNode {
    fn open(&self) -> (Kind, u8, Vec<u8>) {
        self.opens
            .recv_timeout(Duration::from_secs(10))
            .expect("an open")
    }

    fn closed(&self) -> Option<u16> {
        self.closed
            .recv_timeout(Duration::from_secs(10))
            .expect("the node's WebSocket closed")
    }
}

fn echo_node(mut node: Peer) -> EchoNode {
    let (open_tx, opens) = mpsc::channel();
    let (close_tx, closed) = mpsc::channel();
    thread::spawn(move || {
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
                continue;
            }
            if frame.is_open() {
                let _ = open_tx.send((frame.kind, frame.flags, frame.payload.clone()));
            }
            if !frame.payload.is_empty() {
                node.send(&frame::encode(frame.stream, frame.kind, 0, &frame.payload));
            }
            if frame.is_close() {
                node.send(&frame::encode(frame.stream, frame.kind, CLOSE, &[]));
            }
        }
    });
    EchoNode { opens, closed }
}

/// An account with a Mac and an iPhone, both signed in, entitled.
struct Account {
    mac: Dev,
    mac_token: String,
    phone: Dev,
    phone_token: String,
}

fn account(c: &Connect) -> Account {
    let mac = create(c);
    let mac_token = sign_in(c, &mac);
    let phone = add_device(c, &mac, &mac_token, "iPhone");
    let phone_token = sign_in(c, &phone);
    c.plans.set(&mac.account, true);
    Account {
        mac,
        mac_token,
        phone,
        phone_token,
    }
}

/// The Mac's node, registered and online with an echo node.
fn online_node(c: &Connect, a: &Account) -> (String, EchoNode) {
    let node_id = c.register(&a.mac_token, "MacBook Pro")["node_id"]
        .as_str()
        .unwrap()
        .to_string();
    let node = echo_node(c.node_socket(&a.mac_token).expect("the node connects"));
    wait_until("online", || c.online(&node_id));
    (node_id, node)
}

// ---- The routes. ----

#[test]
fn a_device_registers_its_node_and_dials_it_through_the_routes() {
    let c = start();
    let a = account(&c);
    let first = c.register(&a.mac_token, "MacBook Pro");
    let node_id = first["node_id"].as_str().unwrap().to_string();
    assert!(
        tunnel_routes_valid_node(&node_id),
        "node_ and 10 of a-z2-7: {node_id}"
    );
    let view: TunnelNodeView = serde_json::from_value(first.clone()).unwrap();
    assert_eq!(view.account_id, a.mac.account);
    assert_eq!(view.device_id, a.mac.id);
    assert_eq!(view.name, "MacBook Pro");
    assert_eq!(view.pin, PIN);
    assert_eq!(view.public_name, format!("{}.{ZONE}", &node_id[5..]));
    assert!(!view.online);
    // One stable node for each device: again with a new name and pin, the same node.
    let again = c.ok(
        "POST",
        "/v1/tunnel/nodes",
        Some(&a.mac_token),
        Some(&json!({"name": "  Studio Mac ", "pin": PIN2})),
    );
    assert_eq!(again["node_id"], node_id.as_str());
    assert_eq!(again["name"], "Studio Mac");
    assert_eq!(again["pin"], PIN2);
    assert_eq!(again["created_at"], first["created_at"]);
    // The node's WebSocket answers 101 with the subprotocol (checked by `client::finish`).
    let node = echo_node(c.node_socket(&a.mac_token).expect("101"));
    wait_until("online", || c.online(&node_id));
    let listed = c.ok("GET", "/v1/tunnel/nodes", Some(&a.phone_token), None);
    let listed: Vec<TunnelNodeView> = serde_json::from_value(listed).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].node_id, node_id);
    assert!(listed[0].online);
    // The iPhone dials the node and its bytes come back through the echo node.
    let mut dial = c.dial(&a.phone_token, &node_id).expect("101");
    let (kind, flags, payload) = node.open();
    assert_eq!((kind, flags, payload.len()), (Kind::Device, OPEN, 0));
    dial.send(b"hello through the tunnel");
    assert_eq!(dial.read_bytes(24), b"hello through the tunnel");
    let big: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
    dial.send(&big);
    assert_eq!(dial.read_bytes(big.len()), big);
    let usage = c.running().hub().tunnel().unwrap().usage(&a.mac.account);
    assert_eq!((usage.dials, usage.streams), (1, 1));
    assert!(usage.bytes >= 2 * (24 + 16384), "{usage:?}");
}

fn tunnel_routes_valid_node(node_id: &str) -> bool {
    apassy_relay::server::tunnel::valid_node_id(node_id)
}

#[test]
fn node_bodies_are_strict_and_the_routes_need_an_account_device() {
    let c = start();
    let a = account(&c);
    for body in [
        json!({"name": "Mac"}),
        json!({"name": "Mac", "pin": PIN, "extra": 1}),
        json!({"name": "", "pin": PIN}),
        json!({"name": "x".repeat(65), "pin": PIN}),
        json!({"name": "Mac\u{7}", "pin": PIN}),
        json!({"name": "Mac", "pin": "short"}),
        json!({"name": "Mac", "pin": format!("{}=", &PIN[..42])}),
        json!({"name": "Mac", "pin": "+a1oa64ozJdU3s56iDjUthpkQFsZwnCaD5CYEkabiDk"}),
    ] {
        c.fails(
            "POST",
            "/v1/tunnel/nodes",
            Some(&a.mac_token),
            Some(&body),
            400,
            "invalid_request",
        );
    }
    let (status, value) = call_url(
        &c.running().url(),
        Some(EDGE_SECRET),
        "POST",
        "/v1/tunnel/grants",
        Some(&a.mac_token),
        Some(&json!({"node_id": "node_aaaaaaaaaa"})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (400, Some("invalid_request"))
    );
    for (method, path) in [
        ("GET", "/v1/tunnel/nodes"),
        ("POST", "/v1/tunnel/nodes"),
        ("GET", "/v1/tunnel/grants"),
        ("DELETE", "/v1/tunnel/grants/tgr_aaaaaaaaaa"),
    ] {
        let body = (method == "POST").then(|| json!({"name": "Mac", "pin": PIN}));
        c.fails(method, path, None, body.as_ref(), 401, "unauthenticated");
        c.fails(
            method,
            path,
            Some("apassy_act_acc_aaaaaaaaaa_00"),
            body.as_ref(),
            401,
            "unauthenticated",
        );
        c.fails(
            method,
            path,
            Some(&c.team_token),
            body.as_ref(),
            403,
            "account_required",
        );
    }
    c.fails(
        "PUT",
        "/v1/tunnel/nodes",
        Some(&a.mac_token),
        None,
        405,
        "method_not_allowed",
    );
    c.fails(
        "GET",
        "/v1/tunnel/nowhere",
        Some(&a.mac_token),
        None,
        404,
        "not_found",
    );
    c.fails(
        "DELETE",
        "/v1/tunnel/nodes/node_aaaaaaaaaa",
        Some(&a.mac_token),
        None,
        404,
        "node_unknown",
    );
    c.fails(
        "DELETE",
        "/v1/tunnel/grants/tgr_aaaaaaaaaa",
        Some(&a.mac_token),
        None,
        404,
        "not_found",
    );
    // The node WebSocket of a device without a node.
    assert_eq!(
        c.node_socket(&a.mac_token).err(),
        Some((404, "node_unknown".to_string()))
    );
}

#[test]
fn the_dial_checks_run_in_the_contract_order() {
    let c = connect_with(|cfg| cfg.connect.tunnel.streams_per_account = 1);
    let a = account(&c);
    let b = account(&c);
    let node_id = c.register(&a.mac_token, "MacBook Pro")["node_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/v1/tunnel/dial/{node_id}");
    let refused = |token: Option<&str>, path: &str| c.upgrade(path, token).err();
    // 1. Not a WebSocket upgrade (a plain GET), or another subprotocol: 400, before the
    // token is looked at.
    c.fails("GET", &path, None, None, 400, "invalid_request");
    c.fails(
        "GET",
        &path,
        Some(&a.phone_token),
        None,
        400,
        "invalid_request",
    );
    let mut stream = TcpStream::connect(c.addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let key = client::new_key();
    let request = String::from_utf8(ws_request(&path, &key, None, &[]))
        .unwrap()
        .replace("apassy-tunnel-v1", "chat");
    stream.write_all(request.as_bytes()).unwrap();
    match client::finish(&mut stream, &key) {
        Err(client::HandshakeError::Refused(refused)) => assert_eq!(refused.status, 400),
        other => panic!("{other:?}"),
    }
    // 2. 401 without a valid account token, 403 with a team token; before the node.
    for token in [None, Some("apassy_act_acc_aaaaaaaaaa_00"), Some("garbage")] {
        assert_eq!(
            refused(token, "/v1/tunnel/dial/node_zzzzzzzzzz"),
            Some((401, "unauthenticated".to_string()))
        );
    }
    assert_eq!(
        refused(Some(&c.team_token), "/v1/tunnel/dial/node_zzzzzzzzzz"),
        Some((403, "account_required".to_string()))
    );
    // 3. No such node (and a malformed id).
    for missing in ["node_zzzzzzzzzz", "node_x", "nonsense"] {
        assert_eq!(
            refused(Some(&a.phone_token), &format!("/v1/tunnel/dial/{missing}")),
            Some((404, "node_unknown".to_string())),
            "{missing}"
        );
    }
    // 4. Another account without a grant, even while the node's account has no plan.
    c.plans.set(&a.mac.account, false);
    assert_eq!(
        refused(Some(&b.phone_token), &path),
        Some((403, "not_in_group".to_string()))
    );
    // 5. The node's account has no plan; before the offline node.
    assert_eq!(
        refused(Some(&a.phone_token), &path),
        Some((403, "plan_required".to_string()))
    );
    c.plans.set(&a.mac.account, true);
    // 7. The node has no WebSocket.
    assert_eq!(
        refused(Some(&a.phone_token), &path),
        Some((503, "tunnel_offline".to_string()))
    );
    // 6. The open streams of the account (1 here): the second dial is 429.
    let node = echo_node(c.node_socket(&a.mac_token).unwrap());
    wait_until("online", || c.online(&node_id));
    let mut first = c.dial(&a.phone_token, &node_id).expect("101");
    node.open();
    assert_eq!(
        refused(Some(&a.phone_token), &path),
        Some((429, "tunnel_limit".to_string()))
    );
    first.send(b"still fine");
    assert_eq!(first.read_bytes(10), b"still fine");
    // A revoked device's token is 401 at once.
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", b.phone.id),
        Some(&b.mac_token),
        None,
    );
    assert_eq!(
        refused(Some(&b.phone_token), &path),
        Some((401, "unauthenticated".to_string()))
    );
}

#[test]
fn a_grant_lets_another_account_dial_and_its_deletion_resets_the_stream() {
    let c = start();
    let a = account(&c);
    let b = account(&c);
    let (node_id, node) = online_node(&c, &a);
    let path = format!("/v1/tunnel/dial/{node_id}");
    let grant = json!({"node_id": node_id, "account_id": b.mac.account});
    // No group: no grant, no dial.
    c.fails(
        "POST",
        "/v1/tunnel/grants",
        Some(&a.mac_token),
        Some(&grant),
        403,
        "not_in_group",
    );
    c.groups.join(&a.mac.account, &b.mac.account);
    // Only a device of the node's account grants; not for its own account; no unknown node.
    c.fails(
        "POST",
        "/v1/tunnel/grants",
        Some(&b.mac_token),
        Some(&json!({"node_id": node_id, "account_id": a.mac.account})),
        403,
        "forbidden",
    );
    c.fails(
        "POST",
        "/v1/tunnel/grants",
        Some(&a.mac_token),
        Some(&json!({"node_id": node_id, "account_id": a.mac.account})),
        400,
        "invalid_request",
    );
    c.fails(
        "POST",
        "/v1/tunnel/grants",
        Some(&a.mac_token),
        Some(&json!({"node_id": "node_zzzzzzzzzz", "account_id": b.mac.account})),
        404,
        "node_unknown",
    );
    assert_eq!(
        c.upgrade(&path, Some(&b.phone_token)).err(),
        Some((403, "not_in_group".to_string()))
    );
    let made: TunnelGrantView = serde_json::from_value(c.ok(
        "POST",
        "/v1/tunnel/grants",
        Some(&a.mac_token),
        Some(&grant),
    ))
    .unwrap();
    assert!(made.grant_id.starts_with("tgr_") && made.grant_id.len() == 14);
    assert_eq!(
        (made.node_id.as_str(), made.account_id.as_str()),
        (node_id.as_str(), b.mac.account.as_str())
    );
    let same: TunnelGrantView = serde_json::from_value(c.ok(
        "POST",
        "/v1/tunnel/grants",
        Some(&a.phone_token),
        Some(&grant),
    ))
    .unwrap();
    assert_eq!(same, made);
    for token in [&a.mac_token, &b.phone_token] {
        let listed: Vec<TunnelGrantView> =
            serde_json::from_value(c.ok("GET", "/v1/tunnel/grants", Some(token), None)).unwrap();
        assert_eq!(listed, vec![made.clone()]);
    }
    let seen: Vec<TunnelNodeView> =
        serde_json::from_value(c.ok("GET", "/v1/tunnel/nodes", Some(&b.phone_token), None))
            .unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].node_id.as_str(), seen[0].account_id.as_str()),
        (node_id.as_str(), a.mac.account.as_str())
    );
    // The grantee dials; deleting the grant resets its stream at once (4003).
    let mut dial = c.dial(&b.phone_token, &node_id).expect("101");
    node.open();
    dial.send(b"across accounts");
    assert_eq!(dial.read_bytes(15), b"across accounts");
    let deleted: TunnelGrantDeleted = serde_json::from_value(c.ok(
        "DELETE",
        &format!("/v1/tunnel/grants/{}", made.grant_id),
        Some(&b.phone_token),
        None,
    ))
    .unwrap();
    assert_eq!(
        deleted,
        TunnelGrantDeleted {
            grant_id: made.grant_id.clone(),
            closed_streams: 1
        }
    );
    dial.expect_close(close::REVOKED);
    assert_eq!(
        c.upgrade(&path, Some(&b.phone_token)).err(),
        Some((403, "not_in_group".to_string()))
    );
    // A grant holds only while the accounts share a group.
    c.ok(
        "POST",
        "/v1/tunnel/grants",
        Some(&a.mac_token),
        Some(&grant),
    );
    c.groups.part(&a.mac.account, &b.mac.account);
    assert_eq!(
        c.upgrade(&path, Some(&b.phone_token)).err(),
        Some((403, "not_in_group".to_string()))
    );
    let seen = c.ok("GET", "/v1/tunnel/nodes", Some(&b.phone_token), None);
    assert_eq!(seen, json!([]));
    // The groups' hook: the grants between the two end, both ways, and the stream resets.
    c.groups.join(&a.mac.account, &b.mac.account);
    let mut dial = c.dial(&b.phone_token, &node_id).expect("101");
    node.open();
    let hub = c.running().hub();
    let ended = tunnel_routes::grants_end_between(
        &hub,
        &b.mac.account,
        std::slice::from_ref(&a.mac.account),
        apassy_relay::now_unix(),
    )
    .unwrap();
    assert_eq!(ended, 1);
    dial.expect_close(close::REVOKED);
    assert_eq!(
        c.ok("GET", "/v1/tunnel/grants", Some(&a.mac_token), None),
        json!([])
    );
    assert_eq!(
        tunnel_routes::grants_end_between(
            &hub,
            &a.mac.account,
            std::slice::from_ref(&b.mac.account),
            0
        )
        .unwrap(),
        0
    );
    // Billing's hook: the plan of the node's account ended, its open streams end (4003);
    // the node stays connected, and a new dial is 403 `plan_required`.
    let mut own = c.dial(&a.phone_token, &node_id).expect("101");
    node.open();
    c.plans.set(&a.mac.account, false);
    tunnel_routes::plan_ended(&hub, &a.mac.account);
    own.expect_close(close::REVOKED);
    assert!(c.online(&node_id));
    assert_eq!(
        c.upgrade(&path, Some(&a.phone_token)).err(),
        Some((403, "plan_required".to_string()))
    );
}

#[test]
fn revoking_the_device_closes_its_node_and_deletes_it() {
    let c = start();
    let a = account(&c);
    let (node_id, node) = online_node(&c, &a);
    let mut dial = c.dial(&a.phone_token, &node_id).expect("101");
    node.open();
    // The iPhone revokes the Mac: the node's WebSocket closes (4003), the dial ends as for
    // an offline node (4001), and the node row is gone.
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", a.mac.id),
        Some(&a.phone_token),
        None,
    );
    assert_eq!(node.closed(), Some(close::REVOKED));
    dial.expect_close(close::NODE_OFFLINE);
    assert!(!c.online(&node_id));
    assert_eq!(
        c.ok("GET", "/v1/tunnel/nodes", Some(&a.phone_token), None),
        json!([])
    );
    assert_eq!(
        c.dial(&a.phone_token, &node_id).err(),
        Some((404, "node_unknown".to_string()))
    );
    assert!(
        c.directory_rows("SELECT id FROM tunnel_node").is_empty(),
        "the node row is deleted"
    );
    assert_eq!(
        c.node_socket(&a.mac_token).err(),
        Some((401, "unauthenticated".to_string()))
    );
}

#[test]
fn a_revoked_dialer_and_a_removed_node_close_their_tunnels() {
    let c = start();
    let a = account(&c);
    let (node_id, node) = online_node(&c, &a);
    // A dialing device that is revoked: its dial ends (4003).
    let third = add_device(&c, &a.mac, &a.mac_token, "iPad");
    let third_token = sign_in(&c, &third);
    let mut dial = c.dial(&third_token, &node_id).expect("101");
    node.open();
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", third.id),
        Some(&a.mac_token),
        None,
    );
    dial.expect_close(close::REVOKED);
    assert!(c.online(&node_id), "the node of another device stays");
    // `DELETE /v1/tunnel/nodes/{id}`: only a device of the node's account; the tunnel closes.
    let b = account(&c);
    c.fails(
        "DELETE",
        &format!("/v1/tunnel/nodes/{node_id}"),
        Some(&b.mac_token),
        None,
        404,
        "node_unknown",
    );
    let mut dial = c.dial(&a.phone_token, &node_id).expect("101");
    node.open();
    let deleted: TunnelNodeDeleted = serde_json::from_value(c.ok(
        "DELETE",
        &format!("/v1/tunnel/nodes/{node_id}"),
        Some(&a.phone_token),
        Some(&json!({})),
    ))
    .unwrap();
    assert_eq!(deleted.node_id, node_id);
    assert_eq!(node.closed(), Some(close::REVOKED));
    dial.expect_close(close::NODE_OFFLINE);
    assert_eq!(
        c.node_socket(&a.mac_token).err(),
        Some((404, "node_unknown".to_string()))
    );
    // The device registers again: a new node.
    let again = c.register(&a.mac_token, "MacBook Pro");
    assert_ne!(again["node_id"], node_id.as_str());
}

#[test]
fn deleting_the_account_ends_its_tunnel_and_its_grants() {
    let c = start();
    let a = account(&c);
    let b = account(&c);
    let (node_id, node) = online_node(&c, &a);
    let (b_node, b_echo) = online_node(&c, &b);
    c.groups.join(&a.mac.account, &b.mac.account);
    c.ok(
        "POST",
        "/v1/tunnel/grants",
        Some(&b.mac_token),
        Some(&json!({"node_id": b_node, "account_id": a.mac.account})),
    );
    // A's device dials B's node through B's grant.
    let mut across = c.dial(&a.phone_token, &b_node).expect("101");
    b_echo.open();
    c.ok(
        "DELETE",
        "/v1/account",
        Some(&a.mac_token),
        Some(&json!({})),
    );
    assert_eq!(node.closed(), Some(close::REVOKED));
    across.expect_close(close::REVOKED);
    assert!(!c.online(&node_id));
    assert!(c.online(&b_node), "the other account's node stays");
    assert_eq!(
        c.ok("GET", "/v1/tunnel/grants", Some(&b.mac_token), None),
        json!([])
    );
    assert!(c.directory_rows("SELECT id FROM tunnel_grant").is_empty());
    assert_eq!(
        c.directory_rows("SELECT id FROM tunnel_node"),
        vec![b_node.clone()]
    );
}

#[test]
fn the_ninth_node_of_an_account_is_account_limit() {
    let c = start();
    let a = account(&c);
    let mut tokens = vec![a.mac_token.clone(), a.phone_token.clone()];
    for index in 0..7 {
        let dev = add_device(&c, &a.mac, &a.mac_token, &format!("Device {index}"));
        tokens.push(sign_in(&c, &dev));
    }
    assert_eq!(tokens.len(), 9);
    for token in &tokens[..8] {
        c.register(token, "Node");
    }
    let (status, value) = c.call(
        "POST",
        "/v1/tunnel/nodes",
        Some(&tokens[8]),
        Some(&json!({"name": "Ninth", "pin": PIN})),
    );
    assert_eq!(status, 403, "{value}");
    assert_eq!(value["error"]["code"], "account_limit");
    assert_eq!(value["error"]["message"], "This account has 8 nodes.");
    // A device that has a node may still rename it.
    c.register(&tokens[0], "Renamed");
    assert_eq!(
        c.directory_rows("SELECT id FROM tunnel_node").len(),
        8,
        "eight nodes"
    );
}

#[test]
fn the_monthly_budget_survives_a_restart() {
    let mut c = connect_with(|cfg| cfg.connect.tunnel.bytes_per_month = 4096);
    let a = account(&c);
    let (node_id, node) = online_node(&c, &a);
    let mut dial = c.dial(&a.phone_token, &node_id).expect("101");
    node.open();
    // 3000 bytes each way are over 4096: the stream closes with 4002 and new dials are 429.
    dial.send(&[0x61; 3000]);
    dial.expect_close(close::TUNNEL_LIMIT);
    let path = format!("/v1/tunnel/dial/{node_id}");
    assert_eq!(
        c.upgrade(&path, Some(&a.phone_token)).err(),
        Some((429, "tunnel_limit".to_string()))
    );
    drop(node);
    c.restart();
    // The stop wrote the month's counters; the start restored them.
    let month = apassy_relay::server::tunnel::month_of(apassy_relay::now_unix()).to_string();
    let bytes = c.directory_rows(&format!(
        "SELECT CAST(bytes AS TEXT) FROM tunnel_usage WHERE account_id = '{}' AND month = '{month}'",
        a.mac.account
    ));
    assert_eq!(bytes.len(), 1);
    assert!(bytes[0].parse::<u64>().unwrap() >= 4096, "{bytes:?}");
    let a_token = sign_in(&c, &a.phone);
    // Before the node comes back: the limit comes before 503 `tunnel_offline`.
    assert_eq!(
        c.upgrade(&path, Some(&a_token)).err(),
        Some((429, "tunnel_limit".to_string()))
    );
    let usage = c.running().hub().tunnel().unwrap().usage(&a.mac.account);
    assert!(usage.bytes >= 4096 && usage.dials >= 1, "{usage:?}");
}

#[test]
fn the_ingress_from_the_configuration_forwards_a_client_hello_to_an_online_node() {
    let c = connect_with(|cfg| {
        cfg.connect.tunnel.ingress_listen = Some("127.0.0.1:0".parse().unwrap());
        cfg.connect.tunnel.acme_listen = Some("127.0.0.1:0".parse().unwrap());
    });
    let sni = c.running().tunnel_ingress_addr().expect("the ingress runs");
    let acme = c
        .running()
        .tunnel_acme_addr()
        .expect("the ACME listener runs");
    let a = account(&c);
    let (node_id, node) = online_node(&c, &a);
    let name = format!("{}.{ZONE}", &node_id[5..]);
    let hello = client_hello(&name);
    let mut agent = TcpStream::connect(sni).unwrap();
    agent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    agent.write_all(&hello).unwrap();
    let (kind, flags, payload) = node.open();
    assert_eq!((kind, flags), (Kind::Public, OPEN));
    assert_eq!(payload, hello, "the open carries the exact ClientHello");
    let mut echoed = vec![0u8; hello.len()];
    agent.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, hello);
    drop(agent);
    // A name of no node gets `unrecognized_name`.
    let mut stranger = TcpStream::connect(sni).unwrap();
    stranger
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stranger
        .write_all(&client_hello(&format!("zzzzzzzzzz.{ZONE}")))
        .unwrap();
    let mut answer = Vec::new();
    let _ = stranger.read_to_end(&mut answer);
    assert_eq!(answer, ingress::ALERT_UNRECOGNIZED_NAME);
    // ACME HTTP-01 for the node's public name goes to the node as an `acme` stream.
    let request =
        format!("GET /.well-known/acme-challenge/tok_en-1 HTTP/1.1\r\nHost: {name}\r\n\r\n");
    let mut acme_client = TcpStream::connect(acme).unwrap();
    acme_client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    acme_client.write_all(request.as_bytes()).unwrap();
    let (kind, flags, payload) = node.open();
    assert_eq!((kind, flags), (Kind::Acme, OPEN | CLOSE));
    assert_eq!(payload, request.as_bytes());
    let mut back = Vec::new();
    let _ = acme_client.read_to_end(&mut back);
    assert_eq!(back, request.as_bytes());
}

/// A real ClientHello from rustls for `name`.
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

#[test]
fn without_the_account_routes_nothing_of_the_tunnel_exists() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = relay::test_config(dir.path(), UpstreamOptions::default());
    cfg.connect.tunnel.ingress_listen = Some("127.0.0.1:0".parse().unwrap());
    let owner = Relay::init(&cfg, "Test Team", "owner").unwrap();
    let running = relay::start_on_free_port(&mut cfg);
    assert!(running.hub().tunnel().is_none());
    assert!(
        running.tunnel_ingress_addr().is_none(),
        "no ingress without accounts"
    );
    for (method, path) in [
        ("POST", "/v1/tunnel/nodes"),
        ("GET", "/v1/tunnel/nodes"),
        ("DELETE", "/v1/tunnel/nodes/node_aaaaaaaaaa"),
        ("GET", "/v1/tunnel/node"),
        ("GET", "/v1/tunnel/dial/node_aaaaaaaaaa"),
        ("POST", "/v1/tunnel/grants"),
        ("GET", "/v1/tunnel/grants"),
        ("DELETE", "/v1/tunnel/grants/tgr_aaaaaaaaaa"),
    ] {
        let body = (method == "POST").then(|| json!({}));
        let (status, value) = call_url(
            &running.url(),
            Some(EDGE_SECRET),
            method,
            path,
            Some(owner.expose()),
            body.as_ref(),
        );
        assert_eq!(
            (status, value["error"]["code"].as_str()),
            (404, Some("not_found")),
            "{method} {path}"
        );
    }
    running.stop();
}

// ---- The refusal of an `Upgrade` everywhere else (docs/SPEC.md section 35.6). ----

/// Every route of the relay (docs/SPEC.md and `http::route`), the account routes, the
/// tunnel's JSON routes, near misses of the upgrade routes, and unknown paths.
const ROUTES: &[(&str, &str)] = &[
    ("GET", "/healthz"),
    ("GET", "/v1/me"),
    ("POST", "/v1/join"),
    ("POST", "/v1/teams"),
    ("POST", "/v1/connect"),
    ("POST", "/v1/connect/challenge"),
    ("POST", "/v1/auth/challenge"),
    ("POST", "/v1/auth/token"),
    ("GET", "/v1/devices"),
    ("POST", "/v1/devices/enroll"),
    ("POST", "/v1/devices/link"),
    ("POST", "/v1/devices/link/cancel"),
    ("GET", "/v1/devices/links"),
    ("POST", "/v1/devices/links/1/confirm"),
    ("POST", "/v1/devices/links/1/refuse"),
    ("DELETE", "/v1/devices/1"),
    ("POST", "/v1/devices/1/key-holder"),
    ("GET", "/v1/joins"),
    ("POST", "/v1/joins/1/confirm"),
    ("POST", "/v1/joins/1/refuse"),
    ("POST", "/v1/leave"),
    ("GET", "/v1/invites"),
    ("POST", "/v1/invites"),
    ("GET", "/v1/members"),
    ("DELETE", "/v1/members/1"),
    ("POST", "/v1/members/1/role"),
    ("GET", "/v1/collections"),
    ("POST", "/v1/collections"),
    ("PUT", "/v1/collections/1/policy"),
    ("GET", "/v1/items"),
    ("POST", "/v1/items"),
    ("DELETE", "/v1/items/1"),
    ("GET", "/v1/grants"),
    ("POST", "/v1/grants"),
    ("DELETE", "/v1/grants/1"),
    ("GET", "/v1/agents"),
    ("POST", "/v1/agents"),
    ("DELETE", "/v1/agents/1"),
    ("GET", "/v1/approvals"),
    ("POST", "/v1/approvals/1/approve"),
    ("POST", "/v1/approvals/1/deny"),
    ("GET", "/v1/audit"),
    ("GET", "/v1/access"),
    ("POST", "/v1/runs"),
    ("GET", "/v1/runs/1"),
    ("GET", "/v1/host/requests"),
    ("POST", "/v1/host/requests/1/release"),
    ("POST", "/v1/host/requests/1/deny"),
    ("GET", "/v1/sync"),
    ("GET", "/v1/sync/head"),
    ("GET", "/v1/sync/snapshot"),
    ("PUT", "/v1/sync/snapshot"),
    ("POST", "/v1/sync/receipt"),
    ("GET", "/v1/questions"),
    ("POST", "/v1/questions"),
    ("GET", "/v1/questions/q_1/answers"),
    ("POST", "/v1/questions/q_1/settle"),
    ("POST", "/v1/push/token"),
    ("POST", "/v1/push/handle"),
    ("GET", "/v1/feed"),
    ("PUT", "/v1/feed"),
    ("GET", "/v1/feed/actions"),
    ("POST", "/v1/feed/actions"),
    ("GET", "/v1/feed/actions/a_1"),
    ("POST", "/v1/feed/actions/a_1/settle"),
    ("POST", "/mcp"),
    ("GET", "/mcp"),
    ("GET", "/p/apassy_ses_synthetic/api.example.com/"),
    ("POST", "/p/apassy_ses_synthetic/api.example.com/v1/x"),
    ("POST", "/v1/account"),
    ("GET", "/v1/account"),
    ("DELETE", "/v1/account"),
    ("POST", "/v1/account/challenge"),
    ("POST", "/v1/account/token"),
    ("GET", "/v1/account/entitlement"),
    ("POST", "/v1/account/devices/link"),
    ("GET", "/v1/account/devices/pending"),
    ("POST", "/v1/account/devices/join"),
    ("POST", "/v1/account/devices/join/cancel"),
    ("DELETE", "/v1/account/devices/dev_aaaaaaaaaa"),
    ("POST", "/v1/account/recover"),
    ("GET", "/v1/account/vaults"),
    ("POST", "/v1/account/vaults"),
    ("GET", "/.well-known/apassy-connect.json"),
    ("POST", "/v1/tunnel/nodes"),
    ("GET", "/v1/tunnel/nodes"),
    ("DELETE", "/v1/tunnel/nodes/node_aaaaaaaaaa"),
    ("POST", "/v1/tunnel/grants"),
    ("GET", "/v1/tunnel/grants"),
    ("DELETE", "/v1/tunnel/grants/tgr_aaaaaaaaaa"),
    ("GET", "/v1/tunnel"),
    ("GET", "/v1/tunnel/dial"),
    ("GET", "/v1/tunnel/dial/"),
    ("GET", "/v1/tunnel/node/x"),
    ("GET", "/v1/tunnel/dial/node_aaaaaaaaaa/x"),
    ("POST", "/v1/tunnel/node"),
    ("POST", "/v1/tunnel/dial/node_aaaaaaaaaa"),
    ("GET", "/"),
    ("GET", "/nothing/here"),
    ("GET", "/.well-known/oauth-authorization-server"),
    ("OPTIONS", "/v1/me"),
];

/// The two upgrade routes: refused on every listener but the node listener of a relay
/// with the account routes.
const UPGRADE_ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/tunnel/node"),
    ("GET", "/v1/tunnel/dial/node_aaaaaaaaaa"),
];

/// The ways to ask for an upgrade.
const UPGRADE_HEADERS: &[&[(&str, &str)]] = &[
    &[
        ("Connection", "Upgrade"),
        ("Upgrade", "websocket"),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("Sec-WebSocket-Protocol", "apassy-tunnel-v1"),
        ("Authorization", "Bearer apassy_act_acc_aaaaaaaaaa_00"),
    ],
    &[("Upgrade", "h2c")],
    &[("Connection", "keep-alive, upgrade")],
];

/// One raw request: the status and the body.
fn raw(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: relay.test\r\nX-Apassy-Edge: {EDGE_SECRET}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = if method == "GET" { "" } else { "{}" };
    if method != "GET" {
        head.push_str("Content-Type: application/json\r\nContent-Length: 2\r\n");
    }
    head.push_str("\r\n");
    head.push_str(body);
    stream.write_all(head.as_bytes()).unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer).to_string();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| serde_json::from_str(body).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    (status, body)
}

fn assert_refused(addr: SocketAddr, scope: &str, routes: &[(&str, &str)]) {
    for (method, path) in routes {
        for headers in UPGRADE_HEADERS {
            let (status, body) = raw(addr, method, path, headers);
            assert_eq!(
                (status, body["error"]["code"].as_str()),
                (400, Some("invalid_request")),
                "{scope}: {method} {path} with {headers:?}: {body}"
            );
        }
    }
}

#[test]
fn every_other_route_refuses_an_upgrade_on_every_listener() {
    // Without the account routes, with the public and the tailnet listener: every route,
    // the two tunnel routes too, on all of them.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = relay::test_config(dir.path(), UpstreamOptions::default());
    cfg.public_listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.tailnet_listen = Some("127.0.0.1:0".parse().unwrap());
    Relay::init(&cfg, "Test Team", "owner").unwrap();
    let running = relay::start_on_free_port(&mut cfg);
    let mut all: Vec<(&str, &str)> = ROUTES.to_vec();
    all.extend_from_slice(UPGRADE_ROUTES);
    for (scope, addr) in [
        ("node", Some(running.addr)),
        ("public", running.public_addr),
        ("tailnet", running.tailnet_addr),
        ("local route", running.tailnet_local_addr),
    ] {
        assert_refused(addr.expect("listener"), scope, &all);
    }
    running.stop();
    // With the account routes: every other route on the node listener, and every route on
    // the public listener.
    let c = connect_with(|cfg| cfg.public_listen = Some("127.0.0.1:0".parse().unwrap()));
    assert_refused(c.addr(), "node with accounts", ROUTES);
    assert_refused(
        c.running().public_addr.expect("public"),
        "public with accounts",
        &all,
    );
    // And the two tunnel routes answer `101` there.
    let a = account(&c);
    let (node_id, node) = online_node(&c, &a);
    let mut dial = c.dial(&a.phone_token, &node_id).expect("101");
    node.open();
    dial.send(b"ok");
    assert_eq!(dial.read_bytes(2), b"ok");
}

// ---- The contract's examples (connect-tunnel-v1 section 11). ----

fn strict_round_trip<T: DeserializeOwned + Serialize>(body: &Value) {
    let parsed: T = serde_json::from_value(body.clone()).expect("parses");
    assert_eq!(&serde_json::to_value(&parsed).unwrap(), body);
}

#[test]
fn every_example_of_the_contract_parses_with_the_relay_types() {
    let examples: Value = serde_json::from_str(EXAMPLES).unwrap();
    assert_eq!(examples["contract"], "connect-tunnel-v1");
    let mut seen = 0;
    for example in examples["examples"].as_array().unwrap() {
        let name = example["name"].as_str().unwrap();
        let body = &example["body"];
        match (
            example["route"].as_str().unwrap(),
            example["part"].as_str().unwrap(),
        ) {
            ("POST /v1/tunnel/nodes", "request") => {
                strict_round_trip::<TunnelNodeRegister>(body);
                let mut extra = body.clone();
                extra["extra"] = json!(1);
                assert!(serde_json::from_value::<TunnelNodeRegister>(extra).is_err());
            }
            ("POST /v1/tunnel/nodes", "result") => strict_round_trip::<TunnelNodeView>(body),
            ("GET /v1/tunnel/nodes", "result") => strict_round_trip::<Vec<TunnelNodeView>>(body),
            ("DELETE /v1/tunnel/nodes/{node_id}", "result") => {
                strict_round_trip::<TunnelNodeDeleted>(body)
            }
            ("POST /v1/tunnel/grants", "request") => {
                strict_round_trip::<TunnelGrantRequest>(body);
                let mut extra = body.clone();
                extra["extra"] = json!(1);
                assert!(serde_json::from_value::<TunnelGrantRequest>(extra).is_err());
            }
            ("POST /v1/tunnel/grants", "result") => strict_round_trip::<TunnelGrantView>(body),
            ("GET /v1/tunnel/grants", "result") => strict_round_trip::<Vec<TunnelGrantView>>(body),
            ("DELETE /v1/tunnel/grants/{grant_id}", "result") => {
                strict_round_trip::<TunnelGrantDeleted>(body)
            }
            (_, "error") => {
                let code = body["code"].as_str().unwrap();
                assert_eq!(
                    u64::from(status_of(code)),
                    example["status"].as_u64().unwrap(),
                    "{name}"
                );
            }
            other => panic!("an example without a check: {name} {other:?}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 14);
    // The node of the example's public name.
    let registered = &examples["examples"][1]["body"];
    assert_eq!(
        apassy_relay::server::tunnel::public_name(
            registered["node_id"].as_str().unwrap(),
            "node.apassy.wyderka.cc"
        )
        .as_deref(),
        registered["public_name"].as_str()
    );
}

#[test]
fn a_bad_token_on_an_upgrade_route_counts_toward_the_failed_auth_limit() {
    let c = connect_with(|cfg| cfg.auth_limiter = true);
    let a = account(&c);
    let node_id = c.register(&a.mac_token, "MacBook Pro")["node_id"]
        .as_str()
        .unwrap()
        .to_string();
    let dial = format!("/v1/tunnel/dial/{node_id}");
    for n in 0..apassy_relay::server::http::AUTH_FAILURES_MAX {
        let path = if n % 2 == 0 {
            dial.as_str()
        } else {
            "/v1/tunnel/node"
        };
        assert_eq!(
            c.upgrade(path, Some("apa_not_a_token")).err(),
            Some((401, "unauthenticated".to_string())),
            "{n}"
        );
    }
    assert_eq!(
        c.upgrade(&dial, Some("apa_not_a_token")).err(),
        Some((429, "rate_limited".to_string()))
    );
}
