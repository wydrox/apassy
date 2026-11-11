//! The iPhone reaches its Mac through the Apassy Connect dial when the tailnet route is
//! not there (ADR 0037 stage 7, plan s7 unit I2; ios-core-v1 section 5.15; contracts
//! connect-tunnel-v1 section 3.3 and node-pairing-v1 section 7a). Synthetic values only;
//! nothing leaves the loopback.
//!
//! - **Connect** is the relay crate's own server with the account routes and the tunnel
//!   (`apassy_relay::server::Relay` with `ConnectConfig::accounts`), plain HTTP on the
//!   loopback, with test plans that say which account is on Connect.
//! - **The Mac** is the app's own Connect client (`apassy::connect`, unit M1): it makes
//!   the account and confirms the iPhone after an owner check. Its node is M4's tunnel
//!   (`apassy::node::tunnel::Tunnel`) with a pinned node certificate, in front of the
//!   in-process fake relay of the questions and the feed (`common/questions_relay.rs`).
//! - **The tailnet route** of the node is the real TLS front of the node
//!   (`apassy::net::tls_front::Front`) on a loopback port with the same certificate. "The
//!   tailnet is down" is that front stopped (its port closed); it comes back on the same
//!   port.
//! - **Two recorders** stand between the node and the fake relay, one behind the front and
//!   one behind the tunnel, and keep the plaintext of each request: they tell which route
//!   a request took and let the bytes of the two routes be compared.
//! - **Relay sync** has its own node in front of the app's fake relay of relay sync
//!   (`tests/common/fake_relay.rs`): the Mac makes the vault's team on it, the iPhone
//!   joins and pulls through the dial. The Mac keeps its own way to its node (a second
//!   front), as the real Mac does over the loopback.
//! - **The iPhone** is the core with its Connect origin set to the loopback Connect, its
//!   own account device key in a memory key store, and shorter dial times where a test
//!   needs them (`Core::set_dial_timing`).
//! - **A kept dial** needs a node that keeps its connections, as the relay's tailnet
//!   listener keeps the device streams of the tunnel (docs/SPEC.md section 35.6; its own
//!   tests are `crates/apassy-relay/tests/tunnel_keep_alive.rs`). The fake relays answer
//!   `Connection: close`, so the tests of kept dials put a keeping node ([`Keeping`])
//!   between the recorders and the fake relay: it serves sequential requests on one
//!   connection and forwards each to the fake relay.
//!
//! Each test runs in its own process (nextest, `.config/nextest.toml`): the core sets the
//! Connect origin of its process.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;
#[path = "common/questions_fixture.rs"]
mod questions_fixture;
#[path = "common/questions_relay.rs"]
mod questions_relay;

/// The fake relay of relay sync reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerCheck, OwnerGate};
use apassy::connect::{ConnectAccount, ConnectClient, MemoryKeyStore, account_file};
use apassy::contracts::CredentialKind;
use apassy::net::certificate::NodeCertificate;
use apassy::net::sealed_key::{CONNECT_INFO, SealKey};
use apassy::net::tls_front::{Front, FrontHandle, FrontLimits, FrontOptions};
use apassy::node::tunnel::{
    ConnectSetup, Failure, SystemClock, Targets, Tunnel, TunnelAuth, TunnelHandle, TunnelOptions,
    TunnelState,
};
use apassy::questions::access_request as access;
use apassy::sync::{
    DeviceKey, RelayConfig as SyncConfig, RelaySync, RelayUrl, TlsTrust, TunnelRoute, encode_b64u,
};
use apassy::vault::{Field, ItemDraft, SecretValue};
use apassy::vault::{TrustedDeviceKind, Vault};
use apassy_core::{Core, DialTiming};
use apassy_relay::api::PlanView;
use apassy_relay::config::{ConnectConfig, EdgeMode, RelayConfig, TunnelSettings, UpstreamOptions};
use apassy_relay::error::RelayResult;
use apassy_relay::secret::SecretString;
use apassy_relay::server::account::Plans;
use apassy_relay::server::store::Store;
use apassy_relay::server::{Relay, RunningRelay};
use questions_fixture::{
    ANSWER_PUBLIC, ASKER, KEY_ID, PASS, QID, QUESTION_KEY, TEAM, aad, call, fails, open, post, seal,
};
use questions_relay::QuestionsRelay;
use serde_json::{Value, json};
use tempfile::TempDir;

const ZONE: &str = "node.example.test";
const WAIT: Duration = Duration::from_secs(20);

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting: {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("probe")
        .local_addr()
        .expect("address")
        .port()
}

/// Text that the iPhone must never show or keep about a purchase (plan section 6).
fn assert_no_purchase_text(text: &str) {
    for banned in [
        "\"amount\"",
        "\"currency\"",
        "\"price",
        "EUR",
        "€",
        "checkout",
        "portal",
        "subscribe",
        "Subscribe",
        "upgrade",
        "Upgrade",
        "Buy",
        "pricing",
    ] {
        assert!(!text.contains(banned), "{banned} in {text}");
    }
}

// ---------------------------------------------------------------------------
// Connect: the relay with the account routes and the tunnel.

/// The plans of the tests: which accounts are on Connect.
#[derive(Default)]
struct TestPlans(Mutex<HashMap<String, bool>>);

impl TestPlans {
    fn set(&self, account: &str, entitled: bool) {
        self.0.lock().unwrap().insert(account.to_owned(), entitled);
    }
}

impl Plans for TestPlans {
    fn plan(&self, _directory: &Store, account: &str, _now: u64) -> RelayResult<PlanView> {
        let entitled = self
            .0
            .lock()
            .unwrap()
            .get(account)
            .copied()
            .unwrap_or(false);
        Ok(if entitled {
            PlanView {
                plan: Some("personal".into()),
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
}

struct Connect {
    running: Option<RunningRelay>,
    url: String,
    plans: Arc<TestPlans>,
    _dir: TempDir,
}

impl Drop for Connect {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
    }
}

fn connect(tune: impl FnOnce(&mut TunnelSettings)) -> Connect {
    let dir = tempfile::tempdir().unwrap();
    let mut tunnel = TunnelSettings {
        node_zone: ZONE.to_owned(),
        ..TunnelSettings::default()
    };
    tune(&mut tunnel);
    for _ in 0..5 {
        let port = free_port();
        let mut cfg = RelayConfig {
            data_dir: dir.path().join("data"),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            public_listen: None,
            tailnet_listen: None,
            tailnet_agents: false,
            public_url: format!("http://127.0.0.1:{port}"),
            sign_in_origins: Vec::new(),
            public_origins: Vec::new(),
            edge: EdgeMode::Off,
            master_key: SecretString::new("a synthetic vault passphrase for tests".to_owned()),
            session_ttl_secs: 60,
            approval_timeout_secs: 5,
            upstream: UpstreamOptions::default(),
            request_read_timeout: Duration::from_secs(30),
            request_handle_timeout: Duration::from_secs(90),
            limits: Default::default(),
            backup_dir: dir.path().join("backups"),
            push: None,
            team_vaults: true,
            questions_to_approvers: false,
            connect_teams_per_day: 200,
            connect_teams_max: 1000,
            connect_sync_bytes: 0,
            free_connect: true,
            auth_limiter: false,
            operator_socket: false,
            oauth: None,
            connect: ConnectConfig::accounts(None),
        };
        cfg.connect.tunnel = tunnel.clone();
        if !cfg.data_dir.join("relay.db").exists() {
            Relay::init(&cfg, "Test Team", "owner").expect("init");
        }
        match Relay::start(cfg.clone()) {
            Ok(running) => {
                let plans = Arc::new(TestPlans::default());
                running.hub().set_plans(plans.clone());
                return Connect {
                    url: cfg.public_url.clone(),
                    running: Some(running),
                    plans,
                    _dir: dir,
                };
            }
            Err(error) if error.message.starts_with("Cannot listen") => continue,
            Err(error) => panic!("start: {error:?}"),
        }
    }
    panic!("no free port for Connect");
}

impl Connect {
    fn online(&self, node: &str) -> bool {
        self.running
            .as_ref()
            .and_then(|running| running.hub().tunnel().map(|broker| broker.online(node)))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// The Mac: its Connect account, the owner check, its node.

struct Mac {
    _dir: TempDir,
    _store: MemoryKeyStore,
    account: ConnectAccount,
    _owner_dir: TempDir,
    shared: SharedVault,
    gate: OwnerGate,
}

fn mac(connect: &Connect) -> Mac {
    let dir = TempDir::new().unwrap();
    let store = MemoryKeyStore::new();
    let client = ConnectClient::new(&connect.url).unwrap();
    let (account, _recovery) = ConnectAccount::create(
        client,
        &store,
        &account_file(dir.path()),
        "Rafal",
        "MacBook Pro",
    )
    .expect("account");
    let owner_dir = TempDir::new().unwrap();
    let mut vault = Vault::create(&owner_dir.path().join("owner.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    Mac {
        _dir: dir,
        _store: store,
        account,
        _owner_dir: owner_dir,
        shared,
        gate,
    }
}

impl Mac {
    fn id(&self) -> String {
        self.account.state().account_id.clone()
    }

    /// The account seam of the node: a fixed token of this Mac (it lasts 15 minutes).
    fn auth(&mut self, origin: &str) -> Arc<MacAuth> {
        let token = self
            .account
            .with_token(|_, token| Ok(token.to_owned()))
            .expect("token");
        Arc::new(MacAuth {
            origin: origin.to_owned(),
            token,
            device: self.account.state().device_id.clone(),
        })
    }

    /// The iPhone joins the account with the code of this Mac; the Mac confirms.
    fn add(&mut self, phone: &Phone) {
        let link = self.account.start_link().expect("link");
        let waiting = call(
            &phone.core,
            json!({"op": "connect_join", "link": link.code()}),
        );
        assert_eq!(waiting["state"], "waiting");
        let pending = self.account.pending_joins(&link).expect("pending");
        assert_eq!(pending.len(), 1);
        let proof = self
            .gate
            .authorize(
                pending[0].owner_action(&self.id()),
                OwnerCheck::passphrase(PASS),
            )
            .expect("owner check");
        let epoch = self.shared.lock().unwrap().as_ref().unwrap().epoch();
        self.account
            .confirm_join(&link, &pending[0], proof, &epoch)
            .expect("confirm");
        let confirmed = call(&phone.core, json!({"op": "connect_join_poll"}));
        assert_eq!(confirmed["state"], "confirmed");
    }
}

struct MacAuth {
    origin: String,
    token: String,
    device: String,
}

impl TunnelAuth for MacAuth {
    fn origin(&self) -> String {
        self.origin.clone()
    }
    fn with_token(&self, call: &mut dyn FnMut(&str) -> Result<(), Failure>) -> Result<(), Failure> {
        call(&self.token)
    }
    fn entitled(&self) -> Result<(), Failure> {
        Ok(())
    }
    fn has_account(&self) -> bool {
        true
    }
    fn device_id(&self) -> Option<String> {
        Some(self.device.clone())
    }
    fn sign_out(&self) {}
}

/// The bytes that the connections sent, one buffer for each connection.
type Seen = Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>;

/// A TCP forwarder that keeps the bytes of each connection toward `target`.
struct Recorder {
    addr: SocketAddr,
    seen: Seen,
}

impl Recorder {
    fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { continue };
                let Ok(server) = TcpStream::connect(target) else {
                    continue;
                };
                let bytes = Arc::new(Mutex::new(Vec::new()));
                log.lock().unwrap().push(Arc::clone(&bytes));
                let (mut from_client, mut to_server) =
                    (client.try_clone().unwrap(), server.try_clone().unwrap());
                thread::spawn(move || {
                    let mut buffer = [0u8; 8192];
                    while let Ok(read) = from_client.read(&mut buffer) {
                        if read == 0 {
                            break;
                        }
                        bytes.lock().unwrap().extend_from_slice(&buffer[..read]);
                        if to_server.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                    }
                    let _ = to_server.shutdown(Shutdown::Write);
                });
                let (mut from_server, mut to_client) = (server, client);
                thread::spawn(move || {
                    let _ = std::io::copy(&mut from_server, &mut to_client);
                    let _ = to_client.shutdown(Shutdown::Both);
                });
            }
        });
        Self { addr, seen }
    }

    /// The bytes that each connection sent, in order.
    fn requests(&self) -> Vec<Vec<u8>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|bytes| bytes.lock().unwrap().clone())
            .collect()
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// Read one request (its head and its `Content-Length` body) from `stream` after the
/// bytes in `pending`. `None` at the end of the stream.
fn read_request(stream: &mut TcpStream, pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 8192];
    let end = loop {
        if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return None,
            Ok(read) => pending.extend_from_slice(&buffer[..read]),
        }
    };
    let head = String::from_utf8_lossy(&pending[..end]).to_ascii_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().unwrap());
    while pending.len() < end + length {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return None,
            Ok(read) => pending.extend_from_slice(&buffer[..read]),
        }
    }
    Some(pending.drain(..end + length).collect())
}

/// A node that keeps its connections, as the relay's tailnet listener keeps a device
/// stream of the tunnel: it serves sequential requests on one connection and forwards
/// each to the fake relay at `target` on a connection of its own, and gives back the
/// answer without the fake's `Connection: close` unless the request asked to close.
struct Keeping {
    addr: SocketAddr,
    /// The connections that reached it.
    connections: Arc<AtomicUsize>,
    /// Each request: the number of its connection (from 1), its place on that connection
    /// (from 1), and its bytes.
    requests: Arc<Mutex<Vec<(usize, usize, String)>>>,
    /// The next request of this method that is not the first of its connection meets a
    /// dead connection: it is read, and the connection closes without an answer.
    drop_next: Arc<Mutex<Option<&'static str>>>,
}

impl Keeping {
    fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests: Arc<Mutex<Vec<(usize, usize, String)>>> = Arc::default();
        let drop_next: Arc<Mutex<Option<&'static str>>> = Arc::default();
        let (count, log, dropping) = (
            Arc::clone(&connections),
            Arc::clone(&requests),
            Arc::clone(&drop_next),
        );
        thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(mut client) = client else { continue };
                let number = count.fetch_add(1, Ordering::SeqCst) + 1;
                let (log, dropping) = (Arc::clone(&log), Arc::clone(&dropping));
                thread::spawn(move || {
                    let mut pending = Vec::new();
                    for place in 1.. {
                        let Some(request) = read_request(&mut client, &mut pending) else {
                            return;
                        };
                        let text = String::from_utf8_lossy(&request).to_string();
                        log.lock().unwrap().push((number, place, text.clone()));
                        {
                            let mut dropping = dropping.lock().unwrap();
                            if place > 1 && dropping.is_some_and(|method| text.starts_with(method))
                            {
                                *dropping = None;
                                let _ = client.shutdown(Shutdown::Both);
                                return;
                            }
                        }
                        let close = text.contains("Connection: close\r\n");
                        let Ok(mut relay) = TcpStream::connect(target) else {
                            return;
                        };
                        if relay.write_all(&request).is_err() {
                            return;
                        }
                        let mut answer = Vec::new();
                        let _ = relay.read_to_end(&mut answer);
                        let answer = if close {
                            answer
                        } else {
                            String::from_utf8_lossy(&answer)
                                .replacen("Connection: close\r\n", "", 1)
                                .into_bytes()
                        };
                        if client.write_all(&answer).is_err() || close {
                            let _ = client.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            connections,
            requests,
            drop_next,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<(usize, usize, String)> {
        self.requests.lock().unwrap().clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn copy(certificate: &NodeCertificate) -> NodeCertificate {
    NodeCertificate {
        der: certificate.der.clone(),
        pin: certificate.pin,
        key: certificate.key.clone(),
    }
}

/// The node of the Mac: the front (the tailnet route) and the tunnel to Connect, both in
/// front of the fake relay of the questions through their recorders.
struct Node {
    certificate: NodeCertificate,
    port: u16,
    front: Option<FrontHandle>,
    tunnel: Option<TunnelHandle>,
    auth: Arc<MacAuth>,
    node_dir: TempDir,
    tailnet: Recorder,
    dial: Recorder,
    node_id: String,
    origin: String,
    tunnel_times: (Duration, Duration),
}

fn limits() -> FrontLimits {
    FrontLimits {
        max_connections: 256,
        max_per_peer: 256,
        new_per_peer_per_minute: 100_000,
        ..FrontLimits::default()
    }
}

impl Node {
    fn start(
        connect: &Connect,
        auth: Arc<MacAuth>,
        relay: &QuestionsRelay,
        tunnel_times: (Duration, Duration),
    ) -> Self {
        Self::start_for(
            connect,
            auth,
            &relay.url,
            |origin| relay.set_origin(origin),
            tunnel_times,
        )
    }

    /// The node in front of the fake relay at `relay_url`, which learns the node origin
    /// with `set_origin`.
    fn start_for(
        connect: &Connect,
        auth: Arc<MacAuth>,
        relay_url: &str,
        set_origin: impl FnOnce(&str),
        tunnel_times: (Duration, Duration),
    ) -> Self {
        let target: SocketAddr = relay_url.strip_prefix("http://").unwrap().parse().unwrap();
        let certificate = NodeCertificate::generate("Synthetic Test Mac").unwrap();
        let tailnet = Recorder::start(target);
        let dial = Recorder::start(target);
        let mut node = Self {
            certificate,
            port: 0,
            front: None,
            tunnel: None,
            auth,
            node_dir: TempDir::new().unwrap(),
            tailnet,
            dial,
            node_id: String::new(),
            origin: String::new(),
            tunnel_times,
        };
        node.tailnet_up();
        node.origin = format!("https://127.0.0.1:{}", node.port);
        set_origin(&node.origin);
        node.tunnel_up(connect);
        node
    }

    /// The front on its port (a free one the first time). A port that the last front
    /// just closed can take a moment to bind again.
    fn tailnet_up(&mut self) {
        let mut tries = 0;
        let front = loop {
            let mut options = FrontOptions::new(
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                self.port,
                copy(&self.certificate),
                self.tailnet.addr,
            );
            options.allow_loopback_bind = true;
            options.allow_test_peers = true;
            options.limits = limits();
            match Front::start(options) {
                Ok(front) => break front,
                Err(error) => {
                    tries += 1;
                    assert!(tries < 100, "the front did not start again: {error:?}");
                    thread::sleep(Duration::from_millis(50));
                }
            }
        };
        self.port = front.bound()[0].port();
        self.front = Some(front);
    }

    fn tailnet_down(&mut self) {
        if let Some(mut front) = self.front.take() {
            front.stop();
        }
    }

    fn tunnel_up(&mut self, connect: &Connect) {
        let (ping, idle) = self.tunnel_times;
        let setup = ConnectSetup {
            auth: self.auth.clone(),
            tls: None,
            acme: None,
            clock: Arc::new(SystemClock::default()),
            ping_interval: ping,
            idle_limit: idle,
            close_grace: Duration::from_secs(10),
            limits: limits(),
            zone: ZONE.to_owned(),
        };
        let handle = Tunnel::start(TunnelOptions {
            setup,
            node_dir: self.node_dir.path().to_owned(),
            name: "MacBook Pro".to_owned(),
            certificate: copy(&self.certificate),
            targets: Targets {
                device: Some(self.dial.addr),
                public: None,
            },
            seal: Arc::new(SealKey::derive(&[3u8; 32], CONNECT_INFO).expect("seal")),
        })
        .expect("tunnel");
        wait_until("the node's tunnel is on", || {
            let status = handle.status();
            status.state == TunnelState::On && status.public_name.is_some()
        });
        let name = handle.status().public_name.unwrap();
        self.node_id = format!("node_{}", name.split('.').next().unwrap());
        self.tunnel = Some(handle);
        wait_until("Connect sees the node", || connect.online(&self.node_id));
    }

    fn tunnel_down(&mut self, connect: &Connect) {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
        }
        wait_until("Connect sees the node offline", || {
            !connect.online(&self.node_id)
        });
    }

    fn open_streams(&self) -> usize {
        self.tunnel
            .as_ref()
            .map_or(0, |tunnel| tunnel.status().open_streams)
    }

    /// The Connect route of the node, as the code of the Mac carries it.
    fn route(&self, connect: &Connect) -> String {
        TunnelRoute::new(&connect.url, &self.node_id)
            .unwrap()
            .text()
    }
}

// ---------------------------------------------------------------------------
// The iPhone.

struct Phone {
    _root: TempDir,
    file: PathBuf,
    core: Core,
    relay: QuestionsRelay,
    mac_key: DeviceKey,
}

/// The iPhone with a vault (as from iCloud Drive) that holds the question key and the
/// asking Mac's row (relay device 1 of the fake team), and a core whose Connect origin is
/// the loopback Connect.
fn phone(connect: &Connect, timing: DialTiming) -> Phone {
    let root = TempDir::new().unwrap();
    let data = root.path().join("Apassy");
    std::fs::create_dir_all(&data).unwrap();
    // The access requests keep their guard in the request history (a synthetic key in
    // the place of the Keychain).
    std::fs::create_dir_all(data.join("request-history")).unwrap();
    let config = json!({"data_dir": data, "device_name": "Test iPhone", "role": "app",
                        "request_history_enabled": true, "request_history_required": true,
                        "connect_url": connect.url});
    let core = Core::new_with_history_key_provider(
        &config.to_string(),
        Arc::new(questions_fixture::SyntheticHistoryKeys::default()),
    )
    .expect("core");
    core.set_dial_timing(timing);
    assert!(core.set_account_key_store(Arc::new(MemoryKeyStore::new())));
    let vault = call(
        &core,
        json!({"op": "create_local_vault", "name": "Personal", "passphrase": PASS}),
    );
    let id = vault["vault"]["id"].as_str().unwrap().to_owned();
    call(&core, json!({"op": "lock"}));
    let file = data.join("vaults").join(format!("{id}.apassy"));
    {
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        conn.execute(
            "INSERT INTO vault_secret (name, value, updated_at, updated_by) VALUES ('question-key-v1', ?1, 1, 'mac')",
            [QUESTION_KEY.as_slice()],
        )
        .unwrap();
    }
    let mac_key = DeviceKey::generate().unwrap();
    {
        let mut vault = Vault::open(&file).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .register_trusted_device(
                ASKER,
                "MacBook Pro",
                TrustedDeviceKind::Mac,
                mac_key.public_key(),
                None,
            )
            .unwrap();
        vault.set_trusted_device_relay_id(ASKER, TEAM, 1).unwrap();
    }
    call(&core, json!({"op": "unlock", "passphrase": PASS}));
    let relay = QuestionsRelay::start(TEAM, mac_key.public_key());
    Phone {
        _root: root,
        file,
        core,
        relay,
        mac_key,
    }
}

impl Phone {
    /// Change the vault as the sync of a Mac does: lock, change the file, unlock.
    fn as_the_mac<T>(&self, change: impl FnOnce(&mut Vault) -> T) -> T {
        call(&self.core, json!({"op": "lock"}));
        let out = {
            let mut vault = Vault::open(&self.file).unwrap();
            vault.unlock(PASS).unwrap();
            change(&mut vault)
        };
        call(&self.core, json!({"op": "unlock", "passphrase": PASS}));
        out
    }

    fn status(&self) -> Value {
        call(&self.core, json!({"op": "connect_status"}))
    }
}

/// The pinned device link of the node, with its Connect route and its node id.
fn link_of(phone: &Phone, node: &Node, connect: &Connect, pin: &str) -> String {
    let (_, code) = phone.relay.link();
    format!(
        "{}/link#{code}&pin={pin}&alt={}&node={}",
        node.origin,
        node.route(connect),
        node.node_id
    )
}

/// The iPhone joins the questions team of the node with `link`; the Mac confirms and
/// writes the row of the iPhone.
fn attach(phone: &Phone, link: &str) {
    let waiting = call(
        &phone.core,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(phone.relay.confirm_links(), vec![2]);
    let attached = call(&phone.core, json!({"op": "join_attach_poll"}));
    assert_eq!(attached["state"], "attached");
    let (device_id, name, public_key) = phone.relay.confirmed().pop().unwrap();
    phone.as_the_mac(|vault| {
        apassy::relay::membership::register_linked_device(
            vault,
            TEAM,
            device_id,
            &name,
            &public_key,
        )
        .unwrap()
        .unwrap();
    });
    let list = call(&phone.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["registered"], true, "{list}");
}

/// Everything of one test: Connect, the Mac on Connect, the iPhone in its account, and
/// the node on the tunnel.
struct World {
    connect: Connect,
    mac: Mac,
    phone: Phone,
    node: Node,
}

fn world_with(
    tune: impl FnOnce(&mut TunnelSettings),
    timing: DialTiming,
    tunnel_times: (Duration, Duration),
) -> World {
    let connect = connect(tune);
    let mut mac = mac(&connect);
    connect.plans.set(&mac.id(), true);
    let phone = phone(&connect, timing);
    mac.add(&phone);
    let auth = mac.auth(&connect.url);
    let node = Node::start(&connect, auth, &phone.relay, tunnel_times);
    World {
        connect,
        mac,
        phone,
        node,
    }
}

/// [`world`] with a node that keeps its connections ([`Keeping`]) in front of the fake
/// relay, on both routes; the tailnet is down and the iPhone is attached through the
/// dial.
fn keeping_world() -> (World, Keeping) {
    let connect = connect(|_| {});
    let mut mac = mac(&connect);
    connect.plans.set(&mac.id(), true);
    let phone = phone(&connect, quick());
    mac.add(&phone);
    let auth = mac.auth(&connect.url);
    let target: SocketAddr = phone
        .relay
        .url
        .strip_prefix("http://")
        .unwrap()
        .parse()
        .unwrap();
    let keeping = Keeping::start(target);
    let mut node = Node::start_for(
        &connect,
        auth,
        &keeping.url(),
        |origin| phone.relay.set_origin(origin),
        (Duration::from_secs(30), Duration::from_secs(90)),
    );
    node.tailnet_down();
    let pin = node.certificate.pin.text();
    let w = World {
        connect,
        mac,
        phone,
        node,
    };
    attach(&w.phone, &link_of(&w.phone, &w.node, &w.connect, &pin));
    (w, keeping)
}

/// Short waits, so that the states and the probe fit a test.
fn quick() -> DialTiming {
    DialTiming {
        backoff_first: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        not_on_connect: Duration::from_secs(600),
        limit: Duration::from_millis(50),
        probe_every: Duration::from_millis(100),
        ..DialTiming::default()
    }
}

fn world() -> World {
    world_with(
        |_| {},
        quick(),
        (Duration::from_secs(30), Duration::from_secs(90)),
    )
}

/// The Mac posts the access card of the fixture as `QID`; the iPhone lists it. Returns
/// the vault, the card, and its digest.
fn publish_card(phone: &Phone) -> (String, access::Card, String) {
    let vault = phone.as_the_mac(|v| v.sync_identity().unwrap().vault_id);
    let mut card: access::Card = serde_json::from_str(include_str!(
        "../../../tests/fixtures/access-request-v1/card-body.json"
    ))
    .unwrap();
    card.vault_id = vault;
    card.asker.relay_device_id = 1;
    card.created_at = questions_relay::now();
    card.expires_at = card.created_at + 300;
    let body = serde_json::to_vec(&card).unwrap();
    let signature = phone
        .mac_key
        .sign(&access::body_signature_message("card", &body).unwrap())
        .unwrap();
    let wrapper = access::SignedBody::new("card", &body, &signature).unwrap();
    post(
        &phone.relay,
        &QUESTION_KEY,
        QID,
        &serde_json::to_string(&wrapper).unwrap(),
        card.expires_at,
    );
    let listed = call(&phone.core, json!({"op": "access_requests_list"}));
    assert_eq!(listed["requests"].as_array().unwrap().len(), 1, "{listed}");
    (
        listed["requests"][0]["vault_id"].as_str().unwrap().into(),
        card,
        wrapper.digest,
    )
}

/// The Mac (relay device 1) publishes a feed of `seq` (relay-feed-v1).
fn publish_feed(phone: &Phone, seq: u64) {
    let feed = json!({"v": 1, "mac": {"device": ASKER, "name": "MacBook Pro"}, "seq": seq,
                      "generated_at": questions_relay::now(), "truncated": false,
                      "week": {"by_you": 0, "automatic": 0}, "agents": []})
    .to_string();
    let aad = aad(&[
        "apassy-feed-v1",
        "feed",
        TEAM,
        "1",
        &seq.to_string(),
        KEY_ID,
    ]);
    let (nonce, ciphertext) = seal(&QUESTION_KEY, &aad, feed.as_bytes());
    phone.relay.put_feed(1, seq, KEY_ID, &nonce, &ciphertext);
}

/// The requests of the two routes are the same bytes, but for one line: a request through
/// the dial does not ask for `Connection: close` (the iPhone keeps its dials), and one
/// through the tailnet does.
fn assert_same_but_close(through_tailnet: &[Vec<u8>], through_dial: &[Vec<u8>]) {
    const CLOSE: &str = "Connection: close\r\n";
    let text = |bytes: &Vec<u8>| String::from_utf8(bytes.clone()).unwrap();
    for request in through_tailnet {
        assert_eq!(text(request).matches(CLOSE).count(), 1, "{}", text(request));
    }
    for request in through_dial {
        assert!(!text(request).contains(CLOSE), "{}", text(request));
    }
    let without: Vec<String> = through_tailnet
        .iter()
        .map(|request| text(request).replacen(CLOSE, "", 1))
        .collect();
    let dial: Vec<String> = through_dial.iter().map(text).collect();
    assert_eq!(
        without, dial,
        "the requests are the same bytes on both routes but for Connection: close"
    );
}

/// The requests that `run` made through `recorder`.
fn recorded(recorder: &Recorder, run: impl FnOnce()) -> Vec<Vec<u8>> {
    let before = recorder.count();
    run();
    // A connection writes its bytes on its own thread: give it a moment.
    thread::sleep(Duration::from_millis(100));
    recorder.requests()[before..].to_vec()
}

// ---------------------------------------------------------------------------
// The tests.

/// Plan I2 acceptance: with the tailnet down, the join, access requests, questions, and
/// the feed work through the dial; the requests inside the pinned TLS are byte for byte
/// those of the tailnet route; an answer through the dial opens with the key and the AAD
/// of relay-questions-v1.
#[test]
fn questions_the_feed_and_access_requests_reach_the_mac_through_the_dial_with_the_same_bytes() {
    let mut w = world();
    w.node.tailnet_down();
    let pin = w.node.certificate.pin.text();
    let link = link_of(&w.phone, &w.node, &w.connect, &pin);

    attach(&w.phone, &link);
    assert_eq!(w.node.tailnet.count(), 0, "the tailnet is down");
    assert!(w.node.dial.count() > 0, "the join went through the dial");
    let status = w.phone.status();
    assert_eq!(status["dial_route"], true, "{status}");
    assert_eq!(status["dial_state"], "connected");
    assert_no_purchase_text(&status.to_string());

    // An access request through the dial: listed, prepared, answered.
    let (vault, card, digest) = publish_card(&w.phone);
    let prepared = call(
        &w.phone.core,
        json!({"op": "access_request_prepare", "vault_id": vault, "qid": QID,
               "digest": digest, "kind": "deny"}),
    );
    let sent = call(
        &w.phone.core,
        json!({"op": "access_request_answer", "vault_id": vault, "qid": QID,
               "digest": digest, "kind": "deny", "time": prepared["time"]}),
    );
    assert_eq!(sent["sent"], true);
    let stored = w.phone.relay.answers();
    assert_eq!(stored.len(), 1);
    let aad = aad(&["apassy-question-v1", "answer", TEAM, QID, KEY_ID, "2"]);
    let plaintext = open(&QUESTION_KEY, &aad, &stored[0].nonce, &stored[0].ciphertext)
        .expect("the answer opens with the key and the AAD of the contract");
    let answer = access::Answer::parse(&plaintext).unwrap();
    assert_eq!(answer.request_id, card.request_id);
    assert_eq!(answer.kind.text(), "deny");

    // The feed through the dial.
    publish_feed(&w.phone, 1_790_000_100);
    let feed = call(&w.phone.core, json!({"op": "feed_list"}));
    assert_eq!(
        feed["vaults"][0]["macs"][0]["seq"], 1_790_000_100u64,
        "{feed}"
    );
    assert_eq!(
        w.node.tailnet.count(),
        0,
        "everything went through the dial"
    );

    // The same calls, through the dial and then through the tailnet.
    let calls = || {
        call(&w.phone.core, json!({"op": "feed_list"}));
        call(&w.phone.core, json!({"op": "access_requests_list"}));
    };
    let through_dial = recorded(&w.node.dial, calls);
    assert!(!through_dial.is_empty());
    w.node.tailnet_up();
    // The probe brings the requests back to the tailnet.
    wait_until("the requests come back to the tailnet", || {
        let before = w.node.tailnet.count();
        call(&w.phone.core, json!({"op": "access_requests_list"}));
        w.node.tailnet.count() > before
    });
    let through_tailnet = recorded(&w.node.tailnet, calls);
    assert_same_but_close(&through_tailnet, &through_dial);
    let head = String::from_utf8_lossy(&through_dial[0]).to_string();
    assert!(
        head.contains(&format!("Host: 127.0.0.1:{}\r\n", w.node.port)),
        "{head}"
    );
    assert_eq!(w.phone.status()["dial_route"], false);
}

/// The route order: the tailnet first when both work (no dial at all), the dial when the
/// tailnet goes, and the tailnet again when it comes back.
#[test]
fn the_tailnet_comes_first_and_the_dial_takes_over_and_gives_back() {
    let mut w = world();
    let pin = w.node.certificate.pin.text();
    let link = link_of(&w.phone, &w.node, &w.connect, &pin);
    attach(&w.phone, &link);
    call(&w.phone.core, json!({"op": "access_requests_list"}));
    assert_eq!(w.node.dial.count(), 0, "both work: the tailnet only");
    assert_eq!(
        w.phone.core.dials_for_test(),
        0,
        "no dial while the tailnet works"
    );
    let status = w.phone.status();
    assert_eq!(status["dial_route"], false);
    assert_eq!(status["dial_state"], "unused");

    w.node.tailnet_down();
    let through = recorded(&w.node.dial, || {
        call(&w.phone.core, json!({"op": "access_requests_list"}));
    });
    assert_eq!(through.len(), 1, "the dial took over");
    assert_eq!(w.phone.status()["dial_route"], true);
    // While the tailnet is down, the next requests go through the dial at once.
    let dials = w.phone.core.dials_for_test();
    call(&w.phone.core, json!({"op": "access_requests_list"}));
    assert_eq!(w.phone.core.dials_for_test(), dials + 1);

    w.node.tailnet_up();
    wait_until("the tailnet takes the requests again", || {
        let before = w.node.tailnet.count();
        call(&w.phone.core, json!({"op": "access_requests_list"}));
        w.node.tailnet.count() > before
    });
    let dials = w.phone.core.dials_for_test();
    call(&w.phone.core, json!({"op": "access_requests_list"}));
    assert_eq!(w.phone.core.dials_for_test(), dials, "back on the tailnet");
    assert_eq!(w.phone.status()["dial_route"], false);
}

/// A wrong pin ends the dial before any request: the node's certificate is not the one
/// of the code, so no byte of the join reaches the relay.
#[test]
fn a_wrong_pin_ends_the_dial_before_any_request() {
    let mut w = world();
    w.node.tailnet_down();
    let other = NodeCertificate::generate("Another Mac").unwrap();
    let link = link_of(&w.phone, &w.node, &w.connect, &other.pin.text());
    let code = fails(
        &w.phone.core,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    assert_eq!(code, "pin_mismatch");
    assert!(w.phone.core.dials_for_test() >= 1, "the dial was made");
    thread::sleep(Duration::from_millis(200));
    assert!(
        w.node.dial.requests().iter().all(Vec::is_empty),
        "no request byte reached the node's relay"
    );
    assert!(w.phone.relay.confirmed().is_empty());
    assert!(
        !w.phone
            .relay
            .log()
            .iter()
            .any(|line| line.contains("/v1/devices/link")),
        "{:?}",
        w.phone.relay.log()
    );
    assert_eq!(w.phone.status()["dial_route"], false);
}

/// `403 plan_required` on the dial: "Not on Connect" in `connect_status`, no purchase
/// hint anywhere, and no storm of dials.
#[test]
fn plan_required_is_not_on_connect_without_a_purchase_hint_or_a_retry_storm() {
    let mut w = world();
    let pin = w.node.certificate.pin.text();
    attach(&w.phone, &link_of(&w.phone, &w.node, &w.connect, &pin));
    w.connect.plans.set(&w.mac.id(), false);
    w.node.tailnet_down();

    let answer: Value = serde_json::from_str(
        &w.phone
            .core
            .call(&json!({"op": "access_requests_list"}).to_string()),
    )
    .unwrap();
    assert_no_purchase_text(&answer.to_string());
    assert_eq!(w.phone.core.dials_for_test(), 1);
    let status = w.phone.status();
    assert_eq!(status["state"], "account");
    assert_eq!(status["plan"]["status"], "none", "Not on Connect: {status}");
    assert_eq!(status["plan"]["entitled"], false);
    assert_eq!(status["dial_state"], "not_on_connect");
    assert_eq!(status["dial_route"], false);
    assert_no_purchase_text(&status.to_string());

    // More requests, and no new dial: the state holds them back.
    for _ in 0..5 {
        let answer = w
            .phone
            .core
            .call(&json!({"op": "access_requests_list"}).to_string());
        assert_no_purchase_text(&answer);
        let answer = w.phone.core.call(&json!({"op": "feed_list"}).to_string());
        assert_no_purchase_text(&answer);
    }
    assert_eq!(w.phone.core.dials_for_test(), 1, "no retry storm");
    assert_eq!(w.phone.status()["dial_state"], "not_on_connect");
    assert_eq!(w.node.dial.count(), 0);
}

/// `503 tunnel_offline` (the Mac has no tunnel open) and `429 tunnel_limit` are two
/// different quiet states; after each the dial comes back with its own wait.
#[test]
fn the_mac_offline_and_the_limit_are_distinct_quiet_states() {
    let mut w = world_with(
        |tunnel| tunnel.dials_per_minute = 6,
        quick(),
        (Duration::from_secs(30), Duration::from_secs(90)),
    );
    let pin = w.node.certificate.pin.text();
    attach(&w.phone, &link_of(&w.phone, &w.node, &w.connect, &pin));
    w.node.tailnet_down();

    w.node.tunnel_down(&w.connect);
    let answer = w
        .phone
        .core
        .call(&json!({"op": "access_requests_list"}).to_string());
    assert_no_purchase_text(&answer);
    let status = w.phone.status();
    assert_eq!(status["dial_state"], "mac_offline", "{status}");
    assert_eq!(status["dial_route"], false);
    assert_eq!(
        status["plan"]["entitled"], true,
        "the plan is not the problem"
    );

    // The Mac comes back: the dial works again after its short wait.
    w.node.tunnel_up(&w.connect);
    wait_until("the dial reaches the Mac again", || {
        call(&w.phone.core, json!({"op": "access_requests_list"}));
        w.phone.status()["dial_state"] == "connected"
    });
    // Dials until the limit of the account.
    let mut saw_limit = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(60));
        let answer = w
            .phone
            .core
            .call(&json!({"op": "access_requests_list"}).to_string());
        assert_no_purchase_text(&answer);
        if w.phone.status()["dial_state"] == "limit" {
            saw_limit = true;
            break;
        }
    }
    assert!(saw_limit, "429 tunnel_limit is its own state");
    let status = w.phone.status();
    assert_ne!(status["dial_state"], "mac_offline");
    assert_no_purchase_text(&status.to_string());
}

/// The long poll survives the idle limit of Connect through the dial because the dial
/// answers Connect's pings and pings itself (contract 3.2: 30 s and 90 s; here 1 s and
/// 3 s, so a 6-second wait is twice the idle limit). Without pings the same wait ends at
/// the idle limit.
#[test]
fn the_long_poll_survives_the_idle_limit_through_the_dial_with_pings() {
    let times = (Duration::from_secs(1), Duration::from_secs(3));
    let timing = DialTiming {
        ping: times.0,
        idle: times.1,
        ..quick()
    };
    let mut w = world_with(
        |tunnel| {
            tunnel.ping_interval = times.0;
            tunnel.idle_timeout = times.1;
        },
        timing,
        times,
    );
    let pin = w.node.certificate.pin.text();
    w.node.tailnet_down();
    attach(&w.phone, &link_of(&w.phone, &w.node, &w.connect, &pin));
    call(&w.phone.core, json!({"op": "questions_list"}));

    let wait_for_question = |w: &World, after: Duration, qid: &str| -> (Value, Duration) {
        let started = Instant::now();
        thread::scope(|scope| {
            let relay = &w.phone.relay;
            scope.spawn(move || {
                thread::sleep(after);
                let card = questions_fixture::CARD.replace(QID, qid);
                post(
                    relay,
                    &QUESTION_KEY,
                    qid,
                    &card,
                    questions_relay::now() + 300,
                );
            });
            let answer: Value = serde_json::from_str(
                &w.phone
                    .core
                    .call(&json!({"op": "questions_wait", "timeout": 12}).to_string()),
            )
            .unwrap();
            (answer, started.elapsed())
        })
    };
    let first = encode_b64u(&[1u8; 16]);
    let (answer, took) = wait_for_question(&w, Duration::from_secs(6), &first);
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(answer["result"]["changed"], true, "{answer}");
    assert!(took >= Duration::from_secs(5), "{took:?}");
    assert_eq!(
        w.node.tailnet.count(),
        0,
        "the long poll went through the dial"
    );

    // Without pings and pongs, Connect ends the dial at its idle limit.
    w.phone.core.set_dial_timing(DialTiming {
        silent: true,
        ..timing
    });
    let second = encode_b64u(&[2u8; 16]);
    let (answer, took) = wait_for_question(&w, Duration::from_secs(7), &second);
    assert!(
        took < Duration::from_secs(6),
        "the silent dial ended before the question came: {answer} after {took:?}"
    );
}

/// `lock` and `suspend` end the dial at once: a long poll through it returns, and no
/// stream stays open at the node.
#[test]
fn lock_and_suspend_close_the_dial() {
    let mut w = world();
    let pin = w.node.certificate.pin.text();
    w.node.tailnet_down();
    attach(&w.phone, &link_of(&w.phone, &w.node, &w.connect, &pin));
    for op in ["lock", "suspend"] {
        let took = thread::scope(|scope| {
            let core = &w.phone.core;
            let waiting = scope.spawn(move || {
                let started = Instant::now();
                let _ = core.call(&json!({"op": "questions_wait", "timeout": 20}).to_string());
                started.elapsed()
            });
            wait_until("the long poll holds a stream at the node", || {
                w.node.open_streams() > 0
            });
            call(core, json!({"op": op}));
            waiting.join().unwrap()
        });
        assert!(
            took < Duration::from_secs(5),
            "{op} ended the long poll: {took:?}"
        );
        wait_until("no stream stays open at the node", || {
            w.node.open_streams() == 0
        });
        assert_eq!(w.phone.status()["dial_route"], false, "after {op}");
        call(&w.phone.core, json!({"op": "unlock", "passphrase": PASS}));
        call(&w.phone.core, json!({"op": "questions_list"}));
        assert_eq!(
            w.phone.status()["dial_route"],
            true,
            "the dial again after {op}"
        );
    }
}

/// A code with a route through another Connect host than this iPhone's, a malformed or
/// non-`wss` route, or any refused vector of the fixture makes no request at all.
#[test]
fn a_route_that_the_grammar_refuses_makes_no_request() {
    let mut w = world();
    w.node.tailnet_down();
    let pin = w.node.certificate.pin.text();
    let good = link_of(&w.phone, &w.node, &w.connect, &pin);
    let route = w.node.route(&w.connect);
    for bad in [
        good.replace(&route, &route.replace("127.0.0.1", "connect.example.com")),
        good.replace(&route, &route.replace("wss://", "ws://")),
        good.replace(&route, &route.replace("wss://", "https://")),
        good.replace(
            &format!("&node={}", w.node.node_id),
            "&node=node_aaaaaaaaaa",
        ),
    ] {
        let code = fails(
            &w.phone.core,
            json!({"op": "join_attach", "link": bad, "answer_key": ANSWER_PUBLIC}),
        );
        assert_eq!(code, "link_invalid", "{bad}");
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/node-pairing-v1/connect-route.json"
    ))
    .unwrap();
    for refused in fixture["refused"].as_array().unwrap() {
        let text = refused["text"].as_str().unwrap();
        let code = fails(
            &w.phone.core,
            json!({"op": "join_attach", "link": text, "answer_key": ANSWER_PUBLIC}),
        );
        // A refused code with a handoff is "damaged" (`invalid_input`), as before.
        assert!(
            matches!(code.as_str(), "link_invalid" | "invalid_input"),
            "{}: {code}",
            refused["name"]
        );
    }
    assert_eq!(w.phone.core.dials_for_test(), 0);
    assert_eq!(w.node.dial.count(), 0);
    assert_eq!(w.node.tailnet.count(), 0);
}

fn api_item(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(format!("SYNTH-{title}")),
            secret: true,
        }],
    }
}

fn titles(phone: &Core) -> Vec<String> {
    let mut titles: Vec<String> = call(phone, json!({"op": "items"}))["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap().to_owned())
        .collect();
    titles.sort();
    titles
}

/// Plan I2 acceptance, relay sync: with the tailnet down, the iPhone joins a vault on the
/// node and pulls it through the dial (relay-sync-v1 unchanged: the signed heads and the
/// snapshot verify on the iPhone), and a later pull through the dial has the same bytes
/// as one through the tailnet. The Mac's code carries the route (the builder of M5).
#[test]
fn a_sync_pull_works_through_the_dial_with_the_same_bytes() {
    let connect = connect(|_| {});
    let mut mac_account = mac(&connect);
    connect.plans.set(&mac_account.id(), true);
    let phone = phone(&connect, quick());
    mac_account.add(&phone);
    let relay = fake_relay::FakeRelay::start();
    let mut node = Node::start_for(
        &connect,
        mac_account.auth(&connect.url),
        &relay.url,
        |origin| relay.set_origin(origin),
        (Duration::from_secs(30), Duration::from_secs(90)),
    );
    let pin = node.certificate.pin;
    // The Mac's own way to its node: a second front with the same certificate.
    let mut options = FrontOptions::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        0,
        copy(&node.certificate),
        relay.url.strip_prefix("http://").unwrap().parse().unwrap(),
    );
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    options.limits = limits();
    let own = Front::start(options).unwrap();
    let own_route = format!("127.0.0.1:{}", own.bound()[0].port());

    let root = TempDir::new().unwrap();
    let mac_dir = root.path().join("mac");
    std::fs::create_dir_all(&mac_dir).unwrap();
    let mac_path = mac_dir.join("vault.db");
    // The Mac makes the team and the code through the node origin (the tailnet is up);
    // later it reaches its node through its own front.
    let config = SyncConfig::in_data_dir(&mac_dir, &mac_path, &node.origin, "vault");
    let mac_first = RelaySync::new(config.clone().with_trust(TlsTrust::Pinned(pin), &[]));
    let mac =
        RelaySync::new(config.with_trust(TlsTrust::Pinned(pin), std::slice::from_ref(&own_route)));
    let mut mac_vault = Vault::create(&mac_path, PASS).unwrap();
    mac_vault.unlock(PASS).unwrap();
    mac_vault.add(api_item("Alpha")).unwrap();
    mac_first
        .create_team(
            &mut mac_vault,
            "Personal",
            &relay.team_code(),
            "Synthetic MacBook",
        )
        .unwrap();

    // The code of the Mac names the node origin with its pin and its Connect route.
    let code = mac_first.create_link(&mac_vault).unwrap();
    mac_first.forget();
    let advertised = RelayUrl::parse_with_trust(&node.origin, TlsTrust::Pinned(pin))
        .unwrap()
        .with_tunnel(Some(TunnelRoute::new(&connect.url, &node.node_id).unwrap()))
        .unwrap();
    let link = code.for_origin(&advertised, Some("Mac mini")).unwrap();
    assert!(
        link.link.contains(&format!(
            "&alt={}&node={}",
            node.route(&connect),
            node.node_id
        )),
        "{}",
        link.link.as_str()
    );

    node.tailnet_down();
    // The Mac's own calls so far went to the node origin; from now on, only the iPhone's.
    let by_the_mac = node.tailnet.count();
    let join = call(
        &phone.core,
        json!({"op": "join_start", "link": link.link.as_str(), "device_name": "Synthetic iPhone"}),
    );
    assert_eq!(join["state"], "waiting", "{join}");
    let links = mac.pending_links(&mac_vault, Some(&code)).unwrap();
    assert_eq!(links.len(), 1);
    mac.confirm_link(&mac_vault, &links[0]).unwrap();
    assert_eq!(
        call(&phone.core, json!({"op": "join_poll"}))["state"],
        "ready"
    );
    let vault = call(
        &phone.core,
        json!({"op": "join_finish", "passphrase": PASS}),
    )["vault"]
        .clone();
    assert_eq!(vault["relay_url"], json!(node.origin));
    let stored: Vec<String> = serde_json::from_value(vault["alt"].clone()).unwrap();
    assert_eq!(
        stored,
        [node.route(&connect)],
        "the route stays with the entry"
    );
    assert_eq!(
        titles(&phone.core),
        ["Alpha"],
        "the download went through the dial"
    );
    assert_eq!(node.tailnet.count(), by_the_mac);
    assert!(node.dial.count() > 0);

    // The Mac adds an item; the iPhone pulls it through the dial.
    mac_vault.add(api_item("Beta")).unwrap();
    mac.sync(&mut mac_vault).unwrap();
    let status = call(&phone.core, json!({"op": "sync"}))["status"].clone();
    assert_eq!(status["state"], "ok", "{status}");
    assert_eq!(titles(&phone.core), ["Alpha", "Beta"]);
    assert_eq!(phone.status()["dial_route"], true);

    // A pull without changes: the same bytes through the dial and through the tailnet.
    let pull = || {
        let status = call(&phone.core, json!({"op": "sync"}))["status"].clone();
        assert_eq!(status["state"], "ok", "{status}");
    };
    pull();
    let through_dial = recorded(&node.dial, pull);
    assert!(!through_dial.is_empty());
    node.tailnet_up();
    wait_until("the pulls come back to the tailnet", || {
        let before = node.tailnet.count();
        pull();
        node.tailnet.count() > before
    });
    let through_tailnet = recorded(&node.tailnet, pull);
    assert_same_but_close(&through_tailnet, &through_dial);
    drop(own);
}

// ---------------------------------------------------------------------------
// One dial for requests that follow each other.

/// The dials of the iPhone and the connections that reached the node through the dial
/// recorder, now.
fn dial_counts(w: &World) -> (u64, usize) {
    (w.phone.core.dials_for_test(), w.node.dial.count())
}

/// Requests that follow each other share one dial: each kept request goes out without
/// `Connection: close` on the dial's connection, and a burst of far more requests than
/// Connect's 60 dials a minute stays on that dial and never reaches `limit`.
#[test]
fn requests_that_follow_each_other_share_one_dial_and_a_burst_stays_under_the_limit() {
    let (w, keeping) = keeping_world();
    let (dials, streams) = dial_counts(&w);
    let before = keeping.requests().len();
    let started = Instant::now();
    for _ in 0..120 {
        call(&w.phone.core, json!({"op": "access_requests_list"}));
    }
    let burst = started.elapsed();
    let requests = keeping.requests()[before..].to_vec();
    assert!(requests.len() >= 120, "{}", requests.len());
    let (dials_after, streams_after) = dial_counts(&w);
    assert!(
        dials_after - dials <= 1,
        "{} dials for {} requests in {burst:?}",
        dials_after - dials,
        requests.len()
    );
    assert!(streams_after - streams <= 1);
    // One connection carried them, each without `Connection: close`.
    let connection = requests[0].0;
    assert!(requests.iter().all(|(number, _, _)| *number == connection));
    assert!(requests.last().unwrap().1 >= 120);
    for (_, _, request) in &requests {
        assert!(!request.contains("Connection: close"), "{request}");
        assert!(
            request.contains("User-Agent: apassy-sync/1\r\n"),
            "{request}"
        );
    }
    let status = w.phone.status();
    assert_eq!(status["dial_state"], "connected", "{status}");
    assert_eq!(status["dial_route"], true);
    assert_eq!(keeping.connections(), streams_after);
}

/// A kept dial that turns out dead: a read (`GET`) that went out on it goes once more on
/// a fresh dial, and the call works; an answer (`POST`) is never sent twice and fails as
/// an unreachable relay does, with no answer stored on the relay.
#[test]
fn a_dead_kept_dial_takes_a_fresh_dial_for_a_read_and_never_for_an_answer() {
    let (w, keeping) = keeping_world();
    let (vault, _card, digest) = publish_card(&w.phone);
    call(&w.phone.core, json!({"op": "access_requests_list"}));
    let (dials, _) = dial_counts(&w);

    *keeping.drop_next.lock().unwrap() = Some("GET ");
    let before = keeping.requests().len();
    let listed = call(&w.phone.core, json!({"op": "access_requests_list"}));
    assert_eq!(listed["requests"].as_array().unwrap().len(), 1, "{listed}");
    assert!(
        keeping.drop_next.lock().unwrap().is_none(),
        "a read met the dead dial"
    );
    assert_eq!(dial_counts(&w).0, dials + 1, "one fresh dial for the read");
    let requests = keeping.requests()[before..].to_vec();
    let dropped = &requests[0];
    assert!(dropped.1 > 1, "the dead dial was a kept one");
    assert!(
        requests[1..]
            .iter()
            .any(|(number, place, request)| *number != dropped.0
                && *place == 1
                && *request == dropped.2),
        "the same read again, first on a new connection: {requests:?}"
    );

    let prepared = call(
        &w.phone.core,
        json!({"op": "access_request_prepare", "vault_id": vault, "qid": QID,
               "digest": digest, "kind": "deny"}),
    );
    let (dials, _) = dial_counts(&w);
    *keeping.drop_next.lock().unwrap() = Some("POST ");
    let before = keeping.requests().len();
    let code = fails(
        &w.phone.core,
        json!({"op": "access_request_answer", "vault_id": vault, "qid": QID,
               "digest": digest, "kind": "deny", "time": prepared["time"]}),
    );
    assert_eq!(code, "relay_unreachable");
    assert!(
        keeping.drop_next.lock().unwrap().is_none(),
        "the answer met the dead dial"
    );
    let posts: Vec<_> = keeping.requests()[before..]
        .iter()
        .filter(|(_, _, request)| request.starts_with("POST "))
        .cloned()
        .collect();
    assert_eq!(posts.len(), 1, "the answer went out once: {posts:?}");
    assert!(
        w.phone.relay.answers().is_empty(),
        "no answer reached the relay"
    );
    assert_eq!(dial_counts(&w).0, dials, "no dial to send the answer again");
}

/// `lock` and `suspend` close the kept dial: no stream stays open at the node, and the
/// next request after the unlock dials again.
#[test]
fn lock_and_suspend_close_the_kept_dial() {
    let (w, _keeping) = keeping_world();
    for op in ["lock", "suspend"] {
        call(&w.phone.core, json!({"op": "access_requests_list"}));
        wait_until("the kept dial holds one stream at the node", || {
            w.node.open_streams() == 1
        });
        let (dials, _) = dial_counts(&w);
        call(&w.phone.core, json!({"op": "access_requests_list"}));
        assert_eq!(dial_counts(&w).0, dials, "the kept dial took the request");
        call(&w.phone.core, json!({"op": op}));
        wait_until("no stream stays open at the node", || {
            w.node.open_streams() == 0
        });
        assert_eq!(w.phone.status()["dial_route"], false, "after {op}");
        call(&w.phone.core, json!({"op": "unlock", "passphrase": PASS}));
        call(&w.phone.core, json!({"op": "access_requests_list"}));
        assert!(dial_counts(&w).0 > dials, "a new dial after {op}");
    }
}

/// The long poll has a dial of its own: it never takes the kept dial, asks the node to
/// close after its answer, and the requests beside it keep using the kept dial.
#[test]
fn the_long_poll_has_its_own_dial_beside_the_kept_one() {
    let (w, keeping) = keeping_world();
    call(&w.phone.core, json!({"op": "questions_list"}));
    wait_until("the kept dial holds one stream at the node", || {
        w.node.open_streams() == 1
    });
    let (dials, _) = dial_counts(&w);
    let before = keeping.requests().len();
    thread::scope(|scope| {
        let core = &w.phone.core;
        let waiting = scope
            .spawn(move || core.call(&json!({"op": "questions_wait", "timeout": 3}).to_string()));
        wait_until("the long poll holds a stream of its own", || {
            w.node.open_streams() == 2
        });
        assert_eq!(dial_counts(&w).0, dials + 1, "the long poll dialed");
        // Beside it, a request takes the kept dial.
        call(core, json!({"op": "access_requests_list"}));
        assert_eq!(dial_counts(&w).0, dials + 1, "no dial beside the long poll");
        assert_eq!(w.node.open_streams(), 2);
        let _ = waiting.join().unwrap();
    });
    // The long poll's dial closed after its answer; the kept one is still there.
    wait_until("the long poll's stream closed", || {
        w.node.open_streams() == 1
    });
    let requests = keeping.requests()[before..].to_vec();
    let polls: Vec<_> = requests
        .iter()
        .filter(|(_, _, request)| request.contains("wait="))
        .collect();
    assert!(!polls.is_empty(), "{requests:?}");
    for (number, place, request) in &polls {
        assert_eq!(
            *place, 1,
            "the long poll is the first request of its own dial"
        );
        assert!(request.contains("Connection: close\r\n"), "{request}");
        assert!(
            requests
                .iter()
                .filter(|(other, _, _)| other == number)
                .count()
                == 1,
            "nothing else on the long poll's dial"
        );
    }
    for (_, _, request) in requests.iter().filter(|(_, _, r)| !r.contains("wait=")) {
        assert!(!request.contains("Connection: close"), "{request}");
    }
}
