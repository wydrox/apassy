//! The Mac's own node (ADR 0037, cloud slice): an embedded relay in the app process
//! that hosted cloud agents reach through Tailscale Funnel
//! (docs/design/implementation-plan-0037-cloud-agents.md).
//!
//! The root crate cannot depend on the relay crate (the relay depends on this one), so
//! the app talks to its node through the object-safe traits of `backend`. The relay
//! crate implements them (`apassy_relay::embedded::EmbeddedRelay`); the app crate passes
//! that implementation in. Tests use a fake backend.
//!
//! [`Node`] is the service of the desktop and of Settings > Cloud agents. It owns the
//! running node, its host thread (`host`), and the Funnel route (`funnel`):
//!
//! - [`Node::start`] (for an unlocked vault with the route on): the key of the node
//!   (`master_key`), the node on the loopback with its public listener on the stable
//!   port of the vault, the personal team of the vault, the catalog mirror
//!   (`catalog`), the Funnel route on 8443, and the host thread. It blocks (Touch ID,
//!   the Tailscale command line): the desktop runs it on a worker thread.
//! - [`Node::stop`]: the node first (every session ends, every run key goes), then the
//!   Funnel route off, then the host thread is joined. The desktop calls it on lock, on
//!   quit, and wherever it ends waiting runs.
//! - The API of the UI: [`Node::status`], [`Node::set_route`], [`Node::add_agent`] (the
//!   token is in the answer once), [`Node::agents`], [`Node::revoke_agent`], and
//!   [`Node::recent_activity`]. Each blocks briefly; the UI calls them off its thread.
//!
//! On the tailnet (ADR 0037 stage 2; plan `docs/design/implementation-plan-s2-s3.md`,
//! unit N4): with the tailnet route of the vault on (`Vault::set_cloud_tailnet_on`, after
//! the owner check), the node also serves the devices of the vault on the tailnet behind
//! the TLS front (`tailnet`), and a vault's questions team can live on the node
//! (`questions_team`):
//!
//! - [`Node::start`] starts the relay with its tailnet listener
//!   (`NodeBackend::start_on_tailnet`), the node certificate, the front on the tailnet
//!   addresses (or the Serve TCP fallback), and the local route of the node origin, so the
//!   Mac's own clients reach the node over the loopback. The node runs while the vault is
//!   unlocked with either route on; the Funnel route only with the public route on.
//! - A stop goes the other way: the front first, then the relay (every session and run
//!   key gone), then the local route, then Funnel. A lock, a quit, and the end of waiting
//!   runs stop it ([`Node::stop`]).
//! - The API of Settings > Devices (unit N7): [`Node::status`] (`NodeStatus::tailnet`),
//!   [`Node::set_tailnet`], [`Node::set_tailnet_port`], [`Node::ensure_questions_team`],
//!   [`Node::pairing_link`], [`Node::revoke_device`], and "Move approvals to this Mac"
//!   ([`Node::move_approvals`], [`Node::finish_move`], [`Node::cancel_move`],
//!   [`Node::move_state`]). The owner checks are the caller's.
//!
//! Lock order: the node (read or write), then the catalog state, then the vault. No code
//! holds the vault while it waits for the node.

pub mod backend;
pub mod catalog;
pub mod funnel;
mod host;
pub mod master_key;
pub mod questions_team;
pub mod tailnet;

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use zeroize::Zeroizing;

use self::backend::{
    AuditRow, NodeAgentId, NodeBackend, NodeConfig, NodeError, NodeSecret, NodeTailnet, NodeTeamId,
};
use self::funnel::{Funnel, FunnelError, SystemTailscale, Tailscale, TailscaleCli};
use self::master_key::{KeySource, KeyStore, KeychainStore, NoKeychain};
use self::tailnet::{TailnetHere, TailnetRoute};
use crate::broker::SharedVault;
use crate::broker::decide::BrokerContext;
use crate::net::tls_front::FrontRoute;
use crate::questions::QuestionsClient;
use crate::sync::LinkCode;
use crate::vault::{
    CLOUD_PORT_MAX, CLOUD_PORT_MIN, CLOUD_TOKEN_DAYS, RelayMembership, TrustedDeviceKind, Vault,
};

pub use host::LiveSession;

/// The name of the personal team of a vault in the node.
const TEAM_NAME: &str = "Personal";
/// The file in the node directory with the last Funnel target of the app, so a stale
/// handler of an earlier port is known as the app's own.
const LAST_TARGET_FILE: &str = "funnel-target";
/// Rows of "Recent cloud activity".
const RECENT_ROWS: u32 = 20;
/// Ports tried for the public listener before the start gives up.
const PORT_TRIES: u16 = 64;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn error(code: &str, message: impl Into<String>) -> NodeError {
    NodeError::new(code, message)
}

fn funnel_error(error: &FunnelError) -> NodeError {
    let code = match error {
        FunnelError::NoTailscale => "no_tailscale",
        FunnelError::NotConnected(_) => "tailscale_not_connected",
        FunnelError::PortTaken { .. } => "funnel_port_taken",
        FunnelError::HttpsPublic => "funnel_https_public",
        FunnelError::Policy { .. } => "funnel_policy",
        FunnelError::Unreadable(_) | FunnelError::Failed(_) => "funnel_failed",
    };
    NodeError::new(code, error.message())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What a node service is made of.
pub struct NodeOptions {
    /// The relay implementation (`apassy_relay::embedded::EmbeddedRelay`).
    pub backend: Arc<dyn NodeBackend>,
    pub keys: Arc<dyn KeyStore>,
    pub cli: Arc<dyn TailscaleCli>,
    /// `<app data>/node`.
    pub data_dir: PathBuf,
}

impl NodeOptions {
    /// The product: the Keychain through the helper in the app bundle (the file when the
    /// helper cannot be found), the Tailscale command line, and `<app data>/node`.
    pub fn platform(backend: Arc<dyn NodeBackend>) -> Self {
        let keys: Arc<dyn KeyStore> = match crate::native::NativeHelper::locate() {
            Ok(helper) => Arc::new(KeychainStore::new(helper)),
            Err(_) => Arc::new(NoKeychain),
        };
        Self {
            backend,
            keys,
            cli: Arc::new(SystemTailscale),
            data_dir: crate::paths::data_dir().join("node"),
        }
    }
}

/// One device of the questions team of the vault on the node, for Settings > Devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDeviceView {
    /// The relay's device id, for [`Node::revoke_device`].
    pub id: u64,
    /// The name of the trusted device of the vault, else the name the device gave.
    pub name: String,
    /// The kind of the trusted device of the vault; `None`: the vault has no row for it.
    pub kind: Option<TrustedDeviceKind>,
    /// `owner`, `manager`, or `member`.
    pub role: String,
    pub key_holder: bool,
    pub created_at: u64,
    pub last_seen_at: Option<u64>,
    /// It gave the node a push handle that has not failed.
    pub push: bool,
    /// The device of this Mac.
    pub this_mac: bool,
}

/// The tailnet route of the node as Settings > Devices shows it (plan unit N7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailnetStatus {
    /// The tailnet route of the open vault is on (off when no vault is open).
    pub on: bool,
    /// The front runs.
    pub running: bool,
    /// The node origin: the running one, else the one Tailscale gives now (when the route
    /// is on).
    pub origin: Option<String>,
    /// The port of the node origin.
    pub port: u16,
    /// The addresses that the front listens on.
    pub bound: Vec<SocketAddr>,
    /// The front binds `127.0.0.1` and Tailscale Serve forwards the port (the fallback
    /// when no interface has the Tailscale address).
    pub serve_fallback: bool,
    /// The pin of the node certificate, b64u.
    pub pin: Option<String>,
    /// The pin as six words for a visual check (`tailnet::pin_words`).
    pub pin_words: Option<String>,
    /// The node's display name of the pairing links.
    pub name: Option<String>,
    /// The push gateway of the node.
    pub push_gateway: String,
    /// The questions team of the vault on this node, once made.
    pub questions_team: Option<String>,
    /// The relay of the questions of the vault when they go elsewhere (the hosted relay):
    /// Settings offers "Move approvals to this Mac".
    pub questions_elsewhere: Option<String>,
    /// The devices of the questions team on the node, oldest first.
    pub devices: Vec<NodeDeviceView>,
}

/// "Move approvals to this Mac" (ADR 0037, Migration) now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveState {
    /// No move runs.
    Idle,
    /// The node team is made: a device pairs with its link (the "Add an iPhone" sheet with
    /// the client of [`Node::move_approvals`]). The questions still go through
    /// `hosted_team` until [`Node::finish_move`].
    Pairing {
        team_id: String,
        hosted_team: String,
    },
}

/// A move that started: the client of this Mac's device in the new node team, for the
/// pairing sheet (links, confirmation, handoff).
#[derive(Debug)]
pub struct MoveStart {
    pub client: QuestionsClient,
    pub team_id: String,
    /// The questions team that the vault leaves.
    pub hosted_team: String,
}

/// A move that ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveDone {
    /// The questions team of the vault on the node now.
    pub team_id: String,
    /// The hosted relay removed the devices of the old notifications-only team (best
    /// effort). False also for a relay sync team, whose devices stay.
    pub hosted_removed: bool,
}

/// The node as Settings > Cloud agents shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub tailscale: Tailscale,
    /// The public route switch of the open vault (off when no vault is open).
    pub route_on: bool,
    pub running: bool,
    /// The MCP URL for agents: `https://<DNSName>:8443/mcp`.
    pub url: Option<String>,
    /// The loopback port of the public listener.
    pub port: Option<u16>,
    /// The node key is a file, because the Keychain is unavailable to this build.
    pub keychain_fallback: bool,
    /// Text for the owner: why the node did not start, items that it does not take, a
    /// lost key, and the limits of the route.
    pub warnings: Vec<String>,
    /// The tailnet route (plan unit N4).
    pub tailnet: TailnetStatus,
}

/// A cloud agent that was just made. The token is here once.
#[derive(Debug)]
pub struct AddedAgent {
    /// The vault agent.
    pub agent_id: u64,
    pub token: NodeSecret,
    pub expires_at: u64,
    /// The MCP URL for the agent.
    pub url: String,
}

/// One cloud agent for the list of Settings > Cloud agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudAgentView {
    pub agent_id: u64,
    pub name: String,
    /// (item id, item name), in id order.
    pub items: Vec<(u64, String)>,
    pub token_expires_at: u64,
    pub last_used_at: Option<u64>,
    /// A released run of the agent has a session that may still be live.
    pub live_session: bool,
}

struct Running {
    /// Each start has its own number, so that a check stops only the node it saw.
    serial: u64,
    shared: Arc<host::Shared>,
    host: Option<JoinHandle<()>>,
    port: u16,
    funnel_on: bool,
    /// The tailnet route, when it is on.
    tailnet: Option<TailnetRoute>,
}

#[derive(Default)]
struct Notes {
    /// Why the last start failed.
    failure: Option<String>,
    /// The code of that failure.
    failure_code: Option<String>,
    keychain_fallback: bool,
    /// The node key was new and the older node moved aside, or the node lost the team
    /// of the vault: the cloud agents must be added again.
    lost_key: bool,
    /// Why the tailnet route runs without something (Funnel failed beside it), or what
    /// changed for the devices (a new origin, a new pin).
    tailnet_notes: Vec<String>,
}

/// A move of the questions of a vault to the node, between its start and its end. The
/// node membership is in memory only: a quit drops it, and the team stays unused on the
/// node.
struct Move {
    epoch: [u8; 32],
    node: RelayMembership,
    hosted_team: String,
}

/// The failure codes after which the desktop tries a start again by itself
/// ([`Node::retry_soon`]): Tailscale was not there yet, or a port was taken.
const RETRY_CODES: [&str; 5] = [
    "no_tailscale",
    "tailscale_not_connected",
    "tailscale_no_address",
    "tailnet_port_taken",
    "tailnet_serve_failed",
];

/// The node service. Every method can be called from any thread.
pub struct Node {
    backend: Arc<dyn NodeBackend>,
    keys: Arc<dyn KeyStore>,
    funnel: Funnel,
    cli: Arc<dyn TailscaleCli>,
    data_dir: PathBuf,
    /// Tests only (debug builds): `127.0.0.1` stands in for the tailnet address.
    test_loopback: bool,
    moving: Mutex<Option<Move>>,
    /// The key, read once in each app process: a node restart (lock and unlock) asks no
    /// second Touch ID. It opens metadata only.
    key: Mutex<Option<(Zeroizing<String>, KeySource)>>,
    /// Held for the whole of a start: one start at a time, and a stop waits for the start
    /// on its way, so nothing (no Funnel route) is left after the stop returns.
    start_lock: Mutex<()>,
    running: Mutex<Option<Running>>,
    /// Stops that wait for a start: the start gives up at its next step.
    stops_waiting: AtomicUsize,
    serial: AtomicU64,
    notes: Mutex<Notes>,
}

/// The state of the open vault that a start needs.
struct VaultState {
    epoch: [u8; 32],
    file: PathBuf,
    team: Option<String>,
    /// The loopback port of the public listener (0 without the public route).
    port: u16,
    route_on: bool,
    tailnet_on: bool,
    tailnet_port: u16,
    last_origin: Option<String>,
    push_gateway: String,
    /// The questions membership of the vault names a node origin (it has a pin).
    node_questions: bool,
}

impl Node {
    pub fn new(options: NodeOptions) -> Self {
        Self {
            backend: options.backend,
            keys: options.keys,
            funnel: Funnel::new(Arc::clone(&options.cli)),
            cli: options.cli,
            data_dir: options.data_dir,
            test_loopback: false,
            moving: Mutex::new(None),
            key: Mutex::new(None),
            start_lock: Mutex::new(()),
            running: Mutex::new(None),
            stops_waiting: AtomicUsize::new(0),
            serial: AtomicU64::new(0),
            notes: Mutex::new(Notes::default()),
        }
    }

    /// Tests only: the tailnet route uses `127.0.0.1` as the tailnet address of this Mac
    /// (no Tailscale), and the front binds and admits the loopback. Release builds ignore
    /// it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_tailnet(mut self) -> Self {
        self.test_loopback = cfg!(debug_assertions);
        self
    }

    /// True while the node runs.
    pub fn is_running(&self) -> bool {
        lock(&self.running).is_some()
    }

    /// True while the node runs with its tailnet route (the front).
    pub fn tailnet_running(&self) -> bool {
        lock(&self.running)
            .as_ref()
            .is_some_and(|running| running.tailnet.is_some())
    }

    /// The node origin of the running tailnet route.
    pub fn node_origin(&self) -> Option<String> {
        lock(&self.running)
            .as_ref()
            .and_then(|running| running.tailnet.as_ref())
            .map(|route| route.origin.clone())
    }

    /// The last start failed for a reason that can pass by itself (Tailscale was not up,
    /// a port was taken): the desktop tries again after a while.
    pub fn retry_soon(&self) -> bool {
        lock(&self.notes)
            .failure_code
            .as_deref()
            .is_some_and(|code| RETRY_CODES.contains(&code))
    }

    /// The vault session that the node serves, while it runs.
    pub fn serves(&self) -> Option<[u8; 32]> {
        lock(&self.running)
            .as_ref()
            .map(|running| running.shared.epoch())
    }

    /// Whether the open vault wants a node to start: unlocked, and the tailnet route on,
    /// or the public route on with an active cloud agent. `Some` is the vault session.
    pub fn wanted(vault: &Vault) -> Option<[u8; 32]> {
        let tailnet = vault
            .cloud_node_setting()
            .is_ok_and(|setting| setting.tailnet_on);
        Self::may_run(vault).filter(|_| tailnet || vault.has_cloud_agents().unwrap_or(false))
    }

    /// Whether a running node may go on for the open vault: unlocked, and the public or
    /// the tailnet route on. Without a cloud agent a node goes on (the first agent is
    /// being made).
    pub fn may_run(vault: &Vault) -> Option<[u8; 32]> {
        if vault.is_locked() {
            return None;
        }
        vault
            .cloud_node_setting()
            .is_ok_and(|setting| setting.route_on || setting.tailnet_on)
            .then(|| vault.epoch())
    }

    /// Serve the new session of the same vault file (a passphrase change or a backup
    /// ends the session without a lock), so its sessions and the route stay. Returns
    /// false when no node runs, or it serves another file: then stop it.
    pub fn adopt(&self, vault: &Vault) -> bool {
        lock(&self.running)
            .as_ref()
            .is_some_and(|running| running.shared.adopt(vault))
    }

    fn master_key(&self) -> Result<(NodeSecret, KeySource, bool), NodeError> {
        let mut cached = lock(&self.key);
        if let Some((key, source)) = cached.as_ref() {
            return Ok((NodeSecret::new(key.to_string()), *source, false));
        }
        let loaded = master_key::open_key(self.keys.as_ref(), &self.data_dir)?;
        *cached = Some((
            Zeroizing::new(loaded.secret.expose().to_owned()),
            loaded.source,
        ));
        Ok((loaded.secret, loaded.source, loaded.retired.is_some()))
    }

    fn vault_state(vault: &SharedVault) -> Result<VaultState, NodeError> {
        let mut guard = lock(vault);
        let vault = guard
            .as_mut()
            .filter(|vault| !vault.is_locked())
            .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
        let storage = |_| error("vault_error", "The vault cannot be read for the node.");
        let setting = vault.cloud_node_setting().map_err(storage)?;
        if !setting.route_on && !setting.tailnet_on {
            return Err(error(
                "route_off",
                "The public route is off in Settings > Cloud agents.",
            ));
        }
        let port = match (setting.route_on, setting.port) {
            (false, _) => 0,
            (true, Some(port)) => port,
            (true, None) => {
                let port = free_port()?;
                vault.set_cloud_node_port(port).map_err(storage)?;
                port
            }
        };
        let node_questions = crate::relay::membership::questions_membership(vault)
            .ok()
            .flatten()
            .is_some_and(|membership| membership.pin.is_some());
        Ok(VaultState {
            epoch: vault.epoch(),
            file: vault.path().to_path_buf(),
            team: setting.team_id,
            port,
            route_on: setting.route_on,
            tailnet_on: setting.tailnet_on,
            tailnet_port: tailnet::port_or_default(setting.tailnet_port),
            last_origin: setting.node_origin,
            push_gateway: setting
                .push_gateway
                .unwrap_or_else(|| tailnet::DEFAULT_PUSH_GATEWAY.to_owned()),
            node_questions,
        })
    }

    /// The tailnet of this Mac now, or the stand-in of the tests.
    fn tailnet_here(&self) -> Result<TailnetHere, NodeError> {
        if self.test_loopback {
            return Ok(TailnetHere::test_loopback());
        }
        tailnet::find(self.cli.as_ref())
    }

    fn last_target(&self) -> Option<u16> {
        std::fs::read_to_string(self.data_dir.join(LAST_TARGET_FILE))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn note_target(&self, port: u16) {
        let _ = std::fs::write(self.data_dir.join(LAST_TARGET_FILE), port.to_string());
    }

    /// A stop waits: the start gives up.
    fn check_not_stopping(&self) -> Result<(), NodeError> {
        if self.stops_waiting.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(error(
                "node_stopped",
                "The node was stopped while it started.",
            ))
        }
    }

    /// Forget the cloud agents of the vault: its node or its team is new.
    fn forget_agents(vault: &SharedVault, epoch: [u8; 32]) {
        let mut guard = lock(vault);
        if let Some(vault) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
        {
            let _ = vault.reset_cloud_node();
            // The owner had the route on: it stays on.
            let _ = vault.set_cloud_route_on(true);
        }
    }

    /// Start the node for the open vault, unless it runs. See the module text. One start
    /// runs at a time. On an error nothing runs, and [`Node::status`] says why.
    pub fn start(&self, vault: &SharedVault, broker: BrokerContext) -> Result<(), NodeError> {
        let _one = lock(&self.start_lock);
        let result = self.start_inner(vault, broker);
        {
            let mut notes = lock(&self.notes);
            notes.failure = result.as_ref().err().map(|error| error.message.clone());
            notes.failure_code = result.as_ref().err().map(|error| error.code.clone());
        }
        result
    }

    fn start_inner(&self, vault: &SharedVault, broker: BrokerContext) -> Result<(), NodeError> {
        if self.is_running() {
            return Ok(());
        }
        self.check_not_stopping()?;
        let state = Self::vault_state(vault)?;
        lock(&self.notes).tailnet_notes.clear();
        // The Funnel route needs the MagicDNS name; the tailnet route its address.
        let dns_name = if state.route_on {
            let found = match self.funnel.status() {
                Tailscale::Missing => Err(funnel_error(&FunnelError::NoTailscale)),
                Tailscale::NotConnected { state } => {
                    Err(funnel_error(&FunnelError::NotConnected(state)))
                }
                Tailscale::Connected { dns_name } => Ok(dns_name),
            };
            found.map(Some)
        } else {
            Ok(None)
        };
        let dns_name = match dns_name {
            Ok(name) => name,
            // With the tailnet route on, the node starts without Funnel.
            Err(failure) if state.tailnet_on => {
                lock(&self.notes).tailnet_notes.push(format!(
                    "The public route for cloud agents is off: {}",
                    failure.message
                ));
                None
            }
            Err(failure) => return Err(failure),
        };
        let here = if state.tailnet_on {
            Some(self.tailnet_here()?)
        } else {
            None
        };
        self.check_not_stopping()?;
        let (key, source, retired) = self.master_key()?;
        {
            let mut notes = lock(&self.notes);
            notes.keychain_fallback = source == KeySource::File;
            notes.lost_key |= retired;
        }
        let mut team_id = state.team.clone();
        if retired {
            // A new empty node: the cloud agents of the vault are gone with the old one.
            Self::forget_agents(vault, state.epoch);
            team_id = None;
        }
        self.check_not_stopping()?;
        let origin = here.as_ref().map(|here| here.origin(state.tailnet_port));
        let public_url = match (&dns_name, &origin) {
            (Some(name), _) => funnel::public_origin(name),
            // No public route: the node origin is the only origin.
            (None, Some(origin)) => origin.clone(),
            (None, None) => {
                return Err(error(
                    "route_off",
                    "The public route is off in Settings > Cloud agents.",
                ));
            }
        };
        let funnel_wanted = dns_name.is_some();
        let tailnet_config = origin.as_ref().map(|origin| NodeTailnet {
            node_origin: origin.clone(),
            tailnet_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tailnet_agents: false,
            push_gateway: Some(state.push_gateway.clone()),
        });
        // The certificate key is sealed under the node key, which moves into the config.
        let certificate_key = Zeroizing::new(key.expose().as_bytes().to_vec());
        let node = self.backend.start_on_tailnet(
            NodeConfig {
                data_dir: self.data_dir.clone(),
                master_key: key,
                public_url: public_url.clone(),
                public_listen: funnel_wanted
                    .then(|| SocketAddr::from((Ipv4Addr::LOCALHOST, state.port))),
            },
            tailnet_config,
        )?;
        let tailnet_target = node.tailnet_addr();
        let team = match team_id.map(NodeTeamId) {
            Some(team) if node.has_team(&team) => team,
            stored => {
                if stored.is_some() {
                    // The node does not know the team of the vault (its directory is new):
                    // the node ids of the vault's agents name nothing any more.
                    Self::forget_agents(vault, state.epoch);
                    lock(&self.notes).lost_key = true;
                }
                match node.create_team(TEAM_NAME) {
                    Ok(team) => {
                        let mut guard = lock(vault);
                        let saved = guard
                            .as_mut()
                            .filter(|vault| !vault.is_locked() && vault.epoch() == state.epoch)
                            .map(|vault| vault.set_cloud_node_team(Some(&team.0)));
                        if !matches!(saved, Some(Ok(()))) {
                            drop(guard);
                            node.stop();
                            return Err(error(
                                "vault_locked",
                                "The vault was locked while the node started.",
                            ));
                        }
                        team
                    }
                    Err(failure) => {
                        node.stop();
                        return Err(failure);
                    }
                }
            }
        };
        let shared = Arc::new(host::Shared::new(
            node,
            team,
            Arc::clone(vault),
            state.file.clone(),
            broker,
            state.epoch,
            public_url,
        ));
        if let Err(failure) = self
            .check_not_stopping()
            .and_then(|()| shared.refresh(&[]).map(drop))
        {
            Self::teardown(&shared, None);
            return Err(failure);
        }
        // The front, after the relay: it forwards to the relay's tailnet listener.
        let mut route = match &here {
            None => None,
            Some(here) => match self.start_route(here, &state, tailnet_target, &certificate_key) {
                Ok(route) => Some(route),
                Err(failure) => {
                    Self::teardown(&shared, None);
                    return Err(failure);
                }
            },
        };
        drop(certificate_key);
        if let Some(route) = &route {
            self.note_origin(vault, &state, route);
        }
        let mut funnel_on = false;
        if funnel_wanted {
            match self.funnel.enable(state.port, self.last_target()) {
                Ok(_) => {
                    funnel_on = true;
                    self.note_target(state.port);
                }
                Err(failure) if route.is_some() => {
                    lock(&self.notes).tailnet_notes.push(format!(
                        "The public route for cloud agents is off: {}",
                        failure.message()
                    ));
                }
                Err(failure) => {
                    Self::teardown(&shared, None);
                    return Err(funnel_error(&failure));
                }
            }
        }
        let host = match host::spawn(Arc::clone(&shared)) {
            Ok(host) => host,
            Err(_) => {
                Self::stop_parts(&shared, None, route.take());
                if funnel_on {
                    let _ = self.funnel.disable(state.port);
                }
                return Err(error(
                    "node_failed",
                    "The host thread of the node did not start.",
                ));
            }
        };
        let current = {
            let guard = lock(vault);
            guard
                .as_ref()
                .is_some_and(|vault| !vault.is_locked() && vault.epoch() == state.epoch)
        };
        if let Err(failure) = self.check_not_stopping().and_then(|()| {
            if current {
                Ok(())
            } else {
                Err(error(
                    "node_stopped",
                    "The vault was locked while the node started.",
                ))
            }
        }) {
            Self::stop_parts(&shared, Some(host), route.take());
            if funnel_on {
                let _ = self.funnel.disable(state.port);
            }
            return Err(failure);
        }
        *lock(&self.running) = Some(Running {
            serial: self.serial.fetch_add(1, Ordering::SeqCst) + 1,
            shared,
            host: Some(host),
            port: state.port,
            funnel_on,
            tailnet: route,
        });
        Ok(())
    }

    /// The tailnet route of a start: the certificate, then the front on the relay's
    /// tailnet listener, then the local route of the origin.
    fn start_route(
        &self,
        here: &TailnetHere,
        state: &VaultState,
        target: Option<SocketAddr>,
        certificate_key: &[u8],
    ) -> Result<TailnetRoute, NodeError> {
        let target = target.ok_or_else(|| {
            error(
                "node_failed",
                "The relay of the node has no tailnet listener.",
            )
        })?;
        let name = crate::sync::device_name();
        let (certificate, new) = tailnet::certificate(&self.data_dir, certificate_key, &name)?;
        if new && state.node_questions {
            lock(&self.notes).tailnet_notes.push(
                "The node certificate of this Mac is new, so its pin changed. Pair your iPhone again.".to_owned(),
            );
        }
        self.check_not_stopping()?;
        TailnetRoute::start(tailnet::RouteOptions {
            here,
            port: state.tailnet_port,
            certificate,
            target,
            cli: Arc::clone(&self.cli),
            name,
        })
    }

    /// Keep the node origin in the vault; a changed one means a new pairing.
    fn note_origin(&self, vault: &SharedVault, state: &VaultState, route: &TailnetRoute) {
        if state.last_origin.as_deref() == Some(route.origin.as_str()) {
            return;
        }
        if let Some(last) = &state.last_origin
            && state.node_questions
        {
            lock(&self.notes).tailnet_notes.push(format!(
                "The address of this Mac on the tailnet changed from {last} to {}. Pair your iPhone again.",
                route.origin
            ));
        }
        let mut guard = lock(vault);
        if let Some(vault) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == state.epoch)
        {
            let _ = vault.set_cloud_node_origin(Some(&route.origin));
        }
    }

    /// Stop the node and join the host thread.
    fn teardown(shared: &host::Shared, host: Option<JoinHandle<()>>) {
        if let Some(node) = shared.take_node() {
            node.stop();
        }
        if let Some(host) = host {
            let _ = host.join();
        }
    }

    /// Stop the parts in the order of a stop: the front, the relay and the host thread,
    /// then the local route.
    fn stop_parts(
        shared: &host::Shared,
        host: Option<JoinHandle<()>>,
        route: Option<TailnetRoute>,
    ) {
        let mut route = route;
        if let Some(route) = route.as_mut() {
            route.stop_front();
        }
        Self::teardown(shared, host);
        if let Some(route) = route {
            route.finish();
        }
    }

    /// Stop the node: every session ends and every run key goes, the Funnel route goes
    /// off, and the host thread ends. A start on its way gives up, and this call waits
    /// for it. Nothing runs, and no route of the node is on, after it returns.
    pub fn stop(&self) {
        self.stop_running(None);
    }

    /// Stop the running node; with `only`, only when it is the start of that number.
    fn stop_running(&self, only: Option<u64>) {
        self.stops_waiting.fetch_add(1, Ordering::SeqCst);
        let one = lock(&self.start_lock);
        self.stops_waiting.fetch_sub(1, Ordering::SeqCst);
        let running = {
            let mut running = lock(&self.running);
            if only.is_some_and(|serial| running.as_ref().map(|r| r.serial) != Some(serial)) {
                return;
            }
            running.take()
        };
        let Some(mut running) = running else {
            return;
        };
        // The summary rows, while the vault is still open (at a quit; a lock wrote its
        // own rows already).
        host::end_all_sessions(&running.shared, "the node stopped");
        // The front first, then the node: the sessions end at once, before the slower
        // command line. Then the local route of the origin.
        Self::stop_parts(&running.shared, running.host.take(), running.tailnet.take());
        if running.funnel_on {
            let _ = self.funnel.disable(running.port);
        }
        drop(one);
    }

    /// Check the routes of a running node: when the tailnet name changed or the Funnel
    /// handler is gone, or the Tailscale address of the node origin changed, stop it (the
    /// desktop starts it again with the new origin; the sessions end). A tailnet that is
    /// down keeps the node: the front follows the addresses. Only the node that it checked
    /// is stopped. Returns true when it stopped the node.
    pub fn maintain(&self) -> bool {
        let Some((serial, port, public_url, funnel_on, tailnet)) =
            lock(&self.running).as_ref().map(|running| {
                (
                    running.serial,
                    running.port,
                    running.shared.public_url.clone(),
                    running.funnel_on,
                    running
                        .tailnet
                        .as_ref()
                        .map(|route| (route.origin.clone(), route.port)),
                )
            })
        else {
            return false;
        };
        let mut stop = false;
        if funnel_on {
            let name_changed = match self.funnel.status() {
                Tailscale::Connected { dns_name } => funnel::public_origin(&dns_name) != public_url,
                _ => true,
            };
            let route_gone = self
                .funnel
                .serve_state(port)
                .is_ok_and(|state| state.funnel_port != funnel::PortUse::Ours);
            stop |= name_changed || route_gone;
        }
        if let Some((origin, tailnet_port)) = tailnet
            && !self.test_loopback
            && let Ok(here) = tailnet::find(self.cli.as_ref())
        {
            stop |= here.origin(tailnet_port) != origin;
        }
        if stop {
            self.stop_running(Some(serial));
            return !self.is_running();
        }
        false
    }

    fn shared(&self) -> Option<Arc<host::Shared>> {
        lock(&self.running)
            .as_ref()
            .map(|running| Arc::clone(&running.shared))
    }

    /// The MCP URL of the running node, while its Funnel route is on.
    fn mcp_url(&self) -> Option<String> {
        lock(&self.running)
            .as_ref()
            .filter(|running| running.funnel_on)
            .map(|running| format!("{}/mcp", running.shared.public_url))
    }

    /// True while the Funnel route of the running node is on.
    fn funnel_running(&self) -> bool {
        lock(&self.running)
            .as_ref()
            .is_some_and(|running| running.funnel_on)
    }

    /// The node for Settings > Cloud agents. It runs the Tailscale command line.
    pub fn status(&self, vault: &SharedVault) -> NodeStatus {
        let tailscale = self.funnel.status();
        let (route_on, port) = {
            let guard = lock(vault);
            guard
                .as_ref()
                .filter(|vault| !vault.is_locked())
                .and_then(|vault| vault.cloud_node_setting().ok())
                .map_or((false, None), |setting| (setting.route_on, setting.port))
        };
        let running = self.is_running();
        let url = self.mcp_url().or_else(|| match &tailscale {
            Tailscale::Connected { dns_name } => {
                Some(format!("{}/mcp", funnel::public_origin(dns_name)))
            }
            _ => None,
        });
        let mut warnings = Vec::new();
        let notes = lock(&self.notes);
        if let Some(failure) = &notes.failure {
            warnings.push(failure.clone());
        }
        if notes.lost_key {
            warnings.push("The node lost its key or the team of this vault, so Apassy started it empty. Add your cloud agents again.".to_owned());
        }
        if notes.keychain_fallback {
            warnings.push("The node key is a file in the Apassy folder, because this build cannot use the Keychain.".to_owned());
        }
        drop(notes);
        if let Some(shared) = self.shared() {
            for (item, why) in &lock(&shared.catalog).skipped {
                warnings.push(format!(
                    "Item {item} is not offered to cloud agents: {why}."
                ));
            }
        }
        if route_on {
            warnings.push("The name of this Mac is in public certificate logs while the route is on. The Mac must stay awake and the vault unlocked for each run.".to_owned());
        }
        warnings.extend(lock(&self.notes).tailnet_notes.iter().cloned());
        NodeStatus {
            tailscale,
            route_on,
            running,
            url,
            port,
            keychain_fallback: lock(&self.notes).keychain_fallback,
            warnings,
            tailnet: self.tailnet_status(vault),
        }
    }

    /// The tailnet route for Settings > Devices. With the route on and the node stopped,
    /// it asks Tailscale for the origin that a start would have.
    pub fn tailnet_status(&self, vault: &SharedVault) -> TailnetStatus {
        let setting = {
            let guard = lock(vault);
            guard
                .as_ref()
                .filter(|vault| !vault.is_locked())
                .and_then(|vault| vault.cloud_node_setting().ok())
        };
        let Some(setting) = setting else {
            return TailnetStatus {
                port: tailnet::port_or_default(None),
                push_gateway: tailnet::DEFAULT_PUSH_GATEWAY.to_owned(),
                ..TailnetStatus::default()
            };
        };
        let port = tailnet::port_or_default(setting.tailnet_port);
        let mut status = TailnetStatus {
            on: setting.tailnet_on,
            port,
            push_gateway: setting
                .push_gateway
                .clone()
                .unwrap_or_else(|| tailnet::DEFAULT_PUSH_GATEWAY.to_owned()),
            ..TailnetStatus::default()
        };
        let running = lock(&self.running).as_ref().and_then(|running| {
            running.tailnet.as_ref().map(|route| {
                (
                    route.origin.clone(),
                    route.bound(),
                    route.route,
                    route.pin,
                    route.name.clone(),
                )
            })
        });
        match running {
            Some((origin, bound, route, pin, name)) => {
                status.running = true;
                status.origin = Some(origin);
                status.bound = bound;
                status.serve_fallback = route == FrontRoute::ServeTcp;
                status.pin = Some(pin.text());
                status.pin_words = Some(tailnet::pin_words(&pin));
                status.name = Some(name);
            }
            None if setting.tailnet_on => {
                status.origin = self.tailnet_here().ok().map(|here| here.origin(port));
            }
            None => {}
        }
        // The questions team of the vault, on this node or elsewhere.
        let membership = {
            let guard = lock(vault);
            guard
                .as_ref()
                .filter(|vault| !vault.is_locked())
                .and_then(|vault| crate::relay::membership::questions_membership(vault).ok())
                .flatten()
        };
        let Some(membership) = membership else {
            return status;
        };
        let here = status
            .origin
            .as_deref()
            .is_some_and(|origin| questions_team::on_node(&membership, origin));
        if !here {
            status.questions_elsewhere = Some(membership.relay_url.clone());
            return status;
        }
        status.questions_team = Some(membership.team_id.clone());
        if !status.running {
            return status;
        }
        let team = NodeTeamId(membership.team_id.clone());
        let devices = self
            .shared()
            .and_then(|shared| shared.with_node(|node| node.devices(&team)))
            .and_then(Result::ok)
            .unwrap_or_default();
        let guard = lock(vault);
        let open = guard.as_ref().filter(|vault| !vault.is_locked());
        status.devices = devices
            .into_iter()
            .map(|device| {
                let trusted = open.and_then(|vault| {
                    vault
                        .trusted_device_by_relay_id(&membership.team_id, device.id)
                        .ok()
                        .flatten()
                });
                NodeDeviceView {
                    id: device.id,
                    name: trusted
                        .as_ref()
                        .map_or_else(|| device.name.clone(), |trusted| trusted.name.clone()),
                    kind: trusted.as_ref().map(|trusted| trusted.kind),
                    role: device.role,
                    key_holder: device.key_holder,
                    created_at: device.created_at,
                    last_seen_at: device.last_seen_at,
                    push: device.push,
                    this_mac: device.id == membership.device_id,
                }
            })
            .collect();
        status
    }

    /// Turn the tailnet route on or off. The caller passed the owner check for on
    /// (`OwnerRequest::SetTailnetRoute`, unit N7); off takes reach away and needs none. A
    /// running node starts again with the new route: the desktop starts it at its next
    /// comparison ([`crate::desktop`] calls `node_changed`).
    pub fn set_tailnet(&self, vault: &SharedVault, on: bool) -> Result<(), NodeError> {
        {
            let mut guard = lock(vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            vault
                .set_cloud_tailnet_on(on)
                .map_err(|_| error("vault_error", "The route setting cannot be saved."))?;
        }
        if self.is_running() && self.tailnet_running() != on {
            self.stop();
        }
        Ok(())
    }

    /// Set the port of the node origin (`None`: 8444). A new port changes the origin:
    /// every paired device pairs again, so Settings offers it only before the first
    /// pairing. A running route starts again on the new port.
    pub fn set_tailnet_port(
        &self,
        vault: &SharedVault,
        port: Option<u16>,
    ) -> Result<(), NodeError> {
        {
            let mut guard = lock(vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            vault.set_cloud_tailnet_port(port).map_err(|_| {
                error(
                    "invalid_request",
                    "Choose a port from 1024 to 65535, not 8443 or 10000.",
                )
            })?;
        }
        let running_port = lock(&self.running)
            .as_ref()
            .and_then(|running| running.tailnet.as_ref().map(|route| route.port));
        if running_port.is_some_and(|running| running != tailnet::port_or_default(port)) {
            self.stop();
        }
        Ok(())
    }

    /// The running tailnet route: its origin, pin, alternatives, and name, and the vault
    /// session that the node serves. `tailnet_off` when it does not run.
    fn route_info(&self) -> Result<(String, String, [u8; 32]), NodeError> {
        let running = lock(&self.running);
        let running = running.as_ref().ok_or_else(|| {
            error(
                "tailnet_off",
                "The node of this Mac is not on the tailnet. Turn on “Reachable on your tailnet”.",
            )
        })?;
        let route = running.tailnet.as_ref().ok_or_else(|| {
            error(
                "tailnet_off",
                "The node of this Mac is not on the tailnet. Turn on “Reachable on your tailnet”.",
            )
        })?;
        Ok((
            route.origin.clone(),
            route.name.clone(),
            running.shared.epoch(),
        ))
    }

    /// The questions team of the open vault on this node (plan D6): the membership of an
    /// earlier call, or a new team of devices with this Mac, named `device_name`, as its
    /// first device; the vault keeps it (`adopt_node_team`) and the questions worker uses
    /// it. The caller passed the owner check for `OwnerAction::EnableRelayQuestions` with
    /// the node origin. `conflict`: the questions of the vault go through another relay
    /// (use [`Node::move_approvals`]) or through a team of another Mac.
    pub fn ensure_questions_team(
        &self,
        vault: &SharedVault,
        device_name: &str,
    ) -> Result<RelayMembership, NodeError> {
        let (origin, _, epoch) = self.route_info()?;
        let found = {
            let guard = lock(vault);
            let open = guard
                .as_ref()
                .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            let any = crate::relay::membership::questions_membership(open)
                .map_err(|_| error("vault_error", "The relay memberships cannot be read."))?;
            let other_team = crate::relay::membership::existing_questions_team(open)
                .ok()
                .flatten();
            (any, other_team)
        };
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "The node is not running."))?;
        match found {
            (Some(membership), _) if questions_team::on_node(&membership, &origin) => {
                let team = NodeTeamId(membership.team_id.clone());
                if shared.with_node(|node| node.has_team(&team)) == Some(true) {
                    return Ok(membership);
                }
                // The node lost the team (its directory is new): the membership names
                // nothing. It goes, and a new team takes its place.
                let mut guard = lock(vault);
                if let Some(open) = guard
                    .as_mut()
                    .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
                {
                    let _ = crate::relay::membership::disable_questions(open);
                }
            }
            (Some(_), _) => {
                return Err(error(
                    "conflict",
                    "The approvals of this vault go through another relay. Move them to this Mac first.",
                ));
            }
            (None, Some(_)) => {
                return Err(error(
                    "conflict",
                    "This vault has its approvals on another Mac. Join them from that Mac with “Add an iPhone or a Mac…”.",
                ));
            }
            (None, None) => {}
        }
        let route_err = || error("node_stopped", "The node is not running.");
        let membership = {
            let running = lock(&self.running);
            let route = running
                .as_ref()
                .and_then(|running| running.tailnet.as_ref())
                .ok_or_else(route_err)?;
            shared
                .with_node(|node| questions_team::new_node_team(node, route, device_name))
                .ok_or_else(route_err)??
        };
        let mut guard = lock(vault);
        let open = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
            .ok_or_else(|| error("vault_locked", "The vault was locked."))?;
        crate::relay::membership::adopt_node_team(open, &membership, device_name)
            .map_err(questions_team::sync_error)?;
        Ok(membership)
    }

    /// A pairing link of the questions team of the open vault on this node, for an iPhone
    /// or another Mac: the node origin, the pin, the alternatives, and the node name
    /// (node-pairing-v1 section 6), with the client that lists and confirms the devices
    /// that use it. The sheet appends the ADR 0032 handoff (`PairingChannel::link`). It
    /// makes a relay call through the local route: call it off the UI thread.
    pub fn pairing_link(
        &self,
        vault: &SharedVault,
    ) -> Result<(QuestionsClient, LinkCode), NodeError> {
        let (origin, name, epoch) = self.route_info()?;
        let membership = {
            let guard = lock(vault);
            let open = guard
                .as_ref()
                .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            questions_team::node_questions_membership(open, &origin)?
        }
        .ok_or_else(|| {
            error(
                "not_found",
                "This vault has no approvals on this Mac yet. Turn them on first.",
            )
        })?;
        let client =
            QuestionsClient::from_membership(&membership).map_err(questions_team::sync_error)?;
        let link = questions_team::device_link(&client, &membership, Some(&name))
            .map_err(questions_team::sync_error)?;
        Ok((client, link))
    }

    /// Revoke a device of the questions team of the open vault on this node: its tokens
    /// stop at once and its push handle goes (`RunningNode::revoke_device`), and its trusted
    /// device row goes with a new question key, so it cannot read the next questions. The
    /// caller passed the owner check (`OwnerRequest::RevokeNodeDevice`, unit N7). This Mac
    /// itself is refused (`conflict`).
    pub fn revoke_device(&self, vault: &SharedVault, device_id: u64) -> Result<(), NodeError> {
        let (origin, _, epoch) = self.route_info()?;
        let membership = {
            let guard = lock(vault);
            let open = guard
                .as_ref()
                .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            questions_team::node_questions_membership(open, &origin)?
        }
        .ok_or_else(|| error("not_found", "This vault has no approvals on this Mac."))?;
        if device_id == membership.device_id {
            return Err(error(
                "conflict",
                "This Mac holds the approvals of the vault. Turn them off instead.",
            ));
        }
        let team = NodeTeamId(membership.team_id.clone());
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "The node is not running."))?;
        shared
            .with_node(|node| node.revoke_device(&team, device_id))
            .ok_or_else(|| error("node_stopped", "The node is not running."))??;
        let mut guard = lock(vault);
        if let Some(open) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
            && let Ok(Some(device)) = open.trusted_device_by_relay_id(&team.0, device_id)
        {
            open.remove_trusted_device_and_rotate(&device.uuid)
                .map_err(|_| error("vault_error", "The device row cannot be removed."))?;
        }
        Ok(())
    }

    /// "Move approvals to this Mac", step 1 (ADR 0037, Migration; plan D6): a new team of
    /// devices on this node for the questions of the open vault, while they still go
    /// through the hosted relay. Returns the client of this Mac's device in it: the sheet
    /// shows its pairing link ([`questions_team::device_link`]) and confirms the iPhone
    /// with it (a new device key and a new confirmation are unavoidable: identity is per
    /// team, ADR 0019 §4). Then [`Node::finish_move`]. A move that runs is replaced. The
    /// caller passed the owner check for `OwnerAction::EnableRelayQuestions` with the node
    /// origin. `not_found`: the questions of the vault do not go through another relay.
    pub fn move_approvals(
        &self,
        vault: &SharedVault,
        device_name: &str,
    ) -> Result<MoveStart, NodeError> {
        let (origin, _, epoch) = self.route_info()?;
        let hosted = {
            let guard = lock(vault);
            let open = guard
                .as_ref()
                .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            crate::relay::membership::questions_membership(open)
                .map_err(|_| error("vault_error", "The relay memberships cannot be read."))?
        };
        let hosted = hosted
            .filter(|membership| !questions_team::on_node(membership, &origin))
            .ok_or_else(|| {
                error(
                    "not_found",
                    "The approvals of this vault do not go through another relay.",
                )
            })?;
        let route_err = || error("node_stopped", "The node is not running.");
        let shared = self.shared().ok_or_else(route_err)?;
        let node = {
            let running = lock(&self.running);
            let route = running
                .as_ref()
                .and_then(|running| running.tailnet.as_ref())
                .ok_or_else(route_err)?;
            shared
                .with_node(|node| questions_team::new_node_team(node, route, device_name))
                .ok_or_else(route_err)??
        };
        let client = QuestionsClient::from_membership(&node).map_err(questions_team::sync_error)?;
        let start = MoveStart {
            client,
            team_id: node.team_id.clone(),
            hosted_team: hosted.team_id.clone(),
        };
        *lock(&self.moving) = Some(Move {
            epoch,
            node,
            hosted_team: hosted.team_id,
        });
        Ok(start)
    }

    /// The move now.
    pub fn move_state(&self) -> MoveState {
        lock(&self.moving)
            .as_ref()
            .map_or(MoveState::Idle, |moving| MoveState::Pairing {
                team_id: moving.node.team_id.clone(),
                hosted_team: moving.hosted_team.clone(),
            })
    }

    /// Give up a move: its key goes from memory. The team stays unused on the node.
    pub fn cancel_move(&self) {
        lock(&self.moving).take();
    }

    /// "Move approvals to this Mac", step 2, after a device of the vault joined the node
    /// team (its confirmation wrote its trusted device row): the questions of the vault go
    /// through the node team now (`move_questions_to_node`), and the devices of the old
    /// notifications-only team leave the hosted relay (`DELETE /v1/devices/{id}`, best
    /// effort: first the other devices, then this Mac's own). A relay sync team keeps its
    /// devices. The feed and the access requests follow the questions team. It makes relay
    /// calls: call it off the UI thread.
    pub fn finish_move(
        &self,
        vault: &SharedVault,
        device_name: &str,
    ) -> Result<MoveDone, NodeError> {
        let moving = lock(&self.moving)
            .take()
            .ok_or_else(|| error("not_found", "No move of the approvals runs."))?;
        let hosted = {
            let mut guard = lock(vault);
            let open = guard
                .as_mut()
                .filter(|vault| !vault.is_locked() && vault.epoch() == moving.epoch)
                .ok_or_else(|| {
                    error(
                        "vault_locked",
                        "The vault was locked. Start the move again.",
                    )
                })?;
            crate::relay::membership::move_questions_to_node(
                open,
                &moving.node,
                &moving.hosted_team,
                device_name,
            )
            .map_err(questions_team::sync_error)?
        };
        let team_id = moving.node.team_id.clone();
        let mut hosted_removed = false;
        if crate::relay::membership::questions_only(&hosted)
            && let Ok(client) = QuestionsClient::from_membership(&hosted)
        {
            let own = hosted.device_id;
            let others: Vec<u64> = client
                .devices()
                .map(|devices| {
                    devices
                        .into_iter()
                        .filter(|device| device.id != own && !device.current)
                        .map(|device| device.id)
                        .collect()
                })
                .unwrap_or_default();
            let mut all = true;
            for device in others {
                all &= client.remove_device(device).is_ok();
            }
            // The last device of the last owner may be refused: its key is gone anyway.
            let _ = client.remove_device(own);
            client.close();
            hosted_removed = all;
        }
        Ok(MoveDone {
            team_id,
            hosted_removed,
        })
    }

    /// Turn the public route on or off. Off stops the node at once; on lets the desktop
    /// start it (when the vault has a cloud agent).
    pub fn set_route(&self, vault: &SharedVault, on: bool) -> Result<(), NodeError> {
        {
            let mut guard = lock(vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            vault
                .set_cloud_route_on(on)
                .map_err(|_| error("vault_error", "The route setting cannot be saved."))?;
        }
        // Off stops the node (a tailnet route starts again without Funnel); on stops a
        // node that runs for the tailnet only, so that it starts again with Funnel.
        if !on || (self.is_running() && !self.funnel_running()) {
            self.stop();
        }
        Ok(())
    }

    /// Make a cloud agent that may use `items` (vault ids), with a token of `days` days
    /// (30, 90, or 365). Starts the node when it does not run (the route must be on).
    /// The token is in the answer once.
    pub fn add_agent(
        &self,
        vault: &SharedVault,
        broker: BrokerContext,
        name: &str,
        items: &[u64],
        days: u32,
    ) -> Result<AddedAgent, NodeError> {
        if !CLOUD_TOKEN_DAYS.contains(&days) {
            return Err(error(
                "invalid_request",
                "The token lifetime is 30, 90, or 365 days.",
            ));
        }
        if items.is_empty() {
            return Err(error("invalid_request", "Pick at least one credential."));
        }
        let route_on = {
            let guard = lock(vault);
            guard
                .as_ref()
                .filter(|vault| !vault.is_locked())
                .map(|vault| {
                    vault
                        .cloud_node_setting()
                        .is_ok_and(|setting| setting.route_on)
                })
        };
        if route_on.is_none() {
            return Err(error("vault_locked", "The vault is locked."));
        }
        if route_on == Some(false) {
            return Err(error(
                "route_off",
                "The public route is off in Settings > Cloud agents.",
            ));
        }
        if self.is_running() && !self.funnel_running() {
            // A node of the tailnet route only: start it again with Funnel.
            self.stop();
        }
        if !self.is_running() {
            self.start(vault, broker)?;
        }
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "The node is not running."))?;
        let (agent_id, created) = shared.add_agent(name, items, days)?;
        let token = created
            .token
            .ok_or_else(|| error("relay_error", "The node made no token for the agent."))?;
        Ok(AddedAgent {
            agent_id,
            token,
            expires_at: created.expires_at,
            url: format!("{}/mcp", shared.public_url),
        })
    }

    /// The cloud agents of the open vault.
    pub fn agents(&self, vault: &SharedVault) -> Result<Vec<CloudAgentView>, NodeError> {
        let shared = self.shared();
        let at = now();
        let guard = lock(vault);
        let vault = guard
            .as_ref()
            .filter(|vault| !vault.is_locked())
            .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
        // Live sessions only of the node of this vault session.
        let live = shared
            .filter(|shared| shared.epoch() == vault.epoch())
            .map(|shared| shared.live_sessions())
            .unwrap_or_default();
        let agents = vault
            .cloud_agents()
            .map_err(|_| error("vault_error", "The cloud agents cannot be read."))?;
        Ok(agents
            .into_iter()
            .map(|agent| CloudAgentView {
                items: agent
                    .items
                    .iter()
                    .map(|item| {
                        let name = vault
                            .details(*item)
                            .map_or_else(|_| format!("Item {item}"), |d| d.summary.title);
                        (*item, name)
                    })
                    .collect(),
                live_session: live.iter().any(|session| {
                    session.agent_id == agent.agent_id
                        && session.expires_at.is_none_or(|end| end > at)
                }),
                agent_id: agent.agent_id,
                name: agent.name,
                token_expires_at: agent.token_expires_at,
                last_used_at: agent.last_used_at,
            })
            .collect())
    }

    /// Revoke a cloud agent: the vault at once; the node too, now or at its next start.
    /// Its token stops at its next request, its pending runs are denied, and its
    /// sessions end. The caller asks for the owner check first.
    pub fn revoke_agent(&self, vault: &SharedVault, agent_id: u64) -> Result<(), NodeError> {
        let shared = self.shared();
        let (relay_agent, epoch) = {
            let mut guard = lock(vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            let relay = vault
                .cloud_agents()
                .ok()
                .and_then(|agents| agents.into_iter().find(|agent| agent.agent_id == agent_id))
                .map(|agent| agent.relay_agent_id)
                .ok_or_else(|| error("not_found", "No such cloud agent."))?;
            vault
                .revoke_agent(agent_id)
                .map_err(|_| error("vault_error", "The agent cannot be revoked."))?;
            (relay, vault.epoch())
        };
        // Only the node of this vault session knows the agent; else the revocation waits
        // in the vault for the node of this vault (`pending_cloud_revocations`).
        if let Some(shared) = shared.filter(|shared| shared.epoch() == epoch) {
            let revoked =
                shared.with_node(|node| node.revoke_agent(&shared.team, NodeAgentId(relay_agent)));
            if matches!(revoked, Some(Ok(())))
                || matches!(&revoked, Some(Err(e)) if e.code == "not_found")
            {
                let mut guard = lock(vault);
                if let Some(vault) = guard
                    .as_mut()
                    .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
                {
                    let _ = vault.forget_cloud_agent(agent_id);
                }
            }
            let _ = shared.refresh(&[]);
        }
        Ok(())
    }

    /// "Recent cloud activity": the newest masked audit rows of the node.
    pub fn recent_activity(&self) -> Vec<AuditRow> {
        self.shared()
            .and_then(|shared| {
                shared
                    .with_node(|node| node.recent_audit(&shared.team, None, RECENT_ROWS))
                    .and_then(Result::ok)
            })
            .unwrap_or_default()
    }

    /// The node directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A port of the dynamic range that is free on the loopback now. The vault keeps it,
/// so the Funnel target stays the same.
fn free_port() -> Result<u16, NodeError> {
    let span = u32::from(CLOUD_PORT_MAX - CLOUD_PORT_MIN) + 1;
    let mut seed = [0u8; 4];
    getrandom::fill(&mut seed).map_err(|_| error("node_failed", "No randomness."))?;
    let start = u32::from_le_bytes(seed) % span;
    for offset in 0..u32::from(PORT_TRIES) {
        let port = CLOUD_PORT_MIN + u16::try_from((start + offset * 997) % span).unwrap_or(0);
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Ok(port);
        }
    }
    Err(error(
        "node_failed",
        "No free port for the public listener of the node.",
    ))
}

#[cfg(test)]
mod tailnet_tests;
#[cfg(test)]
pub(crate) mod tests;
