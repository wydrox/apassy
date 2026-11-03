//! The Mac's own node (ADR 0037, cloud slice): an embedded relay in the app process
//! that hosted cloud agents reach through Tailscale Funnel
//! (docs/design/implementation-plan-0037-cloud-agents.md).
//!
//! The root crate cannot depend on the relay crate (the relay depends on this one), so
//! the app talks to its node through the object-safe traits of `backend`. The relay
//! crate implements them (`apassy_relay::embedded::EmbeddedRelay`); the app crate passes
//! that implementation in. Tests use a fake backend.
//!
//! [`Node`] is the service of the desktop and of Bouncer > Agents. It owns the
//! running node, its host thread (`host`), and the Funnel route (`funnel`):
//!
//! - [`Node::start`] (for an unlocked vault with the route on, also before any remote
//!   agent: remote agents connect by themselves): the key of the node
//!   (`master_key`), the node on the loopback with its public listener on the stable
//!   port of the vault, the personal team of the vault, the catalog mirror
//!   (`catalog`), the Funnel route on 8443, and the host thread. It blocks (Touch ID,
//!   the Tailscale command line): the desktop runs it on a worker thread.
//! - [`Node::stop`]: the node first (every session ends, every run key goes), then the
//!   Funnel route off, then the host thread is joined. The desktop calls it on lock, on
//!   quit, and wherever it ends waiting runs.
//! - The API of the UI: [`Node::status`], [`Node::set_route`] (the remote access switch),
//!   [`Node::pending_connects`], [`Node::allow_connect`] (after the owner check
//!   `AllowConnect`), [`Node::deny_connect`], [`Node::agents`], [`Node::revoke_agent`]
//!   (Disconnect…), and [`Node::recent_activity`]. Each blocks briefly; the UI calls
//!   them off its thread, except [`Node::pending_connects`], which reads memory only.
//! - Remote agents connect by themselves with the MCP authorization flow (plan "Bouncer
//!   section" decision 4): an allowed connect request makes a relay agent with no item
//!   and a vault agent of kind `cloud` with its OAuth client (`connected_with = oauth`),
//!   and the same client connects again to the same agent. The command-line fallback
//!   [`Node::add_remote_agent`] (`apassy agents add-remote`) makes one with a token.
//!   Neither sees a credential until the owner chooses some.
//!
//! Lock order: the node (read or write), then the catalog state, then the vault. No code
//! holds the vault while it waits for the node.

pub mod backend;
pub mod catalog;
pub mod funnel;
mod host;
pub mod master_key;

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use zeroize::Zeroizing;

use self::backend::{
    AgentAccess, AuditRow, ConnectDecision, NodeAgentId, NodeBackend, NodeConfig, NodeError,
    NodeSecret, NodeTeamId, PendingConnect, TokenIssue,
};
use self::funnel::{Funnel, FunnelError, SystemTailscale, Tailscale, TailscaleCli};
use self::master_key::{KeySource, KeyStore, KeychainStore, NoKeychain};
use crate::broker::SharedVault;
use crate::broker::decide::BrokerContext;
use crate::questions::ConnectEnd;
use crate::questions::feed::note_remote_access_problem;
use crate::vault::{
    ActivityDecision, CLOUD_PORT_MAX, CLOUD_PORT_MIN, ConnectedWith, NewActivity, Vault,
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
/// The longest agent name, in bytes (the limit of the vault and of the node).
const MAX_NAME_BYTES: usize = 64;
/// The connect ends that wait for the desktop at most.
const MAX_CONNECT_ENDS: usize = 64;

/// The vault's token end of an agent of the MCP authorization flow: none. The node gives
/// it short access tokens and refreshes them (9999-12-31T23:59:59Z).
pub const NO_TOKEN_EXPIRY: u64 = 253_402_300_799;
/// The token lifetimes of `apassy agents add-remote`, in days.
pub const REMOTE_TOKEN_DAYS: std::ops::RangeInclusive<u32> = 1..=365;
/// The name of a remote agent whose client gave none.
pub const MCP_CLIENT_NAME: &str = "MCP client";

/// The Activity operations of the remote agents and the remote access of this Mac. The
/// Logs page shows them as connections.
pub const ACTIVITY_CONNECTED: &str = "remote agent connected";
pub const ACTIVITY_CONNECT_DENIED: &str = "remote agent denied";
pub const ACTIVITY_DISCONNECTED: &str = "agent disconnected";
pub const ACTIVITY_ROUTE_ON: &str = "remote access on";
pub const ACTIVITY_ROUTE_OFF: &str = "remote access off";

/// The name of the remote agent of a connect request: its client name, or
/// [`MCP_CLIENT_NAME`]. The text comes from the remote client: it is not verified.
pub fn connect_name(connect: &PendingConnect) -> String {
    connect
        .client_name
        .as_deref()
        .map(clean_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| MCP_CLIENT_NAME.to_owned())
}

/// `text` without control characters, trimmed, at most [`MAX_NAME_BYTES`].
fn clean_name(text: &str) -> String {
    let text: String = text.chars().filter(|c| !c.is_control()).collect();
    cut(text.trim(), MAX_NAME_BYTES).trim_end().to_owned()
}

/// `text` cut to at most `max` bytes at a character boundary.
fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// `wanted` (cleaned; [`MCP_CLIENT_NAME`] when empty), or with the first free number
/// when an agent in `taken` has the name, without regard to case: "Grok Bot 2". The
/// result is at most 64 bytes.
pub fn unique_name(taken: &[String], wanted: &str) -> String {
    let base = Some(clean_name(wanted))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| MCP_CLIENT_NAME.to_owned());
    let free = |name: &str| {
        !taken
            .iter()
            .any(|other| other.trim().eq_ignore_ascii_case(name))
    };
    if free(&base) {
        return base;
    }
    let mut number = 2u32;
    loop {
        let suffix = format!(" {number}");
        let name = format!(
            "{}{suffix}",
            cut(&base, MAX_NAME_BYTES - suffix.len()).trim_end()
        );
        if free(&name) {
            return name;
        }
        number += 1;
    }
}

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

/// The node as the remote access block of Bouncer > Agents shows it.
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
    /// What keeps remote access from working while the route is on; `None` when nothing
    /// does (or the route is off). The remote access block shows its button.
    pub problem: Option<RouteProblem>,
}

/// Why remote access does not work, for the remote access block (plan F6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteProblem {
    /// Tailscale is not installed: "Get Tailscale…".
    NoTailscale,
    /// Tailscale is not connected: "Check Again".
    NotConnected,
    /// The tailnet policy does not allow Funnel for this Mac: "Open Admin Console…".
    Policy,
    /// Another handler has port 8443 of Funnel.
    PortTaken,
    /// The owner's Serve handler on 443 is public.
    HttpsPublic,
    /// Another failure: the message says what.
    Failed(String),
}

impl RouteProblem {
    fn of(error: &NodeError) -> Option<Self> {
        Some(match error.code.as_str() {
            "no_tailscale" => Self::NoTailscale,
            "tailscale_not_connected" => Self::NotConnected,
            "funnel_policy" => Self::Policy,
            "funnel_port_taken" => Self::PortTaken,
            "funnel_https_public" => Self::HttpsPublic,
            // A stop on purpose, or a locked vault, is no problem of the route.
            "node_stopped" | "vault_locked" | "route_off" => return None,
            _ => Self::Failed(error.message.clone()),
        })
    }
}

/// A remote agent that the owner just connected (an allowed connect request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedAgent {
    /// The vault agent.
    pub agent_id: u64,
    pub name: String,
    /// The same OAuth client connected again to the agent it had.
    pub reconnected: bool,
}

/// A remote agent of the command line that was just made. The token is here once.
#[derive(Debug)]
pub struct AddedAgent {
    /// The vault agent.
    pub agent_id: u64,
    /// The name it got: the name asked for, or with a number when it was taken.
    pub name: String,
    pub token: NodeSecret,
    pub expires_at: u64,
    /// The MCP URL for the agent.
    pub url: String,
}

/// One remote (cloud) agent of this Mac, for the Agents page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudAgentView {
    pub agent_id: u64,
    pub name: String,
    /// (item id, item name), in id order: the credentials it may use. Empty until the
    /// owner chooses some.
    pub items: Vec<(u64, String)>,
    /// `OAuth`: it connected by itself and the owner allowed it; `Token`: a token of the
    /// command line (or an agent made before schema 27).
    pub connected_with: ConnectedWith,
    /// When the token of a token agent ends; `None` for an agent of the flow, whose
    /// tokens the node refreshes (see `access`).
    pub token_expires_at: Option<u64>,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    /// A released run of the agent has a session that may still be live.
    pub live_session: bool,
    /// How it reaches the node now (`RunningNode::agent_access`); `None` while the node
    /// does not run or cannot say.
    pub access: Option<AgentAccess>,
}

struct Running {
    /// Each start has its own number, so that a check stops only the node it saw.
    serial: u64,
    shared: Arc<host::Shared>,
    host: Option<JoinHandle<()>>,
    port: u16,
    funnel_on: bool,
}

#[derive(Default)]
struct Notes {
    /// Why the last start failed.
    failure: Option<NodeError>,
    keychain_fallback: bool,
    /// The node key was new and the older node moved aside, or the node lost the team
    /// of the vault: the cloud agents must be added again.
    lost_key: bool,
}

/// The node service. Every method can be called from any thread.
pub struct Node {
    backend: Arc<dyn NodeBackend>,
    keys: Arc<dyn KeyStore>,
    funnel: Funnel,
    data_dir: PathBuf,
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
    /// Connect requests that the owner decided on this Mac or that the node withdrew, for
    /// the questions lane ([`Node::take_connect_ends`]), oldest first.
    connect_ends: Mutex<std::collections::VecDeque<(String, ConnectEnd)>>,
    /// Called on the host thread when the connect requests change; every node of this
    /// service gets it.
    on_connects: Arc<Mutex<Option<host::ConnectsHook>>>,
}

/// The state of the open vault that a start needs.
struct VaultState {
    epoch: [u8; 32],
    file: PathBuf,
    team: Option<String>,
    port: u16,
}

impl Node {
    pub fn new(options: NodeOptions) -> Self {
        Self {
            backend: options.backend,
            keys: options.keys,
            funnel: Funnel::new(options.cli),
            data_dir: options.data_dir,
            key: Mutex::new(None),
            start_lock: Mutex::new(()),
            running: Mutex::new(None),
            stops_waiting: AtomicUsize::new(0),
            serial: AtomicU64::new(0),
            notes: Mutex::new(Notes::default()),
            connect_ends: Mutex::new(std::collections::VecDeque::new()),
            on_connects: Arc::new(Mutex::new(None)),
        }
    }

    /// Call `hook` (on the host thread, with no lock of the node held) each time the
    /// connect requests that wait change: the desktop wakes its window, so Decisions and
    /// the iPhone card see a new request at once, also while the window is idle.
    pub fn set_on_connects_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *lock(&self.on_connects) = Some(Arc::new(hook));
    }

    /// True while the node runs.
    pub fn is_running(&self) -> bool {
        lock(&self.running).is_some()
    }

    /// The vault session that the node serves, while it runs.
    pub fn serves(&self) -> Option<[u8; 32]> {
        lock(&self.running)
            .as_ref()
            .map(|running| running.shared.epoch())
    }

    /// Whether the open vault wants a node to start: unlocked and the public route on.
    /// No remote agent is needed: remote agents connect by themselves through the
    /// running node. `Some` is the vault session.
    pub fn wanted(vault: &Vault) -> Option<[u8; 32]> {
        Self::may_run(vault)
    }

    /// Whether a running node may go on for the open vault: unlocked and the public
    /// route on.
    pub fn may_run(vault: &Vault) -> Option<[u8; 32]> {
        if vault.is_locked() {
            return None;
        }
        vault
            .cloud_node_setting()
            .is_ok_and(|setting| setting.route_on)
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
        if !setting.route_on {
            return Err(error(
                "route_off",
                "Remote access is off (Bouncer > Agents).",
            ));
        }
        let port = match setting.port {
            Some(port) => port,
            None => {
                let port = free_port()?;
                vault.set_cloud_node_port(port).map_err(storage)?;
                port
            }
        };
        Ok(VaultState {
            epoch: vault.epoch(),
            file: vault.path().to_path_buf(),
            team: setting.team_id,
            port,
        })
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
        let problem = result.as_ref().err().and_then(RouteProblem::of);
        note_remote_access_problem(problem.is_some());
        lock(&self.notes).failure = result.as_ref().err().cloned();
        result
    }

    /// At the start of the app, before any vault opens: turn off a Funnel route of this
    /// node that a crash left on (its handler is still the app's last target). A route
    /// of another program is left alone. It runs the Tailscale command line, and does
    /// nothing while a node runs.
    pub fn clear_stale_route(&self) {
        let _one = lock(&self.start_lock);
        if self.is_running() {
            return;
        }
        if let Some(port) = self.last_target() {
            let _ = self.funnel.disable(port);
        }
    }

    fn start_inner(&self, vault: &SharedVault, broker: BrokerContext) -> Result<(), NodeError> {
        if self.is_running() {
            return Ok(());
        }
        self.check_not_stopping()?;
        let state = Self::vault_state(vault)?;
        let dns_name = match self.funnel.status() {
            Tailscale::Missing => return Err(funnel_error(&FunnelError::NoTailscale)),
            Tailscale::NotConnected { state } => {
                return Err(funnel_error(&FunnelError::NotConnected(state)));
            }
            Tailscale::Connected { dns_name } => dns_name,
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
        let public_url = funnel::public_origin(&dns_name);
        let node = match self.backend.start(NodeConfig {
            data_dir: self.data_dir.clone(),
            master_key: key,
            public_url: public_url.clone(),
            public_listen: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, state.port))),
        }) {
            Ok(node) => node,
            Err(failure) => {
                // A handler that an earlier process left on for this port (a crash) must
                // not outlive a start that failed: nothing listens behind it.
                let _ = self.funnel.disable(state.port);
                return Err(failure);
            }
        };
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
        let mut shared = host::Shared::new(
            node,
            team,
            Arc::clone(vault),
            state.file.clone(),
            broker,
            state.epoch,
            public_url,
        );
        shared.on_connects = Arc::clone(&self.on_connects);
        let shared = Arc::new(shared);
        if let Err(failure) = self
            .check_not_stopping()
            .and_then(|()| shared.refresh(&[]).map(drop))
        {
            Self::teardown(&shared, None);
            return Err(failure);
        }
        if let Err(failure) = self.funnel.enable(state.port, self.last_target()) {
            Self::teardown(&shared, None);
            return Err(funnel_error(&failure));
        }
        self.note_target(state.port);
        let host = match host::spawn(Arc::clone(&shared)) {
            Ok(host) => host,
            Err(_) => {
                Self::teardown(&shared, None);
                let _ = self.funnel.disable(state.port);
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
            Self::teardown(&shared, Some(host));
            let _ = self.funnel.disable(state.port);
            return Err(failure);
        }
        *lock(&self.running) = Some(Running {
            serial: self.serial.fetch_add(1, Ordering::SeqCst) + 1,
            shared,
            host: Some(host),
            port: state.port,
            funnel_on: true,
        });
        Ok(())
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
        // The node first: the sessions end at once, before the slower command line.
        Self::teardown(&running.shared, running.host.take());
        if running.funnel_on {
            let _ = self.funnel.disable(running.port);
        }
        drop(one);
    }

    /// Check the route of a running node: when the tailnet name changed or the Funnel
    /// handler is gone, stop it (the desktop starts it again with the new origin; the
    /// sessions end). Only the node that it checked is stopped. Returns true when it
    /// stopped the node.
    pub fn maintain(&self) -> bool {
        let Some((serial, port, public_url)) = lock(&self.running).as_ref().map(|running| {
            (
                running.serial,
                running.port,
                running.shared.public_url.clone(),
            )
        }) else {
            return false;
        };
        let name_changed = match self.funnel.status() {
            Tailscale::Connected { dns_name } => funnel::public_origin(&dns_name) != public_url,
            _ => true,
        };
        let route_gone = self
            .funnel
            .serve_state(port)
            .is_ok_and(|state| state.funnel_port != funnel::PortUse::Ours);
        if name_changed || route_gone {
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

    fn mcp_url(&self) -> Option<String> {
        self.shared()
            .map(|shared| format!("{}/mcp", shared.public_url))
    }

    /// The node for the remote access block. It runs the Tailscale command line.
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
            warnings.push(failure.message.clone());
        }
        let problem = notes
            .failure
            .as_ref()
            .filter(|_| route_on && !running)
            .and_then(RouteProblem::of)
            .or_else(|| match &tailscale {
                _ if !route_on => None,
                Tailscale::Missing => Some(RouteProblem::NoTailscale),
                Tailscale::NotConnected { .. } => Some(RouteProblem::NotConnected),
                Tailscale::Connected { .. } => None,
            });
        // The feed of this Mac says `problem` while the route is on and this holds.
        note_remote_access_problem(problem.is_some());
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
        NodeStatus {
            tailscale,
            route_on,
            running,
            url,
            port,
            keychain_fallback: lock(&self.notes).keychain_fallback,
            warnings,
            problem,
        }
    }

    /// Turn the public route (remote access) on or off. Off stops the node at once; on
    /// lets the desktop start it. A change writes the Activity row `remote access on` or
    /// `remote access off`. On gives authority: the caller asks for the owner check
    /// first (`OwnerRequest::TurnOnRemoteAccess`).
    pub fn set_route(&self, vault: &SharedVault, on: bool) -> Result<(), NodeError> {
        {
            let mut guard = lock(vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            let was = vault
                .cloud_node_setting()
                .is_ok_and(|setting| setting.route_on);
            vault
                .set_cloud_route_on(on)
                .map_err(|_| error("vault_error", "The route setting cannot be saved."))?;
            if was != on {
                let _ = vault.record_activity(&NewActivity {
                    agent_id: None,
                    agent_name: String::new(),
                    item_id: None,
                    operation: if on { ACTIVITY_ROUTE_ON } else { ACTIVITY_ROUTE_OFF }.to_owned(),
                    decision: ActivityDecision::Allow,
                    reason: if on {
                        "Remote access is on: remote agents can reach this Mac through Tailscale Funnel while it is awake and the vault is unlocked. Every remote run still asks you."
                    } else {
                        "Remote access is off: no remote agent reaches this Mac."
                    }
                    .to_owned(),
                });
            }
        }
        if !on {
            lock(&self.notes).failure = None;
            note_remote_access_problem(false);
            self.stop();
        }
        Ok(())
    }

    /// The connect requests that wait for the owner, oldest first, as the host thread
    /// read them from the node last (at most a few seconds old). It reads memory only, so
    /// the UI may call it each frame. Empty while no node runs.
    pub fn pending_connects(&self) -> Vec<PendingConnect> {
        let at = now();
        self.shared()
            .map(|shared| {
                lock(&shared.connects)
                    .iter()
                    .filter(|connect| connect.expires_at > at)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Allow the connect request `id` on this Mac, after the owner check
    /// `OwnerAction::AllowConnect` (Touch ID). See [`Node::allow_connect_on`].
    pub fn allow_connect(
        &self,
        vault: &SharedVault,
        id: &str,
    ) -> Result<ConnectedAgent, NodeError> {
        self.allow_connect_on(vault, id, None)
    }

    /// Allow the connect request `id`: with `device`, the name of the iPhone whose Face
    /// ID answer the questions lane verified; `None` for this Mac. A client that has a
    /// live agent of this vault connects again to it (its credentials stay). Else a new
    /// relay agent with no item, then a vault agent of kind `cloud` with `see_all = 0`,
    /// the OAuth client, and `connected_with = oauth`, then the decision on the relay; a
    /// save that fails revokes the relay agent and denies the request. Errors:
    /// `connect_not_pending` (decided, ended, or unknown), `node_stopped`,
    /// `vault_locked`, `team_limit` (20 remote agents), `agent_not_saved` (the vault did
    /// not take the agent: the relay agent is revoked and the request denied).
    pub fn allow_connect_on(
        &self,
        vault: &SharedVault,
        id: &str,
        device: Option<&str>,
    ) -> Result<ConnectedAgent, NodeError> {
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "Remote access is not running."))?;
        let serves = lock(vault)
            .as_ref()
            .is_some_and(|vault| !vault.is_locked() && vault.epoch() == shared.epoch());
        if !serves {
            return Err(error("vault_locked", "The vault is locked."));
        }
        shared.poll_connects();
        let connect = self
            .pending_connects()
            .into_iter()
            .find(|connect| connect.id == id)
            .ok_or_else(|| {
                error(
                    "connect_not_pending",
                    "This connect request does not wait any more.",
                )
            })?;
        let by = device.map_or_else(
            || "Allowed with Touch ID on this Mac.".to_owned(),
            |device| format!("Allowed with Face ID on {}.", cut(device, MAX_NAME_BYTES)),
        );
        // The same client with a live agent of this vault: connect it to that agent.
        if let Some((agent_id, relay, name)) = Self::live_agent_of(&shared, &connect.client_id) {
            shared
                .with_node(|node| {
                    node.decide_connect(
                        id,
                        ConnectDecision::Allow {
                            team: shared.team.clone(),
                            agent: NodeAgentId(relay),
                        },
                    )
                })
                .unwrap_or_else(|| Err(error("node_stopped", "Remote access is not running.")))?;
            self.note_connect_end(id, ConnectEnd::Allowed);
            Self::record(
                &shared,
                Some(agent_id),
                &name,
                ACTIVITY_CONNECTED,
                ActivityDecision::Allow,
                format!(
                    "{by} {name} connected again with the MCP authorization flow (code {}). It keeps the credentials it had.",
                    cut(&connect.code, 16)
                ),
            );
            return Ok(ConnectedAgent {
                agent_id,
                name,
                reconnected: true,
            });
        }
        let made = shared.add_agent(
            &connect_name(&connect),
            TokenIssue::Later,
            Some(&connect.client_id),
        );
        let (agent_id, name, created) = match made {
            Ok(made) => made,
            Err(failure) if failure.code == host::AGENT_NOT_SAVED => {
                // Nothing was saved and the relay agent is revoked: the client must not
                // wait for a connection that cannot come.
                let _ = self.deny_connect(id);
                return Err(failure);
            }
            Err(failure) => return Err(failure),
        };
        let decided = shared
            .with_node(|node| {
                node.decide_connect(
                    id,
                    ConnectDecision::Allow {
                        team: shared.team.clone(),
                        agent: created.agent_id,
                    },
                )
            })
            .unwrap_or_else(|| Err(error("node_stopped", "Remote access is not running.")));
        if let Err(failure) = decided {
            // The request ended in between: the new agent goes again, on both sides.
            let _ = shared.with_node(|node| node.revoke_agent(&shared.team, created.agent_id));
            shared.in_vault(|vault| {
                if vault.revoke_agent(agent_id).is_ok() {
                    let _ = vault.forget_cloud_agent(agent_id);
                }
            });
            let _ = shared.refresh(&[]);
            return Err(failure);
        }
        self.note_connect_end(id, ConnectEnd::Allowed);
        Self::record(
            &shared,
            Some(agent_id),
            &name,
            ACTIVITY_CONNECTED,
            ActivityDecision::Allow,
            format!(
                "{by} {name} connected with the MCP authorization flow (code {}). It sees no credential until you choose some, and every run asks you.",
                cut(&connect.code, 16)
            ),
        );
        Ok(ConnectedAgent {
            agent_id,
            name,
            reconnected: false,
        })
    }

    /// The live remote agent of this vault that connected with the OAuth client
    /// `client_id`, if the node still knows it: (vault agent, node agent, name). A vault
    /// agent whose node agent is revoked or gone is revoked in the vault too.
    fn live_agent_of(shared: &host::Shared, client_id: &str) -> Option<(u64, u64, String)> {
        let (agent_id, relay, name) = shared.in_vault(|vault| {
            let agent_id = vault.cloud_agent_for_client(client_id).ok().flatten()?;
            vault
                .cloud_agents()
                .ok()?
                .into_iter()
                .find(|agent| agent.agent_id == agent_id)
                .map(|agent| (agent_id, agent.relay_agent_id, agent.name))
        })??;
        let access =
            shared.with_node(|node| node.agent_access(&shared.team, NodeAgentId(relay)))?;
        match access {
            Ok(access) if !access.revoked => Some((agent_id, relay, name)),
            Ok(_) => {
                shared.in_vault(|vault| {
                    if vault.revoke_agent(agent_id).is_ok() {
                        let _ = vault.forget_cloud_agent(agent_id);
                    }
                });
                None
            }
            Err(failure) if failure.code == "not_found" => {
                shared.in_vault(|vault| {
                    if vault.revoke_agent(agent_id).is_ok() {
                        let _ = vault.forget_cloud_agent(agent_id);
                    }
                });
                None
            }
            // A node without the report: trust the vault.
            Err(_) => Some((agent_id, relay, name)),
        }
    }

    /// Deny the connect request `id`: the browser page says "You denied the
    /// connection." Errors: `connect_not_pending`, `node_stopped`.
    pub fn deny_connect(&self, id: &str) -> Result<(), NodeError> {
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "Remote access is not running."))?;
        let name = lock(&shared.connects)
            .iter()
            .find(|connect| connect.id == id)
            .map_or_else(|| MCP_CLIENT_NAME.to_owned(), connect_name);
        shared
            .with_node(|node| node.decide_connect(id, ConnectDecision::Deny))
            .unwrap_or_else(|| Err(error("node_stopped", "Remote access is not running.")))?;
        lock(&shared.connects).retain(|connect| connect.id != id);
        self.note_connect_end(id, ConnectEnd::Denied);
        Self::record(
            &shared,
            None,
            &name,
            ACTIVITY_CONNECT_DENIED,
            ActivityDecision::Deny,
            format!("You denied the connection of {name}. Nothing was made."),
        );
        Ok(())
    }

    /// The connect requests that ended on this Mac since the last call (allowed, denied),
    /// oldest first. The desktop gives each to the questions lane
    /// (`QuestionsWorker::end_connect`), so the iPhone cards settle.
    pub fn take_connect_ends(&self) -> Vec<(String, ConnectEnd)> {
        lock(&self.connect_ends).drain(..).collect()
    }

    fn note_connect_end(&self, id: &str, end: ConnectEnd) {
        let mut ends = lock(&self.connect_ends);
        if ends.len() >= MAX_CONNECT_ENDS {
            ends.pop_front();
        }
        ends.push_back((id.to_owned(), end));
    }

    /// One Activity row about a remote agent, in the vault session of the node.
    fn record(
        shared: &host::Shared,
        agent_id: Option<u64>,
        name: &str,
        operation: &str,
        decision: ActivityDecision,
        reason: String,
    ) {
        shared.in_vault(|vault| {
            let _ = vault.record_activity(&NewActivity {
                agent_id,
                agent_name: cut(name, MAX_NAME_BYTES).to_owned(),
                item_id: None,
                operation: operation.to_owned(),
                decision,
                reason,
            });
        });
    }

    /// The command-line fallback (`apassy agents add-remote NAME [--days N]`): a remote
    /// agent with no item and a bearer token of `days` days (1 to 365), for a client
    /// without the MCP authorization flow. Starts the node when it does not run (the
    /// route must be on). The token is in the answer once, with the MCP address. The
    /// caller asks for the owner check first (`OwnerAction::AddRemoteAgent`).
    pub fn add_remote_agent(
        &self,
        vault: &SharedVault,
        broker: BrokerContext,
        name: &str,
        days: u32,
    ) -> Result<AddedAgent, NodeError> {
        if !REMOTE_TOKEN_DAYS.contains(&days) {
            return Err(error(
                "invalid_request",
                "The token lifetime is 1 to 365 days.",
            ));
        }
        if clean_name(name).is_empty() {
            return Err(error("invalid_request", "Name the remote agent."));
        }
        if !self.is_running() {
            self.start(vault, broker)?;
        }
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "The node is not running."))?;
        let (agent_id, name, created) = shared.add_agent(
            name,
            TokenIssue::Now {
                lifetime_days: days,
            },
            None,
        )?;
        let token = created
            .token
            .ok_or_else(|| error("relay_error", "The node made no token for the agent."))?;
        Self::record(
            &shared,
            Some(agent_id),
            &name,
            ACTIVITY_CONNECTED,
            ActivityDecision::Allow,
            format!(
                "Added with apassy agents add-remote: a token for {days} days. {name} sees no credential until you choose some, and every run asks you."
            ),
        );
        Ok(AddedAgent {
            agent_id,
            name,
            token,
            expires_at: created.expires_at,
            url: format!("{}/mcp", shared.public_url),
        })
    }

    /// The remote (cloud) agents of the open vault, with how each reaches the node now.
    /// It reads the vault, then asks the node without the vault held.
    pub fn agents(&self, vault: &SharedVault) -> Result<Vec<CloudAgentView>, NodeError> {
        let shared = self.shared();
        let at = now();
        let (mut views, epoch) = {
            let guard = lock(vault);
            let vault = guard
                .as_ref()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            // Live sessions only of the node of this vault session.
            let live = shared
                .as_ref()
                .filter(|shared| shared.epoch() == vault.epoch())
                .map(|shared| shared.live_sessions())
                .unwrap_or_default();
            let agents = vault
                .cloud_agents()
                .map_err(|_| error("vault_error", "The cloud agents cannot be read."))?;
            let views: Vec<(u64, CloudAgentView)> = agents
                .into_iter()
                .map(|agent| {
                    let connected_with = vault
                        .cloud_agent_link(agent.agent_id)
                        .ok()
                        .flatten()
                        .map_or(ConnectedWith::Token, |(_, with)| with);
                    let view = CloudAgentView {
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
                        connected_with,
                        // An agent of the flow made before this field has the far end.
                        token_expires_at: (connected_with == ConnectedWith::Token
                            && agent.token_expires_at < NO_TOKEN_EXPIRY)
                            .then_some(agent.token_expires_at),
                        created_at: agent.created_at,
                        last_used_at: agent.last_used_at,
                        access: None,
                    };
                    (agent.relay_agent_id, view)
                })
                .collect();
            (views, vault.epoch())
        };
        if let Some(shared) = shared.filter(|shared| shared.epoch() == epoch) {
            for (relay, view) in &mut views {
                view.access = shared
                    .with_node(|node| node.agent_access(&shared.team, NodeAgentId(*relay)))
                    .and_then(Result::ok);
            }
        }
        Ok(views.into_iter().map(|(_, view)| view).collect())
    }

    /// Disconnect (revoke) a remote agent: the vault at once; the node too, now or at its
    /// next start. Its token stops at its next request, its OAuth refresh family is
    /// revoked, the open connect requests of its client are denied, its pending runs are
    /// denied, and its sessions end. It writes the Activity row `agent disconnected`. It
    /// takes authority away: no owner check is needed (the UI confirms it in a sheet).
    pub fn revoke_agent(&self, vault: &SharedVault, agent_id: u64) -> Result<(), NodeError> {
        let shared = self.shared();
        let (relay_agent, epoch) = {
            let mut guard = lock(vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .ok_or_else(|| error("vault_locked", "The vault is locked."))?;
            let (relay, name) = vault
                .cloud_agents()
                .ok()
                .and_then(|agents| agents.into_iter().find(|agent| agent.agent_id == agent_id))
                .map(|agent| (agent.relay_agent_id, agent.name))
                .ok_or_else(|| error("not_found", "No such cloud agent."))?;
            vault
                .revoke_agent(agent_id)
                .map_err(|_| error("vault_error", "The agent cannot be revoked."))?;
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(agent_id),
                agent_name: name.clone(),
                item_id: None,
                operation: ACTIVITY_DISCONNECTED.to_owned(),
                decision: ActivityDecision::Allow,
                reason: format!(
                    "You disconnected {name}. Its token stops working, and it must connect again and be allowed."
                ),
            });
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

    /// Send the catalog mirror and the item list of each remote agent to the node now:
    /// after the owner chose the credentials of a remote agent ("Choose Credentials…").
    /// The host thread does it every few seconds anyway.
    pub fn sync_catalog(&self) -> Result<(), NodeError> {
        self.shared()
            .ok_or_else(|| error("node_stopped", "The node is not running."))?
            .refresh(&[])
            .map(drop)
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
pub(crate) mod tests;
