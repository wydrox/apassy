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
    AuditRow, NodeAgentId, NodeBackend, NodeConfig, NodeError, NodeSecret, NodeTeamId,
};
use self::funnel::{Funnel, FunnelError, SystemTailscale, Tailscale, TailscaleCli};
use self::master_key::{KeySource, KeyStore, KeychainStore, NoKeychain};
use crate::broker::SharedVault;
use crate::broker::decide::BrokerContext;
use crate::vault::{CLOUD_PORT_MAX, CLOUD_PORT_MIN, CLOUD_TOKEN_DAYS, Vault};

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
}

#[derive(Default)]
struct Notes {
    /// Why the last start failed.
    failure: Option<String>,
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
        }
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

    /// Whether the open vault wants a node to start: unlocked, the public route on, and
    /// an active cloud agent. `Some` is the vault session.
    pub fn wanted(vault: &Vault) -> Option<[u8; 32]> {
        Self::may_run(vault).filter(|_| vault.has_cloud_agents().unwrap_or(false))
    }

    /// Whether a running node may go on for the open vault: unlocked and the public
    /// route on. Without a cloud agent a node goes on (the first agent is being made).
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
                "The public route is off in Settings > Cloud agents.",
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
            Err(error("node_stopped", "The node was stopped while it started."))
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
        lock(&self.notes).failure = result.as_ref().err().map(|error| error.message.clone());
        result
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
        let node = self.backend.start(NodeConfig {
            data_dir: self.data_dir.clone(),
            master_key: key,
            public_url: public_url.clone(),
            public_listen: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, state.port))),
        })?;
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
                warnings.push(format!("Item {item} is not offered to cloud agents: {why}."));
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
        }
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
        if !on {
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
        if !self.is_running() {
            self.start(vault, broker)?;
        }
        let shared = self
            .shared()
            .ok_or_else(|| error("node_stopped", "The node is not running."))?;
        let (agent_id, created) = shared.add_agent(name, items, days)?;
        Ok(AddedAgent {
            agent_id,
            token: created.token,
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
                .and_then(|agents| {
                    agents
                        .into_iter()
                        .find(|agent| agent.agent_id == agent_id)
                })
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
            let revoked = shared
                .with_node(|node| node.revoke_agent(&shared.team, NodeAgentId(relay_agent)));
            if matches!(revoked, Some(Ok(()))) || matches!(&revoked, Some(Err(e)) if e.code == "not_found")
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
pub(crate) mod tests;
