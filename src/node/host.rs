//! The in-process host of the node (ADR 0037, cloud slice, decision 2).
//!
//! One thread for each running node waits for pending runs (`RunningNode::wait_pending`).
//! Each run gets a worker thread that:
//!
//! 1. maps the run to the vault: the node agent to the cloud agent, each item uid to its
//!    vault item (`cloud_item`); a run outside the open vault is denied;
//! 2. asks the broker (`broker::evaluate_cloud`): every cloud run asks the owner, on this
//!    Mac and on the iPhone, and nothing is remembered;
//! 3. on approval, reads the value of each item with `Vault::reveal`, in the order of the
//!    run, in the vault session and with the bindings of the broker's second check, and
//!    releases the run (`RunningNode::release`); else it denies the run with the reason.
//!
//! Activity: the broker writes the row of a refusal; this host writes the row of an
//! approval ("cloud run", the agent, the items, the decision) and, when the session
//! ends, a row with the proxied requests of the session (ADR 0011 §5), counted from the
//! `proxy_request` rows of the node's audit, and it keeps a `cloud_run` row for each
//! run that the broker decided (schema 27) with the counts at the end of its session.
//! Every few seconds the thread checks the released runs for their end, makes the
//! catalog mirror again, and sends revocations that the node has not seen.
//!
//! One question of a cloud agent at a time: the approval queue holds one waiting question
//! for each agent (`question_waiting` for a second one), so the host asks about one run
//! of an agent at a time. A second run of the same agent waits in the node and is asked
//! when the first is settled; a `question_waiting` of the broker is retried the same
//! way, never denied. The relay's run timeout (300 s) bounds the wait.
//!
//! Connect requests of the MCP authorization flow: after each return of the wait (it
//! also returns when they change) the thread reads them from the node
//! (`RunningNode::pending_connects`), so [`super::Node::pending_connects`] answers
//! without a call to the node.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::backend::{
    CreatedAgent, NewCloudAgent, NodeAgentId, NodeError, NodeRunId, NodeSecret, NodeTeamId,
    PendingConnect, PendingRun, RunStatus, RunningNode, TokenIssue,
};
use super::catalog::{self, Checked};
use crate::broker::decide::BrokerContext;
use crate::broker::{CloudContext, CloudDecision, CloudRequest, SharedVault, evaluate_cloud};
use crate::vault::{ActivityDecision, EnvDelivery, NewActivity, NewCloudRun, Vault, format_utc};

/// The longest wait for pending runs. The wait holds the node, and a stop waits for it
/// (on the UI thread), so it is short.
const WAIT: Duration = Duration::from_millis(100);
/// A poll that gives only runs in progress waits this long before the next one.
const BUSY_PAUSE: Duration = Duration::from_millis(250);
/// How often released runs are checked for their end, and the catalog is made again.
pub(super) const CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// The longest reason that the node takes for a denial, in bytes.
const MAX_REASON_BYTES: usize = 500;
/// The audit rows of one run that the session summary reads.
const MAX_RUN_AUDIT: u32 = 500;
/// The Activity text of a cloud run.
const MAX_LABEL_BYTES: usize = 64;
/// The text of an approved release, for the agent.
const RELEASED_NOTE: &str = "The owner approved this run in Apassy.";
/// A run that waits for another question of its agent is tried again after this pause.
pub(super) const RETRY_PAUSE: Duration = Duration::from_secs(1);
/// A retry mark of a run that the node no longer gives is dropped after this time (the
/// relay times a run out after 300 s).
const RETRY_FORGET: Duration = Duration::from_secs(600);
/// The error code of [`Shared::add_agent`] when the vault did not take the agent: the
/// node agent is revoked again.
pub(super) const AGENT_NOT_SAVED: &str = "agent_not_saved";
/// The refusal code of the broker for a second question of one agent.
const QUESTION_WAITING: &str = "question_waiting";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What the host calls when the connect requests of the node change.
pub(super) type ConnectsHook = Arc<dyn Fn() + Send + Sync>;

/// A released run whose session may still be live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSession {
    pub run_id: NodeRunId,
    /// The vault agent.
    pub agent_id: u64,
    pub agent_name: String,
    pub items: Vec<u64>,
    pub label: String,
    pub expires_at: Option<u64>,
}

/// What the catalog mirror keeps between builds.
#[derive(Debug, Default)]
pub(super) struct CatalogState {
    checked: Checked,
    /// The item list that the node has for each agent.
    lists: HashMap<NodeAgentId, Vec<String>>,
    /// Items that a cloud agent sees but that the node does not take, with the reason.
    pub(super) skipped: Vec<(u64, &'static str)>,
}

/// What the host thread, its workers, and the node service share.
pub(super) struct Shared {
    /// The node. `None` once it stopped: a late call does nothing.
    pub(super) node: RwLock<Option<Box<dyn RunningNode>>>,
    pub(super) team: NodeTeamId,
    pub(super) vault: SharedVault,
    /// The vault file of the team.
    pub(super) vault_file: PathBuf,
    pub(super) broker: BrokerContext,
    /// The vault session that the node serves. A passphrase change or a backup of the
    /// same file starts a new session: the node takes it ([`Shared::adopt`]).
    epoch: Mutex<[u8; 32]>,
    /// `https://<DNSName>:8443`.
    pub(super) public_url: String,
    pub(super) stop: Arc<AtomicBool>,
    in_flight: Mutex<HashSet<NodeRunId>>,
    /// Runs that wait for another question of their agent: not tried again before this.
    retry_at: Mutex<HashMap<NodeRunId, Instant>>,
    /// The vault agents whose run the broker is asking about now: one at a time.
    asking: Mutex<HashSet<u64>>,
    /// The connect requests that wait for the owner, as the node gave them last.
    pub(super) connects: Mutex<Vec<PendingConnect>>,
    /// Called when that list changes (the desktop wakes its window). Shared with the
    /// service, so a hook set later reaches a running node.
    pub(super) on_connects: Arc<Mutex<Option<ConnectsHook>>>,
    sessions: Mutex<Vec<LiveSession>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    pub(super) catalog: Mutex<CatalogState>,
}

impl Shared {
    pub(super) fn new(
        node: Box<dyn RunningNode>,
        team: NodeTeamId,
        vault: SharedVault,
        vault_file: PathBuf,
        broker: BrokerContext,
        epoch: [u8; 32],
        public_url: String,
    ) -> Self {
        Self {
            node: RwLock::new(Some(node)),
            team,
            vault,
            vault_file,
            broker,
            epoch: Mutex::new(epoch),
            public_url,
            stop: Arc::new(AtomicBool::new(false)),
            in_flight: Mutex::new(HashSet::new()),
            retry_at: Mutex::new(HashMap::new()),
            asking: Mutex::new(HashSet::new()),
            connects: Mutex::new(Vec::new()),
            on_connects: Arc::new(Mutex::new(None)),
            sessions: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
            catalog: Mutex::new(CatalogState::default()),
        }
    }

    /// Call `f` with the node while it runs.
    pub(super) fn with_node<R>(&self, f: impl FnOnce(&dyn RunningNode) -> R) -> Option<R> {
        let guard = self.node.read().unwrap_or_else(PoisonError::into_inner);
        guard.as_deref().map(f)
    }

    /// The vault session that the node serves.
    pub(super) fn epoch(&self) -> [u8; 32] {
        *lock(&self.epoch)
    }

    /// Serve the new session of the same vault file, after a passphrase change or a
    /// backup. Returns false for another file or a locked vault.
    pub(super) fn adopt(&self, vault: &Vault) -> bool {
        if vault.is_locked() || vault.path() != self.vault_file.as_path() {
            return false;
        }
        *lock(&self.epoch) = vault.epoch();
        true
    }

    /// Call `f` with the vault while the session of the node lasts.
    fn with_vault<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> Option<R> {
        let epoch = self.epoch();
        let mut guard = lock(&self.vault);
        guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
            .map(f)
    }

    /// The sessions that may still be live.
    pub(super) fn live_sessions(&self) -> Vec<LiveSession> {
        lock(&self.sessions).clone()
    }

    /// Take the node out, so that no call reaches it any more. The caller stops it.
    pub(super) fn take_node(&self) -> Option<Box<dyn RunningNode>> {
        self.stop.store(true, Ordering::SeqCst);
        self.node
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Make the catalog mirror again, send it to the node, update the item list of
    /// each agent, and revoke in the node each agent that the vault revoked.
    pub(super) fn refresh(&self, extra: &[u64]) -> Result<catalog::Mirror, NodeError> {
        let guard = self.node.read().unwrap_or_else(PoisonError::into_inner);
        let node: &dyn RunningNode = guard
            .as_deref()
            .ok_or_else(|| NodeError::new("node_stopped", "The node is not running."))?;
        let mut state = lock(&self.catalog);
        self.refresh_with(node, &mut state, extra)
    }

    /// [`Shared::refresh`] with the node and the catalog state held, and with `extra`
    /// items of an agent that is about to be made.
    fn refresh_with(
        &self,
        node: &dyn RunningNode,
        state: &mut CatalogState,
        extra: &[u64],
    ) -> Result<catalog::Mirror, NodeError> {
        let (mirror, revoked) = self
            .with_vault(|vault| {
                let revoked = vault.pending_cloud_revocations().unwrap_or_default();
                catalog::build(vault, node, &mut state.checked, extra).map(|m| (m, revoked))
            })
            .ok_or_else(|| NodeError::new("vault_locked", "The vault is locked."))??;
        for (agent_id, relay_agent) in revoked {
            match node.revoke_agent(&self.team, NodeAgentId(relay_agent)) {
                Ok(()) => {}
                Err(error) if error.code == "not_found" => {}
                Err(error) => return Err(error),
            }
            state.lists.remove(&NodeAgentId(relay_agent));
            self.with_vault(|vault| vault.forget_cloud_agent(agent_id));
        }
        node.sync_items(&self.team, &mirror.items)?;
        for (agent, list) in &mirror.agents {
            if state.lists.get(agent) != Some(list) {
                node.set_agent_items(&self.team, *agent, list)?;
                state.lists.insert(*agent, list.clone());
            }
        }
        state.skipped.clone_from(&mirror.skipped);
        Ok(mirror)
    }

    /// Make a remote agent with no item in the node and in the vault: an agent of the
    /// MCP authorization flow (`TokenIssue::Later`, with the OAuth `client_id` of its
    /// connect request) or of the command line (`TokenIssue::Now`, no client). A name
    /// that another active agent has gets a number ("Grok Bot 2"). The catalog state is
    /// held from the mirror to the save, so the periodic refresh does not send an item
    /// list for the agent in between. A failed save revokes the node agent. Returns the
    /// vault agent, its name, and the node agent with its token.
    pub(super) fn add_agent(
        &self,
        name: &str,
        token: TokenIssue,
        client_id: Option<&str>,
    ) -> Result<(u64, String, CreatedAgent), NodeError> {
        let guard = self.node.read().unwrap_or_else(PoisonError::into_inner);
        let node: &dyn RunningNode = guard
            .as_deref()
            .ok_or_else(|| NodeError::new("node_stopped", "The node is not running."))?;
        let mut state = lock(&self.catalog);
        self.refresh_with(node, &mut state, &[])?;
        let name = self
            .with_vault(|vault| {
                let taken: Vec<String> = vault
                    .list_agents()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|agent| !agent.revoked)
                    .map(|agent| agent.name)
                    .collect();
                super::unique_name(&taken, name)
            })
            .ok_or_else(|| NodeError::new("vault_locked", "The vault is locked."))?;
        let created = node.create_agent(
            &self.team,
            &NewCloudAgent {
                name: name.clone(),
                items: Vec::new(),
                token,
            },
        )?;
        let expires_at = match token {
            TokenIssue::Now { .. } => created.expires_at,
            // The node refreshes the tokens of the flow: the vault keeps no end.
            TokenIssue::Later => super::NO_TOKEN_EXPIRY,
        };
        let saved = self.with_vault(|vault| {
            vault.add_remote_agent(&name, created.agent_id.0, expires_at, client_id)
        });
        match saved {
            Some(Ok(agent_id)) => {
                state.lists.insert(created.agent_id, Vec::new());
                Ok((agent_id, name, created))
            }
            _ => {
                let _ = node.revoke_agent(&self.team, created.agent_id);
                let _ = self.refresh_with(node, &mut state, &[]);
                Err(NodeError::new(
                    AGENT_NOT_SAVED,
                    "The remote agent cannot be saved in the vault. Nothing was made.",
                ))
            }
        }
    }

    /// Read the connect requests of the node again, and call the hook when they changed.
    pub(super) fn poll_connects(&self) {
        let Some(Ok(list)) = self.with_node(|node| node.pending_connects()) else {
            return;
        };
        let changed = {
            let mut connects = lock(&self.connects);
            let changed = *connects != list;
            *connects = list;
            changed
        };
        if changed {
            let hook = lock(&self.on_connects).clone();
            if let Some(hook) = hook {
                hook();
            }
        }
    }

    /// Call `f` with the vault while the session of the node lasts (for the service).
    pub(super) fn in_vault<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> Option<R> {
        self.with_vault(f)
    }
}

/// The question slot of one cloud agent: held while the broker asks about one of its
/// runs. It is given back on drop.
struct AgentSlot<'a> {
    shared: &'a Shared,
    agent_id: u64,
}

impl<'a> AgentSlot<'a> {
    /// The slot of `agent_id`, unless a run of the agent holds it.
    fn take(shared: &'a Shared, agent_id: u64) -> Option<Self> {
        // The lock ends before a slot exists: a slot that is not given must never be
        // made, since its drop would give back the slot of the run that holds it.
        let free = lock(&shared.asking).insert(agent_id);
        free.then(|| Self { shared, agent_id })
    }
}

impl Drop for AgentSlot<'_> {
    fn drop(&mut self) {
        lock(&self.shared.asking).remove(&self.agent_id);
    }
}

/// The host thread of a node.
pub(super) fn spawn(shared: Arc<Shared>) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("apassy-node-host".to_owned())
        .spawn(move || run(&shared))
}

fn run(shared: &Arc<Shared>) {
    let mut checked_at: Option<Instant> = None;
    while !shared.stop.load(Ordering::SeqCst) {
        let pending = shared
            .with_node(|node| node.wait_pending(&shared.team, WAIT))
            .unwrap_or_else(|| Ok(Vec::new()));
        // The wait also returns when the connect requests change.
        shared.poll_connects();
        match pending {
            Ok(runs) => {
                let mut started = false;
                for run in runs {
                    started |= begin(shared, run);
                }
                if !started && !shared.stop.load(Ordering::SeqCst) {
                    // Only runs in progress: the node gives them again at once.
                    thread::sleep(BUSY_PAUSE);
                }
            }
            Err(_) => thread::sleep(WAIT),
        }
        if checked_at.is_none_or(|at| at.elapsed() >= CHECK_INTERVAL) {
            checked_at = Some(Instant::now());
            check_sessions(shared);
            let _ = shared.refresh(&[]);
            reap(shared);
        }
    }
    let workers = std::mem::take(&mut *lock(&shared.workers));
    for worker in workers {
        let _ = worker.join();
    }
}

/// Start a worker for `run`, unless one runs for it or it waits for its retry. Returns
/// true when it started one.
fn begin(shared: &Arc<Shared>, run: PendingRun) -> bool {
    if lock(&shared.retry_at)
        .get(&run.run_id)
        .is_some_and(|at| Instant::now() < *at)
    {
        return false;
    }
    if !lock(&shared.in_flight).insert(run.run_id) {
        return false;
    }
    let worker_shared = Arc::clone(shared);
    let id = run.run_id;
    let spawned = thread::Builder::new()
        .name("apassy-node-run".to_owned())
        .spawn(move || {
            decide(&worker_shared, &run);
            lock(&worker_shared.in_flight).remove(&run.run_id);
        });
    match spawned {
        Ok(handle) => {
            lock(&shared.workers).push(handle);
            true
        }
        Err(_) => {
            lock(&shared.in_flight).remove(&id);
            false
        }
    }
}

/// Join the workers that ended, and forget old retry marks.
fn reap(shared: &Shared) {
    lock(&shared.retry_at).retain(|_, at| at.elapsed() < RETRY_FORGET);
    let mut workers = lock(&shared.workers);
    let (done, live): (Vec<_>, Vec<_>) = std::mem::take(&mut *workers)
        .into_iter()
        .partition(JoinHandle::is_finished);
    *workers = live;
    drop(workers);
    for worker in done {
        let _ = worker.join();
    }
}

/// What the host does with a run.
enum Outcome {
    Release {
        values: Vec<NodeSecret>,
        agent_id: u64,
        items: Vec<u64>,
        label: String,
        decided_by: String,
        /// When the broker started to decide (for the `cloud_run` row).
        asked_at: u64,
    },
    Deny {
        reason: String,
        /// The activity row, when the broker did not write one.
        record: Option<NewActivity>,
        items: Vec<u64>,
        /// The vault agent and when the broker started to decide, when the broker
        /// decided (for the `cloud_run` row).
        decided: Option<(u64, u64)>,
    },
    /// Another question of the agent waits: leave the run pending in the node and try
    /// it again after [`RETRY_PAUSE`].
    Retry,
}

fn deny(reason: impl Into<String>, record: Option<NewActivity>, items: Vec<u64>) -> Outcome {
    Outcome::Deny {
        reason: reason.into(),
        record,
        items,
        decided: None,
    }
}

/// Store the `cloud_run` row of a run that the broker decided, with its decision log row.
fn record_run(vault: &mut Vault, run: &PendingRun, agent_id: u64, asked_at: u64) {
    let decision_log_id = vault.newest_decision_id(agent_id, asked_at).ok().flatten();
    let _ = vault.record_cloud_run(&NewCloudRun {
        relay_run_id: run.run_id.0,
        decision_log_id,
        agent_id,
        at: run.created_at,
    });
}

/// The activity row of a run that the host refused before the broker saw it.
fn refused_row(run: &PendingRun, agent_id: Option<u64>, reason: &str) -> NewActivity {
    NewActivity {
        agent_id,
        agent_name: cut(&run.agent, 64).to_owned(),
        item_id: None,
        operation: "cloud run".to_owned(),
        decision: ActivityDecision::Deny,
        reason: format!("{reason} Run {} of the node.", run.run_id.0),
    }
}

fn decide(shared: &Shared, run: &PendingRun) {
    match outcome(shared, run) {
        Outcome::Retry => {
            // The worker ends and drops its in-flight mark; the next poll after the pause
            // starts a new one.
            lock(&shared.retry_at).insert(run.run_id, Instant::now() + RETRY_PAUSE);
        }
        Outcome::Release {
            values,
            agent_id,
            items,
            label,
            decided_by,
            asked_at,
        } => {
            lock(&shared.retry_at).remove(&run.run_id);
            let released = shared.with_node(|node| {
                node.release(&shared.team, run.run_id, values, Some(RELEASED_NOTE))
            });
            let (decision, reason, live) = match released {
                // The node stopped: the run and its key are gone.
                None => return,
                Some(Ok(state)) if state.status == RunStatus::Ready => {
                    let until = state
                        .session_expires_at
                        .map_or_else(|| "its end".to_owned(), format_utc);
                    (
                        ActivityDecision::Allow,
                        format!(
                            "{decided_by}. Cloud run {} of the node: the values went to the proxy of the node, for a session until {until}. Purpose: {}",
                            run.run_id.0,
                            cut(run.purpose.trim(), 300)
                        ),
                        Some(state.session_expires_at),
                    )
                }
                Some(Ok(state)) => (
                    ActivityDecision::Error,
                    format!(
                        "{decided_by}, but the node did not start the session of cloud run {} ({}).",
                        run.run_id.0,
                        state.code.as_deref().unwrap_or("not ready")
                    ),
                    None,
                ),
                Some(Err(error)) => (
                    ActivityDecision::Error,
                    format!(
                        "{decided_by}, but the node refused the release of cloud run {} ({}).",
                        run.run_id.0, error.code
                    ),
                    None,
                ),
            };
            shared.with_vault(|vault| {
                let _ = vault.record_activity_for_items(
                    &NewActivity {
                        agent_id: Some(agent_id),
                        agent_name: cut(&run.agent, 64).to_owned(),
                        item_id: items.first().copied(),
                        operation: label.clone(),
                        decision,
                        reason,
                    },
                    items.get(1..).unwrap_or_default(),
                );
                record_run(vault, run, agent_id, asked_at);
            });
            if let Some(expires_at) = live {
                lock(&shared.sessions).push(LiveSession {
                    run_id: run.run_id,
                    agent_id,
                    agent_name: cut(&run.agent, 64).to_owned(),
                    items,
                    label,
                    expires_at,
                });
            }
        }
        Outcome::Deny {
            reason,
            record,
            items,
            decided,
        } => {
            lock(&shared.retry_at).remove(&run.run_id);
            let _ = shared.with_node(|node| {
                node.deny(&shared.team, run.run_id, cut(&reason, MAX_REASON_BYTES))
            });
            if record.is_some() || decided.is_some() {
                shared.with_vault(|vault| {
                    if let Some(row) = record {
                        let _ = vault.record_activity_for_items(
                            &NewActivity {
                                item_id: items.first().copied(),
                                ..row
                            },
                            items.get(1..).unwrap_or_default(),
                        );
                    }
                    if let Some((agent_id, asked_at)) = decided {
                        record_run(vault, run, agent_id, asked_at);
                    }
                });
            }
        }
    }
}

fn outcome(shared: &Shared, run: &PendingRun) -> Outcome {
    // 1. The run in the vault. A refusal is boxed: an `Outcome` is large.
    let mapped = shared.with_vault(|vault| -> Result<(u64, Vec<u64>), Box<Outcome>> {
        let Ok(Some(agent_id)) = vault.cloud_agent_for_relay(run.agent_id.0) else {
            let reason = "This agent is not a cloud agent of the vault that is open now.";
            return Err(Box::new(deny(
                reason,
                Some(refused_row(run, None, reason)),
                Vec::new(),
            )));
        };
        let mut items = Vec::with_capacity(run.items.len());
        for item in &run.items {
            match vault.cloud_item_for_uid(&item.uid) {
                Ok(Some(id)) => items.push(id),
                _ => {
                    let reason = "An item of this run is not in the vault that is open now.";
                    return Err(Box::new(deny(
                        reason,
                        Some(refused_row(run, Some(agent_id), reason)),
                        items,
                    )));
                }
            }
        }
        Ok((agent_id, items))
    });
    let (agent_id, items) = match mapped {
        None => return deny("The vault is locked.", None, Vec::new()),
        Some(Err(outcome)) => return *outcome,
        Some(Ok(mapped)) => mapped,
    };
    if items.iter().collect::<BTreeSet<_>>().len() != items.len() {
        let reason = "This run names an item twice.";
        return deny(
            reason,
            Some(refused_row(run, Some(agent_id), reason)),
            items,
        );
    }

    // 2. The broker: the owner decides, about one run of the agent at a time.
    let Some(slot) = AgentSlot::take(shared, agent_id) else {
        return Outcome::Retry;
    };
    let asked_at = now();
    let context = CloudContext {
        relay_run: run.run_id.0,
        agent_cwd: run.cwd.clone(),
        stop: Arc::clone(&shared.stop),
    };
    let request = CloudRequest {
        items: &items,
        command: &run.command,
        purpose: &run.purpose,
        user_request: run.user_request.as_deref(),
    };
    let decision = evaluate_cloud(&shared.broker, agent_id, &request, &context);
    drop(slot);
    let approval = match decision {
        CloudDecision::Approved(approval) => approval,
        // A question of the agent that the host did not start (or one that is still
        // being settled) waits: this run is asked later, not denied.
        CloudDecision::Refused { code, .. } if code == QUESTION_WAITING => {
            return Outcome::Retry;
        }
        // The broker wrote the activity row.
        CloudDecision::Refused { reason, .. } => {
            return Outcome::Deny {
                reason,
                record: None,
                items,
                decided: Some((agent_id, asked_at)),
            };
        }
    };

    // 3. The values, in the order of the run, in the session and with the bindings of
    // the broker's second check.
    let read = shared.with_vault(|vault| {
        if vault.epoch() != approval.epoch || approval.bindings.len() != items.len() {
            return Err("The vault was locked after the approval.");
        }
        let mut values = Vec::with_capacity(items.len());
        for (item, binding) in items.iter().zip(&approval.bindings) {
            if binding.item_id != *item
                || vault.process_binding(*item).ok().flatten().as_ref() != Some(binding)
            {
                return Err("The credential changed after the approval.");
            }
            if !matches!(binding.delivery, EnvDelivery::Placeholder(_)) {
                return Err("A credential of this run is not in placeholder mode.");
            }
            let Ok(value) = vault.reveal(*item, &binding.field) else {
                return Err("A credential of this run has no value.");
            };
            let mut text = value.into_zeroizing();
            values.push(NodeSecret::new(std::mem::take(&mut *text)));
        }
        let text = format!("cloud run {}", run.command.join(" "));
        let label = vault.command_mask(&items).map_or_else(
            |_| "cloud run".to_owned(),
            |mask| mask.summary(&text, MAX_LABEL_BYTES),
        );
        Ok((values, label))
    });
    match read {
        Some(Ok((values, label))) => Outcome::Release {
            values,
            agent_id,
            items,
            label,
            decided_by: approval.decided_by,
            asked_at,
        },
        Some(Err(reason)) => deny(
            reason,
            Some(refused_row(run, Some(agent_id), reason)),
            items,
        ),
        None => deny("The vault was locked after the approval.", None, items),
    }
}

/// Counts of the proxied requests of one session (ADR 0011 §5).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ProxyCounts {
    pub(super) total: usize,
    pub(super) forwarded: usize,
    pub(super) refused: usize,
    pub(super) failed: usize,
    pub(super) hosts: BTreeSet<String>,
}

impl ProxyCounts {
    /// The counts of the `proxy_request` rows of the node's audit.
    pub(super) fn of(rows: &[super::backend::AuditRow]) -> Self {
        let mut counts = Self::default();
        for row in rows.iter().filter(|row| row.action == "proxy_request") {
            counts.total += 1;
            let detail: Value = serde_json::from_str(&row.detail).unwrap_or(Value::Null);
            match detail.get("outcome").and_then(Value::as_str) {
                Some("forwarded") => counts.forwarded += 1,
                Some("refused") => counts.refused += 1,
                Some("upstream_failed") => counts.failed += 1,
                _ => {}
            }
            if let Some(host) = detail.get("host").and_then(Value::as_str) {
                counts.hosts.insert(cut(host, 80).to_owned());
            }
        }
        counts
    }

    /// Store the end of the session of `run` and these counts in its `cloud_run` row.
    fn end_run(&self, vault: &mut Vault, run: NodeRunId, at: u64) {
        let wide = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let _ = vault.end_cloud_run(
            run.0,
            at,
            wide(self.forwarded),
            wide(self.refused),
            wide(self.failed),
        );
    }

    pub(super) fn text(&self) -> String {
        if self.total == 0 {
            return "No request went through the proxy of the node.".to_owned();
        }
        let mut text = format!(
            "{} requests through the proxy of the node: {} forwarded, {} refused, {} failed upstream.",
            self.total, self.forwarded, self.refused, self.failed
        );
        if !self.hosts.is_empty() {
            let hosts: Vec<&str> = self.hosts.iter().take(8).map(String::as_str).collect();
            text.push_str(&format!(" Hosts: {}.", hosts.join(", ")));
        }
        text
    }
}

/// Write the summary row of each session that ended, and forget it.
fn check_sessions(shared: &Shared) {
    let sessions = shared.live_sessions();
    if sessions.is_empty() {
        return;
    }
    let at = now();
    for session in sessions {
        let Some(state) = shared.with_node(|node| node.run_state(&shared.team, session.run_id))
        else {
            return;
        };
        let ended = match &state {
            Ok(state) => {
                state.status != RunStatus::Ready
                    || state.session_expires_at.is_some_and(|end| end <= at)
            }
            Err(_) => true,
        };
        if !ended {
            continue;
        }
        let rows = shared
            .with_node(|node| node.recent_audit(&shared.team, Some(session.run_id), MAX_RUN_AUDIT))
            .and_then(Result::ok)
            .unwrap_or_default();
        let counts = ProxyCounts::of(&rows);
        let why = match &state {
            Ok(state) => state.code.clone().unwrap_or_else(|| "expired".to_owned()),
            Err(error) => error.code.clone(),
        };
        let written = shared.with_vault(|vault| {
            counts.end_run(vault, session.run_id, at);
            vault.record_activity_for_items(
                &NewActivity {
                    agent_id: Some(session.agent_id),
                    agent_name: session.agent_name.clone(),
                    item_id: session.items.first().copied(),
                    operation: "cloud session end".to_owned(),
                    decision: ActivityDecision::Allow,
                    reason: format!(
                        "The session of cloud run {} ended ({why}). {}",
                        session.run_id.0,
                        counts.text()
                    ),
                },
                session.items.get(1..).unwrap_or_default(),
            )
        });
        // A locked vault takes no row now: the session ended with the lock anyway.
        let _ = written;
        lock(&shared.sessions).retain(|live| live.run_id != session.run_id);
    }
}

/// Write the summary rows of the sessions that are still in the list, at a stop: the
/// node ends them.
pub(super) fn end_all_sessions(shared: &Shared, why: &str) {
    let sessions = std::mem::take(&mut *lock(&shared.sessions));
    for session in sessions {
        let rows = shared
            .with_node(|node| node.recent_audit(&shared.team, Some(session.run_id), MAX_RUN_AUDIT))
            .and_then(Result::ok)
            .unwrap_or_default();
        let counts = ProxyCounts::of(&rows);
        shared.with_vault(|vault| {
            counts.end_run(vault, session.run_id, now());
            let _ = vault.record_activity_for_items(
                &NewActivity {
                    agent_id: Some(session.agent_id),
                    agent_name: session.agent_name.clone(),
                    item_id: session.items.first().copied(),
                    operation: "cloud session end".to_owned(),
                    decision: ActivityDecision::Allow,
                    reason: format!(
                        "The session of cloud run {} ended ({why}). {}",
                        session.run_id.0,
                        counts.text()
                    ),
                },
                session.items.get(1..).unwrap_or_default(),
            );
        });
    }
}
