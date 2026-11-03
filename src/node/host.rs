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
//! `proxy_request` rows of the node's audit. Every few seconds the thread checks the
//! released runs for their end, makes the catalog mirror again, and sends revocations
//! that the node has not seen.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::backend::{
    CreatedAgent, NewCloudAgent, NodeAgentId, NodeError, NodeRunId, NodeSecret, NodeTeamId,
    PendingRun, RunStatus, RunningNode,
};
use super::catalog::{self, Checked};
use crate::broker::decide::BrokerContext;
use crate::broker::{CloudContext, CloudDecision, CloudRequest, SharedVault, evaluate_cloud};
use crate::vault::{ActivityDecision, EnvDelivery, NewActivity, Vault, format_utc};

/// The longest wait for pending runs, so a stop is seen soon.
const WAIT: Duration = Duration::from_millis(500);
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
    pub(super) broker: BrokerContext,
    /// The vault session that the node serves.
    pub(super) epoch: [u8; 32],
    pub(super) stop: Arc<AtomicBool>,
    in_flight: Mutex<HashSet<NodeRunId>>,
    sessions: Mutex<Vec<LiveSession>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    pub(super) catalog: Mutex<CatalogState>,
}

impl Shared {
    pub(super) fn new(
        node: Box<dyn RunningNode>,
        team: NodeTeamId,
        vault: SharedVault,
        broker: BrokerContext,
        epoch: [u8; 32],
    ) -> Self {
        Self {
            node: RwLock::new(Some(node)),
            team,
            vault,
            broker,
            epoch,
            stop: Arc::new(AtomicBool::new(false)),
            in_flight: Mutex::new(HashSet::new()),
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

    /// Call `f` with the vault while the session of the node lasts.
    fn with_vault<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> Option<R> {
        let mut guard = lock(&self.vault);
        guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == self.epoch)
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

    /// Make a cloud agent in the node and in the vault, for `items` (vault ids). The
    /// catalog state is held from the mirror to the save, so the periodic refresh does
    /// not archive the new items in between. A failed save revokes the node agent.
    /// Returns the vault agent and the node agent with its token.
    pub(super) fn add_agent(
        &self,
        name: &str,
        items: &[u64],
        days: u32,
    ) -> Result<(u64, CreatedAgent), NodeError> {
        let guard = self.node.read().unwrap_or_else(PoisonError::into_inner);
        let node: &dyn RunningNode = guard
            .as_deref()
            .ok_or_else(|| NodeError::new("node_stopped", "The node is not running."))?;
        let mut state = lock(&self.catalog);
        let mirror = self.refresh_with(node, &mut state, items)?;
        let mut uids = Vec::with_capacity(items.len());
        for item in items {
            let Some(uid) = mirror
                .by_uid
                .iter()
                .find(|(_, id)| *id == item)
                .map(|(uid, _)| uid.clone())
            else {
                let why = mirror
                    .skipped
                    .iter()
                    .find(|(id, _)| id == item)
                    .map_or("not available", |(_, why)| *why);
                return Err(NodeError::new(
                    "not_eligible",
                    format!("Item {item} cannot be offered to a cloud agent: {why}."),
                ));
            };
            uids.push(uid);
        }
        let created = node.create_agent(
            &self.team,
            &NewCloudAgent {
                name: name.trim().to_owned(),
                items: uids.clone(),
                lifetime_days: days,
            },
        )?;
        let saved = self.with_vault(|vault| {
            vault.add_cloud_agent(name, items, created.agent_id.0, created.expires_at)
        });
        match saved {
            Some(Ok(agent_id)) => {
                state.lists.insert(created.agent_id, uids);
                Ok((agent_id, created))
            }
            _ => {
                let _ = node.revoke_agent(&self.team, created.agent_id);
                let _ = self.refresh_with(node, &mut state, &[]);
                Err(NodeError::new(
                    "vault_error",
                    "The cloud agent cannot be saved in the vault. Nothing was made.",
                ))
            }
        }
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

/// Start a worker for `run`, unless one runs for it. Returns true when it started one.
fn begin(shared: &Arc<Shared>, run: PendingRun) -> bool {
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

/// Join the workers that ended.
fn reap(shared: &Shared) {
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
    },
    Deny {
        reason: String,
        /// The activity row, when the broker did not write one.
        record: Option<NewActivity>,
        items: Vec<u64>,
    },
}

fn deny(reason: impl Into<String>, record: Option<NewActivity>, items: Vec<u64>) -> Outcome {
    Outcome::Deny {
        reason: reason.into(),
        record,
        items,
    }
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
        Outcome::Release {
            values,
            agent_id,
            items,
            label,
            decided_by,
        } => {
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
        } => {
            let _ =
                shared.with_node(|node| node.deny(&shared.team, run.run_id, cut(&reason, MAX_REASON_BYTES)));
            if let Some(row) = record {
                shared.with_vault(|vault| {
                    let _ = vault.record_activity_for_items(
                        &NewActivity {
                            item_id: items.first().copied(),
                            ..row
                        },
                        items.get(1..).unwrap_or_default(),
                    );
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
        return deny(reason, Some(refused_row(run, Some(agent_id), reason)), items);
    }

    // 2. The broker: the owner decides.
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
    let approval = match evaluate_cloud(&shared.broker, agent_id, &request, &context) {
        CloudDecision::Approved(approval) => approval,
        // The broker wrote the activity row.
        CloudDecision::Refused { reason, .. } => return deny(reason, None, items),
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
