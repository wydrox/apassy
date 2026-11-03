//! The Mac's own node in the desktop app (ADR 0037, cloud slice, decision 1).
//!
//! The app binary (`crates/apassy-app`) passes the node backend in
//! (`RunOptions::node`); a build without it has no node. The lifecycle follows the
//! iPhone listener (`companion.rs`):
//!
//! - [`DesktopApp::sync_node`] compares what the vault wants with what runs: in a frame
//!   at most once a second, at once after a new vault session, and with no frame every
//!   [`IDLE_SYNC_INTERVAL`] while the vault is unlocked. A start needs an unlocked vault
//!   with the public route (remote access) on (`Node::wanted`; remote agents connect by
//!   themselves, so none is needed before); a running node goes on while the vault is
//!   unlocked with the route on (`Node::may_run`), and a new session of the same vault
//!   file (a passphrase change, a backup) is taken over (`Node::adopt`). It starts the
//!   node on a worker thread (Touch ID for the node key, the Tailscale command line), or
//!   stops it. The window calls it from `logic`, so it runs also while the window is
//!   minimized. A start that failed is not tried again until the vault session changes
//!   or the owner asks ([`DesktopApp::retry_node`]).
//! - [`DesktopApp::stop_node`] stops it at once: the node (every session ends), the
//!   Funnel route off, the host thread joined. The app calls it on lock, on quit, before
//!   an update restart, and before it leaves a vault for another one. After an open, a
//!   create, or a restore, the next comparison stops a node of the earlier vault.
//! - While the node runs, closing the window minimizes it instead of quitting
//!   ([`DesktopApp::keep_open_for_node`]): the cloud agents still reach the Mac. A click
//!   on the Dock icon or the Window menu shows it again. Quit Apassy (⌘Q) quits.
//!
//! - At the start of the app, before any vault opens, a Funnel route that a crash left on
//!   for the node is turned off (`Node::clear_stale_route`, on a thread of its own).
//! - Connect requests of remote agents (plan "Bouncer section" decision 4): the node
//!   wakes the window when they change, and each frame the window gives each new
//!   request of the node to the questions lane
//!   (`QuestionsWorker::post_connect`, the iPhone card), and the end of each one that the
//!   node no longer has (`QuestionsWorker::end_connect`): allowed or denied on this Mac,
//!   expired, or withdrawn. An iPhone answer that the lane verified (Face ID for an
//!   Allow) decides the request on the node ([`answer_connect`]).
//!
//! The Bouncer pages call the API of [`crate::node::Node`] through the helpers here:
//! [`DesktopApp::pending_connects`], [`DesktopApp::ask_allow_connect`] (Touch ID),
//! [`DesktopApp::deny_connect`], [`DesktopApp::remote_access`],
//! [`DesktopApp::ask_remote_access_on`] (Touch ID), [`DesktopApp::remote_access_off`],
//! [`DesktopApp::remote_agents`], and [`DesktopApp::disconnect_remote_agent`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;

use super::owner_check::{OwnerRequest, Task, TaskPoll};
use super::{BrokerState, DesktopApp};
use crate::broker::SharedVault;
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::node::backend::{NodeBackend, PendingConnect};
use crate::node::{CloudAgentView, Node, NodeOptions, NodeStatus, connect_name};
use crate::questions::{
    ConnectAnswer, ConnectApplied, ConnectDecision, ConnectEnd, PendingConnectCard,
};

/// The frames of a window in use compare the node with the vault at most this often.
const SYNC_INTERVAL: Duration = Duration::from_secs(1);
/// With no other frame, an unlocked vault is compared again after this long. The node
/// changes only through the window (a start, a stop, the route check below, and
/// [`DesktopApp::node_changed`], which wakes the window), so this only catches a vault
/// change that nothing reported. It is not a poll that keeps the window busy.
pub(crate) const IDLE_SYNC_INTERVAL: Duration = Duration::from_secs(10);
/// How often a running node checks its route (tailnet name, Funnel handler).
const MAINTAIN_INTERVAL: Duration = Duration::from_secs(60);
/// The note when a close keeps the app open.
pub(crate) const KEPT_OPEN: &str =
    "Apassy stays open for your cloud agents: the window is in the Dock. Quit Apassy to stop them.";

/// A start of the node on a worker thread.
struct Starting {
    /// The vault session that it was made for.
    epoch: [u8; 32],
    /// The message of the node error when it fails.
    task: Task<Result<(), String>>,
}

/// The node of the window.
#[derive(Default)]
pub(crate) struct NodeFlows {
    /// `None`: this build has no node (tests, the demo).
    pub(crate) node: Option<Arc<Node>>,
    /// A start on its way, for the vault session it was made for.
    starting: Option<Starting>,
    /// A route check on its way.
    maintaining: Option<Task<bool>>,
    /// The vault session that the running node serves.
    pub(crate) running_for: Option<[u8; 32]>,
    /// A start that failed, for that vault session, and why.
    pub(crate) failed: Option<([u8; 32], String)>,
    synced_at: Option<Instant>,
    /// The vault session of the last comparison: a new one is compared at once.
    synced_epoch: Option<[u8; 32]>,
    maintained_at: Option<Instant>,
    /// The connect requests that the window gave the questions lane: id, and when each
    /// ends on the node.
    posted: BTreeMap<String, u64>,
    /// The questions lane has the handler of the iPhone answers to connect cards.
    connect_hooked: bool,
    /// The node wakes the window when its connect requests change.
    connects_wake: bool,
    /// Wakes the window for [`DesktopApp::node_changed`]. Set by the first comparison.
    repaint: Option<egui::Context>,
}

impl NodeFlows {
    /// The node of the product, for `backend` (the embedded relay of the app crate).
    pub(crate) fn platform(backend: Option<Arc<dyn NodeBackend>>) -> Self {
        let node = backend.map(|backend| Arc::new(Node::new(NodeOptions::platform(backend))));
        if let Some(node) = &node {
            // Before any vault opens: a start waits for it (the start lock).
            let node = Arc::clone(node);
            let _ = std::thread::Builder::new()
                .name("apassy-node-route".to_owned())
                .spawn(move || node.clear_stale_route());
        }
        Self {
            node,
            ..Self::default()
        }
    }

    /// A node service of the tests.
    #[cfg(test)]
    pub(crate) fn with_node(node: Arc<Node>) -> Self {
        Self {
            node: Some(node),
            ..Self::default()
        }
    }
}

impl DesktopApp {
    /// The node service, for Bouncer > Agents. `None`: this build has no node.
    pub fn cloud_node(&self) -> Option<Arc<Node>> {
        self.node.node.clone()
    }

    /// True while the node runs.
    pub(crate) fn node_running(&self) -> bool {
        self.node
            .node
            .as_ref()
            .is_some_and(|node| node.is_running())
    }

    /// The owner changed something of the cloud agents (the route, an agent): compare
    /// at the next frame, which this asks for, and try a failed start again.
    pub fn node_changed(&mut self) {
        self.node.synced_at = None;
        self.node.failed = None;
        if let Some(repaint) = &self.node.repaint {
            repaint.request_repaint();
        }
    }

    /// Try a start that failed again.
    pub fn retry_node(&mut self) {
        self.node_changed();
    }

    /// What the open vault wants of `node`: the session that wants a start (the route
    /// on), and the session in which a running node may go on (the route on;
    /// a node that serves an earlier session of the same file takes the new one).
    fn node_wanted(&self, node: &Node) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        self.owner_ui
            .session
            .with_vault(|vault| {
                let allowed = Node::may_run(vault);
                if allowed.is_some() && node.serves().is_some() && node.serves() != allowed {
                    node.adopt(vault);
                }
                (Node::wanted(vault), allowed)
            })
            .unwrap_or((None, None))
    }

    /// Start or stop the node so that it matches the vault. See the module text.
    pub(crate) fn sync_node(&mut self, ctx: &egui::Context) {
        let Some(node) = self.node.node.clone() else {
            return;
        };
        if self.node.repaint.is_none() {
            self.node.repaint = Some(ctx.clone());
        }
        if let Some(Starting { epoch, task }) = &self.node.starting {
            let epoch = *epoch;
            match task.poll() {
                TaskPoll::Waiting => {
                    ctx.request_repaint_after(Duration::from_millis(200));
                    return;
                }
                TaskPoll::Done(Ok(())) => self.node.running_for = Some(epoch),
                TaskPoll::Done(Err(message)) => self.node.failed = Some((epoch, message)),
                TaskPoll::Lost => {
                    self.node.failed = Some((epoch, "The node did not start.".to_owned()));
                }
            }
            self.node.starting = None;
        }
        self.poll_maintain(&node, ctx);
        // Each frame: the node wakes the window when its connect requests change
        // (`Node::set_on_connects_change`), and this reads memory only.
        self.sync_connects(&node, ctx);
        // A frame between two comparisons asks for no frame of its own: a new vault
        // session (an unlock, another vault) is compared at once, and the idle look below
        // catches a change that no frame reported.
        let epoch = self.owner_ui.session.epoch();
        if epoch == self.node.synced_epoch
            && self
                .node
                .synced_at
                .is_some_and(|at| at.elapsed() < SYNC_INTERVAL)
        {
            return;
        }
        self.node.synced_at = Some(Instant::now());
        self.node.synced_epoch = epoch;
        if epoch.is_some() {
            ctx.request_repaint_after(IDLE_SYNC_INTERVAL);
        }
        // What runs decides, not what the window started: the node can stop by itself
        // (the route went off, the tailnet name changed).
        let (wanted, allowed) = self.node_wanted(&node);
        let serves = node.serves();
        if serves.is_some() && serves != allowed {
            self.stop_node();
        } else if serves.is_some() {
            self.node.running_for = serves;
            return;
        } else {
            self.node.running_for = None;
        }
        let Some(epoch) = wanted else {
            return;
        };
        if self
            .node
            .failed
            .as_ref()
            .is_some_and(|(failed, _)| *failed == epoch)
        {
            return;
        }
        let BrokerState::Running(broker) = &self.broker else {
            self.node.failed = Some((
                epoch,
                "The agent broker is not running, so the node does not start.".to_owned(),
            ));
            return;
        };
        let context = broker.context();
        let vault = self.owner_ui.session.shared_vault();
        let starter = Arc::clone(&node);
        self.node.starting = Some(Starting {
            epoch,
            task: Task::spawn(Some(ctx.clone()), move || {
                starter
                    .start(&vault, context)
                    .map_err(|error| error.message)
            }),
        });
    }

    /// Check the route of a running node once a minute, on a worker thread.
    fn poll_maintain(&mut self, node: &Arc<Node>, ctx: &egui::Context) {
        if let Some(task) = &self.node.maintaining {
            match task.poll() {
                TaskPoll::Waiting => return,
                TaskPoll::Done(stopped) => {
                    if stopped {
                        // Started again at the next comparison, with the new origin.
                        self.node.running_for = None;
                        self.node.synced_at = None;
                    }
                }
                TaskPoll::Lost => {}
            }
            self.node.maintaining = None;
        }
        if self.node.running_for.is_none() {
            return;
        }
        if let Some(at) = self.node.maintained_at {
            let since = at.elapsed();
            if since < MAINTAIN_INTERVAL {
                // The window wakes for the next check, also while it is minimized.
                ctx.request_repaint_after(MAINTAIN_INTERVAL - since);
                return;
            }
        }
        self.node.maintained_at = Some(Instant::now());
        let node = Arc::clone(node);
        self.node.maintaining = Some(Task::spawn(Some(ctx.clone()), move || node.maintain()));
    }

    /// Stop the node now. See the module text. A start on its way gives up.
    pub(crate) fn stop_node(&mut self) {
        self.node.starting = None;
        self.node.running_for = None;
        self.node.failed = None;
        self.node.synced_at = None;
        self.node.synced_epoch = None;
        if let Some(node) = &self.node.node {
            node.stop();
        }
    }

    /// While the node runs, a close of the window minimizes it: the app keeps serving
    /// the cloud agents. eframe quits when no `CancelClose` comes in the frame of the
    /// request. Quit Apassy (⌘Q) does not ask to close the window, so it still quits.
    pub(crate) fn keep_open_for_node(&mut self, ctx: &egui::Context) {
        if !ctx.input(|input| input.viewport().close_requested()) || !self.node_running() {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        self.set_note(KEPT_OPEN);
    }
}

/// The answer of an iPhone to a connect card, after the questions lane checked it (an
/// Allow is signed with the Face ID answer key of the iPhone): decide the request on the
/// node. A request that the node no longer has, or that it cannot decide, is
/// `NotPending`: the lane then settles with the end that this Mac gives it.
pub(crate) fn answer_connect(
    node: &Node,
    vault: &SharedVault,
    answer: &ConnectAnswer,
) -> ConnectApplied {
    let decided = match answer.decision {
        ConnectDecision::Allow => node
            .allow_connect_on(vault, &answer.id, Some(&answer.device_name))
            .map(drop),
        ConnectDecision::Deny => node.deny_connect(&answer.id),
    };
    if decided.is_ok() {
        ConnectApplied::Applied
    } else {
        ConnectApplied::NotPending
    }
}

/// The longest text of a connect card field (contract relay-questions-v1 section 7.4).
const MAX_CARD_NAME_BYTES: usize = 64;

fn card_text(text: &str) -> String {
    let mut end = text.len().min(MAX_CARD_NAME_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].trim().to_owned()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl DesktopApp {
    /// Give the questions lane the new connect requests of the node and the end of each
    /// one that it no longer has. See the module text.
    fn sync_connects(&mut self, node: &Arc<Node>, ctx: &egui::Context) {
        if !self.node.connects_wake {
            let repaint = ctx.clone();
            node.set_on_connects_change(move || repaint.request_repaint());
            self.node.connects_wake = true;
        }
        let ends = node.take_connect_ends();
        let Some(questions) = self.owner.questions.as_ref() else {
            self.node.posted.clear();
            return;
        };
        if !self.node.connect_hooked {
            let answering = Arc::clone(node);
            let vault = self.owner_ui.session.shared_vault();
            questions
                .set_on_connect_answer(move |answer| answer_connect(&answering, &vault, answer));
            self.node.connect_hooked = true;
        }
        let pending = node.pending_connects();
        let mac_name = card_text(&crate::sync::device_name());
        for connect in &pending {
            if self.node.posted.contains_key(&connect.id) {
                continue;
            }
            // A request that ends within seconds, or of a form that the card does not
            // take, stays on this Mac (the lane says why in its view).
            let _ = questions.post_connect(PendingConnectCard {
                id: connect.id.clone(),
                client_name: card_text(&connect_name(connect)),
                mac_name: mac_name.clone(),
                code: connect.code.clone(),
                expires_at: connect.expires_at,
            });
            self.node
                .posted
                .insert(connect.id.clone(), connect.expires_at);
        }
        let mut ends: BTreeMap<String, ConnectEnd> = ends.into_iter().collect();
        let now = unix_now();
        let gone: Vec<(String, u64)> = self
            .node
            .posted
            .iter()
            .filter(|(id, _)| !pending.iter().any(|connect| &connect.id == *id))
            .map(|(id, at)| (id.clone(), *at))
            .collect();
        for (id, expires_at) in gone {
            let end = ends.remove(&id).unwrap_or(if expires_at <= now {
                ConnectEnd::Expired
            } else {
                ConnectEnd::Withdrawn
            });
            questions.end_connect(&id, end);
            self.node.posted.remove(&id);
        }
        // Decided on this Mac while the node still listed them: the lane takes the first
        // end of each, so the later "gone" end changes nothing.
        for (id, end) in ends {
            questions.end_connect(&id, end);
        }
    }

    /// The connect requests that wait for the owner, oldest first, for Decisions (memory
    /// only: it may be called each frame). Empty without a node.
    pub(crate) fn pending_connects(&self) -> Vec<PendingConnect> {
        self.node
            .node
            .as_ref()
            .map(|node| node.pending_connects())
            .unwrap_or_default()
    }

    /// "Allow" on a connect card: the owner check "Connect <name> to this Mac" (Touch
    /// ID), then [`Node::allow_connect`] for exactly this request and code.
    pub(crate) fn ask_allow_connect(
        &mut self,
        connect: &PendingConnect,
        ctx: Option<&egui::Context>,
    ) {
        self.ask_owner(
            OwnerRequest::AllowConnect {
                id: connect.id.clone(),
                client_name: connect_name(connect),
                code: connect.code.clone(),
            },
            ctx,
        );
    }

    /// "Deny" on a connect card: no owner check, it gives no authority.
    pub(crate) fn deny_connect(&mut self, id: &str) {
        let Some(node) = self.node.node.clone() else {
            return;
        };
        match node.deny_connect(id) {
            Ok(()) => self.set_ok("The connection is denied. Nothing was made."),
            Err(error) => self.set_err(error.message),
        }
    }

    /// After the owner check `AllowConnect`: connect the remote agent of the request.
    pub(crate) fn complete_allow_connect(
        &mut self,
        id: &str,
        client_name: &str,
        code: &str,
        proof: OwnerProof,
    ) {
        let action = OwnerAction::AllowConnect {
            id: id.to_owned(),
            client_name: client_name.to_owned(),
            code: code.to_owned(),
        };
        let Some(epoch) = self.owner_ui.session.epoch() else {
            self.set_err("The vault is locked. Nothing was connected.");
            return;
        };
        if let Err(refusal) = proof.check(&action, &epoch) {
            self.set_err(refusal.message());
            return;
        }
        drop(proof);
        let Some(node) = self.node.node.clone() else {
            self.set_err("This build of Apassy has no remote access.");
            return;
        };
        // Only the request that the owner saw, with its code.
        if !node
            .pending_connects()
            .iter()
            .any(|connect| connect.id == id && connect.code == code)
        {
            self.set_err("This connect request does not wait any more. Nothing was connected.");
            return;
        }
        match node.allow_connect(&self.owner_ui.session.shared_vault(), id) {
            Ok(agent) if agent.reconnected => self.set_ok(format!(
                "{} is connected to this Mac again. It keeps the credentials it had.",
                agent.name
            )),
            Ok(agent) => self.set_ok(format!(
                "{} is connected to this Mac. It sees no credential until you choose some in Agents.",
                agent.name
            )),
            Err(error) => self.set_err(error.message),
        }
    }

    /// The remote access block: the route, the address, and its problem. It runs the
    /// Tailscale command line: call it off the UI thread. `None` without a node.
    pub fn remote_access(&self) -> Option<NodeStatus> {
        let node = self.node.node.as_ref()?;
        Some(node.status(&self.owner_ui.session.shared_vault()))
    }

    /// The remote access switch on: the owner check, then the route on; the next
    /// comparison starts the node.
    pub(crate) fn ask_remote_access_on(&mut self, ctx: Option<&egui::Context>) {
        self.ask_owner(OwnerRequest::TurnOnRemoteAccess, ctx);
    }

    /// After the owner check `TurnOnRemoteAccess`.
    pub(crate) fn complete_remote_access_on(&mut self, proof: OwnerProof) {
        let Some(epoch) = self.owner_ui.session.epoch() else {
            self.set_err("The vault is locked.");
            return;
        };
        if let Err(refusal) = proof.check(&OwnerAction::TurnOnRemoteAccess, &epoch) {
            self.set_err(refusal.message());
            return;
        }
        drop(proof);
        let Some(node) = self.node.node.clone() else {
            self.set_err("This build of Apassy has no remote access.");
            return;
        };
        match node.set_route(&self.owner_ui.session.shared_vault(), true) {
            Ok(()) => {
                self.node_changed();
                self.set_ok("Remote access is on. Give a remote agent the MCP address.");
            }
            Err(error) => self.set_err(error.message),
        }
    }

    /// The remote access switch off: no owner check, it takes authority away. The node
    /// stops at once: every session ends and the Funnel route goes off.
    pub(crate) fn remote_access_off(&mut self) {
        let Some(node) = self.node.node.clone() else {
            return;
        };
        match node.set_route(&self.owner_ui.session.shared_vault(), false) {
            Ok(()) => {
                self.stop_node();
                self.set_ok("Remote access is off. No remote agent reaches this Mac.");
            }
            Err(error) => self.set_err(error.message),
        }
    }

    /// The remote agents of this Mac, for the Agents page. It asks the node: call it off
    /// the UI thread, or cache it.
    pub fn remote_agents(&self) -> Vec<CloudAgentView> {
        self.node
            .node
            .as_ref()
            .and_then(|node| node.agents(&self.owner_ui.session.shared_vault()).ok())
            .unwrap_or_default()
    }

    /// "Disconnect…" of a remote agent, after its sheet: the vault, the relay agent, its
    /// OAuth refresh family, and the open requests of its client. No owner check.
    pub(crate) fn disconnect_remote_agent(&mut self, agent_id: u64) {
        let Some(node) = self.node.node.clone() else {
            return;
        };
        match node.revoke_agent(&self.owner_ui.session.shared_vault(), agent_id) {
            Ok(()) => self.set_ok("The remote agent is disconnected. Its token stops working."),
            Err(error) => self.set_err(error.message),
        }
    }
}
