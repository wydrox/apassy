//! The Mac's own node in the desktop app (ADR 0037, cloud slice, decision 1).
//!
//! The app binary (`crates/apassy-app`) passes the node backend in
//! (`RunOptions::node`); a build without it has no node. The lifecycle follows the
//! iPhone listener (`companion.rs`):
//!
//! - [`DesktopApp::sync_node`] compares what the vault wants with what runs, once a
//!   second: a start needs an unlocked vault with the public route on and an active
//!   cloud agent (`Node::wanted`); a running node goes on while the vault is unlocked
//!   with the route on (`Node::may_run`), and a new session of the same vault file (a
//!   passphrase change, a backup) is taken over (`Node::adopt`). It starts
//!   the node on a worker thread (Touch ID for the node key, the Tailscale command
//!   line), or stops it. The window calls it from `logic`, so it runs also while the
//!   window is minimized. A start that failed is not tried again until the vault session
//!   changes or the owner asks ([`DesktopApp::retry_node`]).
//! - [`DesktopApp::stop_node`] stops it at once: the node (every session ends), the
//!   Funnel route off, the host thread joined. The app calls it on lock, on quit, before
//!   an update restart, and before it leaves a vault for another one. After an open, a
//!   create, or a restore, the next comparison stops a node of the earlier vault.
//! - While the node runs, closing the window minimizes it instead of quitting
//!   ([`DesktopApp::keep_open_for_node`]): the cloud agents still reach the Mac. A click
//!   on the Dock icon or the Window menu shows it again. Quit Apassy (⌘Q) quits.
//!
//! Settings > Cloud agents calls the API of [`crate::node::Node`] through
//! [`DesktopApp::cloud_node`], off the UI thread, and then [`DesktopApp::node_changed`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;

use super::owner_check::{Task, TaskPoll};
use super::{BrokerState, DesktopApp};
use crate::node::backend::NodeBackend;
use crate::node::{Node, NodeOptions};

/// How often the window compares the node with the vault.
const SYNC_INTERVAL: Duration = Duration::from_secs(1);
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
    maintained_at: Option<Instant>,
}

impl NodeFlows {
    /// The node of the product, for `backend` (the embedded relay of the app crate).
    pub(crate) fn platform(backend: Option<Arc<dyn NodeBackend>>) -> Self {
        Self {
            node: backend.map(|backend| Arc::new(Node::new(NodeOptions::platform(backend)))),
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
    /// The node service, for Settings > Cloud agents. `None`: this build has no node.
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
    /// at the next frame, and try a failed start again.
    pub fn node_changed(&mut self) {
        self.node.synced_at = None;
        self.node.failed = None;
    }

    /// Try a start that failed again.
    pub fn retry_node(&mut self) {
        self.node_changed();
    }

    /// What the open vault wants of `node`: the session that wants a start (an active
    /// cloud agent), and the session in which a running node may go on (the route on;
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
        if self
            .node
            .synced_at
            .is_some_and(|at| at.elapsed() < SYNC_INTERVAL)
        {
            return;
        }
        self.node.synced_at = Some(Instant::now());
        ctx.request_repaint_after(SYNC_INTERVAL);
        // What runs decides, not what the window started: the node can stop by itself
        // (the route went off, the tailnet name changed), and "Add a cloud agent" starts
        // it from Settings.
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
        if self.node.running_for.is_none()
            || self
                .node
                .maintained_at
                .is_some_and(|at| at.elapsed() < MAINTAIN_INTERVAL)
        {
            return;
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
