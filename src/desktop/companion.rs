//! The iPhone companion in the desktop app (ADR 0020, contract companion-v1).
//!
//! The app owns the listener of `apassy::companion`. It runs only while the setting is on
//! and the vault is unlocked, in exactly one vault session:
//!
//! - [`DesktopApp::sync_companion`] compares what the vault wants (setting on, unlocked,
//!   the epoch and the port) with what runs. It starts, restarts, or stops the listener.
//!   The window calls it each frame, so an unlock, a Touch ID unlock, and a change of the
//!   setting all start the listener without a separate hook.
//! - [`DesktopApp::stop_companion`] stops it at once. The app calls it on lock, on quit,
//!   when the owner turns the setting off, on "Reset pairing", and wherever it ends
//!   waiting runs: a backup, a restore, another vault, and a passphrase change.
//!
//! Pairing is three steps in Settings > iPhone companion. The owner opens a window and the app
//! draws the QR code. The owner types the 6-digit code that only the iPhone shows. A
//! right code goes through the owner check sheet for `OwnerAction::PairCompanion`, and
//! the proof stores the device. The code is never shown on the Mac, and the link is never
//! put on the pasteboard.

use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui;
use qrcode::{Color, EcLevel, QrCode};
use zeroize::{Zeroize, Zeroizing};

use super::owner_check::{OwnerRequest, Task, TaskPoll};
use super::{BrokerState, DesktopApp};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::companion::pairing::{CodeError, PairingView};
use crate::companion::{
    CompanionHandle, CompanionOptions, OpenPairingError, PairingController, PairingInvite, hosts,
};

/// A QR code has a quiet zone of 4 modules on each side.
pub(crate) const QUIET_ZONE: usize = 4;

/// The listener, as the app sees it.
#[derive(Default)]
pub(crate) enum Listener {
    /// Not running: the setting is off, or the vault is locked.
    #[default]
    Off,
    Running {
        handle: CompanionHandle,
        /// The vault session that the listener serves.
        epoch: [u8; 32],
        mac_name: String,
    },
    /// The listener did not start. The app tries again only after the owner asks, or
    /// after the vault session changes.
    Failed {
        message: String,
        epoch: [u8; 32],
        port: u16,
    },
}

impl Listener {
    /// The vault session and the port that this state was made for.
    fn made_for(&self) -> Option<([u8; 32], u16)> {
        match self {
            Self::Off => None,
            Self::Running { handle, epoch, .. } => Some((*epoch, handle.port())),
            Self::Failed { epoch, port, .. } => Some((*epoch, *port)),
        }
    }
}

/// The modules of a QR code, dark or light, without the quiet zone. They carry the
/// pairing secret or the link code of "Add a device…", so they are erased on drop.
#[derive(Clone)]
pub(crate) struct QrModules {
    width: usize,
    dark: Zeroizing<Vec<bool>>,
}

impl QrModules {
    /// The modules of `text` with error correction level M.
    pub(crate) fn new(text: &str) -> Option<Self> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
        let width = code.width();
        let mut dark = Zeroizing::new(Vec::with_capacity(width * width));
        for y in 0..width {
            for x in 0..width {
                dark.push(code[(x, y)] == Color::Dark);
            }
        }
        Some(Self { width, dark })
    }

    /// Modules on one side, without the quiet zone.
    pub(crate) fn width(&self) -> usize {
        self.width
    }

    /// True when the module at column `x` and row `y` is dark. Outside the code, in the
    /// quiet zone, every module is light.
    pub(crate) fn is_dark(&self, x: usize, y: usize) -> bool {
        x < self.width && y < self.width && self.dark[y * self.width + x]
    }
}

/// A line under the pairing controls.
pub(crate) struct Notice {
    pub(crate) text: String,
    pub(crate) error: bool,
}

/// The state of Settings > iPhone companion.
#[derive(Default)]
pub struct CompanionFlows {
    pub(crate) listener: Listener,
    /// The QR code of the open pairing window. The end of the window is in the view of the
    /// controller.
    pub(crate) invite: Option<QrModules>,
    opening: Option<Task<Result<PairingInvite, OpenPairingError>>>,
    /// The code that the owner types. The app erases it after each try.
    pub(crate) code: String,
    pub(crate) notice: Option<Notice>,
    /// Options that only the tests set: a host for the link and peers on this Mac.
    #[cfg(test)]
    pub(crate) test_options: TestOptions,
    /// True while a pairing window was open at the last poll. A window that ends without
    /// an action of the owner gets a line of text.
    window_seen: bool,
}

/// Options that only the tests of the app set. The app itself never serves a peer on this
/// Mac, and it looks up the hosts of the link.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestOptions {
    pub(crate) link_hosts: Option<Vec<String>>,
    pub(crate) allow_local_peers: bool,
}

/// The time now, Unix seconds.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl CompanionFlows {
    /// True while a worker thread makes a pairing window.
    pub(crate) fn opening_window(&self) -> bool {
        self.opening.is_some()
    }

    /// The name of the Mac, while the listener runs.
    pub(crate) fn mac_name(&self) -> Option<&str> {
        match &self.listener {
            Listener::Running { mac_name, .. } => Some(mac_name),
            _ => None,
        }
    }

    fn say(&mut self, text: impl Into<String>, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
        });
    }
}

/// Text for the owner when the listener did not start.
fn start_failure(error: &std::io::Error, port: u16) -> String {
    let cause = match error.kind() {
        std::io::ErrorKind::AddrInUse => {
            format!("another program already uses port {port}")
        }
        std::io::ErrorKind::PermissionDenied => "the vault does not allow it now".to_owned(),
        _ => error.to_string(),
    };
    format!("The iPhone listener did not start: {cause}. Nothing listens on the network.")
}

impl DesktopApp {
    /// The pairing calls of the running listener.
    pub(crate) fn companion_controller(&self) -> Option<PairingController> {
        match &self.companion.listener {
            Listener::Running { handle, .. } => Some(handle.pairing().clone()),
            _ => None,
        }
    }

    /// Start, restart, or stop the listener so that it matches the vault: it runs only
    /// with the setting on, in an unlocked vault, for the epoch and the port that the
    /// vault has now. A listener that failed stays failed until the epoch or the port
    /// changes, or the owner asks again.
    pub(crate) fn sync_companion(&mut self) {
        let wanted = match self.owner_ui.session.companion_status() {
            Ok((setting, epoch)) if setting.enabled => Some((epoch, setting.port)),
            _ => None,
        };
        if let Some(made_for) = self.companion.listener.made_for()
            && wanted != Some(made_for)
        {
            self.stop_companion();
        }
        let Some((epoch, port)) = wanted else {
            return;
        };
        if matches!(self.companion.listener, Listener::Off) {
            self.start_companion(epoch, port);
        }
    }

    fn start_companion(&mut self, epoch: [u8; 32], port: u16) {
        let BrokerState::Running(broker) = &self.broker else {
            self.companion.listener = Listener::Failed {
                message: "The agent broker is not running, so the iPhone listener does not start. Nothing listens on the network.".to_owned(),
                epoch,
                port,
            };
            return;
        };
        let mac_name = hosts::computer_name().unwrap_or_else(|| "Mac".to_owned());
        let options = CompanionOptions::new(
            self.owner_ui.session.shared_vault(),
            std::sync::Arc::clone(broker.approvals()),
            self.owner_gate(),
            mac_name.clone(),
            env!("CARGO_PKG_VERSION"),
            broker.approval_timeout(),
        );
        #[cfg(test)]
        let options = {
            let mut options = options;
            options.link_hosts = self.companion.test_options.link_hosts.clone();
            options.allow_local_peers = self.companion.test_options.allow_local_peers;
            options
        };
        self.companion.listener = match crate::companion::start(options) {
            Ok(handle) => Listener::Running {
                handle,
                epoch,
                mac_name,
            },
            Err(error) => Listener::Failed {
                message: start_failure(&error, port),
                epoch,
                port,
            },
        };
    }

    /// Stop the listener now: close the pairing window, end every connection, and drop
    /// the TLS key. The typed code and the QR code go too. An owner check for a pairing
    /// closes, because nothing waits for it any more.
    pub(crate) fn stop_companion(&mut self) {
        if let Listener::Running { mut handle, .. } = std::mem::take(&mut self.companion.listener) {
            handle.stop();
        }
        let flows = &mut self.companion;
        flows.invite = None;
        flows.opening = None;
        flows.code.zeroize();
        flows.notice = None;
        flows.window_seen = false;
        self.close_pairing_check();
    }

    /// The owner turns the listener on or off in Settings.
    pub(crate) fn set_companion_on(&mut self, on: bool) {
        if let Err(error) = self.owner_ui.session.set_companion_enabled(on) {
            self.set_err(error.message);
            return;
        }
        if !on {
            self.stop_companion();
            self.set_note("The iPhone listener is off. Nothing listens on the network.");
            return;
        }
        self.sync_companion();
        match &self.companion.listener {
            Listener::Running { handle, .. } => {
                let message = format!(
                    "The iPhone listener is on, port {}. Pair an iPhone in Settings.",
                    handle.port()
                );
                self.set_ok(message);
            }
            Listener::Failed { message, .. } => {
                let message = message.clone();
                self.set_err(message);
            }
            Listener::Off => {}
        }
    }

    /// Try to start a listener that failed.
    pub(crate) fn retry_companion(&mut self) {
        self.stop_companion();
        self.sync_companion();
    }

    /// Open a pairing window. The lookup of the hosts runs on a worker thread.
    pub(crate) fn open_pairing(&mut self, ctx: &egui::Context) {
        let Some(controller) = self.companion_controller() else {
            return;
        };
        if self.companion.opening.is_some() {
            return;
        }
        self.companion.notice = None;
        self.companion.code.zeroize();
        self.companion.opening = Some(Task::spawn(Some(ctx.clone()), move || controller.open()));
    }

    /// Close the pairing window. It needs no owner check.
    pub(crate) fn cancel_pairing(&mut self) {
        if let Some(controller) = self.companion_controller() {
            controller.cancel();
        }
        let flows = &mut self.companion;
        flows.invite = None;
        flows.opening = None;
        flows.code.zeroize();
        flows.notice = None;
        flows.window_seen = false;
        self.close_pairing_check();
    }

    fn close_pairing_check(&mut self) {
        let pairing_check = self
            .owner
            .check
            .as_ref()
            .is_some_and(|dialog| matches!(dialog.request, OwnerRequest::PairCompanion { .. }));
        if pairing_check {
            self.close_owner_check(None);
        }
    }

    /// The owner typed a code and selected "Pair". A right code opens the owner check.
    pub(crate) fn submit_pairing_code(&mut self, ctx: &egui::Context) {
        let Some(controller) = self.companion_controller() else {
            return;
        };
        let mut typed = std::mem::take(&mut self.companion.code);
        let result = controller.submit_code(&typed);
        typed.zeroize();
        match result {
            Ok(OwnerAction::PairCompanion {
                device_id,
                device_name,
                request_key,
                approval_key,
            }) => {
                self.companion.notice = None;
                self.ask_owner(
                    OwnerRequest::PairCompanion {
                        device_id,
                        device_name,
                        request_key,
                        approval_key,
                    },
                    Some(ctx),
                );
            }
            Ok(_) => self.companion.say(
                "The pairing gave an unexpected action. Nothing was paired.",
                true,
            ),
            Err(error) => {
                if error == CodeError::Closed {
                    self.companion.invite = None;
                    self.companion.window_seen = false;
                }
                self.companion.say(error.message(), true);
            }
        }
    }

    /// Store the iPhone that the owner confirmed. `proof` is from the owner check for
    /// `OwnerAction::PairCompanion`.
    pub(crate) fn complete_pairing(&mut self, proof: OwnerProof) {
        let Some(controller) = self.companion_controller() else {
            self.set_err("The iPhone listener is not running. Nothing was paired.");
            return;
        };
        match controller.confirm(proof) {
            Ok(device) => {
                let flows = &mut self.companion;
                flows.invite = None;
                flows.code.zeroize();
                flows.notice = None;
                flows.window_seen = false;
                self.set_ok(format!(
                    "The iPhone \"{}\" is paired. It can approve runs with Face ID.",
                    device.name
                ));
            }
            Err(error) => self.set_err(error.message()),
        }
    }

    /// Remove one paired iPhone. It needs no owner check: it only takes authority away.
    pub(crate) fn remove_companion_device(&mut self, device_id: &str, name: &str) {
        match self.owner_ui.session.remove_companion_device(device_id) {
            Ok(true) => self.set_ok(format!(
                "The iPhone \"{name}\" is removed. It cannot reach this Mac any more."
            )),
            Ok(false) => self.set_note(format!("The iPhone \"{name}\" was already removed.")),
            Err(error) => self.set_err(error.message),
        }
    }

    /// Remove every paired iPhone and make a new certificate. The listener stops first,
    /// so no phone is served in between. It starts again with the new certificate.
    pub(crate) fn reset_companion(&mut self) {
        self.stop_companion();
        match self.owner_ui.session.reset_companion_pairing() {
            Ok(()) => {
                self.set_ok(
                    "Pairing is reset. Every iPhone is removed, and this Mac has a new certificate. Pair each iPhone again.",
                );
                self.sync_companion();
            }
            Err(error) => self.set_err(error.message),
        }
    }

    /// The window calls this each frame. It keeps the listener in step with the vault,
    /// takes the result of a pairing window that opens, and drops the QR code when the
    /// window ends or a phone used the link.
    pub(crate) fn poll_companion(&mut self, ctx: &egui::Context) {
        self.sync_companion();
        self.poll_opening(ctx);
        let Some(controller) = self.companion_controller() else {
            return;
        };
        let view = controller.view();
        let flows = &mut self.companion;
        match view {
            PairingView::Closed => {
                flows.invite = None;
                if flows.window_seen {
                    flows.window_seen = false;
                    if flows.notice.is_none() {
                        flows.say(
                            "The pairing window is closed. Select \"Pair an iPhone\" to make a new code.",
                            false,
                        );
                    }
                }
            }
            PairingView::Open { .. } => flows.window_seen = true,
            PairingView::Waiting { .. } => {
                // A phone used the link. It is used up, so the code goes.
                flows.invite = None;
                flows.window_seen = true;
            }
        }
        if view != PairingView::Closed {
            // A phone can send its request at any time. The window is not told.
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }

    fn poll_opening(&mut self, ctx: &egui::Context) {
        let Some(task) = &self.companion.opening else {
            return;
        };
        let result = match task.poll() {
            TaskPoll::Waiting => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
                return;
            }
            TaskPoll::Done(result) => result,
            TaskPoll::Lost => Err(OpenPairingError::Stopped),
        };
        self.companion.opening = None;
        match result {
            Ok(invite) => match QrModules::new(&invite.link) {
                Some(qr) => {
                    self.companion.invite = Some(qr);
                    self.companion.window_seen = true;
                }
                None => {
                    if let Some(controller) = self.companion_controller() {
                        controller.cancel();
                    }
                    self.companion.say(
                        "Apassy could not draw the QR code. Nothing was paired.",
                        true,
                    );
                }
            },
            Err(error) => self.companion.say(error.message(), true),
        }
    }
}
