//! Owner checks, Touch ID unlock, and notifications in the desktop app (goal items A2,
//! A3, A4, N1 to N4).
//!
//! Each sensitive owner action in the UI makes an [`OwnerRequest`] and calls
//! [`DesktopApp::ask_owner`]. The app then shows the owner check. A worker thread runs
//! [`OwnerGate::authorize`], the one owner-authorization function. With the proof,
//! [`DesktopApp::complete_owner_request`] does the action. Every guarded vault call and
//! [`crate::broker::approvals::ApprovalQueue::approve`] takes the proof, so no UI path
//! can skip the check.
//!
//! Native helper calls block for up to 180 s, so they run on worker threads
//! ([`Task`]). The UI thread polls the results each frame.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use super::inbox::EventKey;
use super::notify::NotificationCenter;
use super::owner_store::{DeclarationForm, ENDED_BY_LOCK, ENDED_BY_QUIT, Ephemeral, FreshToken};
use super::unlock::{
    self, PASSPHRASE_CHANGED_NOTE, TouchIdUnlockError, UnlockMethod, UnlockSetting,
};
use super::{BrokerState, DesktopApp};
use crate::broker::approvals::{
    ApprovalQueue, CheckMethod, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, OwnerProof,
    PendingRun, touch_id_detail,
};
use crate::broker::profile::REPORTING_API_V0;
use crate::native::{Biometry, NativeHelper};
use crate::vault::{EnvDelivery, ExecMode, ExecRule, GrantPlace};

/// The result of a poll of a [`Task`].
pub(crate) enum TaskPoll<T> {
    Waiting,
    Done(T),
    /// The worker thread ended without a result.
    Lost,
}

/// Work on a worker thread. The UI thread polls the result.
pub(crate) struct Task<T> {
    result: Receiver<T>,
}

impl<T: Send + 'static> Task<T> {
    /// Run `work` on a new thread. `repaint` wakes the UI when the work ends.
    pub(crate) fn spawn(
        repaint: Option<egui::Context>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Self {
        let (sender, result) = mpsc::channel();
        let _ = std::thread::Builder::new()
            .name("apassy-owner-task".to_owned())
            .spawn(move || {
                let _ = sender.send(work());
                if let Some(ctx) = repaint {
                    ctx.request_repaint();
                }
            });
        Self { result }
    }

    pub(crate) fn poll(&self) -> TaskPoll<T> {
        match self.result.try_recv() {
            Ok(value) => TaskPoll::Done(value),
            Err(TryRecvError::Empty) => TaskPoll::Waiting,
            Err(TryRecvError::Disconnected) => TaskPoll::Lost,
        }
    }
}

/// The decision of a process grant, for the owner check dialog.
fn decides(mode: ExecMode) -> &'static str {
    match mode {
        ExecMode::Ask => "You approve each run.",
        ExecMode::Bouncer => "The bouncer decides.",
    }
}

/// An owner action that waits for the owner check. It has the parameters of the
/// action, so the app does exactly what the owner confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerRequest {
    Reveal {
        item_id: u64,
    },
    ApproveRun(PendingRun),
    /// Approve one run and add one approval to its pattern (ADR 0010).
    ApproveAndRemember(PendingRun),
    /// Apply a calibrated `task_match` level, in hundredths (ADR 0009 step 3).
    ApplyCalibration {
        level: u32,
    },
    /// Make a candidate model the active model of the bouncer (ADR 0010, goal item B9).
    PromoteModel {
        candidate_id: u64,
        version: String,
    },
    /// Return the bouncer to the model before one promotion (goal item B9).
    RollbackModel {
        activation_id: u64,
        from: String,
        to: String,
    },
    AllowOperation {
        agent_id: u64,
        item_id: u64,
        operation: String,
    },
    SetProcessAccess {
        agent_id: u64,
        item_id: u64,
        place: GrantPlace,
        mode: ExecMode,
    },
    /// Give process access to several credentials at once (ADR 0012).
    GrantMany {
        agent_id: u64,
        item_ids: Vec<u64>,
        place: GrantPlace,
        mode: ExecMode,
    },
    /// Let an agent see all credentials without values (ADR 0012).
    ShowAllCredentials {
        agent_id: u64,
        agent_name: String,
    },
    /// Give the access that an agent asked for (ADR 0012).
    GrantRequest {
        request_id: u64,
        agent_id: u64,
        item_id: u64,
        agent_name: String,
        item_name: String,
        place: GrantPlace,
        mode: ExecMode,
    },
    SaveRule {
        agent_id: u64,
        item_id: u64,
        rule: ExecRule,
    },
    SaveDeclaration {
        item_id: u64,
        form: DeclarationForm,
    },
    SaveVariable {
        item_id: u64,
        env_name: String,
        field: String,
        delivery: EnvDelivery,
    },
    SaveConnector {
        item_id: u64,
        base_url: String,
    },
    ConfirmReview {
        item_id: u64,
    },
    /// Bring an archived item back. Agents with a grant can use it again.
    Unarchive {
        item_id: u64,
        name: String,
    },
    RotateToken {
        agent_id: u64,
        agent_name: String,
    },
    SetTokenLifetime {
        days: String,
    },
}

impl OwnerRequest {
    /// The action that the proof must name.
    pub fn action(&self) -> OwnerAction {
        match self {
            Self::Reveal { item_id } => OwnerAction::Reveal { item_id: *item_id },
            Self::ApproveRun(run) => OwnerAction::ApproveRun(run.clone()),
            Self::ApproveAndRemember(run) => OwnerAction::ApproveAndRemember(run.clone()),
            Self::ApplyCalibration { level } => OwnerAction::ChangeCalibration { level: *level },
            Self::PromoteModel {
                candidate_id,
                version,
            } => OwnerAction::PromoteModel {
                candidate_id: *candidate_id,
                version: version.clone(),
            },
            Self::RollbackModel { activation_id, .. } => OwnerAction::RollbackModel {
                activation_id: *activation_id,
            },
            Self::AllowOperation {
                agent_id, item_id, ..
            }
            | Self::SetProcessAccess {
                agent_id, item_id, ..
            }
            | Self::GrantRequest {
                agent_id, item_id, ..
            } => OwnerAction::ChangeGrant {
                agent_id: *agent_id,
                item_id: *item_id,
            },
            Self::GrantMany {
                agent_id, item_ids, ..
            } => OwnerAction::ChangeGrants {
                agent_id: *agent_id,
                item_ids: item_ids.clone(),
            },
            Self::ShowAllCredentials { agent_id, .. } => OwnerAction::ShowAllCredentials {
                agent_id: *agent_id,
            },
            Self::SaveRule {
                agent_id, item_id, ..
            } => OwnerAction::ChangeRule {
                agent_id: *agent_id,
                item_id: *item_id,
            },
            Self::SaveDeclaration { item_id, .. }
            | Self::SaveVariable { item_id, .. }
            | Self::SaveConnector { item_id, .. }
            | Self::ConfirmReview { item_id }
            | Self::Unarchive { item_id, .. } => OwnerAction::ChangeItemRules { item_id: *item_id },
            Self::RotateToken { agent_id, .. } => OwnerAction::RotateToken {
                agent_id: *agent_id,
            },
            Self::SetTokenLifetime { .. } => OwnerAction::ChangeTokenLifetime,
        }
    }

    /// One sentence for the owner check dialog. It has no secret value.
    pub fn describe(&self) -> String {
        match self {
            Self::Reveal { .. } => "Show the secret values of this item for 30 seconds.".to_owned(),
            Self::ApproveRun(run) => format!(
                "Approve one run of agent \"{}\": {}",
                run.agent,
                run.command.join(" ")
            ),
            Self::ApproveAndRemember(run) => format!(
                "Approve one run of agent \"{}\" and remember its pattern{}: {}",
                run.agent,
                run.remember
                    .as_ref()
                    .map_or_else(String::new, |offer| format!(
                        " {} (approval {} of {})",
                        offer.pattern,
                        offer.approvals + 1,
                        offer.needed
                    )),
                run.command.join(" ")
            ),
            Self::ApplyCalibration { level } => format!(
                "Set the task_match level of the bouncer to {level}%. Apassy replays all past decisions again first."
            ),
            Self::PromoteModel { version, .. } => format!(
                "Make the candidate model {version} the active model of the bouncer. Apassy checks its shadow numbers again first."
            ),
            Self::RollbackModel { from, to, .. } => {
                format!("Roll back the bouncer model from {from} to {to}.")
            }
            Self::AllowOperation { operation, .. } => {
                format!("Let the agent use the operation {operation}.")
            }
            Self::SetProcessAccess { place, mode, .. } => format!(
                "Give the agent process access in {}. {}",
                place.describe(),
                decides(*mode)
            ),
            Self::GrantMany {
                item_ids,
                place,
                mode,
                ..
            } => format!(
                "Give the agent process access to {} credentials in {}. {}",
                item_ids.len(),
                place.describe(),
                decides(*mode)
            ),
            Self::ShowAllCredentials { agent_name, .. } => format!(
                "Let {agent_name} see all your credentials without values: names, usernames, hosts, and visible details. It can ask for access to each."
            ),
            Self::GrantRequest {
                agent_name,
                item_name,
                place,
                mode,
                ..
            } => format!(
                "Give {agent_name} process access to {item_name} in {}. {}",
                place.describe(),
                decides(*mode)
            ),
            Self::SaveRule { .. } => "Save the rule of this process grant.".to_owned(),
            Self::SaveDeclaration { form, .. } => format!(
                "Save the declaration: {}, {} risk, provider {}.",
                form.environment.as_str(),
                form.risk.as_str(),
                form.provider
                    .as_deref()
                    .and_then(crate::vault::providers::find)
                    .map_or("none", |provider| provider.label.as_str())
            ),
            Self::SaveVariable {
                env_name, delivery, ..
            } => match delivery {
                EnvDelivery::Value => format!(
                    "Bind the item to the environment variable {env_name}. Programs get the real value."
                ),
                EnvDelivery::Placeholder(hosts) => format!(
                    "Bind the item to the environment variable {env_name}. Programs get a placeholder, and Apassy sends the real value only to {}.",
                    hosts.join(", ")
                ),
            },
            Self::SaveConnector { base_url, .. } => {
                format!("Send the token of this item to {base_url}.")
            }
            Self::ConfirmReview { .. } => {
                "Confirm the agent settings of this restored item.".to_owned()
            }
            Self::Unarchive { name, .. } => format!(
                "Bring \"{name}\" back from the archive. Agents with a grant can use it again."
            ),
            Self::RotateToken { agent_name, .. } => {
                format!("Give {agent_name} a new token. The old token stops working.")
            }
            Self::SetTokenLifetime { days } => {
                format!("Set the token lifetime to {} days.", days.trim())
            }
        }
    }
}

/// Touch ID and keychain state from `ping`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NativeState {
    /// `None` until the helper answers, or when it cannot answer.
    pub biometry: Option<Biometry>,
    /// Why the helper did not answer.
    pub problem: Option<String>,
}

/// The owner check dialog.
pub(crate) struct CheckDialog {
    pub(crate) request: OwnerRequest,
    /// The passphrase field. The app erases it after each try.
    pub(crate) passphrase: String,
    pub(crate) running: Option<(CheckMethod, Task<Result<OwnerProof, OwnerAuthError>>)>,
    /// The result of the last try.
    pub(crate) message: Option<String>,
}

/// Touch ID unlock state for the open vault file.
#[derive(Default)]
pub(crate) struct UnlockState {
    /// The vault file of `setting`.
    pub(crate) path: Option<PathBuf>,
    pub(crate) setting: Option<UnlockSetting>,
    pub(crate) reading: Option<Task<UnlockSetting>>,
    pub(crate) unlocking: Option<Task<Result<Zeroizing<String>, TouchIdUnlockError>>>,
    pub(crate) changing: Option<Task<Result<String, String>>>,
    /// The passphrase for Touch ID setup (A2). The app erases it after each try.
    pub(crate) setup_passphrase: String,
}

/// All owner-check, unlock, and notification state of the app. One field in
/// [`DesktopApp`].
#[derive(Default)]
pub struct OwnerFlows {
    /// `None` in tests and when the app cannot find its own executable.
    pub(crate) helper: Option<NativeHelper>,
    pub(crate) native: NativeState,
    native_probe: Option<Task<NativeState>>,
    pub(crate) check: Option<CheckDialog>,
    pub(crate) unlock: UnlockState,
    pub(crate) notifications: Option<NotificationCenter>,
    /// Inbox events that the owner marked as seen. This is not an approval (N4).
    pub(crate) acknowledged: BTreeSet<EventKey>,
}

impl OwnerFlows {
    /// Text about Touch ID for the owner check. `None` when Touch ID can run.
    pub(crate) fn touch_id_note(&self) -> Option<String> {
        if self.helper.is_none() {
            return Some(
                "Touch ID is not available: this build has no Touch ID helper. Touch ID works only in Apassy.app. Type the passphrase to confirm.".to_owned(),
            );
        }
        match (&self.native.biometry, &self.native.problem) {
            (Some(Biometry::Available), _) => None,
            (Some(Biometry::Unavailable(code)), _) => Some(format!(
                "Touch ID is not available: {} Type the passphrase to confirm.",
                touch_id_detail(*code)
            )),
            (None, Some(problem)) => Some(format!(
                "Touch ID is not available: the helper did not answer ({problem}). Type the passphrase to confirm."
            )),
            (None, None) => Some("Apassy is checking Touch ID.".to_owned()),
        }
    }

    pub(crate) fn touch_id_ready(&self) -> bool {
        self.helper.is_some() && self.native.biometry == Some(Biometry::Available)
    }
}

impl DesktopApp {
    pub(crate) fn approvals(&self) -> Option<Arc<ApprovalQueue>> {
        match &self.broker {
            BrokerState::Running(handle) => Some(Arc::clone(handle.approvals())),
            _ => None,
        }
    }

    /// Start the helper probe and the notification center. The window calls this once.
    pub(crate) fn start_native(&mut self, ctx: &egui::Context) {
        let helper = NativeHelper::locate().ok();
        self.owner.helper = helper.clone();
        if let Some(helper) = helper.clone() {
            self.owner.native_probe = Some(Task::spawn(Some(ctx.clone()), move || {
                match helper.ping() {
                    Ok(info) => NativeState {
                        biometry: Some(info.biometry),
                        problem: None,
                    },
                    Err(err) => NativeState {
                        biometry: None,
                        problem: Some(err.to_string()),
                    },
                }
            }));
        }
        if let (Some(approvals), Some(helper)) = (self.approvals(), helper) {
            let repaint = ctx.clone();
            self.owner.notifications = Some(NotificationCenter::start(
                approvals,
                self.owner_ui.session.shared_vault(),
                helper,
                move || repaint.request_repaint(),
            ));
        }
    }

    /// The owner-authorization gate for this app.
    pub(crate) fn owner_gate(&self) -> OwnerGate {
        OwnerGate::new(
            self.owner_ui.session.shared_vault(),
            self.owner.helper.clone(),
        )
    }

    /// Ask the owner to confirm `request` (goal item A4). Nothing happens before the
    /// check passes. Touch ID starts at once when it is available.
    pub(crate) fn ask_owner(&mut self, request: OwnerRequest, ctx: Option<&egui::Context>) {
        self.close_owner_check(ctx);
        self.owner.check = Some(CheckDialog {
            request,
            passphrase: String::with_capacity(super::ui::PASSPHRASE_CAPACITY),
            running: None,
            message: None,
        });
        if self.owner.touch_id_ready() {
            self.start_owner_check(OwnerCheck::TouchId, ctx.cloned());
        }
    }

    /// Run the gate on a worker thread for the open dialog.
    pub(crate) fn start_owner_check(&mut self, check: OwnerCheck, ctx: Option<egui::Context>) {
        let gate = self.owner_gate();
        let Some(dialog) = self.owner.check.as_mut() else {
            return;
        };
        let action = dialog.request.action();
        let method = check.method();
        dialog.message = None;
        dialog.running = Some((
            method,
            Task::spawn(ctx, move || gate.authorize(action, check)),
        ));
    }

    /// Start the passphrase check with the text in the dialog. The field is empty after.
    pub(crate) fn start_passphrase_check(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.owner.check.as_mut() else {
            return;
        };
        let typed = Ephemeral::take(&mut dialog.passphrase).into_zeroizing();
        super::ui::forget_secret_field(ctx, super::ui::OWNER_CHECK_FIELD);
        self.start_owner_check(OwnerCheck::Passphrase(typed), Some(ctx.clone()));
    }

    /// Close the dialog. The passphrase field and its undo history are erased.
    pub(crate) fn close_owner_check(&mut self, ctx: Option<&egui::Context>) {
        if let Some(mut dialog) = self.owner.check.take() {
            dialog.passphrase.zeroize();
        }
        if let Some(ctx) = ctx {
            super::ui::forget_secret_field(ctx, super::ui::OWNER_CHECK_FIELD);
        }
    }

    /// Do `request` with `proof`. Each branch passes the proof to the guarded call.
    pub(crate) fn complete_owner_request(&mut self, request: OwnerRequest, proof: OwnerProof) {
        let session = &mut self.owner_ui.session;
        match request {
            OwnerRequest::Reveal { item_id } => match session.reveal(item_id, proof) {
                Ok(details) => self.set_ok(details.reveal_warning()),
                Err(err) => self.set_err(err.message),
            },
            OwnerRequest::ApproveRun(run) => {
                let result = match self.approvals() {
                    Some(approvals) => approvals.approve(proof).map_err(|r| r.message()),
                    None => Err("The broker is not running. Nothing was approved."),
                };
                match result {
                    Ok(()) => self.set_ok(format!(
                        "The run of {} is approved once. A new request needs a new approval.",
                        run.agent
                    )),
                    Err(message) => self.set_err(message),
                }
            }
            OwnerRequest::ApproveAndRemember(run) => {
                // The same queue path as "Approve once". The proof names this action.
                let result = match self.approvals() {
                    Some(approvals) => approvals.approve(proof).map_err(|r| r.message()),
                    None => Err("The broker is not running. Nothing was approved."),
                };
                match result {
                    Ok(()) => self.set_ok(format!(
                        "The run of {} is approved. Its pattern has one more approval.",
                        run.agent
                    )),
                    Err(message) => self.set_err(message),
                }
            }
            OwnerRequest::ApplyCalibration { level } => {
                super::learning_ui::apply_calibration(self, level, proof);
            }
            OwnerRequest::PromoteModel { candidate_id, .. } => {
                super::learning_ui::promote_model(self, candidate_id, proof);
            }
            OwnerRequest::RollbackModel { activation_id, .. } => {
                super::learning_ui::roll_back_model(self, activation_id, proof);
            }
            OwnerRequest::AllowOperation {
                agent_id,
                item_id,
                operation,
            } => {
                let result = session.allow_operation(agent_id, item_id, &operation, proof);
                let _ = self.apply(result, &format!("The agent can now use {operation}."));
            }
            OwnerRequest::SetProcessAccess {
                agent_id,
                item_id,
                place,
                mode,
            } => {
                let result = session.set_exec_grant(agent_id, item_id, &place, mode, proof);
                let message = match mode {
                    ExecMode::Ask => "Process access is saved. You approve each run.",
                    ExecMode::Bouncer => {
                        "Process access is saved. The bouncer decides. A risky run waits for you."
                    }
                };
                let _ = self.apply(result, message);
            }
            OwnerRequest::GrantMany {
                agent_id,
                item_ids,
                place,
                mode,
            } => {
                let count = item_ids.len();
                let result = session.set_exec_grants(agent_id, &item_ids, &place, mode, proof);
                let _ = self.apply(
                    result,
                    &format!("Process access to {count} credentials is saved."),
                );
            }
            OwnerRequest::ShowAllCredentials { agent_id, .. } => {
                let result = session.set_agent_sees_all(agent_id, true, Some(proof));
                let _ = self.apply(
                    result,
                    "The agent sees all credentials without values. It can ask for access.",
                );
            }
            OwnerRequest::GrantRequest {
                request_id,
                item_name,
                place,
                mode,
                ..
            } => {
                let result = session.grant_access_request(request_id, &place, mode, proof);
                let _ = self.apply(result, &format!("Access to {item_name} is given."));
            }
            OwnerRequest::SaveRule {
                agent_id,
                item_id,
                rule,
            } => {
                let result = session.set_exec_rule(agent_id, item_id, rule, proof);
                let _ = self.apply(result, "The rule is saved.");
            }
            OwnerRequest::SaveDeclaration { item_id, form } => {
                let result = session.set_declaration(item_id, &form, proof);
                if self.apply(result, "The declaration is saved.").is_some() {
                    self.owner_ui.declaration_form.stored = true;
                }
            }
            OwnerRequest::SaveVariable {
                item_id,
                env_name,
                field,
                delivery,
            } => {
                let result = session.set_env_binding(item_id, &env_name, &field, &delivery, proof);
                let _ = self.apply(result, &format!("The item is bound to {env_name}."));
            }
            OwnerRequest::SaveConnector { item_id, base_url } => {
                let result = session.set_connector(item_id, REPORTING_API_V0.id, &base_url, proof);
                let _ = self.apply(result, "The connector is saved.");
            }
            OwnerRequest::Unarchive { item_id, name } => {
                let result = session.unarchive(item_id, proof);
                let _ = self.apply(
                    result,
                    &format!(
                        "{name} is back from the archive. Agents with a grant can use it again."
                    ),
                );
            }
            OwnerRequest::ConfirmReview { item_id } => {
                let result = session.confirm_review(item_id, proof);
                let _ = self.apply(
                    result,
                    "The agent settings are confirmed. Agents with a grant can use the item again.",
                );
            }
            OwnerRequest::RotateToken {
                agent_id,
                agent_name,
            } => match session.rotate_agent_token(agent_id, proof) {
                Ok(token) => {
                    self.owner_ui.fresh_token = Some(FreshToken {
                        agent_name: agent_name.clone(),
                        token,
                        rotated: true,
                    });
                    self.set_ok(format!(
                        "{agent_name} has a new token. Copy it now. The old token does not work."
                    ));
                }
                Err(err) => self.set_err(err.message),
            },
            OwnerRequest::SetTokenLifetime { days } => {
                match session.set_token_lifetime_days(&days, proof) {
                    Ok(days) => {
                        self.owner_ui.token_lifetime_input.clear();
                        self.set_ok(format!("Tokens now work for {days} days after issue."));
                    }
                    Err(err) => self.set_err(err.message),
                }
            }
        }
    }

    /// Run the owner check on this thread and complete the request. Tests use this in
    /// place of the dialog.
    #[cfg(test)]
    pub(crate) fn confirm_owner_now(&mut self, check: OwnerCheck) -> Result<(), OwnerAuthError> {
        let dialog = self.owner.check.take().expect("an owner check is open");
        let proof = self
            .owner_gate()
            .authorize(dialog.request.action(), check)?;
        self.complete_owner_request(dialog.request, proof);
        Ok(())
    }

    /// Poll the worker threads. The UI calls this at the start of each frame.
    pub(crate) fn poll_owner_flows(&mut self, ctx: &egui::Context) {
        if let Some(probe) = &self.owner.native_probe
            && let TaskPoll::Done(state) = probe.poll()
        {
            self.owner.native = state;
            self.owner.native_probe = None;
        }
        self.poll_owner_check();
        self.poll_unlock(ctx);
        self.owner_ui.session.expire_reveals();
        if let Some(left) = self.owner_ui.session.next_reveal_expiry() {
            ctx.request_repaint_after(left);
        }
        if self
            .owner
            .check
            .as_ref()
            .is_some_and(|d| d.running.is_some())
            || self.owner.unlock.reading.is_some()
            || self.owner.unlock.unlocking.is_some()
            || self.owner.unlock.changing.is_some()
        {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }

    fn poll_owner_check(&mut self) {
        let Some(dialog) = self.owner.check.as_mut() else {
            return;
        };
        let Some((_, task)) = &dialog.running else {
            return;
        };
        let result = match task.poll() {
            TaskPoll::Waiting => return,
            TaskPoll::Done(result) => result,
            TaskPoll::Lost => Err(OwnerAuthError::Other(
                "the check stopped without a result".to_owned(),
            )),
        };
        dialog.running = None;
        match result {
            Ok(proof) => {
                let Some(dialog) = self.owner.check.take() else {
                    return;
                };
                self.complete_owner_request(dialog.request, proof);
            }
            Err(err) if err.passphrase_fallback() || err == OwnerAuthError::WrongPassphrase => {
                dialog.message = Some(err.message());
            }
            Err(err) => {
                self.owner.check = None;
                self.set_err(err.message());
            }
        }
    }

    // ---- Unlock with Touch ID (goal items A2, A3). ----

    /// Read the unlock setting of the open vault file again, without a prompt.
    pub(crate) fn refresh_unlock_setting(&mut self, ctx: Option<&egui::Context>) {
        let path = self.owner_ui.session.vault_path();
        let unlock = &mut self.owner.unlock;
        unlock.path.clone_from(&path);
        unlock.setting = None;
        unlock.reading = match (self.owner.helper.clone(), path) {
            (Some(helper), Some(path)) => Some(Task::spawn(ctx.cloned(), move || {
                unlock::read_setting(&helper, &path)
            })),
            (None, Some(_)) => {
                unlock.setting = Some(UnlockSetting {
                    method: UnlockMethod::Passphrase,
                    note: Some(unlock::HELPER_MISSING_NOTE.to_owned()),
                    can_set_up: false,
                });
                None
            }
            (_, None) => None,
        };
    }

    /// Start Touch ID unlock. The key comes back to the UI thread, which unlocks.
    pub(crate) fn start_touch_id_unlock(&mut self, ctx: &egui::Context) {
        let (Some(helper), Some(path)) = (
            self.owner.helper.clone(),
            self.owner_ui.session.vault_path(),
        ) else {
            self.set_err(unlock::HELPER_MISSING_NOTE);
            return;
        };
        self.owner.unlock.unlocking = Some(Task::spawn(Some(ctx.clone()), move || {
            unlock::read_unlock_key(&helper, &path)
        }));
    }

    /// Turn on Touch ID unlock with the passphrase in the setup field (goal item A2).
    pub(crate) fn start_touch_id_setup(&mut self, ctx: &egui::Context) {
        let typed = Ephemeral::take(&mut self.owner.unlock.setup_passphrase).into_zeroizing();
        super::ui::forget_secret_field(ctx, super::ui::TOUCH_ID_SETUP_FIELD);
        let Some(helper) = self.owner.helper.clone() else {
            self.set_err(unlock::HELPER_MISSING_NOTE);
            return;
        };
        let vault = self.owner_ui.session.shared_vault();
        self.owner.unlock.changing = Some(Task::spawn(Some(ctx.clone()), move || {
            unlock::turn_on(&helper, &vault, typed)
                .map(|()| "Touch ID unlock is on. Touch ID can unlock this vault file now. The passphrase still works.".to_owned())
                .map_err(|err| err.message())
        }));
    }

    /// Turn off Touch ID unlock. The keychain item is deleted (goal item A3).
    pub(crate) fn start_touch_id_off(&mut self, ctx: Option<&egui::Context>, note: &'static str) {
        let (Some(helper), Some(path)) = (
            self.owner.helper.clone(),
            self.owner_ui.session.vault_path(),
        ) else {
            return;
        };
        self.owner.unlock.changing = Some(Task::spawn(ctx.cloned(), move || {
            unlock::turn_off(&helper, &path)
                .map(|_| note.to_owned())
                .map_err(|err| format!("Apassy could not remove the Touch ID unlock key: {err}"))
        }));
    }

    /// After a passphrase change, the stored key is old. Remove it (goal item A3).
    pub(crate) fn after_passphrase_change(&mut self, ctx: &egui::Context) {
        let touch_id_on = self
            .owner
            .unlock
            .setting
            .as_ref()
            .is_some_and(|setting| setting.method == UnlockMethod::TouchId);
        if touch_id_on {
            self.start_touch_id_off(Some(ctx), PASSPHRASE_CHANGED_NOTE);
        }
    }

    fn poll_unlock(&mut self, ctx: &egui::Context) {
        if let Some(task) = &self.owner.unlock.reading {
            match task.poll() {
                TaskPoll::Waiting => {}
                TaskPoll::Done(setting) => {
                    self.owner.unlock.setting = Some(setting);
                    self.owner.unlock.reading = None;
                }
                TaskPoll::Lost => self.owner.unlock.reading = None,
            }
        }
        if let Some(task) = &self.owner.unlock.changing {
            let result = match task.poll() {
                TaskPoll::Waiting => None,
                TaskPoll::Done(result) => Some(result),
                TaskPoll::Lost => Some(Err(
                    "The Touch ID change stopped without a result.".to_owned()
                )),
            };
            if let Some(result) = result {
                self.owner.unlock.changing = None;
                match result {
                    Ok(message) => self.set_ok(message),
                    Err(message) => self.set_err(message),
                }
                self.refresh_unlock_setting(Some(ctx));
            }
        }
        if let Some(task) = &self.owner.unlock.unlocking {
            let result = match task.poll() {
                TaskPoll::Waiting => return,
                TaskPoll::Done(result) => result,
                TaskPoll::Lost => Err(TouchIdUnlockError::Failed(
                    "the unlock stopped without a result".to_owned(),
                )),
            };
            self.owner.unlock.unlocking = None;
            self.finish_touch_id_unlock(result, ctx);
        }
    }

    /// Unlock with a key from Touch ID. A key that does not open the vault is removed.
    pub(crate) fn finish_touch_id_unlock(
        &mut self,
        result: Result<Zeroizing<String>, TouchIdUnlockError>,
        ctx: &egui::Context,
    ) {
        let key = match result {
            Ok(key) => key,
            Err(err) => {
                if matches!(
                    err,
                    TouchIdUnlockError::BiometryChanged
                        | TouchIdUnlockError::NotSetUp
                        | TouchIdUnlockError::StaleKey
                ) {
                    self.refresh_unlock_setting(Some(ctx));
                }
                self.set_err(err.message());
                return;
            }
        };
        let result = self.owner_ui.session.unlock(&key);
        drop(key);
        match result {
            Ok(()) => self.set_ok("The vault is unlocked with Touch ID."),
            Err(err) if err.code == "wrong_key" => {
                if let (Some(helper), Some(path)) = (
                    self.owner.helper.clone(),
                    self.owner_ui.session.vault_path(),
                ) {
                    let err = unlock::forget_stale_key(&helper, &path);
                    self.set_err(err.message());
                }
                self.refresh_unlock_setting(Some(ctx));
            }
            Err(err) => self.set_err(err.message),
        }
    }

    // ---- Lock and quit (goal items V3, N3). ----

    /// Lock the vault. Waiting runs end and stay in the inbox. Typed secrets and their
    /// undo history are erased (key-memory review F1, F3).
    pub(crate) fn lock_vault(&mut self, ctx: Option<&egui::Context>) {
        let approvals = self.approvals();
        let result = self
            .owner_ui
            .session
            .lock_ending_runs(approvals.as_deref(), ENDED_BY_LOCK);
        if self
            .apply(result, "The vault is locked. Item details are hidden.")
            .is_some()
        {
            self.pending_delete = false;
        }
        self.erase_typed_secrets(ctx);
    }

    /// Erase every typed passphrase and secret, and the undo history of the fields.
    pub(crate) fn erase_typed_secrets(&mut self, ctx: Option<&egui::Context>) {
        let ui_state = &mut self.owner_ui;
        for field in [
            &mut ui_state.passphrase,
            &mut ui_state.passphrase_confirm,
            &mut ui_state.passphrase_current,
            &mut ui_state.passphrase_new,
            &mut ui_state.passphrase_repeat,
            &mut self.owner.unlock.setup_passphrase,
        ] {
            field.zeroize();
        }
        ui_state.add_secrets.clear();
        ui_state.edit_secrets.clear();
        self.close_owner_check(ctx);
        if let Some(ctx) = ctx {
            super::ui::forget_all_secret_fields(ctx);
        }
    }

    /// Quit: record and end waiting runs, lock, and stop the notification threads.
    pub(crate) fn shut_down(&mut self) {
        let approvals = self.approvals();
        let _ = self
            .owner_ui
            .session
            .lock_ending_runs(approvals.as_deref(), ENDED_BY_QUIT);
        self.erase_typed_secrets(None);
        if let Some(mut center) = self.owner.notifications.take() {
            center.stop();
        }
        // A local fine-tune stops with the app (goal item B9).
        self.learning.stop_training();
    }
}
