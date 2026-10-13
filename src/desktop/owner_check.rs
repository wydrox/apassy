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

use super::clipboard::CodeClipboard;
use super::inbox::EventKey;
use super::notify::NotificationCenter;
use super::owner_store::{DeclarationForm, ENDED_BY_LOCK, ENDED_BY_QUIT, Ephemeral, FreshToken};
use super::unlock::{
    self, PASSPHRASE_CHANGED_NOTE, TouchIdUnlockError, UnlockMethod, UnlockSetting,
};
use super::{BrokerState, DesktopApp};
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::{
    ApprovalQueue, CheckMethod, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, OwnerProof,
    PendingRun, action_words, touch_id_detail,
};
use crate::broker::profile::REPORTING_API_V0;
use crate::broker::project::Project;
use crate::native::{AuthCancel, Biometry, CancelOnDrop, NativeHelper};
use crate::questions::{Choice, RemoteEnvironment};
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

/// Text from a page or another program for the dialog and the vault: no control
/// character and no bidirectional format character (they could hide the site), trimmed,
/// at most 64 characters.
pub(crate) fn page_text(text: &str) -> String {
    let clean: String = text
        .chars()
        .filter(|c| !crate::browser::wire::hides_text(*c))
        .collect();
    dialog_cut(clean.trim())
}

/// The credentials of a question for the dialog: their names, or else the variables.
fn question_items(run: &PendingRun) -> String {
    let names: Vec<String> = run
        .question
        .items
        .iter()
        .map(|item| format!("\"{}\"", page_text(&item.name)))
        .collect();
    if names.is_empty() {
        run.env_names.join(", ")
    } else {
        names.join(", ")
    }
}

/// At most 64 characters of a username from the browser, for the dialog.
fn dialog_cut(text: &str) -> String {
    let mut cut: String = text.chars().take(64).collect();
    if cut.len() < text.len() {
        cut.push('…');
    }
    cut
}

/// The decision of a process grant, for the owner check dialog.
/// What a process grant does since ADR 0025: it adds the item to the list of an agent
/// with "Only these items", and it approves no run. Its mode has no effect.
const GRANT_EFFECT: &str = "It adds the credential to the list of an agent with \"Only these items\". It approves no run: the bouncer decides each use.";

/// Whether `field` is a custom detail with the label of a one-time password. The value
/// can also show a setup key: [`DesktopApp::ask_owner`] reads it before the dialog.
fn labelled_setup_key(field: &str) -> bool {
    super::owner_store::detail_label(field).is_some_and(|label| crate::otp::is_otp_label(&label))
}

/// The action that binds one variable. It names the exact field and the variable.
fn bind_action(
    item_id: u64,
    env_name: &str,
    field: &str,
    delivery: &EnvDelivery,
    setup_key: bool,
) -> OwnerAction {
    OwnerAction::BindVariable {
        item_id,
        field: field.to_owned(),
        env_name: env_name.trim().to_owned(),
        delivery: delivery.clone(),
        setup_key,
    }
}

/// The dialog text that binds one variable, or saves the automatic command settings
/// (an empty name, or the name Apassy derives from the item ID). It names the field by
/// its label and never shows a value.
fn describe_variable(
    item_id: u64,
    env_name: &str,
    field: &str,
    delivery: &EnvDelivery,
    setup_key: bool,
) -> String {
    let label = page_text(&super::owner_store::field_label(field));
    let automatic =
        env_name.trim().is_empty() || env_name.trim() == format!("APASSY_ITEM_{item_id}");
    let bind = match (automatic, setup_key) {
        (true, false) => {
            format!("Save automatic command settings with the {label} field of this item.")
        }
        (true, true) => format!(
            "Save automatic command settings with the one-time password setup key \"{label}\" of this item."
        ),
        (false, false) => format!(
            "Bind the field \"{label}\" of this item to the environment variable {env_name}."
        ),
        (false, true) => format!(
            "Bind the one-time password setup key \"{label}\" of this item to the environment variable {env_name}."
        ),
    };
    match (delivery, setup_key) {
        (EnvDelivery::Value, false) => format!("{bind} Programs get the real value."),
        (EnvDelivery::Value, true) => format!(
            "{bind} Programs get the setup key, not a password. They can make one-time codes for this account at any time."
        ),
        (EnvDelivery::Placeholder(hosts), false) => format!(
            "{bind} Programs get a placeholder, and Apassy sends the real value only to {}.",
            hosts.join(", ")
        ),
        (EnvDelivery::Placeholder(hosts), true) => format!(
            "{bind} Programs get a placeholder, and Apassy sends the real setup key only to {}. These hosts can make one-time codes for this account at any time.",
            hosts.join(", ")
        ),
    }
}

/// One variable of [`OwnerRequest::BindVariables`]. `field` is the main secret field of
/// the item. The dialog shows the item name and the variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableBinding {
    pub item_id: u64,
    pub item_name: String,
    pub env_name: String,
    pub field: String,
}

/// One passkey that an assertion can use, without its key. The names come from the
/// vault (the page gave them when the passkey was made).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAccount {
    pub item_id: u64,
    pub item_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub credential_id: Vec<u8>,
}

/// The `chosen` value of a passkey request with several accounts that the owner has not
/// chosen from yet. It is no index of the list: the request has no account, no action
/// that a proof can name, and no check starts.
pub(crate) const NO_ACCOUNT: usize = usize::MAX;

/// The part of a passkey request that every proof for it names. `origin` is the origin
/// in the client data that the app checked and hashed; `None` for the macOS passkey
/// sheet, where macOS checked the relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRequest {
    pub origin: Option<String>,
    pub rid: String,
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
}

/// An owner action that waits for the owner check. It has the parameters of the
/// action, so the app does exactly what the owner confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerRequest {
    Reveal {
        item_id: u64,
    },
    /// Show the code of one one-time password. `field` is the field of its seed. Only
    /// that field is read: the password and the other secret values stay hidden.
    ShowCode {
        item_id: u64,
        field: String,
    },
    /// Copy the current code of one one-time password. The app computes the code, writes
    /// it to the clipboard, and clears the clipboard soon after if it still holds it.
    CopyCode {
        item_id: u64,
        field: String,
    },
    /// Fill one login in the browser (ADR 0021). Only the browser socket asks for it.
    /// The name and the username are for the dialog.
    FillLogin {
        item_id: u64,
        item_name: String,
        username: String,
        origin: String,
    },
    /// Save the login that the owner typed on a page (ADR 0021). The password waits in
    /// the browser ticket of the dialog.
    SaveLogin {
        title: String,
        username: String,
        origin: String,
    },
    /// Make a login with a new password and fill it in the browser (ADR 0021).
    CreateLogin {
        title: String,
        username: String,
        origin: String,
        length: u32,
        symbols: bool,
    },
    /// Fill the current code of one one-time password in the browser. Only the browser
    /// socket asks for it. The name is for the dialog.
    FillCode {
        item_id: u64,
        item_name: String,
        field: String,
        origin: String,
    },
    /// Sign in with a passkey: one assertion for the account `accounts[chosen]`. With
    /// several accounts `chosen` is [`NO_ACCOUNT`] until the owner chooses one, and the
    /// owner can choose another account of the list before the check.
    SignPasskey {
        request: PasskeyRequest,
        accounts: Vec<PasskeyAccount>,
        chosen: usize,
    },
    /// Make a passkey. The names come from the page or from macOS. `attach_name` is the
    /// title of the login that gets it, `None` for a new login.
    CreatePasskey {
        request: PasskeyRequest,
        user_handle: Vec<u8>,
        user_name: String,
        user_display_name: String,
        algorithms: Vec<i64>,
        excluded: Vec<Vec<u8>>,
        target: crate::vault::PasskeyTarget,
        attach_name: Option<String>,
    },
    /// Fill the username and the password of one login for one request of macOS AutoFill.
    /// Only the credential bridge asks for it.
    SystemFillLogin {
        rid: String,
        item_id: u64,
        item_name: String,
        username: String,
    },
    /// Fill the current code of one one-time password for one request of macOS AutoFill.
    SystemFillCode {
        rid: String,
        item_id: u64,
        item_name: String,
        field: String,
    },
    /// Remove the passkey of a login at `revision`. `delete_login`: the login has no
    /// password, so the whole login goes with the passkey. `name` is for the dialog.
    RemovePasskey {
        item_id: u64,
        revision: u64,
        name: String,
        delete_login: bool,
    },
    /// "Allow Once": approve one waiting question, exactly as the owner saw it.
    ApproveRun(PendingRun),
    /// Approve one run and add one approval to its pattern (ADR 0010). Only the command
    /// line asks for it.
    ApproveAndRemember(PendingRun),
    /// "Allow ACTION in PROJECT" (ADR 0025 §3): approve the question and remember the
    /// answer for its credentials, the project, and the kind of action, for every agent.
    ApproveInProject {
        run: PendingRun,
        project: Project,
        action: ActionKind,
    },
    /// "Allow production: ACTION in PROJECT" (ADR 0025 §3b): approve the question and
    /// allow production for the project and the kind of action.
    AllowProduction {
        run: PendingRun,
        project: Project,
        action: ActionKind,
    },
    /// "Development" on a question about a credential that is production only by default
    /// (ADR 0025 §3, §5). The bouncer is then less careful with it, so it needs the
    /// check. The question still waits. "Production" is stricter and needs none.
    CorrectEnvironment {
        run_id: u64,
        agent: String,
        item_id: u64,
        name: String,
        environment: crate::vault::Environment,
    },
    /// Answer a suggestion of Decisions (ADR 0025 §5) so that its credential is not
    /// production: accept "development", choose development instead of production, or
    /// ignore a raise to production. The bouncer is then less careful, so it needs the
    /// check. `environment` is what the credential gets.
    AnswerSuggestion {
        correction_id: u64,
        item_id: u64,
        name: String,
        answer: crate::vault::agent_items::CorrectionAnswer,
        /// The environment that the owner chose instead of the proposal.
        chosen: Option<crate::vault::Environment>,
        environment: crate::vault::Environment,
    },
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
    /// A [`OwnerRequest::SaveVariable`] after the app read the chosen field:
    /// [`DesktopApp::ask_owner`] makes it. `setup_key` is true when the field holds the
    /// setup key of a one-time password, by its label or by its value. The dialog says so.
    ConfirmVariable {
        item_id: u64,
        env_name: String,
        field: String,
        delivery: EnvDelivery,
        setup_key: bool,
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
    /// Set the environment of an item to a value that is not production, as the owner's
    /// answer (ADR 0025 §4). The bouncer is then less careful, so it needs the check.
    /// Production is stricter and needs none: the page sets it without this request.
    SetEnvironment {
        item_id: u64,
        name: String,
        environment: crate::vault::Environment,
    },
    /// Turn "Always ask me" off for an item (ADR 0025 §3). Turning it on is stricter and
    /// needs no check.
    AlwaysAskOff {
        item_id: u64,
        name: String,
    },
    /// Remove an exception of an agent for an item (ADR 0025 §3f). It gives authority
    /// back.
    RemoveAgentException {
        agent_id: u64,
        agent_name: String,
        item_id: u64,
        kind: crate::vault::exceptions::ExceptionKind,
    },
    RotateToken {
        agent_id: u64,
        agent_name: String,
    },
    /// "Connect" in the agent guide: a new token and, with `show_all`, the catalog of
    /// all credentials without values (ADR 0024).
    ConnectAgent {
        agent_id: u64,
        agent_name: String,
        show_all: bool,
    },
    SetTokenLifetime {
        days: String,
    },
    /// Open a command-line session (ADR 0017). Only the command line asks for it.
    OpenCliSession,
    /// Bind the variables of several items with one check (ADR 0017, D1). Only
    /// `apassy import --bind` asks for it. Programs get the real values.
    BindVariables {
        variables: Vec<VariableBinding>,
    },
    /// Pair an iPhone (ADR 0020). The owner typed the right code. The values are the
    /// device exactly as it asked to pair.
    PairCompanion {
        device_id: String,
        device_name: String,
        request_key: Vec<u8>,
        approval_key: Vec<u8>,
    },
    /// Add a device to the relay sync of the vault `vault` (a list ID; ADR 0022). The
    /// values are the link exactly as the "Add a device…" sheet showed it with its safety
    /// words.
    ConfirmSyncDevice {
        vault: String,
        link_id: u64,
        device_name: String,
        public_key: Vec<u8>,
    },
    /// Add an iPhone or a Mac to the notifications-only questions team of the vault
    /// `vault` (plan §A7): the same proof as [`OwnerRequest::ConfirmSyncDevice`] for the
    /// link exactly as the sheet showed it with its safety words. The `device_name` of an
    /// iPhone carries its answer key (`questions::device_link`), so the proof covers it,
    /// and the confirmation writes the row of the iPhone from the keys of the link. The
    /// device gets the questions and can answer them; it gets no vault.
    ConfirmQuestionsDevice {
        vault: String,
        link_id: u64,
        device_name: String,
        public_key: Vec<u8>,
    },
    /// Turn "Send questions through the relay" on (relay-questions-v1): through the relay
    /// sync team `team_id` of the vault, or through a new notifications-only team on
    /// `relay_url` (`team_id` `None`, with the team code of the sheet). It opens a new
    /// channel that can approve runs.
    EnableRelayQuestions {
        relay_url: String,
        team_id: Option<String>,
    },
    /// An approving answer of this Mac to the question of another Mac (relay-questions-v1
    /// section 5.3): `remote_id` is the question in the view of the questions waiter,
    /// `choice` the answer, and `action` the [`OwnerAction::AnswerRemoteQuestion`] of
    /// both, as the card showed them.
    AnswerRemoteQuestion {
        remote_id: u64,
        choice: Choice,
        action: OwnerAction,
    },
}

impl OwnerRequest {
    /// True for a request whose result goes only to a request that still waits: a code or
    /// a passkey. Without a live ticket nothing signs and no code is made.
    pub fn needs_live_ticket(&self) -> bool {
        matches!(
            self,
            Self::FillCode { .. }
                | Self::SignPasskey { .. }
                | Self::CreatePasskey { .. }
                | Self::SystemFillLogin { .. }
                | Self::SystemFillCode { .. }
        )
    }

    /// True when Touch ID may start as the dialog opens. With several accounts the owner
    /// reads the dialog first, so a touch never confirms an account that they did not see.
    pub fn starts_touch_id(&self) -> bool {
        self.is_ready()
    }

    /// True when the request names everything that a proof must name. A passkey request
    /// is not ready until it has an account: no check starts and no proof is used.
    pub fn is_ready(&self) -> bool {
        !matches!(self, Self::SignPasskey { .. }) || self.passkey_account().is_some()
    }

    /// The account of an assertion.
    pub fn passkey_account(&self) -> Option<&PasskeyAccount> {
        match self {
            Self::SignPasskey {
                accounts, chosen, ..
            } => accounts.get(*chosen),
            _ => None,
        }
    }

    /// The action that the proof must name.
    pub fn action(&self) -> OwnerAction {
        match self {
            Self::SystemFillLogin {
                rid,
                item_id,
                item_name,
                ..
            } => OwnerAction::FillSystemLogin {
                rid: rid.clone(),
                item_id: *item_id,
                login: item_name.clone(),
            },
            Self::SystemFillCode {
                rid,
                item_id,
                field,
                ..
            } => OwnerAction::FillSystemCode {
                rid: rid.clone(),
                item_id: *item_id,
                field: field.clone(),
            },
            Self::RemovePasskey {
                item_id, revision, ..
            } => OwnerAction::RemovePasskey {
                item_id: *item_id,
                revision: *revision,
            },
            Self::FillCode {
                item_id,
                field,
                origin,
                ..
            } => OwnerAction::FillCode {
                item_id: *item_id,
                field: field.clone(),
                origin: origin.clone(),
            },
            Self::SignPasskey { request, .. } => {
                // A request that is ready has an account. Without one the action names
                // none, and no check starts for it ([`OwnerRequest::is_ready`]).
                let (item_id, credential_id) =
                    self.passkey_account().map_or((0, Vec::new()), |account| {
                        (account.item_id, account.credential_id.clone())
                    });
                OwnerAction::SignPasskey {
                    origin: request.origin.clone(),
                    rid: request.rid.clone(),
                    rp_id: request.rp_id.clone(),
                    item_id,
                    credential_id,
                    client_data_hash: request.client_data_hash,
                }
            }
            Self::CreatePasskey {
                request,
                user_handle,
                user_name,
                user_display_name,
                algorithms,
                excluded,
                target,
                ..
            } => OwnerAction::CreatePasskey {
                origin: request.origin.clone(),
                rid: request.rid.clone(),
                rp_id: request.rp_id.clone(),
                client_data_hash: request.client_data_hash,
                user_handle: user_handle.clone(),
                user_name: user_name.clone(),
                user_display_name: user_display_name.clone(),
                algorithms: algorithms.clone(),
                excluded: excluded.clone(),
                target: target.clone(),
            },
            Self::Reveal { item_id } => OwnerAction::Reveal { item_id: *item_id },
            Self::ShowCode { item_id, field } => OwnerAction::ShowCode {
                item_id: *item_id,
                field: field.clone(),
            },
            Self::CopyCode { item_id, field } => OwnerAction::CopyCode {
                item_id: *item_id,
                field: field.clone(),
            },
            Self::FillLogin {
                item_id,
                item_name,
                origin,
                ..
            } => OwnerAction::FillLogin {
                item_id: *item_id,
                login: item_name.clone(),
                origin: origin.clone(),
            },
            Self::SaveLogin {
                title,
                username,
                origin,
            } => OwnerAction::SaveLogin {
                title: title.clone(),
                username: username.clone(),
                origin: origin.clone(),
            },
            Self::CreateLogin {
                title,
                username,
                origin,
                length,
                symbols,
            } => OwnerAction::CreateLogin {
                title: title.clone(),
                username: username.clone(),
                origin: origin.clone(),
                length: *length,
                symbols: *symbols,
            },
            Self::ApproveRun(run) => OwnerAction::ApproveRun(run.clone()),
            Self::ApproveAndRemember(run) => OwnerAction::ApproveAndRemember(run.clone()),
            Self::ApproveInProject {
                run,
                project,
                action,
            } => OwnerAction::ApproveInProject {
                run: run.clone(),
                project: project.clone(),
                action: *action,
            },
            Self::AllowProduction {
                run,
                project,
                action,
            } => OwnerAction::AllowProduction {
                run: run.clone(),
                project: project.clone(),
                action: *action,
            },
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
            Self::SaveVariable {
                item_id,
                env_name,
                field,
                delivery,
            } => bind_action(
                *item_id,
                env_name,
                field,
                delivery,
                labelled_setup_key(field),
            ),
            Self::ConfirmVariable {
                item_id,
                env_name,
                field,
                delivery,
                setup_key,
            } => bind_action(*item_id, env_name, field, delivery, *setup_key),
            Self::SaveDeclaration { item_id, .. }
            | Self::SaveConnector { item_id, .. }
            | Self::ConfirmReview { item_id }
            | Self::Unarchive { item_id, .. }
            | Self::SetEnvironment { item_id, .. }
            | Self::CorrectEnvironment { item_id, .. }
            | Self::AnswerSuggestion { item_id, .. }
            | Self::AlwaysAskOff { item_id, .. } => {
                OwnerAction::ChangeItemRules { item_id: *item_id }
            }
            Self::RemoveAgentException {
                agent_id,
                item_id,
                kind,
                ..
            } => OwnerAction::RemoveAgentException {
                agent_id: *agent_id,
                item_id: *item_id,
                kind: *kind,
            },
            Self::ConnectAgent {
                agent_id, show_all, ..
            } => OwnerAction::ConnectAgent {
                agent_id: *agent_id,
                show_all: *show_all,
            },
            Self::RotateToken { agent_id, .. } => OwnerAction::RotateToken {
                agent_id: *agent_id,
            },
            Self::SetTokenLifetime { .. } => OwnerAction::ChangeTokenLifetime,
            Self::OpenCliSession => OwnerAction::OpenCliSession,
            Self::BindVariables { variables } => OwnerAction::BindVariables {
                variables: variables
                    .iter()
                    .map(|binding| (binding.item_id, binding.env_name.clone()))
                    .collect(),
            },
            Self::PairCompanion {
                device_id,
                device_name,
                request_key,
                approval_key,
            } => OwnerAction::PairCompanion {
                device_id: device_id.clone(),
                device_name: device_name.clone(),
                request_key: request_key.clone(),
                approval_key: approval_key.clone(),
            },
            Self::ConfirmSyncDevice {
                link_id,
                device_name,
                public_key,
                ..
            }
            | Self::ConfirmQuestionsDevice {
                link_id,
                device_name,
                public_key,
                ..
            } => OwnerAction::ConfirmSyncDevice {
                link_id: *link_id,
                device_name: device_name.clone(),
                public_key: public_key.clone(),
            },
            Self::EnableRelayQuestions { relay_url, team_id } => {
                OwnerAction::EnableRelayQuestions {
                    relay_url: relay_url.clone(),
                    team_id: team_id.clone(),
                }
            }
            Self::AnswerRemoteQuestion { action, .. } => action.clone(),
        }
    }

    /// One sentence for the owner check dialog. It has no secret value.
    pub fn describe(&self) -> String {
        match self {
            Self::Reveal { .. } => "Show the secret values of this item for 30 seconds.".to_owned(),
            Self::ShowCode { field, .. } => format!(
                "Show the code of \"{}\" for 30 seconds. The other secret values stay hidden.",
                super::owner_store::field_label(field)
            ),
            Self::CopyCode { field, .. } => format!(
                "Copy the current code of \"{}\". Apassy clears the clipboard when the code changes, if the clipboard still holds it.",
                super::owner_store::field_label(field)
            ),
            Self::FillLogin {
                item_name,
                username,
                origin,
                ..
            } => format!(
                "Fill the login \"{item_name}\" ({username}) on {origin} in your browser. The page gets the username and the password once."
            ),
            // The site comes first: the title and the username come from the browser.
            Self::SaveLogin {
                title,
                username,
                origin,
            } => format!(
                "For {origin}: save the login \"{title}\" ({}). The password comes from the page.",
                dialog_cut(username)
            ),
            Self::CreateLogin {
                title,
                username,
                origin,
                length,
                symbols,
            } => format!(
                "For {origin}: create the login \"{title}\" ({}) with a new {length}-character password{}, and fill it in your browser.",
                dialog_cut(username),
                if *symbols { " with symbols" } else { " of letters and digits" }
            ),
            Self::SystemFillLogin {
                item_name,
                username,
                ..
            } => format!(
                "macOS AutoFill asks for the username and the password of the login \"{}\" ({}). macOS fills them in the app or on the website where you chose this login. If you did not just choose it in the AutoFill list, click Cancel.",
                page_text(item_name),
                page_text(username)
            ),
            Self::SystemFillCode {
                item_name, field, ..
            } => format!(
                "macOS AutoFill asks for the current code of \"{}\" of the login \"{}\". macOS fills this one code where you chose it. The setup key stays in Apassy. If you did not just choose it in the AutoFill list, click Cancel.",
                super::owner_store::field_label(field),
                page_text(item_name)
            ),
            Self::RemovePasskey {
                name,
                delete_login: true,
                ..
            } => format!(
                "Delete the login \"{name}\". It has a passkey and no password, so removing the passkey deletes the whole login: the username, the websites, the one-time codes, the notes, and every other field. The delete syncs to your other devices. This cannot be undone. Sign in on the site another way first."
            ),
            Self::RemovePasskey { name, .. } => format!(
                "Remove the passkey from the login \"{name}\". The login keeps its password and its other fields. The site still has the passkey in its list: remove it there too."
            ),
            Self::FillCode {
                item_name,
                field,
                origin,
                ..
            } => format!(
                "For {origin}: fill the current code of \"{}\" from the login \"{item_name}\" in your browser. The page gets this one code. The setup key stays in Apassy.",
                super::owner_store::field_label(field)
            ),
            Self::SignPasskey {
                request, accounts, ..
            } => describe_sign(request, accounts, self.passkey_account()),
            Self::CreatePasskey {
                request,
                user_name,
                user_display_name,
                attach_name,
                target,
                ..
            } => {
                let account = account_text(user_name, user_display_name);
                let place = match (attach_name, target) {
                    (Some(name), _) => format!("into the login \"{}\"", page_text(name)),
                    (None, crate::vault::PasskeyTarget::NewItem { title }) => {
                        format!("as the new login \"{}\"", page_text(title))
                    }
                    (None, crate::vault::PasskeyTarget::Attach { .. }) => {
                        "into a login".to_owned()
                    }
                };
                match &request.origin {
                    Some(origin) => format!(
                        "For {origin}: create a passkey for {} with the account {account}, and save it {place}. The page names the account; check it. The page gets the new public key.",
                        request.rp_id
                    ),
                    None => format!(
                        "macOS asks to create a passkey for {} with the account {account}, and save it {place}. The request comes from an app or a website through the macOS passkey sheet; macOS checked that it is for {}. If you did not ask for it just now, click Cancel.",
                        request.rp_id, request.rp_id
                    ),
                }
            }
            Self::ApproveRun(run) => format!(
                "Approve one run of agent \"{}\": {}",
                run.agent,
                run.command.join(" ")
            ),
            Self::ApproveInProject {
                run,
                project,
                action,
            } => format!(
                "Allow {} in \"{}\" for every agent, and approve this run of agent \"{}\": {}. Apassy remembers the answer for {}. A later run of that kind there asks you no question.",
                action_words(*action),
                page_text(&project.label),
                run.agent,
                run.command.join(" "),
                question_items(run)
            ),
            Self::AllowProduction {
                run,
                project,
                action,
            } => format!(
                "Allow production for \"{}\": {}, for every agent, and approve this run of agent \"{}\": {}. Apassy remembers it for {}. Another kind of action still waits for you.",
                page_text(&project.label),
                action_words(*action),
                run.agent,
                run.command.join(" "),
                question_items(run)
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
            Self::SetProcessAccess { place, .. } => format!(
                "Save a process grant in {}. {GRANT_EFFECT}",
                place.describe()
            ),
            Self::GrantMany {
                item_ids, place, ..
            } => format!(
                "Save process grants for {} credentials in {}. {GRANT_EFFECT}",
                item_ids.len(),
                place.describe()
            ),
            Self::ShowAllCredentials { agent_name, .. } => format!(
                "Remove \"Only these items\" from {agent_name}. It sees all your credentials without values: names, usernames, hosts, and visible details. The bouncer decides each use."
            ),
            Self::GrantRequest {
                agent_name,
                item_name,
                place,
                ..
            } => format!(
                "Save a process grant for {agent_name} to {item_name} in {}. {GRANT_EFFECT}",
                place.describe()
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
                item_id,
                env_name,
                field,
                delivery,
            } => describe_variable(
                *item_id,
                env_name,
                field,
                delivery,
                labelled_setup_key(field),
            ),
            Self::ConfirmVariable {
                item_id,
                env_name,
                field,
                delivery,
                setup_key,
            } => describe_variable(*item_id, env_name, field, delivery, *setup_key),
            Self::SaveConnector { base_url, .. } => {
                format!("Send the token of this item to {base_url}.")
            }
            Self::ConfirmReview { .. } => {
                "Confirm the agent settings of this restored item.".to_owned()
            }
            Self::Unarchive { name, .. } => format!(
                "Bring \"{name}\" back from the archive. Agents can use it again; the bouncer decides each use."
            ),
            Self::SetEnvironment {
                name, environment, ..
            } => format!(
                "Mark \"{name}\" as {}. The bouncer is less careful with it than with production.",
                environment.as_str()
            ),
            Self::CorrectEnvironment {
                agent,
                name,
                environment,
                ..
            } => format!(
                "Mark \"{name}\" as {}. The bouncer is less careful with it than with production. The question of agent \"{agent}\" still waits for your answer.",
                environment.as_str()
            ),
            Self::AnswerSuggestion {
                name,
                answer: crate::vault::agent_items::CorrectionAnswer::Ignored,
                chosen: None,
                environment,
                ..
            } => format!(
                "Ignore the suggestion for \"{name}\": it is {} again. The bouncer is less careful with it than with production.",
                environment.as_str()
            ),
            Self::AnswerSuggestion {
                name, environment, ..
            } => format!(
                "Mark \"{name}\" as {}. The bouncer is less careful with it than with production.",
                environment.as_str()
            ),
            Self::AlwaysAskOff { name, .. } => format!(
                "Turn off \"Always ask me\" for \"{name}\". The bouncer then decides each use."
            ),
            Self::RemoveAgentException {
                agent_name, kind, ..
            } => match kind {
                crate::vault::exceptions::ExceptionKind::Never => format!(
                    "Remove \"Never for {agent_name}\". The bouncer then decides each use by {agent_name}."
                ),
                crate::vault::exceptions::ExceptionKind::AlwaysAsk => format!(
                    "Remove \"Always ask for {agent_name}\". The bouncer then decides each use by {agent_name}."
                ),
                crate::vault::exceptions::ExceptionKind::Only => format!(
                    "Remove this item from the items that {agent_name} may use."
                ),
            },
            Self::RotateToken { agent_name, .. } => {
                format!("Give {agent_name} a new token. The old token stops working.")
            }
            Self::ConnectAgent {
                agent_name,
                show_all: true,
                ..
            } => format!(
                "Give {agent_name} a new token, and let it see the names of your credentials without values. The old token stops working."
            ),
            Self::ConnectAgent { agent_name, .. } => {
                format!("Give {agent_name} a new token. The old token stops working.")
            }
            Self::SetTokenLifetime { days } => {
                format!("Set the token lifetime to {} days.", days.trim())
            }
            Self::OpenCliSession => "Start a command-line session. apassy commands in your terminal can then list, add, and change credentials and agents for 30 idle minutes. They can never show a secret value. Grants, approvals, and new tokens still ask you here.".to_owned(),
            Self::BindVariables { variables } => match variables.len() {
                1 => "Bind 1 credential to the environment variable below. Programs get the real value.".to_owned(),
                count => format!(
                    "Bind {count} credentials to the environment variables below. Programs get the real values."
                ),
            },
            Self::PairCompanion { device_name, .. } => format!(
                "Pair the iPhone \"{device_name}\". It can see the runs that wait for you and approve them with Face ID. It can never see a secret value."
            ),
            Self::ConfirmSyncDevice { device_name, .. } => format!(
                "Add the device \"{device_name}\" to the sync of this vault through the Apassy relay. It gets the encrypted copy and can send changes. It still needs the passphrase to open the vault."
            ),
            Self::ConfirmQuestionsDevice { device_name, .. } => {
                let (name, answer_key) =
                    crate::questions::device_link::split_link_device_name(device_name);
                if answer_key.is_some() {
                    format!(
                        "Add the iPhone \"{name}\" to the questions of this vault through the Apassy relay. It can then see the questions of your agents and answer them with Face ID; Apassy keeps its keys in the vault. It gets no vault and no secret value through the relay."
                    )
                } else {
                    format!(
                        "Add the Mac \"{name}\" to the questions of this vault through the Apassy relay. It can then see the questions of your agents and answer them after Touch ID on it. It gets no vault and no secret value through the relay."
                    )
                }
            }
            Self::EnableRelayQuestions {
                relay_url,
                team_id: Some(_),
            } => format!(
                "Send the questions of this vault through the Apassy relay at {relay_url}. Your other devices of this vault can then answer them, and an Allow there needs Face ID or Touch ID. The relay sees no command and no credential."
            ),
            Self::EnableRelayQuestions {
                relay_url,
                team_id: None,
            } => format!(
                "Make a team for the questions of this vault on the Apassy relay at {relay_url}, with the team code. Your other devices of this vault can then answer the questions, and an Allow there needs Face ID or Touch ID. The relay sees no command and no credential."
            ),
            Self::AnswerRemoteQuestion { choice, action, .. } => {
                let (agent, asker) = match action {
                    OwnerAction::AnswerRemoteQuestion { asker, answer, .. } => (
                        answer.run().map_or("the agent", |run| run.agent.as_str()),
                        asker.as_str(),
                    ),
                    _ => ("the agent", "another Mac"),
                };
                format!(
                    "Answer \"{}\" to the question of {} on {}. Apassy signs the answer with the key of this Mac and sends it, end-to-end encrypted, through the relay.",
                    choice_words(choice),
                    page_text(agent),
                    page_text(asker)
                )
            }
        }
    }
}

/// The words of a remote answer for the owner check dialog.
fn choice_words(choice: &Choice) -> String {
    match choice {
        Choice::ApproveOnce => "Allow Once".to_owned(),
        Choice::ApproveInProject { action, .. } => format!("Allow {}", action_words(*action)),
        Choice::AllowProduction { action, .. } => {
            format!("Allow production: {}", action_words(*action))
        }
        Choice::CorrectEnvironment {
            environment: RemoteEnvironment::Development,
            ..
        } => "Development".to_owned(),
        Choice::CorrectEnvironment { .. } => "Production".to_owned(),
        Choice::Deny => "Deny".to_owned(),
        Choice::NeverForAgent => "Never".to_owned(),
        Choice::AlwaysAskForAgent => "Always Ask".to_owned(),
        Choice::Disconnect => "Disconnect".to_owned(),
    }
}

/// `"name" (display name)` of an account, cleaned for the dialog.
fn account_text(user_name: &str, display_name: &str) -> String {
    let name = page_text(user_name);
    let display = page_text(display_name);
    if display.is_empty() || display == name {
        format!("\"{name}\"")
    } else {
        format!("\"{name}\" ({display})")
    }
}

/// The dialog text of an assertion. The origin comes first: it is the origin in the
/// signed client data. The other accounts of the site are named, so the owner knows
/// that the check is for one of them.
fn describe_sign(
    request: &PasskeyRequest,
    accounts: &[PasskeyAccount],
    chosen: Option<&PasskeyAccount>,
) -> String {
    let Some(account) = chosen else {
        return match &request.origin {
            Some(origin) => format!(
                "For {origin}: sign in to {} with a passkey. The page gets one signature. Choose the account before you confirm.",
                request.rp_id
            ),
            None => format!(
                "macOS asks to sign in to {} with a passkey. The request comes from an app or a website through the macOS passkey sheet; macOS checked that it is for {}. Choose the account before you confirm. If you did not just sign in, click Cancel.",
                request.rp_id, request.rp_id
            ),
        };
    };
    let who = account_text(&account.user_name, &account.user_display_name);
    let login = page_text(&account.item_name);
    let mut text = match &request.origin {
        Some(origin) => format!(
            "For {origin}: sign in to {} as {who} with the passkey of the login \"{login}\". The page gets one signature.",
            request.rp_id
        ),
        None => format!(
            "macOS asks to sign in to {} as {who} with the passkey of the login \"{login}\". The request comes from an app or a website through the macOS passkey sheet; macOS checked that it is for {}. If you did not just sign in, click Cancel.",
            request.rp_id, request.rp_id
        ),
    };
    let others: Vec<String> = accounts
        .iter()
        .filter(|other| other.credential_id != account.credential_id)
        .map(|other| account_text(&other.user_name, &other.user_display_name))
        .collect();
    if !others.is_empty() {
        text.push_str(&format!(
            " Other accounts for this site: {}. Choose the account before you confirm.",
            others.join(", ")
        ));
    }
    text
}

/// Touch ID and keychain state from `ping`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NativeState {
    /// `None` until the helper answers, or when it cannot answer.
    pub biometry: Option<Biometry>,
    /// Why the helper did not answer.
    pub problem: Option<String>,
}

/// Dropping this state cancels the native helper that belongs to the check.
type RunningCheck = (
    CheckMethod,
    Task<Result<OwnerProof, OwnerAuthError>>,
    CancelOnDrop,
);

/// The owner check dialog.
pub(crate) struct CheckDialog {
    pub(crate) request: OwnerRequest,
    /// The passphrase field. The app erases it after each try.
    pub(crate) passphrase: String,
    pub(crate) running: Option<RunningCheck>,
    /// The result of the last try.
    pub(crate) message: Option<String>,
    /// The command-line request that asked for this check (ADR 0017). It gets the
    /// answer. `None` for a check from the views.
    pub(crate) origin: Option<super::owner_cli::CliTicket>,
    /// The browser request that asked for this check (ADR 0021). It gets the answer.
    pub(crate) browser: Option<super::browser::BrowserTicket>,
    /// The request of the macOS passkey sheet that asked for this check. It gets the
    /// answer.
    pub(crate) platform: Option<super::passkey_socket::PlatformTicket>,
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
    /// The questions waiter: the questions through the relay (ADR 0025 §3e). It does
    /// nothing until the open vault has a membership with the purpose `questions`.
    pub(crate) questions: Option<crate::questions::QuestionsWorker>,
    /// Inbox events that the owner marked as seen. This is not an approval (N4).
    pub(crate) acknowledged: BTreeSet<EventKey>,
    /// A copied one-time code and its clear.
    pub(crate) clipboard: CodeClipboard,
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
        if let Some(approvals) = self.approvals() {
            let worker = crate::questions::QuestionsWorker::start(
                approvals,
                self.owner_ui.session.shared_vault(),
                self.owner_gate(),
                crate::questions::QuestionsConfig::default(),
            );
            let repaint = ctx.clone();
            worker.set_on_change(move || repaint.request_repaint());
            if let Some(center) = &self.owner.notifications {
                center.set_question_hook(worker.waker());
            }
            self.owner.questions = Some(worker);
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
        // The dialog of a variable names a setup key also when only its value shows it.
        let request = match request {
            OwnerRequest::SaveVariable {
                item_id,
                env_name,
                field,
                delivery,
            } => OwnerRequest::ConfirmVariable {
                setup_key: self
                    .owner_ui
                    .session
                    .holds_setup_key(item_id, &field)
                    .unwrap_or_else(|_| labelled_setup_key(&field)),
                item_id,
                env_name,
                field,
                delivery,
            },
            other => other,
        };
        self.owner.check = Some(CheckDialog {
            request,
            passphrase: String::with_capacity(super::ui::PASSPHRASE_CAPACITY),
            running: None,
            message: None,
            origin: None,
            browser: None,
            platform: None,
        });
        let starts = self
            .owner
            .check
            .as_ref()
            .is_some_and(|dialog| dialog.request.starts_touch_id());
        if starts && self.owner.touch_id_ready() {
            self.start_owner_check(OwnerCheck::TouchId, ctx.cloned());
        }
    }

    /// Choose account `index` of an open passkey dialog. A check that runs is for the
    /// account before: it is dropped, and its proof never signs. The owner confirms again.
    /// The first choice has no account before it, so no check runs and nothing drops.
    /// The account list of the dialog view calls it.
    pub(crate) fn choose_passkey(&mut self, index: usize) {
        let Some(dialog) = self.owner.check.as_mut() else {
            return;
        };
        let OwnerRequest::SignPasskey {
            accounts, chosen, ..
        } = &mut dialog.request
        else {
            return;
        };
        if index >= accounts.len() || index == *chosen {
            return;
        }
        *chosen = index;
        dialog.running = None;
        dialog.message = None;
    }

    /// Run the gate on a worker thread for the open dialog.
    pub(crate) fn start_owner_check(&mut self, check: OwnerCheck, ctx: Option<egui::Context>) {
        let gate = self.owner_gate();
        let Some(dialog) = self.owner.check.as_mut() else {
            return;
        };
        // A request without an account has no action to name: nothing starts.
        if !dialog.request.is_ready() {
            dialog.message = Some("Choose an account first. Nothing was checked.".to_owned());
            return;
        }
        let action = dialog.request.action();
        let method = check.method();
        // Stop a previous helper before a retry starts another prompt.
        dialog.running = None;
        let cancel = AuthCancel::new();
        let cancel_on_drop = cancel.cancel_on_drop();
        dialog.message = None;
        dialog.running = Some((
            method,
            Task::spawn(ctx, move || {
                gate.authorize_cancellable(action, check, &cancel)
            }),
            cancel_on_drop,
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
        if matches!(
            request,
            OwnerRequest::SignPasskey { .. } | OwnerRequest::CreatePasskey { .. }
        ) {
            return self.complete_passkey(&request.action(), proof);
        }
        let session = &mut self.owner_ui.session;
        match request {
            OwnerRequest::RemovePasskey {
                item_id,
                revision,
                name,
                delete_login,
            } => self.complete_remove_passkey(item_id, revision, &name, delete_login, proof),
            OwnerRequest::SystemFillLogin {
                rid,
                item_id,
                item_name,
                ..
            } => self.complete_system_fill(&rid, item_id, &item_name, proof),
            OwnerRequest::SystemFillCode {
                rid,
                item_id,
                field,
                ..
            } => self.complete_system_code(&rid, item_id, &field, proof),
            OwnerRequest::FillCode {
                item_id,
                field,
                origin,
                ..
            } => self.complete_fill_code(item_id, &field, &origin, proof),
            // Handled above.
            OwnerRequest::SignPasskey { .. } | OwnerRequest::CreatePasskey { .. } => {
                drop(proof);
            }
            OwnerRequest::Reveal { item_id } => match session.reveal(item_id, proof) {
                Ok(details) => self.set_ok(details.reveal_warning()),
                Err(err) => self.set_err(err.message),
            },
            OwnerRequest::ShowCode { item_id, field } => {
                match session.reveal_one_code_seed(item_id, &field, proof) {
                    Ok(()) => self.set_ok(
                        "The code is visible for 30 seconds, or until you hide it or lock the vault.",
                    ),
                    Err(err) => self.set_err(err.message),
                }
            }
            OwnerRequest::CopyCode { item_id, field } => {
                self.complete_copy_code(item_id, &field, proof)
            }
            OwnerRequest::FillLogin {
                item_id, origin, ..
            } => self.complete_fill(item_id, &origin, proof),
            OwnerRequest::SaveLogin {
                title,
                username,
                origin,
            } => self.complete_save(&title, &username, &origin, proof),
            OwnerRequest::CreateLogin {
                title,
                username,
                origin,
                length,
                symbols,
            } => self.complete_create(&title, &username, &origin, length, symbols, proof),
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
            OwnerRequest::ApproveInProject {
                project, action, ..
            } => {
                // The same queue path as "Allow Once". The broker remembers the answer
                // after its second check (ADR 0025 §3).
                let result = match self.approvals() {
                    Some(approvals) => approvals.approve(proof).map_err(|r| r.message()),
                    None => Err("The broker is not running. Nothing was approved."),
                };
                match result {
                    Ok(()) => self.set_ok(format!(
                        "Allowed. Apassy remembers {} in {} for all agents.",
                        action_words(action),
                        project.label
                    )),
                    Err(message) => self.set_err(message),
                }
            }
            OwnerRequest::AllowProduction {
                project, action, ..
            } => {
                let result = match self.approvals() {
                    Some(approvals) => approvals.approve(proof).map_err(|r| r.message()),
                    None => Err("The broker is not running. Nothing was approved."),
                };
                match result {
                    Ok(()) => self.set_ok(format!(
                        "Allowed. Production is allowed for {} in {}. Other kinds of action still ask you.",
                        action_words(action),
                        project.label
                    )),
                    Err(message) => self.set_err(message),
                }
            }
            OwnerRequest::CorrectEnvironment {
                agent,
                item_id,
                name,
                environment,
                ..
            } => match session.correct_environment(item_id, environment, proof) {
                Ok(()) => self.set_ok(format!(
                    "{name} is marked as {}. The question of {agent} still waits: allow it or deny it.",
                    environment.as_str()
                )),
                Err(err) => self.set_err(err.message),
            },
            OwnerRequest::AnswerSuggestion {
                correction_id,
                item_id,
                name,
                answer,
                chosen,
                environment,
            } => match session.answer_correction(
                correction_id,
                item_id,
                answer,
                chosen,
                Some(proof),
            ) {
                Ok(_) => self.set_ok(format!("{name} is {}.", environment.as_str())),
                Err(err) => self.set_err(err.message),
            },
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
                let _ = self.apply(
                    result,
                    "The process grant is saved. It approves no run: the bouncer decides each use, and asks you in Decisions when it is not sure.",
                );
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
                    &format!(
                        "Process grants for {count} credentials are saved. The bouncer decides each use."
                    ),
                );
            }
            OwnerRequest::ShowAllCredentials { agent_id, .. } => {
                let result = session.set_agent_sees_all(agent_id, true, Some(proof));
                let _ = self.apply(
                    result,
                    "\"Only these items\" is removed. The agent sees all credentials without values, and the bouncer decides each use.",
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
                let _ = self.apply(
                    result,
                    &format!(
                        "The process grant for {item_name} is saved, and the request is closed. The bouncer decides each use."
                    ),
                );
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
                    // The owner saw and confirmed each value (ADR 0025 §4).
                    let _ = self.owner_ui.session.with_vault(|vault| {
                        vault.set_declaration_sources(item_id, &Default::default())
                    });
                }
            }
            OwnerRequest::SaveVariable {
                item_id,
                env_name,
                field,
                delivery,
            }
            | OwnerRequest::ConfirmVariable {
                item_id,
                env_name,
                field,
                delivery,
                ..
            } => {
                // The session reads the field again and refuses a proof for another
                // field, variable, delivery, or setup key state.
                let result = session.set_env_binding(item_id, &env_name, &field, &delivery, proof);
                let message = if env_name.trim().is_empty()
                    || env_name.trim() == format!("APASSY_ITEM_{item_id}")
                {
                    "The automatic command settings are saved.".to_owned()
                } else {
                    format!("The item is bound to {env_name}.")
                };
                let _ = self.apply(result, &message);
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
                        "{name} is back from the archive. Agents can use it again; the bouncer decides each use."
                    ),
                );
            }
            OwnerRequest::SetEnvironment {
                item_id,
                name,
                environment,
            } => self.complete_set_environment(item_id, &name, environment, proof),
            OwnerRequest::AlwaysAskOff { item_id, name } => {
                let action = OwnerAction::ChangeItemRules { item_id };
                let result = session.with_vault(|vault| {
                    proof
                        .check(&action, &vault.epoch())
                        .map_err(|refusal| refusal.message().to_owned())?;
                    vault
                        .set_always_ask(item_id, false)
                        .map_err(|err| format!("\"Always ask me\" did not change: {err}."))
                });
                match result {
                    Some(Ok(())) => self.set_ok(format!(
                        "\"Always ask me\" is off for {name}. The bouncer decides each use."
                    )),
                    Some(Err(message)) => self.set_err(message),
                    None => self.set_err("The vault is locked."),
                }
            }
            OwnerRequest::RemoveAgentException {
                agent_id,
                agent_name,
                item_id,
                kind,
            } => {
                let action = OwnerAction::RemoveAgentException {
                    agent_id,
                    item_id,
                    kind,
                };
                let result = session.with_vault(|vault| {
                    proof
                        .check(&action, &vault.epoch())
                        .map_err(|refusal| refusal.message().to_owned())?;
                    vault
                        .remove_agent_exception(agent_id, item_id, kind)
                        .map_err(|err| format!("The exception did not change: {err}."))
                });
                match result {
                    Some(Ok(_)) => self.set_ok(format!(
                        "The exception for {agent_name} is removed. The bouncer decides each use."
                    )),
                    Some(Err(message)) => self.set_err(message),
                    None => self.set_err("The vault is locked."),
                }
            }
            OwnerRequest::ConfirmReview { item_id } => {
                let result = session.confirm_review(item_id, proof);
                let _ = self.apply(
                    result,
                    "The agent settings are confirmed. Agents can use the item again; the bouncer decides each use.",
                );
            }
            OwnerRequest::ConnectAgent {
                agent_id,
                agent_name,
                show_all,
            } => match session.connect_agent(agent_id, show_all, proof) {
                Ok(token) => {
                    self.owner_ui.fresh_token = Some(FreshToken {
                        agent_name: agent_name.clone(),
                        token,
                        rotated: true,
                    });
                    self.set_ok(format!(
                        "{agent_name} has a new token. Connect your host to save it. The old token does not work."
                    ));
                }
                Err(err) => self.set_err(err.message),
            },
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
                        "{agent_name} has a new token. Connect your host to save it. The old token does not work."
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
            OwnerRequest::OpenCliSession => self.open_cli_session(proof),
            OwnerRequest::BindVariables { variables } => self.bind_variables(variables, proof),
            OwnerRequest::PairCompanion { .. } => self.complete_pairing(proof),
            OwnerRequest::ConfirmSyncDevice { vault, link_id, .. }
            | OwnerRequest::ConfirmQuestionsDevice { vault, link_id, .. } => {
                self.relay_confirm_link(&vault, link_id, proof);
            }
            OwnerRequest::EnableRelayQuestions { relay_url, team_id } => {
                self.questions_enable_with(relay_url, team_id, proof);
            }
            OwnerRequest::AnswerRemoteQuestion {
                remote_id, choice, ..
            } => self.answer_remote_question(remote_id, choice, Some(proof)),
        }
    }

    /// Remove a passkey with `proof`. The dialog said whether the login goes too: that
    /// must still be so, else nothing is removed. A deleted login leaves the page.
    fn complete_remove_passkey(
        &mut self,
        item_id: u64,
        revision: u64,
        name: &str,
        delete_login: bool,
        proof: OwnerProof,
    ) {
        let session = &mut self.owner_ui.session;
        match session.passkey_item(item_id) {
            Ok(Some(item)) if item.has_password != delete_login => {}
            Ok(_) | Err(_) => {
                drop(proof);
                return self.set_err(
                    "The login changed after you opened it. Nothing was removed. Open it again.",
                );
            }
        }
        if let Err(err) = session.remove_passkey(item_id, revision, proof) {
            return self.set_err(err.message);
        }
        let selected = self.selected_item_id == Some(item_id.to_string());
        if delete_login {
            if selected {
                self.selected_item_id = None;
                self.show_credentials();
            }
            self.pending_delete = false;
            self.set_ok(format!("The login \"{name}\" is deleted with its passkey."));
        } else {
            // The form gets the new revision of the login.
            if selected {
                self.select_item(item_id.to_string());
            }
            self.set_ok(format!(
                "The passkey is removed from \"{name}\". The login keeps its password."
            ));
        }
    }

    /// Mark the environment of an item as the answer of the owner: only the environment
    /// and its source "owner" change (ADR 0025 §4). The project of a pasted credential
    /// stays empty, and the other values and sources stay.
    fn complete_set_environment(
        &mut self,
        item_id: u64,
        name: &str,
        environment: crate::vault::Environment,
        proof: OwnerProof,
    ) {
        let action = OwnerAction::ChangeItemRules { item_id };
        let result = self.owner_ui.session.with_vault(|vault| {
            proof
                .check(&action, &vault.epoch())
                .map_err(|refusal| refusal.message().to_owned())?;
            vault
                .set_declaration_environment(item_id, environment)
                .map_err(|err| format!("The environment did not change: {err}."))
        });
        match result {
            Some(Ok(())) => {
                self.reload_declaration_form(item_id);
                self.set_ok(format!("{name} is marked as {}.", environment.as_str()));
            }
            Some(Err(message)) => self.set_err(message),
            None => self.set_err("The vault is locked."),
        }
    }

    /// Show the stored declaration of an item in the declaration form.
    pub(crate) fn reload_declaration_form(&mut self, item_id: u64) {
        if let Ok(mut form) = self.owner_ui.session.declaration_form(item_id) {
            form.stored = true;
            self.owner_ui.declaration_form = form;
        }
    }

    /// Copy the current code of one one-time password with `proof`. The seed stays in the
    /// session call. The clipboard gets the code only.
    fn complete_copy_code(&mut self, item_id: u64, field: &str, proof: OwnerProof) {
        let session = &mut self.owner_ui.session;
        let Some(epoch) = session.epoch() else {
            self.set_err("The vault is locked. Nothing was copied.");
            return;
        };
        let code = match session.copy_code(item_id, field, proof) {
            Ok(code) => code,
            Err(err) => {
                self.set_err(err.message);
                return;
            }
        };
        let left = code.left;
        match self
            .owner
            .clipboard
            .copy(code.digits, left, epoch, std::time::Instant::now())
        {
            Ok(after) => self.set_ok(format!(
                "The code is copied. Apassy clears the clipboard in {} seconds if it still holds the code.",
                after.as_secs()
            )),
            Err(err) => self.set_err(err.message()),
        }
    }

    /// Do the request of a passed check, and answer the command line or the browser when
    /// it asked.
    fn finish_owner_check(&mut self, dialog: CheckDialog, proof: OwnerProof) {
        let CheckDialog {
            request,
            origin,
            mut browser,
            platform,
            ..
        } = dialog;
        // A request without an account signs nothing, whatever proof it gets.
        if !request.is_ready() {
            drop(proof);
            self.set_note("Choose an account first. Nothing was signed.");
            return;
        }
        // A code or a passkey goes only to a request that still waits. The check is just
        // before the vault call, on this thread: a request that hung up signs nothing.
        if request.needs_live_ticket() {
            let live = browser
                .as_ref()
                .map(super::browser::BrowserTicket::is_live)
                .or_else(|| {
                    platform
                        .as_ref()
                        .map(super::passkey_socket::PlatformTicket::is_live)
                })
                .unwrap_or(false);
            if !live {
                drop(proof);
                self.set_note(
                    "The request ended before the owner check finished. Nothing was signed or filled.",
                );
                return;
            }
        }
        if let Some(ticket) = browser.as_mut() {
            self.hold_browser_secret(ticket);
        }
        let before = self.status_seq;
        self.complete_owner_request(request, proof);
        if let Some(ticket) = origin {
            self.answer_cli_ticket(ticket, before);
        }
        if let Some(ticket) = browser {
            self.answer_browser_ticket(ticket, before);
        }
        if let Some(ticket) = platform {
            self.answer_platform_ticket(ticket);
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
        self.finish_owner_check(dialog, proof);
        Ok(())
    }

    /// Finish the open dialog with `proof`, as a passed check does. Tests use this with
    /// a proof of their own, also a proof for another action.
    #[cfg(test)]
    pub(crate) fn finish_owner_check_with(&mut self, proof: OwnerProof) {
        let dialog = self.owner.check.take().expect("an owner check is open");
        self.finish_owner_check(dialog, proof);
    }

    /// Poll the worker threads. The UI calls this at the start of each frame.
    pub(crate) fn poll_owner_flows(&mut self, ctx: &egui::Context) {
        if let Some(probe) = &self.owner.native_probe
            && let TaskPoll::Done(state) = probe.poll()
        {
            self.owner.native = state;
            self.owner.native_probe = None;
        }
        self.poll_owner_check(ctx);
        self.expire_browser_check(ctx);
        self.expire_platform_check(ctx);
        self.poll_unlock(ctx);
        self.poll_companion(ctx);
        self.questions_poll(ctx);
        self.poll_remote_answers(ctx);
        self.owner_ui.session.expire_reveals();
        if let Some(left) = self.owner_ui.session.next_reveal_expiry() {
            ctx.request_repaint_after(left);
        }
        // A copied code clears at its time, or at once in another vault session.
        let epoch = self.owner_ui.session.epoch();
        if let Some(left) = self.owner.clipboard.tick(std::time::Instant::now(), epoch) {
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

    fn poll_owner_check(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.owner.check.as_mut() else {
            return;
        };
        let Some((_, task, _)) = &dialog.running else {
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
                self.finish_owner_check(dialog, proof);
            }
            // The owner can try again: the dialog stays open and keeps the action.
            Err(err)
                if err.passphrase_fallback()
                    || matches!(
                        err,
                        OwnerAuthError::WrongPassphrase | OwnerAuthError::EmptyPassphrase
                    ) =>
            {
                dialog.message = Some(err.message());
                // A fill waits in the background. The passphrase field is in the window.
                if (dialog.browser.is_some() || dialog.platform.is_some())
                    && err.passphrase_fallback()
                {
                    super::owner_cli::bring_to_front(ctx);
                }
            }
            Err(err) => {
                if let Some(mut dialog) = self.owner.check.take() {
                    if let Some(ticket) = dialog.origin.take() {
                        ticket.send(crate::owner::wire::Response::error(
                            "owner_check_failed",
                            err.message(),
                        ));
                    }
                    if let Some(ticket) = dialog.browser.take() {
                        ticket.send(crate::browser::wire::Response::error(
                            "owner_check_failed",
                            err.message(),
                        ));
                    }
                    if let Some(ticket) = dialog.platform.take() {
                        ticket.fail("owner_check_failed", &err.message());
                    }
                }
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
        // Sync before the owner sees the list (ADR 0020).
        let loaded = if result.is_ok() {
            self.sync_after_unlock()
        } else {
            None
        };
        match result {
            Ok(()) => self.set_ok(match loaded {
                Some(line) => format!("The vault is unlocked with Touch ID. {line}"),
                None => "The vault is unlocked with Touch ID.".to_owned(),
            }),
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
        self.ui.discard_item_changes = false;
        self.ui.discard_item_kind_change = false;
        self.files.forget();
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
        // A lock stops the iPhone listener at once and drops its key from memory.
        self.stop_companion();
        // The relay token of the questions goes; their open questions expire on the relay.
        if let Some(questions) = &self.owner.questions {
            questions.forget();
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
        // The parsed 1Password export holds secrets.
        self.import.forget();
        // A copied code leaves the clipboard if it is still there, and its buffer goes.
        self.owner.clipboard.end_session();
        self.sync_forget_secrets(ctx);
        self.close_owner_check(ctx);
        if let Some(ctx) = ctx {
            super::ui::forget_all_secret_fields(ctx);
        }
    }

    /// Quit: record and end waiting runs, lock, stop the iPhone listener, and stop the
    /// notification threads.
    pub(crate) fn shut_down(&mut self) {
        // The command line gets "stopped", and every session ends (ADR 0017).
        self.cli.stop();
        // A fill that waits gets "stopped" or "cancelled" (ADR 0021).
        self.browser.stop();
        // The macOS passkey sheet gets "cancelled" for each request that waits.
        self.platform.stop();
        let approvals = self.approvals();
        let _ = self
            .owner_ui
            .session
            .lock_ending_runs(approvals.as_deref(), ENDED_BY_QUIT);
        self.stop_companion();
        self.erase_typed_secrets(None);
        if let Some(mut center) = self.owner.notifications.take() {
            center.stop();
        }
        if let Some(mut questions) = self.owner.questions.take() {
            questions.stop();
        }
        // A local fine-tune stops with the app (goal item B9).
        self.learning.stop_training();
    }
}
