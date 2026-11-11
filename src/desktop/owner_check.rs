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
use std::time::Instant;

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
    ApprovalQueue, CheckMethod, EvaluationOffer, OwnerAction, OwnerAuthError, OwnerCheck,
    OwnerGate, OwnerProof, PasskeyExtras, PendingRun, action_words, touch_id_detail,
};
use crate::broker::profile::REPORTING_API_V0;
use crate::broker::project::Project;
use crate::native::{AuthCancel, Biometry, CancelOnDrop, NativeHelper};
use crate::questions::{Choice, RemoteEnvironment};
use crate::vault::bouncer_scopes::EvaluationConfirmation;
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

/// The owner action of a request of a shared vault ([`OwnerRequest::from_share_action`]).
fn share_request_action(request: OwnerRequest) -> OwnerAction {
    match request {
        OwnerRequest::ShareConnectVault {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            team_id,
            vault_name,
            words,
        } => OwnerAction::ShareConnectVault {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            team_id,
            vault_name,
            words,
        },
        OwnerRequest::AcceptConnectShare {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            words,
        } => OwnerAction::AcceptConnectShare {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            words,
        },
        OwnerRequest::RepinConnectPeer {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            old_fingerprint,
            fingerprint,
            words,
            ends,
            team_id,
            vault_name,
        } => OwnerAction::RepinConnectPeer {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            old_fingerprint,
            fingerprint,
            words,
            ends,
            team_id,
            vault_name,
        },
        OwnerRequest::JoinConnectShare {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            team_id,
            vault_name,
        } => OwnerAction::JoinConnectShare {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            team_id,
            vault_name,
        },
        OwnerRequest::EndConnectShare {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            team_id,
            vault_name,
            leave,
        } => OwnerAction::EndConnectShare {
            account_id,
            peer_account,
            peer_name,
            peer_hint,
            fingerprint,
            team_id,
            vault_name,
            leave,
        },
        other => other.action(),
    }
}

/// A person of another Connect account in an owner check: the name that its verified
/// device list signed, the short fingerprint of its pinned root, and its name at Connect
/// beside them as a hint only.
fn person_text(name: &str, hint: &str, fingerprint: &str) -> String {
    let (name, hint, fingerprint) = (page_text(name), page_text(hint), page_text(fingerprint));
    let verified = if name.is_empty() {
        "an account that this device has not verified yet".to_owned()
    } else {
        format!("\u{201c}{name}\u{201d} (account key {fingerprint})")
    };
    if hint.is_empty() || hint == name {
        verified
    } else {
        format!("{verified}, which Apassy Connect calls \u{201c}{hint}\u{201d},")
    }
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
    /// When its login was added ([`crate::vault::passkey::PasskeyInfo::added`]). The
    /// chooser shows it, so two passkeys of one account differ.
    pub added: Option<u64>,
}

/// The `chosen` value of a passkey request with several accounts that the owner has not
/// chosen from yet. It is no index of the list: the request has no account, no action
/// that a proof can name, and no check starts. A browser request for passkeys of
/// different accounts starts this way; for several passkeys of one account it selects
/// the newest. The dialog and the controller treat any index outside the list this way.
pub(crate) const NO_ACCOUNT: usize = usize::MAX;

/// The WebAuthn extensions of an assertion request, before the owner chooses an
/// account. `prf` is the PRF input for any credential (the browser `eval`, or the PRF of
/// the macOS sheet); `prf_by_credential` has the inputs of the browser
/// `evalByCredential`, by credential ID, which win for their credential. The action of
/// the chosen account names the result of
/// [`PasskeyRequestExtensions::for_credential`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasskeyRequestExtensions {
    pub prf: Option<crate::vault::PasskeyPrfInput>,
    pub prf_by_credential: Vec<(Vec<u8>, crate::vault::PasskeyPrfInput)>,
    pub large_blob: Option<crate::vault::LargeBlobOp>,
}

impl PasskeyRequestExtensions {
    /// The extensions of the request before the owner chooses an account: the PRF of
    /// `eval`, or of some credential of `eval_by_credential`, and the largeBlob
    /// operation. The dialog names them so the owner sees them before the choice.
    pub fn for_any_credential(&self) -> crate::vault::PasskeyAssertionExtensions {
        crate::vault::PasskeyAssertionExtensions {
            prf: self.prf.clone().or_else(|| {
                self.prf_by_credential
                    .first()
                    .map(|(_, input)| input.clone())
            }),
            large_blob: self.large_blob.clone(),
        }
    }

    /// The extensions of the assertion with `credential_id`.
    pub fn for_credential(&self, credential_id: &[u8]) -> crate::vault::PasskeyAssertionExtensions {
        let by_credential = self
            .prf_by_credential
            .iter()
            .find(|(id, _)| id.as_slice() == credential_id)
            .map(|(_, input)| input.clone());
        crate::vault::PasskeyAssertionExtensions {
            prf: by_credential.or_else(|| self.prf.clone()),
            large_blob: self.large_blob.clone(),
        }
    }
}

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
    BrowserDebugging {
        request_label: String,
        identity: crate::browser::trust::InstanceIdentity,
        scope: Option<crate::browser::bypass::BypassScope>,
        binding: Option<crate::browser::bypass::RequestBinding>,
    },
    RemoveOlderIphone {
        device: crate::vault::TrustedDevice,
        team: String,
    },
    AllowAccessOnce {
        request_id: u64,
        digest: String,
    },
    BackupVault {
        path: PathBuf,
    },
    ExportDecisions,
    RegisterAgent {
        name: String,
    },
    RegisterSetupAgent {
        name: String,
    },
    ChangeOwnerFrequency {
        old: crate::broker::approvals::OwnerFrequency,
        new: crate::broker::approvals::OwnerFrequency,
    },
    Reveal {
        item_id: u64,
    },
    /// Show the code of one one-time password. `field` is the field of its seed. Only
    /// that field is read: the password and the other secret values stay hidden.
    CliCode {
        item_id: u64,
        field: String,
        copy: bool,
    },
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
    /// Copy an exact ordinary secret field without revealing it in the window.
    CopyField {
        item_id: u64,
        field: String,
        revision: u64,
    },
    /// Fill one login in the browser (ADR 0021). Only the browser socket asks for it.
    /// The name and the username are for the dialog.
    FillLogin {
        item_id: u64,
        item_name: String,
        username: String,
        origin: String,
    },
    /// Replace one exact login password. The password waits only in its browser ticket.
    UpdateLogin {
        item_id: u64,
        item_name: String,
        username: String,
        origin: String,
        revision: u64,
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
    /// Sign in with a passkey: one assertion for the account `accounts[chosen]`. The
    /// browser request lists the accounts newest first and selects the newest (index 0);
    /// a `chosen` outside the list waits until the owner chooses one. The
    /// owner can choose another account of the list before the check.
    SignPasskey {
        request: PasskeyRequest,
        accounts: Vec<PasskeyAccount>,
        chosen: usize,
        extensions: PasskeyRequestExtensions,
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
    /// Allow one run and authorize later matching model evaluation, with explicit
    /// classification. This is never a standing execution allowance.
    ApproveAndEvaluate {
        run: PendingRun,
        offer: EvaluationOffer,
        confirmations: Vec<EvaluationConfirmation>,
    },
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
    /// check or its exact local window proof. The question still waits. "Production" is stricter and needs none.
    CorrectEnvironment {
        run: PendingRun,
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
    /// Change who hosts the bouncer brain (ADR 0035 section 1). `change` has the bearer
    /// of an own server (redacted in `Debug`); the proof names the kind, the address and
    /// the consent screen (`OwnerAction::ChangeBouncerHosting`). The global owner window
    /// never covers it.
    ChangeBouncerHosting {
        change: crate::vault::BouncerHostChange,
    },
    /// Change who trains the bouncer brain (ADR 0035 section 1), with the same rules.
    ChangeBouncerTraining {
        change: crate::vault::BouncerHostChange,
    },
    /// Turn temporary credentials (way C) on or off for one source item
    /// (`OwnerAction::ChangeDelivery`). `name` is the item title for the texts.
    ChangeDelivery {
        item_id: u64,
        name: String,
        kind: crate::vault::ShortLivedKind,
        on: bool,
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
    /// Add a device to the Apassy Connect account (connect-account-v1 section 7.1): the
    /// join exactly as "Add a device…" showed it, with the six safety words. The proof
    /// goes to [`OwnerFlows::take_connect_proof`] for the Connect view (unit M2), which passes it
    /// to `ConnectAccount::confirm_join`.
    ConfirmConnectDevice {
        account_id: String,
        join_id: u64,
        device_name: String,
        public_key: Vec<u8>,
        words: String,
    },
    /// Revoke a device of the Apassy Connect account (section 7.4); `this_device` is
    /// "Forget this device".
    RevokeConnectDevice {
        account_id: String,
        device_id: String,
        device_name: String,
        /// The short fingerprint of the key that the signed removal names.
        fingerprint: String,
        this_device: bool,
    },
    /// Delete the Apassy Connect account (section 6).
    DeleteConnectAccount {
        account_id: String,
    },
    /// Forget an account file of an earlier version of Apassy on this Mac, with its key.
    ForgetOldConnectAccount,
    /// Delete the vault store (relay copy) `team_id` of the vault `vault_name` at Apassy
    /// Connect (section 8).
    DeleteVaultStore {
        team_id: String,
        vault_name: String,
    },
    /// Take the copy that the device "`device_name`" left on the vault store `team_id` of
    /// the vault `vault_name` (the head `head` of version `version`) once, or replace it
    /// with this device's vault (`replace`; connect-account-v1 section 7.5).
    TakeDepartedCopy {
        team_id: String,
        version: u64,
        head: String,
        replace: bool,
        device_name: String,
        vault_name: String,
    },
    /// Add the device `device_id` ("`device_name`") of the account `account_id` to the
    /// vault store `team_id` of the vault `vault_name` (section 8).
    AddStoreDevice {
        team_id: String,
        device_id: String,
        account_id: String,
        device_name: String,
        vault_name: String,
    },
    /// Change the Family or Team group (connect-billing-v1 section 6).
    ChangeConnectGroup {
        account_id: String,
        group_id: String,
        change: crate::broker::approvals::ConnectGroupChange,
    },
    /// Share the vault store `team_id` with another account (connect-account-v1 section
    /// 16): the words that both devices showed, empty for an account pinned already. The
    /// fields are those of `OwnerAction::ShareConnectVault`.
    ShareConnectVault {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        team_id: String,
        vault_name: String,
        words: String,
    },
    /// "The Words Match" of a share code of another account.
    AcceptConnectShare {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        words: String,
    },
    /// A new pin of an account that was reset, with what ends first.
    RepinConnectPeer {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        old_fingerprint: String,
        fingerprint: String,
        words: String,
        ends: Vec<String>,
        team_id: Option<String>,
        vault_name: Option<String>,
    },
    /// "Join" of a store that another account shares.
    JoinConnectShare {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        team_id: String,
        vault_name: String,
    },
    /// "Stop Sharing with <name>…" or "Leave This Shared Vault…".
    EndConnectShare {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        team_id: String,
        vault_name: String,
        leave: bool,
    },
    /// Turn the tailnet route of this Mac's node on or off (Settings > Devices, plan
    /// S2–S3, unit N7). The node checks nothing itself: the caller asks first.
    SetTailnetRoute {
        on: bool,
    },
    /// Revoke… in Settings > Devices (unit N7): a device of the node team, a device of
    /// another relay, or a Linux node, as the sheet named it.
    RevokeNodeDevice(super::ui::devices::RevokeRequest),
    /// "Allow" on a connect request in Decisions (plan "Bouncer section" decision 6):
    /// connect the remote agent of the request to this Mac. The values are the request
    /// exactly as the card showed it; the app allows it only while the node still has it
    /// with this code (`Node::allow_connect`).
    AllowConnect {
        id: String,
        client_name: String,
        code: String,
        /// Where the code goes back (`PendingConnect.redirect_host`, review 0.5.16).
        redirect_host: String,
    },
    /// `apassy agents add-remote NAME [--days N]`: a remote agent with no item and a
    /// bearer token for the command line. Only the command line asks for it.
    AddRemoteAgent {
        name: String,
        days: u32,
    },
    /// The remote access switch on (Bouncer > Agents): Tailscale Funnel to the node.
    TurnOnRemoteAccess,
    /// "Choose Credentials…" on an agent page: the agent may use `add` from now on, as
    /// "only these items" (ADR 0012). Adding gives access, so it needs the check; the
    /// node then sends the new list to a remote agent. Removing needs none.
    ChooseAgentItems {
        agent_id: u64,
        agent_name: String,
        add: Vec<u64>,
    },
}

impl OwnerRequest {
    /// True for a request that requires a live browser or platform ticket. Without
    /// one, no passkey signs, no code is made and no browser login is filled or updated.
    pub fn needs_live_ticket(&self) -> bool {
        matches!(
            self,
            Self::FillCode { .. }
                | Self::SaveLogin { .. }
                | Self::CreateLogin { .. }
                | Self::FillLogin { .. }
                | Self::UpdateLogin { .. }
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

    /// The request of an owner action of a shared vault (connect-account-v1 section 16):
    /// the same fields, so the prompt shows exactly what the account checks.
    pub(crate) fn from_share_action(action: OwnerAction) -> Option<Self> {
        Some(match action {
            OwnerAction::ShareConnectVault {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                team_id,
                vault_name,
                words,
            } => Self::ShareConnectVault {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                team_id,
                vault_name,
                words,
            },
            OwnerAction::AcceptConnectShare {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                words,
            } => Self::AcceptConnectShare {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                words,
            },
            OwnerAction::RepinConnectPeer {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                old_fingerprint,
                fingerprint,
                words,
                ends,
                team_id,
                vault_name,
            } => Self::RepinConnectPeer {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                old_fingerprint,
                fingerprint,
                words,
                ends,
                team_id,
                vault_name,
            },
            OwnerAction::JoinConnectShare {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                team_id,
                vault_name,
            } => Self::JoinConnectShare {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                team_id,
                vault_name,
            },
            OwnerAction::EndConnectShare {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                team_id,
                vault_name,
                leave,
            } => Self::EndConnectShare {
                account_id,
                peer_account,
                peer_name,
                peer_hint,
                fingerprint,
                team_id,
                vault_name,
                leave,
            },
            _ => return None,
        })
    }

    /// The action that the proof must name.
    pub fn action(&self) -> OwnerAction {
        match self {
            Self::RemoveOlderIphone { device, team } => OwnerAction::RemoveOlderIphone {
                device: device.clone(),
                team: team.clone(),
            },
            Self::AllowAccessOnce { request_id, digest } => OwnerAction::AllowAccessOnce {
                request_id: *request_id,
                digest: digest.clone(),
            },
            Self::BackupVault { path } => OwnerAction::BackupVault { path: path.clone() },
            Self::ExportDecisions => OwnerAction::ExportDecisions,
            Self::RegisterAgent { name } => OwnerAction::RegisterAgent { name: name.clone() },
            Self::RegisterSetupAgent { name } => {
                OwnerAction::RegisterSetupAgent { name: name.clone() }
            }
            Self::BrowserDebugging {
                identity,
                scope,
                binding,
                ..
            } => OwnerAction::BrowserDebugging {
                identity: identity.clone(),
                scope: *scope,
                binding: binding.clone(),
            },
            Self::ChangeOwnerFrequency { old, new } => OwnerAction::ChangeOwnerFrequency {
                old: *old,
                new: *new,
            },
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
            Self::SignPasskey {
                request,
                extensions,
                ..
            } => {
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
                    extensions: extensions.for_credential(&credential_id),
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
            Self::CliCode {
                item_id,
                field,
                copy,
            } => OwnerAction::CliCode {
                item_id: *item_id,
                field: field.clone(),
                copy: *copy,
            },
            Self::ShowCode { item_id, field } => OwnerAction::ShowCode {
                item_id: *item_id,
                field: field.clone(),
            },
            Self::CopyCode { item_id, field } => OwnerAction::CopyCode {
                item_id: *item_id,
                field: field.clone(),
            },
            Self::CopyField {
                item_id,
                field,
                revision,
            } => OwnerAction::CopyField {
                item_id: *item_id,
                field: field.clone(),
                revision: *revision,
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
            Self::UpdateLogin {
                item_id,
                item_name,
                username,
                origin,
                revision,
            } => OwnerAction::UpdateLogin {
                item_id: *item_id,
                login: item_name.clone(),
                username: username.clone(),
                origin: origin.clone(),
                revision: *revision,
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
            Self::ApproveAndEvaluate {
                run,
                offer,
                confirmations,
            } => OwnerAction::ApproveAndEvaluate {
                run: run.clone(),
                offer: offer.clone(),
                confirmations: confirmations.clone(),
            },
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
            Self::ChangeBouncerHosting { change } => crate::broker::brain_host::owner_action(
                crate::vault::BouncerHostRole::Hosting,
                change,
            ),
            Self::ChangeBouncerTraining { change } => crate::broker::brain_host::owner_action(
                crate::vault::BouncerHostRole::Training,
                change,
            ),
            Self::ChangeDelivery {
                item_id, kind, on, ..
            } => OwnerAction::ChangeDelivery {
                item: *item_id,
                kind: *kind,
                on: *on,
            },
            Self::AllowOperation {
                agent_id, item_id, ..
            }
            | Self::SetProcessAccess {
                agent_id, item_id, ..
            } => OwnerAction::ChangeGrant {
                agent_id: *agent_id,
                item_id: *item_id,
            },
            Self::GrantRequest {
                request_id,
                agent_id,
                item_id,
                place,
                mode,
                ..
            } => OwnerAction::GrantAccessRequest {
                request_id: *request_id,
                agent_id: *agent_id,
                item_id: *item_id,
                place: place.clone(),
                mode: *mode,
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
            Self::CorrectEnvironment { run, item_id, .. } => OwnerAction::QuestionDevelopment {
                run_id: run.id,
                item_id: *item_id,
            },
            Self::SaveDeclaration { item_id, .. }
            | Self::SaveConnector { item_id, .. }
            | Self::ConfirmReview { item_id }
            | Self::Unarchive { item_id, .. }
            | Self::SetEnvironment { item_id, .. }
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
            Self::ConfirmConnectDevice {
                account_id,
                join_id,
                device_name,
                public_key,
                words,
            } => OwnerAction::ConfirmConnectDevice {
                account_id: account_id.clone(),
                join_id: *join_id,
                device_name: device_name.clone(),
                public_key: public_key.clone(),
                words: words.clone(),
            },
            Self::RevokeConnectDevice {
                account_id,
                device_id,
                device_name,
                fingerprint,
                ..
            } => OwnerAction::RevokeConnectDevice {
                account_id: account_id.clone(),
                device_id: device_id.clone(),
                device_name: device_name.clone(),
                fingerprint: fingerprint.clone(),
            },
            Self::DeleteConnectAccount { account_id } => OwnerAction::DeleteConnectAccount {
                account_id: account_id.clone(),
            },
            Self::ForgetOldConnectAccount => OwnerAction::ForgetOldConnectAccount,
            Self::DeleteVaultStore { team_id, .. } => OwnerAction::DeleteVaultStore {
                team_id: team_id.clone(),
            },
            Self::TakeDepartedCopy {
                team_id,
                version,
                head,
                replace,
                ..
            } => OwnerAction::TakeDepartedCopy {
                team_id: team_id.clone(),
                version: *version,
                head: head.clone(),
                replace: *replace,
            },
            Self::AddStoreDevice {
                team_id,
                device_id,
                account_id,
                ..
            } => OwnerAction::AddStoreDevice {
                team_id: team_id.clone(),
                device_id: device_id.clone(),
                account_id: account_id.clone(),
            },
            Self::ChangeConnectGroup {
                account_id,
                group_id,
                change,
            } => OwnerAction::ChangeConnectGroup {
                account_id: account_id.clone(),
                group_id: group_id.clone(),
                change: change.clone(),
            },
            share @ (Self::ShareConnectVault { .. }
            | Self::AcceptConnectShare { .. }
            | Self::RepinConnectPeer { .. }
            | Self::JoinConnectShare { .. }
            | Self::EndConnectShare { .. }) => share_request_action(share.clone()),
            Self::SetTailnetRoute { on } => OwnerAction::SetTailnetRoute { on: *on },
            Self::RevokeNodeDevice(request) => request.action(),
            Self::AllowConnect {
                id,
                client_name,
                code,
                redirect_host,
            } => OwnerAction::AllowConnect {
                id: id.clone(),
                client_name: client_name.clone(),
                code: code.clone(),
                redirect_host: redirect_host.clone(),
            },
            Self::AddRemoteAgent { name, days } => OwnerAction::AddRemoteAgent {
                name: name.clone(),
                days: *days,
            },
            Self::TurnOnRemoteAccess => OwnerAction::TurnOnRemoteAccess,
            Self::ChooseAgentItems { agent_id, add, .. } => OwnerAction::ChangeGrants {
                agent_id: *agent_id,
                item_ids: add.clone(),
            },
        }
    }

    /// One sentence for the owner check dialog. It has no secret value.
    pub fn describe(&self) -> String {
        match self {
            Self::RemoveOlderIphone { device, .. } => format!("Remove the older paired {} '{}'? It will no longer receive or answer this vault's requests.", if device.kind == crate::vault::TrustedDeviceKind::Watch { "Apple Watch" } else { "iPhone" }, page_text(&device.name)),
            Self::AllowAccessOnce{..} => "Allow one scoped use attempt before the original request expires. The bouncer still checks the command and may ask you. This saves no grant.".into(),
            Self::BackupVault { path } => format!("Write an encrypted vault backup to {}? The vault locks afterwards.",page_text(&path.display().to_string())),
            Self::ExportDecisions => "Export the decision log to the command line.".to_owned(),
            Self::RegisterSetupAgent { name } => format!("Connect {} and let it see all credential names without values? Its token goes to the command line; the bouncer decides each use.", page_text(name)),
            Self::RegisterAgent { name } => format!("Register {} and issue its agent token to the command line?",page_text(name)),
            Self::BrowserDebugging { identity, scope, request_label, .. } => format!("{} asks to {}. Request: {}. Other programs can control all its profiles.", identity.description(), match scope { Some(crate::browser::bypass::BypassScope::Once) => "allow only the exact refused passkey or code request once", Some(crate::browser::bypass::BypassScope::FiveMinutes) => "allow owner passkeys and codes for 5 minutes across this instance", None => "trust this instance for agent fills with remote debugging" }, request_label),
            Self::ChangeOwnerFrequency { new, .. } if cfg!(target_os = "linux") => format!("Change how often Apassy asks for the owner check to {} on this computer?", new.label()),
            Self::ChangeOwnerFrequency { new, .. } => format!(
                concat!(
                    "Change how often Apassy asks for ",
                    crate::touch_id!(),
                    " to {} on this ",
                    crate::computer!(),
                    "?"
                ),
                new.label()
            ),
            Self::Reveal { .. } => "Show the secret values of this item for 30 seconds.".to_owned(),
            Self::CliCode { copy, .. } => format!("{} the current one-time code for the command line.", if *copy { "Copy" } else { "Show" }),
            Self::ShowCode { field, .. } => format!(
                "Show the code of \"{}\" for 30 seconds. The other secret values stay hidden.",
                super::owner_store::field_label(field)
            ),
            Self::CopyCode { field, .. } => format!(
                "Copy the current code of \"{}\". Apassy clears the clipboard when the code changes, if the clipboard still holds it.",
                super::owner_store::field_label(field)
            ),
            Self::CopyField { field, .. } => format!(
                "Copy “{}” for 30 seconds. Other apps may read or retain it. Apassy clears only its own clipboard entry.",
                page_text(&super::owner_store::field_label(field))
            ),
            Self::FillLogin {
                item_name,
                username,
                origin,
                ..
            } => format!(
                "Fill the login \"{item_name}\" ({username}) on {origin} in your browser. The page gets the username and the password once."
            ),
            Self::UpdateLogin { item_name, username, origin, .. } => format!(
                "For {origin}: update the password of \"{}\" ({}). The new password comes from the page. Other login details stay saved.",
                page_text(item_name),
                dialog_cut(username)
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
                request,
                accounts,
                extensions,
                ..
            } => describe_sign(request, accounts, self.passkey_account(), extensions),
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
                    #[cfg(not(target_os = "linux"))]
                    None => format!(
                        "macOS asks to create a passkey for {} with the account {account}, and save it {place}. The request comes from an app or a website through the macOS passkey sheet; macOS checked that it is for {}. If you did not ask for it just now, click Cancel.",
                        request.rp_id, request.rp_id
                    ),
                    // Linux has no system passkey sheet: a request without a page.
                    #[cfg(target_os = "linux")]
                    None => format!(
                        "An app on this computer asks to create a passkey for {} with the account {account}, and save it {place}. The request has no page address, so Apassy cannot check where it comes from. If you did not ask for it just now, click Cancel.",
                        request.rp_id
                    ),
                }
            }
            Self::ApproveRun(run) => format!(
                "Approve one run of agent \"{}\": {}",
                run.agent,
                run.command.join(" ")
            ),
            Self::ApproveAndEvaluate { run, offer, confirmations } => {
                let items = offer.items.iter().zip(confirmations).map(|(item, confirmation)| {
                    format!("\"{}\": environment {}, risk {}, hosts {} (revision {})",
                        item.name,
                        confirmation.environment.as_str(),
                        confirmation.risk.as_str(),
                        if confirmation.hosts.is_empty() { "none".to_owned() } else { confirmation.hosts.join(", ") },
                        confirmation.revision)
                }).collect::<Vec<_>>().join("; ");
                let binding = if offer.command_binding.is_some() {
                    " Only this exact command, execution context and directly selected script version."
                } else {
                    ""
                };
                format!("Allow this run of agent \"{}\" (ID {}) once: {}. Confirm {}. Enable the bouncer for {} in project \"{}\" ({}), for this agent and these credentials and hosts, from the next matching use. Later requests still require model evaluation; production, always-ask, and hard checks still apply.{}",
                    run.agent, offer.agent_id, run.command.join(" "), items,
                    action_words(offer.action), offer.project.label, offer.project.key, binding)
            },
            Self::ApproveInProject {
                run,
                project,
                action,
            } => format!(
                "Allow {} in \"{}\" for every agent, and approve this run of agent \"{}\": {}. Apassy remembers the answer for {} from the next matching use. This is an execution allowance, separate from bouncer evaluation permission and command-line pattern learning. Hard checks still apply.",
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
                "Approve one run of agent \"{}\" and remember its pattern{}: {}. This adds one command-line teaching approval. Repeated approvals can activate this pattern in the bouncer gate; this is separate from a project allowance or evaluation permission. Hard checks still apply.",
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
                "Set the task_match level of the bouncer gate to {level}%. Apassy replays all past decisions again first."
            ),
            Self::PromoteModel { version, .. } => format!(
                "Make the candidate brain {version} the active bouncer brain. Apassy checks its shadow numbers again first."
            ),
            Self::RollbackModel { from, to, .. } => {
                format!("Roll back the bouncer brain from {from} to {to}.")
            }
            Self::ChangeBouncerHosting { change } => hosting_words(change),
            Self::ChangeBouncerTraining { change } => training_words(change),
            Self::ChangeDelivery {
                name, kind, on, ..
            } => delivery_words(name, *kind, *on),
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
                "Allow this run for \"{agent}\" and mark \"{name}\" as {}.",
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
            Self::OpenCliSession => "Start a command-line session. apassy commands in your terminal can then list, add, and change credentials and agents for 30 idle minutes. Owner actions, including showing one-time codes, follow your \"How often to ask\" setting.".to_owned(),
            Self::BindVariables { variables } => match variables.len() {
                1 => "Bind 1 credential to the environment variable below. Programs get the real value.".to_owned(),
                count => format!(
                    "Bind {count} credentials to the environment variables below. Programs get the real values."
                ),
            },
            Self::PairCompanion { device_name, .. } => format!(
                "Pair the iPhone \"{device_name}\". It can see the runs that wait for you and approve them with Face ID. It can never see a secret value."
            ),
            Self::ConfirmSyncDevice { device_name, .. } => match crate::questions::device_link::split_linked_device_name(device_name) {
                // The kind is visible before Touch ID (ADR 0039 §2).
                (name, Some((crate::questions::device_link::LinkedDeviceKind::Watch, _))) => format!(
                    "Connect Apple Watch “{name}” to the sync of this vault through the Apassy relay. This watch can allow an access request once while it is unlocked on a wrist. It cannot approve runs or change access. It still needs the passphrase to open the vault."
                ),
                _ => format!(
                    "Add the device \"{device_name}\" to the sync of this vault through the Apassy relay. It gets the encrypted copy and can send changes. It still needs the passphrase to open the vault."
                ),
            },
            Self::ConfirmQuestionsDevice { device_name, .. } => {
                let (name, found) =
                    crate::questions::device_link::split_linked_device_name(device_name);
                if let Some((crate::questions::device_link::LinkedDeviceKind::Watch, _)) = found {
                    format!(
                        "Connect Apple Watch “{name}” to the questions of this vault through the Apassy relay. This watch can allow an access request once while it is unlocked on a wrist. It cannot approve runs or change access. It gets no vault and no secret value through the relay."
                    )
                } else if found.is_some() {
                    format!(
                        "Add the iPhone \"{name}\" to the questions of this vault through the Apassy relay. It can then see the questions of your agents and answer them with Face ID; Apassy keeps its keys in the vault. It gets no vault and no secret value through the relay."
                    )
                } else {
                    format!(
                        concat!("Add the ", crate::computer!(), " \"{name}\" to the questions of this vault through the Apassy relay. It can then see the questions of your agents and answer them after ", crate::touch_id_on_it!(), ". It gets no vault and no secret value through the relay.")
                    , name = name)
                }
            }
            Self::EnableRelayQuestions {
                relay_url,
                team_id: Some(_),
            } => format!(
                concat!(
                    "Send the questions of this vault through the Apassy relay at {relay_url}. Your other devices of this vault can then answer them, and ",
                    crate::allow_there!(),
                    ". The relay sees no command and no credential."
                ),
                relay_url = relay_url
            ),
            Self::EnableRelayQuestions {
                relay_url,
                team_id: None,
            } => format!(
                concat!(
                    "Connect this vault to the Apassy relay at {relay_url} for iPhone approvals. No account or subscription is needed. Your other devices of this vault can then answer the questions, and ",
                    crate::allow_there!(),
                    ". The relay sees no command and no credential."
                ),
                relay_url = relay_url
            ),
            Self::AnswerRemoteQuestion { choice, action, .. } => {
                let (agent, asker) = match action {
                    OwnerAction::AnswerRemoteQuestion { asker, answer, .. } => (
                        answer.run().map_or("the agent", |run| run.agent.as_str()),
                        asker.as_str(),
                    ),
                    _ => ("the agent", concat!("another ", crate::computer!())),
                };
                format!(
                    concat!("Answer \"{}\" to the question of {} on {}. Apassy signs the answer with the key of this ", crate::computer!(), " and sends it, end-to-end encrypted, through the relay."),
                    choice_words(choice),
                    page_text(agent),
                    page_text(asker)
                )
            }
            Self::ConfirmConnectDevice {
                device_name, words, ..
            } => format!(
                "\"{}\" asks to join your Apassy Connect account. Both devices show: {}. Confirm only if the other device shows the same words. It can then sign in to your account; it still needs the passphrase to open a vault.",
                page_text(device_name),
                page_text(words)
            ),
            Self::RevokeConnectDevice {
                device_name,
                fingerprint,
                this_device: true,
                ..
            } => format!(
                concat!("Forget this ", crate::computer!(), " (\"{}\", key {}) in your Apassy Connect account? It leaves every vault store of the account and signs out. Your vaults stay on this ", crate::computer!(), "."),
                page_text(device_name),
                page_text(fingerprint)
            ),
            Self::RevokeConnectDevice {
                device_name,
                fingerprint,
                ..
            } => format!(
                "Remove \"{}\" (key {}) from your Apassy Connect account? It signs out at once and leaves every vault store of the account. Its key fingerprint is shown in Settings › Connect on that device.",
                page_text(device_name),
                page_text(fingerprint)
            ),
            Self::DeleteConnectAccount { .. } => "Delete your Apassy Connect account? The subscription ends now, and every vault store, device, and link of the account is deleted at Connect. Your vaults stay on your devices.".to_owned(),
            Self::ForgetOldConnectAccount => concat!("Forget the Apassy Connect account on this ", crate::computer!(), "? Its account file is from an earlier version of Apassy. The file and the account key go from this ", crate::computer!(), "; nothing changes at Connect, and your vaults stay. Then join the account again from another device of the account.").to_owned(),
            Self::DeleteVaultStore { vault_name, .. } => format!(
                "Delete the relay copy of \"{}\" at Apassy Connect? Its snapshots go, and your devices stop syncing this vault through Connect. The vault stays on your devices.",
                page_text(vault_name)
            ),
            Self::TakeDepartedCopy {
                replace: false,
                device_name,
                vault_name,
                ..
            } => format!(
                concat!(
                    "Use the copy of \"{}\" that {} left on the relay? Apassy merges it with the vault on this ",
                    crate::computer!(),
                    " once, and uploads the result."
                ),
                page_text(vault_name),
                page_text(device_name)
            ),
            Self::TakeDepartedCopy {
                replace: true,
                device_name,
                vault_name,
                ..
            } => format!(
                concat!(
                    "Replace the copy of \"{}\" that {} left on the relay with the vault on this ",
                    crate::computer!(),
                    "? Changes that only that copy had are lost."
                ),
                page_text(vault_name),
                page_text(device_name)
            ),
            Self::AddStoreDevice {
                device_name,
                vault_name,
                ..
            } => format!(
                "Let \"{}\" sync the relay copy of \"{}\" at Apassy Connect? It can then read and change the encrypted copy; it still needs the passphrase to open the vault.",
                page_text(device_name),
                page_text(vault_name)
            ),
            Self::ShareConnectVault {
                peer_name,
                peer_hint,
                fingerprint,
                vault_name,
                words,
                ..
            } if words.is_empty() => format!(
                "Share \"{}\" with {} through Apassy Connect? Their devices can then read and change the encrypted copy; they still need the passphrase to open the vault.",
                page_text(vault_name),
                person_text(peer_name, peer_hint, fingerprint)
            ),
            Self::ShareConnectVault {
                peer_name,
                peer_hint,
                fingerprint,
                vault_name,
                words,
                ..
            } => format!(
                "Share \"{}\" with {} through Apassy Connect? Both devices show: {}. Their devices can then read and change the encrypted copy of this vault; they still need its passphrase.",
                page_text(vault_name),
                person_text(peer_name, peer_hint, fingerprint),
                page_text(words)
            ),
            Self::AcceptConnectShare {
                peer_name,
                peer_hint,
                fingerprint,
                words,
                ..
            } => format!(
                "Accept the vaults that {} shares with you through Apassy Connect? Both devices show: {}. Each vault is joined on its own later.",
                person_text(peer_name, peer_hint, fingerprint),
                page_text(words)
            ),
            Self::RepinConnectPeer {
                peer_name,
                peer_hint,
                old_fingerprint,
                fingerprint,
                words,
                ends,
                vault_name,
                ..
            } => {
                let ends = if ends.is_empty() {
                    "No vault is shared with the old account now.".to_owned()
                } else {
                    format!(
                        "Sharing these vaults with the old account ends first: {}.",
                        ends.iter()
                            .map(|name| format!("\"{}\"", page_text(name)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                let share = vault_name.as_deref().map_or_else(String::new, |vault| {
                    format!(" Then \"{}\" is shared with the new account.", page_text(vault))
                });
                format!(
                    "{} reset the account (old account key {}). Verify the new account key? Both devices show: {}. {}{}",
                    person_text(peer_name, peer_hint, fingerprint),
                    page_text(old_fingerprint),
                    page_text(words),
                    ends,
                    share
                )
            }
            Self::JoinConnectShare {
                peer_name,
                peer_hint,
                fingerprint,
                vault_name,
                ..
            } => format!(
                "Join \"{}\", shared by {}? This device downloads the shared copy and syncs it; you need the passphrase of the vault to open it.",
                page_text(vault_name),
                person_text(peer_name, peer_hint, fingerprint)
            ),
            Self::EndConnectShare {
                peer_name,
                peer_hint,
                fingerprint,
                vault_name,
                leave: false,
                ..
            } => format!(
                "Stop sharing \"{}\" with {}? Their devices leave the shared copy now.",
                page_text(vault_name),
                person_text(peer_name, peer_hint, fingerprint)
            ),
            Self::EndConnectShare {
                peer_name,
                peer_hint,
                fingerprint,
                vault_name,
                leave: true,
                ..
            } => format!(
                "Leave \"{}\", shared by {}? This device stops syncing the shared copy; the vault stays here.",
                page_text(vault_name),
                person_text(peer_name, peer_hint, fingerprint)
            ),
            Self::ChangeConnectGroup { change, .. } => match change {
                crate::broker::approvals::ConnectGroupChange::ConfirmMember { name, .. } => format!(
                    "Add \"{}\" to your Apassy Connect family or team? They get the plan and can join the vaults that you share.",
                    page_text(name)
                ),
                crate::broker::approvals::ConnectGroupChange::RemoveMember { name, .. } => format!(
                    "Remove \"{}\" from your Apassy Connect family or team? They keep a free account and leave the vaults that you share.",
                    page_text(name)
                ),
                crate::broker::approvals::ConnectGroupChange::SetSeats { quantity } => format!(
                    "Change your Apassy Connect plan to {quantity} people or seats? Stripe charges the difference."
                ),
            },
            Self::SetTailnetRoute { on: true } => concat!("Make this ", crate::computer!(), " reachable on your tailnet. Your iPhone and ", crate::computers!(), " then reach it directly over Tailscale. Only devices on your tailnet can connect, and each signs in with its own key.").to_owned(),
            Self::SetTailnetRoute { on: false } => concat!("Stop the tailnet route of this ", crate::computer!(), ". Approvals then go through Apassy relay.").to_owned(),
            Self::RevokeNodeDevice(request) if request.linux_vault.is_some() => format!(
                concat!("Revoke \"{}\". This ", crate::computer!(), " stops syncing through it. Its copy stays there."),
                page_text(&request.device_name)
            ),
            Self::RevokeNodeDevice(request) => format!(
                "Revoke \"{}\". It can no longer see or answer questions. To use it again, pair it again.",
                page_text(&request.device_name)
            ),
            Self::AllowConnect {
                client_name,
                code,
                redirect_host,
                ..
            } => {
                // Where the code goes back; a loopback address can be any program of this
                // Mac, as the node's listener is on the loopback (review 0.5.16).
                let local = redirect_host.is_empty()
                    || crate::questions::envelope::is_local_redirect_host(redirect_host);
                format!(
                    concat!("Connect {} to this ", crate::computer!(), " as a new agent? {}.{} Allow only if the page in your browser shows this code: {}. The name comes from the agent and is not verified. It sees no credential until you choose some, and every run asks you."),
                    page_text(client_name),
                    page_text(&crate::questions::envelope::connect_returns_to(redirect_host)),
                    if local {
                        format!(" {}", crate::questions::envelope::LOCAL_CONNECT_WARNING)
                    } else {
                        String::new()
                    },
                    page_text(code)
                )
            }
            Self::AddRemoteAgent { name, days } => format!(
                "Add the remote agent {} and issue its token to the command line? The token works for {days} days. The agent sees no credential until you choose some, and every run asks you.",
                page_text(name)
            ),
            Self::TurnOnRemoteAccess => concat!("Turn on remote access? Remote agents can then reach this ", crate::computer!(), " through Tailscale Funnel while it is awake and the vault is unlocked. The name of this ", crate::computer!(), " appears in public certificate logs. Every remote run still asks you.").to_owned(),
            Self::ChooseAgentItems {
                agent_name, add, ..
            } => format!(
                "Let {} use {}? It sees their names, never their values. The bouncer still decides each use.",
                page_text(agent_name),
                if add.len() == 1 {
                    "1 more credential".to_owned()
                } else {
                    format!("{} more credentials", add.len())
                }
            ),
        }
    }
}

/// The owner check text of a change of the bouncer brain host: what leaves the Mac and
/// the trust warning (ADR 0035 sections 1, 4 and 5). No bearer.
fn hosting_words(change: &crate::vault::BouncerHostChange) -> String {
    use crate::vault::BouncerHostKind;
    let url = page_text(&change.normalized_url());
    let sent = concat!(
        "Each bouncer request goes there: the user request, purpose, and shell command, with item values masked and project and home paths shortened. The bouncer heads trained on your decisions go there too: numbers, no text. No secret value, the vault, or a full path of your project or home folder leaves this ",
        crate::computer!(),
        ", and the bouncer gate still decides on this ",
        crate::computer!(),
        "."
    );
    let trust = crate::desktop::brain_hosting_ui::TRUST_WARNING;
    match change.kind {
        BouncerHostKind::ThisMac => concat!(
            "Run the bouncer brain on this ",
            crate::computer!(),
            " again. Bouncer requests stay on this ",
            crate::computer!(),
            "."
        )
        .to_owned(),
        BouncerHostKind::OwnServer => {
            format!("Use the bouncer brain on your server at {url}. {sent} {trust}")
        }
        BouncerHostKind::Connect => format!(
            "Use the bouncer brain of Apassy Connect at {url}. {sent} Apassy keeps a request in memory only while it answers it. {trust}"
        ),
    }
}

/// The owner check text of a change of the bouncer brain trainer (ADR 0035 sections 1
/// and 4). No bearer.
/// The text of a change of the delivery of a source item. It names the item and what
/// each run gets, never a value.
fn delivery_words(name: &str, kind: crate::vault::ShortLivedKind, on: bool) -> String {
    let name = dialog_cut(name);
    let lease = match kind {
        crate::vault::ShortLivedKind::GithubApp => "a GitHub token that is revoked after the run",
        crate::vault::ShortLivedKind::AwsSts
        | crate::vault::ShortLivedKind::GoogleServiceAccount => {
            "a credential that expires in 15 minutes"
        }
        _ => "a credential made for that run",
    };
    // While runs make no lease, the text promises none (plan s6 unit F flips it).
    if on && !crate::vault::LEASES_IN_RUNS {
        format!(
            "Use temporary credentials for \"{name}\". This version of Apassy does not make them in runs yet: runs of this item fail until it does, and they never get the long-lived key instead."
        )
    } else if on {
        format!(
            "Use temporary credentials for \"{name}\". Each run gets {lease}; the long-lived key stays in Apassy."
        )
    } else if let Some(names) = crate::vault::static_variable_names(kind) {
        format!(
            "Stop temporary credentials for \"{name}\". Runs then get the long-lived key itself in {names}."
        )
    } else {
        format!(
            "Stop temporary credentials for \"{name}\". Runs then get the long-lived key as the variable says (a placeholder or the value)."
        )
    }
}

fn training_words(change: &crate::vault::BouncerHostChange) -> String {
    use crate::vault::BouncerHostKind;
    let url = page_text(&change.normalized_url());
    let sent = "For each training, the training examples go there: your past decisions with their requests, without secret values. A new head set always starts in shadow mode, and only you promote it.";
    match change.kind {
        BouncerHostKind::ThisMac => concat!(
            "Train the bouncer brain on this ",
            crate::computer!(),
            " again. Training examples stay on this ",
            crate::computer!(),
            "."
        )
        .to_owned(),
        BouncerHostKind::OwnServer => {
            format!("Train the bouncer brain on your server at {url}. {sent}")
        }
        BouncerHostKind::Connect => format!(
            "Train the bouncer brain at Apassy Connect ({url}). {sent} Apassy deletes the examples when the job ends, and at the latest after 24 hours."
        ),
    }
}

/// The words of a remote answer for the owner check dialog.
fn choice_words(choice: &Choice) -> String {
    match choice {
        Choice::Approve => "Allow".to_owned(),
        Choice::ApproveAsDevelopment => "Allow as dev".to_owned(),
        Choice::ApproveAsProduction => "Allow as prod".to_owned(),
        Choice::DenyWithComment { .. } => "Dismiss with comment".to_owned(),
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
/// The text of an assertion. Besides the signature it names what the WebAuthn
/// extensions give or store ([`PasskeyExtras::sentences`]), for the chosen account, or
/// for any account before the choice.
fn describe_sign(
    request: &PasskeyRequest,
    accounts: &[PasskeyAccount],
    chosen: Option<&PasskeyAccount>,
    extensions: &PasskeyRequestExtensions,
) -> String {
    let Some(account) = chosen else {
        let extras = PasskeyExtras::of(&extensions.for_any_credential()).sentences();
        return match &request.origin {
            Some(origin) => format!(
                "For {origin}: sign in to {} with a passkey. The page gets one signature.{extras} Choose the account before you confirm.",
                request.rp_id
            ),
            #[cfg(not(target_os = "linux"))]
            None => format!(
                "macOS asks to sign in to {} with a passkey. The request comes from an app or a website through the macOS passkey sheet; macOS checked that it is for {}.{extras} Choose the account before you confirm. If you did not just sign in, click Cancel.",
                request.rp_id, request.rp_id
            ),
            #[cfg(target_os = "linux")]
            None => format!(
                "An app on this computer asks to sign in to {} with a passkey. The request has no page address, so Apassy cannot check where it comes from.{extras} Choose the account before you confirm. If you did not just sign in, click Cancel.",
                request.rp_id
            ),
        };
    };
    let extras = PasskeyExtras::of(&extensions.for_credential(&account.credential_id)).sentences();
    let who = account_text(&account.user_name, &account.user_display_name);
    let login = page_text(&account.item_name);
    let mut text = match &request.origin {
        Some(origin) => format!(
            "For {origin}: sign in to {} as {who} with the passkey of the login \"{login}\". The page gets one signature.{extras}",
            request.rp_id
        ),
        #[cfg(not(target_os = "linux"))]
        None => format!(
            "macOS asks to sign in to {} as {who} with the passkey of the login \"{login}\". The request comes from an app or a website through the macOS passkey sheet; macOS checked that it is for {}.{extras} If you did not just sign in, click Cancel.",
            request.rp_id, request.rp_id
        ),
        #[cfg(target_os = "linux")]
        None => format!(
            "An app on this computer asks to sign in to {} as {who} with the passkey of the login \"{login}\". The request has no page address, so Apassy cannot check where it comes from.{extras} If you did not just sign in, click Cancel.",
            request.rp_id
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
    /// Binds queued native text-edit commands to this exact confirmation.
    pub(crate) identity: u64,
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

fn next_check_dialog_identity() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    })
    .expect("owner confirmation identity exhausted")
}

/// Touch ID unlock state for the open vault file.
#[derive(Default)]
pub(crate) struct UnlockState {
    pub(crate) auto_started: bool,
    /// The vault file of `setting`.
    pub(crate) path: Option<PathBuf>,
    pub(crate) setting: Option<UnlockSetting>,
    pub(crate) reading: Option<Task<UnlockSetting>>,
    pub(crate) unlocking: Option<Task<Result<Zeroizing<String>, TouchIdUnlockError>>>,
    pub(crate) check_generation: Option<u64>,
    pub(crate) changing: Option<Task<Result<String, String>>>,
    /// Touch ID setup verifies the passphrase outside OwnerGate (audit M33).
    pub(crate) fresh_setup: Option<(u64, [u8; 32])>,
    /// The passphrase for Touch ID setup (A2). The app erases it after each try.
    pub(crate) setup_passphrase: String,
}

/// All owner-check, unlock, and notification state of the app. One field in
/// [`DesktopApp`].
#[derive(Default)]
pub struct OwnerFlows {
    /// `None` in tests and when the app cannot find its own executable.
    pub(crate) helper: Option<NativeHelper>,
    pub(crate) lifecycle: Option<crate::native::owner_lifecycle::OwnerLifecycle>,
    /// Linux: screen lock, sleep and session observation (D-Bus), the counterpart of
    /// `lifecycle`. Empty on macOS and in tests.
    pub(crate) session: crate::desktop::session_watch::SessionWatch,
    pub(crate) frequency_read:
        Option<Task<Result<crate::broker::approvals::OwnerFrequency, String>>>,
    pub(crate) frequency_write:
        Option<Task<Result<crate::broker::approvals::OwnerFrequency, String>>>,
    pub(crate) frequency_note: Option<String>,
    pub(crate) native: NativeState,
    native_probe: Option<Task<NativeState>>,
    pub(crate) check_probe: Option<(u64, Task<NativeState>)>,
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
    /// The proof of the last Apassy Connect account check (`OwnerRequest::
    /// ConfirmConnectDevice` and the other Connect requests), until the Connect view
    /// takes it ([`OwnerFlows::take_connect_proof`]): the account call takes the proof
    /// by value, so it works once. A lock drops it; it is bound to the vault session and
    /// lives 60 s.
    connect_proof: Option<OwnerProof>,
}

impl OwnerFlows {
    /// Take the proof of the last Connect account check, once: the slot is empty after
    /// it, also when the account call then fails (B-L1).
    pub(crate) fn take_connect_proof(&mut self) -> Option<OwnerProof> {
        self.connect_proof.take()
    }

    /// Text about Touch ID for the owner check. `None` when Touch ID can run.
    pub(crate) fn touch_id_note(&self) -> Option<String> {
        if cfg!(target_os = "linux") {
            return Some("Confirm with your vault passphrase. System authentication is optional and requires an installed polkit policy.".to_owned());
        }
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
        // Apple helpers must never become an accidental Linux authentication path.
        let helper = if cfg!(target_os = "macos") {
            NativeHelper::locate().ok()
        } else {
            None
        };
        self.owner.helper = helper.clone();
        // Linux: the D-Bus observer feeds the owner window and auto-lock, and the two
        // device settings live in a private file (no helper, no keychain).
        #[cfg(target_os = "linux")]
        {
            use crate::desktop::session_watch::{SessionWatch, store};
            self.owner.session = SessionWatch::start(
                self.owner_ui.session.owner_window.clone(),
                self.auto_lock.source.clone(),
                ctx.clone(),
            );
            self.start_auto_lock_task(ctx, store::read_auto_lock);
            self.owner.frequency_read =
                Some(Task::spawn(Some(ctx.clone()), store::read_owner_frequency));
        }
        if let Some(helper) = &helper {
            self.owner.lifecycle = crate::native::owner_lifecycle::OwnerLifecycle::start(
                helper,
                self.owner_ui.session.owner_window.clone(),
                self.auto_lock.source.clone(),
                ctx.clone(),
            )
            .ok();
            self.start_auto_lock_read(helper.clone(), ctx);
            let helper = helper.clone();
            self.owner.frequency_read = Some(Task::spawn(Some(ctx.clone()), move || {
                helper.owner_policy_read().map_err(|e| e.to_string())
            }));
        }
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
        .with_window(self.owner_ui.session.owner_window.clone())
    }

    /// Ask the owner to confirm `request` (goal item A4). Nothing happens before the
    /// check passes. Touch ID starts at once when it is available.
    pub(crate) fn ask_owner(&mut self, request: OwnerRequest, ctx: Option<&egui::Context>) {
        self.prepare_owner(request, ctx, true);
    }

    /// Prepare the exact action before attaching its source ticket. Reuse is only
    /// attempted after provenance and ticket liveness have been checked.
    pub(crate) fn prepare_owner(
        &mut self,
        request: OwnerRequest,
        ctx: Option<&egui::Context>,
        start: bool,
    ) {
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
            identity: next_check_dialog_identity(),
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
        if start
            && self
                .owner
                .check
                .as_ref()
                .is_some_and(|d| d.request.is_ready())
            && let Some(proof) = self.owner_gate().reuse_local(
                self.owner.check.as_ref().unwrap().request.action(),
                crate::broker::approvals::LocalWindowSource::LocalOwner,
            )
        {
            let dialog = self.owner.check.take().expect("checked dialog");
            self.finish_owner_check(dialog, proof);
            return;
        }
        if start && starts {
            self.probe_owner_biometry(ctx.cloned());
        }
    }

    pub(crate) fn start_local_owner(
        &mut self,
        source: crate::broker::approvals::LocalWindowSource,
        eligible: bool,
        ctx: &egui::Context,
    ) {
        let Some(dialog) = self.owner.check.as_ref() else {
            return;
        };
        if eligible
            && dialog.request.is_ready()
            && let Some(proof) = self
                .owner_gate()
                .reuse_local(dialog.request.action(), source)
        {
            let dialog = self.owner.check.take().expect("checked dialog");
            self.finish_owner_check(dialog, proof);
            return;
        }
        if dialog.request.starts_touch_id() {
            self.probe_owner_biometry(Some(ctx.clone()));
        }
    }

    fn probe_owner_biometry(&mut self, ctx: Option<egui::Context>) {
        let Some(helper) = self.owner.helper.clone() else {
            tracing::info!(biometry = "no_helper", "owner check biometry");
            return;
        };
        let Some(dialog) = self.owner.check.as_ref() else {
            return;
        };
        self.owner.check_probe = Some((
            dialog.identity,
            Task::spawn(ctx, move || match helper.ping() {
                Ok(info) => NativeState {
                    biometry: Some(info.biometry),
                    problem: None,
                },
                Err(_) => NativeState {
                    biometry: None,
                    problem: Some("helper probe failed".into()),
                },
            }),
        ));
    }

    pub(crate) fn development_clicked(&mut self, request: OwnerRequest, ctx: &egui::Context) {
        self.prepare_owner(request, Some(ctx), false);
        self.start_local_owner(
            crate::broker::approvals::LocalWindowSource::DevelopmentClick,
            true,
            ctx,
        );
    }

    /// Called only after the owner clicks Allow once for this exact pending run.
    pub(crate) fn allow_once_clicked(&mut self, request: OwnerRequest, ctx: &egui::Context) {
        self.prepare_owner(request, Some(ctx), false);
        self.start_local_owner(
            crate::broker::approvals::LocalWindowSource::AllowOnceClick,
            true,
            ctx,
        );
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
        dialog.identity = next_check_dialog_identity();
        dialog.running = None;
        dialog.message = None;
    }

    /// Run the gate on a worker thread for the open dialog.
    pub(crate) fn start_owner_check(&mut self, check: OwnerCheck, ctx: Option<egui::Context>) {
        self.owner.check_probe = None;
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
        self.owner.check_probe = None;
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
        let approvals = self.approvals();
        let session = &mut self.owner_ui.session;
        match request {
            OwnerRequest::BrowserDebugging { identity, scope, binding, .. } => {
                let action = OwnerAction::BrowserDebugging { identity: identity.clone(), scope, binding: binding.clone() };
                if !session.epoch().is_some_and(|epoch| proof.check(&action, &epoch).is_ok()) { self.set_err("The owner check changed."); return; }
                if let Some(scope) = scope {
                    self.browser.bypass = Some(crate::browser::bypass::OwnerPasskeyCodeBypass::approved(identity, scope, Instant::now()));
                    if let Some(grant) = &mut self.browser.bypass { grant.binding = binding; }
                    self.browser.bypass_epoch = session.epoch();
                    self.browser.bypass_generation = session.owner_window.generation();
                    self.set_ok("Browser bypass approved.");
                } else {
                    self.browser.trusted_instances = None;
                    let Some(epoch) = session.epoch() else { return; };
                    match crate::browser::trust::add(&identity, proof, epoch) { Ok(()) => self.set_ok(concat!("Instance trusted on this ", crate::computer!(), ".")), Err(e) => self.set_err(e) }
                }
            }
            OwnerRequest::BackupVault { path } => self.complete_fresh_backup(&path, proof),
            OwnerRequest::ExportDecisions => self.complete_fresh_export(proof),
            OwnerRequest::RegisterAgent { name } => self.complete_fresh_agent(&name, false, proof),
            OwnerRequest::RegisterSetupAgent { name } => self.complete_fresh_agent(&name, true, proof),
            OwnerRequest::ChangeOwnerFrequency { old, new } => self.save_owner_frequency(old, new, proof),
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
            OwnerRequest::CliCode { item_id, field, copy } => self.complete_cli_code(item_id, &field, copy, proof),
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
            OwnerRequest::CopyField { item_id, field, revision } => {
                self.complete_copy_field(item_id, &field, revision, proof)
            }
            OwnerRequest::FillLogin {
                item_id, origin, ..
            } => self.complete_fill(item_id, &origin, proof),
            OwnerRequest::UpdateLogin { item_id, revision, username, origin, .. } => {
                self.complete_browser_update(item_id, revision, &username, &origin, proof)
            }
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
            OwnerRequest::ApproveAndEvaluate { run, .. } => {
                let result = match self.approvals() {
                    Some(approvals) => approvals.approve(proof).map_err(|r| r.message()),
                    None => Err("The broker is not running. Nothing was approved."),
                };
                match result {
                    Ok(()) => self.set_ok(format!("The run of {} is approved once. After the broker rechecks it, matching later uses can be evaluated by the bouncer.", run.agent)),
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
                        "Allowed. Apassy remembers {} in {} for all agents from the next matching use, after the broker rechecks it. Hard checks still apply.",
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
                run,
                agent,
                item_id,
                name,
                environment,
                ..
            } => match approvals.as_ref().ok_or_else(|| super::model::ModelError {
                code: "not_waiting",
                message: "The question no longer offers this correction.".into(),
            }).and_then(|queue| session.correct_environment(queue, &run, item_id, environment, proof)) {
                Ok(()) => self.set_ok(format!(
                    "Allowed for {agent}. {name} will be marked as {} after the final credential check.",
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
            OwnerRequest::ChangeBouncerHosting { change } => {
                self.change_bouncer_host(crate::vault::BouncerHostRole::Hosting, change, proof);
            }
            OwnerRequest::ChangeBouncerTraining { change } => {
                self.change_bouncer_host(crate::vault::BouncerHostRole::Training, change, proof);
            }
            OwnerRequest::ChangeDelivery {
                item_id,
                name,
                kind,
                on,
            } => self.complete_change_delivery(item_id, &name, kind, on, proof),
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
            OwnerRequest::AllowAccessOnce{request_id,..} => {
                let result=session.with_vault(|v|crate::broker::access_once::local_answer(v,request_id,crate::questions::access_request::Choice::AllowOnce,Some(proof)));
                match result {Some(Ok(()))=>self.set_ok("Consent recorded for one attempt. The bouncer still checks the command."),Some(Err(e))=>self.set_err(e),None=>self.set_err("Unlock the vault first.")}
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
            OwnerRequest::RemoveOlderIphone { device, team } => self.questions_remove_older_device(&device.uuid,&team,proof),
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
            // The Connect view takes the proof and runs the step (plan s7 M1/M2); the
            // account checks it again against the exact action before it calls Connect.
            OwnerRequest::ConfirmConnectDevice { .. }
            | OwnerRequest::RevokeConnectDevice { .. }
            | OwnerRequest::DeleteConnectAccount { .. }
            | OwnerRequest::ForgetOldConnectAccount
            | OwnerRequest::DeleteVaultStore { .. }
            | OwnerRequest::TakeDepartedCopy { .. }
            | OwnerRequest::AddStoreDevice { .. }
            | OwnerRequest::ChangeConnectGroup { .. }
            | OwnerRequest::ShareConnectVault { .. }
            | OwnerRequest::AcceptConnectShare { .. }
            | OwnerRequest::RepinConnectPeer { .. }
            | OwnerRequest::JoinConnectShare { .. }
            | OwnerRequest::EndConnectShare { .. } => {
                self.owner.connect_proof = Some(proof);
            }
            OwnerRequest::SetTailnetRoute { on } => self.devices_set_route(on, proof),
            OwnerRequest::RevokeNodeDevice(request) => self.devices_revoke(&request, proof),
            OwnerRequest::AllowConnect {
                id,
                client_name,
                code,
                redirect_host,
            } => self.complete_allow_connect(&id, &client_name, &code, &redirect_host, proof),
            OwnerRequest::AddRemoteAgent { name, days } => {
                self.complete_add_remote_agent(&name, days, proof);
            }
            OwnerRequest::TurnOnRemoteAccess => self.complete_remote_access_on(proof),
            OwnerRequest::ChooseAgentItems {
                agent_id,
                agent_name,
                add,
            } => {
                let action = OwnerAction::ChangeGrants {
                    agent_id,
                    item_ids: add.clone(),
                };
                let result = session.with_vault(|vault| {
                    proof
                        .check(&action, &vault.epoch())
                        .map_err(|refusal| refusal.message().to_owned())?;
                    for item_id in &add {
                        vault
                            .add_agent_exception(
                                agent_id,
                                *item_id,
                                crate::vault::exceptions::ExceptionKind::Only,
                            )
                            .map_err(|err| format!("The credentials did not change: {err}."))?;
                    }
                    Ok::<(), String>(())
                });
                match result {
                    Some(Ok(())) => {
                        self.sync_remote_catalog();
                        self.set_ok(format!(
                            "{} can use the chosen credentials. The bouncer decides each use.",
                            page_text(&agent_name)
                        ));
                    }
                    Some(Err(message)) => self.set_err(message),
                    None => self.set_err("The vault is locked."),
                }
            }
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

    /// Mark the environment of an item as the answer of the owner: the environment and
    /// its source "owner" change (ADR 0025 §4). The project of a pasted credential
    /// stays empty, and the other sources stay. A risk or a reversibility that is only a
    /// default follows the environment ([`crate::vault::Vault::set_declaration_environment`],
    /// ADR 0031 of 2026-11-03); the other values stay.
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

    /// Turn way C on or off for a source item with `proof` (contract private-sharing-v1
    /// rule 3). The proof must name the item, the kind of its row, and the new state; the
    /// row keeps its kind and settings.
    fn complete_change_delivery(
        &mut self,
        item_id: u64,
        name: &str,
        kind: crate::vault::ShortLivedKind,
        on: bool,
        proof: OwnerProof,
    ) {
        let action = OwnerAction::ChangeDelivery {
            item: item_id,
            kind,
            on,
        };
        let result = self.owner_ui.session.with_vault(|vault| {
            proof
                .check(&action, &vault.epoch())
                .map_err(|refusal| refusal.message().to_owned())?;
            // The stored kind must be the kind that the owner confirmed.
            match vault.short_lived(item_id) {
                Ok(Some(row)) if row.kind == kind => {}
                Ok(_) => return Err("The item changed. Nothing changed.".to_owned()),
                Err(err) => return Err(format!("The delivery did not change: {err}.")),
            }
            vault
                .set_short_lived_enabled(
                    item_id,
                    on,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_secs()),
                )
                .map_err(|err| format!("The delivery did not change: {err}."))
        });
        match result {
            Some(Ok(())) if on => self.set_ok(format!("{name} now gives temporary credentials.")),
            Some(Ok(())) => self.set_ok(match crate::vault::static_variable_names(kind) {
                Some(names) => format!(
                    "{name} no longer gives temporary credentials. Runs get its long-lived key in {names}."
                ),
                None => format!(
                    "{name} no longer gives temporary credentials. Runs get its long-lived key."
                ),
            }),
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

    /// Release only the exact approved field to the expiring clipboard. No revealed
    /// value or reusable authorization is left in the view.
    fn complete_copy_field(&mut self, item_id: u64, field: &str, revision: u64, proof: OwnerProof) {
        let Some(epoch) = self.owner_ui.session.epoch() else {
            self.set_err("The vault is locked. Nothing was copied.");
            return;
        };
        let value = match self
            .owner_ui
            .session
            .copy_field(item_id, field, revision, proof)
        {
            Ok(value) => value,
            Err(err) => {
                self.set_err(err.message);
                return;
            }
        };
        match self
            .owner
            .clipboard
            .copy_secret(value, epoch, std::time::Instant::now())
        {
            Ok(_) => self
                .set_ok("Copied. Clears in 30 seconds if the clipboard still holds Apassy's copy."),
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
            mut platform,
            ..
        } = dialog;
        let fence = proof.delivery_fence(self.owner_ui.session.shared_vault());
        if let Some(ticket) = &mut browser {
            ticket.delivery_fence = Some(fence.clone());
        }
        if let Some(ticket) = &mut platform {
            ticket.delivery_fence = Some(fence);
        }
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

    pub(crate) fn finish_biometry_probe(
        &mut self,
        identity: u64,
        state: NativeState,
        ctx: &egui::Context,
    ) {
        tracing::info!(biometry = ?state.biometry, "owner check biometry");
        if self
            .owner
            .check
            .as_ref()
            .is_some_and(|d| d.identity == identity && d.running.is_none())
        {
            self.owner.native = state;
            if self.owner.touch_id_ready() {
                self.start_owner_check(OwnerCheck::TouchId, Some(ctx.clone()));
            }
        }
    }

    /// Poll the worker threads. The UI calls this at the start of each frame.
    pub(crate) fn poll_owner_flows(&mut self, ctx: &egui::Context) {
        if let Some((identity, probe)) = &self.owner.check_probe {
            let identity = *identity;
            let state = match probe.poll() {
                TaskPoll::Waiting => None,
                TaskPoll::Done(state) => Some(state),
                TaskPoll::Lost => Some(NativeState {
                    biometry: None,
                    problem: Some("helper probe failed".into()),
                }),
            };
            if let Some(state) = state {
                self.owner.check_probe = None;
                self.finish_biometry_probe(identity, state, ctx);
            }
        }
        if let Some(probe) = &self.owner.native_probe
            && let TaskPoll::Done(state) = probe.poll()
        {
            self.owner.native = state;
            self.owner.native_probe = None;
        }
        self.poll_owner_frequency(ctx);
        self.poll_owner_check(ctx);
        self.expire_browser_check(ctx);
        self.expire_platform_check(ctx);
        self.poll_unlock(ctx);
        self.poll_companion(ctx);
        self.questions_poll(ctx);
        self.poll_remote_feeds();
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
                self.owner.check_probe = None;
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
        if unlock.path != path {
            unlock.auto_started = false;
            unlock.unlocking = None;
            unlock.check_generation = None;
        }
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
        self.owner.unlock.check_generation = Some(self.owner_ui.session.owner_window.generation());
        // The Apassy Connect key of this Mac comes with the same Touch ID: the account
        // session opens with this unlock and asks for nothing more (plan s7 unit M5b).
        let connect = self.connect_session();
        let also = self.connect_key_with_unlock();
        connect.drop_offered();
        self.owner.unlock.unlocking = Some(Task::spawn(Some(ctx.clone()), move || {
            let (key, account_key) = unlock::read_unlock_key_with(&helper, &path, also)?;
            if let Some(account_key) = account_key {
                connect.offer_key(account_key);
            }
            Ok(key)
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
        self.owner.unlock.fresh_setup = self
            .owner_ui
            .session
            .epoch()
            .map(|epoch| (self.owner_ui.session.owner_window.generation(), epoch));
        let vault = self.owner_ui.session.shared_vault();
        let fresh = self.owner.unlock.fresh_setup;
        let window = self.owner_ui.session.owner_window.clone();
        self.owner.unlock.changing = Some(Task::spawn(Some(ctx.clone()), move || {
            let result = unlock::turn_on_after_verification(&helper, &vault, typed, || {
                let slot = vault
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some((generation, epoch)) = fresh
                    && slot
                        .as_ref()
                        .is_some_and(|v| !v.is_locked() && v.epoch() == epoch)
                {
                    window.seed(
                        epoch,
                        crate::broker::approvals::CheckMethod::Passphrase,
                        generation,
                    );
                }
            });
            result.map(|()| "Touch ID unlock is on. Touch ID can unlock this vault file now. The passphrase still works.".to_owned())
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
        self.owner.unlock.fresh_setup = None;
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
                self.owner.unlock.fresh_setup.take();
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
        if !self.owner_ui.session.is_locked() {
            self.owner.unlock.check_generation = None;
            drop(result); // Zeroizing erases a late key; errors are stale too.
            self.connect_session().drop_offered();
            return;
        }
        let key = match result {
            Ok(key) => key,
            Err(err) => {
                self.connect_session().drop_offered();
                self.owner_ui.session.owner_window.invalidate();
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
        let Some(generation) = self.owner.unlock.check_generation.take() else {
            self.connect_session().drop_offered();
            self.owner_ui.session.owner_window.invalidate();
            self.set_err("The unlock check ended. Confirm again.");
            return;
        };
        let result = self.owner_ui.session.unlock_checked(
            &key,
            Some(generation),
            crate::broker::approvals::CheckMethod::TouchId,
        );
        drop(key);
        // The account session opens with the key of the same Touch ID, or never.
        if result.is_ok() {
            self.connect_after_unlock();
        }
        self.connect_session().drop_offered();
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
        self.owner.unlock.auto_started = false;
        self.owner.unlock.unlocking = None;
        self.owner.unlock.check_generation = None;
        self.browser.bypass = None;
        super::ui::invalidate_notifications(self);
        self.ui.discard_item_changes = false;
        self.ui.discard_item_kind_change = false;
        self.files.forget();
        // The node of cloud agents stops first, so its session rows are written while
        // the vault is open: every session ends and the Funnel route goes off.
        self.stop_node();
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
        // The feeds of the other Macs go with the session (relay-feed-v1).
        self.forget_remote_feeds();
        // A Connect proof of this session is worthless after the lock.
        self.owner.connect_proof = None;
        // The Connect account session closes with the vault: its key and token go.
        self.connect_lock();
        self.erase_typed_secrets(ctx);
    }

    /// Erase every typed passphrase and secret, and the undo history of the fields.
    pub(crate) fn erase_typed_secrets(&mut self, ctx: Option<&egui::Context>) {
        self.ui.decisions.forget_evaluation();
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
        // The node of cloud agents: sessions end, the Funnel route goes off.
        self.stop_node();
        let approvals = self.approvals();
        let _ = self
            .owner_ui
            .session
            .lock_ending_runs(approvals.as_deref(), ENDED_BY_QUIT);
        self.stop_companion();
        self.connect_lock();
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

#[cfg(test)]
mod change_delivery_tests {
    use super::*;
    use crate::vault::ShortLivedKind;

    #[test]
    fn the_delivery_request_names_its_exact_action_and_no_value() {
        for on in [true, false] {
            let request = OwnerRequest::ChangeDelivery {
                item_id: 7,
                name: "Synthetic AWS".to_owned(),
                kind: ShortLivedKind::AwsSts,
                on,
            };
            assert_eq!(
                request.action(),
                OwnerAction::ChangeDelivery {
                    item: 7,
                    kind: ShortLivedKind::AwsSts,
                    on,
                }
            );
            assert!(request.is_ready());
            assert!(!request.needs_live_ticket());
            let text = request.describe();
            assert!(text.contains("\"Synthetic AWS\""), "{text}");
            if on && crate::vault::LEASES_IN_RUNS {
                assert!(text.contains("15 minutes"), "{text}");
            } else if on {
                // No promise of a lease while runs make none.
                assert!(!text.contains("15 minutes"), "{text}");
                assert!(text.contains("does not make them in runs yet"), "{text}");
            } else {
                // The static form names the variables of the long-lived key.
                assert!(text.contains("long-lived key"), "{text}");
                assert!(
                    text.contains("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"),
                    "{text}"
                );
            }
            assert!(!text.contains("AKIA") && !text.contains("secret_access_key"));
        }
        let google = OwnerRequest::ChangeDelivery {
            item_id: 8,
            name: "Synthetic service account".to_owned(),
            kind: ShortLivedKind::GoogleServiceAccount,
            on: false,
        }
        .describe();
        assert!(google.contains("in GOOGLE_API_KEY"), "{google}");
        assert!(!google.contains("CLOUDSDK_AUTH_ACCESS_TOKEN"), "{google}");
    }
}

#[cfg(test)]
mod connect_proof_tests {
    use super::*;

    /// B-L1: the Connect view takes the proof once; the slot is then empty, so a second
    /// account call has no proof to use.
    #[test]
    fn the_connect_proof_is_taken_once() {
        let mut flows = OwnerFlows::default();
        assert!(flows.take_connect_proof().is_none());
        let action = OwnerAction::DeleteVaultStore {
            team_id: "t".repeat(32),
        };
        flows.connect_proof = Some(OwnerProof::issue_for_test(
            action.clone(),
            [1; 32],
            std::time::Instant::now(),
        ));
        let proof = flows.take_connect_proof().expect("the proof");
        assert_eq!(proof.check(&action, &[1; 32]), Ok(()));
        assert!(flows.take_connect_proof().is_none());
    }

    /// B-M1: the store requests name their exact actions, and their texts name the vault
    /// and the device, never an id.
    #[test]
    fn the_store_requests_name_their_actions() {
        let team = "t".repeat(32);
        let delete = OwnerRequest::DeleteVaultStore {
            team_id: team.clone(),
            vault_name: "Personal".to_owned(),
        };
        assert_eq!(
            delete.action(),
            OwnerAction::DeleteVaultStore {
                team_id: team.clone()
            }
        );
        assert!(delete.action().needs_fresh_local_check());
        assert!(delete.describe().contains("\"Personal\""));
        let add = OwnerRequest::AddStoreDevice {
            team_id: team.clone(),
            device_id: "dev_p4n6r2t7bc".to_owned(),
            account_id: "acc_m3n5p7q2rb".to_owned(),
            device_name: "iPhone".to_owned(),
            vault_name: "Personal".to_owned(),
        };
        assert_eq!(
            add.action(),
            OwnerAction::AddStoreDevice {
                team_id: team,
                device_id: "dev_p4n6r2t7bc".to_owned(),
                account_id: "acc_m3n5p7q2rb".to_owned(),
            }
        );
        assert!(add.action().needs_fresh_local_check());
        let text = add.describe();
        assert!(
            text.contains("\"iPhone\"") && !text.contains("dev_"),
            "{text}"
        );
    }
}

#[cfg(test)]
mod connect_prompt_tests {
    use super::OwnerRequest;

    /// The owner compares the code of the browser page with this one: the prompt names
    /// the page in the browser, not "the agent", and says that the connect makes a new
    /// agent (security review finding 1d).
    #[test]
    fn the_allow_connect_prompt_asks_to_compare_the_code_of_the_browser_page() {
        let request = OwnerRequest::AllowConnect {
            id: "cr_1".to_owned(),
            client_name: "Grok Bot".to_owned(),
            code: "K7Q-4MD".to_owned(),
            redirect_host: "grok.example".to_owned(),
        };
        let text = request.describe();
        assert!(
            text.contains("Allow only if the page in your browser shows this code: K7Q-4MD."),
            "{text}"
        );
        assert!(
            text.starts_with(concat!(
                "Connect Grok Bot to this ",
                crate::computer!(),
                " as a new agent? Returns to grok.example. Allow only"
            )),
            "{text}"
        );
        assert!(!text.contains("page of the agent"), "{text}");
        assert!(
            !text.contains(concat!("A program on this ", crate::computer!())),
            "{text}"
        );
    }

    /// Review 0.5.16: the node's listener is on the loopback, so any program of this Mac
    /// can start a connect request whose code goes back to localhost. The prompt says so.
    #[test]
    fn the_allow_connect_prompt_says_a_program_on_this_mac_can_start_a_localhost_request() {
        for host in ["127.0.0.1", "localhost", "[::1]", ""] {
            let request = OwnerRequest::AllowConnect {
                id: "cr_1".to_owned(),
                client_name: "Grok Bot".to_owned(),
                code: "K7Q-4MD".to_owned(),
                redirect_host: host.to_owned(),
            };
            let text = request.describe();
            assert!(
                text.contains(concat!(
                    "A program on this ",
                    crate::computer!(),
                    " can start this request."
                )),
                "{host}: {text}"
            );
            assert!(text.contains("K7Q-4MD"), "{text}");
            if !host.is_empty() {
                assert!(
                    text.contains("Returns to a program on a computer (localhost)."),
                    "{text}"
                );
            }
        }
        // The proof binds the host: another host is another action.
        let action = |host: &str| {
            OwnerRequest::AllowConnect {
                id: "cr_1".to_owned(),
                client_name: "Grok Bot".to_owned(),
                code: "K7Q-4MD".to_owned(),
                redirect_host: host.to_owned(),
            }
            .action()
        };
        assert_ne!(action("grok.example"), action("127.0.0.1"));
    }
}
