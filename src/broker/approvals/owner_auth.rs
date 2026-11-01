//! Owner authorization for sensitive owner actions (goal item A4, ADR 0010).
//!
//! Reveal, a fill, a save, a new login, a one-time code, or a passkey in the browser
//! (ADR 0021), a passkey for the macOS passkey sheet, approval of a run,
//! "Approve and remember", changes to grants and rules, token rotation, and a new Mac for
//! relay sync need a fresh owner check: Touch ID now, the master passphrase now, or,
//! for the approval of a run only, the Face ID signature of a paired iPhone (ADR 0020).
//! ADR 0030 permits narrowly scoped local reuse through the same gate for opted-in
//! browser/AutoFill actions and an explicitly clicked Allow once. Always-fresh actions
//! still call `authorize`. A reused proof also ends at its window deadline/revocation.
//! [`OwnerGate::authorize`] does the fresh check. The gate is also the
//! only way to make an [`OwnerProof`]. Each guarded action takes a proof by value:
//!
//! - a proof names one action and its target, for example one waiting run exactly as
//!   the owner saw it,
//! - a proof is valid for [`PROOF_LIFETIME`] after the check,
//! - a proof is valid only in the vault session of the check. A lock or an unlock
//!   makes it invalid,
//! - a proof has no `Clone`, so each proof allows one action.
//!
//! The passphrase check opens a second, read-only SQLCipher connection and closes it
//! at once ([`Vault::verify_passphrase_at`]). The gate does not keep the passphrase.
//! [`OwnerCheck::Passphrase`] erases its copy on drop.
//!
//! The iPhone check ([`OwnerCheck::Companion`]) verifies an ECDSA P-256 signature of the
//! approval string of the contract (`docs/contracts/companion-v1.md`, section 7) with
//! the approval key of a paired device. The Secure Enclave signs only after Face ID. The
//! gate rebuilds the signed text from the action, so the signature names one run exactly
//! as the Mac showed it. A phone can approve a run only: it can never make a proof for a
//! reveal, a grant, or a pairing.
//!
//! The check of a device through the relay ([`OwnerCheck::Remote`], contract
//! relay-questions-v1 section 12.4) verifies the signature of an answer string with a key
//! of the `trusted_device` table of the vault: the Face ID answer key of an iPhone, or the
//! relay key of a Mac, which signs after a local Touch ID for
//! [`OwnerAction::AnswerRemoteQuestion`]. It rebuilds the signed text from the action and
//! the question digest v2 of the run, so a signature names one question exactly as the
//! device showed it. A remote device can approve a run, remember a project answer, allow
//! production, or correct an environment to development for an item of the waiting
//! question: never reveal, grant, pair, connect an agent, or change a setting.
//!
//! The check of an action of the feed through the relay ([`OwnerCheck::RemoteAction`],
//! contract relay-feed-v1 section 9.5) verifies the Face ID answer key of a live iPhone
//! of the vault over the action string, which the gate rebuilds with the item UUID of
//! the action and with the names that the vault has for the agent, the item, and this
//! Mac (v2; a v1 action signs ids only and makes no proof). It makes a proof for the
//! removal of a "Not for this agent" or "Always ask for this agent" exception only.
//!
//! A notification, an inbox acknowledgment, or an agent request cannot make a proof
//! (goal item N4).
//!
//! [`OwnerGate::authorize_cancellable`] is the same check with an [`AuthCancel`]
//! handle. When the request of the check goes away, a cancel kills the Touch ID helper
//! at once, and the gate gives no proof, also for an answer that came just before.

use std::fmt;
use std::path::PathBuf;
use std::sync::PoisonError;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{EvaluationOffer, FirstUseDeclaration, FirstUseOffer, PendingRun};
use crate::broker::SharedVault;
use crate::broker::action_kind::ActionKind;
use crate::broker::project::Project;
use crate::companion::crypto::{ApproveAction, approve_string, verify_ecdsa};
use crate::companion::digest::{question_digest_v2_hex, run_digest_hex};
use crate::companion::wire::valid_device_id;
use crate::native::{
    AuthCancel, HelperErrorCode, MAX_AGENT_NAME_CHARS, MAX_REASON_CHARS, NativeError, NativeHelper,
};
use crate::questions::envelope::{Choice, RemoteEnvironment, answer_string};
use crate::vault::bouncer_scopes::EvaluationConfirmation;
use crate::vault::exceptions::ExceptionKind;
use crate::vault::usage::InteractionKind;
use crate::vault::{Declaration, Vault, VaultErrorKind};
use crate::vault::{TrustedDevice, TrustedDeviceKind};

/// How long a proof stays valid after the owner check.
pub const PROOF_LIFETIME: Duration = Duration::from_secs(60);

/// A phone approval may have a time this many seconds ahead of the Mac clock.
const COMPANION_FUTURE_SLACK: u64 = 60;
/// An answer through the relay may have a time this many seconds ahead of the Mac clock
/// (relay-questions-v1 section 12.4), as a phone approval.
const REMOTE_FUTURE_SLACK: u64 = COMPANION_FUTURE_SLACK;

/// An owner action that needs a fresh owner check. The target is part of the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerAction {
    RemoveOlderIphone {
        device: TrustedDevice,
        team: String,
    },
    /// Fresh local access consent; deliberately absent from the owner-window allowlist.
    AllowAccessOnce {
        request_id: u64,
        digest: String,
    },
    GrantAccessRequest {
        request_id: u64,
        agent_id: u64,
        item_id: u64,
        place: crate::vault::GrantPlace,
        mode: crate::vault::ExecMode,
    },
    BackupVault {
        path: PathBuf,
    },
    ExportDecisions,
    RegisterAgent {
        name: String,
    },
    /// Connect a new setup agent with catalog visibility and issue its token.
    RegisterSetupAgent {
        name: String,
    },
    /// Change the protected, device-local owner-check frequency. Always fresh.
    ChangeOwnerFrequency {
        old: super::OwnerFrequency,
        new: super::OwnerFrequency,
    },
    /// Show the secret values of one item.
    Reveal {
        item_id: u64,
    },
    /// Show the code of one one-time password (TOTP) of one item. `field` is the field of
    /// the seed. The proof opens that field only: no password and no other secret value.
    ShowCode {
        item_id: u64,
        field: String,
    },
    /// Copy the current code of one one-time password of one item. The app computes the
    /// code itself. The seed never leaves the session.
    CopyCode {
        item_id: u64,
        field: String,
    },
    /// Copy one ordinary secret field after a fresh local owner check. The proof names
    /// its exact revision; it never contains the value or authorizes an agent read.
    CopyField {
        item_id: u64,
        field: String,
        revision: u64,
    },
    /// Give the username and the password of one login to the browser, for one site
    /// (ADR 0021). `login` is the title of the login as the owner saw it, and `origin` is
    /// the origin of the page, for example `https://github.com`.
    FillLogin {
        item_id: u64,
        login: String,
        origin: String,
    },
    /// Replace a password for an exact site/account/revision. No secret is in the proof.
    UpdateLogin {
        item_id: u64,
        login: String,
        username: String,
        origin: String,
        revision: u64,
    },
    /// Add a login that the owner typed on a page (ADR 0021). The password is not in the
    /// action: it waits in the app while the dialog is open.
    SaveLogin {
        title: String,
        username: String,
        origin: String,
    },
    /// Add a login with a new password that the app makes, and give it to the browser
    /// (ADR 0021).
    CreateLogin {
        title: String,
        username: String,
        origin: String,
        length: u32,
        symbols: bool,
    },
    /// Give the current code of one one-time password of one login to the browser, for
    /// one site. `field` is the field of the seed. The seed never leaves the app.
    FillCode {
        item_id: u64,
        field: String,
        origin: String,
    },
    /// Sign one WebAuthn assertion with the passkey of one login, for one request exactly
    /// as the owner saw it. `origin` is the origin in the client data that the app checked
    /// and hashed for a request of the extension. `None` is a request of the macOS
    /// passkey sheet: macOS checked the relying party, and there is no web origin. So a
    /// check for the browser never signs a request of macOS, and the other way around.
    /// `rid` is the ID of the request.
    SignPasskey {
        origin: Option<String>,
        rid: String,
        rp_id: String,
        item_id: u64,
        credential_id: Vec<u8>,
        client_data_hash: [u8; 32],
    },
    /// Give the username and the password of one login to macOS AutoFill, for one request
    /// of the macOS AutoFill sheet (`rid`). `login` is the title as the owner saw it. A
    /// proof for the browser never fills the sheet, and the other way around.
    FillSystemLogin {
        rid: String,
        item_id: u64,
        login: String,
    },
    /// Give the current code of one one-time password of one login to macOS AutoFill, for
    /// one request of the sheet. `field` is the field of the seed. The seed never leaves.
    FillSystemCode {
        rid: String,
        item_id: u64,
        field: String,
    },
    /// Remove the passkey of one login at one revision. A login without a password is
    /// deleted with it: the dialog says so.
    RemovePasskey {
        item_id: u64,
        revision: u64,
    },
    /// Make one passkey, for one registration request exactly as the owner saw it: the
    /// account, the algorithms, the excluded credentials, and where it goes. `origin` and
    /// `rid` as in [`OwnerAction::SignPasskey`].
    CreatePasskey {
        origin: Option<String>,
        rid: String,
        rp_id: String,
        client_data_hash: [u8; 32],
        user_handle: Vec<u8>,
        user_name: String,
        user_display_name: String,
        algorithms: Vec<i64>,
        excluded: Vec<Vec<u8>>,
        target: crate::vault::PasskeyTarget,
    },
    /// Approve one waiting run, exactly as the owner saw it.
    ApproveRun(PendingRun),
    /// Approve one waiting run and remember a narrow pattern for later runs (ADR 0010).
    ApproveAndRemember(PendingRun),
    /// Approve this run once and authorize future model evaluation in this exact
    /// scope. Future requests still require their own evaluation. Local owner check only.
    ApproveAndEvaluate {
        run: PendingRun,
        offer: EvaluationOffer,
        confirmations: Vec<EvaluationConfirmation>,
    },
    /// Approve one waiting run with a first use and give the agent process access to its
    /// new items in the folder of the offer (ADR 0024). The proof names the run, the
    /// offer, and each declaration exactly as the owner saw them. A phone cannot make it.
    ApproveAndGrant {
        run: PendingRun,
        offer: FirstUseOffer,
        declarations: Vec<FirstUseDeclaration>,
    },
    /// Approve one waiting question and remember "Allow ACTION in PROJECT" for its items
    /// (ADR 0025 §3). The answer covers every agent in the project. `project` and
    /// `action` must be those of the question. A phone cannot make it.
    ApproveInProject {
        run: PendingRun,
        project: Project,
        action: ActionKind,
    },
    /// Approve one waiting question with a production item and allow production for
    /// the project and the kind of action (ADR 0025 §3b). This is the only way to make a
    /// production allowance. A phone cannot make it.
    AllowProduction {
        run: PendingRun,
        project: Project,
        action: ActionKind,
    },
    /// Remove an exception of an agent (ADR 0025 §3f). It gives authority back.
    RemoveAgentException {
        agent_id: u64,
        item_id: u64,
        kind: ExceptionKind,
    },
    /// Remove a remembered answer (ADR 0025 §3b). Removing is stricter and needs no
    /// check; the variant exists for a caller that confirms it anyway.
    RemoveOwnerAnswer {
        answer_id: u64,
    },
    /// Give an agent access to an item or change that access: a connector operation
    /// or process access.
    ChangeGrant {
        agent_id: u64,
        item_id: u64,
    },
    /// Give an agent process access to several items in one change (ADR 0012).
    ChangeGrants {
        agent_id: u64,
        item_ids: Vec<u64>,
    },
    /// Let an agent see all items without values (ADR 0012). Turning it off takes
    /// authority away and needs no check.
    ShowAllCredentials {
        agent_id: u64,
    },
    /// Change the hard rule of a process grant (ADR 0007).
    ChangeRule {
        agent_id: u64,
        item_id: u64,
    },
    /// Change the agent settings of an item: the declaration, the environment
    /// variable, the connector, or the review after a restore.
    ChangeItemRules {
        item_id: u64,
    },
    /// Give an agent a new token.
    RotateToken {
        agent_id: u64,
    },
    /// Connect a host in the agent guide (ADR 0024): give the agent a new token and, with
    /// `show_all`, let it see all credentials without values. One check for both.
    ConnectAgent {
        agent_id: u64,
        show_all: bool,
    },
    /// Change the token lifetime of all agents.
    ChangeTokenLifetime,
    /// Apply a calibrated `task_match` level of the bouncer, in hundredths (ADR 0009
    /// step 3). A return to the default level is stricter and needs no check.
    ChangeCalibration {
        level: u32,
    },
    /// Make a candidate model from shadow mode the active model of the bouncer (ADR 0010,
    /// goal item B9). The proof names the candidate and its version.
    PromoteModel {
        candidate_id: u64,
        version: String,
    },
    /// Return the bouncer to the model before one promotion (goal item B9). The proof
    /// names the promotion.
    RollbackModel {
        activation_id: u64,
    },
    /// Open a command-line session (ADR 0017). The session can read and change the vault
    /// like the views, but every action in this list still needs its own check.
    OpenCliSession,
    /// Bind the environment variables of several items with one check (ADR 0017, D1).
    /// The proof names each item and its variable, in the order of the dialog.
    BindVariables {
        variables: Vec<(u64, String)>,
    },
    /// Bind one secret field of one item to one environment variable (ADR 0006, 0011).
    /// The proof names the field, the variable, how a process gets the value, and
    /// whether the field holds the setup key of a one-time password, exactly as the
    /// dialog showed them. A proof for the agent settings of the item cannot bind.
    BindVariable {
        item_id: u64,
        field: String,
        env_name: String,
        delivery: crate::vault::EnvDelivery,
        setup_key: bool,
    },
    /// Pair an iPhone (ADR 0020). The proof names the device exactly as the owner
    /// confirmed it: its ID, its name, and both public keys (X9.63, 65 bytes each).
    PairCompanion {
        device_id: String,
        device_name: String,
        request_key: Vec<u8>,
        approval_key: Vec<u8>,
    },
    /// Add a device (a Mac or an iPhone) to the relay sync of the open vault (ADR 0022,
    /// contract relay-sync-v1 section 7.1). The proof names the link exactly as the owner
    /// confirmed it: its number on the relay, the name of the device, and its public key
    /// (X9.63, 65 bytes).
    ConfirmSyncDevice {
        link_id: u64,
        device_name: String,
        public_key: Vec<u8>,
    },
    /// Answer a question of another Mac through the relay (relay-questions-v1 section
    /// 5.3): the Touch ID on this Mac before it signs an approving answer with its relay
    /// key. `answer` is the action of the matching local answer for the run as the card
    /// showed it, `asker` the name of the asking Mac, and `qid` the question.
    AnswerRemoteQuestion {
        qid: String,
        asker: String,
        answer: Box<OwnerAction>,
    },
    /// Turn "Send questions through the relay" on for the open vault on this Mac
    /// (relay-questions-v1 section 12): a relay membership, the question key, and this
    /// Mac as a trusted device. It opens a new channel that can approve runs. The proof
    /// names the relay and the team: the relay sync team of the vault, or `None` for a
    /// new notifications-only team. Turning it off is stricter and needs no check.
    EnableRelayQuestions {
        relay_url: String,
        team_id: Option<String>,
    },
}

/// The words for the Touch ID prompt after the relying party of a passkey. `None` is
/// the macOS passkey sheet.
fn passkey_caller(origin: Option<&String>) -> &'static str {
    match origin {
        Some(_) => " in your browser",
        None => " for a macOS request",
    }
}

impl OwnerAction {
    /// The text for the Touch ID prompt. macOS shows it after "Apassy is trying to".
    /// It has no secret value and no command.
    pub fn reason(&self) -> String {
        match self {
            Self::RemoveOlderIphone { .. } => "remove the older paired iPhone".into(),
            Self::AllowAccessOnce { .. } => "allow one scoped access attempt".to_owned(),
            Self::GrantAccessRequest { .. } => "grant access for this exact request".to_owned(),
            Self::BackupVault { .. } => "write an encrypted vault backup".to_owned(),
            Self::ExportDecisions => "export the decision log".to_owned(),
            Self::RegisterAgent { .. } => "register an agent and issue its token".to_owned(),
            Self::RegisterSetupAgent { .. } => {
                "connect an agent and share the credential catalog without values".to_owned()
            }
            Self::ChangeOwnerFrequency { .. } => {
                "change how often Apassy asks for Touch ID".to_owned()
            }
            Self::Reveal { .. } => "show the secret values of an item".to_owned(),
            Self::ShowCode { .. } => "show a one-time code".to_owned(),
            Self::CopyCode { .. } => "copy a one-time code".to_owned(),
            Self::CopyField { .. } => "copy a secret field to the clipboard".to_owned(),
            Self::FillLogin { login, origin, .. } => format!(
                "fill \"{}\" on {}",
                short_device_name(login),
                short_site(origin)
            ),
            Self::UpdateLogin { login, origin, .. } => format!(
                "update the password of \"{}\" for {}",
                short_device_name(login),
                short_site(origin)
            ),
            Self::SaveLogin { title, origin, .. } => format!(
                "save the login \"{}\" for {}",
                short_device_name(title),
                short_site(origin)
            ),
            Self::CreateLogin { title, origin, .. } => format!(
                "create the login \"{}\" on {}",
                short_device_name(title),
                short_site(origin)
            ),
            Self::RemovePasskey { .. } => "remove a passkey".to_owned(),
            Self::FillSystemLogin { login, .. } => {
                format!("fill \"{}\" with macOS AutoFill", short_device_name(login))
            }
            Self::FillSystemCode { .. } => "fill a one-time code with macOS AutoFill".to_owned(),
            Self::FillCode { origin, .. } => {
                format!("fill a one-time code on {}", short_site(origin))
            }
            Self::SignPasskey { origin, rp_id, .. } => format!(
                "sign in to {} with a passkey{}",
                short_site(rp_id),
                passkey_caller(origin.as_ref())
            ),
            Self::CreatePasskey { origin, rp_id, .. } => format!(
                "create a passkey for {}{}",
                short_site(rp_id),
                passkey_caller(origin.as_ref())
            ),
            Self::ApproveRun(run) => format!("approve a run of agent \"{}\"", short_name(run)),
            Self::ApproveAndRemember(run) => {
                format!(
                    "approve and remember a run of agent \"{}\"",
                    short_name(run)
                )
            }
            Self::ApproveAndEvaluate { run, offer, .. } => format!(
                "approve this run of agent \"{}\" once and allow future model evaluation of {} in \"{}\"",
                short_name(run),
                action_words(offer.action),
                short_device_name(&offer.project.label)
            ),
            Self::ApproveAndGrant {
                run,
                offer,
                declarations,
            } => grant_reason(run, offer, declarations),
            Self::ApproveInProject {
                run,
                project,
                action,
            } => format!(
                "approve a run of agent \"{}\" and allow {} in \"{}\" for all agents",
                short_name(run),
                action_words(*action),
                short_device_name(&project.label)
            ),
            Self::AllowProduction {
                run,
                project,
                action,
            } => format!(
                "allow production for \"{}\": {} (run of agent \"{}\")",
                short_device_name(&project.label),
                action_words(*action),
                short_name(run)
            ),
            Self::RemoveAgentException { .. } => "remove an exception of an agent".to_owned(),
            Self::RemoveOwnerAnswer { .. } => "remove a remembered answer".to_owned(),
            Self::ChangeGrant { .. } => "change the access of an agent".to_owned(),
            Self::ChangeGrants { item_ids, .. } => {
                format!("give an agent access to {} credentials", item_ids.len())
            }
            Self::ShowAllCredentials { .. } => {
                "let an agent see all credentials without values".to_owned()
            }
            Self::ChangeRule { .. } => "change an agent rule".to_owned(),
            Self::ChangeItemRules { .. } => "change the agent settings of an item".to_owned(),
            Self::RotateToken { .. } => "give an agent a new token".to_owned(),
            Self::ConnectAgent {
                show_all: false, ..
            } => "give an agent a new token".to_owned(),
            Self::ConnectAgent { show_all: true, .. } => {
                "connect an agent and let it see credential names without values".to_owned()
            }
            Self::ChangeTokenLifetime => "change the agent token lifetime".to_owned(),
            Self::ChangeCalibration { .. } => {
                "change the task_match level of the bouncer".to_owned()
            }
            Self::PromoteModel { .. } => "promote a new model for the bouncer".to_owned(),
            Self::RollbackModel { .. } => "roll back the model of the bouncer".to_owned(),
            Self::OpenCliSession => "start a command-line session".to_owned(),
            Self::BindVariables { variables } => match variables.len() {
                1 => "bind 1 environment variable".to_owned(),
                count => format!("bind {count} environment variables"),
            },
            Self::BindVariable {
                env_name,
                setup_key: true,
                ..
            } => format!(
                "let programs make one-time codes with the variable {}",
                short_device_name(env_name)
            ),
            Self::BindVariable { env_name, .. } => format!(
                "bind the environment variable {}",
                short_device_name(env_name)
            ),
            Self::PairCompanion { device_name, .. } => {
                format!("pair the iPhone \"{}\"", short_device_name(device_name))
            }
            Self::ConfirmSyncDevice { device_name, .. } => format!(
                "add the device \"{}\" to the sync of this vault",
                short_device_name(&crate::questions::device_link::shown_link_name(device_name))
            ),
            Self::AnswerRemoteQuestion { asker, answer, .. } => {
                format!("{} on {}", answer.reason(), short_device_name(asker))
            }
            Self::EnableRelayQuestions { .. } => {
                "send the questions of this vault through the relay".to_owned()
            }
        }
    }

    /// The waiting run of an approval action.
    pub fn run(&self) -> Option<&PendingRun> {
        match self {
            Self::ApproveRun(run)
            | Self::ApproveAndRemember(run)
            | Self::ApproveAndEvaluate { run, .. }
            | Self::ApproveAndGrant { run, .. }
            | Self::ApproveInProject { run, .. }
            | Self::AllowProduction { run, .. } => Some(run),
            _ => None,
        }
    }
}

/// The kind of action for a prompt (ADR 0025 §3a).
pub fn action_words(action: ActionKind) -> &'static str {
    match action {
        ActionKind::Read => "reading",
        ActionKind::Change => "changes",
        ActionKind::Deploy => "deploys",
        ActionKind::Delete => "deleting or irreversible actions",
    }
}

/// Keep the declaration summary and future effect intact; only displayed names use
/// the remaining native prompt budget. The action still holds the exact names/path.
fn grant_reason(
    run: &PendingRun,
    offer: &FirstUseOffer,
    declarations: &[FirstUseDeclaration],
) -> String {
    let environments = grant_declarations(offer, declarations)
        .filter_map(|(_, declaration)| declaration)
        .map(|declaration| declaration.environment.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let production = environments.contains("production");
    let non_production = environments
        .iter()
        .any(|environment| *environment != "production");
    let future = match (production, non_production) {
        (true, true) => {
            "; later clean non-production runs may skip asking; production asks each run"
        }
        (true, false) => "; production asks each run",
        (false, _) => "; later clean runs may start without asking",
    };
    let environments = environments.into_iter().collect::<Vec<_>>().join(", ");
    let describe = |agent: &str, folder: &str| {
        format!(
            "approve run of \"{agent}\"; grant \"{folder}\" + subfolders; save declarations: {environments}{future}"
        )
    };
    let budget = MAX_REASON_CHARS.saturating_sub(describe("", "").chars().count());
    let agent = super::shown_path(&short_name(run), MAX_AGENT_NAME_CHARS);
    let folder = short_folder(&offer.folder);
    let agent_budget = agent.chars().count().min(budget / 2);
    let folder_budget = folder.chars().count().min(budget - agent_budget);
    // Give a short component's spare space to the other one.
    let agent_budget = agent.chars().count().min(budget - folder_budget);
    describe(
        &super::shown_path(&agent, agent_budget),
        &super::shown_path(&folder, folder_budget),
    )
}

/// The last part of a folder for the prompt, printable characters only, at most 40
/// characters.
fn short_folder(folder: &str) -> String {
    let last = std::path::Path::new(folder).file_name().map_or_else(
        || folder.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let name: String = super::shown_path(&last, usize::MAX)
        .chars()
        .filter(|c| *c != '"')
        .take(MAX_AGENT_NAME_CHARS)
        .collect();
    if name.trim().is_empty() {
        "/".to_owned()
    } else {
        name
    }
}

/// The declaration that "Allow in this folder" leaves for each new item: the one the
/// owner accepted on the card, else the one that the item already has. `None`: neither.
pub fn grant_declarations<'a>(
    offer: &'a FirstUseOffer,
    chosen: &'a [FirstUseDeclaration],
) -> impl Iterator<Item = (&'a str, Option<&'a Declaration>)> {
    offer.items.iter().map(move |item| {
        let declaration = chosen
            .iter()
            .find(|declaration| declaration.item_id == item.item_id)
            .map(|declaration| &declaration.declaration)
            .or(item.declaration.as_ref());
        (item.name.as_str(), declaration)
    })
}

/// True when one of the declarations that "Allow in this folder" leaves is production.
/// Such an item still waits for the owner at each run, also after the access is saved.
pub fn grant_has_production(offer: &FirstUseOffer, chosen: &[FirstUseDeclaration]) -> bool {
    grant_declarations(offer, chosen)
        .any(|(_, declaration)| declaration.is_some_and(Declaration::is_production))
}

/// Agent name for the prompt: printable characters only, at most 40 characters.
fn short_name(run: &PendingRun) -> String {
    let name: String = run
        .agent
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .take(MAX_AGENT_NAME_CHARS)
        .collect();
    if name.trim().is_empty() {
        "unknown".to_owned()
    } else {
        name
    }
}

/// The site of a fill for the prompt: the origin without the scheme, printable ASCII
/// only, at most 64 characters.
fn short_site(origin: &str) -> String {
    let site = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);
    let site: String = site
        .chars()
        .filter(|c| c.is_ascii_graphic() && *c != '"')
        .take(64)
        .collect();
    if site.is_empty() {
        "a website".to_owned()
    } else {
        site
    }
}

/// Device name or login title for the prompt: printable characters only, at most 40
/// characters.
fn short_device_name(name: &str) -> String {
    let name: String = name
        .chars()
        .filter(|c| !crate::browser::wire::hides_text(*c) && *c != '"')
        .take(MAX_AGENT_NAME_CHARS)
        .collect();
    if name.trim().is_empty() {
        "unknown".to_owned()
    } else {
        name
    }
}

/// How the owner confirmed an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckMethod {
    TouchId,
    Passphrase,
    /// Face ID on a paired iPhone, as a signature of the approval key.
    Companion,
    /// A device of the vault through the relay: the Face ID answer key of an iPhone, or
    /// the relay key of a Mac after its Touch ID (relay-questions-v1 section 12.4).
    Remote,
}

/// The check that the owner does now.
pub enum OwnerCheck {
    /// Touch ID through the native helper.
    TouchId,
    /// The master passphrase. The buffer is erased on drop.
    Passphrase(Zeroizing<String>),
    /// The approval signature of a paired iPhone (ADR 0020). `time` is the Unix time in
    /// the signed text, and `signature` is the DER ECDSA signature. It works for the
    /// approval of a run only.
    Companion {
        device_id: String,
        time: u64,
        signature: Vec<u8>,
    },
    /// The signature of an answer through the relay (relay-questions-v1 section 12.4):
    /// the trusted device `device_uuid`, the questions team, the question, the time in the
    /// signed text, and the DER ECDSA signature. `correction_of` is the run that waits for
    /// `qid`, for a correction to development ([`OwnerAction::ChangeItemRules`]): its
    /// digest is signed. It works for the answers of a waiting question only.
    Remote {
        device_uuid: String,
        team_id: String,
        qid: String,
        time: u64,
        signature: Vec<u8>,
        correction_of: Option<Box<PendingRun>>,
    },
    /// The signature of an action of the feed through the relay (relay-feed-v1 section
    /// 9.5 step 8): the signed fields of the action string (the sender `by`, this Mac
    /// `to`, the team, the `action_id`, the exception as the feed showed it, the feed
    /// `seq`, and the time) and the DER ECDSA signature. It works for
    /// [`OwnerAction::RemoveAgentException`] of a `never` or `always_ask` row only, with
    /// the Face ID answer key of a live iPhone of the vault.
    RemoteAction {
        signed: Box<crate::questions::feed::RemovalAction>,
        signature: Vec<u8>,
    },
}

impl OwnerCheck {
    /// Copy `text` into an erasing buffer.
    pub fn passphrase(text: &str) -> Self {
        Self::Passphrase(Zeroizing::new(text.to_owned()))
    }

    pub fn method(&self) -> CheckMethod {
        match self {
            Self::TouchId => CheckMethod::TouchId,
            Self::Passphrase(_) => CheckMethod::Passphrase,
            Self::Companion { .. } => CheckMethod::Companion,
            Self::Remote { .. } | Self::RemoteAction { .. } => CheckMethod::Remote,
        }
    }
}

impl fmt::Debug for OwnerCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TouchId => f.write_str("OwnerCheck::TouchId"),
            Self::Passphrase(_) => f.write_str("OwnerCheck::Passphrase([redacted])"),
            Self::Companion {
                device_id, time, ..
            } => write!(
                f,
                "OwnerCheck::Companion {{ device_id: {device_id}, time: {time}, signature: [redacted] }}"
            ),
            Self::Remote {
                device_uuid,
                qid,
                time,
                ..
            } => write!(
                f,
                "OwnerCheck::Remote {{ device_uuid: {device_uuid}, qid: {qid}, time: {time}, signature: [redacted] }}"
            ),
            Self::RemoteAction { signed, .. } => write!(
                f,
                "OwnerCheck::RemoteAction {{ by: {}, action_id: {}, time: {}, signature: [redacted] }}",
                signed.by, signed.action_id, signed.time
            ),
        }
    }
}

/// Why the gate did not confirm the owner. No variant holds a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerAuthError {
    /// No vault is open, or the vault is locked.
    VaultLocked,
    /// The passphrase does not open the vault.
    WrongPassphrase,
    /// The passphrase field is empty.
    EmptyPassphrase,
    /// Touch ID cannot run now. The owner types the passphrase.
    TouchIdUnavailable { detail: String },
    /// The owner or the system cancelled Touch ID.
    TouchIdCancelled,
    /// The owner selected "Use Apassy Passphrase".
    PassphraseRequested,
    /// Touch ID did not confirm the owner.
    TouchIdFailed,
    /// The vault was locked, unlocked, or replaced during the check.
    SessionChanged,
    /// The time of an iPhone approval is more than [`PROOF_LIFETIME`] old, or more than
    /// 60 seconds ahead of the Mac clock.
    CompanionStale,
    /// The device is not paired, or its signature does not verify for this approval.
    CompanionRejected,
    /// An iPhone can confirm the approval of a run only.
    CompanionUnsupported,
    /// The time of an answer through the relay is more than [`PROOF_LIFETIME`] old, or
    /// more than 60 seconds ahead of the Mac clock.
    RemoteStale,
    /// The device is not a live trusted device of the vault, or its signature does not
    /// verify for this answer.
    RemoteRejected,
    /// A device through the relay can answer a waiting question only.
    RemoteUnsupported,
    /// The app cancelled the check, because its request went away. Apassy did nothing.
    Cancelled,
    /// Another failure. The text has no secret value.
    Other(String),
}

impl OwnerAuthError {
    /// Text for the owner.
    pub fn message(&self) -> String {
        match self {
            Self::VaultLocked => "The vault is locked. Unlock it first.".to_owned(),
            Self::WrongPassphrase => "The passphrase is incorrect. Apassy did nothing.".to_owned(),
            Self::EmptyPassphrase => "Type the passphrase.".to_owned(),
            Self::TouchIdUnavailable { detail } => {
                format!("Touch ID is not available: {detail} Type the passphrase to confirm.")
            }
            Self::TouchIdCancelled => {
                "Touch ID was cancelled. Try again, or type the passphrase.".to_owned()
            }
            Self::PassphraseRequested => "Type the passphrase to confirm.".to_owned(),
            Self::TouchIdFailed => {
                "Touch ID did not confirm you. Try again, or type the passphrase.".to_owned()
            }
            Self::SessionChanged => {
                "The vault was locked or changed during the check. Apassy did nothing.".to_owned()
            }
            Self::CompanionStale => {
                "The iPhone confirmation is too old. Confirm again. Nothing was approved."
                    .to_owned()
            }
            Self::CompanionRejected => {
                "The iPhone confirmation does not match a paired iPhone. Nothing was approved."
                    .to_owned()
            }
            Self::CompanionUnsupported => {
                "An iPhone can confirm the approval of a run only. Apassy did nothing.".to_owned()
            }
            Self::RemoteStale => {
                "The answer from another device is too old. Nothing was approved.".to_owned()
            }
            Self::RemoteRejected => {
                "The answer does not match a device of this vault. Nothing was approved.".to_owned()
            }
            Self::RemoteUnsupported => {
                "Another device can answer a waiting question only. Apassy did nothing.".to_owned()
            }
            Self::Cancelled => "The check was cancelled. Apassy did nothing.".to_owned(),
            Self::Other(text) => format!("The owner check failed: {text}"),
        }
    }

    /// True when the owner can still confirm with the passphrase.
    pub fn passphrase_fallback(&self) -> bool {
        matches!(
            self,
            Self::TouchIdUnavailable { .. }
                | Self::TouchIdCancelled
                | Self::PassphraseRequested
                | Self::TouchIdFailed
        )
    }
}

/// Text for a Touch ID state that is not "available". It names the cause.
pub fn touch_id_detail(code: HelperErrorCode) -> &'static str {
    match code {
        HelperErrorCode::NotAvailable => {
            "the Touch ID keyboard is not connected or not paired, or this Mac has no Touch ID sensor."
        }
        HelperErrorCode::NotEnrolled => "no fingerprint is enrolled in System Settings.",
        HelperErrorCode::LockedOut => {
            "Touch ID is locked after failed attempts. Unlock the Mac with its password to reset it."
        }
        _ => "the Touch ID check did not start.",
    }
}

fn from_native(err: NativeError) -> OwnerAuthError {
    match err.code() {
        Some(HelperErrorCode::Cancelled) => OwnerAuthError::TouchIdCancelled,
        Some(HelperErrorCode::Fallback) => OwnerAuthError::PassphraseRequested,
        Some(HelperErrorCode::Failed) => OwnerAuthError::TouchIdFailed,
        Some(
            code @ (HelperErrorCode::NotAvailable
            | HelperErrorCode::NotEnrolled
            | HelperErrorCode::LockedOut),
        ) => OwnerAuthError::TouchIdUnavailable {
            detail: touch_id_detail(code).to_owned(),
        },
        Some(code) => OwnerAuthError::Other(format!("the Touch ID helper answered {code}.")),
        None => match err {
            NativeError::HelperMissing(_) => OwnerAuthError::TouchIdUnavailable {
                detail:
                    "the Touch ID helper is not in this build. Touch ID works only in Apassy.app."
                        .to_owned(),
            },
            NativeError::Timeout(_) => OwnerAuthError::TouchIdCancelled,
            NativeError::Cancelled => OwnerAuthError::Cancelled,
            other => OwnerAuthError::Other(other.to_string()),
        },
    }
}

/// Proof that the owner passed a fresh check for one action. Only
/// [`OwnerGate::authorize`] makes it. It has no `Clone`.
#[derive(Debug)]
pub struct OwnerProof {
    action: OwnerAction,
    method: CheckMethod,
    epoch: [u8; 32],
    issued: Instant,
    window: Option<super::owner_window::WindowProof>,
    local_generation: Option<(super::owner_window::OwnerWindow, u64)>,
}

/// Why a guarded action refused a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRefusal {
    /// The proof names another action or another target.
    WrongAction,
    /// The vault was locked or unlocked after the check.
    OtherSession,
    /// The check is older than [`PROOF_LIFETIME`].
    Stale,
}

impl ProofRefusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::WrongAction => "The owner check was for another action. Apassy did nothing.",
            Self::OtherSession => {
                "The vault was locked after the owner check. Confirm again. Apassy did nothing."
            }
            Self::Stale => "The owner check is too old. Confirm again. Apassy did nothing.",
        }
    }
}

impl OwnerProof {
    fn issue(action: OwnerAction, method: CheckMethod, epoch: [u8; 32]) -> Self {
        Self {
            action,
            method,
            epoch,
            issued: Instant::now(),
            window: None,
            local_generation: None,
        }
    }

    /// A proof with a chosen issue time, for the unit tests of the approval queue and of
    /// the guarded desktop calls.
    #[cfg(test)]
    pub(crate) fn issue_for_test(action: OwnerAction, epoch: [u8; 32], issued: Instant) -> Self {
        Self {
            action,
            method: CheckMethod::Passphrase,
            epoch,
            issued,
            window: None,
            local_generation: None,
        }
    }

    /// Read-only delivery fence, never an authorization proof. It cannot mint or
    /// consume an action; it only prevents sending an already computed result after
    /// expiry, lock, cancellation or a vault/session change.
    #[cfg(feature = "desktop")]
    pub(crate) fn delivery_fence(&self, vault: SharedVault) -> OwnerDeliveryFence {
        OwnerDeliveryFence {
            vault,
            epoch: self.epoch,
            issued: self.issued,
            window: self.window.clone(),
            local_generation: self.local_generation.clone(),
        }
    }

    pub fn action(&self) -> &OwnerAction {
        &self.action
    }

    pub fn method(&self) -> CheckMethod {
        self.method
    }

    /// True while the proof is younger than [`PROOF_LIFETIME`].
    pub fn is_fresh(&self) -> bool {
        self.issued.elapsed() <= PROOF_LIFETIME
            && self.window.as_ref().is_none_or(|p| p.valid())
            && self
                .local_generation
                .as_ref()
                .is_none_or(|(w, g)| w.generation() == *g)
    }

    /// Check the proof for `expected` in the vault session `epoch`. Call it just before
    /// the action, with the vault mutex held.
    pub fn check(&self, expected: &OwnerAction, epoch: &[u8; 32]) -> Result<(), ProofRefusal> {
        if &self.action != expected {
            return Err(ProofRefusal::WrongAction);
        }
        if &self.epoch != epoch {
            return Err(ProofRefusal::OtherSession);
        }
        if !self.is_fresh() {
            return Err(ProofRefusal::Stale);
        }
        Ok(())
    }
}

/// The owner-authorization gate. It holds the shared vault and, when the app has one,
/// the native helper for Touch ID.
#[derive(Debug, Clone)]
pub struct OwnerGate {
    vault: SharedVault,
    touch_id: Option<NativeHelper>,
    window: super::owner_window::OwnerWindow,
}

impl OwnerGate {
    /// `touch_id` is `None` when this build has no native helper. Then only the
    /// passphrase check works.
    pub fn new(vault: SharedVault, touch_id: Option<NativeHelper>) -> Self {
        Self {
            vault,
            touch_id,
            window: Default::default(),
        }
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn with_window(mut self, window: super::owner_window::OwnerWindow) -> Self {
        self.window = window;
        self
    }

    /// Called only by the local controller after checking a live, signed browser or
    /// AutoFill ticket, or an explicit Allow once click. Never by remote/agent APIs.
    #[cfg(feature = "desktop")]
    pub(crate) fn reuse_local(
        &self,
        action: OwnerAction,
        source: LocalWindowSource,
    ) -> Option<OwnerProof> {
        if !source.permits(&action) {
            return None;
        }
        // Current OS state is checked outside the vault mutex, in addition to the
        // revocation stream and its bounded heartbeat at proof consumption.
        if self
            .touch_id
            .as_ref()
            .is_some_and(|h| !h.owner_session_active())
        {
            self.window.observe(false);
            return None;
        }
        let (_, epoch) = self.session().ok()?;
        let (fence, method) = self.window.ticket(epoch)?;
        let mut proof = OwnerProof::issue(action, method, epoch);
        proof.window = Some(fence);
        Some(proof)
    }

    /// The one owner-authorization function (goal item A4).
    ///
    /// It checks the owner now, with Touch ID, the passphrase, or the signature of a
    /// paired iPhone, and returns a proof for `action` only. The call blocks: Touch ID
    /// waits for the owner, and the passphrase check derives the SQLCipher key. Call it
    /// from a worker thread. The iPhone check does not block: it verifies a signature.
    pub fn authorize(
        &self,
        action: OwnerAction,
        check: OwnerCheck,
    ) -> Result<OwnerProof, OwnerAuthError> {
        self.authorize_with(action, check, None)
    }

    /// [`OwnerGate::authorize`] that `cancel` can stop. Use a new handle for each check.
    ///
    /// A cancel during a Touch ID check kills the helper of this check and reaps it, so
    /// its prompt closes, and this call returns [`OwnerAuthError::Cancelled`] at once.
    /// A cancel cannot stop the passphrase check or the iPhone check, but the gate gives
    /// no proof after a cancel, also when the owner passed just before it. A cancel
    /// after this call returned does nothing: the caller drops a proof that it does not
    /// want.
    pub fn authorize_cancellable(
        &self,
        action: OwnerAction,
        check: OwnerCheck,
        cancel: &AuthCancel,
    ) -> Result<OwnerProof, OwnerAuthError> {
        self.authorize_with(action, check, Some(cancel))
    }

    fn authorize_with(
        &self,
        action: OwnerAction,
        check: OwnerCheck,
        cancel: Option<&AuthCancel>,
    ) -> Result<OwnerProof, OwnerAuthError> {
        let generation = self.window.generation();
        let local = matches!(check, OwnerCheck::TouchId | OwnerCheck::Passphrase(_));
        let mut result = self.authorize_fresh(action.clone(), check, cancel);
        if local && result.is_ok() {
            if self.window.generation() != generation {
                result = Err(OwnerAuthError::SessionChanged);
            } else if let Ok(proof) = &mut result {
                proof.local_generation = Some((self.window.clone(), generation));
            }
        }
        match &result {
            Ok(proof)
                if !matches!(
                    action,
                    OwnerAction::AnswerRemoteQuestion { .. }
                        | OwnerAction::ChangeOwnerFrequency { .. }
                ) =>
            {
                self.window.seed(proof.epoch, proof.method, generation)
            }
            Err(_) => self.window.invalidate(),
            _ => {}
        }
        result
    }

    fn authorize_fresh(
        &self,
        action: OwnerAction,
        check: OwnerCheck,
        cancel: Option<&AuthCancel>,
    ) -> Result<OwnerProof, OwnerAuthError> {
        let cancelled = || cancel.is_some_and(AuthCancel::is_cancelled);
        if cancelled() {
            return Err(OwnerAuthError::Cancelled);
        }
        let (path, epoch) = self.session()?;
        let method = check.method();
        // An action of the feed counts as an owner interaction when it is applied
        // (relay-feed-v1 section 9.5 step 10), not at its check.
        let counted = !matches!(check, OwnerCheck::RemoteAction { .. });
        match check {
            OwnerCheck::TouchId => {
                let Some(helper) = &self.touch_id else {
                    return Err(OwnerAuthError::TouchIdUnavailable {
                        detail: "this build has no Touch ID helper.".to_owned(),
                    });
                };
                let reason = action.reason();
                match cancel {
                    Some(cancel) => helper.authenticate_cancellable(&reason, cancel),
                    None => helper.authenticate(&reason),
                }
                .map_err(from_native)?;
            }
            OwnerCheck::Companion {
                device_id,
                time,
                signature,
            } => self.check_companion(&action, &device_id, time, &signature, epoch)?,
            OwnerCheck::Remote {
                device_uuid,
                team_id,
                qid,
                time,
                signature,
                correction_of,
            } => self.check_remote(
                &action,
                &RemoteAnswer {
                    device_uuid: &device_uuid,
                    team_id: &team_id,
                    qid: &qid,
                    time,
                    signature: &signature,
                    correction_of: correction_of.as_deref(),
                },
                epoch,
            )?,
            OwnerCheck::RemoteAction { signed, signature } => {
                self.check_remote_action(&action, &signed, &signature, epoch)?;
            }
            OwnerCheck::Passphrase(passphrase) => {
                if passphrase.is_empty() {
                    return Err(OwnerAuthError::EmptyPassphrase);
                }
                match Vault::verify_passphrase_at(&path, &passphrase) {
                    Ok(()) => {}
                    Err(err)
                        if matches!(
                            err.kind(),
                            VaultErrorKind::WrongKeyOrCorrupt | VaultErrorKind::InvalidInput
                        ) =>
                    {
                        return Err(OwnerAuthError::WrongPassphrase);
                    }
                    Err(err) => return Err(OwnerAuthError::Other(err.to_string())),
                }
                // `passphrase` drops here and erases its buffer.
            }
        }
        if cancelled() {
            return Err(OwnerAuthError::Cancelled);
        }
        // A lock, an unlock, or another vault during the check ends the session.
        match self.session() {
            Ok((now_path, now_epoch)) if now_path == path && now_epoch == epoch => {
                if counted {
                    self.count_check(&action, &path, epoch);
                }
                Ok(OwnerProof::issue(action, method, epoch))
            }
            _ => Err(OwnerAuthError::SessionChanged),
        }
    }

    /// Count a passed owner check (ADR 0025 §1). An answer to a waiting run is not
    /// counted here: the broker counts the question, and one answer is one interaction.
    /// A failure to count changes nothing.
    fn count_check(&self, action: &OwnerAction, path: &std::path::Path, epoch: [u8; 32]) {
        // The answer of another Mac counts on the asking Mac, as one question.
        if action.run().is_some() || matches!(action, OwnerAction::AnswerRemoteQuestion { .. }) {
            return;
        }
        let mut guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(vault) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.path() == path && vault.epoch() == epoch)
        {
            let _ = vault.record_interaction(InteractionKind::OwnerCheck, &action.reason(), &[]);
        }
    }

    /// Verify the approval signature of a paired iPhone (ADR 0020, contract section 7).
    ///
    /// Only for the approval of a run. The gate loads the approval key of the device from
    /// the vault in the session `epoch`, rebuilds the approval string from the action
    /// (the action name, the ID of the run, the digest of the run as it waits) and `time`,
    /// checks the time, and verifies the signature. Any other action is refused.
    fn check_companion(
        &self,
        action: &OwnerAction,
        device_id: &str,
        time: u64,
        signature: &[u8],
        epoch: [u8; 32],
    ) -> Result<(), OwnerAuthError> {
        let (approve, run) = match action {
            OwnerAction::ApproveRun(run) => (ApproveAction::Approve, run),
            OwnerAction::ApproveAndRemember(run) => (ApproveAction::ApproveAndRemember, run),
            _ => return Err(OwnerAuthError::CompanionUnsupported),
        };
        if !valid_device_id(device_id) {
            return Err(OwnerAuthError::CompanionRejected);
        }
        let keys = {
            let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(vault) if !vault.is_locked() && vault.epoch() == epoch => vault
                    .companion_device_keys(device_id)
                    .map_err(|error| OwnerAuthError::Other(error.to_string()))?,
                _ => return Err(OwnerAuthError::SessionChanged),
            }
        };
        let Some(keys) = keys else {
            return Err(OwnerAuthError::CompanionRejected);
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if time.saturating_add(PROOF_LIFETIME.as_secs()) < now
            || time > now.saturating_add(COMPANION_FUTURE_SLACK)
        {
            return Err(OwnerAuthError::CompanionStale);
        }
        let Some(text) = approve_string(device_id, approve, run.id, &run_digest_hex(run), time)
        else {
            return Err(OwnerAuthError::CompanionRejected);
        };
        if verify_ecdsa(&keys.approval_key, text.as_bytes(), signature) {
            Ok(())
        } else {
            Err(OwnerAuthError::CompanionRejected)
        }
    }

    /// Verify the signature of an answer through the relay (relay-questions-v1 section
    /// 12.4): the live trusted device from the vault in the session `epoch`, the time,
    /// and the signature over the answer string that the gate rebuilds from `action` and
    /// the digest v2 of its run. Only the answers of a waiting question make a proof.
    fn check_remote(
        &self,
        action: &OwnerAction,
        answer: &RemoteAnswer<'_>,
        epoch: [u8; 32],
    ) -> Result<(), OwnerAuthError> {
        let (choice, run) = remote_choice(action, answer.correction_of)?;
        let device = {
            let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(vault) if !vault.is_locked() && vault.epoch() == epoch => vault
                    .trusted_device(answer.device_uuid)
                    .map_err(|error| OwnerAuthError::Other(error.to_string()))?,
                _ => return Err(OwnerAuthError::SessionChanged),
            }
        };
        let Some(device) = device else {
            return Err(OwnerAuthError::RemoteRejected);
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        verify_remote_answer(
            &device,
            answer.team_id,
            answer.qid,
            &choice,
            &question_digest_v2_hex(run),
            answer.time,
            answer.signature,
            now,
        )
    }

    /// Verify the signature of an action of the feed (relay-feed-v1 section 9.5 step 8):
    /// only the removal of a `never` or `always_ask` exception, whose agent and kind are
    /// the signed ones and whose item has the signed UUID; the live trusted device from
    /// the vault in the session `epoch`; the team (the questions team of the vault) and
    /// the target (the trusted device of this Mac in it), rebuilt from the vault and not
    /// taken from the caller; a v2 action (a v1 action signs ids only and is refused),
    /// whose `names` are among those rebuilt from the vault's agent, item, and this Mac
    /// (`feed::names_in_vault`); the window; and the
    /// signature of its answer key over the action string. Only this action makes a proof through `RemoteAction`,
    /// and no other remote check makes a proof for it.
    fn check_remote_action(
        &self,
        action: &OwnerAction,
        signed: &crate::questions::feed::RemovalAction,
        signature: &[u8],
        epoch: [u8; 32],
    ) -> Result<(), OwnerAuthError> {
        let OwnerAction::RemoveAgentException {
            agent_id,
            item_id,
            kind,
        } = action
        else {
            return Err(OwnerAuthError::RemoteUnsupported);
        };
        if *kind == ExceptionKind::Only {
            return Err(OwnerAuthError::RemoteUnsupported);
        }
        if signed.agent_id != *agent_id || signed.kind != *kind {
            return Err(OwnerAuthError::RemoteRejected);
        }
        let other = |error: crate::vault::VaultError| OwnerAuthError::Other(error.to_string());
        let (device, item_uuid, team_id, me, names) = {
            let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(vault) if !vault.is_locked() && vault.epoch() == epoch => {
                    // The team and this Mac come from the vault, never from the caller:
                    // the questions team of the vault and the trusted device of this Mac
                    // in it.
                    let membership =
                        crate::relay::membership::questions_membership(vault).map_err(other)?;
                    let me = match &membership {
                        Some(membership) => {
                            crate::relay::membership::this_device(vault, membership)
                                .map_err(other)?
                        }
                        None => None,
                    };
                    // The names of the agent, the item, and this Mac, from the vault.
                    let names = match &me {
                        Some(me) => crate::questions::feed::names_in_vault(
                            vault, *agent_id, *item_id, &me.uuid,
                        )
                        .map_err(other)?,
                        None => None,
                    };
                    (
                        vault.trusted_device(&signed.by).map_err(other)?,
                        vault.item_uuid(*item_id).map_err(other)?,
                        membership.map(|membership| membership.team_id),
                        me.map(|me| me.uuid),
                        names,
                    )
                }
                _ => return Err(OwnerAuthError::SessionChanged),
            }
        };
        let Some(device) = device else {
            return Err(OwnerAuthError::RemoteRejected);
        };
        if item_uuid.as_deref() != Some(signed.item_uuid.as_str())
            || team_id.as_deref() != Some(signed.team_id.as_str())
            || me.as_deref() != Some(signed.to.as_str())
        {
            return Err(OwnerAuthError::RemoteRejected);
        }
        // Only a v2 action gives authority back, and it signs the names the owner saw:
        // they must be this Mac's names. A v1 action signs ids only.
        let Some(signed_names) = &signed.names else {
            return Err(OwnerAuthError::RemoteRejected);
        };
        if !names.is_some_and(|names| names.contains(signed_names)) {
            return Err(OwnerAuthError::RemoteRejected);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        verify_remote_action(&device, signed, signature, now)
    }

    /// The path and the epoch of the unlocked vault. The vault mutex is held only here.
    fn session(&self) -> Result<(PathBuf, [u8; 32]), OwnerAuthError> {
        let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.as_ref() {
            Some(vault) if !vault.is_locked() => Ok((vault.path().to_path_buf(), vault.epoch())),
            _ => Err(OwnerAuthError::VaultLocked),
        }
    }
}

/// The parts of [`OwnerCheck::Remote`] for the check.
struct RemoteAnswer<'a> {
    device_uuid: &'a str,
    team_id: &'a str,
    qid: &'a str,
    time: u64,
    signature: &'a [u8],
    correction_of: Option<&'a PendingRun>,
}

/// The answer of `action` and the run whose digest it signs. `RemoteUnsupported` for an
/// action that a remote device cannot take, or a correction for an item that the waiting
/// question does not offer to correct.
fn remote_choice<'a>(
    action: &'a OwnerAction,
    correction_of: Option<&'a PendingRun>,
) -> Result<(Choice, &'a PendingRun), OwnerAuthError> {
    match action {
        OwnerAction::ApproveRun(run) => Ok((Choice::ApproveOnce, run)),
        OwnerAction::ApproveAndEvaluate { .. } => Err(OwnerAuthError::RemoteUnsupported),
        OwnerAction::ApproveInProject {
            run,
            project,
            action,
        } => Ok((
            Choice::ApproveInProject {
                action: *action,
                project_key: project.key.clone(),
            },
            run,
        )),
        OwnerAction::AllowProduction {
            run,
            project,
            action,
        } => Ok((
            Choice::AllowProduction {
                action: *action,
                project_key: project.key.clone(),
            },
            run,
        )),
        OwnerAction::ChangeItemRules { item_id } => {
            let run = correction_of.ok_or(OwnerAuthError::RemoteUnsupported)?;
            let choice = Choice::CorrectEnvironment {
                item_id: *item_id,
                environment: RemoteEnvironment::Development,
            };
            if choice.valid_for(&run.question) {
                Ok((choice, run))
            } else {
                Err(OwnerAuthError::RemoteUnsupported)
            }
        }
        _ => Err(OwnerAuthError::RemoteUnsupported),
    }
}

/// The key of `device` that signs `choice` (relay-questions-v1 section 5.3): the answer
/// key of an iPhone for an answer that needs the owner check, else the relay key
/// (`sign_key`). `None`: an iPhone without an answer key.
pub fn remote_key<'a>(device: &'a TrustedDevice, choice: &Choice) -> Option<&'a [u8]> {
    match device.kind {
        TrustedDeviceKind::Iphone if choice.needs_owner_check() => device.answer_key.as_deref(),
        _ => Some(device.sign_key.as_slice()),
    }
}

/// Verify an answer through the relay at the time `now` (relay-questions-v1 sections
/// 12.3 step 7 and 12.4): `now - 60 <= time <= now + 60`, then the signature over the
/// answer string rebuilt from the device, the team, the question, `choice`, `digest`, and
/// `time`, with the key of [`remote_key`]. A signature by the other key of the device is
/// invalid.
#[allow(clippy::too_many_arguments)]
pub fn verify_remote_answer(
    device: &TrustedDevice,
    team_id: &str,
    qid: &str,
    choice: &Choice,
    digest: &str,
    time: u64,
    signature: &[u8],
    now: u64,
) -> Result<(), OwnerAuthError> {
    if time.saturating_add(PROOF_LIFETIME.as_secs()) < now
        || time > now.saturating_add(REMOTE_FUTURE_SLACK)
    {
        return Err(OwnerAuthError::RemoteStale);
    }
    let Some(text) = answer_string(&device.uuid, team_id, qid, choice, digest, time) else {
        return Err(OwnerAuthError::RemoteRejected);
    };
    let Some(key) = remote_key(device, choice) else {
        return Err(OwnerAuthError::RemoteRejected);
    };
    if verify_ecdsa(key, text.as_bytes(), signature) {
        Ok(())
    } else {
        Err(OwnerAuthError::RemoteRejected)
    }
}

/// Verify an action of the feed at the time `now` (relay-feed-v1 sections 9.1, 9.4, and
/// 9.5 step 8): `now - 60 <= time <= now + 60`, then the signature over the action
/// string rebuilt from `signed` with the key of its kind: the answer key (Face ID) of an
/// iPhone for the removal of a `never` or `always_ask` row, its relay key (`sign_key`)
/// for an `only` row. A Mac is no sender in v1, and a signature by the other key of the
/// device is invalid.
pub fn verify_remote_action(
    device: &TrustedDevice,
    signed: &crate::questions::feed::RemovalAction,
    signature: &[u8],
    now: u64,
) -> Result<(), OwnerAuthError> {
    if !crate::questions::feed::in_window(signed.time, now) {
        return Err(OwnerAuthError::RemoteStale);
    }
    if device.kind != TrustedDeviceKind::Iphone || device.uuid != signed.by {
        return Err(OwnerAuthError::RemoteRejected);
    }
    let key = if signed.gives_authority() {
        device.answer_key.as_deref()
    } else {
        Some(device.sign_key.as_slice())
    };
    let (Some(key), Some(text)) = (key, signed.string()) else {
        return Err(OwnerAuthError::RemoteRejected);
    };
    if verify_ecdsa(key, text.as_bytes(), signature) {
        Ok(())
    } else {
        Err(OwnerAuthError::RemoteRejected)
    }
}

#[cfg(test)]
mod evaluation_tests {
    use super::*;

    #[test]
    fn remote_and_companion_choices_cannot_authorize_evaluation() {
        let run = PendingRun {
            id: 123,
            agent: "Synthetic agent".to_owned(),
            command: vec!["true".to_owned()],
            cwd: "/tmp/synthetic-evaluation".to_owned(),
            env_names: vec!["SYNTHETIC_KEY".to_owned()],
            purpose: "Synthetic test".to_owned(),
            risk: String::new(),
            user_request: String::new(),
            request_source: String::new(),
            agent_request: String::new(),
            remember: None,
            question: super::super::QuestionInfo::default(),
        };
        let action = OwnerAction::ApproveAndEvaluate {
            run: run.clone(),
            offer: EvaluationOffer {
                agent_id: 7,
                project: Project {
                    key: "/tmp/synthetic-evaluation".to_owned(),
                    label: "Synthetic".to_owned(),
                    root: "/tmp/synthetic-evaluation".into(),
                },
                action: ActionKind::Read,
                items: Vec::new(),
                command_binding: None,
            },
            confirmations: Vec::new(),
        };
        assert_eq!(action.run(), Some(&run));
        assert!(
            action
                .reason()
                .contains("once and allow future model evaluation")
        );
        assert!(matches!(
            remote_choice(&action, None),
            Err(OwnerAuthError::RemoteUnsupported)
        ));
        let gate = OwnerGate::new(std::sync::Arc::new(std::sync::Mutex::new(None)), None);
        assert_eq!(
            gate.check_companion(&action, "synthetic-device", 0, &[], [0; 32]),
            Err(OwnerAuthError::CompanionUnsupported)
        );
        let once = OwnerAction::ApproveRun(run);
        assert!(matches!(
            remote_choice(&once, None),
            Ok((Choice::ApproveOnce, _))
        ));
        let proof = OwnerProof::issue_for_test(action.clone(), [1; 32], Instant::now());
        assert_eq!(proof.check(&action, &[1; 32]), Ok(()));
        let mut other = action;
        let OwnerAction::ApproveAndEvaluate { offer, .. } = &mut other else {
            unreachable!()
        };
        offer.command_binding = Some("changed-binding".to_owned());
        assert_eq!(
            proof.check(&other, &[1; 32]),
            Err(ProofRefusal::WrongAction)
        );
    }
}

/// Internal provenance, never deserialized from a socket request.
#[derive(Clone, Copy)]
#[cfg(feature = "desktop")]
pub(crate) enum LocalWindowSource {
    BrowserGesture,
    AutoFill,
    AllowOnceClick,
}
#[cfg(feature = "desktop")]
impl LocalWindowSource {
    fn permits(self, action: &OwnerAction) -> bool {
        match self {
            Self::BrowserGesture => matches!(
                action,
                OwnerAction::FillLogin { .. }
                    | OwnerAction::SaveLogin { .. }
                    | OwnerAction::CreateLogin { .. }
                    | OwnerAction::UpdateLogin { .. }
                    | OwnerAction::FillCode { .. }
                    | OwnerAction::SignPasskey {
                        origin: Some(_),
                        ..
                    }
            ),
            Self::AutoFill => matches!(
                action,
                OwnerAction::FillSystemLogin { .. }
                    | OwnerAction::FillSystemCode { .. }
                    | OwnerAction::SignPasskey { origin: None, .. }
            ),
            Self::AllowOnceClick => matches!(action, OwnerAction::ApproveRun(_)),
        }
    }
}

#[derive(Clone)]
#[cfg(feature = "desktop")]
pub(crate) struct OwnerDeliveryFence {
    vault: SharedVault,
    epoch: [u8; 32],
    issued: Instant,
    window: Option<super::owner_window::WindowProof>,
    local_generation: Option<(super::owner_window::OwnerWindow, u64)>,
}
#[cfg(feature = "desktop")]
impl OwnerDeliveryFence {
    pub(crate) fn valid(&self) -> bool {
        let vault = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        vault
            .as_ref()
            .is_some_and(|v| !v.is_locked() && v.epoch() == self.epoch)
            && self.issued.elapsed() <= PROOF_LIFETIME
            && self.window.as_ref().is_none_or(|w| w.valid())
            && self
                .local_generation
                .as_ref()
                .is_none_or(|(w, g)| w.generation() == *g)
    }
}
