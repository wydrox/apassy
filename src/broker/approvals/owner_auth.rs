//! Owner authorization for sensitive owner actions (goal item A4, ADR 0010).
//!
//! Reveal, a fill, a save, a new login, a one-time code, or a passkey in the browser
//! (ADR 0021), a passkey for the macOS passkey sheet, approval of a run,
//! "Approve and remember", changes to grants and rules, token rotation, and a new Mac for
//! relay sync need a fresh owner check: Touch ID now, the master passphrase now, or,
//! for the approval of a run only, the Face ID signature of a paired iPhone (ADR 0020).
//! [`OwnerGate::authorize`] is the only function that does this check. It is also the
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

use super::PendingRun;
use crate::broker::SharedVault;
use crate::companion::crypto::{ApproveAction, approve_string, verify_ecdsa};
use crate::companion::digest::run_digest_hex;
use crate::companion::wire::valid_device_id;
use crate::native::{AuthCancel, HelperErrorCode, MAX_AGENT_NAME_CHARS, NativeError, NativeHelper};
use crate::vault::{Vault, VaultErrorKind};

/// How long a proof stays valid after the owner check.
pub const PROOF_LIFETIME: Duration = Duration::from_secs(60);

/// A phone approval may have a time this many seconds ahead of the Mac clock.
const COMPANION_FUTURE_SLACK: u64 = 60;

/// An owner action that needs a fresh owner check. The target is part of the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerAction {
    /// Show the secret values of one item.
    Reveal { item_id: u64 },
    /// Show the code of one one-time password (TOTP) of one item. `field` is the field of
    /// the seed. The proof opens that field only: no password and no other secret value.
    ShowCode { item_id: u64, field: String },
    /// Copy the current code of one one-time password of one item. The app computes the
    /// code itself. The seed never leaves the session.
    CopyCode { item_id: u64, field: String },
    /// Give the username and the password of one login to the browser, for one site
    /// (ADR 0021). `login` is the title of the login as the owner saw it, and `origin` is
    /// the origin of the page, for example `https://github.com`.
    FillLogin {
        item_id: u64,
        login: String,
        origin: String,
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
    RemovePasskey { item_id: u64, revision: u64 },
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
    /// Give an agent access to an item or change that access: a connector operation
    /// or process access.
    ChangeGrant { agent_id: u64, item_id: u64 },
    /// Give an agent process access to several items in one change (ADR 0012).
    ChangeGrants { agent_id: u64, item_ids: Vec<u64> },
    /// Let an agent see all items without values (ADR 0012). Turning it off takes
    /// authority away and needs no check.
    ShowAllCredentials { agent_id: u64 },
    /// Change the hard rule of a process grant (ADR 0007).
    ChangeRule { agent_id: u64, item_id: u64 },
    /// Change the agent settings of an item: the declaration, the environment
    /// variable, the connector, or the review after a restore.
    ChangeItemRules { item_id: u64 },
    /// Give an agent a new token.
    RotateToken { agent_id: u64 },
    /// Change the token lifetime of all agents.
    ChangeTokenLifetime,
    /// Apply a calibrated `task_match` level of the bouncer, in hundredths (ADR 0009
    /// step 3). A return to the default level is stricter and needs no check.
    ChangeCalibration { level: u32 },
    /// Make a candidate model from shadow mode the active model of the bouncer (ADR 0010,
    /// goal item B9). The proof names the candidate and its version.
    PromoteModel { candidate_id: u64, version: String },
    /// Return the bouncer to the model before one promotion (goal item B9). The proof
    /// names the promotion.
    RollbackModel { activation_id: u64 },
    /// Open a command-line session (ADR 0017). The session can read and change the vault
    /// like the views, but every action in this list still needs its own check.
    OpenCliSession,
    /// Bind the environment variables of several items with one check (ADR 0017, D1).
    /// The proof names each item and its variable, in the order of the dialog.
    BindVariables { variables: Vec<(u64, String)> },
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
            Self::Reveal { .. } => "show the secret values of an item".to_owned(),
            Self::ShowCode { .. } => "show a one-time code".to_owned(),
            Self::CopyCode { .. } => "copy a one-time code".to_owned(),
            Self::FillLogin { login, origin, .. } => format!(
                "fill \"{}\" on {}",
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
                short_device_name(device_name)
            ),
        }
    }

    /// The waiting run of an approval action.
    pub fn run(&self) -> Option<&PendingRun> {
        match self {
            Self::ApproveRun(run) | Self::ApproveAndRemember(run) => Some(run),
            _ => None,
        }
    }
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
}

impl OwnerGate {
    /// `touch_id` is `None` when this build has no native helper. Then only the
    /// passphrase check works.
    pub fn new(vault: SharedVault, touch_id: Option<NativeHelper>) -> Self {
        Self { vault, touch_id }
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
        let cancelled = || cancel.is_some_and(AuthCancel::is_cancelled);
        if cancelled() {
            return Err(OwnerAuthError::Cancelled);
        }
        let (path, epoch) = self.session()?;
        let method = check.method();
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
                Ok(OwnerProof::issue(action, method, epoch))
            }
            _ => Err(OwnerAuthError::SessionChanged),
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

    /// The path and the epoch of the unlocked vault. The vault mutex is held only here.
    fn session(&self) -> Result<(PathBuf, [u8; 32]), OwnerAuthError> {
        let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.as_ref() {
            Some(vault) if !vault.is_locked() => Ok((vault.path().to_path_buf(), vault.epoch())),
            _ => Err(OwnerAuthError::VaultLocked),
        }
    }
}
