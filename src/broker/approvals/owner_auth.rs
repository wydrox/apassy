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
use std::sync::{Arc, PoisonError};
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
    BrowserDebugging {
        identity: crate::browser::trust::InstanceIdentity,
        scope: Option<crate::browser::bypass::BypassScope>,
        binding: Option<crate::browser::bypass::RequestBinding>,
    },
    RemoveOlderIphone {
        device: TrustedDevice,
        team: String,
    },
    /// Local consent for one exact access request.
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
    /// Change the protected, device-local owner-check frequency.
    ChangeOwnerFrequency {
        old: super::OwnerFrequency,
        new: super::OwnerFrequency,
    },
    /// Show the secret values of one item.
    Reveal {
        item_id: u64,
    },
    /// CLI code under the owner's global verification window.
    /// Bound to the exact item, OTP field and show/copy action.
    CliCode {
        item_id: u64,
        field: String,
        copy: bool,
    },
    /// UI code reveal uses the global owner check.
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
    /// `rid` is the ID of the request. `extensions` are the WebAuthn extensions of the
    /// request for this credential (PRF inputs, a largeBlob read or write), so a proof
    /// never writes a blob or makes PRF outputs that the request did not have.
    SignPasskey {
        origin: Option<String>,
        rid: String,
        rp_id: String,
        item_id: u64,
        credential_id: Vec<u8>,
        client_data_hash: [u8; 32],
        extensions: crate::vault::PasskeyAssertionExtensions,
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
    /// Remote classification binds the entire run and chosen environment to the proof.
    ClassifyRemoteRun {
        run: PendingRun,
        environment: crate::vault::Environment,
    },
    /// Development clicked locally for this exact pending question and item.
    QuestionDevelopment {
        run_id: u64,
        item_id: u64,
    },
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
    /// Change who hosts the bouncer brain (ADR 0035 section 1): this Mac, the owner's
    /// server, or Apassy Connect. The proof names the kind, the `https://` address as the
    /// vault stores it (empty for this Mac) and the consent screen that the owner
    /// accepted (0 for this Mac). A return to this Mac needs the check too. The global
    /// owner window never covers it ([`OwnerAction::needs_fresh_local_check`]), and no
    /// phone or other Mac can make it.
    ChangeBouncerHosting {
        kind: crate::vault::BouncerHostKind,
        url: String,
        consent_version: u32,
    },
    /// Change who trains the bouncer brain (ADR 0035 section 1), with the same rules as
    /// [`OwnerAction::ChangeBouncerHosting`].
    ChangeBouncerTraining {
        kind: crate::vault::BouncerHostKind,
        url: String,
        consent_version: u32,
    },
    /// Turn short-lived credentials ("way C", ADR 0037 stage 6 D11) on or off for one
    /// source item (contract private-sharing-v1 rule 3). The proof names the item, the
    /// kind of its `short_lived` row, and the new state, exactly as the sheet showed
    /// them. Off delivers the item as a static key; nothing else turns way C off.
    ChangeDelivery {
        item: u64,
        kind: crate::vault::ShortLivedKind,
        on: bool,
    },
    /// Change the kind or the settings of the `short_lived` row of one source item
    /// (contract private-sharing-v1 section 3.2): the role, the policy, the permissions,
    /// the repositories, the scopes, the account to act as, and the API, token, and
    /// revoke URLs, that is what a lease can do and where the long-lived secret goes. The
    /// proof names the item, the new kind, and the SHA-256 (hex) of the canonical
    /// settings text (`ShortLivedSettings::digest`), exactly as the sheet showed them.
    /// The global owner window never covers it: a changed URL sends the long-lived
    /// secret to another host.
    ChangeShortLivedSettings {
        item: u64,
        kind: crate::vault::ShortLivedKind,
        settings_sha256: String,
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
    /// Add a device to the Apassy Connect account of this Mac (connect-account-v1
    /// section 7.1, plan s7 M1). The proof names the join exactly as the owner confirmed
    /// it: the account, the join at Connect, the name and the public key of the device
    /// (X9.63, 65 bytes), and the six safety words that both devices show. Only a fresh
    /// check on this Mac makes it ([`OwnerAction::needs_fresh_local_check`]); no phone or
    /// other Mac can.
    ConfirmConnectDevice {
        account_id: String,
        join_id: u64,
        device_name: String,
        public_key: Vec<u8>,
        words: String,
    },
    /// Revoke a device of the Apassy Connect account (section 7.4), also this Mac
    /// itself ("Forget this device"). The proof names the account, the device, the name
    /// that the signed device list holds for its key, and the short fingerprint of that
    /// key (`crate::connect::key_fingerprint`): the key that the signed removal names.
    RevokeConnectDevice {
        account_id: String,
        device_id: String,
        device_name: String,
        fingerprint: String,
    },
    /// Delete the Apassy Connect account (section 6): its vault stores, devices, and
    /// subscription end.
    DeleteConnectAccount {
        account_id: String,
    },
    /// Make a new recovery code for the Apassy Connect account (connect-account-v1 section
    /// 9.1): the recovery key at Connect is replaced, and the old code stops working.
    NewRecoveryCode {
        account_id: String,
    },
    /// Recover the Apassy Connect account `account_id` with its recovery code
    /// (connect-account-v1 section 9): this device becomes its first device, every vault
    /// store of the account is deleted at Connect, and a new recovery code replaces the old
    /// one.
    RecoverConnectAccount {
        account_id: String,
    },
    /// Forget an account file of an earlier version of Apassy on this Mac, with the account
    /// key: the device joins its account again after it. Connect is not asked.
    ForgetOldConnectAccount,
    /// Delete a vault store of the Apassy Connect account (connect-account-v1 section 8):
    /// the relay copy of one vault and its snapshots go at Connect. The proof names the
    /// store by its relay team.
    DeleteVaultStore {
        team_id: String,
    },
    /// End the wait of a vault store of the Apassy Connect account on the head `head`
    /// (version `version`) that a device that left the account pushed last
    /// (connect-account-v1 section 7.5): take exactly that copy once (`replace` false), or
    /// replace it with this device's vault (`replace` true). The proof names the store, the
    /// head, and the choice.
    TakeDepartedCopy {
        team_id: String,
        version: u64,
        head: String,
        replace: bool,
    },
    /// "Use the relay copy…" of a vault store of the Apassy Connect account that this device
    /// refuses (an older copy, or a history without its last change; connect-account-v1
    /// section 7.5): take exactly the current head `head` (version `version`), forget what
    /// this device had merged, and merge that copy. The proof names the store and the head.
    UseRelayCopy {
        team_id: String,
        version: u64,
        head: String,
    },
    /// Add a device of the Apassy Connect account, or of its group, to a vault store
    /// (section 8): the device can then read and write the relay copy of that vault. The
    /// proof names the store, the device, and the account of the device.
    AddStoreDevice {
        team_id: String,
        device_id: String,
        account_id: String,
    },
    /// Change the Family or Team group of the Apassy Connect account (connect-billing-v1
    /// section 6): confirm or remove a member, or change the seats.
    ChangeConnectGroup {
        account_id: String,
        group_id: String,
        change: ConnectGroupChange,
    },
    /// Share the vault store `team_id` ("`vault_name`", its name on this device) with
    /// another account of the family or team (connect-account-v1 section 16): this device
    /// signs `peer` for that account's root (when the people compared the six `words`;
    /// empty for an account whose root this account pinned already) and `share` of the
    /// store. The proof names the account, the person by the name that its verified list
    /// signed (`peer_name`, with its name at Connect `peer_hint` beside it), the short
    /// fingerprint of the root that the `peer` pins, the store, and the words.
    ShareConnectVault {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        team_id: String,
        vault_name: String,
        words: String,
        /// The entries that the step signs, in their order: `peer` (unless the pair is
        /// pinned), `store` (unless the list holds it), `share` (unless it is active).
        entries: Vec<ShareEntry>,
    },
    /// "The Words Match" on the device of the account that a share code was sent to: this
    /// device signs `peer` for the root of the inviting account (section 16.2).
    AcceptConnectShare {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        words: String,
        /// The entries that the step signs: the `peer`, or none for a root pinned already.
        entries: Vec<ShareEntry>,
    },
    /// A new pin of an account that was reset (section 16.7), after new words: this device
    /// signs the ends of the old root first (`unshare` and `leave` of the stores `ends`
    /// names, then `unpeer`), then `peer` for the new root, and `share` of the store
    /// `team_id` when one is named. The proof names both root fingerprints and what ends.
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
        /// The entries that the step signs, in their order (the ends, `unpeer`, `peer`,
        /// and `store` and `share` of the store when one is named).
        entries: Vec<ShareEntry>,
    },
    /// "Join" of a store that another account shares with this one: this device signs
    /// `join` of the store (section 16.2 step 5). `vault_name` is the name of a vault of
    /// this computer that syncs the store (empty when there is none: the prompt says "a
    /// vault shared by" the person), `vault_hint` the name that Connect gives the store (a
    /// hint only: the other account chose it).
    JoinConnectShare {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        team_id: String,
        vault_name: String,
        /// The entry that the step signs: the `join`.
        entries: Vec<ShareEntry>,
        vault_hint: String,
    },
    /// End a vault shared between accounts: the owner's `unshare` ("Stop Sharing with
    /// <name>…", `leave` false) or a member's `leave` ("Leave This Shared Vault…").
    EndConnectShare {
        account_id: String,
        peer_account: String,
        peer_name: String,
        peer_hint: String,
        fingerprint: String,
        team_id: String,
        vault_name: String,
        leave: bool,
        /// The entry that the step signs: the `unshare` or the `leave`.
        entries: Vec<ShareEntry>,
    },
    /// The `store` entry of a vault store that this account made before the entry existed,
    /// whose device list holds shares of it already (connect-account-v1 section 16): those
    /// shares, with `people` (their verified names), count again. The proof names the store
    /// and the entry.
    ClaimConnectStore {
        account_id: String,
        team_id: String,
        vault_name: String,
        people: Vec<String>,
        /// The entry that the step signs: the `store`.
        entries: Vec<ShareEntry>,
    },
    /// "Take This Copy Without Its Earlier History…" at the first download of a vault store
    /// of the Apassy Connect account (connect-account-v1 section 16.6): the head `head`
    /// (version `version`), signed by a device that a verified list holds, while an earlier
    /// entry of its history is by a key that no list verifies. The proof names the store and
    /// the head.
    TakeCopyWithoutHistory {
        team_id: String,
        version: u64,
        head: String,
    },
    /// Turn the tailnet route of this Mac's node on or off (plan S2–S3, unit N7): the
    /// iPhone and the other Macs reach the approvals of this Mac directly, or no longer.
    SetTailnetRoute {
        on: bool,
    },
    /// Revoke devices in Settings > Devices (plan S2–S3, unit N7): devices of the team
    /// `team_id` (on this Mac's node or another relay) by their relay numbers, or this Mac
    /// leaves the team of a Linux node. The proof names the team, the devices, and the
    /// name that the sheet showed.
    RevokeNodeDevice {
        team_id: String,
        device_ids: Vec<u64>,
        device_name: String,
    },
    /// Connect a remote agent to this Mac: allow the connect request `id` of the MCP
    /// authorization flow (plan "Bouncer section" decision 4). The proof names the
    /// request, the client name, and the match code exactly as Decisions showed them. A
    /// denial is stricter and needs no check.
    AllowConnect {
        id: String,
        client_name: String,
        code: String,
        /// Where the code goes back, as the dialog showed it (review 0.5.16).
        redirect_host: String,
    },
    /// Make a remote agent with a bearer token for the command line (`apassy agents
    /// add-remote`). The proof names the name and the token lifetime in days.
    AddRemoteAgent {
        name: String,
        days: u32,
    },
    /// Turn remote access on: Tailscale Funnel routes the internet to the node of this
    /// Mac. Off is stricter and needs no check.
    TurnOnRemoteAccess,
}

/// One entry of the signed device list that an owner check of a shared vault covers
/// (connect-account-v1 section 16): its op, the other account (none for a `store`), and
/// the store (none for a `peer` or an `unpeer`). The step signs exactly the entries of its
/// check, in their order, or nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEntry {
    pub op: String,
    pub account: Option<String>,
    pub team: Option<String>,
}

impl ShareEntry {
    /// The entry `op` for `account` and `team`.
    pub fn new(op: &str, account: Option<&str>, team: Option<&str>) -> Self {
        Self {
            op: op.to_owned(),
            account: account.map(str::to_owned),
            team: team.map(str::to_owned),
        }
    }
}

/// A change of a Connect group that needs the owner check (connect-billing-v1 section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectGroupChange {
    /// Make a pending member active: it gets the plan and can be in shared vaults.
    ConfirmMember { account_id: String, name: String },
    /// Remove a member: it leaves the shared vault stores of the group.
    RemoveMember { account_id: String, name: String },
    /// Change the people or seats of the subscription.
    SetSeats { quantity: u64 },
}

/// The words of a short-lived kind in an owner check: what each run gets.
fn delivery_words(kind: crate::vault::ShortLivedKind) -> &'static str {
    use crate::vault::ShortLivedKind as Kind;
    match kind {
        Kind::AwsSts => "AWS credentials that expire in 15 minutes",
        Kind::GithubApp => "a GitHub token for each run",
        Kind::GoogleServiceAccount => "Google access tokens that expire in 15 minutes",
        Kind::OauthRefresh => "an OAuth access token for each run",
        Kind::CloudflareToken | Kind::PlanetscalePassword | Kind::NeonRole => {
            "a credential made for each run"
        }
    }
}

/// Where the bouncer brain runs or trains, for the owner texts. No address: the dialog
/// shows it.
fn host_words(kind: crate::vault::BouncerHostKind, url: &str) -> String {
    match kind {
        crate::vault::BouncerHostKind::ThisMac => {
            concat!("on this ", crate::computer!()).to_owned()
        }
        crate::vault::BouncerHostKind::OwnServer => format!("on your server {}", host_name(url)),
        crate::vault::BouncerHostKind::Connect => format!("at Apassy Connect {}", host_name(url)),
    }
}

/// The host name (and port) of an `https://` address for the Touch ID reason: printable
/// characters only. A long name keeps its end, where the domain that owns it is, so a
/// name such as `brain.example.com.evil.net` cannot hide `evil.net`.
fn host_name(url: &str) -> String {
    const MAX_HOST_CHARS: usize = 60;
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let host: Vec<char> = rest
        .split('/')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_graphic() && *c != '"')
        .collect();
    if host.is_empty() {
        "unknown".to_owned()
    } else if host.len() > MAX_HOST_CHARS {
        let tail: String = host[host.len() - (MAX_HOST_CHARS - 1)..].iter().collect();
        format!("…{tail}")
    } else {
        host.into_iter().collect()
    }
}

/// The words for the Touch ID prompt after the relying party of a passkey. `None` is
/// the macOS passkey sheet.
/// What an assertion gives beyond its signature, from its WebAuthn extensions, for the
/// owner texts. It has no value of the request: only the length of a blob to write. An
/// empty write stores nothing, so it is not named.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PasskeyExtras {
    /// PRF inputs: the page gets PRF outputs, a key made from the passkey.
    pub(crate) prf: bool,
    /// A largeBlob read: the page gets the data stored with the passkey.
    pub(crate) read: bool,
    /// A largeBlob write of this many bytes, stored in the vault.
    pub(crate) write: Option<usize>,
}

impl PasskeyExtras {
    pub(crate) fn of(extensions: &crate::vault::PasskeyAssertionExtensions) -> Self {
        use crate::vault::LargeBlobOp;
        Self {
            prf: extensions.prf.is_some(),
            read: matches!(extensions.large_blob, Some(LargeBlobOp::Read)),
            write: match &extensions.large_blob {
                Some(LargeBlobOp::Write(blob)) if !blob.is_empty() => Some(blob.len()),
                _ => None,
            },
        }
    }

    /// What the page gets: "a key made from the passkey", "the data stored with the
    /// passkey", or both. `None` for neither.
    fn gets(&self) -> Option<&'static str> {
        match (self.prf, self.read) {
            (true, true) => {
                Some("a key made from the passkey and the data stored with the passkey")
            }
            (true, false) => Some("a key made from the passkey"),
            (false, true) => Some("the data stored with the passkey"),
            (false, false) => None,
        }
    }

    fn bytes(n: usize) -> String {
        if n == 1 {
            "1 byte".to_owned()
        } else {
            format!("{n} bytes")
        }
    }

    /// The sentences of the owner dialog, each with a leading space. Empty without
    /// extensions.
    #[cfg(feature = "desktop")]
    pub(crate) fn sentences(&self) -> String {
        let mut text = String::new();
        if let Some(gets) = self.gets() {
            text.push_str(&format!(" The page also gets {gets}."));
        }
        if let Some(n) = self.write {
            text.push_str(&format!(
                " The page also stores {} with the passkey in Apassy.",
                Self::bytes(n)
            ));
        }
        text
    }

    /// The end of the Touch ID reason, with a leading comma. Empty without extensions.
    fn reason(&self) -> String {
        let mut text = String::new();
        if let Some(gets) = self.gets() {
            text.push_str(&format!(", and give the page {gets}"));
        }
        if let Some(n) = self.write {
            text.push_str(&format!(", and store {} with the passkey", Self::bytes(n)));
        }
        text
    }
}

fn passkey_caller(origin: Option<&String>) -> &'static str {
    match origin {
        Some(_) => " in your browser",
        None => " for a macOS request",
    }
}

impl OwnerAction {
    /// Trusted heading: never interpolate website, agent, item, or request text.
    pub fn touch_id_title(&self) -> &'static str {
        match self {
            Self::FillLogin { .. } | Self::FillSystemLogin { .. } => "Fill a password",
            Self::SaveLogin { .. } => "Save a password",
            Self::UpdateLogin { .. } => "Update a password",
            Self::CreateLogin { .. } => "Create a password",
            Self::SignPasskey { .. } => "Sign in with a passkey",
            Self::CreatePasskey { .. } => "Create a passkey",
            Self::RemovePasskey { .. } => "Remove a passkey",
            Self::AllowAccessOnce { .. } | Self::ApproveRun(_) => "Allow once",
            Self::QuestionDevelopment { .. } => "Allow Development",
            Self::ClassifyRemoteRun { environment, .. } => match environment {
                crate::vault::Environment::Development => "Allow as Development",
                crate::vault::Environment::Production => "Allow as Production",
                _ => "Allow once",
            },
            Self::BrowserDebugging { scope: None, .. } => "Trust a browser profile",
            Self::BrowserDebugging { .. } => "Allow browser debugging",
            Self::ShowCode { .. } | Self::CliCode { copy: false, .. } => "Show a one-time code",
            Self::CopyCode { .. } | Self::CliCode { copy: true, .. } => "Copy a one-time code",
            Self::FillCode { .. } | Self::FillSystemCode { .. } => "Fill a one-time code",
            Self::Reveal { .. } => "Show a secret",
            Self::CopyField { .. } => "Copy a secret",
            Self::BackupVault { .. } => "Back up Apassy",
            Self::ExportDecisions => "Export decisions",
            Self::RegisterAgent { .. }
            | Self::RegisterSetupAgent { .. }
            | Self::AddRemoteAgent { .. } => "Connect an agent",
            Self::AllowConnect { .. } => "Connect a remote agent",
            Self::TurnOnRemoteAccess => "Turn on remote access",
            Self::ChangeOwnerFrequency { .. } => "Change owner checks",
            Self::RemoveOlderIphone { device, .. } if device.kind == TrustedDeviceKind::Watch => {
                "Remove an Apple Watch"
            }
            Self::RemoveOlderIphone { .. } => "Remove an iPhone",
            Self::ChangeBouncerHosting { .. } => "Change the bouncer brain host",
            Self::ChangeBouncerTraining { .. } => "Change the bouncer brain training",
            Self::ChangeDelivery { on: true, .. } => "Use temporary credentials",
            Self::ChangeDelivery { on: false, .. } => "Stop temporary credentials",
            Self::ChangeShortLivedSettings { .. } => "Change temporary credentials",
            Self::ConfirmConnectDevice { .. } => "Add a device to Apassy Connect",
            Self::RevokeConnectDevice { .. } => "Remove a device from Apassy Connect",
            Self::DeleteConnectAccount { .. } => "Delete the Apassy Connect account",
            Self::NewRecoveryCode { .. } => "Make a new recovery code",
            Self::RecoverConnectAccount { .. } => "Recover the Apassy Connect account",
            Self::ForgetOldConnectAccount => "Forget the Apassy Connect account here",
            Self::DeleteVaultStore { .. } => "Delete a relay copy at Apassy Connect",
            Self::TakeDepartedCopy { replace: false, .. } => "Use the copy of a device that left",
            Self::TakeDepartedCopy { replace: true, .. } => {
                "Replace the copy of a device that left"
            }
            Self::UseRelayCopy { .. } => "Use the relay copy of a vault",
            Self::AddStoreDevice { .. } => "Add a device to a relay copy",
            Self::ChangeConnectGroup { .. } => "Change your family or team",
            Self::ShareConnectVault { .. } => "Share a vault",
            Self::AcceptConnectShare { .. } => "Accept a shared vault",
            Self::RepinConnectPeer { .. } => "Verify a reset account",
            Self::JoinConnectShare { .. } => "Join a shared vault",
            Self::EndConnectShare { leave: false, .. } => "Stop sharing a vault",
            Self::EndConnectShare { leave: true, .. } => "Leave a shared vault",
            Self::ClaimConnectStore { .. } => "Count the shares of a vault",
            Self::TakeCopyWithoutHistory { .. } => "Take a copy without its history",
            Self::SetTailnetRoute { on: true } => {
                concat!("Reach this ", crate::computer!(), " on your tailnet")
            }
            Self::SetTailnetRoute { on: false } => "Stop the tailnet route",
            Self::RevokeNodeDevice { .. } => "Revoke a device",
            _ => "Confirm with Touch ID",
        }
    }

    /// Supporting purpose text, also used by the system-dialog fallback.
    /// It has no secret value and no command.
    pub fn reason(&self) -> String {
        match self {
            Self::BrowserDebugging { .. } => "allow this exact browser debugging instance".into(),
            Self::RemoveOlderIphone { device, .. } if device.kind == TrustedDeviceKind::Watch => {
                "remove the older paired Apple Watch".into()
            }
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
                concat!("change how often Apassy asks for ", crate::touch_id!()).to_owned()
            }
            Self::Reveal { .. } => "show the secret values of an item".to_owned(),
            Self::CliCode { copy, .. } => if *copy {
                "copy a CLI one-time code"
            } else {
                "show a CLI one-time code"
            }
            .to_owned(),
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
            Self::SignPasskey {
                origin,
                rp_id,
                extensions,
                ..
            } => format!(
                "sign in to {} with a passkey{}{}",
                short_site(rp_id),
                passkey_caller(origin.as_ref()),
                PasskeyExtras::of(extensions).reason()
            ),
            Self::CreatePasskey { origin, rp_id, .. } => format!(
                "create a passkey for {}{}",
                short_site(rp_id),
                passkey_caller(origin.as_ref())
            ),
            Self::ApproveRun(run) => format!("approve a run of agent \"{}\"", short_name(run)),
            Self::ClassifyRemoteRun { run, environment } => format!(
                "classify as {environment:?} and approve a run of agent \"{}\"",
                short_name(run)
            ),
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
            Self::QuestionDevelopment { .. } => "mark a question item as development".to_owned(),
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
                "change the task_match level of the bouncer gate".to_owned()
            }
            Self::PromoteModel { .. } => "promote a new bouncer brain".to_owned(),
            Self::RollbackModel { .. } => "roll back the bouncer brain".to_owned(),
            Self::ChangeBouncerHosting { kind, url, .. } => {
                format!("run the bouncer brain {}", host_words(*kind, url))
            }
            Self::ChangeBouncerTraining { kind, url, .. } => {
                format!("train the bouncer brain {}", host_words(*kind, url))
            }
            Self::ChangeDelivery { kind, on: true, .. } => format!(
                "give agents {} instead of this item's long-lived key",
                delivery_words(*kind)
            ),
            Self::ChangeDelivery {
                kind, on: false, ..
            } => format!(
                "stop {} and let agents use this item's long-lived key",
                delivery_words(*kind)
            ),
            Self::ChangeShortLivedSettings { kind, .. } => format!(
                "change what {} of this item can do and where Apassy asks for them",
                delivery_words(*kind)
            ),
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
            Self::ConfirmConnectDevice {
                device_name, words, ..
            } => format!(
                "add the device \"{}\" to your Apassy Connect account; both devices show: {}",
                short_device_name(device_name),
                words
                    .chars()
                    .filter(|c| c.is_ascii_lowercase() || *c == ' ')
                    .take(80)
                    .collect::<String>()
            ),
            Self::RevokeConnectDevice {
                device_name,
                fingerprint,
                ..
            } => format!(
                "remove the device \"{}\" (key {}) from your Apassy Connect account",
                short_device_name(device_name),
                fingerprint
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit() || *c == ' ')
                    .take(14)
                    .collect::<String>()
            ),
            Self::DeleteConnectAccount { .. } => {
                "delete your Apassy Connect account, its vault stores, and its plan".to_owned()
            }
            Self::NewRecoveryCode { .. } => {
                "make a new recovery code for your Apassy Connect account; the old code stops working".to_owned()
            }
            Self::RecoverConnectAccount { account_id } => format!(
                "recover the Apassy Connect account {}; its vault copies at Connect are deleted",
                account_id
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .take(14)
                    .collect::<String>()
            ),
            Self::ForgetOldConnectAccount => {
                "forget the Apassy Connect account on this device".to_owned()
            }
            Self::DeleteVaultStore { .. } => {
                "delete the relay copy of this vault and its snapshots at Apassy Connect".to_owned()
            }
            Self::TakeDepartedCopy { replace: false, .. } => {
                "merge the relay copy that a device that left your Apassy Connect account saved last".to_owned()
            }
            Self::TakeDepartedCopy { replace: true, .. } => {
                "replace the relay copy that a device that left your Apassy Connect account saved last".to_owned()
            }
            Self::UseRelayCopy { .. } => {
                "take the relay copy of this vault at Apassy Connect as it is now, and merge it".to_owned()
            }
            Self::AddStoreDevice { .. } => {
                "let another device sync the relay copy of this vault at Apassy Connect".to_owned()
            }
            Self::ChangeConnectGroup { change, .. } => match change {
                ConnectGroupChange::ConfirmMember { name, .. } => format!(
                    "add \"{}\" to your Apassy Connect family or team",
                    short_device_name(name)
                ),
                ConnectGroupChange::RemoveMember { name, .. } => format!(
                    "remove \"{}\" from your Apassy Connect family or team",
                    short_device_name(name)
                ),
                ConnectGroupChange::SetSeats { quantity } => {
                    format!("change your Apassy Connect plan to {quantity} people or seats")
                }
            },
            Self::ShareConnectVault {
                peer_name,
                vault_name,
                words,
                ..
            } if words.is_empty() => format!(
                "share \"{}\" with \"{}\" through Apassy Connect",
                short_device_name(vault_name),
                short_device_name(peer_name)
            ),
            Self::ShareConnectVault {
                peer_name,
                vault_name,
                words,
                ..
            } => format!(
                "share \"{}\" with \"{}\" through Apassy Connect; both show: {}",
                short_device_name(vault_name),
                short_device_name(peer_name),
                safe_words(words)
            ),
            Self::AcceptConnectShare {
                peer_name, words, ..
            } => format!(
                "accept the vaults that \"{}\" shares through Apassy Connect; both show: {}",
                short_device_name(peer_name),
                safe_words(words)
            ),
            Self::RepinConnectPeer {
                peer_name, words, ..
            } => format!(
                "verify the reset account of \"{}\" through Apassy Connect; both show: {}",
                short_device_name(peer_name),
                safe_words(words)
            ),
            Self::JoinConnectShare {
                peer_name,
                vault_name,
                ..
            } if vault_name.is_empty() => format!(
                "join a vault shared by \"{}\" through Apassy Connect",
                short_device_name(peer_name)
            ),
            Self::JoinConnectShare {
                peer_name,
                vault_name,
                ..
            } => format!(
                "join \"{}\", shared by \"{}\" through Apassy Connect",
                short_device_name(vault_name),
                short_device_name(peer_name)
            ),
            Self::EndConnectShare {
                peer_name,
                vault_name,
                leave: false,
                ..
            } => format!(
                "stop sharing \"{}\" with \"{}\" through Apassy Connect",
                short_device_name(vault_name),
                short_device_name(peer_name)
            ),
            Self::EndConnectShare {
                peer_name,
                vault_name,
                leave: true,
                ..
            } => format!(
                "leave \"{}\", shared by \"{}\" through Apassy Connect",
                short_device_name(vault_name),
                short_device_name(peer_name)
            ),
            Self::ClaimConnectStore { vault_name, .. } => format!(
                "count the earlier shares of \"{}\" through Apassy Connect again",
                short_device_name(vault_name)
            ),
            Self::TakeCopyWithoutHistory { .. } => {
                "take the relay copy of this vault at Apassy Connect without its earlier history".to_owned()
            }
            Self::SetTailnetRoute { on: true } => concat!(
                "let your iPhone and ",
                crate::computers!(),
                " reach this ",
                crate::computer!(),
                " directly on your tailnet"
            )
            .to_owned(),
            Self::SetTailnetRoute { on: false } => concat!(
                "stop the tailnet route of this ",
                crate::computer!(),
                "; approvals go through Apassy relay"
            )
            .to_owned(),
            Self::RevokeNodeDevice { device_name, .. } => format!(
                "revoke the device \"{}\"; it can no longer see or answer questions",
                short_device_name(device_name)
            ),
            Self::AllowConnect {
                client_name,
                redirect_host,
                ..
            } => {
                // Where the code goes back (review 0.5.16); a loopback host is "localhost".
                let back = if redirect_host.is_empty()
                    || crate::questions::envelope::is_local_redirect_host(redirect_host)
                {
                    "localhost".to_owned()
                } else {
                    short_device_name(redirect_host)
                };
                format!(
                    concat!(
                        "connect \"{}\", which returns to {back}, to this ",
                        crate::computer!()
                    ),
                    short_device_name(client_name),
                    back = back
                )
            }
            Self::AddRemoteAgent { name, .. } => format!(
                "add the remote agent \"{}\" and issue its token",
                short_device_name(name)
            ),
            Self::TurnOnRemoteAccess => concat!(
                "let remote agents reach this ",
                crate::computer!(),
                " through Tailscale Funnel"
            )
            .to_owned(),
        }
    }

    /// True for an action that only a fresh Touch ID or passphrase check on this Mac can
    /// confirm: the global owner window never covers it (ADR 0035 section 1, plan 0035
    /// C2). A change of the bouncer brain host or trainer sends request data to another
    /// computer, so each change asks again. The Apassy Connect account actions (plan s7
    /// M1) add or remove a device or a person of the account, a device of a vault store,
    /// or a vault store, or end the account, so each asks again too. Turning way C off
    /// gives runs the long-lived key again (contract private-sharing-v1 rule 3), so it
    /// asks again as well; turning it on gives runs less and stays in the window.
    /// `AddRemoteAgent` mints a bearer token that works from the internet and goes back
    /// to the caller of the command line, whose session proves no owner at the Mac
    /// (owner-cli-v1 §4, review 0.5.16).
    /// Whether the start screen may confirm this action while no vault is unlocked (the
    /// owner takes the copy that a removed device left on a vault store, connect-account-v1
    /// section 7.5). Every other action needs an unlocked vault.
    pub fn allowed_without_vault(&self) -> bool {
        matches!(
            self,
            Self::TakeDepartedCopy { replace: false, .. } | Self::TakeCopyWithoutHistory { .. }
        )
    }

    pub fn needs_fresh_local_check(&self) -> bool {
        matches!(
            self,
            Self::AddRemoteAgent { .. }
                | Self::ChangeBouncerHosting { .. }
                | Self::ChangeBouncerTraining { .. }
                | Self::ChangeShortLivedSettings { .. }
                | Self::ChangeDelivery { on: false, .. }
                | Self::ConfirmConnectDevice { .. }
                | Self::RevokeConnectDevice { .. }
                | Self::DeleteConnectAccount { .. }
                | Self::NewRecoveryCode { .. }
                | Self::RecoverConnectAccount { .. }
                | Self::ForgetOldConnectAccount
                | Self::DeleteVaultStore { .. }
                | Self::TakeDepartedCopy { .. }
                | Self::UseRelayCopy { .. }
                | Self::AddStoreDevice { .. }
                | Self::ChangeConnectGroup { .. }
                | Self::ShareConnectVault { .. }
                | Self::AcceptConnectShare { .. }
                | Self::RepinConnectPeer { .. }
                | Self::JoinConnectShare { .. }
                | Self::EndConnectShare { .. }
                | Self::ClaimConnectStore { .. }
                | Self::TakeCopyWithoutHistory { .. }
        )
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

/// The six safety words as an owner check shows them: lowercase letters and spaces only,
/// at most 80 characters.
fn safe_words(words: &str) -> String {
    words
        .chars()
        .filter(|c| c.is_ascii_lowercase() || *c == ' ')
        .take(80)
        .collect()
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
    /// Linux polkit auth_self authentication, never reported as biometrics.
    Polkit,
    Passphrase,
    /// Face ID on a paired iPhone, as a signature of the approval key.
    Companion,
    /// A device of the vault through the relay: the Face ID answer key of an iPhone, or
    /// the relay key of a Mac after its Touch ID (relay-questions-v1 section 12.4).
    Remote,
}

/// The check that the owner does now.
pub enum OwnerCheck {
    /// Current answer kinds, verified against their exact action and pending run.
    RemoteChoice {
        device_uuid: String,
        team_id: String,
        qid: String,
        time: u64,
        signature: Vec<u8>,
        run: Box<PendingRun>,
        choice: Choice,
    },
    /// Touch ID through the native helper.
    TouchId,
    /// Linux system authentication for this exact pending action.
    #[cfg(target_os = "linux")]
    Polkit,
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
            #[cfg(target_os = "linux")]
            Self::Polkit => CheckMethod::Polkit,
            Self::Passphrase(_) => CheckMethod::Passphrase,
            Self::Companion { .. } => CheckMethod::Companion,
            Self::Remote { .. } | Self::RemoteChoice { .. } | Self::RemoteAction { .. } => {
                CheckMethod::Remote
            }
        }
    }
}

impl fmt::Debug for OwnerCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TouchId => f.write_str("OwnerCheck::TouchId"),
            #[cfg(target_os = "linux")]
            Self::Polkit => f.write_str("OwnerCheck::Polkit"),
            Self::RemoteChoice { .. } => f.write_str("OwnerCheck::RemoteChoice([redacted])"),
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
            concat!(
                "the Touch ID keyboard is not connected or not paired, or this ",
                crate::computer!(),
                " has no Touch ID sensor."
            )
        }
        HelperErrorCode::NotEnrolled => "no fingerprint is enrolled in System Settings.",
        HelperErrorCode::LockedOut => {
            concat!(
                "Touch ID is locked after failed attempts. Unlock the ",
                crate::computer!(),
                " with its password to reset it."
            )
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

/// The epoch of the session of a step that runs while no vault is unlocked (the start
/// screen's Apassy Connect path), now; `None` while there is none.
pub type StartEpoch = Arc<dyn Fn() -> Option<[u8; 32]> + Send + Sync>;

/// Why a check without an unlocked vault cannot use the passphrase.
#[cfg(not(target_os = "linux"))]
const NO_VAULT_TO_CONFIRM: &str = "No vault is unlocked on this Mac, so its passphrase cannot confirm this. Confirm with Touch ID, or ask on another device of the account instead.";
/// Why a check without an unlocked vault cannot use the passphrase.
#[cfg(target_os = "linux")]
const NO_VAULT_TO_CONFIRM: &str = "No vault is unlocked on this computer, so its passphrase cannot confirm this. Confirm with system authentication, or ask on another device of the account instead.";

/// The owner-authorization gate. It holds the shared vault and, when the app has one,
/// the native helper for Touch ID.
#[derive(Clone)]
pub struct OwnerGate {
    vault: SharedVault,
    touch_id: Option<NativeHelper>,
    window: super::owner_window::OwnerWindow,
    /// The session of the start screen's Connect path, for the few actions that it may
    /// confirm while no vault is unlocked ([`OwnerAction::allowed_without_vault`]).
    start: Option<StartEpoch>,
}

impl std::fmt::Debug for OwnerGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerGate")
            .field("vault", &self.vault)
            .field("touch_id", &self.touch_id)
            .field("window", &self.window)
            .field("start", &self.start.is_some())
            .finish()
    }
}

impl OwnerGate {
    /// `touch_id` is `None` when this build has no native helper. Then only the
    /// passphrase check works.
    pub fn new(vault: SharedVault, touch_id: Option<NativeHelper>) -> Self {
        Self {
            vault,
            touch_id,
            window: Default::default(),
            start: None,
        }
    }

    /// The gate with `start`, the epoch of the start screen's Connect session: while no
    /// vault is unlocked, an action of [`OwnerAction::allowed_without_vault`] is confirmed
    /// with Touch ID or system authentication and bound to that session.
    pub fn with_start_session(mut self, start: StartEpoch) -> Self {
        self.start = Some(start);
        self
    }

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
            tracing::info!(
                reason = "source_action",
                heartbeat_age_ms = self.window.heartbeat_age_ms(),
                "owner window reuse refused"
            );
            return None;
        }
        if action.needs_fresh_local_check() {
            tracing::info!(reason = "fresh_only", "owner window reuse refused");
            return None;
        }
        // ticket() synchronously probes the same lifecycle helper that observed
        // the seed. A separate helper cannot attest intervening lock events.
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
        if self.session().is_err() && action.allowed_without_vault() {
            return self.authorize_without_vault(action, check, cancel);
        }
        let generation = self.window.generation();
        let local = matches!(
            check.method(),
            CheckMethod::TouchId | CheckMethod::Passphrase | CheckMethod::Polkit
        );
        let mut result = self.authorize_fresh(action.clone(), check, cancel);
        if local && result.is_ok() {
            if self.window.generation() != generation {
                result = Err(OwnerAuthError::SessionChanged);
            } else if let Ok(proof) = &mut result {
                proof.local_generation = Some((self.window.clone(), generation));
            }
        }
        if let Ok(proof) = &result {
            self.window.seed(proof.epoch, proof.method, generation);
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
            OwnerCheck::RemoteChoice {
                device_uuid,
                team_id,
                qid,
                time,
                signature,
                run,
                choice,
            } => {
                if !matches!(
                    choice,
                    Choice::Approve | Choice::ApproveAsDevelopment | Choice::ApproveAsProduction
                ) || !choice.valid_for(&run.question)
                    || crate::questions::answer::local_action(&run, &choice).as_ref()
                        != Some(&action)
                {
                    return Err(OwnerAuthError::RemoteUnsupported);
                }
                let device = {
                    let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
                    match guard.as_ref() {
                        Some(vault) if !vault.is_locked() && vault.epoch() == epoch => vault
                            .trusted_device(&device_uuid)
                            .map_err(|e| OwnerAuthError::Other(e.to_string()))?,
                        _ => return Err(OwnerAuthError::SessionChanged),
                    }
                }
                .ok_or(OwnerAuthError::RemoteRejected)?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |t| t.as_secs());
                verify_remote_answer(
                    &device,
                    &team_id,
                    &qid,
                    &choice,
                    &question_digest_v2_hex(&run),
                    time,
                    &signature,
                    now,
                )?;
            }
            #[cfg(target_os = "linux")]
            OwnerCheck::Polkit => {
                crate::native::linux::authenticate(cancel).map_err(|_| {
                    OwnerAuthError::Other(
                        "System authentication did not succeed. Confirm with the passphrase."
                            .into(),
                    )
                })?;
            }
            OwnerCheck::TouchId => {
                let Some(helper) = &self.touch_id else {
                    return Err(OwnerAuthError::TouchIdUnavailable {
                        detail: "this build has no Touch ID helper.".to_owned(),
                    });
                };
                let reason = action.reason();
                helper
                    .authenticate_titled(&reason, action.touch_id_title(), cancel)
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
    /// The check of an action of [`OwnerAction::allowed_without_vault`] while no vault is
    /// unlocked: Touch ID, or system authentication on Linux; no vault holds a passphrase
    /// to check, and no other device answers it. The proof is bound to the epoch of the
    /// start-screen session, which must be the same after the check, still with no vault.
    /// It seeds no window of later checks.
    fn authorize_without_vault(
        &self,
        action: OwnerAction,
        check: OwnerCheck,
        cancel: Option<&AuthCancel>,
    ) -> Result<OwnerProof, OwnerAuthError> {
        let cancelled = || cancel.is_some_and(AuthCancel::is_cancelled);
        let start_epoch = || self.start.as_ref().and_then(|start| start());
        let Some(epoch) = start_epoch() else {
            return Err(OwnerAuthError::VaultLocked);
        };
        if cancelled() {
            return Err(OwnerAuthError::Cancelled);
        }
        let method = check.method();
        match check {
            OwnerCheck::TouchId => {
                let Some(helper) = &self.touch_id else {
                    return Err(OwnerAuthError::TouchIdUnavailable {
                        detail: "this build has no Touch ID helper.".to_owned(),
                    });
                };
                helper
                    .authenticate_titled(&action.reason(), action.touch_id_title(), cancel)
                    .map_err(from_native)?;
            }
            #[cfg(target_os = "linux")]
            OwnerCheck::Polkit => {
                crate::native::linux::authenticate(cancel)
                    .map_err(|_| OwnerAuthError::Other(NO_VAULT_TO_CONFIRM.to_owned()))?;
            }
            OwnerCheck::Passphrase(_) => {
                return Err(OwnerAuthError::Other(NO_VAULT_TO_CONFIRM.to_owned()));
            }
            _ => return Err(OwnerAuthError::RemoteUnsupported),
        }
        if cancelled() {
            return Err(OwnerAuthError::Cancelled);
        }
        if self.session().is_ok() || start_epoch() != Some(epoch) {
            return Err(OwnerAuthError::SessionChanged);
        }
        Ok(OwnerProof::issue(action, method, epoch))
    }

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
/// (`sign_key`). `None`: an iPhone without an answer key, and an Apple Watch for every
/// answer: a watch answers access requests only (ADR 0039 §3).
pub fn remote_key<'a>(device: &'a TrustedDevice, choice: &Choice) -> Option<&'a [u8]> {
    match device.kind {
        TrustedDeviceKind::Watch => None,
        TrustedDeviceKind::Iphone if choice.needs_owner_check() => device.answer_key.as_deref(),
        TrustedDeviceKind::Iphone | TrustedDeviceKind::Mac => Some(device.sign_key.as_slice()),
    }
}

/// Verify an answer through the relay at the time `now` (relay-questions-v1 sections
/// 12.3 step 7 and 12.4): `now - 60 <= time <= now + 60`, then the signature over the
/// answer string rebuilt from the device, the team, the question, `choice`, `digest`, and
/// `time`, with the key of [`remote_key`]. A signature by the other key of the device is
/// invalid. An Apple Watch is refused for every answer, as an unknown device is (ADR
/// 0039 §3).
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
    if device.kind == TrustedDeviceKind::Watch {
        return Err(OwnerAuthError::RemoteRejected);
    }
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
/// for an `only` row. A Mac and an Apple Watch (ADR 0039 §3) are no senders in v1, and a
/// signature by the other key of the device is invalid.
pub fn verify_remote_action(
    device: &TrustedDevice,
    signed: &crate::questions::feed::RemovalAction,
    signature: &[u8],
    now: u64,
) -> Result<(), OwnerAuthError> {
    if !crate::questions::feed::in_window(signed.time, now) {
        return Err(OwnerAuthError::RemoteStale);
    }
    // Only an iPhone: a Mac and a watch row are refused for every action.
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

    #[cfg(feature = "desktop")]
    #[test]
    fn global_owner_source_removes_sensitive_action_exclusions() {
        for action in [
            OwnerAction::AllowAccessOnce {
                request_id: 1,
                digest: "test".into(),
            },
            OwnerAction::BackupVault {
                path: "/tmp/synthetic.backup".into(),
            },
            OwnerAction::ExportDecisions,
            OwnerAction::RegisterAgent {
                name: "Synthetic".into(),
            },
            OwnerAction::RegisterSetupAgent {
                name: "Synthetic".into(),
            },
            OwnerAction::ChangeOwnerFrequency {
                old: super::super::OwnerFrequency::EveryTime,
                new: super::super::OwnerFrequency::OneHour,
            },
            OwnerAction::Reveal { item_id: 1 },
            OwnerAction::CliCode {
                item_id: 1,
                field: "otp".into(),
                copy: false,
            },
            OwnerAction::ShowCode {
                item_id: 1,
                field: "otp".into(),
            },
            OwnerAction::CopyCode {
                item_id: 1,
                field: "otp".into(),
            },
            OwnerAction::CopyField {
                item_id: 1,
                field: "password".into(),
                revision: 1,
            },
            OwnerAction::RemovePasskey {
                item_id: 1,
                revision: 1,
            },
            OwnerAction::RemoveOwnerAnswer { answer_id: 1 },
            OwnerAction::ChangeGrant {
                agent_id: 1,
                item_id: 1,
            },
            OwnerAction::ChangeGrants {
                agent_id: 1,
                item_ids: vec![1],
            },
            OwnerAction::ShowAllCredentials { agent_id: 1 },
            OwnerAction::ChangeRule {
                agent_id: 1,
                item_id: 1,
            },
            OwnerAction::ChangeItemRules { item_id: 1 },
            OwnerAction::RotateToken { agent_id: 1 },
            OwnerAction::ConnectAgent {
                agent_id: 1,
                show_all: true,
            },
            OwnerAction::ChangeTokenLifetime,
            OwnerAction::ChangeCalibration { level: 80 },
            OwnerAction::PromoteModel {
                candidate_id: 1,
                version: "synthetic".into(),
            },
            OwnerAction::RollbackModel { activation_id: 1 },
            OwnerAction::OpenCliSession,
            OwnerAction::BindVariables {
                variables: vec![(1, "KEY".into())],
            },
            OwnerAction::PairCompanion {
                device_id: "synthetic".into(),
                device_name: "Synthetic".into(),
                request_key: vec![1; 65],
                approval_key: vec![2; 65],
            },
            OwnerAction::ConfirmSyncDevice {
                link_id: 1,
                device_name: "Synthetic".into(),
                public_key: vec![1; 65],
            },
            OwnerAction::EnableRelayQuestions {
                relay_url: "https://example.invalid".into(),
                team_id: None,
            },
            OwnerAction::AllowConnect {
                id: "cr_synthetic".into(),
                client_name: "Grok Bot".into(),
                code: "K7Q-4MD".into(),
                redirect_host: "grok.example".into(),
            },
            OwnerAction::TurnOnRemoteAccess,
        ] {
            assert!(LocalWindowSource::LocalOwner.permits(&action), "{action:?}");
        }
        // A new remote agent always asks again (review 0.5.16).
        let remote = OwnerAction::AddRemoteAgent {
            name: "Grok Bot".into(),
            days: 90,
        };
        assert!(!LocalWindowSource::LocalOwner.permits(&remote));
    }

    /// The Apassy Connect account actions (plan s7 M1) always need a fresh check on this
    /// Mac: the global window never covers them, no phone or other Mac makes them, and
    /// their texts name the device and the words without passing the Touch ID limit.
    #[test]
    fn connect_account_actions_need_a_fresh_local_check() {
        let long = "N".repeat(200);
        for action in [
            OwnerAction::ConfirmConnectDevice {
                account_id: "acc_k7m2q4x3ca".into(),
                join_id: 4,
                device_name: long.clone(),
                public_key: vec![4; 65],
                words: "blaze cable flute board seal tiger".into(),
            },
            OwnerAction::RevokeConnectDevice {
                account_id: "acc_k7m2q4x3ca".into(),
                device_id: "dev_p4n6r2t7bc".into(),
                device_name: long.clone(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
            },
            OwnerAction::DeleteConnectAccount {
                account_id: "acc_k7m2q4x3ca".into(),
            },
            OwnerAction::NewRecoveryCode {
                account_id: "acc_k7m2q4x3ca".into(),
            },
            OwnerAction::RecoverConnectAccount {
                account_id: "acc_k7m2q4x3ca".into(),
            },
            OwnerAction::ChangeConnectGroup {
                account_id: "acc_k7m2q4x3ca".into(),
                group_id: "grp_f4m6n2p7qa".into(),
                change: ConnectGroupChange::ConfirmMember {
                    account_id: "acc_m3n5p7q2rb".into(),
                    name: long.clone(),
                },
            },
            OwnerAction::ChangeConnectGroup {
                account_id: "acc_k7m2q4x3ca".into(),
                group_id: "grp_f4m6n2p7qa".into(),
                change: ConnectGroupChange::SetSeats { quantity: 6 },
            },
            OwnerAction::DeleteVaultStore {
                team_id: "t".repeat(32),
            },
            OwnerAction::TakeDepartedCopy {
                team_id: "t".repeat(32),
                version: 7,
                head: "a".repeat(64),
                replace: false,
            },
            OwnerAction::TakeDepartedCopy {
                team_id: "t".repeat(32),
                version: 7,
                head: "a".repeat(64),
                replace: true,
            },
            OwnerAction::UseRelayCopy {
                team_id: "t".repeat(32),
                version: 7,
                head: "a".repeat(64),
            },
            OwnerAction::AddStoreDevice {
                team_id: "t".repeat(32),
                device_id: "dev_p4n6r2t7bc".into(),
                account_id: "acc_m3n5p7q2rb".into(),
            },
            OwnerAction::ShareConnectVault {
                account_id: "acc_k7m2q4x3ca".into(),
                peer_account: "acc_m3n5p7q2rb".into(),
                peer_name: long.clone(),
                peer_hint: "Ola".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                team_id: "t_7k2m5q4x3c".into(),
                vault_name: long.clone(),
                words: "blaze cable flute board seal tiger".into(),
                entries: Vec::new(),
            },
            OwnerAction::ShareConnectVault {
                account_id: "acc_k7m2q4x3ca".into(),
                peer_account: "acc_m3n5p7q2rb".into(),
                peer_name: long.clone(),
                peer_hint: "Ola".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                team_id: "t_7k2m5q4x3c".into(),
                vault_name: long.clone(),
                words: String::new(),
                entries: Vec::new(),
            },
            OwnerAction::AcceptConnectShare {
                account_id: "acc_m3n5p7q2rb".into(),
                peer_account: "acc_k7m2q4x3ca".into(),
                peer_name: long.clone(),
                peer_hint: "Rafal".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                words: "blaze cable flute board seal tiger".into(),
                entries: Vec::new(),
            },
            OwnerAction::RepinConnectPeer {
                account_id: "acc_k7m2q4x3ca".into(),
                peer_account: "acc_m3n5p7q2rb".into(),
                peer_name: long.clone(),
                peer_hint: "Ola".into(),
                old_fingerprint: "9a8b 7c6d 5e4f".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                words: "blaze cable flute board seal tiger".into(),
                ends: vec![long.clone()],
                team_id: Some("t_7k2m5q4x3c".into()),
                vault_name: Some(long.clone()),
                entries: Vec::new(),
            },
            OwnerAction::JoinConnectShare {
                account_id: "acc_m3n5p7q2rb".into(),
                peer_account: "acc_k7m2q4x3ca".into(),
                peer_name: long.clone(),
                peer_hint: "Rafal".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                team_id: "t_7k2m5q4x3c".into(),
                vault_name: long.clone(),
                entries: Vec::new(),
                vault_hint: long.clone(),
            },
            OwnerAction::EndConnectShare {
                account_id: "acc_k7m2q4x3ca".into(),
                peer_account: "acc_m3n5p7q2rb".into(),
                peer_name: long.clone(),
                peer_hint: "Ola".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                team_id: "t_7k2m5q4x3c".into(),
                vault_name: long.clone(),
                leave: false,
                entries: Vec::new(),
            },
            OwnerAction::EndConnectShare {
                account_id: "acc_m3n5p7q2rb".into(),
                peer_account: "acc_k7m2q4x3ca".into(),
                peer_name: long.clone(),
                peer_hint: "Rafal".into(),
                fingerprint: "1a2b 3c4d 5e6f".into(),
                team_id: "t_7k2m5q4x3c".into(),
                vault_name: long.clone(),
                leave: true,
                entries: Vec::new(),
            },
            OwnerAction::ClaimConnectStore {
                account_id: "acc_k7m2q4x3ca".into(),
                team_id: "t_7k2m5q4x3c".into(),
                vault_name: long.clone(),
                people: vec![long.clone()],
                entries: Vec::new(),
            },
            OwnerAction::TakeCopyWithoutHistory {
                team_id: "t_7k2m5q4x3c".into(),
                version: 7,
                head: "a".repeat(64),
            },
        ] {
            assert!(action.needs_fresh_local_check(), "{action:?}");
            #[cfg(feature = "desktop")]
            assert!(
                !LocalWindowSource::LocalOwner.permits(&action),
                "{action:?}"
            );
            assert!(matches!(
                remote_choice(&action, None),
                Err(OwnerAuthError::RemoteUnsupported)
            ));
            let reason = action.reason();
            assert!(reason.chars().count() <= MAX_REASON_CHARS, "{reason}");
            assert!(reason.contains("Apassy Connect"), "{reason}");
            assert_ne!(action.touch_id_title(), "Confirm with Touch ID");
        }
        let connect =
            |join_id: u64, public_key: Vec<u8>, words: &str| OwnerAction::ConfirmConnectDevice {
                account_id: "acc_k7m2q4x3ca".into(),
                join_id,
                device_name: "iPhone".into(),
                public_key,
                words: words.into(),
            };
        let confirm = connect(4, vec![4; 65], "blaze cable flute board seal tiger");
        assert!(
            confirm
                .reason()
                .ends_with("both devices show: blaze cable flute board seal tiger")
        );
        // Another join, key, or set of words is another action.
        let confirm_with =
            |join_id: u64, public_key: Vec<u8>, words: &str| OwnerAction::ConfirmConnectDevice {
                account_id: "acc_k7m2q4x3ca".into(),
                join_id,
                device_name: "iPhone".into(),
                public_key,
                words: words.into(),
            };
        for other in [
            confirm_with(5, vec![4; 65], "blaze cable flute board seal tiger"),
            confirm_with(4, vec![5; 65], "blaze cable flute board seal tiger"),
            confirm_with(4, vec![4; 65], "blaze cable flute board seal tile"),
        ] {
            assert_ne!(other, confirm);
        }
        // The copy of a device that left: another head, or the other choice, is another
        // action.
        let departed = |version: u64, head: &str, replace: bool| OwnerAction::TakeDepartedCopy {
            team_id: "t_abcdefgh23".into(),
            version,
            head: head.into(),
            replace,
        };
        let take = departed(7, "aa", false);
        for other in [
            departed(8, "aa", false),
            departed(7, "ab", false),
            departed(7, "aa", true),
        ] {
            assert_ne!(other, take);
        }
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn browser_debugging_approval_and_trust_use_the_global_owner_source() {
        let identity = crate::browser::trust::InstanceIdentity {
            bundle_id: "net.imput.helium".into(),
            team_id: "S4Q33XPHB4".into(),
            user_data_root: "/tmp/synthetic".into(),
            debugging: "9223".into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        };
        for scope in [
            None,
            Some(crate::browser::bypass::BypassScope::Once),
            Some(crate::browser::bypass::BypassScope::FiveMinutes),
        ] {
            let action = OwnerAction::BrowserDebugging {
                identity: identity.clone(),
                scope,
                binding: None,
            };
            assert!(LocalWindowSource::LocalOwner.permits(&action));
            assert!(LocalWindowSource::BrowserDebuggingClick.permits(&action));
            assert!(!LocalWindowSource::BrowserGesture.permits(&action));
            assert!(matches!(
                remote_choice(&action, None),
                Err(OwnerAuthError::RemoteUnsupported)
            ));
        }
        assert!(
            !LocalWindowSource::BrowserDebuggingClick.permits(&OwnerAction::Reveal { item_id: 1 })
        );
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn question_development_source_and_proof_are_exact() {
        let action = OwnerAction::QuestionDevelopment {
            run_id: 11,
            item_id: 7,
        };
        assert!(LocalWindowSource::DevelopmentClick.permits(&action));
        assert!(LocalWindowSource::LocalOwner.permits(&action));
        for source in [
            LocalWindowSource::AllowOnceClick,
            LocalWindowSource::BrowserGesture,
            LocalWindowSource::AutoFill,
        ] {
            assert!(!source.permits(&action));
        }
        assert!(
            !LocalWindowSource::DevelopmentClick
                .permits(&OwnerAction::ChangeItemRules { item_id: 7 })
        );
        assert!(matches!(
            remote_choice(&action, None),
            Err(OwnerAuthError::RemoteUnsupported)
        ));
        let proof = OwnerProof::issue_for_test(action.clone(), [1; 32], Instant::now());
        assert_eq!(proof.check(&action, &[1; 32]), Ok(()));
        for other in [
            OwnerAction::QuestionDevelopment {
                run_id: 12,
                item_id: 7,
            },
            OwnerAction::QuestionDevelopment {
                run_id: 11,
                item_id: 8,
            },
            OwnerAction::ChangeItemRules { item_id: 7 },
        ] {
            assert_eq!(
                proof.check(&other, &[1; 32]),
                Err(ProofRefusal::WrongAction)
            );
        }
    }

    #[test]
    fn changing_delivery_needs_the_owner_check() {
        use crate::vault::ShortLivedKind;
        let action = OwnerAction::ChangeDelivery {
            item: 7,
            kind: ShortLivedKind::AwsSts,
            on: false,
        };
        // A phone or another Mac cannot make the change.
        assert!(matches!(
            remote_choice(&action, None),
            Err(OwnerAuthError::RemoteUnsupported)
        ));
        // The proof names the item, the kind, and the new state.
        let proof = OwnerProof::issue_for_test(action.clone(), [1; 32], Instant::now());
        assert_eq!(proof.check(&action, &[1; 32]), Ok(()));
        for other in [
            OwnerAction::ChangeDelivery {
                item: 8,
                kind: ShortLivedKind::AwsSts,
                on: false,
            },
            OwnerAction::ChangeDelivery {
                item: 7,
                kind: ShortLivedKind::GithubApp,
                on: false,
            },
            OwnerAction::ChangeDelivery {
                item: 7,
                kind: ShortLivedKind::AwsSts,
                on: true,
            },
            OwnerAction::ChangeItemRules { item_id: 7 },
        ] {
            assert_eq!(
                proof.check(&other, &[1; 32]),
                Err(ProofRefusal::WrongAction),
                "{other:?}"
            );
        }
        // A proof for the agent settings of the item does not change its delivery.
        let rules = OwnerProof::issue_for_test(
            OwnerAction::ChangeItemRules { item_id: 7 },
            [1; 32],
            Instant::now(),
        );
        assert_eq!(
            rules.check(&action, &[1; 32]),
            Err(ProofRefusal::WrongAction)
        );
        // The texts name the change and no value.
        assert_eq!(action.touch_id_title(), "Stop temporary credentials");
        assert!(action.reason().contains("long-lived key"));
        let on = OwnerAction::ChangeDelivery {
            item: 7,
            kind: ShortLivedKind::AwsSts,
            on: true,
        };
        assert!(on.reason().contains("15 minutes"));
        // Off gives runs the long-lived key again: only a fresh check on this Mac makes
        // it, never the global window (A-L1). On gives runs less.
        assert!(action.needs_fresh_local_check());
        #[cfg(feature = "desktop")]
        assert!(!LocalWindowSource::LocalOwner.permits(&action));
        assert!(!on.needs_fresh_local_check());
    }

    #[test]
    fn changing_short_lived_settings_needs_a_fresh_owner_check() {
        use crate::vault::{ShortLivedKind, ShortLivedSettings};
        let settings = |text: &str| {
            ShortLivedSettings::parse(ShortLivedKind::OauthRefresh, text)
                .unwrap()
                .digest()
        };
        let safe =
            settings(r#"{"token_url":"https://auth.example.test/token","client_auth":"basic"}"#);
        let action = OwnerAction::ChangeShortLivedSettings {
            item: 7,
            kind: ShortLivedKind::OauthRefresh,
            settings_sha256: safe.clone(),
        };
        assert!(matches!(
            remote_choice(&action, None),
            Err(OwnerAuthError::RemoteUnsupported)
        ));
        assert!(action.needs_fresh_local_check());
        let proof = OwnerProof::issue_for_test(action.clone(), [1; 32], Instant::now());
        assert_eq!(proof.check(&action, &[1; 32]), Ok(()));
        // Other settings (another token URL), another item, another kind, or the on/off
        // switch are other actions.
        let moved = settings(
            r#"{"token_url":"https://attacker.example.test/token","client_auth":"basic"}"#,
        );
        assert_ne!(moved, safe);
        for other in [
            OwnerAction::ChangeShortLivedSettings {
                item: 7,
                kind: ShortLivedKind::OauthRefresh,
                settings_sha256: moved,
            },
            OwnerAction::ChangeShortLivedSettings {
                item: 8,
                kind: ShortLivedKind::OauthRefresh,
                settings_sha256: safe.clone(),
            },
            OwnerAction::ChangeShortLivedSettings {
                item: 7,
                kind: ShortLivedKind::GithubApp,
                settings_sha256: safe.clone(),
            },
            OwnerAction::ChangeDelivery {
                item: 7,
                kind: ShortLivedKind::OauthRefresh,
                on: true,
            },
        ] {
            assert_eq!(
                proof.check(&other, &[1; 32]),
                Err(ProofRefusal::WrongAction),
                "{other:?}"
            );
        }
        assert_eq!(action.touch_id_title(), "Change temporary credentials");
        assert!(!action.reason().contains("attacker"));
    }

    /// ADR 0035 (panel L4): the Touch ID reason of a hosting change names the host, and a
    /// long name keeps its end, where the owning domain is.
    #[test]
    fn a_hosting_change_names_its_host_in_the_touch_id_reason() {
        use crate::vault::{BouncerHostKind, HOSTING_CONSENT_VERSION};
        let hosting = |kind, url: &str| OwnerAction::ChangeBouncerHosting {
            kind,
            url: url.to_owned(),
            consent_version: HOSTING_CONSENT_VERSION,
        };
        assert_eq!(
            hosting(
                BouncerHostKind::OwnServer,
                "https://brain.tail0a1b.ts.net:8443"
            )
            .reason(),
            "run the bouncer brain on your server brain.tail0a1b.ts.net:8443"
        );
        assert_eq!(
            hosting(BouncerHostKind::ThisMac, "").reason(),
            concat!("run the bouncer brain on this ", crate::computer!())
        );
        let training = OwnerAction::ChangeBouncerTraining {
            kind: BouncerHostKind::Connect,
            url: "https://train.apassy.example".to_owned(),
            consent_version: HOSTING_CONSENT_VERSION,
        };
        assert_eq!(
            training.reason(),
            "train the bouncer brain at Apassy Connect train.apassy.example"
        );
        let long = format!("https://brain.{}.evil.net", "a".repeat(200));
        let reason = hosting(BouncerHostKind::OwnServer, &long).reason();
        assert!(reason.ends_with("aaa.evil.net"), "{reason}");
        assert!(reason.contains('…'), "{reason}");
        assert!(reason.chars().count() <= MAX_REASON_CHARS, "{reason}");
    }

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
        #[cfg(feature = "desktop")]
        for sensitive in [
            action.clone(),
            OwnerAction::ApproveInProject {
                run: run.clone(),
                project: Project {
                    key: "synthetic".into(),
                    label: "Synthetic".into(),
                    root: "/tmp/synthetic".into(),
                },
                action: ActionKind::Read,
            },
            OwnerAction::AllowProduction {
                run: run.clone(),
                project: Project {
                    key: "synthetic".into(),
                    label: "Synthetic".into(),
                    root: "/tmp/synthetic".into(),
                },
                action: ActionKind::Read,
            },
        ] {
            assert!(LocalWindowSource::LocalOwner.permits(&sensitive));
            for source in [
                LocalWindowSource::AllowOnceClick,
                LocalWindowSource::DevelopmentClick,
                LocalWindowSource::BrowserGesture,
                LocalWindowSource::AutoFill,
            ] {
                assert!(!source.permits(&sensitive));
            }
        }
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
    /// An exact action selected in the local owner controller.
    LocalOwner,
    BrowserDebuggingClick,
    BrowserGesture,
    AutoFill,
    AllowOnceClick,
    DevelopmentClick,
}
#[cfg(feature = "desktop")]
impl LocalWindowSource {
    fn permits(self, action: &OwnerAction) -> bool {
        match self {
            // An action of `needs_fresh_local_check` always asks again.
            Self::LocalOwner => !action.needs_fresh_local_check(),
            Self::BrowserDebuggingClick => matches!(action, OwnerAction::BrowserDebugging { .. }),
            Self::BrowserGesture => matches!(
                action,
                OwnerAction::FillLogin { .. }
                    | OwnerAction::SaveLogin { .. }
                    | OwnerAction::CreateLogin { .. }
                    | OwnerAction::UpdateLogin { .. }
                    | OwnerAction::FillCode { .. }
                    | OwnerAction::CreatePasskey {
                        origin: Some(_),
                        ..
                    }
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
                    | OwnerAction::CreatePasskey { origin: None, .. }
            ),
            Self::AllowOnceClick => matches!(action, OwnerAction::ApproveRun(_)),
            Self::DevelopmentClick => matches!(action, OwnerAction::QuestionDevelopment { .. }),
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

#[cfg(test)]
mod touch_id_title_tests {
    use super::OwnerAction;

    /// Review 0.5.16: the Touch ID text of a connect says where the code goes back.
    #[test]
    fn the_touch_id_text_of_a_connect_names_where_the_code_goes_back() {
        let connect = |host: &str| OwnerAction::AllowConnect {
            id: "cr_1".into(),
            client_name: "Grok Bot".into(),
            code: "K7Q-4MD".into(),
            redirect_host: host.into(),
        };
        assert_eq!(
            connect("grok.example").reason(),
            concat!(
                "connect \"Grok Bot\", which returns to grok.example, to this ",
                crate::computer!()
            )
        );
        for host in ["127.0.0.1", "localhost", "[::1]", ""] {
            assert_eq!(
                connect(host).reason(),
                concat!(
                    "connect \"Grok Bot\", which returns to localhost, to this ",
                    crate::computer!()
                ),
                "{host}"
            );
        }
        assert_eq!(
            connect("grok.example").touch_id_title(),
            "Connect a remote agent"
        );
    }

    #[test]
    fn untrusted_login_text_cannot_become_the_authentication_title() {
        let action = OwnerAction::SaveLogin {
            title: "Enter your passphrase here".into(),
            username: "website-controlled".into(),
            origin: "https://example.invalid".into(),
        };
        assert_eq!(action.touch_id_title(), "Save a password");
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn browser_debugging_titles_name_trust_and_bypass() {
        let identity = crate::browser::trust::InstanceIdentity {
            bundle_id: "net.imput.helium".into(),
            team_id: "S4Q33XPHB4".into(),
            user_data_root: "/tmp/synthetic".into(),
            debugging: "9223".into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        };
        let trust = OwnerAction::BrowserDebugging {
            identity: identity.clone(),
            scope: None,
            binding: None,
        };
        assert_eq!(trust.touch_id_title(), "Trust a browser profile");
        let bypass = OwnerAction::BrowserDebugging {
            identity,
            scope: Some(crate::browser::bypass::BypassScope::Once),
            binding: None,
        };
        assert_eq!(bypass.touch_id_title(), "Allow browser debugging");
    }
}

/// An Apple Watch answers access requests only (ADR 0039 §3): the run questions and the
/// feed refuse its row for every answer, signed with either of its keys.
#[cfg(test)]
mod watch_answer_tests {
    use super::*;
    use crate::sync::DeviceKey;

    const TEAM: &str = "t_7k2m5q4x3c";
    const QID: &str = "q_synthetic_watch";
    const DIGEST: &str = "6f1c0e2a3b4d4e5f8a9b0c1d2e3f4a5b6f1c0e2a3b4d4e5f8a9b0c1d2e3f4a5b";
    const NOW: u64 = 1_790_000_060;

    fn row(kind: TrustedDeviceKind, sign: &DeviceKey, answer: &DeviceKey) -> TrustedDevice {
        TrustedDevice {
            uuid: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            name: "Synthetic Watch".to_owned(),
            kind,
            relay_devices: [(TEAM.to_owned(), 3)].into(),
            sign_key: sign.public_key().to_vec(),
            answer_key: Some(answer.public_key().to_vec()),
            created_at: 1,
            updated_at: 1,
            updated_by: String::new(),
        }
    }

    fn every_choice() -> Vec<Choice> {
        let project_key = "/tmp/synthetic-shop/.git".to_owned();
        vec![
            Choice::Approve,
            Choice::ApproveAsDevelopment,
            Choice::ApproveAsProduction,
            Choice::DenyWithComment {
                comment: "Not now".to_owned(),
            },
            Choice::ApproveOnce,
            Choice::ApproveInProject {
                action: ActionKind::Deploy,
                project_key: project_key.clone(),
            },
            Choice::AllowProduction {
                action: ActionKind::Deploy,
                project_key,
            },
            Choice::CorrectEnvironment {
                item_id: 7,
                environment: RemoteEnvironment::Development,
            },
            Choice::CorrectEnvironment {
                item_id: 7,
                environment: RemoteEnvironment::Production,
            },
            Choice::Deny,
            Choice::NeverForAgent,
            Choice::AlwaysAskForAgent,
            Choice::Disconnect,
        ]
    }

    #[test]
    fn a_watch_answers_no_run_question() {
        let sign = DeviceKey::generate().unwrap();
        let answer = DeviceKey::generate().unwrap();
        let watch = row(TrustedDeviceKind::Watch, &sign, &answer);
        let phone = row(TrustedDeviceKind::Iphone, &sign, &answer);
        for choice in every_choice() {
            assert_eq!(remote_key(&watch, &choice), None, "{choice:?}");
            let text = answer_string(&watch.uuid, TEAM, QID, &choice, DIGEST, NOW).unwrap();
            for key in [&sign, &answer] {
                let signature = key.sign(text.as_bytes()).unwrap();
                assert_eq!(
                    verify_remote_answer(&watch, TEAM, QID, &choice, DIGEST, NOW, &signature, NOW),
                    Err(OwnerAuthError::RemoteRejected),
                    "{choice:?}"
                );
            }
            // The same keys in an iPhone row: the key of the kind verifies.
            let key = if choice.needs_owner_check() {
                &answer
            } else {
                &sign
            };
            let signature = key.sign(text.as_bytes()).unwrap();
            assert_eq!(
                verify_remote_answer(&phone, TEAM, QID, &choice, DIGEST, NOW, &signature, NOW),
                Ok(()),
                "{choice:?}"
            );
        }
    }

    #[test]
    fn a_watch_sends_no_feed_action() {
        let sign = DeviceKey::generate().unwrap();
        let answer = DeviceKey::generate().unwrap();
        let watch = row(TrustedDeviceKind::Watch, &sign, &answer);
        let phone = row(TrustedDeviceKind::Iphone, &sign, &answer);
        for kind in [
            ExceptionKind::Never,
            ExceptionKind::AlwaysAsk,
            ExceptionKind::Only,
        ] {
            let removal = crate::questions::feed::RemovalAction {
                by: watch.uuid.clone(),
                to: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d".to_owned(),
                team_id: TEAM.to_owned(),
                action_id: "sLGys7S1tre4ubq7vL2-vw".to_owned(),
                agent_id: 4,
                item_uuid: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c".to_owned(),
                kind,
                created_at: 1_789_990_000,
                feed_seq: 1_790_000_040,
                time: NOW,
                names: None,
            };
            let text = removal.string().unwrap();
            for key in [&sign, &answer] {
                let signature = key.sign(text.as_bytes()).unwrap();
                assert_eq!(
                    verify_remote_action(&watch, &removal, &signature, NOW),
                    Err(OwnerAuthError::RemoteRejected),
                    "{kind:?}"
                );
            }
            let key = if removal.gives_authority() {
                &answer
            } else {
                &sign
            };
            let signature = key.sign(text.as_bytes()).unwrap();
            assert_eq!(
                verify_remote_action(&phone, &removal, &signature, NOW),
                Ok(()),
                "{kind:?}"
            );
        }
    }
}
