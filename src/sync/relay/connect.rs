//! Sync through Apassy Connect (ADR 0037 stage 7, plan s7 unit M3; contracts
//! connect-account-v1 section 8 and relay-sync-v1).
//!
//! A vault store is one relay-sync-v1 team of kind `account` for one vault. Its device
//! key is the Connect account device key of this Mac ([`SessionKey::Account`]): the
//! vault keeps an account row with no private key (schema 34), and the signer comes from
//! the account in memory ([`RelaySync::set_account_signer`]). The relay-sync-v1 wire does
//! not change: the team sign-in, the signed heads, the chain, the receipts, and
//! `DELETE /v1/sync` are those of every relay team.
//!
//! - [`RelaySync::enable_on_connect`]: `POST /v1/account/vaults` (the same vault again
//!   answers the existing store), the sign-in with the account key, the first sync (the
//!   push of version 1, or the merge of a copy that another Mac of the account pushed),
//!   then the registration of the other verified devices of the account in the store. A
//!   second Mac of the same account with a copy of the vault turns on the same way: it
//!   needs no link code, and it merges.
//! - A device of the account without a copy of the vault gets it from the store that
//!   lists it ([`RelaySync::joined_from_store`], then [`super::JoinedDevice::download`]
//!   and [`RelaySync::adopt`] with the passphrase of the copy). A device in the store adds
//!   it first (`register_account_devices`, also the sync worker every 5 minutes). A vault
//!   store has no device link (the relay refuses one): its devices come from the account.
//! - A vault shared between the accounts of a family or team (contract section 16): a
//!   store that holds devices of another account opens only when the account file holds
//!   a share of it that this device verified (a store of this account with signed `share`
//!   entries, or a store of another account that this account's list joined and whose
//!   owner's list still shares it with this account); any other is refused before any
//!   request ([`StoreError::OtherAccount`]). Its heads are signed by the devices of the
//!   accounts of the share (`crate::connect::store_signer_policy`).
//! - [`RelaySync::move_to_connect`]: "Move the relay copy to Connect". It pushes to
//!   Connect first and deletes the old copy second; the move record ([`MoveRecord`],
//!   `<state>.move.json`, no secret) keeps the step, so a failure in between leaves both
//!   copies and a clear state that the owner can retry or undo.
//! - [`StorePlan`]: the plan of the account as the window read it, for the read-only
//!   states of the sync worker: a push that Connect refuses with `403 plan_required`
//!   stops, pulls go on, and nothing is lost on this Mac.
//! - [`store_deleted`]: a recovery deletes every vault store of the account (contract
//!   section 9). The account file and the sync state tell which stores went: a store of
//!   this account whose state names an earlier account key of this device than the key of
//!   an account that this device recovered, or a shared store whose owner's root changed
//!   (section 16.7). Such a sync asks Connect nothing more ([`RelaySync::set_store_deleted`],
//!   [`SyncError::StoreDeleted`]); the vault on this device stays as it is.

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{
    JoinedDevice, KeySource, RelayEnableReport, RelaySync, Session, SessionKey, SharedSlot,
    VaultAccess, ended_by_lock, lock,
};
use crate::broker::approvals::OwnerProof;
use crate::connect::{
    AccountSigner, AccountState, ConnectAccount, ConnectError, PlanView, VaultStoreView,
};
use crate::sync::{RelayRefusal, SyncError, SyncOutcome, state};
use crate::vault::{Vault, VaultErrorKind};

/// The plan of the account of a vault store, from the `PlanView` of connect-billing-v1
/// section 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePlan {
    /// `active` or `trialing`: pushes and pulls work.
    Entitled,
    /// `past_due` within its grace: pushes and pulls work until `grace_until`.
    PastDue { grace_until: Option<u64> },
    /// `read_only`: pulls and downloads work, pushes get `403 plan_required`.
    ReadOnly { until: Option<u64> },
    /// `suspended`: pulls get `403 plan_required` too; the store goes at `delete_at`.
    Suspended { delete_at: Option<u64> },
    /// `none` or `pending`: the account is not on Connect.
    NotOnConnect,
}

impl StorePlan {
    /// The plan state of `view`.
    pub fn from_view(view: &PlanView) -> Self {
        match view.status.as_str() {
            "past_due" => Self::PastDue {
                grace_until: view.grace_until,
            },
            "read_only" => Self::ReadOnly {
                until: view.read_only_until,
            },
            "suspended" => Self::Suspended {
                delete_at: view.delete_at,
            },
            _ if view.entitled => Self::Entitled,
            _ => Self::NotOnConnect,
        }
    }

    /// Whether Connect takes a push of this plan.
    pub fn pushes(self) -> bool {
        matches!(self, Self::Entitled | Self::PastDue { .. })
    }

    /// Whether Connect gives this plan a new vault store.
    pub fn entitled(self) -> bool {
        self.pushes()
    }
}

/// Why the vault store of a relay sync is gone at Apassy Connect ([`store_deleted`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDeleted {
    /// This device recovered the account, and the store is from before it: every store of
    /// the account was deleted then (connect-account-v1 section 9).
    Recovered,
    /// Another account made this shared store, and Connect serves a list of another root
    /// for it now: that account was recovered, which deleted its stores (section 16.7).
    OwnerRecovered,
}

/// Whether the vault store of the relay sync `sync` was deleted at a recovery, from the
/// account file `account` and the sync state alone (no answer of Connect is waited for):
///
/// - [`StoreDeleted::Recovered`]: this device recovered the account
///   (`AccountState::recovered_at`), the store is one that this account made, and its state
///   names an account key of this device other than the key of the account file. Connect
///   never takes a key that was a device of an account at a recovery, so such a state is
///   of a store from before the recovery. A state without the account and the key that
///   started it (an earlier build) is not decided here.
/// - [`StoreDeleted::OwnerRecovered`]: the store is one that another account made and this
///   account joined, and this account's own pin of that account is suspended (a list of
///   another root: that account reset, section 16.7).
///
/// `None` for any other sync, also for a store that went for another reason (a deletion,
/// the end of a plan): that sync keeps the state that its relay calls give.
pub fn store_deleted(account: &AccountState, sync: &state::SyncState) -> Option<StoreDeleted> {
    if sync.transport != state::TransportKind::Relay
        || sync.relay_url.as_deref() != Some(account.origin.as_str())
    {
        return None;
    }
    let team = sync.team_id.as_deref()?;
    let made_by = sync.store_account.as_deref();
    if account.recovered_at.is_some()
        && made_by == Some(account.account_id.as_str())
        && sync
            .store_key
            .as_deref()
            .is_some_and(|key| key != account.public_key)
    {
        return Some(StoreDeleted::Recovered);
    }
    let owner = crate::connect::share::reset_owner(account, team)?;
    made_by
        .is_none_or(|made_by| made_by == owner)
        .then_some(StoreDeleted::OwnerRecovered)
}

/// Why a step of the sync through Apassy Connect failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A relay-sync-v1 step (the sign-in, the head, the merge, the push).
    Sync(SyncError),
    /// A Connect account step (the store, the devices, the token).
    Connect(ConnectError),
    /// The store of this vault holds no device of this Mac yet: another Mac of the
    /// account in the store adds it (Settings › Connect on that Mac).
    NotInStore,
    /// The sync of this vault points at another Connect than the account of this Mac.
    OtherConnect,
    /// The vault has no relay sync to move.
    NothingToMove,
    /// The store holds devices of another account, and the account file of this device
    /// holds no verified share of it (connect-account-v1 section 16). Nothing was asked or
    /// made.
    OtherAccount,
    /// A store of another account that this account joined holds no device of this one
    /// yet: a device of the account that shares it adds it (section 16).
    NotInSharedStore,
}

impl From<SyncError> for StoreError {
    fn from(error: SyncError) -> Self {
        Self::Sync(error)
    }
}

impl From<ConnectError> for StoreError {
    fn from(error: ConnectError) -> Self {
        Self::Connect(error)
    }
}

impl From<crate::vault::VaultError> for StoreError {
    fn from(error: crate::vault::VaultError) -> Self {
        Self::Sync(error.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sync(SyncError::Relay(RelayRefusal::PlanRequired))
            | Self::Connect(ConnectError::PlanRequired) => f.write_str(
                "This account is not on Apassy Connect, or its plan is read-only. The vault stays on this Mac.",
            ),
            Self::Sync(error) => {
                let text = error.to_string();
                let mut chars = text.chars();
                match chars.next() {
                    Some(first) => write!(f, "{}{}.", first.to_uppercase(), chars.as_str()),
                    None => Ok(()),
                }
            }
            Self::Connect(error) => fmt::Display::fmt(error, f),
            Self::NotInStore => f.write_str(
                "This Mac is not in the Apassy Connect copy of this vault yet. On a Mac that syncs it through Apassy Connect, open Settings › Connect: that Mac adds this one. Then try again.",
            ),
            Self::OtherConnect => f.write_str(
                "This vault syncs through another Apassy Connect than the account of this Mac.",
            ),
            Self::NothingToMove => f.write_str("This vault has no relay copy to move."),
            Self::OtherAccount => f.write_str(
                "This vault is shared with another account, and this device has not verified the share yet. Open Settings › Connect, then try again.",
            ),
            Self::NotInSharedStore => f.write_str(
                "This device is not in the shared copy of this vault yet. It is added when the person who shares the vault opens Apassy on a device that syncs it. Then try again.",
            ),
        }
    }
}

/// The result of turning on the sync through Apassy Connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEnableReport {
    /// The relay sync report: the link for the vault list, the store name, the outcome.
    pub enable: RelayEnableReport,
    /// The store (a relay-sync-v1 team id).
    pub team_id: String,
    /// The names of the other devices of the account that this Mac added to the store.
    pub registered: Vec<String>,
    /// The other devices that Connect did not add, with the reason, for a later try.
    pub not_registered: Vec<(String, String)>,
}

/// How far a move of a relay copy to Connect got (the move record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveStep {
    /// The copy is on Connect, and the old copy is still on the old relay: both copies
    /// exist, and the vault still syncs with the old relay. Retry or undo.
    Pushed,
    /// The old copy is deleted and the old sync is off: the copy is on Connect only, and
    /// the sync with Connect did not turn on yet. Retry.
    OldDeleted,
}

/// The move record: `<state>.move.json` beside the state of the old relay sync, mode
/// 0600. It holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveRecord {
    pub step: MoveStep,
    /// The vault (the vault id of its sync record).
    pub vault_id: String,
    /// The Connect origin.
    pub connect_url: String,
    /// The vault store on Connect.
    pub team_id: String,
    /// The relay origin of the old copy.
    pub old_url: String,
    /// The team of the old copy.
    pub old_team_id: String,
}

/// A move that did not finish, with the step it reached ([`MoveRecord`]) and the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveFailure {
    /// `None`: nothing changed (the old copy and the sync are as before).
    pub step: Option<MoveStep>,
    pub error: StoreError,
}

impl fmt::Display for MoveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.step {
            None => write!(
                f,
                "The relay copy did not move: {} Nothing changed; the vault syncs with the relay as before.",
                self.error
            ),
            Some(MoveStep::Pushed) => write!(
                f,
                "The copy is on Apassy Connect, and the old copy is still on the relay: {} Both copies are kept, and the vault syncs with the relay as before. Try again, or undo the move.",
                self.error
            ),
            Some(MoveStep::OldDeleted) => write!(
                f,
                "The copy is on Apassy Connect, and the old copy is deleted, but the sync with Apassy Connect did not turn on: {} The vault is safe on this Mac. Try again.",
                self.error
            ),
        }
    }
}

impl RelaySync {
    // ---- The account key and the plan. ----

    /// The Connect account key of this Mac while its account is signed in, or `None`
    /// at a sign-out. A clone of this relay sync shares it. A session of a vault store
    /// that runs keeps the key it took.
    pub fn set_account_signer(&self, signer: Option<Arc<AccountSigner>>) {
        if signer.is_some() {
            self.account_missing.store(false, Ordering::SeqCst);
        }
        *lock(&self.account) = signer;
    }

    /// Which keys may sign the heads of a vault store (`crate::connect::signer_policy` of
    /// the account file), set by the window with the account key whenever it hands the
    /// account session over (the account file is enough: no answer of Connect is waited
    /// for) and after each refresh of the account, or `None` at a sign-out. A session that
    /// runs reads it at each check of a head, so a device that left the account signs no
    /// later version from the next check on.
    pub fn set_account_signers(&self, policy: Option<super::SignerPolicy>) {
        *lock(&self.account_keys) = policy;
    }

    /// Whether the signers that this relay sync holds give the store `team_id` signers of
    /// its own: a store shared between accounts (connect-account-v1 section 16), from the
    /// account file alone. Settings › Connect › Shared Vaults notes the lists of such a
    /// store itself, after the quiet time of its head.
    pub fn shares_between_accounts(&self, team_id: &str) -> bool {
        lock(&self.account_keys)
            .as_ref()
            .is_some_and(|policy| policy.stores.iter().any(|store| store.team_id == team_id))
    }

    /// The signers that the running sessions of this vault take ([`Self::set_account_signers`]).
    #[cfg(test)]
    pub(crate) fn account_signers(&self) -> Option<super::SignerPolicy> {
        lock(&self.account_keys).clone()
    }

    /// Whether a vault store of this vault asked for the account key, and no account
    /// was signed in on this Mac (Settings › Connect › Sign In…). The sync waits.
    pub fn needs_account_key(&self) -> bool {
        self.account_missing.load(Ordering::SeqCst)
    }

    /// Whether this vault syncs through a vault store of Apassy Connect: its session
    /// signs with the account key, or its row asked for that key.
    pub fn uses_account_key(&self) -> bool {
        self.needs_account_key()
            || lock(&self.session)
                .as_ref()
                .is_some_and(|session| session.key.is_account())
    }

    /// The plan of the account of this vault store, as the window last read it.
    pub fn set_store_plan(&self, plan: Option<StorePlan>) {
        *lock(&self.plan) = plan;
    }

    /// [`Self::set_store_plan`].
    pub fn store_plan(&self) -> Option<StorePlan> {
        *lock(&self.plan)
    }

    /// The vault store of this relay sync was deleted at a recovery ([`store_deleted`]), as
    /// the window found from the account file, or `None` when it was not. A clone shares
    /// it, and so does each session of the vault. While it holds, no sync, poll, or other
    /// call of this vault asks Connect: each ends at once with [`SyncError::StoreDeleted`].
    pub fn set_store_deleted(&self, deleted: Option<StoreDeleted>) {
        self.removed.set_deleted(deleted);
    }

    /// [`Self::set_store_deleted`].
    pub fn store_deleted(&self) -> Option<StoreDeleted> {
        self.removed.deleted()
    }

    // ---- Turning it on. ----

    /// Turn on the sync of the unlocked vault through Apassy Connect with the account of
    /// this Mac (contract connect-account-v1 section 8): make the vault store (or take
    /// the existing store of this vault), sign in with the account key, sync (push
    /// version 1, or merge the copy that another Mac of the account pushed), then add
    /// the other live devices of the account to the store. The account row, the state,
    /// and the link are stored only after the first sync worked.
    ///
    /// - `Connect(PlanRequired)`: the account is not on Connect; nothing turned on.
    /// - [`StoreError::NotInStore`]: the store exists, and another Mac of the account has
    ///   not added this Mac yet.
    pub fn enable_on_connect(
        &self,
        vault: &mut Vault,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, StoreError> {
        let _run = self.try_run()?;
        self.enable_on_connect_in(vault, account, vault_name)
    }

    /// [`Self::enable_on_connect`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the Connect calls and the upload run without the slot's
    /// mutex.
    pub fn enable_on_connect_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, StoreError> {
        let _run = self.run_shared()?;
        self.enable_on_connect_in(&mut SharedSlot { slot, accept }, account, vault_name)
    }

    fn enable_on_connect_in<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, StoreError> {
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled.into());
        }
        let local = vault.with(|vault| {
            self.require_unlocked(vault)?;
            Ok(vault.sync_identity()?)
        })?;
        let (session, store) = self.store_session(account, &local.vault_id, vault_name)?;
        *lock(&self.refused) = None;
        let enable =
            self.finish_enable(vault, session, &local.vault_id, store.name.clone(), None)?;
        let (registered, not_registered) = register_others(account, &store);
        Ok(ConnectEnableReport {
            enable,
            team_id: store.team_id,
            registered,
            not_registered,
        })
    }

    /// The store of `vault_id` (made or taken), and a session in it with the account key
    /// of this Mac.
    fn store_session(
        &self,
        account: &mut ConnectAccount,
        vault_id: &str,
        vault_name: &str,
    ) -> Result<(Arc<Session>, VaultStoreView), StoreError> {
        let url = self.config.relay_url()?;
        if url.as_str() != account.client().origin() {
            return Err(StoreError::OtherConnect);
        }
        let signer = account.signer()?;
        let name = super::clean_name(vault_name, "Vault");
        let store = account.create_vault_store(vault_id, &name)?;
        let me = account.state().device_id.clone();
        let store_device = store
            .devices
            .iter()
            .find(|device| device.device_id == me)
            .map(|device| device.store_device_id)
            .ok_or(StoreError::NotInStore)?;
        if store_device == 0 {
            return Err(ConnectError::BadAnswer.into());
        }
        let policy = account.signer_policy()?;
        self.set_account_signers(Some(policy));
        self.set_account_signer(Some(Arc::clone(&signer)));
        let session = Arc::new(
            Session::new(
                url,
                &store.team_id,
                SessionKey::Account(signer),
                Some(store_device),
            )
            .for_store_of(&account.state().account_id)
            .sharing_removed(&self.removed)
            .with_shared_signers(Arc::clone(&self.account_keys)),
        );
        Ok((session, store))
    }

    /// Add the other live devices of the account that are not in the store of this
    /// vault yet (a Mac that joined the account later). The vault must sync through
    /// Apassy Connect. Returns the names of the devices added.
    pub fn register_account_devices(
        &self,
        account: &mut ConnectAccount,
    ) -> Result<Vec<String>, StoreError> {
        let state = self.require_state()?;
        let team_id = state.team_id.ok_or(SyncError::NotEnabled)?;
        let store = account
            .vault_stores()?
            .into_iter()
            .find(|store| store.team_id == team_id && store.vault_id == state.vault_id)
            .ok_or(StoreError::NotInStore)?;
        Ok(register_others(account, &store).0)
    }

    /// The device of this Mac in `store`, for a new vault on this Mac from the Connect
    /// copy ("Use a vault from another Mac" › "Apassy Connect"): download it with
    /// [`JoinedDevice::download`] and make the vault with [`Self::adopt`] and the
    /// passphrase of the copy. The store must list this Mac (a store of another account
    /// that this account joined: [`StoreError::NotInSharedStore`]). The caller read the
    /// account just before, and no answer of Connect is waited for. For a store of this
    /// account alone the session has a fixed signer policy, the trust store of the account
    /// file as it is now: a head or a chain entry of a key that it does not hold is refused
    /// at once. For a store shared between accounts (the account file holds a share of it)
    /// the session follows the signers of the account file from the first request on, in a
    /// slot of its own that the window updates after each refresh
    /// ([`JoinedDevice::set_signers`]): a head of a member whose list a refresh reads
    /// meanwhile is "checking the device list", never a damaged copy at once
    /// (connect-account-v1 section 16.6). [`Self::adopt`] rebinds the session to the policy
    /// of the relay sync of the new vault, so a later refresh of the account reaches it. A
    /// store that holds
    /// devices of another account ([`VaultStoreView::shared`]) needs a share of it in the
    /// account file (`ConnectAccount::shares_store`), else it is
    /// [`StoreError::OtherAccount`], before any request.
    pub fn joined_from_store(
        account: &mut ConnectAccount,
        store: &VaultStoreView,
    ) -> Result<JoinedDevice, StoreError> {
        if store.shared && !account.shares_store(&store.team_id) {
            return Err(StoreError::OtherAccount);
        }
        let url = crate::sync::RelayUrl::parse(account.client().origin())?;
        let me = account.state().device_id.clone();
        let not_in = if account.joined_store_owner(&store.team_id).is_some() {
            StoreError::NotInSharedStore
        } else {
            StoreError::NotInStore
        };
        let store_device = store
            .devices
            .iter()
            .find(|device| device.device_id == me)
            .map(|device| device.store_device_id)
            .filter(|id| *id > 0)
            .ok_or(not_in)?;
        let signer = account.signer()?;
        let policy = crate::connect::signer_policy(account.state());
        // The account that made the store, from the account file: another account for a
        // store that this account joined, else this account.
        let made_by = account
            .joined_store_owner(&store.team_id)
            .unwrap_or_else(|| account.state().account_id.clone());
        let session = Session::new(
            url,
            &store.team_id,
            SessionKey::Account(signer),
            Some(store_device),
        )
        .for_store_of(&made_by);
        if crate::connect::store_signer_policy(account.state(), &store.team_id).is_none() {
            return Ok(JoinedDevice {
                session: Arc::new(session.with_fixed_signers(policy)),
                team: store.name.clone(),
                notes: Arc::default(),
                signers: None,
            });
        }
        let slot = Arc::new(std::sync::Mutex::new(Some(policy)));
        Ok(JoinedDevice {
            session: Arc::new(session.with_shared_signers(Arc::clone(&slot))),
            team: store.name.clone(),
            notes: Arc::default(),
            signers: Some(slot),
        })
    }

    // ---- "Move the relay copy to Connect". ----

    /// The move record of this (old) relay sync: `<state>.move.json`.
    pub fn move_record_path(&self) -> PathBuf {
        self.config.state_path.with_extension("move.json")
    }

    /// The move of this vault that did not finish, if any.
    pub fn pending_move(&self) -> Option<MoveRecord> {
        let text = fs::read(self.move_record_path()).ok()?;
        serde_json::from_slice(&text).ok()
    }

    /// Write the record atomically, mode 0600: a new file beside it, synced, renamed.
    fn write_move(&self, record: &MoveRecord) -> Result<(), SyncError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.move_record_path();
        let dir = path.parent().ok_or(SyncError::Io)?;
        state::ensure_private_dir(dir)?;
        let text = serde_json::to_vec_pretty(record).map_err(|_| SyncError::State)?;
        let temp = path.with_extension("move.json.tmp");
        state::remove_if_present(&temp)?;
        let written = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .and_then(|mut file| {
                file.write_all(&text)?;
                file.sync_all()
            })
            .and_then(|()| fs::rename(&temp, &path));
        if written.is_err() {
            let _ = fs::remove_file(&temp);
            return Err(SyncError::Io);
        }
        Ok(())
    }

    fn clear_move(&self) {
        let _ = fs::remove_file(self.move_record_path());
    }

    /// "Move the relay copy to Connect" for the unlocked vault that syncs through this
    /// relay sync (the hosted relay): `connect` is the relay sync of the vault for the
    /// Connect origin, with no state yet. In this order:
    ///
    /// 1. sync with the old relay, so that this Mac has every change of the other Macs;
    /// 2. push to Connect: the store, the sign-in with the account key, and the sync
    ///    (version 1, or a merge of the copy of an earlier try); the vault still syncs
    ///    with the old relay. The record says [`MoveStep::Pushed`];
    /// 3. delete the old copy on the old relay (`DELETE /v1/sync`), then turn the old
    ///    sync off on this Mac. The record says [`MoveStep::OldDeleted`];
    /// 4. turn on the sync through Connect ([`Self::enable_on_connect`]) and register
    ///    the other devices of the account. The record goes.
    ///
    /// A failure keeps what is done and says where it stopped ([`MoveFailure`]). The same
    /// call again goes on from there: after step 2 it syncs and pushes again (the copy of
    /// Connect then also has the changes since), after step 3 it only turns on step 4.
    /// [`Self::undo_move`] deletes the Connect copy after step 2.
    pub fn move_to_connect(
        &self,
        connect: &RelaySync,
        vault: &mut Vault,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, MoveFailure> {
        self.move_to_connect_in(connect, vault, account, vault_name)
    }

    /// [`Self::move_to_connect`] with the shared vault slot of the app: the relay and
    /// Connect calls run without the slot's mutex.
    pub fn move_to_connect_shared(
        &self,
        connect: &RelaySync,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, MoveFailure> {
        self.move_to_connect_in(
            connect,
            &mut SharedSlot { slot, accept },
            account,
            vault_name,
        )
    }

    fn move_to_connect_in<A: VaultAccess + ?Sized>(
        &self,
        connect: &RelaySync,
        vault: &mut A,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, MoveFailure> {
        let record = self.pending_move();
        let fail = |step: Option<MoveStep>| move |error: StoreError| MoveFailure { step, error };

        if let Some(record) = record.as_ref().filter(|r| r.step == MoveStep::OldDeleted) {
            // Step 4 only: the old copy is gone already.
            let report = connect
                .enable_on_connect_access(vault, account, vault_name)
                .map_err(fail(Some(MoveStep::OldDeleted)))?;
            if report.team_id != record.team_id {
                return Err(fail(Some(MoveStep::OldDeleted))(
                    ConnectError::BadAnswer.into(),
                ));
            }
            self.clear_move();
            return Ok(report);
        }
        let done = record.as_ref().map(|record| record.step);
        let old = self
            .require_state()
            .map_err(|error| fail(done)(error.into()))?;
        let (Some(old_url), Some(old_team_id)) = (old.relay_url.clone(), old.team_id.clone())
        else {
            return Err(fail(done)(StoreError::NothingToMove));
        };
        if connect.state().ok().flatten().is_some() {
            return Err(fail(done)(SyncError::AlreadyEnabled.into()));
        }
        // 1. Every change of the other Macs, from the old relay.
        {
            let _run = self
                .run_shared()
                .map_err(|error| fail(done)(error.into()))?;
            self.sync_access(vault)
                .map_err(|error| fail(done)(error.into()))?;
        }
        // 2. Push to Connect, beside the old sync.
        let pushed = {
            let _run = connect
                .run_shared()
                .map_err(|error| fail(done)(error.into()))?;
            connect.push_beside(vault, account, &old.vault_id, vault_name)
        };
        let team_id = pushed.map_err(fail(done))?;
        let record = MoveRecord {
            step: MoveStep::Pushed,
            vault_id: old.vault_id.clone(),
            connect_url: connect.config.url.clone(),
            team_id,
            old_url,
            old_team_id,
        };
        self.write_move(&record)
            .map_err(|error| fail(Some(MoveStep::Pushed))(error.into()))?;
        // 3. Delete the old copy, then turn the old sync off here.
        let pushed_step = Some(MoveStep::Pushed);
        {
            let _run = self
                .run_shared()
                .map_err(|error| fail(pushed_step)(error.into()))?;
            self.delete_relay_copy(KeySource::Memory)
                .map_err(|error| fail(pushed_step)(error.into()))?;
            let record = MoveRecord {
                step: MoveStep::OldDeleted,
                ..record.clone()
            };
            // The old copy is gone: a failure from here on is step 3.
            let old_deleted = Some(MoveStep::OldDeleted);
            self.write_move(&record)
                .map_err(|error| fail(old_deleted)(error.into()))?;
            vault
                .with(|vault| {
                    self.require_unlocked(vault)?;
                    vault.remove_relay_device()?;
                    Ok(())
                })
                .map_err(|error| fail(old_deleted)(error.into()))?;
            self.forget();
            self.removed.clear();
            state::remove(&self.config.state_path)
                .map_err(|error| fail(old_deleted)(error.into()))?;
        }
        // 4. The sync through Connect.
        let report = connect
            .enable_on_connect_access(vault, account, vault_name)
            .map_err(fail(Some(MoveStep::OldDeleted)))?;
        self.clear_move();
        Ok(report)
    }

    /// Undo a move that stopped after step 2 ([`MoveStep::Pushed`]): delete the copy on
    /// Connect after a fresh owner check for `ConnectAccount::delete_vault_store_action`,
    /// and drop the record. The old copy and the old sync stay as they are. A move after
    /// step 3 cannot be undone (the old copy is gone): it is `Conflict`.
    pub fn undo_move(
        &self,
        account: &mut ConnectAccount,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), StoreError> {
        let Some(record) = self.pending_move() else {
            return Err(StoreError::NothingToMove);
        };
        if record.step != MoveStep::Pushed {
            return Err(ConnectError::Conflict.into());
        }
        match account.delete_vault_store(&record.team_id, proof, epoch) {
            Ok(()) | Err(ConnectError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.clear_move();
        Ok(())
    }

    /// One sync with the old relay, with the run guard held by the caller.
    fn sync_access<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
    ) -> Result<SyncOutcome, SyncError> {
        self.clear_work();
        let mut state = self.require_state()?;
        let session = vault.with(|vault| self.checked_session(vault, &state))?;
        let transport = self.transport(Arc::clone(&session), &state);
        ended_by_lock(
            &session,
            self.rounds(vault, &mut state, &transport, true, None),
        )
    }

    /// Step 2 of the move: the store and a sync of the vault into it, with a state in
    /// memory only (the vault keeps its old sync). Returns the store. The run guard is
    /// held by the caller.
    fn push_beside<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        account: &mut ConnectAccount,
        vault_id: &str,
        vault_name: &str,
    ) -> Result<String, StoreError> {
        self.clear_work();
        let (session, store) = self.store_session(account, vault_id, vault_name)?;
        let device_id = session.device_id().ok_or(SyncError::NotEnabled)?;
        let mut state = state::SyncState::new_relay(
            session.url.as_str(),
            &session.team_id,
            device_id,
            vault_id,
        );
        let transport = self.transport(Arc::clone(&session), &state);
        let result = self.rounds(vault, &mut state, &transport, false, None);
        // The session was never the one of this relay sync: it goes with this step.
        session.close();
        result?;
        Ok(store.team_id)
    }

    /// [`Self::enable_on_connect_in`] with the run guard, for the move.
    fn enable_on_connect_access<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        account: &mut ConnectAccount,
        vault_name: &str,
    ) -> Result<ConnectEnableReport, StoreError> {
        let _run = self.run_shared()?;
        self.enable_on_connect_in(vault, account, vault_name)
    }
}

/// Add each other live device of the account that `store` does not hold: the names of
/// those added, and those that Connect refused with the reason. A failure here never
/// undoes the sync of this Mac; the next refresh of Settings › Connect tries again.
fn register_others(
    account: &mut ConnectAccount,
    store: &VaultStoreView,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut registered = Vec::new();
    let mut not_registered = Vec::new();
    let devices = match account.view() {
        Ok(view) => view.devices,
        Err(error) => {
            not_registered.push((String::new(), error.to_string()));
            return (registered, not_registered);
        }
    };
    let me = account.state().device_id.clone();
    for device in &devices {
        if device.device_id == me
            || store
                .devices
                .iter()
                .any(|held| held.device_id == device.device_id)
        {
            continue;
        }
        match account.register_own_store_device(&store.team_id, &device.device_id, &devices) {
            Ok(_) => registered.push(device.name.clone()),
            Err(error) => not_registered.push((device.name.clone(), error.to_string())),
        }
    }
    (registered, not_registered)
}

/// Whether `error` of a sync means that Connect refused a push for the plan of the
/// account: the read-only state of a vault store.
pub fn is_plan_refusal(error: SyncError) -> bool {
    error == SyncError::Relay(RelayRefusal::PlanRequired)
}

/// Whether a sync that ended with `error` only lacked the account key of this Mac (the
/// account is signed out): the sync of a vault store waits for "Sign In…".
pub fn waits_for_account(relay: &RelaySync, error: SyncError) -> bool {
    error == SyncError::Vault(VaultErrorKind::Locked) && relay.needs_account_key()
}
