//! The iPhone as a device of an Apassy Connect account (ADR 0037 stage 7, plan s7 unit
//! I1, contracts connect-account-v1 sections 5 to 7 and connect-billing-v1 sections 8 and
//! 10; ios-core-v1 section 5.14).
//!
//! The iPhone only **joins** an account: the person scans or pastes the code that "Add a
//! device…" shows on the Mac, both devices show the same six safety words, and the Mac
//! confirms with Touch ID. The iPhone never creates an account, never starts a checkout or
//! opens the portal, and never collects an email (plan section 6, App Store Review
//! Guideline 3.1). `connect_status` gives the plan state of the account and nothing that
//! leads to a purchase: no price, no currency, no URL.
//!
//! The flow and the checks are those of the Mac (`apassy::connect`, unit M1): the link
//! code, the link hash, the `apassy-connect join v1` signature, the safety words of
//! section 7.3, the challenge with its origin check, and the 15-minute account token in
//! memory. This module adds the iPhone's key store, the state of one process, and the
//! wire of the core.
//!
//! **The account device key** is one P-256 key of this iPhone, outside every vault: a
//! Keychain item of the app (`KeychainAccountKeyStore` in ApassyVaultKit: a generic
//! password, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, not synchronizable, the
//! data-protection Keychain), given to the core through
//! `apassy_core_set_account_key_store` ([`Core::set_account_key_store`]). It is not a key
//! of `join.rs`: a vault join keeps its relay key in the vault it joins, and an account
//! key belongs to no vault. The core reads the PKCS#8 document into an erasing buffer for
//! as long as it signs (as the Mac does after Touch ID), and drops it with `lock` and
//! `suspend`; it never writes it to a file, a log, the state file, or an answer. The key
//! signs only the nine messages of section 5 (`AccountSigner::sign`).
//!
//! **Removal.** Only `403 device_removed` of Connect, an answer to a valid signature of
//! this iPhone, means that a Mac removed it (or the account was deleted). Even then the
//! core deletes nothing: `connect_status` says `removed` with `state: "account"`, and
//! the key and the state file stay until `connect_forget`. A key that the Keychain lost
//! is shown the same way. A `401` is never a removal.
//!
//! **Devices.** `connect_status` lists the devices of the account with `verified`: the
//! core verifies the signed device list of the account from the pinned root and the
//! pinned version of the state file (`apassy::connect::trust`), and the app shows "Not
//! verified" for the others. `list_verified` says whether the signed list itself verified:
//! when it is false, no device is verified, the trust store keeps what it had, and the app
//! says that Apassy could not verify the device list and changed nothing. It is absent
//! when Connect did not answer.
//!
//! **The state file** is the Mac's account file, `connect/account.json` in the data
//! directory (mode 0600): the origin, the ids, the names, the public key, and the trust
//! store (the pinned account root, the pinned version and hash of the device list, and
//! the known and departed device keys). No private key, no token, no email, no code, no
//! plan.
//!
//! The account token stays inside the core: [`Accounts::with_token`] gives it to a call
//! of the Connect client of the account's origin only. The dials of `transport.rs` (unit
//! I2) take it there, for the `Authorization` of `GET /v1/tunnel/dial/{node}` to the same
//! origin. The account lives in [`Accounts`], which the core and its transport share.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use apassy::connect::{
    AccountState, ConnectAccount, ConnectClient, ConnectError, DeviceKeyStore, JoinPoll,
    JoinRequest, LinkCode, PlanView, forget_this_device,
};

use super::errors::{CoreError, CoreResult};
use super::wire::{Secret, ok, params};
use super::{Core, guard};

/// The platform of this device on the wire.
const PLATFORM: &str = "iphone";

/// The Connect state of one process: the account (its key and token in memory), a join
/// that waits for a Mac, and the last plan that Connect gave (memory only).
#[derive(Default)]
pub struct State {
    account: Option<ConnectAccount>,
    join: Option<JoinRequest>,
    last: Option<StatusPlan>,
    /// Counts each start, cancel, end, and forget. A call that ran without the mutex puts
    /// its account or join back only when nothing changed in between.
    generation: u64,
}

/// A join as the app shows it: "Waiting for MacBook Pro… Both devices show: blaze cable
/// flute board seal tiger."
#[derive(Debug, Serialize)]
pub struct JoinOut {
    /// `waiting`, or `confirmed` (the iPhone is a device of the account now).
    pub state: &'static str,
    pub account_id: String,
    /// The name of the device that confirms (the Mac that made the link).
    pub confirmer: String,
    /// The six safety words.
    pub words: Vec<String>,
    pub expires_at: u64,
}

/// The plan of the account as the iPhone shows it (connect-billing-v1 section 10): the
/// name of the plan, its state, and its times. Nothing here is a price, a currency, or a
/// URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusPlan {
    /// `personal`, `family`, `team`, or `None`.
    pub plan: Option<String>,
    /// `none`, `pending`, `active`, `trialing`, `past_due`, `read_only`, or `suspended`.
    pub status: String,
    pub entitled: bool,
    pub renews_at: Option<u64>,
    pub ends_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub read_only_until: Option<u64>,
    pub delete_at: Option<u64>,
    /// The group of the account: `{"kind": "family", "role": "member"}`, or `None`.
    pub group: Option<StatusGroup>,
    /// For a Family: the active people and the people of the plan ("3 of 4 people").
    pub people: Option<People>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusGroup {
    /// `family` or `team`.
    pub kind: String,
    /// `owner`, `admin`, or `member`.
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct People {
    pub active: u64,
    pub of: u64,
}

/// A device of the account as the app lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceOut {
    pub device_id: String,
    pub name: String,
    /// `mac`, `iphone`, or `linux`.
    pub platform: String,
    /// This iPhone.
    pub this: bool,
    /// The signed device list that the core verified holds the device's key. The app
    /// shows "Not verified" when it is false.
    pub verified: bool,
}

/// `connect_status`.
#[derive(Debug, Serialize)]
pub struct StatusOut {
    /// `none`: this iPhone is no device of a Connect account. `account`: it has the state
    /// file of an account.
    pub state: &'static str,
    /// True when Connect says a Mac removed this iPhone from its account (or the account
    /// was deleted), or the Keychain lost the key of this iPhone. With `state: "account"`:
    /// the key and the state file stay until `connect_forget`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub removed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// The plan, or `None` when Connect did not answer and no earlier answer is known.
    pub plan: Option<StatusPlan>,
    /// True when Connect did not answer: `plan` is the last answer of this process.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    /// True when this iPhone reaches its Mac through Apassy Connect now: the last
    /// connection to a node of its vaults went through the dial (unit I2,
    /// `transport.rs`). False after a lock, and while the tailnet reaches the Mac.
    pub dial_route: bool,
    /// The state of the dial (`transport::DialState`): `unused`, `connected`,
    /// `not_on_connect`, `mac_offline`, `limit`, `unreachable`, or `refused`. Quiet
    /// states for the app: none is an error, none is a purchase hint.
    pub dial_state: &'static str,
    /// A waiting join, as `connect_join` answered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinOut>,
    /// The devices of the account, each with `verified`. Empty when Connect did not
    /// answer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceOut>,
    /// When Connect answered: the signed device list verified from the pinned root and
    /// went on from the pinned version (`AccountView::list_verified`). When it is false, no
    /// device is verified and the trust store keeps what it had. `None` (absent) when
    /// Connect did not answer, and without an account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_verified: Option<bool>,
}

#[derive(Serialize)]
struct Forgot {
    forgotten: bool,
}

#[derive(Deserialize)]
struct Start {
    link: Secret,
    #[serde(default)]
    device_name: Option<String>,
}

/// The core error of a Connect step. No message names a token, a code, or a key.
fn core_error(error: ConnectError) -> CoreError {
    match error {
        ConnectError::Offline | ConnectError::Broken => CoreError::new(
            "relay_unreachable",
            "Apassy Connect could not be reached. Check the internet connection and try again.",
        ),
        ConnectError::RateLimited(seconds) => CoreError::new(
            "rate_limited",
            format!("Apassy Connect asks to wait {seconds} seconds."),
        ),
        ConnectError::Forbidden | ConnectError::Invalid => CoreError::new(
            "link_invalid",
            "This code does not work: it was used, it expired, or it is not valid. On your Mac, open Apassy > Settings > Connect and make a new code with “Add a device…”.",
        ),
        ConnectError::JoinRefused => CoreError::new(
            "join_refused",
            "The Mac refused, or the code expired. Make a new code on the Mac.",
        ),
        ConnectError::AccountExists => CoreError::new(
            "already_connected",
            "This iPhone is a device of an Apassy Connect account already.",
        ),
        ConnectError::OldAccountFile => CoreError::new(
            "already_connected",
            "This iPhone must join its Apassy Connect account again: its account file is from an earlier version of Apassy. Forget the account on this iPhone, then add it again from your Mac.",
        ),
        ConnectError::Revoked => CoreError::new(
            "removed",
            "A Mac removed this iPhone from its Apassy Connect account.",
        ),
        ConnectError::KeyLost => CoreError::new(
            "removed",
            "The Apassy Connect key of this iPhone is gone. Forget the account on this iPhone, then add it again from your Mac.",
        ),
        ConnectError::LinkMismatch => CoreError::new(
            "link_invalid",
            "This code does not match the Mac that Apassy Connect named for it. Nothing was joined. On your Mac, make a new code with “Add a device…”.",
        ),
        ConnectError::KeychainUnavailable | ConnectError::NoDeviceKey => CoreError::new(
            "not_allowed",
            "The Keychain of this iPhone is not available to Apassy now. Unlock the iPhone and try again.",
        ),
        ConnectError::AccountLimit => CoreError::new(
            "not_allowed",
            "This Apassy Connect account has the most devices it can have. Remove a device on your Mac first.",
        ),
        ConnectError::OriginMismatch | ConnectError::BadAnswer => CoreError::new(
            "damaged",
            "Apassy Connect gave an answer that Apassy does not accept.",
        ),
        // Every other refusal: a status and a code of Connect, never a purchase hint.
        other => CoreError::internal(other.to_string()),
    }
}

/// The plan of a `PlanView`.
fn status_plan(view: &PlanView, group: Option<StatusGroup>, people: Option<People>) -> StatusPlan {
    StatusPlan {
        plan: view.plan.clone(),
        status: view.status.clone(),
        entitled: view.entitled,
        renews_at: view.renews_at,
        ends_at: view.ends_at,
        grace_until: view.grace_until,
        read_only_until: view.read_only_until,
        delete_at: view.delete_at,
        group,
        people,
    }
}

impl StatusPlan {
    /// "Not on Connect": no plan, not entitled, no times.
    fn not_on_connect() -> Self {
        Self {
            plan: None,
            status: "none".to_owned(),
            entitled: false,
            renews_at: None,
            ends_at: None,
            grace_until: None,
            read_only_until: None,
            delete_at: None,
            group: None,
            people: None,
        }
    }
}

/// The view of a join.
fn join_out(join: &JoinRequest, state: &'static str) -> JoinOut {
    JoinOut {
        state,
        account_id: join.account_id().to_owned(),
        confirmer: join.confirmer_name().to_owned(),
        words: join.words().split_whitespace().map(str::to_owned).collect(),
        expires_at: join.expires_at(),
    }
}

/// The link code in a scanned or pasted text: the code alone (the Mac shows it as text
/// and as a QR code of the same text), trimmed.
fn link_code(text: &str) -> Option<LinkCode> {
    LinkCode::parse(text.trim())
}

/// The Apassy Connect account of one process: the [`State`], the Keychain store of the
/// account device key, the account file, and the Connect origin. The core's calls and
/// the dials of its transport (`transport.rs`) share it.
pub struct Accounts {
    state: Mutex<State>,
    /// The Keychain store of the account device key, from the app
    /// (`apassy_core_set_account_key_store`).
    keys: OnceLock<Arc<dyn DeviceKeyStore>>,
    /// The account file.
    path: PathBuf,
    /// The Connect origin, without a trailing slash.
    origin: String,
}

impl Accounts {
    pub(super) fn new(path: PathBuf, origin: String) -> Self {
        Self {
            state: Mutex::new(State::default()),
            keys: OnceLock::new(),
            path,
            origin,
        }
    }

    fn keys(&self) -> Result<Arc<dyn DeviceKeyStore>, ConnectError> {
        self.keys
            .get()
            .cloned()
            .ok_or(ConnectError::KeychainUnavailable)
    }

    /// Run `call` with the account of this iPhone, opened from the state file and the
    /// Keychain when it is not in memory. `None` without an account. The account is put
    /// back after the call unless a forget or a join came in between, also after Connect
    /// said that this iPhone was removed: nothing is deleted until `connect_forget`.
    fn with_account<T>(
        &self,
        call: impl FnOnce(&mut ConnectAccount) -> Result<T, ConnectError>,
    ) -> Result<Option<T>, ConnectError> {
        let (account, generation) = {
            let mut state = guard(&self.state);
            (state.account.take(), state.generation)
        };
        let mut account = match account {
            Some(account) => account,
            None => {
                let store = self.keys()?;
                match ConnectAccount::open(store.as_ref(), &self.path) {
                    Ok(Some(account)) => account,
                    Ok(None) => return Ok(None),
                    // A state file that names a key that the Keychain does not hold is
                    // `KeyLost`; the file stays until `connect_forget`.
                    Err(error) => return Err(error),
                }
            }
        };
        let result = call(&mut account);
        {
            let mut state = guard(&self.state);
            if state.generation == generation && state.account.is_none() {
                state.account = Some(account);
            }
        }
        result.map(Some)
    }

    /// The account token for a call of the Connect client of the account's origin, and
    /// only there (contract section 3, plan 0035 I-2): the dials of unit I2 take it. A
    /// `401` signs in again once. `None` without an account.
    pub(super) fn with_token<T>(
        &self,
        mut call: impl FnMut(&ConnectClient, &str) -> Result<T, ConnectError>,
    ) -> Result<Option<T>, ConnectError> {
        self.with_account(|account| account.with_token(&mut call))
    }

    fn forget_locally(&self) -> Result<(), ConnectError> {
        {
            let mut state = guard(&self.state);
            state.generation += 1;
            state.account = None;
            state.last = None;
        }
        let store = self.keys()?;
        forget_this_device(store.as_ref(), &self.path).map(|_| ())
    }

    /// The account token and the account device key leave memory.
    fn sign_out(&self) {
        let account = {
            let mut state = guard(&self.state);
            state.generation += 1;
            state.account.take()
        };
        drop(account);
    }
}

impl Core {
    /// The Keychain store of the account device key (`apassy_core_set_account_key_store`).
    /// Once per core; a second store is refused (false).
    pub fn set_account_key_store(&self, store: Arc<dyn DeviceKeyStore>) -> bool {
        self.connect.keys.set(store).is_ok()
    }

    fn account_keys(&self) -> CoreResult<Arc<dyn DeviceKeyStore>> {
        self.connect.keys().map_err(core_error)
    }

    fn account_path(&self) -> PathBuf {
        self.connect.path.clone()
    }

    fn connect_client(&self) -> CoreResult<ConnectClient> {
        ConnectClient::new(&self.connect.origin).map_err(core_error)
    }

    pub(super) fn connect_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "connect_join" => {
                let Start { link, device_name } = params(request)?;
                let name = device_name
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| self.device_name.clone());
                Ok(ok(&self.connect_join(link.expose(), &name)?))
            }
            "connect_join_poll" => Ok(ok(&self.connect_join_poll()?)),
            "connect_join_cancel" => {
                self.connect_join_cancel();
                Ok(ok(&super::wire::Empty {}))
            }
            "connect_status" => Ok(ok(&self.connect_status()?)),
            "connect_forget" => Ok(ok(&Forgot {
                forgotten: self.connect_forget()?,
            })),
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    /// Ask to join the account of the code that "Add a device…" shows on the Mac. The
    /// account device key of this iPhone is made now if it has none.
    fn connect_join(&self, link: &str, device_name: &str) -> CoreResult<JoinOut> {
        self.connect_join_cancel();
        let code = link_code(link).ok_or_else(|| core_error(ConnectError::Invalid))?;
        let store = self.account_keys()?;
        let path = self.account_path();
        if AccountState::load(&path).map_err(core_error)?.is_some() {
            return Err(core_error(ConnectError::AccountExists));
        }
        let generation = guard(&self.connect.state).generation;
        let join = JoinRequest::start_on(
            self.connect_client()?,
            store.as_ref(),
            &path,
            code.expose(),
            device_name,
            PLATFORM,
        )
        .map_err(core_error)?;
        let view = join_out(&join, "waiting");
        let mut state = guard(&self.connect.state);
        if state.generation == generation && state.join.is_none() {
            state.join = Some(join);
        } else {
            drop(state);
            let _ = join.cancel();
        }
        Ok(view)
    }

    /// Ask whether the Mac confirmed. A refusal or an expired code ends the join.
    fn connect_join_poll(&self) -> CoreResult<JoinOut> {
        let (join, generation) = {
            let mut state = guard(&self.connect.state);
            (state.join.take(), state.generation)
        };
        let mut join = join
            .ok_or_else(|| CoreError::invalid("No join waits. Scan the code of the Mac again."))?;
        match join.poll() {
            Ok(JoinPoll::Waiting) => {
                let view = join_out(&join, "waiting");
                let mut state = guard(&self.connect.state);
                if state.generation == generation && state.join.is_none() {
                    state.join = Some(join);
                } else {
                    drop(state);
                    let _ = join.cancel();
                }
                Ok(view)
            }
            Ok(JoinPoll::Refused) => {
                guard(&self.connect.state).generation += 1;
                Err(core_error(ConnectError::JoinRefused))
            }
            Ok(JoinPoll::Confirmed(account)) => {
                let view = join_out(&join, "confirmed");
                let mut state = guard(&self.connect.state);
                state.generation += 1;
                state.account = Some(*account);
                state.last = None;
                Ok(view)
            }
            Err(error) => {
                // No network: the join waits on. Another refusal ends it.
                if matches!(
                    error,
                    ConnectError::Offline | ConnectError::Broken | ConnectError::RateLimited(_)
                ) {
                    let mut state = guard(&self.connect.state);
                    if state.generation == generation && state.join.is_none() {
                        state.join = Some(join);
                    }
                } else {
                    guard(&self.connect.state).generation += 1;
                }
                Err(core_error(error))
            }
        }
    }

    /// Give up a join that waits (best effort: Connect ends a link after 10 minutes).
    pub(super) fn connect_join_cancel(&self) {
        let join = {
            let mut state = guard(&self.connect.state);
            state.generation += 1;
            state.join.take()
        };
        if let Some(join) = join {
            let _ = join.cancel();
        }
    }

    /// [`Accounts::with_account`] with the errors of the core. After Connect said that this
    /// iPhone was removed, nothing is deleted until `connect_forget`.
    fn with_account<T>(
        &self,
        call: impl FnOnce(&mut ConnectAccount) -> Result<T, ConnectError>,
    ) -> CoreResult<Option<T>> {
        self.connect.with_account(call).map_err(core_error)
    }

    /// The plan of the account of this iPhone, as the app shows it.
    fn connect_status(&self) -> CoreResult<StatusOut> {
        let join = guard(&self.connect.state)
            .join
            .as_ref()
            .map(|join| join_out(join, "waiting"));
        let dial_state = self.transport.dial_state();
        let none = |join: Option<JoinOut>| StatusOut {
            state: "none",
            removed: false,
            account_id: None,
            device_name: None,
            plan: None,
            stale: false,
            dial_route: false,
            dial_state: dial_state.text(),
            join,
            devices: Vec::new(),
            list_verified: None,
        };
        let answer = self.with_account(|account| {
            let view = account.view()?;
            let group = view.group.as_ref().map(|group| StatusGroup {
                kind: group.kind.clone(),
                role: group.role.clone(),
            });
            // "3 of 4 people": the active people of a Family and the people of its plan.
            let people = match &view.group {
                Some(group) if group.kind == "family" && group.state == "active" => {
                    match account.group() {
                        Ok(Some(detail)) => Some(People {
                            active: detail
                                .members
                                .iter()
                                .filter(|member| member.state == "active")
                                .count() as u64,
                            of: detail.quantity.max(detail.included),
                        }),
                        Ok(None) => None,
                        Err(ConnectError::Revoked) => return Err(ConnectError::Revoked),
                        Err(_) => None,
                    }
                }
                _ => None,
            };
            let state = account.state();
            let devices = view
                .devices
                .iter()
                .map(|device| DeviceOut {
                    device_id: device.device_id.clone(),
                    // The name that the signed device list holds for the key.
                    name: device.shown_name().to_owned(),
                    platform: device.platform.clone(),
                    this: device.device_id == state.device_id,
                    verified: device.verified,
                })
                .collect();
            Ok((
                state.account_id.clone(),
                state.device_name.clone(),
                status_plan(&view.plan, group, people),
                devices,
                view.list_verified,
            ))
        });
        let (account_id, device_name, plan, devices, list_verified) = match answer {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(none(join)),
            Err(error) if error.code == "removed" => {
                // Removed at Connect, or the key is gone: the state file stays.
                let Ok(Some(state)) = AccountState::load(&self.account_path()) else {
                    return Ok(none(join));
                };
                return Ok(StatusOut {
                    state: "account",
                    removed: true,
                    account_id: Some(state.account_id),
                    device_name: Some(state.device_name),
                    plan: None,
                    stale: false,
                    dial_route: false,
                    dial_state: dial_state.text(),
                    join,
                    devices: Vec::new(),
                    list_verified: None,
                });
            }
            Err(error) if matches!(error.code, "relay_unreachable" | "rate_limited") => {
                // Connect did not answer: the last plan of this process, marked stale.
                let Ok(Some(state)) = AccountState::load(&self.account_path()) else {
                    return Err(error);
                };
                // A dial that Connect refused with `plan_required` is newer than the last
                // plan of this process: "Not on Connect".
                let last = if dial_state == super::DialState::NotOnConnect {
                    Some(StatusPlan::not_on_connect())
                } else {
                    guard(&self.connect.state).last.clone()
                };
                return Ok(StatusOut {
                    state: "account",
                    removed: false,
                    account_id: Some(state.account_id),
                    device_name: Some(state.device_name),
                    plan: last,
                    stale: true,
                    dial_route: self.transport.dial_route(),
                    dial_state: dial_state.text(),
                    join,
                    devices: Vec::new(),
                    list_verified: None,
                });
            }
            Err(error) => return Err(error),
        };
        guard(&self.connect.state).last = Some(plan.clone());
        Ok(StatusOut {
            state: "account",
            removed: false,
            account_id: Some(account_id),
            device_name: Some(device_name),
            plan: Some(plan),
            stale: false,
            dial_route: self.transport.dial_route(),
            dial_state: dial_state.text(),
            join,
            devices,
            list_verified: Some(list_verified),
        })
    }

    /// Forget the account on this iPhone: the account device key, the state file, and
    /// everything in memory. Connect is not asked; the Mac's device list shows this
    /// iPhone until a Mac revokes it. True when there was an account or a key.
    fn connect_forget(&self) -> CoreResult<bool> {
        self.connect_join_cancel();
        let had_state = self.account_path().exists();
        let had_key = self
            .connect
            .keys
            .get()
            .is_some_and(|store| matches!(store.read(), Ok(Some(_))));
        self.forget_locally()?;
        Ok(had_state || had_key)
    }

    fn forget_locally(&self) -> CoreResult<()> {
        self.connect.forget_locally().map_err(core_error)
    }

    /// `lock` and `suspend`: the account token and the account device key leave memory,
    /// and every dial through Connect ends (`transport.rs`). The next Connect call reads
    /// the key again from the Keychain.
    pub(super) fn connect_sign_out(&self) {
        self.transport.close();
        self.connect.sign_out();
    }
}
