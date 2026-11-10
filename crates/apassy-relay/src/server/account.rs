//! Apassy Connect accounts (ADR 0037 stage 7, contract connect-account-v1, docs/SPEC.md
//! section 33).
//!
//! An account is one person: a name, a recovery hash, and its devices. Each device is one
//! P-256 key made on the device; Connect holds the public key only. There is no password
//! and no email sign-in: **no account sign-in adds a device**. A new device joins only by a
//! one-use link that a live device of the account made (`POST /v1/account/devices/link`,
//! only the hash of the code reaches Connect) and the confirmation of that device after the
//! person compared six safety words, which Connect cannot compute (it never sees the code).
//!
//! Sign-in is a challenge (`POST /v1/account/challenge`, a one-use nonce of 60 seconds, at
//! most four open for each key) and a signature over the domain `apassy-connect sign-in v1`
//! (`POST /v1/account/token`). The account token (`apassy_act_…`) lives 15 minutes in
//! memory, never on disk. Each request reads the device again in `relay.db`, so a revoked
//! device loses its token at once; the revoke drops its tokens and nonces from memory too.
//!
//! A vault store is a relay-sync-v1 team of kind `account` (`Hub::create_vault_store`):
//! its relay-sync routes work unchanged with the account device key, and its devices come
//! only from this module (`http` refuses the invite, link, and member routes for it).
//!
//! The plan and the group of an account come from [`Plans`] and [`Groups`]: billing (C2)
//! and groups (C3) fill them. Until then an account has no plan ([`NoPlans`]: no new vault
//! store, no push, no entitlement token: 403 `plan_required`) and no group ([`NoGroups`]:
//! a device of another account is 403 `not_in_group`).
//!
//! The audit (the relay's, in `relay.db`) names accounts and devices by id. It never holds
//! a token, a link code, a recovery code, a key, or a client address.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{
    AccountChallengeRequest, AccountConfirm, AccountConfirmer, AccountCreate, AccountCreated,
    AccountDeleted, AccountDevice, AccountGroup, AccountJoin, AccountJoinCancel, AccountJoinId,
    AccountJoined, AccountLinkCreated, AccountLinkRequest, AccountPendingJoin, AccountRecover,
    AccountRecovered, AccountRevoked, AccountTokenRef, AccountTokenRequest, AccountView,
    EmptyRequest, EntitlementAnswer, PlanView, Platform, StoreDevice, StoreDeviceAdd, TeamKind,
    VaultStoreCreate, VaultStoreDeleted, VaultStoreView, WellKnown, WellKnownKey,
};
use crate::device;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::TeamId;
use crate::secret::{
    TokenHash, is_connect_id, new_account_token, parse_account_token, parse_recovery_code,
    same_bytes, token_hash,
};
use crate::server::auth::Need;
use crate::server::entitlement::{Claims, Entitlement, EntitlementSigner, PublishedKey};
use crate::server::hub::Hub;
use crate::server::store::{Store, db, to_i, to_u};

/// The life of an account token: 15 minutes.
pub const TOKEN_SECS: u64 = 900;
/// The life of a sign-in nonce: 60 seconds.
pub const NONCE_SECS: u64 = 60;
/// Open nonces of one key at most; a further challenge drops the oldest.
pub const NONCES_PER_KEY: usize = 4;
/// Open nonces of the relay at most; over it a challenge is 503 `busy`.
pub const MAX_NONCES: usize = 10_000;
/// Live account tokens of one device at most; a further sign-in drops the oldest.
pub const TOKENS_PER_DEVICE: usize = 8;
/// Live account tokens of the relay at most; over it a sign-in is 503 `busy`.
pub const MAX_TOKENS: usize = 100_000;
/// The life of a device link: 10 minutes.
pub const LINK_SECS: u64 = 600;
/// Open links of one device at most.
pub const LINKS_PER_DEVICE: u64 = 3;
/// Live devices of one account at most (`403 account_limit`).
pub const MAX_DEVICES: u64 = 10;
/// Vault stores for each person of the plan (`403 account_limit`).
pub const STORES_PER_PERSON: u64 = 10;
/// Devices of one account in one vault store at most (`403 account_limit`).
pub const STORE_DEVICES_PER_ACCOUNT: u64 = 10;
/// Recovery tries of one account in one hour at most (`429 rate_limited`).
pub const RECOVERY_TRIES_PER_HOUR: u32 = 5;
/// A repeat of `POST /v1/account` with the same body within this time answers the same
/// result (a retry after a lost answer).
pub const CREATE_RETRY_SECS: u64 = 600;
/// The path of the well-known document.
pub const WELL_KNOWN_PATH: &str = "/.well-known/apassy-connect.json";

// ---- Seams for billing (C2) and groups (C3). ----

/// The plan of an account (connect-billing-v1 section 8). Billing (C2) implements it from
/// the Stripe tables of `relay.db`; [`Hub::set_plans`] installs it. Each call gets the
/// directory store and takes its own lock: no lock of this module is held.
pub trait Plans: Send + Sync {
    /// The `PlanView` of `account` at `now`.
    fn plan(&self, directory: &Store, account: &str, now: u64) -> RelayResult<PlanView>;

    /// The people (Family) or members (Team) that count for the store limit: 1 for
    /// Personal and without a plan.
    fn people(&self, _directory: &Store, _account: &str, _now: u64) -> RelayResult<u64> {
        Ok(1)
    }

    /// `DELETE /v1/account` cancels the subscription at once (connect-billing-v1 section
    /// 9). Returns whether one was canceled.
    fn cancel_for_deletion(
        &self,
        _directory: &Store,
        _account: &str,
        _now: u64,
    ) -> RelayResult<bool> {
        Ok(false)
    }
}

/// No account has a plan: every account is `none` (until billing, C2).
pub struct NoPlans;

impl Plans for NoPlans {
    fn plan(&self, _directory: &Store, _account: &str, _now: u64) -> RelayResult<PlanView> {
        Ok(PlanView::none())
    }
}

/// The groups of accounts (connect-billing-v1 section 6). Groups (C3) implement it;
/// [`Hub::set_groups`] installs it.
pub trait Groups: Send + Sync {
    /// The group of `account` for `GET /v1/account`, or `None`.
    fn group_of(
        &self,
        _directory: &Store,
        _account: &str,
        _now: u64,
    ) -> RelayResult<Option<AccountGroup>> {
        Ok(None)
    }

    /// Whether a device of `other` may be added to a vault store of `account`: both are
    /// active members of one group. Else the add is 403 `not_in_group`.
    fn share_group(
        &self,
        _directory: &Store,
        _account: &str,
        _other: &str,
        _now: u64,
    ) -> RelayResult<bool> {
        Ok(false)
    }

    /// Whether `DELETE /v1/account` is refused (409 `conflict`): an organizer or a Team
    /// owner with confirmed members.
    fn blocks_deletion(&self, _directory: &Store, _account: &str, _now: u64) -> RelayResult<bool> {
        Ok(false)
    }
}

/// No account is in a group (until groups, C3).
pub struct NoGroups;

impl Groups for NoGroups {}

// ---- Routes. ----

/// The account endpoints (connect-account-v1 section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountEndpoint {
    Create,
    Challenge,
    Token,
    Join,
    JoinCancel,
    Recover,
    WellKnown,
    View,
    Delete,
    Link,
    Pending,
    Confirm(u64),
    Refuse(u64),
    Revoke(String),
    VaultCreate,
    VaultList,
    StoreDeviceAdd(TeamId),
    VaultDelete(TeamId),
    Entitlement,
}

/// True for a path of this contract: `/v1/account` and below, and the well-known document.
pub fn is_account_path(path: &str) -> bool {
    path == "/v1/account" || path.starts_with("/v1/account/") || path == WELL_KNOWN_PATH
}

/// The need and the endpoint of an account path: `Need::Edge` (no `Authorization`) or
/// `Need::Account` (an account token). 404 `not_found` for an unknown path, 405 for a
/// known path with another method.
pub fn route(method: &str, path: &str) -> RelayResult<(Need, AccountEndpoint)> {
    use AccountEndpoint::*;
    let not_found = || RelayError::new(codes::NOT_FOUND, "No such path.");
    let wrong_method = || {
        RelayError::new(
            codes::METHOD_NOT_ALLOWED,
            "This path does not allow this method.",
        )
    };
    let pick = |choices: Vec<(&str, Need, AccountEndpoint)>| {
        choices
            .into_iter()
            .find(|(m, _, _)| *m == method)
            .map(|(_, need, endpoint)| (need, endpoint))
            .ok_or_else(wrong_method)
    };
    if path == WELL_KNOWN_PATH {
        return pick(vec![("GET", Need::Edge, WellKnown)]);
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let id = |text: &str| text.parse::<u64>().map_err(|_| not_found());
    match segments.as_slice() {
        ["v1", "account"] => pick(vec![
            ("POST", Need::Edge, Create),
            ("GET", Need::Account, View),
            ("DELETE", Need::Account, Delete),
        ]),
        ["v1", "account", "challenge"] => pick(vec![("POST", Need::Edge, Challenge)]),
        ["v1", "account", "token"] => pick(vec![("POST", Need::Edge, Token)]),
        ["v1", "account", "recover"] => pick(vec![("POST", Need::Edge, Recover)]),
        ["v1", "account", "entitlement"] => pick(vec![("GET", Need::Account, Entitlement)]),
        ["v1", "account", "devices", "link"] => pick(vec![("POST", Need::Account, Link)]),
        ["v1", "account", "devices", "pending"] => pick(vec![("GET", Need::Account, Pending)]),
        ["v1", "account", "devices", "join"] => pick(vec![("POST", Need::Edge, Join)]),
        ["v1", "account", "devices", "join", "cancel"] => {
            pick(vec![("POST", Need::Edge, JoinCancel)])
        }
        ["v1", "account", "devices", "pending", n, "confirm"] => {
            pick(vec![("POST", Need::Account, Confirm(id(n)?))])
        }
        ["v1", "account", "devices", "pending", n, "refuse"] => {
            pick(vec![("POST", Need::Account, Refuse(id(n)?))])
        }
        ["v1", "account", "devices", device] if is_connect_id(device, "dev_") => pick(vec![(
            "DELETE",
            Need::Account,
            Revoke((*device).to_string()),
        )]),
        ["v1", "account", "vaults"] => pick(vec![
            ("POST", Need::Account, VaultCreate),
            ("GET", Need::Account, VaultList),
        ]),
        ["v1", "account", "vaults", team, "devices"] => {
            let team = TeamId::parse(team).ok_or_else(not_found)?;
            pick(vec![("POST", Need::Account, StoreDeviceAdd(team))])
        }
        ["v1", "account", "vaults", team] => {
            let team = TeamId::parse(team).ok_or_else(not_found)?;
            pick(vec![("DELETE", Need::Account, VaultDelete(team))])
        }
        _ => Err(not_found()),
    }
}

// ---- Errors. ----

fn forbidden(message: &str) -> RelayError {
    RelayError::new(codes::FORBIDDEN, message)
}

fn conflict(message: &str) -> RelayError {
    RelayError::new(codes::CONFLICT, message)
}

fn plan_required() -> RelayError {
    RelayError::new(
        codes::PLAN_REQUIRED,
        "This account is not on Apassy Connect.",
    )
}

fn account_limit(message: &str) -> RelayError {
    RelayError::new(codes::ACCOUNT_LIMIT, message)
}

fn not_in_group() -> RelayError {
    RelayError::new(
        codes::NOT_IN_GROUP,
        "That device belongs to an account outside your family or team.",
    )
}

/// 403 `account_required`: a route of Connect called with something that is not a live
/// account device, or for a team that is not a vault store.
pub fn account_required() -> RelayError {
    RelayError::new(
        codes::ACCOUNT_REQUIRED,
        "This route needs an Apassy Connect account device.",
    )
}

fn random_source() -> RelayError {
    RelayError::internal("The system has no random source.")
}

fn busy(message: &str) -> RelayError {
    RelayError::new(codes::BUSY, message)
}

// ---- Values. ----

/// A new id: `prefix` and 10 random characters of `a-z2-7`.
fn new_id(prefix: &str) -> RelayResult<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 10];
    getrandom::fill(&mut bytes).map_err(|_| random_source())?;
    let mut text = String::with_capacity(prefix.len() + 10);
    text.push_str(prefix);
    for byte in bytes {
        text.push(char::from(ALPHABET[usize::from(byte & 31)]));
    }
    Ok(text)
}

/// A person's name or a device name: 1 to 64 bytes of UTF-8 without a control character,
/// trimmed.
fn checked_name(text: &str, what: &str) -> RelayResult<String> {
    let text = text.trim();
    if text.is_empty()
        || text.len() > crate::api::MAX_NAME_BYTES
        || text.chars().any(char::is_control)
    {
        return Err(RelayError::invalid(format!(
            "The {what} is 1 to 64 bytes with no control character."
        )));
    }
    Ok(text.to_string())
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A vault id: a UUID of 36 lowercase characters.
fn valid_vault_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

/// A link hash: b64u of 32 bytes, 43 characters.
fn valid_link_hash(text: &str) -> bool {
    text.len() == 43 && decode_b64(text, 32).is_ok_and(|bytes| bytes.len() == 32)
}

/// The public key of a request: b64u of a P-256 point (65 bytes). 400 otherwise.
fn public_key_of(text: &str) -> RelayResult<[u8; device::PUBLIC_KEY_BYTES]> {
    device::decode_public_key(text)
        .map_err(|_| RelayError::invalid("The public key is not a P-256 key."))
}

fn signature_of(text: &str) -> RelayResult<Vec<u8>> {
    decode_b64(text, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::invalid("The signature is not valid."))
}

/// The SHA-256 of a public key: `account_key` and the nonces keep keys by it.
fn key_hash(public_key: &[u8]) -> [u8; 32] {
    Sha256::digest(public_key).into()
}

/// The SHA-256 of a request body as Connect parsed it: the same body again has the same
/// hash.
fn body_hash<T: Serialize>(body: &T) -> RelayResult<[u8; 32]> {
    let bytes =
        serde_json::to_vec(body).map_err(|_| RelayError::internal("A body cannot be written."))?;
    Ok(Sha256::digest(bytes).into())
}

/// A strict request body: unknown, duplicate, and missing fields are 400.
fn strict<T: DeserializeOwned>(body: &[u8]) -> RelayResult<T> {
    serde_json::from_slice(body)
        .map_err(|_| RelayError::invalid("The request body does not match the contract."))
}

/// An empty body or `{}`: the DELETE routes without a body.
fn no_body(body: &[u8]) -> RelayResult<()> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    strict::<EmptyRequest>(body).map(drop)
}

fn to_value<T: Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("The answer cannot be written."))
}

/// The hour of `now`: `last_seen_at` is kept rounded down to it.
fn hour(now: u64) -> u64 {
    now - now % 3600
}

fn actor(account: &str) -> String {
    format!("account:{account}")
}

// ---- In-memory sign-in state. ----

struct Nonce {
    account: String,
    key: [u8; 32],
    expires_at: u64,
}

struct Token {
    account: String,
    device: String,
    expires_at: u64,
}

#[derive(Default)]
struct AuthState {
    nonces: HashMap<String, Nonce>,
    nonce_order: VecDeque<String>,
    tokens: HashMap<TokenHash, Token>,
    token_order: VecDeque<TokenHash>,
    /// The recovery tries of each account: the start of the hour window and the count.
    recovery: HashMap<String, (u64, u32)>,
}

impl AuthState {
    fn purge(&mut self, now: u64) {
        self.nonces.retain(|_, nonce| nonce.expires_at > now);
        self.tokens.retain(|_, token| token.expires_at > now);
        self.recovery
            .retain(|_, (start, _)| now < start.saturating_add(3600));
        let nonces = &self.nonces;
        self.nonce_order.retain(|nonce| nonces.contains_key(nonce));
        let tokens = &self.tokens;
        self.token_order.retain(|hash| tokens.contains_key(hash));
    }

    /// Drops every token and nonce of `device` (its key `key`).
    fn drop_device(&mut self, device: &str, key: Option<&[u8; 32]>) {
        self.tokens.retain(|_, token| token.device != device);
        if let Some(key) = key {
            self.nonces.retain(|_, nonce| &nonce.key != key);
        }
        let nonces = &self.nonces;
        self.nonce_order.retain(|nonce| nonces.contains_key(nonce));
        let tokens = &self.tokens;
        self.token_order.retain(|hash| tokens.contains_key(hash));
    }

    /// Drops every token and nonce of `account`.
    fn drop_account(&mut self, account: &str) {
        self.tokens.retain(|_, token| token.account != account);
        self.nonces.retain(|_, nonce| nonce.account != account);
        let nonces = &self.nonces;
        self.nonce_order.retain(|nonce| nonces.contains_key(nonce));
        let tokens = &self.tokens;
        self.token_order.retain(|hash| tokens.contains_key(hash));
    }
}

/// The account state of a relay: the sign-in state in memory, the seams of billing and
/// groups, and the entitlement signer. One for each `Hub`.
pub struct Accounts {
    state: Mutex<AuthState>,
    plans: RwLock<Arc<dyn Plans>>,
    groups: RwLock<Arc<dyn Groups>>,
    signer: Option<EntitlementSigner>,
}

impl Accounts {
    /// The state of a relay with the signing key of its configuration (none: no token).
    pub fn new(signer: Option<EntitlementSigner>) -> Self {
        Self {
            state: Mutex::new(AuthState::default()),
            plans: RwLock::new(Arc::new(NoPlans)),
            groups: RwLock::new(Arc::new(NoGroups)),
            signer,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, AuthState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn plans(&self) -> Arc<dyn Plans> {
        self.plans
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn groups(&self) -> Arc<dyn Groups> {
        self.groups
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_plans(&self, plans: Arc<dyn Plans>) {
        *self.plans.write().unwrap_or_else(PoisonError::into_inner) = plans;
    }

    pub fn set_groups(&self, groups: Arc<dyn Groups>) {
        *self.groups.write().unwrap_or_else(PoisonError::into_inner) = groups;
    }

    pub fn signer(&self) -> Option<&EntitlementSigner> {
        self.signer.as_ref()
    }

    /// The live account tokens in memory (for tests and the operator).
    pub fn live_tokens(&self, now: u64) -> usize {
        let mut state = self.state();
        state.purge(now);
        state.tokens.len()
    }
}

// ---- The caller. ----

/// The live account device of a request with an account token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCaller {
    pub account: String,
    pub device: String,
    pub public_key: Vec<u8>,
}

/// One live device of an account, from `relay.db`.
fn live_device(conn: &Connection, device: &str) -> RelayResult<Option<AccountCaller>> {
    conn.query_row(
        "SELECT d.account_id, d.public_key FROM account_device d JOIN account a ON a.id = d.account_id \
         WHERE d.id = ?1 AND d.revoked_at IS NULL",
        params![device],
        |row| {
            Ok(AccountCaller {
                account: row.get(0)?,
                device: device.to_string(),
                public_key: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(db)
}

/// The caller of an account token, for every route with `Need::Account` (also those of
/// billing, groups, and the tunnel): a well-formed token in memory, not expired, whose
/// device is live in `relay.db` now. A team token is 403 `account_required`; anything
/// else is 401 `unauthenticated`, one message for every cause. Marks the device seen
/// (rounded to the hour, at most one write an hour).
pub fn authenticate(hub: &Hub, token: Option<&str>, now: u64) -> RelayResult<AccountCaller> {
    let token = token.ok_or_else(RelayError::unauthenticated)?;
    let Some(account) = parse_account_token(token) else {
        if crate::secret::parse_token(token).is_some() {
            return Err(account_required());
        }
        return Err(RelayError::unauthenticated());
    };
    let hash = token_hash(token);
    let device = {
        let state = hub.accounts.state();
        match state.tokens.get(&hash) {
            Some(entry) if entry.expires_at > now && entry.account == account => {
                entry.device.clone()
            }
            _ => return Err(RelayError::unauthenticated()),
        }
    };
    let caller = hub.directory.store.with(|conn| {
        let caller = live_device(conn, &device)?
            .filter(|caller| caller.account == account)
            .ok_or_else(RelayError::unauthenticated)?;
        conn.execute(
            "UPDATE account_device SET last_seen_at = ?2 WHERE id = ?1 \
             AND (last_seen_at IS NULL OR last_seen_at <> ?2)",
            params![device, to_i(hour(now))],
        )
        .map_err(db)?;
        Ok(caller)
    })?;
    Ok(caller)
}

// ---- Dispatch. ----

/// An edge endpoint: no `Authorization`. `origin` is the Connect origin (the public URL).
pub fn dispatch_edge(
    hub: &Hub,
    endpoint: &AccountEndpoint,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        AccountEndpoint::Create => create(hub, &strict(body)?, now),
        AccountEndpoint::Challenge => challenge(hub, &strict(body)?, now),
        AccountEndpoint::Token => token(hub, &strict(body)?, now),
        AccountEndpoint::Join => join(hub, &strict(body)?, now),
        AccountEndpoint::JoinCancel => join_cancel(hub, &strict(body)?, now),
        AccountEndpoint::Recover => recover(hub, &strict(body)?, now),
        AccountEndpoint::WellKnown => well_known(hub, now),
        _ => Err(RelayError::internal("Not an edge endpoint.")),
    }
}

/// An endpoint with the account token of `caller`.
pub fn dispatch(
    hub: &Hub,
    caller: &AccountCaller,
    endpoint: &AccountEndpoint,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        AccountEndpoint::View => view(hub, caller, now),
        AccountEndpoint::Delete => {
            no_body(body)?;
            delete_account(hub, caller, now)
        }
        AccountEndpoint::Link => link(hub, caller, &strict(body)?, now),
        AccountEndpoint::Pending => pending(hub, caller, now),
        AccountEndpoint::Confirm(join_id) => confirm(hub, caller, *join_id, &strict(body)?, now),
        AccountEndpoint::Refuse(join_id) => {
            strict::<EmptyRequest>(body)?;
            refuse(hub, caller, *join_id, now)
        }
        AccountEndpoint::Revoke(device) => {
            no_body(body)?;
            revoke(hub, caller, device, now)
        }
        AccountEndpoint::VaultCreate => vault_create(hub, caller, &strict(body)?, now),
        AccountEndpoint::VaultList => vault_list(hub, caller),
        AccountEndpoint::StoreDeviceAdd(team) => {
            store_device_add(hub, caller, team, &strict(body)?, now)
        }
        AccountEndpoint::VaultDelete(team) => {
            no_body(body)?;
            vault_delete(hub, caller, team, now)
        }
        AccountEndpoint::Entitlement => entitlement(hub, caller, now),
        _ => Err(RelayError::internal("Not an account endpoint.")),
    }
}

// ---- Account and sign-in (section 6). ----

fn device_view(conn: &Connection, device: &str) -> RelayResult<AccountDevice> {
    conn.query_row(
        "SELECT id, name, platform, public_key, created_at, last_seen_at FROM account_device WHERE id = ?1",
        params![device],
        device_from_row,
    )
    .map_err(db)
}

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountDevice> {
    let platform: String = row.get(2)?;
    let key: Vec<u8> = row.get(3)?;
    Ok(AccountDevice {
        device_id: row.get(0)?,
        name: row.get(1)?,
        platform: Platform::parse(&platform).ok_or(rusqlite::Error::InvalidQuery)?,
        public_key: encode_b64(&key),
        created_at: to_u(row.get(4)?),
        last_seen_at: row.get::<_, Option<i64>>(5)?.map(|at| hour(to_u(at))),
    })
}

fn live_devices(conn: &Connection, account: &str) -> RelayResult<u64> {
    conn.query_row(
        "SELECT count(*) FROM account_device WHERE account_id = ?1 AND revoked_at IS NULL",
        params![account],
        |row| row.get::<_, i64>(0),
    )
    .map(to_u)
    .map_err(db)
}

/// True when `key` (its SHA-256) was ever the key of an account device.
fn key_used(conn: &Connection, key: &[u8; 32]) -> RelayResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_key WHERE key_hash = ?1)",
        params![key.as_slice()],
        |row| row.get(0),
    )
    .map_err(db)
}

/// A new device row and its key in `account_key`, inside a transaction.
fn insert_device(
    conn: &Connection,
    account: &str,
    name: &str,
    platform: Platform,
    public_key: &[u8],
    now: u64,
) -> RelayResult<String> {
    if key_used(conn, &key_hash(public_key))? {
        return Err(conflict(
            "This key is or was a device of an account. Make a new key.",
        ));
    }
    let mut id = new_id("dev_")?;
    while conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM account_device WHERE id = ?1)",
            params![id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(db)?
    {
        id = new_id("dev_")?;
    }
    conn.execute(
        "INSERT INTO account_device (id, account_id, name, platform, public_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, account, name, platform.as_str(), public_key, to_i(now)],
    )
    .map_err(db)?;
    conn.execute(
        "INSERT INTO account_key (key_hash, created_at) VALUES (?1, ?2)",
        params![key_hash(public_key).as_slice(), to_i(now)],
    )
    .map_err(db)?;
    Ok(id)
}

/// `POST /v1/account`: a new account with its first device. The signature over the
/// `apassy-connect account v1` message of this origin proves the key. A key is a device
/// of at most one account, ever; the same body again within `CREATE_RETRY_SECS` answers
/// the same result.
fn create(hub: &Hub, request: &AccountCreate, now: u64) -> RelayResult<Value> {
    let name = checked_name(&request.name, "name")?;
    let device_name = checked_name(&request.device_name, "device name")?;
    let public_key = public_key_of(&request.public_key)?;
    if !is_hex(&request.recovery_hash, 64) {
        return Err(RelayError::invalid(
            "The recovery hash is 64 lowercase hex characters.",
        ));
    }
    let signature = signature_of(&request.signature)?;
    let message = device::account_message(&hub.config.public_url, &request.public_key);
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of the key over the account message of this Connect.",
        ));
    }
    let hash = body_hash(request)?;
    let created = hub.directory.store.tx(|tx| {
        if key_used(tx, &key_hash(&public_key))? {
            // A retry of the same body, shortly after: the same answer.
            let earlier: Option<(String, String, i64)> = tx
                .query_row(
                    "SELECT a.id, d.id, a.created_at FROM account a JOIN account_device d ON d.account_id = a.id \
                     WHERE d.public_key = ?1 AND a.create_hash = ?2 AND a.created_at > ?3 AND d.revoked_at IS NULL",
                    params![public_key.as_slice(), hash.as_slice(), to_i(now.saturating_sub(CREATE_RETRY_SECS))],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(db)?;
            return earlier
                .map(|(account_id, device_id, at)| AccountCreated {
                    account_id,
                    device_id,
                    created_at: to_u(at),
                })
                .ok_or_else(|| conflict("This key is or was a device of an account."));
        }
        let mut account = new_id("acc_")?;
        while tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account WHERE id = ?1)",
                params![account],
                |row| row.get::<_, bool>(0),
            )
            .map_err(db)?
        {
            account = new_id("acc_")?;
        }
        tx.execute(
            "INSERT INTO account (id, name, created_at, recovery_hash, create_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account, name, to_i(now), request.recovery_hash, hash.as_slice()],
        )
        .map_err(db)?;
        let device = insert_device(tx, &account, &device_name, request.platform, &public_key, now)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&account),
            "account_created",
            None,
            &json!({"account_id": account, "device_id": device}),
        )?;
        Ok(AccountCreated {
            account_id: account,
            device_id: device,
            created_at: now,
        })
    })?;
    to_value(&created)
}

/// `POST /v1/account/challenge`: a nonce for a live device of the account. A key whose
/// join waits is 403 `join_pending`; a key whose join was refused, cancelled, or expired
/// is 403 `join_refused`; any other key is 401.
fn challenge(hub: &Hub, request: &AccountChallengeRequest, now: u64) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_") {
        return Err(RelayError::unauthenticated());
    }
    let public_key = public_key_of(&request.public_key)?;
    let live = hub.directory.store.with(|conn| {
        let live: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_device WHERE account_id = ?1 AND public_key = ?2 AND revoked_at IS NULL)",
                params![request.account_id, public_key.as_slice()],
                |row| row.get(0),
            )
            .map_err(db)?;
        if live {
            return Ok(true);
        }
        let join: Option<(String, i64)> = conn
            .query_row(
                "SELECT state, expires_at FROM account_join WHERE account_id = ?1 AND public_key = ?2 ORDER BY id DESC LIMIT 1",
                params![request.account_id, public_key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        match join {
            Some((state, expires_at)) if state == "pending" && to_u(expires_at) > now => Err(
                RelayError::new(codes::JOIN_PENDING, "The other device has not confirmed yet."),
            ),
            Some((state, _)) if state != "confirmed" => Err(RelayError::new(
                codes::JOIN_REFUSED,
                "The other device refused, or the link expired.",
            )),
            _ => Ok(false),
        }
    })?;
    if !live {
        return Err(RelayError::unauthenticated());
    }
    let nonce = device::new_nonce().map_err(|_| random_source())?;
    let expires_at = now.saturating_add(NONCE_SECS);
    let key = key_hash(&public_key);
    let mut state = hub.accounts.state();
    state.purge(now);
    if state
        .nonces
        .values()
        .filter(|nonce| nonce.key == key)
        .count()
        >= NONCES_PER_KEY
        && let Some(oldest) = state
            .nonce_order
            .iter()
            .find(|nonce| {
                state
                    .nonces
                    .get(*nonce)
                    .is_some_and(|entry| entry.key == key)
            })
            .cloned()
    {
        state.nonces.remove(&oldest);
        state.nonce_order.retain(|nonce| *nonce != oldest);
    }
    if state.nonces.len() >= MAX_NONCES {
        return Err(busy(
            "The sign-in challenge table is full. Try again later.",
        ));
    }
    state.nonce_order.push_back(nonce.clone());
    state.nonces.insert(
        nonce.clone(),
        Nonce {
            account: request.account_id.clone(),
            key,
            expires_at,
        },
    );
    Ok(json!({"nonce": nonce, "expires_at": expires_at, "origin": hub.config.public_url}))
}

/// `POST /v1/account/token`: the nonce is used up first, before any check; then the
/// signature over the `apassy-connect sign-in v1` message of this origin, the account, the
/// key, and the nonce, and a live device of that key. Every refusal is the same 401.
fn token(hub: &Hub, request: &AccountTokenRequest, now: u64) -> RelayResult<Value> {
    let nonce = {
        let mut state = hub.accounts.state();
        let nonce = state.nonces.remove(&request.nonce);
        state.nonce_order.retain(|text| *text != request.nonce);
        nonce
    };
    let nonce = nonce
        .filter(|nonce| nonce.expires_at > now && nonce.account == request.account_id)
        .ok_or_else(RelayError::unauthenticated)?;
    let public_key = device::decode_public_key(&request.public_key)
        .map_err(|_| RelayError::unauthenticated())?;
    let signature = decode_b64(&request.signature, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::unauthenticated())?;
    let message = device::account_sign_in_message(
        &hub.config.public_url,
        &request.account_id,
        &request.public_key,
        &request.nonce,
    );
    if nonce.key != key_hash(&public_key) || !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::unauthenticated());
    }
    let device: String = hub.directory.store.tx(|tx| {
        let device: String = tx
            .query_row(
                "SELECT id FROM account_device WHERE account_id = ?1 AND public_key = ?2 AND revoked_at IS NULL",
                params![request.account_id, public_key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?
            .ok_or_else(RelayError::unauthenticated)?;
        tx.execute(
            "UPDATE account_device SET last_seen_at = ?2 WHERE id = ?1",
            params![device, to_i(hour(now))],
        )
        .map_err(db)?;
        Ok(device)
    })?;
    let token = new_account_token(&request.account_id)?;
    let expires_at = now.saturating_add(TOKEN_SECS);
    let hash = token_hash(token.expose());
    {
        let mut state = hub.accounts.state();
        state.purge(now);
        if state
            .tokens
            .values()
            .filter(|entry| entry.device == device)
            .count()
            >= TOKENS_PER_DEVICE
            && let Some(oldest) = state
                .token_order
                .iter()
                .find(|hash| {
                    state
                        .tokens
                        .get(*hash)
                        .is_some_and(|entry| entry.device == device)
                })
                .copied()
        {
            state.tokens.remove(&oldest);
            state.token_order.retain(|hash| *hash != oldest);
        }
        if state.tokens.len() >= MAX_TOKENS {
            return Err(busy("The relay holds too many sign-ins. Try again later."));
        }
        state.token_order.push_back(hash);
        state.tokens.insert(
            hash,
            Token {
                account: request.account_id.clone(),
                device: device.clone(),
                expires_at,
            },
        );
    }
    to_value(&AccountTokenRef {
        token: token.expose(),
        expires_at,
        account_id: &request.account_id,
        device_id: &device,
    })
}

/// `GET /v1/account`.
fn view(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let plan = hub
        .accounts
        .plans()
        .plan(&hub.directory.store, &caller.account, now)?;
    let group = hub
        .accounts
        .groups()
        .group_of(&hub.directory.store, &caller.account, now)?;
    let view = hub.directory.store.with(|conn| {
        let (name, email, created_at): (String, Option<String>, i64) = conn
            .query_row(
                "SELECT name, email, created_at FROM account WHERE id = ?1",
                params![caller.account],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(db)?;
        let mut statement = conn
            .prepare(
                "SELECT id, name, platform, public_key, created_at, last_seen_at FROM account_device \
                 WHERE account_id = ?1 AND revoked_at IS NULL ORDER BY created_at, id",
            )
            .map_err(db)?;
        let devices = statement
            .query_map(params![caller.account], device_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(AccountView {
            account_id: caller.account.clone(),
            name,
            email,
            created_at: to_u(created_at),
            plan,
            devices,
            group,
        })
    })?;
    to_value(&view)
}

/// `DELETE /v1/account`: the subscription is canceled (billing), every vault store of the
/// account is deleted, its devices leave every other store, and its devices, links, joins,
/// nodes, and grants go. The keys stay used (`account_key`). The brain gets `forget`.
fn delete_account(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    if hub
        .accounts
        .groups()
        .blocks_deletion(&hub.directory.store, &caller.account, now)?
    {
        return Err(conflict(
            "Remove the members of your family or team before you delete the account.",
        ));
    }
    let canceled =
        hub.accounts
            .plans()
            .cancel_for_deletion(&hub.directory.store, &caller.account, now)?;
    let deleted_stores = delete_stores_of(hub, &caller.account, now)?;
    let devices = leave_other_stores(hub, &caller.account, now)?;
    hub.directory.store.tx(|tx| {
        tx.execute(
            "DELETE FROM tunnel_grant WHERE account_id = ?1 OR node_id IN (SELECT id FROM tunnel_node WHERE account_id = ?1)",
            params![caller.account],
        )
        .map_err(db)?;
        tx.execute("DELETE FROM tunnel_node WHERE account_id = ?1", params![caller.account])
            .map_err(db)?;
        tx.execute(
            "UPDATE stripe_customer SET email = NULL WHERE account_id = ?1",
            params![caller.account],
        )
        .map_err(db)?;
        // The links, the joins, and the devices go with the account (ON DELETE CASCADE).
        tx.execute("DELETE FROM account WHERE id = ?1", params![caller.account])
            .map_err(db)?;
        enqueue_brain(tx, "forget", &caller.account, now)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_deleted",
            None,
            &json!({"account_id": caller.account, "deleted_stores": deleted_stores,
                    "devices": devices, "subscription_canceled": canceled}),
        )
    })?;
    hub.accounts.state().drop_account(&caller.account);
    crate::server::tunnel_routes::account_deleted(hub, &caller.account);
    to_value(&AccountDeleted {
        account_id: caller.account.clone(),
        deleted_stores,
        subscription_canceled: canceled,
    })
}

/// An I-4 event for the bouncer brain (connect-account-v1 section 11), kept until a later
/// unit delivers it.
fn enqueue_brain(conn: &Connection, kind: &str, subject: &str, now: u64) -> RelayResult<()> {
    conn.execute(
        "INSERT INTO brain_event (kind, subject, created_at, next_at) VALUES (?1, ?2, ?3, ?3)",
        params![kind, subject, to_i(now)],
    )
    .map_err(db)?;
    Ok(())
}

// ---- Account devices (section 7). ----

/// `POST /v1/account/devices/link`: a one-use link of 10 minutes for the hash of a code
/// that the calling device made and keeps.
fn link(
    hub: &Hub,
    caller: &AccountCaller,
    request: &AccountLinkRequest,
    now: u64,
) -> RelayResult<Value> {
    if !valid_link_hash(&request.link_hash) {
        return Err(RelayError::invalid("The link hash is b64u of 32 bytes."));
    }
    let expires_at = now.saturating_add(LINK_SECS);
    let link_id = hub.directory.store.tx(|tx| {
        let open: i64 = tx
            .query_row(
                "SELECT count(*) FROM account_link WHERE device_id = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![caller.device, to_i(now)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(open) >= LINKS_PER_DEVICE {
            return Err(account_limit("This device has 3 open links. Wait until one ends."));
        }
        let taken: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_link WHERE link_hash = ?1)",
                params![request.link_hash],
                |row| row.get(0),
            )
            .map_err(db)?;
        if taken {
            return Err(conflict("This link was made before. Make a new code."));
        }
        tx.execute(
            "INSERT INTO account_link (account_id, device_id, link_hash, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![caller.account, caller.device, request.link_hash, to_i(now), to_i(expires_at)],
        )
        .map_err(db)?;
        let link_id = to_u(tx.last_insert_rowid());
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_link_created",
            None,
            &json!({"link_id": link_id, "device_id": caller.device}),
        )?;
        Ok(link_id)
    })?;
    to_value(&AccountLinkCreated {
        link_id,
        expires_at,
    })
}

/// `GET /v1/account/devices/pending`: the pending joins of links that this device made.
fn pending(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let joins = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT j.id, j.link_id, j.name, j.platform, j.public_key, j.created_at, j.expires_at \
                 FROM account_join j JOIN account_link l ON l.id = j.link_id \
                 WHERE l.device_id = ?1 AND j.state = 'pending' AND j.expires_at > ?2 ORDER BY j.id",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![caller.device, to_i(now)], |row| {
                let platform: String = row.get(3)?;
                let key: Vec<u8> = row.get(4)?;
                Ok(AccountPendingJoin {
                    join_id: to_u(row.get(0)?),
                    link_id: to_u(row.get(1)?),
                    device_name: row.get(2)?,
                    platform: Platform::parse(&platform).ok_or(rusqlite::Error::InvalidQuery)?,
                    public_key: encode_b64(&key),
                    created_at: to_u(row.get(5)?),
                    expires_at: to_u(row.get(6)?),
                })
            })
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    to_value(&joins)
}

/// The confirmer of a link: the device that made it.
fn confirmer(conn: &Connection, link_id: u64) -> RelayResult<AccountConfirmer> {
    conn.query_row(
        "SELECT d.id, d.name, d.public_key FROM account_link l JOIN account_device d ON d.id = l.device_id WHERE l.id = ?1",
        params![to_i(link_id)],
        |row| {
            let key: Vec<u8> = row.get(2)?;
            Ok(AccountConfirmer {
                device_id: row.get(0)?,
                name: row.get(1)?,
                public_key: encode_b64(&key),
            })
        },
    )
    .map_err(db)
}

/// `POST /v1/account/devices/join` (edge): a new device asks to join with the hash of the
/// link code and its signature over the `apassy-connect join v1` message. An unknown, used,
/// or expired link is 403 `forbidden`; the same body again answers the same result. Nothing
/// is added until the device that made the link confirms.
fn join(hub: &Hub, request: &AccountJoin, now: u64) -> RelayResult<Value> {
    let name = checked_name(&request.device_name, "device name")?;
    if !is_connect_id(&request.account_id, "acc_") || !valid_link_hash(&request.link_hash) {
        return Err(RelayError::invalid(
            "The account id or the link hash is not valid.",
        ));
    }
    let public_key = public_key_of(&request.public_key)?;
    let signature = signature_of(&request.signature)?;
    let message = device::account_join_message(
        &hub.config.public_url,
        &request.account_id,
        &request.link_hash,
        &request.public_key,
    );
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of the key over the join message of this Connect.",
        ));
    }
    let hash = body_hash(request)?;
    let joined = hub.directory.store.tx(|tx| {
        let earlier: Option<(i64, i64, i64)> = tx
            .query_row(
                "SELECT id, link_id, expires_at FROM account_join WHERE body_hash = ?1",
                params![hash.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        if let Some((join_id, link_id, expires_at)) = earlier {
            return Ok(AccountJoined {
                join_id: to_u(join_id),
                account_id: request.account_id.clone(),
                confirmer: confirmer(tx, to_u(link_id))?,
                expires_at: to_u(expires_at),
            });
        }
        let link: Option<(i64, i64)> = tx
            .query_row(
                "SELECT l.id, l.expires_at FROM account_link l JOIN account_device d ON d.id = l.device_id \
                 WHERE l.account_id = ?1 AND l.link_hash = ?2 AND l.used_at IS NULL AND l.expires_at > ?3 \
                 AND d.revoked_at IS NULL",
                params![request.account_id, request.link_hash, to_i(now)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let (link_id, expires_at) =
            link.ok_or_else(|| forbidden("The link is not valid, was used, or expired."))?;
        if key_used(tx, &key_hash(&public_key))? {
            return Err(conflict("This key is or was a device of an account. Make a new key."));
        }
        tx.execute(
            "UPDATE account_link SET used_at = ?2 WHERE id = ?1",
            params![link_id, to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "INSERT INTO account_join (link_id, account_id, name, platform, public_key, body_hash, state, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8)",
            params![link_id, request.account_id, name, request.platform.as_str(), public_key.as_slice(),
                    hash.as_slice(), to_i(now), expires_at],
        )
        .map_err(db)?;
        let join_id = to_u(tx.last_insert_rowid());
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&request.account_id),
            "account_join_requested",
            None,
            &json!({"join_id": join_id, "link_id": link_id}),
        )?;
        Ok(AccountJoined {
            join_id,
            account_id: request.account_id.clone(),
            confirmer: confirmer(tx, to_u(link_id))?,
            expires_at: to_u(expires_at),
        })
    })?;
    to_value(&joined)
}

/// `POST /v1/account/devices/join/cancel` (edge): the new device ends its pending join.
fn join_cancel(hub: &Hub, request: &AccountJoinCancel, now: u64) -> RelayResult<Value> {
    let public_key = public_key_of(&request.public_key)?;
    let join_id = hub.directory.store.tx(|tx| {
        let join: Option<i64> = tx
            .query_row(
                "SELECT j.id FROM account_join j JOIN account_link l ON l.id = j.link_id \
                 WHERE j.account_id = ?1 AND l.link_hash = ?2 AND j.public_key = ?3 AND j.state = 'pending'",
                params![request.account_id, request.link_hash, public_key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let join = join.ok_or_else(|| forbidden("There is no such pending join."))?;
        tx.execute(
            "UPDATE account_join SET state = 'cancelled', decided_at = ?2 WHERE id = ?1",
            params![join, to_i(now)],
        )
        .map_err(db)?;
        Ok(to_u(join))
    })?;
    to_value(&AccountJoinId { join_id })
}

/// A pending join of a link that `caller` made: 404 for no such join of the account, 403
/// for a join of another device's link, 409 when it is not pending any more.
fn own_pending_join(
    conn: &Connection,
    caller: &AccountCaller,
    join_id: u64,
    now: u64,
) -> RelayResult<(String, Platform, Vec<u8>)> {
    let row: Option<(String, String, Vec<u8>, String, String, i64)> = conn
        .query_row(
            "SELECT j.name, j.platform, j.public_key, j.state, l.device_id, j.expires_at \
             FROM account_join j JOIN account_link l ON l.id = j.link_id WHERE j.id = ?1 AND j.account_id = ?2",
            params![to_i(join_id), caller.account],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .map_err(db)?;
    let (name, platform, key, state, maker, expires_at) =
        row.ok_or_else(|| RelayError::not_found("join"))?;
    if maker != caller.device {
        return Err(forbidden(
            "Only the device that made the link confirms or refuses it.",
        ));
    }
    if state != "pending" || to_u(expires_at) <= now {
        return Err(conflict("The join is not pending any more."));
    }
    let platform = Platform::parse(&platform)
        .ok_or_else(|| RelayError::internal("A join has an unknown platform."))?;
    Ok((name, platform, key))
}

/// `POST /v1/account/devices/pending/{join_id}/confirm`: the device that made the link
/// adds exactly the key it computed the words for. Another key is 409 and adds nothing.
fn confirm(
    hub: &Hub,
    caller: &AccountCaller,
    join_id: u64,
    request: &AccountConfirm,
    now: u64,
) -> RelayResult<Value> {
    let public_key = public_key_of(&request.public_key)?;
    let added = hub.directory.store.tx(|tx| {
        let (name, platform, key) = own_pending_join(tx, caller, join_id, now)?;
        if key != public_key.as_slice() {
            return Err(conflict("The pending join has another key. Nothing was added."));
        }
        if live_devices(tx, &caller.account)? >= MAX_DEVICES {
            return Err(account_limit("This account has 10 devices."));
        }
        let device = insert_device(tx, &caller.account, &name, platform, &key, now)?;
        tx.execute(
            "UPDATE account_join SET state = 'confirmed', decided_at = ?2, device_id = ?3 WHERE id = ?1",
            params![to_i(join_id), to_i(now), device],
        )
        .map_err(db)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_device_added",
            None,
            &json!({"join_id": join_id, "device_id": device, "by": caller.device}),
        )?;
        device_view(tx, &device)
    })?;
    to_value(&added)
}

/// `POST /v1/account/devices/pending/{join_id}/refuse`.
fn refuse(hub: &Hub, caller: &AccountCaller, join_id: u64, now: u64) -> RelayResult<Value> {
    hub.directory.store.tx(|tx| {
        own_pending_join(tx, caller, join_id, now)?;
        tx.execute(
            "UPDATE account_join SET state = 'refused', decided_at = ?2 WHERE id = ?1",
            params![to_i(join_id), to_i(now)],
        )
        .map_err(db)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_join_refused",
            None,
            &json!({"join_id": join_id, "by": caller.device}),
        )
    })?;
    to_value(&AccountJoinId { join_id })
}

/// Removes `device` from every vault store that holds it: its row in each store is
/// revoked, its relay-sync tokens of that store end, and its row of
/// `account_store_device` goes. Returns the stores it left.
fn leave_stores(hub: &Hub, device: &str, now: u64) -> RelayResult<u64> {
    let stores: Vec<(String, i64)> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare("SELECT team_id, store_device FROM account_store_device WHERE device_id = ?1")
            .map_err(db)?;
        let rows = statement
            .query_map(params![device], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    let mut left = 0;
    for (team, store_device) in stores {
        if let Some(team) = TeamId::parse(&team) {
            hub.remove_store_device(&team, device, to_u(store_device), now)?;
            left += 1;
        }
    }
    Ok(left)
}

/// `DELETE /v1/account/devices/{device_id}` from any live device of the account (also
/// itself). At once: the device is revoked in `relay.db` (every later request of its
/// tokens fails there), its tokens and nonces leave memory, it leaves every vault store,
/// its open links end, its node goes, and the brain gets `revoke`.
fn revoke(hub: &Hub, caller: &AccountCaller, device: &str, now: u64) -> RelayResult<Value> {
    let key = hub.directory.store.tx(|tx| {
        let target = live_device(tx, device)?
            .filter(|target| target.account == caller.account)
            .ok_or_else(|| RelayError::not_found("device"))?;
        tx.execute(
            "UPDATE account_device SET revoked_at = ?2 WHERE id = ?1",
            params![device, to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE account_join SET state = 'expired', decided_at = ?2 WHERE state = 'pending' \
             AND link_id IN (SELECT id FROM account_link WHERE device_id = ?1)",
            params![device, to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE account_link SET expires_at = min(expires_at, ?2) WHERE device_id = ?1 AND used_at IS NULL",
            params![device, to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "DELETE FROM tunnel_grant WHERE node_id IN (SELECT id FROM tunnel_node WHERE device_id = ?1)",
            params![device],
        )
        .map_err(db)?;
        tx.execute("DELETE FROM tunnel_node WHERE device_id = ?1", params![device])
            .map_err(db)?;
        enqueue_brain(tx, "revoke", device, now)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_device_revoked",
            None,
            &json!({"device_id": device, "by": caller.device}),
        )?;
        Ok(key_hash(&target.public_key))
    })?;
    hub.accounts.state().drop_device(device, Some(&key));
    crate::server::tunnel_routes::device_revoked(hub, device);
    let removed_from_stores = leave_stores(hub, device, now)?;
    to_value(&AccountRevoked {
        device_id: device.to_string(),
        removed_from_stores,
    })
}

// ---- Vault stores (section 8). ----

/// The view of one vault store.
fn store_view(conn: &Connection, team: &TeamId) -> RelayResult<VaultStoreView> {
    let row = crate::server::directory::team_by_id(conn, team)?
        .filter(|row| row.kind == TeamKind::Account)
        .ok_or_else(|| RelayError::not_found("vault store"))?;
    let owner = row.account_id.clone().unwrap_or_default();
    let mut statement = conn
        .prepare(
            "SELECT store_device, device_id, account_id FROM account_store_device WHERE team_id = ?1 ORDER BY store_device",
        )
        .map_err(db)?;
    let devices = statement
        .query_map(params![team.as_str()], |row| {
            Ok(StoreDevice {
                store_device_id: to_u(row.get(0)?),
                device_id: row.get(1)?,
                account_id: row.get(2)?,
            })
        })
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    Ok(VaultStoreView {
        team_id: team.clone(),
        vault_id: row.vault_id.unwrap_or_default(),
        name: row.name,
        created_at: row.created_at,
        shared: devices.iter().any(|device| device.account_id != owner),
        devices,
    })
}

/// The stores of an account (made by it), by id.
fn owned_stores(conn: &Connection, account: &str) -> RelayResult<Vec<TeamId>> {
    let mut statement = conn
        .prepare("SELECT id FROM team WHERE kind = 'account' AND account_id = ?1 ORDER BY created_at, id")
        .map_err(db)?;
    let ids = statement
        .query_map(params![account], |row| row.get::<_, String>(0))
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    Ok(ids.iter().filter_map(|id| TeamId::parse(id)).collect())
}

/// `POST /v1/account/vaults`: the store of one vault, with the calling device as store
/// device 1. Needs an entitled plan; the same vault id of the account again answers the
/// existing store.
fn vault_create(
    hub: &Hub,
    caller: &AccountCaller,
    request: &VaultStoreCreate,
    now: u64,
) -> RelayResult<Value> {
    if !valid_vault_id(&request.vault_id) {
        return Err(RelayError::invalid(
            "The vault id is a UUID of 36 lowercase characters.",
        ));
    }
    let name = checked_name(&request.name, "vault name")?;
    let plans = hub.accounts.plans();
    if !plans
        .plan(&hub.directory.store, &caller.account, now)?
        .entitled
    {
        return Err(plan_required());
    }
    let people = plans
        .people(&hub.directory.store, &caller.account, now)?
        .max(1);
    let existing = hub.directory.store.with(|conn| {
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM team WHERE kind = 'account' AND account_id = ?1 AND vault_id = ?2",
                params![caller.account, request.vault_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if let Some(id) = existing.as_deref().and_then(TeamId::parse) {
            return Ok(Some(id));
        }
        if to_u(owned_stores(conn, &caller.account)?.len() as i64)
            >= STORES_PER_PERSON.saturating_mul(people)
        {
            return Err(account_limit(&format!(
                "This account has {} vault stores.",
                STORES_PER_PERSON.saturating_mul(people)
            )));
        }
        Ok(None)
    })?;
    let team = match existing {
        Some(team) => team,
        None => hub.create_vault_store(
            &caller.account,
            &caller.device,
            &caller.public_key,
            &request.vault_id,
            &name,
            now,
        )?,
    };
    to_value(&hub.directory.store.with(|conn| store_view(conn, &team))?)
}

/// `GET /v1/account/vaults`: the stores that hold a device of this account, and the stores
/// it made.
fn vault_list(hub: &Hub, caller: &AccountCaller) -> RelayResult<Value> {
    let views = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT id FROM team WHERE kind = 'account' AND (account_id = ?1 OR id IN \
                 (SELECT team_id FROM account_store_device WHERE account_id = ?1)) ORDER BY created_at, id",
            )
            .map_err(db)?;
        let ids = statement
            .query_map(params![caller.account], |row| row.get::<_, String>(0))
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        ids.iter()
            .filter_map(|id| TeamId::parse(id))
            .map(|team| store_view(conn, &team))
            .collect::<RelayResult<Vec<_>>>()
    })?;
    to_value(&views)
}

/// The vault store `team` and whether `caller`'s device is in it. 404 for no team, 403
/// `account_required` for a team that is not a vault store.
fn store_of(
    conn: &Connection,
    caller: &AccountCaller,
    team: &TeamId,
) -> RelayResult<(String, bool)> {
    let row = crate::server::directory::team_by_id(conn, team)?
        .ok_or_else(|| RelayError::not_found("vault store"))?;
    if row.kind != TeamKind::Account {
        return Err(account_required());
    }
    let member: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM account_store_device WHERE team_id = ?1 AND device_id = ?2)",
            params![team.as_str(), caller.device],
            |row| row.get(0),
        )
        .map_err(db)?;
    Ok((row.account_id.unwrap_or_default(), member))
}

/// `POST /v1/account/vaults/{team_id}/devices`, from a device in the store: adds a live
/// device of the caller's account, or of an account that shares a group with it
/// ([`Groups::share_group`]); any other device is 403 `not_in_group`.
fn store_device_add(
    hub: &Hub,
    caller: &AccountCaller,
    team: &TeamId,
    request: &StoreDeviceAdd,
    now: u64,
) -> RelayResult<Value> {
    if !is_connect_id(&request.device_id, "dev_") {
        return Err(RelayError::invalid("The device id is not valid."));
    }
    let (owner, member) = hub
        .directory
        .store
        .with(|conn| store_of(conn, caller, team))?;
    if !member {
        return Err(forbidden(
            "Only a device in the vault store adds a device to it.",
        ));
    }
    let target = hub
        .directory
        .store
        .with(|conn| live_device(conn, &request.device_id))?
        .ok_or_else(|| RelayError::not_found("device"))?;
    if target.account != caller.account
        && !hub.accounts.groups().share_group(
            &hub.directory.store,
            &caller.account,
            &target.account,
            now,
        )?
    {
        return Err(not_in_group());
    }
    if !hub
        .accounts
        .plans()
        .plan(&hub.directory.store, &owner, now)?
        .entitled
    {
        return Err(plan_required());
    }
    let existing = hub.directory.store.with(|conn| {
        let existing: Option<i64> = conn
            .query_row(
                "SELECT store_device FROM account_store_device WHERE team_id = ?1 AND device_id = ?2",
                params![team.as_str(), target.device],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if existing.is_none() {
            let held: i64 = conn
                .query_row(
                    "SELECT count(*) FROM account_store_device WHERE team_id = ?1 AND account_id = ?2",
                    params![team.as_str(), target.account],
                    |row| row.get(0),
                )
                .map_err(db)?;
            if to_u(held) >= STORE_DEVICES_PER_ACCOUNT {
                return Err(account_limit("This account has 10 devices in the vault store."));
            }
        }
        Ok(existing)
    })?;
    let store_device_id = match existing {
        Some(id) => to_u(id),
        None => hub.add_store_device(
            team,
            &target.account,
            &target.device,
            &target.public_key,
            now,
        )?,
    };
    to_value(&StoreDevice {
        store_device_id,
        device_id: target.device,
        account_id: target.account,
    })
}

/// `DELETE /v1/account/vaults/{team_id}`: a device of the account that made the store
/// deletes it with its snapshots.
fn vault_delete(hub: &Hub, caller: &AccountCaller, team: &TeamId, now: u64) -> RelayResult<Value> {
    let (owner, _) = hub
        .directory
        .store
        .with(|conn| store_of(conn, caller, team))?;
    if owner != caller.account {
        return Err(forbidden(
            "Only the account that made the vault store deletes it.",
        ));
    }
    hub.delete_vault_store(team, &actor(&caller.account), now)?;
    to_value(&VaultStoreDeleted {
        team_id: team.clone(),
    })
}

/// Deletes every vault store that `account` made. Returns how many.
fn delete_stores_of(hub: &Hub, account: &str, now: u64) -> RelayResult<u64> {
    let stores = hub
        .directory
        .store
        .with(|conn| owned_stores(conn, account))?;
    for team in &stores {
        hub.delete_vault_store(team, &actor(account), now)?;
    }
    Ok(stores.len() as u64)
}

/// Removes every device of `account` from the stores of other accounts. Returns how many
/// device rows left.
fn leave_other_stores(hub: &Hub, account: &str, now: u64) -> RelayResult<u64> {
    let devices: Vec<String> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare("SELECT DISTINCT device_id FROM account_store_device WHERE account_id = ?1")
            .map_err(db)?;
        let rows = statement
            .query_map(params![account], |row| row.get(0))
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    let mut left = 0;
    for device in devices {
        left += leave_stores(hub, &device, now)?;
    }
    Ok(left)
}

// ---- Recovery (section 9). ----

/// `POST /v1/account/recover` (edge): only an account with no live device, with the
/// recovery code whose hash Connect holds (a constant-time compare). The new device is the
/// first device, every vault store of the account is deleted (a new device set cannot
/// verify the old chains), the code is replaced, the subscription stays. A wrong code and
/// an account with a live device are the same 403. At most `RECOVERY_TRIES_PER_HOUR` tries
/// for each account in an hour (429).
fn recover(hub: &Hub, request: &AccountRecover, now: u64) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_") {
        return Err(forbidden(
            "The recovery code is not valid for this account.",
        ));
    }
    {
        let mut state = hub.accounts.state();
        state.purge(now);
        let tries = state
            .recovery
            .entry(request.account_id.clone())
            .or_insert((now, 0));
        if tries.1 >= RECOVERY_TRIES_PER_HOUR {
            return Err(RelayError::new(
                codes::RATE_LIMITED,
                "Too many recovery tries for this account. Try again in an hour.",
            ));
        }
        tries.1 += 1;
    }
    let name = checked_name(&request.device_name, "device name")?;
    let public_key = public_key_of(&request.public_key)?;
    if !is_hex(&request.recovery_hash, 64) {
        return Err(RelayError::invalid(
            "The recovery hash is 64 lowercase hex characters.",
        ));
    }
    let signature = signature_of(&request.signature)?;
    let message = device::account_recover_message(
        &hub.config.public_url,
        &request.account_id,
        &request.public_key,
    );
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of the key over the recover message of this Connect.",
        ));
    }
    let wrong = || forbidden("The recovery code is not valid for this account.");
    let code = parse_recovery_code(request.recovery.expose()).ok_or_else(wrong)?;
    let presented = device::account_recovery_hash(code.as_slice());
    let allowed = hub.directory.store.with(|conn| {
        let stored: Option<String> = conn
            .query_row(
                "SELECT recovery_hash FROM account WHERE id = ?1",
                params![request.account_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        // Compared in constant time; an unknown account compares against nothing.
        let matches = stored
            .as_deref()
            .is_some_and(|stored| same_bytes(stored.as_bytes(), presented.as_bytes()));
        Ok(matches && live_devices(conn, &request.account_id)? == 0)
    })?;
    if !allowed {
        return Err(wrong());
    }
    if hub
        .directory
        .store
        .with(|conn| key_used(conn, &key_hash(&public_key)))?
    {
        return Err(conflict(
            "This key is or was a device of an account. Make a new key.",
        ));
    }
    let deleted_stores = delete_stores_of(hub, &request.account_id, now)?;
    let device = hub.directory.store.tx(|tx| {
        // Again under the lock: another recovery may have won the race.
        if live_devices(tx, &request.account_id)? != 0 {
            return Err(wrong());
        }
        tx.execute(
            "UPDATE account SET recovery_hash = ?2 WHERE id = ?1",
            params![request.account_id, request.recovery_hash],
        )
        .map_err(db)?;
        let device = insert_device(tx, &request.account_id, &name, request.platform, &public_key, now)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&request.account_id),
            "account_recovered",
            None,
            &json!({"account_id": request.account_id, "device_id": device, "deleted_stores": deleted_stores}),
        )?;
        Ok(device)
    })?;
    to_value(&AccountRecovered {
        account_id: request.account_id.clone(),
        device_id: device,
        deleted_stores,
    })
}

// ---- The entitlement token (section 10). ----

/// `GET /v1/account/entitlement`: a token of 24 hours for an entitled account, else 403
/// `plan_required`. Without a signing key: 503 `busy`.
fn entitlement(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let plan = hub
        .accounts
        .plans()
        .plan(&hub.directory.store, &caller.account, now)?;
    let plan_name = plan
        .plan
        .as_deref()
        .filter(|name| matches!(*name, "personal" | "family" | "team"));
    let (true, Some(plan_name)) = (plan.entitled, plan_name) else {
        return Err(plan_required());
    };
    let signer = hub
        .accounts
        .signer()
        .ok_or_else(|| busy("This Connect has no signing key for entitlement tokens."))?;
    let claims = Claims::new(
        signer.kid(),
        &caller.account,
        plan_name,
        plan.group_id.as_deref(),
        now,
    );
    let token = Entitlement::sign(signer, &claims)?;
    hub.directory.store.with(|conn| {
        conn.execute(
            "UPDATE entitlement_key SET last_signed_at = ?2 WHERE kid = ?1",
            params![signer.kid(), to_i(now)],
        )
        .map_err(db)
    })?;
    to_value(&EntitlementAnswer {
        token,
        expires_at: claims.exp,
    })
}

/// Records the signing key in `entitlement_key` (kid and public key only) at start, so the
/// well-known document keeps an old key for 24 hours after its last token.
pub fn record_signing_key(hub: &Hub, now: u64) -> RelayResult<()> {
    let Some(signer) = hub.accounts.signer() else {
        return Ok(());
    };
    hub.directory.store.with(|conn| {
        conn.execute(
            "INSERT INTO entitlement_key (kid, public_key, created_at) VALUES (?1, ?2, ?3) ON CONFLICT(kid) DO NOTHING",
            params![signer.kid(), signer.public_key().as_slice(), to_i(now)],
        )
        .map_err(db)
        .map(drop)
    })
}

/// The keys that verify tokens now: the signing key, and each older key that signed a
/// token in the last 24 hours.
pub fn published_keys(hub: &Hub, now: u64) -> RelayResult<Vec<PublishedKey>> {
    let mut keys: Vec<PublishedKey> = hub
        .accounts
        .signer()
        .map(EntitlementSigner::published)
        .into_iter()
        .collect();
    let older: Vec<(String, Vec<u8>)> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare("SELECT kid, public_key FROM entitlement_key WHERE last_signed_at > ?1 ORDER BY kid")
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![to_i(now.saturating_sub(crate::server::entitlement::LIFETIME_SECS))],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    for (kid, public_key) in older {
        if keys.iter().any(|key| key.kid == kid) {
            continue;
        }
        if let Ok(public_key) = <[u8; 32]>::try_from(public_key.as_slice()) {
            keys.push(PublishedKey { kid, public_key });
        }
    }
    Ok(keys)
}

/// `GET /.well-known/apassy-connect.json` (edge).
fn well_known(hub: &Hub, now: u64) -> RelayResult<Value> {
    let keys = published_keys(hub, now)?
        .into_iter()
        .map(|key| WellKnownKey {
            kid: key.kid,
            alg: "Ed25519".to_string(),
            public_key: encode_b64(&key.public_key),
        })
        .collect();
    to_value(&WellKnown {
        v: 1,
        origin: hub.config.public_url.clone(),
        keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_and_methods() {
        assert_eq!(
            route("POST", "/v1/account").unwrap(),
            (Need::Edge, AccountEndpoint::Create)
        );
        assert_eq!(
            route("GET", "/v1/account").unwrap(),
            (Need::Account, AccountEndpoint::View)
        );
        assert_eq!(
            route("POST", "/v1/account/devices/pending/4/confirm").unwrap(),
            (Need::Account, AccountEndpoint::Confirm(4))
        );
        assert_eq!(
            route("DELETE", "/v1/account/devices/dev_p4n6r2t7bc")
                .unwrap()
                .1,
            AccountEndpoint::Revoke("dev_p4n6r2t7bc".into())
        );
        assert_eq!(
            route("DELETE", "/v1/account/devices/join")
                .unwrap_err()
                .code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("DELETE", "/v1/account/devices/dev_X")
                .unwrap_err()
                .code,
            codes::NOT_FOUND
        );
        assert_eq!(
            route("PUT", "/v1/account").unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("GET", "/v1/account/nope").unwrap_err().code,
            codes::NOT_FOUND
        );
        assert_eq!(route("GET", WELL_KNOWN_PATH).unwrap().0, Need::Edge);
        assert!(is_account_path("/v1/account/vaults"));
        assert!(!is_account_path("/v1/accounts"));
    }

    #[test]
    fn values_have_their_forms() {
        assert!(valid_vault_id("0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77"));
        assert!(!valid_vault_id("0F3C2A10-5B7E-4D9A-8C21-6F0E4B1D9A77"));
        assert!(valid_link_hash(
            "K6tgKp_oqj7XbiWqWmDhJq-DIThtvhqbEWY8teg5JbY"
        ));
        assert!(!valid_link_hash(
            "K6tgKp_oqj7XbiWqWmDhJq-DIThtvhqbEWY8teg5Jb"
        ));
        assert!(is_connect_id(&new_id("acc_").unwrap(), "acc_"));
        assert_eq!(hour(7201), 7200);
        assert!(checked_name("  ", "name").is_err());
        assert_eq!(checked_name(" Rafal ", "name").unwrap(), "Rafal");
    }
}
