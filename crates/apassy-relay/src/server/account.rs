//! Apassy Connect accounts (ADR 0037 stage 7, contract connect-account-v1, docs/SPEC.md
//! section 33).
//!
//! An account is one person: a name, a recovery key, and its devices. Each device is one
//! P-256 key made on the device; Connect holds the public key only. There is no password
//! and no email sign-in: **no account sign-in adds a device**. A new device joins only by a
//! one-use link that a live device of the account made (`POST /v1/account/devices/link`,
//! only the hash of the code reaches Connect) and the confirmation of that device after the
//! person compared six safety words, which Connect cannot compute (it never sees the code).
//! The confirmation carries an entry of the account's **signed device list**: the
//! confirming device signs the next version of the list, which names the hash of the entry
//! before and the key it adds; a revoke is such an entry too, signed by the revoking
//! device. The list starts at the account's root key (version 1: the first device, or the
//! device of the last recovery) and goes with every account answer and the join answer, so
//! the devices check the list themselves and need not trust Connect for it.
//!
//! Sign-in is a challenge (`POST /v1/account/challenge`, a nonce of 60 seconds that Connect
//! does not store: random bytes, the expiry, and an HMAC under a key of this process over
//! the account and the key) and a signature over the domain `apassy-connect sign-in v1`
//! (`POST /v1/account/token`). A challenge never ends another one; a nonce is used up only
//! by the sign-in that it grants. The account token (`apassy_act_…`) lives 15 minutes in
//! memory, never on disk. Each request reads the device again in `relay.db`, so a revoked
//! device loses its token at once; the revoke drops its tokens from memory too. A device
//! that was removed learns it only from its own signed sign-in (403 `device_removed`).
//!
//! The recovery code stays with the person: Connect holds the Ed25519 public key derived
//! from it (`device::RecoveryKey`), and a recovery is signed with that key.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use ring::hmac;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{
    AccountChallengeRequest, AccountConfirm, AccountConfirmer, AccountCreate, AccountCreated,
    AccountDeleted, AccountDevice, AccountGroup, AccountJoin, AccountJoinCancel, AccountJoinId,
    AccountJoined, AccountLinkCreated, AccountLinkRequest, AccountPendingJoin, AccountRecover,
    AccountRecovered, AccountRevoke, AccountRevoked, AccountTokenRef, AccountTokenRequest,
    AccountView, EmptyRequest, EntitlementAnswer, ListEntry, ListOp, PlanView, Platform,
    StoreDevice, StoreDeviceAdd, TeamKind, VaultStoreCreate, VaultStoreDeleted, VaultStoreView,
    WellKnown, WellKnownKey,
};
use crate::device;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::TeamId;
use crate::secret::{
    TokenHash, is_connect_id, new_account_token, parse_account_token, same_bytes, token_hash,
};
use crate::server::auth::Need;
use crate::server::connect::{PrefixLimiter, UNKNOWN_PREFIX, checked_prefix};
use crate::server::entitlement::{
    Claims, Entitlement, EntitlementSigner, PUBLISH_LEAD_SECS, PublishedKey,
};
use crate::server::hub::Hub;
use crate::server::store::{Store, db, to_i, to_u};

/// The life of an account token: 15 minutes.
pub const TOKEN_SECS: u64 = 900;
/// The life of a sign-in nonce: 60 seconds.
pub const NONCE_SECS: u64 = 60;
/// The domain of the MAC of a sign-in nonce (relay-internal).
const NONCE_DOMAIN: &str = "apassy-connect nonce v1";
/// Nonces that granted a sign-in, kept until they expire, at most; over it a sign-in is
/// 503 `busy` and its nonce stays unused.
pub const MAX_USED_NONCES: usize = 100_000;
/// Used nonces of one key at most (a sign-in each 2 s for the 60 s of a nonce); over it a
/// sign-in of that key is 429 `rate_limited` and its nonce stays unused.
pub const USED_NONCES_PER_KEY: usize = 30;
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
/// Failed recovery signatures of one account in one hour at most (`429 rate_limited`).
pub const RECOVERY_TRIES_PER_HOUR: u32 = 5;
/// Failed recovery signatures of one client prefix in one hour at most (`429`).
pub const RECOVERY_PREFIX_TRIES_PER_HOUR: u32 = 20;
/// Accounts and prefixes with counted recovery failures at once, each; a new one beyond
/// it is 503 `busy` until the hour of the oldest ends.
pub const MAX_RECOVERY_ENTRIES: usize = 10_000;
/// A repeat of `POST /v1/account` with the same body within this time answers the same
/// result (a retry after a lost answer).
pub const CREATE_RETRY_SECS: u64 = 600;
/// A repeat of `POST /v1/account/recover` with the same body within this time, while the
/// device it made is live, answers the same result.
pub const RECOVER_RETRY_SECS: u64 = 600;
/// The longest signed device list of an account: a change past it is 403 `account_limit`
/// (a recovery starts a new list).
pub const MAX_LIST_ENTRIES: u64 = 256;
/// The versions kept for removals at the end of a list: the live-device limit, at least
/// 10. An `add` past `LAST_ADD_VERSION` is 403 `account_limit`, so every live device of a
/// list can still be removed (also the last one by itself) before `MAX_LIST_ENTRIES`, and
/// the account can then be recovered.
pub const LIST_REMOVAL_RESERVE: u64 = if MAX_DEVICES > 10 { MAX_DEVICES } else { 10 };
/// The last version of a device list that may be an `add` (246).
pub const LAST_ADD_VERSION: u64 = MAX_LIST_ENTRIES - LIST_REMOVAL_RESERVE;
/// Links (with their joins) are kept this long after they expire.
pub const LINK_KEEP_SECS: u64 = 86_400;
/// The relay audit rows of accounts are kept this long.
pub const ACCOUNT_AUDIT_RETENTION_SECS: u64 = 90 * 86_400;
/// How often the pruning part of the account maintenance runs at most.
pub const MAINTENANCE_SECS: u64 = 3600;
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
    // connect-billing-v1 (docs/SPEC.md section 34).
    Plan,
    Checkout,
    Portal,
    /// `/v1/account/group/…` (connect-billing-v1 section 6, `server::group`).
    Group(crate::server::group::GroupEndpoint),
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
        ["v1", "account", "plan"] => pick(vec![("GET", Need::Account, Plan)]),
        ["v1", "account", "checkout"] => pick(vec![("POST", Need::Account, Checkout)]),
        ["v1", "account", "portal"] => pick(vec![("POST", Need::Account, Portal)]),
        ["v1", "account", "group", rest @ ..] => {
            let (need, endpoint) = crate::server::group::route(method, rest)?;
            Ok((need, Group(endpoint)))
        }
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

/// 403 `account_required`: a route of Connect that needs an account token, called with a
/// relay-sync team token (a token of a revoked device is 401 `unauthenticated`).
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

struct Token {
    account: String,
    device: String,
    expires_at: u64,
}

/// The caps of the sign-in tables (`MAX_TOKENS`, `MAX_USED_NONCES`,
/// `USED_NONCES_PER_KEY`); a unit test lowers them.
#[derive(Debug, Clone, Copy)]
struct Caps {
    tokens: usize,
    used_nonces: usize,
    used_per_key: usize,
}

const CAPS: Caps = Caps {
    tokens: MAX_TOKENS,
    used_nonces: MAX_USED_NONCES,
    used_per_key: USED_NONCES_PER_KEY,
};

/// The clock of the sign-in nonces: Unix seconds that follow the wall clock forward and
/// never go back. A nonce carries its expiry on this clock, and a used nonce stays in the
/// table until this clock passes it, so a wall clock that is set back never makes a used
/// nonce valid again.
#[derive(Default)]
struct NonceClock {
    /// The last wall time seen, and this clock at that moment.
    last_wall: u64,
    now: u64,
}

impl NonceClock {
    /// This clock at the wall time `wall`: the steps forward of the wall clock count,
    /// its steps back do not.
    fn tick(&mut self, wall: u64) -> u64 {
        if self.now == 0 {
            self.now = wall;
        } else if wall > self.last_wall {
            self.now = self.now.saturating_add(wall - self.last_wall);
        }
        self.last_wall = wall;
        self.now
    }
}

/// A nonce that granted a sign-in: its expiry on the nonce clock and the key it was for.
#[derive(Debug, Clone, Copy)]
struct UsedNonce {
    expires_at: u64,
    key: [u8; 32],
}

#[derive(Default)]
struct AuthState {
    tokens: HashMap<TokenHash, Token>,
    token_order: VecDeque<TokenHash>,
    /// The nonces that granted a sign-in, until they expire on the nonce clock: each grants
    /// one.
    used: HashMap<[u8; device::NONCE_BYTES], UsedNonce>,
    /// How many of `used` each key holds (`USED_NONCES_PER_KEY`).
    used_by_key: HashMap<[u8; 32], usize>,
    clock: NonceClock,
}

impl AuthState {
    /// Drops the tokens expired at the wall time `now` and the used nonces expired on the
    /// nonce clock `clock`.
    fn purge(&mut self, now: u64, clock: u64) {
        self.tokens.retain(|_, token| token.expires_at > now);
        let by_key = &mut self.used_by_key;
        self.used.retain(|_, used| {
            let keep = used.expires_at > clock;
            if !keep && let Some(count) = by_key.get_mut(&used.key) {
                *count = count.saturating_sub(1);
            }
            keep
        });
        self.used_by_key.retain(|_, count| *count > 0);
        let tokens = &self.tokens;
        self.token_order.retain(|hash| tokens.contains_key(hash));
    }

    /// The last step of a sign-in, under the lock: a used nonce is 401; a key that used
    /// `USED_NONCES_PER_KEY` nonces of the last minute is 429 `rate_limited` for that key
    /// only; a full table is 503 `busy`; both leave the nonce unused. Else the nonce is
    /// used (until it expires) and the token is kept. The device's oldest token goes when
    /// it holds `TOKENS_PER_DEVICE`. `nonce` is the nonce, its expiry on the nonce clock,
    /// and the SHA-256 of its key; `clock` is the nonce clock now.
    fn grant(
        &mut self,
        nonce: ([u8; device::NONCE_BYTES], u64, [u8; 32]),
        hash: TokenHash,
        token: Token,
        (now, clock): (u64, u64),
        caps: Caps,
    ) -> RelayResult<()> {
        self.purge(now, clock);
        if self.used.contains_key(&nonce.0) {
            return Err(RelayError::unauthenticated());
        }
        if self.used_by_key.get(&nonce.2).copied().unwrap_or(0) >= caps.used_per_key {
            return Err(RelayError::new(
                codes::RATE_LIMITED,
                "This device signed in too often. Try again in a minute.",
            ));
        }
        let held = self
            .tokens
            .values()
            .filter(|entry| entry.device == token.device)
            .count();
        let at_device_cap = held >= TOKENS_PER_DEVICE;
        if (!at_device_cap && self.tokens.len() >= caps.tokens)
            || self.used.len() >= caps.used_nonces
        {
            return Err(busy("The relay holds too many sign-ins. Try again later."));
        }
        if at_device_cap
            && let Some(oldest) = self
                .token_order
                .iter()
                .find(|hash| {
                    self.tokens
                        .get(*hash)
                        .is_some_and(|entry| entry.device == token.device)
                })
                .copied()
        {
            self.tokens.remove(&oldest);
            self.token_order.retain(|hash| *hash != oldest);
        }
        self.used.insert(
            nonce.0,
            UsedNonce {
                expires_at: nonce.1,
                key: nonce.2,
            },
        );
        *self.used_by_key.entry(nonce.2).or_insert(0) += 1;
        self.token_order.push_back(hash);
        self.tokens.insert(hash, token);
        Ok(())
    }

    /// Drops every token of `device`.
    fn drop_device(&mut self, device: &str) {
        self.tokens.retain(|_, token| token.device != device);
        let tokens = &self.tokens;
        self.token_order.retain(|hash| tokens.contains_key(hash));
    }

    /// Drops every token of `account`.
    fn drop_account(&mut self, account: &str) {
        self.tokens.retain(|_, token| token.account != account);
        let tokens = &self.tokens;
        self.token_order.retain(|hash| tokens.contains_key(hash));
    }
}

/// The failed recovery signatures of the last hour, in memory only, apart from the
/// sign-in state: of each account, and of each proven client prefix (by its HMAC under a
/// salt of this process, never as text).
#[derive(Default)]
struct RecoveryState {
    accounts: HashMap<String, (u64, u32)>,
    prefixes: HashMap<[u8; 32], (u64, u32)>,
}

impl RecoveryState {
    fn purge(&mut self, now: u64) {
        self.accounts
            .retain(|_, (start, _)| now < start.saturating_add(3600));
        self.prefixes
            .retain(|_, (start, _)| now < start.saturating_add(3600));
    }

    /// Counts one failed recovery signature of an existing account. Only a failure is
    /// ever counted or limited: a valid recovery signature never comes here. 429
    /// `rate_limited` when the account or the source already failed too often this hour
    /// (nothing more is counted); a new entry in a full table is 503 `busy`, and nothing is
    /// counted. Else the failure counts, and the answer stays the caller's 403.
    fn fail(&mut self, account: &str, prefix: &[u8; 32], now: u64, cap: usize) -> RelayResult<()> {
        self.purge(now);
        let account_tries = self.accounts.get(account).map_or(0, |(_, count)| *count);
        let prefix_tries = self.prefixes.get(prefix).map_or(0, |(_, count)| *count);
        if account_tries >= RECOVERY_TRIES_PER_HOUR
            || prefix_tries >= RECOVERY_PREFIX_TRIES_PER_HOUR
        {
            return Err(RelayError::new(
                codes::RATE_LIMITED,
                "Too many recovery tries for this account. Try again in an hour.",
            ));
        }
        if (!self.accounts.contains_key(account) && self.accounts.len() >= cap)
            || (!self.prefixes.contains_key(prefix) && self.prefixes.len() >= cap)
        {
            return Err(busy(
                "Connect holds too many recovery tries. Try again later.",
            ));
        }
        self.accounts
            .entry(account.to_string())
            .or_insert((now, 0))
            .1 += 1;
        self.prefixes.entry(*prefix).or_insert((now, 0)).1 += 1;
        Ok(())
    }
}

/// The account state of a relay: the sign-in state in memory, the recovery tries, the
/// keys of this process (nonce MAC and prefix salt), the seams of billing and groups, and
/// the entitlement signer. One for each `Hub`.
pub struct Accounts {
    state: Mutex<AuthState>,
    recovery: Mutex<RecoveryState>,
    /// The MAC key of the sign-in nonces: 32 random bytes, made at start.
    nonce_key: hmac::Key,
    /// The salt of the client prefixes of the recovery tries.
    prefix_salt: hmac::Key,
    /// The new accounts of each client prefix today.
    prefixes: PrefixLimiter,
    plans: RwLock<Arc<dyn Plans>>,
    groups: RwLock<Arc<dyn Groups>>,
    signer: Option<EntitlementSigner>,
    /// The time of the last pruning pass (`maintain`).
    pruned_at: AtomicU64,
}

fn random_key() -> RelayResult<hmac::Key> {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|_| random_source())?;
    Ok(hmac::Key::new(hmac::HMAC_SHA256, bytes.as_slice()))
}

impl Accounts {
    /// The state of a relay with the signing key of its configuration (none: no token).
    pub fn new(signer: Option<EntitlementSigner>) -> RelayResult<Self> {
        Ok(Self {
            state: Mutex::new(AuthState::default()),
            recovery: Mutex::new(RecoveryState::default()),
            nonce_key: random_key()?,
            prefix_salt: random_key()?,
            prefixes: PrefixLimiter::default(),
            plans: RwLock::new(Arc::new(NoPlans)),
            groups: RwLock::new(Arc::new(NoGroups)),
            signer,
            pruned_at: AtomicU64::new(0),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, AuthState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn recovery(&self) -> std::sync::MutexGuard<'_, RecoveryState> {
        self.recovery.lock().unwrap_or_else(PoisonError::into_inner)
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
        let clock = state.clock.tick(now);
        state.purge(now, clock);
        state.tokens.len()
    }

    /// The nonce clock at the wall time `now` ([`NonceClock`]).
    fn nonce_clock(&self, now: u64) -> u64 {
        self.state().clock.tick(now)
    }

    /// The 16-byte MAC of a nonce: HMAC-SHA256 under the nonce key of
    /// `"apassy-connect nonce v1" 0x00 account 0x00 SHA-256(key) 0x00 random ‖ expiry`.
    fn nonce_mac(&self, account: &str, key: &[u8; 32], head: &[u8]) -> [u8; 16] {
        let mut context = hmac::Context::with_key(&self.nonce_key);
        for (index, part) in [
            NONCE_DOMAIN.as_bytes(),
            account.as_bytes(),
            key.as_slice(),
            head,
        ]
        .iter()
        .enumerate()
        {
            if index > 0 {
                context.update(&[0]);
            }
            context.update(part);
        }
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&context.sign().as_ref()[..16]);
        mac
    }

    /// A new nonce for the key `key` (its SHA-256) of `account`, valid until
    /// `expires_at` on the nonce clock: 12 random bytes, the expiry as a big-endian u32,
    /// and the MAC. Nothing is kept.
    fn new_nonce(&self, account: &str, key: &[u8; 32], expires_at: u64) -> RelayResult<String> {
        let expiry = u32::try_from(expires_at)
            .map_err(|_| RelayError::internal("The clock is past the nonce format."))?;
        let mut nonce = [0u8; device::NONCE_BYTES];
        getrandom::fill(&mut nonce[..12]).map_err(|_| random_source())?;
        nonce[12..16].copy_from_slice(&expiry.to_be_bytes());
        let mac = self.nonce_mac(account, key, &nonce[..16]);
        nonce[16..].copy_from_slice(&mac);
        Ok(encode_b64(&nonce))
    }

    /// The bytes and the expiry of a nonce of this process for `account` and `key`, not
    /// expired at `now` on the nonce clock; `None` for anything else.
    fn check_nonce(
        &self,
        text: &str,
        account: &str,
        key: &[u8; 32],
        now: u64,
    ) -> Option<([u8; device::NONCE_BYTES], u64)> {
        let bytes: [u8; device::NONCE_BYTES] = decode_b64(text, device::NONCE_BYTES)
            .ok()?
            .try_into()
            .ok()?;
        let mac = self.nonce_mac(account, key, &bytes[..16]);
        if !same_bytes(&mac, &bytes[16..]) {
            return None;
        }
        let expires_at = u64::from(u32::from_be_bytes(bytes[12..16].try_into().ok()?));
        (expires_at > now && expires_at <= now.saturating_add(NONCE_SECS))
            .then_some((bytes, expires_at))
    }

    /// The salted hash of a client prefix for the recovery tries.
    fn prefix_tag(&self, prefix: &str) -> [u8; 32] {
        let mut tag = [0u8; 32];
        tag.copy_from_slice(
            hmac::sign(&self.prefix_salt, checked_prefix(prefix).as_bytes()).as_ref(),
        );
        tag
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

/// An edge endpoint: no `Authorization`. `prefix` is the client prefix that the Worker
/// proved (`connect::verified_prefix`, only for `POST /v1/account` and
/// `POST /v1/account/recover`), else `None`. A new account counts only for a proven
/// prefix (the Worker proves every call it forwards); a recovery without one counts as
/// `UNKNOWN_PREFIX`.
pub fn dispatch_edge(
    hub: &Hub,
    endpoint: &AccountEndpoint,
    body: &[u8],
    prefix: Option<&str>,
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        AccountEndpoint::Create => create(hub, &strict(body)?, prefix, now),
        AccountEndpoint::Challenge => challenge(hub, &strict(body)?, now),
        AccountEndpoint::Token => token(hub, &strict(body)?, now),
        AccountEndpoint::Join => join(hub, &strict(body)?, now),
        AccountEndpoint::JoinCancel => join_cancel(hub, &strict(body)?, now),
        AccountEndpoint::Recover => {
            recover(hub, &strict(body)?, prefix.unwrap_or(UNKNOWN_PREFIX), now)
        }
        AccountEndpoint::WellKnown => well_known(hub),
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
        AccountEndpoint::Revoke(device) => revoke(hub, caller, device, &strict(body)?, now),
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
        AccountEndpoint::Plan => to_value(&hub.accounts.plans().plan(
            &hub.directory.store,
            &caller.account,
            now,
        )?),
        AccountEndpoint::Checkout => {
            to_value(&billing(hub)?.checkout(&caller.account, body, now)?)
        }
        AccountEndpoint::Portal => to_value(&billing(hub)?.portal(&caller.account, body)?),
        AccountEndpoint::Group(endpoint) => {
            crate::server::group::dispatch(hub, caller, endpoint, body, now)
        }
        _ => Err(RelayError::internal("Not an account endpoint.")),
    }
}

/// The billing of this relay, or 503 `busy` when Stripe is not set up
/// (`STRIPE_SECRET_KEY_FILE`, `STRIPE_WEBHOOK_SECRET_FILE`).
pub(crate) fn billing(hub: &Hub) -> RelayResult<&crate::server::billing_store::ConnectBilling> {
    hub.billing
        .as_deref()
        .ok_or_else(|| busy("Billing is not set up on this relay."))
}

// ---- Account and sign-in (section 6). ----

/// The view of one device (live or not).
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

// ---- The signed device list (section 7.5). ----

/// The head of the device list of `account`: its version and list hash.
fn list_head(conn: &Connection, account: &str) -> RelayResult<(u64, String)> {
    conn.query_row(
        "SELECT version, hash FROM account_list WHERE account_id = ?1 ORDER BY version DESC LIMIT 1",
        params![account],
        |row| Ok((to_u(row.get(0)?), row.get(1)?)),
    )
    .optional()
    .map_err(db)?
    .ok_or_else(|| RelayError::internal("An account has no device list."))
}

/// The device list of `account`, from version 1.
fn list_entries(conn: &Connection, account: &str) -> RelayResult<Vec<ListEntry>> {
    let mut statement = conn
        .prepare(
            "SELECT version, op, key, link_hash, name, by_key, signature FROM account_list \
             WHERE account_id = ?1 ORDER BY version",
        )
        .map_err(db)?;
    let rows = statement
        .query_map(params![account], |row| {
            let op: String = row.get(1)?;
            let key: Vec<u8> = row.get(2)?;
            let by: Vec<u8> = row.get(5)?;
            let signature: Vec<u8> = row.get(6)?;
            Ok(ListEntry {
                version: to_u(row.get(0)?),
                op: ListOp::parse(&op).ok_or(rusqlite::Error::InvalidQuery)?,
                key: encode_b64(&key),
                link_hash: row.get(3)?,
                name: row.get(4)?,
                by: encode_b64(&by),
                signature: Some(encode_b64(&signature)),
            })
        })
        .map_err(db)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(db)
}

/// One new entry of a device list, before it is written: `name` is the device name of a
/// `root` or an `add` (`None` for a `remove`), `signature` the signature of `by` over its
/// message.
struct ListChange<'a> {
    op: ListOp,
    key: &'a [u8],
    link_hash: Option<&'a str>,
    name: Option<&'a str>,
    by: &'a [u8],
    signature: &'a [u8],
}

/// The `apassy-connect device-list v1` message of `change` as version `version` of the
/// list of `account`, after the entry whose hash is `previous` (`None` for version 1).
fn list_message(
    origin: &str,
    account: &str,
    version: u64,
    previous: Option<&str>,
    change: &ListChange<'_>,
) -> Vec<u8> {
    device::account_list_message(
        origin,
        account,
        version,
        previous.unwrap_or(device::LIST_NONE),
        change.op.as_str(),
        &encode_b64(change.key),
        change.link_hash.unwrap_or(device::LIST_NONE),
        change.name.unwrap_or(device::LIST_NONE),
        &encode_b64(change.by),
    )
}

/// The root entry (version 1) of a new list of `account` for the key `root` and its
/// device name, signed by that key (`statement`): 400 when the statement is not its
/// signature over the root message of this origin.
fn root_change<'a>(
    origin: &str,
    account: &str,
    root: &'a [u8],
    name: &'a str,
    statement: &'a [u8],
) -> RelayResult<ListChange<'a>> {
    let change = ListChange {
        op: ListOp::Root,
        key: root,
        link_hash: None,
        name: Some(name),
        by: root,
        signature: statement,
    };
    if !device::verify(root, &list_message(origin, account, 1, None, &change), statement) {
        return Err(RelayError::invalid(
            "The statement is not the signature of the key over the root entry of the device list. Nothing was made.",
        ));
    }
    Ok(change)
}

/// Writes `change` as version `version` of the list of `account`, after the entry whose
/// hash is `previous` (`None` for version 1), and answers its hash.
fn write_list_entry(
    conn: &Connection,
    origin: &str,
    account: &str,
    version: u64,
    previous: Option<&str>,
    change: &ListChange<'_>,
    now: u64,
) -> RelayResult<String> {
    let message = list_message(origin, account, version, previous, change);
    let hash = device::account_list_hash(&message);
    conn.execute(
        "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            account,
            to_i(version),
            change.op.as_str(),
            change.key,
            change.link_hash,
            change.name,
            change.by,
            change.signature,
            hash,
            to_i(now)
        ],
    )
    .map_err(db)?;
    Ok(hash)
}

/// A new device list of `account` with the checked root entry `root` (`root_change`) as
/// its version 1: at the account's creation and at a recovery, which drops the list
/// before.
fn start_list(
    conn: &Connection,
    origin: &str,
    account: &str,
    root: &ListChange<'_>,
    now: u64,
) -> RelayResult<()> {
    conn.execute(
        "DELETE FROM account_list WHERE account_id = ?1",
        params![account],
    )
    .map_err(db)?;
    write_list_entry(conn, origin, account, 1, None, root, now).map(drop)
}

/// Appends a signed change of `caller` to the device list of its account, inside the
/// transaction of the change: `version` must be the head's version and 1 (409 `conflict`
/// otherwise: the list moved, and the device signs again from the new head), the list must
/// have room (`MAX_LIST_ENTRIES` for any change, `LAST_ADD_VERSION` for an `add`: 403
/// `account_limit`), and the change's signature must be the caller's over the entry's
/// message with the head's hash (400 otherwise). Nothing is written on a refusal.
fn append_signed(
    conn: &Connection,
    origin: &str,
    caller: &AccountCaller,
    version: u64,
    change: &ListChange<'_>,
    now: u64,
) -> RelayResult<()> {
    let (head, previous) = list_head(conn, &caller.account)?;
    if version != head.saturating_add(1) {
        return Err(conflict(
            "The device list changed. Read the account again and sign the new version.",
        ));
    }
    if version > MAX_LIST_ENTRIES {
        return Err(account_limit(
            "This account changed its devices too often. Recover the account to start a new device list.",
        ));
    }
    // The list stays a list that every device verifies: the signer is a device of it, an
    // `add` names a key that was never in it, and a `remove` a key that is in it now.
    let last_op = |key: &[u8]| -> RelayResult<Option<String>> {
        conn.query_row(
            "SELECT op FROM account_list WHERE account_id = ?1 AND key = ?2 ORDER BY version DESC LIMIT 1",
            params![caller.account, key],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)
    };
    if last_op(change.by)?.is_none_or(|op| op == ListOp::Remove.as_str()) {
        return Err(RelayError::unauthenticated());
    }
    match (change.op, last_op(change.key)?) {
        (ListOp::Add, None) => {}
        (ListOp::Add, Some(_)) => {
            return Err(conflict(
                "This key is or was a device of an account. Make a new key.",
            ));
        }
        (ListOp::Remove, Some(op)) if op != ListOp::Remove.as_str() => {}
        _ => return Err(RelayError::not_found("device")),
    }
    let message = list_message(origin, &caller.account, version, Some(&previous), change);
    if change.by != caller.public_key.as_slice()
        || !device::verify(&caller.public_key, &message, change.signature)
    {
        return Err(RelayError::invalid(
            "The statement is not the signature of this device over the next entry of the device list. Nothing changed.",
        ));
    }
    write_list_entry(
        conn,
        origin,
        &caller.account,
        version,
        Some(&previous),
        change,
        now,
    )
    .map(drop)
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

/// True when `key` (its SHA-256) is or was a device of `account`: `account_key` keeps the
/// account after a revoke and after the account's deletion.
fn key_of_account(conn: &Connection, key: &[u8; 32], account: &str) -> RelayResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_key WHERE key_hash = ?1 AND account_id = ?2)",
        params![key.as_slice(), account],
        |row| row.get(0),
    )
    .map_err(db)
}

/// A new device row and its key in `account_key`, inside a transaction. `added_by` is the
/// confirming device, `None` for a root (the first device, or the device of a recovery).
/// The device list gets its entry from the caller.
fn insert_device(
    conn: &Connection,
    account: &str,
    name: &str,
    platform: Platform,
    public_key: &[u8],
    added_by: Option<&str>,
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
        "INSERT INTO account_device (id, account_id, name, platform, public_key, created_at, added_by) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, account, name, platform.as_str(), public_key, to_i(now), added_by],
    )
    .map_err(db)?;
    conn.execute(
        "INSERT INTO account_key (key_hash, account_id, created_at) VALUES (?1, ?2, ?3)",
        params![key_hash(public_key).as_slice(), account, to_i(now)],
    )
    .map_err(db)?;
    Ok(id)
}

/// 503 `busy` of `POST /v1/account` over the relay's caps.
fn accounts_full() -> RelayError {
    busy("Apassy Connect makes no new accounts now. Try again later.")
}

/// The caps of new accounts (`APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY`, `_MAX`): 503 `busy`
/// over either.
fn check_account_room(conn: &Connection, hub: &Hub, now: u64) -> RelayResult<()> {
    let settings = &hub.config.connect;
    if settings.accounts_per_day == 0 || settings.accounts_max == 0 {
        return Err(accounts_full());
    }
    let (today, held): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM account WHERE created_at > ?1), (SELECT count(*) FROM account)",
            params![to_i(now.saturating_sub(86_400))],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db)?;
    if to_u(today) >= settings.accounts_per_day || to_u(held) >= settings.accounts_max {
        return Err(accounts_full());
    }
    Ok(())
}

/// The answer of an earlier `POST /v1/account` of the same body and key within
/// `CREATE_RETRY_SECS`; `None` when the key was never used; 409 when it was used otherwise.
fn earlier_create(
    conn: &Connection,
    public_key: &[u8],
    hash: &[u8; 32],
    now: u64,
) -> RelayResult<Option<AccountCreated>> {
    if !key_used(conn, &key_hash(public_key))? {
        return Ok(None);
    }
    let earlier: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT a.id, d.id, a.created_at FROM account a JOIN account_device d ON d.account_id = a.id \
             WHERE d.public_key = ?1 AND a.create_hash = ?2 AND a.created_at > ?3 AND d.revoked_at IS NULL",
            params![public_key, hash.as_slice(), to_i(now.saturating_sub(CREATE_RETRY_SECS))],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(db)?;
    earlier
        .map(|(account_id, device_id, at)| AccountCreated {
            account_id,
            device_id,
            created_at: to_u(at),
        })
        .map(Some)
        .ok_or_else(|| conflict("This key is or was a device of an account."))
}

/// `POST /v1/account`: a new account with its first device, the account's root. The
/// account id is the device's (`account_id`; an id that exists is 409 `conflict`). The
/// signature over the `apassy-connect account v1` message of this origin proves the key
/// and binds the recovery key; the statement is the key's signature over the root entry
/// of the device list, with that id and the device name (400 otherwise, nothing made). A
/// key is a device of at most one account, ever; the same body again within
/// `CREATE_RETRY_SECS` answers the same result. New accounts have the caps of the relay
/// (503 `busy`) and of the proven client prefix (429 `rate_limited`).
fn create(
    hub: &Hub,
    request: &AccountCreate,
    prefix: Option<&str>,
    now: u64,
) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_") {
        return Err(RelayError::invalid(
            "The account id is acc_ and 10 characters of a-z2-7.",
        ));
    }
    let name = checked_name(&request.name, "name")?;
    let device_name = checked_name(&request.device_name, "device name")?;
    let public_key = public_key_of(&request.public_key)?;
    let recovery_key = device::decode_recovery_key(&request.recovery_key)
        .map_err(|_| RelayError::invalid("The recovery key is b64u of 32 bytes."))?;
    let signature = signature_of(&request.signature)?;
    let statement = signature_of(&request.statement)?;
    let message = device::account_message(
        &hub.config.public_url,
        &request.public_key,
        &request.recovery_key,
    );
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of the key over the account message of this Connect.",
        ));
    }
    let account = request.account_id.as_str();
    let root = root_change(
        &hub.config.public_url,
        account,
        &public_key,
        &device_name,
        &statement,
    )?;
    let hash = body_hash(request)?;
    // A retry of the same body: the same answer, before any count.
    if let Some(earlier) = hub
        .directory
        .store
        .with(|conn| earlier_create(conn, &public_key, &hash, now))?
    {
        return to_value(&earlier);
    }
    hub.directory
        .store
        .with(|conn| check_account_room(conn, hub, now))?;
    let ticket = prefix
        .map(|prefix| {
            hub.accounts
                .prefixes
                .reserve(prefix, hub.config.connect.accounts_per_day, now)
                .map_err(|error| {
                    if error.code == codes::RATE_LIMITED {
                        RelayError::new(
                            codes::RATE_LIMITED,
                            "This network made its new accounts for today. Try again tomorrow.",
                        )
                    } else {
                        error
                    }
                })
        })
        .transpose()?;
    let (created, made) = hub.directory.store.tx(|tx| {
        // Again under the lock: another request may have used the key or the room.
        if let Some(earlier) = earlier_create(tx, &public_key, &hash, now)? {
            return Ok((earlier, false));
        }
        if tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account WHERE id = ?1)",
                params![account],
                |row| row.get::<_, bool>(0),
            )
            .map_err(db)?
        {
            return Err(conflict(
                "This account id is taken. Make a new id and sign again.",
            ));
        }
        check_account_room(tx, hub, now)?;
        tx.execute(
            "INSERT INTO account (id, name, created_at, recovery_key, create_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account, name, to_i(now), recovery_key.as_slice(), hash.as_slice()],
        )
        .map_err(db)?;
        let device = insert_device(tx, account, &device_name, request.platform, &public_key, None, now)?;
        start_list(tx, &hub.config.public_url, account, &root, now)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(account),
            "account_created",
            None,
            &json!({"account_id": account, "device_id": device}),
        )?;
        Ok((
            AccountCreated {
                account_id: account.to_string(),
                device_id: device,
                created_at: now,
            },
            true,
        ))
    })?;
    if made && let Some(ticket) = ticket {
        ticket.keep();
    }
    to_value(&created)
}

/// `POST /v1/account/challenge`: a nonce for a key that is or was a device of the account
/// (live, revoked, or of the deleted account): the sign-in tells a removed device so. The
/// nonce is not stored, so a challenge never ends another one. A key whose join waits is
/// 403 `join_pending`; a key whose join was refused, cancelled, or expired is 403
/// `join_refused`; any other key is 401.
fn challenge(hub: &Hub, request: &AccountChallengeRequest, now: u64) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_") {
        return Err(RelayError::unauthenticated());
    }
    let public_key = public_key_of(&request.public_key)?;
    let key = key_hash(&public_key);
    let known = hub.directory.store.with(|conn| {
        if key_of_account(conn, &key, &request.account_id)? {
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
    if !known {
        return Err(RelayError::unauthenticated());
    }
    let expires_at = now.saturating_add(NONCE_SECS);
    let clock = hub.accounts.nonce_clock(now);
    let nonce =
        hub.accounts
            .new_nonce(&request.account_id, &key, clock.saturating_add(NONCE_SECS))?;
    Ok(json!({"nonce": nonce, "expires_at": expires_at, "origin": hub.config.public_url}))
}

/// 403 `device_removed`: a valid signed sign-in of a key that was a device of the account
/// and is not live any more.
fn device_removed() -> RelayError {
    RelayError::new(
        codes::DEVICE_REMOVED,
        "This device was removed from its Apassy Connect account.",
    )
}

/// `POST /v1/account/token`: first the nonce (its MAC for this account and key, not
/// expired), the key, and the signature over the `apassy-connect sign-in v1` message of
/// this origin, the account, the key, and the nonce: any failure is the same 401 and uses
/// nothing. Then the device: live goes on; a key that was a device of the account is 403
/// `device_removed`; else 401. Last, under the lock: a used nonce is 401, a key with
/// `USED_NONCES_PER_KEY` used nonces 429, a full table 503 `busy`, both with the nonce
/// unused, else the nonce is used and the token kept. Nonces live on the nonce clock
/// ([`NonceClock`]).
fn token(hub: &Hub, request: &AccountTokenRequest, now: u64) -> RelayResult<Value> {
    let public_key = device::decode_public_key(&request.public_key)
        .map_err(|_| RelayError::unauthenticated())?;
    let key = key_hash(&public_key);
    let clock = hub.accounts.nonce_clock(now);
    let nonce = hub
        .accounts
        .check_nonce(&request.nonce, &request.account_id, &key, clock)
        .ok_or_else(RelayError::unauthenticated)?;
    let signature = decode_b64(&request.signature, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::unauthenticated())?;
    let message = device::account_sign_in_message(
        &hub.config.public_url,
        &request.account_id,
        &request.public_key,
        &request.nonce,
    );
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::unauthenticated());
    }
    let device: String = hub.directory.store.tx(|tx| {
        let device: Option<String> = tx
            .query_row(
                "SELECT id FROM account_device WHERE account_id = ?1 AND public_key = ?2 AND revoked_at IS NULL",
                params![request.account_id, public_key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let Some(device) = device else {
            return Err(if key_of_account(tx, &key, &request.account_id)? {
                device_removed()
            } else {
                RelayError::unauthenticated()
            });
        };
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
    hub.accounts.state().grant(
        (nonce.0, nonce.1, key),
        hash,
        Token {
            account: request.account_id.clone(),
            device: device.clone(),
            expires_at,
        },
        (now, clock),
        CAPS,
    )?;
    to_value(&AccountTokenRef {
        token: token.expose(),
        expires_at,
        account_id: &request.account_id,
        device_id: &device,
    })
}

/// `GET /v1/account`: the live devices and the signed device list.
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
                "SELECT id FROM account_device WHERE account_id = ?1 AND revoked_at IS NULL ORDER BY created_at, id",
            )
            .map_err(db)?;
        let ids = statement
            .query_map(params![caller.account], |row| row.get::<_, String>(0))
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        let devices = ids
            .iter()
            .map(|id| device_view(conn, id))
            .collect::<RelayResult<Vec<_>>>()?;
        Ok(AccountView {
            account_id: caller.account.clone(),
            name,
            email,
            created_at: to_u(created_at),
            plan,
            devices,
            group,
            device_list: list_entries(conn, &caller.account)?,
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
        // Its group rows (a member's membership; an owner's group without confirmed
        // members, with its pending members and invites).
        crate::server::group::forget_account(tx, &caller.account)?;
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
    conn
        .query_row(
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
/// is added until the device that made the link confirms. The answer carries the signed
/// device list, so the new device checks the confirmer against the root of its code.
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
                device_list: list_entries(tx, &request.account_id)?,
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
            device_list: list_entries(tx, &request.account_id)?,
        })
    })?;
    to_value(&joined)
}

/// `POST /v1/account/devices/join/cancel` (edge): the new device ends its pending join,
/// with its signature over the `apassy-connect join-cancel v1` message (400 otherwise).
fn join_cancel(hub: &Hub, request: &AccountJoinCancel, now: u64) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_") || !valid_link_hash(&request.link_hash) {
        return Err(RelayError::invalid(
            "The account id or the link hash is not valid.",
        ));
    }
    let public_key = public_key_of(&request.public_key)?;
    let signature = signature_of(&request.signature)?;
    let message = device::account_join_cancel_message(
        &hub.config.public_url,
        &request.account_id,
        &request.link_hash,
        &request.public_key,
    );
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of the key over the join-cancel message of this Connect.",
        ));
    }
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
/// for a join of another device's link, 409 when it is not pending any more. Answers the
/// name, the platform, the key, and the link hash of the join.
fn own_pending_join(
    conn: &Connection,
    caller: &AccountCaller,
    join_id: u64,
    now: u64,
) -> RelayResult<(String, Platform, Vec<u8>, String)> {
    type Row = (String, String, Vec<u8>, String, String, i64, String);
    let row: Option<Row> = conn
        .query_row(
            "SELECT j.name, j.platform, j.public_key, j.state, l.device_id, j.expires_at, l.link_hash \
             FROM account_join j JOIN account_link l ON l.id = j.link_id WHERE j.id = ?1 AND j.account_id = ?2",
            params![to_i(join_id), caller.account],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(db)?;
    let (name, platform, key, state, maker, expires_at, link_hash) =
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
    Ok((name, platform, key, link_hash))
}

/// `POST /v1/account/devices/pending/{join_id}/confirm`: the device that made the link
/// adds exactly the key it computed the words for, with the `add` entry of the device list
/// that it signed for that key and the join's link. Another key is 409; a version that is
/// not the next one is 409 (the device signs again); a statement that does not verify is
/// 400; all three add nothing. The device row and its list entry are written together.
fn confirm(
    hub: &Hub,
    caller: &AccountCaller,
    join_id: u64,
    request: &AccountConfirm,
    now: u64,
) -> RelayResult<Value> {
    let public_key = public_key_of(&request.public_key)?;
    let statement = decode_b64(&request.statement, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::invalid("The statement is not valid."))?;
    let added = hub.directory.store.tx(|tx| {
        let (name, platform, key, link_hash) = own_pending_join(tx, caller, join_id, now)?;
        if key != public_key.as_slice() {
            return Err(conflict("The pending join has another key. Nothing was added."));
        }
        if live_devices(tx, &caller.account)? >= MAX_DEVICES {
            return Err(account_limit("This account has 10 devices."));
        }
        // The entry signs the name of the join exactly as Connect keeps it.
        let change = ListChange {
            op: ListOp::Add,
            key: &key,
            link_hash: Some(&link_hash),
            name: Some(&name),
            by: &caller.public_key,
            signature: &statement,
        };
        append_signed(tx, &hub.config.public_url, caller, request.version, &change, now)?;
        let device = insert_device(tx, &caller.account, &name, platform, &key, Some(&caller.device), now)?;
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
            &json!({"join_id": join_id, "device_id": device, "by": caller.device,
                    "list_version": request.version}),
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

/// Removes `device` from every vault store that holds it, inside the transaction `tx`:
/// its rows of `account_store_device` go (its store sign-in is refused from the commit on,
/// `store_device_live`), and a removal for each store file waits in
/// `account_store_removal` (`Hub::queue_store_removal`). The caller applies them after the
/// commit (`Hub::apply_removals`). Answers the removals.
pub(crate) fn queue_device_removals(
    tx: &Connection,
    device: &str,
    now: u64,
) -> RelayResult<Vec<crate::server::hub::StoreRemoval>> {
    let stores: Vec<(String, i64)> = {
        let mut statement = tx
            .prepare("SELECT team_id, store_device FROM account_store_device WHERE device_id = ?1")
            .map_err(db)?;
        let rows = statement
            .query_map(params![device], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)?
    };
    let mut removals = Vec::with_capacity(stores.len());
    for (team, store_device) in stores {
        let Some(team) = TeamId::parse(&team) else {
            continue;
        };
        let removal = crate::server::hub::StoreRemoval {
            team,
            device: device.to_string(),
            store_device: to_u(store_device),
        };
        crate::server::hub::queue_store_removal(tx, &removal, now)?;
        removals.push(removal);
    }
    Ok(removals)
}

/// Removes `device` from every vault store that holds it: the map rows and the waiting
/// removals in one transaction (`queue_device_removals`), then each store file now when it
/// is open (its relay-sync tokens end there), else at its next open or a maintenance pass.
/// Returns the stores it left.
fn leave_stores(hub: &Hub, device: &str, now: u64) -> RelayResult<u64> {
    let removals = hub
        .directory
        .store
        .tx(|tx| queue_device_removals(tx, device, now))?;
    hub.apply_removals(&removals, now);
    Ok(removals.len() as u64)
}

/// `DELETE /v1/account/devices/{device_id}` from any live device of the account (also
/// itself), with the `remove` entry of the device list that the calling device signed for
/// the device's key (409 when the version is not the next one, 400 when it does not
/// verify; nothing changes). At once, in one transaction: the entry, the revoke in
/// `relay.db` (every later request of its tokens fails there), its open links end, its
/// node goes, the brain gets `revoke`, and its store rows go with a waiting removal for
/// each store file. Then its tokens leave memory, its tunnel closes, and each removal is
/// applied to its store file when that file is open. Its row stays (revoked): its key
/// stays used, and Connect tells the device itself that it was removed.
fn revoke(
    hub: &Hub,
    caller: &AccountCaller,
    device: &str,
    request: &AccountRevoke,
    now: u64,
) -> RelayResult<Value> {
    let statement = decode_b64(&request.statement, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::invalid("The statement is not valid."))?;
    let removals = hub.directory.store.tx(|tx| {
        let target = live_device(tx, device)?
            .filter(|target| target.account == caller.account)
            .ok_or_else(|| RelayError::not_found("device"))?;
        let change = ListChange {
            op: ListOp::Remove,
            key: &target.public_key,
            link_hash: None,
            name: None,
            by: &caller.public_key,
            signature: &statement,
        };
        append_signed(tx, &hub.config.public_url, caller, request.version, &change, now)?;
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
        let removals = queue_device_removals(tx, device, now)?;
        enqueue_brain(tx, "revoke", device, now)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_device_revoked",
            None,
            &json!({"device_id": device, "by": caller.device, "list_version": request.version}),
        )?;
        Ok(removals)
    })?;
    hub.accounts.state().drop_device(device);
    crate::server::tunnel_routes::device_revoked(hub, device);
    hub.apply_removals(&removals, now);
    to_value(&AccountRevoked {
        device_id: device.to_string(),
        removed_from_stores: removals.len() as u64,
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

/// The vault store `team` and whether `caller`'s device is in it. 404 for no team and for
/// a team that is not a vault store (connect-account-v1 section 8: `account_required` is
/// only for a team token on an account route).
fn store_of(
    conn: &Connection,
    caller: &AccountCaller,
    team: &TeamId,
) -> RelayResult<(String, bool)> {
    let row = crate::server::directory::team_by_id(conn, team)?
        .ok_or_else(|| RelayError::not_found("vault store"))?;
    if row.kind != TeamKind::Account {
        return Err(RelayError::not_found("vault store"));
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
/// ([`Groups::share_group`]), when its key is the key the caller verified (else 409); an
/// unknown or revoked device, and a device of any other account, is 403 `not_in_group`.
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
    let public_key = public_key_of(&request.public_key)?;
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
        .ok_or_else(not_in_group)?;
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
    if target.public_key != public_key.as_slice() {
        return Err(conflict(
            "That device has another key than the one you checked. Nothing was added.",
        ));
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

/// `DELETE /v1/account/vaults/{team_id}`: a device in the store, of the account that made
/// it, deletes it with its snapshots.
fn vault_delete(hub: &Hub, caller: &AccountCaller, team: &TeamId, now: u64) -> RelayResult<Value> {
    let (owner, member) = hub
        .directory
        .store
        .with(|conn| store_of(conn, caller, team))?;
    if owner != caller.account || !member {
        return Err(forbidden(
            "Only a device in the vault store, of the account that made it, deletes it.",
        ));
    }
    hub.delete_vault_store(team, &actor(&caller.account), now)?;
    to_value(&VaultStoreDeleted {
        team_id: team.clone(),
    })
}

/// Deletes every vault store that `account` made (also the billing maintenance pass, at
/// the deletion day of an ended plan). Returns how many.
pub(crate) fn delete_stores_of(hub: &Hub, account: &str, now: u64) -> RelayResult<u64> {
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

/// The earlier answer of the same recovery body within `RECOVER_RETRY_SECS`, while the
/// device it made is live.
fn earlier_recovery(
    conn: &Connection,
    account: &str,
    hash: &[u8; 32],
    now: u64,
) -> RelayResult<Option<AccountRecovered>> {
    let earlier: Option<(String, i64)> = conn
        .query_row(
            "SELECT a.recover_device, a.recover_deleted FROM account a \
             JOIN account_device d ON d.id = a.recover_device AND d.account_id = a.id \
             WHERE a.id = ?1 AND a.recover_hash = ?2 AND a.recovered_at > ?3 AND d.revoked_at IS NULL",
            params![account, hash.as_slice(), to_i(now.saturating_sub(RECOVER_RETRY_SECS))],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    Ok(earlier.map(|(device_id, deleted)| AccountRecovered {
        account_id: account.to_string(),
        device_id,
        deleted_stores: to_u(deleted),
    }))
}

/// `POST /v1/account/recover` (edge): only an account with no live device, signed by its
/// recovery key. The message names the new device key and the next recovery key; the new
/// device key signs it too, and signs the root entry of the new device list with its
/// device name (`statement`; 400 otherwise for either, not counted). A wrong recovery signature, an
/// unknown account, and an account with a live device are the same 403. The recovery
/// signature is checked first, and a valid one is never limited: only failed recovery
/// signatures of existing accounts count and are limited, `RECOVERY_TRIES_PER_HOUR` for
/// each account and `RECOVERY_PREFIX_TRIES_PER_HOUR` for each client prefix (429), in a
/// table of `MAX_RECOVERY_ENTRIES` (503 when full). The new device is the account's new
/// root and starts a new device list, every vault store of the account is deleted (a new
/// device list cannot verify the old heads), the recovery key is replaced, the
/// subscription stays. The same body again within `RECOVER_RETRY_SECS` answers the same
/// result.
fn recover(hub: &Hub, request: &AccountRecover, prefix: &str, now: u64) -> RelayResult<Value> {
    let wrong = || forbidden("The recovery key did not sign this for this account.");
    if !is_connect_id(&request.account_id, "acc_") {
        return Err(wrong());
    }
    let name = checked_name(&request.device_name, "device name")?;
    let public_key = public_key_of(&request.public_key)?;
    let next_recovery = device::decode_recovery_key(&request.recovery_key)
        .map_err(|_| RelayError::invalid("The recovery key is b64u of 32 bytes."))?;
    let signature = signature_of(&request.signature)?;
    let statement = signature_of(&request.statement)?;
    let message = device::account_recover_message(
        &hub.config.public_url,
        &request.account_id,
        &request.public_key,
        &request.recovery_key,
    );
    if !device::verify(&public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of the key over the recover message of this Connect.",
        ));
    }
    let root = root_change(
        &hub.config.public_url,
        &request.account_id,
        &public_key,
        &name,
        &statement,
    )?;
    let hash = body_hash(request)?;
    if let Some(earlier) = hub
        .directory
        .store
        .with(|conn| earlier_recovery(conn, &request.account_id, &hash, now))?
    {
        return to_value(&earlier);
    }
    let tag = hub.accounts.prefix_tag(prefix);
    let stored: Option<(Vec<u8>, u64)> = hub.directory.store.with(|conn| {
        let key: Option<Vec<u8>> = conn
            .query_row(
                "SELECT recovery_key FROM account WHERE id = ?1",
                params![request.account_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        key.map(|key| Ok((key, live_devices(conn, &request.account_id)?)))
            .transpose()
    })?;
    // An unknown account is not counted: nothing there to guess.
    let (recovery_key, live) = stored.ok_or_else(wrong)?;
    let recovery_signature = decode_b64(
        &request.recovery_signature,
        device::RECOVERY_SIGNATURE_BYTES,
    )
    .unwrap_or_default();
    if !device::verify_recovery(&recovery_key, &message, &recovery_signature) {
        hub.accounts
            .recovery()
            .fail(&request.account_id, &tag, now, MAX_RECOVERY_ENTRIES)?;
        return Err(wrong());
    }
    if live != 0 {
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
        // Again under the lock: another recovery may have won the race, with the same
        // recovery key or after it was replaced.
        let current: Option<Vec<u8>> = tx
            .query_row(
                "SELECT recovery_key FROM account WHERE id = ?1",
                params![request.account_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if current.as_deref() != Some(recovery_key.as_slice())
            || live_devices(tx, &request.account_id)? != 0
        {
            return Err(wrong());
        }
        let device = insert_device(tx, &request.account_id, &name, request.platform, &public_key, None, now)?;
        start_list(tx, &hub.config.public_url, &request.account_id, &root, now)?;
        tx.execute(
            "UPDATE account SET recovery_key = ?2, recover_hash = ?3, recovered_at = ?4, \
             recover_device = ?5, recover_deleted = ?6 WHERE id = ?1",
            params![
                request.account_id,
                next_recovery.as_slice(),
                hash.as_slice(),
                to_i(now),
                device,
                to_i(deleted_stores)
            ],
        )
        .map_err(db)?;
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
/// `plan_required`. Without a signing key, and while the signing key is not published
/// long enough (`signs_now`): 503 `busy`.
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
    if !hub
        .directory
        .store
        .with(|conn| signs_now(conn, signer.kid(), now))?
    {
        return Err(busy(
            "The new signing key of this Connect is not published long enough yet. Try again later.",
        ));
    }
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

/// Whether the key `kid` signs at `now`: this relay published it at least
/// `PUBLISH_LEAD_SECS` ago (`entitlement_key.created_at`), or it is among the first keys
/// this relay ever had (no key was recorded before it).
fn signs_now(conn: &Connection, kid: &str, now: u64) -> RelayResult<bool> {
    let row: Option<(i64, bool)> = conn
        .query_row(
            "SELECT k.created_at, NOT EXISTS(SELECT 1 FROM entitlement_key o WHERE o.created_at < k.created_at) \
             FROM entitlement_key k WHERE k.kid = ?1",
            params![kid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    Ok(row.is_some_and(|(created_at, first)| {
        first || now >= to_u(created_at).saturating_add(PUBLISH_LEAD_SECS)
    }))
}

/// Records at start, as history, the kid and public key of the signing key and of each
/// key of `APASSY_CONNECT_PUBLISHED_KEYS_FILE` with the time this relay first published
/// it. The time decides when a new signing key signs (`signs_now`); the rows never decide
/// what is published.
pub fn record_keys(hub: &Hub, now: u64) -> RelayResult<()> {
    let keys: Vec<PublishedKey> = published_keys(hub);
    hub.directory.store.tx(|tx| {
        for key in &keys {
            tx.execute(
                "INSERT INTO entitlement_key (kid, public_key, created_at) VALUES (?1, ?2, ?3) ON CONFLICT(kid) DO NOTHING",
                params![key.kid, key.public_key.as_slice(), to_i(now)],
            )
            .map_err(db)?;
        }
        Ok(())
    })
}

/// The keys that verify tokens: the signing key and the keys of
/// `APASSY_CONNECT_PUBLISHED_KEYS_FILE` (the next key before a rotation, the previous one
/// for a day after it), from the configuration only. A key removed from the file goes at
/// the next start.
pub fn published_keys(hub: &Hub) -> Vec<PublishedKey> {
    let mut keys: Vec<PublishedKey> = hub
        .accounts
        .signer()
        .map(EntitlementSigner::published)
        .into_iter()
        .collect();
    for key in &hub.config.connect.published_keys {
        if !keys.iter().any(|known| known.kid == key.kid) {
            keys.push(key.clone());
        }
    }
    keys
}

/// `GET /.well-known/apassy-connect.json` (edge).
fn well_known(hub: &Hub) -> RelayResult<Value> {
    let keys = published_keys(hub)
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

// ---- Maintenance. ----

/// The account part of the relay's maintenance pass (`http::maintain`): the removals
/// from vault stores that wait (`Hub::retry_store_removals`) at every pass; at most once
/// in `MAINTENANCE_SECS`, links (and their joins) more than `LINK_KEEP_SECS` past their
/// end and the relay audit rows of accounts older than `ACCOUNT_AUDIT_RETENTION_SECS`.
pub fn maintain(hub: &Hub, now: u64) {
    if let Err(error) = hub.retry_store_removals(now) {
        eprintln!(
            "apassy-relay: the removals from vault stores could not be retried: {}",
            error.message
        );
    }
    let last = hub.accounts.pruned_at.load(Ordering::Relaxed);
    if last != 0 && now < last.saturating_add(MAINTENANCE_SECS) {
        return;
    }
    hub.accounts.pruned_at.store(now, Ordering::Relaxed);
    if let Err(error) = prune(hub, now) {
        eprintln!(
            "apassy-relay: the account maintenance pass failed: {}",
            error.message
        );
    }
}

/// Deletes old links with their joins (`ON DELETE CASCADE`; the device list keeps the
/// link hash of each `add`), old relay audit rows of accounts, the rows of devices revoked
/// longer ago than the audit (their keys stay in `account_key`, so a removed device still
/// learns that it was removed, and the device list keeps their entries), and I-4 events
/// older than the audit. Answers how many links and audit rows went.
pub fn prune(hub: &Hub, now: u64) -> RelayResult<(usize, usize)> {
    let before = to_i(now.saturating_sub(ACCOUNT_AUDIT_RETENTION_SECS));
    hub.directory.store.tx(|tx| {
        let links = tx
            .execute(
                "DELETE FROM account_link WHERE expires_at < ?1",
                params![to_i(now.saturating_sub(LINK_KEEP_SECS))],
            )
            .map_err(db)?;
        let audit = tx
            .execute(
                "DELETE FROM audit WHERE actor LIKE 'account:%' AND at < ?1",
                params![before],
            )
            .map_err(db)?;
        tx.execute(
            "DELETE FROM account_device WHERE revoked_at IS NOT NULL AND revoked_at < ?1",
            params![before],
        )
        .map_err(db)?;
        tx.execute(
            "DELETE FROM brain_event WHERE created_at < ?1",
            params![before],
        )
        .map_err(db)?;
        Ok((links, audit))
    })
}

/// Whether the store device `store_device` of the vault store `team` is a live account
/// device in `relay.db` (`account_store_device` and `account_device`) that may be in the
/// store now: a device of the account that made the store, or of an account that is an
/// active member of one group with it. The relay-sync sign-in to a vault store needs it,
/// besides its row in the store file, so a device of another account signs in no more
/// from the moment the two accounts share no group.
pub fn store_device_live(conn: &Connection, team: &TeamId, store_device: u64) -> RelayResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_store_device s JOIN account_device d ON d.id = s.device_id \
         JOIN team t ON t.id = s.team_id \
         WHERE s.team_id = ?1 AND s.store_device = ?2 AND d.revoked_at IS NULL AND d.account_id = s.account_id \
         AND (s.account_id = t.account_id OR EXISTS(SELECT 1 FROM group_member a JOIN group_member b \
           ON b.group_id = a.group_id WHERE a.account_id = s.account_id AND b.account_id = t.account_id \
           AND a.state = 'active' AND b.state = 'active')))",
        params![team.as_str(), to_i(store_device)],
        |row| row.get(0),
    )
    .map_err(db)
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

    const NOW: u64 = 1_790_000_000;

    #[test]
    fn a_nonce_is_bound_to_its_account_key_and_time_and_is_not_stored() {
        let accounts = Accounts::new(None).unwrap();
        let key = [7u8; 32];
        let nonce = accounts
            .new_nonce("acc_aaaaaaaaaa", &key, NOW + NONCE_SECS)
            .unwrap();
        assert_eq!(decode_b64(&nonce, 32).unwrap().len(), 32);
        let (bytes, expires_at) = accounts
            .check_nonce(&nonce, "acc_aaaaaaaaaa", &key, NOW)
            .unwrap();
        assert_eq!(expires_at, NOW + NONCE_SECS);
        assert_eq!(encode_b64(&bytes), nonce);
        // Many more challenges of the same key leave it valid: nothing is kept.
        for _ in 0..100 {
            accounts
                .new_nonce("acc_aaaaaaaaaa", &key, NOW + NONCE_SECS)
                .unwrap();
        }
        assert!(
            accounts
                .check_nonce(&nonce, "acc_aaaaaaaaaa", &key, NOW)
                .is_some()
        );
        // Another account, another key, an expired one, a changed byte: refused.
        assert!(
            accounts
                .check_nonce(&nonce, "acc_bbbbbbbbbb", &key, NOW)
                .is_none()
        );
        assert!(
            accounts
                .check_nonce(&nonce, "acc_aaaaaaaaaa", &[8u8; 32], NOW)
                .is_none()
        );
        assert!(
            accounts
                .check_nonce(&nonce, "acc_aaaaaaaaaa", &key, NOW + NONCE_SECS)
                .is_none()
        );
        let mut changed = bytes;
        changed[13] ^= 1;
        assert!(
            accounts
                .check_nonce(&encode_b64(&changed), "acc_aaaaaaaaaa", &key, NOW)
                .is_none()
        );
        // A nonce of another process (another key) is refused.
        let other = Accounts::new(None).unwrap();
        assert!(
            other
                .check_nonce(&nonce, "acc_aaaaaaaaaa", &key, NOW)
                .is_none()
        );
        assert!(
            accounts
                .check_nonce("bm9uY2U", "acc_aaaaaaaaaa", &key, NOW)
                .is_none()
        );
    }

    fn token_for(device: &str) -> Token {
        Token {
            account: "acc_aaaaaaaaaa".into(),
            device: device.into(),
            expires_at: NOW + TOKEN_SECS,
        }
    }

    /// A nonce, its expiry on the nonce clock, and the SHA-256 of its key.
    fn used(seed: u8, key: u8) -> ([u8; 32], u64, [u8; 32]) {
        ([seed; 32], NOW + NONCE_SECS, [key; 32])
    }

    #[test]
    fn a_full_table_answers_busy_and_leaves_the_nonce_unused() {
        let mut state = AuthState::default();
        let small = Caps {
            tokens: 1,
            used_nonces: 10,
            used_per_key: 10,
        };
        let first = used(1, 1);
        state
            .grant(
                first,
                token_hash("t1"),
                token_for("dev_a"),
                (NOW, NOW),
                small,
            )
            .unwrap();
        // A used nonce grants nothing again.
        assert_eq!(
            state
                .grant(
                    first,
                    token_hash("t2"),
                    token_for("dev_a"),
                    (NOW, NOW),
                    small
                )
                .unwrap_err()
                .code,
            codes::UNAUTHENTICATED
        );
        // The token table is full for another device: 503, and its nonce stays unused.
        let second = used(2, 2);
        assert_eq!(
            state
                .grant(
                    second,
                    token_hash("t3"),
                    token_for("dev_b"),
                    (NOW, NOW),
                    small
                )
                .unwrap_err()
                .code,
            codes::BUSY
        );
        assert!(!state.used.contains_key(&second.0));
        // With room again the same nonce works.
        state
            .grant(
                second,
                token_hash("t3"),
                token_for("dev_b"),
                (NOW, NOW),
                CAPS,
            )
            .unwrap();
        // A full table of used nonces is 503 too.
        let one_used = Caps {
            tokens: 100,
            used_nonces: 2,
            used_per_key: 10,
        };
        assert_eq!(
            state
                .grant(
                    used(3, 3),
                    token_hash("t4"),
                    token_for("dev_c"),
                    (NOW, NOW),
                    one_used
                )
                .unwrap_err()
                .code,
            codes::BUSY
        );
        // Used nonces leave with their expiry on the nonce clock.
        state.purge(NOW, NOW + NONCE_SECS);
        assert!(state.used.is_empty());
        assert!(state.used_by_key.is_empty());
        // A device at its cap drops its oldest token, also with the table full.
        let mut state = AuthState::default();
        for index in 0..TOKENS_PER_DEVICE {
            state
                .grant(
                    used(10 + index as u8, 4),
                    token_hash(&format!("d{index}")),
                    token_for("dev_d"),
                    (NOW, NOW),
                    CAPS,
                )
                .unwrap();
        }
        let full = Caps {
            tokens: TOKENS_PER_DEVICE,
            used_nonces: 100,
            used_per_key: 100,
        };
        state
            .grant(
                used(99, 4),
                token_hash("d-new"),
                token_for("dev_d"),
                (NOW, NOW),
                full,
            )
            .unwrap();
        assert_eq!(state.tokens.len(), TOKENS_PER_DEVICE);
        assert!(!state.tokens.contains_key(&token_hash("d0")));
    }

    #[test]
    fn one_key_cannot_fill_the_table_of_used_nonces() {
        let mut state = AuthState::default();
        let caps = Caps {
            tokens: 1000,
            used_nonces: 1000,
            used_per_key: 3,
        };
        for seed in 0..3 {
            state
                .grant(
                    used(seed, 1),
                    token_hash(&format!("a{seed}")),
                    token_for("dev_a"),
                    (NOW, NOW),
                    caps,
                )
                .unwrap();
        }
        // The fourth nonce of the same key in the minute: 429 for that key, unused.
        let fourth = used(3, 1);
        assert_eq!(
            state
                .grant(
                    fourth,
                    token_hash("a3"),
                    token_for("dev_a"),
                    (NOW, NOW),
                    caps
                )
                .unwrap_err()
                .code,
            codes::RATE_LIMITED
        );
        assert!(!state.used.contains_key(&fourth.0));
        // Another key signs in as before.
        state
            .grant(
                used(50, 2),
                token_hash("b0"),
                token_for("dev_b"),
                (NOW, NOW),
                caps,
            )
            .unwrap();
        // When the first nonces expire, the key signs in again.
        state
            .grant(
                fourth,
                token_hash("a3"),
                token_for("dev_a"),
                (NOW, NOW + NONCE_SECS),
                caps,
            )
            .unwrap();
        assert_eq!(state.used_by_key.get(&[1u8; 32]).copied(), Some(1));
    }

    #[test]
    fn the_nonce_clock_never_goes_back() {
        let mut clock = NonceClock::default();
        assert_eq!(clock.tick(NOW), NOW);
        assert_eq!(clock.tick(NOW + 10), NOW + 10);
        // The wall clock is set back an hour: the nonce clock stands still, then follows
        // the wall clock forward from there.
        assert_eq!(clock.tick(NOW - 3600), NOW + 10);
        assert_eq!(clock.tick(NOW - 3590), NOW + 20);
        // A used nonce stays used through the step back: it never grants twice.
        let mut state = AuthState::default();
        let nonce = used(7, 7);
        let first = state.clock.tick(NOW);
        state
            .grant(
                nonce,
                token_hash("x1"),
                token_for("dev_x"),
                (NOW, first),
                CAPS,
            )
            .unwrap();
        let later = state.clock.tick(NOW + 120);
        state.purge(NOW + 120, later);
        assert!(state.used.is_empty());
        let back = state.clock.tick(NOW + 5);
        assert!(back >= NOW + 120, "the clock went back");
        let accounts = Accounts::new(None).unwrap();
        let key = [9u8; 32];
        let issued = accounts.nonce_clock(NOW);
        let text = accounts
            .new_nonce("acc_aaaaaaaaaa", &key, issued + NONCE_SECS)
            .unwrap();
        let after = accounts.nonce_clock(NOW + 120);
        let set_back = accounts.nonce_clock(NOW + 5);
        assert!(set_back >= after);
        assert!(
            accounts
                .check_nonce(&text, "acc_aaaaaaaaaa", &key, set_back)
                .is_none(),
            "an expired nonce stays expired when the wall clock goes back"
        );
    }

    #[test]
    fn recovery_failures_count_per_account_and_prefix_in_a_capped_table() {
        let mut state = RecoveryState::default();
        let prefix = [1u8; 32];
        for _ in 0..RECOVERY_TRIES_PER_HOUR {
            state.fail("acc_a", &prefix, NOW, 100).unwrap();
        }
        assert_eq!(
            state.fail("acc_a", &prefix, NOW, 100).unwrap_err().code,
            codes::RATE_LIMITED
        );
        // Another account from the same prefix goes on until the prefix's limit.
        let mut account = 0;
        while state
            .fail(&format!("acc_{account}"), &prefix, NOW, 100)
            .is_ok()
        {
            account += 1;
        }
        assert_eq!(
            u32::try_from(account).unwrap() + RECOVERY_TRIES_PER_HOUR,
            RECOVERY_PREFIX_TRIES_PER_HOUR
        );
        // Another prefix is free for another account; the hour ends both.
        state.fail("acc_new", &[2u8; 32], NOW, 100).unwrap();
        state.fail("acc_a", &prefix, NOW + 3600, 100).unwrap();
        // A full table: a new account is 503 and is not counted.
        let mut state = RecoveryState::default();
        state.fail("acc_a", &prefix, NOW, 1).unwrap();
        assert_eq!(
            state.fail("acc_b", &prefix, NOW, 1).unwrap_err().code,
            codes::BUSY
        );
        assert!(!state.accounts.contains_key("acc_b"));
        assert_eq!(
            state.fail("acc_a", &[3u8; 32], NOW, 1).unwrap_err().code,
            codes::BUSY
        );
        state.fail("acc_a", &prefix, NOW, 1).unwrap();
    }
}
