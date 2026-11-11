//! The calls of the Connect account contract (connect-account-v1 sections 6 to 10, and
//! `GET /v1/plans` of connect-billing-v1 section 2), over the relay HTTP client of the
//! app: the origin rules of relay-sync-v1 section 3, the JSON envelope, the retries of
//! `503 busy`, and the wait of a `429`.
//!
//! Each call is one request with a 30-second deadline. The edge calls carry no
//! `Authorization`; the others carry the account token, which only this client sends
//! and only to its own origin (plan 0035 I-2). Results ignore unknown fields; the request
//! bodies are exactly those of the contract. The answers are checked by the callers in
//! [`super::account`].

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::ConnectError;
use super::trust::ListEntry;
use crate::sync::relay::{ApiError, call, call_without_busy_retries, json_request};
use crate::sync::relay_http::Request;
use crate::sync::{RelayUrl, SyncError};

/// The deadline of one call.
const CALL_DEADLINE: Duration = Duration::from_secs(30);

/// The Connect origin that the host of this process set ([`set_configured_origin`]).
static PROCESS_ORIGIN: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// The Connect origin of this build: the one that the host of this process set
/// ([`set_configured_origin`], the iPhone core from its config), else
/// `APASSY_CONNECT_URL` when it is set (a sandbox Connect), else
/// [`super::DEFAULT_CONNECT_URL`]. An account keeps the origin it was made at in its
/// account file, so this only chooses where a new account or join goes, and which
/// Connect host a pairing code may name (node-pairing-v1 section 7a).
pub fn configured_origin() -> String {
    if let Some(origin) = PROCESS_ORIGIN
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        return origin;
    }
    std::env::var("APASSY_CONNECT_URL")
        .ok()
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| super::DEFAULT_CONNECT_URL.to_owned())
}

/// Set the Connect origin of this process (without a trailing slash): the iPhone core
/// does it at its start with the origin of its config, as it sets the device name, so
/// the pairing codes that it reads name the same Connect host. The last call wins.
pub fn set_configured_origin(origin: &str) {
    *PROCESS_ORIGIN
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(origin.trim_end_matches('/').to_owned());
}

/// The error of a failed call.
pub(super) fn connect_error(error: ApiError) -> ConnectError {
    match error {
        ApiError::Unreachable => ConnectError::Offline,
        ApiError::Broken => ConnectError::Broken,
        ApiError::Sync(SyncError::RelayUnreachable) => ConnectError::Offline,
        ApiError::Sync(_) => ConnectError::Local,
        ApiError::Relay {
            status,
            code,
            retry_after,
        } => match (status, code.as_str()) {
            (401, _) => ConnectError::Unauthenticated,
            // `403 device_removed` is a removal only as the answer of the token call to a
            // signature of this device ([`ConnectClient::token`]): from any other route it is
            // a refusal like any other.
            (403, "join_pending") => ConnectError::JoinPending,
            (403, "join_refused") => ConnectError::JoinRefused,
            (403, "plan_required") => ConnectError::PlanRequired,
            (403, "account_required") => ConnectError::AccountRequired,
            (403, "account_limit") => ConnectError::AccountLimit,
            (403, "not_in_group") => ConnectError::NotInGroup,
            (403, "forbidden") => ConnectError::Forbidden,
            (404 | 405, _) => ConnectError::NotFound,
            (409, "conflict") => ConnectError::Conflict,
            (409, "account_id_taken") => ConnectError::AccountIdTaken,
            (409, "seat_limit") => ConnectError::SeatLimit,
            (429, _) => ConnectError::RateLimited(retry_after.unwrap_or(60).max(1)),
            _ => ConnectError::Refused { status, code },
        },
    }
}

// ---- Bodies of the requests (section 6 to 10). ----

/// The body of `POST /v1/tunnel/nodes` (connect-tunnel-v1 section 3.1).
#[derive(Serialize)]
struct RegisterNode<'a> {
    name: &'a str,
    pin: &'a str,
}

/// A node as Connect answers it (`NodeView`, connect-tunnel-v1 section 3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelNodeView {
    pub node_id: String,
    pub account_id: String,
    pub device_id: String,
    pub name: String,
    pub pin: String,
    pub public_name: String,
    pub online: bool,
    pub created_at: u64,
}

#[derive(Serialize)]
pub(super) struct CreateAccount<'a> {
    /// The id of the new account, made by this device: the root entry names it.
    pub account_id: &'a str,
    pub name: &'a str,
    pub device_name: &'a str,
    pub platform: &'a str,
    pub public_key: &'a str,
    /// b64u of the Ed25519 public key of the recovery code.
    pub recovery_key: &'a str,
    pub signature: &'a str,
    /// The root entry of the device list (version 1), signed by the new device key over
    /// its name.
    pub statement: &'a str,
}

#[derive(Serialize)]
pub(super) struct ChallengeRequest<'a> {
    pub account_id: &'a str,
    pub public_key: &'a str,
}

#[derive(Serialize)]
pub(super) struct TokenRequest<'a> {
    pub account_id: &'a str,
    pub public_key: &'a str,
    pub nonce: &'a str,
    pub signature: &'a str,
}

#[derive(Serialize)]
struct LinkRequest<'a> {
    link_hash: &'a str,
}

/// `POST …/pending/{join_id}/confirm`: the key that this device adds, and its statement.
#[derive(Serialize)]
struct ConfirmRequest<'a> {
    public_key: &'a str,
    /// The version of the `add` entry of the device list.
    version: u64,
    statement: &'a str,
}

/// The body of `DELETE /v1/account/devices/{device_id}`: the `remove` entry of the device
/// list.
#[derive(Serialize)]
struct RevokeRequest<'a> {
    version: u64,
    statement: &'a str,
}

#[derive(Serialize)]
pub(super) struct JoinBody<'a> {
    pub account_id: &'a str,
    pub link_hash: &'a str,
    pub device_name: &'a str,
    pub platform: &'a str,
    pub public_key: &'a str,
    pub signature: &'a str,
}

#[derive(Serialize)]
pub(super) struct JoinCancel<'a> {
    pub account_id: &'a str,
    pub link_hash: &'a str,
    pub public_key: &'a str,
    pub signature: &'a str,
}

#[derive(Serialize)]
struct VaultCreate<'a> {
    vault_id: &'a str,
    name: &'a str,
}

/// The device to add to a store and the key that this device verified for it.
#[derive(Serialize)]
struct StoreDeviceRequest<'a> {
    device_id: &'a str,
    public_key: &'a str,
}

#[derive(Serialize)]
pub(super) struct RecoverBody<'a> {
    pub account_id: &'a str,
    pub device_name: &'a str,
    pub platform: &'a str,
    pub public_key: &'a str,
    /// b64u of the Ed25519 public key of the new recovery code.
    pub recovery_key: &'a str,
    /// The new device's signature over the `apassy-connect recover v1` message.
    pub signature: &'a str,
    /// The old recovery key's Ed25519 signature over the same message.
    pub recovery_signature: &'a str,
    /// The root entry of the new device list (version 1), signed by the new device key
    /// over its name.
    pub statement: &'a str,
}

/// `POST /v1/account/checkout` (connect-billing-v1 section 4): `people` only for Family,
/// `seats` only for Team; the other is left out of the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckoutRequest {
    /// `personal`, `family`, or `team`.
    pub plan: String,
    /// `month` or `year`.
    pub interval: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub people: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seats: Option<u64>,
}

impl CheckoutRequest {
    /// The body for `count` units of `plan`: people for Family, seats for Team, nothing
    /// for Personal.
    pub fn new(plan: &str, interval: &str, count: u64) -> Self {
        Self {
            plan: plan.to_owned(),
            interval: interval.to_owned(),
            people: (plan == "family").then_some(count),
            seats: (plan == "team").then_some(count),
        }
    }
}

#[derive(Serialize)]
struct InviteRequest<'a> {
    role: &'a str,
}

#[derive(Serialize)]
struct GroupJoinRequest<'a> {
    code: &'a str,
}

#[derive(Serialize)]
struct SeatsRequest {
    quantity: u64,
}

/// The empty JSON object of `DELETE /v1/account` and the refusal of a join.
#[derive(Serialize)]
struct Empty {}

// ---- Results. ----

/// `POST /v1/account`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountCreated {
    pub account_id: String,
    pub device_id: String,
    pub created_at: u64,
}

/// `POST /v1/account/challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct Challenge {
    pub nonce: String,
    /// The origin that Connect signs for; the client stops when it differs. The
    /// `expires_at` of the answer is not read: Connect enforces it, and a Mac clock that
    /// is off must not stop a sign-in.
    pub origin: String,
}

/// `POST /v1/account/token`. The caller moves the token into a `Zeroizing` at once (the
/// relay sync client does the same).
#[derive(Deserialize)]
pub(super) struct TokenAnswer {
    pub token: String,
    pub expires_at: u64,
    pub account_id: String,
    pub device_id: String,
}

/// The `PlanView` of connect-billing-v1 section 8. Every time is Unix seconds or `None`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlanView {
    /// `personal`, `family`, `team`, or `None` without a plan.
    #[serde(default)]
    pub plan: Option<String>,
    /// `none`, `pending`, `active`, `trialing`, `past_due`, `read_only`, or `suspended`.
    pub status: String,
    pub entitled: bool,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub quantity: Option<u64>,
    #[serde(default)]
    pub renews_at: Option<u64>,
    #[serde(default)]
    pub ends_at: Option<u64>,
    #[serde(default)]
    pub grace_until: Option<u64>,
    #[serde(default)]
    pub read_only_until: Option<u64>,
    #[serde(default)]
    pub delete_at: Option<u64>,
    #[serde(default)]
    pub group_id: Option<String>,
}

/// A live device of the account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceView {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    /// b64u of the X9.63 public key.
    pub public_key: String,
    pub created_at: u64,
    /// Rounded down to the hour, or `None`.
    #[serde(default)]
    pub last_seen_at: Option<u64>,
    /// Set by this device, never by Connect: the key is a device of the signed device list
    /// that this device verified ([`super::ConnectAccount::view`]). An unverified device is
    /// not an account device for any decision.
    #[serde(skip)]
    pub verified: bool,
    /// Set by this device for a verified device: the name that the signed device list
    /// holds for its key (the name that its `root` or `add` signed). Show it, not
    /// [`Self::name`], wherever the owner decides about the device.
    #[serde(skip)]
    pub signed_name: Option<String>,
    /// Set by this device: the short fingerprint of [`Self::public_key`]
    /// (`super::key_fingerprint`), empty for a key that is not a point.
    #[serde(skip)]
    pub fingerprint: String,
}

impl DeviceView {
    /// The name to show: the signed name of a verified device, else the name of Connect.
    pub fn shown_name(&self) -> &str {
        self.signed_name.as_deref().unwrap_or(&self.name)
    }
}

/// The group of the account (connect-billing-v1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GroupView {
    pub group_id: String,
    /// `family` or `team`.
    pub kind: String,
    /// `owner`, `admin`, or `member`.
    pub role: String,
    /// `pending` or `active`.
    pub state: String,
}

/// `GET /v1/account`. `email` is the copy of the Stripe customer's email; Apassy shows it
/// and never stores it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountView {
    pub account_id: String,
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    pub created_at: u64,
    pub plan: PlanView,
    pub devices: Vec<DeviceView>,
    #[serde(default)]
    pub group: Option<GroupView>,
    /// The signed device list, from version 1 ([`super::trust`]).
    #[serde(default)]
    pub device_list: Vec<ListEntry>,
    /// b64u of the public recovery key that Connect stores (section 9.1): the `previous`
    /// of a new recovery code.
    #[serde(default)]
    pub recovery_key: Option<String>,
    /// Set by this device, never by Connect: `device_list` verified from the pinned root and
    /// went on from the pinned version. When it is false, no device of the view is
    /// verified, and the trust store keeps what it had.
    #[serde(skip)]
    pub list_verified: bool,
}

/// `DELETE /v1/account`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountDeleted {
    pub account_id: String,
    pub deleted_stores: u64,
    pub subscription_canceled: bool,
}

/// `POST /v1/account/devices/link`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct LinkAnswer {
    pub link_id: u64,
    pub expires_at: u64,
}

/// One entry of `GET /v1/account/devices/pending`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct PendingView {
    pub join_id: u64,
    pub link_id: u64,
    pub device_name: String,
    pub platform: String,
    pub public_key: String,
    /// The joining key's signature over the `apassy-connect join v1` message, which names
    /// `device_name`. A join whose signature does not verify is not offered.
    #[serde(default)]
    pub signature: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// The device that confirms a join.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct Confirmer {
    pub device_id: String,
    pub name: String,
    pub public_key: String,
}

/// `POST /v1/account/devices/join`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct JoinAnswer {
    pub join_id: u64,
    pub account_id: String,
    pub confirmer: Confirmer,
    pub expires_at: u64,
    /// The signed device list of the account, from version 1.
    #[serde(default)]
    pub device_list: Vec<ListEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct JoinId {
    pub join_id: u64,
}

/// `DELETE /v1/account/devices/{device_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RevokeAnswer {
    pub device_id: String,
    pub removed_from_stores: u64,
}

/// A device in a vault store.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoreDevice {
    pub store_device_id: u64,
    pub device_id: String,
    pub account_id: String,
}

/// A vault store: a relay-sync-v1 team of kind `account` for one vault (section 8).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VaultStoreView {
    pub team_id: String,
    pub vault_id: String,
    pub name: String,
    pub created_at: u64,
    pub shared: bool,
    pub devices: Vec<StoreDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct VaultDeleted {
    pub team_id: String,
}

/// `POST /v1/account/recovery` (section 9.1).
#[derive(Serialize)]
pub(super) struct RecoveryRotate<'a> {
    /// b64u of the recovery key that Connect stores now.
    pub previous: &'a str,
    /// b64u of the Ed25519 public key of the new recovery code.
    pub recovery_key: &'a str,
    /// The device's signature over the `apassy-connect recovery-rotate v1` message.
    pub signature: &'a str,
}

/// The answer of `POST /v1/account/recovery`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecoveryRotated {
    pub account_id: String,
    pub rotated_at: u64,
}

/// `POST /v1/account/recover`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecoverAnswer {
    pub account_id: String,
    pub device_id: String,
    pub deleted_stores: u64,
}

/// `GET /v1/account/entitlement`.
#[derive(Deserialize)]
pub(super) struct EntitlementAnswer {
    /// The `expires_at` of the answer is the `exp` of the claims, which the client reads.
    pub token: String,
}

/// A key of the well-known document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WellKnownKey {
    pub kid: String,
    pub alg: String,
    pub public_key: String,
}

/// `GET /.well-known/apassy-connect.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WellKnown {
    pub v: u64,
    pub origin: String,
    pub keys: Vec<WellKnownKey>,
}

impl WellKnown {
    /// The Ed25519 keys of the document; a key of another algorithm or shape is left out.
    pub fn keys(&self) -> Vec<super::EntitlementKey> {
        self.keys
            .iter()
            .filter_map(|key| {
                super::EntitlementKey::from_published(&key.kid, &key.alg, &key.public_key)
            })
            .collect()
    }
}

/// One price of a plan (connect-billing-v1 section 2): cents with VAT included.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlanPrice {
    /// `month` or `year`.
    pub interval: String,
    pub lookup_key: String,
    pub amount: u64,
    #[serde(default)]
    pub extra: Option<u64>,
}

/// One plan of `GET /v1/plans`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlanOffer {
    pub plan: String,
    pub name: String,
    /// `account`, `person`, or `member`.
    pub unit: String,
    pub included: u64,
    pub max: u64,
    pub prices: Vec<PlanPrice>,
}

/// `GET /v1/plans`: the prices come from Connect, never from the app.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlansView {
    pub currency: String,
    /// `inclusive`.
    pub tax: String,
    pub plans: Vec<PlanOffer>,
}

impl PlanOffer {
    /// The price of `interval`, if Connect has one.
    pub fn price(&self, interval: &str) -> Option<&PlanPrice> {
        self.prices.iter().find(|price| price.interval == interval)
    }

    /// The total in cents for `count` units (people or seats; Personal 1) of `interval`
    /// (connect-billing-v1 section 2): `amount + max(0, count − included) × extra`, for
    /// `1 ≤ count ≤ max`. `None` outside that range, or without that price.
    pub fn total(&self, interval: &str, count: u64) -> Option<u64> {
        if count == 0 || count > self.max {
            return None;
        }
        let price = self.price(interval)?;
        let further = count.saturating_sub(self.included);
        if further == 0 {
            return Some(price.amount);
        }
        price
            .extra?
            .checked_mul(further)
            .and_then(|extra| extra.checked_add(price.amount))
    }
}

/// `POST /v1/account/checkout`: the Stripe Checkout page that the Mac opens in the
/// default browser.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CheckoutAnswer {
    pub url: String,
    pub session_id: String,
    pub expires_at: u64,
}

/// `POST /v1/account/portal`: the Stripe Customer Portal page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PortalAnswer {
    pub url: String,
}

/// A member of a family or team (connect-billing-v1 section 6).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GroupMember {
    pub account_id: String,
    pub name: String,
    /// `owner`, `admin`, or `member`.
    pub role: String,
    /// `pending` or `active`.
    pub state: String,
    #[serde(default)]
    pub joined_at: Option<u64>,
}

/// `GET /v1/account/group`: the `GroupView` of connect-billing-v1 section 6, with the
/// members. (The short group of `GET /v1/account` is [`GroupView`].)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GroupDetail {
    pub group_id: String,
    /// `family` or `team`.
    pub kind: String,
    /// The role of this account: `owner`, `admin`, or `member`.
    pub role: String,
    pub owner_account: String,
    pub included: u64,
    /// The subscription quantity: people or seats.
    pub quantity: u64,
    pub members: Vec<GroupMember>,
}

/// `POST /v1/account/group/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InviteAnswer {
    pub invite_id: u64,
    /// `https://<site>/connect/join#apassy_gin_<group id>_<64 hex>`.
    pub url: String,
    pub expires_at: u64,
}

/// `POST /v1/account/group/join`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GroupJoined {
    pub group_id: String,
    pub kind: String,
    /// `pending` until the owner or an admin confirms.
    pub state: String,
    pub owner_name: String,
}

/// `DELETE /v1/account/group/members/{account_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MemberRemoved {
    pub account_id: String,
    pub removed_from_stores: u64,
}

/// `POST /v1/account/group/seats`: the new quantity applies when Stripe confirms it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SeatsAnswer {
    pub quantity: u64,
    pub pending: bool,
}

/// The `result` of an envelope that [`ConnectClient::get_document`] read, or its error.
fn call_answer<T: DeserializeOwned>(
    value: serde_json::Value,
    status: u16,
) -> Result<T, ConnectError> {
    if value["ok"] == serde_json::Value::Bool(true) && (200..300).contains(&status) {
        return serde_json::from_value(value["result"].clone())
            .map_err(|_| ConnectError::BadAnswer);
    }
    let code = value["error"]["code"]
        .as_str()
        .filter(|code| !code.is_empty())
        .unwrap_or("relay_error")
        .to_owned();
    if status < 400 {
        return Err(ConnectError::Offline);
    }
    Err(connect_error(ApiError::Relay {
        status,
        code,
        retry_after: None,
    }))
}

/// A client of one Connect origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectClient {
    url: RelayUrl,
}

impl ConnectClient {
    /// A client of `origin`: `https://` anywhere, `http://` on loopback only, no path.
    pub fn new(origin: &str) -> Result<Self, ConnectError> {
        let url = RelayUrl::parse(origin).map_err(|_| ConnectError::Invalid)?;
        Ok(Self { url })
    }

    /// A client of [`configured_origin`].
    pub fn configured() -> Result<Self, ConnectError> {
        Self::new(&configured_origin())
    }

    /// The origin, as the signed messages carry it: no trailing slash.
    pub fn origin(&self) -> &str {
        self.url.as_str()
    }

    fn send<T: DeserializeOwned>(&self, mut request: Request<'_>) -> Result<T, ConnectError> {
        request.deadline = Some(Instant::now() + CALL_DEADLINE);
        call(&self.url, &request).map_err(connect_error)
    }

    fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &impl Serialize,
    ) -> Result<T, ConnectError> {
        self.send(json_request("POST", path, bearer, body))
    }

    fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        bearer: Option<&str>,
    ) -> Result<T, ConnectError> {
        self.send(Request::new("GET", path.to_owned(), bearer))
    }

    // ---- Edge routes: no Authorization. ----

    pub(super) fn create_account(
        &self,
        body: &CreateAccount<'_>,
    ) -> Result<AccountCreated, ConnectError> {
        self.post("/v1/account", None, body)
    }

    pub(super) fn challenge(&self, body: &ChallengeRequest<'_>) -> Result<Challenge, ConnectError> {
        self.post("/v1/account/challenge", None, body)
    }

    /// The token call never repeats a body after `503 busy`: the nonce of a refused body
    /// stays unused, and the sign-in takes a fresh challenge instead. It is the only call
    /// whose `403 device_removed` is [`ConnectError::Revoked`]: Connect gives it to a valid
    /// signature of this device.
    pub(super) fn token(&self, body: &TokenRequest<'_>) -> Result<TokenAnswer, ConnectError> {
        let mut request = json_request("POST", "/v1/account/token", None, body);
        request.deadline = Some(Instant::now() + CALL_DEADLINE);
        call_without_busy_retries(&self.url, &request).map_err(|error| match error {
            ApiError::Relay {
                status: 403, code, ..
            } if code == "device_removed" => ConnectError::Revoked,
            other => connect_error(other),
        })
    }

    pub(super) fn join(&self, body: &JoinBody<'_>) -> Result<JoinAnswer, ConnectError> {
        self.post("/v1/account/devices/join", None, body)
    }

    pub(super) fn cancel_join(&self, body: &JoinCancel<'_>) -> Result<JoinId, ConnectError> {
        self.post("/v1/account/devices/join/cancel", None, body)
    }

    pub(super) fn recover(&self, body: &RecoverBody<'_>) -> Result<RecoverAnswer, ConnectError> {
        self.post("/v1/account/recover", None, body)
    }

    /// A public document: the JSON envelope of section 2, or the bare document (a
    /// `.well-known` file may be served as it is). Any other answer is an error.
    fn get_document<T: DeserializeOwned>(&self, path: &str) -> Result<T, ConnectError> {
        let mut request = Request::new("GET", path.to_owned(), None);
        request.deadline = Some(Instant::now() + CALL_DEADLINE);
        let answer =
            crate::sync::relay_http::exchange(&self.url, &request).map_err(
                |error| match error {
                    crate::sync::HttpError::Broken => ConnectError::Broken,
                    _ => ConnectError::Offline,
                },
            )?;
        let value: serde_json::Value =
            serde_json::from_slice(&answer.body).map_err(|_| ConnectError::Offline)?;
        if value.get("ok").is_some() {
            // The envelope: an error goes through the usual mapping.
            return call_answer(value, answer.status);
        }
        if answer.status != 200 {
            return Err(ConnectError::Offline);
        }
        serde_json::from_value(value).map_err(|_| ConnectError::BadAnswer)
    }

    /// `GET /.well-known/apassy-connect.json`: the public keys of the entitlement token.
    pub fn well_known(&self) -> Result<WellKnown, ConnectError> {
        self.get_document("/.well-known/apassy-connect.json")
    }

    /// `GET /v1/plans` (public): the plans and their prices.
    pub fn plans(&self) -> Result<PlansView, ConnectError> {
        self.get_document("/v1/plans")
    }

    // ---- Routes with the account token. ----

    pub(super) fn account(&self, token: &str) -> Result<AccountView, ConnectError> {
        self.get("/v1/account", Some(token))
    }

    pub(super) fn delete_account(&self, token: &str) -> Result<AccountDeleted, ConnectError> {
        self.send(json_request(
            "DELETE",
            "/v1/account",
            Some(token),
            &Empty {},
        ))
    }

    pub(super) fn link(&self, token: &str, link_hash: &str) -> Result<LinkAnswer, ConnectError> {
        self.post(
            "/v1/account/devices/link",
            Some(token),
            &LinkRequest { link_hash },
        )
    }

    pub(super) fn pending(&self, token: &str) -> Result<Vec<PendingView>, ConnectError> {
        self.get("/v1/account/devices/pending", Some(token))
    }

    pub(super) fn confirm(
        &self,
        token: &str,
        join_id: u64,
        public_key: &str,
        (version, statement): (u64, &str),
    ) -> Result<DeviceView, ConnectError> {
        self.post(
            &format!("/v1/account/devices/pending/{join_id}/confirm"),
            Some(token),
            &ConfirmRequest {
                public_key,
                version,
                statement,
            },
        )
    }

    pub(super) fn rotate_recovery(
        &self,
        token: &str,
        body: &RecoveryRotate<'_>,
    ) -> Result<RecoveryRotated, ConnectError> {
        self.post("/v1/account/recovery", Some(token), body)
    }

    pub(super) fn refuse(&self, token: &str, join_id: u64) -> Result<JoinId, ConnectError> {
        self.post(
            &format!("/v1/account/devices/pending/{join_id}/refuse"),
            Some(token),
            &Empty {},
        )
    }

    pub(super) fn revoke(
        &self,
        token: &str,
        device_id: &str,
        (version, statement): (u64, &str),
    ) -> Result<RevokeAnswer, ConnectError> {
        if !super::words::valid_device_id(device_id) {
            return Err(ConnectError::Invalid);
        }
        self.send(json_request(
            "DELETE",
            &format!("/v1/account/devices/{device_id}"),
            Some(token),
            &RevokeRequest { version, statement },
        ))
    }

    pub(super) fn create_vault_store(
        &self,
        token: &str,
        vault_id: &str,
        name: &str,
    ) -> Result<VaultStoreView, ConnectError> {
        self.post(
            "/v1/account/vaults",
            Some(token),
            &VaultCreate { vault_id, name },
        )
    }

    pub(super) fn vault_stores(&self, token: &str) -> Result<Vec<VaultStoreView>, ConnectError> {
        self.get("/v1/account/vaults", Some(token))
    }

    pub(super) fn add_store_device(
        &self,
        token: &str,
        team_id: &str,
        device_id: &str,
        public_key: &str,
    ) -> Result<StoreDevice, ConnectError> {
        if !crate::sync::relay_crypto::valid_team_id(team_id)
            || !super::words::valid_device_id(device_id)
        {
            return Err(ConnectError::Invalid);
        }
        self.post(
            &format!("/v1/account/vaults/{team_id}/devices"),
            Some(token),
            &StoreDeviceRequest {
                device_id,
                public_key,
            },
        )
    }

    pub(super) fn delete_vault_store(
        &self,
        token: &str,
        team_id: &str,
    ) -> Result<VaultDeleted, ConnectError> {
        if !crate::sync::relay_crypto::valid_team_id(team_id) {
            return Err(ConnectError::Invalid);
        }
        self.send(Request::new(
            "DELETE",
            format!("/v1/account/vaults/{team_id}"),
            Some(token),
        ))
    }

    pub(super) fn entitlement(&self, token: &str) -> Result<EntitlementAnswer, ConnectError> {
        self.get("/v1/account/entitlement", Some(token))
    }

    /// `POST /v1/tunnel/nodes` (connect-tunnel-v1 section 3.1): register the node of the
    /// calling device with its display name and the pin of its node certificate, or
    /// update both. The node's tunnel (`crate::node::tunnel`, plan s7 unit M4) calls it
    /// before it opens its WebSocket.
    pub fn register_node(
        &self,
        token: &str,
        name: &str,
        pin: &str,
    ) -> Result<TunnelNodeView, ConnectError> {
        self.post("/v1/tunnel/nodes", Some(token), &RegisterNode { name, pin })
    }
    // ---- Billing and groups (connect-billing-v1 sections 4 to 6, 8). ----

    pub(super) fn checkout(
        &self,
        token: &str,
        body: &CheckoutRequest,
    ) -> Result<CheckoutAnswer, ConnectError> {
        self.post("/v1/account/checkout", Some(token), body)
    }

    pub(super) fn portal(&self, token: &str) -> Result<PortalAnswer, ConnectError> {
        self.post("/v1/account/portal", Some(token), &Empty {})
    }

    pub(super) fn plan(&self, token: &str) -> Result<PlanView, ConnectError> {
        self.get("/v1/account/plan", Some(token))
    }

    pub(super) fn group(&self, token: &str) -> Result<GroupDetail, ConnectError> {
        self.get("/v1/account/group", Some(token))
    }

    pub(super) fn invite(&self, token: &str, role: &str) -> Result<InviteAnswer, ConnectError> {
        self.post(
            "/v1/account/group/invites",
            Some(token),
            &InviteRequest { role },
        )
    }

    pub(super) fn join_group(&self, token: &str, code: &str) -> Result<GroupJoined, ConnectError> {
        self.post(
            "/v1/account/group/join",
            Some(token),
            &GroupJoinRequest { code },
        )
    }

    pub(super) fn confirm_member(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<GroupMember, ConnectError> {
        if !super::words::valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        self.post(
            &format!("/v1/account/group/members/{account_id}/confirm"),
            Some(token),
            &Empty {},
        )
    }

    pub(super) fn remove_member(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<MemberRemoved, ConnectError> {
        if !super::words::valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        self.send(Request::new(
            "DELETE",
            format!("/v1/account/group/members/{account_id}"),
            Some(token),
        ))
    }

    pub(super) fn set_seats(
        &self,
        token: &str,
        quantity: u64,
    ) -> Result<SeatsAnswer, ConnectError> {
        self.post(
            "/v1/account/group/seats",
            Some(token),
            &SeatsRequest { quantity },
        )
    }
}
