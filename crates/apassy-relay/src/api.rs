//! Paths, headers, limits, and JSON bodies of the HTTP API (docs/SPEC.md, "HTTP API").
//!
//! Every JSON response is the core wire envelope: `{"ok":true,"result":...}` or
//! `{"ok":false,"error":{"code","message"}}`. The `result` types are below.
//!
//! A body that carries a secret has two types: an owning one with `SecretString`
//! that only implements `Deserialize`, and a borrowed `...Ref<'a>` that only
//! implements `Serialize`. The server reads the first; the CLI sends the second.
//! An item value is no such body any more: the CLI seals it, and the relay never
//! gets it. Binary fields (`sealed`, `host_key`, `nonce`, `sealed_keys`, `run_key`)
//! are base64url without padding.

use std::collections::BTreeMap;

use apassy::vault::ExecRule;
use serde::{Deserialize, Serialize};

use crate::ids::{
    AgentId, AuditId, CollectionId, DeviceId, GrantId, InviteId, ItemId, MemberId, RunId,
    SessionId, TeamId,
};
use crate::secret::SecretString;

pub use apassy::agent::wire::{WireError, WireResponse as Envelope};

/// The secret the Worker adds to every request. The relay refuses a request without it.
pub const EDGE_HEADER: &str = "X-Apassy-Edge";
/// The coarse prefix of the client (an IPv6 /48 or an IPv4 /24) that the Worker adds to
/// `POST /v1/connect`, after it removed any copy of the client. The relay reads it only
/// on that route, behind the edge secret, with `CLIENT_PREFIX_MAC_HEADER`, and keeps only
/// a salted hash of it in memory
/// (docs/SPEC.md section 26).
pub const CLIENT_PREFIX_HEADER: &str = "X-Apassy-Client-Prefix";
/// The Worker's HMAC of `CLIENT_PREFIX_HEADER` under the edge secret
/// (`server::connect::prefix_mac`). Without it the prefix is not taken.
pub const CLIENT_PREFIX_MAC_HEADER: &str = "X-Apassy-Client-Prefix-Mac";
/// Set on every response that the relay itself makes on the proxy path:
/// `refused` (403, 413, 501) or `upstream-error` (502).
pub const RELAY_HEADER: &str = "X-Apassy-Relay";
/// The largest JSON request body on `/v1/*` and `/mcp`.
pub const MAX_JSON_BODY: usize = 64 * 1024;
/// The largest body of `PUT /v1/feed` (docs/SPEC.md section 27): the base64url of a
/// 256 KiB sealed feed is 349526 characters.
pub const MAX_FEED_BODY: usize = 352 * 1024;

/// Limits of a run request (the same as the core `RunRequest::validate`).
pub const MAX_RUN_ITEMS: usize = 16;
pub const MAX_COMMAND_ARGS: usize = 64;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_PURPOSE_BYTES: usize = 500;
pub const MAX_USER_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_NAME_BYTES: usize = 64;

/// The tools of the remote MCP endpoint and of `apassy-team mcp`.
pub const TOOL_LIST_ACCESS: &str = "apassy_list_access";
pub const TOOL_REQUEST_RUN: &str = "apassy_request_run";
pub const TOOL_RUN_STATUS: &str = "apassy_run_status";

/// Paths. `{id}` is a decimal row id.
pub mod paths {
    pub const HEALTH: &str = "/healthz";
    pub const ME: &str = "/v1/me";
    pub const JOIN: &str = "/v1/join";
    pub const TEAMS: &str = "/v1/teams";
    /// `POST`: a codeless Connect team for one device key (section 26).
    pub const CONNECT: &str = "/v1/connect";
    /// Sign-in of a device (section 23).
    pub const AUTH_CHALLENGE: &str = "/v1/auth/challenge";
    pub const AUTH_TOKEN: &str = "/v1/auth/token";
    /// `GET`: devices; `DELETE /v1/devices/{id}`; `POST /v1/devices/{id}/key-holder`.
    pub const DEVICES: &str = "/v1/devices";
    pub const DEVICE_ENROLL: &str = "/v1/devices/enroll";
    /// `POST`: a link code (existing device); `GET`: links waiting for this member;
    /// `POST /v1/devices/links/{id}/confirm` and `/refuse`.
    pub const DEVICE_LINKS: &str = "/v1/devices/links";
    /// `POST`: a new device asks to join its member with a link code.
    pub const DEVICE_LINK: &str = "/v1/devices/link";
    /// `GET`: joins waiting for a confirmation; `POST /v1/joins/{id}/confirm` and `/refuse`.
    pub const JOINS: &str = "/v1/joins";
    pub const LEAVE: &str = "/v1/leave";
    pub const INVITES: &str = "/v1/invites";
    pub const MEMBERS: &str = "/v1/members";
    pub const COLLECTIONS: &str = "/v1/collections";
    pub const ITEMS: &str = "/v1/items";
    pub const GRANTS: &str = "/v1/grants";
    pub const AGENTS: &str = "/v1/agents";
    pub const APPROVALS: &str = "/v1/approvals";
    pub const AUDIT: &str = "/v1/audit";
    pub const ACCESS: &str = "/v1/access";
    pub const RUNS: &str = "/v1/runs";
    /// `GET /v1/host/requests`, `POST /v1/host/requests/{id}/release` and `/deny`.
    pub const HOST_REQUESTS: &str = "/v1/host/requests";
    /// `DELETE`: removes the vault snapshots of the team (docs/SPEC.md section 24).
    pub const SYNC: &str = "/v1/sync";
    /// `GET ?since=N&wait=S`: the current head, the chain, and the receipts.
    pub const SYNC_HEAD: &str = "/v1/sync/head";
    /// `GET ?version=N`: the snapshot bytes; `PUT`: a new snapshot with its head.
    pub const SYNC_SNAPSHOT: &str = "/v1/sync/snapshot";
    /// `POST`: this device merged a version.
    pub const SYNC_RECEIPT: &str = "/v1/sync/receipt";
    /// `POST`: a new question; `GET ?since=N&wait=S`: the questions routed to this device
    /// (docs/SPEC.md section 25). `/v1/questions/{qid}/answers` (`POST`, `GET
    /// ?after=N&wait=S`) and `/v1/questions/{qid}/settle` (`POST`) are under it.
    pub const QUESTIONS: &str = "/v1/questions";
    /// `PUT`: the APNs token of this device; `DELETE`: removes it.
    pub const PUSH_TOKEN: &str = "/v1/push/token";
    /// `PUT`: the sealed feed of this device; `DELETE`: removes it; `GET
    /// ?since=N&wait=S`: the feeds of the caller's member (docs/SPEC.md section 27).
    pub const FEED: &str = "/v1/feed";
    /// `POST`: an action to another device of the member; `GET ?after=N&wait=S`: the open
    /// actions to this device. `GET /v1/feed/actions/{id}?wait=S` (the sender) and `POST
    /// /v1/feed/actions/{id}/settle` (the target) are under it.
    pub const FEED_ACTIONS: &str = "/v1/feed/actions";
    pub const MCP: &str = "/mcp";
    /// `/p/<session key>/<host[:port]>/<path>`.
    pub const PROXY_PREFIX: &str = "/p/";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Created by `apassy-relay init`. Everything, and the only one who invites managers.
    Owner,
    /// Adds items, collections, grants; denies runs; reads the audit. Cannot approve a
    /// run: the keys are on the owner's host.
    Manager,
    /// Uses the collections granted to them through their agents.
    Member,
}

impl Role {
    pub fn is_approver(self) -> bool {
        matches!(self, Self::Owner | Self::Manager)
    }
}

/// How a team was made (docs/SPEC.md section 26). Fixed for the life of the team.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamKind {
    /// Made with a team code of the operator (`POST /v1/teams`, `apassy-relay init`,
    /// `migrate`).
    Operator,
    /// Made without a code by the app of one device (`POST /v1/connect`).
    Connect,
    /// A vault store of an Apassy Connect account (connect-account-v1 section 8): one
    /// vault's relay sync, made by `POST /v1/account/vaults`. Its devices are added by
    /// their account, never by an invite or a device link.
    Account,
}

impl TeamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Connect => "connect",
            Self::Account => "account",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Member,
    Agent,
}

/// `GET /v1/me`, for a member or an agent token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeView {
    pub team: String,
    /// The public id of the team (ADR 0019). `None` from a relay before teams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<TeamId>,
    pub kind: PrincipalKind,
    pub member_id: MemberId,
    pub member_name: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The device that signed in, for an access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// True when that device holds the item keys of the team.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub key_holder: bool,
    /// How the team was made (section 26). `None` from a relay before Connect teams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_kind: Option<TeamKind>,
}

/// `POST /v1/invites` (owner or manager; only the owner may invite a manager or an
/// owner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub role: Role,
    /// 1 to 168 hours. Default 72.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_hours: Option<u32>,
    /// The member name of the new member. When set, the joiner cannot choose another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Collections that the new member may use once the join is confirmed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<CollectionId>,
    /// A shared device (for example a family computer), not a person. Role member only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: bool,
}

/// A new secret for its receiver, sent once: an invite code, a member token after
/// `join`, or an agent token. Read side.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    /// The invite id, the member id, or the agent id.
    pub id: u64,
    pub secret: SecretString,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// Write side of `Issued`.
#[derive(Debug, Serialize)]
pub struct IssuedRef<'a> {
    pub id: u64,
    pub secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// `POST /v1/teams` (no bearer; edge secret only): a one-time team code of the
/// operator makes a new team and its owner. Read side.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamCreate {
    pub code: SecretString,
    /// The team name. 1 to 64 bytes, no control character.
    pub team: String,
    /// The owner's member name. 1 to 64 bytes, letters, digits, `.-_`.
    pub owner: String,
    /// The owner's first device. With it, the owner gets a device (the key holder) and
    /// no member token.
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Write side of `TeamCreate`.
#[derive(Debug, Serialize)]
pub struct TeamCreateRef<'a> {
    pub code: &'a str,
    pub team: &'a str,
    pub owner: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<&'a str>,
}

/// The result of `POST /v1/teams`. Read side.
#[derive(Debug, Deserialize)]
pub struct TeamCreated {
    pub team_id: TeamId,
    pub member_id: MemberId,
    /// The owner token, shown once, when the request had no device key. With a device
    /// key there is no member token: the device signs in (section 23).
    #[serde(default)]
    pub secret: Option<SecretString>,
    /// The owner's device, when the request had a device key. It holds the item keys.
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    /// `connect` in the answer of `POST /v1/connect`; absent from `POST /v1/teams`.
    #[serde(default)]
    pub kind: Option<TeamKind>,
}

/// Write side of `TeamCreated`.
#[derive(Debug, Serialize)]
pub struct TeamCreatedRef<'a> {
    pub team_id: &'a TeamId,
    pub member_id: MemberId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<TeamKind>,
}

/// `POST /v1/connect` (no bearer; edge secret only): the app of one device makes a
/// Connect team without a team code (section 26). The owner is the member `owner`; its
/// device holds the key. Nothing in it is a secret, so one type reads and writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectCreate {
    /// `1`.
    pub v: u32,
    /// The team name. 1 to 64 bytes, no control character.
    pub team: String,
    /// The name of the device, 1 to 64 bytes, no control character.
    pub device_name: String,
    /// The public key of the device, base64url (`device::decode_public_key`): a point
    /// on P-256. One key makes at most one Connect team, ever.
    pub public_key: String,
    /// The proof that the caller holds the key: base64url of an ECDSA P-256 SHA-256
    /// signature (ASN.1 DER) of `device::connect_message(origin, public_key)`.
    pub signature: String,
    /// A fresh nonce from `POST /v1/connect/challenge`. With it, `signature` signs
    /// `device::connect_recovery_message`; only an existing active team is returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_nonce: Option<String>,
}

/// An existence-independent recovery challenge; no team id is required or returned.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectChallenge {
    pub public_key: String,
}

/// `POST /v1/join` (no bearer; edge secret only). Read side. Since section 23 a join
/// carries the key of the joiner's device and waits for a confirmation. A body without
/// `device_name` and `public_key` (an old CLI) is refused with a message to update.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub code: SecretString,
    /// The member name, unique among the live members of the team. 1 to 64 bytes,
    /// letters, digits, `.-_`. Ignored when the invite sets a name.
    #[serde(default)]
    pub name: Option<String>,
    /// The name of the joiner's device, 1 to 64 bytes, no control character.
    #[serde(default)]
    pub device_name: Option<String>,
    /// The public key of the joiner's device, base64url (`device::decode_public_key`).
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Write side of `JoinRequest`.
#[derive(Debug, Serialize)]
pub struct JoinRequestRef<'a> {
    pub code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
    pub device_name: &'a str,
    pub public_key: &'a str,
}

// ---- Devices, sign-in, joins, and links (docs/SPEC.md section 23) ----

/// `POST /v1/auth/challenge` (edge only). The team comes from the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub team_id: TeamId,
    /// base64url, 65 bytes.
    pub public_key: String,
}

/// A one-time nonce to sign, valid for 60 seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// base64url, 32 bytes.
    pub nonce: String,
    pub expires_at: u64,
    /// The relay's own public URL. The client signs ITS configured URL; if this differs,
    /// the client says so instead of failing with a bare 401.
    pub origin: String,
}

/// `POST /v1/auth/token` (edge only): the signed nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    pub team_id: TeamId,
    pub public_key: String,
    pub nonce: String,
    /// base64url of the DER signature of `device::sign_in_message`.
    pub signature: String,
}

/// The access token of a device, 15 minutes. Read side.
#[derive(Debug, Deserialize)]
pub struct AccessGranted {
    pub token: SecretString,
    pub expires_at: u64,
    pub team_id: TeamId,
    pub team: String,
    pub member_id: MemberId,
    pub member_name: String,
    pub role: Role,
    pub device_id: DeviceId,
    pub key_holder: bool,
    /// How the team was made (section 26). `None` from a relay before Connect teams.
    #[serde(default)]
    pub team_kind: Option<TeamKind>,
}

/// Write side of `AccessGranted`.
#[derive(Debug, Serialize)]
pub struct AccessGrantedRef<'a> {
    pub token: &'a str,
    pub expires_at: u64,
    pub team_id: &'a TeamId,
    pub team: &'a str,
    pub member_id: MemberId,
    pub member_name: &'a str,
    pub role: Role,
    pub device_id: DeviceId,
    pub key_holder: bool,
    pub team_kind: TeamKind,
}

/// `POST /v1/devices/enroll` with a member token: the first device of that member.
/// The member token stops working once the device exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEnroll {
    pub name: String,
    pub public_key: String,
}

/// One device. Members see their own; the owner sees all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceView {
    pub id: DeviceId,
    pub member_id: MemberId,
    pub member_name: String,
    pub name: String,
    pub key_holder: bool,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<u64>,
    /// True for the device that made the request.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub current: bool,
    /// The 65-byte public key, base64url. A device checks sync heads with it.
    #[serde(default)]
    pub public_key: String,
}

/// `POST /v1/devices/links`: a one-time code for a new device of the same member, 10
/// minutes. Read side.
#[derive(Debug, Deserialize)]
pub struct LinkCreated {
    pub secret: SecretString,
    pub expires_at: u64,
}

/// Write side of `LinkCreated`.
#[derive(Debug, Serialize)]
pub struct LinkCreatedRef<'a> {
    pub secret: &'a str,
    pub expires_at: u64,
}

/// `POST /v1/devices/link` (edge only): a new device asks to join its member. Read side.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRequest {
    pub code: SecretString,
    pub device_name: String,
    pub public_key: String,
}

/// Write side of `LinkRequest`.
#[derive(Debug, Serialize)]
pub struct LinkRequestRef<'a> {
    pub code: &'a str,
    pub device_name: &'a str,
    pub public_key: &'a str,
}

/// `POST /v1/devices/link/cancel` (edge only): the new device takes back its pending
/// link before a confirmation, with the code and its key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkCancel {
    pub code: SecretString,
    pub public_key: String,
}

/// The answer to a join or a link: it waits for a confirmation. The joiner shows the
/// safety words and compares them with the confirmer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The id of the join or of the link.
    pub id: u64,
    pub team_id: TeamId,
    pub team: String,
    /// Two words (`device::safety_words`). The CLI checks them against its own.
    pub safety: String,
    pub expires_at: u64,
    /// The member that made the invite (a join) or that owns the device (a link).
    pub by: String,
}

/// `GET /v1/joins`: a join that waits for an owner or a manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinView {
    pub id: u64,
    pub name: String,
    pub device_name: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: bool,
    /// The names of the collections that the invite grants.
    pub grants: Vec<String>,
    pub invited_by: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `POST /v1/joins/{id}/confirm`: the new member and its device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinConfirmed {
    pub member_id: MemberId,
    pub device_id: DeviceId,
}

/// `GET /v1/devices/links`: a link that waits on a device of this member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkView {
    pub id: u64,
    pub device_name: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// The key of the waiting device, base64url, so the confirming device computes the
    /// safety words itself.
    #[serde(default)]
    pub public_key: String,
}

/// `POST /v1/joins/{id}/confirm` and `POST /v1/devices/links/{id}/confirm`: the two
/// safety words that the joiner or the new device shows. The relay refuses the
/// confirmation (409) if they differ, so the confirmer must get them from that person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRequest {
    pub safety: String,
}

/// `PUT /v1/members/{id}/role` (owner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleChange {
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    pub id: MemberId,
    pub name: String,
    pub role: Role,
    pub created_at: u64,
    pub revoked: bool,
    /// A shared device, not a person.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: bool,
    /// The number of live devices. 0 for a member that still signs in with a member token.
    #[serde(default)]
    pub devices: u64,
}

/// `GET /v1/invites`: invites without their codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteView {
    pub id: InviteId,
    pub role: Role,
    pub created_at: u64,
    pub expires_at: u64,
    pub used_by: Option<MemberId>,
    /// When a join arrived with this invite (section 23). The invite is used from then on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// The relay suggests a release for a known-safe command, and asks for the rest.
    #[default]
    Bouncer,
    /// The relay suggests asking a person for every run.
    Ask,
}

/// The policy of a collection. "Production always waits" is not a setting: it is
/// always on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub mode: PolicyMode,
    /// The hard rules of the core (`ExecRule::normalized` checks them).
    pub rule: ExecRule,
}

/// `POST /v1/collections` (owner or manager).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionCreate {
    pub name: String,
    #[serde(default)]
    pub policy: Policy,
}

/// `PUT /v1/collections/{id}/policy` body is a `Policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionView {
    pub id: CollectionId,
    pub name: String,
    pub policy: Policy,
    pub item_count: u64,
    pub created_at: u64,
}

/// `POST /v1/items` (owner or manager). The value is sealed in the CLI with an item
/// key that stays on the owner's host (docs/SPEC.md, "Host-held item keys"). A body
/// with a `value` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewItem {
    pub collection_id: CollectionId,
    pub name: String,
    /// `[A-Z_][A-Z0-9_]*`, checked with the core `checked_env_name`.
    pub env_name: String,
    /// 16 random bytes as 32 lowercase hex characters. It names the item on the host.
    pub uid: String,
    /// `nonce(12) || AES-256-GCM(item key, nonce, value, aad)`, base64url. The relay
    /// checks only its length: 12 + 16 + 1 to 4096 bytes after decoding.
    pub sealed: String,
    /// A core provider id, for example `stripe`. Its known hosts are the default hosts.
    #[serde(default)]
    pub provider: Option<String>,
    /// Hosts such as `api.stripe.com` or `api.example.com:8443`. Required when the
    /// provider has no hosts. At most 16.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// `local`, `development`, `staging`, or `production`.
    pub environment: String,
    /// `low`, `medium`, `high`. Default `high`.
    #[serde(default)]
    pub risk: Option<String>,
    /// `read-only`, `read-write`, `admin`. Default `admin`.
    #[serde(default)]
    pub scope: Option<String>,
    /// `reversible`, `partial`, `irreversible`. Default `irreversible`.
    #[serde(default)]
    pub reversibility: Option<String>,
    /// A host rule covers the host and every subdomain. A host that is a public
    /// suffix or a whole registrable domain (`example.com`) is refused unless this is
    /// true. A known host of the provider is not broad.
    #[serde(default)]
    pub allow_broad_host: bool,
}

/// Write side of `NewItem`.
#[derive(Debug, Serialize)]
pub struct NewItemRef<'a> {
    pub collection_id: CollectionId,
    pub name: &'a str,
    pub env_name: &'a str,
    pub uid: &'a str,
    pub sealed: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<&'a str>,
    pub hosts: Vec<String>,
    pub environment: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<&'a str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_broad_host: bool,
}

/// An item without its sealed value. Members see the items of their granted collections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemView {
    pub id: ItemId,
    pub collection_id: CollectionId,
    pub collection: String,
    pub name: String,
    pub env_name: String,
    pub provider: Option<String>,
    pub hosts: Vec<String>,
    pub environment: String,
    pub risk: String,
    pub scope: String,
    pub reversibility: String,
    pub created_at: u64,
}

/// `POST /v1/grants` (owner or manager).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCreate {
    pub collection_id: CollectionId,
    pub member_id: MemberId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub id: GrantId,
    pub collection_id: CollectionId,
    pub collection: String,
    pub member_id: MemberId,
    pub member: String,
    pub created_at: u64,
}

/// `POST /v1/agents` (any member, for themselves).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCreate {
    pub name: String,
    /// 1 to 365. Default 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentView {
    pub id: AgentId,
    pub member_id: MemberId,
    pub name: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// The result of a create call that returns only an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Created {
    pub id: u64,
}

/// The result of `POST /v1/items`: the id and the hosts the value may go to. Each
/// host covers its subdomains too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemCreated {
    pub id: u64,
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// `POST /v1/runs` (agent token), and the MCP tool `apassy_request_run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    /// 1 to 16 distinct item ids.
    pub items: Vec<ItemId>,
    /// The argv the agent will run. 1 to 64 args, each at most 4096 bytes, no NUL.
    pub command: Vec<String>,
    /// Why, in the agent's words. 1 to 500 bytes after trim.
    pub purpose: String,
    /// The user's request that led to this run. Without it the run waits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_request: Option<String>,
    /// The working directory, for the audit only. Absolute if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Session lifetime in seconds, 60 to the relay maximum. Default: the relay TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Waits for the owner's host to release the keys of the items.
    Pending,
    /// Released by the owner's host; the session is live and `session` is set.
    Ready,
    /// Denied by the host or an approver, refused as `release_invalid`, or invalidated
    /// by a revocation. `code` says which.
    Denied,
    /// No one decided in time (no host, or no answer). `code` is `approval_timeout`.
    TimedOut,
    /// The session expired/ended, or a restart discarded a pending run key.
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecidedBy {
    /// An owner or manager denied the run (nobody approves on the relay any more).
    Approver,
    /// A revocation or restart invalidated the pending run.
    Revocation,
    /// No decision in time.
    Timeout,
    /// The owner's host released the keys, or refused, or sent a release that did
    /// not check (`release_invalid`).
    Host,
}

/// The environment of a live session. Only the agent that asked for the run gets it.
/// It holds placeholders and base URLs with the session key: not values, but still
/// not for logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: SessionId,
    pub expires_at: u64,
    /// Variable name to value: each item's placeholder and every base URL variable.
    pub env: BTreeMap<String, String>,
    /// The names in `env` that hold a placeholder.
    pub placeholders: Vec<String>,
    /// Host (`host` or `host:port`) to its base URL on the relay.
    pub base_urls: BTreeMap<String, String>,
}

/// `POST /v1/runs` and `GET /v1/runs/{id}` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunView {
    pub run_id: RunId,
    pub status: RunStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<DecidedBy>,
    /// The name of the approver that denied the run, when `decided_by` is `approver`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    /// An error code for `denied`, `timed_out`, or restart-interrupted `ended`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Why: the relay's verdict while the run waits, then the reason of the host or
    /// the approver.
    pub note: String,
    /// The flags of the analysis.
    pub flags: Vec<String>,
    pub created_at: u64,
    /// When a pending run times out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionView>,
}

/// An item in an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalItem {
    pub id: ItemId,
    pub name: String,
    pub collection: String,
    pub environment: String,
}

/// `GET /v1/approvals` (owner or manager): pending runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub agent: String,
    pub member: String,
    pub items: Vec<ApprovalItem>,
    pub command: Vec<String>,
    pub purpose: String,
    pub user_request: Option<String>,
    pub cwd: Option<String>,
    pub flags: Vec<String>,
    pub note: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `POST /v1/approvals/{run_id}/deny` and `POST /v1/host/requests/{run_id}/deny`. The
/// approve endpoint answers `approve_on_host` whatever the body is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    /// At most 500 bytes. Shown to the agent in `RunView.note`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What the relay itself would do with a run: the verdict of its own analysis. The
/// owner's host decides anyway, and runs its own check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Suggestion {
    /// A known safe command, no rule asked.
    Allow,
    /// A person should decide.
    Ask,
}

/// An item in a host request. The host looks the `uid` up in its own key store and
/// trusts its own metadata for the item, not the relay's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostItem {
    pub uid: String,
    pub id: ItemId,
    pub name: String,
    pub env_name: String,
}

/// `GET /v1/host/requests` (owner token): a pending run that waits for the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRequestView {
    pub run_id: RunId,
    pub agent: String,
    pub member: String,
    pub items: Vec<HostItem>,
    pub command: Vec<String>,
    pub purpose: String,
    pub user_request: Option<String>,
    pub cwd: Option<String>,
    pub ttl_secs: u64,
    pub flags: Vec<String>,
    pub suggestion: Suggestion,
    /// The note of the relay's own verdict.
    pub note: String,
    /// The one-time X25519 public key of this run, base64url. The host seals the
    /// keys of the items of this run to it.
    pub run_key: String,
    pub expires_at: u64,
}

/// `POST /v1/host/requests/{run_id}/release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    /// The one-time X25519 public key of the host, 32 bytes.
    pub host_key: String,
    /// 12 bytes.
    pub nonce: String,
    /// AES-256-GCM of `{"run_id":N,"keys":[{"uid","key"}]}`.
    pub sealed_keys: String,
    /// At most 500 bytes. Shown to the agent in `RunView.note`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `GET /v1/audit?after=<id>&limit=<n>` (owner or manager).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: AuditId,
    pub at: u64,
    /// `member:<id>`, `agent:<id>`, `relay`, or `edge` (an unauthenticated request).
    pub actor: String,
    /// For example `run_requested`, `run_released`, `proxy_request`, `grant_revoked`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// Masked: never a value, a placeholder, a token, or a session key.
    pub detail: serde_json::Value,
}

/// One item in `GET /v1/access` and the MCP tool `apassy_list_access`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessItem {
    pub item_id: ItemId,
    pub item_name: String,
    pub collection: String,
    pub env_name: String,
    pub hosts: Vec<String>,
    pub environment: String,
    /// The base URL variables a run gets for this item.
    pub base_url_vars: Vec<String>,
    /// In words: when the owner's host asks the owner about a run with this item.
    pub approval: String,
    pub rule: ExecRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessView {
    pub agent_id: AgentId,
    pub agent: String,
    pub member: String,
    pub items: Vec<AccessItem>,
    pub note: String,
}

/// One head of the chain in `SyncHeadView`. The public key of `device_id` is in
/// `SyncHeadView::signers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncChainEntry {
    pub version: u64,
    /// The head text, base64url.
    pub head: String,
    /// The DER signature of the head text, base64url.
    pub signature: String,
    pub device_id: DeviceId,
    /// The relay's clock at the push.
    pub pushed_at: u64,
}

/// A device that signed a head of a `SyncHeadView`, with its public key. A removed
/// device stays here for the heads it pushed while it was a member: a client accepts
/// its signature only on a head whose version is at most `last_version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSigner {
    pub device_id: DeviceId,
    /// The 65-byte public key, base64url.
    pub public_key: String,
    /// True when the device or its member was removed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removed: bool,
    /// For a removed device: the newest version it pushed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_version: Option<u64>,
}

/// The newest version that a live device reported as merged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReceipt {
    pub device_id: DeviceId,
    pub device_name: String,
    pub version: u64,
    pub at: u64,
}

/// `GET /v1/sync/head` and the answer of `PUT /v1/sync/snapshot` (docs/SPEC.md section
/// 24.4). Version 0 has no head fields. A client takes every value from the head text it
/// verified, never from the unsigned fields next to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncHeadView {
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_at: Option<u64>,
    /// The heads of the versions after `since`, oldest first, at most 1000. With
    /// more, the client asks again from the last one.
    pub chain: Vec<SyncChainEntry>,
    /// The version of the first chain entry. Absent when the chain is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_from: Option<u64>,
    pub receipts: Vec<SyncReceipt>,
    /// The devices that signed the current head and the chain entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<SyncSigner>,
}

/// `POST /v1/sync/receipt`: this device merged `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRequest {
    pub version: u64,
}

/// `POST /v1/questions` (docs/SPEC.md section 25.4). The relay never opens the
/// ciphertext; it checks only the forms and the sizes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionPost {
    pub v: u64,
    /// 16 random bytes of the asker, base64url: 22 characters.
    pub qid: String,
    /// `member` or `approvers`.
    pub to: String,
    pub expires_at: u64,
    /// 16 lowercase hex characters.
    pub key_id: String,
    /// 12 bytes, base64url.
    pub nonce: String,
    /// base64url, not empty.
    pub ciphertext: String,
}

/// `POST /v1/questions/{qid}/answers` and `POST /v1/questions/{qid}/settle`: one sealed
/// envelope under the question's key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePost {
    pub v: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// `PUT /v1/push/token`: the APNs device token of the calling device.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushTokenPut {
    /// Lowercase hex, 32 to 200 characters.
    pub token: String,
    /// `development` or `production`: the `aps-environment` of the build.
    pub environment: String,
    /// Must equal the relay's push topic.
    pub bundle_id: String,
}

/// A sealed envelope in an answer of the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedView {
    pub key_id: String,
    /// base64url.
    pub nonce: String,
    /// base64url.
    pub ciphertext: String,
}

/// One question in `GET /v1/questions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionView {
    pub qid: String,
    pub seq: u64,
    /// `member` or `approvers`.
    pub to: String,
    pub from_device_id: DeviceId,
    pub from_device_name: String,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// `open`, `settled`, or `expired`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle: Option<SealedView>,
}

/// `GET /v1/questions?since=N&wait=S`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionList {
    /// The team's question sequence now. Below the caller's `since`: the relay was
    /// restored from a backup, read again from 0.
    pub seq: u64,
    pub questions: Vec<QuestionView>,
}

/// One answer in `GET /v1/questions/{qid}/answers`, stamped by the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerView {
    pub id: u64,
    pub device_id: DeviceId,
    pub member_id: MemberId,
    pub role: Role,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub at: u64,
}

/// `GET /v1/questions/{qid}/answers?after=N&wait=S`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerList {
    pub state: String,
    pub expires_at: u64,
    pub answers: Vec<AnswerView>,
}

/// `PUT /v1/feed` (docs/SPEC.md section 27.4): the sealed feed of the calling device.
/// The relay never opens it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedPut {
    pub v: u64,
    /// 1 to 2^53 - 1, higher than the device's last one.
    pub seq: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// One feed in `GET /v1/feed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedView {
    pub device_id: DeviceId,
    /// The relay's name of the device, for a log only.
    pub device_name: String,
    pub seq: u64,
    pub change: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub updated_at: u64,
}

/// `GET /v1/feed?since=N&wait=S`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedList {
    /// The team's feed counter now. Below the caller's `since`: the relay was restored
    /// from a backup, read again from 0.
    pub change: u64,
    /// True when the answer stopped at its size: ask again at once with the `change` of
    /// the last feed.
    pub more: bool,
    /// Every device of the member that has a feed now.
    pub present: Vec<DeviceId>,
    pub feeds: Vec<FeedView>,
}

/// `POST /v1/feed/actions`: a sealed action to another device of the caller's member.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPost {
    pub v: u64,
    /// 16 random bytes of the sender, base64url: 22 characters.
    pub action_id: String,
    pub to_device: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// `POST /v1/feed/actions/{id}/settle`: the outcome in clear and its sealed settle.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSettle {
    pub v: u64,
    /// `applied`, `refused`, or `stale`.
    pub outcome: String,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// One open action in `GET /v1/feed/actions`, stamped by the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionView {
    pub action_id: String,
    pub seq: u64,
    pub from_device_id: DeviceId,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `GET /v1/feed/actions?after=N&wait=S`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionList {
    /// The team's action sequence now. Below the caller's `after`: read again from 0.
    pub seq: u64,
    pub actions: Vec<ActionView>,
}

/// `GET /v1/feed/actions/{id}?wait=S`, for the sending device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionStatus {
    pub action_id: String,
    pub to_device: DeviceId,
    /// `open`, `settled`, or `expired`.
    pub state: String,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle: Option<SealedView>,
}

// ---- Apassy Connect accounts (connect-account-v1, docs/SPEC.md "Connect accounts"). ----
//
// Every request body is strict: unknown, duplicate, and missing fields are refused with
// 400 `invalid_request`. Results are what the contract lists, nothing more.

/// A platform of an account device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Mac,
    Iphone,
    Linux,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Iphone => "iphone",
            Self::Linux => "linux",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "mac" => Some(Self::Mac),
            "iphone" => Some(Self::Iphone),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }
}

/// `POST /v1/account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCreate {
    pub name: String,
    pub device_name: String,
    pub platform: Platform,
    pub public_key: String,
    /// The Ed25519 public key of the recovery code (b64u, 32 bytes): only it reaches
    /// Connect (`device::RecoveryKey`).
    pub recovery_key: String,
    pub signature: String,
}

/// `POST /v1/account` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreated {
    pub account_id: String,
    pub device_id: String,
    pub created_at: u64,
}

/// `POST /v1/account/challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountChallengeRequest {
    pub account_id: String,
    pub public_key: String,
}

/// `POST /v1/account/token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountTokenRequest {
    pub account_id: String,
    pub public_key: String,
    pub nonce: String,
    pub signature: String,
}

/// `POST /v1/account/token` answer: the account token, 15 minutes, in memory only.
#[derive(Debug, Clone, Serialize)]
pub struct AccountTokenRef<'a> {
    pub token: &'a str,
    pub expires_at: u64,
    pub account_id: &'a str,
    pub device_id: &'a str,
}

/// A live device of an account. Whether it is a device of the account is the signed
/// device list's to say ([`ListEntry`]), not this row's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDevice {
    pub device_id: String,
    pub name: String,
    pub platform: Platform,
    pub public_key: String,
    pub created_at: u64,
    /// Rounded down to the hour, or `None`.
    pub last_seen_at: Option<u64>,
}

/// What one entry of the signed device list does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListOp {
    /// Version 1: the account's root key (the first device, or the device of the last
    /// recovery).
    Root,
    /// A device is added, through a link, by a device of the list.
    Add,
    /// A device of the list is removed by a device of the list (also itself).
    Remove,
}

impl ListOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Add => "add",
            Self::Remove => "remove",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "root" => Some(Self::Root),
            "add" => Some(Self::Add),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }
}

/// One entry of the signed device list of an account (connect-account-v1 section 7.5):
/// `by` signed the `apassy-connect device-list v1` message of `version`, the hash of the
/// entry before, `op`, `key`, and `link_hash`. The root entry (version 1) has no
/// signature: its key is the root that each device pinned itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEntry {
    pub version: u64,
    pub op: ListOp,
    /// b64u of the key that the entry adds or removes (the root key for `root`).
    pub key: String,
    /// The link of an `add`, else `None`.
    pub link_hash: Option<String>,
    /// b64u of the key that signed the entry (the root key for `root`).
    pub by: String,
    /// b64u of the DER signature, `None` for `root`.
    pub signature: Option<String>,
}

/// The plan of an account (connect-billing-v1 section 8). Billing (C2) fills it; without
/// a subscription it is [`PlanView::none`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanView {
    /// `personal`, `family`, `team`, or `None`.
    pub plan: Option<String>,
    /// `none`, `pending`, `active`, `trialing`, `past_due`, `read_only`, or `suspended`.
    pub status: String,
    pub entitled: bool,
    pub interval: Option<String>,
    pub quantity: Option<u64>,
    pub renews_at: Option<u64>,
    pub ends_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub read_only_until: Option<u64>,
    pub delete_at: Option<u64>,
    pub group_id: Option<String>,
}

impl PlanView {
    /// An account without a plan.
    pub fn none() -> Self {
        Self {
            plan: None,
            status: "none".to_string(),
            entitled: false,
            interval: None,
            quantity: None,
            renews_at: None,
            ends_at: None,
            grace_until: None,
            read_only_until: None,
            delete_at: None,
            group_id: None,
        }
    }

    /// Pulls and downloads of the vault stores work (section 8 of connect-billing-v1):
    /// an entitled plan, or `read_only`.
    pub fn can_pull(&self) -> bool {
        self.entitled || self.status == "read_only"
    }
}

/// The group of an account in `AccountView` (connect-billing-v1 section 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountGroup {
    pub group_id: String,
    /// `family` or `team`.
    pub kind: String,
    /// `owner`, `admin`, or `member`.
    pub role: String,
    /// `pending` or `active`.
    pub state: String,
}

/// `GET /v1/account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    pub account_id: String,
    pub name: String,
    pub email: Option<String>,
    pub created_at: u64,
    pub plan: PlanView,
    pub devices: Vec<AccountDevice>,
    pub group: Option<AccountGroup>,
    /// The signed device list, from version 1.
    pub device_list: Vec<ListEntry>,
}

/// An empty JSON object: `DELETE /v1/account`, a refusal of a join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

/// `DELETE /v1/account` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDeleted {
    pub account_id: String,
    pub deleted_stores: u64,
    pub subscription_canceled: bool,
}

/// `POST /v1/account/devices/link`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLinkRequest {
    pub link_hash: String,
}

/// `POST /v1/account/devices/link` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLinkCreated {
    pub link_id: u64,
    pub expires_at: u64,
}

/// One pending join of a link that the calling device made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPendingJoin {
    pub join_id: u64,
    pub link_id: u64,
    pub device_name: String,
    pub platform: Platform,
    pub public_key: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `POST /v1/account/devices/pending/{join_id}/confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfirm {
    pub public_key: String,
    /// The version of the new entry of the device list: the head's version and 1.
    pub version: u64,
    /// The `add` entry: b64u of the caller's DER signature over the
    /// `apassy-connect device-list v1` message of `version`, the head's hash, this key,
    /// and the join's link.
    pub statement: String,
}

/// `DELETE /v1/account/devices/{device_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRevoke {
    /// The version of the new entry of the device list: the head's version and 1.
    pub version: u64,
    /// The `remove` entry: b64u of the caller's DER signature over the
    /// `apassy-connect device-list v1` message of `version`, the head's hash, and the
    /// removed device's key.
    pub statement: String,
}

/// `POST /v1/account/devices/join`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountJoin {
    pub account_id: String,
    pub link_hash: String,
    pub device_name: String,
    pub platform: Platform,
    pub public_key: String,
    pub signature: String,
}

/// The device that confirms a join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountConfirmer {
    pub device_id: String,
    pub name: String,
    pub public_key: String,
}

/// `POST /v1/account/devices/join` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountJoined {
    pub join_id: u64,
    pub account_id: String,
    pub confirmer: AccountConfirmer,
    pub expires_at: u64,
    /// The signed device list of the account, from version 1: the new device checks that
    /// the confirmer is a device of it.
    pub device_list: Vec<ListEntry>,
}

/// `POST /v1/account/devices/join/cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountJoinCancel {
    pub account_id: String,
    pub link_hash: String,
    pub public_key: String,
    /// The joining key's signature over `apassy-connect join-cancel v1`.
    pub signature: String,
}

/// `{"join_id": …}`: a refusal or a cancel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountJoinId {
    pub join_id: u64,
}

/// `DELETE /v1/account/devices/{device_id}` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRevoked {
    pub device_id: String,
    pub removed_from_stores: u64,
}

/// `POST /v1/account/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultStoreCreate {
    pub vault_id: String,
    pub name: String,
}

/// A device in a vault store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreDevice {
    pub store_device_id: u64,
    pub device_id: String,
    pub account_id: String,
}

/// A vault store: a relay-sync-v1 team of kind `account` for one vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStoreView {
    pub team_id: TeamId,
    pub vault_id: String,
    pub name: String,
    pub created_at: u64,
    pub shared: bool,
    pub devices: Vec<StoreDevice>,
}

/// `POST /v1/account/vaults/{team_id}/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreDeviceAdd {
    pub device_id: String,
    /// The key of that device as the caller verified it: the device is added only when
    /// it is this key.
    pub public_key: String,
}

/// `DELETE /v1/account/vaults/{team_id}` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStoreDeleted {
    pub team_id: TeamId,
}

/// `POST /v1/account/recover`. The recovery code never travels: the account's recovery
/// key signs the request (`recovery_signature`), and `recovery_key` is the next one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecover {
    pub account_id: String,
    pub device_name: String,
    pub platform: Platform,
    pub public_key: String,
    pub recovery_key: String,
    /// The new device key's DER signature over the recover message.
    pub signature: String,
    /// The current recovery key's Ed25519 signature (64 bytes, b64u) over the same message.
    pub recovery_signature: String,
}

/// `POST /v1/account/recover` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecovered {
    pub account_id: String,
    pub device_id: String,
    pub deleted_stores: u64,
}

/// `GET /v1/account/entitlement` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementAnswer {
    pub token: String,
    pub expires_at: u64,
}

/// A published key of `GET /.well-known/apassy-connect.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownKey {
    pub kid: String,
    pub alg: String,
    pub public_key: String,
}

/// `GET /.well-known/apassy-connect.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnown {
    pub v: u8,
    pub origin: String,
    pub keys: Vec<WellKnownKey>,
}

// ---- The Connect tunnel (docs/contracts/connect-tunnel-v1.md sections 3 and 6). ----

/// `POST /v1/tunnel/nodes`: the node of the calling device, its name and its pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelNodeRegister {
    pub name: String,
    pub pin: String,
}

/// The `NodeView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// `DELETE /v1/tunnel/nodes/{node_id}` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelNodeDeleted {
    pub node_id: String,
}

/// `POST /v1/tunnel/grants`: the node of the caller's account and the grantee account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelGrantRequest {
    pub node_id: String,
    pub account_id: String,
}

/// The `GrantView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelGrantView {
    pub grant_id: String,
    pub node_id: String,
    pub account_id: String,
    pub created_at: u64,
}

/// `DELETE /v1/tunnel/grants/{grant_id}` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelGrantDeleted {
    pub grant_id: String,
    pub closed_streams: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_head_view_of_an_empty_team_has_three_fields() {
        let empty = SyncHeadView {
            version: 0,
            head: None,
            signature: None,
            device_id: None,
            device_name: None,
            pushed_at: None,
            chain: vec![],
            chain_from: None,
            receipts: vec![],
            signers: vec![],
        };
        assert_eq!(
            serde_json::to_string(&empty).unwrap(),
            r#"{"version":0,"chain":[],"receipts":[]}"#
        );
        assert!(serde_json::from_str::<ReceiptRequest>(r#"{"version":1,"x":2}"#).is_err());
    }

    #[test]
    fn run_request_refuses_unknown_fields() {
        let good = r#"{"items":[1],"command":["stripe","balance","retrieve"],"purpose":"check"}"#;
        let request: RunRequest = serde_json::from_str(good).unwrap();
        assert_eq!(request.items, vec![ItemId(1)]);
        let bad = r#"{"items":[1],"command":["ls"],"purpose":"x","path":"/usr/bin"}"#;
        assert!(serde_json::from_str::<RunRequest>(bad).is_err());
    }

    #[test]
    fn new_item_round_trip_through_the_two_sides() {
        let uid = "0123456789abcdef0123456789abcdef";
        let sent = NewItemRef {
            collection_id: CollectionId(1),
            name: "Stripe test",
            env_name: "STRIPE_API_KEY",
            uid,
            sealed: "c2VhbGVkLWJ5dGVz",
            provider: Some("stripe"),
            hosts: vec![],
            environment: "staging",
            risk: None,
            scope: None,
            reversibility: None,
            allow_broad_host: false,
        };
        let text = serde_json::to_string(&sent).unwrap();
        assert!(!text.contains("allow_broad_host"), "{text}");
        let read: NewItem = serde_json::from_str(&text).unwrap();
        assert_eq!(
            (read.uid.as_str(), read.sealed.as_str()),
            (uid, "c2VhbGVkLWJ5dGVz")
        );
        assert!(!read.allow_broad_host);
        let text = serde_json::to_string(&NewItemRef {
            allow_broad_host: true,
            ..sent
        })
        .unwrap();
        let read: NewItem = serde_json::from_str(&text).unwrap();
        assert!(read.allow_broad_host);
    }

    #[test]
    fn new_item_with_a_value_is_refused() {
        let old_client = r#"{"collection_id":1,"name":"n","env_name":"K_KEY","value":"sk_test_x","uid":"0123456789abcdef0123456789abcdef","sealed":"AAAA","environment":"staging"}"#;
        assert!(serde_json::from_str::<NewItem>(old_client).is_err());
        let no_uid = r#"{"collection_id":1,"name":"n","env_name":"K_KEY","value":"sk_test_x","environment":"staging"}"#;
        assert!(serde_json::from_str::<NewItem>(no_uid).is_err());
    }

    #[test]
    fn issued_round_trip_and_policy_default() {
        let text = serde_json::to_string(&IssuedRef {
            id: 3,
            secret: "apassy_agt_x",
            expires_at: Some(10),
        })
        .unwrap();
        let read: Issued = serde_json::from_str(&text).unwrap();
        assert_eq!((read.id, read.secret.expose()), (3, "apassy_agt_x"));
        let policy: Policy = serde_json::from_str("{}").unwrap();
        assert_eq!(policy.mode, PolicyMode::Bouncer);
        let status = serde_json::to_string(&RunStatus::TimedOut).unwrap();
        assert_eq!(status, "\"timed_out\"");
    }
}
