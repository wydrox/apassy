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
    AgentId, AuditId, CollectionId, GrantId, InviteId, ItemId, MemberId, RunId, SessionId, TeamId,
};
use crate::secret::SecretString;

pub use apassy::agent::wire::{WireError, WireResponse as Envelope};

/// The secret the Worker adds to every request. The relay refuses a request without it.
pub const EDGE_HEADER: &str = "X-Apassy-Edge";
/// Set on every response that the relay itself makes on the proxy path:
/// `refused` (403, 413, 501) or `upstream-error` (502).
pub const RELAY_HEADER: &str = "X-Apassy-Relay";
/// The largest JSON request body on `/v1/*` and `/mcp`.
pub const MAX_JSON_BODY: usize = 64 * 1024;

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
}

/// `POST /v1/invites` (owner or manager; only the owner may invite a manager).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub role: Role,
    /// 1 to 168 hours. Default 72.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_hours: Option<u32>,
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
}

/// Write side of `TeamCreate`.
#[derive(Debug, Serialize)]
pub struct TeamCreateRef<'a> {
    pub code: &'a str,
    pub team: &'a str,
    pub owner: &'a str,
}

/// The result of `POST /v1/teams`. Read side.
#[derive(Debug, Deserialize)]
pub struct TeamCreated {
    pub team_id: TeamId,
    pub member_id: MemberId,
    /// The owner token. Shown once.
    pub secret: SecretString,
}

/// Write side of `TeamCreated`.
#[derive(Debug, Serialize)]
pub struct TeamCreatedRef<'a> {
    pub team_id: &'a TeamId,
    pub member_id: MemberId,
    pub secret: &'a str,
}

/// `POST /v1/join` (no bearer; edge secret only). Read side.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub code: SecretString,
    /// The member name, unique in the team. 1 to 64 bytes, letters, digits, `.-_`.
    pub name: String,
}

/// Write side of `JoinRequest`.
#[derive(Debug, Serialize)]
pub struct JoinRequestRef<'a> {
    pub code: &'a str,
    pub name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    pub id: MemberId,
    pub name: String,
    pub role: Role,
    pub created_at: u64,
    pub revoked: bool,
}

/// `GET /v1/invites`: invites without their codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteView {
    pub id: InviteId,
    pub role: Role,
    pub created_at: u64,
    pub expires_at: u64,
    pub used_by: Option<MemberId>,
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
    /// The session expired or was ended by a revocation.
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecidedBy {
    /// An owner or manager denied the run (nobody approves on the relay any more).
    Approver,
    /// A revocation invalidated the pending run.
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
    /// An error code for `denied` and `timed_out`.
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

#[cfg(test)]
mod tests {
    use super::*;

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
