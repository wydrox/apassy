//! The seam between the app and its embedded node (ADR 0037, cloud slice, decision 1).
//!
//! `NodeBackend::start` opens a node and `RunningNode` is the node while it runs. Both
//! are object-safe and use only the plain types of this file, so the root crate never
//! names a relay type. The relay crate implements them in `apassy_relay::embedded`.
//!
//! The model:
//!
//! - One node for each Mac user, in its own data directory, opened with a master key
//!   (the Keychain key of `node::master_key`).
//! - One personal team for each vault (`RunningNode::create_team`). The vault keeps the
//!   `NodeTeamId`; a restart of the node opens the team again (`has_team`).
//! - In that team, the catalog mirror: one item of metadata for each vault item that a
//!   cloud agent may see (`sync_items`). An item is named by its uid at this boundary.
//!   The node never stores a value: values come from the vault only at a release, in the
//!   order of the run's items (`release`).
//! - Cloud agents with an item list (`create_agent`). A bearer token now
//!   (`TokenIssue::Now`, the CLI fallback) is in the answer once; the node keeps only its
//!   hash. An agent of the MCP authorization flow (`TokenIssue::Later`) has no token until
//!   its client trades the code of an allowed connect request (`decide_connect`).
//! - Connect requests: a remote agent opens `/oauth/authorize`, the host loop sees the
//!   request in `pending_connects`, and the owner allows it for an agent or denies it
//!   (`decide_connect`).
//! - Runs: the host loop of the app waits for pending runs (`wait_pending`), decides each
//!   with the broker, and answers with `release` or `deny`.
//!
//! Times are seconds since the Unix epoch. Every method is safe to call from any thread.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

/// A secret text in memory: an item value, an agent token, or the master key. It is
/// erased on drop, its `Debug` is redacted, and it has no `Clone` and no `Serialize`.
pub struct NodeSecret(Zeroizing<String>);

impl NodeSecret {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// The text. Do not log it, format it, or put it in an error.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for NodeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeSecret(<redacted>)")
    }
}

/// An error of the node: a stable code and a message for a person. The codes are those
/// of the relay (docs/SPEC.md of the relay, "Errors"), such as `not_found`,
/// `not_granted`, `release_invalid`, `run_not_pending`, `team_limit`, `conflict`,
/// `invalid_request`, and `relay_error`. It never holds a value or a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeError {
    pub code: String,
    pub message: String,
}

impl NodeError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NodeError {}

/// A team of the node, such as `t_7k2m5q4x3c`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeTeamId(pub String);

/// A cloud agent of a team, as the node numbers it (not the vault's agent id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeAgentId(pub u64);

/// A run of a team, as the node numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeRunId(pub u64);

/// How to start a node.
#[derive(Debug)]
pub struct NodeConfig {
    /// The node's own data directory, such as `<app data>/node`. Made with mode 0700.
    pub data_dir: PathBuf,
    /// Opens the node's files. Text of at least 16 bytes, such as the hex of the
    /// Keychain key.
    pub master_key: NodeSecret,
    /// The origin that agents use, without a path: the Funnel origin
    /// `https://<DNSName>:8443`. Base URLs of sessions start with it.
    pub public_url: String,
    /// The loopback address of the public listener, the target of Funnel, such as
    /// `127.0.0.1:49200`; `None` for no public route. An address that is not on the
    /// loopback is refused.
    pub public_listen: Option<SocketAddr>,
}

/// Starts nodes. Implemented by the relay crate (`apassy_relay::embedded::EmbeddedRelay`)
/// and by the fakes of the tests.
pub trait NodeBackend: Send + Sync {
    /// Opens the data directory (made at the first start), opens its teams, and starts
    /// the listeners. A second node on the same directory is refused (`conflict`).
    fn start(&self, config: NodeConfig) -> Result<Box<dyn RunningNode>, NodeError>;
}

/// One item of the catalog mirror: metadata only, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogItem {
    /// 32 lowercase hex characters, chosen by the app and kept in the vault. It names
    /// the item at this boundary for its whole life: a change of the other fields keeps
    /// it.
    pub uid: String,
    /// 1 to 64 bytes, no control character.
    pub name: String,
    /// The variable of the item, `[A-Z_][A-Z0-9_]*`, unique among the live items.
    pub env_name: String,
    /// Host rules such as `api.stripe.com` or `api.example.com:8443`, at most 16. Empty:
    /// the known hosts of `provider`.
    pub hosts: Vec<String>,
    /// A core provider id, such as `stripe`.
    pub provider: Option<String>,
    /// `local`, `development`, `staging`, or `production`.
    pub environment: String,
    /// `low`, `medium`, or `high` (default `high`).
    pub risk: Option<String>,
    /// `read-only`, `read-write`, or `admin` (default `admin`).
    pub scope: Option<String>,
    /// `reversible`, `partial`, or `irreversible` (default `irreversible`).
    pub reversibility: Option<String>,
    /// A host that is a public suffix or a whole domain is refused unless this is true.
    pub allow_broad_host: bool,
}

/// What `RunningNode::sync_items` did. A second call with the same list adds, changes,
/// and archives nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub added: usize,
    /// Items whose fields changed. Their pending runs are denied and their sessions end.
    pub changed: usize,
    /// Items that left the list. Their pending runs are denied and their sessions end.
    pub archived: usize,
    pub unchanged: usize,
}

/// When a new cloud agent gets its bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenIssue {
    /// Now, in the answer, for 1 to 365 days: the CLI fallback
    /// (`apassy agents add-remote`).
    Now { lifetime_days: u32 },
    /// Later, from the MCP authorization flow: the agent has no live token until the
    /// owner allows a connect request for it and its client trades the code. Each access
    /// token then lives `ACCESS_TOKEN_SECS` of the relay (24 h) and is refreshed.
    Later,
}

/// A new cloud agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCloudAgent {
    /// 1 to 64 bytes, no control character.
    pub name: String,
    /// The uids of the live catalog items it may use, at most 500. It sees nothing else.
    /// An agent of the flow starts with none.
    pub items: Vec<String>,
    pub token: TokenIssue,
}

/// A cloud agent that was just made.
#[derive(Debug)]
pub struct CreatedAgent {
    pub agent_id: NodeAgentId,
    /// The bearer token of the agent, shown once (`TokenIssue::Now`); `None` for
    /// `TokenIssue::Later`. The node keeps only its hash.
    pub token: Option<NodeSecret>,
    /// When the token ends; for `TokenIssue::Later`, the time it was made (no token
    /// lives).
    pub expires_at: u64,
}

/// A connect request of the MCP authorization flow that waits for the owner. Its texts
/// come from the remote client: none of them is verified. The owner checks that the
/// browser page shows the same `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConnect {
    /// The id of the request, for `decide_connect`. Not a secret.
    pub id: String,
    /// The client that registered with the node (RFC 7591). It is public: an allowed
    /// connect always makes a new agent, also for a client id that has one.
    pub client_id: String,
    /// The name the client gave: cleaned, at most 64 bytes. `None`: the app says
    /// "MCP client".
    pub client_name: Option<String>,
    /// The match code on the browser page, such as `K7Q-4MD`.
    pub code: String,
    pub created_at: u64,
    /// When the request ends unanswered (300 s after it came).
    pub expires_at: u64,
    /// The host of the redirect URI of the request: where the browser goes back with the
    /// code, so the client that gets the connection. Lowercase, no port, an IPv6 address
    /// in brackets (`[::1]`). The owner's prompts show it
    /// (`crate::questions::envelope::connect_returns_to`; review 0.5.16). Empty when the
    /// node did not give one.
    pub redirect_host: String,
}

/// The owner's answer to a connect request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectDecision {
    /// Connect the client to this agent of this team (made with `TokenIssue::Later`, or
    /// the agent the client connected before).
    Allow {
        team: NodeTeamId,
        agent: NodeAgentId,
    },
    Deny,
}

/// How an agent reaches the node now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentAccess {
    /// The agent is revoked.
    pub revoked: bool,
    /// When its live bearer token ends; `None`: it has no live token now (not connected
    /// yet, expired, or dropped).
    pub token_expires_at: Option<u64>,
    /// The OAuth client of its live connection; `None`: no live connection of the flow
    /// (a CLI token, or not connected).
    pub client_id: Option<String>,
    /// When the live connection was made: the first token of its refresh family.
    pub connected_at: Option<u64>,
    /// When the refresh token of the live connection ends, unless the client refreshes.
    pub refresh_expires_at: Option<u64>,
}

/// The node's own verdict on a run, from the command analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suggestion {
    Allow,
    Ask,
}

/// One item of a pending run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingItem {
    pub uid: String,
    pub name: String,
    pub env_name: String,
}

/// A run that waits for the host. Its text fields are masked, and come from the agent:
/// none of them is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRun {
    pub run_id: NodeRunId,
    pub agent_id: NodeAgentId,
    /// The name of the agent.
    pub agent: String,
    /// In the order of the run: `release` takes one value for each, in this order.
    pub items: Vec<PendingItem>,
    pub command: Vec<String>,
    pub purpose: String,
    pub user_request: Option<String>,
    pub cwd: Option<String>,
    /// The session lifetime the agent asked for, in seconds.
    pub ttl_secs: u64,
    /// The flags of the command analysis.
    pub flags: Vec<String>,
    /// Why the node suggests what it suggests.
    pub note: String,
    pub suggestion: Suggestion,
    pub created_at: u64,
    /// When the run times out without an answer.
    pub expires_at: u64,
}

/// The status of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    /// Waits for the host.
    Pending,
    /// Released: its session is live until `session_expires_at`.
    Ready,
    /// Denied by the host, refused as `release_invalid`, or invalidated by a revocation.
    Denied,
    /// Nobody answered in time.
    TimedOut,
    /// The session ended (expired, revoked, or the node restarted).
    Ended,
}

/// A run as the node knows it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunState {
    pub run_id: NodeRunId,
    pub status: RunStatus,
    /// An error code for `Denied`, `TimedOut`, or an interrupted `Ended`.
    pub code: Option<String>,
    /// The note the agent sees: the reason of the host, or why the node decided.
    pub note: String,
    pub decided_at: Option<u64>,
    pub session_expires_at: Option<u64>,
}

/// One row of a team's audit. `detail` is JSON text, masked: never a value, a
/// placeholder, a token, or a session key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: u64,
    pub at: u64,
    /// For example `agent:3`, `host:embedded`, `member:1`, `relay`, or `edge`.
    pub actor: String,
    /// For example `run_requested`, `run_released`, `proxy_request`, `agent_revoked`.
    pub action: String,
    pub run_id: Option<NodeRunId>,
    pub detail: String,
}

/// A started node. `stop` ends every session, drops every run key, and joins its
/// threads; dropping it without `stop` leaves it running.
pub trait RunningNode: Send + Sync {
    /// The loopback address of the node listener (every route), for diagnostics.
    fn node_addr(&self) -> SocketAddr;

    /// The bound address of the public listener, if it has one.
    fn public_addr(&self) -> Option<SocketAddr>;

    /// Makes a personal team without a team code, with its catalog collection. The vault
    /// keeps the id.
    fn create_team(&self, name: &str) -> Result<NodeTeamId, NodeError>;

    /// True while the team is open: after a restart, the vault's team is open again.
    fn has_team(&self, team: &NodeTeamId) -> bool;

    /// The value rules of the node (`invalid_request` when a value breaks them): only an
    /// item whose value passes can be released. Nothing is stored.
    fn check_value(&self, value: &NodeSecret) -> Result<(), NodeError>;

    /// Makes the live catalog items of the team exactly `items`: adds the new ones,
    /// changes the ones whose fields differ, and archives the ones not in the list.
    fn sync_items(&self, team: &NodeTeamId, items: &[CatalogItem])
    -> Result<SyncReport, NodeError>;

    /// Makes a cloud agent that may use the listed items only, with a token now or later
    /// (`NewCloudAgent::token`).
    fn create_agent(
        &self,
        team: &NodeTeamId,
        agent: &NewCloudAgent,
    ) -> Result<CreatedAgent, NodeError>;

    /// Changes the item list of an agent. Its pending runs and sessions with an item
    /// that the list leaves out end.
    fn set_agent_items(
        &self,
        team: &NodeTeamId,
        agent: NodeAgentId,
        items: &[String],
    ) -> Result<(), NodeError>;

    /// Revokes an agent: its token stops at the next request, its pending runs are
    /// denied, and its sessions end. Its OAuth refresh families are revoked, and the open
    /// connect requests of its clients are denied.
    fn revoke_agent(&self, team: &NodeTeamId, agent: NodeAgentId) -> Result<(), NodeError>;

    /// The connect requests that wait for the owner, oldest first, on the whole node
    /// (every team). A request stays in the list until it is decided or ends (300 s).
    /// `wait_pending` returns early when this list changes. The default is for nodes
    /// without the flow: none.
    fn pending_connects(&self) -> Result<Vec<PendingConnect>, NodeError> {
        Ok(Vec::new())
    }

    /// Answers a connect request: `Allow` for a live agent of an open team (`not_found`
    /// otherwise), or `Deny`. A request that does not wait any more is
    /// `connect_not_pending`. The browser page shows the answer at its next refresh; an
    /// allowed one sends the client its code once.
    fn decide_connect(&self, id: &str, decision: ConnectDecision) -> Result<(), NodeError> {
        let _ = (id, decision);
        Err(NodeError::new(
            "not_supported",
            "This node has no connect requests.",
        ))
    }

    /// How an agent reaches the node now: its live token and its OAuth connection.
    /// `not_found` for an agent the team does not have.
    fn agent_access(
        &self,
        team: &NodeTeamId,
        agent: NodeAgentId,
    ) -> Result<AgentAccess, NodeError> {
        let _ = (team, agent);
        Err(NodeError::new(
            "not_supported",
            "This node does not report agent access.",
        ))
    }

    /// The runs that wait for the host, oldest first. While there is none, waits up to
    /// `timeout` for one, or until the node stops. A run stays in the list until it is
    /// released, denied, or timed out. It also returns early, maybe with an empty list,
    /// when the connect requests that wait change (`pending_connects`).
    fn wait_pending(
        &self,
        team: &NodeTeamId,
        timeout: Duration,
    ) -> Result<Vec<PendingRun>, NodeError>;

    /// Releases a pending run with the values of its items, `values[i]` for
    /// `PendingRun::items[i]`. Its one-time key is used up: a second call is
    /// `run_not_pending`. A value that breaks the rules, or a wrong count, denies the run
    /// with `release_invalid`. A revoked agent or a changed access denies it with
    /// `approval_invalidated` (an `Ok` with status `Denied`).
    fn release(
        &self,
        team: &NodeTeamId,
        run: NodeRunId,
        values: Vec<NodeSecret>,
        reason: Option<&str>,
    ) -> Result<RunState, NodeError>;

    /// Denies a pending run. The agent sees `reason` (at most 500 bytes).
    fn deny(&self, team: &NodeTeamId, run: NodeRunId, reason: &str) -> Result<RunState, NodeError>;

    /// The run now. A timeout or a session end that is due is applied first.
    fn run_state(&self, team: &NodeTeamId, run: NodeRunId) -> Result<RunState, NodeError>;

    /// The newest audit rows of the team, newest first, at most `limit` (1 to 500); with
    /// `run`, the rows of that run only.
    fn recent_audit(
        &self,
        team: &NodeTeamId,
        run: Option<NodeRunId>,
        limit: u32,
    ) -> Result<Vec<AuditRow>, NodeError>;

    /// Stops the listeners, ends every session, and drops every run key.
    fn stop(self: Box<Self>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_traits_are_object_safe_and_secrets_are_redacted() {
        fn takes(_: Option<&dyn NodeBackend>, _: Option<Box<dyn RunningNode>>) {}
        takes(None, None);
        let secret = NodeSecret::new("sk_test_synthetic_value_0123456789".to_string());
        assert_eq!(format!("{secret:?}"), "NodeSecret(<redacted>)");
        assert_eq!(secret.expose(), "sk_test_synthetic_value_0123456789");
        let error = NodeError::new("not_found", "No such run.");
        assert_eq!(error.to_string(), "not_found: No such run.");
    }
}
