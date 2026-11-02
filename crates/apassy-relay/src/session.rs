//! The interface between the server track and the proxy track.
//!
//! The server creates a `LiveSession` when the owner's host releases a run, and keeps
//! it in memory until it expires or a revocation ends it. The proxy finds the
//! session by the session key in the path `/p/<session key>/<host>/<path>`, swaps
//! placeholders for the values of its secrets, and reports each request back with
//! `SessionSource::record`. The server writes that event to the audit.

use std::sync::Arc;

use apassy::broker::proxy::HostRule;
use serde::Serialize;

use crate::ids::{AgentId, ItemId, MemberId, RunId, SessionId, TeamId};
use crate::secret::SecretString;

/// One variable of a session: a placeholder, its real value, and the hosts where
/// the value may go.
#[derive(Clone)]
pub struct SessionSecret {
    pub item_id: ItemId,
    /// The name of the variable in the run, for example `STRIPE_API_KEY`.
    pub env_name: String,
    /// The placeholder in the environment of the run. Same length as the value.
    pub placeholder: SecretString,
    /// The real value. Only the proxy reads it, to put it into an auth position.
    pub value: SecretString,
    /// The hosts of the item. The value goes only to a host that one of these covers.
    pub hosts: Vec<HostRule>,
}

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSecret")
            .field("item_id", &self.item_id)
            .field("env_name", &self.env_name)
            .field("placeholder", &"<redacted>")
            .field("value", &"<redacted>")
            .field("hosts", &self.hosts)
            .finish()
    }
}

/// One live proxy session: the released run of one agent.
#[derive(Debug, Clone)]
pub struct LiveSession {
    /// The team of the run. The session key names it too.
    pub team: TeamId,
    pub id: SessionId,
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub member_id: MemberId,
    /// Unix seconds. The session ends at this time.
    pub expires_at: u64,
    pub secrets: Vec<SessionSecret>,
}

impl LiveSession {
    pub fn is_live(&self, now: u64) -> bool {
        now < self.expires_at
    }

    /// True if a host of some secret of the session covers this host and port.
    pub fn covers_host(&self, host: &str, port: u16) -> bool {
        self.secrets
            .iter()
            .any(|secret| secret.hosts.iter().any(|rule| rule.covers(host, port)))
    }
}

/// How the proxy finds sessions and reports requests. The server implements it.
pub trait SessionSource: Send + Sync {
    /// The live session with this key, or `None` for an unknown, expired, or ended
    /// session. The server compares key hashes, not keys.
    fn find(&self, session_key: &str, now: u64) -> Option<Arc<LiveSession>>;

    /// Records one proxied or refused request. The server writes it to the audit.
    fn record(&self, event: ProxyEvent);
}

/// What happened to one request on the proxy path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyOutcome {
    /// Sent upstream; `status` is the upstream status.
    Forwarded,
    /// Refused by the relay; `code` says why; `status` is 403, 413 or 501.
    Refused,
    /// The upstream host failed; `status` is 502.
    UpstreamFailed,
}

/// One request on the proxy path, for the audit. It never holds a value, a
/// placeholder, a session key, a query string, a header, or a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyEvent {
    /// The team of the session. `None` when the session key was not found: such a
    /// request goes to the audit of the relay, not of a team. Not written in the row.
    #[serde(skip)]
    pub team: Option<TeamId>,
    /// `None` when the session key was not found.
    pub session_id: Option<SessionId>,
    pub run_id: Option<RunId>,
    pub agent_id: Option<AgentId>,
    pub at: u64,
    pub method: String,
    /// `host` or `host:port` from the path.
    pub host: String,
    /// The path after the host, without the query. `None` for a refused request.
    pub path: Option<String>,
    pub status: u16,
    pub outcome: ProxyOutcome,
    /// An error code of `error::codes` for a refused or failed request.
    pub code: Option<String>,
    /// The variables whose value went into this request.
    pub swapped: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> LiveSession {
        LiveSession {
            team: TeamId::parse("t_abcdefgh23").unwrap(),
            id: SessionId(1),
            run_id: RunId(2),
            agent_id: AgentId(3),
            member_id: MemberId(4),
            expires_at: 100,
            secrets: vec![SessionSecret {
                item_id: ItemId(5),
                env_name: "STRIPE_API_KEY".into(),
                placeholder: SecretString::new("sk_test_PLACEHOLDERxxxxxxxxxxxx".into()),
                value: SecretString::new("sk_test_CANARYVALUEyyyyyyyyyyyy".into()),
                hosts: vec![HostRule::parse("api.stripe.com").unwrap()],
            }],
        }
    }

    #[test]
    fn hosts_and_expiry() {
        let s = session();
        assert!(s.is_live(99));
        assert!(!s.is_live(100));
        assert!(s.covers_host("api.stripe.com", 443));
        assert!(!s.covers_host("api.stripe.com", 8443));
        assert!(!s.covers_host("evil.example", 443));
    }

    #[test]
    fn debug_hides_placeholder_and_value() {
        let shown = format!("{:?}", session());
        assert!(!shown.contains("CANARY"), "{shown}");
        assert!(!shown.contains("PLACEHOLDER"), "{shown}");
        assert!(shown.contains("STRIPE_API_KEY"));
    }
}
