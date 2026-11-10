//! The one error type of the relay, and every error code on the HTTP API.
//!
//! An error body is the core wire envelope:
//! `{"ok":false,"error":{"code":"...","message":"..."}}` (see `api::Envelope`).
//! A message never holds a value, a placeholder, a token, or a session key.

use apassy::agent::wire::WireResponse;

/// Every error code the relay sends. The HTTP status is in `status_of`.
pub mod codes {
    // Request shape and routing.
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const NOT_FOUND: &str = "not_found";
    pub const METHOD_NOT_ALLOWED: &str = "method_not_allowed";
    pub const PAYLOAD_TOO_LARGE: &str = "payload_too_large";
    pub const CONFLICT: &str = "conflict";
    // Edge and identity.
    pub const EDGE_REFUSED: &str = "edge_refused";
    pub const UNAUTHENTICATED: &str = "unauthenticated";
    pub const TOKEN_EXPIRED: &str = "token_expired";
    pub const FORBIDDEN: &str = "forbidden";
    pub const INVITE_INVALID: &str = "invite_invalid";
    // Access to items.
    pub const NOT_GRANTED: &str = "not_granted";
    pub const ITEM_ARCHIVED: &str = "item_archived";
    pub const PLACEHOLDER_IMPOSSIBLE: &str = "placeholder_impossible";
    pub const BROAD_HOST: &str = "broad_host";
    // Hard rules (the same codes as the core broker).
    pub const RULE_EXPIRED: &str = "rule_expired";
    pub const RULE_COMMAND_NOT_PERMITTED: &str = "rule_command_not_permitted";
    pub const RULE_FORBIDDEN_WORD: &str = "rule_forbidden_word";
    pub const RULE_RATE_LIMIT: &str = "rule_rate_limit";
    // Approvals (in `RunView.code`, not as HTTP errors).
    pub const APPROVAL_DENIED: &str = "approval_denied";
    pub const APPROVAL_TIMEOUT: &str = "approval_timeout";
    pub const APPROVAL_INVALIDATED: &str = "approval_invalidated";
    pub const RUN_NOT_PENDING: &str = "run_not_pending";
    /// `POST /v1/approvals/{id}/approve`: the keys are on the owner's host.
    pub const APPROVE_ON_HOST: &str = "approve_on_host";
    /// A release from the host did not open or did not match the run. The run is
    /// denied. Also the `RunView.code` of that run.
    pub const RELEASE_INVALID: &str = "release_invalid";
    /// Sign-in of a device whose join or link waits for a confirmation.
    pub const JOIN_PENDING: &str = "join_pending";
    /// Sign-in of a device whose join or link was refused or expired.
    pub const JOIN_REFUSED: &str = "join_refused";
    /// A host endpoint called by a device that does not hold the item keys.
    pub const NOT_KEY_HOLDER: &str = "not_key_holder";
    // Proxy.
    pub const SESSION_INVALID: &str = "session_invalid";
    pub const HOST_NOT_IN_SESSION: &str = "host_not_in_session";
    pub const MISPLACED_PLACEHOLDER: &str = "misplaced_placeholder";
    pub const WRONG_HOST: &str = "wrong_host";
    pub const PLACEHOLDER_IN_BODY: &str = "placeholder_in_body";
    pub const NOT_SUPPORTED: &str = "not_supported";
    pub const UPSTREAM_FAILED: &str = "upstream_failed";
    pub const ENCODED_RESPONSE: &str = "encoded_response";
    // Load.
    /// Pending run whose one-time key was discarded at restart.
    pub const RUN_INTERRUPTED: &str = "run_interrupted";
    pub const BUSY: &str = "busy";
    pub const TEAM_LIMIT: &str = "team_limit";
    // Vault sync (docs/SPEC.md section 24).
    /// A push whose head fails a check. The message names the check.
    pub const SYNC_HEAD_INVALID: &str = "sync_head_invalid";
    /// `If-Match` does not name the current version. The answer has `ETag`.
    pub const PRECONDITION_FAILED: &str = "precondition_failed";
    // Questions and push (docs/SPEC.md section 25).
    /// An answer from a device outside the routing set of the question, or from the
    /// asking device itself.
    pub const NOT_ROUTED: &str = "not_routed";
    /// The team has `open_questions` open questions, or posted `questions_per_hour`.
    /// 403, not 429: the app holds every call to the relay after a 429.
    pub const TOO_MANY_QUESTIONS: &str = "too_many_questions";
    /// The device already posted 3 answers to this question.
    pub const TOO_MANY_ANSWERS: &str = "too_many_answers";
    /// An answer to a settled question, or a settle with another envelope.
    pub const QUESTION_SETTLED: &str = "question_settled";
    /// An answer or a settle after `expires_at`.
    pub const QUESTION_EXPIRED: &str = "question_expired";
    /// `PUT /v1/push/token` on a relay without push, or `PUT /v1/push/handle` on a relay
    /// without a push gateway.
    pub const PUSH_UNAVAILABLE: &str = "push_unavailable";
    /// `PUT /v1/push/handle` with a gateway that is not one of the node's
    /// (push-gateway-v1 section 10), so a device cannot make the node call an arbitrary
    /// address.
    pub const PUSH_GATEWAY_REFUSED: &str = "push_gateway_refused";
    // Connect teams (docs/SPEC.md section 26).
    /// A snapshot push to a team whose `sync_bytes` is 0: vault sync through the relay
    /// is not in the team's plan.
    pub const PLAN_REQUIRED: &str = "plan_required";
    /// `POST /v1/connect` with a public key that made a Connect team before.
    pub const CONNECT_KEY_USED: &str = "connect_key_used";
    /// Too many requests: `POST /v1/connect` from one client prefix in a day, or a
    /// Connect team over its requests per minute. `Retry-After` says when to try again.
    pub const RATE_LIMITED: &str = "rate_limited";
    // The feed of a Mac and its actions (docs/SPEC.md section 27).
    /// A feed within 10 s of the device's last accepted feed, or one that would pass the
    /// team's `feed_bytes`. 403, not 429: the app's other calls go on.
    pub const FEED_LIMIT: &str = "feed_limit";
    /// `feed_actions_per_hour` of the team, or too many open actions of the team or of
    /// the sending device.
    pub const TOO_MANY_ACTIONS: &str = "too_many_actions";
    /// `GET /v1/feed` of a device that read its feed text of the minute. 403, not 429:
    /// the app's other calls go on.
    pub const FEED_RATE: &str = "feed_rate";
    /// `PUT /v1/feed` with a `seq` at or below the stored `seq` of the device.
    pub const SEQ_NOT_NEWER: &str = "seq_not_newer";
    /// A settle of a settled action with another body.
    pub const ACTION_SETTLED: &str = "action_settled";
    /// A settle after the action's `expires_at`.
    pub const ACTION_EXPIRED: &str = "action_expired";
    // Shared team vaults turned off on this relay (ADR 0037, D8).
    /// A run, MCP, the proxy, a host release, or a new collection, item, grant, or team
    /// agent on a relay with `APASSY_RELAY_TEAM_VAULTS=0`. 410: the feature is gone here,
    /// and a retry does not help.
    pub const TEAM_VAULTS_RETIRED: &str = "team_vaults_retired";
    // Apassy Connect accounts (connect-account-v1 section 4, docs/SPEC.md "Connect accounts").
    /// A Connect route that needs a live account device, called with a relay-sync team
    /// token, or for a store that is not a vault store.
    pub const ACCOUNT_REQUIRED: &str = "account_required";
    /// A device of another account, and the two accounts share no group; a group route
    /// or call by an account that is not in the group.
    pub const NOT_IN_GROUP: &str = "not_in_group";
    /// A count limit of the account: devices, vault stores, nodes.
    pub const ACCOUNT_LIMIT: &str = "account_limit";
    // Connect billing and groups (docs/contracts/connect-billing-v1.md).
    /// A count of people or seats outside `1 ≤ n ≤ max` of the plan, or below the
    /// active members of the group.
    pub const SEAT_LIMIT: &str = "seat_limit";
    // The Connect tunnel (docs/contracts/connect-tunnel-v1.md).
    /// A dial or a grant names a node that does not exist.
    pub const NODE_UNKNOWN: &str = "node_unknown";
    /// Open streams, dials a minute, or the monthly byte budget of the account.
    pub const TUNNEL_LIMIT: &str = "tunnel_limit";
    /// The node exists and has no open tunnel.
    pub const TUNNEL_OFFLINE: &str = "tunnel_offline";
    // Anything else.
    pub const RELAY_ERROR: &str = "relay_error";
}

/// The HTTP status of an error code. Unknown codes are 500.
pub fn status_of(code: &str) -> u16 {
    use codes::*;
    match code {
        INVALID_REQUEST | PLACEHOLDER_IMPOSSIBLE | BROAD_HOST => 400,
        UNAUTHENTICATED | TOKEN_EXPIRED => 401,
        EDGE_REFUSED
        | FORBIDDEN
        | INVITE_INVALID
        | NOT_GRANTED
        | ITEM_ARCHIVED
        | RULE_EXPIRED
        | RULE_COMMAND_NOT_PERMITTED
        | RULE_FORBIDDEN_WORD
        | RULE_RATE_LIMIT
        | SESSION_INVALID
        | HOST_NOT_IN_SESSION
        | MISPLACED_PLACEHOLDER
        | WRONG_HOST
        | PLACEHOLDER_IN_BODY
        | APPROVE_ON_HOST
        | RELEASE_INVALID
        | TEAM_LIMIT
        | JOIN_PENDING
        | JOIN_REFUSED
        | NOT_KEY_HOLDER
        | SYNC_HEAD_INVALID
        | NOT_ROUTED
        | TOO_MANY_QUESTIONS
        | TOO_MANY_ANSWERS
        | PLAN_REQUIRED
        | FEED_LIMIT
        | FEED_RATE
        | TOO_MANY_ACTIONS
        | ACCOUNT_REQUIRED
        | NOT_IN_GROUP
        | ACCOUNT_LIMIT => 403,
        NOT_FOUND | NODE_UNKNOWN => 404,
        METHOD_NOT_ALLOWED => 405,
        CONFLICT | RUN_NOT_PENDING | QUESTION_SETTLED | QUESTION_EXPIRED | PUSH_UNAVAILABLE
        | PUSH_GATEWAY_REFUSED | CONNECT_KEY_USED | SEQ_NOT_NEWER | ACTION_SETTLED
        | ACTION_EXPIRED | SEAT_LIMIT => 409,
        TEAM_VAULTS_RETIRED => 410,
        PRECONDITION_FAILED => 412,
        PAYLOAD_TOO_LARGE => 413,
        RATE_LIMITED | TUNNEL_LIMIT => 429,
        NOT_SUPPORTED => 501,
        UPSTREAM_FAILED | ENCODED_RESPONSE => 502,
        BUSY | TUNNEL_OFFLINE => 503,
        _ => 500,
    }
}

/// An error with a stable code and a short message for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayError {
    pub code: &'static str,
    pub message: String,
}

pub type RelayResult<T> = Result<T, RelayError>;

impl RelayError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, message)
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            codes::UNAUTHENTICATED,
            "The token is missing, unknown, or revoked.",
        )
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(codes::FORBIDDEN, message)
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(codes::NOT_FOUND, format!("No such {what}."))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(codes::RELAY_ERROR, message)
    }

    /// The HTTP status of this error.
    pub fn status(&self) -> u16 {
        status_of(self.code)
    }

    /// The JSON body of this error.
    pub fn to_envelope(&self) -> WireResponse {
        WireResponse::failure(self.code, self.message.clone())
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RelayError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_statuses() {
        assert_eq!(RelayError::unauthenticated().status(), 401);
        assert_eq!(
            RelayError::new(codes::MISPLACED_PLACEHOLDER, "x").status(),
            403
        );
        assert_eq!(RelayError::new(codes::UPSTREAM_FAILED, "x").status(), 502);
        assert_eq!(RelayError::new(codes::BUSY, "x").status(), 503);
        assert_eq!(RelayError::new(codes::APPROVE_ON_HOST, "x").status(), 403);
        assert_eq!(RelayError::new(codes::RELEASE_INVALID, "x").status(), 403);
        assert_eq!(RelayError::new(codes::TEAM_LIMIT, "x").status(), 403);
        assert_eq!(RelayError::new(codes::SYNC_HEAD_INVALID, "x").status(), 403);
        for code in [
            codes::NOT_ROUTED,
            codes::TOO_MANY_QUESTIONS,
            codes::TOO_MANY_ANSWERS,
            codes::PLAN_REQUIRED,
            codes::FEED_LIMIT,
            codes::FEED_RATE,
            codes::TOO_MANY_ACTIONS,
        ] {
            assert_eq!(RelayError::new(code, "x").status(), 403);
        }
        for code in [
            codes::QUESTION_SETTLED,
            codes::QUESTION_EXPIRED,
            codes::PUSH_UNAVAILABLE,
            codes::PUSH_GATEWAY_REFUSED,
            codes::CONNECT_KEY_USED,
            codes::SEQ_NOT_NEWER,
            codes::ACTION_SETTLED,
            codes::ACTION_EXPIRED,
        ] {
            assert_eq!(RelayError::new(code, "x").status(), 409);
        }
        assert_eq!(
            RelayError::new(codes::PRECONDITION_FAILED, "x").status(),
            412
        );
        assert_eq!(RelayError::new(codes::RATE_LIMITED, "x").status(), 429);
        assert_eq!(RelayError::new(codes::NODE_UNKNOWN, "x").status(), 404);
        assert_eq!(RelayError::new(codes::TUNNEL_LIMIT, "x").status(), 429);
        assert_eq!(RelayError::new(codes::TUNNEL_OFFLINE, "x").status(), 503);
        assert_eq!(RelayError::internal("x").status(), 500);
        assert_eq!(status_of("something_new"), 500);
    }

    #[test]
    fn envelope_has_code_and_message() {
        let body = serde_json::to_value(RelayError::not_found("item").to_envelope()).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["message"], "No such item.");
    }
}
