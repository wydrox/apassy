//! Broker wire format version 0. One JSON object per line on the Unix socket.
//!
//! The request has no URL, header, SQL, or secret field. The agent names an
//! item, a named operation, and text parameters. The broker adds the secret.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    Read,
    Change,
    Deploy,
    Delete,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessScope {
    pub action: AccessAction,
    pub hosts: Vec<String>,
}

pub const WIRE_VERSION: u32 = 0;
/// Code-bearing requests require a new version: older brokers must reject them,
/// rather than silently ignoring a selector and running without code approval.
pub const CODE_WIRE_VERSION: u32 = 1;
/// Largest request line in bytes, including the newline.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Largest response line in bytes. A run response carries masked process output.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Largest user prompt that a host hook sends, in bytes (goal item B6).
pub const MAX_HOOK_PROMPT_BYTES: usize = 32 * 1024;

/// Error codes of the access model of ADR 0025 (`docs/contracts/broker-v0.md`).
pub mod codes {
    /// The agent may not use the item: a "Not for this agent" exception, an item that
    /// is not on the list of an agent with "only these items", or no such item. The
    /// code is the same in each case, so it does not tell which items exist.
    pub const NOT_GRANTED: &str = "not_granted";
    /// Another question of this agent waits for the owner, or a newer identical call
    /// took over the waiting question. The same request again joins the waiting question
    /// (or asks again, when a credential changed after the question showed).
    pub const QUESTION_WAITING: &str = "question_waiting";
    /// The owner answered "Allow ACTION in PROJECT" or "Allow production", and Apassy
    /// could not save the answer. The command did not run.
    pub const ANSWER_FAILED: &str = "answer_failed";
    /// ADR 0025 §6: the item was not created by this agent with capture, generate, or
    /// save. The code is the same for an item that does not exist.
    pub const NOT_OWNER: &str = "not_owner";
    /// ADR 0025 §6: this agent added or changed the most items in the last hour. Apassy
    /// refused; the agent asks the owner.
    pub const TOO_MANY_ITEMS: &str = "too_many_items";
    /// ADR 0025 §6: this agent has the most open or new credential requests in the last
    /// hour.
    pub const TOO_MANY_REQUESTS: &str = "too_many_requests";
    /// Apassy refused to capture: the command, the file, or the output does not meet the
    /// capture rules. The text never has a part of the output.
    pub const CAPTURE_REFUSED: &str = "capture_refused";
    /// The owner denied the question of a run or a capture.
    pub const APPROVAL_DENIED: &str = "approval_denied";
    /// The owner did not answer the question within its time (5 minutes).
    pub const APPROVAL_TIMEOUT: &str = "approval_timeout";
    /// The vault was locked or replaced while the question waited.
    pub const APPROVAL_INVALIDATED: &str = "approval_invalidated";
    /// The owner has not answered a credential request yet. The request stays open; the
    /// same request again waits again.
    pub const WAITING: &str = "waiting";
    /// The owner dismissed the credential request.
    pub const DISMISSED: &str = "dismissed";
}

/// A secret value that an agent sends with `save_credential`. Debug never shows it, and
/// it is erased on drop. It is a plain JSON string on the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentSecret(String);

impl AgentSecret {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for AgentSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for AgentSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AgentSecret([redacted])")
    }
}

impl Serialize for AgentSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AgentSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// How Apassy makes a new value (ADR 0025 §6, `generate_credential`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateSpec {
    /// 16 to 128 characters. Default 32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// `alnum` (default), `hex`, `base64url`, or `symbols`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alphabet: Option<String>,
}

/// Which part of a captured output is the credential (ADR 0025 §6). The broker applies it
/// before it stores the value; the agent never sees the output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Extract {
    /// A dot path in JSON output, such as `Credentials.SessionToken` or `items.0.key`.
    Json(String),
    /// One line, from 1.
    Line(u32),
    /// The rest of the first line that holds this text, such as `Token:`.
    After(String),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub v: u32,
    pub token: String,
    /// The agent host session of the sender, if the sender knows it (goal item B6).
    /// Claude Code gives its MCP servers and hooks the session ID. The broker uses it
    /// to find the user request that the host hook sent for the same session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_session: Option<String>,
    pub action: Action,
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireRequest")
            .field("v", &self.v)
            .field("token", &"[redacted]")
            .field("host_session", &self.host_session)
            .field("action", &self.action)
            .finish()
    }
}

/// The agent token is erased on drop.
impl Drop for WireRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl ZeroizeOnDrop for WireRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// Execute once, retaining a value-free outcome in the broker across reconnects.
    Tracked {
        operation_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
        action: Box<Action>,
    },
    OperationStatus {
        operation_id: String,
    },
    CancelOperation {
        operation_id: String,
    },
    /// List the items and named operations that the owner permits for this agent.
    ListAccess,
    AccessRequestStatus {
        request_id: u64,
    },
    CancelAccessRequest {
        request_id: u64,
    },
    /// Run one named operation with one stored credential.
    Call {
        item_id: u64,
        operation: String,
        #[serde(default)]
        params: BTreeMap<String, String>,
    },
    /// Run one command with vault items in its environment (ADR 0006).
    /// The broker starts the process. The response never contains a secret value.
    Run {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_request_id: Option<u64>,
        items: Vec<u64>,
        /// Item IDs whose current TOTP code enters the process, never the seed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        codes: Vec<u64>,
        command: Vec<String>,
        cwd: String,
        purpose: String,
        /// `PATH` for the process. The adapter sends its own `PATH`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// The user's words that led to this request (ADR 0008). The agent supplies it,
        /// so it is a claim. The owner sees it in the approval card.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_request: Option<String>,
    },
    /// Ask the owner for process access to one item that the agent sees (ADR 0012).
    /// The broker records the request and answers at once. The owner decides in the app.
    RequestAccess {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<AccessScope>,
        item_id: u64,
        /// Why the agent needs the item. The owner reads it.
        reason: String,
        /// The working directory where the agent wants to use the item.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
    },
    /// The user prompt from a host hook, for example Claude Code `UserPromptSubmit`
    /// (goal item B6). `apassy-hook` sends it. The broker keeps it in memory and uses
    /// it as the user request of later runs in the same host session.
    SubmitUserRequest {
        /// Host name for the owner: `claude-code` or `codex`. It is a label only.
        host: String,
        /// The working directory of the host session.
        cwd: String,
        /// The user prompt. It is cut at [`MAX_HOOK_PROMPT_BYTES`] when `truncated` is set.
        prompt: String,
        /// The host transcript file. The broker checks the prompt in this file.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transcript_path: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        truncated: bool,
    },
    /// ADR 0025 §6: run one command (no secret in its environment) or read one file, and
    /// save the output as a new credential. Exactly one of `command` and `file`. The
    /// output never comes back.
    CaptureCredential {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        /// The working directory of the command and the project of the new item.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// A folder path as the catalog shows it, such as `Work / Stripe`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
        /// `PATH` for a command that the owner approves. A known token command never
        /// uses it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// The part of the output to store. Default: the whole output, trimmed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extract: Option<Extract>,
    },
    /// ADR 0025 §6: Apassy makes a random value and saves it. The value never comes back.
    GenerateCredential {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alphabet: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
    },
    /// ADR 0025 §6: save a value that the agent already has. The value is already in the
    /// transcript of the agent; capture is better.
    SaveCredential {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        value: AgentSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
    },
    /// ADR 0025 §6: ask the owner to paste a credential. The call waits like a question.
    AskOwnerForCredential {
        name: String,
        purpose: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        where_to_get: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
    },
    /// ADR 0025 §6: a new value for an item that this agent created, by capture or by
    /// generation. Exactly one of `command`, `file`, and `generate`.
    UpdateCredential {
        item_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generate: Option<GenerateSpec>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// For `command` or `file`: the part of the output to store.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extract: Option<Extract>,
    },
    /// ADR 0025 §6: change the name, the notes, the variable, or the hosts of an item
    /// that this agent created.
    DescribeCredential {
        item_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_name: Option<String>,
        /// HTTPS hosts of a placeholder: only for an API key or a login.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        placeholder_hosts: Option<Vec<String>>,
    },
}

impl Action {
    pub fn wire_version(&self) -> u32 {
        match self {
            Self::Run { codes, .. } if !codes.is_empty() => CODE_WIRE_VERSION,
            Self::Tracked { action, .. } => action.wire_version(),
            _ => WIRE_VERSION,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Tracked { .. } => "tracked",
            Self::OperationStatus { .. } => "operation_status",
            Self::CancelOperation { .. } => "cancel_operation",
            Self::ListAccess => "list_access",
            Self::AccessRequestStatus { .. } => "access_request_status",
            Self::CancelAccessRequest { .. } => "cancel_access_request",
            Self::Call { .. } => "call",
            Self::Run { .. } => "run",
            Self::RequestAccess { .. } => "request_access",
            Self::SubmitUserRequest { .. } => "submit_user_request",
            Self::CaptureCredential { .. } => "capture_credential",
            Self::GenerateCredential { .. } => "generate_credential",
            Self::SaveCredential { .. } => "save_credential",
            Self::AskOwnerForCredential { .. } => "ask_owner_for_credential",
            Self::UpdateCredential { .. } => "update_credential",
            Self::DescribeCredential { .. } => "describe_credential",
        }
    }

    /// The action can wait for the owner or for a process, so a client waits longer.
    pub fn waits(&self) -> bool {
        matches!(
            self,
            Self::Run { .. }
                | Self::CaptureCredential { .. }
                | Self::AskOwnerForCredential { .. }
                | Self::UpdateCredential { .. }
        )
    }

    pub fn trackable(&self) -> bool {
        !matches!(
            self,
            Self::ListAccess
                | Self::AccessRequestStatus { .. }
                | Self::CancelAccessRequest { .. }
                | Self::SubmitUserRequest { .. }
                | Self::Tracked { .. }
                | Self::OperationStatus { .. }
                | Self::CancelOperation { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: String,
    pub message: String,
}

impl WireResponse {
    pub fn success(result: Value) -> Self {
        Self {
            operation_id: None,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            operation_id: None,
            ok: false,
            result: None,
            error: Some(WireError {
                code: code.to_owned(),
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_unknown_fields_and_redacts_token() {
        let text = r#"{"v":0,"token":"apassy_agt_x","action":{"kind":"call","item_id":1,"operation":"op","params":{"a":"b"}}}"#;
        let request: WireRequest = serde_json::from_str(text).expect("valid request");
        assert!(!format!("{request:?}").contains("apassy_agt_x"));
        let extra = r#"{"v":0,"token":"t","action":{"kind":"call","item_id":1,"operation":"op","url":"http://x"}}"#;
        assert!(serde_json::from_str::<WireRequest>(extra).is_err());
        let nested = r#"{"v":0,"token":"t","action":{"kind":"call","item_id":1,"operation":"op","params":{"a":{"b":1}}}}"#;
        assert!(serde_json::from_str::<WireRequest>(nested).is_err());
    }

    /// ADR 0025 §6: a saved value is a plain string on the wire, and Debug never shows it.
    #[test]
    fn credential_actions_parse_and_a_saved_value_is_redacted() {
        let canary = "FAKE-wire-canary-8812";
        let text = format!(
            r#"{{"v":0,"token":"t","action":{{"kind":"save_credential","value":"{canary}","name":"Hook secret"}}}}"#
        );
        let request: WireRequest = serde_json::from_str(&text).expect("valid request");
        assert!(!format!("{request:?}").contains(canary));
        let Action::SaveCredential { value, .. } = &request.action else {
            panic!("wrong action");
        };
        assert_eq!(value.expose(), canary);
        assert!(
            serde_json::to_string(&request)
                .expect("json")
                .contains(canary)
        );
        assert_eq!(request.action.name(), "save_credential");
        let update = r#"{"v":0,"token":"t","action":{"kind":"update_credential","item_id":4,"generate":{"length":20,"alphabet":"hex"}}}"#;
        let update: WireRequest = serde_json::from_str(update).expect("valid request");
        assert!(update.action.waits());
        let capture = r#"{"v":0,"token":"t","action":{"kind":"capture_credential","command":["op","read","op://v/i/f"],"extract":{"after":"Token:"}}}"#;
        let capture: WireRequest = serde_json::from_str(capture).expect("valid request");
        assert!(matches!(
            capture.action,
            Action::CaptureCredential {
                extract: Some(Extract::After(_)),
                ..
            }
        ));
        let describe = r#"{"v":0,"token":"t","action":{"kind":"describe_credential","item_id":4,"placeholder_hosts":["api.example.com"]}}"#;
        assert!(serde_json::from_str::<WireRequest>(describe).is_ok());
        for bad in [
            r#"{"v":0,"token":"t","action":{"kind":"describe_credential","item_id":4,"hosts":["api.example.com"]}}"#,
            r#"{"v":0,"token":"t","action":{"kind":"capture_credential","file":"/x","extract":{"json":"a","line":1}}}"#,
            r#"{"v":0,"token":"t","action":{"kind":"capture_credential","file":"/x","extract":{"regex":"."}}}"#,
            r#"{"v":0,"token":"t","action":{"kind":"update_credential","item_id":4,"generate":{"seed":1}}}"#,
            r#"{"v":0,"token":"t","action":{"kind":"generate_credential","name":"x","reveal":true}}"#,
            r#"{"v":0,"token":"t","action":{"kind":"describe_credential","item_id":4,"value":"x"}}"#,
        ] {
            assert!(serde_json::from_str::<WireRequest>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hook_request_and_host_session() {
        let text = r#"{"v":0,"token":"t","host_session":"s-1","action":{"kind":"submit_user_request","host":"claude-code","cwd":"/p","prompt":"Fix the tests."}}"#;
        let request: WireRequest = serde_json::from_str(text).expect("valid request");
        assert_eq!(request.host_session.as_deref(), Some("s-1"));
        assert_eq!(request.action.name(), "submit_user_request");
        let Action::SubmitUserRequest {
            transcript_path,
            truncated,
            ..
        } = &request.action
        else {
            panic!("wrong action");
        };
        assert!(transcript_path.is_none() && !truncated);
        // An older request without a host session stays valid.
        let old = r#"{"v":0,"token":"t","action":{"kind":"list_access"}}"#;
        let old: WireRequest = serde_json::from_str(old).expect("valid request");
        assert!(old.host_session.is_none());
        assert!(
            !serde_json::to_string(&old)
                .expect("json")
                .contains("host_session")
        );
        let extra = r#"{"v":0,"token":"t","action":{"kind":"submit_user_request","host":"x","cwd":"/p","prompt":"p","trusted":true}}"#;
        assert!(serde_json::from_str::<WireRequest>(extra).is_err());
    }
}
