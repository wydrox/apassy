//! Broker wire format version 0. One JSON object per line on the Unix socket.
//!
//! The request has no URL, header, SQL, or secret field. The agent names an
//! item, a named operation, and text parameters. The broker adds the secret.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const WIRE_VERSION: u32 = 0;
/// Largest request line in bytes, including the newline.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Largest response line in bytes. A run response carries masked process output.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub v: u32,
    pub token: String,
    pub action: Action,
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireRequest")
            .field("v", &self.v)
            .field("token", &"[redacted]")
            .field("action", &self.action)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// List the items and named operations that the owner permits for this agent.
    ListAccess,
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
        items: Vec<u64>,
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
}

impl Action {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ListAccess => "list_access",
            Self::Call { .. } => "call",
            Self::Run { .. } => "run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireResponse {
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
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
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
}
