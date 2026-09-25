//! MCP stdio adapter. It forwards tool calls to the local broker socket.
//!
//! The adapter does not open the vault file and never receives a secret value.
//! It holds the agent token in process memory. The token is not a secret value
//! of a stored credential. The owner can revoke it in the desktop app.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use super::client;
use super::wire::{Action, MAX_LINE_BYTES, WireResponse};

pub const TOOL_LIST_ACCESS: &str = "apassy_list_access";
pub const TOOL_USE_CREDENTIAL: &str = "apassy_use_credential";
const SUPPORTED_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// Adapter settings. `token` is `None` when the environment has no agent token.
pub struct AdapterConfig {
    pub socket: PathBuf,
    pub token: Option<String>,
}

impl std::fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterConfig")
            .field("socket", &self.socket)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl AdapterConfig {
    pub fn from_env() -> Self {
        Self {
            socket: client::default_socket_path(),
            token: std::env::var(client::TOKEN_ENV)
                .ok()
                .filter(|token| !token.trim().is_empty()),
        }
    }
}

/// Serve MCP over stdin and stdout until stdin closes.
pub fn run_stdio(config: &AdapterConfig) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut line = String::new();
    let mut input = stdin.lock();
    loop {
        line.clear();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let reply = if line.len() > MAX_LINE_BYTES {
            Some(rpc_error(&Value::Null, -32600, "The request is too large."))
        } else {
            handle_message(config, &line)
        };
        if let Some(reply) = reply {
            serde_json::to_writer(&mut stdout, &reply).map_err(io::Error::other)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
}

/// Handle one JSON-RPC message. Notifications return `None`.
pub fn handle_message(config: &AdapterConfig, line: &str) -> Option<Value> {
    let message: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return Some(rpc_error(&Value::Null, -32700, "The message is not JSON.")),
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);
    let (Some(id), Some(method)) = (id, method) else {
        // A notification or a response. MCP needs no reply.
        return None;
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => Ok(initialize_result(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_list() })),
        "tools/call" => Ok(call_tool(config, &params)),
        _ => Err((-32601, "The method is not supported.")),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, text)) => rpc_error(&id, code, text),
    })
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

fn initialize_result(params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let version = SUPPORTED_PROTOCOLS
        .iter()
        .find(|supported| **supported == requested)
        .copied()
        .unwrap_or(SUPPORTED_PROTOCOLS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "apassy", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Apassy lets you use credentials that the owner permits. You never receive secret values. Call apassy_list_access first to see the permitted items and operations.",
    })
}

pub fn tool_list() -> Value {
    json!([
        {
            "name": TOOL_LIST_ACCESS,
            "title": "List permitted credentials",
            "description": "List the credentials and named operations that the owner permits for this agent. The result has item IDs, item names, operations, and parameter formats. It never has secret values.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_USE_CREDENTIAL,
            "title": "Use a permitted credential",
            "description": "Run one permitted named operation with a stored credential. Apassy adds the secret value inside the broker. You receive only the permitted output fields. The owner sees each call in the Apassy activity log.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": { "type": "integer", "minimum": 1, "description": "Item ID from apassy_list_access." },
                    "operation": { "type": "string", "description": "Operation name from apassy_list_access." },
                    "params": {
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Operation parameters. All values are strings."
                    }
                },
                "required": ["item_id", "operation"],
                "additionalProperties": false
            }
        }
    ])
}

fn call_tool(config: &AdapterConfig, params: &Value) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let action = match name {
        TOOL_LIST_ACCESS => Ok(Action::ListAccess),
        TOOL_USE_CREDENTIAL => call_action(&arguments),
        _ => Err("The tool name is not known.".to_owned()),
    };
    let action = match action {
        Ok(action) => action,
        Err(message) => return tool_error("invalid_arguments", &message),
    };
    let Some(token) = config.token.as_deref() else {
        return tool_error(
            "no_agent_token",
            "The adapter has no agent token. Set APASSY_AGENT_TOKEN in the MCP server configuration.",
        );
    };
    match client::send(&config.socket, token, action) {
        Ok(response) => tool_result(response),
        Err(_) => tool_error(
            "broker_unavailable",
            "The Apassy broker did not answer. Make sure that the Apassy desktop app is open.",
        ),
    }
}

fn call_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(extra) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "item_id" | "operation" | "params"))
    {
        return Err(format!("The argument \"{extra}\" is not permitted."));
    }
    let item_id = object
        .get("item_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| "The item_id argument must be a positive integer.".to_owned())?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| "The operation argument must be a string.".to_owned())?
        .to_owned();
    let mut params = BTreeMap::new();
    if let Some(raw) = object.get("params") {
        let raw = raw
            .as_object()
            .ok_or_else(|| "The params argument must be an object.".to_owned())?;
        for (key, value) in raw {
            let text = value
                .as_str()
                .ok_or_else(|| format!("The parameter \"{key}\" must be a string."))?;
            params.insert(key.clone(), text.to_owned());
        }
    }
    Ok(Action::Call {
        item_id,
        operation,
        params,
    })
}

fn tool_result(response: WireResponse) -> Value {
    if response.ok {
        let result = response.result.unwrap_or(Value::Null);
        let text = serde_json::to_string_pretty(&result).unwrap_or_default();
        json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "result": result },
            "isError": false,
        })
    } else {
        let (code, message) = response.error.map_or_else(
            || {
                (
                    "broker_error".to_owned(),
                    "The broker refused the request.".to_owned(),
                )
            },
            |error| (error.code, error.message),
        );
        tool_error(&code, &message)
    }
}

fn tool_error(code: &str, message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": format!("{code}: {message}") }],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AdapterConfig {
        AdapterConfig {
            socket: PathBuf::from("/nonexistent/apassy-test.sock"),
            token: Some("apassy_agt_test".to_owned()),
        }
    }

    #[test]
    fn initialize_and_tools_list() {
        let reply = handle_message(
            &config(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
        )
        .expect("reply");
        assert_eq!(reply["result"]["protocolVersion"], "2025-03-26");
        let reply = handle_message(
            &config(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        )
        .expect("reply");
        assert_eq!(reply["result"]["tools"].as_array().map(Vec::len), Some(2));
        assert!(
            handle_message(
                &config(),
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
        );
    }

    #[test]
    fn call_arguments_refuse_urls_and_nested_values() {
        let url = json!({"item_id": 1, "operation": "op", "url": "http://x"});
        assert!(call_action(&url).is_err());
        let nested = json!({"item_id": 1, "operation": "op", "params": {"a": {"b": 1}}});
        assert!(call_action(&nested).is_err());
        let zero = json!({"item_id": 0, "operation": "op"});
        assert!(call_action(&zero).is_err());
    }

    #[test]
    fn missing_broker_is_a_tool_error_not_a_crash() {
        let reply = handle_message(
            &config(),
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"apassy_list_access","arguments":{}}}"#,
        )
        .expect("reply");
        assert_eq!(reply["result"]["isError"], true);
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.starts_with("broker_unavailable"));
        assert!(!text.contains("apassy_agt_test"));
    }
}
