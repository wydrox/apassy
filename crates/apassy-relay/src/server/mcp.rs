//! The remote MCP endpoint `POST /mcp` (docs/SPEC.md, "MCP").
//!
//! Streamable HTTP with JSON responses only. Stateless: no session id. `tools/list`
//! and `tools/call` work without a prior `initialize`. A tool failure is a tool
//! result with `isError`, not a JSON-RPC error.

use serde_json::{Value, json};

use crate::api::{self, RunRequest};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::RunId;
use crate::now_unix;
use crate::server::Core;
use crate::server::approvals::{self, MAX_WAIT_SECS};
use crate::server::auth::AgentAuth;
use crate::server::{admin, decide};

/// The protocol versions the endpoint speaks, newest first.
pub const VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const FALLBACK_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "Apassy relay. Call apassy_list_access to see the credentials you can use. Call apassy_request_run with the exact command, the purpose, and the user's request. The status is pending until the owner's host releases the keys of the items: it does so by itself for a known safe command, and it asks the owner for any other. Call apassy_run_status until it is ready, denied, timed_out, or ended. An ended run is terminal, including an unknown reason code. Do not automatically retry an interrupted run; ask the user before requesting another run. When it is ready, run the command yourself with every variable of session.env set. The variables hold placeholders and base URLs, not real values; the relay swaps them. Do not print or store the variables. If apassy-team is installed, prefer `apassy-team run`, which does all of this and keeps the variables out of the transcript.";

/// The reply to one HTTP request on `/mcp`.
pub enum Reply {
    /// HTTP 202 with an empty body.
    Accepted,
    /// HTTP 200 with a JSON-RPC message.
    Json(Value),
}

fn rpc_error(id: Value, code: i64, message: &str) -> Reply {
    Reply::Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
}

fn rpc_result(id: Value, result: Value) -> Reply {
    Reply::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// The three tools with their input schemas.
pub fn tools() -> Value {
    json!([
        {
            "name": api::TOOL_LIST_ACCESS,
            "description": "List the credentials this agent may use: items, hosts, the variables a run gets, and when the owner's host asks the owner about a run.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        },
        {
            "name": api::TOOL_REQUEST_RUN,
            "description": "Ask for a run: the items, the exact command, the purpose, and the user's request. The run waits for the owner's host, which releases the keys by itself for a known safe command and asks the owner about any other.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": {"type": "array", "items": {"type": "integer", "minimum": 1}, "minItems": 1, "description": "Item ids from apassy_list_access."},
                    "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "The exact argv you will run."},
                    "purpose": {"type": "string", "description": "Why, in your words."},
                    "user_request": {"type": "string", "description": "The user's request that led to this run."},
                    "cwd": {"type": "string", "description": "The absolute working directory."},
                    "ttl_secs": {"type": "integer", "description": "Session lifetime in seconds."}
                },
                "required": ["items", "command", "purpose", "user_request"],
                "additionalProperties": false
            }
        },
        {
            "name": api::TOOL_RUN_STATUS,
            "description": "The status of a run. While it is pending, waits up to wait_secs for the owner's host.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {"type": "integer", "minimum": 1},
                    "wait_secs": {"type": "integer", "minimum": 0, "maximum": 25, "default": 20}
                },
                "required": ["run_id"],
                "additionalProperties": false
            }
        }
    ])
}

/// Handles one JSON-RPC message from an authenticated agent.
pub fn handle(core: &Core, agent: &AgentAuth, body: &[u8]) -> Reply {
    let message: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return rpc_error(Value::Null, -32700, "Parse error: the body is not JSON."),
    };
    let Some(object) = message.as_object() else {
        return rpc_error(
            Value::Null,
            -32600,
            "Invalid request: send one JSON-RPC message, not a batch.",
        );
    };
    let id = object.get("id").cloned();
    let method = object.get("method").and_then(Value::as_str);
    let Some(method) = method else {
        // A response from the client has no method: accept it.
        if object.contains_key("result") || object.contains_key("error") {
            return Reply::Accepted;
        }
        return rpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "Invalid request: no method.",
        );
    };
    let Some(id) = id else {
        return Reply::Accepted;
    };
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = asked
                .filter(|v| VERSIONS.contains(v))
                .unwrap_or(FALLBACK_VERSION);
            rpc_result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "apassy-relay", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": INSTRUCTIONS
                }),
            )
        }
        "ping" => rpc_result(id, json!({})),
        "tools/list" => rpc_result(id, json!({"tools": tools()})),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return rpc_error(id, -32602, "Invalid params: a tool name is required.");
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            rpc_result(id, call_tool(core, agent, name, arguments))
        }
        _ => rpc_error(id, -32601, "Method not found."),
    }
}

fn tool_ok(result: &Value) -> Value {
    let text = serde_json::to_string_pretty(result).unwrap_or_default();
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": result,
        "isError": false
    })
}

fn tool_error(error: &RelayError) -> Value {
    json!({
        "content": [{"type": "text", "text": format!("{}: {}", error.code, error.message)}],
        "isError": true
    })
}

fn call_tool(core: &Core, agent: &AgentAuth, name: &str, arguments: Value) -> Value {
    match run_tool(core, agent, name, arguments) {
        Ok(result) => tool_ok(&result),
        Err(error) => tool_error(&error),
    }
}

fn bad_arguments() -> RelayError {
    RelayError::invalid("The arguments do not match the tool schema.")
}

fn run_tool(core: &Core, agent: &AgentAuth, name: &str, arguments: Value) -> RelayResult<Value> {
    // Re-check the agent: a token can be revoked between two calls of one client.
    let now = now_unix();
    let agent = core
        .store
        .with(|conn| crate::server::auth::agent_by_id(conn, agent.id, now))?;
    match name {
        api::TOOL_LIST_ACCESS => {
            if arguments.as_object().is_some_and(|o| !o.is_empty()) {
                return Err(bad_arguments());
            }
            admin::access(core, &agent)
        }
        api::TOOL_REQUEST_RUN => {
            let object = arguments.as_object().ok_or_else(bad_arguments)?;
            if !object.get("user_request").is_some_and(Value::is_string) {
                return Err(bad_arguments());
            }
            let request: RunRequest =
                serde_json::from_value(arguments).map_err(|_| bad_arguments())?;
            let view = decide::request_run(core, &agent, &request, now)?;
            serde_json::to_value(view)
                .map_err(|_| RelayError::internal("A result cannot be written."))
        }
        api::TOOL_RUN_STATUS => {
            let object = arguments.as_object().ok_or_else(bad_arguments)?;
            if object.keys().any(|k| k != "run_id" && k != "wait_secs") {
                return Err(bad_arguments());
            }
            let run_id = object
                .get("run_id")
                .and_then(Value::as_u64)
                .filter(|id| *id >= 1)
                .ok_or_else(bad_arguments)?;
            let wait = match object.get("wait_secs") {
                None => 20,
                Some(value) => value
                    .as_u64()
                    .filter(|w| *w <= MAX_WAIT_SECS)
                    .ok_or_else(bad_arguments)?,
            };
            let view = approvals::get_run(core, &agent, RunId(run_id), wait)?;
            serde_json::to_value(view)
                .map_err(|_| RelayError::internal("A result cannot be written."))
        }
        _ => Err(RelayError::new(codes::INVALID_REQUEST, "Unknown tool.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_tools_with_object_schemas() {
        let list = tools();
        let list = list.as_array().unwrap();
        assert_eq!(list.len(), 3);
        for tool in list {
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
        assert_eq!(
            list[1]["inputSchema"]["required"].as_array().unwrap().len(),
            4
        );
    }
}
