//! MCP stdio adapter. It forwards tool calls to the local broker socket.
//!
//! The adapter does not open the vault file and never receives a secret value.
//! It holds the agent token in process memory. The token is not a secret value
//! of a stored credential. The owner can revoke it in the desktop app.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::client;
use super::wire::{Action, AgentSecret, Extract, GenerateSpec, MAX_LINE_BYTES, WireResponse};

pub const TOOL_LIST_ACCESS: &str = "apassy_list_access";
pub const TOOL_USE_CREDENTIAL: &str = "apassy_use_credential";
pub const TOOL_RUN_WITH_SECRETS: &str = "apassy_run_with_secrets";
pub const TOOL_ACCESS_STATUS: &str = "apassy_access_request_status";
pub const TOOL_ACCESS_CANCEL: &str = "apassy_cancel_access_request";
pub const TOOL_REQUEST_ACCESS: &str = "apassy_request_access";
pub const TOOL_CAPTURE_CREDENTIAL: &str = "apassy_capture_credential";
pub const TOOL_GENERATE_CREDENTIAL: &str = "apassy_generate_credential";
pub const TOOL_SAVE_CREDENTIAL: &str = "apassy_save_credential";
pub const TOOL_ASK_OWNER_FOR_CREDENTIAL: &str = "apassy_ask_owner_for_credential";
pub const TOOL_UPDATE_CREDENTIAL: &str = "apassy_update_credential";
pub const TOOL_DESCRIBE_CREDENTIAL: &str = "apassy_describe_credential";
/// A call that can wait for the owner (5 minutes) or for a command reads this long.
const WAITING_CALL_TIMEOUT: Duration = Duration::from_secs(650);
const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
const SUPPORTED_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// Claude Code sets this variable for its stdio MCP servers to the session ID. The
/// `UserPromptSubmit` hook gets the same ID as `session_id` (goal item B6).
pub const CLAUDE_SESSION_ENV: &str = "CLAUDE_CODE_SESSION_ID";

/// Adapter settings. `token` is `None` when the environment has no agent token.
pub struct AdapterConfig {
    pub socket: PathBuf,
    pub token: Option<String>,
    /// The agent host session, if the host tells its MCP servers.
    pub host_session: Option<String>,
}

impl std::fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterConfig")
            .field("socket", &self.socket)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("host_session", &self.host_session)
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
            host_session: std::env::var(CLAUDE_SESSION_ENV)
                .ok()
                .filter(|session| !session.trim().is_empty()),
        }
    }
}

/// Serve MCP over stdin and stdout until stdin closes.
pub fn run_stdio(config: &AdapterConfig) -> io::Result<()> {
    serve(config, io::stdin().lock(), io::stdout(), PROGRESS_INTERVAL)
}

fn write_message(output: &Mutex<impl Write>, message: &Value) -> io::Result<()> {
    // One buffer per frame avoids flooding a Unix stream's send queue with
    // serde's tiny writes while EOF waits for the remaining workers to drain.
    let mut frame = zeroize::Zeroizing::new(serde_json::to_vec(message).map_err(io::Error::other)?);
    frame.push(b'\n');
    let mut writer = output
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    writer.write_all(&frame)?;
    writer.flush()
}

#[derive(Default)]
struct CallCancellation {
    stopped: AtomicBool,
    // EOF/output failure stops waiting, but only an explicit MCP cancellation
    // abandons an asynchronous scoped access request.
    explicit: AtomicBool,
}

// Three mutating calls plus a reserved read/control slot. No unbounded input queue.
fn serve(
    config: &AdapterConfig,
    mut input: impl BufRead,
    output: impl Write + Send,
    cadence: Duration,
) -> io::Result<()> {
    let output = Mutex::new(output);
    let active = Mutex::new(BTreeMap::<String, (Arc<CallCancellation>, bool)>::new());
    let drained = std::sync::Condvar::new();
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        let result = (|| {
            let mut line = String::new();
            loop {
                workers
                    .retain(|worker: &std::thread::ScopedJoinHandle<'_, ()>| !worker.is_finished());
                line.clear();
                let read = match read_frame(&mut input, &mut line) {
                    Ok(read) => read,
                    Err(err) => {
                        if err.kind() == io::ErrorKind::InvalidData {
                            write_message(
                                &output,
                                &rpc_error(&Value::Null, -32600, &err.to_string()),
                            )?;
                        }
                        return Err(err);
                    }
                };
                if read == 0 {
                    return Ok(());
                }
                if line.trim().is_empty() {
                    continue;
                }
                let message: Value = match serde_json::from_str(&line) {
                    Ok(message) => message,
                    Err(_) => {
                        write_message(
                            &output,
                            &rpc_error(&Value::Null, -32700, "The message is not JSON."),
                        )?;
                        continue;
                    }
                };
                if message["method"] == "notifications/cancelled" && message.get("id").is_none() {
                    let key = message["params"]["requestId"].to_string();
                    if let Some((cancel, _)) = active.lock().unwrap().get(&key) {
                        cancel.explicit.store(true, Ordering::SeqCst);
                        cancel.stopped.store(true, Ordering::SeqCst);
                    }
                    continue;
                }
                if message["method"] != "tools/call" || message.get("id").is_none() {
                    if let Some(reply) = handle_message(config, &line) {
                        write_message(&output, &reply)?;
                    }
                    continue;
                }
                let id = message["id"].clone();
                let key = id.to_string();
                let params = message["params"].clone();
                let read_only = [TOOL_LIST_ACCESS, TOOL_ACCESS_STATUS, TOOL_ACCESS_CANCEL]
                    .iter()
                    .any(|name| params["name"] == *name);
                let cancel = Arc::new(CallCancellation::default());
                {
                    let mut calls = active.lock().unwrap();
                    if calls.contains_key(&key) {
                        write_message(
                            &output,
                            &rpc_error(&id, -32600, "A request with this ID is already active."),
                        )?;
                        continue;
                    }
                    if calls.len() >= 4
                        || (!read_only && calls.values().filter(|(_, read)| !read).count() >= 3)
                    {
                        write_message(
                            &output,
                            &json!({"jsonrpc":"2.0", "id":id, "result":tool_error("busy", "The MCP dispatcher is full. No operation was submitted.")}),
                        )?;
                        continue;
                    }
                    calls.insert(key.clone(), (Arc::clone(&cancel), read_only));
                }
                let output = &output;
                let active = &active;
                let drained = &drained;
                workers.push(scope.spawn(move || {
                    let token = params["_meta"]["progressToken"].clone();
                    let mut progress = 0_u64;
                    let result = call_tool_control(config, &params, &cancel, cadence, |operation_id| {
                        if token.is_string() || token.is_number() {
                            if write_message(output, &json!({"jsonrpc":"2.0", "method":"notifications/progress", "params":{
                                "progressToken":token, "progress":progress, "operation_id":operation_id,
                                "message":format!("Operation {operation_id}; waiting for the broker, owner, or bouncer.")
                            }})).is_err() {
                                for (cancel, _) in active.lock().unwrap().values() { cancel.stopped.store(true, Ordering::SeqCst); }
                            }
                            progress += 1;
                        }
                    });
                    if write_message(output, &json!({"jsonrpc":"2.0", "id":id, "result":result})).is_err() {
                        for (cancel, _) in active.lock().unwrap().values() { cancel.stopped.store(true, Ordering::SeqCst); }
                    }
                    active.lock().unwrap().remove(&key);
                    drained.notify_all();
                }));
            }
        })();
        // A pipe writer can close stdin while still reading a short call's result.
        // Give those calls a bounded drain period. Framing/output errors cancel
        // immediately; EOF still withdraws any question left after the grace.
        let mut calls = active.lock().unwrap();
        if result.is_ok() {
            calls = drained
                .wait_timeout_while(calls, SHUTDOWN_GRACE, |calls| !calls.is_empty())
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        for (cancel, _) in calls.values() {
            cancel.stopped.store(true, Ordering::SeqCst);
        }
        drop(calls);
        for worker in workers {
            let _ = worker.join();
        }
        result
    })
}

fn read_frame(input: &mut impl BufRead, line: &mut String) -> io::Result<usize> {
    let read = input.take((MAX_LINE_BYTES + 1) as u64).read_line(line)?;
    if line.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The MCP request is too large.",
        ));
    }
    Ok(read)
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
        "instructions": "Apassy lets you use the owner's credentials without seeing them. First-use checklist: confirm the host connection and prompt hook, start in apassy-sandbox, and test with a synthetic credential. Call apassy_list_access first: its catalog lists each credential with its item_id and env_name, never a value. has_code and code_env_name describe one-time codes; explicitly select codes in runs, including code-only runs with items: []. Code use requires owner approval unless a remembered project answer explicitly includes codes. You need no grant: put item_ids in apassy_run_with_secrets and use the env_names in your command. The bouncer decides each use; when it asks the owner, the call waits up to 5 minutes. On question_waiting, a different owner question is pending: wait for that question to finish before submitting this request. After a host timeout or lost response the execution outcome is unknown: retrieve the operation with apassy_list_access(operation_id), and inspect activity and the external target with the owner before retrying a mutating call. Use the same idempotency_key with identical arguments within retention for ordinary calls. With access_request_id, every repeated use is refused; query access/operation status instead. Repeating a call without that key is not guaranteed safe. To store a new credential, prefer apassy_capture_credential (a command or a file prints it) or apassy_generate_credential (a new password or token); apassy_ask_owner_for_credential asks the owner to paste one. Use apassy_save_credential only for a value that is already in your transcript. Do not ask for secret values, and do not try to print them.",
    })
}

/// The `extract` argument of capture and update: which part of the output to store.
fn extract_schema() -> Value {
    json!({
        "type": "object",
        "description": "Which part of the output is the credential. Give one key: {\"json\": \"Credentials.SessionToken\"} (a dot path; numbers index arrays), {\"line\": 2} (from 1), or {\"after\": \"Token:\"} (the rest of the first line with this label; it ends with : or =). Apassy applies it; you never see the output.",
        "properties": {
            "json": { "type": "string" },
            "line": { "type": "integer", "minimum": 1 },
            "after": { "type": "string" }
        },
        "minProperties": 1,
        "maxProperties": 1,
        "additionalProperties": false
    })
}

pub fn tool_list() -> Value {
    let mut tools = json!([
        {"name": TOOL_ACCESS_STATUS,"title":"Check scoped access consent","description":"Read this agent's exact request status without creating anything. A receipt never proves execution succeeded.","inputSchema":{"type":"object","properties":{"request_id":{"type":"integer","minimum":1}},"required":["request_id"],"additionalProperties":false}},
        {"name": TOOL_ACCESS_CANCEL,"title":"Cancel scoped access consent","description":"Cancel an abandoned request or its unused/pending allowance. Does not recall released values. Never creates a request.","inputSchema":{"type":"object","properties":{"request_id":{"type":"integer","minimum":1}},"required":["request_id"],"additionalProperties":false}},
        {
            "name": TOOL_LIST_ACCESS,
            "title": "List the credentials you can use",
            "description": "List the credentials of the vault without values: the catalog has each item_id, name, folder, and env_name. You need no grant: a credential with access \"can_use\" goes into apassy_run_with_secrets, and the bouncer decides each use (it can ask the owner). \"needs_field\": the owner must pick one secret field first. has_code and code_env_name permit explicit code selection in runs even when access is needs_field; codes require owner approval unless a project answer explicitly covers them. Named operations are for apassy_use_credential. Never has secret values.",
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
        },
        {
            "name": TOOL_RUN_WITH_SECRETS,
            "title": "Run a command with secrets in its environment",
            "description": "Run one command with catalog credentials in its environment, under the env_name of each item from apassy_list_access. Optional codes selects current one-time codes under code_env_name; items may be [] for codes only. A code requires owner approval unless an explicit project answer includes codes; models and password-only answers cannot approve codes. Supplied literal secret values are masked as [apassy:NAME]. Transformed, fragmented, or unrelated secrets may remain: return only needed non-secret fields. Check exit_code and timed_out even when isError is false. env_holds \"a placeholder\": the real value goes only into HTTPS requests to its hosts (Authorization or API key header, or key parameter), never into a body or a file; network.requests lists them. No grant is needed: the bouncer decides each run, and when it asks the owner this call waits up to 5 minutes. On question_waiting, a different owner question is pending: wait for that question to finish before submitting this request. After a host timeout or lost response the execution outcome is unknown: retrieve the operation with apassy_list_access(operation_id), and inspect activity and the external target with the owner before retrying a mutating call. Use the same idempotency_key with identical arguments within retention for ordinary calls. With access_request_id, every repeated use is refused; query access/operation status instead. Repeating a call without that key is not guaranteed safe. The command is an argument list, not a shell string.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": { "type": "array", "items": { "type": "integer", "minimum": 1 }, "minItems": 0, "description": "Item IDs from process_access, or from the catalog (access \"can_use\"). Use [] for codes only." },
                    "command": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Program and arguments, for example [\"npm\", \"run\", \"migrate\"]." },
                    "cwd": { "type": "string", "description": "Absolute working directory: the project folder. The bouncer uses the project." },
                    "purpose": { "type": "string", "description": "Why you need to run this command. The owner sees it." },
                    "codes": { "type": "array", "items": { "type": "integer", "minimum": 1 }, "maxItems": 16, "description": "Item IDs whose current one-time codes enter code_env_name from the catalog. Owner approval required unless an explicit project answer covers codes. Never delivers a seed. items may be [] for codes only. Not compatible with access_request_id." },
                    "access_request_id": { "type": "integer", "minimum": 1, "description": "Consume this exact scoped access request once. Retries after admission are refused; query status." },
                    "user_request": { "type": "string", "description": "The user's own words from the conversation that led to this command. Quote them. Do not summarize or add words. The bouncer compares the command with this request, and the owner sees it." }
                },
                "required": ["items", "command", "cwd", "purpose", "user_request"],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_REQUEST_ACCESS,
            "title": "Tell the owner why you need a credential",
            "description": "Usually not needed: no grant is required. Use a catalog credential directly with apassy_run_with_secrets; the bouncer decides, and when it asks the owner the call waits up to 5 minutes. Without scope this legacy tool records a note. With scope it requests one asynchronous access consent, expiring in 300 seconds; the bouncer still checks the eventual command. Scoped requests appear in Mac Decisions and iPhone Requests. Query apassy_access_request_status; then explicitly reference one matching run. Without scope the original local note remains available through apassy request list. It returns at once. For a credential that is not in Apassy, use apassy_ask_owner_for_credential.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": { "type": "integer", "minimum": 1, "description": "Item ID from the catalog." },
                    "scope": { "type": "object", "properties": { "action": { "enum": ["read","change","deploy","delete"] }, "hosts": { "type": "array", "items": {"type":"string"}, "maxItems":16 } }, "required":["action","hosts"], "additionalProperties":false },
                    "reason": { "type": "string", "description": "Why you need this credential, with the user's own words when you have them. The owner reads it. At most 500 characters." },
                    "cwd": { "type": "string", "description": "The absolute working directory where you want to use it. Optional." }
                },
                "required": ["item_id", "reason"],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_CAPTURE_CREDENTIAL,
            "title": "Save a command output or a file as a new credential",
            "description": "The best way to store a credential: you never see it. Apassy runs a command or reads a file and saves the trimmed output (or the part that extract names); you get item_id and env_name. Known token commands run at once, such as [\"gh\", \"auth\", \"token\"], [\"op\", \"read\", \"op://vault/item/field\"], [\"gcloud\", \"auth\", \"print-access-token\"]. Any other command, or a file outside your project, waits for the owner (up to 5 minutes; on question_waiting wait for the other question; after a host timeout verify the outcome before retrying). Refused: Apassy paths, more than 64 KiB, empty output, a non-zero exit code. At most 10 new or changed credentials per hour.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Program and arguments that print the credential. Give command or file." },
                    "file": { "type": "string", "description": "Absolute path of a file that holds the credential. Give command or file." },
                    "extract": extract_schema(),
                    "name": { "type": "string", "description": "Name of the new credential. Optional: Apassy finds one from the value." },
                    "cwd": { "type": "string", "description": "Absolute working directory and project. Default: the folder of this MCP server." },
                    "folder": { "type": "string", "description": "Folder path as the catalog shows it, such as \"Work / Stripe\". Optional." },
                    "purpose": { "type": "string", "description": "Why you add it. Optional." }
                },
                "oneOf": [{"required": ["command"], "not": {"anyOf": [{"required": ["file"]}]}}, {"required": ["file"], "not": {"anyOf": [{"required": ["command"]}]}}],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_GENERATE_CREDENTIAL,
            "title": "Generate a new secret",
            "description": "Apassy makes a random password or token, saves it as a new credential, and returns item_id and env_name. You never see the value. Use it, for example, for a new database password, then set it with apassy_run_with_secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Name of the new credential, such as \"Staging database password\"." },
                    "length": { "type": "integer", "minimum": 16, "maximum": 128, "description": "Characters. Default 32." },
                    "alphabet": { "type": "string", "enum": ["alnum", "hex", "base64url", "symbols"], "description": "Default alnum." },
                    "cwd": { "type": "string", "description": "Absolute project folder. Default: the folder of this MCP server." },
                    "folder": { "type": "string", "description": "Folder path as the catalog shows it. Optional." }
                },
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_SAVE_CREDENTIAL,
            "title": "Save a value that you already have",
            "description": "Last resort: save a value that is already in your transcript, for example from an API answer. Prefer apassy_capture_credential (a command or a file gives it, and you never see it) or apassy_generate_credential (a new password). You get item_id and env_name. A value that a credential of yours already has returns that credential.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": { "type": "string", "description": "The secret value. The entire serialized request, including escaping and envelope, must fit in 64 KiB; prefer file capture for large values." },
                    "name": { "type": "string", "description": "Name of the new credential. Optional." },
                    "cwd": { "type": "string", "description": "Absolute project folder. Default: the folder of this MCP server." },
                    "folder": { "type": "string", "description": "Folder path as the catalog shows it. Optional." }
                },
                "required": ["value"],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_ASK_OWNER_FOR_CREDENTIAL,
            "title": "Ask the owner to add a credential",
            "description": "Ask the owner to paste a credential into Apassy. The call waits up to 5 minutes. When the owner saves it, you get item_id and env_name, never the value. On waiting, call again with the same name: the same name in the same project is the same request. On dismissed, tell the user. On question_waiting, another question of yours waits: wait for it first. At most 5 open or new requests per hour.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Name of the credential, such as \"Sentry auth token\"." },
                    "purpose": { "type": "string", "description": "Why you need it. The owner reads it. At most 500 characters." },
                    "where_to_get": { "type": "string", "description": "Where the owner gets it, as plain text, such as \"https://resend.com/api-keys\". Optional." },
                    "cwd": { "type": "string", "description": "Absolute project folder. Default: the folder of this MCP server." },
                    "folder": { "type": "string", "description": "Folder path as the catalog shows it. Optional." }
                },
                "required": ["name", "purpose"],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_UPDATE_CREDENTIAL,
            "title": "Give your credential a new value",
            "description": "Give a credential that you created with capture, generate, or save a new value: from a command or a file (as apassy_capture_credential, also with extract; the same owner questions apply) or generated. You never see the value. Apassy keeps the previous value for the owner to restore. Counts toward the 10 changes per hour. Any other credential gives not_owner: ask the owner.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": { "type": "integer", "minimum": 1, "description": "A credential that you created." },
                    "command": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Program and arguments that print the new value." },
                    "file": { "type": "string", "description": "Absolute path of a file with the new value." },
                    "generate": {
                        "type": "object",
                        "properties": {
                            "length": { "type": "integer", "minimum": 16, "maximum": 128 },
                            "alphabet": { "type": "string", "enum": ["alnum", "hex", "base64url", "symbols"] }
                        },
                        "additionalProperties": false,
                        "description": "Generate the new value. Give command, file, or generate."
                    },
                    "extract": extract_schema(),
                    "cwd": { "type": "string", "description": "Absolute working directory of the command. Default: the folder of this MCP server." }
                },
                "required": ["item_id"],
                "oneOf": [{"required": ["command"], "not": {"anyOf": [{"required": ["file"]}, {"required": ["generate"]}]}}, {"required": ["file"], "not": {"anyOf": [{"required": ["command"]}, {"required": ["generate"]}]}}, {"required": ["generate"], "not": {"anyOf": [{"required": ["command"]}, {"required": ["file"]}]}}],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_DESCRIBE_CREDENTIAL,
            "title": "Describe your credential",
            "description": "Change the name, the notes, the env_name, or the placeholder hosts of a credential that you created with capture, generate, or save. Any other credential gives not_owner.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": { "type": "integer", "minimum": 1 },
                    "name": { "type": "string" },
                    "notes": { "type": "string" },
                    "env_name": { "type": "string", "description": "Like MY_API_KEY. Not reserved, and not the variable of another credential or of its provider." },
                    "placeholder_hosts": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Only for an API key or a login. The variable then holds a placeholder, and Apassy puts the real value only into HTTPS requests to these hosts, such as \"api.example.com\". Only narrows: a placeholder instead of the real value, or some of the current placeholder hosts. Not for a custom value, a database password, or an SSH key." }
                },
                "required": ["item_id"],
                "additionalProperties": false
            }
        }
    ]);
    for tool in tools.as_array_mut().expect("tools") {
        if tool["name"] == TOOL_LIST_ACCESS {
            tool["inputSchema"]["properties"]["operation_id"] = json!({"type":"string", "pattern":"^[0-9a-fA-F]{32}$", "description":"Retrieve the retained outcome of this operation after a reconnect. Returns metadata only, without command output."});
            let description = tool["description"].as_str().unwrap().to_owned();
            tool["description"] = json!(format!(
                "{description} With operation_id, retrieve that operation's status instead of the catalog."
            ));
        } else if tool["name"] != TOOL_ACCESS_STATUS && tool["name"] != TOOL_ACCESS_CANCEL {
            tool["inputSchema"]["properties"]["idempotency_key"] = json!({"type":"string", "minLength":1, "maxLength":128, "description":"Choose a unique key before a mutation. Reuse it only with identical arguments to retrieve the first operation without executing again. Keys expire 15 minutes after completion; never blindly replay after expiry or a broker restart."});
            let description = tool["description"].as_str().unwrap().to_owned();
            tool["description"] = json!(format!(
                "{description} Supply idempotency_key before running. On reconnect use apassy_list_access with operation_id from progress or the error. A repeated identical key returns the original operation receipt (metadata only); different arguments are refused. Cancellation after execution starts cannot undo it. A run with access_request_id is single use: repeated submission is refused even with this key; query status instead."
            ));
        }
    }
    tools
}

fn call_tool(config: &AdapterConfig, params: &Value) -> Value {
    call_tool_control(
        config,
        params,
        &CallCancellation::default(),
        Duration::from_secs(15),
        |_| {},
    )
}

fn call_tool_control(
    config: &AdapterConfig,
    params: &Value,
    cancelled: &CallCancellation,
    cadence: Duration,
    mut progress: impl FnMut(&str),
) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let key = arguments
        .as_object_mut()
        .and_then(|o| o.remove("idempotency_key"));
    let key = match key {
        None => None,
        Some(Value::String(key))
            if !key.is_empty()
                && key.len() <= 128
                && ![TOOL_LIST_ACCESS, TOOL_ACCESS_STATUS, TOOL_ACCESS_CANCEL].contains(&name) =>
        {
            Some(key)
        }
        _ => {
            return tool_error(
                "invalid_arguments",
                "The idempotency_key must be a nonempty string of at most 128 bytes on a mutating tool.",
            );
        }
    };
    let action = match name {
        TOOL_LIST_ACCESS => arguments_object(&arguments, &["operation_id"]).and_then(|o| {
            match optional_text(o, "operation_id")? {
                Some(operation_id) if valid_operation_id(&operation_id) => {
                    Ok(Action::OperationStatus { operation_id })
                }
                Some(_) => Err("The operation_id must be 32 hexadecimal characters.".to_owned()),
                None => Ok(Action::ListAccess),
            }
        }),
        TOOL_USE_CREDENTIAL => call_action(&arguments),
        TOOL_RUN_WITH_SECRETS => run_action(&arguments),
        TOOL_REQUEST_ACCESS => request_action(&arguments),
        TOOL_ACCESS_STATUS | TOOL_ACCESS_CANCEL => (|| {
            let o = arguments_object(&arguments, &["request_id"])?;
            let request_id = o
                .get("request_id")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0)
                .ok_or_else(|| "Use a positive request_id.".to_owned())?;
            Ok(if name == TOOL_ACCESS_STATUS {
                Action::AccessRequestStatus { request_id }
            } else {
                Action::CancelAccessRequest { request_id }
            })
        })(),
        TOOL_CAPTURE_CREDENTIAL => capture_action(&arguments),
        TOOL_GENERATE_CREDENTIAL => generate_action(&arguments),
        TOOL_SAVE_CREDENTIAL => save_action(&arguments),
        TOOL_ASK_OWNER_FOR_CREDENTIAL => ask_owner_action(&arguments),
        TOOL_UPDATE_CREDENTIAL => update_action(&arguments),
        TOOL_DESCRIBE_CREDENTIAL => describe_action(&arguments),
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
    let asynchronous_access = matches!(action, Action::RequestAccess { scope: Some(_), .. });
    let operation_id = if action.trackable() {
        match new_operation_id() {
            Ok(id) => Some(id),
            Err(_) => {
                return tool_error(
                    "broker_error",
                    "The adapter could not allocate an operation ID. Nothing was submitted.",
                );
            }
        }
    } else {
        None
    };
    let action = match &operation_id {
        Some(id) => Action::Tracked {
            operation_id: id.clone(),
            idempotency_key: key,
            action: Box::new(action),
        },
        None => action,
    };
    let options = client::SendOptions {
        host_session: config.host_session.as_deref(),
        timeout: operation_id.as_ref().map(|_| WAITING_CALL_TIMEOUT),
    };
    let mut last_progress = Instant::now();
    if let Some(id) = &operation_id {
        progress(id);
    }
    let response = client::send_observed(&config.socket, token, action, options, || {
        if last_progress.elapsed() >= cadence {
            if let Some(id) = &operation_id {
                progress(id);
            }
            last_progress = Instant::now();
        }
        cancelled.stopped.load(Ordering::SeqCst)
    });
    let result = match response {
        Ok(mut response) => {
            if response.operation_id.is_none() {
                response.operation_id = operation_id.clone();
            }
            return tool_result(response);
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            if asynchronous_access && !cancelled.explicit.load(Ordering::SeqCst) {
                return attach_operation(
                    tool_error(
                        "unknown_outcome",
                        "The asynchronous access request may have been created. Retrieve operation status, then query or explicitly cancel its request ID.",
                    ),
                    operation_id.as_deref(),
                );
            }
            if let Some(id) = &operation_id {
                let cancel = client::send_with(
                    &config.socket,
                    token,
                    Action::CancelOperation {
                        operation_id: id.clone(),
                    },
                    client::SendOptions {
                        timeout: Some(Duration::from_secs(5)),
                        host_session: config.host_session.as_deref(),
                    },
                );
                match cancel {
                    Ok(response)
                        if response.result.as_ref().is_some_and(|v| {
                            v["may_have_run"] == false
                                && v["cancellation_requested"] == true
                                && v["state"] != "waiting_for_owner"
                        }) =>
                    {
                        tool_error(
                            "cancelled",
                            "Cancellation was accepted before execution; any pending question is withdrawn.",
                        )
                    }
                    _ => tool_error(
                        "cancellation_requested",
                        "Cancellation was requested. The command or mutation may already have run; retrieve its operation status.",
                    ),
                }
            } else {
                tool_error("cancelled", "The read was cancelled.")
            }
        }
        Err(error) => {
            // A failed response must not leave an owner question attached to a
            // finished adapter worker. Cancellation is best effort; keep the
            // unknown-outcome diagnostic and receipt ID even if it succeeds.
            if let Some(id) = &operation_id
                && !asynchronous_access
                && !matches!(
                    error.kind(),
                    io::ErrorKind::InvalidInput
                        | io::ErrorKind::NotFound
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::PermissionDenied
                )
            {
                let _ = client::send_with(
                    &config.socket,
                    token,
                    Action::CancelOperation {
                        operation_id: id.clone(),
                    },
                    client::SendOptions {
                        host_session: config.host_session.as_deref(),
                        timeout: Some(Duration::from_secs(5)),
                    },
                );
            }
            transport_error(&error)
        }
    };
    attach_operation(result, operation_id.as_deref())
}

fn valid_operation_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn new_operation_id() -> io::Result<String> {
    let mut bytes = [0; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn attach_operation(mut result: Value, operation_id: Option<&str>) -> Value {
    if let Some(id) = operation_id.filter(|id| valid_operation_id(id)) {
        result["structuredContent"]["operation_id"] = json!(id);
        if result["isError"] == true {
            result["structuredContent"]["next_step"] = json!(format!(
                "Retrieve metadata with apassy_list_access({{\"operation_id\":\"{id}\"}}). If unavailable, verify activity and the external target with the owner before retrying. Never blindly replay a mutation."
            ));
        }
        result["content"].as_array_mut().unwrap().push(json!({"type":"text", "text":format!("Operation {id}. Retrieve metadata with apassy_list_access({{\"operation_id\":\"{id}\"}}). Retention: 15 minutes after completion, in this broker and vault session. Never blindly replay an unknown or expired operation.")}));
    }
    result
}

fn call_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(_extra) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "item_id" | "operation" | "params"))
    {
        return Err("An unexpected argument is not permitted. Use the tool schema.".to_owned());
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
                .ok_or_else(|| "Each operation parameter must be a string.".to_owned())?;
            params.insert(key.clone(), text.to_owned());
        }
    }
    Ok(Action::Call {
        item_id,
        operation,
        params,
    })
}

fn run_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(_extra) = object.keys().find(|key| {
        !matches!(
            key.as_str(),
            "items"
                | "codes"
                | "command"
                | "cwd"
                | "purpose"
                | "user_request"
                | "access_request_id"
        )
    }) {
        return Err("An unexpected argument is not permitted. Use the tool schema.".to_owned());
    }
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "The items argument must be an array of item IDs.".to_owned())?
        .iter()
        .map(|item| {
            item.as_u64()
                .filter(|id| *id > 0)
                .ok_or_else(|| "Each item ID must be a positive integer.".to_owned())
        })
        .collect::<Result<Vec<u64>, String>>()?;
    let codes = match object.get("codes") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .ok_or("codes must be an array of item IDs.")?
            .iter()
            .map(|v| {
                v.as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "Each code item ID must be positive.".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let command = object
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| "The command argument must be an array of strings.".to_owned())?
        .iter()
        .map(|arg| {
            arg.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "Each command argument must be a string.".to_owned())
        })
        .collect::<Result<Vec<String>, String>>()?;
    let text = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("The {name} argument must be a string."))
    };
    if (items.is_empty() && codes.is_empty()) || command.is_empty() {
        return Err("Give at least one item and a nonempty command argument list.".to_owned());
    }
    Ok(Action::Run {
        access_request_id: object
            .get("access_request_id")
            .map(|v| {
                v.as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "Use a positive access_request_id.".to_owned())
            })
            .transpose()?,
        items,
        codes,
        command,
        cwd: text("cwd")?,
        purpose: text("purpose")?,
        user_request: Some(text("user_request")?),
        // The process uses the PATH of the agent host, so tools such as npm resolve the same way.
        path: std::env::var("PATH").ok(),
    })
}

fn request_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(_extra) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "item_id" | "reason" | "cwd" | "scope"))
    {
        return Err("An unexpected argument is not permitted. Use the tool schema.".to_owned());
    }
    let item_id = object
        .get("item_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| "The item_id argument must be a positive integer.".to_owned())?;
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| "The reason argument must be a string.".to_owned())?
        .to_owned();
    let cwd = match object.get("cwd") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| "The cwd argument must be a string.".to_owned())?
                .to_owned(),
        ),
    };
    Ok(Action::RequestAccess {
        scope: object
            .get("scope")
            .map(|v| {
                serde_json::from_value(v.clone()).map_err(|_| "Use the scope schema.".to_owned())
            })
            .transpose()?,
        item_id,
        reason,
        cwd,
    })
}

/// The arguments as an object with only the `allowed` keys.
fn arguments_object<'a>(
    arguments: &'a Value,
    allowed: &[&str],
) -> Result<&'a Map<String, Value>, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(_extra) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err("An unexpected argument is not permitted. Use the tool schema.".to_owned());
    }
    Ok(object)
}

fn optional_text(object: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| format!("The {name} argument must be a string.")),
    }
}

fn required_text(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    optional_text(object, name)?
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("The {name} argument must be a nonempty string."))
}

fn optional_strings(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_array()
            .ok_or_else(|| format!("The {name} argument must be an array of strings."))?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("Each {name} entry must be a string."))
            })
            .collect::<Result<Vec<String>, String>>()
            .map(Some),
    }
}

fn item_id(object: &Map<String, Value>) -> Result<u64, String> {
    object
        .get("item_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| "The item_id argument must be a positive integer.".to_owned())
}

fn length(object: &Map<String, Value>) -> Result<Option<u32>, String> {
    match object.get("length") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|length| u32::try_from(length).ok())
            .map(Some)
            .ok_or_else(|| "The length argument must be a positive integer.".to_owned()),
    }
}

/// The working directory of the call: the argument, or the folder of this MCP server
/// (the agent host starts it in the project).
fn cwd_or_here(object: &Map<String, Value>) -> Result<Option<String>, String> {
    Ok(optional_text(object, "cwd")?.or_else(|| {
        std::env::current_dir()
            .ok()
            .map(|dir| dir.display().to_string())
    }))
}

/// The `extract` argument: one of `json`, `line`, and `after`.
fn extract(object: &Map<String, Value>) -> Result<Option<Extract>, String> {
    match object.get("extract") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value::<Extract>(value.clone())
            .map(Some)
            .map_err(|_| {
                "The extract argument must be one of {\"json\": \"a.b\"}, {\"line\": 2}, or {\"after\": \"Token:\"}.".to_owned()
            }),
    }
}

fn exactly_one_source(object: &Map<String, Value>, keys: &[&str]) -> Result<(), String> {
    if keys
        .iter()
        .any(|key| object.get(*key).is_some_and(Value::is_null))
    {
        return Err("Omit unused source fields instead of sending null.".to_owned());
    }
    if keys
        .iter()
        .filter(|key| object.get(**key).is_some_and(|v| !v.is_null()))
        .count()
        != 1
    {
        return Err(format!("Give exactly one source: {}.", keys.join(", ")));
    }
    if object
        .get("file")
        .is_some_and(|v| v.as_str().is_none_or(str::is_empty))
        || object
            .get("command")
            .is_some_and(|v| v.as_array().is_none_or(Vec::is_empty))
    {
        return Err("The selected file or command must be nonempty.".to_owned());
    }
    Ok(())
}

fn transport_error(error: &io::Error) -> Value {
    let (code, message) = match error.kind() {
        io::ErrorKind::InvalidInput => (
            "too_large",
            "The serialized request exceeds the wire limit. Use a smaller value or capture from a file.",
        ),
        io::ErrorKind::PermissionDenied => (
            "permission_denied",
            "Access to the broker socket was denied. Check socket permissions and the sandbox configuration.",
        ),
        io::ErrorKind::NotFound => (
            "app_not_running",
            "The broker socket is missing. Check APASSY_BROKER_SOCKET; open Apassy if it is closed.",
        ),
        io::ErrorKind::ConnectionRefused => (
            "connection_refused",
            "The broker refused the connection. Check APASSY_BROKER_SOCKET and the app broker status.",
        ),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => (
            "unknown_outcome",
            "The broker response timed out. The operation may have executed.",
        ),
        io::ErrorKind::InvalidData => (
            "protocol_error",
            "The broker response is invalid or incomplete. Check that app and MCP versions match; execution outcome may be unknown.",
        ),
        _ => (
            "unknown_outcome",
            "The broker connection ended without a usable response. The operation may have executed.",
        ),
    };
    tool_error(code, message)
}

fn capture_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(
        arguments,
        &[
            "name", "command", "file", "cwd", "folder", "purpose", "extract",
        ],
    )?;
    exactly_one_source(object, &["command", "file"])?;
    Ok(Action::CaptureCredential {
        name: optional_text(object, "name")?,
        command: optional_strings(object, "command")?,
        file: optional_text(object, "file")?,
        cwd: cwd_or_here(object)?,
        folder: optional_text(object, "folder")?,
        purpose: optional_text(object, "purpose")?,
        // Only for a command that the owner approves. A known token command never uses it.
        path: std::env::var("PATH").ok(),
        extract: extract(object)?,
    })
}

fn generate_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(arguments, &["name", "length", "alphabet", "cwd", "folder"])?;
    if let Some(alphabet) = optional_text(object, "alphabet")?
        && !["alnum", "hex", "base64url", "symbols"].contains(&alphabet.as_str())
    {
        return Err("Choose alphabet: alnum, hex, base64url, or symbols.".to_owned());
    }
    if length(object)?.is_some_and(|n| !(16..=128).contains(&n)) {
        return Err("Use a generated length from 16 through 128.".to_owned());
    }
    Ok(Action::GenerateCredential {
        name: required_text(object, "name")?,
        length: length(object)?,
        alphabet: optional_text(object, "alphabet")?,
        cwd: cwd_or_here(object)?,
        folder: optional_text(object, "folder")?,
    })
}

fn save_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(arguments, &["name", "value", "cwd", "folder"])?;
    let value = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| "The value argument must be a string.".to_owned())?;
    Ok(Action::SaveCredential {
        name: optional_text(object, "name")?,
        value: AgentSecret::new(value.to_owned()),
        cwd: cwd_or_here(object)?,
        folder: optional_text(object, "folder")?,
    })
}

fn ask_owner_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(
        arguments,
        &["name", "purpose", "where_to_get", "cwd", "folder"],
    )?;
    Ok(Action::AskOwnerForCredential {
        name: required_text(object, "name")?,
        purpose: required_text(object, "purpose")?,
        where_to_get: optional_text(object, "where_to_get")?,
        cwd: cwd_or_here(object)?,
        folder: optional_text(object, "folder")?,
    })
}

fn update_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(
        arguments,
        &["item_id", "command", "file", "generate", "cwd", "extract"],
    )?;
    let generate = match object.get("generate") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<GenerateSpec>(value.clone()).map_err(|_| {
                "The generate argument must be an object with length and alphabet.".to_owned()
            })?,
        ),
    };
    exactly_one_source(object, &["command", "file", "generate"])?;
    Ok(Action::UpdateCredential {
        item_id: item_id(object)?,
        command: optional_strings(object, "command")?,
        file: optional_text(object, "file")?,
        generate,
        cwd: cwd_or_here(object)?,
        path: std::env::var("PATH").ok(),
        extract: extract(object)?,
    })
}

fn describe_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(
        arguments,
        &["item_id", "name", "notes", "env_name", "placeholder_hosts"],
    )?;
    Ok(Action::DescribeCredential {
        item_id: item_id(object)?,
        name: optional_text(object, "name")?,
        notes: optional_text(object, "notes")?,
        env_name: optional_text(object, "env_name")?,
        placeholder_hosts: optional_strings(object, "placeholder_hosts")?,
    })
}

fn tool_result(response: WireResponse) -> Value {
    let operation_id = response.operation_id.clone();
    let result = if response.ok {
        let result = response.result.unwrap_or(Value::Null);
        let text = serde_json::to_string_pretty(&result).unwrap_or_default();
        json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "result": result },
            "isError": false,
        })
    } else {
        broker_error(
            response
                .error
                .as_ref()
                .map_or("broker_error", |error| &error.code),
        )
    };
    attach_operation(result, operation_id.as_deref())
}

/// Broker messages can contain request names, paths, or command text. Only
/// recognized codes and fixed messages cross the MCP diagnostic boundary.
pub(crate) fn broker_error(code: &str) -> Value {
    let (code, message) = match code {
        "access_once_unavailable" => (
            code,
            "This scoped use is unavailable or consumed. Query apassy_access_request_status; never repeat an admitted use.",
        ),
        "access_request_waiting" => (
            code,
            "Another scope is active for this agent. Query its access status or review on the Mac.",
        ),
        "access_request_rate_limited" => (
            code,
            "The conservative Mac-local access-request budget is exhausted. Review on the Mac.",
        ),
        "not_found" => (code, "This request is unavailable to this agent."),
        "cancelled" => (code, "The operation was cancelled before execution."),
        "unknown_outcome" | "cancellation_requested" => (
            code,
            "The operation may already have run; retrieve its status before retrying.",
        ),
        "operation_not_found" => (
            code,
            "No retained operation was found. It may have expired, or the broker or vault session restarted. Verify the external target before retrying.",
        ),
        "operation_conflict" | "idempotency_conflict" => (
            code,
            "The key or operation ID was used with different arguments. Nothing was replayed.",
        ),
        "token_expired" => (code, "The Apassy agent token expired."),
        "unauthenticated" => (
            code,
            "The agent token is not valid for the Apassy vault that is open now.",
        ),
        "vault_locked" => (code, "The Apassy vault is locked."),
        "question_waiting" => (code, "A different owner question is pending."),
        "waiting" => (
            code,
            "The credential request is still waiting for the owner.",
        ),
        "dismissed" => (code, "The owner dismissed the credential request."),
        "owner_timeout" | "approval_timeout" => (code, "The owner approval timed out."),
        "timeout" => (code, "The operation timed out; its outcome may be unknown."),
        "approval_denied" => (code, "The owner denied the request."),
        "not_visible" | "not_granted" | "not_owner" | "item_archived" | "review_required" => (
            code,
            "The credential is unavailable for this request. Ask the owner to review its access settings.",
        ),
        "approval_invalidated" | "authorization_changed" => (
            code,
            "The authorization changed. Review the request with the owner.",
        ),
        "no_code" => (
            code,
            "The selected item has no one-time password detail. Check has_code in the catalog.",
        ),
        "invalid_code" => (
            code,
            "The item must have one unambiguous supported one-time password setting. Ask the owner to review it.",
        ),
        "invalid_request" | "bad_request" | "unknown_folder" | "env_name_taken" => (
            code,
            "The broker refused the request parameters. Check the tool schema and catalog.",
        ),
        "too_many_items" | "too_many_requests" | "busy" => (
            code,
            "The broker cannot accept another request yet. Wait and consult the owner.",
        ),
        "capture_refused" => (
            code,
            "The credential capture was refused. Review the capture rules with the owner.",
        ),
        "answer_failed" => (code, "The broker could not save the owner's answer."),
        "permission_denied" => (code, "The broker denied permission for this request."),
        "start_failed" => (
            code,
            "The command did not start. Check the program name and PATH.",
        ),
        "missing_secret"
        | "proxy_failed"
        | "tls_failed"
        | "destination_error"
        | "destination_not_found"
        | "destination_refused"
        | "destination_unreachable"
        | "bad_output"
        | "output_blocked"
        | "unsupported_version"
        | "broker_error" => (
            code,
            "The broker could not complete the request. Inspect Apassy activity for details.",
        ),
        _ => (
            "broker_error",
            "The broker returned an unrecognized refusal. Inspect Apassy activity for details.",
        ),
    };
    tool_error(code, message)
}

/// Next step for a refusal that only the user can fix. The agent host shows the text.
fn hint(code: &str) -> Option<&'static str> {
    match code {
        "token_expired" => Some(
            "Tell the user: the Apassy agent token of this MCP server expired. In the Apassy app, open Agents and click \"Rotate token\". Put the new token in APASSY_AGENT_TOKEN of the MCP server configuration, then restart the MCP server. Do not retry before that.",
        ),
        // ADR 0013: the owner can keep several vaults, one open at a time. The text
        // names no vault and no count.
        "unauthenticated" => Some(
            "Tell the user: Apassy did not accept the agent token of this MCP server. The token is not valid for the vault that is open in Apassy now. If the user keeps several vaults, the user opens and unlocks the vault where this agent is registered. If the user revoked the agent or rotated its token, the user puts a new token from Agents in APASSY_AGENT_TOKEN of the MCP server configuration and restarts the MCP server. Do not retry before that.",
        ),
        "review_required" => Some(
            "Tell the user: the Apassy vault was restored from a backup. In the Apassy app, open the item, examine its agent settings, and click \"Confirm settings\". Do not retry before that.",
        ),
        "not_visible" => Some(
            "Tell the user: the owner did not let this agent see this credential. Only the user can change that: in the Apassy app, open Agents, open this agent, and turn on \"All credentials, without values\". Do not retry before that.",
        ),
        "item_archived" => Some(
            "Tell the user: this credential is archived in Apassy. Only the user can bring it back: in the Apassy app, open the credential and click \"Restore from archive\". Do not retry before that, and do not look for the secret elsewhere.",
        ),
        "vault_locked" => Some("Ask the owner to unlock the vault in Apassy, then retry."),
        "question_waiting" => Some(
            "A different owner question is pending. Wait for it to finish before submitting this request; do not repeat it in a loop.",
        ),
        "owner_timeout" | "approval_timeout" => {
            Some("The owner approval timed out. Ask the owner to resolve it before retrying.")
        }
        "timeout" | "unknown_outcome" | "protocol_error" => Some(
            "Inspect activity and verify the external target with the owner before retrying. Never blindly repeat a mutating call.",
        ),
        "permission_denied" | "connection_refused" | "app_not_running" | "too_large" => {
            Some("Correct the reported cause before retrying.")
        }
        _ => None,
    }
}

fn tool_error(code: &str, message: &str) -> Value {
    let text = match hint(code) {
        Some(hint) => format!("{code}: {message}\n{hint}"),
        None => format!("{code}: {message}"),
    };
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "code": code, "message": message,
            "next_step": hint(code).unwrap_or("Review the refusal with the owner. If the call could have changed external state, verify the outcome first. Never blindly repeat a mutating call."),
            "retryable": false },
        "isError": true,
    })
}

#[cfg(all(test, feature = "vault"))]
#[path = "mcp_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn validation_and_broker_errors_never_echo_request_content() {
        let canary = "synthetic-secret /private/path command --token";
        let result = call_tool(
            &config(),
            &json!({"name": TOOL_USE_CREDENTIAL, "arguments": {
                "item_id": 1, "operation": "test", "params": {(canary): {}}
            }}),
        );
        assert_eq!(result["structuredContent"]["code"], "invalid_arguments");
        assert!(!result.to_string().contains(canary));
        for code in ["question_waiting", "invalid_request", "timeout", canary] {
            let result = tool_result(WireResponse::failure(code, canary));
            assert!(!result.to_string().contains(canary));
            assert_eq!(result["structuredContent"]["retryable"], false);
            if code == "timeout" {
                assert!(
                    result["structuredContent"]["next_step"]
                        .as_str()
                        .unwrap()
                        .contains("Never blindly repeat")
                );
            }
        }
    }

    #[cfg(feature = "vault")]
    #[test]
    fn socket_permission_and_refusal_are_distinct() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        let socket = private.join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut cfg = config();
        cfg.socket = socket;
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = call_tool(&cfg, &json!({"name": TOOL_LIST_ACCESS}));
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(denied["structuredContent"]["code"], "permission_denied");
        drop(listener);
        let refused = call_tool(&cfg, &json!({"name": TOOL_LIST_ACCESS}));
        assert_eq!(refused["structuredContent"]["code"], "connection_refused");
    }

    #[test]
    fn source_schema_one_of_validation_matches_adapter() {
        // Evaluate the standard required/not/anyOf predicates used in source branches.
        fn accepts(schema: &Value, value: &Value) -> bool {
            if let Some(required) = schema.get("required").and_then(Value::as_array)
                && !required
                    .iter()
                    .all(|key| value.get(key.as_str().unwrap()).is_some())
            {
                return false;
            }
            if let Some(not) = schema.get("not")
                && accepts(not, value)
            {
                return false;
            }
            if let Some(any) = schema.get("anyOf").and_then(Value::as_array)
                && !any.iter().any(|branch| accepts(branch, value))
            {
                return false;
            }
            true
        }
        let tools = tool_list();
        for (tool_name, sources) in [
            (TOOL_CAPTURE_CREDENTIAL, vec!["command", "file"]),
            (TOOL_UPDATE_CREDENTIAL, vec!["command", "file", "generate"]),
        ] {
            let tool = tools
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == tool_name)
                .unwrap();
            let branches = tool["inputSchema"]["oneOf"].as_array().unwrap();
            for mask in 0..(1 << sources.len()) {
                let mut value = json!({"item_id":1});
                for (bit, source) in sources.iter().enumerate() {
                    if mask & (1 << bit) != 0 {
                        value[*source] = match *source {
                            "command" => json!(["true"]),
                            "file" => json!("/tmp/synthetic"),
                            _ => json!({}),
                        };
                    }
                }
                let schema_valid = branches
                    .iter()
                    .filter(|branch| accepts(branch, &value))
                    .count()
                    == 1;
                if tool_name == TOOL_CAPTURE_CREDENTIAL {
                    value.as_object_mut().unwrap().remove("item_id");
                }
                let adapter_valid = if tool_name == TOOL_CAPTURE_CREDENTIAL {
                    capture_action(&value).is_ok()
                } else {
                    update_action(&value).is_ok()
                };
                assert_eq!(schema_valid, adapter_valid, "{tool_name}: {value}");
            }
        }
    }

    #[test]
    fn oversized_request_fails_before_connection_and_excludes_value() {
        let result = call_tool(
            &config(),
            &json!({"name":TOOL_SAVE_CREDENTIAL,"arguments":{"value":"synthetic-secret".repeat(MAX_LINE_BYTES)}}),
        );
        assert_eq!(result["structuredContent"]["code"], "too_large");
        assert!(!result.to_string().contains("synthetic-secret"));
    }

    #[cfg(feature = "vault")]
    #[test]
    fn stub_broker_refusals_and_client_timeout_keep_their_causes() {
        use std::os::unix::net::UnixListener;
        for code in ["vault_locked", "approval_timeout", "permission_denied"] {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("broker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let broker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                std::io::BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut request)
                    .unwrap();
                serde_json::to_writer(
                    &mut stream,
                    &WireResponse::failure(code, "Synthetic refusal"),
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            });
            let mut cfg = config();
            cfg.socket = socket;
            let result = call_tool(&cfg, &json!({"name": TOOL_LIST_ACCESS}));
            broker.join().unwrap();
            assert_eq!(result["structuredContent"]["code"], code);
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });
        let error = client::send_with(
            &socket,
            "synthetic-token",
            Action::ListAccess,
            client::SendOptions {
                timeout: Some(Duration::from_millis(10)),
                host_session: None,
            },
        )
        .unwrap_err();
        assert_eq!(
            transport_error(&error)["structuredContent"]["code"],
            "unknown_outcome"
        );
        broker.join().unwrap();
    }

    #[test]
    fn error_categories_are_structured_and_sanitized() {
        for (kind, code) in [
            (io::ErrorKind::InvalidInput, "too_large"),
            (io::ErrorKind::PermissionDenied, "permission_denied"),
            (io::ErrorKind::ConnectionRefused, "connection_refused"),
            (io::ErrorKind::NotFound, "app_not_running"),
            (io::ErrorKind::TimedOut, "unknown_outcome"),
            (io::ErrorKind::InvalidData, "protocol_error"),
        ] {
            let result = transport_error(&io::Error::new(kind, "synthetic-secret"));
            assert_eq!(result["structuredContent"]["code"], code);
            assert!(!result.to_string().contains("synthetic-secret"));
            assert_eq!(result["structuredContent"]["retryable"], false);
        }
        for code in ["vault_locked", "owner_timeout", "question_waiting"] {
            let result = tool_result(WireResponse::failure(code, "Synthetic refusal"));
            assert!(
                result["structuredContent"]["next_step"]
                    .as_str()
                    .unwrap()
                    .len()
                    > 20
            );
        }
    }

    #[test]
    fn source_schemas_and_adapter_refuse_ambiguous_calls() {
        for arguments in [json!({}), json!({"command":["true"],"file":"/tmp/x"})] {
            assert!(capture_action(&arguments).is_err());
        }
        assert!(update_action(&json!({"item_id":1})).is_err());
        assert!(
            run_action(&json!({"items":[1],"command":["true"],"cwd":"/tmp","purpose":"test"}))
                .is_err()
        );
        let result = call_tool(
            &config(),
            &json!({"name":TOOL_LIST_ACCESS,"arguments":{"extra":true}}),
        );
        assert_eq!(result["structuredContent"]["code"], "invalid_arguments");
        for tool in tool_list().as_array().unwrap() {
            let schema = &tool["inputSchema"];
            assert_eq!(schema["additionalProperties"], false);
            if tool["name"] == TOOL_CAPTURE_CREDENTIAL || tool["name"] == TOOL_UPDATE_CREDENTIAL {
                assert!(schema["oneOf"].as_array().unwrap().len() >= 2);
            }
        }
    }

    #[cfg(feature = "vault")]
    #[test]
    fn malformed_stub_broker_keeps_protocol_cause() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            stream.write_all(b"synthetic-secret\n").unwrap();
        });
        let mut cfg = config();
        cfg.socket = socket;
        let result = call_tool(&cfg, &json!({"name":TOOL_LIST_ACCESS}));
        broker.join().unwrap();
        assert_eq!(result["structuredContent"]["code"], "protocol_error");
        assert!(!result.to_string().contains("synthetic-secret"));
    }

    #[test]
    fn audit_mcp_frame_is_bounded_without_a_newline() {
        let mut input = std::io::Cursor::new(vec![b'x'; MAX_LINE_BYTES * 8]);
        let mut line = String::new();
        assert!(read_frame(&mut input, &mut line).is_err());
        assert!(line.len() <= MAX_LINE_BYTES + 1);
        assert!(input.position() <= (MAX_LINE_BYTES + 1) as u64);
    }

    use super::*;

    fn config() -> AdapterConfig {
        AdapterConfig {
            socket: PathBuf::from("/nonexistent/apassy-test.sock"),
            token: Some("apassy_agt_test".to_owned()),
            host_session: None,
        }
    }

    #[test]
    fn scoped_access_refusals_are_typed_and_status_tools_never_get_cached() {
        for code in [
            "access_once_unavailable",
            "access_request_waiting",
            "access_request_rate_limited",
        ] {
            assert_eq!(broker_error(code)["structuredContent"]["code"], code);
        }
        for name in [TOOL_ACCESS_STATUS, TOOL_ACCESS_CANCEL] {
            let tools = tool_list();
            let tool = tools
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == name)
                .unwrap();
            assert!(
                tool["inputSchema"]["properties"]
                    .get("idempotency_key")
                    .is_none()
            );
        }
        assert!(!Action::AccessRequestStatus { request_id: 81 }.trackable());
        assert!(!Action::CancelAccessRequest { request_id: 81 }.trackable());
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
        assert_eq!(reply["result"]["tools"].as_array().map(Vec::len), Some(12));
        for name in [TOOL_ACCESS_STATUS, TOOL_ACCESS_CANCEL] {
            assert!(
                reply["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|tool| tool["name"] == name)
            );
        }
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
        let shell_string =
            json!({"items": [1], "command": "npm run x", "cwd": "/tmp", "purpose": "p"});
        assert!(run_action(&shell_string).is_err());
        let env_override = json!({"items": [1], "command": ["env"], "cwd": "/tmp", "purpose": "p", "env": {"X": "1"}});
        assert!(run_action(&env_override).is_err());
        let good = json!({"items": [1], "command": ["env"], "cwd": "/tmp", "purpose": "p", "user_request": "test"});
        assert!(matches!(run_action(&good), Ok(Action::Run { .. })));
    }

    /// M5, ADR 0025: the tools say that no grant is needed, that a question waits up to 5
    /// minutes, and that the agent calls again with the same request after a host time
    /// out. They steer to capture and generate, not save.
    #[test]
    fn tool_descriptions_follow_the_bouncer_model() {
        let tools = tool_list();
        let description = |name: &str| {
            tools
                .as_array()
                .expect("tools")
                .iter()
                .find(|tool| tool["name"] == name)
                .and_then(|tool| tool["description"].as_str())
                .expect("description")
                .to_owned()
        };
        for name in [
            TOOL_RUN_WITH_SECRETS,
            TOOL_REQUEST_ACCESS,
            TOOL_CAPTURE_CREDENTIAL,
            TOOL_ASK_OWNER_FOR_CREDENTIAL,
        ] {
            assert!(description(name).contains("5 minutes"), "{name}");
        }
        for name in [TOOL_LIST_ACCESS, TOOL_RUN_WITH_SECRETS, TOOL_REQUEST_ACCESS] {
            let text = description(name);
            assert!(text.contains("grant"), "{name}: {text}");
            assert!(!text.contains("process_access"), "{name}: {text}");
            assert!(!text.contains("chooses the folder"), "{name}: {text}");
        }
        assert!(description(TOOL_RUN_WITH_SECRETS).contains("execution outcome is unknown"));
        assert!(description(TOOL_RUN_WITH_SECRETS).contains("different owner question"));
        assert!(description(TOOL_SAVE_CREDENTIAL).contains("Prefer apassy_capture_credential"));
        let describe = tools
            .as_array()
            .expect("tools")
            .iter()
            .find(|tool| tool["name"] == TOOL_DESCRIBE_CREDENTIAL)
            .expect("describe")
            .clone();
        assert!(describe["inputSchema"]["properties"]["placeholder_hosts"].is_object());
        assert!(describe["inputSchema"]["properties"]["hosts"].is_null());
        let instructions = initialize_result(&json!({}))["instructions"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(instructions.contains("5 minutes") && instructions.contains("no grant"));
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
        assert!(text.starts_with("app_not_running"));
        assert!(!text.contains("apassy_agt_test"));
    }

    #[test]
    fn expired_token_gives_the_user_a_next_step() {
        let reply = tool_result(WireResponse::failure(
            "token_expired",
            "The Apassy agent token expired on 2026-10-26 10:00:00 UTC.",
        ));
        assert_eq!(reply["isError"], true);
        let text = reply["content"][0]["text"].as_str().unwrap_or_default();
        assert!(text.starts_with("token_expired: The Apassy agent token expired"));
        assert!(text.contains("Rotate token"), "{text}");
        assert!(text.contains("APASSY_AGENT_TOKEN"), "{text}");
        let other = tool_result(WireResponse::failure("not_granted", "No."));
        assert_eq!(other["structuredContent"]["code"], "not_granted");
        assert!(!other.to_string().contains("No."));
    }

    /// ADR 0013: a token of a vault that is not open gets a clear next step. The text
    /// names no other vault.
    #[test]
    fn a_token_for_another_vault_gives_the_user_a_next_step() {
        let reply = tool_result(WireResponse::failure(
            "unauthenticated",
            "The agent token is not valid for the Apassy vault that is open now. The owner may have another vault open, or the owner revoked the token.",
        ));
        assert_eq!(reply["isError"], true);
        let text = reply["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.starts_with("unauthenticated: The agent token is not valid for the Apassy vault that is open now."),
            "{text}"
        );
        assert!(
            text.contains("opens and unlocks the vault where this agent is registered"),
            "{text}"
        );
        assert!(text.contains("APASSY_AGENT_TOKEN"), "{text}");
        assert!(text.contains("Do not retry"), "{text}");
        assert!(!text.contains("vaults.json"), "{text}");
    }

    #[test]
    fn request_access_arguments_are_checked() {
        let action = request_action(&serde_json::json!({
            "item_id": 7,
            "reason": "The user asked to deploy.",
            "cwd": "/Users/me/Dev/app"
        }))
        .expect("action");
        assert_eq!(
            action,
            Action::RequestAccess {
                scope: None,
                item_id: 7,
                reason: "The user asked to deploy.".to_owned(),
                cwd: Some("/Users/me/Dev/app".to_owned()),
            }
        );
        for bad in [
            serde_json::json!({ "item_id": 0, "reason": "x" }),
            serde_json::json!({ "item_id": 7 }),
            serde_json::json!({ "item_id": 7, "reason": "x", "folder": "/" }),
            serde_json::json!({ "item_id": 7, "reason": "x", "cwd": 5 }),
        ] {
            assert!(request_action(&bad).is_err(), "{bad}");
        }
        let hint = tool_result(WireResponse::failure("not_visible", "No."));
        let text = hint["content"][0]["text"].as_str().unwrap_or_default();
        assert!(text.contains("All credentials, without values"), "{text}");
    }

    /// ADR 0025 §6: the arguments of the tools that add credentials.
    #[test]
    fn credential_tool_arguments_are_checked_and_a_saved_value_is_redacted() {
        let capture = capture_action(&json!({
            "command": ["gh", "auth", "token"],
            "cwd": "/Users/me/Dev/app",
            "name": "GitHub token"
        }))
        .expect("capture");
        let Action::CaptureCredential {
            command, cwd, path, ..
        } = &capture
        else {
            panic!("wrong action");
        };
        assert_eq!(command.as_deref().map(<[String]>::len), Some(3));
        assert_eq!(cwd.as_deref(), Some("/Users/me/Dev/app"));
        assert!(path.is_some());
        assert!(capture.waits());
        // Without cwd, the folder of the adapter is the project.
        let Action::CaptureCredential { cwd, .. } =
            capture_action(&json!({"file": "/tmp/key"})).expect("file")
        else {
            panic!("wrong action");
        };
        assert!(cwd.is_some());
        let canary = "FAKE-save-canary-5521";
        let save = save_action(&json!({"value": canary, "name": "Webhook secret"})).expect("save");
        assert!(!format!("{save:?}").contains(canary), "{save:?}");
        assert!(!save.waits());
        assert!(matches!(
            generate_action(&json!({"name": "DB password", "length": 24, "alphabet": "hex"})),
            Ok(Action::GenerateCredential {
                length: Some(24),
                ..
            })
        ));
        assert!(
            ask_owner_action(&json!({"name": "Sentry token", "purpose": "Upload maps."}))
                .expect("ask")
                .waits()
        );
        let update =
            update_action(&json!({"item_id": 3, "generate": {"length": 40}})).expect("update");
        assert!(matches!(
            update,
            Action::UpdateCredential {
                item_id: 3,
                generate: Some(GenerateSpec {
                    length: Some(40),
                    alphabet: None
                }),
                ..
            }
        ));
        assert!(
            describe_action(&json!({"item_id": 3, "placeholder_hosts": ["api.example.com"]}))
                .is_ok()
        );
        assert!(
            describe_action(&json!({"item_id": 3, "hosts": ["api.example.com"]})).is_err(),
            "hosts is renamed to placeholder_hosts"
        );
        let Action::CaptureCredential { extract, .. } = capture_action(&json!({
            "command": ["op", "read", "op://Private/Stripe/key"],
            "extract": {"json": "Credentials.SessionToken"}
        }))
        .expect("extract") else {
            panic!("wrong action");
        };
        assert_eq!(
            extract,
            Some(Extract::Json("Credentials.SessionToken".to_owned()))
        );
        assert!(matches!(
            update_action(&json!({"item_id": 3, "file": "/tmp/x", "extract": {"line": 2}})),
            Ok(Action::UpdateCredential {
                extract: Some(Extract::Line(2)),
                ..
            })
        ));
        for bad in [
            capture_action(&json!({"command": ["x"], "extract": {"json": "a", "line": 1}})),
            capture_action(&json!({"command": ["x"], "extract": {"regex": ".*"}})),
            capture_action(&json!({"command": ["x"], "extract": "Token:"})),
        ] {
            assert!(bad.is_err(), "{bad:?}");
        }
        for bad in [
            save_action(&json!({"value": 5})),
            save_action(&json!({"value": "x", "url": "http://x"})),
            generate_action(&json!({"length": 32})),
            generate_action(&json!({"name": "x", "length": -1})),
            ask_owner_action(&json!({"name": "x"})),
            update_action(&json!({"item_id": 0, "file": "/tmp/x"})),
            update_action(&json!({"item_id": 1, "generate": {"length": 32, "seed": 1}})),
            describe_action(&json!({"item_id": 1, "hosts": "api.example.com"})),
            capture_action(&json!({"command": "gh auth token"})),
        ] {
            assert!(bad.is_err(), "{bad:?}");
        }
        // The error text of a refused save never repeats the value.
        let error = save_action(&json!({"value": canary, "extra": canary})).unwrap_err();
        assert!(!error.contains(canary), "{error}");
    }
    #[test]
    fn code_only_run_has_explicit_typed_selection() {
        let action = run_action(&json!({"items":[],"codes":[7],"command":["true"],"cwd":"/tmp","purpose":"Synthetic test","user_request":"Synthetic test"})).unwrap();
        assert!(
            matches!(action, Action::Run { items, codes, .. } if items.is_empty() && codes == vec![7])
        );
        for codes in [json!([0]), json!(["7"]), json!(null)] {
            assert!(run_action(&json!({"items":[],"codes":codes,"command":["true"],"cwd":"/tmp","purpose":"Test","user_request":"Test"})).is_err());
        }
    }
}
