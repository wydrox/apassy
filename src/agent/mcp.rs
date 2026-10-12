//! MCP stdio adapter. It forwards tool calls to the local broker socket.
//!
//! The adapter does not open the vault file and never receives a secret value.
//! It holds the agent token in process memory. The token is not a secret value
//! of a stored credential. The owner can revoke it in the desktop app.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::client;
use super::wire::{Action, AgentSecret, Extract, GenerateSpec, MAX_LINE_BYTES, WireResponse};

pub const TOOL_LIST_ACCESS: &str = "apassy_list_access";
pub const TOOL_USE_CREDENTIAL: &str = "apassy_use_credential";
pub const TOOL_RUN_WITH_SECRETS: &str = "apassy_run_with_secrets";
pub const TOOL_REQUEST_ACCESS: &str = "apassy_request_access";
pub const TOOL_CAPTURE_CREDENTIAL: &str = "apassy_capture_credential";
pub const TOOL_GENERATE_CREDENTIAL: &str = "apassy_generate_credential";
pub const TOOL_SAVE_CREDENTIAL: &str = "apassy_save_credential";
pub const TOOL_ASK_OWNER_FOR_CREDENTIAL: &str = "apassy_ask_owner_for_credential";
pub const TOOL_UPDATE_CREDENTIAL: &str = "apassy_update_credential";
pub const TOOL_DESCRIBE_CREDENTIAL: &str = "apassy_describe_credential";
/// A call that can wait for the owner (5 minutes) or for a command reads this long.
const WAITING_CALL_TIMEOUT: Duration = Duration::from_secs(600);
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
        "instructions": "Apassy lets you use the owner's credentials without seeing them. Call apassy_list_access first: its catalog lists each credential with its item_id and env_name, never a value. You need no grant: put item_ids in apassy_run_with_secrets and use the env_names in your command. The bouncer decides each use; when it asks the owner, the call waits up to 5 minutes. If your host ends the call first, or you get question_waiting, call again with the same request: it joins the waiting question. To store a new credential, prefer apassy_capture_credential (a command or a file prints it) or apassy_generate_credential (a new password or token); apassy_ask_owner_for_credential asks the owner to paste one. Use apassy_save_credential only for a value that is already in your transcript. Do not ask for secret values, and do not try to print them.",
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
    json!([
        {
            "name": TOOL_LIST_ACCESS,
            "title": "List the credentials you can use",
            "description": "List the credentials of the vault without values: the catalog has each item_id, name, folder, and env_name. You need no grant: a credential with access \"can_use\" goes into apassy_run_with_secrets, and the bouncer decides each use (it can ask the owner). \"needs_field\": the owner must pick one secret field first. Named operations are for apassy_use_credential. Never has secret values.",
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
            "description": "Run one command with catalog credentials in its environment, under the env_name of each item from apassy_list_access. You never get the values; in the output they show as [apassy:NAME]. env_holds \"a placeholder\": the real value goes only into HTTPS requests to its hosts (Authorization or API key header, or key parameter), never into a body or a file; network.requests lists them. No grant is needed: the bouncer decides each run, and when it asks the owner this call waits up to 5 minutes. If your host ends the call first, or you get question_waiting, call again with the same request: it joins the waiting question. The command is an argument list, not a shell string.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": { "type": "array", "items": { "type": "integer", "minimum": 1 }, "minItems": 1, "description": "Item IDs from process_access, or from the catalog (access \"can_use\")." },
                    "command": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Program and arguments, for example [\"npm\", \"run\", \"migrate\"]." },
                    "cwd": { "type": "string", "description": "Absolute working directory: the project folder. The bouncer uses the project." },
                    "purpose": { "type": "string", "description": "Why you need to run this command. The owner sees it." },
                    "user_request": { "type": "string", "description": "The user's own words from the conversation that led to this command. Quote them. Do not summarize or add words. The bouncer compares the command with this request, and the owner sees it." }
                },
                "required": ["items", "command", "cwd", "purpose", "user_request"],
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_REQUEST_ACCESS,
            "title": "Tell the owner why you need a credential",
            "description": "Usually not needed: no grant is required. Use a catalog credential directly with apassy_run_with_secrets; the bouncer decides, and when it asks the owner the call waits up to 5 minutes. This tool only records a note to the owner about one catalog credential and returns at once. For a credential that is not in Apassy, use apassy_ask_owner_for_credential.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": { "type": "integer", "minimum": 1, "description": "Item ID from the catalog." },
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
            "description": "The best way to store a credential: you never see it. Apassy runs a command or reads a file and saves the trimmed output (or the part that extract names); you get item_id and env_name. Known token commands run at once, such as [\"gh\", \"auth\", \"token\"], [\"op\", \"read\", \"op://vault/item/field\"], [\"gcloud\", \"auth\", \"print-access-token\"]. Any other command, or a file outside your project, waits for the owner (up to 5 minutes; on question_waiting or a host timeout call again with the same request). Refused: Apassy paths, more than 64 KiB, empty output, a non-zero exit code. At most 10 new or changed credentials per hour.",
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
                    "value": { "type": "string", "description": "The secret value. At most 64 KiB." },
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
            "description": "Ask the owner to paste a credential into Apassy. The call waits up to 5 minutes. When the owner saves it, you get item_id and env_name, never the value. On waiting, call again with the same name: the same name in the same project is the same request. On dismissed, tell the user. On question_waiting, another question of yours waits (the text names it): wait for it first. At most 5 open or new requests per hour.",
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
        TOOL_RUN_WITH_SECRETS => run_action(&arguments),
        TOOL_REQUEST_ACCESS => request_action(&arguments),
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
    let options = client::SendOptions {
        host_session: config.host_session.as_deref(),
        timeout: action.waits().then_some(WAITING_CALL_TIMEOUT),
    };
    match client::send_with(&config.socket, token, action, options) {
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

fn run_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(extra) = object.keys().find(|key| {
        !matches!(
            key.as_str(),
            "items" | "command" | "cwd" | "purpose" | "user_request"
        )
    }) {
        return Err(format!("The argument \"{extra}\" is not permitted."));
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
    Ok(Action::Run {
        items,
        command,
        cwd: text("cwd")?,
        purpose: text("purpose")?,
        user_request: object
            .get("user_request")
            .and_then(Value::as_str)
            .map(str::to_owned),
        // The process uses the PATH of the agent host, so tools such as npm resolve the same way.
        path: std::env::var("PATH").ok(),
    })
}

fn request_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "The arguments must be an object.".to_owned())?;
    if let Some(extra) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "item_id" | "reason" | "cwd"))
    {
        return Err(format!("The argument \"{extra}\" is not permitted."));
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
    if let Some(extra) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("The argument \"{extra}\" is not permitted."));
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
    optional_text(object, name)?.ok_or_else(|| format!("The {name} argument must be a string."))
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

fn capture_action(arguments: &Value) -> Result<Action, String> {
    let object = arguments_object(
        arguments,
        &[
            "name", "command", "file", "cwd", "folder", "purpose", "extract",
        ],
    )?;
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
            host_session: None,
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
        assert_eq!(reply["result"]["tools"].as_array().map(Vec::len), Some(10));
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
        let good = json!({"items": [1], "command": ["env"], "cwd": "/tmp", "purpose": "p"});
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
        assert!(description(TOOL_RUN_WITH_SECRETS).contains("call again with the same request"));
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
        assert!(text.starts_with("broker_unavailable"));
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
        assert_eq!(other["content"][0]["text"], "not_granted: No.");
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
}
