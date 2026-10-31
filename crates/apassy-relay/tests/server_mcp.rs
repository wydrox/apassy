//! The remote MCP endpoint `POST /mcp`.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use relay::{CANARY, Team, TestRelay, start};
use serde_json::{Value, json};

const USER: &str = "Please check the repository state.";

fn rpc_raw(
    relay: &TestRelay,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: &Value,
) -> (u16, String) {
    relay.call_with_headers("POST", "/mcp", token, headers, Some(body))
}

fn rpc(relay: &TestRelay, team: &Team, body: &Value) -> Value {
    let (status, text) = rpc_raw(relay, Some(&team.agent_token), &[], body);
    assert_eq!(status, 200, "{text}");
    serde_json::from_str(&text).unwrap()
}

fn call(relay: &TestRelay, team: &Team, name: &str, arguments: Value) -> Value {
    let reply = rpc(
        relay,
        team,
        &json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}}),
    );
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 7);
    assert!(reply.get("error").is_none(), "{reply}");
    reply["result"].clone()
}

fn error_text(result: &Value) -> String {
    assert_eq!(result["isError"], true, "{result}");
    assert!(result.get("structuredContent").is_none());
    result["content"][0]["text"].as_str().unwrap().to_string()
}

#[test]
fn initialize_negotiates_the_protocol_version() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    for version in ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] {
        let reply = rpc(
            &relay,
            &team,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}),
        );
        assert_eq!(reply["result"]["protocolVersion"], version);
    }
    for asked in [json!("1999-01-01"), json!(5), Value::Null] {
        let reply = rpc(
            &relay,
            &team,
            &json!({"jsonrpc": "2.0", "id": "a", "method": "initialize", "params": {"protocolVersion": asked}}),
        );
        assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(reply["id"], "a", "a string id comes back as it is");
    }
    let reply = rpc(
        &relay,
        &team,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    );
    let result = &reply["result"];
    assert_eq!(result["protocolVersion"], "2025-06-18");
    assert_eq!(
        result["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(result["serverInfo"]["name"], "apassy-relay");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    let instructions = result["instructions"].as_str().unwrap();
    assert!(instructions.starts_with("Apassy relay. Call apassy_list_access"));
    assert!(instructions.contains("apassy-team run"));
    assert!(instructions.contains("or ended"));
    assert!(instructions.contains("Do not automatically retry"));
}

#[test]
fn notifications_and_client_responses_get_202_and_no_body() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    for body in [
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}),
        json!({"jsonrpc": "2.0", "id": 9, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 9, "error": {"code": -1, "message": "no"}}),
    ] {
        let (status, text) = rpc_raw(&relay, Some(&team.agent_token), &[], &body);
        assert_eq!(status, 202, "{body}");
        assert_eq!(text, "");
    }
}

#[test]
fn ping_and_unknown_methods() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let reply = rpc(
        &relay,
        &team,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    );
    assert_eq!(reply["result"], json!({}));
    for method in [
        "resources/list",
        "prompts/list",
        "tools/nothing",
        "completion/complete",
    ] {
        let reply = rpc(
            &relay,
            &team,
            &json!({"jsonrpc": "2.0", "id": 2, "method": method}),
        );
        assert_eq!(reply["error"]["code"], -32601, "{method}");
        assert_eq!(reply["id"], 2);
        assert!(reply.get("result").is_none());
    }
}

#[test]
fn bad_json_and_bad_shapes_are_json_rpc_errors() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    // Not JSON.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut response = agent
        .post(&format!("{}/mcp", relay.url))
        .header("X-Apassy-Edge", &relay.edge_secret)
        .header("Authorization", format!("Bearer {}", team.agent_token))
        .send("this is {not json")
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let reply: Value =
        serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    assert_eq!(reply["id"], Value::Null);
    // A batch.
    let reply = rpc(
        &relay,
        &team,
        &json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]),
    );
    assert_eq!(reply["error"]["code"], -32600);
    // Not an object, no method, a method of the wrong type.
    for body in [
        json!(5),
        json!("x"),
        json!({"jsonrpc": "2.0", "id": 4}),
        json!({"jsonrpc": "2.0", "id": 4, "method": 7}),
    ] {
        let reply = rpc(&relay, &team, &body);
        assert_eq!(reply["error"]["code"], -32600, "{body}");
    }
    // tools/call without a tool name.
    let reply = rpc(
        &relay,
        &team,
        &json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {}}),
    );
    assert_eq!(reply["error"]["code"], -32602);
}

#[test]
fn the_endpoint_needs_an_agent_token() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    for token in [
        None,
        Some("apassy_agt_nothing"),
        Some(team.member_token.as_str()),
        Some(relay.owner_token.as_str()),
    ] {
        let (status, text) = rpc_raw(&relay, token, &[], &body);
        assert_eq!(status, 401, "{token:?}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "unauthenticated");
    }
    // A revoked agent is refused at the next call.
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        &relay.owner_token,
        None,
    );
    let (status, _) = rpc_raw(&relay, Some(&team.agent_token), &[], &body);
    assert_eq!(status, 401);
}

#[test]
fn the_origin_header_is_checked() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    for origin in ["https://evil.example", "http://127.0.0.1:1", "null"] {
        let (status, text) = rpc_raw(
            &relay,
            Some(&team.agent_token),
            &[("Origin", origin)],
            &body,
        );
        assert_eq!(status, 403, "{origin}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["error"]["code"], "forbidden");
    }
    let own = relay.config.public_url.clone();
    let (status, _) = rpc_raw(&relay, Some(&team.agent_token), &[("Origin", &own)], &body);
    assert_eq!(status, 200);
    // No Origin, and other unknown headers, are fine.
    let (status, _) = rpc_raw(
        &relay,
        Some(&team.agent_token),
        &[("MCP-Protocol-Version", "2099-01-01"), ("X-Whatever", "1")],
        &body,
    );
    assert_eq!(status, 200);
}

#[test]
fn get_and_delete_are_405() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    for method in ["GET", "DELETE"] {
        relay.fails(
            method,
            "/mcp",
            Some(&team.agent_token),
            None,
            405,
            "method_not_allowed",
        );
    }
}

#[test]
fn tools_list_has_the_three_tools_and_their_schemas() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    // No initialize before it.
    let reply = rpc(
        &relay,
        &team,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    let tools = reply["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "apassy_list_access",
            "apassy_request_run",
            "apassy_run_status"
        ]
    );
    for tool in tools {
        assert!(tool["description"].as_str().unwrap().len() > 20);
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }
    let run = &tools[1]["inputSchema"];
    assert_eq!(
        run["required"],
        json!(["items", "command", "purpose", "user_request"])
    );
    assert_eq!(run["properties"]["items"]["type"], "array");
    assert_eq!(run["properties"]["items"]["minItems"], 1);
    assert_eq!(run["properties"]["items"]["items"]["minimum"], 1);
    assert_eq!(run["properties"]["command"]["minItems"], 1);
    assert_eq!(run["properties"]["command"]["items"]["type"], "string");
    for field in ["purpose", "user_request", "cwd"] {
        assert_eq!(run["properties"][field]["type"], "string");
    }
    assert_eq!(run["properties"]["ttl_secs"]["type"], "integer");
    let status = &tools[2]["inputSchema"];
    assert_eq!(status["required"], json!(["run_id"]));
    assert_eq!(status["properties"]["wait_secs"]["minimum"], 0);
    assert_eq!(status["properties"]["wait_secs"]["maximum"], 25);
    assert_eq!(status["properties"]["wait_secs"]["default"], 20);
    assert_eq!(tools[0]["inputSchema"]["properties"], json!({}));
}

#[test]
fn list_access_works_without_initialize() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let result = call(&relay, &team, "apassy_list_access", json!({}));
    assert_eq!(result["isError"], false);
    assert_eq!(
        result["structuredContent"]["items"][0]["item_id"],
        team.item
    );
    assert_eq!(
        result["structuredContent"]["items"][0]["env_name"],
        "STRIPE_API_KEY"
    );
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
    assert_eq!(result["content"][0]["type"], "text");
    assert!(!result.to_string().contains(CANARY));
    // Arguments are not allowed.
    let error = call(&relay, &team, "apassy_list_access", json!({"x": 1}));
    assert!(error_text(&error).starts_with("invalid_request: "));
}

#[test]
fn request_run_waits_for_the_host_even_for_a_known_safe_command() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let asked = call(
        &relay,
        &team,
        "apassy_request_run",
        json!({
            "items": [team.item], "command": ["git", "status"], "purpose": "look", "user_request": USER, "cwd": "/work"
        }),
    );
    assert_eq!(asked["isError"], false);
    let view = &asked["structuredContent"];
    assert_eq!(view["status"], "pending");
    assert!(view.get("session").is_none());
    let run_id = view["run_id"].as_u64().unwrap();
    assert_eq!(relay.host_request(run_id)["suggestion"], "allow");
    // The host releases it, and the status tool shows the session.
    relay.release_ok(run_id);
    let status = call(
        &relay,
        &team,
        "apassy_run_status",
        json!({"run_id": run_id, "wait_secs": 0}),
    );
    let view = &status["structuredContent"];
    assert_eq!(view["status"], "ready");
    assert_eq!(view["decided_by"], "host");
    assert!(view["session"]["env"]["STRIPE_API_KEY"].is_string());
    assert!(
        view["session"]["env"]["STRIPE_API_BASE"]
            .as_str()
            .unwrap()
            .contains("/p/apassy_ses_")
    );
    let pending = call(
        &relay,
        &team,
        "apassy_request_run",
        json!({
            "items": [team.item], "command": ["python3", "x.py"], "purpose": "run it", "user_request": USER, "ttl_secs": 60
        }),
    );
    assert_eq!(pending["structuredContent"]["status"], "pending");
    assert!(pending["structuredContent"].get("session").is_none());
}

#[test]
fn request_run_failures_are_tool_errors_not_rpc_errors() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    // The user request is required by the tool schema.
    let result = call(
        &relay,
        &team,
        "apassy_request_run",
        json!({"items": [team.item], "command": ["git", "status"], "purpose": "x"}),
    );
    assert!(error_text(&result).starts_with("invalid_request: "));
    // An unknown field, a wrong type, a missing field.
    for arguments in [
        json!({"items": [team.item], "command": ["ls"], "purpose": "x", "user_request": "y", "path": "/bin"}),
        json!({"items": "1", "command": ["ls"], "purpose": "x", "user_request": "y"}),
        json!({"items": [team.item], "purpose": "x", "user_request": "y"}),
        json!("not an object"),
    ] {
        let result = call(&relay, &team, "apassy_request_run", arguments);
        assert!(error_text(&result).starts_with("invalid_request: "));
    }
    // An unknown item and a hard rule.
    let result = call(
        &relay,
        &team,
        "apassy_request_run",
        json!({"items": [4242], "command": ["ls"], "purpose": "x", "user_request": "y"}),
    );
    assert!(error_text(&result).starts_with("not_granted: "));
    relay.ok(
        "PUT",
        &format!("/v1/collections/{}/policy", team.collection),
        &relay.owner_token,
        Some(&json!({"rule": {"allowed_prefixes": ["git"]}})),
    );
    let result = call(
        &relay,
        &team,
        "apassy_request_run",
        json!({"items": [team.item], "command": ["ls"], "purpose": "x", "user_request": "y"}),
    );
    assert!(error_text(&result).starts_with("rule_command_not_permitted: "));
    // An unknown tool.
    let result = call(&relay, &team, "apassy_nothing", json!({}));
    assert_eq!(error_text(&result), "invalid_request: Unknown tool.");
}

#[test]
fn run_status_reads_a_run_and_waits() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let pending = call(
        &relay,
        &team,
        "apassy_request_run",
        json!({
            "items": [team.item], "command": ["python3", "x.py"], "purpose": "run it", "user_request": USER
        }),
    );
    let run_id = pending["structuredContent"]["run_id"].as_u64().unwrap();
    let started = std::time::Instant::now();
    let status = call(
        &relay,
        &team,
        "apassy_run_status",
        json!({"run_id": run_id, "wait_secs": 0}),
    );
    assert_eq!(status["structuredContent"]["status"], "pending");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    // With a wait, a release in the meantime ends it.
    let approver = {
        let url = relay.url.clone();
        let edge = relay.edge_secret.clone();
        let owner = relay.owner_token.clone();
        let body = relay.release_for(&relay.host_request(run_id), None);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(700));
            relay::call_url(
                &url,
                Some(&edge),
                "POST",
                &format!("/v1/host/requests/{run_id}/release"),
                Some(&owner),
                Some(&body),
            )
        })
    };
    let status = call(
        &relay,
        &team,
        "apassy_run_status",
        json!({"run_id": run_id}),
    );
    assert_eq!(approver.join().unwrap().0, 200);
    assert_eq!(status["structuredContent"]["status"], "ready");
    assert!(status["structuredContent"]["session"]["env"]["STRIPE_API_KEY"].is_string());
    // Bad arguments and another agent's run.
    for arguments in [
        json!({}),
        json!({"run_id": 0}),
        json!({"run_id": run_id, "wait_secs": 26}),
        json!({"run_id": run_id, "extra": 1}),
        json!({"run_id": "1"}),
    ] {
        let result = call(&relay, &team, "apassy_run_status", arguments);
        assert!(error_text(&result).starts_with("invalid_request: "));
    }
    let other = relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": "second"})),
    );
    let reply = relay.call_with_headers(
        "POST",
        "/mcp",
        other["secret"].as_str(),
        &[],
        Some(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "apassy_run_status", "arguments": {"run_id": run_id, "wait_secs": 0}}
        })),
    );
    let reply: Value = serde_json::from_str(&reply.1).unwrap();
    assert!(error_text(&reply["result"]).starts_with("not_found: "));
}
