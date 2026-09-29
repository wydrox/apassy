//! End to end (docs/SPEC.md section 19): one relay in process with the real proxy,
//! a mock HTTPS upstream for api.stripe.com and api.github.com, the HTTP API, the
//! remote MCP endpoint, and the `apassy-team` binary. Synthetic values only.

#[path = "common/relay.rs"]
mod relay;
#[path = "common/upstream.rs"]
mod upstream;

use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use relay::TestRelay;
use serde_json::{Value, json};
use upstream::{MockUpstream, Recorded};

/// The staging Stripe value.
const STRIPE_CANARY: &str = "sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF";
/// The production GitHub value.
const GITHUB_CANARY: &str = "ghp_SyntheticCanaryTwoValue0123456789abcdefABCDEF";
const RELAY_HEADER: &str = "x-apassy-relay";
const USER_REQUEST: &str = "Please check the balance of our Stripe test account.";

/// A plain HTTP call that also gives back the response headers (names lowercase).
fn http(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, BTreeMap<String, String>, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(body.unwrap_or_default().as_bytes().to_vec())
        .expect("request");
    let mut response = agent.run(request).expect("http call");
    let status = response.status().as_u16();
    let heads = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_lowercase(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, heads, text)
}

/// The team of the test: ids and tokens.
struct Team {
    collection: u64,
    stripe_item: u64,
    github_item: u64,
    member_id: u64,
    member_token: String,
    invite_code: String,
    grant: u64,
    agent_token: String,
}

/// Steps 1 and 2: the owner makes the collection and both items, invites a member,
/// the member joins, the owner grants the collection, the member makes an agent.
fn make_team(relay: &TestRelay) -> Team {
    let owner = relay.owner_token.as_str();
    let collection = relay.ok(
        "POST",
        "/v1/collections",
        owner,
        Some(&json!({"name": "payments"})),
    )["id"]
        .as_u64()
        .expect("collection id");
    let stripe_item = relay.ok(
        "POST",
        "/v1/items",
        owner,
        Some(&json!({
            "collection_id": collection,
            "name": "Stripe test key",
            "env_name": "STRIPE_API_KEY",
            "value": STRIPE_CANARY,
            "provider": "stripe",
            "environment": "staging",
        })),
    )["id"]
        .as_u64()
        .expect("item id");
    let github_item = relay.ok(
        "POST",
        "/v1/items",
        owner,
        Some(&json!({
            "collection_id": collection,
            "name": "GitHub deploy token",
            "env_name": "GITHUB_TOKEN",
            "value": GITHUB_CANARY,
            "hosts": ["api.github.com"],
            "environment": "production",
        })),
    )["id"]
        .as_u64()
        .expect("item id");

    let invite = relay.ok(
        "POST",
        "/v1/invites",
        owner,
        Some(&json!({"role": "member"})),
    );
    let invite_code = invite["secret"].as_str().expect("code").to_string();
    let joined = relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(&json!({"code": invite_code, "name": "alice"})),
    );
    let member_id = joined["id"].as_u64().expect("member id");
    let member_token = joined["secret"].as_str().expect("token").to_string();
    let grant = relay.ok(
        "POST",
        "/v1/grants",
        owner,
        Some(&json!({"collection_id": collection, "member_id": member_id})),
    )["id"]
        .as_u64()
        .expect("grant id");
    let agent = relay.ok(
        "POST",
        "/v1/agents",
        &member_token,
        Some(&json!({"name": "alice-agent"})),
    );
    Team {
        collection,
        stripe_item,
        github_item,
        member_id,
        member_token,
        invite_code,
        grant,
        agent_token: agent["secret"].as_str().expect("token").to_string(),
    }
}

fn run_body(items: &[u64], command: &[&str], user_request: &str) -> Value {
    json!({
        "items": items,
        "command": command,
        "purpose": "check the account for the user",
        "user_request": user_request,
        "cwd": "/work",
    })
}

/// A proxied call with the edge header and `Authorization: Bearer <placeholder>`.
fn proxied(
    relay: &TestRelay,
    url: &str,
    placeholder: &str,
) -> (u16, BTreeMap<String, String>, String) {
    let bearer = format!("Bearer {placeholder}");
    http(
        "GET",
        url,
        &[
            ("X-Apassy-Edge", relay.edge_secret.as_str()),
            ("Authorization", bearer.as_str()),
        ],
        None,
    )
}

/// The last request the mock got for `host` and `target`.
fn seen(upstream: &MockUpstream, host: &str, target: &str) -> Recorded {
    upstream
        .requests()
        .into_iter()
        .rev()
        .find(|r| r.target == target && r.header("host") == Some(host))
        .unwrap_or_else(|| panic!("the upstream got no request for {host}{target}"))
}

/// A relay-made refusal: the status, the header, and the code.
fn assert_refused(answer: &(u16, BTreeMap<String, String>, String), status: u16, code: &str) {
    let (got, headers, text) = answer;
    assert_eq!(*got, status, "{text}");
    assert_eq!(
        headers.get(RELAY_HEADER).map(String::as_str),
        Some("refused"),
        "{text}"
    );
    let body: Value = serde_json::from_str(text).expect("envelope");
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], code, "{text}");
}

/// Checks a call through the Stripe base URL: the mock saw the value, the agent got
/// the placeholder back in the header and the body, and never the value.
fn check_stripe_swap(
    relay: &TestRelay,
    upstream: &MockUpstream,
    env: &Value,
    target: &str,
) -> String {
    let placeholder = env["STRIPE_API_KEY"].as_str().expect("placeholder");
    let base = env["STRIPE_API_BASE"].as_str().expect("base");
    assert_ne!(placeholder, STRIPE_CANARY);
    assert_eq!(placeholder.len(), STRIPE_CANARY.len());
    assert!(
        base.starts_with(&format!("{}/p/apassy_ses_", relay.url)),
        "{base}"
    );
    let before = upstream.requests().len();
    let (status, headers, text) = proxied(relay, &format!("{base}{target}"), placeholder);
    assert_eq!(status, 200, "{text}");
    assert_eq!(upstream.requests().len(), before + 1);
    let recorded = seen(upstream, "api.stripe.com", target);
    assert_eq!(
        recorded.header("authorization"),
        Some(format!("Bearer {STRIPE_CANARY}").as_str())
    );
    assert!(recorded.header("x-apassy-edge").is_none());
    assert_eq!(
        headers.get("x-echo-authorization").map(String::as_str),
        Some(format!("Bearer {placeholder}").as_str())
    );
    let echo: Value = serde_json::from_str(&text).expect("echo json");
    assert_eq!(echo["authorization"], format!("Bearer {placeholder}"));
    assert!(!text.contains(STRIPE_CANARY));
    assert!(!headers.values().any(|v| v.contains(STRIPE_CANARY)));
    placeholder.to_string()
}

/// Session keys from the base URLs of a session env.
fn session_keys(env: &Value) -> Vec<String> {
    env.as_object()
        .expect("env")
        .values()
        .filter_map(Value::as_str)
        .filter_map(|v| v.split("/p/").nth(1))
        .filter_map(|rest| rest.split('/').next())
        .map(str::to_string)
        .collect()
}

/// Every audit row, page by page, as one JSON text.
fn whole_audit(relay: &TestRelay) -> String {
    let mut rows = Vec::new();
    let mut after = 0;
    loop {
        let page = relay.ok(
            "GET",
            &format!("/v1/audit?after={after}&limit=500"),
            &relay.owner_token,
            None,
        );
        let page = page.as_array().expect("rows").clone();
        let Some(last) = page.last() else { break };
        after = last["id"].as_u64().expect("id");
        rows.extend(page);
    }
    assert!(rows.len() > 20, "the audit has only {} rows", rows.len());
    serde_json::to_string(&rows).expect("json")
}

/// Waits until the run of this command is pending, and returns its id.
fn pending_run_of(relay: &TestRelay, first_arg: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let list = relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
        if let Some(run) = list
            .as_array()
            .expect("list")
            .iter()
            .find(|a| a["command"][0] == first_arg)
        {
            return run["run_id"].as_u64().expect("run id");
        }
        assert!(Instant::now() < deadline, "no pending run of {first_arg}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn the_whole_flow_through_api_mcp_and_cli() {
    let upstream = upstream::start(&["api.stripe.com", "api.github.com"]);
    let relay = relay::start(upstream.options());
    let owner = relay.owner_token.clone();

    // 1 and 2.
    let team = make_team(&relay);
    let agent = team.agent_token.clone();
    let access = relay.ok("GET", "/v1/access", &agent, None);
    let access_text = access.to_string();
    assert!(access_text.contains("STRIPE_API_KEY") && access_text.contains("GITHUB_TOKEN"));
    assert!(!access_text.contains(STRIPE_CANARY) && !access_text.contains(GITHUB_CANARY));

    let mut placeholders = Vec::new();
    let mut keys = Vec::new();

    // 3. A known-safe command with a staging item runs at once.
    let (status, run) = relay.run(
        &agent,
        &run_body(
            &[team.stripe_item],
            &["stripe", "balance", "retrieve"],
            USER_REQUEST,
        ),
    );
    assert_eq!(status, 200, "{run}");
    let run = &run["result"];
    assert_eq!(run["status"], "ready", "{run}");
    assert_eq!(run["decided_by"], "known_safe");
    let stripe_env = run["session"]["env"].clone();
    placeholders.push(check_stripe_swap(
        &relay,
        &upstream,
        &stripe_env,
        "/v1/balance",
    ));
    keys.extend(session_keys(&stripe_env));

    // 4. A production item waits. Deny, then ask again and approve.
    let both = [team.github_item, team.stripe_item];
    let (status, run) = relay.run(&agent, &run_body(&both, &["git", "status"], USER_REQUEST));
    assert_eq!(status, 200, "{run}");
    assert_eq!(run["result"]["status"], "pending", "{run}");
    assert!(run["result"]["session"].is_null());
    assert!(
        run["result"]["note"]
            .as_str()
            .unwrap()
            .contains("Production credential"),
        "{run}"
    );
    let denied_id = run["result"]["run_id"].as_u64().unwrap();
    relay.ok(
        "POST",
        &format!("/v1/approvals/{denied_id}/deny"),
        &owner,
        Some(&json!({"reason": "not now"})),
    );
    let denied = relay.ok("GET", &format!("/v1/runs/{denied_id}"), &agent, None);
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["code"], "approval_denied");
    assert!(denied["session"].is_null());

    let (_, run) = relay.run(&agent, &run_body(&both, &["git", "status"], USER_REQUEST));
    assert_eq!(run["result"]["status"], "pending", "{run}");
    let approved_id = run["result"]["run_id"].as_u64().unwrap();
    let pending = relay.ok("GET", "/v1/approvals", &owner, None);
    assert!(
        pending
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["run_id"] == approved_id)
    );
    relay.ok(
        "POST",
        &format!("/v1/approvals/{approved_id}/approve"),
        &owner,
        Some(&json!({})),
    );
    let ready = relay.ok(
        "GET",
        &format!("/v1/runs/{approved_id}?wait=1"),
        &agent,
        None,
    );
    assert_eq!(ready["status"], "ready", "{ready}");
    assert_eq!(ready["decided_by"], "approver");
    let both_env = ready["session"]["env"].clone();
    keys.extend(session_keys(&both_env));
    let github_placeholder = both_env["GITHUB_TOKEN"].as_str().unwrap().to_string();
    let github_base = both_env["GITHUB_API_URL"].as_str().unwrap().to_string();
    assert_eq!(github_placeholder.len(), GITHUB_CANARY.len());
    let (status, headers, text) =
        proxied(&relay, &format!("{github_base}/user"), &github_placeholder);
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        seen(&upstream, "api.github.com", "/user").header("authorization"),
        Some(format!("Bearer {GITHUB_CANARY}").as_str())
    );
    assert_eq!(
        headers.get("x-echo-authorization").map(String::as_str),
        Some(format!("Bearer {github_placeholder}").as_str())
    );
    assert!(!text.contains(GITHUB_CANARY));
    placeholders.push(github_placeholder.clone());
    let both_stripe = check_stripe_swap(&relay, &upstream, &both_env, "/v1/customers");
    placeholders.push(both_stripe.clone());

    // 5. Refusals: a placeholder in the path, and a Stripe placeholder sent to GitHub.
    let stripe_base = both_env["STRIPE_API_BASE"].as_str().unwrap();
    let before = upstream.requests().len();
    let answer = proxied(
        &relay,
        &format!("{stripe_base}/v1/customers/{both_stripe}"),
        &both_stripe,
    );
    assert_refused(&answer, 403, "misplaced_placeholder");
    let answer = proxied(&relay, &format!("{github_base}/user"), &both_stripe);
    assert_refused(&answer, 403, "wrong_host");
    assert_eq!(
        upstream.requests().len(),
        before,
        "a refusal reached the upstream"
    );

    // 7a. The same flow through the remote MCP endpoint.
    let mcp_call = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "apassy_request_run", "arguments": {
            "items": [team.stripe_item],
            "command": ["stripe", "balance", "retrieve"],
            "purpose": "check the balance",
            "user_request": USER_REQUEST,
        }},
    });
    let (status, answer) = relay.call("POST", "/mcp", Some(&agent), Some(&mcp_call));
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["id"], 7);
    assert_eq!(answer["result"]["isError"], false, "{answer}");
    let mcp_run = &answer["result"]["structuredContent"];
    assert_eq!(mcp_run["status"], "ready", "{answer}");
    let mcp_env = mcp_run["session"]["env"].clone();
    keys.extend(session_keys(&mcp_env));
    placeholders.push(check_stripe_swap(
        &relay,
        &upstream,
        &mcp_env,
        "/v1/charges",
    ));
    let status_call = json!({
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "apassy_run_status",
                   "arguments": {"run_id": mcp_run["run_id"], "wait_secs": 0}},
    });
    let (_, answer) = relay.call("POST", "/mcp", Some(&agent), Some(&status_call));
    assert_eq!(answer["result"]["structuredContent"]["status"], "ready");

    // 7b. The same flow through `apassy-team run`. The child prints the variable to
    // stdout, so the command asks (secret_output); the owner approves it.
    let home = tempfile::tempdir().expect("home");
    let out = home.path().join("session.env");
    let child = Command::new(env!("CARGO_BIN_EXE_apassy-team"))
        .args([
            "run",
            "--items",
            &team.stripe_item.to_string(),
            "--purpose",
            "check the balance",
            "--request",
            USER_REQUEST,
            "--wait",
            "60",
            "--",
            "sh",
            "-c",
            r#"printf '%s\n%s\n' "$STRIPE_API_KEY" "$STRIPE_API_BASE" > "$E2E_OUT"; printf 'edge:%s\n' "${APASSY_EDGE_SECRET:-none}""#,
        ])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("APASSY_RELAY_URL", &relay.url)
        .env("APASSY_TOKEN", &agent)
        .env("APASSY_EDGE_SECRET", &relay.edge_secret)
        .env("E2E_OUT", &out)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("apassy-team");
    let cli_run = pending_run_of(&relay, "sh");
    let flags = relay.ok("GET", "/v1/approvals", &owner, None);
    let flags = flags
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["run_id"] == cli_run)
        .expect("pending")["flags"]
        .to_string();
    assert!(flags.contains("secret_output"), "{flags}");
    relay.ok(
        "POST",
        &format!("/v1/approvals/{cli_run}/approve"),
        &owner,
        Some(&json!({"reason": "ok for the test"})),
    );
    let output = child.wait_with_output().expect("apassy-team output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains(&format!("Waiting for an approver (run {cli_run}).")));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "edge:none\n");
    let written = std::fs::read_to_string(&out).expect("child output");
    let mut lines = written.lines();
    let cli_placeholder = lines.next().expect("placeholder");
    let cli_base = lines.next().expect("base");
    let cli_env = json!({"STRIPE_API_KEY": cli_placeholder, "STRIPE_API_BASE": cli_base});
    keys.extend(session_keys(&cli_env));
    placeholders.push(check_stripe_swap(
        &relay,
        &upstream,
        &cli_env,
        "/v1/payment_intents",
    ));

    // 6. The owner revokes the grant: live sessions end, a new run is not granted.
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        &owner,
        None,
    );
    let before = upstream.requests().len();
    let answer = proxied(
        &relay,
        &format!(
            "{}/v1/balance",
            stripe_env["STRIPE_API_BASE"].as_str().unwrap()
        ),
        &placeholders[0],
    );
    assert_refused(&answer, 403, "session_invalid");
    let answer = proxied(&relay, &format!("{github_base}/user"), &github_placeholder);
    assert_refused(&answer, 403, "session_invalid");
    let answer = proxied(&relay, &format!("{cli_base}/v1/balance"), cli_placeholder);
    assert_refused(&answer, 403, "session_invalid");
    assert_eq!(upstream.requests().len(), before);
    let (status, answer) = relay.run(
        &agent,
        &run_body(
            &[team.stripe_item],
            &["stripe", "balance", "retrieve"],
            USER_REQUEST,
        ),
    );
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "not_granted");
    let revoked_cli = Command::new(env!("CARGO_BIN_EXE_apassy-team"))
        .args([
            "run",
            "--items",
            &team.stripe_item.to_string(),
            "--purpose",
            "check the balance",
            "--",
            "true",
        ])
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("APASSY_RELAY_URL", &relay.url)
        .env("APASSY_TOKEN", &agent)
        .env("APASSY_EDGE_SECRET", &relay.edge_secret)
        .stdin(Stdio::null())
        .output()
        .expect("apassy-team");
    assert_eq!(revoked_cli.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&revoked_cli.stderr).contains("not_granted"));

    // 8. The whole audit holds no value, placeholder, token, or session key.
    let audit = whole_audit(&relay);
    for action in [
        "run_allowed",
        "run_pending",
        "run_denied",
        "run_approved",
        "session_started",
        "session_ended",
        "grant_revoked",
        "proxy_request",
    ] {
        assert!(audit.contains(action), "no {action} in the audit");
    }
    assert!(!keys.is_empty());
    let mut needles: Vec<&str> = vec![
        STRIPE_CANARY,
        GITHUB_CANARY,
        &owner,
        &agent,
        &team.member_token,
        &team.invite_code,
        &relay.edge_secret,
    ];
    needles.extend(placeholders.iter().map(String::as_str));
    needles.extend(keys.iter().map(String::as_str));
    for needle in needles {
        assert!(!audit.contains(needle), "the audit holds a secret");
    }
    assert!(
        !audit.contains("apassy_ses_"),
        "the audit holds a session key"
    );

    // The team is still sound for the owner: the member and the items are there.
    let members = relay.ok("GET", "/v1/members", &owner, None);
    assert!(members.to_string().contains("alice"));
    let items = relay.ok(
        "GET",
        &format!("/v1/items?collection={}", team.collection),
        &owner,
        None,
    );
    assert_eq!(items.as_array().unwrap().len(), 2);
    let _ = team.member_id;
    relay.stop();
}
