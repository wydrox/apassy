//! End to end (docs/SPEC.md section 19): one relay in process with the real proxy,
//! a mock HTTPS upstream for api.stripe.com and api.github.com, the HTTP API, the
//! remote MCP endpoint, and the `apassy-team` binary. Synthetic values only.
//!
//! The owner adds the items with `apassy-team item add` (the value is sealed there and
//! its key goes to a key store in a temp XDG dir). The owner's host runs as the real
//! host loop on a thread, with the same key store; the person at its terminal is a
//! script that gives the answers of the test. No run starts without a release.

#[path = "common/relay.rs"]
mod relay;
#[path = "common/upstream.rs"]
mod upstream;

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::broker::packs::RuleSet;
use apassy_relay::api::HostRequestView;
use apassy_relay::cli::client::Client;
use apassy_relay::cli::host::{Answer, HostContext, HostOptions, serve};
use apassy_relay::cli::keystore::{KeyEntry, KeyStore};
use apassy_relay::secret::SecretString;
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

/// `apassy-team` as the owner, with a key store in `config` (an XDG dir).
fn owner_cli(relay: &TestRelay, config: &Path, args: &[&str], stdin: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-team"))
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", config)
        .env("XDG_CONFIG_HOME", config)
        .env("APASSY_RELAY_URL", &relay.url)
        .env("APASSY_TEAM_TOKEN", &relay.owner_token)
        .env("APASSY_EDGE_SECRET", &relay.edge_secret)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("apassy-team");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write the value");
    child.wait_with_output().expect("apassy-team output")
}

/// `apassy-team item add` as the owner. Returns the item id.
fn cli_item_add(
    relay: &TestRelay,
    config: &Path,
    collection: u64,
    args: &[&str],
    value: &str,
) -> u64 {
    let collection = collection.to_string();
    let mut all = vec!["item", "add", "--collection", collection.as_str()];
    all.extend_from_slice(args);
    let output = owner_cli(relay, config, &all, &format!("{value}\n"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("keys.json"), "{stderr}");
    assert!(!stderr.contains(value));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(value));
    stdout.trim().parse().expect("the item id on stdout")
}

/// Steps 1 and 2: the owner makes the collection and both items (with the CLI, so
/// the keys land in the key store), invites a member, the member joins, the owner
/// grants the collection, the member makes an agent.
fn make_team(relay: &TestRelay, config: &Path) -> Team {
    let owner = relay.owner_token.as_str();
    let collection = relay.ok(
        "POST",
        "/v1/collections",
        owner,
        Some(&json!({"name": "payments"})),
    )["id"]
        .as_u64()
        .expect("collection id");
    let stripe_item = cli_item_add(
        relay,
        config,
        collection,
        &[
            "--name",
            "Stripe test key",
            "--env",
            "STRIPE_API_KEY",
            "--environment",
            "staging",
            "--provider",
            "stripe",
        ],
        STRIPE_CANARY,
    );
    let github_item = cli_item_add(
        relay,
        config,
        collection,
        &[
            "--name",
            "GitHub deploy token",
            "--env",
            "GITHUB_TOKEN",
            "--environment",
            "production",
            "--host",
            "api.github.com",
        ],
        GITHUB_CANARY,
    );

    let invite = relay.ok(
        "POST",
        "/v1/invites",
        owner,
        Some(&json!({"role": "member"})),
    );
    let invite_code = invite["secret"].as_str().unwrap().to_string();
    let key = apassy_relay::device::DeviceKey::generate().unwrap();
    let joined = relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(&json!({
            "code": invite_code, "name": "alice", "device_name": "Alice device",
            "public_key": key.public_key_b64()
        })),
    );
    let confirmed = relay.ok(
        "POST",
        &format!("/v1/joins/{}/confirm", joined["id"]),
        owner,
        Some(&json!({"safety": joined["safety"]})),
    );
    let member_id = confirmed["member_id"].as_u64().unwrap();
    let member_token = relay.sign_in(&relay.team_id, &key);
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

/// A run that the person was shown, and the LOCAL environments of its items.
type Shown = Vec<(u64, Vec<String>)>;

/// The owner's host on a thread: the real loop, a scripted person.
struct Host {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// What the person was shown: the run id and the LOCAL environments of its items.
    shown: Arc<Mutex<Shown>>,
}

impl Host {
    fn start(relay: &TestRelay, config: &Path, answers: Vec<Answer>) -> Host {
        let stop = Arc::new(AtomicBool::new(false));
        let shown: Arc<Mutex<Shown>> = Arc::default();
        let (stop2, shown2) = (stop.clone(), shown.clone());
        let (url, edge, owner) = (
            relay.url.clone(),
            relay.edge_secret.clone(),
            relay.owner_token.clone(),
        );
        let store = KeyStore::at(config.join("apassy-team"));
        let mut answers: VecDeque<Answer> = answers.into();
        let thread = std::thread::spawn(move || {
            let client = Client::new(
                &url,
                Some(&SecretString::new(owner)),
                Some(&SecretString::new(edge)),
            );
            let rules = RuleSet::builtin().expect("rules");
            let ctx = HostContext {
                client: &client,
                store: &store,
                options: HostOptions::default(),
                rules: &rules,
                poll_secs: 1,
            };
            let mut person = |request: &HostRequestView, local: &[&KeyEntry], _why: &str| {
                shown2.lock().unwrap().push((
                    request.run_id.0,
                    local.iter().map(|e| e.environment.clone()).collect(),
                ));
                // With no answer left, the person says no: never yes by default.
                answers.pop_front().unwrap_or(Answer::No)
            };
            serve(&ctx, &mut person, &stop2).expect("the host loop");
        });
        Host {
            stop,
            thread: Some(thread),
            shown,
        }
    }

    fn finish(mut self) -> Shown {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the host thread");
        }
        self.shown.lock().unwrap().clone()
    }
}

/// Waits until the run is decided (not pending), as the agent does, and gives the view.
fn decided(relay: &TestRelay, agent: &str, run_id: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let view = relay.ok("GET", &format!("/v1/runs/{run_id}?wait=5"), agent, None);
        if view["status"] != "pending" {
            return view;
        }
        assert!(Instant::now() < deadline, "run {run_id} is still pending");
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

/// Asks for a run as the agent. The run waits for the host: always `pending`.
fn ask(relay: &TestRelay, agent: &str, body: &Value) -> u64 {
    let (status, run) = relay.run(agent, body);
    assert_eq!(status, 200, "{run}");
    assert_eq!(run["result"]["status"], "pending", "{run}");
    assert!(
        run["result"]["session"].is_null(),
        "no session before a release"
    );
    run["result"]["run_id"].as_u64().expect("run id")
}

#[test]
fn the_whole_flow_through_api_mcp_and_cli() {
    let upstream = upstream::start(&["api.stripe.com", "api.github.com"]);
    let relay = relay::start(upstream.options());
    let owner = relay.owner_token.clone();
    let config = tempfile::tempdir().expect("owner config");

    // 1 and 2. The owner adds the items with the CLI: the keys stay on this machine.
    let team = make_team(&relay, config.path());
    let agent = team.agent_token.clone();
    let access = relay.ok("GET", "/v1/access", &agent, None);
    let access_text = access.to_string();
    assert!(access_text.contains("STRIPE_API_KEY") && access_text.contains("GITHUB_TOKEN"));
    assert!(!access_text.contains(STRIPE_CANARY) && !access_text.contains(GITHUB_CANARY));
    let store = KeyStore::at(config.path().join("apassy-team"));
    let entries = store.load().expect("key store");
    assert_eq!(entries.len(), 2);
    let item_keys: Vec<String> = entries.iter().map(|e| e.key.expose().to_string()).collect();
    // The relay holds no readable value at all, before any run.
    for cell in relay.vault_cells() {
        for value in [STRIPE_CANARY, GITHUB_CANARY] {
            assert!(!cell.windows(value.len()).any(|w| w == value.as_bytes()));
        }
        for key in &item_keys {
            assert!(!cell.windows(key.len()).any(|w| w == key.as_bytes()));
        }
    }

    // The owner's host: the first run is a production item that the person denies, the
    // second the person allows, the third (the CLI run with secret output) too.
    let host = Host::start(
        &relay,
        config.path(),
        vec![Answer::No, Answer::Yes, Answer::Yes],
    );

    let mut placeholders = Vec::new();
    let mut keys = Vec::new();

    // 3. A known-safe command with a staging item: pending, and then released by the
    // host without a question.
    let run_id = ask(
        &relay,
        &agent,
        &run_body(
            &[team.stripe_item],
            &["stripe", "balance", "retrieve"],
            USER_REQUEST,
        ),
    );
    let run = decided(&relay, &agent, run_id);
    assert_eq!(run["status"], "ready", "{run}");
    assert_eq!(run["decided_by"], "host");
    assert_eq!(run["note"], "Released automatically: known safe command.");
    let stripe_env = run["session"]["env"].clone();
    placeholders.push(check_stripe_swap(
        &relay,
        &upstream,
        &stripe_env,
        "/v1/balance",
    ));
    keys.extend(session_keys(&stripe_env));

    // 4. A production item waits for the person. They say no, then yes.
    let both = [team.github_item, team.stripe_item];
    let denied_id = ask(
        &relay,
        &agent,
        &run_body(&both, &["git", "status"], USER_REQUEST),
    );
    let denied = decided(&relay, &agent, denied_id);
    assert_eq!(denied["status"], "denied", "{denied}");
    assert_eq!(denied["code"], "approval_denied");
    assert_eq!(denied["note"], "Denied on the host.");
    assert!(denied["session"].is_null());

    let approved_id = ask(
        &relay,
        &agent,
        &run_body(&both, &["git", "status"], USER_REQUEST),
    );
    let ready = decided(&relay, &agent, approved_id);
    assert_eq!(ready["status"], "ready", "{ready}");
    assert_eq!(ready["decided_by"], "host");
    assert_eq!(ready["note"], "Approved on the host.");
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

    // An approver cannot approve on the relay: the keys are on the host.
    relay.fails(
        "POST",
        &format!("/v1/approvals/{approved_id}/approve"),
        Some(&owner),
        None,
        403,
        "approve_on_host",
    );

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

    // 7a. The same flow through the remote MCP endpoint: pending, then released.
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
    assert_eq!(mcp_run["status"], "pending", "{answer}");
    let status_call = json!({
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "apassy_run_status",
                   "arguments": {"run_id": mcp_run["run_id"], "wait_secs": 20}},
    });
    let (_, answer) = relay.call("POST", "/mcp", Some(&agent), Some(&status_call));
    let mcp_ready = &answer["result"]["structuredContent"];
    assert_eq!(mcp_ready["status"], "ready", "{answer}");
    let mcp_env = mcp_ready["session"]["env"].clone();
    keys.extend(session_keys(&mcp_env));
    placeholders.push(check_stripe_swap(
        &relay,
        &upstream,
        &mcp_env,
        "/v1/charges",
    ));

    // 7b. The same flow through `apassy-team run`. The child prints the variable to
    // stdout, so the command asks (secret_output); the person says yes.
    let home = tempfile::tempdir().expect("home");
    let out = home.path().join("session.env");
    let output = Command::new(env!("CARGO_BIN_EXE_apassy-team"))
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
        .output()
        .expect("apassy-team");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("Waiting for an approver (run "), "{stderr}");
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

    // What the person saw: only the runs that the host could not release by itself, and
    // always with the local environments.
    let shown = host.finish();
    let shown_ids: Vec<u64> = shown.iter().map(|(id, _)| *id).collect();
    assert_eq!(shown_ids.len(), 3, "{shown:?}");
    assert_eq!(
        shown[0],
        (
            denied_id,
            vec!["production".to_string(), "staging".to_string()]
        )
    );
    assert_eq!(shown[1].0, approved_id);
    assert_eq!(shown[2].1, vec!["staging".to_string()]);
    // The log of the host: one line per run, no key, no value.
    let log = std::fs::read_to_string(store.log_path()).expect("host.log");
    let decisions: Vec<String> = log
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).expect("json line")["decision"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        decisions,
        vec!["auto", "denied", "approved", "auto", "approved"],
        "{log}"
    );
    for hidden in item_keys
        .iter()
        .map(String::as_str)
        .chain([STRIPE_CANARY, GITHUB_CANARY])
    {
        assert!(!log.contains(hidden), "host.log holds a secret");
    }

    // 8. The whole audit holds no value, placeholder, token, session key, or item key.
    let audit = whole_audit(&relay);
    for action in [
        "run_pending",
        "run_denied",
        "run_released",
        "session_started",
        "session_ended",
        "grant_revoked",
        "proxy_request",
    ] {
        assert!(audit.contains(action), "no {action} in the audit");
    }
    for action in ["run_approved", "run_allowed"] {
        assert!(!audit.contains(action), "{action} is not written any more");
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
    needles.extend(item_keys.iter().map(String::as_str));
    for needle in needles {
        assert!(!audit.contains(needle), "the audit holds a secret");
    }
    assert!(
        !audit.contains("apassy_ses_"),
        "the audit holds a session key"
    );
    // And after all those sessions, no cell of the vault holds a value or an item key.
    for cell in relay.vault_cells() {
        for value in [STRIPE_CANARY, GITHUB_CANARY] {
            assert!(!cell.windows(value.len()).any(|w| w == value.as_bytes()));
        }
        for key in &item_keys {
            assert!(!cell.windows(key.len()).any(|w| w == key.as_bytes()));
        }
    }

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
