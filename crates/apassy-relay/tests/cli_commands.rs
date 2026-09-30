//! The commands of `apassy-team` against a recording server: method, path, bearer, edge header, body, and output.

mod cli_support;

use cli_support::*;
use serde_json::{Value, json};

struct Case {
    args: Vec<&'static str>,
    stdin: Option<&'static str>,
    result: Value,
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    /// The agent token instead of the member token.
    agent: bool,
}

fn case(args: &[&'static str], method: &'static str, path: &'static str, result: Value) -> Case {
    Case {
        args: args.to_vec(),
        stdin: None,
        result,
        method,
        path,
        body: None,
        agent: false,
    }
}

fn empty_rule() -> Value {
    json!({"allowed_prefixes": [], "forbidden_words": [], "expires_at": null,
           "max_runs_per_hour": null, "instruction": ""})
}

fn cases() -> Vec<Case> {
    let collection_view = json!({"id": 2, "name": "pay", "policy": {"mode": "ask", "rule": {}},
                                 "item_count": 1, "created_at": 1});
    let item_view = json!({"id": 4, "collection_id": 2, "collection": "pay", "name": "Stripe",
        "env_name": "STRIPE_API_KEY", "provider": "stripe", "hosts": ["api.stripe.com"],
        "environment": "staging", "risk": "high", "scope": "admin",
        "reversibility": "irreversible", "created_at": 1});
    let mut list = vec![
        case(
            &["me"],
            "GET",
            "/v1/me",
            json!({"team": "T", "kind": "member", "member_id": 1, "member_name": "olga", "role": "owner"}),
        ),
        Case {
            body: Some(json!({"role": "manager", "expires_hours": 5})),
            ..case(
                &["invite", "--role", "manager", "--hours", "5"],
                "POST",
                "/v1/invites",
                json!({"id": 3, "secret": "apassy_inv_x", "expires_at": 100}),
            )
        },
        Case {
            body: Some(json!({"role": "member"})),
            ..case(
                &["invite"],
                "POST",
                "/v1/invites",
                json!({"id": 3, "secret": "apassy_inv_x", "expires_at": 100}),
            )
        },
        case(
            &["invites"],
            "GET",
            "/v1/invites",
            json!([{"id": 1, "role": "member", "created_at": 1, "expires_at": 2, "used_by": null}]),
        ),
        case(
            &["members"],
            "GET",
            "/v1/members",
            json!([{"id": 1, "name": "olga", "role": "owner", "created_at": 1, "revoked": false}]),
        ),
        case(
            &["member", "revoke", "4"],
            "DELETE",
            "/v1/members/4",
            json!({"id": 4}),
        ),
        Case {
            body: Some(json!({"name": "pay", "policy": {"mode": "ask", "rule": {
                "allowed_prefixes": ["stripe"], "forbidden_words": ["delete"],
                "expires_at": 99, "max_runs_per_hour": 3, "instruction": "careful"}}})),
            ..case(
                &[
                    "collection",
                    "create",
                    "pay",
                    "--mode",
                    "ask",
                    "--allow-prefix",
                    "stripe",
                    "--forbid",
                    "delete",
                    "--max-runs-per-hour",
                    "3",
                    "--rule-expires-at",
                    "99",
                    "--instruction",
                    "careful",
                ],
                "POST",
                "/v1/collections",
                json!({"id": 2}),
            )
        },
        Case {
            body: Some(
                json!({"name": "plain", "policy": {"mode": "bouncer", "rule": empty_rule()}}),
            ),
            ..case(
                &["collection", "create", "plain"],
                "POST",
                "/v1/collections",
                json!({"id": 3}),
            )
        },
        case(
            &["collection", "list"],
            "GET",
            "/v1/collections",
            json!([collection_view.clone()]),
        ),
        Case {
            body: Some(json!({"mode": "bouncer", "rule": {
                "allowed_prefixes": [], "forbidden_words": ["drop"], "expires_at": null,
                "max_runs_per_hour": null, "instruction": ""}})),
            ..case(
                &["collection", "policy", "2", "--forbid", "drop"],
                "PUT",
                "/v1/collections/2/policy",
                collection_view.clone(),
            )
        },
        case(
            &["item", "list"],
            "GET",
            "/v1/items",
            json!([item_view.clone()]),
        ),
        case(
            &["item", "list", "--collection", "2"],
            "GET",
            "/v1/items?collection=2",
            json!([item_view]),
        ),
        case(
            &["item", "archive", "6"],
            "DELETE",
            "/v1/items/6",
            json!({"id": 6}),
        ),
        Case {
            body: Some(json!({"collection_id": 1, "member_id": 2})),
            ..case(
                &["grant", "--collection", "1", "--member", "2"],
                "POST",
                "/v1/grants",
                json!({"id": 5}),
            )
        },
        case(
            &["grants"],
            "GET",
            "/v1/grants",
            json!([{"id": 5, "collection_id": 1, "collection": "pay", "member_id": 2,
                    "member": "bob", "created_at": 1}]),
        ),
        case(
            &["revoke", "--grant", "5"],
            "DELETE",
            "/v1/grants/5",
            json!({"id": 5}),
        ),
        Case {
            body: Some(json!({"name": "ci", "days": 7})),
            ..case(
                &["agent", "create", "ci", "--days", "7"],
                "POST",
                "/v1/agents",
                json!({"id": 2, "secret": "apassy_agt_x", "expires_at": 100}),
            )
        },
        case(
            &["agent", "list"],
            "GET",
            "/v1/agents",
            json!([{"id": 2, "member_id": 1, "name": "ci", "created_at": 1, "expires_at": 9, "revoked": false}]),
        ),
        case(
            &["agent", "revoke", "2"],
            "DELETE",
            "/v1/agents/2",
            json!({"id": 2}),
        ),
        case(&["pending"], "GET", "/v1/approvals", json!([])),
        Case {
            body: Some(json!({"reason": "looks fine"})),
            ..case(
                &["approve", "9", "--reason", "looks fine"],
                "POST",
                "/v1/approvals/9/approve",
                run_view(9, "ready", None),
            )
        },
        Case {
            body: Some(json!({})),
            ..case(
                &["deny", "9"],
                "POST",
                "/v1/approvals/9/deny",
                run_view(9, "denied", None),
            )
        },
        case(
            &["audit", "--after", "5", "--limit", "10"],
            "GET",
            "/v1/audit?after=5&limit=10",
            json!([{"id": 6, "at": 1, "actor": "member:1", "action": "grant_created", "detail": {}}]),
        ),
        case(&["audit"], "GET", "/v1/audit", json!([])),
    ];
    list.push(Case {
        agent: true,
        ..case(
            &["access"],
            "GET",
            "/v1/access",
            json!({"agent_id": 2, "agent": "ci", "member": "olga", "items": [], "note": ""}),
        )
    });
    list
}

#[test]
fn every_command_sends_the_right_request() {
    for case in cases() {
        let mock = Mock::always(200, case.result.clone());
        let mut cli = Cli::new().with("APASSY_EDGE_SECRET", EDGE);
        cli = if case.agent {
            cli.agent(&mock.url)
        } else {
            cli.member(&mock.url)
        };
        let output = cli.run(&case.args, case.stdin);
        let label = case.args.join(" ");
        assert_eq!(
            code(&output),
            0,
            "`{label}` failed: {}",
            text(&output.stderr)
        );
        let seen = mock.requests();
        assert_eq!(seen.len(), 1, "`{label}` made {} requests", seen.len());
        let request = &seen[0];
        assert_eq!(request.method, case.method, "`{label}`");
        assert_eq!(request.url, case.path, "`{label}`");
        let token = if case.agent {
            AGENT_TOKEN
        } else {
            MEMBER_TOKEN
        };
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {token}").as_str()),
            "`{label}`"
        );
        assert_eq!(request.header("x-apassy-edge"), Some(EDGE), "`{label}`");
        match &case.body {
            Some(body) => assert_eq!(&request.json(), body, "`{label}`"),
            None => assert!(request.body.is_empty(), "`{label}` sent a body"),
        }
    }
}

#[test]
fn no_edge_header_without_the_variable() {
    let mock = Mock::always(
        200,
        json!({"team": "T", "kind": "member", "member_id": 1,
                                        "member_name": "olga", "role": "owner"}),
    );
    let output = Cli::new().member(&mock.url).run(&["me"], None);
    assert_eq!(code(&output), 0);
    let seen = mock.requests();
    assert_eq!(seen[0].header("x-apassy-edge"), None);
    assert_eq!(text(&output.stdout), "team T: member olga (id 1, owner)\n");
}

#[test]
fn me_works_with_an_agent_token_and_json_prints_the_result() {
    let mock = Mock::always(
        200,
        json!({"team": "T", "kind": "agent", "member_id": 1,
        "member_name": "olga", "role": "member", "agent_id": 2, "agent_name": "ci"}),
    );
    let output = Cli::new().agent(&mock.url).run(&["me", "--json"], None);
    assert_eq!(code(&output), 0);
    let printed: Value = serde_json::from_str(&text(&output.stdout)).unwrap();
    assert_eq!(printed["agent_name"], "ci");
    assert_eq!(
        mock.requests()[0].header("authorization"),
        Some(format!("Bearer {AGENT_TOKEN}").as_str())
    );
}

const ME: &str = r#"{"ok":true,"result":{"team":"Test Team","kind":"member","member_id":1,"member_name":"olga","role":"owner"}}"#;

/// A relay that answers `GET /v1/me` and takes every item.
fn item_mock(item_answer: fn() -> Answer) -> Mock {
    Mock::start(move |request, _| {
        if request.url == "/v1/me" {
            raw(200, ME)
        } else {
            item_answer()
        }
    })
}

fn item_created() -> Answer {
    ok(json!({"id": 4, "hosts": ["api.stripe.com", "files.stripe.com"]}))
}

fn item_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "item",
        "add",
        "--collection",
        "2",
        "--name",
        "Stripe test key",
        "--env",
        "STRIPE_API_KEY",
        "--environment",
        "staging",
    ];
    args.extend_from_slice(extra);
    args
}

fn keys_file(cli: &Cli) -> std::path::PathBuf {
    cli.config_dir().join("apassy-team").join("keys.json")
}

fn key_entries(cli: &Cli) -> Vec<Value> {
    let text = std::fs::read_to_string(keys_file(cli)).unwrap_or_default();
    if text.is_empty() {
        return Vec::new();
    }
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["version"], 1);
    file["entries"].as_array().unwrap().clone()
}

#[test]
fn item_add_seals_the_value_and_keeps_its_key_on_this_machine() {
    use apassy_relay::hostkeys;
    use std::os::unix::fs::PermissionsExt;
    let mock = item_mock(item_created);
    let cli = Cli::new().member(&mock.url);
    let args = item_args(&["--provider", "stripe"]);
    let output = cli.run(&args, Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    // The relay got the token check and the sealed item, and nothing else.
    let seen = mock.requests();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("GET", "/v1/me")
    );
    assert_eq!(
        (seen[1].method.as_str(), seen[1].url.as_str()),
        ("POST", "/v1/items")
    );
    let body = seen[1].json();
    assert!(body.get("value").is_none(), "{body}");
    assert!(body.get("allow_broad_host").is_none());
    assert_eq!(body["collection_id"], 2);
    assert_eq!(body["provider"], "stripe");
    let uid = body["uid"].as_str().unwrap();
    assert!(hostkeys::is_uid(uid), "{uid}");
    let sealed = hostkeys::decode_b64(body["sealed"].as_str().unwrap(), 5000).unwrap();
    assert_eq!(sealed.len(), 12 + CANARY.len() + 16);
    // The key is in keys.json, with the metadata that the host trusts.
    let entries = key_entries(&cli);
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["relay_url"], mock.url.as_str());
    assert_eq!(entry["team"], "Test Team");
    assert_eq!(entry["uid"], uid);
    assert_eq!(entry["item_id"], 4);
    assert_eq!(entry["name"], "Stripe test key");
    assert_eq!(entry["env_name"], "STRIPE_API_KEY");
    assert_eq!(entry["environment"], "staging");
    // The hosts are what the relay said it stored.
    assert_eq!(
        entry["hosts"],
        json!(["api.stripe.com", "files.stripe.com"])
    );
    assert!(entry["created_at"].as_u64().unwrap() > 1_700_000_000);
    let key = hostkeys::decode_key(entry["key"].as_str().unwrap()).unwrap();
    let opened = hostkeys::open_item(&key, uid, &sealed).unwrap();
    assert_eq!(opened.as_slice(), CANARY.as_bytes());
    // The value and the key are nowhere on the wire, on stdout, or on stderr.
    let key_text = entry["key"].as_str().unwrap();
    let wire: String = seen
        .iter()
        .map(|r| format!("{} {}", r.url, r.body))
        .collect();
    for hidden in [CANARY, key_text] {
        assert!(!wire.contains(hidden), "the relay got a secret");
        assert!(!text(&output.stdout).contains(hidden));
        assert!(!text(&output.stderr).contains(hidden));
    }
    assert_eq!(text(&output.stdout), "4\n");
    assert!(
        text(&output.stderr).contains("keys.json"),
        "{}",
        text(&output.stderr)
    );
    // Modes.
    let dir_mode = std::fs::metadata(cli.config_dir().join("apassy-team"))
        .unwrap()
        .permissions()
        .mode();
    let file_mode = std::fs::metadata(keys_file(&cli))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!((dir_mode & 0o777, file_mode & 0o777), (0o700, 0o600));
    // The value is not in the arguments of the CLI either: it only came through stdin.
    assert!(!args.iter().any(|a| a.contains(CANARY)));
    // A second item gets its own uid and key, and the first stays.
    let output = cli.run(&item_args(&[]), Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let entries = key_entries(&cli);
    assert_eq!(entries.len(), 2);
    assert_ne!(entries[0]["uid"], entries[1]["uid"]);
    assert_ne!(entries[0]["key"], entries[1]["key"]);
}

#[test]
fn item_add_shows_what_each_host_covers_and_sends_allow_broad_host() {
    let mock = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            raw(200, ME)
        } else {
            ok(json!({"id": 5, "hosts": ["example.com", "api.example.com:8443"]}))
        }
    });
    let cli = Cli::new().member(&mock.url);
    let args = item_args(&[
        "--host",
        "example.com",
        "--host",
        "api.example.com:8443",
        "--allow-broad-host",
    ]);
    let output = cli.run(&args, Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    assert_eq!(mock.requests()[1].json()["allow_broad_host"], true);
    assert_eq!(
        mock.requests()[1].json()["hosts"],
        json!(["example.com", "api.example.com:8443"])
    );
    assert_eq!(text(&output.stdout), "5\n");
    let stderr = text(&output.stderr);
    assert!(
        stderr.starts_with(
            "The value may go to example.com and every subdomain of it.\n\
             The value may go to api.example.com and every subdomain of it, on port 8443.\n"
        ),
        "{stderr}"
    );
}

#[test]
fn item_add_sends_the_declarations_and_the_local_entry_has_them_too() {
    let mock = item_mock(item_created);
    let cli = Cli::new().member(&mock.url);
    let args = item_args(&[
        "--provider",
        "stripe",
        "--risk",
        "low",
        "--scope",
        "read-only",
        "--reversibility",
        "reversible",
    ]);
    let output = cli.run(&args, Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let body = mock.requests()[1].json();
    assert_eq!(body["risk"], "low");
    assert_eq!(body["scope"], "read-only");
    assert_eq!(body["reversibility"], "reversible");
    let entry = &key_entries(&cli)[0];
    assert_eq!(entry["risk"], "low");
    assert_eq!(entry["scope"], "read-only");
    assert_eq!(entry["reversibility"], "reversible");
}

#[test]
fn item_add_removes_one_newline_and_refuses_an_empty_value() {
    use apassy_relay::hostkeys;
    let mock = item_mock(item_created);
    let cli = Cli::new().member(&mock.url);
    let args = item_args(&[]);
    let empty = cli.run(&args, Some("\n"));
    assert_eq!(code(&empty), 2);
    let none = cli.run(&args, None);
    assert_eq!(code(&none), 2);
    assert!(mock.requests().is_empty(), "no request without a value");
    assert!(key_entries(&cli).is_empty());
    // Only one newline is removed: what is left is not printable ASCII.
    let two = cli.run(&args, Some(&format!("{CANARY}\n\n")));
    assert_eq!(code(&two), 2);
    assert!(mock.requests().is_empty());
    assert!(key_entries(&cli).is_empty());
    // One newline, or a carriage return and a newline, is removed.
    for stdin in [
        format!("{CANARY}\n"),
        format!("{CANARY}\r\n"),
        CANARY.to_string(),
    ] {
        let output = cli.run(&args, Some(&stdin));
        assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    }
    for entry in key_entries(&cli) {
        let uid = entry["uid"].as_str().unwrap().to_string();
        let key = hostkeys::decode_key(entry["key"].as_str().unwrap()).unwrap();
        let sealed = mock
            .requests()
            .iter()
            .map(|r| r.json())
            .find(|b| b["uid"] == uid.as_str())
            .unwrap();
        let sealed = hostkeys::decode_b64(sealed["sealed"].as_str().unwrap(), 5000).unwrap();
        assert_eq!(
            hostkeys::open_item(&key, &uid, &sealed).unwrap().as_slice(),
            CANARY.as_bytes()
        );
    }
}

/// The relay cannot check a value, so the CLI does: nothing is sent, and no key is
/// written, for a value that the relay would have refused.
#[test]
fn item_add_checks_the_value_before_anything_else() {
    let mock = item_mock(item_created);
    let cli = Cli::new().member(&mock.url);
    let args = item_args(&[]);
    for (why, value) in [
        ("a NUL", format!("{CANARY}\0x")),
        ("a tab", format!("{CANARY}\tx")),
        ("a quote", format!("{CANARY}\"x")),
        ("a backslash", format!("{CANARY}\\x")),
        ("DEL", format!("{CANARY}\u{7f}")),
        ("a letter that is not ASCII", format!("{CANARY}\u{e9}")),
        ("4097 bytes", "a".repeat(4097)),
    ] {
        let output = cli.run(&args, Some(&value));
        assert_eq!(code(&output), 2, "{why}");
        let stderr = text(&output.stderr);
        assert!(stderr.contains("printable ASCII"), "{why}: {stderr}");
        assert!(!stderr.contains(CANARY), "{why}");
    }
    // Too short for a placeholder.
    let output = cli.run(&args, Some("short\n"));
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("cannot get a placeholder"));
    assert!(mock.requests().is_empty(), "nothing went to the relay");
    assert!(!keys_file(&cli).exists(), "no key was written");
    // Signs and spaces are fine, and so is 4096 bytes.
    let signs = "sk_test_51Synthetic/Canary+Value= with ~!@#$%^&*()";
    let long = format!("sk_test_{}", "Ab1".repeat(1362));
    for value in [signs.to_string(), long] {
        let output = cli.run(&args, Some(&value));
        assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    }
    // A value in the name is refused: the relay stores the name in clear.
    let mut named = item_args(&[]);
    named[5] = CANARY;
    let output = cli.run(&named, Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 2);
    assert!(!text(&output.stderr).contains(CANARY));
}

/// When the relay refuses the item, there is no item and so no key to keep.
#[test]
fn item_add_removes_the_key_when_the_relay_refuses_the_item() {
    let mock = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            raw(200, ME)
        } else {
            err(
                409,
                "conflict",
                "This collection has an item with this variable name.",
            )
        }
    });
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(&item_args(&[]), Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 4);
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("conflict: This collection has an item"),
        "{stderr}"
    );
    assert!(!stderr.contains(CANARY));
    assert!(!text(&output.stdout).contains(CANARY));
    // The entry was written before the upload and is gone again.
    assert_eq!(mock.requests().len(), 2);
    assert!(key_entries(&cli).is_empty());
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(keys_file(&cli)).unwrap().permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_relay_error_shows_code_and_message_and_exits_4_without_the_value() {
    let mock = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            raw(200, ME)
        } else {
            err(400, "broad_host", "The host example.com is a whole domain.")
        }
    });
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(&item_args(&[]), Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 4);
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("broad_host: The host example.com is a whole domain."),
        "{stderr}"
    );
    assert!(!stderr.contains(CANARY));
    assert!(!text(&output.stdout).contains(CANARY));
    assert!(key_entries(&cli).is_empty());
}

/// A relay that takes the request and then drops the connection: the CLI cannot know
/// whether the item exists, so the key stays (an item without its key is lost).
#[test]
fn item_add_keeps_the_key_when_it_cannot_know_whether_the_item_was_stored() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0u8; 4096];
            let n = stream.read(&mut head).unwrap_or(0);
            let head = String::from_utf8_lossy(&head[..n]).into_owned();
            if head.starts_with("GET /v1/me") {
                let body = ME;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            // The item request is read and dropped: no answer.
        }
    });
    let cli = Cli::new().member(&url);
    let output = cli.run(&item_args(&[]), Some(&format!("{CANARY}\n")));
    server.join().unwrap();
    assert_eq!(code(&output), 4);
    let stderr = text(&output.stderr);
    assert!(stderr.contains("may have taken the item"), "{stderr}");
    assert!(stderr.contains("keys.json"), "{stderr}");
    assert!(!stderr.contains(CANARY));
    let entries = key_entries(&cli);
    assert_eq!(entries.len(), 1, "the key stays");
    assert!(entries[0]["item_id"].is_null());
}

/// A relay that is not there: nothing was sent, and nothing is left behind.
#[test]
fn item_add_to_a_relay_that_is_down_writes_no_key() {
    let cli = Cli::new().member(&dead_url());
    let output = cli.run(&item_args(&[]), Some(&format!("{CANARY}\n")));
    assert_eq!(code(&output), 4);
    assert!(!keys_file(&cli).exists());
}

#[test]
fn approve_says_that_the_keys_are_on_the_owners_host() {
    let message = "The keys are on the owner's host. Approve there with apassy-team host.";
    let mock = Mock::start(move |_, _| err(403, "approve_on_host", message));
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(&["approve", "9"], None);
    assert_eq!(code(&output), 2);
    assert_eq!(text(&output.stderr), format!("apassy-team: {message}\n"));
    assert_eq!(text(&output.stdout), "");
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(mock.requests()[0].url, "/v1/approvals/9/approve");
    // Deny still works.
    let ok_mock = Mock::always(200, run_view(9, "denied", None));
    let output = Cli::new().member(&ok_mock.url).run(&["deny", "9"], None);
    assert_eq!(code(&output), 0);
}

#[test]
fn help_names_the_host_command_and_the_approve_refusal() {
    let output = Cli::new().run(&["help"], None);
    assert_eq!(code(&output), 0);
    let help = text(&output.stdout);
    assert!(help.contains("host [--ask-all] [--auto-limit N]"), "{help}");
    assert!(help.contains("keys.json"), "{help}");
    assert!(help.contains("`host`"), "{help}");
    assert!(help.contains("sealed here"), "{help}");
}

#[test]
fn invite_and_agent_create_print_the_secret_once_on_stdout_only() {
    let secret = "apassy_inv_1111111111111111111111111111111111111111111111111111111111111111";
    let mock = Mock::always(
        200,
        json!({"id": 3, "secret": secret, "expires_at": 1_790_000_000}),
    );
    let output = Cli::new().member(&mock.url).run(&["invite"], None);
    assert_eq!(code(&output), 0);
    assert_eq!(text(&output.stdout), format!("{secret}\n"));
    assert!(!text(&output.stderr).contains(secret));
    assert!(text(&output.stderr).contains("Invite 3"));

    let token = "apassy_agt_2222222222222222222222222222222222222222222222222222222222222222";
    let mock = Mock::always(
        200,
        json!({"id": 2, "secret": token, "expires_at": 1_790_000_000}),
    );
    let output = Cli::new()
        .member(&mock.url)
        .run(&["agent", "create", "ci"], None);
    assert_eq!(code(&output), 0);
    assert_eq!(text(&output.stdout), format!("{token}\n"));
    assert!(!text(&output.stderr).contains(token));
}

#[test]
fn pending_prints_the_run_and_escapes_control_characters() {
    let run = json!({"run_id": 7, "agent_id": 2, "agent": "ci", "member": "bob",
        "items": [{"id": 4, "name": "Stripe", "collection": "pay", "environment": "staging"}],
        "command": ["stripe", "refunds", "create", "--note", "two words", "\u{1b}]0;pwned\u{7}"],
        "purpose": "refund\nrm -rf /", "user_request": "please refund", "cwd": "/work",
        "flags": ["ask_owner"], "note": "Rule flags: ask_owner", "created_at": 1, "expires_at": 601});
    let mock = Mock::always(200, json!([run]));
    let output = Cli::new().member(&mock.url).run(&["pending"], None);
    assert_eq!(code(&output), 0);
    let out = text(&output.stdout);
    assert!(out.contains("run 7"), "{out}");
    assert!(
        out.contains("stripe refunds create --note 'two words'"),
        "{out}"
    );
    assert!(out.contains("request:  please refund"), "{out}");
    assert!(out.contains("flags:    ask_owner"), "{out}");
    assert!(
        !out.contains('\u{1b}') && !out.contains('\u{7}'),
        "no raw control characters"
    );
    assert!(out.contains("refund\\nrm -rf /"), "{out}");
}

#[test]
fn an_empty_pending_list_says_so() {
    let mock = Mock::always(200, json!([]));
    let output = Cli::new().member(&mock.url).run(&["pending"], None);
    assert_eq!(text(&output.stdout), "No runs are waiting.\n");
}

#[test]
fn usage_errors_exit_2_and_send_nothing() {
    let mock = Mock::always(200, json!({}));
    let cli = Cli::new().member(&mock.url);
    for args in [
        vec![],
        vec!["bogus"],
        vec!["member", "revoke"],
        vec!["grant", "--collection", "1"],
        vec!["approve", "abc"],
        vec!["me", "--nope"],
        vec!["run", "--items", "1", "--purpose", "x"],
        vec!["invite", "--role", "owner"],
    ] {
        let output = cli.run(&args, None);
        assert_eq!(code(&output), 2, "{args:?}");
        assert!(
            text(&output.stderr).starts_with("apassy-team: "),
            "{args:?}"
        );
    }
    assert!(mock.requests().is_empty());
}

#[test]
fn missing_settings_and_a_dead_relay_have_clear_exit_codes() {
    // No relay and no token: a usage error (2).
    let output = Cli::new().run(&["members"], None);
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("APASSY_RELAY_URL"));
    // A relay that does not answer: exit 4.
    let output = Cli::new().member(&dead_url()).run(&["members"], None);
    assert_eq!(code(&output), 4);
    assert!(text(&output.stderr).contains("Cannot reach the relay"));
    assert!(!text(&output.stderr).contains(MEMBER_TOKEN));
    // An answer that is not an envelope (for example a proxy error page): exit 4.
    let mock = Mock::start(|_, _| raw(502, "<html>bad gateway</html>"));
    let output = Cli::new().member(&mock.url).run(&["members"], None);
    assert_eq!(code(&output), 4);
    assert!(text(&output.stderr).contains("HTTP 502"));
    // A busy relay: the code of the envelope is printed.
    let mock = Mock::start(|_, _| err(503, "busy", "The relay is busy. Try again in a moment."));
    let output = Cli::new().member(&mock.url).run(&["approve", "7"], None);
    assert_eq!(code(&output), 4);
    assert!(
        text(&output.stderr).contains("relay: busy: The relay is busy."),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn help_and_version_exit_0() {
    let cli = Cli::new();
    let help = cli.run(&["help"], None);
    assert_eq!(code(&help), 0);
    assert!(text(&help.stdout).contains("Exit codes"));
    let version = cli.run(&["--version"], None);
    assert_eq!(code(&version), 0);
    assert!(text(&version.stdout).starts_with("apassy-team "));
}

#[test]
fn redirects_are_not_followed() {
    // A redirect from the relay must not carry the token to another host.
    let target = Mock::always(200, json!([]));
    let location = format!("{}/v1/members", target.url);
    let redirecting = Mock::start(move |_, _| Answer {
        status: 302,
        body: String::new(),
        delay: std::time::Duration::ZERO,
        headers: vec![("Location".to_owned(), location.clone())],
    });
    let output = Cli::new().member(&redirecting.url).run(&["members"], None);
    assert_eq!(code(&output), 4);
    assert_eq!(redirecting.requests().len(), 1);
    assert!(
        target.requests().is_empty(),
        "the redirect target got a request"
    );
}
