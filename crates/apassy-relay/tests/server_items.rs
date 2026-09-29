//! Collections, items, grants, and access.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use relay::{CANARY, CANARY2, start};
use serde_json::{Value, json};

fn item_body(collection: u64, env: &str, value: &str) -> Value {
    json!({
        "collection_id": collection, "name": "An item", "env_name": env, "value": value,
        "hosts": ["api.example.com"], "environment": "staging"
    })
}

fn add(relay: &relay::TestRelay, body: &Value) -> (u16, Value) {
    relay.call("POST", "/v1/items", Some(&relay.owner_token), Some(body))
}

#[test]
fn env_name_rules() {
    let relay = start(UpstreamOptions::default());
    let c = relay.add_collection("c", json!({}));
    for bad in [
        "lower_case",
        "1STARTS_WITH_DIGIT",
        "HAS-DASH",
        "",
        "PATH",
        "HOME",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "APASSY_ANYTHING",
        "APASSY_RELAY_SESSION_EXPIRES",
        "STRIPE_API_BASE",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "GITHUB_API_URL",
        &"A".repeat(65),
    ] {
        let (status, body) = add(&relay, &item_body(c, bad, CANARY));
        assert_eq!(status, 400, "{bad}: {body}");
        assert_eq!(body["error"]["code"], "invalid_request", "{bad}");
    }
    let (status, body) = add(&relay, &item_body(c, "GOOD_NAME_1", CANARY));
    assert_eq!(status, 200, "{body}");
    // The same name twice in one collection is a conflict; another collection is fine.
    let (status, body) = add(&relay, &item_body(c, "GOOD_NAME_1", CANARY2));
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "conflict");
    let c2 = relay.add_collection("c2", json!({}));
    assert_eq!(add(&relay, &item_body(c2, "GOOD_NAME_1", CANARY2)).0, 200);
}

#[test]
fn hosts_and_providers() {
    let relay = start(UpstreamOptions::default());
    let c = relay.add_collection("c", json!({}));
    // No host and no provider: refused with the exact message.
    let mut body = item_body(c, "NO_HOST_KEY", CANARY);
    body["hosts"] = json!([]);
    let (status, result) = add(&relay, &body);
    assert_eq!(status, 400);
    assert_eq!(
        result["error"]["message"],
        "A relay item needs at least one host."
    );
    // A provider gives the default hosts.
    let mut body = item_body(c, "STRIPE_API_KEY", CANARY);
    body["hosts"] = json!([]);
    body["provider"] = json!("stripe");
    let (status, result) = add(&relay, &body);
    assert_eq!(status, 200, "{result}");
    let items = relay.ok(
        "GET",
        &format!("/v1/items?collection={c}"),
        &relay.owner_token,
        None,
    );
    let known = apassy::vault::providers::known_hosts("stripe");
    assert_eq!(items[0]["hosts"], json!(known));
    assert_eq!(known[0], "api.stripe.com");
    assert_eq!(items[0]["provider"], "stripe");
    // An unknown provider, an upper case host, a bad port, a path, too many hosts.
    for (provider, hosts) in [
        (Some("no-such-provider"), json!(["api.example.com"])),
        (None, json!(["API.Example.com"])),
        (None, json!(["api.example.com:0"])),
        (None, json!(["api.example.com/path"])),
        (None, json!(["https://api.example.com"])),
        (
            None,
            json!(
                (0..17)
                    .map(|i| format!("h{i}.example.com"))
                    .collect::<Vec<_>>()
            ),
        ),
    ] {
        let mut body = item_body(c, "OTHER_KEY_X", CANARY);
        body["hosts"] = hosts.clone();
        if let Some(p) = provider {
            body["provider"] = json!(p);
        }
        let (status, result) = add(&relay, &body);
        assert_eq!(status, 400, "{hosts}: {result}");
    }
    // A host with a port is kept as given, and 16 hosts pass.
    let mut body = item_body(c, "PORT_KEY_X", CANARY);
    body["hosts"] = json!(["api.example.com:8443", "api.example.com:443"]);
    assert_eq!(add(&relay, &body).0, 200);
    let mut body = item_body(c, "MANY_KEY_X", CANARY);
    body["hosts"] = json!(
        (0..16)
            .map(|i| format!("h{i}.example.com"))
            .collect::<Vec<_>>()
    );
    assert_eq!(add(&relay, &body).0, 200);
}

#[test]
fn a_broad_host_needs_allow_broad_host_and_is_audited() {
    let relay = start(UpstreamOptions::default());
    let c = relay.add_collection("c", json!({}));
    // A host covers every subdomain. A public suffix or a whole domain would let the
    // value go to a subdomain that someone else owns: refused.
    for host in [
        "herokuapp.com",
        "azurewebsites.net",
        "github.io",
        "workers.dev",
        "s3.amazonaws.com",
        "amazonaws.com",
        "example.com",
        "example.co.uk",
        "com",
    ] {
        let mut body = item_body(c, "BROAD_KEY_X", CANARY);
        body["hosts"] = json!(["api.example.com", host]);
        let (status, result) = add(&relay, &body);
        assert_eq!(status, 400, "{host}: {result}");
        assert_eq!(result["error"]["code"], "broad_host", "{host}");
        let message = result["error"]["message"].as_str().unwrap();
        assert!(message.contains(host), "{message}");
        assert!(message.contains("--allow-broad-host"), "{message}");
    }
    // A provider default that is a public suffix is broad too.
    let mut body = item_body(c, "SUPABASE_KEY_X", CANARY);
    body["hosts"] = json!([]);
    body["provider"] = json!("supabase");
    assert_eq!(add(&relay, &body).1["error"]["code"], "broad_host");
    // A known whole-domain host of the provider of the item is not broad.
    let mut body = item_body(c, "AWS_KEY_X", CANARY);
    body["hosts"] = json!([]);
    body["provider"] = json!("aws");
    let (status, result) = add(&relay, &body);
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["result"]["hosts"], json!(["amazonaws.com"]));
    // An exact host, and the host of one customer under a private suffix, pass. The
    // answer shows the hosts.
    let mut body = item_body(c, "APP_KEY_X", CANARY);
    body["hosts"] = json!(["api.example.com", "myapp.herokuapp.com:8443"]);
    let (status, result) = add(&relay, &body);
    assert_eq!(status, 200, "{result}");
    assert_eq!(
        result["result"]["hosts"],
        json!(["api.example.com", "myapp.herokuapp.com:8443"])
    );
    // On purpose: allowed, and the audit names the broad host.
    let mut body = item_body(c, "BROAD_KEY_X", CANARY);
    body["hosts"] = json!(["api.example.com", "example.com"]);
    body["allow_broad_host"] = json!(true);
    let (status, result) = add(&relay, &body);
    assert_eq!(status, 200, "{result}");
    let rows = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let added: Vec<&serde_json::Value> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "item_added")
        .collect();
    let last = added.last().unwrap();
    assert_eq!(last["detail"]["env_name"], "BROAD_KEY_X");
    assert_eq!(last["detail"]["broad_hosts"], json!(["example.com"]));
    assert_eq!(added[0]["detail"]["broad_hosts"], json!([]));
}

#[test]
fn declarations_and_defaults() {
    let relay = start(UpstreamOptions::default());
    let c = relay.add_collection("c", json!({}));
    for (field, bad) in [
        ("environment", "prod"),
        ("risk", "extreme"),
        ("scope", "root"),
        ("reversibility", "maybe"),
    ] {
        let mut body = item_body(c, "DECL_KEY_X", CANARY);
        body[field] = json!(bad);
        assert_eq!(add(&relay, &body).0, 400, "{field}");
    }
    let mut body = item_body(c, "DECL_KEY_X", CANARY);
    body.as_object_mut().unwrap().remove("environment");
    assert_eq!(add(&relay, &body).0, 400, "environment is required");
    assert_eq!(add(&relay, &item_body(c, "DECL_KEY_X", CANARY)).0, 200);
    let items = relay.ok("GET", "/v1/items", &relay.owner_token, None);
    assert_eq!(items[0]["risk"], "high");
    assert_eq!(items[0]["scope"], "admin");
    assert_eq!(items[0]["reversibility"], "irreversible");
    assert_eq!(items[0]["environment"], "staging");
    assert_eq!(items[0]["collection"], "c");
}

#[test]
fn value_rules_and_placeholder_impossible() {
    let relay = start(UpstreamOptions::default());
    let c = relay.add_collection("c", json!({}));
    // Too short for a placeholder.
    let (status, body) = add(&relay, &item_body(c, "SHORT_KEY_X", "short"));
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "placeholder_impossible");
    // Empty, NUL, newline, too long. A quote, a backslash, a control character, or a
    // byte that is not ASCII: JSON would escape it, so a JSON echo of the value
    // would not be found in a response.
    for bad in [
        String::new(),
        format!("{CANARY}\0x"),
        format!("{CANARY}\nx"),
        format!("{CANARY}\r"),
        "a".repeat(4097),
        "sk_test_51Synth\"etic\\Canary0123456789abcdef".to_owned(),
        format!("{CANARY}\"x"),
        format!("{CANARY}\\x"),
        format!("{CANARY}\tx"),
        format!("{CANARY}\u{7f}"),
        format!("{CANARY}\u{e9}"),
    ] {
        let (status, body) = add(&relay, &item_body(c, "BAD_VALUE_X", &bad));
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request");
    }
    // Printable ASCII with a space and signs is fine.
    let signs = "sk_test_51Synthetic/Canary+Value= with ~!@#$%^&*()";
    assert_eq!(add(&relay, &item_body(c, "SIGNS_VALUE_X", signs)).0, 200);
    // A value of 4096 bytes with room for random characters is fine.
    let long = format!("sk_test_{}", "Ab1".repeat(1362));
    assert!(long.len() <= 4096);
    assert_eq!(add(&relay, &item_body(c, "LONG_VALUE_X", &long)).0, 200);
    // Names: empty and control characters.
    let mut body = item_body(c, "NAME_X", CANARY);
    body["name"] = json!("");
    assert_eq!(add(&relay, &body).0, 400);
    body["name"] = json!("bad\u{7}name");
    assert_eq!(add(&relay, &body).0, 400);
    // An unknown collection.
    let (status, body) = add(&relay, &item_body(9999, "NOCOLL_X", CANARY));
    assert_eq!(status, 404, "{body}");
}

#[test]
fn no_endpoint_ever_returns_a_value() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let second = relay.add_item(
        team.collection,
        "GITHUB_TOKEN",
        CANARY2,
        json!({"provider": "github", "environment": "production"}),
    );
    // Run a command, so a session and a placeholder exist as well.
    let (status, run) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("check")),
    );
    assert_eq!(status, 200, "{run}");
    let mut seen = Vec::new();
    let owner = relay.owner_token.clone();
    for (token, path) in [
        (&owner, "/v1/me".to_string()),
        (&owner, "/v1/members".to_string()),
        (&owner, "/v1/invites".to_string()),
        (&owner, "/v1/collections".to_string()),
        (&owner, "/v1/items".to_string()),
        (&owner, format!("/v1/items?collection={}", team.collection)),
        (&owner, "/v1/grants".to_string()),
        (&owner, "/v1/agents".to_string()),
        (&owner, "/v1/approvals".to_string()),
        (&owner, "/v1/audit?limit=500".to_string()),
        (&team.member_token, "/v1/items".to_string()),
        (&team.member_token, "/v1/collections".to_string()),
        (&team.agent_token, "/v1/me".to_string()),
        (&team.agent_token, "/v1/access".to_string()),
    ] {
        let (status, body) = relay.call("GET", &path, Some(token), None);
        assert_eq!(status, 200, "{path}: {body}");
        seen.push((path, body.to_string()));
    }
    // The policy change and the archive answers too.
    let (_, body) = relay.call(
        "PUT",
        &format!("/v1/collections/{}/policy", team.collection),
        Some(&owner),
        Some(&json!({"mode": "bouncer"})),
    );
    seen.push(("policy".into(), body.to_string()));
    let (_, body) = relay.call("DELETE", &format!("/v1/items/{second}"), Some(&owner), None);
    seen.push(("archive".into(), body.to_string()));
    for (path, text) in seen {
        assert!(!text.contains(CANARY), "{path} holds a value");
        assert!(!text.contains(CANARY2), "{path} holds a value");
    }
}

#[test]
fn item_lists_by_role_and_grants() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let other = relay.add_collection("secret-stuff", json!({}));
    relay.add_item(
        other,
        "OTHER_TOKEN",
        CANARY2,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
    // The owner sees both collections and both items.
    assert_eq!(
        relay
            .ok("GET", "/v1/collections", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        relay
            .ok("GET", "/v1/items", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // A member sees the granted collection only.
    let collections = relay.ok("GET", "/v1/collections", &team.member_token, None);
    assert_eq!(collections.as_array().unwrap().len(), 1);
    assert_eq!(collections[0]["name"], "payments");
    assert_eq!(collections[0]["item_count"], 1);
    let items = relay.ok("GET", "/v1/items", &team.member_token, None);
    assert_eq!(items.as_array().unwrap().len(), 1);
    // Asking for the other collection gives nothing, not an error that tells more.
    let none = relay.ok(
        "GET",
        &format!("/v1/items?collection={other}"),
        &team.member_token,
        None,
    );
    assert_eq!(none.as_array().unwrap().len(), 0);
    relay.fails(
        "GET",
        "/v1/items?collection=x",
        Some(&team.member_token),
        None,
        400,
        "invalid_request",
    );
    // A second grant for the same pair is a conflict.
    relay.fails(
        "POST",
        "/v1/grants",
        Some(&relay.owner_token),
        Some(&json!({"collection_id": team.collection, "member_id": team.member_id})),
        409,
        "conflict",
    );
    relay.fails(
        "POST",
        "/v1/grants",
        Some(&relay.owner_token),
        Some(&json!({"collection_id": 999, "member_id": team.member_id})),
        404,
        "not_found",
    );
    relay.fails(
        "POST",
        "/v1/grants",
        Some(&relay.owner_token),
        Some(&json!({"collection_id": other, "member_id": 999})),
        404,
        "not_found",
    );
    // Grant, list, revoke, and grant again.
    let grants = relay.ok("GET", "/v1/grants", &relay.owner_token, None);
    assert_eq!(grants[0]["member"], "alice");
    assert_eq!(grants[0]["collection"], "payments");
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        &relay.owner_token,
        None,
    );
    assert_eq!(
        relay
            .ok("GET", "/v1/items", &team.member_token, None)
            .as_array()
            .unwrap()
            .len(),
        0
    );
    relay.fails(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        Some(&relay.owner_token),
        None,
        404,
        "not_found",
    );
    relay.ok(
        "POST",
        "/v1/grants",
        &relay.owner_token,
        Some(&json!({"collection_id": team.collection, "member_id": team.member_id})),
    );
}

#[test]
fn collections_and_policies() {
    let relay = start(UpstreamOptions::default());
    let id = relay.add_collection("infra", json!({"mode": "ask", "rule": {"allowed_prefixes": ["  git ", ""], "forbidden_words": ["drop"]}}));
    relay.fails(
        "POST",
        "/v1/collections",
        Some(&relay.owner_token),
        Some(&json!({"name": "infra"})),
        409,
        "conflict",
    );
    relay.fails(
        "POST",
        "/v1/collections",
        Some(&relay.owner_token),
        Some(&json!({"name": ""})),
        400,
        "invalid_request",
    );
    relay.fails(
        "POST",
        "/v1/collections",
        Some(&relay.owner_token),
        Some(&json!({"name": "x", "policy": {"rule": {"max_runs_per_hour": 0}}})),
        400,
        "invalid_request",
    );
    let list = relay.ok("GET", "/v1/collections", &relay.owner_token, None);
    // The rule is normalized: trimmed, empty entries gone.
    assert_eq!(
        list[0]["policy"]["rule"]["allowed_prefixes"],
        json!(["git"])
    );
    assert_eq!(list[0]["policy"]["mode"], "ask");
    let view = relay.ok(
        "PUT",
        &format!("/v1/collections/{id}/policy"),
        &relay.owner_token,
        Some(&json!({"mode": "bouncer", "rule": {"max_runs_per_hour": 3}})),
    );
    assert_eq!(view["policy"]["mode"], "bouncer");
    assert_eq!(view["policy"]["rule"]["max_runs_per_hour"], 3);
    assert_eq!(view["policy"]["rule"]["allowed_prefixes"], json!([]));
    relay.fails(
        "PUT",
        "/v1/collections/999/policy",
        Some(&relay.owner_token),
        Some(&json!({})),
        404,
        "not_found",
    );
    relay.fails(
        "PUT",
        &format!("/v1/collections/{id}/policy"),
        Some(&relay.owner_token),
        Some(&json!({"mode": "loud"})),
        400,
        "invalid_request",
    );
}

#[test]
fn access_lists_only_granted_items() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let other = relay.add_collection("hidden", json!({}));
    let hidden_item = relay.add_item(
        other,
        "HIDDEN_KEY",
        CANARY2,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
    let prod = relay.add_item(
        team.collection,
        "OPENAI_API_KEY",
        "sk-proj-SyntheticCanaryThree0123456789abcdef",
        json!({"provider": "openai", "environment": "production"}),
    );
    let access = relay.ok("GET", "/v1/access", &team.agent_token, None);
    let items = access["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{access}");
    assert!(items.iter().all(|i| i["item_id"] != hidden_item));
    let stripe = items.iter().find(|i| i["item_id"] == team.item).unwrap();
    assert_eq!(stripe["env_name"], "STRIPE_API_KEY");
    assert_eq!(
        stripe["hosts"],
        json!(apassy::vault::providers::known_hosts("stripe"))
    );
    assert_eq!(
        stripe["base_url_vars"],
        json!(["APASSY_BASE_STRIPE_API_KEY", "STRIPE_API_BASE"])
    );
    assert!(stripe["approval"].as_str().unwrap().contains("known safe"));
    let openai = items.iter().find(|i| i["item_id"] == prod).unwrap();
    assert!(openai["approval"].as_str().unwrap().contains("production"));
    assert!(
        openai["base_url_vars"]
            .as_array()
            .unwrap()
            .contains(&json!("OPENAI_BASE_URL"))
    );
    assert_eq!(access["member"], "alice");
    assert_eq!(access["agent"], "alice-agent");
    assert!(!access.to_string().contains(CANARY));
    // After the grant is revoked, the list is empty.
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        &relay.owner_token,
        None,
    );
    let access = relay.ok("GET", "/v1/access", &team.agent_token, None);
    assert_eq!(access["items"].as_array().unwrap().len(), 0);
    // An archived item leaves the list of the owner too.
    relay.ok(
        "DELETE",
        &format!("/v1/items/{prod}"),
        &relay.owner_token,
        None,
    );
    relay.fails(
        "DELETE",
        &format!("/v1/items/{prod}"),
        Some(&relay.owner_token),
        None,
        404,
        "not_found",
    );
    assert_eq!(
        relay
            .ok("GET", "/v1/items", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn an_archived_env_name_can_be_used_again() {
    let relay = start(UpstreamOptions::default());
    let c = relay.add_collection("c", json!({}));
    let first = relay.add_item(
        c,
        "REUSED_KEY",
        CANARY,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
    relay.ok(
        "DELETE",
        &format!("/v1/items/{first}"),
        &relay.owner_token,
        None,
    );
    relay.add_item(
        c,
        "REUSED_KEY",
        CANARY2,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
}
