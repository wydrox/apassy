//! Teams of devices on a node (docs/SPEC.md sections 32.3 and 32.4): the in-process
//! bootstrap (`RunningNode::create_device_team`), the sign-in origin set, the device list
//! and revocation, and the node pairing codes of directory 1005 (`make_node_code`,
//! `POST /v1/teams`). Each node listens on free loopback ports and keeps its data in a
//! temporary directory. Synthetic values only.

#[path = "common/node.rs"]
mod node;
#[path = "common/relay.rs"]
mod relay;

use apassy::node::backend::RunningNode;
use apassy_relay::config::UpstreamOptions;
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys;
use apassy_relay::now_unix;
use apassy_relay::server::operator::Command;
use node::{NODE_ORIGIN, Node, NodeOptions, PUBLIC_URL, code};
use serde_json::json;

#[test]
fn a_device_team_is_made_in_process_and_its_device_signs_in_with_the_node_origin() {
    let node = Node::start(NodeOptions::default());
    let (team, mac) = node.device_team("Questions");
    // The challenge names the node origin (the first of the set).
    let challenge = node.ok(
        &node.tailnet(),
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": mac.team, "public_key": mac.key.public_key_b64()})),
    );
    assert_eq!(challenge["origin"], NODE_ORIGIN);
    // The Mac is the owner and the key holder, with no member token.
    let me = node.ok(&node.tailnet(), "GET", "/v1/me", Some(&mac.token), None);
    assert_eq!(me["role"], "owner", "{me}");
    assert_eq!(me["device_id"], mac.id);
    // It makes device links like any owner device.
    let link = node.ok(
        &node.tailnet(),
        "POST",
        "/v1/devices/links",
        Some(&mac.token),
        None,
    );
    assert!(
        link["secret"]
            .as_str()
            .is_some_and(|code| code.starts_with("apassy_lnk_"))
    );
    let devices = node.node().devices(&team).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, mac.id);
    assert_eq!(devices[0].name, "Mac mini");
    assert!(devices[0].key_holder);
    assert_eq!(devices[0].role, "owner");
    assert!(!devices[0].push);
    // The directory names the bootstrap; the node holds two teams side by side.
    let personal = node.node().create_team("Personal").unwrap();
    assert!(node.node().has_team(&team) && node.node().has_team(&personal));
    assert!(
        node.relay_audit()
            .iter()
            .any(|(action, detail)| action == "team_created" && detail.contains("\"device\"")),
    );
    // A bad key or name makes nothing.
    assert_eq!(
        node.node()
            .create_device_team("Questions", "Mac mini", "not a key")
            .unwrap_err()
            .code,
        "invalid_request"
    );
    let key = DeviceKey::generate().unwrap();
    assert_eq!(
        node.node()
            .create_device_team("", "Mac mini", &key.public_key_b64())
            .unwrap_err()
            .code,
        "invalid_request"
    );
}

#[test]
fn a_device_team_survives_a_restart() {
    let mut node = Node::start(NodeOptions::default());
    let (team, mac) = node.device_team("Questions");
    node.stop();
    node.node = Some(apassy_relay::embedded::EmbeddedNode::start(node.config.clone()).unwrap());
    assert!(node.node().has_team(&team));
    let token = node.sign_in(&mac.team, &mac.key);
    let me = node.ok(&node.tailnet(), "GET", "/v1/me", Some(&token), None);
    assert_eq!(me["device_id"], mac.id);
}

#[test]
fn a_sign_in_signed_with_the_second_origin_passes_and_one_with_an_unknown_origin_fails() {
    let node = Node::start(NodeOptions::default());
    let (_, mac) = node.device_team("Questions");
    let base = node.tailnet();
    // The Funnel origin is in the set while the public route is on.
    node.sign_in_with(&base, &mac.team, &mac.key, PUBLIC_URL)
        .expect("the second origin");
    // The app's own loopback listener takes the node origin too.
    node.sign_in_with(&node.local(), &mac.team, &mac.key, NODE_ORIGIN)
        .expect("the node listener");
    for origin in [
        "https://100.64.0.8:8444",
        "https://100.64.0.7:8445",
        "http://100.64.0.7:8444",
        "https://apassy-relay.wyderka.cc",
    ] {
        let (status, value) = node
            .sign_in_with(&base, &mac.team, &mac.key, origin)
            .expect_err(origin);
        assert_eq!((status, code(&value)), (401, "unauthenticated"), "{origin}");
    }
}

#[test]
fn a_node_without_the_public_route_takes_only_its_node_origin() {
    let dir = tempfile::tempdir().unwrap();
    let config =
        apassy_relay::config::RelayConfig::embedded(apassy_relay::config::EmbeddedOptions {
            data_dir: dir.path().join("node"),
            master_key: apassy_relay::secret::SecretString::new(node::MASTER_KEY.to_string()),
            public_url: NODE_ORIGIN.to_string(),
            public_listen: None,
            node_origin: Some(NODE_ORIGIN.to_string()),
            tailnet_listen: Some(node::loopback()),
            tailnet_agents: true,
            push_gateway: None,
        })
        .unwrap();
    assert_eq!(config.sign_in_origins(), [NODE_ORIGIN]);
    let mut node = Node {
        node: Some(apassy_relay::embedded::EmbeddedNode::start(config.clone()).unwrap()),
        config,
        dir,
    };
    let (_, mac) = node.device_team("Build box");
    let (status, _) = node
        .sign_in_with(&node.tailnet(), &mac.team, &mac.key, PUBLIC_URL)
        .expect_err("not in the set");
    assert_eq!(status, 401);
    node.stop();
}

#[test]
fn the_hosted_relay_accepts_exactly_its_public_url() {
    let relay = relay::start(UpstreamOptions::default());
    let (_, _, key) = relay.join_device("member", "bob");
    let public_key = key.public_key_b64();
    for (origin, status) in [
        (relay.config.public_url.clone(), 200),
        (NODE_ORIGIN.to_string(), 401),
        (PUBLIC_URL.to_string(), 401),
    ] {
        let challenge = relay.ok(
            "POST",
            "/v1/auth/challenge",
            "",
            Some(&json!({"team_id": relay.team_id, "public_key": public_key})),
        );
        assert_eq!(challenge["origin"], relay.config.public_url.as_str());
        let nonce = challenge["nonce"].as_str().unwrap();
        let signature = key
            .sign(&device::sign_in_message(
                &origin,
                &relay.team_id,
                &public_key,
                nonce,
            ))
            .unwrap();
        let (got, body) = relay.call(
            "POST",
            "/v1/auth/token",
            None,
            Some(&json!({"team_id": relay.team_id, "public_key": public_key,
                "nonce": nonce, "signature": hostkeys::encode_b64(&signature)})),
        );
        assert_eq!(got, status, "{origin}: {body}");
    }
    assert_eq!(
        relay.config.sign_in_origins(),
        [relay.config.public_url.as_str()]
    );
}

#[test]
fn the_app_lists_and_revokes_the_devices_of_a_team() {
    let node = Node::start(NodeOptions::default());
    let (team, mac) = node.device_team("Questions");
    let phone = node.add_device(&mac, "iPhone");
    let ids: Vec<u64> = node
        .node()
        .devices(&team)
        .unwrap()
        .iter()
        .map(|device| device.id)
        .collect();
    assert_eq!(ids, [mac.id, phone.id]);
    node.node().revoke_device(&team, phone.id).unwrap();
    // The phone's token stops at once, and it cannot sign in again.
    let (status, _) = node.call(&node.tailnet(), "GET", "/v1/me", Some(&phone.token), None);
    assert_eq!(status, 401);
    assert!(
        node.sign_in_with(&node.tailnet(), &phone.team, &phone.key, NODE_ORIGIN)
            .is_err()
    );
    assert_eq!(node.node().devices(&team).unwrap().len(), 1);
    // The last device of the last owner stays.
    assert_eq!(
        node.node().revoke_device(&team, mac.id).unwrap_err().code,
        "conflict"
    );
    let rows = node::team_audit(&node.team_file(&mac.team));
    assert!(
        rows.iter()
            .any(|(action, detail)| action == "device_revoked" && detail["device_id"] == phone.id)
    );
}

/// `POST /v1/teams` with a code, as the Mac does with a node pairing link.
fn create_team(node: &Node, code: &str, key: &DeviceKey) -> (u16, serde_json::Value) {
    node.call(
        &node.tailnet(),
        "POST",
        "/v1/teams",
        None,
        Some(&json!({"code": code, "team": "Work", "owner": "rafal",
            "device_name": "MacBook", "public_key": key.public_key_b64()})),
    )
}

#[test]
fn a_node_code_makes_a_team_once_and_never_after_its_minutes() {
    let node = Node::start(NodeOptions::default());
    let made = node.node().make_node_code(10).unwrap();
    let now = now_unix();
    assert!((now + 590..=now + 600).contains(&made.expires_at));
    let code_text = made.code.expose().to_string();
    assert!(code_text.starts_with("apassy_tcd_"));
    let key = DeviceKey::generate().unwrap();
    let (status, body) = create_team(&node, &code_text, &key);
    assert_eq!(status, 200, "{body}");
    let team =
        apassy_relay::ids::TeamId::parse(body["result"]["team_id"].as_str().unwrap()).unwrap();
    // The new owner device signs in with the node origin.
    let token = node.sign_in(&team, &key);
    let me = node.ok(&node.tailnet(), "GET", "/v1/me", Some(&token), None);
    assert_eq!(me["role"], "owner");
    // One use.
    let (status, body) = create_team(&node, &code_text, &DeviceKey::generate().unwrap());
    assert_eq!((status, code(&body)), (403, "invite_invalid"), "{body}");
    // A code past its minutes is refused.
    let (old, _) = node
        .node()
        .hub()
        .directory
        .new_node_code(1, now_unix() - 120)
        .unwrap();
    let (status, body) = create_team(&node, old.expose(), &DeviceKey::generate().unwrap());
    assert_eq!((status, code(&body)), (403, "invite_invalid"), "{body}");
    // 1 to 10 minutes.
    for minutes in [0, 11] {
        assert_eq!(
            node.node().make_node_code(minutes).unwrap_err().code,
            "invalid_request"
        );
    }
    // The directory names the kind of each code it used.
    let audit = node.relay_audit();
    assert!(
        audit
            .iter()
            .any(|(action, detail)| action == "team_created" && detail.contains("\"node\""))
    );
    assert_eq!(
        audit
            .iter()
            .filter(|(action, _)| action == "node_code_created")
            .count(),
        2
    );
}

#[test]
fn a_node_code_makes_no_team_on_a_relay_that_is_not_a_node() {
    let relay = relay::start(UpstreamOptions::default());
    let node_code = relay.operator(Command::NodeCode { minutes: 10 }).unwrap();
    let team_code = relay.operator(Command::TeamCode { hours: 1 }).unwrap();
    let body = |code: &serde_json::Value| {
        json!({"code": code, "team": "Work", "owner": "rafal", "device_name": "MacBook",
            "public_key": DeviceKey::generate().unwrap().public_key_b64()})
    };
    let (status, value) = relay.call("POST", "/v1/teams", None, Some(&body(&node_code["code"])));
    assert_eq!((status, code(&value)), (403, "invite_invalid"), "{value}");
    // The operator's code still works.
    let (status, value) = relay.call("POST", "/v1/teams", None, Some(&body(&team_code["code"])));
    assert_eq!(status, 200, "{value}");
    // A node without the tailnet route makes no node code.
    let node = Node::start(NodeOptions {
        no_tailnet: true,
        ..NodeOptions::default()
    });
    assert_eq!(
        node.node().make_node_code(10).unwrap_err().code,
        "not_supported"
    );
}
