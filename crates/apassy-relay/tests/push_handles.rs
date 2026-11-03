//! Push handles on a node (push-gateway-v1 section 10, docs/SPEC.md section 25.9):
//! `PUT` and `DELETE /v1/push/handle`, the gateway allow-list, the hosted relay without a
//! gateway, the push thread in the gateway mode against a fake gateway (the proof of the
//! contract, no token, the failed mark), the sealed summary header, and a revoked device.
//! Each node listens on free loopback ports and keeps its data in a temporary directory.
//! The handles and secrets are the synthetic vectors of push-gateway-v1 section 18.

#[path = "common/node.rs"]
mod node;
#[path = "common/relay.rs"]
mod relay;

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::node::backend::RunningNode;
use apassy_relay::config::UpstreamOptions;
use apassy_relay::hostkeys::{decode_b64, encode_b64};
use apassy_relay::now_unix;
use apassy_relay::server::push::{self, COLLAPSE_ID};
use node::{Device, Node, NodeOptions, code, team_audit};
use serde_json::{Value, json};

const IPHONE_SECRET: &str = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";
const WATCH_SECRET: &str = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
const IPHONE_HANDLE: &str = "AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGaT4PzL5NTfCFBpTDac2pO0SkZriCatsFILmsMt3V6FVKy5oQwVC_Xp0KbnZecVv6zArmDfifrV5jgi8MknGQGiRecJm9NW2etrseKbY4QHHDC16hpS29-n_ooa8Wf7_gDcl-gXUOCOht6OHZn7JjU2hewAbctZWpd_qZzpQMPBS4GKjewB9GMj8v0if9Q6ZZSlj1UQzXfSRw3Lme5AOFU5ggjW-mmefcljd5raXzDrJ-r7U7GcjJI-XAMcaScWgVAShGeklTDrvW8Qpt8C40X2UhL_GmK8G3vg9q7_5xrlTqrBrHrZRBMHwSQ3dMPyRp5zrrzBIgGn6IlRz7SLrGYTy4uHS4";
const WATCH_HANDLE: &str = "AQEQERITFBUWFxgZGhsCGEvzbKA4AcXPuDTJwi3BZGPnoSQ9aH8XBay_-VOQstGWIJlekXGdAALT_B73l_ZgGeZMEDAmyTp2zqYF69tWqZ_1R6DSxX2gstrWUC6hi0uL_AXLKTvezTUSly0XROF6ardVkVxMFK69c8oKF652vi9NMQVtpThfgcSo1b4B8urodIEdJzfJsnhSiQ2d5NFf0hi-5MRKb1hhk1whHjAU3e-pWX7QCq_bvnIu4-iml6auHpWStEPb5l8i9oVTE7ZxeOKQupMT1YV2MB-wVcUDzDx1kjox7A8NLoDDI84B00IU9fWhfFl2srTzPyfOPP8eKqBUfazI2uE1AUYBE8c3XkCdmXoCQiRLuWBv8G00W7pcFusI2_UX-MOYh1D253_JLDrQmxzREA";
const SUMMARY: &str = "ICEiIyQlJicoKSorLZYy_9V2mK8YOxL9BrISycdM3QC8LastsrSZ2rydHt5kH7FQOVw3Z9Fcdh4X0rBDP0peQmDtu1ueo2qMc8jG-HaJeH5MYA7UnBcbZRxtOLpdrfxf1XCmrKUi-gmLBZxFvggJiX35uKUAdZwfhwUqeu6y8tnLbItuN-Yk4e_Jkqawp39RHi3ux-0DNm4DCs1Nlnki8MWzWpS7q_Yf1-3uwYdSdBlr-qq7uI6GCJiJ-79H4cte4JJnY8GQ0RvTh9ZbxyqpdIhFpoe0V1w2ZgierYd-NuopbMxBWD0nepd9qDJGCGmbMZG1CwxXrjC_l2986y7k_EjhkwIbDdeBxTVnZ67guVWth1D8h-UMVEvCKR3zc2ANEQ1Qrr-skb_eNEo0hnj6Bvx6MiFWKwMUV_PcRAFVpb7so6XLs1i2bkYSzEv-w_buoaz-EnNnMD70ddE-FuZDqHiWaar_Wo0dSHz5qf5hcXNT6x185swuTpTL8sKUr32di0Qa0ObJE6BCpMOdFlxGtaKrb7bu1svCr0nLWDhMhi2Tp8ibOnvYKei4HFG251WGQ8AxcJl_7m_NTDOq4bDlEOOaOgSF7KiofJolVL4sBk8oFlaTgp2-Jvn4rFU1c04OaWJGQfOaJIvpnRXa883CBzSKZ2sNaovOg00TUiQ8Dc31pqs-ZzE8xHmg7E7YbmDyG3-UPiey7OE407l9";
const KEY_ID: &str = "630dcd2966c43366";
const CARD_NONCE: &str = "AAECAwQFBgcICQoL";

/// One call of the node to the fake gateway: the path and the body.
type Calls = Arc<Mutex<Vec<(String, Value)>>>;

/// A push gateway in process: it records each call and answers each with the HTTP status
/// and body set (200 `{"v":1,"status":200}` by default).
struct FakeGateway {
    url: String,
    calls: Calls,
    answer: Arc<Mutex<(u16, String)>>,
    stop: Arc<AtomicBool>,
}

impl FakeGateway {
    fn start() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let calls: Calls = Arc::default();
        let answer = Arc::new(Mutex::new((200, r#"{"v":1,"status":200}"#.to_string())));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, reply, done) = (calls.clone(), answer.clone(), stop.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(100)) else {
                    continue;
                };
                let mut text = String::new();
                request.as_reader().read_to_string(&mut text).unwrap();
                let body: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
                seen.lock().unwrap().push((request.url().to_string(), body));
                let (status, body) = reply.lock().unwrap().clone();
                let _ = request
                    .respond(tiny_http::Response::from_string(body).with_status_code(status));
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            calls,
            answer,
            stop,
        }
    }

    fn answer(&self, status: u16, body: Value) {
        *self.answer.lock().unwrap() = (status, body.to_string());
    }

    /// Waits until the gateway has `count` calls, and a moment more for a wrong extra one.
    fn calls(&self, count: usize) -> Vec<(String, Value)> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.calls.lock().unwrap().len() < count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(300));
        self.calls.lock().unwrap().clone()
    }
}

impl Drop for FakeGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn handle_body(gateway: &str, handle: &str, secret: &str) -> Value {
    json!({"v": 1, "gateway": gateway, "handle": handle, "secret": secret})
}

fn put_handle(node: &Node, device: &Device, body: &Value) -> (u16, Value) {
    node.call(
        &node.tailnet(),
        "PUT",
        "/v1/push/handle",
        Some(&device.token),
        Some(body),
    )
}

fn card(qid: &str, expires_at: u64) -> Value {
    json!({"v": 1, "qid": qid, "to": "member", "expires_at": expires_at, "key_id": KEY_ID,
        "nonce": CARD_NONCE, "ciphertext": encode_b64(&[9; 40])})
}

fn qid(n: u8) -> String {
    encode_b64(&[n; 16])
}

/// Posts a question of `by` through the tailnet listener, with optional extra headers.
fn ask(node: &Node, by: &Device, qid: &str, headers: &[(&str, &str)]) -> (u16, Value) {
    let (status, text) = relay::call_raw(
        &node.tailnet(),
        None,
        "POST",
        "/v1/questions",
        Some(&by.token),
        headers,
        Some(&card(qid, now_unix() + 300)),
    );
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// The device ids and failed marks (0 or 1) of the team's push handles.
fn handles(node: &Node, device: &Device) -> Vec<(i64, i64)> {
    let conn = node.team_file(&device.team);
    let mut statement = conn
        .prepare("SELECT device_id, failed_at IS NOT NULL FROM push_handle ORDER BY device_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A node with a fake gateway, its Mac, its iPhone, and its Apple Watch (one member).
fn fixture() -> (FakeGateway, Node, Device, Device, Device) {
    let gateway = FakeGateway::start();
    let node = Node::start(NodeOptions {
        gateway: Some(gateway.url.clone()),
        ..NodeOptions::default()
    });
    let (_, mac) = node.device_team("Questions");
    let phone = node.add_device(&mac, "iPhone");
    let watch = node.add_device(&mac, "Apple Watch");
    (gateway, node, mac, phone, watch)
}

#[test]
fn a_device_puts_its_handle_and_the_node_checks_its_form_and_gateway() {
    let (gateway, node, mac, phone, _) = fixture();
    let body = handle_body(&gateway.url, IPHONE_HANDLE, IPHONE_SECRET);
    let before = now_unix();
    let (status, value) = put_handle(&node, &phone, &body);
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["result"]["device_id"], phone.id);
    assert!(value["result"]["updated_at"].as_u64().unwrap() >= before);
    // The row holds the decoded handle and secret; nothing else names them.
    let conn = node.team_file(&phone.team);
    let (stored_gateway, handle, secret): (String, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT gateway, handle, secret FROM push_handle WHERE device_id = ?1",
            [phone.id as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored_gateway, gateway.url);
    assert_eq!(handle, decode_b64(IPHONE_HANDLE, 1024).unwrap());
    assert_eq!(secret, decode_b64(IPHONE_SECRET, 32).unwrap());
    let audit = team_audit(&conn);
    let set: Vec<&Value> = audit
        .iter()
        .filter(|(action, _)| action == "push_handle_set")
        .map(|(_, detail)| detail)
        .collect();
    assert_eq!(set, [&json!({"device_id": phone.id})]);
    let text = format!("{audit:?}");
    assert!(!text.contains(IPHONE_HANDLE) && !text.contains(IPHONE_SECRET));
    // The same handle again writes no new row; a new one replaces it.
    assert_eq!(put_handle(&node, &phone, &body).0, 200);
    assert_eq!(
        put_handle(
            &node,
            &phone,
            &handle_body(&gateway.url, WATCH_HANDLE, WATCH_SECRET)
        )
        .0,
        200
    );
    let rows = team_audit(&node.team_file(&phone.team))
        .into_iter()
        .filter(|(action, _)| action == "push_handle_set")
        .count();
    assert_eq!(rows, 2);
    assert_eq!(handles(&node, &phone), [(phone.id as i64, 0)]);
    // A gateway that is not the node's: 409, so a device cannot make the node call it.
    let slash = format!("{}/", gateway.url);
    for other in [
        "https://push.apassy.wyderka.cc",
        "http://127.0.0.1:9",
        slash.as_str(),
    ] {
        let (status, value) = put_handle(
            &node,
            &phone,
            &handle_body(other, IPHONE_HANDLE, IPHONE_SECRET),
        );
        let expected = if other.ends_with('/') {
            (400, "invalid_request")
        } else {
            (409, "push_gateway_refused")
        };
        assert_eq!((status, code(&value)), expected, "{other}: {value}");
    }
    // Forms: the version, the fields, the handle, and the secret.
    let mut unknown = body.clone();
    unknown["token"] = json!("a1".repeat(32));
    for bad in [
        json!({"v": 2, "gateway": gateway.url, "handle": IPHONE_HANDLE, "secret": IPHONE_SECRET}),
        json!({"v": 1, "gateway": gateway.url, "handle": IPHONE_HANDLE}),
        unknown,
        handle_body(&gateway.url, &encode_b64(&[1; 15]), IPHONE_SECRET),
        handle_body(&gateway.url, &encode_b64(&[1; 1025]), IPHONE_SECRET),
        handle_body(&gateway.url, "not base64url!", IPHONE_SECRET),
        handle_body(&gateway.url, IPHONE_HANDLE, &IPHONE_SECRET[..42]),
        handle_body(&gateway.url, IPHONE_HANDLE, &encode_b64(&[7; 31])),
        handle_body(
            &gateway.url,
            IPHONE_HANDLE,
            "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn9",
        ),
    ] {
        let (status, value) = put_handle(&node, &phone, &bad);
        assert_eq!((status, code(&value)), (400, "invalid_request"), "{bad}");
    }
    // A device of the node never uses the hosted relay's token route.
    let (status, value) = node.call(
        &node.tailnet(),
        "PUT",
        "/v1/push/token",
        Some(&mac.token),
        Some(
            &json!({"token": "a1".repeat(32), "environment": "production",
            "bundle_id": "com.wydrox.apassy.companion"}),
        ),
    );
    assert_eq!((status, code(&value)), (409, "push_unavailable"), "{value}");
    // DELETE removes it, once with a row.
    let removed = node.ok(
        &node.tailnet(),
        "DELETE",
        "/v1/push/handle",
        Some(&phone.token),
        None,
    );
    assert_eq!(removed["device_id"], phone.id);
    assert!(handles(&node, &phone).is_empty());
    node.ok(
        &node.tailnet(),
        "DELETE",
        "/v1/push/handle",
        Some(&phone.token),
        None,
    );
    let removed_rows = team_audit(&node.team_file(&phone.team))
        .into_iter()
        .filter(|(action, detail)| {
            action == "push_handle_removed" && detail["device_id"] == phone.id
        })
        .count();
    assert_eq!(removed_rows, 1);
}

#[test]
fn the_hosted_relay_and_a_node_without_a_gateway_answer_push_unavailable() {
    let relay = relay::start(UpstreamOptions::default());
    let (_, token, _) = relay.join_device("member", "bob");
    let body = handle_body(
        "https://push.apassy.wyderka.cc",
        IPHONE_HANDLE,
        IPHONE_SECRET,
    );
    for method in ["PUT", "DELETE"] {
        let body = (method == "PUT").then_some(&body);
        let (status, value) = relay.call(method, "/v1/push/handle", Some(&token), body);
        assert_eq!((status, code(&value)), (409, "push_unavailable"), "{value}");
    }
    let node = Node::start(NodeOptions::default());
    let (_, mac) = node.device_team("Questions");
    let (status, value) = put_handle(&node, &mac, &body);
    assert_eq!((status, code(&value)), (409, "push_unavailable"), "{value}");
}

#[test]
fn a_post_pushes_once_per_handle_with_the_contract_proof_and_no_token() {
    let (gateway, node, mac, phone, watch) = fixture();
    assert_eq!(
        put_handle(
            &node,
            &phone,
            &handle_body(&gateway.url, IPHONE_HANDLE, IPHONE_SECRET)
        )
        .0,
        200
    );
    assert_eq!(
        put_handle(
            &node,
            &watch,
            &handle_body(&gateway.url, WATCH_HANDLE, WATCH_SECRET)
        )
        .0,
        200
    );
    // The asking Mac has a handle too: it is not in its own routing set.
    assert_eq!(
        put_handle(
            &node,
            &mac,
            &handle_body(&gateway.url, WATCH_HANDLE, IPHONE_SECRET)
        )
        .0,
        200
    );
    let (status, posted) = ask(&node, &mac, &qid(1), &[]);
    assert_eq!(status, 200, "{posted}");
    let expires_at = posted["result"]["expires_at"].as_u64().unwrap();
    let calls = gateway.calls(2);
    assert_eq!(calls.len(), 2, "{calls:?}");
    let mut seen = Vec::new();
    for (path, body) in &calls {
        assert_eq!(path, "/v1/push");
        let fields: Vec<&String> = body.as_object().unwrap().keys().collect();
        assert_eq!(fields.len(), 6, "{body}");
        assert_eq!(body["v"], 1);
        assert_eq!(body["collapse_id"], COLLAPSE_ID);
        assert_eq!(body["expires_at"], expires_at);
        let at = body["at"].as_u64().unwrap();
        assert!(at < expires_at && expires_at <= at + 600);
        assert!(at.abs_diff(now_unix()) <= 5);
        let handle = body["handle"].as_str().unwrap();
        let secret = if handle == IPHONE_HANDLE {
            IPHONE_SECRET
        } else {
            WATCH_SECRET
        };
        assert_eq!(
            body["proof"],
            push::proof(
                &decode_b64(secret, 32).unwrap(),
                handle,
                at,
                expires_at,
                COLLAPSE_ID,
                None
            )
        );
        assert!(!body.to_string().contains("token") && !body.to_string().contains(secret));
        seen.push(handle.to_string());
    }
    seen.sort();
    let mut expected = vec![IPHONE_HANDLE.to_string(), WATCH_HANDLE.to_string()];
    expected.sort();
    assert_eq!(seen, expected);
    let deadline = Instant::now() + Duration::from_secs(10);
    let sent = || {
        team_audit(&node.team_file(&mac.team))
            .into_iter()
            .any(|(action, detail)| action == "push_sent" && detail["count"] == 2)
    };
    while !sent() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(sent());
}

#[test]
fn a_final_answer_marks_the_handle_and_a_new_put_clears_it() {
    let (gateway, node, mac, phone, _) = fixture();
    let body = handle_body(&gateway.url, IPHONE_HANDLE, IPHONE_SECRET);
    assert_eq!(put_handle(&node, &phone, &body).0, 200);
    // APNs said the token is gone.
    gateway.answer(
        200,
        json!({"v": 1, "status": 410, "reason": "Unregistered"}),
    );
    assert_eq!(ask(&node, &mac, &qid(1), &[]).0, 200);
    assert_eq!(gateway.calls(1).len(), 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while handles(&node, &phone) != [(phone.id as i64, 1)] && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(handles(&node, &phone), [(phone.id as i64, 1)]);
    // The next question skips the failed handle: no call, and no retry of the first.
    assert_eq!(ask(&node, &mac, &qid(2), &[]).0, 200);
    assert_eq!(gateway.calls(2).len(), 1);
    // A new PUT clears the mark; a gateway refusal of the handle marks it again.
    assert_eq!(put_handle(&node, &phone, &body).0, 200);
    assert_eq!(handles(&node, &phone), [(phone.id as i64, 0)]);
    gateway.answer(
        403,
        json!({"ok": false, "error": {"code": "handle_expired", "message": "The handle expired."}}),
    );
    assert_eq!(ask(&node, &mac, &qid(3), &[]).0, 200);
    assert_eq!(gateway.calls(2).len(), 2);
    let deadline = Instant::now() + Duration::from_secs(10);
    while handles(&node, &phone) != [(phone.id as i64, 1)] && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(handles(&node, &phone), [(phone.id as i64, 1)]);
    // A stale clock keeps the handle and writes a clock row; a 503 drops the push only.
    assert_eq!(put_handle(&node, &phone, &body).0, 200);
    gateway.answer(
        403,
        json!({"ok": false, "error": {"code": "stale_request", "message": "Check the clock."}}),
    );
    assert_eq!(ask(&node, &mac, &qid(4), &[]).0, 200);
    assert_eq!(gateway.calls(3).len(), 3);
    gateway.answer(
        503,
        json!({"ok": false, "error": {"code": "push_unavailable", "message": "No APNs."}}),
    );
    assert_eq!(ask(&node, &mac, &qid(5), &[]).0, 200);
    assert_eq!(gateway.calls(4).len(), 4);
    assert_eq!(handles(&node, &phone), [(phone.id as i64, 0)]);
    let audit = team_audit(&node.team_file(&mac.team));
    assert!(
        audit.iter().any(
            |(action, detail)| action == "push_failed" && detail == &json!({"reason": "clock"})
        )
    );
}

#[test]
fn a_summary_header_goes_to_the_gateway_in_the_proof_and_a_bad_one_is_refused() {
    let (gateway, node, mac, phone, _) = fixture();
    assert_eq!(
        put_handle(
            &node,
            &phone,
            &handle_body(&gateway.url, IPHONE_HANDLE, IPHONE_SECRET)
        )
        .0,
        200
    );
    let (status, value) = ask(
        &node,
        &mac,
        &qid(1),
        &[(push::SUMMARY_HEADER, &SUMMARY[..719])],
    );
    assert_eq!((status, code(&value)), (400, "invalid_request"), "{value}");
    let (status, posted) = ask(&node, &mac, &qid(2), &[(push::SUMMARY_HEADER, SUMMARY)]);
    assert_eq!(status, 200, "{posted}");
    let calls = gateway.calls(1);
    assert_eq!(calls.len(), 1, "{calls:?}");
    let body = &calls[0].1;
    assert_eq!(body["summary"], SUMMARY);
    assert_eq!(body.as_object().unwrap().len(), 7);
    let at = body["at"].as_u64().unwrap();
    assert_eq!(
        body["proof"],
        push::proof(
            &decode_b64(IPHONE_SECRET, 32).unwrap(),
            IPHONE_HANDLE,
            at,
            posted["result"]["expires_at"].as_u64().unwrap(),
            COLLAPSE_ID,
            Some(SUMMARY)
        )
    );
    // The summary is in no row of the team file.
    let conn = node.team_file(&mac.team);
    assert!(!format!("{:?}", team_audit(&conn)).contains(&SUMMARY[..40]));
}

#[test]
fn a_revoked_device_loses_its_handle() {
    let (gateway, node, mac, phone, _) = fixture();
    assert_eq!(
        put_handle(
            &node,
            &phone,
            &handle_body(&gateway.url, IPHONE_HANDLE, IPHONE_SECRET)
        )
        .0,
        200
    );
    let node_team = apassy::node::backend::NodeTeamId(mac.team.as_str().to_string());
    assert!(
        node.node()
            .devices(&node_team)
            .unwrap()
            .iter()
            .any(|device| device.id == phone.id && device.push)
    );
    node.node().revoke_device(&node_team, phone.id).unwrap();
    assert!(handles(&node, &phone).is_empty());
    assert_eq!(ask(&node, &mac, &qid(1), &[]).0, 200);
    assert!(gateway.calls(1).is_empty());
}
