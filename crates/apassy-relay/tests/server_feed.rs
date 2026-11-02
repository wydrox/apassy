//! SPEC27 the feeds of the Macs through the relay (relay-feed-v1): the vector envelopes
//! and their AADs as the relay sees them, same-member routing, a monotonic `seq`, the
//! sizes, the pace and the `feed_bytes` budget, actions to their target only, the settle
//! and the sender's read, expiry and purge, the long polls and their lane, paging,
//! revocation, Connect teams, the move from schema 5 to 6, and the audit.

#[path = "common/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use apassy_relay::config::UpstreamOptions;
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::{decode_b64, encode_b64};
use apassy_relay::ids::TeamId;
use apassy_relay::now_unix;
use apassy_relay::server::Core;
use apassy_relay::server::directory::TeamLimitsUpdate;
use apassy_relay::server::feed;
use apassy_relay::server::operator::Command;
use apassy_relay::sync_head::hex;
use relay::{TestRelay, open_team_file, start, start_with, team_of};
use serde_json::{Value, json};

// The test vectors of `docs/contracts/relay-feed-v1.md` (core), section 17.
const KEY_ID: &str = "630dcd2966c43366";
const SEQ: u64 = 1_790_000_040;
const FEED_NONCE: &str = "MDEyMzQ1Njc4OTo7";
const ACTION_ID: &str = "sLGys7S1tre4ubq7vL2-vw";
const ACTION_NONCE: &str = "QEFCQ0RFRkdISUpL";
const SETTLE_NONCE: &str = "UFFSU1RVVldYWVpb";
const VECTOR_TEAM: &str = "t_7k2m5q4x3c";

const FEED_CT_HEX: &str = "2dd63c68fed0fbc70573da2e4fe30a66aeb5b976a8a32b0bac67d36775ac2786b3c33d810f960fecdfb645235a84123fc5efd943182bc2ec6862253cd5f918b6ce2b3f1b5baec9990a838d36008edbf9ce1294712bbe2dcf1a7db5c7268e61beb68f20a72bd99de63f88d774bf4121b9a766adade408521da5b3f36aa0b6b57f5e0fdd956a7fc7471bbb5ff39441703e59e76517dcb23d098944e744d4a4797fdf44a9143e5ab65e2474eada739bb1f83ba85ea8dfe4ed55fe9ef01f8007eb352b281f2fdb1db7f9164a2ac9856b9b943786ee6ffef7f962e6fa81deb8a2d999509e18d91b746984c550dd8fccca1fcb1ff803ca97e48d04a78b79695b98bcddc170f808894ef24bd3a890358075f9031cee5ddec1bd9490f4d3162b902c38fbfb69f3ff41fecafa48d111d253daaf23f447d5f9998406241c60a1110213e932690c93933f6e4c91cf52a37380b2a48749999519caed7b735c7395e8e58d8a9e664b16308ec8c502a185a13289e31a5ba84d5ced3a4de5bbcfca9c3bc3b22eb0077f5e1d21af4bfac786ca23eeecaeecdc8e64d59c7997832031134b6d6239dd0ecaf50de6611493b21406f6c780c167cf92edbfe4ee5bf5b87b8d795535ee3249b614a699776b884198a76e346fa239a0ea2e05f5a9b3bf90cb5f99c966486d90836d591637195412f2d114eabe41e6a8d8291012700aac012c1e139e109fc35a7bbd491fb67a9f933dfda4d978f867c6263c4c2d39efeee34636166fb40b147823542fec687577d784b540c8078d40ed40f9b3fd5b3f6db45023ff3afbc7039dd4ecad5835a8f1b0ad63fdfeaa4fc5902941167c69edd10d9a2ec53a3626b696ce0b8e31a96cc78e8b8396c4a561326de2994013a218fc5602b2b288acbbdf522771eddeb42c2be6e0f4048d2bbec3502c7922e9d9e9c5819e0c5d8f401f10fff0e4afd09b0584d9b7d60dde78184303fd03275ee4b93c5a819a5553dcb9ce8f48540e110894242e2cdd3bb1ce18c8367835793c116e51dcbc9ebcab5147c8010958b359794aed4ece7c837ea6a5bacc13b131bf9a6f9fdd31c18f36f7c60ea545035897d624f1e0d180f935139c2fd1b203e4c3722cf5ecaea15541e58947b78db27d464c31add5aed50cbe545702db2093c72f7dc0690e7c366c486f15ca00bb7a0364c986af0a6890965bb4ee6189018eef28ef95f88c270416f72bea4193c7532372c7deb509106955eb7a20ac611074f0d49313d8ff98d4d685b33ffb0b61cece6f6bb3c9a1c01210d418661810651b6f79236a5e83ac257f4e9a9f57cdef5d1ead09fbb024b3b879af3d10";

const ACTION_CT_HEX: &str = "83760aa3487bc22339ac8269d48132a4d0ee593a37b006168d3b816a9e555f5e85d1e847500750db7c180d6b483697bcdb715aafcf15bd4ae9a322086a5f574cff551c3b7e2b861220235deaf24a170fee3da44fc9dfc2429f05c30f367eb216a95dbb391fe5384e66eaf6e93fd854db8fc1d6ceb0b2ab28d979941a463e3768ea501aefb6d699f22d9a1c02c99bfdddfd7c80e2a4cf67d726f759e70e92ee1a4208141f7e524fc951c2e256158fef5c05ebac29bccb949f0d55496147c2adca721668fbabe886329f133e0a88c2a5a8852d6313d8b1a8599a9e54d090baf388daafb0f9aef88394fd2dd1d17ae94da471e0809a58f297dca1445b7856d52ffd318b85094841c7dafc3d91560900be56e5f679d80a7034b6bbd91f3194a3984e46fbf31bef4e009fc9594605f8734cc51c5ef7a6a11bc23583f85ddd57b8c0b89fe84609d024214c9bb156b8df32a17499c42b9db93e5328b59343b3d4f5bd6dfd7f510ebc14181e77fc16ce84944f495bb2b6128a25991a5c4d48356faf8357c590e377c72b9594ef2cfc90e70c25d470d5856f5932ab7a95df6cb8e2234c8d075eda3e9036e08067be6043ec080bb183b69f";

const SETTLE_CT_HEX: &str = "45c1455083097076570a95408f49b1f62de9b76b09a5c47982c1f3b5c77807a3639e5ecf86f3776b677093db298da725bfe2853c8688b69ad7b4a7832e77d73b1ac2ecd226b7cb5a4afdf3983e7e2acf4d006065b984d08880aaa87d41d13ec7fb54c8e0c1f5a9e420b91c0814b97d13b6e076ff2594ee2ba2c7d39ddfaea96b2a1c";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A vector ciphertext as the wire carries it: base64url.
fn b64(hex: &str) -> String {
    encode_b64(&unhex(hex))
}

/// A synthetic action id: 16 bytes of `n`.
fn action_id(n: u8) -> String {
    encode_b64(&[n; 16])
}

/// One signed-in device: its access token, its id, its member, and its key.
struct Device {
    token: String,
    id: u64,
    member: u64,
    key: DeviceKey,
}

fn device_of(relay: &TestRelay, token: String, key: DeviceKey) -> Device {
    let me = relay.ok("GET", "/v1/me", &token, None);
    Device {
        id: me["device_id"].as_u64().expect("device id"),
        member: me["member_id"].as_u64().expect("member id"),
        token,
        key,
    }
}

/// A new team through a team code: the owner's first device, named "Owner device".
fn personal_team(relay: &mut TestRelay) -> Device {
    let (token, key) = relay.new_team_device("Personal", "owner");
    relay.switch_team(&token);
    device_of(relay, token, key)
}

/// Another device of the same member through a confirmed device link.
fn add_device(relay: &TestRelay, first: &Device, name: &str) -> Device {
    let key = DeviceKey::generate().unwrap();
    let team = team_of(&first.token);
    let made = relay.ok("POST", "/v1/devices/links", &first.token, None);
    let code = made["secret"].as_str().unwrap().to_string();
    let pending = relay.ok(
        "POST",
        "/v1/devices/link",
        "",
        Some(&json!({"code": code, "device_name": name, "public_key": key.public_key_b64()})),
    );
    let words = device::safety_words(&team, &code, &key.public_key());
    relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        &first.token,
        Some(&json!({"safety": words})),
    );
    let token = relay.sign_in(&team, &key);
    device_of(relay, token, key)
}

/// A new member of the current team with one device.
fn join(relay: &TestRelay, role: &str, name: &str) -> Device {
    let (_, token, key) = relay.join_device(role, name);
    device_of(relay, token, key)
}

fn core_of(relay: &TestRelay, device: &Device) -> std::sync::Arc<Core> {
    relay.hub().team(&team_of(&device.token)).unwrap()
}

fn feed_body(seq: u64, ciphertext: &str) -> Value {
    json!({"v": 1, "seq": seq, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": ciphertext})
}

fn action_body(id: &str, to: u64, ciphertext: &str) -> Value {
    json!({"v": 1, "action_id": id, "to_device": to, "key_id": KEY_ID, "nonce": ACTION_NONCE,
        "ciphertext": ciphertext})
}

fn settle_body(outcome: &str, ciphertext: &str) -> Value {
    json!({"v": 1, "outcome": outcome, "key_id": KEY_ID, "nonce": SETTLE_NONCE,
        "ciphertext": ciphertext})
}

fn put(relay: &TestRelay, by: &Device, seq: u64, ciphertext: &str) -> (u16, Value) {
    relay.call(
        "PUT",
        "/v1/feed",
        Some(&by.token),
        Some(&feed_body(seq, ciphertext)),
    )
}

/// A feed that must land.
fn publish(relay: &TestRelay, by: &Device, seq: u64) -> Value {
    relay.ok(
        "PUT",
        "/v1/feed",
        &by.token,
        Some(&feed_body(seq, &encode_b64(&[seq as u8; 40]))),
    )
}

/// Lifts the 10 s pace of feeds: the last feed of each device is 10 s older.
fn pace(relay: &TestRelay, core: &Core) {
    core.feed_times.lock().unwrap().clear();
    relay.edit_vault_live("UPDATE feed SET updated_at = updated_at - 10");
}

/// Moves the last `feed_started` or `feed_deleted` row of each device an hour back.
fn hour_later(core: &Core) {
    for last in core.feed_audit.lock().unwrap().values_mut() {
        last.at = last.at.saturating_sub(feed::FEED_AUDIT_SECS);
    }
}

fn feeds(relay: &TestRelay, by: &Device, since: u64) -> Value {
    relay.ok("GET", &format!("/v1/feed?since={since}"), &by.token, None)
}

fn feed_ids(list: &Value) -> Vec<u64> {
    list["feeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|feed| feed["device_id"].as_u64().unwrap())
        .collect()
}

fn post(relay: &TestRelay, by: &Device, id: &str, to: &Device) -> (u16, Value) {
    relay.call(
        "POST",
        "/v1/feed/actions",
        Some(&by.token),
        Some(&action_body(id, to.id, &encode_b64(&[4; 30]))),
    )
}

fn actions(relay: &TestRelay, by: &Device, after: u64) -> Value {
    relay.ok(
        "GET",
        &format!("/v1/feed/actions?after={after}"),
        &by.token,
        None,
    )
}

fn action_ids(list: &Value) -> Vec<String> {
    list["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action["action_id"].as_str().unwrap().to_string())
        .collect()
}

/// The audit rows of the current team: action and detail.
fn audit(relay: &TestRelay) -> Vec<(String, Value)> {
    relay
        .vault_rows("SELECT action, detail FROM audit ORDER BY id")
        .into_iter()
        .map(|(action, detail)| {
            (
                String::from_utf8(action).unwrap(),
                serde_json::from_slice(&detail).unwrap(),
            )
        })
        .collect()
}

fn rows<'a>(rows: &'a [(String, Value)], action: &str) -> Vec<&'a Value> {
    rows.iter()
        .filter(|(name, _)| name == action)
        .map(|(_, detail)| detail)
        .collect()
}

fn code(value: &Value) -> &str {
    value["error"]["code"].as_str().unwrap_or_default()
}

/// Calls `f` and returns its answer with how long it took.
fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let started = Instant::now();
    let out = f();
    (out, started.elapsed())
}

/// A request written by hand: `head` holds the extra header lines, each with `\r\n`.
fn raw(
    relay: &TestRelay,
    method: &str,
    path: &str,
    token: &str,
    head: &str,
    body: &[u8],
) -> (u16, Value) {
    let addr = relay.url.trim_start_matches("http://").to_string();
    let mut stream = std::net::TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nX-Apassy-Edge: {}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\n{head}Connection: close\r\n\r\n",
        relay.edge_secret,
    )
    .unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let status = answer
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {answer:?}"));
    let json = answer
        .find('{')
        .zip(answer.rfind('}'))
        .map(|(start, end)| serde_json::from_str(&answer[start..=end]).unwrap())
        .unwrap_or(Value::Null);
    (status, json)
}

/// The AAD of relay-feed-v1 section 6.1 as hex: the fields joined with one zero byte.
fn aad(parts: &[&str]) -> String {
    hex(parts.join("\0").as_bytes())
}

#[test]
fn the_vector_envelopes_go_through_put_list_action_settle_and_status() {
    let mut relay = start(UpstreamOptions::default());
    // The device ids of the vectors: the Mac is 2, the iPhone 3.
    let first = personal_team(&mut relay);
    let mac = add_device(&relay, &first, "MacBook Pro");
    let phone = add_device(&relay, &first, "Test iPhone");
    assert_eq!((first.id, mac.id, phone.id), (1, 2, 3));

    let feed_ct = b64(FEED_CT_HEX);
    let before = now_unix();
    let put = relay.ok(
        "PUT",
        "/v1/feed",
        &mac.token,
        Some(&feed_body(SEQ, &feed_ct)),
    );
    assert_eq!(
        (&put["device_id"], &put["seq"], &put["change"]),
        (&json!(2), &json!(SEQ), &json!(1))
    );
    let updated_at = put["updated_at"].as_u64().unwrap();
    assert!((before..=now_unix()).contains(&updated_at));
    // Every device of the member reads it, the publisher too.
    for device in [&phone, &mac, &first] {
        assert_eq!(
            feeds(&relay, device, 0),
            json!({"change": 1, "more": false, "present": [2], "feeds": [{
                "device_id": 2, "device_name": "MacBook Pro", "seq": SEQ, "change": 1,
                "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": feed_ct,
                "updated_at": updated_at}]})
        );
        assert_eq!(
            feeds(&relay, device, 1),
            json!({"change": 1, "more": false, "present": [2], "feeds": []})
        );
    }
    // Stored and returned as given: the ciphertext opens with the AAD that the reader
    // builds from the clear fields (section 17.1).
    let listed = feeds(&relay, &phone, 0);
    let entry = &listed["feeds"][0];
    assert_eq!(
        hex(&decode_b64(entry["ciphertext"].as_str().unwrap(), 300_000).unwrap()),
        FEED_CT_HEX
    );
    assert_eq!(
        relay.vault_rows("SELECT lower(hex(ciphertext)), lower(hex(nonce)) FROM feed")[0],
        (
            FEED_CT_HEX.as_bytes().to_vec(),
            b"303132333435363738393a3b".to_vec()
        )
    );
    assert_eq!(
        aad(&[
            "apassy-feed-v1",
            "feed",
            VECTOR_TEAM,
            &entry["device_id"].to_string(),
            &entry["seq"].to_string(),
            entry["key_id"].as_str().unwrap(),
        ]),
        "6170617373792d666565642d7631006665656400745f376b326d357134783363003200313739303030303034300036333064636432393636633433333636"
    );

    // The action of 17.3 from the iPhone to the Mac.
    let action_ct = b64(ACTION_CT_HEX);
    let body = action_body(ACTION_ID, mac.id, &action_ct);
    let before = now_unix();
    let posted = relay.ok("POST", "/v1/feed/actions", &phone.token, Some(&body));
    assert_eq!(
        (&posted["action_id"], &posted["seq"]),
        (&json!(ACTION_ID), &json!(1))
    );
    let created_at = posted["created_at"].as_u64().unwrap();
    assert!((before..=now_unix()).contains(&created_at));
    assert_eq!(posted["expires_at"], created_at + 300);
    // A retry of a post that landed.
    relay.fails(
        "POST",
        "/v1/feed/actions",
        Some(&phone.token),
        Some(&body),
        409,
        "conflict",
    );
    // Only the target lists it, with the sender stamped.
    let listed = actions(&relay, &mac, 0);
    assert_eq!(
        listed,
        json!({"seq": 1, "actions": [{"action_id": ACTION_ID, "seq": 1, "from_device_id": 3,
            "key_id": KEY_ID, "nonce": ACTION_NONCE, "ciphertext": action_ct,
            "created_at": created_at, "expires_at": created_at + 300}]})
    );
    for device in [&phone, &first] {
        assert_eq!(actions(&relay, device, 0), json!({"seq": 1, "actions": []}));
    }
    assert_eq!(actions(&relay, &mac, 1)["actions"], json!([]));
    let entry = &listed["actions"][0];
    assert_eq!(
        aad(&[
            "apassy-feed-v1",
            "action",
            VECTOR_TEAM,
            entry["action_id"].as_str().unwrap(),
            entry["key_id"].as_str().unwrap(),
            &entry["from_device_id"].to_string(),
            &mac.id.to_string(),
        ]),
        "6170617373792d666565642d763100616374696f6e00745f376b326d35713478336300734c4779733753317472653475627137764c322d7677003633306463643239363663343333363600330032"
    );
    // The sender reads it open; nobody else finds it.
    let status_path = format!("/v1/feed/actions/{ACTION_ID}");
    let open = relay.ok("GET", &status_path, &phone.token, None);
    assert_eq!(
        open,
        json!({"action_id": ACTION_ID, "to_device": 2, "state": "open",
            "created_at": created_at, "expires_at": created_at + 300})
    );
    for device in [&mac, &first] {
        relay.fails(
            "GET",
            &status_path,
            Some(&device.token),
            None,
            404,
            "not_found",
        );
    }

    // The settle of 17.4, by the target only; a retry answers the same.
    let settle_ct = b64(SETTLE_CT_HEX);
    let settle_path = format!("/v1/feed/actions/{ACTION_ID}/settle");
    let settle = settle_body("applied", &settle_ct);
    for device in [&phone, &first] {
        relay.fails(
            "POST",
            &settle_path,
            Some(&device.token),
            Some(&settle),
            404,
            "not_found",
        );
    }
    let settled = relay.ok("POST", &settle_path, &mac.token, Some(&settle));
    assert_eq!(
        (
            &settled["action_id"],
            &settled["state"],
            &settled["outcome"]
        ),
        (&json!(ACTION_ID), &json!("settled"), &json!("applied"))
    );
    let settled_at = settled["settled_at"].as_u64().unwrap();
    assert_eq!(
        relay.ok("POST", &settle_path, &mac.token, Some(&settle)),
        settled
    );
    for other in [
        settle_body("refused", &settle_ct),
        settle_body("applied", &encode_b64(&[1; 130])),
        json!({"v": 1, "outcome": "applied", "key_id": "0123456789abcdef", "nonce": SETTLE_NONCE,
            "ciphertext": settle_ct}),
    ] {
        relay.fails(
            "POST",
            &settle_path,
            Some(&mac.token),
            Some(&other),
            409,
            "action_settled",
        );
    }
    // The settled action leaves the target's list; the sender reads the outcome and the
    // settle as stored.
    assert_eq!(actions(&relay, &mac, 0)["actions"], json!([]));
    let read = relay.ok("GET", &format!("{status_path}?wait=25"), &phone.token, None);
    assert_eq!(
        read,
        json!({"action_id": ACTION_ID, "to_device": 2, "state": "settled",
            "created_at": created_at, "expires_at": created_at + 300, "outcome": "applied",
            "settled_at": settled_at,
            "settle": {"key_id": KEY_ID, "nonce": SETTLE_NONCE, "ciphertext": settle_ct}})
    );
    assert_eq!(
        aad(&[
            "apassy-feed-v1",
            "settle",
            VECTOR_TEAM,
            read["action_id"].as_str().unwrap(),
            read["settle"]["key_id"].as_str().unwrap(),
            read["outcome"].as_str().unwrap(),
        ]),
        "6170617373792d666565642d763100736574746c6500745f376b326d35713478336300734c4779733753317472653475627137764c322d76770036333064636432393636633433333636006170706c696564"
    );

    // The audit: device ids and the clear outcome only, never an envelope or an id.
    let rows_now = audit(&relay);
    assert_eq!(
        rows(&rows_now, "feed_started"),
        vec![&json!({"device_id": 2})]
    );
    assert_eq!(
        rows(&rows_now, "feed_action_posted"),
        vec![&json!({"device_id": 3, "to_device_id": 2})]
    );
    assert_eq!(
        rows(&rows_now, "feed_action_settled"),
        vec![&json!({"device_id": 2, "from_device_id": 3, "outcome": "applied"})]
    );
    let text = serde_json::to_string(&rows_now).unwrap();
    for secret in [
        ACTION_ID,
        FEED_NONCE,
        ACTION_NONCE,
        SETTLE_NONCE,
        &feed_ct[..40],
        &action_ct[..40],
    ] {
        assert!(!text.contains(secret), "{secret}");
    }
}

#[test]
fn only_the_devices_of_the_member_see_a_feed_and_send_to_it() {
    let mut relay = start(UpstreamOptions::default());
    // The owner token of `init` is a member token without a device.
    let member_token = relay.owner_token.clone();
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let other = join(&relay, "manager", "Sam");
    let others_phone = add_device(&relay, &other, "Sam's iPhone");
    assert_ne!(other.member, mac.member);
    publish(&relay, &mac, 1);
    publish(&relay, &other, 1);
    // Each member sees its own feed only, with `present` of its own devices.
    assert_eq!(feed_ids(&feeds(&relay, &phone, 0)), vec![mac.id]);
    assert_eq!(feeds(&relay, &phone, 0)["present"], json!([mac.id]));
    for device in [&other, &others_phone] {
        let list = feeds(&relay, device, 0);
        assert_eq!(feed_ids(&list), vec![other.id]);
        assert_eq!(list["present"], json!([other.id]));
    }
    // An action to another member's device, or to itself, is not routed; to a device
    // of the member without a feed it is 404.
    for (by, to) in [(&others_phone, &mac), (&phone, &other), (&mac, &mac)] {
        let (status, value) = post(&relay, by, &action_id(1), to);
        assert_eq!((status, code(&value)), (403, "not_routed"), "{value}");
    }
    let (status, value) = post(&relay, &mac, &action_id(1), &phone);
    assert_eq!((status, code(&value)), (404, "not_found"), "{value}");
    let (status, value) = relay.call(
        "POST",
        "/v1/feed/actions",
        Some(&phone.token),
        Some(&action_body(&action_id(1), 999, &encode_b64(&[1; 20]))),
    );
    assert_eq!((status, code(&value)), (403, "not_routed"));
    // The actions of one member stay with it.
    assert_eq!(post(&relay, &phone, &action_id(2), &mac).0, 200);
    assert_eq!(post(&relay, &others_phone, &action_id(3), &other).0, 200);
    assert_eq!(action_ids(&actions(&relay, &mac, 0)), vec![action_id(2)]);
    assert_eq!(action_ids(&actions(&relay, &other, 0)), vec![action_id(3)]);
    relay.fails(
        "GET",
        &format!("/v1/feed/actions/{}", action_id(2)),
        Some(&others_phone.token),
        None,
        404,
        "not_found",
    );
    relay.fails(
        "POST",
        &format!("/v1/feed/actions/{}/settle", action_id(2)),
        Some(&other.token),
        Some(&settle_body("stale", &encode_b64(&[1; 20]))),
        404,
        "not_found",
    );
    // An action_id is one per team: another member cannot reuse it either.
    publish(&relay, &others_phone, 1);
    let (status, value) = post(&relay, &other, &action_id(2), &others_phone);
    assert_eq!((status, code(&value)), (409, "conflict"));
    // A member token (no device) is 401 on every feed route.
    for (method, path, body) in [
        ("GET", "/v1/feed".to_string(), None),
        (
            "PUT",
            "/v1/feed".to_string(),
            Some(feed_body(1, &encode_b64(&[1; 20]))),
        ),
        ("DELETE", "/v1/feed".to_string(), None),
        ("GET", "/v1/feed/actions".to_string(), None),
        (
            "POST",
            "/v1/feed/actions".to_string(),
            Some(action_body(&action_id(9), mac.id, &encode_b64(&[1; 20]))),
        ),
        ("GET", format!("/v1/feed/actions/{}", action_id(2)), None),
        (
            "POST",
            format!("/v1/feed/actions/{}/settle", action_id(2)),
            Some(settle_body("stale", &encode_b64(&[1; 20]))),
        ),
    ] {
        relay.fails(
            method,
            &path,
            Some(&member_token),
            body.as_ref(),
            401,
            "unauthenticated",
        );
    }
    // Another team sees nothing of this one.
    let (outsider_token, key) = relay.new_team_device("Elsewhere", "eve");
    let outsider = device_of(&relay, outsider_token, key);
    assert_eq!(
        feeds(&relay, &outsider, 0),
        json!({"change": 0, "more": false, "present": [], "feeds": []})
    );
    assert_eq!(
        actions(&relay, &outsider, 0),
        json!({"seq": 0, "actions": []})
    );
    relay.fails(
        "GET",
        &format!("/v1/feed/actions/{}", action_id(2)),
        Some(&outsider.token),
        None,
        404,
        "not_found",
    );
}

#[test]
fn seq_goes_up_and_a_feed_replaces_the_last_one() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let core = core_of(&relay, &mac);
    assert_eq!(publish(&relay, &mac, 100)["change"], 1);
    // The same seq again (a retry of a feed that landed) is 409, not the pace's 403; so
    // is a lower one.
    for seq in [100, 99, 1] {
        let (status, value) = put(&relay, &mac, seq, &encode_b64(&[1; 20]));
        assert_eq!((status, code(&value)), (409, "seq_not_newer"), "{seq}");
    }
    // A higher one within 10 s of the last accepted feed is paced.
    let (status, value) = put(&relay, &mac, 101, &encode_b64(&[1; 20]));
    assert_eq!((status, code(&value)), (403, "feed_limit"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("10 seconds")
    );
    pace(&relay, &core);
    let second = publish(&relay, &mac, 101);
    assert_eq!(
        (&second["seq"], &second["change"]),
        (&json!(101), &json!(2))
    );
    // One row per device: the new feed replaced the old one, with the new counter.
    let list = feeds(&relay, &phone, 0);
    assert_eq!(list["feeds"].as_array().unwrap().len(), 1);
    assert_eq!(
        (
            &list["feeds"][0]["seq"],
            &list["feeds"][0]["change"],
            &list["change"]
        ),
        (&json!(101), &json!(2), &json!(2))
    );
    assert_eq!(list["feeds"][0]["ciphertext"], encode_b64(&[101; 40]));
    assert_eq!(
        relay.vault_rows("SELECT count(*), max(seq) FROM feed")[0],
        (b"1".to_vec(), b"101".to_vec())
    );
    // Feeds of two devices take turns on one team counter.
    let mini = add_device(&relay, &mac, "Mac mini");
    assert_eq!(publish(&relay, &mini, 5)["change"], 3);
    pace(&relay, &core);
    assert_eq!(publish(&relay, &mac, 102)["change"], 4);
    let list = feeds(&relay, &phone, 2);
    assert_eq!(feed_ids(&list), vec![mini.id, mac.id]);
    assert_eq!(list["present"], json!([mac.id, mini.id]));
    // The largest seq is 2^53 - 1; 0 and 2^53 are out of the form.
    pace(&relay, &core);
    for seq in [0u64, 1 << 53] {
        let (status, value) = put(&relay, &mini, seq, &encode_b64(&[1; 20]));
        assert_eq!((status, code(&value)), (400, "invalid_request"), "{seq}");
    }
    let (status, value) = relay.call(
        "PUT",
        "/v1/feed",
        Some(&mini.token),
        Some(&json!({"v": 1, "seq": -1, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": "AAAA"})),
    );
    assert_eq!((status, code(&value)), (400, "invalid_request"));
    assert_eq!(
        publish(&relay, &mini, (1 << 53) - 1)["seq"],
        json!(9_007_199_254_740_991u64)
    );
    // A delete does not lift the pace, and the feed's next seq is free again.
    relay.ok("DELETE", "/v1/feed", &mini.token, None);
    let (status, value) = put(&relay, &mini, 1, &encode_b64(&[1; 20]));
    assert_eq!((status, code(&value)), (403, "feed_limit"), "{value}");
    pace(&relay, &core);
    assert_eq!(put(&relay, &mini, 1, &encode_b64(&[1; 20])).0, 200);
    // No audit row per feed update: one `feed_started` per first feed. The delete came
    // within the hour of the device's last row, so it waits: no row yet.
    let audit_rows = audit(&relay);
    assert_eq!(
        rows(&audit_rows, "feed_started"),
        vec![
            &json!({"device_id": mac.id}),
            &json!({"device_id": mini.id})
        ]
    );
    assert!(rows(&audit_rows, "feed_deleted").is_empty());
    let count = audit_rows.len();
    pace(&relay, &core);
    publish(&relay, &mac, 200);
    assert_eq!(audit(&relay).len(), count);
    // A loop of PUT and DELETE does not grow the audit: at most one row per device and
    // hour, and the feed is on again, as the last row says, so maintenance writes none.
    for seq in 2..8 {
        relay.ok("DELETE", "/v1/feed", &mini.token, None);
        pace(&relay, &core);
        assert_eq!(put(&relay, &mini, seq, &encode_b64(&[1; 20])).0, 200);
    }
    hour_later(&core);
    feed::maintenance(&core, now_unix()).unwrap();
    assert_eq!(audit(&relay).len(), count);
    // An hour later a delete writes its row at once; the start right after it waits,
    // and maintenance writes it an hour later, as the feed is on then.
    relay.ok("DELETE", "/v1/feed", &mini.token, None);
    pace(&relay, &core);
    assert_eq!(put(&relay, &mini, 9, &encode_b64(&[1; 20])).0, 200);
    feed::maintenance(&core, now_unix()).unwrap();
    let audit_rows = audit(&relay);
    assert_eq!(
        audit_rows[count..],
        [(
            "feed_deleted".to_string(),
            json!({"device_id": mini.id, "reason": "deleted"})
        )]
    );
    hour_later(&core);
    feed::maintenance(&core, now_unix()).unwrap();
    let audit_rows = audit(&relay);
    assert_eq!(
        audit_rows[count..],
        [
            (
                "feed_deleted".to_string(),
                json!({"device_id": mini.id, "reason": "deleted"})
            ),
            ("feed_started".to_string(), json!({"device_id": mini.id}))
        ]
    );
    let actors = relay.vault_rows("SELECT actor, '' FROM audit ORDER BY id DESC LIMIT 1");
    assert_eq!(actors[0].0, format!("member:{}", mini.member).into_bytes());
    // A revocation always writes its row, also within the hour.
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", mini.id),
        &mac.token,
        None,
    );
    assert_eq!(
        rows(&audit(&relay), "feed_deleted").last().unwrap(),
        &&json!({"device_id": mini.id, "reason": "device_revoked"})
    );
    // A revoked device's held-back row is not written later.
    hour_later(&core);
    let count = audit(&relay).len();
    feed::maintenance(&core, now_unix()).unwrap();
    assert_eq!(audit(&relay).len(), count);
}

#[test]
fn sizes_forms_and_body_caps() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let core = core_of(&relay, &mac);
    // The largest feed: 256 KiB of ciphertext, 349526 characters in a body under
    // 352 KiB. One byte more is 413.
    let full = encode_b64(&vec![7; feed::MAX_FEED_BYTES]);
    assert_eq!(full.len(), 349_526);
    let (status, value) = put(
        &relay,
        &mac,
        2,
        &encode_b64(&vec![7; feed::MAX_FEED_BYTES + 1]),
    );
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    assert_eq!(put(&relay, &mac, 1, &full).0, 200);
    // Forms: v, key_id, nonce, an empty or non-b64u ciphertext, an unknown field.
    pace(&relay, &core);
    for body in [
        json!({"v": 2, "seq": 5, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": "AAAA"}),
        json!({"v": 1, "seq": 5, "key_id": "630DCD2966C43366", "nonce": FEED_NONCE, "ciphertext": "AAAA"}),
        json!({"v": 1, "seq": 5, "key_id": KEY_ID, "nonce": "AAAA", "ciphertext": "AAAA"}),
        json!({"v": 1, "seq": 5, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": ""}),
        json!({"v": 1, "seq": 5, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": "a+b/"}),
        json!({"v": 1, "seq": 5, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": "AAAA", "device": 1}),
        json!({"v": 1, "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": "AAAA"}),
    ] {
        let (status, value) = relay.call("PUT", "/v1/feed", Some(&mac.token), Some(&body));
        assert_eq!((status, code(&value)), (400, "invalid_request"), "{body}");
    }
    // The body cap of the feed: 352 KiB, read from Content-Length before the token.
    let big = vec![b' '; 360_449];
    let (status, value) = raw(
        &relay,
        "PUT",
        "/v1/feed",
        "apassy_acc_nothing",
        "Content-Length: 360449\r\n",
        &big,
    );
    assert_eq!(
        (status, code(&value)),
        (413, "payload_too_large"),
        "{value}"
    );
    let (status, value) = raw(
        &relay,
        "PUT",
        "/v1/feed",
        &mac.token,
        "Content-Length: 360449\r\n",
        &big,
    );
    assert_eq!(
        (status, code(&value)),
        (413, "payload_too_large"),
        "{value}"
    );
    // Without Content-Length, or chunked: 400.
    let (status, value) = raw(&relay, "PUT", "/v1/feed", &mac.token, "", b"");
    assert_eq!((status, code(&value)), (400, "invalid_request"), "{value}");
    let body = feed_body(9, "AAAA").to_string();
    let chunked = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    let (status, value) = raw(
        &relay,
        "PUT",
        "/v1/feed",
        &mac.token,
        "Transfer-Encoding: chunked\r\n",
        chunked.as_bytes(),
    );
    assert_eq!((status, code(&value)), (400, "invalid_request"), "{value}");
    // A body of 352 KiB with spaces around the feed is read whole.
    let mut padded = feed_body(10, &full).to_string().into_bytes();
    padded.resize(360_448, b' ');
    let (status, value) = raw(
        &relay,
        "PUT",
        "/v1/feed",
        &mac.token,
        "Content-Length: 360448\r\n",
        &padded,
    );
    assert_eq!(status, 200, "{value}");
    // Every other body keeps the 64 KiB cap.
    let over = vec![b' '; 65_537];
    for (method, path) in [
        ("POST", "/v1/feed/actions".to_string()),
        ("POST", format!("/v1/feed/actions/{}/settle", action_id(1))),
        ("POST", "/v1/questions".to_string()),
    ] {
        let (status, value) = raw(
            &relay,
            method,
            &path,
            &phone.token,
            "Content-Length: 65537\r\n",
            &over,
        );
        assert_eq!(
            (status, code(&value)),
            (413, "payload_too_large"),
            "{method} {path}"
        );
    }
    // The action and settle ciphertexts: 4112 and 1040 bytes at most.
    let (status, value) = relay.call(
        "POST",
        "/v1/feed/actions",
        Some(&phone.token),
        Some(&action_body(
            &action_id(1),
            mac.id,
            &encode_b64(&vec![1; feed::MAX_ACTION_BYTES + 1]),
        )),
    );
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    assert_eq!(
        relay
            .call(
                "POST",
                "/v1/feed/actions",
                Some(&phone.token),
                Some(&action_body(
                    &action_id(1),
                    mac.id,
                    &encode_b64(&vec![1; feed::MAX_ACTION_BYTES])
                )),
            )
            .0,
        200
    );
    let settle_path = format!("/v1/feed/actions/{}/settle", action_id(1));
    let (status, value) = relay.call(
        "POST",
        &settle_path,
        Some(&mac.token),
        Some(&settle_body(
            "applied",
            &encode_b64(&vec![1; feed::MAX_SETTLE_BYTES + 1]),
        )),
    );
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    // Action and settle forms.
    for body in [
        action_body("short", mac.id, "AAAA"),
        action_body(&action_id(2), 0, "AAAA"),
        json!({"v": 1, "action_id": action_id(2), "to_device": mac.id, "key_id": KEY_ID, "nonce": ACTION_NONCE, "ciphertext": "AAAA", "from_device_id": 1}),
        json!({"v": 1, "action_id": action_id(2), "to_device": "2", "key_id": KEY_ID, "nonce": ACTION_NONCE, "ciphertext": "AAAA"}),
    ] {
        let (status, value) =
            relay.call("POST", "/v1/feed/actions", Some(&phone.token), Some(&body));
        assert_eq!((status, code(&value)), (400, "invalid_request"), "{body}");
    }
    for body in [
        settle_body("done", "AAAA"),
        json!({"v": 1, "outcome": "applied", "key_id": "x", "nonce": SETTLE_NONCE, "ciphertext": "AAAA"}),
        json!({"v": 1, "outcome": "applied", "key_id": KEY_ID, "nonce": SETTLE_NONCE, "ciphertext": ""}),
        json!({"v": 0, "outcome": "applied", "key_id": KEY_ID, "nonce": SETTLE_NONCE, "ciphertext": "AAAA"}),
    ] {
        let (status, value) = relay.call("POST", &settle_path, Some(&mac.token), Some(&body));
        assert_eq!((status, code(&value)), (400, "invalid_request"), "{body}");
    }
    // A settle may be sealed under another key_id than the action (the target's current
    // key, section 9.5).
    let other_key = json!({"v": 1, "outcome": "refused", "key_id": "0123456789abcdef",
        "nonce": SETTLE_NONCE, "ciphertext": "AAAA"});
    assert_eq!(
        relay.ok("POST", &settle_path, &mac.token, Some(&other_key))["outcome"],
        "refused"
    );
    // Query forms: since, after, and wait are numbers, wait at most 25; a path id is
    // in its form.
    for path in [
        "/v1/feed?since=x",
        "/v1/feed?wait=26",
        "/v1/feed/actions?after=-1",
        "/v1/feed/actions?wait=26",
        "/v1/feed/actions/short",
        "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw?wait=x",
    ] {
        relay.fails(
            "GET",
            path,
            Some(&phone.token),
            None,
            400,
            "invalid_request",
        );
    }
    for (method, path) in [
        ("POST", "/v1/feed"),
        ("PUT", "/v1/feed/actions"),
        ("DELETE", "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw"),
        ("GET", "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw/settle"),
    ] {
        relay.fails(
            method,
            path,
            Some(&phone.token),
            None,
            405,
            "method_not_allowed",
        );
    }
    relay.fails(
        "GET",
        "/v1/feed/x",
        Some(&phone.token),
        None,
        404,
        "not_found",
    );
}

#[test]
fn feed_bytes_bound_the_feeds_of_a_team_apart_from_questions() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let team = team_of(&mac.token);
    let limits = relay
        .operator(Command::Limits {
            team: team.clone(),
            set: None,
        })
        .unwrap();
    assert_eq!(
        (&limits["feed_bytes"], &limits["feed_actions_per_hour"]),
        (&json!(4_194_304), &json!(60))
    );
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                feed_bytes: Some(1_048_576),
                question_bytes: Some(1_048_576),
                ..Default::default()
            }),
        })
        .unwrap();
    let full = encode_b64(&vec![7; feed::MAX_FEED_BYTES]);
    let devices: Vec<Device> = (0..3)
        .map(|n| add_device(&relay, &mac, &format!("Mac {n}")))
        .collect();
    // One member holds at most its share, three quarters of the team's budget: three
    // full feeds are 768 KiB of 1 MiB, and a fourth of the member is over it.
    assert_eq!(feed::member_share(1_048_576, 50), 786_432);
    for device in &devices {
        assert_eq!(put(&relay, device, 1, &full).0, 200);
    }
    let (status, value) = put(&relay, &mac, 1, &full);
    assert_eq!((status, code(&value)), (403, "feed_limit"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("member_feed_bytes")
    );
    // A member at its share does not block another member: its full feed takes the
    // rest of the team's budget, exactly 1 MiB in all.
    let other = join(&relay, "member", "Ola");
    assert_eq!(put(&relay, &other, 1, &full).0, 200);
    // Then the team's budget is full for everyone.
    let third = join(&relay, "member", "Ewa");
    let (status, value) = put(&relay, &third, 1, &encode_b64(&[1; 1000]));
    assert_eq!((status, code(&value)), (403, "feed_limit"));
    let message = value["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("feed_bytes") && !message.contains("member_"),
        "{message}"
    );
    assert_eq!(
        rows(&audit(&relay), "limit_reached"),
        vec![
            &json!({"limit": "member_feed_bytes"}),
            &json!({"limit": "feed_bytes"})
        ]
    );
    // A device's own old feed does not count against its new one.
    let core = core_of(&relay, &mac);
    pace(&relay, &core);
    assert_eq!(put(&relay, &devices[0], 2, &full).0, 200);
    // The feed budget does not touch the question budget: questions still fit.
    let card = json!({"v": 1, "qid": action_id(1), "to": "member", "expires_at": now_unix() + 300,
        "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": encode_b64(&vec![1; 32_784])});
    assert_eq!(
        relay
            .call("POST", "/v1/questions", Some(&mac.token), Some(&card))
            .0,
        200
    );
    // A smaller feed fits once a feed goes.
    relay.ok("DELETE", "/v1/feed", &devices[2].token, None);
    assert_eq!(put(&relay, &mac, 1, &encode_b64(&[1; 1000])).0, 200);
    // The range of feed_bytes: 1 MiB to 64 MiB.
    for value in [1_048_575, 67_108_865] {
        let error = relay
            .operator(Command::Limits {
                team: team.clone(),
                set: Some(TeamLimitsUpdate {
                    feed_bytes: Some(value),
                    ..Default::default()
                }),
            })
            .unwrap_err();
        assert!(error.message.contains("feed_bytes"), "{error}");
    }
}

#[test]
fn a_feed_list_pages_at_one_mebibyte_of_text() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let full = encode_b64(&vec![7; feed::MAX_FEED_BYTES]);
    let devices: Vec<Device> = (0..4)
        .map(|n| add_device(&relay, &mac, &format!("Mac {n}")))
        .collect();
    for device in &devices {
        assert_eq!(put(&relay, device, 1, &full).0, 200);
    }
    // 349526 characters each: three reach 1 MiB, so the answer stops there.
    let first = feeds(&relay, &phone, 0);
    assert_eq!(first["more"], true);
    assert_eq!(first["change"], 4);
    assert_eq!(
        feed_ids(&first),
        devices[..3].iter().map(|d| d.id).collect::<Vec<_>>()
    );
    assert_eq!(first["present"].as_array().unwrap().len(), 4);
    let last = first["feeds"][2]["change"].as_u64().unwrap();
    let second = feeds(&relay, &phone, last);
    assert_eq!(second["more"], false);
    assert_eq!(feed_ids(&second), vec![devices[3].id]);
    // One feed larger than the cap still goes alone.
    relay.ok("DELETE", "/v1/feed", &devices[1].token, None);
    relay.ok("DELETE", "/v1/feed", &devices[2].token, None);
    relay.ok("DELETE", "/v1/feed", &devices[3].token, None);
    let alone = feeds(&relay, &phone, 0);
    assert_eq!(
        (feed_ids(&alone), &alone["more"]),
        (vec![devices[0].id], &json!(false))
    );
}

/// Run `reads` from a cleared table of feed reads until one run starts and ends in the
/// same minute of the relay clock (the budget is per minute): at most three runs.
fn within_one_minute<T>(core: &Core, mut reads: impl FnMut() -> T) -> T {
    for _ in 0..3 {
        let minute = now_unix() / 60;
        core.feed_reads.lock().unwrap().clear();
        let result = reads();
        if now_unix() / 60 == minute {
            return result;
        }
    }
    panic!("the reads crossed a minute three times");
}

#[test]
fn feed_reads_have_a_text_budget_per_device_and_minute() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let core = core_of(&relay, &mac);
    let full = encode_b64(&vec![7; feed::MAX_FEED_BYTES]);
    let macs: Vec<Device> = (0..3)
        .map(|n| add_device(&relay, &mac, &format!("Mac {n}")))
        .collect();
    for device in &macs {
        assert_eq!(put(&relay, device, 1, &full).0, 200);
    }
    // Each read of everything gives three full feeds (1048578 characters). A read starts
    // only while its reserve of one whole page fits in the 16 MiB of the minute: 15 of
    // them, and the 16th read of the minute is 403 `feed_rate`, not a 429.
    let page = 3 * full.len() as u64;
    let reads = (feed::FEED_READ_TEXT_PER_MINUTE - feed::FEED_READ_RESERVE) / page + 1;
    assert_eq!(reads, 15);
    // The budget is per minute of the relay clock: reads that cross into the next
    // minute are made again from a cleared table, within one minute.
    let (lens, (status, value), waited) = within_one_minute(&core, || {
        let lens: Vec<usize> = (0..reads)
            .map(|_| feed_ids(&feeds(&relay, &phone, 0)).len())
            .collect();
        let refused = relay.call("GET", "/v1/feed?since=0", Some(&phone.token), None);
        // Every feed read of the device waits for the next minute, also one that would
        // give nothing.
        let (waited, _) = relay.call("GET", "/v1/feed?since=3&wait=5", Some(&phone.token), None);
        (lens, refused, waited)
    });
    assert_eq!(lens, vec![3; 15]);
    assert_eq!((status, code(&value)), (403, "feed_rate"), "{value}");
    assert_eq!(waited, 403);
    // Its other calls go on.
    assert_eq!(relay.call("GET", "/v1/me", Some(&phone.token), None).0, 200);
    assert_eq!(
        relay
            .call("GET", "/v1/questions?since=0", Some(&phone.token), None)
            .0,
        200
    );
    // Other devices read as before.
    assert_eq!(feed_ids(&feeds(&relay, &mac, 0)).len(), 3);
    // Reads that go on from the last answer cost only what they give: an empty one
    // nothing, however often.
    for _ in 0..50 {
        assert_eq!(feeds(&relay, &mac, 3)["feeds"], json!([]));
    }
    // No audit row for the budget; the next minute (here, a cleared table) reads again.
    assert!(rows(&audit(&relay), "limit_reached").is_empty());
    core.feed_reads.lock().unwrap().clear();
    assert_eq!(feed_ids(&feeds(&relay, &phone, 0)).len(), 3);
}

#[test]
fn feed_reads_in_parallel_stay_within_the_budget() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let full = encode_b64(&vec![7; feed::MAX_FEED_BYTES]);
    for n in 0..3 {
        let device = add_device(&relay, &mac, &format!("Mac {n}"));
        assert_eq!(put(&relay, &device, 1, &full).0, 200);
    }
    // Forty reads of everything at once, from one device: the reserve before each read
    // and the cap of reads in flight keep the text given within the minute's budget.
    let relay = &relay;
    let core = core_of(relay, &mac);
    let answers: Vec<(u16, Value)> = within_one_minute(&core, || {
        std::thread::scope(|scope| {
            let threads: Vec<_> = (0..40)
                .map(|_| {
                    scope.spawn(|| {
                        relay.call("GET", "/v1/feed?since=0&wait=0", Some(&phone.token), None)
                    })
                })
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        })
    });
    let given: u64 = answers
        .iter()
        .filter(|(status, _)| *status == 200)
        .map(|(_, list)| {
            list["result"]["feeds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feed| feed["ciphertext"].as_str().unwrap().len() as u64)
                .sum::<u64>()
        })
        .sum();
    let passed = answers.iter().filter(|(status, _)| *status == 200).count();
    let refused = answers
        .iter()
        .filter(|(status, value)| *status == 403 && code(value) == "feed_rate")
        .count();
    assert_eq!(passed + refused, 40, "{answers:?}");
    assert!(passed <= 15, "{passed}");
    assert!(given <= feed::FEED_READ_TEXT_PER_MINUTE, "{given}");
    // Every read ended: the device's two seats in flight are free again.
    core.feed_reads.lock().unwrap().clear();
    assert_eq!(feed_ids(&feeds(relay, &phone, 0)).len(), 3);
}

#[test]
fn actions_have_limits_and_expire_then_go() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let pad = add_device(&relay, &mac, "iPad");
    let tablet = add_device(&relay, &mac, "Second iPad");
    let core = core_of(&relay, &mac);
    publish(&relay, &mac, 1);
    // Another member with its own Mac and iPhone.
    let ola_mac = join(&relay, "member", "Ola");
    publish(&relay, &ola_mac, 1);
    let ola_phone = add_device(&relay, &ola_mac, "Ola's iPhone");
    // 10 open actions of one sending device, 15 of one member, 20 of the team.
    for n in 0..10 {
        assert_eq!(post(&relay, &phone, &action_id(n), &mac).0, 200);
    }
    let (status, value) = post(&relay, &phone, &action_id(10), &mac);
    assert_eq!((status, code(&value)), (403, "too_many_actions"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("device_open_feed_actions")
    );
    for n in 10..15 {
        assert_eq!(post(&relay, &pad, &action_id(n), &mac).0, 200);
    }
    let (status, value) = post(&relay, &tablet, &action_id(20), &mac);
    assert_eq!((status, code(&value)), (403, "too_many_actions"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("member_open_feed_actions")
    );
    // A member at its share does not block another member, up to the team's 20.
    for n in 15..20 {
        assert_eq!(post(&relay, &ola_phone, &action_id(n), &ola_mac).0, 200);
    }
    let (status, value) = post(&relay, &ola_phone, &action_id(21), &ola_mac);
    assert_eq!((status, code(&value)), (403, "too_many_actions"));
    let message = value["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("open_feed_actions") && !message.contains("member_"),
        "{message}"
    );
    // Each target lists its own open actions.
    let listed = actions(&relay, &mac, 0);
    assert_eq!(listed["actions"].as_array().unwrap().len(), 15);
    assert_eq!(listed["seq"], 20);
    assert_eq!(
        actions(&relay, &ola_mac, 0)["actions"]
            .as_array()
            .unwrap()
            .len(),
        5
    );

    // An open action past expires_at is expired before maintenance marks it.
    let first = action_id(0);
    relay.edit_vault_live(&format!(
        "UPDATE feed_action SET expires_at = {} WHERE action_id = '{first}'",
        now_unix() - 1
    ));
    let status_path = format!("/v1/feed/actions/{first}");
    let read = relay.ok("GET", &format!("{status_path}?wait=25"), &phone.token, None);
    assert_eq!(read["state"], "expired");
    assert!(read.get("outcome").is_none() && read.get("settle").is_none());
    relay.fails(
        "POST",
        &format!("{status_path}/settle"),
        Some(&mac.token),
        Some(&settle_body("applied", &encode_b64(&[1; 20]))),
        409,
        "action_expired",
    );
    assert!(!action_ids(&actions(&relay, &mac, 0)).contains(&first));
    // A settled one leaves the list too; its retry is the same after the expiry.
    let second = action_id(1);
    let settle = settle_body("stale", &encode_b64(&[2; 20]));
    let settled = relay.ok(
        "POST",
        &format!("/v1/feed/actions/{second}/settle"),
        &mac.token,
        Some(&settle),
    );
    // Maintenance at the expiry of the rest: every action is settled or expired, the
    // device's share is free again, and the retry of a settle still answers the same.
    feed::maintenance(&core, now_unix() + 301).unwrap();
    assert_eq!(actions(&relay, &mac, 0)["actions"], json!([]));
    assert_eq!(
        relay.vault_rows("SELECT state, count(*) FROM feed_action GROUP BY state ORDER BY state"),
        vec![
            (b"expired".to_vec(), b"19".to_vec()),
            (b"settled".to_vec(), b"1".to_vec())
        ]
    );
    assert_eq!(
        relay.ok(
            "POST",
            &format!("/v1/feed/actions/{second}/settle"),
            &mac.token,
            Some(&settle)
        ),
        settled
    );
    // Ten minutes after the end the envelopes go: the action is unknown, and its id
    // stays taken.
    feed::maintenance(&core, now_unix() + 301 + 600).unwrap();
    for id in [&first, &second] {
        relay.fails(
            "GET",
            &format!("/v1/feed/actions/{id}"),
            Some(&phone.token),
            None,
            404,
            "not_found",
        );
        relay.fails(
            "POST",
            &format!("/v1/feed/actions/{id}/settle"),
            Some(&mac.token),
            Some(&settle),
            404,
            "not_found",
        );
    }
    assert_eq!(
        relay.vault_rows("SELECT count(*), sum(length(ciphertext) + length(nonce) + coalesce(length(settle_ciphertext), 0)) FROM feed_action")[0],
        (b"20".to_vec(), b"0".to_vec())
    );
    let (status, value) = post(&relay, &phone, &second, &mac);
    assert_eq!((status, code(&value)), (409, "conflict"));

    // feed_actions_per_hour counts the purged ones too: 20 in the last hour, 15 of the
    // first member. At 24 a member's share is 18.
    let team = team_of(&mac.token);
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                feed_actions_per_hour: Some(24),
                ..Default::default()
            }),
        })
        .unwrap();
    assert_eq!(feed::member_share(24, 50), 18);
    for n in 30..33 {
        assert_eq!(post(&relay, &tablet, &action_id(n), &mac).0, 200);
    }
    let (status, value) = post(&relay, &tablet, &action_id(33), &mac);
    assert_eq!((status, code(&value)), (403, "too_many_actions"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("member_feed_actions_per_hour")
    );
    // The other member still posts, up to the team's limit.
    assert_eq!(post(&relay, &ola_phone, &action_id(34), &ola_mac).0, 200);
    let (status, value) = post(&relay, &ola_phone, &action_id(35), &ola_mac);
    assert_eq!((status, code(&value)), (403, "too_many_actions"));
    let message = value["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("feed_actions_per_hour") && !message.contains("member_"),
        "{message}"
    );
    let limits: Vec<Value> = rows(&audit(&relay), "limit_reached")
        .into_iter()
        .cloned()
        .collect();
    assert_eq!(
        limits,
        vec![
            json!({"limit": "device_open_feed_actions"}),
            json!({"limit": "member_open_feed_actions"}),
            json!({"limit": "open_feed_actions"}),
            json!({"limit": "member_feed_actions_per_hour"}),
            json!({"limit": "feed_actions_per_hour"})
        ]
    );
    // A day after the post every action is gone; the sequence goes on.
    relay.edit_vault_live(&format!(
        "UPDATE feed_action SET created_at = {}",
        now_unix() - feed::ACTION_RETENTION_SECS
    ));
    feed::maintenance(&core, now_unix()).unwrap();
    assert_eq!(
        relay.vault_rows("SELECT count(*), '' FROM feed_action")[0].0,
        b"0".to_vec()
    );
    let posted = relay.ok(
        "POST",
        "/v1/feed/actions",
        &tablet.token,
        Some(&action_body(&second, mac.id, &encode_b64(&[1; 20]))),
    );
    assert_eq!(posted["seq"], 25);
    // No row was written for an expiry or a purge.
    let audit_rows = audit(&relay);
    assert_eq!(rows(&audit_rows, "feed_action_posted").len(), 25);
    assert_eq!(rows(&audit_rows, "feed_action_settled").len(), 1);
}

#[test]
fn feeds_go_with_their_device_and_after_thirty_days() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let mini = add_device(&relay, &mac, "Mac mini");
    let core = core_of(&relay, &mac);
    publish(&relay, &mini, 1);
    publish(&relay, &mac, 1);
    assert_eq!(post(&relay, &phone, &action_id(1), &mini).0, 200);
    assert_eq!(post(&relay, &mini, &action_id(2), &mac).0, 200);
    // Revoking the Mac mini deletes its feed with a new counter value; the actions to it
    // and from it expire.
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", mini.id),
        &mac.token,
        None,
    );
    let list = feeds(&relay, &phone, 0);
    assert_eq!(
        (feed_ids(&list), &list["present"], &list["change"]),
        (vec![mac.id], &json!([mac.id]), &json!(3))
    );
    assert_eq!(
        relay.ok(
            "GET",
            &format!("/v1/feed/actions/{}", action_id(1)),
            &phone.token,
            None
        )["state"],
        "expired"
    );
    assert_eq!(actions(&relay, &mac, 0)["actions"], json!([]));
    assert_eq!(
        rows(&audit(&relay), "feed_deleted"),
        vec![&json!({"device_id": mini.id, "reason": "device_revoked"})]
    );
    // The revoked device cannot read or publish.
    relay.fails(
        "GET",
        "/v1/feed",
        Some(&mini.token),
        None,
        401,
        "unauthenticated",
    );
    // DELETE of the Mac's own feed: change up, present empty, the answer the same twice.
    assert_eq!(post(&relay, &phone, &action_id(3), &mac).0, 200);
    let deleted = relay.ok("DELETE", "/v1/feed", &mac.token, None);
    assert_eq!(deleted, json!({"device_id": mac.id, "change": 4}));
    assert_eq!(relay.ok("DELETE", "/v1/feed", &mac.token, None), deleted);
    assert_eq!(
        feeds(&relay, &phone, 0),
        json!({"change": 4, "more": false, "present": [], "feeds": []})
    );
    assert_eq!(
        relay.ok(
            "GET",
            &format!("/v1/feed/actions/{}", action_id(3)),
            &phone.token,
            None
        )["state"],
        "expired"
    );
    // A feed not updated for 30 days goes at maintenance.
    pace(&relay, &core);
    publish(&relay, &mac, 2);
    relay.edit_vault_live(&format!(
        "UPDATE feed SET updated_at = {}",
        now_unix() - feed::FEED_RETENTION_SECS
    ));
    feed::maintenance(&core, now_unix()).unwrap();
    let list = feeds(&relay, &phone, 0);
    assert_eq!((&list["present"], &list["change"]), (&json!([]), &json!(6)));
    // A member who leaves takes the feeds of its devices.
    let other = join(&relay, "member", "Kim");
    publish(&relay, &other, 1);
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", other.member),
        &mac.token,
        None,
    );
    assert_eq!(
        relay.vault_rows("SELECT count(*), '' FROM feed")[0].0,
        b"0".to_vec()
    );
    assert_eq!(
        rows(&audit(&relay), "feed_deleted").last().unwrap()["reason"],
        "member_revoked"
    );
}

#[test]
fn long_polls_wake_on_feeds_actions_settles_and_deletes() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let core = core_of(&relay, &mac);
    let relay = &relay;

    // The feed list wakes on a PUT; a second feed poll of the same device answers at once.
    std::thread::scope(|scope| {
        let poll = scope
            .spawn(|| timed(|| relay.ok("GET", "/v1/feed?since=0&wait=25", &phone.token, None)));
        std::thread::sleep(Duration::from_millis(500));
        let (second, took) =
            timed(|| relay.ok("GET", "/v1/feed?since=0&wait=25", &phone.token, None));
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert_eq!(second["feeds"], json!([]));
        publish(relay, &mac, 1);
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(feed_ids(&woken), vec![mac.id]);
    });
    // The target's action poll wakes on a post.
    std::thread::scope(|scope| {
        let poll = scope.spawn(|| {
            timed(|| relay.ok("GET", "/v1/feed/actions?after=0&wait=25", &mac.token, None))
        });
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(post(relay, &phone, &action_id(1), &mac).0, 200);
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(action_ids(&woken), vec![action_id(1)]);
    });
    // The sender's status poll wakes on the settle; the feed poll and the action poll of
    // one device do not take each other's place.
    let status = format!("/v1/feed/actions/{}?wait=25", action_id(1));
    std::thread::scope(|scope| {
        let poll = scope.spawn(|| timed(|| relay.ok("GET", &status, &phone.token, None)));
        let listed = scope
            .spawn(|| timed(|| relay.ok("GET", "/v1/feed?since=1&wait=2", &phone.token, None)));
        let mac_actions = scope.spawn(|| {
            timed(|| relay.ok("GET", "/v1/feed/actions?after=1&wait=2", &mac.token, None))
        });
        std::thread::sleep(Duration::from_millis(500));
        relay.ok(
            "POST",
            &format!("/v1/feed/actions/{}/settle", action_id(1)),
            &mac.token,
            Some(&settle_body("applied", &encode_b64(&[1; 20]))),
        );
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(woken["state"], "settled");
        for held in [listed, mac_actions] {
            let (_, took) = held.join().unwrap();
            assert!(took >= Duration::from_millis(1500), "{took:?}");
        }
    });
    // A status poll wakes on an expiry; a feed poll wakes when a feed leaves.
    assert_eq!(post(relay, &phone, &action_id(2), &mac).0, 200);
    let expiring = format!("/v1/feed/actions/{}?wait=25", action_id(2));
    std::thread::scope(|scope| {
        let poll = scope.spawn(|| timed(|| relay.ok("GET", &expiring, &phone.token, None)));
        let gone = scope
            .spawn(|| timed(|| relay.ok("GET", "/v1/feed?since=1&wait=25", &phone.token, None)));
        std::thread::sleep(Duration::from_millis(500));
        feed::maintenance(&core, now_unix() + 301).unwrap();
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(woken["state"], "expired");
        relay.ok("DELETE", "/v1/feed", &mac.token, None);
        let (left, took) = gone.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!((&left["present"], &left["feeds"]), (&json!([]), &json!([])));
    });
    // A counter below `since` (a restored relay) answers at once.
    let (list, took) = timed(|| relay.ok("GET", "/v1/feed?since=99&wait=25", &phone.token, None));
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert_eq!(list["change"], 2);
    let (list, took) =
        timed(|| relay.ok("GET", "/v1/feed/actions?after=99&wait=25", &mac.token, None));
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert_eq!(list["seq"], 2);
    // A revoked device's poll ends with 401.
    let mini = add_device(relay, &mac, "Mac mini");
    std::thread::scope(|scope| {
        let poll =
            scope.spawn(|| relay.call("GET", "/v1/feed?since=2&wait=25", Some(&mini.token), None));
        std::thread::sleep(Duration::from_millis(700));
        relay.ok(
            "DELETE",
            &format!("/v1/devices/{}", mini.id),
            &mac.token,
            None,
        );
        let (status, value) = poll.join().unwrap();
        assert_eq!((status, code(&value)), (401, "unauthenticated"));
    });
}

#[test]
fn feed_polls_have_their_own_lane_and_leave_the_question_polls_their_share() {
    let mut relay = start_with(
        |config| {
            config.limits.max_active = 2;
            config.limits.member_reserve = 1;
            config.limits.question_long_polls = 3;
            config.limits.question_long_polls_per_team = 2;
            config.limits.feed_long_polls = 3;
            config.limits.feed_long_polls_per_team = 2;
        },
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let pad = add_device(&relay, &mac, "iPad");
    publish(&relay, &mac, 1);
    let relay = &relay;
    std::thread::scope(|scope| {
        // Two question polls fill the team's question share of 2, and a feed list poll
        // and the Mac's action poll its feed share of 2, each in its own lane, and no
        // thread of `max_active`.
        let held = [
            (&phone.token, "/v1/questions?since=0&wait=3"),
            (&pad.token, "/v1/questions?since=0&wait=3"),
            (&pad.token, "/v1/feed?since=1&wait=3"),
            (&mac.token, "/v1/feed/actions?after=0&wait=3"),
        ]
        .map(|(token, path)| scope.spawn(move || timed(|| relay.ok("GET", path, token, None)).1));
        std::thread::sleep(Duration::from_millis(700));
        // A third poll of either kind answers at once, as with wait=0.
        for (token, path) in [
            (&phone.token, "/v1/feed?since=1&wait=3"),
            (&mac.token, "/v1/questions?since=0&wait=3"),
        ] {
            let (_, took) = timed(|| relay.ok("GET", path, token, None));
            assert!(took < Duration::from_secs(2), "{path}: {took:?}");
        }
        // Members still get answers: the polls hold no member slot.
        for _ in 0..3 {
            assert_eq!(relay.call("GET", "/v1/me", Some(&mac.token), None).0, 200);
        }
        for (index, poll) in held.into_iter().enumerate() {
            let took = poll.join().unwrap();
            assert!(took >= Duration::from_millis(2500), "{index}: {took:?}");
        }
    });
    // The seats came back.
    let (_, took) = timed(|| relay.ok("GET", "/v1/feed/actions?after=0&wait=1", &mac.token, None));
    assert!(took >= Duration::from_secs(1), "{took:?}");
}

#[test]
fn readers_that_poll_first_leave_the_mac_its_action_seat() {
    let mut relay = start_with(
        |config| config.limits.feed_long_polls_per_team = 2,
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let pad = add_device(&relay, &mac, "iPad");
    publish(&relay, &mac, 1);
    let relay = &relay;
    std::thread::scope(|scope| {
        // The unfriendly order: two readers ask first. One holds the readers' seat, the
        // other answers at once, and the Mac's action poll still holds.
        let reader = scope
            .spawn(|| timed(|| relay.ok("GET", "/v1/feed?since=1&wait=3", &phone.token, None)).1);
        std::thread::sleep(Duration::from_millis(500));
        let (_, took) = timed(|| relay.ok("GET", "/v1/feed?since=1&wait=3", &pad.token, None));
        assert!(took < Duration::from_secs(2), "{took:?}");
        let (_, took) =
            timed(|| relay.ok("GET", "/v1/feed/actions?after=0&wait=2", &mac.token, None));
        assert!(took >= Duration::from_millis(1500), "{took:?}");
        assert!(reader.join().unwrap() >= Duration::from_millis(2500));
    });
}

#[test]
fn one_member_leaves_a_feed_seat_to_each_other_member() {
    let mut relay = start_with(
        |config| config.limits.feed_long_polls_per_team = 4,
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let pad = add_device(&relay, &mac, "iPad");
    let tablet = add_device(&relay, &mac, "Second iPad");
    publish(&relay, &mac, 1);
    // Another member with a Mac that publishes.
    let ola = join(&relay, "member", "Ola");
    publish(&relay, &ola, 1);
    assert_eq!(feed::member_seats(4, 1), 3);
    let relay = &relay;
    std::thread::scope(|scope| {
        // The first member's devices take three of the four seats.
        let held = [
            (&mac.token, "/v1/feed/actions?after=0&wait=3"),
            (&tablet.token, "/v1/feed/actions?after=0&wait=3"),
            (&phone.token, "/v1/feed?since=2&wait=3"),
        ]
        .map(|(token, path)| scope.spawn(move || timed(|| relay.ok("GET", path, token, None)).1));
        std::thread::sleep(Duration::from_millis(600));
        // Its fourth poll answers at once, though the list seats are not all held.
        let (_, took) = timed(|| relay.ok("GET", "/v1/feed?since=2&wait=3", &pad.token, None));
        assert!(took < Duration::from_secs(2), "{took:?}");
        // The other member's Mac still finds its seat.
        let (_, took) =
            timed(|| relay.ok("GET", "/v1/feed/actions?after=0&wait=2", &ola.token, None));
        assert!(took >= Duration::from_millis(1500), "{took:?}");
        for poll in held {
            assert!(poll.join().unwrap() >= Duration::from_millis(2500));
        }
    });
}

/// The body of `POST /v1/connect`, signed by `key` for this relay.
fn connect_body(relay: &TestRelay, team: &str, key: &DeviceKey) -> Value {
    let public_key = key.public_key_b64();
    let signature = key
        .sign(&device::connect_message(
            &relay.config.public_url,
            &public_key,
        ))
        .unwrap();
    json!({"v": 1, "team": team, "device_name": "Rafal's Mac", "public_key": public_key,
        "signature": encode_b64(&signature)})
}

/// A new Connect team of a fresh key and its signed-in Mac.
fn connect(relay: &TestRelay) -> (TeamId, Device) {
    let key = DeviceKey::generate().unwrap();
    let made = relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body(relay, "Rafal", &key)),
    );
    let team: TeamId = serde_json::from_value(made["team_id"].clone()).unwrap();
    let token = relay.sign_in(&team, &key);
    let device = device_of(relay, token, key);
    (team, device)
}

#[test]
fn a_connect_team_has_one_mebibyte_of_feeds_and_its_own_feed_seats() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let hub = relay.hub();
    let core = hub.team(&team).unwrap();
    // The preset: 1 MiB of feeds, not stored, and the file cap grows by it.
    let limits = relay
        .operator(Command::Limits {
            team: team.clone(),
            set: None,
        })
        .unwrap();
    assert_eq!(
        (
            &limits["feed_bytes"],
            &limits["feed_actions_per_hour"],
            &limits["question_bytes"]
        ),
        (&json!(1_048_576), &json!(60), &json!(2_097_152))
    );
    let stored = {
        let conn = rusqlite::Connection::open(relay.config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.query_row(
            "SELECT limits FROM team WHERE id = ?1",
            [team.as_str()],
            |r| r.get::<_, String>(0),
        )
        .unwrap()
    };
    assert!(!stored.contains("feed_"), "{stored}");
    let (_, max) = core.store.pages().unwrap();
    assert_eq!(max, (2 + 1 + 8) * 1_048_576 / 4096);
    // Four full feeds fit, a fifth does not.
    let full = encode_b64(&vec![7; feed::MAX_FEED_BYTES]);
    let macs: Vec<Device> = (0..4)
        .map(|n| add_device(&relay, &mac, &format!("Mac {n}")))
        .collect();
    for device in &macs {
        assert_eq!(put(&relay, device, 1, &full).0, 200);
    }
    let (status, value) = put(&relay, &mac, 1, &full);
    assert_eq!((status, code(&value)), (403, "feed_limit"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("feed_bytes")
    );
    for device in &macs[1..] {
        relay.ok("DELETE", "/v1/feed", &device.token, None);
    }
    assert_eq!(put(&relay, &mac, 1, &encode_b64(&[1; 100])).0, 200);
    // Actions work as in any team.
    assert_eq!(post(&relay, &phone, &action_id(1), &mac).0, 200);
    assert_eq!(action_ids(&actions(&relay, &mac, 0)), vec![action_id(1)]);

    // Two feed polls hold while the team's two question polls hold too; a third feed
    // poll and a third question poll answer at once. The readers come first: one holds
    // the readers' seat, the other answers at once, and the Mac's action poll then
    // still finds its seat.
    let pad = &macs[1];
    let change = feeds(&relay, &phone, 0)["change"].as_u64().unwrap();
    let feed_poll = format!("/v1/feed?since={change}&wait=3");
    let status_poll = format!("/v1/feed/actions/{}?wait=3", action_id(1));
    std::thread::scope(|scope| {
        let relay = &relay;
        let reader = {
            let path = feed_poll.as_str();
            let token = &phone.token;
            scope.spawn(move || timed(|| relay.ok("GET", path, token, None)).1)
        };
        std::thread::sleep(Duration::from_millis(500));
        let (_, took) = timed(|| relay.ok("GET", &feed_poll, &pad.token, None));
        assert!(took < Duration::from_secs(2), "{took:?}");
        let mut held: Vec<_> = [
            (&mac.token, "/v1/questions?since=0&wait=3"),
            (&phone.token, "/v1/questions?since=0&wait=3"),
            (&mac.token, "/v1/feed/actions?after=1&wait=3"),
            // The status poll has a seat of its own, apart from the list poll's.
            (&phone.token, status_poll.as_str()),
        ]
        .into_iter()
        .map(|(token, path)| scope.spawn(move || timed(|| relay.ok("GET", path, token, None)).1))
        .collect();
        held.push(reader);
        std::thread::sleep(Duration::from_millis(700));
        let (_, took) = timed(|| relay.ok("GET", "/v1/questions?since=0&wait=3", &pad.token, None));
        assert!(took < Duration::from_secs(2), "{took:?}");
        for (index, poll) in held.into_iter().enumerate() {
            let took = poll.join().unwrap();
            assert!(took >= Duration::from_millis(2000), "{index}: {took:?}");
        }
    });
    assert_eq!(apassy_relay::server::connect::TEAM_FEED_POLLS, 3);
    // Feed polls have a Connect bound of their own, apart from `connect_long_polls`:
    // with each at 1, one team holds a feed poll and a question poll at once, and
    // another team's poll of either kind answers at once.
    let bound = start_with(
        |config| {
            config.limits.connect_long_polls = 1;
            config.limits.connect_feed_long_polls = 1;
        },
        UpstreamOptions::default(),
    );
    let (_, first) = connect(&bound);
    let (_, second) = connect(&bound);
    std::thread::scope(|scope| {
        let (bound, token) = (&bound, &first.token);
        let held = [
            "/v1/feed/actions?after=0&wait=3",
            "/v1/questions?since=0&wait=3",
        ]
        .map(|path| scope.spawn(move || timed(|| bound.ok("GET", path, token, None)).1));
        std::thread::sleep(Duration::from_millis(500));
        for path in [
            "/v1/feed/actions?after=0&wait=3",
            "/v1/questions?since=0&wait=3",
        ] {
            let (_, took) = timed(|| bound.ok("GET", path, &second.token, None));
            assert!(took < Duration::from_secs(2), "{path}: {took:?}");
        }
        for poll in held {
            assert!(poll.join().unwrap() >= Duration::from_secs(3));
        }
    });
}

#[test]
fn a_team_file_of_schema_5_moves_to_6_and_keeps_a_pre_v6_copy() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let team = team_of(&mac.token);
    let card = json!({"v": 1, "qid": action_id(7), "to": "member", "expires_at": now_unix() + 300,
        "key_id": KEY_ID, "nonce": FEED_NONCE, "ciphertext": encode_b64(&[1; 40])});
    relay.ok("POST", "/v1/questions", &mac.token, Some(&card));
    // A device and a member from before the migration.
    let pad = add_device(&relay, &mac, "iPad");
    let ola = join(&relay, "member", "Ola");
    let ewa = join(&relay, "manager", "Ewa");
    // Make the file what the schema 5 image left: no feed tables, version 5.
    relay.edit_offline(|config| {
        let conn = open_team_file(config, &team);
        conn.execute_batch(
            "DROP TABLE feed_action; DROP TABLE feed;
             ALTER TABLE team DROP COLUMN feed_change; ALTER TABLE team DROP COLUMN feed_action_seq;
             PRAGMA user_version = 5;",
        )
        .unwrap();
    });
    let path = relay.config.team_path(&team);
    let mut backup = path.clone().into_os_string();
    backup.push(".pre-v6");
    let backup = std::path::PathBuf::from(backup);
    // The start above moved it to 6 and kept the copy (mode 0600, encrypted, version 5).
    assert_eq!(
        relay.vault_rows("SELECT user_version, '' FROM pragma_user_version")[0].0,
        b"6"
    );
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (_, key) = apassy_relay::server::Relay::team_vault(&relay.config, &team).unwrap();
    let old = rusqlite::Connection::open(&backup).unwrap();
    old.execute_batch(&format!("PRAGMA key = '{}';", key.expose()))
        .unwrap();
    let (version, tables): (i64, i64) = old
        .query_row(
            "SELECT (SELECT user_version FROM pragma_user_version), \
             (SELECT count(*) FROM sqlite_master WHERE name IN ('feed','feed_action'))",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((version, tables), (5, 0));
    drop(old);
    // The question is still there, and the feed works after a new sign-in.
    let token = relay.sign_in(&team, &mac.key);
    let mac = device_of(&relay, token, mac.key);
    let phone = add_device(&relay, &mac, "iPhone");
    assert_eq!(
        relay.ok("GET", "/v1/questions?since=0", &phone.token, None)["questions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(publish(&relay, &mac, 1)["change"], 1);
    assert_eq!(feed_ids(&feeds(&relay, &phone, 0)), vec![mac.id]);
    // `apassy-relay rollback-check` (OPERATIONS 21.3) names what a rollback would undo,
    // read-only, with the relay up: no revocation yet, only the audit rows written since
    // the migration.
    let entry_of = |config: &apassy_relay::config::RelayConfig, id: &TeamId| -> Value {
        let check = apassy_relay::server::rollback::check(config).unwrap();
        serde_json::to_value(&check)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["team"] == json!(id))
            .unwrap()
            .clone()
    };
    let entry = |relay: &TestRelay, id: &TeamId| entry_of(&relay.config, id);
    let before = entry(&relay, &team);
    assert_eq!(
        (
            &before["pre_v6"],
            &before["schema"],
            &before["revocations"],
            &before["changes"]
        ),
        (&json!(true), &json!(6), &json!([]), &json!([]))
    );
    let lost = before["audit_rows_lost"].as_u64().unwrap();
    assert!(lost > 0, "{before}");
    assert_eq!(
        (&before["clean"], &before["access_rows_lost"]),
        (&json!(true), &json!([]))
    );
    // A feed limit away from the preset is in relay.db, which the old image refuses
    // whole: the team is not clean until it is set back.
    for (feed_bytes, stored) in [(2_097_152, true), (4_194_304, false)] {
        relay
            .operator(Command::Limits {
                team: team.clone(),
                set: Some(TeamLimitsUpdate {
                    feed_bytes: Some(feed_bytes),
                    ..Default::default()
                }),
            })
            .unwrap();
        let entry = entry(&relay, &team);
        assert_eq!(
            (&entry["feed_limits_stored"], &entry["clean"]),
            (&json!(stored), &json!(!stored)),
            "{entry}"
        );
    }
    // A device and a member revoked after the migration come back with the copy: the
    // check names them, by kind, id, and time, and counts the audit rows that go.
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", pad.id),
        &mac.token,
        None,
    );
    relay.ok(
        "PUT",
        &format!("/v1/members/{}/role", ewa.member),
        &mac.token,
        Some(&json!({"role": "member"})),
    );
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", ola.member),
        &mac.token,
        None,
    );
    let copy = std::fs::read(&backup).unwrap();
    let after = entry(&relay, &team);
    let named: Vec<(String, u64)> = after["revocations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|revocation| {
            assert!(revocation["revoked_at"].as_u64().unwrap() >= now_unix() - 60);
            (
                revocation["kind"].as_str().unwrap().to_string(),
                revocation["id"].as_u64().unwrap(),
            )
        })
        .collect();
    // The member's own device went with it.
    assert_eq!(
        named,
        vec![
            ("device".to_string(), pad.id),
            ("device".to_string(), ola.id),
            ("member".to_string(), ola.member)
        ]
    );
    // The demotion is named too, and the lost rows by action.
    assert_eq!(
        after["changes"],
        json!([{"kind": "member_role", "id": ewa.member}])
    );
    assert!(after["audit_rows_lost"].as_u64().unwrap() > lost);
    for action in ["device_revoked", "member_revoked", "member_role_changed"] {
        assert!(
            after["audit_lost"][action].as_u64().unwrap() >= 1,
            "{after}"
        );
        assert!(
            after["access_rows_lost"]
                .as_array()
                .unwrap()
                .contains(&json!(action)),
            "{after}"
        );
    }
    assert_eq!(after["clean"], false);
    assert!(after.get("error").is_none(), "{after}");
    // It only reads: the copy is the same, byte for byte.
    assert_eq!(std::fs::read(&backup).unwrap(), copy);
    // A team made after the migration has no copy: the old image cannot open it.
    let (later, _) = relay.new_team_device("Later", "owner");
    let later = entry(&relay, &team_of(&later));
    assert_eq!(
        (
            &later["pre_v6"],
            &later["schema"],
            &later["revocations"],
            &later["clean"]
        ),
        (&json!(false), &json!(6), &json!([]), &json!(false))
    );
    // The rollback of OPERATIONS 21.3: the copy goes back over the file, which is then
    // version 5 again with its question, and the image of schema 6 moves it once more.
    // The check also runs with the relay stopped, and says the same.
    let named_now = after["revocations"].clone();
    relay.edit_offline(|config| {
        assert_eq!(entry_of(config, &team)["revocations"], named_now);
        let path = config.team_path(&team);
        let mut backup = path.clone().into_os_string();
        backup.push(".pre-v6");
        std::fs::copy(&backup, &path).unwrap();
        let conn = open_team_file(config, &team);
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 5);
    });
    assert_eq!(
        relay.vault_rows("SELECT user_version, '' FROM pragma_user_version")[0].0,
        b"6"
    );
    assert_eq!(
        relay.vault_rows("SELECT count(*), '' FROM question")[0].0,
        b"1"
    );
    assert_eq!(relay.vault_rows("SELECT count(*), '' FROM feed")[0].0, b"0");
    // And the revocations after the migration are undone: the device and the member
    // are live again. This is what 21.3 warns about.
    assert_eq!(
        relay.vault_rows(&format!(
            "SELECT (SELECT revoked_at IS NULL FROM device WHERE id = {}), \
             (SELECT revoked_at IS NULL FROM member WHERE id = {})",
            pad.id, ola.member
        ))[0],
        (b"1".to_vec(), b"1".to_vec())
    );
}

#[test]
fn a_connect_team_deleted_with_its_key_freed_lets_the_key_connect_again() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay);
    // The rollback of OPERATIONS 21.3 for a Connect team made after the deploy: suspend
    // it and delete it with its key freed, with the new image still up.
    relay
        .operator(Command::Suspend { team: team.clone() })
        .unwrap();
    let deleted = relay
        .operator(Command::Delete {
            team: team.clone(),
            free_connect_key: true,
        })
        .unwrap();
    assert_eq!(
        deleted,
        json!({"team": team, "state": "deleted", "connect_key": "freed"})
    );
    // The same device key makes a new team, and the freed row still counts for the
    // daily cap.
    let again = relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body(&relay, "Rafal", &mac.key)),
    );
    assert_ne!(again["team_id"], json!(team));
    let rows = {
        let conn = rusqlite::Connection::open(relay.config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.query_row(
            "SELECT count(*), count(team_id) FROM connect_key",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap()
    };
    assert_eq!(rows, (2, 1));
    let audit = relay.relay_audit();
    assert!(
        audit
            .iter()
            .any(|(_, action, detail)| action == "team_deleted"
                && detail.contains("\"connect_key_freed\":true")),
        "{audit:?}"
    );
    // Without the flag the key stays used.
    let second: TeamId = serde_json::from_value(again["team_id"].clone()).unwrap();
    relay
        .operator(Command::Suspend {
            team: second.clone(),
        })
        .unwrap();
    relay
        .operator(Command::Delete {
            team: second,
            free_connect_key: false,
        })
        .unwrap();
    relay.fails(
        "POST",
        "/v1/connect",
        None,
        Some(&connect_body(&relay, "Rafal", &mac.key)),
        409,
        "connect_key_used",
    );
    // An operator team has no connect key: the flag is refused, and the team stays.
    let mut relay = relay;
    let owner = personal_team(&mut relay);
    let operator_team = team_of(&owner.token);
    relay
        .operator(Command::Suspend {
            team: operator_team.clone(),
        })
        .unwrap();
    let refused = relay
        .operator(Command::Delete {
            team: operator_team.clone(),
            free_connect_key: true,
        })
        .unwrap_err();
    assert!(refused.message.contains("Connect team"), "{refused}");
    assert!(
        relay
            .hub()
            .directory
            .team(&operator_team)
            .unwrap()
            .is_some()
    );
}

#[test]
fn deletion_between_polls_returns_the_absent_publisher_immediately() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let made = publish(&relay, &mac, 1);
    let since = made["change"].as_u64().unwrap();
    relay.ok("DELETE", "/v1/feed", &mac.token, None);
    let (list, took) = timed(|| {
        relay.ok(
            "GET",
            &format!("/v1/feed?since={since}&wait=25"),
            &phone.token,
            None,
        )
    });
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert_eq!(list["present"], json!([]));
    assert!(list["change"].as_u64().unwrap() > since);
}
