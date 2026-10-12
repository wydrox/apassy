//! SPEC25 questions through the relay: the vector envelopes, routing, the asker's own
//! endpoints, limits, expiry and retention, the long polls and their lane, the push
//! trigger with a mock Worker, separation between teams, and the audit.

#[path = "common/relay.rs"]
mod relay;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy_relay::config::{PushConfig, UpstreamOptions};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::encode_b64;
use apassy_relay::now_unix;
use apassy_relay::secret::SecretString;
use apassy_relay::server::directory::TeamLimitsUpdate;
use apassy_relay::server::operator::Command;
use apassy_relay::server::questions;
use relay::{TestRelay, start, start_with, team_of};
use serde_json::{Value, json};

// The test vectors of `docs/contracts/relay-questions-v1.md` (core), section 20.
const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
const KEY_ID: &str = "630dcd2966c43366";
const CARD_NONCE: &str = "AAECAwQFBgcICQoL";
const ANSWER_NONCE: &str = "EBESExQVFhcYGRob";
const SETTLE_NONCE: &str = "ICEiIyQlJicoKSor";
const TOPIC: &str = "com.wydrox.apassy.companion";
const PUSH_SECRET: &str = "push-secret-for-tests-0123456789abcdef0123";

const CARD_CT_HEX: &str = concat!(
    "f2d97e2213268962c6ea5bd1a23f61288e19ddd10218ddc883f85ea404b2d477def55e84c43293f9445913aa47aef401",
    "1ae1df1d9e4d9aa13088bb30f57afde5185585a9d47201dda5242f91201fea95f7ea2202095b910c6c64933abc5f2e9d",
    "23bf0196d5e305b9d038b1d8cdfa97d09b007445a57f238a2a0c40ba1d60de32835cf28a9003ef5c79234f4a001e194f",
    "da53bd092906a87c08c39603972f950f0881b8d88c76a7d2bb5c4a3206d68a6eaa769c6874371b60bc7ac3f20852f132",
    "f5653ce00e906e71496a1f55ef281d6040f4e74e13618d7b344445c2897b08984e1e2692edc761c2e0d82732c668bbff",
    "8931df900e0fc3fd93f303b495df2d00e6ff74d60725dbf1e8f8a51c48b59fbab440e585539629fb5744514e5432f009",
    "7360125db91fad7922072ba7e46729661b4d8997ddb612f737c872a6020d0bde2233e7626b3de5f7808253ac3be6e0d3",
    "1dc7aa6282180fbb043a20f46eb42b180b1a695f1c13360fb03ddfbb58c46063d173951a4982f4a0913f3339535b78f7",
    "854537a69637511d5e2c226e30d37f159a0ec897fc28d4a6ea749989f37b590cf7f6a30caf27de4e2802d14b1db0dc0d",
    "e3db79e82ccd1e76f2572f82af25e365317e42bffd3e97a056e727352a699d6350e12f9ceb2b7ddb169decdad203236f",
    "f12350de3bab743232a4dd3f5685f47cc72981327ed03cc4323d575371249f8418739fe2eee8a3fc7ceda1da72d0a62d",
    "8a741b920ad04be913f15fae7d572703194d4cba17f66443a28362038e58c0dff69e4307fbb11072f42b14735d691cf1",
    "ff6c91e24f9f65d451fabe07796ea5299e93c7586b6e3280d03d436c14146585f0b9e3218f4a52c29ed0798582b55c22",
    "aa91d40bd1ec73bfc38c2bd3407fd7c8ccc8e0e4575223d1eccdb3c4f760df7b7122667449f39c38c89422c0dc468bf2",
    "a0665307af7d388d734d4656b83983446820fedce1131846d821fe09ca81baaa8a80aae9c92d925bf07de3974e62c60d",
    "4ad08adc9b7d4a1f700915d1ea0b967ea64c84bc4780add5347e5153825db90afa9c02f3cbaaa126dbc3fb97c2ba8ed9",
    "2c4cc0d241e23d6fc59b78b4d59e36d0882f110acdbdb75e026c9df55fc80577c8726e7e012d391ede22c42ce32ba587",
    "8926adf56d7cab49b150a201d9fa07f545dd5152181821c7e17100ff04cb5f46b3d3e7a7b675e9c4c6d63198562b627b",
    "8392a4ec03ca59e2f19396cd8817eb18109903c1fb0afd39b6c4462405490fcf931f1053ecf73483e7b28c3ac615f63f",
    "4fab000a6259259a98d219dde6c4e8715c1e14eebd130f6e1f22ee269ef7f6c1acac47d244597baeb538b9e97c83438b",
    "b4f1eca9a36ebef614c3b6cd86f4b4868b9a6c81d78d3dce172a591b5bba86b4245b79040a3cb37079e995f5e8b83b11",
    "13c1bca6576f113d645d1136accc2bff64bada12aad3eb950834f63caa3fff01c55952edd9ac6f374f86eded6cc93825",
    "c114418705f39324695c99b3d7e9914484015fd789ccc85359d662fdddf55cc373592d345335c277af91b1f2bb758f65",
    "2496ca22d87b75118bb17eafb0885e9759633a2cb69ccaa58a3890a212cabd334cb8a64023ed808b856f3e612507ce64",
    "a66b",
);

const ANSWER_CT_HEX: &str = concat!(
    "25e833253c28ea4b6aaf5741e389da3e3d0f9a1fd7aea605e7fcc66c9dced1adcefff20efba899be0cb7c1ceb3cb32bf",
    "206d626c9953465defbab3b89e8d1ff8327cf7ec21c7ec2787484140c0b291f117db2557de3967a5f61be0d5bcf26128",
    "d2d20e2eda7de6910266abba48c80fb399588f148fb234ca61707674c2ca04549304e6b80a7a418b40b0a3e798143e95",
    "4cf74dafda3441b8e0a99ded218ce4f533dcfdffac93b4114b8dd6b5a4bffeb094da742ad1e5e6a8821c796b3c594c23",
    "683028ef1c55d1b464cce313780013a5fecc377db92cc3bfcd5469686e75b04a01e226f674b06b3e519ad72f975b5aee",
    "88e3e4a8c5e8d3edca1a4b57c3d1627e17b8a7630579bf1b458e7660749530e2b713d036f4b7b363d0935a5b11548197",
    "5d54a9351cda0cba86e3d202a94a984f4dd2bedf7d690c38ed4a3c058e95c8456e92c408d061d0062ede9e7299e4a0e1",
    "57b9fc13d09fd25e76bfa0b456b99d17885a8f5d6583b02cbe06327ca1eb93ab08de920c3f69fd1aa8d635952bfa3b56",
    "1c30",
);

const SETTLE_CT_HEX: &str = concat!(
    "08c5fe5e2bded018eaacc9ea731de0f33c0711044305ef3ce38e4cc5cdc9a95931c2f021ee37f50891bb8e780d94417a",
    "e76d1515fc3c76f7ca24e0c3472df717faea79cbe8b60ad589fe1467835b1e42cf7dad045cca0dc97bf303a57429ee4b",
    "c00a4175fd49e86be86a99b517e0fba583d6af00b7fc7d6a983f524c793c91a2f1a27695d2a61fb5a3dfb82ba1b0cc87",
    "f5cb65f8b240c5048e9db9946699d9cf33b2e300c919917c85e02c39b7da8a4cbd1d46065030eb6a8df582bea0f277bf",
    "ec618de93fe7d74fd233a2f8646fb5f066a9390178f5251b3cc003cfec",
);

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

/// A synthetic qid: 16 bytes of `n`.
fn qid(n: u8) -> String {
    encode_b64(&[n; 16])
}

/// One signed-in device: its access token, its id, and its member.
#[derive(Clone)]
struct Device {
    token: String,
    id: u64,
    member: u64,
}

fn device_of(relay: &TestRelay, token: String) -> Device {
    let me = relay.ok("GET", "/v1/me", &token, None);
    Device {
        id: me["device_id"].as_u64().expect("device id"),
        member: me["member_id"].as_u64().expect("member id"),
        token,
    }
}

/// A new team through a team code: the owner's Mac, named "Owner device".
fn personal_team(relay: &mut TestRelay) -> Device {
    let (token, _key) = relay.new_team_device("Personal", "owner");
    relay.switch_team(&token);
    device_of(relay, token)
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
    device_of(relay, token)
}

/// A new member of the current team with one device.
fn join(relay: &TestRelay, role: &str, name: &str) -> Device {
    let (_, token, _) = relay.join_device(role, name);
    device_of(relay, token)
}

fn card(qid: &str, to: &str, expires_at: u64, ciphertext: &str) -> Value {
    json!({"v": 1, "qid": qid, "to": to, "expires_at": expires_at, "key_id": KEY_ID,
        "nonce": CARD_NONCE, "ciphertext": ciphertext})
}

fn sealed(nonce: &str, ciphertext: &str) -> Value {
    json!({"v": 1, "key_id": KEY_ID, "nonce": nonce, "ciphertext": ciphertext})
}

/// Posts a question that expires in 300 s and expects 200.
fn ask(relay: &TestRelay, by: &Device, qid: &str, to: &str) -> Value {
    relay.ok(
        "POST",
        "/v1/questions",
        &by.token,
        Some(&card(qid, to, now_unix() + 300, &encode_b64(&[9; 40]))),
    )
}

fn answer(relay: &TestRelay, by: &Device, qid: &str) -> (u16, Value) {
    relay.call(
        "POST",
        &format!("/v1/questions/{qid}/answers"),
        Some(&by.token),
        Some(&sealed(ANSWER_NONCE, &encode_b64(&[5; 30]))),
    )
}

fn list(relay: &TestRelay, by: &Device, since: u64) -> Value {
    relay.ok(
        "GET",
        &format!("/v1/questions?since={since}"),
        &by.token,
        None,
    )
}

fn qids(list: &Value) -> Vec<String> {
    list["questions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["qid"].as_str().unwrap().to_string())
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

#[test]
fn the_vector_envelopes_go_through_post_list_answer_and_settle() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let mini = add_device(&relay, &mac, "Mac mini");
    let phone = add_device(&relay, &mac, "iPhone");
    let expires_at = now_unix() + 300;
    let card_ct = b64(CARD_CT_HEX);
    let body = card(QID, "member", expires_at, &card_ct);
    let before = now_unix();
    let posted = relay.ok("POST", "/v1/questions", &mac.token, Some(&body));
    assert_eq!(posted["qid"], QID);
    assert_eq!(posted["seq"], 1);
    assert_eq!(posted["expires_at"], expires_at);
    let created_at = posted["created_at"].as_u64().unwrap();
    assert!((before..=now_unix()).contains(&created_at));
    // A retry of a post that landed.
    relay.fails(
        "POST",
        "/v1/questions",
        Some(&mac.token),
        Some(&body),
        409,
        "conflict",
    );

    // The asker does not list its own question; the two other devices do.
    let own = list(&relay, &mac, 0);
    assert_eq!(own, json!({"seq": 1, "questions": []}));
    for device in [&mini, &phone] {
        assert_eq!(
            list(&relay, device, 0),
            json!({"seq": 1, "questions": [{
                "qid": QID, "seq": 1, "to": "member", "from_device_id": mac.id,
                "from_device_name": "Owner device", "key_id": KEY_ID, "nonce": CARD_NONCE,
                "ciphertext": card_ct, "created_at": created_at, "expires_at": expires_at,
                "state": "open"}]})
        );
        assert_eq!(list(&relay, device, 1)["questions"], json!([]));
    }

    // Two answers; the asker reads them in arrival order with the relay's stamp.
    let answer_ct = b64(ANSWER_CT_HEX);
    let path = format!("/v1/questions/{QID}/answers");
    let first = relay.ok(
        "POST",
        &path,
        &phone.token,
        Some(&sealed(ANSWER_NONCE, &answer_ct)),
    );
    let second = relay.ok(
        "POST",
        &path,
        &mini.token,
        Some(&sealed(ANSWER_NONCE, &answer_ct)),
    );
    let (first_id, second_id) = (
        first["id"].as_u64().unwrap(),
        second["id"].as_u64().unwrap(),
    );
    assert!(second_id > first_id);
    let read = relay.ok("GET", &format!("{path}?after=0"), &mac.token, None);
    assert_eq!(read["state"], "open");
    assert_eq!(read["expires_at"], expires_at);
    assert_eq!(
        read["answers"][0],
        json!({"id": first_id, "device_id": phone.id, "member_id": mac.member, "role": "owner",
            "key_id": KEY_ID, "nonce": ANSWER_NONCE, "ciphertext": answer_ct, "at": first["at"]})
    );
    assert_eq!(read["answers"][1]["device_id"], mini.id);
    assert_eq!(read["answers"].as_array().unwrap().len(), 2);
    let later = relay.ok("GET", &format!("{path}?after={first_id}"), &mac.token, None);
    assert_eq!(later["answers"].as_array().unwrap().len(), 1);
    assert_eq!(later["answers"][0]["id"], second_id);

    // The settle; a retry answers the same, another envelope is refused.
    let settle_path = format!("/v1/questions/{QID}/settle");
    let settle_ct = b64(SETTLE_CT_HEX);
    let settled = relay.ok(
        "POST",
        &settle_path,
        &mac.token,
        Some(&sealed(SETTLE_NONCE, &settle_ct)),
    );
    assert_eq!(settled["qid"], QID);
    assert_eq!(settled["state"], "settled");
    let settled_at = settled["settled_at"].as_u64().unwrap();
    assert_eq!(
        relay.ok(
            "POST",
            &settle_path,
            &mac.token,
            Some(&sealed(SETTLE_NONCE, &settle_ct))
        ),
        settled
    );
    relay.fails(
        "POST",
        &settle_path,
        Some(&mac.token),
        Some(&sealed(CARD_NONCE, &settle_ct)),
        409,
        "question_settled",
    );
    // Both devices see the settle once, with the next sequence value.
    for device in [&mini, &phone] {
        let after = list(&relay, device, 1);
        assert_eq!(after["seq"], 2);
        let question = &after["questions"][0];
        assert_eq!(question["seq"], 2);
        assert_eq!(question["state"], "settled");
        assert_eq!(question["settled_at"], settled_at);
        assert_eq!(
            question["settle"],
            json!({"key_id": KEY_ID, "nonce": SETTLE_NONCE, "ciphertext": settle_ct})
        );
        assert_eq!(list(&relay, device, 2)["questions"], json!([]));
    }
    // A late answer.
    let (status, late) = answer(&relay, &phone, QID);
    assert_eq!((status, code(&late)), (409, "question_settled"));
    assert_eq!(relay.ok("GET", &path, &mac.token, None)["state"], "settled");

    // The audit holds device ids and counts only.
    let rows_now = audit(&relay);
    assert_eq!(
        rows(&rows_now, "question_posted"),
        vec![&json!({"device_id": mac.id, "to_approvers": false, "routed": 2})]
    );
    assert_eq!(
        rows(&rows_now, "question_answered"),
        vec![
            &json!({"device_id": phone.id, "asker_device_id": mac.id}),
            &json!({"device_id": mini.id, "asker_device_id": mac.id}),
        ]
    );
    assert_eq!(
        rows(&rows_now, "question_settled"),
        vec![&json!({"device_id": mac.id})]
    );
    assert_eq!(
        rows(&rows_now, "question_refused"),
        vec![&json!({"reason": "settled", "device_id": mac.id})]
    );
    let text = format!("{rows_now:?}");
    for secret in [
        QID,
        KEY_ID,
        CARD_NONCE,
        ANSWER_NONCE,
        SETTLE_NONCE,
        &card_ct[..40],
        &answer_ct[..40],
        &settle_ct[..40],
    ] {
        assert!(!text.contains(secret), "the audit holds {secret}");
    }
}

#[test]
fn routing_follows_the_member_and_the_approvers() {
    // `to: "approvers"` needs the relay flag until shared vaults.
    let mut relay = start_with(
        |config| config.questions_to_approvers = true,
        UpstreamOptions::default(),
    );
    let owner = personal_team(&mut relay);
    let alice = join(&relay, "member", "alice");
    let alice_phone = add_device(&relay, &alice, "Alice iPhone");
    let maria = join(&relay, "manager", "maria");
    let bob = join(&relay, "member", "bob");

    // `member`: the asking member's other devices only.
    let mine = qid(1);
    ask(&relay, &alice, &mine, "member");
    for other in [&owner, &maria, &bob, &alice] {
        assert_eq!(qids(&list(&relay, other, 0)), Vec::<String>::new());
    }
    assert_eq!(qids(&list(&relay, &alice_phone, 0)), vec![mine.clone()]);
    for other in [&owner, &maria, &bob, &alice] {
        let (status, refused) = answer(&relay, other, &mine);
        assert_eq!((status, code(&refused)), (403, "not_routed"));
    }
    assert_eq!(answer(&relay, &alice_phone, &mine).0, 200);

    // `approvers`: also the owners' and the managers' devices, not other members'.
    let team = qid(2);
    ask(&relay, &alice, &team, "approvers");
    assert_eq!(qids(&list(&relay, &owner, 0)), vec![team.clone()]);
    assert_eq!(qids(&list(&relay, &maria, 0)), vec![team.clone()]);
    assert_eq!(list(&relay, &maria, 0)["questions"][0]["to"], "approvers");
    assert_eq!(qids(&list(&relay, &bob, 0)), Vec::<String>::new());
    assert_eq!(
        qids(&list(&relay, &alice_phone, 0)),
        vec![mine.clone(), team.clone()]
    );
    assert_eq!(answer(&relay, &owner, &team).0, 200);
    assert_eq!(answer(&relay, &maria, &team).0, 200);
    let (status, refused) = answer(&relay, &bob, &team);
    assert_eq!((status, code(&refused)), (403, "not_routed"));
    let (status, refused) = answer(&relay, &alice, &team);
    assert_eq!((status, code(&refused)), (403, "not_routed"));
    let stamped = relay.ok(
        "GET",
        &format!("/v1/questions/{team}/answers"),
        &alice.token,
        None,
    );
    let roles: Vec<(u64, String)> = stamped["answers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["member_id"].as_u64().unwrap(),
                a["role"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        roles,
        vec![
            (owner.member, "owner".to_string()),
            (maria.member, "manager".to_string())
        ]
    );

    // A manager who becomes a member stops seeing approvers' questions at once.
    relay.ok(
        "PUT",
        &format!("/v1/members/{}/role", maria.member),
        &owner.token,
        Some(&json!({"role": "member"})),
    );
    assert_eq!(qids(&list(&relay, &maria, 0)), Vec::<String>::new());
    let (status, refused) = answer(&relay, &maria, &team);
    assert_eq!((status, code(&refused)), (403, "not_routed"));

    // A device removed after the post gets 401.
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", alice_phone.id),
        &owner.token,
        None,
    );
    relay.fails(
        "GET",
        "/v1/questions?since=0",
        Some(&alice_phone.token),
        None,
        401,
        "unauthenticated",
    );
    let refusals = audit(&relay);
    // The first refusal of the ten seconds, with the device that was refused.
    assert!(
        rows(&refusals, "question_refused")
            .contains(&&json!({"reason": "not_routed", "device_id": owner.id}))
    );
    assert_eq!(
        rows(&refusals, "question_posted")[1],
        &json!({"device_id": alice.id, "to_approvers": true, "routed": 3})
    );
}

#[test]
fn only_the_asker_reads_answers_and_settles_and_member_tokens_are_refused() {
    let mut relay = start(UpstreamOptions::default());
    // The owner token of `init` is a member token without a device.
    let member_token = relay.owner_token.clone();
    for (method, path) in [
        ("POST", "/v1/questions".to_string()),
        ("GET", "/v1/questions".to_string()),
        ("POST", format!("/v1/questions/{QID}/answers")),
        ("GET", format!("/v1/questions/{QID}/answers")),
        ("POST", format!("/v1/questions/{QID}/settle")),
        ("PUT", "/v1/push/token".to_string()),
        ("DELETE", "/v1/push/token".to_string()),
    ] {
        let body = match method {
            "POST" | "PUT" => Some(json!({})),
            _ => None,
        };
        let (status, value) = relay.call(method, &path, Some(&member_token), body.as_ref());
        assert_eq!(
            (status, code(&value)),
            (401, "unauthenticated"),
            "{method} {path}"
        );
    }
    let mac = personal_team(&mut relay);
    let mini = add_device(&relay, &mac, "Mac mini");
    ask(&relay, &mac, QID, "member");
    relay.fails(
        "GET",
        &format!("/v1/questions/{QID}/answers"),
        Some(&mini.token),
        None,
        404,
        "not_found",
    );
    relay.fails(
        "POST",
        &format!("/v1/questions/{QID}/settle"),
        Some(&mini.token),
        Some(&sealed(SETTLE_NONCE, &encode_b64(&[1; 20]))),
        404,
        "not_found",
    );
    // An unknown qid.
    let unknown = qid(7);
    let (status, value) = answer(&relay, &mini, &unknown);
    assert_eq!((status, code(&value)), (404, "not_found"));
    relay.fails(
        "GET",
        &format!("/v1/questions/{unknown}/answers"),
        Some(&mac.token),
        None,
        404,
        "not_found",
    );
    // A qid out of its form in the path.
    relay.fails(
        "GET",
        "/v1/questions/short/answers",
        Some(&mac.token),
        None,
        400,
        "invalid_request",
    );
}

#[test]
fn limits_sizes_and_forms() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let team = team_of(&mac.token);
    let now = now_unix();
    let post = |body: &Value| relay.call("POST", "/v1/questions", Some(&mac.token), Some(body));

    // Forms: 400. Sizes: 413. Nothing is stored.
    let good = encode_b64(&[1; 40]);
    for (bad, why) in [
        (
            json!({"v": 2, "qid": qid(1), "to": "member", "expires_at": now + 300, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": good}),
            "v",
        ),
        (
            json!({"v": 1, "qid": "short", "to": "member", "expires_at": now + 300, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": good}),
            "qid",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "everyone", "expires_at": now + 300, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": good}),
            "to",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "member", "expires_at": now + 10, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": good}),
            "now + 10",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "member", "expires_at": now + 650, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": good}),
            "now + 650",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "member", "expires_at": now + 300, "key_id": "630DCD2966C43366", "nonce": CARD_NONCE, "ciphertext": good}),
            "key_id",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "member", "expires_at": now + 300, "key_id": KEY_ID, "nonce": "AAEC", "ciphertext": good}),
            "nonce",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "member", "expires_at": now + 300, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": ""}),
            "empty",
        ),
        (
            json!({"v": 1, "qid": qid(1), "to": "member", "expires_at": now + 300, "key_id": KEY_ID, "nonce": CARD_NONCE, "ciphertext": good, "extra": 1}),
            "unknown field",
        ),
    ] {
        let (status, value) = post(&bad);
        assert_eq!((status, code(&value)), (400, "invalid_request"), "{why}");
    }
    let (status, value) = post(&card(
        &qid(1),
        "member",
        now + 300,
        &encode_b64(&vec![1; 32_785]),
    ));
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    assert_eq!(list(&relay, &phone, 0), json!({"seq": 0, "questions": []}));
    relay.ok(
        "POST",
        "/v1/questions",
        &mac.token,
        Some(&card(
            &qid(1),
            "member",
            now_unix() + 300,
            &encode_b64(&vec![1; 32_784]),
        )),
    );

    // Answers: the size, the key id, and three per device.
    let path = format!("/v1/questions/{}/answers", qid(1));
    let send = |ciphertext: Vec<u8>, key_id: &str| {
        relay.call(
            "POST",
            &path,
            Some(&phone.token),
            Some(&json!({"v": 1, "key_id": key_id, "nonce": ANSWER_NONCE, "ciphertext": encode_b64(&ciphertext)})),
        )
    };
    let (status, value) = send(vec![2; 8_209], KEY_ID);
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    // The size comes before the qid is looked up.
    let (status, value) = relay.call(
        "POST",
        &format!("/v1/questions/{}/answers", qid(9)),
        Some(&phone.token),
        Some(&sealed(ANSWER_NONCE, &encode_b64(&[2; 8_209]))),
    );
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    let (status, value) = send(vec![2; 20], "0000000000000000");
    assert_eq!((status, code(&value)), (400, "invalid_request"));
    for _ in 0..3 {
        assert_eq!(send(vec![2; 8_208], KEY_ID).0, 200);
    }
    let (status, value) = send(vec![2; 20], KEY_ID);
    assert_eq!((status, code(&value)), (403, "too_many_answers"));

    // The settle: its size and the key id.
    let settle = format!("/v1/questions/{}/settle", qid(1));
    let (status, value) = relay.call(
        "POST",
        &settle,
        Some(&mac.token),
        Some(&sealed(SETTLE_NONCE, &encode_b64(&[3; 1_041]))),
    );
    assert_eq!((status, code(&value)), (413, "payload_too_large"));
    let (status, value) = relay.call(
        "POST",
        &settle,
        Some(&mac.token),
        Some(&json!({"v": 1, "key_id": "0000000000000000", "nonce": SETTLE_NONCE, "ciphertext": encode_b64(&[3; 20])})),
    );
    assert_eq!((status, code(&value)), (400, "invalid_request"));
    relay.ok(
        "POST",
        &settle,
        &mac.token,
        Some(&sealed(SETTLE_NONCE, &encode_b64(&[3; 1_040]))),
    );

    // Open questions: 10 of one device, 15 of one member, 20 of the team. Each refusal
    // names its limit, with one `limit_reached` row per limit in ten seconds.
    let bob = join(&relay, "member", "bob");
    let refused_with = |by: &Device, n: u8, limit: &str| {
        let (status, value) = relay.call(
            "POST",
            "/v1/questions",
            Some(&by.token),
            Some(&card(&qid(n), "member", now_unix() + 300, &good)),
        );
        assert_eq!(
            (status, code(&value)),
            (403, "too_many_questions"),
            "{limit}"
        );
        let message = value["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("team's {limit} limit")),
            "{message}"
        );
    };
    for n in 2..=11 {
        ask(&relay, &mac, &qid(n), "member");
    }
    refused_with(&mac, 12, "device_open_questions");
    refused_with(&mac, 12, "device_open_questions");
    // Another device of the same member has its own share, up to the member's.
    for n in 12..=16 {
        ask(&relay, &phone, &qid(n), "member");
    }
    refused_with(&phone, 17, "member_open_questions");
    // Another member fills the team.
    for n in 17..=21 {
        ask(&relay, &bob, &qid(n), "member");
    }
    refused_with(&bob, 22, "open_questions");
    let reached = audit(&relay);
    assert_eq!(
        rows(&reached, "limit_reached"),
        vec![
            &json!({"limit": "device_open_questions"}),
            &json!({"limit": "member_open_questions"}),
            &json!({"limit": "open_questions"}),
        ]
    );
    assert!(
        rows(&reached, "question_refused")
            .contains(&&json!({"reason": "too_many_questions", "device_id": mac.id}))
    );

    // The operator raises the open limits and sets the hourly one: 21 questions of
    // this hour so far.
    let limits = relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                open_questions: Some(1000),
                member_open_questions: Some(1000),
                device_open_questions: Some(1000),
                questions_per_hour: Some(25),
                ..Default::default()
            }),
        })
        .unwrap();
    assert_eq!(limits["open_questions"], 1000);
    assert_eq!(limits["questions_per_hour"], 25);
    assert_eq!(limits["device_questions_per_hour"], 150);
    for n in 22..=25 {
        ask(&relay, &mac, &qid(n), "member");
    }
    refused_with(&mac, 26, "questions_per_hour");
    // Hourly shares: the asking Mac has 15 of this hour, its member 20.
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                questions_per_hour: Some(1000),
                device_questions_per_hour: Some(16),
                member_questions_per_hour: Some(22),
                ..Default::default()
            }),
        })
        .unwrap();
    ask(&relay, &mac, &qid(26), "member");
    refused_with(&mac, 27, "device_questions_per_hour");
    ask(&relay, &phone, &qid(27), "member");
    refused_with(&phone, 28, "member_questions_per_hour");
    // Another member still asks.
    ask(&relay, &bob, &qid(28), "member");
    let infos = relay.operator(Command::Teams).unwrap();
    let info = infos
        .as_array()
        .unwrap()
        .iter()
        .find(|info| info["id"] == json!(team))
        .unwrap();
    assert_eq!(info["open_questions"], 27);
    assert_eq!(info["push_tokens"], 0);
}

#[test]
fn questions_expire_with_a_new_seq_and_go_after_a_day() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let core = relay.hub().team(&team_of(&mac.token)).unwrap();
    let (first, second) = (qid(1), qid(2));
    ask(&relay, &mac, &first, "member");
    ask(&relay, &mac, &second, "member");
    // An open question past `expires_at` is expired before maintenance marks it.
    relay.edit_vault_live(&format!(
        "UPDATE question SET expires_at = {} WHERE qid = '{second}'",
        now_unix() - 1
    ));
    let (status, value) = answer(&relay, &phone, &second);
    assert_eq!((status, code(&value)), (409, "question_expired"));
    relay.fails(
        "POST",
        &format!("/v1/questions/{second}/settle"),
        Some(&mac.token),
        Some(&sealed(SETTLE_NONCE, &encode_b64(&[1; 20]))),
        409,
        "question_expired",
    );
    let read = relay.ok(
        "GET",
        &format!("/v1/questions/{second}/answers?wait=25"),
        &mac.token,
        None,
    );
    assert_eq!(read["state"], "expired");
    questions::maintenance(&core, now_unix()).unwrap();
    let changed = list(&relay, &phone, 2);
    assert_eq!(qids(&changed), vec![second.clone()]);
    assert_eq!(changed["questions"][0]["state"], "expired");
    assert_eq!(changed["questions"][0]["seq"], 3);
    assert_eq!(list(&relay, &phone, 3)["questions"], json!([]));

    // The first one at its expiry.
    questions::maintenance(&core, now_unix() + 301).unwrap();
    let (status, value) = answer(&relay, &phone, &first);
    assert_eq!((status, code(&value)), (409, "question_expired"));
    assert_eq!(list(&relay, &phone, 3)["questions"][0]["seq"], 4);
    let expired = audit(&relay);
    assert_eq!(
        rows(&expired, "question_expired"),
        vec![&json!({"device_id": mac.id}), &json!({"device_id": mac.id})]
    );

    // A day after the post every question is gone, with its answers; the sequence goes on.
    let open = qid(3);
    ask(&relay, &mac, &open, "member");
    assert_eq!(answer(&relay, &phone, &open).0, 200);
    relay.edit_vault_live(&format!(
        "UPDATE question SET created_at = {}",
        now_unix() - questions::RETENTION_SECS
    ));
    questions::maintenance(&core, now_unix()).unwrap();
    assert_eq!(list(&relay, &phone, 0), json!({"seq": 5, "questions": []}));
    relay.fails(
        "GET",
        &format!("/v1/questions/{first}/answers"),
        Some(&mac.token),
        None,
        404,
        "not_found",
    );
    assert_eq!(
        relay.vault_rows("SELECT count(*), (SELECT count(*) FROM question_answer) FROM question")
            [0],
        (b"0".to_vec(), b"0".to_vec())
    );
    let posted = ask(&relay, &mac, &qid(4), "member");
    assert_eq!(posted["seq"], 6);
}

/// Calls `f` and returns its answer with how long it took.
fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let started = Instant::now();
    let out = f();
    (out, started.elapsed())
}

#[test]
fn long_polls_wake_on_posts_answers_and_expiry() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let core = relay.hub().team(&team_of(&mac.token)).unwrap();
    let relay = &relay;

    // The list wakes on a post; a second list poll of the same device answers at once.
    std::thread::scope(|scope| {
        let poll = scope.spawn(|| {
            timed(|| relay.ok("GET", "/v1/questions?since=0&wait=25", &phone.token, None))
        });
        std::thread::sleep(Duration::from_millis(500));
        let (second, took) =
            timed(|| relay.ok("GET", "/v1/questions?since=0&wait=25", &phone.token, None));
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert_eq!(second["questions"], json!([]));
        ask(relay, &mac, &qid(1), "member");
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(qids(&woken), vec![qid(1)]);
    });

    // The asker's answer poll wakes on an answer.
    let answers = format!("/v1/questions/{}/answers?after=0&wait=25", qid(1));
    std::thread::scope(|scope| {
        let poll = scope.spawn(|| timed(|| relay.ok("GET", &answers, &mac.token, None)));
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(answer(relay, &phone, &qid(1)).0, 200);
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(woken["answers"].as_array().unwrap().len(), 1);
    });

    // The three kinds of poll of one device do not take each other's place: with a
    // sync poll and a question list poll open, its answer poll still waits.
    ask(relay, &phone, &qid(2), "member");
    std::thread::scope(|scope| {
        let sync = scope.spawn(|| {
            timed(|| relay.ok("GET", "/v1/sync/head?since=0&wait=3", &phone.token, None))
        });
        let listed = scope.spawn(|| {
            timed(|| relay.ok("GET", "/v1/questions?since=2&wait=3", &phone.token, None))
        });
        std::thread::sleep(Duration::from_millis(300));
        let (own, took) = timed(|| {
            relay.ok(
                "GET",
                &format!("/v1/questions/{}/answers?after=0&wait=2", qid(2)),
                &phone.token,
                None,
            )
        });
        assert!(took >= Duration::from_millis(1500), "{took:?}");
        assert_eq!(own["answers"], json!([]));
        for poll in [sync, listed] {
            let (_, took) = poll.join().unwrap();
            assert!(took >= Duration::from_millis(2500), "{took:?}");
        }
    });

    // The answer poll wakes on an expiry, and a list poll sees it.
    let expiring = format!("/v1/questions/{}/answers?after=0&wait=25", qid(2));
    std::thread::scope(|scope| {
        let poll = scope.spawn(|| timed(|| relay.ok("GET", &expiring, &phone.token, None)));
        let seen = scope
            .spawn(|| timed(|| relay.ok("GET", "/v1/questions?since=2&wait=25", &mac.token, None)));
        std::thread::sleep(Duration::from_millis(500));
        questions::maintenance(&core, now_unix() + 301).unwrap();
        let (woken, took) = poll.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(woken["state"], "expired");
        let (listed, took) = seen.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(listed["questions"][0]["state"], "expired");
    });
}

#[test]
fn question_polls_have_their_own_lane() {
    let mut relay = start_with(
        |config| {
            config.limits.max_active = 2;
            config.limits.member_reserve = 1;
            config.limits.question_long_polls = 2;
        },
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let mini = add_device(&relay, &mac, "Mac mini");
    ask(&relay, &mac, &qid(1), "member");
    let relay = &relay;
    let answers = format!("/v1/questions/{}/answers?after=0&wait=25", qid(1));
    std::thread::scope(|scope| {
        // Two question polls fill the question lane and none of `max_active`.
        let listed = scope.spawn(|| {
            timed(|| relay.ok("GET", "/v1/questions?since=1&wait=25", &phone.token, None))
        });
        let answered = scope.spawn(|| timed(|| relay.ok("GET", &answers, &mac.token, None)));
        std::thread::sleep(Duration::from_millis(700));
        // A third poll overflows into the member lane and is answered at once.
        let (third, took) =
            timed(|| relay.ok("GET", "/v1/questions?since=1&wait=25", &mini.token, None));
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert_eq!(third["questions"], json!([]));
        // Members still get answers: the two polls hold no member slot.
        for _ in 0..3 {
            assert_eq!(relay.call("GET", "/v1/me", Some(&mini.token), None).0, 200);
        }
        ask(relay, &mini, &qid(2), "member");
        assert_eq!(answer(relay, &phone, &qid(1)).0, 200);
        let (woken, took) = listed.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(qids(&woken), vec![qid(2)]);
        let (woken, took) = answered.join().unwrap();
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(woken["answers"].as_array().unwrap().len(), 1);
    });
}

/// The calls the mock Worker got: the `X-Apassy-Push` header and the JSON body.
type Calls = Arc<Mutex<Vec<(Option<String>, Value)>>>;

/// A Worker push route in process: it records each call and answers each token with
/// the status set for it (200 by default).
struct MockWorker {
    url: String,
    calls: Calls,
    answers: Arc<Mutex<HashMap<String, (u16, &'static str)>>>,
    hang: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl MockWorker {
    fn start() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let calls: Calls = Arc::default();
        let answers: Arc<Mutex<HashMap<String, (u16, &'static str)>>> = Arc::default();
        let hang = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, set, slow, done) = (calls.clone(), answers.clone(), hang.clone(), stop.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(100)) else {
                    continue;
                };
                let secret = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("X-Apassy-Push"))
                    .map(|h| h.value.as_str().to_string());
                let mut text = String::new();
                request.as_reader().read_to_string(&mut text).unwrap();
                let body: Value = serde_json::from_str(&text).unwrap();
                seen.lock().unwrap().push((secret, body.clone()));
                let set = set.clone();
                let slow = slow.load(Ordering::Relaxed);
                std::thread::spawn(move || {
                    if slow {
                        std::thread::sleep(Duration::from_secs(15));
                    }
                    let results: Vec<Value> = body["tokens"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|token| {
                            let token = token.as_str().unwrap();
                            match set.lock().unwrap().get(token) {
                                Some((status, reason)) => {
                                    json!({"token": token, "status": status, "reason": reason})
                                }
                                None => json!({"token": token, "status": 200}),
                            }
                        })
                        .collect();
                    let _ = request.respond(tiny_http::Response::from_string(
                        json!({"results": results}).to_string(),
                    ));
                });
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}/internal/push"),
            calls,
            answers,
            hang,
            stop,
        }
    }

    fn config(&self) -> PushConfig {
        PushConfig {
            url: self.url.clone(),
            topic: TOPIC.to_string(),
            secret: SecretString::new(PUSH_SECRET.to_string()),
        }
    }

    /// Waits until the Worker has `count` calls, and a moment more for a wrong extra one.
    fn calls(&self, count: usize) -> Vec<(Option<String>, Value)> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.calls.lock().unwrap().len() < count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(300));
        self.calls.lock().unwrap().clone()
    }
}

impl Drop for MockWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn token_of(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn put_token(relay: &TestRelay, by: &Device, token: &str, environment: &str) -> (u16, Value) {
    relay.call(
        "PUT",
        "/v1/push/token",
        Some(&by.token),
        Some(&json!({"token": token, "environment": environment, "bundle_id": TOPIC})),
    )
}

/// The failed mark of each push token: device id and 0 or 1.
fn failed_marks(relay: &TestRelay) -> Vec<(Vec<u8>, Vec<u8>)> {
    relay.vault_rows("SELECT device_id, failed_at IS NOT NULL FROM push_token ORDER BY device_id")
}

#[test]
fn a_post_pushes_to_the_routing_set_through_the_worker() {
    let worker = MockWorker::start();
    let push = worker.config();
    let mut relay = start_with(
        |config| config.push = Some(push),
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let mini = add_device(&relay, &mac, "Mac mini");
    let bob = join(&relay, "member", "bob");
    let (phone_token, mini_token, mac_token, bob_token) =
        (token_of('a'), token_of('b'), token_of('c'), token_of('d'));
    for (device, token, environment) in [
        (&phone, &phone_token, "production"),
        (&mini, &mini_token, "development"),
        (&mac, &mac_token, "production"),
        (&bob, &bob_token, "production"),
    ] {
        let (status, value) = put_token(&relay, device, token, environment);
        assert_eq!(status, 200, "{value}");
        assert_eq!(value["result"]["device_id"], device.id);
    }
    // Forms of a token.
    for (token, environment, bundle) in [
        (token_of('A'), "production", TOPIC),
        ("ab".repeat(15) + "a", "production", TOPIC),
        ("a".repeat(201), "production", TOPIC),
        (token_of('a'), "staging", TOPIC),
        (token_of('a'), "production", "com.example.other"),
    ] {
        let (status, value) = relay.call(
            "PUT",
            "/v1/push/token",
            Some(&phone.token),
            Some(&json!({"token": token, "environment": environment, "bundle_id": bundle})),
        );
        assert_eq!(
            (status, code(&value)),
            (400, "invalid_request"),
            "{token} {environment} {bundle}"
        );
    }

    // The phone's token is gone at Apple.
    worker
        .answers
        .lock()
        .unwrap()
        .insert(phone_token.clone(), (410, "Unregistered"));
    let posted = ask(&relay, &mac, &qid(1), "member");
    let calls = worker.calls(2);
    assert_eq!(calls.len(), 2, "{calls:?}");
    // One call per environment, with the push secret, the routing set's tokens only.
    assert_eq!(
        calls[0],
        (
            Some(PUSH_SECRET.to_string()),
            json!({"tokens": [mini_token], "environment": "development",
                "collapse_id": "apassy-question", "expires_at": posted["expires_at"]})
        )
    );
    assert_eq!(
        calls[1],
        (
            Some(PUSH_SECRET.to_string()),
            json!({"tokens": [phone_token], "environment": "production",
                "collapse_id": "apassy-question", "expires_at": posted["expires_at"]})
        )
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let phone_mark = (phone.id.to_string().into_bytes(), b"1".to_vec());
    while !failed_marks(&relay).contains(&phone_mark) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(failed_marks(&relay).contains(&phone_mark));

    // The next post skips the failed token; a new PUT clears the mark.
    ask(&relay, &mac, &qid(2), "member");
    let calls = worker.calls(3);
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(calls[2].1["tokens"], json!([mini_token]));
    worker.answers.lock().unwrap().clear();
    assert_eq!(put_token(&relay, &phone, &phone_token, "production").0, 200);
    assert!(!failed_marks(&relay).contains(&phone_mark));
    ask(&relay, &mac, &qid(3), "member");
    let calls = worker.calls(5);
    assert_eq!(calls.len(), 5, "{calls:?}");
    assert_eq!(calls[4].1["tokens"], json!([phone_token]));

    // The audit: counts and device ids, never a token or the secret.
    let deadline = Instant::now() + Duration::from_secs(10);
    while rows(&audit(&relay), "push_sent").len() < 4 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let pushed = audit(&relay);
    assert_eq!(
        rows(&pushed, "push_sent"),
        vec![
            &json!({"count": 1, "environment": "development"}),
            &json!({"count": 1, "environment": "development"}),
            &json!({"count": 1, "environment": "development"}),
            &json!({"count": 1, "environment": "production"}),
        ]
    );
    assert_eq!(
        rows(&pushed, "push_failed"),
        vec![&json!({"device_id": phone.id, "status": 410, "reason": "Unregistered"})]
    );
    assert!(
        rows(&pushed, "push_token_set")
            .contains(&&json!({"device_id": phone.id, "environment": "production"}))
    );
    let text = format!("{pushed:?}");
    for secret in [
        phone_token.as_str(),
        mini_token.as_str(),
        mac_token.as_str(),
        bob_token.as_str(),
        PUSH_SECRET,
        TOPIC,
    ] {
        assert!(!text.contains(secret), "the audit holds {secret}");
    }

    // A removed device loses its token; DELETE removes the caller's own.
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{}", mini.id),
        &mac.token,
        None,
    );
    assert!(
        !failed_marks(&relay)
            .iter()
            .any(|(id, _)| *id == mini.id.to_string().into_bytes())
    );
    assert_eq!(
        relay.ok("DELETE", "/v1/push/token", &phone.token, None),
        json!({"device_id": phone.id})
    );
    assert_eq!(
        relay.ok("DELETE", "/v1/push/token", &phone.token, None),
        json!({"device_id": phone.id})
    );
    assert!(
        !failed_marks(&relay)
            .iter()
            .any(|(id, _)| *id == phone.id.to_string().into_bytes())
    );
    assert_eq!(
        rows(&audit(&relay), "push_token_removed"),
        vec![&json!({"device_id": phone.id})]
    );
    // A revoked member's devices lose their tokens too.
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", bob.member),
        &mac.token,
        None,
    );
    assert!(
        !failed_marks(&relay)
            .iter()
            .any(|(id, _)| *id == bob.id.to_string().into_bytes())
    );
}

#[test]
fn a_slow_worker_delays_no_request() {
    let worker = MockWorker::start();
    worker.hang.store(true, Ordering::Relaxed);
    let push = worker.config();
    let mut relay = start_with(
        |config| config.push = Some(push),
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    assert_eq!(
        put_token(&relay, &phone, &token_of('e'), "production").0,
        200
    );
    for n in 1..=3 {
        let (_, took) = timed(|| ask(&relay, &mac, &qid(n), "member"));
        assert!(took < Duration::from_secs(2), "{took:?}");
    }
    assert!(!worker.calls(1).is_empty());
}

#[test]
fn without_push_a_token_is_refused_and_nothing_is_sent() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let (status, value) = put_token(&relay, &phone, &token_of('a'), "production");
    assert_eq!((status, code(&value)), (409, "push_unavailable"));
    ask(&relay, &mac, &qid(1), "member");
    assert_eq!(
        relay.vault_rows("SELECT count(*), '' FROM push_token")[0].0,
        b"0"
    );
    assert!(rows(&audit(&relay), "push_sent").is_empty());
}

#[test]
fn a_team_sees_nothing_of_another_team() {
    let mut relay = start(UpstreamOptions::default());
    let a = personal_team(&mut relay);
    let a_phone = add_device(&relay, &a, "iPhone");
    let b = personal_team(&mut relay);
    let b_phone = add_device(&relay, &b, "iPhone");
    assert_ne!(team_of(&a.token), team_of(&b.token));
    ask(&relay, &a, QID, "member");
    assert_eq!(answer(&relay, &a_phone, QID).0, 200);

    // Team B's devices get nothing of it.
    for device in [&b, &b_phone] {
        assert_eq!(list(&relay, device, 0), json!({"seq": 0, "questions": []}));
        let (status, value) = answer(&relay, device, QID);
        assert_eq!((status, code(&value)), (404, "not_found"));
    }
    relay.fails(
        "GET",
        &format!("/v1/questions/{QID}/answers"),
        Some(&b.token),
        None,
        404,
        "not_found",
    );
    relay.fails(
        "POST",
        &format!("/v1/questions/{QID}/settle"),
        Some(&b.token),
        Some(&sealed(SETTLE_NONCE, &encode_b64(&[1; 20]))),
        404,
        "not_found",
    );
    // The same qid is free in team B, and each team keeps its own.
    let own = ask(&relay, &b, QID, "member");
    assert_eq!(own["seq"], 1);
    assert_eq!(
        list(&relay, &b_phone, 0)["questions"][0]["from_device_id"],
        b.id
    );
    let a_list = list(&relay, &a_phone, 0);
    assert_eq!(a_list["questions"].as_array().unwrap().len(), 1);
    assert_eq!(a_list["questions"][0]["from_device_id"], a.id);
    let a_answers = relay.ok(
        "GET",
        &format!("/v1/questions/{QID}/answers"),
        &a.token,
        None,
    );
    assert_eq!(a_answers["answers"].as_array().unwrap().len(), 1);
    assert_eq!(a_answers["answers"][0]["device_id"], a_phone.id);
}

#[test]
fn approvers_questions_wait_for_shared_vaults() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    // Without APASSY_RELAY_QUESTIONS_TO_APPROVERS: forms first, then 403, nothing stored.
    let (status, value) = relay.call(
        "POST",
        "/v1/questions",
        Some(&mac.token),
        Some(&card(
            &qid(1),
            "approvers",
            now_unix() + 650,
            &encode_b64(&[1; 20]),
        )),
    );
    assert_eq!((status, code(&value)), (400, "invalid_request"));
    let (status, value) = relay.call(
        "POST",
        "/v1/questions",
        Some(&mac.token),
        Some(&card(
            &qid(1),
            "approvers",
            now_unix() + 300,
            &encode_b64(&[1; 20]),
        )),
    );
    assert_eq!((status, code(&value)), (403, "not_routed"));
    assert_eq!(list(&relay, &phone, 0), json!({"seq": 0, "questions": []}));
    assert_eq!(
        rows(&audit(&relay), "question_refused"),
        vec![&json!({"reason": "not_routed", "device_id": mac.id})]
    );
    // `member` questions go on.
    ask(&relay, &mac, &qid(1), "member");
}

#[test]
fn answers_per_question_are_capped() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let mini = add_device(&relay, &mac, "Mac mini");
    ask(&relay, &mac, &qid(1), "member");
    // 19 answers of the Mac mini, written past its own limit of 3, and one of the phone.
    relay.edit_vault_live(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 19) \
         INSERT INTO question_answer (qid, device_id, member_id, role, key_id, nonce, ciphertext, at) \
         SELECT '{}', {}, {}, 'owner', '{KEY_ID}', x'00', x'00', 0 FROM n",
        qid(1),
        mini.id,
        mini.member
    ));
    assert_eq!(answer(&relay, &phone, &qid(1)).0, 200);
    let (status, value) = answer(&relay, &phone, &qid(1));
    assert_eq!((status, code(&value)), (403, "too_many_answers"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("20 answers")
    );
}

/// The bytes of ciphertext in the team file (cards, settles, answers), and the answer
/// rows.
fn stored(relay: &TestRelay) -> (u64, u64) {
    let (bytes, answers) = &relay.vault_rows(
        "SELECT (SELECT coalesce(sum(length(ciphertext) + coalesce(length(settle_ciphertext), 0)), 0) FROM question) \
         + (SELECT coalesce(sum(length(ciphertext)), 0) FROM question_answer), \
         (SELECT count(*) FROM question_answer)",
    )[0];
    let number = |cell: &[u8]| String::from_utf8_lossy(cell).parse::<u64>().unwrap();
    (number(bytes), number(answers))
}

#[test]
fn question_storage_has_a_budget_and_ended_questions_lose_their_ciphertext() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let team = team_of(&mac.token);
    let core = relay.hub().team(&team).unwrap();
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                question_bytes: Some(1_048_576),
                open_questions: Some(1000),
                member_open_questions: Some(1000),
                device_open_questions: Some(1000),
                ..Default::default()
            }),
        })
        .unwrap();
    let big = encode_b64(&vec![1; questions::MAX_CARD_BYTES]);
    // 31 full cards are 1016304 bytes; the 32nd would pass 1 MiB.
    for n in 1..=31 {
        relay.ok(
            "POST",
            "/v1/questions",
            &mac.token,
            Some(&card(&qid(n), "member", now_unix() + 300, &big)),
        );
    }
    let (status, value) = relay.call(
        "POST",
        "/v1/questions",
        Some(&mac.token),
        Some(&card(&qid(32), "member", now_unix() + 300, &big)),
    );
    assert_eq!((status, code(&value)), (403, "too_many_questions"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("question_bytes")
    );
    // Answers count too: three full answers fit, a fourth does not.
    let full_answer = |n: u8| {
        relay.call(
            "POST",
            &format!("/v1/questions/{}/answers", qid(n)),
            Some(&phone.token),
            Some(&sealed(
                ANSWER_NONCE,
                &encode_b64(&vec![2; questions::MAX_ANSWER_BYTES]),
            )),
        )
    };
    for _ in 0..3 {
        assert_eq!(full_answer(1).0, 200);
    }
    let (status, value) = full_answer(2);
    assert_eq!((status, code(&value)), (403, "too_many_answers"));
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("question_bytes")
    );
    assert_eq!(
        rows(&audit(&relay), "limit_reached"),
        vec![&json!({"limit": "question_bytes"})]
    );
    // A settle is never refused for the budget.
    relay.ok(
        "POST",
        &format!("/v1/questions/{}/settle", qid(1)),
        &mac.token,
        Some(&sealed(SETTLE_NONCE, &encode_b64(&[3; 1_040]))),
    );
    assert_eq!(stored(&relay), (31 * 32_784 + 1_040 + 3 * 8_208, 3));

    // Ended questions keep their ciphertext for ten minutes after the end.
    let now = now_unix();
    questions::maintenance(&core, now + 301).unwrap();
    assert_eq!(stored(&relay).1, 3);
    assert_eq!(
        list(&relay, &phone, 0)["questions"]
            .as_array()
            .unwrap()
            .len(),
        31
    );
    // Then only the metadata stays: no list shows the question, the asker reads its
    // state without answers, and the budget is free again.
    questions::maintenance(&core, now + 901).unwrap();
    assert_eq!(stored(&relay), (0, 0));
    let seq = list(&relay, &phone, 0)["seq"].as_u64().unwrap();
    assert_eq!(
        list(&relay, &phone, 0),
        json!({"seq": seq, "questions": []})
    );
    let read = relay.ok(
        "GET",
        &format!("/v1/questions/{}/answers", qid(1)),
        &mac.token,
        None,
    );
    assert_eq!(
        (
            read["state"].as_str(),
            read["answers"].as_array().unwrap().len()
        ),
        (Some("settled"), 0)
    );
    let (status, value) = answer(&relay, &phone, &qid(2));
    assert_eq!((status, code(&value)), (409, "question_expired"));
    // The rows stay until the day is over: a repost of a qid is still a conflict.
    assert_eq!(
        relay.vault_rows("SELECT count(*), 0 FROM question")[0].0,
        b"31".to_vec()
    );
    relay.fails(
        "POST",
        "/v1/questions",
        Some(&mac.token),
        Some(&card(&qid(2), "member", now_unix() + 300, &big)),
        409,
        "conflict",
    );
    relay.ok(
        "POST",
        "/v1/questions",
        &mac.token,
        Some(&card(&qid(32), "member", now_unix() + 300, &big)),
    );
}

#[test]
fn a_long_poll_ends_with_401_when_its_device_is_revoked_or_its_role_changes() {
    let mut relay = start(UpstreamOptions::default());
    let owner = personal_team(&mut relay);
    let phone = add_device(&relay, &owner, "iPhone");
    let maria = join(&relay, "manager", "maria");
    let alice = join(&relay, "member", "alice");
    let alice_phone = add_device(&relay, &alice, "Alice iPhone");
    ask(&relay, &alice, &qid(1), "member");
    let relay = &relay;
    let status_of = |token: &str, path: &str| {
        timed(|| {
            let (status, value) = relay.call("GET", path, Some(token), None);
            (status, code(&value).to_string(), value)
        })
    };
    std::thread::scope(|scope| {
        // A list poll of a device revoked while it waits: 401, not the next question.
        let revoked = scope.spawn(|| status_of(&phone.token, "/v1/questions?since=0&wait=25"));
        // A list poll of a manager who becomes a member.
        let demoted = scope.spawn(|| status_of(&maria.token, "/v1/questions?since=0&wait=25"));
        // The asker's answer poll of a device revoked while it waits.
        let asker = scope.spawn(|| {
            status_of(
                &alice.token,
                &format!("/v1/questions/{}/answers?after=0&wait=25", qid(1)),
            )
        });
        std::thread::sleep(Duration::from_millis(700));
        relay.ok(
            "DELETE",
            &format!("/v1/devices/{}", phone.id),
            &owner.token,
            None,
        );
        relay.ok(
            "PUT",
            &format!("/v1/members/{}/role", maria.member),
            &owner.token,
            Some(&json!({"role": "member"})),
        );
        relay.ok(
            "DELETE",
            &format!("/v1/devices/{}", alice.id),
            &owner.token,
            None,
        );
        ask(relay, &owner, &qid(2), "member");
        assert_eq!(answer(relay, &alice_phone, &qid(1)).0, 200);
        for poll in [revoked, demoted, asker] {
            let ((status, code, value), took) = poll.join().unwrap();
            assert_eq!((status, code.as_str()), (401, "unauthenticated"), "{value}");
            assert!(took < Duration::from_secs(10), "{took:?}");
        }
    });
}

#[test]
fn a_team_holds_at_most_its_share_of_the_question_lane() {
    let mut relay = start_with(
        |config| {
            config.limits.question_long_polls = 8;
            config.limits.question_long_polls_per_team = 2;
        },
        UpstreamOptions::default(),
    );
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    let mini = add_device(&relay, &mac, "Mac mini");
    let (other_token, _) = relay.new_team_device("Other", "owner");
    let other = device_of(&relay, other_token);
    let relay = &relay;
    std::thread::scope(|scope| {
        // Two polls of the team take its share.
        let polls: Vec<_> = [&phone, &mini]
            .into_iter()
            .map(|device| {
                scope.spawn(move || {
                    timed(|| relay.ok("GET", "/v1/questions?since=0&wait=25", &device.token, None))
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(700));
        // A third poll of the team is answered at once, though the lane has room.
        let ((status, third), took) = timed(|| {
            relay.call(
                "GET",
                &format!("/v1/questions/{}/answers?after=0&wait=25", qid(9)),
                Some(&mac.token),
                None,
            )
        });
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert_eq!((status, code(&third)), (404, "not_found"));
        let (listed, took) =
            timed(|| relay.ok("GET", "/v1/questions?since=0&wait=25", &mac.token, None));
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert_eq!(listed["questions"], json!([]));
        // Another team still waits in the lane.
        let (_, took) =
            timed(|| relay.ok("GET", "/v1/questions?since=0&wait=2", &other.token, None));
        assert!(took >= Duration::from_millis(1500), "{took:?}");
        ask(relay, &mac, &qid(1), "member");
        for poll in polls {
            let (woken, took) = poll.join().unwrap();
            assert!(took < Duration::from_secs(10), "{took:?}");
            assert_eq!(qids(&woken), vec![qid(1)]);
        }
    });
    // The seats came back: the team's polls wait again.
    let (_, took) = timed(|| relay.ok("GET", "/v1/questions?since=1&wait=2", &phone.token, None));
    assert!(took >= Duration::from_millis(1500), "{took:?}");
}

/// Sends the headers of a request, waits `pause`, then sends its JSON body. Returns
/// the status and the JSON envelope.
fn slow_body(
    relay: &TestRelay,
    method: &str,
    path: &str,
    token: &str,
    body: &Value,
    pause: Duration,
) -> (u16, Value) {
    use std::io::{Read, Write};
    let body = body.to_string();
    let addr = relay.url.trim_start_matches("http://").to_string();
    let mut stream = std::net::TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nX-Apassy-Edge: {}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        relay.edge_secret,
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    std::thread::sleep(pause);
    stream.write_all(body.as_bytes()).unwrap();
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

#[test]
fn the_request_time_of_a_question_call_is_taken_after_its_body() {
    let mut relay = start(UpstreamOptions::default());
    let mac = personal_team(&mut relay);
    let phone = add_device(&relay, &mac, "iPhone");
    // `expires_at` is 602 s after the headers: too far for the time of the headers,
    // within 600 s of the time of the body.
    let headers_at = now_unix();
    let (status, posted) = slow_body(
        &relay,
        "POST",
        "/v1/questions",
        &mac.token,
        &card(&qid(1), "member", headers_at + 602, &encode_b64(&[1; 20])),
        Duration::from_millis(3_200),
    );
    assert_eq!(status, 200, "{posted}");
    assert!(posted["result"]["created_at"].as_u64().unwrap() >= headers_at + 3);
    let headers_at = now_unix();
    let (status, answered) = slow_body(
        &relay,
        "POST",
        &format!("/v1/questions/{}/answers", qid(1)),
        &phone.token,
        &sealed(ANSWER_NONCE, &encode_b64(&[5; 30])),
        Duration::from_millis(2_200),
    );
    assert_eq!(status, 200, "{answered}");
    assert!(answered["result"]["at"].as_u64().unwrap() >= headers_at + 2);
    let headers_at = now_unix();
    let (status, settled) = slow_body(
        &relay,
        "POST",
        &format!("/v1/questions/{}/settle", qid(1)),
        &mac.token,
        &sealed(SETTLE_NONCE, &encode_b64(&[3; 20])),
        Duration::from_millis(2_200),
    );
    assert_eq!(status, 200, "{settled}");
    assert!(settled["result"]["settled_at"].as_u64().unwrap() >= headers_at + 2);
}
