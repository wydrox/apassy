//! Vaults shared between the accounts of a family or team on the relay (contract
//! connect-account-v1 section 16, docs/SPEC.md section 33): the entries of the device list
//! that name another account (`POST /v1/account/list`) with each check of the service, the
//! share codes of the ceremony (`/v1/account/peers/…`), the other account's list within
//! one group, the removal of the store rows in the transaction of an `unshare` or a
//! `leave`, and the bounds of a list. Each test starts its own relay with a fake Stripe
//! server on free loopback ports in a temporary directory. Synthetic values only.

#[path = "common/connect.rs"]
mod connect;
#[path = "common/fake_stripe.rs"]
mod fake_stripe;
#[path = "common/relay.rs"]
mod relay;

use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::encode_b64;
use connect::{Connect, Dev, start, store_add_body};
use serde_json::{Value, json};

const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
const OTHER_VAULT: &str = "1f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";

/// A Family bought by Rafal with Ola as an active member, and Rafal's store.
struct Family {
    c: Connect,
    owner: Dev,
    member: Dev,
    team: String,
}

fn family() -> Family {
    let c = start();
    let owner = c.account("Rafal");
    c.subscribe(&owner, "connect_family_month", 4);
    let member = c.account("Ola");
    c.add_member(&owner, &member);
    let team = store(&c, &owner, VAULT);
    Family {
        c,
        owner,
        member,
        team,
    }
}

fn store(c: &Connect, owner: &Dev, vault: &str) -> String {
    c.ok(
        "POST",
        "/v1/account/vaults",
        Some(&owner.token),
        Some(&json!({"vault_id": vault, "name": "Family"})),
    )["team_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn code(answer: &(u16, Value)) -> (u16, Option<&str>) {
    (answer.0, answer.1["error"]["code"].as_str())
}

fn peer(c: &Connect, by: &Dev, other: &Dev) -> (u16, Value) {
    c.list_entry(
        by,
        "peer",
        &other.account,
        Some(&other.key.public_key_b64()),
        None,
    )
}

fn add_to_store(c: &Connect, by: &Dev, team: &str, who: &Dev) -> (u16, Value) {
    c.call(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&by.token),
        Some(&store_add_body(who)),
    )
}

/// The store sign-in of `dev`: the status of its challenge.
fn store_challenge(c: &Connect, team: &str, dev: &Dev) -> u16 {
    c.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": dev.key.public_key_b64()})),
    )
    .0
}

#[test]
fn a_share_needs_a_peer_the_group_and_a_store_of_the_caller() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    // A share before the peer: the rules of the list.
    assert_eq!(
        code(&c.list_entry(owner, "share", &member.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
    // A peer with a root that is not the member's: refused, nothing stored.
    let other = DeviceKey::generate().unwrap();
    assert_eq!(
        code(&c.list_entry(
            owner,
            "peer",
            &member.account,
            Some(&other.public_key_b64()),
            None
        )),
        (409, Some("conflict"))
    );
    // A peer of an account outside the group.
    let stranger = c.account("Stranger");
    assert_eq!(
        code(&peer(c, owner, &stranger)),
        (403, Some("not_in_group"))
    );
    let before = c.list_head(&owner.account).0;
    assert_eq!(peer(c, owner, member).0, 200);
    assert_eq!(c.list_head(&owner.account).0, before + 1);
    // The same peer again.
    assert_eq!(code(&peer(c, owner, member)), (409, Some("conflict")));
    // The member's own store is not the owner's to share, and a store id that names no
    // store is none either.
    let member_store = store(c, member, OTHER_VAULT);
    assert_eq!(
        code(&c.list_entry(owner, "share", &member.account, None, Some(&member_store))),
        (403, Some("forbidden"))
    );
    assert_eq!(
        code(&c.list_entry(owner, "share", &member.account, None, Some("t_aaaaaaaaaa"))),
        (404, Some("not_found"))
    );
    // Before the share the member's device is refused in the store, also in one group.
    assert_eq!(
        code(&add_to_store(c, owner, &f.team, member)),
        (403, Some("not_in_group"))
    );
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(add_to_store(c, owner, &f.team, member).0, 200);
    // The owner adds the member's device before the member's `join`; it signs in after it.
    assert_eq!(store_challenge(c, &f.team, member), 401);
    c.join_store(member, owner, &f.team);
    assert_eq!(store_challenge(c, &f.team, member), 200);
    // The same share again.
    assert_eq!(
        code(&c.list_entry(owner, "share", &member.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
}

#[test]
fn an_entry_is_checked_for_its_shape_signature_version_and_signer() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let (head, previous) = c.list_head(&owner.account);
    let entry =
        |op: &str, root: Option<String>, team: Option<String>, version: u64, by: &DeviceKey| {
            let message = device::share_list_message(
                c.origin(),
                &owner.account,
                version,
                &previous,
                op,
                &member.account,
                root.as_deref().unwrap_or(device::LIST_NONE),
                team.as_deref().unwrap_or(device::LIST_NONE),
                &owner.key.public_key_b64(),
            );
            json!({"version": version, "op": op, "account_id": member.account, "root": root,
               "team_id": team, "statement": encode_b64(&by.sign(&message).unwrap())})
        };
    let root = Some(member.key.public_key_b64());
    let post = |body: &Value| c.call("POST", "/v1/account/list", Some(&owner.token), Some(body));
    // Shapes: a device op, a root on a share, no root on a peer, a store on a peer, no
    // store on a share, an unknown field, this account itself.
    for body in [
        entry("add", None, None, head + 1, &owner.key),
        entry(
            "share",
            root.clone(),
            Some(f.team.clone()),
            head + 1,
            &owner.key,
        ),
        entry("peer", None, None, head + 1, &owner.key),
        entry(
            "peer",
            root.clone(),
            Some(f.team.clone()),
            head + 1,
            &owner.key,
        ),
        entry("share", None, None, head + 1, &owner.key),
    ] {
        assert_eq!(code(&post(&body)).0, 400, "{body}");
    }
    let mut extra = entry("peer", root.clone(), None, head + 1, &owner.key);
    extra["by"] = json!("x");
    assert_eq!(code(&post(&extra)), (400, Some("invalid_request")));
    let mut itself = entry("peer", root.clone(), None, head + 1, &owner.key);
    itself["account_id"] = json!(owner.account);
    assert_eq!(code(&post(&itself)), (400, Some("invalid_request")));
    // Another key's signature, another version.
    let other = DeviceKey::generate().unwrap();
    assert_eq!(
        code(&post(&entry("peer", root.clone(), None, head + 1, &other))),
        (400, Some("invalid_request"))
    );
    assert_eq!(
        code(&post(&entry(
            "peer",
            root.clone(),
            None,
            head + 2,
            &owner.key
        ))),
        (409, Some("conflict"))
    );
    assert_eq!(
        code(&post(&entry("peer", root.clone(), None, head, &owner.key))),
        (409, Some("conflict"))
    );
    assert_eq!(c.list_head(&owner.account).0, head, "nothing was stored");
    assert_eq!(
        post(&entry("peer", root, None, head + 1, &owner.key)).0,
        200
    );
    // The answer of `GET /v1/account` carries the entry with its fields.
    let list = c.ok("GET", "/v1/account", Some(&owner.token), None)["device_list"].clone();
    let last = list.as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["op"], "peer");
    assert_eq!(last["account_id"], member.account.as_str());
    assert_eq!(last["root"], member.key.public_key_b64().as_str());
    assert!(last["key"].is_null() && last.get("team_id").is_none());
    // A device entry keeps its fields of section 7.5 only.
    assert!(list[0].get("account_id").is_none());
}

#[test]
fn an_unshare_removes_the_member_from_the_store_in_its_transaction() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    c.share_store(owner, member, &f.team);
    assert_eq!(add_to_store(c, owner, &f.team, member).0, 200);
    c.join_store(member, owner, &f.team);
    assert_eq!(store_challenge(c, &f.team, member), 200);
    let rows = |account: &str| {
        c.rows(&format!(
            "SELECT device_id FROM account_store_device WHERE team_id = '{}' AND account_id = '{account}'",
            f.team
        ))
    };
    assert_eq!(rows(&member.account).len(), 1);
    let (status, answer) = c.list_entry(owner, "unshare", &member.account, None, Some(&f.team));
    assert_eq!(status, 200, "{answer}");
    assert!(rows(&member.account).is_empty());
    assert_eq!(rows(&owner.account).len(), 1);
    assert_ne!(store_challenge(c, &f.team, member), 200);
    assert_eq!(store_challenge(c, &f.team, owner), 200);
    // A store row left behind (a removal that did not run to its end) signs in no more:
    // the store sign-in needs the owner's active share too.
    c.edit_directory(&format!(
        "INSERT INTO account_store_device (team_id, device_id, account_id, store_device, added_at) \
         VALUES ('{}', '{}', '{}', 2, 1);",
        f.team, member.id, member.account
    ));
    let team_id = apassy_relay::ids::TeamId::parse(&f.team).unwrap();
    let live = c
        .relay
        .hub()
        .directory
        .store
        .with(|conn| apassy_relay::server::account::store_device_live(conn, &team_id, 2))
        .unwrap();
    assert!(!live, "a row without the share is no live store device");
    c.edit_directory(&format!(
        "DELETE FROM account_store_device WHERE team_id = '{}' AND device_id = '{}';",
        f.team, member.id
    ));
    // No new device of the member comes in without a new share.
    assert_eq!(
        code(&add_to_store(c, owner, &f.team, member)),
        (403, Some("not_in_group"))
    );
    // The unshare is not repeated; the peer stays, so a new share needs no new peer.
    assert_eq!(
        code(&c.list_entry(owner, "unshare", &member.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(add_to_store(c, owner, &f.team, member).0, 200);
}

#[test]
fn a_join_needs_the_owners_share_and_a_leave_removes_the_callers_devices() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    // The member's join before its own peer of the owner, and before the owner's share.
    assert_eq!(
        code(&c.list_entry(member, "join", &owner.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
    assert_eq!(peer(c, member, owner).0, 200);
    assert_eq!(
        code(&c.list_entry(member, "join", &owner.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
    c.share_store(owner, member, &f.team);
    assert_eq!(add_to_store(c, owner, &f.team, member).0, 200);
    assert_eq!(
        c.list_entry(member, "join", &owner.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(
        code(&c.list_entry(member, "join", &owner.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
    // A peer that a join names is not unpinned.
    assert_eq!(
        code(&c.list_entry(member, "unpeer", &owner.account, None, None)),
        (409, Some("conflict"))
    );
    assert_eq!(
        c.list_entry(member, "leave", &owner.account, None, Some(&f.team))
            .0,
        200
    );
    assert!(
        c.rows(&format!(
            "SELECT device_id FROM account_store_device WHERE team_id = '{}' AND account_id = '{}'",
            f.team, member.account
        ))
        .is_empty()
    );
    assert_eq!(
        c.list_entry(member, "unpeer", &owner.account, None, None).0,
        200
    );
    // The owner's unpeer waits for the end of its share.
    assert_eq!(
        code(&c.list_entry(owner, "unpeer", &member.account, None, None)),
        (409, Some("conflict"))
    );
}

#[test]
fn another_accounts_key_signs_no_entry() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    assert_eq!(peer(c, owner, member).0, 200);
    // Another account's key never signs the owner's list, also with the owner's token.
    let (head, previous) = c.list_head(&owner.account);
    let message = device::share_list_message(
        c.origin(),
        &owner.account,
        head + 1,
        &previous,
        "share",
        &member.account,
        device::LIST_NONE,
        &f.team,
        &member.key.public_key_b64(),
    );
    let body = json!({"version": head + 1, "op": "share", "account_id": member.account,
                      "root": null, "team_id": f.team,
                      "statement": encode_b64(&member.key.sign(&message).unwrap())});
    assert_eq!(
        code(&c.call("POST", "/v1/account/list", Some(&owner.token), Some(&body))),
        (400, Some("invalid_request"))
    );
}

#[test]
fn the_list_keeps_room_to_end_every_peer_and_share() {
    use apassy_relay::server::account::{LAST_ADD_VERSION, MAX_LIST_ENTRIES, MAX_PEERS};
    assert_eq!((LAST_ADD_VERSION, MAX_LIST_ENTRIES), (822, 1024));
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    assert_eq!(peer(c, owner, member).0, 200);
    // At version 822 nothing more is added; an unpeer still works up to 1024.
    let (head, _) = c.list_head(&owner.account);
    c.edit_directory(&format!(
        "UPDATE account_list SET version = {LAST_ADD_VERSION} WHERE account_id = '{}' AND version = {head};",
        owner.account
    ));
    let refused = c.list_entry(owner, "share", &member.account, None, Some(&f.team));
    assert_eq!(code(&refused), (403, Some("account_limit")), "{refused:?}");
    assert!(
        refused.1["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Removing a device still works")
    );
    assert_eq!(
        c.list_entry(owner, "unpeer", &member.account, None, None).0,
        200
    );
    let (head, _) = c.list_head(&owner.account);
    c.edit_directory(&format!(
        "UPDATE account_list SET version = {MAX_LIST_ENTRIES} WHERE account_id = '{}' AND version = {head};",
        owner.account
    ));
    assert_eq!(code(&peer(c, owner, member)), (403, Some("account_limit")));
    // 64 peers at most: a list with 64 active peers takes no 65th.
    let g = family();
    let fake_root = [4u8; 65];
    let mut sql = String::new();
    let (head, hash) = g.c.list_head(&g.owner.account);
    for index in 0..MAX_PEERS {
        sql.push_str(&format!(
            "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at, peer_account, peer_root, team_id) \
             VALUES ('{}', {}, 'peer', NULL, NULL, NULL, x'00', x'00', '{hash}', 1, 'acc_{:010}', x'{}', NULL);",
            g.owner.account,
            head + 1 + index,
            index,
            fake_root.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
        ).replace("acc_00000000", "acc_aaaaaaaa"));
    }
    g.c.edit_directory(&sql);
    // The rows above stand for a list of 64 active peers (each with the hash of the head
    // before them): the next peer is refused for the count.
    assert_eq!(
        code(&peer(&g.c, &g.owner, &g.member)),
        (403, Some("account_limit"))
    );
}

/// A share needs a plan that allows sharing (Family or Team) on both accounts.
#[test]
fn a_share_needs_a_family_or_team_plan() {
    use apassy_relay::api::PlanView;
    use apassy_relay::server::account::Plans;
    use apassy_relay::server::store::Store;
    struct Personal;
    impl Plans for Personal {
        fn plan(&self, _: &Store, _: &str, _: u64) -> apassy_relay::error::RelayResult<PlanView> {
            Ok(PlanView {
                plan: Some("personal".into()),
                status: "active".into(),
                entitled: true,
                ..PlanView::none()
            })
        }
    }
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    assert_eq!(peer(c, owner, member).0, 200);
    c.relay.hub().set_plans(std::sync::Arc::new(Personal));
    assert_eq!(
        code(&c.list_entry(owner, "share", &member.account, None, Some(&f.team))),
        (403, Some("plan_required"))
    );
}

#[test]
fn a_share_code_works_once_for_its_member_and_ten_minutes() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let code_text = format!(
        "apassy_shr_{}_{}_{}",
        owner.account,
        "cd".repeat(32),
        "ab".repeat(16)
    );
    let hash = device::share_link_hash(&code_text);
    let stranger = c.account("Stranger");
    // A code for an account outside the group.
    assert_eq!(
        code(&c.call(
            "POST",
            "/v1/account/peers/link",
            Some(&owner.token),
            Some(&json!({"link_hash": hash, "account_id": stranger.account})),
        )),
        (403, Some("not_in_group"))
    );
    let link = c.ok(
        "POST",
        "/v1/account/peers/link",
        Some(&owner.token),
        Some(&json!({"link_hash": hash, "account_id": member.account})),
    );
    assert!(link["expires_at"].as_u64().unwrap() > connect::now());
    let body_of = |by: &Dev, signer: &DeviceKey| {
        let message = device::peer_join_message(
            c.origin(),
            &owner.account,
            &hash,
            &by.account,
            &by.key.public_key_b64(),
            &signer.public_key_b64(),
        );
        json!({"account_id": owner.account, "link_hash": hash,
               "signature": encode_b64(&signer.sign(&message).unwrap())})
    };
    let send = |by: &Dev, body: &Value| {
        c.call(
            "POST",
            "/v1/account/peers/join",
            Some(&by.token),
            Some(body),
        )
    };
    let answer = |by: &Dev, signer: &DeviceKey| send(by, &body_of(by, signer));
    // Another key's signature, and another member than the code's.
    assert_eq!(
        code(&answer(member, &DeviceKey::generate().unwrap())),
        (400, Some("invalid_request"))
    );
    let anna = c.account("Anna");
    c.add_member(owner, &anna);
    assert_eq!(code(&answer(&anna, &anna.key)), (403, Some("forbidden")));
    let body = body_of(member, &member.key);
    let first = send(member, &body);
    assert_eq!(first.0, 200, "{first:?}");
    // The same body again (a retry after a lost answer) answers the same.
    assert_eq!(
        send(member, &body).1["result"]["join_id"],
        first.1["result"]["join_id"]
    );
    let joined = &first.1["result"];
    assert_eq!(
        joined["inviter"]["public_key"],
        owner.key.public_key_b64().as_str()
    );
    assert_eq!(
        joined["device_list"][0]["key"],
        owner.key.public_key_b64().as_str()
    );
    // The code is used up for any other answer (an ECDSA signature differs each time).
    assert_eq!(code(&answer(member, &member.key)), (403, Some("forbidden")));
    // The device that made the code sees the answer with the member's list.
    let pending = c.ok("GET", "/v1/account/peers/pending", Some(&owner.token), None);
    assert_eq!(pending.as_array().unwrap().len(), 1);
    assert_eq!(pending[0]["account_id"], member.account.as_str());
    assert_eq!(
        pending[0]["public_key"],
        member.key.public_key_b64().as_str()
    );
    assert_eq!(
        pending[0]["device_list"][0]["key"],
        member.key.public_key_b64().as_str()
    );
    let join_id = joined["join_id"].as_u64().unwrap();
    let path = format!("/v1/account/peers/join/{join_id}");
    assert_eq!(
        c.ok("GET", &path, Some(&member.token), None)["state"],
        "pending"
    );
    assert_eq!(
        code(&c.call("GET", &path, Some(&stranger.token), None)),
        (404, Some("not_found"))
    );
    // The owner's `peer` confirms the answer.
    assert_eq!(peer(c, owner, member).0, 200);
    assert_eq!(
        c.ok("GET", &path, Some(&member.token), None)["state"],
        "confirmed"
    );
    // A refused answer, and an expired code.
    let other_code = format!(
        "apassy_shr_{}_{}_{}",
        owner.account,
        "ef".repeat(32),
        "ab".repeat(16)
    );
    let other_hash = device::share_link_hash(&other_code);
    c.ok(
        "POST",
        "/v1/account/peers/link",
        Some(&owner.token),
        Some(&json!({"link_hash": other_hash, "account_id": member.account})),
    );
    c.edit_directory(&format!(
        "UPDATE account_peer_link SET expires_at = 1 WHERE link_hash = '{other_hash}';"
    ));
    let message = device::peer_join_message(
        c.origin(),
        &owner.account,
        &other_hash,
        &member.account,
        &member.key.public_key_b64(),
        &member.key.public_key_b64(),
    );
    assert_eq!(
        code(&c.call(
            "POST",
            "/v1/account/peers/join",
            Some(&member.token),
            Some(
                &json!({"account_id": owner.account, "link_hash": other_hash,
                         "signature": encode_b64(&member.key.sign(&message).unwrap())})
            ),
        )),
        (403, Some("forbidden"))
    );
}

#[test]
fn the_list_of_another_account_is_given_only_within_one_group() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let view = c.ok(
        "GET",
        &format!("/v1/account/peers/{}", member.account),
        Some(&owner.token),
        None,
    );
    assert_eq!(view["name"], "Ola");
    assert_eq!(view["devices"][0]["device_id"], member.id.as_str());
    assert_eq!(
        view["device_list"][0]["key"],
        member.key.public_key_b64().as_str()
    );
    let stranger = c.account("Stranger");
    assert_eq!(
        code(&c.call(
            "GET",
            &format!("/v1/account/peers/{}", stranger.account),
            Some(&owner.token),
            None
        )),
        (403, Some("not_in_group"))
    );
    assert_eq!(
        code(&c.call(
            "GET",
            &format!("/v1/account/peers/{}", owner.account),
            Some(&owner.token),
            None
        )),
        (400, Some("invalid_request"))
    );
}

/// A 1006 file of an earlier build of the accounts step without the entries of section 16
/// (no `account_list.team_id`) is refused at open.
#[test]
fn a_directory_without_the_share_columns_is_refused_at_open() {
    use apassy_relay::server::directory::Directory;
    let c = start();
    let _ = c.account("Rafal");
    let (config, dir) = {
        let Connect { relay, .. } = c;
        relay.stop_keep()
    };
    let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
        .unwrap();
    conn.execute_batch(
        "DROP INDEX account_list_team; ALTER TABLE account_list DROP COLUMN team_id;",
    )
    .unwrap();
    drop(conn);
    let refused = Directory::open(&config).err().expect("refused");
    assert!(
        refused.message.contains("account_list.team_id"),
        "{}",
        refused.message
    );
    drop(dir);
}

/// The vectors of contract section 16 are the messages, the hashes, and the words of this
/// relay, and every list entry of them parses with strict types and keeps its JSON.
#[test]
fn the_share_vectors_are_the_messages_of_this_relay() {
    use apassy_relay::hostkeys::decode_b64;
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/connect-account-v1/share-vectors.json"
    ))
    .unwrap();
    let hex = |text: &str| -> Vec<u8> {
        (0..text.len() / 2)
            .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap())
            .collect()
    };
    let origin = v["origin"].as_str().unwrap();
    let (a, x, store) = (
        v["account_a"].as_str().unwrap(),
        v["account_x"].as_str().unwrap(),
        v["store"].as_str().unwrap(),
    );
    let pub_a = hex(v["device_a"]["public_hex"].as_str().unwrap());
    let pub_b = hex(v["device_b"]["public_hex"].as_str().unwrap());
    let (a64, b64) = (encode_b64(&pub_a), encode_b64(&pub_b));
    let code = v["code"]["code"].as_str().unwrap();
    assert_eq!(
        device::share_fingerprint(&pub_a, &pub_a),
        v["code"]["fingerprint"].as_str().unwrap()
    );
    assert_eq!(
        device::share_link_hash(code),
        v["code"]["link_hash"].as_str().unwrap()
    );
    assert_eq!(
        device::share_safety_words(code, (a, &pub_a, &pub_a), (x, &pub_b, &pub_b)),
        v["words"]["words"].as_str().unwrap()
    );
    let link_hash = device::share_link_hash(code);
    let messages = [
        (
            "share_list_peer",
            device::share_list_message(
                origin,
                a,
                2,
                v["lists"]["a"]["hashes"][0].as_str().unwrap(),
                "peer",
                x,
                &b64,
                "-",
                &a64,
            ),
            &pub_a,
        ),
        (
            "share_list_share",
            device::share_list_message(
                origin,
                a,
                3,
                v["lists"]["a"]["hashes"][1].as_str().unwrap(),
                "share",
                x,
                "-",
                store,
                &a64,
            ),
            &pub_a,
        ),
        (
            "share_list_member_peer",
            device::share_list_message(
                origin,
                x,
                2,
                v["lists"]["x"]["hashes"][0].as_str().unwrap(),
                "peer",
                a,
                &a64,
                "-",
                &b64,
            ),
            &pub_b,
        ),
        (
            "share_list_join",
            device::share_list_message(
                origin,
                x,
                3,
                v["lists"]["x"]["hashes"][1].as_str().unwrap(),
                "join",
                a,
                "-",
                store,
                &b64,
            ),
            &pub_b,
        ),
        (
            "peer_join",
            device::peer_join_message(origin, a, &link_hash, x, &b64, &b64),
            &pub_b,
        ),
    ];
    for (name, message, key) in messages {
        let vector = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap();
        assert_eq!(
            encode_b64(&message),
            vector["message_b64u"].as_str().unwrap(),
            "{name}"
        );
        let signature = decode_b64(vector["signature_b64u"].as_str().unwrap(), 72).unwrap();
        assert!(device::verify(key, &message, &signature), "{name}");
    }
    for list in ["a", "x"] {
        for (entry, hash) in v["lists"][list]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .zip(v["lists"][list]["hashes"].as_array().unwrap())
        {
            let typed: apassy_relay::api::ListEntry =
                serde_json::from_value(entry.clone()).unwrap();
            assert_eq!(serde_json::to_value(&typed).unwrap(), *entry);
            assert_eq!(hash.as_str().unwrap().len(), 43);
        }
    }
}

// ---- The share condition of the service (docs/SPEC.md section 33.13). ----

/// The challenge status of `dev` in `team` after the owner `owner` shared it, added `dev`,
/// and `dev`'s account joined it: a family with the store shared, added, and joined.
fn shared_and_joined() -> Family {
    let f = family();
    f.c.share_store(&f.owner, &f.member, &f.team);
    assert_eq!(add_to_store(&f.c, &f.owner, &f.team, &f.member).0, 200);
    f.c.join_store(&f.member, &f.owner, &f.team);
    assert_eq!(store_challenge(&f.c, &f.team, &f.member), 200);
    f
}

/// Whether the store device `store_device` of `team` may sign in (`store_device_live`).
fn live(c: &Connect, team: &str, store_device: u64) -> bool {
    let team = apassy_relay::ids::TeamId::parse(team).unwrap();
    c.relay
        .hub()
        .directory
        .store
        .with(|conn| apassy_relay::server::account::store_device_live(conn, &team, store_device))
        .unwrap()
}

/// A store row of `dev` in `team` as store device `store_device`, left behind or put there.
fn put_row(c: &Connect, team: &str, dev: &Dev, store_device: u64) {
    c.edit_directory(&format!(
        "INSERT INTO account_store_device (team_id, device_id, account_id, store_device, added_at) \
         VALUES ('{team}', '{}', '{}', {store_device}, 1);",
        dev.id, dev.account
    ));
}

/// A member that recovers its account has a new root: the owner's `peer` pins the old one,
/// so the old share adds none of its new devices, and none signs in, until the owner pins
/// the new root and shares again (section 16.7).
#[test]
fn a_member_that_recovers_gets_no_new_device_into_the_shared_store() {
    let f = shared_and_joined();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let renewed = c.recover(member);
    assert_eq!(
        code(&add_to_store(c, owner, &f.team, &renewed)),
        (403, Some("not_in_group"))
    );
    // Its new list pins the owner and asks to join: the share names the old root.
    assert_eq!(peer(c, &renewed, owner).0, 200);
    assert_eq!(
        code(&c.list_entry(&renewed, "join", &owner.account, None, Some(&f.team))),
        (409, Some("conflict"))
    );
    put_row(c, &f.team, &renewed, 7);
    assert!(
        !live(c, &f.team, 7),
        "a row under the old root is no live store device"
    );
    assert_eq!(store_challenge(c, &f.team, &renewed), 401);
    c.edit_directory(&format!(
        "DELETE FROM account_store_device WHERE device_id = '{}';",
        renewed.id
    ));
    // New words: unshare, unpeer, peer of the new root, share; then the member joins.
    for (op, root, team) in [
        ("unshare", None, Some(f.team.as_str())),
        ("unpeer", None, None),
    ] {
        assert_eq!(c.list_entry(owner, op, &member.account, root, team).0, 200);
    }
    assert_eq!(peer(c, owner, &renewed).0, 200);
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(add_to_store(c, owner, &f.team, &renewed).0, 200);
    c.join_store(&renewed, owner, &f.team);
    assert_eq!(store_challenge(c, &f.team, &renewed), 200);
}

/// A removal from the group voids the shares that name the member at Connect: after a new
/// admission the old share adds no device and signs none in, and the old `join` counts
/// for nothing; a newer `share` and the member's `join` after it do (contract section 16:
/// a removal is never a grant).
#[test]
fn a_removal_from_the_group_grants_nothing_after_a_new_admission() {
    let f = shared_and_joined();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let removed = c.call(
        "DELETE",
        &format!("/v1/account/group/members/{}", member.account),
        Some(&owner.token),
        None,
    );
    assert_eq!(removed.0, 200, "{:?}", removed.1);
    c.add_member(owner, member);
    assert_eq!(
        code(&add_to_store(c, owner, &f.team, member)),
        (403, Some("not_in_group"))
    );
    put_row(c, &f.team, member, 7);
    assert!(!live(c, &f.team, 7), "the old share is void");
    assert_eq!(store_challenge(c, &f.team, member), 401);
    c.edit_directory(&format!(
        "DELETE FROM account_store_device WHERE device_id = '{}';",
        member.id
    ));
    // A newer share: the device is added, and signs in only after the member's new join.
    assert_eq!(
        c.list_entry(owner, "unshare", &member.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(add_to_store(c, owner, &f.team, member).0, 200);
    assert_eq!(store_challenge(c, &f.team, member), 401, "the old join");
    assert_eq!(
        c.list_entry(member, "leave", &owner.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(add_to_store(c, owner, &f.team, member).0, 200);
    c.join_store(member, owner, &f.team);
    assert_eq!(store_challenge(c, &f.team, member), 200);
}

/// A member that left a store is added again by another member's device: the row is
/// there, and it signs in only after its own new `join`.
#[test]
fn a_member_that_left_signs_in_again_only_after_its_own_join() {
    let f = shared_and_joined();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let anna = c.account("Anna");
    c.add_member(owner, &anna);
    c.share_store(owner, &anna, &f.team);
    assert_eq!(add_to_store(c, owner, &f.team, &anna).0, 200);
    c.join_store(&anna, owner, &f.team);
    assert_eq!(
        c.list_entry(member, "leave", &owner.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(store_challenge(c, &f.team, member), 401);
    assert_eq!(add_to_store(c, &anna, &f.team, member).0, 200);
    assert_eq!(store_challenge(c, &f.team, member), 401);
    c.join_store(member, owner, &f.team);
    assert_eq!(store_challenge(c, &f.team, member), 200);
}

/// The store add checks the share again in the transaction that maps the device: an
/// `unshare` after the checks of the route maps nothing.
#[test]
fn an_unshare_that_races_a_store_add_maps_nothing() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    c.share_store(owner, member, &f.team);
    // The route checked the share; then the owner's unshare; then the add runs.
    assert_eq!(
        c.list_entry(owner, "unshare", &member.account, None, Some(&f.team))
            .0,
        200
    );
    let team = apassy_relay::ids::TeamId::parse(&f.team).unwrap();
    let added = c.relay.hub().add_store_device(
        &team,
        &member.account,
        &member.id,
        &member.key.public_key(),
        connect::now(),
    );
    assert_eq!(
        added.as_ref().map_err(|error| error.code),
        Err(apassy_relay::error::codes::NOT_IN_GROUP),
        "{added:?}"
    );
    assert!(
        c.rows(&format!(
            "SELECT team_id FROM account_store_device WHERE device_id = '{}'",
            member.id
        ))
        .is_empty()
    );
    assert_eq!(store_challenge(c, &f.team, member), 401);
}

/// The share code `index` of `owner`, its hash, and the answer of `by` to it.
fn share_code(owner: &Dev, index: u32) -> String {
    let code = format!(
        "apassy_shr_{}_{index:064x}_{}",
        owner.account,
        "ab".repeat(16)
    );
    device::share_link_hash(&code)
}

fn make_code(c: &Connect, owner: &Dev, for_account: &str, hash: &str) -> (u16, Value) {
    c.call(
        "POST",
        "/v1/account/peers/link",
        Some(&owner.token),
        Some(&json!({"link_hash": hash, "account_id": for_account})),
    )
}

fn answer_code(c: &Connect, by: &Dev, owner: &Dev, hash: &str) -> u64 {
    let message = device::peer_join_message(
        c.origin(),
        &owner.account,
        hash,
        &by.account,
        &by.key.public_key_b64(),
        &by.key.public_key_b64(),
    );
    let answer = c.call(
        "POST",
        "/v1/account/peers/join",
        Some(&by.token),
        Some(&json!({"account_id": owner.account, "link_hash": hash,
                     "signature": encode_b64(&by.key.sign(&message).unwrap())})),
    );
    assert_eq!(answer.0, 200, "{:?}", answer.1);
    answer.1["result"]["join_id"].as_u64().unwrap()
}

fn join_state(c: &Connect, by: &Dev, join_id: u64) -> (u16, Value) {
    c.call(
        "GET",
        &format!("/v1/account/peers/join/{join_id}"),
        Some(&by.token),
        None,
    )
}

/// A used code counts for the 3 of a device until it expires, and a device has at most 8
/// pending answers: a ninth ends the oldest.
#[test]
fn a_used_code_counts_until_it_expires_and_pending_answers_are_bounded() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let first = share_code(owner, 0);
    for index in 0..3 {
        assert_eq!(
            make_code(c, owner, &member.account, &share_code(owner, index)).0,
            200
        );
    }
    let oldest = answer_code(c, member, owner, &first);
    assert_eq!(
        code(&make_code(c, owner, &member.account, &share_code(owner, 3))),
        (403, Some("account_limit"))
    );
    // Codes that expire make room; their answers keep their own time.
    for index in 3..11 {
        c.edit_directory(&format!(
            "UPDATE account_peer_link SET expires_at = 1 WHERE device_id = '{}';",
            owner.id
        ));
        let hash = share_code(owner, index);
        assert_eq!(make_code(c, owner, &member.account, &hash).0, 200);
        answer_code(c, member, owner, &hash);
    }
    let pending = c.ok("GET", "/v1/account/peers/pending", Some(&owner.token), None);
    let ids: Vec<u64> = pending
        .as_array()
        .unwrap()
        .iter()
        .map(|answer| answer["join_id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids.len(), 8, "{pending}");
    assert!(!ids.contains(&oldest));
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
    assert_eq!(
        join_state(c, member, oldest).1["result"]["state"],
        "expired"
    );
}

/// A revoke ends the share codes that the device made, the pending answers to them, and
/// the answers that it gave.
#[test]
fn a_revoked_device_ends_its_share_codes_and_answers() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let anna = c.account("Anna");
    c.add_member(owner, &anna);
    let (ola_code, anna_code, open_code) = (
        share_code(owner, 1),
        share_code(owner, 2),
        share_code(owner, 3),
    );
    make_code(c, owner, &member.account, &ola_code);
    make_code(c, owner, &anna.account, &anna_code);
    make_code(c, owner, &anna.account, &open_code);
    let ola_answer = answer_code(c, member, owner, &ola_code);
    let anna_answer = answer_code(c, &anna, owner, &anna_code);
    // The answering device goes: its answer ends.
    let (status, answer) = c.revoke(member, &member.id, &member.key.public_key_b64());
    assert_eq!(status, 200, "{answer}");
    let pending = c.ok("GET", "/v1/account/peers/pending", Some(&owner.token), None);
    assert_eq!(
        pending
            .as_array()
            .unwrap()
            .iter()
            .map(|answer| answer["join_id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [anna_answer]
    );
    assert_eq!(
        c.rows(&format!(
            "SELECT state FROM account_peer_join WHERE id = {ola_answer}"
        )),
        ["expired"]
    );
    // The device that made the codes goes: the answers to them and its codes end.
    let now = connect::now();
    let (status, answer) = c.revoke(owner, &owner.id, &owner.key.public_key_b64());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        join_state(c, &anna, anna_answer).1["result"]["state"],
        "expired"
    );
    let open: Vec<String> = c.rows(&format!(
        "SELECT link_hash FROM account_peer_link WHERE device_id = '{}' AND expires_at > {}",
        owner.id,
        now + 5
    ));
    assert!(open.is_empty(), "{open:?}");
}

/// `DELETE /v1/account/peers/join/{id}`: the device that made the code refuses, the device
/// that answered withdraws, any other device gets 404, and a decided answer stays.
#[test]
fn an_answer_is_refused_by_its_maker_or_withdrawn_by_its_answerer() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let anna = c.account("Anna");
    c.add_member(owner, &anna);
    let stranger = c.account("Stranger");
    let end = |by: &Dev, join_id: u64| {
        c.call(
            "DELETE",
            &format!("/v1/account/peers/join/{join_id}"),
            Some(&by.token),
            Some(&json!({})),
        )
    };
    let (first, second) = (share_code(owner, 1), share_code(owner, 2));
    make_code(c, owner, &member.account, &first);
    make_code(c, owner, &member.account, &second);
    let refused = answer_code(c, member, owner, &first);
    let withdrawn = answer_code(c, member, owner, &second);
    for other in [&anna, &stranger] {
        assert_eq!(code(&end(other, refused)), (404, Some("not_found")));
        assert_eq!(
            code(&join_state(c, other, refused)),
            (404, Some("not_found"))
        );
    }
    assert_eq!(end(owner, refused).1["result"]["state"], "refused");
    assert_eq!(end(member, refused).1["result"]["state"], "refused");
    assert_eq!(end(member, withdrawn).1["result"]["state"], "cancelled");
    assert_eq!(end(owner, withdrawn).1["result"]["state"], "cancelled");
    assert_eq!(
        c.ok("GET", "/v1/account/peers/pending", Some(&owner.token), None),
        json!([])
    );
}

/// The signer of an entry is a live device of the list: a key whose last device entry is
/// a `remove` signs nothing (401), and a revoked device's token ends at its revoke.
#[test]
fn a_device_that_its_list_removed_signs_no_entry() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    // The list ends the key while its device row is live (the row and the list disagree).
    let (head, hash) = c.list_head(&owner.account);
    c.edit_directory(&format!(
        "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at) \
         SELECT account_id, {}, 'remove', key, NULL, NULL, key, x'00', '{hash}', 1 FROM account_list \
         WHERE account_id = '{}' AND version = 1;",
        head + 1,
        owner.account
    ));
    assert_eq!(
        code(&peer(c, owner, member)),
        (401, Some("unauthenticated"))
    );
    assert_eq!(
        c.list_head(&owner.account).0,
        head + 1,
        "nothing was stored"
    );
    // A revoked device: its token ends.
    let (status, answer) = c.revoke(member, &member.id, &member.key.public_key_b64());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        code(&peer(c, member, owner)),
        (401, Some("unauthenticated"))
    );
}

/// Each entry that adds something (`peer`, `share`, `join`; `add` in
/// `tests/server_account.rs`) is taken at version 822 and refused at 823 with 403
/// `account_limit`; each end (`unshare`, `unpeer`, `leave`; `remove` in
/// `tests/server_account.rs`) works up to 1024.
#[test]
fn each_adding_entry_stops_at_822_and_each_end_works_up_to_1024() {
    use apassy_relay::server::account::{
        LAST_ADD_VERSION, LIST_REMOVAL_RESERVE, MAX_DEVICES, MAX_LIST_ENTRIES, MAX_PEERS,
        MAX_SHARED,
    };
    assert_eq!(LIST_REMOVAL_RESERVE, MAX_DEVICES + MAX_PEERS + MAX_SHARED);
    assert_eq!((LAST_ADD_VERSION, MAX_LIST_ENTRIES), (822, 1024));
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let (anna, late) = (c.account("Anna"), c.account("Late"));
    c.add_member(owner, &anna);
    c.add_member(owner, &late);
    assert_eq!(peer(c, owner, &anna).0, 200);
    assert_eq!(peer(c, member, &anna).0, 200);
    let move_row = |account: &str, from: u64, to: u64| {
        c.edit_directory(&format!(
            "UPDATE account_list SET version = {to} WHERE account_id = '{account}' AND version = {from};"
        ));
    };
    let move_head = |account: &str, to: u64| move_row(account, c.list_head(account).0, to);
    let limited = |answer: (u16, Value)| {
        assert_eq!(code(&answer), (403, Some("account_limit")), "{answer:?}");
    };
    // The owner's peer and share at 822; nothing more at 823.
    move_head(&owner.account, LAST_ADD_VERSION - 1);
    assert_eq!(peer(c, owner, member).0, 200);
    assert_eq!(c.list_head(&owner.account).0, LAST_ADD_VERSION);
    limited(c.list_entry(owner, "share", &member.account, None, Some(&f.team)));
    move_row(&owner.account, LAST_ADD_VERSION - 1, LAST_ADD_VERSION - 2);
    move_row(&owner.account, LAST_ADD_VERSION, LAST_ADD_VERSION - 1);
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
    limited(peer(c, owner, &late));
    // The member's peer and join at 822; nothing more at 823.
    move_head(&member.account, LAST_ADD_VERSION - 1);
    assert_eq!(peer(c, member, owner).0, 200);
    limited(c.list_entry(member, "join", &owner.account, None, Some(&f.team)));
    move_row(&member.account, LAST_ADD_VERSION - 1, LAST_ADD_VERSION - 2);
    move_row(&member.account, LAST_ADD_VERSION, LAST_ADD_VERSION - 1);
    assert_eq!(
        c.list_entry(member, "join", &owner.account, None, Some(&f.team))
            .0,
        200
    );
    // The ends up to 1024: the owner's unshare at 1023 and unpeer at 1024, the member's
    // leave at 1024; nothing at 1025.
    move_head(&owner.account, MAX_LIST_ENTRIES - 2);
    assert_eq!(
        c.list_entry(owner, "unshare", &member.account, None, Some(&f.team))
            .0,
        200
    );
    assert_eq!(
        c.list_entry(owner, "unpeer", &anna.account, None, None).0,
        200
    );
    assert_eq!(c.list_head(&owner.account).0, MAX_LIST_ENTRIES);
    limited(c.list_entry(owner, "unpeer", &member.account, None, None));
    move_head(&member.account, MAX_LIST_ENTRIES - 1);
    assert_eq!(
        c.list_entry(member, "leave", &owner.account, None, Some(&f.team))
            .0,
        200
    );
    limited(c.list_entry(member, "unpeer", &owner.account, None, None));
}

/// At most 128 active shares and joins of one list together (403 `account_limit`).
#[test]
fn a_list_holds_at_most_128_shares_and_joins() {
    use apassy_relay::server::account::MAX_SHARED;
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    assert_eq!(peer(c, owner, member).0, 200);
    assert_eq!(peer(c, member, owner).0, 200);
    // A store id of base32 for each index.
    let fake_store = |index: u64| {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let tail: String = (0..10)
            .map(|place| char::from(ALPHABET[((index >> (5 * place)) & 31) as usize]))
            .collect();
        format!("t_{tail}")
    };
    // Rows that stand for entries of the list, each with the hash of the head before them.
    let fill = |account: &str, op: &str, peer_account: &str, count: u64| {
        let (head, hash) = c.list_head(account);
        let mut sql = String::new();
        for index in 0..count {
            sql.push_str(&format!(
                "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at, peer_account, peer_root, team_id) \
                 VALUES ('{account}', {}, '{op}', NULL, NULL, NULL, x'00', x'00', '{hash}', 1, '{peer_account}', NULL, '{}');",
                head + 1 + index,
                fake_store(index)
            ));
        }
        c.edit_directory(&sql);
    };
    fill(&owner.account, "share", &member.account, MAX_SHARED - 1);
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
    let second = store(c, owner, OTHER_VAULT);
    assert_eq!(
        code(&c.list_entry(owner, "share", &member.account, None, Some(&second))),
        (403, Some("account_limit"))
    );
    fill(&member.account, "join", &owner.account, MAX_SHARED);
    assert_eq!(
        code(&c.list_entry(member, "join", &owner.account, None, Some(&f.team))),
        (403, Some("account_limit"))
    );
}

/// A Connect seam of plans for these tests: each account's view, `none` for any other.
struct MapPlans(std::collections::HashMap<String, apassy_relay::api::PlanView>);

impl apassy_relay::server::account::Plans for MapPlans {
    fn plan(
        &self,
        _: &apassy_relay::server::store::Store,
        account: &str,
        _: u64,
    ) -> apassy_relay::error::RelayResult<apassy_relay::api::PlanView> {
        Ok(self
            .0
            .get(account)
            .cloned()
            .unwrap_or_else(apassy_relay::api::PlanView::none))
    }
}

fn plan_view(plan: &str, status: &str, entitled: bool) -> apassy_relay::api::PlanView {
    apassy_relay::api::PlanView {
        plan: Some(plan.into()),
        status: status.into(),
        entitled,
        ..apassy_relay::api::PlanView::none()
    }
}

/// A share needs a plan that allows sharing on both accounts: a Family on one side only
/// is 403 `plan_required`, in either direction.
#[test]
fn a_share_needs_the_plan_on_both_accounts() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    assert_eq!(peer(c, owner, member).0, 200);
    let set = |owner_plan: Option<&str>, member_plan: Option<&str>| {
        let mut plans = std::collections::HashMap::new();
        for (account, plan) in [(&owner.account, owner_plan), (&member.account, member_plan)] {
            if let Some(plan) = plan {
                plans.insert(account.clone(), plan_view(plan, "active", true));
            }
        }
        c.relay
            .hub()
            .set_plans(std::sync::Arc::new(MapPlans(plans)));
    };
    for (one, other) in [(Some("family"), None), (None, Some("family"))] {
        set(one, other);
        assert_eq!(
            code(&c.list_entry(owner, "share", &member.account, None, Some(&f.team))),
            (403, Some("plan_required"))
        );
    }
    set(Some("family"), Some("team"));
    assert_eq!(
        c.list_entry(owner, "share", &member.account, None, Some(&f.team))
            .0,
        200
    );
}

/// A member whose plan is read-only (beyond the paid seats, or after its plan ended)
/// pulls a shared store and does not push to it (403 `plan_required`); the owner pushes.
#[test]
fn a_read_only_member_pulls_a_shared_store_and_does_not_push() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    c.share_store(owner, member, &f.team);
    let added = add_to_store(c, owner, &f.team, member);
    assert_eq!(added.0, 200, "{:?}", added.1);
    let member_device = added.1["result"]["store_device_id"].as_u64().unwrap();
    c.join_store(member, owner, &f.team);
    let mut plans = std::collections::HashMap::new();
    plans.insert(owner.account.clone(), plan_view("family", "active", true));
    plans.insert(
        member.account.clone(),
        plan_view("family", "read_only", false),
    );
    c.relay
        .hub()
        .set_plans(std::sync::Arc::new(MapPlans(plans)));
    let mut pusher = connect::Pusher::new(&f.team, VAULT);
    let owner_token = c.store_token(&f.team, owner);
    let pushed = c.try_push(&pusher, &owner_token, 1, owner, b"version one");
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    pusher.pushed(1, b"version one");
    let member_token = c.store_token(&f.team, member);
    let refused = c.try_push(
        &pusher,
        &member_token,
        member_device,
        member,
        b"version two",
    );
    assert_eq!(
        (refused.status, refused.body["error"]["code"].as_str()),
        (403, Some("plan_required")),
        "{}",
        refused.body
    );
    assert_eq!(c.pull(&member_token, pusher.version), (200, 200));
}

/// Every route of shared vaults counts for the calling device: 60 a minute, then 429
/// `rate_limited` with `Retry-After`; another device and the other account routes go on.
#[test]
fn the_routes_of_shared_vaults_count_for_each_device() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    let pending = |dev: &Dev| {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let response = agent
            .get(format!("{}/v1/account/peers/pending", c.relay.url))
            .header("X-Apassy-Edge", relay::EDGE_SECRET)
            .header("Authorization", format!("Bearer {}", dev.token))
            .call()
            .unwrap();
        let retry = response
            .headers()
            .get("Retry-After")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        (response.status().as_u16(), retry)
    };
    for _ in 0..60 {
        assert_eq!(pending(owner).0, 200);
    }
    let (status, retry) = pending(owner);
    assert_eq!(status, 429);
    let retry: u64 = retry.expect("Retry-After").parse().unwrap();
    assert!((1..=60).contains(&retry), "{retry}");
    assert_eq!(
        code(&c.list_entry(
            owner,
            "peer",
            &member.account,
            Some(&member.key.public_key_b64()),
            None
        )),
        (429, Some("rate_limited"))
    );
    assert_eq!(pending(member).0, 200);
    assert_eq!(
        c.call("GET", "/v1/account", Some(&owner.token), None).0,
        200
    );
}
