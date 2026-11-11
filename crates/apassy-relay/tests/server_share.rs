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
fn a_revoked_device_signs_no_entry() {
    let f = family();
    let (c, owner, member) = (&f.c, &f.owner, &f.member);
    assert_eq!(peer(c, owner, member).0, 200);
    // The member's token ends with its account deletion; another account's key never
    // signs the owner's list.
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
