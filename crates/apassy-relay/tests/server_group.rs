//! Connect groups on the relay (plan s7 unit C3, contract connect-billing-v1 section 6,
//! docs/SPEC.md section 36): invites, joins, confirmations, roles, removal, seats through
//! billing, and the shared vault stores of a group. Each test starts its own relay with a
//! fake Stripe server on free loopback ports in a temporary directory; the subscriptions
//! come from signed synthetic webhooks, as in production. One test for each bullet of the
//! plan's C3 acceptance, and the refusals around them.

#[path = "common/connect.rs"]
mod connect;
#[path = "common/fake_stripe.rs"]
mod fake_stripe;
#[path = "common/relay.rs"]
mod relay;

use connect::{Connect, Dev, invite_code, start, store_add_body};
use serde_json::{Value, json};

const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";

/// A Family of `quantity` people bought by a new account.
fn family(c: &Connect, quantity: u32) -> Dev {
    let owner = c.account("Rafal");
    c.subscribe(&owner, "connect_family_month", quantity);
    owner
}

fn team(c: &Connect, seats: u32) -> Dev {
    let owner = c.account("Owner");
    c.subscribe(&owner, "connect_team_month", seats);
    owner
}

fn invite(c: &Connect, by: &Dev, role: &str) -> Value {
    c.ok(
        "POST",
        "/v1/account/group/invites",
        Some(&by.token),
        Some(&json!({"role": role})),
    )
}

fn join(c: &Connect, who: &Dev, code: &str) -> (u16, Value) {
    c.call(
        "POST",
        "/v1/account/group/join",
        Some(&who.token),
        Some(&json!({"code": code})),
    )
}

fn confirm(c: &Connect, by: &Dev, who: &Dev) -> (u16, Value) {
    c.call(
        "POST",
        &format!("/v1/account/group/members/{}/confirm", who.account),
        Some(&by.token),
        Some(&json!({})),
    )
}

fn remove(c: &Connect, by: &Dev, who: &Dev) -> (u16, Value) {
    c.call(
        "DELETE",
        &format!("/v1/account/group/members/{}", who.account),
        Some(&by.token),
        None,
    )
}

fn code_of(answer: &(u16, Value)) -> (u16, Option<&str>) {
    (answer.0, answer.1["error"]["code"].as_str())
}

#[test]
fn the_webhook_makes_the_group_with_the_buyer_as_owner() {
    let c = start();
    let owner = family(&c, 4);
    let group = c.ok("GET", "/v1/account/group", Some(&owner.token), None);
    assert_eq!(group["kind"], "family");
    assert_eq!(group["role"], "owner");
    assert_eq!(group["owner_account"], owner.account.as_str());
    assert_eq!(
        (group["included"].as_u64(), group["quantity"].as_u64()),
        (Some(4), Some(4))
    );
    assert_eq!(group["members"].as_array().unwrap().len(), 1);
    let view = c.ok("GET", "/v1/account", Some(&owner.token), None);
    assert_eq!(view["group"]["role"], "owner");
    assert_eq!(view["group"]["state"], "active");
    assert_eq!(view["plan"]["group_id"], group["group_id"]);
    // Without a group: 404 for the view, 403 not_in_group for the others.
    let stranger = c.account("Stranger");
    c.fails(
        "GET",
        "/v1/account/group",
        Some(&stranger.token),
        None,
        404,
        "not_found",
    );
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&stranger.token),
        Some(&json!({"role": "member"})),
        403,
        "not_in_group",
    );
    c.fails(
        "POST",
        "/v1/account/group/seats",
        Some(&stranger.token),
        Some(&json!({"quantity": 5})),
        403,
        "not_in_group",
    );
}

#[test]
fn an_invite_is_one_use_and_lives_seven_days() {
    let c = start();
    let owner = family(&c, 4);
    let made = invite(&c, &owner, "member");
    let now = connect::now();
    let expires = made["expires_at"].as_u64().unwrap();
    assert!((now + 7 * 86_400..=now + 7 * 86_400 + 5).contains(&expires));
    let url = made["url"].as_str().unwrap();
    assert!(
        url.starts_with("https://apassy.wyderka.cc/connect/join#apassy_gin_grp_"),
        "{url}"
    );
    let code = invite_code(&made);
    // Connect keeps the SHA-256 of the code, never the code.
    let stored = c.rows("SELECT hex(code_hash) FROM group_invite");
    assert_eq!(stored.len(), 1);
    assert!(!stored[0].to_lowercase().contains(&code[code.len() - 64..]));
    let (anna, bob) = (c.account("Anna"), c.account("Bob"));
    let joined = join(&c, &anna, &code);
    assert_eq!(joined.0, 200, "{}", joined.1);
    assert_eq!(joined.1["result"]["state"], "pending");
    assert_eq!(joined.1["result"]["owner_name"], "Rafal");
    // The same code again by the account that used it answers the same; by another: 403.
    assert_eq!(join(&c, &anna, &code).0, 200);
    assert_eq!(code_of(&join(&c, &bob, &code)), (403, Some("forbidden")));
    // An expired invite is refused, and so is a code that was never made.
    let late = invite_code(&invite(&c, &owner, "member"));
    c.edit_directory("UPDATE group_invite SET expires_at = 1000 WHERE used_at IS NULL");
    assert_eq!(code_of(&join(&c, &bob, &late)), (403, Some("forbidden")));
    let forged = format!("{}{}", &late[..late.len() - 64], "ab".repeat(32));
    assert_eq!(code_of(&join(&c, &bob, &forged)), (403, Some("forbidden")));
    assert_eq!(
        code_of(&join(&c, &bob, "apassy_gin_nothing")),
        (400, Some("invalid_request"))
    );
}

#[test]
fn a_pending_member_has_no_entitlement_until_confirmed() {
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    assert_eq!(
        join(&c, &anna, &invite_code(&invite(&c, &owner, "member"))).0,
        200
    );
    let plan = c.plan(&anna);
    assert_eq!(
        (plan["status"].as_str(), plan["entitled"].as_bool()),
        (Some("none"), Some(false))
    );
    c.fails(
        "GET",
        "/v1/account/entitlement",
        Some(&anna.token),
        None,
        403,
        "plan_required",
    );
    c.fails(
        "POST",
        "/v1/account/vaults",
        Some(&anna.token),
        Some(&c.vault_body(&anna, VAULT, "Anna", &connect::new_team_id())),
        403,
        "plan_required",
    );
    // A pending member sees its group, the owner, and itself only.
    let seen = c.ok("GET", "/v1/account/group", Some(&anna.token), None);
    assert_eq!(seen["role"], "member");
    assert_eq!(seen["members"].as_array().unwrap().len(), 2);
    // A pending member does not buy: its owner's plan covers it.
    c.fails(
        "POST",
        "/v1/account/checkout",
        Some(&anna.token),
        Some(&json!({"plan": "personal", "interval": "month"})),
        409,
        "conflict",
    );
    let confirmed = confirm(&c, &owner, &anna);
    assert_eq!(confirmed.0, 200, "{}", confirmed.1);
    assert_eq!(confirmed.1["result"]["state"], "active");
    let plan = c.plan(&anna);
    assert_eq!(
        (plan["plan"].as_str(), plan["entitled"].as_bool()),
        (Some("family"), Some(true))
    );
    assert_eq!(
        plan["group_id"],
        c.ok("GET", "/v1/account/group", Some(&owner.token), None)["group_id"]
    );
    let token = c.ok("GET", "/v1/account/entitlement", Some(&anna.token), None);
    assert!(token["token"].as_str().unwrap().contains('.'));
    // An active member does not buy either (409), and has no portal (403).
    c.fails(
        "POST",
        "/v1/account/checkout",
        Some(&anna.token),
        Some(&json!({"plan": "personal", "interval": "month"})),
        409,
        "conflict",
    );
    c.fails(
        "POST",
        "/v1/account/portal",
        Some(&anna.token),
        Some(&json!({})),
        403,
        "forbidden",
    );
    // An account with a group or a plan of its own cannot join another.
    let other = family(&c, 4);
    let code = invite_code(&invite(&c, &other, "member"));
    assert_eq!(code_of(&join(&c, &anna, &code)), (409, Some("conflict")));
    assert_eq!(code_of(&join(&c, &owner, &code)), (409, Some("conflict")));
}

#[test]
fn the_family_quantity_follows_the_people_and_the_team_follows_its_members() {
    let c = start();
    // A Family of 4 people: three members fit without a change at Stripe.
    let owner = family(&c, 4);
    let people: Vec<Dev> = (0..3).map(|n| c.account(&format!("Person {n}"))).collect();
    for person in &people {
        c.add_member(&owner, person);
    }
    assert!(
        c.stripe
            .calls_to("POST", "/v1/subscription_items/si_")
            .is_empty()
    );
    let item = format!("/v1/subscription_items/si_{}", &owner.account[4..]);
    assert!(c.stripe.calls_to("POST", &item).is_empty());
    // The fifth person raises the quantity to 5 with prorations; Connect applies it only
    // when the webhook arrives.
    let fifth = c.account("Person 4");
    c.add_member(&owner, &fifth);
    let calls = c.stripe.calls_to("POST", &item);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].field("quantity"), Some("5"));
    assert_eq!(
        calls[0].field("proration_behavior"),
        Some("create_prorations")
    );
    assert!(calls[0].header("Idempotency-Key").is_some());
    assert_eq!(c.plan(&owner)["quantity"], 4);
    c.update(&owner, "connect_family_month", 5, "active");
    assert_eq!(c.plan(&owner)["quantity"], 5);
    assert_eq!(
        c.ok("GET", "/v1/account/group", Some(&owner.token), None)["quantity"],
        5
    );
    // Seats below the members: 409 seat_limit, and no call.
    c.stripe.clear_calls();
    c.fails(
        "POST",
        "/v1/account/group/seats",
        Some(&owner.token),
        Some(&json!({"quantity": 4})),
        409,
        "seat_limit",
    );
    c.fails(
        "POST",
        "/v1/account/group/seats",
        Some(&owner.token),
        Some(&json!({"quantity": 11})),
        409,
        "seat_limit",
    );
    assert!(c.stripe.calls().is_empty());
    let seats = c.ok(
        "POST",
        "/v1/account/group/seats",
        Some(&owner.token),
        Some(&json!({"quantity": 6})),
    );
    assert_eq!(seats, json!({"quantity": 6, "pending": true}));
    // Only the owner changes the seats.
    c.fails(
        "POST",
        "/v1/account/group/seats",
        Some(&fifth.token),
        Some(&json!({"quantity": 7})),
        403,
        "forbidden",
    );
    // At the maximum of 10 people a further confirm is 409 seat_limit.
    // The owner, five people, and five more are the ten of the maximum.
    c.update(&owner, "connect_family_month", 10, "active");
    for n in 5..10 {
        let person = c.account(&format!("Person {n}"));
        c.add_member(&owner, &person);
    }
    let eleventh = c.account("Person 11");
    assert_eq!(
        join(&c, &eleventh, &invite_code(&invite(&c, &owner, "member"))).0,
        200
    );
    assert_eq!(
        code_of(&confirm(&c, &owner, &eleventh)),
        (409, Some("seat_limit"))
    );
    assert_eq!(c.plan(&eleventh)["entitled"], false);

    // A Team of one seat: each confirmed member is a seat.
    let boss = team(&c, 1);
    let worker = c.account("Worker");
    c.add_member(&boss, &worker);
    let item = format!("/v1/subscription_items/si_{}", &boss.account[4..]);
    let calls = c.stripe.calls_to("POST", &item);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].field("quantity"), Some("2"));
    c.update(&boss, "connect_team_month", 2, "active");
    let group = c.ok("GET", "/v1/account/group", Some(&boss.token), None);
    assert_eq!(
        (group["included"].as_u64(), group["quantity"].as_u64()),
        (Some(1), Some(2))
    );
    c.fails(
        "POST",
        "/v1/account/group/seats",
        Some(&boss.token),
        Some(&json!({"quantity": 1})),
        409,
        "seat_limit",
    );
}

#[test]
fn a_removed_member_keeps_a_free_account_and_leaves_the_shared_stores() {
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    c.add_member(&owner, &anna);
    let store = c.ok(
        "POST",
        "/v1/account/vaults",
        Some(&owner.token),
        Some(&c.vault_body(&owner, VAULT, "Family", &connect::new_team_id())),
    );
    let team = store["team_id"].as_str().unwrap().to_string();
    c.share_store(&owner, &anna, &team);
    let added = c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&owner.token),
        Some(&store_add_body(&anna)),
    );
    assert_eq!(added["account_id"], anna.account.as_str());
    let listed = c.ok("GET", "/v1/account/vaults", Some(&anna.token), None);
    assert_eq!(listed[0]["shared"], true);
    assert_eq!(c.plan(&anna)["entitled"], true);
    let removed = remove(&c, &owner, &anna);
    assert_eq!(removed.0, 200, "{}", removed.1);
    assert_eq!(
        removed.1["result"],
        json!({"account_id": anna.account, "removed_from_stores": 1})
    );
    // At once: no entitlement, no group, out of the store; the account and its device live.
    let plan = c.plan(&anna);
    assert_eq!(
        (plan["status"].as_str(), plan["entitled"].as_bool()),
        (Some("none"), Some(false))
    );
    c.fails(
        "GET",
        "/v1/account/entitlement",
        Some(&anna.token),
        None,
        403,
        "plan_required",
    );
    let view = c.ok("GET", "/v1/account", Some(&anna.token), None);
    assert!(view["group"].is_null());
    assert_eq!(view["devices"].as_array().unwrap().len(), 1);
    assert_eq!(
        c.ok("GET", "/v1/account/vaults", Some(&anna.token), None),
        json!([])
    );
    let devices = c.ok("GET", "/v1/account/vaults", Some(&owner.token), None)[0]["devices"].clone();
    assert_eq!(devices.as_array().unwrap().len(), 1);
    // Out of the group, the device cannot be added again.
    c.fails(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&owner.token),
        Some(&store_add_body(&anna)),
        403,
        "not_in_group",
    );
}

#[test]
fn a_members_device_joins_a_shared_store_and_a_strangers_does_not() {
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    let stranger = c.account("Stranger");
    let pending = c.account("Pending");
    c.add_member(&owner, &anna);
    assert_eq!(
        join(&c, &pending, &invite_code(&invite(&c, &owner, "member"))).0,
        200
    );
    let team = c.ok(
        "POST",
        "/v1/account/vaults",
        Some(&owner.token),
        Some(&c.vault_body(&owner, VAULT, "Family", &connect::new_team_id())),
    )["team_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/v1/account/vaults/{team}/devices");
    // A member of the group without a signed share of the store is refused too.
    for outsider in [&stranger, &pending, &anna] {
        c.fails(
            "POST",
            &path,
            Some(&owner.token),
            Some(&store_add_body(outsider)),
            403,
            "not_in_group",
        );
    }
    c.share_store(&owner, &anna, &team);
    let added = c.ok(
        "POST",
        &path,
        Some(&owner.token),
        Some(&store_add_body(&anna)),
    );
    assert_eq!(added["store_device_id"], 2);
    // The member's device, now in the store, may add the owner's other devices; a stranger
    // cannot add itself.
    c.fails(
        "POST",
        &path,
        Some(&stranger.token),
        Some(&store_add_body(&stranger)),
        403,
        "forbidden",
    );
}

#[test]
fn roles_only_the_owner_removes_an_admin_and_a_family_has_no_admins() {
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    c.add_member(&owner, &anna);
    // A Family has one organizer and no admins; a member does not invite.
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&owner.token),
        Some(&json!({"role": "admin"})),
        403,
        "forbidden",
    );
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&anna.token),
        Some(&json!({"role": "member"})),
        403,
        "forbidden",
    );
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&owner.token),
        Some(&json!({"role": "owner"})),
        400,
        "invalid_request",
    );
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&owner.token),
        Some(&json!({"role": "member", "extra": 1})),
        400,
        "invalid_request",
    );
    // The owner cannot be removed, by anyone; a member may remove itself.
    assert_eq!(
        code_of(&remove(&c, &anna, &owner)),
        (403, Some("forbidden"))
    );
    assert_eq!(
        code_of(&remove(&c, &owner, &owner)),
        (403, Some("forbidden"))
    );
    assert_eq!(remove(&c, &anna, &anna).0, 200);
    assert!(c.ok("GET", "/v1/account", Some(&anna.token), None)["group"].is_null());

    // A Team: the owner invites an admin; an admin invites members, not admins, and
    // removes members, not admins.
    let boss = team(&c, 5);
    let (admin, other_admin, member) = (
        c.account("Admin"),
        c.account("Admin 2"),
        c.account("Member"),
    );
    for (who, role) in [(&admin, "admin"), (&other_admin, "admin")] {
        let code = invite_code(&invite(&c, &boss, role));
        assert_eq!(join(&c, who, &code).0, 200);
        assert_eq!(confirm(&c, &boss, who).0, 200);
    }
    assert_eq!(
        c.ok("GET", "/v1/account/group", Some(&admin.token), None)["role"],
        "admin"
    );
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&admin.token),
        Some(&json!({"role": "admin"})),
        403,
        "forbidden",
    );
    let code = invite_code(&invite(&c, &admin, "member"));
    assert_eq!(join(&c, &member, &code).0, 200);
    let confirmed = confirm(&c, &admin, &member);
    assert_eq!(confirmed.0, 200, "{}", confirmed.1);
    assert_eq!(
        code_of(&remove(&c, &admin, &other_admin)),
        (403, Some("forbidden"))
    );
    assert_eq!(
        code_of(&remove(&c, &member, &admin)),
        (403, Some("forbidden"))
    );
    assert_eq!(
        code_of(&confirm(&c, &member, &admin)),
        (403, Some("forbidden"))
    );
    assert_eq!(remove(&c, &admin, &member).0, 200);
    assert_eq!(remove(&c, &boss, &other_admin).0, 200);
    // A member of another group is not found in this one.
    assert_eq!(code_of(&remove(&c, &boss, &anna)), (404, Some("not_found")));
}

#[test]
fn an_owner_with_confirmed_members_cannot_delete_the_account() {
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    c.add_member(&owner, &anna);
    c.fails(
        "DELETE",
        "/v1/account",
        Some(&owner.token),
        Some(&json!({})),
        409,
        "conflict",
    );
    // A member deletes its own account: it leaves the group.
    let deleted = c.ok("DELETE", "/v1/account", Some(&anna.token), Some(&json!({})));
    assert_eq!(deleted["subscription_canceled"], false);
    let group = c.ok("GET", "/v1/account/group", Some(&owner.token), None);
    assert_eq!(group["members"].as_array().unwrap().len(), 1);
    // Now the owner can: the subscription is canceled at Stripe at once, the group goes.
    let deleted = c.ok(
        "DELETE",
        "/v1/account",
        Some(&owner.token),
        Some(&json!({})),
    );
    assert_eq!(deleted["subscription_canceled"], true);
    let cancel = format!("/v1/subscriptions/sub_{}", &owner.account[4..]);
    assert_eq!(c.stripe.calls_to("DELETE", &cancel).len(), 1);
    assert!(c.rows("SELECT id FROM \"group\"").is_empty());
    assert!(c.rows("SELECT account_id FROM group_member").is_empty());
}

/// A removed member leaves every shared store, also when one store file refuses the write:
/// the removal goes on to the next store, the member is out of both at once (no relay-sync
/// sign-in), and the refused store gets the revoke at the next maintenance pass.
#[test]
fn a_member_removal_goes_on_past_a_store_that_refuses_the_write() {
    use apassy_relay::ids::TeamId;
    use apassy_relay::server::store::db;
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    c.add_member(&owner, &anna);
    let mut stores = Vec::new();
    for vault in [VAULT, "1f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77"] {
        let team = c.ok(
            "POST",
            "/v1/account/vaults",
            Some(&owner.token),
            Some(&c.vault_body(&owner, vault, "Family", &connect::new_team_id())),
        )["team_id"]
            .as_str()
            .unwrap()
            .to_string();
        c.share_store(&owner, &anna, &team);
        c.ok(
            "POST",
            &format!("/v1/account/vaults/{team}/devices"),
            Some(&owner.token),
            Some(&store_add_body(&anna)),
        );
        stores.push(TeamId::parse(&team).unwrap());
    }
    let hub = c.relay.hub();
    let query_only = |team: &TeamId, on: bool| {
        let sql = if on {
            "PRAGMA query_only = 1;"
        } else {
            "PRAGMA query_only = 0;"
        };
        hub.team(team)
            .unwrap()
            .store
            .with(|conn| conn.execute_batch(sql).map_err(db))
            .unwrap();
    };
    let revoked = |team: &TeamId| -> bool {
        hub.team(team)
            .unwrap()
            .store
            .with(|conn| {
                conn.query_row(
                    "SELECT revoked_at IS NOT NULL FROM device WHERE name = ?1",
                    [anna.id.as_str()],
                    |row| row.get(0),
                )
                .map_err(db)
            })
            .unwrap()
    };
    query_only(&stores[0], true);
    let removed = remove(&c, &owner, &anna);
    assert_eq!(removed.0, 200, "{}", removed.1);
    assert_eq!(removed.1["result"]["removed_from_stores"], 2);
    assert!(!revoked(&stores[0]));
    assert!(revoked(&stores[1]));
    assert_eq!(
        c.rows("SELECT team_id FROM account_store_removal"),
        [stores[0].to_string()]
    );
    // Out of both at once: the relay-sync sign-in of each store refuses the device (a
    // challenge writes to its store, so the first one takes writes again for it).
    query_only(&stores[0], false);
    for team in &stores {
        let (status, _) = c.call(
            "POST",
            "/v1/auth/challenge",
            None,
            Some(&json!({"team_id": team, "public_key": anna.key.public_key_b64()})),
        );
        assert_eq!(status, 401, "{team}");
    }
    apassy_relay::server::http::maintain(
        &hub,
        connect::now() + apassy_relay::server::hub::STORE_REMOVAL_MAX_WAIT_SECS,
    );
    assert!(revoked(&stores[0]));
    assert!(
        c.rows("SELECT team_id FROM account_store_removal")
            .is_empty()
    );
}

/// A member removed while the store file refuses the write, who joins again and is added
/// to the store again before the removal lands: the store keeps its row (the add clears
/// the removal that waited for it), and a maintenance pass leaves the member in the store.
#[test]
fn a_store_device_added_again_clears_the_removal_that_waited_for_it() {
    use apassy_relay::ids::TeamId;
    use apassy_relay::server::store::db;
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    c.add_member(&owner, &anna);
    let team = c.ok(
        "POST",
        "/v1/account/vaults",
        Some(&owner.token),
        Some(&c.vault_body(&owner, VAULT, "Family", &connect::new_team_id())),
    )["team_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/v1/account/vaults/{team}/devices");
    c.share_store(&owner, &anna, &team);
    let first = c.ok(
        "POST",
        &path,
        Some(&owner.token),
        Some(&store_add_body(&anna)),
    );
    let id = TeamId::parse(&team).unwrap();
    let hub = c.relay.hub();
    let query_only = |on: bool| {
        let sql = if on {
            "PRAGMA query_only = 1;"
        } else {
            "PRAGMA query_only = 0;"
        };
        hub.team(&id)
            .unwrap()
            .store
            .with(|conn| conn.execute_batch(sql).map_err(db))
            .unwrap();
    };
    query_only(true);
    let removed = remove(&c, &owner, &anna);
    assert_eq!(removed.0, 200, "{}", removed.1);
    query_only(false);
    assert_eq!(
        c.rows("SELECT team_id FROM account_store_removal"),
        std::slice::from_ref(&team)
    );
    // Anna joins again and is added again after a newer share (the removal voided the
    // old one): the live row of the store is hers again, and she signs in after her join.
    c.add_member(&owner, &anna);
    for op in ["unshare", "share"] {
        let (status, answer) = c.list_entry(&owner, op, &anna.account, None, Some(&team));
        assert_eq!(status, 200, "{answer}");
    }
    let again = c.ok(
        "POST",
        &path,
        Some(&owner.token),
        Some(&store_add_body(&anna)),
    );
    assert_eq!(again["store_device_id"], first["store_device_id"]);
    assert!(
        c.rows("SELECT team_id FROM account_store_removal")
            .is_empty()
    );
    apassy_relay::server::http::maintain(
        &hub,
        connect::now() + apassy_relay::server::hub::STORE_REMOVAL_MAX_WAIT_SECS,
    );
    c.join_store(&anna, &owner, &team);
    let (status, answer) = c.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": anna.key.public_key_b64()})),
    );
    assert_eq!(status, 200, "{answer}");
}

/// A store device of another account signs in to a store only while both accounts are/// A store device of another account signs in to a store only while both accounts are
/// active members of one group: a membership that ends, also one whose store rows were
/// left behind, ends its store sign-in.
#[test]
fn a_members_store_sign_in_needs_the_group() {
    let c = start();
    let owner = family(&c, 4);
    let anna = c.account("Anna");
    c.add_member(&owner, &anna);
    let team = c.ok(
        "POST",
        "/v1/account/vaults",
        Some(&owner.token),
        Some(&c.vault_body(&owner, VAULT, "Family", &connect::new_team_id())),
    )["team_id"]
        .as_str()
        .unwrap()
        .to_string();
    c.share_store(&owner, &anna, &team);
    c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&owner.token),
        Some(&store_add_body(&anna)),
    );
    let challenge = |dev: &Dev| {
        c.call(
            "POST",
            "/v1/auth/challenge",
            None,
            Some(&json!({"team_id": team, "public_key": dev.key.public_key_b64()})),
        )
        .0
    };
    c.join_store(&anna, &owner, &team);
    assert_eq!(challenge(&anna), 200);
    // The membership goes and its store rows stay (a removal that did not run to its end):
    // the sign-in is refused all the same; the owner's own device signs in.
    c.edit_directory(&format!(
        "DELETE FROM group_member WHERE account_id = '{}';",
        anna.account
    ));
    assert_eq!(
        c.rows("SELECT device_id FROM account_store_device").len(),
        2
    );
    assert_eq!(challenge(&anna), 401);
    assert_eq!(challenge(&owner), 200);
}

// ---- Paid seats under one lock of the group (the review of billing and groups). ----

/// `who` joins the group of `owner` and stays pending.
fn pending(c: &Connect, owner: &Dev, name: &str) -> Dev {
    let who = c.account(name);
    let code = invite_code(&invite(c, owner, "member"));
    assert_eq!(join(c, &who, &code).0, 200);
    who
}

/// Confirms each of `who` at once, one thread each; answers the statuses.
fn confirm_all(c: &Connect, owner: &Dev, who: &[Dev]) -> Vec<(u16, Option<String>)> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = who
            .iter()
            .map(|dev| {
                let url = c.relay.url.clone();
                let token = owner.token.clone();
                let path = format!("/v1/account/group/members/{}/confirm", dev.account);
                scope.spawn(move || {
                    let (status, value) = relay::call_url(
                        &url,
                        Some(relay::EDGE_SECRET),
                        "POST",
                        &path,
                        Some(&token),
                        Some(&json!({})),
                    );
                    (status, value["error"]["code"].as_str().map(str::to_string))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn active_members(c: &Connect, owner: &Dev) -> usize {
    c.ok("GET", "/v1/account/group", Some(&owner.token), None)["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["state"] == "active")
        .count()
}

/// The quantities billing asked Stripe for, in order.
fn asked(c: &Connect, owner: &Dev) -> Vec<u32> {
    c.stripe
        .calls_to(
            "POST",
            &format!("/v1/subscription_items/si_{}", &owner.account[4..]),
        )
        .iter()
        .map(|call| call.field("quantity").unwrap().parse().unwrap())
        .collect()
}

#[test]
fn confirms_at_once_never_pass_the_plans_maximum() {
    let c = start();
    let owner = family(&c, 8);
    for n in 0..7 {
        let person = c.account(&format!("Person {n}"));
        c.add_member(&owner, &person);
    }
    let waiting: Vec<Dev> = (0..4)
        .map(|n| pending(&c, &owner, &format!("Late {n}")))
        .collect();
    // Eight people are paid for; each confirm asks Stripe for one more, and Stripe takes
    // its time with the first answer.
    c.stripe.delay_next("/v1/subscription_items/", 500);
    let answers = confirm_all(&c, &owner, &waiting);
    let ok = answers.iter().filter(|(status, _)| *status == 200).count();
    let full = answers
        .iter()
        .filter(|(status, code)| *status == 409 && code.as_deref() == Some("seat_limit"))
        .count();
    assert_eq!((ok, full), (2, 2), "{answers:?}");
    assert_eq!(active_members(&c, &owner), 10);
    assert_eq!(asked(&c, &owner), [9, 10]);
}

#[test]
fn confirms_at_once_each_raise_the_seats_they_need() {
    let c = start();
    let owner = team(&c, 1);
    let waiting: Vec<Dev> = (0..5)
        .map(|n| pending(&c, &owner, &format!("Worker {n}")))
        .collect();
    let answers = confirm_all(&c, &owner, &waiting);
    assert!(
        answers.iter().all(|(status, _)| *status == 200),
        "{answers:?}"
    );
    assert_eq!(active_members(&c, &owner), 6);
    // Each confirm counted the one before it: the asks rise to the six members.
    assert_eq!(asked(&c, &owner), [2, 3, 4, 5, 6]);
    for dev in &waiting {
        assert_eq!(c.plan(dev)["entitled"], true, "{}", dev.account);
    }
}

#[test]
fn a_confirm_waits_for_a_seats_change_of_the_same_group() {
    let c = start();
    let owner = team(&c, 3);
    let member = c.account("Member");
    c.add_member(&owner, &member);
    let late = pending(&c, &owner, "Late");
    // The owner lowers the seats to the two members; Stripe takes a second to answer.
    c.stripe.delay_next("/v1/subscription_items/", 1000);
    let (url, token) = (c.relay.url.clone(), owner.token.clone());
    std::thread::scope(|scope| {
        let lower = scope.spawn(move || {
            relay::call_url(
                &url,
                Some(relay::EDGE_SECRET),
                "POST",
                "/v1/account/group/seats",
                Some(&token),
                Some(&json!({"quantity": 2})),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let confirmed = confirm(&c, &owner, &late);
        assert_eq!(confirmed.0, 200, "{}", confirmed.1);
        assert_eq!(lower.join().unwrap().0, 200);
    });
    // The confirm counted after the change: Stripe's last word covers the three members.
    assert_eq!(asked(&c, &owner), [2, 3]);
    assert_eq!(active_members(&c, &owner), 3);
    assert_eq!(c.plan(&late)["entitled"], true);
}

#[test]
fn a_confirm_that_stripe_refuses_leaves_the_member_pending() {
    let c = start();
    let owner = team(&c, 1);
    let late = pending(&c, &owner, "Late");
    c.stripe.fail_path("/v1/subscription_items/", 400, 1);
    assert_eq!(
        code_of(&confirm(&c, &owner, &late)),
        (502, Some("upstream_failed"))
    );
    assert_eq!(active_members(&c, &owner), 1);
    assert_eq!(c.plan(&late)["status"], "none");
    assert_eq!(
        c.rows("SELECT action FROM audit WHERE action = 'group_member_confirm_undone'")
            .len(),
        1
    );
    // Asked again, it works.
    assert_eq!(confirm(&c, &owner, &late).0, 200);
    assert_eq!(active_members(&c, &owner), 2);
}

/// A store row of the member that came while its confirmation waited for Stripe goes
/// in the transaction that makes it pending again, with a waiting removal for the file.
#[test]
fn a_confirm_that_stripe_refuses_removes_the_store_rows_of_its_window() {
    let c = start();
    let owner = team(&c, 1);
    let late = pending(&c, &owner, "Late");
    let (store, _) = c.store(&owner, VAULT);
    c.stripe.delay_next("/v1/subscription_items/", 1500);
    c.stripe.fail_path("/v1/subscription_items/", 400, 1);
    std::thread::scope(|scope| {
        let confirmed = scope.spawn(|| confirm(&c, &owner, &late));
        std::thread::sleep(std::time::Duration::from_millis(500));
        // The member is active for the moment: a row of its device in the owner's store.
        c.edit_directory(&format!(
            "INSERT INTO account_store_device (team_id, device_id, account_id, store_device, added_at) \
             VALUES ('{store}', '{}', '{}', 2, 1);",
            late.id, late.account
        ));
        assert_eq!(
            code_of(&confirmed.join().unwrap()),
            (502, Some("upstream_failed"))
        );
    });
    assert_eq!(active_members(&c, &owner), 1);
    assert!(
        c.rows(&format!(
            "SELECT device_id FROM account_store_device WHERE device_id = '{}'",
            late.id
        ))
        .is_empty()
    );
    assert_eq!(
        c.rows("SELECT action FROM audit WHERE action = 'group_member_confirm_undone'")
            .len(),
        1
    );
}

/// A confirmation that goes back to pending voids, in its transaction, the shares that
/// name the member and the shares that the member made (as a removal from the group
/// does), each from the head of its owner's list: a share of its window counts for nothing
/// after a later confirmation.
#[test]
fn a_confirm_that_stripe_refuses_voids_the_shares_of_its_window() {
    let c = start();
    let owner = team(&c, 1);
    let late = pending(&c, &owner, "Late");
    c.stripe.delay_next("/v1/subscription_items/", 1500);
    c.stripe.fail_path("/v1/subscription_items/", 400, 1);
    // Rows that stand for a `share` of each list naming the other, each after its head.
    let share_row = |of: &Dev, names: &Dev, team: &str| {
        let row = c.rows(&format!(
            "SELECT version || ' ' || hash FROM account_list WHERE account_id = '{}' \
             ORDER BY version DESC LIMIT 1",
            of.account
        ));
        let (head, hash) = row[0].split_once(' ').unwrap();
        let version: u64 = head.parse::<u64>().unwrap() + 1;
        c.edit_directory(&format!(
            "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at, peer_account, peer_root, team_id) \
             VALUES ('{}', {version}, 'share', NULL, NULL, NULL, x'00', x'00', '{hash}', 1, '{}', NULL, '{team}');",
            of.account, names.account
        ));
        version
    };
    let versions = std::thread::scope(|scope| {
        let confirmed = scope.spawn(|| confirm(&c, &owner, &late));
        std::thread::sleep(std::time::Duration::from_millis(500));
        let versions = (
            share_row(&owner, &late, "t_aaaaaaaaaa"),
            share_row(&late, &owner, "t_bbbbbbbbbb"),
        );
        assert_eq!(
            code_of(&confirmed.join().unwrap()),
            (502, Some("upstream_failed"))
        );
        versions
    });
    assert_eq!(active_members(&c, &owner), 1);
    let mut marks = c
        .rows("SELECT account_id || ' ' || peer_account || ' ' || version FROM account_share_void");
    marks.sort();
    let mut wanted = vec![
        format!("{} {} {}", owner.account, late.account, versions.0),
        format!("{} {} {}", late.account, owner.account, versions.1),
    ];
    wanted.sort();
    assert_eq!(marks, wanted);
}

#[test]
fn after_a_switch_to_personal_the_family_has_no_plan_and_its_members_read_only() {
    let c = start();
    let owner = family(&c, 4);
    let member = c.account("Ola");
    c.add_member(&owner, &member);
    c.store(&member, VAULT);
    // The owner switches to Personal in the portal.
    c.update(&owner, "connect_personal_month", 1, "active");
    let mine = c.plan(&owner);
    assert_eq!(
        (mine["plan"].as_str(), mine["entitled"].as_bool()),
        (Some("personal"), Some(true))
    );
    let theirs = c.plan(&member);
    assert_eq!(
        (theirs["status"].as_str(), theirs["entitled"].as_bool()),
        (Some("read_only"), Some(false))
    );
    assert!(theirs["delete_at"].is_null(), "{theirs}");
    c.fails(
        "POST",
        "/v1/account/group/invites",
        Some(&owner.token),
        Some(&json!({"role": "member"})),
        403,
        "plan_required",
    );
    // The view keeps a number for the app: the quantity of the group's last subscription.
    assert_eq!(
        c.ok("GET", "/v1/account/group", Some(&owner.token), None)["quantity"],
        1
    );
}

#[test]
fn a_late_event_of_an_old_plan_never_deletes_the_stores_of_a_paid_group() {
    let c = start();
    let owner = family(&c, 4);
    let member = c.account("Ola");
    c.add_member(&owner, &member);
    let (team, _) = c.store(&member, VAULT);
    let customer = c.customer_of(&owner);
    let old = format!("sub_{}", &owner.account[4..]);
    c.update(&owner, "connect_family_month", 4, "canceled");
    // The owner buys again: a new subscription keeps the group.
    let new = format!("{old}2");
    c.deliver_ok(&c.checkout_completed(&owner.account, &customer, &new));
    c.deliver_ok(&c.subscription_event(
        "created",
        &owner.account,
        &customer,
        &new,
        "connect_family_month",
        4,
        "active",
    ));
    // A late event of the old subscription, the newest of all.
    c.deliver_ok(&c.subscription_event(
        "updated",
        &owner.account,
        &customer,
        &old,
        "connect_family_month",
        4,
        "canceled",
    ));
    assert_eq!(c.plan(&member)["entitled"], true);
    // The old plan's deletion day: the members keep their stores.
    c.end_subscription_at(&old, connect::now() - 91 * 86_400);
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    // The pass handled the old plan: Stripe shows it ended, and only the owner, whose new
    // plan is paid, was a candidate.
    assert_eq!(
        apassy_relay::server::billing_store::maintain(&hub, &billing, connect::now()).unwrap(),
        1
    );
    let audit = c.rows("SELECT detail FROM audit WHERE action = 'plan_stores_deleted'");
    let detail: Value = serde_json::from_str(&audit[0]).unwrap();
    assert_eq!(
        (detail["subscription"].as_str(), detail["accounts"].as_u64()),
        (Some(old.as_str()), Some(0))
    );
    assert!(c.rows("SELECT id FROM team").contains(&team));
    assert_eq!(c.plan(&member)["entitled"], true);
}

#[test]
fn joining_a_group_ends_the_checkout_the_account_had_open() {
    let c = start();
    let owner = family(&c, 4);
    let who = c.account("Ola");
    c.stripe.set_session_expires_at(connect::now() + 86_400);
    let session = c.ok(
        "POST",
        "/v1/account/checkout",
        Some(&who.token),
        Some(&json!({"plan": "personal", "interval": "month"})),
    )["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(c.stripe.session_status(&session).as_deref(), Some("open"));
    let code = invite_code(&invite(&c, &owner, "member"));
    let (status, answer) = join(&c, &who, &code);
    assert_eq!(status, 200, "{answer}");
    // Stripe ended it, and Connect forgot it.
    assert_eq!(
        c.stripe.session_status(&session).as_deref(),
        Some("expired")
    );
    assert_eq!(
        c.rows(&format!(
            "SELECT coalesce(checkout_session, '-') FROM stripe_customer WHERE account_id = '{}'",
            who.account
        )),
        ["-"]
    );
}

#[test]
fn a_buyer_whose_data_waits_keeps_the_stores_of_its_members_too() {
    let c = start();
    let owner = family(&c, 4);
    let member = c.account("Ola");
    c.add_member(&owner, &member);
    let (team, _) = c.store(&member, VAULT);
    let old = format!("sub_{}", &owner.account[4..]);
    c.update(&owner, "connect_family_month", 4, "canceled");
    c.end_subscription_at(&old, connect::now() - 91 * 86_400);
    assert_eq!(c.plan(&member)["status"], "none");
    // Stripe has another subscription of the owner that is not over: the owner's data
    // waits, and so does the data of its members.
    let mut newer = c.stripe.subscription(&old).unwrap();
    newer["id"] = json!(format!("{old}2"));
    newer["status"] = json!("past_due");
    newer["ended_at"] = Value::Null;
    c.stripe.put_subscription(newer);
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    assert_eq!(
        apassy_relay::server::billing_store::maintain(&hub, &billing, connect::now()).unwrap(),
        0
    );
    assert!(c.rows("SELECT id FROM team").contains(&team));
    assert!(
        c.rows("SELECT detail FROM audit WHERE action = 'plan_stores_deleted'")
            .is_empty()
    );
}
