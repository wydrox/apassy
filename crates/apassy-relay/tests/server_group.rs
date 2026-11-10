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

use connect::{Connect, Dev, invite_code, start};
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
        Some(&json!({"vault_id": VAULT, "name": "Anna"})),
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
        Some(&json!({"vault_id": VAULT, "name": "Family"})),
    );
    let team = store["team_id"].as_str().unwrap().to_string();
    let added = c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&owner.token),
        Some(&json!({"device_id": anna.id})),
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
        Some(&json!({"device_id": anna.id})),
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
        Some(&json!({"vault_id": VAULT, "name": "Family"})),
    )["team_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/v1/account/vaults/{team}/devices");
    for outsider in [&stranger, &pending] {
        c.fails(
            "POST",
            &path,
            Some(&owner.token),
            Some(&json!({"device_id": outsider.id})),
            403,
            "not_in_group",
        );
    }
    let added = c.ok(
        "POST",
        &path,
        Some(&owner.token),
        Some(&json!({"device_id": anna.id})),
    );
    assert_eq!(added["store_device_id"], 2);
    // The member's device, now in the store, may add the owner's other devices; a stranger
    // cannot add itself.
    c.fails(
        "POST",
        &path,
        Some(&stranger.token),
        Some(&json!({"device_id": stranger.id})),
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
