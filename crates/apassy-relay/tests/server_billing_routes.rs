//! Connect billing over HTTP (plan s7 unit C2, the wiring step; contract connect-billing-v1;
//! docs/SPEC.md section 34): the routes, the raw webhook, the plan of an account from the
//! directory tables, the capability gates of every plan state on a real vault store, the
//! maintenance pass, the account deletion, the price warm-up, and the settings. The
//! handlers' own logic is tested in `server_billing.rs` against the in-memory store; this
//! file tests what needed the routes. Each test starts its own relay and fake Stripe on
//! free loopback ports in a temporary directory.

#[path = "common/connect.rs"]
mod connect;
#[path = "common/fake_stripe.rs"]
mod fake_stripe;
#[path = "common/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use apassy_relay::config::{ConnectConfig, RelayConfig};
use apassy_relay::secret::SecretString;
use apassy_relay::server::billing_store::maintain;
use apassy_relay::server::operator::{Command, run};
use apassy_relay::server::stripe::signature_header;
use connect::{Connect, Dev, Pusher, WEBHOOK_SECRET, now, start, start_with_config};
use serde_json::{Value, json};

const PLANS: &str = include_str!("../../../tests/fixtures/connect-billing-v1/plans.json");
const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
const DAY: u64 = 86_400;

fn wait_for(what: &str, check: impl Fn() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < Duration::from_secs(10), "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_prices_are_read_at_start_and_the_plans_are_public() {
    let c = start();
    // The warm-up at start asks Stripe without any request to the relay.
    wait_for("the price warm-up", || {
        !c.stripe.calls_to("GET", "/v1/prices").is_empty()
    });
    let call = &c.stripe.calls_to("GET", "/v1/prices")[0];
    assert_eq!(
        call.header("Authorization"),
        Some("Bearer rk_test_FAKE_apassy_billing_tests")
    );
    assert_eq!(call.header("Stripe-Version"), Some("2025-03-31.basil"));
    let plans = c.ok("GET", "/v1/plans", None, None);
    let fixture: Value = serde_json::from_str(PLANS).unwrap();
    assert_eq!(plans, fixture);
    // The cache answers: one lookup for the warm-up and the request.
    assert_eq!(c.stripe.calls_to("GET", "/v1/prices").len(), 1);
    c.fails(
        "GET",
        "/v1/plans",
        Some("apassy_act_acc_aaaaaaaaaa_00"),
        None,
        400,
        "invalid_request",
    );
    c.fails(
        "POST",
        "/v1/plans",
        None,
        Some(&json!({})),
        405,
        "method_not_allowed",
    );
    c.fails(
        "GET",
        "/v1/stripe/webhook",
        None,
        None,
        405,
        "method_not_allowed",
    );
}

#[test]
fn a_checkout_over_http_sends_the_contract_form_and_changes_nothing() {
    let c = start();
    let a = c.account("Rafal");
    let answer = c.ok(
        "POST",
        "/v1/account/checkout",
        Some(&a.token),
        Some(&json!({"plan": "family", "interval": "year", "people": 6})),
    );
    assert!(
        answer["url"]
            .as_str()
            .unwrap()
            .starts_with("https://checkout.stripe.com/")
    );
    assert!(
        answer["session_id"]
            .as_str()
            .unwrap()
            .starts_with("cs_test_")
    );
    let calls = c.stripe.calls_to("POST", "/v1/checkout/sessions");
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    for (field, value) in [
        ("mode", "subscription"),
        ("line_items[0][price]", "price_SynthFamilyYear"),
        ("line_items[0][quantity]", "6"),
        ("automatic_tax[enabled]", "true"),
        ("billing_address_collection", "required"),
        ("client_reference_id", a.account.as_str()),
        ("metadata[account_id]", a.account.as_str()),
        (
            "subscription_data[metadata][account_id]",
            a.account.as_str(),
        ),
        ("consent_collection[terms_of_service]", "required"),
        (
            "success_url",
            "https://apassy.wyderka.cc/connect/done?session_id={CHECKOUT_SESSION_ID}",
        ),
        ("cancel_url", "https://apassy.wyderka.cc/connect/cancel"),
    ] {
        assert_eq!(call.field(field), Some(value), "{field}");
    }
    assert!(call.header("Idempotency-Key").is_some());
    // Nothing of the account, its device, or its token reaches Stripe beyond the ids.
    assert!(!call.body.contains(&a.token) && !call.body.contains(&a.id));
    assert!(!call.body.contains(&a.key.public_key_b64()));
    // The browser's return changes nothing: only the webhook does.
    assert_eq!(c.plan(&a)["status"], "none");
    // The strict body and the counts.
    for (body, status, code) in [
        (
            json!({"plan": "family", "interval": "year"}),
            400,
            "invalid_request",
        ),
        (
            json!({"plan": "personal", "interval": "month", "seats": 2}),
            400,
            "invalid_request",
        ),
        (
            json!({"plan": "family", "interval": "week", "people": 4}),
            400,
            "invalid_request",
        ),
        (
            json!({"plan": "family", "interval": "month", "people": 11}),
            409,
            "seat_limit",
        ),
        (
            json!({"plan": "team", "interval": "month", "seats": 0}),
            409,
            "seat_limit",
        ),
        (
            json!({"plan": "personal", "interval": "month", "x": 1}),
            400,
            "invalid_request",
        ),
    ] {
        c.fails(
            "POST",
            "/v1/account/checkout",
            Some(&a.token),
            Some(&body),
            status,
            code,
        );
    }
    c.fails(
        "POST",
        "/v1/account/checkout",
        None,
        Some(&json!({})),
        401,
        "unauthenticated",
    );
    // An entitled account changes its plan in the portal, not with a new checkout.
    c.subscribe(&a, "connect_personal_month", 1);
    c.fails(
        "POST",
        "/v1/account/checkout",
        Some(&a.token),
        Some(&json!({"plan": "personal", "interval": "month"})),
        409,
        "conflict",
    );
    // The bound customer goes with a later checkout.
    let portal = c.ok(
        "POST",
        "/v1/account/portal",
        Some(&a.token),
        Some(&json!({})),
    );
    assert!(
        portal["url"]
            .as_str()
            .unwrap()
            .starts_with("https://billing.stripe.com/")
    );
    // The customer Connect made before the first session is the account's.
    let call = &c.stripe.calls_to("POST", "/v1/billing_portal/sessions")[0];
    let made = &c.stripe.calls_to("POST", "/v1/checkout/sessions")[0];
    assert_eq!(call.field("customer"), made.field("customer"));
    assert_eq!(call.field("customer"), Some(c.customer_of(&a).as_str()));
    assert_eq!(
        call.field("return_url"),
        Some("https://apassy.wyderka.cc/connect/done")
    );
    let b = c.account("Bob");
    c.fails(
        "POST",
        "/v1/account/portal",
        Some(&b.token),
        Some(&json!({})),
        404,
        "not_found",
    );
}

#[test]
fn the_webhook_takes_the_raw_body_and_checks_size_signature_and_repeats() {
    let c = start();
    let a = c.account("Rafal");
    let secret = SecretString::new(WEBHOOK_SECRET.to_string());
    // Stripe's bytes, not a canonical JSON form: the signature is over these bytes.
    let event = c.checkout_completed(&a.account, "cus_RawBytes01", "sub_RawBytes01");
    let body = format!("{}\n", serde_json::to_string_pretty(&event).unwrap()).into_bytes();
    let header = signature_header(&secret, now(), &body);
    // A changed byte, another secret, a stale time, no header: 400, and nothing changes.
    let mut changed = body.clone();
    let at = changed.len() - 3;
    changed[at] = b' ';
    let other = signature_header(
        &SecretString::new("whsec_another_synthetic_secret".to_string()),
        now(),
        &body,
    );
    let stale = signature_header(&secret, now() - 301, &body);
    for (bytes, signature) in [
        (&changed, header.as_str()),
        (&body, other.as_str()),
        (&body, stale.as_str()),
        (&body, "t=1,v0=00"),
    ] {
        let (status, answer) = c.deliver_bytes(bytes, signature);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (400, Some("invalid_request"))
        );
    }
    assert!(c.rows("SELECT id FROM stripe_event").is_empty());
    assert!(c.rows("SELECT customer_id FROM stripe_customer").is_empty());
    // A body over 256 KiB is 413 before the signature: the relay reads at most one byte
    // more than the cap.
    let mut large = body.clone();
    large.extend(std::iter::repeat_n(b' ', 256 * 1024));
    let (status, answer) = c.deliver_bytes(&large, &signature_header(&secret, now(), &large));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (413, Some("payload_too_large"))
    );
    // The real one, once; its repeat changes nothing.
    let (status, answer) = c.deliver_bytes(&body, &header);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        answer["result"],
        json!({"received": true, "duplicate": false})
    );
    let (status, answer) = c.deliver_bytes(&body, &header);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        answer["result"],
        json!({"received": true, "duplicate": true})
    );
    assert_eq!(
        c.rows("SELECT customer_id FROM stripe_customer"),
        ["cus_RawBytes01"]
    );
    // The email copy shows in the account.
    let view = c.ok("GET", "/v1/account", Some(&a.token), None);
    assert_eq!(view["email"], "person@example.test");
    // An unknown account: logged and ignored, 200, so Stripe does not retry it.
    let stranger = c.checkout_completed("acc_aaaaaaaaaa", "cus_Stranger01", "sub_Stranger01");
    c.deliver_ok(&stranger);
    assert_eq!(
        c.rows("SELECT customer_id FROM stripe_customer"),
        ["cus_RawBytes01"]
    );
    assert_eq!(c.rows("SELECT id FROM stripe_event").len(), 2);
}

#[test]
fn the_plan_state_gates_new_stores_pushes_pulls_downloads_and_the_entitlement_token() {
    let c = start();
    let a = c.account("Rafal");
    // Without a plan: no store, no token.
    c.fails(
        "POST",
        "/v1/account/vaults",
        Some(&a.token),
        Some(&json!({"vault_id": VAULT, "name": "Personal"})),
        403,
        "plan_required",
    );
    c.fails(
        "GET",
        "/v1/account/entitlement",
        Some(&a.token),
        None,
        403,
        "plan_required",
    );
    let subscription = c.subscribe(&a, "connect_personal_month", 1);
    let plan = c.plan(&a);
    assert_eq!(
        (
            plan["plan"].as_str(),
            plan["status"].as_str(),
            plan["entitled"].as_bool()
        ),
        (Some("personal"), Some("active"), Some(true))
    );
    assert!(plan["renews_at"].as_u64().is_some());
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&a.token), None)["plan"],
        plan
    );
    let (team, device) = c.store(&a, VAULT);
    let token = c.store_token(&team, &a);
    let mut pusher = Pusher::new(&team, VAULT);
    let answer = c.try_push(&pusher, &token, device, &a, b"version one");
    assert_eq!(answer.status, 200, "{}", answer.body);
    pusher.pushed(device, b"version one");
    assert_eq!(c.pull(&token, pusher.version), (200, 200));
    let entitlement = c.ok("GET", "/v1/account/entitlement", Some(&a.token), None);
    assert!(entitlement["expires_at"].as_u64().unwrap() > now());

    // A failed payment: past due, still entitled for the grace.
    c.deliver_ok(
        &json!({"id": "evt_failed01", "type": "invoice.payment_failed", "created": c.tick(),
        "data": {"object": {"id": "in_failed01", "customer": format!("cus_{}", &a.account[4..]),
                 "subscription": subscription, "attempt_count": 1}}}),
    );
    c.update(&a, "connect_personal_month", 1, "past_due");
    let plan = c.plan(&a);
    assert_eq!(
        (plan["status"].as_str(), plan["entitled"].as_bool()),
        (Some("past_due"), Some(true))
    );
    assert!(plan["grace_until"].as_u64().unwrap() > now() + 13 * DAY);
    let answer = c.try_push(&pusher, &token, device, &a, b"version two");
    assert_eq!(answer.status, 200, "{}", answer.body);
    pusher.pushed(device, b"version two");

    // Beyond the grace: read-only. Pushes, new stores, and the token stop; pulls and
    // downloads work.
    c.edit_directory(&format!(
        "UPDATE stripe_subscription SET first_failure_at = {}",
        now() - 15 * DAY
    ));
    let plan = c.plan(&a);
    assert_eq!(
        (plan["status"].as_str(), plan["entitled"].as_bool()),
        (Some("read_only"), Some(false))
    );
    let answer = c.try_push(&pusher, &token, device, &a, b"version three");
    assert_eq!(
        (answer.status, answer.body["error"]["code"].as_str()),
        (403, Some("plan_required"))
    );
    assert_eq!(c.pull(&token, pusher.version), (200, 200));
    c.fails(
        "POST",
        "/v1/account/vaults",
        Some(&a.token),
        Some(&json!({"vault_id": "1f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77", "name": "Work"})),
        403,
        "plan_required",
    );
    c.fails(
        "GET",
        "/v1/account/entitlement",
        Some(&a.token),
        None,
        403,
        "plan_required",
    );
    // A plan_required carries no price, link, or purchase hint.
    let (_, refused) = c.call("GET", "/v1/account/entitlement", Some(&a.token), None);
    let text = refused.to_string().to_lowercase();
    for word in ["eur", "€", "http", "buy", "subscribe", "upgrade", "price"] {
        assert!(!text.contains(word), "{text}");
    }

    // Unpaid since 31 days: suspended, pulls and downloads stop too.
    c.update(&a, "connect_personal_month", 1, "unpaid");
    c.edit_directory(&format!(
        "UPDATE stripe_subscription SET ended_at = {}",
        now() - 31 * DAY
    ));
    let plan = c.plan(&a);
    assert_eq!(plan["status"], "suspended");
    assert_eq!(c.pull(&token, pusher.version), (403, 403));
    // A payment before the deletion day brings the store back as it was.
    c.update(&a, "connect_personal_month", 1, "active");
    assert_eq!(c.pull(&token, pusher.version), (200, 200));
    let answer = c.try_push(&pusher, &token, device, &a, b"version three");
    assert_eq!(answer.status, 200, "{}", answer.body);
    // Canceled is final at Stripe: a later event of the same subscription that says
    // otherwise changes nothing. A renewal after a cancel is a new subscription.
    c.update(&a, "connect_personal_month", 1, "canceled");
    c.update(&a, "connect_personal_month", 1, "active");
    let plan = c.plan(&a);
    assert_eq!(
        (plan["status"].as_str(), plan["entitled"].as_bool()),
        (Some("read_only"), Some(false))
    );
}

#[test]
fn the_maintenance_pass_deletes_the_stores_at_the_configured_day_with_an_audit_row() {
    let c = start_with_config(|cfg| {
        let billing = cfg.connect.billing.as_mut().unwrap();
        billing.config.durations.read_only_days = 10;
        billing.config.durations.delete_days = 40;
    });
    let a = c.account("Rafal");
    let b = c.account("Bob");
    c.subscribe(&a, "connect_personal_month", 1);
    c.subscribe(&b, "connect_personal_month", 1);
    let (team, _) = c.store(&a, VAULT);
    c.store(&b, VAULT);
    c.update(&a, "connect_personal_month", 1, "canceled");
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    // Day 39 after the end: suspended, the store stays.
    ended_days_ago(&c, &a, 39);
    assert_eq!(c.plan(&a)["status"], "suspended");
    assert_eq!(
        apassy_relay::server::billing_store::maintain(&hub, &billing, now()).unwrap(),
        0
    );
    assert_eq!(
        c.rows("SELECT id FROM team WHERE kind = 'account'").len(),
        2
    );
    // Day 41: the store of the ended plan goes, with an audit row and I-4 forget; the
    // account stays and its plan is none.
    ended_days_ago(&c, &a, 41);
    assert_eq!(
        apassy_relay::server::billing_store::maintain(&hub, &billing, now()).unwrap(),
        1
    );
    let left = c.rows("SELECT account_id FROM team WHERE kind = 'account'");
    assert_eq!(left, std::slice::from_ref(&b.account));
    assert!(!c.rows("SELECT id FROM team").contains(&team));
    let audit = c.rows("SELECT detail FROM audit WHERE action = 'plan_stores_deleted'");
    assert_eq!(audit.len(), 1);
    let detail: Value = serde_json::from_str(&audit[0]).unwrap();
    assert_eq!(detail["account_id"], a.account.as_str());
    assert_eq!(detail["deleted_stores"], 1);
    assert_eq!(
        c.rows(&format!(
            "SELECT kind FROM brain_event WHERE subject = '{}'",
            a.account
        )),
        ["forget"]
    );
    assert_eq!(c.plan(&a)["status"], "none");
    assert!(
        c.ok("GET", "/v1/account", Some(&a.token), None)["devices"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    // The next pass does nothing.
    assert_eq!(
        apassy_relay::server::billing_store::maintain(&hub, &billing, now()).unwrap(),
        0
    );
}

#[test]
fn deleting_the_account_cancels_the_subscription_at_once_and_keeps_the_customer() {
    let c = start();
    let a = c.account("Rafal");
    c.subscribe(&a, "connect_personal_month", 1);
    c.store(&a, VAULT);
    let deleted = c.ok("DELETE", "/v1/account", Some(&a.token), Some(&json!({})));
    assert_eq!(
        deleted,
        json!({"account_id": a.account, "deleted_stores": 1, "subscription_canceled": true})
    );
    let cancel = format!("/v1/subscriptions/sub_{}", &a.account[4..]);
    assert_eq!(c.stripe.calls_to("DELETE", &cancel).len(), 1);
    // The customer stays for the invoices, without the email copy.
    assert_eq!(
        c.rows("SELECT customer_id || '/' || coalesce(email, '-') FROM stripe_customer"),
        [format!("cus_{}/-", &a.account[4..])]
    );
    assert!(c.rows("SELECT id FROM account").is_empty());
    // A Stripe outage leaves the account as it was: the deletion can be asked again.
    let b = c.account("Bob");
    c.subscribe(&b, "connect_personal_month", 1);
    c.stripe.fail_next(500, 4);
    let (status, _) = c.call("DELETE", "/v1/account", Some(&b.token), Some(&json!({})));
    assert!(status >= 500, "{status}");
    assert_eq!(
        c.rows("SELECT id FROM account"),
        std::slice::from_ref(&b.account)
    );
}

#[test]
fn without_stripe_files_the_billing_routes_are_busy_and_no_account_has_a_plan() {
    let c = start_with_config(|cfg| cfg.connect.billing = None);
    let a = c.account("Rafal");
    c.fails("GET", "/v1/plans", None, None, 503, "busy");
    c.fails(
        "POST",
        "/v1/account/checkout",
        Some(&a.token),
        Some(&json!({"plan": "personal", "interval": "month"})),
        503,
        "busy",
    );
    c.fails(
        "POST",
        "/v1/account/portal",
        Some(&a.token),
        Some(&json!({})),
        503,
        "busy",
    );
    let (status, answer) = c.deliver(&c.checkout_completed(&a.account, "cus_X1", "sub_X1"));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (503, Some("busy"))
    );
    assert_eq!(c.plan(&a)["status"], "none");
    assert!(c.stripe.calls().is_empty());
}

#[test]
fn the_settings_need_both_stripe_files_and_take_the_api_base_from_code_only() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("stripe-key");
    let webhook = dir.path().join("stripe-webhook-secret");
    std::fs::write(&key, "rk_test_FAKE_apassy_billing_tests\n").unwrap();
    std::fs::write(&webhook, format!("{WEBHOOK_SECRET}\n")).unwrap();
    let live = dir.path().join("live-key");
    std::fs::write(&live, "sk_live_SYNTHETIC_never_accepted_0123456789").unwrap();
    let data = dir.path().join("data").to_string_lossy().into_owned();
    let (key, webhook, live) = (
        key.to_string_lossy().into_owned(),
        webhook.to_string_lossy().into_owned(),
        live.to_string_lossy().into_owned(),
    );
    let with = |extra: &[(&str, &str)]| {
        let mut pairs: Vec<(String, String)> = vec![
            ("APASSY_RELAY_DATA".into(), data.clone()),
            (
                "APASSY_RELAY_PUBLIC_URL".into(),
                "https://connect.example.test".into(),
            ),
            ("APASSY_RELAY_EDGE_SECRET".into(), relay::EDGE_SECRET.into()),
            ("APASSY_RELAY_KEY".into(), relay::VAULT_KEY.into()),
            ("APASSY_RELAY_CONNECT_ACCOUNTS".into(), "1".into()),
        ];
        pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        RelayConfig::from_lookup(move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    };
    assert!(with(&[]).unwrap().connect.billing.is_none());
    assert!(with(&[("STRIPE_SECRET_KEY_FILE", &key)]).is_err());
    assert!(with(&[("STRIPE_WEBHOOK_SECRET_FILE", &webhook)]).is_err());
    assert!(
        with(&[
            ("STRIPE_SECRET_KEY_FILE", &live),
            ("STRIPE_WEBHOOK_SECRET_FILE", &webhook)
        ])
        .is_err()
    );
    let config = with(&[
        ("STRIPE_SECRET_KEY_FILE", &key),
        ("STRIPE_WEBHOOK_SECRET_FILE", &webhook),
        ("APASSY_CONNECT_GRACE_DAYS", "7"),
        ("APASSY_CONNECT_FAMILY_EXTRA_CENTS", "150"),
        ("APASSY_CONNECT_SITE_URL", "https://site.example.test"),
    ])
    .unwrap();
    let billing = config.connect.billing.clone().unwrap();
    assert_eq!(billing.stripe_api_base, "https://api.stripe.com");
    assert_eq!(billing.config.durations.grace_days, 7);
    assert_eq!(billing.config.family_extra_cents, 150);
    assert_eq!(billing.config.site_url, "https://site.example.test");
    // The secrets never show in a debug print.
    let shown = format!("{config:?}");
    assert!(
        !shown.contains("rk_test_FAKE") && !shown.contains(WEBHOOK_SECRET),
        "{shown}"
    );
    assert!(!billing.config.auto_raise_seats);
    let raising = with(&[
        ("STRIPE_SECRET_KEY_FILE", &key),
        ("STRIPE_WEBHOOK_SECRET_FILE", &webhook),
        ("APASSY_CONNECT_AUTO_RAISE_SEATS", "1"),
    ])
    .unwrap();
    assert!(raising.connect.billing.unwrap().config.auto_raise_seats);
    for bad in [
        ("APASSY_CONNECT_GRACE_DAYS", "0"),
        ("APASSY_CONNECT_DELETE_DAYS", "20"),
        ("APASSY_CONNECT_FAMILY_EXTRA_CENTS", "x"),
        ("APASSY_CONNECT_AUTO_RAISE_SEATS", "true"),
    ] {
        assert!(with(&[bad]).is_err(), "{bad:?}");
    }
    // Only a loopback http:// base besides Stripe's own: a relay with another one does not
    // start.
    let mut settings = billing.clone();
    for base in [
        "https://api.stripe.com",
        "http://127.0.0.1:9",
        "http://[::1]:9",
    ] {
        settings.stripe_api_base = base.to_string();
        assert!(settings.check_api_base().is_ok(), "{base}");
    }
    for base in [
        "https://stripe.example.test",
        "http://10.0.0.1:80",
        "http://api.stripe.com",
    ] {
        settings.stripe_api_base = base.to_string();
        assert!(settings.check_api_base().is_err(), "{base}");
    }
    let mut cfg = relay::test_config(dir.path(), apassy_relay::config::UpstreamOptions::default());
    cfg.connect = ConnectConfig::accounts(Some(connect::signing_key()));
    cfg.connect.billing = Some(settings);
    apassy_relay::server::Relay::init(&cfg, "Test Team", "owner").unwrap();
    assert!(apassy_relay::server::Relay::start(cfg).is_err());
}

// ---------------------------------------------------------------------------------------
// The deletion pass asks Stripe, goes on past a failure, and holds on a clock gap.

/// Moves the end of `dev`'s subscription `days` into the past, here and at Stripe.
fn ended_days_ago(c: &Connect, dev: &Dev, days: u64) {
    c.end_subscription_at(&format!("sub_{}", &dev.account[4..]), now() - days * DAY);
}

fn store_count(c: &Connect, dev: &Dev) -> usize {
    c.rows(&format!(
        "SELECT id FROM team WHERE kind = 'account' AND account_id = '{}'",
        dev.account
    ))
    .len()
}

#[test]
fn the_deletion_keeps_what_stripe_shows_live_and_waits_for_an_unreachable_stripe() {
    let c = start();
    let a = c.account("Rafal");
    let b = c.account("Bob");
    c.subscribe(&a, "connect_personal_month", 1);
    c.subscribe(&b, "connect_personal_month", 1);
    c.store(&a, VAULT);
    c.store(&b, VAULT);
    // A's plan ended here (unpaid), but its payment went through at Stripe and the event
    // was lost: Stripe shows it active.
    c.update(&a, "connect_personal_month", 1, "unpaid");
    let mut paid = c
        .stripe
        .subscription(&format!("sub_{}", &a.account[4..]))
        .unwrap();
    paid["status"] = json!("active");
    c.stripe.put_subscription(paid);
    c.update(&b, "connect_personal_month", 1, "canceled");
    ended_days_ago(&c, &a, 91);
    ended_days_ago(&c, &b, 91);
    // Stripe cannot be reached for B: the pass skips it.
    c.stripe.fail_path(
        &format!("/v1/subscriptions/sub_{}", &b.account[4..]),
        503,
        2,
    );
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    assert_eq!(maintain(&hub, &billing, now()).unwrap(), 0);
    assert_eq!((store_count(&c, &a), store_count(&c, &b)), (1, 1));
    // A took Stripe's state: entitled again, with its store.
    let plan = c.plan(&a);
    assert_eq!(
        (plan["status"].as_str(), plan["entitled"].as_bool()),
        (Some("active"), Some(true))
    );
    // The next pass reaches Stripe, which shows B canceled: B's store goes.
    assert_eq!(maintain(&hub, &billing, now()).unwrap(), 1);
    assert_eq!((store_count(&c, &a), store_count(&c, &b)), (1, 0));
}

#[test]
fn one_failed_deletion_does_not_stop_the_pass() {
    let c = start();
    let a = c.account("Rafal");
    let b = c.account("Bob");
    let mut teams = Vec::new();
    for dev in [&a, &b] {
        c.subscribe(dev, "connect_personal_month", 1);
        teams.push(c.store(dev, VAULT).0);
        c.update(dev, "connect_personal_month", 1, "canceled");
        ended_days_ago(&c, dev, 91);
    }
    // The pass takes the plans in the order of their subscription ids: the first one's
    // store file cannot be removed.
    let (first, second) = if a.account < b.account {
        (0, 1)
    } else {
        (1, 0)
    };
    let devs = [&a, &b];
    let team = apassy_relay::ids::TeamId::parse(&teams[first]).unwrap();
    let mut blocker = c.relay.config.team_path(&team).into_os_string();
    blocker.push(".pre-v3");
    std::fs::create_dir_all(&blocker).unwrap();
    std::fs::write(std::path::Path::new(&blocker).join("keep"), b"x").unwrap();
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    assert_eq!(maintain(&hub, &billing, now()).unwrap(), 1);
    assert_eq!(store_count(&c, devs[second]), 0);
    let audit = c.rows("SELECT detail FROM audit WHERE action = 'plan_stores_deleted' ORDER BY id");
    assert_eq!(audit.len(), 2, "{audit:?}");
    let failed: Vec<Value> = audit
        .iter()
        .map(|row| serde_json::from_str::<Value>(row).unwrap())
        .filter(|row| row["failed"] == 1)
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["account_id"], devs[first].account.as_str());
    // The next pass within a day does not read the unfinished plan again, and writes no
    // row for it.
    std::fs::remove_dir_all(&blocker).unwrap();
    assert_eq!(maintain(&hub, &billing, now() + 3600).unwrap(), 0);
    assert_eq!(
        c.rows("SELECT detail FROM audit WHERE action = 'plan_stores_deleted'")
            .len(),
        2
    );
    // A day later the pass finishes the first plan (Stripe's clock is a day on too).
    let later = now() + DAY + 60;
    c.stripe.set_date(Some(later));
    assert_eq!(maintain(&hub, &billing, later).unwrap(), 1);
    assert_eq!(store_count(&c, devs[first]), 0);
    assert_eq!(maintain(&hub, &billing, later).unwrap(), 0);
}

#[test]
fn a_clock_gap_holds_deletions_until_the_operator_resumes_them() {
    let c = start();
    let a = c.account("Rafal");
    c.subscribe(&a, "connect_personal_month", 1);
    c.store(&a, VAULT);
    c.update(&a, "connect_personal_month", 1, "canceled");
    ended_days_ago(&c, &a, 91);
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    // The last pass ran three days ago (the relay was down, or the clock jumped).
    c.edit_directory(&format!(
        "INSERT INTO billing_clock (id, last_pass_at) VALUES (1, {}) \
         ON CONFLICT(id) DO UPDATE SET last_pass_at = excluded.last_pass_at, held_since = NULL",
        now() - 3 * DAY
    ));
    assert_eq!(maintain(&hub, &billing, now()).unwrap(), 0);
    assert_eq!(store_count(&c, &a), 1);
    let ready = run(&hub, &Command::Readiness, now()).unwrap();
    assert!(
        ready["billing"]["deletions_held_since"].as_u64().is_some(),
        "{ready}"
    );
    assert_eq!(maintain(&hub, &billing, now() + 3600).unwrap(), 0);
    // The operator checked the clock and resumes.
    let resumed = run(
        &hub,
        &Command::Billing {
            resume_deletions: true,
            resolve: None,
        },
        now(),
    )
    .unwrap();
    assert!(
        resumed["status"]["deletions_held_since"].is_null(),
        "{resumed}"
    );
    assert_eq!(maintain(&hub, &billing, now()).unwrap(), 1);
    assert_eq!(store_count(&c, &a), 0);
    assert_eq!(
        c.rows("SELECT action FROM audit WHERE action = 'billing_deletions_resumed'")
            .len(),
        1
    );
}

#[test]
fn a_webhook_without_a_usable_signature_is_refused_before_its_body_is_read() {
    use std::io::{Read, Write};
    let c = start();
    let address = c.relay.url.trim_start_matches("http://").to_string();
    for signature in [None, Some("t=1000,v1=00"), Some("v1=00")] {
        let mut stream = std::net::TcpStream::connect(&address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sent = Instant::now();
        let mut head = format!(
            "POST /v1/stripe/webhook HTTP/1.1\r\nHost: relay.test\r\nX-Apassy-Edge: {}\r\n\
             Content-Type: application/json\r\nContent-Length: 200000\r\n",
            relay::EDGE_SECRET
        );
        if let Some(signature) = signature {
            head.push_str(&format!("Stripe-Signature: {signature}\r\n"));
        }
        head.push_str("\r\n");
        // The head only: the relay answers without waiting for a byte of the body.
        stream.write_all(head.as_bytes()).unwrap();
        let mut answer = Vec::new();
        let mut buffer = [0u8; 4096];
        while !answer.windows(4).any(|w| w == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).expect("an answer before the body");
            assert!(read > 0, "the relay closed without an answer");
            answer.extend_from_slice(&buffer[..read]);
        }
        assert!(sent.elapsed() < Duration::from_secs(2), "{signature:?}");
        // The rest of the answer: the error names the signature, not the body.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 {
                break;
            }
            answer.extend_from_slice(&buffer[..read]);
        }
        let text = String::from_utf8_lossy(&answer);
        assert!(text.starts_with("HTTP/1.1 400"), "{signature:?}: {text}");
        assert!(
            text.contains("The Stripe signature does not verify."),
            "{signature:?}: {text}"
        );
    }
    // A signed webhook still works after the refusals.
    let a = c.account("Rafal");
    c.subscribe(&a, "connect_personal_month", 1);
    assert_eq!(c.plan(&a)["status"], "active");
}

#[test]
fn a_paid_subscription_connect_cannot_bind_is_shown_to_the_operator() {
    let c = start();
    let a = c.account("Rafal");
    c.ok(
        "POST",
        "/v1/account/checkout",
        Some(&a.token),
        Some(&json!({"plan": "personal", "interval": "month"})),
    );
    let made = c.customer_of(&a);
    assert!(made.starts_with("cus_SynthMade"), "{made}");
    // A session of another customer for the same account: received, not applied.
    let (status, answer) =
        c.deliver(&c.checkout_completed(&a.account, "cus_SynthStray01", "sub_SynthStray01"));
    assert_eq!(status, 200, "{answer}");
    assert_eq!(c.plan(&a)["status"], "none");
    let hub = c.relay.hub();
    let ready = run(&hub, &Command::Readiness, now()).unwrap();
    assert_eq!(ready["billing"]["open_problems"], 1, "{ready}");
    let audit = c.rows("SELECT detail FROM audit WHERE action = 'billing_problem_recorded'");
    assert_eq!(audit.len(), 1);
    let detail: Value = serde_json::from_str(&audit[0]).unwrap();
    assert_eq!(
        (detail["object"].as_str(), detail["account_id"].as_str()),
        (Some("sub_SynthStray01"), Some(a.account.as_str()))
    );
    assert!(!audit[0].contains('@'), "no email in the audit");
    let listed = run(
        &hub,
        &Command::Billing {
            resume_deletions: false,
            resolve: None,
        },
        now(),
    )
    .unwrap();
    let id = listed["problems"][0]["id"].as_u64().unwrap();
    let resolved = run(
        &hub,
        &Command::Billing {
            resume_deletions: false,
            resolve: Some(id),
        },
        now(),
    )
    .unwrap();
    assert_eq!(resolved["status"]["open_problems"], 0, "{resolved}");
}

#[test]
fn the_deletion_waits_while_stripe_has_another_subscription_of_the_account() {
    let c = start();
    let a = c.account("Rafal");
    let sub = c.subscribe(&a, "connect_personal_month", 1);
    c.store(&a, VAULT);
    c.update(&a, "connect_personal_month", 1, "canceled");
    ended_days_ago(&c, &a, 91);
    // A new subscription at Stripe whose events have not arrived (or that Connect cannot
    // map): the account's data stays.
    let mut newer = c.stripe.subscription(&sub).unwrap();
    newer["id"] = json!(format!("{sub}2"));
    newer["status"] = json!("active");
    newer["ended_at"] = Value::Null;
    c.stripe.put_subscription(newer.clone());
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    assert_eq!(maintain(&hub, &billing, now()).unwrap(), 0);
    assert_eq!(store_count(&c, &a), 1);
    assert!(
        c.rows("SELECT detail FROM audit WHERE action = 'plan_stores_deleted'")
            .is_empty()
    );
    // Stripe ended that one too: a day later the data goes.
    newer["status"] = json!("incomplete_expired");
    c.stripe.put_subscription(newer);
    let later = now() + DAY + 60;
    c.stripe.set_date(Some(later));
    assert_eq!(maintain(&hub, &billing, later).unwrap(), 1);
    assert_eq!(store_count(&c, &a), 0);
}

#[test]
fn a_checkout_stored_while_the_deletion_asks_stripe_keeps_the_data() {
    let c = start();
    let a = c.account("Rafal");
    c.subscribe(&a, "connect_personal_month", 1);
    c.store(&a, VAULT);
    c.update(&a, "connect_personal_month", 1, "canceled");
    ended_days_ago(&c, &a, 91);
    c.stripe.set_session_expires_at(now() + DAY);
    // The read of the subscription answers at once; the list of the deletion's last
    // question waits, and a checkout runs meanwhile.
    c.stripe.delay_next("/v1/subscriptions", 0);
    c.stripe.delay_next("/v1/subscriptions", 1500);
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    std::thread::scope(|scope| {
        let pass = scope.spawn(|| maintain(&hub, &billing, now()).unwrap());
        std::thread::sleep(Duration::from_millis(400));
        c.ok(
            "POST",
            "/v1/account/checkout",
            Some(&a.token),
            Some(&json!({"plan": "personal", "interval": "month"})),
        );
        assert_eq!(pass.join().unwrap(), 0);
    });
    assert_eq!(store_count(&c, &a), 1);
}

#[test]
fn a_problem_row_that_opens_again_takes_the_new_reason_and_the_audit_keeps_both() {
    use apassy_relay::server::billing::{BillingStore, Problem};
    let c = start();
    let hub = c.relay.hub();
    let billing = hub.billing().expect("billing").clone();
    let record = |reason: &'static str| {
        billing
            .store
            .transaction(|tx| {
                tx.record_problem(&Problem {
                    object: "sub_SynthReopen001".to_owned(),
                    account: None,
                    customer: Some("cus_SynthReopen001".to_owned()),
                    event: None,
                    reason,
                    at: now(),
                })
            })
            .unwrap()
    };
    assert!(record("personal_quantity"));
    let id = billing.problems().unwrap()[0].id;
    billing.resolve_problem(id, now()).unwrap();
    assert!(record("raise_refused"));
    let open = billing.problems().unwrap();
    assert_eq!(
        (open.len(), open[0].id, open[0].reason.as_str()),
        (1, id, "raise_refused")
    );
    // Open with another reason: the row takes it too.
    assert!(record("deleted_account"));
    assert_eq!(billing.problems().unwrap()[0].reason, "deleted_account");
    let reasons: Vec<String> = c
        .rows("SELECT detail FROM audit WHERE action = 'billing_problem_recorded' ORDER BY id")
        .iter()
        .map(|detail| {
            serde_json::from_str::<Value>(detail).unwrap()["reason"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        reasons,
        ["personal_quantity", "raise_refused", "deleted_account"]
    );
    // Connect closes a problem it resolved itself, with a record of how.
    assert!(
        billing
            .store
            .transaction(|tx| tx.close_problem(
                "sub_SynthReopen001",
                "deleted_account",
                "test",
                now()
            ))
            .unwrap()
    );
    assert!(billing.problems().unwrap().is_empty());
    let closed = c.rows(
        "SELECT actor || ' ' || detail FROM audit WHERE action = 'billing_problem_resolved' ORDER BY id",
    );
    assert!(closed.last().unwrap().starts_with("billing "), "{closed:?}");
    assert!(
        closed.last().unwrap().contains("\"how\":\"test\""),
        "{closed:?}"
    );
}
