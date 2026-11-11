//! Connect billing (docs/contracts/connect-billing-v1.md; the C2 acceptance of
//! docs/design/implementation-plan-s7-connect.md) without the HTTP routes: the Stripe
//! client against the fake Stripe server on a free loopback port, the webhook check with
//! the D1 fixtures, the plan state machine on a fake clock, read-only semantics, totals,
//! checkout, the portal, seats, and what reaches Stripe and the logs.

#[path = "common/fake_stripe.rs"]
mod fake_stripe;

use std::sync::{Arc, Mutex};

use apassy_relay::error::codes;
use apassy_relay::secret::SecretString;
use apassy_relay::server::billing::{
    Billing, BillingConfig, BillingStore, Capability, CustomerRow, DeletionGate, Durations,
    GroupRole, Interval, MemberState, MemoryBillingStore, Plan, PlanInput, PlanStatus, PlansView,
    StripeCheck, StripeStatus, WebhookEffect, plan_state, total_cents,
};
use apassy_relay::server::stripe::{
    API_VERSION, MAX_WEBHOOK_BODY, StripeClient, StripeConfig, signature_header,
};
use fake_stripe::{FAKE_KEY, FakeStripe, SESSION_EXPIRES_AT};
use serde_json::{Value, json};

const DAY: u64 = 86_400;
const ACCOUNT: &str = "acc_k7m2q4x3ca";
const OTHER: &str = "acc_m3n5p7q2rb";
const THIRD: &str = "acc_r5s7t2u4vc";
const CUSTOMER: &str = "cus_SynthAcc0001";
const SUBSCRIPTION: &str = "sub_SynthAcc0001";
const EMAIL: &str = "person@example.test";
const START: u64 = 1_790_000_000;
const PERIOD_END: u64 = 1_792_592_000;
const FAILED: u64 = 1_792_592_100;
const ENDED: u64 = 1_793_801_700;

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../../tests/fixtures/connect-billing-v1/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|_| panic!("read {name}"))
}

fn fixture(name: &str) -> Value {
    serde_json::from_slice(&fixture_bytes(name)).unwrap()
}

fn vectors() -> Value {
    fixture("webhook-vectors.json")
}

fn endpoint_secret() -> SecretString {
    SecretString::new(vectors()["endpoint_secret"].as_str().unwrap().to_owned())
}

/// The billing of one test, its fake Stripe, and the captured log lines.
struct Setup {
    stripe: FakeStripe,
    billing: Billing<MemoryBillingStore>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Setup {
    fn new() -> Self {
        Self::with_config(BillingConfig::default())
    }

    fn with_config(config: BillingConfig) -> Self {
        let stripe = FakeStripe::start();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let logs = Arc::clone(&logs);
            Arc::new(move |line: &str| logs.lock().unwrap().push(line.to_owned()))
                as Arc<dyn Fn(&str) + Send + Sync>
        };
        let client = StripeClient::new(
            StripeConfig::new(stripe.base(), SecretString::new(FAKE_KEY.into())).unwrap(),
        )
        .with_log(Arc::clone(&sink));
        let store = MemoryBillingStore::new();
        store.add_account(ACCOUNT);
        let billing = Billing::new(store, client, config, endpoint_secret())
            .unwrap()
            .with_log(sink);
        Self {
            stripe,
            billing,
            logs,
        }
    }

    fn store(&self) -> &MemoryBillingStore {
        &self.billing.store
    }

    fn logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().clone()
    }

    /// Delivers a webhook fixture with its recorded header at its `t`.
    fn deliver_fixture(&self, file: &str) -> WebhookEffect {
        let (header, t) = fixture_header(file);
        let body = fixture_bytes(&format!("webhook/{file}"));
        let outcome = self.billing.webhook(Some(&header), &body, t).unwrap();
        assert!(outcome.answer.received);
        outcome.effect
    }

    /// Signs and delivers an event body at `now`.
    fn deliver(&self, event: &Value, now: u64) -> WebhookEffect {
        let body = format!("{event}\n").into_bytes();
        let header = signature_header(&endpoint_secret(), now, &body);
        self.billing
            .webhook(Some(&header), &body, now)
            .unwrap()
            .effect
    }

    fn plan(&self, account: &str, now: u64) -> apassy_relay::server::billing::PlanView {
        self.billing.plan_view(account, now).unwrap()
    }

    /// Binds `customer` to `account` as Connect does before a first checkout.
    fn bind_customer(&self, account: &str, customer: &str) {
        self.store()
            .transaction(|tx| {
                tx.put_customer(&CustomerRow {
                    account: account.to_owned(),
                    customer: customer.to_owned(),
                    email: None,
                })
            })
            .unwrap();
    }
}

fn fixture_header(file: &str) -> (String, u64) {
    let vectors = vectors();
    let event = vectors["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["file"] == file)
        .unwrap();
    (
        event["header"].as_str().unwrap().to_owned(),
        event["t"].as_u64().unwrap(),
    )
}

fn event(id: &str, kind: &str, created: u64, object: Value) -> Value {
    json!({
        "id": id, "object": "event", "api_version": API_VERSION, "created": created,
        "data": {"object": object}, "livemode": false, "pending_webhooks": 1,
        "request": {"id": null, "idempotency_key": null}, "type": kind
    })
}

fn checkout_session(account: &str, meta: &str, customer: &str, subscription: &str) -> Value {
    json!({
        "id": format!("cs_test_{}", &subscription[4..]), "object": "checkout.session",
        "client_reference_id": account, "customer": customer,
        "customer_details": {"email": EMAIL, "name": "Synthetic Person"},
        "metadata": {"account_id": meta}, "mode": "subscription",
        "payment_status": "paid", "status": "complete", "subscription": subscription
    })
}

struct Sub<'a> {
    id: &'a str,
    customer: &'a str,
    account: &'a str,
    status: &'a str,
    lookup: &'a str,
    quantity: u32,
    ended_at: Option<u64>,
    cancel_at_period_end: bool,
}

impl Default for Sub<'_> {
    fn default() -> Self {
        Self {
            id: SUBSCRIPTION,
            customer: CUSTOMER,
            account: ACCOUNT,
            status: "active",
            lookup: "connect_personal_month",
            quantity: 1,
            ended_at: None,
            cancel_at_period_end: false,
        }
    }
}

fn subscription(sub: &Sub<'_>) -> Value {
    json!({
        "id": sub.id, "object": "subscription", "cancel_at_period_end": sub.cancel_at_period_end,
        "customer": sub.customer, "ended_at": sub.ended_at,
        "items": {"object": "list", "data": [{
            "id": format!("si_{}", &sub.id[4..]), "object": "subscription_item",
            "current_period_end": PERIOD_END, "current_period_start": START,
            "price": {"id": "price_Synth", "object": "price", "currency": "eur",
                      "lookup_key": sub.lookup, "tax_behavior": "inclusive"},
            "quantity": sub.quantity
        }]},
        "metadata": {"account_id": sub.account}, "status": sub.status
    })
}

fn invoice(subscription: &str, customer: &str) -> Value {
    json!({
        "id": "in_Synth", "object": "invoice", "customer": customer, "attempt_count": 1,
        "next_payment_attempt": null,
        "parent": {"type": "subscription_details",
                   "subscription_details": {"subscription": subscription}}
    })
}

/// Binds a Family subscription of `quantity` people to ACCOUNT through two webhooks.
fn family(setup: &Setup, quantity: u32) -> String {
    setup.deliver(
        &event(
            "evt_FamCheckout",
            "checkout.session.completed",
            START,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, SUBSCRIPTION),
        ),
        START,
    );
    setup.deliver(
        &event(
            "evt_FamCreated",
            "customer.subscription.created",
            START + 1,
            subscription(&Sub {
                lookup: "connect_family_month",
                quantity,
                ..Sub::default()
            }),
        ),
        START + 1,
    );
    setup.plan(ACCOUNT, START + 2).group_id.expect("a group")
}

// ---------------------------------------------------------------------------------------
// The webhook check.

#[test]
fn every_fixture_is_accepted_once_and_a_repeat_changes_nothing() {
    let setup = Setup::new();
    for event in vectors()["events"].as_array().unwrap() {
        let file = event["file"].as_str().unwrap();
        let effect = setup.deliver_fixture(file);
        assert!(
            matches!(effect, WebhookEffect::Applied { ref account } if account == ACCOUNT),
            "{file}: {effect:?}"
        );
        let before = setup.store().snapshot();
        let (header, t) = fixture_header(file);
        let body = fixture_bytes(&format!("webhook/{file}"));
        let again = setup.billing.webhook(Some(&header), &body, t).unwrap();
        assert!(again.answer.received && again.answer.duplicate, "{file}");
        assert_eq!(again.effect, WebhookEffect::Duplicate);
        assert_eq!(
            setup.store().snapshot(),
            before,
            "{file}: a repeat changed the store"
        );
    }
    assert_eq!(setup.store().event_ids().len(), 6);
    // The six events end in a cancellation: read-only from `ended_at`.
    let plan = setup.plan(ACCOUNT, ENDED + DAY);
    assert_eq!(plan.status, PlanStatus::ReadOnly);
    assert_eq!(plan.read_only_until, Some(ENDED + 30 * DAY));
    assert_eq!(
        setup.store().customer(CUSTOMER).unwrap().email.as_deref(),
        Some(EMAIL)
    );
}

#[test]
fn the_header_vectors_are_accepted_or_refused_as_recorded() {
    for case in vectors()["headers"].as_array().unwrap() {
        let setup = Setup::new();
        let name = case["name"].as_str().unwrap();
        let body = fixture_bytes(&format!("webhook/{}", case["file"].as_str().unwrap()));
        let before = setup.store().snapshot();
        let result = setup.billing.webhook(
            Some(case["header"].as_str().unwrap()),
            &body,
            case["now"].as_u64().unwrap(),
        );
        if case["accepted"].as_bool().unwrap() {
            assert!(result.is_ok(), "{name}: {result:?}");
        } else {
            let error = result.expect_err(name);
            assert_eq!(error.code, codes::INVALID_REQUEST, "{name}");
            assert_eq!(error.status(), 400);
            assert_eq!(
                setup.store().snapshot(),
                before,
                "{name}: a refusal changed the store"
            );
        }
    }
}

#[test]
fn a_changed_byte_another_secret_or_no_header_is_refused_without_a_change() {
    let setup = Setup::new();
    let (header, t) = fixture_header("checkout-session-completed.json");
    let body = fixture_bytes("webhook/checkout-session-completed.json");
    let before = setup.store().snapshot();
    let mut changed = body.clone();
    let at = changed.iter().position(|b| *b == b'7').unwrap();
    changed[at] = b'8';
    let other = signature_header(
        &SecretString::new("whsec_another_endpoint_secret".into()),
        t,
        &body,
    );
    for (header, body) in [
        (Some(header.as_str()), changed.as_slice()),
        (Some(other.as_str()), body.as_slice()),
        (None, body.as_slice()),
        (Some(""), body.as_slice()),
    ] {
        let error = setup.billing.webhook(header, body, t).unwrap_err();
        assert_eq!((error.code, error.status()), (codes::INVALID_REQUEST, 400));
    }
    assert_eq!(setup.store().snapshot(), before);
    assert!(setup.store().event_ids().is_empty());
}

#[test]
fn a_stale_or_future_timestamp_is_refused() {
    let setup = Setup::new();
    let (header, t) = fixture_header("customer-subscription-created.json");
    let body = fixture_bytes("webhook/customer-subscription-created.json");
    for now in [t + 301, t - 301, t + 10 * DAY] {
        let error = setup
            .billing
            .webhook(Some(&header), &body, now)
            .unwrap_err();
        assert_eq!(error.code, codes::INVALID_REQUEST, "now {now}");
    }
    assert!(setup.store().subscriptions().is_empty());
    assert!(setup.billing.webhook(Some(&header), &body, t + 300).is_ok());
}

#[test]
fn a_body_over_256_kib_is_refused_before_the_signature() {
    let setup = Setup::new();
    let now = START;
    // A correctly signed event padded past the cap: refused by size alone.
    let mut big = event(
        "evt_Big",
        "ping",
        now,
        json!({"pad": "x".repeat(MAX_WEBHOOK_BODY)}),
    )
    .to_string()
    .into_bytes();
    big.push(b'\n');
    let header = signature_header(&endpoint_secret(), now, &big);
    let error = setup.billing.webhook(Some(&header), &big, now).unwrap_err();
    assert_eq!(
        (error.code, error.status()),
        (codes::PAYLOAD_TOO_LARGE, 413)
    );
    // Exactly at the cap: read and checked (here: not JSON, so 400 after the signature).
    let exact = vec![b' '; MAX_WEBHOOK_BODY];
    let header = signature_header(&endpoint_secret(), now, &exact);
    let error = setup
        .billing
        .webhook(Some(&header), &exact, now)
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::INVALID_REQUEST, 400));
    assert!(setup.store().event_ids().is_empty());
}

#[test]
fn a_signed_body_that_is_not_an_event_is_refused() {
    let setup = Setup::new();
    for body in [
        &b"not json"[..],
        b"{\"id\":\"evt_1\"}",
        b"{\"id\":\"x\",\"type\":\"a\",\"created\":1,\"data\":{\"object\":{}}}",
    ] {
        let header = signature_header(&endpoint_secret(), START, body);
        let error = setup
            .billing
            .webhook(Some(&header), body, START)
            .unwrap_err();
        assert_eq!(error.code, codes::INVALID_REQUEST);
    }
    assert!(setup.store().event_ids().is_empty());
}

#[test]
fn an_unknown_or_mismatched_client_reference_id_is_logged_and_ignored() {
    let setup = Setup::new();
    let cases = [
        (
            "evt_Unknown01",
            checkout_session(OTHER, OTHER, "cus_Stranger1", "sub_Stranger1"),
        ),
        (
            "evt_Mismatch1",
            checkout_session(ACCOUNT, OTHER, "cus_Stranger1", "sub_Stranger1"),
        ),
        ("evt_NoRef0001", {
            let mut session = checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, SUBSCRIPTION);
            session["client_reference_id"] = Value::Null;
            session
        }),
    ];
    for (id, session) in cases {
        let effect = setup.deliver(
            &event(id, "checkout.session.completed", START, session),
            START,
        );
        assert_eq!(effect, WebhookEffect::Ignored, "{id}");
    }
    assert!(setup.store().customers().is_empty());
    assert!(setup.store().subscriptions().is_empty());
    // The ids are stored, so Stripe's retry is a duplicate, and each one is logged.
    assert_eq!(setup.store().event_ids().len(), 3);
    let logs = setup.logs();
    assert_eq!(
        logs.iter().filter(|l| l.contains(": ignored: ")).count(),
        3,
        "{logs:?}"
    );
    assert!(logs.iter().all(|line| !line.contains(EMAIL)));
}

#[test]
fn a_subscription_event_for_an_unknown_account_or_another_customer_is_ignored() {
    let setup = Setup::new();
    let stranger = Sub {
        account: OTHER,
        ..Sub::default()
    };
    let effect = setup.deliver(
        &event(
            "evt_Stranger1",
            "customer.subscription.created",
            START,
            subscription(&stranger),
        ),
        START,
    );
    assert_eq!(effect, WebhookEffect::Ignored);
    // Bind the account, then send an event that moves its subscription to another
    // customer, or names another account: neither applies.
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let before = setup.store().subscription(SUBSCRIPTION).unwrap();
    let moved = Sub {
        customer: "cus_Attacker01",
        status: "active",
        ..Sub::default()
    };
    let renamed = Sub {
        account: THIRD,
        ..Sub::default()
    };
    setup.store().add_account(THIRD);
    for (id, sub) in [("evt_Moved0001", moved), ("evt_Renamed01", renamed)] {
        let effect = setup.deliver(
            &event(
                id,
                "customer.subscription.updated",
                START + 10,
                subscription(&sub),
            ),
            START + 10,
        );
        assert_eq!(effect, WebhookEffect::Ignored, "{id}");
    }
    assert_eq!(setup.store().subscription(SUBSCRIPTION).unwrap(), before);
    // A checkout that would bind another customer to the bound account: ignored too.
    let effect = setup.deliver(
        &event(
            "evt_Rebind001",
            "checkout.session.completed",
            START + 20,
            checkout_session(ACCOUNT, ACCOUNT, "cus_Attacker01", "sub_Attacker01"),
        ),
        START + 20,
    );
    assert_eq!(effect, WebhookEffect::Ignored);
    assert!(setup.store().customer("cus_Attacker01").is_none());
}

#[test]
fn an_unknown_price_gives_no_plan_and_another_event_type_changes_nothing() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    let foreign = Sub {
        lookup: "someone_else_price",
        ..Sub::default()
    };
    // The status of a bound subscription always applies; a price that is not one of
    // Connect's gives no plan, and the charging subscription is recorded for the operator.
    let effect = setup.deliver(
        &event(
            "evt_Foreign01",
            "customer.subscription.created",
            START + 1,
            subscription(&foreign),
        ),
        START + 1,
    );
    assert!(
        matches!(effect, WebhookEffect::Applied { .. }),
        "{effect:?}"
    );
    let row = setup.store().subscription(SUBSCRIPTION).unwrap();
    assert_eq!((row.status, row.plan), (StripeStatus::Active, None));
    assert_eq!(
        setup.plan(ACCOUNT, START + 2),
        apassy_relay::server::billing::PlanView::none()
    );
    let problems = setup.store().problems();
    assert_eq!(problems.len(), 1);
    assert_eq!(
        (problems[0].object.as_str(), problems[0].reason.as_str()),
        (SUBSCRIPTION, "unknown_price")
    );
    let before = setup.store().subscription(SUBSCRIPTION).unwrap();
    let effect = setup.deliver(
        &event("evt_Other00001", "customer.created", START + 2, json!({})),
        START + 2,
    );
    assert_eq!(effect, WebhookEffect::Ignored);
    assert_eq!(setup.store().subscription(SUBSCRIPTION).unwrap(), before);
    assert!(
        setup
            .store()
            .event_ids()
            .contains(&"evt_Other00001".to_owned())
    );
}

#[test]
fn an_older_event_does_not_undo_a_newer_one() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    // Stripe delivers the update (past_due) before the creation (active).
    setup.deliver_fixture("customer-subscription-updated.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let row = setup.store().subscription(SUBSCRIPTION).unwrap();
    assert_eq!(row.status, StripeStatus::PastDue);
    // The update carried no failure time, so the grace starts at the update.
    assert_eq!(row.first_failed_at, Some(FAILED + 1));
    // A late invoice.paid from before the failure does not clear it.
    setup.deliver_fixture("invoice-payment-failed.json");
    let late_paid = event(
        "evt_LatePaid1",
        "invoice.paid",
        START + 2,
        invoice(SUBSCRIPTION, CUSTOMER),
    );
    assert_eq!(
        setup.deliver(&late_paid, FAILED + 10),
        WebhookEffect::Ignored
    );
    assert_eq!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .first_failed_at,
        Some(FAILED + 1)
    );
}

// ---------------------------------------------------------------------------------------
// The plan state.

#[test]
fn every_case_of_plan_states_follows_section_8() {
    let file = fixture("plan-states.json");
    let durations = Durations {
        grace_days: file["grace_days"].as_u64().unwrap(),
        read_only_days: file["read_only_days"].as_u64().unwrap(),
        delete_days: file["delete_days"].as_u64().unwrap(),
    };
    assert_eq!(durations, Durations::default());
    for case in file["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input: PlanInput = serde_json::from_value(case["input"].clone()).unwrap();
        let state = plan_state(&input, &durations);
        let expect = &case["expect"];
        let status: PlanStatus = serde_json::from_value(expect["status"].clone()).unwrap();
        assert_eq!(state.status, status, "{name}");
        assert_eq!(
            state.entitled,
            expect["entitled"].as_bool().unwrap(),
            "{name}"
        );
        for (field, value) in [
            ("renews_at", state.renews_at),
            ("ends_at", state.ends_at),
            ("grace_until", state.grace_until),
            ("read_only_until", state.read_only_until),
            ("delete_at", state.delete_at),
        ] {
            assert_eq!(value, expect[field].as_u64(), "{name}: {field}");
        }
        let push = expect["push"].as_bool().unwrap();
        let pull = expect["pull"].as_bool().unwrap();
        for capability in [
            Capability::NewStore,
            Capability::Push,
            Capability::Dial,
            Capability::EntitlementToken,
        ] {
            assert_eq!(state.allows(capability), push, "{name}: {capability:?}");
        }
        for capability in [Capability::Pull, Capability::Download] {
            assert_eq!(state.allows(capability), pull, "{name}: {capability:?}");
        }
    }
}

#[test]
fn past_due_keeps_the_entitlement_for_14_days_then_read_only_on_a_fake_clock() {
    let setup = Setup::new();
    for file in [
        "checkout-session-completed.json",
        "customer-subscription-created.json",
        "invoice-paid.json",
    ] {
        setup.deliver_fixture(file);
    }
    let active = setup.plan(ACCOUNT, START + DAY);
    assert_eq!((active.status, active.entitled), (PlanStatus::Active, true));
    assert_eq!(active.renews_at, Some(PERIOD_END));
    assert_eq!(active.plan, Some(Plan::Personal));
    setup.deliver_fixture("invoice-payment-failed.json");
    setup.deliver_fixture("customer-subscription-updated.json");
    let grace_until = FAILED + 14 * DAY;
    for now in [FAILED, FAILED + DAY, grace_until - 1] {
        let plan = setup.plan(ACCOUNT, now);
        assert_eq!(
            (plan.status, plan.entitled),
            (PlanStatus::PastDue, true),
            "now {now}"
        );
        assert_eq!(plan.grace_until, Some(grace_until));
        assert!(plan.state().require(Capability::Push).is_ok());
    }
    let read_only = setup.plan(ACCOUNT, grace_until);
    assert_eq!(
        (read_only.status, read_only.entitled),
        (PlanStatus::ReadOnly, false)
    );
    assert_eq!(read_only.read_only_until, Some(grace_until + 30 * DAY));
    // Read-only semantics: a push (and a new store, a dial, a token) is plan_required,
    // a pull and a download still work.
    let state = read_only.state();
    let refused = state.require(Capability::Push).unwrap_err();
    assert_eq!(
        (refused.code, refused.status()),
        (codes::PLAN_REQUIRED, 403)
    );
    for capability in [
        Capability::NewStore,
        Capability::Dial,
        Capability::EntitlementToken,
    ] {
        assert_eq!(
            state.require(capability).unwrap_err().code,
            codes::PLAN_REQUIRED
        );
    }
    assert!(state.require(Capability::Pull).is_ok());
    assert!(state.require(Capability::Download).is_ok());
    // A paid invoice and an active update return the plan.
    setup.deliver(
        &event(
            "evt_Paid00002",
            "invoice.paid",
            grace_until + 5,
            invoice(SUBSCRIPTION, CUSTOMER),
        ),
        grace_until + 5,
    );
    setup.deliver(
        &event(
            "evt_Active0002",
            "customer.subscription.updated",
            grace_until + 6,
            subscription(&Sub::default()),
        ),
        grace_until + 6,
    );
    let back = setup.plan(ACCOUNT, grace_until + 7);
    assert_eq!((back.status, back.entitled), (PlanStatus::Active, true));
    assert_eq!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .first_failed_at,
        None
    );
}

#[test]
fn canceled_is_read_only_30_days_then_suspended_then_deleted_at_90() {
    let setup = Setup::new();
    for event in vectors()["events"].as_array().unwrap() {
        setup.deliver_fixture(event["file"].as_str().unwrap());
    }
    let read_only = setup.plan(ACCOUNT, ENDED);
    assert_eq!(read_only.status, PlanStatus::ReadOnly);
    assert_eq!(read_only.delete_at, Some(ENDED + 90 * DAY));
    let suspended = setup.plan(ACCOUNT, ENDED + 30 * DAY);
    assert_eq!(suspended.status, PlanStatus::Suspended);
    assert_eq!(
        suspended
            .state()
            .require(Capability::Download)
            .unwrap_err()
            .code,
        codes::PLAN_REQUIRED
    );
    assert_eq!(
        suspended
            .state()
            .require(Capability::Pull)
            .unwrap_err()
            .code,
        codes::PLAN_REQUIRED
    );
    // The maintenance pass lists nothing before the deletion time.
    let early = setup.billing.maintenance(ENDED + 90 * DAY - 1).unwrap();
    assert!(early.due.is_empty());
    let report = setup.billing.maintenance(ENDED + 90 * DAY).unwrap();
    assert_eq!(report.due.len(), 1);
    let due = &report.due[0];
    assert_eq!(
        (due.subscription.as_str(), due.account.as_str()),
        (SUBSCRIPTION, ACCOUNT)
    );
    assert_eq!(due.delete_at, ENDED + 90 * DAY);
    assert_eq!(
        setup.plan(ACCOUNT, ENDED + 90 * DAY),
        apassy_relay::server::billing::PlanView::none()
    );
    // The caller deletes the stores (audit row, forget) and records it once.
    setup
        .billing
        .mark_stores_deleted(SUBSCRIPTION, ENDED + 90 * DAY)
        .unwrap();
    assert!(
        setup
            .billing
            .maintenance(ENDED + 91 * DAY)
            .unwrap()
            .due
            .is_empty()
    );
    // Event ids older than 30 days are pruned by the same pass (here the earlier one).
    assert_eq!(early.events_pruned + report.events_pruned, 6);
    assert!(setup.store().event_ids().is_empty());
}

#[test]
fn unpaid_and_paused_end_at_the_time_connect_saw_them() {
    for status in ["unpaid", "paused", "incomplete_expired"] {
        let setup = Setup::new();
        setup.deliver_fixture("checkout-session-completed.json");
        setup.deliver_fixture("customer-subscription-created.json");
        let at = PERIOD_END + 3 * DAY;
        setup.deliver(
            &event(
                "evt_Lapsed001",
                "customer.subscription.updated",
                at,
                subscription(&Sub {
                    status,
                    ..Sub::default()
                }),
            ),
            at,
        );
        let plan = setup.plan(ACCOUNT, at);
        assert_eq!(plan.status, PlanStatus::ReadOnly, "{status}");
        assert_eq!(plan.read_only_until, Some(at + 30 * DAY), "{status}");
    }
}

#[test]
fn the_durations_are_configuration() {
    let config = BillingConfig {
        durations: Durations {
            grace_days: 3,
            read_only_days: 5,
            delete_days: 9,
        },
        ..BillingConfig::default()
    };
    let setup = Setup::with_config(config);
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    setup.deliver_fixture("invoice-payment-failed.json");
    setup.deliver_fixture("customer-subscription-updated.json");
    assert_eq!(
        setup.plan(ACCOUNT, FAILED + 3 * DAY - 1).status,
        PlanStatus::PastDue
    );
    assert_eq!(
        setup.plan(ACCOUNT, FAILED + 3 * DAY).status,
        PlanStatus::ReadOnly
    );
    assert_eq!(
        setup.plan(ACCOUNT, FAILED + 8 * DAY).status,
        PlanStatus::Suspended
    );
    assert_eq!(
        setup.plan(ACCOUNT, FAILED + 12 * DAY).status,
        PlanStatus::None
    );
}

// ---------------------------------------------------------------------------------------
// Prices and totals.

#[test]
fn the_plans_view_of_the_fake_prices_is_the_fixture() {
    let setup = Setup::new();
    let expected: PlansView = serde_json::from_value(fixture("plans.json")).unwrap();
    assert_eq!(setup.billing.plans(START).unwrap(), expected);
    // The cache answers without another price call.
    setup.billing.plans(START + 60).unwrap();
    assert_eq!(setup.stripe.calls_to("GET", "/v1/prices").len(), 1);
    let call = &setup.stripe.calls_to("GET", "/v1/prices")[0];
    let keys: Vec<&str> = call
        .query
        .iter()
        .filter(|(k, _)| k == "lookup_keys[]")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(keys.len(), 6);
    assert!(call.query.contains(&("active".into(), "true".into())));
    assert!(
        call.query
            .contains(&("expand[]".into(), "data.tiers".into()))
    );
}

#[test]
fn a_missing_or_malformed_price_keeps_its_plan_out() {
    let setup = Setup::new();
    let prices: Vec<Value> = fake_stripe::default_prices()
        .into_iter()
        .filter(|p| {
            !p["lookup_key"]
                .as_str()
                .unwrap()
                .starts_with("connect_team")
        })
        .map(|mut p| {
            if p["lookup_key"] == "connect_family_year" {
                p["tax_behavior"] = json!("exclusive");
            }
            p
        })
        .collect();
    setup.stripe.set_prices(prices);
    let view = setup.billing.plans(START).unwrap();
    let plans: Vec<Plan> = view.plans.iter().map(|p| p.plan).collect();
    assert_eq!(plans, [Plan::Personal, Plan::Family]);
    assert_eq!(view.plans[1].prices.len(), 1);
    assert!(
        setup
            .logs()
            .iter()
            .any(|l| l.contains("connect_family_year") && l.contains("inclusive"))
    );
    let error = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"team","interval":"month","seats":2}"#,
            START,
        )
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::BUSY, 503));
}

#[test]
fn the_totals_follow_the_formula_and_a_year_is_ten_months() {
    let plans: PlansView = serde_json::from_value(fixture("plans.json")).unwrap();
    let price = |plan: &str, interval: &str| {
        let entry = plans
            .plans
            .iter()
            .find(|p| p.plan.as_str() == plan)
            .unwrap();
        let price = entry
            .prices
            .iter()
            .find(|p| p.interval.as_str() == interval)
            .unwrap();
        (entry.plan, price.amount, price.extra)
    };
    let totals = fixture("totals.json");
    for case in totals["totals"].as_array().unwrap() {
        let (plan, amount, extra) = price(
            case["plan"].as_str().unwrap(),
            case["interval"].as_str().unwrap(),
        );
        let count = u32::try_from(case["count"].as_u64().unwrap()).unwrap();
        assert_eq!(
            total_cents(plan, amount, extra, count).unwrap(),
            case["amount"].as_u64().unwrap(),
            "{case}"
        );
    }
    for case in totals["seat_limit"].as_array().unwrap() {
        let (plan, amount, extra) = price(
            case["plan"].as_str().unwrap(),
            case["interval"].as_str().unwrap(),
        );
        let count = u32::try_from(case["count"].as_u64().unwrap()).unwrap();
        let error = total_cents(plan, amount, extra, count).unwrap_err();
        assert_eq!(
            (error.code, error.status()),
            (codes::SEAT_LIMIT, 409),
            "{case}"
        );
    }
    for entry in &plans.plans {
        let (month, year) = (&entry.prices[0], &entry.prices[1]);
        assert_eq!(year.amount, month.amount * 10, "{:?}", entry.plan);
        assert_eq!(year.extra, month.extra.map(|e| e * 10), "{:?}", entry.plan);
    }
    // A Family of 6: the graduated amount, 700 a month and 7000 a year.
    let (plan, amount, extra) = price("family", "month");
    assert_eq!(total_cents(plan, amount, extra, 6).unwrap(), 700);
    let (plan, amount, extra) = price("family", "year");
    assert_eq!(total_cents(plan, amount, extra, 6).unwrap(), 7000);
}

// ---------------------------------------------------------------------------------------
// Checkout and the portal.

#[test]
fn a_family_checkout_of_6_sends_the_contract_form() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let before = setup.store().subscriptions();
    let answer = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"family","interval":"year","people":6}"#,
            START,
        )
        .unwrap();
    assert!(
        answer
            .url
            .starts_with("https://checkout.stripe.com/c/pay/cs_test_")
    );
    assert!(answer.url.ends_with(&answer.session_id));
    assert_eq!(answer.expires_at, SESSION_EXPIRES_AT);
    let calls = setup.stripe.calls_to("POST", "/v1/checkout/sessions");
    assert_eq!(calls.len(), 1);
    let examples = fixture("examples.json");
    let form = examples["examples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "stripe_checkout_form")
        .unwrap()["body"]
        .clone();
    let expected: Vec<(String, String)> = serde_json::from_value(form).unwrap();
    assert_eq!(calls[0].form, expected);
    assert_eq!(calls[0].header("Stripe-Version"), Some(API_VERSION));
    assert!(
        calls[0]
            .header("Idempotency-Key")
            .is_some_and(|k| k.starts_with("apassy-checkout-"))
    );
    assert_eq!(
        calls[0].header("Content-Type"),
        Some("application/x-www-form-urlencoded")
    );
    // The checkout binds no subscription: the webhook does.
    assert_eq!(setup.store().subscriptions(), before);
    assert!(setup.store().groups().is_empty());
}

#[test]
fn a_family_of_6_is_bound_by_the_webhook_with_its_group() {
    let setup = Setup::new();
    let group = family(&setup, 6);
    let plan = setup.plan(ACCOUNT, START + 2);
    assert_eq!(plan.plan, Some(Plan::Family));
    assert_eq!(plan.quantity, Some(6));
    assert!(plan.entitled);
    assert_eq!(setup.store().groups().len(), 1);
    assert_eq!(setup.store().groups()[0].owner_account, ACCOUNT);
    assert!(group.starts_with("grp_") && group.len() == 14);
}

#[test]
fn a_team_checkout_of_a_returning_customer_adds_tax_ids_and_the_customer() {
    let setup = Setup::new();
    for event in vectors()["events"].as_array().unwrap() {
        setup.deliver_fixture(event["file"].as_str().unwrap());
    }
    // Canceled and read-only: the account may buy again, as the same customer.
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"team","interval":"month","seats":5}"#,
            ENDED + DAY,
        )
        .unwrap();
    let call = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .pop()
        .unwrap();
    assert_eq!(
        call.field("line_items[0][price]"),
        Some("price_SynthTeamMonth")
    );
    assert_eq!(call.field("line_items[0][quantity]"), Some("5"));
    assert_eq!(call.field("tax_id_collection[enabled]"), Some("true"));
    assert_eq!(call.field("customer"), Some(CUSTOMER));
    assert_eq!(call.field("customer_update[address]"), Some("auto"));
}

#[test]
fn checkout_refusals() {
    let setup = Setup::new();
    let refuse = |account: &str, body: &str| {
        setup
            .billing
            .checkout(account, body.as_bytes(), START + 5)
            .unwrap_err()
    };
    for (body, code) in [
        (
            r#"{"plan":"personal","interval":"month","people":1}"#,
            codes::INVALID_REQUEST,
        ),
        (
            r#"{"plan":"family","interval":"month"}"#,
            codes::INVALID_REQUEST,
        ),
        (
            r#"{"plan":"family","interval":"month","seats":4}"#,
            codes::INVALID_REQUEST,
        ),
        (
            r#"{"plan":"team","interval":"month","people":2}"#,
            codes::INVALID_REQUEST,
        ),
        (
            r#"{"plan":"team","interval":"week","seats":2}"#,
            codes::INVALID_REQUEST,
        ),
        (
            r#"{"plan":"personal","interval":"month","coupon":"free"}"#,
            codes::INVALID_REQUEST,
        ),
        (
            r#"{"plan":"family","interval":"month","people":11}"#,
            codes::SEAT_LIMIT,
        ),
        (
            r#"{"plan":"family","interval":"month","people":0}"#,
            codes::SEAT_LIMIT,
        ),
        (
            r#"{"plan":"team","interval":"year","seats":251}"#,
            codes::SEAT_LIMIT,
        ),
    ] {
        assert_eq!(refuse(ACCOUNT, body).code, code, "{body}");
    }
    assert_eq!(
        refuse(
            "acc_zzzzzzzzzz",
            r#"{"plan":"personal","interval":"month"}"#
        )
        .code,
        codes::NOT_FOUND
    );
    // An entitled account changes its plan in the portal.
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let error = refuse(
        ACCOUNT,
        r#"{"plan":"family","interval":"month","people":4}"#,
    );
    assert_eq!((error.code, error.status()), (codes::CONFLICT, 409));
    // A pending or active member of a group does not buy.
    let setup = Setup::new();
    let group = family(&setup, 4);
    for state in [MemberState::Pending, MemberState::Active] {
        setup
            .store()
            .add_member(&group, OTHER, GroupRole::Member, state);
        let error = setup
            .billing
            .checkout(
                OTHER,
                br#"{"plan":"personal","interval":"month"}"#,
                START + 5,
            )
            .unwrap_err();
        assert_eq!(error.code, codes::CONFLICT, "{state:?}");
    }
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/checkout/sessions")
            .is_empty()
    );
}

#[test]
fn a_family_extra_that_differs_from_stripe_refuses_family_checkouts() {
    let setup = Setup::with_config(BillingConfig {
        family_extra_cents: 150,
        ..BillingConfig::default()
    });
    let error = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"family","interval":"month","people":5}"#,
            START,
        )
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::BUSY, 503));
    assert!(setup.logs().iter().any(|l| l.contains("Family extra")));
    // Personal is not affected.
    assert!(
        setup
            .billing
            .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
            .is_ok()
    );
}

#[test]
fn a_repeated_checkout_gets_the_open_session_and_a_retry_reuses_its_key() {
    let setup = Setup::new();
    let body = br#"{"plan":"personal","interval":"year"}"#;
    setup.billing.plans(START).unwrap();
    setup.stripe.fail_path("/v1/checkout/sessions", 500, 1);
    let first = setup.billing.checkout(ACCOUNT, body, START).unwrap();
    let second = setup.billing.checkout(ACCOUNT, body, START + 60).unwrap();
    assert_eq!(
        (first.session_id.as_str(), first.url.as_str()),
        (second.session_id.as_str(), second.url.as_str()),
        "one click, one session"
    );
    // The retry of the failed call kept its key; the repeat read the open session back.
    let calls = setup.stripe.calls_to("POST", "/v1/checkout/sessions");
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].header("Idempotency-Key"),
        calls[1].header("Idempotency-Key")
    );
    assert_eq!(
        setup
            .stripe
            .calls_to(
                "GET",
                &format!("/v1/checkout/sessions/{}", first.session_id)
            )
            .len(),
        1
    );
}

#[test]
fn a_new_attempt_after_a_finished_session_or_with_another_price_is_a_new_session() {
    let setup = Setup::new();
    let body = br#"{"plan":"personal","interval":"month"}"#;
    let first = setup.billing.checkout(ACCOUNT, body, START).unwrap();
    // The payment failed after the session completed: a new attempt is a new session.
    setup
        .stripe
        .set_session_status(&first.session_id, "complete");
    let second = setup.billing.checkout(ACCOUNT, body, START + 60).unwrap();
    assert_ne!(second.session_id, first.session_id);
    // An expired session too.
    setup
        .stripe
        .set_session_status(&second.session_id, "expired");
    let third = setup.billing.checkout(ACCOUNT, body, START + 120).unwrap();
    assert_ne!(third.session_id, second.session_id);
    let keys: Vec<String> = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .iter()
        .filter(|c| c.path == "/v1/checkout/sessions")
        .map(|c| c.header("Idempotency-Key").unwrap().to_owned())
        .collect();
    assert_eq!(keys.len(), 3);
    assert!(keys[0] != keys[1] && keys[1] != keys[2] && keys[0] != keys[2]);
    // A price change within the hour: the new price, a new key, and the open session of
    // the old price ends first.
    let mut prices = fake_stripe::default_prices();
    prices[0]["id"] = json!("price_SynthPersonalMonthNew");
    setup.stripe.set_prices(prices);
    setup.billing.stripe.forget_prices();
    let fourth = setup.billing.checkout(ACCOUNT, body, START + 180).unwrap();
    assert_ne!(fourth.session_id, third.session_id);
    let last = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .into_iter()
        .rfind(|c| c.path == "/v1/checkout/sessions")
        .unwrap();
    assert_eq!(
        last.field("line_items[0][price]"),
        Some("price_SynthPersonalMonthNew")
    );
    assert!(!keys.contains(&last.header("Idempotency-Key").unwrap().to_owned()));
    assert_eq!(
        setup.stripe.session_status(&third.session_id).as_deref(),
        Some("expired")
    );
    // Another plan is another key too.
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"personal","interval":"year"}"#,
            START + 240,
        )
        .unwrap();
    let other = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .into_iter()
        .rfind(|c| c.path == "/v1/checkout/sessions")
        .unwrap();
    assert_ne!(
        other.header("Idempotency-Key"),
        last.header("Idempotency-Key")
    );
}

#[test]
fn stripe_refusals_and_outages_are_errors_without_a_change() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let body = br#"{"plan":"personal","interval":"month"}"#;
    setup.billing.plans(START).unwrap();
    setup
        .stripe
        .fail_method("POST", "/v1/checkout/sessions", 400, 1);
    let error = setup.billing.checkout(ACCOUNT, body, START).unwrap_err();
    assert_eq!((error.code, error.status()), (codes::UPSTREAM_FAILED, 502));
    setup
        .stripe
        .fail_method("POST", "/v1/checkout/sessions", 503, 2);
    let error = setup.billing.checkout(ACCOUNT, body, START).unwrap_err();
    assert_eq!((error.code, error.status()), (codes::BUSY, 503));
    assert!(setup.store().subscriptions().is_empty());
    let logs = setup.logs();
    assert!(logs.iter().any(|l| l.contains("POST /v1/checkout/sessions answered 400 (api_error/fake_failure)")), "{logs:?}");
    assert!(
        logs.iter().all(|l| !l.contains("fake stripe refusal")),
        "Stripe's message is not logged"
    );
}

#[test]
fn the_portal_is_for_the_owner_of_the_customer() {
    let setup = Setup::new();
    let error = setup.billing.portal(ACCOUNT, b"{}").unwrap_err();
    assert_eq!((error.code, error.status()), (codes::NOT_FOUND, 404));
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    let error = setup.billing.portal(OTHER, b"{}").unwrap_err();
    assert_eq!((error.code, error.status()), (codes::FORBIDDEN, 403));
    assert_eq!(
        setup
            .billing
            .portal(ACCOUNT, br#"{"x":1}"#)
            .unwrap_err()
            .code,
        codes::INVALID_REQUEST
    );
    let answer = setup.billing.portal(ACCOUNT, b"{}").unwrap();
    assert!(
        answer
            .url
            .starts_with("https://billing.stripe.com/p/session/")
    );
    let call = setup
        .stripe
        .calls_to("POST", "/v1/billing_portal/sessions")
        .pop()
        .unwrap();
    assert_eq!(
        call.form,
        [
            ("customer".to_owned(), CUSTOMER.to_owned()),
            (
                "return_url".to_owned(),
                "https://apassy.wyderka.cc/connect/done".to_owned()
            ),
        ]
    );
    assert!(call.header("Idempotency-Key").is_some());
}

// ---------------------------------------------------------------------------------------
// Seats and members.

#[test]
fn seats_below_the_members_are_seat_limit_and_only_the_owner_changes_them() {
    let setup = Setup::new();
    let group = family(&setup, 5);
    for (account, role) in [
        (OTHER, GroupRole::Member),
        (THIRD, GroupRole::Member),
        ("acc_a2b3c4d5ef", GroupRole::Member),
        ("acc_b2c3d4e5fg", GroupRole::Member),
    ] {
        setup
            .store()
            .add_member(&group, account, role, MemberState::Active);
    }
    setup.store().add_member(
        &group,
        "acc_c2d3e4f5gh",
        GroupRole::Member,
        MemberState::Pending,
    );
    let error = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":4}"#, START + 10)
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::SEAT_LIMIT, 409));
    assert_eq!(error.message, "The family has 5 people; choose at least 5.");
    let error = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":11}"#, START + 10)
        .unwrap_err();
    assert_eq!(error.code, codes::SEAT_LIMIT);
    // A member cannot change the quantity, and an account outside the group neither.
    let error = setup
        .billing
        .change_seats(OTHER, br#"{"quantity":10}"#, START + 10)
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::FORBIDDEN, 403));
    let error = setup
        .billing
        .change_seats("acc_c2d3e4f5gh", br#"{"quantity":10}"#, START + 10)
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::NOT_IN_GROUP, 403));
    setup.store().add_account("acc_d2e3f4g5hi");
    let error = setup
        .billing
        .change_seats("acc_d2e3f4g5hi", br#"{"quantity":10}"#, START + 10)
        .unwrap_err();
    assert_eq!(error.code, codes::NOT_IN_GROUP);
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .is_empty()
    );
    // The same quantity asks Stripe nothing.
    let same = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":5}"#, START + 10)
        .unwrap();
    assert!(!same.pending);
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .is_empty()
    );
}

#[test]
fn a_quantity_change_calls_stripe_with_prorations_and_applies_only_on_the_webhook() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    let answer = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":6}"#, START + 10)
        .unwrap();
    assert_eq!((answer.quantity, answer.pending), (6, true));
    let calls = setup.stripe.calls_to("POST", "/v1/subscription_items/");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/v1/subscription_items/si_SynthAcc0001");
    assert_eq!(
        calls[0].form,
        [
            ("quantity".to_owned(), "6".to_owned()),
            (
                "proration_behavior".to_owned(),
                "create_prorations".to_owned()
            ),
        ]
    );
    assert!(
        calls[0]
            .header("Idempotency-Key")
            .is_some_and(|k| k.starts_with("apassy-seats-"))
    );
    // Not applied yet: the stored quantity is Stripe's last word.
    assert_eq!(
        setup.store().subscription(SUBSCRIPTION).unwrap().quantity,
        4
    );
    assert_eq!(setup.plan(OTHER, START + 11).quantity, Some(4));
    // Each change gets its own key, so 6, then 4, then 6 again are three changes.
    setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":5}"#, START + 12)
        .unwrap();
    let keys: Vec<String> = setup
        .stripe
        .calls_to("POST", "/v1/subscription_items/")
        .iter()
        .map(|c| c.header("Idempotency-Key").unwrap().to_owned())
        .collect();
    assert_ne!(keys[0], keys[1]);
    // Stripe's webhook applies it.
    setup.deliver(
        &event(
            "evt_Quantity01",
            "customer.subscription.updated",
            START + 20,
            subscription(&Sub {
                lookup: "connect_family_month",
                quantity: 6,
                ..Sub::default()
            }),
        ),
        START + 20,
    );
    assert_eq!(
        setup.store().subscription(SUBSCRIPTION).unwrap().quantity,
        6
    );
    let member = setup.plan(OTHER, START + 21);
    assert_eq!(
        (member.plan, member.quantity, member.entitled),
        (Some(Plan::Family), Some(6), true)
    );
    assert_eq!(member.group_id.as_deref(), Some(group.as_str()));
}

#[test]
fn a_member_is_entitled_only_while_active_and_the_group_plan_is_entitled() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Pending);
    assert_eq!(
        setup.plan(OTHER, START + 5),
        apassy_relay::server::billing::PlanView::none()
    );
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    assert!(setup.plan(OTHER, START + 5).entitled);
    // The organizer cancels: the member is read-only with the group.
    setup.deliver(
        &event(
            "evt_FamDeleted",
            "customer.subscription.deleted",
            ENDED,
            subscription(&Sub {
                lookup: "connect_family_month",
                quantity: 4,
                status: "canceled",
                ended_at: Some(ENDED),
                ..Sub::default()
            }),
        ),
        ENDED,
    );
    let member = setup.plan(OTHER, ENDED + 1);
    assert_eq!(
        (member.status, member.entitled),
        (PlanStatus::ReadOnly, false)
    );
    // A seats change on an ended plan is refused before Stripe.
    let error = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":5}"#, ENDED + 1)
        .unwrap_err();
    assert_eq!(error.code, codes::PLAN_REQUIRED);
}

// ---------------------------------------------------------------------------------------
// What reaches Stripe and the logs.

#[test]
fn no_stripe_call_carries_an_account_secret_and_state_changes_only_by_webhook() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    let before = setup.store().snapshot();
    setup.stripe.clear_calls();
    setup.billing.plans(START).unwrap();
    setup.billing.portal(ACCOUNT, b"{}").unwrap();
    setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":7}"#, START + 3)
        .unwrap();
    setup.store().add_account(THIRD);
    setup
        .billing
        .checkout(
            THIRD,
            br#"{"plan":"team","interval":"year","seats":3}"#,
            START + 3,
        )
        .unwrap();
    assert!(setup.billing.cancel_for_account_deletion(ACCOUNT).unwrap());
    let calls = setup.stripe.calls();
    // The prices, the portal, the seats, THIRD's customer and its session; for ACCOUNT's
    // deletion the list of its open sessions, the list of its subscriptions, the cancel,
    // and the list once more.
    assert_eq!(calls.len(), 9, "{calls:?}");
    let made = setup.stripe.calls_to("POST", "/v1/customers");
    assert_eq!(made.len(), 1);
    assert_eq!(
        made[0].form,
        [("metadata[account_id]".to_owned(), THIRD.to_owned())]
    );
    // Only the headers of the client and of HTTP itself.
    let allowed_headers = [
        "authorization",
        "stripe-version",
        "idempotency-key",
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "user-agent",
        "host",
    ];
    // Only the ids, quantities, prices, and site URLs of contract section 1.
    let allowed_fields = [
        "mode",
        "line_items[0][price]",
        "line_items[0][quantity]",
        "automatic_tax[enabled]",
        "billing_address_collection",
        "client_reference_id",
        "metadata[account_id]",
        "subscription_data[metadata][account_id]",
        "consent_collection[terms_of_service]",
        "success_url",
        "cancel_url",
        "tax_id_collection[enabled]",
        "customer",
        "customer_update[address]",
        "customer_update[name]",
        "return_url",
        "quantity",
        "proration_behavior",
    ];
    let secret = endpoint_secret();
    for call in &calls {
        for (name, value) in &call.headers {
            assert!(
                allowed_headers.contains(&name.to_ascii_lowercase().as_str()),
                "header {name}"
            );
            assert!(!value.contains(secret.expose()));
        }
        assert_eq!(
            call.header("Authorization"),
            Some(format!("Bearer {FAKE_KEY}").as_str())
        );
        for (name, value) in call.form.iter().chain(call.query.iter()) {
            assert!(
                allowed_fields.contains(&name.as_str())
                    || ["lookup_keys[]", "active", "expand[]", "limit", "status"]
                        .contains(&name.as_str()),
                "field {name}"
            );
            assert!(!value.contains("apassy_"), "{name}: a token form");
            assert!(!value.contains(EMAIL), "{name}: the email");
            assert!(
                !value.contains("whsec_") && !value.contains("rk_"),
                "{name}: a key"
            );
        }
        assert!(
            call.method != "POST" || call.header("Idempotency-Key").is_some(),
            "{}",
            call.path
        );
    }
    let canceled = &calls[calls.len() - 2];
    assert_eq!(canceled.method, "DELETE");
    assert_eq!(canceled.path, format!("/v1/subscriptions/{SUBSCRIPTION}"));
    assert_eq!(
        (
            calls.last().unwrap().method.as_str(),
            calls.last().unwrap().path.as_str()
        ),
        ("GET", "/v1/subscriptions")
    );
    // None of these calls changed the subscriptions or the group; the account deletion
    // only dropped the email copy.
    let after = setup.store().subscription(SUBSCRIPTION).unwrap();
    assert_eq!((after.quantity, after.status), (4, StripeStatus::Active));
    assert_eq!(setup.store().customer(CUSTOMER).unwrap().email, None);
    assert_eq!(setup.store().groups().len(), 1);
    assert_ne!(
        setup.store().snapshot(),
        before,
        "only the email copy changed"
    );
}

#[test]
fn logs_hold_no_email_key_or_secret() {
    let setup = Setup::new();
    for event in vectors()["events"].as_array().unwrap() {
        setup.deliver_fixture(event["file"].as_str().unwrap());
    }
    setup.deliver_fixture("checkout-session-completed.json");
    let _ = setup.billing.webhook(Some("t=1,v1=00"), b"{}", START);
    setup.stripe.fail_next(400, 1);
    let _ = setup.billing.checkout(
        ACCOUNT,
        br#"{"plan":"personal","interval":"month"}"#,
        ENDED + DAY,
    );
    let logs = setup.logs();
    assert!(logs.len() >= 8, "{logs:?}");
    for line in &logs {
        assert!(!line.contains(EMAIL), "{line}");
        assert!(!line.contains('@'), "{line}");
        assert!(!line.contains(FAKE_KEY), "{line}");
        assert!(!line.contains(endpoint_secret().expose()), "{line}");
        assert!(!line.contains("whsec_"), "{line}");
    }
}

#[test]
fn a_failed_transaction_keeps_no_event_id() {
    // The in-memory store keeps changes only when the whole transaction succeeds, as
    // SQLite does: a store error leaves the event id unrecorded, so Stripe retries.
    let store = MemoryBillingStore::new();
    let result: Result<(), _> = store.transaction(|tx| {
        assert!(tx.record_event("evt_Rollback1", "invoice.paid", START)?);
        Err(apassy_relay::error::RelayError::internal("disk full"))
    });
    assert!(result.is_err());
    assert!(store.event_ids().is_empty());
}

#[test]
fn a_cancel_at_period_end_shows_the_end_and_stays_entitled() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver(
        &event(
            "evt_CancelEnd1",
            "customer.subscription.updated",
            START + 100,
            subscription(&Sub {
                cancel_at_period_end: true,
                ..Sub::default()
            }),
        ),
        START + 100,
    );
    let plan = setup.plan(ACCOUNT, START + 200);
    assert_eq!((plan.status, plan.entitled), (PlanStatus::Active, true));
    assert_eq!((plan.renews_at, plan.ends_at), (None, Some(PERIOD_END)));
}

// ---------------------------------------------------------------------------------------
// The review of billing and groups: paid seats, Stripe's word, and the deletion pass.

/// A `customer.subscription.<kind>` event of the default subscription.
fn sub_event(id: &str, kind: &str, created: u64, sub: &Sub<'_>) -> Value {
    event(
        id,
        &format!("customer.subscription.{kind}"),
        created,
        subscription(sub),
    )
}

#[test]
fn an_owner_with_members_buys_again_for_at_least_its_members() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    for account in [OTHER, THIRD] {
        setup
            .store()
            .add_member(&group, account, GroupRole::Member, MemberState::Active);
    }
    setup.deliver(
        &sub_event(
            "evt_FamEnded01",
            "deleted",
            ENDED,
            &Sub {
                lookup: "connect_family_month",
                quantity: 4,
                status: "canceled",
                ended_at: Some(ENDED),
                ..Sub::default()
            },
        ),
        ENDED,
    );
    let refuse = |body: &str| {
        setup
            .billing
            .checkout(ACCOUNT, body.as_bytes(), ENDED + DAY)
            .unwrap_err()
    };
    // Three people are in the family: two cannot be bought for them.
    let error = refuse(r#"{"plan":"family","interval":"month","people":2}"#);
    assert_eq!((error.code, error.status()), (codes::SEAT_LIMIT, 409));
    assert_eq!(error.message, "The family has 3 people; choose at least 3.");
    // Nor another plan that would leave them without one.
    for body in [
        r#"{"plan":"personal","interval":"month"}"#,
        r#"{"plan":"team","interval":"month","seats":5}"#,
    ] {
        assert_eq!(refuse(body).code, codes::CONFLICT, "{body}");
    }
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/checkout/sessions")
            .is_empty()
    );
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"family","interval":"month","people":3}"#,
            ENDED + DAY,
        )
        .unwrap();
}

#[test]
fn members_beyond_the_paid_seats_are_read_only_until_the_quantity_is_raised() {
    let setup = Setup::new();
    setup.deliver(
        &event(
            "evt_TeamCheckout",
            "checkout.session.completed",
            START,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, SUBSCRIPTION),
        ),
        START,
    );
    let team = Sub {
        lookup: "connect_team_month",
        quantity: 2,
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_TeamMade01", "created", START + 1, &team),
        START + 1,
    );
    let group = setup.plan(ACCOUNT, START + 2).group_id.unwrap();
    // The owner is the first seat, OTHER (confirmed first) the second; THIRD is beyond.
    for account in [OTHER, THIRD] {
        setup
            .store()
            .add_member(&group, account, GroupRole::Member, MemberState::Active);
    }
    assert!(setup.plan(ACCOUNT, START + 3).entitled);
    assert!(setup.plan(OTHER, START + 3).entitled);
    let beyond = setup.plan(THIRD, START + 3);
    assert_eq!(
        (beyond.status, beyond.entitled, beyond.delete_at),
        (PlanStatus::ReadOnly, false, None)
    );
    assert!(!beyond.state().allows(Capability::Push));
    // Stripe's quantity 3 covers THIRD.
    setup.deliver(
        &sub_event(
            "evt_TeamThree1",
            "updated",
            START + 10,
            &Sub {
                quantity: 3,
                ..team
            },
        ),
        START + 10,
    );
    assert!(setup.plan(THIRD, START + 11).entitled);
    // A Family pays for at least 4 people: a quantity of 2 covers four.
    let setup = Setup::new();
    let group = family(&setup, 2);
    for account in [OTHER, THIRD, "acc_a2b3c4d5ef", "acc_b2c3d4e5fg"] {
        setup
            .store()
            .add_member(&group, account, GroupRole::Member, MemberState::Active);
    }
    for account in [OTHER, THIRD, "acc_a2b3c4d5ef"] {
        assert!(setup.plan(account, START + 3).entitled, "{account}");
    }
    assert!(!setup.plan("acc_b2c3d4e5fg", START + 3).entitled);
}

/// A Team group of three active members on a subscription that pays for one.
fn team_with_unpaid_members(setup: &Setup) -> String {
    setup.deliver(
        &event(
            "evt_TeamCheckout",
            "checkout.session.completed",
            START,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, SUBSCRIPTION),
        ),
        START,
    );
    let team = Sub {
        lookup: "connect_team_month",
        quantity: 1,
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_TeamMade01", "created", START + 1, &team),
        START + 1,
    );
    let group = setup.plan(ACCOUNT, START + 2).group_id.unwrap();
    for account in [OTHER, THIRD] {
        setup
            .store()
            .add_member(&group, account, GroupRole::Member, MemberState::Active);
    }
    group
}

#[test]
fn the_maintenance_pass_leaves_the_quantity_to_the_owner_by_default() {
    let setup = Setup::new();
    assert!(!setup.billing.config.auto_raise_seats);
    let group = team_with_unpaid_members(&setup);
    assert!(setup.plan(ACCOUNT, START + 3).entitled);
    assert!(!setup.plan(THIRD, START + 3).entitled);
    for now in [START + 3, START + 3 + DAY] {
        let report = setup.billing.reconcile(now).unwrap();
        assert!(report.raised.is_empty(), "{now}");
        assert_eq!(report.failed, 0);
    }
    // No charge without the owner: Stripe saw no quantity change.
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .is_empty()
    );
    // The members beyond the paid quantity stay read-only, without a deletion day.
    let unpaid = setup.plan(THIRD, START + 4);
    assert_eq!(unpaid.status, PlanStatus::ReadOnly);
    assert_eq!(unpaid.delete_at, None);
    // The owner raises the seats: the same call that the pass makes with the setting.
    let answer = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":3}"#, START + 5)
        .unwrap();
    assert!(answer.pending);
    let calls = setup.stripe.calls_to("POST", "/v1/subscription_items/");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].field("quantity"), Some("3"));
    assert!(setup.plan(THIRD, START + 6).entitled);
    assert_eq!(
        setup.plan(OTHER, START + 6).group_id.as_deref(),
        Some(group.as_str())
    );
}

#[test]
fn the_maintenance_pass_raises_the_quantity_to_the_members() {
    let setup = Setup::with_config(BillingConfig {
        auto_raise_seats: true,
        ..BillingConfig::default()
    });
    let group = team_with_unpaid_members(&setup);
    assert!(!setup.plan(THIRD, START + 3).entitled);
    let report = setup.billing.reconcile(START + 3).unwrap();
    assert_eq!(report.raised, [(group.clone(), 3)]);
    let calls = setup.stripe.calls_to("POST", "/v1/subscription_items/");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].field("quantity"), Some("3"));
    assert_eq!(
        calls[0].field("proration_behavior"),
        Some("create_prorations")
    );
    // Stripe accepted it: the members are paid for before the webhook arrives.
    assert!(setup.plan(THIRD, START + 4).entitled);
    // The next pass asks nothing again.
    assert!(
        setup
            .billing
            .reconcile(START + 5)
            .unwrap()
            .raised
            .is_empty()
    );
    assert_eq!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .len(),
        1
    );
}

#[test]
fn a_price_without_its_lookup_key_keeps_the_stored_plan_and_applies_every_status() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    assert!(setup.plan(ACCOUNT, START + 10).entitled);
    // The products script moved the lookup key to a new price: the old price of this
    // subscription has none in its events.
    let keyless = |id: &str, status: &str, created: u64, ended_at: Option<u64>| {
        let mut object = subscription(&Sub {
            status,
            ended_at,
            ..Sub::default()
        });
        object["items"]["data"][0]["price"]["lookup_key"] = Value::Null;
        event(id, "customer.subscription.updated", created, object)
    };
    for (id, status, created) in [
        ("evt_Keyless01", "past_due", FAILED),
        ("evt_Keyless02", "unpaid", FAILED + DAY),
    ] {
        let effect = setup.deliver(&keyless(id, status, created, None), created);
        assert!(matches!(effect, WebhookEffect::Applied { .. }), "{status}");
        let row = setup.store().subscription(SUBSCRIPTION).unwrap();
        assert_eq!(row.status.as_str(), status);
        assert_eq!(
            (row.plan, row.interval),
            (Some(Plan::Personal), Some(Interval::Month))
        );
    }
    let mut deleted = keyless("evt_Keyless03", "canceled", ENDED, Some(ENDED));
    deleted["type"] = json!("customer.subscription.deleted");
    setup.deliver(&deleted, ENDED);
    let row = setup.store().subscription(SUBSCRIPTION).unwrap();
    assert_eq!(
        (row.status, row.ended_at),
        (StripeStatus::Canceled, Some(ENDED))
    );
    assert_eq!(setup.plan(ACCOUNT, ENDED + 1).status, PlanStatus::ReadOnly);
    assert!(setup.store().problems().is_empty());
    // A new subscription on a price that lost its key maps by the price's metadata.
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    let mut object = subscription(&Sub {
        lookup: "connect_family_year",
        quantity: 5,
        ..Sub::default()
    });
    object["items"]["data"][0]["price"] = json!({
        "id": "price_SynthOldFamilyYear", "object": "price", "lookup_key": null,
        "metadata": {"apassy_plan": "family"},
        "recurring": {"interval": "year", "interval_count": 1}
    });
    setup.deliver(
        &event(
            "evt_OldPrice01",
            "customer.subscription.created",
            START + 1,
            object,
        ),
        START + 1,
    );
    let plan = setup.plan(ACCOUNT, START + 2);
    assert_eq!(
        (plan.plan, plan.interval, plan.quantity),
        (Some(Plan::Family), Some(Interval::Year), Some(5))
    );
}

#[test]
fn canceled_and_incomplete_expired_are_final() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let canceled = Sub {
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_Final00001", "deleted", ENDED, &canceled),
        ENDED,
    );
    // `active` with the same `created` second, and later, changes nothing.
    for (id, created) in [("evt_Final00002", ENDED), ("evt_Final00003", ENDED + 60)] {
        assert_eq!(
            setup.deliver(&sub_event(id, "updated", created, &Sub::default()), created),
            WebhookEffect::Ignored
        );
    }
    assert_eq!(
        setup.store().subscription(SUBSCRIPTION).unwrap().status,
        StripeStatus::Canceled
    );
    assert!(!setup.plan(ACCOUNT, ENDED + 100).entitled);
    // incomplete_expired too.
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    let expired = Sub {
        status: "incomplete_expired",
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_Expired001", "updated", START + 5, &expired),
        START + 5,
    );
    setup.deliver(
        &sub_event("evt_Expired002", "updated", START + 9, &Sub::default()),
        START + 9,
    );
    assert_eq!(
        setup.store().subscription(SUBSCRIPTION).unwrap().status,
        StripeStatus::IncompleteExpired
    );
}

#[test]
fn members_take_the_paid_subscription_of_the_group_over_a_late_event_of_an_old_one() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    let old = Sub {
        lookup: "connect_family_month",
        quantity: 4,
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    };
    setup.deliver(&sub_event("evt_OldEnded01", "deleted", ENDED, &old), ENDED);
    // The owner buys again: a new subscription of the same customer keeps the group.
    let new_id = "sub_SynthAcc0002";
    setup.deliver(
        &event(
            "evt_NewCheckout",
            "checkout.session.completed",
            ENDED + 100,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, new_id),
        ),
        ENDED + 100,
    );
    let new = Sub {
        id: new_id,
        lookup: "connect_family_month",
        quantity: 4,
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_NewMade001", "created", ENDED + 101, &new),
        ENDED + 101,
    );
    assert_eq!(
        setup.plan(OTHER, ENDED + 102).group_id.as_deref(),
        Some(group.as_str())
    );
    // A late event of the old subscription, newer than the new one's, hides nothing.
    setup.deliver(
        &sub_event("evt_OldLate001", "updated", ENDED + 500, &old),
        ENDED + 500,
    );
    let member = setup.plan(OTHER, ENDED + 501);
    assert_eq!(
        (member.status, member.entitled, member.group_id.as_deref()),
        (PlanStatus::Active, true, Some(group.as_str()))
    );
    // At the old plan's deletion day the members keep their stores: the group is paid.
    let day = ENDED + 91 * DAY;
    let due = setup.billing.maintenance(day).unwrap().due;
    assert!(
        due.iter().any(|d| d.subscription == SUBSCRIPTION),
        "{due:?}"
    );
    assert!(!setup.billing.deletes_members(SUBSCRIPTION, day).unwrap());
    assert!(setup.plan(OTHER, day).entitled);
}

#[test]
fn a_switch_to_personal_gives_the_members_the_read_only_window_and_never_their_deletion() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    // The owner switches to Personal in the portal: the subscription keeps its group.
    let switched = START + 100;
    setup.deliver(
        &sub_event("evt_ToPersonal", "updated", switched, &Sub::default()),
        switched,
    );
    let owner = setup.plan(ACCOUNT, switched + 1);
    assert_eq!(
        (owner.plan, owner.entitled, owner.group_id),
        (Some(Plan::Personal), true, None)
    );
    let member = setup.plan(OTHER, switched + 1);
    assert_eq!(
        (member.status, member.entitled),
        (PlanStatus::ReadOnly, false)
    );
    assert_eq!(member.read_only_until, Some(switched + 30 * DAY));
    assert_eq!(member.delete_at, None);
    assert!(member.state().allows(Capability::Pull));
    // The family has no plan of its own: no invite, no confirm, no seats.
    assert!(
        setup
            .billing
            .group_plan(&group, switched + 1)
            .unwrap()
            .is_none()
    );
    let error = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":5}"#, switched + 1)
        .unwrap_err();
    assert_eq!(error.code, codes::PLAN_REQUIRED);
    // The owner's Personal plan ends later; at its deletion day the members keep theirs.
    setup.deliver(
        &sub_event(
            "evt_PersonalEnd",
            "deleted",
            ENDED,
            &Sub {
                status: "canceled",
                ended_at: Some(ENDED),
                ..Sub::default()
            },
        ),
        ENDED,
    );
    let day = ENDED + 91 * DAY;
    assert!(
        setup
            .billing
            .maintenance(day)
            .unwrap()
            .due
            .iter()
            .any(|d| d.subscription == SUBSCRIPTION)
    );
    assert!(!setup.billing.deletes_members(SUBSCRIPTION, day).unwrap());
    // Back to Family before that: the members are entitled again.
    let setup = Setup::new();
    let group = family(&setup, 4);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Active);
    setup.deliver(
        &sub_event("evt_ToPersonal", "updated", START + 100, &Sub::default()),
        START + 100,
    );
    setup.deliver(
        &sub_event(
            "evt_BackFamily",
            "updated",
            START + 200,
            &Sub {
                lookup: "connect_family_month",
                quantity: 4,
                ..Sub::default()
            },
        ),
        START + 200,
    );
    assert!(setup.plan(OTHER, START + 201).entitled);
}

#[test]
fn a_first_checkout_makes_the_customer_and_every_session_names_it() {
    let setup = Setup::new();
    // Two first checkouts at once make one customer.
    std::thread::scope(|scope| {
        for body in [
            br#"{"plan":"personal","interval":"month"}"#.as_slice(),
            br#"{"plan":"personal","interval":"year"}"#.as_slice(),
        ] {
            let billing = &setup.billing;
            scope.spawn(move || billing.checkout(ACCOUNT, body, START).unwrap());
        }
    });
    let customers = setup.store().customers();
    assert_eq!(customers.len(), 1, "{customers:?}");
    let customer = customers[0].customer.clone();
    assert_eq!(customers[0].account, ACCOUNT);
    let made = setup.stripe.calls_to("POST", "/v1/customers");
    assert!(!made.is_empty());
    assert!(
        made.iter()
            .all(|call| call.header("Idempotency-Key") == made[0].header("Idempotency-Key"))
    );
    // One after the other: the second request ends the first one's open session.
    let sessions: Vec<_> = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .into_iter()
        .filter(|call| call.path == "/v1/checkout/sessions")
        .collect();
    assert_eq!(sessions.len(), 2);
    for call in &sessions {
        assert_eq!(call.field("customer"), Some(customer.as_str()));
        assert_eq!(call.field("customer_update[address]"), Some("auto"));
    }
    assert_eq!(
        setup
            .stripe
            .calls_to("POST", "/v1/checkout/sessions/")
            .iter()
            .filter(|call| call.path.ends_with("/expire"))
            .count(),
        1
    );
    // The later session binds as usual: Stripe made it for the same customer.
    setup.deliver(
        &event(
            "evt_MadeCustomer",
            "checkout.session.completed",
            START + 5,
            checkout_session(ACCOUNT, ACCOUNT, &customer, SUBSCRIPTION),
        ),
        START + 5,
    );
    assert!(setup.store().problems().is_empty());
    assert_eq!(
        setup.store().subscription(SUBSCRIPTION).unwrap().customer,
        customer
    );
}

#[test]
fn a_paid_subscription_connect_cannot_bind_is_recorded_for_the_operator() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    // A second customer of the same account (an old session): acknowledged, not applied,
    // and recorded with its ids.
    let other = ("cus_SynthOther01", "sub_SynthOther01");
    let effect = setup.deliver(
        &event(
            "evt_Elsewhere01",
            "checkout.session.completed",
            START + 5,
            checkout_session(ACCOUNT, ACCOUNT, other.0, other.1),
        ),
        START + 5,
    );
    assert_eq!(effect, WebhookEffect::Ignored);
    let effect = setup.deliver(
        &sub_event(
            "evt_Elsewhere02",
            "created",
            START + 6,
            &Sub {
                id: other.1,
                customer: other.0,
                ..Sub::default()
            },
        ),
        START + 6,
    );
    assert_eq!(effect, WebhookEffect::Ignored);
    let problems = setup.store().problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert_eq!(
        (
            problems[0].object.as_str(),
            problems[0].account_id.as_deref(),
            problems[0].customer_id.as_deref(),
            problems[0].reason.as_str(),
            problems[0].events
        ),
        (other.1, Some(ACCOUNT), Some(other.0), "bound_elsewhere", 2)
    );
    assert_eq!(setup.billing.status().unwrap().open_problems, 1);
    assert!(
        setup
            .logs()
            .iter()
            .any(|l| l.contains("recorded for the operator"))
    );
    setup
        .billing
        .resolve_problem(problems[0].id, START + 7)
        .unwrap();
    assert_eq!(setup.billing.status().unwrap().open_problems, 0);
    // A canceled one charges nothing: it is not recorded.
    setup.deliver(
        &sub_event(
            "evt_Elsewhere03",
            "deleted",
            START + 8,
            &Sub {
                id: "sub_SynthOther02",
                customer: "cus_SynthOther02",
                status: "canceled",
                ended_at: Some(START + 8),
                ..Sub::default()
            },
        ),
        START + 8,
    );
    assert_eq!(setup.billing.status().unwrap().open_problems, 0);
}

#[test]
fn the_deletion_asks_stripe_first_and_applies_what_stripe_shows() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let canceled = Sub {
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_Ended00001", "deleted", ENDED, &canceled),
        ENDED,
    );
    let day = ENDED + 91 * DAY;
    setup.stripe.set_date(Some(day));
    // Stripe shows it canceled too: the stores may go.
    setup.stripe.put_subscription(subscription(&canceled));
    assert_eq!(
        setup.billing.verify_ended(SUBSCRIPTION, day).unwrap(),
        StripeCheck::Ended
    );
    // Stripe cannot be reached: an error, nothing changes, the next pass asks again.
    setup.stripe.fail_path("/v1/subscriptions/", 503, 2);
    assert_eq!(
        setup
            .billing
            .verify_ended(SUBSCRIPTION, day)
            .unwrap_err()
            .code,
        codes::BUSY
    );
    // Stripe's clock is a week behind the relay's: nothing is deleted.
    setup.stripe.set_date(Some(day - 7 * DAY));
    let setup_clock = Setup::new();
    setup_clock.deliver_fixture("checkout-session-completed.json");
    setup_clock.deliver(
        &sub_event("evt_Ended00001", "deleted", ENDED, &canceled),
        ENDED,
    );
    setup_clock.stripe.put_subscription(subscription(&canceled));
    setup_clock.stripe.set_date(Some(day - 7 * DAY));
    assert_eq!(
        setup_clock.billing.verify_ended(SUBSCRIPTION, day).unwrap(),
        StripeCheck::ClockAhead
    );
    // A lost renewal: the local row ended, Stripe shows it active. Its state applies and
    // the plan is entitled again.
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver(
        &sub_event(
            "evt_Ended00001",
            "updated",
            ENDED,
            &Sub {
                status: "unpaid",
                ..Sub::default()
            },
        ),
        ENDED,
    );
    setup.stripe.set_date(Some(day));
    setup.stripe.put_subscription(subscription(&Sub::default()));
    assert_eq!(
        setup.billing.verify_ended(SUBSCRIPTION, day).unwrap(),
        StripeCheck::Live
    );
    assert!(setup.plan(ACCOUNT, day).entitled);
    assert!(setup.billing.maintenance(day).unwrap().due.is_empty());
}

#[test]
fn a_live_row_whose_period_ended_long_ago_is_read_from_stripe() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    // The cancellation's event was lost; Stripe shows the subscription canceled.
    let canceled = Sub {
        status: "canceled",
        ended_at: Some(PERIOD_END),
        ..Sub::default()
    };
    setup.stripe.put_subscription(subscription(&canceled));
    let soon = PERIOD_END + DAY;
    assert!(setup.billing.reconcile(soon).unwrap().read.is_empty());
    let later = PERIOD_END + 3 * DAY;
    let report = setup.billing.reconcile(later).unwrap();
    assert_eq!(report.read, [(SUBSCRIPTION.to_owned(), ACCOUNT.to_owned())]);
    let plan = setup.plan(ACCOUNT, later);
    assert_eq!((plan.status, plan.entitled), (PlanStatus::ReadOnly, false));
    assert_eq!(plan.read_only_until, Some(PERIOD_END + 30 * DAY));
    // A row Stripe shows live is asked at most once a day.
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    setup.stripe.put_subscription(subscription(&Sub::default()));
    assert_eq!(setup.billing.reconcile(later).unwrap().read.len(), 1);
    assert!(
        setup
            .billing
            .reconcile(later + 3600)
            .unwrap()
            .read
            .is_empty()
    );
    assert_eq!(
        setup.billing.reconcile(later + DAY + 1).unwrap().read.len(),
        1
    );
    assert_eq!(setup.stripe.calls_to("GET", "/v1/subscriptions/").len(), 2);
}

#[test]
fn a_gap_between_passes_holds_deletions_until_the_operator_resumes_them() {
    let setup = Setup::new();
    assert_eq!(
        setup.billing.deletion_gate(START).unwrap(),
        DeletionGate::Open
    );
    assert_eq!(
        setup.billing.deletion_gate(START + 3600).unwrap(),
        DeletionGate::Open
    );
    // The clock jumps three days ahead.
    let jumped = START + 3600 + 3 * DAY;
    assert_eq!(
        setup.billing.deletion_gate(jumped).unwrap(),
        DeletionGate::Held { since: jumped }
    );
    // It stays held at the next passes.
    assert_eq!(
        setup.billing.deletion_gate(jumped + 3600).unwrap(),
        DeletionGate::Held { since: jumped }
    );
    assert_eq!(
        setup.billing.status().unwrap().deletions_held_since,
        Some(jumped)
    );
    // The operator checked the clock.
    setup.billing.resume_deletions(jumped + 7200).unwrap();
    assert_eq!(
        setup.billing.deletion_gate(jumped + 10_800).unwrap(),
        DeletionGate::Open
    );
}

#[test]
fn a_failed_price_lookup_waits_before_the_next_one() {
    let setup = Setup::new();
    setup.stripe.fail_next(503, 20);
    assert_eq!(setup.billing.plans(START).unwrap_err().code, codes::BUSY);
    let after_first = setup.stripe.calls_to("GET", "/v1/prices").len();
    assert_eq!(after_first, 2, "the call and its retry");
    // Requests within the minute ask Stripe nothing.
    for t in [START + 1, START + 30, START + 59] {
        assert_eq!(setup.billing.plans(t).unwrap_err().code, codes::BUSY);
    }
    assert_eq!(
        setup.stripe.calls_to("GET", "/v1/prices").len(),
        after_first
    );
    assert_eq!(
        setup.billing.plans(START + 60).unwrap_err().code,
        codes::BUSY
    );
    assert_eq!(
        setup.stripe.calls_to("GET", "/v1/prices").len(),
        after_first + 2
    );
    // With cached prices, a failure answers them and waits too.
    let setup = Setup::new();
    setup.billing.plans(START).unwrap();
    setup.stripe.fail_next(503, 20);
    let stale = START + 3601;
    assert!(setup.billing.plans(stale).is_ok());
    assert!(setup.billing.plans(stale + 10).is_ok());
    assert_eq!(setup.stripe.calls_to("GET", "/v1/prices").len(), 3);
}

#[test]
fn a_session_or_portal_on_another_origin_is_refused() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    setup
        .stripe
        .set_checkout_origin("https://checkout.stripe.com.example.test/");
    let error = setup
        .billing
        .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::UPSTREAM_FAILED, 502));
    let answer = setup.billing.portal(ACCOUNT, b"{}").unwrap();
    assert!(
        answer
            .url
            .starts_with("https://billing.stripe.com/p/session/")
    );
}

// ---------------------------------------------------------------------------------------
// Groups and plans that cannot bind, other subscriptions at Stripe, and the pass.

/// The open problems of the store, as (object, reason).
fn problems(setup: &Setup) -> Vec<(String, String)> {
    setup
        .store()
        .problems()
        .into_iter()
        .map(|row| (row.object, row.reason))
        .collect()
}

/// A Family of ACCOUNT whose subscription ended (`canceled`), here and at Stripe.
fn ended_family(setup: &Setup) -> String {
    let group = family(setup, 4);
    let ended = Sub {
        lookup: "connect_family_month",
        quantity: 4,
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_FamEnded02", "deleted", ENDED, &ended),
        ENDED,
    );
    setup.stripe.put_subscription(subscription(&ended));
    group
}

#[test]
fn the_owner_alone_in_an_ended_family_buys_team_and_the_group_takes_its_kind() {
    let setup = Setup::new();
    let group = ended_family(&setup);
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"team","interval":"month","seats":3}"#,
            ENDED + DAY,
        )
        .unwrap();
    let team = "sub_SynthTeam0002";
    setup.deliver(
        &event(
            "evt_TeamAfterFamily",
            "checkout.session.completed",
            ENDED + DAY + 10,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, team),
        ),
        ENDED + DAY + 10,
    );
    setup.deliver(
        &sub_event(
            "evt_TeamAfterFamily2",
            "created",
            ENDED + DAY + 11,
            &Sub {
                id: team,
                lookup: "connect_team_month",
                quantity: 3,
                ..Sub::default()
            },
        ),
        ENDED + DAY + 11,
    );
    // The same group, now a team, with its plan: invites and seats work again.
    let groups = setup.store().groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(
        (groups[0].group_id.as_str(), groups[0].kind),
        (
            group.as_str(),
            apassy_relay::server::billing::GroupKind::Team
        )
    );
    let plan = setup
        .billing
        .group_plan(&group, ENDED + DAY + 12)
        .unwrap()
        .expect("the group's plan");
    assert!(plan.state.entitled);
    assert_eq!(plan.subscription, team);
    assert!(problems(&setup).is_empty(), "{:?}", problems(&setup));
}

#[test]
fn a_plan_of_the_other_kind_is_refused_while_the_group_has_someone_else() {
    let setup = Setup::new();
    let group = ended_family(&setup);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Pending);
    let error = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"team","interval":"month","seats":3}"#,
            ENDED + DAY,
        )
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::CONFLICT, 409));
    // Connect Personal stays possible: no other active member loses a plan.
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"personal","interval":"month"}"#,
            ENDED + DAY,
        )
        .unwrap();
}

#[test]
fn a_family_bought_by_a_member_of_another_group_is_recorded_and_bound_by_the_pass_later() {
    let setup = Setup::new();
    // OTHER owns a family; ACCOUNT joined it after it opened a checkout of its own.
    setup.store().add_account(OTHER);
    let other_group = setup
        .store()
        .transaction(|tx| {
            tx.create_group(
                apassy_relay::server::billing::GroupKind::Family,
                OTHER,
                START,
            )
        })
        .unwrap();
    setup.store().add_member(
        &other_group,
        ACCOUNT,
        GroupRole::Member,
        MemberState::Active,
    );
    let own = Sub {
        lookup: "connect_family_month",
        quantity: 4,
        ..Sub::default()
    };
    setup.deliver(
        &event(
            "evt_MemberPaid01",
            "checkout.session.completed",
            START + 1,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, SUBSCRIPTION),
        ),
        START + 1,
    );
    setup.deliver(
        &sub_event("evt_MemberPaid02", "created", START + 2, &own),
        START + 2,
    );
    // It charges and has no group: the operator sees it.
    assert_eq!(
        problems(&setup),
        [(SUBSCRIPTION.to_owned(), "no_group".to_owned())]
    );
    assert!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .group_id
            .is_none()
    );
    // The pass looks again: still in the other group, the problem is not counted again.
    let before = setup.store().problems();
    setup.billing.reconcile(START + 3).unwrap();
    assert_eq!(setup.store().problems(), before);
    // It left the other group: the pass makes its own family.
    setup.store().remove_member(ACCOUNT);
    setup.billing.reconcile(START + 4).unwrap();
    let bound = setup.store().subscription(SUBSCRIPTION).unwrap();
    let group = bound.group_id.expect("a group of its own");
    assert_ne!(group, other_group);
    assert!(setup.plan(ACCOUNT, START + 5).entitled);
    // Bound now: its `no_group` problem closed itself.
    assert!(problems(&setup).is_empty(), "{:?}", problems(&setup));
}

#[test]
fn a_subscription_that_is_not_over_at_stripe_refuses_a_new_checkout() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let body = br#"{"plan":"personal","interval":"month"}"#;
    for status in ["unpaid", "paused", "past_due", "incomplete"] {
        // Stripe has it; its events have not arrived here.
        setup.stripe.put_subscription(subscription(&Sub {
            status,
            ..Sub::default()
        }));
        let error = setup.billing.checkout(ACCOUNT, body, START).unwrap_err();
        assert_eq!(
            (error.code, error.status()),
            (codes::CONFLICT, 409),
            "{status}"
        );
    }
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/checkout/sessions")
            .is_empty()
    );
    // Ended at Stripe: the account buys again.
    setup.stripe.put_subscription(subscription(&Sub {
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    }));
    setup.billing.checkout(ACCOUNT, body, START).unwrap();
}

#[test]
fn a_new_session_after_a_completed_one_is_a_new_session() {
    let setup = Setup::new();
    let body = br#"{"plan":"personal","interval":"month"}"#;
    let first = setup.billing.checkout(ACCOUNT, body, START).unwrap();
    let customer = setup.store().customers()[0].customer.clone();
    let mut done = checkout_session(ACCOUNT, ACCOUNT, &customer, SUBSCRIPTION);
    done["id"] = json!(first.session_id);
    setup.deliver(
        &event(
            "evt_FirstDone",
            "checkout.session.completed",
            START + 5,
            done,
        ),
        START + 5,
    );
    setup
        .stripe
        .set_session_status(&first.session_id, "complete");
    // Its payment failed for good; the same request again.
    setup.stripe.put_subscription(subscription(&Sub {
        customer: &customer,
        status: "incomplete_expired",
        ..Sub::default()
    }));
    let second = setup.billing.checkout(ACCOUNT, body, START + DAY).unwrap();
    assert_ne!(second.session_id, first.session_id);
    let keys: Vec<_> = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .into_iter()
        .filter(|call| call.path == "/v1/checkout/sessions")
        .map(|call| call.header("Idempotency-Key").unwrap().to_owned())
        .collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn a_team_session_for_an_existing_customer_lets_stripe_save_the_business_name() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"team","interval":"month","seats":2}"#,
            START,
        )
        .unwrap();
    let call = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .pop()
        .unwrap();
    assert_eq!(call.field("tax_id_collection[enabled]"), Some("true"));
    assert_eq!(call.field("customer_update[name]"), Some("auto"));
    assert_eq!(call.field("customer_update[address]"), Some("auto"));
    // Personal and Family collect no tax id and leave the name alone.
    let form = apassy_relay::server::billing::checkout_form(
        ACCOUNT,
        "price_SynthFamilyMonth",
        4,
        Plan::Family,
        Some(CUSTOMER),
        "https://apassy.wyderka.cc",
    );
    assert!(
        form.pairs()
            .iter()
            .all(|(k, _)| k != "customer_update[name]")
    );
}

#[test]
fn a_personal_plan_with_more_than_one_unit_is_recorded_and_set_to_one_by_the_pass() {
    let setup = Setup::new();
    let group = family(&setup, 6);
    // The owner switched to Personal in the portal; the quantity of 6 stayed.
    setup.stripe.put_subscription(subscription(&Sub {
        quantity: 6,
        ..Sub::default()
    }));
    setup.deliver(
        &sub_event(
            "evt_ToPersonal6",
            "updated",
            START + 10,
            &Sub {
                quantity: 6,
                ..Sub::default()
            },
        ),
        START + 10,
    );
    assert_eq!(
        problems(&setup),
        [(SUBSCRIPTION.to_owned(), "personal_quantity".to_owned())]
    );
    let report = setup.billing.reconcile(START + 11).unwrap();
    assert_eq!(report.failed, 0);
    let calls = setup.stripe.calls_to("POST", "/v1/subscription_items/");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].field("quantity"), Some("1"));
    assert_eq!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .effective_quantity(),
        1
    );
    // The next pass asks nothing again; the group keeps no plan.
    setup.billing.reconcile(START + 12).unwrap();
    assert_eq!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .len(),
        1
    );
    assert!(
        setup
            .billing
            .group_plan(&group, START + 12)
            .unwrap()
            .is_none()
    );
}

#[test]
fn account_deletion_cancels_unpaid_paused_and_unknown_subscriptions() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    for (id, status) in [
        ("sub_SynthUnpaid01", "unpaid"),
        ("sub_SynthPaused01", "paused"),
        ("sub_SynthGone0001", "canceled"),
    ] {
        let sub = Sub {
            id,
            status,
            ..Sub::default()
        };
        setup.deliver(
            &sub_event(&format!("evt_{}", &id[4..]), "created", START + 1, &sub),
            START + 1,
        );
        setup.stripe.put_subscription(subscription(&sub));
    }
    // One Stripe has whose events never arrived.
    setup.stripe.put_subscription(subscription(&Sub {
        id: "sub_SynthUnseen01",
        ..Sub::default()
    }));
    assert!(setup.billing.cancel_for_account_deletion(ACCOUNT).unwrap());
    let mut canceled: Vec<String> = setup
        .stripe
        .calls_to("DELETE", "/v1/subscriptions/")
        .into_iter()
        .map(|call| call.path["/v1/subscriptions/".len()..].to_owned())
        .collect();
    canceled.sort();
    assert_eq!(
        canceled,
        [
            "sub_SynthPaused01",
            "sub_SynthUnpaid01",
            "sub_SynthUnseen01"
        ]
    );
    // The account is gone; a later event that charges again is recorded.
    setup.store().remove_account(ACCOUNT);
    setup.deliver(
        &sub_event(
            "evt_ChargesAgain",
            "updated",
            START + 50,
            &Sub {
                id: "sub_SynthUnpaid01",
                status: "active",
                ..Sub::default()
            },
        ),
        START + 50,
    );
    assert_eq!(
        problems(&setup),
        [("sub_SynthUnpaid01".to_owned(), "deleted_account".to_owned())]
    );
}

#[test]
fn concurrent_price_lookups_ask_stripe_once() {
    let setup = Setup::new();
    setup.stripe.delay_next("/v1/prices", 400);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let billing = &setup.billing;
            scope.spawn(move || billing.plans(START).unwrap());
        }
    });
    assert_eq!(setup.stripe.calls_to("GET", "/v1/prices").len(), 1);
}

#[test]
fn a_quantity_change_whose_answer_was_lost_is_read_back_from_stripe() {
    let setup = Setup::new();
    family(&setup, 4);
    setup.stripe.put_subscription(subscription(&Sub {
        lookup: "connect_family_month",
        quantity: 4,
        ..Sub::default()
    }));
    // Stripe takes the change, and both answers are lost.
    setup.stripe.fail_after("/v1/subscription_items/", 503, 2);
    let answer = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":6}"#, START + 3)
        .unwrap();
    assert_eq!((answer.quantity, answer.pending), (6, true));
    assert_eq!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .requested_quantity,
        Some(6)
    );
    // Lost and not taken (Stripe still has 6, 7 was asked): the error stays.
    setup.stripe.fail_path("/v1/subscription_items/", 503, 2);
    let error = setup
        .billing
        .change_seats(ACCOUNT, br#"{"quantity":7}"#, START + 4)
        .unwrap_err();
    assert_eq!(error.code, codes::BUSY);
}

#[test]
fn a_raise_that_stripe_refuses_is_recorded_once_and_not_asked_every_pass() {
    let setup = Setup::with_config(BillingConfig {
        auto_raise_seats: true,
        ..BillingConfig::default()
    });
    team_with_unpaid_members(&setup);
    setup.stripe.fail_path("/v1/subscription_items/", 400, 1);
    let report = setup.billing.reconcile(START + 3).unwrap();
    assert_eq!(report.failed, 1);
    assert_eq!(
        problems(&setup),
        [(SUBSCRIPTION.to_owned(), "raise_refused".to_owned())]
    );
    for now in [START + 3 + 3600, START + 3 + DAY] {
        assert!(setup.billing.reconcile(now).unwrap().raised.is_empty());
    }
    assert_eq!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .len(),
        1
    );
    // The operator resolved it: the next pass asks again.
    let id = setup.store().problems()[0].id;
    setup.billing.resolve_problem(id, START + 2 * DAY).unwrap();
    assert_eq!(
        setup
            .billing
            .reconcile(START + 2 * DAY)
            .unwrap()
            .raised
            .len(),
        1
    );
}

#[test]
fn a_read_without_stripes_time_does_not_take_the_relays_clock() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let created = setup
        .store()
        .subscription(SUBSCRIPTION)
        .unwrap()
        .last_event_created;
    setup.stripe.set_bad_date(true);
    setup.stripe.put_subscription(subscription(&Sub::default()));
    // The relay's clock is far ahead; the read has no usable `Date`.
    let ahead = PERIOD_END + 30 * DAY;
    assert_eq!(setup.billing.reconcile(ahead).unwrap().read.len(), 1);
    assert_eq!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .last_event_created,
        created
    );
    // A later event of Stripe, older than the relay's clock, still applies.
    setup.deliver(
        &sub_event(
            "evt_AfterRead01",
            "updated",
            created + 100,
            &Sub {
                status: "past_due",
                ..Sub::default()
            },
        ),
        created + 100,
    );
    assert_eq!(
        setup.store().subscription(SUBSCRIPTION).unwrap().status,
        StripeStatus::PastDue
    );
}

#[test]
fn the_stale_read_holds_no_account_lock_while_stripe_answers() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    setup.stripe.put_subscription(subscription(&Sub::default()));
    setup.stripe.delay_next("/v1/subscriptions/", 1500);
    let later = PERIOD_END + 3 * DAY;
    std::thread::scope(|scope| {
        let billing = &setup.billing;
        let pass = scope.spawn(move || billing.reconcile(later).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(300));
        let started = std::time::Instant::now();
        setup.deliver(
            &event(
                "evt_DuringRead",
                "invoice.paid",
                PERIOD_END + 10,
                invoice(SUBSCRIPTION, CUSTOMER),
            ),
            PERIOD_END + 10,
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(900),
            "the webhook waited for the pass: {:?}",
            started.elapsed()
        );
        pass.join().unwrap();
    });
}

#[test]
fn a_due_plan_is_read_from_stripe_at_most_once_a_day() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    setup.deliver_fixture("customer-subscription-created.json");
    let ended = Sub {
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_DueEnded01", "deleted", ENDED, &ended),
        ENDED,
    );
    setup.stripe.put_subscription(subscription(&ended));
    let due = ENDED + 91 * DAY;
    assert_eq!(setup.billing.maintenance(due).unwrap().due.len(), 1);
    setup.stripe.set_date(Some(due));
    assert_eq!(
        setup.billing.verify_ended(SUBSCRIPTION, due).unwrap(),
        StripeCheck::Ended
    );
    // Its deletion did not finish: within a day it is not listed again.
    assert!(
        setup
            .billing
            .maintenance(due + 3600)
            .unwrap()
            .due
            .is_empty()
    );
    assert_eq!(
        setup.billing.maintenance(due + DAY + 1).unwrap().due.len(),
        1
    );
}

#[test]
fn the_data_of_an_ended_plan_stays_while_stripe_or_an_open_problem_says_so() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    assert_eq!(setup.billing.deletion_blocked(ACCOUNT).unwrap(), None);
    // A subscription Stripe has and Connect does not: anything but a final status keeps
    // the data.
    for status in ["active", "incomplete", "past_due", "unpaid", "paused"] {
        setup.stripe.put_subscription(subscription(&Sub {
            status,
            ..Sub::default()
        }));
        assert!(
            setup.billing.deletion_blocked(ACCOUNT).unwrap().is_some(),
            "{status}"
        );
    }
    setup.stripe.put_subscription(subscription(&Sub {
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    }));
    assert_eq!(setup.billing.deletion_blocked(ACCOUNT).unwrap(), None);
    // Stripe cannot be asked: an error, never a deletion.
    setup.stripe.fail_path("/v1/subscriptions", 503, 2);
    assert!(setup.billing.deletion_blocked(ACCOUNT).is_err());
    // A checkout session Stripe shows open or complete keeps it; an expired one is
    // forgotten.
    let session = setup
        .billing
        .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
        .unwrap()
        .session_id;
    assert!(setup.billing.deletion_blocked(ACCOUNT).unwrap().is_some());
    setup.stripe.set_session_status(&session, "complete");
    assert!(setup.billing.deletion_blocked(ACCOUNT).unwrap().is_some());
    setup.stripe.set_session_status(&session, "expired");
    assert_eq!(setup.billing.deletion_blocked(ACCOUNT).unwrap(), None);
    assert!(
        setup
            .store()
            .transaction(|tx| tx.open_checkout(ACCOUNT))
            .unwrap()
            .is_none()
    );
    // An open problem of the account keeps it until the operator resolves it.
    setup
        .store()
        .transaction(|tx| {
            tx.record_problem(&apassy_relay::server::billing::Problem {
                object: "sub_SynthProblem1".to_owned(),
                account: Some(ACCOUNT.to_owned()),
                customer: Some(CUSTOMER.to_owned()),
                event: None,
                reason: "unknown_price",
                at: START,
            })
        })
        .unwrap();
    assert!(setup.billing.deletion_blocked(ACCOUNT).unwrap().is_some());
    let id = setup.store().problems()[0].id;
    setup.billing.resolve_problem(id, START + 1).unwrap();
    assert_eq!(setup.billing.deletion_blocked(ACCOUNT).unwrap(), None);
}

// ---------------------------------------------------------------------------------------
// One open session, Stripe's lists in pages, the Personal quantity, the account deletion,
// and the problem rows.

/// The sessions the fake shows open for a customer.
fn open_sessions(setup: &Setup, customer: &str) -> Vec<String> {
    setup.stripe.open_sessions(customer)
}

/// The POSTs that made a Checkout Session.
fn sessions_made(setup: &Setup) -> usize {
    setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .into_iter()
        .filter(|call| call.path == "/v1/checkout/sessions")
        .count()
}

#[test]
fn a_session_that_cannot_be_ended_refuses_a_new_one() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let first = setup
        .billing
        .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
        .unwrap();
    // Another request; Stripe does not end the open session (both tries fail).
    setup.stripe.fail_path(
        &format!("/v1/checkout/sessions/{}/expire", first.session_id),
        503,
        2,
    );
    let error = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"family","interval":"month","people":4}"#,
            START + 1,
        )
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::BUSY, 503));
    assert_eq!(sessions_made(&setup), 1);
    assert_eq!(
        open_sessions(&setup, CUSTOMER),
        std::slice::from_ref(&first.session_id)
    );
    assert_eq!(
        setup
            .store()
            .transaction(|tx| tx.open_checkout(ACCOUNT))
            .unwrap()
            .map(|open| open.session_id),
        Some(first.session_id.clone())
    );
    // Stripe ends it now: the new session is the only open one.
    let second = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"family","interval":"month","people":4}"#,
            START + 2,
        )
        .unwrap();
    assert_eq!(open_sessions(&setup, CUSTOMER), [second.session_id]);
}

#[test]
fn an_open_session_connect_no_longer_stores_ends_before_a_new_one() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    setup
        .stripe
        .add_session("cs_test_SynthForgotten1", CUSTOMER, "open");
    let made = setup
        .billing
        .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
        .unwrap();
    assert_eq!(
        setup
            .stripe
            .session_status("cs_test_SynthForgotten1")
            .as_deref(),
        Some("expired")
    );
    assert_eq!(open_sessions(&setup, CUSTOMER), [made.session_id]);
}

#[test]
fn a_list_error_during_checkout_gives_no_session_and_every_page_is_read() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let body = br#"{"plan":"personal","interval":"month"}"#;
    for path in ["/v1/checkout/sessions", "/v1/subscriptions"] {
        setup.stripe.fail_path(path, 503, 2);
        assert!(
            setup.billing.checkout(ACCOUNT, body, START).is_err(),
            "{path}"
        );
        assert_eq!(sessions_made(&setup), 0, "{path}");
    }
    // Five ended subscriptions and one that is not over, on the third page of two.
    setup.stripe.set_page_size(2);
    for n in 1..=5 {
        setup.stripe.put_subscription(subscription(&Sub {
            id: &format!("sub_SynthEnded{n:04}"),
            status: "canceled",
            ended_at: Some(ENDED),
            ..Sub::default()
        }));
    }
    setup.stripe.put_subscription(subscription(&Sub {
        id: "sub_SynthLive0001",
        status: "unpaid",
        ..Sub::default()
    }));
    setup.stripe.clear_calls();
    let error = setup.billing.checkout(ACCOUNT, body, START).unwrap_err();
    assert_eq!((error.code, error.status()), (codes::CONFLICT, 409));
    let pages = setup.stripe.calls_to("GET", "/v1/subscriptions");
    assert_eq!(pages.len(), 3);
    assert!(
        pages[1..]
            .iter()
            .all(|call| call.query.iter().any(|(key, _)| key == "starting_after")),
        "{pages:?}"
    );
    // Ended too: the account buys.
    setup.stripe.put_subscription(subscription(&Sub {
        id: "sub_SynthLive0001",
        status: "canceled",
        ended_at: Some(ENDED),
        ..Sub::default()
    }));
    setup.billing.checkout(ACCOUNT, body, START).unwrap();
    // A list longer than Connect reads is refused, not taken as complete.
    setup.stripe.set_page_size(1);
    for n in 6..=12 {
        setup.stripe.put_subscription(subscription(&Sub {
            id: &format!("sub_SynthEnded{n:04}"),
            status: "canceled",
            ended_at: Some(ENDED),
            ..Sub::default()
        }));
    }
    let error = setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"family","interval":"month","people":4}"#,
            START,
        )
        .unwrap_err();
    assert_eq!((error.code, error.status()), (codes::CONFLICT, 409));
}

#[test]
fn a_join_during_a_checkout_ends_the_session_the_checkout_makes() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    // The checkout's first Stripe call waits; the join's end of sessions runs meanwhile.
    setup.stripe.delay_next("/v1/checkout/sessions", 800);
    std::thread::scope(|scope| {
        let billing = &setup.billing;
        let checkout = scope.spawn(move || {
            billing
                .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
                .unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        billing.end_open_checkout(ACCOUNT, START).unwrap();
        let made = checkout.join().unwrap();
        // The end waited for the checkout and ended the session it stored.
        assert_eq!(
            setup.stripe.session_status(&made.session_id).as_deref(),
            Some("expired")
        );
    });
    assert!(open_sessions(&setup, CUSTOMER).is_empty());
    assert!(
        setup
            .store()
            .transaction(|tx| tx.open_checkout(ACCOUNT))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_stored_personal_row_that_stripe_shows_otherwise_keeps_its_quantity() {
    let setup = Setup::new();
    family(&setup, 6);
    let personal6 = Sub {
        quantity: 6,
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_ToPersonal61", "updated", START + 10, &personal6),
        START + 10,
    );
    assert_eq!(
        problems(&setup),
        [(SUBSCRIPTION.to_owned(), "personal_quantity".to_owned())]
    );
    // Before the pass the owner switched back to Family at Stripe; its event is late.
    let back = Sub {
        lookup: "connect_family_month",
        quantity: 6,
        ..Sub::default()
    };
    setup.stripe.put_subscription(subscription(&back));
    setup.stripe.set_date(Some(START + 20));
    let report = setup.billing.reconcile(START + 30).unwrap();
    assert_eq!(report.failed, 0);
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .is_empty()
    );
    // Stripe's state applied: Family again with its 6 people, and the problem is over.
    let row = setup.store().subscription(SUBSCRIPTION).unwrap();
    assert_eq!(
        (row.plan, row.effective_quantity()),
        (Some(Plan::Family), 6)
    );
    assert!(problems(&setup).is_empty(), "{:?}", problems(&setup));
    // A price Connect cannot map never changes a quantity, even on a stored Personal row.
    setup.deliver(
        &sub_event("evt_ToPersonal62", "updated", START + 40, &personal6),
        START + 40,
    );
    let unknown = Sub {
        lookup: "someone_elses_price",
        quantity: 6,
        ..Sub::default()
    };
    setup.stripe.put_subscription(subscription(&unknown));
    setup.stripe.set_date(Some(START + 50));
    setup.billing.reconcile(START + 60).unwrap();
    assert!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .is_empty()
    );
    // Its later event records no `personal_quantity`: the price is not Connect Personal.
    setup
        .billing
        .resolve_problem(setup.store().problems()[0].id, START + 61)
        .unwrap();
    setup.deliver(
        &sub_event("evt_UnknownPrice6", "updated", START + 70, &unknown),
        START + 70,
    );
    assert!(
        problems(&setup)
            .iter()
            .all(|(_, reason)| reason != "personal_quantity"),
        "{:?}",
        problems(&setup)
    );
}

#[test]
fn the_pass_closes_the_personal_quantity_problem_it_resolved() {
    let setup = Setup::new();
    family(&setup, 6);
    let personal6 = Sub {
        quantity: 6,
        ..Sub::default()
    };
    setup.stripe.put_subscription(subscription(&personal6));
    setup.deliver(
        &sub_event("evt_ToPersonal63", "updated", START + 10, &personal6),
        START + 10,
    );
    assert_eq!(problems(&setup).len(), 1);
    setup.billing.reconcile(START + 11).unwrap();
    assert_eq!(
        setup
            .stripe
            .calls_to("POST", "/v1/subscription_items/")
            .len(),
        1
    );
    assert!(problems(&setup).is_empty(), "{:?}", problems(&setup));
}

#[test]
fn account_deletion_ends_every_session_first_and_cancels_what_appears_meanwhile() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let stored = setup
        .billing
        .checkout(ACCOUNT, br#"{"plan":"personal","interval":"month"}"#, START)
        .unwrap()
        .session_id;
    setup
        .stripe
        .add_session("cs_test_SynthForgotten2", CUSTOMER, "open");
    setup.stripe.put_subscription(subscription(&Sub {
        status: "active",
        ..Sub::default()
    }));
    // Stripe does not end the session it lists: the deletion is refused before any
    // subscription is canceled.
    setup.stripe.fail_path(
        "/v1/checkout/sessions/cs_test_SynthForgotten2/expire",
        503,
        2,
    );
    assert!(setup.billing.cancel_for_account_deletion(ACCOUNT).is_err());
    assert!(
        setup
            .stripe
            .calls_to("DELETE", "/v1/subscriptions/")
            .is_empty()
    );
    // The stored session completes just before its expire (with a subscription), and a
    // purchase finishes while the deletion cancels: both new subscriptions are canceled.
    setup.stripe.clear_calls();
    setup.stripe.complete_on_expire(
        &stored,
        subscription(&Sub {
            id: "sub_SynthLate00001",
            status: "incomplete",
            ..Sub::default()
        }),
    );
    setup.stripe.appear_on_cancel(
        SUBSCRIPTION,
        subscription(&Sub {
            id: "sub_SynthLate00002",
            status: "active",
            ..Sub::default()
        }),
    );
    assert!(setup.billing.cancel_for_account_deletion(ACCOUNT).unwrap());
    let mut canceled: Vec<String> = setup
        .stripe
        .calls_to("DELETE", "/v1/subscriptions/")
        .into_iter()
        .map(|call| call.path["/v1/subscriptions/".len()..].to_owned())
        .collect();
    canceled.sort();
    assert_eq!(
        canceled,
        [
            "sub_SynthAcc0001",
            "sub_SynthLate00001",
            "sub_SynthLate00002"
        ]
    );
    assert!(open_sessions(&setup, CUSTOMER).is_empty());
    assert_eq!(
        setup
            .stripe
            .session_status("cs_test_SynthForgotten2")
            .as_deref(),
        Some("expired")
    );
    // The sessions ended before the first list of subscriptions.
    let calls = setup.stripe.calls();
    let first_list = calls
        .iter()
        .position(|call| call.method == "GET" && call.path == "/v1/subscriptions")
        .unwrap();
    let last_expire = calls
        .iter()
        .rposition(|call| call.path.ends_with("/expire"))
        .unwrap();
    assert!(last_expire < first_list);
}

#[test]
fn a_problem_that_opens_again_with_another_reason_takes_it() {
    let setup = Setup::new();
    let problem = |reason: &'static str, at: u64| apassy_relay::server::billing::Problem {
        object: SUBSCRIPTION.to_owned(),
        account: Some(ACCOUNT.to_owned()),
        customer: Some(CUSTOMER.to_owned()),
        event: None,
        reason,
        at,
    };
    let record = |reason, at| {
        setup
            .store()
            .transaction(|tx| tx.record_problem(&problem(reason, at)))
            .unwrap()
    };
    assert!(record("personal_quantity", START));
    assert!(!record("personal_quantity", START + 1));
    // Open with another reason: the row takes it.
    assert!(record("deleted_account", START + 2));
    assert_eq!(problems(&setup)[0].1, "deleted_account");
    let id = setup.store().problems()[0].id;
    setup.billing.resolve_problem(id, START + 3).unwrap();
    assert!(record("raise_refused", START + 4));
    assert_eq!(
        problems(&setup),
        [(SUBSCRIPTION.to_owned(), "raise_refused".to_owned())]
    );
}

#[test]
fn a_late_older_event_of_a_deleted_account_records_nothing() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    let canceled = Sub {
        status: "canceled",
        ended_at: Some(START + 20),
        ..Sub::default()
    };
    setup.deliver(
        &sub_event("evt_DelCreated01", "created", START + 1, &Sub::default()),
        START + 1,
    );
    setup.deliver(
        &sub_event("evt_DelCanceled1", "deleted", START + 20, &canceled),
        START + 20,
    );
    setup.store().remove_account(ACCOUNT);
    // An older event that still charged arrives late: it does not apply and records
    // nothing.
    setup.deliver(
        &sub_event(
            "evt_DelLateOld01",
            "updated",
            START + 10,
            &Sub {
                status: "past_due",
                ..Sub::default()
            },
        ),
        START + 30,
    );
    assert!(problems(&setup).is_empty(), "{:?}", problems(&setup));
}

#[test]
fn no_group_is_made_for_an_account_that_no_longer_exists() {
    let setup = Setup::new();
    setup.store().add_account(OTHER);
    let other_group = setup
        .store()
        .transaction(|tx| {
            tx.create_group(
                apassy_relay::server::billing::GroupKind::Family,
                OTHER,
                START,
            )
        })
        .unwrap();
    setup.store().add_member(
        &other_group,
        ACCOUNT,
        GroupRole::Member,
        MemberState::Active,
    );
    setup.deliver(
        &event(
            "evt_GoneCheckout",
            "checkout.session.completed",
            START + 1,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, SUBSCRIPTION),
        ),
        START + 1,
    );
    setup.deliver(
        &sub_event(
            "evt_GoneCreated1",
            "created",
            START + 2,
            &Sub {
                lookup: "connect_family_month",
                quantity: 4,
                ..Sub::default()
            },
        ),
        START + 2,
    );
    assert_eq!(setup.store().groups().len(), 1);
    // The account is deleted; the pass and a later event make no group for it.
    setup.store().remove_account(ACCOUNT);
    setup.billing.reconcile(START + 3).unwrap();
    setup.deliver(
        &sub_event(
            "evt_GoneUpdated1",
            "updated",
            START + 4,
            &Sub {
                lookup: "connect_family_month",
                quantity: 4,
                ..Sub::default()
            },
        ),
        START + 4,
    );
    assert_eq!(setup.store().groups().len(), 1);
    assert!(
        setup
            .store()
            .subscription(SUBSCRIPTION)
            .unwrap()
            .group_id
            .is_none()
    );
    assert_eq!(
        problems(&setup),
        [(SUBSCRIPTION.to_owned(), "deleted_account".to_owned())]
    );
}

#[test]
fn a_stale_invite_used_before_payment_keeps_the_group_and_its_kind() {
    let setup = Setup::new();
    // The owner alone in an ended family opened a Team checkout; a stale family invite is
    // used before it pays.
    let group = ended_family(&setup);
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"team","interval":"month","seats":3}"#,
            ENDED + DAY,
        )
        .unwrap();
    setup.store().add_account(OTHER);
    setup
        .store()
        .add_member(&group, OTHER, GroupRole::Member, MemberState::Pending);
    let team = "sub_SynthTeam0003";
    setup.deliver(
        &event(
            "evt_StaleInvite1",
            "checkout.session.completed",
            ENDED + DAY + 10,
            checkout_session(ACCOUNT, ACCOUNT, CUSTOMER, team),
        ),
        ENDED + DAY + 10,
    );
    setup.deliver(
        &sub_event(
            "evt_StaleInvite2",
            "created",
            ENDED + DAY + 11,
            &Sub {
                id: team,
                lookup: "connect_team_month",
                quantity: 3,
                ..Sub::default()
            },
        ),
        ENDED + DAY + 11,
    );
    let groups = setup.store().groups();
    assert_eq!(
        (groups.len(), groups[0].kind),
        (1, apassy_relay::server::billing::GroupKind::Family)
    );
    assert!(setup.store().subscription(team).unwrap().group_id.is_none());
    assert_eq!(problems(&setup), [(team.to_owned(), "no_group".to_owned())]);
}

#[test]
fn no_conversion_while_a_plan_of_the_groups_kind_is_entitled() {
    let setup = Setup::new();
    let group = family(&setup, 4);
    let team = "sub_SynthTeam0004";
    setup.deliver(
        &sub_event(
            "evt_TeamBeside01",
            "created",
            START + 5,
            &Sub {
                id: team,
                lookup: "connect_team_month",
                quantity: 2,
                ..Sub::default()
            },
        ),
        START + 5,
    );
    let groups = setup.store().groups();
    assert_eq!(
        (groups[0].group_id.as_str(), groups[0].kind),
        (
            group.as_str(),
            apassy_relay::server::billing::GroupKind::Family
        )
    );
    assert_eq!(problems(&setup), [(team.to_owned(), "no_group".to_owned())]);
}

#[test]
fn the_pass_stops_between_subscriptions_when_the_relay_stops() {
    let setup = Setup::new();
    setup.bind_customer(ACCOUNT, CUSTOMER);
    for id in ["sub_SynthStale001", "sub_SynthStale002"] {
        let sub = Sub {
            id,
            ..Sub::default()
        };
        setup.deliver(
            &sub_event(&format!("evt_{}", &id[4..]), "created", START + 1, &sub),
            START + 1,
        );
        setup.stripe.put_subscription(subscription(&sub));
    }
    let later = PERIOD_END + 3 * DAY;
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let report = setup
        .billing
        .reconcile_until(later, &|| {
            asked.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 1
        })
        .unwrap();
    assert_eq!(report.read.len(), 1);
    assert_eq!(setup.stripe.calls_to("GET", "/v1/subscriptions/").len(), 1);
}
