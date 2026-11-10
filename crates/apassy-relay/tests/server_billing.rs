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
    Billing, BillingConfig, BillingStore, Capability, Durations, GroupRole, MemberState,
    MemoryBillingStore, Plan, PlanInput, PlanStatus, PlansView, StripeStatus, WebhookEffect,
    plan_state, total_cents,
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
fn an_unknown_lookup_key_and_another_event_type_change_nothing() {
    let setup = Setup::new();
    setup.deliver_fixture("checkout-session-completed.json");
    let before = setup.store().subscription(SUBSCRIPTION).unwrap();
    let foreign = Sub {
        lookup: "someone_else_price",
        ..Sub::default()
    };
    let effect = setup.deliver(
        &event(
            "evt_Foreign01",
            "customer.subscription.created",
            START + 1,
            subscription(&foreign),
        ),
        START + 1,
    );
    assert_eq!(effect, WebhookEffect::Ignored);
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
    let before = setup.store().snapshot();
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
    // The checkout changes nothing here: the webhook binds the subscription.
    assert_eq!(setup.store().snapshot(), before);
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
fn a_repeated_checkout_reuses_its_idempotency_key_and_a_retry_does_too() {
    let setup = Setup::new();
    let body = br#"{"plan":"personal","interval":"year"}"#;
    setup.billing.plans(START).unwrap();
    setup.stripe.fail_next(500, 1);
    let first = setup.billing.checkout(ACCOUNT, body, START).unwrap();
    let second = setup.billing.checkout(ACCOUNT, body, START + 60).unwrap();
    assert_eq!(
        first.session_id, second.session_id,
        "one click, one session"
    );
    let calls = setup.stripe.calls_to("POST", "/v1/checkout/sessions");
    assert_eq!(calls.len(), 3);
    let keys: Vec<&str> = calls
        .iter()
        .map(|c| c.header("Idempotency-Key").unwrap())
        .collect();
    assert!(keys.iter().all(|k| *k == keys[0]), "{keys:?}");
    // Another plan is another key.
    setup
        .billing
        .checkout(
            ACCOUNT,
            br#"{"plan":"personal","interval":"month"}"#,
            START + 61,
        )
        .unwrap();
    let last = setup
        .stripe
        .calls_to("POST", "/v1/checkout/sessions")
        .pop()
        .unwrap();
    assert_ne!(last.header("Idempotency-Key").unwrap(), keys[0]);
}

#[test]
fn stripe_refusals_and_outages_are_errors_without_a_change() {
    let setup = Setup::new();
    let body = br#"{"plan":"personal","interval":"month"}"#;
    setup.billing.plans(START).unwrap();
    setup.stripe.fail_next(400, 1);
    let error = setup.billing.checkout(ACCOUNT, body, START).unwrap_err();
    assert_eq!((error.code, error.status()), (codes::UPSTREAM_FAILED, 502));
    setup.stripe.fail_next(503, 2);
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
    assert_eq!(calls.len(), 5, "{calls:?}");
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
                    || ["lookup_keys[]", "active", "expand[]", "limit"].contains(&name.as_str()),
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
    assert_eq!(calls.last().unwrap().method, "DELETE");
    assert_eq!(
        calls.last().unwrap().path,
        format!("/v1/subscriptions/{SUBSCRIPTION}")
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
