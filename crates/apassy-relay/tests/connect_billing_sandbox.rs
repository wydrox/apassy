//! The Stripe sandbox job of Connect billing (C2 of docs/design/implementation-plan-s7-connect.md):
//! the real Stripe API in test mode, on a test clock. Ignored unless run on purpose with a
//! sandbox key, by `.github/workflows/connect-sandbox.yml` (manual only):
//!
//! ```text
//! STRIPE_SANDBOX_KEY_FILE=/path/to/rk_test_key \
//!   cargo nextest run -p apassy-relay -E 'binary(connect_billing_sandbox)' --run-ignored only
//! ```
//!
//! The key must be a test key (`sk_test_…` or `rk_test_…`); a live key is refused. The
//! sandbox needs the prices of `scripts/stripe-products.sh` (run without `--live`).
//!
//! The flow: the price lookup and `GET /v1/plans`; a Family and a Team Checkout Session made
//! by Connect for an account of their own, which names the Stripe customer Connect made
//! (Stripe checks the whole form, tax, tax ids for an existing customer, and consent
//! included; a session cannot be paid without a browser, so each one is expired); a
//! customer on a **test clock** with a test card and a
//! subscription with the account id in its metadata (what a paid checkout makes); then the
//! clock goes through a renewal, a failed payment, and a cancellation. After each step the
//! test reads the new events with `GET /v1/events`, signs each one with a synthetic endpoint
//! secret, delivers it to `Billing::webhook`, and checks the plan state. Nothing is charged:
//! test mode only.

use std::time::{Duration, Instant};

use apassy_relay::secret::SecretString;
use apassy_relay::server::billing::{
    Billing, BillingConfig, Capability, MemoryBillingStore, PlanStatus, StripeStatus,
};
use apassy_relay::server::stripe::{
    API_BASE, API_VERSION, StripeClient, StripeConfig, form_encode, read_secret_key_file,
    signature_header,
};
use serde_json::Value;

const ACCOUNT: &str = "acc_sandbx2tes";
/// The account of the Checkout Sessions: Connect makes its Stripe customer, so the
/// subscription of the test clock's own customer belongs to `ACCOUNT` alone.
const CHECKOUT_ACCOUNT: &str = "acc_sandbx3tes";
const DAY: u64 = 86_400;
const WEBHOOK_SECRET: &str = "whsec_SYNTHETIC_sandbox_job_delivers_its_own_events";

/// A small client for the calls the relay itself never makes (test clocks, customers,
/// payment methods, subscriptions, events).
struct Sandbox {
    key: SecretString,
    agent: ureq::Agent,
}

impl Sandbox {
    fn call(&self, method: &str, path: &str, pairs: &[(&str, &str)]) -> Value {
        let form: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let encoded = form_encode(&form);
        let mut url = format!("{API_BASE}{path}");
        let builder = ureq::http::Request::builder()
            .header("Authorization", format!("Bearer {}", self.key.expose()))
            .header("Stripe-Version", API_VERSION);
        let response = if method == "GET" {
            if !encoded.is_empty() {
                url = format!("{url}?{encoded}");
            }
            self.agent
                .run(builder.method("GET").uri(url).body(()).unwrap())
        } else {
            self.agent.run(
                builder
                    .method(method)
                    .uri(url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(encoded)
                    .unwrap(),
            )
        };
        let mut response = response.unwrap_or_else(|e| panic!("{method} {path}: {e}"));
        let status = response.status().as_u16();
        let body: Value =
            serde_json::from_slice(&response.body_mut().read_to_vec().unwrap()).unwrap();
        assert!(
            (200..300).contains(&status),
            "{method} {path}: {status} {}",
            body["error"]["code"]
        );
        body
    }

    fn wait_for_clock(&self, clock: &str) {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let status = self.call("GET", &format!("/v1/test_helpers/test_clocks/{clock}"), &[]);
            if status["status"] == "ready" {
                return;
            }
            assert!(Instant::now() < deadline, "the test clock did not settle");
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn advance(&self, clock: &str, to: u64) {
        let to = to.to_string();
        self.call(
            "POST",
            &format!("/v1/test_helpers/test_clocks/{clock}/advance"),
            &[("frozen_time", &to)],
        );
        self.wait_for_clock(clock);
    }

    /// The events of this customer since `since`, oldest first.
    fn events(&self, customer: &str, subscription: Option<&str>, since: u64) -> Vec<Value> {
        let since = since.to_string();
        let mut events: Vec<Value> = self.call(
            "GET",
            "/v1/events",
            &[
                ("created[gte]", &since),
                ("limit", "100"),
                ("types[]", "customer.subscription.created"),
                ("types[]", "customer.subscription.updated"),
                ("types[]", "customer.subscription.deleted"),
                ("types[]", "invoice.paid"),
                ("types[]", "invoice.payment_failed"),
            ],
        )["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| {
                let object = &event["data"]["object"];
                object["customer"] == customer || subscription.is_some_and(|s| object["id"] == s)
            })
            .cloned()
            .collect();
        events.sort_by_key(|event| event["created"].as_u64().unwrap_or(0));
        events
    }
}

/// Signs and delivers each event as Stripe would, at `now` (the clock's time).
fn deliver(billing: &Billing<MemoryBillingStore>, events: &[Value], now: u64) -> usize {
    let secret = SecretString::new(WEBHOOK_SECRET.into());
    let mut applied = 0;
    for event in events {
        let body = event.to_string().into_bytes();
        let header = signature_header(&secret, now, &body);
        let outcome = billing
            .webhook(Some(&header), &body, now)
            .expect("the event verifies");
        if !outcome.answer.duplicate {
            applied += 1;
        }
    }
    applied
}

#[test]
#[ignore = "needs STRIPE_SANDBOX_KEY_FILE: run by .github/workflows/connect-sandbox.yml"]
fn the_plan_follows_a_test_clock_through_renewal_failure_and_cancellation() {
    let path = std::env::var("STRIPE_SANDBOX_KEY_FILE")
        .expect("set STRIPE_SANDBOX_KEY_FILE to a file with a Stripe test key");
    let key = read_secret_key_file(std::path::Path::new(&path)).expect("a Stripe key");
    assert!(
        key.expose().starts_with("sk_test_") || key.expose().starts_with("rk_test_"),
        "the sandbox job runs with a test key only"
    );
    let sandbox = Sandbox {
        key: SecretString::new(key.expose().to_owned()),
        agent: ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into(),
    };
    let store = MemoryBillingStore::new();
    store.add_account(ACCOUNT);
    store.add_account(CHECKOUT_ACCOUNT);
    let client = StripeClient::new(StripeConfig::new(API_BASE, key).unwrap());
    let billing = Billing::new(
        store,
        client,
        BillingConfig::default(),
        SecretString::new(WEBHOOK_SECRET.into()),
    )
    .unwrap();
    let started = apassy_relay::now_unix();

    // 1. Prices and plans: the six lookup keys of the products script.
    let plans = billing.plans(started).expect("GET /v1/prices");
    assert_eq!(
        plans.plans.len(),
        3,
        "run stripe-products.sh in the sandbox first"
    );
    let prices = billing.prices(started).unwrap();
    let personal = prices
        .get(
            apassy_relay::server::billing::Plan::Personal,
            apassy_relay::server::billing::Interval::Month,
        )
        .expect("connect_personal_month")
        .clone();

    // 2. Checkout Sessions: Stripe checks the form of contract section 4. The Team one
    //    collects tax ids for the customer Connect made with the Family one (Stripe needs
    //    `customer_update[name]=auto` for that).
    for body in [
        br#"{"plan":"family","interval":"month","people":6}"#.as_slice(),
        br#"{"plan":"team","interval":"month","seats":3}"#.as_slice(),
    ] {
        let session = billing
            .checkout(CHECKOUT_ACCOUNT, body, started)
            .expect("a checkout session");
        assert!(session.url.starts_with("https://checkout.stripe.com/"));
        assert!(session.session_id.starts_with("cs_test_"));
        let read = sandbox.call(
            "GET",
            &format!("/v1/checkout/sessions/{}", session.session_id),
            &[],
        );
        assert_eq!(read["status"], "open");
        if read["tax_id_collection"]["enabled"] == true {
            assert!(
                read["customer"].is_string(),
                "a session of an existing customer"
            );
        }
        sandbox.call(
            "POST",
            &format!("/v1/checkout/sessions/{}/expire", session.session_id),
            &[],
        );
    }

    // 3. A customer on a test clock with a test card, and its subscription.
    let frozen = started - started % DAY + DAY;
    let frozen_text = frozen.to_string();
    let clock = sandbox.call(
        "POST",
        "/v1/test_helpers/test_clocks",
        &[
            ("frozen_time", &frozen_text),
            ("name", "apassy-connect-billing"),
        ],
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let customer = sandbox.call(
            "POST",
            "/v1/customers",
            &[
                ("test_clock", &clock),
                ("payment_method", "pm_card_visa"),
                ("invoice_settings[default_payment_method]", "pm_card_visa"),
                ("metadata[account_id]", ACCOUNT),
            ],
        )["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let subscription = sandbox.call(
            "POST",
            "/v1/subscriptions",
            &[
                ("customer", &customer),
                ("items[0][price]", &personal.price_id),
                ("metadata[account_id]", ACCOUNT),
            ],
        );
        let sub_id = subscription["id"].as_str().unwrap().to_owned();
        sandbox.wait_for_clock(&clock);
        let events = sandbox.events(&customer, Some(&sub_id), started - 60);
        assert!(
            deliver(&billing, &events, frozen) >= 1,
            "no subscription events"
        );
        let plan = billing.plan_view(ACCOUNT, frozen).unwrap();
        assert_eq!(
            (plan.status, plan.entitled),
            (PlanStatus::Active, true),
            "{plan:?}"
        );
        let first_end = plan.renews_at.expect("a renewal time");

        // 4. The renewal: the clock passes the period end, the invoice is paid.
        sandbox.advance(&clock, first_end + 3600);
        let events = sandbox.events(&customer, Some(&sub_id), started - 60);
        deliver(&billing, &events, first_end + 3600);
        let plan = billing.plan_view(ACCOUNT, first_end + 3600).unwrap();
        assert_eq!(plan.status, PlanStatus::Active, "{plan:?}");
        let second_end = plan.renews_at.expect("a renewal time");
        assert!(second_end > first_end, "the period moved on");

        // 5. A failed payment: a card that declines, then the next period end.
        sandbox.call(
            "POST",
            "/v1/payment_methods/pm_card_chargeCustomerFail/attach",
            &[("customer", &customer)],
        );
        let methods = sandbox.call(
            "GET",
            "/v1/payment_methods",
            &[("customer", &customer), ("type", "card")],
        );
        let failing = methods["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["card"]["last4"] == "0341")
            .and_then(|m| m["id"].as_str())
            .expect("the failing card")
            .to_owned();
        sandbox.call(
            "POST",
            &format!("/v1/customers/{customer}"),
            &[("invoice_settings[default_payment_method]", &failing)],
        );
        sandbox.advance(&clock, second_end + 3600);
        let events = sandbox.events(&customer, Some(&sub_id), started - 60);
        deliver(&billing, &events, second_end + 3600);
        let row = billing_row(&billing, &sub_id);
        assert_eq!(row.status, StripeStatus::PastDue, "{row:?}");
        assert!(row.first_failed_at.is_some());
        let plan = billing.plan_view(ACCOUNT, second_end + 3600).unwrap();
        assert!(
            matches!(plan.status, PlanStatus::PastDue | PlanStatus::ReadOnly),
            "{plan:?}"
        );
        assert_eq!(
            plan.state(),
            row.state(second_end + 3600, &billing.config.durations)
        );

        // 6. The cancellation: read-only, pulls still work.
        sandbox.call("DELETE", &format!("/v1/subscriptions/{sub_id}"), &[]);
        sandbox.wait_for_clock(&clock);
        let events = sandbox.events(&customer, Some(&sub_id), started - 60);
        deliver(&billing, &events, second_end + 7200);
        let plan = billing.plan_view(ACCOUNT, second_end + 7200).unwrap();
        assert_eq!(plan.status, PlanStatus::ReadOnly, "{plan:?}");
        assert!(plan.state().require(Capability::Push).is_err());
        assert!(plan.state().require(Capability::Pull).is_ok());
    }));
    // The clock and everything on it go away, also after a failed step.
    sandbox.call(
        "DELETE",
        &format!("/v1/test_helpers/test_clocks/{clock}"),
        &[],
    );
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn billing_row(
    billing: &Billing<MemoryBillingStore>,
    id: &str,
) -> apassy_relay::server::billing::SubscriptionRow {
    billing
        .store
        .subscription(id)
        .expect("the stored subscription")
}
