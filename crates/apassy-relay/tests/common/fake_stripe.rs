//! A fake Stripe API for the billing tests: an in-process HTTP server on a free loopback
//! port. It answers the price list (`GET /v1/prices`), Checkout and Customer Portal
//! sessions, subscription item updates, and subscription cancels, and it records every
//! call so a test can check what the relay sent. Like Stripe, a POST with an
//! `Idempotency-Key` seen before gets the first answer again.
//!
//! Hooks: `fail_next(status, n)` answers the next `n` calls with that status, and
//! `set_prices` replaces the price list.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use apassy_relay::server::stripe::form_decode;
use serde_json::{Value, json};

/// The key the fake accepts as `Authorization: Bearer <key>`.
pub const FAKE_KEY: &str = "rk_test_FAKE_apassy_billing_tests";
/// `expires_at` of every Checkout Session.
pub const SESSION_EXPIRES_AT: u64 = 1_790_086_400;

/// One call the fake got.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub form: Vec<(String, String)>,
}

impl Call {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    prices: Vec<Value>,
    failures: Vec<u16>,
    replays: HashMap<String, (u16, String)>,
}

pub struct FakeStripe {
    base: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
}

/// The six prices of the default configuration (contract section 2), with synthetic ids.
pub fn default_prices() -> Vec<Value> {
    let per_unit = |id: &str, key: &str, interval: &str, amount: u64| {
        json!({
            "id": id, "object": "price", "active": true, "currency": "eur",
            "lookup_key": key, "billing_scheme": "per_unit", "tax_behavior": "inclusive",
            "unit_amount": amount, "tiers_mode": null,
            "recurring": {"interval": interval, "interval_count": 1}
        })
    };
    let family = |id: &str, key: &str, interval: &str, flat: u64, extra: u64| {
        json!({
            "id": id, "object": "price", "active": true, "currency": "eur",
            "lookup_key": key, "billing_scheme": "tiered", "tax_behavior": "inclusive",
            "unit_amount": null, "tiers_mode": "graduated",
            "tiers": [
                {"up_to": 4, "flat_amount": flat, "unit_amount": 0},
                {"up_to": null, "flat_amount": null, "unit_amount": extra}
            ],
            "recurring": {"interval": interval, "interval_count": 1}
        })
    };
    vec![
        per_unit(
            "price_SynthPersonalMonth",
            "connect_personal_month",
            "month",
            300,
        ),
        per_unit(
            "price_SynthPersonalYear",
            "connect_personal_year",
            "year",
            3000,
        ),
        family(
            "price_SynthFamilyMonth",
            "connect_family_month",
            "month",
            500,
            100,
        ),
        family(
            "price_SynthFamilyYear",
            "connect_family_year",
            "year",
            5000,
            1000,
        ),
        per_unit("price_SynthTeamMonth", "connect_team_month", "month", 400),
        per_unit("price_SynthTeamYear", "connect_team_year", "year", 4000),
    ]
}

impl FakeStripe {
    pub fn start() -> Self {
        let server =
            Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind the fake Stripe"));
        let addr = server.server_addr().to_ip().expect("an IP address");
        let state = Arc::new(Mutex::new(State {
            prices: default_prices(),
            ..State::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let server = Arc::clone(&server);
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let counter = AtomicU32::new(0);
                while !stop.load(Ordering::Relaxed) {
                    match server.recv_timeout(Duration::from_millis(100)) {
                        Ok(Some(request)) => handle(request, &state, &counter),
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            base: format!("http://{addr}"),
            state,
            stop,
            server,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, the base URL for `StripeConfig::new`.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    /// The calls of one method and path prefix.
    pub fn calls_to(&self, method: &str, path: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| call.method == method && call.path.starts_with(path))
            .collect()
    }

    pub fn clear_calls(&self) {
        self.state.lock().unwrap().calls.clear();
    }

    pub fn set_prices(&self, prices: Vec<Value>) {
        self.state.lock().unwrap().prices = prices;
    }

    /// The next `n` calls answer `status` with a Stripe error body.
    pub fn fail_next(&self, status: u16, n: usize) {
        self.state
            .lock()
            .unwrap()
            .failures
            .extend(std::iter::repeat_n(status, n));
    }
}

impl Drop for FakeStripe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.unblock();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn error_body(kind: &str, code: &str) -> String {
    json!({"error": {"type": kind, "code": code, "message": "fake stripe refusal"}}).to_string()
}

fn handle(mut request: tiny_http::Request, state: &Mutex<State>, counter: &AtomicU32) {
    let method = request.method().as_str().to_owned();
    let url = request.url().to_owned();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|h| {
            (
                h.field.as_str().as_str().to_owned(),
                h.value.as_str().to_owned(),
            )
        })
        .collect();
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);
    let form = form_decode(&body).unwrap_or_default();
    let call = Call {
        method: method.clone(),
        path: path.to_owned(),
        query: form_decode(query).unwrap_or_default(),
        headers,
        body,
        form,
    };
    let (status, answer) = answer(&call, state, counter);
    state.lock().unwrap().calls.push(call);
    let response = tiny_http::Response::from_string(answer)
        .with_status_code(status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap());
    let _ = request.respond(response);
}

fn answer(call: &Call, state: &Mutex<State>, counter: &AtomicU32) -> (u16, String) {
    let mut guard = state.lock().unwrap();
    if call.header("Authorization") != Some(&format!("Bearer {FAKE_KEY}")) {
        return (401, error_body("invalid_request_error", "api_key_invalid"));
    }
    if !guard.failures.is_empty() {
        let status = guard.failures.remove(0);
        return (status, error_body("api_error", "fake_failure"));
    }
    let replay_key = call
        .header("Idempotency-Key")
        .filter(|_| call.method == "POST")
        .map(|key| format!("{} {key}", call.path));
    if let Some(key) = &replay_key
        && let Some(previous) = guard.replays.get(key)
    {
        return previous.clone();
    }
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let result = match (call.method.as_str(), call.path.as_str()) {
        ("GET", "/v1/prices") => {
            let keys: Vec<&str> = call
                .query
                .iter()
                .filter(|(k, _)| k == "lookup_keys[]")
                .map(|(_, v)| v.as_str())
                .collect();
            let data: Vec<Value> = guard
                .prices
                .iter()
                .filter(|price| {
                    price["active"] == json!(true)
                        && price["lookup_key"]
                            .as_str()
                            .is_some_and(|key| keys.contains(&key))
                })
                .cloned()
                .collect();
            (
                200,
                json!({"object": "list", "data": data, "has_more": false}).to_string(),
            )
        }
        ("POST", "/v1/checkout/sessions") => {
            let id = format!("cs_test_SynthSession{n:04}");
            (
                200,
                json!({
                    "id": id, "object": "checkout.session",
                    "url": format!("https://checkout.stripe.com/c/pay/{id}"),
                    "expires_at": SESSION_EXPIRES_AT
                })
                .to_string(),
            )
        }
        ("POST", "/v1/billing_portal/sessions") => (
            200,
            json!({
                "id": format!("bps_Synth{n:04}"), "object": "billing_portal.session",
                "url": format!("https://billing.stripe.com/p/session/test_SynthPortal{n:04}")
            })
            .to_string(),
        ),
        ("POST", path) if path.starts_with("/v1/subscription_items/") => {
            let item = &path["/v1/subscription_items/".len()..];
            let quantity: u64 = call
                .field("quantity")
                .and_then(|q| q.parse().ok())
                .unwrap_or(0);
            (
                200,
                json!({"id": item, "object": "subscription_item", "quantity": quantity})
                    .to_string(),
            )
        }
        ("DELETE", path) if path.starts_with("/v1/subscriptions/") => {
            let id = &path["/v1/subscriptions/".len()..];
            (
                200,
                json!({"id": id, "object": "subscription", "status": "canceled"}).to_string(),
            )
        }
        _ => (404, error_body("invalid_request_error", "resource_missing")),
    };
    if let Some(key) = replay_key {
        guard.replays.insert(key, result.clone());
    }
    result
}
