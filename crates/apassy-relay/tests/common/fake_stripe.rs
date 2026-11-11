//! A fake Stripe API for the billing tests: an in-process HTTP server on a free loopback
//! port. It answers the price list (`GET /v1/prices`), customers, Checkout Sessions (made,
//! read back, expired) and Customer Portal sessions, subscription item updates,
//! subscription reads and cancels, and it records every call so a test can check what the
//! relay sent. Like Stripe, a POST with an `Idempotency-Key` seen before gets the first
//! answer again.
//!
//! It also lists a customer's subscriptions (`GET /v1/subscriptions?customer=…`) and reads
//! an item (`GET /v1/subscription_items/{id}`). Like Stripe, it refuses a Checkout Session
//! that collects tax ids for an existing customer without `customer_update[name]=auto`.
//!
//! Hooks: `fail_next(status, n)` answers the next `n` calls with that status;
//! `fail_path(prefix, status, n)` does it for one path only; `fail_after(prefix, status,
//! n)` applies the next `n` calls of a path and then answers that status (a lost answer);
//! `delay_next(prefix, ms)`
//! holds the next call of a path; `set_prices` replaces the price list;
//! `put_subscription` stores the object `GET /v1/subscriptions/{id}` answers;
//! `set_session_status` changes a session; `set_checkout_origin` makes sessions on another
//! origin; `set_date` sends a chosen `Date` header (Stripe's clock).
//!
//! Lists come in pages like Stripe's (`limit`, `starting_after`, `has_more`; the ids in
//! order): `set_page_size` makes the pages smaller than `limit`. It lists a customer's
//! Checkout Sessions (`GET /v1/checkout/sessions?customer=…&status=…`); `add_session`
//! stores one that Connect did not make; `complete_on_expire` makes a session complete
//! (with its subscription) just before Connect's expire, which Stripe then refuses;
//! `appear_on_cancel` adds a subscription when Connect cancels another.
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
    /// (method or any, path prefix, status).
    path_failures: Vec<(Option<String>, String, u16)>,
    after_failures: Vec<(String, u16)>,
    delays: Vec<(String, u64)>,
    replays: HashMap<String, (u16, String)>,
    /// Checkout Sessions by id.
    sessions: HashMap<String, Session>,
    /// Sessions that complete when Connect asks to expire them, with the subscription
    /// they make.
    complete_on_expire: HashMap<String, Value>,
    /// The most entries of one list page (`None`: the `limit` asked).
    page_size: Option<usize>,
    /// Subscriptions that appear when Connect cancels another one (made in between).
    appear_on_cancel: HashMap<String, Value>,
    subscriptions: HashMap<String, Value>,
    checkout_origin: Option<String>,
    date: Option<u64>,
    /// A `Date` header Connect cannot read (an answer without Stripe's time).
    bad_date: bool,
    /// `expires_at` of new sessions; `SESSION_EXPIRES_AT` without one.
    session_expires_at: Option<u64>,
}

/// A Checkout Session of the fake.
#[derive(Debug, Clone)]
struct Session {
    status: String,
    url: String,
    expires_at: u64,
    customer: Option<String>,
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
                let counter = Arc::new(AtomicU32::new(0));
                while !stop.load(Ordering::Relaxed) {
                    match server.recv_timeout(Duration::from_millis(100)) {
                        // Each call on its own thread, as Stripe answers calls at once: a
                        // held call (`delay_next`) does not hold the others.
                        Ok(Some(request)) => {
                            let (state, counter) = (Arc::clone(&state), Arc::clone(&counter));
                            std::thread::spawn(move || handle(request, &state, &counter));
                        }
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

    /// The next `n` calls whose path starts with `prefix` answer `status`.
    pub fn fail_path(&self, prefix: &str, status: u16, n: usize) {
        self.state
            .lock()
            .unwrap()
            .path_failures
            .extend(std::iter::repeat_n((None, prefix.to_owned(), status), n));
    }

    /// The next `n` calls of `method` whose path starts with `prefix` answer `status`.
    pub fn fail_method(&self, method: &str, prefix: &str, status: u16, n: usize) {
        self.state
            .lock()
            .unwrap()
            .path_failures
            .extend(std::iter::repeat_n(
                (Some(method.to_owned()), prefix.to_owned(), status),
                n,
            ));
    }

    /// The next `n` calls whose path starts with `prefix` take effect, and then answer
    /// `status` (Stripe did it; the answer was lost).
    pub fn fail_after(&self, prefix: &str, status: u16, n: usize) {
        self.state
            .lock()
            .unwrap()
            .after_failures
            .extend(std::iter::repeat_n((prefix.to_owned(), status), n));
    }

    /// The next call whose path starts with `prefix` waits `ms` before its answer.
    pub fn delay_next(&self, prefix: &str, ms: u64) {
        self.state
            .lock()
            .unwrap()
            .delays
            .push((prefix.to_owned(), ms));
    }

    /// Stores the subscription that `GET /v1/subscriptions/{id}` answers (Stripe's state).
    pub fn put_subscription(&self, object: Value) {
        let id = object["id"].as_str().expect("a subscription id").to_owned();
        self.state.lock().unwrap().subscriptions.insert(id, object);
    }

    /// The stored subscription, as `GET /v1/subscriptions/{id}` answers it.
    pub fn subscription(&self, id: &str) -> Option<Value> {
        self.state.lock().unwrap().subscriptions.get(id).cloned()
    }

    /// `open`, `complete`, or `expired`.
    pub fn set_session_status(&self, id: &str, status: &str) {
        if let Some(session) = self.state.lock().unwrap().sessions.get_mut(id) {
            session.status = status.to_owned();
        }
    }

    pub fn session_status(&self, id: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .sessions
            .get(id)
            .map(|session| session.status.clone())
    }

    /// The sessions of `customer` that are open, in the order of their ids.
    pub fn open_sessions(&self, customer: &str) -> Vec<String> {
        let mut open: Vec<String> = self
            .state
            .lock()
            .unwrap()
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.status == "open" && session.customer.as_deref() == Some(customer)
            })
            .map(|(id, _)| id.clone())
            .collect();
        open.sort();
        open
    }

    /// Stores a Checkout Session of `customer` that Connect did not make (or forgot).
    pub fn add_session(&self, id: &str, customer: &str, status: &str) {
        self.state.lock().unwrap().sessions.insert(
            id.to_owned(),
            Session {
                status: status.to_owned(),
                url: format!("https://checkout.stripe.com/c/pay/{id}"),
                expires_at: SESSION_EXPIRES_AT,
                customer: Some(customer.to_owned()),
            },
        );
    }

    /// When Connect asks to expire session `id`, it completes first and makes the
    /// subscription `subscription` (Stripe's state); the expire is refused as Stripe
    /// refuses a session that is not open.
    pub fn complete_on_expire(&self, id: &str, subscription: Value) {
        self.state
            .lock()
            .unwrap()
            .complete_on_expire
            .insert(id.to_owned(), subscription);
    }

    /// When Connect cancels subscription `id`, the subscription `appears` is stored too (one
    /// that a purchase made in between).
    pub fn appear_on_cancel(&self, id: &str, appears: Value) {
        self.state
            .lock()
            .unwrap()
            .appear_on_cancel
            .insert(id.to_owned(), appears);
    }

    /// Lists answer at most `size` entries a page (Stripe answers at most `limit`).
    pub fn set_page_size(&self, size: usize) {
        self.state.lock().unwrap().page_size = Some(size.max(1));
    }

    /// New Checkout Sessions get URLs on this origin (with the trailing `/`).
    pub fn set_checkout_origin(&self, origin: &str) {
        self.state.lock().unwrap().checkout_origin = Some(origin.to_owned());
    }

    /// Every answer carries a `Date` header that is not an HTTP date (`true`), as if
    /// Stripe's time were missing.
    pub fn set_bad_date(&self, bad: bool) {
        self.state.lock().unwrap().bad_date = bad;
    }

    /// New Checkout Sessions expire at this time (a test on the real clock).
    pub fn set_session_expires_at(&self, time: u64) {
        self.state.lock().unwrap().session_expires_at = Some(time);
    }

    /// Every answer carries `Date` of this time (Stripe's clock); `None` is the real clock.
    pub fn set_date(&self, time: Option<u64>) {
        self.state.lock().unwrap().date = time;
    }
}

/// An HTTP date (IMF-fixdate) of `secs`.
pub fn http_date(secs: u64) -> String {
    let days = secs / 86_400;
    let rest = secs % 86_400;
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{weekday}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        months[(month - 1) as usize],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
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
    let delay = {
        let mut guard = state.lock().unwrap();
        guard
            .delays
            .iter()
            .position(|(prefix, _)| call.path.starts_with(prefix.as_str()))
            .map(|index| guard.delays.remove(index).1)
    };
    if let Some(ms) = delay {
        std::thread::sleep(Duration::from_millis(ms));
    }
    let (status, answer) = answer(&call, state, counter);
    let (date, bad_date) = {
        let guard = state.lock().unwrap();
        (guard.date, guard.bad_date)
    };
    state.lock().unwrap().calls.push(call);
    let mut response = tiny_http::Response::from_string(answer)
        .with_status_code(status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap());
    if bad_date {
        response = response.with_header(tiny_http::Header::from_bytes("Date", "unknown").unwrap());
    } else if let Some(time) = date {
        response =
            response.with_header(tiny_http::Header::from_bytes("Date", http_date(time)).unwrap());
    }
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
    if let Some(index) = guard.path_failures.iter().position(|(method, prefix, _)| {
        call.path.starts_with(prefix.as_str()) && method.as_deref().is_none_or(|m| m == call.method)
    }) {
        let status = guard.path_failures.remove(index).2;
        return (status, error_body("api_error", "fake_failure"));
    }
    let replay_key = call
        .header("Idempotency-Key")
        .filter(|_| call.method == "POST")
        .map(|key| format!("{} {key}", call.path));
    let replayed = replay_key
        .as_ref()
        .and_then(|key| guard.replays.get(key))
        .cloned();
    let result = match replayed {
        Some(previous) => previous,
        None => fresh_answer(call, &mut guard, counter, replay_key),
    };
    if let Some(index) = guard
        .after_failures
        .iter()
        .position(|(prefix, _)| call.path.starts_with(prefix.as_str()))
    {
        let status = guard.after_failures.remove(index).1;
        return (status, error_body("api_error", "fake_failure"));
    }
    result
}

fn fresh_answer(
    call: &Call,
    guard: &mut State,
    counter: &AtomicU32,
    replay_key: Option<String>,
) -> (u16, String) {
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
        ("POST", "/v1/customers") => {
            let id = format!("cus_SynthMade{n:04}");
            (
                200,
                json!({"id": id, "object": "customer",
                       "metadata": {"account_id": call.field("metadata[account_id]")}})
                .to_string(),
            )
        }
        ("POST", "/v1/checkout/sessions")
            if call.field("tax_id_collection[enabled]") == Some("true")
                && call.field("customer").is_some()
                && call.field("customer_update[name]") != Some("auto") =>
        {
            (
                400,
                error_body("invalid_request_error", "parameter_missing"),
            )
        }
        ("POST", "/v1/checkout/sessions") => {
            let id = format!("cs_test_SynthSession{n:04}");
            let origin = guard
                .checkout_origin
                .clone()
                .unwrap_or_else(|| "https://checkout.stripe.com/".to_owned());
            let url = format!("{origin}c/pay/{id}");
            let expires_at = guard.session_expires_at.unwrap_or(SESSION_EXPIRES_AT);
            guard.sessions.insert(
                id.clone(),
                Session {
                    status: "open".to_owned(),
                    url: url.clone(),
                    expires_at,
                    customer: call.field("customer").map(str::to_owned),
                },
            );
            (
                200,
                json!({
                    "id": id, "object": "checkout.session", "status": "open",
                    "url": url, "expires_at": expires_at
                })
                .to_string(),
            )
        }
        ("POST", path)
            if path.starts_with("/v1/checkout/sessions/") && path.ends_with("/expire") =>
        {
            let id = &path["/v1/checkout/sessions/".len()..path.len() - "/expire".len()];
            if let Some(subscription) = guard.complete_on_expire.remove(id) {
                if let Some(session) = guard.sessions.get_mut(id) {
                    session.status = "complete".to_owned();
                }
                let sub_id = subscription["id"].as_str().unwrap_or_default().to_owned();
                guard.subscriptions.insert(sub_id, subscription);
            }
            match guard.sessions.get_mut(id) {
                Some(session) if session.status == "open" => {
                    session.status = "expired".to_owned();
                    (
                        200,
                        json!({"id": id, "object": "checkout.session", "status": "expired",
                               "url": null, "expires_at": session.expires_at})
                        .to_string(),
                    )
                }
                Some(_) => (
                    400,
                    error_body("invalid_request_error", "checkout_session_not_open"),
                ),
                None => (404, error_body("invalid_request_error", "resource_missing")),
            }
        }
        ("GET", "/v1/checkout/sessions") => {
            let field = |name: &str| {
                call.query
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            };
            let (customer, status) = (field("customer"), field("status"));
            let data: Vec<Value> = guard
                .sessions
                .iter()
                .filter(|(_, session)| {
                    session.customer == customer
                        && status
                            .as_deref()
                            .is_none_or(|status| session.status == status)
                })
                .map(|(id, session)| session_json(id, session))
                .collect();
            page(call, guard.page_size, data)
        }
        ("GET", path) if path.starts_with("/v1/checkout/sessions/") => {
            let id = &path["/v1/checkout/sessions/".len()..];
            match guard.sessions.get(id) {
                Some(session) => (200, session_json(id, session).to_string()),
                None => (404, error_body("invalid_request_error", "resource_missing")),
            }
        }
        ("GET", "/v1/subscriptions") => {
            let customer = call
                .query
                .iter()
                .find(|(k, _)| k == "customer")
                .map(|(_, v)| v.clone());
            let data: Vec<Value> = guard
                .subscriptions
                .values()
                .filter(|object| object["customer"].as_str() == customer.as_deref())
                .cloned()
                .collect();
            page(call, guard.page_size, data)
        }
        ("GET", path) if path.starts_with("/v1/subscription_items/") => {
            let item = &path["/v1/subscription_items/".len()..];
            let quantity = guard.subscriptions.values().find_map(|object| {
                (object.pointer("/items/data/0/id").and_then(Value::as_str) == Some(item))
                    .then(|| object.pointer("/items/data/0/quantity").cloned())
                    .flatten()
            });
            match quantity {
                Some(quantity) => (
                    200,
                    json!({"id": item, "object": "subscription_item", "quantity": quantity})
                        .to_string(),
                ),
                None => (404, error_body("invalid_request_error", "resource_missing")),
            }
        }
        ("GET", path) if path.starts_with("/v1/subscriptions/") => {
            let id = &path["/v1/subscriptions/".len()..];
            match guard.subscriptions.get(id) {
                Some(object) => (200, object.to_string()),
                None => (404, error_body("invalid_request_error", "resource_missing")),
            }
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
            for object in guard.subscriptions.values_mut() {
                if object.pointer("/items/data/0/id").and_then(Value::as_str) == Some(item) {
                    object["items"]["data"][0]["quantity"] = json!(quantity);
                }
            }
            (
                200,
                json!({"id": item, "object": "subscription_item", "quantity": quantity})
                    .to_string(),
            )
        }
        ("DELETE", path) if path.starts_with("/v1/subscriptions/") => {
            let id = &path["/v1/subscriptions/".len()..];
            if let Some(object) = guard.subscriptions.get_mut(id) {
                object["status"] = json!("canceled");
            }
            if let Some(appears) = guard.appear_on_cancel.remove(id) {
                let new_id = appears["id"].as_str().unwrap_or_default().to_owned();
                guard.subscriptions.insert(new_id, appears);
            }
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

/// A session as Stripe answers it.
fn session_json(id: &str, session: &Session) -> Value {
    json!({"id": id, "object": "checkout.session", "status": session.status,
           "customer": session.customer,
           "url": if session.status == "open" { json!(session.url) } else { Value::Null },
           "expires_at": session.expires_at})
}

/// One page of a list, in the order of the ids: the entries after `starting_after`, at
/// most `limit` (and the fake's page size), and `has_more`.
fn page(call: &Call, page_size: Option<usize>, mut data: Vec<Value>) -> (u16, String) {
    let field = |name: &str| {
        call.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    data.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    if let Some(after) = field("starting_after") {
        data.retain(|object| object["id"].as_str().is_some_and(|id| id > after.as_str()));
    }
    let limit = field("limit")
        .and_then(|limit| limit.parse::<usize>().ok())
        .unwrap_or(10)
        .min(page_size.unwrap_or(usize::MAX));
    let has_more = data.len() > limit;
    data.truncate(limit);
    (
        200,
        json!({"object": "list", "data": data, "has_more": has_more}).to_string(),
    )
}
