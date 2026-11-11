//! The Stripe client of Connect billing, and the check of the Stripe webhook signature
//! (docs/contracts/connect-billing-v1.md sections 1, 2, 4, 5, 6, 7, 9; docs/SPEC.md
//! section "Billing").
//!
//! No SDK: form-encoded requests over the crate's `ureq`, with the restricted key read
//! from a file, one pinned `Stripe-Version`, and an `Idempotency-Key` on every POST that
//! is reused when the same call is retried. The base URL is configuration, so the tests
//! talk to `tests/common/fake_stripe.rs` on a loopback port.
//!
//! What Connect sends Stripe: the account id (`client_reference_id`, metadata), price
//! ids, quantities, customer and subscription ids, and its own site URLs. Never a device
//! key, a token, a vault id, a device name, or a value. A log line of this module names
//! the method, the path, the HTTP status, and Stripe's error type and code; never the
//! key, a request body, or Stripe's error message.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{RelayError, RelayResult, codes};
use crate::secret::SecretString;

/// Stripe's API origin.
pub const API_BASE: &str = "https://api.stripe.com";
/// The pinned API version: the version of the webhook endpoint (contract section 1).
pub const API_VERSION: &str = "2025-03-31.basil";
/// The largest webhook body the relay reads (contract section 7).
pub const MAX_WEBHOOK_BODY: usize = 256 * 1024;
/// The largest distance between `t` of the signature and the relay's clock.
pub const SIGNATURE_TOLERANCE: u64 = 300;
/// The header of the webhook signature.
pub const SIGNATURE_HEADER: &str = "Stripe-Signature";
/// The header of an idempotent POST.
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
/// How long resolved prices are kept before the next lookup.
pub const PRICE_TTL: u64 = 3600;
/// After a failed price lookup, the next one waits this long: `GET /v1/plans` answers
/// from the last prices, or `503 busy`, without asking Stripe on every request.
pub const PRICE_RETRY_SECS: u64 = 60;
/// The only origin of a Checkout Session URL that Connect returns.
pub const CHECKOUT_ORIGIN: &str = "https://checkout.stripe.com/";
/// The only origin of a Customer Portal URL that Connect returns.
pub const PORTAL_ORIGIN: &str = "https://billing.stripe.com/";
/// The largest answer from Stripe that the relay reads.
const MAX_ANSWER_BYTES: u64 = 1024 * 1024;
/// The largest `Stripe-Signature` header the relay parses, and its most `v1` values.
const MAX_SIGNATURE_HEADER: usize = 4096;
const MAX_SIGNATURES: usize = 8;
/// Attempts of one call: the first and one retry with the same idempotency key.
const ATTEMPTS: u32 = 2;
/// The size of one page of a Stripe list (Stripe's largest `limit`).
pub const LIST_PAGE: usize = 100;
/// The most pages of one list that Connect reads (`starting_after`); a longer list is
/// treated as unknown (`complete: false`).
pub const MAX_LIST_PAGES: usize = 10;

/// Where log lines go. The default writes to standard error with the relay's prefix.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// The default log sink.
pub fn stderr_log() -> LogSink {
    Arc::new(|line: &str| eprintln!("apassy-relay: billing: {line}"))
}

/// Reads the restricted API key from a file (`STRIPE_SECRET_KEY_FILE`). The content,
/// without a trailing newline, must be a restricted key (`rk_live_…`, `rk_test_…`) or a
/// sandbox secret key (`sk_test_…`). A live secret key (`sk_live_…`) is refused: Connect
/// runs with the restricted key of OPERATIONS.md only.
pub fn read_secret_key_file(path: &Path) -> RelayResult<SecretString> {
    let key = read_trimmed(path, "STRIPE_SECRET_KEY_FILE")?;
    check_secret_key(&key)?;
    Ok(key)
}

/// Checks the form of an API key (see `read_secret_key_file`).
pub fn check_secret_key(key: &SecretString) -> RelayResult<()> {
    let text = key.expose();
    let allowed = ["rk_live_", "rk_test_", "sk_test_"]
        .iter()
        .any(|prefix| text.starts_with(prefix));
    if text.starts_with("sk_live_") {
        return Err(RelayError::invalid(
            "STRIPE_SECRET_KEY_FILE holds a live secret key; Connect needs a restricted key (rk_live_…).",
        ));
    }
    if !allowed || text.len() > 512 || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(RelayError::invalid(
            "STRIPE_SECRET_KEY_FILE does not hold a Stripe restricted key.",
        ));
    }
    Ok(())
}

/// Reads the webhook endpoint secret from a file (`STRIPE_WEBHOOK_SECRET_FILE`): the
/// whole `whsec_…` string.
pub fn read_webhook_secret_file(path: &Path) -> RelayResult<SecretString> {
    let secret = read_trimmed(path, "STRIPE_WEBHOOK_SECRET_FILE")?;
    check_webhook_secret(&secret)?;
    Ok(secret)
}

/// Checks the form of a webhook endpoint secret.
pub fn check_webhook_secret(secret: &SecretString) -> RelayResult<()> {
    let text = secret.expose();
    if !text.starts_with("whsec_") || text.len() < 16 || text.len() > 512 {
        return Err(RelayError::invalid(
            "STRIPE_WEBHOOK_SECRET_FILE does not hold a webhook secret (whsec_…).",
        ));
    }
    Ok(())
}

fn read_trimmed(path: &Path, name: &str) -> RelayResult<SecretString> {
    let text = std::fs::read_to_string(path)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| RelayError::invalid(format!("{name} cannot be read.")))?;
    Ok(SecretString::new(
        text.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

/// True for a Stripe object id with this prefix (`cus_`, `sub_`, `si_`, `price_`, `cs_`,
/// `evt_`): ASCII letters, digits, and `_`, at most 255 bytes. Ids that go into a URL path
/// are checked with it first.
pub fn is_stripe_id(prefix: &str, id: &str) -> bool {
    id.len() > prefix.len()
        && id.len() <= 255
        && id.starts_with(prefix)
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

// ---------------------------------------------------------------------------------------
// Form encoding.

/// A form body for Stripe, in the order of the calls (`application/x-www-form-urlencoded`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, key: &str, value: impl Into<String>) -> &mut Self {
        self.0.push((key.to_owned(), value.into()));
        self
    }

    pub fn pairs(&self) -> &[(String, String)] {
        &self.0
    }

    pub fn encode(&self) -> String {
        form_encode(&self.0)
    }
}

/// Percent-encodes pairs as a form body or a query: every byte but `A-Z a-z 0-9 - . _ ~`
/// is `%XX`.
pub fn form_encode(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        encode_component(&mut out, key);
        out.push('=');
        encode_component(&mut out, value);
    }
    out
}

fn encode_component(out: &mut String, text: &str) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }
}

/// Decodes a form body or a query (`+` is a space). The inverse of `form_encode`; the
/// fake Stripe server of the tests uses it.
pub fn form_decode(text: &str) -> RelayResult<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    if text.is_empty() {
        return Ok(pairs);
    }
    for part in text.split('&') {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        pairs.push((decode_component(key)?, decode_component(value)?));
    }
    Ok(pairs)
}

fn decode_component(text: &str) -> RelayResult<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                    .ok_or_else(|| RelayError::invalid("A form field is not percent-encoded."))?;
                out.push(pair);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| RelayError::invalid("A form field is not UTF-8."))
}

// ---------------------------------------------------------------------------------------
// Prices.

/// One tier of a tiered Stripe price.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StripeTier {
    /// `None` is `inf`.
    pub up_to: Option<u64>,
    pub flat_amount: Option<u64>,
    pub unit_amount: Option<u64>,
}

/// The recurring part of a price.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StripeRecurring {
    pub interval: String,
    #[serde(default = "one")]
    pub interval_count: u64,
}

fn one() -> u64 {
    1
}

/// A Stripe price, as `GET /v1/prices` answers it (the fields Connect reads).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StripePrice {
    pub id: String,
    #[serde(default)]
    pub lookup_key: Option<String>,
    pub currency: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub tax_behavior: Option<String>,
    #[serde(default)]
    pub billing_scheme: Option<String>,
    #[serde(default)]
    pub unit_amount: Option<u64>,
    #[serde(default)]
    pub tiers_mode: Option<String>,
    #[serde(default)]
    pub tiers: Option<Vec<StripeTier>>,
    #[serde(default)]
    pub recurring: Option<StripeRecurring>,
}

#[derive(Deserialize)]
struct PriceList {
    data: Vec<StripePrice>,
}

struct PriceCache {
    fetched_at: u64,
    keys: Vec<String>,
    prices: HashMap<String, StripePrice>,
}

/// The price cache and the time of the last failed lookup.
#[derive(Default)]
struct Prices {
    cache: Option<PriceCache>,
    failed_at: Option<u64>,
}

impl Prices {
    fn for_keys(&self, keys: &[&str]) -> Option<&PriceCache> {
        self.cache.as_ref().filter(|cache| {
            cache
                .keys
                .iter()
                .map(String::as_str)
                .eq(keys.iter().copied())
        })
    }
}

/// A Checkout Session as Connect uses it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
    pub expires_at: u64,
}

/// A Checkout Session read back: `status` is `open`, `complete`, or `expired`; `url` is
/// `null` once it is not open.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CheckoutSessionState {
    pub id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    pub expires_at: u64,
}

/// A subscription read from Stripe: the object, and Stripe's time from the answer's
/// `Date` header.
#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionRead {
    pub object: Value,
    pub date: Option<u64>,
}

/// The subscriptions of one customer at Stripe (`StripeClient::customer_subscriptions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerSubscriptions {
    /// (subscription id, Stripe status), as Stripe lists them.
    pub list: Vec<(String, String)>,
    /// False when Stripe has more than `MAX_LIST_PAGES` pages.
    pub complete: bool,
    /// Stripe's time from the `Date` header of the first answer.
    pub date: Option<u64>,
}

/// The open Checkout Sessions of one customer at Stripe
/// (`StripeClient::customer_open_sessions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerSessions {
    /// The session ids, as Stripe lists them.
    pub list: Vec<String>,
    /// False when Stripe has more than `MAX_LIST_PAGES` pages.
    pub complete: bool,
}

/// True for a URL that Connect may hand to a browser for this Stripe origin: the origin
/// itself, a path, at most 4096 bytes, no space or control character.
pub fn is_stripe_page(url: &str, origin: &str) -> bool {
    url.len() <= 4096
        && url
            .strip_prefix(origin)
            .is_some_and(|path| !path.is_empty())
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// A Customer Portal session as Connect uses it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PortalSession {
    pub url: String,
}

// ---------------------------------------------------------------------------------------
// The client.

/// Where and how to reach Stripe.
#[derive(Clone)]
pub struct StripeConfig {
    /// `https://api.stripe.com`, or `http://127.0.0.1:<port>` of the fake server.
    pub base_url: String,
    pub api_version: String,
    pub timeout: Duration,
    key: Arc<SecretString>,
}

impl std::fmt::Debug for StripeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripeConfig")
            .field("base_url", &self.base_url)
            .field("api_version", &self.api_version)
            .field("timeout", &self.timeout)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl StripeConfig {
    /// A configuration with the pinned API version and a 10-second timeout. The base is
    /// `https://…`, or `http://` on a loopback address only (the fake server).
    pub fn new(base_url: &str, key: SecretString) -> RelayResult<Self> {
        check_secret_key(&key)?;
        let base = base_url.trim_end_matches('/');
        let loopback = ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
            .iter()
            .any(|prefix| base.starts_with(prefix));
        if !(base.starts_with("https://") || loopback) || base.contains(['?', '#', ' ', '@', '\\'])
        {
            return Err(RelayError::invalid(
                "The Stripe API base must be https://, or http:// on a loopback address.",
            ));
        }
        Ok(Self {
            base_url: base.to_owned(),
            api_version: API_VERSION.to_owned(),
            timeout: Duration::from_secs(10),
            key: Arc::new(key),
        })
    }

    /// The live API with the key of `STRIPE_SECRET_KEY_FILE`.
    pub fn from_key_file(path: &Path) -> RelayResult<Self> {
        Self::new(API_BASE, read_secret_key_file(path)?)
    }

    /// True when the key is a live key (`rk_live_…`).
    pub fn is_live(&self) -> bool {
        self.key.expose().starts_with("rk_live_")
    }
}

/// The Stripe client. One per relay; calls from several request threads share it.
pub struct StripeClient {
    config: StripeConfig,
    agent: ureq::Agent,
    prices: Mutex<Prices>,
    /// Held by the one caller that asks Stripe for the prices: the others wait for its
    /// answer and take it from the cache (one lookup at a time).
    fetching: Mutex<()>,
    log: LogSink,
}

/// The HTTP method of a Stripe call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

impl StripeClient {
    pub fn new(config: StripeConfig) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(config.timeout))
            .build()
            .into();
        Self {
            config,
            agent,
            prices: Mutex::new(Prices::default()),
            fetching: Mutex::new(()),
            log: stderr_log(),
        }
    }

    /// The same client with another log sink (the tests capture lines).
    pub fn with_log(mut self, log: LogSink) -> Self {
        self.log = log;
        self
    }

    pub fn config(&self) -> &StripeConfig {
        &self.config
    }

    /// The active prices of these lookup keys, from the cache when it is younger than
    /// `PRICE_TTL` and has the same keys. A failed lookup keeps the cached prices, if any,
    /// and the next lookup waits `PRICE_RETRY_SECS`: until then the cached prices answer,
    /// or `503 busy` without a call.
    ///
    /// One lookup at a time: callers that find the cache old while another one asks Stripe
    /// wait for that answer and take it from the cache.
    pub fn prices(&self, keys: &[&str], now: u64) -> RelayResult<HashMap<String, StripePrice>> {
        if let Some(answer) = self.cached_prices(keys, now) {
            return answer;
        }
        let _fetching = self.fetching.lock().unwrap_or_else(PoisonError::into_inner);
        // Another caller may have asked Stripe while this one waited.
        if let Some(answer) = self.cached_prices(keys, now) {
            return answer;
        }
        match self.fetch_prices(keys) {
            Ok(fetched) => {
                let mut prices = self.prices.lock().unwrap_or_else(PoisonError::into_inner);
                prices.cache = Some(PriceCache {
                    fetched_at: now,
                    keys: keys.iter().map(|key| (*key).to_owned()).collect(),
                    prices: fetched.clone(),
                });
                prices.failed_at = None;
                Ok(fetched)
            }
            Err(error) => {
                let mut prices = self.prices.lock().unwrap_or_else(PoisonError::into_inner);
                prices.failed_at = Some(now);
                match prices.for_keys(keys) {
                    Some(cache) => Ok(cache.prices.clone()),
                    None => Err(error),
                }
            }
        }
    }

    /// The answer of `prices` without a call: the cache when it is fresh, the cache or
    /// `503 busy` within `PRICE_RETRY_SECS` of a failed lookup; `None` when Stripe is to
    /// be asked.
    fn cached_prices(
        &self,
        keys: &[&str],
        now: u64,
    ) -> Option<RelayResult<HashMap<String, StripePrice>>> {
        let prices = self.prices.lock().unwrap_or_else(PoisonError::into_inner);
        let cached = prices.for_keys(keys);
        if let Some(cache) = cached
            && now.saturating_sub(cache.fetched_at) < PRICE_TTL
            && now >= cache.fetched_at
        {
            return Some(Ok(cache.prices.clone()));
        }
        if prices
            .failed_at
            .is_some_and(|at| now >= at && now < at.saturating_add(PRICE_RETRY_SECS))
        {
            return Some(match cached {
                Some(cache) => Ok(cache.prices.clone()),
                None => Err(RelayError::new(
                    codes::BUSY,
                    "Stripe cannot be reached. Try again later.",
                )),
            });
        }
        None
    }

    /// Drops the cached prices: the next `prices` call asks Stripe.
    pub fn forget_prices(&self) {
        *self.prices.lock().unwrap_or_else(PoisonError::into_inner) = Prices::default();
    }

    /// `GET /v1/prices?lookup_keys[]=…&active=true&expand[]=data.tiers` (at most 10 keys).
    pub fn fetch_prices(&self, keys: &[&str]) -> RelayResult<HashMap<String, StripePrice>> {
        if keys.is_empty() || keys.len() > 10 {
            return Err(RelayError::internal("Stripe takes 1 to 10 lookup keys."));
        }
        let mut query: Vec<(String, String)> = keys
            .iter()
            .map(|key| ("lookup_keys[]".to_owned(), (*key).to_owned()))
            .collect();
        query.push(("active".into(), "true".into()));
        query.push(("expand[]".into(), "data.tiers".into()));
        query.push(("limit".into(), "100".into()));
        let value = self.call(
            Method::Get,
            "/v1/prices",
            Some(&form_encode(&query)),
            None,
            None,
        )?;
        let list: PriceList =
            serde_json::from_value(value).map_err(|_| self.bad_answer("/v1/prices"))?;
        let mut prices = HashMap::new();
        for price in list.data {
            let Some(key) = price.lookup_key.clone() else {
                continue;
            };
            if price.active && keys.contains(&key.as_str()) && is_stripe_id("price_", &price.id) {
                prices.insert(key, price);
            }
        }
        Ok(prices)
    }

    /// `POST /v1/checkout/sessions` with the form the billing module built.
    pub fn create_checkout_session(
        &self,
        form: &Form,
        idempotency_key: &str,
    ) -> RelayResult<CheckoutSession> {
        let value = self.call(
            Method::Post,
            "/v1/checkout/sessions",
            None,
            Some(form),
            Some(idempotency_key),
        )?;
        let session: CheckoutSession =
            serde_json::from_value(value).map_err(|_| self.bad_answer("/v1/checkout/sessions"))?;
        if !is_stripe_id("cs_", &session.id) || !is_stripe_page(&session.url, CHECKOUT_ORIGIN) {
            return Err(self.bad_answer("/v1/checkout/sessions"));
        }
        Ok(session)
    }

    /// `GET /v1/checkout/sessions/{id}`: whether a session is still open.
    pub fn checkout_session(&self, id: &str) -> RelayResult<CheckoutSessionState> {
        if !is_stripe_id("cs_", id) {
            return Err(RelayError::internal(
                "The stored checkout session id is not valid.",
            ));
        }
        let path = format!("/v1/checkout/sessions/{id}");
        let value = self.call(Method::Get, &path, None, None, None)?;
        let mut session: CheckoutSessionState =
            serde_json::from_value(value).map_err(|_| self.bad_answer("/v1/checkout/sessions"))?;
        if session.id != id {
            return Err(self.bad_answer("/v1/checkout/sessions"));
        }
        if session
            .url
            .as_deref()
            .is_some_and(|url| !is_stripe_page(url, CHECKOUT_ORIGIN))
        {
            session.url = None;
        }
        Ok(session)
    }

    /// `POST /v1/checkout/sessions/{id}/expire`: an open session ends, so it cannot make
    /// a subscription later.
    pub fn expire_checkout_session(&self, id: &str, idempotency_key: &str) -> RelayResult<()> {
        if !is_stripe_id("cs_", id) {
            return Err(RelayError::internal(
                "The stored checkout session id is not valid.",
            ));
        }
        self.call(
            Method::Post,
            &format!("/v1/checkout/sessions/{id}/expire"),
            None,
            Some(&Form::new()),
            Some(idempotency_key),
        )?;
        Ok(())
    }

    /// `POST /v1/customers` with `metadata[account_id]`: the Stripe customer of an
    /// account, made before its first checkout. Answers the customer id.
    pub fn create_customer(&self, account: &str, idempotency_key: &str) -> RelayResult<String> {
        let mut form = Form::new();
        form.push("metadata[account_id]", account);
        let value = self.call(
            Method::Post,
            "/v1/customers",
            None,
            Some(&form),
            Some(idempotency_key),
        )?;
        match value.pointer("/id").and_then(Value::as_str) {
            Some(id) if is_stripe_id("cus_", id) => Ok(id.to_owned()),
            _ => Err(self.bad_answer("/v1/customers")),
        }
    }

    /// `GET /v1/subscriptions/{id}`: Stripe's state of a subscription, with Stripe's time.
    pub fn subscription(&self, id: &str) -> RelayResult<SubscriptionRead> {
        if !is_stripe_id("sub_", id) {
            return Err(RelayError::internal(
                "The stored subscription id is not valid.",
            ));
        }
        let (object, date) = self.call_dated(
            Method::Get,
            &format!("/v1/subscriptions/{id}"),
            None,
            None,
            None,
        )?;
        if object.pointer("/id").and_then(Value::as_str) != Some(id) {
            return Err(self.bad_answer("/v1/subscriptions"));
        }
        Ok(SubscriptionRead { object, date })
    }

    /// `GET /v1/subscriptions?customer=…&status=all&limit=100`, page after page
    /// (`starting_after`): every subscription of a customer at Stripe, ended ones
    /// included, as (id, status). `complete` is false when Stripe has more than
    /// `MAX_LIST_PAGES` pages: the caller treats the list as unknown.
    pub fn customer_subscriptions(&self, customer: &str) -> RelayResult<CustomerSubscriptions> {
        if !is_stripe_id("cus_", customer) {
            return Err(RelayError::internal(
                "The stored Stripe customer id is not valid.",
            ));
        }
        let path = "/v1/subscriptions";
        let (list, complete, date) = self.list_pages(
            path,
            &[
                ("customer", customer.to_owned()),
                ("status", "all".to_owned()),
            ],
            |object| {
                let id = object.pointer("/id").and_then(Value::as_str);
                let status = object.pointer("/status").and_then(Value::as_str);
                let owner = object.pointer("/customer").and_then(Value::as_str);
                match (id, status) {
                    (Some(id), Some(status))
                        if is_stripe_id("sub_", id) && owner == Some(customer) =>
                    {
                        Ok((id.to_owned(), status.to_owned()))
                    }
                    _ => Err(self.bad_answer(path)),
                }
            },
        )?;
        Ok(CustomerSubscriptions {
            list,
            complete,
            date,
        })
    }

    /// `GET /v1/checkout/sessions?customer=…&status=open&limit=100`, page after page: the
    /// open Checkout Sessions of a customer at Stripe, also those Connect no longer
    /// stores. `complete` is false when Stripe has more than `MAX_LIST_PAGES` pages.
    pub fn customer_open_sessions(&self, customer: &str) -> RelayResult<CustomerSessions> {
        if !is_stripe_id("cus_", customer) {
            return Err(RelayError::internal(
                "The stored Stripe customer id is not valid.",
            ));
        }
        let path = "/v1/checkout/sessions";
        let (list, complete, _) = self.list_pages(
            path,
            &[
                ("customer", customer.to_owned()),
                ("status", "open".to_owned()),
            ],
            |object| {
                let id = object.pointer("/id").and_then(Value::as_str);
                let owner = object.pointer("/customer").and_then(Value::as_str);
                match id {
                    Some(id) if is_stripe_id("cs_", id) && owner == Some(customer) => {
                        Ok(id.to_owned())
                    }
                    _ => Err(self.bad_answer(path)),
                }
            },
        )?;
        Ok(CustomerSessions { list, complete })
    }

    /// Reads a Stripe list page after page (`limit=100`, then `starting_after` the last
    /// id), at most `MAX_LIST_PAGES` pages. Answers the entries, whether the list ended
    /// within them, and Stripe's time of the first answer.
    fn list_pages<T>(
        &self,
        path: &str,
        filters: &[(&str, String)],
        entry: impl Fn(&Value) -> RelayResult<T>,
    ) -> RelayResult<(Vec<T>, bool, Option<u64>)> {
        let mut entries = Vec::new();
        let mut after: Option<String> = None;
        let mut first_date = None;
        for page in 0..MAX_LIST_PAGES {
            let mut query: Vec<(String, String)> = filters
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect();
            query.push(("limit".to_owned(), LIST_PAGE.to_string()));
            if let Some(after) = &after {
                query.push(("starting_after".to_owned(), after.clone()));
            }
            let (value, date) =
                self.call_dated(Method::Get, path, Some(&form_encode(&query)), None, None)?;
            if page == 0 {
                first_date = date;
            }
            let Some(data) = value.pointer("/data").and_then(Value::as_array) else {
                return Err(self.bad_answer(path));
            };
            let more = match value.pointer("/has_more").and_then(Value::as_bool) {
                Some(more) => more,
                None => return Err(self.bad_answer(path)),
            };
            for object in data {
                entries.push(entry(object)?);
            }
            if !more {
                return Ok((entries, true, first_date));
            }
            // A page that says there is more must end with an id to go on from.
            match data
                .last()
                .and_then(|object| object.pointer("/id"))
                .and_then(Value::as_str)
            {
                Some(id) if Some(id) != after.as_deref() => after = Some(id.to_owned()),
                _ => return Err(self.bad_answer(path)),
            }
        }
        Ok((entries, false, first_date))
    }

    /// `GET /v1/subscription_items/{item}`: the quantity Stripe has for an item (read back
    /// after a quantity change whose answer was lost).
    pub fn item_quantity(&self, item: &str) -> RelayResult<u32> {
        if !is_stripe_id("si_", item) {
            return Err(RelayError::internal(
                "The stored subscription item id is not valid.",
            ));
        }
        let value = self.call(
            Method::Get,
            &format!("/v1/subscription_items/{item}"),
            None,
            None,
            None,
        )?;
        if value.pointer("/id").and_then(Value::as_str) != Some(item) {
            return Err(self.bad_answer("/v1/subscription_items"));
        }
        value
            .pointer("/quantity")
            .and_then(Value::as_u64)
            .and_then(|quantity| u32::try_from(quantity).ok())
            .ok_or_else(|| self.bad_answer("/v1/subscription_items"))
    }

    /// `POST /v1/billing_portal/sessions` with `customer` and `return_url`.
    pub fn create_portal_session(
        &self,
        customer: &str,
        return_url: &str,
        idempotency_key: &str,
    ) -> RelayResult<PortalSession> {
        if !is_stripe_id("cus_", customer) {
            return Err(RelayError::internal(
                "The stored Stripe customer id is not valid.",
            ));
        }
        let mut form = Form::new();
        form.push("customer", customer)
            .push("return_url", return_url);
        let value = self.call(
            Method::Post,
            "/v1/billing_portal/sessions",
            None,
            Some(&form),
            Some(idempotency_key),
        )?;
        let session: PortalSession = serde_json::from_value(value)
            .map_err(|_| self.bad_answer("/v1/billing_portal/sessions"))?;
        if !is_stripe_page(&session.url, PORTAL_ORIGIN) {
            return Err(self.bad_answer("/v1/billing_portal/sessions"));
        }
        Ok(session)
    }

    /// `POST /v1/subscription_items/{item}` with `quantity` and
    /// `proration_behavior=create_prorations`. Connect applies the new quantity only when
    /// `customer.subscription.updated` arrives.
    pub fn update_item_quantity(
        &self,
        item: &str,
        quantity: u32,
        idempotency_key: &str,
    ) -> RelayResult<()> {
        if !is_stripe_id("si_", item) {
            return Err(RelayError::internal(
                "The stored subscription item id is not valid.",
            ));
        }
        let mut form = Form::new();
        form.push("quantity", quantity.to_string())
            .push("proration_behavior", "create_prorations");
        self.call(
            Method::Post,
            &format!("/v1/subscription_items/{item}"),
            None,
            Some(&form),
            Some(idempotency_key),
        )?;
        Ok(())
    }

    /// `DELETE /v1/subscriptions/{id}`: the subscription ends now (account deletion,
    /// contract section 9). A subscription Stripe no longer knows (404) counts as ended.
    pub fn cancel_subscription(&self, subscription: &str) -> RelayResult<()> {
        if !is_stripe_id("sub_", subscription) {
            return Err(RelayError::internal(
                "The stored subscription id is not valid.",
            ));
        }
        match self.call(
            Method::Delete,
            &format!("/v1/subscriptions/{subscription}"),
            None,
            None,
            None,
        ) {
            Ok(_) => Ok(()),
            Err(error) if error.code == codes::NOT_FOUND => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn bad_answer(&self, path: &str) -> RelayError {
        (self.log)(&format!(
            "stripe: the answer of {path} is not the expected object"
        ));
        RelayError::new(codes::UPSTREAM_FAILED, "Stripe did not answer as expected.")
    }

    /// One call with its retry. A transport failure, 409 (Stripe's lock on the same
    /// idempotency key), 429, or 5xx is tried once more with the same idempotency key.
    fn call(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        form: Option<&Form>,
        idempotency_key: Option<&str>,
    ) -> RelayResult<Value> {
        self.call_dated(method, path, query, form, idempotency_key)
            .map(|(value, _)| value)
    }

    /// `call`, with Stripe's time from the `Date` header of the answer.
    fn call_dated(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        form: Option<&Form>,
        idempotency_key: Option<&str>,
    ) -> RelayResult<(Value, Option<u64>)> {
        if method == Method::Post && idempotency_key.is_none_or(str::is_empty) {
            return Err(RelayError::internal(
                "A Stripe POST needs an idempotency key.",
            ));
        }
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(250));
            }
            match self.call_once(method, path, query, form, idempotency_key) {
                Ok((status, body, date)) if (200..300).contains(&status) => {
                    return serde_json::from_slice(&body)
                        .map(|value| (value, date))
                        .map_err(|_| self.bad_answer(path));
                }
                Ok((status, body, _)) => {
                    let (kind, code) = stripe_error_words(&body);
                    (self.log)(&format!(
                        "stripe: {} {path} answered {status} ({kind}/{code})",
                        method.as_str()
                    ));
                    let retry = status == 409 || status == 429 || status >= 500;
                    last = Some(match status {
                        404 => {
                            RelayError::new(codes::NOT_FOUND, "Stripe does not know that object.")
                        }
                        429 | 500.. => {
                            RelayError::new(codes::BUSY, "Stripe is busy. Try again later.")
                        }
                        _ => RelayError::new(
                            codes::UPSTREAM_FAILED,
                            "Stripe did not accept the request.",
                        ),
                    });
                    if !retry {
                        break;
                    }
                }
                Err(words) => {
                    (self.log)(&format!(
                        "stripe: {} {path} failed: {words}",
                        method.as_str()
                    ));
                    last = Some(RelayError::new(
                        codes::BUSY,
                        "Stripe cannot be reached. Try again later.",
                    ));
                }
            }
        }
        Err(last.unwrap_or_else(|| RelayError::new(codes::BUSY, "Stripe cannot be reached.")))
    }

    fn call_once(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        form: Option<&Form>,
        idempotency_key: Option<&str>,
    ) -> Result<(u16, Vec<u8>, Option<u64>), String> {
        let mut url = format!("{}{path}", self.config.base_url);
        if let Some(query) = query {
            url.push('?');
            url.push_str(query);
        }
        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.key.expose()),
            )
            .header("Stripe-Version", self.config.api_version.as_str())
            .header("Accept", "application/json");
        if let Some(key) = idempotency_key {
            builder = builder.header(IDEMPOTENCY_HEADER, key);
        }
        let result = match form {
            Some(form) => builder
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form.encode())
                .map_err(|_| "the request cannot be built".to_owned())
                .and_then(|request| self.agent.run(request).map_err(transport_words)),
            None => builder
                .body(())
                .map_err(|_| "the request cannot be built".to_owned())
                .and_then(|request| self.agent.run(request).map_err(transport_words)),
        };
        let mut response = result?;
        let status = response.status().as_u16();
        let date = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_http_date);
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .map_err(transport_words)?;
        Ok((status, body, date))
    }
}

/// Seconds since 1970 of an HTTP date in the IMF-fixdate form (`Tue, 10 Nov 2026 21:58:00
/// GMT`), the form Stripe sends. Any other form is `None`.
pub fn parse_http_date(text: &str) -> Option<u64> {
    let parts: Vec<&str> = text.trim().split(' ').collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    let day: u64 = day.parse().ok().filter(|d| (1..=31).contains(d))?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| m == month)? as u64
        + 1;
    let year: u64 = year.parse().ok().filter(|y| (1970..=9999).contains(y))?;
    let clock: Vec<u64> = time
        .split(':')
        .map(|part| part.parse().ok())
        .collect::<Option<_>>()?;
    let [hour, minute, second] = clock.as_slice() else {
        return None;
    };
    if *hour > 23 || *minute > 59 || *second > 60 {
        return None;
    }
    // Days from 1970-01-01 of a civil date (Howard Hinnant's algorithm).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let year_of_era = y - era * 400;
    let day_of_year = (153 * m + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn transport_words(error: ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "timeout".to_owned(),
        ureq::Error::Io(e) => format!("{:?}", e.kind()),
        ureq::Error::HostNotFound => "host not found".to_owned(),
        ureq::Error::ConnectionFailed => "connection failed".to_owned(),
        ureq::Error::BodyExceedsLimit(_) => "answer too large".to_owned(),
        _ => "transport error".to_owned(),
    }
}

/// Stripe's error `type` and `code`, for a log line. Never the message: it may quote a
/// parameter.
fn stripe_error_words(body: &[u8]) -> (String, String) {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let word = |name: &str| {
        value
            .pointer(&format!("/error/{name}"))
            .and_then(Value::as_str)
            .filter(|text| {
                text.len() <= 64 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .unwrap_or("-")
            .to_owned()
    };
    (word("type"), word("code"))
}

// ---------------------------------------------------------------------------------------
// The webhook signature.

/// Why a webhook signature is refused. Each one answers `400 invalid_request`, and the
/// relay changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// No header, a header without `t` or without `v1`, or one that does not parse.
    Header,
    /// `|now − t| > 300`.
    Timestamp,
    /// No `v1` equals the expected value.
    Mismatch,
}

/// The parts of a `Stripe-Signature` header: `t` as text and as a number, and the `v1`
/// values. A header without `t` or without `v1`, or one that does not parse, is
/// `Header`; a `t` more than 300 seconds from `now`, either way, is `Timestamp`.
fn parse_signature_header(
    header: Option<&str>,
    now: u64,
) -> Result<(&str, u64, Vec<&str>), SignatureError> {
    let header = header.ok_or(SignatureError::Header)?;
    if header.len() > MAX_SIGNATURE_HEADER {
        return Err(SignatureError::Header);
    }
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            return Err(SignatureError::Header);
        };
        match key {
            "t" => {
                if timestamp.is_some()
                    || value.is_empty()
                    || value.len() > 12
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(SignatureError::Header);
                }
                timestamp = Some(value);
            }
            "v1" => {
                if signatures.len() == MAX_SIGNATURES {
                    return Err(SignatureError::Header);
                }
                signatures.push(value);
            }
            _ => {}
        }
    }
    let text = timestamp.ok_or(SignatureError::Header)?;
    if signatures.is_empty() {
        return Err(SignatureError::Header);
    }
    let t: u64 = text.parse().map_err(|_| SignatureError::Header)?;
    if t.abs_diff(now) > SIGNATURE_TOLERANCE {
        return Err(SignatureError::Timestamp);
    }
    Ok((text, t, signatures))
}

/// The checks of a `Stripe-Signature` header that need no body (its form and `t`), so the
/// route can refuse a request before it reads the body. Answers `t`.
pub fn check_signature_header(header: Option<&str>, now: u64) -> Result<u64, SignatureError> {
    parse_signature_header(header, now).map(|(_, t, _)| t)
}

/// Checks `Stripe-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>…]` against the exact
/// body bytes (contract section 7). The expected value is HMAC-SHA256 with the endpoint
/// secret (the whole `whsec_…` string) over `<t>.<body>`; any `v1` may match, compared in
/// constant time by `ring::hmac::verify`; other schemes such as `v0` are ignored. The
/// timestamp must be within 300 seconds of `now`, either way. Answers `t`.
pub fn verify_signature(
    header: Option<&str>,
    body: &[u8],
    secret: &SecretString,
    now: u64,
) -> Result<u64, SignatureError> {
    let (text, t, signatures) = parse_signature_header(header, now)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.expose().as_bytes());
    let mut message = Vec::with_capacity(text.len() + 1 + body.len());
    message.extend_from_slice(text.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    for signature in signatures {
        let Some(tag) = decode_hex(signature) else {
            continue;
        };
        if ring::hmac::verify(&key, &message, &tag).is_ok() {
            return Ok(t);
        }
    }
    Err(SignatureError::Mismatch)
}

/// The `Stripe-Signature` header Stripe would send for this body at `t`. For the tests
/// and the sandbox job, which deliver events themselves.
pub fn signature_header(secret: &SecretString, t: u64, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.expose().as_bytes());
    let mut message = t.to_string().into_bytes();
    message.push(b'.');
    message.extend_from_slice(body);
    let tag = ring::hmac::sign(&key, &message);
    format!("t={t},v1={}", crate::sync_head::hex(tag.as_ref()))
}

/// Lowercase or uppercase hex of exactly 32 bytes.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != 64 {
        return None;
    }
    (0..32)
        .map(|index| u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretString {
        SecretString::new("whsec_unit_test_secret_value".into())
    }

    #[test]
    fn form_round_trips_brackets_and_urls() {
        let mut form = Form::new();
        form.push("line_items[0][price]", "price_X")
            .push(
                "success_url",
                "https://a.example/done?session_id={CHECKOUT_SESSION_ID}",
            )
            .push("name", "a b&c=d");
        let text = form.encode();
        assert!(!text.contains('[') && !text.contains('{') && !text.contains(' '));
        assert_eq!(form_decode(&text).unwrap(), form.pairs());
    }

    #[test]
    fn a_signed_body_verifies_and_a_changed_one_does_not() {
        let body = b"{\"id\":\"evt_1\"}\n";
        let header = signature_header(&secret(), 1000, body);
        assert_eq!(
            verify_signature(Some(&header), body, &secret(), 1000),
            Ok(1000)
        );
        assert_eq!(
            verify_signature(Some(&header), b"{\"id\":\"evt_2\"}\n", &secret(), 1000),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_signature(Some(&header), body, &secret(), 1301),
            Err(SignatureError::Timestamp)
        );
        assert_eq!(
            verify_signature(Some(&header), body, &secret(), 1300),
            Ok(1000)
        );
        assert_eq!(
            verify_signature(None, body, &secret(), 1000),
            Err(SignatureError::Header)
        );
        let twice = format!("t=1000,{}", header.trim_start_matches("t=1000,"));
        assert_eq!(
            verify_signature(Some(&format!("{twice},t=1000")), body, &secret(), 1000),
            Err(SignatureError::Header)
        );
    }

    #[test]
    fn only_restricted_or_sandbox_keys_are_taken() {
        for good in ["rk_live_abc123", "rk_test_abc123", "sk_test_abc123"] {
            assert!(
                check_secret_key(&SecretString::new(good.into())).is_ok(),
                "{good}"
            );
        }
        for bad in [
            "sk_live_abc123",
            "pk_test_abc",
            "",
            "rk_test_a b",
            "whsec_x",
        ] {
            assert!(
                check_secret_key(&SecretString::new(bad.into())).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_base_must_be_https_or_loopback() {
        let key = || SecretString::new("rk_test_abc".into());
        assert!(StripeConfig::new("https://api.stripe.com", key()).is_ok());
        assert!(StripeConfig::new("http://127.0.0.1:4242", key()).is_ok());
        assert!(StripeConfig::new("http://api.stripe.com", key()).is_err());
        assert!(StripeConfig::new("http://127.0.0.1.evil.example", key()).is_err());
    }

    #[test]
    fn http_dates_and_stripe_pages() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Tue, 10 Nov 2026 21:58:00 GMT"),
            Some(1_794_347_880)
        );
        assert_eq!(parse_http_date("Tue, 10 Nov 2026 21:58:00 CET"), None);
        assert_eq!(parse_http_date("1794347880"), None);
        assert!(is_stripe_page(
            "https://checkout.stripe.com/c/pay/cs_test_1",
            CHECKOUT_ORIGIN
        ));
        for bad in [
            "https://checkout.stripe.com/",
            "https://checkout.stripe.com.evil.example/c/pay/cs_1",
            "https://evil.example/https://checkout.stripe.com/",
            "http://checkout.stripe.com/c/pay/cs_1",
            "https://billing.stripe.com/p/session/x",
            "https://checkout.stripe.com/c/pay/cs 1",
        ] {
            assert!(!is_stripe_page(bad, CHECKOUT_ORIGIN), "{bad}");
        }
        assert!(is_stripe_page(
            "https://billing.stripe.com/p/session/test_1",
            PORTAL_ORIGIN
        ));
    }

    #[test]
    fn the_header_is_checked_before_the_body() {
        let header = signature_header(&secret(), 1000, b"{}");
        assert_eq!(check_signature_header(Some(&header), 1000), Ok(1000));
        assert_eq!(
            check_signature_header(Some(&header), 1301),
            Err(SignatureError::Timestamp)
        );
        assert_eq!(
            check_signature_header(None, 1000),
            Err(SignatureError::Header)
        );
        assert_eq!(
            check_signature_header(Some("t=1000"), 1000),
            Err(SignatureError::Header)
        );
    }

    #[test]
    fn ids_for_paths_are_plain() {
        assert!(is_stripe_id("si_", "si_Abc123"));
        assert!(!is_stripe_id("si_", "si_"));
        assert!(!is_stripe_id("si_", "si_a/../b"));
        assert!(!is_stripe_id("si_", "sub_abc"));
    }
}
