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
/// The largest answer from Stripe that the relay reads.
const MAX_ANSWER_BYTES: u64 = 1024 * 1024;
/// The largest `Stripe-Signature` header the relay parses, and its most `v1` values.
const MAX_SIGNATURE_HEADER: usize = 4096;
const MAX_SIGNATURES: usize = 8;
/// Attempts of one call: the first and one retry with the same idempotency key.
const ATTEMPTS: u32 = 2;

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

/// A Checkout Session as Connect uses it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
    pub expires_at: u64,
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
    prices: Mutex<Option<PriceCache>>,
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
            prices: Mutex::new(None),
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
    /// `PRICE_TTL` and has the same keys. A failed lookup keeps the cached prices, if any.
    pub fn prices(&self, keys: &[&str], now: u64) -> RelayResult<HashMap<String, StripePrice>> {
        {
            let cache = self.prices.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(cache) = &*cache
                && now.saturating_sub(cache.fetched_at) < PRICE_TTL
                && now >= cache.fetched_at
                && cache
                    .keys
                    .iter()
                    .map(String::as_str)
                    .eq(keys.iter().copied())
            {
                return Ok(cache.prices.clone());
            }
        }
        match self.fetch_prices(keys) {
            Ok(prices) => {
                *self.prices.lock().unwrap_or_else(PoisonError::into_inner) = Some(PriceCache {
                    fetched_at: now,
                    keys: keys.iter().map(|key| (*key).to_owned()).collect(),
                    prices: prices.clone(),
                });
                Ok(prices)
            }
            Err(error) => {
                let cache = self.prices.lock().unwrap_or_else(PoisonError::into_inner);
                match &*cache {
                    Some(cache)
                        if cache
                            .keys
                            .iter()
                            .map(String::as_str)
                            .eq(keys.iter().copied()) =>
                    {
                        Ok(cache.prices.clone())
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Drops the cached prices: the next `prices` call asks Stripe.
    pub fn forget_prices(&self) {
        *self.prices.lock().unwrap_or_else(PoisonError::into_inner) = None;
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
        if !is_stripe_id("cs_", &session.id) || !session.url.starts_with("https://") {
            return Err(self.bad_answer("/v1/checkout/sessions"));
        }
        Ok(session)
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
        if !session.url.starts_with("https://") {
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
                Ok((status, body)) if (200..300).contains(&status) => {
                    return serde_json::from_slice(&body).map_err(|_| self.bad_answer(path));
                }
                Ok((status, body)) => {
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
    ) -> Result<(u16, Vec<u8>), String> {
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
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .map_err(transport_words)?;
        Ok((status, body))
    }
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
    fn ids_for_paths_are_plain() {
        assert!(is_stripe_id("si_", "si_Abc123"));
        assert!(!is_stripe_id("si_", "si_"));
        assert!(!is_stripe_id("si_", "si_a/../b"));
        assert!(!is_stripe_id("si_", "sub_abc"));
    }
}
